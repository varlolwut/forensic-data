import hashlib
import json
import time
from collections.abc import Generator
from dataclasses import dataclass, replace
from datetime import date
from decimal import Decimal
from enum import StrEnum
from sys import getsizeof
from typing import cast, final

from forensic_data.acquisition import InputCutDefinition, classify_input_cut_alignment
from forensic_data.canonical import (
    DecimalParameters,
    DecodedValue,
    FieldSchema,
    Fingerprint,
    LogicalType,
    TimestampParameters,
)
from forensic_data.contracts.model import (
    AssurancePolicy,
    DatasetDefinition,
    EvidenceAction,
    EvidenceDefinition,
    ExecutionBudgets,
    RelationLocator,
    RelationManifestReadiness,
    RelationScope,
    RowCheckDefinition,
    ScopeOperator,
    StableReadKind,
)
from forensic_data.contracts.semantics import semantic_value_from_json
from forensic_data.planning import ResolvedScope
from forensic_data.postgres import (
    PostgresAcquisitionRaceError,
    PostgresConnectorError,
    PostgresContextClosedError,
    PostgresContextLostError,
    PostgresDataValidationError,
    PostgresIntegerExactRow,
    PostgresIntegerExactRowsRead,
    PostgresIntegerKeySummary,
    PostgresIntegerKeySummaryRead,
    PostgresProtectedReadContext,
    PostgresProtectedRelationInspection,
    PostgresQueryContextError,
    PostgresRangeFingerprint,
    PostgresRangeFingerprintRead,
    PostgresReadDeadline,
    PostgresReadDeadlineExceededError,
    PostgresReadMetrics,
    PostgresResultLimitError,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetExceededError,
    PostgresSourceDirection,
    ReadContextState,
    UnsupportedPostgresProfileError,
)
from forensic_data.postgres_sql import PostgresIntegerRangeRequest, PostgresScopePredicate
from forensic_data.reporting import (
    DifferenceKind,
    DifferenceRecord,
    EvidenceFieldValue,
    EvidenceUnavailableReason,
    EvidenceValueAvailability,
    KeyAvailability,
    canonical_difference_key_bytes,
    canonical_difference_record_bytes,
)
from forensic_data.result import (
    ComparisonCoverage,
    ComparisonTotals,
    ConsistencyLevel,
    ConsistencyStatus,
    EvidenceCoverage,
    ExactTotal,
    Guarantee,
    InferredTotal,
    LowerBoundTotal,
    ReasonCode,
    ResultMetrics,
    ResultReason,
    SafeParameter,
    UnavailableTotal,
    Verdict,
)

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
_SUMMARY_RECORD_BYTES = 136
_SESSION_SETUP_RECORD_BYTES = 128
_MAX_INT64_KEY_ENVELOPE_BYTES = 136
_EXACT_STATUS_BYTES = 2
_DEADLINE_CHECK_RECORDS = 64
_POINTER_BYTES = getsizeof((None,)) - getsizeof(())
_EMPTY_TUPLE_BYTES = getsizeof(())
_EMPTY_LIST_BYTES = getsizeof([])
_EMPTY_DICT_BYTES = getsizeof({})
_DICT_ENTRY_RESERVATION_BYTES = getsizeof({0: None}) - _EMPTY_DICT_BYTES
_ASCII_TEXT_HEADER_BYTES = getsizeof("")
_BYTES_HEADER_BYTES = getsizeof(b"")
_DECODE_ENVELOPE_EXPANSION = 6
_DECODE_FIELD_RESERVATION_BYTES = (
    (6 * _POINTER_BYTES) + _ASCII_TEXT_HEADER_BYTES + _BYTES_HEADER_BYTES + getsizeof(Decimal(0))
)


class ComparisonExecutionError(RuntimeError):
    """The bounded integer-key comparison could not produce a completed artifact."""


class UnsupportedComparisonError(ComparisonExecutionError):
    """The requested check is outside the implemented comparison capability."""


class ComparisonBudgetExceededError(ComparisonExecutionError):
    """The next deterministic comparison operation cannot fit its declared budgets."""


class ComparisonProtocolError(ComparisonExecutionError):
    """Connector output violated the integer-key comparison protocol."""


class ComparisonKeyMappingError(ComparisonExecutionError):
    """A completed key summary found values that cannot map losslessly to INT64."""

    def __init__(
        self,
        reference_summary: PostgresIntegerKeySummary,
        target_summary: PostgresIntegerKeySummary,
        metrics: ResultMetrics,
        reference_full_scans: int,
        target_full_scans: int,
        contract_violation_reason: ResultReason | None,
    ) -> None:
        self.reference_summary = reference_summary
        self.target_summary = target_summary
        self.metrics = metrics
        self.reference_full_scans = reference_full_scans
        self.target_full_scans = target_full_scans
        self.contract_violation_reason = contract_violation_reason
        super().__init__(
            "scoped integer-key validation found physical values that cannot map "
            "losslessly to logical INT64: "
            f"reference_invalid={reference_summary.invalid_key_count}, "
            f"target_invalid={target_summary.invalid_key_count}"
        )


class ComparisonSegmentState(StrEnum):
    SPLIT = "split"
    FINGERPRINT_MATCH = "fingerprint_match"
    EXACT_MATCH = "exact_match"
    EXACT_MISMATCH = "exact_mismatch"


@final
@dataclass(frozen=True, slots=True)
class ComparisonSegmentRecord:
    segment_sequence: int
    parent_segment_sequence: int | None
    depth: int
    lower_inclusive: int
    upper_exclusive: int | None
    state: ComparisonSegmentState
    reference_fingerprint: Fingerprint
    target_fingerprint: Fingerprint

    def __post_init__(self) -> None:
        _require_nonnegative_integer(self.segment_sequence, "segment_sequence")
        if self.parent_segment_sequence is not None:
            _require_nonnegative_integer(
                self.parent_segment_sequence,
                "parent_segment_sequence",
            )
            if self.parent_segment_sequence >= self.segment_sequence:
                raise ValueError("parent segment must precede its child")
        _require_nonnegative_integer(self.depth, "segment depth")
        if (self.depth == 0) != (self.parent_segment_sequence is None):
            raise ValueError("only the depth-zero root segment can omit its parent")
        _require_int64(self.lower_inclusive, "segment lower bound")
        if self.upper_exclusive is not None:
            _require_int64(self.upper_exclusive, "segment upper bound")
            if self.upper_exclusive <= self.lower_inclusive:
                raise ValueError("segment upper bound must exceed its lower bound")
        _require_instance(self.state, ComparisonSegmentState, "segment state")
        _require_instance(
            self.reference_fingerprint,
            Fingerprint,
            "reference fingerprint",
        )
        _require_instance(self.target_fingerprint, Fingerprint, "target fingerprint")
        if (
            self.state
            in (ComparisonSegmentState.FINGERPRINT_MATCH, ComparisonSegmentState.EXACT_MATCH)
            and self.reference_fingerprint != self.target_fingerprint
        ):
            raise ValueError(f"{self.state.value} segment requires equal fingerprints")
        if (
            self.state in (ComparisonSegmentState.SPLIT, ComparisonSegmentState.EXACT_MISMATCH)
            and self.reference_fingerprint == self.target_fingerprint
        ):
            raise ValueError(f"{self.state.value} segment requires unequal fingerprints")


@final
@dataclass(frozen=True, slots=True)
class CompletedComparisonArtifact:
    check_id: str
    contract_digest: str
    scope_digest: str
    input_cut_digest: str
    verdict: Verdict
    consistency: ConsistencyStatus
    guarantee: Guarantee
    comparison_coverage: ComparisonCoverage
    totals: ComparisonTotals
    evidence_coverage: EvidenceCoverage
    metrics: ResultMetrics
    reasons: tuple[ResultReason, ...]
    segments: tuple[ComparisonSegmentRecord, ...]
    anomalies: tuple[DifferenceRecord, ...]
    reference_key_summary: PostgresIntegerKeySummary
    target_key_summary: PostgresIntegerKeySummary
    reference_full_scans: int
    target_full_scans: int

    def __post_init__(self) -> None:
        if type(self.check_id) is not str or self.check_id.strip() == "":
            raise ValueError("completed comparison check_id must be nonblank")
        _require_sha256(self.contract_digest, "completed comparison contract digest")
        _require_sha256(self.scope_digest, "completed comparison scope digest")
        _require_sha256(self.input_cut_digest, "completed comparison input-cut digest")
        _require_instance(self.verdict, Verdict, "completed comparison verdict")
        _require_instance(self.consistency, ConsistencyStatus, "completed consistency")
        _require_instance(self.guarantee, Guarantee, "completed guarantee")
        if self.guarantee not in (Guarantee.EXACT, Guarantee.FINGERPRINT):
            raise ValueError("completed integer comparison requires exact or fingerprint guarantee")
        _require_instance(
            self.comparison_coverage,
            ComparisonCoverage,
            "completed comparison coverage",
        )
        _require_instance(self.totals, ComparisonTotals, "completed totals")
        _require_instance(self.evidence_coverage, EvidenceCoverage, "completed evidence coverage")
        _require_instance(self.metrics, ResultMetrics, "completed metrics")
        if type(self.reasons) is not tuple:
            raise TypeError("completed comparison reasons must be an immutable tuple")
        for reason in self.reasons:
            _require_instance(reason, ResultReason, "completed comparison reason")
        if type(self.segments) is not tuple or not self.segments:
            raise ValueError("completed comparison requires a nonempty segment topology")
        for segment in self.segments:
            _require_instance(segment, ComparisonSegmentRecord, "completed segment")
        if tuple(segment.segment_sequence for segment in self.segments) != tuple(
            range(len(self.segments))
        ):
            raise ValueError("completed segment sequences must be contiguous from zero")
        if type(self.anomalies) is not tuple:
            raise TypeError("completed comparison anomalies must be an immutable tuple")
        for anomaly in self.anomalies:
            _require_instance(anomaly, DifferenceRecord, "completed anomaly")
        _validate_evidence_coverage(self.evidence_coverage, self.anomalies)
        by_sequence = {segment.segment_sequence: segment for segment in self.segments}
        if any(
            by_sequence.get(anomaly.segment_sequence) is None
            or by_sequence[anomaly.segment_sequence].state
            is not ComparisonSegmentState.EXACT_MISMATCH
            for anomaly in self.anomalies
        ):
            raise ValueError("completed anomalies require exact-mismatch segments")
        _require_instance(
            self.reference_key_summary,
            PostgresIntegerKeySummary,
            "reference key summary",
        )
        _require_instance(
            self.target_key_summary,
            PostgresIntegerKeySummary,
            "target key summary",
        )
        _require_nonnegative_integer(self.reference_full_scans, "reference_full_scans")
        _require_nonnegative_integer(self.target_full_scans, "target_full_scans")
        if self.metrics.fingerprint_nodes != len(self.segments):
            raise ValueError("fingerprint_nodes must equal the logical segment topology size")


@final
@dataclass(frozen=True, slots=True)
class CompletedStructuralComparisonArtifact:
    check_id: str
    contract_digest: str
    scope_digest: str
    input_cut_digest: str
    verdict: Verdict
    consistency: ConsistencyStatus
    guarantee: Guarantee
    comparison_coverage: ComparisonCoverage
    totals: ComparisonTotals
    evidence_coverage: EvidenceCoverage
    metrics: ResultMetrics
    reasons: tuple[ResultReason, ...]
    reference_key_summary: PostgresIntegerKeySummary
    target_key_summary: PostgresIntegerKeySummary
    reference_full_scans: int
    target_full_scans: int

    def __post_init__(self) -> None:
        if type(self.check_id) is not str or self.check_id.strip() == "":
            raise ValueError("completed structural comparison check_id must be nonblank")
        _require_sha256(self.contract_digest, "completed structural contract digest")
        _require_sha256(self.scope_digest, "completed structural scope digest")
        _require_sha256(self.input_cut_digest, "completed structural input-cut digest")
        if self.verdict is not Verdict.MISMATCH:
            raise ValueError("completed structural key-contract result must be mismatch")
        _require_instance(self.consistency, ConsistencyStatus, "completed consistency")
        if self.guarantee is not Guarantee.STRUCTURAL:
            raise ValueError("completed key-contract result requires structural guarantee")
        _require_instance(
            self.comparison_coverage,
            ComparisonCoverage,
            "completed structural comparison coverage",
        )
        _require_instance(self.totals, ComparisonTotals, "completed structural totals")
        _require_instance(
            self.evidence_coverage,
            EvidenceCoverage,
            "completed structural evidence coverage",
        )
        _require_instance(self.metrics, ResultMetrics, "completed structural metrics")
        if type(self.reasons) is not tuple or len(self.reasons) != 1:
            raise ValueError("completed structural comparison requires one immutable reason")
        _require_instance(self.reasons[0], ResultReason, "completed structural reason")
        _require_instance(
            self.reference_key_summary,
            PostgresIntegerKeySummary,
            "reference key summary",
        )
        _require_instance(
            self.target_key_summary,
            PostgresIntegerKeySummary,
            "target key summary",
        )
        _require_nonnegative_integer(self.reference_full_scans, "reference_full_scans")
        _require_nonnegative_integer(self.target_full_scans, "target_full_scans")
        _validate_structural_artifact(self)


@final
@dataclass(frozen=True, slots=True)
class UnresolvedComparisonSegment:
    segment_sequence: int
    parent_segment_sequence: int | None
    depth: int
    lower_inclusive: int
    upper_exclusive: int | None
    reason: ReasonCode
    reference_fingerprint: Fingerprint | None
    target_fingerprint: Fingerprint | None

    def __post_init__(self) -> None:
        _require_nonnegative_integer(self.segment_sequence, "unresolved segment sequence")
        if self.parent_segment_sequence is not None:
            _require_nonnegative_integer(
                self.parent_segment_sequence,
                "unresolved parent segment sequence",
            )
            if self.parent_segment_sequence >= self.segment_sequence:
                raise ValueError("unresolved parent segment must precede its child")
        _require_nonnegative_integer(self.depth, "unresolved segment depth")
        if (self.depth == 0) != (self.parent_segment_sequence is None):
            raise ValueError("only an unresolved root can omit its parent")
        _require_int64(self.lower_inclusive, "unresolved segment lower bound")
        if self.upper_exclusive is not None:
            _require_int64(self.upper_exclusive, "unresolved segment upper bound")
            if self.upper_exclusive <= self.lower_inclusive:
                raise ValueError("unresolved segment upper bound must exceed its lower bound")
        _require_instance(self.reason, ReasonCode, "unresolved segment reason")
        if (self.reference_fingerprint is None) != (self.target_fingerprint is None):
            raise ValueError("unresolved fingerprint witness requires both sides")
        if self.reference_fingerprint is not None:
            _require_instance(
                self.reference_fingerprint,
                Fingerprint,
                "unresolved reference fingerprint",
            )
            _require_instance(
                self.target_fingerprint,
                Fingerprint,
                "unresolved target fingerprint",
            )
            if self.reference_fingerprint == self.target_fingerprint:
                raise ValueError("unresolved fingerprint witness must prove a mismatch")


@final
@dataclass(frozen=True, slots=True)
class PartialComparisonFrontier:
    topology: tuple[ComparisonSegmentRecord, ...]
    unresolved: tuple[UnresolvedComparisonSegment, ...]

    def __post_init__(self) -> None:
        if type(self.topology) is not tuple or type(self.unresolved) is not tuple:
            raise TypeError("partial comparison frontier members must be immutable tuples")
        topology_sequences: set[int] = set()
        for segment in self.topology:
            _require_instance(segment, ComparisonSegmentRecord, "partial topology segment")
            if segment.segment_sequence in topology_sequences:
                raise ValueError("partial topology segment sequences must be unique")
            topology_sequences.add(segment.segment_sequence)
        unresolved_sequences: set[int] = set()
        for segment in self.unresolved:
            _require_instance(segment, UnresolvedComparisonSegment, "unresolved segment")
            if segment.segment_sequence in unresolved_sequences:
                raise ValueError("unresolved segment sequences must be unique")
            unresolved_sequences.add(segment.segment_sequence)
        if topology_sequences.intersection(unresolved_sequences):
            raise ValueError("partial topology and unresolved frontier must be disjoint")
        if tuple(item.segment_sequence for item in self.topology) != tuple(
            sorted(topology_sequences)
        ):
            raise ValueError("partial topology must use ascending segment order")
        if tuple(item.segment_sequence for item in self.unresolved) != tuple(
            sorted(unresolved_sequences)
        ):
            raise ValueError("unresolved frontier must use ascending segment order")


@final
@dataclass(frozen=True, slots=True)
class PartialComparisonArtifact:
    check_id: str
    contract_digest: str
    scope_digest: str
    input_cut_digest: str
    verdict: Verdict
    consistency: ConsistencyStatus
    guarantee: Guarantee
    comparison_coverage: ComparisonCoverage
    totals: ComparisonTotals
    evidence_coverage: EvidenceCoverage
    metrics: ResultMetrics
    frontier: PartialComparisonFrontier
    anomalies: tuple[DifferenceRecord, ...]
    reference_full_scans: int
    target_full_scans: int

    def __post_init__(self) -> None:
        if type(self.check_id) is not str or self.check_id.strip() == "":
            raise ValueError("partial comparison check_id must be nonblank")
        _require_sha256(self.contract_digest, "partial comparison contract digest")
        _require_sha256(self.scope_digest, "partial comparison scope digest")
        _require_sha256(self.input_cut_digest, "partial comparison input-cut digest")
        _require_instance(self.verdict, Verdict, "partial comparison verdict")
        if self.verdict is Verdict.MATCH:
            raise ValueError("partial comparison cannot claim a match")
        _require_instance(self.consistency, ConsistencyStatus, "partial consistency")
        if len(self.consistency.read_context_ids) != 2:
            raise ValueError("partial comparison requires both protected context identities")
        if self.consistency.stable_reads not in (
            ConsistencyLevel.UNKNOWN,
            ConsistencyLevel.VERIFIED,
        ):
            raise ValueError("partial comparison cannot invent asserted stable-read proof")
        if self.consistency.cut_alignment not in (
            ConsistencyLevel.UNKNOWN,
            ConsistencyLevel.VERIFIED,
        ):
            raise ValueError("partial comparison cannot invent asserted cut-alignment proof")
        if (
            self.consistency.stable_reads is ConsistencyLevel.VERIFIED
            and self.consistency.cut_alignment is not ConsistencyLevel.VERIFIED
        ):
            raise ValueError("verified partial stable reads require a verified aligned cut")
        if self.guarantee is not Guarantee.NOT_ESTABLISHED:
            raise ValueError("partial comparison requires not_established guarantee")
        _require_instance(
            self.comparison_coverage,
            ComparisonCoverage,
            "partial comparison coverage",
        )
        _require_instance(self.totals, ComparisonTotals, "partial comparison totals")
        _require_instance(
            self.evidence_coverage,
            EvidenceCoverage,
            "partial comparison evidence coverage",
        )
        _require_instance(self.metrics, ResultMetrics, "partial comparison metrics")
        _require_instance(self.frontier, PartialComparisonFrontier, "partial frontier")
        if type(self.anomalies) is not tuple:
            raise TypeError("partial comparison anomalies must be an immutable tuple")
        for anomaly in self.anomalies:
            _require_instance(anomaly, DifferenceRecord, "partial comparison anomaly")
        _validate_evidence_coverage(self.evidence_coverage, self.anomalies)
        _validate_partial_frontier_coverage(self)
        _validate_partial_totals(self)
        _require_nonnegative_integer(self.reference_full_scans, "reference_full_scans")
        _require_nonnegative_integer(self.target_full_scans, "target_full_scans")


type ComparisonInterruptionCause = ComparisonExecutionError | PostgresConnectorError


class ComparisonInterruptedError(ComparisonExecutionError):
    """A typed comparison failure carrying all durable progress reached before it."""

    def __init__(
        self,
        cause: ComparisonInterruptionCause,
        artifact: PartialComparisonArtifact,
    ) -> None:
        self.cause = cause
        self.artifact = _require_instance(
            artifact,
            PartialComparisonArtifact,
            "partial comparison artifact",
        )
        super().__init__(f"comparison interrupted by {type(cause).__name__}")


def canonical_partial_comparison_frontier_bytes(
    frontier: PartialComparisonFrontier,
) -> bytes:
    _require_instance(frontier, PartialComparisonFrontier, "partial comparison frontier")
    payload = {
        "topology": [_segment_semantic_value(item) for item in frontier.topology],
        "unresolved": [
            {
                "depth": item.depth,
                "lower_inclusive": item.lower_inclusive,
                "parent_segment_sequence": item.parent_segment_sequence,
                "reference_fingerprint": (
                    None
                    if item.reference_fingerprint is None
                    else _fingerprint_semantic_value(item.reference_fingerprint)
                ),
                "reason": item.reason.value,
                "segment_sequence": item.segment_sequence,
                "target_fingerprint": (
                    None
                    if item.target_fingerprint is None
                    else _fingerprint_semantic_value(item.target_fingerprint)
                ),
                "upper_exclusive": item.upper_exclusive,
            }
            for item in frontier.unresolved
        ],
    }
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def partial_comparison_frontier_from_canonical_bytes(
    payload: bytes,
) -> PartialComparisonFrontier:
    if type(payload) is not bytes:
        raise TypeError("partial comparison frontier payload must be bytes")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("partial comparison frontier must be valid UTF-8 JSON") from error
    value = semantic_value_from_json(text)
    root = _require_json_object(value, "partial comparison frontier")
    if set(root) != {"topology", "unresolved"}:
        raise ValueError("partial comparison frontier has unsupported or missing fields")
    topology_values = _require_json_array(root["topology"], "partial topology")
    unresolved_values = _require_json_array(root["unresolved"], "unresolved frontier")
    frontier = PartialComparisonFrontier(
        topology=tuple(_comparison_segment_from_semantic_value(item) for item in topology_values),
        unresolved=tuple(
            _unresolved_segment_from_semantic_value(item) for item in unresolved_values
        ),
    )
    if canonical_partial_comparison_frontier_bytes(frontier) != payload:
        raise ValueError("partial comparison frontier is not canonical JSON")
    return frontier


def _segment_semantic_value(segment: ComparisonSegmentRecord) -> dict[str, object]:
    return {
        "depth": segment.depth,
        "lower_inclusive": segment.lower_inclusive,
        "parent_segment_sequence": segment.parent_segment_sequence,
        "reference_fingerprint": _fingerprint_semantic_value(segment.reference_fingerprint),
        "segment_sequence": segment.segment_sequence,
        "state": segment.state.value,
        "target_fingerprint": _fingerprint_semantic_value(segment.target_fingerprint),
        "upper_exclusive": segment.upper_exclusive,
    }


def _fingerprint_semantic_value(fingerprint: Fingerprint) -> dict[str, object]:
    return {"count": fingerprint.count, "limb_sums": list(fingerprint.limb_sums)}


def _comparison_segment_from_semantic_value(value: object) -> ComparisonSegmentRecord:
    item = _require_json_object(value, "partial topology segment")
    expected = {
        "depth",
        "lower_inclusive",
        "parent_segment_sequence",
        "reference_fingerprint",
        "segment_sequence",
        "state",
        "target_fingerprint",
        "upper_exclusive",
    }
    if set(item) != expected:
        raise ValueError("partial topology segment has unsupported or missing fields")
    return ComparisonSegmentRecord(
        segment_sequence=_require_json_integer(item["segment_sequence"], "segment sequence"),
        parent_segment_sequence=_optional_json_integer(
            item["parent_segment_sequence"],
            "parent segment sequence",
        ),
        depth=_require_json_integer(item["depth"], "segment depth"),
        lower_inclusive=_require_json_integer(item["lower_inclusive"], "lower bound"),
        upper_exclusive=_optional_json_integer(item["upper_exclusive"], "upper bound"),
        state=ComparisonSegmentState(_require_json_string(item["state"], "segment state")),
        reference_fingerprint=_fingerprint_from_semantic_value(
            item["reference_fingerprint"],
            "reference fingerprint",
        ),
        target_fingerprint=_fingerprint_from_semantic_value(
            item["target_fingerprint"],
            "target fingerprint",
        ),
    )


def _unresolved_segment_from_semantic_value(value: object) -> UnresolvedComparisonSegment:
    item = _require_json_object(value, "unresolved segment")
    expected = {
        "depth",
        "lower_inclusive",
        "parent_segment_sequence",
        "reference_fingerprint",
        "reason",
        "segment_sequence",
        "target_fingerprint",
        "upper_exclusive",
    }
    if set(item) != expected:
        raise ValueError("unresolved segment has unsupported or missing fields")
    return UnresolvedComparisonSegment(
        segment_sequence=_require_json_integer(item["segment_sequence"], "segment sequence"),
        parent_segment_sequence=_optional_json_integer(
            item["parent_segment_sequence"],
            "parent segment sequence",
        ),
        depth=_require_json_integer(item["depth"], "segment depth"),
        lower_inclusive=_require_json_integer(item["lower_inclusive"], "lower bound"),
        upper_exclusive=_optional_json_integer(item["upper_exclusive"], "upper bound"),
        reason=ReasonCode(_require_json_string(item["reason"], "unresolved reason")),
        reference_fingerprint=_optional_fingerprint_from_semantic_value(
            item["reference_fingerprint"],
            "unresolved reference fingerprint",
        ),
        target_fingerprint=_optional_fingerprint_from_semantic_value(
            item["target_fingerprint"],
            "unresolved target fingerprint",
        ),
    )


def _fingerprint_from_semantic_value(value: object, context: str) -> Fingerprint:
    item = _require_json_object(value, context)
    if set(item) != {"count", "limb_sums"}:
        raise ValueError(f"{context} has unsupported or missing fields")
    limbs = _require_json_array(item["limb_sums"], f"{context} limbs")
    if len(limbs) != 8:
        raise ValueError(f"{context} requires exactly eight limbs")
    parsed_limbs = tuple(_require_json_integer(limb, f"{context} limb") for limb in limbs)
    return Fingerprint(
        count=_require_json_integer(item["count"], f"{context} count"),
        limb_sums=(
            parsed_limbs[0],
            parsed_limbs[1],
            parsed_limbs[2],
            parsed_limbs[3],
            parsed_limbs[4],
            parsed_limbs[5],
            parsed_limbs[6],
            parsed_limbs[7],
        ),
    )


def _optional_fingerprint_from_semantic_value(
    value: object,
    context: str,
) -> Fingerprint | None:
    if value is None:
        return None
    return _fingerprint_from_semantic_value(value, context)


def _require_json_object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be a JSON object")
    raw = cast(dict[object, object], value)
    if any(type(key) is not str for key in raw):
        raise ValueError(f"{context} must use string object keys")
    return {cast(str, key): item for key, item in raw.items()}


def _require_json_array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be a JSON array")
    return list(cast(list[object], value))


def _require_json_integer(value: object, context: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{context} must be an exact JSON integer")
    return value


def _optional_json_integer(value: object, context: str) -> int | None:
    if value is None:
        return None
    return _require_json_integer(value, context)


def _require_json_string(value: object, context: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{context} must be a JSON string")
    return value


@final
@dataclass(frozen=True, slots=True)
class _ValidatedInputs:
    key_field_index: int
    reference_scope: PostgresScopePredicate | None
    target_scope: PostgresScopePredicate | None
    max_encoded_row_bytes: int


@final
@dataclass(frozen=True, slots=True)
class _PendingSegment:
    segment_sequence: int
    parent_segment_sequence: int | None
    depth: int
    lower_inclusive: int
    upper_exclusive: int | None


@final
@dataclass(frozen=True, slots=True)
class _FingerprintNode:
    segment: _PendingSegment
    reference: PostgresRangeFingerprint
    target: PostgresRangeFingerprint


@final
@dataclass(frozen=True, slots=True)
class _ExactCounts:
    matched: int
    missing: int
    extra: int
    modified: int

    def __post_init__(self) -> None:
        _require_nonnegative_integer(self.matched, "exact matched count")
        _require_nonnegative_integer(self.missing, "exact missing count")
        _require_nonnegative_integer(self.extra, "exact extra count")
        _require_nonnegative_integer(self.modified, "exact modified count")


@final
@dataclass(frozen=True, slots=True)
class _ExactDifference:
    segment_sequence: int
    kind: DifferenceKind
    key_row: PostgresIntegerExactRow
    reference_row: PostgresIntegerExactRow | None
    target_row: PostgresIntegerExactRow | None


@final
@dataclass(frozen=True, slots=True)
class _Usage:
    queries: int
    fetched_records: int
    result_bytes: int
    fingerprint_nodes: int
    coordinator_peak_bytes: int
    reference_full_scans: int
    target_full_scans: int
    elapsed_milliseconds: int


@final
@dataclass(frozen=True, slots=True)
class _ComparisonProgress:
    pending: tuple[_PendingSegment, ...]
    topology: tuple[ComparisonSegmentRecord, ...]
    exact_counts: _ExactCounts
    pruned_matched: int
    pruned_segments: int
    exact_segments: int
    summaries_verified: bool
    mismatch_witnesses: tuple[_FingerprintNode, ...]
    usage: _Usage
    anomalies: tuple[DifferenceRecord, ...]
    found_records: int
    found_bytes: int
    retained_bytes: int
    retention_open: bool


@final
@dataclass(frozen=True, slots=True)
class _ExactSideReservation:
    records: int
    result_bytes: int
    envelope_bytes: int
    segment_identifier_bytes: int
    full_scans: int


@final
@dataclass(frozen=True, slots=True)
class _ExactFrontierReservation:
    reference: _ExactSideReservation
    target: _ExactSideReservation
    coordinator_peak_bytes: int


@final
@dataclass(frozen=True, slots=True)
class _FingerprintLevelPlan:
    requests: tuple[PostgresIntegerRangeRequest, ...]
    side_result_bytes: int
    record_bytes: int
    coordinator_peak_bytes: int


def _initial_comparison_progress(
    source_budget: PostgresSourceBudgetAttempt,
) -> _ComparisonProgress:
    snapshot = source_budget.snapshot()
    return _ComparisonProgress(
        pending=(
            _PendingSegment(
                segment_sequence=0,
                parent_segment_sequence=None,
                depth=0,
                lower_inclusive=INT64_MIN,
                upper_exclusive=None,
            ),
        ),
        topology=(),
        exact_counts=_ExactCounts(matched=0, missing=0, extra=0, modified=0),
        pruned_matched=0,
        pruned_segments=0,
        exact_segments=0,
        summaries_verified=False,
        mismatch_witnesses=(),
        usage=_Usage(
            queries=snapshot.queries,
            fetched_records=snapshot.fetched_records,
            result_bytes=snapshot.result_bytes,
            fingerprint_nodes=0,
            coordinator_peak_bytes=0,
            reference_full_scans=snapshot.reference_full_scans,
            target_full_scans=snapshot.target_full_scans,
            elapsed_milliseconds=snapshot.elapsed_milliseconds,
        ),
        anomalies=(),
        found_records=0,
        found_bytes=0,
        retained_bytes=0,
        retention_open=True,
    )


def execute_postgres_integer_key_comparison(
    reference_context: PostgresProtectedReadContext,
    reference_relation: PostgresProtectedRelationInspection,
    target_context: PostgresProtectedReadContext,
    target_relation: PostgresProtectedRelationInspection,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    input_cut: InputCutDefinition,
    budgets: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
    source_budget: PostgresSourceBudgetAttempt,
) -> CompletedComparisonArtifact | CompletedStructuralComparisonArtifact:
    reference_context = _require_instance(
        reference_context,
        PostgresProtectedReadContext,
        "reference protected context",
    )
    reference_relation = _require_instance(
        reference_relation,
        PostgresProtectedRelationInspection,
        "reference protected relation",
    )
    target_context = _require_instance(
        target_context,
        PostgresProtectedReadContext,
        "target protected context",
    )
    target_relation = _require_instance(
        target_relation,
        PostgresProtectedRelationInspection,
        "target protected relation",
    )
    check = _require_instance(check, RowCheckDefinition, "row check")
    scope = _require_instance(scope, ResolvedScope, "resolved scope")
    input_cut = _require_instance(input_cut, InputCutDefinition, "aligned input cut")
    budgets = _require_instance(budgets, ExecutionBudgets, "execution budgets")
    evidence_policy = _require_instance(
        evidence_policy,
        EvidenceDefinition,
        "evidence policy",
    )
    source_budget = _require_instance(
        source_budget,
        PostgresSourceBudgetAttempt,
        "source budget attempt",
    )
    if reference_context.source_budget is not source_budget:
        raise ComparisonProtocolError(
            "reference protected context uses a different source budget attempt"
        )
    if target_context.source_budget is not source_budget:
        raise ComparisonProtocolError(
            "target protected context uses a different source budget attempt"
        )
    if reference_context.source_direction is not PostgresSourceDirection.REFERENCE:
        raise ComparisonProtocolError("reference protected context has the wrong source direction")
    if target_context.source_direction is not PostgresSourceDirection.TARGET:
        raise ComparisonProtocolError("target protected context has the wrong source direction")
    progress = _initial_comparison_progress(source_budget)
    execution = _execute_postgres_integer_key_comparison(
        reference_context,
        reference_relation,
        target_context,
        target_relation,
        check,
        scope,
        input_cut,
        budgets,
        evidence_policy,
        source_budget,
        progress,
    )
    try:
        while True:
            try:
                progress = next(execution)
            except StopIteration as completed:
                return cast(
                    CompletedComparisonArtifact | CompletedStructuralComparisonArtifact,
                    completed.value,
                )
    except (ComparisonExecutionError, PostgresConnectorError) as cause:
        artifact = _partial_comparison_artifact(
            check,
            scope,
            input_cut,
            reference_context,
            target_context,
            source_budget,
            progress,
            cause,
        )
        raise ComparisonInterruptedError(cause, artifact) from cause


def _execute_postgres_integer_key_comparison(
    reference_context: PostgresProtectedReadContext,
    reference_relation: PostgresProtectedRelationInspection,
    target_context: PostgresProtectedReadContext,
    target_relation: PostgresProtectedRelationInspection,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    input_cut: InputCutDefinition,
    budgets: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
    source_budget: PostgresSourceBudgetAttempt,
    progress: _ComparisonProgress,
) -> Generator[
    _ComparisonProgress,
    None,
    CompletedComparisonArtifact | CompletedStructuralComparisonArtifact,
]:
    read_deadline = source_budget.read_deadline(budgets.statement_timeout_milliseconds)
    validated = _validate_inputs(
        reference_context,
        reference_relation,
        target_context,
        target_relation,
        check,
        scope,
        input_cut,
        budgets,
    )
    usage = progress.usage
    _require_deadline(read_deadline.deadline_nanoseconds)
    summary_coordinator_peak = _summary_phase_memory_bytes(budgets)
    progress = replace(
        progress,
        usage=_usage_with_coordinator_peak(usage, summary_coordinator_peak),
    )
    usage = progress.usage
    yield progress
    _require_full_scan_capacity(
        source_budget,
        reference_full_scans=1,
        target_full_scans=1,
    )
    _require_budget_capacity(
        source_budget,
        budgets,
        additional_queries=4,
        additional_records=4,
        additional_result_bytes=(2 * (_SUMMARY_RECORD_BYTES + _SESSION_SETUP_RECORD_BYTES)),
        coordinator_bytes=summary_coordinator_peak,
    )
    reference_summary_read = reference_context.read_integer_key_summary(
        reference_relation,
        validated.key_field_index,
        validated.reference_scope,
        validated.max_encoded_row_bytes,
        _SUMMARY_RECORD_BYTES,
        _SUMMARY_RECORD_BYTES,
        read_deadline,
        1,
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    target_summary_read = target_context.read_integer_key_summary(
        target_relation,
        validated.key_field_index,
        validated.target_scope,
        validated.max_encoded_row_bytes,
        _SUMMARY_RECORD_BYTES,
        _SUMMARY_RECORD_BYTES,
        read_deadline,
        1,
    )
    usage = _consume_source_usage(
        usage,
        source_budget,
        fingerprint_nodes=0,
        coordinator_peak_bytes=summary_coordinator_peak,
    )
    reference_summary = reference_summary_read.summary
    target_summary = target_summary_read.summary
    root = _root_segment(reference_summary, target_summary)
    progress = replace(
        progress,
        pending=(root,),
        summaries_verified=True,
        usage=usage,
    )
    yield progress
    _require_deadline(read_deadline.deadline_nanoseconds)
    contract_violation_reason = _structural_contract_violation_reason(
        reference_summary,
        target_summary,
    )
    if reference_summary.invalid_key_count > 0 or target_summary.invalid_key_count > 0:
        raise ComparisonKeyMappingError(
            reference_summary,
            target_summary,
            _result_metrics(usage),
            usage.reference_full_scans,
            usage.target_full_scans,
            contract_violation_reason,
        )
    if contract_violation_reason is not None:
        usage = _consume_source_usage(
            usage,
            source_budget,
            fingerprint_nodes=0,
            coordinator_peak_bytes=usage.coordinator_peak_bytes,
        )
        progress = replace(progress, usage=usage)
        yield progress
        return _completed_structural_artifact(
            check,
            scope,
            input_cut,
            reference_context,
            target_context,
            reference_summary,
            target_summary,
            usage,
            contract_violation_reason,
        )
    if check.assurance_policy is AssurancePolicy.EXACT_REQUIRED:
        raise UnsupportedComparisonError(
            "integer-range fingerprint comparison does not implement exact_required assurance"
        )
    if not reference_summary.usable_access_path or not target_summary.usable_access_path:
        raise UnsupportedComparisonError(
            "integer-range comparison requires a confirmed leading, non-partial, built-in "
            "PostgreSQL btree path on both protected relations"
        )

    pending: tuple[_PendingSegment, ...] = (root,)

    while pending:
        fingerprint_plan = _plan_fingerprint_level(
            pending,
            usage,
            budgets,
        )
        progress = replace(
            progress,
            usage=_usage_with_coordinator_peak(
                usage,
                fingerprint_plan.coordinator_peak_bytes,
            ),
        )
        usage = progress.usage
        yield progress
        reference_fingerprints, target_fingerprints, usage = _read_fingerprint_level(
            reference_context,
            reference_relation,
            validated.reference_scope,
            target_context,
            target_relation,
            validated.target_scope,
            validated.key_field_index,
            validated.max_encoded_row_bytes,
            pending,
            usage,
            budgets,
            read_deadline,
            source_budget,
            fingerprint_plan,
        )
        progress = replace(progress, usage=usage)
        yield progress
        level_nodes = _fingerprint_nodes(
            pending,
            reference_fingerprints,
            target_fingerprints,
            read_deadline.deadline_nanoseconds,
        )
        if pending[0].segment_sequence == 0:
            root_node = level_nodes[0]
            if root_node.reference.fingerprint.count != reference_summary.row_count:
                raise ComparisonProtocolError(
                    "reference root fingerprint count does not match its key summary"
                )
            if root_node.target.fingerprint.count != target_summary.row_count:
                raise ComparisonProtocolError(
                    "target root fingerprint count does not match its key summary"
                )
        matching, mismatching = _partition_fingerprint_nodes(
            level_nodes,
            read_deadline.deadline_nanoseconds,
        )
        if mismatching:
            progress = _progress_with_mismatch_witnesses(progress, mismatching)
            yield progress
        _require_deadline(read_deadline.deadline_nanoseconds)
        for index, node in enumerate(matching):
            if index % _DEADLINE_CHECK_RECORDS == 0:
                _require_deadline(read_deadline.deadline_nanoseconds)
            progress = replace(
                progress,
                topology=(
                    *progress.topology,
                    _segment_record(node, ComparisonSegmentState.FINGERPRINT_MATCH),
                ),
                pending=_without_pending_sequence(
                    progress.pending,
                    node.segment.segment_sequence,
                ),
                pruned_matched=(progress.pruned_matched + node.reference.fingerprint.count),
                pruned_segments=progress.pruned_segments + 1,
            )
            yield progress
        if not mismatching:
            pending = ()
            continue

        exact_reservation = _exact_frontier_reservation(
            mismatching,
            usage,
            budgets,
            validated.max_encoded_row_bytes,
            len(check.comparison_schema.schema.fields),
        )
        if _exact_frontier_fits(exact_reservation, usage, budgets, source_budget):
            progress = replace(
                progress,
                usage=_usage_with_coordinator_peak(
                    usage,
                    exact_reservation.coordinator_peak_bytes,
                ),
            )
            usage = progress.usage
            yield progress
            reference_exact, target_exact, usage = _read_exact_frontier(
                reference_context,
                reference_relation,
                validated.reference_scope,
                target_context,
                target_relation,
                validated.target_scope,
                validated.key_field_index,
                validated.max_encoded_row_bytes,
                mismatching,
                exact_reservation,
                usage,
                budgets,
                read_deadline,
                source_budget,
            )
            progress = replace(progress, usage=usage)
            yield progress
            reference_rows, target_rows = _group_exact_frontier_rows(
                mismatching,
                reference_exact,
                target_exact,
                read_deadline.deadline_nanoseconds,
            )
            for node in mismatching:
                counts, exact_record, differences = _classify_exact_leaf(
                    node,
                    reference_rows[_segment_id(node.segment.segment_sequence)],
                    target_rows[_segment_id(node.segment.segment_sequence)],
                    read_deadline.deadline_nanoseconds,
                )
                leaf_progress = replace(
                    progress,
                    exact_counts=_add_exact_counts(progress.exact_counts, counts),
                    exact_segments=progress.exact_segments + 1,
                    topology=(*progress.topology, exact_record),
                    pending=_without_pending_sequence(
                        progress.pending,
                        node.segment.segment_sequence,
                    ),
                    mismatch_witnesses=_without_mismatch_witness(
                        progress.mismatch_witnesses,
                        node.segment.segment_sequence,
                    ),
                )
                progress = _retain_exact_differences(
                    leaf_progress,
                    differences,
                    check,
                    evidence_policy,
                    budgets,
                    read_deadline.deadline_nanoseconds,
                )
                yield progress
            pending = progress.pending
            continue

        split_nodes: list[tuple[_FingerprintNode, tuple[_PendingSegment, _PendingSegment]]] = []
        next_sequence = usage.fingerprint_nodes
        for index, node in enumerate(mismatching):
            if index % _DEADLINE_CHECK_RECORDS == 0:
                _require_deadline(read_deadline.deadline_nanoseconds)
            split = _split_segment(node.segment, next_sequence)
            if split is None:
                raise ComparisonBudgetExceededError(
                    "mismatched single-key range does not fit the remaining exact-fetch budgets"
                )
            split_nodes.append((node, split))
            next_sequence += 2
        children = tuple(child for _, split in split_nodes for child in split)
        if any(child.depth > budgets.max_depth for child in children):
            raise ComparisonBudgetExceededError(
                "integer-range subdivision would exceed execution max_depth"
            )
        if usage.fingerprint_nodes + len(children) > budgets.max_fingerprint_nodes:
            raise ComparisonBudgetExceededError(
                "integer-range subdivision would exceed execution max_fingerprint_nodes"
            )
        processed_children: tuple[_PendingSegment, ...] = ()
        for index, (node, split) in enumerate(split_nodes):
            processed_children = (*processed_children, *split)
            remaining = tuple(item.segment for item, _ in split_nodes[index + 1 :])
            progress = replace(
                progress,
                topology=(
                    *progress.topology,
                    _segment_record(node, ComparisonSegmentState.SPLIT),
                ),
                pending=(*processed_children, *remaining),
                mismatch_witnesses=_without_mismatch_witness(
                    progress.mismatch_witnesses,
                    node.segment.segment_sequence,
                ),
            )
            yield progress
        pending = children

    ordered_topology = tuple(sorted(progress.topology, key=lambda item: item.segment_sequence))
    if tuple(item.segment_sequence for item in ordered_topology) != tuple(
        range(len(ordered_topology))
    ):
        raise ComparisonProtocolError("comparison segment topology is not contiguous")
    totals_values = _ExactCounts(
        matched=progress.pruned_matched + progress.exact_counts.matched,
        missing=progress.exact_counts.missing,
        extra=progress.exact_counts.extra,
        modified=progress.exact_counts.modified,
    )
    difference_count = totals_values.missing + totals_values.extra + totals_values.modified
    verdict = Verdict.MATCH if difference_count == 0 else Verdict.MISMATCH
    guarantee = Guarantee.FINGERPRINT if progress.pruned_segments > 0 else Guarantee.EXACT
    totals = _comparison_totals(totals_values, guarantee)
    reasons = _comparison_reasons(totals_values)
    _require_deadline(read_deadline.deadline_nanoseconds)
    usage = _consume_source_usage(
        usage,
        source_budget,
        fingerprint_nodes=0,
        coordinator_peak_bytes=usage.coordinator_peak_bytes,
    )
    progress = replace(progress, usage=usage)
    yield progress
    if progress.found_records != difference_count:
        raise ComparisonProtocolError(
            "retained evidence accounting differs from exact difference totals"
        )
    return CompletedComparisonArtifact(
        check_id=check.check_id,
        contract_digest=check.contract_digest,
        scope_digest=scope.scope_digest,
        input_cut_digest=input_cut.input_cut_digest,
        verdict=verdict,
        consistency=ConsistencyStatus(
            stable_reads=ConsistencyLevel.VERIFIED,
            cut_alignment=ConsistencyLevel.VERIFIED,
            read_context_ids=(
                reference_context.evidence.context_id,
                target_context.evidence.context_id,
            ),
        ),
        guarantee=guarantee,
        comparison_coverage=ComparisonCoverage(
            total_partitions=1,
            covered_partitions=1,
            resolved_segments=progress.pruned_segments + progress.exact_segments,
            pruned_segments=progress.pruned_segments,
            exact_segments=progress.exact_segments,
            unresolved_segments=0,
            unresolved_reasons=(),
        ),
        totals=totals,
        evidence_coverage=EvidenceCoverage(
            found_records=progress.found_records,
            retained_records=len(progress.anomalies),
            found_bytes=progress.found_bytes,
            retained_bytes=progress.retained_bytes,
        ),
        metrics=_result_metrics(usage),
        reasons=reasons,
        segments=ordered_topology,
        anomalies=progress.anomalies,
        reference_key_summary=reference_summary,
        target_key_summary=target_summary,
        reference_full_scans=usage.reference_full_scans,
        target_full_scans=usage.target_full_scans,
    )


def _partial_comparison_artifact(
    check: RowCheckDefinition,
    scope: ResolvedScope,
    input_cut: InputCutDefinition,
    reference_context: PostgresProtectedReadContext,
    target_context: PostgresProtectedReadContext,
    source_budget: PostgresSourceBudgetAttempt,
    progress: _ComparisonProgress,
    cause: ComparisonInterruptionCause,
) -> PartialComparisonArtifact:
    reason = _interruption_reason_code(cause)
    contract_violation = (
        cause.contract_violation_reason if isinstance(cause, ComparisonKeyMappingError) else None
    )
    topology = tuple(sorted(progress.topology, key=lambda item: item.segment_sequence))
    topology_sequences = {item.segment_sequence for item in topology}
    unresolved_pending = tuple(
        sorted(
            (item for item in progress.pending if item.segment_sequence not in topology_sequences),
            key=lambda item: item.segment_sequence,
        )
    )
    witnesses = {item.segment.segment_sequence: item for item in progress.mismatch_witnesses}
    unresolved = tuple(
        UnresolvedComparisonSegment(
            segment_sequence=item.segment_sequence,
            parent_segment_sequence=item.parent_segment_sequence,
            depth=item.depth,
            lower_inclusive=item.lower_inclusive,
            upper_exclusive=item.upper_exclusive,
            reason=reason,
            reference_fingerprint=(
                None
                if item.segment_sequence not in witnesses
                else witnesses[item.segment_sequence].reference.fingerprint
            ),
            target_fingerprint=(
                None
                if item.segment_sequence not in witnesses
                else witnesses[item.segment_sequence].target.fingerprint
            ),
        )
        for item in unresolved_pending
    )
    pruned_segments = sum(
        item.state is ComparisonSegmentState.FINGERPRINT_MATCH for item in topology
    )
    exact_segments = sum(
        item.state in (ComparisonSegmentState.EXACT_MATCH, ComparisonSegmentState.EXACT_MISMATCH)
        for item in topology
    )
    resolved_segments = pruned_segments + exact_segments
    usage = _consume_source_usage(
        progress.usage,
        source_budget,
        fingerprint_nodes=0,
        coordinator_peak_bytes=progress.usage.coordinator_peak_bytes,
    )
    has_proven_difference = (
        progress.exact_counts.missing + progress.exact_counts.extra + progress.exact_counts.modified
        > 0
    )
    has_fingerprint_mismatch = any(
        item.reference_fingerprint != item.target_fingerprint for item in topology
    ) or any(item.reference_fingerprint is not None for item in unresolved)
    return PartialComparisonArtifact(
        check_id=check.check_id,
        contract_digest=check.contract_digest,
        scope_digest=scope.scope_digest,
        input_cut_digest=input_cut.input_cut_digest,
        verdict=(
            Verdict.MISMATCH
            if (has_proven_difference or has_fingerprint_mismatch or contract_violation is not None)
            else Verdict.INCONCLUSIVE
        ),
        consistency=ConsistencyStatus(
            stable_reads=(
                ConsistencyLevel.VERIFIED
                if progress.summaries_verified
                else ConsistencyLevel.UNKNOWN
            ),
            cut_alignment=ConsistencyLevel.VERIFIED,
            read_context_ids=(
                reference_context.evidence.context_id,
                target_context.evidence.context_id,
            ),
        ),
        guarantee=Guarantee.NOT_ESTABLISHED,
        comparison_coverage=ComparisonCoverage(
            total_partitions=1,
            covered_partitions=(1 if not unresolved and resolved_segments > 0 else 0),
            resolved_segments=resolved_segments,
            pruned_segments=pruned_segments,
            exact_segments=exact_segments,
            unresolved_segments=len(unresolved),
            unresolved_reasons=(() if not unresolved else (reason,)),
        ),
        totals=_partial_totals(progress.exact_counts, exact_segments, reason),
        evidence_coverage=EvidenceCoverage(
            found_records=progress.found_records,
            retained_records=len(progress.anomalies),
            found_bytes=progress.found_bytes,
            retained_bytes=progress.retained_bytes,
        ),
        metrics=_result_metrics(usage),
        frontier=PartialComparisonFrontier(topology=topology, unresolved=unresolved),
        anomalies=tuple(progress.anomalies),
        reference_full_scans=usage.reference_full_scans,
        target_full_scans=usage.target_full_scans,
    )


def partial_comparison_artifact_from_completed(
    artifact: CompletedComparisonArtifact | CompletedStructuralComparisonArtifact,
    reason_code: ReasonCode,
) -> PartialComparisonArtifact:
    _require_instance(reason_code, ReasonCode, "partial cleanup reason")
    if isinstance(artifact, CompletedStructuralComparisonArtifact):
        return PartialComparisonArtifact(
            check_id=artifact.check_id,
            contract_digest=artifact.contract_digest,
            scope_digest=artifact.scope_digest,
            input_cut_digest=artifact.input_cut_digest,
            verdict=Verdict.MISMATCH,
            consistency=artifact.consistency,
            guarantee=Guarantee.NOT_ESTABLISHED,
            comparison_coverage=artifact.comparison_coverage,
            totals=artifact.totals,
            evidence_coverage=artifact.evidence_coverage,
            metrics=artifact.metrics,
            frontier=PartialComparisonFrontier(topology=(), unresolved=()),
            anomalies=(),
            reference_full_scans=artifact.reference_full_scans,
            target_full_scans=artifact.target_full_scans,
        )
    artifact = _require_instance(
        artifact,
        CompletedComparisonArtifact,
        "completed comparison artifact",
    )
    exact_reference_rows = sum(
        segment.reference_fingerprint.count
        for segment in artifact.segments
        if segment.state
        in (ComparisonSegmentState.EXACT_MATCH, ComparisonSegmentState.EXACT_MISMATCH)
    )
    missing = _available_total_integer(artifact.totals.missing, "missing")
    extra = _available_total_integer(artifact.totals.extra, "extra")
    modified = _available_total_integer(artifact.totals.modified, "modified")
    exact_matched = exact_reference_rows - missing - modified
    if exact_matched < 0:
        raise ValueError("completed comparison exact leaves do not close to its totals")
    exact_counts = _ExactCounts(
        matched=exact_matched,
        missing=missing,
        extra=extra,
        modified=modified,
    )
    return PartialComparisonArtifact(
        check_id=artifact.check_id,
        contract_digest=artifact.contract_digest,
        scope_digest=artifact.scope_digest,
        input_cut_digest=artifact.input_cut_digest,
        verdict=(
            Verdict.MISMATCH if artifact.verdict is Verdict.MISMATCH else Verdict.INCONCLUSIVE
        ),
        consistency=artifact.consistency,
        guarantee=Guarantee.NOT_ESTABLISHED,
        comparison_coverage=artifact.comparison_coverage,
        totals=_partial_totals(
            exact_counts,
            artifact.comparison_coverage.exact_segments,
            reason_code,
        ),
        evidence_coverage=artifact.evidence_coverage,
        metrics=artifact.metrics,
        frontier=PartialComparisonFrontier(topology=artifact.segments, unresolved=()),
        anomalies=artifact.anomalies,
        reference_full_scans=artifact.reference_full_scans,
        target_full_scans=artifact.target_full_scans,
    )


def _partial_totals(
    counts: _ExactCounts,
    exact_segments: int,
    reason: ReasonCode,
) -> ComparisonTotals:
    if exact_segments > 0:
        return ComparisonTotals(
            matched=LowerBoundTotal(precision="lower_bound", value=str(counts.matched)),
            missing=LowerBoundTotal(precision="lower_bound", value=str(counts.missing)),
            extra=LowerBoundTotal(precision="lower_bound", value=str(counts.extra)),
            modified=LowerBoundTotal(precision="lower_bound", value=str(counts.modified)),
        )
    unavailable = UnavailableTotal(precision="unavailable", value=None, reason=reason)
    return ComparisonTotals(
        matched=unavailable,
        missing=unavailable,
        extra=unavailable,
        modified=unavailable,
    )


def _available_total_integer(total: object, name: str) -> int:
    if not isinstance(total, (ExactTotal, InferredTotal, LowerBoundTotal)):
        raise ValueError(f"completed comparison {name} total must be available")
    return int(total.value)


def _interruption_reason_code(cause: ComparisonInterruptionCause) -> ReasonCode:
    if isinstance(
        cause,
        (
            ComparisonBudgetExceededError,
            PostgresReadDeadlineExceededError,
            PostgresResultLimitError,
            PostgresSourceBudgetExceededError,
        ),
    ):
        return ReasonCode.BUDGET_EXHAUSTED
    if isinstance(cause, (PostgresContextLostError, PostgresAcquisitionRaceError)):
        return ReasonCode.SNAPSHOT_LOST
    if isinstance(cause, ComparisonKeyMappingError):
        return ReasonCode.LOSSY_TRANSPORT
    if isinstance(cause, (UnsupportedComparisonError, UnsupportedPostgresProfileError)):
        return ReasonCode.UNSUPPORTED_CAPABILITY
    if isinstance(
        cause,
        (
            ComparisonProtocolError,
            PostgresContextClosedError,
            PostgresDataValidationError,
            PostgresQueryContextError,
        ),
    ):
        return ReasonCode.PROTOCOL_VIOLATION
    if isinstance(cause, PostgresConnectorError):
        return ReasonCode.QUERY_ERROR
    raise AssertionError(f"unhandled comparison interruption {type(cause).__name__}")


def _without_pending_sequence(
    pending: tuple[_PendingSegment, ...],
    segment_sequence: int,
) -> tuple[_PendingSegment, ...]:
    return tuple(item for item in pending if item.segment_sequence != segment_sequence)


def _progress_with_mismatch_witnesses(
    progress: _ComparisonProgress,
    nodes: tuple[_FingerprintNode, ...],
) -> _ComparisonProgress:
    by_sequence = {
        item.segment.segment_sequence: item for item in (*progress.mismatch_witnesses, *nodes)
    }
    return replace(
        progress,
        mismatch_witnesses=tuple(by_sequence[key] for key in sorted(by_sequence)),
    )


def _without_mismatch_witness(
    witnesses: tuple[_FingerprintNode, ...],
    segment_sequence: int,
) -> tuple[_FingerprintNode, ...]:
    return tuple(item for item in witnesses if item.segment.segment_sequence != segment_sequence)


def _validate_inputs(
    reference_context: PostgresProtectedReadContext,
    reference_relation: PostgresProtectedRelationInspection,
    target_context: PostgresProtectedReadContext,
    target_relation: PostgresProtectedRelationInspection,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    input_cut: InputCutDefinition,
    budgets: ExecutionBudgets,
) -> _ValidatedInputs:
    if len(check.key) != 1:
        raise UnsupportedComparisonError(
            "integer-range comparison requires exactly one logical key field"
        )
    key_name = check.key[0]
    key_indexes = tuple(
        index
        for index, field in enumerate(check.comparison_schema.schema.fields)
        if field.name == key_name
    )
    if len(key_indexes) != 1:
        raise UnsupportedComparisonError(
            "integer-range comparison key does not identify exactly one comparison field"
        )
    key_field_index = key_indexes[0]
    key_field = check.comparison_schema.schema.fields[key_field_index]
    if key_field.logical_type is not LogicalType.INT64 or key_field.nullable:
        raise UnsupportedComparisonError(
            "integer-range comparison requires one non-null logical INT64 key"
        )
    if check.reference.grain != check.key or check.target.grain != check.key:
        raise UnsupportedComparisonError(
            "integer-range comparison requires the key to equal both dataset grains"
        )
    if budgets.max_full_scans_per_side < 1:
        raise ComparisonBudgetExceededError(
            "integer-key summary requires one reserved full scan per side"
        )
    if reference_context.state is not ReadContextState.ACTIVE:
        raise ComparisonProtocolError("reference protected read context must be active")
    if target_context.state is not ReadContextState.ACTIVE:
        raise ComparisonProtocolError("target protected read context must be active")
    if not any(item is reference_relation for item in reference_context.protected_relations):
        raise ComparisonProtocolError(
            "reference relation inspection does not belong to the exact protected context"
        )
    if not any(item is target_relation for item in target_context.protected_relations):
        raise ComparisonProtocolError(
            "target relation inspection does not belong to the exact protected context"
        )
    reference_context_id = reference_context.evidence.context_id
    target_context_id = target_context.evidence.context_id
    if reference_context_id == target_context_id:
        raise ComparisonProtocolError(
            "reference and target comparisons require two distinct protected context IDs"
        )
    _validate_dataset_relation(check.reference, reference_relation, "reference")
    _validate_dataset_relation(check.target, target_relation, "target")
    for direction, consistency in zip(
        ("reference", "target"),
        check.consistency.datasets,
        strict=True,
    ):
        if not isinstance(consistency.readiness, RelationManifestReadiness):
            raise UnsupportedComparisonError(
                f"{direction} comparison requires relation-manifest readiness"
            )
        if consistency.stable_read is not StableReadKind.TRANSACTION_SNAPSHOT:
            raise UnsupportedComparisonError(
                f"{direction} comparison requires transaction-snapshot stable reads"
            )
    expected_scope = tuple(
        (parameter.name, parameter.field) for parameter in check.scope.parameters
    )
    actual_scope = tuple((parameter.name, parameter.field) for parameter in scope.parameters)
    if actual_scope != expected_scope:
        raise UnsupportedComparisonError(
            "resolved scope parameters are outside the row-check closure"
        )
    reference_scope = _scope_predicate_for_dataset(check, scope, check.reference)
    target_scope = _scope_predicate_for_dataset(check, scope, check.target)
    _validate_input_cut(check, scope, input_cut)
    maximum_segment_id_bytes = len(f"s{max(0, budgets.max_fingerprint_nodes - 1)}".encode("ascii"))
    available_exact_bytes = min(
        budgets.max_application_result_bytes,
        INT64_MAX,
    )
    max_encoded_row_bytes = (
        available_exact_bytes
        - _MAX_INT64_KEY_ENVELOPE_BYTES
        - maximum_segment_id_bytes
        - _EXACT_STATUS_BYTES
    )
    if max_encoded_row_bytes < 1:
        raise ComparisonBudgetExceededError(
            "application-result budget cannot hold one canonical exact row"
        )
    return _ValidatedInputs(
        key_field_index=key_field_index,
        reference_scope=reference_scope,
        target_scope=target_scope,
        max_encoded_row_bytes=max_encoded_row_bytes,
    )


def _validate_dataset_relation(
    dataset: DatasetDefinition,
    relation: PostgresProtectedRelationInspection,
    direction: str,
) -> None:
    if not isinstance(dataset.locator, RelationLocator):
        raise UnsupportedComparisonError(
            f"{direction} integer-range comparison does not support opaque SQL datasets"
        )
    if dataset.locator.relation_scope is not RelationScope.PHYSICAL_ONLY:
        raise UnsupportedComparisonError(
            f"{direction} integer-range comparison requires a physical-only relation"
        )
    expected_relation = (dataset.locator.schema, dataset.locator.name)
    if relation.acquisition.relation.components != expected_relation:
        raise ComparisonProtocolError(
            f"{direction} protected acquisition does not match the contract relation"
        )
    if relation.inspection.relation.components != expected_relation:
        raise ComparisonProtocolError(
            f"{direction} protected inspection resolved outside the contract relation"
        )
    if relation.acquisition.schema != dataset.logical_schema.schema:
        raise ComparisonProtocolError(
            f"{direction} protected acquisition schema does not match the dataset schema"
        )
    expected_columns = tuple(item.column_name for item in dataset.projection)
    if relation.acquisition.column_names != expected_columns:
        raise ComparisonProtocolError(
            f"{direction} protected acquisition projection does not match the dataset"
        )


def _scope_predicate_for_dataset(
    check: RowCheckDefinition,
    scope: ResolvedScope,
    dataset: DatasetDefinition,
) -> PostgresScopePredicate | None:
    if not scope.parameters:
        if check.scope.bindings:
            raise ComparisonProtocolError("full scope must not contain physical bindings")
        return None
    if len(scope.parameters) != 1:
        raise UnsupportedComparisonError("integer-range comparison supports one scope parameter")
    bindings = tuple(
        binding for binding in check.scope.bindings if binding.dataset_id == dataset.dataset_id
    )
    if len(bindings) != 1:
        raise ComparisonProtocolError("scoped comparison requires one binding for each dataset")
    binding = bindings[0]
    parameter = scope.parameters[0]
    if binding.operator is not ScopeOperator.EQUAL or binding.parameter != parameter.name:
        raise UnsupportedComparisonError(
            "integer-range comparison supports only the declared single equality scope"
        )
    matching_projection = tuple(
        projected for projected in dataset.projection if projected.column_name == binding.column
    )
    if len(matching_projection) != 1:
        raise UnsupportedComparisonError(
            "scoped integer-range comparison requires the scope column in the inspected "
            "dataset projection exactly once"
        )
    return PostgresScopePredicate(
        field=parameter.field,
        column_name=binding.column,
        canonical_payload=parameter.canonical_payload,
    )


def _validate_input_cut(
    check: RowCheckDefinition,
    scope: ResolvedScope,
    input_cut: InputCutDefinition,
) -> None:
    if input_cut.reference.dataset_id != check.reference.dataset_id:
        raise ComparisonProtocolError("input cut reference dataset does not match the check")
    if input_cut.target.dataset_id != check.target.dataset_id:
        raise ComparisonProtocolError("input cut target dataset does not match the check")
    if (
        input_cut.reference.scope_digest != scope.scope_digest
        or input_cut.target.scope_digest != scope.scope_digest
    ):
        raise ComparisonProtocolError("input cut scope digest does not match the resolved scope")
    if input_cut.late_arrivals is not check.consistency.late_arrivals:
        raise ComparisonProtocolError("input cut late-arrival policy does not match the row check")
    expected_fields = check.consistency.alignment_fields
    reference_fields = tuple(value.field.name for value in input_cut.reference.alignment_values)
    target_fields = tuple(value.field.name for value in input_cut.target.alignment_values)
    if reference_fields != expected_fields or target_fields != expected_fields:
        raise ComparisonProtocolError(
            "input cut alignment fields do not match the row-check consistency policy"
        )
    if classify_input_cut_alignment(input_cut) is not None:
        raise ComparisonProtocolError("reference and target input cuts are not aligned")


def _completed_structural_artifact(
    check: RowCheckDefinition,
    scope: ResolvedScope,
    input_cut: InputCutDefinition,
    reference_context: PostgresProtectedReadContext,
    target_context: PostgresProtectedReadContext,
    reference_summary: PostgresIntegerKeySummary,
    target_summary: PostgresIntegerKeySummary,
    usage: _Usage,
    reason: ResultReason,
) -> CompletedStructuralComparisonArtifact:
    return CompletedStructuralComparisonArtifact(
        check_id=check.check_id,
        contract_digest=check.contract_digest,
        scope_digest=scope.scope_digest,
        input_cut_digest=input_cut.input_cut_digest,
        verdict=Verdict.MISMATCH,
        consistency=ConsistencyStatus(
            stable_reads=ConsistencyLevel.VERIFIED,
            cut_alignment=ConsistencyLevel.VERIFIED,
            read_context_ids=(
                reference_context.evidence.context_id,
                target_context.evidence.context_id,
            ),
        ),
        guarantee=Guarantee.STRUCTURAL,
        comparison_coverage=ComparisonCoverage(
            total_partitions=1,
            covered_partitions=1,
            resolved_segments=1,
            pruned_segments=0,
            exact_segments=1,
            unresolved_segments=0,
            unresolved_reasons=(),
        ),
        totals=_unavailable_contract_totals(),
        evidence_coverage=EvidenceCoverage(
            found_records=0,
            retained_records=0,
            found_bytes=0,
            retained_bytes=0,
        ),
        metrics=_result_metrics(usage),
        reasons=(reason,),
        reference_key_summary=reference_summary,
        target_key_summary=target_summary,
        reference_full_scans=usage.reference_full_scans,
        target_full_scans=usage.target_full_scans,
    )


def _structural_contract_violation_reason(
    reference: PostgresIntegerKeySummary,
    target: PostgresIntegerKeySummary,
) -> ResultReason | None:
    if (
        reference.null_key_count == 0
        and reference.valid_key_count == reference.distinct_key_count
        and target.null_key_count == 0
        and target.valid_key_count == target.distinct_key_count
    ):
        return None
    return ResultReason(
        code=ReasonCode.CONTRACT_VIOLATION,
        operation="validate_integer_key_contract",
        message="scoped integer-key validation found null or duplicate keys",
        safe_parameters=_key_summary_safe_parameters(reference, target),
        native_error_code=None,
        query_id=None,
        redacted_response=None,
    )


def _key_summary_safe_parameters(
    reference: PostgresIntegerKeySummary,
    target: PostgresIntegerKeySummary,
) -> tuple[SafeParameter, ...]:
    return tuple(
        SafeParameter(name=name, value=str(value))
        for name, value in (
            ("reference_row_count", reference.row_count),
            ("reference_null_key_count", reference.null_key_count),
            ("reference_invalid_key_count", reference.invalid_key_count),
            ("reference_valid_key_count", reference.valid_key_count),
            ("reference_distinct_key_count", reference.distinct_key_count),
            ("target_row_count", target.row_count),
            ("target_null_key_count", target.null_key_count),
            ("target_invalid_key_count", target.invalid_key_count),
            ("target_valid_key_count", target.valid_key_count),
            ("target_distinct_key_count", target.distinct_key_count),
        )
    )


def _unavailable_contract_totals() -> ComparisonTotals:
    return ComparisonTotals(
        matched=UnavailableTotal(
            precision="unavailable",
            value=None,
            reason=ReasonCode.CONTRACT_VIOLATION,
        ),
        missing=UnavailableTotal(
            precision="unavailable",
            value=None,
            reason=ReasonCode.CONTRACT_VIOLATION,
        ),
        extra=UnavailableTotal(
            precision="unavailable",
            value=None,
            reason=ReasonCode.CONTRACT_VIOLATION,
        ),
        modified=UnavailableTotal(
            precision="unavailable",
            value=None,
            reason=ReasonCode.CONTRACT_VIOLATION,
        ),
    )


def _validate_structural_artifact(artifact: CompletedStructuralComparisonArtifact) -> None:
    if artifact.consistency.stable_reads is not ConsistencyLevel.VERIFIED:
        raise ValueError("completed structural comparison requires verified stable reads")
    if artifact.consistency.cut_alignment is not ConsistencyLevel.VERIFIED:
        raise ValueError("completed structural comparison requires verified cut alignment")
    if len(artifact.consistency.read_context_ids) != 2:
        raise ValueError("completed structural comparison requires two read contexts")
    expected_coverage = ComparisonCoverage(
        total_partitions=1,
        covered_partitions=1,
        resolved_segments=1,
        pruned_segments=0,
        exact_segments=1,
        unresolved_segments=0,
        unresolved_reasons=(),
    )
    if artifact.comparison_coverage != expected_coverage:
        raise ValueError(
            "completed structural comparison requires one resolved exact logical partition"
        )
    if artifact.totals != _unavailable_contract_totals():
        raise ValueError("completed structural comparison requires unavailable contract totals")
    if artifact.evidence_coverage != EvidenceCoverage(
        found_records=0,
        retained_records=0,
        found_bytes=0,
        retained_bytes=0,
    ):
        raise ValueError("completed structural comparison cannot claim retained row evidence")
    if (
        artifact.metrics.queries < 2
        or artifact.metrics.fetched_records < 2
        or artifact.metrics.fingerprint_nodes != 0
    ):
        raise ValueError("completed structural comparison requires both summary-read receipts")
    if artifact.reference_full_scans != 1 or artifact.target_full_scans != 1:
        raise ValueError("completed structural comparison requires one summary scan per side")
    if artifact.reference_key_summary.invalid_key_count != 0:
        raise ValueError("reference structural result cannot include invalid mapped keys")
    if artifact.target_key_summary.invalid_key_count != 0:
        raise ValueError("target structural result cannot include invalid mapped keys")
    expected_reason = _structural_contract_violation_reason(
        artifact.reference_key_summary,
        artifact.target_key_summary,
    )
    if expected_reason is None or artifact.reasons != (expected_reason,):
        raise ValueError(
            "completed structural comparison reason must exactly encode its key summaries"
        )


def _root_segment(
    reference: PostgresIntegerKeySummary,
    target: PostgresIntegerKeySummary,
) -> _PendingSegment:
    minimums = tuple(
        value for value in (reference.minimum_key, target.minimum_key) if value is not None
    )
    maximums = tuple(
        value for value in (reference.maximum_key, target.maximum_key) if value is not None
    )
    if not minimums:
        lower = INT64_MIN
        upper: int | None = None
    else:
        lower = min(minimums)
        maximum = max(maximums)
        upper = None if maximum == INT64_MAX else maximum + 1
    return _PendingSegment(
        segment_sequence=0,
        parent_segment_sequence=None,
        depth=0,
        lower_inclusive=lower,
        upper_exclusive=upper,
    )


def _plan_fingerprint_level(
    pending: tuple[_PendingSegment, ...],
    usage: _Usage,
    budgets: ExecutionBudgets,
) -> _FingerprintLevelPlan:
    if usage.fingerprint_nodes + len(pending) > budgets.max_fingerprint_nodes:
        raise ComparisonBudgetExceededError(
            "next fingerprint level exceeds execution max_fingerprint_nodes"
        )
    requests = tuple(_range_request(item) for item in pending)
    side_result_bytes = sum(_fingerprint_record_bytes(item.segment_id) for item in requests)
    record_bytes = max(_fingerprint_record_bytes(item.segment_id) for item in requests)
    return _FingerprintLevelPlan(
        requests=requests,
        side_result_bytes=side_result_bytes,
        record_bytes=record_bytes,
        coordinator_peak_bytes=_fingerprint_phase_memory_bytes(
            usage,
            pending,
            requests,
            budgets,
            side_result_bytes,
        ),
    )


def _read_fingerprint_level(
    reference_context: PostgresProtectedReadContext,
    reference_relation: PostgresProtectedRelationInspection,
    reference_scope: PostgresScopePredicate | None,
    target_context: PostgresProtectedReadContext,
    target_relation: PostgresProtectedRelationInspection,
    target_scope: PostgresScopePredicate | None,
    key_field_index: int,
    max_encoded_row_bytes: int,
    pending: tuple[_PendingSegment, ...],
    usage: _Usage,
    budgets: ExecutionBudgets,
    read_deadline: PostgresReadDeadline,
    source_budget: PostgresSourceBudgetAttempt,
    plan: _FingerprintLevelPlan,
) -> tuple[PostgresRangeFingerprintRead, PostgresRangeFingerprintRead, _Usage]:
    _require_full_scan_capacity(
        source_budget,
        reference_full_scans=len(plan.requests),
        target_full_scans=len(plan.requests),
    )
    _require_budget_capacity(
        source_budget,
        budgets,
        additional_queries=4,
        additional_records=(2 * len(plan.requests)) + 2,
        additional_result_bytes=((2 * plan.side_result_bytes) + (2 * _SESSION_SETUP_RECORD_BYTES)),
        coordinator_bytes=plan.coordinator_peak_bytes,
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    reference_read = reference_context.read_integer_range_fingerprints(
        reference_relation,
        key_field_index,
        reference_scope,
        plan.requests,
        max_encoded_row_bytes,
        plan.record_bytes,
        plan.side_result_bytes,
        read_deadline,
        len(plan.requests),
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    target_read = target_context.read_integer_range_fingerprints(
        target_relation,
        key_field_index,
        target_scope,
        plan.requests,
        max_encoded_row_bytes,
        plan.record_bytes,
        plan.side_result_bytes,
        read_deadline,
        len(plan.requests),
    )
    next_usage = _consume_source_usage(
        usage,
        source_budget,
        fingerprint_nodes=len(plan.requests),
        coordinator_peak_bytes=plan.coordinator_peak_bytes,
    )
    return reference_read, target_read, next_usage


def _fingerprint_nodes(
    pending: tuple[_PendingSegment, ...],
    reference: PostgresRangeFingerprintRead,
    target: PostgresRangeFingerprintRead,
    deadline_nanoseconds: int,
) -> tuple[_FingerprintNode, ...]:
    if len(reference.ranges) != len(pending) or len(target.ranges) != len(pending):
        raise ComparisonProtocolError(
            "fingerprint connector receipts do not cover the requested range level"
        )
    result: list[_FingerprintNode] = []
    for index, (segment, reference_range, target_range) in enumerate(
        zip(pending, reference.ranges, target.ranges, strict=True)
    ):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        expected_id = _segment_id(segment.segment_sequence)
        if reference_range.segment_id != expected_id or target_range.segment_id != expected_id:
            raise ComparisonProtocolError(
                "fingerprint connector receipts do not preserve segment identity"
            )
        result.append(
            _FingerprintNode(
                segment=segment,
                reference=reference_range,
                target=target_range,
            )
        )
    _require_deadline(deadline_nanoseconds)
    return tuple(result)


def _partition_fingerprint_nodes(
    nodes: tuple[_FingerprintNode, ...],
    deadline_nanoseconds: int,
) -> tuple[tuple[_FingerprintNode, ...], tuple[_FingerprintNode, ...]]:
    matching: list[_FingerprintNode] = []
    mismatching: list[_FingerprintNode] = []
    for index, node in enumerate(nodes):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        if node.reference.fingerprint == node.target.fingerprint:
            matching.append(node)
        else:
            mismatching.append(node)
    _require_deadline(deadline_nanoseconds)
    return tuple(matching), tuple(mismatching)


def _exact_frontier_fits(
    reservation: _ExactFrontierReservation,
    usage: _Usage,
    budgets: ExecutionBudgets,
    source_budget: PostgresSourceBudgetAttempt,
) -> bool:
    reserved_result_bytes = max(1, reservation.reference.result_bytes) + max(
        1,
        reservation.target.result_bytes,
    )
    remaining = source_budget.remaining()
    return (
        remaining.queries >= 4
        and remaining.fetched_records
        >= reservation.reference.records + reservation.target.records + 2
        and remaining.result_bytes >= reserved_result_bytes + (2 * _SESSION_SETUP_RECORD_BYTES)
        and reservation.coordinator_peak_bytes <= budgets.max_coordinator_memory_bytes
        and remaining.reference_full_scans >= reservation.reference.full_scans
        and remaining.target_full_scans >= reservation.target.full_scans
    )


def _read_exact_frontier(
    reference_context: PostgresProtectedReadContext,
    reference_relation: PostgresProtectedRelationInspection,
    reference_scope: PostgresScopePredicate | None,
    target_context: PostgresProtectedReadContext,
    target_relation: PostgresProtectedRelationInspection,
    target_scope: PostgresScopePredicate | None,
    key_field_index: int,
    max_encoded_row_bytes: int,
    nodes: tuple[_FingerprintNode, ...],
    reservation: _ExactFrontierReservation,
    usage: _Usage,
    budgets: ExecutionBudgets,
    read_deadline: PostgresReadDeadline,
    source_budget: PostgresSourceBudgetAttempt,
) -> tuple[PostgresIntegerExactRowsRead, PostgresIntegerExactRowsRead, _Usage]:
    requests = tuple(_range_request(node.segment) for node in nodes)
    reference_limit = max(1, reservation.reference.result_bytes)
    target_limit = max(1, reservation.target.result_bytes)
    _require_full_scan_capacity(
        source_budget,
        reference_full_scans=reservation.reference.full_scans,
        target_full_scans=reservation.target.full_scans,
    )
    _require_budget_capacity(
        source_budget,
        budgets,
        additional_queries=4,
        additional_records=(reservation.reference.records + reservation.target.records + 2),
        additional_result_bytes=(
            reference_limit + target_limit + (2 * _SESSION_SETUP_RECORD_BYTES)
        ),
        coordinator_bytes=reservation.coordinator_peak_bytes,
    )
    maximum_record_bytes = (
        max_encoded_row_bytes
        + _MAX_INT64_KEY_ENVELOPE_BYTES
        + max(len(item.segment_id.encode("ascii")) for item in requests)
        + _EXACT_STATUS_BYTES
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    reference_read = reference_context.read_integer_range_rows(
        reference_relation,
        key_field_index,
        reference_scope,
        requests,
        max_encoded_row_bytes,
        max(1, reservation.reference.records),
        min(maximum_record_bytes, reference_limit),
        reference_limit,
        read_deadline,
        reservation.reference.full_scans,
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    target_read = target_context.read_integer_range_rows(
        target_relation,
        key_field_index,
        target_scope,
        requests,
        max_encoded_row_bytes,
        max(1, reservation.target.records),
        min(maximum_record_bytes, target_limit),
        target_limit,
        read_deadline,
        reservation.target.full_scans,
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    if reference_read.metrics.fetched_records != reservation.reference.records:
        raise ComparisonProtocolError(
            "reference exact frontier row count differs from its fingerprints"
        )
    if target_read.metrics.fetched_records != reservation.target.records:
        raise ComparisonProtocolError(
            "target exact frontier row count differs from its fingerprints"
        )
    if reference_read.metrics.result_bytes != reservation.reference.result_bytes:
        raise ComparisonProtocolError(
            "reference exact frontier byte count differs from its fingerprint preflight"
        )
    if target_read.metrics.result_bytes != reservation.target.result_bytes:
        raise ComparisonProtocolError(
            "target exact frontier byte count differs from its fingerprint preflight"
        )
    next_usage = _consume_source_usage(
        usage,
        source_budget,
        fingerprint_nodes=0,
        coordinator_peak_bytes=reservation.coordinator_peak_bytes,
    )
    return reference_read, target_read, next_usage


def _group_exact_frontier_rows(
    nodes: tuple[_FingerprintNode, ...],
    reference: PostgresIntegerExactRowsRead,
    target: PostgresIntegerExactRowsRead,
    deadline_nanoseconds: int,
) -> tuple[
    dict[str, tuple[PostgresIntegerExactRow, ...]],
    dict[str, tuple[PostgresIntegerExactRow, ...]],
]:
    _require_deadline(deadline_nanoseconds)
    segment_ids = tuple(_segment_id(node.segment.segment_sequence) for node in nodes)
    reference_rows = _group_exact_rows(reference.rows, segment_ids, deadline_nanoseconds)
    target_rows = _group_exact_rows(target.rows, segment_ids, deadline_nanoseconds)
    _require_deadline(deadline_nanoseconds)
    return reference_rows, target_rows


def _classify_exact_leaf(
    node: _FingerprintNode,
    reference_rows: tuple[PostgresIntegerExactRow, ...],
    target_rows: tuple[PostgresIntegerExactRow, ...],
    deadline_nanoseconds: int,
) -> tuple[_ExactCounts, ComparisonSegmentRecord, tuple[_ExactDifference, ...]]:
    _require_deadline(deadline_nanoseconds)
    if len(reference_rows) != node.reference.fingerprint.count:
        raise ComparisonProtocolError("reference exact segment count differs from its fingerprint")
    if len(target_rows) != node.target.fingerprint.count:
        raise ComparisonProtocolError("target exact segment count differs from its fingerprint")
    counts, differences = _compare_exact_rows(
        reference_rows,
        target_rows,
        node.segment.segment_sequence,
        deadline_nanoseconds,
    )
    if counts.matched + counts.missing + counts.modified != node.reference.fingerprint.count:
        raise ComparisonProtocolError(
            "reference exact classifications do not close to the segment fingerprint"
        )
    if counts.matched + counts.extra + counts.modified != node.target.fingerprint.count:
        raise ComparisonProtocolError(
            "target exact classifications do not close to the segment fingerprint"
        )
    difference_count = counts.missing + counts.extra + counts.modified
    if difference_count == 0 and node.reference.fingerprint != node.target.fingerprint:
        raise ComparisonProtocolError("unequal segment fingerprints resolved to equal exact rows")
    state = (
        ComparisonSegmentState.EXACT_MATCH
        if difference_count == 0
        else ComparisonSegmentState.EXACT_MISMATCH
    )
    return counts, _segment_record(node, state), differences


def _group_exact_rows(
    rows: tuple[PostgresIntegerExactRow, ...],
    segment_ids: tuple[str, ...],
    deadline_nanoseconds: int,
) -> dict[str, tuple[PostgresIntegerExactRow, ...]]:
    grouped_lists: dict[str, list[PostgresIntegerExactRow]] = {
        segment_id: [] for segment_id in segment_ids
    }
    for index, row in enumerate(rows):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        group = grouped_lists.get(row.segment_id)
        if group is None:
            raise ComparisonProtocolError(
                "exact frontier receipt contains an unrequested segment ID"
            )
        group.append(row)
    grouped: dict[str, tuple[PostgresIntegerExactRow, ...]] = {}
    for index, (segment_id, values) in enumerate(grouped_lists.items()):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        grouped[segment_id] = tuple(values)
    _require_deadline(deadline_nanoseconds)
    return grouped


def _compare_exact_rows(
    reference: tuple[PostgresIntegerExactRow, ...],
    target: tuple[PostgresIntegerExactRow, ...],
    segment_sequence: int,
    deadline_nanoseconds: int,
) -> tuple[_ExactCounts, tuple[_ExactDifference, ...]]:
    reference_index = 0
    target_index = 0
    matched = 0
    missing = 0
    extra = 0
    modified = 0
    classified_records = 0
    differences: list[_ExactDifference] = []
    while reference_index < len(reference) and target_index < len(target):
        if classified_records % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        reference_row = reference[reference_index]
        target_row = target[target_index]
        if reference_row.key_value < target_row.key_value:
            missing += 1
            differences.append(
                _ExactDifference(
                    segment_sequence=segment_sequence,
                    kind=DifferenceKind.MISSING,
                    key_row=reference_row,
                    reference_row=reference_row,
                    target_row=None,
                )
            )
            reference_index += 1
            classified_records += 1
            continue
        if reference_row.key_value > target_row.key_value:
            extra += 1
            differences.append(
                _ExactDifference(
                    segment_sequence=segment_sequence,
                    kind=DifferenceKind.EXTRA,
                    key_row=target_row,
                    reference_row=None,
                    target_row=target_row,
                )
            )
            target_index += 1
            classified_records += 1
            continue
        if reference_row.key_envelope != target_row.key_envelope:
            raise ComparisonProtocolError(
                "equal logical integer keys produced different canonical key envelopes"
            )
        if reference_row.row_envelope == target_row.row_envelope:
            matched += 1
        else:
            modified += 1
            differences.append(
                _ExactDifference(
                    segment_sequence=segment_sequence,
                    kind=DifferenceKind.MODIFIED,
                    key_row=reference_row,
                    reference_row=reference_row,
                    target_row=target_row,
                )
            )
        reference_index += 1
        target_index += 1
        classified_records += 1
    while reference_index < len(reference):
        if classified_records % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        reference_row = reference[reference_index]
        missing += 1
        differences.append(
            _ExactDifference(
                segment_sequence=segment_sequence,
                kind=DifferenceKind.MISSING,
                key_row=reference_row,
                reference_row=reference_row,
                target_row=None,
            )
        )
        reference_index += 1
        classified_records += 1
    while target_index < len(target):
        if classified_records % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        target_row = target[target_index]
        extra += 1
        differences.append(
            _ExactDifference(
                segment_sequence=segment_sequence,
                kind=DifferenceKind.EXTRA,
                key_row=target_row,
                reference_row=None,
                target_row=target_row,
            )
        )
        target_index += 1
        classified_records += 1
    _require_deadline(deadline_nanoseconds)
    return (
        _ExactCounts(
            matched=matched,
            missing=missing,
            extra=extra,
            modified=modified,
        ),
        tuple(differences),
    )


def _add_exact_counts(left: _ExactCounts, right: _ExactCounts) -> _ExactCounts:
    return _ExactCounts(
        matched=left.matched + right.matched,
        missing=left.missing + right.missing,
        extra=left.extra + right.extra,
        modified=left.modified + right.modified,
    )


def _retain_exact_differences(
    progress: _ComparisonProgress,
    differences: tuple[_ExactDifference, ...],
    check: RowCheckDefinition,
    evidence_policy: EvidenceDefinition,
    budgets: ExecutionBudgets,
    deadline_nanoseconds: int,
) -> _ComparisonProgress:
    anomalies = progress.anomalies
    found_records = progress.found_records
    found_bytes = progress.found_bytes
    retained_bytes = progress.retained_bytes
    retention_open = progress.retention_open
    for index, difference in enumerate(differences):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        record = _difference_record(
            found_records,
            difference,
            check,
            evidence_policy,
        )
        record_bytes = len(canonical_difference_record_bytes(record))
        found_records += 1
        found_bytes += record_bytes
        if not retention_open:
            continue
        if len(anomalies) >= budgets.max_evidence_rows:
            retention_open = False
            continue
        if retained_bytes + record_bytes > budgets.max_evidence_bytes:
            retention_open = False
            continue
        anomalies = (*anomalies, record)
        retained_bytes += record_bytes
    _require_deadline(deadline_nanoseconds)
    return replace(
        progress,
        anomalies=anomalies,
        found_records=found_records,
        found_bytes=found_bytes,
        retained_bytes=retained_bytes,
        retention_open=retention_open,
    )


def _difference_record(
    sequence: int,
    difference: _ExactDifference,
    check: RowCheckDefinition,
    evidence_policy: EvidenceDefinition,
) -> DifferenceRecord:
    fields = check.comparison_schema.schema.fields
    if len(difference.key_row.values) != len(fields):
        raise ComparisonProtocolError(
            "decoded exact-row field count differs from the comparison schema"
        )
    actions = _evidence_actions(fields, evidence_policy)
    key_names = frozenset(check.key)
    key_values = tuple(
        _evidence_field_value(field, difference.key_row.values[index], actions[index])
        for index, field in enumerate(fields)
        if field.name in key_names and actions[index] is not EvidenceAction.OMIT
    )
    all_key_fields_stored = all(
        actions[index] is EvidenceAction.STORE
        for index, field in enumerate(fields)
        if field.name in key_names
    )
    key_availability = (
        KeyAvailability.AVAILABLE if all_key_fields_stored else KeyAvailability.KEYSET_UNAVAILABLE
    )
    key_digest = (
        hashlib.sha256(canonical_difference_key_bytes(key_values)).hexdigest()
        if all_key_fields_stored
        else None
    )
    return DifferenceRecord(
        sequence=sequence,
        segment_sequence=difference.segment_sequence,
        kind=difference.kind,
        key_availability=key_availability,
        key_digest=key_digest,
        omitted_field_names=tuple(
            field.name
            for field, action in zip(fields, actions, strict=True)
            if action is EvidenceAction.OMIT
        ),
        key_values=key_values,
        reference_values=_side_evidence_values(
            difference.reference_row,
            fields,
            actions,
            key_names,
        ),
        target_values=_side_evidence_values(
            difference.target_row,
            fields,
            actions,
            key_names,
        ),
    )


def _evidence_actions(
    fields: tuple[FieldSchema, ...],
    evidence_policy: EvidenceDefinition,
) -> tuple[EvidenceAction, ...]:
    overrides = {item.field_name: item.action for item in evidence_policy.fields}
    field_names = {field.name for field in fields}
    unknown = tuple(name for name in overrides if name not in field_names)
    if unknown:
        raise ComparisonProtocolError(
            "evidence policy references fields outside the comparison schema"
        )
    return tuple(overrides.get(field.name, evidence_policy.unspecified_fields) for field in fields)


def _side_evidence_values(
    row: PostgresIntegerExactRow | None,
    fields: tuple[FieldSchema, ...],
    actions: tuple[EvidenceAction, ...],
    key_names: frozenset[str],
) -> tuple[EvidenceFieldValue, ...]:
    if row is None:
        return ()
    if len(row.values) != len(fields):
        raise ComparisonProtocolError(
            "decoded exact-row field count differs from the comparison schema"
        )
    return tuple(
        _evidence_field_value(field, row.values[index], actions[index])
        for index, field in enumerate(fields)
        if field.name not in key_names and actions[index] is not EvidenceAction.OMIT
    )


def _evidence_field_value(
    field: FieldSchema,
    value: DecodedValue | None,
    action: EvidenceAction,
) -> EvidenceFieldValue:
    decimal_precision, decimal_scale, timestamp_precision = _field_type_parameters(field)
    if action is EvidenceAction.REDACT:
        return EvidenceFieldValue(
            field_name=field.name,
            logical_type=field.logical_type,
            decimal_precision=decimal_precision,
            decimal_scale=decimal_scale,
            timestamp_precision=timestamp_precision,
            raw_available=False,
            availability=EvidenceValueAvailability.REDACTED,
            is_null=None,
            canonical_text=None,
            canonical_hex=None,
            unavailable_reason=EvidenceUnavailableReason.POLICY_REDACTED,
        )
    if action is not EvidenceAction.STORE:
        raise AssertionError("omitted fields must not be materialized as evidence values")
    return EvidenceFieldValue(
        field_name=field.name,
        logical_type=field.logical_type,
        decimal_precision=decimal_precision,
        decimal_scale=decimal_scale,
        timestamp_precision=timestamp_precision,
        raw_available=True,
        availability=EvidenceValueAvailability.STORED,
        is_null=value is None,
        canonical_text=(None if value is None else _canonical_decoded_text(value)),
        canonical_hex=None,
        unavailable_reason=None,
    )


def _field_type_parameters(field: FieldSchema) -> tuple[int | None, int | None, int | None]:
    if isinstance(field.parameters, DecimalParameters):
        return field.parameters.precision, field.parameters.scale, None
    if isinstance(field.parameters, TimestampParameters):
        return None, None, field.parameters.precision
    return None, None, None


def _canonical_decoded_text(value: DecodedValue) -> str:
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if isinstance(value, Decimal):
        return format(value, "f")
    if type(value) is date:
        return value.isoformat()
    if type(value) is str:
        return value
    raise ComparisonProtocolError(
        f"decoded evidence value has unsupported type {type(value).__name__}"
    )


def _split_segment(
    segment: _PendingSegment,
    next_sequence: int,
) -> tuple[_PendingSegment, _PendingSegment] | None:
    mathematical_upper = (
        INT64_MAX + 1 if segment.upper_exclusive is None else segment.upper_exclusive
    )
    width = mathematical_upper - segment.lower_inclusive
    if width <= 1:
        return None
    midpoint = segment.lower_inclusive + (width // 2)
    child_depth = segment.depth + 1
    return (
        _PendingSegment(
            segment_sequence=next_sequence,
            parent_segment_sequence=segment.segment_sequence,
            depth=child_depth,
            lower_inclusive=segment.lower_inclusive,
            upper_exclusive=midpoint,
        ),
        _PendingSegment(
            segment_sequence=next_sequence + 1,
            parent_segment_sequence=segment.segment_sequence,
            depth=child_depth,
            lower_inclusive=midpoint,
            upper_exclusive=segment.upper_exclusive,
        ),
    )


def _segment_record(
    node: _FingerprintNode,
    state: ComparisonSegmentState,
) -> ComparisonSegmentRecord:
    return ComparisonSegmentRecord(
        segment_sequence=node.segment.segment_sequence,
        parent_segment_sequence=node.segment.parent_segment_sequence,
        depth=node.segment.depth,
        lower_inclusive=node.segment.lower_inclusive,
        upper_exclusive=node.segment.upper_exclusive,
        state=state,
        reference_fingerprint=node.reference.fingerprint,
        target_fingerprint=node.target.fingerprint,
    )


def _range_request(segment: _PendingSegment) -> PostgresIntegerRangeRequest:
    return PostgresIntegerRangeRequest(
        segment_id=_segment_id(segment.segment_sequence),
        lower_inclusive=segment.lower_inclusive,
        upper_exclusive=segment.upper_exclusive,
    )


def _segment_id(segment_sequence: int) -> str:
    _require_nonnegative_integer(segment_sequence, "segment sequence")
    return f"s{segment_sequence}"


def _fingerprint_record_bytes(segment_id: str) -> int:
    return len(segment_id.encode("ascii")) + (3 * 19) + (8 * 38) + (2 * 38)


def _slot_object_bytes(value_type: type[object]) -> int:
    return getsizeof(object.__new__(value_type))


def _tuple_storage_bytes(item_count: int) -> int:
    _require_nonnegative_integer(item_count, "tuple item count")
    return _EMPTY_TUPLE_BYTES + (item_count * _POINTER_BYTES)


def _list_storage_bytes(item_count: int) -> int:
    _require_nonnegative_integer(item_count, "list item count")
    if item_count == 0:
        return _EMPTY_LIST_BYTES
    reserved_items = item_count + (item_count // 8) + 6
    return _EMPTY_LIST_BYTES + (reserved_items * _POINTER_BYTES)


def _dict_storage_bytes(item_count: int) -> int:
    _require_nonnegative_integer(item_count, "dictionary item count")
    return _EMPTY_DICT_BYTES + (item_count * _DICT_ENTRY_RESERVATION_BYTES)


def _maximum_integer_object_bytes(budgets: ExecutionBudgets) -> int:
    return max(
        getsizeof(INT64_MIN),
        getsizeof(INT64_MAX),
        getsizeof((10**38) - 1),
        getsizeof(budgets.max_application_result_bytes),
        getsizeof(budgets.max_coordinator_memory_bytes),
        getsizeof(budgets.max_fingerprint_nodes),
    )


def _fingerprint_value_memory_bytes() -> int:
    maximum_limb = INT64_MAX * ((1 << 32) - 1)
    return (
        _slot_object_bytes(Fingerprint)
        + _tuple_storage_bytes(8)
        + getsizeof(INT64_MAX)
        + (8 * getsizeof(maximum_limb))
    )


def _read_metrics_memory_bytes(budgets: ExecutionBudgets) -> int:
    return _slot_object_bytes(PostgresReadMetrics) + (2 * _maximum_integer_object_bytes(budgets))


def _summary_parsed_side_memory_bytes(budgets: ExecutionBudgets) -> int:
    return (
        _slot_object_bytes(PostgresIntegerKeySummaryRead)
        + _slot_object_bytes(PostgresIntegerKeySummary)
        + _read_metrics_memory_bytes(budgets)
        + (7 * _maximum_integer_object_bytes(budgets))
        + getsizeof(True)
    )


def _raw_rows_memory_bytes(
    record_count: int,
    field_count: int,
    ascii_value_count: int,
    result_bytes: int,
) -> int:
    _require_nonnegative_integer(record_count, "raw record count")
    _require_nonnegative_integer(field_count, "raw row field count")
    _require_nonnegative_integer(ascii_value_count, "raw ASCII value count")
    _require_nonnegative_integer(result_bytes, "raw result bytes")
    return (
        _list_storage_bytes(record_count)
        + _tuple_storage_bytes(record_count)
        + (record_count * _tuple_storage_bytes(field_count))
        + (ascii_value_count * _ASCII_TEXT_HEADER_BYTES)
        + result_bytes
    )


def _summary_phase_memory_bytes(budgets: ExecutionBudgets) -> int:
    parsed_side = _summary_parsed_side_memory_bytes(budgets)
    target_raw = _raw_rows_memory_bytes(
        record_count=1,
        field_count=9,
        ascii_value_count=7,
        result_bytes=_SUMMARY_RECORD_BYTES,
    )
    return (2 * parsed_side) + target_raw


def _summary_pair_memory_bytes(budgets: ExecutionBudgets) -> int:
    return 2 * _summary_parsed_side_memory_bytes(budgets)


def _topology_memory_bytes(node_count: int, budgets: ExecutionBudgets) -> int:
    _require_nonnegative_integer(node_count, "topology node count")
    integer_bytes = _maximum_integer_object_bytes(budgets)
    record_bytes = (
        _slot_object_bytes(ComparisonSegmentRecord)
        + (5 * integer_bytes)
        + (2 * _fingerprint_value_memory_bytes())
    )
    return (
        node_count * record_bytes
        + (2 * _list_storage_bytes(node_count))
        + _tuple_storage_bytes(node_count)
        + getsizeof(ComparisonSegmentState.EXACT_MISMATCH)
    )


def _frontier_structure_memory_bytes(
    segments: tuple[_PendingSegment, ...],
    budgets: ExecutionBudgets,
) -> int:
    item_count = len(segments)
    integer_bytes = _maximum_integer_object_bytes(budgets)
    segment_identifier_bytes = sum(
        len(_segment_id(item.segment_sequence).encode("ascii")) for item in segments
    )
    item_bytes = (
        _slot_object_bytes(_PendingSegment)
        + _slot_object_bytes(PostgresIntegerRangeRequest)
        + _slot_object_bytes(_FingerprintNode)
        + (5 * integer_bytes)
        + _ASCII_TEXT_HEADER_BYTES
    )
    return (
        item_count * item_bytes
        + segment_identifier_bytes
        + (6 * _tuple_storage_bytes(item_count))
        + (2 * _list_storage_bytes(item_count))
    )


def _fingerprint_parsed_side_memory_bytes(
    requests: tuple[PostgresIntegerRangeRequest, ...],
    budgets: ExecutionBudgets,
) -> int:
    item_count = len(requests)
    segment_identifier_bytes = sum(len(item.segment_id.encode("ascii")) for item in requests)
    parsed_item_bytes = (
        _slot_object_bytes(PostgresRangeFingerprint)
        + _fingerprint_value_memory_bytes()
        + (2 * _maximum_integer_object_bytes(budgets))
        + _ASCII_TEXT_HEADER_BYTES
    )
    return (
        _slot_object_bytes(PostgresRangeFingerprintRead)
        + _read_metrics_memory_bytes(budgets)
        + _list_storage_bytes(item_count)
        + _tuple_storage_bytes(item_count)
        + (item_count * parsed_item_bytes)
        + segment_identifier_bytes
    )


def _fingerprint_phase_memory_bytes(
    usage: _Usage,
    pending: tuple[_PendingSegment, ...],
    requests: tuple[PostgresIntegerRangeRequest, ...],
    budgets: ExecutionBudgets,
    side_result_bytes: int,
) -> int:
    parsed_side = _fingerprint_parsed_side_memory_bytes(requests, budgets)
    target_raw = _raw_rows_memory_bytes(
        record_count=len(requests),
        field_count=15,
        ascii_value_count=14 * len(requests),
        result_bytes=side_result_bytes,
    )
    retained = (
        _summary_pair_memory_bytes(budgets)
        + _topology_memory_bytes(usage.fingerprint_nodes, budgets)
        + _frontier_structure_memory_bytes(pending, budgets)
    )
    query_peak = retained + (2 * parsed_side) + target_raw
    projected_topology_peak = (
        _summary_pair_memory_bytes(budgets)
        + _topology_memory_bytes(usage.fingerprint_nodes + len(pending), budgets)
        + _frontier_structure_memory_bytes(pending, budgets)
    )
    return max(query_peak, projected_topology_peak)


def _reference_exact_frontier_bytes(nodes: tuple[_FingerprintNode, ...]) -> int:
    return sum(
        node.reference.row_envelope_bytes
        + node.reference.key_envelope_bytes
        + node.reference.fingerprint.count
        * (len(node.reference.segment_id.encode("ascii")) + _EXACT_STATUS_BYTES)
        for node in nodes
    )


def _target_exact_frontier_bytes(nodes: tuple[_FingerprintNode, ...]) -> int:
    return sum(
        node.target.row_envelope_bytes
        + node.target.key_envelope_bytes
        + node.target.fingerprint.count
        * (len(node.target.segment_id.encode("ascii")) + _EXACT_STATUS_BYTES)
        for node in nodes
    )


def _reference_exact_side_reservation(
    nodes: tuple[_FingerprintNode, ...],
) -> _ExactSideReservation:
    records = sum(node.reference.fingerprint.count for node in nodes)
    envelope_bytes = sum(
        node.reference.row_envelope_bytes + node.reference.key_envelope_bytes for node in nodes
    )
    segment_identifier_bytes = sum(
        node.reference.fingerprint.count * len(node.reference.segment_id.encode("ascii"))
        for node in nodes
    )
    return _ExactSideReservation(
        records=records,
        result_bytes=_reference_exact_frontier_bytes(nodes),
        envelope_bytes=envelope_bytes,
        segment_identifier_bytes=segment_identifier_bytes,
        full_scans=max(1, len(nodes)),
    )


def _target_exact_side_reservation(
    nodes: tuple[_FingerprintNode, ...],
) -> _ExactSideReservation:
    records = sum(node.target.fingerprint.count for node in nodes)
    envelope_bytes = sum(
        node.target.row_envelope_bytes + node.target.key_envelope_bytes for node in nodes
    )
    segment_identifier_bytes = sum(
        node.target.fingerprint.count * len(node.target.segment_id.encode("ascii"))
        for node in nodes
    )
    return _ExactSideReservation(
        records=records,
        result_bytes=_target_exact_frontier_bytes(nodes),
        envelope_bytes=envelope_bytes,
        segment_identifier_bytes=segment_identifier_bytes,
        full_scans=max(1, len(nodes)),
    )


def _exact_parsed_side_memory_bytes(
    reservation: _ExactSideReservation,
    budgets: ExecutionBudgets,
    schema_field_count: int,
) -> int:
    record_bytes = (
        _slot_object_bytes(PostgresIntegerExactRow)
        + _maximum_integer_object_bytes(budgets)
        + (2 * _BYTES_HEADER_BYTES)
        + _ASCII_TEXT_HEADER_BYTES
        + _tuple_storage_bytes(schema_field_count)
        + (schema_field_count * _DECODE_FIELD_RESERVATION_BYTES)
    )
    return (
        _slot_object_bytes(PostgresIntegerExactRowsRead)
        + _read_metrics_memory_bytes(budgets)
        + _list_storage_bytes(reservation.records)
        + _tuple_storage_bytes(reservation.records)
        + (reservation.records * record_bytes)
        + reservation.envelope_bytes
        + reservation.segment_identifier_bytes
    )


def _exact_raw_side_memory_bytes(reservation: _ExactSideReservation) -> int:
    return _raw_rows_memory_bytes(
        record_count=reservation.records,
        field_count=6,
        ascii_value_count=3 * reservation.records,
        result_bytes=reservation.result_bytes,
    )


def _exact_decode_scratch_bytes(
    reservation: _ExactSideReservation,
    max_encoded_row_bytes: int,
    schema_field_count: int,
) -> int:
    if reservation.records == 0:
        return 0
    maximum_single_envelope_bytes = min(
        reservation.envelope_bytes,
        max_encoded_row_bytes + _MAX_INT64_KEY_ENVELOPE_BYTES,
    )
    return _DECODE_ENVELOPE_EXPANSION * maximum_single_envelope_bytes + (
        schema_field_count * _DECODE_FIELD_RESERVATION_BYTES
    )


def _exact_grouping_memory_bytes(
    reservation: _ExactSideReservation,
    segment_count: int,
) -> int:
    return (
        (2 * _dict_storage_bytes(segment_count))
        + (segment_count * (_EMPTY_LIST_BYTES + _EMPTY_TUPLE_BYTES))
        + (3 * reservation.records * _POINTER_BYTES)
    )


def _exact_frontier_reservation(
    nodes: tuple[_FingerprintNode, ...],
    usage: _Usage,
    budgets: ExecutionBudgets,
    max_encoded_row_bytes: int,
    schema_field_count: int,
) -> _ExactFrontierReservation:
    reference = _reference_exact_side_reservation(nodes)
    target = _target_exact_side_reservation(nodes)
    reference_parsed = _exact_parsed_side_memory_bytes(
        reference,
        budgets,
        schema_field_count,
    )
    target_parsed = _exact_parsed_side_memory_bytes(
        target,
        budgets,
        schema_field_count,
    )
    retained = (
        _summary_pair_memory_bytes(budgets)
        + _topology_memory_bytes(usage.fingerprint_nodes, budgets)
        + _frontier_structure_memory_bytes(
            tuple(node.segment for node in nodes),
            budgets,
        )
    )
    reference_query_peak = (
        retained
        + _exact_raw_side_memory_bytes(reference)
        + reference_parsed
        + _exact_decode_scratch_bytes(
            reference,
            max_encoded_row_bytes,
            schema_field_count,
        )
    )
    target_query_peak = (
        retained
        + reference_parsed
        + _exact_raw_side_memory_bytes(target)
        + target_parsed
        + _exact_decode_scratch_bytes(
            target,
            max_encoded_row_bytes,
            schema_field_count,
        )
    )
    grouping_peak = (
        retained
        + reference_parsed
        + target_parsed
        + _exact_grouping_memory_bytes(reference, len(nodes))
        + _exact_grouping_memory_bytes(target, len(nodes))
    )
    return _ExactFrontierReservation(
        reference=reference,
        target=target,
        coordinator_peak_bytes=max(
            reference_query_peak,
            target_query_peak,
            grouping_peak,
        ),
    )


def _comparison_totals(
    counts: _ExactCounts,
    guarantee: Guarantee,
) -> ComparisonTotals:
    if guarantee is Guarantee.FINGERPRINT:
        return ComparisonTotals(
            matched=InferredTotal(
                precision="inferred_under_fingerprint",
                value=str(counts.matched),
            ),
            missing=InferredTotal(
                precision="inferred_under_fingerprint",
                value=str(counts.missing),
            ),
            extra=InferredTotal(
                precision="inferred_under_fingerprint",
                value=str(counts.extra),
            ),
            modified=InferredTotal(
                precision="inferred_under_fingerprint",
                value=str(counts.modified),
            ),
        )
    if guarantee is Guarantee.EXACT:
        return ComparisonTotals(
            matched=ExactTotal(precision="exact", value=str(counts.matched)),
            missing=ExactTotal(precision="exact", value=str(counts.missing)),
            extra=ExactTotal(precision="exact", value=str(counts.extra)),
            modified=ExactTotal(precision="exact", value=str(counts.modified)),
        )
    raise AssertionError("completed integer comparison has an unsupported guarantee")


def _comparison_reasons(counts: _ExactCounts) -> tuple[ResultReason, ...]:
    if counts.missing + counts.extra + counts.modified == 0:
        return ()
    return (
        ResultReason(
            code=ReasonCode.DATA_MISMATCH,
            operation="compare_integer_key_rows",
            message="exact terminal leaves established row differences",
            safe_parameters=(
                SafeParameter(name="missing_count", value=str(counts.missing)),
                SafeParameter(name="extra_count", value=str(counts.extra)),
                SafeParameter(name="modified_count", value=str(counts.modified)),
            ),
            native_error_code=None,
            query_id=None,
            redacted_response=None,
        ),
    )


def _require_budget_capacity(
    source_budget: PostgresSourceBudgetAttempt,
    budgets: ExecutionBudgets,
    additional_queries: int,
    additional_records: int,
    additional_result_bytes: int,
    coordinator_bytes: int,
) -> None:
    remaining = source_budget.remaining()
    if additional_queries > remaining.queries:
        raise ComparisonBudgetExceededError("next comparison read exceeds max_queries")
    if additional_records > remaining.fetched_records:
        raise ComparisonBudgetExceededError("next comparison read exceeds max_fetched_records")
    if additional_result_bytes > remaining.result_bytes:
        raise ComparisonBudgetExceededError(
            "next comparison read exceeds max_application_result_bytes"
        )
    if coordinator_bytes > budgets.max_coordinator_memory_bytes:
        raise ComparisonBudgetExceededError(
            "next comparison read exceeds max_coordinator_memory_bytes"
        )


def _require_full_scan_capacity(
    source_budget: PostgresSourceBudgetAttempt,
    reference_full_scans: int,
    target_full_scans: int,
) -> None:
    remaining = source_budget.remaining()
    if reference_full_scans > remaining.reference_full_scans:
        raise ComparisonBudgetExceededError("next reference read exceeds max_full_scans_per_side")
    if target_full_scans > remaining.target_full_scans:
        raise ComparisonBudgetExceededError("next target read exceeds max_full_scans_per_side")


def _consume_source_usage(
    usage: _Usage,
    source_budget: PostgresSourceBudgetAttempt,
    fingerprint_nodes: int,
    coordinator_peak_bytes: int,
) -> _Usage:
    snapshot = source_budget.snapshot()
    return _Usage(
        queries=snapshot.queries,
        fetched_records=snapshot.fetched_records,
        result_bytes=snapshot.result_bytes,
        fingerprint_nodes=usage.fingerprint_nodes + fingerprint_nodes,
        coordinator_peak_bytes=max(usage.coordinator_peak_bytes, coordinator_peak_bytes),
        reference_full_scans=snapshot.reference_full_scans,
        target_full_scans=snapshot.target_full_scans,
        elapsed_milliseconds=snapshot.elapsed_milliseconds,
    )


def _usage_with_coordinator_peak(usage: _Usage, coordinator_peak_bytes: int) -> _Usage:
    return _Usage(
        queries=usage.queries,
        fetched_records=usage.fetched_records,
        result_bytes=usage.result_bytes,
        fingerprint_nodes=usage.fingerprint_nodes,
        coordinator_peak_bytes=max(usage.coordinator_peak_bytes, coordinator_peak_bytes),
        reference_full_scans=usage.reference_full_scans,
        target_full_scans=usage.target_full_scans,
        elapsed_milliseconds=usage.elapsed_milliseconds,
    )


def _require_deadline(deadline_nanoseconds: int) -> None:
    if time.monotonic_ns() >= deadline_nanoseconds:
        raise ComparisonBudgetExceededError("integer comparison exceeded run_timeout_milliseconds")


def _result_metrics(usage: _Usage) -> ResultMetrics:
    return _result_metrics_with_elapsed(usage, usage.elapsed_milliseconds)


def _result_metrics_with_elapsed(usage: _Usage, elapsed_milliseconds: int) -> ResultMetrics:
    return ResultMetrics(
        queries=usage.queries,
        fetched_records=usage.fetched_records,
        result_bytes=usage.result_bytes,
        fingerprint_nodes=usage.fingerprint_nodes,
        coordinator_peak_bytes=usage.coordinator_peak_bytes,
        elapsed_milliseconds=elapsed_milliseconds,
    )


def _validate_evidence_coverage(
    coverage: EvidenceCoverage,
    anomalies: tuple[DifferenceRecord, ...],
) -> None:
    if tuple(item.sequence for item in anomalies) != tuple(range(len(anomalies))):
        raise ValueError("retained anomaly sequences must be contiguous from zero")
    retained_bytes = sum(len(canonical_difference_record_bytes(item)) for item in anomalies)
    if coverage.retained_records != len(anomalies):
        raise ValueError("retained evidence count differs from anomaly records")
    if coverage.retained_bytes != retained_bytes:
        raise ValueError("retained evidence bytes differ from anomaly payloads")


def _validate_partial_frontier_coverage(artifact: PartialComparisonArtifact) -> None:
    coverage = artifact.comparison_coverage
    topology = artifact.frontier.topology
    unresolved = artifact.frontier.unresolved
    pruned = sum(item.state is ComparisonSegmentState.FINGERPRINT_MATCH for item in topology)
    exact = sum(
        item.state in (ComparisonSegmentState.EXACT_MATCH, ComparisonSegmentState.EXACT_MISMATCH)
        for item in topology
    )
    structural_empty_frontier = (
        not topology
        and not unresolved
        and coverage.resolved_segments == 1
        and coverage.pruned_segments == 0
        and coverage.exact_segments == 1
        and all(isinstance(total, UnavailableTotal) for total in artifact.totals.values())
    )
    if not structural_empty_frontier and (
        coverage.pruned_segments != pruned
        or coverage.exact_segments != exact
        or coverage.resolved_segments != pruned + exact
    ):
        raise ValueError("partial comparison coverage differs from its terminal topology")
    if coverage.unresolved_segments != len(unresolved):
        raise ValueError("partial unresolved coverage differs from its frontier")
    expected_reasons = tuple(dict.fromkeys(item.reason for item in unresolved))
    if coverage.unresolved_reasons != expected_reasons:
        raise ValueError("partial unresolved reasons differ from its frontier")
    expected_covered = 1 if not unresolved and coverage.resolved_segments > 0 else 0
    if coverage.total_partitions != 1 or coverage.covered_partitions != expected_covered:
        raise ValueError("partial comparison partition coverage differs from its frontier")
    has_fingerprint_mismatch = any(
        item.reference_fingerprint != item.target_fingerprint for item in topology
    ) or any(item.reference_fingerprint is not None for item in unresolved)
    if has_fingerprint_mismatch and artifact.verdict is not Verdict.MISMATCH:
        raise ValueError("partial fingerprint mismatch witness requires mismatch verdict")
    by_sequence = {item.segment_sequence: item for item in topology}
    for anomaly in artifact.anomalies:
        segment = by_sequence.get(anomaly.segment_sequence)
        if segment is None or segment.state is not ComparisonSegmentState.EXACT_MISMATCH:
            raise ValueError("partial anomaly requires an exact-mismatch topology segment")


def _validate_partial_totals(artifact: PartialComparisonArtifact) -> None:
    totals = artifact.totals.values()
    lower_bounds = tuple(isinstance(total, LowerBoundTotal) for total in totals)
    if any(isinstance(total, (ExactTotal, InferredTotal)) for total in totals):
        raise ValueError("partial comparison totals cannot claim exact or inferred precision")
    if any(lower_bounds) and artifact.comparison_coverage.exact_segments == 0:
        raise ValueError("partial lower bounds require a completed exact segment")
    if (
        any(
            isinstance(total, LowerBoundTotal) and total.value != "0"
            for total in artifact.totals.differences()
        )
        and artifact.verdict is not Verdict.MISMATCH
    ):
        raise ValueError("positive partial difference lower bound requires mismatch verdict")


def _require_instance[ValueT](
    value: object,
    expected_type: type[ValueT],
    context: str,
) -> ValueT:
    if not isinstance(value, expected_type):
        raise TypeError(f"{context} must be a {expected_type.__name__}")
    return value


def _require_nonnegative_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{context} must be a non-negative integer")


def _require_int64(value: object, context: str) -> None:
    if type(value) is not int or not INT64_MIN <= value <= INT64_MAX:
        raise ValueError(f"{context} must be a signed int64 integer")


def _require_sha256(value: object, context: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{context} must be lowercase SHA-256 hex")
