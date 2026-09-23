import time
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from sys import getsizeof
from typing import final

from forensic_data.acquisition import InputCutDefinition, classify_input_cut_alignment
from forensic_data.canonical import Fingerprint, LogicalType
from forensic_data.contracts.model import (
    AssurancePolicy,
    DatasetDefinition,
    ExecutionBudgets,
    RelationLocator,
    RelationManifestReadiness,
    RelationScope,
    RowCheckDefinition,
    ScopeOperator,
    StableReadKind,
)
from forensic_data.planning import ResolvedScope
from forensic_data.postgres import (
    PostgresIntegerExactRow,
    PostgresIntegerExactRowsRead,
    PostgresIntegerKeySummary,
    PostgresIntegerKeySummaryRead,
    PostgresProtectedReadContext,
    PostgresProtectedRelationInspection,
    PostgresRangeFingerprint,
    PostgresRangeFingerprintRead,
    PostgresReadDeadline,
    PostgresReadMetrics,
    ReadContextState,
)
from forensic_data.postgres_sql import PostgresIntegerRangeRequest, PostgresScopePredicate
from forensic_data.result import (
    ComparisonCoverage,
    ComparisonTotals,
    ConsistencyLevel,
    ConsistencyStatus,
    EvidenceCoverage,
    ExactTotal,
    Guarantee,
    InferredTotal,
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
class _Usage:
    queries: int
    fetched_records: int
    result_bytes: int
    fingerprint_nodes: int
    coordinator_peak_bytes: int
    reference_full_scans: int
    target_full_scans: int


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


def execute_postgres_integer_key_comparison(
    reference_context: PostgresProtectedReadContext,
    reference_relation: PostgresProtectedRelationInspection,
    target_context: PostgresProtectedReadContext,
    target_relation: PostgresProtectedRelationInspection,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    input_cut: InputCutDefinition,
    budgets: ExecutionBudgets,
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
    started_nanoseconds = time.monotonic_ns()
    read_deadline = PostgresReadDeadline(
        statement_timeout_milliseconds=budgets.statement_timeout_milliseconds,
        deadline_nanoseconds=(started_nanoseconds + (budgets.run_timeout_milliseconds * 1_000_000)),
    )
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
    usage = _Usage(
        queries=0,
        fetched_records=0,
        result_bytes=0,
        fingerprint_nodes=0,
        coordinator_peak_bytes=0,
        reference_full_scans=0,
        target_full_scans=0,
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    summary_coordinator_peak = _summary_phase_memory_bytes(budgets)
    _require_full_scan_capacity(
        usage,
        budgets,
        reference_full_scans=1,
        target_full_scans=1,
    )
    _require_budget_capacity(
        usage,
        budgets,
        additional_queries=2,
        additional_records=2,
        additional_result_bytes=2 * _SUMMARY_RECORD_BYTES,
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
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    usage = _consume_read_pair(
        usage,
        reference_summary_read.metrics,
        target_summary_read.metrics,
        fingerprint_nodes=0,
        reference_full_scans=1,
        target_full_scans=1,
        coordinator_peak_bytes=summary_coordinator_peak,
    )
    reference_summary = reference_summary_read.summary
    target_summary = target_summary_read.summary
    contract_violation_reason = _structural_contract_violation_reason(
        reference_summary,
        target_summary,
    )
    if reference_summary.invalid_key_count > 0 or target_summary.invalid_key_count > 0:
        raise ComparisonKeyMappingError(
            reference_summary,
            target_summary,
            _result_metrics(usage, started_nanoseconds),
            usage.reference_full_scans,
            usage.target_full_scans,
            contract_violation_reason,
        )
    if contract_violation_reason is not None:
        return _completed_structural_artifact(
            check,
            scope,
            input_cut,
            reference_context,
            target_context,
            reference_summary,
            target_summary,
            usage,
            started_nanoseconds,
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

    root = _root_segment(reference_summary, target_summary)
    pending: tuple[_PendingSegment, ...] = (root,)
    topology: list[ComparisonSegmentRecord] = []
    pruned_matched = 0
    exact_counts = _ExactCounts(matched=0, missing=0, extra=0, modified=0)
    pruned_segments = 0
    exact_segments = 0

    while pending:
        level_nodes, usage = _read_fingerprint_level(
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
        matching = tuple(
            node
            for index, node in enumerate(level_nodes)
            if _fingerprint_node_matches_before_deadline(
                node,
                index,
                read_deadline.deadline_nanoseconds,
            )
        )
        mismatching = tuple(
            node
            for index, node in enumerate(level_nodes)
            if not _fingerprint_node_matches_before_deadline(
                node,
                index,
                read_deadline.deadline_nanoseconds,
            )
        )
        _require_deadline(read_deadline.deadline_nanoseconds)
        for index, node in enumerate(matching):
            if index % _DEADLINE_CHECK_RECORDS == 0:
                _require_deadline(read_deadline.deadline_nanoseconds)
            topology.append(_segment_record(node, ComparisonSegmentState.FINGERPRINT_MATCH))
            pruned_matched += node.reference.fingerprint.count
            pruned_segments += 1
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
        if _exact_frontier_fits(exact_reservation, usage, budgets):
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
            )
            level_exact_counts, exact_records = _classify_exact_frontier(
                mismatching,
                reference_exact,
                target_exact,
                read_deadline.deadline_nanoseconds,
            )
            exact_counts = _add_exact_counts(exact_counts, level_exact_counts)
            topology.extend(exact_records)
            exact_segments += len(exact_records)
            pending = ()
            continue

        children: list[_PendingSegment] = []
        next_sequence = usage.fingerprint_nodes
        for index, node in enumerate(mismatching):
            if index % _DEADLINE_CHECK_RECORDS == 0:
                _require_deadline(read_deadline.deadline_nanoseconds)
            split = _split_segment(node.segment, next_sequence)
            if split is None:
                raise ComparisonBudgetExceededError(
                    "mismatched single-key range does not fit the remaining exact-fetch budgets"
                )
            topology.append(_segment_record(node, ComparisonSegmentState.SPLIT))
            children.extend(split)
            next_sequence += 2
        if any(child.depth > budgets.max_depth for child in children):
            raise ComparisonBudgetExceededError(
                "integer-range subdivision would exceed execution max_depth"
            )
        if usage.fingerprint_nodes + len(children) > budgets.max_fingerprint_nodes:
            raise ComparisonBudgetExceededError(
                "integer-range subdivision would exceed execution max_fingerprint_nodes"
            )
        pending = tuple(children)

    ordered_topology = tuple(sorted(topology, key=lambda item: item.segment_sequence))
    if tuple(item.segment_sequence for item in ordered_topology) != tuple(
        range(len(ordered_topology))
    ):
        raise ComparisonProtocolError("comparison segment topology is not contiguous")
    totals_values = _ExactCounts(
        matched=pruned_matched + exact_counts.matched,
        missing=exact_counts.missing,
        extra=exact_counts.extra,
        modified=exact_counts.modified,
    )
    difference_count = totals_values.missing + totals_values.extra + totals_values.modified
    verdict = Verdict.MATCH if difference_count == 0 else Verdict.MISMATCH
    guarantee = Guarantee.FINGERPRINT if pruned_segments > 0 else Guarantee.EXACT
    totals = _comparison_totals(totals_values, guarantee)
    reasons = _comparison_reasons(totals_values)
    elapsed_milliseconds = _elapsed_milliseconds(started_nanoseconds)
    _require_deadline(read_deadline.deadline_nanoseconds)
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
            resolved_segments=pruned_segments + exact_segments,
            pruned_segments=pruned_segments,
            exact_segments=exact_segments,
            unresolved_segments=0,
            unresolved_reasons=(),
        ),
        totals=totals,
        evidence_coverage=EvidenceCoverage(
            found_records=difference_count,
            retained_records=0,
            found_bytes=0,
            retained_bytes=0,
        ),
        metrics=_result_metrics_with_elapsed(usage, elapsed_milliseconds),
        reasons=reasons,
        segments=ordered_topology,
        reference_key_summary=reference_summary,
        target_key_summary=target_summary,
        reference_full_scans=usage.reference_full_scans,
        target_full_scans=usage.target_full_scans,
    )


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
    started_nanoseconds: int,
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
        metrics=_result_metrics(usage, started_nanoseconds),
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
        artifact.metrics.queries != 2
        or artifact.metrics.fetched_records != 2
        or artifact.metrics.fingerprint_nodes != 0
    ):
        raise ValueError(
            "completed structural comparison requires exactly two summary-read receipts"
        )
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
) -> tuple[tuple[_FingerprintNode, ...], _Usage]:
    if usage.fingerprint_nodes + len(pending) > budgets.max_fingerprint_nodes:
        raise ComparisonBudgetExceededError(
            "next fingerprint level exceeds execution max_fingerprint_nodes"
        )
    requests = tuple(_range_request(item) for item in pending)
    side_result_bytes = sum(_fingerprint_record_bytes(item.segment_id) for item in requests)
    record_bytes = max(_fingerprint_record_bytes(item.segment_id) for item in requests)
    coordinator_peak = _fingerprint_phase_memory_bytes(
        usage,
        pending,
        requests,
        budgets,
        side_result_bytes,
    )
    _require_full_scan_capacity(
        usage,
        budgets,
        reference_full_scans=len(requests),
        target_full_scans=len(requests),
    )
    _require_budget_capacity(
        usage,
        budgets,
        additional_queries=2,
        additional_records=2 * len(requests),
        additional_result_bytes=2 * side_result_bytes,
        coordinator_bytes=coordinator_peak,
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    reference_read = reference_context.read_integer_range_fingerprints(
        reference_relation,
        key_field_index,
        reference_scope,
        requests,
        max_encoded_row_bytes,
        record_bytes,
        side_result_bytes,
        read_deadline,
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    target_read = target_context.read_integer_range_fingerprints(
        target_relation,
        key_field_index,
        target_scope,
        requests,
        max_encoded_row_bytes,
        record_bytes,
        side_result_bytes,
        read_deadline,
    )
    _require_deadline(read_deadline.deadline_nanoseconds)
    next_usage = _consume_read_pair(
        usage,
        reference_read.metrics,
        target_read.metrics,
        fingerprint_nodes=len(requests),
        reference_full_scans=len(requests),
        target_full_scans=len(requests),
        coordinator_peak_bytes=coordinator_peak,
    )
    nodes = _fingerprint_nodes(
        pending,
        reference_read,
        target_read,
        read_deadline.deadline_nanoseconds,
    )
    return nodes, next_usage


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


def _fingerprint_node_matches_before_deadline(
    node: _FingerprintNode,
    index: int,
    deadline_nanoseconds: int,
) -> bool:
    if index % _DEADLINE_CHECK_RECORDS == 0:
        _require_deadline(deadline_nanoseconds)
    return node.reference.fingerprint == node.target.fingerprint


def _exact_frontier_fits(
    reservation: _ExactFrontierReservation,
    usage: _Usage,
    budgets: ExecutionBudgets,
) -> bool:
    reserved_result_bytes = max(1, reservation.reference.result_bytes) + max(
        1,
        reservation.target.result_bytes,
    )
    return (
        usage.queries + 2 <= budgets.max_queries
        and usage.fetched_records + reservation.reference.records + reservation.target.records
        <= budgets.max_fetched_records
        and usage.result_bytes + reserved_result_bytes <= budgets.max_application_result_bytes
        and reservation.coordinator_peak_bytes <= budgets.max_coordinator_memory_bytes
        and usage.reference_full_scans + reservation.reference.full_scans
        <= budgets.max_full_scans_per_side
        and usage.target_full_scans + reservation.target.full_scans
        <= budgets.max_full_scans_per_side
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
) -> tuple[PostgresIntegerExactRowsRead, PostgresIntegerExactRowsRead, _Usage]:
    requests = tuple(_range_request(node.segment) for node in nodes)
    reference_limit = max(1, reservation.reference.result_bytes)
    target_limit = max(1, reservation.target.result_bytes)
    _require_full_scan_capacity(
        usage,
        budgets,
        reference_full_scans=reservation.reference.full_scans,
        target_full_scans=reservation.target.full_scans,
    )
    _require_budget_capacity(
        usage,
        budgets,
        additional_queries=2,
        additional_records=reservation.reference.records + reservation.target.records,
        additional_result_bytes=reference_limit + target_limit,
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
    next_usage = _consume_read_pair(
        usage,
        reference_read.metrics,
        target_read.metrics,
        fingerprint_nodes=0,
        reference_full_scans=reservation.reference.full_scans,
        target_full_scans=reservation.target.full_scans,
        coordinator_peak_bytes=reservation.coordinator_peak_bytes,
    )
    return reference_read, target_read, next_usage


def _classify_exact_frontier(
    nodes: tuple[_FingerprintNode, ...],
    reference: PostgresIntegerExactRowsRead,
    target: PostgresIntegerExactRowsRead,
    deadline_nanoseconds: int,
) -> tuple[_ExactCounts, tuple[ComparisonSegmentRecord, ...]]:
    _require_deadline(deadline_nanoseconds)
    segment_ids = tuple(_segment_id(node.segment.segment_sequence) for node in nodes)
    reference_rows = _group_exact_rows(reference.rows, segment_ids, deadline_nanoseconds)
    target_rows = _group_exact_rows(target.rows, segment_ids, deadline_nanoseconds)
    totals = _ExactCounts(matched=0, missing=0, extra=0, modified=0)
    records: list[ComparisonSegmentRecord] = []
    for index, node in enumerate(nodes):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        segment_id = _segment_id(node.segment.segment_sequence)
        reference_segment_rows = reference_rows[segment_id]
        target_segment_rows = target_rows[segment_id]
        if len(reference_segment_rows) != node.reference.fingerprint.count:
            raise ComparisonProtocolError(
                "reference exact segment count differs from its fingerprint"
            )
        if len(target_segment_rows) != node.target.fingerprint.count:
            raise ComparisonProtocolError("target exact segment count differs from its fingerprint")
        counts = _compare_exact_rows(
            reference_segment_rows,
            target_segment_rows,
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
        totals = _add_exact_counts(totals, counts)
        state = (
            ComparisonSegmentState.EXACT_MATCH
            if counts.missing + counts.extra + counts.modified == 0
            else ComparisonSegmentState.EXACT_MISMATCH
        )
        records.append(_segment_record(node, state))
    _require_deadline(deadline_nanoseconds)
    return totals, tuple(records)


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
    deadline_nanoseconds: int,
) -> _ExactCounts:
    reference_index = 0
    target_index = 0
    matched = 0
    missing = 0
    extra = 0
    modified = 0
    classified_records = 0
    while reference_index < len(reference) and target_index < len(target):
        if classified_records % _DEADLINE_CHECK_RECORDS == 0:
            _require_deadline(deadline_nanoseconds)
        reference_row = reference[reference_index]
        target_row = target[target_index]
        if reference_row.key_value < target_row.key_value:
            missing += 1
            reference_index += 1
            classified_records += 1
            continue
        if reference_row.key_value > target_row.key_value:
            extra += 1
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
        reference_index += 1
        target_index += 1
        classified_records += 1
    missing += len(reference) - reference_index
    extra += len(target) - target_index
    _require_deadline(deadline_nanoseconds)
    return _ExactCounts(
        matched=matched,
        missing=missing,
        extra=extra,
        modified=modified,
    )


def _add_exact_counts(left: _ExactCounts, right: _ExactCounts) -> _ExactCounts:
    return _ExactCounts(
        matched=left.matched + right.matched,
        missing=left.missing + right.missing,
        extra=left.extra + right.extra,
        modified=left.modified + right.modified,
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
) -> int:
    record_bytes = (
        _slot_object_bytes(PostgresIntegerExactRow)
        + _maximum_integer_object_bytes(budgets)
        + (2 * _BYTES_HEADER_BYTES)
        + _ASCII_TEXT_HEADER_BYTES
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
    reference_parsed = _exact_parsed_side_memory_bytes(reference, budgets)
    target_parsed = _exact_parsed_side_memory_bytes(target, budgets)
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
    usage: _Usage,
    budgets: ExecutionBudgets,
    additional_queries: int,
    additional_records: int,
    additional_result_bytes: int,
    coordinator_bytes: int,
) -> None:
    if usage.queries + additional_queries > budgets.max_queries:
        raise ComparisonBudgetExceededError("next comparison read exceeds max_queries")
    if usage.fetched_records + additional_records > budgets.max_fetched_records:
        raise ComparisonBudgetExceededError("next comparison read exceeds max_fetched_records")
    if usage.result_bytes + additional_result_bytes > budgets.max_application_result_bytes:
        raise ComparisonBudgetExceededError(
            "next comparison read exceeds max_application_result_bytes"
        )
    if coordinator_bytes > budgets.max_coordinator_memory_bytes:
        raise ComparisonBudgetExceededError(
            "next comparison read exceeds max_coordinator_memory_bytes"
        )


def _require_full_scan_capacity(
    usage: _Usage,
    budgets: ExecutionBudgets,
    reference_full_scans: int,
    target_full_scans: int,
) -> None:
    if usage.reference_full_scans + reference_full_scans > budgets.max_full_scans_per_side:
        raise ComparisonBudgetExceededError("next reference read exceeds max_full_scans_per_side")
    if usage.target_full_scans + target_full_scans > budgets.max_full_scans_per_side:
        raise ComparisonBudgetExceededError("next target read exceeds max_full_scans_per_side")


def _consume_read_pair(
    usage: _Usage,
    reference: PostgresReadMetrics,
    target: PostgresReadMetrics,
    fingerprint_nodes: int,
    reference_full_scans: int,
    target_full_scans: int,
    coordinator_peak_bytes: int,
) -> _Usage:
    paired_bytes = reference.result_bytes + target.result_bytes
    return _Usage(
        queries=usage.queries + 2,
        fetched_records=(
            usage.fetched_records + reference.fetched_records + target.fetched_records
        ),
        result_bytes=usage.result_bytes + paired_bytes,
        fingerprint_nodes=usage.fingerprint_nodes + fingerprint_nodes,
        coordinator_peak_bytes=max(usage.coordinator_peak_bytes, coordinator_peak_bytes),
        reference_full_scans=usage.reference_full_scans + reference_full_scans,
        target_full_scans=usage.target_full_scans + target_full_scans,
    )


def _require_deadline(deadline_nanoseconds: int) -> None:
    if time.monotonic_ns() >= deadline_nanoseconds:
        raise ComparisonBudgetExceededError("integer comparison exceeded run_timeout_milliseconds")


def _elapsed_milliseconds(started_nanoseconds: int) -> int:
    elapsed_nanoseconds = time.monotonic_ns() - started_nanoseconds
    return max(0, elapsed_nanoseconds // 1_000_000)


def _result_metrics(usage: _Usage, started_nanoseconds: int) -> ResultMetrics:
    return _result_metrics_with_elapsed(usage, _elapsed_milliseconds(started_nanoseconds))


def _result_metrics_with_elapsed(usage: _Usage, elapsed_milliseconds: int) -> ResultMetrics:
    return ResultMetrics(
        queries=usage.queries,
        fetched_records=usage.fetched_records,
        result_bytes=usage.result_bytes,
        fingerprint_nodes=usage.fingerprint_nodes,
        coordinator_peak_bytes=usage.coordinator_peak_bytes,
        elapsed_milliseconds=elapsed_milliseconds,
    )


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
