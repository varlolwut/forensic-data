from enum import IntEnum, StrEnum
from typing import Annotated, Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__: Final[tuple[str, ...]] = (
    "ComparisonCoverage",
    "ComparisonTotals",
    "ConsistencyLevel",
    "ConsistencyStatus",
    "EvidenceCoverage",
    "ExactTotal",
    "ExecutionStatus",
    "ExitCode",
    "Guarantee",
    "InferredTotal",
    "LowerBoundTotal",
    "PersistenceState",
    "PersistenceStatus",
    "ReasonCode",
    "ResultMetrics",
    "ResultReason",
    "RunResult",
    "SafeParameter",
    "Total",
    "UnavailableTotal",
    "Verdict",
    "exit_code_for_result",
)

type NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
type NonNegativeIntegerText = Annotated[
    str,
    Field(strict=True, pattern=r"^(0|[1-9][0-9]*)$"),
]
type NonEmptyText = Annotated[str, Field(strict=True, min_length=1)]
type Sha256Hex = Annotated[
    str,
    Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
]


class _ProtocolModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)


class ExecutionStatus(StrEnum):
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class Verdict(StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"
    INCONCLUSIVE = "inconclusive"


class Guarantee(StrEnum):
    NOT_ESTABLISHED = "not_established"
    EXACT = "exact"
    FINGERPRINT = "fingerprint"
    AGGREGATE = "aggregate"
    STRUCTURAL = "structural"


class ConsistencyLevel(StrEnum):
    VERIFIED = "verified"
    ASSERTED = "asserted"
    UNKNOWN = "unknown"


class ExitCode(IntEnum):
    MATCH = 0
    MISMATCH = 1
    ERROR = 2
    INCOMPLETE = 3


class ReasonCode(StrEnum):
    DATA_MISMATCH = "data_mismatch"
    CONTRACT_VIOLATION = "contract_violation"
    NOT_READY = "not_ready"
    CUT_MISMATCH = "cut_mismatch"
    SNAPSHOT_LOST = "snapshot_lost"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CANCELLED = "cancelled"
    CANCELLATION_UNCONFIRMED = "cancellation_unconfirmed"
    OVERSIZED_RECORD = "oversized_record"
    INVALID_CONTRACT = "invalid_contract"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    LOSSY_TRANSPORT = "lossy_transport"
    QUERY_ERROR = "query_error"
    PERSISTENCE_ERROR = "persistence_error"
    COMMIT_UNKNOWN = "commit_unknown"
    PROTOCOL_VIOLATION = "protocol_violation"


_COMPLETED_REASON_CODES: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.DATA_MISMATCH,
        ReasonCode.CONTRACT_VIOLATION,
    }
)
_INCOMPLETE_REASON_CODES: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.NOT_READY,
        ReasonCode.CUT_MISMATCH,
        ReasonCode.SNAPSHOT_LOST,
        ReasonCode.BUDGET_EXHAUSTED,
        ReasonCode.CANCELLED,
        ReasonCode.CANCELLATION_UNCONFIRMED,
        ReasonCode.OVERSIZED_RECORD,
    }
)
_ERROR_REASON_CODES: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.INVALID_CONTRACT,
        ReasonCode.UNSUPPORTED_CAPABILITY,
        ReasonCode.LOSSY_TRANSPORT,
        ReasonCode.QUERY_ERROR,
        ReasonCode.PERSISTENCE_ERROR,
        ReasonCode.COMMIT_UNKNOWN,
        ReasonCode.PROTOCOL_VIOLATION,
    }
)


class SafeParameter(_ProtocolModel):
    name: NonEmptyText
    value: str


class ResultReason(_ProtocolModel):
    code: ReasonCode
    operation: NonEmptyText
    message: NonEmptyText
    safe_parameters: tuple[SafeParameter, ...]
    native_error_code: str | None
    query_id: str | None
    redacted_response: str | None


class ExactTotal(_ProtocolModel):
    precision: Literal["exact"]
    value: NonNegativeIntegerText


class LowerBoundTotal(_ProtocolModel):
    precision: Literal["lower_bound"]
    value: NonNegativeIntegerText


class InferredTotal(_ProtocolModel):
    precision: Literal["inferred_under_fingerprint"]
    value: NonNegativeIntegerText


class UnavailableTotal(_ProtocolModel):
    precision: Literal["unavailable"]
    value: None
    reason: ReasonCode


type Total = Annotated[
    ExactTotal | LowerBoundTotal | InferredTotal | UnavailableTotal,
    Field(discriminator="precision"),
]


class ComparisonTotals(_ProtocolModel):
    matched: Total
    missing: Total
    extra: Total
    modified: Total

    def values(self) -> tuple[Total, Total, Total, Total]:
        return (self.matched, self.missing, self.extra, self.modified)

    def differences(self) -> tuple[Total, Total, Total]:
        return (self.missing, self.extra, self.modified)


class ComparisonCoverage(_ProtocolModel):
    total_partitions: NonNegativeInt
    covered_partitions: NonNegativeInt
    resolved_segments: NonNegativeInt
    pruned_segments: NonNegativeInt
    exact_segments: NonNegativeInt
    unresolved_segments: NonNegativeInt
    unresolved_reasons: tuple[ReasonCode, ...]

    @model_validator(mode="after")
    def validate_segment_counts(self) -> "ComparisonCoverage":
        if self.covered_partitions > self.total_partitions:
            raise ValueError("covered_partitions cannot exceed total_partitions")
        if self.resolved_segments != self.pruned_segments + self.exact_segments:
            raise ValueError("resolved_segments must equal pruned_segments plus exact_segments")
        if self.covered_partitions > self.resolved_segments:
            raise ValueError("covered partitions require resolved terminal segments")
        if self.unresolved_segments > 0 and self.covered_partitions == self.total_partitions:
            raise ValueError("unresolved segments require at least one uncovered partition")
        if self.unresolved_segments == 0 and self.unresolved_reasons:
            raise ValueError("unresolved_reasons must be empty when unresolved_segments is zero")
        if self.unresolved_segments > 0 and not self.unresolved_reasons:
            raise ValueError("unresolved_reasons must identify why segments are unresolved")
        return self


class EvidenceCoverage(_ProtocolModel):
    found_records: NonNegativeInt
    retained_records: NonNegativeInt
    found_bytes: NonNegativeInt
    retained_bytes: NonNegativeInt

    @model_validator(mode="after")
    def validate_retention_bounds(self) -> "EvidenceCoverage":
        if self.retained_records > self.found_records:
            raise ValueError("retained_records cannot exceed found_records")
        if self.retained_bytes > self.found_bytes:
            raise ValueError("retained_bytes cannot exceed found_bytes")
        return self


class ConsistencyStatus(_ProtocolModel):
    stable_reads: ConsistencyLevel
    cut_alignment: ConsistencyLevel
    read_context_ids: tuple[UUID, ...]

    @model_validator(mode="after")
    def validate_context_ids(self) -> "ConsistencyStatus":
        if len(set(self.read_context_ids)) != len(self.read_context_ids):
            raise ValueError("read_context_ids must not contain duplicates")
        return self


class ResultMetrics(_ProtocolModel):
    queries: NonNegativeInt
    fetched_records: NonNegativeInt
    result_bytes: NonNegativeInt
    fingerprint_nodes: NonNegativeInt
    coordinator_peak_bytes: NonNegativeInt
    elapsed_milliseconds: NonNegativeInt


class PersistenceState(StrEnum):
    CONFIRMED = "confirmed"
    NOT_ATTEMPTED = "not_attempted"
    FAILED = "failed"
    COMMIT_UNKNOWN = "commit_unknown"


_PERSISTENCE_REASON_STATES: Final[tuple[tuple[ReasonCode, PersistenceState], ...]] = (
    (ReasonCode.PERSISTENCE_ERROR, PersistenceState.FAILED),
    (ReasonCode.COMMIT_UNKNOWN, PersistenceState.COMMIT_UNKNOWN),
)


class PersistenceStatus(_ProtocolModel):
    state: PersistenceState
    operation_id: UUID | None
    reason: ResultReason | None

    @model_validator(mode="after")
    def validate_state_details(self) -> "PersistenceStatus":
        if self.state is PersistenceState.NOT_ATTEMPTED:
            if self.operation_id is not None or self.reason is not None:
                raise ValueError("not_attempted persistence cannot have an operation_id or reason")
            return self

        if self.operation_id is None:
            raise ValueError(f"{self.state.value} persistence requires operation_id")

        if self.state is PersistenceState.CONFIRMED:
            if self.reason is not None:
                raise ValueError("confirmed persistence cannot have a failure reason")
            return self

        if self.reason is None:
            raise ValueError(f"{self.state.value} persistence requires a failure reason")

        expected_code = (
            ReasonCode.PERSISTENCE_ERROR
            if self.state is PersistenceState.FAILED
            else ReasonCode.COMMIT_UNKNOWN
        )
        if self.reason.code is not expected_code:
            raise ValueError(
                f"{self.state.value} persistence requires reason code {expected_code.value}"
            )
        return self


class RunResult(_ProtocolModel):
    schema_version: Literal[1]
    run_id: UUID
    attempt_id: UUID
    check_id: NonEmptyText
    contract_digest: Sha256Hex
    scope_digest: Sha256Hex
    execution_status: ExecutionStatus
    verdict: Verdict
    consistency: ConsistencyStatus
    guarantee: Guarantee
    comparison_coverage: ComparisonCoverage
    totals: ComparisonTotals
    evidence_coverage: EvidenceCoverage
    metrics: ResultMetrics
    reasons: tuple[ResultReason, ...]
    persistence: PersistenceStatus

    @model_validator(mode="after")
    def validate_outcome(self) -> "RunResult":
        reason_codes = _all_reason_codes(self)
        top_level_reason_codes = {reason.code for reason in self.reasons}
        _validate_execution_state(self)
        _validate_persistence_reason_codes(self, reason_codes)
        _validate_guarantee(self)
        _validate_totals(self, reason_codes)
        _validate_reason_severity(self, reason_codes, top_level_reason_codes)
        return self


def _all_reason_codes(result: RunResult) -> set[ReasonCode]:
    reason_codes = {reason.code for reason in result.reasons}
    reason_codes.update(result.comparison_coverage.unresolved_reasons)
    reason_codes.update(
        total.reason for total in result.totals.values() if isinstance(total, UnavailableTotal)
    )
    if result.persistence.reason is not None:
        reason_codes.add(result.persistence.reason.code)
    return reason_codes


def _validate_execution_state(result: RunResult) -> None:
    valid_verdicts: dict[ExecutionStatus, frozenset[Verdict]] = {
        ExecutionStatus.COMPLETED: frozenset({Verdict.MATCH, Verdict.MISMATCH}),
        ExecutionStatus.INCOMPLETE: frozenset({Verdict.INCONCLUSIVE, Verdict.MISMATCH}),
        ExecutionStatus.ERROR: frozenset({Verdict.INCONCLUSIVE, Verdict.MISMATCH}),
    }
    if result.verdict not in valid_verdicts[result.execution_status]:
        raise ValueError(
            f"{result.execution_status.value} execution cannot have {result.verdict.value} verdict"
        )
    if result.execution_status is ExecutionStatus.COMPLETED:
        if result.comparison_coverage.unresolved_segments != 0:
            raise ValueError("completed execution cannot have unresolved segments")
        if result.persistence.state is not PersistenceState.CONFIRMED:
            raise ValueError("completed execution requires confirmed persistence")
    if (
        result.execution_status is ExecutionStatus.INCOMPLETE
        and result.guarantee is not Guarantee.NOT_ESTABLISHED
    ):
        raise ValueError("incomplete execution requires not_established guarantee")
    if (
        result.persistence.state in {PersistenceState.FAILED, PersistenceState.COMMIT_UNKNOWN}
        and result.execution_status is not ExecutionStatus.ERROR
    ):
        raise ValueError("failed or uncertain persistence requires error execution status")


def _validate_persistence_reason_codes(
    result: RunResult,
    reason_codes: set[ReasonCode],
) -> None:
    for reason_code, persistence_state in _PERSISTENCE_REASON_STATES:
        has_reason = reason_code in reason_codes
        has_state = result.persistence.state is persistence_state
        if has_reason != has_state:
            raise ValueError(
                f"reason code {reason_code.value} and persistence state "
                f"{persistence_state.value} must appear together"
            )


def _has_known_consistency(result: RunResult) -> bool:
    return bool(result.consistency.read_context_ids) and (
        result.consistency.stable_reads is not ConsistencyLevel.UNKNOWN
        and result.consistency.cut_alignment is not ConsistencyLevel.UNKNOWN
    )


def _validate_guarantee(result: RunResult) -> None:
    if result.guarantee is Guarantee.NOT_ESTABLISHED:
        if result.execution_status is ExecutionStatus.COMPLETED or result.verdict is Verdict.MATCH:
            raise ValueError("not_established guarantee cannot be completed or match")
        return

    if not result.consistency.read_context_ids:
        raise ValueError("established guarantee requires at least one read context")
    if (
        result.consistency.stable_reads is ConsistencyLevel.UNKNOWN
        or result.consistency.cut_alignment is ConsistencyLevel.UNKNOWN
    ):
        raise ValueError("established guarantee requires known consistency evidence")
    coverage = result.comparison_coverage
    if coverage.total_partitions == 0:
        raise ValueError("established guarantee requires at least one verified root partition")
    if (
        coverage.covered_partitions != coverage.total_partitions
        or coverage.unresolved_segments != 0
        or coverage.resolved_segments < coverage.covered_partitions
    ):
        raise ValueError("established guarantee requires a complete resolved frontier")
    if result.guarantee is Guarantee.EXACT:
        if coverage.pruned_segments:
            raise ValueError("exact guarantee cannot include pruned segments")
        if not all(isinstance(total, ExactTotal) for total in result.totals.values()):
            raise ValueError("exact guarantee requires exact totals")
    if result.guarantee is Guarantee.FINGERPRINT:
        if coverage.pruned_segments == 0:
            raise ValueError("fingerprint guarantee requires at least one pruned segment")
        if isinstance(result.totals.matched, ExactTotal):
            raise ValueError("fingerprint guarantee cannot claim an exact matched total")
        if not isinstance(result.totals.matched, InferredTotal):
            raise ValueError("fingerprint guarantee requires an inferred matched total")


def _has_positive_proven_difference(result: RunResult) -> bool:
    return any(
        isinstance(total, (ExactTotal, LowerBoundTotal)) and total.value != "0"
        for total in result.totals.differences()
    )


def _validate_totals(result: RunResult, reason_codes: set[ReasonCode]) -> None:
    inferred_differences = tuple(
        total for total in result.totals.differences() if isinstance(total, InferredTotal)
    )
    if any(total.value != "0" for total in inferred_differences):
        raise ValueError("inferred missing, extra, or modified totals must be zero")
    if any(isinstance(total, InferredTotal) for total in result.totals.values()):
        if result.guarantee is not Guarantee.FINGERPRINT:
            raise ValueError("inferred totals require fingerprint guarantee")

    _validate_match_totals(result)
    has_positive_difference = _has_positive_proven_difference(result)
    has_data_mismatch_reason = ReasonCode.DATA_MISMATCH in reason_codes
    has_contract_violation = ReasonCode.CONTRACT_VIOLATION in reason_codes

    if (has_positive_difference or has_data_mismatch_reason) and not _has_known_consistency(result):
        raise ValueError(
            "proven data mismatch requires known consistency and at least one read context"
        )
    if (
        result.guarantee is Guarantee.FINGERPRINT
        and has_positive_difference
        and result.comparison_coverage.exact_segments == 0
    ):
        raise ValueError("fingerprint difference requires an exact terminal segment")
    if (
        result.guarantee is Guarantee.FINGERPRINT
        and has_data_mismatch_reason
        and not has_positive_difference
    ):
        raise ValueError("fingerprint data_mismatch requires a proven difference")
    if (
        result.guarantee is Guarantee.EXACT
        and result.verdict is Verdict.MISMATCH
        and not has_positive_difference
    ):
        raise ValueError("exact mismatch requires a positive exact difference total")

    has_proven_mismatch = (
        has_positive_difference or has_data_mismatch_reason or has_contract_violation
    )
    if has_proven_mismatch and result.verdict is not Verdict.MISMATCH:
        raise ValueError("proven difference or contract violation requires mismatch verdict")
    if result.verdict is Verdict.MISMATCH and not has_proven_mismatch:
        raise ValueError("mismatch verdict requires a proven difference or violation")

    if has_contract_violation and not all(
        isinstance(total, UnavailableTotal) for total in result.totals.values()
    ):
        raise ValueError("contract violation requires unavailable row totals")
    _validate_fingerprint_evidence(result)
    _validate_late_persistence_evidence(result)


def _validate_match_totals(result: RunResult) -> None:
    if result.verdict is not Verdict.MATCH:
        return
    if any(isinstance(total, UnavailableTotal) for total in result.totals.values()):
        raise ValueError("match result requires all totals to be available")
    if any(total.value != "0" for total in result.totals.differences()):
        raise ValueError("match result requires zero difference totals")
    if result.guarantee is Guarantee.FINGERPRINT:
        if not all(isinstance(total, InferredTotal) for total in result.totals.values()):
            raise ValueError("fingerprint match requires inferred totals")
        return
    if not all(isinstance(total, ExactTotal) for total in result.totals.differences()):
        raise ValueError("non-fingerprint match requires exact zero difference totals")


def _validate_fingerprint_evidence(result: RunResult) -> None:
    if result.guarantee is not Guarantee.FINGERPRINT:
        return
    if result.verdict is Verdict.INCONCLUSIVE:
        if not all(isinstance(total, InferredTotal) for total in result.totals.values()):
            raise ValueError("inconclusive full fingerprint requires preserved inferred totals")


def _validate_late_persistence_evidence(result: RunResult) -> None:
    if result.guarantee is Guarantee.NOT_ESTABLISHED:
        return
    if result.persistence.state not in {PersistenceState.FAILED, PersistenceState.COMMIT_UNKNOWN}:
        return
    persistence_reason_codes = {ReasonCode.PERSISTENCE_ERROR, ReasonCode.COMMIT_UNKNOWN}
    if any(
        isinstance(total, UnavailableTotal) and total.reason in persistence_reason_codes
        for total in result.totals.values()
    ):
        raise ValueError("late persistence failure cannot erase comparison totals")


def _reason_codes_for_status(status: ExecutionStatus) -> frozenset[ReasonCode]:
    if status is ExecutionStatus.ERROR:
        return _ERROR_REASON_CODES
    if status is ExecutionStatus.INCOMPLETE:
        return _INCOMPLETE_REASON_CODES
    return _COMPLETED_REASON_CODES


def _validate_reason_severity(
    result: RunResult,
    reason_codes: set[ReasonCode],
    top_level_reason_codes: set[ReasonCode],
) -> None:
    highest_reason_status = _highest_reason_status(reason_codes)
    if highest_reason_status is not None and highest_reason_status is not result.execution_status:
        raise ValueError(f"reason severity requires {highest_reason_status.value} execution status")
    if result.verdict is Verdict.MATCH:
        if reason_codes:
            raise ValueError("match result cannot have failure reasons")
        return

    governing_reason_codes = _reason_codes_for_status(result.execution_status)
    if result.execution_status is ExecutionStatus.COMPLETED:
        if not reason_codes.intersection(governing_reason_codes):
            raise ValueError("completed result requires a reason for that status")
        return

    detailed_reason_codes = set(top_level_reason_codes)
    if result.persistence.reason is not None:
        detailed_reason_codes.add(result.persistence.reason.code)
    if not detailed_reason_codes.intersection(governing_reason_codes):
        raise ValueError(
            f"{result.execution_status.value} result requires a detailed top-level reason"
        )


def _highest_reason_status(
    reason_codes: set[ReasonCode],
) -> ExecutionStatus | None:
    for status in (
        ExecutionStatus.ERROR,
        ExecutionStatus.INCOMPLETE,
        ExecutionStatus.COMPLETED,
    ):
        if reason_codes.intersection(_reason_codes_for_status(status)):
            return status
    return None


def exit_code_for_result(result: RunResult) -> ExitCode:
    if result.execution_status is ExecutionStatus.ERROR:
        return ExitCode.ERROR
    if result.execution_status is ExecutionStatus.INCOMPLETE:
        return ExitCode.INCOMPLETE
    if result.verdict is Verdict.MISMATCH:
        return ExitCode.MISMATCH
    return ExitCode.MATCH
