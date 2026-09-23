from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from forensic_data.result import ExecutionStatus, ReasonCode, ResultReason, RunResult

__all__: Final[tuple[str, ...]] = (
    "DIFF_PAGE_LIMIT_MAX",
    "HISTORY_PAGE_LIMIT_MAX",
    "DetailAvailability",
    "DiffPage",
    "HistoryAttemptStatus",
    "HistoryCursor",
    "HistoryEntry",
    "HistoryPage",
    "StoredResultAvailability",
)

HISTORY_PAGE_LIMIT_MAX: Final[int] = 100
DIFF_PAGE_LIMIT_MAX: Final[int] = 100

type NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
type PositivePageLimit = Annotated[
    int,
    Field(strict=True, ge=1, le=HISTORY_PAGE_LIMIT_MAX),
]
type NonEmptyText = Annotated[str, Field(strict=True, min_length=1)]
type Sha256Hex = Annotated[
    str,
    Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
]


class _ReportingModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)


class HistoryAttemptStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    ERROR = "error"
    ABANDONED = "abandoned"


class StoredResultAvailability(StrEnum):
    AVAILABLE = "available"
    NOT_CREATED = "not_created"


class DetailAvailability(StrEnum):
    NOT_RETAINED = "not_retained"


class HistoryCursor(_ReportingModel):
    check_id: NonEmptyText
    scope_digest: Sha256Hex
    started_at: datetime
    run_id: UUID
    attempt_id: UUID

    @model_validator(mode="after")
    def validate_started_at(self) -> Self:
        _require_utc_datetime(self.started_at, "history cursor started_at")
        return self


class HistoryEntry(_ReportingModel):
    run_id: UUID
    attempt_id: UUID
    check_id: NonEmptyText
    contract_digest: Sha256Hex
    scope_digest: Sha256Hex
    ordinal: Annotated[int, Field(strict=True, ge=1)]
    status: HistoryAttemptStatus
    end_operation_id: UUID | None
    started_at: datetime
    ended_at: datetime | None
    is_run_terminal: bool
    terminal_reason: ResultReason | None
    stored_result_availability: StoredResultAvailability
    stored_result: RunResult | None

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        _require_utc_datetime(self.started_at, "history entry started_at")
        if self.ended_at is not None:
            _require_utc_datetime(self.ended_at, "history entry ended_at")
            if self.ended_at < self.started_at:
                raise ValueError("history entry cannot end before it started")
        if self.status is HistoryAttemptStatus.RUNNING:
            self._validate_running_entry()
            return self
        if self.status is HistoryAttemptStatus.COMPLETED:
            self._validate_completed_entry()
        else:
            self._validate_terminal_entry()
        return self

    def _validate_running_entry(self) -> None:
        if self.end_operation_id is not None or self.ended_at is not None:
            raise ValueError("running history entry cannot have terminal fields")
        if self.terminal_reason is not None:
            raise ValueError("running history entry cannot have a terminal reason")
        if self.is_run_terminal:
            raise ValueError("running history entry cannot be the selected terminal attempt")
        if self.stored_result_availability is not StoredResultAvailability.NOT_CREATED:
            raise ValueError("running history entry must report that no result was created")
        if self.stored_result is not None:
            raise ValueError("running history entry cannot contain a stored result")

    def _validate_completed_entry(self) -> None:
        if self.end_operation_id is None or self.ended_at is None:
            raise ValueError("completed history entry requires terminal fields")
        if self.terminal_reason is not None:
            raise ValueError("completed history entry cannot have a terminal reason")
        if self.stored_result_availability is not StoredResultAvailability.AVAILABLE:
            raise ValueError("completed history entry requires an available stored result")
        if self.stored_result is None:
            raise ValueError("completed history entry requires its stored result")
        result = self.stored_result
        identity = (
            self.run_id,
            self.attempt_id,
            self.check_id,
            self.contract_digest,
            self.scope_digest,
            self.end_operation_id,
        )
        result_identity = (
            result.run_id,
            result.attempt_id,
            result.check_id,
            result.contract_digest,
            result.scope_digest,
            result.persistence.operation_id,
        )
        if identity != result_identity:
            raise ValueError("completed history entry identity differs from its stored result")
        if result.execution_status is not ExecutionStatus.COMPLETED:
            raise ValueError("completed history entry requires a completed stored result")

    def _validate_terminal_entry(self) -> None:
        if self.end_operation_id is None or self.ended_at is None:
            raise ValueError("terminal history entry requires terminal fields")
        if self.terminal_reason is None:
            raise ValueError("noncompleted history entry requires its terminal reason")
        if self.stored_result_availability is not StoredResultAvailability.NOT_CREATED:
            raise ValueError("noncompleted history entry must report that no result was created")
        if self.stored_result is not None:
            raise ValueError("noncompleted history entry cannot contain a stored result")
        allowed_codes: dict[HistoryAttemptStatus, frozenset[ReasonCode]] = {
            HistoryAttemptStatus.INCOMPLETE: frozenset(
                {
                    ReasonCode.NOT_READY,
                    ReasonCode.CUT_MISMATCH,
                    ReasonCode.SNAPSHOT_LOST,
                    ReasonCode.BUDGET_EXHAUSTED,
                    ReasonCode.CANCELLED,
                    ReasonCode.CANCELLATION_UNCONFIRMED,
                    ReasonCode.OVERSIZED_RECORD,
                }
            ),
            HistoryAttemptStatus.ERROR: frozenset(
                {
                    ReasonCode.INVALID_CONTRACT,
                    ReasonCode.UNSUPPORTED_CAPABILITY,
                    ReasonCode.LOSSY_TRANSPORT,
                    ReasonCode.QUERY_ERROR,
                    ReasonCode.PERSISTENCE_ERROR,
                    ReasonCode.COMMIT_UNKNOWN,
                    ReasonCode.PROTOCOL_VIOLATION,
                }
            ),
            HistoryAttemptStatus.ABANDONED: frozenset({ReasonCode.SNAPSHOT_LOST}),
        }
        if self.terminal_reason.code not in allowed_codes[self.status]:
            raise ValueError(
                f"history status {self.status.value!r} cannot have reason "
                f"{self.terminal_reason.code.value!r}"
            )


class HistoryPage(_ReportingModel):
    schema_version: Literal[1]
    check_id: NonEmptyText
    scope_digest: Sha256Hex
    requested_limit: PositivePageLimit
    items: tuple[HistoryEntry, ...]
    next_cursor: HistoryCursor | None

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if len(self.items) > self.requested_limit:
            raise ValueError("history page contains more entries than requested")
        identities: set[tuple[UUID, UUID]] = set()
        previous_key: tuple[datetime, int, int] | None = None
        for item in self.items:
            if item.check_id != self.check_id or item.scope_digest != self.scope_digest:
                raise ValueError("history entry identity differs from its page filter")
            identity = (item.run_id, item.attempt_id)
            if identity in identities:
                raise ValueError("history page cannot contain duplicate attempt identities")
            identities.add(identity)
            item_key = (item.started_at, item.run_id.int, item.attempt_id.int)
            if previous_key is not None and item_key >= previous_key:
                raise ValueError("history page entries must use descending keyset order")
            previous_key = item_key
        if self.next_cursor is not None:
            if not self.items:
                raise ValueError("empty history page cannot have a next cursor")
            last = self.items[-1]
            expected = HistoryCursor(
                check_id=self.check_id,
                scope_digest=self.scope_digest,
                started_at=last.started_at,
                run_id=last.run_id,
                attempt_id=last.attempt_id,
            )
            if self.next_cursor != expected:
                raise ValueError("history next cursor must identify the final returned entry")
        return self


class DiffPage(_ReportingModel):
    schema_version: Literal[1]
    run_id: UUID
    attempt_id: UUID
    requested_limit: Annotated[int, Field(strict=True, ge=1, le=DIFF_PAGE_LIMIT_MAX)]
    stored_result: RunResult
    detail_availability: Literal[DetailAvailability.NOT_RETAINED]
    found_records: NonNegativeInt
    retained_records: Literal[0]
    details: tuple[()]
    next_cursor: None

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if (self.run_id, self.attempt_id) != (
            self.stored_result.run_id,
            self.stored_result.attempt_id,
        ):
            raise ValueError("diff page identity differs from its stored result")
        if self.stored_result.execution_status is not ExecutionStatus.COMPLETED:
            raise ValueError("diff page requires a completed stored result")
        coverage = self.stored_result.evidence_coverage
        if self.found_records != coverage.found_records:
            raise ValueError("diff found_records differs from stored evidence coverage")
        if coverage.retained_records != 0:
            raise ValueError("not_retained diff cannot hide retained evidence")
        return self


def _require_utc_datetime(value: datetime, context: str) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{context} must use UTC")
