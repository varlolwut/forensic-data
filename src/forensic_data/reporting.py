import hashlib
import json
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from forensic_data.canonical import LogicalType
from forensic_data.contracts.model import RelationScope, SqlDialect
from forensic_data.result import ExecutionStatus, ReasonCode, ResultReason, RunResult

__all__: Final[tuple[str, ...]] = (
    "DIFF_PAGE_LIMIT_MAX",
    "HISTORY_PAGE_LIMIT_MAX",
    "ComparisonContext",
    "ComparisonDirection",
    "ComparisonField",
    "ComparisonLocator",
    "ComparisonScopeValue",
    "ComparisonSideIdentity",
    "DetailAvailability",
    "DiffCursor",
    "DiffPage",
    "DifferenceKind",
    "DifferenceRecord",
    "EvidenceFieldValue",
    "EvidenceUnavailableReason",
    "EvidenceValueAvailability",
    "HistoryAttemptStatus",
    "HistoryCursor",
    "HistoryEntry",
    "HistoryPage",
    "KeyAvailability",
    "RelationComparisonLocator",
    "SqlComparisonLocator",
    "StoredResultAvailability",
    "canonical_difference_key_bytes",
    "canonical_difference_record_bytes",
)

HISTORY_PAGE_LIMIT_MAX: Final[int] = 100
DIFF_PAGE_LIMIT_MAX: Final[int] = 100

type NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
type PositivePageLimit = Annotated[
    int,
    Field(strict=True, ge=1, le=HISTORY_PAGE_LIMIT_MAX),
]
type PositiveDiffPageLimit = Annotated[
    int,
    Field(strict=True, ge=1, le=DIFF_PAGE_LIMIT_MAX),
]
type NonEmptyText = Annotated[str, Field(strict=True, min_length=1)]
type Sha256Hex = Annotated[
    str,
    Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
]


class _ReportingModel(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
        strict=True,
    )


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
    AVAILABLE = "available"
    PARTIALLY_RETAINED = "partially_retained"
    NOT_RETAINED = "not_retained"


class DifferenceKind(StrEnum):
    MISSING = "missing"
    EXTRA = "extra"
    MODIFIED = "modified"


class EvidenceValueAvailability(StrEnum):
    STORED = "stored"
    REDACTED = "redacted"


class EvidenceUnavailableReason(StrEnum):
    POLICY_REDACTED = "policy_redacted"


class KeyAvailability(StrEnum):
    AVAILABLE = "available"
    KEYSET_UNAVAILABLE = "keyset_unavailable"


class EvidenceFieldValue(_ReportingModel):
    field_name: NonEmptyText
    logical_type: LogicalType
    decimal_precision: Annotated[int, Field(strict=True, ge=1, le=38)] | None
    decimal_scale: Annotated[int, Field(strict=True, ge=0, le=38)] | None
    timestamp_precision: Annotated[int, Field(strict=True, ge=0, le=9)] | None
    raw_available: bool
    availability: EvidenceValueAvailability
    is_null: bool | None
    canonical_text: str | None
    canonical_hex: Annotated[str, Field(strict=True, pattern=r"^(?:[0-9a-f]{2})*$")] | None
    unavailable_reason: EvidenceUnavailableReason | None

    @model_validator(mode="after")
    def validate_value(self) -> Self:
        self._validate_type_parameters()
        if self.availability is EvidenceValueAvailability.STORED:
            if not self.raw_available:
                raise ValueError("stored evidence field requires raw_available")
            if self.is_null is None:
                raise ValueError("stored evidence field requires an explicit null marker")
            if self.unavailable_reason is not None:
                raise ValueError("stored evidence field cannot have an unavailable reason")
            value_count = int(self.canonical_text is not None) + int(self.canonical_hex is not None)
            if self.is_null and value_count != 0:
                raise ValueError("stored NULL evidence field cannot contain a canonical value")
            if not self.is_null and value_count != 1:
                raise ValueError(
                    "stored non-NULL evidence field requires exactly one canonical text or hex value"
                )
            return self

        if self.raw_available or self.is_null is not None:
            raise ValueError("unavailable evidence field cannot expose raw value or null state")
        if self.canonical_text is not None or self.canonical_hex is not None:
            raise ValueError("unavailable evidence field cannot contain a canonical value")
        expected_reason = EvidenceUnavailableReason.POLICY_REDACTED
        if self.unavailable_reason is not expected_reason:
            raise ValueError(
                f"{self.availability.value} evidence field requires reason {expected_reason.value}"
            )
        return self

    def _validate_type_parameters(self) -> None:
        if self.logical_type is LogicalType.DECIMAL:
            if self.decimal_precision is None or self.decimal_scale is None:
                raise ValueError("decimal evidence field requires precision and scale")
            if self.decimal_scale > self.decimal_precision:
                raise ValueError("decimal evidence scale cannot exceed precision")
            if self.timestamp_precision is not None:
                raise ValueError("decimal evidence field cannot have timestamp precision")
            return
        if self.logical_type in (LogicalType.TIMESTAMP_LOCAL, LogicalType.TIMESTAMP_INSTANT):
            if self.timestamp_precision is None:
                raise ValueError("timestamp evidence field requires declared precision")
            if self.decimal_precision is not None or self.decimal_scale is not None:
                raise ValueError("timestamp evidence field cannot have decimal parameters")
            return
        if (
            self.decimal_precision is not None
            or self.decimal_scale is not None
            or self.timestamp_precision is not None
        ):
            raise ValueError(
                f"{self.logical_type.value} evidence field cannot have type parameters"
            )


class DifferenceRecord(_ReportingModel):
    sequence: NonNegativeInt
    segment_sequence: NonNegativeInt
    kind: DifferenceKind
    key_availability: KeyAvailability
    key_digest: Sha256Hex | None
    omitted_field_names: tuple[NonEmptyText, ...]
    key_values: tuple[EvidenceFieldValue, ...]
    reference_values: tuple[EvidenceFieldValue, ...]
    target_values: tuple[EvidenceFieldValue, ...]

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        _require_unique_field_names(self.key_values, "difference key values")
        _require_unique_field_names(self.reference_values, "difference reference values")
        _require_unique_field_names(self.target_values, "difference target values")
        if len(set(self.omitted_field_names)) != len(self.omitted_field_names):
            raise ValueError("difference omitted field names must be unique")
        represented_names = {
            value.field_name
            for value in (*self.key_values, *self.reference_values, *self.target_values)
        }
        if represented_names.intersection(self.omitted_field_names):
            raise ValueError("omitted difference fields cannot contain retained or redacted values")
        if self.key_availability is KeyAvailability.AVAILABLE:
            if not self.key_values or not all(
                value.availability is EvidenceValueAvailability.STORED for value in self.key_values
            ):
                raise ValueError("available difference key requires all retained key fields")
            if self.key_digest is None:
                raise ValueError("available difference key requires its policy-safe digest")
            expected_digest = hashlib.sha256(
                canonical_difference_key_bytes(self.key_values)
            ).hexdigest()
            if self.key_digest != expected_digest:
                raise ValueError("difference key digest does not match its retained key values")
        elif self.key_digest is not None:
            raise ValueError("keyset_unavailable difference cannot contain a key digest")
        if self.kind is DifferenceKind.MISSING and self.target_values:
            raise ValueError("missing difference cannot contain target values")
        if self.kind is DifferenceKind.EXTRA and self.reference_values:
            raise ValueError("extra difference cannot contain reference values")
        return self


class DiffCursor(_ReportingModel):
    run_id: UUID
    attempt_id: UUID
    check_id: NonEmptyText
    result_operation_id: UUID
    sequence: NonNegativeInt


class ComparisonDirection(StrEnum):
    REFERENCE = "reference"
    TARGET = "target"


class RelationComparisonLocator(_ReportingModel):
    locator_type: Literal["relation"]
    catalog: NonEmptyText | None
    schema_name: NonEmptyText = Field(alias="schema", serialization_alias="schema")
    name: NonEmptyText
    relation_scope: RelationScope


class SqlComparisonLocator(_ReportingModel):
    locator_type: Literal["sql"]
    dialect: SqlDialect
    content_sha256: Sha256Hex


type ComparisonLocator = Annotated[
    RelationComparisonLocator | SqlComparisonLocator,
    Field(discriminator="locator_type"),
]


class ComparisonSideIdentity(_ReportingModel):
    direction: ComparisonDirection
    connection_id: NonEmptyText
    dataset_id: NonEmptyText
    locator: ComparisonLocator


class ComparisonScopeValue(_ReportingModel):
    name: NonEmptyText
    logical_type: LogicalType
    canonical_value: str


class ComparisonField(_ReportingModel):
    field_name: NonEmptyText
    logical_type: LogicalType
    decimal_precision: Annotated[int, Field(strict=True, ge=1, le=38)] | None
    decimal_scale: Annotated[int, Field(strict=True, ge=0, le=38)] | None
    timestamp_precision: Annotated[int, Field(strict=True, ge=0, le=9)] | None

    @model_validator(mode="after")
    def validate_parameters(self) -> Self:
        _validate_logical_type_parameters(
            self.logical_type,
            self.decimal_precision,
            self.decimal_scale,
            self.timestamp_precision,
            "comparison field",
        )
        return self


class ComparisonContext(_ReportingModel):
    reference: ComparisonSideIdentity
    target: ComparisonSideIdentity
    scope: tuple[ComparisonScopeValue, ...]
    comparison_fields: tuple[ComparisonField, ...]
    ordered_key: tuple[NonEmptyText, ...]

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        if self.reference.direction is not ComparisonDirection.REFERENCE:
            raise ValueError("comparison reference side requires reference direction")
        if self.target.direction is not ComparisonDirection.TARGET:
            raise ValueError("comparison target side requires target direction")
        scope_names = tuple(value.name for value in self.scope)
        if len(set(scope_names)) != len(scope_names):
            raise ValueError("comparison scope values must not contain duplicate names")
        field_names = tuple(field.field_name for field in self.comparison_fields)
        if not field_names or len(set(field_names)) != len(field_names):
            raise ValueError("comparison fields must be nonempty and uniquely named")
        if not self.ordered_key or len(set(self.ordered_key)) != len(self.ordered_key):
            raise ValueError("comparison ordered key must be nonempty and unique")
        if any(field_name not in set(field_names) for field_name in self.ordered_key):
            raise ValueError("comparison ordered key must reference comparison fields")
        return self


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
        if self.stored_result_availability is StoredResultAvailability.NOT_CREATED:
            if self.stored_result is not None:
                raise ValueError("not-created terminal result cannot contain a stored result")
            return
        if self.status is HistoryAttemptStatus.ABANDONED:
            raise ValueError("abandoned history entry cannot contain a comparison result")
        if self.stored_result_availability is not StoredResultAvailability.AVAILABLE:
            raise AssertionError("unhandled stored-result availability")
        if self.stored_result is None:
            raise ValueError("available terminal result requires its stored result")
        expected_status = (
            ExecutionStatus.INCOMPLETE
            if self.status is HistoryAttemptStatus.INCOMPLETE
            else ExecutionStatus.ERROR
        )
        result = self.stored_result
        if result.execution_status is not expected_status:
            raise ValueError("terminal history status differs from its stored result")
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
            raise ValueError("terminal history entry identity differs from its stored result")
        if self.terminal_reason.code not in {reason.code for reason in result.reasons}:
            raise ValueError("terminal history reason is absent from its stored result")


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
    requested_limit: PositiveDiffPageLimit
    stored_result: RunResult
    comparison_context: ComparisonContext
    detail_availability: DetailAvailability
    found_records: NonNegativeInt
    retained_records: NonNegativeInt
    details: tuple[DifferenceRecord, ...]
    next_cursor: DiffCursor | None

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if (self.run_id, self.attempt_id) != (
            self.stored_result.run_id,
            self.stored_result.attempt_id,
        ):
            raise ValueError("diff page identity differs from its stored result")
        coverage = self.stored_result.evidence_coverage
        if self.found_records != coverage.found_records:
            raise ValueError("diff found_records differs from stored evidence coverage")
        if self.retained_records != coverage.retained_records:
            raise ValueError("diff retained_records differs from stored evidence coverage")
        expected_availability = _detail_availability(
            coverage.found_records, coverage.retained_records
        )
        if self.detail_availability is not expected_availability:
            raise ValueError("diff detail availability disagrees with stored evidence coverage")
        if len(self.details) > self.requested_limit:
            raise ValueError("diff page contains more details than requested")
        previous_sequence: int | None = None
        for detail in self.details:
            if detail.sequence >= self.retained_records:
                raise ValueError("diff detail sequence exceeds retained evidence")
            if previous_sequence is not None and detail.sequence != previous_sequence + 1:
                raise ValueError("diff details must use contiguous ascending sequence order")
            previous_sequence = detail.sequence
        if self.next_cursor is not None:
            if not self.details:
                raise ValueError("empty diff page cannot have a next cursor")
            last = self.details[-1]
            expected_cursor = DiffCursor(
                run_id=self.run_id,
                attempt_id=self.attempt_id,
                check_id=self.stored_result.check_id,
                result_operation_id=_result_operation_id(self.stored_result),
                sequence=last.sequence,
            )
            if self.next_cursor != expected_cursor:
                raise ValueError("diff next cursor must identify the final returned detail")
            if last.sequence + 1 >= self.retained_records:
                raise ValueError("diff page cannot continue past the retained evidence prefix")
        elif self.details and self.details[-1].sequence + 1 < self.retained_records:
            raise ValueError("diff page omits its required continuation cursor")
        return self


def canonical_difference_record_bytes(record: DifferenceRecord) -> bytes:
    payload = record.model_dump(mode="json")
    return _canonical_json_bytes(payload)


def canonical_difference_key_bytes(
    key_values: tuple[EvidenceFieldValue, ...],
) -> bytes:
    if type(key_values) is not tuple:
        raise TypeError("difference key values must be an immutable tuple")
    _require_unique_field_names(key_values, "difference key values")
    if not key_values or any(
        value.availability is not EvidenceValueAvailability.STORED for value in key_values
    ):
        raise ValueError("canonical difference key requires nonempty stored key values")
    payload = {"key_values": [value.model_dump(mode="json") for value in key_values]}
    return _canonical_json_bytes(payload)


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _detail_availability(found_records: int, retained_records: int) -> DetailAvailability:
    if found_records == retained_records:
        return DetailAvailability.AVAILABLE
    if retained_records == 0:
        return DetailAvailability.NOT_RETAINED
    return DetailAvailability.PARTIALLY_RETAINED


def _result_operation_id(result: RunResult) -> UUID:
    operation_id = result.persistence.operation_id
    if operation_id is None:
        raise ValueError("diff stored result requires a persistence operation identity")
    return operation_id


def _require_unique_field_names(
    values: tuple[EvidenceFieldValue, ...],
    context: str,
) -> None:
    names = tuple(value.field_name for value in values)
    if len(set(names)) != len(names):
        raise ValueError(f"{context} must not contain duplicate field names")


def _validate_logical_type_parameters(
    logical_type: LogicalType,
    decimal_precision: int | None,
    decimal_scale: int | None,
    timestamp_precision: int | None,
    context: str,
) -> None:
    if logical_type is LogicalType.DECIMAL:
        if decimal_precision is None or decimal_scale is None:
            raise ValueError(f"{context} decimal type requires precision and scale")
        if decimal_scale > decimal_precision:
            raise ValueError(f"{context} decimal scale cannot exceed precision")
        if timestamp_precision is not None:
            raise ValueError(f"{context} decimal type cannot have timestamp precision")
        return
    if logical_type in (LogicalType.TIMESTAMP_LOCAL, LogicalType.TIMESTAMP_INSTANT):
        if timestamp_precision is None:
            raise ValueError(f"{context} timestamp type requires declared precision")
        if decimal_precision is not None or decimal_scale is not None:
            raise ValueError(f"{context} timestamp type cannot have decimal parameters")
        return
    if (
        decimal_precision is not None
        or decimal_scale is not None
        or timestamp_precision is not None
    ):
        raise ValueError(f"{context} {logical_type.value} type cannot have parameters")


def _require_utc_datetime(value: datetime, context: str) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{context} must use UTC")
