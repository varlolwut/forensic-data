import logging
import math
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime
from datetime import time as datetime_time
from decimal import Decimal
from enum import StrEnum
from threading import Condition, Lock, get_ident
from typing import NoReturn, cast
from uuid import UUID, uuid4

import pyodbc
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from forensic_data.canonical import (
    CanonicalizationError,
    CanonicalSchema,
    Fingerprint,
    FingerprintOverflowError,
    decode_key_with_context,
    decode_row_with_context,
    prepare_envelope_context,
)
from forensic_data.contracts.model import ReadinessManifestColumns, RelationScope
from forensic_data.mssql_sql import (
    INT32_MAX,
    MAX_COMPILED_RELATION_MEMBERS,
    MssqlCanonicalQuery,
    MssqlCanonicalResultKind,
    MssqlFieldBinding,
    MssqlInspectedRelation,
    MssqlIntegerRangeRequest,
    MssqlLoweringError,
    MssqlPhysicalField,
    MssqlRelation,
    MssqlScopePredicate,
    build_mssql_integer_key_summary_query,
    build_mssql_integer_range_fingerprint_query,
    build_mssql_integer_range_rows_query,
    build_mssql_relation_manifest_query,
    validate_mssql_inspection,
)
from forensic_data.postgres import (
    PostgresIntegerExactRow,
    PostgresIntegerExactRowsRead,
    PostgresIntegerKeySummary,
    PostgresIntegerKeySummaryRead,
    PostgresRangeFingerprint,
    PostgresRangeFingerprintRead,
    PostgresReadDeadline,
    PostgresReadDeadlineExceededError,
    PostgresReadMetrics,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetExceededError,
    PostgresSourceDirection,
    PostgresSourceQueryCharge,
)
from forensic_data.postgres_sql import PostgresIntegerRangeRequest, PostgresScopePredicate

LOGGER = logging.getLogger(__name__)
_DRIVER_NAME = "ODBC Driver 18 for SQL Server"
_CONFIRMATION_SENTINEL = 1
_SQL_COPT_SS_TXN_ISOLATION = 1_227
_SQL_TXN_SS_SNAPSHOT = 32
_CANONICAL_UTF8_COLLATION = "Latin1_General_100_BIN2_UTF8"
_MAX_INTEGER_RANGE_ROW_BYTES = 8_000
_MAX_INT64_KEY_ENVELOPE_BYTES = 136
_EXACT_STATUS_BYTES = 2
_DEADLINE_CHECK_RECORDS = 64

type MssqlParameter = str | int | Decimal | bytes
type MssqlValue = bool | int | Decimal | str | bytes | None
type MssqlRow = tuple[MssqlValue, ...]


class MssqlTransportError(RuntimeError):
    """Base error for the SQL Server transport boundary."""


class MssqlConnectionError(MssqlTransportError):
    """Opening or profiling a SQL Server connection failed."""


class MssqlQueryError(MssqlTransportError):
    """A SQL Server statement failed and its transport was retired."""

    def __init__(self, query_id: UUID, session_id: int, sqlstate: str) -> None:
        self.query_id = query_id
        self.session_id = session_id
        self.sqlstate = sqlstate
        super().__init__(
            "SQL Server query failed: "
            f"query_id={query_id}, session_id={session_id}, sqlstate={sqlstate!r}"
        )


class MssqlDataValidationError(MssqlTransportError):
    """SQL Server or its driver returned data outside the typed transport contract."""


class MssqlLossyTransportError(MssqlDataValidationError):
    """A driver value cannot cross the transport boundary without information loss."""


class MssqlResultLimitError(MssqlTransportError):
    """A SQL Server result exceeded an explicit transport limit."""


class MssqlCancellationError(MssqlTransportError):
    """Base error for SQL Server query cancellation."""


class MssqlCancellationConfirmedError(MssqlCancellationError):
    """The requested statement ended and the same SQL Server session was confirmed."""

    def __init__(
        self,
        query_id: UUID,
        session_id: int,
        sqlstate: str,
        confirmation_session_id: int,
        confirmation_value: int,
    ) -> None:
        self.query_id = query_id
        self.session_id = session_id
        self.sqlstate = sqlstate
        self.confirmation_session_id = confirmation_session_id
        self.confirmation_value = confirmation_value
        super().__init__(
            "SQL Server query cancellation was confirmed: "
            f"query_id={query_id}, session_id={session_id}, sqlstate={sqlstate!r}"
        )


class MssqlCancellationUnconfirmedError(MssqlCancellationError):
    """A cancellation request could not be proven complete on its original session."""

    def __init__(self, query_id: UUID, session_id: int, reason: str) -> None:
        self.query_id = query_id
        self.session_id = session_id
        self.reason = reason
        super().__init__(
            "SQL Server query cancellation could not be confirmed: "
            f"query_id={query_id}, session_id={session_id}, reason={reason!r}"
        )


class MssqlCancellationRequestTimeoutError(MssqlCancellationError):
    """The worker did not acknowledge a cancellation request within its deadline."""


class MssqlTransportClosedError(MssqlTransportError):
    """An operation was attempted on a retired SQL Server transport."""


class MssqlCloseError(MssqlTransportError):
    """A SQL Server cursor or connection could not be closed explicitly."""


class MssqlNoActiveQueryError(MssqlCancellationError):
    """Cancellation was requested without an active SQL Server statement."""


class MssqlWrongQueryIdError(MssqlCancellationError):
    """Cancellation targeted a query other than the currently active statement."""


class MssqlThreadOwnershipError(MssqlTransportError):
    """A connection operation was attempted outside its owner thread."""


class MssqlQueryTimeoutError(MssqlQueryError):
    """ODBC timed out a statement and same-session completion was confirmed."""


class UnsupportedMssqlProfileError(MssqlTransportError):
    """The server, database, or transaction cannot satisfy the SQL Server profile."""


class MssqlMetadataError(MssqlDataValidationError):
    """SQL Server catalog provenance is absent, unsupported, or changed."""


class UnsupportedMssqlRelationError(MssqlMetadataError):
    """Initial SQL Server relation inspection rejected the declared source."""


class MssqlQueryContextError(MssqlTransportError):
    """A compiled SQL Server query belongs to another read context."""


class MssqlContextClosedError(MssqlTransportClosedError):
    """A closed SQL Server read context cannot execute another operation."""


class MssqlContextLostError(MssqlTransportError):
    """A failed SQL Server read context cannot be resumed."""


class MssqlTlsVerification(StrEnum):
    VERIFY_SERVER_CERTIFICATE = "verify-server-certificate"
    TRUST_FIXTURE_CERTIFICATE = "trust-fixture-certificate"


class MssqlConnectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: str
    port: int = Field(ge=1, le=65_535)
    database: str
    user: str
    password: SecretStr
    tls_verification: MssqlTlsVerification
    login_timeout_seconds: int = Field(ge=1)
    query_timeout_seconds: int = Field(ge=1)
    cancellation_acknowledgement_timeout_seconds: float = Field(gt=0)
    application_name: str

    @field_validator("host", "database", "user", "application_name")
    @classmethod
    def validate_nonempty_connection_text(cls, value: str) -> str:
        if not value:
            raise ValueError("SQL Server connection text fields must not be empty")
        _validate_odbc_text_scalar(value, "SQL Server connection text fields")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: SecretStr) -> SecretStr:
        password = value.get_secret_value()
        if not password:
            raise ValueError("SQL Server password must not be empty")
        _validate_odbc_text_scalar(password, "SQL Server password")
        return value

    @field_validator("cancellation_acknowledgement_timeout_seconds")
    @classmethod
    def validate_finite_cancellation_timeout(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("cancellation acknowledgement timeout must be finite")
        return value


@dataclass(frozen=True, slots=True)
class MssqlRetryPolicy:
    max_attempts: int
    delay_seconds: float

    def __post_init__(self) -> None:
        if type(self.max_attempts) is not int or self.max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        if (
            type(self.delay_seconds) is not float
            or not math.isfinite(self.delay_seconds)
            or self.delay_seconds < 0
        ):
            raise ValueError("delay_seconds must be a finite non-negative float")


@dataclass(frozen=True, slots=True)
class MssqlQuery:
    query_id: UUID
    statement: str
    parameters: tuple[MssqlParameter, ...]

    def __post_init__(self) -> None:
        if type(self.query_id) is not UUID:
            raise TypeError("query_id must be a UUID")
        if type(self.statement) is not str or not self.statement:
            raise ValueError("statement must be non-empty text")
        _validate_odbc_text_scalar(self.statement, "statement")
        if type(self.parameters) is not tuple:
            raise TypeError("parameters must be a tuple")
        for parameter in self.parameters:
            _validate_parameter(parameter)


@dataclass(frozen=True, slots=True)
class MssqlFetchLimits:
    """Bounds retained rows and one transient fetch batch, not process RSS."""

    fetch_batch_records: int
    max_records: int
    max_value_bytes: int
    max_record_bytes: int
    max_total_bytes: int
    max_declared_value_bytes: int
    max_declared_record_bytes: int

    def __post_init__(self) -> None:
        for name, value in (
            ("fetch_batch_records", self.fetch_batch_records),
            ("max_records", self.max_records),
            ("max_value_bytes", self.max_value_bytes),
            ("max_record_bytes", self.max_record_bytes),
            ("max_total_bytes", self.max_total_bytes),
            ("max_declared_value_bytes", self.max_declared_value_bytes),
            ("max_declared_record_bytes", self.max_declared_record_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_value_bytes > self.max_record_bytes:
            raise ValueError("max_value_bytes must not exceed max_record_bytes")
        if self.max_record_bytes > self.max_total_bytes:
            raise ValueError("max_record_bytes must not exceed max_total_bytes")
        if self.max_declared_value_bytes > self.max_declared_record_bytes:
            raise ValueError("max_declared_value_bytes must not exceed max_declared_record_bytes")
        maximum_batch_bytes = self.fetch_batch_records * self.max_record_bytes
        if maximum_batch_bytes > self.max_total_bytes:
            raise ValueError(
                "max_total_bytes must admit one worst-case fetch batch: "
                f"required={maximum_batch_bytes}"
            )


@dataclass(frozen=True, slots=True)
class MssqlDriverEvidence:
    pyodbc_version: str
    driver_name: str
    driver_version: str
    server_version: str
    session_id: int


@dataclass(frozen=True, slots=True)
class MssqlServerProfile:
    driver: MssqlDriverEvidence
    product_version: str
    product_major_version: int
    product_build: str
    engine_edition: int
    edition: str
    product_level: str
    product_update_level: str | None
    product_update_reference: str | None
    server_collation: str
    database_id: int
    database_name: str
    compatibility_level: int
    database_collation: str
    snapshot_isolation_state: int
    snapshot_isolation_state_description: str
    read_committed_snapshot: bool
    database_read_only: bool
    database_updateability: str
    canonical_utf8_code_page: int
    can_view_definition: bool


@dataclass(frozen=True, slots=True)
class MssqlReadContextEvidence:
    context_id: UUID
    engine: str
    server_version: str
    strategy: str
    snapshot_locator: None
    started_at: datetime
    session_id: int
    database_id: int
    transaction_count: int
    transaction_state: int
    transaction_isolation_level: int
    allowed_concurrency: int
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MssqlRelationAcquisition:
    schema: CanonicalSchema
    relation: MssqlRelation
    relation_scope: RelationScope
    column_names: tuple[str, ...]
    max_metadata_record_bytes: int
    max_metadata_total_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.schema), CanonicalSchema):
            raise TypeError("SQL Server acquisition schema must be CanonicalSchema")
        if type(self.relation) is not MssqlRelation:
            raise TypeError("SQL Server acquisition relation must be MssqlRelation")
        if self.relation_scope is not RelationScope.PHYSICAL_ONLY:
            raise ValueError("SQL Server acquisition requires physical_only relation scope")
        if type(self.column_names) is not tuple or len(self.column_names) != len(
            self.schema.fields
        ):
            raise ValueError(
                "SQL Server acquisition columns must cover the logical schema in order"
            )
        for column_name in self.column_names:
            _validate_catalog_identifier(column_name, "SQL Server acquisition column")
        for name, value in (
            ("max_metadata_record_bytes", self.max_metadata_record_bytes),
            ("max_metadata_total_bytes", self.max_metadata_total_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"SQL Server acquisition {name} must be positive")
        if self.max_metadata_record_bytes > self.max_metadata_total_bytes:
            raise ValueError("SQL Server acquisition record limit cannot exceed its total limit")


class MssqlReadContextState(StrEnum):
    ACTIVE = "active"
    LOST = "lost"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class MssqlReadMetrics:
    fetched_records: int
    fetched_bytes: int
    fetch_calls: int
    largest_batch_records: int


@dataclass(frozen=True, slots=True)
class MssqlReadResult:
    rows: tuple[MssqlRow, ...]
    metrics: MssqlReadMetrics


@dataclass(frozen=True, slots=True)
class MssqlKeySummary:
    row_count: int
    null_key_count: int
    invalid_key_count: int
    oversized_key_count: int
    valid_key_count: int
    distinct_key_count: int

    def __post_init__(self) -> None:
        for field_name, value in (
            ("row_count", self.row_count),
            ("null_key_count", self.null_key_count),
            ("invalid_key_count", self.invalid_key_count),
            ("oversized_key_count", self.oversized_key_count),
            ("valid_key_count", self.valid_key_count),
            ("distinct_key_count", self.distinct_key_count),
        ):
            _require_bounded_integer(value, field_name, 0, (1 << 63) - 1)
        if self.row_count != (
            self.null_key_count
            + self.invalid_key_count
            + self.oversized_key_count
            + self.valid_key_count
        ):
            raise MssqlDataValidationError(
                "SQL Server key-summary counts do not partition the source rows"
            )
        if self.distinct_key_count > self.valid_key_count:
            raise MssqlDataValidationError(
                "SQL Server distinct canonical-key count exceeds the valid key count"
            )


@dataclass(frozen=True, slots=True)
class MssqlKeySummaryRead:
    summary: MssqlKeySummary
    metrics: MssqlReadMetrics


@dataclass(frozen=True, slots=True)
class MssqlRelationManifestRecord:
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: date
    source_cut: str | None
    dataset_version: str | None
    completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class _MssqlCancellationEvidence:
    requested: bool
    confirmation_session_id: int
    confirmation_value: int


class _MssqlQueryAccounting:
    def timeout_seconds(self, configured_timeout_seconds: int) -> int:
        raise NotImplementedError

    def before_dispatch(self) -> None:
        raise NotImplementedError

    def before_fetch(self) -> None:
        raise NotImplementedError

    def after_empty_fetch(self) -> None:
        raise NotImplementedError

    def consume_records(self, record_bytes: tuple[int, ...]) -> None:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class _StandaloneMssqlQueryAccounting(_MssqlQueryAccounting):
    def timeout_seconds(self, configured_timeout_seconds: int) -> int:
        return configured_timeout_seconds

    def before_dispatch(self) -> None:
        return

    def before_fetch(self) -> None:
        return

    def after_empty_fetch(self) -> None:
        return

    def consume_records(self, record_bytes: tuple[int, ...]) -> None:
        return


@dataclass(frozen=True, slots=True)
class _BudgetedMssqlQueryAccounting(_MssqlQueryAccounting):
    charge: PostgresSourceQueryCharge
    deadline: PostgresReadDeadline

    def timeout_seconds(self, configured_timeout_seconds: int) -> int:
        _require_mssql_deadline(self.deadline, "query timeout calculation")
        remaining_nanoseconds = self.deadline.deadline_nanoseconds - time.monotonic_ns()
        remaining_seconds = max(1, math.ceil(remaining_nanoseconds / 1_000_000_000))
        statement_seconds = max(
            1,
            math.ceil(self.deadline.statement_timeout_milliseconds / 1_000),
        )
        return min(configured_timeout_seconds, remaining_seconds, statement_seconds)

    def before_dispatch(self) -> None:
        _require_mssql_deadline(self.deadline, "query dispatch")
        self.charge.require_fetch_deadline()

    def before_fetch(self) -> None:
        _require_mssql_deadline(self.deadline, "result fetch")
        self.charge.require_fetch_deadline()

    def after_empty_fetch(self) -> None:
        _require_mssql_deadline(self.deadline, "empty result receipt")
        self.charge.require_fetch_deadline()

    def consume_records(self, record_bytes: tuple[int, ...]) -> None:
        self.charge.consume_records(record_bytes)
        _require_mssql_deadline(self.deadline, "result receipt")


class MssqlTransport:
    """A single-owner pyodbc transport with query-scoped cross-thread cancellation.

    A native SQLCancel call remains driver-controlled. If it stalls, the statement handle stays
    active and cannot be closed or reported complete until that call returns.
    Acknowledgement is timely only when the supervisor observes terminal detachment by its deadline.
    """

    def __init__(
        self,
        connection: pyodbc.Connection,
        evidence: MssqlDriverEvidence,
        cancellation_acknowledgement_timeout_seconds: float,
        query_timeout_seconds: int,
    ) -> None:
        self._connection = connection
        self._evidence = evidence
        self._cancellation_acknowledgement_timeout_seconds = (
            cancellation_acknowledgement_timeout_seconds
        )
        self._query_timeout_seconds = query_timeout_seconds
        self._owner_thread_id = get_ident()
        self._state_changed = Condition(Lock())
        self._closed = False
        self._active_query_id: UUID | None = None
        self._active_cursor: pyodbc.Cursor | None = None
        self._cancel_requested = False
        self._cancel_calls = 0

    @property
    def evidence(self) -> MssqlDriverEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._state_changed:
            return self._closed

    @property
    def active_query_id(self) -> UUID | None:
        with self._state_changed:
            return self._active_query_id

    def configure_snapshot_transaction(self) -> None:
        self._require_owner_thread()
        self._require_open()
        with self._state_changed:
            if self._active_query_id is not None:
                raise MssqlTransportError(
                    "SQL Server transport cannot configure SNAPSHOT while a query is active"
                )
        try:
            self._connection.rollback()
            self._connection.autocommit = True
            self._connection.set_attr(
                _SQL_COPT_SS_TXN_ISOLATION,
                _SQL_TXN_SS_SNAPSHOT,
            )
            self._connection.autocommit = False
        except pyodbc.Error as error:
            self._retire_after_setup_error()
            raise MssqlConnectionError(
                "SQL Server ODBC SNAPSHOT transaction configuration failed: "
                f"session_id={self._evidence.session_id}, sqlstate={_sqlstate(error)!r}"
            ) from None

    def rollback(self) -> None:
        self._require_owner_thread()
        self._require_open()
        with self._state_changed:
            if self._active_query_id is not None:
                raise MssqlTransportError(
                    "SQL Server transport cannot roll back while a query is active: "
                    f"query_id={self._active_query_id}"
                )
        try:
            self._connection.rollback()
        except pyodbc.Error:
            self._retire_after_setup_error()
            raise MssqlCloseError(
                f"SQL Server transaction rollback failed: session_id={self._evidence.session_id}"
            ) from None

    def execute_bounded(
        self,
        query: MssqlQuery,
        limits: MssqlFetchLimits,
    ) -> MssqlReadResult:
        return self._execute_bounded(
            query,
            limits,
            _StandaloneMssqlQueryAccounting(),
        )

    def execute_budgeted(
        self,
        query: MssqlQuery,
        limits: MssqlFetchLimits,
        charge: PostgresSourceQueryCharge,
        deadline: PostgresReadDeadline,
    ) -> MssqlReadResult:
        if not isinstance(cast(object, charge), PostgresSourceQueryCharge):
            raise TypeError("SQL Server budgeted query charge must be PostgresSourceQueryCharge")
        if not isinstance(cast(object, deadline), PostgresReadDeadline):
            raise TypeError("SQL Server budgeted query deadline must be PostgresReadDeadline")
        return self._execute_bounded(
            query,
            limits,
            _BudgetedMssqlQueryAccounting(charge, deadline),
        )

    def _execute_bounded(
        self,
        query: MssqlQuery,
        limits: MssqlFetchLimits,
        accounting: _MssqlQueryAccounting,
    ) -> MssqlReadResult:
        self._require_owner_thread()
        self._require_open()
        cursor: pyodbc.Cursor | None = None
        published = False
        rows: list[MssqlRow] = []
        fetched_bytes = 0
        fetch_calls = 0
        largest_batch_records = 0
        try:
            self._connection.timeout = accounting.timeout_seconds(self._query_timeout_seconds)
            cursor = self._connection.cursor()
            cursor.arraysize = limits.fetch_batch_records
            self._publish_active_query(query.query_id, cursor)
            published = True
            if self._is_cancel_requested(query.query_id):
                self._raise_confirmed_cancellation(cursor, query.query_id, "before-dispatch")

            statement = f"/* dfe_query_id={query.query_id} */\n{query.statement}"
            accounting.before_dispatch()
            if query.parameters:
                cursor.execute(statement, query.parameters)
            else:
                cursor.execute(statement)
            if self._is_cancel_requested(query.query_id):
                self._raise_confirmed_cancellation(cursor, query.query_id, "raced-success")
            expected_column_count = _validate_result_description(
                cursor.description,
                limits.max_declared_value_bytes,
                limits.max_declared_record_bytes,
            )

            while True:
                accounting.before_fetch()
                remaining_with_overflow_probe = limits.max_records + 1 - len(rows)
                fetch_size = min(limits.fetch_batch_records, remaining_with_overflow_probe)
                raw_batch = cursor.fetchmany(fetch_size)
                fetch_calls += 1
                largest_batch_records = max(largest_batch_records, len(raw_batch))
                if not raw_batch:
                    accounting.after_empty_fetch()
                    if self._is_cancel_requested(query.query_id):
                        self._raise_confirmed_cancellation(
                            cursor,
                            query.query_id,
                            "raced-success",
                        )
                    break
                if self._is_cancel_requested(query.query_id):
                    accounting.consume_records(tuple(limits.max_record_bytes for _row in raw_batch))
                    self._raise_confirmed_cancellation(
                        cursor,
                        query.query_id,
                        "raced-success",
                    )

                validated_batch: list[MssqlRow] = []
                batch_record_bytes: list[int] = []
                for raw_row in raw_batch:
                    try:
                        row, row_bytes = _validated_driver_row(
                            raw_row,
                            expected_column_count,
                            limits.max_value_bytes,
                            limits.max_record_bytes,
                        )
                    except MssqlTransportError:
                        accounting.consume_records(
                            (
                                *batch_record_bytes,
                                *(
                                    limits.max_record_bytes
                                    for _remaining_row in raw_batch[len(batch_record_bytes) :]
                                ),
                            )
                        )
                        raise
                    validated_batch.append(row)
                    batch_record_bytes.append(row_bytes)

                accounting.consume_records(tuple(batch_record_bytes))
                batch_bytes = sum(batch_record_bytes)

                if len(rows) + len(validated_batch) > limits.max_records:
                    raise MssqlResultLimitError(
                        "SQL Server result exceeded max_records: "
                        f"query_id={query.query_id}, max_records={limits.max_records}"
                    )
                if fetched_bytes + batch_bytes > limits.max_total_bytes:
                    raise MssqlResultLimitError(
                        "SQL Server result exceeded max_total_bytes: "
                        f"query_id={query.query_id}, max_total_bytes={limits.max_total_bytes}"
                    )
                rows.extend(validated_batch)
                fetched_bytes += batch_bytes

            self._drain_terminal_results(cursor, query.query_id, accounting)
            if self._finish_success(query.query_id, cursor):
                self._raise_confirmed_cancellation(cursor, query.query_id, "raced-success")
            return MssqlReadResult(
                rows=tuple(rows),
                metrics=MssqlReadMetrics(
                    fetched_records=len(rows),
                    fetched_bytes=fetched_bytes,
                    fetch_calls=fetch_calls,
                    largest_batch_records=largest_batch_records,
                ),
            )
        except pyodbc.Error as error:
            sqlstate = _sqlstate(error)
            if published and cursor is not None:
                cancel_requested = self._detach_terminal_cursor(query.query_id, cursor)
                if cancel_requested:
                    self._raise_confirmed_cancellation_from_detached(
                        cursor,
                        query.query_id,
                        sqlstate,
                    )
                if sqlstate in ("HYT00", "HYT01"):
                    self._raise_confirmed_timeout_from_detached(
                        cursor,
                        query.query_id,
                        sqlstate,
                    )
            self._retire_after_query_error(cursor, query.query_id)
            raise MssqlQueryError(query.query_id, self._evidence.session_id, sqlstate) from None
        except UnicodeDecodeError:
            if published and cursor is not None:
                cancellation_evidence = self._interrupt_and_retire(cursor, query.query_id)
                self._raise_raced_cancellation(query.query_id, cancellation_evidence)
            elif cursor is not None:
                self._close_unpublished_cursor(cursor, query.query_id)
            raise MssqlLossyTransportError(
                f"ODBC returned text that cannot be decoded losslessly: query_id={query.query_id}"
            ) from None
        except OverflowError:
            if published and cursor is not None:
                cancellation_evidence = self._interrupt_and_retire(cursor, query.query_id)
                self._raise_raced_cancellation(query.query_id, cancellation_evidence)
            elif cursor is not None:
                self._close_unpublished_cursor(cursor, query.query_id)
            raise MssqlDataValidationError(
                "ODBC value conversion exceeded its supported numeric range: "
                f"query_id={query.query_id}"
            ) from None
        except MssqlCloseError:
            raise
        except MssqlCancellationError:
            raise
        except (PostgresReadDeadlineExceededError, PostgresSourceBudgetExceededError):
            if published and cursor is not None:
                cancellation_evidence = self._interrupt_and_retire(cursor, query.query_id)
                self._raise_raced_cancellation(query.query_id, cancellation_evidence)
            elif cursor is not None:
                self._close_unpublished_cursor(cursor, query.query_id)
            raise
        except MssqlTransportError:
            if published and cursor is not None:
                cancellation_evidence = self._interrupt_and_retire(cursor, query.query_id)
                self._raise_raced_cancellation(query.query_id, cancellation_evidence)
            elif cursor is not None:
                self._close_unpublished_cursor(cursor, query.query_id)
            raise

    def _drain_terminal_results(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
        accounting: _MssqlQueryAccounting,
    ) -> None:
        while True:
            accounting.before_fetch()
            has_next_result = cursor.nextset()
            accounting.after_empty_fetch()
            if self._is_cancel_requested(query_id):
                self._raise_confirmed_cancellation(cursor, query_id, "raced-success")
            if not has_next_result:
                return
            if cast(object, cursor.description) is not None:
                raise MssqlDataValidationError(
                    "SQL Server query returned an unexpected additional data result set: "
                    f"query_id={query_id}"
                )

    def cancel(self, query_id: UUID) -> None:
        if type(query_id) is not UUID:
            raise TypeError("query_id must be a UUID")
        if get_ident() == self._owner_thread_id:
            raise MssqlThreadOwnershipError(
                "SQL Server cancel must be called from the transport owner's supervisor thread"
            )
        deadline = time.monotonic() + self._cancellation_acknowledgement_timeout_seconds
        with self._state_changed:
            self._validate_cancellation_target_locked(query_id)
            if self._cancel_requested:
                self._wait_for_cancellation_acknowledgement_locked(query_id, deadline)
                return
            self._cancel_requested = True
        while True:
            with self._state_changed:
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise self._cancellation_request_timeout(query_id)
                if self._active_query_id != query_id or self._active_cursor is None:
                    return
                cursor = self._active_cursor
                self._cancel_calls += 1
            try:
                cursor.cancel()
            except pyodbc.Error as error:
                LOGGER.warning(
                    "SQL Server cancellation request returned an ODBC diagnostic",
                    extra={
                        "query_id": str(query_id),
                        "session_id": self._evidence.session_id,
                        "sqlstate": _sqlstate(error),
                    },
                )
            finally:
                with self._state_changed:
                    self._cancel_calls -= 1
                    self._state_changed.notify_all()
            with self._state_changed:
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise self._cancellation_request_timeout(query_id)
                if not self._query_handle_is_active_locked(query_id):
                    return
                self._state_changed.wait(min(0.05, remaining_seconds))

    def close(self) -> None:
        self._require_owner_thread()
        with self._state_changed:
            if self._closed:
                return
            if self._active_query_id is not None:
                raise MssqlTransportError(
                    "SQL Server transport cannot close while a query is active: "
                    f"query_id={self._active_query_id}"
                )
            self._closed = True
            self._state_changed.notify_all()
        try:
            self._connection.close()
        except pyodbc.Error:
            raise MssqlCloseError("SQL Server connection close failed") from None

    def _publish_active_query(self, query_id: UUID, cursor: pyodbc.Cursor) -> None:
        with self._state_changed:
            if self._closed:
                raise MssqlTransportClosedError("SQL Server transport is already closed")
            if self._active_query_id is not None:
                raise MssqlTransportError(
                    "SQL Server transport already has an active query: "
                    f"query_id={self._active_query_id}"
                )
            if self._cancel_calls != 0:
                raise MssqlTransportError(
                    "SQL Server cancellation bookkeeping was not quiescent before dispatch"
                )
            self._active_query_id = query_id
            self._active_cursor = cursor
            self._cancel_requested = False
            self._state_changed.notify_all()

    def _validate_cancellation_target_locked(self, query_id: UUID) -> None:
        if self._closed:
            raise MssqlTransportClosedError("SQL Server transport is already closed")
        if self._active_query_id is None:
            raise MssqlNoActiveQueryError("SQL Server transport has no active query")
        if self._active_query_id != query_id:
            raise MssqlWrongQueryIdError(
                "SQL Server cancellation query_id does not match the active query: "
                f"requested={query_id}, active={self._active_query_id}"
            )
        if self._active_cursor is None:
            raise MssqlNoActiveQueryError(
                "SQL Server query reached its atomic terminal point before cancellation"
            )

    def _is_cancel_requested(self, query_id: UUID) -> bool:
        with self._state_changed:
            return self._active_query_id == query_id and self._cancel_requested

    def _finish_success(self, query_id: UUID, cursor: pyodbc.Cursor) -> bool:
        with self._state_changed:
            if self._active_query_id != query_id or self._active_cursor is not cursor:
                raise MssqlTransportError(
                    "SQL Server active query state changed before successful completion"
                )
            if self._cancel_requested:
                return True
            while self._cancel_calls > 0:
                self._state_changed.wait()
                if self._cancel_requested:
                    return True
            self._clear_active_query_locked()
            self._state_changed.notify_all()
        try:
            cursor.close()
        except pyodbc.Error:
            self._retire_connection_after_terminal_query(query_id)
            raise MssqlCloseError(
                "SQL Server cursor close failed after a successful bounded read: "
                f"query_id={query_id}"
            ) from None
        return False

    def _raise_confirmed_cancellation(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
        sqlstate: str,
    ) -> None:
        self._detach_terminal_cursor(query_id, cursor)
        self._raise_confirmed_cancellation_from_detached(cursor, query_id, sqlstate)

    def _raise_confirmed_cancellation_from_detached(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
        sqlstate: str,
    ) -> None:
        confirmation_session_id, confirmation_value = self._confirm_detached_terminal_statement(
            cursor, query_id
        )
        raise MssqlCancellationConfirmedError(
            query_id,
            self._evidence.session_id,
            sqlstate,
            confirmation_session_id,
            confirmation_value,
        )

    def _raise_confirmed_timeout_from_detached(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
        sqlstate: str,
    ) -> None:
        self._confirm_detached_terminal_statement(cursor, query_id)
        raise MssqlQueryTimeoutError(query_id, self._evidence.session_id, sqlstate)

    def _interrupt_and_retire(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
    ) -> _MssqlCancellationEvidence:
        cancel_requested = self._detach_terminal_cursor(query_id, cursor)
        try:
            cursor.cancel()
        except pyodbc.Error as error:
            LOGGER.warning(
                "SQL Server result interruption returned an ODBC diagnostic",
                extra={
                    "query_id": str(query_id),
                    "session_id": self._evidence.session_id,
                    "sqlstate": _sqlstate(error),
                },
            )
        confirmation_session_id, confirmation_value = self._confirm_detached_terminal_statement(
            cursor, query_id
        )
        return _MssqlCancellationEvidence(
            requested=cancel_requested,
            confirmation_session_id=confirmation_session_id,
            confirmation_value=confirmation_value,
        )

    def _raise_raced_cancellation(
        self,
        query_id: UUID,
        evidence: _MssqlCancellationEvidence,
    ) -> None:
        if evidence.requested:
            raise MssqlCancellationConfirmedError(
                query_id,
                self._evidence.session_id,
                "raced-local-failure",
                evidence.confirmation_session_id,
                evidence.confirmation_value,
            )

    def _confirm_detached_terminal_statement(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
    ) -> tuple[int, int]:
        try:
            cursor.close()
            self._connection.timeout = max(
                1,
                math.ceil(self._cancellation_acknowledgement_timeout_seconds),
            )
            confirmation_cursor = self._connection.cursor()
            try:
                confirmation_row = confirmation_cursor.execute(
                    "SELECT CONVERT(int, @@SPID), CONVERT(int, 1)"
                ).fetchone()
            finally:
                confirmation_cursor.close()
            confirmation_session_id, confirmation_value = _validated_confirmation_row(
                confirmation_row
            )
            if confirmation_session_id != self._evidence.session_id:
                raise MssqlCancellationUnconfirmedError(
                    query_id,
                    self._evidence.session_id,
                    "confirmation used a different SQL Server session",
                )
            if confirmation_value != _CONFIRMATION_SENTINEL:
                raise MssqlCancellationUnconfirmedError(
                    query_id,
                    self._evidence.session_id,
                    "confirmation sentinel was not returned",
                )
        except MssqlCancellationUnconfirmedError:
            self._retire_connection_after_terminal_query(query_id)
            raise
        except (pyodbc.Error, MssqlDataValidationError):
            self._retire_connection_after_terminal_query(query_id)
            raise MssqlCancellationUnconfirmedError(
                query_id,
                self._evidence.session_id,
                "same-session completion probe failed",
            ) from None

        self._retire_connection_after_terminal_query(query_id)
        return confirmation_session_id, confirmation_value

    def _detach_terminal_cursor(self, query_id: UUID, cursor: pyodbc.Cursor) -> bool:
        with self._state_changed:
            while self._cancel_calls > 0:
                self._state_changed.wait()
            identity_matches = self._active_query_id == query_id and self._active_cursor is cursor
            if identity_matches:
                cancel_requested = self._cancel_requested
                self._active_cursor = None
                self._state_changed.notify_all()
                return cancel_requested
        self._retire_connection_after_terminal_query(query_id)
        raise MssqlCancellationUnconfirmedError(
            query_id,
            self._evidence.session_id,
            "active statement identity changed before confirmation",
        )

    def _retire_after_query_error(
        self,
        cursor: pyodbc.Cursor | None,
        query_id: UUID,
    ) -> None:
        with self._state_changed:
            if self._active_query_id == query_id:
                self._active_cursor = None
                self._state_changed.notify_all()
        if cursor is not None:
            try:
                cursor.close()
            except pyodbc.Error:
                LOGGER.warning(
                    "SQL Server cursor close failed during query-error retirement",
                    extra={
                        "query_id": str(query_id),
                        "session_id": self._evidence.session_id,
                    },
                )
        self._retire_connection_after_terminal_query(query_id)

    def _close_unpublished_cursor(self, cursor: pyodbc.Cursor, query_id: UUID) -> None:
        try:
            cursor.close()
        except pyodbc.Error:
            LOGGER.warning(
                "SQL Server unpublished cursor close failed",
                extra={
                    "query_id": str(query_id),
                    "session_id": self._evidence.session_id,
                },
            )

    def _retire_connection_after_terminal_query(self, query_id: UUID) -> None:
        with self._state_changed:
            self._clear_active_query_locked()
            self._closed = True
            self._state_changed.notify_all()
        try:
            self._connection.close()
        except pyodbc.Error:
            LOGGER.warning(
                "SQL Server connection close failed during terminal retirement",
                extra={
                    "query_id": str(query_id),
                    "session_id": self._evidence.session_id,
                },
            )

    def _clear_active_query_locked(self) -> None:
        self._active_query_id = None
        self._active_cursor = None
        self._cancel_requested = False

    def _retire_after_setup_error(self) -> None:
        with self._state_changed:
            self._clear_active_query_locked()
            self._closed = True
            self._state_changed.notify_all()
        try:
            self._connection.close()
        except pyodbc.Error:
            LOGGER.warning(
                "SQL Server connection close failed during setup retirement",
                extra={"session_id": self._evidence.session_id},
            )

    def _wait_for_cancellation_acknowledgement_locked(
        self,
        query_id: UUID,
        deadline: float,
    ) -> None:
        while self._active_query_id == query_id and self._active_cursor is not None:
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise self._cancellation_request_timeout(query_id)
            self._state_changed.wait(remaining_seconds)
        if deadline - time.monotonic() <= 0:
            raise self._cancellation_request_timeout(query_id)

    def _query_handle_is_active_locked(self, query_id: UUID) -> bool:
        return self._active_query_id == query_id and self._active_cursor is not None

    def _cancellation_request_timeout(
        self,
        query_id: UUID,
    ) -> MssqlCancellationRequestTimeoutError:
        return MssqlCancellationRequestTimeoutError(
            "SQL Server worker did not acknowledge cancellation before the deadline: "
            f"query_id={query_id}, session_id={self._evidence.session_id}"
        )

    def _require_owner_thread(self) -> None:
        if get_ident() != self._owner_thread_id:
            raise MssqlThreadOwnershipError(
                "SQL Server connection operations must run on the transport owner thread"
            )

    def _require_open(self) -> None:
        with self._state_changed:
            if self._closed:
                raise MssqlTransportClosedError("SQL Server transport is already closed")


class MssqlReadContext:
    """One sequential SQL Server transaction-level SNAPSHOT read context."""

    def __init__(
        self,
        transport: MssqlTransport,
        profile: MssqlServerProfile,
        evidence: MssqlReadContextEvidence,
    ) -> None:
        self._transport = transport
        self._profile = profile
        self._evidence = evidence
        self._state = MssqlReadContextState.ACTIVE
        self._protected_relations: list[MssqlInspectedRelation] = []

    @property
    def profile(self) -> MssqlServerProfile:
        return self._profile

    @property
    def evidence(self) -> MssqlReadContextEvidence:
        return self._evidence

    @property
    def state(self) -> MssqlReadContextState:
        return self._state

    @property
    def protected_relations(self) -> tuple[MssqlInspectedRelation, ...]:
        return tuple(self._protected_relations)

    @property
    def active_query_id(self) -> UUID | None:
        return self._transport.active_query_id

    def cancel(self, query_id: UUID) -> None:
        self._transport.cancel(query_id)

    def inspect_relation(
        self,
        schema: CanonicalSchema,
        relation: MssqlRelation,
        column_names: tuple[str, ...],
        max_metadata_record_bytes: int,
        max_metadata_total_bytes: int,
    ) -> MssqlInspectedRelation:
        self._require_active()
        _validate_inspection_request(
            schema,
            relation,
            column_names,
            max_metadata_record_bytes,
            max_metadata_total_bytes,
        )
        relation_rows = self._execute_metadata(
            _relation_metadata_query(relation),
            1,
            max_metadata_record_bytes,
            max_metadata_total_bytes,
        )
        identity = self._relation_identity(relation, relation_rows)
        column_rows = (
            self._execute_metadata(
                _column_metadata_query(identity[2], column_names),
                len(column_names),
                max_metadata_record_bytes,
                max_metadata_total_bytes,
            )
            if column_names
            else ()
        )
        return self._register_inspection(
            schema,
            relation,
            column_names,
            identity,
            column_rows,
        )

    def inspect_relation_budgeted(
        self,
        schema: CanonicalSchema,
        relation: MssqlRelation,
        column_names: tuple[str, ...],
        max_metadata_record_bytes: int,
        max_metadata_total_bytes: int,
        source_budget: PostgresSourceBudgetAttempt,
        source_direction: PostgresSourceDirection,
        deadline: PostgresReadDeadline,
    ) -> MssqlInspectedRelation:
        self._require_active()
        _validate_inspection_request(
            schema,
            relation,
            column_names,
            max_metadata_record_bytes,
            max_metadata_total_bytes,
        )
        relation_rows = self._execute_metadata_budgeted(
            _relation_metadata_query(relation),
            1,
            max_metadata_record_bytes,
            max_metadata_total_bytes,
            source_budget,
            source_direction,
            deadline,
        )
        identity = self._relation_identity(relation, relation_rows)
        column_rows = (
            self._execute_metadata_budgeted(
                _column_metadata_query(identity[2], column_names),
                len(column_names),
                max_metadata_record_bytes,
                max_metadata_total_bytes,
                source_budget,
                source_direction,
                deadline,
            )
            if column_names
            else ()
        )
        return self._register_inspection(
            schema,
            relation,
            column_names,
            identity,
            column_rows,
        )

    def _relation_identity(
        self,
        relation: MssqlRelation,
        relation_rows: tuple[MssqlRow, ...],
    ) -> tuple[int, int, int]:
        if len(relation_rows) != 1:
            raise MssqlMetadataError(
                "SQL Server relation is missing or not visible to the reader: "
                f"schema={relation.schema_name!r}, table={relation.table_name!r}"
            )
        return _validated_relation_metadata(
            relation_rows[0],
            relation,
            self._profile,
        )

    def _register_inspection(
        self,
        schema: CanonicalSchema,
        relation: MssqlRelation,
        column_names: tuple[str, ...],
        identity: tuple[int, int, int],
        column_rows: tuple[MssqlRow, ...],
    ) -> MssqlInspectedRelation:
        database_id, schema_id, object_id = identity
        if column_names:
            if len(column_rows) != len(column_names):
                raise MssqlMetadataError(
                    "SQL Server catalog did not return one row per requested column: "
                    f"expected={len(column_names)}, actual={len(column_rows)}"
                )
            bindings = tuple(
                _binding_from_metadata_row(field.name, column_name, index, row)
                for index, (field, column_name, row) in enumerate(
                    zip(schema.fields, column_names, column_rows, strict=True)
                )
            )
        else:
            bindings = ()
        inspection = MssqlInspectedRelation(
            context_id=self._evidence.context_id,
            database_id=database_id,
            schema_id=schema_id,
            object_id=object_id,
            relation=relation,
            bindings=bindings,
        )
        validate_mssql_inspection(schema, inspection)
        self._protected_relations.append(inspection)
        return inspection

    def read_canonical_rows(
        self,
        query: MssqlCanonicalQuery,
        limits: MssqlFetchLimits,
    ) -> MssqlReadResult:
        self._require_query(query, MssqlCanonicalResultKind.ROWS)
        raw_result = self._execute_compiled(query, _row_transport_limits(query, limits))
        witnessed_rows = self._validated_witness_rows(query, raw_result.rows)
        if any(not has_data for has_data, _payload in witnessed_rows):
            if len(witnessed_rows) != 1 or witnessed_rows[0][0]:
                self._lose_for_metadata_error(
                    "SQL Server row query returned a malformed empty-relation witness"
                )
            payload_rows: tuple[MssqlRow, ...] = ()
        else:
            payload_rows = tuple(payload for _has_data, payload in witnessed_rows)
        _validate_logical_rows(payload_rows, limits)
        return MssqlReadResult(
            rows=payload_rows,
            metrics=_logical_read_metrics(raw_result.metrics, payload_rows),
        )

    def read_fingerprint(
        self,
        query: MssqlCanonicalQuery,
        limits: MssqlFetchLimits,
    ) -> MssqlReadResult:
        self._require_query(query, MssqlCanonicalResultKind.FINGERPRINT)
        raw_result = self._execute_compiled(query, _summary_transport_limits(query, limits))
        witnessed_rows = self._validated_witness_rows(query, raw_result.rows)
        if len(witnessed_rows) != 1:
            self._lose_for_metadata_error(
                "SQL Server fingerprint query must return exactly one provenance row"
            )
        payload_rows = (witnessed_rows[0][1],)
        _validate_logical_rows(payload_rows, limits)
        return MssqlReadResult(
            rows=payload_rows,
            metrics=_logical_read_metrics(raw_result.metrics, payload_rows),
        )

    def read_key_summary(
        self,
        query: MssqlCanonicalQuery,
        limits: MssqlFetchLimits,
    ) -> MssqlKeySummaryRead:
        self._require_query(query, MssqlCanonicalResultKind.KEY_SUMMARY)
        raw_result = self._execute_compiled(query, _summary_transport_limits(query, limits))
        witnessed_rows = self._validated_witness_rows(query, raw_result.rows)
        if len(witnessed_rows) != 1:
            self._lose_for_metadata_error(
                "SQL Server key-summary query must return exactly one provenance row"
            )
        payload = witnessed_rows[0][1]
        if len(payload) != 6:
            self._lose_for_metadata_error(
                "SQL Server key-summary query returned an unexpected payload shape"
            )
        counts = tuple(
            _require_bounded_integer(value, field_name, 0, (1 << 63) - 1)
            for value, field_name in zip(
                payload,
                (
                    "row_count",
                    "null_key_count",
                    "invalid_key_count",
                    "oversized_key_count",
                    "valid_key_count",
                    "distinct_key_count",
                ),
                strict=True,
            )
        )
        summary = MssqlKeySummary(
            row_count=counts[0],
            null_key_count=counts[1],
            invalid_key_count=counts[2],
            oversized_key_count=counts[3],
            valid_key_count=counts[4],
            distinct_key_count=counts[5],
        )
        payload_rows = (payload,)
        _validate_logical_rows(payload_rows, limits)
        return MssqlKeySummaryRead(
            summary=summary,
            metrics=_logical_read_metrics(raw_result.metrics, payload_rows),
        )

    def read_integer_key_summary(
        self,
        query: MssqlCanonicalQuery,
        limits: MssqlFetchLimits,
        charge: PostgresSourceQueryCharge,
        deadline: PostgresReadDeadline,
    ) -> PostgresIntegerKeySummaryRead:
        self._require_query(query, MssqlCanonicalResultKind.INTEGER_KEY_SUMMARY)
        raw_result = self._execute_compiled_budgeted(
            query,
            _summary_transport_limits(query, limits),
            charge,
            deadline,
        )
        witnessed_rows = self._validated_witness_rows(query, raw_result.rows)
        if len(witnessed_rows) != 1:
            self._lose_for_metadata_error(
                "SQL Server integer-key summary must return one provenance row"
            )
        payload = witnessed_rows[0][1]
        if len(payload) != 8:
            self._lose_for_metadata_error(
                "SQL Server integer-key summary returned an unexpected payload shape"
            )
        counts = tuple(
            _require_bounded_integer(value, field_name, 0, (1 << 63) - 1)
            for value, field_name in zip(
                payload[:5],
                (
                    "row_count",
                    "null_key_count",
                    "invalid_key_count",
                    "valid_key_count",
                    "distinct_key_count",
                ),
                strict=True,
            )
        )
        minimum_key = _require_optional_int64(payload[5], "minimum_key")
        maximum_key = _require_optional_int64(payload[6], "maximum_key")
        usable_access_path = _require_boolean(payload[7], "usable_access_path")
        payload_rows = (payload,)
        _validate_logical_rows(payload_rows, limits)
        metrics = _logical_read_metrics(raw_result.metrics, payload_rows)
        return PostgresIntegerKeySummaryRead(
            summary=PostgresIntegerKeySummary(
                row_count=counts[0],
                null_key_count=counts[1],
                invalid_key_count=counts[2],
                valid_key_count=counts[3],
                distinct_key_count=counts[4],
                minimum_key=minimum_key,
                maximum_key=maximum_key,
                usable_access_path=usable_access_path,
            ),
            metrics=_comparison_read_metrics(metrics),
        )

    def read_integer_range_fingerprints(
        self,
        query: MssqlCanonicalQuery,
        ranges: tuple[MssqlIntegerRangeRequest, ...],
        limits: MssqlFetchLimits,
        charge: PostgresSourceQueryCharge,
        deadline: PostgresReadDeadline,
    ) -> PostgresRangeFingerprintRead:
        self._require_query(query, MssqlCanonicalResultKind.INTEGER_RANGE_FINGERPRINTS)
        raw_result = self._execute_compiled_budgeted(
            query,
            _summary_transport_limits(query, limits),
            charge,
            deadline,
        )
        witnessed_rows = self._validated_witness_rows(query, raw_result.rows)
        if len(witnessed_rows) != len(ranges):
            self._lose_for_metadata_error(
                "SQL Server range fingerprints must return one provenance row per range"
            )
        parsed: list[PostgresRangeFingerprint] = []
        payload_rows: list[MssqlRow] = []
        for index, (range_request, (_has_data, payload)) in enumerate(
            zip(ranges, witnessed_rows, strict=True)
        ):
            if index % _DEADLINE_CHECK_RECORDS == 0:
                _require_mssql_deadline(deadline, "range fingerprint decoding")
            if len(payload) != 14:
                self._lose_for_metadata_error(
                    "SQL Server range fingerprint returned an unexpected payload shape"
                )
            segment_id = _require_ascii_bytes(
                payload[0],
                "range fingerprint segment_id",
            ).decode("ascii")
            if segment_id != range_request.segment_id:
                self._lose_for_metadata_error(
                    "SQL Server range fingerprints changed requested segment order"
                )
            values = tuple(
                _require_unsigned_integer(value, field_name, (1 << 127) - 1)
                for value, field_name in zip(
                    payload[1:],
                    (
                        "valid_row_count",
                        "limb_0",
                        "limb_1",
                        "limb_2",
                        "limb_3",
                        "limb_4",
                        "limb_5",
                        "limb_6",
                        "limb_7",
                        "invalid_row_count",
                        "oversized_row_count",
                        "row_envelope_bytes",
                        "key_envelope_bytes",
                    ),
                    strict=True,
                )
            )
            if values[0] > (1 << 63) - 1:
                raise MssqlDataValidationError(
                    "SQL Server range fingerprint row count exceeds signed INT64"
                )
            if values[9] != 0:
                raise MssqlDataValidationError(
                    "SQL Server range fingerprint found rows outside the logical schema: "
                    f"segment_id={segment_id!r}, invalid_row_count={values[9]}"
                )
            if values[10] != 0:
                raise MssqlResultLimitError(
                    "SQL Server range fingerprint found canonical rows above the configured "
                    f"limit: segment_id={segment_id!r}, oversized_row_count={values[10]}"
                )
            try:
                fingerprint = Fingerprint(
                    count=values[0],
                    limb_sums=(
                        values[1],
                        values[2],
                        values[3],
                        values[4],
                        values[5],
                        values[6],
                        values[7],
                        values[8],
                    ),
                )
            except FingerprintOverflowError as error:
                raise MssqlDataValidationError(
                    "SQL Server range fingerprint exceeded canonical accumulator bounds: "
                    f"segment_id={segment_id!r}, reason_type={type(error).__name__}"
                ) from None
            parsed.append(
                PostgresRangeFingerprint(
                    segment_id=segment_id,
                    fingerprint=fingerprint,
                    row_envelope_bytes=values[11],
                    key_envelope_bytes=values[12],
                )
            )
            payload_rows.append(payload)
        _require_mssql_deadline(deadline, "range fingerprint decoding")
        logical_rows = tuple(payload_rows)
        _validate_logical_rows_before_deadline(
            logical_rows,
            limits,
            deadline,
            "range fingerprint validation",
        )
        return PostgresRangeFingerprintRead(
            ranges=tuple(parsed),
            metrics=_comparison_read_metrics(
                _logical_read_metrics_before_deadline(
                    raw_result.metrics,
                    logical_rows,
                    deadline,
                    "range fingerprint metrics",
                )
            ),
        )

    def read_integer_range_rows(
        self,
        query: MssqlCanonicalQuery,
        ranges: tuple[MssqlIntegerRangeRequest, ...],
        key_field_index: int,
        limits: MssqlFetchLimits,
        charge: PostgresSourceQueryCharge,
        deadline: PostgresReadDeadline,
    ) -> PostgresIntegerExactRowsRead:
        self._require_query(query, MssqlCanonicalResultKind.INTEGER_RANGE_ROWS)
        raw_result = self._execute_compiled_budgeted(
            query,
            _exact_row_transport_limits(query, limits, ranges),
            charge,
            deadline,
        )
        witnessed_rows = self._validated_witness_rows(query, raw_result.rows)
        key_schema = CanonicalSchema(
            protocol=query.schema.protocol,
            fields=(query.schema.fields[key_field_index],),
        )
        key_context = prepare_envelope_context(key_schema)
        parsed: list[PostgresIntegerExactRow] = []
        payload_rows: list[MssqlRow] = []
        range_ordinals = {item.segment_id: index for index, item in enumerate(ranges)}
        previous_ordinal = -1
        previous_key: int | None = None
        for index, (has_data, payload) in enumerate(witnessed_rows):
            if index % _DEADLINE_CHECK_RECORDS == 0:
                _require_mssql_deadline(deadline, "exact-row decoding")
            if len(payload) != 5:
                self._lose_for_metadata_error(
                    "SQL Server exact row returned an unexpected payload shape"
                )
            payload_rows.append(payload)
            if not has_data:
                if any(value is not None for value in payload):
                    self._lose_for_metadata_error(
                        "SQL Server empty exact-range witness contains row payload"
                    )
                continue
            segment_id = _require_ascii_bytes(payload[0], "exact row segment_id").decode("ascii")
            ordinal = range_ordinals.get(segment_id)
            if ordinal is None:
                self._lose_for_metadata_error(
                    "SQL Server exact row references an unrequested segment"
                )
            if ordinal < previous_ordinal:
                raise MssqlDataValidationError(
                    "SQL Server exact rows do not follow requested segment order"
                )
            invalid_row = _require_boolean(payload[3], "exact row invalid_row")
            oversized_row = _require_boolean(payload[4], "exact row oversized_row")
            if invalid_row and oversized_row:
                raise MssqlDataValidationError(
                    "SQL Server exact row statuses must be mutually exclusive"
                )
            if invalid_row:
                raise MssqlDataValidationError(
                    "SQL Server exact range contains a row outside the logical schema"
                )
            if oversized_row:
                raise MssqlResultLimitError(
                    "SQL Server exact range contains a canonical row above the configured limit"
                )
            key_envelope = _require_ascii_bytes(payload[1], "exact row key_envelope")
            row_envelope = _require_ascii_bytes(payload[2], "exact row row_envelope")
            try:
                decoded_key = decode_key_with_context(key_context, key_envelope)
                values = decode_row_with_context(query.context, row_envelope)
            except CanonicalizationError as error:
                raise MssqlDataValidationError(
                    "SQL Server exact row returned a non-canonical envelope: "
                    f"reason_type={type(error).__name__}"
                ) from None
            key_value = decoded_key[0]
            row_key_value = values[key_field_index]
            if type(key_value) is not int or type(row_key_value) is not int:
                raise MssqlDataValidationError(
                    "SQL Server exact row canonical key is not logical INT64"
                )
            if key_value != row_key_value:
                raise MssqlDataValidationError("SQL Server exact key and row envelopes disagree")
            requested_range = ranges[ordinal]
            if key_value < requested_range.lower_inclusive or (
                requested_range.upper_exclusive is not None
                and key_value >= requested_range.upper_exclusive
            ):
                raise MssqlDataValidationError(
                    "SQL Server exact key falls outside its requested range: "
                    f"segment_id={segment_id!r}, key_value={key_value}, "
                    f"lower_inclusive={requested_range.lower_inclusive}, "
                    f"upper_exclusive={requested_range.upper_exclusive!r}"
                )
            if (
                ordinal == previous_ordinal
                and previous_key is not None
                and key_value <= previous_key
            ):
                raise MssqlDataValidationError(
                    "SQL Server exact keys must be strictly increasing within a segment"
                )
            previous_ordinal = ordinal
            previous_key = key_value
            parsed.append(
                PostgresIntegerExactRow(
                    segment_id=segment_id,
                    key_value=key_value,
                    key_envelope=key_envelope,
                    row_envelope=row_envelope,
                    values=values,
                )
            )
        _require_mssql_deadline(deadline, "exact-row decoding")
        logical_rows = tuple(payload_rows)
        _validate_logical_rows_before_deadline(
            logical_rows,
            limits,
            deadline,
            "exact-row validation",
        )
        return PostgresIntegerExactRowsRead(
            rows=tuple(parsed),
            metrics=_exact_read_metrics_before_deadline(
                tuple(parsed),
                deadline,
            ),
        )

    def read_relation_manifest(
        self,
        query: MssqlCanonicalQuery,
        limits: MssqlFetchLimits,
        charge: PostgresSourceQueryCharge,
        deadline: PostgresReadDeadline,
    ) -> tuple[MssqlRelationManifestRecord, ...]:
        self._require_query(query, MssqlCanonicalResultKind.RELATION_MANIFEST)
        raw_result = self._execute_compiled_budgeted(
            query,
            _row_transport_limits(query, limits),
            charge,
            deadline,
        )
        witnessed_rows = self._validated_witness_rows(query, raw_result.rows)
        records: list[MssqlRelationManifestRecord] = []
        for has_data, payload in witnessed_rows:
            if len(payload) != 8:
                self._lose_for_metadata_error(
                    "SQL Server readiness manifest returned an unexpected payload shape"
                )
            if not has_data:
                if any(value is not None for value in payload):
                    self._lose_for_metadata_error(
                        "SQL Server empty readiness witness contains manifest payload"
                    )
                continue
            records.append(_relation_manifest_record(payload))
        if len(records) > 2:
            raise MssqlResultLimitError(
                "SQL Server readiness manifest returned more than two current rows"
            )
        return tuple(records)

    def close(self) -> None:
        if self._state is MssqlReadContextState.CLOSED:
            return
        try:
            if not self._transport.closed:
                self._transport.rollback()
                self._transport.close()
        except MssqlTransportError:
            self._state = MssqlReadContextState.LOST
            raise
        self._state = MssqlReadContextState.CLOSED

    def _execute_metadata(
        self,
        query: MssqlQuery,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[MssqlRow, ...]:
        limits = MssqlFetchLimits(
            fetch_batch_records=1,
            max_records=max_records,
            max_value_bytes=max_record_bytes,
            max_record_bytes=max_record_bytes,
            max_total_bytes=max_total_bytes,
            max_declared_value_bytes=max_record_bytes,
            max_declared_record_bytes=max_record_bytes,
        )
        try:
            return self._transport.execute_bounded(query, limits).rows
        except MssqlTransportError:
            self._state = MssqlReadContextState.LOST
            raise

    def _execute_metadata_budgeted(
        self,
        query: MssqlQuery,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        source_budget: PostgresSourceBudgetAttempt,
        source_direction: PostgresSourceDirection,
        deadline: PostgresReadDeadline,
    ) -> tuple[MssqlRow, ...]:
        limits = MssqlFetchLimits(
            fetch_batch_records=1,
            max_records=max_records,
            max_value_bytes=max_record_bytes,
            max_record_bytes=max_record_bytes,
            max_total_bytes=max_total_bytes,
            max_declared_value_bytes=max_record_bytes,
            max_declared_record_bytes=max_record_bytes,
        )
        try:
            charge = source_budget.dispatch_query(source_direction, 0)
            return self._transport.execute_budgeted(
                query,
                limits,
                charge,
                deadline,
            ).rows
        except (
            MssqlTransportError,
            PostgresReadDeadlineExceededError,
            PostgresSourceBudgetExceededError,
        ):
            self._state = MssqlReadContextState.LOST
            raise

    def _execute_compiled(
        self,
        query: MssqlCanonicalQuery,
        limits: MssqlFetchLimits,
    ) -> MssqlReadResult:
        try:
            return self._transport.execute_bounded(
                MssqlQuery(
                    query_id=uuid4(),
                    statement=query.statement,
                    parameters=query.parameters,
                ),
                limits,
            )
        except MssqlTransportError:
            self._state = MssqlReadContextState.LOST
            raise

    def _execute_compiled_budgeted(
        self,
        query: MssqlCanonicalQuery,
        limits: MssqlFetchLimits,
        charge: PostgresSourceQueryCharge,
        deadline: PostgresReadDeadline,
    ) -> MssqlReadResult:
        try:
            return self._transport.execute_budgeted(
                MssqlQuery(
                    query_id=uuid4(),
                    statement=query.statement,
                    parameters=query.parameters,
                ),
                limits,
                charge,
                deadline,
            )
        except (
            MssqlTransportError,
            PostgresReadDeadlineExceededError,
            PostgresSourceBudgetExceededError,
        ):
            self._state = MssqlReadContextState.LOST
            raise

    def _validated_witness_rows(
        self,
        query: MssqlCanonicalQuery,
        rows: tuple[MssqlRow, ...],
    ) -> tuple[tuple[bool, MssqlRow], ...]:
        if not rows:
            self._lose_for_metadata_error(
                "SQL Server compiled query returned no physical provenance witness"
            )
        inspection = query.inspection
        expected_identity = (
            inspection.database_id,
            inspection.schema_id,
            inspection.object_id,
            *(binding.column_id for binding in inspection.bindings),
        )
        prefix_fields = len(expected_identity) + 1
        witnessed: list[tuple[bool, MssqlRow]] = []
        for row_index, row in enumerate(rows):
            if len(row) < prefix_fields:
                self._lose_for_metadata_error(
                    "SQL Server compiled query omitted physical provenance fields: "
                    f"row_index={row_index}"
                )
            identity = row[: len(expected_identity)]
            has_data = row[len(expected_identity)]
            if identity != expected_identity:
                self._lose_for_metadata_error(
                    "SQL Server compiled query physical provenance changed: "
                    f"row_index={row_index}, expected_identity={expected_identity!r}, "
                    f"actual_identity={identity!r}"
                )
            if type(has_data) is not bool:
                self._lose_for_metadata_error(
                    "SQL Server compiled query returned an invalid data-presence witness: "
                    f"row_index={row_index}, actual_type={type(has_data).__name__}"
                )
            witnessed.append((has_data, row[prefix_fields:]))
        return tuple(witnessed)

    def _require_query(
        self,
        query: MssqlCanonicalQuery,
        expected_kind: MssqlCanonicalResultKind,
    ) -> None:
        self._require_active()
        if type(query) is not MssqlCanonicalQuery:
            raise TypeError("query must be MssqlCanonicalQuery")
        if query.result_kind is not expected_kind:
            raise MssqlQueryContextError(
                "SQL Server compiled query has the wrong result kind: "
                f"expected={expected_kind.value!r}, actual={query.result_kind.value!r}"
            )
        if query.inspection.context_id != self._evidence.context_id:
            raise MssqlQueryContextError(
                "SQL Server compiled query belongs to a different read context: "
                f"query_context_id={query.inspection.context_id}, "
                f"active_context_id={self._evidence.context_id}"
            )

    def _require_active(self) -> None:
        if self._state is MssqlReadContextState.CLOSED:
            raise MssqlContextClosedError("SQL Server read context is already closed")
        if self._state is MssqlReadContextState.LOST:
            raise MssqlContextLostError("SQL Server read context was lost and cannot be reused")

    def _lose_for_metadata_error(self, message: str) -> NoReturn:
        self._state = MssqlReadContextState.LOST
        if not self._transport.closed:
            self._transport.rollback()
            self._transport.close()
        raise MssqlMetadataError(message)


class MssqlProtectedReadContext:
    """A catalog-bound SQL Server SNAPSHOT context charged to one run budget."""

    def __init__(
        self,
        read_context: MssqlReadContext,
        acquisitions: tuple[MssqlRelationAcquisition, ...],
        source_budget: PostgresSourceBudgetAttempt,
        source_direction: PostgresSourceDirection,
    ) -> None:
        if len(acquisitions) != len(read_context.protected_relations):
            raise ValueError(
                "SQL Server protected context acquisitions and inspections differ in count"
            )
        self._read_context = read_context
        self._acquisitions = acquisitions
        self._source_budget = source_budget
        self._source_direction = source_direction
        for acquisition, inspection in zip(
            acquisitions, read_context.protected_relations, strict=True
        ):
            if acquisition.relation != inspection.relation:
                raise ValueError("SQL Server protected acquisition and inspection relations differ")

    @property
    def profile(self) -> MssqlServerProfile:
        return self._read_context.profile

    @property
    def evidence(self) -> MssqlReadContextEvidence:
        return self._read_context.evidence

    @property
    def state(self) -> MssqlReadContextState:
        return self._read_context.state

    @property
    def protected_relations(self) -> tuple[MssqlInspectedRelation, ...]:
        return self._read_context.protected_relations

    @property
    def source_budget(self) -> PostgresSourceBudgetAttempt:
        return self._source_budget

    @property
    def source_direction(self) -> PostgresSourceDirection:
        return self._source_direction

    @property
    def active_query_id(self) -> UUID | None:
        return self._read_context.active_query_id

    def cancel(self, query_id: UUID) -> None:
        self._read_context.cancel(query_id)

    def read_integer_key_summary(
        self,
        protected_relation: MssqlInspectedRelation,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        max_encoded_envelope_bytes: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresIntegerKeySummaryRead:
        acquisition = self._acquisition(protected_relation)
        _require_mssql_deadline(deadline, "integer-key summary")
        if full_scans != 1:
            raise MssqlDataValidationError(
                "SQL Server integer-key summary requires exactly one physical scan"
            )
        query = build_mssql_integer_key_summary_query(
            acquisition.schema,
            protected_relation,
            key_field_index,
            _mssql_scope(scope),
            max_encoded_envelope_bytes,
        )
        charge = self._source_budget.dispatch_query(self._source_direction, full_scans)
        result = self._read_context.read_integer_key_summary(
            query,
            _mssql_fetch_limits(1, max_record_bytes, max_total_bytes),
            charge,
            deadline,
        )
        _require_mssql_deadline(deadline, "integer-key summary")
        return result

    def read_integer_range_fingerprints(
        self,
        protected_relation: MssqlInspectedRelation,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresRangeFingerprintRead:
        acquisition = self._acquisition(protected_relation)
        mssql_ranges = _mssql_ranges(ranges)
        _require_mssql_deadline(deadline, "integer-range fingerprint")
        if full_scans != len(mssql_ranges):
            raise MssqlDataValidationError(
                "SQL Server range fingerprint scan reservation differs from its ranges"
            )
        query = build_mssql_integer_range_fingerprint_query(
            acquisition.schema,
            protected_relation,
            key_field_index,
            _mssql_scope(scope),
            mssql_ranges,
            max_encoded_envelope_bytes,
        )
        charge = self._source_budget.dispatch_query(self._source_direction, full_scans)
        result = self._read_context.read_integer_range_fingerprints(
            query,
            mssql_ranges,
            _mssql_fetch_limits(len(mssql_ranges), max_record_bytes, max_total_bytes),
            charge,
            deadline,
        )
        _require_mssql_deadline(deadline, "integer-range fingerprint")
        return result

    def read_integer_range_rows(
        self,
        protected_relation: MssqlInspectedRelation,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresIntegerExactRowsRead:
        acquisition = self._acquisition(protected_relation)
        mssql_ranges = _mssql_ranges(ranges)
        _require_mssql_deadline(deadline, "integer-range exact read")
        if full_scans != len(mssql_ranges):
            raise MssqlDataValidationError(
                "SQL Server exact-range scan reservation differs from its ranges"
            )
        query = build_mssql_integer_range_rows_query(
            acquisition.schema,
            protected_relation,
            key_field_index,
            _mssql_scope(scope),
            mssql_ranges,
            max_encoded_envelope_bytes,
        )
        charge = self._source_budget.dispatch_query(self._source_direction, full_scans)
        result = self._read_context.read_integer_range_rows(
            query,
            mssql_ranges,
            key_field_index,
            _mssql_fetch_limits(max_records, max_record_bytes, max_total_bytes),
            charge,
            deadline,
        )
        _require_mssql_deadline(deadline, "integer-range exact read")
        return result

    def read_relation_manifest(
        self,
        protected_relation: MssqlInspectedRelation,
        columns: ReadinessManifestColumns,
        dataset_id: str,
        scope_digest: str,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[MssqlRelationManifestRecord, ...]:
        acquisition = self._acquisition(protected_relation)
        if acquisition.column_names != columns.values():
            raise MssqlQueryContextError(
                "SQL Server readiness columns differ from the protected acquisition"
            )
        query = build_mssql_relation_manifest_query(
            acquisition.schema,
            protected_relation,
            dataset_id,
            scope_digest,
            max_record_bytes,
        )
        deadline = _mssql_source_deadline(self._source_budget)
        charge = self._source_budget.dispatch_query(self._source_direction, 0)
        result = self._read_context.read_relation_manifest(
            query,
            _mssql_fetch_limits(2, max_record_bytes, max_total_bytes),
            charge,
            deadline,
        )
        _require_mssql_deadline(deadline, "relation manifest")
        return result

    def close(self) -> None:
        self._read_context.close()

    def _acquisition(
        self,
        protected_relation: MssqlInspectedRelation,
    ) -> MssqlRelationAcquisition:
        matches = tuple(
            acquisition
            for acquisition, inspection in zip(
                self._acquisitions,
                self._read_context.protected_relations,
                strict=True,
            )
            if inspection is protected_relation
        )
        if len(matches) != 1:
            raise MssqlQueryContextError(
                "SQL Server protected relation does not belong to this exact context"
            )
        return matches[0]


def open_mssql_protected_read_context(
    settings: MssqlConnectionSettings,
    retry_policy: MssqlRetryPolicy,
    acquisitions: tuple[MssqlRelationAcquisition, ...],
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> MssqlProtectedReadContext:
    if type(acquisitions) is not tuple or not acquisitions:
        raise ValueError(
            "SQL Server protected context requires a non-empty immutable acquisition set"
        )
    if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
        raise TypeError("SQL Server protected context requires PostgresSourceBudgetAttempt")
    if not isinstance(cast(object, source_direction), PostgresSourceDirection):
        raise TypeError("SQL Server protected context requires PostgresSourceDirection")
    for acquisition in acquisitions:
        if type(acquisition) is not MssqlRelationAcquisition:
            raise TypeError(
                "SQL Server protected acquisitions must contain MssqlRelationAcquisition"
            )
    if len({item.relation for item in acquisitions}) != len(acquisitions):
        raise ValueError("SQL Server protected acquisitions must reference distinct relations")

    context = _open_mssql_read_context_budgeted(
        settings,
        retry_policy,
        source_budget,
        source_direction,
    )
    try:
        for acquisition in acquisitions:
            context.inspect_relation_budgeted(
                acquisition.schema,
                acquisition.relation,
                acquisition.column_names,
                acquisition.max_metadata_record_bytes,
                acquisition.max_metadata_total_bytes,
                source_budget,
                source_direction,
                _mssql_source_deadline(source_budget),
            )
    except (MssqlMetadataError, MssqlLoweringError) as error:
        context.close()
        message = str(error).strip()
        if not message:
            raise MssqlDataValidationError(
                "SQL Server relation inspection failed without an actionable explanation"
            ) from error
        raise UnsupportedMssqlRelationError(message) from error
    except (
        MssqlTransportError,
        PostgresReadDeadlineExceededError,
        PostgresSourceBudgetExceededError,
        TypeError,
        ValueError,
    ):
        context.close()
        raise
    return MssqlProtectedReadContext(
        context,
        acquisitions,
        source_budget,
        source_direction,
    )


def _open_mssql_read_context_budgeted(
    settings: MssqlConnectionSettings,
    retry_policy: MssqlRetryPolicy,
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> MssqlReadContext:
    if type(settings) is not MssqlConnectionSettings:
        raise TypeError("settings must be MssqlConnectionSettings")
    if type(retry_policy) is not MssqlRetryPolicy:
        raise TypeError("retry_policy must be MssqlRetryPolicy")
    transport = _open_mssql_transport_budgeted(
        settings,
        retry_policy,
        source_budget,
        source_direction,
    )
    try:
        profile_deadline = _mssql_source_deadline(source_budget)
        profile_charge = source_budget.dispatch_query(source_direction, 0)
        profile_result = transport.execute_budgeted(
            MssqlQuery(
                query_id=uuid4(),
                statement=_profile_query(),
                parameters=(),
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=1_024,
                max_record_bytes=8_192,
                max_total_bytes=8_192,
                max_declared_value_bytes=1_024,
                max_declared_record_bytes=8_192,
            ),
            profile_charge,
            profile_deadline,
        )
        if len(profile_result.rows) != 1:
            raise MssqlDataValidationError(
                "SQL Server capability probe must return exactly one row"
            )
        profile = _server_profile_from_row(transport.evidence, profile_result.rows[0])
        _validate_server_profile(profile)
        started_at = datetime.now(UTC)
        transport.configure_snapshot_transaction()
        snapshot_deadline = _mssql_source_deadline(source_budget)
        snapshot_charge = source_budget.dispatch_query(source_direction, 0)
        snapshot_result = transport.execute_budgeted(
            MssqlQuery(
                query_id=uuid4(),
                statement=_snapshot_transaction_query(),
                parameters=(),
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=64,
                max_record_bytes=1_024,
                max_total_bytes=1_024,
                max_declared_value_bytes=64,
                max_declared_record_bytes=1_024,
            ),
            snapshot_charge,
            snapshot_deadline,
        )
        if len(snapshot_result.rows) != 1:
            raise MssqlDataValidationError(
                "SQL Server SNAPSHOT transaction probe must return exactly one row"
            )
        evidence = _read_context_evidence_from_row(
            profile,
            snapshot_result.rows[0],
            started_at,
        )
    except (
        MssqlTransportError,
        PostgresReadDeadlineExceededError,
        PostgresSourceBudgetExceededError,
    ):
        _close_opening_transport(transport)
        raise
    return MssqlReadContext(transport, profile, evidence)


def open_mssql_read_context(
    settings: MssqlConnectionSettings,
    retry_policy: MssqlRetryPolicy,
) -> MssqlReadContext:
    if type(settings) is not MssqlConnectionSettings:
        raise TypeError("settings must be MssqlConnectionSettings")
    if type(retry_policy) is not MssqlRetryPolicy:
        raise TypeError("retry_policy must be MssqlRetryPolicy")
    transport = open_mssql_transport(settings, retry_policy)
    try:
        profile_result = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=_profile_query(),
                parameters=(),
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=1_024,
                max_record_bytes=8_192,
                max_total_bytes=8_192,
                max_declared_value_bytes=1_024,
                max_declared_record_bytes=8_192,
            ),
        )
        if len(profile_result.rows) != 1:
            raise MssqlDataValidationError(
                "SQL Server capability probe must return exactly one row"
            )
        profile = _server_profile_from_row(transport.evidence, profile_result.rows[0])
        _validate_server_profile(profile)
        started_at = datetime.now(UTC)
        transport.configure_snapshot_transaction()
        snapshot_result = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=_snapshot_transaction_query(),
                parameters=(),
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=64,
                max_record_bytes=1_024,
                max_total_bytes=1_024,
                max_declared_value_bytes=64,
                max_declared_record_bytes=1_024,
            ),
        )
        if len(snapshot_result.rows) != 1:
            raise MssqlDataValidationError(
                "SQL Server SNAPSHOT transaction probe must return exactly one row"
            )
        evidence = _read_context_evidence_from_row(
            profile,
            snapshot_result.rows[0],
            started_at,
        )
    except MssqlTransportError:
        _close_opening_transport(transport)
        raise
    return MssqlReadContext(transport, profile, evidence)


def open_mssql_transport(
    settings: MssqlConnectionSettings,
    retry_policy: MssqlRetryPolicy,
) -> MssqlTransport:
    if type(settings) is not MssqlConnectionSettings:
        raise TypeError("settings must be MssqlConnectionSettings")
    if type(retry_policy) is not MssqlRetryPolicy:
        raise TypeError("retry_policy must be MssqlRetryPolicy")

    last_error: MssqlConnectionError | None = None
    for attempt_number in range(1, retry_policy.max_attempts + 1):
        try:
            return _open_mssql_transport_once(settings)
        except MssqlConnectionError as error:
            last_error = error
            if attempt_number == retry_policy.max_attempts:
                break
            LOGGER.warning(
                "SQL Server connection attempt failed",
                extra={
                    "attempt_number": attempt_number,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "database": settings.database,
                    "user": settings.user,
                },
            )
            time.sleep(retry_policy.delay_seconds)

    if last_error is None:
        raise AssertionError("SQL Server connection retry loop did not execute")
    raise last_error


def _open_mssql_transport_budgeted(
    settings: MssqlConnectionSettings,
    retry_policy: MssqlRetryPolicy,
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> MssqlTransport:
    last_error: MssqlConnectionError | None = None
    for attempt_number in range(1, retry_policy.max_attempts + 1):
        _require_source_budget_deadline(source_budget, "connection attempt")
        try:
            return _open_mssql_transport_once_budgeted(
                settings,
                source_budget,
                source_direction,
            )
        except MssqlConnectionError as error:
            last_error = error
            if attempt_number == retry_policy.max_attempts:
                break
            LOGGER.warning(
                "SQL Server protected connection attempt failed",
                extra={
                    "attempt_number": attempt_number,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "database": settings.database,
                    "user": settings.user,
                },
            )
            _sleep_mssql_retry_delay(
                retry_policy.delay_seconds,
                source_budget,
            )

    if last_error is None:
        raise AssertionError("SQL Server protected connection retry loop did not execute")
    raise last_error


def _profile_query() -> str:
    return (
        "SELECT CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')), "
        "TRY_CONVERT(int, SERVERPROPERTY(N'ProductMajorVersion')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductBuild')), "
        "TRY_CONVERT(int, SERVERPROPERTY(N'EngineEdition')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'Edition')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductLevel')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateLevel')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateReference')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'Collation')), "
        "CONVERT(int, DB_ID()), CONVERT(nvarchar(128), DB_NAME()), "
        "CONVERT(int, [dfe_database].[compatibility_level]), "
        "CONVERT(nvarchar(128), [dfe_database].[collation_name]), "
        "CONVERT(int, [dfe_database].[snapshot_isolation_state]), "
        "CONVERT(nvarchar(60), [dfe_database].[snapshot_isolation_state_desc]), "
        "CONVERT(bit, [dfe_database].[is_read_committed_snapshot_on]), "
        "CONVERT(bit, [dfe_database].[is_read_only]), "
        "CONVERT(nvarchar(128), DATABASEPROPERTYEX(DB_NAME(), N'Updateability')), "
        "TRY_CONVERT(int, COLLATIONPROPERTY("
        f"N'{_CANONICAL_UTF8_COLLATION}', N'CodePage')), "
        "CONVERT(bit, HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'VIEW DEFINITION')) "
        "FROM sys.databases AS [dfe_database] "
        "WHERE [dfe_database].[database_id] = DB_ID()"
    )


def _snapshot_transaction_query() -> str:
    return (
        "SELECT CONVERT(int, DB_ID()), "
        "CONVERT(int, [dfe_database].[compatibility_level]), "
        "CONVERT(int, [dfe_database].[snapshot_isolation_state]), "
        "CONVERT(bit, [dfe_database].[is_read_committed_snapshot_on]), "
        "CONVERT(int, @@SPID), CONVERT(int, @@TRANCOUNT), "
        "CONVERT(int, XACT_STATE()), "
        "CONVERT(int, [dfe_session].[transaction_isolation_level]), "
        "CONVERT(int, [dfe_session].[open_transaction_count]), "
        "(SELECT COUNT_BIG(*) FROM GENERATE_SERIES("
        "CONVERT(bigint, 1), CONVERT(bigint, 1), CONVERT(bigint, 1))) "
        "FROM sys.databases AS [dfe_database] "
        "JOIN sys.dm_exec_sessions AS [dfe_session] "
        "ON [dfe_session].[session_id] = @@SPID "
        "WHERE [dfe_database].[database_id] = DB_ID()"
    )


def _server_profile_from_row(
    driver: MssqlDriverEvidence,
    row: MssqlRow,
) -> MssqlServerProfile:
    if len(row) != 20:
        raise MssqlDataValidationError(
            "SQL Server capability probe returned an unexpected field count: "
            f"expected=20, actual={len(row)}"
        )
    return MssqlServerProfile(
        driver=driver,
        product_version=_require_text(row[0], "product_version"),
        product_major_version=_require_bounded_integer(
            row[1], "product_major_version", 1, INT32_MAX
        ),
        product_build=_require_text(row[2], "product_build"),
        engine_edition=_require_bounded_integer(row[3], "engine_edition", 1, INT32_MAX),
        edition=_require_text(row[4], "edition"),
        product_level=_require_text(row[5], "product_level"),
        product_update_level=_require_optional_text(row[6], "product_update_level"),
        product_update_reference=_require_optional_text(row[7], "product_update_reference"),
        server_collation=_require_text(row[8], "server_collation"),
        database_id=_require_bounded_integer(row[9], "database_id", 1, INT32_MAX),
        database_name=_require_text(row[10], "database_name"),
        compatibility_level=_require_bounded_integer(row[11], "compatibility_level", 1, INT32_MAX),
        database_collation=_require_text(row[12], "database_collation"),
        snapshot_isolation_state=_require_bounded_integer(
            row[13], "snapshot_isolation_state", 0, 3
        ),
        snapshot_isolation_state_description=_require_text(
            row[14], "snapshot_isolation_state_desc"
        ),
        read_committed_snapshot=_require_boolean(row[15], "is_read_committed_snapshot_on"),
        database_read_only=_require_boolean(row[16], "is_read_only"),
        database_updateability=_require_text(row[17], "database_updateability"),
        canonical_utf8_code_page=_require_bounded_integer(
            row[18], "canonical_utf8_code_page", 1, INT32_MAX
        ),
        can_view_definition=_require_boolean(row[19], "can_view_definition"),
    )


def _validate_server_profile(profile: MssqlServerProfile) -> None:
    failures: list[str] = []
    if profile.product_major_version != 16:
        failures.append(f"product_major_version={profile.product_major_version}, required=16")
    if profile.engine_edition not in (2, 3, 4):
        failures.append(f"engine_edition={profile.engine_edition}, required one of 2,3,4")
    if profile.compatibility_level != 160:
        failures.append(f"compatibility_level={profile.compatibility_level}, required=160")
    if (
        profile.snapshot_isolation_state != 1
        or profile.snapshot_isolation_state_description != "ON"
    ):
        failures.append(
            "ALLOW_SNAPSHOT_ISOLATION is not ON: "
            f"snapshot_isolation_state={profile.snapshot_isolation_state}, "
            f"snapshot_isolation_state_desc="
            f"{profile.snapshot_isolation_state_description!r}, "
            f"read_committed_snapshot={profile.read_committed_snapshot}"
        )
    if profile.canonical_utf8_code_page != 65_001:
        failures.append(
            "canonical UTF-8 collation is unavailable: "
            f"code_page={profile.canonical_utf8_code_page}, required=65001"
        )
    if not profile.can_view_definition:
        failures.append(
            "reader lacks database VIEW DEFINITION required to prove complete "
            "row-level-security absence"
        )
    if profile.product_version != profile.driver.server_version:
        failures.append(
            "driver and capability probes disagree on server version: "
            f"driver={profile.driver.server_version!r}, "
            f"capability={profile.product_version!r}"
        )
    if failures:
        raise UnsupportedMssqlProfileError(
            "SQL Server 2022 capability profile is unsupported: "
            f"database={profile.database_name!r}, database_id={profile.database_id}; "
            + "; ".join(failures)
        )


def _read_context_evidence_from_row(
    profile: MssqlServerProfile,
    row: MssqlRow,
    started_at: datetime,
) -> MssqlReadContextEvidence:
    if len(row) != 10:
        raise MssqlDataValidationError(
            "SQL Server SNAPSHOT transaction probe returned an unexpected field count: "
            f"expected=10, actual={len(row)}"
        )
    database_id = _require_bounded_integer(row[0], "database_id", 1, INT32_MAX)
    compatibility_level = _require_bounded_integer(row[1], "compatibility_level", 1, INT32_MAX)
    snapshot_isolation_state = _require_bounded_integer(row[2], "snapshot_isolation_state", 0, 3)
    read_committed_snapshot = _require_boolean(row[3], "is_read_committed_snapshot_on")
    session_id = _require_bounded_integer(row[4], "session_id", 1, INT32_MAX)
    transaction_count = _require_bounded_integer(row[5], "transaction_count", 0, INT32_MAX)
    transaction_state = _require_integer(row[6], "transaction_state")
    transaction_isolation_level = _require_bounded_integer(
        row[7], "transaction_isolation_level", 0, 5
    )
    open_transaction_count = _require_bounded_integer(
        row[8], "open_transaction_count", 0, INT32_MAX
    )
    generated_count = _require_bounded_integer(row[9], "GENERATE_SERIES count", 0, (1 << 63) - 1)
    failures: list[str] = []
    if database_id != profile.database_id:
        failures.append(f"database_id={database_id}, profiled_database_id={profile.database_id}")
    if compatibility_level != profile.compatibility_level:
        failures.append(
            "compatibility level changed before SNAPSHOT: "
            f"profiled={profile.compatibility_level}, active={compatibility_level}"
        )
    if snapshot_isolation_state != 1:
        failures.append(f"snapshot_isolation_state={snapshot_isolation_state}, required=1")
    if read_committed_snapshot != profile.read_committed_snapshot:
        failures.append(
            "RCSI setting changed before SNAPSHOT: "
            f"profiled={profile.read_committed_snapshot}, active={read_committed_snapshot}"
        )
    if session_id != profile.driver.session_id:
        failures.append(f"session_id={session_id}, expected={profile.driver.session_id}")
    if transaction_count != 1:
        failures.append(f"transaction_count={transaction_count}, required=1")
    if transaction_state != 1:
        failures.append(f"transaction_state={transaction_state}, required=1")
    if transaction_isolation_level != 5:
        failures.append(f"transaction_isolation_level={transaction_isolation_level}, required=5")
    if open_transaction_count < 1:
        failures.append(f"open_transaction_count={open_transaction_count}, required>=1")
    if generated_count != 1:
        failures.append(f"GENERATE_SERIES count={generated_count}, required=1")
    if failures:
        raise UnsupportedMssqlProfileError(
            "SQL Server transaction-level SNAPSHOT proof failed: " + "; ".join(failures)
        )
    return MssqlReadContextEvidence(
        context_id=uuid4(),
        engine="mssql",
        server_version=profile.product_version,
        strategy="transaction_snapshot",
        snapshot_locator=None,
        started_at=started_at,
        session_id=session_id,
        database_id=database_id,
        transaction_count=transaction_count,
        transaction_state=transaction_state,
        transaction_isolation_level=transaction_isolation_level,
        allowed_concurrency=1,
        limitations=(
            "the SNAPSHOT transaction cannot be reopened after this context closes",
            "restricted readers do not require server-state DMV privileges",
            "SQL Server metadata is not versioned and any provenance drift fails the context",
            "one active query is allowed on this connection",
        ),
    )


def _close_opening_transport(transport: MssqlTransport) -> None:
    if transport.closed:
        return
    transport.rollback()
    transport.close()


def _validate_inspection_request(
    schema: CanonicalSchema,
    relation: MssqlRelation,
    column_names: tuple[str, ...],
    max_metadata_record_bytes: int,
    max_metadata_total_bytes: int,
) -> None:
    if not isinstance(cast(object, schema), CanonicalSchema):
        raise TypeError("schema must be CanonicalSchema")
    if type(relation) is not MssqlRelation:
        raise TypeError("relation must be MssqlRelation")
    if type(column_names) is not tuple or not all(
        type(column_name) is str for column_name in column_names
    ):
        raise TypeError("column_names must be an immutable tuple of text values")
    if len(column_names) != len(schema.fields):
        raise MssqlMetadataError(
            "SQL Server requested column count does not match the logical schema: "
            f"columns={len(column_names)}, fields={len(schema.fields)}"
        )
    if len(column_names) > MAX_COMPILED_RELATION_MEMBERS:
        raise MssqlMetadataError(
            "SQL Server requested column count exceeds the executable profile limit: "
            f"columns={len(column_names)}, maximum={MAX_COMPILED_RELATION_MEMBERS}"
        )
    if len(set(column_names)) != len(column_names):
        raise MssqlMetadataError("SQL Server requested column names must be unique")
    for index, column_name in enumerate(column_names):
        _validate_catalog_identifier(column_name, f"column_names[{index}]")
    if type(max_metadata_record_bytes) is not int or max_metadata_record_bytes < 1:
        raise ValueError("max_metadata_record_bytes must be a positive integer")
    if type(max_metadata_total_bytes) is not int or max_metadata_total_bytes < 1:
        raise ValueError("max_metadata_total_bytes must be a positive integer")
    if max_metadata_record_bytes > max_metadata_total_bytes:
        raise ValueError("max_metadata_record_bytes must not exceed max_metadata_total_bytes")


def _relation_metadata_query(relation: MssqlRelation) -> MssqlQuery:
    securable = "QUOTENAME([dfe_schema].[name]) + N'.' + QUOTENAME([dfe_table].[name])"
    statement = (
        "SELECT CONVERT(int, DB_ID()), CONVERT(nvarchar(128), DB_NAME()), "
        "CONVERT(int, [dfe_schema].[schema_id]), "
        "CONVERT(nvarchar(128), [dfe_schema].[name]), "
        "CONVERT(int, [dfe_table].[object_id]), "
        "CONVERT(nvarchar(128), [dfe_table].[name]), "
        "CONVERT(nvarchar(2), RTRIM([dfe_table].[type])), "
        "CONVERT(bit, [dfe_table].[is_ms_shipped]), "
        "CONVERT(bit, [dfe_table].[is_memory_optimized]), "
        "CONVERT(int, [dfe_table].[temporal_type]), "
        "CONVERT(bit, [dfe_table].[is_external]), "
        "CONVERT(int, [dfe_table].[ledger_type]), "
        "CONVERT(bit, [dfe_table].[is_node]), CONVERT(bit, [dfe_table].[is_edge]), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'SELECT')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'INSERT')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'UPDATE')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'DELETE')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'ALTER')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'CONTROL')), "
        "CONVERT(bit, CASE WHEN EXISTS ("
        "SELECT 1 FROM sys.columns AS [dfe_writable_column] "
        "WHERE [dfe_writable_column].[object_id] = [dfe_table].[object_id] "
        f"AND HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'UPDATE', "
        "[dfe_writable_column].[name], N'COLUMN') = 1) THEN 1 ELSE 0 END), "
        "CONVERT(bit, HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'VIEW DEFINITION')), "
        "CONVERT(bit, CASE WHEN EXISTS ("
        "SELECT 1 FROM sys.security_predicates AS [dfe_predicate] "
        "JOIN sys.security_policies AS [dfe_policy] "
        "ON [dfe_policy].[object_id] = [dfe_predicate].[object_id] "
        "WHERE [dfe_predicate].[target_object_id] = [dfe_table].[object_id] "
        "AND [dfe_policy].[is_enabled] = 1) THEN 1 ELSE 0 END) "
        "FROM sys.schemas AS [dfe_schema] "
        "JOIN sys.tables AS [dfe_table] "
        "ON [dfe_table].[schema_id] = [dfe_schema].[schema_id] "
        "WHERE [dfe_schema].[name] = ? AND [dfe_table].[name] = ?"
    )
    return MssqlQuery(
        query_id=uuid4(),
        statement=statement,
        parameters=(relation.schema_name, relation.table_name),
    )


def _validated_relation_metadata(
    row: MssqlRow,
    relation: MssqlRelation,
    profile: MssqlServerProfile,
) -> tuple[int, int, int]:
    if len(row) != 23:
        raise MssqlDataValidationError(
            "SQL Server relation catalog probe returned an unexpected field count: "
            f"expected=23, actual={len(row)}"
        )
    database_id = _require_bounded_integer(row[0], "database_id", 1, INT32_MAX)
    database_name = _require_text(row[1], "database_name")
    schema_id = _require_bounded_integer(row[2], "schema_id", 1, INT32_MAX)
    schema_name = _require_text(row[3], "schema_name")
    object_id = _require_bounded_integer(row[4], "object_id", 1, INT32_MAX)
    table_name = _require_text(row[5], "table_name")
    table_type = _require_text(row[6], "table_type")
    is_ms_shipped = _require_boolean(row[7], "is_ms_shipped")
    is_memory_optimized = _require_boolean(row[8], "is_memory_optimized")
    temporal_type = _require_bounded_integer(row[9], "temporal_type", 0, INT32_MAX)
    is_external = _require_boolean(row[10], "is_external")
    ledger_type = _require_bounded_integer(row[11], "ledger_type", 0, INT32_MAX)
    is_node = _require_boolean(row[12], "is_node")
    is_edge = _require_boolean(row[13], "is_edge")
    permissions = tuple(
        _require_bounded_integer(value, name, 0, 1)
        for value, name in zip(
            row[14:20],
            ("SELECT", "INSERT", "UPDATE", "DELETE", "ALTER", "CONTROL"),
            strict=True,
        )
    )
    has_column_update = _require_boolean(row[20], "has_column_update")
    can_view_definition = _require_boolean(row[21], "can_view_definition")
    has_enabled_security_policy = _require_boolean(row[22], "has_enabled_security_policy")
    failures: list[str] = []
    if database_id != profile.database_id or database_name != profile.database_name:
        failures.append(
            "database identity differs from the active read context: "
            f"actual=({database_id}, {database_name!r}), "
            f"expected=({profile.database_id}, {profile.database_name!r})"
        )
    if schema_name != relation.schema_name or table_name != relation.table_name:
        failures.append(
            "resolved relation name differs from the requested exact identifiers: "
            f"actual=({schema_name!r}, {table_name!r})"
        )
    if table_type != "U" or is_ms_shipped:
        failures.append(
            f"relation is not an unshipped user table: type={table_type!r}, "
            f"is_ms_shipped={is_ms_shipped}"
        )
    if is_memory_optimized or temporal_type != 0 or is_external or ledger_type != 0:
        failures.append(
            "relation storage profile is unsupported: "
            f"memory_optimized={is_memory_optimized}, temporal_type={temporal_type}, "
            f"external={is_external}, ledger_type={ledger_type}"
        )
    if is_node or is_edge:
        failures.append(f"graph relation is unsupported: node={is_node}, edge={is_edge}")
    if permissions != (1, 0, 0, 0, 0, 0):
        failures.append(
            "reader permissions must be SELECT-only for the resolved relation: "
            f"select={permissions[0]}, insert={permissions[1]}, update={permissions[2]}, "
            f"delete={permissions[3]}, alter={permissions[4]}, control={permissions[5]}"
        )
    if has_column_update:
        failures.append("reader has UPDATE permission on at least one physical column")
    if not can_view_definition:
        failures.append(
            "reader lost database VIEW DEFINITION required to enumerate security policies"
        )
    if has_enabled_security_policy:
        failures.append("relation has an enabled row-level security policy")
    if failures:
        raise MssqlMetadataError(
            "SQL Server relation inspection rejected the physical source: "
            f"schema={relation.schema_name!r}, table={relation.table_name!r}; "
            + "; ".join(failures)
        )
    return database_id, schema_id, object_id


def _column_metadata_query(
    object_id: int,
    column_names: tuple[str, ...],
) -> MssqlQuery:
    requested_rows = ", ".join("(?, ?)" for _column_name in column_names)
    statement = (
        "SELECT CONVERT(int, [dfe_requested].[request_ordinal]), "
        "CONVERT(nvarchar(128), [dfe_requested].[column_name]), "
        "CONVERT(int, [dfe_column].[column_id]), "
        "CONVERT(nvarchar(128), [dfe_column].[name]), "
        "CONVERT(int, [dfe_column].[system_type_id]), "
        "CONVERT(int, [dfe_column].[user_type_id]), "
        "CONVERT(nvarchar(128), [dfe_type].[name]), "
        "CONVERT(nvarchar(128), [dfe_type_schema].[name]), "
        "CONVERT(int, [dfe_type].[system_type_id]), "
        "CONVERT(int, [dfe_type].[user_type_id]), "
        "CONVERT(bit, [dfe_type].[is_user_defined]), "
        "CONVERT(bit, [dfe_type].[is_assembly_type]), "
        "CONVERT(bit, [dfe_type].[is_table_type]), "
        "CONVERT(int, [dfe_column].[max_length]), "
        "CONVERT(int, [dfe_column].[precision]), "
        "CONVERT(int, [dfe_column].[scale]), "
        "CONVERT(nvarchar(128), [dfe_column].[collation_name]), "
        "CONVERT(bit, [dfe_column].[is_nullable]), "
        "CONVERT(bit, [dfe_column].[is_identity]), "
        "CONVERT(bit, [dfe_column].[is_computed]), "
        "CONVERT(int, [dfe_column].[generated_always_type]), "
        "CONVERT(int, [dfe_column].[encryption_type]), "
        "CONVERT(bit, [dfe_column].[is_hidden]), "
        "CONVERT(bit, [dfe_column].[is_masked]) "
        f"FROM (VALUES {requested_rows}) "
        "AS [dfe_requested]([request_ordinal], [column_name]) "
        "LEFT JOIN sys.columns AS [dfe_column] "
        "ON [dfe_column].[object_id] = ? "
        "AND [dfe_column].[name] = [dfe_requested].[column_name] "
        "LEFT JOIN sys.types AS [dfe_type] "
        "ON [dfe_type].[user_type_id] = [dfe_column].[user_type_id] "
        "LEFT JOIN sys.schemas AS [dfe_type_schema] "
        "ON [dfe_type_schema].[schema_id] = [dfe_type].[schema_id] "
        "ORDER BY [dfe_requested].[request_ordinal]"
    )
    parameters: list[MssqlParameter] = []
    for index, column_name in enumerate(column_names, start=1):
        parameters.extend((index, column_name))
    parameters.append(object_id)
    return MssqlQuery(
        query_id=uuid4(),
        statement=statement,
        parameters=tuple(parameters),
    )


def _binding_from_metadata_row(
    field_name: str,
    column_name: str,
    index: int,
    row: MssqlRow,
) -> MssqlFieldBinding:
    if len(row) != 24:
        raise MssqlDataValidationError(
            "SQL Server column catalog probe returned an unexpected field count: "
            f"expected=24, actual={len(row)}"
        )
    ordinal = _require_bounded_integer(row[0], "requested column ordinal", 1, INT32_MAX)
    requested_name = _require_text(row[1], "requested column name")
    if ordinal != index + 1 or requested_name != column_name:
        raise MssqlDataValidationError(
            "SQL Server column catalog probe changed the requested column order or name: "
            f"column_index={index}"
        )
    if row[2] is None:
        raise MssqlMetadataError(
            "SQL Server requested column is missing or not visible: "
            f"column_index={index}, column_name={column_name!r}"
        )
    column_id = _require_bounded_integer(row[2], "column_id", 1, INT32_MAX)
    actual_name = _require_text(row[3], "column_name")
    if actual_name != column_name:
        raise MssqlDataValidationError(
            "SQL Server catalog resolved a different exact column identifier: "
            f"column_index={index}, expected={column_name!r}, actual={actual_name!r}"
        )
    system_type_id = _require_bounded_integer(row[4], "column system_type_id", 1, 255)
    user_type_id = _require_bounded_integer(row[5], "column user_type_id", 1, INT32_MAX)
    type_name = _require_text(row[6], "declared type name")
    type_schema_name = _require_text(row[7], "declared type schema name")
    declared_system_type_id = _require_bounded_integer(row[8], "declared system_type_id", 1, 255)
    declared_user_type_id = _require_bounded_integer(row[9], "declared user_type_id", 1, INT32_MAX)
    is_user_defined = _require_boolean(row[10], "type is_user_defined")
    is_assembly_type = _require_boolean(row[11], "type is_assembly_type")
    is_table_type = _require_boolean(row[12], "type is_table_type")
    max_length = _require_integer(row[13], "column max_length")
    precision = _require_bounded_integer(row[14], "column precision", 0, 38)
    scale = _require_bounded_integer(row[15], "column scale", 0, 38)
    collation_name = _require_optional_text(row[16], "column collation_name")
    is_nullable = _require_boolean(row[17], "column is_nullable")
    _require_boolean(row[18], "column is_identity")
    is_computed = _require_boolean(row[19], "column is_computed")
    generated_always_type = _require_bounded_integer(
        row[20], "column generated_always_type", 0, INT32_MAX
    )
    encryption_type = _require_optional_integer(row[21], "column encryption_type")
    is_hidden = _require_boolean(row[22], "column is_hidden")
    is_masked = _require_boolean(row[23], "column is_masked")
    if (
        user_type_id != system_type_id
        or declared_system_type_id != system_type_id
        or declared_user_type_id != user_type_id
        or type_schema_name != "sys"
        or is_user_defined
        or is_assembly_type
        or is_table_type
    ):
        raise MssqlMetadataError(
            "SQL Server requested column must use a direct built-in sys type: "
            f"column_index={index}, column_name={column_name!r}, "
            f"type={type_schema_name}.{type_name}, system_type_id={system_type_id}, "
            f"user_type_id={user_type_id}"
        )
    if is_computed or generated_always_type != 0 or encryption_type is not None:
        raise MssqlMetadataError(
            "SQL Server requested column uses unsupported computed/generated/encrypted "
            f"semantics: column_index={index}, column_name={column_name!r}"
        )
    if is_hidden or is_masked:
        raise MssqlMetadataError(
            "SQL Server requested column is hidden or masked: "
            f"column_index={index}, column_name={column_name!r}"
        )
    return MssqlFieldBinding(
        field_name=field_name,
        column_id=column_id,
        column_name=column_name,
        is_nullable=is_nullable,
        physical=MssqlPhysicalField(
            system_type_name=type_name,
            system_type_id=system_type_id,
            user_type_id=user_type_id,
            max_length=max_length,
            precision=precision,
            scale=scale,
            collation_name=collation_name,
        ),
    )


def _open_mssql_transport_once(settings: MssqlConnectionSettings) -> MssqlTransport:
    connection: pyodbc.Connection | None = None
    try:
        connection = pyodbc.connect(
            _build_connection_string(settings),
            autocommit=False,
            readonly=True,
            timeout=settings.login_timeout_seconds,
        )
        connection.timeout = settings.query_timeout_seconds
        evidence = _read_driver_evidence(connection)
        return MssqlTransport(
            connection,
            evidence,
            settings.cancellation_acknowledgement_timeout_seconds,
            settings.query_timeout_seconds,
        )
    except pyodbc.Error as error:
        connection_close_failed = _close_failed_connection(connection)
        raise MssqlConnectionError(
            "SQL Server connection or profile query failed: "
            f"host={settings.host!r}, port={settings.port}, "
            f"database={settings.database!r}, user={settings.user!r}, "
            f"sqlstate={_sqlstate(error)!r}, "
            f"connection_close_failed={connection_close_failed}"
        ) from None
    except MssqlDataValidationError as error:
        connection_close_failed = _close_failed_connection(connection)
        raise MssqlConnectionError(
            "SQL Server profile validation failed: "
            f"host={settings.host!r}, port={settings.port}, "
            f"database={settings.database!r}, user={settings.user!r}, "
            f"validation_error={type(error).__name__!r}, "
            f"connection_close_failed={connection_close_failed}"
        ) from None
    except (
        MssqlTransportError,
        PostgresReadDeadlineExceededError,
        PostgresSourceBudgetExceededError,
    ):
        _close_failed_connection(connection)
        raise


def _open_mssql_transport_once_budgeted(
    settings: MssqlConnectionSettings,
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> MssqlTransport:
    connection: pyodbc.Connection | None = None
    try:
        connection = pyodbc.connect(
            _build_connection_string(settings),
            autocommit=False,
            readonly=True,
            timeout=_mssql_budget_timeout_seconds(
                source_budget,
                settings.login_timeout_seconds,
            ),
        )
        connection.timeout = _mssql_budget_timeout_seconds(
            source_budget,
            settings.query_timeout_seconds,
        )
        evidence = _read_driver_evidence_budgeted(
            connection,
            source_budget,
            source_direction,
        )
        return MssqlTransport(
            connection,
            evidence,
            settings.cancellation_acknowledgement_timeout_seconds,
            settings.query_timeout_seconds,
        )
    except pyodbc.Error as error:
        connection_close_failed = _close_failed_connection(connection)
        raise MssqlConnectionError(
            "SQL Server protected connection or driver probe failed: "
            f"host={settings.host!r}, port={settings.port}, "
            f"database={settings.database!r}, user={settings.user!r}, "
            f"sqlstate={_sqlstate(error)!r}, "
            f"connection_close_failed={connection_close_failed}"
        ) from None
    except MssqlDataValidationError as error:
        connection_close_failed = _close_failed_connection(connection)
        raise MssqlConnectionError(
            "SQL Server protected driver evidence validation failed: "
            f"host={settings.host!r}, port={settings.port}, "
            f"database={settings.database!r}, user={settings.user!r}, "
            f"validation_error={type(error).__name__!r}, "
            f"connection_close_failed={connection_close_failed}"
        ) from None


def _read_driver_evidence(connection: pyodbc.Connection) -> MssqlDriverEvidence:
    driver_name = _required_driver_text(connection.getinfo(pyodbc.SQL_DRIVER_NAME), "driver name")
    driver_version = _required_driver_text(
        connection.getinfo(pyodbc.SQL_DRIVER_VER),
        "driver version",
    )
    cursor = connection.cursor()
    try:
        row = cursor.execute(
            "SELECT CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')), CONVERT(int, @@SPID)"
        ).fetchone()
    finally:
        cursor.close()
    if row is None or len(row) != 2:
        raise MssqlDataValidationError("SQL Server profile query did not return one profile row")
    server_version: object = row[0]
    session_id: object = row[1]
    if type(server_version) is not str or not server_version:
        raise MssqlDataValidationError("SQL Server profile returned an invalid server version")
    if type(session_id) is not int or session_id < 1:
        raise MssqlDataValidationError("SQL Server profile returned an invalid session ID")
    connection.rollback()
    return MssqlDriverEvidence(
        pyodbc_version=pyodbc.version,
        driver_name=driver_name,
        driver_version=driver_version,
        server_version=server_version,
        session_id=session_id,
    )


def _read_driver_evidence_budgeted(
    connection: pyodbc.Connection,
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> MssqlDriverEvidence:
    driver_name = _required_driver_text(connection.getinfo(pyodbc.SQL_DRIVER_NAME), "driver name")
    driver_version = _required_driver_text(
        connection.getinfo(pyodbc.SQL_DRIVER_VER),
        "driver version",
    )
    limits = MssqlFetchLimits(
        fetch_batch_records=1,
        max_records=1,
        max_value_bytes=512,
        max_record_bytes=1_024,
        max_total_bytes=1_024,
        max_declared_value_bytes=512,
        max_declared_record_bytes=1_024,
    )
    deadline = _mssql_source_deadline(source_budget)
    charge = source_budget.dispatch_query(source_direction, 0)
    connection.timeout = _mssql_budget_timeout_seconds(
        source_budget,
        deadline.statement_timeout_milliseconds // 1_000 + 1,
    )
    _require_mssql_deadline(deadline, "driver evidence dispatch")
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')), CONVERT(int, @@SPID)"
        )
        expected_column_count = _validate_result_description(
            cursor.description,
            limits.max_declared_value_bytes,
            limits.max_declared_record_bytes,
        )
        raw_row = cursor.fetchone()
        if raw_row is None:
            _require_mssql_deadline(deadline, "empty driver evidence receipt")
            charge.require_fetch_deadline()
            raise MssqlDataValidationError(
                "SQL Server profile query did not return one profile row"
            )
        try:
            row, row_bytes = _validated_driver_row(
                raw_row,
                expected_column_count,
                limits.max_value_bytes,
                limits.max_record_bytes,
            )
        except MssqlTransportError:
            charge.consume_record(limits.max_record_bytes)
            raise
        charge.consume_record(row_bytes)
        _require_mssql_deadline(deadline, "driver evidence receipt")
    finally:
        cursor.close()
    if len(row) != 2:
        raise MssqlDataValidationError("SQL Server profile query did not return one profile row")
    server_version = _require_text(row[0], "driver evidence server version")
    session_id = _require_bounded_integer(row[1], "driver evidence session ID", 1, INT32_MAX)
    connection.rollback()
    return MssqlDriverEvidence(
        pyodbc_version=pyodbc.version,
        driver_name=driver_name,
        driver_version=driver_version,
        server_version=server_version,
        session_id=session_id,
    )


def _close_failed_connection(connection: pyodbc.Connection | None) -> bool:
    if connection is None:
        return False
    try:
        connection.close()
    except pyodbc.Error:
        return True
    return False


def _build_connection_string(settings: MssqlConnectionSettings) -> str:
    trust_server_certificate = (
        "Yes"
        if settings.tls_verification is MssqlTlsVerification.TRUST_FIXTURE_CERTIFICATE
        else "No"
    )
    values = (
        ("Driver", _DRIVER_NAME),
        ("Server", f"tcp:{settings.host},{settings.port}"),
        ("Database", settings.database),
        ("UID", settings.user),
        ("PWD", settings.password.get_secret_value()),
        ("Encrypt", "Mandatory"),
        ("TrustServerCertificate", trust_server_certificate),
        ("ApplicationIntent", "ReadOnly"),
        ("MARS_Connection", "No"),
        ("ConnectRetryCount", "0"),
        ("LongAsMax", "Yes"),
        ("APP", settings.application_name),
    )
    return ";".join(f"{key}={_odbc_braced(value)}" for key, value in values)


def _odbc_braced(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"


def _required_driver_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        raise MssqlDataValidationError(f"ODBC returned an invalid {field_name}")
    return value


def _provenance_record_bytes(query: MssqlCanonicalQuery) -> int:
    return (11 * (3 + len(query.inspection.bindings))) + 1


def _row_transport_limits(
    query: MssqlCanonicalQuery,
    limits: MssqlFetchLimits,
) -> MssqlFetchLimits:
    overhead = _provenance_record_bytes(query)
    max_value_bytes = max(limits.max_value_bytes, 11)
    max_record_bytes = limits.max_record_bytes + overhead
    max_total_bytes = limits.max_total_bytes + (
        max(limits.max_records + 1, limits.fetch_batch_records) * overhead
    )
    return MssqlFetchLimits(
        fetch_batch_records=limits.fetch_batch_records,
        max_records=limits.max_records + 1,
        max_value_bytes=max_value_bytes,
        max_record_bytes=max_record_bytes,
        max_total_bytes=max_total_bytes,
        max_declared_value_bytes=max(limits.max_declared_value_bytes, 11),
        max_declared_record_bytes=limits.max_declared_record_bytes + overhead,
    )


def _exact_row_transport_limits(
    query: MssqlCanonicalQuery,
    limits: MssqlFetchLimits,
    ranges: tuple[MssqlIntegerRangeRequest, ...],
) -> MssqlFetchLimits:
    transport = _row_transport_limits(query, limits)
    maximum_segment_id_bytes = max(len(item.segment_id.encode("ascii")) for item in ranges)
    maximum_row_envelope_bytes = min(
        query.max_encoded_envelope_bytes,
        _MAX_INTEGER_RANGE_ROW_BYTES,
    )
    maximum_payload_record_bytes = (
        maximum_segment_id_bytes
        + _MAX_INT64_KEY_ENVELOPE_BYTES
        + maximum_row_envelope_bytes
        + _EXACT_STATUS_BYTES
    )
    maximum_payload_value_bytes = max(
        maximum_segment_id_bytes,
        _MAX_INT64_KEY_ENVELOPE_BYTES,
        maximum_row_envelope_bytes,
    )
    overhead = _provenance_record_bytes(query)
    return MssqlFetchLimits(
        fetch_batch_records=transport.fetch_batch_records,
        max_records=transport.max_records,
        max_value_bytes=transport.max_value_bytes,
        max_record_bytes=transport.max_record_bytes,
        max_total_bytes=transport.max_total_bytes,
        max_declared_value_bytes=max(11, maximum_payload_value_bytes),
        max_declared_record_bytes=overhead + maximum_payload_record_bytes,
    )


def _summary_transport_limits(
    query: MssqlCanonicalQuery,
    limits: MssqlFetchLimits,
) -> MssqlFetchLimits:
    overhead = _provenance_record_bytes(query)
    descriptor_headroom = _summary_descriptor_headroom(query.result_kind)
    max_value_bytes = max(limits.max_value_bytes, 11)
    max_record_bytes = limits.max_record_bytes + overhead
    max_total_bytes = limits.max_total_bytes + (
        max(limits.max_records, limits.fetch_batch_records) * overhead
    )
    return MssqlFetchLimits(
        fetch_batch_records=limits.fetch_batch_records,
        max_records=limits.max_records,
        max_value_bytes=max_value_bytes,
        max_record_bytes=max_record_bytes,
        max_total_bytes=max_total_bytes,
        max_declared_value_bytes=max(limits.max_declared_value_bytes, 11),
        max_declared_record_bytes=(
            limits.max_declared_record_bytes + overhead + descriptor_headroom
        ),
    )


def _summary_descriptor_headroom(result_kind: MssqlCanonicalResultKind) -> int:
    if result_kind is MssqlCanonicalResultKind.FINGERPRINT:
        return 27
    if result_kind is MssqlCanonicalResultKind.KEY_SUMMARY:
        return 6
    if result_kind is MssqlCanonicalResultKind.INTEGER_KEY_SUMMARY:
        return 7
    if result_kind is MssqlCanonicalResultKind.INTEGER_RANGE_FINGERPRINTS:
        return 33
    raise MssqlQueryContextError(
        "SQL Server summary transport received a non-summary result kind: "
        f"result_kind={result_kind.value!r}"
    )


def _validate_logical_rows(
    rows: tuple[MssqlRow, ...],
    limits: MssqlFetchLimits,
) -> None:
    if len(rows) > limits.max_records:
        raise MssqlResultLimitError(
            "SQL Server logical result exceeded max_records after provenance removal: "
            f"observed={len(rows)}, max_records={limits.max_records}"
        )
    total_bytes = 0
    for row_index, row in enumerate(rows):
        record_bytes = sum(
            _validated_driver_value(value, column_index)[1]
            for column_index, value in enumerate(row)
        )
        if record_bytes > limits.max_record_bytes:
            raise MssqlResultLimitError(
                "SQL Server logical row exceeded max_record_bytes after provenance removal: "
                f"row_index={row_index}, observed={record_bytes}, "
                f"max_record_bytes={limits.max_record_bytes}"
            )
        total_bytes += record_bytes
    if total_bytes > limits.max_total_bytes:
        raise MssqlResultLimitError(
            "SQL Server logical result exceeded max_total_bytes after provenance removal: "
            f"observed={total_bytes}, max_total_bytes={limits.max_total_bytes}"
        )


def _validate_logical_rows_before_deadline(
    rows: tuple[MssqlRow, ...],
    limits: MssqlFetchLimits,
    deadline: PostgresReadDeadline,
    operation: str,
) -> None:
    if len(rows) > limits.max_records:
        raise MssqlResultLimitError(
            "SQL Server logical result exceeded max_records after provenance removal: "
            f"observed={len(rows)}, max_records={limits.max_records}"
        )
    total_bytes = 0
    for row_index, row in enumerate(rows):
        if row_index % _DEADLINE_CHECK_RECORDS == 0:
            _require_mssql_deadline(deadline, operation)
        record_bytes = sum(
            _validated_driver_value(value, column_index)[1]
            for column_index, value in enumerate(row)
        )
        if record_bytes > limits.max_record_bytes:
            raise MssqlResultLimitError(
                "SQL Server logical row exceeded max_record_bytes after provenance removal: "
                f"row_index={row_index}, observed={record_bytes}, "
                f"max_record_bytes={limits.max_record_bytes}"
            )
        total_bytes += record_bytes
    _require_mssql_deadline(deadline, operation)
    if total_bytes > limits.max_total_bytes:
        raise MssqlResultLimitError(
            "SQL Server logical result exceeded max_total_bytes after provenance removal: "
            f"observed={total_bytes}, max_total_bytes={limits.max_total_bytes}"
        )


def _logical_read_metrics(
    physical: MssqlReadMetrics,
    rows: tuple[MssqlRow, ...],
) -> MssqlReadMetrics:
    fetched_bytes = sum(
        _validated_driver_value(value, column_index)[1]
        for row in rows
        for column_index, value in enumerate(row)
    )
    return MssqlReadMetrics(
        fetched_records=len(rows),
        fetched_bytes=fetched_bytes,
        fetch_calls=physical.fetch_calls,
        largest_batch_records=min(physical.largest_batch_records, len(rows)),
    )


def _logical_read_metrics_before_deadline(
    physical: MssqlReadMetrics,
    rows: tuple[MssqlRow, ...],
    deadline: PostgresReadDeadline,
    operation: str,
) -> MssqlReadMetrics:
    fetched_bytes = 0
    for row_index, row in enumerate(rows):
        if row_index % _DEADLINE_CHECK_RECORDS == 0:
            _require_mssql_deadline(deadline, operation)
        fetched_bytes += sum(
            _validated_driver_value(value, column_index)[1]
            for column_index, value in enumerate(row)
        )
    _require_mssql_deadline(deadline, operation)
    return MssqlReadMetrics(
        fetched_records=len(rows),
        fetched_bytes=fetched_bytes,
        fetch_calls=physical.fetch_calls,
        largest_batch_records=min(physical.largest_batch_records, len(rows)),
    )


def _exact_read_metrics_before_deadline(
    rows: tuple[PostgresIntegerExactRow, ...],
    deadline: PostgresReadDeadline,
) -> PostgresReadMetrics:
    result_bytes = 0
    for row_index, row in enumerate(rows):
        if row_index % _DEADLINE_CHECK_RECORDS == 0:
            _require_mssql_deadline(deadline, "exact-row metrics")
        result_bytes += (
            len(row.segment_id.encode("ascii"))
            + len(row.key_envelope)
            + len(row.row_envelope)
            + _EXACT_STATUS_BYTES
        )
    _require_mssql_deadline(deadline, "exact-row metrics")
    return PostgresReadMetrics(
        fetched_records=len(rows),
        result_bytes=result_bytes,
    )


def _comparison_read_metrics(metrics: MssqlReadMetrics) -> PostgresReadMetrics:
    return PostgresReadMetrics(
        fetched_records=metrics.fetched_records,
        result_bytes=metrics.fetched_bytes,
    )


def _mssql_fetch_limits(
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
) -> MssqlFetchLimits:
    return MssqlFetchLimits(
        fetch_batch_records=1,
        max_records=max_records,
        max_value_bytes=max_record_bytes,
        max_record_bytes=max_record_bytes,
        max_total_bytes=max_total_bytes,
        max_declared_value_bytes=max_record_bytes,
        max_declared_record_bytes=max_record_bytes,
    )


def _mssql_scope(scope: PostgresScopePredicate | None) -> MssqlScopePredicate | None:
    if scope is None:
        return None
    if not isinstance(cast(object, scope), PostgresScopePredicate):
        raise TypeError("SQL Server comparison scope must be PostgresScopePredicate or None")
    return MssqlScopePredicate(
        field=scope.field,
        column_name=scope.column_name,
        canonical_payload=scope.canonical_payload,
    )


def _mssql_ranges(
    ranges: tuple[PostgresIntegerRangeRequest, ...],
) -> tuple[MssqlIntegerRangeRequest, ...]:
    if type(ranges) is not tuple:
        raise TypeError("SQL Server comparison ranges must be an immutable tuple")
    return tuple(
        MssqlIntegerRangeRequest(
            segment_id=item.segment_id,
            lower_inclusive=item.lower_inclusive,
            upper_exclusive=item.upper_exclusive,
        )
        for item in ranges
    )


def _require_mssql_deadline(deadline: PostgresReadDeadline, operation: str) -> None:
    if not isinstance(cast(object, deadline), PostgresReadDeadline):
        raise TypeError("SQL Server comparison deadline must be PostgresReadDeadline")
    if time.monotonic_ns() >= deadline.deadline_nanoseconds:
        raise PostgresReadDeadlineExceededError(
            f"SQL Server {operation} exceeded the immutable whole-run deadline"
        )


def _mssql_source_deadline(
    source_budget: PostgresSourceBudgetAttempt,
) -> PostgresReadDeadline:
    return source_budget.read_deadline(source_budget.effective_statement_timeout_milliseconds())


def _require_source_budget_deadline(
    source_budget: PostgresSourceBudgetAttempt,
    operation: str,
) -> None:
    _require_mssql_deadline(_mssql_source_deadline(source_budget), operation)


def _mssql_budget_timeout_seconds(
    source_budget: PostgresSourceBudgetAttempt,
    configured_timeout_seconds: int,
) -> int:
    if type(configured_timeout_seconds) is not int or configured_timeout_seconds < 1:
        raise ValueError("SQL Server configured timeout seconds must be a positive integer")
    deadline = _mssql_source_deadline(source_budget)
    remaining_nanoseconds = deadline.deadline_nanoseconds - time.monotonic_ns()
    remaining_seconds = max(1, math.ceil(remaining_nanoseconds / 1_000_000_000))
    statement_seconds = max(
        1,
        math.ceil(deadline.statement_timeout_milliseconds / 1_000),
    )
    return min(configured_timeout_seconds, remaining_seconds, statement_seconds)


def _sleep_mssql_retry_delay(
    delay_seconds: float,
    source_budget: PostgresSourceBudgetAttempt,
) -> None:
    deadline = _mssql_source_deadline(source_budget)
    remaining_seconds = (deadline.deadline_nanoseconds - time.monotonic_ns()) / 1_000_000_000
    if delay_seconds >= remaining_seconds:
        raise PostgresReadDeadlineExceededError(
            "SQL Server connection retry delay would exceed the immutable whole-run deadline"
        )
    time.sleep(delay_seconds)


def _require_optional_int64(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _require_bounded_integer(value, field_name, -(1 << 63), (1 << 63) - 1)


def _require_unsigned_integer(value: object, field_name: str, maximum: int) -> int:
    if type(value) is int:
        result = value
    elif type(value) is Decimal and value.is_finite() and value == value.to_integral_value():
        result = int(value)
    else:
        raise MssqlDataValidationError(
            "SQL Server returned a non-integral aggregate: "
            f"field={field_name!r}, python_type={type(value).__name__!r}"
        )
    if not 0 <= result <= maximum:
        raise MssqlDataValidationError(
            f"SQL Server aggregate is outside 0..{maximum}: field={field_name!r}"
        )
    return result


def _require_ascii_bytes(value: object, field_name: str) -> bytes:
    if type(value) is not bytes:
        raise MssqlDataValidationError(
            f"SQL Server returned non-binary canonical data: field={field_name!r}"
        )
    try:
        value.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise MssqlDataValidationError(
            f"SQL Server returned non-ASCII canonical bytes: field={field_name!r}"
        ) from None
    return value


def _relation_manifest_record(payload: MssqlRow) -> MssqlRelationManifestRecord:
    business_date_text = _require_text(payload[4], "manifest business_date")
    try:
        business_date = date.fromisoformat(business_date_text)
    except ValueError:
        raise MssqlDataValidationError(
            "SQL Server readiness business_date is not exact ISO date text"
        ) from None
    if business_date.isoformat() != business_date_text:
        raise MssqlDataValidationError(
            "SQL Server readiness business_date is not canonical ISO date text"
        )
    completed_text = _require_optional_text(payload[7], "manifest completed_at")
    completed_at: datetime | None = None
    if completed_text is not None:
        completed_at = _manifest_completed_at(completed_text)
    return MssqlRelationManifestRecord(
        dataset_id=_require_text(payload[0], "manifest dataset_id"),
        scope_digest=_require_text(payload[1], "manifest scope_digest"),
        batch_id=_require_text(payload[2], "manifest batch_id"),
        state=_require_text(payload[3], "manifest state"),
        business_date=business_date,
        source_cut=_require_optional_text(payload[5], "manifest source_cut"),
        dataset_version=_require_optional_text(payload[6], "manifest dataset_version"),
        completed_at=completed_at,
    )


def _manifest_completed_at(value: str) -> datetime:
    if value.endswith("Z"):
        local_text = value[:-1]
    elif value.endswith("+00:00"):
        local_text = value[:-6]
    else:
        raise MssqlDataValidationError(
            "SQL Server readiness completed_at must use canonical UTC designator Z or +00:00"
        )
    if len(local_text) < 19:
        raise MssqlDataValidationError(
            "SQL Server readiness completed_at is not exact ISO timestamp text"
        )
    second_text = local_text[:19]
    fractional_text = ""
    if len(local_text) > 19:
        if local_text[19] != ".":
            raise MssqlDataValidationError(
                "SQL Server readiness completed_at has a non-canonical fractional separator"
            )
        fractional_text = local_text[20:]
        if (
            not fractional_text
            or len(fractional_text) > 7
            or not fractional_text.isascii()
            or not fractional_text.isdecimal()
        ):
            raise MssqlDataValidationError(
                "SQL Server readiness completed_at has an invalid fractional precision"
            )
    if len(fractional_text) > 6 and any(character != "0" for character in fractional_text[6:]):
        raise MssqlDataValidationError(
            "SQL Server readiness completed_at cannot map losslessly to precision 6"
        )
    microseconds = fractional_text[:6].ljust(6, "0")
    normalized = f"{second_text}.{microseconds}+00:00"
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError:
        raise MssqlDataValidationError(
            "SQL Server readiness completed_at is not exact ISO timestamp text"
        ) from None
    if result.strftime("%Y-%m-%dT%H:%M:%S") != second_text:
        raise MssqlDataValidationError(
            "SQL Server readiness completed_at is not canonical ISO timestamp text"
        )
    return result


def _validate_catalog_identifier(value: str, field_name: str) -> None:
    _validate_odbc_text_scalar(value, field_name)
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if len(value.encode("utf-16-le")) // 2 > 128:
        raise ValueError(f"{field_name} exceeds the SQL Server 128-character limit")


def _require_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        raise MssqlDataValidationError(
            f"SQL Server returned an invalid non-empty text field: field={field_name!r}"
        )
    try:
        _validate_odbc_text_scalar(value, field_name)
    except ValueError as error:
        raise MssqlDataValidationError(
            f"SQL Server returned invalid scalar text: field={field_name!r}, reason={error}"
        ) from None
    return value


def _require_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field_name)


def _require_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise MssqlDataValidationError(
            f"SQL Server returned a non-integer field: field={field_name!r}"
        )
    return value


def _require_optional_integer(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _require_integer(value, field_name)


def _require_bounded_integer(
    value: object,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    integer = _require_integer(value, field_name)
    if not minimum <= integer <= maximum:
        raise MssqlDataValidationError(
            "SQL Server returned an out-of-range integer field: "
            f"field={field_name!r}, value={integer}, minimum={minimum}, maximum={maximum}"
        )
    return integer


def _require_boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise MssqlDataValidationError(
            f"SQL Server returned a non-boolean field: field={field_name!r}"
        )
    return value


def _validate_parameter(parameter: object) -> None:
    if type(parameter) is str:
        _validate_odbc_text_scalar(parameter, "SQL Server string parameters")
        return
    if type(parameter) in (int, bytes):
        return
    if type(parameter) is Decimal and parameter.is_finite():
        return
    raise TypeError("SQL Server parameters must be finite Decimal, str, int, or bytes values")


def _validate_odbc_text_scalar(value: str, field_name: str) -> None:
    if "\x00" in value:
        raise ValueError(f"{field_name} must not contain U+0000")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ValueError(f"{field_name} must not contain unpaired surrogates") from None


def _validate_result_description(
    description: object,
    max_value_bytes: int,
    max_record_bytes: int,
) -> int:
    if type(description) is not tuple or not description:
        raise MssqlDataValidationError("SQL Server query must return a described result set")
    columns = cast(tuple[object, ...], description)
    declared_record_bytes = 0
    for column_index, raw_column in enumerate(columns):
        if type(raw_column) is not tuple:
            raise MssqlDataValidationError(
                f"ODBC returned invalid result metadata: column_index={column_index}"
            )
        column = cast(tuple[object, ...], raw_column)
        if len(column) != 7:
            raise MssqlDataValidationError(
                f"ODBC returned invalid result metadata: column_index={column_index}"
            )
        type_code: object = column[1]
        column_size: object = column[3]
        if type(column_size) is not int or column_size < 1:
            raise MssqlResultLimitError(
                "SQL Server result column has unknown or unbounded size: "
                f"column_index={column_index}"
            )
        declared_max_bytes = _declared_value_max_bytes(type_code, column_size, column_index)
        if declared_max_bytes > max_value_bytes:
            raise MssqlResultLimitError(
                "SQL Server result column exceeds max_value_bytes before fetch: "
                f"column_index={column_index}, declared_max_bytes={declared_max_bytes}, "
                f"max_value_bytes={max_value_bytes}"
            )
        declared_record_bytes += declared_max_bytes
    if declared_record_bytes > max_record_bytes:
        raise MssqlResultLimitError(
            "SQL Server declared row exceeds max_record_bytes before fetch: "
            f"declared_max_bytes={declared_record_bytes}, "
            f"max_record_bytes={max_record_bytes}"
        )
    return len(columns)


def _declared_value_max_bytes(
    type_code: object,
    column_size: int,
    column_index: int,
) -> int:
    if type_code is str:
        return column_size * 4
    if type_code is Decimal:
        return column_size + 3
    if type_code is int:
        return column_size + 1
    if type_code is bool:
        return 1
    if type_code is bytes or type_code is bytearray:
        return column_size
    if (
        type_code is float
        or type_code is date
        or type_code is datetime
        or type_code is datetime_time
    ):
        return max(column_size * 4, 64)
    raise MssqlDataValidationError(
        "ODBC returned unsupported result type metadata: "
        f"column_index={column_index}, type_code={type_code!r}"
    )


def _validated_driver_row(
    raw_row: object,
    expected_column_count: int,
    max_value_bytes: int,
    max_record_bytes: int,
) -> tuple[MssqlRow, int]:
    if not isinstance(raw_row, pyodbc.Row):
        raise MssqlDataValidationError("ODBC fetch returned a non-row value")
    if len(raw_row) != expected_column_count:
        raise MssqlDataValidationError(
            "ODBC row arity differs from its result description: "
            f"expected={expected_column_count}, actual={len(raw_row)}"
        )
    values: list[MssqlValue] = []
    record_bytes = 0
    for column_index in range(len(raw_row)):
        raw_value: object = raw_row[column_index]
        value, value_bytes = _validated_driver_value(raw_value, column_index)
        if value_bytes > max_value_bytes:
            raise MssqlResultLimitError(
                "SQL Server value exceeds max_value_bytes after fetch: "
                f"column_index={column_index}, value_bytes={value_bytes}, "
                f"max_value_bytes={max_value_bytes}"
            )
        values.append(value)
        record_bytes += value_bytes
    if record_bytes > max_record_bytes:
        raise MssqlResultLimitError(
            "SQL Server row exceeds max_record_bytes after fetch: "
            f"record_bytes={record_bytes}, max_record_bytes={max_record_bytes}"
        )
    return tuple(values), record_bytes


def _validated_driver_value(raw_value: object, column_index: int) -> tuple[MssqlValue, int]:
    if raw_value is None:
        return None, 0
    if type(raw_value) is bool:
        return raw_value, 1
    if type(raw_value) is int:
        return raw_value, len(str(raw_value).encode("ascii"))
    if type(raw_value) is Decimal:
        if not raw_value.is_finite():
            raise MssqlDataValidationError(
                f"ODBC returned a non-finite Decimal: column_index={column_index}"
            )
        return raw_value, len(format(raw_value, "f").encode("ascii"))
    if type(raw_value) is str:
        try:
            encoded = raw_value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise MssqlLossyTransportError(
                f"ODBC returned text containing an unpaired surrogate: column_index={column_index}"
            ) from None
        return raw_value, len(encoded)
    if type(raw_value) is bytes:
        return raw_value, len(raw_value)
    if type(raw_value) is bytearray:
        value = bytes(raw_value)
        return value, len(value)
    if isinstance(raw_value, (float, date, datetime, datetime_time)):
        raise MssqlLossyTransportError(
            "ODBC returned a value with a lossy or unsupported native mapping: "
            f"column_index={column_index}, python_type={type(raw_value).__name__!r}; "
            "project temporal values as exact ISO text"
        )
    raise MssqlDataValidationError(
        "ODBC returned an unsupported Python value type: "
        f"column_index={column_index}, python_type={type(raw_value).__name__!r}"
    )


def _validated_confirmation_row(row: pyodbc.Row | None) -> tuple[int, int]:
    if row is None or len(row) != 2:
        raise MssqlDataValidationError("SQL Server cancellation probe returned no row")
    session_id: object = row[0]
    sentinel: object = row[1]
    if type(session_id) is not int or session_id < 1:
        raise MssqlDataValidationError(
            "SQL Server cancellation probe returned an invalid session ID"
        )
    if type(sentinel) is not int:
        raise MssqlDataValidationError("SQL Server cancellation probe returned an invalid sentinel")
    return session_id, sentinel


def _sqlstate(error: pyodbc.Error) -> str:
    if error.args and type(error.args[0]) is str:
        sqlstate = error.args[0]
        if len(sqlstate) == 5 and sqlstate.isascii() and sqlstate.isalnum():
            return sqlstate.upper()
    return "unknown"
