import logging
import math
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from sys import getsizeof
from threading import get_ident
from typing import NoReturn, Protocol, cast, final, runtime_checkable
from uuid import UUID, uuid4

import oracledb
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from forensic_data.coordinator_memory import dict_storage_bytes, tuple_storage_bytes
from forensic_data.oracle_limits import (
    MAX_ORACLE_BIND_OCCURRENCES,
    MAX_ORACLE_BIND_PARAMETERS,
    MAX_ORACLE_BIND_TOTAL_BYTES,
    MAX_ORACLE_BIND_VALUE_BYTES,
    MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS,
    MAX_ORACLE_DECIMAL_OBJECT_BYTES,
    MAX_ORACLE_QUERY_BYTES,
    MAX_ORACLE_RESULT_COLUMNS,
    ORACLE_DECIMAL_TUPLE_SCRATCH_BYTES,
    ORACLE_THIN_BASELINE_RETAINED_BYTES,
    OracleFetchLimits,
    OracleProjectionKind,
    OracleTransportLimits,
    build_oracle_fetch_limits,
)
from forensic_data.oracle_profile import OracleRuntimeProfile
from forensic_data.postgres import (
    PostgresReadDeadline,
    PostgresReadDeadlineExceededError,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetExceededError,
    PostgresSourceDirection,
    PostgresSourceQueryCharge,
)

LOGGER = logging.getLogger(__name__)
_BIND_NAME = re.compile(r"[a-z][a-z0-9_]{0,29}\Z", re.ASCII)
_SQL_BIND_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,29}\Z", re.ASCII)
_PROFILE_HASH = "87b54e8c83aa8171e48100090b696dc29a85dae82917013be1282880db10a02d"
_PROFILE_UNICODE_HEX = "e282ac"
_PROFILE_CHAR_HEX = "412020"
_MAX_ORACLE_NUMBER_PRECISION = 38
_ORACLE_NUMBER_ABSOLUTE_LIMIT = 10**_MAX_ORACLE_NUMBER_PRECISION
_MIN_ORACLE_NUMBER_ADJUSTED_EXPONENT = -130
_MAX_ORACLE_NUMBER_ADJUSTED_EXPONENT = 125
_RETRYABLE_ORACLE_CONNECT_CODES = frozenset((1_033, 1_034, 1_090, 12_514, 12_571, 12_757))
_RETRYABLE_DRIVER_CONNECT_FULL_CODES = frozenset(("DPY-6005",))
_QUERY_ID_PREFIX_BYTES = len("/* dfe_query_id=00000000-0000-0000-0000-000000000000 */\n")
_MAX_UNICODE_TEXT_BASE_BYTES = getsizeof("\U0010ffff")
_ORACLE_DRIVER_BIND_RESERVATION_BYTES = 1_024
_ORACLE_OPERATION_RESERVATION_BYTES = 8_192
_MAX_ORACLE_CONNECTION_TEXT_BYTES = 4_096
_MAX_ORACLE_PASSWORD_BYTES = 4_096
_MAX_ORACLE_WALLET_PATH_BYTES = 32_768
_MAX_ORACLE_RETRY_DELAY_SECONDS = 3_600.0
_MAX_ORACLE_ERROR_MESSAGE_BYTES = 8_192
_READ_ONLY_TRANSACTION_STATEMENT = "SET TRANSACTION READ ONLY"
_ORACLE_SQL_WHITESPACE = frozenset((" ", "\t", "\r", "\n", "\f"))

type OracleBindValue = str | int | Decimal | bytes | None
type OracleValue = str | Decimal | bytes | None
type OracleRow = tuple[OracleValue, ...]
type _OracleSourceAccountingFailure = (
    PostgresReadDeadlineExceededError | PostgresSourceBudgetExceededError
)


class OracleTransportError(RuntimeError):
    """Base error for the Oracle Thin transport boundary."""


class OracleConnectionError(OracleTransportError):
    """Opening or establishing a read-only Oracle context failed."""

    def __init__(
        self,
        message: str,
        retryable: bool,
        driver_message: str | None,
        os_error_code: int | None,
        os_message: str | None,
    ) -> None:
        if type(message) is not str or not message:
            raise ValueError("Oracle connection error message must be non-empty text")
        if type(retryable) is not bool:
            raise TypeError("Oracle connection retryable flag must be a boolean")
        if driver_message is not None:
            _validate_oracle_error_message(driver_message)
        if os_error_code is not None and type(os_error_code) is not int:
            raise TypeError("Oracle connection OS error code must be an integer or None")
        if os_message is not None:
            _validate_os_error_message(os_message)
        if driver_message is not None and os_message is not None:
            raise ValueError("Oracle connection error cannot contain driver and OS messages")
        self.retryable = retryable
        self.driver_message = driver_message
        self.os_error_code = os_error_code
        self.os_message = os_message
        error_message = message
        if driver_message is not None:
            error_message = f"{message}, driver_message={driver_message!r}"
        if os_message is not None:
            error_message = f"{message}, os_error_code={os_error_code!r}, os_message={os_message!r}"
        super().__init__(error_message)


class OracleQueryError(OracleTransportError):
    """An Oracle statement failed and its read context was retired."""

    def __init__(
        self,
        query_id: UUID,
        session_id: int | None,
        code: int,
        full_code: str,
        driver_message: str,
        recoverable: bool,
        cleanup_failed: bool,
    ) -> None:
        _validate_oracle_error_message(driver_message)
        self.query_id = query_id
        self.session_id = session_id
        self.code = code
        self.full_code = full_code
        self.driver_message = driver_message
        self.recoverable = recoverable
        self.cleanup_failed = cleanup_failed
        super().__init__(
            "Oracle query failed: "
            f"query_id={query_id}, session_id={session_id}, code={code}, "
            f"full_code={full_code!r}, driver_message={driver_message!r}, "
            f"recoverable={recoverable}, "
            f"cleanup_failed={cleanup_failed}"
        )


class OracleQueryTimeoutError(OracleQueryError):
    """python-oracledb ended a round trip at its configured call timeout."""


class OracleSnapshotLostError(OracleQueryError):
    """Oracle could no longer serve the original read-only transaction cut."""


class OracleDataValidationError(OracleTransportError):
    """Oracle or python-oracledb returned data outside the typed boundary."""


class OracleLossyTransportError(OracleDataValidationError):
    """A driver value cannot cross the boundary without information loss."""


class OracleResultLimitError(OracleTransportError):
    """An Oracle result exceeded an explicit transport limit."""


class OracleTransportClosedError(OracleTransportError):
    """An operation targeted a retired Oracle transport."""


class OracleCloseError(OracleTransportError):
    """An Oracle rollback, cursor close, or connection close failed."""


class UnsupportedOracleProfileError(OracleTransportError):
    """Observed Oracle capabilities cannot satisfy the selected profile."""


class OracleContextClosedError(OracleTransportClosedError):
    """A closed Oracle read context cannot execute another operation."""


class OracleContextLostError(OracleTransportError):
    """A failed Oracle read context cannot be resumed."""


class OracleThreadOwnershipError(OracleTransportError):
    """A connection operation ran outside the transport owner thread."""


class OracleDriverStateError(OracleTransportError):
    """The driver transport failed outside its structured Oracle error boundary."""


class OracleNetworkError(OracleTransportError):
    """A source round trip failed with an unstructured operating-system error."""

    def __init__(
        self,
        query_id: UUID,
        session_id: int | None,
        cleanup_failed: bool,
        os_error_code: int | None,
        os_message: str,
    ) -> None:
        if os_error_code is not None and type(os_error_code) is not int:
            raise TypeError("Oracle network OS error code must be an integer or None")
        _validate_os_error_message(os_message)
        self.query_id = query_id
        self.session_id = session_id
        self.cleanup_failed = cleanup_failed
        self.os_error_code = os_error_code
        self.os_message = os_message
        super().__init__(
            "Oracle source I/O failed outside the structured driver error boundary: "
            f"query_id={query_id}, session_id={session_id}, "
            f"cleanup_failed={cleanup_failed}, os_error_code={os_error_code!r}, "
            f"os_message={os_message!r}"
        )


class OracleProtocol(StrEnum):
    TCP = "tcp"
    TCPS = "tcps"


class OracleReadContextState(StrEnum):
    ACTIVE = "active"
    LOST = "lost"
    CLOSED = "closed"


class _OracleCleanupPreparation(StrEnum):
    ROUND_TRIP = "round_trip"
    DISCONNECTED = "disconnected"
    EXPIRED_ARMED = "expired_armed"
    UNAVAILABLE = "unavailable"


class OracleConnectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: str
    port: int = Field(ge=1, le=65_535)
    service_name: str
    user: str
    password: SecretStr
    protocol: OracleProtocol
    tls_server_dn_match: bool
    wallet_location: Path | None
    tcp_connect_timeout_seconds: float = Field(gt=0)
    disable_out_of_band_breaks: bool
    application_name: str

    @field_validator("host", "service_name", "user", "application_name")
    @classmethod
    def validate_nonempty_connection_text(cls, value: str) -> str:
        if not value:
            raise ValueError("Oracle connection text fields must not be empty")
        if "\x00" in value:
            raise ValueError("Oracle connection text fields must not contain NUL")
        try:
            value_bytes = _strict_utf8_byte_length(value)
        except UnicodeEncodeError:
            raise ValueError(
                "Oracle connection text fields must not contain unpaired surrogates"
            ) from None
        if value_bytes > _MAX_ORACLE_CONNECTION_TEXT_BYTES:
            raise ValueError(
                "Oracle connection text field exceeds the UTF-8 byte limit: "
                f"value_bytes={value_bytes}, maximum={_MAX_ORACLE_CONNECTION_TEXT_BYTES}"
            )
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: SecretStr) -> SecretStr:
        password = value.get_secret_value()
        if not password:
            raise ValueError("Oracle password must not be empty")
        if "\x00" in password:
            raise ValueError("Oracle password must not contain NUL")
        try:
            password_bytes = _strict_utf8_byte_length(password)
        except UnicodeEncodeError:
            raise ValueError("Oracle password must not contain unpaired surrogates") from None
        if password_bytes > _MAX_ORACLE_PASSWORD_BYTES:
            raise ValueError(
                "Oracle password exceeds the UTF-8 byte limit: "
                f"password_bytes={password_bytes}, maximum={_MAX_ORACLE_PASSWORD_BYTES}"
            )
        return value

    @field_validator("tcp_connect_timeout_seconds")
    @classmethod
    def validate_connect_timeout(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("Oracle TCP connect timeout must be finite")
        return value

    @field_validator("application_name")
    @classmethod
    def validate_application_name_size(cls, value: str) -> str:
        try:
            value_bytes = _strict_utf8_byte_length(value)
        except UnicodeEncodeError:
            raise ValueError(
                "Oracle application_name must not contain unpaired surrogates"
            ) from None
        if value_bytes > 48:
            raise ValueError("Oracle application_name must not exceed 48 UTF-8 bytes")
        return value

    @model_validator(mode="after")
    def validate_tls_settings(self) -> "OracleConnectionSettings":
        if self.protocol is OracleProtocol.TCP:
            if self.tls_server_dn_match:
                raise ValueError("Oracle TCP cannot enable TLS server-DN matching")
            if self.wallet_location is not None:
                raise ValueError("Oracle TCP cannot configure a TLS wallet")
        elif not self.tls_server_dn_match:
            raise ValueError("Oracle TCPS requires TLS server-DN matching")
        if self.wallet_location is not None:
            try:
                wallet_path_bytes = _strict_utf8_byte_length(str(self.wallet_location))
            except UnicodeEncodeError:
                raise ValueError(
                    "Oracle wallet_location must not contain unpaired surrogates"
                ) from None
            if wallet_path_bytes > _MAX_ORACLE_WALLET_PATH_BYTES:
                raise ValueError(
                    "Oracle wallet_location exceeds the UTF-8 byte limit: "
                    f"path_bytes={wallet_path_bytes}, maximum={_MAX_ORACLE_WALLET_PATH_BYTES}"
                )
        return self


@final
@dataclass(frozen=True, slots=True)
class OracleRetryPolicy:
    max_attempts: int
    delay_seconds: float

    def __post_init__(self) -> None:
        if type(self.max_attempts) is not int or self.max_attempts < 1:
            raise ValueError("Oracle max_attempts must be a positive integer")
        if (
            type(self.delay_seconds) is not float
            or not math.isfinite(self.delay_seconds)
            or self.delay_seconds < 0
        ):
            raise ValueError("Oracle delay_seconds must be a finite non-negative float")
        if self.delay_seconds > _MAX_ORACLE_RETRY_DELAY_SECONDS:
            raise ValueError(
                "Oracle delay_seconds exceeds the supported retry-delay limit: "
                f"delay_seconds={self.delay_seconds}, "
                f"maximum={_MAX_ORACLE_RETRY_DELAY_SECONDS}"
            )


@final
@dataclass(frozen=True, slots=True)
class OracleBindParameter:
    name: str
    value: OracleBindValue

    def __post_init__(self) -> None:
        if type(self.name) is not str or _BIND_NAME.fullmatch(self.name) is None:
            raise ValueError(
                "Oracle bind names must use 1..30 lowercase ASCII letters, digits, or underscore"
            )
        _validate_bind_value(self.value, self.name)
        value_bytes = _bind_value_bytes(self.value)
        if value_bytes > MAX_ORACLE_BIND_VALUE_BYTES:
            raise ValueError(
                f"Oracle bind {self.name!r} exceeds the absolute value-byte limit: "
                f"value_bytes={value_bytes}, maximum={MAX_ORACLE_BIND_VALUE_BYTES}"
            )


@final
@dataclass(frozen=True, slots=True)
class OracleProjection:
    name: str
    kind: OracleProjectionKind
    nullable: bool
    max_bytes: int
    max_driver_bytes: int

    def __post_init__(self) -> None:
        _validate_projection_name(self.name)
        if not isinstance(cast(object, self.kind), OracleProjectionKind):
            raise TypeError("Oracle projection kind must be OracleProjectionKind")
        if type(self.nullable) is not bool:
            raise TypeError("Oracle projection nullable must be a boolean")
        if type(self.max_bytes) is not int or self.max_bytes < 1:
            raise ValueError("Oracle projection max_bytes must be a positive integer")
        if type(self.max_driver_bytes) is not int or self.max_driver_bytes < self.max_bytes:
            raise ValueError(
                "Oracle projection max_driver_bytes must be an integer no smaller than max_bytes"
            )
        if self.kind in (OracleProjectionKind.ASCII, OracleProjectionKind.TEXT):
            if self.max_driver_bytes > 4 * self.max_bytes:
                raise ValueError(
                    "Oracle text projection driver bytes cannot exceed four times max_bytes"
                )
        elif self.max_driver_bytes != self.max_bytes:
            raise ValueError("Oracle RAW and DECIMAL projection driver bytes must equal max_bytes")


@final
@dataclass(frozen=True, slots=True)
class OracleQuery:
    query_id: UUID
    statement: str
    parameters: tuple[OracleBindParameter, ...]
    projections: tuple[OracleProjection, ...]
    full_scans: int

    def __post_init__(self) -> None:
        if type(self.query_id) is not UUID:
            raise TypeError("Oracle query_id must be a UUID")
        if type(self.statement) is not str or not self.statement:
            raise ValueError("Oracle statement must be non-empty text")
        if "\x00" in self.statement:
            raise ValueError("Oracle statement must not contain NUL")
        try:
            statement_bytes = _strict_utf8_byte_length(self.statement)
        except UnicodeEncodeError:
            raise ValueError("Oracle statement must not contain unpaired surrogates") from None
        if statement_bytes + _QUERY_ID_PREFIX_BYTES > MAX_ORACLE_QUERY_BYTES:
            raise ValueError(
                "Oracle statement exceeds the absolute UTF-8 query limit: "
                f"statement_bytes={statement_bytes + _QUERY_ID_PREFIX_BYTES}, "
                f"maximum={MAX_ORACLE_QUERY_BYTES}"
            )
        _require_oracle_select_statement(self.statement)
        if type(self.parameters) is not tuple:
            raise TypeError("Oracle query parameters must be a tuple")
        if len(self.parameters) > MAX_ORACLE_BIND_PARAMETERS:
            raise ValueError(
                "Oracle query exceeds the absolute bind-parameter limit: "
                f"bind_parameters={len(self.parameters)}, "
                f"maximum={MAX_ORACLE_BIND_PARAMETERS}"
            )
        bind_occurrence_names = _oracle_bind_occurrence_names(self.statement)
        bind_occurrences = len(bind_occurrence_names)
        if bind_occurrences > MAX_ORACLE_BIND_OCCURRENCES:
            raise ValueError(
                "Oracle query exceeds the absolute bind-occurrence limit: "
                f"bind_occurrences={bind_occurrences}, "
                f"maximum={MAX_ORACLE_BIND_OCCURRENCES}"
            )
        parameter_names: set[str] = set()
        bind_total_bytes = 0
        for parameter in self.parameters:
            if type(parameter) is not OracleBindParameter:
                raise TypeError("Oracle query parameters must be OracleBindParameter values")
            if parameter.name in parameter_names:
                raise ValueError(f"Oracle query has duplicate bind name {parameter.name!r}")
            parameter_names.add(parameter.name)
            bind_total_bytes += _bind_value_bytes(parameter.value)
        occurrence_names = frozenset(bind_occurrence_names)
        if occurrence_names != frozenset(parameter_names):
            raise ValueError(
                "Oracle statement bind placeholders must match query parameters exactly: "
                f"placeholder_names={sorted(occurrence_names)!r}, "
                f"parameter_names={sorted(parameter_names)!r}"
            )
        if bind_total_bytes > MAX_ORACLE_BIND_TOTAL_BYTES:
            raise ValueError(
                "Oracle query exceeds the absolute bind-value total limit: "
                f"bind_total_bytes={bind_total_bytes}, "
                f"maximum={MAX_ORACLE_BIND_TOTAL_BYTES}"
            )
        if type(self.projections) is not tuple or not self.projections:
            raise ValueError("Oracle query projections must be a non-empty tuple")
        if len(self.projections) > MAX_ORACLE_RESULT_COLUMNS:
            raise ValueError(
                "Oracle query exceeds the absolute result-column limit: "
                f"projection_count={len(self.projections)}, "
                f"maximum={MAX_ORACLE_RESULT_COLUMNS}"
            )
        projection_names: set[str] = set()
        for projection in self.projections:
            if type(projection) is not OracleProjection:
                raise TypeError("Oracle query projections must be OracleProjection values")
            if projection.name in projection_names:
                raise ValueError(f"Oracle query has duplicate projection {projection.name!r}")
            projection_names.add(projection.name)
        if type(self.full_scans) is not int or self.full_scans < 0:
            raise ValueError("Oracle query full_scans must be a non-negative integer")


@final
@dataclass(frozen=True, slots=True)
class _OracleReadOnlyTransaction:
    query_id: UUID

    def __post_init__(self) -> None:
        if type(self.query_id) is not UUID:
            raise TypeError("Oracle read-only transaction query_id must be a UUID")


@final
@dataclass(frozen=True, slots=True)
class OracleDriverEvidence:
    driver_version: str
    server_version: str
    thin_mode: bool
    requested_username: str


@final
@dataclass(frozen=True, slots=True)
class OracleServerProfile:
    runtime_profile: OracleRuntimeProfile
    driver: OracleDriverEvidence
    database_name: str
    database_unique_name: str
    instance_name: str
    service_name: str
    session_user: str
    authenticated_identity: str
    proxy_user: str | None
    current_schema: str
    session_id: int
    audit_session_id: int
    database_timezone: str
    session_timezone: str
    database_character_set: str
    national_character_set: str
    nls_numeric_characters: str
    nls_date_language: str
    nls_calendar: str
    nls_timestamp_format: str
    nls_timestamp_tz_format: str


@final
@dataclass(frozen=True, slots=True)
class OracleReadContextEvidence:
    context_id: UUID
    engine: str
    server_version: str
    strategy: str
    snapshot_locator: None
    started_at: datetime
    session_id: int
    audit_session_id: int
    allowed_concurrency: int
    limitations: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class OracleReadMetrics:
    fetched_records: int
    fetched_bytes: int
    fetch_calls: int
    largest_batch_records: int

    def __post_init__(self) -> None:
        for name, value in (
            ("fetched_records", self.fetched_records),
            ("fetched_bytes", self.fetched_bytes),
            ("fetch_calls", self.fetch_calls),
            ("largest_batch_records", self.largest_batch_records),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"Oracle {name} must be a non-negative integer")


@final
@dataclass(frozen=True, slots=True)
class OracleReadResult:
    rows: tuple[OracleRow, ...]
    metrics: OracleReadMetrics
    completion_deadline_nanoseconds: int

    def __post_init__(self) -> None:
        if (
            type(self.completion_deadline_nanoseconds) is not int
            or self.completion_deadline_nanoseconds < 1
        ):
            raise ValueError("Oracle result completion deadline must be a positive integer")


@final
@dataclass(frozen=True, slots=True)
class _OracleErrorDetails:
    code: int
    full_code: str
    safe_message: str
    recoverable: bool


@final
@dataclass(frozen=True, slots=True)
class _OracleConnectionDisposal:
    close_confirmed: bool
    cleanup_failed: bool
    failures: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class _OracleCleanupPreparationResult:
    state: _OracleCleanupPreparation
    failure: str | None


@runtime_checkable
class _OracleErrorDetailsProtocol(Protocol):
    code: int
    full_code: str
    message: str
    isrecoverable: bool


class _OracleCursorProtocol(Protocol):
    arraysize: int
    outputtypehandler: object
    prefetchrows: int

    @property
    def description(self) -> object: ...

    def execute(
        self,
        statement: str,
        parameters: dict[str, OracleBindValue],
        *,
        fetch_lobs: bool,
        fetch_decimals: bool,
    ) -> object: ...

    def fetchmany(self, *, size: int) -> list[object]: ...

    def close(self) -> None: ...


@runtime_checkable
class _OracleFetchInfoProtocol(Protocol):
    name: str
    type_code: object
    display_size: int | None
    internal_size: int | None
    precision: int | None
    scale: int | None


@runtime_checkable
class _OracleDbTypeProtocol(Protocol):
    name: str


@final
@dataclass(frozen=True, slots=True)
class _OracleColumnDescription:
    name: str
    type_name: str
    display_size: int | None
    internal_size: int | None
    precision: int | None
    scale: int | None


@final
class _OracleOutputTypeHandler:
    __slots__ = ("_descriptions", "_limits", "_projections")

    def __init__(
        self,
        projections: tuple[OracleProjection, ...],
        limits: OracleFetchLimits,
    ) -> None:
        self._projections = projections
        self._limits = limits
        self._descriptions: list[_OracleColumnDescription] = []

    def __call__(self, cursor: object, raw_info: object) -> None:
        if not isinstance(cursor, oracledb.Cursor):
            raise OracleDataValidationError(
                "python-oracledb invoked the output type handler with an invalid cursor"
            )
        column_index = len(self._descriptions)
        if column_index >= len(self._projections):
            raise OracleDataValidationError(
                "Oracle result description has more columns than the typed projection: "
                f"projection_count={len(self._projections)}"
            )
        self._descriptions.append(
            _validated_column_description(
                raw_info,
                self._projections[column_index],
                column_index,
            )
        )

    def validated_description(
        self,
        description: object,
    ) -> tuple[_OracleColumnDescription, ...]:
        if type(description) is not list:
            raise OracleDataValidationError("Oracle query must return a described result set")
        raw_description = cast(list[object], description)
        if len(raw_description) != len(self._projections):
            raise OracleDataValidationError(
                "Oracle result description has an unexpected column count: "
                f"expected={len(self._projections)}, actual={len(raw_description)}"
            )
        if len(self._descriptions) != len(self._projections):
            raise OracleDataValidationError(
                "python-oracledb did not invoke the bounded output handler for every result column"
            )
        for index, (raw_info, projection, admitted) in enumerate(
            zip(
                raw_description,
                self._projections,
                self._descriptions,
                strict=True,
            )
        ):
            if _validated_column_description(raw_info, projection, index) != admitted:
                raise OracleDataValidationError(
                    "Oracle result metadata changed after bounded fetch-variable admission: "
                    f"column_index={index}"
                )
        if sum(projection.max_bytes for projection in self._projections) != (
            self._limits.max_record_bytes
        ):
            raise ValueError("Oracle result projections differ from the fetch record limit")
        return tuple(self._descriptions)


class OracleTransport:
    """Single-owner Thin connection with bounded, sequential result transport."""

    def __init__(
        self,
        connection: oracledb.Connection,
        evidence: OracleDriverEvidence,
        limits: OracleTransportLimits,
        whole_run_deadline_nanoseconds: int,
    ) -> None:
        if not isinstance(cast(object, connection), oracledb.Connection):
            raise TypeError("Oracle transport connection must be oracledb.Connection")
        if type(evidence) is not OracleDriverEvidence:
            raise TypeError("Oracle transport evidence must be OracleDriverEvidence")
        if type(limits) is not OracleTransportLimits:
            raise TypeError("Oracle transport limits must be OracleTransportLimits")
        if type(whole_run_deadline_nanoseconds) is not int or whole_run_deadline_nanoseconds < 1:
            raise ValueError("Oracle whole-run deadline must be a positive integer")
        self._connection = connection
        self._evidence = evidence
        self._limits = limits
        self._whole_run_deadline_nanoseconds = whole_run_deadline_nanoseconds
        self._owner_thread_id = get_ident()
        self._closed = False
        self._active_query_id: UUID | None = None
        self._active_cursor: _OracleCursorProtocol | None = None
        self._session_id: int | None = None
        self._connection_close_confirmed = False
        self._cleanup_succeeded = False
        self._cleanup_failures: tuple[str, ...] = ()
        self._retained_thin_chunk_buffer_bytes = ORACLE_THIN_BASELINE_RETAINED_BYTES

    @property
    def evidence(self) -> OracleDriverEvidence:
        return self._evidence

    @property
    def limits(self) -> OracleTransportLimits:
        return self._limits

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def active_query_id(self) -> UUID | None:
        return self._active_query_id

    @property
    def connection_close_confirmed(self) -> bool:
        return self._connection_close_confirmed

    @property
    def cleanup_succeeded(self) -> bool:
        return self._cleanup_succeeded

    @property
    def cleanup_failures(self) -> tuple[str, ...]:
        return self._cleanup_failures

    @property
    def retained_thin_chunk_buffer_bytes(self) -> int:
        return self._retained_thin_chunk_buffer_bytes

    def require_owner_thread(self) -> None:
        self._require_owner_thread()

    def bind_session_identity(self, session_id: int) -> None:
        self._require_owner_thread()
        self._require_open()
        if type(session_id) is not int or session_id < 1:
            raise ValueError("Oracle session_id must be a positive integer")
        if self._session_id is not None:
            raise OracleTransportError("Oracle transport session identity is already bound")
        self._session_id = session_id

    def execute_read_only_transaction_budgeted(
        self,
        control: _OracleReadOnlyTransaction,
        charge: PostgresSourceQueryCharge,
        deadline: PostgresReadDeadline,
    ) -> None:
        if type(control) is not _OracleReadOnlyTransaction:
            raise TypeError("Oracle transaction control must be _OracleReadOnlyTransaction")
        _require_source_charge(charge)
        _require_deadline(deadline)
        _validate_read_only_transaction_against_limits(control, self._limits)
        self._require_owner_thread()
        self._require_open()
        cursor: _OracleCursorProtocol | None = None
        try:
            work_deadline_nanoseconds = _oracle_work_deadline_nanoseconds(
                deadline,
                self._limits.cancellation_reserve_milliseconds,
                "control statement",
            )
            cursor = _new_oracle_cursor(self._connection, "control statement")
            _configure_control_cursor(cursor)
            self._publish_active_query(control.query_id, cursor)
            control_parameters: dict[str, OracleBindValue] = {}
            self._prepare_round_trip(
                charge,
                work_deadline_nanoseconds,
                "control statement dispatch",
            )
            _execute_oracle_statement(
                cursor,
                _READ_ONLY_TRANSACTION_STATEMENT,
                control_parameters,
                "control statement dispatch",
            )
            self._complete_round_trip(
                charge,
                work_deadline_nanoseconds,
                "control statement completion",
            )
            if cursor.description is not None:
                raise OracleDataValidationError(
                    "Oracle control statement unexpectedly returned a result set: "
                    f"query_id={control.query_id}"
                )
            self._finish_success(
                control.query_id,
                cursor,
                charge,
                work_deadline_nanoseconds,
            )
        except oracledb.Error as error:
            self._raise_query_error(control.query_id, cursor, error)
        except OSError as error:
            self._raise_network_error(control.query_id, cursor, error)
        except (
            OracleTransportError,
            PostgresReadDeadlineExceededError,
            PostgresSourceBudgetExceededError,
        ) as error:
            cleanup_failed = self._retire_after_local_failure(control.query_id, cursor)
            _preserve_cleanup_failure(
                error,
                cleanup_failed,
                self._cleanup_failures,
                control.query_id,
                self._session_id,
            )
            raise

    def execute_budgeted(
        self,
        query: OracleQuery,
        fetch_limits: OracleFetchLimits,
        charge: PostgresSourceQueryCharge,
        deadline: PostgresReadDeadline,
    ) -> OracleReadResult:
        if type(query) is not OracleQuery:
            raise TypeError("Oracle query must be OracleQuery")
        if type(fetch_limits) is not OracleFetchLimits:
            raise TypeError("Oracle fetch limits must be OracleFetchLimits")
        _require_source_charge(charge)
        _require_deadline(deadline)
        _validate_query_against_limits(query, fetch_limits, self._limits)
        self._require_owner_thread()
        self._require_open()
        self._admit_fetch_limits(fetch_limits)
        cursor: _OracleCursorProtocol | None = None
        rows: list[OracleRow] = []
        fetched_bytes = 0
        fetch_calls = 0
        largest_batch_records = 0
        try:
            work_deadline_nanoseconds = _oracle_work_deadline_nanoseconds(
                deadline,
                self._limits.cancellation_reserve_milliseconds,
                "query",
            )
            cursor = _new_oracle_cursor(self._connection, "query")
            output_type_handler = _OracleOutputTypeHandler(query.projections, fetch_limits)
            _configure_query_cursor(cursor, fetch_limits, output_type_handler)
            self._publish_active_query(query.query_id, cursor)
            annotated_statement = _statement_with_query_id(query)
            bind_values = _bind_values(query.parameters)
            self._prepare_round_trip(charge, work_deadline_nanoseconds, "query dispatch")
            _execute_oracle_statement(
                cursor,
                annotated_statement,
                bind_values,
                "query dispatch",
            )
            self._complete_round_trip(
                charge,
                work_deadline_nanoseconds,
                "query dispatch completion",
            )
            description = output_type_handler.validated_description(cursor.description)

            while True:
                remaining_with_overflow_probe = fetch_limits.max_received_records - len(rows)
                fetch_size = min(
                    fetch_limits.fetch_batch_records,
                    remaining_with_overflow_probe,
                )
                _set_oracle_fetch_array_size(cursor, fetch_size)
                self._prepare_round_trip(charge, work_deadline_nanoseconds, "result fetch")
                fetched = _fetch_oracle_batch(cursor, fetch_size)
                if type(fetched) is not list:
                    validation_error = OracleDataValidationError(
                        "python-oracledb fetchmany returned a non-list batch"
                    )
                    accounting_error = _consume_received_records(
                        charge,
                        tuple(
                            fetch_limits.max_received_record_bytes
                            for _record_index in range(fetch_size)
                        ),
                    )
                    completion_error = self._round_trip_completion_failure(
                        charge,
                        work_deadline_nanoseconds,
                        "invalid result fetch completion",
                    )
                    _raise_received_batch_failures(
                        validation_error,
                        accounting_error,
                        completion_error,
                    )
                raw_batch = fetched
                if len(raw_batch) > fetch_size:
                    validation_error = OracleDataValidationError(
                        "python-oracledb fetchmany exceeded the requested batch size: "
                        f"requested={fetch_size}, actual={len(raw_batch)}"
                    )
                    accounting_error = _consume_received_records(
                        charge,
                        tuple(fetch_limits.max_received_record_bytes for _row in raw_batch),
                    )
                    completion_error = self._round_trip_completion_failure(
                        charge,
                        work_deadline_nanoseconds,
                        "oversized result fetch completion",
                    )
                    _raise_received_batch_failures(
                        validation_error,
                        accounting_error,
                        completion_error,
                    )
                fetch_calls += 1
                largest_batch_records = max(largest_batch_records, len(raw_batch))
                if not raw_batch:
                    self._complete_round_trip(
                        charge,
                        work_deadline_nanoseconds,
                        "empty result fetch completion",
                    )
                    break

                validated_batch: list[OracleRow] = []
                batch_record_bytes: list[int] = []
                validation_error: OracleTransportError | None = None
                for raw_row in raw_batch:
                    try:
                        row, record_bytes = _validated_driver_row(
                            raw_row,
                            description,
                            query.projections,
                            fetch_limits,
                        )
                    except OracleTransportError as error:
                        validation_error = error
                        batch_record_bytes.extend(
                            fetch_limits.max_received_record_bytes
                            for _remaining in raw_batch[len(batch_record_bytes) :]
                        )
                        break
                    validated_batch.append(row)
                    batch_record_bytes.append(record_bytes)

                accounting_error = _consume_received_records(
                    charge,
                    tuple(batch_record_bytes),
                )
                completion_error = self._round_trip_completion_failure(
                    charge,
                    work_deadline_nanoseconds,
                    "result receipt",
                )
                if (
                    validation_error is not None
                    or accounting_error is not None
                    or completion_error is not None
                ):
                    _raise_received_batch_failures(
                        validation_error,
                        accounting_error,
                        completion_error,
                    )
                batch_bytes = sum(batch_record_bytes)
                if len(rows) + len(validated_batch) > fetch_limits.max_records:
                    raise OracleResultLimitError(
                        "Oracle result exceeded max_records: "
                        f"query_id={query.query_id}, max_records={fetch_limits.max_records}"
                    )
                if fetched_bytes + batch_bytes > fetch_limits.max_total_bytes:
                    raise OracleResultLimitError(
                        "Oracle result exceeded max_total_bytes: "
                        f"query_id={query.query_id}, "
                        f"max_total_bytes={fetch_limits.max_total_bytes}"
                    )
                rows.extend(validated_batch)
                fetched_bytes += batch_bytes
                del fetched, raw_batch, validated_batch, batch_record_bytes

            result = OracleReadResult(
                rows=tuple(rows),
                metrics=OracleReadMetrics(
                    fetched_records=len(rows),
                    fetched_bytes=fetched_bytes,
                    fetch_calls=fetch_calls,
                    largest_batch_records=largest_batch_records,
                ),
                completion_deadline_nanoseconds=work_deadline_nanoseconds,
            )
            self._finish_success(
                query.query_id,
                cursor,
                charge,
                work_deadline_nanoseconds,
            )
            return result
        except oracledb.Error as error:
            self._raise_query_error(query.query_id, cursor, error)
        except OSError as error:
            self._raise_network_error(query.query_id, cursor, error)
        except (
            OracleTransportError,
            PostgresReadDeadlineExceededError,
            PostgresSourceBudgetExceededError,
        ) as error:
            cleanup_failed = self._retire_after_local_failure(query.query_id, cursor)
            _preserve_cleanup_failure(
                error,
                cleanup_failed,
                self._cleanup_failures,
                query.query_id,
                self._session_id,
            )
            raise

    def rollback_and_close(self) -> None:
        self._require_owner_thread()
        self._require_open()
        if self._active_query_id is not None:
            raise OracleTransportError(
                "Oracle transport cannot close while a query is active: "
                f"query_id={self._active_query_id}"
            )
        self._closed = True
        rollback_failed = False
        close_failed = False
        cleanup_failures: list[str] = []
        cleanup_deadline_nanoseconds = _cleanup_deadline_nanoseconds(
            self._whole_run_deadline_nanoseconds,
            self._limits,
        )
        rollback_preparation = _prepare_cleanup_round_trip(
            self._connection,
            cleanup_deadline_nanoseconds,
        )
        if rollback_preparation.failure is not None:
            cleanup_failures.append(rollback_preparation.failure)
        if rollback_preparation.state is _OracleCleanupPreparation.ROUND_TRIP:
            try:
                self._connection.rollback()
            except (AttributeError, OSError, oracledb.Error) as error:
                rollback_failed = True
                cleanup_failures.append(_safe_cleanup_error_summary("rollback", error))
        else:
            rollback_failed = True
            if rollback_preparation.failure is None:
                cleanup_failures.append(
                    f"rollback skipped: cleanup_state={rollback_preparation.state.value!r}"
                )
        if not _cleanup_deadline_intact(cleanup_deadline_nanoseconds):
            rollback_failed = True
        disposal = _dispose_oracle_connection(
            self._connection,
            cleanup_deadline_nanoseconds,
        )
        self._connection_close_confirmed = disposal.close_confirmed
        cleanup_failures.extend(disposal.failures)
        close_failed = disposal.cleanup_failed
        if rollback_failed or close_failed:
            self._cleanup_failures = tuple(cleanup_failures)
            raise OracleCloseError(
                "Oracle read-only context cleanup failed: "
                f"session_id={self._session_id}, rollback_failed={rollback_failed}, "
                f"connection_close_failed={close_failed}, "
                f"failures={self._cleanup_failures!r}"
            )
        self._cleanup_failures = ()
        self._cleanup_succeeded = True

    def _prepare_round_trip(
        self,
        charge: PostgresSourceQueryCharge,
        work_deadline_nanoseconds: int,
        operation: str,
    ) -> None:
        charge.require_fetch_deadline()
        timeout_milliseconds = _oracle_call_timeout_milliseconds(
            work_deadline_nanoseconds,
            operation,
        )
        _set_oracle_call_timeout(self._connection, timeout_milliseconds, operation)

    def _complete_round_trip(
        self,
        charge: PostgresSourceQueryCharge,
        work_deadline_nanoseconds: int,
        operation: str,
    ) -> None:
        charge.require_fetch_deadline()
        _oracle_call_timeout_milliseconds(
            work_deadline_nanoseconds,
            operation,
        )

    def _round_trip_completion_failure(
        self,
        charge: PostgresSourceQueryCharge,
        work_deadline_nanoseconds: int,
        operation: str,
    ) -> _OracleSourceAccountingFailure | None:
        try:
            self._complete_round_trip(
                charge,
                work_deadline_nanoseconds,
                operation,
            )
        except (PostgresReadDeadlineExceededError, PostgresSourceBudgetExceededError) as error:
            return error
        return None

    def _publish_active_query(self, query_id: UUID, cursor: _OracleCursorProtocol) -> None:
        if self._active_query_id is not None or self._active_cursor is not None:
            raise OracleTransportError(
                f"Oracle transport already has an active query: query_id={self._active_query_id}"
            )
        self._active_query_id = query_id
        self._active_cursor = cursor

    def _finish_success(
        self,
        query_id: UUID,
        cursor: _OracleCursorProtocol,
        charge: PostgresSourceQueryCharge,
        work_deadline_nanoseconds: int,
    ) -> None:
        if self._active_query_id != query_id or self._active_cursor is not cursor:
            raise OracleTransportError(
                "Oracle active query identity changed before successful completion"
            )
        self._prepare_round_trip(
            charge,
            work_deadline_nanoseconds,
            "cursor detachment",
        )
        try:
            cursor.close()
        except (AttributeError, OSError, oracledb.Error) as error:
            cleanup_failed = self._retire_connection(query_id, None)
            close_error = OracleCloseError(
                "Oracle cursor close failed after a successful bounded read: "
                f"query_id={query_id}, cleanup_failed={cleanup_failed}, "
                f"failure={_safe_cleanup_error_summary('cursor close', error)!r}"
            )
            _preserve_cleanup_failure(
                close_error,
                cleanup_failed,
                self._cleanup_failures,
                query_id,
                self._session_id,
            )
            raise close_error from None
        try:
            self._complete_round_trip(
                charge,
                work_deadline_nanoseconds,
                "cursor detachment completion",
            )
        except (PostgresReadDeadlineExceededError, PostgresSourceBudgetExceededError) as error:
            cleanup_failed = self._retire_connection(query_id, None)
            _preserve_cleanup_failure(
                error,
                cleanup_failed,
                self._cleanup_failures,
                query_id,
                self._session_id,
            )
            raise
        self._active_query_id = None
        self._active_cursor = None

    def _raise_query_error(
        self,
        query_id: UUID,
        cursor: _OracleCursorProtocol | None,
        error: oracledb.Error,
    ) -> NoReturn:
        cleanup_failed = self._retire_connection(query_id, cursor)
        try:
            details = _driver_error_details(error)
        except OracleDataValidationError as validation_error:
            _preserve_cleanup_failure(
                validation_error,
                cleanup_failed,
                self._cleanup_failures,
                query_id,
                self._session_id,
            )
            raise
        error_type: type[OracleQueryError] = OracleQueryError
        if details.full_code == "DPY-4024":
            error_type = OracleQueryTimeoutError
        elif details.code in (1_466, 1_555):
            error_type = OracleSnapshotLostError
        query_error = error_type(
            query_id,
            self._session_id,
            details.code,
            details.full_code,
            details.safe_message,
            details.recoverable,
            cleanup_failed,
        )
        _preserve_cleanup_failure(
            query_error,
            cleanup_failed,
            self._cleanup_failures,
            query_id,
            self._session_id,
        )
        raise query_error from None

    def _raise_network_error(
        self,
        query_id: UUID,
        cursor: _OracleCursorProtocol | None,
        error: OSError,
    ) -> NoReturn:
        cleanup_failed = self._retire_connection(query_id, cursor)
        os_error_code, os_message = _safe_os_error_details(error)
        network_error = OracleNetworkError(
            query_id,
            self._session_id,
            cleanup_failed,
            os_error_code,
            os_message,
        )
        _preserve_cleanup_failure(
            network_error,
            cleanup_failed,
            self._cleanup_failures,
            query_id,
            self._session_id,
        )
        raise network_error from None

    def _retire_after_local_failure(
        self,
        query_id: UUID,
        cursor: _OracleCursorProtocol | None,
    ) -> bool:
        if self._closed:
            return False
        cleanup_failed = self._retire_connection(query_id, cursor)
        if cleanup_failed:
            LOGGER.warning(
                "Oracle cleanup failed while retiring a locally failed query",
                extra={
                    "query_id": str(query_id),
                    "session_id": self._session_id,
                    "cleanup_failed": True,
                },
            )
        return cleanup_failed

    def _retire_connection(
        self,
        query_id: UUID,
        cursor: _OracleCursorProtocol | None,
    ) -> bool:
        if self._closed:
            return False
        self._active_query_id = None
        self._active_cursor = None
        self._closed = True
        cleanup_failed = False
        cleanup_failures: list[str] = []
        cleanup_deadline_nanoseconds = _cleanup_deadline_nanoseconds(
            self._whole_run_deadline_nanoseconds,
            self._limits,
        )
        if cursor is not None:
            cursor_preparation = _prepare_cleanup_round_trip(
                self._connection,
                cleanup_deadline_nanoseconds,
            )
            if cursor_preparation.failure is not None:
                cleanup_failures.append(cursor_preparation.failure)
            if cursor_preparation.state in (
                _OracleCleanupPreparation.ROUND_TRIP,
                _OracleCleanupPreparation.DISCONNECTED,
            ):
                try:
                    cursor.close()
                except (AttributeError, OSError, oracledb.Error) as error:
                    cleanup_failed = True
                    cleanup_failures.append(_safe_cleanup_error_summary("cursor close", error))
            else:
                cleanup_failed = True
                if cursor_preparation.failure is None:
                    cleanup_failures.append(
                        f"cursor close skipped: cleanup_state={cursor_preparation.state.value!r}"
                    )
            cleanup_failed = (
                not _cleanup_deadline_intact(cleanup_deadline_nanoseconds) or cleanup_failed
            )
        rollback_preparation = _prepare_cleanup_round_trip(
            self._connection,
            cleanup_deadline_nanoseconds,
        )
        if rollback_preparation.failure is not None:
            cleanup_failures.append(rollback_preparation.failure)
        if rollback_preparation.state is _OracleCleanupPreparation.ROUND_TRIP:
            try:
                self._connection.rollback()
            except (AttributeError, OSError, oracledb.Error) as error:
                cleanup_failed = True
                cleanup_failures.append(_safe_cleanup_error_summary("rollback", error))
        else:
            cleanup_failed = True
            if rollback_preparation.failure is None:
                cleanup_failures.append(
                    f"rollback skipped: cleanup_state={rollback_preparation.state.value!r}"
                )
        cleanup_failed = (
            not _cleanup_deadline_intact(cleanup_deadline_nanoseconds) or cleanup_failed
        )
        disposal = _dispose_oracle_connection(
            self._connection,
            cleanup_deadline_nanoseconds,
        )
        self._connection_close_confirmed = disposal.close_confirmed
        cleanup_failures.extend(disposal.failures)
        cleanup_failed = disposal.cleanup_failed or cleanup_failed
        if cleanup_failed:
            LOGGER.warning(
                "Oracle connection retirement cleanup failed",
                extra={
                    "query_id": str(query_id),
                    "session_id": self._session_id,
                    "connection_close_confirmed": self._connection_close_confirmed,
                },
            )
        self._cleanup_succeeded = not cleanup_failed
        self._cleanup_failures = tuple(cleanup_failures)
        return cleanup_failed

    def _require_owner_thread(self) -> None:
        if get_ident() != self._owner_thread_id:
            raise OracleThreadOwnershipError(
                "Oracle connection operations must run on the transport owner thread"
            )

    def _admit_fetch_limits(self, fetch_limits: OracleFetchLimits) -> None:
        if fetch_limits.prior_thin_chunk_buffer_bytes != self._retained_thin_chunk_buffer_bytes:
            raise OracleTransportError(
                "Oracle fetch limits were assembled against stale Thin buffer state: "
                f"expected={self._retained_thin_chunk_buffer_bytes}, "
                f"actual={fetch_limits.prior_thin_chunk_buffer_bytes}"
            )
        self._retained_thin_chunk_buffer_bytes = fetch_limits.retained_thin_chunk_buffer_bytes

    def _require_open(self) -> None:
        if self._closed:
            raise OracleTransportClosedError("Oracle transport is already closed")


class OracleReadContext:
    """One sequential Oracle transaction-level READ ONLY context."""

    def __init__(
        self,
        transport: OracleTransport,
        profile: OracleServerProfile,
        evidence: OracleReadContextEvidence,
        source_budget: PostgresSourceBudgetAttempt,
        source_direction: PostgresSourceDirection,
    ) -> None:
        if type(transport) is not OracleTransport:
            raise TypeError("Oracle read context transport must be OracleTransport")
        if type(profile) is not OracleServerProfile:
            raise TypeError("Oracle read context profile must be OracleServerProfile")
        if type(evidence) is not OracleReadContextEvidence:
            raise TypeError("Oracle read context evidence must be OracleReadContextEvidence")
        if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
            raise TypeError("Oracle read context budget must be PostgresSourceBudgetAttempt")
        if source_direction is not PostgresSourceDirection.REFERENCE:
            raise ValueError("Oracle read contexts are supported only as a reference source")
        self._transport = transport
        self._profile = profile
        self._evidence = evidence
        self._source_budget = source_budget
        self._source_direction = source_direction
        self._state = OracleReadContextState.ACTIVE

    @property
    def profile(self) -> OracleServerProfile:
        return self._profile

    @property
    def runtime_profile(self) -> OracleRuntimeProfile:
        return self._profile.runtime_profile

    @property
    def evidence(self) -> OracleReadContextEvidence:
        return self._evidence

    @property
    def source_budget(self) -> PostgresSourceBudgetAttempt:
        return self._source_budget

    @property
    def source_direction(self) -> PostgresSourceDirection:
        return self._source_direction

    @property
    def state(self) -> OracleReadContextState:
        return self._state

    @property
    def active_query_id(self) -> UUID | None:
        return self._transport.active_query_id

    def read(
        self,
        query: OracleQuery,
        max_records: int,
    ) -> OracleReadResult:
        self._require_active()
        self._transport.require_owner_thread()
        if type(query) is not OracleQuery:
            raise TypeError("Oracle read query must be OracleQuery")
        _require_query_owned_capacity(query, self._transport.limits)
        fetch_limits = build_oracle_fetch_limits(
            self._transport.limits,
            max_records,
            tuple(projection.kind for projection in query.projections),
            tuple(projection.max_bytes for projection in query.projections),
            tuple(projection.max_driver_bytes for projection in query.projections),
            self._transport.retained_thin_chunk_buffer_bytes,
        )
        _require_source_capacity(self._source_budget, fetch_limits, 1)
        _validate_query_against_limits(query, fetch_limits, self._transport.limits)
        deadline = _source_deadline(self._source_budget)
        charge = self._source_budget.dispatch_query(
            self._source_direction,
            query.full_scans,
        )
        try:
            return self._transport.execute_budgeted(
                query,
                fetch_limits,
                charge,
                deadline,
            )
        except (
            OracleTransportError,
            PostgresReadDeadlineExceededError,
            PostgresSourceBudgetExceededError,
        ):
            self._state = OracleReadContextState.LOST
            raise

    def close(self) -> None:
        if self._state is OracleReadContextState.CLOSED:
            return
        try:
            if not self._transport.closed:
                self._transport.rollback_and_close()
            elif not self._transport.cleanup_succeeded:
                raise OracleCloseError(
                    "Oracle read context cleanup remains unconfirmed after transport retirement: "
                    f"connection_close_confirmed="
                    f"{self._transport.connection_close_confirmed}"
                )
        except OracleTransportError:
            self._state = OracleReadContextState.LOST
            raise
        self._state = OracleReadContextState.CLOSED

    def _require_active(self) -> None:
        if self._state is OracleReadContextState.CLOSED:
            raise OracleContextClosedError("Oracle read context is closed")
        if self._state is OracleReadContextState.LOST:
            raise OracleContextLostError("Oracle read context was lost and cannot be resumed")


def open_oracle_read_context(
    settings: OracleConnectionSettings,
    retry_policy: OracleRetryPolicy,
    transport_limits: OracleTransportLimits,
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
    runtime_profile: OracleRuntimeProfile,
) -> OracleReadContext:
    if not isinstance(cast(object, settings), OracleConnectionSettings):
        raise TypeError("Oracle settings must be OracleConnectionSettings")
    if type(retry_policy) is not OracleRetryPolicy:
        raise TypeError("Oracle retry policy must be OracleRetryPolicy")
    if type(transport_limits) is not OracleTransportLimits:
        raise TypeError("Oracle transport limits must be OracleTransportLimits")
    if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
        raise TypeError("Oracle source budget must be PostgresSourceBudgetAttempt")
    if source_direction is not PostgresSourceDirection.REFERENCE:
        raise ValueError("Oracle can be opened only as a reference source")
    if not isinstance(cast(object, runtime_profile), OracleRuntimeProfile):
        raise TypeError("Oracle runtime profile must be OracleRuntimeProfile")
    if not oracledb.is_thin_mode():
        raise UnsupportedOracleProfileError(
            "Oracle profile requires python-oracledb Thin mode, but Thick mode is initialized"
        )
    transaction_control = _OracleReadOnlyTransaction(uuid4())
    profile_query = _profile_query()
    _require_query_owned_capacity(profile_query, transport_limits)
    profile_limits = build_oracle_fetch_limits(
        transport_limits,
        1,
        tuple(projection.kind for projection in profile_query.projections),
        tuple(projection.max_bytes for projection in profile_query.projections),
        tuple(projection.max_driver_bytes for projection in profile_query.projections),
        ORACLE_THIN_BASELINE_RETAINED_BYTES,
    )
    _validate_read_only_transaction_against_limits(transaction_control, transport_limits)
    _validate_query_against_limits(profile_query, profile_limits, transport_limits)
    _require_source_capacity(source_budget, profile_limits, 2)

    started_at = datetime.now(UTC)
    context_id = uuid4()
    transport = _open_oracle_transport_budgeted(
        settings,
        retry_policy,
        transport_limits,
        source_budget,
    )
    try:
        transaction_charge = source_budget.dispatch_query(source_direction, 0)
        transport.execute_read_only_transaction_budgeted(
            transaction_control,
            transaction_charge,
            _source_deadline(source_budget),
        )
        profile_charge = source_budget.dispatch_query(source_direction, 0)
        profile_result = transport.execute_budgeted(
            profile_query,
            profile_limits,
            profile_charge,
            _source_deadline(source_budget),
        )
        if len(profile_result.rows) != 1:
            raise OracleDataValidationError(
                "Oracle profile query must return exactly one row: "
                f"actual={len(profile_result.rows)}"
            )
        profile = _server_profile_from_row(
            runtime_profile, transport.evidence, profile_result.rows[0]
        )
        transport.bind_session_identity(profile.session_id)
        evidence = OracleReadContextEvidence(
            context_id=context_id,
            engine="oracle",
            server_version=profile.driver.server_version,
            strategy="transaction_read_only_session_unprotected",
            snapshot_locator=None,
            started_at=started_at,
            session_id=profile.session_id,
            audit_session_id=profile.audit_session_id,
            allowed_concurrency=1,
            limitations=(
                "the READ ONLY transaction cannot be reopened after this context closes",
                "the stable cut depends on source undo retention and may fail with ORA-01555",
                "Oracle scalar empty strings are indistinguishable from NULL",
                "one active query is allowed on this physical connection",
                "coordinator memory admission covers modeled Python objects and audited Thin "
                "buffers, not whole-process RSS or native allocator state",
                "round-trip call_timeout does not provide process-level hard cancellation for "
                "name resolution, connect, or cleanup",
                "dataset and readiness object identity are not bound or DDL-protected",
                "VPD, views, synonyms, database links, virtual columns, and hidden columns "
                "are not yet admitted",
            ),
        )
        context = OracleReadContext(
            transport,
            profile,
            evidence,
            source_budget,
            source_direction,
        )
        profile_charge.require_fetch_deadline()
        _oracle_call_timeout_milliseconds(
            profile_result.completion_deadline_nanoseconds,
            "profile context assembly",
        )
        return context
    except (
        OracleTransportError,
        PostgresReadDeadlineExceededError,
        PostgresSourceBudgetExceededError,
    ) as error:
        if not transport.closed:
            try:
                transport.rollback_and_close()
            except OracleCloseError as close_error:
                error.add_note(
                    f"Oracle context cleanup also failed: cleanup_error={str(close_error)!r}"
                )
        raise


def _profile_query() -> OracleQuery:
    projections = (
        OracleProjection("DB_NAME", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("DB_UNIQUE_NAME", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("INSTANCE_NAME", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("SERVICE_NAME", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("SESSION_USER", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("AUTHENTICATED_IDENTITY", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("PROXY_USER", OracleProjectionKind.TEXT, True, 128, 512),
        OracleProjection("CURRENT_SCHEMA", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("IS_DBA", OracleProjectionKind.ASCII, False, 5, 20),
        OracleProjection("SESSION_ID", OracleProjectionKind.ASCII, False, 20, 80),
        OracleProjection("AUDIT_SESSION_ID", OracleProjectionKind.ASCII, False, 20, 80),
        OracleProjection("DATABASE_TIMEZONE", OracleProjectionKind.ASCII, False, 64, 256),
        OracleProjection("SESSION_TIMEZONE", OracleProjectionKind.ASCII, False, 64, 256),
        OracleProjection("DATABASE_CHARACTER_SET", OracleProjectionKind.ASCII, False, 128, 512),
        OracleProjection("NATIONAL_CHARACTER_SET", OracleProjectionKind.ASCII, False, 128, 512),
        OracleProjection("NLS_NUMERIC_CHARACTERS", OracleProjectionKind.TEXT, False, 32, 128),
        OracleProjection("NLS_DATE_LANGUAGE", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("NLS_CALENDAR", OracleProjectionKind.TEXT, False, 128, 512),
        OracleProjection("NLS_TIMESTAMP_FORMAT", OracleProjectionKind.TEXT, False, 256, 1_024),
        OracleProjection("NLS_TIMESTAMP_TZ_FORMAT", OracleProjectionKind.TEXT, False, 256, 1_024),
        OracleProjection("KNOWN_HASH", OracleProjectionKind.ASCII, False, 64, 256),
        OracleProjection("UNICODE_HEX", OracleProjectionKind.ASCII, False, 32, 128),
        OracleProjection("CHAR_HEX", OracleProjectionKind.ASCII, False, 32, 128),
        OracleProjection("EMPTY_IS_NULL", OracleProjectionKind.ASCII, False, 1, 4),
    )
    statement = """
SELECT
    CAST(SYS_CONTEXT('USERENV', 'DB_NAME') AS VARCHAR2(128 BYTE)) AS DB_NAME,
    CAST(SYS_CONTEXT('USERENV', 'DB_UNIQUE_NAME') AS VARCHAR2(128 BYTE)) AS DB_UNIQUE_NAME,
    CAST(SYS_CONTEXT('USERENV', 'INSTANCE_NAME') AS VARCHAR2(128 BYTE)) AS INSTANCE_NAME,
    CAST(SYS_CONTEXT('USERENV', 'SERVICE_NAME') AS VARCHAR2(128 BYTE)) AS SERVICE_NAME,
    CAST(SYS_CONTEXT('USERENV', 'SESSION_USER') AS VARCHAR2(128 BYTE)) AS SESSION_USER,
    CAST(SYS_CONTEXT('USERENV', 'AUTHENTICATED_IDENTITY') AS VARCHAR2(128 BYTE))
        AS AUTHENTICATED_IDENTITY,
    CAST(SYS_CONTEXT('USERENV', 'PROXY_USER') AS VARCHAR2(128 BYTE)) AS PROXY_USER,
    CAST(SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') AS VARCHAR2(128 BYTE)) AS CURRENT_SCHEMA,
    CAST(SYS_CONTEXT('USERENV', 'ISDBA') AS VARCHAR2(5 BYTE)) AS IS_DBA,
    CAST(SYS_CONTEXT('USERENV', 'SID') AS VARCHAR2(20 BYTE)) AS SESSION_ID,
    CAST(SYS_CONTEXT('USERENV', 'SESSIONID') AS VARCHAR2(20 BYTE)) AS AUDIT_SESSION_ID,
    CAST(DBTIMEZONE AS VARCHAR2(64 BYTE)) AS DATABASE_TIMEZONE,
    CAST(SESSIONTIMEZONE AS VARCHAR2(64 BYTE)) AS SESSION_TIMEZONE,
    CAST((
        SELECT VALUE FROM NLS_DATABASE_PARAMETERS WHERE PARAMETER = 'NLS_CHARACTERSET'
    ) AS VARCHAR2(128 BYTE)) AS DATABASE_CHARACTER_SET,
    CAST((
        SELECT VALUE FROM NLS_DATABASE_PARAMETERS WHERE PARAMETER = 'NLS_NCHAR_CHARACTERSET'
    ) AS VARCHAR2(128 BYTE)) AS NATIONAL_CHARACTER_SET,
    CAST((
        SELECT VALUE FROM NLS_SESSION_PARAMETERS WHERE PARAMETER = 'NLS_NUMERIC_CHARACTERS'
    ) AS VARCHAR2(32 BYTE)) AS NLS_NUMERIC_CHARACTERS,
    CAST((
        SELECT VALUE FROM NLS_SESSION_PARAMETERS WHERE PARAMETER = 'NLS_DATE_LANGUAGE'
    ) AS VARCHAR2(128 BYTE)) AS NLS_DATE_LANGUAGE,
    CAST((
        SELECT VALUE FROM NLS_SESSION_PARAMETERS WHERE PARAMETER = 'NLS_CALENDAR'
    ) AS VARCHAR2(128 BYTE)) AS NLS_CALENDAR,
    CAST((
        SELECT VALUE FROM NLS_SESSION_PARAMETERS WHERE PARAMETER = 'NLS_TIMESTAMP_FORMAT'
    ) AS VARCHAR2(256 BYTE)) AS NLS_TIMESTAMP_FORMAT,
    CAST((
        SELECT VALUE FROM NLS_SESSION_PARAMETERS WHERE PARAMETER = 'NLS_TIMESTAMP_TZ_FORMAT'
    ) AS VARCHAR2(256 BYTE)) AS NLS_TIMESTAMP_TZ_FORMAT,
    CAST(LOWER(RAWTOHEX(STANDARD_HASH(
        UTL_I18N.STRING_TO_RAW('DFE1', 'AL32UTF8'), 'SHA256'
    ))) AS VARCHAR2(64 BYTE)) AS KNOWN_HASH,
    CAST(LOWER(RAWTOHEX(
        UTL_I18N.STRING_TO_RAW(UNISTR('\\20AC'), 'AL32UTF8')
    )) AS VARCHAR2(32 BYTE)) AS UNICODE_HEX,
    CAST(LOWER(RAWTOHEX(
        UTL_I18N.STRING_TO_RAW(CAST('A' AS CHAR(3)), 'AL32UTF8')
    )) AS VARCHAR2(32 BYTE)) AS CHAR_HEX,
    CAST(CASE WHEN '' IS NULL THEN '1' ELSE '0' END AS VARCHAR2(1 BYTE)) AS EMPTY_IS_NULL
FROM SYS.DUAL
""".strip()
    return OracleQuery(uuid4(), statement, (), projections, 0)


def _open_oracle_transport_budgeted(
    settings: OracleConnectionSettings,
    retry_policy: OracleRetryPolicy,
    limits: OracleTransportLimits,
    source_budget: PostgresSourceBudgetAttempt,
) -> OracleTransport:
    last_error: OracleConnectionError | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        deadline = _source_deadline(source_budget)
        try:
            return _open_oracle_transport_once(settings, limits, deadline)
        except OracleConnectionError as error:
            last_error = error
            if not error.retryable or attempt == retry_policy.max_attempts:
                break
            LOGGER.warning(
                "Oracle connection attempt failed; retrying",
                extra={
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "service_name": settings.service_name,
                    "error_type": type(error).__name__,
                },
            )
            _sleep_oracle_retry_delay(retry_policy.delay_seconds, source_budget, limits)
    if last_error is None:
        raise RuntimeError("Oracle connection retry loop ended without an attempt")
    raise last_error


def _open_oracle_transport_once(
    settings: OracleConnectionSettings,
    limits: OracleTransportLimits,
    deadline: PostgresReadDeadline,
) -> OracleTransport:
    connection: oracledb.Connection | None = None
    try:
        work_deadline_nanoseconds = _oracle_work_deadline_nanoseconds(
            deadline,
            limits.cancellation_reserve_milliseconds,
            "connection attempt",
        )
        connect_timeout_seconds = _oracle_connect_timeout_seconds(
            settings.tcp_connect_timeout_seconds,
            work_deadline_nanoseconds,
        )
        connection = oracledb.connect(
            user=settings.user,
            password=settings.password.get_secret_value(),
            host=settings.host,
            port=settings.port,
            protocol=settings.protocol.value,
            service_name=settings.service_name,
            retry_count=0,
            retry_delay=0,
            tcp_connect_timeout=connect_timeout_seconds,
            ssl_server_dn_match=settings.tls_server_dn_match,
            wallet_location=(
                str(settings.wallet_location) if settings.wallet_location is not None else None
            ),
            mode=oracledb.AUTH_MODE_DEFAULT,
            disable_oob=settings.disable_out_of_band_breaks,
            stmtcachesize=0,
            program=settings.application_name,
            driver_name="forensic-data",
        )
        evidence = _configure_open_oracle_connection(
            connection,
            work_deadline_nanoseconds,
        )
        transport = OracleTransport(
            connection,
            evidence,
            limits,
            deadline.deadline_nanoseconds,
        )
        _oracle_call_timeout_milliseconds(
            work_deadline_nanoseconds,
            "connection finalization",
        )
        return transport
    except oracledb.Error as error:
        connection_close_failed = _close_failed_connection(
            connection,
            limits,
            deadline.deadline_nanoseconds,
        )
        details = _driver_error_details(error)
        retryable = not connection_close_failed and _is_retryable_connection_error(details)
        raise OracleConnectionError(
            (
                "Oracle Thin connection failed: "
                f"host={settings.host!r}, port={settings.port}, "
                f"service_name={settings.service_name!r}, user={settings.user!r}, "
                f"code={details.code}, full_code={details.full_code!r}, "
                f"recoverable={details.recoverable}, "
                f"retryable={retryable}, "
                f"connection_close_failed={connection_close_failed}"
            ),
            retryable,
            details.safe_message,
            None,
            None,
        ) from None
    except UnsupportedOracleProfileError as error:
        connection_close_failed = _close_failed_connection(
            connection,
            limits,
            deadline.deadline_nanoseconds,
        )
        if connection_close_failed:
            error.add_note("Oracle connection cleanup also failed after rejecting Thin mode")
        raise
    except OracleDriverStateError as error:
        connection_close_failed = _close_failed_connection(
            connection,
            limits,
            deadline.deadline_nanoseconds,
        )
        retryable = not connection_close_failed
        raise OracleConnectionError(
            (
                "Oracle Thin connection failed outside the structured driver error "
                "boundary: "
                f"host={settings.host!r}, port={settings.port}, "
                f"service_name={settings.service_name!r}, user={settings.user!r}, "
                f"failure_type={type(error).__name__!r}, retryable={retryable}, "
                f"connection_close_failed={connection_close_failed}"
            ),
            retryable,
            None,
            None,
            None,
        ) from None
    except OSError as error:
        connection_close_failed = _close_failed_connection(
            connection,
            limits,
            deadline.deadline_nanoseconds,
        )
        retryable = not connection_close_failed
        os_error_code, os_message = _safe_os_error_details(error)
        raise OracleConnectionError(
            (
                "Oracle Thin connection failed at the operating-system boundary: "
                f"host={settings.host!r}, port={settings.port}, "
                f"service_name={settings.service_name!r}, user={settings.user!r}, "
                f"retryable={retryable}, "
                f"connection_close_failed={connection_close_failed}"
            ),
            retryable,
            None,
            os_error_code,
            os_message,
        ) from None
    except OracleDataValidationError as error:
        connection_close_failed = _close_failed_connection(
            connection,
            limits,
            deadline.deadline_nanoseconds,
        )
        raise OracleConnectionError(
            (
                "Oracle connection property validation failed: "
                f"host={settings.host!r}, port={settings.port}, "
                f"service_name={settings.service_name!r}, user={settings.user!r}, "
                f"validation_error={type(error).__name__!r}, "
                f"connection_close_failed={connection_close_failed}"
            ),
            False,
            None,
            None,
            None,
        ) from None
    except (PostgresReadDeadlineExceededError, PostgresSourceBudgetExceededError) as error:
        connection_close_failed = _close_failed_connection(
            connection,
            limits,
            deadline.deadline_nanoseconds,
        )
        if connection_close_failed:
            error.add_note("Oracle connection cleanup also failed after source budget rejection")
        raise


def _configure_open_oracle_connection(
    connection: oracledb.Connection,
    work_deadline_nanoseconds: int,
) -> OracleDriverEvidence:
    _set_oracle_call_timeout(
        connection,
        _oracle_call_timeout_milliseconds(
            work_deadline_nanoseconds,
            "connection completion",
        ),
        "connection completion",
    )
    try:
        connection.autocommit = False
        thin_mode = connection.thin
        server_version_value = connection.version
        requested_username_value = connection.username
    except (AttributeError, OSError, OverflowError):
        raise OracleDriverStateError(
            "python-oracledb could not expose the opened connection profile"
        ) from None
    if not thin_mode:
        raise UnsupportedOracleProfileError(
            "Oracle connection is not using required python-oracledb Thin mode"
        )
    return OracleDriverEvidence(
        driver_version=_required_connection_text(oracledb.__version__, "driver version"),
        server_version=_required_connection_text(server_version_value, "server version"),
        thin_mode=True,
        requested_username=_required_connection_text(
            requested_username_value,
            "requested connection username",
        ),
    )


def _server_profile_from_row(
    runtime_profile: OracleRuntimeProfile,
    driver: OracleDriverEvidence,
    row: OracleRow,
) -> OracleServerProfile:
    if len(row) != 24:
        raise OracleDataValidationError(
            "Oracle profile query returned an unexpected field count: "
            f"expected=24, actual={len(row)}"
        )
    database_name = _required_text(row[0], "database name")
    database_unique_name = _required_text(row[1], "database unique name")
    instance_name = _required_text(row[2], "instance name")
    service_name = _required_text(row[3], "service name")
    session_user = _required_text(row[4], "session user")
    authenticated_identity = _required_text(row[5], "authenticated identity")
    proxy_user = _optional_text(row[6], "proxy user")
    current_schema = _required_text(row[7], "current schema")
    is_dba = _required_ascii_text(row[8], "ISDBA")
    session_id = _positive_ascii_integer(row[9], "session ID")
    audit_session_id = _positive_ascii_integer(row[10], "audit session ID")
    database_timezone = _required_ascii_text(row[11], "database timezone")
    session_timezone = _required_ascii_text(row[12], "session timezone")
    database_character_set = _required_ascii_text(row[13], "database character set")
    national_character_set = _required_ascii_text(row[14], "national character set")
    nls_numeric_characters = _required_text(row[15], "NLS numeric characters")
    nls_date_language = _required_text(row[16], "NLS date language")
    nls_calendar = _required_text(row[17], "NLS calendar")
    nls_timestamp_format = _required_text(row[18], "NLS timestamp format")
    nls_timestamp_tz_format = _required_text(row[19], "NLS timestamp TZ format")
    known_hash = _required_ascii_text(row[20], "known SHA-256")
    unicode_hex = _required_ascii_text(row[21], "Unicode conversion probe")
    char_hex = _required_ascii_text(row[22], "CHAR padding probe")
    empty_is_null = _required_ascii_text(row[23], "empty-string probe")

    failures: list[str] = []
    if not driver.thin_mode:
        failures.append("driver reported Thick mode")
    if authenticated_identity != session_user:
        failures.append(
            f"authenticated_identity={authenticated_identity!r} differs from "
            f"session_user={session_user!r}"
        )
    if proxy_user is not None:
        failures.append(f"proxy_user={proxy_user!r}, required=None")
    if current_schema != session_user:
        failures.append(
            f"current_schema={current_schema!r} differs from session_user={session_user!r}"
        )
    if session_user.upper() == "SYS":
        failures.append("SYS sessions are outside the Oracle source profile")
    if is_dba != "FALSE":
        failures.append(f"ISDBA={is_dba!r}, required='FALSE'")
    if database_character_set != "AL32UTF8":
        failures.append(f"NLS_CHARACTERSET={database_character_set!r}, required='AL32UTF8'")
    if known_hash != _PROFILE_HASH:
        failures.append("STANDARD_HASH SHA-256 known-answer probe failed")
    if unicode_hex != _PROFILE_UNICODE_HEX:
        failures.append("AL32UTF8 Unicode known-answer probe failed")
    if char_hex != _PROFILE_CHAR_HEX:
        failures.append("Oracle CHAR right-padding probe failed")
    if empty_is_null != "1":
        failures.append("Oracle scalar empty-string NULL probe failed")
    if failures:
        raise UnsupportedOracleProfileError(
            "Oracle Thin capability profile is unsupported: " + "; ".join(failures)
        )

    return OracleServerProfile(
        runtime_profile=runtime_profile,
        driver=driver,
        database_name=database_name,
        database_unique_name=database_unique_name,
        instance_name=instance_name,
        service_name=service_name,
        session_user=session_user,
        authenticated_identity=authenticated_identity,
        proxy_user=proxy_user,
        current_schema=current_schema,
        session_id=session_id,
        audit_session_id=audit_session_id,
        database_timezone=database_timezone,
        session_timezone=session_timezone,
        database_character_set=database_character_set,
        national_character_set=national_character_set,
        nls_numeric_characters=nls_numeric_characters,
        nls_date_language=nls_date_language,
        nls_calendar=nls_calendar,
        nls_timestamp_format=nls_timestamp_format,
        nls_timestamp_tz_format=nls_timestamp_tz_format,
    )


def _validate_read_only_transaction_against_limits(
    control: _OracleReadOnlyTransaction,
    limits: OracleTransportLimits,
) -> None:
    statement_bytes = _strict_utf8_byte_length(_READ_ONLY_TRANSACTION_STATEMENT)
    if statement_bytes > limits.max_query_bytes:
        raise OracleResultLimitError(
            "Oracle control statement exceeds max_query_bytes before dispatch: "
            f"query_id={control.query_id}, statement_bytes={statement_bytes}, "
            f"max_query_bytes={limits.max_query_bytes}"
        )
    if statement_bytes > limits.max_request_bytes:
        raise OracleResultLimitError(
            "Oracle control statement exceeds max_request_bytes before dispatch: "
            f"query_id={control.query_id}, statement_bytes={statement_bytes}, "
            f"max_request_bytes={limits.max_request_bytes}"
        )
    coordinator_request_bytes = _read_only_transaction_request_memory_bytes(
        control,
        statement_bytes,
    )
    if coordinator_request_bytes > limits.max_coordinator_bytes:
        raise OracleResultLimitError(
            "Oracle control statement exceeds the coordinator memory budget before "
            "dispatch: "
            f"query_id={control.query_id}, "
            f"coordinator_request_bytes={coordinator_request_bytes}, "
            f"max_coordinator_bytes={limits.max_coordinator_bytes}"
        )


def _validate_query_against_limits(
    query: OracleQuery,
    fetch_limits: OracleFetchLimits,
    transport_limits: OracleTransportLimits,
) -> None:
    _require_oracle_select_statement(query.statement)
    _require_query_owned_capacity(query, transport_limits)
    if len(query.projections) != len(fetch_limits.projection_max_bytes):
        raise ValueError("Oracle query projections differ from the assembled fetch limits")
    for index, projection in enumerate(query.projections):
        if (
            projection.kind is not fetch_limits.projection_kinds[index]
            or projection.max_bytes != fetch_limits.projection_max_bytes[index]
            or projection.max_driver_bytes != fetch_limits.projection_driver_max_bytes[index]
        ):
            raise ValueError("Oracle query projections differ from the assembled fetch limits")
    statement_bytes = _QUERY_ID_PREFIX_BYTES + _strict_utf8_byte_length(query.statement)
    if statement_bytes > transport_limits.max_query_bytes:
        raise OracleResultLimitError(
            "Oracle query exceeds max_query_bytes before dispatch: "
            f"query_id={query.query_id}, statement_bytes={statement_bytes}, "
            f"max_query_bytes={transport_limits.max_query_bytes}"
        )
    if len(query.parameters) > transport_limits.max_bind_parameters:
        raise OracleResultLimitError(
            "Oracle query exceeds max_bind_parameters before dispatch: "
            f"query_id={query.query_id}, bind_parameters={len(query.parameters)}, "
            f"max_bind_parameters={transport_limits.max_bind_parameters}"
        )
    bind_occurrences = len(_oracle_bind_occurrence_names(query.statement))
    if bind_occurrences > transport_limits.max_bind_occurrences:
        raise OracleResultLimitError(
            "Oracle query exceeds max_bind_occurrences before dispatch: "
            f"query_id={query.query_id}, bind_occurrences={bind_occurrences}, "
            f"max_bind_occurrences={transport_limits.max_bind_occurrences}"
        )
    total_bind_bytes = 0
    max_driver_bind_value_bytes = 0
    bind_name_bytes = 0
    for parameter in query.parameters:
        value_bytes = _bind_value_bytes(parameter.value)
        if value_bytes > transport_limits.max_bind_value_bytes:
            raise OracleResultLimitError(
                "Oracle bind value exceeds max_bind_value_bytes before dispatch: "
                f"query_id={query.query_id}, bind_name={parameter.name!r}, "
                f"value_bytes={value_bytes}, "
                f"max_bind_value_bytes={transport_limits.max_bind_value_bytes}"
            )
        total_bind_bytes += value_bytes
        max_driver_bind_value_bytes = max(max_driver_bind_value_bytes, max(1, value_bytes))
        bind_name_bytes += len(parameter.name)
    if total_bind_bytes > transport_limits.max_bind_total_bytes:
        raise OracleResultLimitError(
            "Oracle bind values exceed max_bind_total_bytes before dispatch: "
            f"query_id={query.query_id}, bind_total_bytes={total_bind_bytes}, "
            f"max_bind_total_bytes={transport_limits.max_bind_total_bytes}"
        )
    driver_bind_payload_bytes = bind_occurrences * max_driver_bind_value_bytes
    request_bytes = statement_bytes + bind_name_bytes + driver_bind_payload_bytes
    if request_bytes > transport_limits.max_request_bytes:
        raise OracleResultLimitError(
            "Oracle query and driver bind payload exceed max_request_bytes before dispatch: "
            f"query_id={query.query_id}, request_bytes={request_bytes}, "
            f"max_request_bytes={transport_limits.max_request_bytes}"
        )
    coordinator_request_bytes = _query_request_memory_bytes(
        query,
        statement_bytes,
        bind_name_bytes,
        driver_bind_payload_bytes,
        bind_occurrences,
    )
    coordinator_peak_bytes = coordinator_request_bytes + fetch_limits.coordinator_response_bytes
    if coordinator_peak_bytes > transport_limits.max_coordinator_bytes:
        raise OracleResultLimitError(
            "Oracle query exceeds the coordinator memory budget before dispatch: "
            f"query_id={query.query_id}, "
            f"coordinator_request_bytes={coordinator_request_bytes}, "
            f"coordinator_response_bytes={fetch_limits.coordinator_response_bytes}, "
            f"coordinator_peak_bytes={coordinator_peak_bytes}, "
            f"max_coordinator_bytes={transport_limits.max_coordinator_bytes}"
        )


def _require_query_owned_capacity(
    query: OracleQuery,
    limits: OracleTransportLimits,
) -> None:
    query_owned_bytes = _query_owned_memory_bytes(query)
    assembly_bytes = (
        query_owned_bytes
        + (3 * tuple_storage_bytes(len(query.projections)))
        + _ORACLE_OPERATION_RESERVATION_BYTES
    )
    if assembly_bytes > limits.max_coordinator_bytes:
        raise OracleResultLimitError(
            "Oracle query object exceeds the coordinator memory budget before assembly: "
            f"query_id={query.query_id}, query_owned_bytes={query_owned_bytes}, "
            f"assembly_bytes={assembly_bytes}, "
            f"max_coordinator_bytes={limits.max_coordinator_bytes}"
        )


def _read_only_transaction_request_memory_bytes(
    control: _OracleReadOnlyTransaction,
    statement_bytes: int,
) -> int:
    return (
        getsizeof(control)
        + getsizeof(control.query_id)
        + getsizeof(_READ_ONLY_TRANSACTION_STATEMENT)
        + (2 * statement_bytes)
        + _ORACLE_OPERATION_RESERVATION_BYTES
    )


def _query_request_memory_bytes(
    query: OracleQuery,
    statement_bytes: int,
    bind_name_bytes: int,
    driver_bind_payload_bytes: int,
    bind_occurrences: int,
) -> int:
    bind_count = len(query.parameters)
    driver_request_bytes = statement_bytes + bind_name_bytes + driver_bind_payload_bytes
    annotated_statement_bytes = _MAX_UNICODE_TEXT_BASE_BYTES + (
        4 * (len(query.statement) + _QUERY_ID_PREFIX_BYTES)
    )
    return (
        _query_owned_memory_bytes(query)
        + annotated_statement_bytes
        + dict_storage_bytes(bind_count)
        + (bind_count * _ORACLE_DRIVER_BIND_RESERVATION_BYTES)
        + (bind_occurrences * _ORACLE_DRIVER_BIND_RESERVATION_BYTES)
        + (2 * driver_request_bytes)
        + ORACLE_DECIMAL_TUPLE_SCRATCH_BYTES
        + _ORACLE_OPERATION_RESERVATION_BYTES
    )


def _query_owned_memory_bytes(query: OracleQuery) -> int:
    owned_bytes = (
        getsizeof(query)
        + getsizeof(query.query_id)
        + getsizeof(query.statement)
        + getsizeof(query.parameters)
        + getsizeof(query.projections)
        + getsizeof(query.full_scans)
    )
    for parameter in query.parameters:
        owned_bytes += getsizeof(parameter) + getsizeof(parameter.name) + getsizeof(parameter.value)
    for projection in query.projections:
        owned_bytes += (
            getsizeof(projection)
            + getsizeof(projection.name)
            + getsizeof(projection.kind)
            + getsizeof(projection.nullable)
            + getsizeof(projection.max_bytes)
            + getsizeof(projection.max_driver_bytes)
        )
    return owned_bytes


def _validated_column_description(
    raw_info: object,
    projection: OracleProjection,
    column_index: int,
) -> _OracleColumnDescription:
    try:
        if not isinstance(raw_info, _OracleFetchInfoProtocol):
            raise OracleDataValidationError(
                f"Oracle returned invalid result metadata: column_index={column_index}"
            )
        raw_type_code = raw_info.type_code
        if not isinstance(raw_type_code, _OracleDbTypeProtocol):
            raise OracleDataValidationError(
                f"Oracle returned invalid result type metadata: column_index={column_index}"
            )
        info = _OracleColumnDescription(
            name=raw_info.name,
            type_name=raw_type_code.name,
            display_size=raw_info.display_size,
            internal_size=raw_info.internal_size,
            precision=raw_info.precision,
            scale=raw_info.scale,
        )
    except (AttributeError, OSError):
        raise OracleDriverStateError(
            f"python-oracledb could not expose bounded result metadata: column_index={column_index}"
        ) from None
    if info.name != projection.name:
        raise OracleDataValidationError(
            "Oracle result projection name changed: "
            f"column_index={column_index}, expected={projection.name!r}, "
            f"actual={info.name!r}"
        )
    declared_bytes = _declared_projection_bytes(info, projection, column_index)
    declared_limit = projection.max_bytes
    if projection.kind in (OracleProjectionKind.ASCII, OracleProjectionKind.TEXT):
        declared_limit = projection.max_driver_bytes
    if declared_bytes > declared_limit:
        raise OracleResultLimitError(
            "Oracle result projection exceeds its declared byte limit before fetch: "
            f"column_index={column_index}, declared_bytes={declared_bytes}, "
            f"max_bytes={declared_limit}"
        )
    return info


def _declared_projection_bytes(
    info: _OracleColumnDescription,
    projection: OracleProjection,
    column_index: int,
) -> int:
    if projection.kind in (OracleProjectionKind.ASCII, OracleProjectionKind.TEXT):
        if info.type_name != "DB_TYPE_VARCHAR":
            raise OracleDataValidationError(
                "Oracle text projection has an unexpected database type: "
                f"column_index={column_index}, type_name={info.type_name!r}"
            )
        display_size = _required_declared_size(info.display_size, column_index)
        internal_size = _required_declared_size(info.internal_size, column_index)
        if internal_size > 4 * display_size:
            raise OracleResultLimitError(
                "Oracle text projection has an unsupported driver buffer ratio: "
                f"column_index={column_index}, display_size={display_size}, "
                f"internal_size={internal_size}"
            )
        if display_size > projection.max_bytes:
            raise OracleResultLimitError(
                "Oracle text projection display width exceeds its logical byte limit: "
                f"column_index={column_index}, display_size={display_size}, "
                f"max_bytes={projection.max_bytes}"
            )
        return internal_size
    if projection.kind is OracleProjectionKind.RAW:
        if info.type_name != "DB_TYPE_RAW":
            raise OracleDataValidationError(
                "Oracle RAW projection has an unexpected database type: "
                f"column_index={column_index}, type_name={info.type_name!r}"
            )
        return _required_declared_size(info.internal_size, column_index)
    if info.type_name != "DB_TYPE_NUMBER":
        raise OracleDataValidationError(
            "Oracle decimal projection has an unexpected database type: "
            f"column_index={column_index}, type_name={info.type_name!r}"
        )
    precision = info.precision
    scale = info.scale
    if type(precision) is not int or not 1 <= precision <= 38 or type(scale) is not int:
        raise OracleResultLimitError(
            "Oracle NUMBER projection has unknown or unsupported declared precision: "
            f"column_index={column_index}, precision={precision!r}, scale={scale!r}"
        )
    if scale >= 0:
        return max(precision - scale, 1) + (scale + 1 if scale > 0 else 0) + 1
    return precision + abs(scale) + 1


def _validated_driver_row(
    raw_row: object,
    description: tuple[_OracleColumnDescription, ...],
    projections: tuple[OracleProjection, ...],
    limits: OracleFetchLimits,
) -> tuple[OracleRow, int]:
    if type(raw_row) is not tuple:
        raise OracleDataValidationError("python-oracledb fetch returned a non-tuple row")
    row = cast(tuple[object, ...], raw_row)
    if len(row) != len(description) or len(row) != len(projections):
        raise OracleDataValidationError(
            "Oracle row arity differs from its result description: "
            f"description={len(description)}, projections={len(projections)}, actual={len(row)}"
        )
    values: list[OracleValue] = []
    record_bytes = 0
    for index, (raw_value, projection) in enumerate(zip(row, projections, strict=True)):
        value, value_bytes = _validated_driver_value(raw_value, projection, index)
        if value_bytes > projection.max_bytes:
            raise OracleResultLimitError(
                "Oracle value exceeds its projection byte limit after fetch: "
                f"column_index={index}, value_bytes={value_bytes}, "
                f"max_bytes={projection.max_bytes}"
            )
        values.append(value)
        record_bytes += value_bytes
    if record_bytes > limits.max_record_bytes:
        raise OracleResultLimitError(
            "Oracle row exceeds max_record_bytes after fetch: "
            f"record_bytes={record_bytes}, max_record_bytes={limits.max_record_bytes}"
        )
    return tuple(values), record_bytes


def _validated_driver_value(
    raw_value: object,
    projection: OracleProjection,
    column_index: int,
) -> tuple[OracleValue, int]:
    if raw_value is None:
        if not projection.nullable:
            raise OracleDataValidationError(
                f"Oracle returned NULL for a non-null projection: column_index={column_index}"
            )
        return None, 0
    if projection.kind is OracleProjectionKind.ASCII:
        if type(raw_value) is not str:
            raise OracleDataValidationError(
                "Oracle ASCII projection returned an unexpected Python type: "
                f"column_index={column_index}, python_type={type(raw_value).__name__!r}"
            )
        if not raw_value.isascii():
            raise OracleLossyTransportError(
                f"Oracle ASCII projection returned non-ASCII text: column_index={column_index}"
            )
        return raw_value, len(raw_value)
    if projection.kind is OracleProjectionKind.TEXT:
        if type(raw_value) is not str:
            raise OracleDataValidationError(
                "Oracle text projection returned an unexpected Python type: "
                f"column_index={column_index}, python_type={type(raw_value).__name__!r}"
            )
        try:
            value_bytes = _strict_utf8_byte_length(raw_value)
        except UnicodeEncodeError:
            raise OracleLossyTransportError(
                "Oracle text projection contains an unpaired surrogate: "
                f"column_index={column_index}"
            ) from None
        return raw_value, value_bytes
    if projection.kind is OracleProjectionKind.RAW:
        if type(raw_value) is not bytes:
            raise OracleDataValidationError(
                "Oracle RAW projection returned an unexpected Python type: "
                f"column_index={column_index}, python_type={type(raw_value).__name__!r}"
            )
        return raw_value, len(raw_value)
    if type(raw_value) is not Decimal:
        if isinstance(raw_value, (float, int)):
            raise OracleLossyTransportError(
                "Oracle NUMBER projection did not use exact Decimal transport: "
                f"column_index={column_index}, python_type={type(raw_value).__name__!r}"
            )
        raise OracleDataValidationError(
            "Oracle NUMBER projection returned an unexpected Python type: "
            f"column_index={column_index}, python_type={type(raw_value).__name__!r}"
        )
    if not raw_value.is_finite():
        raise OracleDataValidationError(
            f"Oracle NUMBER projection returned a non-finite Decimal: column_index={column_index}"
        )
    if raw_value.is_zero() and raw_value.as_tuple().sign:
        raise OracleDataValidationError(
            f"Oracle NUMBER projection returned a negative zero: column_index={column_index}"
        )
    return raw_value, _decimal_transport_bytes(raw_value)


def _driver_error_details(error: oracledb.Error) -> _OracleErrorDetails:
    if len(error.args) != 1:
        raise OracleDataValidationError(
            "python-oracledb error did not expose exactly one structured detail value"
        ) from None
    raw_details = error.args[0]
    if not isinstance(raw_details, _OracleErrorDetailsProtocol):
        raise OracleDataValidationError(
            "python-oracledb error did not expose code/full_code/message/recoverability"
        ) from None
    if type(raw_details.code) is not int or raw_details.code < 0:
        raise OracleDataValidationError("python-oracledb error code is invalid") from None
    if type(raw_details.full_code) is not str or not raw_details.full_code:
        raise OracleDataValidationError("python-oracledb full error code is invalid") from None
    _validate_oracle_error_message(raw_details.message)
    if type(raw_details.isrecoverable) is not bool:
        raise OracleDataValidationError("python-oracledb recoverability flag is invalid") from None
    return _OracleErrorDetails(
        code=raw_details.code,
        full_code=raw_details.full_code,
        safe_message=_safe_oracle_error_message(
            raw_details.code,
            raw_details.full_code,
        ),
        recoverable=raw_details.isrecoverable,
    )


def _validate_oracle_error_message(message: str) -> None:
    if type(message) is not str or not message:
        raise OracleDataValidationError("python-oracledb error message is invalid") from None
    try:
        message_bytes = _strict_utf8_byte_length(message)
    except UnicodeEncodeError:
        raise OracleDataValidationError(
            "python-oracledb error message encoding is invalid"
        ) from None
    if message_bytes > _MAX_ORACLE_ERROR_MESSAGE_BYTES:
        raise OracleDataValidationError(
            "python-oracledb error message exceeds the transport boundary: "
            f"message_bytes={message_bytes}, maximum={_MAX_ORACLE_ERROR_MESSAGE_BYTES}"
        ) from None


def _validate_os_error_message(message: str) -> None:
    if type(message) is not str or not message:
        raise ValueError("Oracle operating-system error message must be non-empty text")
    try:
        message_bytes = _strict_utf8_byte_length(message)
    except UnicodeEncodeError:
        raise ValueError("Oracle operating-system error message encoding is invalid") from None
    if message_bytes > _MAX_ORACLE_ERROR_MESSAGE_BYTES:
        raise ValueError(
            "Oracle operating-system error message exceeds the transport boundary: "
            f"message_bytes={message_bytes}, maximum={_MAX_ORACLE_ERROR_MESSAGE_BYTES}"
        )


def _safe_os_error_details(error: OSError) -> tuple[int | None, str]:
    error_code = error.errno if type(error.errno) is int else None
    raw_message = error.strerror
    if type(raw_message) is not str or not raw_message:
        return error_code, "operating-system error text unavailable"
    try:
        message_bytes = _strict_utf8_byte_length(raw_message)
    except UnicodeEncodeError:
        return error_code, "operating-system error text redacted due to invalid encoding"
    if message_bytes > _MAX_ORACLE_ERROR_MESSAGE_BYTES:
        return error_code, "operating-system error text redacted because it exceeded the limit"
    return error_code, raw_message


def _safe_oracle_error_message(code: int, full_code: str) -> str:
    if full_code == "DPY-4024":
        return "python-oracledb call timeout exceeded"
    if full_code == "DPY-6005":
        return "python-oracledb could not connect to Oracle"
    if code == 1_555:
        return "Oracle read consistency was lost"
    if code == 1_466:
        return "Oracle object definition changed during read"
    return "Oracle native error text was redacted"


def _is_retryable_connection_error(details: _OracleErrorDetails) -> bool:
    return (
        details.recoverable
        or details.code in _RETRYABLE_ORACLE_CONNECT_CODES
        or details.full_code in _RETRYABLE_DRIVER_CONNECT_FULL_CODES
    )


def _oracle_call_timeout_milliseconds(
    work_deadline_nanoseconds: int,
    operation: str,
) -> int:
    if type(work_deadline_nanoseconds) is not int or work_deadline_nanoseconds < 1:
        raise ValueError("Oracle work deadline must be a positive integer")
    remaining_nanoseconds = work_deadline_nanoseconds - time.monotonic_ns()
    remaining_milliseconds = remaining_nanoseconds // 1_000_000
    if remaining_milliseconds < 1:
        raise PostgresReadDeadlineExceededError(
            f"Oracle source operation reached its immutable deadline: operation={operation!r}"
        )
    if remaining_milliseconds > MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS:
        raise ValueError(
            "Oracle work deadline exceeds python-oracledb call_timeout: "
            f"operation={operation!r}, "
            f"timeout_milliseconds={remaining_milliseconds}, "
            f"maximum={MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS}"
        )
    return remaining_milliseconds


def _set_oracle_call_timeout(
    connection: oracledb.Connection,
    timeout_milliseconds: int,
    operation: str,
) -> None:
    try:
        connection.call_timeout = timeout_milliseconds
    except (AttributeError, OSError, OverflowError):
        raise OracleDriverStateError(
            f"python-oracledb could not arm a bounded source round trip: operation={operation!r}"
        ) from None


def _oracle_work_deadline_nanoseconds(
    deadline: PostgresReadDeadline,
    cancellation_reserve_milliseconds: int,
    operation: str,
) -> int:
    _require_deadline(deadline)
    if type(cancellation_reserve_milliseconds) is not int or cancellation_reserve_milliseconds < 1:
        raise ValueError("Oracle cancellation reserve must be a positive integer")
    now_nanoseconds = time.monotonic_ns()
    work_deadline_nanoseconds = min(
        now_nanoseconds + deadline.statement_timeout_milliseconds * 1_000_000,
        deadline.deadline_nanoseconds - cancellation_reserve_milliseconds * 1_000_000,
    )
    work_interval_nanoseconds = work_deadline_nanoseconds - now_nanoseconds
    if work_interval_nanoseconds < 1_000_000:
        raise PostgresReadDeadlineExceededError(
            "Oracle source operation reached the immutable whole-run deadline reserve: "
            f"operation={operation!r}, "
            f"cancellation_reserve_milliseconds={cancellation_reserve_milliseconds}"
        )
    if work_interval_nanoseconds // 1_000_000 > MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS:
        raise ValueError(
            "Oracle effective operation deadline exceeds python-oracledb call_timeout: "
            f"operation={operation!r}, "
            f"timeout_milliseconds={work_interval_nanoseconds // 1_000_000}, "
            f"maximum={MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS}"
        )
    return work_deadline_nanoseconds


def _oracle_connect_timeout_seconds(
    configured_seconds: float,
    work_deadline_nanoseconds: int,
) -> float:
    available_milliseconds = _oracle_call_timeout_milliseconds(
        work_deadline_nanoseconds,
        "connection attempt",
    )
    return min(configured_seconds, available_milliseconds / 1_000)


def _source_deadline(source_budget: PostgresSourceBudgetAttempt) -> PostgresReadDeadline:
    return source_budget.read_deadline(source_budget.effective_statement_timeout_milliseconds())


def _require_source_capacity(
    source_budget: PostgresSourceBudgetAttempt,
    fetch_limits: OracleFetchLimits,
    required_queries: int,
) -> None:
    remaining = source_budget.remaining()
    if type(required_queries) is not int or required_queries < 1:
        raise ValueError("Oracle required_queries must be a positive integer")
    if required_queries > remaining.queries:
        raise PostgresSourceBudgetExceededError(
            "Oracle operation exceeds remaining whole-run query capacity"
        )
    if fetch_limits.max_received_records > remaining.fetched_records:
        raise PostgresSourceBudgetExceededError(
            "Oracle query and overflow probe exceed remaining whole-run fetched-record capacity"
        )
    if fetch_limits.max_received_bytes > remaining.result_bytes:
        raise PostgresSourceBudgetExceededError(
            "Oracle query and overflow probe exceed remaining whole-run result-byte capacity"
        )


def _sleep_oracle_retry_delay(
    delay_seconds: float,
    source_budget: PostgresSourceBudgetAttempt,
    limits: OracleTransportLimits,
) -> None:
    if delay_seconds == 0:
        _require_whole_run_reserve(source_budget, limits, "zero-second retry delay")
        return
    delay_numerator, delay_denominator = delay_seconds.as_integer_ratio()
    delay_nanoseconds = (
        delay_numerator * 1_000_000_000 + delay_denominator - 1
    ) // delay_denominator
    available_nanoseconds = _whole_run_available_nanoseconds(source_budget, limits)
    if delay_nanoseconds >= available_nanoseconds:
        raise PostgresReadDeadlineExceededError(
            "Oracle retry delay would consume the immutable deadline reserve"
        )
    time.sleep(delay_seconds)
    _require_whole_run_reserve(source_budget, limits, "retry delay completion")


def _whole_run_available_nanoseconds(
    source_budget: PostgresSourceBudgetAttempt,
    limits: OracleTransportLimits,
) -> int:
    remaining_nanoseconds = source_budget.remaining().deadline_nanoseconds - time.monotonic_ns()
    return remaining_nanoseconds - limits.cancellation_reserve_milliseconds * 1_000_000


def _require_whole_run_reserve(
    source_budget: PostgresSourceBudgetAttempt,
    limits: OracleTransportLimits,
    operation: str,
) -> None:
    if _whole_run_available_nanoseconds(source_budget, limits) <= 0:
        raise PostgresReadDeadlineExceededError(
            "Oracle source work reached the immutable whole-run deadline reserve: "
            f"operation={operation!r}"
        )


def _close_failed_connection(
    connection: oracledb.Connection | None,
    limits: OracleTransportLimits,
    whole_run_deadline_nanoseconds: int,
) -> bool:
    if connection is None:
        return False
    cleanup_deadline_nanoseconds = _cleanup_deadline_nanoseconds(
        whole_run_deadline_nanoseconds,
        limits,
    )
    disposal = _dispose_oracle_connection(
        connection,
        cleanup_deadline_nanoseconds,
    )
    return disposal.cleanup_failed


def _cleanup_deadline_nanoseconds(
    whole_run_deadline_nanoseconds: int,
    limits: OracleTransportLimits,
) -> int:
    if type(whole_run_deadline_nanoseconds) is not int or whole_run_deadline_nanoseconds < 1:
        raise ValueError("Oracle whole-run cleanup deadline must be a positive integer")
    return min(
        whole_run_deadline_nanoseconds,
        time.monotonic_ns() + limits.cleanup_timeout_milliseconds * 1_000_000,
    )


def _prepare_cleanup_round_trip(
    connection: oracledb.Connection,
    cleanup_deadline_nanoseconds: int,
) -> _OracleCleanupPreparationResult:
    try:
        if not connection.is_healthy():
            return _OracleCleanupPreparationResult(
                _OracleCleanupPreparation.DISCONNECTED,
                None,
            )
        remaining_nanoseconds = cleanup_deadline_nanoseconds - time.monotonic_ns()
        remaining_milliseconds = remaining_nanoseconds // 1_000_000
        if remaining_milliseconds < 1:
            connection.call_timeout = 1
            return _OracleCleanupPreparationResult(
                _OracleCleanupPreparation.EXPIRED_ARMED,
                "cleanup deadline expired before the final Oracle close; armed 1 millisecond",
            )
        connection.call_timeout = remaining_milliseconds
    except (AttributeError, OSError, OverflowError, oracledb.Error) as error:
        return _OracleCleanupPreparationResult(
            _OracleCleanupPreparation.UNAVAILABLE,
            _safe_cleanup_error_summary("call-timeout preparation", error),
        )
    return _OracleCleanupPreparationResult(
        _OracleCleanupPreparation.ROUND_TRIP,
        None,
    )


def _dispose_oracle_connection(
    connection: oracledb.Connection,
    cleanup_deadline_nanoseconds: int,
) -> _OracleConnectionDisposal:
    preparation = _prepare_cleanup_round_trip(
        connection,
        cleanup_deadline_nanoseconds,
    )
    failures: list[str] = []
    if preparation.failure is not None:
        failures.append(preparation.failure)
    close_failed = preparation.state in (
        _OracleCleanupPreparation.EXPIRED_ARMED,
        _OracleCleanupPreparation.UNAVAILABLE,
    )
    close_confirmed = False
    try:
        connection.close()
        close_confirmed = True
    except (AttributeError, OSError, oracledb.Error) as error:
        close_failed = True
        failures.append(_safe_cleanup_error_summary("connection close", error))
        close_confirmed = _finish_disconnected_oracle_close(connection)
        if not close_confirmed:
            failures.append("disconnected Oracle close could not be confirmed")
    deadline_intact = _cleanup_deadline_intact(cleanup_deadline_nanoseconds)
    return _OracleConnectionDisposal(
        close_confirmed,
        close_failed or not close_confirmed or not deadline_intact,
        tuple(failures),
    )


def _finish_disconnected_oracle_close(connection: oracledb.Connection) -> bool:
    try:
        if connection.is_healthy():
            return False
        connection.close()
    except (AttributeError, OSError, oracledb.Error):
        return False
    return True


def _safe_cleanup_error_summary(operation: str, error: BaseException) -> str:
    if isinstance(error, oracledb.Error):
        try:
            details = _driver_error_details(error)
        except OracleDataValidationError:
            return (
                f"{operation} failed: failure_type={type(error).__name__!r}, "
                "driver_details='invalid'"
            )
        return (
            f"{operation} failed: failure_type={type(error).__name__!r}, "
            f"code={details.code}, full_code={details.full_code!r}, "
            f"driver_message={details.safe_message!r}"
        )
    if isinstance(error, OSError):
        error_code, message = _safe_os_error_details(error)
        return (
            f"{operation} failed: failure_type={type(error).__name__!r}, "
            f"os_error_code={error_code!r}, os_message={message!r}"
        )
    return f"{operation} failed: failure_type={type(error).__name__!r}"


def _cleanup_deadline_intact(cleanup_deadline_nanoseconds: int) -> bool:
    return time.monotonic_ns() < cleanup_deadline_nanoseconds


def _preserve_cleanup_failure(
    primary_error: BaseException,
    cleanup_failed: bool,
    cleanup_failures: tuple[str, ...],
    query_id: UUID,
    session_id: int | None,
) -> None:
    if not cleanup_failed:
        return
    primary_error.add_note(
        "Oracle query cleanup was not confirmed: "
        f"query_id={query_id}, session_id={session_id}, failures={cleanup_failures!r}"
    )


def _consume_received_records(
    charge: PostgresSourceQueryCharge,
    record_bytes: tuple[int, ...],
) -> _OracleSourceAccountingFailure | None:
    try:
        charge.consume_records(record_bytes)
    except (PostgresReadDeadlineExceededError, PostgresSourceBudgetExceededError) as error:
        return error
    return None


def _raise_received_batch_failures(
    validation_error: OracleTransportError | None,
    accounting_error: _OracleSourceAccountingFailure | None,
    completion_error: _OracleSourceAccountingFailure | None,
) -> NoReturn:
    if completion_error is not None:
        if validation_error is not None:
            completion_error.add_note(
                "Oracle received-batch validation also failed: "
                f"validation_error_type={type(validation_error).__name__!r}, "
                f"validation_error={validation_error}"
            )
        if accounting_error is not None and accounting_error is not completion_error:
            completion_error.add_note(
                "Oracle received-batch accounting also failed: "
                f"accounting_error_type={type(accounting_error).__name__!r}, "
                f"accounting_error={accounting_error}"
            )
        raise completion_error
    if validation_error is not None:
        if accounting_error is not None:
            validation_error.add_note(
                "Oracle received-batch accounting also failed: "
                f"accounting_error_type={type(accounting_error).__name__!r}, "
                f"accounting_error={accounting_error}"
            )
        raise validation_error
    if accounting_error is not None:
        raise accounting_error
    raise AssertionError("Oracle received-batch failure resolver received no failure")


def _statement_with_query_id(query: OracleQuery) -> str:
    return f"/* dfe_query_id={query.query_id} */\n{query.statement}"


def _new_oracle_cursor(
    connection: oracledb.Connection,
    operation: str,
) -> _OracleCursorProtocol:
    try:
        return cast(_OracleCursorProtocol, connection.cursor())
    except (AttributeError, OSError):
        raise OracleDriverStateError(
            f"python-oracledb could not create a bounded cursor: operation={operation!r}"
        ) from None


def _configure_control_cursor(cursor: _OracleCursorProtocol) -> None:
    try:
        cursor.arraysize = 1
        cursor.prefetchrows = 0
    except (AttributeError, OSError):
        raise OracleDriverStateError(
            "python-oracledb could not configure the bounded control cursor"
        ) from None


def _configure_query_cursor(
    cursor: _OracleCursorProtocol,
    fetch_limits: OracleFetchLimits,
    output_type_handler: _OracleOutputTypeHandler,
) -> None:
    try:
        cursor.arraysize = fetch_limits.fetch_batch_records
        cursor.prefetchrows = 0
        cursor.outputtypehandler = output_type_handler
    except (AttributeError, OSError):
        raise OracleDriverStateError(
            "python-oracledb could not configure the bounded query cursor"
        ) from None


def _execute_oracle_statement(
    cursor: _OracleCursorProtocol,
    statement: str,
    parameters: dict[str, OracleBindValue],
    operation: str,
) -> None:
    try:
        cursor.execute(
            statement,
            parameters,
            fetch_lobs=True,
            fetch_decimals=True,
        )
    except UnicodeDecodeError:
        raise OracleLossyTransportError(
            "python-oracledb could not strictly decode Oracle character data: "
            f"operation={operation!r}"
        ) from None
    except AttributeError:
        raise OracleDriverStateError(
            f"python-oracledb failed outside its structured error boundary: operation={operation!r}"
        ) from None


def _fetch_oracle_batch(
    cursor: _OracleCursorProtocol,
    fetch_size: int,
) -> list[object]:
    try:
        return cursor.fetchmany(size=fetch_size)
    except UnicodeDecodeError:
        raise OracleLossyTransportError(
            "python-oracledb could not strictly decode Oracle character data: "
            "operation='result fetch'"
        ) from None
    except AttributeError:
        raise OracleDriverStateError(
            "python-oracledb failed outside its structured error boundary: operation='result fetch'"
        ) from None


def _set_oracle_fetch_array_size(
    cursor: _OracleCursorProtocol,
    fetch_size: int,
) -> None:
    try:
        cursor.arraysize = fetch_size
    except (AttributeError, OSError):
        raise OracleDriverStateError(
            "python-oracledb could not apply the bounded fetch array size"
        ) from None


def _bind_values(parameters: tuple[OracleBindParameter, ...]) -> dict[str, OracleBindValue]:
    return {parameter.name: parameter.value for parameter in parameters}


def _oracle_bind_occurrence_names(statement: str) -> tuple[str, ...]:
    names: list[str] = []
    index = 0
    statement_length = len(statement)
    while index < statement_length:
        character = statement[index]
        if character == "'":
            index = _oracle_quoted_section_end(statement, index, "'")
            continue
        if character == '"':
            index = _oracle_quoted_section_end(statement, index, '"')
            continue
        if character == "-" and index + 1 < statement_length and statement[index + 1] == "-":
            newline_index = statement.find("\n", index + 2)
            index = statement_length if newline_index < 0 else newline_index + 1
            continue
        if character == "/" and index + 1 < statement_length and statement[index + 1] == "*":
            comment_end = statement.find("*/", index + 2)
            if comment_end < 0:
                raise ValueError("Oracle statement contains an unterminated block comment")
            index = comment_end + 2
            continue
        if character in ("q", "Q") and index + 2 < statement_length and statement[index + 1] == "'":
            opening_delimiter = statement[index + 2]
            if opening_delimiter.isspace() or opening_delimiter == "'":
                raise ValueError("Oracle statement contains an invalid alternative quote")
            closing_delimiter = {
                "[": "]",
                "{": "}",
                "(": ")",
                "<": ">",
            }.get(opening_delimiter, opening_delimiter)
            q_quote_end = statement.find(f"{closing_delimiter}'", index + 3)
            if q_quote_end < 0:
                raise ValueError("Oracle statement contains an unterminated alternative quote")
            index = q_quote_end + 2
            continue
        if character != ":":
            index += 1
            continue
        name_start = index + 1
        name_end = name_start
        while name_end < statement_length and _is_oracle_identifier_character(statement[name_end]):
            name_end += 1
        if name_end - name_start > 30:
            raise ValueError("Oracle statement bind placeholders must not exceed 30 characters")
        raw_name = statement[name_start:name_end]
        if _SQL_BIND_NAME.fullmatch(raw_name) is None:
            raise ValueError(
                "Oracle statement bind placeholders must use 1..30 ASCII letters, "
                "digits, or underscore and start with a letter"
            )
        if len(names) >= MAX_ORACLE_BIND_OCCURRENCES:
            raise ValueError(
                "Oracle query exceeds the absolute bind-occurrence limit: "
                f"bind_occurrences={len(names) + 1}, "
                f"maximum={MAX_ORACLE_BIND_OCCURRENCES}"
            )
        names.append(raw_name.lower())
        index = name_end
    return tuple(names)


def _require_oracle_select_statement(statement: str) -> None:
    index = 0
    while index < len(statement) and statement[index] in _ORACLE_SQL_WHITESPACE:
        index += 1
    keyword_end = index + len("SELECT")
    if (
        statement[index:keyword_end].upper() != "SELECT"
        or keyword_end >= len(statement)
        or statement[keyword_end] not in _ORACLE_SQL_WHITESPACE
    ):
        raise ValueError(
            "Oracle data-query statements must start with SELECT followed by ASCII whitespace"
        )


def _oracle_quoted_section_end(
    statement: str,
    opening_index: int,
    quote: str,
) -> int:
    index = opening_index + 1
    statement_length = len(statement)
    while index < statement_length:
        if statement[index] != quote:
            index += 1
            continue
        if index + 1 < statement_length and statement[index + 1] == quote:
            index += 2
            continue
        return index + 1
    raise ValueError("Oracle statement contains an unterminated quoted section")


def _is_oracle_identifier_character(character: str) -> bool:
    return character.isalnum() or character in ("_", "$", "#")


def _strict_utf8_byte_length(value: str) -> int:
    byte_length = 0
    for index, character in enumerate(value):
        code_point = ord(character)
        if code_point <= 0x7F:
            byte_length += 1
        elif code_point <= 0x7FF:
            byte_length += 2
        elif 0xD800 <= code_point <= 0xDFFF:
            raise UnicodeEncodeError(
                "utf-8",
                value,
                index,
                index + 1,
                "surrogates not allowed",
            )
        elif code_point <= 0xFFFF:
            byte_length += 3
        else:
            byte_length += 4
    return byte_length


def _bind_value_bytes(value: OracleBindValue) -> int:
    if value is None:
        return 0
    if type(value) is str:
        return _strict_utf8_byte_length(value)
    if type(value) is bytes:
        return len(value)
    if type(value) is int:
        return len(str(value).encode("ascii"))
    if type(value) is Decimal:
        return _decimal_transport_bytes(value)
    raise TypeError(f"unsupported Oracle bind type {type(value).__name__!r}")


def _decimal_transport_bytes(value: Decimal) -> int:
    if getsizeof(value) > MAX_ORACLE_DECIMAL_OBJECT_BYTES:
        raise OracleDataValidationError(
            "Oracle Decimal coefficient exceeds the bounded NUMBER transport storage"
        )
    decimal_tuple = value.as_tuple()
    if len(decimal_tuple.digits) > _MAX_ORACLE_NUMBER_PRECISION:
        raise OracleDataValidationError(
            f"Oracle Decimal coefficient exceeds NUMBER precision {_MAX_ORACLE_NUMBER_PRECISION}"
        )
    exponent = decimal_tuple.exponent
    if type(exponent) is not int:
        raise OracleDataValidationError("Oracle Decimal exponent must be an integer")
    if value.is_zero():
        return 1
    digits = max(1, len(decimal_tuple.digits))
    sign_bytes = 1 if decimal_tuple.sign else 0
    if exponent >= 0:
        return sign_bytes + digits + exponent
    integer_digits = max(1, digits + exponent)
    fractional_digits = max(-exponent, -exponent - digits)
    return sign_bytes + integer_digits + 1 + fractional_digits


def _validate_bind_value(value: object, name: str) -> None:
    if value is None or type(value) in (str, bytes):
        if type(value) is str:
            try:
                _strict_utf8_byte_length(value)
            except UnicodeEncodeError:
                raise ValueError(f"Oracle bind {name!r} contains an unpaired surrogate") from None
        return
    if type(value) is int:
        if not -_ORACLE_NUMBER_ABSOLUTE_LIMIT < value < _ORACLE_NUMBER_ABSOLUTE_LIMIT:
            raise ValueError(
                f"Oracle bind {name!r} integer exceeds NUMBER precision "
                f"{_MAX_ORACLE_NUMBER_PRECISION}"
            )
        return
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError(f"Oracle bind {name!r} Decimal must be finite")
        if getsizeof(value) > MAX_ORACLE_DECIMAL_OBJECT_BYTES:
            raise ValueError(
                f"Oracle bind {name!r} Decimal coefficient exceeds bounded NUMBER storage"
            )
        decimal_tuple = value.as_tuple()
        if len(decimal_tuple.digits) > _MAX_ORACLE_NUMBER_PRECISION:
            raise ValueError(
                f"Oracle bind {name!r} Decimal coefficient exceeds NUMBER precision "
                f"{_MAX_ORACLE_NUMBER_PRECISION}; trailing-zero normalization is not implicit"
            )
        if value.is_zero():
            if decimal_tuple.sign:
                raise ValueError(f"Oracle bind {name!r} Decimal must not be negative zero")
            return
        adjusted_exponent = value.adjusted()
        if not (
            _MIN_ORACLE_NUMBER_ADJUSTED_EXPONENT
            <= adjusted_exponent
            <= _MAX_ORACLE_NUMBER_ADJUSTED_EXPONENT
        ):
            raise ValueError(
                f"Oracle bind {name!r} Decimal is outside the exact NUMBER exponent range: "
                f"adjusted_exponent={adjusted_exponent}, "
                f"minimum={_MIN_ORACLE_NUMBER_ADJUSTED_EXPONENT}, "
                f"maximum={_MAX_ORACLE_NUMBER_ADJUSTED_EXPONENT}"
            )
        return
    raise TypeError(f"Oracle bind {name!r} has unsupported Python type {type(value).__name__!r}")


def _validate_projection_name(value: object) -> None:
    if type(value) is not str or not value or len(value) > 128:
        raise ValueError("Oracle projection name must be 1..128 characters")
    if not value.isascii() or value.upper() != value:
        raise ValueError("Oracle projection names must be uppercase ASCII")
    if "\x00" in value:
        raise ValueError("Oracle projection name must not contain NUL")


def _required_declared_size(value: int | None, column_index: int) -> int:
    if type(value) is not int or value < 1:
        raise OracleResultLimitError(
            "Oracle result projection has unknown or unbounded byte size: "
            f"column_index={column_index}, internal_size={value!r}"
        )
    return value


def _required_connection_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise OracleDataValidationError(f"python-oracledb returned an invalid {field_name}")
    try:
        value_bytes = _strict_utf8_byte_length(value)
    except UnicodeEncodeError:
        raise OracleDataValidationError(
            f"python-oracledb returned an invalid {field_name} encoding"
        ) from None
    if value_bytes > _MAX_ORACLE_CONNECTION_TEXT_BYTES:
        raise OracleDataValidationError(
            f"python-oracledb returned an oversized {field_name}: "
            f"value_bytes={value_bytes}, maximum={_MAX_ORACLE_CONNECTION_TEXT_BYTES}"
        )
    return value


def _required_text(value: OracleValue, field_name: str) -> str:
    if type(value) is not str or not value:
        raise OracleDataValidationError(f"Oracle profile returned an invalid {field_name}")
    return value


def _optional_text(value: OracleValue, field_name: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, field_name)


def _required_ascii_text(value: OracleValue, field_name: str) -> str:
    text = _required_text(value, field_name)
    if not text.isascii():
        raise OracleDataValidationError(f"Oracle profile returned non-ASCII {field_name}")
    return text


def _positive_ascii_integer(value: OracleValue, field_name: str) -> int:
    text = _required_ascii_text(value, field_name)
    if not text.isdecimal() or not text.isascii():
        raise OracleDataValidationError(f"Oracle profile returned a non-decimal {field_name}")
    parsed = int(text)
    if parsed < 1:
        raise OracleDataValidationError(f"Oracle profile returned a non-positive {field_name}")
    return parsed


def _require_source_charge(charge: object) -> None:
    if not isinstance(charge, PostgresSourceQueryCharge):
        raise TypeError("Oracle budgeted query charge must be PostgresSourceQueryCharge")


def _require_deadline(deadline: object) -> None:
    if not isinstance(deadline, PostgresReadDeadline):
        raise TypeError("Oracle budgeted query deadline must be PostgresReadDeadline")
