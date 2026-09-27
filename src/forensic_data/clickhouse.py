import logging
import math
import re
import time
from base64 import b64encode
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation, localcontext
from enum import StrEnum
from importlib.metadata import version as package_version
from ipaddress import IPv6Address
from typing import cast, final
from urllib.parse import urlencode
from uuid import UUID, uuid4

from clickhouse_connect.driver.binding import (
    bind_query,  # pyright: ignore[reportUnknownVariableType]
)
from clickhouse_connect.driver.exceptions import ProgrammingError
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from forensic_data.clickhouse_http import (
    CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES,
    ClickHouseHttpDispatchState,
    ClickHouseHttpExecution,
    ClickHouseHttpOutcome,
    ClickHouseHttpOutcomeKind,
    ClickHouseHttpPoolConfig,
    ClickHouseHttpRequest,
    ClickHouseHttpResponseProtocol,
    ClickHouseHttpWorker,
    ClickHouseHttpWorkerError,
    ClickHouseHttpWorkerStartupError,
    start_clickhouse_http_worker,
)
from forensic_data.clickhouse_profile import ClickHouseRuntimeProfile
from forensic_data.postgres import (
    PostgresReadDeadline,
    PostgresReadDeadlineExceededError,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetExceededError,
    PostgresSourceDirection,
    PostgresSourceQueryCharge,
)

LOGGER = logging.getLogger(__name__)
_LOCAL_FIXTURE_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_INTEGER_TEXT = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)\Z")
_DECIMAL_TYPE = re.compile(r"Decimal\(([1-9][0-9]*),\s*(0|[1-9][0-9]*)\)\Z")
_DATETIME64_TYPE = re.compile(r"DateTime64\((0|[1-9][0-9]*)(?:,\s*'([^']+)')?\)\Z")
_MAX_PROFILE_RESPONSE_BYTES = 8_192
_MAX_SETTINGS_RESPONSE_BYTES = 8_192
_MAX_CATALOG_RESPONSE_BYTES = 8_192
_MAX_TIMEZONE_RESPONSE_BYTES = 1_024
_CLICKHOUSE_FORMAT = re.compile(r"[A-Za-z][A-Za-z0-9]*\Z", re.ASCII)
_CLICKHOUSE_PARAMETER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_CLICKHOUSE_HOST_LABEL = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_RETRYABLE_HTTP_STATUSES = frozenset((429, 502, 503, 504))
_HTTP_IPC_OVERHEAD_BYTES = 65_536
_KILL_QUERY_RESPONSE_OVERHEAD_BYTES = 65_536
_CLICKHOUSE_ZERO_SCAN_OPERATIONS = frozenset(
    {
        "initialize_clickhouse_transport",
        "initialize_clickhouse_control_transport",
        "cancel_clickhouse_query",
        "inspect_server_profile",
        "inspect_resource_constraints",
        "inspect_datetime64_timezone",
        "inspect_fidelity_relation",
        "inspect_immutable_version_readiness_table",
        "inspect_immutable_version_table",
        "inspect_system_row_policy_visibility",
        "inspect_immutable_version_row_policies",
        "inspect_immutable_version_columns",
        "read_immutable_version_readiness",
        "inspect_legacy_table_catalog",
        "inspect_legacy_table_columns",
        "inspect_legacy_row_policies",
        "inspect_legacy_projection_settings",
        "inspect_legacy_projection_parts",
        "inspect_legacy_mutations",
        "inspect_legacy_active_parts",
        "read_legacy_immutable_version_readiness",
        "inspect_logical_projection_mutations",
        "inspect_logical_projection_runtime",
        "inspect_logical_projection_parts",
        "inspect_canonical_relation",
    }
)
_CLICKHOUSE_SINGLE_SCAN_OPERATIONS = frozenset(
    {
        "read_exact_decimal_datetime64_values",
        "read_canonical_rows",
        "read_canonical_fingerprint",
        "read_canonical_key_groups",
    }
)

type ClickHouseParameter = str | int


class ClickHouseTransportError(RuntimeError):
    """Base error for the ClickHouse HTTP boundary."""


class ClickHouseConnectionError(ClickHouseTransportError):
    """Opening or profiling a ClickHouse connection failed."""

    def __init__(
        self,
        attempt_id: UUID,
        connection_attempts: int,
        query_id: UUID | None,
        http_status: int | None,
        error_code: int | None,
        error_name: str | None,
        received_error_bytes: int,
        error_response_truncated: bool,
        cause_type: str,
    ) -> None:
        self.attempt_id = attempt_id
        self.connection_attempts = connection_attempts
        self.query_id = query_id
        self.http_status = http_status
        self.error_code = error_code
        self.error_name = error_name
        self.received_error_bytes = received_error_bytes
        self.error_response_truncated = error_response_truncated
        self.cause_type = cause_type
        super().__init__(
            "ClickHouse connection failed: "
            f"attempt_id={attempt_id}, connection_attempts={connection_attempts}, "
            f"query_id={query_id}, http_status={http_status!r}, "
            f"error_code={error_code!r}, error_name={error_name!r}, "
            f"received_error_bytes={received_error_bytes}, "
            f"error_response_truncated={error_response_truncated}, "
            f"cause_type={cause_type!r}"
        )


class ClickHouseQueryCompletion(StrEnum):
    NOT_DISPATCHED = "not_dispatched"
    SERVER_TERMINAL = "server_terminal"
    CANCELLED = "cancelled"
    UNCONFIRMED = "unconfirmed"


class ClickHouseQueryError(ClickHouseTransportError):
    """A ClickHouse query failed and its dedicated transport was retired."""

    def __init__(
        self,
        attempt_id: UUID,
        query_id: UUID,
        operation: str,
        http_status: int | None,
        error_code: int | None,
        error_name: str | None,
        received_error_bytes: int,
        error_response_truncated: bool,
        cause_type: str,
        completion: ClickHouseQueryCompletion,
    ) -> None:
        self.attempt_id = attempt_id
        self.query_id = query_id
        self.operation = operation
        self.http_status = http_status
        self.error_code = error_code
        self.error_name = error_name
        self.received_error_bytes = received_error_bytes
        self.error_response_truncated = error_response_truncated
        self.cause_type = cause_type
        self.completion = completion
        super().__init__(
            "ClickHouse query failed: "
            f"attempt_id={attempt_id}, query_id={query_id}, operation={operation!r}, "
            f"http_status={http_status!r}, error_code={error_code!r}, "
            f"error_name={error_name!r}, received_error_bytes={received_error_bytes}, "
            f"error_response_truncated={error_response_truncated}, "
            f"cause_type={cause_type!r}, completion={completion.value!r}"
        )


class ClickHouseAttemptDeadlineExceededError(ClickHouseTransportError):
    """The immutable attempt deadline expired and no result was accepted."""

    def __init__(
        self,
        attempt_id: UUID,
        query_id: UUID,
        operation: str,
        completion: ClickHouseQueryCompletion,
    ) -> None:
        self.attempt_id = attempt_id
        self.query_id = query_id
        self.operation = operation
        self.completion = completion
        super().__init__(
            "ClickHouse query exceeded the immutable attempt deadline: "
            f"attempt_id={attempt_id}, query_id={query_id}, operation={operation!r}, "
            f"completion={completion.value!r}"
        )


class ClickHouseCancellationUnconfirmedError(ClickHouseTransportError):
    """ClickHouse query completion could not be confirmed after cancellation."""

    def __init__(
        self,
        attempt_id: UUID,
        query_id: UUID,
        operation: str,
        trigger_cause: str,
        cancellation_cause: str,
        http_status: int | None,
        error_code: int | None,
        error_name: str | None,
        received_response_bytes: int,
        response_truncated: bool,
    ) -> None:
        self.attempt_id = attempt_id
        self.query_id = query_id
        self.operation = operation
        self.trigger_cause = trigger_cause
        self.cancellation_cause = cancellation_cause
        self.http_status = http_status
        self.error_code = error_code
        self.error_name = error_name
        self.received_response_bytes = received_response_bytes
        self.response_truncated = response_truncated
        super().__init__(
            "ClickHouse query cancellation is unconfirmed: "
            f"attempt_id={attempt_id}, query_id={query_id}, operation={operation!r}, "
            f"trigger_cause={trigger_cause!r}, cancellation_cause={cancellation_cause!r}, "
            f"http_status={http_status!r}, error_code={error_code!r}, "
            f"error_name={error_name!r}, received_response_bytes={received_response_bytes}, "
            f"response_truncated={response_truncated}, source_slot_released=False"
        )


class ClickHouseTransportAttemptMismatchError(ClickHouseTransportError):
    """An observation was offered to a different ClickHouse transport attempt."""


class ClickHouseTransportCleanupError(ClickHouseTransportError):
    """An isolated ClickHouse HTTP worker could not be reaped."""


class ClickHouseSourceAccountingError(ClickHouseTransportError):
    """A budgeted ClickHouse request lacks an explicit source-work reservation."""


class ClickHouseDataValidationError(ClickHouseTransportError):
    """ClickHouse returned data outside the typed transport contract."""


class ClickHouseResultLimitError(ClickHouseTransportError):
    """A ClickHouse result exceeded its explicit response bound."""


class ClickHouseResponseLimitError(ClickHouseResultLimitError):
    """A bounded HTTP response exceeded the caller's accepted result size."""

    def __init__(
        self,
        attempt_id: UUID,
        query_id: UUID,
        operation: str,
        received_response_bytes: int,
        response_truncated: bool,
    ) -> None:
        self.attempt_id = attempt_id
        self.query_id = query_id
        self.operation = operation
        self.received_response_bytes = received_response_bytes
        self.response_truncated = response_truncated
        super().__init__(
            "ClickHouse response exceeded its explicit byte bound: "
            f"attempt_id={attempt_id}, query_id={query_id}, operation={operation!r}, "
            f"received_response_bytes={received_response_bytes}, "
            f"response_truncated={response_truncated}"
        )


class UnsupportedClickHouseProfileError(ClickHouseTransportError):
    """The selected ClickHouse strategy lacks a required capability or setting."""


class ClickHouseTransportClosedError(ClickHouseTransportError):
    """An operation was attempted on a retired ClickHouse transport."""


class ClickHouseTransportSecurity(StrEnum):
    TLS_VERIFY = "tls-verify"
    PLAINTEXT_LOCAL_FIXTURE = "plaintext-local-fixture"


class ClickHouseTransportState(StrEnum):
    ACTIVE = "active"
    LOST = "lost"
    CANCELLATION_UNCONFIRMED = "cancellation_unconfirmed"
    CLOSED = "closed"


class ClickHouseResourceSetting(StrEnum):
    MAX_MEMORY_USAGE = "max_memory_usage"
    MAX_THREADS = "max_threads"
    MAX_EXECUTION_TIME = "max_execution_time"
    MAX_RESULT_ROWS = "max_result_rows"
    MAX_RESULT_BYTES = "max_result_bytes"
    MAX_ROWS_TO_GROUP_BY = "max_rows_to_group_by"


class ClickHouseTimezoneStrategy(StrEnum):
    SESSION_SETTING = "session_setting"
    SERVER_UTC_CONFIGURATION = "server_utc_configuration"


class ClickHouseOverflowSetting(StrEnum):
    GROUP_BY = "group_by_overflow_mode"
    READ = "read_overflow_mode"
    READ_LEAF = "read_overflow_mode_leaf"
    RESULT = "result_overflow_mode"
    SORT = "sort_overflow_mode"
    TIMEOUT = "timeout_overflow_mode"


class ClickHouseConnectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: str
    port: int = Field(ge=1, le=65_535)
    database: str
    user: str
    password: SecretStr
    transport_security: ClickHouseTransportSecurity
    ca_cert: str | None
    connect_timeout_seconds: int = Field(ge=1)
    send_receive_timeout_seconds: int = Field(ge=1)
    application_name: str

    @field_validator("database", "user", "application_name")
    @classmethod
    def validate_nonempty_text(cls, value: str) -> str:
        validate_clickhouse_text_scalar(value, "ClickHouse connection text")
        return value

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        validate_clickhouse_text_scalar(value, "ClickHouse host")
        if any(character in value for character in "/?#@[]") or any(
            character.isspace() for character in value
        ):
            raise ValueError("ClickHouse host must be a hostname or unbracketed IP address")
        if ":" in value:
            try:
                IPv6Address(value)
            except ValueError:
                raise ValueError(
                    "ClickHouse host containing ':' must be an unbracketed IPv6 address"
                ) from None
            return value
        hostname = value[:-1] if value.endswith(".") else value
        if (
            not hostname
            or len(value) > 253
            or any(_CLICKHOUSE_HOST_LABEL.fullmatch(label) is None for label in hostname.split("."))
        ):
            raise ValueError("ClickHouse host must be a valid ASCII hostname or IP address")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: SecretStr) -> SecretStr:
        password = value.get_secret_value()
        validate_clickhouse_text_scalar(password, "ClickHouse password")
        return value

    @model_validator(mode="after")
    def validate_transport_security(self) -> "ClickHouseConnectionSettings":
        if self.transport_security is ClickHouseTransportSecurity.PLAINTEXT_LOCAL_FIXTURE:
            if self.host not in _LOCAL_FIXTURE_HOSTS:
                raise ValueError(
                    "plaintext ClickHouse transport is restricted to localhost fixtures"
                )
            if self.ca_cert is not None:
                raise ValueError("plaintext ClickHouse transport must not declare a CA certificate")
        elif self.ca_cert is not None:
            validate_clickhouse_text_scalar(self.ca_cert, "ClickHouse CA certificate path")
        return self


@dataclass(frozen=True, slots=True)
class ClickHouseRetryPolicy:
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
class ClickHouseTransportLimits:
    max_initialization_response_bytes: int
    max_error_response_bytes: int
    max_cancellation_response_bytes: int
    max_query_bytes: int
    max_ipc_message_bytes: int
    cancellation_reserve_milliseconds: int
    process_cleanup_timeout_milliseconds: int

    def __post_init__(self) -> None:
        for name, value in (
            ("max_initialization_response_bytes", self.max_initialization_response_bytes),
            ("max_error_response_bytes", self.max_error_response_bytes),
            ("max_cancellation_response_bytes", self.max_cancellation_response_bytes),
            ("max_query_bytes", self.max_query_bytes),
            ("max_ipc_message_bytes", self.max_ipc_message_bytes),
            ("cancellation_reserve_milliseconds", self.cancellation_reserve_milliseconds),
            ("process_cleanup_timeout_milliseconds", self.process_cleanup_timeout_milliseconds),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name, bounded_ipc_bytes in (
            (
                "max_initialization_response_bytes",
                self.max_initialization_response_bytes + CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES,
            ),
            ("max_error_response_bytes", self.max_error_response_bytes),
            (
                "max_cancellation_response_bytes",
                self.max_cancellation_response_bytes + CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES,
            ),
            ("max_query_bytes", self.max_query_bytes),
        ):
            if bounded_ipc_bytes + _HTTP_IPC_OVERHEAD_BYTES > self.max_ipc_message_bytes:
                raise ValueError(
                    "max_ipc_message_bytes must contain each bounded HTTP payload plus IPC "
                    f"overhead: incompatible_limit={name!r}"
                )
        if (
            self.max_query_bytes + _KILL_QUERY_RESPONSE_OVERHEAD_BYTES
            > self.max_cancellation_response_bytes
        ):
            raise ValueError(
                "max_cancellation_response_bytes must contain the maximum query text and "
                "KILL QUERY acknowledgement overhead"
            )


def required_clickhouse_ipc_message_bytes(max_response_bytes: int) -> int:
    if type(max_response_bytes) is not int or max_response_bytes < 1:
        raise ValueError("max_response_bytes must be a positive integer")
    return max_response_bytes + CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES + _HTTP_IPC_OVERHEAD_BYTES


@dataclass(frozen=True, slots=True)
class ClickHouseRawResult:
    attempt_id: UUID
    query_id: UUID
    payload: bytes


@dataclass(frozen=True, slots=True)
class _ClickHousePreparedRequest:
    request: ClickHouseHttpRequest
    work_deadline: int
    query_id: UUID


type _ClickHouseSourceCharge = PostgresSourceQueryCharge | None
type _ClickHouseSourceAccountingFailure = (
    ClickHouseSourceAccountingError
    | PostgresReadDeadlineExceededError
    | PostgresSourceBudgetExceededError
)


class _ClickHouseRequestAccounting:
    def dispatch_known(self, operation: str) -> _ClickHouseSourceCharge:
        raise NotImplementedError

    def dispatch_explicit(
        self,
        operation: str,
        full_scans: int,
    ) -> _ClickHouseSourceCharge:
        raise NotImplementedError

    def consume_payload(
        self,
        charge: _ClickHouseSourceCharge,
        payload: bytes,
        result_format: str,
    ) -> None:
        raise NotImplementedError

    def consume_observed_result_bytes(
        self,
        charge: _ClickHouseSourceCharge,
        result_bytes: int,
    ) -> None:
        raise NotImplementedError


@final
class _UnbudgetedClickHouseRequestAccounting(_ClickHouseRequestAccounting):
    def dispatch_known(self, operation: str) -> _ClickHouseSourceCharge:
        validate_clickhouse_text_scalar(operation, "ClickHouse unbudgeted operation")
        return None

    def dispatch_explicit(
        self,
        operation: str,
        full_scans: int,
    ) -> _ClickHouseSourceCharge:
        validate_clickhouse_text_scalar(operation, "ClickHouse unbudgeted operation")
        _validate_nonnegative_source_full_scans(full_scans)
        return None

    def consume_payload(
        self,
        charge: _ClickHouseSourceCharge,
        payload: bytes,
        result_format: str,
    ) -> None:
        if charge is not None:
            raise AssertionError("unbudgeted ClickHouse accounting received a source charge")
        if type(payload) is not bytes or type(result_format) is not str:
            raise TypeError("ClickHouse response accounting requires bytes and a format name")

    def consume_observed_result_bytes(
        self,
        charge: _ClickHouseSourceCharge,
        result_bytes: int,
    ) -> None:
        if charge is not None:
            raise AssertionError("unbudgeted ClickHouse accounting received a source charge")
        _validate_nonnegative_source_result_bytes(result_bytes)


@final
class _SourceBudgetClickHouseRequestAccounting(_ClickHouseRequestAccounting):
    def __init__(
        self,
        source_budget: PostgresSourceBudgetAttempt,
        direction: PostgresSourceDirection,
    ) -> None:
        if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
            raise TypeError("ClickHouse source accounting requires PostgresSourceBudgetAttempt")
        if not isinstance(cast(object, direction), PostgresSourceDirection):
            raise TypeError("ClickHouse source accounting requires PostgresSourceDirection")
        self._source_budget = source_budget
        self._direction = direction

    def dispatch_known(self, operation: str) -> _ClickHouseSourceCharge:
        validate_clickhouse_text_scalar(operation, "ClickHouse budgeted operation")
        if operation in _CLICKHOUSE_ZERO_SCAN_OPERATIONS:
            full_scans = 0
        elif operation in _CLICKHOUSE_SINGLE_SCAN_OPERATIONS:
            full_scans = 1
        else:
            raise ClickHouseSourceAccountingError(
                "ClickHouse budgeted request lacks an immutable full-scan reservation: "
                f"operation={operation!r}"
            )
        return self._source_budget.dispatch_query(self._direction, full_scans)

    def dispatch_explicit(
        self,
        operation: str,
        full_scans: int,
    ) -> _ClickHouseSourceCharge:
        validate_clickhouse_text_scalar(operation, "ClickHouse budgeted operation")
        _validate_nonnegative_source_full_scans(full_scans)
        return self._source_budget.dispatch_query(self._direction, full_scans)

    def consume_payload(
        self,
        charge: _ClickHouseSourceCharge,
        payload: bytes,
        result_format: str,
    ) -> None:
        if charge is None:
            raise AssertionError("budgeted ClickHouse accounting lost its source charge")
        charge.consume_records(_clickhouse_result_record_bytes(payload, result_format))

    def consume_observed_result_bytes(
        self,
        charge: _ClickHouseSourceCharge,
        result_bytes: int,
    ) -> None:
        if charge is None:
            raise AssertionError("budgeted ClickHouse accounting lost its source charge")
        _validate_nonnegative_source_result_bytes(result_bytes)
        charge.consume_observed_result_bytes(result_bytes)


@dataclass(frozen=True, slots=True)
class ClickHouseResourceConstraint:
    setting: ClickHouseResourceSetting
    value: Decimal
    minimum: Decimal | None
    maximum: Decimal | None
    changeable_in_readonly: bool


@dataclass(frozen=True, slots=True)
class ClickHouseLockedOverflowMode:
    setting: ClickHouseOverflowSetting
    value: str


@dataclass(frozen=True, slots=True)
class ClickHouseModernProfileProvenance:
    runtime_profile: ClickHouseRuntimeProfile
    response_protocol: ClickHouseHttpResponseProtocol
    timezone_strategy: ClickHouseTimezoneStrategy


@dataclass(frozen=True, slots=True)
class ClickHouseLegacyProfileProvenance:
    runtime_profile: ClickHouseRuntimeProfile
    response_protocol: ClickHouseHttpResponseProtocol
    timezone_strategy: ClickHouseTimezoneStrategy
    cancel_http_readonly_queries_on_client_close: int
    cancel_http_readonly_queries_on_client_close_locked: bool
    send_progress_in_http_headers: int
    send_progress_in_http_headers_locked: bool
    allow_experimental_projection_optimization: int
    allow_experimental_projection_optimization_locked: bool
    force_optimize_projection: int
    force_optimize_projection_locked: bool
    locked_overflow_modes: tuple[ClickHouseLockedOverflowMode, ...]


type ClickHouseProfileProvenance = (
    ClickHouseModernProfileProvenance | ClickHouseLegacyProfileProvenance
)


@dataclass(frozen=True, slots=True)
class ClickHouseServerProfile:
    provenance: ClickHouseProfileProvenance
    binding_library_name: str
    binding_library_version: str
    transport_library_name: str
    transport_library_version: str
    server_version: str
    server_version_number: int
    build_id: str
    server_timezone: str
    session_timezone: str
    current_user: str
    current_database: str
    readonly: int
    max_memory_usage: int
    max_threads: int
    max_execution_time_seconds: Decimal
    effective_max_execution_time_seconds: Decimal
    max_result_rows: int
    max_result_bytes: int
    result_overflow_mode: str
    readonly_locked: bool
    result_overflow_mode_locked: bool
    resource_constraints: tuple[ClickHouseResourceConstraint, ...]


@dataclass(frozen=True, slots=True)
class ClickHouseDecimalType:
    precision: int
    scale: int


@dataclass(frozen=True, slots=True)
class ClickHouseDateTime64Type:
    precision: int
    declared_timezone: str | None
    timezone: str


@dataclass(frozen=True, slots=True)
class ClickHouseFidelityRelation:
    database: str
    table: str
    decimal_column: str
    decimal_type: ClickHouseDecimalType
    datetime_column: str
    datetime_type: ClickHouseDateTime64Type


@dataclass(frozen=True, slots=True)
class ClickHouseExactReadRequest:
    relation: ClickHouseFidelityRelation
    order_column: str
    max_rows: int
    max_response_bytes: int
    max_execution_time_seconds: int

    def __post_init__(self) -> None:
        if type(self.relation) is not ClickHouseFidelityRelation:
            raise TypeError("relation must be ClickHouseFidelityRelation")
        validate_clickhouse_identifier(self.order_column, "ClickHouse order column")
        for name, value in (
            ("max_rows", self.max_rows),
            ("max_response_bytes", self.max_response_bytes),
            ("max_execution_time_seconds", self.max_execution_time_seconds),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class ClickHouseExactRow:
    order_value: int
    decimal_scaled_value: int
    decimal_text: str
    datetime_ticks: int
    datetime_text: str


class _ClickHouseProfilePayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_version: str
    server_version_number: str
    build_id: str
    server_timezone: str
    session_timezone: str
    current_user: str
    current_database: str
    readonly: str
    max_memory_usage: str
    max_threads: str
    max_result_rows: str
    max_result_bytes: str
    result_overflow_mode: str


class _ClickHouseLegacyProfilePayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_version: str
    server_version_number: str
    build_id: str
    server_timezone: str
    session_timezone: str
    current_user: str
    current_database: str
    readonly: str
    max_memory_usage: str
    max_threads: str
    max_result_rows: str
    max_result_bytes: str
    result_overflow_mode: str
    cancel_http_readonly_queries_on_client_close: str
    send_progress_in_http_headers: str


class _ClickHouseColumnPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    name: str
    type: str


class _ClickHouseTimeZonePayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    effective_timezone: str


class _ClickHouseSettingPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    name: str
    value: str
    min: str | None
    max: str | None
    readonly: int


@dataclass(frozen=True, slots=True)
class _ClickHouseInitializationProbe:
    query: str
    query_settings: tuple[tuple[str, ClickHouseParameter], ...]
    expected_payload: bytes


@dataclass(frozen=True, slots=True)
class _ClickHouseTransportProtocol:
    runtime_profile: ClickHouseRuntimeProfile
    response_protocol: ClickHouseHttpResponseProtocol
    url_parameters: tuple[tuple[str, str], ...]
    transport_owned_query_settings: frozenset[str]
    locked_query_settings: frozenset[str]
    unsupported_query_settings: frozenset[str]
    cancellation_query_settings: tuple[tuple[str, ClickHouseParameter], ...]
    data_initialization: _ClickHouseInitializationProbe
    control_initialization: _ClickHouseInitializationProbe


_MODERN_CLICKHOUSE_PROTOCOL = _ClickHouseTransportProtocol(
    runtime_profile=ClickHouseRuntimeProfile.LTS,
    response_protocol=ClickHouseHttpResponseProtocol.MODERN_EXCEPTION_FRAME,
    url_parameters=(
        ("http_write_exception_in_output_format", "0"),
        ("wait_end_of_query", "1"),
    ),
    transport_owned_query_settings=frozenset(
        {
            "http_write_exception_in_output_format",
            "query_id",
            "wait_end_of_query",
        }
    ),
    locked_query_settings=frozenset(),
    unsupported_query_settings=frozenset(),
    cancellation_query_settings=(("session_timezone", "UTC"),),
    data_initialization=_ClickHouseInitializationProbe(
        query=(
            "SELECT 'ready', "
            "toUInt8(getSetting('cancel_http_readonly_queries_on_client_close')), "
            "toUInt8(getSetting('http_write_exception_in_output_format'))"
        ),
        query_settings=(("session_timezone", "UTC"), ("max_result_rows", 1)),
        expected_payload=b"ready\t1\t0\n",
    ),
    control_initialization=_ClickHouseInitializationProbe(
        query=(
            "SELECT 'control-ready', "
            "toUInt8(getSetting('cancel_http_readonly_queries_on_client_close')), "
            "toUInt8(getSetting('http_write_exception_in_output_format'))"
        ),
        query_settings=(("session_timezone", "UTC"), ("max_result_rows", 1)),
        expected_payload=b"control-ready\t1\t0\n",
    ),
)

_LEGACY_CLICKHOUSE_21_8_PROTOCOL = _ClickHouseTransportProtocol(
    runtime_profile=ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE,
    response_protocol=ClickHouseHttpResponseProtocol.LEGACY_CLEAN_EOF,
    url_parameters=(("wait_end_of_query", "1"),),
    transport_owned_query_settings=frozenset({"query_id", "wait_end_of_query"}),
    locked_query_settings=frozenset(
        {
            "cancel_http_readonly_queries_on_client_close",
            "allow_experimental_projection_optimization",
            "force_optimize_projection",
            "group_by_overflow_mode",
            "read_overflow_mode",
            "read_overflow_mode_leaf",
            "readonly",
            "result_overflow_mode",
            "send_progress_in_http_headers",
            "sort_overflow_mode",
            "timeout_overflow_mode",
        }
    ),
    unsupported_query_settings=frozenset(
        {
            "apply_mutations_on_fly",
            "apply_patch_parts",
            "final",
            "http_write_exception_in_output_format",
            "session_timezone",
            "timeout_overflow_mode_leaf",
        }
    ),
    cancellation_query_settings=(),
    data_initialization=_ClickHouseInitializationProbe(
        query=(
            "SELECT 'ready', "
            "toUInt8(getSetting('cancel_http_readonly_queries_on_client_close')), "
            "toUInt8(getSetting('send_progress_in_http_headers')), "
            "toUInt8(getSetting('readonly')), "
            "toString(getSetting('result_overflow_mode')), timezone()"
        ),
        query_settings=(),
        expected_payload=b"ready\t1\t0\t2\tthrow\tUTC\n",
    ),
    control_initialization=_ClickHouseInitializationProbe(
        query=(
            "SELECT 'control-ready', "
            "toUInt8(getSetting('cancel_http_readonly_queries_on_client_close')), "
            "toUInt8(getSetting('send_progress_in_http_headers')), "
            "toUInt8(getSetting('readonly')), "
            "toString(getSetting('result_overflow_mode')), timezone()"
        ),
        query_settings=(),
        expected_payload=b"control-ready\t1\t0\t2\tthrow\tUTC\n",
    ),
)


class ClickHouseTransport:
    """Dedicated single-owner ClickHouse HTTP transport."""

    def __init__(
        self,
        settings: ClickHouseConnectionSettings,
        protocol: _ClickHouseTransportProtocol,
        limits: ClickHouseTransportLimits,
        deadline: PostgresReadDeadline,
        attempt_id: UUID,
        connection_attempts: int,
        data_worker: ClickHouseHttpWorker,
        control_worker: ClickHouseHttpWorker,
        physical_request_count: int,
        accounting: _ClickHouseRequestAccounting,
    ) -> None:
        self._settings = settings
        self._protocol = protocol
        self._limits = limits
        self._deadline = deadline
        self._attempt_id = attempt_id
        self._connection_attempts = connection_attempts
        self._data_worker = data_worker
        self._control_worker = control_worker
        self._physical_request_count = physical_request_count
        self._accounting = accounting
        self._last_query_id: UUID | None = None
        self._state = ClickHouseTransportState.ACTIVE

    @property
    def state(self) -> ClickHouseTransportState:
        return self._state

    @property
    def closed(self) -> bool:
        return self._state is not ClickHouseTransportState.ACTIVE

    @property
    def attempt_id(self) -> UUID:
        return self._attempt_id

    @property
    def connection_attempts(self) -> int:
        return self._connection_attempts

    @property
    def physical_request_count(self) -> int:
        return self._physical_request_count

    @property
    def last_query_id(self) -> UUID | None:
        return self._last_query_id

    @property
    def runtime_profile(self) -> ClickHouseRuntimeProfile:
        return self._protocol.runtime_profile

    @property
    def response_protocol(self) -> ClickHouseHttpResponseProtocol:
        return self._protocol.response_protocol

    @property
    def source_slot_released(self) -> bool:
        return self._state in (ClickHouseTransportState.LOST, ClickHouseTransportState.CLOSED)

    def require_attempt(self, attempt_id: UUID, operation: str) -> None:
        if type(attempt_id) is not UUID:
            raise TypeError("ClickHouse expected transport attempt ID must be a UUID")
        validate_clickhouse_text_scalar(operation, "ClickHouse attempt-bound operation")
        self._require_active(operation)
        if attempt_id != self._attempt_id:
            raise ClickHouseTransportAttemptMismatchError(
                "ClickHouse observation belongs to a different transport attempt: "
                f"operation={operation!r}, expected_attempt_id={attempt_id}, "
                f"actual_attempt_id={self._attempt_id}"
            )

    def execute_raw(
        self,
        query: str,
        parameters: dict[str, ClickHouseParameter],
        settings: dict[str, ClickHouseParameter],
        result_format: str,
        max_response_bytes: int,
        operation: str,
    ) -> ClickHouseRawResult:
        prepared = self._prepare_raw_request(
            query,
            parameters,
            settings,
            result_format,
            max_response_bytes,
            operation,
        )
        charge = self._accounting.dispatch_known(operation)
        return self._execute_request(
            target_worker=self._data_worker,
            cancellation_worker=self._control_worker,
            request=prepared.request,
            work_deadline=prepared.work_deadline,
            query_id=prepared.query_id,
            operation=operation,
            result_format=result_format,
            charge=charge,
        )

    def execute_source_raw(
        self,
        query: str,
        parameters: dict[str, ClickHouseParameter],
        settings: dict[str, ClickHouseParameter],
        result_format: str,
        max_response_bytes: int,
        operation: str,
        full_scans: int,
    ) -> ClickHouseRawResult:
        prepared = self._prepare_raw_request(
            query,
            parameters,
            settings,
            result_format,
            max_response_bytes,
            operation,
        )
        charge = self._accounting.dispatch_explicit(operation, full_scans)
        return self._execute_request(
            target_worker=self._data_worker,
            cancellation_worker=self._control_worker,
            request=prepared.request,
            work_deadline=prepared.work_deadline,
            query_id=prepared.query_id,
            operation=operation,
            result_format=result_format,
            charge=charge,
        )

    def _prepare_raw_request(
        self,
        query: str,
        parameters: dict[str, ClickHouseParameter],
        settings: dict[str, ClickHouseParameter],
        result_format: str,
        max_response_bytes: int,
        operation: str,
    ) -> "_ClickHousePreparedRequest":
        self._require_active(operation)
        validate_clickhouse_text_scalar(query, "ClickHouse query")
        validate_clickhouse_text_scalar(result_format, "ClickHouse result format")
        validate_clickhouse_text_scalar(operation, "ClickHouse operation")
        if type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        _require_protocol_query_settings(self._protocol, settings)
        query_id = uuid4()
        self._last_query_id = query_id
        work_deadline = self._work_deadline_nanoseconds()
        http_deadline = self._http_deadline_nanoseconds(work_deadline)
        request = _clickhouse_http_request(
            settings=self._settings,
            protocol=self._protocol,
            transport_limits=self._limits,
            read_deadline=self._deadline,
            dispatch_deadline_nanoseconds=work_deadline,
            io_deadline_nanoseconds=http_deadline,
            query_id=query_id,
            query=query,
            parameters=parameters,
            query_settings=settings,
            result_format=result_format,
            max_response_bytes=max_response_bytes,
        )
        self._require_prepared_before_deadline(work_deadline, query_id, operation)
        return _ClickHousePreparedRequest(
            request=request,
            work_deadline=work_deadline,
            query_id=query_id,
        )

    def initialize_control_connection(self) -> ClickHouseRawResult:
        operation = "initialize_clickhouse_control_transport"
        probe = self._protocol.control_initialization
        self._require_active(operation)
        query_id = uuid4()
        self._last_query_id = query_id
        work_deadline = self._work_deadline_nanoseconds()
        http_deadline = self._http_deadline_nanoseconds(work_deadline)
        request = _clickhouse_http_request(
            settings=self._settings,
            protocol=self._protocol,
            transport_limits=self._limits,
            read_deadline=self._deadline,
            dispatch_deadline_nanoseconds=work_deadline,
            io_deadline_nanoseconds=http_deadline,
            query_id=query_id,
            query=probe.query,
            parameters={},
            query_settings=dict(probe.query_settings),
            result_format="TabSeparatedRaw",
            max_response_bytes=self._limits.max_initialization_response_bytes,
        )
        self._require_prepared_before_deadline(work_deadline, query_id, operation)
        charge = self._accounting.dispatch_known(operation)
        return self._execute_request(
            target_worker=self._control_worker,
            cancellation_worker=self._data_worker,
            request=request,
            work_deadline=work_deadline,
            query_id=query_id,
            operation=operation,
            result_format="TabSeparatedRaw",
            charge=charge,
        )

    def _execute_request(
        self,
        target_worker: ClickHouseHttpWorker,
        cancellation_worker: ClickHouseHttpWorker,
        request: ClickHouseHttpRequest,
        work_deadline: int,
        query_id: UUID,
        operation: str,
        result_format: str,
        charge: _ClickHouseSourceCharge,
    ) -> ClickHouseRawResult:
        self._physical_request_count += 1
        execution = target_worker.execute(request, work_deadline)
        accounting_error = self._consume_observed_outcome(
            charge,
            execution.outcome,
            result_format,
        )
        if execution.deadline_exceeded:
            try:
                self._raise_deadline_outcome(
                    execution,
                    query_id,
                    operation,
                    cancellation_worker,
                )
            except ClickHouseTransportError as error:
                _preserve_source_accounting_failure(error, accounting_error)
                raise
        if execution.outcome is None:
            raise AssertionError("ClickHouse HTTP execution ended without an outcome")
        try:
            result = self._resolve_query_outcome(
                execution.outcome,
                query_id,
                operation,
                cancellation_worker,
            )
        except ClickHouseTransportError as error:
            _preserve_source_accounting_failure(error, accounting_error)
            raise
        if accounting_error is not None:
            cleanup_cause = self._retire(ClickHouseTransportState.LOST)
            if cleanup_cause is not None:
                raise ClickHouseTransportCleanupError(
                    "ClickHouse source accounting failed after a completed query and "
                    "worker cleanup was not confirmed: "
                    f"attempt_id={self._attempt_id}, query_id={query_id}, "
                    "operation="
                    f"{operation!r}, primary_error_type={type(accounting_error).__name__!r}, "
                    f"cleanup_cause={cleanup_cause!r}"
                ) from accounting_error
            raise accounting_error
        return result

    def _consume_observed_outcome(
        self,
        charge: _ClickHouseSourceCharge,
        outcome: ClickHouseHttpOutcome | None,
        result_format: str,
    ) -> _ClickHouseSourceAccountingFailure | None:
        if outcome is None:
            return None
        try:
            if outcome.kind is ClickHouseHttpOutcomeKind.SUCCESS:
                self._accounting.consume_payload(charge, outcome.payload, result_format)
            elif outcome.kind is ClickHouseHttpOutcomeKind.RESULT_LIMIT:
                self._accounting.consume_observed_result_bytes(
                    charge,
                    outcome.received_bytes,
                )
        except (
            ClickHouseSourceAccountingError,
            PostgresReadDeadlineExceededError,
            PostgresSourceBudgetExceededError,
        ) as error:
            return error
        return None

    def close(self) -> None:
        if self._state is ClickHouseTransportState.CLOSED:
            return
        if self._state is ClickHouseTransportState.CANCELLATION_UNCONFIRMED:
            return
        if self._state is ClickHouseTransportState.LOST:
            return
        cleanup_cause = self._retire_workers(graceful=True)
        if cleanup_cause is not None:
            self._state = ClickHouseTransportState.CANCELLATION_UNCONFIRMED
            raise ClickHouseTransportCleanupError(
                "ClickHouse transport could not reap its isolated workers during close: "
                f"cause_type={cleanup_cause!r}"
            )
        self._state = ClickHouseTransportState.CLOSED

    def _resolve_query_outcome(
        self,
        outcome: ClickHouseHttpOutcome,
        query_id: UUID,
        operation: str,
        cancellation_worker: ClickHouseHttpWorker,
    ) -> ClickHouseRawResult:
        if outcome.kind is ClickHouseHttpOutcomeKind.SUCCESS:
            return ClickHouseRawResult(
                attempt_id=self._attempt_id,
                query_id=query_id,
                payload=outcome.payload,
            )
        if outcome.kind is ClickHouseHttpOutcomeKind.RESULT_LIMIT:
            if not outcome.truncated:
                cleanup_cause = self._retire(ClickHouseTransportState.LOST)
                if cleanup_cause is not None:
                    raise ClickHouseTransportCleanupError(
                        "ClickHouse returned a complete oversized response but worker "
                        "cleanup failed: "
                        f"attempt_id={self._attempt_id}, query_id={query_id}, "
                        f"operation={operation!r}, cause_type={cleanup_cause!r}"
                    )
                raise ClickHouseResponseLimitError(
                    attempt_id=self._attempt_id,
                    query_id=query_id,
                    operation=operation,
                    received_response_bytes=outcome.received_bytes,
                    response_truncated=False,
                )
            cancellation_confirmed, cancellation_cause = self._cancel_and_retire(
                cancellation_worker,
                query_id,
                operation,
            )
            if not cancellation_confirmed:
                raise _cancellation_unconfirmed_error(
                    self._attempt_id,
                    query_id,
                    operation,
                    "ResponseLimit",
                    outcome,
                    cancellation_cause,
                )
            raise ClickHouseResponseLimitError(
                attempt_id=self._attempt_id,
                query_id=query_id,
                operation=operation,
                received_response_bytes=outcome.received_bytes,
                response_truncated=True,
            )
        if outcome.kind is ClickHouseHttpOutcomeKind.SERVER_ERROR:
            if outcome.truncated:
                cancellation_confirmed, cancellation_cause = self._cancel_and_retire(
                    cancellation_worker,
                    query_id,
                    operation,
                )
                if not cancellation_confirmed:
                    raise _cancellation_unconfirmed_error(
                        self._attempt_id,
                        query_id,
                        operation,
                        "ErrorResponseLimit",
                        outcome,
                        cancellation_cause,
                    )
                raise _query_error_from_outcome(
                    attempt_id=self._attempt_id,
                    query_id=query_id,
                    operation=operation,
                    outcome=outcome,
                    completion=ClickHouseQueryCompletion.CANCELLED,
                )
            cleanup_cause = self._retire(ClickHouseTransportState.LOST)
            if cleanup_cause is not None:
                raise ClickHouseTransportCleanupError(
                    "ClickHouse returned a terminal server error but worker cleanup failed: "
                    f"attempt_id={self._attempt_id}, query_id={query_id}, "
                    f"operation={operation!r}, cause_type={cleanup_cause!r}"
                )
            raise _query_error_from_outcome(
                attempt_id=self._attempt_id,
                query_id=query_id,
                operation=operation,
                outcome=outcome,
                completion=ClickHouseQueryCompletion.SERVER_TERMINAL,
            )
        if outcome.dispatch_state is ClickHouseHttpDispatchState.NOT_SENT:
            cleanup_cause = self._retire(ClickHouseTransportState.LOST)
            if cleanup_cause is not None:
                raise ClickHouseTransportCleanupError(
                    "ClickHouse request was not dispatched but worker cleanup failed: "
                    f"attempt_id={self._attempt_id}, query_id={query_id}, "
                    f"operation={operation!r}, cause_type={cleanup_cause!r}"
                )
            raise _query_error_from_outcome(
                attempt_id=self._attempt_id,
                query_id=query_id,
                operation=operation,
                outcome=outcome,
                completion=ClickHouseQueryCompletion.NOT_DISPATCHED,
            )
        cancellation_confirmed, cancellation_cause = self._cancel_and_retire(
            cancellation_worker,
            query_id,
            operation,
        )
        if not cancellation_confirmed:
            raise _cancellation_unconfirmed_error(
                self._attempt_id,
                query_id,
                operation,
                outcome.cause_type or outcome.kind.value,
                outcome,
                cancellation_cause,
            )
        raise _query_error_from_outcome(
            attempt_id=self._attempt_id,
            query_id=query_id,
            operation=operation,
            outcome=outcome,
            completion=ClickHouseQueryCompletion.CANCELLED,
        )

    def _raise_deadline_outcome(
        self,
        execution: ClickHouseHttpExecution,
        query_id: UUID,
        operation: str,
        cancellation_worker: ClickHouseHttpWorker,
    ) -> None:
        outcome = execution.outcome
        if outcome is not None and (
            outcome.kind
            in (
                ClickHouseHttpOutcomeKind.SUCCESS,
                ClickHouseHttpOutcomeKind.SERVER_ERROR,
                ClickHouseHttpOutcomeKind.RESULT_LIMIT,
            )
            and not outcome.truncated
        ):
            cleanup_cause = self._retire(ClickHouseTransportState.LOST)
            if cleanup_cause is not None:
                raise ClickHouseTransportCleanupError(
                    "ClickHouse query finished after its deadline but worker cleanup failed: "
                    f"attempt_id={self._attempt_id}, query_id={query_id}, "
                    f"operation={operation!r}, cause_type={cleanup_cause!r}"
                )
            raise ClickHouseAttemptDeadlineExceededError(
                attempt_id=self._attempt_id,
                query_id=query_id,
                operation=operation,
                completion=ClickHouseQueryCompletion.SERVER_TERMINAL,
            )
        if outcome is not None and (outcome.dispatch_state is ClickHouseHttpDispatchState.NOT_SENT):
            cleanup_cause = self._retire(ClickHouseTransportState.LOST)
            if cleanup_cause is not None:
                raise ClickHouseTransportCleanupError(
                    "ClickHouse query deadline expired before dispatch and cleanup failed: "
                    f"attempt_id={self._attempt_id}, query_id={query_id}, "
                    f"operation={operation!r}, cause_type={cleanup_cause!r}"
                )
            raise ClickHouseAttemptDeadlineExceededError(
                attempt_id=self._attempt_id,
                query_id=query_id,
                operation=operation,
                completion=ClickHouseQueryCompletion.NOT_DISPATCHED,
            )
        cancellation_confirmed, cancellation_cause = self._cancel_and_retire(
            cancellation_worker,
            query_id,
            operation,
        )
        if cancellation_confirmed:
            raise ClickHouseAttemptDeadlineExceededError(
                attempt_id=self._attempt_id,
                query_id=query_id,
                operation=operation,
                completion=ClickHouseQueryCompletion.CANCELLED,
            )
        raise _cancellation_unconfirmed_error(
            self._attempt_id,
            query_id,
            operation,
            "AttemptDeadlineExceeded",
            outcome,
            cancellation_cause,
        )

    def _cancel_and_retire(
        self,
        cancellation_worker: ClickHouseHttpWorker,
        query_id: UUID,
        operation: str,
    ) -> tuple[bool, str]:
        cancellation_deadline = min(
            self._deadline.deadline_nanoseconds,
            time.monotonic_ns() + self._limits.cancellation_reserve_milliseconds * 1_000_000,
        )
        if time.monotonic_ns() >= cancellation_deadline:
            cleanup_cause = self._retire(ClickHouseTransportState.CANCELLATION_UNCONFIRMED)
            return False, cleanup_cause or "CancellationDeadlineExceeded"
        control_query_id = uuid4()
        try:
            request = _clickhouse_http_request(
                settings=self._settings,
                protocol=self._protocol,
                transport_limits=self._limits,
                read_deadline=self._deadline,
                dispatch_deadline_nanoseconds=cancellation_deadline,
                io_deadline_nanoseconds=cancellation_deadline,
                query_id=control_query_id,
                query="KILL QUERY WHERE query_id = {target_query_id:String} SYNC",
                parameters={"target_query_id": str(query_id)},
                query_settings=dict(self._protocol.cancellation_query_settings),
                result_format="TabSeparatedRaw",
                max_response_bytes=self._limits.max_cancellation_response_bytes,
            )
        except (ProgrammingError, ValueError) as error:
            self._retire(ClickHouseTransportState.CANCELLATION_UNCONFIRMED)
            return False, type(error).__name__
        try:
            charge = self._accounting.dispatch_known("cancel_clickhouse_query")
        except (
            ClickHouseSourceAccountingError,
            PostgresReadDeadlineExceededError,
            PostgresSourceBudgetExceededError,
        ) as error:
            cleanup_cause = self._retire(ClickHouseTransportState.CANCELLATION_UNCONFIRMED)
            return False, cleanup_cause or type(error).__name__
        self._physical_request_count += 1
        execution = cancellation_worker.execute(
            request,
            cancellation_deadline,
        )
        outcome = execution.outcome
        accounting_error = self._consume_observed_outcome(
            charge,
            outcome,
            "TabSeparatedRaw",
        )
        if accounting_error is not None:
            cleanup_cause = self._retire(ClickHouseTransportState.CANCELLATION_UNCONFIRMED)
            return False, cleanup_cause or type(accounting_error).__name__
        if execution.deadline_exceeded or outcome is None:
            cleanup_cause = self._retire(ClickHouseTransportState.CANCELLATION_UNCONFIRMED)
            return False, cleanup_cause or "CancellationAcknowledgementDeadlineExceeded"
        kill_confirmed = outcome.kind is ClickHouseHttpOutcomeKind.SUCCESS and _kill_query_finished(
            outcome.payload,
            query_id,
            self._settings.user,
        )
        state = (
            ClickHouseTransportState.LOST
            if kill_confirmed
            else ClickHouseTransportState.CANCELLATION_UNCONFIRMED
        )
        cleanup_cause = self._retire(state)
        if kill_confirmed and cleanup_cause is None:
            return True, "KillQuerySyncFinished"
        return False, cleanup_cause or _cancellation_cause(outcome)

    def _retire(self, state: ClickHouseTransportState) -> str | None:
        cleanup_cause = self._retire_workers(graceful=False)
        self._state = (
            state if cleanup_cause is None else ClickHouseTransportState.CANCELLATION_UNCONFIRMED
        )
        return cleanup_cause

    def _retire_workers(self, graceful: bool) -> str | None:
        first_cause: str | None = None
        for worker in (self._data_worker, self._control_worker):
            try:
                if graceful:
                    worker.close()
                else:
                    worker.terminate()
            except ClickHouseHttpWorkerError as error:
                if first_cause is None:
                    first_cause = type(error).__name__
        return first_cause

    def _work_deadline_nanoseconds(self) -> int:
        now = time.monotonic_ns()
        deadline = min(
            now + self._deadline.statement_timeout_milliseconds * 1_000_000,
            self._deadline.deadline_nanoseconds
            - self._limits.cancellation_reserve_milliseconds * 1_000_000,
        )
        if now >= deadline:
            cleanup_cause = self._retire(ClickHouseTransportState.LOST)
            if cleanup_cause is not None:
                raise ClickHouseTransportCleanupError(
                    "ClickHouse attempt has no work budget and worker cleanup failed: "
                    f"attempt_id={self._attempt_id}, cause_type={cleanup_cause!r}"
                )
            raise ClickHouseAttemptDeadlineExceededError(
                attempt_id=self._attempt_id,
                query_id=uuid4(),
                operation="admit_clickhouse_query",
                completion=ClickHouseQueryCompletion.NOT_DISPATCHED,
            )
        return deadline

    def _http_deadline_nanoseconds(self, work_deadline: int) -> int:
        return min(
            self._deadline.deadline_nanoseconds,
            work_deadline + self._limits.cancellation_reserve_milliseconds * 1_000_000,
        )

    def _require_prepared_before_deadline(
        self,
        deadline_nanoseconds: int,
        query_id: UUID,
        operation: str,
    ) -> None:
        if time.monotonic_ns() < deadline_nanoseconds:
            return
        cleanup_cause = self._retire(ClickHouseTransportState.LOST)
        if cleanup_cause is not None:
            raise ClickHouseTransportCleanupError(
                "ClickHouse request preparation exceeded its deadline and worker cleanup failed: "
                f"attempt_id={self._attempt_id}, query_id={query_id}, "
                f"operation={operation!r}, cause_type={cleanup_cause!r}"
            )
        raise ClickHouseAttemptDeadlineExceededError(
            attempt_id=self._attempt_id,
            query_id=query_id,
            operation=operation,
            completion=ClickHouseQueryCompletion.NOT_DISPATCHED,
        )

    def _require_active(self, operation: str) -> None:
        if self._state is not ClickHouseTransportState.ACTIVE:
            raise ClickHouseTransportClosedError(
                "ClickHouse transport is not active: "
                f"operation={operation!r}, state={self._state.value!r}"
            )


def open_clickhouse_transport(
    settings: ClickHouseConnectionSettings,
    retry_policy: ClickHouseRetryPolicy,
    limits: ClickHouseTransportLimits,
    deadline: PostgresReadDeadline,
    attempt_id: UUID,
) -> ClickHouseTransport:
    return _open_clickhouse_transport(
        settings,
        _MODERN_CLICKHOUSE_PROTOCOL,
        retry_policy,
        limits,
        deadline,
        attempt_id,
        _UnbudgetedClickHouseRequestAccounting(),
    )


def open_legacy_clickhouse_source_transport(
    settings: ClickHouseConnectionSettings,
    retry_policy: ClickHouseRetryPolicy,
    limits: ClickHouseTransportLimits,
    deadline: PostgresReadDeadline,
    attempt_id: UUID,
) -> ClickHouseTransport:
    return _open_clickhouse_transport(
        settings,
        _LEGACY_CLICKHOUSE_21_8_PROTOCOL,
        retry_policy,
        limits,
        deadline,
        attempt_id,
        _UnbudgetedClickHouseRequestAccounting(),
    )


def open_budgeted_clickhouse_transport(
    settings: ClickHouseConnectionSettings,
    retry_policy: ClickHouseRetryPolicy,
    limits: ClickHouseTransportLimits,
    deadline: PostgresReadDeadline,
    attempt_id: UUID,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> ClickHouseTransport:
    if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
        raise TypeError("budgeted ClickHouse transport requires PostgresSourceBudgetAttempt")
    if not isinstance(cast(object, direction), PostgresSourceDirection):
        raise TypeError("budgeted ClickHouse transport requires PostgresSourceDirection")
    if source_budget.attempt_id != attempt_id:
        raise ValueError(
            "budgeted ClickHouse transport attempt ID differs from its source budget: "
            f"transport_attempt_id={attempt_id}, budget_attempt_id={source_budget.attempt_id}"
        )
    return _open_clickhouse_transport(
        settings,
        _MODERN_CLICKHOUSE_PROTOCOL,
        retry_policy,
        limits,
        deadline,
        attempt_id,
        _SourceBudgetClickHouseRequestAccounting(source_budget, direction),
    )


def open_budgeted_legacy_clickhouse_source_transport(
    settings: ClickHouseConnectionSettings,
    retry_policy: ClickHouseRetryPolicy,
    limits: ClickHouseTransportLimits,
    deadline: PostgresReadDeadline,
    attempt_id: UUID,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> ClickHouseTransport:
    if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
        raise TypeError("budgeted legacy ClickHouse transport requires PostgresSourceBudgetAttempt")
    if not isinstance(cast(object, direction), PostgresSourceDirection):
        raise TypeError("budgeted legacy ClickHouse transport requires PostgresSourceDirection")
    if source_budget.attempt_id != attempt_id:
        raise ValueError(
            "budgeted legacy ClickHouse transport attempt ID differs from its source budget: "
            f"transport_attempt_id={attempt_id}, budget_attempt_id={source_budget.attempt_id}"
        )
    return _open_clickhouse_transport(
        settings,
        _LEGACY_CLICKHOUSE_21_8_PROTOCOL,
        retry_policy,
        limits,
        deadline,
        attempt_id,
        _SourceBudgetClickHouseRequestAccounting(source_budget, direction),
    )


def _open_clickhouse_transport(
    settings: ClickHouseConnectionSettings,
    protocol: _ClickHouseTransportProtocol,
    retry_policy: ClickHouseRetryPolicy,
    limits: ClickHouseTransportLimits,
    deadline: PostgresReadDeadline,
    attempt_id: UUID,
    accounting: _ClickHouseRequestAccounting,
) -> ClickHouseTransport:
    _require_open_arguments(settings, retry_policy, limits, deadline, attempt_id)
    if type(protocol) is not _ClickHouseTransportProtocol:
        raise TypeError("ClickHouse transport protocol has an unexpected type")
    if not isinstance(cast(object, accounting), _ClickHouseRequestAccounting):
        raise TypeError("ClickHouse transport accounting has an unexpected type")
    last_error: ClickHouseQueryError | None = None
    total_dispatches = 0
    for attempt in range(1, retry_policy.max_attempts + 1):
        work_deadline = _clickhouse_work_deadline(
            deadline,
            limits,
            attempt_id,
            attempt,
        )
        data_worker: ClickHouseHttpWorker | None = None
        control_worker: ClickHouseHttpWorker | None = None
        transport: ClickHouseTransport | None = None
        keep_workers = False
        try:
            pool_config = _http_pool_config(settings, limits)
            cleanup_timeout_seconds = limits.process_cleanup_timeout_milliseconds / 1_000
            data_worker = start_clickhouse_http_worker(
                pool_config,
                work_deadline,
                cleanup_timeout_seconds,
            )
            control_worker = start_clickhouse_http_worker(
                pool_config,
                work_deadline,
                cleanup_timeout_seconds,
            )
            transport = ClickHouseTransport(
                settings=settings,
                protocol=protocol,
                limits=limits,
                deadline=deadline,
                attempt_id=attempt_id,
                connection_attempts=attempt,
                data_worker=data_worker,
                control_worker=control_worker,
                physical_request_count=total_dispatches,
                accounting=accounting,
            )
            data_probe = protocol.data_initialization
            initialized = transport.execute_raw(
                query=data_probe.query,
                parameters={},
                settings=dict(data_probe.query_settings),
                result_format="TabSeparatedRaw",
                max_response_bytes=limits.max_initialization_response_bytes,
                operation="initialize_clickhouse_transport",
            )
            total_dispatches = transport.physical_request_count
            if initialized.payload != data_probe.expected_payload:
                transport.close()
                raise ClickHouseConnectionError(
                    attempt_id=attempt_id,
                    connection_attempts=attempt,
                    query_id=initialized.query_id,
                    http_status=200,
                    error_code=None,
                    error_name=None,
                    received_error_bytes=0,
                    error_response_truncated=False,
                    cause_type="RequiredHttpTransportSettingsUnavailable",
                )
            control_initialized = transport.initialize_control_connection()
            total_dispatches = transport.physical_request_count
            if control_initialized.payload != protocol.control_initialization.expected_payload:
                transport.close()
                raise ClickHouseConnectionError(
                    attempt_id=attempt_id,
                    connection_attempts=attempt,
                    query_id=control_initialized.query_id,
                    http_status=200,
                    error_code=None,
                    error_name=None,
                    received_error_bytes=0,
                    error_response_truncated=False,
                    cause_type="RequiredControlHttpTransportSettingsUnavailable",
                )
            keep_workers = True
            return transport
        except ClickHouseQueryError as error:
            if transport is not None:
                total_dispatches = transport.physical_request_count
            last_error = error
            LOGGER.warning(
                "ClickHouse initialization attempt failed",
                extra={
                    "operation": "connect_clickhouse",
                    "attempt_id": str(attempt_id),
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "database": settings.database,
                    "user": settings.user,
                    "transport_security": settings.transport_security.value,
                    "error_code": error.error_code,
                    "error_name": error.error_name,
                    "http_status": error.http_status,
                    "completion": error.completion.value,
                },
            )
            if attempt == retry_policy.max_attempts or not _connection_error_is_retryable(error):
                raise _connection_error_from_query(error, attempt) from None
            _sleep_before_clickhouse_retry(
                retry_policy.delay_seconds,
                work_deadline,
                attempt_id,
                attempt,
            )
        except ClickHouseResponseLimitError as error:
            if transport is None:
                raise AssertionError(
                    "ClickHouse initialization limit failed before transport construction"
                ) from None
            raise ClickHouseConnectionError(
                attempt_id=attempt_id,
                connection_attempts=attempt,
                query_id=error.query_id,
                http_status=200,
                error_code=None,
                error_name=None,
                received_error_bytes=error.received_response_bytes,
                error_response_truncated=error.response_truncated,
                cause_type="InitializationResponseLimit",
            ) from None
        except ClickHouseConnectionError:
            raise
        except ClickHouseHttpWorkerStartupError as error:
            LOGGER.warning(
                "ClickHouse HTTP worker startup attempt failed",
                extra={
                    "operation": "connect_clickhouse",
                    "attempt_id": str(attempt_id),
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "database": settings.database,
                    "user": settings.user,
                    "transport_security": settings.transport_security.value,
                    "cause_type": error.cause_type,
                    "retryable": error.retryable,
                },
            )
            if attempt == retry_policy.max_attempts or not error.retryable:
                raise ClickHouseConnectionError(
                    attempt_id=attempt_id,
                    connection_attempts=attempt,
                    query_id=None,
                    http_status=None,
                    error_code=None,
                    error_name=None,
                    received_error_bytes=0,
                    error_response_truncated=False,
                    cause_type=error.cause_type,
                ) from None
            _sleep_before_clickhouse_retry(
                retry_policy.delay_seconds,
                work_deadline,
                attempt_id,
                attempt,
            )
        except ClickHouseHttpWorkerError as error:
            raise ClickHouseConnectionError(
                attempt_id=attempt_id,
                connection_attempts=attempt,
                query_id=None,
                http_status=None,
                error_code=None,
                error_name=None,
                received_error_bytes=0,
                error_response_truncated=False,
                cause_type=type(error).__name__,
            ) from None
        finally:
            if not keep_workers:
                cleanup_causes: list[str] = []
                if data_worker is not None:
                    data_cleanup_cause = _terminate_http_worker(data_worker)
                    if data_cleanup_cause is not None:
                        cleanup_causes.append(data_cleanup_cause)
                if control_worker is not None:
                    control_cleanup_cause = _terminate_http_worker(control_worker)
                    if control_cleanup_cause is not None:
                        cleanup_causes.append(control_cleanup_cause)
                if cleanup_causes:
                    raise ClickHouseTransportCleanupError(
                        "ClickHouse startup failure left isolated worker cleanup unconfirmed: "
                        f"attempt_id={attempt_id}, connection_attempt={attempt}, "
                        f"cleanup_causes={tuple(cleanup_causes)!r}"
                    )
    if last_error is None:
        raise AssertionError("ClickHouse connection loop ended without an attempt")
    raise _connection_error_from_query(last_error, retry_policy.max_attempts) from None


def _clickhouse_http_request(
    settings: ClickHouseConnectionSettings,
    protocol: _ClickHouseTransportProtocol,
    transport_limits: ClickHouseTransportLimits,
    read_deadline: PostgresReadDeadline,
    dispatch_deadline_nanoseconds: int,
    io_deadline_nanoseconds: int,
    query_id: UUID,
    query: str,
    parameters: dict[str, ClickHouseParameter],
    query_settings: dict[str, ClickHouseParameter],
    result_format: str,
    max_response_bytes: int,
) -> ClickHouseHttpRequest:
    if type(protocol) is not _ClickHouseTransportProtocol:
        raise TypeError("ClickHouse HTTP protocol has an unexpected type")
    if _CLICKHOUSE_FORMAT.fullmatch(result_format) is None:
        raise ValueError("ClickHouse result format must be an ASCII identifier")
    _require_clickhouse_request_inputs(parameters, query_settings, query, transport_limits)
    _require_protocol_query_settings(protocol, query_settings)
    try:
        bound_query, bound_parameters = bind_query(query, parameters, UTC)
    except ProgrammingError:
        raise
    if type(bound_query) is not str:
        raise ValueError("ClickHouse HTTP transport does not accept binary query bindings")
    final_query = f"{bound_query} FORMAT {result_format}"
    query_bytes = final_query.encode("utf-8", errors="strict")
    if len(query_bytes) > transport_limits.max_query_bytes:
        raise ValueError(
            "ClickHouse query exceeds its explicit UTF-8 byte bound: "
            f"max_query_bytes={transport_limits.max_query_bytes}, "
            f"actual_query_bytes={len(query_bytes)}"
        )
    if (
        required_clickhouse_ipc_message_bytes(max_response_bytes)
        > transport_limits.max_ipc_message_bytes
    ):
        raise ValueError(
            "ClickHouse response bound exceeds the isolated transport IPC bound: "
            f"max_response_bytes={max_response_bytes}, "
            f"max_ipc_message_bytes={transport_limits.max_ipc_message_bytes}"
        )
    remaining_nanoseconds = io_deadline_nanoseconds - time.monotonic_ns()
    effective_settings = _effective_clickhouse_query_settings(
        query_settings,
        read_deadline,
        max(1, remaining_nanoseconds),
    )
    url_parameters: dict[str, str] = {
        "database": settings.database,
        "query_id": str(query_id),
    }
    for name, value in protocol.url_parameters:
        if name in url_parameters:
            raise AssertionError(
                f"ClickHouse protocol URL parameter collides with request metadata: name={name!r}"
            )
        url_parameters[name] = value
    for name, value in effective_settings.items():
        _require_clickhouse_parameter_name(name, "setting")
        if name in url_parameters or name.startswith("param_"):
            raise ValueError(f"ClickHouse query setting name is reserved: name={name!r}")
        url_parameters[name] = _clickhouse_parameter_text(value, name)
    for name, value in bound_parameters.items():
        if type(name) is not str or not name.startswith("param_"):
            raise ValueError("ClickHouse binding library returned an invalid parameter name")
        if type(value) is not str:
            raise ValueError("ClickHouse binding library returned a non-text parameter value")
        if name in url_parameters:
            raise ValueError(f"ClickHouse bound parameter collides with a setting: name={name!r}")
        url_parameters[name] = value
    url = f"{_clickhouse_base_url(settings)}?{urlencode(sorted(url_parameters.items()))}"
    headers = _clickhouse_http_headers(settings)
    request_bytes = (
        len(url.encode("utf-8", errors="strict"))
        + len(query_bytes)
        + sum(
            len(name.encode("ascii", errors="strict"))
            + len(value.encode("latin-1", errors="strict"))
            for name, value in headers
        )
    )
    if request_bytes + _HTTP_IPC_OVERHEAD_BYTES > transport_limits.max_ipc_message_bytes:
        raise ValueError(
            "ClickHouse bound HTTP request exceeds the isolated transport IPC bound: "
            f"max_ipc_message_bytes={transport_limits.max_ipc_message_bytes}, "
            f"request_bytes={request_bytes}"
        )
    return ClickHouseHttpRequest(
        url=url,
        headers=headers,
        body=query_bytes,
        query_id=str(query_id),
        response_protocol=protocol.response_protocol,
        max_response_bytes=max_response_bytes,
        max_error_response_bytes=transport_limits.max_error_response_bytes,
        dispatch_deadline_nanoseconds=dispatch_deadline_nanoseconds,
        io_deadline_nanoseconds=io_deadline_nanoseconds,
    )


def _require_protocol_query_settings(
    protocol: _ClickHouseTransportProtocol,
    query_settings: dict[str, ClickHouseParameter],
) -> None:
    if type(protocol) is not _ClickHouseTransportProtocol:
        raise TypeError("ClickHouse query protocol has an unexpected type")
    if type(query_settings) is not dict:
        raise TypeError("ClickHouse query settings must be a dictionary")
    names = frozenset(query_settings)
    owned = names & protocol.transport_owned_query_settings
    if owned:
        raise ValueError(
            "ClickHouse query settings must not override transport-owned metadata: "
            f"settings={tuple(sorted(owned))!r}"
        )
    locked = names & protocol.locked_query_settings
    if locked:
        raise ValueError(
            "ClickHouse query settings must omit values locked by the selected runtime profile: "
            f"runtime_profile={protocol.runtime_profile.value!r}, "
            f"settings={tuple(sorted(locked))!r}"
        )
    unsupported = names & protocol.unsupported_query_settings
    if unsupported:
        raise ValueError(
            "ClickHouse query settings are unsupported by the selected runtime profile: "
            f"runtime_profile={protocol.runtime_profile.value!r}, "
            f"settings={tuple(sorted(unsupported))!r}"
        )


def _require_clickhouse_request_inputs(
    parameters: dict[str, ClickHouseParameter],
    query_settings: dict[str, ClickHouseParameter],
    query: str,
    transport_limits: ClickHouseTransportLimits,
) -> None:
    if type(parameters) is not dict:
        raise TypeError("ClickHouse query parameters must be a dictionary")
    if type(query_settings) is not dict:
        raise TypeError("ClickHouse query settings must be a dictionary")
    input_bytes = len(query.encode("utf-8", errors="strict"))
    for values, label in ((parameters, "parameter"), (query_settings, "setting")):
        for name, value in values.items():
            _require_clickhouse_parameter_name(name, label)
            input_bytes += len(name.encode("ascii", errors="strict"))
            if type(value) is int:
                input_bytes += len(str(value))
            elif type(value) is str:
                validate_clickhouse_text_scalar(value, f"ClickHouse query {label} {name}")
                input_bytes += len(value.encode("utf-8", errors="strict"))
            else:
                raise TypeError(
                    f"ClickHouse query {label} must be text or an integer: name={name!r}"
                )
    if input_bytes + _HTTP_IPC_OVERHEAD_BYTES > transport_limits.max_ipc_message_bytes:
        raise ValueError(
            "ClickHouse query inputs exceed the isolated transport IPC bound before binding: "
            f"max_ipc_message_bytes={transport_limits.max_ipc_message_bytes}, "
            f"input_bytes={input_bytes}"
        )


def _effective_clickhouse_query_settings(
    settings: dict[str, ClickHouseParameter],
    deadline: PostgresReadDeadline,
    remaining_nanoseconds: int,
) -> dict[str, ClickHouseParameter]:
    if type(settings) is not dict:
        raise TypeError("ClickHouse query settings must be a dictionary")
    effective = dict(settings)
    configured_execution_time = effective.get("max_execution_time")
    if configured_execution_time is not None and (
        type(configured_execution_time) is not int or configured_execution_time < 1
    ):
        raise ValueError("ClickHouse max_execution_time must be a positive integer")
    remaining_seconds = max(1, math.ceil(remaining_nanoseconds / 1_000_000_000))
    statement_seconds = math.ceil(deadline.statement_timeout_milliseconds / 1_000) + 1
    execution_seconds = min(remaining_seconds, statement_seconds)
    if type(configured_execution_time) is int:
        execution_seconds = min(execution_seconds, configured_execution_time)
    effective["max_execution_time"] = execution_seconds
    return effective


def _clickhouse_base_url(settings: ClickHouseConnectionSettings) -> str:
    host = settings.host
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{_interface(settings.transport_security)}://{rendered_host}:{settings.port}/"


def _clickhouse_http_headers(
    settings: ClickHouseConnectionSettings,
) -> tuple[tuple[str, str], ...]:
    if ":" in settings.user:
        raise ValueError("ClickHouse HTTP Basic-auth user must not contain ':'")
    for value, label in (
        (settings.user, "user"),
        (settings.password.get_secret_value(), "password"),
        (settings.application_name, "application name"),
    ):
        if "\r" in value or "\n" in value:
            raise ValueError(f"ClickHouse HTTP {label} must not contain CR or LF")
    authorization = b64encode(
        f"{settings.user}:{settings.password.get_secret_value()}".encode()
    ).decode("ascii")
    return (
        ("Accept-Encoding", "identity"),
        ("Authorization", f"Basic {authorization}"),
        ("Content-Type", "text/plain; charset=utf-8"),
        ("User-Agent", settings.application_name),
    )


def _clickhouse_parameter_text(value: ClickHouseParameter, name: str) -> str:
    if type(value) is int:
        return str(value)
    if type(value) is str:
        validate_clickhouse_text_scalar(value, f"ClickHouse query setting {name}")
        return value
    raise TypeError(f"ClickHouse query setting must be text or an integer: name={name!r}")


def _require_clickhouse_parameter_name(name: str, label: str) -> None:
    if type(name) is not str or _CLICKHOUSE_PARAMETER_NAME.fullmatch(name) is None:
        raise ValueError(f"ClickHouse {label} name must be an ASCII identifier")


def _query_error_from_outcome(
    attempt_id: UUID,
    query_id: UUID,
    operation: str,
    outcome: ClickHouseHttpOutcome,
    completion: ClickHouseQueryCompletion,
) -> ClickHouseQueryError:
    cause_type = outcome.cause_type or "ClickHouseServerError"
    return ClickHouseQueryError(
        attempt_id=attempt_id,
        query_id=query_id,
        operation=operation,
        http_status=outcome.status_code,
        error_code=outcome.error_code,
        error_name=outcome.error_name,
        received_error_bytes=outcome.received_bytes,
        error_response_truncated=outcome.truncated,
        cause_type=cause_type,
        completion=completion,
    )


def _cancellation_unconfirmed_error(
    attempt_id: UUID,
    query_id: UUID,
    operation: str,
    trigger_cause: str,
    outcome: ClickHouseHttpOutcome | None,
    cancellation_cause: str,
) -> ClickHouseCancellationUnconfirmedError:
    return ClickHouseCancellationUnconfirmedError(
        attempt_id=attempt_id,
        query_id=query_id,
        operation=operation,
        trigger_cause=trigger_cause,
        cancellation_cause=cancellation_cause,
        http_status=None if outcome is None else outcome.status_code,
        error_code=None if outcome is None else outcome.error_code,
        error_name=None if outcome is None else outcome.error_name,
        received_response_bytes=0 if outcome is None else outcome.received_bytes,
        response_truncated=False if outcome is None else outcome.truncated,
    )


def _kill_query_finished(
    payload: bytes,
    target_query_id: UUID,
    expected_user: str,
) -> bool:
    validate_clickhouse_text_scalar(expected_user, "ClickHouse cancellation user")
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        return False
    row = payload[:-1]
    if b"\n" in row or b"\r" in row:
        return False
    fields = row.split(b"\t")
    if len(fields) != 4 or fields[0] != b"finished" or not fields[3]:
        return False
    try:
        observed_query_id = fields[1].decode("ascii", errors="strict")
        observed_user = fields[2].decode("utf-8", errors="strict")
        fields[3].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return observed_query_id == str(target_query_id) and observed_user == expected_user


def _cancellation_cause(outcome: ClickHouseHttpOutcome) -> str:
    if outcome.cause_type is not None:
        return outcome.cause_type
    if outcome.kind is ClickHouseHttpOutcomeKind.SERVER_ERROR:
        return "KillQueryServerError"
    if outcome.kind is ClickHouseHttpOutcomeKind.RESULT_LIMIT:
        return "KillQueryResponseLimit"
    if outcome.kind is ClickHouseHttpOutcomeKind.SUCCESS:
        return "KillQueryNotFinished"
    return "KillQueryProtocolError"


def _terminate_http_worker(worker: ClickHouseHttpWorker) -> str | None:
    try:
        worker.terminate()
    except ClickHouseHttpWorkerError as error:
        return type(error).__name__
    return None


def _http_pool_config(
    settings: ClickHouseConnectionSettings,
    limits: ClickHouseTransportLimits,
) -> ClickHouseHttpPoolConfig:
    return ClickHouseHttpPoolConfig(
        ca_cert=settings.ca_cert,
        tls_preflight_url=(
            f"{_clickhouse_base_url(settings)}ping"
            if settings.transport_security is ClickHouseTransportSecurity.TLS_VERIFY
            else None
        ),
        connect_timeout_seconds=settings.connect_timeout_seconds,
        read_timeout_seconds=settings.send_receive_timeout_seconds,
        max_ipc_message_bytes=limits.max_ipc_message_bytes,
    )


def _clickhouse_work_deadline(
    deadline: PostgresReadDeadline,
    limits: ClickHouseTransportLimits,
    attempt_id: UUID,
    connection_attempts: int,
) -> int:
    now = time.monotonic_ns()
    work_deadline = min(
        now + deadline.statement_timeout_milliseconds * 1_000_000,
        deadline.deadline_nanoseconds - limits.cancellation_reserve_milliseconds * 1_000_000,
    )
    if now >= work_deadline:
        raise ClickHouseConnectionError(
            attempt_id=attempt_id,
            connection_attempts=connection_attempts,
            query_id=None,
            http_status=None,
            error_code=None,
            error_name=None,
            received_error_bytes=0,
            error_response_truncated=False,
            cause_type="AttemptDeadlineExceededBeforeInitialization",
        )
    return work_deadline


def _require_open_arguments(
    settings: ClickHouseConnectionSettings,
    retry_policy: ClickHouseRetryPolicy,
    limits: ClickHouseTransportLimits,
    deadline: PostgresReadDeadline,
    attempt_id: UUID,
) -> None:
    if type(settings) is not ClickHouseConnectionSettings:
        raise TypeError("settings must be ClickHouseConnectionSettings")
    if type(retry_policy) is not ClickHouseRetryPolicy:
        raise TypeError("retry_policy must be ClickHouseRetryPolicy")
    if type(limits) is not ClickHouseTransportLimits:
        raise TypeError("limits must be ClickHouseTransportLimits")
    if type(deadline) is not PostgresReadDeadline:
        raise TypeError("deadline must be PostgresReadDeadline")
    if type(attempt_id) is not UUID or attempt_id.int == 0:
        raise ValueError("attempt_id must be a non-zero UUID")


def _require_transport_runtime_profile(
    transport: ClickHouseTransport,
    expected_profile: ClickHouseRuntimeProfile,
    operation: str,
) -> None:
    if type(transport) is not ClickHouseTransport:
        raise TypeError("ClickHouse profile inspection requires ClickHouseTransport")
    if not isinstance(cast(object, expected_profile), ClickHouseRuntimeProfile):
        raise TypeError("expected ClickHouse runtime profile has an unexpected type")
    validate_clickhouse_text_scalar(operation, "ClickHouse runtime-profile operation")
    if transport.runtime_profile is not expected_profile:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse transport runtime profile does not match the requested operation: "
            f"operation={operation!r}, expected={expected_profile.value!r}, "
            f"actual={transport.runtime_profile.value!r}"
        )


def _connection_error_is_retryable(error: ClickHouseQueryError) -> bool:
    return (
        error.completion
        in (ClickHouseQueryCompletion.NOT_DISPATCHED, ClickHouseQueryCompletion.CANCELLED)
        or error.http_status in _RETRYABLE_HTTP_STATUSES
    )


def _connection_error_from_query(
    error: ClickHouseQueryError,
    connection_attempts: int,
) -> ClickHouseConnectionError:
    return ClickHouseConnectionError(
        attempt_id=error.attempt_id,
        connection_attempts=connection_attempts,
        query_id=error.query_id,
        http_status=error.http_status,
        error_code=error.error_code,
        error_name=error.error_name,
        received_error_bytes=error.received_error_bytes,
        error_response_truncated=error.error_response_truncated,
        cause_type=error.cause_type,
    )


def _sleep_before_clickhouse_retry(
    delay_seconds: float,
    work_deadline: int,
    attempt_id: UUID,
    connection_attempts: int,
) -> None:
    remaining_seconds = (work_deadline - time.monotonic_ns()) / 1_000_000_000
    if delay_seconds >= remaining_seconds:
        raise ClickHouseConnectionError(
            attempt_id=attempt_id,
            connection_attempts=connection_attempts,
            query_id=None,
            http_status=None,
            error_code=None,
            error_name=None,
            received_error_bytes=0,
            error_response_truncated=False,
            cause_type="AttemptDeadlineExceededBeforeRetry",
        )
    time.sleep(delay_seconds)


def inspect_clickhouse_server_profile(
    transport: ClickHouseTransport,
    settings: ClickHouseConnectionSettings,
) -> ClickHouseServerProfile:
    _require_transport_runtime_profile(
        transport,
        ClickHouseRuntimeProfile.LTS,
        "inspect_server_profile",
    )
    result = transport.execute_raw(
        query=(
            "SELECT version() AS server_version, "
            "(SELECT value FROM system.build_options "
            "WHERE name = 'VERSION_INTEGER') AS server_version_number, "
            "buildId() AS build_id, "
            "serverTimezone() AS server_timezone, timezone() AS session_timezone, "
            "currentUser() AS current_user, "
            "currentDatabase() AS current_database, "
            "toString(getSetting('readonly')) AS readonly, "
            "toString(getSetting('max_memory_usage')) AS max_memory_usage, "
            "toString(getSetting('max_threads')) AS max_threads, "
            "toString(getSetting('max_result_rows')) AS max_result_rows, "
            "toString(getSetting('max_result_bytes')) AS max_result_bytes, "
            "toString(getSetting('result_overflow_mode')) AS result_overflow_mode"
        ),
        parameters={},
        settings={"session_timezone": "UTC"},
        result_format="JSONEachRow",
        max_response_bytes=_MAX_PROFILE_RESPONSE_BYTES,
        operation="inspect_server_profile",
    )
    payload = _single_json_row(result.payload, _ClickHouseProfilePayload, "server profile")
    setting_result = transport.execute_raw(
        query=(
            "SELECT name, value, min, max, readonly FROM system.settings "
            "WHERE name IN "
            "('readonly', 'max_memory_usage', 'max_threads', 'max_execution_time', "
            "'max_result_rows', 'max_result_bytes', 'max_rows_to_group_by', "
            "'result_overflow_mode') "
            "ORDER BY name"
        ),
        parameters={},
        settings={"session_timezone": "UTC"},
        result_format="JSONEachRow",
        max_response_bytes=_MAX_SETTINGS_RESPONSE_BYTES,
        operation="inspect_resource_constraints",
    )
    setting_rows = parse_clickhouse_json_rows(
        setting_result.payload,
        _ClickHouseSettingPayload,
        "resource constraints",
    )
    settings_by_name = _settings_by_name(setting_rows)
    profile = ClickHouseServerProfile(
        provenance=ClickHouseModernProfileProvenance(
            runtime_profile=ClickHouseRuntimeProfile.LTS,
            response_protocol=ClickHouseHttpResponseProtocol.MODERN_EXCEPTION_FRAME,
            timezone_strategy=ClickHouseTimezoneStrategy.SESSION_SETTING,
        ),
        binding_library_name="clickhouse-connect",
        binding_library_version=_validated_driver_version(package_version("clickhouse-connect")),
        transport_library_name="urllib3",
        transport_library_version=_validated_driver_version(package_version("urllib3")),
        server_version=_validated_profile_text(payload.server_version, "server version"),
        server_version_number=_parse_positive_integer(
            payload.server_version_number,
            "server version number",
        ),
        build_id=_validated_profile_text(payload.build_id, "build ID"),
        server_timezone=_validated_profile_text(payload.server_timezone, "server timezone"),
        session_timezone=_validated_profile_text(payload.session_timezone, "session timezone"),
        current_user=_validated_profile_text(payload.current_user, "current user"),
        current_database=_validated_profile_text(payload.current_database, "current database"),
        readonly=_parse_nonnegative_integer(payload.readonly, "readonly"),
        max_memory_usage=_parse_nonnegative_integer(payload.max_memory_usage, "max_memory_usage"),
        max_threads=_parse_nonnegative_integer(payload.max_threads, "max_threads"),
        max_execution_time_seconds=_required_setting_maximum(
            settings_by_name[ClickHouseResourceSetting.MAX_EXECUTION_TIME.value],
            ClickHouseResourceSetting.MAX_EXECUTION_TIME,
        ),
        effective_max_execution_time_seconds=_parse_nonnegative_decimal(
            settings_by_name[ClickHouseResourceSetting.MAX_EXECUTION_TIME.value].value,
            "effective max_execution_time",
        ),
        max_result_rows=_parse_nonnegative_integer(payload.max_result_rows, "max_result_rows"),
        max_result_bytes=_parse_nonnegative_integer(payload.max_result_bytes, "max_result_bytes"),
        result_overflow_mode=_validated_profile_text(
            payload.result_overflow_mode, "result_overflow_mode"
        ),
        readonly_locked=_setting_is_locked(settings_by_name["readonly"]),
        result_overflow_mode_locked=_setting_is_locked(settings_by_name["result_overflow_mode"]),
        resource_constraints=_resource_constraints(settings_by_name),
    )
    _require_clickhouse_profile(profile, settings)
    return profile


def inspect_legacy_clickhouse_server_profile(
    transport: ClickHouseTransport,
    settings: ClickHouseConnectionSettings,
) -> ClickHouseServerProfile:
    _require_transport_runtime_profile(
        transport,
        ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE,
        "inspect_legacy_server_profile",
    )
    result = transport.execute_raw(
        query=(
            "SELECT version() AS server_version, "
            "(SELECT value FROM system.build_options "
            "WHERE name = 'VERSION_INTEGER') AS server_version_number, "
            "buildId() AS build_id, "
            "timezone() AS server_timezone, timezone() AS session_timezone, "
            "currentUser() AS current_user, "
            "currentDatabase() AS current_database, "
            "toString(getSetting('readonly')) AS readonly, "
            "toString(getSetting('max_memory_usage')) AS max_memory_usage, "
            "toString(getSetting('max_threads')) AS max_threads, "
            "toString(getSetting('max_result_rows')) AS max_result_rows, "
            "toString(getSetting('max_result_bytes')) AS max_result_bytes, "
            "toString(getSetting('result_overflow_mode')) AS result_overflow_mode, "
            "toString(toUInt8(getSetting("
            "'cancel_http_readonly_queries_on_client_close'))) "
            "AS cancel_http_readonly_queries_on_client_close, "
            "toString(toUInt8(getSetting('send_progress_in_http_headers'))) "
            "AS send_progress_in_http_headers"
        ),
        parameters={},
        settings={},
        result_format="JSONEachRow",
        max_response_bytes=_MAX_PROFILE_RESPONSE_BYTES,
        operation="inspect_server_profile",
    )
    payload = _single_json_row(
        result.payload,
        _ClickHouseLegacyProfilePayload,
        "legacy server profile",
    )
    setting_result = transport.execute_raw(
        query=(
            "SELECT name, value, min, max, readonly FROM system.settings "
            "WHERE name IN "
            "('readonly', 'max_memory_usage', 'max_threads', 'max_execution_time', "
            "'max_result_rows', 'max_result_bytes', 'max_rows_to_group_by', "
            "'result_overflow_mode', "
            "'cancel_http_readonly_queries_on_client_close', "
            "'send_progress_in_http_headers', "
            "'allow_experimental_projection_optimization', "
            "'force_optimize_projection', 'timeout_overflow_mode', "
            "'read_overflow_mode', 'read_overflow_mode_leaf', "
            "'sort_overflow_mode', 'group_by_overflow_mode') "
            "ORDER BY name"
        ),
        parameters={},
        settings={},
        result_format="JSONEachRow",
        max_response_bytes=_MAX_SETTINGS_RESPONSE_BYTES,
        operation="inspect_resource_constraints",
    )
    setting_rows = parse_clickhouse_json_rows(
        setting_result.payload,
        _ClickHouseSettingPayload,
        "legacy resource constraints",
    )
    settings_by_name = _legacy_settings_by_name(setting_rows)
    readonly = _parse_nonnegative_integer(payload.readonly, "readonly")
    catalog_readonly = _parse_nonnegative_integer(
        settings_by_name["readonly"].value,
        "readonly catalog value",
    )
    if readonly != catalog_readonly:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy readonly setting changed between profile observations"
        )
    cancel_on_close = _parse_binary_integer(
        payload.cancel_http_readonly_queries_on_client_close,
        "cancel_http_readonly_queries_on_client_close",
    )
    send_progress = _parse_binary_integer(
        payload.send_progress_in_http_headers,
        "send_progress_in_http_headers",
    )
    if cancel_on_close != _parse_binary_integer(
        settings_by_name["cancel_http_readonly_queries_on_client_close"].value,
        "cancel_http_readonly_queries_on_client_close catalog value",
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse legacy cancellation setting changed between profile observations"
        )
    if send_progress != _parse_binary_integer(
        settings_by_name["send_progress_in_http_headers"].value,
        "send_progress_in_http_headers catalog value",
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse legacy progress-header setting changed between profile observations"
        )
    profile = ClickHouseServerProfile(
        provenance=ClickHouseLegacyProfileProvenance(
            runtime_profile=ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE,
            response_protocol=ClickHouseHttpResponseProtocol.LEGACY_CLEAN_EOF,
            timezone_strategy=ClickHouseTimezoneStrategy.SERVER_UTC_CONFIGURATION,
            cancel_http_readonly_queries_on_client_close=cancel_on_close,
            cancel_http_readonly_queries_on_client_close_locked=_setting_is_locked(
                settings_by_name["cancel_http_readonly_queries_on_client_close"]
            ),
            send_progress_in_http_headers=send_progress,
            send_progress_in_http_headers_locked=_setting_is_locked(
                settings_by_name["send_progress_in_http_headers"]
            ),
            allow_experimental_projection_optimization=_parse_binary_integer(
                settings_by_name["allow_experimental_projection_optimization"].value,
                "allow_experimental_projection_optimization",
            ),
            allow_experimental_projection_optimization_locked=_setting_is_locked(
                settings_by_name["allow_experimental_projection_optimization"]
            ),
            force_optimize_projection=_parse_binary_integer(
                settings_by_name["force_optimize_projection"].value,
                "force_optimize_projection",
            ),
            force_optimize_projection_locked=_setting_is_locked(
                settings_by_name["force_optimize_projection"]
            ),
            locked_overflow_modes=_legacy_locked_overflow_modes(settings_by_name),
        ),
        binding_library_name="clickhouse-connect",
        binding_library_version=_validated_driver_version(package_version("clickhouse-connect")),
        transport_library_name="urllib3",
        transport_library_version=_validated_driver_version(package_version("urllib3")),
        server_version=_validated_profile_text(payload.server_version, "server version"),
        server_version_number=_parse_positive_integer(
            payload.server_version_number,
            "server version number",
        ),
        build_id=_validated_profile_text(payload.build_id, "build ID"),
        server_timezone=_validated_profile_text(payload.server_timezone, "server timezone"),
        session_timezone=_validated_profile_text(payload.session_timezone, "session timezone"),
        current_user=_validated_profile_text(payload.current_user, "current user"),
        current_database=_validated_profile_text(payload.current_database, "current database"),
        readonly=readonly,
        max_memory_usage=_parse_nonnegative_integer(payload.max_memory_usage, "max_memory_usage"),
        max_threads=_parse_nonnegative_integer(payload.max_threads, "max_threads"),
        max_execution_time_seconds=_required_setting_maximum(
            settings_by_name[ClickHouseResourceSetting.MAX_EXECUTION_TIME.value],
            ClickHouseResourceSetting.MAX_EXECUTION_TIME,
        ),
        effective_max_execution_time_seconds=_parse_nonnegative_decimal(
            settings_by_name[ClickHouseResourceSetting.MAX_EXECUTION_TIME.value].value,
            "effective max_execution_time",
        ),
        max_result_rows=_parse_nonnegative_integer(payload.max_result_rows, "max_result_rows"),
        max_result_bytes=_parse_nonnegative_integer(payload.max_result_bytes, "max_result_bytes"),
        result_overflow_mode=_validated_profile_text(
            payload.result_overflow_mode,
            "result_overflow_mode",
        ),
        readonly_locked=_setting_is_locked(settings_by_name["readonly"]),
        result_overflow_mode_locked=_setting_is_locked(settings_by_name["result_overflow_mode"]),
        resource_constraints=_resource_constraints(settings_by_name),
    )
    _require_legacy_clickhouse_profile(profile, settings)
    return profile


def inspect_clickhouse_fidelity_relation(
    transport: ClickHouseTransport,
    database: str,
    table: str,
    decimal_column: str,
    datetime_column: str,
) -> ClickHouseFidelityRelation:
    for label, identifier in (
        ("ClickHouse database", database),
        ("ClickHouse table", table),
        ("ClickHouse decimal column", decimal_column),
        ("ClickHouse DateTime64 column", datetime_column),
    ):
        validate_clickhouse_identifier(identifier, label)
    result = transport.execute_raw(
        query=(
            "SELECT name, type FROM system.columns "
            "WHERE database = {database:String} AND table = {table:String} "
            "AND name IN ({decimal_column:String}, {datetime_column:String}) "
            "ORDER BY position"
        ),
        parameters={
            "database": database,
            "table": table,
            "decimal_column": decimal_column,
            "datetime_column": datetime_column,
        },
        settings={"session_timezone": "UTC", "max_result_rows": 3},
        result_format="JSONEachRow",
        max_response_bytes=_MAX_CATALOG_RESPONSE_BYTES,
        operation="inspect_fidelity_relation",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _ClickHouseColumnPayload,
        "fidelity relation catalog",
    )
    by_name = {row.name: row.type for row in rows}
    if (
        len(rows) != 2
        or len(by_name) != 2
        or set(by_name)
        != {
            decimal_column,
            datetime_column,
        }
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse fidelity relation must expose both requested physical columns exactly once: "
            f"database={database!r}, table={table!r}, observed_columns={tuple(by_name)!r}"
        )
    decimal_type = parse_clickhouse_decimal_type(by_name[decimal_column])
    datetime_type = inspect_clickhouse_datetime64_type(transport, by_name[datetime_column])
    return ClickHouseFidelityRelation(
        database=database,
        table=table,
        decimal_column=decimal_column,
        decimal_type=decimal_type,
        datetime_column=datetime_column,
        datetime_type=datetime_type,
    )


def read_clickhouse_exact_values(
    transport: ClickHouseTransport,
    request: ClickHouseExactReadRequest,
) -> tuple[ClickHouseExactRow, ...]:
    decimal_reinterpret = clickhouse_decimal_reinterpret_function(
        request.relation.decimal_type.precision
    )
    database = quote_clickhouse_identifier(request.relation.database)
    table = quote_clickhouse_identifier(request.relation.table)
    order_column = quote_clickhouse_identifier(request.order_column)
    decimal_column = quote_clickhouse_identifier(request.relation.decimal_column)
    datetime_column = quote_clickhouse_identifier(request.relation.datetime_column)
    result = transport.execute_raw(
        query=(
            f"SELECT toString({order_column}), "
            f"toString({decimal_reinterpret}({decimal_column})), "
            f"toDecimalString({decimal_column}, {{decimal_scale:UInt8}}), "
            f"toString(reinterpretAsInt64({datetime_column})), "
            f"toString(toTimeZone({datetime_column}, 'UTC')) "
            f"FROM {database}.{table} ORDER BY {order_column} "
            "LIMIT {row_limit:UInt64}"
        ),
        parameters={
            "decimal_scale": request.relation.decimal_type.scale,
            "row_limit": request.max_rows + 1,
        },
        settings={
            "session_timezone": "UTC",
            "max_execution_time": request.max_execution_time_seconds,
            "max_result_rows": request.max_rows + 1,
            "max_result_bytes": request.max_response_bytes,
            "result_overflow_mode": "throw",
        },
        result_format="TabSeparatedRaw",
        max_response_bytes=request.max_response_bytes,
        operation="read_exact_decimal_datetime64_values",
    )
    lines = result.payload.splitlines()
    if len(lines) > request.max_rows:
        raise ClickHouseResultLimitError(
            "ClickHouse exact-value read exceeded its row bound: "
            f"query_id={result.query_id}, max_rows={request.max_rows}, actual_rows={len(lines)}"
        )
    return tuple(
        _parse_exact_row(line, request.relation, row_ordinal)
        for row_ordinal, line in enumerate(lines, start=1)
    )


def _parse_exact_row(
    line: bytes,
    relation: ClickHouseFidelityRelation,
    row_ordinal: int,
) -> ClickHouseExactRow:
    fields = line.split(b"\t")
    if len(fields) != 5:
        raise ClickHouseDataValidationError(
            "ClickHouse exact-value row must contain five tab-separated fields: "
            f"row_ordinal={row_ordinal}, actual_fields={len(fields)}"
        )
    try:
        values = tuple(field.decode("ascii") for field in fields)
    except UnicodeDecodeError as error:
        raise ClickHouseDataValidationError(
            "ClickHouse exact Decimal/DateTime64 payload must be ASCII: "
            f"row_ordinal={row_ordinal}, start={error.start}, end={error.end}"
        ) from None
    order_value = _parse_integer(values[0], f"row {row_ordinal} order value")
    decimal_scaled = _parse_integer(values[1], f"row {row_ordinal} Decimal scaled value")
    decimal_text = values[2]
    _require_decimal_text(
        decimal_text,
        decimal_scaled,
        relation.decimal_type,
        row_ordinal,
    )
    datetime_ticks = _parse_integer(values[3], f"row {row_ordinal} DateTime64 ticks")
    datetime_text = values[4]
    expected_datetime = _render_utc_datetime64(datetime_ticks, relation.datetime_type.precision)
    if datetime_text != expected_datetime:
        raise ClickHouseDataValidationError(
            "ClickHouse DateTime64 text does not match its exact stored ticks: "
            f"row_ordinal={row_ordinal}, precision={relation.datetime_type.precision}, "
            f"physical_timezone={relation.datetime_type.timezone!r}"
        )
    return ClickHouseExactRow(
        order_value=order_value,
        decimal_scaled_value=decimal_scaled,
        decimal_text=decimal_text,
        datetime_ticks=datetime_ticks,
        datetime_text=datetime_text,
    )


def _require_decimal_text(
    text: str,
    scaled_value: int,
    decimal_type: ClickHouseDecimalType,
    row_ordinal: int,
) -> None:
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise ClickHouseDataValidationError(
            f"ClickHouse Decimal text is invalid: row_ordinal={row_ordinal}"
        ) from None
    if value.as_tuple().exponent != -decimal_type.scale:
        raise ClickHouseDataValidationError(
            "ClickHouse Decimal text does not preserve its declared scale: "
            f"row_ordinal={row_ordinal}, expected_scale={decimal_type.scale}"
        )
    with localcontext() as context:
        context.prec = decimal_type.precision + decimal_type.scale + 2
        observed_scaled = value.scaleb(decimal_type.scale)
    if (
        observed_scaled != observed_scaled.to_integral_value()
        or int(observed_scaled) != scaled_value
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse Decimal text does not match its exact stored integer: "
            f"row_ordinal={row_ordinal}, precision={decimal_type.precision}, "
            f"scale={decimal_type.scale}"
        )
    if abs(scaled_value) >= 10**decimal_type.precision:
        raise ClickHouseDataValidationError(
            "ClickHouse Decimal stored integer exceeds its declared precision: "
            f"row_ordinal={row_ordinal}, precision={decimal_type.precision}"
        )


def _render_utc_datetime64(ticks: int, precision: int) -> str:
    scale = 10**precision
    seconds, fraction = divmod(ticks, scale)
    try:
        value = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    except OverflowError:
        raise ClickHouseDataValidationError(
            "ClickHouse DateTime64 ticks exceed the canonical calendar range: "
            f"precision={precision}"
        ) from None
    rendered = (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d} "
        f"{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
    )
    if precision == 0:
        return rendered
    return f"{rendered}.{fraction:0{precision}d}"


def parse_clickhouse_decimal_type(type_name: str) -> ClickHouseDecimalType:
    match = _DECIMAL_TYPE.fullmatch(type_name)
    if match is None:
        raise UnsupportedClickHouseProfileError(
            f"ClickHouse physical type is not Decimal(P, S): type={type_name!r}"
        )
    precision = int(match.group(1))
    scale = int(match.group(2))
    if not 1 <= precision <= 76 or not 0 <= scale <= precision:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse Decimal type is outside the engine's supported precision/scale: "
            f"type={type_name!r}"
        )
    return ClickHouseDecimalType(precision=precision, scale=scale)


def inspect_clickhouse_datetime64_type(
    transport: ClickHouseTransport,
    type_name: str,
) -> ClickHouseDateTime64Type:
    precision, declared_timezone = parse_clickhouse_datetime64_declaration(type_name)
    result = transport.execute_raw(
        query=(
            "SELECT timezoneOf(defaultValueOfTypeName({type_name:String})) AS effective_timezone"
        ),
        parameters={"type_name": type_name},
        settings={"session_timezone": "UTC"},
        result_format="JSONEachRow",
        max_response_bytes=_MAX_TIMEZONE_RESPONSE_BYTES,
        operation="inspect_datetime64_timezone",
    )
    payload = _single_json_row(
        result.payload,
        _ClickHouseTimeZonePayload,
        "DateTime64 effective timezone",
    )
    effective_timezone = _validated_profile_text(
        payload.effective_timezone,
        "DateTime64 effective timezone",
    )
    return ClickHouseDateTime64Type(
        precision=precision,
        declared_timezone=declared_timezone,
        timezone=effective_timezone,
    )


def parse_clickhouse_datetime64_declaration(type_name: str) -> tuple[int, str | None]:
    match = _DATETIME64_TYPE.fullmatch(type_name)
    if match is None:
        raise UnsupportedClickHouseProfileError(
            f"ClickHouse physical type is not DateTime64(P, timezone): type={type_name!r}"
        )
    precision = int(match.group(1))
    timezone = match.group(2)
    if not 0 <= precision <= 9:
        raise UnsupportedClickHouseProfileError(
            f"ClickHouse DateTime64 precision is outside canonical v1: type={type_name!r}"
        )
    if timezone is not None:
        validate_clickhouse_text_scalar(timezone, "ClickHouse DateTime64 timezone")
    return precision, timezone


def clickhouse_decimal_reinterpret_function(precision: int) -> str:
    if precision <= 9:
        return "reinterpretAsInt32"
    if precision <= 18:
        return "reinterpretAsInt64"
    if precision <= 38:
        return "reinterpretAsInt128"
    return "reinterpretAsInt256"


def _single_json_row[Payload: BaseModel](
    payload: bytes,
    model_type: type[Payload],
    label: str,
) -> Payload:
    rows = parse_clickhouse_json_rows(payload, model_type, label)
    if len(rows) != 1:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must return exactly one row: actual={len(rows)}"
        )
    return rows[0]


def parse_clickhouse_json_rows[Payload: BaseModel](
    payload: bytes,
    model_type: type[Payload],
    label: str,
) -> tuple[Payload, ...]:
    if type(payload) is not bytes:
        raise TypeError("ClickHouse JSONEachRow payload must be bytes")
    if not payload:
        return ()
    if b"\r" in payload:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} returned a JSONEachRow response containing a carriage return"
        )
    if not payload.endswith(b"\n"):
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} returned an incomplete JSONEachRow response: missing final LF"
        )
    lines = payload[:-1].split(b"\n")
    for ordinal, line in enumerate(lines, start=1):
        if not line:
            raise ClickHouseDataValidationError(
                f"ClickHouse {label} returned an empty JSONEachRow record: record={ordinal}"
            )
    try:
        return tuple(model_type.model_validate_json(line) for line in lines)
    except ValueError as error:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} returned invalid typed JSON: cause_type={type(error).__name__}"
        ) from None


def _settings_by_name(
    rows: tuple[_ClickHouseSettingPayload, ...],
) -> dict[str, _ClickHouseSettingPayload]:
    expected = {
        "readonly",
        "max_memory_usage",
        "max_threads",
        "max_execution_time",
        "max_result_rows",
        "max_result_bytes",
        "max_rows_to_group_by",
        "result_overflow_mode",
    }
    by_name = {row.name: row for row in rows}
    if len(rows) != len(expected) or set(by_name) != expected:
        raise ClickHouseDataValidationError(
            "ClickHouse resource profile did not return each required setting exactly once: "
            f"expected_count={len(expected)}, observed_count={len(rows)}, "
            f"distinct_count={len(by_name)}"
        )
    return by_name


def _legacy_settings_by_name(
    rows: tuple[_ClickHouseSettingPayload, ...],
) -> dict[str, _ClickHouseSettingPayload]:
    expected = (
        {setting.value for setting in ClickHouseResourceSetting}
        | {setting.value for setting in ClickHouseOverflowSetting}
        | {
            "allow_experimental_projection_optimization",
            "cancel_http_readonly_queries_on_client_close",
            "force_optimize_projection",
            "readonly",
            "send_progress_in_http_headers",
        }
    )
    by_name = {row.name: row for row in rows}
    if len(rows) != len(expected) or set(by_name) != expected:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy resource profile did not return each required setting exactly "
            f"once: expected_count={len(expected)}, observed_count={len(rows)}, "
            f"distinct_count={len(by_name)}"
        )
    return by_name


def _setting_is_locked(row: _ClickHouseSettingPayload) -> bool:
    if row.readonly not in (0, 1):
        raise ClickHouseDataValidationError(
            f"ClickHouse setting writability must be encoded as zero or one: setting={row.name!r}"
        )
    return row.readonly == 1


def _resource_constraints(
    settings_by_name: dict[str, _ClickHouseSettingPayload],
) -> tuple[ClickHouseResourceConstraint, ...]:
    constraints: list[ClickHouseResourceConstraint] = []
    for setting in ClickHouseResourceSetting:
        row = settings_by_name[setting.value]
        constraints.append(
            ClickHouseResourceConstraint(
                setting=setting,
                value=_parse_nonnegative_decimal(row.value, f"{setting.value} value"),
                minimum=(
                    None
                    if row.min is None
                    else _parse_nonnegative_decimal(row.min, f"{setting.value} minimum")
                ),
                maximum=(
                    None
                    if row.max is None
                    else _parse_nonnegative_decimal(row.max, f"{setting.value} maximum")
                ),
                changeable_in_readonly=not _setting_is_locked(row),
            )
        )
    return tuple(constraints)


def _required_setting_maximum(
    row: _ClickHouseSettingPayload,
    setting: ClickHouseResourceSetting,
) -> Decimal:
    if row.max is None:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires a declared resource ceiling: "
            f"setting={setting.value!r}"
        )
    maximum = _parse_nonnegative_decimal(row.max, f"{setting.value} maximum")
    if maximum <= 0:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires a positive resource ceiling: "
            f"setting={setting.value!r}"
        )
    return maximum


def _legacy_locked_overflow_modes(
    settings_by_name: dict[str, _ClickHouseSettingPayload],
) -> tuple[ClickHouseLockedOverflowMode, ...]:
    modes: list[ClickHouseLockedOverflowMode] = []
    for setting in ClickHouseOverflowSetting:
        row = settings_by_name[setting.value]
        value = _validated_profile_text(row.value, setting.value)
        locked = _setting_is_locked(row)
        if value != "throw" or not locked:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse legacy source profile requires a locked throw overflow mode: "
                f"setting={setting.value!r}, observed={value!r}, "
                f"locked={locked}"
            )
        modes.append(ClickHouseLockedOverflowMode(setting=setting, value=value))
    return tuple(modes)


def _require_clickhouse_profile(
    profile: ClickHouseServerProfile,
    settings: ClickHouseConnectionSettings,
) -> None:
    if profile.provenance != ClickHouseModernProfileProvenance(
        runtime_profile=ClickHouseRuntimeProfile.LTS,
        response_protocol=ClickHouseHttpResponseProtocol.MODERN_EXCEPTION_FRAME,
        timezone_strategy=ClickHouseTimezoneStrategy.SESSION_SETTING,
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse modern profile has inconsistent runtime provenance"
        )
    if profile.readonly != 1:
        raise UnsupportedClickHouseProfileError(
            f"ClickHouse source profile requires readonly=1: observed={profile.readonly}"
        )
    _require_clickhouse_profile_baseline(profile, settings)


def _require_clickhouse_profile_baseline(
    profile: ClickHouseServerProfile,
    settings: ClickHouseConnectionSettings,
) -> None:
    if type(profile.server_version_number) is not int or profile.server_version_number < 1:
        raise ClickHouseDataValidationError(
            "ClickHouse source profile requires a positive VERSION_INTEGER catalog value"
        )
    if profile.current_user != settings.user or profile.current_database != settings.database:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse HTTP session identity does not match its declared connection: "
            f"declared_user={settings.user!r}, observed_user={profile.current_user!r}, "
            f"declared_database={settings.database!r}, "
            f"observed_database={profile.current_database!r}"
        )
    if profile.session_timezone != "UTC":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse profile requires an effective UTC session timezone: "
            f"observed={profile.session_timezone!r}"
        )
    if not profile.readonly_locked:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires the readonly setting to be locked"
        )
    for name, value in (
        ("max_memory_usage", profile.max_memory_usage),
        ("max_threads", profile.max_threads),
        ("max_result_rows", profile.max_result_rows),
        ("max_result_bytes", profile.max_result_bytes),
    ):
        if value < 1:
            raise UnsupportedClickHouseProfileError(
                f"ClickHouse source profile requires a positive {name}: observed={value}"
            )
    if profile.max_execution_time_seconds <= 0:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires a positive max_execution_time: "
            f"observed={profile.max_execution_time_seconds}"
        )
    if not 0 < profile.effective_max_execution_time_seconds <= profile.max_execution_time_seconds:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires a positive effective max_execution_time "
            "within its declared ceiling: "
            f"effective={profile.effective_max_execution_time_seconds}, "
            f"ceiling={profile.max_execution_time_seconds}"
        )
    if profile.result_overflow_mode != "throw":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires result_overflow_mode='throw': "
            f"observed={profile.result_overflow_mode!r}"
        )
    if not profile.result_overflow_mode_locked:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires result_overflow_mode to be locked"
        )
    mirrored_values = {
        ClickHouseResourceSetting.MAX_MEMORY_USAGE: Decimal(profile.max_memory_usage),
        ClickHouseResourceSetting.MAX_THREADS: Decimal(profile.max_threads),
        ClickHouseResourceSetting.MAX_EXECUTION_TIME: (
            profile.effective_max_execution_time_seconds
        ),
        ClickHouseResourceSetting.MAX_RESULT_ROWS: Decimal(profile.max_result_rows),
        ClickHouseResourceSetting.MAX_RESULT_BYTES: Decimal(profile.max_result_bytes),
    }
    constraints_by_setting = {
        constraint.setting: constraint for constraint in profile.resource_constraints
    }
    if set(constraints_by_setting) != set(ClickHouseResourceSetting):
        raise ClickHouseDataValidationError(
            "ClickHouse source profile requires each resource constraint exactly once"
        )
    for setting, constraint in constraints_by_setting.items():
        minimum_is_valid = constraint.minimum is None or (
            0 <= constraint.minimum <= constraint.value
        )
        maximum_is_valid = constraint.maximum is not None and (
            constraint.value <= constraint.maximum
        )
        effective_ceiling_exists = not constraint.changeable_in_readonly or maximum_is_valid
        if constraint.value <= 0 or not minimum_is_valid or not effective_ceiling_exists:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse source resource constraint is unsafe: "
                f"setting={setting.value!r}, requires_positive_bounded_value=True"
            )
    for setting, expected_value in mirrored_values.items():
        if constraints_by_setting[setting].value != expected_value:
            raise ClickHouseDataValidationError(
                "ClickHouse source profile value differs from its resource constraint: "
                f"setting={setting.value!r}"
            )
    execution_constraint = constraints_by_setting[ClickHouseResourceSetting.MAX_EXECUTION_TIME]
    if execution_constraint.maximum != profile.max_execution_time_seconds:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source max_execution_time ceiling does not match its declared "
            "constraint maximum"
        )
    for setting in (
        ClickHouseResourceSetting.MAX_EXECUTION_TIME,
        ClickHouseResourceSetting.MAX_RESULT_ROWS,
        ClickHouseResourceSetting.MAX_RESULT_BYTES,
        ClickHouseResourceSetting.MAX_ROWS_TO_GROUP_BY,
    ):
        if not constraints_by_setting[setting].changeable_in_readonly:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse source setting must permit the adapter's bounded downward override: "
                f"setting={setting.value!r}"
            )


def _require_legacy_clickhouse_profile(
    profile: ClickHouseServerProfile,
    settings: ClickHouseConnectionSettings,
) -> None:
    provenance = profile.provenance
    if type(provenance) is not ClickHouseLegacyProfileProvenance:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy profile has inconsistent runtime provenance"
        )
    if (
        provenance.runtime_profile is not ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE
        or provenance.response_protocol is not ClickHouseHttpResponseProtocol.LEGACY_CLEAN_EOF
        or provenance.timezone_strategy is not ClickHouseTimezoneStrategy.SERVER_UTC_CONFIGURATION
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse legacy profile has inconsistent protocol or timezone provenance"
        )
    if profile.readonly != 2:
        raise UnsupportedClickHouseProfileError(
            f"ClickHouse legacy source profile requires readonly=2: observed={profile.readonly}"
        )
    if profile.server_timezone != "UTC" or profile.session_timezone != "UTC":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy source profile requires UTC server configuration: "
            f"server_timezone={profile.server_timezone!r}, "
            f"effective_timezone={profile.session_timezone!r}"
        )
    if (
        provenance.cancel_http_readonly_queries_on_client_close != 1
        or not provenance.cancel_http_readonly_queries_on_client_close_locked
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy source profile requires locked "
            "cancel_http_readonly_queries_on_client_close=1"
        )
    if (
        provenance.send_progress_in_http_headers != 0
        or not provenance.send_progress_in_http_headers_locked
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy source profile requires locked send_progress_in_http_headers=0"
        )
    if (
        provenance.allow_experimental_projection_optimization != 0
        or not provenance.allow_experimental_projection_optimization_locked
        or provenance.force_optimize_projection != 0
        or not provenance.force_optimize_projection_locked
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy source profile requires locked projection selection guards: "
            "allow_experimental_projection_optimization=0, force_optimize_projection=0"
        )
    expected_overflow_modes = tuple(
        ClickHouseLockedOverflowMode(setting=setting, value="throw")
        for setting in ClickHouseOverflowSetting
    )
    if provenance.locked_overflow_modes != expected_overflow_modes:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy profile has inconsistent locked overflow-mode provenance"
        )
    _require_clickhouse_profile_baseline(profile, settings)
    for constraint in profile.resource_constraints:
        if constraint.changeable_in_readonly and (
            constraint.minimum is None
            or constraint.minimum < 1
            or constraint.minimum > constraint.value
        ):
            raise UnsupportedClickHouseProfileError(
                "ClickHouse legacy source resource constraint must prevent zero from disabling "
                f"the guard: setting={constraint.setting.value!r}, "
                f"minimum={(None if constraint.minimum is None else str(constraint.minimum))!r}"
            )


def clickhouse_resource_setting_ceiling(
    profile: ClickHouseServerProfile,
    setting: ClickHouseResourceSetting,
    operation: str,
) -> int:
    constraint = _resource_constraint_for_setting(profile, setting)
    _validated_profile_text(operation, "resource operation")
    ceiling = constraint.maximum if constraint.changeable_in_readonly else constraint.value
    if ceiling is None or ceiling < 1 or ceiling != ceiling.to_integral_value():
        raise UnsupportedClickHouseProfileError(
            "ClickHouse resource setting lacks a positive integer ceiling: "
            f"operation={operation!r}, setting={setting.value!r}, "
            f"observed_ceiling={(None if ceiling is None else str(ceiling))!r}"
        )
    return int(ceiling)


def require_clickhouse_resource_setting_value(
    profile: ClickHouseServerProfile,
    setting: ClickHouseResourceSetting,
    requested_value: int,
    operation: str,
) -> None:
    if type(requested_value) is not int or requested_value < 1:
        raise ClickHouseDataValidationError(
            "ClickHouse query resource setting must be a positive integer: "
            f"operation={operation!r}, setting={setting.value!r}, "
            f"requested={requested_value!r}"
        )
    _validated_profile_text(operation, "resource operation")
    constraint = _resource_constraint_for_setting(profile, setting)
    requested = Decimal(requested_value)
    if constraint.changeable_in_readonly:
        accepted = (
            (constraint.minimum is None or constraint.minimum <= requested)
            and constraint.maximum is not None
            and requested <= constraint.maximum
        )
    else:
        accepted = requested == constraint.value
    if not accepted:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse query resource setting is outside the observed accepted range: "
            f"operation={operation!r}, setting={setting.value!r}, "
            f"requested={requested_value}, current={str(constraint.value)!r}, "
            f"minimum={(None if constraint.minimum is None else str(constraint.minimum))!r}, "
            f"maximum={(None if constraint.maximum is None else str(constraint.maximum))!r}, "
            f"changeable_in_readonly={constraint.changeable_in_readonly}"
        )


def _resource_constraint_for_setting(
    profile: ClickHouseServerProfile,
    setting: ClickHouseResourceSetting,
) -> ClickHouseResourceConstraint:
    if type(profile) is not ClickHouseServerProfile:
        raise TypeError("ClickHouse resource profile must be ClickHouseServerProfile")
    if not isinstance(cast(object, setting), ClickHouseResourceSetting):
        raise TypeError("ClickHouse resource setting must be ClickHouseResourceSetting")
    matching = tuple(
        constraint for constraint in profile.resource_constraints if constraint.setting is setting
    )
    if len(matching) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse resource profile does not contain the requested setting exactly once: "
            f"setting={setting.value!r}, observed={len(matching)}"
        )
    return matching[0]


def _interface(security: ClickHouseTransportSecurity) -> str:
    if security is ClickHouseTransportSecurity.TLS_VERIFY:
        return "https"
    return "http"


def _validated_driver_version(value: str) -> str:
    return _validated_profile_text(value, "driver version")


def _validated_profile_text(value: str, label: str) -> str:
    validate_clickhouse_text_scalar(value, f"ClickHouse {label}")
    if len(value.encode("utf-8")) > 512:
        raise ClickHouseDataValidationError(f"ClickHouse {label} exceeds 512 UTF-8 bytes")
    return value


def _parse_nonnegative_integer(value: str, label: str) -> int:
    parsed = _parse_integer(value, label)
    if parsed < 0:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be non-negative")
    return parsed


def _parse_binary_integer(value: str, label: str) -> int:
    parsed = _parse_nonnegative_integer(value, label)
    if parsed not in (0, 1):
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be encoded as zero or one: observed={parsed}"
        )
    return parsed


def _parse_positive_integer(value: str, label: str) -> int:
    parsed = _parse_integer(value, label)
    if parsed < 1:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be positive")
    return parsed


def _parse_integer(value: str, label: str) -> int:
    if _INTEGER_TEXT.fullmatch(value) is None:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be a canonical decimal integer"
        )
    return int(value)


def _parse_nonnegative_decimal(value: str, label: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be an exact decimal"
        ) from None
    if not parsed.is_finite() or parsed < 0:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be a finite non-negative decimal"
        )
    return parsed


def _validate_nonnegative_source_full_scans(full_scans: int) -> None:
    if type(full_scans) is not int or full_scans < 0:
        raise ValueError("ClickHouse source full-scan reservation must be a non-negative integer")


def _validate_nonnegative_source_result_bytes(result_bytes: int) -> None:
    if type(result_bytes) is not int or result_bytes < 0:
        raise ValueError("ClickHouse observed result bytes must be a non-negative integer")


def _preserve_source_accounting_failure(
    primary_error: BaseException,
    accounting_error: _ClickHouseSourceAccountingFailure | None,
) -> None:
    if accounting_error is None:
        return
    primary_error.add_note(
        "ClickHouse source-result accounting also failed: "
        f"accounting_error_type={type(accounting_error).__name__!r}"
    )


def _clickhouse_result_record_bytes(
    payload: bytes,
    result_format: str,
) -> tuple[int, ...]:
    if type(payload) is not bytes:
        raise TypeError("ClickHouse accounted response payload must be bytes")
    if result_format == "JSONEachRow":
        return tuple(len(line) for line in payload.splitlines())
    if result_format == "TabSeparatedRaw":
        return tuple(
            sum(len(field) for field in line.split(b"\t")) for line in payload.splitlines()
        )
    raise ClickHouseSourceAccountingError(
        "ClickHouse budgeted response uses an unsupported accounting format: "
        f"result_format={result_format!r}"
    )


def quote_clickhouse_identifier(identifier: str) -> str:
    validate_clickhouse_identifier(identifier, "ClickHouse SQL identifier")
    escaped = identifier.replace("\\", "\\\\").replace('"', '""')
    return '"' + escaped + '"'


def validate_clickhouse_identifier(identifier: str, label: str) -> None:
    validate_clickhouse_text_scalar(identifier, label)
    if len(identifier.encode("utf-8")) > 512:
        raise ValueError(f"{label} exceeds 512 UTF-8 bytes")


def validate_clickhouse_text_scalar(value: str, label: str) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be non-empty text")
    if "\x00" in value:
        raise ValueError(f"{label} must not contain U+0000")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(
            f"{label} must contain valid Unicode scalar values: "
            f"start={error.start}, end={error.end}"
        ) from None
