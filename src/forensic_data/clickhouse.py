import logging
import math
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation, localcontext
from enum import StrEnum
from io import IOBase
from uuid import UUID, uuid4

import clickhouse_connect
from clickhouse_connect.driver.client import Client
from clickhouse_connect.driver.exceptions import Error, OperationalError
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from urllib3 import PoolManager
from urllib3.exceptions import HTTPError

LOGGER = logging.getLogger(__name__)
_LOCAL_FIXTURE_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_INTEGER_TEXT = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)\Z")
_DECIMAL_TYPE = re.compile(r"Decimal\(([1-9][0-9]*),\s*(0|[1-9][0-9]*)\)\Z")
_DATETIME64_TYPE = re.compile(r"DateTime64\((0|[1-9][0-9]*)(?:,\s*'([^']+)')?\)\Z")
_MAX_PROFILE_RESPONSE_BYTES = 8_192
_MAX_SETTINGS_RESPONSE_BYTES = 8_192
_MAX_CATALOG_RESPONSE_BYTES = 8_192
_MAX_TIMEZONE_RESPONSE_BYTES = 1_024

type ClickHouseParameter = str | int


class ClickHouseTransportError(RuntimeError):
    """Base error for the ClickHouse HTTP boundary."""


class ClickHouseConnectionError(ClickHouseTransportError):
    """Opening or profiling a ClickHouse connection failed."""


class ClickHouseQueryError(ClickHouseTransportError):
    """A ClickHouse query failed and its dedicated transport was retired."""

    def __init__(
        self,
        query_id: UUID,
        operation: str,
        error_code: int | None,
        error_name: str | None,
        cause_type: str,
    ) -> None:
        self.query_id = query_id
        self.operation = operation
        self.error_code = error_code
        self.error_name = error_name
        self.cause_type = cause_type
        super().__init__(
            "ClickHouse query failed: "
            f"query_id={query_id}, operation={operation!r}, error_code={error_code!r}, "
            f"error_name={error_name!r}, cause_type={cause_type!r}"
        )


class ClickHouseDataValidationError(ClickHouseTransportError):
    """ClickHouse returned data outside the typed transport contract."""


class ClickHouseResultLimitError(ClickHouseTransportError):
    """A ClickHouse result exceeded its explicit response bound."""


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
    CLOSED = "closed"


class ClickHouseResourceSetting(StrEnum):
    MAX_MEMORY_USAGE = "max_memory_usage"
    MAX_THREADS = "max_threads"
    MAX_EXECUTION_TIME = "max_execution_time"
    MAX_RESULT_ROWS = "max_result_rows"
    MAX_RESULT_BYTES = "max_result_bytes"


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

    @field_validator("host", "database", "user", "application_name")
    @classmethod
    def validate_nonempty_text(cls, value: str) -> str:
        _validate_text_scalar(value, "ClickHouse connection text")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: SecretStr) -> SecretStr:
        password = value.get_secret_value()
        _validate_text_scalar(password, "ClickHouse password")
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
            _validate_text_scalar(self.ca_cert, "ClickHouse CA certificate path")
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
class ClickHouseRawResult:
    query_id: UUID
    payload: bytes


@dataclass(frozen=True, slots=True)
class ClickHouseResourceConstraint:
    setting: ClickHouseResourceSetting
    value: Decimal
    minimum: Decimal | None
    maximum: Decimal | None
    changeable_in_readonly: bool


@dataclass(frozen=True, slots=True)
class ClickHouseServerProfile:
    driver_name: str
    driver_version: str
    server_version: str
    build_id: str
    server_timezone: str
    session_timezone: str
    current_user: str
    current_database: str
    readonly: int
    max_memory_usage: int
    max_threads: int
    max_execution_time_seconds: Decimal
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
        _validate_identifier(self.order_column, "ClickHouse order column")
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
    build_id: str
    server_timezone: str
    session_timezone: str
    current_user: str
    current_database: str
    readonly: str
    max_memory_usage: str
    max_threads: str
    max_execution_time: str
    max_result_rows: str
    max_result_bytes: str
    result_overflow_mode: str


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


class ClickHouseTransport:
    """Dedicated single-owner ClickHouse HTTP transport."""

    def __init__(self, client: Client, pool_manager: PoolManager) -> None:
        self._client = client
        self._pool_manager = pool_manager
        self._state = ClickHouseTransportState.ACTIVE

    @property
    def state(self) -> ClickHouseTransportState:
        return self._state

    @property
    def closed(self) -> bool:
        return self._state is not ClickHouseTransportState.ACTIVE

    def execute_raw(
        self,
        query: str,
        parameters: dict[str, ClickHouseParameter],
        settings: dict[str, ClickHouseParameter],
        result_format: str,
        max_response_bytes: int,
        operation: str,
    ) -> ClickHouseRawResult:
        self._require_active(operation)
        _validate_text_scalar(query, "ClickHouse query")
        _validate_text_scalar(result_format, "ClickHouse result format")
        _validate_text_scalar(operation, "ClickHouse operation")
        if type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        if "query_id" in settings or "wait_end_of_query" in settings:
            raise ValueError(
                "ClickHouse query settings must not override transport-owned query metadata"
            )
        query_id = uuid4()
        source: IOBase | None = None
        try:
            raw_source = self._client.raw_stream(  # pyright: ignore[reportUnknownMemberType]
                query=query,
                parameters=parameters,
                settings={
                    **settings,
                    "query_id": str(query_id),
                    "wait_end_of_query": 1,
                },
                fmt=result_format,
                use_database=True,
                external_data=None,
                transport_settings=None,
            )
            if not isinstance(raw_source, IOBase):
                raise ClickHouseDataValidationError(
                    "ClickHouse synchronous raw stream returned an unsupported source type"
                )
            source = raw_source
            payload = _read_bounded_response(
                source=source,
                max_response_bytes=max_response_bytes,
                query_id=query_id,
                operation=operation,
            )
        except ClickHouseTransportError:
            self._retire(ClickHouseTransportState.LOST)
            raise
        except Error as error:
            self._retire(ClickHouseTransportState.LOST)
            raise ClickHouseQueryError(
                query_id=query_id,
                operation=operation,
                error_code=error.code,
                error_name=error.name,
                cause_type=type(error).__name__,
            ) from None
        except (HTTPError, OSError) as error:
            self._retire(ClickHouseTransportState.LOST)
            raise ClickHouseQueryError(
                query_id=query_id,
                operation=operation,
                error_code=None,
                error_name=None,
                cause_type=type(error).__name__,
            ) from None
        finally:
            if source is not None:
                source.close()
        return ClickHouseRawResult(query_id=query_id, payload=payload)

    def close(self) -> None:
        if self._state is ClickHouseTransportState.CLOSED:
            return
        self._client.close()
        self._pool_manager.clear()
        self._state = ClickHouseTransportState.CLOSED

    def _retire(self, state: ClickHouseTransportState) -> None:
        self._client.close()
        self._pool_manager.clear()
        self._state = state

    def _require_active(self, operation: str) -> None:
        if self._state is not ClickHouseTransportState.ACTIVE:
            raise ClickHouseTransportClosedError(
                "ClickHouse transport is not active: "
                f"operation={operation!r}, state={self._state.value!r}"
            )


def _read_bounded_response(
    source: IOBase,
    max_response_bytes: int,
    query_id: UUID,
    operation: str,
) -> bytes:
    payload = source.read(max_response_bytes + 1)
    if type(payload) is not bytes:
        raise ClickHouseDataValidationError(
            "ClickHouse synchronous raw stream returned a non-bytes payload: "
            f"query_id={query_id}, operation={operation!r}"
        )
    if len(payload) > max_response_bytes:
        raise ClickHouseResultLimitError(
            "ClickHouse response exceeded its explicit byte bound before full buffering: "
            f"query_id={query_id}, operation={operation!r}, "
            f"max_response_bytes={max_response_bytes}, observed_bytes_at_least={len(payload)}"
        )
    return payload


def open_clickhouse_transport(
    settings: ClickHouseConnectionSettings,
    retry_policy: ClickHouseRetryPolicy,
) -> ClickHouseTransport:
    last_error: OperationalError | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        pool_manager = _new_pool_manager(settings)
        try:
            client = clickhouse_connect.get_client(  # pyright: ignore[reportUnknownMemberType]
                host=settings.host,
                username=settings.user,
                password=settings.password.get_secret_value(),
                database=settings.database,
                interface=_interface(settings.transport_security),
                port=settings.port,
                secure=_secure(settings.transport_security),
                settings={"session_timezone": "UTC"},
                compress=False,
                query_limit=0,
                query_retries=0,
                connect_timeout=settings.connect_timeout_seconds,
                send_receive_timeout=settings.send_receive_timeout_seconds,
                client_name=settings.application_name,
                verify=True,
                ca_cert=settings.ca_cert,
                pool_mgr=pool_manager,
                tz_source="server",
                tz_mode="schema",
                show_clickhouse_errors=False,
                autogenerate_session_id=False,
                autogenerate_query_id=False,
                form_encode_query_params=True,
                native_codec="python",
            )
            return ClickHouseTransport(client=client, pool_manager=pool_manager)
        except OperationalError as error:
            pool_manager.clear()
            last_error = error
            LOGGER.warning(
                "ClickHouse connection attempt failed",
                extra={
                    "operation": "connect_clickhouse",
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "database": settings.database,
                    "user": settings.user,
                    "transport_security": settings.transport_security.value,
                    "error_code": error.code,
                    "error_name": error.name,
                },
            )
            if attempt < retry_policy.max_attempts:
                time.sleep(retry_policy.delay_seconds)
        except Error as error:
            pool_manager.clear()
            raise ClickHouseConnectionError(
                _connection_error_message(settings, attempt, error)
            ) from None
    if last_error is None:
        raise AssertionError("ClickHouse connection loop ended without an attempt")
    raise ClickHouseConnectionError(
        _connection_error_message(settings, retry_policy.max_attempts, last_error)
    ) from None


def inspect_clickhouse_server_profile(
    transport: ClickHouseTransport,
    settings: ClickHouseConnectionSettings,
) -> ClickHouseServerProfile:
    result = transport.execute_raw(
        query=(
            "SELECT version() AS server_version, buildId() AS build_id, "
            "serverTimezone() AS server_timezone, timezone() AS session_timezone, "
            "currentUser() AS current_user, "
            "currentDatabase() AS current_database, "
            "toString(getSetting('readonly')) AS readonly, "
            "toString(getSetting('max_memory_usage')) AS max_memory_usage, "
            "toString(getSetting('max_threads')) AS max_threads, "
            "toString(getSetting('max_execution_time')) AS max_execution_time, "
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
            "'max_result_rows', 'max_result_bytes', 'result_overflow_mode') "
            "ORDER BY name"
        ),
        parameters={},
        settings={"session_timezone": "UTC"},
        result_format="JSONEachRow",
        max_response_bytes=_MAX_SETTINGS_RESPONSE_BYTES,
        operation="inspect_resource_constraints",
    )
    setting_rows = _json_rows(
        setting_result.payload,
        _ClickHouseSettingPayload,
        "resource constraints",
    )
    settings_by_name = _settings_by_name(setting_rows)
    profile = ClickHouseServerProfile(
        driver_name="clickhouse-connect",
        driver_version=_validated_driver_version(clickhouse_connect.__version__),
        server_version=_validated_profile_text(payload.server_version, "server version"),
        build_id=_validated_profile_text(payload.build_id, "build ID"),
        server_timezone=_validated_profile_text(payload.server_timezone, "server timezone"),
        session_timezone=_validated_profile_text(payload.session_timezone, "session timezone"),
        current_user=_validated_profile_text(payload.current_user, "current user"),
        current_database=_validated_profile_text(payload.current_database, "current database"),
        readonly=_parse_nonnegative_integer(payload.readonly, "readonly"),
        max_memory_usage=_parse_nonnegative_integer(payload.max_memory_usage, "max_memory_usage"),
        max_threads=_parse_nonnegative_integer(payload.max_threads, "max_threads"),
        max_execution_time_seconds=_parse_nonnegative_decimal(
            payload.max_execution_time, "max_execution_time"
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
        _validate_identifier(identifier, label)
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
    rows = _json_rows(result.payload, _ClickHouseColumnPayload, "fidelity relation catalog")
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
    decimal_type = _parse_decimal_type(by_name[decimal_column])
    datetime_type = _inspect_datetime64_type(transport, by_name[datetime_column])
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
    decimal_reinterpret = _decimal_reinterpret_function(request.relation.decimal_type.precision)
    database = _quote_identifier(request.relation.database)
    table = _quote_identifier(request.relation.table)
    order_column = _quote_identifier(request.order_column)
    decimal_column = _quote_identifier(request.relation.decimal_column)
    datetime_column = _quote_identifier(request.relation.datetime_column)
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


def _parse_decimal_type(type_name: str) -> ClickHouseDecimalType:
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


def _inspect_datetime64_type(
    transport: ClickHouseTransport,
    type_name: str,
) -> ClickHouseDateTime64Type:
    precision, declared_timezone = _parse_datetime64_declaration(type_name)
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


def _parse_datetime64_declaration(type_name: str) -> tuple[int, str | None]:
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
        _validate_text_scalar(timezone, "ClickHouse DateTime64 timezone")
    return precision, timezone


def _decimal_reinterpret_function(precision: int) -> str:
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
    rows = _json_rows(payload, model_type, label)
    if len(rows) != 1:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must return exactly one row: actual={len(rows)}"
        )
    return rows[0]


def _json_rows[Payload: BaseModel](
    payload: bytes,
    model_type: type[Payload],
    label: str,
) -> tuple[Payload, ...]:
    lines = payload.splitlines()
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


def _require_clickhouse_profile(
    profile: ClickHouseServerProfile,
    settings: ClickHouseConnectionSettings,
) -> None:
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
    if profile.readonly != 1:
        raise UnsupportedClickHouseProfileError(
            f"ClickHouse source profile requires readonly=1: observed={profile.readonly}"
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
    if profile.result_overflow_mode != "throw":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires result_overflow_mode='throw': "
            f"observed={profile.result_overflow_mode!r}"
        )
    if not profile.result_overflow_mode_locked:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse source profile requires result_overflow_mode to be locked"
        )
    expected_values = {
        ClickHouseResourceSetting.MAX_MEMORY_USAGE: Decimal(profile.max_memory_usage),
        ClickHouseResourceSetting.MAX_THREADS: Decimal(profile.max_threads),
        ClickHouseResourceSetting.MAX_EXECUTION_TIME: profile.max_execution_time_seconds,
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
    for setting, expected_value in expected_values.items():
        constraint = constraints_by_setting[setting]
        minimum_is_valid = constraint.minimum is None or (
            0 <= constraint.minimum <= constraint.value
        )
        maximum_is_valid = constraint.maximum is not None and (
            constraint.value <= constraint.maximum
        )
        effective_ceiling_exists = not constraint.changeable_in_readonly or maximum_is_valid
        if (
            constraint.value != expected_value
            or constraint.value <= 0
            or not minimum_is_valid
            or not effective_ceiling_exists
        ):
            raise UnsupportedClickHouseProfileError(
                "ClickHouse source resource constraint is unsafe: "
                f"setting={setting.value!r}, requires_positive_bounded_value=True"
            )
    for setting in (
        ClickHouseResourceSetting.MAX_EXECUTION_TIME,
        ClickHouseResourceSetting.MAX_RESULT_ROWS,
        ClickHouseResourceSetting.MAX_RESULT_BYTES,
    ):
        if not constraints_by_setting[setting].changeable_in_readonly:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse source setting must permit the adapter's bounded downward override: "
                f"setting={setting.value!r}"
            )


def _interface(security: ClickHouseTransportSecurity) -> str:
    if security is ClickHouseTransportSecurity.TLS_VERIFY:
        return "https"
    return "http"


def _new_pool_manager(settings: ClickHouseConnectionSettings) -> PoolManager:
    if settings.ca_cert is not None:
        return PoolManager(
            num_pools=1,
            maxsize=1,
            block=True,
            cert_reqs="CERT_REQUIRED",
            ca_certs=settings.ca_cert,
        )
    return PoolManager(
        num_pools=1,
        maxsize=1,
        block=True,
        cert_reqs="CERT_REQUIRED",
    )


def _secure(security: ClickHouseTransportSecurity) -> bool:
    return security is ClickHouseTransportSecurity.TLS_VERIFY


def _connection_error_message(
    settings: ClickHouseConnectionSettings,
    attempts: int,
    error: Error,
) -> str:
    return (
        "ClickHouse connection failed: "
        f"host={settings.host!r}, port={settings.port}, database={settings.database!r}, "
        f"user={settings.user!r}, transport_security={settings.transport_security.value!r}, "
        f"attempts={attempts}, error_code={error.code!r}, error_name={error.name!r}, "
        f"cause_type={type(error).__name__!r}"
    )


def _validated_driver_version(value: str) -> str:
    return _validated_profile_text(value, "driver version")


def _validated_profile_text(value: str, label: str) -> str:
    _validate_text_scalar(value, f"ClickHouse {label}")
    if len(value.encode("utf-8")) > 512:
        raise ClickHouseDataValidationError(f"ClickHouse {label} exceeds 512 UTF-8 bytes")
    return value


def _parse_nonnegative_integer(value: str, label: str) -> int:
    parsed = _parse_integer(value, label)
    if parsed < 0:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be non-negative")
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


def _quote_identifier(identifier: str) -> str:
    _validate_identifier(identifier, "ClickHouse SQL identifier")
    escaped = identifier.replace("\\", "\\\\").replace('"', '""')
    return '"' + escaped + '"'


def _validate_identifier(identifier: str, label: str) -> None:
    _validate_text_scalar(identifier, label)
    if len(identifier.encode("utf-8")) > 512:
        raise ValueError(f"{label} exceeds 512 UTF-8 bytes")


def _validate_text_scalar(value: str, label: str) -> None:
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
