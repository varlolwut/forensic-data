import logging
import math
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from threading import Lock
from typing import cast
from uuid import UUID, uuid4

import psycopg
from psycopg import Column, ServerCursor, sql
from psycopg.rows import tuple_row
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from forensic_data.canonical import (
    CanonicalizationError,
    CanonicalSchema,
    Fingerprint,
    FingerprintOverflowError,
    decode_row_with_context,
    envelope_sha256,
)
from forensic_data.postgres_sql import (
    PostgresFieldBinding,
    PostgresInspectedRelation,
    PostgresParameter,
    PostgresPhysicalField,
    PostgresQuery,
    PostgresRelation,
    PostgresTypeIdentity,
    validate_postgres_inspection,
)

LOGGER = logging.getLogger(__name__)
INT64_MAX = (1 << 63) - 1
UINT32_MAX = (1 << 32) - 1
SHA256_BYTES = 32
_CANONICAL_STATUS_BYTES = 2
_CURSOR_FETCH_RECORDS = 64
_METADATA_ROW_COLUMNS = 15


class PostgresConnectorError(RuntimeError):
    """Base error for the PostgreSQL connector boundary."""


class PostgresConnectionError(PostgresConnectorError):
    """A PostgreSQL connection or read-context setup failed."""


class UnsupportedPostgresProfileError(PostgresConnectorError):
    """The connected server cannot provide the PostgreSQL 17 profile."""


class PostgresMetadataError(PostgresConnectorError):
    """Required PostgreSQL relation or column provenance is unavailable."""


class PostgresContextClosedError(PostgresConnectorError):
    """A query was attempted after the read context was closed."""


class PostgresContextLostError(PostgresConnectorError):
    """A query was attempted after the transaction read context was lost."""


class PostgresQueryError(PostgresConnectorError):
    """A query failed and invalidated its transaction read context."""


class PostgresQueryContextError(PostgresConnectorError):
    """A compiled query was used outside its originating transaction context."""


class PostgresCloseError(PostgresConnectorError):
    """Closing a PostgreSQL read context failed."""


class PostgresDataValidationError(PostgresConnectorError):
    """PostgreSQL returned a value outside the typed adapter contract."""


class PostgresResultLimitError(PostgresConnectorError):
    """A PostgreSQL result exceeded an explicitly reserved byte or record budget."""


class PostgresSslMode(StrEnum):
    DISABLE = "disable"
    REQUIRE = "require"
    VERIFY_CA = "verify-ca"
    VERIFY_FULL = "verify-full"


class PostgresConnectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: str
    port: int = Field(ge=1, le=65535)
    dbname: str
    user: str
    password: SecretStr
    sslmode: PostgresSslMode
    connect_timeout_seconds: int = Field(ge=1)
    statement_timeout_milliseconds: int = Field(ge=1)
    application_name: str

    @field_validator("host", "dbname", "user", "application_name")
    @classmethod
    def validate_nonempty_text(cls, value: str) -> str:
        if not value:
            raise ValueError("connection text fields must not be empty")
        if "\x00" in value:
            raise ValueError("connection text fields must not contain U+0000")
        return value


@dataclass(frozen=True, slots=True)
class PostgresRetryPolicy:
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
class PostgresServerProfile:
    driver_version: str
    server_version: str
    server_version_number: int
    server_encoding: str
    client_encoding: str
    integer_datetimes: bool
    timezone: str
    max_identifier_utf8_bytes: int


@dataclass(frozen=True, slots=True)
class PostgresReadContextEvidence:
    context_id: UUID
    engine: str
    server_version: str
    strategy: str
    snapshot_locator: str
    started_at: datetime
    backend_process_id: int
    allowed_concurrency: int
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PostgresCanonicalRow:
    envelope: bytes
    sha256: bytes


class ReadContextState(StrEnum):
    ACTIVE = "active"
    LOST = "lost"
    CLOSED = "closed"


type DatabaseRow = tuple[object, ...]
type ExecutableSql = sql.SQL | sql.Composed


class PostgresReadContext:
    """One sequential PostgreSQL read-only Repeatable Read transaction."""

    def __init__(
        self,
        connection: psycopg.Connection[DatabaseRow],
        profile: PostgresServerProfile,
        evidence: PostgresReadContextEvidence,
        statement_timeout_milliseconds: int,
    ) -> None:
        self._connection = connection
        self._profile = profile
        self._evidence = evidence
        self._statement_timeout_milliseconds = statement_timeout_milliseconds
        self._state = ReadContextState.ACTIVE
        self._query_lock = Lock()

    @property
    def profile(self) -> PostgresServerProfile:
        return self._profile

    @property
    def evidence(self) -> PostgresReadContextEvidence:
        return self._evidence

    @property
    def state(self) -> ReadContextState:
        return self._state

    def read_scalar_integer(
        self,
        statement: ExecutableSql,
        parameters: tuple[PostgresParameter, ...],
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> int:
        rows = self._execute_bounded(
            statement,
            parameters,
            1,
            max_record_bytes,
            max_total_bytes,
        )
        if len(rows) != 1 or len(rows[0]) != 1:
            raise PostgresDataValidationError(
                "PostgreSQL scalar integer query must return exactly one row and one column"
            )
        value = rows[0][0]
        if type(value) is not int:
            raise PostgresDataValidationError(
                "PostgreSQL scalar integer query returned a non-integer value"
            )
        return value

    def inspect_relation(
        self,
        schema: CanonicalSchema,
        relation: PostgresRelation,
        column_names: tuple[str, ...],
        max_metadata_record_bytes: int,
        max_metadata_total_bytes: int,
    ) -> PostgresInspectedRelation:
        _require_schema(schema)
        _require_relation(relation)
        _require_column_names(column_names, len(schema.fields))
        _validate_relation_identifiers(relation, self._profile.max_identifier_utf8_bytes)
        _validate_column_identifiers(column_names, self._profile.max_identifier_utf8_bytes)
        locked_row_type_oid = self._lock_relation(relation)
        relation_oid, relation_row_type_oid, relation_schema, relation_name = (
            self._resolve_relation(
                relation,
                max_metadata_record_bytes,
                max_metadata_total_bytes,
            )
        )
        if relation_row_type_oid != locked_row_type_oid:
            raise PostgresMetadataError(
                "PostgreSQL relation identity changed between lock acquisition and catalog "
                "inspection"
            )
        resolved_relation = PostgresRelation(components=(relation_schema, relation_name))
        if not column_names:
            bindings: tuple[PostgresFieldBinding, ...] = ()
        else:
            statement, parameters = _metadata_query(
                relation_oid,
                relation_schema,
                relation_name,
                column_names,
            )
            rows = self._execute_bounded(
                statement,
                parameters,
                len(column_names),
                max_metadata_record_bytes,
                max_metadata_total_bytes,
            )
            if len(rows) != len(column_names):
                raise PostgresMetadataError(
                    "PostgreSQL catalog query did not return one row per requested column: "
                    f"expected={len(column_names)}, actual={len(rows)}"
                )
            bindings = tuple(
                _binding_from_metadata_row(
                    field.name,
                    column_name,
                    index,
                    row,
                )
                for index, (field, column_name, row) in enumerate(
                    zip(schema.fields, column_names, rows, strict=True)
                )
            )
        inspection = PostgresInspectedRelation(
            context_id=self._evidence.context_id,
            relation_oid=relation_oid,
            relation_row_type_oid=relation_row_type_oid,
            relation=resolved_relation,
            bindings=bindings,
            max_identifier_utf8_bytes=self._profile.max_identifier_utf8_bytes,
        )
        validate_postgres_inspection(schema, inspection)
        return inspection

    def read_canonical_rows(
        self,
        query: PostgresQuery,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[PostgresCanonicalRow, ...]:
        _validate_postgres_query(query)
        self._require_query_context(query)
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        minimum_record_budget = (
            query.max_encoded_envelope_bytes + SHA256_BYTES + _CANONICAL_STATUS_BYTES
        )
        if max_record_bytes < minimum_record_budget:
            raise ValueError(
                "max_record_bytes must reserve the configured envelope and SHA-256 digest: "
                f"required={minimum_record_budget}, actual={max_record_bytes}"
            )
        rows = self._execute_compiled_query(
            query,
            max_records,
            max_record_bytes,
            max_total_bytes,
        )
        return tuple(_canonical_row_from_database(row, query) for row in rows)

    def read_fingerprint(
        self,
        query: PostgresQuery,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> Fingerprint:
        _validate_postgres_query(query)
        self._require_query_context(query)
        rows = self._execute_compiled_query(
            query,
            1,
            max_record_bytes,
            max_total_bytes,
        )
        if len(rows) != 1 or len(rows[0]) != 12:
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint query must return one row with origin type, valid "
                "count, eight limbs, invalid count, and oversized count"
            )
        if rows[0][0] is not None:
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint origin type marker must be NULL"
            )
        values = tuple(
            _parse_unsigned_decimal(value, 19 if index in (0, 9, 10) else 38)
            for index, value in enumerate(rows[0][1:])
        )
        count = values[0]
        invalid_count = values[9]
        oversized_count = values[10]
        if count > INT64_MAX or invalid_count > INT64_MAX or oversized_count > INT64_MAX:
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint row count exceeds the signed int64 protocol bound"
            )
        if invalid_count > 0:
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint rejected source rows that cannot be represented "
                f"losslessly: invalid_row_count={invalid_count}"
            )
        if oversized_count > 0:
            raise PostgresResultLimitError(
                "PostgreSQL fingerprint rejected canonical envelopes above the configured "
                f"limit: oversized_row_count={oversized_count}, "
                f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
            )
        try:
            return Fingerprint(
                count=count,
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
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint violates canonical accumulator bounds: "
                f"reason_type={type(error).__name__}"
            ) from None

    def close(self) -> None:
        failure: str | None = None
        with self._query_lock:
            if self._state is ReadContextState.CLOSED:
                return
            previous_state = self._state
            self._state = ReadContextState.CLOSED
            if previous_state is ReadContextState.ACTIVE:
                try:
                    self._connection.rollback()
                except psycopg.Error as error:
                    self._connection.close()
                    failure = _database_error_message("close read context", error)
            self._connection.close()
        if failure is not None:
            raise PostgresCloseError(failure)

    def _lock_relation(self, relation: PostgresRelation) -> int:
        # Parenthesized alias.* is a whole-row value even when a column shares the alias name.
        statement = sql.SQL(
            "SELECT CASE WHEN FALSE THEN (dfe_source.*) ELSE NULL END AS origin_type "
            "FROM ONLY {relation} AS dfe_source LIMIT 0"
        ).format(relation=sql.Identifier(*relation.components))
        database_failure: str | None = None
        metadata_failure: str | None = None
        row_type_oid: int | None = None
        with self._query_lock:
            self._require_active()
            cursor_name = f"dfe_{uuid4().hex}"
            try:
                self._restore_session_invariants()
                with self._connection.cursor(name=cursor_name) as cursor:
                    cursor.execute(statement)
                    row_type_oid = _origin_type_oid(
                        cursor.description,
                        "relation lock",
                    )
            except psycopg.Error as error:
                self._state = ReadContextState.LOST
                self._connection.close()
                if error.sqlstate in ("42P01", "42501"):
                    metadata_failure = _database_error_message(
                        "lock relation for inspection",
                        error,
                    )
                else:
                    database_failure = _database_error_message(
                        "lock relation for inspection",
                        error,
                    )
        if metadata_failure is not None:
            raise PostgresMetadataError(metadata_failure)
        if database_failure is not None:
            raise PostgresQueryError(database_failure)
        if row_type_oid is None:
            raise AssertionError("PostgreSQL relation lock completed without row type provenance")
        return row_type_oid

    def _resolve_relation(
        self,
        relation: PostgresRelation,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[int, int, str, str]:
        statement, parameters = _relation_query(relation)
        rows = self._execute_bounded(
            statement,
            parameters,
            1,
            max_record_bytes,
            max_total_bytes,
        )
        if not rows:
            raise PostgresMetadataError(
                "PostgreSQL relation is missing, inaccessible, or not a supported physical "
                "regular table"
            )
        row = rows[0]
        if len(row) != 6:
            raise PostgresDataValidationError(
                "PostgreSQL relation catalog probe must return exactly six fields"
            )
        relation_oid = _require_bounded_integer(row[0], "relation OID", 1, UINT32_MAX)
        relation_row_type_oid = _require_bounded_integer(
            row[1],
            "relation row type OID",
            1,
            UINT32_MAX,
        )
        relation_schema = _require_text(row[2], "relation schema")
        relation_name = _require_text(row[3], "relation name")
        relation_kind = _require_text(row[4], "relation kind")
        has_select = _require_boolean(row[5], "relation SELECT privilege")
        if relation_kind != "r":
            raise PostgresMetadataError(
                "PostgreSQL relation kind is unsupported by the v1 physical-table profile: "
                f"relation_kind={relation_kind!r}, allowed=('r',)"
            )
        if not has_select:
            raise PostgresMetadataError(
                "PostgreSQL relation is visible but the read role lacks SELECT privilege"
            )
        return relation_oid, relation_row_type_oid, relation_schema, relation_name

    def _execute_bounded(
        self,
        statement: ExecutableSql,
        parameters: tuple[PostgresParameter, ...],
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[DatabaseRow, ...]:
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        database_failure: str | None = None
        records: tuple[DatabaseRow, ...] | None = None
        with self._query_lock:
            self._require_active()
            cursor_name = f"dfe_{uuid4().hex}"
            try:
                self._restore_session_invariants()
                with self._connection.cursor(name=cursor_name) as cursor:
                    cursor.execute(statement, parameters)
                    records = _fetch_bounded_rows(
                        cursor,
                        max_records,
                        max_record_bytes,
                        max_total_bytes,
                    )
            except psycopg.Error as error:
                self._state = ReadContextState.LOST
                self._connection.close()
                database_failure = _database_error_message("execute read-only query", error)
        if database_failure is not None:
            raise PostgresQueryError(database_failure)
        if records is None:
            raise AssertionError("PostgreSQL bounded query completed without a result")
        return records

    def _execute_compiled_query(
        self,
        query: PostgresQuery,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[DatabaseRow, ...]:
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        database_failure: str | None = None
        records: tuple[DatabaseRow, ...] | None = None
        with self._query_lock:
            self._require_active()
            cursor_name = f"dfe_{uuid4().hex}"
            try:
                self._restore_session_invariants()
                with self._connection.cursor(name=cursor_name) as cursor:
                    cursor.execute(
                        _executable_statement(query.statement),
                        query.parameters,
                    )
                    _require_compiled_origin_type(
                        cursor.description,
                        query.inspected_relation.relation_row_type_oid,
                    )
                    records = _fetch_bounded_rows(
                        cursor,
                        max_records,
                        max_record_bytes,
                        max_total_bytes,
                    )
            except psycopg.Error as error:
                self._state = ReadContextState.LOST
                self._connection.close()
                database_failure = _database_error_message("execute compiled query", error)
        if database_failure is not None:
            raise PostgresQueryError(database_failure)
        if records is None:
            raise AssertionError("PostgreSQL compiled query completed without a result")
        return records

    def _restore_session_invariants(self) -> None:
        self._connection.execute("SET LOCAL search_path TO pg_catalog")
        self._connection.execute("SET LOCAL row_security TO off")
        self._connection.execute("SET LOCAL TIME ZONE 'UTC'")
        self._connection.execute("SET LOCAL DateStyle TO 'ISO, YMD'")
        self._connection.execute(
            "SELECT pg_catalog.set_config('statement_timeout', %s, true)",
            (str(self._statement_timeout_milliseconds),),
        )

    def _require_query_context(self, query: PostgresQuery) -> None:
        if query.inspected_relation.context_id != self._evidence.context_id:
            raise PostgresQueryContextError(
                "PostgreSQL compiled query belongs to a different read context: "
                f"query_context_id={query.inspected_relation.context_id}, "
                f"active_context_id={self._evidence.context_id}"
            )

    def _require_active(self) -> None:
        if self._state is ReadContextState.CLOSED:
            raise PostgresContextClosedError("PostgreSQL read context is already closed")
        if self._state is ReadContextState.LOST:
            raise PostgresContextLostError(
                "PostgreSQL transaction context was lost and cannot be reused"
            )


def open_postgres_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
) -> PostgresReadContext:
    failure_message: str | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        try:
            return _open_once(settings)
        except psycopg.OperationalError as error:
            failure_message = _connection_error_message(settings, attempt, error)
            LOGGER.warning(
                "PostgreSQL connection attempt failed",
                extra={
                    "operation": "open_read_context",
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "dbname": settings.dbname,
                    "user": settings.user,
                    "sslmode": settings.sslmode.value,
                    "error_type": type(error).__name__,
                    "sqlstate": error.sqlstate,
                },
            )
            if attempt < retry_policy.max_attempts:
                time.sleep(retry_policy.delay_seconds)
        except psycopg.Error as error:
            failure_message = _connection_error_message(settings, attempt, error)
            break
    if failure_message is None:
        raise AssertionError("connection retry loop ended without an attempt")
    raise PostgresConnectionError(failure_message)


def _open_once(settings: PostgresConnectionSettings) -> PostgresReadContext:
    connection = psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password.get_secret_value(),
        sslmode=settings.sslmode.value,
        connect_timeout=settings.connect_timeout_seconds,
        application_name=settings.application_name,
        autocommit=True,
        row_factory=tuple_row,
    )
    started_at = datetime.now(UTC)
    try:
        connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        connection.execute("SET LOCAL search_path TO pg_catalog")
        connection.execute("SET LOCAL row_security TO off")
        connection.execute("SET LOCAL TIME ZONE 'UTC'")
        connection.execute("SET LOCAL DateStyle TO 'ISO, YMD'")
        connection.execute(
            "SELECT pg_catalog.set_config('statement_timeout', %s, true)",
            (str(settings.statement_timeout_milliseconds),),
        )
        row = connection.execute(
            "SELECT pg_catalog.current_setting('server_version'), "
            "pg_catalog.current_setting('server_version_num')::integer, "
            "pg_catalog.current_setting('server_encoding'), "
            "pg_catalog.current_setting('client_encoding'), "
            "pg_catalog.current_setting('integer_datetimes') = 'on', "
            "pg_catalog.current_setting('TimeZone'), "
            "pg_catalog.current_setting('max_identifier_length')::integer, "
            "pg_catalog.pg_backend_pid(), pg_catalog.pg_current_snapshot()::text, "
            "pg_catalog.current_setting('transaction_isolation'), "
            "pg_catalog.current_setting('transaction_read_only') = 'on'"
        ).fetchone()
        if row is None:
            raise PostgresDataValidationError("PostgreSQL capability probe returned no row")
        profile, evidence = _profile_and_evidence(row, started_at)
        _validate_profile(profile, row)
    except psycopg.Error:
        connection.close()
        raise
    except PostgresConnectorError:
        connection.close()
        raise
    return PostgresReadContext(
        connection,
        profile,
        evidence,
        settings.statement_timeout_milliseconds,
    )


def _profile_and_evidence(
    row: DatabaseRow,
    started_at: datetime,
) -> tuple[PostgresServerProfile, PostgresReadContextEvidence]:
    if len(row) != 11:
        raise PostgresDataValidationError(
            "PostgreSQL capability probe must return exactly eleven typed fields"
        )
    server_version = _require_text(row[0], "server_version")
    server_version_number = _require_integer(row[1], "server_version_num")
    server_encoding = _require_text(row[2], "server_encoding")
    client_encoding = _require_text(row[3], "client_encoding")
    integer_datetimes = _require_boolean(row[4], "integer_datetimes")
    timezone = _require_text(row[5], "TimeZone")
    max_identifier_utf8_bytes = _require_bounded_integer(
        row[6],
        "max_identifier_length",
        1,
        INT64_MAX,
    )
    backend_process_id = _require_integer(row[7], "backend_process_id")
    snapshot_locator = _require_text(row[8], "snapshot_locator")
    profile = PostgresServerProfile(
        driver_version=psycopg.__version__,
        server_version=server_version,
        server_version_number=server_version_number,
        server_encoding=server_encoding,
        client_encoding=client_encoding,
        integer_datetimes=integer_datetimes,
        timezone=timezone,
        max_identifier_utf8_bytes=max_identifier_utf8_bytes,
    )
    evidence = PostgresReadContextEvidence(
        context_id=uuid4(),
        engine="postgresql",
        server_version=server_version,
        strategy="read_only_repeatable_read",
        snapshot_locator=snapshot_locator,
        started_at=started_at,
        backend_process_id=backend_process_id,
        allowed_concurrency=1,
        limitations=(
            "snapshot locator is evidence only and cannot reopen a closed transaction",
            "one active query is allowed for this connection",
            "relation reads target one physical regular table with inheritance expansion disabled",
        ),
    )
    return profile, evidence


def _validate_profile(profile: PostgresServerProfile, row: DatabaseRow) -> None:
    isolation = _require_text(row[9], "transaction_isolation")
    read_only = _require_boolean(row[10], "transaction_read_only")
    failures: list[str] = []
    if not 170000 <= profile.server_version_number < 180000:
        failures.append(f"server_version_num={profile.server_version_number}, required=17.x")
    if profile.server_encoding != "UTF8":
        failures.append(f"server_encoding={profile.server_encoding!r}, required='UTF8'")
    if profile.client_encoding != "UTF8":
        failures.append(f"client_encoding={profile.client_encoding!r}, required='UTF8'")
    if not profile.integer_datetimes:
        failures.append("integer_datetimes=off, required=on")
    if profile.timezone != "UTC":
        failures.append(f"TimeZone={profile.timezone!r}, required='UTC'")
    if isolation != "repeatable read":
        failures.append(f"transaction_isolation={isolation!r}, required='repeatable read'")
    if not read_only:
        failures.append("transaction_read_only=off, required=on")
    if failures:
        raise UnsupportedPostgresProfileError(
            "PostgreSQL 17 capability profile is unsupported: " + "; ".join(failures)
        )


def _relation_query(
    relation: PostgresRelation,
) -> tuple[ExecutableSql, tuple[PostgresParameter, ...]]:
    relation_expression = sql.SQL(
        "pg_catalog.to_regclass(pg_catalog.quote_ident(%s) || '.' || pg_catalog.quote_ident(%s))"
    )
    parameters: tuple[PostgresParameter, ...] = (
        relation.components[0],
        relation.components[1],
    )
    statement = sql.SQL(
        "SELECT c.oid::bigint, c.reltype::bigint, n.nspname, c.relname, c.relkind::text, "
        "pg_catalog.has_table_privilege(c.oid, 'SELECT') "
        "FROM pg_catalog.pg_class AS c "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE c.oid = {relation_expression}"
    ).format(relation_expression=relation_expression)
    return statement, parameters


def _metadata_query(
    relation_oid: int,
    relation_schema: str,
    relation_name: str,
    column_names: tuple[str, ...],
) -> tuple[ExecutableSql, tuple[PostgresParameter, ...]]:
    requested_rows = sql.SQL(", ").join(sql.SQL("(%s::integer, %s::text)") for _ in column_names)
    statement = sql.SQL(
        "WITH requested(request_ordinal, column_name) AS (VALUES {requested_rows}) "
        "SELECT requested.request_ordinal, requested.column_name, attribute.attname, "
        "pg_catalog.format_type(attribute.atttypid, attribute.atttypmod), "
        "declared_namespace.nspname, declared_type.typname, declared_type.oid::bigint, "
        "base_namespace.nspname, base_type.typname, base_type.oid::bigint, "
        "declared_type.typtype = 'd', attribute.attndims::integer, "
        "information.numeric_precision, information.numeric_scale, information.column_name "
        "FROM requested "
        "LEFT JOIN pg_catalog.pg_attribute AS attribute "
        "ON attribute.attrelid = %s::oid "
        "AND attribute.attname = requested.column_name "
        "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
        "LEFT JOIN pg_catalog.pg_type AS declared_type ON declared_type.oid = attribute.atttypid "
        "LEFT JOIN pg_catalog.pg_namespace AS declared_namespace "
        "ON declared_namespace.oid = declared_type.typnamespace "
        "LEFT JOIN pg_catalog.pg_type AS base_type "
        "ON base_type.oid = CASE WHEN declared_type.typtype = 'd' "
        "THEN declared_type.typbasetype ELSE declared_type.oid END "
        "LEFT JOIN pg_catalog.pg_namespace AS base_namespace "
        "ON base_namespace.oid = base_type.typnamespace "
        "LEFT JOIN information_schema.columns AS information "
        "ON information.table_catalog = current_database() "
        "AND information.table_schema = %s "
        "AND information.table_name = %s "
        "AND information.column_name = requested.column_name "
        "ORDER BY requested.request_ordinal"
    ).format(requested_rows=requested_rows)
    parameters_list: list[PostgresParameter] = []
    for index, column_name in enumerate(column_names, start=1):
        parameters_list.extend((index, column_name))
    parameters_list.extend((relation_oid, relation_schema, relation_name))
    return statement, tuple(parameters_list)


def _binding_from_metadata_row(
    field_name: str,
    column_name: str,
    index: int,
    row: DatabaseRow,
) -> PostgresFieldBinding:
    if len(row) != _METADATA_ROW_COLUMNS:
        raise PostgresDataValidationError(
            "PostgreSQL column catalog probe returned an unexpected field count: "
            f"expected={_METADATA_ROW_COLUMNS}, actual={len(row)}"
        )
    ordinal = _require_bounded_integer(row[0], "requested column ordinal", 1, INT64_MAX)
    if ordinal != index + 1:
        raise PostgresDataValidationError(
            "PostgreSQL column catalog probe returned an unexpected ordinal: "
            f"expected={index + 1}, actual={ordinal}"
        )
    requested_name = _require_text(row[1], "requested column name")
    if requested_name != column_name:
        raise PostgresDataValidationError(
            "PostgreSQL column catalog probe changed the requested identifier"
        )
    if row[2] is None or row[14] is None:
        raise PostgresMetadataError(
            "PostgreSQL requested column is missing or not visible to the read role: "
            f"column_index={index}, column_name={column_name!r}"
        )
    actual_name = _require_text(row[2], "column name")
    information_name = _require_text(row[14], "information_schema column name")
    if actual_name != column_name or information_name != column_name:
        raise PostgresDataValidationError(
            "PostgreSQL catalog sources disagree about the requested column identifier: "
            f"column_index={index}"
        )
    declared_type = PostgresTypeIdentity(
        schema_name=_require_text(row[4], "declared type schema"),
        type_name=_require_text(row[5], "declared type name"),
        oid=_require_bounded_integer(row[6], "declared type OID", 1, UINT32_MAX),
    )
    base_type = PostgresTypeIdentity(
        schema_name=_require_text(row[7], "base type schema"),
        type_name=_require_text(row[8], "base type name"),
        oid=_require_bounded_integer(row[9], "base type OID", 1, UINT32_MAX),
    )
    physical = PostgresPhysicalField(
        declared_type=declared_type,
        base_type=base_type,
        formatted_type=_require_text(row[3], "formatted type"),
        is_domain=_require_boolean(row[10], "is_domain"),
        array_dimensions=_require_bounded_integer(
            row[11],
            "array dimensions",
            0,
            INT64_MAX,
        ),
        numeric_precision=_require_optional_integer(row[12], "numeric precision"),
        numeric_scale=_require_optional_integer(row[13], "numeric scale"),
    )
    return PostgresFieldBinding(
        field_name=field_name,
        column_name=column_name,
        physical=physical,
    )


def _canonical_row_from_database(
    row: DatabaseRow,
    query: PostgresQuery,
) -> PostgresCanonicalRow:
    if len(row) != 5:
        raise PostgresDataValidationError(
            "PostgreSQL canonical row query must return origin type, envelope, SHA-256, "
            "invalid, and oversized fields"
        )
    if row[0] is not None:
        raise PostgresDataValidationError(
            "PostgreSQL canonical row origin type marker must be NULL"
        )
    invalid_row = _require_boolean(row[3], "canonical invalid-row status")
    oversized_row = _require_boolean(row[4], "canonical oversized-row status")
    if invalid_row and oversized_row:
        raise PostgresDataValidationError(
            "PostgreSQL canonical row statuses must be mutually exclusive"
        )
    if invalid_row or oversized_row:
        if row[1] is not None or row[2] is not None:
            raise PostgresDataValidationError(
                "PostgreSQL rejected canonical rows must not expose an envelope or digest"
            )
        if invalid_row:
            raise PostgresDataValidationError(
                "PostgreSQL source row cannot be represented losslessly by the logical schema"
            )
        raise PostgresResultLimitError(
            "PostgreSQL canonical envelope exceeds the configured SQL-side limit: "
            f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
        )
    envelope_text = _require_text(row[1], "canonical envelope")
    try:
        envelope = envelope_text.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise PostgresDataValidationError(
            "PostgreSQL canonical envelope contains non-ASCII bytes"
        ) from None
    if len(envelope) > query.max_encoded_envelope_bytes:
        raise PostgresDataValidationError(
            "PostgreSQL canonical envelope exceeds its declared SQL-side limit: "
            f"observed={len(envelope)}, limit={query.max_encoded_envelope_bytes}"
        )
    digest = row[2]
    if type(digest) is not bytes or len(digest) != SHA256_BYTES:
        raise PostgresDataValidationError(
            "PostgreSQL canonical row SHA-256 must be exactly 32 bytes"
        )
    try:
        decode_row_with_context(query.context, envelope)
    except CanonicalizationError as error:
        raise PostgresDataValidationError(
            "PostgreSQL canonical envelope failed reference decoding: "
            f"reason_type={type(error).__name__}"
        ) from None
    expected_digest = envelope_sha256(envelope)
    if digest != expected_digest:
        raise PostgresDataValidationError(
            "PostgreSQL canonical row SHA-256 does not match the returned envelope"
        )
    return PostgresCanonicalRow(envelope=envelope, sha256=digest)


def _origin_type_oid(
    description: Sequence[Column] | None,
    operation: str,
) -> int:
    if description is None or not description:
        raise PostgresDataValidationError(
            f"PostgreSQL {operation} did not expose result type provenance"
        )
    origin_type = description[0]
    if origin_type.name != "origin_type":
        raise PostgresDataValidationError(
            f"PostgreSQL {operation} returned an unexpected provenance column: "
            f"column_name={origin_type.name!r}"
        )
    return _require_bounded_integer(
        origin_type.type_code,
        f"{operation} origin type OID",
        1,
        UINT32_MAX,
    )


def _require_compiled_origin_type(
    description: Sequence[Column] | None,
    expected_row_type_oid: int,
) -> None:
    observed_row_type_oid = _origin_type_oid(description, "compiled query")
    if observed_row_type_oid != expected_row_type_oid:
        raise PostgresMetadataError(
            "PostgreSQL compiled query resolved to a different relation identity: "
            f"expected_row_type_oid={expected_row_type_oid}, "
            f"observed_row_type_oid={observed_row_type_oid}"
        )


def _fetch_bounded_rows(
    cursor: ServerCursor[DatabaseRow],
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
) -> tuple[DatabaseRow, ...]:
    records: list[DatabaseRow] = []
    total_bytes = 0
    while True:
        remaining = max_records + 1 - len(records)
        fetch_records = min(_CURSOR_FETCH_RECORDS, remaining)
        batch = cursor.fetchmany(fetch_records)
        if not batch:
            break
        for row in batch:
            if len(records) == max_records:
                raise PostgresResultLimitError(
                    "PostgreSQL query exceeded the reserved record budget: "
                    f"max_records={max_records}"
                )
            record_bytes = _database_row_bytes(row)
            if record_bytes > max_record_bytes:
                raise PostgresResultLimitError(
                    "PostgreSQL query returned a record above the byte budget: "
                    f"record_bytes={record_bytes}, max_record_bytes={max_record_bytes}"
                )
            total_bytes += record_bytes
            if total_bytes > max_total_bytes:
                raise PostgresResultLimitError(
                    "PostgreSQL query exceeded the total byte budget: "
                    f"observed_bytes={total_bytes}, max_total_bytes={max_total_bytes}"
                )
            records.append(row)
    return tuple(records)


def _parse_unsigned_decimal(value: object, maximum_digits: int) -> int:
    if type(value) is not str or not value or not value.isascii() or not value.isdecimal():
        raise PostgresDataValidationError(
            "PostgreSQL exact aggregate must be an unsigned canonical decimal string"
        )
    if len(value) > 1 and value[0] == "0":
        raise PostgresDataValidationError(
            "PostgreSQL exact aggregate must not contain leading zeroes"
        )
    if len(value) > maximum_digits:
        raise PostgresDataValidationError(
            "PostgreSQL exact aggregate exceeds its decimal digit bound: "
            f"digits={len(value)}, maximum={maximum_digits}"
        )
    return int(value)


def _database_row_bytes(row: DatabaseRow) -> int:
    total = 0
    for value in row:
        if value is None:
            continue
        if type(value) is str:
            try:
                total += len(value.encode("utf-8", errors="strict"))
            except UnicodeEncodeError:
                raise PostgresDataValidationError(
                    "PostgreSQL returned text containing a surrogate code point"
                ) from None
            continue
        if type(value) is bytes:
            total += len(value)
            continue
        if type(value) is bool:
            total += 1
            continue
        if type(value) is int:
            total += len(str(value).encode("ascii"))
            continue
        raise PostgresDataValidationError(
            "PostgreSQL returned an unsupported result value type: "
            f"value_type={type(value).__name__}"
        )
    return total


def _validate_result_limits(
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
) -> None:
    _validate_positive_integer(max_records, "max_records")
    _validate_positive_integer(max_record_bytes, "max_record_bytes")
    _validate_positive_integer(max_total_bytes, "max_total_bytes")
    if max_record_bytes > max_total_bytes:
        raise ValueError(
            "max_record_bytes must not exceed max_total_bytes: "
            f"record={max_record_bytes}, total={max_total_bytes}"
        )


def _validate_postgres_query(query: object) -> None:
    if not isinstance(query, PostgresQuery):
        raise TypeError("query must be a PostgresQuery")
    _validate_positive_integer(
        query.max_encoded_envelope_bytes,
        "query.max_encoded_envelope_bytes",
    )
    if type(query.parameters) is not tuple:
        raise TypeError("query.parameters must be an immutable tuple")


def _executable_statement(statement: sql.Composable) -> ExecutableSql:
    if isinstance(statement, (sql.SQL, sql.Composed)):
        return statement
    raise TypeError("query.statement must be psycopg.sql.SQL or psycopg.sql.Composed")


def _require_schema(value: object) -> None:
    if not isinstance(value, CanonicalSchema):
        raise TypeError("schema must be a CanonicalSchema")


def _require_relation(value: object) -> None:
    if not isinstance(value, PostgresRelation):
        raise TypeError("relation must be a PostgresRelation")


def _require_column_names(value: object, expected_count: int) -> None:
    if type(value) is not tuple:
        raise TypeError("column_names must be an immutable tuple")
    column_names = cast(tuple[object, ...], value)
    if len(column_names) != expected_count:
        raise ValueError(
            "column_names count must equal the logical schema field count: "
            f"expected={expected_count}, actual={len(column_names)}"
        )
    for index, column_name in enumerate(column_names):
        if type(column_name) is not str or not column_name or "\x00" in column_name:
            raise ValueError(
                "PostgreSQL column identifiers must be non-empty strings without U+0000: "
                f"column_index={index}"
            )


def _validate_relation_identifiers(relation: PostgresRelation, maximum_bytes: int) -> None:
    for index, component in enumerate(relation.components):
        _validate_identifier_bytes(component, f"relation component {index}", maximum_bytes)


def _validate_column_identifiers(column_names: tuple[str, ...], maximum_bytes: int) -> None:
    for index, column_name in enumerate(column_names):
        _validate_identifier_bytes(column_name, f"column identifier {index}", maximum_bytes)


def _validate_identifier_bytes(value: str, context: str, maximum_bytes: int) -> None:
    try:
        byte_length = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise PostgresMetadataError(
            f"PostgreSQL {context} contains a surrogate code point"
        ) from None
    if byte_length > maximum_bytes:
        raise PostgresMetadataError(
            f"PostgreSQL {context} exceeds the probed identifier limit: "
            f"utf8_bytes={byte_length}, maximum={maximum_bytes}"
        )


def _require_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        raise PostgresDataValidationError(
            f"PostgreSQL field {field_name!r} must be a non-empty string"
        )
    return value


def _require_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise PostgresDataValidationError(f"PostgreSQL field {field_name!r} must be an integer")
    return value


def _require_bounded_integer(
    value: object,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    integer = _require_integer(value, field_name)
    if not minimum <= integer <= maximum:
        raise PostgresDataValidationError(
            f"PostgreSQL field {field_name!r} is outside its accepted range: "
            f"minimum={minimum}, maximum={maximum}"
        )
    return integer


def _require_optional_integer(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _require_integer(value, field_name)


def _require_boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise PostgresDataValidationError(f"PostgreSQL field {field_name!r} must be a boolean")
    return value


def _validate_positive_integer(value: object, field_name: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")


def _database_error_message(operation: str, error: psycopg.Error) -> str:
    return (
        f"PostgreSQL {operation} failed and invalidated the read context: "
        f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
    )


def _connection_error_message(
    settings: PostgresConnectionSettings,
    attempts: int,
    error: psycopg.Error,
) -> str:
    return (
        "PostgreSQL read context setup failed after bounded attempts: "
        f"host={settings.host!r}, port={settings.port}, dbname={settings.dbname!r}, "
        f"user={settings.user!r}, sslmode={settings.sslmode.value!r}, attempts={attempts}, "
        f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
    )
