import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from types import TracebackType
from typing import LiteralString, Protocol, Self, cast, final
from uuid import UUID, uuid4

import psycopg
import psycopg2
from psycopg import pq
from psycopg.rows import tuple_row
from psycopg2.extensions import connection as Psycopg2Connection

from forensic_data.greenplum_catalog import (
    GREENGAGE_HASH_CAPABILITY_QUERY,
    GREENGAGE_RELATION_QUERY,
    ORIGINAL_GREENPLUM_HASH_CAPABILITY_QUERY,
    ORIGINAL_GREENPLUM_RELATION_QUERY,
    READER_IDENTITY_QUERY,
    TOPOLOGY_QUERY,
    GreengageHashCapability,
    GreengageRelationCatalog,
    GreenplumCatalogDataError,
    GreenplumCatalogMetadataError,
    GreenplumCatalogParameter,
    GreenplumDistributedHashPlan,
    GreenplumDistributedHashRow,
    GreenplumReaderIdentity,
    GreenplumRelationProbeRequest,
    GreenplumTopology,
    GreenplumTypeProbe,
    OriginalGreenplumHashCapability,
    OriginalGreenplumRelationCatalog,
    explain_query,
    greengage_distributed_hash_query,
    greenplum_type_catalog_query,
    original_greenplum_distributed_hash_query,
    parse_greengage_distributed_hash_plan,
    parse_greengage_hash_capability,
    parse_greengage_relation_catalog,
    parse_greenplum_distributed_hash_rows,
    parse_greenplum_reader_identity,
    parse_greenplum_topology,
    parse_greenplum_type_probe,
    parse_original_greenplum_distributed_hash_plan,
    parse_original_greenplum_hash_capability,
    parse_original_greenplum_relation_catalog,
    require_hash_record_id_integer_type,
    require_hash_rows_cover_topology,
)
from forensic_data.greenplum_profile import GreenplumRuntimeProfile
from forensic_data.postgres import (
    INT64_MAX,
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresRetryPolicy,
)

LOGGER = logging.getLogger(__name__)
_PSYCOPG2_VERSION = version("psycopg2")
_PSYCOPG_VERSION = version("psycopg")
_MAX_PROFILE_TEXT_BYTES = 4096
_MAX_TOPOLOGY_ROWS = 2048
_MAX_EXPLAIN_ROWS = 2048

ORIGINAL_GREENPLUM_PROFILE_QUERY = (
    "SELECT pg_catalog.version(), pg_catalog.current_setting('server_version'), "
    "pg_catalog.current_setting('server_version_num')::integer, "
    "pg_catalog.current_setting('server_encoding'), "
    "pg_catalog.current_setting('client_encoding'), "
    "pg_catalog.current_setting('integer_datetimes') = 'on', "
    "pg_catalog.current_setting('TimeZone'), "
    "pg_catalog.current_setting('max_identifier_length')::integer, "
    "pg_catalog.current_setting('gp_role'), "
    "pg_catalog.current_setting('gp_session_role'), current_database(), "
    "pg_catalog.pg_backend_pid(), "
    "pg_catalog.current_setting('transaction_isolation'), "
    "pg_catalog.current_setting('transaction_read_only') = 'on'"
)

GREENGAGE_PROFILE_QUERY = (
    "SELECT pg_catalog.version(), pg_catalog.current_setting('gp_server_version'), "
    "pg_catalog.current_setting('server_version'), "
    "pg_catalog.current_setting('server_version_num')::integer, "
    "pg_catalog.current_setting('server_encoding'), "
    "pg_catalog.current_setting('client_encoding'), "
    "pg_catalog.current_setting('integer_datetimes') = 'on', "
    "pg_catalog.current_setting('TimeZone'), "
    "pg_catalog.current_setting('max_identifier_length')::integer, "
    "pg_catalog.current_setting('gp_role'), "
    "pg_catalog.current_setting('gp_session_role'), current_database(), "
    "pg_catalog.pg_backend_pid(), "
    "pg_catalog.current_setting('transaction_isolation'), "
    "pg_catalog.current_setting('transaction_read_only') = 'on'"
)

_SESSION_SETUP_QUERY = (
    "SELECT pg_catalog.set_config('search_path', 'pg_catalog', true), "
    "pg_catalog.set_config('TimeZone', 'UTC', true), "
    "pg_catalog.set_config('DateStyle', 'ISO, YMD', true), "
    "pg_catalog.set_config('statement_timeout', %s, true)"
)


class GreenplumConnectorError(RuntimeError):
    """Base error for original Greenplum and Greengage probe boundaries."""


class GreenplumConnectionError(GreenplumConnectorError):
    """A Greenplum-family connection or read-only session setup failed."""


class UnsupportedGreenplumProfileError(GreenplumConnectorError):
    """The connected product cannot satisfy its declared runtime profile."""


class GreenplumMetadataError(GreenplumConnectorError):
    """Required Greenplum-family catalog or capability evidence is unavailable."""


class GreenplumDataValidationError(GreenplumConnectorError):
    """A driver or server value is outside the typed Greenplum probe contract."""


class GreenplumQueryError(GreenplumConnectorError):
    """A bounded Greenplum-family probe query failed without retry."""

    def __init__(
        self,
        operation: str,
        sqlstate: str | None,
        error_category: str,
    ) -> None:
        self.operation = operation
        self.sqlstate = sqlstate
        self.error_category = error_category
        super().__init__(
            "Greenplum-family query failed: "
            f"operation={operation!r}, sqlstate={sqlstate!r}, "
            f"error_category={error_category!r}"
        )


class GreenplumCloseError(GreenplumConnectorError):
    """A Greenplum-family probe session could not roll back and close cleanly."""


@final
@dataclass(frozen=True, slots=True)
class GreenplumDriverEvidence:
    driver_name: str
    driver_version: str
    build_libpq_version: int
    runtime_libpq_version: int


@final
@dataclass(frozen=True, slots=True)
class GreenplumServerProfile:
    runtime_profile: GreenplumRuntimeProfile
    full_version: str
    product_version: str
    compatibility_version: str
    compatibility_version_number: int
    server_encoding: str
    client_encoding: str
    integer_datetimes: bool
    timezone: str
    max_identifier_utf8_bytes: int
    gp_role: str
    gp_session_role: str
    database_name: str
    backend_process_id: int
    transaction_isolation: str
    transaction_read_only: bool


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumProbeEvidence:
    probe_id: UUID
    started_at: datetime
    driver: GreenplumDriverEvidence
    server: GreenplumServerProfile
    reader: GreenplumReaderIdentity
    topology: GreenplumTopology
    relation: OriginalGreenplumRelationCatalog
    types: GreenplumTypeProbe
    hash_capability: OriginalGreenplumHashCapability
    hash_plan: GreenplumDistributedHashPlan
    hash_rows: tuple[GreenplumDistributedHashRow, ...]
    required_extensions: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class GreengageProbeEvidence:
    probe_id: UUID
    started_at: datetime
    driver: GreenplumDriverEvidence
    server: GreenplumServerProfile
    reader: GreenplumReaderIdentity
    topology: GreenplumTopology
    relation: GreengageRelationCatalog
    types: GreenplumTypeProbe
    hash_capability: GreengageHashCapability
    hash_plan: GreenplumDistributedHashPlan
    hash_rows: tuple[GreenplumDistributedHashRow, ...]
    required_extensions: tuple[str, ...]


class _GreenplumProbeSession(Protocol):
    def begin_read_only(self, statement_timeout_milliseconds: int) -> None: ...

    def fetch_rows(
        self,
        statement: str,
        parameters: tuple[GreenplumCatalogParameter, ...],
        max_rows: int,
        operation: str,
    ) -> tuple[DatabaseRow, ...]: ...


class _OriginalGreenplumSession:
    def __init__(self, connection: Psycopg2Connection) -> None:
        self._connection = connection
        self._closed = False

    def begin_read_only(self, statement_timeout_milliseconds: int) -> None:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute("BEGIN READ ONLY")
                cursor.execute(
                    _SESSION_SETUP_QUERY,
                    (str(statement_timeout_milliseconds),),
                )
                cursor.fetchone()
        except psycopg2.Error as error:
            raise GreenplumConnectionError(
                "original Greenplum read-only session setup failed: "
                f"sqlstate={error.pgcode!r}, detail={str(error).strip()!r}"
            ) from None

    def fetch_rows(
        self,
        statement: str,
        parameters: tuple[GreenplumCatalogParameter, ...],
        max_rows: int,
        operation: str,
    ) -> tuple[DatabaseRow, ...]:
        _validate_max_rows(max_rows)
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(cast(LiteralString, statement), parameters)
                if cursor.description is None:
                    raise GreenplumDataValidationError(
                        "original Greenplum probe query returned no row description: "
                        f"operation={operation!r}"
                    )
                rows = cursor.fetchmany(max_rows + 1)
        except psycopg2.Error as error:
            raise GreenplumQueryError(
                operation,
                error.pgcode,
                type(error).__name__,
            ) from None
        result = tuple(cast(DatabaseRow, row) for row in rows)
        _require_bounded_result(result, max_rows, operation)
        return result

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._closed:
            return
        self._closed = True
        cleanup_error: psycopg2.Error | None = None
        try:
            with self._connection.cursor() as cursor:
                cursor.execute("ROLLBACK")
        except psycopg2.Error as error:
            cleanup_error = error
        self._connection.close()
        if cleanup_error is None:
            return
        _handle_cleanup_error(
            exception,
            cleanup_error.pgcode,
            str(cleanup_error).strip(),
            "original_greenplum",
        )


class _GreengageSession:
    def __init__(self, connection: psycopg.Connection[DatabaseRow]) -> None:
        self._connection = connection
        self._closed = False

    def begin_read_only(self, statement_timeout_milliseconds: int) -> None:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute("BEGIN READ ONLY")
                cursor.execute(
                    _SESSION_SETUP_QUERY,
                    (str(statement_timeout_milliseconds),),
                )
                cursor.fetchone()
        except psycopg.Error as error:
            raise GreenplumConnectionError(
                "Greengage read-only session setup failed: "
                f"sqlstate={error.sqlstate!r}, detail={str(error).strip()!r}"
            ) from None

    def fetch_rows(
        self,
        statement: str,
        parameters: tuple[GreenplumCatalogParameter, ...],
        max_rows: int,
        operation: str,
    ) -> tuple[DatabaseRow, ...]:
        _validate_max_rows(max_rows)
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(cast(LiteralString, statement), parameters)
                if cursor.description is None:
                    raise GreenplumDataValidationError(
                        "Greengage probe query returned no row description: "
                        f"operation={operation!r}"
                    )
                rows = cursor.fetchmany(max_rows + 1)
        except psycopg.Error as error:
            raise GreenplumQueryError(
                operation,
                error.sqlstate,
                type(error).__name__,
            ) from None
        result = tuple(rows)
        _require_bounded_result(result, max_rows, operation)
        return result

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._closed:
            return
        self._closed = True
        cleanup_error: psycopg.Error | None = None
        try:
            with self._connection.cursor() as cursor:
                cursor.execute("ROLLBACK")
        except psycopg.Error as error:
            cleanup_error = error
        self._connection.close()
        if cleanup_error is None:
            return
        _handle_cleanup_error(
            exception,
            cleanup_error.sqlstate,
            str(cleanup_error).strip(),
            "greengage",
        )


def probe_original_greenplum(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    request: GreenplumRelationProbeRequest,
) -> OriginalGreenplumProbeEvidence:
    started_at = datetime.now(UTC)
    session = _connect_original_greenplum(settings, retry_policy)
    with session:
        try:
            session.begin_read_only(settings.statement_timeout_milliseconds)
            driver = _original_greenplum_driver_evidence()
            server = _probe_original_greenplum_profile(session, settings)
            _validate_request_identifier_lengths(request, server.max_identifier_utf8_bytes)
            topology = _probe_topology(session)
            reader = _probe_reader_identity(session, settings)
            relation_rows = session.fetch_rows(
                ORIGINAL_GREENPLUM_RELATION_QUERY,
                (request.schema_name, request.relation_name),
                2,
                "original_greenplum_relation_catalog",
            )
            relation = parse_original_greenplum_relation_catalog(relation_rows, request)
            type_probe = _probe_types(session, relation.relation_oid, request)
            require_hash_record_id_integer_type(type_probe, request)
            hash_capability_rows = session.fetch_rows(
                ORIGINAL_GREENPLUM_HASH_CAPABILITY_QUERY,
                (),
                2,
                "original_greenplum_hash_capability",
            )
            hash_capability = parse_original_greenplum_hash_capability(hash_capability_rows)
            hash_statement, hash_parameters = original_greenplum_distributed_hash_query(request)
            hash_plan = _probe_original_greenplum_hash_plan(
                session,
                hash_statement,
                hash_parameters,
                request,
                topology,
                "original_greenplum_hash_plan",
            )
            hash_rows = _probe_hash_rows(
                session,
                hash_statement,
                hash_parameters,
                request,
                topology,
                "original_greenplum_distributed_hash",
            )
        except GreenplumCatalogMetadataError as error:
            raise GreenplumMetadataError(str(error)) from None
        except GreenplumCatalogDataError as error:
            raise GreenplumDataValidationError(str(error)) from None
    return OriginalGreenplumProbeEvidence(
        probe_id=uuid4(),
        started_at=started_at,
        driver=driver,
        server=server,
        reader=reader,
        topology=topology,
        relation=relation,
        types=type_probe,
        hash_capability=hash_capability,
        hash_plan=hash_plan,
        hash_rows=hash_rows,
        required_extensions=(),
    )


def probe_greengage(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    request: GreenplumRelationProbeRequest,
) -> GreengageProbeEvidence:
    started_at = datetime.now(UTC)
    session = _connect_greengage(settings, retry_policy)
    with session:
        try:
            session.begin_read_only(settings.statement_timeout_milliseconds)
            driver = _greengage_driver_evidence()
            server = _probe_greengage_profile(session, settings)
            _validate_request_identifier_lengths(request, server.max_identifier_utf8_bytes)
            topology = _probe_topology(session)
            reader = _probe_reader_identity(session, settings)
            relation_rows = session.fetch_rows(
                GREENGAGE_RELATION_QUERY,
                (request.schema_name, request.relation_name),
                2,
                "greengage_relation_catalog",
            )
            relation = parse_greengage_relation_catalog(relation_rows, request)
            type_probe = _probe_types(session, relation.relation_oid, request)
            require_hash_record_id_integer_type(type_probe, request)
            hash_capability_rows = session.fetch_rows(
                GREENGAGE_HASH_CAPABILITY_QUERY,
                (),
                2,
                "greengage_hash_capability",
            )
            hash_capability = parse_greengage_hash_capability(hash_capability_rows)
            hash_statement, hash_parameters = greengage_distributed_hash_query(request)
            hash_plan = _probe_greengage_hash_plan(
                session,
                hash_statement,
                hash_parameters,
                request,
                topology,
                "greengage_hash_plan",
            )
            hash_rows = _probe_hash_rows(
                session,
                hash_statement,
                hash_parameters,
                request,
                topology,
                "greengage_distributed_hash",
            )
        except GreenplumCatalogMetadataError as error:
            raise GreenplumMetadataError(str(error)) from None
        except GreenplumCatalogDataError as error:
            raise GreenplumDataValidationError(str(error)) from None
    return GreengageProbeEvidence(
        probe_id=uuid4(),
        started_at=started_at,
        driver=driver,
        server=server,
        reader=reader,
        topology=topology,
        relation=relation,
        types=type_probe,
        hash_capability=hash_capability,
        hash_plan=hash_plan,
        hash_rows=hash_rows,
        required_extensions=(),
    )


def _probe_original_greenplum_profile(
    session: _GreenplumProbeSession,
    settings: PostgresConnectionSettings,
) -> GreenplumServerProfile:
    rows = session.fetch_rows(
        ORIGINAL_GREENPLUM_PROFILE_QUERY,
        (),
        2,
        "original_greenplum_server_profile",
    )
    row = _require_single_row(rows, "original Greenplum server profile")
    if len(row) != 14:
        raise GreenplumDataValidationError(
            f"original Greenplum profile must return exactly fourteen fields: actual={len(row)}"
        )
    full_version = _require_text(row[0], "original Greenplum full version")
    product_version = _extract_product_version(full_version, "Greenplum Database")
    profile = _build_server_profile(
        GreenplumRuntimeProfile.ORIGINAL_GREENPLUM,
        full_version,
        product_version,
        row,
        1,
    )
    _validate_server_profile(profile, settings)
    return profile


def _probe_greengage_profile(
    session: _GreenplumProbeSession,
    settings: PostgresConnectionSettings,
) -> GreenplumServerProfile:
    rows = session.fetch_rows(
        GREENGAGE_PROFILE_QUERY,
        (),
        2,
        "greengage_server_profile",
    )
    row = _require_single_row(rows, "Greengage server profile")
    if len(row) != 15:
        raise GreenplumDataValidationError(
            f"Greengage profile must return exactly fifteen fields: actual={len(row)}"
        )
    full_version = _require_text(row[0], "Greengage full version")
    product_version = _require_text(row[1], "Greengage product version")
    version_from_identity = _extract_product_version(full_version, "Greengage Database")
    if product_version != version_from_identity:
        raise UnsupportedGreenplumProfileError(
            "Greengage identity sources disagree: "
            f"version_identity={version_from_identity!r}, "
            f"gp_server_version={product_version!r}"
        )
    profile = _build_server_profile(
        GreenplumRuntimeProfile.GREENGAGE,
        full_version,
        product_version,
        row,
        2,
    )
    _validate_server_profile(profile, settings)
    return profile


def _build_server_profile(
    runtime_profile: GreenplumRuntimeProfile,
    full_version: str,
    product_version: str,
    row: DatabaseRow,
    compatibility_index: int,
) -> GreenplumServerProfile:
    return GreenplumServerProfile(
        runtime_profile=runtime_profile,
        full_version=full_version,
        product_version=product_version,
        compatibility_version=_require_text(
            row[compatibility_index],
            "Greenplum PostgreSQL compatibility version",
        ),
        compatibility_version_number=_require_bounded_integer(
            row[compatibility_index + 1],
            "Greenplum PostgreSQL compatibility version number",
            1,
            INT64_MAX,
        ),
        server_encoding=_require_text(
            row[compatibility_index + 2],
            "Greenplum server encoding",
        ),
        client_encoding=_require_text(
            row[compatibility_index + 3],
            "Greenplum client encoding",
        ),
        integer_datetimes=_require_boolean(
            row[compatibility_index + 4],
            "Greenplum integer-datetimes flag",
        ),
        timezone=_require_text(row[compatibility_index + 5], "Greenplum TimeZone"),
        max_identifier_utf8_bytes=_require_bounded_integer(
            row[compatibility_index + 6],
            "Greenplum max identifier length",
            1,
            INT64_MAX,
        ),
        gp_role=_require_text(row[compatibility_index + 7], "Greenplum gp_role"),
        gp_session_role=_require_text(
            row[compatibility_index + 8],
            "Greenplum gp_session_role",
        ),
        database_name=_require_text(
            row[compatibility_index + 9],
            "Greenplum current database",
        ),
        backend_process_id=_require_bounded_integer(
            row[compatibility_index + 10],
            "Greenplum backend process ID",
            1,
            INT64_MAX,
        ),
        transaction_isolation=_require_text(
            row[compatibility_index + 11],
            "Greenplum transaction isolation",
        ),
        transaction_read_only=_require_boolean(
            row[compatibility_index + 12],
            "Greenplum transaction read-only flag",
        ),
    )


def _validate_server_profile(
    profile: GreenplumServerProfile,
    settings: PostgresConnectionSettings,
) -> None:
    failures: list[str] = []
    if profile.server_encoding != "UTF8":
        failures.append(f"server_encoding={profile.server_encoding!r}, required='UTF8'")
    if profile.client_encoding != "UTF8":
        failures.append(f"client_encoding={profile.client_encoding!r}, required='UTF8'")
    if not profile.integer_datetimes:
        failures.append("integer_datetimes=off, required=on")
    if profile.timezone != "UTC":
        failures.append(f"TimeZone={profile.timezone!r}, required='UTC'")
    if profile.gp_role != "dispatch":
        failures.append(f"gp_role={profile.gp_role!r}, required='dispatch'")
    if profile.gp_session_role != "dispatch":
        failures.append(f"gp_session_role={profile.gp_session_role!r}, required='dispatch'")
    if profile.database_name != settings.dbname:
        failures.append(f"database={profile.database_name!r}, required={settings.dbname!r}")
    if not profile.transaction_read_only:
        failures.append("transaction_read_only=off, required=on")
    if failures:
        raise UnsupportedGreenplumProfileError(
            "Greenplum-family capability profile is unsupported: "
            f"runtime_profile={profile.runtime_profile.value!r}, "
            f"full_version={profile.full_version!r}; " + "; ".join(failures)
        )


def _validate_request_identifier_lengths(
    request: GreenplumRelationProbeRequest,
    max_identifier_utf8_bytes: int,
) -> None:
    identifiers = (
        ("schema", request.schema_name),
        ("relation", request.relation_name),
        *((f"column[{index}]", column.column_name) for index, column in enumerate(request.columns)),
    )
    for category, identifier in identifiers:
        try:
            byte_length = len(identifier.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            raise GreenplumMetadataError(
                "Greenplum probe identifier is not valid UTF-8 text: "
                f"identifier_category={category!r}"
            ) from None
        if byte_length > max_identifier_utf8_bytes:
            raise GreenplumMetadataError(
                "Greenplum probe identifier exceeds the connected server limit: "
                f"identifier_category={category!r}, utf8_bytes={byte_length}, "
                f"maximum={max_identifier_utf8_bytes}"
            )


def _probe_topology(session: _GreenplumProbeSession) -> GreenplumTopology:
    rows = session.fetch_rows(
        TOPOLOGY_QUERY,
        (),
        _MAX_TOPOLOGY_ROWS,
        "greenplum_topology",
    )
    return parse_greenplum_topology(rows)


def _probe_reader_identity(
    session: _GreenplumProbeSession,
    settings: PostgresConnectionSettings,
) -> GreenplumReaderIdentity:
    rows = session.fetch_rows(
        READER_IDENTITY_QUERY,
        (),
        2,
        "greenplum_reader_identity",
    )
    row = _require_single_row(rows, "Greenplum reader identity")
    identity = parse_greenplum_reader_identity(row)
    if identity.user_name != settings.user:
        raise GreenplumMetadataError(
            "Greenplum authenticated reader differs from the requested role: "
            f"requested={settings.user!r}, actual={identity.user_name!r}"
        )
    return identity


def _probe_types(
    session: _GreenplumProbeSession,
    relation_oid: int,
    request: GreenplumRelationProbeRequest,
) -> GreenplumTypeProbe:
    statement, parameters = greenplum_type_catalog_query(relation_oid, request)
    rows = session.fetch_rows(
        statement,
        parameters,
        len(request.columns),
        "greenplum_type_catalog",
    )
    return parse_greenplum_type_probe(rows, request)


def _probe_original_greenplum_hash_plan(
    session: _GreenplumProbeSession,
    hash_statement: str,
    hash_parameters: tuple[GreenplumCatalogParameter, ...],
    request: GreenplumRelationProbeRequest,
    topology: GreenplumTopology,
    operation: str,
) -> GreenplumDistributedHashPlan:
    rows = session.fetch_rows(
        explain_query(hash_statement),
        hash_parameters,
        _MAX_EXPLAIN_ROWS,
        operation,
    )
    return parse_original_greenplum_distributed_hash_plan(
        rows,
        request,
        len(topology.primary_content_ids),
    )


def _probe_greengage_hash_plan(
    session: _GreenplumProbeSession,
    hash_statement: str,
    hash_parameters: tuple[GreenplumCatalogParameter, ...],
    request: GreenplumRelationProbeRequest,
    topology: GreenplumTopology,
    operation: str,
) -> GreenplumDistributedHashPlan:
    rows = session.fetch_rows(
        explain_query(hash_statement),
        hash_parameters,
        _MAX_EXPLAIN_ROWS,
        operation,
    )
    return parse_greengage_distributed_hash_plan(
        rows,
        request,
        len(topology.primary_content_ids),
    )


def _probe_hash_rows(
    session: _GreenplumProbeSession,
    hash_statement: str,
    hash_parameters: tuple[GreenplumCatalogParameter, ...],
    request: GreenplumRelationProbeRequest,
    topology: GreenplumTopology,
    operation: str,
) -> tuple[GreenplumDistributedHashRow, ...]:
    rows = session.fetch_rows(
        hash_statement,
        hash_parameters,
        request.hash_row_limit,
        operation,
    )
    parsed = parse_greenplum_distributed_hash_rows(rows)
    require_hash_rows_cover_topology(parsed, topology)
    return parsed


def _connect_original_greenplum(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
) -> _OriginalGreenplumSession:
    last_error: psycopg2.Error | None = None
    last_attempt = 0
    for attempt in range(1, retry_policy.max_attempts + 1):
        last_attempt = attempt
        try:
            connection = psycopg2.connect(
                host=settings.host,
                port=settings.port,
                dbname=settings.dbname,
                user=settings.user,
                password=settings.password.get_secret_value(),
                sslmode=settings.sslmode.value,
                connect_timeout=settings.connect_timeout_seconds,
                application_name=settings.application_name,
            )
            connection.autocommit = True
            return _OriginalGreenplumSession(connection)
        except psycopg2.Error as error:
            last_error = error
            LOGGER.warning(
                "Original Greenplum connection attempt failed",
                extra={
                    "operation": "connect_original_greenplum_probe",
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "dbname": settings.dbname,
                    "user": settings.user,
                    "sslmode": settings.sslmode.value,
                    "error_type": type(error).__name__,
                    "sqlstate": error.pgcode,
                },
            )
            if not isinstance(error, psycopg2.OperationalError):
                break
            if attempt < retry_policy.max_attempts:
                time.sleep(retry_policy.delay_seconds)
    if last_error is None:
        raise AssertionError("original Greenplum connection loop ended without an attempt")
    raise GreenplumConnectionError(
        _connection_error_message(
            "original_greenplum",
            settings,
            last_attempt,
            last_error.pgcode,
            str(last_error).strip(),
        )
    ) from None


def _connect_greengage(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
) -> _GreengageSession:
    last_error: psycopg.Error | None = None
    last_attempt = 0
    for attempt in range(1, retry_policy.max_attempts + 1):
        last_attempt = attempt
        try:
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
            return _GreengageSession(connection)
        except psycopg.Error as error:
            last_error = error
            LOGGER.warning(
                "Greengage connection attempt failed",
                extra={
                    "operation": "connect_greengage_probe",
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
            if not isinstance(error, psycopg.OperationalError):
                break
            if attempt < retry_policy.max_attempts:
                time.sleep(retry_policy.delay_seconds)
    if last_error is None:
        raise AssertionError("Greengage connection loop ended without an attempt")
    raise GreenplumConnectionError(
        _connection_error_message(
            "greengage",
            settings,
            last_attempt,
            last_error.sqlstate,
            str(last_error).strip(),
        )
    ) from None


def _original_greenplum_driver_evidence() -> GreenplumDriverEvidence:
    build_version = psycopg2.__libpq_version__
    runtime_version = psycopg2.extensions.libpq_version()
    return _driver_evidence("psycopg2", _PSYCOPG2_VERSION, build_version, runtime_version)


def _greengage_driver_evidence() -> GreenplumDriverEvidence:
    return _driver_evidence(
        "psycopg",
        _PSYCOPG_VERSION,
        pq.__build_version__,
        pq.version(),
    )


def _driver_evidence(
    driver_name: str,
    driver_version: str,
    build_libpq_version: int,
    runtime_libpq_version: int,
) -> GreenplumDriverEvidence:
    _require_text(driver_name, "Greenplum driver name")
    _require_text(driver_version, "Greenplum driver version")
    _require_bounded_integer(
        build_libpq_version,
        "Greenplum build libpq version",
        1,
        INT64_MAX,
    )
    _require_bounded_integer(
        runtime_libpq_version,
        "Greenplum runtime libpq version",
        1,
        INT64_MAX,
    )
    return GreenplumDriverEvidence(
        driver_name=driver_name,
        driver_version=driver_version,
        build_libpq_version=build_libpq_version,
        runtime_libpq_version=runtime_libpq_version,
    )


def _extract_product_version(full_version: str, product_marker: str) -> str:
    marker = f"({product_marker} "
    start = full_version.find(marker)
    if start < 0:
        raise UnsupportedGreenplumProfileError(
            "Connected server does not expose the declared product identity: "
            f"required_marker={product_marker!r}, full_version={full_version!r}"
        )
    version_start = start + len(marker)
    version_end = full_version.find(")", version_start)
    if version_end < 0:
        raise UnsupportedGreenplumProfileError(
            "Connected server product identity is unterminated: "
            f"required_marker={product_marker!r}, full_version={full_version!r}"
        )
    product_version = full_version[version_start:version_end]
    if not product_version:
        raise UnsupportedGreenplumProfileError(
            "Connected server product identity contains no product version: "
            f"required_marker={product_marker!r}, full_version={full_version!r}"
        )
    return product_version


def _connection_error_message(
    product: str,
    settings: PostgresConnectionSettings,
    attempts: int,
    sqlstate: str | None,
    detail: str,
) -> str:
    return (
        "Greenplum-family connection failed: "
        f"product={product!r}, host={settings.host!r}, port={settings.port}, "
        f"dbname={settings.dbname!r}, user={settings.user!r}, "
        f"sslmode={settings.sslmode.value!r}, attempts={attempts}, "
        f"sqlstate={sqlstate!r}, detail={detail!r}"
    )


def _handle_cleanup_error(
    primary_error: BaseException | None,
    sqlstate: str | None,
    detail: str,
    product: str,
) -> None:
    message = (
        "Greenplum-family rollback failed while closing the probe session: "
        f"product={product!r}, sqlstate={sqlstate!r}, detail={detail!r}"
    )
    if primary_error is None:
        raise GreenplumCloseError(message)
    primary_error.add_note(message)
    LOGGER.warning(
        "Greenplum-family rollback failed while preserving the primary error",
        extra={
            "operation": "close_greenplum_probe",
            "product": product,
            "sqlstate": sqlstate,
            "detail": detail,
        },
    )


def _require_bounded_result(
    rows: tuple[DatabaseRow, ...],
    max_rows: int,
    operation: str,
) -> None:
    if len(rows) > max_rows:
        raise GreenplumDataValidationError(
            "Greenplum-family probe query exceeded its result row bound: "
            f"operation={operation!r}, max_rows={max_rows}"
        )


def _validate_max_rows(max_rows: int) -> None:
    if type(max_rows) is not int or max_rows < 1:
        raise ValueError("Greenplum probe max_rows must be a positive integer")


def _require_single_row(rows: tuple[DatabaseRow, ...], label: str) -> DatabaseRow:
    if len(rows) != 1:
        raise GreenplumDataValidationError(
            f"{label} must return exactly one row: actual={len(rows)}"
        )
    return rows[0]


def _require_text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise GreenplumDataValidationError(f"{label} must be non-empty text")
    if "\x00" in value:
        raise GreenplumDataValidationError(f"{label} must not contain U+0000")
    if len(value.encode("utf-8")) > _MAX_PROFILE_TEXT_BYTES:
        raise GreenplumDataValidationError(f"{label} exceeds {_MAX_PROFILE_TEXT_BYTES} UTF-8 bytes")
    return value


def _require_boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise GreenplumDataValidationError(f"{label} must be boolean")
    return value


def _require_bounded_integer(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise GreenplumDataValidationError(
            f"{label} must be an integer in [{minimum}, {maximum}]: value={value!r}"
        )
    return value
