import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from threading import Lock
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
    GreenplumRelationRequest,
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
from forensic_data.greenplum_sql import (
    GreenplumCanonicalFingerprint,
    GreenplumCanonicalFingerprintPlan,
    GreenplumCanonicalFingerprintQuery,
    GreenplumCanonicalProbeRequest,
    build_greengage_fingerprint_query,
    build_original_greenplum_fingerprint_query,
    parse_greengage_fingerprint_plan,
    parse_greenplum_canonical_fingerprint,
    parse_original_greenplum_fingerprint_plan,
)
from forensic_data.postgres import (
    INT64_MAX,
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresRetryPolicy,
    ReadContextState,
)
from forensic_data.postgres_sql import PostgresLoweringError

LOGGER = logging.getLogger(__name__)
_PSYCOPG2_VERSION = version("psycopg2")
_PSYCOPG_VERSION = version("psycopg")
_MAX_PROFILE_TEXT_BYTES = 4096
_MAX_TOPOLOGY_ROWS = 2048
_MAX_EXPLAIN_ROWS = 2048
_MAX_CANONICAL_EXPLAIN_ROWS = 50_000
_MAX_CANONICAL_RELATIONS = 8
_UNDEFINED_OBJECT_SQLSTATE = "42704"

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
    "pg_catalog.current_setting('transaction_read_only') = 'on', "
    "pg_catalog.txid_current_snapshot()::text"
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
    "pg_catalog.current_setting('transaction_read_only') = 'on', "
    "pg_catalog.txid_current_snapshot()::text"
)

GREENGAGE_CANONICAL_PLANNING_SETTINGS_QUERY = (
    "SELECT pg_catalog.current_setting('optimizer'), "
    "pg_catalog.current_setting('gp_enable_multiphase_agg'), "
    "pg_catalog.current_setting('gp_eager_two_phase_agg')"
)

_SESSION_SETUP_QUERY = (
    "SELECT pg_catalog.set_config('search_path', 'pg_catalog', true), "
    "pg_catalog.set_config('TimeZone', 'UTC', true), "
    "pg_catalog.set_config('DateStyle', 'ISO, YMD', true), "
    "pg_catalog.set_config('statement_timeout', %s, true)"
)
_GREENGAGE_SESSION_SETUP_QUERY = (
    _SESSION_SETUP_QUERY + ", pg_catalog.set_config('row_security', 'off', true)"
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


class GreenplumContextClosedError(GreenplumConnectorError):
    """A Greenplum canonical read context cannot execute another read."""


class GreenplumContextLostError(GreenplumConnectorError):
    """A Greenplum canonical read context lost its transaction snapshot."""


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
    snapshot_locator: str


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


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumCanonicalRelationEvidence:
    relation: OriginalGreenplumRelationCatalog
    types: GreenplumTypeProbe
    query: GreenplumCanonicalFingerprintQuery
    plan: GreenplumCanonicalFingerprintPlan
    fingerprint: GreenplumCanonicalFingerprint


@final
@dataclass(frozen=True, slots=True)
class GreengageCanonicalRelationEvidence:
    relation: GreengageRelationCatalog
    types: GreenplumTypeProbe
    query: GreenplumCanonicalFingerprintQuery
    plan: GreenplumCanonicalFingerprintPlan
    fingerprint: GreenplumCanonicalFingerprint


@final
@dataclass(frozen=True, slots=True)
class GreenplumRelationLockEvidence:
    relation_oid: int
    schema_name: str
    relation_name: str
    lock_mode: str


@final
@dataclass(frozen=True, slots=True)
class GreenplumSessionSettingEvidence:
    name: str
    value: str


@final
@dataclass(frozen=True, slots=True)
class GreenplumCanonicalReadContextEvidence:
    context_id: UUID
    runtime_profile: GreenplumRuntimeProfile
    strategy: str
    snapshot_locator: str
    started_at: datetime
    backend_process_id: int
    allowed_concurrency: int
    planning_settings: tuple[GreenplumSessionSettingEvidence, ...]
    relation_locks: tuple[GreenplumRelationLockEvidence, ...]
    acquired_before_snapshot: bool
    limitations: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class _OriginalGreenplumPreparedCanonicalRelation:
    relation: OriginalGreenplumRelationCatalog
    types: GreenplumTypeProbe
    query: GreenplumCanonicalFingerprintQuery
    plan: GreenplumCanonicalFingerprintPlan


@final
@dataclass(frozen=True, slots=True)
class _GreengagePreparedCanonicalRelation:
    relation: GreengageRelationCatalog
    types: GreenplumTypeProbe
    query: GreenplumCanonicalFingerprintQuery
    plan: GreenplumCanonicalFingerprintPlan


@final
@dataclass(frozen=True, slots=True)
class _OriginalGreenplumCanonicalCandidate:
    relation: OriginalGreenplumRelationCatalog
    types: GreenplumTypeProbe


@final
@dataclass(frozen=True, slots=True)
class _GreengageCanonicalCandidate:
    relation: GreengageRelationCatalog
    types: GreenplumTypeProbe


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumCanonicalProbeEvidence:
    probe_id: UUID
    started_at: datetime
    driver: GreenplumDriverEvidence
    server: GreenplumServerProfile
    reader: GreenplumReaderIdentity
    topology: GreenplumTopology
    hash_capability: OriginalGreenplumHashCapability
    relations: tuple[OriginalGreenplumCanonicalRelationEvidence, ...]
    planning_settings: tuple[GreenplumSessionSettingEvidence, ...]
    required_extensions: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class GreengageCanonicalProbeEvidence:
    probe_id: UUID
    started_at: datetime
    driver: GreenplumDriverEvidence
    server: GreenplumServerProfile
    reader: GreenplumReaderIdentity
    topology: GreenplumTopology
    hash_capability: GreengageHashCapability
    relations: tuple[GreengageCanonicalRelationEvidence, ...]
    planning_settings: tuple[GreenplumSessionSettingEvidence, ...]
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

    def begin_canonical_snapshot(
        self,
        statement_timeout_milliseconds: int,
        lock_statement: str,
    ) -> None:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute("BEGIN ISOLATION LEVEL SERIALIZABLE READ ONLY")
                for statement in _canonical_setup_statements(statement_timeout_milliseconds):
                    cursor.execute(cast(LiteralString, statement))
                cursor.execute(cast(LiteralString, lock_statement))
        except psycopg2.Error as error:
            raise GreenplumConnectionError(
                "original Greenplum canonical snapshot setup failed: "
                "strategy='read_only_serializable', "
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

    def close(self) -> None:
        self.__exit__(None, None, None)

    def close_after_failure(self, error: BaseException) -> None:
        self.__exit__(type(error), error, error.__traceback__)

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
                    _GREENGAGE_SESSION_SETUP_QUERY,
                    (str(statement_timeout_milliseconds),),
                )
                cursor.fetchone()
        except psycopg.Error as error:
            raise GreenplumConnectionError(
                "Greengage read-only session setup failed: "
                f"sqlstate={error.sqlstate!r}, detail={str(error).strip()!r}"
            ) from None

    def begin_canonical_snapshot(
        self,
        statement_timeout_milliseconds: int,
        lock_statement: str,
    ) -> None:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
                for statement in _canonical_setup_statements(statement_timeout_milliseconds):
                    cursor.execute(cast(LiteralString, statement))
                cursor.execute("SET LOCAL row_security TO off")
                cursor.execute("SET LOCAL optimizer TO off")
                cursor.execute("SET LOCAL gp_enable_multiphase_agg TO on")
                cursor.execute("SET LOCAL gp_eager_two_phase_agg TO on")
                cursor.execute(cast(LiteralString, lock_statement))
        except psycopg.Error as error:
            if error.sqlstate == _UNDEFINED_OBJECT_SQLSTATE:
                raise UnsupportedGreenplumProfileError(
                    "Greengage canonical planning capability is unavailable: "
                    f"sqlstate={error.sqlstate!r}, detail={str(error).strip()!r}"
                ) from None
            raise GreenplumConnectionError(
                "Greengage canonical snapshot setup failed: "
                "strategy='read_only_repeatable_read', "
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

    def close(self) -> None:
        self.__exit__(None, None, None)

    def close_after_failure(self, error: BaseException) -> None:
        self.__exit__(type(error), error, error.__traceback__)

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


def probe_original_greenplum_canonical_fingerprints(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    requests: tuple[GreenplumCanonicalProbeRequest, ...],
) -> OriginalGreenplumCanonicalProbeEvidence:
    context = open_original_greenplum_canonical_read_context(
        settings,
        retry_policy,
        requests,
    )
    with context:
        relations = context.read_canonical_fingerprints()
        return OriginalGreenplumCanonicalProbeEvidence(
            probe_id=context.evidence.context_id,
            started_at=context.evidence.started_at,
            driver=context.driver,
            server=context.server,
            reader=context.reader,
            topology=context.topology,
            hash_capability=context.hash_capability,
            relations=relations,
            planning_settings=context.evidence.planning_settings,
            required_extensions=(),
        )


def probe_greengage_canonical_fingerprints(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    requests: tuple[GreenplumCanonicalProbeRequest, ...],
) -> GreengageCanonicalProbeEvidence:
    context = open_greengage_canonical_read_context(
        settings,
        retry_policy,
        requests,
    )
    with context:
        relations = context.read_canonical_fingerprints()
        return GreengageCanonicalProbeEvidence(
            probe_id=context.evidence.context_id,
            started_at=context.evidence.started_at,
            driver=context.driver,
            server=context.server,
            reader=context.reader,
            topology=context.topology,
            hash_capability=context.hash_capability,
            relations=relations,
            planning_settings=context.evidence.planning_settings,
            required_extensions=(),
        )


class OriginalGreenplumCanonicalReadContext:
    """One sealed original Greenplum read-only Serializable snapshot."""

    def __init__(
        self,
        session: _OriginalGreenplumSession,
        driver: GreenplumDriverEvidence,
        server: GreenplumServerProfile,
        reader: GreenplumReaderIdentity,
        topology: GreenplumTopology,
        hash_capability: OriginalGreenplumHashCapability,
        prepared_relations: tuple[_OriginalGreenplumPreparedCanonicalRelation, ...],
        evidence: GreenplumCanonicalReadContextEvidence,
    ) -> None:
        self._session = session
        self._driver = driver
        self._server = server
        self._reader = reader
        self._topology = topology
        self._hash_capability = hash_capability
        self._prepared_relations = prepared_relations
        self._evidence = evidence
        self._state = ReadContextState.ACTIVE
        self._query_lock = Lock()

    @property
    def driver(self) -> GreenplumDriverEvidence:
        return self._driver

    @property
    def server(self) -> GreenplumServerProfile:
        return self._server

    @property
    def reader(self) -> GreenplumReaderIdentity:
        return self._reader

    @property
    def topology(self) -> GreenplumTopology:
        return self._topology

    @property
    def hash_capability(self) -> OriginalGreenplumHashCapability:
        return self._hash_capability

    @property
    def evidence(self) -> GreenplumCanonicalReadContextEvidence:
        return self._evidence

    @property
    def state(self) -> ReadContextState:
        return self._state

    def read_canonical_fingerprints(
        self,
    ) -> tuple[OriginalGreenplumCanonicalRelationEvidence, ...]:
        with self._query_lock:
            self._require_active()
            try:
                return tuple(
                    _read_original_greenplum_canonical_relation(self._session, prepared)
                    for prepared in self._prepared_relations
                )
            except GreenplumCatalogMetadataError as error:
                mapped = GreenplumMetadataError(str(error))
                self._lose(mapped)
                raise mapped from None
            except GreenplumCatalogDataError as error:
                mapped = GreenplumDataValidationError(str(error))
                self._lose(mapped)
                raise mapped from None
            except GreenplumConnectorError as error:
                self._lose(error)
                raise

    def close(self) -> None:
        self._close(None)

    def __enter__(self) -> Self:
        self._require_active()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._close(exception)

    def _close(self, primary_error: BaseException | None) -> None:
        with self._query_lock:
            if self._state is ReadContextState.CLOSED:
                return
            previous_state = self._state
            self._state = ReadContextState.CLOSED
            if previous_state is not ReadContextState.ACTIVE:
                return
            if primary_error is None:
                self._session.close()
            else:
                self._session.close_after_failure(primary_error)

    def _lose(self, error: BaseException) -> None:
        self._state = ReadContextState.LOST
        self._session.close_after_failure(error)

    def _require_active(self) -> None:
        if self._state is ReadContextState.CLOSED:
            raise GreenplumContextClosedError(
                "original Greenplum canonical read context is already closed"
            )
        if self._state is ReadContextState.LOST:
            raise GreenplumContextLostError(
                "original Greenplum canonical transaction snapshot was lost and cannot be reused"
            )


class GreengageCanonicalReadContext:
    """One sealed Greengage read-only Repeatable Read snapshot."""

    def __init__(
        self,
        session: _GreengageSession,
        driver: GreenplumDriverEvidence,
        server: GreenplumServerProfile,
        reader: GreenplumReaderIdentity,
        topology: GreenplumTopology,
        hash_capability: GreengageHashCapability,
        prepared_relations: tuple[_GreengagePreparedCanonicalRelation, ...],
        evidence: GreenplumCanonicalReadContextEvidence,
    ) -> None:
        self._session = session
        self._driver = driver
        self._server = server
        self._reader = reader
        self._topology = topology
        self._hash_capability = hash_capability
        self._prepared_relations = prepared_relations
        self._evidence = evidence
        self._state = ReadContextState.ACTIVE
        self._query_lock = Lock()

    @property
    def driver(self) -> GreenplumDriverEvidence:
        return self._driver

    @property
    def server(self) -> GreenplumServerProfile:
        return self._server

    @property
    def reader(self) -> GreenplumReaderIdentity:
        return self._reader

    @property
    def topology(self) -> GreenplumTopology:
        return self._topology

    @property
    def hash_capability(self) -> GreengageHashCapability:
        return self._hash_capability

    @property
    def evidence(self) -> GreenplumCanonicalReadContextEvidence:
        return self._evidence

    @property
    def state(self) -> ReadContextState:
        return self._state

    def read_canonical_fingerprints(
        self,
    ) -> tuple[GreengageCanonicalRelationEvidence, ...]:
        with self._query_lock:
            self._require_active()
            try:
                return tuple(
                    _read_greengage_canonical_relation(self._session, prepared)
                    for prepared in self._prepared_relations
                )
            except GreenplumCatalogMetadataError as error:
                mapped = GreenplumMetadataError(str(error))
                self._lose(mapped)
                raise mapped from None
            except GreenplumCatalogDataError as error:
                mapped = GreenplumDataValidationError(str(error))
                self._lose(mapped)
                raise mapped from None
            except GreenplumConnectorError as error:
                self._lose(error)
                raise

    def close(self) -> None:
        self._close(None)

    def __enter__(self) -> Self:
        self._require_active()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._close(exception)

    def _close(self, primary_error: BaseException | None) -> None:
        with self._query_lock:
            if self._state is ReadContextState.CLOSED:
                return
            previous_state = self._state
            self._state = ReadContextState.CLOSED
            if previous_state is not ReadContextState.ACTIVE:
                return
            if primary_error is None:
                self._session.close()
            else:
                self._session.close_after_failure(primary_error)

    def _lose(self, error: BaseException) -> None:
        self._state = ReadContextState.LOST
        self._session.close_after_failure(error)

    def _require_active(self) -> None:
        if self._state is ReadContextState.CLOSED:
            raise GreenplumContextClosedError("Greengage canonical read context is already closed")
        if self._state is ReadContextState.LOST:
            raise GreenplumContextLostError(
                "Greengage canonical transaction snapshot was lost and cannot be reused"
            )


def open_original_greenplum_canonical_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    requests: tuple[GreenplumCanonicalProbeRequest, ...],
) -> OriginalGreenplumCanonicalReadContext:
    _validate_canonical_requests(requests)
    candidates = _discover_original_greenplum_canonical_candidates(
        settings,
        retry_policy,
        requests,
    )
    started_at = datetime.now(UTC)
    session = _connect_original_greenplum(settings, retry_policy)
    try:
        session.begin_canonical_snapshot(
            settings.statement_timeout_milliseconds,
            _canonical_lock_statement(requests),
        )
        driver = _original_greenplum_driver_evidence()
        server = _probe_original_greenplum_profile(session, settings)
        _validate_canonical_snapshot_profile(
            server,
            "serializable",
            "read_only_serializable",
        )
        topology = _probe_topology(session)
        reader = _probe_reader_identity(session, settings)
        hash_capability_rows = session.fetch_rows(
            ORIGINAL_GREENPLUM_HASH_CAPABILITY_QUERY,
            (),
            2,
            "original_greenplum_canonical_hash_capability",
        )
        hash_capability = parse_original_greenplum_hash_capability(hash_capability_rows)
        bound_relations = tuple(
            _bind_original_greenplum_canonical_relation(
                session,
                request,
                candidate,
                server,
            )
            for request, candidate in zip(requests, candidates, strict=True)
        )
        relation_locks = _probe_relation_locks(
            session,
            tuple(bound.relation for bound in bound_relations),
            "original_greenplum_canonical_relation_locks",
        )
        prepared_relations = tuple(
            _prepare_original_greenplum_canonical_relation(
                session,
                request,
                bound,
                server,
                topology,
                hash_capability.function_oid,
            )
            for request, bound in zip(requests, bound_relations, strict=True)
        )
        _require_relation_locks_unchanged(
            relation_locks,
            _probe_relation_locks(
                session,
                tuple(bound.relation for bound in bound_relations),
                "original_greenplum_canonical_retained_relation_locks",
            ),
            server.runtime_profile,
        )
        evidence = GreenplumCanonicalReadContextEvidence(
            context_id=uuid4(),
            runtime_profile=server.runtime_profile,
            strategy="read_only_serializable",
            snapshot_locator=server.snapshot_locator,
            started_at=started_at,
            backend_process_id=server.backend_process_id,
            allowed_concurrency=1,
            planning_settings=(),
            relation_locks=relation_locks,
            acquired_before_snapshot=True,
            limitations=(
                "Original Greenplum rejects Repeatable Read; this profile uses its native "
                "read-only Serializable transaction mode.",
                "The legacy Serializable label is not evidence of modern PostgreSQL SSI semantics.",
                "Append-optimized DELETE is unavailable at Serializable isolation; fixture "
                "mutation and cleanup use a separate Read Committed writer.",
            ),
        )
    except (GreenplumCatalogMetadataError, PostgresLoweringError) as error:
        mapped = GreenplumMetadataError(str(error))
        session.close_after_failure(mapped)
        raise mapped from None
    except GreenplumCatalogDataError as error:
        mapped = GreenplumDataValidationError(str(error))
        session.close_after_failure(mapped)
        raise mapped from None
    except BaseException as error:
        session.close_after_failure(error)
        raise
    return OriginalGreenplumCanonicalReadContext(
        session,
        driver,
        server,
        reader,
        topology,
        hash_capability,
        prepared_relations,
        evidence,
    )


def open_greengage_canonical_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    requests: tuple[GreenplumCanonicalProbeRequest, ...],
) -> GreengageCanonicalReadContext:
    _validate_canonical_requests(requests)
    candidates = _discover_greengage_canonical_candidates(
        settings,
        retry_policy,
        requests,
    )
    started_at = datetime.now(UTC)
    session = _connect_greengage(settings, retry_policy)
    try:
        session.begin_canonical_snapshot(
            settings.statement_timeout_milliseconds,
            _canonical_lock_statement(requests),
        )
        planning_settings = _probe_greengage_canonical_planning_settings(session)
        driver = _greengage_driver_evidence()
        server = _probe_greengage_profile(session, settings)
        _validate_canonical_snapshot_profile(
            server,
            "repeatable read",
            "read_only_repeatable_read",
        )
        topology = _probe_topology(session)
        reader = _probe_reader_identity(session, settings)
        hash_capability_rows = session.fetch_rows(
            GREENGAGE_HASH_CAPABILITY_QUERY,
            (),
            2,
            "greengage_canonical_hash_capability",
        )
        hash_capability = parse_greengage_hash_capability(hash_capability_rows)
        bound_relations = tuple(
            _bind_greengage_canonical_relation(
                session,
                request,
                candidate,
                server,
            )
            for request, candidate in zip(requests, candidates, strict=True)
        )
        relation_locks = _probe_relation_locks(
            session,
            tuple(bound.relation for bound in bound_relations),
            "greengage_canonical_relation_locks",
        )
        prepared_relations = tuple(
            _prepare_greengage_canonical_relation(
                session,
                request,
                bound,
                server,
                topology,
            )
            for request, bound in zip(requests, bound_relations, strict=True)
        )
        _require_relation_locks_unchanged(
            relation_locks,
            _probe_relation_locks(
                session,
                tuple(bound.relation for bound in bound_relations),
                "greengage_canonical_retained_relation_locks",
            ),
            server.runtime_profile,
        )
        evidence = GreenplumCanonicalReadContextEvidence(
            context_id=uuid4(),
            runtime_profile=server.runtime_profile,
            strategy="read_only_repeatable_read",
            snapshot_locator=server.snapshot_locator,
            started_at=started_at,
            backend_process_id=server.backend_process_id,
            allowed_concurrency=1,
            planning_settings=planning_settings,
            relation_locks=relation_locks,
            acquired_before_snapshot=True,
            limitations=(
                "Append-optimized DELETE is unavailable at Repeatable Read isolation; fixture "
                "mutation and cleanup use a separate Read Committed writer.",
            ),
        )
    except (GreenplumCatalogMetadataError, PostgresLoweringError) as error:
        mapped = GreenplumMetadataError(str(error))
        session.close_after_failure(mapped)
        raise mapped from None
    except GreenplumCatalogDataError as error:
        mapped = GreenplumDataValidationError(str(error))
        session.close_after_failure(mapped)
        raise mapped from None
    except BaseException as error:
        session.close_after_failure(error)
        raise
    return GreengageCanonicalReadContext(
        session,
        driver,
        server,
        reader,
        topology,
        hash_capability,
        prepared_relations,
        evidence,
    )


def _discover_original_greenplum_canonical_candidates(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    requests: tuple[GreenplumCanonicalProbeRequest, ...],
) -> tuple[_OriginalGreenplumCanonicalCandidate, ...]:
    session = _connect_original_greenplum(settings, retry_policy)
    with session:
        try:
            session.begin_read_only(settings.statement_timeout_milliseconds)
            server = _probe_original_greenplum_profile(session, settings)
            candidates: list[_OriginalGreenplumCanonicalCandidate] = []
            for request in requests:
                _validate_request_identifier_lengths(
                    request,
                    server.max_identifier_utf8_bytes,
                )
                relation = _probe_original_greenplum_relation(session, request)
                candidates.append(
                    _OriginalGreenplumCanonicalCandidate(
                        relation=relation,
                        types=_probe_types(session, relation.relation_oid, request),
                    )
                )
        except GreenplumCatalogMetadataError as error:
            raise GreenplumMetadataError(str(error)) from None
        except GreenplumCatalogDataError as error:
            raise GreenplumDataValidationError(str(error)) from None
    return tuple(candidates)


def _discover_greengage_canonical_candidates(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    requests: tuple[GreenplumCanonicalProbeRequest, ...],
) -> tuple[_GreengageCanonicalCandidate, ...]:
    session = _connect_greengage(settings, retry_policy)
    with session:
        try:
            session.begin_read_only(settings.statement_timeout_milliseconds)
            server = _probe_greengage_profile(session, settings)
            candidates: list[_GreengageCanonicalCandidate] = []
            for request in requests:
                _validate_request_identifier_lengths(
                    request,
                    server.max_identifier_utf8_bytes,
                )
                relation = _probe_greengage_relation(session, request)
                candidates.append(
                    _GreengageCanonicalCandidate(
                        relation=relation,
                        types=_probe_types(session, relation.relation_oid, request),
                    )
                )
        except GreenplumCatalogMetadataError as error:
            raise GreenplumMetadataError(str(error)) from None
        except GreenplumCatalogDataError as error:
            raise GreenplumDataValidationError(str(error)) from None
    return tuple(candidates)


def _bind_original_greenplum_canonical_relation(
    session: _GreenplumProbeSession,
    request: GreenplumCanonicalProbeRequest,
    candidate: _OriginalGreenplumCanonicalCandidate,
    server: GreenplumServerProfile,
) -> _OriginalGreenplumCanonicalCandidate:
    _validate_request_identifier_lengths(request, server.max_identifier_utf8_bytes)
    relation = _probe_original_greenplum_relation(session, request)
    type_probe = _probe_types(session, relation.relation_oid, request)
    _require_original_greenplum_candidate(candidate, relation, type_probe, request)
    return _OriginalGreenplumCanonicalCandidate(relation=relation, types=type_probe)


def _prepare_original_greenplum_canonical_relation(
    session: _GreenplumProbeSession,
    request: GreenplumCanonicalProbeRequest,
    bound: _OriginalGreenplumCanonicalCandidate,
    server: GreenplumServerProfile,
    topology: GreenplumTopology,
    hash_function_oid: int,
) -> _OriginalGreenplumPreparedCanonicalRelation:
    relation = bound.relation
    type_probe = bound.types
    query = build_original_greenplum_fingerprint_query(
        request,
        relation.relation_row_type_oid,
        type_probe.bindings,
        server.max_identifier_utf8_bytes,
        topology.primary_content_ids,
    )
    plan_rows = session.fetch_rows(
        explain_query(query.statement),
        query.parameters,
        _MAX_CANONICAL_EXPLAIN_ROWS,
        "original_greenplum_canonical_fingerprint_plan",
    )
    plan = parse_original_greenplum_fingerprint_plan(
        plan_rows,
        request,
        len(topology.primary_content_ids),
        hash_function_oid,
        relation.storage_kind,
    )
    return _OriginalGreenplumPreparedCanonicalRelation(
        relation=relation,
        types=type_probe,
        query=query,
        plan=plan,
    )


def _bind_greengage_canonical_relation(
    session: _GreenplumProbeSession,
    request: GreenplumCanonicalProbeRequest,
    candidate: _GreengageCanonicalCandidate,
    server: GreenplumServerProfile,
) -> _GreengageCanonicalCandidate:
    _validate_request_identifier_lengths(request, server.max_identifier_utf8_bytes)
    relation = _probe_greengage_relation(session, request)
    type_probe = _probe_types(session, relation.relation_oid, request)
    _require_greengage_candidate(candidate, relation, type_probe, request)
    return _GreengageCanonicalCandidate(relation=relation, types=type_probe)


def _prepare_greengage_canonical_relation(
    session: _GreenplumProbeSession,
    request: GreenplumCanonicalProbeRequest,
    bound: _GreengageCanonicalCandidate,
    server: GreenplumServerProfile,
    topology: GreenplumTopology,
) -> _GreengagePreparedCanonicalRelation:
    relation = bound.relation
    type_probe = bound.types
    query = build_greengage_fingerprint_query(
        request,
        relation.relation_row_type_oid,
        type_probe.bindings,
        server.max_identifier_utf8_bytes,
        topology.primary_content_ids,
    )
    plan_rows = session.fetch_rows(
        explain_query(query.statement),
        query.parameters,
        _MAX_CANONICAL_EXPLAIN_ROWS,
        "greengage_canonical_fingerprint_plan",
    )
    plan = parse_greengage_fingerprint_plan(
        plan_rows,
        request,
        len(topology.primary_content_ids),
        relation.storage_kind,
    )
    return _GreengagePreparedCanonicalRelation(
        relation=relation,
        types=type_probe,
        query=query,
        plan=plan,
    )


def _read_original_greenplum_canonical_relation(
    session: _GreenplumProbeSession,
    prepared: _OriginalGreenplumPreparedCanonicalRelation,
) -> OriginalGreenplumCanonicalRelationEvidence:
    rows = session.fetch_rows(
        prepared.query.statement,
        prepared.query.parameters,
        2,
        "original_greenplum_canonical_fingerprint",
    )
    return OriginalGreenplumCanonicalRelationEvidence(
        relation=prepared.relation,
        types=prepared.types,
        query=prepared.query,
        plan=prepared.plan,
        fingerprint=parse_greenplum_canonical_fingerprint(rows, prepared.query),
    )


def _read_greengage_canonical_relation(
    session: _GreenplumProbeSession,
    prepared: _GreengagePreparedCanonicalRelation,
) -> GreengageCanonicalRelationEvidence:
    rows = session.fetch_rows(
        prepared.query.statement,
        prepared.query.parameters,
        2,
        "greengage_canonical_fingerprint",
    )
    return GreengageCanonicalRelationEvidence(
        relation=prepared.relation,
        types=prepared.types,
        query=prepared.query,
        plan=prepared.plan,
        fingerprint=parse_greenplum_canonical_fingerprint(rows, prepared.query),
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
    if len(row) != 15:
        raise GreenplumDataValidationError(
            f"original Greenplum profile must return exactly fifteen fields: actual={len(row)}"
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
    if len(row) != 16:
        raise GreenplumDataValidationError(
            f"Greengage profile must return exactly sixteen fields: actual={len(row)}"
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


def _probe_greengage_canonical_planning_settings(
    session: _GreenplumProbeSession,
) -> tuple[GreenplumSessionSettingEvidence, ...]:
    rows = session.fetch_rows(
        GREENGAGE_CANONICAL_PLANNING_SETTINGS_QUERY,
        (),
        2,
        "greengage_canonical_planning_settings",
    )
    row = _require_single_row(rows, "Greengage canonical planning settings")
    if len(row) != 3:
        raise GreenplumDataValidationError(
            "Greengage canonical planning settings must return exactly three fields: "
            f"actual={len(row)}"
        )
    settings = (
        GreenplumSessionSettingEvidence(
            name="optimizer",
            value=_require_text(row[0], "Greengage optimizer setting"),
        ),
        GreenplumSessionSettingEvidence(
            name="gp_enable_multiphase_agg",
            value=_require_text(row[1], "Greengage gp_enable_multiphase_agg setting"),
        ),
        GreenplumSessionSettingEvidence(
            name="gp_eager_two_phase_agg",
            value=_require_text(row[2], "Greengage gp_eager_two_phase_agg setting"),
        ),
    )
    required = (
        GreenplumSessionSettingEvidence(name="optimizer", value="off"),
        GreenplumSessionSettingEvidence(name="gp_enable_multiphase_agg", value="on"),
        GreenplumSessionSettingEvidence(name="gp_eager_two_phase_agg", value="on"),
    )
    if settings != required:
        actual = tuple((setting.name, setting.value) for setting in settings)
        raise UnsupportedGreenplumProfileError(
            "Greengage canonical planning settings differ from the required distributed "
            f"aggregation profile: actual={actual!r}, required=("
            "('optimizer', 'off'), "
            "('gp_enable_multiphase_agg', 'on'), "
            "('gp_eager_two_phase_agg', 'on'))"
        )
    return settings


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
        snapshot_locator=_require_snapshot_locator(
            row[compatibility_index + 13],
            "Greenplum transaction snapshot locator",
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


def _validate_canonical_snapshot_profile(
    profile: GreenplumServerProfile,
    required_isolation: str,
    strategy: str,
) -> None:
    if profile.transaction_isolation != required_isolation:
        raise UnsupportedGreenplumProfileError(
            "Greenplum-family canonical snapshot isolation differs from its declared "
            "strategy: "
            f"runtime_profile={profile.runtime_profile.value!r}, strategy={strategy!r}, "
            f"actual={profile.transaction_isolation!r}, required={required_isolation!r}"
        )
    if not profile.transaction_read_only:
        raise UnsupportedGreenplumProfileError(
            "Greenplum-family canonical snapshot must be read-only: "
            f"runtime_profile={profile.runtime_profile.value!r}, strategy={strategy!r}"
        )


def _validate_request_identifier_lengths(
    request: GreenplumRelationRequest,
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
    request: GreenplumRelationRequest,
) -> GreenplumTypeProbe:
    statement, parameters = greenplum_type_catalog_query(relation_oid, request)
    rows = session.fetch_rows(
        statement,
        parameters,
        len(request.columns),
        "greenplum_type_catalog",
    )
    return parse_greenplum_type_probe(rows, request)


def _validate_canonical_requests(
    requests: tuple[GreenplumCanonicalProbeRequest, ...],
) -> None:
    if type(requests) is not tuple or not requests:
        raise ValueError("Greenplum canonical probe requires an immutable relation request tuple")
    if len(requests) > _MAX_CANONICAL_RELATIONS:
        raise ValueError(
            "Greenplum canonical probe relation count exceeds the supported maximum: "
            f"actual={len(requests)}, maximum={_MAX_CANONICAL_RELATIONS}"
        )
    identities: list[tuple[str, str]] = []
    for index, request in enumerate(requests):
        if type(request) is not GreenplumCanonicalProbeRequest:
            raise TypeError(
                "Greenplum canonical relation request must be a "
                f"GreenplumCanonicalProbeRequest: index={index}, "
                f"type={type(request).__name__}"
            )
        identities.append((request.schema_name, request.relation_name))
    if len(set(identities)) != len(identities):
        raise ValueError("Greenplum canonical relation requests must be unique")


def _canonical_setup_statements(
    statement_timeout_milliseconds: int,
) -> tuple[str, ...]:
    if type(statement_timeout_milliseconds) is not int or statement_timeout_milliseconds < 1:
        raise ValueError("Greenplum statement timeout must be a positive integer")
    return (
        "SET LOCAL search_path TO pg_catalog",
        "SET LOCAL TimeZone TO 'UTC'",
        "SET LOCAL DateStyle TO 'ISO, YMD'",
        f"SET LOCAL statement_timeout TO '{statement_timeout_milliseconds}ms'",
    )


def _canonical_lock_statement(
    requests: tuple[GreenplumCanonicalProbeRequest, ...],
) -> str:
    ordered_relations = tuple(
        sorted(
            (
                (_quote_identifier(request.schema_name), _quote_identifier(request.relation_name))
                for request in requests
            ),
        )
    )
    relation_list = ", ".join(
        f"{schema_name}.{relation_name}" for schema_name, relation_name in ordered_relations
    )
    return f"LOCK TABLE {relation_list} IN ACCESS SHARE MODE"


def _quote_identifier(identifier: str) -> str:
    if type(identifier) is not str or not identifier or "\x00" in identifier:
        raise ValueError("Greenplum SQL identifier must be non-empty text without U+0000")
    return '"' + identifier.replace('"', '""') + '"'


def _probe_original_greenplum_relation(
    session: _GreenplumProbeSession,
    request: GreenplumCanonicalProbeRequest,
) -> OriginalGreenplumRelationCatalog:
    rows = session.fetch_rows(
        ORIGINAL_GREENPLUM_RELATION_QUERY,
        (request.schema_name, request.relation_name),
        2,
        "original_greenplum_canonical_relation_catalog",
    )
    return parse_original_greenplum_relation_catalog(rows, request)


def _probe_greengage_relation(
    session: _GreenplumProbeSession,
    request: GreenplumCanonicalProbeRequest,
) -> GreengageRelationCatalog:
    rows = session.fetch_rows(
        GREENGAGE_RELATION_QUERY,
        (request.schema_name, request.relation_name),
        2,
        "greengage_canonical_relation_catalog",
    )
    relation = parse_greengage_relation_catalog(rows, request)
    if relation.row_security_enabled or relation.row_security_forced:
        raise GreenplumCatalogMetadataError(
            "Greengage canonical relation enables row-level security, which is unsupported: "
            f"relation={relation.schema_name!r}.{relation.relation_name!r}, "
            f"row_security_enabled={relation.row_security_enabled}, "
            f"row_security_forced={relation.row_security_forced}"
        )
    return relation


def _require_original_greenplum_candidate(
    candidate: _OriginalGreenplumCanonicalCandidate,
    relation: OriginalGreenplumRelationCatalog,
    type_probe: GreenplumTypeProbe,
    request: GreenplumCanonicalProbeRequest,
) -> None:
    if candidate.relation != relation or candidate.types != type_probe:
        raise GreenplumMetadataError(
            "original Greenplum relation identity or type metadata changed between discovery "
            "and protected snapshot acquisition: "
            f"relation={request.schema_name!r}.{request.relation_name!r}"
        )


def _require_greengage_candidate(
    candidate: _GreengageCanonicalCandidate,
    relation: GreengageRelationCatalog,
    type_probe: GreenplumTypeProbe,
    request: GreenplumCanonicalProbeRequest,
) -> None:
    if candidate.relation != relation or candidate.types != type_probe:
        raise GreenplumMetadataError(
            "Greengage relation identity or type metadata changed between discovery and "
            "protected snapshot acquisition: "
            f"relation={request.schema_name!r}.{request.relation_name!r}"
        )


def _probe_relation_locks(
    session: _GreenplumProbeSession,
    relations: tuple[OriginalGreenplumRelationCatalog | GreengageRelationCatalog, ...],
    operation: str,
) -> tuple[GreenplumRelationLockEvidence, ...]:
    expected_by_oid = {
        relation.relation_oid: (relation.schema_name, relation.relation_name)
        for relation in relations
    }
    if len(expected_by_oid) != len(relations):
        raise GreenplumMetadataError(
            "Greenplum canonical relation closure contains duplicate relation OIDs"
        )
    placeholders = ", ".join("%s::oid" for _ in relations)
    statement = (
        "SELECT relation::bigint, mode::text, granted "
        "FROM pg_catalog.pg_locks "
        "WHERE pid = pg_catalog.pg_backend_pid() AND locktype = 'relation' "
        "AND mode = 'AccessShareLock' AND granted "
        f"AND relation IN ({placeholders}) ORDER BY relation"
    )
    rows = session.fetch_rows(
        statement,
        tuple(expected_by_oid),
        len(relations),
        operation,
    )
    locks: list[GreenplumRelationLockEvidence] = []
    observed_oids: list[int] = []
    for index, row in enumerate(rows):
        if len(row) != 3:
            raise GreenplumDataValidationError(
                "Greenplum relation-lock row must return exactly three fields: "
                f"row_index={index}, actual={len(row)}"
            )
        relation_oid = _require_bounded_integer(
            row[0],
            f"Greenplum locked relation OID at row {index}",
            1,
            INT64_MAX,
        )
        identity = expected_by_oid.get(relation_oid)
        if identity is None:
            raise GreenplumDataValidationError(
                "Greenplum relation-lock query returned an unexpected relation OID: "
                f"relation_oid={relation_oid}"
            )
        mode = _require_text(row[1], f"Greenplum relation lock mode at row {index}")
        granted = _require_boolean(row[2], f"Greenplum relation lock grant at row {index}")
        if mode != "AccessShareLock" or not granted:
            raise GreenplumMetadataError(
                "Greenplum canonical relation does not hold its required granted lock: "
                f"relation_oid={relation_oid}, mode={mode!r}, granted={granted}"
            )
        observed_oids.append(relation_oid)
        locks.append(
            GreenplumRelationLockEvidence(
                relation_oid=relation_oid,
                schema_name=identity[0],
                relation_name=identity[1],
                lock_mode=mode,
            )
        )
    if len(observed_oids) != len(expected_by_oid) or set(observed_oids) != set(expected_by_oid):
        raise GreenplumMetadataError(
            "Greenplum canonical transaction does not hold the complete relation lock "
            "closure: "
            f"expected_oids={tuple(sorted(expected_by_oid))!r}, "
            f"observed_oids={tuple(sorted(observed_oids))!r}"
        )
    return tuple(sorted(locks, key=lambda lock: (lock.schema_name, lock.relation_name)))


def _require_relation_locks_unchanged(
    acquired: tuple[GreenplumRelationLockEvidence, ...],
    retained: tuple[GreenplumRelationLockEvidence, ...],
    runtime_profile: GreenplumRuntimeProfile,
) -> None:
    if acquired != retained:
        raise GreenplumMetadataError(
            "Greenplum canonical relation lock closure changed during plan preparation: "
            f"runtime_profile={runtime_profile.value!r}, acquired={acquired!r}, "
            f"retained={retained!r}"
        )


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


def _require_snapshot_locator(value: object, label: str) -> str:
    locator = _require_text(value, label)
    if not locator.isascii():
        raise GreenplumDataValidationError(f"{label} must be ASCII text")
    parts = locator.split(":")
    if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
        raise GreenplumDataValidationError(
            f"{label} must use canonical xmin:xmax:xip-list syntax: value={locator!r}"
        )
    active_ids = () if not parts[2] else tuple(parts[2].split(","))
    if any(not transaction_id.isdigit() for transaction_id in active_ids):
        raise GreenplumDataValidationError(
            f"{label} contains a non-decimal active transaction ID: value={locator!r}"
        )
    return locator


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
