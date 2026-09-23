# pyright: reportPrivateUsage=false

import logging
import time
from dataclasses import replace
from datetime import UTC, datetime
from importlib.metadata import version
from types import TracebackType
from typing import LiteralString, NoReturn, Self, cast

import psycopg
import psycopg2
from psycopg import sql
from psycopg2.extensions import TRANSACTION_STATUS_INTRANS
from psycopg2.extensions import (
    Column as Psycopg2Column,
)
from psycopg2.extensions import (
    connection as Psycopg2Connection,
)
from psycopg2.extensions import (
    cursor as Psycopg2Cursor,
)

from forensic_data.canonical import CanonicalSchema
from forensic_data.contracts.model import RelationScope
from forensic_data.postgres import (
    INT64_MAX,
    UINT32_MAX,
    DatabaseRow,
    PostgresAcquisitionRaceError,
    PostgresConnectionError,
    PostgresConnectionSettings,
    PostgresDataValidationError,
    PostgresInheritanceDetachState,
    PostgresMetadataError,
    PostgresProtectedReadContext,
    PostgresProtectedReadContextEvidence,
    PostgresProtectedRelationInspection,
    PostgresReadContext,
    PostgresRelationAcquisition,
    PostgresRelationKind,
    PostgresRelationPersistence,
    PostgresRetryPolicy,
    PostgresServerProfile,
    PostgresSourceBudgetAttempt,
    PostgresSourceDirection,
    UnsupportedPostgresProfileError,
    _configure_protected_lock_timeouts,
    _configure_protected_snapshot_invariants,
    _configure_protected_statement_timeout,
    _database_row_bytes,
    _discover_physical_relation_candidate,
    _execute_pretransaction_candidate_bounded,
    _execute_setup_bounded,
    _execute_source_command,
    _frozen_candidate_from_rows,
    _lock_candidate_relation,
    _PostgresRelationCandidate,
    _PostgresRelationMemberCandidate,
    _profile_and_evidence,
    _protected_acquisition_database_error_message,
    _ProtectedAcquisitionReceipt,
    _require_boolean,
    _require_bounded_integer,
    _require_text,
    _seal_protected_candidate,
    _unique_lock_candidates,
    _validate_and_order_acquisitions,
    _validate_protected_lock_timeout,
)
from forensic_data.postgres_sql import (
    PostgresIntegerRangeRequest,
    PostgresQuery,
    PostgresQueryRelation,
    PostgresScopePredicate,
    build_postgres_legacy_union_fingerprint_query,
    build_postgres_legacy_union_integer_key_summary_query,
    build_postgres_legacy_union_integer_range_fingerprint_query,
    build_postgres_legacy_union_row_envelope_query,
)

LOGGER = logging.getLogger(__name__)
_POSTGRES_9_6_VERSION_NUMBER = 90624
_PGCRYPTO_EXTENSION_VERSION = "1.3"
_PGCRYPTO_SCHEMA = "dfe_ext"
_SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
_PSYCOPG2_VERSION = version("psycopg2")

type LegacyStatement = LiteralString | sql.SQL | sql.Composed


class _LegacyCursor:
    def __init__(
        self,
        connection: "_LegacyConnection",
        cursor: Psycopg2Cursor,
        name: str | None,
    ) -> None:
        self._connection = connection
        self._cursor = cursor
        self._name = name
        self._description: tuple[Psycopg2Column, ...] | None = None
        self._portal_declared = False
        self._closed = False

    @property
    def description(self) -> tuple[Psycopg2Column, ...] | None:
        description = self._cursor.description
        if description is not None:
            return description
        if self._description is None and self._name is not None:
            self._description = self._probe_named_cursor_description()
        return self._description

    def execute(
        self,
        statement: LegacyStatement,
        parameters: tuple[object, ...],
    ) -> None:
        self._description = None
        try:
            statement_text = _legacy_statement_text(statement)
            if self._name is None:
                self._cursor.execute(statement_text, parameters)
            else:
                portal_name = _quoted_legacy_portal_name(self._name)
                self._cursor.execute(
                    f"DECLARE {portal_name} NO SCROLL CURSOR FOR {statement_text}",
                    parameters,
                )
                self._portal_declared = True
        except psycopg2.Error as error:
            _raise_translated_database_error(error)

    def fetchmany(self, size: int) -> list[DatabaseRow]:
        try:
            if self._name is None:
                rows = self._cursor.fetchmany(size)
            else:
                if type(size) is not int or size < 1:
                    raise ValueError("PostgreSQL 9.6 portal fetch size must be positive")
                portal_name = _quoted_legacy_portal_name(self._name)
                charge = self._connection.source_budget.dispatch_query(
                    self._connection.direction,
                    0,
                )
                self._cursor.execute(f"FETCH FORWARD {size} FROM {portal_name}")
                charge.require_fetch_deadline()
                rows = self._cursor.fetchall()
            return [cast(DatabaseRow, row) for row in rows]
        except psycopg2.Error as error:
            _raise_translated_database_error(error)

    def fetchall(self) -> list[DatabaseRow]:
        try:
            if self._name is None:
                rows = self._cursor.fetchall()
            else:
                portal_name = _quoted_legacy_portal_name(self._name)
                charge = self._connection.source_budget.dispatch_query(
                    self._connection.direction,
                    0,
                )
                self._cursor.execute(f"FETCH FORWARD ALL FROM {portal_name}")
                charge.require_fetch_deadline()
                rows = self._cursor.fetchall()
            return [cast(DatabaseRow, row) for row in rows]
        except psycopg2.Error as error:
            _raise_translated_database_error(error)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        database_error: psycopg2.Error | None = None
        try:
            if (
                self._name is not None
                and self._portal_declared
                and self._connection.raw_connection.get_transaction_status()
                == TRANSACTION_STATUS_INTRANS
            ):
                portal_name = _quoted_legacy_portal_name(self._name)
                self._cursor.execute(f"CLOSE {portal_name}")
                self._portal_declared = False
        except psycopg2.Error as error:
            database_error = error
        try:
            self._cursor.close()
        except psycopg2.Error as error:
            if database_error is None:
                database_error = error
        if database_error is not None:
            _raise_translated_database_error(database_error)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exception is None:
            self.close()
            return
        try:
            self.close()
        except psycopg.Error as cleanup_error:
            exception.add_note(
                "PostgreSQL 9.6 portal cleanup also failed: "
                f"error_type={type(cleanup_error).__name__}, "
                f"sqlstate={cleanup_error.sqlstate!r}"
            )
            LOGGER.warning(
                "PostgreSQL 9.6 portal cleanup failed while preserving the primary error",
                extra={
                    "operation": "close_postgres_9_6_portal",
                    "error_type": type(cleanup_error).__name__,
                    "sqlstate": cleanup_error.sqlstate,
                },
            )

    def _probe_named_cursor_description(self) -> tuple[Psycopg2Column, ...] | None:
        if self._name is None:
            raise AssertionError("named PostgreSQL cursor descriptor probe requires a portal name")
        portal_name = _quoted_legacy_portal_name(self._name)
        charge = self._connection.source_budget.dispatch_query(
            self._connection.direction,
            0,
        )
        try:
            with self._connection.raw_connection.cursor() as probe:
                probe.execute(f"FETCH FORWARD 0 FROM {portal_name}")
                charge.require_fetch_deadline()
                rows = tuple(cast(DatabaseRow, row) for row in probe.fetchall())
                charge.consume_records(tuple(_database_row_bytes(row) for row in rows))
                if rows:
                    raise PostgresDataValidationError(
                        "PostgreSQL legacy descriptor probe unexpectedly returned rows"
                    )
                return probe.description
        except psycopg2.Error as error:
            _raise_translated_database_error(error)


class _LegacyConnection:
    def __init__(
        self,
        connection: Psycopg2Connection,
        source_budget: PostgresSourceBudgetAttempt,
        direction: PostgresSourceDirection,
    ) -> None:
        self._connection = connection
        self._source_budget = source_budget
        self._direction = direction

    @property
    def raw_connection(self) -> Psycopg2Connection:
        return self._connection

    @property
    def source_budget(self) -> PostgresSourceBudgetAttempt:
        return self._source_budget

    @property
    def direction(self) -> PostgresSourceDirection:
        return self._direction

    def cursor(
        self,
        *names: str | None,
        **options: str | None,
    ) -> _LegacyCursor:
        if len(names) > 1 or (names and options):
            raise TypeError("PostgreSQL 9.6 connection cursor accepts at most one name")
        if options.keys() - {"name"}:
            raise TypeError("PostgreSQL 9.6 connection cursor accepts only the name option")
        name = options.get("name") if options else (None if not names else names[0])
        if name is not None:
            _quoted_legacy_portal_name(name)
        try:
            return _LegacyCursor(self, self._connection.cursor(), name)
        except psycopg2.Error as error:
            _raise_translated_database_error(error)

    def rollback(self) -> None:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute("ROLLBACK")
        except psycopg2.Error as error:
            _raise_translated_database_error(error)

    def close(self) -> None:
        self._connection.close()


class PostgresLegacyProtectedReadContext(PostgresProtectedReadContext):
    def _build_integer_key_summary_query(
        self,
        schema: CanonicalSchema,
        relations: tuple[PostgresQueryRelation, ...],
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        max_encoded_envelope_bytes: int,
    ) -> PostgresQuery:
        return build_postgres_legacy_union_integer_key_summary_query(
            schema,
            relations,
            key_field_index,
            scope,
            max_encoded_envelope_bytes,
        )

    def _build_row_envelope_query(
        self,
        schema: CanonicalSchema,
        relations: tuple[PostgresQueryRelation, ...],
        max_encoded_envelope_bytes: int,
    ) -> PostgresQuery:
        return build_postgres_legacy_union_row_envelope_query(
            schema,
            relations,
            max_encoded_envelope_bytes,
        )

    def _build_fingerprint_query(
        self,
        schema: CanonicalSchema,
        relations: tuple[PostgresQueryRelation, ...],
        max_encoded_envelope_bytes: int,
    ) -> PostgresQuery:
        return build_postgres_legacy_union_fingerprint_query(
            schema,
            relations,
            max_encoded_envelope_bytes,
        )

    def _build_integer_range_fingerprint_query(
        self,
        schema: CanonicalSchema,
        relations: tuple[PostgresQueryRelation, ...],
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
    ) -> PostgresQuery:
        return build_postgres_legacy_union_integer_range_fingerprint_query(
            schema,
            relations,
            key_field_index,
            scope,
            ranges,
            max_encoded_envelope_bytes,
        )


def open_postgres_9_6_protected_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    acquisitions: tuple[PostgresRelationAcquisition, ...],
    lock_timeout_milliseconds: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresProtectedReadContext:
    ordered_acquisitions = _validate_and_order_acquisitions(acquisitions)
    _validate_protected_lock_timeout(
        lock_timeout_milliseconds,
        settings.statement_timeout_milliseconds,
    )
    for acquisition_attempt in range(1, retry_policy.max_attempts + 1):
        connection = _connect_legacy_protected(
            settings,
            retry_policy,
            source_budget,
            direction,
        )
        try:
            return _open_legacy_protected_once(
                connection,
                settings,
                ordered_acquisitions,
                lock_timeout_milliseconds,
                source_budget,
                direction,
            )
        except PostgresAcquisitionRaceError as error:
            LOGGER.warning(
                "PostgreSQL 9.6 protected relation identity changed during acquisition",
                extra={
                    "operation": "open_postgres_9_6_protected_read_context",
                    "attempt": acquisition_attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "dbname": settings.dbname,
                    "user": settings.user,
                    "error_type": type(error).__name__,
                },
            )
            if acquisition_attempt == retry_policy.max_attempts:
                raise PostgresAcquisitionRaceError(
                    "PostgreSQL 9.6 protected relation identity did not stabilize within "
                    "the bounded acquisition attempts: "
                    f"host={settings.host!r}, port={settings.port}, "
                    f"dbname={settings.dbname!r}, user={settings.user!r}, "
                    f"attempts={acquisition_attempt}, last_failure={error}"
                ) from None
            time.sleep(retry_policy.delay_seconds)
        except psycopg.Error as error:
            raise PostgresConnectionError(
                _protected_acquisition_database_error_message(settings, error)
            ) from None
    raise AssertionError("PostgreSQL 9.6 protected acquisition retry loop ended without an attempt")


def _connect_legacy_protected(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> _LegacyConnection:
    failure_message: str | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
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
                options=(
                    "-c statement_timeout="
                    f"{min(settings.statement_timeout_milliseconds, source_budget.effective_statement_timeout_milliseconds())}"
                ),
            )
            connection.autocommit = True
            return _LegacyConnection(connection, source_budget, direction)
        except psycopg2.OperationalError as error:
            failure_message = _legacy_connection_error_message(settings, attempt, error)
            LOGGER.warning(
                "PostgreSQL 9.6 protected connection attempt failed",
                extra={
                    "operation": "connect_postgres_9_6_protected_read_context",
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
            if attempt < retry_policy.max_attempts:
                time.sleep(retry_policy.delay_seconds)
        except psycopg2.Error as error:
            raise PostgresConnectionError(
                _legacy_connection_error_message(settings, attempt, error)
            ) from None
    if failure_message is None:
        raise AssertionError("PostgreSQL 9.6 connection retry loop ended without an attempt")
    raise PostgresConnectionError(failure_message)


def _open_legacy_protected_once(
    connection: _LegacyConnection,
    settings: PostgresConnectionSettings,
    acquisitions: tuple[PostgresRelationAcquisition, ...],
    lock_timeout_milliseconds: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresProtectedReadContext:
    transport = cast(psycopg.Connection[DatabaseRow], connection)
    succeeded = False
    try:
        candidates = tuple(
            _discover_legacy_relation_candidate(
                transport,
                acquisition,
                source_budget,
                direction,
            )
            for acquisition in acquisitions
        )
        lock_candidates = _unique_lock_candidates(candidates)
        started_at = datetime.now(UTC)
        _execute_source_command(
            transport,
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
            (),
            source_budget,
            direction,
        )
        for candidate in lock_candidates:
            _configure_protected_lock_timeouts(
                transport,
                settings.statement_timeout_milliseconds,
                lock_timeout_milliseconds,
                source_budget,
                direction,
            )
            _lock_candidate_relation(transport, candidate, source_budget, direction)
        _configure_protected_statement_timeout(
            transport,
            settings.statement_timeout_milliseconds,
            source_budget,
            direction,
        )
        _configure_protected_snapshot_invariants(transport, source_budget, direction)
        profile, evidence = _capture_legacy_protected_snapshot(
            transport,
            lock_candidates,
            started_at,
            source_budget,
            direction,
        )
        _validate_legacy_pgcrypto(
            transport,
            acquisitions,
            source_budget,
            direction,
        )
        protected_relations = tuple(
            _inspect_legacy_protected_candidate(
                transport,
                candidate,
                profile,
                evidence,
                source_budget,
                direction,
            )
            for candidate in candidates
        )
        read_context = PostgresReadContext(
            transport,
            profile,
            evidence,
            settings.statement_timeout_milliseconds,
            source_budget,
            direction,
        )
        acquisition_receipt = _ProtectedAcquisitionReceipt(
            read_context=read_context,
            protected_relations=protected_relations,
        )
        context = PostgresLegacyProtectedReadContext(
            read_context,
            protected_relations,
            acquisition_receipt,
        )
        succeeded = True
        return context
    finally:
        if not succeeded:
            connection.close()


def _discover_legacy_relation_candidate(
    connection: psycopg.Connection[DatabaseRow],
    acquisition: PostgresRelationAcquisition,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> _PostgresRelationCandidate:
    if acquisition.relation_scope is RelationScope.PHYSICAL_ONLY:
        return _discover_physical_relation_candidate(
            connection,
            acquisition,
            source_budget,
            direction,
        )
    if acquisition.relation_scope is not RelationScope.FROZEN_PHYSICAL_UNION:
        raise ValueError("PostgreSQL 9.6 acquisition has an unsupported relation scope")
    statement = sql.SQL(
        "WITH RECURSIVE dfe_root AS ("
        "SELECT c.oid FROM pg_catalog.pg_class AS c "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = %s AND c.relname = %s"
        "), dfe_members(relation_oid) AS ("
        "SELECT dfe_root.oid FROM dfe_root UNION "
        "SELECT inheritance.inhrelid FROM pg_catalog.pg_inherits AS inheritance "
        "JOIN dfe_members ON inheritance.inhparent = dfe_members.relation_oid"
        ") SELECT c.oid::bigint, c.reltype::bigint, n.oid::bigint, n.nspname, c.relname, "
        "c.relkind::text, c.relpersistence::text, "
        "pg_catalog.has_table_privilege(c.oid, 'SELECT'), "
        "c.relrowsecurity, c.relforcerowsecurity, "
        "pg_catalog.has_schema_privilege(n.oid, 'USAGE'), "
        "c.oid = dfe_root.oid, inheritance.inhparent::bigint, "
        "inheritance.inhseqno::integer, "
        "CASE WHEN inheritance.inhparent IS NULL THEN NULL::boolean ELSE FALSE::boolean END, "
        "pg_catalog.current_setting('max_identifier_length')::integer "
        "FROM dfe_members JOIN pg_catalog.pg_class AS c "
        "ON c.oid = dfe_members.relation_oid "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
        "CROSS JOIN dfe_root LEFT JOIN pg_catalog.pg_inherits AS inheritance "
        "ON inheritance.inhrelid = c.oid "
        "AND inheritance.inhparent IN (SELECT relation_oid FROM dfe_members) "
        "ORDER BY n.nspname, c.relname, c.oid, inheritance.inhseqno, inheritance.inhparent "
        "LIMIT %s"
    )
    max_records = acquisition.max_metadata_total_bytes
    rows = _execute_pretransaction_candidate_bounded(
        connection,
        statement,
        (*acquisition.relation.components, max_records + 1),
        max_records,
        acquisition.max_metadata_record_bytes,
        acquisition.max_metadata_total_bytes,
        source_budget,
        direction,
    )
    if not rows:
        raise PostgresMetadataError(
            "PostgreSQL 9.6 frozen physical union root is missing or inaccessible during "
            f"candidate discovery: relation={acquisition.relation.components!r}"
        )
    candidate = _frozen_candidate_from_rows(acquisition, rows)
    unsupported_members = tuple(
        member
        for member in candidate.members
        if member.relation_kind is not PostgresRelationKind.REGULAR
    )
    if unsupported_members:
        raise PostgresMetadataError(
            "PostgreSQL 9.6 frozen physical union contains a non-regular relation: "
            f"relation={unsupported_members[0].relation.components!r}, "
            f"relation_kind={unsupported_members[0].relation_kind.value!r}, required='r'"
        )
    return replace(
        candidate,
        edges=tuple(
            replace(
                edge,
                detach_state=PostgresInheritanceDetachState.UNSUPPORTED_BY_SERVER,
            )
            for edge in candidate.edges
        ),
    )


def _inspect_legacy_protected_candidate(
    connection: psycopg.Connection[DatabaseRow],
    candidate: _PostgresRelationCandidate,
    profile: PostgresServerProfile,
    evidence: PostgresProtectedReadContextEvidence,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresProtectedRelationInspection:
    acquisition = candidate.acquisition
    try:
        final_candidate = _discover_legacy_relation_candidate(
            connection,
            acquisition,
            source_budget,
            direction,
        )
    except PostgresAcquisitionRaceError:
        raise
    except PostgresMetadataError as error:
        raise PostgresAcquisitionRaceError(
            "PostgreSQL 9.6 protected relation graph became invalid between discovery and "
            f"the protected snapshot: relation={acquisition.relation.components!r}, "
            f"reason={error}"
        ) from None
    return _seal_protected_candidate(
        connection,
        candidate,
        final_candidate,
        profile,
        evidence,
        source_budget,
        direction,
    )


def _capture_legacy_protected_snapshot(
    connection: psycopg.Connection[DatabaseRow],
    lock_candidates: tuple[_PostgresRelationMemberCandidate, ...],
    started_at: datetime,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> tuple[PostgresServerProfile, PostgresProtectedReadContextEvidence]:
    lock_checks = sql.SQL(", ").join(
        sql.SQL(
            "EXISTS(SELECT 1 FROM pg_catalog.pg_locks AS held_lock "
            "WHERE held_lock.locktype = 'relation' "
            "AND held_lock.pid = pg_catalog.pg_backend_pid() "
            "AND held_lock.relation = %s::oid "
            "AND held_lock.mode = 'AccessShareLock' AND held_lock.granted)"
        )
        for _ in lock_candidates
    )
    statement = sql.SQL(
        "SELECT pg_catalog.current_setting('server_version'), "
        "pg_catalog.current_setting('server_version_num')::integer, "
        "pg_catalog.current_setting('server_encoding'), "
        "pg_catalog.current_setting('client_encoding'), "
        "pg_catalog.current_setting('integer_datetimes') = 'on', "
        "pg_catalog.current_setting('TimeZone'), "
        "pg_catalog.current_setting('max_identifier_length')::integer, "
        "pg_catalog.pg_backend_pid(), pg_catalog.txid_current_snapshot()::text, "
        "pg_catalog.current_setting('transaction_isolation'), "
        "pg_catalog.current_setting('transaction_read_only') = 'on', {lock_checks}"
    ).format(lock_checks=lock_checks)
    parameters = tuple(candidate.relation_oid for candidate in lock_candidates)
    max_record_bytes = max(
        candidate.acquisition.max_metadata_record_bytes for candidate in lock_candidates
    )
    max_total_bytes = max(
        candidate.acquisition.max_metadata_total_bytes for candidate in lock_candidates
    )
    rows = _execute_setup_bounded(
        connection,
        statement,
        parameters,
        1,
        max_record_bytes,
        max_total_bytes,
        source_budget,
        direction,
    )
    if not rows:
        raise PostgresDataValidationError(
            "PostgreSQL 9.6 protected snapshot and lock probe returned no row"
        )
    row = rows[0]
    expected_fields = 11 + len(lock_candidates)
    if len(row) != expected_fields:
        raise PostgresDataValidationError(
            "PostgreSQL 9.6 protected snapshot probe returned an unexpected field count: "
            f"expected={expected_fields}, actual={len(row)}"
        )
    profile_row = row[:11]
    profile, base_evidence = _profile_and_evidence(profile_row, started_at)
    legacy_profile = replace(
        profile,
        driver_version=_PSYCOPG2_VERSION,
    )
    _validate_legacy_profile(legacy_profile, profile_row)
    for index, (candidate, value) in enumerate(zip(lock_candidates, row[11:], strict=True)):
        if not _require_boolean(value, f"PostgreSQL 9.6 candidate lock proof {index}"):
            raise PostgresAcquisitionRaceError(
                "PostgreSQL 9.6 protected acquisition cannot prove an AccessShareLock for "
                "the discovered relation before its snapshot: "
                f"relation={candidate.relation.components!r}, "
                f"relation_oid={candidate.relation_oid}"
            )
    locked_relation_oids = tuple(candidate.relation_oid for candidate in lock_candidates)
    evidence = PostgresProtectedReadContextEvidence(
        context_id=base_evidence.context_id,
        engine=base_evidence.engine,
        server_version=base_evidence.server_version,
        strategy="protected_read_only_repeatable_read",
        snapshot_locator=base_evidence.snapshot_locator,
        started_at=base_evidence.started_at,
        backend_process_id=base_evidence.backend_process_id,
        allowed_concurrency=base_evidence.allowed_concurrency,
        limitations=(
            *base_evidence.limitations,
            "snapshot locator uses PostgreSQL 9.6 txid_current_snapshot",
            "SHA-256 requires preinstalled pgcrypto 1.3 in schema dfe_ext",
            "every discovered physical relation holds AccessShareLock before the snapshot",
            "only pre-acquired regular members contribute rows through explicit ONLY scans",
        ),
        locked_relation_oids=locked_relation_oids,
        lock_mode="access_share",
        relation_persistence=PostgresRelationPersistence.PERMANENT,
        acquired_before_snapshot=True,
    )
    return legacy_profile, evidence


def _validate_legacy_profile(
    profile: PostgresServerProfile,
    row: DatabaseRow,
) -> None:
    isolation = _require_text(row[9], "transaction_isolation")
    read_only = _require_boolean(row[10], "transaction_read_only")
    failures: list[str] = []
    if profile.server_version_number != _POSTGRES_9_6_VERSION_NUMBER:
        failures.append(f"server_version_num={profile.server_version_number}, required=90624")
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
            "PostgreSQL 9.6.24 source capability profile is unsupported: " + "; ".join(failures)
        )


def _validate_legacy_pgcrypto(
    connection: psycopg.Connection[DatabaseRow],
    acquisitions: tuple[PostgresRelationAcquisition, ...],
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> None:
    max_record_bytes = max(item.max_metadata_record_bytes for item in acquisitions)
    max_total_bytes = max(item.max_metadata_total_bytes for item in acquisitions)
    capability_rows = _execute_setup_bounded(
        connection,
        "SELECT dfe_extension.extversion, dfe_namespace.nspname, "
        "pg_catalog.has_schema_privilege(dfe_namespace.oid, 'USAGE'), "
        "digest_function.oid::bigint, "
        "coalesce(pg_catalog.has_function_privilege(digest_function.oid, 'EXECUTE'), false), "
        "coalesce(digest_function.prorettype = 17::oid, false) "
        "FROM pg_catalog.pg_extension AS dfe_extension "
        "JOIN pg_catalog.pg_namespace AS dfe_namespace "
        "ON dfe_namespace.oid = dfe_extension.extnamespace "
        "LEFT JOIN pg_catalog.pg_proc AS digest_function "
        "ON digest_function.pronamespace = dfe_namespace.oid "
        "AND digest_function.proname = 'digest' "
        "AND digest_function.proargtypes = '17 25'::oidvector "
        "WHERE dfe_extension.extname = 'pgcrypto'",
        (),
        1,
        max_record_bytes,
        max_total_bytes,
        source_budget,
        direction,
    )
    failures: list[str] = []
    if len(capability_rows) != 1:
        failures.append("preinstalled pgcrypto extension is missing")
    else:
        row = capability_rows[0]
        if len(row) != 6:
            raise PostgresDataValidationError(
                "PostgreSQL 9.6 pgcrypto capability probe returned an unexpected field count"
            )
        extension_version = _require_text(row[0], "pgcrypto extension version")
        extension_schema = _require_text(row[1], "pgcrypto extension schema")
        function_oid = row[3]
        if extension_version != _PGCRYPTO_EXTENSION_VERSION:
            failures.append(f"pgcrypto_version={extension_version!r}, required='1.3'")
        if extension_schema != _PGCRYPTO_SCHEMA:
            failures.append(f"pgcrypto_schema={extension_schema!r}, required='dfe_ext'")
        if not _require_boolean(row[2], "pgcrypto schema USAGE privilege"):
            failures.append("read role lacks USAGE on pgcrypto schema dfe_ext")
        if function_oid is None:
            failures.append("pgcrypto digest(bytea,text) function is missing")
        else:
            _require_bounded_integer(
                function_oid,
                "pgcrypto digest function OID",
                1,
                UINT32_MAX,
            )
        if not _require_boolean(row[4], "pgcrypto digest EXECUTE privilege"):
            failures.append("read role lacks EXECUTE on pgcrypto digest(bytea,text)")
        if not _require_boolean(row[5], "pgcrypto digest return type"):
            failures.append("pgcrypto digest(bytea,text) does not return bytea")
    if failures:
        raise UnsupportedPostgresProfileError(
            "PostgreSQL 9.6.24 source pgcrypto capability is unsupported: " + "; ".join(failures)
        )
    digest_rows = _execute_setup_bounded(
        connection,
        "SELECT candidate.value = pg_catalog.decode(%s, 'hex'), "
        "pg_catalog.octet_length(candidate.value)::integer "
        "FROM (SELECT dfe_ext.digest(pg_catalog.convert_to('abc', 'UTF8'), 'sha256') "
        "AS value) AS candidate",
        (_SHA256_ABC,),
        1,
        max_record_bytes,
        max_total_bytes,
        source_budget,
        direction,
    )
    if (
        len(digest_rows) != 1
        or len(digest_rows[0]) != 2
        or not _require_boolean(digest_rows[0][0], "pgcrypto SHA-256 canonical probe")
        or _require_bounded_integer(
            digest_rows[0][1],
            "pgcrypto SHA-256 byte length",
            0,
            INT64_MAX,
        )
        != 32
    ):
        raise UnsupportedPostgresProfileError(
            "PostgreSQL 9.6.24 source pgcrypto SHA-256 canonical probe failed"
        )


def _legacy_statement_text(statement: LegacyStatement) -> str:
    if type(statement) is str:
        return statement
    if isinstance(statement, sql.Composable):
        return statement.as_string()
    raise TypeError("PostgreSQL 9.6 statement must be text or psycopg.sql composable SQL")


def _quoted_legacy_portal_name(name: str) -> str:
    if (
        not name.startswith("dfe_")
        or len(name) != 36
        or any(character not in "0123456789abcdef" for character in name[4:])
    ):
        raise PostgresDataValidationError(
            "PostgreSQL 9.6 operation received an invalid internal portal name"
        )
    return f'"{name}"'


def _raise_translated_database_error(error: psycopg2.Error) -> NoReturn:
    sqlstate = error.pgcode
    error_type: type[psycopg.Error]
    if sqlstate is None:
        error_type = psycopg.DatabaseError
    else:
        try:
            error_type = psycopg.errors.lookup(sqlstate)
        except KeyError:
            error_type = psycopg.DatabaseError
    raise error_type("PostgreSQL 9.6 legacy driver operation failed") from None


def _legacy_connection_error_message(
    settings: PostgresConnectionSettings,
    attempt: int,
    error: psycopg2.Error,
) -> str:
    return (
        "PostgreSQL 9.6 connection failed: "
        f"host={settings.host!r}, port={settings.port}, dbname={settings.dbname!r}, "
        f"user={settings.user!r}, sslmode={settings.sslmode.value!r}, attempt={attempt}, "
        f"error_type={type(error).__name__}, sqlstate={error.pgcode!r}"
    )
