import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import date
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
    TimestampParameters,
    decode_row,
)
from forensic_data.contracts.model import ReadinessManifestColumns
from forensic_data.postgres import (
    PostgresConnectionError,
    PostgresConnectionSettings,
    PostgresMetadataError,
    PostgresProtectedReadContext,
    PostgresQueryContextError,
    PostgresRelationAcquisition,
    PostgresRelationPersistence,
    PostgresRetryPolicy,
    open_postgres_protected_read_context,
    open_postgres_read_context,
)
from forensic_data.postgres_sql import PostgresRelation
from tests.postgres_support import connect_writer, required_connection_settings

pytestmark = [pytest.mark.integration, pytest.mark.postgres]

_METADATA_RECORD_BYTES = 4_096
_METADATA_TOTAL_BYTES = 32_768
_READER_SETTINGS = required_connection_settings(
    "DFE_TEST_POSTGRES_READER_DSN",
    "dfe-phase02-protected-reader",
)
_WRITER_SETTINGS = required_connection_settings(
    "DFE_TEST_POSTGRES_WRITER_DSN",
    "dfe-phase02-protected-writer",
)


def test_protected_acquisition_waits_for_truncate_then_holds_the_full_relation_set() -> None:
    schema = _integer_schema()
    suffix = uuid4().hex
    namespace = f"dfe_protected_{suffix}"
    application_name = f"dfe-protected-race-{suffix}"
    rebound_application_name = f"dfe-protected-rebound-{suffix}"
    reader_settings = _settings_with_application_name(_READER_SETTINGS, application_name)
    rebound_reader_settings = _settings_with_application_name(
        _READER_SETTINGS,
        rebound_application_name,
    )
    dataset_relation = PostgresRelation(components=(namespace, "dataset_values"))
    manifest_relation = PostgresRelation(components=(namespace, "manifest_values"))
    manifest_columns = _manifest_columns()
    scope_digest = "ab" * 32
    acquisitions = (
        _acquisition(_manifest_schema(), manifest_relation, manifest_columns.values()),
        _acquisition(schema, dataset_relation, ("id",)),
    )
    writer = connect_writer(_WRITER_SETTINGS)
    observer = connect_writer(_WRITER_SETTINGS)
    context: PostgresProtectedReadContext | None = None
    rebound_context: PostgresProtectedReadContext | None = None
    transaction_open = False
    try:
        writer.execute(
            sql.SQL("CREATE SCHEMA {} AUTHORIZATION dfe_fixture_writer").format(
                sql.Identifier(namespace)
            )
        )
        writer.execute(
            sql.SQL("CREATE TABLE {} (id bigint NOT NULL)").format(
                sql.Identifier(*dataset_relation.components)
            )
        )
        writer.execute(
            sql.SQL(
                "CREATE TABLE {} ("
                "logical_dataset text NOT NULL, scope_sha varchar(64) NOT NULL, "
                "batch_token text NOT NULL, publication_state varchar(32) NOT NULL, "
                "cut_date date NOT NULL, source_token text NULL, "
                "version_token varchar(128) NULL, completed_utc timestamptz NULL)"
            ).format(sql.Identifier(*manifest_relation.components))
        )
        for relation in (dataset_relation, manifest_relation):
            writer.execute(
                sql.SQL("GRANT SELECT ON {} TO dfe_fixture_reader").format(
                    sql.Identifier(*relation.components)
                )
            )
        writer.execute(
            sql.SQL("GRANT USAGE ON SCHEMA {} TO dfe_fixture_reader").format(
                sql.Identifier(namespace)
            )
        )
        writer.execute(
            sql.SQL("INSERT INTO {} (id) VALUES (1)").format(
                sql.Identifier(*dataset_relation.components)
            )
        )
        writer.execute(
            sql.SQL(
                "INSERT INTO {} ("
                "logical_dataset, scope_sha, batch_token, publication_state, cut_date, "
                "source_token, version_token, completed_utc) VALUES "
                "(%s, %s, 'batch-1', 'complete', DATE '2026-09-23', "
                "'cut-a', 'version-a', TIMESTAMPTZ '2026-09-23 10:00:00+00'), "
                "(%s, %s, 'batch-2', 'building', DATE '2026-09-24', "
                "NULL, NULL, NULL)"
            ).format(sql.Identifier(*manifest_relation.components)),
            ("orders", scope_digest, "orders", scope_digest),
        )

        writer.execute("BEGIN")
        transaction_open = True
        writer.execute(
            sql.SQL("DROP TABLE {}").format(sql.Identifier(*dataset_relation.components))
        )
        writer.execute(
            sql.SQL("CREATE SEQUENCE {}").format(sql.Identifier(*dataset_relation.components))
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            rebound_future = executor.submit(
                _open_protected_context,
                rebound_reader_settings,
                acquisitions,
                PostgresRetryPolicy(max_attempts=2, delay_seconds=2.0),
            )
            observed_rebound_lock_wait = _wait_for_lock_wait(
                observer,
                rebound_application_name,
                2.0,
            )
            writer.execute("COMMIT")
            transaction_open = False
            assert _wait_for_application_connection_count(
                observer,
                rebound_application_name,
                0,
                2.0,
            )
            writer.execute("BEGIN")
            transaction_open = True
            writer.execute(
                sql.SQL("DROP SEQUENCE {}").format(sql.Identifier(*dataset_relation.components))
            )
            writer.execute(
                sql.SQL("CREATE TABLE {} (id bigint NOT NULL)").format(
                    sql.Identifier(*dataset_relation.components)
                )
            )
            writer.execute(
                sql.SQL("GRANT SELECT ON {} TO dfe_fixture_reader").format(
                    sql.Identifier(*dataset_relation.components)
                )
            )
            writer.execute(
                sql.SQL("INSERT INTO {} (id) VALUES (1)").format(
                    sql.Identifier(*dataset_relation.components)
                )
            )
            writer.execute("COMMIT")
            transaction_open = False
            rebound_context = rebound_future.result(timeout=5.0)
        assert observed_rebound_lock_wait
        rebound_rows = rebound_context.read_canonical_rows(
            rebound_context.protected_relations[0],
            512,
            2,
            1_024,
            2_048,
        )
        assert tuple(decode_row(schema, row.envelope) for row in rebound_rows) == ((1,),)
        rebound_context.close()
        rebound_context = None

        writer.execute("BEGIN")
        transaction_open = True
        writer.execute(
            sql.SQL("TRUNCATE TABLE {}").format(sql.Identifier(*dataset_relation.components))
        )
        direct_failure_started_at = time.monotonic()
        with pytest.raises(PostgresConnectionError, match="was not retried"):
            open_postgres_protected_read_context(
                reader_settings,
                PostgresRetryPolicy(max_attempts=2, delay_seconds=2.0),
                acquisitions,
                100,
            )
        direct_failure_elapsed = time.monotonic() - direct_failure_started_at
        assert direct_failure_elapsed < 1.5
        assert _wait_for_application_connection_count(
            observer,
            application_name,
            0,
            1.0,
        )
        writer.execute("ROLLBACK")
        transaction_open = False

        writer.execute("BEGIN")
        transaction_open = True
        writer.execute(
            sql.SQL("TRUNCATE TABLE {}").format(sql.Identifier(*dataset_relation.components))
        )
        writer.execute(
            sql.SQL("INSERT INTO {} (id) VALUES (2)").format(
                sql.Identifier(*dataset_relation.components)
            )
        )

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                _open_protected_context,
                reader_settings,
                acquisitions,
                PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0),
            )
            observed_lock_wait = _wait_for_lock_wait(
                observer,
                application_name,
                2.0,
            )
            writer.execute("COMMIT")
            transaction_open = False
            context = future.result(timeout=5.0)
        assert observed_lock_wait

        protected = context.protected_relations
        assert tuple(item.acquisition.relation for item in protected) == (
            dataset_relation,
            manifest_relation,
        )
        assert context.evidence.strategy == "protected_read_only_repeatable_read"
        assert context.evidence.acquired_before_snapshot is True
        assert context.evidence.lock_mode == "access_share"
        assert context.evidence.relation_persistence is PostgresRelationPersistence.PERMANENT
        assert context.evidence.locked_relation_oids == tuple(
            item.inspection.relation_oid for item in protected
        )
        assert all(item.namespace_oid > 0 for item in protected)
        assert all(
            item.relation_persistence is PostgresRelationPersistence.PERMANENT for item in protected
        )
        assert all(item.acquired_before_snapshot is True for item in protected)

        rows = context.read_canonical_rows(
            protected[0],
            512,
            2,
            1_024,
            2_048,
        )
        assert tuple(decode_row(schema, row.envelope) for row in rows) == ((2,),)
        assert (
            context.read_fingerprint(
                protected[0],
                512,
                1_024,
                1_024,
            ).count
            == 1
        )
        copied_protected_relation = replace(protected[0])
        with pytest.raises(PostgresQueryContextError, match="exact pre-acquired"):
            context.read_canonical_rows(
                copied_protected_relation,
                512,
                2,
                1_024,
                2_048,
            )
        ordinary_context = open_postgres_read_context(
            reader_settings,
            PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0),
        )
        try:
            with pytest.raises(
                PostgresQueryContextError,
                match="requires an internal acquisition receipt",
            ):
                PostgresProtectedReadContext(
                    ordinary_context,
                    protected,
                    object(),
                )
        finally:
            ordinary_context.close()
        permuted_manifest_columns = ReadinessManifestColumns(
            dataset_id=manifest_columns.dataset_id,
            scope_digest=manifest_columns.scope_digest,
            batch_id=manifest_columns.batch_id,
            state=manifest_columns.state,
            business_date=manifest_columns.business_date,
            source_cut=manifest_columns.dataset_version,
            dataset_version=manifest_columns.source_cut,
            completed_at=manifest_columns.completed_at,
        )
        with pytest.raises(PostgresMetadataError, match="ordered acquired column closure"):
            context.read_relation_manifest(
                protected[1],
                permuted_manifest_columns,
                "orders",
                scope_digest,
                1_024,
                2_048,
            )
        assert (
            context.read_relation_manifest(
                protected[1],
                manifest_columns,
                "missing-orders",
                "cd" * 32,
                1_024,
                2_048,
            )
            == ()
        )
        manifest_rows = context.read_relation_manifest(
            protected[1],
            manifest_columns,
            "orders",
            scope_digest,
            1_024,
            2_048,
        )
        assert len(manifest_rows) == 2
        assert {row.batch_id for row in manifest_rows} == {"batch-1", "batch-2"}
        assert {row.state for row in manifest_rows} == {"complete", "building"}
        assert all(row.dataset_id == "orders" for row in manifest_rows)
        assert all(row.scope_digest == scope_digest for row in manifest_rows)
        assert {row.business_date for row in manifest_rows} == {
            date(2026, 9, 23),
            date(2026, 9, 24),
        }
        building_record = next(row for row in manifest_rows if row.state == "building")
        assert building_record.source_cut is None
        assert building_record.dataset_version is None
        assert building_record.completed_at is None

        observer.execute("BEGIN")
        try:
            observer.execute("SET LOCAL lock_timeout TO '100ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                observer.execute(
                    sql.SQL("TRUNCATE TABLE {}").format(
                        sql.Identifier(*manifest_relation.components)
                    )
                )
        finally:
            observer.execute("ROLLBACK")
    finally:
        if transaction_open:
            writer.execute("ROLLBACK")
        if rebound_context is not None:
            rebound_context.close()
        if context is not None:
            context.close()
        observer.close()
        writer.execute(
            sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(namespace))
        )
        writer.close()


def _integer_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _manifest_columns() -> ReadinessManifestColumns:
    return ReadinessManifestColumns(
        dataset_id="logical_dataset",
        scope_digest="scope_sha",
        batch_id="batch_token",
        state="publication_state",
        business_date="cut_date",
        source_cut="source_token",
        dataset_version="version_token",
        completed_at="completed_utc",
    )


def _manifest_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="dataset_id",
                logical_type=LogicalType.STRING,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="scope_digest",
                logical_type=LogicalType.STRING,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="batch_id",
                logical_type=LogicalType.STRING,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="state",
                logical_type=LogicalType.STRING,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="business_date",
                logical_type=LogicalType.DATE,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="source_cut",
                logical_type=LogicalType.STRING,
                nullable=True,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="dataset_version",
                logical_type=LogicalType.STRING,
                nullable=True,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="completed_at",
                logical_type=LogicalType.TIMESTAMP_INSTANT,
                nullable=True,
                parameters=TimestampParameters(precision=6),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _acquisition(
    schema: CanonicalSchema,
    relation: PostgresRelation,
    column_names: tuple[str, ...],
) -> PostgresRelationAcquisition:
    return PostgresRelationAcquisition(
        schema=schema,
        relation=relation,
        column_names=column_names,
        max_metadata_record_bytes=_METADATA_RECORD_BYTES,
        max_metadata_total_bytes=_METADATA_TOTAL_BYTES,
    )


def _settings_with_application_name(
    settings: PostgresConnectionSettings,
    application_name: str,
) -> PostgresConnectionSettings:
    return PostgresConnectionSettings(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password,
        sslmode=settings.sslmode,
        connect_timeout_seconds=settings.connect_timeout_seconds,
        statement_timeout_milliseconds=settings.statement_timeout_milliseconds,
        application_name=application_name,
    )


def _open_protected_context(
    settings: PostgresConnectionSettings,
    acquisitions: tuple[PostgresRelationAcquisition, ...],
    retry_policy: PostgresRetryPolicy,
) -> PostgresProtectedReadContext:
    return open_postgres_protected_read_context(
        settings,
        retry_policy,
        acquisitions,
        4_000,
    )


def _wait_for_lock_wait(
    observer: psycopg.Connection[tuple[object, ...]],
    application_name: str,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        row = observer.execute(
            "SELECT pg_catalog.count(*) "
            "FROM pg_catalog.pg_locks AS waiting_lock "
            "JOIN pg_catalog.pg_stat_activity AS activity ON activity.pid = waiting_lock.pid "
            "WHERE activity.application_name = %s AND NOT waiting_lock.granted",
            (application_name,),
        ).fetchone()
        if row is None or len(row) != 1 or type(row[0]) is not int:
            raise AssertionError("PostgreSQL lock-wait observation returned an invalid row")
        if row[0] == 1:
            return True
        time.sleep(0.01)
    return False


def _wait_for_application_connection_count(
    observer: psycopg.Connection[tuple[object, ...]],
    application_name: str,
    expected_count: int,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        row = observer.execute(
            "SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity "
            "WHERE application_name = %s",
            (application_name,),
        ).fetchone()
        if row is None or len(row) != 1 or type(row[0]) is not int:
            raise AssertionError("PostgreSQL application observation returned an invalid row")
        if row[0] == expected_count:
            return True
        time.sleep(0.01)
    return False
