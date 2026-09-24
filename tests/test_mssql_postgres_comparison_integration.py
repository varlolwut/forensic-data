# pyright: reportPrivateUsage=false

import hashlib
from contextlib import closing
from datetime import date
from pathlib import Path
from uuid import uuid4

import pytest

from forensic_data.application import (
    DiffRequest,
    ExecuteCheckRequest,
    HistoryRequest,
    MssqlPostgresExecutionServices,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    read_diff,
    read_history,
)
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import LoadedContractConfig, RowCheckDefinition
from forensic_data.contracts.semantics import canonicalize_semantic_json
from forensic_data.mssql import MssqlRetryPolicy
from forensic_data.persistence.postgres import migrate_postgres_metadata
from forensic_data.planning import ResolvedScope, resolve_scope_values
from forensic_data.postgres import PostgresRetryPolicy
from forensic_data.reporting import DetailAvailability, HistoryAttemptStatus
from forensic_data.result import RunResult
from tests import test_postgres_comparison_integration as pg_comparison
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.mssql_support import connect_setup_writer, required_reader_settings
from tests.postgres_support import connect_writer

pytestmark = [pytest.mark.integration, pytest.mark.mssql, pytest.mark.postgres]

_CONTRACT_PATH = Path(__file__).parent / "fixtures/mssql-2022/comparison-contract.yaml"
_BUSINESS_DATE = date(2026, 9, 23)
_CORRUPT_COMPLETED_AT = "2026-09-23T13:30:45.123456+00:00"
_MUTATED_COMPLETED_AT = "2026-09-23T14:30:45.123456+00:00"
_REFERENCE_BASELINE_BATCH = "reference-orders-baseline"
_REFERENCE_CORRUPT_BATCH = "reference-orders-corrupt"
_TARGET_BASELINE_BATCH = "target-orders-baseline"
_TARGET_CORRUPT_BATCH = "target-orders-corrupt"
_BASELINE_SOURCE_CUT = "orders-cut-baseline"
_CORRUPT_SOURCE_CUT = "orders-cut-corrupt"
_SCOPE_VALUES = (ScopeValue(name="business_date", value="2026-09-23"),)
_NO_POSTGRES_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_SOURCE_POSTGRES_RETRY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)
_NO_MSSQL_RETRY = MssqlRetryPolicy(max_attempts=1, delay_seconds=0.0)


def test_mssql_source_to_postgres_target_retains_historical_corruption_evidence() -> None:
    _reset_mssql_reference()
    metadata_request = required_metadata_database_settings()
    target_request = pg_comparison._new_source_database_settings("target")
    try:
        with (
            disposable_metadata_database(metadata_request) as metadata,
            pg_comparison._disposable_source_database(target_request) as target,
        ):
            migrate_postgres_metadata(metadata.migrator, _NO_POSTGRES_RETRY, 5_000)
            config = _mixed_engine_config()
            check = config.checks[0]
            scope = resolve_scope_values(check, {"business_date": "2026-09-23"})
            assert scope.scope_digest == (
                "df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab"
            )
            pg_comparison._seed_source_database(
                target,
                "target_orders",
                check.target.dataset_id,
                scope.scope_digest,
                _TARGET_BASELINE_BATCH,
                _BASELINE_SOURCE_CUT,
                "target-orders-v1",
                "901.00",
            )
            services = _execution_services(metadata, target, check)
            metadata_services = PostgresMetadataServices(
                connection_id=config.metadata.connection.connection_id,
                settings=metadata.reader,
                retry_policy=_NO_POSTGRES_RETRY,
            )

            baseline = execute_check(
                config,
                ExecuteCheckRequest(
                    request_id=uuid4(),
                    check_id=check.check_id,
                    scope_values=_SCOPE_VALUES,
                    reference_expected_batch_id=_REFERENCE_BASELINE_BATCH,
                    target_expected_batch_id=_TARGET_BASELINE_BATCH,
                    origin="mssql-postgres-integration",
                ),
                services,
            )
            pg_comparison._assert_baseline_result(
                baseline,
                check,
                scope,
                config.execution,
            )

            _corrupt_mssql_reference(scope.scope_digest)
            pg_comparison._corrupt_target_and_advance_manifest(
                target,
                check.target.dataset_id,
                scope.scope_digest,
            )
            corrupt = execute_check(
                config,
                ExecuteCheckRequest(
                    request_id=uuid4(),
                    check_id=check.check_id,
                    scope_values=_SCOPE_VALUES,
                    reference_expected_batch_id=_REFERENCE_CORRUPT_BATCH,
                    target_expected_batch_id=_TARGET_CORRUPT_BATCH,
                    origin="mssql-postgres-integration",
                ),
                services,
            )
            pg_comparison._assert_corrupt_result(
                corrupt,
                check,
                scope,
                config.execution,
            )
            _assert_mixed_engine_provenance(metadata, corrupt)

            _mutate_mssql_reference_after_publication(scope.scope_digest)
            _assert_historical_result_and_evidence(
                metadata,
                metadata_services,
                check,
                scope,
                baseline,
                corrupt,
            )
    finally:
        _reset_mssql_reference()


def _mixed_engine_config() -> LoadedContractConfig:
    return load_contract_config(_CONTRACT_PATH)


def _execution_services(
    metadata: MetadataDatabaseSettings,
    target: pg_comparison._SourceDatabaseSettings,
    check: RowCheckDefinition,
) -> MssqlPostgresExecutionServices:
    reference_settings = required_reader_settings("dfe-mssql-postgres-reference").model_copy(
        update={"query_timeout_seconds": 60}
    )
    return MssqlPostgresExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference_settings,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target.reader,
        metadata_connection_id="metadata_pg",
        metadata_settings=metadata.writer,
        reference_retry_policy=_NO_MSSQL_RETRY,
        target_retry_policy=_SOURCE_POSTGRES_RETRY,
        metadata_retry_policy=_NO_POSTGRES_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        metadata_record_bytes=32_000,
        metadata_total_bytes=64_000,
    )


def _reset_mssql_reference() -> None:
    with closing(connect_setup_writer("dfe-comparison-reset")) as connection:
        with connection:
            connection.execute(
                "UPDATE [dfe_fixture].[comparison_orders] "
                "SET [amount] = CONVERT(decimal(18, 2), N'100.00') "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23) "
                "AND [order_id] IN (1000, 1100)"
            )
            connection.execute(
                "UPDATE [dfe_fixture].[comparison_batch_manifest] "
                "SET [batch_id] = N'reference-orders-baseline', "
                "[state] = N'complete', "
                "[business_date] = CONVERT(date, N'2026-09-23', 23), "
                "[source_cut] = N'orders-cut-baseline', "
                "[dataset_version] = N'reference-orders-v1', "
                "[completed_at] = CONVERT("
                "datetimeoffset(6), N'2026-09-23T12:30:45.123456+00:00', 127) "
                "WHERE [dataset_id] = N'reference_orders' "
                "AND [scope_digest] = "
                "N'df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab'"
            )
            row = connection.execute(
                "SELECT "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders] "
                "), "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders] "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23)), "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders] "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23) AND ("
                "[amount] IS NULL OR [amount] <> CONVERT(decimal(18, 2), N'100.00') "
                "OR NOT (([order_id] BETWEEN 2 AND 2000 AND [order_id] % 2 = 0) "
                "OR [order_id] BETWEEN 1000001 AND 1999000))), "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders] "
                "WHERE [order_id] = CONVERT(decimal(21, 2), N'1.00') "
                "AND [business_date] = CONVERT(date, N'2026-09-22', 23) "
                "AND [amount] = CONVERT(decimal(18, 2), N'900.00')), "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_batch_manifest] "
                "WHERE [dataset_id] = N'reference_orders' "
                "AND [scope_digest] = "
                "N'df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab' "
                "AND [batch_id] = N'reference-orders-baseline' "
                "AND [state] = N'complete' "
                "AND [business_date] = CONVERT(date, N'2026-09-23', 23) "
                "AND [source_cut] = N'orders-cut-baseline' "
                "AND [dataset_version] = N'reference-orders-v1' "
                "AND [completed_at] = CONVERT("
                "datetimeoffset(6), N'2026-09-23T12:30:45.123456+00:00', 127))"
            ).fetchone()
            assert row is not None
            assert tuple(row) == (1_000_001, 1_000_000, 0, 1, 1)


def _corrupt_mssql_reference(scope_digest: str) -> None:
    with closing(connect_setup_writer("dfe-comparison-corrupt")) as connection:
        with connection:
            updated = connection.execute(
                "UPDATE [dfe_fixture].[comparison_orders] SET [amount] = NULL "
                "WHERE [business_date] = ? AND [order_id] = 1000",
                _BUSINESS_DATE,
            ).rowcount
            manifest_updated = connection.execute(
                "UPDATE [dfe_fixture].[comparison_batch_manifest] "
                "SET [batch_id] = ?, [source_cut] = ?, [dataset_version] = ?, "
                "[completed_at] = CONVERT(datetimeoffset(6), ?, 127) "
                "WHERE [dataset_id] = ? AND [scope_digest] = ?",
                _REFERENCE_CORRUPT_BATCH,
                _CORRUPT_SOURCE_CUT,
                "reference-orders-v2",
                _CORRUPT_COMPLETED_AT,
                "reference_orders",
                scope_digest,
            ).rowcount
            assert (updated, manifest_updated) == (1, 1)


def _mutate_mssql_reference_after_publication(scope_digest: str) -> None:
    with closing(connect_setup_writer("dfe-comparison-post-publication-mutation")) as connection:
        with connection:
            updated = connection.execute(
                "UPDATE [dfe_fixture].[comparison_orders] "
                "SET [amount] = CASE [order_id] "
                "WHEN 1000 THEN CONVERT(decimal(18, 2), N'777.77') "
                "WHEN 1100 THEN CONVERT(decimal(18, 2), N'888.88') END "
                "WHERE [business_date] = ? AND [order_id] IN (1000, 1100)",
                _BUSINESS_DATE,
            ).rowcount
            manifest_updated = connection.execute(
                "UPDATE [dfe_fixture].[comparison_batch_manifest] "
                "SET [batch_id] = ?, [source_cut] = ?, [dataset_version] = ?, "
                "[completed_at] = CONVERT(datetimeoffset(6), ?, 127) "
                "WHERE [dataset_id] = ? AND [scope_digest] = ?",
                "reference-orders-after-publication",
                "orders-cut-after-publication",
                "reference-orders-v3",
                _MUTATED_COMPLETED_AT,
                "reference_orders",
                scope_digest,
            ).rowcount
            assert (updated, manifest_updated) == (2, 1)


def _assert_historical_result_and_evidence(
    metadata: MetadataDatabaseSettings,
    services: PostgresMetadataServices,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    baseline: RunResult,
    corrupt: RunResult,
) -> None:
    history = read_history(
        HistoryRequest(
            check_id=check.check_id,
            scope_digest=scope.scope_digest,
            limit=2,
            cursor=None,
        ),
        services,
    )
    assert tuple(item.status for item in history.items) == (
        HistoryAttemptStatus.COMPLETED,
        HistoryAttemptStatus.COMPLETED,
    )
    assert tuple(item.stored_result for item in history.items) == (corrupt, baseline)
    assert history.next_cursor is None

    first_page = read_diff(
        DiffRequest(
            run_id=corrupt.run_id,
            attempt_id=corrupt.attempt_id,
            limit=25,
            cursor=None,
        ),
        services,
    )
    assert first_page.detail_availability is DetailAvailability.AVAILABLE
    assert first_page.stored_result == corrupt
    assert first_page.found_records == 37
    assert first_page.retained_records == 37
    assert tuple(item.sequence for item in first_page.details) == tuple(range(25))
    assert first_page.next_cursor is not None
    assert first_page.next_cursor.sequence == 24
    second_page = read_diff(
        DiffRequest(
            run_id=corrupt.run_id,
            attempt_id=corrupt.attempt_id,
            limit=25,
            cursor=first_page.next_cursor,
        ),
        services,
    )
    assert tuple(item.sequence for item in second_page.details) == tuple(range(25, 37))
    assert second_page.next_cursor is None
    pg_comparison._assert_retained_difference_details(first_page.details + second_page.details)
    pg_comparison._assert_numeric_difference_view(
        metadata.reader,
        corrupt.run_id,
        corrupt.attempt_id,
    )


def _assert_mixed_engine_provenance(
    metadata: MetadataDatabaseSettings,
    result: RunResult,
) -> None:
    with connect_writer(metadata.reader) as connection:
        datasets = connection.execute(
            "SELECT dataset_id, connection_id, adapter, driver, profile, locator_kind, "
            "relation_scope FROM dfe_metadata.dataset_versions ORDER BY dataset_id"
        ).fetchall()
        contexts = connection.execute(
            "SELECT direction, engine, strategy, snapshot_locator, allowed_concurrency, state, "
            "pg_catalog.octet_length(scope_digest), driver_version, server_version, "
            "server_version_number, backend_process_id, acquisition_evidence ->> 'kind', "
            "acquisition_evidence #>> '{payload,driver,pyodbc_version}', "
            "acquisition_evidence #>> '{payload,driver,driver_name}', "
            "acquisition_evidence #>> '{payload,driver,driver_version}', "
            "acquisition_evidence #>> '{payload,profile,database_name}', "
            "acquisition_evidence #>> '{payload,profile,compatibility_level}', "
            "acquisition_evidence #>> '{payload,profile,snapshot_isolation_state_description}', "
            "acquisition_evidence #>> '{payload,profile,read_committed_snapshot}', "
            "acquisition_evidence #>> '{payload,profile,can_view_definition}', "
            "acquisition_evidence #>> '{payload,context,database_id}', "
            "acquisition_evidence #>> '{payload,context,transaction_count}', "
            "acquisition_evidence #>> '{payload,context,transaction_state}', "
            "acquisition_evidence #>> '{payload,context,transaction_isolation_level}', "
            "pg_catalog.jsonb_array_length(acquisition_evidence #> '{payload,relations}') "
            "FROM dfe_metadata.attempt_read_contexts "
            "WHERE run_id = %s AND attempt_id = %s ORDER BY direction",
            (result.run_id, result.attempt_id),
        ).fetchall()
        observations = connection.execute(
            "SELECT direction, physical_binding ->> 'engine', readiness_provider_kind, "
            "projection_code_artifact_id, readiness_code_artifact_id, "
            "pg_catalog.octet_length(physical_schema_digest), "
            "pg_catalog.octet_length(physical_binding_digest) "
            "FROM dfe_metadata.dataset_observations "
            "WHERE run_id = %s AND attempt_id = %s ORDER BY direction",
            (result.run_id, result.attempt_id),
        ).fetchall()
        mssql_binding = connection.execute(
            "SELECT physical_binding #>> '{payload,profile,database_name}', "
            "physical_binding #>> '{payload,profile,compatibility_level}', "
            "physical_binding #>> '{payload,dataset_relation,relation,0}', "
            "physical_binding #>> '{payload,dataset_relation,relation,1}', "
            "physical_binding #>> '{payload,dataset_relation,database_id}', "
            "physical_binding #>> '{payload,dataset_relation,schema_id}', "
            "physical_binding #>> '{payload,dataset_relation,object_id}', "
            "physical_binding #>> '{payload,readiness_relation,relation,0}', "
            "physical_binding #>> '{payload,readiness_relation,relation,1}', "
            "physical_binding #>> '{payload,readiness_relation,database_id}', "
            "physical_binding #>> '{payload,readiness_relation,schema_id}', "
            "physical_binding #>> '{payload,readiness_relation,object_id}', "
            "pg_catalog.jsonb_array_length("
            "physical_binding #> '{payload,dataset_relation,columns}'), "
            "pg_catalog.jsonb_array_length("
            "physical_binding #> '{payload,readiness_relation,columns}'), "
            "physical_binding::text, physical_binding_digest, "
            "physical_schema_digest = dataset_versions.logical_schema_digest "
            "FROM dfe_metadata.dataset_observations "
            "JOIN dfe_metadata.dataset_versions USING (dataset_version_id) "
            "WHERE run_id = %s AND attempt_id = %s AND direction = 'reference'",
            (result.run_id, result.attempt_id),
        ).fetchone()
        mssql_dataset_columns = connection.execute(
            "SELECT columns.ordinality, columns.value ->> 'field_name', "
            "(columns.value ->> 'column_id')::integer, "
            "columns.value ->> 'column_name', "
            "(columns.value ->> 'is_nullable')::boolean, "
            "columns.value #>> '{physical,system_type_name}', "
            "(columns.value #>> '{physical,system_type_id}')::integer, "
            "(columns.value #>> '{physical,user_type_id}')::integer, "
            "(columns.value #>> '{physical,max_length}')::integer, "
            "(columns.value #>> '{physical,precision}')::integer, "
            "(columns.value #>> '{physical,scale}')::integer, "
            "columns.value #>> '{physical,collation_name}' "
            "FROM dfe_metadata.dataset_observations, "
            "LATERAL pg_catalog.jsonb_array_elements("
            "physical_binding #> '{payload,dataset_relation,columns}') "
            "WITH ORDINALITY AS columns(value, ordinality) "
            "WHERE run_id = %s AND attempt_id = %s AND direction = 'reference' "
            "ORDER BY columns.ordinality",
            (result.run_id, result.attempt_id),
        ).fetchall()
        mssql_readiness_columns = connection.execute(
            "SELECT columns.ordinality, columns.value ->> 'field_name', "
            "(columns.value ->> 'column_id')::integer, "
            "columns.value ->> 'column_name', "
            "(columns.value ->> 'is_nullable')::boolean, "
            "columns.value #>> '{physical,system_type_name}', "
            "(columns.value #>> '{physical,system_type_id}')::integer, "
            "(columns.value #>> '{physical,user_type_id}')::integer, "
            "(columns.value #>> '{physical,max_length}')::integer, "
            "(columns.value #>> '{physical,precision}')::integer, "
            "(columns.value #>> '{physical,scale}')::integer, "
            "columns.value #>> '{physical,collation_name}' "
            "FROM dfe_metadata.dataset_observations, "
            "LATERAL pg_catalog.jsonb_array_elements("
            "physical_binding #> '{payload,readiness_relation,columns}') "
            "WITH ORDINALITY AS columns(value, ordinality) "
            "WHERE run_id = %s AND attempt_id = %s AND direction = 'reference' "
            "ORDER BY columns.ordinality",
            (result.run_id, result.attempt_id),
        ).fetchall()
        code_artifact_count = connection.execute(
            "SELECT pg_catalog.count(*) FROM dfe_metadata.code_artifacts"
        ).fetchone()

    assert datasets == [
        (
            "reference_orders",
            "reference_mssql",
            "mssql",
            "pyodbc",
            "mssql_2022",
            "relation",
            "physical_only",
        ),
        (
            "target_orders",
            "target_pg",
            "postgresql",
            "psycopg",
            "postgresql_17",
            "relation",
            "physical_only",
        ),
    ]
    assert len(contexts) == 2
    assert contexts[0][0:7] == (
        "reference",
        "mssql",
        "transaction_snapshot",
        None,
        1,
        "closed",
        32,
    )
    assert contexts[0][7] != ""
    assert contexts[0][7:] == (
        "5.3.0",
        "16.0.4295.3",
        16,
        contexts[0][10],
        "mssql_snapshot_relations",
        "5.3.0",
        "libmsodbcsql-18.7.so.1.1",
        "18.07.0001",
        "dfe_fixture",
        "160",
        "ON",
        "false",
        "true",
        str(contexts[0][20]),
        "1",
        "1",
        "5",
        2,
    )
    backend_process_id = contexts[0][10]
    database_id = contexts[0][20]
    assert isinstance(backend_process_id, int)
    assert isinstance(database_id, str)
    assert backend_process_id > 0
    assert int(database_id) > 0
    assert contexts[1][0] == "target"
    assert contexts[1][1] == "postgresql"
    assert contexts[1][2] == "protected_read_only_repeatable_read"
    assert contexts[1][5] == "closed"
    assert observations == [
        ("reference", "mssql", "relation_manifest", None, None, 32, 32),
        ("target", "postgresql", "relation_manifest", None, None, 32, 32),
    ]
    assert mssql_binding is not None
    assert mssql_binding[0:14] == (
        "dfe_fixture",
        "160",
        "dfe_fixture",
        "comparison_orders",
        str(contexts[0][20]),
        mssql_binding[5],
        mssql_binding[6],
        "dfe_fixture",
        "comparison_batch_manifest",
        str(contexts[0][20]),
        mssql_binding[10],
        mssql_binding[11],
        3,
        8,
    )
    for identity in (mssql_binding[5], mssql_binding[6], mssql_binding[10], mssql_binding[11]):
        assert isinstance(identity, str)
        assert int(identity) > 0
    assert mssql_binding[6] != mssql_binding[11]
    assert mssql_binding[16] is True
    assert isinstance(mssql_binding[14], str)
    assert isinstance(mssql_binding[15], bytes)
    assert hashlib.sha256(
        canonicalize_semantic_json(mssql_binding[14]).encode("utf-8")
    ).digest() == bytes(mssql_binding[15])
    assert mssql_dataset_columns == [
        (1, "order_id", 1, "order_id", False, "decimal", 106, 106, 13, 21, 2, None),
        (2, "business_date", 2, "business_date", False, "date", 40, 40, 3, 10, 0, None),
        (3, "amount", 3, "amount", True, "decimal", 106, 106, 9, 18, 2, None),
    ]
    assert mssql_readiness_columns == [
        (
            1,
            "dataset_id",
            1,
            "dataset_id",
            False,
            "nvarchar",
            231,
            231,
            256,
            0,
            0,
            "Latin1_General_100_CI_AS_SC",
        ),
        (
            2,
            "scope_digest",
            2,
            "scope_digest",
            False,
            "nvarchar",
            231,
            231,
            128,
            0,
            0,
            "Latin1_General_100_CI_AS_SC",
        ),
        (
            3,
            "batch_id",
            3,
            "batch_id",
            False,
            "nvarchar",
            231,
            231,
            256,
            0,
            0,
            "Latin1_General_100_CI_AS_SC",
        ),
        (
            4,
            "state",
            4,
            "state",
            False,
            "nvarchar",
            231,
            231,
            64,
            0,
            0,
            "Latin1_General_100_CI_AS_SC",
        ),
        (5, "business_date", 5, "business_date", False, "date", 40, 40, 3, 10, 0, None),
        (
            6,
            "source_cut",
            6,
            "source_cut",
            True,
            "nvarchar",
            231,
            231,
            256,
            0,
            0,
            "Latin1_General_100_CI_AS_SC",
        ),
        (
            7,
            "dataset_version",
            7,
            "dataset_version",
            True,
            "nvarchar",
            231,
            231,
            256,
            0,
            0,
            "Latin1_General_100_CI_AS_SC",
        ),
        (8, "completed_at", 8, "completed_at", True, "datetimeoffset", 43, 43, 10, 33, 6, None),
    ]
    assert code_artifact_count == (0,)
