# pyright: reportPrivateUsage=false

import shlex
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, date, datetime
from importlib.metadata import version
from io import StringIO
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import pq
from psycopg.conninfo import make_conninfo
from psycopg.rows import tuple_row

import forensic_data.application as application_module
from forensic_data.application import (
    DiffRequest,
    ExecuteCheckRequest,
    HistoryRequest,
    MssqlGreengageExecutionServices,
    PostgresGreengageExecutionServices,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    read_diff,
    read_history,
)
from forensic_data.canonical import LogicalType
from forensic_data.cli import run_cli
from forensic_data.comparison import CompletedComparisonArtifact
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import (
    ExecutionBudgets,
    LoadedContractConfig,
    RowCheckDefinition,
)
from forensic_data.mssql import MssqlConnectionSettings, MssqlRetryPolicy
from forensic_data.persistence.lifecycle import (
    CompletedComparisonDefinition,
    IntegerRangeFingerprintPersistence,
    PersistedInputCut,
    RunAttemptRecord,
)
from forensic_data.persistence.postgres import migrate_postgres_metadata
from forensic_data.planning import ResolvedScope, resolve_scope_values
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresRetryPolicy,
)
from forensic_data.reporting import (
    DetailAvailability,
    DifferenceKind,
    DifferenceRecord,
    EvidenceFieldValue,
    EvidenceValueAvailability,
    HistoryAttemptStatus,
    KeyAvailability,
)
from forensic_data.result import (
    ComparisonTotals,
    ExactTotal,
    ExitCode,
    Guarantee,
    ReasonCode,
    RunResult,
    Verdict,
    exit_code_for_result,
)
from tests import test_postgres_comparison_integration as pg_comparison
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.mssql_support import connect_setup_writer, required_reader_settings
from tests.postgres_support import connect_writer, required_connection_settings

pytestmark = [
    pytest.mark.integration,
    pytest.mark.greenplum,
    pytest.mark.postgres,
    pytest.mark.mssql,
]

_CONTRACT_PATH = Path(__file__).parent / "fixtures/greenplum/greengage/comparison-contract.yaml"
_BUSINESS_DATE = date(2026, 9, 23)
_OUT_OF_SCOPE_DATE = date(2026, 9, 22)
_BASELINE_COMPLETED_AT = datetime(2026, 9, 23, 12, 30, 45, 123456, tzinfo=UTC)
_CORRUPT_COMPLETED_AT = datetime(2026, 9, 23, 13, 30, 45, 123456, tzinfo=UTC)
_MUTATED_COMPLETED_AT = datetime(2026, 9, 23, 14, 30, 45, 123456, tzinfo=UTC)
_BASELINE_SOURCE_CUT = "orders-cut-baseline"
_CORRUPT_SOURCE_CUT = "orders-cut-corrupt"
_REFERENCE_BASELINE_BATCH = "reference-orders-baseline"
_TARGET_BASELINE_BATCH = "target-orders-baseline"
_REFERENCE_CORRUPT_BATCH = "reference-orders-corrupt"
_TARGET_CORRUPT_BATCH = "target-orders-corrupt"
_REFERENCE_EMPTY_TARGET_BATCH = "reference-orders-empty-target"
_TARGET_EMPTY_TARGET_BATCH = "target-orders-empty-target"
_EMPTY_TARGET_SOURCE_CUT = "orders-cut-empty-target"
_REFERENCE_FUNCTION_BATCH = "reference-orders-function-load"
_TARGET_FUNCTION_BATCH = "target-orders-function-load"
_FUNCTION_SOURCE_CUT = "orders-cut-function-load"
_PRECISE_AMOUNT = "1234567890123456789012345678901.1234567"
_PRECISE_AMOUNT_MODIFIED = "1234567890123456789012345678901.1234568"
_LOCAL_TIME = "2026-09-23T11:22:33.123456"
_INSTANT_TIME = "2026-09-23T08:22:33.123456Z"
_SCOPE_VALUES = (ScopeValue(name="business_date", value="2026-09-23"),)
_SCOPE_JSON = '{"business_date":"2026-09-23"}'
_NO_POSTGRES_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_SOURCE_POSTGRES_RETRY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)
_NO_MSSQL_RETRY = MssqlRetryPolicy(max_attempts=1, delay_seconds=0.0)

type _GreengageServices = PostgresGreengageExecutionServices | MssqlGreengageExecutionServices
type _Mutation = Callable[[], None]


def test_postgres_and_mssql_sources_to_greengage_retain_exact_endpoint_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_contract_config(_CONTRACT_PATH)
    postgres_check = _check(config, "pg_to_greengage_orders")
    mssql_check = _check(config, "mssql_to_greengage_orders")
    postgres_scope = resolve_scope_values(
        postgres_check,
        {"business_date": "2026-09-23"},
    )
    mssql_scope = resolve_scope_values(
        mssql_check,
        {"business_date": "2026-09-23"},
    )
    metadata_request = required_metadata_database_settings()
    postgres_request = pg_comparison._new_source_database_settings("reference")
    greengage_reader = pg_comparison._with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_GREENGAGE_READER_DSN",
            "dfe-greengage-endpoint-reader",
        ),
        60_000,
    )
    greengage_writer = pg_comparison._with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_GREENGAGE_WRITER_DSN",
            "dfe-greengage-endpoint-writer",
        ),
        60_000,
    )
    mssql_reader = required_reader_settings("dfe-mssql-greengage-reference").model_copy(
        update={"query_timeout_seconds": 60}
    )
    captured_full_scans: set[tuple[str, Verdict]] = set()
    persist_completed = application_module.completed_comparison_persistence_from_artifact

    def capture_full_scans(
        attempt: RunAttemptRecord,
        persisted_cut: PersistedInputCut,
        artifact: CompletedComparisonArtifact,
    ) -> tuple[
        CompletedComparisonDefinition,
        tuple[IntegerRangeFingerprintPersistence, ...],
        tuple[DifferenceRecord, ...],
    ]:
        expected_target_full_scans = 2 if artifact.verdict is Verdict.MATCH else 4
        assert artifact.target_full_scans == expected_target_full_scans
        captured_full_scans.add((artifact.check_id, artifact.verdict))
        return persist_completed(attempt, persisted_cut, artifact)

    monkeypatch.setattr(
        application_module,
        "completed_comparison_persistence_from_artifact",
        capture_full_scans,
    )

    try:
        _reset_mssql_reference(mssql_scope.scope_digest)
        _clear_greengage_target(greengage_writer)
        with (
            disposable_metadata_database(metadata_request) as metadata,
            pg_comparison._disposable_source_database(postgres_request) as postgres,
        ):
            migrate_postgres_metadata(metadata.migrator, _NO_POSTGRES_RETRY, 5_000)
            metadata_services = PostgresMetadataServices(
                connection_id=config.metadata.connection.connection_id,
                settings=metadata.reader,
                retry_policy=_NO_POSTGRES_RETRY,
            )
            _seed_postgres_reference(
                postgres,
                postgres_check.reference.dataset_id,
                postgres_scope.scope_digest,
            )
            _seed_greengage_target(
                greengage_writer,
                postgres_check.target.dataset_id,
                postgres_scope.scope_digest,
            )
            postgres_services = _postgres_services(
                metadata,
                postgres,
                greengage_reader,
                postgres_check,
            )
            _exercise_endpoint(
                config,
                postgres_check,
                postgres_scope,
                postgres_services,
                metadata,
                metadata_services,
                _cli_environment(
                    postgres.reader,
                    mssql_reader,
                    greengage_reader,
                    metadata.writer,
                ),
                lambda: _advance_postgres_reference_manifest(
                    postgres,
                    postgres_check.reference.dataset_id,
                    postgres_scope.scope_digest,
                ),
                lambda: _mutate_postgres_reference_after_publication(
                    postgres,
                    postgres_check.reference.dataset_id,
                    postgres_scope.scope_digest,
                ),
                greengage_writer,
                "postgresql",
                "psycopg",
                "postgresql_17",
                "postgresql",
                "protected_read_only_repeatable_read",
            )

            _clear_greengage_target(greengage_writer)
            _reset_mssql_reference(mssql_scope.scope_digest)
            _seed_greengage_target(
                greengage_writer,
                mssql_check.target.dataset_id,
                mssql_scope.scope_digest,
            )
            mssql_services = _mssql_services(
                metadata,
                mssql_reader,
                greengage_reader,
                mssql_check,
            )
            _exercise_endpoint(
                config,
                mssql_check,
                mssql_scope,
                mssql_services,
                metadata,
                metadata_services,
                _cli_environment(
                    postgres.reader,
                    mssql_reader,
                    greengage_reader,
                    metadata.writer,
                ),
                lambda: _advance_mssql_reference_manifest(mssql_scope.scope_digest),
                lambda: _mutate_mssql_reference_after_publication(mssql_scope.scope_digest),
                greengage_writer,
                "mssql",
                "pyodbc",
                "mssql_2022",
                "mssql",
                "transaction_snapshot",
            )
    finally:
        try:
            _clear_greengage_target(greengage_writer)
        finally:
            _cleanup_mssql_reference(mssql_scope.scope_digest)
    assert captured_full_scans == {
        (postgres_check.check_id, Verdict.MATCH),
        (postgres_check.check_id, Verdict.MISMATCH),
        (mssql_check.check_id, Verdict.MATCH),
        (mssql_check.check_id, Verdict.MISMATCH),
    }


def test_postgres_source_to_empty_greengage_target_retains_exact_missing_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_contract_config(_CONTRACT_PATH)
    check = _check(config, "pg_to_greengage_orders")
    scope = resolve_scope_values(check, {"business_date": "2026-09-23"})
    metadata_request = required_metadata_database_settings()
    postgres_request = pg_comparison._new_source_database_settings("reference")
    greengage_reader = pg_comparison._with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_GREENGAGE_READER_DSN",
            "dfe-greengage-empty-target-reader",
        ),
        60_000,
    )
    greengage_writer = pg_comparison._with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_GREENGAGE_WRITER_DSN",
            "dfe-greengage-empty-target-writer",
        ),
        60_000,
    )
    captured_artifacts: list[CompletedComparisonArtifact] = []
    persist_completed = application_module.completed_comparison_persistence_from_artifact

    def capture_artifact(
        attempt: RunAttemptRecord,
        persisted_cut: PersistedInputCut,
        artifact: CompletedComparisonArtifact,
    ) -> tuple[
        CompletedComparisonDefinition,
        tuple[IntegerRangeFingerprintPersistence, ...],
        tuple[DifferenceRecord, ...],
    ]:
        captured_artifacts.append(artifact)
        return persist_completed(attempt, persisted_cut, artifact)

    monkeypatch.setattr(
        application_module,
        "completed_comparison_persistence_from_artifact",
        capture_artifact,
    )

    _clear_greengage_target(greengage_writer)
    try:
        with (
            disposable_metadata_database(metadata_request) as metadata,
            pg_comparison._disposable_source_database(postgres_request) as postgres,
        ):
            migrate_postgres_metadata(metadata.migrator, _NO_POSTGRES_RETRY, 5_000)
            metadata_services = PostgresMetadataServices(
                connection_id=config.metadata.connection.connection_id,
                settings=metadata.reader,
                retry_policy=_NO_POSTGRES_RETRY,
            )
            _seed_single_postgres_reference(
                postgres,
                check.reference.dataset_id,
                scope.scope_digest,
            )
            _seed_empty_greengage_target_manifest(
                greengage_writer,
                check.target.dataset_id,
                scope.scope_digest,
            )
            result = execute_check(
                config,
                ExecuteCheckRequest(
                    request_id=uuid4(),
                    check_id=check.check_id,
                    scope_values=_SCOPE_VALUES,
                    reference_expected_batch_id=_REFERENCE_EMPTY_TARGET_BATCH,
                    target_expected_batch_id=_TARGET_EMPTY_TARGET_BATCH,
                    origin="greengage-empty-target-exact-integration",
                ),
                _postgres_services(metadata, postgres, greengage_reader, check),
            )
            _assert_empty_target_result(result, check, scope, config.execution)
            assert len(captured_artifacts) == 1
            artifact = captured_artifacts[0]
            assert artifact.reference_key_summary.row_count == 1
            assert artifact.reference_key_summary.minimum_key == 42
            assert artifact.reference_key_summary.maximum_key == 42
            assert artifact.target_key_summary.row_count == 0
            assert artifact.target_key_summary.minimum_key is None
            assert artifact.target_key_summary.maximum_key is None
            assert artifact.reference_full_scans == 3
            assert artifact.target_full_scans == 3

            _mutate_single_postgres_reference_after_publication(
                postgres,
                check.reference.dataset_id,
                scope.scope_digest,
            )
            _assert_persisted_endpoint_provenance(
                metadata.reader,
                result,
                check,
                "postgresql",
                "psycopg",
                "postgresql_17",
                "postgresql",
                "protected_read_only_repeatable_read",
            )
            _assert_empty_target_history_and_difference(
                metadata_services,
                check,
                scope,
                result,
            )
    finally:
        _clear_greengage_target(greengage_writer)


def test_writer_functions_publish_atomic_miniature_batch_for_read_only_dfe() -> None:
    config = load_contract_config(_CONTRACT_PATH)
    check = _check(config, "pg_to_greengage_orders")
    scope = resolve_scope_values(check, {"business_date": "2026-09-23"})
    metadata_request = required_metadata_database_settings()
    postgres_request = pg_comparison._new_source_database_settings("reference")
    greengage_reader = pg_comparison._with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_GREENGAGE_READER_DSN",
            "dfe-greengage-function-load-reader",
        ),
        60_000,
    )
    greengage_writer = pg_comparison._with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_GREENGAGE_WRITER_DSN",
            "dfe-greengage-function-load-writer",
        ),
        60_000,
    )

    _clear_greengage_target(greengage_writer)
    try:
        with (
            disposable_metadata_database(metadata_request) as metadata,
            pg_comparison._disposable_source_database(postgres_request) as postgres,
        ):
            migrate_postgres_metadata(metadata.migrator, _NO_POSTGRES_RETRY, 5_000)
            metadata_services = PostgresMetadataServices(
                connection_id=config.metadata.connection.connection_id,
                settings=metadata.reader,
                retry_policy=_NO_POSTGRES_RETRY,
            )
            _create_postgres_function_load_fixture(postgres.writer)
            _assert_postgres_function_catalog(postgres.writer)
            _assert_postgres_function_rollback(
                postgres.writer,
                check.reference.dataset_id,
                scope.scope_digest,
            )
            _assert_greengage_function_rollback(
                greengage_writer,
                check.target.dataset_id,
                scope.scope_digest,
            )
            _assert_postgres_reader_write_denials(
                postgres.reader,
                check.reference.dataset_id,
                scope.scope_digest,
            )
            _assert_greengage_reader_write_denials(
                greengage_reader,
                check.target.dataset_id,
                scope.scope_digest,
            )
            _publish_postgres_function_batch(
                postgres.writer,
                postgres.reader,
                check.reference.dataset_id,
                scope.scope_digest,
            )
            _publish_greengage_function_batch(
                greengage_writer,
                greengage_reader,
                check.target.dataset_id,
                scope.scope_digest,
            )

            result = execute_check(
                config,
                ExecuteCheckRequest(
                    request_id=uuid4(),
                    check_id=check.check_id,
                    scope_values=_SCOPE_VALUES,
                    reference_expected_batch_id=_REFERENCE_FUNCTION_BATCH,
                    target_expected_batch_id=_TARGET_FUNCTION_BATCH,
                    origin="greengage-function-load-exact-integration",
                ),
                _postgres_services(metadata, postgres, greengage_reader, check),
            )
            _assert_function_load_result(result, check, scope, config.execution)

            _mutate_function_postgres_reference_after_publication(
                postgres,
                check.reference.dataset_id,
                scope.scope_digest,
            )
            _assert_persisted_endpoint_provenance(
                metadata.reader,
                result,
                check,
                "postgresql",
                "psycopg",
                "postgresql_17",
                "postgresql",
                "protected_read_only_repeatable_read",
            )
            _assert_function_load_history_and_difference(
                metadata_services,
                check,
                scope,
                result,
            )
    finally:
        _clear_greengage_target(greengage_writer)


def _exercise_endpoint(
    config: LoadedContractConfig,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    services: _GreengageServices,
    metadata: MetadataDatabaseSettings,
    metadata_services: PostgresMetadataServices,
    cli_environment: dict[str, str],
    advance_reference_manifest: _Mutation,
    mutate_reference_after_publication: _Mutation,
    greengage_writer: PostgresConnectionSettings,
    expected_reference_adapter: str,
    expected_reference_driver: str,
    expected_reference_profile: str,
    expected_reference_engine: str,
    expected_reference_strategy: str,
) -> None:
    baseline_request_id = uuid4()
    baseline_exit, baseline_stdout, baseline_stderr = _invoke_cli(
        (
            "check",
            "--config",
            str(_CONTRACT_PATH),
            "--check",
            check.check_id,
            "--scope-json",
            _SCOPE_JSON,
            "--reference-batch",
            _REFERENCE_BASELINE_BATCH,
            "--target-batch",
            _TARGET_BASELINE_BATCH,
            "--request-id",
            str(baseline_request_id),
            "--output",
            "json",
        ),
        cli_environment,
    )
    assert baseline_exit == int(ExitCode.MATCH), (baseline_stdout, baseline_stderr)
    assert baseline_stderr == ""
    baseline = RunResult.model_validate_json(baseline_stdout)
    baseline_request = ExecuteCheckRequest(
        request_id=baseline_request_id,
        check_id=check.check_id,
        scope_values=_SCOPE_VALUES,
        reference_expected_batch_id=_REFERENCE_BASELINE_BATCH,
        target_expected_batch_id=_TARGET_BASELINE_BATCH,
        origin="cli",
    )
    assert execute_check(config, baseline_request, services) == baseline
    pg_comparison._assert_baseline_result(baseline, check, scope, config.execution)

    advance_reference_manifest()
    _corrupt_greengage_target(
        greengage_writer,
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
            origin="greengage-endpoint-integration",
        ),
        services,
    )
    assert corrupt.run_id != baseline.run_id
    assert corrupt.attempt_id != baseline.attempt_id
    pg_comparison._assert_corrupt_result(corrupt, check, scope, config.execution)
    _assert_persisted_endpoint_provenance(
        metadata.reader,
        corrupt,
        check,
        expected_reference_adapter,
        expected_reference_driver,
        expected_reference_profile,
        expected_reference_engine,
        expected_reference_strategy,
    )

    mutate_reference_after_publication()
    _assert_historical_results_and_evidence(
        metadata_services,
        check,
        scope,
        baseline,
        corrupt,
    )


def _check(config: LoadedContractConfig, check_id: str) -> RowCheckDefinition:
    matches = tuple(check for check in config.checks if check.check_id == check_id)
    if len(matches) != 1:
        raise AssertionError(
            "Greengage endpoint fixture must define exactly one requested check: "
            f"check_id={check_id!r}, matches={len(matches)}"
        )
    return matches[0]


def _postgres_services(
    metadata: MetadataDatabaseSettings,
    reference: pg_comparison._SourceDatabaseSettings,
    target: PostgresConnectionSettings,
    check: RowCheckDefinition,
) -> PostgresGreengageExecutionServices:
    return PostgresGreengageExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference.reader,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target,
        metadata_connection_id="metadata_pg",
        metadata_settings=metadata.writer,
        reference_retry_policy=_SOURCE_POSTGRES_RETRY,
        target_retry_policy=_SOURCE_POSTGRES_RETRY,
        metadata_retry_policy=_NO_POSTGRES_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        metadata_record_bytes=32_000,
        metadata_total_bytes=64_000,
    )


def _mssql_services(
    metadata: MetadataDatabaseSettings,
    reference: MssqlConnectionSettings,
    target: PostgresConnectionSettings,
    check: RowCheckDefinition,
) -> MssqlGreengageExecutionServices:
    return MssqlGreengageExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target,
        metadata_connection_id="metadata_pg",
        metadata_settings=metadata.writer,
        reference_retry_policy=_NO_MSSQL_RETRY,
        target_retry_policy=_SOURCE_POSTGRES_RETRY,
        metadata_retry_policy=_NO_POSTGRES_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        metadata_record_bytes=32_000,
        metadata_total_bytes=64_000,
    )


def _invoke_cli(
    arguments: tuple[str, ...],
    environment: dict[str, str],
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    exit_code = run_cli(arguments, environment, stdout, stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _cli_environment(
    postgres_reference: PostgresConnectionSettings,
    mssql_reference: MssqlConnectionSettings,
    greengage_target: PostgresConnectionSettings,
    metadata: PostgresConnectionSettings,
) -> dict[str, str]:
    return {
        "DFE_PG_REFERENCE_DSN": _postgres_dsn(postgres_reference),
        "DFE_MSSQL_REFERENCE_DSN": _mssql_dsn(mssql_reference),
        "DFE_GREENGAGE_TARGET_DSN": _postgres_dsn(greengage_target),
        "DFE_METADATA_DSN": _postgres_dsn(metadata),
    }


def _postgres_dsn(settings: PostgresConnectionSettings) -> str:
    return make_conninfo(
        host=settings.host,
        port=str(settings.port),
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password.get_secret_value(),
        sslmode=settings.sslmode.value,
        connect_timeout=str(settings.connect_timeout_seconds),
    )


def _mssql_dsn(settings: MssqlConnectionSettings) -> str:
    return shlex.join(
        (
            f"host={settings.host}",
            f"port={settings.port}",
            f"database={settings.database}",
            f"user={settings.user}",
            f"password={settings.password.get_secret_value()}",
            f"tls_verification={settings.tls_verification.value}",
            f"login_timeout={settings.login_timeout_seconds}",
            f"query_timeout={settings.query_timeout_seconds}",
            "cancellation_acknowledgement_timeout="
            f"{settings.cancellation_acknowledgement_timeout_seconds}",
        )
    )


def _seed_postgres_reference(
    settings: pg_comparison._SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            _create_postgres_reference_relations(connection)
            connection.execute(
                "INSERT INTO dfe_demo.source_orders ("
                "order_id, business_date, precise_amount, local_time, instant_time) "
                "SELECT dfe_seed.value * 2, %s, "
                "CASE WHEN dfe_seed.value * 2 = 1000 THEN NULL "
                "ELSE %s::numeric(38, 7) END, %s::timestamp(6), %s::timestamptz(6) "
                "FROM pg_catalog.generate_series(1, 1000) AS dfe_seed(value) "
                "UNION ALL "
                "SELECT 1000000 + dfe_seed.value, %s, %s::numeric(38, 7), "
                "%s::timestamp(6), %s::timestamptz(6) "
                "FROM pg_catalog.generate_series(1, 999000) AS dfe_seed(value)",
                (
                    _BUSINESS_DATE,
                    _PRECISE_AMOUNT,
                    _LOCAL_TIME,
                    _INSTANT_TIME,
                    _BUSINESS_DATE,
                    _PRECISE_AMOUNT,
                    _LOCAL_TIME,
                    _INSTANT_TIME,
                ),
            )
            connection.execute(
                "INSERT INTO dfe_demo.source_orders ("
                "order_id, business_date, precise_amount, local_time, instant_time) "
                "VALUES (1, %s, 900.0000000, "
                "'2026-09-22T11:22:33.123456'::timestamp(6), "
                "'2026-09-22T08:22:33.123456Z'::timestamptz(6))",
                (_OUT_OF_SCOPE_DATE,),
            )
            connection.execute("ANALYZE dfe_demo.source_orders")
            connection.execute(
                "INSERT INTO dfe_control.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                (
                    dataset_id,
                    scope_digest,
                    _REFERENCE_BASELINE_BATCH,
                    _BUSINESS_DATE,
                    _BASELINE_SOURCE_CUT,
                    "pg-reference-orders-v1",
                    _BASELINE_COMPLETED_AT,
                ),
            )
            connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_fixture_reader")
            connection.execute(
                "GRANT SELECT ON dfe_demo.source_orders, dfe_control.batch_manifest "
                "TO dfe_fixture_reader"
            )


def _seed_single_postgres_reference(
    settings: pg_comparison._SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            _create_postgres_reference_relations(connection)
            connection.execute(
                "INSERT INTO dfe_demo.source_orders ("
                "order_id, business_date, precise_amount, local_time, instant_time) "
                "VALUES (42, %s, %s::numeric(38, 7), %s::timestamp(6), %s::timestamptz(6))",
                (_BUSINESS_DATE, _PRECISE_AMOUNT, _LOCAL_TIME, _INSTANT_TIME),
            )
            connection.execute(
                "INSERT INTO dfe_control.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                (
                    dataset_id,
                    scope_digest,
                    _REFERENCE_EMPTY_TARGET_BATCH,
                    _BUSINESS_DATE,
                    _EMPTY_TARGET_SOURCE_CUT,
                    "pg-reference-orders-empty-target-v1",
                    _BASELINE_COMPLETED_AT,
                ),
            )
            connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_fixture_reader")
            connection.execute(
                "GRANT SELECT ON dfe_demo.source_orders, dfe_control.batch_manifest "
                "TO dfe_fixture_reader"
            )


def _create_postgres_reference_relations(
    connection: psycopg.Connection[DatabaseRow],
) -> None:
    connection.execute("CREATE SCHEMA dfe_demo")
    connection.execute("CREATE SCHEMA dfe_control")
    connection.execute(
        "CREATE TABLE dfe_demo.source_orders ("
        "order_id bigint PRIMARY KEY, business_date date NOT NULL, "
        "precise_amount numeric(38, 7) NULL, "
        "local_time timestamp(6) without time zone NOT NULL, "
        "instant_time timestamp(6) with time zone NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE dfe_control.batch_manifest ("
        "dataset_id text NOT NULL, scope_digest text NOT NULL, "
        "batch_id text NOT NULL, state text NOT NULL, business_date date NOT NULL, "
        "source_cut text, dataset_version text, "
        "completed_at timestamp(6) with time zone, "
        "PRIMARY KEY (dataset_id, scope_digest))"
    )


def _create_postgres_function_load_fixture(
    settings: PostgresConnectionSettings,
) -> None:
    with connect_writer(settings) as connection:
        with connection.transaction():
            _create_postgres_reference_relations(connection)
            connection.execute(
                """
                CREATE FUNCTION dfe_control.publish_miniature_orders_batch(
                  p_dataset_id text,
                  p_scope_digest text,
                  p_batch_id text,
                  p_business_date date,
                  p_source_cut text,
                  p_dataset_version text,
                  p_completed_at timestamp with time zone,
                  p_second_amount numeric
                )
                RETURNS integer
                LANGUAGE plpgsql
                VOLATILE
                SECURITY INVOKER
                SET search_path = pg_catalog
                AS $function$
                BEGIN
                  IF p_dataset_id IS NULL OR btrim(p_dataset_id) = '' THEN
                    RAISE EXCEPTION 'dataset_id must be non-null and nonblank'
                      USING ERRCODE = '22023';
                  END IF;
                  IF p_scope_digest IS NULL
                     OR p_scope_digest !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION
                      'scope_digest must be exactly 64 lowercase hexadecimal characters'
                      USING ERRCODE = '22023';
                  END IF;
                  IF p_batch_id IS NULL OR btrim(p_batch_id) = '' THEN
                    RAISE EXCEPTION 'batch_id must be non-null and nonblank'
                      USING ERRCODE = '22023';
                  END IF;
                  IF p_business_date IS NULL THEN
                    RAISE EXCEPTION 'business_date must be non-null'
                      USING ERRCODE = '22023';
                  END IF;
                  IF p_source_cut IS NULL OR btrim(p_source_cut) = '' THEN
                    RAISE EXCEPTION 'source_cut must be non-null and nonblank'
                      USING ERRCODE = '22023';
                  END IF;
                  IF p_dataset_version IS NULL OR btrim(p_dataset_version) = '' THEN
                    RAISE EXCEPTION 'dataset_version must be non-null and nonblank'
                      USING ERRCODE = '22023';
                  END IF;
                  IF p_completed_at IS NULL THEN
                    RAISE EXCEPTION 'completed_at must be non-null'
                      USING ERRCODE = '22023';
                  END IF;
                  IF p_second_amount IS NULL THEN
                    RAISE EXCEPTION 'second_amount must be non-null'
                      USING ERRCODE = '22023';
                  END IF;

                  INSERT INTO dfe_demo.source_orders (
                    order_id,
                    business_date,
                    precise_amount,
                    local_time,
                    instant_time
                  )
                  VALUES
                    (
                      701,
                      p_business_date,
                      NULL,
                      p_business_date + TIME '11:22:33.123456',
                      (p_business_date + TIME '08:22:33.123456') AT TIME ZONE 'UTC'
                    ),
                    (
                      702,
                      p_business_date,
                      p_second_amount,
                      p_business_date + TIME '11:22:33.123456',
                      (p_business_date + TIME '08:22:33.123456') AT TIME ZONE 'UTC'
                    );

                  INSERT INTO dfe_control.batch_manifest (
                    dataset_id,
                    scope_digest,
                    batch_id,
                    state,
                    business_date,
                    source_cut,
                    dataset_version,
                    completed_at
                  )
                  VALUES (
                    p_dataset_id,
                    p_scope_digest,
                    p_batch_id,
                    'complete',
                    p_business_date,
                    p_source_cut,
                    p_dataset_version,
                    p_completed_at
                  );

                  RETURN 2;
                END;
                $function$
                """
            )
            connection.execute(
                "REVOKE EXECUTE ON FUNCTION "
                "dfe_control.publish_miniature_orders_batch("
                "text, text, text, date, text, text, timestamp with time zone, numeric) "
                "FROM PUBLIC"
            )
            connection.execute(
                "REVOKE EXECUTE ON FUNCTION "
                "dfe_control.publish_miniature_orders_batch("
                "text, text, text, date, text, text, timestamp with time zone, numeric) "
                "FROM dfe_fixture_reader"
            )
            connection.execute(
                "GRANT EXECUTE ON FUNCTION "
                "dfe_control.publish_miniature_orders_batch("
                "text, text, text, date, text, text, timestamp with time zone, numeric) "
                "TO dfe_fixture_writer"
            )
            connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_fixture_reader")
            connection.execute(
                "GRANT SELECT ON dfe_demo.source_orders, dfe_control.batch_manifest "
                "TO dfe_fixture_reader"
            )


def _assert_postgres_function_catalog(settings: PostgresConnectionSettings) -> None:
    with connect_writer(settings) as connection:
        observed = connection.execute(
            "SELECT pg_get_userbyid(p.proowner), p.prorettype = 'integer'::regtype, "
            "l.lanname, p.provolatile, p.prosecdef, p.proconfig, "
            "has_function_privilege('dfe_fixture_writer', p.oid, 'EXECUTE'), "
            "has_function_privilege('dfe_fixture_reader', p.oid, 'EXECUTE'), "
            "NOT EXISTS ("
            "SELECT 1 FROM pg_catalog.aclexplode("
            "COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) AS privilege "
            "WHERE privilege.privilege_type = 'EXECUTE' "
            "AND privilege.grantee <> ("
            "SELECT oid FROM pg_catalog.pg_roles "
            "WHERE rolname = 'dfe_fixture_writer')) "
            "FROM pg_catalog.pg_proc AS p "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace "
            "JOIN pg_catalog.pg_language AS l ON l.oid = p.prolang "
            "WHERE n.nspname = 'dfe_control' "
            "AND p.proname = 'publish_miniature_orders_batch' "
            "AND p.proargtypes = "
            "'25 25 25 1082 25 25 1184 1700'::pg_catalog.oidvector"
        ).fetchone()
    assert observed == (
        "dfe_fixture_writer",
        True,
        "plpgsql",
        "v",
        False,
        ["search_path=pg_catalog"],
        True,
        False,
        True,
    )


def _call_postgres_load_function(
    cursor: psycopg.Cursor[DatabaseRow],
    dataset_id: str,
    scope_digest: str,
    batch_id: str,
    second_amount: str,
) -> DatabaseRow:
    cursor.execute(
        "SELECT dfe_control.publish_miniature_orders_batch("
        "%s, %s, %s, %s, %s, %s, %s, %s::numeric(38, 7))",
        (
            dataset_id,
            scope_digest,
            batch_id,
            _BUSINESS_DATE,
            _FUNCTION_SOURCE_CUT,
            "pg-reference-orders-function-v1",
            _BASELINE_COMPLETED_AT,
            second_amount,
        ),
    )
    result = cursor.fetchone()
    if result is None:
        raise AssertionError("PostgreSQL miniature-load function returned no result row")
    return result


def _call_greengage_load_function(
    cursor: psycopg.Cursor[DatabaseRow],
    dataset_id: str,
    scope_digest: str,
    batch_id: str,
    second_amount: str,
) -> DatabaseRow:
    cursor.execute(
        "SELECT dfe_endpoint.publish_miniature_orders_batch("
        "%s, %s, %s, %s, %s, %s, %s, %s::numeric(38, 7))",
        (
            dataset_id,
            scope_digest,
            batch_id,
            _BUSINESS_DATE,
            _FUNCTION_SOURCE_CUT,
            "greengage-target-orders-function-v1",
            _BASELINE_COMPLETED_AT,
            second_amount,
        ),
    )
    result = cursor.fetchone()
    if result is None:
        raise AssertionError("Greengage miniature-load function returned no result row")
    return result


def _postgres_publication_state(
    cursor: psycopg.Cursor[DatabaseRow],
    dataset_id: str,
    scope_digest: str,
) -> DatabaseRow:
    cursor.execute(
        "SELECT "
        "(SELECT count(*) FROM dfe_demo.source_orders "
        "WHERE business_date = %s AND order_id IN (701, 702)), "
        "(SELECT count(*) FROM dfe_control.batch_manifest "
        "WHERE dataset_id = %s AND scope_digest = %s)",
        (_BUSINESS_DATE, dataset_id, scope_digest),
    )
    result = cursor.fetchone()
    if result is None:
        raise AssertionError("PostgreSQL publication-state query returned no result row")
    return result


def _greengage_publication_state(
    cursor: psycopg.Cursor[DatabaseRow],
    dataset_id: str,
    scope_digest: str,
) -> DatabaseRow:
    cursor.execute(
        "SELECT "
        "(SELECT count(*) FROM dfe_endpoint.target_orders "
        "WHERE business_date = %s AND order_id IN (701, 702)), "
        "(SELECT count(*) FROM dfe_endpoint.batch_manifest "
        "WHERE dataset_id = %s AND scope_digest = %s)",
        (_BUSINESS_DATE, dataset_id, scope_digest),
    )
    result = cursor.fetchone()
    if result is None:
        raise AssertionError("Greengage publication-state query returned no result row")
    return result


def _assert_postgres_function_rollback(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            cursor.execute(
                "INSERT INTO dfe_control.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, 'postgres-function-atomicity-marker', 'blocked', "
                "%s, 'orders-cut-function-marker', "
                "'pg-reference-orders-function-marker', %s)",
                (dataset_id, scope_digest, _BUSINESS_DATE, _CORRUPT_COMPLETED_AT),
            )
            connection.commit()

            _configure_fixture_write(cursor)
            try:
                with pytest.raises(psycopg.errors.UniqueViolation) as failure:
                    _call_postgres_load_function(
                        cursor,
                        dataset_id,
                        scope_digest,
                        _REFERENCE_FUNCTION_BATCH,
                        _PRECISE_AMOUNT,
                    )
                assert failure.value.sqlstate == "23505"
            finally:
                connection.rollback()

            _configure_fixture_write(cursor)
            assert _postgres_publication_state(cursor, dataset_id, scope_digest) == (0, 1)
            cursor.execute(
                "SELECT batch_id, state, business_date, source_cut, dataset_version, "
                "completed_at FROM dfe_control.batch_manifest "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (dataset_id, scope_digest),
            )
            assert cursor.fetchone() == (
                "postgres-function-atomicity-marker",
                "blocked",
                _BUSINESS_DATE,
                "orders-cut-function-marker",
                "pg-reference-orders-function-marker",
                _CORRUPT_COMPLETED_AT,
            )
            cursor.execute(
                "DELETE FROM dfe_control.batch_manifest "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (dataset_id, scope_digest),
            )
            connection.commit()


def _assert_greengage_function_rollback(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            cursor.execute(
                "INSERT INTO dfe_endpoint.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, 'greengage-function-atomicity-marker', 'blocked', "
                "%s, 'orders-cut-function-marker', "
                "'greengage-target-orders-function-marker', %s)",
                (dataset_id, scope_digest, _BUSINESS_DATE, _CORRUPT_COMPLETED_AT),
            )
            connection.commit()

            _configure_fixture_write(cursor)
            try:
                with pytest.raises(psycopg.errors.UniqueViolation) as failure:
                    _call_greengage_load_function(
                        cursor,
                        dataset_id,
                        scope_digest,
                        _TARGET_FUNCTION_BATCH,
                        _PRECISE_AMOUNT_MODIFIED,
                    )
                assert failure.value.sqlstate == "23505"
            finally:
                connection.rollback()

            _configure_fixture_write(cursor)
            assert _greengage_publication_state(cursor, dataset_id, scope_digest) == (0, 1)
            cursor.execute(
                "SELECT batch_id, state, business_date, source_cut, dataset_version, "
                "completed_at FROM dfe_endpoint.batch_manifest "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (dataset_id, scope_digest),
            )
            assert cursor.fetchone() == (
                "greengage-function-atomicity-marker",
                "blocked",
                _BUSINESS_DATE,
                "orders-cut-function-marker",
                "greengage-target-orders-function-marker",
                _CORRUPT_COMPLETED_AT,
            )
            cursor.execute(
                "DELETE FROM dfe_endpoint.batch_manifest "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (dataset_id, scope_digest),
            )
            connection.commit()


def _assert_postgres_reader_write_denials(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            try:
                with pytest.raises(psycopg.errors.InsufficientPrivilege) as direct_denial:
                    cursor.execute(
                        "INSERT INTO dfe_demo.source_orders ("
                        "order_id, business_date, precise_amount, local_time, instant_time) "
                        "VALUES (799, %s, %s::numeric(38, 7), %s::timestamp(6), "
                        "%s::timestamptz(6))",
                        (_BUSINESS_DATE, _PRECISE_AMOUNT, _LOCAL_TIME, _INSTANT_TIME),
                    )
                assert direct_denial.value.sqlstate == "42501"
            finally:
                connection.rollback()

            _configure_fixture_write(cursor)
            try:
                with pytest.raises(psycopg.errors.InsufficientPrivilege) as function_denial:
                    _call_postgres_load_function(
                        cursor,
                        dataset_id,
                        scope_digest,
                        _REFERENCE_FUNCTION_BATCH,
                        _PRECISE_AMOUNT,
                    )
                assert function_denial.value.sqlstate == "42501"
            finally:
                connection.rollback()

            assert _postgres_publication_state(cursor, dataset_id, scope_digest) == (0, 0)


def _assert_greengage_reader_write_denials(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            try:
                with pytest.raises(psycopg.errors.InsufficientPrivilege) as direct_denial:
                    cursor.execute(
                        "INSERT INTO dfe_endpoint.target_orders ("
                        "order_id, business_date, precise_amount, local_time, instant_time) "
                        "VALUES (799, %s, %s::numeric(38, 7), %s::timestamp(6), "
                        "%s::timestamptz(6))",
                        (_BUSINESS_DATE, _PRECISE_AMOUNT, _LOCAL_TIME, _INSTANT_TIME),
                    )
                assert direct_denial.value.sqlstate == "42501"
            finally:
                connection.rollback()

            _configure_fixture_write(cursor)
            try:
                with pytest.raises(psycopg.errors.InsufficientPrivilege) as function_denial:
                    _call_greengage_load_function(
                        cursor,
                        dataset_id,
                        scope_digest,
                        _TARGET_FUNCTION_BATCH,
                        _PRECISE_AMOUNT_MODIFIED,
                    )
                assert function_denial.value.sqlstate == "42501"
            finally:
                connection.rollback()

            assert _greengage_publication_state(cursor, dataset_id, scope_digest) == (0, 0)


def _publish_postgres_function_batch(
    writer: PostgresConnectionSettings,
    reader: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(writer) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            assert _call_postgres_load_function(
                cursor,
                dataset_id,
                scope_digest,
                _REFERENCE_FUNCTION_BATCH,
                _PRECISE_AMOUNT,
            ) == (2,)
            assert _postgres_publication_state(cursor, dataset_id, scope_digest) == (2, 1)
            with connect_writer(reader) as observer:
                with observer.cursor() as observer_cursor:
                    assert _postgres_publication_state(
                        observer_cursor,
                        dataset_id,
                        scope_digest,
                    ) == (0, 0)
            connection.commit()

    with connect_writer(reader) as observer:
        with observer.cursor() as observer_cursor:
            assert _postgres_publication_state(
                observer_cursor,
                dataset_id,
                scope_digest,
            ) == (2, 1)
            observer_cursor.execute(
                "SELECT batch_id, state, business_date, source_cut, dataset_version, "
                "completed_at FROM dfe_control.batch_manifest "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (dataset_id, scope_digest),
            )
            assert observer_cursor.fetchone() == (
                _REFERENCE_FUNCTION_BATCH,
                "complete",
                _BUSINESS_DATE,
                _FUNCTION_SOURCE_CUT,
                "pg-reference-orders-function-v1",
                _BASELINE_COMPLETED_AT,
            )


def _publish_greengage_function_batch(
    writer: PostgresConnectionSettings,
    reader: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(writer) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            assert _call_greengage_load_function(
                cursor,
                dataset_id,
                scope_digest,
                _TARGET_FUNCTION_BATCH,
                _PRECISE_AMOUNT_MODIFIED,
            ) == (2,)
            assert _greengage_publication_state(cursor, dataset_id, scope_digest) == (2, 1)
            with connect_writer(reader) as observer:
                with observer.cursor() as observer_cursor:
                    assert _greengage_publication_state(
                        observer_cursor,
                        dataset_id,
                        scope_digest,
                    ) == (0, 0)
            connection.commit()

    with connect_writer(reader) as observer:
        with observer.cursor() as observer_cursor:
            assert _greengage_publication_state(
                observer_cursor,
                dataset_id,
                scope_digest,
            ) == (2, 1)
            observer_cursor.execute(
                "SELECT batch_id, state, business_date, source_cut, dataset_version, "
                "completed_at FROM dfe_endpoint.batch_manifest "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (dataset_id, scope_digest),
            )
            assert observer_cursor.fetchone() == (
                _TARGET_FUNCTION_BATCH,
                "complete",
                _BUSINESS_DATE,
                _FUNCTION_SOURCE_CUT,
                "greengage-target-orders-function-v1",
                _BASELINE_COMPLETED_AT,
            )


def _advance_postgres_reference_manifest(
    settings: pg_comparison._SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        updated = connection.execute(
            "UPDATE dfe_control.batch_manifest SET batch_id = %s, source_cut = %s, "
            "dataset_version = %s, completed_at = %s "
            "WHERE dataset_id = %s AND scope_digest = %s",
            (
                _REFERENCE_CORRUPT_BATCH,
                _CORRUPT_SOURCE_CUT,
                "pg-reference-orders-v2",
                _CORRUPT_COMPLETED_AT,
                dataset_id,
                scope_digest,
            ),
        ).rowcount
        assert updated == 1


def _mutate_postgres_reference_after_publication(
    settings: pg_comparison._SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            updated = connection.execute(
                "UPDATE dfe_demo.source_orders SET precise_amount = CASE order_id "
                "WHEN 1000 THEN 777.7777777::numeric(38, 7) "
                "WHEN 1100 THEN 888.8888888::numeric(38, 7) END "
                "WHERE business_date = %s AND order_id IN (1000, 1100)",
                (_BUSINESS_DATE,),
            ).rowcount
            manifest_updated = connection.execute(
                "UPDATE dfe_control.batch_manifest SET batch_id = %s, source_cut = %s, "
                "dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    "reference-orders-after-publication",
                    "orders-cut-after-publication",
                    "pg-reference-orders-v3",
                    _MUTATED_COMPLETED_AT,
                    dataset_id,
                    scope_digest,
                ),
            ).rowcount
            assert (updated, manifest_updated) == (2, 1)


def _mutate_single_postgres_reference_after_publication(
    settings: pg_comparison._SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            updated = connection.execute(
                "UPDATE dfe_demo.source_orders SET precise_amount = 777.7777777::numeric(38, 7) "
                "WHERE business_date = %s AND order_id = 42",
                (_BUSINESS_DATE,),
            ).rowcount
            manifest_updated = connection.execute(
                "UPDATE dfe_control.batch_manifest SET batch_id = %s, source_cut = %s, "
                "dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    "reference-orders-empty-target-after-publication",
                    "orders-cut-empty-target-after-publication",
                    "pg-reference-orders-empty-target-v2",
                    _MUTATED_COMPLETED_AT,
                    dataset_id,
                    scope_digest,
                ),
            ).rowcount
            assert (updated, manifest_updated) == (1, 1)


def _mutate_function_postgres_reference_after_publication(
    settings: pg_comparison._SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            updated = connection.execute(
                "UPDATE dfe_demo.source_orders "
                "SET precise_amount = 777.7777777::numeric(38, 7) "
                "WHERE business_date = %s AND order_id = 702",
                (_BUSINESS_DATE,),
            ).rowcount
            manifest_updated = connection.execute(
                "UPDATE dfe_control.batch_manifest SET batch_id = %s, source_cut = %s, "
                "dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    "reference-orders-function-after-publication",
                    "orders-cut-function-after-publication",
                    "pg-reference-orders-function-v2",
                    _MUTATED_COMPLETED_AT,
                    dataset_id,
                    scope_digest,
                ),
            ).rowcount
            assert (updated, manifest_updated) == (1, 1)


def _connect_transactional_postgres(
    settings: PostgresConnectionSettings,
) -> psycopg.Connection[DatabaseRow]:
    return psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password.get_secret_value(),
        sslmode=settings.sslmode.value,
        connect_timeout=settings.connect_timeout_seconds,
        application_name=settings.application_name,
        autocommit=False,
        row_factory=tuple_row,
    )


def _configure_fixture_write(cursor: psycopg.Cursor[DatabaseRow]) -> None:
    cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
    cursor.execute("SET LOCAL statement_timeout = '60000ms'")


def _clear_greengage_target(settings: PostgresConnectionSettings) -> None:
    with _connect_transactional_postgres(settings) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            cursor.execute("DELETE FROM dfe_endpoint.target_orders")
            cursor.execute("DELETE FROM dfe_endpoint.batch_manifest")


def _seed_greengage_target(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            cursor.execute(
                "INSERT INTO dfe_endpoint.target_orders ("
                "order_id, business_date, precise_amount, local_time, instant_time) "
                "SELECT dfe_seed.value * 2, %s, "
                "CASE WHEN dfe_seed.value * 2 = 1000 THEN NULL "
                "ELSE %s::numeric(38, 7) END, %s::timestamp(6), %s::timestamptz(6) "
                "FROM pg_catalog.generate_series(1, 1000) AS dfe_seed(value) "
                "UNION ALL "
                "SELECT 1000000 + dfe_seed.value, %s, %s::numeric(38, 7), "
                "%s::timestamp(6), %s::timestamptz(6) "
                "FROM pg_catalog.generate_series(1, 999000) AS dfe_seed(value)",
                (
                    _BUSINESS_DATE,
                    _PRECISE_AMOUNT,
                    _LOCAL_TIME,
                    _INSTANT_TIME,
                    _BUSINESS_DATE,
                    _PRECISE_AMOUNT,
                    _LOCAL_TIME,
                    _INSTANT_TIME,
                ),
            )
            cursor.execute(
                "INSERT INTO dfe_endpoint.target_orders ("
                "order_id, business_date, precise_amount, local_time, instant_time) "
                "VALUES (1, %s, 900.0000000, "
                "'2026-09-22T11:22:33.123456'::timestamp(6), "
                "'2026-09-22T08:22:33.123456Z'::timestamptz(6))",
                (_OUT_OF_SCOPE_DATE,),
            )
            cursor.execute(
                "INSERT INTO dfe_endpoint.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                (
                    dataset_id,
                    scope_digest,
                    _TARGET_BASELINE_BATCH,
                    _BUSINESS_DATE,
                    _BASELINE_SOURCE_CUT,
                    "greengage-target-orders-v1",
                    _BASELINE_COMPLETED_AT,
                ),
            )


def _seed_empty_greengage_target_manifest(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            cursor.execute(
                "INSERT INTO dfe_endpoint.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                (
                    dataset_id,
                    scope_digest,
                    _TARGET_EMPTY_TARGET_BATCH,
                    _BUSINESS_DATE,
                    _EMPTY_TARGET_SOURCE_CUT,
                    "greengage-target-orders-empty-v1",
                    _BASELINE_COMPLETED_AT,
                ),
            )
            cursor.execute(
                "SELECT COUNT(*) FROM dfe_endpoint.target_orders WHERE business_date = %s",
                (_BUSINESS_DATE,),
            )
            assert cursor.fetchone() == (0,)


def _corrupt_greengage_target(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        with connection.cursor() as cursor:
            _configure_fixture_write(cursor)
            cursor.execute(
                "DELETE FROM dfe_endpoint.target_orders "
                "WHERE business_date = %s AND order_id BETWEEN 1000 AND 1040",
                (_BUSINESS_DATE,),
            )
            cursor.execute(
                "UPDATE dfe_endpoint.target_orders "
                "SET precise_amount = precise_amount + 0.0000001 "
                "WHERE business_date = %s AND order_id BETWEEN 1100 AND 1122",
                (_BUSINESS_DATE,),
            )
            cursor.execute(
                "INSERT INTO dfe_endpoint.target_orders ("
                "order_id, business_date, precise_amount, local_time, instant_time) VALUES "
                "(1201, %s, 50.0000000, %s::timestamp(6), %s::timestamptz(6)), "
                "(1203, %s, 50.0000000, %s::timestamp(6), %s::timestamptz(6)), "
                "(1205, %s, 50.0000000, %s::timestamp(6), %s::timestamptz(6)), "
                "(1207, %s, 50.0000000, %s::timestamp(6), %s::timestamptz(6))",
                (
                    _BUSINESS_DATE,
                    _LOCAL_TIME,
                    _INSTANT_TIME,
                    _BUSINESS_DATE,
                    _LOCAL_TIME,
                    _INSTANT_TIME,
                    _BUSINESS_DATE,
                    _LOCAL_TIME,
                    _INSTANT_TIME,
                    _BUSINESS_DATE,
                    _LOCAL_TIME,
                    _INSTANT_TIME,
                ),
            )
            cursor.execute(
                "UPDATE dfe_endpoint.batch_manifest SET batch_id = %s, source_cut = %s, "
                "dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    _TARGET_CORRUPT_BATCH,
                    _CORRUPT_SOURCE_CUT,
                    "greengage-target-orders-v2",
                    _CORRUPT_COMPLETED_AT,
                    dataset_id,
                    scope_digest,
                ),
            )


def _reset_mssql_reference(scope_digest: str) -> None:
    with closing(connect_setup_writer("dfe-mssql-greengage-reset")) as connection:
        with connection:
            connection.execute(
                "UPDATE [dfe_fixture].[comparison_orders] SET "
                "[amount] = CONVERT(decimal(18, 2), N'100.00'), "
                "[precise_amount] = CONVERT(decimal(38, 7), "
                "N'1234567890123456789012345678901.1234567'), "
                "[local_time] = CONVERT(datetime2(7), "
                "N'2026-09-23T11:22:33.1234560', 126), "
                "[instant_time] = CONVERT(datetimeoffset(7), "
                "N'2026-09-23T08:22:33.1234560+00:00', 127) "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23) "
                "AND [order_id] IN (1000, 1100)"
            )
            connection.execute(
                "UPDATE [dfe_fixture].[comparison_orders] SET [precise_amount] = NULL "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23) "
                "AND [order_id] = 1000"
            )
            connection.execute(
                "DELETE FROM [dfe_fixture].[comparison_batch_manifest] "
                "WHERE [dataset_id] = ? AND [scope_digest] = ?",
                "mssql_reference_orders",
                scope_digest,
            )
            connection.execute(
                "INSERT INTO [dfe_fixture].[comparison_batch_manifest] ("
                "[dataset_id], [scope_digest], [batch_id], [state], [business_date], "
                "[source_cut], [dataset_version], [completed_at]) VALUES ("
                "?, ?, ?, N'complete', CONVERT(date, N'2026-09-23', 23), ?, ?, "
                "CONVERT(datetimeoffset(6), N'2026-09-23T12:30:45.123456+00:00', 127))",
                "mssql_reference_orders",
                scope_digest,
                _REFERENCE_BASELINE_BATCH,
                _BASELINE_SOURCE_CUT,
                "mssql-reference-orders-v1",
            )
            row = connection.execute(
                "SELECT "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders] "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23)), "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders] "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23) "
                "AND [order_id] = 1000 AND [precise_amount] IS NULL), "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_batch_manifest] "
                "WHERE [dataset_id] = ? AND [scope_digest] = ? "
                "AND [batch_id] = ? AND [source_cut] = ?) ",
                "mssql_reference_orders",
                scope_digest,
                _REFERENCE_BASELINE_BATCH,
                _BASELINE_SOURCE_CUT,
            ).fetchone()
            assert row is not None
            assert tuple(row) == (1_000_000, 1, 1)


def _cleanup_mssql_reference(scope_digest: str) -> None:
    with closing(connect_setup_writer("dfe-mssql-greengage-cleanup")) as connection:
        with connection:
            connection.execute(
                "UPDATE [dfe_fixture].[comparison_orders] SET "
                "[amount] = CONVERT(decimal(18, 2), N'100.00'), "
                "[precise_amount] = CONVERT(decimal(38, 7), "
                "N'1234567890123456789012345678901.1234567'), "
                "[local_time] = CONVERT(datetime2(7), "
                "N'2026-09-23T11:22:33.1234560', 126), "
                "[instant_time] = CONVERT(datetimeoffset(7), "
                "N'2026-09-23T08:22:33.1234560+00:00', 127) "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23) "
                "AND [order_id] IN (1000, 1100)"
            )
            connection.execute(
                "DELETE FROM [dfe_fixture].[comparison_batch_manifest] "
                "WHERE [dataset_id] = ? AND [scope_digest] = ?",
                "mssql_reference_orders",
                scope_digest,
            )
            row = connection.execute(
                "SELECT "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders] "
                "WHERE [business_date] = CONVERT(date, N'2026-09-23', 23) "
                "AND [order_id] IN (1000, 1100) "
                "AND [amount] = CONVERT(decimal(18, 2), N'100.00') "
                "AND [precise_amount] = CONVERT(decimal(38, 7), "
                "N'1234567890123456789012345678901.1234567') "
                "AND [local_time] = CONVERT(datetime2(7), "
                "N'2026-09-23T11:22:33.1234560', 126) "
                "AND [instant_time] = CONVERT(datetimeoffset(7), "
                "N'2026-09-23T08:22:33.1234560+00:00', 127)), "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_batch_manifest] "
                "WHERE [dataset_id] = ? AND [scope_digest] = ?), "
                "(SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_batch_manifest] "
                "WHERE [dataset_id] = N'reference_orders')",
                "mssql_reference_orders",
                scope_digest,
            ).fetchone()
            assert row is not None
            assert tuple(row) == (2, 0, 1)


def _advance_mssql_reference_manifest(scope_digest: str) -> None:
    with closing(connect_setup_writer("dfe-mssql-greengage-advance")) as connection:
        with connection:
            updated = connection.execute(
                "UPDATE [dfe_fixture].[comparison_batch_manifest] SET "
                "[batch_id] = ?, [source_cut] = ?, [dataset_version] = ?, "
                "[completed_at] = CONVERT(datetimeoffset(6), ?, 127) "
                "WHERE [dataset_id] = ? AND [scope_digest] = ?",
                _REFERENCE_CORRUPT_BATCH,
                _CORRUPT_SOURCE_CUT,
                "mssql-reference-orders-v2",
                _CORRUPT_COMPLETED_AT.isoformat(),
                "mssql_reference_orders",
                scope_digest,
            ).rowcount
            assert updated == 1


def _mutate_mssql_reference_after_publication(scope_digest: str) -> None:
    with closing(connect_setup_writer("dfe-mssql-greengage-post-publication")) as connection:
        with connection:
            updated = connection.execute(
                "UPDATE [dfe_fixture].[comparison_orders] SET [precise_amount] = "
                "CASE [order_id] "
                "WHEN 1000 THEN CONVERT(decimal(38, 7), N'777.7777777') "
                "WHEN 1100 THEN CONVERT(decimal(38, 7), N'888.8888888') END "
                "WHERE [business_date] = ? AND [order_id] IN (1000, 1100)",
                _BUSINESS_DATE,
            ).rowcount
            manifest_updated = connection.execute(
                "UPDATE [dfe_fixture].[comparison_batch_manifest] SET "
                "[batch_id] = ?, [source_cut] = ?, [dataset_version] = ?, "
                "[completed_at] = CONVERT(datetimeoffset(6), ?, 127) "
                "WHERE [dataset_id] = ? AND [scope_digest] = ?",
                "reference-orders-after-publication",
                "orders-cut-after-publication",
                "mssql-reference-orders-v3",
                _MUTATED_COMPLETED_AT.isoformat(),
                "mssql_reference_orders",
                scope_digest,
            ).rowcount
            assert (updated, manifest_updated) == (2, 1)


def _assert_historical_results_and_evidence(
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
    assert tuple(detail.sequence for detail in first_page.details) == tuple(range(25))
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
    assert tuple(detail.sequence for detail in second_page.details) == tuple(range(25, 37))
    assert second_page.next_cursor is None
    _assert_retained_difference_details(first_page.details + second_page.details)


def _assert_empty_target_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    pg_comparison._assert_common_completed_result(result, check, scope, execution_policy)
    assert result.verdict is Verdict.MISMATCH
    assert result.guarantee is Guarantee.EXACT
    assert exit_code_for_result(result) is ExitCode.MISMATCH
    assert result.comparison_coverage.resolved_segments == 1
    assert result.comparison_coverage.pruned_segments == 0
    assert result.comparison_coverage.exact_segments == 1
    assert result.metrics.fingerprint_nodes == 1
    assert result.totals == ComparisonTotals(
        matched=ExactTotal(precision="exact", value="0"),
        missing=ExactTotal(precision="exact", value="1"),
        extra=ExactTotal(precision="exact", value="0"),
        modified=ExactTotal(precision="exact", value="0"),
    )
    assert result.evidence_coverage.found_records == 1
    assert result.evidence_coverage.found_bytes > 0
    assert result.evidence_coverage.retained_records == 1
    assert result.evidence_coverage.retained_bytes == result.evidence_coverage.found_bytes
    assert tuple(reason.code for reason in result.reasons) == (ReasonCode.DATA_MISMATCH,)


def _assert_function_load_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    pg_comparison._assert_common_completed_result(result, check, scope, execution_policy)
    assert result.verdict is Verdict.MISMATCH
    assert result.guarantee is Guarantee.EXACT
    assert exit_code_for_result(result) is ExitCode.MISMATCH
    assert result.comparison_coverage.resolved_segments == 1
    assert result.comparison_coverage.pruned_segments == 0
    assert result.comparison_coverage.exact_segments == 1
    assert result.metrics.fingerprint_nodes == 1
    assert result.totals == ComparisonTotals(
        matched=ExactTotal(precision="exact", value="1"),
        missing=ExactTotal(precision="exact", value="0"),
        extra=ExactTotal(precision="exact", value="0"),
        modified=ExactTotal(precision="exact", value="1"),
    )
    assert result.evidence_coverage.found_records == 1
    assert result.evidence_coverage.found_bytes > 0
    assert result.evidence_coverage.retained_records == 1
    assert result.evidence_coverage.retained_bytes == result.evidence_coverage.found_bytes
    assert tuple(reason.code for reason in result.reasons) == (ReasonCode.DATA_MISMATCH,)


def _assert_empty_target_history_and_difference(
    services: PostgresMetadataServices,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    result: RunResult,
) -> None:
    history = read_history(
        HistoryRequest(
            check_id=check.check_id,
            scope_digest=scope.scope_digest,
            limit=1,
            cursor=None,
        ),
        services,
    )
    assert len(history.items) == 1
    assert history.items[0].status is HistoryAttemptStatus.COMPLETED
    assert history.items[0].stored_result == result
    assert history.next_cursor is None

    page = read_diff(
        DiffRequest(
            run_id=result.run_id,
            attempt_id=result.attempt_id,
            limit=1,
            cursor=None,
        ),
        services,
    )
    assert page.detail_availability is DetailAvailability.AVAILABLE
    assert page.stored_result == result
    assert page.found_records == 1
    assert page.retained_records == 1
    assert page.next_cursor is None
    assert len(page.details) == 1
    detail = page.details[0]
    assert detail.sequence == 0
    assert detail.kind is DifferenceKind.MISSING
    assert detail.key_availability is KeyAvailability.AVAILABLE
    assert detail.omitted_field_names == ("business_date",)
    assert len(detail.key_values) == 1
    _assert_stored_value(detail.key_values[0], "order_id", LogicalType.INT64, "42")
    _assert_retained_side(detail.reference_values, _PRECISE_AMOUNT)
    assert detail.target_values == ()


def _assert_function_load_history_and_difference(
    services: PostgresMetadataServices,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    result: RunResult,
) -> None:
    history = read_history(
        HistoryRequest(
            check_id=check.check_id,
            scope_digest=scope.scope_digest,
            limit=1,
            cursor=None,
        ),
        services,
    )
    assert len(history.items) == 1
    assert history.items[0].status is HistoryAttemptStatus.COMPLETED
    assert history.items[0].stored_result == result
    assert history.next_cursor is None

    page = read_diff(
        DiffRequest(
            run_id=result.run_id,
            attempt_id=result.attempt_id,
            limit=1,
            cursor=None,
        ),
        services,
    )
    assert page.detail_availability is DetailAvailability.AVAILABLE
    assert page.stored_result == result
    assert page.found_records == 1
    assert page.retained_records == 1
    assert page.next_cursor is None
    assert len(page.details) == 1
    detail = page.details[0]
    assert detail.sequence == 0
    assert detail.kind is DifferenceKind.MODIFIED
    assert detail.key_availability is KeyAvailability.AVAILABLE
    assert detail.omitted_field_names == ("business_date",)
    assert len(detail.key_values) == 1
    _assert_stored_value(detail.key_values[0], "order_id", LogicalType.INT64, "702")
    _assert_retained_side(detail.reference_values, _PRECISE_AMOUNT)
    _assert_retained_side(detail.target_values, _PRECISE_AMOUNT_MODIFIED)


def _assert_retained_difference_details(details: tuple[DifferenceRecord, ...]) -> None:
    expected_keys = (
        tuple(range(1000, 1041, 2)) + tuple(range(1100, 1123, 2)) + (1201, 1203, 1205, 1207)
    )
    expected_kinds = (
        (DifferenceKind.MISSING,) * 21
        + (DifferenceKind.MODIFIED,) * 12
        + (DifferenceKind.EXTRA,) * 4
    )
    assert len(details) == 37
    assert tuple(detail.sequence for detail in details) == tuple(range(37))
    assert tuple(detail.kind for detail in details) == expected_kinds
    assert len({detail.key_digest for detail in details}) == 37
    for detail, expected_key in zip(details, expected_keys, strict=True):
        assert detail.key_availability is KeyAvailability.AVAILABLE
        assert detail.key_digest is not None
        assert len(detail.key_digest) == 64
        assert detail.omitted_field_names == ("business_date",)
        assert len(detail.key_values) == 1
        _assert_stored_value(
            detail.key_values[0],
            "order_id",
            LogicalType.INT64,
            str(expected_key),
        )

        reference_amount: str | None
        if detail.kind is DifferenceKind.EXTRA:
            reference_amount = None
        elif expected_key == 1000:
            reference_amount = "null"
        else:
            reference_amount = _PRECISE_AMOUNT
        target_amount: str | None
        if detail.kind is DifferenceKind.MISSING:
            target_amount = None
        elif detail.kind is DifferenceKind.MODIFIED:
            target_amount = _PRECISE_AMOUNT_MODIFIED
        else:
            target_amount = "50.0000000"
        _assert_retained_side(detail.reference_values, reference_amount)
        _assert_retained_side(detail.target_values, target_amount)


def _assert_retained_side(
    values: tuple[EvidenceFieldValue, ...],
    expected_precise_amount: str | None,
) -> None:
    if expected_precise_amount is None:
        assert values == ()
        return
    fields = {value.field_name: value for value in values}
    assert frozenset(fields) == frozenset(("precise_amount", "local_time", "instant_time"))
    precise_amount = fields["precise_amount"]
    assert precise_amount.logical_type is LogicalType.DECIMAL
    assert precise_amount.decimal_precision == 38
    assert precise_amount.decimal_scale == 7
    assert precise_amount.timestamp_precision is None
    if expected_precise_amount == "null":
        _assert_stored_null(precise_amount)
    else:
        _assert_stored_value(
            precise_amount,
            "precise_amount",
            LogicalType.DECIMAL,
            expected_precise_amount,
        )
    local_time = fields["local_time"]
    assert local_time.decimal_precision is None
    assert local_time.decimal_scale is None
    assert local_time.timestamp_precision == 6
    _assert_stored_value(
        local_time,
        "local_time",
        LogicalType.TIMESTAMP_LOCAL,
        _LOCAL_TIME,
    )
    instant_time = fields["instant_time"]
    assert instant_time.decimal_precision is None
    assert instant_time.decimal_scale is None
    assert instant_time.timestamp_precision == 6
    _assert_stored_value(
        instant_time,
        "instant_time",
        LogicalType.TIMESTAMP_INSTANT,
        _INSTANT_TIME,
    )


def _assert_stored_null(value: EvidenceFieldValue) -> None:
    assert value.availability is EvidenceValueAvailability.STORED
    assert value.raw_available
    assert value.is_null is True
    assert value.canonical_text is None
    assert value.canonical_hex is None
    assert value.unavailable_reason is None


def _assert_stored_value(
    value: EvidenceFieldValue,
    field_name: str,
    logical_type: LogicalType,
    canonical_text: str,
) -> None:
    assert value.field_name == field_name
    assert value.logical_type is logical_type
    assert value.availability is EvidenceValueAvailability.STORED
    assert value.raw_available
    assert value.is_null is False
    assert value.canonical_text == canonical_text
    assert value.canonical_hex is None
    assert value.unavailable_reason is None


def _assert_persisted_endpoint_provenance(
    metadata: PostgresConnectionSettings,
    result: RunResult,
    check: RowCheckDefinition,
    expected_reference_adapter: str,
    expected_reference_driver: str,
    expected_reference_profile: str,
    expected_reference_engine: str,
    expected_reference_strategy: str,
) -> None:
    with connect_writer(metadata) as connection:
        source = connection.execute(
            "SELECT versions.dataset_id, versions.adapter, versions.driver, versions.profile, "
            "contexts.engine, contexts.strategy, contexts.state, "
            "observations.readiness_provider_kind, "
            "pg_catalog.octet_length(observations.physical_schema_digest), "
            "pg_catalog.octet_length(observations.physical_binding_digest) "
            "FROM dfe_metadata.attempt_read_contexts AS contexts "
            "JOIN dfe_metadata.dataset_versions AS versions "
            "USING (dataset_version_id) "
            "JOIN dfe_metadata.dataset_observations AS observations "
            "USING (run_id, attempt_id, read_context_id, dataset_version_id, direction) "
            "WHERE contexts.run_id = %s AND contexts.attempt_id = %s "
            "AND contexts.direction = 'reference'",
            (result.run_id, result.attempt_id),
        ).fetchone()
        target = connection.execute(
            "SELECT versions.dataset_id, versions.adapter, versions.driver, versions.profile, "
            "contexts.engine, contexts.strategy, contexts.state, "
            "contexts.snapshot_locator IS NOT NULL, contexts.backend_process_id > 0, "
            "contexts.allowed_concurrency, contexts.acquisition_evidence ->> 'kind', "
            "contexts.acquisition_evidence #>> '{payload,profile,product}', "
            "contexts.acquisition_evidence #>> '{payload,profile,runtime_profile}', "
            "contexts.acquisition_evidence #>> '{payload,context,runtime_profile}', "
            "contexts.acquisition_evidence #>> '{payload,context,engine}', "
            "contexts.acquisition_evidence #>> '{payload,context,strategy}', "
            "(contexts.acquisition_evidence #>> "
            "'{payload,context,acquired_before_snapshot}')::boolean, "
            "contexts.acquisition_evidence #> '{payload,context,planning_settings}' = "
            '\'[{"name":"optimizer","value":"off"},'
            '{"name":"gp_enable_multiphase_agg","value":"on"},'
            '{"name":"gp_eager_two_phase_agg","value":"on"}]\'::jsonb, '
            "pg_catalog.jsonb_array_length(contexts.acquisition_evidence #> "
            "'{payload,context,relation_locks}'), "
            "NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements("
            "contexts.acquisition_evidence #> "
            "'{payload,context,relation_locks}') AS relation_lock(value) "
            "WHERE relation_lock.value ->> 'lock_mode' <> 'AccessShareLock'), "
            "pg_catalog.jsonb_array_length(contexts.acquisition_evidence #> "
            "'{payload,topology,primary_content_ids}'), "
            "pg_catalog.jsonb_array_length(contexts.acquisition_evidence #> "
            "'{payload,topology,segments}'), "
            "contexts.acquisition_evidence #>> '{payload,hash_capability,selected_strategy}', "
            "contexts.acquisition_evidence #>> '{payload,reader,user_name}', "
            "(contexts.acquisition_evidence #>> "
            "'{payload,reader,default_transaction_read_only}')::boolean, "
            "observations.readiness_provider_kind, observations.physical_binding ->> 'engine', "
            "observations.physical_binding #>> '{payload,profile,product}', "
            "observations.physical_binding #>> '{payload,profile,runtime_profile}', "
            "observations.physical_binding #>> '{payload,dataset_relation,storage_kind}', "
            "observations.physical_binding #>> "
            "'{payload,dataset_relation,storage_profile,kind}', "
            "observations.physical_binding #>> '{payload,dataset_relation,access_method}', "
            "(observations.physical_binding #>> "
            "'{payload,dataset_relation,has_distribution_policy}')::boolean, "
            "observations.physical_binding #> "
            "'{payload,dataset_relation,distribution_attribute_numbers}' = '[1]'::jsonb, "
            "(observations.physical_binding #>> "
            "'{payload,dataset_relation,reader_has_select}')::boolean, "
            "NOT (observations.physical_binding #>> "
            "'{payload,dataset_relation,reader_has_insert}')::boolean, "
            "NOT (observations.physical_binding #>> "
            "'{payload,dataset_relation,reader_has_update}')::boolean, "
            "NOT (observations.physical_binding #>> "
            "'{payload,dataset_relation,reader_has_delete}')::boolean, "
            "NOT (observations.physical_binding #>> "
            "'{payload,dataset_relation,reader_has_truncate}')::boolean, "
            "pg_catalog.jsonb_array_length(observations.physical_binding #> "
            "'{payload,dataset_relation,columns}'), "
            "pg_catalog.jsonb_array_length(observations.physical_binding #> "
            "'{payload,readiness_relation,columns}'), "
            "observations.physical_binding #>> "
            "'{payload,dataset_relation,columns,0,physical,formatted_type}', "
            "observations.physical_binding #>> "
            "'{payload,dataset_relation,columns,2,physical,formatted_type}', "
            "observations.physical_binding #>> "
            "'{payload,dataset_relation,columns,3,physical,formatted_type}', "
            "observations.physical_binding #>> "
            "'{payload,dataset_relation,columns,4,physical,formatted_type}', "
            "pg_catalog.octet_length(observations.physical_schema_digest), "
            "pg_catalog.octet_length(observations.physical_binding_digest), "
            "observations.physical_schema_digest = versions.logical_schema_digest "
            "FROM dfe_metadata.attempt_read_contexts AS contexts "
            "JOIN dfe_metadata.dataset_versions AS versions "
            "USING (dataset_version_id) "
            "JOIN dfe_metadata.dataset_observations AS observations "
            "USING (run_id, attempt_id, read_context_id, dataset_version_id, direction) "
            "WHERE contexts.run_id = %s AND contexts.attempt_id = %s "
            "AND contexts.direction = 'target'",
            (result.run_id, result.attempt_id),
        ).fetchone()
        target_provenance = connection.execute(
            "SELECT contexts.acquisition_evidence #>> '{payload,driver,driver_name}', "
            "contexts.acquisition_evidence #>> '{payload,driver,driver_version}', "
            "(contexts.acquisition_evidence #>> "
            "'{payload,driver,build_libpq_version}')::bigint, "
            "(contexts.acquisition_evidence #>> "
            "'{payload,driver,runtime_libpq_version}')::bigint, "
            "observations.physical_binding #> "
            "'{payload,dataset_relation,requested_relation}' = "
            '\'["dfe_endpoint","target_orders"]\'::jsonb, '
            "observations.physical_binding #> "
            "'{payload,dataset_relation,resolved_relation}' = "
            '\'["dfe_endpoint","target_orders"]\'::jsonb, '
            "observations.physical_binding #> "
            "'{payload,readiness_relation,requested_relation}' = "
            '\'["dfe_endpoint","batch_manifest"]\'::jsonb, '
            "observations.physical_binding #> "
            "'{payload,readiness_relation,resolved_relation}' = "
            '\'["dfe_endpoint","batch_manifest"]\'::jsonb, '
            "observations.physical_binding #>> "
            "'{payload,readiness_relation,storage_kind}', "
            "observations.physical_binding #>> "
            "'{payload,readiness_relation,storage_profile,kind}', "
            "observations.physical_binding #>> "
            "'{payload,readiness_relation,access_method}', "
            "(observations.physical_binding #>> "
            "'{payload,readiness_relation,has_distribution_policy}')::boolean, "
            "observations.physical_binding #> "
            "'{payload,readiness_relation,distribution_attribute_numbers}' = "
            "'[1,2]'::jsonb, "
            "(observations.physical_binding #>> "
            "'{payload,readiness_relation,reader_has_select}')::boolean, "
            "NOT (observations.physical_binding #>> "
            "'{payload,readiness_relation,reader_has_insert}')::boolean, "
            "NOT (observations.physical_binding #>> "
            "'{payload,readiness_relation,reader_has_update}')::boolean, "
            "NOT (observations.physical_binding #>> "
            "'{payload,readiness_relation,reader_has_delete}')::boolean, "
            "NOT (observations.physical_binding #>> "
            "'{payload,readiness_relation,reader_has_truncate}')::boolean, "
            "(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array("
            "column_binding.value ->> 'field_name', "
            "column_binding.value ->> 'column_name', "
            "column_binding.value #>> '{physical,formatted_type}') "
            "ORDER BY column_binding.ordinality) FROM pg_catalog.jsonb_array_elements("
            "observations.physical_binding #> "
            "'{payload,readiness_relation,columns}') WITH ORDINALITY "
            "AS column_binding(value, ordinality)) = "
            '\'[["dataset_id","dataset_id","text"],'
            '["scope_digest","scope_digest","text"],'
            '["batch_id","batch_id","text"],'
            '["state","state","text"],'
            '["business_date","business_date","date"],'
            '["source_cut","source_cut","text"],'
            '["dataset_version","dataset_version","text"],'
            '["completed_at","completed_at",'
            '"timestamp(6) with time zone"]]\'::jsonb '
            "FROM dfe_metadata.attempt_read_contexts AS contexts "
            "JOIN dfe_metadata.dataset_observations AS observations "
            "USING (run_id, attempt_id, read_context_id, dataset_version_id, direction) "
            "WHERE contexts.run_id = %s AND contexts.attempt_id = %s "
            "AND contexts.direction = 'target'",
            (result.run_id, result.attempt_id),
        ).fetchone()

    assert source == (
        check.reference.dataset_id,
        expected_reference_adapter,
        expected_reference_driver,
        expected_reference_profile,
        expected_reference_engine,
        expected_reference_strategy,
        "closed",
        "relation_manifest",
        32,
        32,
    )
    assert target is not None
    assert target[0:17] == (
        check.target.dataset_id,
        "greengage",
        "psycopg",
        "greengage",
        "greengage",
        "protected_read_only_repeatable_read_distributed",
        "closed",
        True,
        True,
        1,
        "greengage_protected_relations",
        "greengage",
        "greengage",
        "greengage",
        "greengage",
        "protected_read_only_repeatable_read_distributed",
        True,
    )
    assert target[17] is True
    assert target[18:27] == (
        2,
        True,
        2,
        3,
        "pg_catalog_builtin",
        "dfe_greengage_reader",
        True,
        "relation_manifest",
        "greengage",
    )
    assert isinstance(target[20], int)
    assert target[20] > 0
    assert target[27:] == (
        "greengage",
        "greengage",
        "heap",
        "heap",
        "heap",
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        5,
        8,
        "bigint",
        "numeric(38,7)",
        "timestamp(6) without time zone",
        "timestamp(6) with time zone",
        32,
        32,
        True,
    )
    assert target_provenance == (
        "psycopg",
        version("psycopg"),
        pq.__build_version__,
        pq.version(),
        True,
        True,
        True,
        True,
        "heap",
        "heap",
        "heap",
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
    )
