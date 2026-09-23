import re
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from io import StringIO
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from forensic_data.application import (
    DiffRequest,
    ExecuteCheckRequest,
    HistoryRequest,
    PlanCheckRequest,
    PostgresExecutionServices,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    plan_check,
    read_diff,
    read_history,
)
from forensic_data.cli import run_cli
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import ExecutionBudgets, RowCheckDefinition
from forensic_data.persistence.definitions import build_metadata_registration_definition
from forensic_data.persistence.errors import CompletedComparisonNotFoundError
from forensic_data.persistence.lifecycle import read_postgres_completed_comparison
from forensic_data.persistence.postgres import migrate_postgres_metadata, register_postgres_metadata
from forensic_data.planning import PlanReport, ResolvedScope, resolve_scope_values
from forensic_data.postgres import PostgresConnectionSettings, PostgresRetryPolicy
from forensic_data.reporting import (
    DetailAvailability,
    DiffPage,
    HistoryAttemptStatus,
    HistoryPage,
    StoredResultAvailability,
)
from forensic_data.result import (
    ComparisonTotals,
    ConsistencyLevel,
    ExecutionStatus,
    ExitCode,
    Guarantee,
    InferredTotal,
    PersistenceState,
    ReasonCode,
    RunResult,
    UnavailableTotal,
    Verdict,
    exit_code_for_result,
)
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.postgres_support import connect_writer, required_connection_settings

pytestmark = [pytest.mark.integration, pytest.mark.postgres]

_CONTRACT_PATH = Path(__file__).parents[1] / "examples/postgres-relation-manifest/contract.yaml"
_DATABASE_NAME_PATTERN = re.compile(r"\Adfe_comparison_(?:reference|target)_[0-9a-f]{32}\Z")
_BUSINESS_DATE = date(2026, 9, 23)
_OUT_OF_SCOPE_DATE = date(2026, 9, 22)
_BASELINE_COMPLETED_AT = datetime(2026, 9, 23, 12, 30, 45, 123456, tzinfo=UTC)
_CORRUPT_COMPLETED_AT = datetime(2026, 9, 23, 13, 30, 45, 123456, tzinfo=UTC)
_STRUCTURAL_COMPLETED_AT = datetime(2026, 9, 23, 14, 30, 45, 123456, tzinfo=UTC)
_LOSSY_COMPLETED_AT = datetime(2026, 9, 23, 15, 30, 45, 123456, tzinfo=UTC)
_BASELINE_SOURCE_CUT = "orders-cut-baseline"
_CORRUPT_SOURCE_CUT = "orders-cut-corrupt"
_STRUCTURAL_SOURCE_CUT = "orders-cut-structural"
_LOSSY_SOURCE_CUT = "orders-cut-lossy"
_REFERENCE_BASELINE_BATCH = "reference-orders-baseline"
_TARGET_BASELINE_BATCH = "target-orders-baseline"
_REFERENCE_CORRUPT_BATCH = "reference-orders-corrupt"
_TARGET_CORRUPT_BATCH = "target-orders-corrupt"
_REFERENCE_STRUCTURAL_BATCH = "reference-orders-structural"
_TARGET_STRUCTURAL_BATCH = "target-orders-structural"
_REFERENCE_LOSSY_BATCH = "reference-orders-lossy"
_TARGET_LOSSY_BATCH = "target-orders-lossy"
_NO_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_SOURCE_RETRY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)
_SCOPE_VALUES = (ScopeValue(name="business_date", value="2026-09-23"),)
_SCOPE_JSON = '{"business_date":"2026-09-23"}'


@dataclass(frozen=True, slots=True)
class _SourceDatabaseSettings:
    database_name: str
    admin: PostgresConnectionSettings
    writer: PostgresConnectionSettings
    reader: PostgresConnectionSettings


def test_postgres_application_cli_history_diff_and_structural_mismatch() -> None:
    metadata_request = required_metadata_database_settings()
    reference_request = _new_source_database_settings("reference")
    target_request = _new_source_database_settings("target")
    with (
        disposable_metadata_database(metadata_request) as metadata,
        _disposable_source_database(reference_request) as reference,
        _disposable_source_database(target_request) as target,
    ):
        migrate_postgres_metadata(metadata.migrator, _NO_RETRY, 5_000)
        config = load_contract_config(_CONTRACT_PATH)
        check = config.checks[0]
        scope = resolve_scope_values(check, {"business_date": "2026-09-23"})
        registration = register_postgres_metadata(
            metadata.writer,
            _NO_RETRY,
            build_metadata_registration_definition(config.version, check, config.evidence),
        )
        _seed_source_database(
            reference,
            "reference_orders",
            registration.reference_dataset.definition.dataset_id,
            scope.scope_digest,
            _REFERENCE_BASELINE_BATCH,
            _BASELINE_SOURCE_CUT,
            "reference-orders-v1",
            "900.00",
        )
        _seed_source_database(
            target,
            "target_orders",
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
            _TARGET_BASELINE_BATCH,
            _BASELINE_SOURCE_CUT,
            "target-orders-v1",
            "901.00",
        )
        services = _execution_services(metadata, reference, target, check)
        metadata_services = PostgresMetadataServices(
            connection_id=config.metadata.connection.connection_id,
            settings=metadata.reader,
            retry_policy=_NO_RETRY,
        )

        api_plan = plan_check(
            config,
            PlanCheckRequest(check_id=check.check_id, scope_values=_SCOPE_VALUES),
        )
        plan_exit, plan_stdout, plan_stderr = _invoke_cli(
            (
                "plan",
                "--config",
                str(_CONTRACT_PATH),
                "--check",
                check.check_id,
                "--scope-json",
                _SCOPE_JSON,
                "--output",
                "json",
            ),
            {},
        )
        assert plan_exit == 0
        assert plan_stderr == ""
        assert PlanReport.model_validate_json(plan_stdout) == api_plan

        baseline_request = ExecuteCheckRequest(
            request_id=uuid4(),
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_BASELINE_BATCH,
            target_expected_batch_id=_TARGET_BASELINE_BATCH,
            origin="api-integration",
        )
        baseline = execute_check(config, baseline_request, services)
        assert execute_check(config, baseline_request, services) == baseline
        assert (
            read_postgres_completed_comparison(
                metadata.reader,
                _NO_RETRY,
                baseline.run_id,
                baseline.attempt_id,
            )
            == baseline
        )
        _assert_baseline_result(baseline, check, scope, config.execution)

        _advance_reference_manifest(
            reference,
            registration.reference_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        _corrupt_target_and_advance_manifest(
            target,
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        corrupt_request_id = uuid4()
        corrupt_exit, corrupt_stdout, corrupt_stderr = _invoke_cli(
            (
                "check",
                "--config",
                str(_CONTRACT_PATH),
                "--check",
                check.check_id,
                "--scope-json",
                _SCOPE_JSON,
                "--reference-batch",
                _REFERENCE_CORRUPT_BATCH,
                "--target-batch",
                _TARGET_CORRUPT_BATCH,
                "--request-id",
                str(corrupt_request_id),
                "--output",
                "json",
            ),
            _cli_environment(reference, target, metadata.writer),
        )
        assert corrupt_exit == int(ExitCode.MISMATCH)
        assert corrupt_stderr == ""
        corrupt = RunResult.model_validate_json(corrupt_stdout)
        corrupt_request = ExecuteCheckRequest(
            request_id=corrupt_request_id,
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_CORRUPT_BATCH,
            target_expected_batch_id=_TARGET_CORRUPT_BATCH,
            origin="cli",
        )
        assert execute_check(config, corrupt_request, services) == corrupt
        assert (
            read_postgres_completed_comparison(
                metadata.reader,
                _NO_RETRY,
                corrupt.run_id,
                corrupt.attempt_id,
            )
            == corrupt
        )
        assert corrupt.run_id != baseline.run_id
        assert corrupt.attempt_id != baseline.attempt_id
        _assert_corrupt_result(corrupt, check, scope, config.execution)

        _revoke_source_reader_connect(reference)
        _revoke_source_reader_connect(target)
        metadata_environment = {"DFE_METADATA_DSN": _connection_dsn(metadata.reader)}
        first_history = read_history(
            HistoryRequest(
                check_id=check.check_id,
                scope_digest=scope.scope_digest,
                limit=1,
                cursor=None,
            ),
            metadata_services,
        )
        assert len(first_history.items) == 1
        assert first_history.items[0].run_id == corrupt.run_id
        assert first_history.items[0].status is HistoryAttemptStatus.COMPLETED
        assert (
            first_history.items[0].stored_result_availability is StoredResultAvailability.AVAILABLE
        )
        assert first_history.items[0].stored_result == corrupt
        assert first_history.next_cursor is not None
        history_exit, history_stdout, history_stderr = _invoke_cli(
            (
                "history",
                "--config",
                str(_CONTRACT_PATH),
                "--check",
                check.check_id,
                "--scope-json",
                _SCOPE_JSON,
                "--limit",
                "1",
                "--output",
                "json",
            ),
            metadata_environment,
        )
        assert history_exit == 0
        assert history_stderr == ""
        assert HistoryPage.model_validate_json(history_stdout) == first_history

        second_history = read_history(
            HistoryRequest(
                check_id=check.check_id,
                scope_digest=scope.scope_digest,
                limit=1,
                cursor=first_history.next_cursor,
            ),
            metadata_services,
        )
        assert len(second_history.items) == 1
        assert second_history.items[0].run_id == baseline.run_id
        assert second_history.items[0].stored_result == baseline
        assert second_history.next_cursor is None
        assert first_history.next_cursor is not None
        second_exit, second_stdout, second_stderr = _invoke_cli(
            (
                "history",
                "--config",
                str(_CONTRACT_PATH),
                "--check",
                check.check_id,
                "--scope-json",
                _SCOPE_JSON,
                "--limit",
                "1",
                "--cursor-json",
                first_history.next_cursor.model_dump_json(),
                "--output",
                "json",
            ),
            metadata_environment,
        )
        assert second_exit == 0
        assert second_stderr == ""
        assert HistoryPage.model_validate_json(second_stdout) == second_history

        diff_page = read_diff(
            DiffRequest(run_id=corrupt.run_id, attempt_id=corrupt.attempt_id, limit=25),
            metadata_services,
        )
        assert diff_page.detail_availability is DetailAvailability.NOT_RETAINED
        assert diff_page.stored_result == corrupt
        assert diff_page.found_records == 37
        assert diff_page.retained_records == 0
        assert diff_page.details == ()
        assert diff_page.next_cursor is None
        diff_exit, diff_stdout, diff_stderr = _invoke_cli(
            (
                "diff",
                "--config",
                str(_CONTRACT_PATH),
                "--run-id",
                str(corrupt.run_id),
                "--attempt-id",
                str(corrupt.attempt_id),
                "--limit",
                "25",
                "--output",
                "json",
            ),
            metadata_environment,
        )
        assert diff_exit == 0
        assert diff_stderr == ""
        assert DiffPage.model_validate_json(diff_stdout) == diff_page

        _grant_source_reader_connect(reference)
        _grant_source_reader_connect(target)
        _replace_with_structural_key_violation(
            reference,
            target,
            registration.reference_dataset.definition.dataset_id,
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        structural_request = ExecuteCheckRequest(
            request_id=uuid4(),
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_STRUCTURAL_BATCH,
            target_expected_batch_id=_TARGET_STRUCTURAL_BATCH,
            origin="api-integration",
        )
        structural = execute_check(config, structural_request, services)
        assert (
            read_postgres_completed_comparison(
                metadata.reader,
                _NO_RETRY,
                structural.run_id,
                structural.attempt_id,
            )
            == structural
        )
        _assert_structural_result(structural, check, scope, config.execution)
        _assert_attempt_has_no_segments(metadata.reader, structural.run_id, structural.attempt_id)

        _introduce_lossy_key_mapping(
            reference,
            target,
            registration.reference_dataset.definition.dataset_id,
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        lossy_request_id = uuid4()
        lossy_exit, lossy_stdout, lossy_stderr = _invoke_cli(
            (
                "check",
                "--config",
                str(_CONTRACT_PATH),
                "--check",
                check.check_id,
                "--scope-json",
                _SCOPE_JSON,
                "--reference-batch",
                _REFERENCE_LOSSY_BATCH,
                "--target-batch",
                _TARGET_LOSSY_BATCH,
                "--request-id",
                str(lossy_request_id),
                "--output",
                "json",
            ),
            _cli_environment(reference, target, metadata.writer),
        )
        assert lossy_exit == int(ExitCode.ERROR)
        assert lossy_stderr == ""
        lossy = RunResult.model_validate_json(lossy_stdout)
        lossy_request = ExecuteCheckRequest(
            request_id=lossy_request_id,
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_LOSSY_BATCH,
            target_expected_batch_id=_TARGET_LOSSY_BATCH,
            origin="cli",
        )
        assert execute_check(config, lossy_request, services) == lossy
        _assert_lossy_result(lossy, check, scope, config.execution)
        with pytest.raises(CompletedComparisonNotFoundError):
            read_postgres_completed_comparison(
                metadata.reader,
                _NO_RETRY,
                lossy.run_id,
                lossy.attempt_id,
            )
        lossy_history = read_history(
            HistoryRequest(
                check_id=check.check_id,
                scope_digest=scope.scope_digest,
                limit=1,
                cursor=None,
            ),
            metadata_services,
        )
        assert len(lossy_history.items) == 1
        assert lossy_history.items[0].attempt_id == lossy.attempt_id
        assert lossy_history.items[0].status is HistoryAttemptStatus.ERROR
        assert (
            lossy_history.items[0].stored_result_availability
            is StoredResultAvailability.NOT_CREATED
        )
        assert lossy_history.items[0].stored_result is None


def _invoke_cli(
    arguments: tuple[str, ...],
    environment: dict[str, str],
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    exit_code = run_cli(arguments, environment, stdout, stderr)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _execution_services(
    metadata: MetadataDatabaseSettings,
    reference: _SourceDatabaseSettings,
    target: _SourceDatabaseSettings,
    check: RowCheckDefinition,
) -> PostgresExecutionServices:
    return PostgresExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference.reader,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target.reader,
        metadata_connection_id="metadata_pg",
        metadata_settings=metadata.writer,
        source_retry_policy=_SOURCE_RETRY,
        metadata_retry_policy=_NO_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        metadata_record_bytes=4_096,
        metadata_total_bytes=32_768,
    )


def _cli_environment(
    reference: _SourceDatabaseSettings,
    target: _SourceDatabaseSettings,
    metadata: PostgresConnectionSettings,
) -> dict[str, str]:
    return {
        "DFE_REFERENCE_DSN": _connection_dsn(reference.reader),
        "DFE_TARGET_DSN": _connection_dsn(target.reader),
        "DFE_METADATA_DSN": _connection_dsn(metadata),
    }


def _connection_dsn(settings: PostgresConnectionSettings) -> str:
    return make_conninfo(
        host=settings.host,
        port=str(settings.port),
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password.get_secret_value(),
        sslmode=settings.sslmode.value,
        connect_timeout=str(settings.connect_timeout_seconds),
    )


def _new_source_database_settings(
    database_label: Literal["reference", "target"],
) -> _SourceDatabaseSettings:
    database_name = f"dfe_comparison_{database_label}_{uuid4().hex}"
    admin = required_connection_settings(
        "DFE_TEST_POSTGRES_ADMIN_DSN",
        f"forensic-data-comparison-{database_label}-admin",
    )
    writer = required_connection_settings(
        "DFE_TEST_POSTGRES_WRITER_DSN",
        f"forensic-data-comparison-{database_label}-writer",
    )
    reader = required_connection_settings(
        "DFE_TEST_POSTGRES_READER_DSN",
        f"forensic-data-comparison-{database_label}-reader",
    )
    return _SourceDatabaseSettings(
        database_name=database_name,
        admin=_for_database(admin, database_name),
        writer=_for_database(writer, database_name),
        reader=_with_statement_timeout(_for_database(reader, database_name), 30_000),
    )


@contextmanager
def _disposable_source_database(
    settings: _SourceDatabaseSettings,
) -> Generator[_SourceDatabaseSettings, None, None]:
    if _DATABASE_NAME_PATTERN.fullmatch(settings.database_name) is None:
        raise ValueError(
            "comparison source database name must use the generated role and UUID form"
        )
    cluster_admin = required_connection_settings(
        "DFE_TEST_POSTGRES_ADMIN_DSN",
        "forensic-data-comparison-cluster-admin",
    )
    created = False
    try:
        with connect_writer(cluster_admin) as connection:
            connection.execute(
                sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'UTF8'").format(
                    sql.Identifier(settings.database_name),
                    sql.Identifier("dfe_fixture_writer"),
                )
            )
            created = True
            connection.execute(
                sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
                    sql.Identifier(settings.database_name)
                )
            )
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}, {}").format(
                    sql.Identifier(settings.database_name),
                    sql.Identifier("dfe_fixture_writer"),
                    sql.Identifier("dfe_fixture_reader"),
                )
            )
        yield settings
    finally:
        if created:
            with connect_writer(cluster_admin) as connection:
                connection.execute(
                    sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                        sql.Identifier(settings.database_name)
                    )
                )


def _for_database(
    settings: PostgresConnectionSettings,
    database_name: str,
) -> PostgresConnectionSettings:
    return PostgresConnectionSettings(
        host=settings.host,
        port=settings.port,
        dbname=database_name,
        user=settings.user,
        password=settings.password,
        sslmode=settings.sslmode,
        connect_timeout_seconds=settings.connect_timeout_seconds,
        statement_timeout_milliseconds=settings.statement_timeout_milliseconds,
        application_name=settings.application_name,
    )


def _with_statement_timeout(
    settings: PostgresConnectionSettings,
    statement_timeout_milliseconds: int,
) -> PostgresConnectionSettings:
    return PostgresConnectionSettings(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password,
        sslmode=settings.sslmode,
        connect_timeout_seconds=settings.connect_timeout_seconds,
        statement_timeout_milliseconds=statement_timeout_milliseconds,
        application_name=settings.application_name,
    )


def _seed_source_database(
    settings: _SourceDatabaseSettings,
    relation_name: Literal["reference_orders", "target_orders"],
    dataset_id: str,
    scope_digest: str,
    batch_id: str,
    source_cut: str,
    dataset_version: str,
    sentinel_amount: str,
) -> None:
    relation = sql.Identifier("dfe_demo", relation_name)
    key_type = (
        sql.SQL("numeric(21, 2)") if relation_name == "reference_orders" else sql.SQL("bigint")
    )
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            connection.execute("CREATE SCHEMA dfe_demo")
            connection.execute("CREATE SCHEMA dfe_control")
            connection.execute(
                sql.SQL(
                    "CREATE TABLE {} ("
                    "order_id {} PRIMARY KEY, "
                    "business_date date NOT NULL, "
                    "amount numeric(18, 2) NOT NULL)"
                ).format(relation, key_type)
            )
            connection.execute(
                "CREATE TABLE dfe_control.batch_manifest ("
                "dataset_id text NOT NULL, scope_digest text NOT NULL, batch_id text NOT NULL, "
                "state text NOT NULL, business_date date NOT NULL, source_cut text, "
                "dataset_version text, completed_at timestamp(6) with time zone, "
                "PRIMARY KEY (dataset_id, scope_digest))"
            )
            connection.execute(
                sql.SQL(
                    "INSERT INTO {} (order_id, business_date, amount) "
                    "SELECT (dfe_seed.value * 2)::bigint, %s, 100.00::numeric(18, 2) "
                    "FROM pg_catalog.generate_series(1, 1000) AS dfe_seed(value) "
                    "UNION ALL "
                    "SELECT (1000000 + dfe_seed.value)::bigint, %s, "
                    "100.00::numeric(18, 2) "
                    "FROM pg_catalog.generate_series(1, 999000) AS dfe_seed(value)"
                ).format(relation),
                (_BUSINESS_DATE, _BUSINESS_DATE),
            )
            connection.execute(
                sql.SQL(
                    "INSERT INTO {} (order_id, business_date, amount) VALUES (1, %s, %s)"
                ).format(relation),
                (_OUT_OF_SCOPE_DATE, sentinel_amount),
            )
            connection.execute(sql.SQL("ANALYZE {}").format(relation))
            connection.execute(
                "INSERT INTO dfe_control.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                (
                    dataset_id,
                    scope_digest,
                    batch_id,
                    _BUSINESS_DATE,
                    source_cut,
                    dataset_version,
                    _BASELINE_COMPLETED_AT,
                ),
            )
            connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_fixture_reader")
            connection.execute(
                sql.SQL("GRANT SELECT ON {}, {} TO dfe_fixture_reader").format(
                    relation,
                    sql.Identifier("dfe_control", "batch_manifest"),
                )
            )


def _advance_reference_manifest(
    settings: _SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        connection.execute(
            "UPDATE dfe_control.batch_manifest "
            "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
            "WHERE dataset_id = %s AND scope_digest = %s",
            (
                _REFERENCE_CORRUPT_BATCH,
                _CORRUPT_SOURCE_CUT,
                "reference-orders-v2",
                _CORRUPT_COMPLETED_AT,
                dataset_id,
                scope_digest,
            ),
        )


def _corrupt_target_and_advance_manifest(
    settings: _SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            connection.execute(
                "DELETE FROM dfe_demo.target_orders "
                "WHERE business_date = %s AND order_id BETWEEN 1000 AND 1040",
                (_BUSINESS_DATE,),
            )
            connection.execute(
                "UPDATE dfe_demo.target_orders SET amount = amount + 10.00 "
                "WHERE business_date = %s AND order_id BETWEEN 1100 AND 1122",
                (_BUSINESS_DATE,),
            )
            connection.execute(
                "INSERT INTO dfe_demo.target_orders (order_id, business_date, amount) VALUES "
                "(1201, %s, 50.00), (1203, %s, 50.00), "
                "(1205, %s, 50.00), (1207, %s, 50.00)",
                (_BUSINESS_DATE, _BUSINESS_DATE, _BUSINESS_DATE, _BUSINESS_DATE),
            )
            connection.execute(
                "UPDATE dfe_control.batch_manifest "
                "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    _TARGET_CORRUPT_BATCH,
                    _CORRUPT_SOURCE_CUT,
                    "target-orders-v2",
                    _CORRUPT_COMPLETED_AT,
                    dataset_id,
                    scope_digest,
                ),
            )


def _revoke_source_reader_connect(settings: _SourceDatabaseSettings) -> None:
    cluster_admin = required_connection_settings(
        "DFE_TEST_POSTGRES_ADMIN_DSN",
        "forensic-data-comparison-revoke-source-reader",
    )
    with connect_writer(cluster_admin) as connection:
        connection.execute(
            sql.SQL("REVOKE CONNECT ON DATABASE {} FROM dfe_fixture_reader").format(
                sql.Identifier(settings.database_name)
            )
        )


def _grant_source_reader_connect(settings: _SourceDatabaseSettings) -> None:
    cluster_admin = required_connection_settings(
        "DFE_TEST_POSTGRES_ADMIN_DSN",
        "forensic-data-comparison-grant-source-reader",
    )
    with connect_writer(cluster_admin) as connection:
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO dfe_fixture_reader").format(
                sql.Identifier(settings.database_name)
            )
        )


def _replace_with_structural_key_violation(
    reference: _SourceDatabaseSettings,
    target: _SourceDatabaseSettings,
    reference_dataset_id: str,
    target_dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(reference.writer) as connection:
        with connection.transaction():
            connection.execute("TRUNCATE TABLE dfe_demo.reference_orders")
            connection.execute(
                "INSERT INTO dfe_demo.reference_orders "
                "(order_id, business_date, amount) VALUES "
                "(1, %s, 10.00), (2, %s, 20.00), (3, %s, 30.00)",
                (_BUSINESS_DATE, _BUSINESS_DATE, _BUSINESS_DATE),
            )
            connection.execute("ANALYZE dfe_demo.reference_orders")
            connection.execute(
                "UPDATE dfe_control.batch_manifest "
                "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    _REFERENCE_STRUCTURAL_BATCH,
                    _STRUCTURAL_SOURCE_CUT,
                    "reference-orders-v3",
                    _STRUCTURAL_COMPLETED_AT,
                    reference_dataset_id,
                    scope_digest,
                ),
            )
    with connect_writer(target.writer) as connection:
        with connection.transaction():
            connection.execute(
                "ALTER TABLE dfe_demo.target_orders DROP CONSTRAINT target_orders_pkey"
            )
            connection.execute(
                "ALTER TABLE dfe_demo.target_orders ALTER COLUMN order_id DROP NOT NULL"
            )
            connection.execute("TRUNCATE TABLE dfe_demo.target_orders")
            connection.execute(
                "INSERT INTO dfe_demo.target_orders "
                "(order_id, business_date, amount) VALUES "
                "(1, %s, 10.00), (2, %s, 20.00), (2, %s, 20.00), (NULL, %s, 40.00)",
                (_BUSINESS_DATE, _BUSINESS_DATE, _BUSINESS_DATE, _BUSINESS_DATE),
            )
            connection.execute("ANALYZE dfe_demo.target_orders")
            connection.execute(
                "UPDATE dfe_control.batch_manifest "
                "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    _TARGET_STRUCTURAL_BATCH,
                    _STRUCTURAL_SOURCE_CUT,
                    "target-orders-v3",
                    _STRUCTURAL_COMPLETED_AT,
                    target_dataset_id,
                    scope_digest,
                ),
            )


def _introduce_lossy_key_mapping(
    reference: _SourceDatabaseSettings,
    target: _SourceDatabaseSettings,
    reference_dataset_id: str,
    target_dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(reference.writer) as connection:
        with connection.transaction():
            connection.execute(
                "UPDATE dfe_demo.reference_orders SET order_id = 1.50 WHERE order_id = 1.00"
            )
            connection.execute("ANALYZE dfe_demo.reference_orders")
            connection.execute(
                "UPDATE dfe_control.batch_manifest "
                "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    _REFERENCE_LOSSY_BATCH,
                    _LOSSY_SOURCE_CUT,
                    "reference-orders-v4",
                    _LOSSY_COMPLETED_AT,
                    reference_dataset_id,
                    scope_digest,
                ),
            )
    with connect_writer(target.writer) as connection:
        connection.execute(
            "UPDATE dfe_control.batch_manifest "
            "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
            "WHERE dataset_id = %s AND scope_digest = %s",
            (
                _TARGET_LOSSY_BATCH,
                _LOSSY_SOURCE_CUT,
                "target-orders-v4",
                _LOSSY_COMPLETED_AT,
                target_dataset_id,
                scope_digest,
            ),
        )


def _assert_attempt_has_no_segments(
    settings: PostgresConnectionSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> None:
    with connect_writer(settings) as connection:
        row = connection.execute(
            "SELECT pg_catalog.count(*) FROM dfe_metadata.segment_fingerprints "
            "WHERE run_id = %s AND attempt_id = %s",
            (run_id, attempt_id),
        ).fetchone()
    assert row == (0,)


def _assert_common_completed_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    assert result.check_id == check.check_id
    assert result.contract_digest == check.contract_digest
    assert result.scope_digest == scope.scope_digest
    assert result.execution_status is ExecutionStatus.COMPLETED
    assert result.consistency.stable_reads is ConsistencyLevel.VERIFIED
    assert result.consistency.cut_alignment is ConsistencyLevel.VERIFIED
    assert len(result.consistency.read_context_ids) == 2
    assert result.comparison_coverage.total_partitions == 1
    assert result.comparison_coverage.covered_partitions == 1
    assert result.comparison_coverage.unresolved_segments == 0
    assert result.comparison_coverage.unresolved_reasons == ()
    assert result.evidence_coverage.retained_records == 0
    assert result.evidence_coverage.retained_bytes == 0
    assert result.metrics.queries <= execution_policy.max_queries
    assert result.metrics.fetched_records <= execution_policy.max_fetched_records
    assert result.metrics.result_bytes <= execution_policy.max_application_result_bytes
    assert result.metrics.fingerprint_nodes <= execution_policy.max_fingerprint_nodes
    assert result.metrics.coordinator_peak_bytes <= execution_policy.max_coordinator_memory_bytes
    assert result.metrics.elapsed_milliseconds <= execution_policy.run_timeout_milliseconds
    assert result.persistence.state is PersistenceState.CONFIRMED
    assert result.persistence.operation_id is not None
    assert result.persistence.reason is None


def _assert_baseline_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    _assert_common_completed_result(result, check, scope, execution_policy)
    assert result.verdict is Verdict.MATCH
    assert result.guarantee is Guarantee.FINGERPRINT
    assert exit_code_for_result(result) is ExitCode.MATCH
    assert result.comparison_coverage.pruned_segments > 0
    assert result.comparison_coverage.exact_segments == 0
    assert result.totals == ComparisonTotals(
        matched=InferredTotal(precision="inferred_under_fingerprint", value="1000000"),
        missing=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        extra=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        modified=InferredTotal(precision="inferred_under_fingerprint", value="0"),
    )
    assert result.evidence_coverage.found_records == 0
    assert result.evidence_coverage.found_bytes == 0
    assert result.reasons == ()


def _assert_corrupt_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    _assert_common_completed_result(result, check, scope, execution_policy)
    assert result.verdict is Verdict.MISMATCH
    assert result.guarantee is Guarantee.FINGERPRINT
    assert exit_code_for_result(result) is ExitCode.MISMATCH
    assert result.comparison_coverage.pruned_segments > 0
    assert result.comparison_coverage.exact_segments > 0
    assert result.totals == ComparisonTotals(
        matched=InferredTotal(precision="inferred_under_fingerprint", value="999967"),
        missing=InferredTotal(precision="inferred_under_fingerprint", value="21"),
        extra=InferredTotal(precision="inferred_under_fingerprint", value="4"),
        modified=InferredTotal(precision="inferred_under_fingerprint", value="12"),
    )
    assert result.evidence_coverage.found_records == 37
    assert result.evidence_coverage.found_bytes == 0
    assert tuple(reason.code for reason in result.reasons) == (ReasonCode.DATA_MISMATCH,)


def _assert_structural_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    _assert_common_completed_result(result, check, scope, execution_policy)
    assert result.verdict is Verdict.MISMATCH
    assert result.guarantee is Guarantee.STRUCTURAL
    assert exit_code_for_result(result) is ExitCode.MISMATCH
    assert result.comparison_coverage.resolved_segments == 1
    assert result.comparison_coverage.pruned_segments == 0
    assert result.comparison_coverage.exact_segments == 1
    unavailable = UnavailableTotal(
        precision="unavailable",
        value=None,
        reason=ReasonCode.CONTRACT_VIOLATION,
    )
    assert result.totals == ComparisonTotals(
        matched=unavailable,
        missing=unavailable,
        extra=unavailable,
        modified=unavailable,
    )
    assert result.evidence_coverage.found_records == 0
    assert result.evidence_coverage.found_bytes == 0
    assert result.metrics.queries == 2
    assert result.metrics.fetched_records == 2
    assert result.metrics.fingerprint_nodes == 0
    assert tuple(reason.code for reason in result.reasons) == (ReasonCode.CONTRACT_VIOLATION,)
    assert tuple(
        (parameter.name, parameter.value) for parameter in result.reasons[0].safe_parameters
    ) == (
        ("reference_row_count", "3"),
        ("reference_null_key_count", "0"),
        ("reference_invalid_key_count", "0"),
        ("reference_valid_key_count", "3"),
        ("reference_distinct_key_count", "3"),
        ("target_row_count", "4"),
        ("target_null_key_count", "1"),
        ("target_invalid_key_count", "0"),
        ("target_valid_key_count", "3"),
        ("target_distinct_key_count", "2"),
    )


def _assert_lossy_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    assert result.check_id == check.check_id
    assert result.contract_digest == check.contract_digest
    assert result.scope_digest == scope.scope_digest
    assert result.execution_status is ExecutionStatus.ERROR
    assert result.verdict is Verdict.MISMATCH
    assert result.guarantee is Guarantee.NOT_ESTABLISHED
    assert exit_code_for_result(result) is ExitCode.ERROR
    assert result.consistency.stable_reads is ConsistencyLevel.VERIFIED
    assert result.consistency.cut_alignment is ConsistencyLevel.VERIFIED
    assert len(result.consistency.read_context_ids) == 2
    assert result.comparison_coverage.total_partitions == 1
    assert result.comparison_coverage.covered_partitions == 0
    assert result.comparison_coverage.unresolved_segments == 1
    assert result.comparison_coverage.unresolved_reasons == (ReasonCode.LOSSY_TRANSPORT,)
    assert all(
        isinstance(total, UnavailableTotal) and total.reason is ReasonCode.LOSSY_TRANSPORT
        for total in result.totals.values()
    )
    assert result.evidence_coverage.found_records == 0
    assert result.metrics.queries == 2
    assert result.metrics.fetched_records == 2
    assert result.metrics.fingerprint_nodes == 0
    assert result.metrics.result_bytes <= execution_policy.max_application_result_bytes
    assert result.persistence.state is PersistenceState.CONFIRMED
    assert tuple(reason.code for reason in result.reasons) == (
        ReasonCode.LOSSY_TRANSPORT,
        ReasonCode.CONTRACT_VIOLATION,
    )
    assert tuple(
        (parameter.name, parameter.value) for parameter in result.reasons[1].safe_parameters
    ) == (
        ("reference_row_count", "3"),
        ("reference_null_key_count", "0"),
        ("reference_invalid_key_count", "1"),
        ("reference_valid_key_count", "2"),
        ("reference_distinct_key_count", "2"),
        ("target_row_count", "4"),
        ("target_null_key_count", "1"),
        ("target_invalid_key_count", "0"),
        ("target_valid_key_count", "3"),
        ("target_distinct_key_count", "2"),
    )
