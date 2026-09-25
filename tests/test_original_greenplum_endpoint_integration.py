# pyright: reportPrivateUsage=false

from contextlib import closing
from datetime import UTC, date, datetime
from decimal import Decimal
from io import StringIO
from pathlib import Path
from uuid import uuid4

import psycopg
import psycopg2
import pytest
from psycopg.conninfo import make_conninfo
from psycopg.rows import tuple_row
from psycopg2.extensions import connection as Psycopg2Connection

from forensic_data import application, comparison
from forensic_data.application import (
    DiffRequest,
    ExecuteCheckRequest,
    HistoryRequest,
    OriginalGreenplumGreengageExecutionServices,
    OriginalGreenplumPostgresExecutionServices,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    read_diff,
    read_history,
)
from forensic_data.cli import run_cli
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import (
    LoadedContractConfig,
    RelationManifestReadiness,
    RowCheckDefinition,
)
from forensic_data.original_greenplum_endpoint import (
    OriginalGreenplumProtectedReadContext,
    OriginalGreenplumProtectedRelationInspection,
)
from forensic_data.persistence.postgres import migrate_postgres_metadata
from forensic_data.planning import PlanDirection, ResolvedScope, resolve_scope_values
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresReadMetrics,
    PostgresRetryPolicy,
)
from forensic_data.postgres_sql import PostgresIntegerRangeRequest
from forensic_data.reporting import (
    DetailAvailability,
    DifferenceKind,
    EvidenceFieldValue,
    EvidenceValueAvailability,
    HistoryAttemptStatus,
    KeyAvailability,
)
from forensic_data.result import (
    ComparisonTotals,
    ExactTotal,
    ExecutionStatus,
    ExitCode,
    Guarantee,
    PersistenceState,
    ReasonCode,
    RunResult,
    Verdict,
    exit_code_for_result,
)
from tests import test_postgres_comparison_integration as postgres_comparison
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.postgres_support import (
    connect_writer,
    required_connection_settings,
    source_budget_attempt,
)

pytestmark = [pytest.mark.integration, pytest.mark.greenplum, pytest.mark.postgres]

_CONTRACT_PATH = (
    Path(__file__).parent / "fixtures/greenplum/original-greenplum/comparison-contract.yaml"
)
_BUSINESS_DATE = date(2026, 9, 25)
_LOCAL_TIME = datetime(2026, 9, 25, 11, 22, 33, 123456)
_INSTANT_TIME = datetime(2026, 9, 25, 8, 22, 33, 123456, tzinfo=UTC)
_COMPLETED_AT = datetime(2026, 9, 25, 12, 30, 45, 123456, tzinfo=UTC)
_MUTATED_AT = datetime(2026, 9, 25, 13, 30, 45, 123456, tzinfo=UTC)
_REFERENCE_BATCH = "p0407-original-reference-v1"
_TARGET_BATCH = "p0407-target-v1"
_SOURCE_CUT = "p0407-orders-cut-v1"
_SCOPE_VALUES = (ScopeValue(name="business_date", value="2026-09-25"),)
_SCOPE_JSON = '{"business_date":"2026-09-25"}'
_NO_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_SOURCE_RETRY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)

type _OriginalExecutionServices = (
    OriginalGreenplumPostgresExecutionServices | OriginalGreenplumGreengageExecutionServices
)


def test_original_greenplum_source_to_postgres_and_greengage_is_durable() -> None:
    config = load_contract_config(_CONTRACT_PATH)
    postgres_check = _check(config, "original_to_postgres_orders")
    greengage_check = _check(config, "original_to_greengage_orders")
    postgres_scope = resolve_scope_values(
        postgres_check,
        {"business_date": "2026-09-25"},
    )
    greengage_scope = resolve_scope_values(
        greengage_check,
        {"business_date": "2026-09-25"},
    )
    assert postgres_scope.scope_digest == greengage_scope.scope_digest

    original_reader = _with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_ORIGINAL_GREENPLUM_READER_DSN",
            "dfe-p0407-original-endpoint-reader",
        ),
        60_000,
    )
    original_writer = required_connection_settings(
        "DFE_TEST_ORIGINAL_GREENPLUM_WRITER_DSN",
        "dfe-p0407-original-endpoint-writer",
    )
    greengage_reader = _with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_GREENGAGE_READER_DSN",
            "dfe-p0407-greengage-endpoint-reader",
        ),
        60_000,
    )
    greengage_writer = required_connection_settings(
        "DFE_TEST_GREENGAGE_WRITER_DSN",
        "dfe-p0407-greengage-endpoint-writer",
    )
    metadata_request = required_metadata_database_settings()
    postgres_target_request = postgres_comparison._new_source_database_settings("target")

    _clear_original_reference(original_writer)
    _clear_greengage_target(greengage_writer)
    try:
        with (
            disposable_metadata_database(metadata_request) as metadata,
            postgres_comparison._disposable_source_database(
                postgres_target_request
            ) as postgres_target,
        ):
            migrate_postgres_metadata(metadata.migrator, _NO_RETRY, 5_000)
            _seed_original_reference(
                original_writer,
                postgres_check.reference.dataset_id,
                postgres_scope.scope_digest,
            )
            _seed_postgres_target(
                postgres_target,
                postgres_check.target.dataset_id,
                postgres_scope.scope_digest,
            )
            _seed_greengage_target(
                greengage_writer,
                greengage_check.target.dataset_id,
                greengage_scope.scope_digest,
            )

            metadata_services = PostgresMetadataServices(
                connection_id=config.metadata.connection.connection_id,
                settings=metadata.reader,
                retry_policy=_NO_RETRY,
            )
            postgres_services = _postgres_services(
                metadata,
                original_reader,
                postgres_target.reader,
                postgres_check,
            )
            greengage_services = _greengage_services(
                metadata,
                original_reader,
                greengage_reader,
                greengage_check,
            )
            _assert_empty_original_greenplum_reads(postgres_check, postgres_services)

            postgres_result = _execute_through_cli_and_api(
                config,
                postgres_check,
                postgres_scope,
                postgres_services,
                _cli_environment(
                    original_reader,
                    postgres_target.reader,
                    greengage_reader,
                    metadata.writer,
                ),
            )
            greengage_result = _execute_through_cli_and_api(
                config,
                greengage_check,
                greengage_scope,
                greengage_services,
                _cli_environment(
                    original_reader,
                    postgres_target.reader,
                    greengage_reader,
                    metadata.writer,
                ),
            )
            _assert_original_greenplum_provenance(
                metadata.reader,
                postgres_result,
                postgres_check.reference.dataset_id,
            )
            _assert_original_greenplum_provenance(
                metadata.reader,
                greengage_result,
                greengage_check.reference.dataset_id,
            )

            _mutate_original_after_publication(
                original_writer,
                postgres_check.reference.dataset_id,
                postgres_scope.scope_digest,
            )
            _mutate_target_manifest_after_publication(
                postgres_target.writer,
                postgres_check.target.dataset_id,
                postgres_scope.scope_digest,
            )
            _mutate_target_manifest_after_publication(
                greengage_writer,
                greengage_check.target.dataset_id,
                greengage_scope.scope_digest,
            )

            _assert_durable_history_and_diff(
                metadata_services,
                postgres_check,
                postgres_scope,
                postgres_result,
            )
            _assert_durable_history_and_diff(
                metadata_services,
                greengage_check,
                greengage_scope,
                greengage_result,
            )
    finally:
        try:
            _clear_original_reference(original_writer)
        finally:
            _clear_greengage_target(greengage_writer)


def _check(config: LoadedContractConfig, check_id: str) -> RowCheckDefinition:
    matches = tuple(check for check in config.checks if check.check_id == check_id)
    if len(matches) != 1:
        raise AssertionError(
            "original Greenplum endpoint fixture must define the requested check exactly once: "
            f"check_id={check_id!r}, matches={len(matches)}"
        )
    return matches[0]


def _assert_empty_original_greenplum_reads(
    check: RowCheckDefinition,
    services: OriginalGreenplumPostgresExecutionServices,
) -> None:
    readiness = check.consistency.datasets[0].readiness
    assert isinstance(readiness, RelationManifestReadiness)
    empty_scope = resolve_scope_values(check, {"business_date": "2026-09-26"})
    scope = comparison._scope_predicate_for_dataset(check, empty_scope, check.reference)
    key_indexes = tuple(
        index
        for index, field in enumerate(check.comparison_schema.schema.fields)
        if field.name == check.key[0]
    )
    assert len(key_indexes) == 1
    source_budget = source_budget_attempt()
    protected = application._open_original_greenplum_side(
        check.reference,
        readiness,
        PlanDirection.REFERENCE,
        source_budget,
        services,
    )
    context = protected.context
    relation = protected.dataset_relation
    assert isinstance(context, OriginalGreenplumProtectedReadContext)
    assert isinstance(relation, OriginalGreenplumProtectedRelationInspection)
    try:
        summary = context.read_integer_key_summary(
            relation,
            key_indexes[0],
            scope,
            1_048_576,
            1_048_576,
            1_048_576,
            source_budget.read_deadline(source_budget.effective_statement_timeout_milliseconds()),
            1,
        )
        assert (
            summary.summary.row_count,
            summary.summary.null_key_count,
            summary.summary.invalid_key_count,
            summary.summary.valid_key_count,
            summary.summary.distinct_key_count,
            summary.summary.minimum_key,
            summary.summary.maximum_key,
        ) == (0, 0, 0, 0, 0, None, None)
        assert summary.metrics.fetched_records == 1

        exact = context.read_integer_range_rows(
            relation,
            key_indexes[0],
            scope,
            (PostgresIntegerRangeRequest("empty", 0, 10),),
            1_048_576,
            1,
            1_048_576,
            1_048_576,
            source_budget.read_deadline(source_budget.effective_statement_timeout_milliseconds()),
            1,
        )
        assert exact.rows == ()
        assert exact.metrics == PostgresReadMetrics(fetched_records=0, result_bytes=0)
    finally:
        context.close()


def _execute_through_cli_and_api(
    config: LoadedContractConfig,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    services: _OriginalExecutionServices,
    environment: dict[str, str],
) -> RunResult:
    request_id = uuid4()
    stdout = StringIO()
    stderr = StringIO()
    exit_code = run_cli(
        (
            "check",
            "--config",
            str(_CONTRACT_PATH),
            "--check",
            check.check_id,
            "--scope-json",
            _SCOPE_JSON,
            "--reference-batch",
            _REFERENCE_BATCH,
            "--target-batch",
            _TARGET_BATCH,
            "--request-id",
            str(request_id),
            "--output",
            "json",
        ),
        environment,
        stdout,
        stderr,
    )
    assert stderr.getvalue() == ""
    result = RunResult.model_validate_json(stdout.getvalue())
    assert exit_code == int(exit_code_for_result(result))
    request = ExecuteCheckRequest(
        request_id=request_id,
        check_id=check.check_id,
        scope_values=_SCOPE_VALUES,
        reference_expected_batch_id=_REFERENCE_BATCH,
        target_expected_batch_id=_TARGET_BATCH,
        origin="cli",
    )
    assert execute_check(config, request, services) == result
    _assert_exact_oracle(result, check, scope)
    return result


def _assert_exact_oracle(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
) -> None:
    if result.execution_status is not ExecutionStatus.COMPLETED:
        raise AssertionError(
            tuple(
                (reason.code.value, tuple(item.value for item in reason.safe_parameters))
                for reason in result.reasons
            )
        )
    assert result.check_id == check.check_id
    assert result.contract_digest == check.contract_digest
    assert result.scope_digest == scope.scope_digest
    assert result.execution_status is ExecutionStatus.COMPLETED
    assert result.verdict is Verdict.MISMATCH
    assert result.guarantee is Guarantee.EXACT
    assert result.persistence.state is PersistenceState.CONFIRMED
    assert exit_code_for_result(result) is ExitCode.MISMATCH
    assert result.totals == ComparisonTotals(
        matched=ExactTotal(precision="exact", value="1"),
        missing=ExactTotal(precision="exact", value="1"),
        extra=ExactTotal(precision="exact", value="1"),
        modified=ExactTotal(precision="exact", value="1"),
    )
    assert result.comparison_coverage.resolved_segments == 1
    assert result.comparison_coverage.pruned_segments == 0
    assert result.comparison_coverage.exact_segments == 1
    assert result.comparison_coverage.unresolved_segments == 0
    assert result.metrics.fingerprint_nodes == 1
    assert result.evidence_coverage.found_records == 3
    assert result.evidence_coverage.retained_records == 3
    assert result.evidence_coverage.retained_bytes == result.evidence_coverage.found_bytes
    assert tuple(reason.code for reason in result.reasons) == (ReasonCode.DATA_MISMATCH,)


def _postgres_services(
    metadata: MetadataDatabaseSettings,
    reference: PostgresConnectionSettings,
    target: PostgresConnectionSettings,
    check: RowCheckDefinition,
) -> OriginalGreenplumPostgresExecutionServices:
    return OriginalGreenplumPostgresExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference,
        target_connection_id=check.target.connection.connection_id,
        target_settings=_with_statement_timeout(target, 60_000),
        metadata_connection_id="metadata_pg",
        metadata_settings=_with_statement_timeout(metadata.writer, 60_000),
        reference_retry_policy=_SOURCE_RETRY,
        target_retry_policy=_SOURCE_RETRY,
        metadata_retry_policy=_NO_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        metadata_record_bytes=1_048_576,
        metadata_total_bytes=67_108_864,
    )


def _greengage_services(
    metadata: MetadataDatabaseSettings,
    reference: PostgresConnectionSettings,
    target: PostgresConnectionSettings,
    check: RowCheckDefinition,
) -> OriginalGreenplumGreengageExecutionServices:
    return OriginalGreenplumGreengageExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target,
        metadata_connection_id="metadata_pg",
        metadata_settings=_with_statement_timeout(metadata.writer, 60_000),
        reference_retry_policy=_SOURCE_RETRY,
        target_retry_policy=_SOURCE_RETRY,
        metadata_retry_policy=_NO_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        metadata_record_bytes=1_048_576,
        metadata_total_bytes=67_108_864,
    )


def _cli_environment(
    original: PostgresConnectionSettings,
    postgres_target: PostgresConnectionSettings,
    greengage_target: PostgresConnectionSettings,
    metadata: PostgresConnectionSettings,
) -> dict[str, str]:
    return {
        "DFE_ORIGINAL_GREENPLUM_REFERENCE_DSN": _connection_dsn(original),
        "DFE_POSTGRES_TARGET_DSN": _connection_dsn(postgres_target),
        "DFE_GREENGAGE_TARGET_DSN": _connection_dsn(greengage_target),
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


def _connect_original_writer(settings: PostgresConnectionSettings) -> Psycopg2Connection:
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
    connection.autocommit = False
    return connection


def _clear_original_reference(settings: PostgresConnectionSettings) -> None:
    with closing(_connect_original_writer(settings)) as connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
                cursor.execute("SET LOCAL statement_timeout = '60000ms'")
                cursor.execute("DELETE FROM dfe_fixture.comparison_orders")
                cursor.execute("DELETE FROM dfe_fixture.comparison_batch_manifest")
            connection.commit()
        except psycopg2.Error:
            connection.rollback()
            raise


def _seed_original_reference(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    rows = (
        (1, _BUSINESS_DATE, Decimal("100.0000000"), _LOCAL_TIME, _INSTANT_TIME),
        (2, _BUSINESS_DATE, Decimal("200.0000000"), _LOCAL_TIME, _INSTANT_TIME),
        (3, _BUSINESS_DATE, None, _LOCAL_TIME, _INSTANT_TIME),
    )
    with closing(_connect_original_writer(settings)) as connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
                cursor.execute("SET LOCAL statement_timeout = '60000ms'")
                cursor.executemany(
                    "INSERT INTO dfe_fixture.comparison_orders ("
                    "order_id, business_date, precise_amount, local_time, instant_time) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    rows,
                )
                cursor.execute(
                    "INSERT INTO dfe_fixture.comparison_batch_manifest ("
                    "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                    "dataset_version, completed_at) "
                    "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                    (
                        dataset_id,
                        scope_digest,
                        _REFERENCE_BATCH,
                        _BUSINESS_DATE,
                        _SOURCE_CUT,
                        "original-reference-orders-v1",
                        _COMPLETED_AT,
                    ),
                )
            connection.commit()
        except psycopg2.Error:
            connection.rollback()
            raise


def _mutate_original_after_publication(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with closing(_connect_original_writer(settings)) as connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
                cursor.execute("SET LOCAL statement_timeout = '60000ms'")
                cursor.execute(
                    "UPDATE dfe_fixture.comparison_orders "
                    "SET precise_amount = 999.0000000 WHERE order_id = 1"
                )
                updated = cursor.rowcount
                cursor.execute(
                    "UPDATE dfe_fixture.comparison_batch_manifest SET batch_id = %s, "
                    "source_cut = %s, dataset_version = %s, completed_at = %s "
                    "WHERE dataset_id = %s AND scope_digest = %s",
                    (
                        "p0407-original-reference-v2",
                        "p0407-orders-cut-v2",
                        "original-reference-orders-v2",
                        _MUTATED_AT,
                        dataset_id,
                        scope_digest,
                    ),
                )
                manifest_updated = cursor.rowcount
                assert (updated, manifest_updated) == (1, 1)
            connection.commit()
        except (psycopg2.Error, AssertionError):
            connection.rollback()
            raise


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


def _seed_postgres_target(
    settings: postgres_comparison._SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings.writer) as connection:
        connection.execute("CREATE SCHEMA dfe_endpoint AUTHORIZATION dfe_fixture_writer")
        connection.execute(
            "CREATE TABLE dfe_endpoint.target_orders ("
            "order_id bigint PRIMARY KEY, business_date date NOT NULL, "
            "precise_amount numeric(38, 7), local_time timestamp(6) NOT NULL, "
            "instant_time timestamptz(6) NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE dfe_endpoint.batch_manifest ("
            "dataset_id text NOT NULL, scope_digest text NOT NULL, batch_id text NOT NULL, "
            "state text NOT NULL, business_date date NOT NULL, source_cut text, "
            "dataset_version text, completed_at timestamptz(6), "
            "PRIMARY KEY (dataset_id, scope_digest))"
        )
        connection.execute("GRANT USAGE ON SCHEMA dfe_endpoint TO dfe_fixture_reader")
        connection.execute(
            "GRANT SELECT ON dfe_endpoint.target_orders, "
            "dfe_endpoint.batch_manifest TO dfe_fixture_reader"
        )
        _insert_target_rows(connection, dataset_id, scope_digest, "postgres-target-orders-v1")


def _clear_greengage_target(settings: PostgresConnectionSettings) -> None:
    with _connect_transactional_postgres(settings) as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
        connection.execute("SET LOCAL statement_timeout = '60000ms'")
        connection.execute("DELETE FROM dfe_endpoint.target_orders")
        connection.execute("DELETE FROM dfe_endpoint.batch_manifest")


def _seed_greengage_target(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
        connection.execute("SET LOCAL statement_timeout = '60000ms'")
        _insert_target_rows(connection, dataset_id, scope_digest, "greengage-target-orders-v1")


def _insert_target_rows(
    connection: psycopg.Connection[DatabaseRow],
    dataset_id: str,
    scope_digest: str,
    dataset_version: str,
) -> None:
    rows = (
        (1, _BUSINESS_DATE, Decimal("100.0000000"), _LOCAL_TIME, _INSTANT_TIME),
        (2, _BUSINESS_DATE, Decimal("200.0000001"), _LOCAL_TIME, _INSTANT_TIME),
        (4, _BUSINESS_DATE, Decimal("400.0000000"), _LOCAL_TIME, _INSTANT_TIME),
    )
    with connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO dfe_endpoint.target_orders ("
            "order_id, business_date, precise_amount, local_time, instant_time) "
            "VALUES (%s, %s, %s, %s, %s)",
            rows,
        )
        cursor.execute(
            "INSERT INTO dfe_endpoint.batch_manifest ("
            "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
            "dataset_version, completed_at) "
            "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
            (
                dataset_id,
                scope_digest,
                _TARGET_BATCH,
                _BUSINESS_DATE,
                _SOURCE_CUT,
                dataset_version,
                _COMPLETED_AT,
            ),
        )


def _mutate_target_manifest_after_publication(
    settings: PostgresConnectionSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with _connect_transactional_postgres(settings) as connection:
        updated = connection.execute(
            "UPDATE dfe_endpoint.batch_manifest SET batch_id = %s, source_cut = %s, "
            "dataset_version = %s, completed_at = %s "
            "WHERE dataset_id = %s AND scope_digest = %s",
            (
                "p0407-target-v2",
                "p0407-orders-cut-v2",
                "target-orders-v2",
                _MUTATED_AT,
                dataset_id,
                scope_digest,
            ),
        ).rowcount
        assert updated == 1


def _assert_durable_history_and_diff(
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
            limit=10,
            cursor=None,
        ),
        services,
    )
    assert page.detail_availability is DetailAvailability.AVAILABLE
    assert page.stored_result == result
    assert page.found_records == 3
    assert page.retained_records == 3
    assert page.next_cursor is None
    assert tuple(detail.sequence for detail in page.details) == (0, 1, 2)
    details = {_stored_key(detail.key_values): detail for detail in page.details}
    assert {key: detail.kind for key, detail in details.items()} == {
        "2": DifferenceKind.MODIFIED,
        "3": DifferenceKind.MISSING,
        "4": DifferenceKind.EXTRA,
    }
    for detail in details.values():
        assert detail.key_availability is KeyAvailability.AVAILABLE
        assert detail.key_digest is not None
        assert detail.omitted_field_names == ("business_date",)
    assert _stored_field(details["2"].reference_values, "precise_amount").canonical_text == (
        "200.0000000"
    )
    assert _stored_field(details["2"].target_values, "precise_amount").canonical_text == (
        "200.0000001"
    )
    missing_amount = _stored_field(details["3"].reference_values, "precise_amount")
    assert missing_amount.is_null is True
    assert details["3"].target_values == ()
    assert details["4"].reference_values == ()
    assert _stored_field(details["4"].target_values, "precise_amount").canonical_text == (
        "400.0000000"
    )


def _stored_key(values: tuple[EvidenceFieldValue, ...]) -> str:
    assert len(values) == 1
    value = values[0]
    assert value.field_name == "order_id"
    assert value.availability is EvidenceValueAvailability.STORED
    assert value.canonical_text is not None
    return value.canonical_text


def _stored_field(
    values: tuple[EvidenceFieldValue, ...],
    field_name: str,
) -> EvidenceFieldValue:
    matches = tuple(value for value in values if value.field_name == field_name)
    assert len(matches) == 1
    assert matches[0].availability is EvidenceValueAvailability.STORED
    return matches[0]


def _assert_original_greenplum_provenance(
    metadata: PostgresConnectionSettings,
    result: RunResult,
    dataset_id: str,
) -> None:
    with connect_writer(metadata) as connection:
        row = connection.execute(
            "SELECT versions.dataset_id, versions.adapter, versions.driver, versions.profile, "
            "contexts.engine, contexts.strategy, contexts.state, "
            "contexts.snapshot_locator IS NOT NULL, contexts.backend_process_id > 0, "
            "contexts.allowed_concurrency, contexts.acquisition_evidence ->> 'kind', "
            "contexts.acquisition_evidence #>> '{payload,driver,driver_name}', "
            "contexts.acquisition_evidence #>> '{payload,driver,driver_version}', "
            "(contexts.acquisition_evidence #>> "
            "'{payload,driver,build_libpq_version}')::bigint, "
            "(contexts.acquisition_evidence #>> "
            "'{payload,driver,runtime_libpq_version}')::bigint, "
            "contexts.acquisition_evidence #>> '{payload,profile,product}', "
            "contexts.acquisition_evidence #>> '{payload,profile,product_version}', "
            "contexts.acquisition_evidence #>> '{payload,profile,runtime_profile}', "
            "contexts.acquisition_evidence #>> '{payload,profile,compatibility_version}', "
            "contexts.acquisition_evidence #>> '{payload,profile,transaction_isolation}', "
            "(contexts.acquisition_evidence #>> "
            "'{payload,profile,transaction_read_only}')::boolean, "
            "contexts.acquisition_evidence #>> '{payload,context,engine}', "
            "contexts.acquisition_evidence #>> '{payload,context,strategy}', "
            "(contexts.acquisition_evidence #>> "
            "'{payload,context,acquired_before_snapshot}')::boolean, "
            "pg_catalog.jsonb_array_length(contexts.acquisition_evidence #> "
            "'{payload,context,relation_locks}'), "
            "NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements("
            "contexts.acquisition_evidence #> '{payload,context,relation_locks}') "
            "AS relation_lock(value) "
            "WHERE relation_lock.value ->> 'lock_mode' <> 'AccessShareLock'), "
            "contexts.acquisition_evidence #> "
            "'{payload,topology,primary_content_ids}' = '[0,1]'::jsonb, "
            "pg_catalog.jsonb_array_length(contexts.acquisition_evidence #> "
            "'{payload,topology,segments}'), "
            "contexts.acquisition_evidence #>> "
            "'{payload,hash_capability,selected_strategy}', "
            "(contexts.acquisition_evidence #>> "
            "'{payload,hash_capability,canonical_sha256_verified}')::boolean, "
            "contexts.acquisition_evidence #>> '{payload,reader,user_name}', "
            "(contexts.acquisition_evidence #>> "
            "'{payload,reader,default_transaction_read_only}')::boolean, "
            "(contexts.acquisition_evidence #>> "
            "'{payload,reader,transaction_read_only}')::boolean, "
            "observations.readiness_provider_kind, "
            "observations.physical_binding ->> 'engine', "
            "observations.physical_binding #>> "
            "'{payload,dataset_relation,storage_kind}', "
            "observations.physical_binding #>> "
            "'{payload,readiness_relation,storage_kind}', "
            "observations.physical_binding #> "
            "'{payload,dataset_relation,requested_relation}' = "
            '\'["dfe_fixture","comparison_orders"]\'::jsonb, '
            "observations.physical_binding #> "
            "'{payload,readiness_relation,requested_relation}' = "
            '\'["dfe_fixture","comparison_batch_manifest"]\'::jsonb, '
            "observations.physical_binding #> "
            "'{payload,dataset_relation,distribution_attribute_numbers}' = '[1]'::jsonb, "
            "observations.physical_binding #> "
            "'{payload,readiness_relation,distribution_attribute_numbers}' = '[1,2]'::jsonb, "
            "pg_catalog.jsonb_array_length(observations.physical_binding #> "
            "'{payload,dataset_relation,columns}'), "
            "pg_catalog.jsonb_array_length(observations.physical_binding #> "
            "'{payload,readiness_relation,columns}'), "
            "pg_catalog.octet_length(observations.physical_schema_digest), "
            "pg_catalog.octet_length(observations.physical_binding_digest), "
            "observations.physical_schema_digest = versions.logical_schema_digest "
            "FROM dfe_metadata.attempt_read_contexts AS contexts "
            "JOIN dfe_metadata.dataset_versions AS versions "
            "USING (dataset_version_id) "
            "JOIN dfe_metadata.dataset_observations AS observations "
            "USING (run_id, attempt_id, read_context_id, dataset_version_id, direction) "
            "WHERE contexts.run_id = %s AND contexts.attempt_id = %s "
            "AND contexts.direction = 'reference'",
            (result.run_id, result.attempt_id),
        ).fetchone()
    assert row == (
        dataset_id,
        "greenplum",
        "psycopg2",
        "original_greenplum",
        "greenplum",
        "protected_read_only_serializable_distributed",
        "closed",
        True,
        True,
        1,
        "original_greenplum_protected_relations",
        "psycopg2",
        "2.9.13",
        170011,
        170011,
        "original_greenplum",
        "4.3.99.00 build dev",
        "original_greenplum",
        "8.3.23",
        "serializable",
        True,
        "greenplum",
        "protected_read_only_serializable_distributed",
        True,
        2,
        True,
        True,
        5,
        "unpackaged_contrib_sql",
        True,
        "dfe_original_greenplum_reader",
        False,
        True,
        "relation_manifest",
        "greenplum",
        "heap",
        "heap",
        True,
        True,
        True,
        True,
        5,
        8,
        32,
        32,
        True,
    )
