# pyright: reportPrivateUsage=false

import hashlib
import json
from contextlib import ExitStack, closing
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from io import StringIO
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import psycopg
import psycopg2
import pytest
from clickhouse_connect.driver.client import Client

from forensic_data import application as application_module
from forensic_data.application import (
    DiffRequest,
    ExecuteCheckRequest,
    HistoryRequest,
    MssqlClickHouseExecutionServices,
    OriginalGreenplumClickHouseExecutionServices,
    PostgresClickHouseExecutionServices,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    read_diff,
    read_history,
)
from forensic_data.cli import run_cli
from forensic_data.clickhouse import ClickHouseConnectionSettings
from forensic_data.clickhouse_endpoint import ClickHouseProtectedReadContext
from forensic_data.clickhouse_limits import (
    ClickHouseExecutionLimits,
    build_clickhouse_execution_limits,
)
from forensic_data.clickhouse_readiness import (
    ClickHouseImmutableVersionManifest,
    parse_clickhouse_immutable_version_manifest,
)
from forensic_data.comparison import (
    CompletedComparisonArtifact,
    PartialComparisonArtifact,
)
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import (
    LoadedContractConfig,
    RowCheckDefinition,
)
from forensic_data.mssql import MssqlConnectionSettings, MssqlRetryPolicy
from forensic_data.persistence.lifecycle import (
    CompletedComparisonDefinition,
    IntegerRangeFingerprintPersistence,
    LifecycleOperationConflictError,
    PartialComparisonDefinition,
    PersistedInputCut,
    PersistedReadContext,
    RunAttemptRecord,
    RunLifecycleStateError,
    StoredLifecycleIntegrityError,
    close_postgres_clickhouse_read_context,
    close_postgres_read_context,
)
from forensic_data.persistence.postgres import migrate_postgres_metadata
from forensic_data.planning import ResolvedScope, resolve_scope_values
from forensic_data.postgres import DatabaseRow, PostgresConnectionSettings, PostgresRetryPolicy
from forensic_data.reporting import (
    DetailAvailability,
    DifferenceKind,
    DifferenceRecord,
    EvidenceFieldValue,
    EvidenceValueAvailability,
    HistoryAttemptStatus,
)
from forensic_data.result import (
    ComparisonTotals,
    ConsistencyLevel,
    ExactTotal,
    ExecutionStatus,
    ExitCode,
    Guarantee,
    LowerBoundTotal,
    PersistenceState,
    ReasonCode,
    ResultReason,
    RunResult,
    UnavailableTotal,
    Verdict,
    exit_code_for_result,
)
from tests import test_original_greenplum_endpoint_integration as original_greenplum
from tests import test_postgres_comparison_integration as postgres_comparison
from tests.clickhouse_support import (
    required_clickhouse_admin_settings,
    required_clickhouse_reader_settings,
    single_attempt_clickhouse_retry_policy,
)
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.mssql_support import (
    connect_setup_writer,
    required_reader_settings,
)
from tests.postgres_support import connect_writer, required_connection_settings

pytestmark = [
    pytest.mark.integration,
    pytest.mark.clickhouse,
    pytest.mark.greenplum,
    pytest.mark.mssql,
    pytest.mark.postgres,
]

_CONTRACT_PATH = (Path(__file__).parent / "fixtures/clickhouse/comparison-contract.yaml").resolve()
_MANIFEST_PATH = (
    Path(__file__).parent / "fixtures/clickhouse/manifests/comparison-orders-v001.json"
).resolve()
_BUSINESS_DATE = date(2024, 2, 29)
_COMPLETED_AT = datetime(2024, 3, 1, 1, 2, 3, 456789, tzinfo=UTC)
_MUTATED_AT = datetime(2024, 3, 1, 2, 3, 4, 567890, tzinfo=UTC)
_SOURCE_CUT = "comparison-orders-cut-000001"
_REFERENCE_BATCH = "reference-orders-2024-02-29-v001"
_TARGET_BATCH = "comparison-orders-2024-02-29-v001"
_SCOPE_DIGEST = "13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897"
_TABLE_UUID = "44444444-4444-4444-8444-444444444444"
_ISSUER = "dfe_fixture_loader"
_SCOPE_VALUES = (ScopeValue(name="business_date", value="2024-02-29"),)
_SCOPE_JSON = '{"business_date":"2024-02-29"}'
_NO_POSTGRES_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_NO_MSSQL_RETRY = MssqlRetryPolicy(max_attempts=1, delay_seconds=0.0)
_REFERENCE_ROWS = (
    (
        1,
        _BUSINESS_DATE,
        Decimal("100.0000000"),
        datetime(2024, 2, 29, 10, 0, 1, 111111),
        datetime(2024, 2, 29, 8, 0, 1, 111111, tzinfo=UTC),
    ),
    (
        2,
        _BUSINESS_DATE,
        Decimal("200.0000000"),
        datetime(2024, 2, 29, 10, 0, 2, 222222),
        datetime(2024, 2, 29, 8, 0, 2, 222222, tzinfo=UTC),
    ),
    (
        3,
        _BUSINESS_DATE,
        Decimal("300.0000000"),
        datetime(2024, 2, 29, 10, 0, 3, 333333),
        datetime(2024, 2, 29, 8, 0, 3, 333333, tzinfo=UTC),
    ),
    (
        4,
        _BUSINESS_DATE,
        Decimal("400.0000000"),
        datetime(2024, 2, 29, 10, 0, 4, 444444),
        datetime(2024, 2, 29, 8, 0, 4, 444444, tzinfo=UTC),
    ),
)

type _ClickHouseExecutionServices = (
    PostgresClickHouseExecutionServices
    | OriginalGreenplumClickHouseExecutionServices
    | MssqlClickHouseExecutionServices
)
type _ClickHouseCloseCall = tuple[
    PostgresConnectionSettings,
    PostgresRetryPolicy,
    RunAttemptRecord,
    ClickHouseProtectedReadContext,
    UUID,
    UUID,
    datetime,
    PersistedReadContext,
]


def test_postgres_original_greenplum_and_mssql_to_clickhouse_are_durable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_contract_config(_CONTRACT_PATH)
    clickhouse_limits = build_clickhouse_execution_limits(config.execution)
    checks = (
        _check(config, "postgres_to_clickhouse_orders"),
        _check(config, "original_greenplum_to_clickhouse_orders"),
        _check(config, "mssql_to_clickhouse_orders"),
    )
    scopes = tuple(resolve_scope_values(check, {"business_date": "2024-02-29"}) for check in checks)
    assert {scope.scope_digest for scope in scopes} == {_SCOPE_DIGEST}
    manifest_payload = _MANIFEST_PATH.read_bytes()
    manifest = parse_clickhouse_immutable_version_manifest(manifest_payload, 1_048_576)
    clickhouse_reader = required_clickhouse_reader_settings("dfe-p0506-target")
    original_reader = postgres_comparison._with_statement_timeout(
        required_connection_settings(
            "DFE_TEST_ORIGINAL_GREENPLUM_READER_DSN",
            "dfe-p0506-original-greenplum-reference",
        ),
        60_000,
    )
    original_writer = required_connection_settings(
        "DFE_TEST_ORIGINAL_GREENPLUM_WRITER_DSN",
        "dfe-p0506-original-greenplum-writer",
    )
    mssql_reader = required_reader_settings("dfe-p0506-mssql-reference").model_copy(
        update={"query_timeout_seconds": 60}
    )
    metadata_request = required_metadata_database_settings()
    postgres_request = postgres_comparison._new_source_database_settings("reference")
    completed_artifacts: dict[str, CompletedComparisonArtifact] = {}
    partial_artifacts: list[PartialComparisonArtifact] = []
    clickhouse_close_calls: dict[UUID, _ClickHouseCloseCall] = {}
    _capture_real_artifacts(
        monkeypatch,
        completed_artifacts,
        partial_artifacts,
        clickhouse_close_calls,
    )

    with ExitStack() as owned_restorations:
        owned_restorations.callback(_reset_clickhouse_fixture)
        _reset_clickhouse_fixture()
        owned_restorations.callback(_reset_mssql_reference)
        _reset_mssql_reference()
        owned_restorations.callback(
            original_greenplum._clear_original_reference,
            original_writer,
        )
        original_greenplum._clear_original_reference(original_writer)
        with (
            disposable_metadata_database(metadata_request) as metadata,
            postgres_comparison._disposable_source_database(postgres_request) as postgres,
        ):
            migrate_postgres_metadata(metadata.migrator, _NO_POSTGRES_RETRY, 5_000)
            _seed_postgres_reference(postgres, checks[0], scopes[0])
            _seed_original_greenplum_reference(original_writer, checks[1], scopes[1])
            services = (
                _postgres_services(
                    metadata,
                    postgres.reader,
                    clickhouse_reader,
                    manifest,
                    checks[0],
                    clickhouse_limits,
                ),
                _original_greenplum_services(
                    metadata,
                    original_reader,
                    clickhouse_reader,
                    manifest,
                    checks[1],
                    clickhouse_limits,
                ),
                _mssql_services(
                    metadata,
                    mssql_reader,
                    clickhouse_reader,
                    manifest,
                    checks[2],
                    clickhouse_limits,
                ),
            )
            results = (
                _execute_postgres_through_cli_and_api(
                    config,
                    checks[0],
                    scopes[0],
                    services[0],
                    postgres.reader,
                    clickhouse_reader,
                    metadata.writer,
                ),
                _execute_api(config, checks[1], services[1]),
                _execute_api(config, checks[2], services[2]),
            )
            for result, check, scope in zip(results, checks, scopes, strict=True):
                _assert_completed_mismatch(result, check, scope, config)
                artifact = completed_artifacts[check.check_id]
                assert artifact.reference_full_scans == 3
                assert artifact.target_full_scans == 5
                assert artifact.metrics.queries == result.metrics.queries
                assert artifact.metrics.result_bytes == result.metrics.result_bytes

            loss_config = replace(
                config,
                execution=replace(
                    config.execution,
                    max_queries=results[0].metrics.queries - 1,
                    max_attempts=1,
                ),
            )
            loss = _execute_api(loss_config, checks[0], services[0])
            _assert_confirmation_loss(loss, results[0], loss_config)
            assert len(partial_artifacts) == 1
            partial_artifact = partial_artifacts[0]
            assert partial_artifact.reference_full_scans == 3
            assert partial_artifact.target_full_scans == 5
            assert partial_artifact.verdict is Verdict.MISMATCH
            assert partial_artifact.totals == ComparisonTotals(
                matched=LowerBoundTotal(precision="lower_bound", value="2"),
                missing=LowerBoundTotal(precision="lower_bound", value="1"),
                extra=LowerBoundTotal(precision="lower_bound", value="1"),
                modified=LowerBoundTotal(precision="lower_bound", value="1"),
            )

            _mutate_postgres_after_publication(postgres)
            _mutate_original_greenplum_after_publication(original_writer, checks[1], scopes[1])
            _mutate_mssql_after_publication()
            _mutate_clickhouse_readiness()

            fresh_metadata = PostgresMetadataServices(
                connection_id=config.metadata.connection.connection_id,
                settings=metadata.reader,
                retry_policy=_NO_POSTGRES_RETRY,
            )
            for result, check, scope in zip(results, checks, scopes, strict=True):
                _assert_durable_history_and_diff(
                    fresh_metadata,
                    check,
                    scope,
                    result,
                )
            _assert_durable_history_and_diff(
                fresh_metadata,
                checks[0],
                scopes[0],
                loss,
            )
            _assert_persisted_clickhouse_provenance(
                metadata.reader,
                results,
                loss,
                manifest_payload,
                clickhouse_reader,
            )
            assert set(clickhouse_close_calls) == {result.attempt_id for result in results}
            _assert_specialized_close_reconciliation(clickhouse_close_calls[results[0].attempt_id])
            _tamper_closure_and_assert_fresh_history_rejects(
                metadata,
                checks[0],
                scopes[0],
                results[0],
            )


def _capture_real_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    completed_artifacts: dict[str, CompletedComparisonArtifact],
    partial_artifacts: list[PartialComparisonArtifact],
    clickhouse_close_calls: dict[UUID, _ClickHouseCloseCall],
) -> None:
    persist_completed = application_module.completed_comparison_persistence_from_artifact
    persist_partial = application_module.partial_comparison_persistence_from_artifact
    persist_clickhouse_close = application_module.close_postgres_clickhouse_read_context

    def capture_completed(
        attempt: RunAttemptRecord,
        persisted_cut: PersistedInputCut,
        artifact: CompletedComparisonArtifact,
    ) -> tuple[
        CompletedComparisonDefinition,
        tuple[IntegerRangeFingerprintPersistence, ...],
        tuple[DifferenceRecord, ...],
    ]:
        completed_artifacts[artifact.check_id] = artifact
        return persist_completed(attempt, persisted_cut, artifact)

    def capture_partial(
        attempt: RunAttemptRecord,
        persisted_cut: PersistedInputCut,
        artifact: PartialComparisonArtifact,
        execution_status: ExecutionStatus,
        primary_reason: ResultReason,
        additional_reasons: tuple[ResultReason, ...],
    ) -> PartialComparisonDefinition:
        partial_artifacts.append(artifact)
        return persist_partial(
            attempt,
            persisted_cut,
            artifact,
            execution_status,
            primary_reason,
            additional_reasons,
        )

    def capture_clickhouse_close(
        settings: PostgresConnectionSettings,
        retry_policy: PostgresRetryPolicy,
        attempt: RunAttemptRecord,
        protected_context: ClickHouseProtectedReadContext,
        read_context_id: UUID,
        end_operation_id: UUID,
        ended_at: datetime,
    ) -> PersistedReadContext:
        persisted = persist_clickhouse_close(
            settings,
            retry_policy,
            attempt,
            protected_context,
            read_context_id,
            end_operation_id,
            ended_at,
        )
        clickhouse_close_calls[attempt.attempt_id] = (
            settings,
            retry_policy,
            attempt,
            protected_context,
            read_context_id,
            end_operation_id,
            ended_at,
            persisted,
        )
        return persisted

    monkeypatch.setattr(
        application_module,
        "completed_comparison_persistence_from_artifact",
        capture_completed,
    )
    monkeypatch.setattr(
        application_module,
        "partial_comparison_persistence_from_artifact",
        capture_partial,
    )
    monkeypatch.setattr(
        application_module,
        "close_postgres_clickhouse_read_context",
        capture_clickhouse_close,
    )


def _check(config: LoadedContractConfig, check_id: str) -> RowCheckDefinition:
    matches = tuple(check for check in config.checks if check.check_id == check_id)
    assert len(matches) == 1
    return matches[0]


def _execute_api(
    config: LoadedContractConfig,
    check: RowCheckDefinition,
    services: _ClickHouseExecutionServices,
) -> RunResult:
    return execute_check(
        config,
        ExecuteCheckRequest(
            request_id=uuid4(),
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_BATCH,
            target_expected_batch_id=_TARGET_BATCH,
            origin="p0506-clickhouse-api-integration",
        ),
        services,
    )


def _execute_postgres_through_cli_and_api(
    config: LoadedContractConfig,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    services: PostgresClickHouseExecutionServices,
    postgres: PostgresConnectionSettings,
    clickhouse: ClickHouseConnectionSettings,
    metadata: PostgresConnectionSettings,
) -> RunResult:
    request_id = uuid4()
    clickhouse_secret = {
        "host": clickhouse.host,
        "port": clickhouse.port,
        "database": clickhouse.database,
        "user": clickhouse.user,
        "password": clickhouse.password.get_secret_value(),
        "transport_security": clickhouse.transport_security.value,
        "ca_cert": None,
        "connect_timeout_seconds": clickhouse.connect_timeout_seconds,
        "send_receive_timeout_seconds": clickhouse.send_receive_timeout_seconds,
    }
    assert clickhouse.ca_cert is None
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
            "--target-manifest",
            str(_MANIFEST_PATH),
            "--target-manifest-issuer",
            _ISSUER,
            "--request-id",
            str(request_id),
            "--output",
            "json",
        ),
        {
            "DFE_P0506_POSTGRES_REFERENCE_DSN": postgres_comparison._connection_dsn(postgres),
            "DFE_P0506_CLICKHOUSE_TARGET_SECRET": json.dumps(clickhouse_secret),
            "DFE_P0506_METADATA_DSN": postgres_comparison._connection_dsn(metadata),
        },
        stdout,
        stderr,
    )
    assert _CONTRACT_PATH.is_absolute()
    assert _MANIFEST_PATH.is_absolute()
    assert stderr.getvalue() == ""
    result = RunResult.model_validate_json(stdout.getvalue())
    reason_summary = tuple(
        (
            reason.code.value,
            reason.operation,
            reason.message,
            tuple(
                (parameter.name, parameter.value)
                for parameter in reason.safe_parameters
                if not parameter.name.startswith("failure_")
            ),
        )
        for reason in result.reasons
    )
    assert exit_code == int(ExitCode.MISMATCH), reason_summary
    assert exit_code == int(exit_code_for_result(result))
    api_replay = execute_check(
        config,
        ExecuteCheckRequest(
            request_id=request_id,
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_BATCH,
            target_expected_batch_id=_TARGET_BATCH,
            origin="cli",
        ),
        services,
    )
    assert api_replay == result
    _assert_completed_mismatch(result, check, scope, config)
    return result


def _assert_completed_mismatch(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    config: LoadedContractConfig,
) -> None:
    if result.execution_status is not ExecutionStatus.COMPLETED:
        raise AssertionError(result.reasons)
    assert result.check_id == check.check_id
    assert result.contract_digest == check.contract_digest
    assert result.scope_digest == scope.scope_digest
    assert result.verdict is Verdict.MISMATCH
    assert result.guarantee is Guarantee.EXACT
    assert result.consistency.stable_reads is ConsistencyLevel.ASSERTED
    assert result.consistency.cut_alignment is ConsistencyLevel.VERIFIED
    assert len(result.consistency.read_context_ids) == 2
    assert result.totals == ComparisonTotals(
        matched=ExactTotal(precision="exact", value="2"),
        missing=ExactTotal(precision="exact", value="1"),
        extra=ExactTotal(precision="exact", value="1"),
        modified=ExactTotal(precision="exact", value="1"),
    )
    assert result.comparison_coverage.total_partitions == 1
    assert result.comparison_coverage.covered_partitions == 1
    assert result.comparison_coverage.resolved_segments == 1
    assert result.comparison_coverage.pruned_segments == 0
    assert result.comparison_coverage.exact_segments == 1
    assert result.comparison_coverage.unresolved_segments == 0
    assert result.metrics.queries > 0
    assert result.metrics.fetched_records > 0
    assert result.metrics.result_bytes > 0
    assert result.metrics.fingerprint_nodes == 1
    assert result.metrics.queries <= config.execution.max_queries
    assert result.metrics.result_bytes <= config.execution.max_application_result_bytes
    assert result.evidence_coverage.found_records == 3
    assert result.evidence_coverage.retained_records == 3
    assert result.evidence_coverage.found_bytes > 0
    assert result.evidence_coverage.retained_bytes == result.evidence_coverage.found_bytes
    assert tuple(reason.code for reason in result.reasons) == (ReasonCode.DATA_MISMATCH,)
    assert result.persistence.state is PersistenceState.CONFIRMED
    assert exit_code_for_result(result) is ExitCode.MISMATCH


def _assert_confirmation_loss(
    result: RunResult,
    completed: RunResult,
    config: LoadedContractConfig,
) -> None:
    assert config.execution.max_attempts == 1
    assert config.execution.max_queries == completed.metrics.queries - 1
    assert result.execution_status is ExecutionStatus.INCOMPLETE
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.guarantee is Guarantee.NOT_ESTABLISHED
    assert result.consistency.stable_reads is ConsistencyLevel.UNKNOWN
    assert result.consistency.cut_alignment is ConsistencyLevel.VERIFIED
    unavailable = UnavailableTotal(
        precision="unavailable",
        value=None,
        reason=ReasonCode.BUDGET_EXHAUSTED,
    )
    assert result.totals == ComparisonTotals(
        matched=unavailable,
        missing=unavailable,
        extra=unavailable,
        modified=unavailable,
    )
    assert result.evidence_coverage == completed.evidence_coverage
    assert result.metrics.queries == config.execution.max_queries
    assert result.metrics.fetched_records > 0
    assert result.metrics.result_bytes > 0
    assert result.persistence.state is PersistenceState.CONFIRMED
    budget_reasons = tuple(
        reason for reason in result.reasons if reason.code is ReasonCode.BUDGET_EXHAUSTED
    )
    assert len(budget_reasons) == 1
    assert budget_reasons[0].operation == "confirm_target"
    assert "final confirmation" in budget_reasons[0].message
    assert tuple(reason.code for reason in result.reasons[1:]) == ()
    assert exit_code_for_result(result) is ExitCode.INCOMPLETE


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
            limit=10,
            cursor=None,
        ),
        services,
    )
    matches = tuple(item for item in history.items if item.run_id == result.run_id)
    assert len(matches) == 1
    assert matches[0].attempt_id == result.attempt_id
    assert matches[0].stored_result == result
    expected_status = (
        HistoryAttemptStatus.COMPLETED
        if result.execution_status is ExecutionStatus.COMPLETED
        else HistoryAttemptStatus.INCOMPLETE
    )
    assert matches[0].status is expected_status

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
    details = {_stored_key(detail.key_values): detail for detail in page.details}
    assert {key: detail.kind for key, detail in details.items()} == {
        "2": DifferenceKind.MODIFIED,
        "3": DifferenceKind.MISSING,
        "5": DifferenceKind.EXTRA,
    }
    modified = details["2"]
    assert modified.omitted_field_names == ("business_date",)
    assert _stored_field(modified.reference_values, "precise_amount").canonical_text == (
        "200.0000000"
    )
    assert _stored_field(modified.target_values, "precise_amount").canonical_text == ("200.0000001")
    assert _stored_field(modified.reference_values, "local_time").canonical_text == (
        "2024-02-29T10:00:02.222222"
    )
    assert _stored_field(modified.target_values, "local_time").canonical_text == (
        "2024-02-29T10:00:02.222223"
    )
    assert _stored_field(modified.reference_values, "instant_time").canonical_text == (
        "2024-02-29T08:00:02.222222Z"
    )
    assert _stored_field(modified.target_values, "instant_time").canonical_text == (
        "2024-02-29T08:00:02.222223Z"
    )
    assert _stored_field(details["3"].reference_values, "precise_amount").canonical_text == (
        "300.0000000"
    )
    assert details["3"].target_values == ()
    assert details["5"].reference_values == ()
    assert _stored_field(details["5"].target_values, "precise_amount").canonical_text == (
        "500.0000000"
    )


def _stored_key(values: tuple[EvidenceFieldValue, ...]) -> str:
    assert len(values) == 1
    value = values[0]
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


def _assert_persisted_clickhouse_provenance(
    metadata: PostgresConnectionSettings,
    completed: tuple[RunResult, RunResult, RunResult],
    lost: RunResult,
    manifest_payload: bytes,
    clickhouse: ClickHouseConnectionSettings,
) -> None:
    for result in completed:
        _assert_attempt_clickhouse_provenance(
            metadata,
            result,
            "closed",
            True,
            manifest_payload,
            clickhouse,
        )
    _assert_attempt_clickhouse_provenance(
        metadata,
        lost,
        "lost",
        False,
        manifest_payload,
        clickhouse,
    )


def _assert_specialized_close_reconciliation(call: _ClickHouseCloseCall) -> None:
    (
        settings,
        retry_policy,
        attempt,
        protected_context,
        read_context_id,
        end_operation_id,
        ended_at,
        persisted,
    ) = call
    replayed = close_postgres_clickhouse_read_context(
        settings,
        retry_policy,
        attempt,
        protected_context,
        read_context_id,
        end_operation_id,
        ended_at,
    )
    assert replayed == persisted
    assert replayed.closure_evidence_json is not None

    with pytest.raises(
        RunLifecycleStateError,
        match="require close_postgres_clickhouse_read_context",
    ):
        close_postgres_read_context(
            settings,
            retry_policy,
            attempt,
            read_context_id,
            end_operation_id,
            ended_at,
        )
    with pytest.raises(
        LifecycleOperationConflictError,
        match="different closure evidence",
    ):
        close_postgres_clickhouse_read_context(
            settings,
            retry_policy,
            attempt,
            protected_context,
            read_context_id,
            end_operation_id,
            ended_at + timedelta(microseconds=1),
        )
    with connect_writer(settings) as connection:
        retained = connection.execute(
            "SELECT closure_evidence::text "
            "FROM dfe_metadata.attempt_read_contexts WHERE read_context_id = %s",
            (read_context_id,),
        ).fetchone()
    assert retained is not None
    assert _json_object_from_text(retained[0], "retained ClickHouse closure") == (
        _json_object_from_text(
            persisted.closure_evidence_json,
            "replayed ClickHouse closure",
        )
    )


def _tamper_closure_and_assert_fresh_history_rejects(
    metadata: MetadataDatabaseSettings,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    result: RunResult,
) -> None:
    fresh_metadata = PostgresMetadataServices(
        connection_id="metadata_pg",
        settings=metadata.reader,
        retry_policy=_NO_POSTGRES_RETRY,
    )
    history_request = HistoryRequest(
        check_id=check.check_id,
        scope_digest=scope.scope_digest,
        limit=10,
        cursor=None,
    )
    with connect_writer(metadata.writer) as connection:
        original = connection.execute(
            "SELECT closure_evidence::text FROM dfe_metadata.attempt_read_contexts "
            "WHERE read_context_id = %s AND run_id = %s AND attempt_id = %s "
            "AND direction = 'target' AND engine = 'clickhouse'",
            (result.consistency.read_context_ids[1], result.run_id, result.attempt_id),
        ).fetchone()
        assert original is not None
        original_json = original[0]
        assert type(original_json) is str
        update = connection.execute(
            "UPDATE dfe_metadata.attempt_read_contexts "
            "SET closure_evidence = jsonb_set(closure_evidence, "
            "'{payload,final_logical_fingerprint,invalid_row_count}', 'false'::jsonb, false) "
            "WHERE read_context_id = %s",
            (result.consistency.read_context_ids[1],),
        )
        assert update.rowcount == 1
    try:
        with pytest.raises(
            StoredLifecycleIntegrityError,
            match="final witnesses differ from immutable acquisition",
        ):
            read_history(history_request, fresh_metadata)
    finally:
        with connect_writer(metadata.writer) as connection:
            restored = connection.execute(
                "UPDATE dfe_metadata.attempt_read_contexts SET closure_evidence = %s::jsonb "
                "WHERE read_context_id = %s",
                (original_json, result.consistency.read_context_ids[1]),
            )
            assert restored.rowcount == 1

    with connect_writer(metadata.writer) as connection:
        update = connection.execute(
            "UPDATE dfe_metadata.attempt_read_contexts "
            "SET closure_evidence = jsonb_set("
            "closure_evidence, '{payload,raw_manifest_sha256}', to_jsonb(%s::text), false) "
            "WHERE read_context_id = %s AND run_id = %s AND attempt_id = %s "
            "AND direction = 'target' AND engine = 'clickhouse'",
            (
                "0" * 64,
                result.consistency.read_context_ids[1],
                result.run_id,
                result.attempt_id,
            ),
        )
        assert update.rowcount == 1

    with pytest.raises(
        StoredLifecycleIntegrityError,
        match="closure manifest provenance differs",
    ):
        read_history(history_request, fresh_metadata)


def _assert_attempt_clickhouse_provenance(
    metadata: PostgresConnectionSettings,
    result: RunResult,
    expected_state: str,
    expect_confirmation: bool,
    manifest_payload: bytes,
    clickhouse: ClickHouseConnectionSettings,
) -> None:
    with connect_writer(metadata) as connection:
        contexts = connection.execute(
            "SELECT read_context_id, direction, engine, driver_version, server_version, "
            "server_version_number, strategy, snapshot_locator, allowed_concurrency, state, "
            "acquisition_evidence::text, closure_evidence::text "
            "FROM dfe_metadata.attempt_read_contexts WHERE attempt_id = %s "
            "ORDER BY direction",
            (result.attempt_id,),
        ).fetchall()
        observations = connection.execute(
            "SELECT observations.direction, versions.dataset_id, versions.adapter, "
            "versions.driver, versions.profile, versions.locator_kind, "
            "versions.relation_scope, observations.readiness_provider_kind, "
            "observations.readiness_evidence::text, observations.physical_binding::text "
            "FROM dfe_metadata.dataset_observations AS observations "
            "JOIN dfe_metadata.dataset_versions AS versions "
            "ON versions.dataset_version_id = observations.dataset_version_id "
            "WHERE observations.attempt_id = %s ORDER BY observations.direction",
            (result.attempt_id,),
        ).fetchall()
        contract_row = connection.execute(
            "SELECT contracts.semantic_payload::text "
            "FROM dfe_metadata.runs AS runs "
            "JOIN dfe_metadata.contract_versions AS contracts "
            "ON contracts.contract_version_id = runs.contract_version_id "
            "WHERE runs.run_id = %s",
            (result.run_id,),
        ).fetchone()
    assert len(contexts) == 2
    assert len(observations) == 2
    assert contract_row is not None
    contract = _json_object_from_text(contract_row[0], "retained contract")
    consistency = _json_object(contract["consistency"], "retained contract consistency")
    assert consistency["minimum_evidence"] == "asserted"
    contract_datasets = _json_array(
        consistency["datasets"],
        "retained contract consistency datasets",
    )
    assert len(contract_datasets) == 2
    reference_contract = _json_object(contract_datasets[0], "retained reference contract")
    target_contract = _json_object(contract_datasets[1], "retained target contract")
    assert reference_contract["stable_read"] == "transaction_snapshot"
    assert target_contract["dataset_id"] == "clickhouse_target_orders"
    assert target_contract["stable_read"] == "immutable_named_version"
    reference_context, target_context = contexts
    assert reference_context[1] == "reference"
    assert reference_context[11] is None
    assert target_context[1] == "target"
    assert target_context[2] == "clickhouse"
    assert type(target_context[3]) is str and target_context[3]
    assert target_context[4] == "26.8.6.5"
    assert target_context[5] == 26008006
    assert target_context[6] == "plain_merge_tree"
    assert target_context[7] == _TABLE_UUID
    assert target_context[8] == 1
    assert target_context[9] == expected_state
    assert target_context[0] == result.consistency.read_context_ids[1]
    acquisition = _json_object_from_text(target_context[10], "ClickHouse acquisition evidence")
    assert acquisition["evidence_version"] == 1
    assert acquisition["kind"] == "clickhouse_immutable_named_version_projection"
    payload = _json_object(acquisition["payload"], "ClickHouse acquisition payload")
    _assert_clickhouse_payload(
        payload,
        result,
        manifest_payload,
    )
    closure_text = target_context[11]
    if expect_confirmation:
        closure = _json_object_from_text(closure_text, "ClickHouse closure evidence")
        _assert_clickhouse_closure(closure, result)
    else:
        assert closure_text is None

    reference_observation, target_observation = observations
    assert reference_observation[0] == "reference"
    assert reference_observation[2] != "clickhouse"
    assert target_observation[:8] == (
        "target",
        "clickhouse_target_orders",
        "clickhouse",
        "clickhouse-connect",
        "clickhouse_lts",
        "relation",
        "physical_only",
        "relation_manifest",
    )
    readiness = _json_object_from_text(
        target_observation[8],
        "ClickHouse retained readiness evidence",
    )
    assert readiness["kind"] == "relation_manifest"
    assert readiness["state"] == "complete"
    physical = _json_object_from_text(
        target_observation[9],
        "ClickHouse retained physical binding",
    )
    assert physical["engine"] == "clickhouse"
    physical_payload = _json_object(physical["payload"], "ClickHouse physical payload")
    _assert_clickhouse_payload(
        physical_payload,
        result,
        manifest_payload,
    )
    _assert_clickhouse_observation_wrappers(physical_payload, result)

    retained_json = f"{target_context[10]}{closure_text or ''}{target_observation[9]}"
    retained_keys = _json_keys(acquisition) | _json_keys(physical)
    if closure_text is not None:
        retained_keys.update(
            _json_keys(_json_object_from_text(closure_text, "ClickHouse closure evidence"))
        )
    assert clickhouse.password.get_secret_value() not in retained_json
    assert "ca_cert" not in retained_keys
    assert "password" not in retained_keys
    assert "200.0000001" not in retained_json
    assert "2024-02-29T10:00:02.222223" not in retained_json
    assert "2024-02-29T08:00:02.222223" not in retained_json


def _assert_clickhouse_observation_wrappers(
    payload: dict[str, object],
    result: RunResult,
) -> None:
    expected_context_id = str(result.consistency.read_context_ids[1])
    dataset_relation = _json_object(
        payload["dataset_relation"],
        "ClickHouse protected dataset relation",
    )
    assert dataset_relation["context_id"] == expected_context_id
    dataset_identity = _json_object(
        dataset_relation["version_identity"],
        "ClickHouse protected dataset identity",
    )
    assert dataset_identity["uuid"] == _TABLE_UUID
    canonical_relation = _json_object(
        dataset_relation["canonical_relation"],
        "ClickHouse canonical relation",
    )
    assert canonical_relation["database"] == "dfe_fixture"
    assert canonical_relation["table"] == "comparison_orders_v001"

    readiness_relation = _json_object(
        payload["readiness_relation"],
        "ClickHouse protected readiness relation",
    )
    assert readiness_relation["context_id"] == expected_context_id
    readiness_identity = _json_object(
        readiness_relation["identity"],
        "ClickHouse protected readiness identity",
    )
    assert readiness_identity["table"] == "immutable_version_readiness"
    request = _json_object(
        readiness_relation["request"],
        "ClickHouse protected readiness request",
    )
    assert request["direction"] == "target"
    assert request["dataset_id"] == "clickhouse_target_orders"


def _assert_clickhouse_payload(
    payload: dict[str, object],
    result: RunResult,
    manifest_payload: bytes,
) -> None:
    context = _json_object(payload["context"], "ClickHouse context provenance")
    assert context["attempt_id"] == str(result.attempt_id)
    assert context["context_id"] == str(result.consistency.read_context_ids[1])
    assert context["engine"] == "clickhouse"
    assert context["source_direction"] == "target"
    assert context["strategy"] == "plain_merge_tree"
    assert context["snapshot_locator"] == _TABLE_UUID
    assert context["consistency_level"] == "asserted"
    assert context["allowed_concurrency"] == 1

    profile = _json_object(payload["profile"], "ClickHouse server profile")
    assert profile["server_version"] == "26.8.6.5"
    assert profile["server_version_number"] == 26008006
    assert type(profile["build_id"]) is str and profile["build_id"]
    binding_library = _json_object(profile["binding_library"], "ClickHouse binding library")
    transport_library = _json_object(
        profile["transport_library"],
        "ClickHouse transport library",
    )
    assert binding_library["name"] == "clickhouse-connect"
    assert type(binding_library["version"]) is str and binding_library["version"]
    assert type(transport_library["name"]) is str and transport_library["name"]
    assert type(transport_library["version"]) is str and transport_library["version"]
    resource_constraints = _json_array(
        profile["resource_constraints"],
        "ClickHouse resource constraints",
    )
    typed_resource_constraints = tuple(
        _json_object(item, "ClickHouse resource constraint") for item in resource_constraints
    )
    group_constraints = tuple(
        item for item in typed_resource_constraints if item["setting"] == "max_rows_to_group_by"
    )
    assert group_constraints == (
        {
            "changeable_in_readonly": True,
            "maximum": "100000",
            "minimum": "1",
            "setting": "max_rows_to_group_by",
            "value": "1",
        },
    )

    projection = _json_object(payload["projection"], "ClickHouse projection")
    assert projection["strategy"] == "plain_merge_tree"
    assert projection["overall_evidence"] == "asserted"
    assert _json_array(projection["limitations"], "projection limitations")
    projection_request = _json_object(
        projection["projection_request"],
        "ClickHouse projection request",
    )
    expected_projection_limits = (
        (99_999, 100_000)
        if result.check_id == "postgres_to_clickhouse_orders"
        and result.execution_status is ExecutionStatus.COMPLETED
        else (100, 100)
    )
    assert (
        projection_request["max_mutation_records"],
        projection_request["max_tie_groups"],
    ) == expected_projection_limits
    fingerprint = _json_object(
        projection["logical_fingerprint"],
        "ClickHouse logical fingerprint",
    )
    assert fingerprint["count"] == 4
    assert fingerprint["invalid_row_count"] == 0
    assert fingerprint["oversized_row_count"] == 0
    runtime = _json_object(projection["runtime_witness"], "ClickHouse runtime witness")
    assert runtime["active_row_count"] == 4
    active_part_count = runtime["active_part_count"]
    assert type(active_part_count) is int
    assert active_part_count > 0
    assert runtime["patch_part_count"] == 0
    assert runtime["lightweight_delete_part_count"] == 0
    mutation = _json_object(projection["mutation_witness"], "ClickHouse mutation witness")
    assert mutation["records"] == []

    immutable = _json_object(
        projection["immutable_binding"],
        "ClickHouse immutable binding",
    )
    assert immutable["attempt_id"] == str(result.attempt_id)
    assert immutable["context_id"] == str(result.consistency.read_context_ids[1])
    assert immutable["strategy"] == "immutable_named_version"
    assert immutable["stable_read_evidence"] == "asserted"
    assert immutable["overall_evidence"] == "asserted"
    readiness_evidence = _json_object(
        immutable["readiness_evidence"],
        "ClickHouse query readiness evidence",
    )
    assert readiness_evidence["consistency_level"] == "verified"
    request = _json_object(immutable["request"], "ClickHouse immutable request")
    assert request["direction"] == "target"
    assert request["minimum_evidence"] == "asserted"
    assert request["dataset_id"] == "clickhouse_target_orders"
    assert request["scope_digest"] == _SCOPE_DIGEST
    assert request["expected_batch_id"] == _TARGET_BATCH
    assert request["expected_issuer"] == _ISSUER
    assert request["endpoint_profile"] == "direct_single_server"

    manifest = _json_object(immutable["manifest"], "ClickHouse immutable manifest")
    assert manifest == {
        "artifact_sha256": hashlib.sha256(manifest_payload).hexdigest(),
        "business_date": "2024-02-29",
        "completed_at": "2024-03-01T01:02:03.456789+00:00",
        "completion_revision": 7,
        "dataset_id": "clickhouse_target_orders",
        "dataset_version": "comparison_orders_v001",
        "expected_batch_id": _TARGET_BATCH,
        "immutability_evidence": "asserted",
        "issuer": _ISSUER,
        "late_arrivals": "next_batch",
        "manifest_version": 1,
        "publication_revision": 11,
        "scope_digest": _SCOPE_DIGEST,
        "source_cut": _SOURCE_CUT,
        "version_locator": {
            "database": "dfe_fixture",
            "table": "comparison_orders_v001",
            "uuid": _TABLE_UUID,
        },
    }
    record = _json_object(immutable["readiness_record"], "ClickHouse readiness record")
    assert record["dataset_id"] == "clickhouse_target_orders"
    assert record["batch_id"] == _TARGET_BATCH
    assert record["dataset_version"] == "comparison_orders_v001"
    assert record["source_cut"] == _SOURCE_CUT
    assert record["completion_revision"] == 7
    assert record["publication_revision"] == 11
    assert record["state"] == "complete"
    readiness_identity = _json_object(
        immutable["readiness_identity"],
        "ClickHouse readiness identity",
    )
    assert readiness_identity["table"] == "immutable_version_readiness"
    version_identity = _json_object(
        immutable["version_identity"],
        "ClickHouse version identity",
    )
    assert version_identity["table"] == "comparison_orders_v001"
    assert version_identity["uuid"] == _TABLE_UUID
    assert version_identity["table_engine"] == "MergeTree"
    assert version_identity["table_readonly"] is True
    assert version_identity["sorting_key"] == "order_id"
    server_uuid = version_identity["server_uuid"]
    assert type(server_uuid) is str
    assert str(UUID(server_uuid)) == server_uuid
    assert readiness_identity["server_uuid"] == server_uuid
    definition_sha256 = version_identity["definition_sha256"]
    assert type(definition_sha256) is str
    assert len(definition_sha256) == 64


def _assert_clickhouse_closure(
    closure: dict[str, object],
    result: RunResult,
) -> None:
    assert set(closure) == {"evidence_version", "kind", "payload"}
    assert closure["evidence_version"] == 1
    assert closure["kind"] == "clickhouse_merge_tree_final_confirmation"
    payload = _json_object(closure["payload"], "ClickHouse closure payload")
    assert set(payload) == {
        "acquisition_evidence_sha256",
        "attempt_id",
        "binding_sha256",
        "confirmed_at",
        "end_operation_id",
        "ended_at",
        "final_logical_fingerprint",
        "final_mutation_witness",
        "final_readiness_evidence",
        "final_readiness_identity",
        "final_readiness_record",
        "final_runtime_witness",
        "final_version_identity",
        "immutable_confirmed_at",
        "manifest_completion_revision",
        "manifest_publication_revision",
        "physical_query_provenance",
        "raw_manifest_sha256",
        "read_context_id",
        "run_id",
    }
    assert payload["attempt_id"] == str(result.attempt_id)
    assert payload["run_id"] == str(result.run_id)
    assert payload["read_context_id"] == str(result.consistency.read_context_ids[1])
    assert payload["manifest_completion_revision"] == 7
    assert payload["manifest_publication_revision"] == 11
    assert payload["raw_manifest_sha256"] == hashlib.sha256(_MANIFEST_PATH.read_bytes()).hexdigest()
    for digest_name in (
        "acquisition_evidence_sha256",
        "binding_sha256",
        "raw_manifest_sha256",
    ):
        digest = payload[digest_name]
        assert type(digest) is str
        assert len(digest) == 64

    final_readiness = _json_object(
        payload["final_readiness_evidence"],
        "ClickHouse final readiness evidence",
    )
    assert final_readiness["consistency_level"] == "verified"
    final_record = _json_object(
        payload["final_readiness_record"],
        "ClickHouse final readiness record",
    )
    assert final_record["dataset_id"] == "clickhouse_target_orders"
    assert final_record["batch_id"] == _TARGET_BATCH
    assert final_record["source_cut"] == _SOURCE_CUT
    assert final_record["completion_revision"] == 7
    assert final_record["publication_revision"] == 11
    final_identity = _json_object(
        payload["final_version_identity"],
        "ClickHouse final version identity",
    )
    assert final_identity["uuid"] == _TABLE_UUID
    assert final_identity["table"] == "comparison_orders_v001"
    final_fingerprint = _json_object(
        payload["final_logical_fingerprint"],
        "ClickHouse final logical fingerprint",
    )
    assert final_fingerprint["count"] == 4
    final_mutation = _json_object(
        payload["final_mutation_witness"],
        "ClickHouse final mutation witness",
    )
    assert final_mutation["records"] == []
    final_runtime = _json_object(
        payload["final_runtime_witness"],
        "ClickHouse final runtime witness",
    )
    assert final_runtime["active_row_count"] == 4

    provenance = _json_object(
        payload["physical_query_provenance"],
        "ClickHouse physical query provenance",
    )
    assert set(provenance) == {
        "attempt_id",
        "connection_attempts",
        "final_query_id",
        "physical_request_count",
    }
    assert provenance["attempt_id"] == str(result.attempt_id)
    connection_attempts = provenance["connection_attempts"]
    assert type(connection_attempts) is int
    assert connection_attempts >= 1
    physical_request_count = provenance["physical_request_count"]
    assert type(physical_request_count) is int
    assert physical_request_count >= 1
    final_query_id = provenance["final_query_id"]
    assert type(final_query_id) is str
    assert str(UUID(final_query_id)) == final_query_id
    for timestamp_name in ("immutable_confirmed_at", "confirmed_at", "ended_at"):
        timestamp = payload[timestamp_name]
        assert type(timestamp) is str
        assert datetime.fromisoformat(timestamp).tzinfo is UTC
    end_operation_id = payload["end_operation_id"]
    assert type(end_operation_id) is str
    assert str(UUID(end_operation_id)) == end_operation_id


def _json_object_from_text(value: object, label: str) -> dict[str, object]:
    if type(value) is not str:
        raise AssertionError(f"{label} must be retained JSON text")
    return _json_object(cast(object, json.loads(value)), label)


def _json_object(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise AssertionError(f"{label} must be a JSON object")
    untyped = cast(dict[object, object], value)
    if any(type(key) is not str for key in untyped):
        raise AssertionError(f"{label} keys must be strings")
    return cast(dict[str, object], untyped)


def _json_array(value: object, label: str) -> list[object]:
    if type(value) is not list:
        raise AssertionError(f"{label} must be a JSON array")
    return cast(list[object], value)


def _json_keys(value: object) -> set[str]:
    if type(value) is dict:
        mapping = cast(dict[object, object], value)
        keys: set[str] = set()
        for key, item in mapping.items():
            if type(key) is not str:
                raise AssertionError("retained JSON keys must be strings")
            keys.add(key)
            keys.update(_json_keys(item))
        return keys
    if type(value) is list:
        keys = set()
        for item in cast(list[object], value):
            keys.update(_json_keys(item))
        return keys
    return set()


def _seed_postgres_reference(
    settings: postgres_comparison._SourceDatabaseSettings,
    check: RowCheckDefinition,
    scope: ResolvedScope,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            connection.execute("CREATE SCHEMA dfe_demo")
            connection.execute("CREATE SCHEMA dfe_control")
            connection.execute(
                "CREATE TABLE dfe_demo.reference_orders ("
                "order_id bigint PRIMARY KEY, business_date date NOT NULL, "
                "precise_amount numeric(38, 7) NOT NULL, "
                "local_time timestamp(6) NOT NULL, "
                "instant_time timestamptz(6) NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE dfe_control.batch_manifest ("
                "dataset_id text NOT NULL, scope_digest text NOT NULL, batch_id text NOT NULL, "
                "state text NOT NULL, business_date date NOT NULL, source_cut text, "
                "dataset_version text, completed_at timestamptz(6), "
                "PRIMARY KEY (dataset_id, scope_digest))"
            )
            with connection.cursor() as cursor:
                cursor.executemany(
                    "INSERT INTO dfe_demo.reference_orders ("
                    "order_id, business_date, precise_amount, local_time, instant_time) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    _REFERENCE_ROWS,
                )
            connection.execute("ANALYZE dfe_demo.reference_orders")
            _insert_postgres_manifest(connection, check.reference.dataset_id, scope.scope_digest)
            connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_fixture_reader")
            connection.execute(
                "GRANT SELECT ON dfe_demo.reference_orders, "
                "dfe_control.batch_manifest TO dfe_fixture_reader"
            )


def _insert_postgres_manifest(
    connection: psycopg.Connection[DatabaseRow],
    dataset_id: str,
    scope_digest: str,
) -> None:
    connection.execute(
        "INSERT INTO dfe_control.batch_manifest ("
        "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
        "dataset_version, completed_at) "
        "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
        (
            dataset_id,
            scope_digest,
            _REFERENCE_BATCH,
            _BUSINESS_DATE,
            _SOURCE_CUT,
            "postgres-reference-orders-v1",
            _COMPLETED_AT,
        ),
    )


def _seed_original_greenplum_reference(
    settings: PostgresConnectionSettings,
    check: RowCheckDefinition,
    scope: ResolvedScope,
) -> None:
    with closing(original_greenplum._connect_original_writer(settings)) as connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
                cursor.execute("SET LOCAL statement_timeout = '60000ms'")
                cursor.executemany(
                    "INSERT INTO dfe_fixture.comparison_orders ("
                    "order_id, business_date, precise_amount, local_time, instant_time) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    _REFERENCE_ROWS,
                )
                cursor.execute(
                    "INSERT INTO dfe_fixture.comparison_batch_manifest ("
                    "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                    "dataset_version, completed_at) "
                    "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                    (
                        check.reference.dataset_id,
                        scope.scope_digest,
                        _REFERENCE_BATCH,
                        _BUSINESS_DATE,
                        _SOURCE_CUT,
                        "original-greenplum-reference-orders-v1",
                        _COMPLETED_AT,
                    ),
                )
            connection.commit()
        except psycopg2.Error:
            connection.rollback()
            raise


def _mutate_postgres_after_publication(
    settings: postgres_comparison._SourceDatabaseSettings,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            connection.execute(
                "UPDATE dfe_demo.reference_orders SET precise_amount = 999.0000000 "
                "WHERE order_id = 1"
            )
            connection.execute(
                "UPDATE dfe_control.batch_manifest SET batch_id = %s, source_cut = %s, "
                "dataset_version = %s, completed_at = %s",
                (
                    "postgres-reference-after-publication",
                    "postgres-cut-after-publication",
                    "postgres-reference-orders-v2",
                    _MUTATED_AT,
                ),
            )


def _mutate_original_greenplum_after_publication(
    settings: PostgresConnectionSettings,
    check: RowCheckDefinition,
    scope: ResolvedScope,
) -> None:
    with closing(original_greenplum._connect_original_writer(settings)) as connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
                cursor.execute("SET LOCAL statement_timeout = '60000ms'")
                cursor.execute(
                    "UPDATE dfe_fixture.comparison_orders "
                    "SET precise_amount = 999.0000000 WHERE order_id = 1"
                )
                cursor.execute(
                    "UPDATE dfe_fixture.comparison_batch_manifest SET batch_id = %s, "
                    "source_cut = %s, dataset_version = %s, completed_at = %s "
                    "WHERE dataset_id = %s AND scope_digest = %s",
                    (
                        "original-reference-after-publication",
                        "original-cut-after-publication",
                        "original-greenplum-reference-orders-v2",
                        _MUTATED_AT,
                        check.reference.dataset_id,
                        scope.scope_digest,
                    ),
                )
            connection.commit()
        except psycopg2.Error:
            connection.rollback()
            raise


def _reset_mssql_reference() -> None:
    with closing(connect_setup_writer("dfe-p0506-mssql-reset")) as connection:
        with connection:
            connection.execute("DELETE FROM [dfe_fixture].[clickhouse_comparison_orders]")
            connection.execute(
                "DELETE FROM [dfe_fixture].[comparison_batch_manifest] "
                "WHERE [dataset_id] = N'mssql_reference_orders' "
                "AND [scope_digest] = "
                "N'13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897'"
            )
            connection.execute(
                "INSERT INTO [dfe_fixture].[clickhouse_comparison_orders] "
                "([order_id], [business_date], [precise_amount], [local_time], [instant_time]) "
                "VALUES "
                "(1, CONVERT(date, N'2024-02-29', 23), "
                "CONVERT(decimal(38, 7), N'100.0000000'), "
                "CONVERT(datetime2(7), N'2024-02-29T10:00:01.1111110', 126), "
                "CONVERT(datetimeoffset(7), N'2024-02-29T08:00:01.1111110+00:00', 127)), "
                "(2, CONVERT(date, N'2024-02-29', 23), "
                "CONVERT(decimal(38, 7), N'200.0000000'), "
                "CONVERT(datetime2(7), N'2024-02-29T10:00:02.2222220', 126), "
                "CONVERT(datetimeoffset(7), N'2024-02-29T08:00:02.2222220+00:00', 127)), "
                "(3, CONVERT(date, N'2024-02-29', 23), "
                "CONVERT(decimal(38, 7), N'300.0000000'), "
                "CONVERT(datetime2(7), N'2024-02-29T10:00:03.3333330', 126), "
                "CONVERT(datetimeoffset(7), N'2024-02-29T08:00:03.3333330+00:00', 127)), "
                "(4, CONVERT(date, N'2024-02-29', 23), "
                "CONVERT(decimal(38, 7), N'400.0000000'), "
                "CONVERT(datetime2(7), N'2024-02-29T10:00:04.4444440', 126), "
                "CONVERT(datetimeoffset(7), N'2024-02-29T08:00:04.4444440+00:00', 127))"
            )
            connection.execute(
                "INSERT INTO [dfe_fixture].[comparison_batch_manifest] "
                "([dataset_id], [scope_digest], [batch_id], [state], [business_date], "
                "[source_cut], [dataset_version], [completed_at]) VALUES "
                "(N'mssql_reference_orders', "
                "N'13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897', "
                "N'reference-orders-2024-02-29-v001', N'complete', "
                "CONVERT(date, N'2024-02-29', 23), N'comparison-orders-cut-000001', "
                "N'mssql-reference-orders-v1', "
                "CONVERT(datetimeoffset(6), N'2024-03-01T01:02:03.456789+00:00', 127))"
            )


def _mutate_mssql_after_publication() -> None:
    with closing(connect_setup_writer("dfe-p0506-mssql-mutate")) as connection:
        with connection:
            connection.execute(
                "UPDATE [dfe_fixture].[clickhouse_comparison_orders] "
                "SET [precise_amount] = CONVERT(decimal(38, 7), N'999.0000000') "
                "WHERE [order_id] = 1"
            )
            connection.execute(
                "UPDATE [dfe_fixture].[comparison_batch_manifest] "
                "SET [batch_id] = N'mssql-reference-after-publication', "
                "[source_cut] = N'mssql-cut-after-publication', "
                "[dataset_version] = N'mssql-reference-orders-v2', "
                "[completed_at] = CONVERT("
                "datetimeoffset(6), N'2024-03-01T02:03:04.567890+00:00', 127) "
                "WHERE [dataset_id] = N'mssql_reference_orders' "
                "AND [scope_digest] = "
                "N'13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897'"
            )


def _reset_clickhouse_fixture() -> None:
    settings = required_clickhouse_admin_settings("dfe-p0506-clickhouse-reset")
    client = _open_clickhouse_client(settings)
    try:
        _clickhouse_command(client, "DROP TABLE IF EXISTS dfe_fixture.comparison_orders_v001 SYNC")
        _clickhouse_command(
            client,
            "CREATE TABLE dfe_fixture.comparison_orders_v001 "
            "UUID '44444444-4444-4444-8444-444444444444' "
            "(order_id Int64, business_date Date, precise_amount Decimal(38, 7), "
            "local_time DateTime64(6, 'UTC'), instant_time DateTime64(6, 'UTC')) "
            "ENGINE = MergeTree ORDER BY order_id",
        )
        _clickhouse_command(
            client,
            "INSERT INTO dfe_fixture.comparison_orders_v001 VALUES "
            "(1, toDate('2024-02-29'), '100.0000000', "
            "toDateTime64('2024-02-29 10:00:01.111111', 6, 'UTC'), "
            "toDateTime64('2024-02-29 08:00:01.111111', 6, 'UTC')), "
            "(2, toDate('2024-02-29'), '200.0000001', "
            "toDateTime64('2024-02-29 10:00:02.222223', 6, 'UTC'), "
            "toDateTime64('2024-02-29 08:00:02.222223', 6, 'UTC')), "
            "(4, toDate('2024-02-29'), '400.0000000', "
            "toDateTime64('2024-02-29 10:00:04.444444', 6, 'UTC'), "
            "toDateTime64('2024-02-29 08:00:04.444444', 6, 'UTC')), "
            "(5, toDate('2024-02-29'), '500.0000000', "
            "toDateTime64('2024-02-29 10:00:05.555555', 6, 'UTC'), "
            "toDateTime64('2024-02-29 08:00:05.555555', 6, 'UTC'))",
        )
        _clickhouse_command(
            client,
            "ALTER TABLE dfe_fixture.comparison_orders_v001 MODIFY SETTING table_readonly = 1",
        )
        _clickhouse_command(client, "TRUNCATE TABLE dfe_fixture.immutable_version_readiness SYNC")
        _clickhouse_command(client, _readiness_reset_insert())
    finally:
        client.close_connections()


def _mutate_clickhouse_readiness() -> None:
    settings = required_clickhouse_admin_settings("dfe-p0506-clickhouse-mutate")
    client = _open_clickhouse_client(settings)
    try:
        _clickhouse_command(
            client,
            "ALTER TABLE dfe_fixture.immutable_version_readiness DELETE WHERE "
            "dataset_id = 'clickhouse_target_orders' AND "
            "scope_digest = "
            "'13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897' "
            "SETTINGS mutations_sync = 2",
        )
        _clickhouse_command(
            client,
            "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
            "('clickhouse_target_orders', "
            "'13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897', "
            "'comparison-orders-after-publication', 'building', toDate('2024-02-29'), "
            "NULL, NULL, NULL, NULL, toUInt64(12))",
        )
    finally:
        client.close_connections()


def _readiness_reset_insert() -> str:
    return (
        "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
        "('immutable_orders', "
        "'5689623b7c5d8424c827123d15d6fdbb011108a79efa1c7586d0f392230697e1', "
        "'immutable-orders-2024-02-29-v001', 'complete', toDate('2024-02-29'), "
        "'source-orders-cut-000001', 'immutable_orders_v001', "
        "toDateTime64('2024-03-01 00:00:00.000000', 6, 'UTC'), toUInt64(1), toUInt64(1)), "
        "('logical_orders', "
        "'8e9db77eac98d983fe0053501478a2f52fa3fd35bca9ea56cbb3e6b44f3430e7', "
        "'logical-orders-2024-02-29-v001', 'complete', toDate('2024-02-29'), "
        "'logical-orders-cut-000001', 'logical_orders_v001', "
        "toDateTime64('2024-03-01 00:10:00.000000', 6, 'UTC'), toUInt64(1), toUInt64(1)), "
        "('clickhouse_target_orders', "
        "'13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897', "
        "'comparison-orders-2024-02-29-v001', 'complete', toDate('2024-02-29'), "
        "'comparison-orders-cut-000001', 'comparison_orders_v001', "
        "toDateTime64('2024-03-01 01:02:03.456789', 6, 'UTC'), "
        "toUInt64(7), toUInt64(11))"
    )


def _open_clickhouse_client(settings: ClickHouseConnectionSettings) -> Client:
    from tests.test_clickhouse_integration import _open_clickhouse_fixture_client

    return _open_clickhouse_fixture_client(settings)


def _clickhouse_command(client: Client, statement: str) -> None:
    client.command(statement)  # pyright: ignore[reportUnknownMemberType]


def _postgres_services(
    metadata: MetadataDatabaseSettings,
    reference: PostgresConnectionSettings,
    target: ClickHouseConnectionSettings,
    manifest: ClickHouseImmutableVersionManifest,
    check: RowCheckDefinition,
    limits: ClickHouseExecutionLimits,
) -> PostgresClickHouseExecutionServices:
    return PostgresClickHouseExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target,
        metadata_connection_id="metadata_pg",
        metadata_settings=metadata.writer,
        reference_retry_policy=_NO_POSTGRES_RETRY,
        target_retry_policy=single_attempt_clickhouse_retry_policy(),
        metadata_retry_policy=_NO_POSTGRES_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        target_transport_limits=limits.transport,
        target_readiness_limits=limits.readiness,
        target_canonical_limits=limits.canonical,
        target_manifest=manifest,
        target_expected_issuer=_ISSUER,
        target_max_mutation_records=100,
        target_max_tie_groups=100,
        metadata_record_bytes=1_048_576,
        metadata_total_bytes=8_388_608,
    )


def _original_greenplum_services(
    metadata: MetadataDatabaseSettings,
    reference: PostgresConnectionSettings,
    target: ClickHouseConnectionSettings,
    manifest: ClickHouseImmutableVersionManifest,
    check: RowCheckDefinition,
    limits: ClickHouseExecutionLimits,
) -> OriginalGreenplumClickHouseExecutionServices:
    return OriginalGreenplumClickHouseExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target,
        metadata_connection_id="metadata_pg",
        metadata_settings=metadata.writer,
        reference_retry_policy=_NO_POSTGRES_RETRY,
        target_retry_policy=single_attempt_clickhouse_retry_policy(),
        metadata_retry_policy=_NO_POSTGRES_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        target_transport_limits=limits.transport,
        target_readiness_limits=limits.readiness,
        target_canonical_limits=limits.canonical,
        target_manifest=manifest,
        target_expected_issuer=_ISSUER,
        target_max_mutation_records=100,
        target_max_tie_groups=100,
        metadata_record_bytes=1_048_576,
        metadata_total_bytes=8_388_608,
    )


def _mssql_services(
    metadata: MetadataDatabaseSettings,
    reference: MssqlConnectionSettings,
    target: ClickHouseConnectionSettings,
    manifest: ClickHouseImmutableVersionManifest,
    check: RowCheckDefinition,
    limits: ClickHouseExecutionLimits,
) -> MssqlClickHouseExecutionServices:
    return MssqlClickHouseExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target,
        metadata_connection_id="metadata_pg",
        metadata_settings=metadata.writer,
        reference_retry_policy=_NO_MSSQL_RETRY,
        target_retry_policy=single_attempt_clickhouse_retry_policy(),
        metadata_retry_policy=_NO_POSTGRES_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        target_transport_limits=limits.transport,
        target_readiness_limits=limits.readiness,
        target_canonical_limits=limits.canonical,
        target_manifest=manifest,
        target_expected_issuer=_ISSUER,
        target_max_mutation_records=100,
        target_max_tie_groups=100,
        metadata_record_bytes=1_048_576,
        metadata_total_bytes=8_388_608,
    )
