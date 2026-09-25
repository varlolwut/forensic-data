import re
from collections.abc import Generator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from decimal import Decimal
from io import StringIO
from pathlib import Path
from time import monotonic, sleep
from typing import Literal
from uuid import UUID, uuid4

import psycopg
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
from forensic_data.canonical import LogicalType
from forensic_data.cli import run_cli
from forensic_data.comparison import (
    ComparisonSegmentState,
    PartialComparisonFrontier,
    partial_comparison_frontier_from_canonical_bytes,
)
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import EvidenceAction, ExecutionBudgets, RowCheckDefinition
from forensic_data.contracts.semantics import canonicalize_semantic_json
from forensic_data.persistence.definitions import build_metadata_registration_definition
from forensic_data.persistence.errors import CompletedComparisonNotFoundError
from forensic_data.persistence.lifecycle import (
    read_postgres_completed_comparison,
    read_postgres_partial_comparison,
)
from forensic_data.persistence.postgres import migrate_postgres_metadata, register_postgres_metadata
from forensic_data.planning import PlanReport, ResolvedScope, resolve_scope_values
from forensic_data.postgres import DatabaseRow, PostgresConnectionSettings, PostgresRetryPolicy
from forensic_data.reporting import (
    DetailAvailability,
    DifferenceKind,
    DifferenceRecord,
    DiffPage,
    EvidenceFieldValue,
    EvidenceUnavailableReason,
    EvidenceValueAvailability,
    HistoryAttemptStatus,
    HistoryPage,
    KeyAvailability,
    StoredResultAvailability,
)
from forensic_data.result import (
    ComparisonCoverage,
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
_SMALL_COMPLETED_AT = datetime(2026, 9, 23, 14, 45, 45, 123456, tzinfo=UTC)
_LOSSY_COMPLETED_AT = datetime(2026, 9, 23, 15, 30, 45, 123456, tzinfo=UTC)
_BASELINE_SOURCE_CUT = "orders-cut-baseline"
_CORRUPT_SOURCE_CUT = "orders-cut-corrupt"
_STRUCTURAL_SOURCE_CUT = "orders-cut-structural"
_SMALL_SOURCE_CUT = "orders-cut-small"
_LOSSY_SOURCE_CUT = "orders-cut-lossy"
_REFERENCE_BASELINE_BATCH = "reference-orders-baseline"
_TARGET_BASELINE_BATCH = "target-orders-baseline"
_REFERENCE_CORRUPT_BATCH = "reference-orders-corrupt"
_TARGET_CORRUPT_BATCH = "target-orders-corrupt"
_REFERENCE_STRUCTURAL_BATCH = "reference-orders-structural"
_TARGET_STRUCTURAL_BATCH = "target-orders-structural"
_REFERENCE_SMALL_BATCH = "reference-orders-small"
_TARGET_SMALL_BATCH = "target-orders-small"
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


@dataclass(frozen=True, slots=True)
class _BoundRetryAttempt:
    run_id: UUID
    attempt_id: UUID
    cut_binding_operation_id: UUID
    attempt_cut_operation_id: UUID
    input_cut_digest: bytes
    backend_process_id: int


def test_postgres_application_retry_reuses_bound_cut_operation() -> None:
    metadata_request = required_metadata_database_settings()
    reference_request = _new_source_database_settings("reference")
    target_request = _new_source_database_settings("target")
    with (
        disposable_metadata_database(metadata_request) as metadata,
        _disposable_source_database(reference_request) as reference,
        _disposable_source_database(target_request) as target,
    ):
        migrate_postgres_metadata(metadata.migrator, _NO_RETRY, 5_000)
        loaded_config = load_contract_config(_CONTRACT_PATH)
        config = replace(
            loaded_config,
            execution=replace(
                loaded_config.execution,
                max_queries=(
                    loaded_config.execution.max_queries * loaded_config.execution.max_attempts
                ),
            ),
        )
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
            "reference-orders-retry",
            "900.00",
        )
        _seed_source_database(
            target,
            "target_orders",
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
            _TARGET_BASELINE_BATCH,
            _BASELINE_SOURCE_CUT,
            "target-orders-retry",
            "901.00",
        )
        request = ExecuteCheckRequest(
            request_id=uuid4(),
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_BASELINE_BATCH,
            target_expected_batch_id=_TARGET_BASELINE_BATCH,
            origin="api-retry-after-bound-cut-integration",
        )

        with (
            connect_writer(metadata.reader) as metadata_observer,
            connect_writer(reference.admin) as source_observer,
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            execution = executor.submit(
                execute_check,
                config,
                request,
                _execution_services(metadata, reference, target, check),
            )
            first_attempt = _terminate_reference_after_bound_cut(
                metadata_observer,
                source_observer,
                reference,
                request.request_id,
                execution,
                30.0,
            )
            result = execution.result(timeout=120.0)

        assert result.run_id == first_attempt.run_id
        assert result.attempt_id != first_attempt.attempt_id
        _assert_baseline_result(result, check, scope, config.execution)
        _assert_retry_after_bound_cut_receipts(
            metadata,
            result,
            first_attempt,
            config.execution,
        )


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

        _replace_with_structural_key_violation(
            reference,
            target,
            registration.reference_dataset.definition.dataset_id,
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        _revoke_source_reader_connect(reference)
        _revoke_source_reader_connect(target)
        metadata_environment = {"DFE_METADATA_DSN": _connection_dsn(metadata.reader)}
        replay_exit, replay_stdout, replay_stderr = _invoke_cli(
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
            ),
            _cli_environment(reference, target, metadata.writer),
        )
        assert replay_exit == int(ExitCode.MISMATCH)
        assert replay_stderr == ""
        _assert_human_comparison_context(replay_stdout)

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

        first_diff_page = read_diff(
            DiffRequest(
                run_id=corrupt.run_id,
                attempt_id=corrupt.attempt_id,
                limit=25,
                cursor=None,
            ),
            metadata_services,
        )
        assert first_diff_page.detail_availability is DetailAvailability.AVAILABLE
        assert first_diff_page.stored_result == corrupt
        assert first_diff_page.found_records == 37
        assert first_diff_page.retained_records == 37
        assert len(first_diff_page.details) == 25
        assert tuple(item.sequence for item in first_diff_page.details) == tuple(range(25))
        assert first_diff_page.next_cursor is not None
        assert first_diff_page.next_cursor.sequence == 24
        first_diff_exit, first_diff_stdout, first_diff_stderr = _invoke_cli(
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
        assert first_diff_exit == 0
        assert first_diff_stderr == ""
        assert DiffPage.model_validate_json(first_diff_stdout) == first_diff_page
        first_human_exit, first_human_stdout, first_human_stderr = _invoke_cli(
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
            ),
            metadata_environment,
        )
        assert first_human_exit == 0
        assert first_human_stderr == ""
        _assert_human_comparison_context(first_human_stdout)
        assert (
            "Difference 0: missing; key=[order_id=1000]; omitted=[business_date]; "
            "reference=[amount=NULL]; target=<absent>" in first_human_stdout
        )
        assert (
            "Difference 21: modified; key=[order_id=1100]; omitted=[business_date]; "
            "reference=[amount=100.00]; target=[amount=110.00]" in first_human_stdout
        )

        second_diff_page = read_diff(
            DiffRequest(
                run_id=corrupt.run_id,
                attempt_id=corrupt.attempt_id,
                limit=25,
                cursor=first_diff_page.next_cursor,
            ),
            metadata_services,
        )
        assert len(second_diff_page.details) == 12
        assert tuple(item.sequence for item in second_diff_page.details) == tuple(range(25, 37))
        assert second_diff_page.next_cursor is None
        second_diff_exit, second_diff_stdout, second_diff_stderr = _invoke_cli(
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
                "--cursor-json",
                first_diff_page.next_cursor.model_dump_json(),
                "--output",
                "json",
            ),
            metadata_environment,
        )
        assert second_diff_exit == 0
        assert second_diff_stderr == ""
        assert DiffPage.model_validate_json(second_diff_stdout) == second_diff_page
        second_human_exit, second_human_stdout, second_human_stderr = _invoke_cli(
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
                "--cursor-json",
                first_diff_page.next_cursor.model_dump_json(),
            ),
            metadata_environment,
        )
        assert second_human_exit == 0
        assert second_human_stderr == ""
        assert (
            "Difference 33: extra; key=[order_id=1201]; omitted=[business_date]; "
            "reference=<absent>; target=[amount=50.00]" in second_human_stdout
        )
        retained_details = first_diff_page.details + second_diff_page.details
        _assert_retained_difference_details(retained_details)
        _assert_numeric_difference_view(metadata.reader, corrupt.run_id, corrupt.attempt_id)

        _grant_source_reader_connect(reference)
        _grant_source_reader_connect(target)
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

        _replace_with_small_policy_case(
            reference,
            target,
            registration.reference_dataset.definition.dataset_id,
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        budget_config = replace(
            config,
            execution=replace(config.execution, max_full_scans_per_side=2),
        )
        budget_request = ExecuteCheckRequest(
            request_id=uuid4(),
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_SMALL_BATCH,
            target_expected_batch_id=_TARGET_SMALL_BATCH,
            origin="api-integration",
        )
        budget_partial = execute_check(budget_config, budget_request, services)
        assert execute_check(budget_config, budget_request, services) == budget_partial
        assert (
            read_postgres_partial_comparison(
                metadata.reader,
                _NO_RETRY,
                budget_partial.run_id,
                budget_partial.attempt_id,
            )
            == budget_partial
        )
        assert budget_partial.execution_status is ExecutionStatus.INCOMPLETE
        assert budget_partial.verdict is Verdict.MISMATCH
        assert budget_partial.guarantee is Guarantee.NOT_ESTABLISHED
        assert budget_partial.persistence.state is PersistenceState.CONFIRMED
        assert budget_partial.consistency.stable_reads is ConsistencyLevel.VERIFIED
        assert budget_partial.consistency.cut_alignment is ConsistencyLevel.VERIFIED
        assert budget_partial.comparison_coverage == ComparisonCoverage(
            total_partitions=1,
            covered_partitions=0,
            resolved_segments=0,
            pruned_segments=0,
            exact_segments=0,
            unresolved_segments=2,
            unresolved_reasons=(ReasonCode.BUDGET_EXHAUSTED,),
        )
        unavailable_budget_total = UnavailableTotal(
            precision="unavailable",
            value=None,
            reason=ReasonCode.BUDGET_EXHAUSTED,
        )
        assert budget_partial.totals == ComparisonTotals(
            matched=unavailable_budget_total,
            missing=unavailable_budget_total,
            extra=unavailable_budget_total,
            modified=unavailable_budget_total,
        )
        assert tuple(reason.code for reason in budget_partial.reasons) == (
            ReasonCode.BUDGET_EXHAUSTED,
            ReasonCode.DATA_MISMATCH,
        )
        assert budget_partial.evidence_coverage.found_records == 0
        assert budget_partial.evidence_coverage.retained_records == 0
        assert budget_partial.evidence_coverage.found_bytes == 0
        assert budget_partial.evidence_coverage.retained_bytes == 0
        assert budget_partial.metrics.queries > 0
        assert budget_partial.metrics.fetched_records > 0
        assert budget_partial.metrics.result_bytes > 0
        assert budget_partial.metrics.fingerprint_nodes == 1
        _assert_budget_partial_frontier(
            _read_partial_frontier(
                metadata.reader,
                budget_partial.run_id,
                budget_partial.attempt_id,
            )
        )
        budget_diff = read_diff(
            DiffRequest(
                run_id=budget_partial.run_id,
                attempt_id=budget_partial.attempt_id,
                limit=25,
                cursor=None,
            ),
            metadata_services,
        )
        assert budget_diff.stored_result == budget_partial
        assert budget_diff.detail_availability is DetailAvailability.AVAILABLE
        assert budget_diff.found_records == 0
        assert budget_diff.retained_records == 0
        assert budget_diff.details == ()
        assert budget_diff.next_cursor is None

        policy_config = replace(
            config,
            execution=replace(config.execution, max_evidence_rows=2),
            evidence=replace(
                config.evidence,
                fields=tuple(
                    replace(field, action=EvidenceAction.REDACT)
                    if field.field_name == "amount"
                    else field
                    for field in config.evidence.fields
                ),
            ),
        )
        policy_request = ExecuteCheckRequest(
            request_id=uuid4(),
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_SMALL_BATCH,
            target_expected_batch_id=_TARGET_SMALL_BATCH,
            origin="api-integration",
        )
        policy_result = execute_check(policy_config, policy_request, services)
        assert policy_result.execution_status is ExecutionStatus.COMPLETED
        assert policy_result.verdict is Verdict.MISMATCH
        assert policy_result.guarantee is Guarantee.EXACT
        assert tuple(total.value for total in policy_result.totals.values()) == (
            "0",
            "2",
            "1",
            "1",
        )
        assert policy_result.evidence_coverage.found_records == 4
        assert policy_result.evidence_coverage.retained_records == 2
        assert (
            policy_result.evidence_coverage.found_bytes
            > policy_result.evidence_coverage.retained_bytes
            > 0
        )

        _introduce_lossy_key_mapping(
            reference,
            target,
            registration.reference_dataset.definition.dataset_id,
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        assert execute_check(policy_config, policy_request, services) == policy_result
        policy_diff = read_diff(
            DiffRequest(
                run_id=policy_result.run_id,
                attempt_id=policy_result.attempt_id,
                limit=25,
                cursor=None,
            ),
            metadata_services,
        )
        assert policy_diff.stored_result == policy_result
        assert policy_diff.detail_availability is DetailAvailability.PARTIALLY_RETAINED
        assert policy_diff.found_records == 4
        assert policy_diff.retained_records == 2
        assert policy_diff.next_cursor is None
        assert tuple(
            (detail.sequence, detail.kind, detail.key_values[0].canonical_text)
            for detail in policy_diff.details
        ) == (
            (0, DifferenceKind.MODIFIED, "1"),
            (1, DifferenceKind.MISSING, "2"),
        )
        for detail in policy_diff.details:
            assert detail.omitted_field_names == ("business_date",)
            assert tuple(value.field_name for value in detail.reference_values) == ("amount",)
            for value in (*detail.reference_values, *detail.target_values):
                assert value.field_name == "amount"
                assert value.availability is EvidenceValueAvailability.REDACTED
                assert not value.raw_available
                assert value.is_null is None
                assert value.canonical_text is None
                assert value.canonical_hex is None
                assert value.unavailable_reason is EvidenceUnavailableReason.POLICY_REDACTED
        assert tuple(value.field_name for value in policy_diff.details[0].target_values) == (
            "amount",
        )
        assert policy_diff.details[1].target_values == ()
        policy_diff_exit, policy_diff_stdout, policy_diff_stderr = _invoke_cli(
            (
                "diff",
                "--config",
                str(_CONTRACT_PATH),
                "--run-id",
                str(policy_result.run_id),
                "--attempt-id",
                str(policy_result.attempt_id),
                "--limit",
                "25",
            ),
            metadata_environment,
        )
        assert policy_diff_exit == 0
        assert policy_diff_stderr == ""
        assert (
            "Difference 0: modified; key=[order_id=1]; omitted=[business_date]; "
            "reference=[amount=<redacted>]; target=[amount=<redacted>]" in policy_diff_stdout
        )
        assert (
            "Difference 1: missing; key=[order_id=2]; omitted=[business_date]; "
            "reference=[amount=<redacted>]; target=<absent>" in policy_diff_stdout
        )

        _replace_with_structural_key_violation(
            reference,
            target,
            registration.reference_dataset.definition.dataset_id,
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
        )
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
        assert (
            read_postgres_partial_comparison(
                metadata.reader,
                _NO_RETRY,
                lossy.run_id,
                lossy.attempt_id,
            )
            == lossy
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
            lossy_history.items[0].stored_result_availability is StoredResultAvailability.AVAILABLE
        )
        assert lossy_history.items[0].stored_result == lossy


def _terminate_reference_after_bound_cut(
    metadata_connection: psycopg.Connection[DatabaseRow],
    source_connection: psycopg.Connection[DatabaseRow],
    reference: _SourceDatabaseSettings,
    request_id: UUID,
    execution: Future[RunResult],
    timeout_seconds: float,
) -> _BoundRetryAttempt:
    deadline = monotonic() + timeout_seconds
    while monotonic() < deadline:
        cut_row = metadata_connection.execute(
            "SELECT r.run_id, a.attempt_id, r.cut_binding_operation_id, "
            "a.cut_operation_id, r.bound_input_cut_digest, a.input_cut_digest "
            "FROM dfe_metadata.runs AS r "
            "JOIN dfe_metadata.run_attempts AS a ON a.run_id = r.run_id "
            "WHERE r.request_id = %s AND a.ordinal = 1 "
            "AND r.cut_binding_operation_id IS NOT NULL "
            "AND a.cut_operation_id IS NOT NULL",
            (request_id,),
        ).fetchone()
        if cut_row is not None:
            backend_rows = source_connection.execute(
                "SELECT pid FROM pg_catalog.pg_stat_activity "
                "WHERE datname = pg_catalog.current_database() AND usename = %s "
                "AND application_name = %s AND backend_type = 'client backend' "
                "AND state = 'active' AND position('dfe_ranges' in query) > 0 "
                "AND pid <> pg_catalog.pg_backend_pid() ORDER BY backend_start",
                (reference.reader.user, reference.reader.application_name),
            ).fetchall()
            if len(backend_rows) == 1:
                backend_process_id = backend_rows[0][0]
                if type(backend_process_id) is not int:
                    raise AssertionError("protected reference backend PID must be an integer")
                termination = source_connection.execute(
                    "SELECT pg_catalog.pg_terminate_backend(%s)",
                    (backend_process_id,),
                ).fetchone()
                assert termination == (True,)
                return _bound_retry_attempt(cut_row, backend_process_id)
            if len(backend_rows) > 1:
                raise AssertionError(
                    "retry fixture found more than one protected reference backend: "
                    f"backend_pids={tuple(row[0] for row in backend_rows)!r}"
                )
        if execution.done():
            completed = execution.result()
            raise AssertionError(
                "comparison completed before the bound-cut backend termination: "
                f"run_id={completed.run_id}, attempt_id={completed.attempt_id}"
            )
        sleep(0.001)
    raise AssertionError(
        "timed out waiting for a bound input cut and protected reference backend: "
        f"request_id={request_id}, timeout_seconds={timeout_seconds}"
    )


def _bound_retry_attempt(row: tuple[object, ...], backend_process_id: int) -> _BoundRetryAttempt:
    if len(row) != 6:
        raise AssertionError(f"bound retry attempt row must contain six fields: actual={len(row)}")
    run_id, attempt_id, binding_operation, attempt_operation, run_digest, attempt_digest = row
    if not isinstance(run_id, UUID):
        raise AssertionError("bound retry run id must be a UUID")
    if not isinstance(attempt_id, UUID):
        raise AssertionError("bound retry attempt id must be a UUID")
    if not isinstance(binding_operation, UUID):
        raise AssertionError("bound retry cut binding operation id must be a UUID")
    if not isinstance(attempt_operation, UUID):
        raise AssertionError("bound retry attempt cut operation id must be a UUID")
    if type(run_digest) is not bytes or type(attempt_digest) is not bytes:
        raise AssertionError("bound retry input cut digests must be bytes")
    if run_digest != attempt_digest:
        raise AssertionError("first attempt input cut digest must equal the run binding digest")
    return _BoundRetryAttempt(
        run_id=run_id,
        attempt_id=attempt_id,
        cut_binding_operation_id=binding_operation,
        attempt_cut_operation_id=attempt_operation,
        input_cut_digest=run_digest,
        backend_process_id=backend_process_id,
    )


def _assert_retry_after_bound_cut_receipts(
    metadata: MetadataDatabaseSettings,
    result: RunResult,
    first_attempt: _BoundRetryAttempt,
    execution_policy: ExecutionBudgets,
) -> None:
    first_partial = read_postgres_partial_comparison(
        metadata.reader,
        _NO_RETRY,
        first_attempt.run_id,
        first_attempt.attempt_id,
    )
    with connect_writer(metadata.reader) as connection:
        run_row = connection.execute(
            "SELECT cut_binding_operation_id, bound_input_cut_digest, "
            "selected_terminal_attempt_id FROM dfe_metadata.runs WHERE run_id = %s",
            (result.run_id,),
        ).fetchone()
        attempt_rows = connection.execute(
            "SELECT ordinal, attempt_id, start_operation_id, cut_operation_id, "
            "input_cut_digest, status, terminal_reason_code, "
            "terminal_reason ->> 'operation', terminal_reason ->> 'message', "
            "terminal_reason ->> 'native_error_code', "
            "(SELECT parameter ->> 'value' FROM "
            "pg_catalog.jsonb_array_elements(terminal_reason -> 'safe_parameters') AS parameter "
            "WHERE parameter ->> 'name' = 'error_type'), "
            "(SELECT parameter ->> 'value' FROM "
            "pg_catalog.jsonb_array_elements(terminal_reason -> 'safe_parameters') AS parameter "
            "WHERE parameter ->> 'name' = 'cleanup_cut_aligned'), "
            "(SELECT parameter ->> 'value' FROM "
            "pg_catalog.jsonb_array_elements(terminal_reason -> 'safe_parameters') AS parameter "
            "WHERE parameter ->> 'name' = 'cleanup_stable_reads') "
            "FROM dfe_metadata.run_attempts WHERE run_id = %s ORDER BY ordinal",
            (result.run_id,),
        ).fetchall()
        observation_rows = connection.execute(
            "SELECT attempt_id, observation_id, observation_operation_id, "
            "read_context_id, input_cut_digest "
            "FROM dfe_metadata.dataset_observations WHERE run_id = %s "
            "ORDER BY attempt_id, direction",
            (result.run_id,),
        ).fetchall()

    assert run_row == (
        first_attempt.cut_binding_operation_id,
        first_attempt.input_cut_digest,
        result.attempt_id,
    )
    assert len(attempt_rows) == 2
    first_row, second_row = attempt_rows
    assert first_row[0:2] == (1, first_attempt.attempt_id)
    assert first_row[3:7] == (
        first_attempt.attempt_cut_operation_id,
        first_attempt.input_cut_digest,
        "error",
        ReasonCode.QUERY_ERROR.value,
    )
    assert second_row[0:2] == (2, result.attempt_id)
    assert second_row[4:13] == (
        first_attempt.input_cut_digest,
        "completed",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert isinstance(first_row[2], UUID)
    assert isinstance(second_row[2], UUID)
    assert isinstance(second_row[3], UUID)
    assert first_row[2] != second_row[2]
    assert first_row[3] != second_row[3]

    assert first_row[7:13] == (
        "read_source",
        "a source operation failed",
        None,
        "PostgresQueryError",
        "1",
        ConsistencyLevel.VERIFIED.value,
    )

    assert first_partial.run_id == result.run_id
    assert first_partial.attempt_id == first_attempt.attempt_id
    assert first_partial.execution_status is ExecutionStatus.ERROR
    assert first_partial.consistency.stable_reads is ConsistencyLevel.VERIFIED
    assert first_partial.consistency.cut_alignment is ConsistencyLevel.VERIFIED
    assert first_partial.persistence.state is PersistenceState.CONFIRMED
    assert tuple(reason.code for reason in first_partial.reasons) == (
        ReasonCode.QUERY_ERROR,
        ReasonCode.SNAPSHOT_LOST,
    )
    assert first_partial.metrics.queries > 0
    assert first_partial.metrics.fetched_records > 0
    assert first_partial.metrics.result_bytes > 0
    assert first_partial.metrics.queries + result.metrics.queries <= execution_policy.max_queries

    assert len(observation_rows) == 4
    assert tuple(row[0] for row in observation_rows).count(first_attempt.attempt_id) == 2
    assert tuple(row[0] for row in observation_rows).count(result.attempt_id) == 2
    assert len({row[1] for row in observation_rows}) == 4
    assert len({row[2] for row in observation_rows}) == 4
    assert all(row[4] == first_attempt.input_cut_digest for row in observation_rows)
    assert {row[3] for row in observation_rows if row[0] == first_attempt.attempt_id} == set(
        first_partial.consistency.read_context_ids
    )
    assert {row[3] for row in observation_rows if row[0] == result.attempt_id} == set(
        result.consistency.read_context_ids
    )
    assert set(first_partial.consistency.read_context_ids).isdisjoint(
        result.consistency.read_context_ids
    )


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
        with connection.transaction():
            connection.execute(
                "ALTER TABLE dfe_demo.reference_orders ALTER COLUMN amount DROP NOT NULL"
            )
            connection.execute(
                "UPDATE dfe_demo.reference_orders SET amount = NULL WHERE order_id = 1000"
            )
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


def _replace_with_small_policy_case(
    reference: _SourceDatabaseSettings,
    target: _SourceDatabaseSettings,
    reference_dataset_id: str,
    target_dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(reference.writer) as connection:
        with connection.transaction():
            connection.execute(
                "UPDATE dfe_control.batch_manifest "
                "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    _REFERENCE_SMALL_BATCH,
                    _SMALL_SOURCE_CUT,
                    "reference-orders-v4",
                    _SMALL_COMPLETED_AT,
                    reference_dataset_id,
                    scope_digest,
                ),
            )
    with connect_writer(target.writer) as connection:
        with connection.transaction():
            connection.execute("TRUNCATE TABLE dfe_demo.target_orders")
            connection.execute(
                "ALTER TABLE dfe_demo.target_orders ALTER COLUMN order_id SET NOT NULL"
            )
            connection.execute(
                "ALTER TABLE dfe_demo.target_orders "
                "ADD CONSTRAINT target_orders_pkey PRIMARY KEY (order_id)"
            )
            connection.execute(
                "INSERT INTO dfe_demo.target_orders "
                "(order_id, business_date, amount) VALUES "
                "(1, %s, 11.00), (4, %s, 40.00)",
                (_BUSINESS_DATE, _BUSINESS_DATE),
            )
            connection.execute("ANALYZE dfe_demo.target_orders")
            connection.execute(
                "UPDATE dfe_control.batch_manifest "
                "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    _TARGET_SMALL_BATCH,
                    _SMALL_SOURCE_CUT,
                    "target-orders-v4",
                    _SMALL_COMPLETED_AT,
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
                    "reference-orders-v5",
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
                "target-orders-v5",
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


def _assert_human_comparison_context(output: str) -> None:
    assert (
        "Reference: connection=reference_pg dataset=reference_orders "
        'relation="dfe_demo"."reference_orders" relation_scope=physical_only' in output
    )
    assert (
        "Target: connection=target_pg dataset=target_orders "
        'relation="dfe_demo"."target_orders" relation_scope=physical_only' in output
    )
    assert 'Scope values: business_date(date)="2026-09-23"' in output
    assert "DFE_REFERENCE_DSN" not in output
    assert "DFE_TARGET_DSN" not in output
    assert "password=" not in output


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
        _assert_stored_evidence_value(
            detail.key_values[0],
            "order_id",
            LogicalType.INT64,
            str(expected_key),
        )
        reference_amount = None if detail.kind is DifferenceKind.EXTRA else "100.00"
        if detail.kind is DifferenceKind.MISSING:
            target_amount = None
        elif detail.kind is DifferenceKind.MODIFIED:
            target_amount = "110.00"
        else:
            target_amount = "50.00"
        if expected_key == 1000:
            _assert_retained_null_side_value(detail.reference_values)
        else:
            _assert_retained_side_values(detail.reference_values, reference_amount)
        _assert_retained_side_values(detail.target_values, target_amount)


def _assert_retained_side_values(
    values: tuple[EvidenceFieldValue, ...],
    expected_amount: str | None,
) -> None:
    if expected_amount is None:
        assert values == ()
        return
    assert tuple(value.field_name for value in values) == ("amount",)
    (amount,) = values
    _assert_stored_evidence_value(amount, "amount", LogicalType.DECIMAL, expected_amount)
    assert amount.decimal_precision == 18
    assert amount.decimal_scale == 2


def _assert_retained_null_side_value(values: tuple[EvidenceFieldValue, ...]) -> None:
    assert tuple(value.field_name for value in values) == ("amount",)
    (amount,) = values
    assert amount.logical_type is LogicalType.DECIMAL
    assert amount.decimal_precision == 18
    assert amount.decimal_scale == 2
    assert amount.timestamp_precision is None
    assert amount.availability is EvidenceValueAvailability.STORED
    assert amount.raw_available
    assert amount.is_null is True
    assert amount.canonical_text is None
    assert amount.canonical_hex is None
    assert amount.unavailable_reason is None


def _assert_stored_evidence_value(
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


def _assert_numeric_difference_view(
    settings: PostgresConnectionSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> None:
    with connect_writer(settings) as connection:
        rows = connection.execute(
            "SELECT anomaly_sequence, anomaly_kind, field_name, logical_type, "
            "reference_availability, target_availability, reference_value, target_value, "
            "target_minus_reference FROM dfe_metadata.numeric_differences "
            "WHERE run_id = %s AND attempt_id = %s ORDER BY anomaly_sequence, field_name",
            (run_id, attempt_id),
        ).fetchall()
    assert len(rows) == 37
    for sequence, row in enumerate(rows):
        if sequence == 0:
            expected = (
                sequence,
                "missing",
                "amount",
                "decimal",
                "stored",
                None,
                None,
                None,
                None,
            )
        elif sequence < 21:
            expected = (
                sequence,
                "missing",
                "amount",
                "decimal",
                "stored",
                None,
                Decimal("100.00"),
                None,
                None,
            )
        elif sequence < 33:
            expected = (
                sequence,
                "modified",
                "amount",
                "decimal",
                "stored",
                "stored",
                Decimal("100.00"),
                Decimal("110.00"),
                Decimal("10.00"),
            )
        else:
            expected = (
                sequence,
                "extra",
                "amount",
                "decimal",
                None,
                "stored",
                None,
                Decimal("50.00"),
                None,
            )
        assert row == expected


def _read_partial_frontier(
    settings: PostgresConnectionSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> PartialComparisonFrontier:
    with connect_writer(settings) as connection:
        row = connection.execute(
            "SELECT frontier_payload::text FROM dfe_metadata.partial_check_results "
            "WHERE run_id = %s AND attempt_id = %s",
            (run_id, attempt_id),
        ).fetchone()
    assert row is not None
    assert type(row[0]) is str
    canonical_payload = canonicalize_semantic_json(row[0]).encode("utf-8", errors="strict")
    return partial_comparison_frontier_from_canonical_bytes(canonical_payload)


def _assert_budget_partial_frontier(frontier: PartialComparisonFrontier) -> None:
    assert len(frontier.topology) == 1
    (root,) = frontier.topology
    assert root.segment_sequence == 0
    assert root.parent_segment_sequence is None
    assert root.depth == 0
    assert root.lower_inclusive == 1
    assert root.upper_exclusive == 5
    assert root.state is ComparisonSegmentState.SPLIT
    assert root.reference_fingerprint.count == 3
    assert root.target_fingerprint.count == 2
    assert root.reference_fingerprint != root.target_fingerprint

    assert tuple(item.segment_sequence for item in frontier.unresolved) == (1, 2)
    assert tuple(item.parent_segment_sequence for item in frontier.unresolved) == (0, 0)
    assert tuple(item.depth for item in frontier.unresolved) == (1, 1)
    assert tuple(item.lower_inclusive for item in frontier.unresolved) == (1, 3)
    assert tuple(item.upper_exclusive for item in frontier.unresolved) == (3, 5)
    assert tuple(item.reason for item in frontier.unresolved) == (
        ReasonCode.BUDGET_EXHAUSTED,
        ReasonCode.BUDGET_EXHAUSTED,
    )
    assert all(item.reference_fingerprint is None for item in frontier.unresolved)
    assert all(item.target_fingerprint is None for item in frontier.unresolved)


def _assert_common_completed_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    assert result.check_id == check.check_id
    assert result.contract_digest == check.contract_digest
    assert result.scope_digest == scope.scope_digest
    assert result.execution_status is ExecutionStatus.COMPLETED, (
        result.reasons,
        result.metrics,
    )
    assert result.consistency.stable_reads is ConsistencyLevel.VERIFIED
    assert result.consistency.cut_alignment is ConsistencyLevel.VERIFIED
    assert len(result.consistency.read_context_ids) == 2
    assert result.comparison_coverage.total_partitions == 1
    assert result.comparison_coverage.covered_partitions == 1
    assert result.comparison_coverage.unresolved_segments == 0
    assert result.comparison_coverage.unresolved_reasons == ()
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
    assert result.evidence_coverage.retained_records == 0
    assert result.evidence_coverage.retained_bytes == 0
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
    assert result.evidence_coverage.found_bytes > 0
    assert result.evidence_coverage.retained_records == 37
    assert result.evidence_coverage.retained_bytes == result.evidence_coverage.found_bytes
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
    assert result.evidence_coverage.retained_records == 0
    assert result.evidence_coverage.retained_bytes == 0
    assert result.metrics.queries >= 2
    assert result.metrics.fetched_records >= 2
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
    assert result.metrics.queries >= 2
    assert result.metrics.fetched_records >= 2
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
