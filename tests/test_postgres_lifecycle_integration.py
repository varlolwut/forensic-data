import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import LiteralString
from uuid import UUID, uuid4

import psycopg
import pytest

from forensic_data.acquisition import (
    CompleteReadinessRecord,
    InputCutDefinition,
    RelationManifestEvidence,
    RunRequestDefinition,
    build_input_cut_definition,
    build_run_request_definition,
    run_request_semantic_value,
    validate_relation_manifest_readiness,
)
from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
    TimestampParameters,
)
from forensic_data.comparison import (
    CompletedComparisonArtifact,
    execute_postgres_integer_key_comparison,
)
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import (
    EvidenceDefinition,
    ExecutionBudgets,
    LateArrivalPolicy,
    MinimumEvidence,
    RelationLocator,
    RelationManifestReadiness,
    RelationScope,
    RowCheckDefinition,
)
from forensic_data.contracts.semantics import (
    SemanticValue,
    canonical_semantic_json,
    semantic_digest_hex,
    semantic_value_from_json,
)
from forensic_data.persistence.definitions import build_metadata_registration_definition
from forensic_data.persistence.errors import (
    ActiveRunAttemptError,
    AttemptFenceError,
    InputCutMismatchError,
    LifecycleOperationConflictError,
    LifecycleTransactionError,
    RunInvocationContinuationError,
    RunLifecycleStateError,
    RunRequestConflictError,
    StoredLifecycleIntegrityError,
)
from forensic_data.persistence.lifecycle import (
    AlignedInputCutPersistence,
    AttemptOutcomeRecord,
    AttemptStatus,
    ClaimedRun,
    ReadContextPersistence,
    ReadContextStatus,
    RelationManifestObservationPersistence,
    RunAttemptRecord,
    claim_postgres_run,
    close_postgres_read_context,
    completed_comparison_persistence_from_artifact,
    persist_postgres_aligned_input_cut,
    persist_postgres_read_context,
    publish_postgres_completed_comparison,
    publish_postgres_terminal_error_attempt,
    read_postgres_history,
    record_postgres_retryable_incomplete_attempt,
    renew_postgres_run_attempt,
    start_postgres_run_attempt,
)
from forensic_data.persistence.model import DatasetVersionRecord, MetadataRegistration
from forensic_data.persistence.postgres import (
    migrate_postgres_metadata,
    register_postgres_metadata,
)
from forensic_data.planning import PlanDirection, resolve_scope_values
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresProtectedReadContext,
    PostgresProtectedRelationInspection,
    PostgresRelationAcquisition,
    PostgresRetryPolicy,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetLedger,
    PostgresSourceDirection,
    open_postgres_protected_read_context,
)
from forensic_data.postgres_sql import PostgresRelation
from forensic_data.reporting import HistoryAttemptStatus, StoredResultAvailability
from forensic_data.result import ReasonCode, ResultReason
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.postgres_support import connect_writer

pytestmark = [pytest.mark.integration, pytest.mark.postgres]

_CONTRACT_PATH = Path(__file__).parents[1] / "examples/postgres-relation-manifest/contract.yaml"
_NO_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_SOURCE_RETRY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)
_REFERENCE_BATCH = "reference-batch-2026-09-23"
_TARGET_BATCH = "target-batch-2026-09-23"
_BUSINESS_DATE = date(2026, 9, 23)
_COMPLETED_AT = datetime(2026, 9, 23, 12, 30, 45, 123456, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _AcquiredSide:
    context: PostgresProtectedReadContext
    dataset_relation: PostgresProtectedRelationInspection
    readiness_relation: PostgresProtectedRelationInspection
    evidence: RelationManifestEvidence


def test_postgres_lifecycle_persists_frozen_union_composition_evidence() -> None:
    requested = required_metadata_database_settings()
    with disposable_metadata_database(requested) as settings:
        migrate_postgres_metadata(settings.migrator, _NO_RETRY, 5_000)
        config = load_contract_config(_CONTRACT_PATH)
        execution = replace(config.execution, max_queries=500)
        check = _frozen_reference_check(config.checks[0])
        registration = register_postgres_metadata(
            settings.writer,
            _NO_RETRY,
            build_metadata_registration_definition(config.version, check, config.evidence),
        )
        scope = resolve_scope_values(check, {"business_date": "2026-09-23"})
        _create_reference_inheritance_source_relations(
            settings,
            registration,
            scope.scope_digest,
        )
        run = claim_postgres_run(
            settings.writer,
            _NO_RETRY,
            uuid4(),
            uuid4(),
            _run_request(uuid4(), registration, check, execution, config.evidence),
        )
        attempt = start_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            run,
            uuid4(),
            uuid4(),
            uuid4(),
            datetime.now(UTC) + timedelta(minutes=5),
            execution,
        )
        source_budget = PostgresSourceBudgetLedger(execution).start_attempt(attempt.attempt_id)
        reference = _acquire_side(
            settings.writer,
            check,
            PlanDirection.REFERENCE,
            scope.scope_digest,
            _REFERENCE_BATCH,
            source_budget,
        )
        target = _acquire_side(
            settings.writer,
            check,
            PlanDirection.TARGET,
            scope.scope_digest,
            _TARGET_BATCH,
            source_budget,
        )
        try:
            persist_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                attempt,
                _context_definition(
                    registration.reference_dataset,
                    PlanDirection.REFERENCE,
                    reference,
                ),
            )
            persist_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                attempt,
                _context_definition(
                    registration.target_dataset,
                    PlanDirection.TARGET,
                    target,
                ),
            )
            cut = build_input_cut_definition(reference.evidence, target.evidence)
            persist_postgres_aligned_input_cut(
                settings.writer,
                _NO_RETRY,
                attempt,
                _cut_persistence(uuid4(), cut, registration, reference, target),
            )
            _assert_frozen_union_persistence(settings, attempt.attempt_id, reference)
        finally:
            reference.context.close()
            target.context.close()


def test_postgres_lifecycle_reconciles_fences_cuts_and_terminal_publication() -> None:
    requested = required_metadata_database_settings()
    with disposable_metadata_database(requested) as settings:
        migrate_postgres_metadata(settings.migrator, _NO_RETRY, 5_000)
        config = load_contract_config(_CONTRACT_PATH)
        execution = replace(config.execution, max_queries=500)
        check = config.checks[0]
        registration = register_postgres_metadata(
            settings.writer,
            _NO_RETRY,
            build_metadata_registration_definition(config.version, check, config.evidence),
        )
        scope = resolve_scope_values(check, {"business_date": "2026-09-23"})
        _create_source_relations(settings, registration, scope.scope_digest)
        request_id = uuid4()
        request = _run_request(
            request_id,
            registration,
            check,
            execution,
            config.evidence,
        )

        run_id = uuid4()
        creation_operation_id = uuid4()
        run = claim_postgres_run(
            settings.writer,
            _NO_RETRY,
            run_id,
            creation_operation_id,
            request,
        )
        assert (
            claim_postgres_run(
                settings.writer,
                _NO_RETRY,
                run_id,
                creation_operation_id,
                request,
            )
            == run
        )
        conflicting_request = build_run_request_definition(
            request_id=request_id,
            contract_version_id=registration.contract.contract_version_id,
            origin="pytest",
            check=check,
            scope=scope,
            reference_expected_batch_id=_REFERENCE_BATCH,
            target_expected_batch_id="different-target-batch",
            execution_policy=execution,
            evidence_policy=config.evidence,
        )
        with pytest.raises(RunRequestConflictError):
            claim_postgres_run(
                settings.writer,
                _NO_RETRY,
                uuid4(),
                uuid4(),
                conflicting_request,
            )

        first_start_operation = uuid4()
        first_owner = uuid4()
        first_expiry = datetime.now(UTC) + timedelta(minutes=5)
        first = start_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            run,
            uuid4(),
            first_start_operation,
            first_owner,
            first_expiry,
            execution,
        )
        with pytest.raises(ActiveRunAttemptError):
            start_postgres_run_attempt(
                settings.writer,
                _NO_RETRY,
                run,
                uuid4(),
                uuid4(),
                uuid4(),
                first_expiry,
                execution,
            )
        first_renewal_operation = uuid4()
        first_renewed = renew_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            first,
            first_renewal_operation,
            first_expiry + timedelta(minutes=1),
        )
        twice_renewed = renew_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            first_renewed,
            uuid4(),
            first_expiry + timedelta(minutes=2),
        )
        assert twice_renewed.lease_revision == 2
        start_replay = start_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            run,
            first.attempt_id,
            first_start_operation,
            first_owner,
            first_expiry,
            execution,
        )
        assert start_replay.lease_revision == 2
        old_renewal_replay = renew_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            first,
            first_renewal_operation,
            first_expiry + timedelta(minutes=1),
        )
        assert old_renewal_replay == twice_renewed
        with pytest.raises(LifecycleOperationConflictError):
            renew_postgres_run_attempt(
                settings.writer,
                _NO_RETRY,
                first,
                first_renewal_operation,
                first_expiry + timedelta(minutes=3),
            )

        source_budget_ledger = PostgresSourceBudgetLedger(execution)
        first_source_budget = source_budget_ledger.start_attempt(first.attempt_id)
        first_reference = _acquire_side(
            settings.writer,
            check,
            PlanDirection.REFERENCE,
            scope.scope_digest,
            _REFERENCE_BATCH,
            first_source_budget,
        )
        first_target = _acquire_side(
            settings.writer,
            check,
            PlanDirection.TARGET,
            scope.scope_digest,
            _TARGET_BATCH,
            first_source_budget,
        )
        cut_binding_operation = uuid4()
        try:
            reference_context = _context_definition(
                registration.reference_dataset,
                PlanDirection.REFERENCE,
                first_reference,
            )
            with pytest.raises(AttemptFenceError):
                persist_postgres_read_context(
                    settings.writer,
                    _NO_RETRY,
                    first,
                    reference_context,
                )
            persisted_reference = persist_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                twice_renewed,
                reference_context,
            )
            target_context = _context_definition(
                registration.target_dataset,
                PlanDirection.TARGET,
                first_target,
            )
            persisted_target = persist_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                twice_renewed,
                target_context,
            )
            cut = build_input_cut_definition(
                first_reference.evidence,
                first_target.evidence,
            )
            narrow_cut = _narrow_alignment_cut(first_reference.evidence, first_target.evidence)
            with pytest.raises(ValueError, match="alignment fields"):
                persist_postgres_aligned_input_cut(
                    settings.writer,
                    _NO_RETRY,
                    twice_renewed,
                    _cut_persistence(
                        uuid4(),
                        narrow_cut,
                        registration,
                        first_reference,
                        first_target,
                    ),
                )
            first_cut_persistence = _cut_persistence(
                cut_binding_operation,
                cut,
                registration,
                first_reference,
                first_target,
            )
            with pytest.raises(ValueError, match="readiness relation"):
                replace(
                    first_cut_persistence.reference,
                    readiness_relation=first_reference.dataset_relation,
                )
            first_persisted_cut = persist_postgres_aligned_input_cut(
                settings.writer,
                _NO_RETRY,
                twice_renewed,
                first_cut_persistence,
            )
            assert first_persisted_cut.input_cut == cut
            close_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                twice_renewed,
                persisted_reference.read_context_id,
                uuid4(),
                datetime.now(UTC),
            )
            close_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                twice_renewed,
                persisted_target.read_context_id,
                uuid4(),
                datetime.now(UTC),
            )
        finally:
            first_reference.context.close()
            first_target.context.close()

        replayed_reference = persist_postgres_read_context(
            settings.writer,
            _NO_RETRY,
            twice_renewed,
            reference_context,
        )
        replayed_target = persist_postgres_read_context(
            settings.writer,
            _NO_RETRY,
            twice_renewed,
            target_context,
        )
        assert replayed_reference.read_context_id == persisted_reference.read_context_id
        assert replayed_reference.state is ReadContextStatus.CLOSED
        assert replayed_target.read_context_id == persisted_target.read_context_id
        assert replayed_target.state is ReadContextStatus.CLOSED
        assert (
            persist_postgres_aligned_input_cut(
                settings.writer,
                _NO_RETRY,
                twice_renewed,
                first_cut_persistence,
            )
            == first_persisted_cut
        )
        unpersisted = _acquire_side(
            settings.writer,
            check,
            PlanDirection.REFERENCE,
            scope.scope_digest,
            _REFERENCE_BATCH,
            first_source_budget,
        )
        unpersisted_definition = _context_definition(
            registration.reference_dataset,
            PlanDirection.REFERENCE,
            unpersisted,
        )
        unpersisted.context.close()
        with pytest.raises(RunLifecycleStateError, match="active protected source context"):
            persist_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                twice_renewed,
                unpersisted_definition,
            )
        first_remaining = source_budget_ledger.remaining()
        first_usage = first_source_budget.overall_snapshot()
        assert first_usage.queries > 0
        assert first_remaining.queries == execution.max_queries - first_usage.queries
        assert (
            first_remaining.fetched_records
            == execution.max_fetched_records - first_usage.fetched_records
        )
        assert (
            first_remaining.result_bytes
            == execution.max_application_result_bytes - first_usage.result_bytes
        )

        retryable = record_postgres_retryable_incomplete_attempt(
            settings.writer,
            _NO_RETRY,
            twice_renewed,
            uuid4(),
            _reason(ReasonCode.NOT_READY, "retry after an incomplete source cut"),
            datetime.now(UTC),
        )
        assert retryable.status is AttemptStatus.INCOMPLETE

        second_start_operation = uuid4()
        second_owner = first_owner
        second_expiry = datetime.now(UTC) + timedelta(minutes=5)
        with pytest.raises(
            RunInvocationContinuationError,
            match="inspect durable history and use a new request UUID",
        ):
            start_postgres_run_attempt(
                settings.writer,
                _NO_RETRY,
                run,
                uuid4(),
                uuid4(),
                uuid4(),
                second_expiry,
                execution,
            )
        second = start_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            run,
            uuid4(),
            second_start_operation,
            second_owner,
            second_expiry,
            execution,
        )
        with connect_writer(settings.admin) as connection:
            connection.execute("UPDATE dfe_demo.target_orders SET amount = 11.00")
        active_history = read_postgres_history(
            settings.reader,
            _NO_RETRY,
            check.check_id,
            scope.scope_digest,
            100,
            None,
        )
        active_by_attempt = {item.attempt_id: item for item in active_history.items}
        assert active_by_attempt[first.attempt_id].status is HistoryAttemptStatus.INCOMPLETE
        assert active_by_attempt[second.attempt_id].status is HistoryAttemptStatus.RUNNING
        assert active_by_attempt[second.attempt_id].end_operation_id is None
        assert active_by_attempt[second.attempt_id].ended_at is None
        assert active_by_attempt[second.attempt_id].terminal_reason is None
        assert (
            active_by_attempt[second.attempt_id].stored_result_availability
            is StoredResultAvailability.NOT_CREATED
        )
        assert active_by_attempt[second.attempt_id].stored_result is None
        second_source_budget = source_budget_ledger.start_attempt(second.attempt_id)
        second_reference = _acquire_side(
            settings.writer,
            check,
            PlanDirection.REFERENCE,
            scope.scope_digest,
            _REFERENCE_BATCH,
            second_source_budget,
        )
        second_target = _acquire_side(
            settings.writer,
            check,
            PlanDirection.TARGET,
            scope.scope_digest,
            _TARGET_BATCH,
            second_source_budget,
        )
        try:
            second_reference_context = persist_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                second,
                _context_definition(
                    registration.reference_dataset,
                    PlanDirection.REFERENCE,
                    second_reference,
                ),
            )
            second_target_context = persist_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                second,
                _context_definition(
                    registration.target_dataset,
                    PlanDirection.TARGET,
                    second_target,
                ),
            )
            changed_cut = _changed_source_cut(registration, check, scope.scope_digest)
            with pytest.raises(InputCutMismatchError):
                persist_postgres_aligned_input_cut(
                    settings.writer,
                    _NO_RETRY,
                    second,
                    _cut_persistence(
                        cut_binding_operation,
                        changed_cut,
                        registration,
                        second_reference,
                        second_target,
                    ),
                )
            _assert_attempt_has_no_observations(settings, second.attempt_id)
            second_cut = build_input_cut_definition(
                second_reference.evidence,
                second_target.evidence,
            )
            same_cut = persist_postgres_aligned_input_cut(
                settings.writer,
                _NO_RETRY,
                second,
                _cut_persistence(
                    cut_binding_operation,
                    second_cut,
                    registration,
                    second_reference,
                    second_target,
                ),
            )
            assert same_cut.input_cut.input_cut_digest == cut.input_cut_digest
            comparison_artifact = execute_postgres_integer_key_comparison(
                second_reference.context,
                second_reference.dataset_relation,
                second_target.context,
                second_target.dataset_relation,
                check,
                scope,
                second_cut,
                execution,
                config.evidence,
                second_source_budget,
            )
            assert isinstance(comparison_artifact, CompletedComparisonArtifact)
            second_remaining = source_budget_ledger.remaining()
            assert comparison_artifact.metrics.queries > 0
            assert comparison_artifact.metrics.fetched_records > 0
            assert comparison_artifact.metrics.result_bytes > 0
            assert (
                second_remaining.queries
                == first_remaining.queries - comparison_artifact.metrics.queries
            )
            assert (
                second_remaining.fetched_records
                == first_remaining.fetched_records - comparison_artifact.metrics.fetched_records
            )
            assert (
                second_remaining.result_bytes
                == first_remaining.result_bytes - comparison_artifact.metrics.result_bytes
            )
            assert (
                second_remaining.reference_full_scans
                == first_remaining.reference_full_scans - comparison_artifact.reference_full_scans
            )
            assert (
                second_remaining.target_full_scans
                == first_remaining.target_full_scans - comparison_artifact.target_full_scans
            )
            close_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                second,
                second_reference_context.read_context_id,
                uuid4(),
                datetime.now(UTC),
            )
            close_postgres_read_context(
                settings.writer,
                _NO_RETRY,
                second,
                second_target_context.read_context_id,
                uuid4(),
                datetime.now(UTC),
            )
        finally:
            second_reference.context.close()
            second_target.context.close()

        mixed_cut = replace(
            same_cut,
            observation_ids=(
                first_persisted_cut.observation_ids[0],
                same_cut.observation_ids[1],
            ),
        )
        mixed_definition, mixed_segments, mixed_anomalies = (
            completed_comparison_persistence_from_artifact(
                second,
                mixed_cut,
                comparison_artifact,
            )
        )
        assert len(mixed_anomalies) == 1
        with pytest.raises(
            StoredLifecycleIntegrityError,
            match="observation differs from its bound context, cut, or scope",
        ):
            publish_postgres_completed_comparison(
                settings.writer,
                _NO_RETRY,
                second,
                uuid4(),
                mixed_definition,
                mixed_segments,
                mixed_anomalies,
                datetime.now(UTC),
            )
        _assert_attempt_has_no_comparison(settings, second.attempt_id)

        terminal_operation = uuid4()
        terminal_reason = _reason(
            ReasonCode.PERSISTENCE_ERROR,
            "comparison could not be persisted",
        )
        terminal_at = datetime.now(UTC)
        barrier = Barrier(2)
        competing_attempt_id = uuid4()
        competing_start_operation_id = uuid4()
        competing_owner = uuid4()
        competing_expiry = datetime.now(UTC) + timedelta(minutes=5)

        def start_competing_attempt() -> RunAttemptRecord:
            barrier.wait()
            return start_postgres_run_attempt(
                settings.writer,
                _NO_RETRY,
                run,
                competing_attempt_id,
                competing_start_operation_id,
                competing_owner,
                competing_expiry,
                execution,
            )

        def publish_failure() -> AttemptOutcomeRecord:
            barrier.wait()
            return publish_postgres_terminal_error_attempt(
                settings.writer,
                _NO_RETRY,
                second,
                terminal_operation,
                terminal_reason,
                terminal_at,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            start_future = executor.submit(start_competing_attempt)
            terminal_future = executor.submit(publish_failure)
            terminal = terminal_future.result(timeout=10.0)
            with pytest.raises((ActiveRunAttemptError, RunLifecycleStateError)):
                start_future.result(timeout=10.0)
        assert terminal.status is AttemptStatus.ERROR
        _assert_attempt_absent(settings, competing_attempt_id)
        final_replay = _replay_start(
            settings.writer,
            run,
            second,
            second_start_operation,
            second_owner,
            second_expiry,
            execution,
        )
        assert final_replay.status is AttemptStatus.ERROR
        assert final_replay.run.selected_terminal_attempt_id == second.attempt_id
        _assert_terminal_failure(settings, run.run_id, second.attempt_id)
        terminal_history = read_postgres_history(
            settings.reader,
            _NO_RETRY,
            check.check_id,
            scope.scope_digest,
            100,
            None,
        )
        terminal_by_attempt = {item.attempt_id: item for item in terminal_history.items}
        assert terminal_by_attempt[first.attempt_id].status is HistoryAttemptStatus.INCOMPLETE
        assert terminal_by_attempt[second.attempt_id].status is HistoryAttemptStatus.ERROR
        assert terminal_by_attempt[second.attempt_id].is_run_terminal
        assert terminal_by_attempt[second.attempt_id].terminal_reason == terminal_reason
        assert terminal_by_attempt[second.attempt_id].stored_result is None


def test_postgres_lifecycle_fences_waits_and_reconciles_store_loss() -> None:
    requested = required_metadata_database_settings()
    with disposable_metadata_database(requested) as settings:
        migrate_postgres_metadata(settings.migrator, _NO_RETRY, 5_000)
        config = load_contract_config(_CONTRACT_PATH)
        check = config.checks[0]
        registration = register_postgres_metadata(
            settings.writer,
            _NO_RETRY,
            build_metadata_registration_definition(config.version, check, config.evidence),
        )

        store_run, _ = _claim_new_run(
            settings,
            registration,
            check,
            config.execution,
            config.evidence,
        )
        store_expiry = _server_now(settings.admin) + timedelta(minutes=10)
        store_attempt = start_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            store_run,
            uuid4(),
            uuid4(),
            uuid4(),
            store_expiry,
            config.execution,
        )

        candidate_run, _ = _claim_new_run(
            settings,
            registration,
            check,
            config.execution,
            config.evidence,
        )
        blocker_run, _ = _claim_new_run(
            settings,
            registration,
            check,
            config.execution,
            config.evidence,
        )
        candidate_attempt_id = uuid4()
        candidate_start_operation = uuid4()
        candidate_owner = uuid4()
        candidate_expiry = _server_now(settings.admin) + timedelta(seconds=2)
        start_application = f"lifecycle-start-expiry-{uuid4().hex}"
        start_settings = _settings_with_application_name(settings.writer, start_application)
        with (
            connect_writer(settings.admin) as blocker,
            connect_writer(settings.admin) as observer,
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            blocker.execute("BEGIN")
            blocker.execute(
                "INSERT INTO dfe_metadata.run_attempts ("
                "attempt_id, run_id, ordinal, start_operation_id, execution_budgets, "
                "owner_token, initial_lease_expires_at, lease_expires_at"
                ") SELECT %s, %s, 1, %s, execution_budgets, %s, %s, %s "
                "FROM dfe_metadata.run_attempts WHERE attempt_id = %s",
                (
                    candidate_attempt_id,
                    blocker_run.run_id,
                    uuid4(),
                    uuid4(),
                    candidate_expiry + timedelta(minutes=5),
                    candidate_expiry + timedelta(minutes=5),
                    store_attempt.attempt_id,
                ),
            )
            start_future = executor.submit(
                start_postgres_run_attempt,
                start_settings,
                _NO_RETRY,
                candidate_run,
                candidate_attempt_id,
                candidate_start_operation,
                candidate_owner,
                candidate_expiry,
                config.execution,
            )
            _wait_for_lock_wait(observer, start_application, frozenset(), 5.0)
            _sleep_until_server_time(
                observer,
                candidate_expiry + timedelta(milliseconds=50),
            )
            blocker.execute("ROLLBACK")
            with pytest.raises(AttemptFenceError):
                start_future.result(timeout=10.0)
        _assert_start_receipt_absent(
            settings,
            candidate_attempt_id,
            candidate_start_operation,
        )

        renewal_run, _ = _claim_new_run(
            settings,
            registration,
            check,
            config.execution,
            config.evidence,
        )
        renewal_expiry = _server_now(settings.admin) + timedelta(seconds=2)
        renewal_attempt = start_postgres_run_attempt(
            settings.writer,
            _NO_RETRY,
            renewal_run,
            uuid4(),
            uuid4(),
            uuid4(),
            renewal_expiry,
            config.execution,
        )
        renewal_blocker_run, _ = _claim_new_run(
            settings,
            registration,
            check,
            config.execution,
            config.evidence,
        )
        renewal_operation = uuid4()
        renewed_expiry = renewal_expiry + timedelta(minutes=5)
        renewal_application = f"lifecycle-renew-expiry-{uuid4().hex}"
        renewal_settings = _settings_with_application_name(
            settings.writer,
            renewal_application,
        )
        with (
            connect_writer(settings.admin) as blocker,
            connect_writer(settings.admin) as observer,
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            blocker.execute("BEGIN")
            blocker.execute(
                "INSERT INTO dfe_metadata.run_attempts ("
                "attempt_id, run_id, ordinal, start_operation_id, execution_budgets, "
                "owner_token, lease_revision, initial_lease_expires_at, "
                "lease_expires_at, lease_operation_id"
                ") SELECT %s, %s, 1, %s, execution_budgets, %s, 1, %s, %s, %s "
                "FROM dfe_metadata.run_attempts WHERE attempt_id = %s",
                (
                    uuid4(),
                    renewal_blocker_run.run_id,
                    uuid4(),
                    uuid4(),
                    renewed_expiry,
                    renewed_expiry,
                    renewal_operation,
                    store_attempt.attempt_id,
                ),
            )
            renewal_future = executor.submit(
                renew_postgres_run_attempt,
                renewal_settings,
                _NO_RETRY,
                renewal_attempt,
                renewal_operation,
                renewed_expiry,
            )
            _wait_for_lock_wait(observer, renewal_application, frozenset(), 5.0)
            _sleep_until_server_time(
                observer,
                renewal_expiry + timedelta(milliseconds=50),
            )
            blocker.execute("ROLLBACK")
            with pytest.raises(AttemptFenceError):
                renewal_future.result(timeout=10.0)
        _assert_renewal_unchanged(
            settings,
            renewal_attempt,
            renewal_operation,
        )

        pending_run_id = uuid4()
        pending_creation_operation = uuid4()
        pending_request = _run_request(
            uuid4(),
            registration,
            check,
            config.execution,
            config.evidence,
        )
        pending_application = f"lifecycle-pending-receipt-{uuid4().hex}"
        pending_settings = _settings_with_application_name(
            settings.writer,
            pending_application,
        )
        with (
            connect_writer(settings.admin) as blocker,
            connect_writer(settings.admin) as observer,
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            _begin_writer_fixture(blocker)
            _fixture_lock_operation_identities(
                blocker,
                (
                    pending_run_id,
                    pending_creation_operation,
                    pending_request.request_id,
                ),
            )
            _insert_pending_run_receipt(
                blocker,
                pending_run_id,
                pending_creation_operation,
                pending_request,
            )
            pending_future = executor.submit(
                claim_postgres_run,
                pending_settings,
                _NO_RETRY,
                pending_run_id,
                pending_creation_operation,
                pending_request,
            )
            first_backend = _wait_for_lock_wait(
                observer,
                pending_application,
                frozenset(),
                5.0,
            )
            _terminate_backend(observer, first_backend)
            _wait_for_lock_wait(
                observer,
                pending_application,
                frozenset((first_backend,)),
                5.0,
            )
            blocker.execute("COMMIT")
            reconciled_run = pending_future.result(timeout=10.0)
        assert reconciled_run.run_id == pending_run_id
        assert reconciled_run.creation_operation_id == pending_creation_operation

        terminal_operation = uuid4()
        terminal_application = f"lifecycle-store-loss-{uuid4().hex}"
        terminal_settings = _settings_with_application_name(
            settings.writer,
            terminal_application,
        )
        with (
            connect_writer(settings.admin) as blocker,
            connect_writer(settings.admin) as observer,
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            _begin_writer_fixture(blocker)
            blocker.execute(
                "SELECT run_id FROM dfe_metadata.runs WHERE run_id = %s FOR UPDATE",
                (store_run.run_id,),
            ).fetchone()
            terminal_future = executor.submit(
                publish_postgres_terminal_error_attempt,
                terminal_settings,
                _NO_RETRY,
                store_attempt,
                terminal_operation,
                _reason(ReasonCode.PERSISTENCE_ERROR, "metadata store connection lost"),
                datetime.now(UTC),
            )
            terminal_backend = _wait_for_lock_wait(
                observer,
                terminal_application,
                frozenset(),
                5.0,
            )
            _terminate_backend(observer, terminal_backend)
            with pytest.raises(LifecycleTransactionError):
                terminal_future.result(timeout=10.0)
            blocker.execute("ROLLBACK")
        _assert_terminal_receipt_absent(
            settings,
            store_run.run_id,
            store_attempt.attempt_id,
            terminal_operation,
        )


def _run_request(
    request_id: UUID,
    registration: MetadataRegistration,
    check: RowCheckDefinition,
    execution_policy: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
) -> RunRequestDefinition:
    return build_run_request_definition(
        request_id=request_id,
        contract_version_id=registration.contract.contract_version_id,
        origin="pytest",
        check=check,
        scope=resolve_scope_values(check, {"business_date": "2026-09-23"}),
        reference_expected_batch_id=_REFERENCE_BATCH,
        target_expected_batch_id=_TARGET_BATCH,
        execution_policy=execution_policy,
        evidence_policy=evidence_policy,
    )


def _claim_new_run(
    settings: MetadataDatabaseSettings,
    registration: MetadataRegistration,
    check: RowCheckDefinition,
    execution_policy: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
) -> tuple[ClaimedRun, RunRequestDefinition]:
    request = _run_request(
        uuid4(),
        registration,
        check,
        execution_policy,
        evidence_policy,
    )
    return (
        claim_postgres_run(
            settings.writer,
            _NO_RETRY,
            uuid4(),
            uuid4(),
            request,
        ),
        request,
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


def _server_now(settings: PostgresConnectionSettings) -> datetime:
    with connect_writer(settings) as connection:
        row = connection.execute("SELECT pg_catalog.clock_timestamp()").fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], datetime):
        raise AssertionError("PostgreSQL server-clock probe returned an invalid row")
    return row[0]


def _begin_writer_fixture(connection: psycopg.Connection[DatabaseRow]) -> None:
    connection.execute("BEGIN")
    connection.execute("SET LOCAL ROLE dfe_metadata_writer")


def _wait_for_lock_wait(
    observer: psycopg.Connection[DatabaseRow],
    application_name: str,
    excluded_backends: frozenset[int],
    timeout_seconds: float,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        rows = observer.execute(
            "SELECT DISTINCT activity.pid FROM pg_catalog.pg_locks AS waiting_lock "
            "JOIN pg_catalog.pg_stat_activity AS activity ON activity.pid = waiting_lock.pid "
            "WHERE activity.application_name = %s AND NOT waiting_lock.granted "
            "ORDER BY activity.pid",
            (application_name,),
        ).fetchall()
        for row in rows:
            if len(row) != 1 or type(row[0]) is not int:
                raise AssertionError("PostgreSQL lock-wait observation returned an invalid row")
            if row[0] not in excluded_backends:
                return row[0]
        time.sleep(0.01)
    raise AssertionError(
        f"PostgreSQL backend did not enter an observable lock wait: "
        f"application_name={application_name!r}"
    )


def _sleep_until_server_time(
    connection: psycopg.Connection[DatabaseRow],
    deadline: datetime,
) -> None:
    connection.execute("SELECT pg_catalog.pg_sleep_until(%s)", (deadline,)).fetchone()


def _fixture_lock_operation_identities(
    connection: psycopg.Connection[DatabaseRow],
    identities: tuple[UUID, ...],
) -> None:
    for identity in sorted(set(identities), key=lambda value: value.int):
        connection.execute(
            "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s, 1145455922))",
            (str(identity),),
        )


def _insert_pending_run_receipt(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    creation_operation_id: UUID,
    request: RunRequestDefinition,
) -> None:
    connection.execute(
        "INSERT INTO dfe_metadata.runs ("
        "run_id, creation_operation_id, request_id, request_identity_digest, "
        "request_payload, contract_version_id, origin, scope_digest"
        ") VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s)",
        (
            run_id,
            creation_operation_id,
            request.request_id,
            bytes.fromhex(request.request_identity_digest),
            canonical_semantic_json(run_request_semantic_value(request)),
            request.contract_version_id,
            request.origin,
            bytes.fromhex(request.scope.scope_digest),
        ),
    )


def _terminate_backend(
    connection: psycopg.Connection[DatabaseRow],
    backend_process_id: int,
) -> None:
    row = connection.execute(
        "SELECT pg_catalog.pg_terminate_backend(%s)",
        (backend_process_id,),
    ).fetchone()
    assert row == (True,)


def _assert_start_receipt_absent(
    settings: MetadataDatabaseSettings,
    attempt_id: UUID,
    start_operation_id: UUID,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET ROLE dfe_metadata_reader")
        row = connection.execute(
            "SELECT pg_catalog.count(*) FROM dfe_metadata.run_attempts "
            "WHERE attempt_id = %s OR start_operation_id = %s",
            (attempt_id, start_operation_id),
        ).fetchone()
    assert row == (0,)


def _assert_renewal_unchanged(
    settings: MetadataDatabaseSettings,
    attempt: RunAttemptRecord,
    renewal_operation_id: UUID,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET ROLE dfe_metadata_reader")
        attempt_row = connection.execute(
            "SELECT lease_revision, lease_operation_id, lease_expires_at "
            "FROM dfe_metadata.run_attempts WHERE attempt_id = %s",
            (attempt.attempt_id,),
        ).fetchone()
        receipt_row = connection.execute(
            "SELECT pg_catalog.count(*) FROM dfe_metadata.attempt_lease_renewals "
            "WHERE lease_operation_id = %s",
            (renewal_operation_id,),
        ).fetchone()
    assert attempt_row == (0, None, attempt.lease_expires_at)
    assert receipt_row == (0,)


def _assert_terminal_receipt_absent(
    settings: MetadataDatabaseSettings,
    run_id: UUID,
    attempt_id: UUID,
    terminal_operation_id: UUID,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET ROLE dfe_metadata_reader")
        row = connection.execute(
            "SELECT r.selected_terminal_attempt_id, r.terminal_operation_id, "
            "a.status, a.end_operation_id, a.terminal_reason_code "
            "FROM dfe_metadata.runs AS r "
            "JOIN dfe_metadata.run_attempts AS a ON a.run_id = r.run_id "
            "WHERE r.run_id = %s AND a.attempt_id = %s",
            (run_id, attempt_id),
        ).fetchone()
        receipt_row = connection.execute(
            "SELECT pg_catalog.count(*) FROM dfe_metadata.run_attempts WHERE end_operation_id = %s",
            (terminal_operation_id,),
        ).fetchone()
    assert row == (None, None, "running", None, None)
    assert receipt_row == (0,)


def _assert_attempt_has_no_comparison(
    settings: MetadataDatabaseSettings,
    attempt_id: UUID,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET ROLE dfe_metadata_reader")
        row = connection.execute(
            "SELECT status, "
            "(SELECT pg_catalog.count(*) FROM dfe_metadata.check_results "
            "WHERE attempt_id = %s), "
            "(SELECT pg_catalog.count(*) FROM dfe_metadata.segment_fingerprints "
            "WHERE attempt_id = %s), "
            "(SELECT pg_catalog.count(*) FROM dfe_metadata.anomalies "
            "WHERE attempt_id = %s) "
            "FROM dfe_metadata.run_attempts WHERE attempt_id = %s",
            (attempt_id, attempt_id, attempt_id, attempt_id),
        ).fetchone()
    assert row == ("running", 0, 0, 0)


def _context_definition(
    dataset: DatasetVersionRecord,
    direction: PlanDirection,
    acquired: _AcquiredSide,
) -> ReadContextPersistence:
    return ReadContextPersistence(
        acquisition_operation_id=uuid4(),
        dataset=dataset,
        direction=direction,
        protected_context=acquired.context,
    )


def _cut_persistence(
    binding_operation_id: UUID,
    cut: InputCutDefinition,
    registration: MetadataRegistration,
    reference: _AcquiredSide,
    target: _AcquiredSide,
) -> AlignedInputCutPersistence:
    recorded_at = datetime.now(UTC)
    reference_for_cut = replace(
        reference,
        evidence=replace(
            reference.evidence,
            late_arrivals=cut.late_arrivals,
            cut=cut.reference,
        ),
    )
    target_for_cut = replace(
        target,
        evidence=replace(
            target.evidence,
            late_arrivals=cut.late_arrivals,
            cut=cut.target,
        ),
    )
    return AlignedInputCutPersistence(
        cut_binding_operation_id=binding_operation_id,
        attempt_cut_operation_id=uuid4(),
        input_cut=cut,
        reference=_observation(
            registration.reference_dataset,
            PlanDirection.REFERENCE,
            reference_for_cut,
            recorded_at,
        ),
        target=_observation(
            registration.target_dataset,
            PlanDirection.TARGET,
            target_for_cut,
            recorded_at,
        ),
        recorded_at=recorded_at,
    )


def _observation(
    dataset: DatasetVersionRecord,
    direction: PlanDirection,
    acquired: _AcquiredSide,
    observed_at: datetime,
) -> RelationManifestObservationPersistence:
    return RelationManifestObservationPersistence(
        observation_id=uuid4(),
        observation_operation_id=uuid4(),
        dataset=dataset,
        direction=direction,
        readiness=acquired.evidence,
        protected_context=acquired.context,
        dataset_relation=acquired.dataset_relation,
        readiness_relation=acquired.readiness_relation,
        projection_code_artifact=None,
        observed_at=observed_at,
    )


def _acquire_side(
    settings: PostgresConnectionSettings,
    check: RowCheckDefinition,
    direction: PlanDirection,
    scope_digest: str,
    batch_id: str,
    source_budget: PostgresSourceBudgetAttempt,
) -> _AcquiredSide:
    dataset = check.reference if direction is PlanDirection.REFERENCE else check.target
    consistency = check.consistency.datasets[0 if direction is PlanDirection.REFERENCE else 1]
    readiness = consistency.readiness
    assert isinstance(dataset.locator, RelationLocator)
    assert isinstance(readiness, RelationManifestReadiness)
    dataset_relation = PostgresRelation(components=(dataset.locator.schema, dataset.locator.name))
    readiness_relation = PostgresRelation(
        components=(readiness.relation.schema, readiness.relation.name)
    )
    context = open_postgres_protected_read_context(
        settings,
        _SOURCE_RETRY,
        (
            _acquisition(
                dataset.logical_schema.schema,
                dataset_relation,
                tuple(item.column_name for item in dataset.projection),
                dataset.locator.relation_scope,
            ),
            _acquisition(
                _manifest_schema(),
                readiness_relation,
                readiness.columns.values(),
                readiness.relation.relation_scope,
            ),
        ),
        2_000,
        source_budget,
        PostgresSourceDirection(direction.value),
    )
    protected = context.protected_relations
    dataset_protected = _protected_relation(protected, dataset_relation)
    readiness_protected = _protected_relation(protected, readiness_relation)
    rows = context.read_relation_manifest(
        readiness_protected,
        readiness.columns,
        dataset.dataset_id,
        scope_digest,
        4_096,
        32_768,
    )
    evidence = validate_relation_manifest_readiness(
        direction=direction,
        rows=rows,
        expected_dataset_id=dataset.dataset_id,
        expected_scope_digest=scope_digest,
        expected_batch_id=batch_id,
        alignment_fields=check.consistency.alignment_fields,
        minimum_evidence=check.consistency.minimum_evidence,
        late_arrivals=check.consistency.late_arrivals,
    )
    assert isinstance(evidence, RelationManifestEvidence)
    return _AcquiredSide(context, dataset_protected, readiness_protected, evidence)


def _protected_relation(
    protected: tuple[PostgresProtectedRelationInspection, ...],
    relation: PostgresRelation,
) -> PostgresProtectedRelationInspection:
    for item in protected:
        if item.inspection.relation == relation:
            return item
    raise AssertionError(f"protected relation is missing: {relation.components!r}")


def _acquisition(
    schema: CanonicalSchema,
    relation: PostgresRelation,
    columns: tuple[str, ...],
    relation_scope: RelationScope,
) -> PostgresRelationAcquisition:
    return PostgresRelationAcquisition(
        schema=schema,
        relation=relation,
        relation_scope=relation_scope,
        column_names=columns,
        max_metadata_record_bytes=4_096,
        max_metadata_total_bytes=32_768,
    )


def _frozen_reference_check(check: RowCheckDefinition) -> RowCheckDefinition:
    if not isinstance(check.reference.locator, RelationLocator) or not isinstance(
        check.target.locator,
        RelationLocator,
    ):
        raise AssertionError("frozen-union lifecycle fixture requires relation datasets")
    reference = replace(
        check.reference,
        locator=replace(
            check.reference.locator,
            relation_scope=RelationScope.FROZEN_PHYSICAL_UNION,
        ),
    )
    return replace(check, reference=reference)


def _manifest_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            _string_field("dataset_id", False),
            _string_field("scope_digest", False),
            _string_field("batch_id", False),
            _string_field("state", False),
            FieldSchema(
                name="business_date",
                logical_type=LogicalType.DATE,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            _string_field("source_cut", True),
            _string_field("dataset_version", True),
            FieldSchema(
                name="completed_at",
                logical_type=LogicalType.TIMESTAMP_INSTANT,
                nullable=True,
                parameters=TimestampParameters(precision=6),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _string_field(name: str, nullable: bool) -> FieldSchema:
    return FieldSchema(
        name=name,
        logical_type=LogicalType.STRING,
        nullable=nullable,
        parameters=NoParameters(),
        normalization=Normalization.NONE,
    )


def _narrow_alignment_cut(
    reference: RelationManifestEvidence,
    target: RelationManifestEvidence,
) -> InputCutDefinition:
    narrow_reference = replace(
        reference,
        cut=replace(reference.cut, alignment_values=(reference.cut.business_date,)),
    )
    narrow_target = replace(
        target,
        cut=replace(target.cut, alignment_values=(target.cut.business_date,)),
    )
    return build_input_cut_definition(narrow_reference, narrow_target)


def _changed_source_cut(
    registration: MetadataRegistration,
    check: RowCheckDefinition,
    scope_digest: str,
) -> InputCutDefinition:
    reference = _synthetic_evidence(
        PlanDirection.REFERENCE,
        registration.reference_dataset.definition.dataset_id,
        _REFERENCE_BATCH,
        "changed-source-cut",
        "reference-version-1",
        scope_digest,
        check,
    )
    target = _synthetic_evidence(
        PlanDirection.TARGET,
        registration.target_dataset.definition.dataset_id,
        _TARGET_BATCH,
        "changed-source-cut",
        "target-version-1",
        scope_digest,
        check,
    )
    return build_input_cut_definition(reference, target)


def _synthetic_evidence(
    direction: PlanDirection,
    dataset_id: str,
    batch_id: str,
    source_cut: str,
    dataset_version: str,
    scope_digest: str,
    check: RowCheckDefinition,
) -> RelationManifestEvidence:
    result = validate_relation_manifest_readiness(
        direction=direction,
        rows=(
            CompleteReadinessRecord(
                dataset_id=dataset_id,
                scope_digest=scope_digest,
                batch_id=batch_id,
                state="complete",
                business_date=_BUSINESS_DATE,
                source_cut=source_cut,
                dataset_version=dataset_version,
                completed_at=_COMPLETED_AT,
            ),
        ),
        expected_dataset_id=dataset_id,
        expected_scope_digest=scope_digest,
        expected_batch_id=batch_id,
        alignment_fields=check.consistency.alignment_fields,
        minimum_evidence=MinimumEvidence.VERIFIED,
        late_arrivals=LateArrivalPolicy.NEXT_BATCH,
    )
    assert isinstance(result, RelationManifestEvidence)
    return result


def _create_source_relations(
    settings: MetadataDatabaseSettings,
    registration: MetadataRegistration,
    scope_digest: str,
) -> None:
    with connect_writer(settings.admin) as connection:
        connection.execute("CREATE SCHEMA dfe_demo")
        connection.execute("CREATE SCHEMA dfe_control")
        connection.execute(
            "CREATE TABLE dfe_demo.reference_orders ("
            "order_id bigint PRIMARY KEY, business_date date NOT NULL, amount numeric(18,2))"
        )
        connection.execute(
            "CREATE TABLE dfe_demo.target_orders ("
            "order_id bigint PRIMARY KEY, business_date date NOT NULL, amount numeric(18,2))"
        )
        connection.execute(
            "CREATE TABLE dfe_control.batch_manifest ("
            "dataset_id text NOT NULL, scope_digest text NOT NULL, batch_id text NOT NULL, "
            "state text NOT NULL, business_date date NOT NULL, source_cut text, "
            "dataset_version text, completed_at timestamp(6) with time zone)"
        )
        connection.execute(
            "INSERT INTO dfe_demo.reference_orders VALUES (1, %s, 10.00)",
            (_BUSINESS_DATE,),
        )
        connection.execute(
            "INSERT INTO dfe_demo.target_orders VALUES (1, %s, 10.00)",
            (_BUSINESS_DATE,),
        )
        manifest_statement: LiteralString = (
            "INSERT INTO dfe_control.batch_manifest VALUES ("
            "%s, %s, %s, 'complete', %s, 'source-cut-42', %s, %s)"
        )
        connection.execute(
            manifest_statement,
            (
                registration.reference_dataset.definition.dataset_id,
                scope_digest,
                _REFERENCE_BATCH,
                _BUSINESS_DATE,
                "reference-version-1",
                _COMPLETED_AT,
            ),
        )
        connection.execute(
            manifest_statement,
            (
                registration.target_dataset.definition.dataset_id,
                scope_digest,
                _TARGET_BATCH,
                _BUSINESS_DATE,
                "target-version-1",
                _COMPLETED_AT,
            ),
        )
        connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_metadata_writer")
        connection.execute(
            "GRANT SELECT ON dfe_demo.reference_orders, dfe_demo.target_orders, "
            "dfe_control.batch_manifest TO dfe_metadata_writer"
        )


def _create_reference_inheritance_source_relations(
    settings: MetadataDatabaseSettings,
    registration: MetadataRegistration,
    scope_digest: str,
) -> None:
    _create_source_relations(settings, registration, scope_digest)
    with connect_writer(settings.admin) as connection:
        connection.execute(
            "CREATE TABLE dfe_demo.reference_orders_child () INHERITS (dfe_demo.reference_orders)"
        )
        connection.execute("GRANT SELECT ON dfe_demo.reference_orders_child TO dfe_metadata_writer")


def _assert_frozen_union_persistence(
    settings: MetadataDatabaseSettings,
    attempt_id: UUID,
    reference: _AcquiredSide,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET ROLE dfe_metadata_reader")
        context_row = connection.execute(
            "SELECT acquisition_evidence::text FROM dfe_metadata.attempt_read_contexts "
            "WHERE attempt_id = %s AND direction = 'reference'",
            (attempt_id,),
        ).fetchone()
        observation_rows = connection.execute(
            "SELECT direction, physical_binding::text, physical_binding_digest "
            "FROM dfe_metadata.dataset_observations WHERE attempt_id = %s",
            (attempt_id,),
        ).fetchall()
    assert context_row is not None
    assert len(observation_rows) == 2
    observations = {_test_text(row[0]): row for row in observation_rows}
    evidence = _test_semantic_object_from_json(
        _test_text(context_row[0]),
        "protected acquisition evidence",
    )
    acquisition_payload = _test_semantic_object(
        evidence.get("payload"),
        "protected acquisition payload",
    )
    relations = tuple(
        _test_semantic_object(item, "protected acquisition relation")
        for item in _test_semantic_array(
            acquisition_payload.get("relations"),
            "protected acquisition relations",
        )
    )
    frozen_relation = next(
        relation
        for relation in relations
        if relation.get("relation_scope") == RelationScope.FROZEN_PHYSICAL_UNION.value
    )
    physical_relation = next(
        relation for relation in relations if relation.get("relation_scope") is None
    )
    _assert_physical_only_relation_evidence(physical_relation)
    _assert_frozen_relation_evidence(frozen_relation, reference)

    composition = reference.dataset_relation.composition
    assert composition is not None
    lock_identities = [
        (member.inspection.relation.components, member.inspection.relation_oid)
        for member in composition.members
    ]
    lock_identities.append(
        (
            reference.readiness_relation.inspection.relation.components,
            reference.readiness_relation.inspection.relation_oid,
        )
    )
    persisted_lock_oids = acquisition_payload.get("locked_relation_oids")
    assert persisted_lock_oids == list(reference.context.evidence.locked_relation_oids)
    assert persisted_lock_oids == [
        relation_oid
        for _relation, relation_oid in sorted(
            lock_identities,
            key=lambda item: (item[0], item[1]),
        )
    ]

    reference_observation = observations["reference"]
    binding = _test_semantic_object_from_json(
        _test_text(reference_observation[1]),
        "physical binding",
    )
    assert _test_bytes(reference_observation[2]).hex() == semantic_digest_hex(binding)
    binding_payload = _test_semantic_object(
        binding.get("payload"),
        "physical binding payload",
    )
    assert binding_payload.get("dataset_relation") == frozen_relation
    assert binding_payload.get("readiness_relation") == physical_relation

    target_observation = observations["target"]
    target_binding = _test_semantic_object_from_json(
        _test_text(target_observation[1]),
        "target physical binding",
    )
    assert _test_bytes(target_observation[2]).hex() == semantic_digest_hex(target_binding)
    target_payload = _test_semantic_object(
        target_binding.get("payload"),
        "target physical binding payload",
    )
    _assert_physical_only_relation_evidence(
        _test_semantic_object(target_payload.get("dataset_relation"), "target dataset relation")
    )
    _assert_physical_only_relation_evidence(
        _test_semantic_object(
            target_payload.get("readiness_relation"),
            "target readiness relation",
        )
    )


def _assert_frozen_relation_evidence(
    relation: dict[str, SemanticValue],
    reference: _AcquiredSide,
) -> None:
    assert relation.get("relation_scope") == RelationScope.FROZEN_PHYSICAL_UNION.value
    composition = _test_semantic_object(
        relation.get("composition"),
        "protected relation composition",
    )
    composition_payload = {
        key: value for key, value in composition.items() if key != "composition_digest"
    }
    assert composition.get("composition_digest") == semantic_digest_hex(composition_payload)
    assert composition_payload.get("composition_version") == 1
    protected_composition = reference.dataset_relation.composition
    assert protected_composition is not None
    members = {
        _test_integer(member.get("relation_oid"), "composition member OID"): member
        for member in (
            _test_semantic_object(item, "protected composition member")
            for item in _test_semantic_array(
                composition_payload.get("members"),
                "protected composition members",
            )
        )
    }
    assert len(members) == len(protected_composition.members)
    for protected_member in protected_composition.members:
        member = members[protected_member.inspection.relation_oid]
        assert set(member) == {
            "columns",
            "namespace_oid",
            "physical_binding_digest",
            "relation_kind",
            "relation_oid",
            "relation_persistence",
            "relation_row_type_oid",
            "resolved_relation",
        }
        binding = {key: value for key, value in member.items() if key != "physical_binding_digest"}
        assert member.get("physical_binding_digest") == semantic_digest_hex(binding)
        assert (
            member.get("namespace_oid"),
            member.get("relation_kind"),
            member.get("relation_persistence"),
            member.get("relation_row_type_oid"),
            member.get("resolved_relation"),
            member.get("columns"),
        ) == (
            protected_member.namespace_oid,
            protected_member.relation_kind.value,
            protected_member.relation_persistence.value,
            protected_member.inspection.relation_row_type_oid,
            list(protected_member.inspection.relation.components),
            relation.get("columns"),
        )
    assert composition_payload.get("root_relation_oid") == (protected_composition.root_relation_oid)
    edges = {
        (
            edge.get("parent_relation_oid"),
            edge.get("child_relation_oid"),
            edge.get("inhseqno"),
            edge.get("detach_state"),
        )
        for edge in (
            _test_semantic_object(item, "protected composition edge")
            for item in _test_semantic_array(
                composition_payload.get("edges"),
                "protected composition edges",
            )
        )
    }
    assert edges == {
        (
            edge.parent_relation_oid,
            edge.child_relation_oid,
            edge.sequence,
            edge.detach_state.value,
        )
        for edge in protected_composition.edges
    }


def _assert_physical_only_relation_evidence(
    relation: dict[str, SemanticValue],
) -> None:
    assert set(relation) == {
        "acquired_before_snapshot",
        "columns",
        "lock_mode",
        "max_identifier_utf8_bytes",
        "namespace_oid",
        "relation_oid",
        "relation_persistence",
        "relation_row_type_oid",
        "requested_relation",
        "resolved_relation",
    }


def _test_semantic_object_from_json(
    value: str,
    context: str,
) -> dict[str, SemanticValue]:
    return _test_semantic_object(semantic_value_from_json(value), context)


def _test_semantic_object(
    value: SemanticValue | None,
    context: str,
) -> dict[str, SemanticValue]:
    if type(value) is not dict:
        raise AssertionError(f"{context} must be an object")
    return value


def _test_semantic_array(
    value: SemanticValue | None,
    context: str,
) -> list[SemanticValue]:
    if type(value) is not list:
        raise AssertionError(f"{context} must be an array")
    return value


def _test_text(value: object) -> str:
    if type(value) is not str:
        raise AssertionError("persisted lifecycle value must be text")
    return value


def _test_integer(value: SemanticValue | None, context: str) -> int:
    if type(value) is not int:
        raise AssertionError(f"{context} must be an integer")
    return value


def _test_bytes(value: object) -> bytes:
    if type(value) is not bytes:
        raise AssertionError("persisted lifecycle value must be bytes")
    return value


def _reason(code: ReasonCode, message: str) -> ResultReason:
    return ResultReason(
        code=code,
        operation="lifecycle_integration",
        message=message,
        safe_parameters=(),
        native_error_code=None,
        query_id=None,
        redacted_response=None,
    )


def _assert_attempt_has_no_observations(
    settings: MetadataDatabaseSettings,
    attempt_id: UUID,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET ROLE dfe_metadata_reader")
        row = connection.execute(
            "SELECT pg_catalog.count(*) FROM dfe_metadata.dataset_observations "
            "WHERE attempt_id = %s",
            (attempt_id,),
        ).fetchone()
    assert row == (0,)


def _assert_attempt_absent(
    settings: MetadataDatabaseSettings,
    attempt_id: UUID,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET ROLE dfe_metadata_reader")
        row = connection.execute(
            "SELECT pg_catalog.count(*) FROM dfe_metadata.run_attempts WHERE attempt_id = %s",
            (attempt_id,),
        ).fetchone()
    assert row == (0,)


def _replay_start(
    settings: PostgresConnectionSettings,
    run: ClaimedRun,
    attempt: RunAttemptRecord,
    start_operation_id: UUID,
    owner_token: UUID,
    lease_expires_at: datetime,
    execution_policy: ExecutionBudgets,
) -> RunAttemptRecord:
    return start_postgres_run_attempt(
        settings,
        _NO_RETRY,
        run,
        attempt.attempt_id,
        start_operation_id,
        owner_token,
        lease_expires_at,
        execution_policy,
    )


def _assert_terminal_failure(
    settings: MetadataDatabaseSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET ROLE dfe_metadata_reader")
        row = connection.execute(
            "SELECT r.selected_terminal_attempt_id, a.status, a.terminal_reason_code "
            "FROM dfe_metadata.runs AS r "
            "JOIN dfe_metadata.run_attempts AS a ON a.run_id = r.run_id "
            "WHERE r.run_id = %s AND a.attempt_id = %s",
            (run_id, attempt_id),
        ).fetchone()
    assert row == (attempt_id, "error", "persistence_error")
