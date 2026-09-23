import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, LiteralString, cast, final
from uuid import UUID, uuid5

import psycopg
from psycopg.rows import tuple_row

from forensic_data.acquisition import (
    ExpectedBatchDefinition,
    InputCutDefinition,
    RelationManifestEvidence,
    RunRequestDefinition,
    classify_input_cut_alignment,
    input_cut_semantic_value,
    readiness_evidence_semantic_value,
    run_request_semantic_value,
)
from forensic_data.canonical import Fingerprint, combine_fingerprints, schema_digest_hex
from forensic_data.comparison import CompletedComparisonArtifact
from forensic_data.contracts.model import ExecutionBudgets
from forensic_data.contracts.semantics import (
    SemanticValue,
    canonical_semantic_json,
    canonicalize_semantic_json,
    semantic_digest_hex,
    semantic_value_from_json,
)
from forensic_data.persistence.errors import (
    ActiveRunAttemptError,
    AttemptFenceError,
    InputCutMismatchError,
    LifecycleCommitUnknownError,
    LifecycleOperationConflictError,
    LifecyclePersistenceError,
    LifecycleTransactionError,
    MetadataMigrationChecksumError,
    MetadataMigrationHistoryError,
    RunAttemptLimitError,
    RunLifecycleStateError,
    RunRequestConflictError,
    StoredLifecycleIntegrityError,
)
from forensic_data.persistence.migrations import load_postgres_metadata_migrations
from forensic_data.persistence.model import (
    CodeArtifactRecord,
    DatasetLocatorKind,
    DatasetVersionRecord,
)
from forensic_data.planning import PlanDirection
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresProtectedReadContext,
    PostgresProtectedRelationInspection,
    PostgresRetryPolicy,
    ReadContextState,
)
from forensic_data.postgres_sql import (
    PostgresFieldBinding,
    PostgresPhysicalField,
    PostgresTypeIdentity,
)
from forensic_data.result import (
    ComparisonCoverage,
    ComparisonTotals,
    ConsistencyLevel,
    ConsistencyStatus,
    EvidenceCoverage,
    ExecutionStatus,
    Guarantee,
    PersistenceState,
    PersistenceStatus,
    ReasonCode,
    ResultMetrics,
    ResultReason,
    RunResult,
    Total,
    Verdict,
)

__all__ = (
    "AlignedInputCutPersistence",
    "AttemptOutcomeRecord",
    "AttemptStatus",
    "ClaimedRun",
    "ComparisonSegmentState",
    "CompletedComparisonDefinition",
    "IntegerRangeFingerprintPersistence",
    "PersistedInputCut",
    "PersistedReadContext",
    "ReadContextPersistence",
    "ReadContextStatus",
    "RelationManifestObservationPersistence",
    "RunAttemptRecord",
    "abandon_expired_postgres_attempt",
    "claim_postgres_run",
    "close_postgres_read_context",
    "completed_comparison_persistence_from_artifact",
    "mark_postgres_read_context_lost",
    "persist_postgres_aligned_input_cut",
    "persist_postgres_read_context",
    "publish_postgres_completed_comparison",
    "publish_postgres_terminal_error_attempt",
    "publish_postgres_terminal_incomplete_attempt",
    "read_postgres_completed_comparison",
    "record_postgres_retryable_error_attempt",
    "record_postgres_retryable_incomplete_attempt",
    "renew_postgres_run_attempt",
    "start_postgres_run_attempt",
)

LOGGER = logging.getLogger(__name__)

_METADATA_MAJOR_VERSION: Final[int] = 17
_WRITER_ROLE: Final[str] = "dfe_metadata_writer"
_READER_ROLE: Final[str] = "dfe_metadata_reader"
_CANONICAL_PROTOCOL: Final[str] = "dfe_canon_v1"
_FINGERPRINT_PROTOCOL: Final[str] = "sha256_sum32_v1"


class AttemptStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    ERROR = "error"
    ABANDONED = "abandoned"


class ReadContextStatus(StrEnum):
    ACTIVE = "active"
    CLOSED = "closed"
    LOST = "lost"


class ComparisonSegmentState(StrEnum):
    SPLIT = "split"
    FINGERPRINT_MATCH = "fingerprint_match"
    EXACT_MATCH = "exact_match"
    EXACT_MISMATCH = "exact_mismatch"


@final
@dataclass(frozen=True, slots=True)
class IntegerRangeFingerprintPersistence:
    segment_sequence: int
    parent_segment_sequence: int | None
    depth: int
    lower_inclusive: int
    upper_exclusive: int | None
    state: ComparisonSegmentState
    reference_observation_id: UUID
    reference_fingerprint: Fingerprint
    target_observation_id: UUID
    target_fingerprint: Fingerprint

    def __post_init__(self) -> None:
        _require_int64(self.segment_sequence, "segment sequence")
        _require_nonnegative_integer(self.segment_sequence, "segment sequence")
        if self.parent_segment_sequence is not None:
            _require_int64(self.parent_segment_sequence, "parent segment sequence")
            _require_nonnegative_integer(
                self.parent_segment_sequence,
                "parent segment sequence",
            )
            if self.parent_segment_sequence >= self.segment_sequence:
                raise ValueError("parent segment sequence must precede its child")
        _require_nonnegative_int32(self.depth, "segment depth")
        if (self.depth == 0) != (self.parent_segment_sequence is None):
            raise ValueError("only a depth-zero segment can have no parent")
        _require_int64(self.lower_inclusive, "segment lower bound")
        if self.upper_exclusive is not None:
            _require_int64(self.upper_exclusive, "segment upper bound")
            if self.upper_exclusive <= self.lower_inclusive:
                raise ValueError("bounded segment upper bound must exceed its lower bound")
        _require_instance(self.state, ComparisonSegmentState, "segment state")
        _require_uuid(self.reference_observation_id, "reference observation id")
        _require_instance(
            self.reference_fingerprint,
            Fingerprint,
            "reference segment fingerprint",
        )
        _require_uuid(self.target_observation_id, "target observation id")
        _require_instance(
            self.target_fingerprint,
            Fingerprint,
            "target segment fingerprint",
        )


@final
@dataclass(frozen=True, slots=True)
class CompletedComparisonDefinition:
    check_id: str
    contract_digest: str
    scope_digest: str
    verdict: Verdict
    consistency: ConsistencyStatus
    guarantee: Guarantee
    comparison_coverage: ComparisonCoverage
    totals: ComparisonTotals
    evidence_coverage: EvidenceCoverage
    metrics: ResultMetrics
    reasons: tuple[ResultReason, ...]

    def __post_init__(self) -> None:
        if type(self.check_id) is not str or self.check_id.strip() == "":
            raise ValueError("completed comparison check id must be nonblank")
        _require_sha256(self.contract_digest, "completed comparison contract digest")
        _require_sha256(self.scope_digest, "completed comparison scope digest")
        _require_instance(self.verdict, Verdict, "completed comparison verdict")
        if self.verdict is Verdict.INCONCLUSIVE:
            raise ValueError("completed comparison verdict cannot be inconclusive")
        _require_instance(
            self.consistency,
            ConsistencyStatus,
            "completed comparison consistency",
        )
        _require_instance(self.guarantee, Guarantee, "completed comparison guarantee")
        if self.guarantee not in (Guarantee.EXACT, Guarantee.FINGERPRINT):
            raise ValueError(
                "integer-range completed comparison requires exact or fingerprint guarantee"
            )
        _require_instance(
            self.comparison_coverage,
            ComparisonCoverage,
            "completed comparison coverage",
        )
        _require_instance(self.totals, ComparisonTotals, "completed comparison totals")
        _require_instance(
            self.evidence_coverage,
            EvidenceCoverage,
            "completed comparison evidence coverage",
        )
        _require_instance(self.metrics, ResultMetrics, "completed comparison metrics")
        if type(self.reasons) is not tuple:
            raise TypeError("completed comparison reasons must be an immutable tuple")
        for reason in self.reasons:
            _require_instance(reason, ResultReason, "completed comparison reason")


@final
@dataclass(frozen=True, slots=True)
class ClaimedRun:
    run_id: UUID
    creation_operation_id: UUID
    request: RunRequestDefinition
    created_at: datetime
    bound_input_cut_digest: str | None
    cut_binding_operation_id: UUID | None
    selected_terminal_attempt_id: UUID | None
    terminal_operation_id: UUID | None

    def __post_init__(self) -> None:
        _require_uuid(self.run_id, "run id")
        _require_uuid(self.creation_operation_id, "run creation operation id")
        _require_instance(self.request, RunRequestDefinition, "run request")
        _require_utc_datetime(self.created_at, "run created_at")
        _require_optional_sha256(self.bound_input_cut_digest, "bound input cut digest")
        _require_optional_uuid(self.cut_binding_operation_id, "cut binding operation id")
        _require_optional_uuid(
            self.selected_terminal_attempt_id,
            "selected terminal attempt id",
        )
        _require_optional_uuid(self.terminal_operation_id, "terminal operation id")


@final
@dataclass(frozen=True, slots=True)
class RunAttemptRecord:
    attempt_id: UUID
    run: ClaimedRun
    ordinal: int
    start_operation_id: UUID
    status: AttemptStatus
    execution_budgets: ExecutionBudgets
    owner_token: UUID
    lease_revision: int
    lease_operation_id: UUID | None
    initial_lease_expires_at: datetime
    lease_expires_at: datetime
    started_at: datetime
    input_cut_digest: str | None
    end_operation_id: UUID | None

    def __post_init__(self) -> None:
        _require_uuid(self.attempt_id, "attempt id")
        _require_instance(self.run, ClaimedRun, "attempt run")
        _require_positive_integer(self.ordinal, "attempt ordinal")
        _require_uuid(self.start_operation_id, "attempt start operation id")
        _require_instance(self.status, AttemptStatus, "attempt status")
        _require_instance(self.execution_budgets, ExecutionBudgets, "attempt budgets")
        _require_uuid(self.owner_token, "attempt owner token")
        _require_nonnegative_integer(self.lease_revision, "attempt lease revision")
        _require_optional_uuid(self.lease_operation_id, "attempt lease operation id")
        if (self.lease_revision == 0) != (self.lease_operation_id is None):
            raise ValueError(
                "attempt lease revision zero must have no lease operation and renewed "
                "revisions require one"
            )
        _require_utc_datetime(self.initial_lease_expires_at, "initial attempt lease expiry")
        _require_utc_datetime(self.lease_expires_at, "attempt lease expiry")
        if self.lease_expires_at < self.initial_lease_expires_at:
            raise ValueError("current attempt lease cannot precede its initial lease")
        _require_utc_datetime(self.started_at, "attempt started_at")
        _require_optional_sha256(self.input_cut_digest, "attempt input cut digest")
        _require_optional_uuid(self.end_operation_id, "attempt end operation id")


@final
@dataclass(frozen=True, slots=True)
class ReadContextPersistence:
    acquisition_operation_id: UUID
    dataset: DatasetVersionRecord
    direction: PlanDirection
    protected_context: PostgresProtectedReadContext

    def __post_init__(self) -> None:
        _require_uuid(self.acquisition_operation_id, "context acquisition operation id")
        _require_instance(self.dataset, DatasetVersionRecord, "context dataset")
        _require_instance(self.direction, PlanDirection, "context direction")
        _require_instance(
            self.protected_context,
            PostgresProtectedReadContext,
            "protected read context",
        )
        evidence = self.protected_context.evidence
        protected_relations = self.protected_context.protected_relations
        if (
            tuple(item.inspection.relation_oid for item in protected_relations)
            != evidence.locked_relation_oids
        ):
            raise ValueError(
                "protected context relations must exactly match its locked relation evidence"
            )
        if self.protected_context.state is not ReadContextState.ACTIVE:
            raise ValueError("only an active protected context can be persisted")


@final
@dataclass(frozen=True, slots=True)
class PersistedReadContext:
    read_context_id: UUID
    attempt_id: UUID
    acquisition_operation_id: UUID
    dataset_version_id: UUID
    direction: PlanDirection
    state: ReadContextStatus
    started_at: datetime
    end_operation_id: UUID | None
    ended_at: datetime | None

    def __post_init__(self) -> None:
        _require_uuid(self.read_context_id, "read context id")
        _require_uuid(self.attempt_id, "read context attempt id")
        _require_uuid(self.acquisition_operation_id, "context acquisition operation id")
        _require_uuid(self.dataset_version_id, "context dataset version id")
        _require_instance(self.direction, PlanDirection, "context direction")
        _require_instance(self.state, ReadContextStatus, "read context state")
        _require_utc_datetime(self.started_at, "read context started_at")
        _require_optional_uuid(self.end_operation_id, "read context end operation id")
        _require_optional_utc_datetime(self.ended_at, "read context ended_at")


@final
@dataclass(frozen=True, slots=True)
class RelationManifestObservationPersistence:
    observation_id: UUID
    observation_operation_id: UUID
    dataset: DatasetVersionRecord
    direction: PlanDirection
    readiness: RelationManifestEvidence
    protected_context: PostgresProtectedReadContext
    dataset_relation: PostgresProtectedRelationInspection
    readiness_relation: PostgresProtectedRelationInspection
    projection_code_artifact: CodeArtifactRecord | None
    observed_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.observation_id, "observation id")
        _require_uuid(self.observation_operation_id, "observation operation id")
        _require_instance(self.dataset, DatasetVersionRecord, "observation dataset")
        _require_instance(self.direction, PlanDirection, "observation direction")
        _require_instance(
            self.readiness,
            RelationManifestEvidence,
            "observation readiness evidence",
        )
        _require_instance(
            self.protected_context,
            PostgresProtectedReadContext,
            "observation protected context",
        )
        _require_instance(
            self.dataset_relation,
            PostgresProtectedRelationInspection,
            "observation dataset relation",
        )
        _require_instance(
            self.readiness_relation,
            PostgresProtectedRelationInspection,
            "observation readiness relation",
        )
        if self.projection_code_artifact is not None:
            _require_instance(
                self.projection_code_artifact,
                CodeArtifactRecord,
                "observation projection capture",
            )
        _require_utc_datetime(self.observed_at, "observation observed_at")
        if self.readiness.cut.direction is not self.direction:
            raise ValueError("observation readiness direction must match its direction")
        if self.readiness.cut.dataset_id != self.dataset.definition.dataset_id:
            raise ValueError("observation readiness dataset must match its dataset record")
        if self.dataset.definition.locator_kind is not DatasetLocatorKind.RELATION:
            raise ValueError("relation-manifest lifecycle supports only relation datasets")
        if self.projection_code_artifact is not None:
            raise ValueError("relation datasets cannot persist a projection code capture")
        if (
            self.dataset_relation.inspection.context_id
            != self.readiness_relation.inspection.context_id
        ):
            raise ValueError(
                "observation dataset and readiness relations must share one protected context"
            )
        if self.protected_context.evidence.context_id != (
            self.dataset_relation.inspection.context_id
        ):
            raise ValueError("observation relations must belong to its protected context")
        protected_relations = self.protected_context.protected_relations
        if self.protected_context.state is not ReadContextState.ACTIVE:
            raise ValueError("observation protected context must still be active")
        if not any(item is self.dataset_relation for item in protected_relations) or not any(
            item is self.readiness_relation for item in protected_relations
        ):
            raise ValueError(
                "observation relations must be the exact sealed protected-context objects"
            )
        if (
            self.dataset_relation.inspection.relation_oid
            == self.readiness_relation.inspection.relation_oid
        ):
            raise ValueError(
                "observation dataset and readiness relations must be distinct relations"
            )


@final
@dataclass(frozen=True, slots=True)
class AlignedInputCutPersistence:
    cut_binding_operation_id: UUID
    attempt_cut_operation_id: UUID
    input_cut: InputCutDefinition
    reference: RelationManifestObservationPersistence
    target: RelationManifestObservationPersistence
    recorded_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.cut_binding_operation_id, "run cut binding operation id")
        _require_uuid(self.attempt_cut_operation_id, "attempt cut operation id")
        _require_instance(self.input_cut, InputCutDefinition, "input cut")
        _require_instance(
            self.reference,
            RelationManifestObservationPersistence,
            "reference observation",
        )
        _require_instance(
            self.target,
            RelationManifestObservationPersistence,
            "target observation",
        )
        _require_utc_datetime(self.recorded_at, "cut recorded_at")
        if self.reference.direction is not PlanDirection.REFERENCE:
            raise ValueError("reference observation direction must be reference")
        if self.target.direction is not PlanDirection.TARGET:
            raise ValueError("target observation direction must be target")
        if self.reference.readiness.cut != self.input_cut.reference:
            raise ValueError("reference observation must contain the input cut reference")
        if self.target.readiness.cut != self.input_cut.target:
            raise ValueError("target observation must contain the input cut target")
        if self.reference.observed_at != self.recorded_at:
            raise ValueError("reference observation time must equal the cut receipt time")
        if self.target.observed_at != self.recorded_at:
            raise ValueError("target observation time must equal the cut receipt time")


@final
@dataclass(frozen=True, slots=True)
class PersistedInputCut:
    run_id: UUID
    attempt_id: UUID
    input_cut: InputCutDefinition
    cut_binding_operation_id: UUID
    attempt_cut_operation_id: UUID
    observation_ids: tuple[UUID, UUID]
    recorded_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.run_id, "bound cut run id")
        _require_uuid(self.attempt_id, "bound cut attempt id")
        _require_instance(self.input_cut, InputCutDefinition, "bound input cut")
        _require_uuid(self.cut_binding_operation_id, "run cut binding operation id")
        _require_uuid(self.attempt_cut_operation_id, "attempt cut operation id")
        if type(self.observation_ids) is not tuple or len(self.observation_ids) != 2:
            raise ValueError("bound cut observation ids must be a reference/target pair")
        for observation_id in self.observation_ids:
            _require_uuid(observation_id, "bound cut observation id")
        _require_utc_datetime(self.recorded_at, "bound cut recorded_at")


@final
@dataclass(frozen=True, slots=True)
class AttemptOutcomeRecord:
    run_id: UUID
    attempt_id: UUID
    status: AttemptStatus
    operation_id: UUID
    reason: ResultReason
    ended_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.run_id, "outcome run id")
        _require_uuid(self.attempt_id, "outcome attempt id")
        if self.status not in (
            AttemptStatus.INCOMPLETE,
            AttemptStatus.ERROR,
            AttemptStatus.ABANDONED,
        ):
            raise ValueError("attempt outcome status must be incomplete, error, or abandoned")
        _require_uuid(self.operation_id, "outcome operation id")
        _require_instance(self.reason, ResultReason, "attempt outcome reason")
        _require_utc_datetime(self.ended_at, "attempt outcome ended_at")


@final
@dataclass(frozen=True, slots=True)
class _RunExpectation:
    candidate_run_id: UUID
    creation_operation_id: UUID
    request: RunRequestDefinition
    request_payload_json: str
    request_identity_digest: bytes
    scope_digest: bytes


@final
@dataclass(frozen=True, slots=True)
class _AttemptExpectation:
    candidate_attempt_id: UUID
    start_operation_id: UUID
    run: ClaimedRun
    execution_budgets: ExecutionBudgets
    execution_budgets_json: str
    owner_token: UUID
    lease_expires_at: datetime


@final
@dataclass(frozen=True, slots=True)
class _ContextExpectation:
    attempt: RunAttemptRecord
    definition: ReadContextPersistence
    limitations_json: str
    acquisition_evidence_json: str


@final
@dataclass(frozen=True, slots=True)
class _LeaseRenewalExpectation:
    attempt: RunAttemptRecord
    operation_id: UUID
    lease_expires_at: datetime


@final
@dataclass(frozen=True, slots=True)
class _ObservationExpectation:
    definition: RelationManifestObservationPersistence
    readiness_json: str
    physical_schema_digest: bytes
    physical_binding_json: str
    physical_binding_digest: bytes


@final
@dataclass(frozen=True, slots=True)
class _CutExpectation:
    attempt: RunAttemptRecord
    definition: AlignedInputCutPersistence
    input_cut_json: str
    input_cut_digest: bytes
    observations: tuple[_ObservationExpectation, _ObservationExpectation]


@final
@dataclass(frozen=True, slots=True)
class _OutcomeExpectation:
    attempt: RunAttemptRecord
    operation_id: UUID
    status: AttemptStatus
    reason: ResultReason
    reason_json: str
    ended_at: datetime


@final
@dataclass(frozen=True, slots=True)
class _CompletedComparisonExpectation:
    attempt: RunAttemptRecord
    operation_id: UUID
    comparison: CompletedComparisonDefinition
    segments: tuple[IntegerRangeFingerprintPersistence, ...]
    ended_at: datetime
    result: RunResult
    result_json: str
    result_digest: bytes


@final
@dataclass(frozen=True, slots=True)
class _StoredSegmentSide:
    observation_id: UUID
    run_id: UUID
    attempt_id: UUID
    direction: PlanDirection
    segment_sequence: int
    parent_segment_sequence: int | None
    depth: int
    lower_inclusive: int
    upper_exclusive: int | None
    state: ComparisonSegmentState
    fingerprint: Fingerprint


@dataclass(frozen=True, slots=True)
class _ReceiptAbsent:
    pass


@dataclass(frozen=True, slots=True)
class _ReconciliationUnavailable:
    pass


def claim_postgres_run(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    run_id: UUID,
    creation_operation_id: UUID,
    request: RunRequestDefinition,
) -> ClaimedRun:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_uuid(run_id, "candidate run id")
    _require_uuid(creation_operation_id, "run creation operation id")
    _require_instance(request, RunRequestDefinition, "run request")
    request_payload_json = canonical_semantic_json(run_request_semantic_value(request))
    expectation = _RunExpectation(
        candidate_run_id=run_id,
        creation_operation_id=creation_operation_id,
        request=request,
        request_payload_json=request_payload_json,
        request_identity_digest=bytes.fromhex(request.request_identity_digest),
        scope_digest=bytes.fromhex(request.scope.scope_digest),
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "claim_run",
        (
            expectation.candidate_run_id,
            expectation.creation_operation_id,
            expectation.request.request_id,
        ),
        lambda connection: _claim_run_once(connection, settings, expectation),
        lambda connection: _lookup_claimed_run(connection, settings, expectation),
    )


def start_postgres_run_attempt(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    run: ClaimedRun,
    attempt_id: UUID,
    start_operation_id: UUID,
    owner_token: UUID,
    lease_expires_at: datetime,
    execution_budgets: ExecutionBudgets,
) -> RunAttemptRecord:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(run, ClaimedRun, "claimed run")
    _require_uuid(attempt_id, "candidate attempt id")
    _require_uuid(start_operation_id, "attempt start operation id")
    _require_uuid(owner_token, "attempt owner token")
    _require_utc_datetime(lease_expires_at, "attempt lease expiry")
    _require_instance(execution_budgets, ExecutionBudgets, "attempt execution budgets")
    if execution_budgets != run.request.execution_policy:
        raise ValueError(
            "attempt execution budgets must equal the immutable run request execution policy"
        )
    expectation = _AttemptExpectation(
        candidate_attempt_id=attempt_id,
        start_operation_id=start_operation_id,
        run=run,
        execution_budgets=execution_budgets,
        execution_budgets_json=canonical_semantic_json(
            _execution_budgets_semantic_value(execution_budgets)
        ),
        owner_token=owner_token,
        lease_expires_at=lease_expires_at.astimezone(UTC),
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "start_run_attempt",
        (expectation.candidate_attempt_id, expectation.start_operation_id),
        lambda connection: _start_attempt_once(connection, settings, expectation),
        lambda connection: _lookup_started_attempt(connection, settings, expectation),
    )


def renew_postgres_run_attempt(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    lease_operation_id: UUID,
    lease_expires_at: datetime,
) -> RunAttemptRecord:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_uuid(lease_operation_id, "lease renewal operation id")
    _require_utc_datetime(lease_expires_at, "renewed lease expiry")
    if lease_expires_at <= attempt.lease_expires_at:
        raise ValueError("renewed lease expiry must be later than the current lease expiry")
    expected = _LeaseRenewalExpectation(
        attempt=attempt,
        operation_id=lease_operation_id,
        lease_expires_at=lease_expires_at.astimezone(UTC),
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "renew_run_attempt",
        (expected.operation_id,),
        lambda connection: _renew_attempt_once(connection, settings, expected),
        lambda connection: _lookup_renewed_attempt(connection, settings, expected),
    )


def persist_postgres_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    definition: ReadContextPersistence,
) -> PersistedReadContext:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_instance(definition, ReadContextPersistence, "read context definition")
    _validate_context_definition(attempt, definition)
    expectation = _ContextExpectation(
        attempt=attempt,
        definition=definition,
        limitations_json=canonical_semantic_json(
            list(definition.protected_context.evidence.limitations)
        ),
        acquisition_evidence_json=canonical_semantic_json(
            _acquisition_evidence_semantic_value(definition)
        ),
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "persist_read_context",
        (
            expectation.definition.protected_context.evidence.context_id,
            expectation.definition.acquisition_operation_id,
        ),
        lambda connection: _persist_context_once(connection, settings, expectation),
        lambda connection: _lookup_persisted_context(connection, settings, expectation),
    )


def persist_postgres_aligned_input_cut(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    definition: AlignedInputCutPersistence,
) -> PersistedInputCut:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_instance(definition, AlignedInputCutPersistence, "aligned input cut persistence")
    if classify_input_cut_alignment(definition.input_cut) is not None:
        raise InputCutMismatchError(
            "input cut persistence rejected a non-aligned cut: reason_code='cut_mismatch'"
        )
    expectation = _cut_expectation(attempt, definition)
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "persist_aligned_input_cut",
        _cut_operation_identities(expectation),
        lambda connection: _persist_cut_once(connection, settings, expectation),
        lambda connection: _lookup_persisted_cut(connection, settings, expectation),
    )


def completed_comparison_persistence_from_artifact(
    attempt: RunAttemptRecord,
    persisted_cut: PersistedInputCut,
    artifact: CompletedComparisonArtifact,
) -> tuple[
    CompletedComparisonDefinition,
    tuple[IntegerRangeFingerprintPersistence, ...],
]:
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_instance(persisted_cut, PersistedInputCut, "persisted input cut")
    _require_instance(
        artifact,
        CompletedComparisonArtifact,
        "completed comparison artifact",
    )
    if persisted_cut.run_id != attempt.run.run_id or persisted_cut.attempt_id != attempt.attempt_id:
        raise ValueError("persisted input cut must belong to the comparison attempt")
    input_cut_digest = persisted_cut.input_cut.input_cut_digest
    if artifact.input_cut_digest != input_cut_digest:
        raise ValueError("comparison artifact input cut differs from the persisted attempt cut")
    for bound_digest in (
        attempt.run.bound_input_cut_digest,
        attempt.input_cut_digest,
    ):
        if bound_digest is not None and bound_digest != input_cut_digest:
            raise ValueError("comparison attempt record is bound to a different input cut")
    if artifact.scope_digest != persisted_cut.input_cut.reference.scope_digest:
        raise ValueError("comparison artifact scope differs from its persisted input cut")
    if artifact.reference_full_scans > attempt.execution_budgets.max_full_scans_per_side:
        raise ValueError("reference full scans exceed the immutable attempt budget")
    if artifact.target_full_scans > attempt.execution_budgets.max_full_scans_per_side:
        raise ValueError("target full scans exceed the immutable attempt budget")
    reference_observation_id, target_observation_id = persisted_cut.observation_ids
    definition = CompletedComparisonDefinition(
        check_id=artifact.check_id,
        contract_digest=artifact.contract_digest,
        scope_digest=artifact.scope_digest,
        verdict=artifact.verdict,
        consistency=artifact.consistency,
        guarantee=artifact.guarantee,
        comparison_coverage=artifact.comparison_coverage,
        totals=artifact.totals,
        evidence_coverage=artifact.evidence_coverage,
        metrics=artifact.metrics,
        reasons=artifact.reasons,
    )
    segments = tuple(
        IntegerRangeFingerprintPersistence(
            segment_sequence=segment.segment_sequence,
            parent_segment_sequence=segment.parent_segment_sequence,
            depth=segment.depth,
            lower_inclusive=segment.lower_inclusive,
            upper_exclusive=segment.upper_exclusive,
            state=ComparisonSegmentState(segment.state.value),
            reference_observation_id=reference_observation_id,
            reference_fingerprint=segment.reference_fingerprint,
            target_observation_id=target_observation_id,
            target_fingerprint=segment.target_fingerprint,
        )
        for segment in artifact.segments
    )
    _validate_completed_segments(definition, segments)
    _validate_completed_budget_use(attempt.execution_budgets, definition, segments)
    _validate_artifact_summary_closure(artifact, segments[0])
    return definition, segments


def publish_postgres_completed_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    terminal_operation_id: UUID,
    comparison: CompletedComparisonDefinition,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
    ended_at: datetime,
) -> RunResult:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_uuid(terminal_operation_id, "completed comparison operation id")
    _require_instance(
        comparison,
        CompletedComparisonDefinition,
        "completed comparison definition",
    )
    _require_utc_datetime(ended_at, "completed comparison ended_at")
    expected = _completed_comparison_expectation(
        attempt,
        terminal_operation_id,
        comparison,
        segments,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "publish_completed_comparison",
        (expected.operation_id,),
        lambda connection: _publish_completed_comparison_once(connection, settings, expected),
        lambda connection: _lookup_completed_comparison(connection, settings, expected),
    )


def read_postgres_completed_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    run_id: UUID,
    attempt_id: UUID,
) -> RunResult:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_uuid(run_id, "completed comparison run id")
    _require_uuid(attempt_id, "completed comparison attempt id")
    return _run_read_with_retries(
        settings,
        retry_policy,
        "read_completed_comparison",
        lambda connection: _read_completed_comparison_once(
            connection,
            settings,
            run_id,
            attempt_id,
        ),
    )


def close_postgres_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    read_context_id: UUID,
    end_operation_id: UUID,
    ended_at: datetime,
) -> PersistedReadContext:
    return _finish_postgres_read_context(
        settings,
        retry_policy,
        attempt,
        read_context_id,
        end_operation_id,
        ended_at,
        ReadContextStatus.CLOSED,
        "close_read_context",
    )


def mark_postgres_read_context_lost(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    read_context_id: UUID,
    end_operation_id: UUID,
    ended_at: datetime,
) -> PersistedReadContext:
    return _finish_postgres_read_context(
        settings,
        retry_policy,
        attempt,
        read_context_id,
        end_operation_id,
        ended_at,
        ReadContextStatus.LOST,
        "mark_read_context_lost",
    )


def record_postgres_retryable_incomplete_attempt(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    end_operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> AttemptOutcomeRecord:
    _validate_retryable_outcome_arguments(
        settings,
        retry_policy,
        attempt,
        end_operation_id,
        reason,
        ended_at,
    )
    _validate_incomplete_reason(reason)
    expected = _incomplete_outcome_expectation(
        attempt,
        end_operation_id,
        reason,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "record_retryable_incomplete_attempt",
        (expected.operation_id,),
        lambda connection: _persist_retryable_outcome_once(connection, settings, expected),
        lambda connection: _lookup_retryable_attempt_outcome(connection, settings, expected),
    )


def record_postgres_retryable_error_attempt(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    end_operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> AttemptOutcomeRecord:
    _validate_retryable_outcome_arguments(
        settings,
        retry_policy,
        attempt,
        end_operation_id,
        reason,
        ended_at,
    )
    _validate_error_reason(reason)
    expected = _error_outcome_expectation(
        attempt,
        end_operation_id,
        reason,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "record_retryable_error_attempt",
        (expected.operation_id,),
        lambda connection: _persist_retryable_outcome_once(connection, settings, expected),
        lambda connection: _lookup_retryable_attempt_outcome(connection, settings, expected),
    )


def publish_postgres_terminal_incomplete_attempt(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    terminal_operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> AttemptOutcomeRecord:
    _validate_terminal_outcome_arguments(
        settings,
        retry_policy,
        attempt,
        terminal_operation_id,
        reason,
        ended_at,
    )
    _validate_incomplete_reason(reason)
    expected = _incomplete_outcome_expectation(
        attempt,
        terminal_operation_id,
        reason,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "publish_terminal_incomplete_attempt",
        (expected.operation_id,),
        lambda connection: _publish_terminal_outcome_once(connection, settings, expected),
        lambda connection: _lookup_terminal_attempt_outcome(connection, settings, expected),
    )


def publish_postgres_terminal_error_attempt(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    terminal_operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> AttemptOutcomeRecord:
    _validate_terminal_outcome_arguments(
        settings,
        retry_policy,
        attempt,
        terminal_operation_id,
        reason,
        ended_at,
    )
    _validate_error_reason(reason)
    expected = _error_outcome_expectation(
        attempt,
        terminal_operation_id,
        reason,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "publish_terminal_error_attempt",
        (expected.operation_id,),
        lambda connection: _publish_terminal_outcome_once(connection, settings, expected),
        lambda connection: _lookup_terminal_attempt_outcome(connection, settings, expected),
    )


def abandon_expired_postgres_attempt(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    maintenance_operation_id: UUID,
    reason: ResultReason,
    abandoned_at: datetime,
) -> AttemptOutcomeRecord:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_uuid(maintenance_operation_id, "maintenance operation id")
    _require_instance(reason, ResultReason, "abandonment reason")
    _require_utc_datetime(abandoned_at, "attempt abandoned_at")
    if reason.code is not ReasonCode.SNAPSHOT_LOST:
        raise ValueError("expired attempt abandonment requires reason snapshot_lost")
    expectation = _abandoned_outcome_expectation(
        attempt,
        maintenance_operation_id,
        reason,
        abandoned_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "abandon_expired_attempt",
        (expectation.operation_id,),
        lambda connection: _abandon_attempt_once(connection, settings, expectation),
        lambda connection: _lookup_retryable_attempt_outcome(connection, settings, expectation),
    )


def _claim_run_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _RunExpectation,
) -> ClaimedRun:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(
        connection,
        (
            expected.candidate_run_id,
            expected.creation_operation_id,
            expected.request.request_id,
        ),
    )
    operation_row = _select_run_by_creation_operation(
        connection,
        expected.creation_operation_id,
    )
    if operation_row is not None:
        return _commit_result(connection, _claimed_run_from_row(operation_row, expected))
    request_row = _select_run_by_request(connection, expected.request.request_id)
    if request_row is not None:
        return _commit_result(connection, _claimed_run_from_row(request_row, expected))
    run_row = _select_run_by_id(connection, expected.candidate_run_id)
    if run_row is not None:
        raise LifecycleOperationConflictError(
            "candidate run UUID is already bound to another lifecycle aggregate"
        )
    connection.execute(
        "INSERT INTO dfe_metadata.runs ("
        "run_id, creation_operation_id, request_id, request_identity_digest, "
        "request_payload, contract_version_id, origin, scope_digest"
        ") VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s)",
        (
            expected.candidate_run_id,
            expected.creation_operation_id,
            expected.request.request_id,
            expected.request_identity_digest,
            expected.request_payload_json,
            expected.request.contract_version_id,
            expected.request.origin,
            expected.scope_digest,
        ),
    )
    inserted = _select_run_by_request(connection, expected.request.request_id)
    if inserted is None:
        raise StoredLifecycleIntegrityError(
            "run claim insert produced no durable request identity row"
        )
    return _commit_result(connection, _claimed_run_from_row(inserted, expected))


def _lookup_claimed_run(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _RunExpectation,
) -> ClaimedRun | None:
    operation_row = _select_run_by_creation_operation(
        connection,
        expected.creation_operation_id,
    )
    if operation_row is not None:
        return _commit_result(connection, _claimed_run_from_row(operation_row, expected))
    request_row = _select_run_by_request(connection, expected.request.request_id)
    if request_row is not None:
        return _commit_result(connection, _claimed_run_from_row(request_row, expected))
    run_row = _select_run_by_id(connection, expected.candidate_run_id)
    if run_row is not None:
        raise LifecycleOperationConflictError(
            "candidate run UUID is already bound to another lifecycle aggregate"
        )
    connection.execute("COMMIT")
    return None


def _start_attempt_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _AttemptExpectation,
) -> RunAttemptRecord:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(
        connection,
        (expected.candidate_attempt_id, expected.start_operation_id),
    )
    run_row = _lock_run_by_id(connection, expected.run.run_id)
    if run_row is None:
        raise RunLifecycleStateError("cannot start an attempt for an unknown run")
    current_run = _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.run))
    operation_row = _select_attempt_by_start_operation(
        connection,
        expected.start_operation_id,
    )
    if operation_row is not None:
        return _commit_result(
            connection,
            _started_attempt_from_row(operation_row, expected, current_run),
        )
    candidate_row = _select_attempt_by_id(connection, expected.candidate_attempt_id)
    if candidate_row is not None:
        raise LifecycleOperationConflictError(
            "candidate attempt UUID is already bound to another lifecycle attempt"
        )
    if current_run.selected_terminal_attempt_id is not None:
        raise RunLifecycleStateError("cannot start an attempt for a terminal run")
    attempt_rows = connection.execute(
        "SELECT attempt_id, status FROM dfe_metadata.run_attempts "
        "WHERE run_id = %s ORDER BY ordinal FOR UPDATE",
        (expected.run.run_id,),
    ).fetchall()
    if any(
        _row_text(row[1], "attempt status") == AttemptStatus.RUNNING.value for row in attempt_rows
    ):
        raise ActiveRunAttemptError(
            "run already has a fenced running attempt; expired attempts require explicit "
            "maintenance abandonment"
        )
    if len(attempt_rows) >= expected.run.request.execution_policy.max_attempts:
        raise RunAttemptLimitError(
            "run exhausted the immutable request max_attempts budget: "
            f"attempt_count={len(attempt_rows)}, "
            f"max_attempts={expected.run.request.execution_policy.max_attempts}"
        )
    database_now = _database_now(connection)
    if expected.lease_expires_at <= database_now:
        raise AttemptFenceError("new attempt lease expiry must be later than database time")
    ordinal = len(attempt_rows) + 1
    cursor = connection.execute(
        "INSERT INTO dfe_metadata.run_attempts ("
        "attempt_id, run_id, ordinal, start_operation_id, execution_budgets, "
        "owner_token, initial_lease_expires_at, lease_expires_at"
        ") SELECT %s, %s, %s, %s, %s::jsonb, %s, %s, %s "
        "WHERE %s > pg_catalog.clock_timestamp()",
        (
            expected.candidate_attempt_id,
            expected.run.run_id,
            ordinal,
            expected.start_operation_id,
            expected.execution_budgets_json,
            expected.owner_token,
            expected.lease_expires_at,
            expected.lease_expires_at,
            expected.lease_expires_at,
        ),
    )
    if cursor.rowcount != 1:
        raise AttemptFenceError("new attempt lease expired before admission")
    inserted = _select_attempt_by_start_operation(
        connection,
        expected.start_operation_id,
    )
    if inserted is None:
        raise StoredLifecycleIntegrityError(
            "attempt start insert produced no durable operation receipt"
        )
    return _commit_fenced_result(
        connection,
        _started_attempt_from_row(inserted, expected, current_run),
        expected.lease_expires_at,
        "new attempt admission",
    )


def _lookup_started_attempt(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _AttemptExpectation,
) -> RunAttemptRecord | None:
    row = _select_attempt_by_start_operation(connection, expected.start_operation_id)
    if row is not None:
        run_row = _select_run_by_id(connection, expected.run.run_id)
        if run_row is None:
            raise StoredLifecycleIntegrityError("attempt start receipt run is missing")
        current_run = _claimed_run_from_row(
            run_row,
            _expectation_for_claimed_run(expected.run),
        )
        return _commit_result(
            connection,
            _started_attempt_from_row(row, expected, current_run),
        )
    candidate = _select_attempt_by_id(connection, expected.candidate_attempt_id)
    if candidate is not None:
        raise LifecycleOperationConflictError(
            "candidate attempt UUID is already bound to another lifecycle attempt"
        )
    connection.execute("COMMIT")
    return None


def _renew_attempt_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _LeaseRenewalExpectation,
) -> RunAttemptRecord:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, (expected.operation_id,))
    run_row = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise AttemptFenceError("lease renewal run is unknown")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.attempt.run))
    row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    if row is None or _row_uuid(row[1], "renewal run id") != expected.attempt.run.run_id:
        raise AttemptFenceError("lease renewal attempt is unknown")
    receipt = _select_lease_renewal_receipt(connection, expected.operation_id)
    if receipt is not None:
        return _commit_result(
            connection,
            _renewed_attempt_from_receipt(connection, receipt, expected),
        )
    _require_attempt_fence_row(connection, row, expected.attempt)
    pre_renewal_expiry = _row_datetime(row[9], "current lease expiry")
    if expected.lease_expires_at <= pre_renewal_expiry:
        raise AttemptFenceError("renewed lease expiry must be later than the current lease")
    cursor = connection.execute(
        "UPDATE dfe_metadata.run_attempts SET lease_revision = lease_revision + 1, "
        "lease_operation_id = %s, lease_expires_at = %s "
        "WHERE run_id = %s AND attempt_id = %s AND owner_token = %s "
        "AND lease_revision = %s AND status = 'running' "
        "AND lease_expires_at > pg_catalog.clock_timestamp()",
        (
            expected.operation_id,
            expected.lease_expires_at,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.attempt.owner_token,
            expected.attempt.lease_revision,
        ),
    )
    if cursor.rowcount != 1:
        raise AttemptFenceError("lease renewal compare-and-set did not update the attempt")
    connection.execute(
        "INSERT INTO dfe_metadata.attempt_lease_renewals ("
        "lease_operation_id, run_id, attempt_id, owner_token, "
        "expected_lease_revision, requested_lease_expires_at, "
        "resulting_lease_revision"
        ") VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (
            expected.operation_id,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.attempt.owner_token,
            expected.attempt.lease_revision,
            expected.lease_expires_at,
            expected.attempt.lease_revision + 1,
        ),
    )
    receipt = _select_lease_renewal_receipt(connection, expected.operation_id)
    if receipt is None:
        raise StoredLifecycleIntegrityError("lease renewal receipt insert is missing")
    return _commit_fenced_result(
        connection,
        _renewed_attempt_from_receipt(connection, receipt, expected),
        pre_renewal_expiry,
        "lease renewal",
    )


def _lookup_renewed_attempt(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _LeaseRenewalExpectation,
) -> RunAttemptRecord | None:
    receipt = _select_lease_renewal_receipt(connection, expected.operation_id)
    if receipt is None:
        connection.execute("COMMIT")
        return None
    return _commit_result(
        connection,
        _renewed_attempt_from_receipt(connection, receipt, expected),
    )


def _renewed_attempt_from_receipt(
    connection: psycopg.Connection[DatabaseRow],
    receipt: DatabaseRow,
    expected: _LeaseRenewalExpectation,
) -> RunAttemptRecord:
    requested = (
        expected.operation_id,
        expected.attempt.run.run_id,
        expected.attempt.attempt_id,
        expected.attempt.owner_token,
        expected.attempt.lease_revision,
        expected.lease_expires_at,
        expected.attempt.lease_revision + 1,
    )
    actual = (
        _row_uuid(receipt[0], "lease renewal operation id"),
        _row_uuid(receipt[1], "lease renewal run id"),
        _row_uuid(receipt[2], "lease renewal attempt id"),
        _row_uuid(receipt[3], "lease renewal owner token"),
        _row_integer(receipt[4], "lease renewal expected revision"),
        _row_datetime(receipt[5], "lease renewal requested expiry"),
        _row_integer(receipt[6], "lease renewal resulting revision"),
    )
    if actual != requested:
        raise LifecycleOperationConflictError(
            "lease renewal operation UUID is bound to a different full renewal receipt"
        )
    row = _select_attempt_by_id(connection, expected.attempt.attempt_id)
    if row is None:
        raise StoredLifecycleIntegrityError("lease renewal attempt row is missing")
    immutable_matches = (
        _row_uuid(row[1], "renewed attempt run id") == expected.attempt.run.run_id
        and _row_uuid(row[3], "renewed attempt start operation id")
        == expected.attempt.start_operation_id
        and _canonical_database_json(row[5], "renewed attempt execution budgets")
        == canonical_semantic_json(
            _execution_budgets_semantic_value(expected.attempt.execution_budgets)
        )
        and _row_uuid(row[6], "renewed attempt owner token") == expected.attempt.owner_token
        and _row_datetime(row[18], "initial attempt lease expiry")
        == expected.attempt.initial_lease_expires_at
    )
    if not immutable_matches:
        raise StoredLifecycleIntegrityError(
            "lease renewal receipt does not close over the attempt immutable start facts"
        )
    run_row = _select_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise StoredLifecycleIntegrityError("lease renewal run row is missing")
    current_run = _claimed_run_from_row(
        run_row,
        _expectation_for_claimed_run(expected.attempt.run),
    )
    current_revision = _row_integer(row[7], "current lease revision")
    if current_revision < expected.attempt.lease_revision + 1:
        raise StoredLifecycleIntegrityError(
            "current attempt lease revision precedes its immutable renewal receipt"
        )
    current_operation_id = _row_optional_uuid(row[8], "current lease operation id")
    current_expiry = _row_datetime(row[9], "current lease expiry")
    if current_expiry < expected.lease_expires_at:
        raise StoredLifecycleIntegrityError(
            "current attempt lease expiry precedes its immutable renewal receipt"
        )
    if current_revision == expected.attempt.lease_revision + 1 and (
        current_operation_id != expected.operation_id or current_expiry != expected.lease_expires_at
    ):
        raise StoredLifecycleIntegrityError(
            "current attempt lease state differs from its latest renewal receipt"
        )
    try:
        status = AttemptStatus(_row_text(row[4], "renewed attempt status"))
    except ValueError:
        raise StoredLifecycleIntegrityError("stored attempt status is unsupported") from None
    cut_digest = _row_optional_bytes(row[10], "renewed attempt cut digest")
    return RunAttemptRecord(
        attempt_id=expected.attempt.attempt_id,
        run=current_run,
        ordinal=_row_integer(row[2], "renewed attempt ordinal"),
        start_operation_id=_row_uuid(row[3], "renewed attempt start operation id"),
        status=status,
        execution_budgets=expected.attempt.execution_budgets,
        owner_token=expected.attempt.owner_token,
        lease_revision=current_revision,
        lease_operation_id=current_operation_id,
        initial_lease_expires_at=_row_datetime(row[18], "initial attempt lease expiry"),
        lease_expires_at=current_expiry,
        started_at=_row_datetime(row[16], "renewed attempt started_at"),
        input_cut_digest=cut_digest.hex() if cut_digest is not None else None,
        end_operation_id=_row_optional_uuid(row[13], "renewed attempt end operation id"),
    )


def _persist_context_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _ContextExpectation,
) -> PersistedReadContext:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(
        connection,
        (
            expected.definition.protected_context.evidence.context_id,
            expected.definition.acquisition_operation_id,
        ),
    )
    run_row = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise AttemptFenceError("read context run fence is unknown")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.attempt.run))
    attempt_row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    if (
        attempt_row is None
        or _row_uuid(attempt_row[1], "context attempt run id") != expected.attempt.run.run_id
    ):
        raise AttemptFenceError("read context attempt fence is unknown")
    operation_row = _select_context_by_acquisition_operation(
        connection,
        expected.definition.acquisition_operation_id,
    )
    if operation_row is not None:
        return _commit_result(connection, _persisted_context_from_row(operation_row, expected))
    context_row = _select_context_by_id(
        connection,
        expected.definition.protected_context.evidence.context_id,
    )
    if context_row is not None:
        raise LifecycleOperationConflictError(
            "read context UUID is already bound to another acquisition operation"
        )
    _require_protected_context_active(expected.definition.protected_context)
    _require_attempt_fence_row(connection, attempt_row, expected.attempt)
    pre_mutation_lease_expiry = _row_datetime(
        attempt_row[9],
        "read context attempt lease expiry",
    )
    _require_dataset_closure(
        connection,
        expected.attempt.run,
        expected.definition.dataset,
        expected.definition.direction,
    )
    evidence = expected.definition.protected_context.evidence
    profile = expected.definition.protected_context.profile
    cursor = connection.execute(
        "INSERT INTO dfe_metadata.attempt_read_contexts ("
        "read_context_id, run_id, attempt_id, dataset_version_id, direction, "
        "acquisition_operation_id, scope_digest, engine, driver_version, "
        "server_version, server_version_number, strategy, snapshot_locator, "
        "backend_process_id, allowed_concurrency, limitations, acquisition_evidence, "
        "started_at"
        ") SELECT "
        "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
        "%s::jsonb, %s::jsonb, %s"
        " FROM dfe_metadata.run_attempts AS fence "
        "WHERE fence.run_id = %s AND fence.attempt_id = %s "
        "AND fence.owner_token = %s AND fence.lease_revision = %s "
        "AND fence.status = 'running' "
        "AND fence.lease_expires_at > pg_catalog.clock_timestamp()",
        (
            evidence.context_id,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.definition.dataset.dataset_version_id,
            expected.definition.direction.value,
            expected.definition.acquisition_operation_id,
            bytes.fromhex(expected.attempt.run.request.scope.scope_digest),
            evidence.engine,
            profile.driver_version,
            profile.server_version,
            profile.server_version_number,
            evidence.strategy,
            evidence.snapshot_locator,
            evidence.backend_process_id,
            evidence.allowed_concurrency,
            expected.limitations_json,
            expected.acquisition_evidence_json,
            evidence.started_at,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.attempt.owner_token,
            expected.attempt.lease_revision,
        ),
    )
    if cursor.rowcount != 1:
        raise AttemptFenceError("read context acquisition fence expired before persistence")
    inserted = _select_context_by_acquisition_operation(
        connection,
        expected.definition.acquisition_operation_id,
    )
    if inserted is None:
        raise StoredLifecycleIntegrityError(
            "read context insert produced no durable operation receipt"
        )
    return _commit_fenced_result(
        connection,
        _persisted_context_from_row(inserted, expected),
        pre_mutation_lease_expiry,
        "read context acquisition",
    )


def _lookup_persisted_context(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _ContextExpectation,
) -> PersistedReadContext | None:
    row = _select_context_by_acquisition_operation(
        connection,
        expected.definition.acquisition_operation_id,
    )
    if row is not None:
        return _commit_result(connection, _persisted_context_from_row(row, expected))
    candidate = _select_context_by_id(
        connection,
        expected.definition.protected_context.evidence.context_id,
    )
    if candidate is not None:
        raise LifecycleOperationConflictError(
            "read context UUID is already bound to another acquisition operation"
        )
    connection.execute("COMMIT")
    return None


def _persist_cut_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _CutExpectation,
) -> PersistedInputCut:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, _cut_operation_identities(expected))
    locked_run = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if locked_run is None:
        raise RunLifecycleStateError("cannot bind an input cut for an unknown run")
    _claimed_run_from_row(locked_run, _expectation_for_claimed_run(expected.attempt.run))
    attempt_lock_row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    if (
        attempt_lock_row is None
        or _row_uuid(attempt_lock_row[1], "cut attempt run id") != expected.attempt.run.run_id
    ):
        raise AttemptFenceError("input cut attempt fence is unknown")
    operation_row = _select_attempt_by_cut_operation(
        connection,
        expected.definition.attempt_cut_operation_id,
    )
    if operation_row is not None:
        return _commit_result(connection, _persisted_cut_from_database(connection, expected))
    conflicting_run = connection.execute(
        "SELECT run_id FROM dfe_metadata.runs WHERE cut_binding_operation_id = %s",
        (expected.definition.cut_binding_operation_id,),
    ).fetchone()
    if (
        conflicting_run is not None
        and _row_uuid(conflicting_run[0], "cut operation run id") != expected.attempt.run.run_id
    ):
        raise LifecycleOperationConflictError(
            "run cut binding operation UUID is already bound to another run"
        )
    _require_attempt_fence_row(connection, attempt_lock_row, expected.attempt)
    pre_mutation_lease_expiry = _row_datetime(
        attempt_lock_row[9],
        "input cut attempt lease expiry",
    )
    run_row = connection.execute(
        "SELECT bound_input_cut_digest, bound_input_cut_payload::text, "
        "cut_binding_operation_id, selected_terminal_attempt_id "
        "FROM dfe_metadata.runs WHERE run_id = %s",
        (expected.attempt.run.run_id,),
    ).fetchone()
    if run_row is None:
        raise RunLifecycleStateError("cannot bind an input cut for an unknown run")
    if run_row[3] is not None:
        raise RunLifecycleStateError("cannot bind an input cut after terminal publication")
    stored_digest = _row_optional_bytes(run_row[0], "bound input cut digest")
    stored_payload = _row_optional_canonical_json(run_row[1], "bound input cut payload")
    stored_operation = _row_optional_uuid(run_row[2], "run cut binding operation id")
    if stored_digest is not None or stored_payload is not None or stored_operation is not None:
        if stored_digest != expected.input_cut_digest or stored_payload != expected.input_cut_json:
            raise InputCutMismatchError(
                "observed input cut differs from the run's first bound cut: "
                "reason_code='cut_mismatch'"
            )
        if stored_operation != expected.definition.cut_binding_operation_id:
            raise LifecycleOperationConflictError(
                "run input cut is already bound under a different operation UUID"
            )
    attempt_cut_row = connection.execute(
        "SELECT input_cut_digest, cut_operation_id, cut_observed_at "
        "FROM dfe_metadata.run_attempts WHERE run_id = %s AND attempt_id = %s",
        (expected.attempt.run.run_id, expected.attempt.attempt_id),
    ).fetchone()
    if attempt_cut_row is None:
        raise RunLifecycleStateError("cannot bind a cut for an unknown attempt")
    existing_attempt_digest = _row_optional_bytes(
        attempt_cut_row[0],
        "attempt input cut digest",
    )
    existing_attempt_operation = _row_optional_uuid(
        attempt_cut_row[1],
        "attempt cut operation id",
    )
    existing_attempt_time = _row_optional_datetime(
        attempt_cut_row[2],
        "attempt cut observed_at",
    )
    if (
        existing_attempt_digest is not None
        or existing_attempt_operation is not None
        or existing_attempt_time is not None
    ):
        if (
            existing_attempt_digest != expected.input_cut_digest
            or existing_attempt_operation != expected.definition.attempt_cut_operation_id
            or existing_attempt_time != expected.definition.recorded_at
        ):
            raise LifecycleOperationConflictError(
                "attempt already has a different immutable cut receipt"
            )
        return _commit_result(connection, _persisted_cut_from_database(connection, expected))
    _require_protected_context_active(expected.definition.reference.protected_context)
    _require_protected_context_active(expected.definition.target.protected_context)
    _require_cut_contract_consistency(connection, expected)
    attempt_update = connection.execute(
        "UPDATE dfe_metadata.run_attempts SET input_cut_digest = %s, "
        "cut_operation_id = %s, cut_observed_at = %s "
        "WHERE run_id = %s AND attempt_id = %s AND owner_token = %s "
        "AND lease_revision = %s AND status = 'running' "
        "AND lease_expires_at > pg_catalog.clock_timestamp() AND input_cut_digest IS NULL",
        (
            expected.input_cut_digest,
            expected.definition.attempt_cut_operation_id,
            expected.definition.recorded_at,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.attempt.owner_token,
            expected.attempt.lease_revision,
        ),
    )
    if attempt_update.rowcount != 1:
        raise AttemptFenceError("attempt cut compare-and-set did not update")
    for observation in expected.observations:
        _persist_observation(connection, expected, observation)
    if stored_digest is None:
        run_update = connection.execute(
            "UPDATE dfe_metadata.runs SET bound_input_cut_digest = %s, "
            "bound_input_cut_payload = %s::jsonb, cut_binding_operation_id = %s, "
            "cut_bound_at = %s WHERE run_id = %s AND bound_input_cut_digest IS NULL",
            (
                expected.input_cut_digest,
                expected.input_cut_json,
                expected.definition.cut_binding_operation_id,
                expected.definition.recorded_at,
                expected.attempt.run.run_id,
            ),
        )
        if run_update.rowcount != 1:
            raise InputCutMismatchError(
                "run first-cut compare-and-set did not bind the requested full cut: "
                "reason_code='cut_mismatch'"
            )
    result = _persisted_cut_from_database(connection, expected)
    return _commit_fenced_result(
        connection,
        result,
        pre_mutation_lease_expiry,
        "aligned input cut persistence",
    )


def _lookup_persisted_cut(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _CutExpectation,
) -> PersistedInputCut | None:
    operation_row = _select_attempt_by_cut_operation(
        connection,
        expected.definition.attempt_cut_operation_id,
    )
    if operation_row is None:
        connection.execute("COMMIT")
        return None
    return _commit_result(connection, _persisted_cut_from_database(connection, expected))


def _persist_observation(
    connection: psycopg.Connection[DatabaseRow],
    cut: _CutExpectation,
    expected: _ObservationExpectation,
) -> None:
    definition = expected.definition
    operation_row = _select_observation_by_operation(
        connection,
        definition.observation_operation_id,
    )
    if operation_row is not None:
        _require_observation_row(operation_row, cut, expected)
        return
    candidate_row = _select_observation_by_id(connection, definition.observation_id)
    if candidate_row is not None:
        raise LifecycleOperationConflictError(
            "observation UUID is already bound to another observation operation"
        )
    context_id = definition.dataset_relation.inspection.context_id
    context_row = connection.execute(
        "SELECT state, run_id, attempt_id, dataset_version_id, direction, scope_digest "
        ", acquisition_evidence::text "
        "FROM dfe_metadata.attempt_read_contexts WHERE read_context_id = %s FOR UPDATE",
        (context_id,),
    ).fetchone()
    if context_row is None:
        raise RunLifecycleStateError("observation references an unknown read context")
    expected_context = (
        ReadContextStatus.ACTIVE.value,
        cut.attempt.run.run_id,
        cut.attempt.attempt_id,
        definition.dataset.dataset_version_id,
        definition.direction.value,
        bytes.fromhex(cut.attempt.run.request.scope.scope_digest),
    )
    actual_context = (
        _row_text(context_row[0], "observation context state"),
        _row_uuid(context_row[1], "observation context run id"),
        _row_uuid(context_row[2], "observation context attempt id"),
        _row_uuid(context_row[3], "observation context dataset id"),
        _row_text(context_row[4], "observation context direction"),
        _row_bytes(context_row[5], "observation context scope digest"),
    )
    if actual_context != expected_context:
        raise RunLifecycleStateError(
            "observation read context is outside the active attempt/dataset closure"
        )
    _require_context_contains_observation_relations(context_row[6], definition)
    _require_observation_definition(cut.attempt, definition)
    projection_id = (
        definition.projection_code_artifact.code_artifact_id
        if definition.projection_code_artifact is not None
        else None
    )
    connection.execute(
        "INSERT INTO dfe_metadata.dataset_observations ("
        "observation_id, observation_operation_id, run_id, attempt_id, "
        "read_context_id, dataset_version_id, direction, scope_digest, input_cut_digest, "
        "readiness_evidence, physical_schema_digest, physical_binding_digest, "
        "physical_binding, projection_code_artifact_id, readiness_provider_kind, "
        "readiness_code_artifact_id, observed_at"
        ") VALUES ("
        "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, "
        "%s, 'relation_manifest', NULL, %s"
        ")",
        (
            definition.observation_id,
            definition.observation_operation_id,
            cut.attempt.run.run_id,
            cut.attempt.attempt_id,
            context_id,
            definition.dataset.dataset_version_id,
            definition.direction.value,
            bytes.fromhex(cut.attempt.run.request.scope.scope_digest),
            cut.input_cut_digest,
            expected.readiness_json,
            expected.physical_schema_digest,
            expected.physical_binding_digest,
            expected.physical_binding_json,
            projection_id,
            definition.observed_at,
        ),
    )
    inserted = _select_observation_by_operation(
        connection,
        definition.observation_operation_id,
    )
    if inserted is None:
        raise StoredLifecycleIntegrityError(
            "observation insert produced no durable operation receipt"
        )
    _require_observation_row(inserted, cut, expected)


def _persisted_cut_from_database(
    connection: psycopg.Connection[DatabaseRow],
    expected: _CutExpectation,
) -> PersistedInputCut:
    run_row = connection.execute(
        "SELECT bound_input_cut_digest, bound_input_cut_payload::text, "
        "cut_binding_operation_id, cut_bound_at FROM dfe_metadata.runs WHERE run_id = %s",
        (expected.attempt.run.run_id,),
    ).fetchone()
    if run_row is None:
        raise StoredLifecycleIntegrityError("bound cut run row is missing")
    actual_run_cut = (
        _row_bytes(run_row[0], "bound input cut digest"),
        _canonical_database_json(run_row[1], "bound input cut payload"),
        _row_uuid(run_row[2], "run cut binding operation id"),
        _row_datetime(run_row[3], "run cut bound_at"),
    )
    if (
        actual_run_cut[0] != expected.input_cut_digest
        or actual_run_cut[1] != expected.input_cut_json
    ):
        raise InputCutMismatchError(
            "stored run cut differs from the requested full canonical cut: "
            "reason_code='cut_mismatch'"
        )
    if actual_run_cut[2] != expected.definition.cut_binding_operation_id:
        raise LifecycleOperationConflictError(
            "run cut binding operation differs from the requested stable receipt"
        )
    attempt_row = _select_attempt_by_cut_operation(
        connection,
        expected.definition.attempt_cut_operation_id,
    )
    if attempt_row is None:
        raise StoredLifecycleIntegrityError("attempt cut operation receipt is missing")
    if (
        _row_uuid(attempt_row[0], "cut attempt id") != expected.attempt.attempt_id
        or _row_uuid(attempt_row[1], "cut run id") != expected.attempt.run.run_id
        or _row_optional_bytes(attempt_row[10], "attempt input cut digest")
        != expected.input_cut_digest
        or _row_optional_datetime(attempt_row[12], "attempt cut observed_at")
        != expected.definition.recorded_at
    ):
        raise LifecycleOperationConflictError(
            "attempt cut operation receipt differs from the requested cut mutation"
        )
    rows = connection.execute(
        _OBSERVATION_SELECT + " WHERE attempt_id = %s ORDER BY direction",
        (expected.attempt.attempt_id,),
    ).fetchall()
    if len(rows) != 2:
        raise StoredLifecycleIntegrityError(
            "aligned cut must have exactly two persisted dataset observations"
        )
    expected_by_direction = {
        item.definition.direction.value: item for item in expected.observations
    }
    observation_ids: list[UUID] = []
    for row in rows:
        direction = _row_text(row[6], "observation direction")
        observation = expected_by_direction.get(direction)
        if observation is None:
            raise StoredLifecycleIntegrityError(
                "aligned cut observations contain an unexpected direction"
            )
        _require_observation_row(row, expected, observation)
        observation_ids.append(_row_uuid(row[0], "observation id"))
    return PersistedInputCut(
        run_id=expected.attempt.run.run_id,
        attempt_id=expected.attempt.attempt_id,
        input_cut=expected.definition.input_cut,
        cut_binding_operation_id=actual_run_cut[2],
        attempt_cut_operation_id=expected.definition.attempt_cut_operation_id,
        observation_ids=cast(tuple[UUID, UUID], tuple(observation_ids)),
        recorded_at=expected.definition.recorded_at,
    )


def _finish_postgres_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    read_context_id: UUID,
    end_operation_id: UUID,
    ended_at: datetime,
    target_state: ReadContextStatus,
    operation: str,
) -> PersistedReadContext:
    _validate_context_end_arguments(
        settings,
        retry_policy,
        attempt,
        read_context_id,
        end_operation_id,
        ended_at,
    )
    normalized_ended_at = ended_at.astimezone(UTC)
    return _run_with_reconciliation(
        settings,
        retry_policy,
        operation,
        (read_context_id, end_operation_id),
        lambda connection: _finish_context_once(
            connection,
            settings,
            attempt,
            read_context_id,
            end_operation_id,
            normalized_ended_at,
            target_state,
        ),
        lambda connection: _lookup_finished_context(
            connection,
            attempt,
            read_context_id,
            end_operation_id,
            normalized_ended_at,
            target_state,
        ),
    )


def _validate_context_end_arguments(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    read_context_id: UUID,
    end_operation_id: UUID,
    ended_at: datetime,
) -> None:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_uuid(read_context_id, "read context id")
    _require_uuid(end_operation_id, "read context end operation id")
    _require_utc_datetime(ended_at, "read context ended_at")


def _begin_context_end_transaction(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    attempt: RunAttemptRecord,
    read_context_id: UUID,
    end_operation_id: UUID,
) -> tuple[DatabaseRow | None, DatabaseRow]:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, (read_context_id, end_operation_id))
    run_row = _lock_run_by_id(connection, attempt.run.run_id)
    if run_row is None:
        raise AttemptFenceError("read context end run fence is unknown")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(attempt.run))
    attempt_lock_row = _lock_attempt_by_id(connection, attempt.attempt_id)
    if (
        attempt_lock_row is None
        or _row_uuid(attempt_lock_row[1], "context end attempt run id") != attempt.run.run_id
    ):
        raise AttemptFenceError("read context end attempt fence is unknown")
    operation_row = _select_context_by_end_operation(connection, end_operation_id)
    return operation_row, attempt_lock_row


def _prepare_new_context_end(
    connection: psycopg.Connection[DatabaseRow],
    attempt: RunAttemptRecord,
    attempt_lock_row: DatabaseRow,
    read_context_id: UUID,
) -> datetime:
    _require_attempt_fence_row(connection, attempt_lock_row, attempt)
    pre_mutation_lease_expiry = _row_datetime(
        attempt_lock_row[9],
        "read context end attempt lease expiry",
    )
    row = _lock_context_by_id(connection, read_context_id)
    if row is None:
        raise RunLifecycleStateError("cannot finish an unknown read context")
    if (
        _row_uuid(row[1], "context run id") != attempt.run.run_id
        or _row_uuid(row[2], "context attempt id") != attempt.attempt_id
    ):
        raise RunLifecycleStateError("read context is outside the fenced attempt")
    if _row_text(row[18], "read context state") != ReadContextStatus.ACTIVE.value:
        raise RunLifecycleStateError("read context is not active")
    return pre_mutation_lease_expiry


def _finish_context_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    attempt: RunAttemptRecord,
    read_context_id: UUID,
    end_operation_id: UUID,
    ended_at: datetime,
    target_state: ReadContextStatus,
) -> PersistedReadContext:
    operation_row, attempt_lock_row = _begin_context_end_transaction(
        connection,
        settings,
        attempt,
        read_context_id,
        end_operation_id,
    )
    if operation_row is not None:
        return _commit_result(
            connection,
            _require_finished_context(
                operation_row,
                attempt,
                read_context_id,
                end_operation_id,
                ended_at,
                target_state,
            ),
        )
    pre_mutation_lease_expiry = _prepare_new_context_end(
        connection,
        attempt,
        attempt_lock_row,
        read_context_id,
    )
    cursor = connection.execute(
        "UPDATE dfe_metadata.attempt_read_contexts SET state = %s, "
        "end_operation_id = %s, ended_at = %s "
        "WHERE read_context_id = %s AND state = 'active' "
        "AND EXISTS (SELECT 1 FROM dfe_metadata.run_attempts AS fence "
        "WHERE fence.run_id = %s AND fence.attempt_id = %s "
        "AND fence.owner_token = %s AND fence.lease_revision = %s "
        "AND fence.status = 'running' "
        "AND fence.lease_expires_at > pg_catalog.clock_timestamp())",
        (
            target_state.value,
            end_operation_id,
            ended_at,
            read_context_id,
            attempt.run.run_id,
            attempt.attempt_id,
            attempt.owner_token,
            attempt.lease_revision,
        ),
    )
    if cursor.rowcount != 1:
        raise AttemptFenceError("read context end fence expired before persistence")
    updated = _select_context_by_end_operation(connection, end_operation_id)
    if updated is None:
        raise StoredLifecycleIntegrityError(
            "read context end mutation produced no durable operation receipt"
        )
    result = _require_finished_context(
        updated,
        attempt,
        read_context_id,
        end_operation_id,
        ended_at,
        target_state,
    )
    return _commit_fenced_result(
        connection,
        result,
        pre_mutation_lease_expiry,
        "read context end",
    )


def _lookup_finished_context(
    connection: psycopg.Connection[DatabaseRow],
    attempt: RunAttemptRecord,
    read_context_id: UUID,
    end_operation_id: UUID,
    ended_at: datetime,
    target_state: ReadContextStatus,
) -> PersistedReadContext | None:
    row = _select_context_by_end_operation(connection, end_operation_id)
    if row is None:
        connection.execute("COMMIT")
        return None
    return _commit_result(
        connection,
        _require_finished_context(
            row,
            attempt,
            read_context_id,
            end_operation_id,
            ended_at,
            target_state,
        ),
    )


def _persist_retryable_outcome_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _OutcomeExpectation,
) -> AttemptOutcomeRecord:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, (expected.operation_id,))
    run_row = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise RunLifecycleStateError("cannot finish an attempt for an unknown run")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.attempt.run))
    attempt_lock_row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    attempt_lock_row = _require_outcome_attempt_row(attempt_lock_row, expected)
    operation_row = _select_attempt_by_end_operation(connection, expected.operation_id)
    if operation_row is not None:
        return _commit_result(
            connection,
            _retryable_outcome_from_database(connection, expected),
        )
    _require_attempt_fence_row(connection, attempt_lock_row, expected.attempt)
    pre_mutation_lease_expiry = _row_datetime(
        attempt_lock_row[9],
        "retryable outcome attempt lease expiry",
    )
    selected_attempt = _row_optional_uuid(run_row[10], "selected terminal attempt id")
    if selected_attempt is not None:
        raise RunLifecycleStateError("run already has a selected terminal attempt")
    _require_attempt_closure_for_end(connection, expected.attempt)
    cursor = connection.execute(
        "UPDATE dfe_metadata.run_attempts SET status = %s, end_operation_id = %s, "
        "terminal_reason_code = %s, terminal_reason = %s::jsonb, ended_at = %s "
        "WHERE run_id = %s AND attempt_id = %s AND owner_token = %s "
        "AND lease_revision = %s AND status = 'running' "
        "AND lease_expires_at > pg_catalog.clock_timestamp()",
        (
            expected.status.value,
            expected.operation_id,
            expected.reason.code.value,
            expected.reason_json,
            expected.ended_at,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.attempt.owner_token,
            expected.attempt.lease_revision,
        ),
    )
    if cursor.rowcount != 1:
        raise AttemptFenceError("retryable attempt outcome compare-and-set did not update")
    return _commit_fenced_result(
        connection,
        _retryable_outcome_from_database(connection, expected),
        pre_mutation_lease_expiry,
        "retryable attempt outcome",
    )


def _publish_terminal_outcome_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _OutcomeExpectation,
) -> AttemptOutcomeRecord:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, (expected.operation_id,))
    run_row = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise RunLifecycleStateError("cannot publish an outcome for an unknown run")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.attempt.run))
    attempt_lock_row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    attempt_lock_row = _require_outcome_attempt_row(attempt_lock_row, expected)
    operation_row = _select_attempt_by_end_operation(connection, expected.operation_id)
    if operation_row is not None:
        return _commit_result(
            connection,
            _terminal_outcome_from_database(connection, expected),
        )
    _require_attempt_fence_row(connection, attempt_lock_row, expected.attempt)
    pre_mutation_lease_expiry = _row_datetime(
        attempt_lock_row[9],
        "terminal outcome attempt lease expiry",
    )
    if _row_optional_uuid(run_row[10], "selected terminal attempt id") is not None:
        raise RunLifecycleStateError("run already has a selected terminal attempt")
    _require_attempt_closure_for_end(connection, expected.attempt)
    cursor = connection.execute(
        "UPDATE dfe_metadata.run_attempts SET status = %s, end_operation_id = %s, "
        "terminal_reason_code = %s, terminal_reason = %s::jsonb, ended_at = %s "
        "WHERE run_id = %s AND attempt_id = %s AND owner_token = %s "
        "AND lease_revision = %s AND status = 'running' "
        "AND lease_expires_at > pg_catalog.clock_timestamp()",
        (
            expected.status.value,
            expected.operation_id,
            expected.reason.code.value,
            expected.reason_json,
            expected.ended_at,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.attempt.owner_token,
            expected.attempt.lease_revision,
        ),
    )
    if cursor.rowcount != 1:
        raise AttemptFenceError("terminal attempt outcome compare-and-set did not update")
    publication = connection.execute(
        "UPDATE dfe_metadata.runs SET selected_terminal_attempt_id = %s, "
        "terminal_operation_id = %s, terminal_at = %s "
        "WHERE run_id = %s AND selected_terminal_attempt_id IS NULL",
        (
            expected.attempt.attempt_id,
            expected.operation_id,
            expected.ended_at,
            expected.attempt.run.run_id,
        ),
    )
    if publication.rowcount != 1:
        raise RunLifecycleStateError("terminal run publication compare-and-set did not update")
    return _commit_fenced_result(
        connection,
        _terminal_outcome_from_database(connection, expected),
        pre_mutation_lease_expiry,
        "terminal attempt publication",
    )


def _publish_completed_comparison_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _CompletedComparisonExpectation,
) -> RunResult:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, (expected.operation_id,))
    run_row = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise RunLifecycleStateError("cannot publish a comparison for an unknown run")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.attempt.run))
    attempt_row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    if (
        attempt_row is None
        or _row_uuid(attempt_row[1], "completed comparison attempt run id")
        != expected.attempt.run.run_id
    ):
        raise AttemptFenceError("completed comparison attempt fence is unknown")
    if _select_result_by_operation(connection, expected.operation_id) is not None:
        return _commit_result(
            connection,
            _completed_result_from_database(connection, expected),
        )
    if _select_attempt_by_end_operation(connection, expected.operation_id) is not None:
        raise LifecycleOperationConflictError(
            "completed comparison operation UUID is already bound to a different outcome"
        )
    _require_attempt_fence_row(connection, attempt_row, expected.attempt)
    pre_mutation_lease_expiry = _row_datetime(
        attempt_row[9],
        "completed comparison attempt lease expiry",
    )
    if _row_optional_uuid(run_row[10], "selected terminal attempt id") is not None:
        raise RunLifecycleStateError("run already has a selected terminal attempt")
    _require_locked_completed_comparison_closure(connection, expected)
    for segment in expected.segments:
        _insert_completed_segment(connection, expected, segment)
    attempt_update = connection.execute(
        "UPDATE dfe_metadata.run_attempts SET status = 'completed', "
        "end_operation_id = %s, terminal_reason_code = NULL, "
        "terminal_reason = NULL, ended_at = %s "
        "WHERE run_id = %s AND attempt_id = %s AND owner_token = %s "
        "AND lease_revision = %s AND status = 'running' "
        "AND lease_expires_at > pg_catalog.clock_timestamp()",
        (
            expected.operation_id,
            expected.ended_at,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.attempt.owner_token,
            expected.attempt.lease_revision,
        ),
    )
    if attempt_update.rowcount != 1:
        raise AttemptFenceError("completed comparison attempt compare-and-set did not update")
    connection.execute(
        "INSERT INTO dfe_metadata.check_results ("
        "run_id, attempt_id, check_id, result_operation_id, contract_digest, "
        "scope_digest, execution_status, verdict, guarantee, result_digest, "
        "result_payload, completed_at) VALUES ("
        "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)",
        (
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.comparison.check_id,
            expected.operation_id,
            bytes.fromhex(expected.comparison.contract_digest),
            bytes.fromhex(expected.comparison.scope_digest),
            ExecutionStatus.COMPLETED.value,
            expected.comparison.verdict.value,
            expected.comparison.guarantee.value,
            expected.result_digest,
            expected.result_json,
            expected.ended_at,
        ),
    )
    run_update = connection.execute(
        "UPDATE dfe_metadata.runs SET selected_terminal_attempt_id = %s, "
        "terminal_operation_id = %s, terminal_at = %s "
        "WHERE run_id = %s AND selected_terminal_attempt_id IS NULL",
        (
            expected.attempt.attempt_id,
            expected.operation_id,
            expected.ended_at,
            expected.attempt.run.run_id,
        ),
    )
    if run_update.rowcount != 1:
        raise RunLifecycleStateError(
            "completed comparison run publication compare-and-set did not update"
        )
    result = _completed_result_from_database(connection, expected)
    return _commit_fenced_result(
        connection,
        result,
        pre_mutation_lease_expiry,
        "completed comparison publication",
    )


def _lookup_completed_comparison(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _CompletedComparisonExpectation,
) -> RunResult | None:
    if _select_result_by_operation(connection, expected.operation_id) is None:
        connection.execute("COMMIT")
        return None
    return _commit_result(
        connection,
        _completed_result_from_database(connection, expected),
    )


def _read_completed_comparison_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> RunResult:
    _begin_reader_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    rows = _select_results_by_attempt(connection, run_id, attempt_id)
    if not rows:
        raise RunLifecycleStateError(
            "completed comparison does not exist for the requested run and attempt"
        )
    if len(rows) != 1:
        raise StoredLifecycleIntegrityError(
            "completed attempt must contain exactly one immutable check result"
        )
    result, completed_at = _completed_result_from_row(rows[0])
    if result.run_id != run_id or result.attempt_id != attempt_id:
        raise StoredLifecycleIntegrityError(
            "completed result payload identity differs from its lookup key"
        )
    segments = _completed_segments_from_database(connection, run_id, attempt_id)
    _require_valid_stored_segments(result, segments)
    _require_completed_database_closure(
        connection,
        result,
        segments,
        completed_at,
    )
    _require_completed_terminal_receipt(connection, result, completed_at)
    return _commit_result(connection, result)


def _lookup_retryable_attempt_outcome(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _OutcomeExpectation,
) -> AttemptOutcomeRecord | None:
    row = _select_attempt_by_end_operation(connection, expected.operation_id)
    if row is None:
        connection.execute("COMMIT")
        return None
    return _commit_result(connection, _retryable_outcome_from_database(connection, expected))


def _lookup_terminal_attempt_outcome(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _OutcomeExpectation,
) -> AttemptOutcomeRecord | None:
    row = _select_attempt_by_end_operation(connection, expected.operation_id)
    if row is None:
        connection.execute("COMMIT")
        return None
    return _commit_result(connection, _terminal_outcome_from_database(connection, expected))


def _abandon_attempt_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _OutcomeExpectation,
) -> AttemptOutcomeRecord:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, (expected.operation_id,))
    run_row = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise RunLifecycleStateError("cannot abandon an attempt for an unknown run")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.attempt.run))
    attempt_row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    if (
        attempt_row is None
        or _row_uuid(attempt_row[1], "attempt run id") != expected.attempt.run.run_id
    ):
        raise RunLifecycleStateError("cannot abandon an unknown attempt")
    operation_row = _select_attempt_by_end_operation(connection, expected.operation_id)
    if operation_row is not None:
        return _commit_result(
            connection,
            _retryable_outcome_from_database(connection, expected),
        )
    if _row_text(attempt_row[4], "attempt status") != AttemptStatus.RUNNING.value:
        raise RunLifecycleStateError("only a running attempt can be abandoned")
    if _row_datetime(attempt_row[9], "attempt lease expiry") > _database_now(connection):
        raise AttemptFenceError("maintenance abandonment requires an expired attempt lease")
    active_contexts = connection.execute(
        "SELECT read_context_id FROM dfe_metadata.attempt_read_contexts "
        "WHERE run_id = %s AND attempt_id = %s AND state = 'active' "
        "ORDER BY read_context_id FOR UPDATE",
        (expected.attempt.run.run_id, expected.attempt.attempt_id),
    ).fetchall()
    for row in active_contexts:
        context_id = _row_uuid(row[0], "abandoned read context id")
        context_operation_id = _derived_context_abandonment_operation(
            expected.operation_id,
            context_id,
        )
        context_update = connection.execute(
            "UPDATE dfe_metadata.attempt_read_contexts SET state = 'lost', "
            "end_operation_id = %s, ended_at = %s WHERE read_context_id = %s "
            "AND state = 'active'",
            (context_operation_id, expected.ended_at, context_id),
        )
        if context_update.rowcount != 1:
            raise RunLifecycleStateError(
                "expired attempt abandonment could not mark every active context lost"
            )
    cursor = connection.execute(
        "UPDATE dfe_metadata.run_attempts SET status = 'abandoned', "
        "end_operation_id = %s, terminal_reason_code = %s, "
        "terminal_reason = %s::jsonb, ended_at = %s "
        "WHERE run_id = %s AND attempt_id = %s AND status = 'running' "
        "AND lease_expires_at <= pg_catalog.clock_timestamp()",
        (
            expected.operation_id,
            expected.reason.code.value,
            expected.reason_json,
            expected.ended_at,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
        ),
    )
    if cursor.rowcount != 1:
        raise AttemptFenceError("expired attempt abandonment compare-and-set did not update")
    return _commit_result(
        connection,
        _retryable_outcome_from_database(connection, expected),
    )


def _cut_expectation(
    attempt: RunAttemptRecord,
    definition: AlignedInputCutPersistence,
) -> _CutExpectation:
    if definition.input_cut.reference.scope_digest != attempt.run.request.scope.scope_digest:
        raise ValueError("input cut scope must match the claimed run scope")
    input_cut_value = input_cut_semantic_value(definition.input_cut)
    input_cut_json = canonical_semantic_json(input_cut_value)
    input_cut_digest_hex = semantic_digest_hex(input_cut_value)
    if input_cut_digest_hex != definition.input_cut.input_cut_digest:
        raise ValueError("input cut public payload does not match its typed digest")
    reference = _observation_expectation(definition.reference)
    target = _observation_expectation(definition.target)
    return _CutExpectation(
        attempt=attempt,
        definition=definition,
        input_cut_json=input_cut_json,
        input_cut_digest=bytes.fromhex(input_cut_digest_hex),
        observations=(reference, target),
    )


def _cut_operation_identities(expected: _CutExpectation) -> tuple[UUID, ...]:
    return (
        expected.definition.cut_binding_operation_id,
        expected.definition.attempt_cut_operation_id,
        expected.definition.reference.observation_id,
        expected.definition.reference.observation_operation_id,
        expected.definition.target.observation_id,
        expected.definition.target.observation_operation_id,
    )


def _observation_expectation(
    definition: RelationManifestObservationPersistence,
) -> _ObservationExpectation:
    readiness_json = canonical_semantic_json(
        readiness_evidence_semantic_value(definition.readiness)
    )
    physical_binding_value = _physical_binding_semantic_value(definition)
    physical_binding_json = canonical_semantic_json(physical_binding_value)
    return _ObservationExpectation(
        definition=definition,
        readiness_json=readiness_json,
        physical_schema_digest=bytes.fromhex(
            schema_digest_hex(definition.dataset_relation.acquisition.schema)
        ),
        physical_binding_json=physical_binding_json,
        physical_binding_digest=bytes.fromhex(semantic_digest_hex(physical_binding_value)),
    )


def _incomplete_outcome_expectation(
    attempt: RunAttemptRecord,
    operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> _OutcomeExpectation:
    return _OutcomeExpectation(
        attempt=attempt,
        operation_id=operation_id,
        status=AttemptStatus.INCOMPLETE,
        reason=reason,
        reason_json=canonical_semantic_json(_reason_semantic_value(reason)),
        ended_at=ended_at.astimezone(UTC),
    )


def _error_outcome_expectation(
    attempt: RunAttemptRecord,
    operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> _OutcomeExpectation:
    return _OutcomeExpectation(
        attempt=attempt,
        operation_id=operation_id,
        status=AttemptStatus.ERROR,
        reason=reason,
        reason_json=canonical_semantic_json(_reason_semantic_value(reason)),
        ended_at=ended_at.astimezone(UTC),
    )


def _abandoned_outcome_expectation(
    attempt: RunAttemptRecord,
    operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> _OutcomeExpectation:
    return _OutcomeExpectation(
        attempt=attempt,
        operation_id=operation_id,
        status=AttemptStatus.ABANDONED,
        reason=reason,
        reason_json=canonical_semantic_json(_reason_semantic_value(reason)),
        ended_at=ended_at.astimezone(UTC),
    )


def _completed_comparison_expectation(
    attempt: RunAttemptRecord,
    operation_id: UUID,
    comparison: CompletedComparisonDefinition,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
    ended_at: datetime,
) -> _CompletedComparisonExpectation:
    if attempt.status is not AttemptStatus.RUNNING:
        raise ValueError("completed comparison publication requires a running attempt record")
    if comparison.scope_digest != attempt.run.request.scope.scope_digest:
        raise ValueError("completed comparison scope digest must match the immutable run scope")
    _validate_completed_segments(comparison, segments)
    _validate_completed_budget_use(
        attempt.execution_budgets,
        comparison,
        segments,
    )
    candidate_result = RunResult(
        schema_version=1,
        run_id=attempt.run.run_id,
        attempt_id=attempt.attempt_id,
        check_id=comparison.check_id,
        contract_digest=comparison.contract_digest,
        scope_digest=comparison.scope_digest,
        execution_status=ExecutionStatus.COMPLETED,
        verdict=comparison.verdict,
        consistency=comparison.consistency,
        guarantee=comparison.guarantee,
        comparison_coverage=comparison.comparison_coverage,
        totals=comparison.totals,
        evidence_coverage=comparison.evidence_coverage,
        metrics=comparison.metrics,
        reasons=comparison.reasons,
        persistence=PersistenceStatus(
            state=PersistenceState.CONFIRMED,
            operation_id=operation_id,
            reason=None,
        ),
    )
    result = RunResult.model_validate_json(candidate_result.model_dump_json())
    result_value = semantic_value_from_json(result.model_dump_json())
    result_json = canonical_semantic_json(result_value)
    return _CompletedComparisonExpectation(
        attempt=attempt,
        operation_id=operation_id,
        comparison=comparison,
        segments=segments,
        ended_at=ended_at.astimezone(UTC),
        result=result,
        result_json=result_json,
        result_digest=bytes.fromhex(semantic_digest_hex(result_value)),
    )


def _validate_completed_segments(
    comparison: CompletedComparisonDefinition,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
) -> None:
    if type(segments) is not tuple or not segments:
        raise ValueError("completed comparison requires a nonempty immutable segment topology")
    for segment in segments:
        _require_instance(
            segment,
            IntegerRangeFingerprintPersistence,
            "completed comparison segment",
        )
    expected_sequences = tuple(range(len(segments)))
    if tuple(segment.segment_sequence for segment in segments) != expected_sequences:
        raise ValueError(
            "completed comparison segment sequences must be contiguous from zero in order"
        )
    reference_observation_id = segments[0].reference_observation_id
    target_observation_id = segments[0].target_observation_id
    if reference_observation_id == target_observation_id:
        raise ValueError("completed comparison observations must be distinct")
    if any(
        segment.reference_observation_id != reference_observation_id
        or segment.target_observation_id != target_observation_id
        for segment in segments
    ):
        raise ValueError("all completed comparison segments must use one observation pair")
    matched = _available_total_integer(
        comparison.totals.matched,
        "completed comparison matched total",
    )
    missing = _available_total_integer(
        comparison.totals.missing,
        "completed comparison missing total",
    )
    extra = _available_total_integer(
        comparison.totals.extra,
        "completed comparison extra total",
    )
    modified = _available_total_integer(
        comparison.totals.modified,
        "completed comparison modified total",
    )
    if matched + missing + modified != segments[0].reference_fingerprint.count:
        raise ValueError("completed comparison totals do not close to the reference root row count")
    if matched + extra + modified != segments[0].target_fingerprint.count:
        raise ValueError("completed comparison totals do not close to the target root row count")

    children_by_parent: dict[int, list[IntegerRangeFingerprintPersistence]] = {}
    for segment in segments[1:]:
        parent_sequence = segment.parent_segment_sequence
        if parent_sequence is None:
            raise ValueError("non-root completed comparison segment must have a parent")
        children_by_parent.setdefault(parent_sequence, []).append(segment)

    terminal_states = {
        ComparisonSegmentState.FINGERPRINT_MATCH,
        ComparisonSegmentState.EXACT_MATCH,
        ComparisonSegmentState.EXACT_MISMATCH,
    }
    for segment in segments:
        children = tuple(children_by_parent.get(segment.segment_sequence, ()))
        if segment.state is ComparisonSegmentState.SPLIT:
            _validate_split_segment(segment, children)
        elif segment.state in terminal_states:
            if children:
                raise ValueError("terminal completed comparison segment cannot have children")
        else:
            raise AssertionError("unhandled completed comparison segment state")
        if (
            segment.state is ComparisonSegmentState.FINGERPRINT_MATCH
            and segment.reference_fingerprint != segment.target_fingerprint
        ):
            raise ValueError("fingerprint-match segment requires equal side fingerprints")
        if (
            segment.state is ComparisonSegmentState.EXACT_MATCH
            and segment.reference_fingerprint != segment.target_fingerprint
        ):
            raise ValueError("exact-match segment requires equal side fingerprints")

    terminal_segments = tuple(segment for segment in segments if segment.state in terminal_states)
    pruned_segments = sum(
        segment.state is ComparisonSegmentState.FINGERPRINT_MATCH for segment in terminal_segments
    )
    exact_segments = len(terminal_segments) - pruned_segments
    coverage = comparison.comparison_coverage
    if (
        coverage.total_partitions != 1
        or coverage.covered_partitions != 1
        or coverage.resolved_segments != len(terminal_segments)
        or coverage.pruned_segments != pruned_segments
        or coverage.exact_segments != exact_segments
        or coverage.unresolved_segments != 0
        or coverage.unresolved_reasons
    ):
        raise ValueError(
            "completed comparison coverage must exactly describe its terminal range frontier"
        )
    if comparison.metrics.fingerprint_nodes != len(segments):
        raise ValueError(
            "completed comparison fingerprint_nodes must equal the persisted logical nodes"
        )
    has_exact_mismatch = any(
        segment.state is ComparisonSegmentState.EXACT_MISMATCH for segment in terminal_segments
    )
    if (comparison.verdict is Verdict.MISMATCH) != has_exact_mismatch:
        raise ValueError(
            "completed comparison verdict must match the exact-mismatch terminal frontier"
        )


def _validate_split_segment(
    parent: IntegerRangeFingerprintPersistence,
    children: tuple[IntegerRangeFingerprintPersistence, ...],
) -> None:
    if len(children) != 2:
        raise ValueError("split completed comparison segment must have exactly two children")
    left, right = sorted(children, key=lambda segment: segment.lower_inclusive)
    if left.depth != parent.depth + 1 or right.depth != parent.depth + 1:
        raise ValueError("split completed comparison children must advance depth by one")
    if (
        left.lower_inclusive != parent.lower_inclusive
        or left.upper_exclusive is None
        or right.lower_inclusive != left.upper_exclusive
        or right.upper_exclusive != parent.upper_exclusive
    ):
        raise ValueError("split completed comparison children must exactly cover their parent")
    if (
        combine_fingerprints((left.reference_fingerprint, right.reference_fingerprint))
        != parent.reference_fingerprint
    ):
        raise ValueError("reference child fingerprints must combine to their split parent")
    if (
        combine_fingerprints((left.target_fingerprint, right.target_fingerprint))
        != parent.target_fingerprint
    ):
        raise ValueError("target child fingerprints must combine to their split parent")


def _available_total_integer(total: Total, context: str) -> int:
    if total.value is None:
        raise ValueError(f"{context} must be available for a completed row comparison")
    return int(total.value)


def _validate_completed_budget_use(
    budgets: ExecutionBudgets,
    comparison: CompletedComparisonDefinition,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
) -> None:
    metrics = comparison.metrics
    for name, actual, maximum in (
        ("queries", metrics.queries, budgets.max_queries),
        ("fetched_records", metrics.fetched_records, budgets.max_fetched_records),
        (
            "result_bytes",
            metrics.result_bytes,
            budgets.max_application_result_bytes,
        ),
        ("fingerprint_nodes", metrics.fingerprint_nodes, budgets.max_fingerprint_nodes),
        (
            "coordinator_peak_bytes",
            metrics.coordinator_peak_bytes,
            budgets.max_coordinator_memory_bytes,
        ),
        (
            "elapsed_milliseconds",
            metrics.elapsed_milliseconds,
            budgets.run_timeout_milliseconds,
        ),
        (
            "retained_evidence_records",
            comparison.evidence_coverage.retained_records,
            budgets.max_evidence_rows,
        ),
        (
            "retained_evidence_bytes",
            comparison.evidence_coverage.retained_bytes,
            budgets.max_evidence_bytes,
        ),
    ):
        if actual > maximum:
            raise ValueError(f"completed comparison {name} exceeds its immutable attempt budget")
    if max(segment.depth for segment in segments) > budgets.max_depth:
        raise ValueError("completed comparison segment depth exceeds its attempt budget")


def _validate_artifact_summary_closure(
    artifact: CompletedComparisonArtifact,
    root: IntegerRangeFingerprintPersistence,
) -> None:
    for direction, summary in (
        (PlanDirection.REFERENCE, artifact.reference_key_summary),
        (PlanDirection.TARGET, artifact.target_key_summary),
    ):
        if (
            summary.null_key_count != 0
            or summary.invalid_key_count != 0
            or summary.valid_key_count != summary.row_count
            or summary.distinct_key_count != summary.row_count
        ):
            raise ValueError(
                f"completed {direction.value} artifact violates the unique integer-key contract"
            )
    if artifact.reference_key_summary.row_count != root.reference_fingerprint.count:
        raise ValueError("reference key summary does not close to the root fingerprint")
    if artifact.target_key_summary.row_count != root.target_fingerprint.count:
        raise ValueError("target key summary does not close to the root fingerprint")


def _validate_context_definition(
    attempt: RunAttemptRecord,
    definition: ReadContextPersistence,
) -> None:
    if attempt.status is not AttemptStatus.RUNNING:
        raise ValueError("new read contexts require a running attempt record")
    evidence = definition.protected_context.evidence
    profile = definition.protected_context.profile
    if evidence.server_version != profile.server_version:
        raise ValueError("read context evidence and server profile versions must match")
    if evidence.engine != "postgresql":
        raise ValueError("initial lifecycle read contexts require engine='postgresql'")
    expected_dataset_id = _expected_batch(attempt.run.request, definition.direction).dataset_id
    if definition.dataset.definition.dataset_id != expected_dataset_id:
        raise ValueError("read context dataset is outside the run request direction closure")


def _require_protected_context_active(context: PostgresProtectedReadContext) -> None:
    evidence = context.evidence
    relations = context.protected_relations
    if tuple(item.inspection.relation_oid for item in relations) != evidence.locked_relation_oids:
        raise RunLifecycleStateError(
            "protected source context relation closure changed before persistence"
        )
    if context.state is not ReadContextState.ACTIVE:
        raise RunLifecycleStateError(
            "new lifecycle evidence requires an active protected source context"
        )


def _require_observation_definition(
    attempt: RunAttemptRecord,
    definition: RelationManifestObservationPersistence,
) -> None:
    expected_batch = _expected_batch(attempt.run.request, definition.direction)
    if definition.dataset.definition.dataset_id != expected_batch.dataset_id:
        raise ValueError("observation dataset is outside the run request direction closure")
    if definition.readiness.cut.scope_digest != attempt.run.request.scope.scope_digest:
        raise ValueError("observation readiness scope differs from the run scope")
    batch_value = _canonical_string_value(
        definition.readiness.cut.batch_id.field,
        definition.readiness.cut.batch_id.canonical_payload,
        "observation batch id",
    )
    if batch_value != expected_batch.batch_id:
        raise ValueError("observation readiness batch differs from the requested batch")
    context_id = definition.dataset_relation.inspection.context_id
    if definition.readiness_relation.inspection.context_id != context_id:
        raise ValueError("observation protected relations must share one context")
    dataset_schema_digest = schema_digest_hex(definition.dataset_relation.acquisition.schema)
    if dataset_schema_digest != definition.dataset.definition.logical_schema_digest:
        raise ValueError("observation physical schema differs from the dataset definition")
    _require_dataset_relation_closure(definition.dataset, definition.dataset_relation)


def _require_dataset_relation_closure(
    dataset: DatasetVersionRecord,
    protected: PostgresProtectedRelationInspection,
) -> None:
    payload = _semantic_object(
        semantic_value_from_json(dataset.definition.semantic_payload_json),
        "dataset semantic payload",
    )
    body = _semantic_object(payload.get("dataset"), "dataset semantic body")
    locator = _semantic_object(body.get("locator"), "dataset relation locator")
    expected_relation = (
        _semantic_text(locator.get("schema"), "dataset relation schema"),
        _semantic_text(locator.get("name"), "dataset relation name"),
    )
    if protected.acquisition.relation.components != expected_relation:
        raise ValueError("protected dataset relation differs from the registered locator")
    projection = _semantic_array(body.get("projection"), "dataset projection")
    expected_columns = tuple(
        _semantic_text(
            _semantic_object(item, "dataset projection item").get("column"),
            "dataset projection column",
        )
        for item in projection
    )
    if protected.acquisition.column_names != expected_columns:
        raise ValueError("protected dataset columns differ from the registered projection")


def _require_cut_contract_consistency(
    connection: psycopg.Connection[DatabaseRow],
    cut: _CutExpectation,
) -> None:
    consistency = _contract_consistency_payload(connection, cut.attempt.run)
    alignment_fields = tuple(
        _semantic_text(item, "contract alignment field")
        for item in _semantic_array(
            consistency.get("alignment_fields"),
            "contract alignment fields",
        )
    )
    requested_alignment = tuple(
        item.field.name for item in cut.definition.input_cut.reference.alignment_values
    )
    if alignment_fields != requested_alignment:
        raise ValueError("input cut ordered alignment fields differ from the immutable contract")
    late_arrivals = _semantic_text(
        consistency.get("late_arrivals"),
        "contract late-arrival policy",
    )
    if late_arrivals != cut.definition.input_cut.late_arrivals.value:
        raise ValueError("input cut late-arrival policy differs from the immutable contract")
    minimum_evidence = _semantic_text(
        consistency.get("minimum_evidence"),
        "contract minimum evidence",
    )
    for observation in cut.observations:
        definition = observation.definition
        evidence_alignment = tuple(
            item.field.name for item in definition.readiness.cut.alignment_values
        )
        if evidence_alignment != alignment_fields:
            raise ValueError(
                "readiness evidence alignment fields differ from the immutable contract"
            )
        if definition.readiness.late_arrivals.value != late_arrivals:
            raise ValueError(
                "readiness evidence late-arrival policy differs from the immutable contract"
            )
        if minimum_evidence == "verified" and (
            definition.readiness.evidence_level.value != "verified"
        ):
            raise ValueError("readiness evidence level does not satisfy the immutable contract")
        if minimum_evidence not in ("asserted", "verified"):
            raise StoredLifecycleIntegrityError(
                "contract minimum evidence is outside the supported lifecycle values"
            )
        _require_readiness_relation_closure(consistency, definition)
        _require_stable_read_context(connection, definition)


def _contract_consistency_payload(
    connection: psycopg.Connection[DatabaseRow],
    run: ClaimedRun,
) -> dict[str, SemanticValue]:
    row = connection.execute(
        "SELECT semantic_payload::text FROM dfe_metadata.contract_versions "
        "WHERE contract_version_id = %s",
        (run.request.contract_version_id,),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("run contract version is missing")
    payload = _semantic_object(
        semantic_value_from_json(_row_text(row[0], "contract semantic payload")),
        "contract semantic payload",
    )
    return _semantic_object(payload.get("consistency"), "contract consistency")


def _require_readiness_relation_closure(
    consistency: dict[str, SemanticValue],
    definition: RelationManifestObservationPersistence,
) -> None:
    datasets = _semantic_array(consistency.get("datasets"), "contract consistency datasets")
    index = 0 if definition.direction is PlanDirection.REFERENCE else 1
    if len(datasets) != 2:
        raise StoredLifecycleIntegrityError(
            "run contract consistency must contain a reference/target dataset pair"
        )
    item = _semantic_object(datasets[index], "contract consistency dataset")
    if (
        _semantic_text(item.get("dataset_id"), "contract consistency dataset id")
        != definition.dataset.definition.dataset_id
    ):
        raise StoredLifecycleIntegrityError(
            "contract consistency dataset is outside the run direction closure"
        )
    if (
        _semantic_text(item.get("stable_read"), "contract stable-read strategy")
        != "transaction_snapshot"
    ):
        raise ValueError("lifecycle runtime requires contract transaction_snapshot reads")
    readiness = _semantic_object(item.get("readiness"), "contract readiness")
    if _semantic_text(readiness.get("kind"), "contract readiness kind") != "relation_manifest":
        raise ValueError("lifecycle runtime supports only relation_manifest readiness")
    relation = _semantic_object(readiness.get("relation"), "contract readiness relation")
    expected_relation = (
        _semantic_text(relation.get("schema"), "readiness relation schema"),
        _semantic_text(relation.get("name"), "readiness relation name"),
    )
    if definition.readiness_relation.acquisition.relation.components != expected_relation:
        raise ValueError("protected readiness relation differs from the contract provider")
    columns = _semantic_object(readiness.get("columns"), "readiness columns")
    expected_columns = tuple(
        _semantic_text(columns.get(name), f"readiness {name} column")
        for name in (
            "dataset_id",
            "scope_digest",
            "batch_id",
            "state",
            "business_date",
            "source_cut",
            "dataset_version",
            "completed_at",
        )
    )
    if definition.readiness_relation.acquisition.column_names != expected_columns:
        raise ValueError("protected readiness columns differ from the contract mapping")


def _require_stable_read_context(
    connection: psycopg.Connection[DatabaseRow],
    definition: RelationManifestObservationPersistence,
) -> None:
    row = connection.execute(
        "SELECT strategy, snapshot_locator, acquisition_evidence::text "
        "FROM dfe_metadata.attempt_read_contexts WHERE read_context_id = %s",
        (definition.dataset_relation.inspection.context_id,),
    ).fetchone()
    if row is None:
        raise RunLifecycleStateError("readiness evidence context is missing")
    if _row_text(row[0], "readiness context strategy") != ("protected_read_only_repeatable_read"):
        raise ValueError("readiness context does not provide the contract transaction snapshot")
    snapshot_locator = _row_optional_text(row[1], "readiness snapshot locator")
    if snapshot_locator is None or not snapshot_locator.strip():
        raise ValueError("readiness context lacks a transaction snapshot locator")
    evidence = _semantic_object(
        semantic_value_from_json(_row_text(row[2], "readiness acquisition evidence")),
        "readiness acquisition evidence",
    )
    if _semantic_text(evidence.get("kind"), "readiness acquisition kind") != (
        "postgresql_protected_relations"
    ):
        raise ValueError("readiness context lacks verified protected-relation evidence")


def _require_context_contains_observation_relations(
    acquisition_evidence_json: object,
    definition: RelationManifestObservationPersistence,
) -> None:
    evidence = _semantic_object(
        semantic_value_from_json(
            _row_text(acquisition_evidence_json, "context acquisition evidence")
        ),
        "context acquisition evidence",
    )
    payload = _semantic_object(evidence.get("payload"), "context acquisition payload")
    relations = _semantic_array(
        payload.get("relations"),
        "context acquisition relations",
    )
    expected = (
        _protected_relation_semantic_value(definition.dataset_relation),
        _protected_relation_semantic_value(definition.readiness_relation),
    )
    for relation in expected:
        if relation not in relations:
            raise StoredLifecycleIntegrityError(
                "observation relation is absent from persisted protected acquisition evidence"
            )


def _acquisition_evidence_semantic_value(
    definition: ReadContextPersistence,
) -> dict[str, SemanticValue]:
    evidence = definition.protected_context.evidence
    return {
        "evidence_version": 1,
        "kind": "postgresql_protected_relations",
        "payload": {
            "acquired_before_snapshot": evidence.acquired_before_snapshot,
            "lock_mode": evidence.lock_mode,
            "locked_relation_oids": list(evidence.locked_relation_oids),
            "relation_persistence": evidence.relation_persistence.value,
            "relations": [
                _protected_relation_semantic_value(item)
                for item in definition.protected_context.protected_relations
            ],
        },
    }


def _physical_binding_semantic_value(
    definition: RelationManifestObservationPersistence,
) -> dict[str, SemanticValue]:
    return {
        "binding_version": 1,
        "engine": "postgresql",
        "payload": {
            "dataset_relation": _protected_relation_semantic_value(definition.dataset_relation),
            "readiness_relation": _protected_relation_semantic_value(definition.readiness_relation),
        },
    }


def _protected_relation_semantic_value(
    protected: PostgresProtectedRelationInspection,
) -> dict[str, SemanticValue]:
    inspection = protected.inspection
    return {
        "acquired_before_snapshot": protected.acquired_before_snapshot,
        "columns": [_binding_semantic_value(item) for item in inspection.bindings],
        "lock_mode": protected.lock_mode,
        "max_identifier_utf8_bytes": inspection.max_identifier_utf8_bytes,
        "namespace_oid": protected.namespace_oid,
        "relation_oid": inspection.relation_oid,
        "relation_persistence": protected.relation_persistence.value,
        "relation_row_type_oid": inspection.relation_row_type_oid,
        "requested_relation": list(protected.acquisition.relation.components),
        "resolved_relation": list(inspection.relation.components),
    }


def _binding_semantic_value(binding: PostgresFieldBinding) -> dict[str, SemanticValue]:
    return {
        "column_name": binding.column_name,
        "field_name": binding.field_name,
        "physical": _physical_field_semantic_value(binding.physical),
    }


def _physical_field_semantic_value(field: PostgresPhysicalField) -> dict[str, SemanticValue]:
    return {
        "array_dimensions": field.array_dimensions,
        "base_type": _type_identity_semantic_value(field.base_type),
        "declared_type": _type_identity_semantic_value(field.declared_type),
        "formatted_type": field.formatted_type,
        "is_domain": field.is_domain,
        "numeric_precision": field.numeric_precision,
        "numeric_scale": field.numeric_scale,
    }


def _type_identity_semantic_value(identity: PostgresTypeIdentity) -> dict[str, SemanticValue]:
    return {
        "oid": identity.oid,
        "schema_name": identity.schema_name,
        "type_name": identity.type_name,
    }


def _execution_budgets_semantic_value(
    budgets: ExecutionBudgets,
) -> dict[str, SemanticValue]:
    return {
        "max_application_result_bytes": budgets.max_application_result_bytes,
        "max_attempts": budgets.max_attempts,
        "max_checks_concurrency": budgets.max_checks_concurrency,
        "max_coordinator_memory_bytes": budgets.max_coordinator_memory_bytes,
        "max_depth": budgets.max_depth,
        "max_evidence_bytes": budgets.max_evidence_bytes,
        "max_evidence_rows": budgets.max_evidence_rows,
        "max_fetched_records": budgets.max_fetched_records,
        "max_fingerprint_nodes": budgets.max_fingerprint_nodes,
        "max_full_scans_per_side": budgets.max_full_scans_per_side,
        "max_queries": budgets.max_queries,
        "max_source_concurrency": budgets.max_source_concurrency,
        "run_timeout_milliseconds": budgets.run_timeout_milliseconds,
        "statement_timeout_milliseconds": budgets.statement_timeout_milliseconds,
        "version": budgets.version,
    }


def _execution_budgets_from_database(value: object) -> ExecutionBudgets:
    budgets_json = _canonical_database_json(value, "completed attempt execution budgets")
    try:
        budgets = _semantic_object(
            semantic_value_from_json(budgets_json),
            "completed attempt execution budgets",
        )
        return ExecutionBudgets(
            version=_semantic_integer(budgets.get("version"), "execution budget version"),
            max_queries=_semantic_integer(
                budgets.get("max_queries"),
                "execution max_queries",
            ),
            max_fetched_records=_semantic_integer(
                budgets.get("max_fetched_records"),
                "execution max_fetched_records",
            ),
            max_application_result_bytes=_semantic_integer(
                budgets.get("max_application_result_bytes"),
                "execution max_application_result_bytes",
            ),
            max_evidence_rows=_semantic_integer(
                budgets.get("max_evidence_rows"),
                "execution max_evidence_rows",
            ),
            max_evidence_bytes=_semantic_integer(
                budgets.get("max_evidence_bytes"),
                "execution max_evidence_bytes",
            ),
            max_fingerprint_nodes=_semantic_integer(
                budgets.get("max_fingerprint_nodes"),
                "execution max_fingerprint_nodes",
            ),
            max_coordinator_memory_bytes=_semantic_integer(
                budgets.get("max_coordinator_memory_bytes"),
                "execution max_coordinator_memory_bytes",
            ),
            max_depth=_semantic_integer(
                budgets.get("max_depth"),
                "execution max_depth",
            ),
            max_full_scans_per_side=_semantic_integer(
                budgets.get("max_full_scans_per_side"),
                "execution max_full_scans_per_side",
            ),
            statement_timeout_milliseconds=_semantic_integer(
                budgets.get("statement_timeout_milliseconds"),
                "execution statement_timeout_milliseconds",
            ),
            run_timeout_milliseconds=_semantic_integer(
                budgets.get("run_timeout_milliseconds"),
                "execution run_timeout_milliseconds",
            ),
            max_attempts=_semantic_integer(
                budgets.get("max_attempts"),
                "execution max_attempts",
            ),
            max_checks_concurrency=_semantic_integer(
                budgets.get("max_checks_concurrency"),
                "execution max_checks_concurrency",
            ),
            max_source_concurrency=_semantic_integer(
                budgets.get("max_source_concurrency"),
                "execution max_source_concurrency",
            ),
        )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored completed attempt budgets are invalid: reason={error}"
        ) from None


def _reason_semantic_value(reason: ResultReason) -> dict[str, SemanticValue]:
    return {
        "message": reason.message,
        "native_error_code": reason.native_error_code,
        "operation": reason.operation,
        "query_id": reason.query_id,
        "reason_version": 1,
        "redacted_response": reason.redacted_response,
        "safe_parameters": [
            {"name": item.name, "value": item.value} for item in reason.safe_parameters
        ],
    }


_RUN_SELECT: Final[LiteralString] = (
    "SELECT run_id, creation_operation_id, request_id, request_identity_digest, "
    "request_payload::text, contract_version_id, origin, scope_digest, "
    "bound_input_cut_digest, cut_binding_operation_id, selected_terminal_attempt_id, "
    "terminal_operation_id, created_at FROM dfe_metadata.runs"
)

_ATTEMPT_SELECT: Final[LiteralString] = (
    "SELECT attempt_id, run_id, ordinal, start_operation_id, status, "
    "execution_budgets::text, owner_token, lease_revision, lease_operation_id, "
    "lease_expires_at, "
    "input_cut_digest, cut_operation_id, cut_observed_at, end_operation_id, "
    "terminal_reason_code, terminal_reason::text, started_at, ended_at, "
    "initial_lease_expires_at "
    "FROM dfe_metadata.run_attempts"
)

_CONTEXT_SELECT: Final[LiteralString] = (
    "SELECT read_context_id, run_id, attempt_id, dataset_version_id, direction, "
    "acquisition_operation_id, scope_digest, engine, driver_version, server_version, "
    "server_version_number, strategy, snapshot_locator, backend_process_id, "
    "allowed_concurrency, limitations::text, acquisition_evidence::text, started_at, "
    "state, end_operation_id, ended_at FROM dfe_metadata.attempt_read_contexts"
)

_OBSERVATION_SELECT: Final[LiteralString] = (
    "SELECT observation_id, observation_operation_id, run_id, attempt_id, "
    "read_context_id, dataset_version_id, direction, scope_digest, input_cut_digest, "
    "readiness_evidence::text, physical_schema_digest, physical_binding_digest, "
    "physical_binding::text, projection_code_artifact_id, readiness_provider_kind, "
    "readiness_code_artifact_id, observed_at FROM dfe_metadata.dataset_observations"
)

_RESULT_SELECT: Final[LiteralString] = (
    "SELECT run_id, attempt_id, check_id, result_operation_id, contract_digest, "
    "scope_digest, execution_status, verdict, guarantee, result_digest, "
    "result_payload::text, completed_at FROM dfe_metadata.check_results"
)

_SEGMENT_SELECT: Final[LiteralString] = (
    "SELECT observation_id, run_id, attempt_id, direction, segment_sequence, "
    "parent_segment_sequence, depth, boundary_kind, lower_inclusive, upper_exclusive, "
    "traversal_state, canonical_protocol, fingerprint_protocol, row_count, "
    "limb_0::text, limb_1::text, limb_2::text, limb_3::text, limb_4::text, "
    "limb_5::text, limb_6::text, limb_7::text "
    "FROM dfe_metadata.segment_fingerprints"
)

_LEASE_RENEWAL_SELECT: Final[LiteralString] = (
    "SELECT lease_operation_id, run_id, attempt_id, owner_token, "
    "expected_lease_revision, requested_lease_expires_at, "
    "resulting_lease_revision FROM dfe_metadata.attempt_lease_renewals"
)


def _select_run_by_creation_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _RUN_SELECT + " WHERE creation_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_lease_renewal_receipt(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _LEASE_RENEWAL_SELECT + " WHERE lease_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_run_by_request(
    connection: psycopg.Connection[DatabaseRow],
    request_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _RUN_SELECT + " WHERE request_id = %s",
        (request_id,),
    ).fetchone()


def _select_run_by_id(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _RUN_SELECT + " WHERE run_id = %s",
        (run_id,),
    ).fetchone()


def _lock_run_by_id(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _RUN_SELECT + " WHERE run_id = %s FOR UPDATE",
        (run_id,),
    ).fetchone()


def _select_attempt_by_start_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _ATTEMPT_SELECT + " WHERE start_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_attempt_by_cut_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _ATTEMPT_SELECT + " WHERE cut_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_attempt_by_end_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _ATTEMPT_SELECT + " WHERE end_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_attempt_by_id(
    connection: psycopg.Connection[DatabaseRow],
    attempt_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _ATTEMPT_SELECT + " WHERE attempt_id = %s",
        (attempt_id,),
    ).fetchone()


def _lock_attempt_by_id(
    connection: psycopg.Connection[DatabaseRow],
    attempt_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _ATTEMPT_SELECT + " WHERE attempt_id = %s FOR UPDATE",
        (attempt_id,),
    ).fetchone()


def _select_context_by_acquisition_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _CONTEXT_SELECT + " WHERE acquisition_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_context_by_end_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _CONTEXT_SELECT + " WHERE end_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_context_by_id(
    connection: psycopg.Connection[DatabaseRow],
    context_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _CONTEXT_SELECT + " WHERE read_context_id = %s",
        (context_id,),
    ).fetchone()


def _lock_context_by_id(
    connection: psycopg.Connection[DatabaseRow],
    context_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _CONTEXT_SELECT + " WHERE read_context_id = %s FOR UPDATE",
        (context_id,),
    ).fetchone()


def _select_observation_by_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _OBSERVATION_SELECT + " WHERE observation_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_observation_by_id(
    connection: psycopg.Connection[DatabaseRow],
    observation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _OBSERVATION_SELECT + " WHERE observation_id = %s",
        (observation_id,),
    ).fetchone()


def _select_result_by_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _RESULT_SELECT + " WHERE result_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_results_by_attempt(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
) -> list[DatabaseRow]:
    return connection.execute(
        _RESULT_SELECT + " WHERE run_id = %s AND attempt_id = %s ORDER BY check_id",
        (run_id, attempt_id),
    ).fetchall()


def _select_segment_rows_by_attempt(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
) -> list[DatabaseRow]:
    return connection.execute(
        _SEGMENT_SELECT + " WHERE run_id = %s AND attempt_id = %s "
        "ORDER BY segment_sequence, CASE direction "
        "WHEN 'reference' THEN 0 WHEN 'target' THEN 1 ELSE 2 END",
        (run_id, attempt_id),
    ).fetchall()


def _claimed_run_from_row(row: DatabaseRow, expected: _RunExpectation) -> ClaimedRun:
    stored_request_id = _row_uuid(row[2], "run request id")
    immutable_matches = (
        _row_bytes(row[3], "run request identity digest") == expected.request_identity_digest
        and _canonical_database_json(row[4], "run request payload") == expected.request_payload_json
        and _row_uuid(row[5], "run contract version id") == expected.request.contract_version_id
        and _row_text(row[6], "run origin") == expected.request.origin
        and _row_bytes(row[7], "run scope digest") == expected.scope_digest
    )
    if stored_request_id != expected.request.request_id or not immutable_matches:
        if stored_request_id == expected.request.request_id:
            raise RunRequestConflictError(
                "request UUID is already bound to a different full canonical request payload"
            )
        raise LifecycleOperationConflictError(
            "run creation operation UUID is already bound to a different request"
        )
    bound_digest = _row_optional_bytes(row[8], "bound input cut digest")
    return ClaimedRun(
        run_id=_row_uuid(row[0], "run id"),
        creation_operation_id=_row_uuid(row[1], "run creation operation id"),
        request=expected.request,
        created_at=_row_datetime(row[12], "run created_at"),
        bound_input_cut_digest=bound_digest.hex() if bound_digest is not None else None,
        cut_binding_operation_id=_row_optional_uuid(row[9], "cut binding operation id"),
        selected_terminal_attempt_id=_row_optional_uuid(
            row[10],
            "selected terminal attempt id",
        ),
        terminal_operation_id=_row_optional_uuid(row[11], "terminal operation id"),
    )


def _expectation_for_claimed_run(run: ClaimedRun) -> _RunExpectation:
    return _RunExpectation(
        candidate_run_id=run.run_id,
        creation_operation_id=run.creation_operation_id,
        request=run.request,
        request_payload_json=canonical_semantic_json(run_request_semantic_value(run.request)),
        request_identity_digest=bytes.fromhex(run.request.request_identity_digest),
        scope_digest=bytes.fromhex(run.request.scope.scope_digest),
    )


def _started_attempt_from_row(
    row: DatabaseRow,
    expected: _AttemptExpectation,
    current_run: ClaimedRun,
) -> RunAttemptRecord:
    exact_start = (
        _row_uuid(row[0], "attempt id") == expected.candidate_attempt_id
        and _row_uuid(row[1], "attempt run id") == expected.run.run_id
        and _row_uuid(row[3], "attempt start operation id") == expected.start_operation_id
        and _canonical_database_json(row[5], "attempt execution budgets")
        == expected.execution_budgets_json
        and _row_uuid(row[6], "attempt owner token") == expected.owner_token
        and _row_datetime(row[18], "initial attempt lease expiry") == expected.lease_expires_at
    )
    if not exact_start:
        raise LifecycleOperationConflictError(
            "attempt start operation UUID is already bound to a different full start receipt"
        )
    try:
        status = AttemptStatus(_row_text(row[4], "attempt status"))
    except ValueError:
        raise StoredLifecycleIntegrityError("stored attempt status is unsupported") from None
    cut_digest = _row_optional_bytes(row[10], "attempt input cut digest")
    return RunAttemptRecord(
        attempt_id=expected.candidate_attempt_id,
        run=current_run,
        ordinal=_row_integer(row[2], "attempt ordinal"),
        start_operation_id=expected.start_operation_id,
        status=status,
        execution_budgets=expected.execution_budgets,
        owner_token=expected.owner_token,
        lease_revision=_row_integer(row[7], "attempt lease revision"),
        lease_operation_id=_row_optional_uuid(row[8], "attempt lease operation id"),
        initial_lease_expires_at=expected.lease_expires_at,
        lease_expires_at=_row_datetime(row[9], "attempt lease expiry"),
        started_at=_row_datetime(row[16], "attempt started_at"),
        input_cut_digest=cut_digest.hex() if cut_digest is not None else None,
        end_operation_id=_row_optional_uuid(row[13], "attempt end operation id"),
    )


def _persisted_context_from_row(
    row: DatabaseRow,
    expected: _ContextExpectation,
) -> PersistedReadContext:
    definition = expected.definition
    evidence = definition.protected_context.evidence
    profile = definition.protected_context.profile
    immutable_actual = (
        _row_uuid(row[0], "read context id"),
        _row_uuid(row[1], "read context run id"),
        _row_uuid(row[2], "read context attempt id"),
        _row_uuid(row[3], "read context dataset version id"),
        _row_text(row[4], "read context direction"),
        _row_uuid(row[5], "context acquisition operation id"),
        _row_bytes(row[6], "read context scope digest"),
        _row_text(row[7], "read context engine"),
        _row_text(row[8], "read context driver version"),
        _row_text(row[9], "read context server version"),
        _row_integer(row[10], "read context server version number"),
        _row_text(row[11], "read context strategy"),
        _row_optional_text(row[12], "read context snapshot locator"),
        _row_optional_integer(row[13], "read context backend process id"),
        _row_integer(row[14], "read context allowed concurrency"),
        _canonical_database_json(row[15], "read context limitations"),
        _canonical_database_json(row[16], "read context acquisition evidence"),
        _row_datetime(row[17], "read context started_at"),
    )
    immutable_expected = (
        evidence.context_id,
        expected.attempt.run.run_id,
        expected.attempt.attempt_id,
        definition.dataset.dataset_version_id,
        definition.direction.value,
        definition.acquisition_operation_id,
        bytes.fromhex(expected.attempt.run.request.scope.scope_digest),
        evidence.engine,
        profile.driver_version,
        profile.server_version,
        profile.server_version_number,
        evidence.strategy,
        evidence.snapshot_locator,
        evidence.backend_process_id,
        evidence.allowed_concurrency,
        expected.limitations_json,
        expected.acquisition_evidence_json,
        evidence.started_at.astimezone(UTC),
    )
    if immutable_actual != immutable_expected:
        raise LifecycleOperationConflictError(
            "context acquisition operation UUID is already bound to different evidence"
        )
    try:
        state = ReadContextStatus(_row_text(row[18], "read context state"))
    except ValueError:
        raise StoredLifecycleIntegrityError("stored read context state is unsupported") from None
    return PersistedReadContext(
        read_context_id=evidence.context_id,
        attempt_id=expected.attempt.attempt_id,
        acquisition_operation_id=definition.acquisition_operation_id,
        dataset_version_id=definition.dataset.dataset_version_id,
        direction=definition.direction,
        state=state,
        started_at=evidence.started_at.astimezone(UTC),
        end_operation_id=_row_optional_uuid(row[19], "read context end operation id"),
        ended_at=_row_optional_datetime(row[20], "read context ended_at"),
    )


def _require_observation_row(
    row: DatabaseRow,
    cut: _CutExpectation,
    expected: _ObservationExpectation,
) -> None:
    definition = expected.definition
    projection_id = (
        definition.projection_code_artifact.code_artifact_id
        if definition.projection_code_artifact is not None
        else None
    )
    actual = (
        _row_uuid(row[0], "observation id"),
        _row_uuid(row[1], "observation operation id"),
        _row_uuid(row[2], "observation run id"),
        _row_uuid(row[3], "observation attempt id"),
        _row_uuid(row[4], "observation context id"),
        _row_uuid(row[5], "observation dataset version id"),
        _row_text(row[6], "observation direction"),
        _row_bytes(row[7], "observation scope digest"),
        _row_bytes(row[8], "observation input cut digest"),
        _canonical_database_json(row[9], "observation readiness evidence"),
        _row_bytes(row[10], "observation physical schema digest"),
        _row_bytes(row[11], "observation physical binding digest"),
        _canonical_database_json(row[12], "observation physical binding"),
        _row_optional_uuid(row[13], "observation projection capture id"),
        _row_text(row[14], "observation readiness provider kind"),
        _row_optional_uuid(row[15], "observation readiness capture id"),
        _row_datetime(row[16], "observation observed_at"),
    )
    requested = (
        definition.observation_id,
        definition.observation_operation_id,
        cut.attempt.run.run_id,
        cut.attempt.attempt_id,
        definition.dataset_relation.inspection.context_id,
        definition.dataset.dataset_version_id,
        definition.direction.value,
        bytes.fromhex(cut.attempt.run.request.scope.scope_digest),
        cut.input_cut_digest,
        expected.readiness_json,
        expected.physical_schema_digest,
        expected.physical_binding_digest,
        expected.physical_binding_json,
        projection_id,
        "relation_manifest",
        None,
        definition.observed_at.astimezone(UTC),
    )
    if actual != requested:
        raise LifecycleOperationConflictError(
            "observation operation UUID is already bound to different immutable evidence"
        )


def _require_finished_context(
    row: DatabaseRow,
    attempt: RunAttemptRecord,
    read_context_id: UUID,
    end_operation_id: UUID,
    ended_at: datetime,
    target_state: ReadContextStatus,
) -> PersistedReadContext:
    actual = (
        _row_uuid(row[0], "read context id"),
        _row_uuid(row[1], "read context run id"),
        _row_uuid(row[2], "read context attempt id"),
        _row_text(row[18], "read context state"),
        _row_optional_uuid(row[19], "read context end operation id"),
        _row_optional_datetime(row[20], "read context ended_at"),
    )
    requested = (
        read_context_id,
        attempt.run.run_id,
        attempt.attempt_id,
        target_state.value,
        end_operation_id,
        ended_at,
    )
    if actual != requested:
        raise LifecycleOperationConflictError(
            "read context end operation UUID is already bound to a different transition"
        )
    try:
        direction = PlanDirection(_row_text(row[4], "read context direction"))
    except ValueError:
        raise StoredLifecycleIntegrityError(
            "stored read context direction is unsupported"
        ) from None
    return PersistedReadContext(
        read_context_id=read_context_id,
        attempt_id=attempt.attempt_id,
        acquisition_operation_id=_row_uuid(row[5], "context acquisition operation id"),
        dataset_version_id=_row_uuid(row[3], "context dataset version id"),
        direction=direction,
        state=target_state,
        started_at=_row_datetime(row[17], "read context started_at"),
        end_operation_id=end_operation_id,
        ended_at=ended_at,
    )


def _retryable_outcome_from_database(
    connection: psycopg.Connection[DatabaseRow],
    expected: _OutcomeExpectation,
) -> AttemptOutcomeRecord:
    result = _outcome_receipt_from_database(connection, expected)
    run_row = connection.execute(
        "SELECT terminal_operation_id FROM dfe_metadata.runs WHERE run_id = %s",
        (expected.attempt.run.run_id,),
    ).fetchone()
    if run_row is None:
        raise StoredLifecycleIntegrityError("attempt outcome run row is missing")
    if _row_optional_uuid(run_row[0], "run terminal operation id") == expected.operation_id:
        raise LifecycleOperationConflictError(
            "retryable outcome operation unexpectedly selected a terminal run"
        )
    return result


def _terminal_outcome_from_database(
    connection: psycopg.Connection[DatabaseRow],
    expected: _OutcomeExpectation,
) -> AttemptOutcomeRecord:
    result = _outcome_receipt_from_database(connection, expected)
    run_row = connection.execute(
        "SELECT selected_terminal_attempt_id, terminal_operation_id, terminal_at "
        "FROM dfe_metadata.runs WHERE run_id = %s",
        (expected.attempt.run.run_id,),
    ).fetchone()
    if run_row is None:
        raise StoredLifecycleIntegrityError("attempt outcome run row is missing")
    if (
        _row_optional_uuid(run_row[0], "selected terminal attempt id")
        != expected.attempt.attempt_id
        or _row_optional_uuid(run_row[1], "terminal operation id") != expected.operation_id
        or _row_optional_datetime(run_row[2], "run terminal_at") != expected.ended_at
    ):
        raise LifecycleOperationConflictError(
            "terminal publication operation differs from the attempt outcome receipt"
        )
    return result


def _outcome_receipt_from_database(
    connection: psycopg.Connection[DatabaseRow],
    expected: _OutcomeExpectation,
) -> AttemptOutcomeRecord:
    row = _select_attempt_by_end_operation(connection, expected.operation_id)
    if row is None:
        raise StoredLifecycleIntegrityError("attempt outcome operation receipt is missing")
    actual = (
        _row_uuid(row[0], "outcome attempt id"),
        _row_uuid(row[1], "outcome run id"),
        _row_text(row[4], "outcome attempt status"),
        _row_optional_uuid(row[13], "attempt end operation id"),
        _row_optional_text(row[14], "attempt terminal reason code"),
        _row_optional_canonical_json(row[15], "attempt terminal reason"),
        _row_optional_datetime(row[17], "attempt ended_at"),
    )
    requested = (
        expected.attempt.attempt_id,
        expected.attempt.run.run_id,
        expected.status.value,
        expected.operation_id,
        expected.reason.code.value,
        expected.reason_json,
        expected.ended_at,
    )
    if actual != requested:
        raise LifecycleOperationConflictError(
            "attempt outcome operation UUID is already bound to a different full outcome"
        )
    return AttemptOutcomeRecord(
        run_id=expected.attempt.run.run_id,
        attempt_id=expected.attempt.attempt_id,
        status=expected.status,
        operation_id=expected.operation_id,
        reason=expected.reason,
        ended_at=expected.ended_at,
    )


def _insert_completed_segment(
    connection: psycopg.Connection[DatabaseRow],
    expected: _CompletedComparisonExpectation,
    segment: IntegerRangeFingerprintPersistence,
) -> None:
    _insert_completed_segment_side(
        connection,
        expected,
        segment,
        PlanDirection.REFERENCE,
        segment.reference_observation_id,
        segment.reference_fingerprint,
    )
    _insert_completed_segment_side(
        connection,
        expected,
        segment,
        PlanDirection.TARGET,
        segment.target_observation_id,
        segment.target_fingerprint,
    )


def _insert_completed_segment_side(
    connection: psycopg.Connection[DatabaseRow],
    expected: _CompletedComparisonExpectation,
    segment: IntegerRangeFingerprintPersistence,
    direction: PlanDirection,
    observation_id: UUID,
    fingerprint: Fingerprint,
) -> None:
    connection.execute(
        "INSERT INTO dfe_metadata.segment_fingerprints ("
        "observation_id, run_id, attempt_id, direction, segment_sequence, "
        "parent_segment_sequence, depth, boundary_kind, lower_inclusive, "
        "upper_exclusive, traversal_state, canonical_protocol, fingerprint_protocol, "
        "row_count, limb_0, limb_1, limb_2, limb_3, limb_4, limb_5, limb_6, limb_7) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, 'integer_range', %s, %s, %s, %s, %s, "
        "%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            observation_id,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            direction.value,
            segment.segment_sequence,
            segment.parent_segment_sequence,
            segment.depth,
            segment.lower_inclusive,
            segment.upper_exclusive,
            segment.state.value,
            _CANONICAL_PROTOCOL,
            _FINGERPRINT_PROTOCOL,
            fingerprint.count,
            *fingerprint.limb_sums,
        ),
    )


def _completed_result_from_database(
    connection: psycopg.Connection[DatabaseRow],
    expected: _CompletedComparisonExpectation,
) -> RunResult:
    row = _select_result_by_operation(connection, expected.operation_id)
    if row is None:
        raise StoredLifecycleIntegrityError("completed comparison operation receipt is missing")
    result, completed_at = _completed_result_from_row(row)
    if (
        result != expected.result
        or _canonical_database_json(row[10], "completed result payload") != expected.result_json
        or _row_bytes(row[9], "completed result digest") != expected.result_digest
        or completed_at != expected.ended_at
    ):
        raise LifecycleOperationConflictError(
            "completed comparison operation UUID is already bound to a different full result"
        )
    segments = _completed_segments_from_database(
        connection,
        expected.attempt.run.run_id,
        expected.attempt.attempt_id,
    )
    if segments != expected.segments:
        raise LifecycleOperationConflictError(
            "completed comparison operation UUID is bound to different segment evidence"
        )
    _require_valid_stored_segments(result, segments)
    _require_completed_database_closure(
        connection,
        result,
        segments,
        completed_at,
    )
    _require_completed_terminal_receipt(connection, result, completed_at)
    return result


def _completed_result_from_row(row: DatabaseRow) -> tuple[RunResult, datetime]:
    payload_json = _canonical_database_json(row[10], "completed result payload")
    try:
        payload_value = semantic_value_from_json(payload_json)
        result = RunResult.model_validate_json(payload_json)
        replay_json = canonical_semantic_json(semantic_value_from_json(result.model_dump_json()))
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored completed result violates the public result protocol: reason={error}"
        ) from None
    if replay_json != payload_json:
        raise StoredLifecycleIntegrityError(
            "stored completed result payload contains unsupported or non-round-trippable fields"
        )
    digest = bytes.fromhex(semantic_digest_hex(payload_value))
    actual = (
        _row_uuid(row[0], "completed result run id"),
        _row_uuid(row[1], "completed result attempt id"),
        _row_text(row[2], "completed result check id"),
        _row_uuid(row[3], "completed result operation id"),
        _row_bytes(row[4], "completed result contract digest").hex(),
        _row_bytes(row[5], "completed result scope digest").hex(),
        _row_text(row[6], "completed result execution status"),
        _row_text(row[7], "completed result verdict"),
        _row_text(row[8], "completed result guarantee"),
        _row_bytes(row[9], "completed result digest"),
    )
    expected = (
        result.run_id,
        result.attempt_id,
        result.check_id,
        result.persistence.operation_id,
        result.contract_digest,
        result.scope_digest,
        result.execution_status.value,
        result.verdict.value,
        result.guarantee.value,
        digest,
    )
    if actual != expected:
        raise StoredLifecycleIntegrityError(
            "stored completed result columns differ from its canonical public payload"
        )
    return result, _row_datetime(row[11], "completed result completed_at")


def _comparison_definition_from_result(result: RunResult) -> CompletedComparisonDefinition:
    return CompletedComparisonDefinition(
        check_id=result.check_id,
        contract_digest=result.contract_digest,
        scope_digest=result.scope_digest,
        verdict=result.verdict,
        consistency=result.consistency,
        guarantee=result.guarantee,
        comparison_coverage=result.comparison_coverage,
        totals=result.totals,
        evidence_coverage=result.evidence_coverage,
        metrics=result.metrics,
        reasons=result.reasons,
    )


def _require_valid_stored_segments(
    result: RunResult,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
) -> None:
    try:
        definition = _comparison_definition_from_result(result)
        _validate_completed_segments(definition, segments)
    except (TypeError, ValueError) as error:
        raise StoredLifecycleIntegrityError(
            f"stored completed segment topology is invalid: reason={error}"
        ) from None


def _completed_segments_from_database(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
) -> tuple[IntegerRangeFingerprintPersistence, ...]:
    rows = _select_segment_rows_by_attempt(connection, run_id, attempt_id)
    if not rows or len(rows) % 2 != 0:
        raise StoredLifecycleIntegrityError(
            "completed comparison requires paired reference and target segment evidence"
        )
    segments: list[IntegerRangeFingerprintPersistence] = []
    for offset in range(0, len(rows), 2):
        reference = _stored_segment_side_from_row(rows[offset])
        target = _stored_segment_side_from_row(rows[offset + 1])
        common_reference = (
            reference.run_id,
            reference.attempt_id,
            reference.segment_sequence,
            reference.parent_segment_sequence,
            reference.depth,
            reference.lower_inclusive,
            reference.upper_exclusive,
            reference.state,
        )
        common_target = (
            target.run_id,
            target.attempt_id,
            target.segment_sequence,
            target.parent_segment_sequence,
            target.depth,
            target.lower_inclusive,
            target.upper_exclusive,
            target.state,
        )
        if (
            reference.direction is not PlanDirection.REFERENCE
            or target.direction is not PlanDirection.TARGET
            or common_reference != common_target
            or reference.run_id != run_id
            or reference.attempt_id != attempt_id
        ):
            raise StoredLifecycleIntegrityError(
                "stored reference and target segment evidence has inconsistent closure"
            )
        try:
            segment = IntegerRangeFingerprintPersistence(
                segment_sequence=reference.segment_sequence,
                parent_segment_sequence=reference.parent_segment_sequence,
                depth=reference.depth,
                lower_inclusive=reference.lower_inclusive,
                upper_exclusive=reference.upper_exclusive,
                state=reference.state,
                reference_observation_id=reference.observation_id,
                reference_fingerprint=reference.fingerprint,
                target_observation_id=target.observation_id,
                target_fingerprint=target.fingerprint,
            )
        except (TypeError, ValueError) as error:
            raise StoredLifecycleIntegrityError(
                f"stored completed segment violates its typed contract: reason={error}"
            ) from None
        segments.append(segment)
    return tuple(segments)


def _stored_segment_side_from_row(row: DatabaseRow) -> _StoredSegmentSide:
    try:
        direction = PlanDirection(_row_text(row[3], "segment direction"))
        state = ComparisonSegmentState(_row_text(row[10], "segment traversal state"))
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored completed segment enum is unsupported: reason={error}"
        ) from None
    if _row_text(row[7], "segment boundary kind") != "integer_range":
        raise StoredLifecycleIntegrityError("stored completed segment boundary kind is unsupported")
    if _row_text(row[11], "segment canonical protocol") != _CANONICAL_PROTOCOL:
        raise StoredLifecycleIntegrityError(
            "stored completed segment canonical protocol is unsupported"
        )
    if _row_text(row[12], "segment fingerprint protocol") != _FINGERPRINT_PROTOCOL:
        raise StoredLifecycleIntegrityError(
            "stored completed segment fingerprint protocol is unsupported"
        )
    try:
        fingerprint = Fingerprint(
            count=_row_integer(row[13], "segment fingerprint count"),
            limb_sums=(
                _row_unsigned_decimal_integer(row[14], "segment fingerprint limb 0"),
                _row_unsigned_decimal_integer(row[15], "segment fingerprint limb 1"),
                _row_unsigned_decimal_integer(row[16], "segment fingerprint limb 2"),
                _row_unsigned_decimal_integer(row[17], "segment fingerprint limb 3"),
                _row_unsigned_decimal_integer(row[18], "segment fingerprint limb 4"),
                _row_unsigned_decimal_integer(row[19], "segment fingerprint limb 5"),
                _row_unsigned_decimal_integer(row[20], "segment fingerprint limb 6"),
                _row_unsigned_decimal_integer(row[21], "segment fingerprint limb 7"),
            ),
        )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored completed segment fingerprint is invalid: reason={error}"
        ) from None
    return _StoredSegmentSide(
        observation_id=_row_uuid(row[0], "segment observation id"),
        run_id=_row_uuid(row[1], "segment run id"),
        attempt_id=_row_uuid(row[2], "segment attempt id"),
        direction=direction,
        segment_sequence=_row_integer(row[4], "segment sequence"),
        parent_segment_sequence=_row_optional_integer(
            row[5],
            "segment parent sequence",
        ),
        depth=_row_integer(row[6], "segment depth"),
        lower_inclusive=_row_integer(row[8], "segment lower bound"),
        upper_exclusive=_row_optional_integer(row[9], "segment upper bound"),
        state=state,
        fingerprint=fingerprint,
    )


def _require_attempt_fence_row(
    connection: psycopg.Connection[DatabaseRow],
    row: DatabaseRow,
    expected: RunAttemptRecord,
) -> None:
    if _row_uuid(row[6], "attempt owner token") != expected.owner_token:
        raise AttemptFenceError("attempt fence failed because the owner token differs")
    if _row_integer(row[7], "attempt lease revision") != expected.lease_revision:
        raise AttemptFenceError("attempt fence failed because the lease revision is stale")
    if _row_text(row[4], "attempt status") != AttemptStatus.RUNNING.value:
        raise AttemptFenceError("attempt fence failed because the attempt is not running")
    if _row_datetime(row[9], "attempt lease expiry") <= _database_now(connection):
        raise AttemptFenceError("attempt fence failed because the lease is expired")


def _require_outcome_attempt_row(
    row: DatabaseRow | None,
    expected: _OutcomeExpectation,
) -> DatabaseRow:
    if row is None or _row_uuid(row[1], "outcome attempt run id") != expected.attempt.run.run_id:
        raise AttemptFenceError("attempt outcome fence is unknown")
    return row


def _require_dataset_closure(
    connection: psycopg.Connection[DatabaseRow],
    run: ClaimedRun,
    dataset: DatasetVersionRecord,
    direction: PlanDirection,
) -> None:
    column = (
        "reference_dataset_version_id"
        if direction is PlanDirection.REFERENCE
        else "target_dataset_version_id"
    )
    row = connection.execute(
        f"SELECT {column} FROM dfe_metadata.contract_versions WHERE contract_version_id = %s",
        (run.request.contract_version_id,),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("run contract version is missing")
    if _row_uuid(row[0], "contract dataset version id") != dataset.dataset_version_id:
        raise RunLifecycleStateError(
            "dataset version is outside the run contract direction closure"
        )
    expected_batch = _expected_batch(run.request, direction)
    if dataset.definition.dataset_id != expected_batch.dataset_id:
        raise RunLifecycleStateError(
            "dataset logical identity is outside the run request direction closure"
        )


def _require_locked_completed_comparison_closure(
    connection: psycopg.Connection[DatabaseRow],
    expected: _CompletedComparisonExpectation,
) -> None:
    context_rows = connection.execute(
        _CONTEXT_SELECT + " WHERE run_id = %s AND attempt_id = %s "
        "ORDER BY CASE direction WHEN 'reference' THEN 0 WHEN 'target' THEN 1 ELSE 2 END "
        "FOR UPDATE",
        (expected.attempt.run.run_id, expected.attempt.attempt_id),
    ).fetchall()
    observation_rows = _select_observation_rows_by_attempt(
        connection,
        expected.attempt.run.run_id,
        expected.attempt.attempt_id,
    )
    _require_completed_closure_rows(
        connection,
        expected.result,
        expected.segments,
        expected.ended_at,
        context_rows,
        observation_rows,
    )


def _require_completed_database_closure(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
    completed_at: datetime,
) -> None:
    context_rows = connection.execute(
        _CONTEXT_SELECT + " WHERE run_id = %s AND attempt_id = %s "
        "ORDER BY CASE direction WHEN 'reference' THEN 0 WHEN 'target' THEN 1 ELSE 2 END",
        (result.run_id, result.attempt_id),
    ).fetchall()
    observation_rows = _select_observation_rows_by_attempt(
        connection,
        result.run_id,
        result.attempt_id,
    )
    _require_completed_closure_rows(
        connection,
        result,
        segments,
        completed_at,
        context_rows,
        observation_rows,
    )


def _select_observation_rows_by_attempt(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
) -> list[DatabaseRow]:
    return connection.execute(
        _OBSERVATION_SELECT + " WHERE run_id = %s AND attempt_id = %s "
        "ORDER BY CASE direction WHEN 'reference' THEN 0 WHEN 'target' THEN 1 ELSE 2 END",
        (run_id, attempt_id),
    ).fetchall()


def _require_completed_closure_rows(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
    completed_at: datetime,
    context_rows: list[DatabaseRow],
    observation_rows: list[DatabaseRow],
) -> None:
    if (
        result.consistency.stable_reads is not ConsistencyLevel.VERIFIED
        or result.consistency.cut_alignment is not ConsistencyLevel.VERIFIED
    ):
        raise RunLifecycleStateError(
            "completed comparison requires verified stable reads and cut alignment"
        )
    if len(context_rows) != 2:
        raise RunLifecycleStateError(
            "completed comparison requires exactly two protected read contexts"
        )
    reference_context, target_context = context_rows
    if (
        _row_text(reference_context[4], "reference context direction")
        != PlanDirection.REFERENCE.value
        or _row_text(target_context[4], "target context direction") != PlanDirection.TARGET.value
    ):
        raise StoredLifecycleIntegrityError(
            "completed comparison contexts lack one reference and one target direction"
        )
    reference_context_id = _row_uuid(reference_context[0], "reference context id")
    target_context_id = _row_uuid(target_context[0], "target context id")
    if result.consistency.read_context_ids != (
        reference_context_id,
        target_context_id,
    ):
        raise RunLifecycleStateError(
            "completed result context ids must be ordered as its reference and target contexts"
        )
    context_ended_at = (
        _require_closed_completed_context(
            reference_context,
            result,
            PlanDirection.REFERENCE,
            completed_at,
        ),
        _require_closed_completed_context(
            target_context,
            result,
            PlanDirection.TARGET,
            completed_at,
        ),
    )
    if not segments:
        raise StoredLifecycleIntegrityError("completed comparison closure has no segment evidence")
    if len(observation_rows) != 2:
        raise RunLifecycleStateError(
            "completed comparison requires exactly two bound-cut observations"
        )
    attempt_row = connection.execute(
        "SELECT input_cut_digest, execution_budgets::text "
        "FROM dfe_metadata.run_attempts "
        "WHERE run_id = %s AND attempt_id = %s",
        (result.run_id, result.attempt_id),
    ).fetchone()
    if attempt_row is None:
        raise StoredLifecycleIntegrityError("completed comparison attempt closure row is missing")
    attempt_cut_digest = _row_optional_bytes(
        attempt_row[0],
        "completed comparison attempt cut digest",
    )
    attempt_budgets = _execution_budgets_from_database(attempt_row[1])
    _validate_completed_budget_use(
        attempt_budgets,
        _comparison_definition_from_result(result),
        segments,
    )
    run_contract_row = connection.execute(
        "SELECT dfe_run.scope_digest, dfe_run.bound_input_cut_digest, "
        "dfe_contract.check_id, dfe_contract.semantic_digest, "
        "dfe_contract.assurance_policy "
        "FROM dfe_metadata.runs AS dfe_run "
        "JOIN dfe_metadata.contract_versions AS dfe_contract "
        "ON dfe_contract.contract_version_id = dfe_run.contract_version_id "
        "WHERE dfe_run.run_id = %s",
        (result.run_id,),
    ).fetchone()
    if run_contract_row is None:
        raise StoredLifecycleIntegrityError("completed comparison run contract closure is missing")
    run_cut_digest = _row_optional_bytes(
        run_contract_row[1],
        "completed comparison run cut digest",
    )
    if attempt_cut_digest is None or run_cut_digest != attempt_cut_digest:
        raise RunLifecycleStateError(
            "completed comparison requires the attempt's aligned cut bound to its run"
        )
    if (
        _row_bytes(run_contract_row[0], "completed comparison run scope digest").hex()
        != result.scope_digest
        or _row_text(run_contract_row[2], "completed comparison contract check id")
        != result.check_id
        or _row_bytes(
            run_contract_row[3],
            "completed comparison contract semantic digest",
        ).hex()
        != result.contract_digest
    ):
        raise RunLifecycleStateError(
            "completed result identity differs from its immutable run contract and scope"
        )
    assurance_policy = _row_text(
        run_contract_row[4],
        "completed comparison contract assurance policy",
    )
    if assurance_policy not in ("exact_required", "fingerprint_allowed"):
        raise StoredLifecycleIntegrityError(
            "completed comparison contract assurance policy is unsupported"
        )
    if assurance_policy == "exact_required" and result.guarantee is not Guarantee.EXACT:
        raise RunLifecycleStateError(
            "exact_required contract cannot publish a weaker completed guarantee"
        )
    reference_observation, target_observation = observation_rows
    expected_observation_ids = (
        segments[0].reference_observation_id,
        segments[0].target_observation_id,
    )
    _require_completed_observation(
        reference_observation,
        result,
        PlanDirection.REFERENCE,
        reference_context,
        expected_observation_ids[0],
        attempt_cut_digest,
        context_ended_at[0],
    )
    _require_completed_observation(
        target_observation,
        result,
        PlanDirection.TARGET,
        target_context,
        expected_observation_ids[1],
        attempt_cut_digest,
        context_ended_at[1],
    )


def _require_closed_completed_context(
    row: DatabaseRow,
    result: RunResult,
    direction: PlanDirection,
    completed_at: datetime,
) -> datetime:
    if (
        _row_uuid(row[1], "completed context run id") != result.run_id
        or _row_uuid(row[2], "completed context attempt id") != result.attempt_id
        or _row_text(row[4], "completed context direction") != direction.value
        or _row_bytes(row[6], "completed context scope digest").hex() != result.scope_digest
    ):
        raise StoredLifecycleIntegrityError(
            "completed protected context differs from its run, attempt, direction, or scope"
        )
    if _row_text(row[18], "completed context state") != ReadContextStatus.CLOSED.value:
        raise RunLifecycleStateError(
            "completed comparison requires both protected read contexts to be closed, not lost"
        )
    if _row_optional_uuid(row[19], "completed context end operation id") is None:
        raise StoredLifecycleIntegrityError("closed completed context has no durable end operation")
    ended_at = _row_optional_datetime(row[20], "completed context ended_at")
    if ended_at is None:
        raise StoredLifecycleIntegrityError("closed completed context has no durable end timestamp")
    if ended_at > completed_at:
        raise RunLifecycleStateError(
            "completed comparison cannot precede protected context closure"
        )
    return ended_at


def _require_completed_observation(
    row: DatabaseRow,
    result: RunResult,
    direction: PlanDirection,
    context_row: DatabaseRow,
    expected_observation_id: UUID,
    input_cut_digest: bytes,
    context_ended_at: datetime,
) -> None:
    if (
        _row_uuid(row[0], "completed observation id") != expected_observation_id
        or _row_uuid(row[2], "completed observation run id") != result.run_id
        or _row_uuid(row[3], "completed observation attempt id") != result.attempt_id
        or _row_uuid(row[4], "completed observation context id")
        != _row_uuid(context_row[0], "completed observation expected context id")
        or _row_uuid(row[5], "completed observation dataset version id")
        != _row_uuid(context_row[3], "completed context dataset version id")
        or _row_text(row[6], "completed observation direction") != direction.value
        or _row_bytes(row[7], "completed observation scope digest").hex() != result.scope_digest
        or _row_bytes(row[8], "completed observation input cut digest") != input_cut_digest
    ):
        raise StoredLifecycleIntegrityError(
            "completed segment observation differs from its bound context, cut, or scope"
        )
    if _row_datetime(row[16], "completed observation observed_at") > context_ended_at:
        raise StoredLifecycleIntegrityError(
            "completed observation was recorded after its protected context closed"
        )


def _require_completed_terminal_receipt(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    completed_at: datetime,
) -> None:
    operation_id = result.persistence.operation_id
    if operation_id is None:
        raise StoredLifecycleIntegrityError("completed result has no persistence operation id")
    attempt_row = _select_attempt_by_id(connection, result.attempt_id)
    if attempt_row is None:
        raise StoredLifecycleIntegrityError("completed result attempt is missing")
    attempt_receipt = (
        _row_uuid(attempt_row[1], "completed attempt run id"),
        _row_text(attempt_row[4], "completed attempt status"),
        _row_optional_uuid(attempt_row[13], "completed attempt end operation id"),
        _row_optional_text(attempt_row[14], "completed attempt terminal reason code"),
        _row_optional_canonical_json(
            attempt_row[15],
            "completed attempt terminal reason",
        ),
        _row_optional_datetime(attempt_row[17], "completed attempt ended_at"),
    )
    if attempt_receipt != (
        result.run_id,
        AttemptStatus.COMPLETED.value,
        operation_id,
        None,
        None,
        completed_at,
    ):
        raise StoredLifecycleIntegrityError(
            "completed result differs from its terminal attempt receipt"
        )
    run_row = connection.execute(
        "SELECT selected_terminal_attempt_id, terminal_operation_id, terminal_at "
        "FROM dfe_metadata.runs WHERE run_id = %s",
        (result.run_id,),
    ).fetchone()
    if run_row is None:
        raise StoredLifecycleIntegrityError("completed result run is missing")
    if (
        _row_optional_uuid(run_row[0], "completed run selected attempt id") != result.attempt_id
        or _row_optional_uuid(run_row[1], "completed run terminal operation id") != operation_id
        or _row_optional_datetime(run_row[2], "completed run terminal_at") != completed_at
    ):
        raise StoredLifecycleIntegrityError(
            "completed result differs from its terminal run publication"
        )


def _require_attempt_closure_for_end(
    connection: psycopg.Connection[DatabaseRow],
    attempt: RunAttemptRecord,
) -> None:
    active_count_row = connection.execute(
        "SELECT pg_catalog.count(*) FROM dfe_metadata.attempt_read_contexts "
        "WHERE run_id = %s AND attempt_id = %s AND state = 'active'",
        (attempt.run.run_id, attempt.attempt_id),
    ).fetchone()
    if active_count_row is None or _row_integer(active_count_row[0], "active context count") != 0:
        raise RunLifecycleStateError(
            "attempt outcome requires every acquired read context to be closed or lost"
        )
    row = connection.execute(
        "SELECT input_cut_digest FROM dfe_metadata.run_attempts "
        "WHERE run_id = %s AND attempt_id = %s",
        (attempt.run.run_id, attempt.attempt_id),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("attempt closure row is missing")
    cut_digest = _row_optional_bytes(row[0], "attempt closure input cut digest")
    observation_count_row = connection.execute(
        "SELECT pg_catalog.count(*) FROM dfe_metadata.dataset_observations "
        "WHERE run_id = %s AND attempt_id = %s",
        (attempt.run.run_id, attempt.attempt_id),
    ).fetchone()
    if observation_count_row is None:
        raise StoredLifecycleIntegrityError("attempt observation count is missing")
    observation_count = _row_integer(observation_count_row[0], "attempt observation count")
    if cut_digest is None:
        if observation_count != 0:
            raise StoredLifecycleIntegrityError(
                "attempt without a bound cut cannot contain dataset observations"
            )
        return
    if observation_count != 2:
        raise StoredLifecycleIntegrityError(
            "attempt with a bound cut requires exactly two dataset observations"
        )
    run_row = connection.execute(
        "SELECT bound_input_cut_digest FROM dfe_metadata.runs WHERE run_id = %s",
        (attempt.run.run_id,),
    ).fetchone()
    if run_row is None or _row_optional_bytes(run_row[0], "run bound cut digest") != cut_digest:
        raise StoredLifecycleIntegrityError(
            "attempt input cut digest differs from its run's first bound cut"
        )


def _validate_retryable_outcome_arguments(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> None:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_uuid(operation_id, "attempt outcome operation id")
    _require_instance(reason, ResultReason, "attempt outcome reason")
    _require_utc_datetime(ended_at, "attempt outcome ended_at")


def _validate_terminal_outcome_arguments(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    operation_id: UUID,
    reason: ResultReason,
    ended_at: datetime,
) -> None:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_uuid(operation_id, "attempt terminal publication operation id")
    _require_instance(reason, ResultReason, "attempt outcome reason")
    _require_utc_datetime(ended_at, "attempt outcome ended_at")


def _validate_incomplete_reason(reason: ResultReason) -> None:
    supported = frozenset(
        (
            ReasonCode.NOT_READY,
            ReasonCode.CUT_MISMATCH,
            ReasonCode.SNAPSHOT_LOST,
            ReasonCode.BUDGET_EXHAUSTED,
            ReasonCode.CANCELLED,
            ReasonCode.CANCELLATION_UNCONFIRMED,
            ReasonCode.OVERSIZED_RECORD,
        )
    )
    if reason.code not in supported:
        raise ValueError(
            f"attempt status {AttemptStatus.INCOMPLETE.value!r} "
            f"does not accept reason code {reason.code.value!r}"
        )


def _validate_error_reason(reason: ResultReason) -> None:
    supported = frozenset(
        (
            ReasonCode.INVALID_CONTRACT,
            ReasonCode.UNSUPPORTED_CAPABILITY,
            ReasonCode.LOSSY_TRANSPORT,
            ReasonCode.QUERY_ERROR,
            ReasonCode.PERSISTENCE_ERROR,
            ReasonCode.COMMIT_UNKNOWN,
            ReasonCode.PROTOCOL_VIOLATION,
        )
    )
    if reason.code not in supported:
        raise ValueError(
            f"attempt status {AttemptStatus.ERROR.value!r} "
            f"does not accept reason code {reason.code.value!r}"
        )


def _expected_batch(
    request: RunRequestDefinition,
    direction: PlanDirection,
) -> ExpectedBatchDefinition:
    index = 0 if direction is PlanDirection.REFERENCE else 1
    expected = request.expected_batches[index]
    if expected.direction is not direction:
        raise ValueError("run request expected batch direction closure is invalid")
    return expected


def _canonical_string_value(field: object, payload: bytes, context: str) -> str:
    from forensic_data.canonical import FieldSchema, decode_payload

    if not isinstance(field, FieldSchema):
        raise ValueError(f"{context} field must be a FieldSchema")
    value = decode_payload(field, payload)
    if type(value) is not str:
        raise ValueError(f"{context} must decode to text")
    return value


def _derived_context_abandonment_operation(
    maintenance_operation_id: UUID,
    context_id: UUID,
) -> UUID:
    return uuid5(maintenance_operation_id, f"read-context-lost:{context_id}")


def _lock_operation_identities(
    connection: psycopg.Connection[DatabaseRow],
    identities: tuple[UUID, ...],
) -> None:
    for identity in sorted(set(identities), key=lambda value: value.int):
        connection.execute(
            "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(%s, 1145455922))",
            (str(identity),),
        )


def _is_ambiguous_connection_failure(error: psycopg.OperationalError) -> bool:
    sqlstate = error.sqlstate
    return sqlstate is None or sqlstate.startswith("08") or sqlstate in ("57P01", "57P02", "57P03")


def _run_read_with_retries[ResultT](
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    operation: str,
    read: Callable[[psycopg.Connection[DatabaseRow]], ResultT],
) -> ResultT:
    last_error: psycopg.OperationalError | None = None
    for attempt_number in range(1, retry_policy.max_attempts + 1):
        connection: psycopg.Connection[DatabaseRow] | None = None
        try:
            connection = _connect(settings)
            _validate_metadata_profile(connection)
            return read(connection)
        except psycopg.OperationalError as error:
            last_error = error
        except psycopg.Error as error:
            raise LifecycleTransactionError(
                "PostgreSQL lifecycle read transaction definitively failed: "
                f"operation={operation!r}, error_type={type(error).__name__}, "
                f"sqlstate={error.sqlstate!r}"
            ) from None
        finally:
            if connection is not None:
                connection.close()
        _warn_lifecycle_attempt_failure(
            settings,
            retry_policy,
            operation,
            attempt_number,
            last_error,
        )
        if attempt_number < retry_policy.max_attempts:
            time.sleep(retry_policy.delay_seconds)
    if last_error is None:
        raise AssertionError("lifecycle read retry loop ended without an operational error")
    raise LifecycleTransactionError(
        "PostgreSQL lifecycle read transaction failed after bounded attempts: "
        f"operation={operation!r}, host={settings.host!r}, port={settings.port}, "
        f"dbname={settings.dbname!r}, user={settings.user!r}, "
        f"attempts={retry_policy.max_attempts}, "
        f"error_type={type(last_error).__name__}, sqlstate={last_error.sqlstate!r}"
    ) from None


def _run_with_reconciliation[ResultT](
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    operation: str,
    reconciliation_identities: tuple[UUID, ...],
    write: Callable[[psycopg.Connection[DatabaseRow]], ResultT],
    reconcile: Callable[[psycopg.Connection[DatabaseRow]], ResultT | None],
) -> ResultT:
    last_error: psycopg.OperationalError | None = None
    unresolved_ambiguous_write = False
    for attempt_number in range(1, retry_policy.max_attempts + 1):
        if unresolved_ambiguous_write:
            reconciled = _try_reconcile(
                settings,
                operation,
                reconciliation_identities,
                reconcile,
            )
            if not isinstance(reconciled, (_ReceiptAbsent, _ReconciliationUnavailable)):
                return reconciled
            if isinstance(reconciled, _ReceiptAbsent):
                unresolved_ambiguous_write = False
            else:
                if last_error is None:
                    raise AssertionError("unresolved commit has no operational failure")
                _warn_lifecycle_attempt_failure(
                    settings,
                    retry_policy,
                    operation,
                    attempt_number,
                    last_error,
                )
                if attempt_number < retry_policy.max_attempts:
                    time.sleep(retry_policy.delay_seconds)
                continue
        connection: psycopg.Connection[DatabaseRow] | None = None
        write_entered = False
        try:
            connection = _connect(settings)
            _validate_metadata_profile(connection)
            write_entered = True
            return write(connection)
        except psycopg.OperationalError as error:
            last_error = error
            if write_entered and _is_ambiguous_connection_failure(error):
                unresolved_ambiguous_write = True
        except psycopg.Error as error:
            raise LifecycleTransactionError(
                "PostgreSQL lifecycle transaction definitively failed and was rolled back: "
                f"operation={operation!r}, error_type={type(error).__name__}, "
                f"sqlstate={error.sqlstate!r}"
            ) from None
        finally:
            if connection is not None:
                connection.close()
        if unresolved_ambiguous_write:
            reconciled = _try_reconcile(
                settings,
                operation,
                reconciliation_identities,
                reconcile,
            )
            if not isinstance(reconciled, (_ReceiptAbsent, _ReconciliationUnavailable)):
                return reconciled
            if isinstance(reconciled, _ReceiptAbsent):
                unresolved_ambiguous_write = False
        _warn_lifecycle_attempt_failure(
            settings,
            retry_policy,
            operation,
            attempt_number,
            last_error,
        )
        if attempt_number < retry_policy.max_attempts:
            time.sleep(retry_policy.delay_seconds)
    if last_error is None:
        raise AssertionError("lifecycle retry loop ended without an operational error")
    if not unresolved_ambiguous_write:
        raise LifecycleTransactionError(
            "PostgreSQL lifecycle transaction failed and no ambiguous commit remained "
            "after bounded attempts: "
            f"operation={operation!r}, host={settings.host!r}, port={settings.port}, "
            f"dbname={settings.dbname!r}, user={settings.user!r}, "
            f"attempts={retry_policy.max_attempts}, "
            f"error_type={type(last_error).__name__}, sqlstate={last_error.sqlstate!r}"
        ) from None
    raise LifecycleCommitUnknownError(
        "PostgreSQL lifecycle operation could not be confirmed after bounded retries: "
        f"operation={operation!r}, host={settings.host!r}, port={settings.port}, "
        f"dbname={settings.dbname!r}, user={settings.user!r}, "
        f"attempts={retry_policy.max_attempts}, "
        f"error_type={type(last_error).__name__}, sqlstate={last_error.sqlstate!r}"
    ) from None


def _warn_lifecycle_attempt_failure(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    operation: str,
    attempt_number: int,
    error: psycopg.OperationalError,
) -> None:
    LOGGER.warning(
        "PostgreSQL lifecycle operation attempt failed",
        extra={
            "operation": operation,
            "attempt": attempt_number,
            "max_attempts": retry_policy.max_attempts,
            "host": settings.host,
            "port": settings.port,
            "dbname": settings.dbname,
            "user": settings.user,
            "error_type": type(error).__name__,
            "sqlstate": error.sqlstate,
        },
    )


def _try_reconcile[ResultT](
    settings: PostgresConnectionSettings,
    operation: str,
    reconciliation_identities: tuple[UUID, ...],
    reconcile: Callable[[psycopg.Connection[DatabaseRow]], ResultT | None],
) -> ResultT | _ReceiptAbsent | _ReconciliationUnavailable:
    connection: psycopg.Connection[DatabaseRow] | None = None
    try:
        try:
            connection = _connect(settings)
            _validate_metadata_profile(connection)
            _begin_reconciliation_transaction(
                connection,
                settings.statement_timeout_milliseconds,
            )
            _require_current_schema(connection)
            _lock_operation_identities(connection, reconciliation_identities)
        except psycopg.Error as error:
            _warn_reconciliation_failure(settings, operation, type(error).__name__, error.sqlstate)
            return _ReconciliationUnavailable()
        except (
            LifecyclePersistenceError,
            MetadataMigrationHistoryError,
            StoredLifecycleIntegrityError,
        ) as error:
            _warn_reconciliation_failure(settings, operation, type(error).__name__, None)
            return _ReconciliationUnavailable()
        try:
            result = reconcile(connection)
        except psycopg.Error as error:
            _warn_reconciliation_failure(settings, operation, type(error).__name__, error.sqlstate)
            return _ReconciliationUnavailable()
        if result is None:
            return _ReceiptAbsent()
        return result
    finally:
        if connection is not None:
            connection.close()


def _warn_reconciliation_failure(
    settings: PostgresConnectionSettings,
    operation: str,
    error_type: str,
    sqlstate: str | None,
) -> None:
    LOGGER.warning(
        "PostgreSQL lifecycle operation reconciliation failed",
        extra={
            "operation": operation,
            "host": settings.host,
            "port": settings.port,
            "dbname": settings.dbname,
            "user": settings.user,
            "error_type": error_type,
            "sqlstate": sqlstate,
        },
    )


def _connect(settings: PostgresConnectionSettings) -> psycopg.Connection[DatabaseRow]:
    return psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password.get_secret_value(),
        sslmode=settings.sslmode.value,
        connect_timeout=settings.connect_timeout_seconds,
        application_name=settings.application_name,
        options=f"-c statement_timeout={settings.statement_timeout_milliseconds}",
        autocommit=True,
        row_factory=tuple_row,
    )


def _validate_metadata_profile(connection: psycopg.Connection[DatabaseRow]) -> None:
    row = connection.execute(
        "SELECT pg_catalog.current_setting('server_version_num')::integer, "
        "pg_catalog.current_setting('server_encoding')"
    ).fetchone()
    if row is None or len(row) != 2:
        raise LifecyclePersistenceError("metadata profile probe returned an invalid row")
    version_number = _row_integer(row[0], "metadata server version number")
    encoding = _row_text(row[1], "metadata server encoding")
    if version_number // 10_000 != _METADATA_MAJOR_VERSION or encoding != "UTF8":
        raise LifecyclePersistenceError(
            "lifecycle persistence requires PostgreSQL 17 with UTF8 encoding: "
            f"server_version_number={version_number}, encoding={encoding!r}"
        )


def _begin_writer_transaction(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
) -> None:
    connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE")
    connection.execute(f"SET LOCAL ROLE {_WRITER_ROLE}")
    _configure_transaction(connection, statement_timeout_milliseconds)


def _begin_reconciliation_transaction(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
) -> None:
    connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE")
    connection.execute(f"SET LOCAL ROLE {_WRITER_ROLE}")
    _configure_transaction(connection, statement_timeout_milliseconds)


def _begin_reader_transaction(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
) -> None:
    connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
    connection.execute(f"SET LOCAL ROLE {_READER_ROLE}")
    _configure_transaction(connection, statement_timeout_milliseconds)


def _configure_transaction(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
) -> None:
    connection.execute("SET LOCAL search_path TO pg_catalog")
    connection.execute("SET LOCAL TIME ZONE 'UTC'")
    connection.execute("SET LOCAL DateStyle TO 'ISO, YMD'")
    connection.execute(
        "SELECT pg_catalog.set_config('statement_timeout', %s, true)",
        (f"{statement_timeout_milliseconds}ms",),
    )


def _require_current_schema(connection: psycopg.Connection[DatabaseRow]) -> None:
    migrations = load_postgres_metadata_migrations()
    rows = connection.execute(
        "SELECT version, name, checksum_sha256 FROM dfe_metadata.migrations ORDER BY version"
    ).fetchall()
    if len(rows) != len(migrations):
        raise MetadataMigrationHistoryError(
            "PostgreSQL metadata schema version differs from the packaged lifecycle runtime: "
            f"applied_count={len(rows)}, required_count={len(migrations)}"
        )
    for row, expected in zip(rows, migrations, strict=True):
        version = _row_integer(row[0], "migration version")
        name = _row_text(row[1], "migration name")
        checksum = _row_bytes(row[2], "migration checksum").hex()
        if version != expected.version or name != expected.name:
            raise MetadataMigrationHistoryError(
                "PostgreSQL migration journal is not the exact packaged prefix: "
                f"expected_version={expected.version}, actual_version={version}, "
                f"expected_name={expected.name!r}, actual_name={name!r}"
            )
        if checksum != expected.checksum_sha256:
            raise MetadataMigrationChecksumError(
                "PostgreSQL migration checksum differs from the packaged SQL bytes: "
                f"version={version}, name={name!r}"
            )


def _database_now(connection: psycopg.Connection[DatabaseRow]) -> datetime:
    row = connection.execute("SELECT pg_catalog.clock_timestamp()").fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("database clock query returned no row")
    return _row_datetime(row[0], "database current timestamp")


def _commit_result[ResultT](
    connection: psycopg.Connection[DatabaseRow],
    result: ResultT,
) -> ResultT:
    connection.execute("COMMIT")
    return result


def _commit_fenced_result[ResultT](
    connection: psycopg.Connection[DatabaseRow],
    result: ResultT,
    pre_mutation_lease_expires_at: datetime,
    operation: str,
) -> ResultT:
    if pre_mutation_lease_expires_at <= _database_now(connection):
        raise AttemptFenceError(
            f"attempt lease expired before fenced lifecycle commit: operation={operation!r}"
        )
    connection.execute("COMMIT")
    return result


def _canonical_database_json(value: object, context: str) -> str:
    text = _row_text(value, context)
    try:
        return canonicalize_semantic_json(text)
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"PostgreSQL {context} is not canonical semantic JSON: reason={error}"
        ) from None


def _row_optional_canonical_json(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _canonical_database_json(value, context)


def _row_text(value: object, context: str) -> str:
    if type(value) is not str:
        raise StoredLifecycleIntegrityError(f"PostgreSQL {context} must be text")
    return value


def _row_optional_text(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _row_text(value, context)


def _row_integer(value: object, context: str) -> int:
    if type(value) is not int:
        raise StoredLifecycleIntegrityError(f"PostgreSQL {context} must be an integer")
    return value


def _row_optional_integer(value: object, context: str) -> int | None:
    if value is None:
        return None
    return _row_integer(value, context)


def _row_unsigned_decimal_integer(value: object, context: str) -> int:
    text = _row_text(value, context)
    try:
        integer = int(text)
    except ValueError:
        raise StoredLifecycleIntegrityError(
            f"PostgreSQL {context} must be an unsigned decimal integer"
        ) from None
    if integer < 0 or str(integer) != text:
        raise StoredLifecycleIntegrityError(
            f"PostgreSQL {context} must use canonical unsigned decimal integer text"
        )
    return integer


def _row_bytes(value: object, context: str) -> bytes:
    if type(value) is bytes:
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    raise StoredLifecycleIntegrityError(f"PostgreSQL {context} must be bytes")


def _row_optional_bytes(value: object, context: str) -> bytes | None:
    if value is None:
        return None
    return _row_bytes(value, context)


def _row_uuid(value: object, context: str) -> UUID:
    if type(value) is not UUID:
        raise StoredLifecycleIntegrityError(f"PostgreSQL {context} must be a UUID")
    return value


def _row_optional_uuid(value: object, context: str) -> UUID | None:
    if value is None:
        return None
    return _row_uuid(value, context)


def _row_datetime(value: object, context: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise StoredLifecycleIntegrityError(
            f"PostgreSQL {context} must be a timezone-aware timestamp"
        )
    return value.astimezone(UTC)


def _row_optional_datetime(value: object, context: str) -> datetime | None:
    if value is None:
        return None
    return _row_datetime(value, context)


def _semantic_object(value: SemanticValue | None, context: str) -> dict[str, SemanticValue]:
    if not isinstance(value, dict):
        raise StoredLifecycleIntegrityError(f"{context} must be a semantic object")
    return value


def _semantic_array(value: SemanticValue | None, context: str) -> list[SemanticValue]:
    if not isinstance(value, list):
        raise StoredLifecycleIntegrityError(f"{context} must be a semantic array")
    return value


def _semantic_text(value: SemanticValue | None, context: str) -> str:
    if type(value) is not str or value.strip() == "":
        raise StoredLifecycleIntegrityError(f"{context} must be nonblank semantic text")
    return value


def _semantic_integer(value: SemanticValue | None, context: str) -> int:
    if type(value) is not int:
        raise StoredLifecycleIntegrityError(f"{context} must be a semantic integer")
    return value


def _require_instance[ExpectedT](
    value: object,
    expected_type: type[ExpectedT],
    context: str,
) -> ExpectedT:
    if not isinstance(value, expected_type):
        raise TypeError(f"{context} must be {expected_type.__name__}")
    return value


def _require_uuid(value: object, context: str) -> None:
    if type(value) is not UUID:
        raise TypeError(f"{context} must be an exact UUID")


def _require_optional_uuid(value: object, context: str) -> None:
    if value is not None:
        _require_uuid(value, context)


def _require_positive_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"{context} must be a positive exact integer")


def _require_nonnegative_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{context} must be a non-negative exact integer")


def _require_nonnegative_int32(value: object, context: str) -> None:
    if type(value) is not int or not 0 <= value <= (1 << 31) - 1:
        raise ValueError(f"{context} must be a non-negative exact signed int32 integer")


def _require_int64(value: object, context: str) -> None:
    if type(value) is not int or not -(1 << 63) <= value <= (1 << 63) - 1:
        raise ValueError(f"{context} must be an exact signed int64 integer")


def _require_utc_datetime(value: object, context: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{context} must be an exact timezone-aware datetime")
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError(f"{context} must use UTC")


def _require_optional_utc_datetime(value: object, context: str) -> None:
    if value is not None:
        _require_utc_datetime(value, context)


def _require_optional_sha256(value: object, context: str) -> None:
    if value is None:
        return
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{context} must be a lowercase hexadecimal SHA-256 digest")


def _require_sha256(value: object, context: str) -> None:
    if value is None:
        raise ValueError(f"{context} must be a lowercase hexadecimal SHA-256 digest")
    _require_optional_sha256(value, context)
