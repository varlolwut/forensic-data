import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
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
from forensic_data.canonical import (
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    Fingerprint,
    LogicalType,
    NoParameters,
    Normalization,
    TimestampParameters,
    canonical_schema_json,
    combine_fingerprints,
    decode_payload,
    encode_payload,
    schema_digest_hex,
    schema_from_metadata_json,
)
from forensic_data.comparison import (
    ComparisonSegmentRecord,
    CompletedComparisonArtifact,
    CompletedStructuralComparisonArtifact,
    PartialComparisonArtifact,
    PartialComparisonFrontier,
    UnresolvedComparisonSegment,
    canonical_partial_comparison_frontier_bytes,
    partial_comparison_frontier_from_canonical_bytes,
)
from forensic_data.contracts.model import (
    EvidenceAction,
    ExecutionBudgets,
    RelationScope,
    SqlDialect,
)
from forensic_data.contracts.semantics import (
    SemanticValue,
    canonical_semantic_json,
    canonicalize_semantic_json,
    semantic_digest_hex,
    semantic_value_from_json,
)
from forensic_data.greengage_endpoint import (
    GreengageProtectedReadContext,
    GreengageProtectedRelationInspection,
)
from forensic_data.greenplum import (
    GreenplumDriverEvidence,
    GreenplumRelationLockEvidence,
    GreenplumServerProfile,
    GreenplumSessionSettingEvidence,
)
from forensic_data.greenplum_catalog import (
    GreengageHashCapability,
    GreenplumReaderIdentity,
    GreenplumSegment,
    GreenplumStorageProfile,
    GreenplumTopology,
    OriginalGreenplumHashCapability,
)
from forensic_data.greenplum_profile import (
    ORIGINAL_GREENPLUM_DRIVER,
    ORIGINAL_GREENPLUM_PROFILE,
    GreenplumRuntimeProfile,
)
from forensic_data.mssql import MssqlProtectedReadContext, MssqlReadContextState
from forensic_data.mssql_sql import (
    MssqlFieldBinding,
    MssqlInspectedRelation,
    MssqlPhysicalField,
    MssqlUtf8HelperBinding,
    validate_mssql_inspection,
)
from forensic_data.original_greenplum_endpoint import (
    OriginalGreenplumProtectedReadContext,
    OriginalGreenplumProtectedRelationInspection,
)
from forensic_data.persistence.errors import (
    ActiveRunAttemptError,
    AttemptFenceError,
    CompletedComparisonNotFoundError,
    InputCutMismatchError,
    LifecycleCommitUnknownError,
    LifecycleOperationConflictError,
    LifecyclePersistenceError,
    LifecycleTransactionError,
    MetadataMigrationChecksumError,
    MetadataMigrationHistoryError,
    PartialComparisonNotFoundError,
    RunAttemptLimitError,
    RunInvocationContinuationError,
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
    PostgresInheritanceEdge,
    PostgresProtectedReadContext,
    PostgresProtectedRelationInspection,
    PostgresProtectedRelationMember,
    PostgresRelationKind,
    PostgresRelationPersistence,
    PostgresRetryPolicy,
    PostgresSourceDirection,
    ReadContextState,
)
from forensic_data.postgres_sql import (
    PostgresFieldBinding,
    PostgresPhysicalField,
    PostgresTypeIdentity,
)
from forensic_data.reporting import (
    DIFF_PAGE_LIMIT_MAX,
    HISTORY_PAGE_LIMIT_MAX,
    ComparisonContext,
    ComparisonDirection,
    ComparisonField,
    ComparisonScopeValue,
    ComparisonSideIdentity,
    DetailAvailability,
    DiffCursor,
    DifferenceKind,
    DifferenceRecord,
    DiffPage,
    EvidenceFieldValue,
    EvidenceValueAvailability,
    HistoryAttemptStatus,
    HistoryCursor,
    HistoryEntry,
    HistoryPage,
    KeyAvailability,
    RelationComparisonLocator,
    SqlComparisonLocator,
    StoredResultAvailability,
    canonical_difference_key_bytes,
    canonical_difference_record_bytes,
)
from forensic_data.result import (
    ComparisonCoverage,
    ComparisonTotals,
    ConsistencyLevel,
    ConsistencyStatus,
    EvidenceCoverage,
    ExactTotal,
    ExecutionStatus,
    Guarantee,
    InferredTotal,
    LowerBoundTotal,
    PersistenceState,
    PersistenceStatus,
    ReasonCode,
    ResultMetrics,
    ResultReason,
    RunResult,
    Total,
    UnavailableTotal,
    Verdict,
)

__all__ = (
    "AlignedInputCutPersistence",
    "AttemptOutcomeRecord",
    "AttemptStatus",
    "ClaimedRun",
    "ComparisonSegmentState",
    "CompletedComparisonDefinition",
    "CompletedStructuralComparisonDefinition",
    "IntegerRangeFingerprintPersistence",
    "PartialComparisonDefinition",
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
    "completed_structural_comparison_persistence_from_artifact",
    "mark_postgres_read_context_lost",
    "partial_comparison_persistence_from_artifact",
    "persist_postgres_aligned_input_cut",
    "persist_postgres_read_context",
    "publish_postgres_completed_comparison",
    "publish_postgres_completed_structural_comparison",
    "publish_postgres_terminal_error_attempt",
    "publish_postgres_terminal_error_comparison",
    "publish_postgres_terminal_incomplete_attempt",
    "publish_postgres_terminal_incomplete_comparison",
    "read_postgres_completed_comparison",
    "read_postgres_diff",
    "read_postgres_history",
    "read_postgres_partial_comparison",
    "read_postgres_terminal_attempt",
    "record_postgres_retryable_error_attempt",
    "record_postgres_retryable_error_comparison",
    "record_postgres_retryable_incomplete_attempt",
    "record_postgres_retryable_incomplete_comparison",
    "renew_postgres_run_attempt",
    "start_postgres_run_attempt",
)

LOGGER = logging.getLogger(__name__)

_WRITER_ROLE: Final[str] = "dfe_metadata_writer"
_READER_ROLE: Final[str] = "dfe_metadata_reader"
_CANONICAL_PROTOCOL: Final[str] = "dfe_canon_v1"
_FINGERPRINT_PROTOCOL: Final[str] = "sha256_sum32_v1"
type _ProtectedReadContext = (
    PostgresProtectedReadContext
    | MssqlProtectedReadContext
    | GreengageProtectedReadContext
    | OriginalGreenplumProtectedReadContext
)
type _ProtectedRelationInspection = (
    PostgresProtectedRelationInspection
    | MssqlInspectedRelation
    | GreengageProtectedRelationInspection
    | OriginalGreenplumProtectedRelationInspection
)
_STRUCTURAL_SUMMARY_PARAMETER_NAMES: Final[tuple[str, ...]] = (
    "reference_row_count",
    "reference_null_key_count",
    "reference_invalid_key_count",
    "reference_valid_key_count",
    "reference_distinct_key_count",
    "target_row_count",
    "target_null_key_count",
    "target_invalid_key_count",
    "target_valid_key_count",
    "target_distinct_key_count",
)


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
class PartialComparisonDefinition:
    check_id: str
    contract_digest: str
    scope_digest: str
    input_cut_digest: str
    execution_status: ExecutionStatus
    verdict: Verdict
    consistency: ConsistencyStatus
    guarantee: Guarantee
    comparison_coverage: ComparisonCoverage
    totals: ComparisonTotals
    evidence_coverage: EvidenceCoverage
    metrics: ResultMetrics
    primary_reason: ResultReason
    additional_reasons: tuple[ResultReason, ...]
    frontier: PartialComparisonFrontier
    reference_observation_id: UUID
    target_observation_id: UUID
    anomalies: tuple[DifferenceRecord, ...]

    def __post_init__(self) -> None:
        _require_nonblank_text(self.check_id, "partial comparison check id")
        _require_sha256(self.contract_digest, "partial comparison contract digest")
        _require_sha256(self.scope_digest, "partial comparison scope digest")
        _require_sha256(self.input_cut_digest, "partial comparison input cut digest")
        _require_instance(
            self.execution_status,
            ExecutionStatus,
            "partial comparison execution status",
        )
        if self.execution_status is ExecutionStatus.COMPLETED:
            raise ValueError("partial comparison execution status cannot be completed")
        _require_instance(self.verdict, Verdict, "partial comparison verdict")
        _require_instance(self.consistency, ConsistencyStatus, "partial comparison consistency")
        _require_instance(self.guarantee, Guarantee, "partial comparison guarantee")
        if self.guarantee is not Guarantee.NOT_ESTABLISHED:
            raise ValueError("partial comparison requires not_established guarantee")
        _require_instance(
            self.comparison_coverage,
            ComparisonCoverage,
            "partial comparison coverage",
        )
        _require_instance(self.totals, ComparisonTotals, "partial comparison totals")
        _require_instance(
            self.evidence_coverage,
            EvidenceCoverage,
            "partial comparison evidence coverage",
        )
        _require_instance(self.metrics, ResultMetrics, "partial comparison metrics")
        _require_instance(self.primary_reason, ResultReason, "partial comparison primary reason")
        if type(self.additional_reasons) is not tuple:
            raise TypeError("partial comparison additional reasons must be an immutable tuple")
        for reason in self.additional_reasons:
            _require_instance(reason, ResultReason, "partial comparison additional reason")
        _require_instance(self.frontier, PartialComparisonFrontier, "partial comparison frontier")
        _require_uuid(self.reference_observation_id, "partial reference observation id")
        _require_uuid(self.target_observation_id, "partial target observation id")
        if self.reference_observation_id == self.target_observation_id:
            raise ValueError("partial comparison observations must be distinct")
        if type(self.anomalies) is not tuple:
            raise TypeError("partial comparison anomalies must be an immutable tuple")
        for anomaly in self.anomalies:
            _require_instance(anomaly, DifferenceRecord, "partial comparison anomaly")

    @property
    def reasons(self) -> tuple[ResultReason, ...]:
        return (self.primary_reason, *self.additional_reasons)


@final
@dataclass(frozen=True, slots=True)
class CompletedStructuralComparisonDefinition:
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
            raise ValueError("completed structural comparison check id must be nonblank")
        _require_sha256(self.contract_digest, "completed structural contract digest")
        _require_sha256(self.scope_digest, "completed structural scope digest")
        _require_instance(
            self.consistency,
            ConsistencyStatus,
            "completed structural consistency",
        )
        _require_instance(
            self.comparison_coverage,
            ComparisonCoverage,
            "completed structural coverage",
        )
        _require_instance(self.totals, ComparisonTotals, "completed structural totals")
        _require_instance(
            self.evidence_coverage,
            EvidenceCoverage,
            "completed structural evidence coverage",
        )
        _require_instance(self.metrics, ResultMetrics, "completed structural metrics")
        if type(self.reasons) is not tuple:
            raise TypeError("completed structural reasons must be an immutable tuple")
        for reason in self.reasons:
            _require_instance(reason, ResultReason, "completed structural reason")
        _validate_completed_structural_definition(self)


type _CompletedResultDefinition = (
    CompletedComparisonDefinition | CompletedStructuralComparisonDefinition
)


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
    protected_context: _ProtectedReadContext

    def __post_init__(self) -> None:
        _require_uuid(self.acquisition_operation_id, "context acquisition operation id")
        _require_instance(self.dataset, DatasetVersionRecord, "context dataset")
        _require_instance(self.direction, PlanDirection, "context direction")
        context = _require_supported_read_context(
            self.protected_context,
            "protected read context",
        )
        _require_context_direction(context, self.direction, "protected read context")
        if isinstance(context, PostgresProtectedReadContext):
            evidence = context.evidence
            if _protected_context_lock_closure(context) != evidence.locked_relation_oids:
                raise ValueError(
                    "protected context relations must exactly match its locked relation evidence"
                )
            if context.state is not ReadContextState.ACTIVE:
                raise ValueError("only an active protected context can be persisted")
        elif isinstance(context, GreengageProtectedReadContext):
            _greengage_context_relations(context)
            if context.state is not ReadContextState.ACTIVE:
                raise ValueError("only an active protected context can be persisted")
        elif isinstance(context, OriginalGreenplumProtectedReadContext):
            _original_greenplum_context_relations(context)
            if context.state is not ReadContextState.ACTIVE:
                raise ValueError("only an active protected context can be persisted")
        else:
            _mssql_context_relations(context)
            if context.state is not MssqlReadContextState.ACTIVE:
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
    protected_context: _ProtectedReadContext
    dataset_relation: _ProtectedRelationInspection
    readiness_relation: _ProtectedRelationInspection
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
        context = _require_supported_read_context(
            self.protected_context,
            "observation protected context",
        )
        _require_context_direction(context, self.direction, "observation protected context")
        dataset_relation = _require_context_relation(
            context,
            self.dataset_relation,
            "observation dataset relation",
        )
        readiness_relation = _require_context_relation(
            context,
            self.readiness_relation,
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
        if _relation_context_id(dataset_relation) != _relation_context_id(readiness_relation):
            raise ValueError(
                "observation dataset and readiness relations must share one protected context"
            )
        if context.evidence.context_id != _relation_context_id(dataset_relation):
            raise ValueError("observation relations must belong to its protected context")
        protected_relations = _context_relations(context)
        if not _context_is_active(context):
            raise ValueError("observation protected context must still be active")
        if not any(item is dataset_relation for item in protected_relations) or not any(
            item is readiness_relation for item in protected_relations
        ):
            raise ValueError(
                "observation relations must be the exact sealed protected-context objects"
            )
        if _relation_physical_identity(dataset_relation) == _relation_physical_identity(
            readiness_relation
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
class _ContextStorageIdentity:
    driver_version: str
    server_version: str
    server_version_number: int
    backend_process_id: int | None


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
    comparison: _CompletedResultDefinition
    segments: tuple[IntegerRangeFingerprintPersistence, ...]
    anomalies: tuple["_AnomalyExpectation", ...]
    evidence_manifest_digest: bytes
    ended_at: datetime
    result: RunResult
    result_json: str
    result_digest: bytes


@final
@dataclass(frozen=True, slots=True)
class _AnomalyExpectation:
    record: DifferenceRecord
    payload_json: str
    payload_digest: bytes
    payload_byte_length: int
    record_digest: bytes


@final
@dataclass(frozen=True, slots=True)
class _AnomalyManifestSummary:
    retained_records: int
    retained_bytes: int
    manifest_digest: bytes | None


@final
@dataclass(frozen=True, slots=True)
class _ComparisonEvidenceBoundary:
    context: ComparisonContext
    actions: tuple[EvidenceAction, ...]


@final
@dataclass(frozen=True, slots=True)
class _PartialComparisonExpectation:
    attempt: RunAttemptRecord
    operation_id: UUID
    comparison: PartialComparisonDefinition
    ended_at: datetime
    result: RunResult
    result_json: str
    result_digest: bytes
    frontier_json: str
    frontier_digest: bytes
    anomalies: tuple[_AnomalyExpectation, ...]
    evidence_manifest_digest: bytes


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
    tuple[DifferenceRecord, ...],
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
    _validate_anomaly_coverage(definition.evidence_coverage, artifact.anomalies)
    _validate_completed_anomaly_segments(artifact.anomalies, segments)
    return definition, segments, artifact.anomalies


def partial_comparison_persistence_from_artifact(
    attempt: RunAttemptRecord,
    persisted_cut: PersistedInputCut,
    artifact: PartialComparisonArtifact,
    execution_status: ExecutionStatus,
    primary_reason: ResultReason,
    additional_reasons: tuple[ResultReason, ...],
) -> PartialComparisonDefinition:
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_instance(persisted_cut, PersistedInputCut, "persisted input cut")
    _require_instance(artifact, PartialComparisonArtifact, "partial comparison artifact")
    _require_instance(execution_status, ExecutionStatus, "partial comparison execution status")
    _require_instance(primary_reason, ResultReason, "partial comparison primary reason")
    if type(additional_reasons) is not tuple:
        raise TypeError("partial comparison additional reasons must be an immutable tuple")
    if persisted_cut.run_id != attempt.run.run_id or persisted_cut.attempt_id != attempt.attempt_id:
        raise ValueError("persisted input cut must belong to the partial comparison attempt")
    input_cut_digest = persisted_cut.input_cut.input_cut_digest
    if artifact.input_cut_digest != input_cut_digest:
        raise ValueError("partial comparison artifact cut differs from the persisted attempt cut")
    for bound_digest in (attempt.run.bound_input_cut_digest, attempt.input_cut_digest):
        if bound_digest is not None and bound_digest != input_cut_digest:
            raise ValueError("partial comparison attempt is bound to a different input cut")
    if artifact.scope_digest != persisted_cut.input_cut.reference.scope_digest:
        raise ValueError("partial comparison artifact scope differs from its persisted cut")
    if artifact.reference_full_scans > attempt.execution_budgets.max_full_scans_per_side:
        raise ValueError("partial reference full scans exceed the immutable attempt budget")
    if artifact.target_full_scans > attempt.execution_budgets.max_full_scans_per_side:
        raise ValueError("partial target full scans exceed the immutable attempt budget")
    reference_observation_id, target_observation_id = persisted_cut.observation_ids
    definition = PartialComparisonDefinition(
        check_id=artifact.check_id,
        contract_digest=artifact.contract_digest,
        scope_digest=artifact.scope_digest,
        input_cut_digest=artifact.input_cut_digest,
        execution_status=execution_status,
        verdict=artifact.verdict,
        consistency=artifact.consistency,
        guarantee=artifact.guarantee,
        comparison_coverage=artifact.comparison_coverage,
        totals=artifact.totals,
        evidence_coverage=artifact.evidence_coverage,
        metrics=artifact.metrics,
        primary_reason=primary_reason,
        additional_reasons=additional_reasons,
        frontier=artifact.frontier,
        reference_observation_id=reference_observation_id,
        target_observation_id=target_observation_id,
        anomalies=artifact.anomalies,
    )
    _validate_partial_definition(attempt.execution_budgets, definition)
    return definition


def completed_structural_comparison_persistence_from_artifact(
    attempt: RunAttemptRecord,
    persisted_cut: PersistedInputCut,
    artifact: CompletedStructuralComparisonArtifact,
) -> CompletedStructuralComparisonDefinition:
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_instance(persisted_cut, PersistedInputCut, "persisted input cut")
    _require_instance(
        artifact,
        CompletedStructuralComparisonArtifact,
        "completed structural comparison artifact",
    )
    if persisted_cut.run_id != attempt.run.run_id or persisted_cut.attempt_id != attempt.attempt_id:
        raise ValueError("persisted input cut must belong to the structural comparison attempt")
    input_cut_digest = persisted_cut.input_cut.input_cut_digest
    if artifact.input_cut_digest != input_cut_digest:
        raise ValueError("structural comparison artifact differs from the persisted attempt cut")
    for bound_digest in (
        attempt.run.bound_input_cut_digest,
        attempt.input_cut_digest,
    ):
        if bound_digest is not None and bound_digest != input_cut_digest:
            raise ValueError("structural comparison attempt is bound to a different input cut")
    if artifact.scope_digest != persisted_cut.input_cut.reference.scope_digest:
        raise ValueError("structural comparison artifact scope differs from its persisted cut")
    if artifact.reference_full_scans > attempt.execution_budgets.max_full_scans_per_side:
        raise ValueError("reference full scans exceed the immutable attempt budget")
    if artifact.target_full_scans > attempt.execution_budgets.max_full_scans_per_side:
        raise ValueError("target full scans exceed the immutable attempt budget")
    definition = CompletedStructuralComparisonDefinition(
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
    _validate_completed_segments(definition, ())
    _validate_completed_budget_use(attempt.execution_budgets, definition, ())
    _validate_structural_artifact_summary_closure(artifact)
    return definition


def publish_postgres_completed_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    terminal_operation_id: UUID,
    comparison: CompletedComparisonDefinition,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
    anomalies: tuple[DifferenceRecord, ...],
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
        anomalies,
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


def publish_postgres_completed_structural_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    terminal_operation_id: UUID,
    comparison: CompletedStructuralComparisonDefinition,
    ended_at: datetime,
) -> RunResult:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_uuid(terminal_operation_id, "completed structural operation id")
    _require_instance(
        comparison,
        CompletedStructuralComparisonDefinition,
        "completed structural comparison definition",
    )
    _require_utc_datetime(ended_at, "completed structural comparison ended_at")
    expected = _completed_comparison_expectation(
        attempt,
        terminal_operation_id,
        comparison,
        (),
        (),
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "publish_completed_structural_comparison",
        (expected.operation_id,),
        lambda connection: _publish_completed_comparison_once(connection, settings, expected),
        lambda connection: _lookup_completed_comparison(connection, settings, expected),
    )


def record_postgres_retryable_incomplete_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    operation_id: UUID,
    comparison: PartialComparisonDefinition,
    ended_at: datetime,
) -> RunResult:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    expected = _partial_comparison_expectation(
        attempt,
        operation_id,
        comparison,
        ExecutionStatus.INCOMPLETE,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "record_retryable_incomplete_comparison",
        (expected.operation_id,),
        lambda connection: _record_retryable_partial_comparison_once(
            connection,
            settings,
            expected,
        ),
        lambda connection: _lookup_retryable_partial_comparison(
            connection,
            settings,
            expected,
        ),
    )


def record_postgres_retryable_error_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    operation_id: UUID,
    comparison: PartialComparisonDefinition,
    ended_at: datetime,
) -> RunResult:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    expected = _partial_comparison_expectation(
        attempt,
        operation_id,
        comparison,
        ExecutionStatus.ERROR,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "record_retryable_error_comparison",
        (expected.operation_id,),
        lambda connection: _record_retryable_partial_comparison_once(
            connection,
            settings,
            expected,
        ),
        lambda connection: _lookup_retryable_partial_comparison(
            connection,
            settings,
            expected,
        ),
    )


def publish_postgres_terminal_incomplete_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    operation_id: UUID,
    comparison: PartialComparisonDefinition,
    ended_at: datetime,
) -> RunResult:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    expected = _partial_comparison_expectation(
        attempt,
        operation_id,
        comparison,
        ExecutionStatus.INCOMPLETE,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "publish_terminal_incomplete_comparison",
        (expected.operation_id,),
        lambda connection: _publish_terminal_partial_comparison_once(
            connection,
            settings,
            expected,
        ),
        lambda connection: _lookup_terminal_partial_comparison(
            connection,
            settings,
            expected,
        ),
    )


def publish_postgres_terminal_error_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    attempt: RunAttemptRecord,
    operation_id: UUID,
    comparison: PartialComparisonDefinition,
    ended_at: datetime,
) -> RunResult:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    expected = _partial_comparison_expectation(
        attempt,
        operation_id,
        comparison,
        ExecutionStatus.ERROR,
        ended_at,
    )
    return _run_with_reconciliation(
        settings,
        retry_policy,
        "publish_terminal_error_comparison",
        (expected.operation_id,),
        lambda connection: _publish_terminal_partial_comparison_once(
            connection,
            settings,
            expected,
        ),
        lambda connection: _lookup_terminal_partial_comparison(
            connection,
            settings,
            expected,
        ),
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


def read_postgres_partial_comparison(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    run_id: UUID,
    attempt_id: UUID,
) -> RunResult:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_uuid(run_id, "partial comparison run id")
    _require_uuid(attempt_id, "partial comparison attempt id")
    return _run_read_with_retries(
        settings,
        retry_policy,
        "read_partial_comparison",
        lambda connection: _read_partial_comparison_once(
            connection,
            settings,
            run_id,
            attempt_id,
        ),
    )


def read_postgres_diff(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    run_id: UUID,
    attempt_id: UUID,
    limit: int,
    cursor: DiffCursor | None,
) -> DiffPage:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_uuid(run_id, "diff run id")
    _require_uuid(attempt_id, "diff attempt id")
    _require_positive_integer(limit, "diff page limit")
    if limit > DIFF_PAGE_LIMIT_MAX:
        raise ValueError(f"diff page limit cannot exceed {DIFF_PAGE_LIMIT_MAX}")
    if cursor is not None:
        _require_instance(cursor, DiffCursor, "diff cursor")
        if cursor.run_id != run_id or cursor.attempt_id != attempt_id:
            raise ValueError("diff cursor belongs to a different run or attempt")
    return _run_read_with_retries(
        settings,
        retry_policy,
        "read_diff",
        lambda connection: _read_postgres_diff_once(
            connection,
            settings,
            run_id,
            attempt_id,
            limit,
            cursor,
        ),
    )


def read_postgres_history(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    check_id: str,
    scope_digest: str,
    limit: int,
    cursor: HistoryCursor | None,
) -> HistoryPage:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_nonblank_text(check_id, "history check id")
    _require_sha256(scope_digest, "history scope digest")
    _require_positive_integer(limit, "history page limit")
    if limit > HISTORY_PAGE_LIMIT_MAX:
        raise ValueError(f"history page limit cannot exceed {HISTORY_PAGE_LIMIT_MAX}")
    if cursor is not None:
        _require_instance(cursor, HistoryCursor, "history cursor")
        if cursor.check_id != check_id or cursor.scope_digest != scope_digest:
            raise ValueError("history cursor belongs to a different check or scope")
    return _run_read_with_retries(
        settings,
        retry_policy,
        "read_history",
        lambda connection: _read_postgres_history_once(
            connection,
            settings,
            check_id,
            scope_digest,
            limit,
            cursor,
        ),
    )


def read_postgres_terminal_attempt(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    run_id: UUID,
    attempt_id: UUID,
) -> AttemptOutcomeRecord:
    _require_instance(settings, PostgresConnectionSettings, "metadata connection settings")
    _require_instance(retry_policy, PostgresRetryPolicy, "metadata retry policy")
    _require_uuid(run_id, "terminal attempt run id")
    _require_uuid(attempt_id, "terminal attempt id")
    return _run_read_with_retries(
        settings,
        retry_policy,
        "read_terminal_attempt",
        lambda connection: _read_postgres_terminal_attempt_once(
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
        "SELECT attempt_id, status, owner_token FROM dfe_metadata.run_attempts "
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
    if any(
        _row_uuid(row[2], "attempt invocation owner token") != expected.owner_token
        for row in attempt_rows
    ):
        raise RunInvocationContinuationError(
            "run has prior attempts admitted by a different process invocation and cannot "
            "safely reset whole-run source budgets: "
            f"run_id={expected.run.run_id}; inspect durable history and use a new request UUID"
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
    storage_identity = _context_storage_identity(expected.definition.protected_context)
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
            _context_engine(expected.definition.protected_context),
            storage_identity.driver_version,
            storage_identity.server_version,
            storage_identity.server_version_number,
            evidence.strategy,
            evidence.snapshot_locator,
            storage_identity.backend_process_id,
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
    context_id = _relation_context_id(definition.dataset_relation)
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
    if _select_partial_result_by_operation(connection, expected.operation_id) is not None:
        raise LifecycleOperationConflictError(
            "completed comparison operation UUID is already bound to a partial result"
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
    comparison_boundary = _comparison_evidence_boundary_from_database(
        connection,
        expected.result,
    )
    _validate_anomaly_evidence_boundary(
        tuple(anomaly.record for anomaly in expected.anomalies),
        comparison_boundary,
    )
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
        "result_payload, completed_at, evidence_manifest_digest) VALUES ("
        "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)",
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
            expected.evidence_manifest_digest,
        ),
    )
    if expected.anomalies:
        reference_observation_id = expected.segments[0].reference_observation_id
        target_observation_id = expected.segments[0].target_observation_id
        for anomaly in expected.anomalies:
            _insert_anomaly(
                connection,
                expected.attempt.run.run_id,
                expected.attempt.attempt_id,
                expected.comparison.check_id,
                expected.operation_id,
                reference_observation_id,
                target_observation_id,
                anomaly,
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


def _record_retryable_partial_comparison_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _PartialComparisonExpectation,
) -> RunResult:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, (expected.operation_id,))
    run_row = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise RunLifecycleStateError("cannot record a partial comparison for an unknown run")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.attempt.run))
    attempt_row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    if (
        attempt_row is None
        or _row_uuid(attempt_row[1], "partial comparison attempt run id")
        != expected.attempt.run.run_id
    ):
        raise AttemptFenceError("partial comparison attempt fence is unknown")
    if _select_partial_result_by_operation(connection, expected.operation_id) is not None:
        result = _partial_result_from_database(connection, expected)
        _require_retryable_partial_selection(connection, result)
        return _commit_result(connection, result)
    _require_new_partial_operation(connection, expected.operation_id)
    _require_attempt_fence_row(connection, attempt_row, expected.attempt)
    pre_mutation_lease_expiry = _row_datetime(
        attempt_row[9],
        "retryable partial comparison attempt lease expiry",
    )
    if _row_optional_uuid(run_row[10], "selected terminal attempt id") is not None:
        raise RunLifecycleStateError("run already has a selected terminal attempt")
    _require_locked_partial_comparison_closure(connection, expected)
    _finish_partial_attempt(connection, expected)
    _insert_partial_result(connection, expected)
    _insert_partial_anomalies(connection, expected)
    result = _partial_result_from_database(connection, expected)
    _require_retryable_partial_selection(connection, result)
    return _commit_fenced_result(
        connection,
        result,
        pre_mutation_lease_expiry,
        "retryable partial comparison publication",
    )


def _publish_terminal_partial_comparison_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _PartialComparisonExpectation,
) -> RunResult:
    _begin_writer_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    _lock_operation_identities(connection, (expected.operation_id,))
    run_row = _lock_run_by_id(connection, expected.attempt.run.run_id)
    if run_row is None:
        raise RunLifecycleStateError("cannot publish a partial comparison for an unknown run")
    _claimed_run_from_row(run_row, _expectation_for_claimed_run(expected.attempt.run))
    attempt_row = _lock_attempt_by_id(connection, expected.attempt.attempt_id)
    if (
        attempt_row is None
        or _row_uuid(attempt_row[1], "partial comparison attempt run id")
        != expected.attempt.run.run_id
    ):
        raise AttemptFenceError("partial comparison attempt fence is unknown")
    if _select_partial_result_by_operation(connection, expected.operation_id) is not None:
        result = _partial_result_from_database(connection, expected)
        _require_selected_partial_comparison(connection, result, expected.ended_at)
        return _commit_result(connection, result)
    _require_new_partial_operation(connection, expected.operation_id)
    _require_attempt_fence_row(connection, attempt_row, expected.attempt)
    pre_mutation_lease_expiry = _row_datetime(
        attempt_row[9],
        "terminal partial comparison attempt lease expiry",
    )
    if _row_optional_uuid(run_row[10], "selected terminal attempt id") is not None:
        raise RunLifecycleStateError("run already has a selected terminal attempt")
    _require_locked_partial_comparison_closure(connection, expected)
    _finish_partial_attempt(connection, expected)
    _insert_partial_result(connection, expected)
    _insert_partial_anomalies(connection, expected)
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
            "terminal partial comparison run publication compare-and-set did not update"
        )
    result = _partial_result_from_database(connection, expected)
    _require_selected_partial_comparison(connection, result, expected.ended_at)
    return _commit_fenced_result(
        connection,
        result,
        pre_mutation_lease_expiry,
        "terminal partial comparison publication",
    )


def _require_new_partial_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> None:
    if _select_result_by_operation(connection, operation_id) is not None:
        raise LifecycleOperationConflictError(
            "partial comparison operation UUID is already bound to a completed result"
        )
    if _select_attempt_by_end_operation(connection, operation_id) is not None:
        raise LifecycleOperationConflictError(
            "partial comparison operation UUID is already bound to a different outcome"
        )


def _finish_partial_attempt(
    connection: psycopg.Connection[DatabaseRow],
    expected: _PartialComparisonExpectation,
) -> None:
    reason = expected.comparison.primary_reason
    reason_json = canonical_semantic_json(_reason_semantic_value(reason))
    cursor = connection.execute(
        "UPDATE dfe_metadata.run_attempts SET status = %s, end_operation_id = %s, "
        "terminal_reason_code = %s, terminal_reason = %s::jsonb, ended_at = %s "
        "WHERE run_id = %s AND attempt_id = %s AND owner_token = %s "
        "AND lease_revision = %s AND status = 'running' "
        "AND lease_expires_at > pg_catalog.clock_timestamp()",
        (
            expected.comparison.execution_status.value,
            expected.operation_id,
            reason.code.value,
            reason_json,
            expected.ended_at,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            expected.attempt.owner_token,
            expected.attempt.lease_revision,
        ),
    )
    if cursor.rowcount != 1:
        raise AttemptFenceError("partial comparison attempt compare-and-set did not update")


def _insert_partial_result(
    connection: psycopg.Connection[DatabaseRow],
    expected: _PartialComparisonExpectation,
) -> None:
    comparison = expected.comparison
    connection.execute(
        "INSERT INTO dfe_metadata.partial_check_results ("
        "run_id, attempt_id, check_id, end_operation_id, contract_digest, scope_digest, "
        "input_cut_digest, reference_observation_id, reference_direction, "
        "target_observation_id, target_direction, execution_status, verdict, guarantee, "
        "result_digest, result_payload, frontier_digest, frontier_payload, "
        "evidence_manifest_digest, ended_at) VALUES ("
        "%s, %s, %s, %s, %s, %s, %s, %s, 'reference', %s, 'target', %s, %s, %s, "
        "%s, %s::jsonb, %s, %s::jsonb, %s, %s)",
        (
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            comparison.check_id,
            expected.operation_id,
            bytes.fromhex(comparison.contract_digest),
            bytes.fromhex(comparison.scope_digest),
            bytes.fromhex(comparison.input_cut_digest),
            comparison.reference_observation_id,
            comparison.target_observation_id,
            comparison.execution_status.value,
            comparison.verdict.value,
            comparison.guarantee.value,
            expected.result_digest,
            expected.result_json,
            expected.frontier_digest,
            expected.frontier_json,
            expected.evidence_manifest_digest,
            expected.ended_at,
        ),
    )


def _insert_partial_anomalies(
    connection: psycopg.Connection[DatabaseRow],
    expected: _PartialComparisonExpectation,
) -> None:
    comparison = expected.comparison
    for anomaly in expected.anomalies:
        _insert_anomaly(
            connection,
            expected.attempt.run.run_id,
            expected.attempt.attempt_id,
            comparison.check_id,
            expected.operation_id,
            comparison.reference_observation_id,
            comparison.target_observation_id,
            anomaly,
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


def _lookup_retryable_partial_comparison(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _PartialComparisonExpectation,
) -> RunResult | None:
    if _select_partial_result_by_operation(connection, expected.operation_id) is None:
        connection.execute("COMMIT")
        return None
    result = _partial_result_from_database(connection, expected)
    _require_retryable_partial_selection(connection, result)
    return _commit_result(connection, result)


def _lookup_terminal_partial_comparison(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    expected: _PartialComparisonExpectation,
) -> RunResult | None:
    if _select_partial_result_by_operation(connection, expected.operation_id) is None:
        connection.execute("COMMIT")
        return None
    result = _partial_result_from_database(connection, expected)
    _require_selected_partial_comparison(connection, result, expected.ended_at)
    return _commit_result(connection, result)


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
        raise CompletedComparisonNotFoundError(
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
    manifest_digest = _row_optional_bytes(
        rows[0][12],
        "completed result evidence manifest digest",
    )
    observation_ids = _completed_observation_ids(connection, result, segments)
    anomalies = _anomalies_from_database(
        connection,
        result,
        observation_ids,
        manifest_digest,
    )
    comparison_boundary = _comparison_evidence_boundary_from_database(connection, result)
    _validate_anomaly_evidence_boundary(anomalies, comparison_boundary)
    _require_completed_database_closure(
        connection,
        result,
        segments,
        completed_at,
    )
    _require_completed_terminal_receipt(connection, result, completed_at)
    return _commit_result(connection, result)


def _read_partial_comparison_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> RunResult:
    _begin_reader_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    completed_rows = _select_results_by_attempt(connection, run_id, attempt_id)
    partial_rows = _select_partial_results_by_attempt(connection, run_id, attempt_id)
    if not partial_rows:
        raise PartialComparisonNotFoundError(
            "partial comparison does not exist for the requested run and attempt"
        )
    if len(partial_rows) != 1 or completed_rows:
        raise StoredLifecycleIntegrityError(
            "partial attempt must contain exactly one partial parent and no completed parent"
        )
    result, ended_at, frontier, input_cut_digest, observation_ids, manifest_digest = (
        _partial_result_from_row(partial_rows[0])
    )
    if result.run_id != run_id or result.attempt_id != attempt_id:
        raise StoredLifecycleIntegrityError(
            "partial result payload identity differs from its lookup key"
        )
    anomalies = _anomalies_from_database(
        connection,
        result,
        observation_ids,
        manifest_digest,
    )
    _require_valid_stored_partial(result, frontier, observation_ids, anomalies)
    _validate_anomaly_evidence_boundary(
        anomalies,
        _comparison_evidence_boundary_from_database(connection, result),
    )
    _require_partial_database_closure(
        connection,
        result,
        frontier,
        input_cut_digest,
        observation_ids,
        ended_at,
    )
    _require_partial_terminal_receipt(connection, result, ended_at)
    return _commit_result(connection, result)


def _read_postgres_diff_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    run_id: UUID,
    attempt_id: UUID,
    limit: int,
    cursor: DiffCursor | None,
) -> DiffPage:
    _begin_reader_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    completed_rows = _select_results_by_attempt(connection, run_id, attempt_id)
    partial_rows = _select_partial_results_by_attempt(connection, run_id, attempt_id)
    if len(completed_rows) + len(partial_rows) == 0:
        raise CompletedComparisonNotFoundError(
            "comparison result does not exist for the requested run and attempt"
        )
    if len(completed_rows) + len(partial_rows) != 1:
        raise StoredLifecycleIntegrityError(
            "diff identity requires exactly one completed or partial result parent"
        )
    segments: tuple[IntegerRangeFingerprintPersistence, ...] | None = None
    frontier: PartialComparisonFrontier | None = None
    input_cut_digest: str | None = None
    if completed_rows:
        result, ended_at = _completed_result_from_row(completed_rows[0])
        segments = _completed_segments_from_database(connection, run_id, attempt_id)
        observation_ids = _completed_observation_ids(connection, result, segments)
        manifest_digest = _row_optional_bytes(
            completed_rows[0][12],
            "diff completed evidence manifest digest",
        )
    else:
        result, ended_at, frontier, input_cut_digest, observation_ids, manifest_digest = (
            _partial_result_from_row(partial_rows[0])
        )
    if result.run_id != run_id or result.attempt_id != attempt_id:
        raise StoredLifecycleIntegrityError("diff result payload differs from its lookup key")
    _anomaly_manifest_summary_from_database(connection, result, manifest_digest)
    if segments is not None:
        _require_valid_stored_segments(result, segments)
        _require_completed_database_closure(connection, result, segments, ended_at)
        _require_completed_terminal_receipt(connection, result, ended_at)
    elif frontier is not None and input_cut_digest is not None:
        _require_valid_stored_partial_snapshot(result, frontier, observation_ids)
        _require_partial_database_closure(
            connection,
            result,
            frontier,
            input_cut_digest,
            observation_ids,
            ended_at,
        )
        _require_partial_terminal_receipt(connection, result, ended_at)
    else:
        raise AssertionError("validated diff parent has no completed or partial closure")
    operation_id = result.persistence.operation_id
    if operation_id is None:
        raise StoredLifecycleIntegrityError("diff result has no persistence operation id")
    if cursor is not None and (
        cursor.check_id != result.check_id or cursor.result_operation_id != operation_id
    ):
        raise ValueError("diff cursor belongs to a different immutable result")
    comparison_boundary = _comparison_evidence_boundary_from_database(connection, result)
    after_sequence = cursor.sequence if cursor is not None else -1
    page_records = _anomaly_page_from_database(
        connection,
        result,
        observation_ids,
        after_sequence,
        limit + 1,
    )
    if segments is not None:
        _validate_completed_anomaly_segments(page_records, segments)
    elif frontier is not None:
        _validate_partial_anomaly_records(frontier, page_records)
    else:
        raise AssertionError("validated diff parent has no segment topology")
    _validate_anomaly_evidence_boundary(page_records, comparison_boundary)
    details = page_records[:limit]
    next_cursor = None
    if len(page_records) > limit:
        next_cursor = DiffCursor(
            run_id=run_id,
            attempt_id=attempt_id,
            check_id=result.check_id,
            result_operation_id=operation_id,
            sequence=details[-1].sequence,
        )
    coverage = result.evidence_coverage
    if coverage.found_records == coverage.retained_records:
        detail_availability = DetailAvailability.AVAILABLE
    elif coverage.retained_records == 0:
        detail_availability = DetailAvailability.NOT_RETAINED
    else:
        detail_availability = DetailAvailability.PARTIALLY_RETAINED
    try:
        page = DiffPage(
            schema_version=1,
            run_id=run_id,
            attempt_id=attempt_id,
            requested_limit=limit,
            stored_result=result,
            comparison_context=comparison_boundary.context,
            detail_availability=detail_availability,
            found_records=coverage.found_records,
            retained_records=coverage.retained_records,
            details=details,
            next_cursor=next_cursor,
        )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored diff violates the public reporting protocol: reason={error}"
        ) from None
    return _commit_result(connection, page)


def _read_postgres_history_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    check_id: str,
    scope_digest: str,
    limit: int,
    cursor: HistoryCursor | None,
) -> HistoryPage:
    _begin_reader_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    rows = _select_history_rows(
        connection,
        check_id,
        scope_digest,
        limit + 1,
        cursor,
    )
    page_rows = rows[:limit]
    items = tuple(_history_entry_from_row(connection, row) for row in page_rows)
    next_cursor = None
    if len(rows) > limit:
        last = items[-1]
        next_cursor = HistoryCursor(
            check_id=check_id,
            scope_digest=scope_digest,
            started_at=last.started_at,
            run_id=last.run_id,
            attempt_id=last.attempt_id,
        )
    try:
        page = HistoryPage(
            schema_version=1,
            check_id=check_id,
            scope_digest=scope_digest,
            requested_limit=limit,
            items=items,
            next_cursor=next_cursor,
        )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored history violates the public reporting protocol: reason={error}"
        ) from None
    return _commit_result(connection, page)


def _read_postgres_terminal_attempt_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> AttemptOutcomeRecord:
    _begin_reader_transaction(connection, settings.statement_timeout_milliseconds)
    _require_current_schema(connection)
    row = connection.execute(
        _ATTEMPT_SELECT + " WHERE run_id = %s AND attempt_id = %s",
        (run_id, attempt_id),
    ).fetchone()
    if row is None:
        raise RunLifecycleStateError("terminal attempt does not exist for the requested identity")
    outcome = _attempt_outcome_from_stored_row(row, run_id, attempt_id)
    _require_stored_attempt_closure(connection, run_id, attempt_id)
    _require_attempt_anomaly_parent_closure(connection, run_id, attempt_id)
    result_count_row = connection.execute(
        "SELECT "
        "(SELECT pg_catalog.count(*) FROM dfe_metadata.check_results "
        "WHERE run_id = %s AND attempt_id = %s), "
        "(SELECT pg_catalog.count(*) FROM dfe_metadata.partial_check_results "
        "WHERE run_id = %s AND attempt_id = %s)",
        (run_id, attempt_id, run_id, attempt_id),
    ).fetchone()
    if (
        result_count_row is None
        or _row_integer(
            result_count_row[0],
            "terminal attempt completed result count",
        )
        != 0
        or _row_integer(
            result_count_row[1],
            "terminal attempt partial result count",
        )
        != 0
    ):
        raise StoredLifecycleIntegrityError(
            "lifecycle-only terminal read cannot contain a completed or partial result parent"
        )
    _require_terminal_attempt_run_binding(connection, outcome)
    return _commit_result(connection, outcome)


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
        physical_schema_digest=bytes.fromhex(_observation_schema_digest(definition)),
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
    comparison: _CompletedResultDefinition,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
    anomaly_records: tuple[DifferenceRecord, ...],
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
    _validate_anomaly_coverage(comparison.evidence_coverage, anomaly_records)
    _validate_completed_anomaly_segments(anomaly_records, segments)
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
    reference_observation_id = segments[0].reference_observation_id if segments else None
    target_observation_id = segments[0].target_observation_id if segments else None
    anomalies = _anomaly_expectations(
        attempt.run.run_id,
        attempt.attempt_id,
        comparison.check_id,
        operation_id,
        reference_observation_id,
        target_observation_id,
        anomaly_records,
    )
    return _CompletedComparisonExpectation(
        attempt=attempt,
        operation_id=operation_id,
        comparison=comparison,
        segments=segments,
        anomalies=anomalies,
        evidence_manifest_digest=_evidence_manifest_digest(anomalies),
        ended_at=ended_at.astimezone(UTC),
        result=result,
        result_json=result_json,
        result_digest=bytes.fromhex(semantic_digest_hex(result_value)),
    )


def _partial_comparison_expectation(
    attempt: RunAttemptRecord,
    operation_id: UUID,
    comparison: PartialComparisonDefinition,
    expected_status: ExecutionStatus,
    ended_at: datetime,
) -> _PartialComparisonExpectation:
    _require_instance(attempt, RunAttemptRecord, "run attempt")
    _require_uuid(operation_id, "partial comparison operation id")
    _require_instance(comparison, PartialComparisonDefinition, "partial comparison definition")
    _require_instance(expected_status, ExecutionStatus, "expected partial execution status")
    _require_utc_datetime(ended_at, "partial comparison ended_at")
    if attempt.status is not AttemptStatus.RUNNING:
        raise ValueError("partial comparison publication requires a running attempt record")
    if comparison.execution_status is not expected_status:
        raise ValueError("partial comparison execution status differs from the selected publisher")
    if comparison.scope_digest != attempt.run.request.scope.scope_digest:
        raise ValueError("partial comparison scope digest must match the immutable run scope")
    for bound_digest in (
        attempt.input_cut_digest,
        attempt.run.bound_input_cut_digest,
    ):
        if bound_digest is not None and comparison.input_cut_digest != bound_digest:
            raise ValueError("partial comparison differs from an immutable input-cut binding")
    _validate_partial_definition(attempt.execution_budgets, comparison)
    if expected_status is ExecutionStatus.INCOMPLETE:
        _validate_incomplete_reason(comparison.primary_reason)
        attempt_status = AttemptStatus.INCOMPLETE
    elif expected_status is ExecutionStatus.ERROR:
        _validate_error_reason(comparison.primary_reason)
        attempt_status = AttemptStatus.ERROR
    else:
        raise ValueError("partial comparison publisher requires incomplete or error status")
    candidate_result = RunResult(
        schema_version=1,
        run_id=attempt.run.run_id,
        attempt_id=attempt.attempt_id,
        check_id=comparison.check_id,
        contract_digest=comparison.contract_digest,
        scope_digest=comparison.scope_digest,
        execution_status=expected_status,
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
    if attempt_status.value != result.execution_status.value:
        raise AssertionError("partial comparison attempt and result statuses diverged")
    result_value = semantic_value_from_json(result.model_dump_json())
    result_json = canonical_semantic_json(result_value)
    frontier_bytes = canonical_partial_comparison_frontier_bytes(comparison.frontier)
    frontier_json = frontier_bytes.decode("utf-8", errors="strict")
    frontier_value = semantic_value_from_json(frontier_json)
    if canonical_semantic_json(frontier_value) != frontier_json:
        raise ValueError("partial comparison frontier is not canonical semantic JSON")
    anomalies = _anomaly_expectations(
        attempt.run.run_id,
        attempt.attempt_id,
        comparison.check_id,
        operation_id,
        comparison.reference_observation_id,
        comparison.target_observation_id,
        comparison.anomalies,
    )
    return _PartialComparisonExpectation(
        attempt=attempt,
        operation_id=operation_id,
        comparison=comparison,
        ended_at=ended_at.astimezone(UTC),
        result=result,
        result_json=result_json,
        result_digest=bytes.fromhex(semantic_digest_hex(result_value)),
        frontier_json=frontier_json,
        frontier_digest=bytes.fromhex(semantic_digest_hex(frontier_value)),
        anomalies=anomalies,
        evidence_manifest_digest=_evidence_manifest_digest(anomalies),
    )


def _anomaly_expectations(
    run_id: UUID,
    attempt_id: UUID,
    check_id: str,
    operation_id: UUID,
    reference_observation_id: UUID | None,
    target_observation_id: UUID | None,
    records: tuple[DifferenceRecord, ...],
) -> tuple[_AnomalyExpectation, ...]:
    if records and (reference_observation_id is None or target_observation_id is None):
        raise ValueError("retained anomalies require an exact observation pair")
    expectations: list[_AnomalyExpectation] = []
    for record in records:
        payload_bytes = canonical_difference_record_bytes(record)
        payload_json = payload_bytes.decode("utf-8", errors="strict")
        payload_value = semantic_value_from_json(payload_json)
        payload_digest = bytes.fromhex(semantic_digest_hex(payload_value))
        record_value: SemanticValue = {
            "attempt_id": str(attempt_id),
            "check_id": check_id,
            "end_operation_id": str(operation_id),
            "key_digest": record.key_digest,
            "kind": record.kind.value,
            "payload_byte_length": len(payload_bytes),
            "payload_digest": payload_digest.hex(),
            "record_version": 1,
            "reference_direction": PlanDirection.REFERENCE.value,
            "reference_observation_id": (
                str(reference_observation_id) if reference_observation_id is not None else None
            ),
            "run_id": str(run_id),
            "segment_sequence": record.segment_sequence,
            "sequence": record.sequence,
            "target_direction": PlanDirection.TARGET.value,
            "target_observation_id": (
                str(target_observation_id) if target_observation_id is not None else None
            ),
        }
        expectations.append(
            _AnomalyExpectation(
                record=record,
                payload_json=payload_json,
                payload_digest=payload_digest,
                payload_byte_length=len(payload_bytes),
                record_digest=bytes.fromhex(semantic_digest_hex(record_value)),
            )
        )
    return tuple(expectations)


def _evidence_manifest_digest(anomalies: tuple[_AnomalyExpectation, ...]) -> bytes:
    value: SemanticValue = {
        "manifest_version": 1,
        "record_digests": [anomaly.record_digest.hex() for anomaly in anomalies],
    }
    return bytes.fromhex(semantic_digest_hex(value))


def _validate_anomaly_coverage(
    coverage: EvidenceCoverage,
    anomalies: tuple[DifferenceRecord, ...],
) -> None:
    if type(anomalies) is not tuple:
        raise TypeError("comparison anomalies must be an immutable tuple")
    for anomaly in anomalies:
        _require_instance(anomaly, DifferenceRecord, "comparison anomaly")
    if tuple(anomaly.sequence for anomaly in anomalies) != tuple(range(len(anomalies))):
        raise ValueError("retained anomaly sequences must be contiguous from zero in order")
    retained_bytes = sum(len(canonical_difference_record_bytes(item)) for item in anomalies)
    if coverage.retained_records != len(anomalies):
        raise ValueError("retained evidence count differs from the anomaly records")
    if coverage.retained_bytes != retained_bytes:
        raise ValueError("retained evidence bytes differ from canonical anomaly payload bytes")


def _validate_completed_anomaly_segments(
    anomalies: tuple[DifferenceRecord, ...],
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
) -> None:
    if not anomalies:
        return
    by_sequence = {segment.segment_sequence: segment for segment in segments}
    for anomaly in anomalies:
        segment = by_sequence.get(anomaly.segment_sequence)
        if segment is None:
            raise ValueError("retained anomaly references an unknown completed segment")
        if segment.state is not ComparisonSegmentState.EXACT_MISMATCH:
            raise ValueError("retained anomaly must belong to an exact-mismatch segment")


def _validate_partial_definition(
    budgets: ExecutionBudgets,
    comparison: PartialComparisonDefinition,
) -> None:
    _validate_anomaly_coverage(comparison.evidence_coverage, comparison.anomalies)
    _validate_partial_anomaly_segments(comparison)
    _validate_partial_frontier_closure(
        comparison.frontier,
        comparison.metrics,
        comparison.comparison_coverage,
        comparison.totals,
        comparison.verdict,
        comparison.consistency,
        comparison.reasons,
    )
    _validate_partial_budget_use(
        budgets,
        comparison.metrics,
        comparison.evidence_coverage,
        comparison.frontier,
    )


def _validate_partial_budget_use(
    budgets: ExecutionBudgets,
    metrics: ResultMetrics,
    evidence_coverage: EvidenceCoverage,
    frontier: PartialComparisonFrontier,
) -> None:
    for name, actual, maximum in (
        ("queries", metrics.queries, budgets.max_queries),
        (
            "fingerprint_nodes",
            metrics.fingerprint_nodes,
            budgets.max_fingerprint_nodes,
        ),
        (
            "coordinator_peak_bytes",
            metrics.coordinator_peak_bytes,
            budgets.max_coordinator_memory_bytes,
        ),
        (
            "retained_evidence_records",
            evidence_coverage.retained_records,
            budgets.max_evidence_rows,
        ),
        (
            "retained_evidence_bytes",
            evidence_coverage.retained_bytes,
            budgets.max_evidence_bytes,
        ),
    ):
        if actual > maximum:
            raise ValueError(f"partial comparison {name} exceeds its immutable attempt budget")
    nodes = (*frontier.topology, *frontier.unresolved)
    if nodes and max(segment.depth for segment in nodes) > budgets.max_depth:
        raise ValueError("partial comparison segment depth exceeds its attempt budget")


def _validate_partial_frontier_closure(
    frontier: PartialComparisonFrontier,
    metrics: ResultMetrics,
    coverage: ComparisonCoverage,
    totals: ComparisonTotals,
    verdict: Verdict,
    consistency: ConsistencyStatus,
    reasons: tuple[ResultReason, ...],
) -> None:
    if consistency.stable_reads not in (
        ConsistencyLevel.UNKNOWN,
        ConsistencyLevel.VERIFIED,
    ):
        raise ValueError("partial comparison cannot claim asserted stable-read proof")
    if consistency.cut_alignment is not ConsistencyLevel.VERIFIED:
        raise ValueError("partial comparison requires its verified persisted aligned cut")
    topology = frontier.topology
    unresolved = frontier.unresolved
    nodes: tuple[ComparisonSegmentRecord | UnresolvedComparisonSegment, ...] = (
        *topology,
        *unresolved,
    )
    structural_empty_frontier = (
        not nodes
        and coverage.resolved_segments == 1
        and coverage.pruned_segments == 0
        and coverage.exact_segments == 1
        and all(isinstance(total, UnavailableTotal) for total in totals.values())
    )
    if structural_empty_frontier:
        if metrics.fingerprint_nodes != 0:
            raise ValueError("structural partial comparison cannot claim fingerprint nodes")
    elif not nodes:
        raise ValueError("row partial comparison requires a nonempty persisted frontier")
    else:
        _validate_partial_frontier_tree(frontier)
        witnessed = sum(item.reference_fingerprint is not None for item in unresolved)
        minimum_queried = len(topology) + witnessed
        if not minimum_queried <= metrics.fingerprint_nodes <= len(nodes):
            raise ValueError(
                "partial fingerprint_nodes must cover persisted topology and witnesses "
                "without exceeding the allocated frontier"
            )

    pruned = sum(
        item.state.value == ComparisonSegmentState.FINGERPRINT_MATCH.value for item in topology
    )
    exact = sum(
        item.state.value
        in (
            ComparisonSegmentState.EXACT_MATCH.value,
            ComparisonSegmentState.EXACT_MISMATCH.value,
        )
        for item in topology
    )
    if not structural_empty_frontier and (
        coverage.resolved_segments != pruned + exact
        or coverage.pruned_segments != pruned
        or coverage.exact_segments != exact
    ):
        raise ValueError("partial comparison coverage differs from its terminal topology")
    unresolved_reasons = tuple(dict.fromkeys(item.reason for item in unresolved))
    if (
        coverage.total_partitions != 1
        or coverage.covered_partitions
        != (1 if not unresolved and coverage.resolved_segments > 0 else 0)
        or coverage.unresolved_segments != len(unresolved)
        or coverage.unresolved_reasons != unresolved_reasons
    ):
        raise ValueError("partial comparison coverage differs from its unresolved frontier")

    total_values = totals.values()
    if any(isinstance(total, (ExactTotal, InferredTotal)) for total in total_values):
        raise ValueError("partial comparison totals cannot claim exact or inferred precision")
    if any(isinstance(total, LowerBoundTotal) for total in total_values) and exact == 0:
        raise ValueError("partial lower-bound totals require a completed exact segment")
    has_proven_mismatch = any(
        item.reference_fingerprint != item.target_fingerprint for item in topology
    ) or any(item.reference_fingerprint is not None for item in unresolved)
    if any(
        isinstance(total, LowerBoundTotal) and total.value != "0" for total in totals.differences()
    ):
        has_proven_mismatch = True
    reason_codes = {reason.code for reason in reasons}
    contract_reasons = tuple(
        reason for reason in reasons if reason.code is ReasonCode.CONTRACT_VIOLATION
    )
    if len(contract_reasons) > 1:
        raise ValueError("partial comparison cannot contain duplicate contract proofs")
    has_contract_proof = bool(contract_reasons)
    if contract_reasons:
        if consistency.stable_reads is not ConsistencyLevel.VERIFIED:
            raise ValueError("partial contract proof requires verified summary reads")
        if structural_empty_frontier:
            _validate_structural_summary_reason(contract_reasons[0])
        else:
            _validate_partial_contract_summary_reason(contract_reasons[0])
    if (ReasonCode.DATA_MISMATCH in reason_codes) != has_proven_mismatch:
        raise ValueError("partial data_mismatch reason must exactly match persisted row evidence")
    if (verdict is Verdict.MISMATCH) != (has_proven_mismatch or has_contract_proof):
        raise ValueError(
            "partial mismatch verdict requires persisted row evidence or contract-violation proof"
        )
    if structural_empty_frontier and not has_contract_proof:
        raise ValueError("structural partial comparison requires contract-violation proof")


def _validate_partial_frontier_tree(frontier: PartialComparisonFrontier) -> None:
    nodes: tuple[ComparisonSegmentRecord | UnresolvedComparisonSegment, ...] = (
        *frontier.topology,
        *frontier.unresolved,
    )
    by_sequence = {item.segment_sequence: item for item in nodes}
    if tuple(sorted(by_sequence)) != tuple(range(len(nodes))):
        raise ValueError("partial frontier sequences must be contiguous from zero")
    root = by_sequence[0]
    if root.parent_segment_sequence is not None or root.depth != 0:
        raise ValueError("partial frontier root must be the depth-zero segment")
    children_by_parent: dict[
        int,
        list[ComparisonSegmentRecord | UnresolvedComparisonSegment],
    ] = {}
    for sequence in range(1, len(nodes)):
        node = by_sequence[sequence]
        parent_sequence = node.parent_segment_sequence
        if parent_sequence is None or parent_sequence not in by_sequence:
            raise ValueError("non-root partial frontier segment requires a known parent")
        children_by_parent.setdefault(parent_sequence, []).append(node)

    topology_sequences = {item.segment_sequence for item in frontier.topology}
    for segment in frontier.topology:
        children = tuple(children_by_parent.get(segment.segment_sequence, ()))
        if segment.state.value == ComparisonSegmentState.SPLIT.value:
            _validate_partial_split_segment(segment, children)
        elif children:
            raise ValueError("terminal partial topology segment cannot have children")
        if (
            segment.state.value
            in (
                ComparisonSegmentState.FINGERPRINT_MATCH.value,
                ComparisonSegmentState.EXACT_MATCH.value,
            )
            and segment.reference_fingerprint != segment.target_fingerprint
        ):
            raise ValueError("matched partial topology segment requires equal fingerprints")
        if (
            segment.state.value
            in (
                ComparisonSegmentState.SPLIT.value,
                ComparisonSegmentState.EXACT_MISMATCH.value,
            )
            and segment.reference_fingerprint == segment.target_fingerprint
        ):
            raise ValueError("mismatched partial topology segment requires unequal fingerprints")
    for segment in frontier.unresolved:
        if children_by_parent.get(segment.segment_sequence):
            raise ValueError("unresolved partial frontier segment cannot have children")
        parent_sequence = segment.parent_segment_sequence
        if parent_sequence is not None and parent_sequence not in topology_sequences:
            raise ValueError("unresolved partial frontier parent must be persisted topology")


def _validate_partial_split_segment(
    parent: ComparisonSegmentRecord,
    children: tuple[ComparisonSegmentRecord | UnresolvedComparisonSegment, ...],
) -> None:
    if len(children) != 2:
        raise ValueError("split partial topology segment must have exactly two children")
    left, right = sorted(children, key=lambda segment: segment.lower_inclusive)
    if left.depth != parent.depth + 1 or right.depth != parent.depth + 1:
        raise ValueError("split partial topology children must advance depth by one")
    if (
        left.lower_inclusive != parent.lower_inclusive
        or left.upper_exclusive is None
        or right.lower_inclusive != left.upper_exclusive
        or right.upper_exclusive != parent.upper_exclusive
    ):
        raise ValueError("split partial topology children must exactly cover their parent")
    left_fingerprints = _partial_frontier_fingerprints(left)
    right_fingerprints = _partial_frontier_fingerprints(right)
    if left_fingerprints is None or right_fingerprints is None:
        return
    if (
        combine_fingerprints((left_fingerprints[0], right_fingerprints[0]))
        != parent.reference_fingerprint
    ):
        raise ValueError("known reference child fingerprints must combine to their split parent")
    if (
        combine_fingerprints((left_fingerprints[1], right_fingerprints[1]))
        != parent.target_fingerprint
    ):
        raise ValueError("known target child fingerprints must combine to their split parent")


def _partial_frontier_fingerprints(
    segment: ComparisonSegmentRecord | UnresolvedComparisonSegment,
) -> tuple[Fingerprint, Fingerprint] | None:
    if isinstance(segment, ComparisonSegmentRecord):
        return segment.reference_fingerprint, segment.target_fingerprint
    reference = segment.reference_fingerprint
    target = segment.target_fingerprint
    if reference is None or target is None:
        return None
    return reference, target


def _validate_partial_anomaly_segments(comparison: PartialComparisonDefinition) -> None:
    _validate_partial_anomaly_records(comparison.frontier, comparison.anomalies)


def _validate_partial_anomaly_records(
    frontier: PartialComparisonFrontier,
    anomalies: tuple[DifferenceRecord, ...],
) -> None:
    by_sequence = {segment.segment_sequence: segment for segment in frontier.topology}
    for anomaly in anomalies:
        segment = by_sequence.get(anomaly.segment_sequence)
        if segment is None:
            raise ValueError("retained anomaly references an unknown partial segment")
        if segment.state.value != ComparisonSegmentState.EXACT_MISMATCH.value:
            raise ValueError("retained anomaly must belong to an exact-mismatch segment")


def _validate_completed_structural_definition(
    comparison: CompletedStructuralComparisonDefinition,
) -> None:
    if comparison.verdict is not Verdict.MISMATCH:
        raise ValueError("completed structural comparison must have mismatch verdict")
    if comparison.guarantee is not Guarantee.STRUCTURAL:
        raise ValueError("completed structural comparison requires structural guarantee")
    if (
        comparison.consistency.stable_reads is not ConsistencyLevel.VERIFIED
        or comparison.consistency.cut_alignment is not ConsistencyLevel.VERIFIED
        or len(comparison.consistency.read_context_ids) != 2
    ):
        raise ValueError(
            "completed structural comparison requires two verified aligned read contexts"
        )
    coverage = comparison.comparison_coverage
    if (
        coverage.total_partitions != 1
        or coverage.covered_partitions != 1
        or coverage.resolved_segments != 1
        or coverage.pruned_segments != 0
        or coverage.exact_segments != 1
        or coverage.unresolved_segments != 0
        or coverage.unresolved_reasons
    ):
        raise ValueError(
            "completed structural comparison requires one resolved exact logical partition"
        )
    if any(
        not isinstance(total, UnavailableTotal) or total.reason is not ReasonCode.CONTRACT_VIOLATION
        for total in comparison.totals.values()
    ):
        raise ValueError(
            "completed structural comparison requires unavailable contract-violation totals"
        )
    evidence = comparison.evidence_coverage
    if (
        evidence.found_records != 0
        or evidence.retained_records != 0
        or evidence.found_bytes != 0
        or evidence.retained_bytes != 0
    ):
        raise ValueError("completed structural comparison cannot claim row evidence")
    if (
        comparison.metrics.queries < 2
        or comparison.metrics.fetched_records < 2
        or comparison.metrics.fingerprint_nodes != 0
    ):
        raise ValueError("completed structural comparison requires both summary-read receipts")
    if len(comparison.reasons) != 1:
        raise ValueError("completed structural comparison requires one contract reason")
    _validate_structural_summary_reason(comparison.reasons[0])


def _validate_structural_summary_reason(reason: ResultReason) -> None:
    reference, target = _canonical_contract_summary(reason)
    for direction, summary in (("reference", reference), ("target", target)):
        if summary[2] != 0:
            raise ValueError(
                f"completed structural {direction} summary contains invalid mapped keys"
            )
    _require_contract_summary_violation(reference, target)


def _validate_partial_contract_summary_reason(reason: ResultReason) -> None:
    reference, target = _canonical_contract_summary(reason)
    _require_contract_summary_violation(reference, target)


def _canonical_contract_summary(
    reason: ResultReason,
) -> tuple[tuple[int, int, int, int, int], tuple[int, int, int, int, int]]:
    if (
        reason.code is not ReasonCode.CONTRACT_VIOLATION
        or reason.operation != "validate_integer_key_contract"
        or reason.message != "scoped integer-key validation found null or duplicate keys"
        or reason.native_error_code is not None
        or reason.query_id is not None
        or reason.redacted_response is not None
    ):
        raise ValueError("completed structural reason must use the canonical contract summary")
    parameter_names = tuple(parameter.name for parameter in reason.safe_parameters)
    if parameter_names != _STRUCTURAL_SUMMARY_PARAMETER_NAMES:
        raise ValueError(
            "completed structural reason must contain the fixed ordered key-summary parameters"
        )
    values = tuple(
        _canonical_nonnegative_parameter(parameter.value, parameter.name)
        for parameter in reason.safe_parameters
    )
    reference = cast(tuple[int, int, int, int, int], values[:5])
    target = cast(tuple[int, int, int, int, int], values[5:])
    for direction, summary in (("reference", reference), ("target", target)):
        row_count, null_count, invalid_count, valid_count, distinct_count = summary
        if row_count != null_count + invalid_count + valid_count:
            raise ValueError(
                f"completed structural {direction} summary counts do not partition its rows"
            )
        if distinct_count > valid_count:
            raise ValueError(f"completed structural {direction} distinct keys exceed valid keys")
    return reference, target


def _require_contract_summary_violation(
    reference: tuple[int, int, int, int, int],
    target: tuple[int, int, int, int, int],
) -> None:
    reference_violation = reference[1] > 0 or reference[3] != reference[4]
    target_violation = target[1] > 0 or target[3] != target[4]
    if not reference_violation and not target_violation:
        raise ValueError("completed structural summary contains no null or duplicate key")


def _canonical_nonnegative_parameter(value: str, name: str) -> int:
    if value == "0":
        return 0
    if (
        type(value) is not str
        or not value
        or value[0] not in "123456789"
        or any(character not in "0123456789" for character in value[1:])
    ):
        raise ValueError(f"completed structural parameter {name} must be canonical decimal")
    return int(value)


def _validate_completed_segments(
    comparison: _CompletedResultDefinition,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
) -> None:
    if type(segments) is not tuple:
        raise TypeError("completed comparison segments must be an immutable tuple")
    if isinstance(comparison, CompletedStructuralComparisonDefinition):
        if segments:
            raise ValueError("completed structural comparison cannot contain fingerprint rows")
        _validate_completed_structural_definition(comparison)
        return
    if not segments:
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
    comparison: _CompletedResultDefinition,
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
    if segments and max(segment.depth for segment in segments) > budgets.max_depth:
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


def _validate_structural_artifact_summary_closure(
    artifact: CompletedStructuralComparisonArtifact,
) -> None:
    if artifact.reference_full_scans != 1 or artifact.target_full_scans != 1:
        raise ValueError("completed structural artifact requires one summary scan per side")
    if (
        artifact.metrics.queries < 2
        or artifact.metrics.fetched_records < 2
        or artifact.metrics.fingerprint_nodes != 0
    ):
        raise ValueError("completed structural artifact requires both summary-read receipts")
    definition = CompletedStructuralComparisonDefinition(
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
    _validate_completed_structural_definition(definition)


def _validate_context_definition(
    attempt: RunAttemptRecord,
    definition: ReadContextPersistence,
) -> None:
    if attempt.status is not AttemptStatus.RUNNING:
        raise ValueError("new read contexts require a running attempt record")
    context = definition.protected_context
    if isinstance(context, PostgresProtectedReadContext):
        evidence = context.evidence
        if evidence.server_version != context.profile.server_version:
            raise ValueError("read context evidence and server profile versions must match")
        if evidence.engine != "postgresql":
            raise ValueError("initial lifecycle read contexts require engine='postgresql'")
    elif isinstance(context, GreengageProtectedReadContext):
        _validate_greengage_context_definition(context)
    elif isinstance(context, OriginalGreenplumProtectedReadContext):
        _validate_original_greenplum_context_definition(context)
    else:
        evidence = context.evidence
        profile = context.profile
        driver = profile.driver
        if (
            evidence.server_version != profile.product_version
            or profile.product_version != driver.server_version
        ):
            raise ValueError("read context evidence and server profile versions must match")
        if evidence.engine != "mssql":
            raise ValueError("SQL Server lifecycle read contexts require engine='mssql'")
        if evidence.strategy != "transaction_snapshot" or evidence.snapshot_locator is not None:
            raise ValueError(
                "SQL Server lifecycle read context must be a live SNAPSHOT transaction"
            )
        if (
            evidence.session_id != driver.session_id
            or evidence.database_id != profile.database_id
            or evidence.transaction_count != 1
            or evidence.transaction_state != 1
            or evidence.transaction_isolation_level != 5
            or evidence.allowed_concurrency != 1
        ):
            raise ValueError(
                "SQL Server lifecycle read context evidence differs from its proven session"
            )
    if definition.dataset.definition.adapter.value != _context_engine(context):
        raise ValueError("read context engine differs from the registered dataset adapter")
    expected_dataset_id = _expected_batch(attempt.run.request, definition.direction).dataset_id
    if definition.dataset.definition.dataset_id != expected_dataset_id:
        raise ValueError("read context dataset is outside the run request direction closure")


def _validate_greengage_context_definition(
    context: GreengageProtectedReadContext,
) -> None:
    evidence = context.evidence
    server = context.server
    reader = context.reader
    topology = context.topology
    hash_capability = context.hash_capability
    _require_instance(context.driver, GreenplumDriverEvidence, "Greengage driver evidence")
    _require_instance(server, GreenplumServerProfile, "Greengage server profile")
    _require_instance(reader, GreenplumReaderIdentity, "Greengage reader identity")
    _require_instance(topology, GreenplumTopology, "Greengage topology")
    _require_instance(
        hash_capability,
        GreengageHashCapability,
        "Greengage hash capability",
    )
    _require_nonblank_text(reader.user_name, "Greengage reader role name")
    if "\x00" in reader.user_name:
        raise ValueError("Greengage reader role name must not contain U+0000")
    if (
        reader.is_superuser is not False
        or reader.can_create_role is not False
        or reader.can_create_database is not False
        or reader.can_login is not True
        or reader.transaction_read_only is not True
    ):
        raise ValueError(
            "Greengage lifecycle read context requires a non-admin login role in a read-only "
            "transaction"
        )
    if (
        type(hash_capability.function_oid) is not int
        or not 1 <= hash_capability.function_oid <= (1 << 32) - 1
        or hash_capability.schema_name != "pg_catalog"
        or hash_capability.function_name != "sha256"
        or hash_capability.argument_type_oids != (17,)
        or hash_capability.result_type_oid != 17
        or hash_capability.volatility_code != "i"
        or hash_capability.is_strict is not True
        or hash_capability.reader_has_execute is not True
        or hash_capability.reader_has_schema_usage is not True
        or hash_capability.selected_strategy != "pg_catalog_builtin"
    ):
        raise ValueError(
            "Greengage lifecycle read context requires the exact safe immutable strict "
            "pg_catalog.sha256(bytea) capability with reader EXECUTE and schema USAGE"
        )
    if type(topology.segments) is not tuple or not topology.segments:
        raise ValueError("Greengage lifecycle topology must contain segment configuration rows")
    for index, segment in enumerate(topology.segments):
        if type(segment) is not GreenplumSegment:
            raise TypeError(
                "Greengage lifecycle topology must contain exact GreenplumSegment values: "
                f"segment_index={index}"
            )
        if type(segment.content_id) is not int or not -1 <= segment.content_id <= (1 << 63) - 1:
            raise ValueError(
                "Greengage lifecycle topology content ID is outside its exact catalog "
                f"domain: segment_index={index}"
            )
        for code, label in (
            (segment.role, "role"),
            (segment.preferred_role, "preferred role"),
            (segment.status, "status"),
        ):
            if type(code) is not str or len(code) != 1 or "\x00" in code:
                raise ValueError(
                    "Greengage lifecycle topology requires one-character catalog codes: "
                    f"segment_index={index}, code={label!r}"
                )
    if len(set(topology.segments)) != len(topology.segments):
        raise ValueError("Greengage lifecycle topology contains duplicate segment rows")
    active_primaries = tuple(
        segment for segment in topology.segments if segment.role == "p" and segment.status == "u"
    )
    coordinator_rows = tuple(segment for segment in active_primaries if segment.content_id == -1)
    primary_content_ids = tuple(
        sorted(segment.content_id for segment in active_primaries if segment.content_id >= 0)
    )
    if len(coordinator_rows) != 1:
        raise ValueError("Greengage lifecycle topology requires exactly one active coordinator")
    if not primary_content_ids or len(set(primary_content_ids)) != len(primary_content_ids):
        raise ValueError("Greengage lifecycle topology requires distinct active primary contents")
    if (
        type(topology.primary_content_ids) is not tuple
        or topology.primary_content_ids != primary_content_ids
    ):
        raise ValueError(
            "Greengage lifecycle topology active primary contents differ from its segment rows"
        )
    _require_uuid(evidence.context_id, "Greengage read context id")
    _require_utc_datetime(evidence.started_at, "Greengage read context started_at")
    _require_nonblank_text(evidence.snapshot_locator, "Greengage snapshot locator")
    if type(evidence.limitations) is not tuple:
        raise TypeError("Greengage read context limitations must be an immutable tuple")
    for limitation in evidence.limitations:
        _require_nonblank_text(limitation, "Greengage read context limitation")
    if type(evidence.planning_settings) is not tuple:
        raise TypeError("Greengage planning settings must be an immutable tuple")
    for setting in evidence.planning_settings:
        _require_instance(
            setting,
            GreenplumSessionSettingEvidence,
            "Greengage planning setting evidence",
        )
    if type(evidence.relation_locks) is not tuple:
        raise TypeError("Greengage relation locks must be an immutable tuple")
    for lock in evidence.relation_locks:
        _require_instance(
            lock,
            GreenplumRelationLockEvidence,
            "Greengage relation lock evidence",
        )
    if (
        evidence.runtime_profile is not GreenplumRuntimeProfile.GREENGAGE
        or server.runtime_profile is not GreenplumRuntimeProfile.GREENGAGE
    ):
        raise ValueError("Greengage lifecycle read context requires the greengage runtime profile")
    if context.driver.driver_name != "psycopg":
        raise ValueError("Greengage lifecycle read context requires the psycopg driver")
    if context.source_direction is not PostgresSourceDirection.TARGET:
        raise ValueError("Greengage lifecycle read context is supported only as a target")
    if evidence.strategy != "protected_read_only_repeatable_read_distributed":
        raise ValueError(
            "Greengage lifecycle read context requires the protected distributed "
            "Repeatable Read strategy"
        )
    if (
        evidence.snapshot_locator != server.snapshot_locator
        or evidence.backend_process_id != server.backend_process_id
    ):
        raise ValueError(
            "Greengage lifecycle read context evidence differs from its server profile"
        )
    if (
        server.transaction_isolation != "repeatable read"
        or server.transaction_read_only is not True
        or evidence.allowed_concurrency != 1
        or evidence.acquired_before_snapshot is not True
    ):
        raise ValueError(
            "Greengage lifecycle read context must be a protected read-only Repeatable Read "
            "transaction"
        )
    actual_planning = tuple((setting.name, setting.value) for setting in evidence.planning_settings)
    expected_planning = (
        ("optimizer", "off"),
        ("gp_enable_multiphase_agg", "on"),
        ("gp_eager_two_phase_agg", "on"),
    )
    if actual_planning != expected_planning:
        raise ValueError(
            "Greengage lifecycle read context lacks the required distributed planner settings"
        )
    relations = _greengage_context_relations(context)
    expected_locks = tuple(
        sorted(
            (
                relation.catalog.relation_oid,
                relation.catalog.schema_name,
                relation.catalog.relation_name,
                "AccessShareLock",
            )
            for relation in relations
        )
    )
    actual_locks = tuple(
        sorted(
            (
                lock.relation_oid,
                lock.schema_name,
                lock.relation_name,
                lock.lock_mode,
            )
            for lock in evidence.relation_locks
        )
    )
    if actual_locks != expected_locks:
        raise ValueError(
            "Greengage protected context relations must exactly match its retained lock evidence"
        )


def _validate_original_greenplum_context_definition(
    context: OriginalGreenplumProtectedReadContext,
) -> None:
    evidence = context.evidence
    server = context.server
    reader = context.reader
    topology = context.topology
    hash_capability = context.hash_capability
    _require_instance(
        context.driver,
        GreenplumDriverEvidence,
        "original Greenplum driver evidence",
    )
    _require_instance(server, GreenplumServerProfile, "original Greenplum server profile")
    _require_instance(reader, GreenplumReaderIdentity, "original Greenplum reader identity")
    _require_instance(topology, GreenplumTopology, "original Greenplum topology")
    _require_instance(
        hash_capability,
        OriginalGreenplumHashCapability,
        "original Greenplum hash capability",
    )
    _require_nonblank_text(reader.user_name, "original Greenplum reader role name")
    if "\x00" in reader.user_name:
        raise ValueError("original Greenplum reader role name must not contain U+0000")
    if (
        reader.is_superuser is not False
        or reader.can_create_role is not False
        or reader.can_create_database is not False
        or reader.can_login is not True
        or reader.transaction_read_only is not True
    ):
        raise ValueError(
            "original Greenplum lifecycle read context requires a non-admin login role in a "
            "read-only transaction"
        )
    if (
        type(hash_capability.function_oid) is not int
        or not 1 <= hash_capability.function_oid <= (1 << 32) - 1
        or hash_capability.schema_name != "dfe_ext"
        or hash_capability.function_name != "digest"
        or hash_capability.argument_type_oids != (17, 25)
        or hash_capability.result_type_oid != 17
        or hash_capability.volatility_code != "i"
        or hash_capability.is_strict is not True
        or hash_capability.reader_has_execute is not True
        or hash_capability.reader_has_schema_usage is not True
        or hash_capability.selected_strategy != "unpackaged_contrib_sql"
        or hash_capability.canonical_sha256_verified is not True
    ):
        raise ValueError(
            "original Greenplum lifecycle read context requires the exact safe immutable strict "
            "dfe_ext.digest(bytea, text) capability with reader EXECUTE, schema USAGE, and a "
            "protected-snapshot SHA-256 known-answer proof"
        )
    if type(topology.segments) is not tuple or not topology.segments:
        raise ValueError(
            "original Greenplum lifecycle topology must contain segment configuration rows"
        )
    for index, segment in enumerate(topology.segments):
        if type(segment) is not GreenplumSegment:
            raise TypeError(
                "original Greenplum lifecycle topology must contain exact GreenplumSegment "
                f"values: segment_index={index}"
            )
        if type(segment.content_id) is not int or not -1 <= segment.content_id <= (1 << 63) - 1:
            raise ValueError(
                "original Greenplum lifecycle topology content ID is outside its exact catalog "
                f"domain: segment_index={index}"
            )
        for code, label in (
            (segment.role, "role"),
            (segment.preferred_role, "preferred role"),
            (segment.status, "status"),
        ):
            if type(code) is not str or len(code) != 1 or "\x00" in code:
                raise ValueError(
                    "original Greenplum lifecycle topology requires one-character catalog codes: "
                    f"segment_index={index}, code={label!r}"
                )
    if len(set(topology.segments)) != len(topology.segments):
        raise ValueError("original Greenplum lifecycle topology contains duplicate segment rows")
    active_primaries = tuple(
        segment for segment in topology.segments if segment.role == "p" and segment.status == "u"
    )
    coordinator_rows = tuple(segment for segment in active_primaries if segment.content_id == -1)
    primary_content_ids = tuple(
        sorted(segment.content_id for segment in active_primaries if segment.content_id >= 0)
    )
    if len(coordinator_rows) != 1:
        raise ValueError(
            "original Greenplum lifecycle topology requires exactly one active coordinator"
        )
    if not primary_content_ids or len(set(primary_content_ids)) != len(primary_content_ids):
        raise ValueError(
            "original Greenplum lifecycle topology requires distinct active primary contents"
        )
    if (
        type(topology.primary_content_ids) is not tuple
        or topology.primary_content_ids != primary_content_ids
    ):
        raise ValueError(
            "original Greenplum lifecycle topology active primary contents differ from its "
            "segment rows"
        )
    _require_uuid(evidence.context_id, "original Greenplum read context id")
    _require_utc_datetime(evidence.started_at, "original Greenplum read context started_at")
    _require_nonblank_text(evidence.snapshot_locator, "original Greenplum snapshot locator")
    if type(evidence.limitations) is not tuple:
        raise TypeError("original Greenplum read context limitations must be an immutable tuple")
    for limitation in evidence.limitations:
        _require_nonblank_text(limitation, "original Greenplum read context limitation")
    if type(evidence.relation_locks) is not tuple:
        raise TypeError("original Greenplum relation locks must be an immutable tuple")
    for lock in evidence.relation_locks:
        _require_instance(
            lock,
            GreenplumRelationLockEvidence,
            "original Greenplum relation lock evidence",
        )
    if (
        evidence.runtime_profile is not GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
        or server.runtime_profile is not GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
    ):
        raise ValueError(
            "original Greenplum lifecycle read context requires the original_greenplum "
            "runtime profile"
        )
    if context.driver.driver_name != ORIGINAL_GREENPLUM_DRIVER:
        raise ValueError("original Greenplum lifecycle read context requires the psycopg2 driver")
    if context.source_direction is not PostgresSourceDirection.REFERENCE:
        raise ValueError("original Greenplum lifecycle read context is supported only as a source")
    if evidence.strategy != "protected_read_only_serializable_distributed":
        raise ValueError(
            "original Greenplum lifecycle read context requires the protected distributed "
            "Serializable strategy"
        )
    if (
        evidence.snapshot_locator != server.snapshot_locator
        or evidence.backend_process_id != server.backend_process_id
    ):
        raise ValueError(
            "original Greenplum lifecycle read context evidence differs from its server profile"
        )
    if (
        server.transaction_isolation != "serializable"
        or server.transaction_read_only is not True
        or evidence.allowed_concurrency != 1
        or evidence.acquired_before_snapshot is not True
    ):
        raise ValueError(
            "original Greenplum lifecycle read context must be a protected read-only Serializable "
            "transaction"
        )
    relations = _original_greenplum_context_relations(context)
    expected_locks = tuple(
        sorted(
            (
                relation.catalog.relation_oid,
                relation.catalog.schema_name,
                relation.catalog.relation_name,
                "AccessShareLock",
            )
            for relation in relations
        )
    )
    actual_locks = tuple(
        sorted(
            (
                lock.relation_oid,
                lock.schema_name,
                lock.relation_name,
                lock.lock_mode,
            )
            for lock in evidence.relation_locks
        )
    )
    if actual_locks != expected_locks:
        raise ValueError(
            "original Greenplum protected context relations must exactly match its retained "
            "lock evidence"
        )


def _context_storage_identity(context: _ProtectedReadContext) -> _ContextStorageIdentity:
    if isinstance(context, PostgresProtectedReadContext):
        profile = context.profile
        return _ContextStorageIdentity(
            driver_version=profile.driver_version,
            server_version=profile.server_version,
            server_version_number=profile.server_version_number,
            backend_process_id=context.evidence.backend_process_id,
        )
    if isinstance(
        context,
        (GreengageProtectedReadContext, OriginalGreenplumProtectedReadContext),
    ):
        return _ContextStorageIdentity(
            driver_version=context.driver.driver_version,
            server_version=context.server.product_version,
            server_version_number=context.server.compatibility_version_number,
            backend_process_id=context.evidence.backend_process_id,
        )
    profile = context.profile
    return _ContextStorageIdentity(
        driver_version=profile.driver.pyodbc_version,
        server_version=profile.product_version,
        server_version_number=profile.product_major_version,
        backend_process_id=context.evidence.session_id,
    )


def _context_engine(context: _ProtectedReadContext) -> str:
    if isinstance(context, GreengageProtectedReadContext):
        return "greengage"
    if isinstance(context, OriginalGreenplumProtectedReadContext):
        return "greenplum"
    return context.evidence.engine


def _require_supported_read_context(value: object, context: str) -> _ProtectedReadContext:
    if isinstance(
        value,
        (
            PostgresProtectedReadContext,
            MssqlProtectedReadContext,
            GreengageProtectedReadContext,
            OriginalGreenplumProtectedReadContext,
        ),
    ):
        return value
    raise TypeError(f"{context} must be a supported protected read context")


def _require_context_direction(
    context: _ProtectedReadContext,
    direction: PlanDirection,
    label: str,
) -> None:
    expected = PostgresSourceDirection(direction.value)
    if context.source_direction is not expected:
        raise ValueError(
            f"{label} source direction differs from its persistence direction: "
            f"expected={expected.value!r}, actual={context.source_direction.value!r}"
        )


def _require_context_relation(
    context: _ProtectedReadContext,
    value: object,
    label: str,
) -> _ProtectedRelationInspection:
    if isinstance(context, PostgresProtectedReadContext):
        return _require_instance(value, PostgresProtectedRelationInspection, label)
    if isinstance(context, GreengageProtectedReadContext):
        return _require_instance(value, GreengageProtectedRelationInspection, label)
    if isinstance(context, OriginalGreenplumProtectedReadContext):
        return _require_instance(value, OriginalGreenplumProtectedRelationInspection, label)
    return _require_instance(value, MssqlInspectedRelation, label)


def _mssql_context_relations(
    context: MssqlProtectedReadContext,
) -> tuple[MssqlInspectedRelation, ...]:
    relations = context.protected_relations
    if type(relations) is not tuple or not relations:
        raise ValueError("SQL Server protected context must contain inspected relations")
    evidence = context.evidence
    seen_identities: set[tuple[int, int]] = set()
    for index, relation in enumerate(relations):
        if type(relation) is not MssqlInspectedRelation:
            raise TypeError(
                "SQL Server protected context relations must contain "
                f"MssqlInspectedRelation values: relation_index={index}"
            )
        if relation.context_id != evidence.context_id:
            raise ValueError(
                "SQL Server protected relation belongs to a different read context: "
                f"relation_index={index}"
            )
        if relation.database_id != evidence.database_id:
            raise ValueError(
                "SQL Server protected relation belongs to a different database: "
                f"relation_index={index}"
            )
        identity = (relation.database_id, relation.object_id)
        if identity in seen_identities:
            raise ValueError(
                "SQL Server protected context contains a duplicate physical relation: "
                f"database_id={relation.database_id}, object_id={relation.object_id}"
            )
        seen_identities.add(identity)
    return relations


def _greengage_context_relations(
    context: GreengageProtectedReadContext,
) -> tuple[GreengageProtectedRelationInspection, ...]:
    relations = context.protected_relations
    if type(relations) is not tuple or not relations:
        raise ValueError("Greengage protected context must contain inspected relations")
    seen_relation_oids: set[int] = set()
    for index, relation in enumerate(relations):
        if type(relation) is not GreengageProtectedRelationInspection:
            raise TypeError(
                "Greengage protected context relations must contain "
                "GreengageProtectedRelationInspection values: "
                f"relation_index={index}"
            )
        if relation.inspection.context_id != context.evidence.context_id:
            raise ValueError(
                "Greengage protected relation belongs to a different read context: "
                f"relation_index={index}"
            )
        if (
            (relation.catalog.schema_name, relation.catalog.relation_name)
            != relation.acquisition.relation.components
            or relation.catalog.relation_kind != "r"
            or relation.catalog.persistence_code != "p"
            or relation.catalog.row_security_enabled
            or relation.catalog.row_security_forced
            or not relation.catalog.has_distribution_policy
            or relation.catalog.reader_has_select is not True
            or relation.catalog.reader_has_schema_usage is not True
            or relation.catalog.reader_has_insert is not False
            or relation.catalog.reader_has_update is not False
            or relation.catalog.reader_has_delete is not False
            or relation.catalog.reader_has_truncate is not False
            or relation.lock_mode != "access_share"
            or relation.acquired_before_snapshot is not True
        ):
            raise ValueError(
                "Greengage protected relation differs from its physical protected profile: "
                f"relation_index={index}"
            )
        relation_oid = relation.catalog.relation_oid
        if relation_oid in seen_relation_oids:
            raise ValueError(
                "Greengage protected context contains a duplicate physical relation: "
                f"relation_oid={relation_oid}"
            )
        if relation.catalog.distribution_segment_count != len(context.topology.primary_content_ids):
            raise ValueError(
                "Greengage protected relation distribution differs from its retained topology: "
                f"relation_oid={relation_oid}"
            )
        seen_relation_oids.add(relation_oid)
    return relations


def _original_greenplum_context_relations(
    context: OriginalGreenplumProtectedReadContext,
) -> tuple[OriginalGreenplumProtectedRelationInspection, ...]:
    relations = context.protected_relations
    if type(relations) is not tuple or not relations:
        raise ValueError("original Greenplum protected context must contain inspected relations")
    expected_storage_kinds = {
        "h": "heap",
        "a": "append_optimized_row",
        "c": "append_optimized_column",
    }
    seen_relation_oids: set[int] = set()
    for index, relation in enumerate(relations):
        if type(relation) is not OriginalGreenplumProtectedRelationInspection:
            raise TypeError(
                "original Greenplum protected context relations must contain "
                "OriginalGreenplumProtectedRelationInspection values: "
                f"relation_index={index}"
            )
        catalog = relation.catalog
        if relation.inspection.context_id != context.evidence.context_id:
            raise ValueError(
                "original Greenplum protected relation belongs to a different read context: "
                f"relation_index={index}"
            )
        expected_storage_kind = expected_storage_kinds.get(catalog.storage_code)
        if (
            (catalog.schema_name, catalog.relation_name) != relation.acquisition.relation.components
            or catalog.relation_kind != "r"
            or expected_storage_kind is None
            or catalog.storage_kind.value != expected_storage_kind
            or catalog.storage_profile.kind is not catalog.storage_kind
            or not catalog.has_distribution_policy
            or catalog.reader_has_select is not True
            or catalog.reader_has_schema_usage is not True
            or catalog.reader_has_insert is not False
            or catalog.reader_has_update is not False
            or catalog.reader_has_delete is not False
            or catalog.reader_has_truncate is not False
            or relation.lock_mode != "access_share"
            or relation.acquired_before_snapshot is not True
        ):
            raise ValueError(
                "original Greenplum protected relation differs from its physical protected "
                f"profile: relation_index={index}"
            )
        if type(catalog.distribution_attribute_numbers) is not tuple or any(
            type(attribute_number) is not int or attribute_number < 1
            for attribute_number in catalog.distribution_attribute_numbers
        ):
            raise ValueError(
                "original Greenplum protected relation has invalid distribution attributes: "
                f"relation_index={index}"
            )
        if len(set(catalog.distribution_attribute_numbers)) != len(
            catalog.distribution_attribute_numbers
        ):
            raise ValueError(
                "original Greenplum protected relation has duplicate distribution attributes: "
                f"relation_index={index}"
            )
        relation_oid = catalog.relation_oid
        if relation_oid in seen_relation_oids:
            raise ValueError(
                "original Greenplum protected context contains a duplicate physical relation: "
                f"relation_oid={relation_oid}"
            )
        seen_relation_oids.add(relation_oid)
    return relations


def _context_relations(
    context: _ProtectedReadContext,
) -> tuple[_ProtectedRelationInspection, ...]:
    if isinstance(context, PostgresProtectedReadContext):
        return context.protected_relations
    if isinstance(context, GreengageProtectedReadContext):
        return _greengage_context_relations(context)
    if isinstance(context, OriginalGreenplumProtectedReadContext):
        return _original_greenplum_context_relations(context)
    return _mssql_context_relations(context)


def _context_is_active(context: _ProtectedReadContext) -> bool:
    if isinstance(context, PostgresProtectedReadContext):
        return context.state is ReadContextState.ACTIVE
    if isinstance(
        context,
        (GreengageProtectedReadContext, OriginalGreenplumProtectedReadContext),
    ):
        return context.state is ReadContextState.ACTIVE
    return context.state is MssqlReadContextState.ACTIVE


def _relation_context_id(relation: _ProtectedRelationInspection) -> UUID:
    if isinstance(relation, PostgresProtectedRelationInspection):
        return relation.inspection.context_id
    if isinstance(relation, GreengageProtectedRelationInspection):
        return relation.inspection.context_id
    if isinstance(relation, OriginalGreenplumProtectedRelationInspection):
        return relation.inspection.context_id
    return relation.context_id


def _relation_physical_identity(
    relation: _ProtectedRelationInspection,
) -> tuple[str, int, int]:
    if isinstance(relation, PostgresProtectedRelationInspection):
        return ("postgresql", 0, relation.inspection.relation_oid)
    if isinstance(relation, GreengageProtectedRelationInspection):
        return ("greengage", 0, relation.inspection.relation_oid)
    if isinstance(relation, OriginalGreenplumProtectedRelationInspection):
        return ("greenplum", 0, relation.inspection.relation_oid)
    return ("mssql", relation.database_id, relation.object_id)


def _relation_components(relation: _ProtectedRelationInspection) -> tuple[str, str]:
    if isinstance(relation, PostgresProtectedRelationInspection):
        components = relation.acquisition.relation.components
        if len(components) != 2:
            raise ValueError("protected PostgreSQL relation must have schema and relation names")
        return (components[0], components[1])
    if isinstance(relation, GreengageProtectedRelationInspection):
        return relation.acquisition.relation.components
    if isinstance(relation, OriginalGreenplumProtectedRelationInspection):
        return relation.acquisition.relation.components
    return (relation.relation.schema_name, relation.relation.table_name)


def _relation_column_names(relation: _ProtectedRelationInspection) -> tuple[str, ...]:
    if isinstance(relation, PostgresProtectedRelationInspection):
        return relation.acquisition.column_names
    if isinstance(relation, GreengageProtectedRelationInspection):
        return relation.acquisition.column_names
    if isinstance(relation, OriginalGreenplumProtectedRelationInspection):
        return relation.acquisition.column_names
    return tuple(binding.column_name for binding in relation.bindings)


def _observation_schema_digest(
    definition: RelationManifestObservationPersistence,
) -> str:
    relation = definition.dataset_relation
    if isinstance(relation, PostgresProtectedRelationInspection):
        return schema_digest_hex(relation.acquisition.schema)
    if isinstance(relation, GreengageProtectedRelationInspection):
        return schema_digest_hex(relation.acquisition.schema)
    if isinstance(relation, OriginalGreenplumProtectedRelationInspection):
        return schema_digest_hex(relation.acquisition.schema)
    schema = _dataset_canonical_schema(definition.dataset)
    validate_mssql_inspection(schema, relation)
    return schema_digest_hex(schema)


def _dataset_canonical_schema(dataset: DatasetVersionRecord) -> CanonicalSchema:
    resolved = _semantic_object(
        semantic_value_from_json(dataset.definition.resolved_definition_json),
        "dataset resolved definition",
    )
    schema_json = canonical_semantic_json(resolved.get("logical_schema"))
    try:
        schema = schema_from_metadata_json(schema_json)
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored dataset logical schema is invalid: reason={error}"
        ) from None
    if schema_digest_hex(schema) != dataset.definition.logical_schema_digest:
        raise StoredLifecycleIntegrityError(
            "stored dataset logical schema differs from its immutable digest"
        )
    if canonical_schema_json(schema) != schema_json:
        raise StoredLifecycleIntegrityError(
            "stored dataset logical schema contains unsupported fields"
        )
    return schema


def _protected_context_lock_closure(
    context: PostgresProtectedReadContext,
) -> tuple[int, ...]:
    identities_by_oid: dict[
        int,
        tuple[
            tuple[str, ...],
            int,
            int,
            PostgresRelationKind,
            PostgresRelationPersistence,
        ],
    ] = {}
    for protected in context.protected_relations:
        inspection = protected.inspection
        if protected.composition is None:
            members = (
                PostgresProtectedRelationMember(
                    inspection=inspection,
                    namespace_oid=protected.namespace_oid,
                    relation_kind=PostgresRelationKind.REGULAR,
                    relation_persistence=protected.relation_persistence,
                ),
            )
        else:
            members = protected.composition.members
        for member in members:
            member_inspection = member.inspection
            identity = (
                member_inspection.relation.components,
                member_inspection.relation_row_type_oid,
                member.namespace_oid,
                member.relation_kind,
                member.relation_persistence,
            )
            previous = identities_by_oid.get(member_inspection.relation_oid)
            if previous is not None and previous != identity:
                raise ValueError(
                    "protected context maps one locked relation OID to conflicting identities"
                )
            identities_by_oid[member_inspection.relation_oid] = identity
    return tuple(
        relation_oid
        for relation_oid, _identity in sorted(
            identities_by_oid.items(),
            key=lambda item: (item[1][0], item[0]),
        )
    )


def _require_protected_context_active(context: _ProtectedReadContext) -> None:
    if isinstance(context, PostgresProtectedReadContext):
        evidence = context.evidence
        if _protected_context_lock_closure(context) != evidence.locked_relation_oids:
            raise RunLifecycleStateError(
                "protected source context relation closure changed before persistence"
            )
    elif isinstance(context, GreengageProtectedReadContext):
        try:
            _validate_greengage_context_definition(context)
        except (TypeError, ValueError) as error:
            raise RunLifecycleStateError(
                f"protected Greengage context relation closure is invalid: reason={error}"
            ) from None
    elif isinstance(context, OriginalGreenplumProtectedReadContext):
        try:
            _validate_original_greenplum_context_definition(context)
        except (TypeError, ValueError) as error:
            raise RunLifecycleStateError(
                f"protected original Greenplum context relation closure is invalid: reason={error}"
            ) from None
    else:
        try:
            _mssql_context_relations(context)
        except (TypeError, ValueError) as error:
            raise RunLifecycleStateError(
                f"protected source context relation closure is invalid: reason={error}"
            ) from None
    if not _context_is_active(context):
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
    context_id = _relation_context_id(definition.dataset_relation)
    if _relation_context_id(definition.readiness_relation) != context_id:
        raise ValueError("observation protected relations must share one context")
    dataset_schema_digest = _observation_schema_digest(definition)
    if dataset_schema_digest != definition.dataset.definition.logical_schema_digest:
        raise ValueError("observation physical schema differs from the dataset definition")
    _require_dataset_relation_closure(definition.dataset, definition.dataset_relation)


def _require_dataset_relation_closure(
    dataset: DatasetVersionRecord,
    protected: _ProtectedRelationInspection,
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
    if _relation_components(protected) != expected_relation:
        raise ValueError("protected dataset relation differs from the registered locator")
    expected_scope = dataset.definition.relation_scope
    if expected_scope is None:
        raise ValueError("registered relation dataset must declare a relation scope")
    if isinstance(protected, PostgresProtectedRelationInspection):
        actual_scope = protected.acquisition.relation_scope
    elif isinstance(protected, GreengageProtectedRelationInspection):
        actual_scope = protected.acquisition.relation_scope
    elif isinstance(protected, OriginalGreenplumProtectedRelationInspection):
        actual_scope = protected.acquisition.relation_scope
    else:
        actual_scope = RelationScope.PHYSICAL_ONLY
    if actual_scope is not expected_scope:
        raise ValueError(
            "protected dataset relation scope differs from the immutable dataset definition"
        )
    projection = _semantic_array(body.get("projection"), "dataset projection")
    expected_columns = tuple(
        _semantic_text(
            _semantic_object(item, "dataset projection item").get("column"),
            "dataset projection column",
        )
        for item in projection
    )
    if _relation_column_names(protected) != expected_columns:
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
    if _relation_components(definition.readiness_relation) != expected_relation:
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
    if _relation_column_names(definition.readiness_relation) != expected_columns:
        raise ValueError("protected readiness columns differ from the contract mapping")


def _require_stable_read_context(
    connection: psycopg.Connection[DatabaseRow],
    definition: RelationManifestObservationPersistence,
) -> None:
    row = connection.execute(
        "SELECT strategy, snapshot_locator, acquisition_evidence::text "
        "FROM dfe_metadata.attempt_read_contexts WHERE read_context_id = %s",
        (_relation_context_id(definition.dataset_relation),),
    ).fetchone()
    if row is None:
        raise RunLifecycleStateError("readiness evidence context is missing")
    strategy = _row_text(row[0], "readiness context strategy")
    snapshot_locator = _row_optional_text(row[1], "readiness snapshot locator")
    context = definition.protected_context
    if isinstance(context, PostgresProtectedReadContext):
        if strategy != "protected_read_only_repeatable_read":
            raise ValueError("readiness context does not provide the contract transaction snapshot")
        if snapshot_locator is None or not snapshot_locator.strip():
            raise ValueError("readiness context lacks a transaction snapshot locator")
        expected_kind = "postgresql_protected_relations"
    elif isinstance(context, GreengageProtectedReadContext):
        if strategy != "protected_read_only_repeatable_read_distributed":
            raise ValueError("readiness context does not provide the contract transaction snapshot")
        if snapshot_locator is None or not snapshot_locator.strip():
            raise ValueError("Greengage readiness context lacks a transaction snapshot locator")
        expected_kind = "greengage_protected_relations"
    elif isinstance(context, OriginalGreenplumProtectedReadContext):
        if strategy != "protected_read_only_serializable_distributed":
            raise ValueError("readiness context does not provide the contract transaction snapshot")
        if snapshot_locator is None or not snapshot_locator.strip():
            raise ValueError(
                "original Greenplum readiness context lacks a transaction snapshot locator"
            )
        expected_kind = "original_greenplum_protected_relations"
    else:
        if strategy != "transaction_snapshot":
            raise ValueError("readiness context does not provide the contract transaction snapshot")
        if snapshot_locator is not None:
            raise ValueError("SQL Server readiness context has an unexpected snapshot locator")
        expected_kind = "mssql_snapshot_relations"
    evidence = _semantic_object(
        semantic_value_from_json(_row_text(row[2], "readiness acquisition evidence")),
        "readiness acquisition evidence",
    )
    if _semantic_text(evidence.get("kind"), "readiness acquisition kind") != expected_kind:
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
        _relation_semantic_value(definition.dataset_relation),
        _relation_semantic_value(definition.readiness_relation),
    )
    for relation in expected:
        if relation not in relations:
            raise StoredLifecycleIntegrityError(
                "observation relation is absent from persisted protected acquisition evidence"
            )


def _acquisition_evidence_semantic_value(
    definition: ReadContextPersistence,
) -> dict[str, SemanticValue]:
    context = definition.protected_context
    if isinstance(context, MssqlProtectedReadContext):
        return {
            "evidence_version": 1,
            "kind": "mssql_snapshot_relations",
            "payload": {
                "context": _mssql_context_semantic_value(context),
                "driver": _mssql_driver_semantic_value(context),
                "profile": _mssql_profile_semantic_value(context),
                "relations": [
                    _mssql_relation_semantic_value(item)
                    for item in _mssql_context_relations(context)
                ],
            },
        }
    if isinstance(context, GreengageProtectedReadContext):
        return {
            "evidence_version": 1,
            "kind": "greengage_protected_relations",
            "payload": {
                **_greengage_context_provenance_semantic_value(context),
                "relations": [
                    _greengage_relation_semantic_value(item)
                    for item in _greengage_context_relations(context)
                ],
            },
        }
    if isinstance(context, OriginalGreenplumProtectedReadContext):
        return {
            "evidence_version": 1,
            "kind": "original_greenplum_protected_relations",
            "payload": {
                **_original_greenplum_context_provenance_semantic_value(context),
                "relations": [
                    _original_greenplum_relation_semantic_value(item)
                    for item in _original_greenplum_context_relations(context)
                ],
            },
        }
    evidence = context.evidence
    return {
        "evidence_version": 1,
        "kind": "postgresql_protected_relations",
        "payload": {
            "acquired_before_snapshot": evidence.acquired_before_snapshot,
            "lock_mode": evidence.lock_mode,
            "locked_relation_oids": list(evidence.locked_relation_oids),
            "relation_persistence": evidence.relation_persistence.value,
            "relations": [
                _protected_relation_semantic_value(item) for item in context.protected_relations
            ],
        },
    }


def _physical_binding_semantic_value(
    definition: RelationManifestObservationPersistence,
) -> dict[str, SemanticValue]:
    context = definition.protected_context
    if isinstance(context, MssqlProtectedReadContext):
        dataset_relation = _require_instance(
            definition.dataset_relation,
            MssqlInspectedRelation,
            "SQL Server dataset relation",
        )
        readiness_relation = _require_instance(
            definition.readiness_relation,
            MssqlInspectedRelation,
            "SQL Server readiness relation",
        )
        return {
            "binding_version": 1,
            "engine": "mssql",
            "payload": {
                "context": _mssql_context_semantic_value(context),
                "driver": _mssql_driver_semantic_value(context),
                "profile": _mssql_profile_semantic_value(context),
                "dataset_relation": _mssql_relation_semantic_value(dataset_relation),
                "readiness_relation": _mssql_relation_semantic_value(readiness_relation),
            },
        }
    if isinstance(context, GreengageProtectedReadContext):
        dataset_relation = _require_instance(
            definition.dataset_relation,
            GreengageProtectedRelationInspection,
            "Greengage dataset relation",
        )
        readiness_relation = _require_instance(
            definition.readiness_relation,
            GreengageProtectedRelationInspection,
            "Greengage readiness relation",
        )
        return {
            "binding_version": 1,
            "engine": "greengage",
            "payload": {
                **_greengage_context_provenance_semantic_value(context),
                "dataset_relation": _greengage_relation_semantic_value(dataset_relation),
                "readiness_relation": _greengage_relation_semantic_value(readiness_relation),
            },
        }
    if isinstance(context, OriginalGreenplumProtectedReadContext):
        dataset_relation = _require_instance(
            definition.dataset_relation,
            OriginalGreenplumProtectedRelationInspection,
            "original Greenplum dataset relation",
        )
        readiness_relation = _require_instance(
            definition.readiness_relation,
            OriginalGreenplumProtectedRelationInspection,
            "original Greenplum readiness relation",
        )
        return {
            "binding_version": 1,
            "engine": "greenplum",
            "payload": {
                **_original_greenplum_context_provenance_semantic_value(context),
                "dataset_relation": _original_greenplum_relation_semantic_value(dataset_relation),
                "readiness_relation": _original_greenplum_relation_semantic_value(
                    readiness_relation
                ),
            },
        }
    dataset_relation = _require_instance(
        definition.dataset_relation,
        PostgresProtectedRelationInspection,
        "PostgreSQL dataset relation",
    )
    readiness_relation = _require_instance(
        definition.readiness_relation,
        PostgresProtectedRelationInspection,
        "PostgreSQL readiness relation",
    )
    return {
        "binding_version": 1,
        "engine": "postgresql",
        "payload": {
            "dataset_relation": _protected_relation_semantic_value(dataset_relation),
            "readiness_relation": _protected_relation_semantic_value(readiness_relation),
        },
    }


def _relation_semantic_value(
    relation: _ProtectedRelationInspection,
) -> dict[str, SemanticValue]:
    if isinstance(relation, PostgresProtectedRelationInspection):
        return _protected_relation_semantic_value(relation)
    if isinstance(relation, GreengageProtectedRelationInspection):
        return _greengage_relation_semantic_value(relation)
    if isinstance(relation, OriginalGreenplumProtectedRelationInspection):
        return _original_greenplum_relation_semantic_value(relation)
    return _mssql_relation_semantic_value(relation)


def _protected_relation_semantic_value(
    protected: PostgresProtectedRelationInspection,
) -> dict[str, SemanticValue]:
    inspection = protected.inspection
    value: dict[str, SemanticValue] = {
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
    if protected.acquisition.relation_scope is RelationScope.PHYSICAL_ONLY:
        return value
    composition = protected.composition
    if composition is None:
        raise ValueError("frozen physical union lacks a protected composition")
    composition_value: dict[str, SemanticValue] = {
        "composition_version": 1,
        "edges": [_inheritance_edge_semantic_value(edge) for edge in composition.edges],
        "members": [_protected_member_semantic_value(member) for member in composition.members],
        "root_relation_oid": composition.root_relation_oid,
    }
    value["composition"] = {
        "composition_digest": semantic_digest_hex(composition_value),
        **composition_value,
    }
    value["relation_scope"] = protected.acquisition.relation_scope.value
    return value


def _protected_member_semantic_value(
    member: PostgresProtectedRelationMember,
) -> dict[str, SemanticValue]:
    inspection = member.inspection
    binding: dict[str, SemanticValue] = {
        "columns": [_binding_semantic_value(item) for item in inspection.bindings],
        "namespace_oid": member.namespace_oid,
        "relation_kind": member.relation_kind.value,
        "relation_oid": inspection.relation_oid,
        "relation_persistence": member.relation_persistence.value,
        "relation_row_type_oid": inspection.relation_row_type_oid,
        "resolved_relation": list(inspection.relation.components),
    }
    return {
        **binding,
        "physical_binding_digest": semantic_digest_hex(binding),
    }


def _inheritance_edge_semantic_value(
    edge: PostgresInheritanceEdge,
) -> dict[str, SemanticValue]:
    return {
        "child_relation_oid": edge.child_relation_oid,
        "detach_state": edge.detach_state.value,
        "inhseqno": edge.sequence,
        "parent_relation_oid": edge.parent_relation_oid,
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


def _greengage_context_provenance_semantic_value(
    context: GreengageProtectedReadContext,
) -> dict[str, SemanticValue]:
    return {
        "context": _greengage_context_semantic_value(context),
        "driver": _greenplum_driver_semantic_value(context.driver),
        "hash_capability": _greengage_hash_capability_semantic_value(context.hash_capability),
        "profile": _greengage_profile_semantic_value(context.server),
        "reader": _greenplum_reader_semantic_value(context.reader),
        "topology": _greenplum_topology_semantic_value(context.topology),
    }


def _greengage_context_semantic_value(
    context: GreengageProtectedReadContext,
) -> dict[str, SemanticValue]:
    evidence = context.evidence
    return {
        "acquired_before_snapshot": evidence.acquired_before_snapshot,
        "allowed_concurrency": evidence.allowed_concurrency,
        "backend_process_id": evidence.backend_process_id,
        "context_id": str(evidence.context_id),
        "engine": "greengage",
        "limitations": list(evidence.limitations),
        "planning_settings": [
            _greenplum_planning_setting_semantic_value(setting)
            for setting in evidence.planning_settings
        ],
        "relation_locks": [
            _greenplum_relation_lock_semantic_value(lock) for lock in evidence.relation_locks
        ],
        "runtime_profile": evidence.runtime_profile.value,
        "snapshot_locator": evidence.snapshot_locator,
        "started_at": evidence.started_at.astimezone(UTC).isoformat(),
        "strategy": evidence.strategy,
    }


def _greenplum_driver_semantic_value(
    driver: GreenplumDriverEvidence,
) -> dict[str, SemanticValue]:
    return {
        "build_libpq_version": driver.build_libpq_version,
        "driver_name": driver.driver_name,
        "driver_version": driver.driver_version,
        "runtime_libpq_version": driver.runtime_libpq_version,
    }


def _greengage_profile_semantic_value(
    profile: GreenplumServerProfile,
) -> dict[str, SemanticValue]:
    return {
        "backend_process_id": profile.backend_process_id,
        "client_encoding": profile.client_encoding,
        "compatibility_version": profile.compatibility_version,
        "compatibility_version_number": profile.compatibility_version_number,
        "database_name": profile.database_name,
        "full_version": profile.full_version,
        "gp_role": profile.gp_role,
        "gp_session_role": profile.gp_session_role,
        "integer_datetimes": profile.integer_datetimes,
        "max_identifier_utf8_bytes": profile.max_identifier_utf8_bytes,
        "product": "greengage",
        "product_version": profile.product_version,
        "runtime_profile": profile.runtime_profile.value,
        "server_encoding": profile.server_encoding,
        "snapshot_locator": profile.snapshot_locator,
        "timezone": profile.timezone,
        "transaction_isolation": profile.transaction_isolation,
        "transaction_read_only": profile.transaction_read_only,
    }


def _greenplum_reader_semantic_value(
    reader: GreenplumReaderIdentity,
) -> dict[str, SemanticValue]:
    return {
        "can_create_database": reader.can_create_database,
        "can_create_role": reader.can_create_role,
        "can_login": reader.can_login,
        "default_transaction_read_only": reader.default_transaction_read_only,
        "is_superuser": reader.is_superuser,
        "transaction_read_only": reader.transaction_read_only,
        "user_name": reader.user_name,
    }


def _greenplum_topology_semantic_value(
    topology: GreenplumTopology,
) -> dict[str, SemanticValue]:
    return {
        "primary_content_ids": list(topology.primary_content_ids),
        "segments": [_greenplum_segment_semantic_value(segment) for segment in topology.segments],
    }


def _greenplum_segment_semantic_value(
    segment: GreenplumSegment,
) -> dict[str, SemanticValue]:
    return {
        "content_id": segment.content_id,
        "preferred_role": segment.preferred_role,
        "role": segment.role,
        "status": segment.status,
    }


def _greenplum_planning_setting_semantic_value(
    setting: GreenplumSessionSettingEvidence,
) -> dict[str, SemanticValue]:
    return {"name": setting.name, "value": setting.value}


def _greenplum_relation_lock_semantic_value(
    lock: GreenplumRelationLockEvidence,
) -> dict[str, SemanticValue]:
    return {
        "lock_mode": lock.lock_mode,
        "relation_name": lock.relation_name,
        "relation_oid": lock.relation_oid,
        "schema_name": lock.schema_name,
    }


def _greengage_hash_capability_semantic_value(
    capability: GreengageHashCapability,
) -> dict[str, SemanticValue]:
    return {
        "argument_type_oids": list(capability.argument_type_oids),
        "function_name": capability.function_name,
        "function_oid": capability.function_oid,
        "is_strict": capability.is_strict,
        "reader_has_execute": capability.reader_has_execute,
        "reader_has_schema_usage": capability.reader_has_schema_usage,
        "result_type_oid": capability.result_type_oid,
        "schema_name": capability.schema_name,
        "selected_strategy": capability.selected_strategy,
        "volatility_code": capability.volatility_code,
    }


def _greengage_relation_semantic_value(
    protected: GreengageProtectedRelationInspection,
) -> dict[str, SemanticValue]:
    inspection = protected.inspection
    catalog = protected.catalog
    return {
        "access_method": catalog.access_method,
        "acquired_before_snapshot": protected.acquired_before_snapshot,
        "columns": [_binding_semantic_value(item) for item in inspection.bindings],
        "context_id": str(inspection.context_id),
        "distribution_attribute_numbers": list(catalog.distribution_attribute_numbers),
        "distribution_policy_type": catalog.distribution_policy_type,
        "distribution_segment_count": catalog.distribution_segment_count,
        "has_distribution_policy": catalog.has_distribution_policy,
        "is_append_optimized": catalog.is_append_optimized,
        "lock_mode": protected.lock_mode,
        "max_identifier_utf8_bytes": inspection.max_identifier_utf8_bytes,
        "persistence_code": catalog.persistence_code,
        "reader_has_delete": catalog.reader_has_delete,
        "reader_has_insert": catalog.reader_has_insert,
        "reader_has_schema_usage": catalog.reader_has_schema_usage,
        "reader_has_select": catalog.reader_has_select,
        "reader_has_truncate": catalog.reader_has_truncate,
        "reader_has_update": catalog.reader_has_update,
        "relation_kind": catalog.relation_kind,
        "relation_oid": inspection.relation_oid,
        "relation_row_type_oid": inspection.relation_row_type_oid,
        "relation_scope": protected.acquisition.relation_scope.value,
        "requested_relation": list(protected.acquisition.relation.components),
        "resolved_relation": list(inspection.relation.components),
        "row_security_enabled": catalog.row_security_enabled,
        "row_security_forced": catalog.row_security_forced,
        "storage_kind": catalog.storage_kind.value,
        "storage_profile": _greenplum_storage_profile_semantic_value(catalog.storage_profile),
    }


def _original_greenplum_context_provenance_semantic_value(
    context: OriginalGreenplumProtectedReadContext,
) -> dict[str, SemanticValue]:
    return {
        "context": _original_greenplum_context_semantic_value(context),
        "driver": _greenplum_driver_semantic_value(context.driver),
        "hash_capability": _original_greenplum_hash_capability_semantic_value(
            context.hash_capability
        ),
        "profile": _original_greenplum_profile_semantic_value(context.server),
        "reader": _greenplum_reader_semantic_value(context.reader),
        "topology": _greenplum_topology_semantic_value(context.topology),
    }


def _original_greenplum_context_semantic_value(
    context: OriginalGreenplumProtectedReadContext,
) -> dict[str, SemanticValue]:
    evidence = context.evidence
    return {
        "acquired_before_snapshot": evidence.acquired_before_snapshot,
        "allowed_concurrency": evidence.allowed_concurrency,
        "backend_process_id": evidence.backend_process_id,
        "context_id": str(evidence.context_id),
        "engine": "greenplum",
        "limitations": list(evidence.limitations),
        "relation_locks": [
            _greenplum_relation_lock_semantic_value(lock) for lock in evidence.relation_locks
        ],
        "runtime_profile": evidence.runtime_profile.value,
        "snapshot_locator": evidence.snapshot_locator,
        "started_at": evidence.started_at.astimezone(UTC).isoformat(),
        "strategy": evidence.strategy,
    }


def _original_greenplum_profile_semantic_value(
    profile: GreenplumServerProfile,
) -> dict[str, SemanticValue]:
    return {
        "backend_process_id": profile.backend_process_id,
        "client_encoding": profile.client_encoding,
        "compatibility_version": profile.compatibility_version,
        "compatibility_version_number": profile.compatibility_version_number,
        "database_name": profile.database_name,
        "full_version": profile.full_version,
        "gp_role": profile.gp_role,
        "gp_session_role": profile.gp_session_role,
        "integer_datetimes": profile.integer_datetimes,
        "max_identifier_utf8_bytes": profile.max_identifier_utf8_bytes,
        "product": ORIGINAL_GREENPLUM_PROFILE,
        "product_version": profile.product_version,
        "runtime_profile": profile.runtime_profile.value,
        "server_encoding": profile.server_encoding,
        "snapshot_locator": profile.snapshot_locator,
        "timezone": profile.timezone,
        "transaction_isolation": profile.transaction_isolation,
        "transaction_read_only": profile.transaction_read_only,
    }


def _original_greenplum_hash_capability_semantic_value(
    capability: OriginalGreenplumHashCapability,
) -> dict[str, SemanticValue]:
    return {
        "argument_type_oids": list(capability.argument_type_oids),
        "canonical_sha256_verified": capability.canonical_sha256_verified,
        "function_name": capability.function_name,
        "function_oid": capability.function_oid,
        "is_strict": capability.is_strict,
        "reader_has_execute": capability.reader_has_execute,
        "reader_has_schema_usage": capability.reader_has_schema_usage,
        "result_type_oid": capability.result_type_oid,
        "schema_name": capability.schema_name,
        "selected_strategy": capability.selected_strategy,
        "volatility_code": capability.volatility_code,
    }


def _original_greenplum_relation_semantic_value(
    protected: OriginalGreenplumProtectedRelationInspection,
) -> dict[str, SemanticValue]:
    inspection = protected.inspection
    catalog = protected.catalog
    return {
        "acquired_before_snapshot": protected.acquired_before_snapshot,
        "columns": [_binding_semantic_value(item) for item in inspection.bindings],
        "context_id": str(inspection.context_id),
        "distribution_attribute_numbers": list(catalog.distribution_attribute_numbers),
        "has_distribution_policy": catalog.has_distribution_policy,
        "lock_mode": protected.lock_mode,
        "max_identifier_utf8_bytes": inspection.max_identifier_utf8_bytes,
        "reader_has_delete": catalog.reader_has_delete,
        "reader_has_insert": catalog.reader_has_insert,
        "reader_has_schema_usage": catalog.reader_has_schema_usage,
        "reader_has_select": catalog.reader_has_select,
        "reader_has_truncate": catalog.reader_has_truncate,
        "reader_has_update": catalog.reader_has_update,
        "relation_kind": catalog.relation_kind,
        "relation_oid": inspection.relation_oid,
        "relation_row_type_oid": inspection.relation_row_type_oid,
        "relation_scope": protected.acquisition.relation_scope.value,
        "requested_relation": list(protected.acquisition.relation.components),
        "resolved_relation": list(inspection.relation.components),
        "storage_code": catalog.storage_code,
        "storage_kind": catalog.storage_kind.value,
        "storage_profile": _greenplum_storage_profile_semantic_value(catalog.storage_profile),
    }


def _greenplum_storage_profile_semantic_value(
    profile: GreenplumStorageProfile,
) -> dict[str, SemanticValue]:
    return {
        "append_only_catalog_present": profile.append_only_catalog_present,
        "block_size_bytes": profile.block_size_bytes,
        "checksum": profile.checksum,
        "column_store": profile.column_store,
        "compression_level": profile.compression_level,
        "compression_type": profile.compression_type,
        "kind": profile.kind.value,
        "relation_options": [
            {"name": name, "value": value} for name, value in profile.relation_options
        ],
    }


def _mssql_context_semantic_value(
    context: MssqlProtectedReadContext,
) -> dict[str, SemanticValue]:
    evidence = context.evidence
    return {
        "allowed_concurrency": evidence.allowed_concurrency,
        "context_id": str(evidence.context_id),
        "database_id": evidence.database_id,
        "engine": evidence.engine,
        "limitations": list(evidence.limitations),
        "server_version": evidence.server_version,
        "session_id": evidence.session_id,
        "snapshot_locator": evidence.snapshot_locator,
        "started_at": evidence.started_at.astimezone(UTC).isoformat(),
        "strategy": evidence.strategy,
        "transaction_count": evidence.transaction_count,
        "transaction_isolation_level": evidence.transaction_isolation_level,
        "transaction_state": evidence.transaction_state,
    }


def _mssql_driver_semantic_value(
    context: MssqlProtectedReadContext,
) -> dict[str, SemanticValue]:
    driver = context.profile.driver
    return {
        "driver_name": driver.driver_name,
        "driver_version": driver.driver_version,
        "pyodbc_version": driver.pyodbc_version,
        "server_version": driver.server_version,
        "session_id": driver.session_id,
    }


def _mssql_profile_semantic_value(
    context: MssqlProtectedReadContext,
) -> dict[str, SemanticValue]:
    profile = context.profile
    value: dict[str, SemanticValue] = {
        "can_view_definition": profile.can_view_definition,
        "canonical_utf8_code_page": profile.canonical_utf8_code_page,
        "compatibility_level": profile.compatibility_level,
        "database_collation": profile.database_collation,
        "database_id": profile.database_id,
        "database_name": profile.database_name,
        "database_read_only": profile.database_read_only,
        "database_updateability": profile.database_updateability,
        "edition": profile.edition,
        "engine_edition": profile.engine_edition,
        "product_build": profile.product_build,
        "product_level": profile.product_level,
        "product_major_version": profile.product_major_version,
        "product_update_level": profile.product_update_level,
        "product_update_reference": profile.product_update_reference,
        "product_version": profile.product_version,
        "read_committed_snapshot": profile.read_committed_snapshot,
        "server_collation": profile.server_collation,
        "snapshot_isolation_state": profile.snapshot_isolation_state,
        "snapshot_isolation_state_description": (profile.snapshot_isolation_state_description),
    }
    if profile.canonical_utf8_helper is not None:
        value["canonical_utf8_strategy"] = "owner_installed_scalar_function_v1"
        value["canonical_utf8_helper"] = _mssql_utf8_helper_semantic_value(
            profile.canonical_utf8_helper
        )
    return value


def _mssql_utf8_helper_semantic_value(
    helper: MssqlUtf8HelperBinding,
) -> dict[str, SemanticValue]:
    return {
        "ansi_nulls": helper.ansi_nulls,
        "ansi_padding": helper.ansi_padding,
        "ansi_warnings": helper.ansi_warnings,
        "arithabort": helper.arithabort,
        "can_alter": helper.can_alter,
        "can_control": helper.can_control,
        "can_execute": helper.can_execute,
        "can_view_definition": helper.can_view_definition,
        "concat_null_yields_null": helper.concat_null_yields_null,
        "database_collation": helper.database_collation,
        "database_compatibility_level": helper.database_compatibility_level,
        "database_id": helper.database_id,
        "database_name": helper.database_name,
        "definition_sha256": helper.definition_sha256.hex(),
        "definition_utf16_bytes": helper.definition_utf16_bytes,
        "execute_as_principal_id": helper.execute_as_principal_id,
        "input_has_default_value": helper.input_has_default_value,
        "input_is_output": helper.input_is_output,
        "input_max_length": helper.input_max_length,
        "input_parameter_name": helper.input_parameter_name,
        "input_type_name": helper.input_type_name,
        "input_type_schema": helper.input_type_schema,
        "is_deterministic": helper.is_deterministic,
        "is_encrypted": helper.is_encrypted,
        "is_precise": helper.is_precise,
        "is_schema_bound": helper.is_schema_bound,
        "null_on_null_input": helper.null_on_null_input,
        "numeric_roundabort": helper.numeric_roundabort,
        "object_id": helper.object_id,
        "object_name": helper.object_name,
        "object_type": helper.object_type,
        "quoted_identifier": helper.quoted_identifier,
        "return_has_default_value": helper.return_has_default_value,
        "return_is_output": helper.return_is_output,
        "return_max_length": helper.return_max_length,
        "return_type_name": helper.return_type_name,
        "return_type_schema": helper.return_type_schema,
        "schema_id": helper.schema_id,
        "schema_name": helper.schema_name,
        "uses_ansi_nulls": helper.uses_ansi_nulls,
        "uses_database_collation": helper.uses_database_collation,
        "uses_quoted_identifier": helper.uses_quoted_identifier,
    }


def _mssql_relation_semantic_value(
    relation: MssqlInspectedRelation,
) -> dict[str, SemanticValue]:
    return {
        "columns": [_mssql_binding_semantic_value(binding) for binding in relation.bindings],
        "context_id": str(relation.context_id),
        "database_id": relation.database_id,
        "object_id": relation.object_id,
        "relation": [relation.relation.schema_name, relation.relation.table_name],
        "schema_id": relation.schema_id,
    }


def _mssql_binding_semantic_value(binding: MssqlFieldBinding) -> dict[str, SemanticValue]:
    return {
        "column_id": binding.column_id,
        "column_name": binding.column_name,
        "field_name": binding.field_name,
        "is_nullable": binding.is_nullable,
        "physical": _mssql_physical_field_semantic_value(binding.physical),
    }


def _mssql_physical_field_semantic_value(
    field: MssqlPhysicalField,
) -> dict[str, SemanticValue]:
    return {
        "collation_name": field.collation_name,
        "max_length": field.max_length,
        "precision": field.precision,
        "scale": field.scale,
        "system_type_id": field.system_type_id,
        "system_type_name": field.system_type_name,
        "user_type_id": field.user_type_id,
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
    "result_payload::text, completed_at, evidence_manifest_digest "
    "FROM dfe_metadata.check_results"
)

_PARTIAL_RESULT_SELECT: Final[LiteralString] = (
    "SELECT run_id, attempt_id, check_id, end_operation_id, contract_digest, "
    "scope_digest, input_cut_digest, reference_observation_id, reference_direction, "
    "target_observation_id, target_direction, execution_status, verdict, guarantee, "
    "result_digest, result_payload::text, frontier_digest, frontier_payload::text, "
    "evidence_manifest_digest, ended_at FROM dfe_metadata.partial_check_results"
)

_ANOMALY_SELECT: Final[LiteralString] = (
    "SELECT run_id, attempt_id, check_id, end_operation_id, anomaly_sequence, "
    "segment_sequence, anomaly_kind, key_digest, reference_observation_id, "
    "reference_direction, target_observation_id, target_direction, "
    "evidence_payload::text, payload_digest, payload_byte_length, record_digest "
    "FROM dfe_metadata.anomalies"
)

_HISTORY_SELECT: Final[LiteralString] = (
    "SELECT dfe_attempt.run_id, dfe_attempt.attempt_id, dfe_attempt.ordinal, "
    "dfe_attempt.status, dfe_attempt.end_operation_id, dfe_attempt.terminal_reason_code, "
    "dfe_attempt.terminal_reason::text, dfe_attempt.started_at, dfe_attempt.ended_at, "
    "dfe_run.selected_terminal_attempt_id, dfe_contract.check_id, "
    "dfe_contract.semantic_digest, dfe_run.scope_digest, "
    "dfe_result.run_id, dfe_result.attempt_id, dfe_result.check_id, "
    "dfe_result.result_operation_id, dfe_result.contract_digest, dfe_result.scope_digest, "
    "dfe_result.execution_status, dfe_result.verdict, dfe_result.guarantee, "
    "dfe_result.result_digest, dfe_result.result_payload::text, dfe_result.completed_at, "
    "dfe_result.evidence_manifest_digest, "
    "dfe_partial.run_id, dfe_partial.attempt_id, dfe_partial.check_id, "
    "dfe_partial.end_operation_id, dfe_partial.contract_digest, "
    "dfe_partial.scope_digest, dfe_partial.input_cut_digest, "
    "dfe_partial.reference_observation_id, dfe_partial.reference_direction, "
    "dfe_partial.target_observation_id, dfe_partial.target_direction, "
    "dfe_partial.execution_status, dfe_partial.verdict, dfe_partial.guarantee, "
    "dfe_partial.result_digest, dfe_partial.result_payload::text, "
    "dfe_partial.frontier_digest, dfe_partial.frontier_payload::text, "
    "dfe_partial.evidence_manifest_digest, dfe_partial.ended_at "
    "FROM dfe_metadata.run_attempts AS dfe_attempt "
    "JOIN dfe_metadata.runs AS dfe_run ON dfe_run.run_id = dfe_attempt.run_id "
    "JOIN dfe_metadata.contract_versions AS dfe_contract "
    "ON dfe_contract.contract_version_id = dfe_run.contract_version_id "
    "LEFT JOIN dfe_metadata.check_results AS dfe_result "
    "ON dfe_result.run_id = dfe_attempt.run_id "
    "AND dfe_result.attempt_id = dfe_attempt.attempt_id "
    "AND dfe_result.check_id = dfe_contract.check_id "
    "LEFT JOIN dfe_metadata.partial_check_results AS dfe_partial "
    "ON dfe_partial.run_id = dfe_attempt.run_id "
    "AND dfe_partial.attempt_id = dfe_attempt.attempt_id "
    "AND dfe_partial.check_id = dfe_contract.check_id "
    "WHERE dfe_contract.check_id = %s AND dfe_run.scope_digest = %s"
)

_HISTORY_ORDER_LIMIT: Final[LiteralString] = (
    " ORDER BY dfe_attempt.started_at DESC, dfe_attempt.run_id DESC, "
    "dfe_attempt.attempt_id DESC LIMIT %s"
)

_HISTORY_CURSOR_ORDER_LIMIT: Final[LiteralString] = (
    " AND (dfe_attempt.started_at, dfe_attempt.run_id, dfe_attempt.attempt_id) "
    "< (%s, %s, %s) ORDER BY dfe_attempt.started_at DESC, dfe_attempt.run_id DESC, "
    "dfe_attempt.attempt_id DESC LIMIT %s"
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


def _select_partial_result_by_operation(
    connection: psycopg.Connection[DatabaseRow],
    operation_id: UUID,
) -> DatabaseRow | None:
    return connection.execute(
        _PARTIAL_RESULT_SELECT + " WHERE end_operation_id = %s",
        (operation_id,),
    ).fetchone()


def _select_partial_results_by_attempt(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
) -> list[DatabaseRow]:
    return connection.execute(
        _PARTIAL_RESULT_SELECT + " WHERE run_id = %s AND attempt_id = %s ORDER BY check_id",
        (run_id, attempt_id),
    ).fetchall()


def _select_anomaly_rows_by_attempt(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
    check_id: str,
) -> list[DatabaseRow]:
    return connection.execute(
        _ANOMALY_SELECT + " WHERE run_id = %s AND attempt_id = %s AND check_id = %s "
        "ORDER BY anomaly_sequence",
        (run_id, attempt_id, check_id),
    ).fetchall()


def _select_anomaly_page_rows(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    after_sequence: int,
    limit: int,
) -> list[DatabaseRow]:
    operation_id = result.persistence.operation_id
    if operation_id is None:
        raise StoredLifecycleIntegrityError("stored result has no persistence operation id")
    return connection.execute(
        _ANOMALY_SELECT + " WHERE run_id = %s AND attempt_id = %s AND check_id = %s "
        "AND end_operation_id = %s AND anomaly_sequence > %s "
        "ORDER BY anomaly_sequence LIMIT %s",
        (
            result.run_id,
            result.attempt_id,
            result.check_id,
            operation_id,
            after_sequence,
            limit,
        ),
    ).fetchall()


def _select_history_rows(
    connection: psycopg.Connection[DatabaseRow],
    check_id: str,
    scope_digest: str,
    limit: int,
    cursor: HistoryCursor | None,
) -> list[DatabaseRow]:
    scope_digest_bytes = bytes.fromhex(scope_digest)
    if cursor is None:
        return connection.execute(
            _HISTORY_SELECT + _HISTORY_ORDER_LIMIT,
            (check_id, scope_digest_bytes, limit),
        ).fetchall()
    return connection.execute(
        _HISTORY_SELECT + _HISTORY_CURSOR_ORDER_LIMIT,
        (
            check_id,
            scope_digest_bytes,
            cursor.started_at,
            cursor.run_id,
            cursor.attempt_id,
            limit,
        ),
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
    storage_identity = _context_storage_identity(definition.protected_context)
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
        _context_engine(definition.protected_context),
        storage_identity.driver_version,
        storage_identity.server_version,
        storage_identity.server_version_number,
        evidence.strategy,
        evidence.snapshot_locator,
        storage_identity.backend_process_id,
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
        _relation_context_id(definition.dataset_relation),
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


def _insert_anomaly(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
    check_id: str,
    operation_id: UUID,
    reference_observation_id: UUID,
    target_observation_id: UUID,
    anomaly: _AnomalyExpectation,
) -> None:
    connection.execute(
        "INSERT INTO dfe_metadata.anomalies ("
        "run_id, attempt_id, check_id, end_operation_id, anomaly_sequence, "
        "segment_sequence, anomaly_kind, key_digest, reference_observation_id, "
        "reference_direction, target_observation_id, target_direction, "
        "evidence_payload, payload_digest, payload_byte_length, record_digest) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'reference', %s, 'target', "
        "%s::jsonb, %s, %s, %s)",
        (
            run_id,
            attempt_id,
            check_id,
            operation_id,
            anomaly.record.sequence,
            anomaly.record.segment_sequence,
            anomaly.record.kind.value,
            (
                bytes.fromhex(anomaly.record.key_digest)
                if anomaly.record.key_digest is not None
                else None
            ),
            reference_observation_id,
            target_observation_id,
            anomaly.payload_json,
            anomaly.payload_digest,
            anomaly.payload_byte_length,
            anomaly.record_digest,
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
        or _row_optional_bytes(row[12], "completed evidence manifest digest")
        != expected.evidence_manifest_digest
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
    if _select_partial_results_by_attempt(
        connection,
        expected.attempt.run.run_id,
        expected.attempt.attempt_id,
    ):
        raise StoredLifecycleIntegrityError(
            "completed comparison cannot also contain a partial result parent"
        )
    observation_ids = _completed_observation_ids(connection, result, segments)
    anomalies = _anomalies_from_database(
        connection,
        result,
        observation_ids,
        expected.evidence_manifest_digest,
    )
    if anomalies != tuple(anomaly.record for anomaly in expected.anomalies):
        raise LifecycleOperationConflictError(
            "completed comparison operation UUID is bound to different retained anomalies"
        )
    comparison_boundary = _comparison_evidence_boundary_from_database(connection, result)
    _validate_anomaly_evidence_boundary(anomalies, comparison_boundary)
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


def _partial_result_from_database(
    connection: psycopg.Connection[DatabaseRow],
    expected: _PartialComparisonExpectation,
) -> RunResult:
    row = _select_partial_result_by_operation(connection, expected.operation_id)
    if row is None:
        raise StoredLifecycleIntegrityError("partial comparison operation receipt is missing")
    (
        result,
        ended_at,
        frontier,
        input_cut_digest,
        observation_ids,
        manifest_digest,
    ) = _partial_result_from_row(row)
    if (
        result != expected.result
        or _canonical_database_json(row[15], "partial result payload") != expected.result_json
        or _row_bytes(row[14], "partial result digest") != expected.result_digest
        or frontier != expected.comparison.frontier
        or _canonical_database_json(row[17], "partial frontier payload") != expected.frontier_json
        or _row_bytes(row[16], "partial frontier digest") != expected.frontier_digest
        or input_cut_digest != expected.comparison.input_cut_digest
        or observation_ids
        != (
            expected.comparison.reference_observation_id,
            expected.comparison.target_observation_id,
        )
        or manifest_digest != expected.evidence_manifest_digest
        or ended_at != expected.ended_at
    ):
        raise LifecycleOperationConflictError(
            "partial comparison operation UUID is already bound to a different full result"
        )
    if _select_results_by_attempt(
        connection,
        expected.attempt.run.run_id,
        expected.attempt.attempt_id,
    ):
        raise StoredLifecycleIntegrityError(
            "partial comparison cannot also contain a completed result parent"
        )
    anomalies = _anomalies_from_database(
        connection,
        result,
        observation_ids,
        manifest_digest,
    )
    if anomalies != tuple(anomaly.record for anomaly in expected.anomalies):
        raise LifecycleOperationConflictError(
            "partial comparison operation UUID is bound to different retained anomalies"
        )
    _require_valid_stored_partial(result, frontier, observation_ids, anomalies)
    _validate_anomaly_evidence_boundary(
        anomalies,
        _comparison_evidence_boundary_from_database(connection, result),
    )
    _require_partial_database_closure(
        connection,
        result,
        frontier,
        input_cut_digest,
        observation_ids,
        ended_at,
    )
    _require_partial_terminal_receipt(connection, result, ended_at)
    return result


def _partial_result_from_row(
    row: DatabaseRow,
) -> tuple[
    RunResult,
    datetime,
    PartialComparisonFrontier,
    str,
    tuple[UUID, UUID],
    bytes,
]:
    if len(row) != 20:
        raise StoredLifecycleIntegrityError(
            f"PostgreSQL partial result row has an invalid column count: "
            f"actual={len(row)}, expected=20"
        )
    payload_json = _canonical_database_json(row[15], "partial result payload")
    try:
        payload_value = semantic_value_from_json(payload_json)
        result = RunResult.model_validate_json(payload_json)
        replay_json = canonical_semantic_json(semantic_value_from_json(result.model_dump_json()))
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored partial result violates the public result protocol: reason={error}"
        ) from None
    if replay_json != payload_json:
        raise StoredLifecycleIntegrityError(
            "stored partial result payload contains unsupported or non-round-trippable fields"
        )
    frontier_json = _canonical_database_json(row[17], "partial frontier payload")
    try:
        frontier = partial_comparison_frontier_from_canonical_bytes(
            frontier_json.encode("utf-8", errors="strict")
        )
        replay_frontier_json = canonical_partial_comparison_frontier_bytes(frontier).decode(
            "utf-8",
            errors="strict",
        )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored partial frontier violates the comparison protocol: reason={error}"
        ) from None
    if replay_frontier_json != frontier_json:
        raise StoredLifecycleIntegrityError(
            "stored partial frontier contains unsupported or non-round-trippable fields"
        )
    result_digest = bytes.fromhex(semantic_digest_hex(payload_value))
    frontier_digest = bytes.fromhex(semantic_digest_hex(semantic_value_from_json(frontier_json)))
    input_cut_digest = _row_bytes(row[6], "partial result input cut digest").hex()
    observation_ids = (
        _row_uuid(row[7], "partial result reference observation id"),
        _row_uuid(row[9], "partial result target observation id"),
    )
    actual = (
        _row_uuid(row[0], "partial result run id"),
        _row_uuid(row[1], "partial result attempt id"),
        _row_text(row[2], "partial result check id"),
        _row_uuid(row[3], "partial result operation id"),
        _row_bytes(row[4], "partial result contract digest").hex(),
        _row_bytes(row[5], "partial result scope digest").hex(),
        _row_text(row[8], "partial result reference direction"),
        _row_text(row[10], "partial result target direction"),
        _row_text(row[11], "partial result execution status"),
        _row_text(row[12], "partial result verdict"),
        _row_text(row[13], "partial result guarantee"),
        _row_bytes(row[14], "partial result digest"),
        _row_bytes(row[16], "partial frontier digest"),
    )
    expected = (
        result.run_id,
        result.attempt_id,
        result.check_id,
        result.persistence.operation_id,
        result.contract_digest,
        result.scope_digest,
        PlanDirection.REFERENCE.value,
        PlanDirection.TARGET.value,
        result.execution_status.value,
        result.verdict.value,
        result.guarantee.value,
        result_digest,
        frontier_digest,
    )
    if actual != expected:
        raise StoredLifecycleIntegrityError(
            "stored partial result columns differ from its canonical payloads"
        )
    manifest_digest = _row_bytes(row[18], "partial evidence manifest digest")
    if len(manifest_digest) != 32:
        raise StoredLifecycleIntegrityError("partial evidence manifest digest is not SHA-256")
    return (
        result,
        _row_datetime(row[19], "partial result ended_at"),
        frontier,
        input_cut_digest,
        observation_ids,
        manifest_digest,
    )


def _require_valid_stored_partial(
    result: RunResult,
    frontier: PartialComparisonFrontier,
    observation_ids: tuple[UUID, UUID],
    anomalies: tuple[DifferenceRecord, ...],
) -> None:
    _require_valid_stored_partial_snapshot(result, frontier, observation_ids)
    try:
        _validate_anomaly_coverage(result.evidence_coverage, anomalies)
        by_sequence = {segment.segment_sequence: segment for segment in frontier.topology}
        for anomaly in anomalies:
            segment = by_sequence.get(anomaly.segment_sequence)
            if (
                segment is None
                or segment.state.value != ComparisonSegmentState.EXACT_MISMATCH.value
            ):
                raise ValueError(
                    "partial anomaly must reference a persisted exact-mismatch segment"
                )
    except (TypeError, ValueError) as error:
        raise StoredLifecycleIntegrityError(
            f"stored partial comparison is invalid: reason={error}"
        ) from None


def _require_valid_stored_partial_snapshot(
    result: RunResult,
    frontier: PartialComparisonFrontier,
    observation_ids: tuple[UUID, UUID],
) -> None:
    try:
        if result.execution_status is ExecutionStatus.COMPLETED:
            raise ValueError("partial result cannot have completed execution status")
        if result.guarantee is not Guarantee.NOT_ESTABLISHED:
            raise ValueError("partial result requires not_established guarantee")
        if result.verdict is Verdict.MATCH:
            raise ValueError("partial result cannot claim a match")
        if len(result.consistency.read_context_ids) != 2:
            raise ValueError("partial result requires two protected context identities")
        if observation_ids[0] == observation_ids[1]:
            raise ValueError("partial result observation identities must be distinct")
        _validate_partial_frontier_closure(
            frontier,
            result.metrics,
            result.comparison_coverage,
            result.totals,
            result.verdict,
            result.consistency,
            result.reasons,
        )
    except (TypeError, ValueError) as error:
        raise StoredLifecycleIntegrityError(
            f"stored partial comparison snapshot is invalid: reason={error}"
        ) from None


def _completed_observation_ids(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    segments: tuple[IntegerRangeFingerprintPersistence, ...],
) -> tuple[UUID, UUID]:
    if segments:
        return (
            segments[0].reference_observation_id,
            segments[0].target_observation_id,
        )
    rows = _select_observation_rows_by_attempt(connection, result.run_id, result.attempt_id)
    if len(rows) != 2:
        raise StoredLifecycleIntegrityError(
            "completed structural comparison requires one observation per direction"
        )
    if (
        _row_text(rows[0][6], "completed reference observation direction")
        != PlanDirection.REFERENCE.value
        or _row_text(rows[1][6], "completed target observation direction")
        != PlanDirection.TARGET.value
    ):
        raise StoredLifecycleIntegrityError(
            "completed structural observations are not ordered reference then target"
        )
    return (
        _row_uuid(rows[0][0], "completed reference observation id"),
        _row_uuid(rows[1][0], "completed target observation id"),
    )


def _anomalies_from_database(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    observation_ids: tuple[UUID, UUID],
    manifest_digest: bytes | None,
) -> tuple[DifferenceRecord, ...]:
    operation_id = result.persistence.operation_id
    if operation_id is None:
        raise StoredLifecycleIntegrityError("stored result has no persistence operation id")
    _require_attempt_anomaly_parent_closure(connection, result.run_id, result.attempt_id)
    _require_exact_result_parent(connection, result, operation_id)
    rows = _select_anomaly_rows_by_attempt(
        connection,
        result.run_id,
        result.attempt_id,
        result.check_id,
    )
    if manifest_digest is None:
        if rows:
            raise StoredLifecycleIntegrityError(
                "historical result without an evidence manifest contains anomaly rows"
            )
        if (
            result.evidence_coverage.retained_records != 0
            or result.evidence_coverage.retained_bytes != 0
        ):
            raise StoredLifecycleIntegrityError(
                "historical result without an evidence manifest claims retained evidence"
            )
        return ()
    if len(manifest_digest) != 32:
        raise StoredLifecycleIntegrityError("stored evidence manifest digest is not SHA-256")
    expectations = tuple(
        _anomaly_from_row(row, result, operation_id, observation_ids) for row in rows
    )
    records = tuple(item.record for item in expectations)
    try:
        _validate_anomaly_coverage(result.evidence_coverage, records)
    except (TypeError, ValueError) as error:
        raise StoredLifecycleIntegrityError(
            f"stored anomaly coverage is invalid: reason={error}"
        ) from None
    if _evidence_manifest_digest(expectations) != manifest_digest:
        raise StoredLifecycleIntegrityError(
            "stored anomaly record digests do not close to the evidence manifest"
        )
    return records


def _anomaly_manifest_summary_from_database(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    manifest_digest: bytes | None,
) -> _AnomalyManifestSummary:
    operation_id = result.persistence.operation_id
    if operation_id is None:
        raise StoredLifecycleIntegrityError("stored result has no persistence operation id")
    _require_attempt_anomaly_parent_closure(connection, result.run_id, result.attempt_id)
    _require_exact_result_parent(connection, result, operation_id)
    cursor = connection.execute(
        "SELECT anomaly_sequence, payload_byte_length, record_digest, end_operation_id "
        "FROM dfe_metadata.anomalies "
        "WHERE run_id = %s AND attempt_id = %s AND check_id = %s "
        "ORDER BY anomaly_sequence",
        (result.run_id, result.attempt_id, result.check_id),
    )
    digest = hashlib.sha256()
    digest.update(b'{"manifest_version":1,"record_digests":[')
    retained_records = 0
    retained_bytes = 0
    for row in cursor:
        sequence = _row_integer(row[0], "anomaly manifest sequence")
        if sequence != retained_records:
            raise StoredLifecycleIntegrityError(
                "stored anomaly manifest sequences are not contiguous from zero"
            )
        payload_byte_length = _row_integer(row[1], "anomaly manifest payload byte length")
        if payload_byte_length <= 0:
            raise StoredLifecycleIntegrityError(
                "stored anomaly manifest contains a nonpositive payload length"
            )
        record_digest = _row_bytes(row[2], "anomaly manifest record digest")
        if len(record_digest) != 32:
            raise StoredLifecycleIntegrityError(
                "stored anomaly manifest contains a non-SHA-256 record digest"
            )
        if _row_uuid(row[3], "anomaly manifest operation id") != operation_id:
            raise StoredLifecycleIntegrityError(
                "stored anomaly manifest contains a different result operation identity"
            )
        if retained_records:
            digest.update(b",")
        digest.update(b'"')
        digest.update(record_digest.hex().encode("ascii"))
        digest.update(b'"')
        retained_records += 1
        retained_bytes += payload_byte_length
    digest.update(b"]}")
    coverage = result.evidence_coverage
    if retained_records != coverage.retained_records or retained_bytes != coverage.retained_bytes:
        raise StoredLifecycleIntegrityError(
            "stored anomaly manifest counts or bytes differ from evidence coverage"
        )
    if manifest_digest is None:
        if retained_records != 0:
            raise StoredLifecycleIntegrityError(
                "historical result without an evidence manifest contains anomaly rows"
            )
        return _AnomalyManifestSummary(
            retained_records=retained_records,
            retained_bytes=retained_bytes,
            manifest_digest=None,
        )
    if len(manifest_digest) != 32:
        raise StoredLifecycleIntegrityError("stored evidence manifest digest is not SHA-256")
    if digest.digest() != manifest_digest:
        raise StoredLifecycleIntegrityError(
            "stored anomaly record digests do not close to the evidence manifest"
        )
    return _AnomalyManifestSummary(
        retained_records=retained_records,
        retained_bytes=retained_bytes,
        manifest_digest=manifest_digest,
    )


def _anomaly_page_from_database(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    observation_ids: tuple[UUID, UUID],
    after_sequence: int,
    limit: int,
) -> tuple[DifferenceRecord, ...]:
    operation_id = result.persistence.operation_id
    if operation_id is None:
        raise StoredLifecycleIntegrityError("stored result has no persistence operation id")
    rows = _select_anomaly_page_rows(
        connection,
        result,
        after_sequence,
        limit,
    )
    records = tuple(
        _anomaly_from_row(row, result, operation_id, observation_ids).record for row in rows
    )
    if records and records[0].sequence != after_sequence + 1:
        raise StoredLifecycleIntegrityError(
            "stored anomaly keyset page does not begin at the next retained sequence"
        )
    if tuple(record.sequence for record in records) != tuple(
        range(after_sequence + 1, after_sequence + 1 + len(records))
    ):
        raise StoredLifecycleIntegrityError(
            "stored anomaly keyset page is not contiguous in ascending sequence order"
        )
    return records


def _anomaly_from_row(
    row: DatabaseRow,
    result: RunResult,
    operation_id: UUID,
    observation_ids: tuple[UUID, UUID],
) -> _AnomalyExpectation:
    if len(row) != 16:
        raise StoredLifecycleIntegrityError(
            f"PostgreSQL anomaly row has an invalid column count: actual={len(row)}, expected=16"
        )
    payload_json = _canonical_database_json(row[12], "anomaly evidence payload")
    try:
        record = DifferenceRecord.model_validate_json(payload_json)
        replay_json = canonical_difference_record_bytes(record).decode("utf-8", errors="strict")
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored anomaly violates the public evidence protocol: reason={error}"
        ) from None
    if replay_json != payload_json:
        raise StoredLifecycleIntegrityError(
            "stored anomaly payload contains unsupported or non-round-trippable fields"
        )
    expected = _anomaly_expectations(
        result.run_id,
        result.attempt_id,
        result.check_id,
        operation_id,
        observation_ids[0],
        observation_ids[1],
        (record,),
    )[0]
    key_digest = _row_optional_bytes(row[7], "anomaly key digest")
    actual_closure = (
        _row_uuid(row[0], "anomaly run id"),
        _row_uuid(row[1], "anomaly attempt id"),
        _row_text(row[2], "anomaly check id"),
        _row_uuid(row[3], "anomaly end operation id"),
        _row_integer(row[4], "anomaly sequence"),
        _row_integer(row[5], "anomaly segment sequence"),
        _row_text(row[6], "anomaly kind"),
        key_digest.hex() if key_digest is not None else None,
        _row_uuid(row[8], "anomaly reference observation id"),
        _row_text(row[9], "anomaly reference direction"),
        _row_uuid(row[10], "anomaly target observation id"),
        _row_text(row[11], "anomaly target direction"),
        _row_bytes(row[13], "anomaly payload digest"),
        _row_integer(row[14], "anomaly payload byte length"),
        _row_bytes(row[15], "anomaly record digest"),
    )
    expected_closure = (
        result.run_id,
        result.attempt_id,
        result.check_id,
        operation_id,
        record.sequence,
        record.segment_sequence,
        record.kind.value,
        record.key_digest,
        observation_ids[0],
        PlanDirection.REFERENCE.value,
        observation_ids[1],
        PlanDirection.TARGET.value,
        expected.payload_digest,
        expected.payload_byte_length,
        expected.record_digest,
    )
    if actual_closure != expected_closure:
        raise StoredLifecycleIntegrityError(
            "stored anomaly columns differ from its canonical evidence payload and closure"
        )
    return expected


def _require_exact_result_parent(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    operation_id: UUID,
) -> None:
    row = connection.execute(
        "SELECT "
        "(SELECT pg_catalog.count(*) FROM dfe_metadata.check_results "
        "WHERE run_id = %s AND attempt_id = %s AND check_id = %s "
        "AND result_operation_id = %s), "
        "(SELECT pg_catalog.count(*) FROM dfe_metadata.partial_check_results "
        "WHERE run_id = %s AND attempt_id = %s AND check_id = %s "
        "AND end_operation_id = %s)",
        (
            result.run_id,
            result.attempt_id,
            result.check_id,
            operation_id,
            result.run_id,
            result.attempt_id,
            result.check_id,
            operation_id,
        ),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("stored result parent count query returned no row")
    completed_count = _row_integer(row[0], "completed anomaly parent count")
    partial_count = _row_integer(row[1], "partial anomaly parent count")
    if completed_count + partial_count != 1:
        raise StoredLifecycleIntegrityError(
            "anomaly result identity requires exactly one completed or partial parent"
        )


def _require_attempt_anomaly_parent_closure(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
) -> None:
    row = connection.execute(
        "SELECT pg_catalog.count(*) FROM dfe_metadata.anomalies AS dfe_anomaly "
        "LEFT JOIN dfe_metadata.check_results AS dfe_completed "
        "ON dfe_completed.run_id = dfe_anomaly.run_id "
        "AND dfe_completed.attempt_id = dfe_anomaly.attempt_id "
        "AND dfe_completed.check_id = dfe_anomaly.check_id "
        "AND dfe_completed.result_operation_id = dfe_anomaly.end_operation_id "
        "LEFT JOIN dfe_metadata.partial_check_results AS dfe_partial "
        "ON dfe_partial.run_id = dfe_anomaly.run_id "
        "AND dfe_partial.attempt_id = dfe_anomaly.attempt_id "
        "AND dfe_partial.check_id = dfe_anomaly.check_id "
        "AND dfe_partial.end_operation_id = dfe_anomaly.end_operation_id "
        "WHERE dfe_anomaly.run_id = %s AND dfe_anomaly.attempt_id = %s "
        "AND ((dfe_completed.attempt_id IS NULL) = (dfe_partial.attempt_id IS NULL))",
        (run_id, attempt_id),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("anomaly parent closure query returned no row")
    if _row_integer(row[0], "invalid anomaly parent count") != 0:
        raise StoredLifecycleIntegrityError(
            "every anomaly must have exactly one completed or partial result parent"
        )


def _comparison_evidence_boundary_from_database(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
) -> _ComparisonEvidenceBoundary:
    row = connection.execute(
        "SELECT dfe_run.request_identity_digest, dfe_run.request_payload::text, "
        "dfe_run.contract_version_id, dfe_run.scope_digest, "
        "dfe_contract.contract_version_id, dfe_contract.check_id, "
        "dfe_contract.semantic_digest, dfe_contract.comparison_schema_digest, "
        "dfe_contract.semantic_payload::text, dfe_contract.resolved_definition::text, "
        "dfe_reference.dataset_version_id, dfe_reference.dataset_id, "
        "dfe_reference.semantic_digest, dfe_reference.connection_id, "
        "dfe_reference.locator_kind, dfe_reference.semantic_payload::text, "
        "dfe_target.dataset_version_id, dfe_target.dataset_id, "
        "dfe_target.semantic_digest, dfe_target.connection_id, "
        "dfe_target.locator_kind, dfe_target.semantic_payload::text "
        "FROM dfe_metadata.runs AS dfe_run "
        "JOIN dfe_metadata.contract_versions AS dfe_contract "
        "ON dfe_contract.contract_version_id = dfe_run.contract_version_id "
        "JOIN dfe_metadata.dataset_versions AS dfe_reference "
        "ON dfe_reference.dataset_version_id = dfe_contract.reference_dataset_version_id "
        "JOIN dfe_metadata.dataset_versions AS dfe_target "
        "ON dfe_target.dataset_version_id = dfe_contract.target_dataset_version_id "
        "WHERE dfe_run.run_id = %s",
        (result.run_id,),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError(
            "comparison context metadata is missing for the requested result"
        )
    request_json = _canonical_database_json(row[1], "comparison context run request")
    contract_json = _canonical_database_json(row[8], "comparison context contract")
    contract_resolved_json = _canonical_database_json(
        row[9],
        "comparison context resolved contract",
    )
    reference_json = _canonical_database_json(row[15], "comparison context reference dataset")
    target_json = _canonical_database_json(row[21], "comparison context target dataset")
    request_value = _semantic_object(
        semantic_value_from_json(request_json),
        "comparison context run request",
    )
    contract_value = _semantic_object(
        semantic_value_from_json(contract_json),
        "comparison context contract",
    )
    reference_value = _semantic_object(
        semantic_value_from_json(reference_json),
        "comparison context reference dataset",
    )
    target_value = _semantic_object(
        semantic_value_from_json(target_json),
        "comparison context target dataset",
    )
    if (
        bytes.fromhex(semantic_digest_hex(request_value))
        != _row_bytes(row[0], "comparison context request identity digest")
        or bytes.fromhex(semantic_digest_hex(contract_value))
        != _row_bytes(row[6], "comparison context contract digest")
        or bytes.fromhex(semantic_digest_hex(reference_value))
        != _row_bytes(row[12], "comparison context reference dataset digest")
        or bytes.fromhex(semantic_digest_hex(target_value))
        != _row_bytes(row[18], "comparison context target dataset digest")
    ):
        raise StoredLifecycleIntegrityError(
            "comparison context immutable metadata digest closure is invalid"
        )
    contract_version_id = _row_uuid(row[2], "comparison context run contract version id")
    if contract_version_id != _row_uuid(row[4], "comparison context contract version id"):
        raise StoredLifecycleIntegrityError(
            "comparison context run references a different contract version"
        )
    if (
        _semantic_text(
            request_value.get("contract_version_id"),
            "comparison context request contract version id",
        )
        != str(contract_version_id)
        or _row_text(row[5], "comparison context check id") != result.check_id
        or _row_bytes(row[6], "comparison context contract digest").hex() != result.contract_digest
        or _row_bytes(row[3], "comparison context run scope digest").hex() != result.scope_digest
    ):
        raise StoredLifecycleIntegrityError(
            "comparison context identity differs from the stored result"
        )
    direction = _semantic_object(
        contract_value.get("direction"),
        "comparison context contract direction",
    )
    reference_body = _semantic_object(
        reference_value.get("dataset"),
        "comparison context reference dataset body",
    )
    target_body = _semantic_object(
        target_value.get("dataset"),
        "comparison context target dataset body",
    )
    if direction.get("reference") != reference_body or direction.get("target") != target_body:
        raise StoredLifecycleIntegrityError(
            "comparison context contract directions differ from their dataset versions"
        )
    reference = _comparison_side_from_semantics(
        row,
        10,
        11,
        13,
        14,
        reference_body,
        ComparisonDirection.REFERENCE,
    )
    target = _comparison_side_from_semantics(
        row,
        16,
        17,
        19,
        20,
        target_body,
        ComparisonDirection.TARGET,
    )
    _require_request_batch_context(request_value, reference, target)
    scope = _comparison_scope_from_semantics(request_value, contract_value, result.scope_digest)
    comparison_fields, ordered_key = _comparison_schema_from_semantics(
        contract_value,
        contract_resolved_json,
        _row_bytes(row[7], "comparison context schema digest").hex(),
    )
    try:
        context = ComparisonContext(
            reference=reference,
            target=target,
            scope=scope,
            comparison_fields=comparison_fields,
            ordered_key=ordered_key,
        )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored comparison context violates the reporting protocol: reason={error}"
        ) from None
    return _ComparisonEvidenceBoundary(
        context=context,
        actions=_evidence_actions_from_request(request_value, context),
    )


def _evidence_actions_from_request(
    request: dict[str, SemanticValue],
    context: ComparisonContext,
) -> tuple[EvidenceAction, ...]:
    policy = _semantic_object(
        request.get("evidence_policy"),
        "comparison context evidence policy",
    )
    rules = _semantic_array(
        policy.get("field_rules"),
        "comparison context evidence field rules",
    )
    overrides: dict[str, EvidenceAction] = {}
    try:
        default_action = EvidenceAction(
            _semantic_text(
                policy.get("unspecified_fields"),
                "comparison context unspecified evidence action",
            )
        )
        for index, item in enumerate(rules):
            rule = _semantic_object(item, f"comparison context evidence rule {index}")
            field_name = _semantic_text(
                rule.get("field_name"),
                f"comparison context evidence rule {index} field",
            )
            if field_name in overrides:
                raise StoredLifecycleIntegrityError(
                    "comparison context evidence policy contains duplicate field rules"
                )
            overrides[field_name] = EvidenceAction(
                _semantic_text(
                    rule.get("action"),
                    f"comparison context evidence rule {index} action",
                )
            )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored comparison evidence policy is invalid: reason={error}"
        ) from None
    field_names = tuple(field.field_name for field in context.comparison_fields)
    unknown = tuple(name for name in overrides if name not in set(field_names))
    if unknown:
        raise StoredLifecycleIntegrityError(
            "comparison context evidence policy references fields outside the comparison schema"
        )
    return tuple(overrides.get(name, default_action) for name in field_names)


def _comparison_side_from_semantics(
    row: DatabaseRow,
    version_id_index: int,
    dataset_id_index: int,
    connection_id_index: int,
    locator_kind_index: int,
    body: dict[str, SemanticValue],
    direction: ComparisonDirection,
) -> ComparisonSideIdentity:
    dataset_id = _row_text(row[dataset_id_index], f"{direction.value} dataset id")
    connection_id = _row_text(
        row[connection_id_index],
        f"{direction.value} connection id",
    )
    if _row_uuid(row[version_id_index], f"{direction.value} dataset version id").int == 0:
        raise StoredLifecycleIntegrityError("dataset version UUID cannot be nil")
    connection = _semantic_object(
        body.get("connection"),
        f"comparison context {direction.value} connection",
    )
    if (
        _semantic_text(body.get("dataset_id"), f"{direction.value} payload dataset id")
        != dataset_id
        or _semantic_text(
            connection.get("connection_id"),
            f"{direction.value} payload connection id",
        )
        != connection_id
    ):
        raise StoredLifecycleIntegrityError(
            f"comparison context {direction.value} dataset columns differ from its payload"
        )
    locator = _semantic_object(
        body.get("locator"),
        f"comparison context {direction.value} locator",
    )
    locator_kind = _row_text(
        row[locator_kind_index],
        f"{direction.value} locator kind",
    )
    if _semantic_text(locator.get("kind"), f"{direction.value} payload locator kind") != (
        locator_kind
    ):
        raise StoredLifecycleIntegrityError(
            f"comparison context {direction.value} locator kind differs from its payload"
        )
    if locator_kind == DatasetLocatorKind.RELATION.value:
        catalog_value = locator.get("catalog")
        catalog = (
            None
            if catalog_value is None
            else _semantic_text(
                catalog_value,
                f"{direction.value} relation catalog",
            )
        )
        try:
            public_locator = RelationComparisonLocator(
                locator_type="relation",
                catalog=catalog,
                schema=_semantic_text(locator.get("schema"), f"{direction.value} schema"),
                name=_semantic_text(locator.get("name"), f"{direction.value} relation"),
                relation_scope=RelationScope(
                    _semantic_text(
                        locator.get("relation_scope"),
                        f"{direction.value} relation scope",
                    )
                ),
            )
        except ValueError as error:
            raise StoredLifecycleIntegrityError(
                f"stored {direction.value} relation locator is invalid: reason={error}"
            ) from None
    elif locator_kind == DatasetLocatorKind.SQL.value:
        try:
            public_locator = SqlComparisonLocator(
                locator_type="sql",
                dialect=SqlDialect(
                    _semantic_text(locator.get("dialect"), f"{direction.value} SQL dialect")
                ),
                content_sha256=_semantic_text(
                    locator.get("content_sha256"),
                    f"{direction.value} SQL content digest",
                ),
            )
        except ValueError as error:
            raise StoredLifecycleIntegrityError(
                f"stored {direction.value} SQL locator is invalid: reason={error}"
            ) from None
    else:
        raise StoredLifecycleIntegrityError(f"stored {direction.value} locator kind is unsupported")
    return ComparisonSideIdentity(
        direction=direction,
        connection_id=connection_id,
        dataset_id=dataset_id,
        locator=public_locator,
    )


def _require_request_batch_context(
    request: dict[str, SemanticValue],
    reference: ComparisonSideIdentity,
    target: ComparisonSideIdentity,
) -> None:
    batches = _semantic_array(
        request.get("expected_batches"),
        "comparison context expected batches",
    )
    if len(batches) != 2:
        raise StoredLifecycleIntegrityError(
            "comparison context request requires two expected batches"
        )
    for item, side in zip(batches, (reference, target), strict=True):
        batch = _semantic_object(item, f"comparison context {side.direction.value} batch")
        if (
            _semantic_text(batch.get("direction"), "comparison context batch direction")
            != side.direction.value
            or _semantic_text(batch.get("dataset_id"), "comparison context batch dataset")
            != side.dataset_id
        ):
            raise StoredLifecycleIntegrityError(
                "comparison context expected batch differs from its dataset direction"
            )


def _comparison_scope_from_semantics(
    request: dict[str, SemanticValue],
    contract: dict[str, SemanticValue],
    scope_digest: str,
) -> tuple[ComparisonScopeValue, ...]:
    request_scope = _semantic_object(request.get("scope"), "comparison context request scope")
    if semantic_digest_hex(request_scope) != scope_digest:
        raise StoredLifecycleIntegrityError(
            "comparison context request scope differs from the run scope digest"
        )
    contract_scope = _semantic_object(
        contract.get("scope"),
        "comparison context contract scope",
    )
    request_parameters = _semantic_array(
        request_scope.get("parameters"),
        "comparison context request scope parameters",
    )
    declared_parameters = _semantic_array(
        contract_scope.get("parameters"),
        "comparison context declared scope parameters",
    )
    if len(request_parameters) != len(declared_parameters):
        raise StoredLifecycleIntegrityError(
            "comparison context resolved scope count differs from its contract declaration"
        )
    values: list[ComparisonScopeValue] = []
    for index, (request_item, declared_item) in enumerate(
        zip(request_parameters, declared_parameters, strict=True)
    ):
        resolved = _semantic_object(request_item, f"resolved scope parameter {index}")
        declared = _semantic_object(declared_item, f"declared scope parameter {index}")
        name = _semantic_text(resolved.get("name"), f"resolved scope parameter {index} name")
        if name != _semantic_text(
            declared.get("name"),
            f"declared scope parameter {index} name",
        ):
            raise StoredLifecycleIntegrityError(
                "comparison context resolved scope order differs from its contract"
            )
        field = _scope_field_from_semantics(
            name,
            _semantic_object(resolved.get("type"), f"resolved scope parameter {name} type"),
        )
        if _scope_field_signature(field) != _declared_scope_type_signature(
            _semantic_object(declared.get("type"), f"declared scope parameter {name} type")
        ):
            raise StoredLifecycleIntegrityError(
                f"comparison context scope parameter {name!r} type differs from its contract"
            )
        payload_hex = _semantic_text(
            resolved.get("payload_hex"),
            f"resolved scope parameter {name} payload",
        )
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError:
            raise StoredLifecycleIntegrityError(
                f"comparison context scope parameter {name!r} payload is not hexadecimal"
            ) from None
        if payload.hex() != payload_hex:
            raise StoredLifecycleIntegrityError(
                f"comparison context scope parameter {name!r} payload is not lowercase hex"
            )
        decoded = decode_payload(field, payload)
        if decoded is True:
            canonical_value = "true"
        elif decoded is False:
            canonical_value = "false"
        elif isinstance(decoded, (date, datetime)):
            canonical_value = decoded.isoformat()
        else:
            canonical_value = str(decoded)
        values.append(
            ComparisonScopeValue(
                name=name,
                logical_type=field.logical_type,
                canonical_value=canonical_value,
            )
        )
    return tuple(values)


def _scope_field_from_semantics(
    name: str,
    value: dict[str, SemanticValue],
) -> FieldSchema:
    try:
        logical_type = LogicalType(_semantic_text(value.get("kind"), "scope logical type"))
        normalization = Normalization(
            _semantic_text(value.get("normalization"), "scope normalization")
        )
        if logical_type is LogicalType.DECIMAL:
            parameters = DecimalParameters(
                precision=_semantic_integer(value.get("precision"), "scope decimal precision"),
                scale=_semantic_integer(value.get("scale"), "scope decimal scale"),
            )
        elif logical_type in (LogicalType.TIMESTAMP_LOCAL, LogicalType.TIMESTAMP_INSTANT):
            parameters = TimestampParameters(
                precision=_semantic_integer(
                    value.get("precision"),
                    "scope timestamp precision",
                )
            )
        else:
            parameters = NoParameters()
        return FieldSchema(
            name=name,
            logical_type=logical_type,
            nullable=False,
            parameters=parameters,
            normalization=normalization,
        )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored resolved scope type is invalid: reason={error}"
        ) from None


def _scope_field_signature(
    field: FieldSchema,
) -> tuple[LogicalType, int | None, int | None, int | None]:
    if isinstance(field.parameters, DecimalParameters):
        return (
            field.logical_type,
            field.parameters.precision,
            field.parameters.scale,
            None,
        )
    if isinstance(field.parameters, TimestampParameters):
        return (field.logical_type, None, None, field.parameters.precision)
    return (field.logical_type, None, None, None)


def _declared_scope_type_signature(
    value: dict[str, SemanticValue],
) -> tuple[LogicalType, int | None, int | None, int | None]:
    try:
        logical_type = LogicalType(_semantic_text(value.get("kind"), "declared scope logical type"))
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored declared scope type is invalid: reason={error}"
        ) from None
    if _semantic_text(value.get("normalization"), "declared scope normalization") != (
        Normalization.NONE.value
    ):
        raise StoredLifecycleIntegrityError("declared scope normalization is unsupported")
    parameters = _semantic_object(value.get("parameters"), "declared scope type parameters")
    if logical_type is LogicalType.DECIMAL:
        return (
            logical_type,
            _semantic_integer(parameters.get("precision"), "declared decimal precision"),
            _semantic_integer(parameters.get("scale"), "declared decimal scale"),
            None,
        )
    if logical_type in (LogicalType.TIMESTAMP_LOCAL, LogicalType.TIMESTAMP_INSTANT):
        return (
            logical_type,
            None,
            None,
            _semantic_integer(parameters.get("precision"), "declared timestamp precision"),
        )
    if parameters:
        raise StoredLifecycleIntegrityError(
            "declared non-parameterized scope type contains parameters"
        )
    return (logical_type, None, None, None)


def _comparison_schema_from_semantics(
    contract: dict[str, SemanticValue],
    resolved_contract_json: str,
    expected_digest: str,
) -> tuple[tuple[ComparisonField, ...], tuple[str, ...]]:
    resolved = _semantic_object(
        semantic_value_from_json(resolved_contract_json),
        "comparison context resolved contract",
    )
    schema_value = resolved.get("comparison_schema")
    schema_json = canonical_semantic_json(schema_value)
    try:
        schema = schema_from_metadata_json(schema_json)
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored comparison schema is invalid: reason={error}"
        ) from None
    if schema_digest_hex(schema) != expected_digest:
        raise StoredLifecycleIntegrityError(
            "stored comparison schema differs from its immutable digest"
        )
    contract_schema = _semantic_object(
        contract.get("logical_schema"),
        "comparison context contract logical schema",
    )
    if (
        _semantic_text(
            contract_schema.get("logical_schema_digest"),
            "comparison context contract schema digest",
        )
        != expected_digest
    ):
        raise StoredLifecycleIntegrityError(
            "contract logical schema digest differs from its resolved schema"
        )
    fields = tuple(_comparison_field(field) for field in schema.fields)
    ordered_key = tuple(
        _semantic_text(item, f"comparison context key item {index}")
        for index, item in enumerate(
            _semantic_array(contract.get("key"), "comparison context ordered key")
        )
    )
    field_names = {field.field_name for field in fields}
    if not ordered_key or len(set(ordered_key)) != len(ordered_key):
        raise StoredLifecycleIntegrityError("comparison context ordered key is invalid")
    if any(name not in field_names for name in ordered_key):
        raise StoredLifecycleIntegrityError(
            "comparison context ordered key references an unknown comparison field"
        )
    if canonical_schema_json(schema) != schema_json:
        raise StoredLifecycleIntegrityError("stored comparison schema contains unsupported fields")
    return fields, ordered_key


def _comparison_field(field: FieldSchema) -> ComparisonField:
    if isinstance(field.parameters, DecimalParameters):
        decimal_precision = field.parameters.precision
        decimal_scale = field.parameters.scale
        timestamp_precision = None
    elif isinstance(field.parameters, TimestampParameters):
        decimal_precision = None
        decimal_scale = None
        timestamp_precision = field.parameters.precision
    else:
        decimal_precision = None
        decimal_scale = None
        timestamp_precision = None
    return ComparisonField(
        field_name=field.name,
        logical_type=field.logical_type,
        decimal_precision=decimal_precision,
        decimal_scale=decimal_scale,
        timestamp_precision=timestamp_precision,
    )


def _validate_anomaly_schema(
    anomalies: tuple[DifferenceRecord, ...],
    context: ComparisonContext,
) -> None:
    fields = {field.field_name: field for field in context.comparison_fields}
    ordered_fields = tuple(field.field_name for field in context.comparison_fields)
    for anomaly in anomalies:
        groups = (anomaly.key_values, anomaly.reference_values, anomaly.target_values)
        for group in groups:
            group_names = tuple(value.field_name for value in group)
            if group_names != tuple(name for name in ordered_fields if name in group_names):
                raise StoredLifecycleIntegrityError(
                    "stored anomaly fields do not follow comparison schema order"
                )
            for value in group:
                expected = fields.get(value.field_name)
                if expected is None or (
                    value.logical_type,
                    value.decimal_precision,
                    value.decimal_scale,
                    value.timestamp_precision,
                ) != (
                    expected.logical_type,
                    expected.decimal_precision,
                    expected.decimal_scale,
                    expected.timestamp_precision,
                ):
                    raise StoredLifecycleIntegrityError(
                        "stored anomaly field differs from the immutable comparison schema"
                    )
        if tuple(value.field_name for value in anomaly.key_values) not in (
            context.ordered_key,
            (),
        ):
            raise StoredLifecycleIntegrityError(
                "stored anomaly key fields differ from the immutable ordered key"
            )
        if tuple(anomaly.omitted_field_names) != tuple(
            name for name in ordered_fields if name in anomaly.omitted_field_names
        ):
            raise StoredLifecycleIntegrityError(
                "stored anomaly omitted fields do not follow comparison schema order"
            )
        if any(name not in fields for name in anomaly.omitted_field_names):
            raise StoredLifecycleIntegrityError(
                "stored anomaly omits a field outside the comparison schema"
            )


def _validate_anomaly_evidence_boundary(
    anomalies: tuple[DifferenceRecord, ...],
    boundary: _ComparisonEvidenceBoundary,
) -> None:
    _validate_anomaly_schema(anomalies, boundary.context)
    fields = boundary.context.comparison_fields
    if len(fields) != len(boundary.actions):
        raise StoredLifecycleIntegrityError(
            "comparison evidence policy action count differs from its immutable schema"
        )
    actions = {
        field.field_name: action for field, action in zip(fields, boundary.actions, strict=True)
    }
    field_definitions = {field.field_name: field for field in fields}
    ordered_key = boundary.context.ordered_key
    ordered_key_set = set(ordered_key)
    expected_omitted = tuple(
        field.field_name
        for field, action in zip(fields, boundary.actions, strict=True)
        if action is EvidenceAction.OMIT
    )
    expected_key_fields = tuple(
        name for name in ordered_key if actions[name] is not EvidenceAction.OMIT
    )
    expected_side_fields = tuple(
        field.field_name
        for field, action in zip(fields, boundary.actions, strict=True)
        if field.field_name not in ordered_key_set and action is not EvidenceAction.OMIT
    )
    all_key_fields_stored = all(actions[name] is EvidenceAction.STORE for name in ordered_key)
    for anomaly in anomalies:
        if anomaly.omitted_field_names != expected_omitted:
            raise StoredLifecycleIntegrityError(
                "stored anomaly omitted fields differ from the immutable evidence policy"
            )
        _require_evidence_group_policy(
            anomaly.key_values,
            expected_key_fields,
            actions,
            field_definitions,
            "key",
        )
        reference_fields = () if anomaly.kind is DifferenceKind.EXTRA else expected_side_fields
        target_fields = () if anomaly.kind is DifferenceKind.MISSING else expected_side_fields
        _require_evidence_group_policy(
            anomaly.reference_values,
            reference_fields,
            actions,
            field_definitions,
            "reference",
        )
        _require_evidence_group_policy(
            anomaly.target_values,
            target_fields,
            actions,
            field_definitions,
            "target",
        )
        if all_key_fields_stored:
            if any(value.is_null for value in anomaly.key_values):
                raise StoredLifecycleIntegrityError(
                    "stored anomaly cannot retain a NULL ordered-key component"
                )
            expected_key_digest = hashlib.sha256(
                canonical_difference_key_bytes(anomaly.key_values)
            ).hexdigest()
            if (
                anomaly.key_availability is not KeyAvailability.AVAILABLE
                or anomaly.key_digest != expected_key_digest
            ):
                raise StoredLifecycleIntegrityError(
                    "stored anomaly key digest differs from its policy-safe retained key"
                )
        elif (
            anomaly.key_availability is not KeyAvailability.KEYSET_UNAVAILABLE
            or anomaly.key_digest is not None
        ):
            raise StoredLifecycleIntegrityError(
                "stored anomaly exposes keyset availability forbidden by its evidence policy"
            )


def _require_evidence_group_policy(
    values: tuple[EvidenceFieldValue, ...],
    expected_fields: tuple[str, ...],
    actions: dict[str, EvidenceAction],
    field_definitions: dict[str, ComparisonField],
    direction: str,
) -> None:
    actual_fields = tuple(value.field_name for value in values)
    if actual_fields != expected_fields:
        raise StoredLifecycleIntegrityError(
            f"stored anomaly {direction} fields differ from the immutable evidence policy"
        )
    for value in values:
        action = actions[value.field_name]
        expected_availability = (
            EvidenceValueAvailability.STORED
            if action is EvidenceAction.STORE
            else EvidenceValueAvailability.REDACTED
        )
        if value.availability is not expected_availability:
            raise StoredLifecycleIntegrityError(
                f"stored anomaly {direction} representation differs from the immutable "
                "evidence policy"
            )
        if value.availability is EvidenceValueAvailability.STORED and not value.is_null:
            _require_canonical_evidence_value(value, field_definitions[value.field_name])


def _require_canonical_evidence_value(
    value: EvidenceFieldValue,
    field: ComparisonField,
) -> None:
    if value.canonical_text is None or value.canonical_hex is not None:
        raise StoredLifecycleIntegrityError(
            "stored non-NULL anomaly value requires its canonical text representation"
        )
    if field.logical_type is LogicalType.DECIMAL:
        if field.decimal_precision is None or field.decimal_scale is None:
            raise StoredLifecycleIntegrityError(
                "stored decimal anomaly field lacks immutable precision or scale"
            )
        parameters = DecimalParameters(
            precision=field.decimal_precision,
            scale=field.decimal_scale,
        )
    elif field.logical_type in (LogicalType.TIMESTAMP_LOCAL, LogicalType.TIMESTAMP_INSTANT):
        if field.timestamp_precision is None:
            raise StoredLifecycleIntegrityError(
                "stored timestamp anomaly field lacks immutable precision"
            )
        parameters = TimestampParameters(precision=field.timestamp_precision)
    else:
        parameters = NoParameters()
    schema_field = FieldSchema(
        name=field.field_name,
        logical_type=field.logical_type,
        nullable=True,
        parameters=parameters,
        normalization=Normalization.NONE,
    )
    text = value.canonical_text
    try:
        if field.logical_type is LogicalType.INT64:
            candidate: int | bool | str = int(text)
        elif field.logical_type is LogicalType.BOOLEAN:
            if text not in ("true", "false"):
                raise ValueError("boolean evidence text must be true or false")
            candidate = text == "true"
        else:
            candidate = text
        decoded = decode_payload(schema_field, encode_payload(schema_field, candidate))
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            "stored anomaly value is invalid for its immutable logical schema: "
            f"field={field.field_name!r}, reason={error}"
        ) from None
    if decoded is True:
        replay = "true"
    elif decoded is False:
        replay = "false"
    elif isinstance(decoded, Decimal):
        replay = format(decoded, "f")
    elif type(decoded) is date:
        replay = decoded.isoformat()
    else:
        replay = str(decoded)
    if replay != text:
        raise StoredLifecycleIntegrityError(
            "stored anomaly value is not canonical for its immutable logical schema: "
            f"field={field.field_name!r}"
        )


def _history_entry_from_row(
    connection: psycopg.Connection[DatabaseRow],
    row: DatabaseRow,
) -> HistoryEntry:
    if len(row) != 46:
        raise StoredLifecycleIntegrityError(
            f"PostgreSQL history row has an invalid column count: actual={len(row)}, expected=46"
        )
    run_id = _row_uuid(row[0], "history run id")
    attempt_id = _row_uuid(row[1], "history attempt id")
    _require_attempt_anomaly_parent_closure(connection, run_id, attempt_id)
    try:
        status = HistoryAttemptStatus(_row_text(row[3], "history attempt status"))
    except ValueError:
        raise StoredLifecycleIntegrityError(
            "stored history attempt status is unsupported"
        ) from None
    end_operation_id = _row_optional_uuid(row[4], "history attempt end operation id")
    started_at = _row_datetime(row[7], "history attempt started_at")
    ended_at = _row_optional_datetime(row[8], "history attempt ended_at")
    selected_attempt_id = _row_optional_uuid(row[9], "history selected terminal attempt id")
    check_id = _row_text(row[10], "history check id")
    contract_digest = _row_bytes(row[11], "history contract digest").hex()
    scope_digest = _row_bytes(row[12], "history scope digest").hex()
    completed_row = row[13:26]
    partial_row = row[26:46]
    result: RunResult | None = None
    terminal_reason: ResultReason | None = None
    availability = StoredResultAvailability.NOT_CREATED
    if status is HistoryAttemptStatus.RUNNING:
        if (
            end_operation_id is not None
            or row[5] is not None
            or row[6] is not None
            or ended_at is not None
        ):
            raise StoredLifecycleIntegrityError(
                "stored running history attempt unexpectedly has terminal fields"
            )
        if selected_attempt_id is not None:
            raise StoredLifecycleIntegrityError(
                "stored running history attempt belongs to an already terminal run"
            )
        if any(value is not None for value in (*completed_row, *partial_row)):
            raise StoredLifecycleIntegrityError(
                "stored running history attempt unexpectedly has a check result"
            )
    elif status is HistoryAttemptStatus.COMPLETED:
        if end_operation_id is None or ended_at is None:
            raise StoredLifecycleIntegrityError(
                "stored completed history attempt lacks terminal fields"
            )
        if row[5] is not None or row[6] is not None:
            raise StoredLifecycleIntegrityError(
                "stored completed history attempt unexpectedly has a terminal reason"
            )
        if any(value is None for value in completed_row[:12]):
            raise StoredLifecycleIntegrityError(
                "stored completed history attempt lacks its immutable result"
            )
        if any(value is not None for value in partial_row):
            raise StoredLifecycleIntegrityError(
                "stored completed history attempt also contains a partial result"
            )
        result, completed_at = _completed_result_from_row(completed_row)
        segments = _completed_segments_from_database(connection, run_id, attempt_id)
        _require_valid_stored_segments(result, segments)
        observation_ids = _completed_observation_ids(connection, result, segments)
        anomalies = _anomalies_from_database(
            connection,
            result,
            observation_ids,
            _row_optional_bytes(completed_row[12], "history evidence manifest digest"),
        )
        _validate_anomaly_evidence_boundary(
            anomalies,
            _comparison_evidence_boundary_from_database(connection, result),
        )
        _require_completed_database_closure(
            connection,
            result,
            segments,
            completed_at,
        )
        _require_completed_terminal_receipt(connection, result, completed_at)
        availability = StoredResultAvailability.AVAILABLE
    else:
        if end_operation_id is None or ended_at is None:
            raise StoredLifecycleIntegrityError(
                "stored noncompleted history attempt lacks terminal fields"
            )
        if any(value is not None for value in completed_row):
            raise StoredLifecycleIntegrityError(
                "stored noncompleted history attempt unexpectedly has a check result"
            )
        terminal_reason = _terminal_reason_from_database(row[5], row[6])
        if any(value is not None for value in partial_row):
            if any(value is None for value in partial_row):
                raise StoredLifecycleIntegrityError(
                    "stored history partial comparison row is incomplete"
                )
            (
                result,
                partial_ended_at,
                frontier,
                input_cut_digest,
                observation_ids,
                manifest_digest,
            ) = _partial_result_from_row(partial_row)
            anomalies = _anomalies_from_database(
                connection,
                result,
                observation_ids,
                manifest_digest,
            )
            _require_valid_stored_partial(result, frontier, observation_ids, anomalies)
            _validate_anomaly_evidence_boundary(
                anomalies,
                _comparison_evidence_boundary_from_database(connection, result),
            )
            _require_partial_database_closure(
                connection,
                result,
                frontier,
                input_cut_digest,
                observation_ids,
                partial_ended_at,
            )
            _require_partial_terminal_receipt(connection, result, partial_ended_at)
            availability = StoredResultAvailability.AVAILABLE
    try:
        entry = HistoryEntry(
            run_id=run_id,
            attempt_id=attempt_id,
            check_id=check_id,
            contract_digest=contract_digest,
            scope_digest=scope_digest,
            ordinal=_row_integer(row[2], "history attempt ordinal"),
            status=status,
            end_operation_id=end_operation_id,
            started_at=started_at,
            ended_at=ended_at,
            is_run_terminal=selected_attempt_id == attempt_id,
            terminal_reason=terminal_reason,
            stored_result_availability=availability,
            stored_result=result,
        )
    except ValueError as error:
        raise StoredLifecycleIntegrityError(
            f"stored history entry violates the public reporting protocol: reason={error}"
        ) from None
    if entry.status not in (
        HistoryAttemptStatus.RUNNING,
        HistoryAttemptStatus.COMPLETED,
    ):
        if (
            entry.end_operation_id is None
            or entry.ended_at is None
            or entry.terminal_reason is None
        ):
            raise AssertionError("validated noncompleted history entry has no reason")
        outcome = AttemptOutcomeRecord(
            run_id=entry.run_id,
            attempt_id=entry.attempt_id,
            status=AttemptStatus(entry.status.value),
            operation_id=entry.end_operation_id,
            reason=entry.terminal_reason,
            ended_at=entry.ended_at,
        )
        _require_stored_attempt_closure(connection, entry.run_id, entry.attempt_id)
        _require_terminal_attempt_run_binding(connection, outcome)
    return entry


def _terminal_reason_from_database(
    reason_code_value: object,
    reason_payload_value: object,
) -> ResultReason:
    reason_code_text = _row_optional_text(reason_code_value, "terminal reason code")
    reason_json = _row_optional_canonical_json(reason_payload_value, "terminal reason payload")
    if reason_code_text is None or reason_json is None:
        raise StoredLifecycleIntegrityError(
            "stored noncompleted attempt lacks its terminal reason code or payload"
        )
    try:
        reason_code = ReasonCode(reason_code_text)
        stored_value = _semantic_object(
            semantic_value_from_json(reason_json),
            "terminal reason payload",
        )
        if _semantic_integer(stored_value.get("reason_version"), "terminal reason version") != 1:
            raise StoredLifecycleIntegrityError("terminal reason version must be exactly 1")
        public_value: dict[str, SemanticValue] = {
            key: value for key, value in stored_value.items() if key != "reason_version"
        }
        public_value["code"] = reason_code.value
        reason = ResultReason.model_validate_json(canonical_semantic_json(public_value))
    except (ValueError, StoredLifecycleIntegrityError) as error:
        raise StoredLifecycleIntegrityError(
            f"stored terminal reason violates the public result protocol: reason={error}"
        ) from None
    if canonical_semantic_json(_reason_semantic_value(reason)) != reason_json:
        raise StoredLifecycleIntegrityError(
            "stored terminal reason contains unsupported or non-round-trippable fields"
        )
    return reason


def _attempt_outcome_from_stored_row(
    row: DatabaseRow,
    run_id: UUID,
    attempt_id: UUID,
) -> AttemptOutcomeRecord:
    if len(row) != 19:
        raise StoredLifecycleIntegrityError(
            f"PostgreSQL attempt row has an invalid column count: actual={len(row)}, expected=19"
        )
    if (
        _row_uuid(row[0], "terminal attempt id") != attempt_id
        or _row_uuid(row[1], "terminal attempt run id") != run_id
    ):
        raise StoredLifecycleIntegrityError(
            "stored terminal attempt identity differs from its lookup key"
        )
    try:
        status = AttemptStatus(_row_text(row[4], "terminal attempt status"))
    except ValueError:
        raise StoredLifecycleIntegrityError(
            "stored terminal attempt status is unsupported"
        ) from None
    if status not in (
        AttemptStatus.INCOMPLETE,
        AttemptStatus.ERROR,
        AttemptStatus.ABANDONED,
    ):
        raise RunLifecycleStateError(
            "requested attempt has no durable incomplete, error, or abandoned outcome"
        )
    operation_id = _row_optional_uuid(row[13], "terminal attempt operation id")
    ended_at = _row_optional_datetime(row[17], "terminal attempt ended_at")
    if operation_id is None or ended_at is None:
        raise StoredLifecycleIntegrityError(
            "stored terminal attempt lacks an operation id or end timestamp"
        )
    started_at = _row_datetime(row[16], "terminal attempt started_at")
    if ended_at < started_at:
        raise StoredLifecycleIntegrityError("stored terminal attempt ended before it started")
    reason = _terminal_reason_from_database(row[14], row[15])
    try:
        if status is AttemptStatus.INCOMPLETE:
            _validate_incomplete_reason(reason)
        elif status is AttemptStatus.ERROR:
            _validate_error_reason(reason)
        elif reason.code is not ReasonCode.SNAPSHOT_LOST:
            raise ValueError("abandoned attempt requires snapshot_lost reason")
        return AttemptOutcomeRecord(
            run_id=run_id,
            attempt_id=attempt_id,
            status=status,
            operation_id=operation_id,
            reason=reason,
            ended_at=ended_at,
        )
    except (TypeError, ValueError) as error:
        raise StoredLifecycleIntegrityError(
            f"stored terminal attempt violates the outcome protocol: reason={error}"
        ) from None


def _require_terminal_attempt_run_binding(
    connection: psycopg.Connection[DatabaseRow],
    outcome: AttemptOutcomeRecord,
) -> None:
    run_row = connection.execute(
        "SELECT selected_terminal_attempt_id, terminal_operation_id, terminal_at "
        "FROM dfe_metadata.runs WHERE run_id = %s",
        (outcome.run_id,),
    ).fetchone()
    if run_row is None:
        raise StoredLifecycleIntegrityError("terminal attempt run is missing")
    selected_attempt_id = _row_optional_uuid(run_row[0], "selected terminal attempt id")
    terminal_operation_id = _row_optional_uuid(run_row[1], "run terminal operation id")
    terminal_at = _row_optional_datetime(run_row[2], "run terminal_at")
    if selected_attempt_id is None:
        if terminal_operation_id is not None or terminal_at is not None:
            raise StoredLifecycleIntegrityError(
                "unterminated run contains a partial terminal publication identity"
            )
        return
    if terminal_operation_id is None or terminal_at is None:
        raise StoredLifecycleIntegrityError(
            "terminated run lacks its operation id or terminal timestamp"
        )
    if selected_attempt_id == outcome.attempt_id:
        if (
            terminal_operation_id != outcome.operation_id
            or terminal_at != outcome.ended_at
            or outcome.status is AttemptStatus.ABANDONED
        ):
            raise StoredLifecycleIntegrityError(
                "terminal attempt differs from its selected run publication"
            )
        return
    selected_row = connection.execute(
        "SELECT status, end_operation_id, ended_at FROM dfe_metadata.run_attempts "
        "WHERE run_id = %s AND attempt_id = %s",
        (outcome.run_id, selected_attempt_id),
    ).fetchone()
    if selected_row is None:
        raise StoredLifecycleIntegrityError("selected terminal run attempt is missing")
    selected_status = _row_text(selected_row[0], "selected terminal attempt status")
    if (
        selected_status
        not in (
            AttemptStatus.COMPLETED.value,
            AttemptStatus.INCOMPLETE.value,
            AttemptStatus.ERROR.value,
        )
        or _row_optional_uuid(selected_row[1], "selected terminal operation id")
        != terminal_operation_id
        or _row_optional_datetime(selected_row[2], "selected terminal ended_at") != terminal_at
    ):
        raise StoredLifecycleIntegrityError(
            "selected terminal attempt differs from its run publication"
        )


def _comparison_definition_from_result(result: RunResult) -> _CompletedResultDefinition:
    definition_type = (
        CompletedStructuralComparisonDefinition
        if result.guarantee is Guarantee.STRUCTURAL
        else CompletedComparisonDefinition
    )
    return definition_type(
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
    if len(rows) % 2 != 0:
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


def _require_locked_partial_comparison_closure(
    connection: psycopg.Connection[DatabaseRow],
    expected: _PartialComparisonExpectation,
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
    _require_partial_closure_rows(
        connection,
        expected.result,
        expected.comparison.frontier,
        expected.comparison.input_cut_digest,
        (
            expected.comparison.reference_observation_id,
            expected.comparison.target_observation_id,
        ),
        expected.ended_at,
        context_rows,
        observation_rows,
    )
    _validate_anomaly_evidence_boundary(
        tuple(anomaly.record for anomaly in expected.anomalies),
        _comparison_evidence_boundary_from_database(connection, expected.result),
    )


def _require_partial_database_closure(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    frontier: PartialComparisonFrontier,
    input_cut_digest: str,
    observation_ids: tuple[UUID, UUID],
    ended_at: datetime,
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
    _require_partial_closure_rows(
        connection,
        result,
        frontier,
        input_cut_digest,
        observation_ids,
        ended_at,
        context_rows,
        observation_rows,
    )


def _require_partial_closure_rows(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    frontier: PartialComparisonFrontier,
    input_cut_digest: str,
    observation_ids: tuple[UUID, UUID],
    ended_at: datetime,
    context_rows: list[DatabaseRow],
    observation_rows: list[DatabaseRow],
) -> None:
    if len(context_rows) != 2:
        raise RunLifecycleStateError(
            "partial comparison requires exactly two protected read contexts"
        )
    reference_context, target_context = context_rows
    if (
        _row_text(reference_context[4], "partial reference context direction")
        != PlanDirection.REFERENCE.value
        or _row_text(target_context[4], "partial target context direction")
        != PlanDirection.TARGET.value
    ):
        raise StoredLifecycleIntegrityError(
            "partial comparison contexts lack one reference and one target direction"
        )
    context_ids = (
        _row_uuid(reference_context[0], "partial reference context id"),
        _row_uuid(target_context[0], "partial target context id"),
    )
    if result.consistency.read_context_ids != context_ids:
        raise RunLifecycleStateError(
            "partial result context ids must be ordered reference then target"
        )
    context_ended_at = (
        _require_terminal_partial_context(
            reference_context,
            result,
            PlanDirection.REFERENCE,
            ended_at,
        ),
        _require_terminal_partial_context(
            target_context,
            result,
            PlanDirection.TARGET,
            ended_at,
        ),
    )
    if len(observation_rows) != 2:
        raise RunLifecycleStateError(
            "partial comparison requires exactly two bound-cut observations"
        )
    attempt_row = connection.execute(
        "SELECT input_cut_digest, execution_budgets::text FROM dfe_metadata.run_attempts "
        "WHERE run_id = %s AND attempt_id = %s",
        (result.run_id, result.attempt_id),
    ).fetchone()
    if attempt_row is None:
        raise StoredLifecycleIntegrityError("partial comparison attempt closure is missing")
    attempt_cut = _row_optional_bytes(attempt_row[0], "partial attempt cut digest")
    if attempt_cut is None or attempt_cut.hex() != input_cut_digest:
        raise StoredLifecycleIntegrityError(
            "partial parent input cut differs from the attempt binding"
        )
    run_contract_row = connection.execute(
        "SELECT dfe_run.scope_digest, dfe_run.bound_input_cut_digest, "
        "dfe_contract.check_id, dfe_contract.semantic_digest "
        "FROM dfe_metadata.runs AS dfe_run "
        "JOIN dfe_metadata.contract_versions AS dfe_contract "
        "ON dfe_contract.contract_version_id = dfe_run.contract_version_id "
        "WHERE dfe_run.run_id = %s",
        (result.run_id,),
    ).fetchone()
    if run_contract_row is None:
        raise StoredLifecycleIntegrityError("partial comparison run contract closure is missing")
    if (
        _row_bytes(run_contract_row[0], "partial run scope digest").hex() != result.scope_digest
        or _row_optional_bytes(run_contract_row[1], "partial run cut digest") != attempt_cut
        or _row_text(run_contract_row[2], "partial contract check id") != result.check_id
        or _row_bytes(run_contract_row[3], "partial contract digest").hex()
        != result.contract_digest
    ):
        raise StoredLifecycleIntegrityError(
            "partial result identity differs from its immutable run, cut, or contract"
        )
    if len(result.reasons) == 0:
        raise StoredLifecycleIntegrityError("partial result requires a primary terminal reason")
    try:
        _require_valid_stored_partial_snapshot(result, frontier, observation_ids)
        _validate_partial_budget_use(
            _execution_budgets_from_database(attempt_row[1]),
            result.metrics,
            result.evidence_coverage,
            frontier,
        )
        if result.execution_status is ExecutionStatus.INCOMPLETE:
            _validate_incomplete_reason(result.reasons[0])
        else:
            _validate_error_reason(result.reasons[0])
    except (TypeError, ValueError) as error:
        raise StoredLifecycleIntegrityError(
            f"stored partial comparison closure is invalid: reason={error}"
        ) from None
    reference_observation, target_observation = observation_rows
    _require_completed_observation(
        reference_observation,
        result,
        PlanDirection.REFERENCE,
        reference_context,
        observation_ids[0],
        attempt_cut,
        context_ended_at[0],
    )
    _require_completed_observation(
        target_observation,
        result,
        PlanDirection.TARGET,
        target_context,
        observation_ids[1],
        attempt_cut,
        context_ended_at[1],
    )


def _require_terminal_partial_context(
    row: DatabaseRow,
    result: RunResult,
    direction: PlanDirection,
    ended_at: datetime,
) -> datetime:
    if (
        _row_uuid(row[1], "partial context run id") != result.run_id
        or _row_uuid(row[2], "partial context attempt id") != result.attempt_id
        or _row_text(row[4], "partial context direction") != direction.value
        or _row_bytes(row[6], "partial context scope digest").hex() != result.scope_digest
    ):
        raise StoredLifecycleIntegrityError(
            "partial context differs from its run, attempt, direction, or scope"
        )
    try:
        state = ReadContextStatus(_row_text(row[18], "partial context state"))
    except ValueError:
        raise StoredLifecycleIntegrityError("partial context state is unsupported") from None
    if state not in (ReadContextStatus.CLOSED, ReadContextStatus.LOST):
        raise RunLifecycleStateError("partial comparison requires every context to be terminal")
    if _row_optional_uuid(row[19], "partial context end operation id") is None:
        raise StoredLifecycleIntegrityError("terminal partial context lacks an end operation")
    context_ended_at = _row_optional_datetime(row[20], "partial context ended_at")
    if context_ended_at is None or context_ended_at > ended_at:
        raise StoredLifecycleIntegrityError(
            "partial context end timestamp is absent or later than its result"
        )
    return context_ended_at


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
    if assurance_policy == "exact_required" and result.guarantee not in (
        Guarantee.EXACT,
        Guarantee.STRUCTURAL,
    ):
        raise RunLifecycleStateError(
            "exact_required contract cannot publish a weaker completed guarantee"
        )
    reference_observation, target_observation = observation_rows
    if segments:
        expected_observation_ids = (
            segments[0].reference_observation_id,
            segments[0].target_observation_id,
        )
    elif result.guarantee is Guarantee.STRUCTURAL:
        expected_observation_ids = (
            _row_uuid(reference_observation[0], "reference structural observation id"),
            _row_uuid(target_observation[0], "target structural observation id"),
        )
    else:
        raise StoredLifecycleIntegrityError(
            "completed row comparison closure has no segment evidence"
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


def _require_partial_terminal_receipt(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    ended_at: datetime,
) -> None:
    operation_id = result.persistence.operation_id
    if operation_id is None:
        raise StoredLifecycleIntegrityError("partial result has no persistence operation id")
    if not result.reasons:
        raise StoredLifecycleIntegrityError("partial result has no primary terminal reason")
    attempt_row = _select_attempt_by_id(connection, result.attempt_id)
    if attempt_row is None:
        raise StoredLifecycleIntegrityError("partial result attempt is missing")
    primary_reason = result.reasons[0]
    expected_reason_json = canonical_semantic_json(_reason_semantic_value(primary_reason))
    actual = (
        _row_uuid(attempt_row[1], "partial attempt run id"),
        _row_text(attempt_row[4], "partial attempt status"),
        _row_optional_uuid(attempt_row[13], "partial attempt end operation id"),
        _row_optional_text(attempt_row[14], "partial attempt terminal reason code"),
        _row_optional_canonical_json(attempt_row[15], "partial attempt terminal reason"),
        _row_optional_datetime(attempt_row[17], "partial attempt ended_at"),
    )
    expected = (
        result.run_id,
        result.execution_status.value,
        operation_id,
        primary_reason.code.value,
        expected_reason_json,
        ended_at,
    )
    if actual != expected:
        raise StoredLifecycleIntegrityError(
            "partial result differs from its terminal attempt receipt"
        )
    outcome = AttemptOutcomeRecord(
        run_id=result.run_id,
        attempt_id=result.attempt_id,
        status=AttemptStatus(result.execution_status.value),
        operation_id=operation_id,
        reason=primary_reason,
        ended_at=ended_at,
    )
    _require_terminal_attempt_run_binding(connection, outcome)


def _require_retryable_partial_selection(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
) -> None:
    row = connection.execute(
        "SELECT selected_terminal_attempt_id FROM dfe_metadata.runs WHERE run_id = %s",
        (result.run_id,),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("retryable partial result run is missing")
    if _row_optional_uuid(row[0], "retryable partial selected attempt") == result.attempt_id:
        raise LifecycleOperationConflictError(
            "retryable partial comparison is unexpectedly the selected run outcome"
        )


def _require_selected_partial_comparison(
    connection: psycopg.Connection[DatabaseRow],
    result: RunResult,
    ended_at: datetime,
) -> None:
    operation_id = result.persistence.operation_id
    row = connection.execute(
        "SELECT selected_terminal_attempt_id, terminal_operation_id, terminal_at "
        "FROM dfe_metadata.runs WHERE run_id = %s",
        (result.run_id,),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("terminal partial result run is missing")
    if (
        _row_optional_uuid(row[0], "terminal partial selected attempt") != result.attempt_id
        or _row_optional_uuid(row[1], "terminal partial operation id") != operation_id
        or _row_optional_datetime(row[2], "terminal partial terminal_at") != ended_at
    ):
        raise LifecycleOperationConflictError(
            "terminal partial comparison differs from the selected run publication"
        )


def _require_attempt_closure_for_end(
    connection: psycopg.Connection[DatabaseRow],
    attempt: RunAttemptRecord,
) -> None:
    _require_stored_attempt_closure(
        connection,
        attempt.run.run_id,
        attempt.attempt_id,
    )


def _require_stored_attempt_closure(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
) -> None:
    active_count_row = connection.execute(
        "SELECT pg_catalog.count(*) FROM dfe_metadata.attempt_read_contexts "
        "WHERE run_id = %s AND attempt_id = %s AND state = 'active'",
        (run_id, attempt_id),
    ).fetchone()
    if active_count_row is None or _row_integer(active_count_row[0], "active context count") != 0:
        raise RunLifecycleStateError(
            "attempt outcome requires every acquired read context to be closed or lost"
        )
    row = connection.execute(
        "SELECT input_cut_digest FROM dfe_metadata.run_attempts "
        "WHERE run_id = %s AND attempt_id = %s",
        (run_id, attempt_id),
    ).fetchone()
    if row is None:
        raise StoredLifecycleIntegrityError("attempt closure row is missing")
    cut_digest = _row_optional_bytes(row[0], "attempt closure input cut digest")
    observation_count_row = connection.execute(
        "SELECT pg_catalog.count(*) FROM dfe_metadata.dataset_observations "
        "WHERE run_id = %s AND attempt_id = %s",
        (run_id, attempt_id),
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
        (run_id,),
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
    if encoding != "UTF8":
        raise LifecyclePersistenceError(
            "lifecycle persistence requires PostgreSQL with UTF8 encoding: "
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


def _require_nonblank_text(value: object, context: str) -> None:
    if type(value) is not str or value.strip() == "":
        raise ValueError(f"{context} must be nonblank text")


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
