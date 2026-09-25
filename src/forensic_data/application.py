from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, cast, final
from uuid import UUID, uuid4

from forensic_data.acquisition import (
    AcquisitionValidationError,
    EarlyExecutionOutcome,
    InputCutDefinition,
    RelationManifestEvidence,
    RelationManifestRow,
    build_input_cut_definition,
    build_run_request_definition,
    classify_check_acquisition,
    classify_input_cut_alignment,
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
    ComparisonBudgetExceededError,
    ComparisonInterruptedError,
    ComparisonKeyMappingError,
    ComparisonProtocolError,
    CompletedComparisonArtifact,
    CompletedStructuralComparisonArtifact,
    PartialComparisonArtifact,
    UnsupportedComparisonError,
    execute_integer_key_comparison,
    partial_comparison_artifact_from_completed,
)
from forensic_data.contracts.errors import ContractReferenceError
from forensic_data.contracts.model import (
    Adapter,
    ConsistencyDatasetDefinition,
    DatasetDefinition,
    LoadedContractConfig,
    ReadinessManifestColumns,
    RelationLocator,
    RelationManifestReadiness,
    RelationScope,
    RowCheckDefinition,
)
from forensic_data.greengage_endpoint import (
    GreengageAcquisitionRaceError,
    GreengageBudgetExceededError,
    GreengageProtectedReadContext,
    GreengageProtectedRelationInspection,
    GreengageRelation,
    GreengageRelationAcquisition,
    open_greengage_protected_read_context,
)
from forensic_data.greenplum import (
    GreenplumCloseError,
    GreenplumConnectionError,
    GreenplumContextClosedError,
    GreenplumContextLostError,
    GreenplumDataValidationError,
    GreenplumMetadataError,
    GreenplumQueryError,
    UnsupportedGreenplumProfileError,
)
from forensic_data.greenplum_profile import (
    GreenplumRuntimeProfile,
    match_greenplum_runtime_profile,
)
from forensic_data.mssql import (
    MssqlCancellationConfirmedError,
    MssqlCancellationUnconfirmedError,
    MssqlCloseError,
    MssqlConnectionError,
    MssqlConnectionSettings,
    MssqlContextClosedError,
    MssqlContextLostError,
    MssqlDataValidationError,
    MssqlInspectedRelation,
    MssqlMetadataError,
    MssqlProtectedReadContext,
    MssqlQueryContextError,
    MssqlQueryError,
    MssqlQueryTimeoutError,
    MssqlReadContextState,
    MssqlRelationAcquisition,
    MssqlResultLimitError,
    MssqlRetryPolicy,
    MssqlTransportError,
    UnsupportedMssqlProfileError,
    UnsupportedMssqlRelationError,
    open_mssql_protected_read_context,
)
from forensic_data.mssql_legacy import open_mssql_2016_protected_read_context
from forensic_data.mssql_profile import MssqlRuntimeProfile, match_mssql_runtime_profile
from forensic_data.mssql_sql import MssqlLoweringError, MssqlRelation
from forensic_data.original_greenplum_endpoint import (
    OriginalGreenplumAcquisitionRaceError,
    OriginalGreenplumBudgetExceededError,
    OriginalGreenplumProtectedReadContext,
    OriginalGreenplumProtectedRelationInspection,
    OriginalGreenplumRelation,
    OriginalGreenplumRelationAcquisition,
    OriginalGreenplumResultLimitError,
    open_original_greenplum_protected_read_context,
)
from forensic_data.persistence.definitions import build_metadata_registration_definition
from forensic_data.persistence.errors import (
    CompletedComparisonNotFoundError,
    LifecyclePersistenceError,
    PartialComparisonNotFoundError,
)
from forensic_data.persistence.lifecycle import (
    AlignedInputCutPersistence,
    AttemptOutcomeRecord,
    AttemptStatus,
    ClaimedRun,
    PartialComparisonDefinition,
    PersistedInputCut,
    PersistedReadContext,
    ReadContextPersistence,
    RelationManifestObservationPersistence,
    RunAttemptRecord,
    claim_postgres_run,
    close_postgres_read_context,
    completed_comparison_persistence_from_artifact,
    completed_structural_comparison_persistence_from_artifact,
    mark_postgres_read_context_lost,
    partial_comparison_persistence_from_artifact,
    persist_postgres_aligned_input_cut,
    persist_postgres_read_context,
    publish_postgres_completed_comparison,
    publish_postgres_completed_structural_comparison,
    publish_postgres_terminal_error_attempt,
    publish_postgres_terminal_error_comparison,
    publish_postgres_terminal_incomplete_attempt,
    publish_postgres_terminal_incomplete_comparison,
    read_postgres_completed_comparison,
    read_postgres_diff,
    read_postgres_history,
    read_postgres_partial_comparison,
    read_postgres_terminal_attempt,
    record_postgres_retryable_error_attempt,
    record_postgres_retryable_error_comparison,
    record_postgres_retryable_incomplete_attempt,
    record_postgres_retryable_incomplete_comparison,
    start_postgres_run_attempt,
)
from forensic_data.persistence.model import DatasetVersionRecord, MetadataRegistration
from forensic_data.persistence.postgres import register_postgres_metadata
from forensic_data.planning import (
    PlanDirection,
    PlanReport,
    ResolvedScope,
    ScopeInputValue,
    compile_static_plan,
    resolve_scope_values,
)
from forensic_data.postgres import (
    PostgresAcquisitionRaceError,
    PostgresCloseError,
    PostgresConnectionError,
    PostgresConnectionSettings,
    PostgresContextClosedError,
    PostgresContextLostError,
    PostgresDataValidationError,
    PostgresMetadataError,
    PostgresProtectedReadContext,
    PostgresProtectedRelationInspection,
    PostgresQueryContextError,
    PostgresQueryError,
    PostgresReadDeadlineExceededError,
    PostgresRelationAcquisition,
    PostgresResultLimitError,
    PostgresRetryPolicy,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetExceededError,
    PostgresSourceBudgetLedger,
    PostgresSourceDirection,
    ReadContextState,
    UnsupportedPostgresProfileError,
    open_postgres_protected_read_context,
)
from forensic_data.postgres_legacy import open_postgres_9_6_protected_read_context
from forensic_data.postgres_profile import (
    PostgresRuntimeProfile,
    match_postgres_runtime_profile,
)
from forensic_data.postgres_sql import PostgresRelation
from forensic_data.reporting import DiffCursor, DiffPage, HistoryCursor, HistoryPage
from forensic_data.result import (
    ComparisonCoverage,
    ComparisonTotals,
    ConsistencyLevel,
    ConsistencyStatus,
    EvidenceCoverage,
    ExecutionStatus,
    Guarantee,
    LowerBoundTotal,
    PersistenceState,
    PersistenceStatus,
    ReasonCode,
    ResultMetrics,
    ResultReason,
    RunResult,
    SafeParameter,
    UnavailableTotal,
    Verdict,
)

__all__: Final[tuple[str, ...]] = (
    "ApplicationError",
    "ApplicationStateError",
    "DiffRequest",
    "ExecuteCheckRequest",
    "HistoryRequest",
    "MssqlGreengageExecutionServices",
    "MssqlPostgresExecutionServices",
    "OriginalGreenplumGreengageExecutionServices",
    "OriginalGreenplumPostgresExecutionServices",
    "PlanCheckRequest",
    "PostgresExecutionServices",
    "PostgresGreengageExecutionServices",
    "PostgresMetadataServices",
    "ScopeValue",
    "execute_check",
    "plan_check",
    "read_diff",
    "read_history",
)


class ApplicationError(RuntimeError):
    """Base error for the callable application boundary."""


class ApplicationStateError(ApplicationError):
    """A durable run cannot be represented by the requested application operation."""


@final
@dataclass(frozen=True, slots=True)
class ScopeValue:
    name: str
    value: ScopeInputValue

    def __post_init__(self) -> None:
        _require_nonblank(self.name, "scope value name")
        if type(self.value) not in (bool, int, str):
            raise TypeError("scope value must be an exact boolean, integer, or string")


@final
@dataclass(frozen=True, slots=True)
class PlanCheckRequest:
    check_id: str
    scope_values: tuple[ScopeValue, ...]

    def __post_init__(self) -> None:
        _validate_request_scope(self.check_id, self.scope_values)


@final
@dataclass(frozen=True, slots=True)
class ExecuteCheckRequest:
    request_id: UUID
    check_id: str
    scope_values: tuple[ScopeValue, ...]
    reference_expected_batch_id: str
    target_expected_batch_id: str
    origin: str

    def __post_init__(self) -> None:
        if type(self.request_id) is not UUID:
            raise TypeError("execute request_id must be a UUID")
        _validate_request_scope(self.check_id, self.scope_values)
        _require_nonblank(
            self.reference_expected_batch_id,
            "reference expected batch id",
        )
        _require_nonblank(
            self.target_expected_batch_id,
            "target expected batch id",
        )
        _require_nonblank(self.origin, "execute origin")


@final
@dataclass(frozen=True, slots=True)
class HistoryRequest:
    check_id: str
    scope_digest: str
    limit: int
    cursor: HistoryCursor | None

    def __post_init__(self) -> None:
        _require_nonblank(self.check_id, "history check id")
        _require_sha256(self.scope_digest, "history scope digest")
        _require_positive_integer(self.limit, "history limit")
        if self.cursor is not None and not isinstance(
            cast(object, self.cursor),
            HistoryCursor,
        ):
            raise TypeError("history cursor must be HistoryCursor or None")


@final
@dataclass(frozen=True, slots=True)
class DiffRequest:
    run_id: UUID
    attempt_id: UUID
    limit: int
    cursor: DiffCursor | None

    def __post_init__(self) -> None:
        if type(self.run_id) is not UUID or type(self.attempt_id) is not UUID:
            raise TypeError("diff run_id and attempt_id must be UUIDs")
        _require_positive_integer(self.limit, "diff limit")
        if self.cursor is not None and not isinstance(cast(object, self.cursor), DiffCursor):
            raise TypeError("diff cursor must be DiffCursor or None")
        if self.cursor is not None and (
            self.cursor.run_id != self.run_id or self.cursor.attempt_id != self.attempt_id
        ):
            raise ValueError("diff cursor identity differs from its request")


@final
@dataclass(frozen=True, slots=True)
class PostgresExecutionServices:
    reference_connection_id: str
    reference_settings: PostgresConnectionSettings
    target_connection_id: str
    target_settings: PostgresConnectionSettings
    metadata_connection_id: str
    metadata_settings: PostgresConnectionSettings
    source_retry_policy: PostgresRetryPolicy
    metadata_retry_policy: PostgresRetryPolicy
    protected_lock_timeout_milliseconds: int
    metadata_record_bytes: int
    metadata_total_bytes: int

    def __post_init__(self) -> None:
        for value, context in (
            (self.reference_connection_id, "reference connection id"),
            (self.target_connection_id, "target connection id"),
            (self.metadata_connection_id, "metadata connection id"),
        ):
            _require_nonblank(value, context)
        for value, context in (
            (self.reference_settings, "reference connection settings"),
            (self.target_settings, "target connection settings"),
            (self.metadata_settings, "metadata connection settings"),
        ):
            if not isinstance(cast(object, value), PostgresConnectionSettings):
                raise TypeError(f"{context} must be PostgresConnectionSettings")
        for value, context in (
            (self.source_retry_policy, "source retry policy"),
            (self.metadata_retry_policy, "metadata retry policy"),
        ):
            if not isinstance(cast(object, value), PostgresRetryPolicy):
                raise TypeError(f"{context} must be PostgresRetryPolicy")
        _require_positive_integer(
            self.protected_lock_timeout_milliseconds,
            "protected lock timeout milliseconds",
        )
        _require_positive_integer(self.metadata_record_bytes, "metadata record bytes")
        _require_positive_integer(self.metadata_total_bytes, "metadata total bytes")
        if self.metadata_record_bytes > self.metadata_total_bytes:
            raise ValueError("metadata record bytes cannot exceed metadata total bytes")


@final
@dataclass(frozen=True, slots=True)
class MssqlPostgresExecutionServices:
    reference_connection_id: str
    reference_settings: MssqlConnectionSettings
    target_connection_id: str
    target_settings: PostgresConnectionSettings
    metadata_connection_id: str
    metadata_settings: PostgresConnectionSettings
    reference_retry_policy: MssqlRetryPolicy
    target_retry_policy: PostgresRetryPolicy
    metadata_retry_policy: PostgresRetryPolicy
    protected_lock_timeout_milliseconds: int
    metadata_record_bytes: int
    metadata_total_bytes: int

    def __post_init__(self) -> None:
        for value, context in (
            (self.reference_connection_id, "reference connection id"),
            (self.target_connection_id, "target connection id"),
            (self.metadata_connection_id, "metadata connection id"),
        ):
            _require_nonblank(value, context)
        if not isinstance(cast(object, self.reference_settings), MssqlConnectionSettings):
            raise TypeError("reference connection settings must be MssqlConnectionSettings")
        for value, context in (
            (self.target_settings, "target connection settings"),
            (self.metadata_settings, "metadata connection settings"),
        ):
            if not isinstance(cast(object, value), PostgresConnectionSettings):
                raise TypeError(f"{context} must be PostgresConnectionSettings")
        if type(self.reference_retry_policy) is not MssqlRetryPolicy:
            raise TypeError("reference retry policy must be MssqlRetryPolicy")
        for value, context in (
            (self.target_retry_policy, "target retry policy"),
            (self.metadata_retry_policy, "metadata retry policy"),
        ):
            if not isinstance(cast(object, value), PostgresRetryPolicy):
                raise TypeError(f"{context} must be PostgresRetryPolicy")
        _require_positive_integer(
            self.protected_lock_timeout_milliseconds,
            "protected lock timeout milliseconds",
        )
        _require_positive_integer(self.metadata_record_bytes, "metadata record bytes")
        _require_positive_integer(self.metadata_total_bytes, "metadata total bytes")
        if self.metadata_record_bytes > self.metadata_total_bytes:
            raise ValueError("metadata record bytes cannot exceed metadata total bytes")


@final
@dataclass(frozen=True, slots=True)
class PostgresGreengageExecutionServices:
    reference_connection_id: str
    reference_settings: PostgresConnectionSettings
    target_connection_id: str
    target_settings: PostgresConnectionSettings
    metadata_connection_id: str
    metadata_settings: PostgresConnectionSettings
    reference_retry_policy: PostgresRetryPolicy
    target_retry_policy: PostgresRetryPolicy
    metadata_retry_policy: PostgresRetryPolicy
    protected_lock_timeout_milliseconds: int
    metadata_record_bytes: int
    metadata_total_bytes: int

    def __post_init__(self) -> None:
        for value, context in (
            (self.reference_connection_id, "reference connection id"),
            (self.target_connection_id, "target connection id"),
            (self.metadata_connection_id, "metadata connection id"),
        ):
            _require_nonblank(value, context)
        for value, context in (
            (self.reference_settings, "reference connection settings"),
            (self.target_settings, "target connection settings"),
            (self.metadata_settings, "metadata connection settings"),
        ):
            if not isinstance(cast(object, value), PostgresConnectionSettings):
                raise TypeError(f"{context} must be PostgresConnectionSettings")
        for value, context in (
            (self.reference_retry_policy, "reference retry policy"),
            (self.target_retry_policy, "target retry policy"),
            (self.metadata_retry_policy, "metadata retry policy"),
        ):
            if not isinstance(cast(object, value), PostgresRetryPolicy):
                raise TypeError(f"{context} must be PostgresRetryPolicy")
        _require_positive_integer(
            self.protected_lock_timeout_milliseconds,
            "protected lock timeout milliseconds",
        )
        _require_positive_integer(self.metadata_record_bytes, "metadata record bytes")
        _require_positive_integer(self.metadata_total_bytes, "metadata total bytes")
        if self.metadata_record_bytes > self.metadata_total_bytes:
            raise ValueError("metadata record bytes cannot exceed metadata total bytes")


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumPostgresExecutionServices:
    reference_connection_id: str
    reference_settings: PostgresConnectionSettings
    target_connection_id: str
    target_settings: PostgresConnectionSettings
    metadata_connection_id: str
    metadata_settings: PostgresConnectionSettings
    reference_retry_policy: PostgresRetryPolicy
    target_retry_policy: PostgresRetryPolicy
    metadata_retry_policy: PostgresRetryPolicy
    protected_lock_timeout_milliseconds: int
    metadata_record_bytes: int
    metadata_total_bytes: int

    def __post_init__(self) -> None:
        for value, context in (
            (self.reference_connection_id, "reference connection id"),
            (self.target_connection_id, "target connection id"),
            (self.metadata_connection_id, "metadata connection id"),
        ):
            _require_nonblank(value, context)
        for value, context in (
            (self.reference_settings, "reference connection settings"),
            (self.target_settings, "target connection settings"),
            (self.metadata_settings, "metadata connection settings"),
        ):
            if not isinstance(cast(object, value), PostgresConnectionSettings):
                raise TypeError(f"{context} must be PostgresConnectionSettings")
        for value, context in (
            (self.reference_retry_policy, "reference retry policy"),
            (self.target_retry_policy, "target retry policy"),
            (self.metadata_retry_policy, "metadata retry policy"),
        ):
            if not isinstance(cast(object, value), PostgresRetryPolicy):
                raise TypeError(f"{context} must be PostgresRetryPolicy")
        _require_positive_integer(
            self.protected_lock_timeout_milliseconds,
            "protected lock timeout milliseconds",
        )
        _require_positive_integer(self.metadata_record_bytes, "metadata record bytes")
        _require_positive_integer(self.metadata_total_bytes, "metadata total bytes")
        if self.metadata_record_bytes > self.metadata_total_bytes:
            raise ValueError("metadata record bytes cannot exceed metadata total bytes")


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumGreengageExecutionServices:
    reference_connection_id: str
    reference_settings: PostgresConnectionSettings
    target_connection_id: str
    target_settings: PostgresConnectionSettings
    metadata_connection_id: str
    metadata_settings: PostgresConnectionSettings
    reference_retry_policy: PostgresRetryPolicy
    target_retry_policy: PostgresRetryPolicy
    metadata_retry_policy: PostgresRetryPolicy
    protected_lock_timeout_milliseconds: int
    metadata_record_bytes: int
    metadata_total_bytes: int

    def __post_init__(self) -> None:
        for value, context in (
            (self.reference_connection_id, "reference connection id"),
            (self.target_connection_id, "target connection id"),
            (self.metadata_connection_id, "metadata connection id"),
        ):
            _require_nonblank(value, context)
        for value, context in (
            (self.reference_settings, "reference connection settings"),
            (self.target_settings, "target connection settings"),
            (self.metadata_settings, "metadata connection settings"),
        ):
            if not isinstance(cast(object, value), PostgresConnectionSettings):
                raise TypeError(f"{context} must be PostgresConnectionSettings")
        for value, context in (
            (self.reference_retry_policy, "reference retry policy"),
            (self.target_retry_policy, "target retry policy"),
            (self.metadata_retry_policy, "metadata retry policy"),
        ):
            if not isinstance(cast(object, value), PostgresRetryPolicy):
                raise TypeError(f"{context} must be PostgresRetryPolicy")
        _require_positive_integer(
            self.protected_lock_timeout_milliseconds,
            "protected lock timeout milliseconds",
        )
        _require_positive_integer(self.metadata_record_bytes, "metadata record bytes")
        _require_positive_integer(self.metadata_total_bytes, "metadata total bytes")
        if self.metadata_record_bytes > self.metadata_total_bytes:
            raise ValueError("metadata record bytes cannot exceed metadata total bytes")


@final
@dataclass(frozen=True, slots=True)
class MssqlGreengageExecutionServices:
    reference_connection_id: str
    reference_settings: MssqlConnectionSettings
    target_connection_id: str
    target_settings: PostgresConnectionSettings
    metadata_connection_id: str
    metadata_settings: PostgresConnectionSettings
    reference_retry_policy: MssqlRetryPolicy
    target_retry_policy: PostgresRetryPolicy
    metadata_retry_policy: PostgresRetryPolicy
    protected_lock_timeout_milliseconds: int
    metadata_record_bytes: int
    metadata_total_bytes: int

    def __post_init__(self) -> None:
        for value, context in (
            (self.reference_connection_id, "reference connection id"),
            (self.target_connection_id, "target connection id"),
            (self.metadata_connection_id, "metadata connection id"),
        ):
            _require_nonblank(value, context)
        if not isinstance(cast(object, self.reference_settings), MssqlConnectionSettings):
            raise TypeError("reference connection settings must be MssqlConnectionSettings")
        for value, context in (
            (self.target_settings, "target connection settings"),
            (self.metadata_settings, "metadata connection settings"),
        ):
            if not isinstance(cast(object, value), PostgresConnectionSettings):
                raise TypeError(f"{context} must be PostgresConnectionSettings")
        if type(self.reference_retry_policy) is not MssqlRetryPolicy:
            raise TypeError("reference retry policy must be MssqlRetryPolicy")
        for value, context in (
            (self.target_retry_policy, "target retry policy"),
            (self.metadata_retry_policy, "metadata retry policy"),
        ):
            if not isinstance(cast(object, value), PostgresRetryPolicy):
                raise TypeError(f"{context} must be PostgresRetryPolicy")
        _require_positive_integer(
            self.protected_lock_timeout_milliseconds,
            "protected lock timeout milliseconds",
        )
        _require_positive_integer(self.metadata_record_bytes, "metadata record bytes")
        _require_positive_integer(self.metadata_total_bytes, "metadata total bytes")
        if self.metadata_record_bytes > self.metadata_total_bytes:
            raise ValueError("metadata record bytes cannot exceed metadata total bytes")


type ExecutionServices = (
    PostgresExecutionServices
    | MssqlPostgresExecutionServices
    | PostgresGreengageExecutionServices
    | OriginalGreenplumPostgresExecutionServices
    | OriginalGreenplumGreengageExecutionServices
    | MssqlGreengageExecutionServices
)
type ProtectedReadContext = (
    PostgresProtectedReadContext
    | MssqlProtectedReadContext
    | GreengageProtectedReadContext
    | OriginalGreenplumProtectedReadContext
)
type ProtectedRelation = (
    PostgresProtectedRelationInspection
    | MssqlInspectedRelation
    | GreengageProtectedRelationInspection
    | OriginalGreenplumProtectedRelationInspection
)


@final
@dataclass(frozen=True, slots=True)
class PostgresMetadataServices:
    connection_id: str
    settings: PostgresConnectionSettings
    retry_policy: PostgresRetryPolicy

    def __post_init__(self) -> None:
        _require_nonblank(self.connection_id, "metadata service connection id")
        if not isinstance(cast(object, self.settings), PostgresConnectionSettings):
            raise TypeError("metadata service settings must be PostgresConnectionSettings")
        if not isinstance(cast(object, self.retry_policy), PostgresRetryPolicy):
            raise TypeError("metadata service retry policy must be PostgresRetryPolicy")


@final
@dataclass(frozen=True, slots=True)
class _ProtectedSide:
    direction: PlanDirection
    context: ProtectedReadContext
    dataset_relation: ProtectedRelation
    readiness_relation: ProtectedRelation


@final
@dataclass(frozen=True, slots=True)
class _ReadySide:
    protected: _ProtectedSide
    evidence: RelationManifestEvidence


@final
@dataclass(frozen=True, slots=True)
class _AttemptResource:
    protected: _ProtectedSide
    persisted: PersistedReadContext | None


@final
@dataclass(frozen=True, slots=True)
class _AttemptFailure:
    execution_status: ExecutionStatus
    verdict: Verdict
    reason: ResultReason
    additional_reasons: tuple[ResultReason, ...]
    retryable: bool
    context_ids: tuple[UUID, ...]
    stable_reads: ConsistencyLevel
    cut_aligned: bool
    comparison_coverage: ComparisonCoverage
    evidence_coverage: EvidenceCoverage
    metrics: ResultMetrics
    partial_artifact: PartialComparisonArtifact | None
    persisted_cut: PersistedInputCut | None


@final
@dataclass(frozen=True, slots=True)
class _ConsistencyState:
    context_ids: tuple[UUID, ...]
    stable_reads: ConsistencyLevel
    cut_aligned: bool


def plan_check(config: LoadedContractConfig, request: PlanCheckRequest) -> PlanReport:
    _require_config(config)
    return compile_static_plan(config, request.check_id, _scope_mapping(request.scope_values))


def read_history(
    request: HistoryRequest,
    services: PostgresMetadataServices,
) -> HistoryPage:
    return read_postgres_history(
        services.settings,
        services.retry_policy,
        request.check_id,
        request.scope_digest,
        request.limit,
        request.cursor,
    )


def read_diff(
    request: DiffRequest,
    services: PostgresMetadataServices,
) -> DiffPage:
    return read_postgres_diff(
        services.settings,
        services.retry_policy,
        request.run_id,
        request.attempt_id,
        request.limit,
        request.cursor,
    )


def execute_check(
    config: LoadedContractConfig,
    request: ExecuteCheckRequest,
    services: ExecutionServices,
) -> RunResult:
    _require_config(config)
    check = _find_check(config, request.check_id)
    _validate_service_closure(config, check, services)
    _validate_runtime_profiles(config, check)
    scope = resolve_scope_values(check, _scope_mapping(request.scope_values))
    source_budget = PostgresSourceBudgetLedger(config.execution)
    invocation_owner_token = uuid4()
    registration = register_postgres_metadata(
        services.metadata_settings,
        services.metadata_retry_policy,
        build_metadata_registration_definition(config.version, check, config.evidence),
    )
    run_request = build_run_request_definition(
        request_id=request.request_id,
        contract_version_id=registration.contract.contract_version_id,
        origin=request.origin,
        check=check,
        scope=scope,
        reference_expected_batch_id=request.reference_expected_batch_id,
        target_expected_batch_id=request.target_expected_batch_id,
        execution_policy=config.execution,
        evidence_policy=config.evidence,
    )
    run = claim_postgres_run(
        services.metadata_settings,
        services.metadata_retry_policy,
        uuid4(),
        uuid4(),
        run_request,
    )
    if run.selected_terminal_attempt_id is not None:
        try:
            return read_postgres_completed_comparison(
                services.metadata_settings,
                services.metadata_retry_policy,
                run.run_id,
                run.selected_terminal_attempt_id,
            )
        except CompletedComparisonNotFoundError:
            try:
                return read_postgres_partial_comparison(
                    services.metadata_settings,
                    services.metadata_retry_policy,
                    run.run_id,
                    run.selected_terminal_attempt_id,
                )
            except PartialComparisonNotFoundError:
                outcome = read_postgres_terminal_attempt(
                    services.metadata_settings,
                    services.metadata_retry_policy,
                    run.run_id,
                    run.selected_terminal_attempt_id,
                )
                return _run_result_from_terminal_readback(check, scope, outcome)

    cut_binding_operation_id = run.cut_binding_operation_id or uuid4()
    static_outcome = classify_check_acquisition(check)
    while True:
        attempt = _start_attempt(run, config, invocation_owner_token, services)
        attempt_source_budget = source_budget.start_attempt(attempt.attempt_id)
        if static_outcome is None:
            attempt_result = _execute_attempt(
                check,
                scope,
                registration,
                attempt,
                attempt_source_budget,
                services,
                cut_binding_operation_id,
            )
        else:
            attempt_result = _failure_from_early_outcome(
                static_outcome,
                (),
                False,
                _result_metrics_from_source_budget(attempt_source_budget),
            )
        if isinstance(attempt_result, RunResult):
            return attempt_result
        if attempt_result.retryable and attempt.ordinal < config.execution.max_attempts:
            _record_retryable_failure(attempt, attempt_result, services)
            continue
        outcome = _publish_terminal_failure(attempt, attempt_result, services)
        if isinstance(outcome, RunResult):
            return outcome
        return _run_result_from_attempt_outcome(check, scope, outcome, attempt_result)


def _start_attempt(
    run: ClaimedRun,
    config: LoadedContractConfig,
    invocation_owner_token: UUID,
    services: ExecutionServices,
) -> RunAttemptRecord:
    lease_expires_at = datetime.now(UTC) + timedelta(
        milliseconds=config.execution.run_timeout_milliseconds
    )
    return start_postgres_run_attempt(
        services.metadata_settings,
        services.metadata_retry_policy,
        run,
        uuid4(),
        uuid4(),
        invocation_owner_token,
        lease_expires_at,
        config.execution,
    )


def _execute_attempt(
    check: RowCheckDefinition,
    scope: ResolvedScope,
    registration: MetadataRegistration,
    attempt: RunAttemptRecord,
    source_budget: PostgresSourceBudgetAttempt,
    services: ExecutionServices,
    cut_binding_operation_id: UUID,
) -> RunResult | _AttemptFailure:
    resources: list[_AttemptResource] = []
    artifact: CompletedComparisonArtifact | CompletedStructuralComparisonArtifact | None = None
    persisted_cut: PersistedInputCut | None = None
    failure: _AttemptFailure | None = None
    greenplum_endpoint_direction: PlanDirection | None = PlanDirection.REFERENCE
    try:
        reference = _open_side(check, PlanDirection.REFERENCE, source_budget, services)
        resources.append(_AttemptResource(reference, None))
        reference_receipt = _persist_context(
            attempt,
            registration.reference_dataset,
            reference,
            services,
        )
        resources[-1] = _AttemptResource(reference, reference_receipt)
        reference_readiness = _read_readiness(
            check,
            scope,
            reference,
            attempt.run.request.expected_batches[0].batch_id,
            services,
        )
        if isinstance(reference_readiness, EarlyExecutionOutcome):
            failure = _failure_from_early_outcome(
                reference_readiness,
                _context_ids(resources),
                False,
                _result_metrics_from_source_budget(source_budget),
            )
        else:
            greenplum_endpoint_direction = PlanDirection.TARGET
            target = _open_side(check, PlanDirection.TARGET, source_budget, services)
            resources.append(_AttemptResource(target, None))
            target_receipt = _persist_context(
                attempt,
                registration.target_dataset,
                target,
                services,
            )
            resources[-1] = _AttemptResource(target, target_receipt)
            target_readiness = _read_readiness(
                check,
                scope,
                target,
                attempt.run.request.expected_batches[1].batch_id,
                services,
            )
            if isinstance(target_readiness, EarlyExecutionOutcome):
                failure = _failure_from_early_outcome(
                    target_readiness,
                    _context_ids(resources),
                    False,
                    _result_metrics_from_source_budget(source_budget),
                )
            else:
                greenplum_endpoint_direction = None
                input_cut = build_input_cut_definition(
                    reference_readiness,
                    target_readiness,
                )
                alignment_outcome = classify_input_cut_alignment(input_cut)
                if alignment_outcome is not None:
                    failure = _failure_from_early_outcome(
                        alignment_outcome,
                        _context_ids(resources),
                        False,
                        _result_metrics_from_source_budget(source_budget),
                    )
                else:
                    ready_reference = _ReadySide(reference, reference_readiness)
                    ready_target = _ReadySide(target, target_readiness)
                    persisted_cut = persist_postgres_aligned_input_cut(
                        services.metadata_settings,
                        services.metadata_retry_policy,
                        attempt,
                        _cut_persistence(
                            input_cut,
                            registration,
                            ready_reference,
                            ready_target,
                            cut_binding_operation_id,
                        ),
                    )
                    artifact = execute_integer_key_comparison(
                        reference.context,
                        reference.dataset_relation,
                        target.context,
                        target.dataset_relation,
                        check,
                        scope,
                        input_cut,
                        attempt.execution_budgets,
                        attempt.run.request.evidence_policy,
                        source_budget,
                    )
    except ComparisonInterruptedError as error:
        failure = _failure_from_comparison_interruption(
            error,
            resources,
            persisted_cut,
        )
    except ComparisonKeyMappingError as error:
        contract_reason = error.contract_violation_reason
        failure = _AttemptFailure(
            execution_status=ExecutionStatus.ERROR,
            verdict=(Verdict.MISMATCH if contract_reason is not None else Verdict.INCONCLUSIVE),
            reason=_reason(
                ReasonCode.LOSSY_TRANSPORT,
                "validate_key_mapping",
                "scoped key values cannot map losslessly to logical INT64",
                _mapping_error_parameters(error, _context_ids(resources)),
            ),
            additional_reasons=(() if contract_reason is None else (contract_reason,)),
            retryable=False,
            context_ids=_context_ids(resources),
            stable_reads=(
                ConsistencyLevel.VERIFIED if persisted_cut is not None else ConsistencyLevel.UNKNOWN
            ),
            cut_aligned=persisted_cut is not None,
            comparison_coverage=ComparisonCoverage(
                total_partitions=1,
                covered_partitions=0,
                resolved_segments=0,
                pruned_segments=0,
                exact_segments=0,
                unresolved_segments=1,
                unresolved_reasons=(ReasonCode.LOSSY_TRANSPORT,),
            ),
            evidence_coverage=EvidenceCoverage(
                found_records=0,
                retained_records=0,
                found_bytes=0,
                retained_bytes=0,
            ),
            metrics=error.metrics,
            partial_artifact=None,
            persisted_cut=persisted_cut,
        )
    except UnsupportedComparisonError as error:
        failure = _failure_from_unsupported_comparison(
            error,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except MssqlQueryTimeoutError as error:
        failure = _failure_from_terminal_source_reason(
            _mssql_query_timeout_reason(error),
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except OriginalGreenplumResultLimitError as error:
        failure = _failure_from_error(
            ExecutionStatus.INCOMPLETE,
            ReasonCode.BUDGET_EXHAUSTED,
            "read_source",
            "a bounded source read exceeded its configured result budget",
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except (
        ComparisonBudgetExceededError,
        GreengageBudgetExceededError,
        OriginalGreenplumBudgetExceededError,
        PostgresReadDeadlineExceededError,
        PostgresSourceBudgetExceededError,
    ) as error:
        failure = _failure_from_error(
            ExecutionStatus.INCOMPLETE,
            ReasonCode.BUDGET_EXHAUSTED,
            "compare",
            "the check exhausted an immutable execution budget",
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except MssqlCancellationConfirmedError as error:
        failure = _failure_from_terminal_source_reason(
            _mssql_confirmed_cancellation_reason(error),
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except MssqlCancellationUnconfirmedError as error:
        failure = _failure_from_terminal_source_reason(
            _mssql_unconfirmed_cancellation_reason(error),
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except (PostgresResultLimitError, MssqlResultLimitError) as error:
        failure = _failure_from_error(
            ExecutionStatus.INCOMPLETE,
            ReasonCode.BUDGET_EXHAUSTED,
            "read_source",
            "a bounded source read exceeded its configured result budget",
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except UnsupportedMssqlRelationError as error:
        failure = _failure_from_error(
            ExecutionStatus.ERROR,
            ReasonCode.UNSUPPORTED_CAPABILITY,
            "inspect_source_relation",
            _actionable_mssql_error_message(error, "SQL Server relation refusal"),
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except MssqlLoweringError as error:
        failure = _failure_from_error(
            ExecutionStatus.ERROR,
            ReasonCode.UNSUPPORTED_CAPABILITY,
            "compile_source_query",
            _actionable_mssql_error_message(error, "SQL Server query lowering refusal"),
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except (
        PostgresContextLostError,
        PostgresAcquisitionRaceError,
        MssqlContextLostError,
        MssqlMetadataError,
        GreenplumContextLostError,
        GreengageAcquisitionRaceError,
        OriginalGreenplumAcquisitionRaceError,
    ) as error:
        failure = _failure_from_error(
            ExecutionStatus.INCOMPLETE,
            ReasonCode.SNAPSHOT_LOST,
            "read_source",
            "a protected source snapshot was lost before completion",
            error,
            True,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except (
        PostgresConnectionError,
        PostgresQueryError,
        PostgresMetadataError,
        MssqlConnectionError,
        MssqlQueryError,
        GreenplumConnectionError,
        GreenplumQueryError,
    ) as error:
        failure = _failure_from_error(
            ExecutionStatus.ERROR,
            ReasonCode.QUERY_ERROR,
            "read_source",
            "a source operation failed",
            error,
            True,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except UnsupportedPostgresProfileError as error:
        failure = _failure_from_error(
            ExecutionStatus.ERROR,
            ReasonCode.UNSUPPORTED_CAPABILITY,
            "open_source",
            "a source does not satisfy the required runtime profile",
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except UnsupportedMssqlProfileError as error:
        failure = _failure_from_error(
            ExecutionStatus.ERROR,
            ReasonCode.UNSUPPORTED_CAPABILITY,
            "open_source",
            _actionable_mssql_error_message(error, "SQL Server profile refusal"),
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except (UnsupportedGreenplumProfileError, GreenplumMetadataError) as error:
        if greenplum_endpoint_direction is PlanDirection.REFERENCE:
            operation = "open_reference"
            message = (
                "the original Greenplum reference does not satisfy the required runtime capability"
            )
        elif greenplum_endpoint_direction is PlanDirection.TARGET:
            operation = "open_target"
            message = "the Greengage target does not satisfy the required runtime capability"
        else:
            operation = "compare"
            message = "a Greenplum-family endpoint does not satisfy the required runtime capability"
        failure = _failure_from_error(
            ExecutionStatus.ERROR,
            ReasonCode.UNSUPPORTED_CAPABILITY,
            operation,
            message,
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except (
        AcquisitionValidationError,
        ComparisonProtocolError,
        PostgresContextClosedError,
        PostgresDataValidationError,
        PostgresQueryContextError,
        MssqlContextClosedError,
        MssqlDataValidationError,
        MssqlQueryContextError,
        GreenplumContextClosedError,
        GreenplumDataValidationError,
    ) as error:
        failure = _failure_from_error(
            ExecutionStatus.ERROR,
            ReasonCode.PROTOCOL_VIOLATION,
            "execute_check",
            "source evidence violated the declared check protocol",
            error,
            False,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    except MssqlTransportError as error:
        failure = _failure_from_error(
            ExecutionStatus.ERROR,
            ReasonCode.QUERY_ERROR,
            "read_source",
            "a SQL Server source operation failed",
            error,
            True,
            resources,
            persisted_cut is not None,
            source_budget,
        )
    finally:
        context_lost = _close_attempt_resources(attempt, tuple(resources), services)

    if context_lost:
        context_loss_reason = _context_loss_reason()
        if failure is not None:
            failure = _failure_with_secondary_context_loss(failure, context_loss_reason)
        elif artifact is not None:
            if persisted_cut is None:
                raise AssertionError("completed comparison is missing its persisted input cut")
            failure = _failure_from_artifact_context_loss(
                artifact,
                persisted_cut,
                context_loss_reason,
            )
        else:
            failure = _failure_from_cleanup_context_loss(
                context_loss_reason,
                _context_ids(resources),
                persisted_cut is not None,
                _result_metrics_from_source_budget(source_budget),
            )
        artifact = None
    if failure is not None:
        return failure
    if artifact is None or persisted_cut is None:
        raise AssertionError("successful attempt did not produce comparison and cut artifacts")
    if isinstance(artifact, CompletedStructuralComparisonArtifact):
        structural = completed_structural_comparison_persistence_from_artifact(
            attempt,
            persisted_cut,
            artifact,
        )
        return publish_postgres_completed_structural_comparison(
            services.metadata_settings,
            services.metadata_retry_policy,
            attempt,
            uuid4(),
            structural,
            datetime.now(UTC),
        )
    comparison, segments, anomalies = completed_comparison_persistence_from_artifact(
        attempt,
        persisted_cut,
        artifact,
    )
    return publish_postgres_completed_comparison(
        services.metadata_settings,
        services.metadata_retry_policy,
        attempt,
        uuid4(),
        comparison,
        segments,
        anomalies,
        datetime.now(UTC),
    )


def _open_side(
    check: RowCheckDefinition,
    direction: PlanDirection,
    source_budget: PostgresSourceBudgetAttempt,
    services: ExecutionServices,
) -> _ProtectedSide:
    dataset, consistency = _side_definitions(check, direction)
    locator = dataset.locator
    readiness = consistency.readiness
    if not isinstance(locator, RelationLocator) or not isinstance(
        readiness,
        RelationManifestReadiness,
    ):
        raise UnsupportedComparisonError(
            f"{direction.value} execution requires a physical relation and relation manifest"
        )
    if (locator.schema, locator.name) == (
        readiness.relation.schema,
        readiness.relation.name,
    ):
        raise UnsupportedComparisonError(
            f"{direction.value} dataset and readiness manifest must use distinct physical relations"
        )
    if dataset.connection.adapter is Adapter.MSSQL:
        return _open_mssql_side(
            dataset,
            readiness,
            direction,
            source_budget,
            services,
        )
    if dataset.connection.adapter is Adapter.GREENPLUM:
        return _open_original_greenplum_side(
            dataset,
            readiness,
            direction,
            source_budget,
            services,
        )
    if dataset.connection.adapter is Adapter.GREENGAGE:
        return _open_greengage_side(
            dataset,
            readiness,
            direction,
            source_budget,
            services,
        )
    if dataset.connection.adapter is Adapter.POSTGRESQL:
        return _open_postgres_side(
            dataset,
            readiness,
            direction,
            source_budget,
            services,
        )
    raise UnsupportedComparisonError(
        f"{direction.value} dataset uses an unsupported execution adapter: "
        f"adapter={dataset.connection.adapter.value!r}"
    )


def _open_postgres_side(
    dataset: DatasetDefinition,
    readiness: RelationManifestReadiness,
    direction: PlanDirection,
    source_budget: PostgresSourceBudgetAttempt,
    services: ExecutionServices,
) -> _ProtectedSide:
    settings = _postgres_settings(services, direction)
    retry_policy = _postgres_retry_policy(services, direction)
    dataset_locator = dataset.locator
    if not isinstance(dataset_locator, RelationLocator):
        raise UnsupportedComparisonError(
            f"{direction.value} PostgreSQL execution requires a physical relation"
        )
    dataset_relation = PostgresRelation(components=(dataset_locator.schema, dataset_locator.name))
    readiness_relation = PostgresRelation(
        components=(readiness.relation.schema, readiness.relation.name)
    )
    acquisitions = (
        PostgresRelationAcquisition(
            schema=dataset.logical_schema.schema,
            relation=dataset_relation,
            relation_scope=dataset_locator.relation_scope,
            column_names=tuple(field.column_name for field in dataset.projection),
            max_metadata_record_bytes=services.metadata_record_bytes,
            max_metadata_total_bytes=services.metadata_total_bytes,
        ),
        PostgresRelationAcquisition(
            schema=_manifest_schema(),
            relation=readiness_relation,
            relation_scope=RelationScope.PHYSICAL_ONLY,
            column_names=readiness.columns.values(),
            max_metadata_record_bytes=services.metadata_record_bytes,
            max_metadata_total_bytes=services.metadata_total_bytes,
        ),
    )
    runtime_profile = match_postgres_runtime_profile(
        dataset.connection.driver,
        dataset.connection.profile,
    )
    if runtime_profile is PostgresRuntimeProfile.POSTGRES_17:
        context = open_postgres_protected_read_context(
            settings,
            retry_policy,
            acquisitions,
            services.protected_lock_timeout_milliseconds,
            source_budget,
            PostgresSourceDirection(direction.value),
        )
    elif runtime_profile is PostgresRuntimeProfile.POSTGRES_9_6:
        context = open_postgres_9_6_protected_read_context(
            settings,
            retry_policy,
            acquisitions,
            services.protected_lock_timeout_milliseconds,
            source_budget,
            PostgresSourceDirection(direction.value),
        )
    else:
        raise UnsupportedPostgresProfileError(
            f"declared PostgreSQL {direction.value} driver/profile is unsupported: "
            f"driver={dataset.connection.driver!r}, profile={dataset.connection.profile!r}"
        )
    return _ProtectedSide(
        direction=direction,
        context=context,
        dataset_relation=_protected_relation(context, dataset_relation),
        readiness_relation=_protected_relation(context, readiness_relation),
    )


def _open_mssql_side(
    dataset: DatasetDefinition,
    readiness: RelationManifestReadiness,
    direction: PlanDirection,
    source_budget: PostgresSourceBudgetAttempt,
    services: ExecutionServices,
) -> _ProtectedSide:
    if direction is not PlanDirection.REFERENCE:
        raise UnsupportedMssqlProfileError("SQL Server is supported only as a reference source")
    if not isinstance(
        services,
        (MssqlPostgresExecutionServices, MssqlGreengageExecutionServices),
    ):
        raise TypeError("SQL Server reference execution requires mixed-engine execution services")
    locator = dataset.locator
    if not isinstance(locator, RelationLocator):
        raise UnsupportedComparisonError(
            "SQL Server reference execution requires a physical relation"
        )
    if locator.relation_scope is not RelationScope.PHYSICAL_ONLY:
        raise UnsupportedComparisonError(
            "SQL Server reference execution requires physical_only relation scope"
        )
    runtime_profile = match_mssql_runtime_profile(
        dataset.connection.driver,
        dataset.connection.profile,
    )
    if runtime_profile not in (
        MssqlRuntimeProfile.MSSQL_2022,
        MssqlRuntimeProfile.MSSQL_2016,
    ):
        raise UnsupportedMssqlProfileError(
            "declared SQL Server reference driver/profile is unsupported: "
            f"driver={dataset.connection.driver!r}, profile={dataset.connection.profile!r}"
        )
    dataset_relation = MssqlRelation(
        schema_name=locator.schema,
        table_name=locator.name,
    )
    readiness_relation = MssqlRelation(
        schema_name=readiness.relation.schema,
        table_name=readiness.relation.name,
    )
    acquisitions = (
        MssqlRelationAcquisition(
            schema=dataset.logical_schema.schema,
            relation=dataset_relation,
            relation_scope=locator.relation_scope,
            column_names=tuple(field.column_name for field in dataset.projection),
            max_metadata_record_bytes=services.metadata_record_bytes,
            max_metadata_total_bytes=services.metadata_total_bytes,
        ),
        MssqlRelationAcquisition(
            schema=_manifest_schema(),
            relation=readiness_relation,
            relation_scope=RelationScope.PHYSICAL_ONLY,
            column_names=readiness.columns.values(),
            max_metadata_record_bytes=services.metadata_record_bytes,
            max_metadata_total_bytes=services.metadata_total_bytes,
        ),
    )
    if runtime_profile is MssqlRuntimeProfile.MSSQL_2022:
        context = open_mssql_protected_read_context(
            services.reference_settings,
            services.reference_retry_policy,
            acquisitions,
            source_budget,
            PostgresSourceDirection.REFERENCE,
        )
    else:
        context = open_mssql_2016_protected_read_context(
            services.reference_settings,
            services.reference_retry_policy,
            acquisitions,
            source_budget,
            PostgresSourceDirection.REFERENCE,
        )
    return _ProtectedSide(
        direction=direction,
        context=context,
        dataset_relation=_protected_mssql_relation(context, dataset_relation),
        readiness_relation=_protected_mssql_relation(context, readiness_relation),
    )


def _open_greengage_side(
    dataset: DatasetDefinition,
    readiness: RelationManifestReadiness,
    direction: PlanDirection,
    source_budget: PostgresSourceBudgetAttempt,
    services: ExecutionServices,
) -> _ProtectedSide:
    if direction is not PlanDirection.TARGET:
        raise UnsupportedGreenplumProfileError(
            "Greengage endpoint execution is implemented only for the target direction"
        )
    if not isinstance(
        services,
        (
            PostgresGreengageExecutionServices,
            MssqlGreengageExecutionServices,
            OriginalGreenplumGreengageExecutionServices,
        ),
    ):
        raise TypeError("Greengage target execution requires Greengage execution services")
    locator = dataset.locator
    if not isinstance(locator, RelationLocator):
        raise UnsupportedComparisonError("Greengage target execution requires a physical relation")
    if locator.relation_scope is not RelationScope.PHYSICAL_ONLY:
        raise UnsupportedComparisonError(
            "Greengage target execution requires physical_only relation scope"
        )
    if (
        match_greenplum_runtime_profile(
            dataset.connection.driver,
            dataset.connection.profile,
        )
        is not GreenplumRuntimeProfile.GREENGAGE
    ):
        raise UnsupportedGreenplumProfileError(
            "declared Greengage target requires driver='psycopg' and profile='greengage'"
        )
    dataset_relation = GreengageRelation(
        components=(locator.schema, locator.name),
    )
    readiness_relation = GreengageRelation(
        components=(readiness.relation.schema, readiness.relation.name),
    )
    acquisitions = (
        GreengageRelationAcquisition(
            schema=dataset.logical_schema.schema,
            relation=dataset_relation,
            relation_scope=locator.relation_scope,
            column_names=tuple(field.column_name for field in dataset.projection),
            max_metadata_record_bytes=services.metadata_record_bytes,
            max_metadata_total_bytes=services.metadata_total_bytes,
        ),
        GreengageRelationAcquisition(
            schema=_manifest_schema(),
            relation=readiness_relation,
            relation_scope=RelationScope.PHYSICAL_ONLY,
            column_names=readiness.columns.values(),
            max_metadata_record_bytes=services.metadata_record_bytes,
            max_metadata_total_bytes=services.metadata_total_bytes,
        ),
    )
    context = open_greengage_protected_read_context(
        services.target_settings,
        services.target_retry_policy,
        acquisitions,
        services.protected_lock_timeout_milliseconds,
        source_budget,
        PostgresSourceDirection.TARGET,
    )
    return _ProtectedSide(
        direction=direction,
        context=context,
        dataset_relation=_protected_greengage_relation(context, dataset_relation),
        readiness_relation=_protected_greengage_relation(context, readiness_relation),
    )


def _open_original_greenplum_side(
    dataset: DatasetDefinition,
    readiness: RelationManifestReadiness,
    direction: PlanDirection,
    source_budget: PostgresSourceBudgetAttempt,
    services: ExecutionServices,
) -> _ProtectedSide:
    if direction is not PlanDirection.REFERENCE:
        raise UnsupportedGreenplumProfileError(
            "original Greenplum endpoint execution is implemented only for the reference direction"
        )
    if not isinstance(
        services,
        (
            OriginalGreenplumPostgresExecutionServices,
            OriginalGreenplumGreengageExecutionServices,
        ),
    ):
        raise TypeError(
            "original Greenplum reference execution requires original Greenplum execution services"
        )
    locator = dataset.locator
    if not isinstance(locator, RelationLocator):
        raise UnsupportedComparisonError(
            "original Greenplum reference execution requires a physical relation"
        )
    if locator.relation_scope is not RelationScope.PHYSICAL_ONLY:
        raise UnsupportedComparisonError(
            "original Greenplum reference execution requires physical_only relation scope"
        )
    if (
        match_greenplum_runtime_profile(
            dataset.connection.driver,
            dataset.connection.profile,
        )
        is not GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
    ):
        raise UnsupportedGreenplumProfileError(
            "declared original Greenplum reference requires "
            "driver='psycopg2' and profile='original_greenplum'"
        )
    dataset_relation = OriginalGreenplumRelation(
        components=(locator.schema, locator.name),
    )
    readiness_relation = OriginalGreenplumRelation(
        components=(readiness.relation.schema, readiness.relation.name),
    )
    acquisitions = (
        OriginalGreenplumRelationAcquisition(
            schema=dataset.logical_schema.schema,
            relation=dataset_relation,
            relation_scope=locator.relation_scope,
            column_names=tuple(field.column_name for field in dataset.projection),
            max_metadata_record_bytes=services.metadata_record_bytes,
            max_metadata_total_bytes=services.metadata_total_bytes,
        ),
        OriginalGreenplumRelationAcquisition(
            schema=_manifest_schema(),
            relation=readiness_relation,
            relation_scope=RelationScope.PHYSICAL_ONLY,
            column_names=readiness.columns.values(),
            max_metadata_record_bytes=services.metadata_record_bytes,
            max_metadata_total_bytes=services.metadata_total_bytes,
        ),
    )
    context = open_original_greenplum_protected_read_context(
        services.reference_settings,
        services.reference_retry_policy,
        acquisitions,
        services.protected_lock_timeout_milliseconds,
        source_budget,
        PostgresSourceDirection.REFERENCE,
    )
    return _ProtectedSide(
        direction=direction,
        context=context,
        dataset_relation=_protected_original_greenplum_relation(context, dataset_relation),
        readiness_relation=_protected_original_greenplum_relation(context, readiness_relation),
    )


def _persist_context(
    attempt: RunAttemptRecord,
    dataset: DatasetVersionRecord,
    protected: _ProtectedSide,
    services: ExecutionServices,
) -> PersistedReadContext:
    return persist_postgres_read_context(
        services.metadata_settings,
        services.metadata_retry_policy,
        attempt,
        ReadContextPersistence(
            acquisition_operation_id=uuid4(),
            dataset=dataset,
            direction=protected.direction,
            protected_context=protected.context,
        ),
    )


def _read_readiness(
    check: RowCheckDefinition,
    scope: ResolvedScope,
    protected: _ProtectedSide,
    expected_batch_id: str,
    services: ExecutionServices,
) -> RelationManifestEvidence | EarlyExecutionOutcome:
    dataset, consistency = _side_definitions(check, protected.direction)
    readiness = consistency.readiness
    if not isinstance(readiness, RelationManifestReadiness):
        raise UnsupportedComparisonError(
            f"{protected.direction.value} execution requires relation-manifest readiness"
        )
    rows = _read_relation_manifest(
        protected,
        readiness.columns,
        dataset.dataset_id,
        scope.scope_digest,
        services.metadata_record_bytes,
        services.metadata_total_bytes,
    )
    return validate_relation_manifest_readiness(
        direction=protected.direction,
        rows=rows,
        expected_dataset_id=dataset.dataset_id,
        expected_scope_digest=scope.scope_digest,
        expected_batch_id=expected_batch_id,
        alignment_fields=check.consistency.alignment_fields,
        minimum_evidence=check.consistency.minimum_evidence,
        late_arrivals=check.consistency.late_arrivals,
    )


def _read_relation_manifest(
    protected: _ProtectedSide,
    columns: ReadinessManifestColumns,
    dataset_id: str,
    scope_digest: str,
    max_record_bytes: int,
    max_total_bytes: int,
) -> tuple[RelationManifestRow, ...]:
    context = protected.context
    relation = protected.readiness_relation
    if isinstance(context, PostgresProtectedReadContext):
        if not isinstance(relation, PostgresProtectedRelationInspection):
            raise ApplicationStateError(
                "PostgreSQL protected context is paired with a SQL Server readiness relation"
            )
        return context.read_relation_manifest(
            relation,
            columns,
            dataset_id,
            scope_digest,
            max_record_bytes,
            max_total_bytes,
        )
    if isinstance(context, GreengageProtectedReadContext):
        if not isinstance(relation, GreengageProtectedRelationInspection):
            raise ApplicationStateError(
                "Greengage protected context is paired with another engine's readiness relation"
            )
        return context.read_relation_manifest(
            relation,
            columns,
            dataset_id,
            scope_digest,
            max_record_bytes,
            max_total_bytes,
        )
    if isinstance(context, OriginalGreenplumProtectedReadContext):
        if not isinstance(relation, OriginalGreenplumProtectedRelationInspection):
            raise ApplicationStateError(
                "original Greenplum protected context is paired with another engine's "
                "readiness relation"
            )
        return context.read_relation_manifest(
            relation,
            columns,
            dataset_id,
            scope_digest,
            max_record_bytes,
            max_total_bytes,
        )
    if not isinstance(relation, MssqlInspectedRelation):
        raise ApplicationStateError(
            "SQL Server protected context is paired with a PostgreSQL readiness relation"
        )
    return context.read_relation_manifest(
        relation,
        columns,
        dataset_id,
        scope_digest,
        max_record_bytes,
        max_total_bytes,
    )


def _cut_persistence(
    input_cut: InputCutDefinition,
    registration: MetadataRegistration,
    reference: _ReadySide,
    target: _ReadySide,
    cut_binding_operation_id: UUID,
) -> AlignedInputCutPersistence:
    recorded_at = datetime.now(UTC)
    return AlignedInputCutPersistence(
        cut_binding_operation_id=cut_binding_operation_id,
        attempt_cut_operation_id=uuid4(),
        input_cut=input_cut,
        reference=_observation(
            registration.reference_dataset,
            reference,
            recorded_at,
        ),
        target=_observation(
            registration.target_dataset,
            target,
            recorded_at,
        ),
        recorded_at=recorded_at,
    )


def _observation(
    dataset: DatasetVersionRecord,
    side: _ReadySide,
    observed_at: datetime,
) -> RelationManifestObservationPersistence:
    return RelationManifestObservationPersistence(
        observation_id=uuid4(),
        observation_operation_id=uuid4(),
        dataset=dataset,
        direction=side.protected.direction,
        readiness=side.evidence,
        protected_context=side.protected.context,
        dataset_relation=side.protected.dataset_relation,
        readiness_relation=side.protected.readiness_relation,
        projection_code_artifact=None,
        observed_at=observed_at,
    )


def _close_attempt_resources(
    attempt: RunAttemptRecord,
    resources: tuple[_AttemptResource, ...],
    services: ExecutionServices,
) -> bool:
    context_lost = False
    persistence_error: LifecyclePersistenceError | None = None
    for resource in resources:
        state_before_close = resource.protected.context.state
        close_failed = False
        try:
            resource.protected.context.close()
        except (PostgresCloseError, MssqlCloseError, GreenplumCloseError):
            close_failed = True
            context_lost = True
        was_active = _protected_context_state_is_active(state_before_close)
        if not was_active:
            context_lost = True
        if resource.persisted is None:
            continue
        try:
            if close_failed or not was_active:
                mark_postgres_read_context_lost(
                    services.metadata_settings,
                    services.metadata_retry_policy,
                    attempt,
                    resource.persisted.read_context_id,
                    uuid4(),
                    datetime.now(UTC),
                )
            else:
                close_postgres_read_context(
                    services.metadata_settings,
                    services.metadata_retry_policy,
                    attempt,
                    resource.persisted.read_context_id,
                    uuid4(),
                    datetime.now(UTC),
                )
        except LifecyclePersistenceError as error:
            if persistence_error is None:
                persistence_error = error
    if persistence_error is not None:
        raise persistence_error
    return context_lost


def _context_loss_reason() -> ResultReason:
    return _reason(
        ReasonCode.SNAPSHOT_LOST,
        "close_read_context",
        "a protected source snapshot could not be closed cleanly",
        (),
    )


def _protected_context_state_is_active(
    state: ReadContextState | MssqlReadContextState,
) -> bool:
    return state is ReadContextState.ACTIVE or state is MssqlReadContextState.ACTIVE


def _failure_with_secondary_context_loss(
    failure: _AttemptFailure,
    context_loss_reason: ResultReason,
) -> _AttemptFailure:
    state = _ConsistencyState(
        context_ids=failure.context_ids,
        stable_reads=_degraded_stable_reads(failure.stable_reads),
        cut_aligned=failure.cut_aligned,
    )
    return _AttemptFailure(
        execution_status=failure.execution_status,
        verdict=failure.verdict,
        reason=_reason_with_cleanup_state(
            _reason_without_failure_consistency(failure.reason),
            state,
        ),
        additional_reasons=(*failure.additional_reasons, context_loss_reason),
        retryable=failure.retryable,
        context_ids=failure.context_ids,
        stable_reads=state.stable_reads,
        cut_aligned=failure.cut_aligned,
        comparison_coverage=failure.comparison_coverage,
        evidence_coverage=failure.evidence_coverage,
        metrics=failure.metrics,
        partial_artifact=failure.partial_artifact,
        persisted_cut=failure.persisted_cut,
    )


def _failure_from_artifact_context_loss(
    artifact: CompletedComparisonArtifact | CompletedStructuralComparisonArtifact,
    persisted_cut: PersistedInputCut,
    context_loss_reason: ResultReason,
) -> _AttemptFailure:
    state = _ConsistencyState(
        context_ids=artifact.consistency.read_context_ids,
        stable_reads=_degraded_stable_reads(artifact.consistency.stable_reads),
        cut_aligned=artifact.consistency.cut_alignment is not ConsistencyLevel.UNKNOWN,
    )
    return _AttemptFailure(
        execution_status=ExecutionStatus.INCOMPLETE,
        verdict=(
            Verdict.MISMATCH if artifact.verdict is Verdict.MISMATCH else Verdict.INCONCLUSIVE
        ),
        reason=_reason_with_cleanup_state(context_loss_reason, state),
        additional_reasons=artifact.reasons,
        retryable=artifact.verdict is not Verdict.MISMATCH,
        context_ids=state.context_ids,
        stable_reads=state.stable_reads,
        cut_aligned=state.cut_aligned,
        comparison_coverage=artifact.comparison_coverage,
        evidence_coverage=artifact.evidence_coverage,
        metrics=artifact.metrics,
        partial_artifact=partial_comparison_artifact_from_completed(
            artifact,
            ReasonCode.SNAPSHOT_LOST,
        ),
        persisted_cut=persisted_cut,
    )


def _failure_from_cleanup_context_loss(
    context_loss_reason: ResultReason,
    context_ids: tuple[UUID, ...],
    cut_aligned: bool,
    metrics: ResultMetrics,
) -> _AttemptFailure:
    state = _ConsistencyState(
        context_ids=context_ids,
        stable_reads=ConsistencyLevel.UNKNOWN,
        cut_aligned=cut_aligned,
    )
    return _AttemptFailure(
        execution_status=ExecutionStatus.INCOMPLETE,
        verdict=Verdict.INCONCLUSIVE,
        reason=_reason_with_cleanup_state(
            _reason_with_failure_metrics(context_loss_reason, metrics),
            state,
        ),
        additional_reasons=(),
        retryable=True,
        context_ids=context_ids,
        stable_reads=state.stable_reads,
        cut_aligned=cut_aligned,
        comparison_coverage=_empty_comparison_coverage(),
        evidence_coverage=_empty_evidence_coverage(),
        metrics=metrics,
        partial_artifact=None,
        persisted_cut=None,
    )


def _degraded_stable_reads(level: ConsistencyLevel) -> ConsistencyLevel:
    if level is ConsistencyLevel.VERIFIED:
        return ConsistencyLevel.VERIFIED
    return ConsistencyLevel.UNKNOWN


def _reason_with_failure_consistency(
    reason: ResultReason,
    state: _ConsistencyState,
    metrics: ResultMetrics,
) -> ResultReason:
    parameters = (*_failure_consistency_parameters(state), *_failure_metrics_parameters(metrics))
    existing_names = {parameter.name for parameter in reason.safe_parameters}
    if any(parameter.name in existing_names for parameter in parameters):
        raise ApplicationStateError("attempt reason conflicts with failure consistency parameters")
    return ResultReason(
        code=reason.code,
        operation=reason.operation,
        message=reason.message,
        safe_parameters=(*reason.safe_parameters, *parameters),
        native_error_code=reason.native_error_code,
        query_id=reason.query_id,
        redacted_response=reason.redacted_response,
    )


def _failure_consistency_parameters(
    state: _ConsistencyState,
) -> tuple[SafeParameter, ...]:
    values: list[tuple[str, str]] = [
        ("failure_context_count", str(len(state.context_ids))),
        ("failure_stable_reads", state.stable_reads.value),
        ("failure_cut_aligned", "1" if state.cut_aligned else "0"),
    ]
    values.extend(
        (f"failure_context_{index}", str(context_id))
        for index, context_id in enumerate(state.context_ids)
    )
    return tuple(SafeParameter(name=name, value=value) for name, value in values)


def _failure_metrics_parameters(metrics: ResultMetrics) -> tuple[SafeParameter, ...]:
    values = (
        ("failure_metrics_queries", str(metrics.queries)),
        ("failure_metrics_fetched_records", str(metrics.fetched_records)),
        ("failure_metrics_result_bytes", str(metrics.result_bytes)),
        ("failure_metrics_fingerprint_nodes", str(metrics.fingerprint_nodes)),
        ("failure_metrics_coordinator_peak_bytes", str(metrics.coordinator_peak_bytes)),
        ("failure_metrics_elapsed_milliseconds", str(metrics.elapsed_milliseconds)),
    )
    return tuple(SafeParameter(name=name, value=value) for name, value in values)


def _reason_with_failure_metrics(
    reason: ResultReason,
    metrics: ResultMetrics,
) -> ResultReason:
    parameters = _failure_metrics_parameters(metrics)
    existing_names = {parameter.name for parameter in reason.safe_parameters}
    if any(parameter.name in existing_names for parameter in parameters):
        raise ApplicationStateError("attempt reason conflicts with failure metric parameters")
    return ResultReason(
        code=reason.code,
        operation=reason.operation,
        message=reason.message,
        safe_parameters=(*reason.safe_parameters, *parameters),
        native_error_code=reason.native_error_code,
        query_id=reason.query_id,
        redacted_response=reason.redacted_response,
    )


def _reason_without_failure_consistency(reason: ResultReason) -> ResultReason:
    state = _failure_consistency_from_reason(reason)
    if state is None:
        return reason
    parameter_names = {parameter.name for parameter in _failure_consistency_parameters(state)}
    return ResultReason(
        code=reason.code,
        operation=reason.operation,
        message=reason.message,
        safe_parameters=tuple(
            parameter
            for parameter in reason.safe_parameters
            if parameter.name not in parameter_names
        ),
        native_error_code=reason.native_error_code,
        query_id=reason.query_id,
        redacted_response=reason.redacted_response,
    )


def _reason_with_cleanup_state(
    reason: ResultReason,
    state: _ConsistencyState,
) -> ResultReason:
    parameters = _cleanup_state_parameters(state)
    existing_names = {parameter.name for parameter in reason.safe_parameters}
    if any(parameter.name in existing_names for parameter in parameters):
        raise ApplicationStateError("attempt reason conflicts with cleanup state parameters")
    return ResultReason(
        code=reason.code,
        operation=reason.operation,
        message=reason.message,
        safe_parameters=(*reason.safe_parameters, *parameters),
        native_error_code=reason.native_error_code,
        query_id=reason.query_id,
        redacted_response=reason.redacted_response,
    )


def _cleanup_state_parameters(state: _ConsistencyState) -> tuple[SafeParameter, ...]:
    values: list[tuple[str, str]] = [
        ("cleanup_context_lost", "1"),
        ("cleanup_context_count", str(len(state.context_ids))),
        ("cleanup_stable_reads", state.stable_reads.value),
        ("cleanup_cut_aligned", "1" if state.cut_aligned else "0"),
    ]
    values.extend(
        (f"cleanup_context_{index}", str(context_id))
        for index, context_id in enumerate(state.context_ids)
    )
    return tuple(SafeParameter(name=name, value=value) for name, value in values)


def _record_retryable_failure(
    attempt: RunAttemptRecord,
    failure: _AttemptFailure,
    services: ExecutionServices,
) -> AttemptOutcomeRecord | RunResult:
    if failure.partial_artifact is not None:
        comparison = _partial_comparison_definition(attempt, failure)
        if failure.execution_status is ExecutionStatus.INCOMPLETE:
            return record_postgres_retryable_incomplete_comparison(
                services.metadata_settings,
                services.metadata_retry_policy,
                attempt,
                uuid4(),
                comparison,
                datetime.now(UTC),
            )
        return record_postgres_retryable_error_comparison(
            services.metadata_settings,
            services.metadata_retry_policy,
            attempt,
            uuid4(),
            comparison,
            datetime.now(UTC),
        )
    if failure.execution_status is ExecutionStatus.INCOMPLETE:
        return record_postgres_retryable_incomplete_attempt(
            services.metadata_settings,
            services.metadata_retry_policy,
            attempt,
            uuid4(),
            failure.reason,
            datetime.now(UTC),
        )
    return record_postgres_retryable_error_attempt(
        services.metadata_settings,
        services.metadata_retry_policy,
        attempt,
        uuid4(),
        failure.reason,
        datetime.now(UTC),
    )


def _publish_terminal_failure(
    attempt: RunAttemptRecord,
    failure: _AttemptFailure,
    services: ExecutionServices,
) -> AttemptOutcomeRecord | RunResult:
    if failure.partial_artifact is not None:
        comparison = _partial_comparison_definition(attempt, failure)
        if failure.execution_status is ExecutionStatus.INCOMPLETE:
            return publish_postgres_terminal_incomplete_comparison(
                services.metadata_settings,
                services.metadata_retry_policy,
                attempt,
                uuid4(),
                comparison,
                datetime.now(UTC),
            )
        return publish_postgres_terminal_error_comparison(
            services.metadata_settings,
            services.metadata_retry_policy,
            attempt,
            uuid4(),
            comparison,
            datetime.now(UTC),
        )
    if failure.execution_status is ExecutionStatus.INCOMPLETE:
        return publish_postgres_terminal_incomplete_attempt(
            services.metadata_settings,
            services.metadata_retry_policy,
            attempt,
            uuid4(),
            failure.reason,
            datetime.now(UTC),
        )
    return publish_postgres_terminal_error_attempt(
        services.metadata_settings,
        services.metadata_retry_policy,
        attempt,
        uuid4(),
        failure.reason,
        datetime.now(UTC),
    )


def _partial_comparison_definition(
    attempt: RunAttemptRecord,
    failure: _AttemptFailure,
) -> PartialComparisonDefinition:
    artifact = failure.partial_artifact
    persisted_cut = failure.persisted_cut
    if artifact is None or persisted_cut is None:
        raise ApplicationStateError(
            "partial comparison publication requires its artifact and persisted cut"
        )
    return partial_comparison_persistence_from_artifact(
        attempt,
        persisted_cut,
        artifact,
        failure.execution_status,
        failure.reason,
        failure.additional_reasons,
    )


def _run_result_from_attempt_outcome(
    check: RowCheckDefinition,
    scope: ResolvedScope,
    outcome: AttemptOutcomeRecord,
    failure: _AttemptFailure,
) -> RunResult:
    unavailable = UnavailableTotal(precision="unavailable", value=None, reason=outcome.reason.code)
    cut_alignment = ConsistencyLevel.VERIFIED if failure.cut_aligned else ConsistencyLevel.UNKNOWN
    return RunResult(
        schema_version=1,
        run_id=outcome.run_id,
        attempt_id=outcome.attempt_id,
        check_id=check.check_id,
        contract_digest=check.contract_digest,
        scope_digest=scope.scope_digest,
        execution_status=failure.execution_status,
        verdict=failure.verdict,
        consistency=ConsistencyStatus(
            stable_reads=failure.stable_reads,
            cut_alignment=cut_alignment,
            read_context_ids=failure.context_ids,
        ),
        guarantee=Guarantee.NOT_ESTABLISHED,
        comparison_coverage=failure.comparison_coverage,
        totals=ComparisonTotals(
            matched=unavailable,
            missing=unavailable,
            extra=unavailable,
            modified=unavailable,
        ),
        evidence_coverage=failure.evidence_coverage,
        metrics=failure.metrics,
        reasons=(outcome.reason, *failure.additional_reasons),
        persistence=PersistenceStatus(
            state=PersistenceState.CONFIRMED,
            operation_id=outcome.operation_id,
            reason=None,
        ),
    )


def _failure_from_early_outcome(
    outcome: EarlyExecutionOutcome,
    context_ids: tuple[UUID, ...],
    cut_aligned: bool,
    metrics: ResultMetrics,
) -> _AttemptFailure:
    state = _ConsistencyState(
        context_ids=context_ids,
        stable_reads=ConsistencyLevel.UNKNOWN,
        cut_aligned=cut_aligned,
    )
    return _AttemptFailure(
        execution_status=outcome.execution_status,
        verdict=Verdict.INCONCLUSIVE,
        reason=_reason_with_failure_consistency(outcome.reason, state, metrics),
        additional_reasons=(),
        retryable=outcome.execution_status is ExecutionStatus.INCOMPLETE,
        context_ids=state.context_ids,
        stable_reads=state.stable_reads,
        cut_aligned=state.cut_aligned,
        comparison_coverage=_empty_comparison_coverage(),
        evidence_coverage=_empty_evidence_coverage(),
        metrics=metrics,
        partial_artifact=None,
        persisted_cut=None,
    )


def _failure_from_comparison_interruption(
    error: ComparisonInterruptedError,
    resources: list[_AttemptResource],
    persisted_cut: PersistedInputCut | None,
) -> _AttemptFailure:
    if persisted_cut is None:
        raise ApplicationStateError(
            "interrupted comparison requires its persisted aligned input cut"
        )
    artifact = error.artifact
    cause = error.cause
    additional_reasons: tuple[ResultReason, ...] = ()
    if isinstance(cause, ComparisonKeyMappingError):
        contract_reason = cause.contract_violation_reason
        execution_status = ExecutionStatus.ERROR
        reason = _reason(
            ReasonCode.LOSSY_TRANSPORT,
            "validate_key_mapping",
            "scoped key values cannot map losslessly to logical INT64",
            _mapping_error_parameters(cause, artifact.consistency.read_context_ids),
        )
        additional_reasons = () if contract_reason is None else (contract_reason,)
        retryable = False
    elif isinstance(cause, UnsupportedComparisonError):
        execution_status = ExecutionStatus.ERROR
        message = str(cause).strip()
        if not message:
            raise ApplicationStateError(
                "unsupported comparison error must include a safe actionable explanation"
            )
        reason = _reason(ReasonCode.UNSUPPORTED_CAPABILITY, "compare", message, ())
        retryable = False
    elif isinstance(cause, MssqlQueryTimeoutError):
        execution_status = ExecutionStatus.INCOMPLETE
        reason = _mssql_query_timeout_reason(cause)
        retryable = False
    elif isinstance(
        cause,
        (
            ComparisonBudgetExceededError,
            GreengageBudgetExceededError,
            OriginalGreenplumBudgetExceededError,
            PostgresReadDeadlineExceededError,
            PostgresResultLimitError,
            PostgresSourceBudgetExceededError,
            MssqlResultLimitError,
        ),
    ):
        execution_status = ExecutionStatus.INCOMPLETE
        reason = _reason_from_source_error(
            ReasonCode.BUDGET_EXHAUSTED,
            "compare",
            "the check exhausted an immutable execution budget",
            cause,
        )
        retryable = False
    elif isinstance(cause, MssqlCancellationConfirmedError):
        execution_status = ExecutionStatus.INCOMPLETE
        reason = _mssql_confirmed_cancellation_reason(cause)
        retryable = False
    elif isinstance(cause, MssqlCancellationUnconfirmedError):
        execution_status = ExecutionStatus.INCOMPLETE
        reason = _mssql_unconfirmed_cancellation_reason(cause)
        retryable = False
    elif isinstance(
        cause,
        (
            PostgresContextLostError,
            PostgresAcquisitionRaceError,
            MssqlContextLostError,
            MssqlMetadataError,
            GreenplumContextLostError,
            GreengageAcquisitionRaceError,
            OriginalGreenplumAcquisitionRaceError,
        ),
    ):
        execution_status = ExecutionStatus.INCOMPLETE
        reason = _reason(
            ReasonCode.SNAPSHOT_LOST,
            "read_source",
            "a protected source snapshot was lost before completion",
            (SafeParameter(name="error_type", value=type(cause).__name__),),
        )
        retryable = True
    elif isinstance(
        cause,
        (
            PostgresConnectionError,
            PostgresQueryError,
            PostgresMetadataError,
            MssqlConnectionError,
            MssqlQueryError,
            GreenplumConnectionError,
            GreenplumQueryError,
        ),
    ):
        execution_status = ExecutionStatus.ERROR
        reason = _reason_from_source_error(
            ReasonCode.QUERY_ERROR,
            "read_source",
            "a source operation failed",
            cause,
        )
        retryable = True
    elif isinstance(cause, UnsupportedPostgresProfileError):
        execution_status = ExecutionStatus.ERROR
        reason = _reason(
            ReasonCode.UNSUPPORTED_CAPABILITY,
            "open_source",
            "a source does not satisfy the required runtime profile",
            (SafeParameter(name="error_type", value=type(cause).__name__),),
        )
        retryable = False
    elif isinstance(cause, UnsupportedMssqlProfileError):
        execution_status = ExecutionStatus.ERROR
        reason = _reason(
            ReasonCode.UNSUPPORTED_CAPABILITY,
            "open_source",
            _actionable_mssql_error_message(cause, "SQL Server profile refusal"),
            (SafeParameter(name="error_type", value=type(cause).__name__),),
        )
        retryable = False
    elif isinstance(cause, (UnsupportedGreenplumProfileError, GreenplumMetadataError)):
        execution_status = ExecutionStatus.ERROR
        reason = _reason(
            ReasonCode.UNSUPPORTED_CAPABILITY,
            "compare",
            "a Greenplum-family endpoint does not satisfy the required runtime capability",
            (SafeParameter(name="error_type", value=type(cause).__name__),),
        )
        retryable = False
    elif isinstance(
        cause,
        (
            AcquisitionValidationError,
            ComparisonProtocolError,
            PostgresContextClosedError,
            PostgresDataValidationError,
            PostgresQueryContextError,
            MssqlContextClosedError,
            MssqlDataValidationError,
            MssqlQueryContextError,
            GreenplumContextClosedError,
            GreenplumDataValidationError,
        ),
    ):
        execution_status = ExecutionStatus.ERROR
        reason = _reason(
            ReasonCode.PROTOCOL_VIOLATION,
            "execute_check",
            "source evidence violated the declared check protocol",
            (SafeParameter(name="error_type", value=type(cause).__name__),),
        )
        retryable = False
    elif isinstance(cause, MssqlTransportError):
        execution_status = ExecutionStatus.ERROR
        reason = _reason(
            ReasonCode.QUERY_ERROR,
            "read_source",
            "a SQL Server source operation failed",
            (SafeParameter(name="error_type", value=type(cause).__name__),),
        )
        retryable = True
    else:
        raise AssertionError(f"unhandled comparison interruption cause {type(cause).__name__}")

    if artifact.verdict is Verdict.MISMATCH and not any(
        item.code in (ReasonCode.DATA_MISMATCH, ReasonCode.CONTRACT_VIOLATION)
        for item in additional_reasons
    ):
        additional_reasons = (*additional_reasons, _partial_data_mismatch_reason(artifact))
    consistency = artifact.consistency
    if tuple(consistency.read_context_ids) != _context_ids(resources):
        raise ApplicationStateError(
            "partial comparison context identity differs from the active attempt resources"
        )
    return _AttemptFailure(
        execution_status=execution_status,
        verdict=artifact.verdict,
        reason=reason,
        additional_reasons=additional_reasons,
        retryable=retryable,
        context_ids=consistency.read_context_ids,
        stable_reads=consistency.stable_reads,
        cut_aligned=consistency.cut_alignment is not ConsistencyLevel.UNKNOWN,
        comparison_coverage=artifact.comparison_coverage,
        evidence_coverage=artifact.evidence_coverage,
        metrics=artifact.metrics,
        partial_artifact=artifact,
        persisted_cut=persisted_cut,
    )


def _partial_data_mismatch_reason(artifact: PartialComparisonArtifact) -> ResultReason:
    difference_names = ("missing", "extra", "modified")
    difference_totals = artifact.totals.differences()
    parameters = tuple(
        SafeParameter(name=f"{name}_lower_bound", value=total.value)
        for name, total in zip(difference_names, difference_totals, strict=True)
        if isinstance(total, LowerBoundTotal) and total.value != "0"
    )
    return _reason(
        ReasonCode.DATA_MISMATCH,
        "compare_integer_key_rows",
        (
            "completed exact leaves established row differences"
            if parameters
            else "comparable fingerprints established a content difference"
        ),
        parameters,
    )


def _failure_from_error(
    execution_status: ExecutionStatus,
    reason_code: ReasonCode,
    operation: str,
    message: str,
    error: Exception,
    retryable: bool,
    resources: list[_AttemptResource],
    cut_aligned: bool,
    source_budget: PostgresSourceBudgetAttempt,
) -> _AttemptFailure:
    state = _ConsistencyState(
        context_ids=_context_ids(resources),
        stable_reads=ConsistencyLevel.UNKNOWN,
        cut_aligned=cut_aligned,
    )
    metrics = _result_metrics_from_source_budget(source_budget)
    return _AttemptFailure(
        execution_status=execution_status,
        verdict=Verdict.INCONCLUSIVE,
        reason=_reason_with_failure_consistency(
            _reason_from_source_error(
                reason_code,
                operation,
                message,
                error,
            ),
            state,
            metrics,
        ),
        additional_reasons=(),
        retryable=retryable,
        context_ids=state.context_ids,
        stable_reads=state.stable_reads,
        cut_aligned=state.cut_aligned,
        comparison_coverage=_empty_comparison_coverage(),
        evidence_coverage=_empty_evidence_coverage(),
        metrics=metrics,
        partial_artifact=None,
        persisted_cut=None,
    )


def _reason_from_source_error(
    code: ReasonCode,
    operation: str,
    message: str,
    error: Exception,
) -> ResultReason:
    reason = _reason(code, operation, message, _source_error_parameters(error))
    if isinstance(error, GreenplumQueryError):
        return reason.model_copy(update={"native_error_code": error.sqlstate})
    return reason


def _source_error_parameters(error: Exception) -> tuple[SafeParameter, ...]:
    parameters = [SafeParameter(name="error_type", value=type(error).__name__)]
    if isinstance(error, GreenplumQueryError):
        parameters.extend(
            (
                SafeParameter(name="source_operation", value=error.operation),
                SafeParameter(name="error_category", value=error.error_category),
            )
        )
    if isinstance(
        error,
        (GreengageBudgetExceededError, OriginalGreenplumBudgetExceededError),
    ):
        parameters.append(SafeParameter(name="budget_detail", value=str(error)))
    return tuple(parameters)


def _actionable_mssql_error_message(
    error: MssqlLoweringError | UnsupportedMssqlProfileError | UnsupportedMssqlRelationError,
    context: str,
) -> str:
    message = str(error).strip()
    if not message:
        raise ApplicationStateError(f"{context} must include a safe actionable explanation")
    return message


def _failure_from_terminal_source_reason(
    reason: ResultReason,
    resources: list[_AttemptResource],
    cut_aligned: bool,
    source_budget: PostgresSourceBudgetAttempt,
) -> _AttemptFailure:
    state = _ConsistencyState(
        context_ids=_context_ids(resources),
        stable_reads=ConsistencyLevel.UNKNOWN,
        cut_aligned=cut_aligned,
    )
    metrics = _result_metrics_from_source_budget(source_budget)
    return _AttemptFailure(
        execution_status=ExecutionStatus.INCOMPLETE,
        verdict=Verdict.INCONCLUSIVE,
        reason=_reason_with_failure_consistency(reason, state, metrics),
        additional_reasons=(),
        retryable=False,
        context_ids=state.context_ids,
        stable_reads=state.stable_reads,
        cut_aligned=state.cut_aligned,
        comparison_coverage=_empty_comparison_coverage(),
        evidence_coverage=_empty_evidence_coverage(),
        metrics=metrics,
        partial_artifact=None,
        persisted_cut=None,
    )


def _mssql_query_timeout_reason(error: MssqlQueryTimeoutError) -> ResultReason:
    return ResultReason(
        code=ReasonCode.BUDGET_EXHAUSTED,
        operation="read_source",
        message="the SQL Server statement reached its immutable query or run timeout",
        safe_parameters=(
            SafeParameter(name="error_type", value=type(error).__name__),
            SafeParameter(name="session_id", value=str(error.session_id)),
        ),
        native_error_code=error.sqlstate,
        query_id=str(error.query_id),
        redacted_response=None,
    )


def _mssql_confirmed_cancellation_reason(
    error: MssqlCancellationConfirmedError,
) -> ResultReason:
    return ResultReason(
        code=ReasonCode.CANCELLED,
        operation="cancel_source_query",
        message="the SQL Server source query was cancelled and completion was confirmed",
        safe_parameters=(
            SafeParameter(name="error_type", value=type(error).__name__),
            SafeParameter(name="session_id", value=str(error.session_id)),
            SafeParameter(
                name="confirmation_session_id",
                value=str(error.confirmation_session_id),
            ),
            SafeParameter(name="confirmation_value", value=str(error.confirmation_value)),
        ),
        native_error_code=error.sqlstate,
        query_id=str(error.query_id),
        redacted_response=None,
    )


def _mssql_unconfirmed_cancellation_reason(
    error: MssqlCancellationUnconfirmedError,
) -> ResultReason:
    return ResultReason(
        code=ReasonCode.CANCELLATION_UNCONFIRMED,
        operation="cancel_source_query",
        message="SQL Server source-query completion could not be confirmed after cancellation",
        safe_parameters=(
            SafeParameter(name="error_type", value=type(error).__name__),
            SafeParameter(name="session_id", value=str(error.session_id)),
            SafeParameter(name="confirmation_failure", value=error.reason),
        ),
        native_error_code=None,
        query_id=str(error.query_id),
        redacted_response=None,
    )


def _failure_from_unsupported_comparison(
    error: UnsupportedComparisonError,
    resources: list[_AttemptResource],
    cut_aligned: bool,
    source_budget: PostgresSourceBudgetAttempt,
) -> _AttemptFailure:
    message = str(error).strip()
    if not message:
        raise ApplicationStateError(
            "unsupported comparison error must include a safe actionable explanation"
        )
    return _failure_from_error(
        ExecutionStatus.ERROR,
        ReasonCode.UNSUPPORTED_CAPABILITY,
        "compare",
        message,
        error,
        False,
        resources,
        cut_aligned,
        source_budget,
    )


def _reason(
    code: ReasonCode,
    operation: str,
    message: str,
    safe_parameters: tuple[SafeParameter, ...],
) -> ResultReason:
    return ResultReason(
        code=code,
        operation=operation,
        message=message,
        safe_parameters=safe_parameters,
        native_error_code=None,
        query_id=None,
        redacted_response=None,
    )


def _run_result_from_terminal_readback(
    check: RowCheckDefinition,
    scope: ResolvedScope,
    outcome: AttemptOutcomeRecord,
) -> RunResult:
    if outcome.status is AttemptStatus.ERROR:
        execution_status = ExecutionStatus.ERROR
    elif outcome.status in (AttemptStatus.INCOMPLETE, AttemptStatus.ABANDONED):
        execution_status = ExecutionStatus.INCOMPLETE
    else:
        raise ApplicationStateError(
            "terminal attempt readback returned a status that is not an early outcome"
        )
    if _is_artifact_context_loss_reason(outcome.reason):
        if outcome.status is not AttemptStatus.INCOMPLETE:
            raise ApplicationStateError(
                "stored artifact cleanup result must have incomplete attempt status"
            )
        failure = _failure_from_stored_artifact_context_loss(outcome.reason)
        return _run_result_from_attempt_outcome(check, scope, outcome, failure)

    cleanup_state = _cleanup_state_from_reason(outcome.reason)
    contract_reason = _mapping_contract_reason(outcome.reason)
    verdict = Verdict.MISMATCH if contract_reason is not None else Verdict.INCONCLUSIVE
    failure_metrics = _failure_metrics_from_reason(outcome.reason)
    metrics = failure_metrics if failure_metrics is not None else _mapping_metrics(outcome.reason)
    mapping_failure = outcome.reason.code is ReasonCode.LOSSY_TRANSPORT
    failure_state = _failure_consistency_from_reason(outcome.reason)
    if failure_state is not None and (cleanup_state is not None or mapping_failure):
        raise ApplicationStateError(
            "stored terminal reason mixes generic and specialized consistency state"
        )
    if cleanup_state is not None:
        state = cleanup_state
    elif failure_state is not None:
        state = failure_state
    else:
        context_ids = _mapping_context_ids(outcome.reason)
        cut_aligned = mapping_failure and len(context_ids) == 2
        state = _ConsistencyState(
            context_ids=context_ids,
            stable_reads=(ConsistencyLevel.VERIFIED if cut_aligned else ConsistencyLevel.UNKNOWN),
            cut_aligned=cut_aligned,
        )
    cleanup_is_primary = (
        outcome.reason.code is ReasonCode.SNAPSHOT_LOST
        and outcome.reason.operation == "close_read_context"
    )
    cleanup_reasons = (
        () if cleanup_state is None or cleanup_is_primary else (_context_loss_reason(),)
    )
    failure = _AttemptFailure(
        execution_status=execution_status,
        verdict=verdict,
        reason=outcome.reason,
        additional_reasons=(
            (() if contract_reason is None else (contract_reason,)) + cleanup_reasons
        ),
        retryable=False,
        context_ids=state.context_ids,
        stable_reads=state.stable_reads,
        cut_aligned=state.cut_aligned,
        comparison_coverage=(
            _mapping_failure_coverage() if mapping_failure else _empty_comparison_coverage()
        ),
        evidence_coverage=_empty_evidence_coverage(),
        metrics=metrics,
        partial_artifact=None,
        persisted_cut=None,
    )
    return _run_result_from_attempt_outcome(check, scope, outcome, failure)


def _is_artifact_context_loss_reason(reason: ResultReason) -> bool:
    values = _safe_parameter_mapping(reason)
    return values.get("cleanup_artifact") == "1"


def _failure_from_stored_artifact_context_loss(reason: ResultReason) -> _AttemptFailure:
    values = _safe_parameter_mapping(reason)
    state = _cleanup_state_from_reason(reason)
    if state is None or values.get("cleanup_artifact") != "1":
        raise ApplicationStateError("stored artifact cleanup state is incomplete")
    verdict_text = values.get("observed_verdict")
    if verdict_text not in (Verdict.MATCH.value, Verdict.MISMATCH.value):
        raise ApplicationStateError("stored artifact cleanup verdict is unsupported")
    observed_verdict = Verdict(verdict_text)
    findings = _stored_artifact_findings(values)
    if (observed_verdict is Verdict.MISMATCH) != bool(findings):
        raise ApplicationStateError("stored artifact cleanup verdict and findings disagree")
    return _AttemptFailure(
        execution_status=ExecutionStatus.INCOMPLETE,
        verdict=(
            Verdict.MISMATCH if observed_verdict is Verdict.MISMATCH else Verdict.INCONCLUSIVE
        ),
        reason=reason,
        additional_reasons=findings,
        retryable=False,
        context_ids=state.context_ids,
        stable_reads=state.stable_reads,
        cut_aligned=state.cut_aligned,
        comparison_coverage=_stored_artifact_coverage(values),
        evidence_coverage=_stored_artifact_evidence(values),
        metrics=_stored_artifact_metrics(values),
        partial_artifact=None,
        persisted_cut=None,
    )


def _failure_consistency_from_reason(reason: ResultReason) -> _ConsistencyState | None:
    values = _safe_parameter_mapping(reason)
    count_text = values.get("failure_context_count")
    if count_text is None:
        return None
    count = _nonnegative_decimal(count_text, "failure_context_count")
    if count > 2:
        raise ApplicationStateError("stored failure context count exceeds the endpoint boundary")
    try:
        context_ids = tuple(UUID(values[f"failure_context_{index}"]) for index in range(count))
    except (KeyError, ValueError):
        raise ApplicationStateError("stored failure context identity is invalid") from None
    if len(set(context_ids)) != len(context_ids):
        raise ApplicationStateError("stored failure context identities must be distinct")
    stable_reads_text = values.get("failure_stable_reads")
    try:
        stable_reads = ConsistencyLevel(stable_reads_text)
    except (TypeError, ValueError):
        raise ApplicationStateError("stored failure stable-read level is invalid") from None
    if stable_reads is ConsistencyLevel.ASSERTED:
        raise ApplicationStateError("stored failure consistency cannot assert stable reads")
    cut_aligned_text = values.get("failure_cut_aligned")
    if cut_aligned_text not in ("0", "1"):
        raise ApplicationStateError("stored failure cut-alignment marker is invalid")
    cut_aligned = cut_aligned_text == "1"
    if cut_aligned and len(context_ids) != 2:
        raise ApplicationStateError("stored aligned failure state requires two contexts")
    if stable_reads is ConsistencyLevel.VERIFIED and len(context_ids) != 2:
        raise ApplicationStateError("stored verified failure state requires two contexts")
    return _ConsistencyState(
        context_ids=context_ids,
        stable_reads=stable_reads,
        cut_aligned=cut_aligned,
    )


def _failure_metrics_from_reason(reason: ResultReason) -> ResultMetrics | None:
    values = _safe_parameter_mapping(reason)
    marker = values.get("failure_metrics_queries")
    if marker is None:
        return None
    return ResultMetrics(
        queries=_nonnegative_decimal(marker, "failure_metrics_queries"),
        fetched_records=_nonnegative_decimal(
            values.get("failure_metrics_fetched_records"),
            "failure_metrics_fetched_records",
        ),
        result_bytes=_nonnegative_decimal(
            values.get("failure_metrics_result_bytes"),
            "failure_metrics_result_bytes",
        ),
        fingerprint_nodes=_nonnegative_decimal(
            values.get("failure_metrics_fingerprint_nodes"),
            "failure_metrics_fingerprint_nodes",
        ),
        coordinator_peak_bytes=_nonnegative_decimal(
            values.get("failure_metrics_coordinator_peak_bytes"),
            "failure_metrics_coordinator_peak_bytes",
        ),
        elapsed_milliseconds=_nonnegative_decimal(
            values.get("failure_metrics_elapsed_milliseconds"),
            "failure_metrics_elapsed_milliseconds",
        ),
    )


def _cleanup_state_from_reason(reason: ResultReason) -> _ConsistencyState | None:
    values = _safe_parameter_mapping(reason)
    marker = values.get("cleanup_context_lost")
    if marker is None:
        return None
    if marker != "1":
        raise ApplicationStateError("stored cleanup context-lost marker is invalid")
    count = _nonnegative_decimal(values.get("cleanup_context_count"), "cleanup_context_count")
    if count > 2:
        raise ApplicationStateError("stored cleanup context count exceeds the endpoint boundary")
    try:
        context_ids = tuple(UUID(values[f"cleanup_context_{index}"]) for index in range(count))
    except (KeyError, ValueError):
        raise ApplicationStateError("stored cleanup context identity is invalid") from None
    if len(set(context_ids)) != len(context_ids):
        raise ApplicationStateError("stored cleanup context identities must be distinct")
    stable_reads_text = values.get("cleanup_stable_reads")
    try:
        stable_reads = ConsistencyLevel(stable_reads_text)
    except (TypeError, ValueError):
        raise ApplicationStateError("stored cleanup stable-read level is invalid") from None
    if stable_reads is ConsistencyLevel.ASSERTED:
        raise ApplicationStateError("lost cleanup context cannot retain asserted stable reads")
    cut_aligned_text = values.get("cleanup_cut_aligned")
    if cut_aligned_text not in ("0", "1"):
        raise ApplicationStateError("stored cleanup cut-alignment marker is invalid")
    cut_aligned = cut_aligned_text == "1"
    if cut_aligned and len(context_ids) != 2:
        raise ApplicationStateError("stored aligned cleanup state requires two contexts")
    if stable_reads is ConsistencyLevel.VERIFIED and len(context_ids) != 2:
        raise ApplicationStateError("stored verified cleanup state requires two contexts")
    return _ConsistencyState(
        context_ids=context_ids,
        stable_reads=stable_reads,
        cut_aligned=cut_aligned,
    )


def _stored_artifact_findings(values: Mapping[str, str]) -> tuple[ResultReason, ...]:
    payload = _required_parameter(values, "observed_finding")
    if payload == "none":
        return ()
    try:
        finding = ResultReason.model_validate_json(payload)
    except ValueError as error:
        raise ApplicationStateError(
            f"stored artifact cleanup finding is invalid: reason={error}"
        ) from None
    if finding.code not in (ReasonCode.DATA_MISMATCH, ReasonCode.CONTRACT_VIOLATION):
        raise ApplicationStateError("stored artifact cleanup finding code is unsupported")
    return (finding,)


def _stored_artifact_coverage(values: Mapping[str, str]) -> ComparisonCoverage:
    payload = _required_parameter(values, "observed_comparison_coverage")
    try:
        return ComparisonCoverage.model_validate_json(payload)
    except ValueError as error:
        raise ApplicationStateError(
            f"stored artifact comparison coverage is invalid: reason={error}"
        ) from None


def _stored_artifact_evidence(values: Mapping[str, str]) -> EvidenceCoverage:
    payload = _required_parameter(values, "observed_evidence_coverage")
    try:
        return EvidenceCoverage.model_validate_json(payload)
    except ValueError as error:
        raise ApplicationStateError(
            f"stored artifact evidence coverage is invalid: reason={error}"
        ) from None


def _stored_artifact_metrics(values: Mapping[str, str]) -> ResultMetrics:
    payload = _required_parameter(values, "observed_metrics")
    try:
        return ResultMetrics.model_validate_json(payload)
    except ValueError as error:
        raise ApplicationStateError(
            f"stored artifact metrics are invalid: reason={error}"
        ) from None


def _required_parameter(values: Mapping[str, str], name: str) -> str:
    value = values.get(name)
    if value is None:
        raise ApplicationStateError(f"stored terminal reason parameter {name!r} is missing")
    return value


def _mapping_error_parameters(
    error: ComparisonKeyMappingError,
    context_ids: tuple[UUID, ...],
) -> tuple[SafeParameter, ...]:
    reference = error.reference_summary
    target = error.target_summary
    metrics = error.metrics
    values: list[tuple[str, str]] = [
        ("reference_row_count", str(reference.row_count)),
        ("reference_null_key_count", str(reference.null_key_count)),
        ("reference_invalid_key_count", str(reference.invalid_key_count)),
        ("reference_valid_key_count", str(reference.valid_key_count)),
        ("reference_distinct_key_count", str(reference.distinct_key_count)),
        ("target_row_count", str(target.row_count)),
        ("target_null_key_count", str(target.null_key_count)),
        ("target_invalid_key_count", str(target.invalid_key_count)),
        ("target_valid_key_count", str(target.valid_key_count)),
        ("target_distinct_key_count", str(target.distinct_key_count)),
        ("queries", str(metrics.queries)),
        ("fetched_records", str(metrics.fetched_records)),
        ("result_bytes", str(metrics.result_bytes)),
        ("fingerprint_nodes", str(metrics.fingerprint_nodes)),
        ("coordinator_peak_bytes", str(metrics.coordinator_peak_bytes)),
        ("elapsed_milliseconds", str(metrics.elapsed_milliseconds)),
    ]
    if len(context_ids) == 2:
        values.extend(
            (
                ("reference_read_context_id", str(context_ids[0])),
                ("target_read_context_id", str(context_ids[1])),
            )
        )
    return tuple(SafeParameter(name=name, value=value) for name, value in values)


def _mapping_contract_reason(reason: ResultReason) -> ResultReason | None:
    if reason.code is not ReasonCode.LOSSY_TRANSPORT:
        return None
    values = _safe_parameter_mapping(reason)
    counts = _mapping_counts(values)
    reference_null = counts["reference_null_key_count"]
    reference_duplicates = (
        counts["reference_valid_key_count"] - counts["reference_distinct_key_count"]
    )
    target_null = counts["target_null_key_count"]
    target_duplicates = counts["target_valid_key_count"] - counts["target_distinct_key_count"]
    if reference_null + reference_duplicates + target_null + target_duplicates == 0:
        return None
    parameter_names = (
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
    return _reason(
        ReasonCode.CONTRACT_VIOLATION,
        "validate_integer_key_contract",
        "scoped integer-key validation found null or duplicate keys",
        tuple(SafeParameter(name=name, value=values[name]) for name in parameter_names),
    )


def _mapping_counts(values: Mapping[str, str]) -> dict[str, int]:
    prefixes = ("reference", "target")
    suffixes = (
        "row_count",
        "null_key_count",
        "invalid_key_count",
        "valid_key_count",
        "distinct_key_count",
    )
    parsed = {
        f"{prefix}_{suffix}": _nonnegative_decimal(
            values.get(f"{prefix}_{suffix}"),
            f"{prefix}_{suffix}",
        )
        for prefix in prefixes
        for suffix in suffixes
    }
    for prefix in prefixes:
        if parsed[f"{prefix}_row_count"] != (
            parsed[f"{prefix}_null_key_count"]
            + parsed[f"{prefix}_invalid_key_count"]
            + parsed[f"{prefix}_valid_key_count"]
        ):
            raise ApplicationStateError(
                f"stored {prefix} key-summary counts do not partition row_count"
            )
        if parsed[f"{prefix}_distinct_key_count"] > parsed[f"{prefix}_valid_key_count"]:
            raise ApplicationStateError(
                f"stored {prefix} distinct key count exceeds valid key count"
            )
    return parsed


def _mapping_metrics(reason: ResultReason) -> ResultMetrics:
    if reason.code is not ReasonCode.LOSSY_TRANSPORT:
        return _empty_metrics()
    values = _safe_parameter_mapping(reason)
    return ResultMetrics(
        queries=_nonnegative_decimal(values.get("queries"), "queries"),
        fetched_records=_nonnegative_decimal(
            values.get("fetched_records"),
            "fetched_records",
        ),
        result_bytes=_nonnegative_decimal(values.get("result_bytes"), "result_bytes"),
        fingerprint_nodes=_nonnegative_decimal(
            values.get("fingerprint_nodes"),
            "fingerprint_nodes",
        ),
        coordinator_peak_bytes=_nonnegative_decimal(
            values.get("coordinator_peak_bytes"),
            "coordinator_peak_bytes",
        ),
        elapsed_milliseconds=_nonnegative_decimal(
            values.get("elapsed_milliseconds"),
            "elapsed_milliseconds",
        ),
    )


def _mapping_context_ids(reason: ResultReason) -> tuple[UUID, ...]:
    if reason.code is not ReasonCode.LOSSY_TRANSPORT:
        return ()
    values = _safe_parameter_mapping(reason)
    reference = values.get("reference_read_context_id")
    target = values.get("target_read_context_id")
    if reference is None and target is None:
        return ()
    if reference is None or target is None:
        raise ApplicationStateError("stored key-mapping context identity is incomplete")
    try:
        context_ids = (UUID(reference), UUID(target))
    except ValueError:
        raise ApplicationStateError("stored key-mapping context identity is invalid") from None
    if context_ids[0] == context_ids[1]:
        raise ApplicationStateError("stored key-mapping context identities must differ")
    return context_ids


def _safe_parameter_mapping(reason: ResultReason) -> dict[str, str]:
    values = {parameter.name: parameter.value for parameter in reason.safe_parameters}
    if len(values) != len(reason.safe_parameters):
        raise ApplicationStateError("stored terminal reason has duplicate safe parameters")
    return values


def _nonnegative_decimal(value: str | None, name: str) -> int:
    if value is None or not value.isascii() or not value.isdecimal():
        raise ApplicationStateError(
            f"stored terminal reason parameter {name!r} must be nonnegative decimal text"
        )
    return int(value)


def _mapping_failure_coverage() -> ComparisonCoverage:
    return ComparisonCoverage(
        total_partitions=1,
        covered_partitions=0,
        resolved_segments=0,
        pruned_segments=0,
        exact_segments=0,
        unresolved_segments=1,
        unresolved_reasons=(ReasonCode.LOSSY_TRANSPORT,),
    )


def _empty_comparison_coverage() -> ComparisonCoverage:
    return ComparisonCoverage(
        total_partitions=0,
        covered_partitions=0,
        resolved_segments=0,
        pruned_segments=0,
        exact_segments=0,
        unresolved_segments=0,
        unresolved_reasons=(),
    )


def _empty_evidence_coverage() -> EvidenceCoverage:
    return EvidenceCoverage(
        found_records=0,
        retained_records=0,
        found_bytes=0,
        retained_bytes=0,
    )


def _empty_metrics() -> ResultMetrics:
    return ResultMetrics(
        queries=0,
        fetched_records=0,
        result_bytes=0,
        fingerprint_nodes=0,
        coordinator_peak_bytes=0,
        elapsed_milliseconds=0,
    )


def _result_metrics_from_source_budget(
    source_budget: PostgresSourceBudgetAttempt,
) -> ResultMetrics:
    snapshot = source_budget.snapshot()
    return ResultMetrics(
        queries=snapshot.queries,
        fetched_records=snapshot.fetched_records,
        result_bytes=snapshot.result_bytes,
        fingerprint_nodes=0,
        coordinator_peak_bytes=0,
        elapsed_milliseconds=snapshot.elapsed_milliseconds,
    )


def _context_ids(resources: list[_AttemptResource]) -> tuple[UUID, ...]:
    return tuple(
        resource.persisted.read_context_id
        for resource in resources
        if resource.persisted is not None
    )


def _side_definitions(
    check: RowCheckDefinition,
    direction: PlanDirection,
) -> tuple[DatasetDefinition, ConsistencyDatasetDefinition]:
    index = 0 if direction is PlanDirection.REFERENCE else 1
    dataset = check.reference if direction is PlanDirection.REFERENCE else check.target
    return dataset, check.consistency.datasets[index]


def _postgres_settings(
    services: ExecutionServices,
    direction: PlanDirection,
) -> PostgresConnectionSettings:
    if direction is PlanDirection.TARGET and isinstance(
        services,
        (
            PostgresExecutionServices,
            MssqlPostgresExecutionServices,
            OriginalGreenplumPostgresExecutionServices,
        ),
    ):
        return services.target_settings
    if direction is PlanDirection.REFERENCE and isinstance(
        services,
        (PostgresExecutionServices, PostgresGreengageExecutionServices),
    ):
        return services.reference_settings
    raise TypeError("execution services do not provide PostgreSQL settings for this direction")


def _postgres_retry_policy(
    services: ExecutionServices,
    direction: PlanDirection,
) -> PostgresRetryPolicy:
    if isinstance(services, PostgresExecutionServices):
        return services.source_retry_policy
    if direction is PlanDirection.TARGET and isinstance(
        services,
        (MssqlPostgresExecutionServices, OriginalGreenplumPostgresExecutionServices),
    ):
        return services.target_retry_policy
    if direction is PlanDirection.REFERENCE and isinstance(
        services,
        PostgresGreengageExecutionServices,
    ):
        return services.reference_retry_policy
    raise TypeError(
        "execution services do not provide a PostgreSQL retry policy for this direction"
    )


def _protected_relation(
    context: PostgresProtectedReadContext,
    relation: PostgresRelation,
) -> PostgresProtectedRelationInspection:
    matches = tuple(
        item for item in context.protected_relations if item.inspection.relation == relation
    )
    if len(matches) != 1:
        raise PostgresQueryContextError(
            "protected PostgreSQL relation set does not contain exactly one requested relation"
        )
    return matches[0]


def _protected_mssql_relation(
    context: MssqlProtectedReadContext,
    relation: MssqlRelation,
) -> MssqlInspectedRelation:
    matches = tuple(item for item in context.protected_relations if item.relation == relation)
    if len(matches) != 1:
        raise MssqlQueryContextError(
            "protected SQL Server relation set does not contain exactly one requested relation"
        )
    return matches[0]


def _protected_greengage_relation(
    context: GreengageProtectedReadContext,
    relation: GreengageRelation,
) -> GreengageProtectedRelationInspection:
    matches = tuple(
        item for item in context.protected_relations if item.acquisition.relation == relation
    )
    if len(matches) != 1:
        raise GreenplumMetadataError(
            "protected Greengage relation set does not contain exactly one requested relation"
        )
    return matches[0]


def _protected_original_greenplum_relation(
    context: OriginalGreenplumProtectedReadContext,
    relation: OriginalGreenplumRelation,
) -> OriginalGreenplumProtectedRelationInspection:
    matches = tuple(
        item for item in context.protected_relations if item.acquisition.relation == relation
    )
    if len(matches) != 1:
        raise GreenplumMetadataError(
            "protected original Greenplum relation set does not contain exactly one requested "
            "relation"
        )
    return matches[0]


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


def _find_check(config: LoadedContractConfig, check_id: str) -> RowCheckDefinition:
    _require_nonblank(check_id, "check id")
    matches = tuple(check for check in config.checks if check.check_id == check_id)
    if len(matches) != 1:
        raise ContractReferenceError(f"application request references unknown check {check_id!r}")
    return matches[0]


def _validate_service_closure(
    config: LoadedContractConfig,
    check: RowCheckDefinition,
    services: ExecutionServices,
) -> None:
    expected = (
        check.reference.connection.connection_id,
        check.target.connection.connection_id,
        config.metadata.connection.connection_id,
    )
    actual = (
        services.reference_connection_id,
        services.target_connection_id,
        services.metadata_connection_id,
    )
    if actual != expected:
        raise ValueError(
            "execution service connection identities do not match the selected check closure: "
            f"expected={expected!r}, actual={actual!r}"
        )
    pair = (
        check.reference.connection.adapter,
        check.target.connection.adapter,
    )
    if pair == (Adapter.MSSQL, Adapter.POSTGRESQL):
        if not isinstance(services, MssqlPostgresExecutionServices):
            raise TypeError("MSSQL to PostgreSQL execution requires matching services")
        return
    if pair == (Adapter.MSSQL, Adapter.GREENGAGE):
        if not isinstance(services, MssqlGreengageExecutionServices):
            raise TypeError("MSSQL to Greengage execution requires matching services")
        return
    if pair == (Adapter.POSTGRESQL, Adapter.POSTGRESQL):
        if not isinstance(services, PostgresExecutionServices):
            raise TypeError("PostgreSQL endpoint execution requires matching services")
        return
    if pair == (Adapter.POSTGRESQL, Adapter.GREENGAGE):
        if not isinstance(services, PostgresGreengageExecutionServices):
            raise TypeError("PostgreSQL to Greengage execution requires matching services")
        return
    if pair == (Adapter.GREENPLUM, Adapter.POSTGRESQL):
        if not isinstance(services, OriginalGreenplumPostgresExecutionServices):
            raise TypeError("original Greenplum to PostgreSQL execution requires matching services")
        return
    if pair == (Adapter.GREENPLUM, Adapter.GREENGAGE):
        if not isinstance(services, OriginalGreenplumGreengageExecutionServices):
            raise TypeError("original Greenplum to Greengage execution requires matching services")
        return
    raise UnsupportedComparisonError(
        "execution adapter pair is not implemented: "
        f"reference={pair[0].value!r}, target={pair[1].value!r}"
    )


def _validate_runtime_profiles(
    config: LoadedContractConfig,
    check: RowCheckDefinition,
) -> None:
    reference = check.reference.connection
    if reference.adapter is Adapter.MSSQL:
        if match_mssql_runtime_profile(reference.driver, reference.profile) not in (
            MssqlRuntimeProfile.MSSQL_2022,
            MssqlRuntimeProfile.MSSQL_2016,
        ):
            raise UnsupportedMssqlProfileError(
                "declared SQL Server reference driver/profile is unsupported: "
                f"driver={reference.driver!r}, profile={reference.profile!r}"
            )
    elif reference.adapter is Adapter.POSTGRESQL:
        reference_profile = match_postgres_runtime_profile(
            reference.driver,
            reference.profile,
        )
        if reference_profile not in (
            PostgresRuntimeProfile.POSTGRES_17,
            PostgresRuntimeProfile.POSTGRES_9_6,
        ):
            raise UnsupportedPostgresProfileError(
                "declared PostgreSQL reference driver/profile is unsupported: "
                f"driver={reference.driver!r}, profile={reference.profile!r}"
            )
    elif reference.adapter is Adapter.GREENPLUM:
        if (
            match_greenplum_runtime_profile(reference.driver, reference.profile)
            is not GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
        ):
            raise UnsupportedGreenplumProfileError(
                "original Greenplum reference requires "
                "driver='psycopg2' and profile='original_greenplum'"
            )
    else:
        raise UnsupportedComparisonError(
            f"declared reference adapter is unsupported: adapter={reference.adapter.value!r}"
        )
    target = check.target.connection
    if target.adapter is Adapter.POSTGRESQL:
        if match_postgres_runtime_profile(target.driver, target.profile) is None:
            raise UnsupportedPostgresProfileError(
                "PostgreSQL target requires an explicit supported driver/profile pair: "
                "('psycopg', 'postgresql_17') or ('psycopg2', 'postgresql_9_6')"
            )
    elif target.adapter is Adapter.GREENGAGE:
        if (
            match_greenplum_runtime_profile(target.driver, target.profile)
            is not GreenplumRuntimeProfile.GREENGAGE
        ):
            raise UnsupportedGreenplumProfileError(
                "Greengage target requires driver='psycopg' and profile='greengage'"
            )
    else:
        raise UnsupportedComparisonError(
            f"declared target adapter is unsupported: adapter={target.adapter.value!r}"
        )
    metadata = config.metadata.connection
    if (
        metadata.adapter is not Adapter.POSTGRESQL
        or match_postgres_runtime_profile(metadata.driver, metadata.profile)
        is not PostgresRuntimeProfile.POSTGRES_17
    ):
        raise UnsupportedPostgresProfileError(
            "PostgreSQL metadata requires driver='psycopg' and profile='postgresql_17'"
        )


def _scope_mapping(values: tuple[ScopeValue, ...]) -> Mapping[str, ScopeInputValue]:
    return {item.name: item.value for item in values}


def _validate_request_scope(check_id: str, scope_values: tuple[ScopeValue, ...]) -> None:
    _require_nonblank(check_id, "request check id")
    if type(scope_values) is not tuple:
        raise TypeError("request scope values must be an immutable tuple")
    for value in cast(tuple[object, ...], scope_values):
        if not isinstance(value, ScopeValue):
            raise TypeError("request scope values must contain ScopeValue entries")
    names = tuple(value.name for value in scope_values)
    if len(set(names)) != len(names):
        raise ValueError("request scope values must have unique names")


def _require_config(config: object) -> LoadedContractConfig:
    if not isinstance(config, LoadedContractConfig):
        raise TypeError("application config must be LoadedContractConfig")
    return config


def _require_nonblank(value: object, context: str) -> str:
    if type(value) is not str or value.strip() == "":
        raise ValueError(f"{context} must be nonblank text")
    return value


def _require_positive_integer(value: object, context: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{context} must be a positive exact integer")
    return value


def _require_sha256(value: object, context: str) -> str:
    text = _require_nonblank(value, context)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{context} must be a lowercase SHA-256 hexadecimal digest")
    return text
