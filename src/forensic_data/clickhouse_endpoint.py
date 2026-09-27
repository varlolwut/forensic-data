import sys
import time
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from threading import Lock
from typing import cast, final
from uuid import UUID

from forensic_data.acquisition import EarlyExecutionOutcome, RelationManifestEvidence
from forensic_data.canonical import (
    CanonicalizationError,
    CanonicalSchema,
    Fingerprint,
    FingerprintOverflowError,
    decode_key_with_context,
    decode_row_with_context,
    prepare_envelope_context,
)
from forensic_data.canonical.model import INT64_MAX
from forensic_data.clickhouse import (
    ClickHouseConnectionSettings,
    ClickHouseDataValidationError,
    ClickHouseResourceSetting,
    ClickHouseResultLimitError,
    ClickHouseRetryPolicy,
    ClickHouseServerProfile,
    ClickHouseTransport,
    ClickHouseTransportCleanupError,
    ClickHouseTransportError,
    ClickHouseTransportLimits,
    inspect_clickhouse_server_profile,
    open_budgeted_clickhouse_transport,
    require_clickhouse_resource_setting_value,
)
from forensic_data.clickhouse_canonical import (
    ClickHouseCanonicalLimits,
    ClickHouseCanonicalRelation,
)
from forensic_data.clickhouse_endpoint_sql import (
    ClickHouseEndpointQuery,
    build_clickhouse_integer_key_summary_query,
    build_clickhouse_integer_range_fingerprint_query,
    build_clickhouse_integer_range_rows_query,
)
from forensic_data.clickhouse_projection import (
    ClickHouseMergeTreeProjectionBinding,
    ClickHouseMergeTreeProjectionConfirmation,
    ClickHouseProjectionRequest,
    acquire_clickhouse_merge_tree_projection,
    confirm_clickhouse_merge_tree_projection,
    effective_clickhouse_projection_request,
)
from forensic_data.clickhouse_readiness import (
    ClickHouseImmutableVersionManifest,
    ClickHouseImmutableVersionRequest,
    ClickHouseRelationManifestRecord,
    ClickHouseTableIdentity,
)
from forensic_data.contracts.model import RelationScope
from forensic_data.postgres import (
    PostgresDataValidationError,
    PostgresIntegerExactRow,
    PostgresIntegerExactRowsRead,
    PostgresIntegerKeySummary,
    PostgresIntegerKeySummaryRead,
    PostgresRangeFingerprint,
    PostgresRangeFingerprintRead,
    PostgresReadDeadline,
    PostgresReadDeadlineExceededError,
    PostgresReadMetrics,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetExceededError,
    PostgresSourceDirection,
)
from forensic_data.postgres_sql import PostgresIntegerRangeRequest, PostgresScopePredicate
from forensic_data.result import ConsistencyLevel


class ClickHouseProtectedContextClosedError(ClickHouseTransportError):
    """A read was attempted after the protected ClickHouse context was closed."""


class ClickHouseProtectedContextLostError(ClickHouseTransportError):
    """The protected ClickHouse immutable-version evidence is no longer reusable."""


class ClickHouseProtectedContextConfirmationError(ClickHouseProtectedContextLostError):
    """Final same-attempt immutable projection confirmation did not succeed."""

    def __init__(self, outcome: EarlyExecutionOutcome) -> None:
        if not isinstance(cast(object, outcome), EarlyExecutionOutcome):
            raise TypeError("ClickHouse confirmation outcome must be EarlyExecutionOutcome")
        self.outcome = outcome
        super().__init__(
            "ClickHouse protected context final confirmation failed: "
            f"execution_status={outcome.execution_status.value!r}, "
            f"reason_code={outcome.reason.code.value!r}, "
            f"operation={outcome.reason.operation!r}"
        )


class ClickHouseProtectedContextCleanupError(ClickHouseTransportError):
    """A protected-context failure also left worker cleanup unconfirmed."""

    def __init__(
        self,
        primary_error: BaseException | None,
        cleanup_error: BaseException,
    ) -> None:
        self.primary_error_type = None if primary_error is None else type(primary_error).__name__
        self.cleanup_error_type = type(cleanup_error).__name__
        super().__init__(
            "ClickHouse protected context failed and worker cleanup was not confirmed: "
            f"primary_error_type={self.primary_error_type!r}, "
            f"cleanup_error_type={self.cleanup_error_type!r}"
        )


class ClickHouseProtectedContextState(StrEnum):
    ACTIVE = "active"
    LOST = "lost"
    CLOSED = "closed"


@final
@dataclass(frozen=True, slots=True)
class ClickHouseRelation:
    components: tuple[str, str]

    def __post_init__(self) -> None:
        if type(self.components) is not tuple or len(self.components) != 2:
            raise ValueError("ClickHouse relation must contain database and table components")
        for index, component in enumerate(self.components):
            if type(component) is not str or not component or "\x00" in component:
                raise ValueError(
                    "ClickHouse relation component must be non-empty text without U+0000: "
                    f"index={index}"
                )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseRelationAcquisition:
    schema: CanonicalSchema
    relation: ClickHouseRelation
    relation_scope: RelationScope
    column_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.schema) is not CanonicalSchema:
            raise TypeError("ClickHouse acquisition schema must be CanonicalSchema")
        if type(self.relation) is not ClickHouseRelation:
            raise TypeError("ClickHouse acquisition relation must be ClickHouseRelation")
        if self.relation_scope is not RelationScope.PHYSICAL_ONLY:
            raise ValueError("ClickHouse protected endpoint supports physical_only acquisition")
        if type(self.column_names) is not tuple:
            raise TypeError("ClickHouse acquisition columns must be an immutable tuple")
        if len(self.column_names) != len(self.schema.fields):
            raise ValueError(
                "ClickHouse acquisition requires one physical column per canonical field"
            )
        if len(set(self.column_names)) != len(self.column_names):
            raise ValueError("ClickHouse acquisition column names must be unique")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseProtectedRelationInspection:
    context_id: UUID
    acquisition: ClickHouseRelationAcquisition
    canonical_relation: ClickHouseCanonicalRelation
    version_identity: ClickHouseTableIdentity
    projection_binding: ClickHouseMergeTreeProjectionBinding

    def __post_init__(self) -> None:
        if type(self.context_id) is not UUID or self.context_id.int == 0:
            raise ValueError("ClickHouse protected relation requires a non-zero context ID")
        if type(self.acquisition) is not ClickHouseRelationAcquisition:
            raise TypeError("ClickHouse protected relation acquisition has an invalid type")
        if type(self.canonical_relation) is not ClickHouseCanonicalRelation:
            raise TypeError("ClickHouse protected relation requires a canonical relation")
        if type(self.version_identity) is not ClickHouseTableIdentity:
            raise TypeError("ClickHouse protected relation requires a table identity")
        if type(self.projection_binding) is not ClickHouseMergeTreeProjectionBinding:
            raise TypeError("ClickHouse protected relation requires a projection binding")
        immutable = self.projection_binding.immutable_binding
        if self.context_id != immutable.context_id:
            raise ValueError("ClickHouse protected relation belongs to another context")
        if self.version_identity != immutable.version_identity:
            raise ValueError("ClickHouse protected relation has a different version identity")
        if self.canonical_relation != self.projection_binding.relation:
            raise ValueError("ClickHouse protected relation differs from its projection binding")
        if self.acquisition.schema != self.canonical_relation.schema:
            raise ValueError("ClickHouse protected relation schema closure is inconsistent")
        if self.acquisition.column_names != tuple(
            binding.column_name for binding in self.canonical_relation.bindings
        ):
            raise ValueError("ClickHouse protected relation column closure is inconsistent")
        if self.acquisition.relation.components != (
            self.version_identity.database,
            self.version_identity.table,
        ):
            raise ValueError("ClickHouse protected relation locator differs from its identity")

    def physical_scan_count(self) -> int:
        return 1


@final
@dataclass(frozen=True, slots=True)
class ClickHouseProtectedReadinessInspection:
    context_id: UUID
    identity: ClickHouseTableIdentity
    record: ClickHouseRelationManifestRecord
    evidence: RelationManifestEvidence
    request: ClickHouseImmutableVersionRequest

    def __post_init__(self) -> None:
        if type(self.context_id) is not UUID or self.context_id.int == 0:
            raise ValueError("ClickHouse protected readiness requires a non-zero context ID")
        if type(self.identity) is not ClickHouseTableIdentity:
            raise TypeError("ClickHouse protected readiness requires a table identity")
        if type(self.record) is not ClickHouseRelationManifestRecord:
            raise TypeError("ClickHouse protected readiness requires a manifest record")
        if type(self.evidence) is not RelationManifestEvidence:
            raise TypeError("ClickHouse protected readiness requires manifest evidence")
        if type(self.request) is not ClickHouseImmutableVersionRequest:
            raise TypeError("ClickHouse protected readiness requires an immutable request")
        if (
            self.identity.database != self.request.readiness_database
            or self.identity.table != self.request.readiness_table
        ):
            raise ValueError("ClickHouse protected readiness locator differs from its request")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseProtectedReadContextEvidence:
    context_id: UUID
    attempt_id: UUID
    engine: str
    server_version: str
    server_version_number: int
    strategy: str
    snapshot_locator: str
    started_at: datetime
    allowed_concurrency: int
    consistency_level: ConsistencyLevel
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.context_id) is not UUID or self.context_id.int == 0:
            raise ValueError("ClickHouse context evidence requires a non-zero context ID")
        if type(self.attempt_id) is not UUID or self.attempt_id.int == 0:
            raise ValueError("ClickHouse context evidence requires a non-zero attempt ID")
        for label, value in (
            ("engine", self.engine),
            ("server version", self.server_version),
            ("strategy", self.strategy),
            ("snapshot locator", self.snapshot_locator),
        ):
            if type(value) is not str or not value or "\x00" in value:
                raise ValueError(f"ClickHouse context {label} must be non-empty text")
        if type(self.server_version_number) is not int or self.server_version_number < 1:
            raise ValueError("ClickHouse context server version number must be positive")
        if type(self.started_at) is not datetime or self.started_at.utcoffset() is None:
            raise ValueError("ClickHouse context started_at must be timezone-aware")
        if self.allowed_concurrency != 1:
            raise ValueError("ClickHouse protected context allows exactly one owner")
        if self.consistency_level is not ConsistencyLevel.ASSERTED:
            raise ValueError("ClickHouse immutable named-version consistency must remain asserted")
        if type(self.limitations) is not tuple or not self.limitations:
            raise ValueError("ClickHouse context limitations must be a non-empty tuple")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseFinalConfirmationEvidence:
    context_id: UUID
    attempt_id: UUID
    connection_attempts: int
    physical_request_count: int
    final_query_id: UUID
    confirmation: ClickHouseMergeTreeProjectionConfirmation

    def __post_init__(self) -> None:
        if type(self.context_id) is not UUID or self.context_id.int == 0:
            raise ValueError("ClickHouse final confirmation requires a non-zero context ID")
        if type(self.attempt_id) is not UUID or self.attempt_id.int == 0:
            raise ValueError("ClickHouse final confirmation requires a non-zero attempt ID")
        if type(self.connection_attempts) is not int or self.connection_attempts < 1:
            raise ValueError("ClickHouse final confirmation connection attempts must be positive")
        if type(self.physical_request_count) is not int or self.physical_request_count < 1:
            raise ValueError(
                "ClickHouse final confirmation physical request count must be positive"
            )
        if type(self.final_query_id) is not UUID or self.final_query_id.int == 0:
            raise ValueError("ClickHouse final confirmation requires a non-zero final query ID")
        if type(self.confirmation) is not ClickHouseMergeTreeProjectionConfirmation:
            raise TypeError(
                "ClickHouse final confirmation evidence requires the exact confirmation type"
            )
        immutable = self.confirmation.binding.immutable_binding
        if self.context_id != immutable.context_id or self.attempt_id != immutable.attempt_id:
            raise ValueError(
                "ClickHouse final confirmation evidence differs from its immutable binding"
            )


_CLICKHOUSE_ENDPOINT_RUNTIME_ERRORS = (
    ClickHouseTransportError,
    PostgresDataValidationError,
    PostgresReadDeadlineExceededError,
    PostgresSourceBudgetExceededError,
)


class ClickHouseProtectedReadContext:
    """One single-owner, immutable named-version ClickHouse target context."""

    def __init__(
        self,
        transport: ClickHouseTransport,
        profile: ClickHouseServerProfile,
        projection_binding: ClickHouseMergeTreeProjectionBinding,
        protected_relation: ClickHouseProtectedRelationInspection,
        protected_readiness: ClickHouseProtectedReadinessInspection,
        evidence: ClickHouseProtectedReadContextEvidence,
        source_budget: PostgresSourceBudgetAttempt,
        source_direction: PostgresSourceDirection,
    ) -> None:
        self._transport = transport
        self._profile = profile
        self._projection_binding = projection_binding
        self._protected_relations = (protected_relation,)
        self._protected_readiness = protected_readiness
        self._evidence = evidence
        self._source_budget = source_budget
        self._source_direction = source_direction
        self._confirmation: ClickHouseMergeTreeProjectionConfirmation | None = None
        self._confirmation_evidence: ClickHouseFinalConfirmationEvidence | None = None
        self._state = ClickHouseProtectedContextState.ACTIVE
        self._query_lock = Lock()
        _validate_context_closure(self)

    @property
    def profile(self) -> ClickHouseServerProfile:
        return self._profile

    @property
    def projection_binding(self) -> ClickHouseMergeTreeProjectionBinding:
        return self._projection_binding

    @property
    def protected_relations(self) -> tuple[ClickHouseProtectedRelationInspection, ...]:
        return self._protected_relations

    @property
    def protected_readiness(self) -> ClickHouseProtectedReadinessInspection:
        return self._protected_readiness

    @property
    def evidence(self) -> ClickHouseProtectedReadContextEvidence:
        return self._evidence

    @property
    def state(self) -> ClickHouseProtectedContextState:
        return self._state

    @property
    def source_budget(self) -> PostgresSourceBudgetAttempt:
        return self._source_budget

    @property
    def source_direction(self) -> PostgresSourceDirection:
        return self._source_direction

    @property
    def confirmation(self) -> ClickHouseMergeTreeProjectionConfirmation | None:
        return self._confirmation

    @property
    def confirmation_evidence(self) -> ClickHouseFinalConfirmationEvidence | None:
        return self._confirmation_evidence

    def read_integer_key_summary(
        self,
        protected_relation: ClickHouseProtectedRelationInspection,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        max_encoded_envelope_bytes: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresIntegerKeySummaryRead:
        self._require_relation(protected_relation)
        _require_limits(max_record_bytes, max_total_bytes)
        _require_full_scans(full_scans, 1, "integer-key summary")
        limits = _comparison_limits(
            self._projection_binding,
            max_encoded_envelope_bytes,
        )
        key_column = protected_relation.acquisition.column_names[key_field_index]
        usable_access_path = protected_relation.version_identity.sorting_key == key_column
        query = build_clickhouse_integer_key_summary_query(
            protected_relation.canonical_relation,
            key_field_index,
            scope,
            limits,
            usable_access_path,
            max_total_bytes,
            full_scans,
        )
        payload = self._execute_source_query(query, deadline)
        try:
            fields = _single_tsv_record(payload, 8, "integer-key summary")
            _require_record_limits(fields, max_record_bytes, max_total_bytes)
            summary = PostgresIntegerKeySummary(
                row_count=_parse_unsigned(fields[0], "summary row count", INT64_MAX),
                null_key_count=_parse_unsigned(fields[1], "summary null key count", INT64_MAX),
                invalid_key_count=_parse_unsigned(
                    fields[2],
                    "summary invalid key count",
                    INT64_MAX,
                ),
                valid_key_count=_parse_unsigned(fields[3], "summary valid key count", INT64_MAX),
                distinct_key_count=_parse_unsigned(
                    fields[4],
                    "summary distinct key count",
                    INT64_MAX,
                ),
                minimum_key=_parse_optional_int64(fields[5], "summary minimum key"),
                maximum_key=_parse_optional_int64(fields[6], "summary maximum key"),
                usable_access_path=_parse_flag(fields[7], "summary usable access path"),
            )
            return PostgresIntegerKeySummaryRead(
                summary=summary,
                metrics=_metrics((fields,)),
            )
        except _CLICKHOUSE_ENDPOINT_RUNTIME_ERRORS as error:
            self._retire(error)
            raise

    def read_integer_range_fingerprints(
        self,
        protected_relation: ClickHouseProtectedRelationInspection,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresRangeFingerprintRead:
        self._require_relation(protected_relation)
        _require_limits(max_record_bytes, max_total_bytes)
        _require_full_scans(full_scans, 1, "integer-range fingerprint")
        limits = _comparison_limits(
            self._projection_binding,
            max_encoded_envelope_bytes,
        )
        query = build_clickhouse_integer_range_fingerprint_query(
            protected_relation.canonical_relation,
            key_field_index,
            scope,
            ranges,
            limits,
            max_total_bytes,
            full_scans,
        )
        payload = self._execute_source_query(query, deadline)
        try:
            records = _tsv_records(payload, 14, "integer-range fingerprint")
            _require_result_limits(records, max_record_bytes, max_total_bytes)
            parsed = _parse_range_fingerprints(records, ranges, limits, deadline)
            return PostgresRangeFingerprintRead(
                ranges=parsed,
                metrics=_metrics(records),
            )
        except _CLICKHOUSE_ENDPOINT_RUNTIME_ERRORS as error:
            self._retire(error)
            raise

    def read_integer_range_rows(
        self,
        protected_relation: ClickHouseProtectedRelationInspection,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresIntegerExactRowsRead:
        self._require_relation(protected_relation)
        _require_positive_integer(max_records, "exact-row record limit")
        _require_limits(max_record_bytes, max_total_bytes)
        _require_full_scans(full_scans, 1, "integer-range exact read")
        limits = _comparison_limits(
            self._projection_binding,
            max_encoded_envelope_bytes,
        )
        query = build_clickhouse_integer_range_rows_query(
            protected_relation.canonical_relation,
            key_field_index,
            scope,
            ranges,
            limits,
            max_records,
            max_total_bytes,
            full_scans,
        )
        payload = self._execute_source_query(query, deadline)
        try:
            records = _tsv_records(payload, 5, "integer-range exact rows")
            if len(records) > max_records:
                raise ClickHouseResultLimitError(
                    "ClickHouse exact rows exceeded the declared record limit: "
                    f"maximum={max_records}, observed_at_least={len(records)}"
                )
            _require_result_limits(records, max_record_bytes, max_total_bytes)
            rows = _parse_exact_rows(
                records,
                ranges,
                key_field_index,
                protected_relation.acquisition.schema,
                limits,
                deadline,
            )
            return PostgresIntegerExactRowsRead(rows=rows, metrics=_metrics(records))
        except _CLICKHOUSE_ENDPOINT_RUNTIME_ERRORS as error:
            self._retire(error)
            raise

    def close(self) -> None:
        with self._query_lock:
            if self._state is ClickHouseProtectedContextState.CLOSED:
                return
            if self._state is ClickHouseProtectedContextState.LOST:
                self._transport.close()
                return
            try:
                confirmation = confirm_clickhouse_merge_tree_projection(
                    self._transport,
                    self._projection_binding,
                )
                if isinstance(confirmation, EarlyExecutionOutcome):
                    raise ClickHouseProtectedContextConfirmationError(confirmation)
            except (
                ClickHouseTransportError,
                PostgresReadDeadlineExceededError,
                PostgresSourceBudgetExceededError,
            ) as error:
                self._lose(error)
                raise
            final_query_id = self._transport.last_query_id
            if final_query_id is None:
                error = ClickHouseProtectedContextLostError(
                    "ClickHouse final confirmation completed without a final query identity"
                )
                self._lose(error)
                raise error
            self._confirmation = confirmation
            self._confirmation_evidence = ClickHouseFinalConfirmationEvidence(
                context_id=self._evidence.context_id,
                attempt_id=self._evidence.attempt_id,
                connection_attempts=self._transport.connection_attempts,
                physical_request_count=self._transport.physical_request_count,
                final_query_id=final_query_id,
                confirmation=confirmation,
            )
            try:
                self._transport.close()
            except ClickHouseTransportError as error:
                self._state = ClickHouseProtectedContextState.LOST
                raise ClickHouseProtectedContextCleanupError(None, error) from error
            self._state = ClickHouseProtectedContextState.CLOSED

    def _execute_source_query(
        self,
        query: ClickHouseEndpointQuery,
        deadline: PostgresReadDeadline,
    ) -> bytes:
        with self._query_lock:
            self._require_active()
            try:
                _require_profile_admitted_endpoint_query(self._profile, query)
                _require_deadline(deadline, self._source_budget)
                result = self._transport.execute_source_raw(
                    query=query.statement,
                    parameters=query.parameters,
                    settings=query.settings,
                    result_format="TabSeparatedRaw",
                    max_response_bytes=query.max_response_bytes,
                    operation=query.operation,
                    full_scans=query.full_scans,
                )
                _require_deadline(deadline, self._source_budget)
            except _CLICKHOUSE_ENDPOINT_RUNTIME_ERRORS as error:
                self._lose(error)
                raise
        return result.payload

    def _require_relation(
        self,
        protected_relation: ClickHouseProtectedRelationInspection,
    ) -> None:
        self._require_active()
        if not any(item is protected_relation for item in self._protected_relations):
            raise ClickHouseDataValidationError(
                "ClickHouse relation inspection does not belong to the exact protected set"
            )
        if protected_relation.context_id != self._evidence.context_id:
            raise ClickHouseDataValidationError(
                "ClickHouse protected relation belongs to another context"
            )

    def _retire(self, error: BaseException) -> None:
        with self._query_lock:
            self._lose(error)

    def _lose(self, error: BaseException) -> None:
        if self._state is not ClickHouseProtectedContextState.ACTIVE:
            return
        self._state = ClickHouseProtectedContextState.LOST
        try:
            self._transport.close()
        except ClickHouseTransportCleanupError as cleanup_error:
            raise ClickHouseProtectedContextCleanupError(error, cleanup_error) from error

    def _require_active(self) -> None:
        if self._state is ClickHouseProtectedContextState.CLOSED:
            raise ClickHouseProtectedContextClosedError(
                "ClickHouse protected context is already closed"
            )
        if self._state is ClickHouseProtectedContextState.LOST:
            raise ClickHouseProtectedContextLostError(
                "ClickHouse protected context was lost and cannot be reused"
            )


def open_clickhouse_protected_read_context(
    settings: ClickHouseConnectionSettings,
    retry_policy: ClickHouseRetryPolicy,
    transport_limits: ClickHouseTransportLimits,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
    projection_request: ClickHouseProjectionRequest,
    manifest: ClickHouseImmutableVersionManifest,
) -> ClickHouseProtectedReadContext | EarlyExecutionOutcome:
    if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
        raise TypeError("ClickHouse protected context requires PostgresSourceBudgetAttempt")
    if not isinstance(cast(object, direction), PostgresSourceDirection):
        raise TypeError("ClickHouse protected context requires PostgresSourceDirection")
    if type(projection_request) is not ClickHouseProjectionRequest:
        raise TypeError("ClickHouse protected context requires ClickHouseProjectionRequest")
    if type(manifest) is not ClickHouseImmutableVersionManifest:
        raise TypeError("ClickHouse protected context requires an immutable version manifest")
    deadline = source_budget.read_deadline(source_budget.effective_statement_timeout_milliseconds())
    transport = open_budgeted_clickhouse_transport(
        settings,
        retry_policy,
        transport_limits,
        deadline,
        source_budget.attempt_id,
        source_budget,
        direction,
    )
    succeeded = False
    try:
        profile = inspect_clickhouse_server_profile(transport, settings)
        effective_request = effective_clickhouse_projection_request(
            projection_request,
            profile,
        )
        acquired = acquire_clickhouse_merge_tree_projection(
            transport,
            effective_request,
            manifest,
        )
        if isinstance(acquired, EarlyExecutionOutcome):
            transport.close()
            succeeded = True
            return acquired
        context = _protected_context(
            transport,
            profile,
            acquired,
            source_budget,
            direction,
        )
        succeeded = True
        return context
    finally:
        if not succeeded:
            primary_error = sys.exception()
            try:
                transport.close()
            except ClickHouseTransportError as cleanup_error:
                if primary_error is None:
                    raise
                raise ClickHouseProtectedContextCleanupError(
                    primary_error,
                    cleanup_error,
                ) from primary_error


def _protected_context(
    transport: ClickHouseTransport,
    profile: ClickHouseServerProfile,
    binding: ClickHouseMergeTreeProjectionBinding,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> ClickHouseProtectedReadContext:
    immutable = binding.immutable_binding
    acquisition = ClickHouseRelationAcquisition(
        schema=binding.request.schema,
        relation=ClickHouseRelation(
            components=(binding.relation.database, binding.relation.table),
        ),
        relation_scope=RelationScope.PHYSICAL_ONLY,
        column_names=binding.request.column_names,
    )
    relation = ClickHouseProtectedRelationInspection(
        context_id=immutable.context_id,
        acquisition=acquisition,
        canonical_relation=binding.relation,
        version_identity=immutable.version_identity,
        projection_binding=binding,
    )
    readiness = ClickHouseProtectedReadinessInspection(
        context_id=immutable.context_id,
        identity=immutable.readiness_identity,
        record=immutable.readiness_record,
        evidence=immutable.readiness_evidence,
        request=immutable.request,
    )
    evidence = ClickHouseProtectedReadContextEvidence(
        context_id=immutable.context_id,
        attempt_id=immutable.attempt_id,
        engine="ClickHouse",
        server_version=profile.server_version,
        server_version_number=profile.server_version_number,
        strategy=binding.strategy,
        snapshot_locator=str(immutable.version_identity.uuid),
        started_at=binding.opened_at,
        allowed_concurrency=1,
        consistency_level=ConsistencyLevel.ASSERTED,
        limitations=binding.limitations,
    )
    return ClickHouseProtectedReadContext(
        transport,
        profile,
        binding,
        relation,
        readiness,
        evidence,
        source_budget,
        direction,
    )


def _require_profile_admitted_endpoint_query(
    profile: ClickHouseServerProfile,
    query: ClickHouseEndpointQuery,
) -> None:
    setting_names = (
        ("max_execution_time", ClickHouseResourceSetting.MAX_EXECUTION_TIME),
        ("max_result_rows", ClickHouseResourceSetting.MAX_RESULT_ROWS),
        ("max_result_bytes", ClickHouseResourceSetting.MAX_RESULT_BYTES),
        ("max_rows_to_group_by", ClickHouseResourceSetting.MAX_ROWS_TO_GROUP_BY),
    )
    for name, setting in setting_names:
        requested_value = query.settings.get(name)
        if requested_value is None:
            continue
        if type(requested_value) is not int:
            raise ClickHouseDataValidationError(
                "ClickHouse endpoint query resource setting must be an integer: "
                f"operation={query.operation!r}, setting={name!r}, "
                f"value_type={type(requested_value).__name__!r}"
            )
        require_clickhouse_resource_setting_value(
            profile,
            setting,
            requested_value,
            query.operation,
        )


def _validate_context_closure(context: ClickHouseProtectedReadContext) -> None:
    immutable = context.projection_binding.immutable_binding
    relation = context.protected_relations[0]
    readiness = context.protected_readiness
    if context.evidence.context_id != immutable.context_id:
        raise ValueError("ClickHouse context evidence differs from its immutable binding")
    if context.evidence.attempt_id != immutable.attempt_id:
        raise ValueError("ClickHouse context attempt differs from its immutable binding")
    if context.source_budget.attempt_id != immutable.attempt_id:
        raise ValueError("ClickHouse source budget differs from its immutable binding")
    if relation.context_id != immutable.context_id:
        raise ValueError("ClickHouse protected relation context closure is inconsistent")
    if readiness.context_id != immutable.context_id:
        raise ValueError("ClickHouse protected readiness context closure is inconsistent")
    if (
        readiness.identity != immutable.readiness_identity
        or readiness.record != immutable.readiness_record
        or readiness.evidence != immutable.readiness_evidence
        or readiness.request != immutable.request
    ):
        raise ValueError("ClickHouse protected readiness differs from its immutable binding")


def _comparison_limits(
    binding: ClickHouseMergeTreeProjectionBinding,
    max_encoded_envelope_bytes: int,
) -> ClickHouseCanonicalLimits:
    limits = binding.request.canonical_limits
    if max_encoded_envelope_bytes > limits.max_encoded_envelope_bytes:
        raise ClickHouseDataValidationError(
            "ClickHouse comparison envelope limit exceeds the accepted projection: "
            f"accepted={limits.max_encoded_envelope_bytes}, "
            f"requested={max_encoded_envelope_bytes}"
        )
    return ClickHouseCanonicalLimits(
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
        max_response_bytes=limits.max_response_bytes,
        max_execution_time_seconds=limits.max_execution_time_seconds,
    )


def _parse_range_fingerprints(
    records: tuple[tuple[bytes, ...], ...],
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    limits: ClickHouseCanonicalLimits,
    deadline: PostgresReadDeadline,
) -> tuple[PostgresRangeFingerprint, ...]:
    if len(records) != len(ranges):
        raise ClickHouseDataValidationError(
            "ClickHouse range fingerprint query must return one row per range: "
            f"expected={len(ranges)}, actual={len(records)}"
        )
    result: list[PostgresRangeFingerprint] = []
    for index, (record, requested) in enumerate(zip(records, ranges, strict=True)):
        if index % 64 == 0:
            _require_deadline_only(deadline, "range fingerprint decoding")
        segment_id = _ascii_text(record[0], "range fingerprint segment ID")
        if segment_id != requested.segment_id:
            raise ClickHouseDataValidationError(
                "ClickHouse range fingerprints do not preserve requested segment order"
            )
        values = tuple(
            _parse_unsigned(
                value,
                "range fingerprint value",
                INT64_MAX if ordinal in (0, 9, 10) else (1 << 127) - 1,
            )
            for ordinal, value in enumerate(record[1:])
        )
        if values[9] > 0:
            raise ClickHouseDataValidationError(
                "ClickHouse range fingerprint found rows outside the canonical contract: "
                f"segment_id={segment_id!r}, invalid_row_count={values[9]}"
            )
        if values[10] > 0:
            raise ClickHouseResultLimitError(
                "ClickHouse range fingerprint found oversized canonical rows: "
                f"segment_id={segment_id!r}, "
                f"max_encoded_envelope_bytes={limits.max_encoded_envelope_bytes}"
            )
        try:
            fingerprint = Fingerprint(
                count=values[0],
                limb_sums=(
                    values[1],
                    values[2],
                    values[3],
                    values[4],
                    values[5],
                    values[6],
                    values[7],
                    values[8],
                ),
            )
        except FingerprintOverflowError as error:
            raise ClickHouseDataValidationError(
                "ClickHouse range fingerprint exceeds canonical accumulator bounds: "
                f"segment_id={segment_id!r}"
            ) from error
        result.append(
            PostgresRangeFingerprint(
                segment_id=segment_id,
                fingerprint=fingerprint,
                row_envelope_bytes=values[11],
                key_envelope_bytes=values[12],
            )
        )
    _require_deadline_only(deadline, "range fingerprint decoding")
    return tuple(result)


def _parse_exact_rows(
    records: tuple[tuple[bytes, ...], ...],
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    key_field_index: int,
    schema: CanonicalSchema,
    limits: ClickHouseCanonicalLimits,
    deadline: PostgresReadDeadline,
) -> tuple[PostgresIntegerExactRow, ...]:
    context = prepare_envelope_context(schema)
    if type(key_field_index) is not int or not 0 <= key_field_index < len(schema.fields):
        raise ClickHouseDataValidationError("ClickHouse exact-row key index is invalid")
    key_context = prepare_envelope_context(
        CanonicalSchema(protocol=schema.protocol, fields=(schema.fields[key_field_index],))
    )
    ordinals = {item.segment_id: index for index, item in enumerate(ranges)}
    result: list[PostgresIntegerExactRow] = []
    previous_ordinal = -1
    previous_key: int | None = None
    for index, record in enumerate(records):
        if index % 64 == 0:
            _require_deadline_only(deadline, "exact-row decoding")
        segment_id = _ascii_text(record[0], "exact-row segment ID")
        ordinal = ordinals.get(segment_id)
        if ordinal is None:
            raise ClickHouseDataValidationError(
                "ClickHouse exact row returned an unrequested segment ID"
            )
        invalid = _parse_flag(record[3], "exact-row invalid status")
        oversized = _parse_flag(record[4], "exact-row oversized status")
        if invalid and oversized:
            raise ClickHouseDataValidationError(
                "ClickHouse exact-row statuses must be mutually exclusive"
            )
        if invalid:
            raise ClickHouseDataValidationError(
                "ClickHouse exact read found a row outside the canonical contract"
            )
        if oversized:
            raise ClickHouseResultLimitError(
                "ClickHouse exact read found an oversized canonical row: "
                f"max_encoded_envelope_bytes={limits.max_encoded_envelope_bytes}"
            )
        key_envelope = _ascii_bytes(record[1], "exact key envelope")
        row_envelope = _ascii_bytes(record[2], "exact row envelope")
        if len(row_envelope) > limits.max_encoded_envelope_bytes:
            raise ClickHouseResultLimitError(
                "ClickHouse exact row exceeds the canonical envelope limit: "
                f"observed_bytes={len(row_envelope)}, "
                f"maximum={limits.max_encoded_envelope_bytes}"
            )
        try:
            key_values = decode_key_with_context(key_context, key_envelope)
            row_values = decode_row_with_context(context, row_envelope)
        except CanonicalizationError as error:
            raise ClickHouseDataValidationError(
                "ClickHouse exact row failed canonical reference decoding: "
                f"reason_type={type(error).__name__}"
            ) from error
        key_value = key_values[0]
        row_key_value = row_values[key_field_index]
        if type(key_value) is not int or type(row_key_value) is not int:
            raise ClickHouseDataValidationError(
                "ClickHouse exact comparison key is not logical INT64"
            )
        if key_value != row_key_value:
            raise ClickHouseDataValidationError("ClickHouse exact key and row envelopes disagree")
        requested = ranges[ordinal]
        if key_value < requested.lower_inclusive or (
            requested.upper_exclusive is not None and key_value >= requested.upper_exclusive
        ):
            raise ClickHouseDataValidationError(
                "ClickHouse exact key falls outside its requested segment"
            )
        if ordinal < previous_ordinal or (
            ordinal == previous_ordinal and previous_key is not None and key_value <= previous_key
        ):
            raise ClickHouseDataValidationError(
                "ClickHouse exact rows are not strictly ordered by segment and key"
            )
        previous_ordinal = ordinal
        previous_key = key_value
        result.append(
            PostgresIntegerExactRow(
                segment_id=segment_id,
                key_value=key_value,
                key_envelope=key_envelope,
                row_envelope=row_envelope,
                values=row_values,
            )
        )
    _require_deadline_only(deadline, "exact-row decoding")
    return tuple(result)


def _single_tsv_record(
    payload: bytes,
    field_count: int,
    operation: str,
) -> tuple[bytes, ...]:
    records = _tsv_records(payload, field_count, operation)
    if len(records) != 1:
        raise ClickHouseDataValidationError(
            f"ClickHouse {operation} must return exactly one record: actual={len(records)}"
        )
    return records[0]


def _tsv_records(
    payload: bytes,
    field_count: int,
    operation: str,
) -> tuple[tuple[bytes, ...], ...]:
    if type(payload) is not bytes:
        raise TypeError("ClickHouse TSV payload must be bytes")
    records: list[tuple[bytes, ...]] = []
    for ordinal, line in enumerate(payload.splitlines(), start=1):
        fields = tuple(line.split(b"\t"))
        if len(fields) != field_count:
            raise ClickHouseDataValidationError(
                f"ClickHouse {operation} returned an invalid TSV shape: "
                f"record={ordinal}, expected_fields={field_count}, actual_fields={len(fields)}"
            )
        records.append(fields)
    return tuple(records)


def _require_result_limits(
    records: tuple[tuple[bytes, ...], ...],
    max_record_bytes: int,
    max_total_bytes: int,
) -> None:
    total = 0
    for record in records:
        record_bytes = sum(len(field) for field in record)
        if record_bytes > max_record_bytes:
            raise ClickHouseResultLimitError(
                "ClickHouse comparison record exceeded its logical byte limit: "
                f"observed={record_bytes}, maximum={max_record_bytes}"
            )
        total += record_bytes
        if total > max_total_bytes:
            raise ClickHouseResultLimitError(
                "ClickHouse comparison result exceeded its logical total byte limit: "
                f"observed_at_least={total}, maximum={max_total_bytes}"
            )


def _require_record_limits(
    record: tuple[bytes, ...],
    max_record_bytes: int,
    max_total_bytes: int,
) -> None:
    _require_result_limits((record,), max_record_bytes, max_total_bytes)


def _metrics(records: tuple[tuple[bytes, ...], ...]) -> PostgresReadMetrics:
    return PostgresReadMetrics(
        fetched_records=len(records),
        result_bytes=sum(sum(len(field) for field in record) for record in records),
    )


def _parse_unsigned(value: bytes, label: str, maximum: int) -> int:
    text = _ascii_text(value, label)
    if not text.isdecimal() or (len(text) > 1 and text.startswith("0")):
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be canonical unsigned text")
    parsed = int(text)
    if parsed > maximum:
        raise ClickHouseDataValidationError(f"ClickHouse {label} exceeds its numeric bound")
    return parsed


def _parse_optional_int64(value: bytes, label: str) -> int | None:
    if not value:
        return None
    text = _ascii_text(value, label)
    digits = text[1:] if text.startswith("-") else text
    if not digits.isdecimal() or (len(digits) > 1 and digits.startswith("0")):
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be canonical signed text")
    parsed = int(text)
    if not -(1 << 63) <= parsed <= INT64_MAX:
        raise ClickHouseDataValidationError(f"ClickHouse {label} exceeds signed int64")
    return parsed


def _parse_flag(value: bytes, label: str) -> bool:
    if value == b"0":
        return False
    if value == b"1":
        return True
    raise ClickHouseDataValidationError(f"ClickHouse {label} must be exactly 0 or 1")


def _ascii_text(value: bytes, label: str) -> str:
    try:
        text = value.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be ASCII") from None
    if "\x00" in text:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must not contain U+0000")
    return text


def _ascii_bytes(value: bytes, label: str) -> bytes:
    _ascii_text(value, label)
    return value


def _require_limits(max_record_bytes: int, max_total_bytes: int) -> None:
    _require_positive_integer(max_record_bytes, "record byte limit")
    _require_positive_integer(max_total_bytes, "total byte limit")
    if max_record_bytes > max_total_bytes:
        raise ValueError("ClickHouse record byte limit must not exceed its total byte limit")


def _require_positive_integer(value: int, label: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"ClickHouse {label} must be a positive integer")


def _require_full_scans(reserved: int, expected: int, operation: str) -> None:
    if type(reserved) is not int or reserved < 0:
        raise ValueError("ClickHouse full-scan reservation must be a non-negative integer")
    if reserved != expected:
        raise ValueError(
            "ClickHouse full-scan reservation differs from the endpoint contract: "
            f"operation={operation!r}, reserved={reserved}, expected={expected}"
        )


def _require_deadline(
    deadline: PostgresReadDeadline,
    source_budget: PostgresSourceBudgetAttempt,
) -> None:
    if not isinstance(cast(object, deadline), PostgresReadDeadline):
        raise TypeError("ClickHouse comparison deadline must be PostgresReadDeadline")
    if deadline.deadline_nanoseconds != source_budget.remaining().deadline_nanoseconds:
        raise ValueError("ClickHouse comparison deadline belongs to another source budget")
    _require_deadline_only(deadline, "comparison read")


def _require_deadline_only(deadline: PostgresReadDeadline, operation: str) -> None:
    if time.monotonic_ns() >= deadline.deadline_nanoseconds:
        raise PostgresReadDeadlineExceededError(
            f"ClickHouse {operation} exceeded the immutable source deadline"
        )
