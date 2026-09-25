import logging
import re
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime
from importlib.metadata import version
from threading import Lock
from types import TracebackType
from typing import LiteralString, Self, cast, final
from uuid import UUID, uuid4

import psycopg
from psycopg import pq
from psycopg.rows import tuple_row

from forensic_data.canonical import (
    CanonicalizationError,
    CanonicalSchema,
    Fingerprint,
    FingerprintOverflowError,
    decode_row_with_context,
    encode_key_with_context,
)
from forensic_data.canonical.model import DECIMAL_38_MAX, INT64_MAX
from forensic_data.canonical.schema import prepare_envelope_context
from forensic_data.contracts.model import ReadinessManifestColumns, RelationScope
from forensic_data.greengage_endpoint_sql import (
    GreengageEndpointParameter,
    GreengageEndpointQuery,
    GreengageRangeFingerprintQuery,
    build_greengage_integer_key_summary_query,
    build_greengage_integer_range_fingerprint_query,
    build_greengage_integer_range_rows_query,
    explain_greengage_endpoint_query,
    validate_greengage_range_fingerprint_plan,
)
from forensic_data.greenplum import (
    GREENGAGE_CANONICAL_PLANNING_SETTINGS_QUERY,
    GREENGAGE_PROFILE_QUERY,
    GreenplumCloseError,
    GreenplumConnectionError,
    GreenplumConnectorError,
    GreenplumContextClosedError,
    GreenplumContextLostError,
    GreenplumDataValidationError,
    GreenplumDriverEvidence,
    GreenplumMetadataError,
    GreenplumQueryError,
    GreenplumRelationLockEvidence,
    GreenplumServerProfile,
    GreenplumSessionSettingEvidence,
    UnsupportedGreenplumProfileError,
)
from forensic_data.greenplum_catalog import (
    GREENGAGE_HASH_CAPABILITY_QUERY,
    GREENGAGE_RELATION_QUERY,
    READER_IDENTITY_QUERY,
    TOPOLOGY_QUERY,
    GreengageHashCapability,
    GreengageRelationCatalog,
    GreenplumCatalogDataError,
    GreenplumCatalogMetadataError,
    GreenplumColumnProbe,
    GreenplumReaderIdentity,
    GreenplumRelationRequest,
    GreenplumTopology,
    GreenplumTypeProbe,
    greenplum_type_catalog_query,
    parse_greengage_hash_capability,
    parse_greengage_relation_catalog,
    parse_greenplum_reader_identity,
    parse_greenplum_topology,
    parse_greenplum_type_probe,
)
from forensic_data.greenplum_profile import GreenplumRuntimeProfile
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresDataValidationError,
    PostgresInspectedRelation,
    PostgresIntegerExactRow,
    PostgresIntegerExactRowsRead,
    PostgresIntegerKeySummary,
    PostgresIntegerKeySummaryRead,
    PostgresRangeFingerprint,
    PostgresRangeFingerprintRead,
    PostgresReadDeadline,
    PostgresReadDeadlineExceededError,
    PostgresReadMetrics,
    PostgresRelationManifestRecord,
    PostgresRetryPolicy,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetExceededError,
    PostgresSourceDirection,
    ReadContextState,
)
from forensic_data.postgres_sql import (
    PostgresIntegerRangeRequest,
    PostgresLoweringError,
    PostgresRelation,
    PostgresScopePredicate,
    validate_postgres_inspection,
)

LOGGER = logging.getLogger(__name__)
INT64_MIN = -(1 << 63)
_PSYCOPG_VERSION = version("psycopg")
_MAX_TOPOLOGY_ROWS = 2_048
_MAX_EXPLAIN_ROWS = 1_024
_MAX_EXPLAIN_TOTAL_BYTES = 256 * 1_024
_MAX_EXPLAIN_RECORD_BYTES = _MAX_EXPLAIN_TOTAL_BYTES
_EXPLAIN_PARSER_MEMORY_MULTIPLIER = 16
_EXPLAIN_ROW_MEMORY_BYTES = 512
_SESSION_INVARIANT_RECORD_BYTES = 128
# Covers raw text, joined/lower/masked copies, the mutable mask buffer, expression
# slices, and bounded row containers without relying on per-character interning.
_MAX_EXPLAIN_COORDINATOR_BYTES = (
    (_EXPLAIN_PARSER_MEMORY_MULTIPLIER * _MAX_EXPLAIN_TOTAL_BYTES)
    + (_EXPLAIN_ROW_MEMORY_BYTES * _MAX_EXPLAIN_ROWS)
    + _EXPLAIN_ROW_MEMORY_BYTES
    + _SESSION_INVARIANT_RECORD_BYTES
)
_CURSOR_FETCH_RECORDS = 64
_RAW_RESULT_OVERHEAD_BYTES = 32_768
_MAX_ROW_TYPE_OID_BYTES = 10
_HAS_DATA_BYTES = 1
_EXACT_STATUS_BYTES = 2
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MANIFEST_FIELDS = (
    "dataset_id",
    "scope_digest",
    "batch_id",
    "state",
    "business_date",
    "source_cut",
    "dataset_version",
    "completed_at",
)


class GreengageAcquisitionRaceError(GreenplumMetadataError):
    """A relation changed between discovery and protected snapshot acquisition."""


class GreengageBudgetExceededError(GreenplumConnectorError):
    """A bounded Greengage read exceeded its immutable result budget."""


class GreengageResultLimitError(GreengageBudgetExceededError):
    """A Greengage query result exceeded a declared record or byte limit."""


_GREENGAGE_RUNTIME_FAILURES = (
    GreenplumConnectionError,
    GreenplumQueryError,
    GreenplumContextLostError,
    GreenplumDataValidationError,
    GreenplumMetadataError,
    UnsupportedGreenplumProfileError,
    GreengageBudgetExceededError,
    PostgresDataValidationError,
    PostgresReadDeadlineExceededError,
    PostgresSourceBudgetExceededError,
)


@final
@dataclass(frozen=True, slots=True)
class GreengageRelation:
    components: tuple[str, str]

    def __post_init__(self) -> None:
        if type(self.components) is not tuple or len(self.components) != 2:
            raise ValueError("Greengage relation must contain schema and relation components")
        for index, component in enumerate(self.components):
            if type(component) is not str or not component or "\x00" in component:
                raise ValueError(
                    "Greengage relation component must be non-empty text without U+0000: "
                    f"index={index}"
                )


@final
@dataclass(frozen=True, slots=True)
class GreengageRelationAcquisition:
    schema: CanonicalSchema
    relation: GreengageRelation
    relation_scope: RelationScope
    column_names: tuple[str, ...]
    max_metadata_record_bytes: int
    max_metadata_total_bytes: int

    def __post_init__(self) -> None:
        if type(self.schema) is not CanonicalSchema:
            raise TypeError("Greengage acquisition schema must be a CanonicalSchema")
        if type(self.relation) is not GreengageRelation:
            raise TypeError("Greengage acquisition relation must be a GreengageRelation")
        if self.relation_scope is not RelationScope.PHYSICAL_ONLY:
            raise ValueError("Greengage endpoint supports physical_only acquisition")
        if type(self.column_names) is not tuple:
            raise TypeError("Greengage acquisition column names must be an immutable tuple")
        if len(self.column_names) != len(self.schema.fields):
            raise ValueError(
                "Greengage acquisition requires one physical column per canonical field"
            )
        if len(set(self.column_names)) != len(self.column_names):
            raise ValueError("Greengage acquisition column names must be unique")
        for index, column_name in enumerate(self.column_names):
            if type(column_name) is not str or not column_name or "\x00" in column_name:
                raise ValueError(
                    f"Greengage column name must be non-empty text without U+0000: index={index}"
                )
        _validate_result_limits(
            len(self.column_names) or 1,
            self.max_metadata_record_bytes,
            self.max_metadata_total_bytes,
        )


@final
@dataclass(frozen=True, slots=True)
class GreengageProtectedRelationInspection:
    acquisition: GreengageRelationAcquisition
    inspection: PostgresInspectedRelation
    catalog: GreengageRelationCatalog
    lock_mode: str
    acquired_before_snapshot: bool

    def __post_init__(self) -> None:
        if type(self.acquisition) is not GreengageRelationAcquisition:
            raise TypeError("Greengage protected acquisition has an unexpected type")
        if not isinstance(cast(object, self.inspection), PostgresInspectedRelation):
            raise TypeError("Greengage protected inspection has an unexpected type")
        if not isinstance(cast(object, self.catalog), GreengageRelationCatalog):
            raise TypeError("Greengage protected catalog evidence has an unexpected type")
        if self.inspection.relation.components != self.acquisition.relation.components:
            raise ValueError("Greengage protected relation differs from its acquisition")
        if self.inspection.relation_oid != self.catalog.relation_oid:
            raise ValueError("Greengage protected relation OID evidence is inconsistent")
        if self.inspection.relation_row_type_oid != self.catalog.relation_row_type_oid:
            raise ValueError("Greengage protected row type OID evidence is inconsistent")
        if self.lock_mode != "access_share":
            raise ValueError("Greengage protected relation lock mode must be access_share")
        if self.acquired_before_snapshot is not True:
            raise ValueError("Greengage protected relation must be locked before the snapshot")
        validate_postgres_inspection(self.acquisition.schema, self.inspection)

    def physical_scan_count(self) -> int:
        return 1


@final
@dataclass(frozen=True, slots=True)
class GreengageProtectedReadContextEvidence:
    context_id: UUID
    runtime_profile: GreenplumRuntimeProfile
    strategy: str
    snapshot_locator: str
    started_at: datetime
    backend_process_id: int
    allowed_concurrency: int
    planning_settings: tuple[GreenplumSessionSettingEvidence, ...]
    relation_locks: tuple[GreenplumRelationLockEvidence, ...]
    acquired_before_snapshot: bool
    limitations: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class GreengageFingerprintPlanReservation:
    additional_queries: int
    max_fetched_records: int
    max_result_bytes: int
    max_coordinator_bytes: int


@final
@dataclass(frozen=True, slots=True)
class GreengageFingerprintResultReservation:
    additional_record_bytes: int
    additional_result_bytes: int
    additional_fields_per_record: int
    additional_ascii_values: int


@dataclass(frozen=True, slots=True)
class _GreengageCandidate:
    acquisition: GreengageRelationAcquisition
    request: GreenplumRelationRequest
    relation: GreengageRelationCatalog
    types: GreenplumTypeProbe


class _GreengageEndpointSession:
    def __init__(
        self,
        connection: psycopg.Connection[DatabaseRow],
        source_budget: PostgresSourceBudgetAttempt,
        direction: PostgresSourceDirection,
        statement_timeout_milliseconds: int,
    ) -> None:
        if type(statement_timeout_milliseconds) is not int or statement_timeout_milliseconds < 1:
            raise ValueError("Greengage statement timeout must be a positive integer")
        self.connection = connection
        self.source_budget = source_budget
        self.direction = direction
        self.statement_timeout_milliseconds = statement_timeout_milliseconds
        self.closed = False

    def prepare_acquisition_statement(self) -> None:
        timeout_milliseconds = min(
            self.statement_timeout_milliseconds,
            self.source_budget.effective_statement_timeout_milliseconds(),
        )
        self.command(
            f"SET statement_timeout TO {timeout_milliseconds}",
            (),
            "greengage_configure_acquisition_statement_timeout",
        )

    def command(
        self,
        statement: str,
        parameters: tuple[GreengageEndpointParameter, ...],
        operation: str,
    ) -> None:
        charge = self.source_budget.dispatch_query(self.direction, 0)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(cast(LiteralString, statement), parameters)
                if cursor.description is not None:
                    rows = tuple(cursor.fetchall())
                    charge.consume_records(tuple(_database_row_bytes(row) for row in rows))
        except psycopg.Error as error:
            raise GreenplumQueryError(
                operation,
                error.sqlstate,
                type(error).__name__,
            ) from None

    def fetch_rows(
        self,
        statement: str,
        parameters: tuple[GreengageEndpointParameter, ...],
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        full_scans: int,
        operation: str,
    ) -> tuple[DatabaseRow, ...]:
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        charge = self.source_budget.dispatch_query(self.direction, full_scans)
        records: list[DatabaseRow] = []
        total_bytes = 0
        cursor_name = f"dfe_gg_{uuid4().hex}"
        try:
            with self.connection.cursor(name=cursor_name) as cursor:
                cursor.execute(cast(LiteralString, statement), parameters)
                while True:
                    charge.require_fetch_deadline()
                    remaining = max_records + 1 - len(records)
                    batch = tuple(cursor.fetchmany(min(_CURSOR_FETCH_RECORDS, remaining)))
                    if not batch:
                        break
                    batch_bytes = tuple(_database_row_bytes(row) for row in batch)
                    charge.consume_records(batch_bytes)
                    observed_records = len(records) + len(batch)
                    observed_bytes = total_bytes + sum(batch_bytes)
                    if observed_records > max_records:
                        raise GreengageResultLimitError(
                            "Greengage query exceeded its record budget: "
                            f"operation={operation!r}, max_records={max_records}"
                        )
                    oversized = next(
                        (value for value in batch_bytes if value > max_record_bytes),
                        None,
                    )
                    if oversized is not None:
                        raise GreengageResultLimitError(
                            "Greengage query returned a record above its byte budget: "
                            f"operation={operation!r}, record_bytes={oversized}, "
                            f"max_record_bytes={max_record_bytes}"
                        )
                    if observed_bytes > max_total_bytes:
                        raise GreengageResultLimitError(
                            "Greengage query exceeded its total byte budget: "
                            f"operation={operation!r}, observed_bytes={observed_bytes}, "
                            f"max_total_bytes={max_total_bytes}"
                        )
                    records.extend(batch)
                    total_bytes = observed_bytes
        except psycopg.Error as error:
            raise GreenplumQueryError(
                operation,
                error.sqlstate,
                type(error).__name__,
            ) from None
        return tuple(records)

    def fetch_client_rows(
        self,
        statement: str,
        parameters: tuple[GreengageEndpointParameter, ...],
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        full_scans: int,
        operation: str,
    ) -> tuple[DatabaseRow, ...]:
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        charge = self.source_budget.dispatch_query(self.direction, full_scans)
        records: list[DatabaseRow] = []
        total_bytes = 0
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(cast(LiteralString, statement), parameters)
                if cursor.description is None:
                    raise GreenplumDataValidationError(
                        "Greengage bounded metadata query returned no row description: "
                        f"operation={operation!r}"
                    )
                while True:
                    charge.require_fetch_deadline()
                    remaining = max_records + 1 - len(records)
                    batch = tuple(cursor.fetchmany(min(_CURSOR_FETCH_RECORDS, remaining)))
                    if not batch:
                        break
                    batch_bytes = tuple(_database_row_bytes(row) for row in batch)
                    charge.consume_records(batch_bytes)
                    observed_records = len(records) + len(batch)
                    observed_bytes = total_bytes + sum(batch_bytes)
                    if observed_records > max_records:
                        raise GreengageResultLimitError(
                            "Greengage bounded metadata query exceeded its record budget: "
                            f"operation={operation!r}, max_records={max_records}"
                        )
                    oversized = next(
                        (value for value in batch_bytes if value > max_record_bytes),
                        None,
                    )
                    if oversized is not None:
                        raise GreengageResultLimitError(
                            "Greengage bounded metadata query returned a record above its "
                            f"byte budget: operation={operation!r}, "
                            f"record_bytes={oversized}, max_record_bytes={max_record_bytes}"
                        )
                    if observed_bytes > max_total_bytes:
                        raise GreengageResultLimitError(
                            "Greengage bounded metadata query exceeded its total byte budget: "
                            f"operation={operation!r}, observed_bytes={observed_bytes}, "
                            f"max_total_bytes={max_total_bytes}"
                        )
                    records.extend(batch)
                    total_bytes = observed_bytes
        except psycopg.Error as error:
            raise GreenplumQueryError(
                operation,
                error.sqlstate,
                type(error).__name__,
            ) from None
        return tuple(records)

    def close(self, primary_error: BaseException | None) -> None:
        if self.closed:
            return
        self.closed = True
        cleanup_error: psycopg.Error | None = None
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("ROLLBACK")
        except psycopg.Error as error:
            cleanup_error = error
        self.connection.close()
        if cleanup_error is None or primary_error is not None:
            return
        raise GreenplumCloseError(
            "Greengage protected endpoint cleanup failed: "
            f"sqlstate={cleanup_error.sqlstate!r}, "
            f"error_category={type(cleanup_error).__name__!r}"
        ) from None


class GreengageProtectedReadContext:
    """One sealed Greengage read-only Repeatable Read endpoint snapshot."""

    def __init__(
        self,
        session: _GreengageEndpointSession,
        driver: GreenplumDriverEvidence,
        server: GreenplumServerProfile,
        reader: GreenplumReaderIdentity,
        topology: GreenplumTopology,
        hash_capability: GreengageHashCapability,
        protected_relations: tuple[GreengageProtectedRelationInspection, ...],
        evidence: GreengageProtectedReadContextEvidence,
    ) -> None:
        self._session = session
        self._driver = driver
        self._server = server
        self._reader = reader
        self._topology = topology
        self._hash_capability = hash_capability
        self._protected_relations = protected_relations
        self._evidence = evidence
        self._state = ReadContextState.ACTIVE
        self._query_lock = Lock()

    @property
    def driver(self) -> GreenplumDriverEvidence:
        return self._driver

    @property
    def server(self) -> GreenplumServerProfile:
        return self._server

    @property
    def reader(self) -> GreenplumReaderIdentity:
        return self._reader

    @property
    def topology(self) -> GreenplumTopology:
        return self._topology

    @property
    def hash_capability(self) -> GreengageHashCapability:
        return self._hash_capability

    @property
    def protected_relations(self) -> tuple[GreengageProtectedRelationInspection, ...]:
        return self._protected_relations

    @property
    def evidence(self) -> GreengageProtectedReadContextEvidence:
        return self._evidence

    @property
    def state(self) -> ReadContextState:
        return self._state

    @property
    def source_budget(self) -> PostgresSourceBudgetAttempt:
        return self._session.source_budget

    @property
    def source_direction(self) -> PostgresSourceDirection:
        return self._session.direction

    @property
    def fingerprint_plan_reservation(self) -> GreengageFingerprintPlanReservation:
        return GreengageFingerprintPlanReservation(
            additional_queries=2,
            max_fetched_records=_MAX_EXPLAIN_ROWS + 1,
            max_result_bytes=_MAX_EXPLAIN_TOTAL_BYTES + _SESSION_INVARIANT_RECORD_BYTES,
            max_coordinator_bytes=_MAX_EXPLAIN_COORDINATOR_BYTES,
        )

    def fingerprint_result_reservation(
        self,
        range_count: int,
    ) -> GreengageFingerprintResultReservation:
        if type(range_count) is not int or range_count < 1:
            raise ValueError("Greengage fingerprint range count must be a positive integer")
        topology_bytes = len(
            ",".join(str(content_id) for content_id in self._topology.primary_content_ids).encode(
                "ascii"
            )
        )
        additional_record_bytes = 2 * topology_bytes
        return GreengageFingerprintResultReservation(
            additional_record_bytes=additional_record_bytes,
            additional_result_bytes=range_count * additional_record_bytes,
            additional_fields_per_record=2,
            additional_ascii_values=2 * range_count,
        )

    def read_integer_key_summary(
        self,
        protected_relation: GreengageProtectedRelationInspection,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        max_encoded_envelope_bytes: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresIntegerKeySummaryRead:
        self._require_relation(protected_relation)
        _require_full_scans(full_scans, 1, "integer-key summary")
        query = _key_summary_query(
            protected_relation,
            key_field_index,
            scope,
            max_encoded_envelope_bytes,
        )
        rows = self._execute_read(
            query,
            1,
            max_record_bytes + _RAW_RESULT_OVERHEAD_BYTES,
            max_total_bytes + _RAW_RESULT_OVERHEAD_BYTES,
            full_scans,
            deadline,
            "greengage_integer_key_summary",
        )
        try:
            if len(rows) != 1:
                raise GreenplumDataValidationError(
                    "Greengage integer-key summary must return exactly one row"
                )
            summary = _parse_key_summary(rows[0], query)
            return PostgresIntegerKeySummaryRead(
                summary=summary,
                metrics=_read_metrics(rows, deadline),
            )
        except _GREENGAGE_RUNTIME_FAILURES as error:
            self._retire(error)
            raise

    def read_integer_range_fingerprints(
        self,
        protected_relation: GreengageProtectedRelationInspection,
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
        _require_full_scans(full_scans, 1, "integer-range fingerprint")
        query = _range_fingerprint_query(
            protected_relation,
            self._topology,
            key_field_index,
            scope,
            ranges,
            max_encoded_envelope_bytes,
        )
        result_reservation = self.fingerprint_result_reservation(len(ranges))
        with self._query_lock:
            self._require_active()
            try:
                self._restore_invariants(deadline)
                plan_rows = self._session.fetch_client_rows(
                    explain_greengage_endpoint_query(query.statement),
                    query.parameters,
                    _MAX_EXPLAIN_ROWS,
                    _MAX_EXPLAIN_RECORD_BYTES,
                    _MAX_EXPLAIN_TOTAL_BYTES,
                    0,
                    "greengage_integer_range_fingerprint_plan",
                )
                validate_greengage_range_fingerprint_plan(
                    plan_rows,
                    query,
                    protected_relation.catalog.storage_kind,
                )
                self._restore_invariants(deadline)
                rows = self._session.fetch_rows(
                    query.statement,
                    query.parameters,
                    len(ranges),
                    max_record_bytes
                    + _MAX_ROW_TYPE_OID_BYTES
                    + result_reservation.additional_record_bytes,
                    max_total_bytes
                    + (len(ranges) * _MAX_ROW_TYPE_OID_BYTES)
                    + result_reservation.additional_result_bytes,
                    full_scans,
                    "greengage_integer_range_fingerprint",
                )
                _require_query_provenance(
                    rows,
                    query,
                    "greengage_integer_range_fingerprint",
                )
            except (GreenplumCatalogDataError, GreenplumCatalogMetadataError) as error:
                mapped = _map_catalog_error(error)
                self._lose(mapped)
                raise mapped from None
            except _GREENGAGE_RUNTIME_FAILURES as error:
                self._lose(error)
                raise
        try:
            parsed = _parse_range_fingerprints(rows, query, deadline)
            return PostgresRangeFingerprintRead(
                ranges=parsed,
                metrics=_read_metrics(rows, deadline),
            )
        except _GREENGAGE_RUNTIME_FAILURES as error:
            self._retire(error)
            raise

    def read_integer_range_rows(
        self,
        protected_relation: GreengageProtectedRelationInspection,
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
        _require_full_scans(full_scans, len(ranges), "integer-range exact read")
        query = _range_rows_query(
            protected_relation,
            key_field_index,
            scope,
            ranges,
            max_encoded_envelope_bytes,
        )
        rows = self._execute_read(
            query,
            max_records,
            max_record_bytes + _MAX_ROW_TYPE_OID_BYTES + _HAS_DATA_BYTES,
            max_total_bytes + (max_records * (_MAX_ROW_TYPE_OID_BYTES + _HAS_DATA_BYTES)),
            full_scans,
            deadline,
            "greengage_integer_range_rows",
        )
        try:
            parsed = _parse_exact_rows(rows, query, ranges, key_field_index, deadline)
            return PostgresIntegerExactRowsRead(
                rows=parsed,
                metrics=_exact_read_metrics(
                    parsed,
                    max_records,
                    max_record_bytes,
                    max_total_bytes,
                    deadline,
                ),
            )
        except _GREENGAGE_RUNTIME_FAILURES as error:
            self._retire(error)
            raise

    def read_relation_manifest(
        self,
        protected_relation: GreengageProtectedRelationInspection,
        columns: ReadinessManifestColumns,
        dataset_id: str,
        scope_digest: str,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[PostgresRelationManifestRecord, ...]:
        self._require_relation(protected_relation)
        _validate_manifest_contract(protected_relation, columns)
        if type(dataset_id) is not str or not dataset_id or "\x00" in dataset_id:
            raise ValueError("Greengage manifest dataset_id must be non-empty text")
        if type(scope_digest) is not str or _SHA256_HEX.fullmatch(scope_digest) is None:
            raise ValueError("Greengage manifest scope_digest must be lowercase SHA-256 hex")
        _validate_result_limits(2, max_record_bytes, max_total_bytes)
        statement = _manifest_statement(protected_relation, columns)
        try:
            deadline = self.source_budget.read_deadline(
                self.source_budget.effective_statement_timeout_milliseconds()
            )
        except PostgresReadDeadlineExceededError as error:
            self._retire(error)
            raise
        query = GreengageEndpointQuery(
            statement=statement,
            parameters=(dataset_id, scope_digest),
            context=prepare_envelope_context(protected_relation.acquisition.schema),
            relation_row_type_oid=protected_relation.inspection.relation_row_type_oid,
            max_encoded_envelope_bytes=max_record_bytes,
        )
        rows = self._execute_read(
            query,
            2,
            max_record_bytes + _MAX_ROW_TYPE_OID_BYTES,
            max_total_bytes + (2 * _MAX_ROW_TYPE_OID_BYTES),
            0,
            deadline,
            "greengage_relation_manifest",
        )
        try:
            return tuple(_parse_manifest_record(row, query) for row in rows)
        except _GREENGAGE_RUNTIME_FAILURES as error:
            self._retire(error)
            raise

    def close(self) -> None:
        self._close(None)

    def __enter__(self) -> Self:
        self._require_active()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._close(exception)

    def _execute_read(
        self,
        query: GreengageEndpointQuery,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        full_scans: int,
        deadline: PostgresReadDeadline,
        operation: str,
    ) -> tuple[DatabaseRow, ...]:
        with self._query_lock:
            self._require_active()
            try:
                self._restore_invariants(deadline)
                rows = self._session.fetch_rows(
                    query.statement,
                    query.parameters,
                    max_records,
                    max_record_bytes,
                    max_total_bytes,
                    full_scans,
                    operation,
                )
                _require_query_provenance(rows, query, operation)
            except _GREENGAGE_RUNTIME_FAILURES as error:
                self._lose(error)
                raise
        return rows

    def _restore_invariants(self, deadline: PostgresReadDeadline) -> None:
        _require_deadline(deadline, "session invariant restoration")
        remaining_milliseconds = max(
            1,
            (deadline.deadline_nanoseconds - time.monotonic_ns()) // 1_000_000,
        )
        timeout_milliseconds = min(
            self._session.statement_timeout_milliseconds,
            deadline.statement_timeout_milliseconds,
            self.source_budget.effective_statement_timeout_milliseconds(),
            remaining_milliseconds,
        )
        rows = self._session.fetch_client_rows(
            "SELECT pg_catalog.set_config('statement_timeout', %s, true), "
            "pg_catalog.current_setting('transaction_isolation'), "
            "pg_catalog.current_setting('transaction_read_only'), "
            "pg_catalog.current_setting('optimizer'), "
            "pg_catalog.current_setting('gp_enable_multiphase_agg'), "
            "pg_catalog.current_setting('gp_eager_two_phase_agg'), "
            "pg_catalog.current_setting('row_security'), "
            "pg_catalog.current_setting('TimeZone')",
            (str(timeout_milliseconds),),
            1,
            _SESSION_INVARIANT_RECORD_BYTES,
            _SESSION_INVARIANT_RECORD_BYTES,
            0,
            "greengage_restore_endpoint_invariants",
        )
        expected = (
            "repeatable read",
            "on",
            "off",
            "on",
            "on",
            "off",
            "UTC",
        )
        if len(rows) != 1 or len(rows[0]) != 8:
            raise GreenplumDataValidationError(
                "Greengage endpoint invariant probe returned an unexpected shape"
            )
        actual = tuple(_require_text(value, "Greengage endpoint setting") for value in rows[0][1:])
        if actual != expected:
            raise UnsupportedGreenplumProfileError(
                "Greengage endpoint session invariants changed inside the protected snapshot: "
                f"actual={actual!r}, expected={expected!r}"
            )

    def _require_relation(
        self,
        protected_relation: GreengageProtectedRelationInspection,
    ) -> None:
        self._require_active()
        if not any(candidate is protected_relation for candidate in self._protected_relations):
            raise GreenplumMetadataError(
                "Greengage relation inspection does not belong to the exact protected set"
            )
        if protected_relation.inspection.context_id != self._evidence.context_id:
            raise GreenplumMetadataError(
                "Greengage protected relation belongs to a different read context"
            )

    def _close(self, primary_error: BaseException | None) -> None:
        with self._query_lock:
            if self._state is ReadContextState.CLOSED:
                return
            previous_state = self._state
            self._state = ReadContextState.CLOSED
            if previous_state is ReadContextState.ACTIVE:
                self._session.close(primary_error)

    def _lose(self, error: BaseException) -> None:
        if self._state is not ReadContextState.ACTIVE:
            return
        self._state = ReadContextState.LOST
        self._session.close(error)

    def _retire(self, error: BaseException) -> None:
        with self._query_lock:
            self._lose(error)

    def _require_active(self) -> None:
        if self._state is ReadContextState.CLOSED:
            raise GreenplumContextClosedError(
                "Greengage protected endpoint context is already closed"
            )
        if self._state is ReadContextState.LOST:
            raise GreenplumContextLostError(
                "Greengage protected endpoint snapshot was lost and cannot be reused"
            )


def open_greengage_protected_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    acquisitions: tuple[GreengageRelationAcquisition, ...],
    lock_timeout_milliseconds: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> GreengageProtectedReadContext:
    ordered = _validate_acquisitions(acquisitions)
    _validate_lock_timeout(lock_timeout_milliseconds, settings.statement_timeout_milliseconds)
    last_error: BaseException | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        try:
            connection = _connect_once(settings, source_budget)
            session = _GreengageEndpointSession(
                connection,
                source_budget,
                direction,
                settings.statement_timeout_milliseconds,
            )
            return _open_once(
                session,
                settings,
                ordered,
                lock_timeout_milliseconds,
            )
        except (GreengageAcquisitionRaceError, GreenplumConnectionError) as error:
            last_error = error
            LOGGER.warning(
                "Greengage protected endpoint acquisition attempt failed",
                extra={
                    "operation": "open_greengage_protected_read_context",
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "dbname": settings.dbname,
                    "user": settings.user,
                    "error_type": type(error).__name__,
                },
            )
            if attempt < retry_policy.max_attempts:
                time.sleep(retry_policy.delay_seconds)
    if last_error is None:
        raise AssertionError("Greengage protected acquisition loop ended without an attempt")
    raise last_error


def _open_once(
    session: _GreengageEndpointSession,
    settings: PostgresConnectionSettings,
    acquisitions: tuple[GreengageRelationAcquisition, ...],
    lock_timeout_milliseconds: int,
) -> GreengageProtectedReadContext:
    succeeded = False
    try:
        candidates = tuple(
            _discover_candidate(session, acquisition) for acquisition in acquisitions
        )
        started_at = datetime.now(UTC)
        session.prepare_acquisition_statement()
        session.command(
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
            (),
            "greengage_begin_protected_snapshot",
        )
        session.prepare_acquisition_statement()
        session.command(
            "SET LOCAL search_path TO pg_catalog; SET LOCAL TimeZone TO 'UTC'; "
            "SET LOCAL DateStyle TO 'ISO, YMD'; SET LOCAL row_security TO off; "
            "SET LOCAL optimizer TO off; SET LOCAL gp_enable_multiphase_agg TO on; "
            "SET LOCAL gp_eager_two_phase_agg TO on; "
            f"SET LOCAL lock_timeout TO '{lock_timeout_milliseconds}ms'",
            (),
            "greengage_configure_protected_snapshot",
        )
        session.prepare_acquisition_statement()
        session.command(
            _lock_statement(acquisitions),
            (),
            "greengage_lock_protected_relations",
        )
        server = _probe_server(session, settings)
        planning_settings = _probe_planning_settings(session)
        topology = _probe_topology(session)
        reader = _probe_reader(session, settings)
        hash_capability = _probe_hash_capability(session)
        context_id = uuid4()
        sealed = tuple(
            _seal_candidate(session, candidate, context_id, server, topology)
            for candidate in candidates
        )
        relation_locks = _probe_locks(session, sealed)
        evidence = GreengageProtectedReadContextEvidence(
            context_id=context_id,
            runtime_profile=GreenplumRuntimeProfile.GREENGAGE,
            strategy="protected_read_only_repeatable_read_distributed",
            snapshot_locator=server.snapshot_locator,
            started_at=started_at,
            backend_process_id=server.backend_process_id,
            allowed_concurrency=1,
            planning_settings=planning_settings,
            relation_locks=relation_locks,
            acquired_before_snapshot=True,
            limitations=(
                "physical_only",
                "single_coordinator_session",
                "distributed_partial_fingerprint_aggregation_required",
            ),
        )
        context = GreengageProtectedReadContext(
            session,
            _driver_evidence(),
            server,
            reader,
            topology,
            hash_capability,
            sealed,
            evidence,
        )
        succeeded = True
        return context
    except GreengageAcquisitionRaceError as error:
        session.close(error)
        raise
    except GreenplumCatalogMetadataError as error:
        mapped = GreenplumMetadataError(str(error))
        session.close(mapped)
        raise mapped from None
    except GreenplumCatalogDataError as error:
        mapped = GreenplumDataValidationError(str(error))
        session.close(mapped)
        raise mapped from None
    except BaseException as error:
        session.close(error)
        raise
    finally:
        if not succeeded and not session.closed:
            session.close(None)


def _connect_once(
    settings: PostgresConnectionSettings,
    source_budget: PostgresSourceBudgetAttempt,
) -> psycopg.Connection[DatabaseRow]:
    try:
        return psycopg.connect(
            host=settings.host,
            port=settings.port,
            dbname=settings.dbname,
            user=settings.user,
            password=settings.password.get_secret_value(),
            sslmode=settings.sslmode.value,
            connect_timeout=settings.connect_timeout_seconds,
            application_name=settings.application_name,
            options=(
                "-c statement_timeout="
                f"{min(settings.statement_timeout_milliseconds, source_budget.effective_statement_timeout_milliseconds())}"
            ),
            autocommit=True,
            row_factory=tuple_row,
        )
    except psycopg.Error as error:
        raise GreenplumConnectionError(
            "Greengage protected endpoint connection failed: "
            f"host={settings.host!r}, port={settings.port}, dbname={settings.dbname!r}, "
            f"user={settings.user!r}, sslmode={settings.sslmode.value!r}, "
            f"sqlstate={error.sqlstate!r}, error_category={type(error).__name__!r}"
        ) from None


def _discover_candidate(
    session: _GreengageEndpointSession,
    acquisition: GreengageRelationAcquisition,
) -> _GreengageCandidate:
    request = _relation_request(acquisition)
    session.prepare_acquisition_statement()
    relation_rows = session.fetch_client_rows(
        GREENGAGE_RELATION_QUERY,
        acquisition.relation.components,
        1,
        acquisition.max_metadata_record_bytes,
        acquisition.max_metadata_total_bytes,
        0,
        "greengage_endpoint_candidate_relation",
    )
    relation = parse_greengage_relation_catalog(relation_rows, request)
    _validate_endpoint_catalog(relation)
    type_statement, type_parameters = greenplum_type_catalog_query(
        relation.relation_oid,
        request,
    )
    session.prepare_acquisition_statement()
    type_rows = session.fetch_client_rows(
        type_statement,
        cast(tuple[GreengageEndpointParameter, ...], type_parameters),
        len(request.columns),
        acquisition.max_metadata_record_bytes,
        acquisition.max_metadata_total_bytes,
        0,
        "greengage_endpoint_candidate_types",
    )
    types = parse_greenplum_type_probe(type_rows, request)
    return _GreengageCandidate(acquisition, request, relation, types)


def _seal_candidate(
    session: _GreengageEndpointSession,
    candidate: _GreengageCandidate,
    context_id: UUID,
    server: GreenplumServerProfile,
    topology: GreenplumTopology,
) -> GreengageProtectedRelationInspection:
    acquisition = candidate.acquisition
    try:
        session.prepare_acquisition_statement()
        relation_rows = session.fetch_client_rows(
            GREENGAGE_RELATION_QUERY,
            acquisition.relation.components,
            1,
            acquisition.max_metadata_record_bytes,
            acquisition.max_metadata_total_bytes,
            0,
            "greengage_endpoint_protected_relation",
        )
        relation = parse_greengage_relation_catalog(relation_rows, candidate.request)
        _validate_endpoint_catalog(relation)
        type_statement, type_parameters = greenplum_type_catalog_query(
            relation.relation_oid,
            candidate.request,
        )
        session.prepare_acquisition_statement()
        type_rows = session.fetch_client_rows(
            type_statement,
            cast(tuple[GreengageEndpointParameter, ...], type_parameters),
            len(candidate.request.columns),
            acquisition.max_metadata_record_bytes,
            acquisition.max_metadata_total_bytes,
            0,
            "greengage_endpoint_protected_types",
        )
        types = parse_greenplum_type_probe(type_rows, candidate.request)
    except (
        GreenplumCatalogDataError,
        GreenplumCatalogMetadataError,
        GreenplumMetadataError,
    ) as error:
        raise GreengageAcquisitionRaceError(
            "Greengage relation metadata stopped matching its discovered shape during "
            f"protected acquisition: relation={acquisition.relation.components!r}, "
            f"reason_type={type(error).__name__}"
        ) from None
    if relation != candidate.relation or types != candidate.types:
        raise GreengageAcquisitionRaceError(
            "Greengage relation identity or type metadata changed between discovery and "
            f"protected acquisition: relation={acquisition.relation.components!r}"
        )
    if relation.distribution_segment_count != len(topology.primary_content_ids):
        raise GreenplumMetadataError(
            "Greengage relation distribution segment count differs from active topology: "
            f"relation={acquisition.relation.components!r}, "
            f"distribution_segments={relation.distribution_segment_count}, "
            f"active_primaries={len(topology.primary_content_ids)}"
        )
    try:
        inspection = PostgresInspectedRelation(
            context_id=context_id,
            relation_oid=relation.relation_oid,
            relation_row_type_oid=relation.relation_row_type_oid,
            relation=PostgresRelation(components=acquisition.relation.components),
            bindings=types.bindings,
            max_identifier_utf8_bytes=server.max_identifier_utf8_bytes,
        )
        validate_postgres_inspection(acquisition.schema, inspection)
        return GreengageProtectedRelationInspection(
            acquisition=acquisition,
            inspection=inspection,
            catalog=relation,
            lock_mode="access_share",
            acquired_before_snapshot=True,
        )
    except PostgresLoweringError as error:
        raise GreenplumMetadataError(
            "Greengage relation cannot satisfy the canonical schema capability: "
            f"relation={acquisition.relation.components!r}, detail={str(error)!r}"
        ) from None


def _validate_acquisitions(
    acquisitions: object,
) -> tuple[GreengageRelationAcquisition, ...]:
    if type(acquisitions) is not tuple or not acquisitions:
        raise ValueError("Greengage acquisitions must be a non-empty immutable tuple")
    typed = cast(tuple[object, ...], acquisitions)
    for index, acquisition in enumerate(typed):
        if not isinstance(acquisition, GreengageRelationAcquisition):
            raise TypeError(
                "Greengage acquisitions contain an unexpected value: "
                f"index={index}, type={type(acquisition).__name__}"
            )
    ordered = tuple(
        sorted(
            cast(tuple[GreengageRelationAcquisition, ...], typed),
            key=lambda acquisition: acquisition.relation.components,
        )
    )
    identities = tuple(acquisition.relation.components for acquisition in ordered)
    if len(set(identities)) != len(identities):
        raise ValueError("Greengage acquisitions must identify distinct physical relations")
    return ordered


def _validate_lock_timeout(
    lock_timeout_milliseconds: object,
    statement_timeout_milliseconds: int,
) -> None:
    if type(lock_timeout_milliseconds) is not int or lock_timeout_milliseconds < 1:
        raise ValueError("Greengage lock_timeout_milliseconds must be a positive integer")
    if lock_timeout_milliseconds >= statement_timeout_milliseconds:
        raise ValueError(
            "Greengage lock timeout must be less than statement timeout: "
            f"lock={lock_timeout_milliseconds}, statement={statement_timeout_milliseconds}"
        )


def _lock_statement(acquisitions: tuple[GreengageRelationAcquisition, ...]) -> str:
    relations = ", ".join(
        ".".join(_quote_identifier(component) for component in acquisition.relation.components)
        for acquisition in acquisitions
    )
    return f"LOCK TABLE {relations} IN ACCESS SHARE MODE"


def _quote_identifier(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("Greengage SQL identifier must be non-empty text without U+0000")
    return '"' + value.replace('"', '""') + '"'


def _relation_request(acquisition: GreengageRelationAcquisition) -> GreenplumRelationRequest:
    return GreenplumRelationRequest(
        schema_name=acquisition.relation.components[0],
        relation_name=acquisition.relation.components[1],
        columns=tuple(
            GreenplumColumnProbe(field_name=field.name, column_name=column_name)
            for field, column_name in zip(
                acquisition.schema.fields,
                acquisition.column_names,
                strict=True,
            )
        ),
    )


def _validate_endpoint_catalog(relation: GreengageRelationCatalog) -> None:
    failures: list[str] = []
    if relation.relation_kind != "r":
        failures.append(f"relation_kind={relation.relation_kind!r}, required='r'")
    if relation.persistence_code != "p":
        failures.append(f"persistence={relation.persistence_code!r}, required='p'")
    if relation.row_security_enabled or relation.row_security_forced:
        failures.append(
            "row_security must be disabled: "
            f"enabled={relation.row_security_enabled}, forced={relation.row_security_forced}"
        )
    if not relation.has_distribution_policy:
        failures.append("distribution_policy=missing")
    if failures:
        raise GreenplumCatalogMetadataError(
            "Greengage endpoint relation is outside the physical-only protected profile: "
            f"relation={relation.schema_name!r}.{relation.relation_name!r}; " + "; ".join(failures)
        )


def _probe_server(
    session: _GreengageEndpointSession,
    settings: PostgresConnectionSettings,
) -> GreenplumServerProfile:
    session.prepare_acquisition_statement()
    rows = session.fetch_client_rows(
        GREENGAGE_PROFILE_QUERY,
        (),
        1,
        4_096,
        4_096,
        0,
        "greengage_endpoint_server_profile",
    )
    if len(rows) != 1 or len(rows[0]) != 16:
        raise GreenplumDataValidationError(
            "Greengage endpoint profile must return exactly one sixteen-field row"
        )
    row = rows[0]
    full_version = _require_text(row[0], "Greengage full version")
    product_version = _require_text(row[1], "Greengage product version")
    identity_version = _extract_product_version(full_version, "Greengage Database")
    if product_version != identity_version:
        raise UnsupportedGreenplumProfileError(
            "Greengage endpoint product identity sources disagree: "
            f"version_identity={identity_version!r}, gp_server_version={product_version!r}"
        )
    profile = GreenplumServerProfile(
        runtime_profile=GreenplumRuntimeProfile.GREENGAGE,
        full_version=full_version,
        product_version=product_version,
        compatibility_version=_require_text(row[2], "Greengage compatibility version"),
        compatibility_version_number=_require_integer(
            row[3],
            "Greengage compatibility version number",
            1,
            INT64_MAX,
        ),
        server_encoding=_require_text(row[4], "Greengage server encoding"),
        client_encoding=_require_text(row[5], "Greengage client encoding"),
        integer_datetimes=_require_boolean(row[6], "Greengage integer datetimes"),
        timezone=_require_text(row[7], "Greengage TimeZone"),
        max_identifier_utf8_bytes=_require_integer(
            row[8],
            "Greengage max identifier length",
            1,
            INT64_MAX,
        ),
        gp_role=_require_text(row[9], "Greengage gp_role"),
        gp_session_role=_require_text(row[10], "Greengage gp_session_role"),
        database_name=_require_text(row[11], "Greengage database"),
        backend_process_id=_require_integer(
            row[12],
            "Greengage backend process ID",
            1,
            INT64_MAX,
        ),
        transaction_isolation=_require_text(row[13], "Greengage isolation"),
        transaction_read_only=_require_boolean(row[14], "Greengage read-only state"),
        snapshot_locator=_require_text(row[15], "Greengage snapshot locator"),
    )
    failures: list[str] = []
    for actual, required, label in (
        (profile.server_encoding, "UTF8", "server_encoding"),
        (profile.client_encoding, "UTF8", "client_encoding"),
        (profile.timezone, "UTC", "TimeZone"),
        (profile.gp_role, "dispatch", "gp_role"),
        (profile.gp_session_role, "dispatch", "gp_session_role"),
        (profile.transaction_isolation, "repeatable read", "transaction_isolation"),
        (profile.database_name, settings.dbname, "database"),
    ):
        if actual != required:
            failures.append(f"{label}={actual!r}, required={required!r}")
    if not profile.integer_datetimes:
        failures.append("integer_datetimes=off, required=on")
    if not profile.transaction_read_only:
        failures.append("transaction_read_only=off, required=on")
    if failures:
        raise UnsupportedGreenplumProfileError(
            "Greengage endpoint profile is unsupported: " + "; ".join(failures)
        )
    return profile


def _probe_planning_settings(
    session: _GreengageEndpointSession,
) -> tuple[GreenplumSessionSettingEvidence, ...]:
    session.prepare_acquisition_statement()
    rows = session.fetch_client_rows(
        GREENGAGE_CANONICAL_PLANNING_SETTINGS_QUERY,
        (),
        1,
        4_096,
        4_096,
        0,
        "greengage_endpoint_planning_settings",
    )
    if len(rows) != 1 or len(rows[0]) != 3:
        raise GreenplumDataValidationError(
            "Greengage endpoint planning probe must return one three-field row"
        )
    values = tuple(_require_text(value, "Greengage planning setting") for value in rows[0])
    expected = ("off", "on", "on")
    if values != expected:
        raise UnsupportedGreenplumProfileError(
            "Greengage endpoint planning settings do not provide distributed exact "
            f"aggregation: actual={values!r}, expected={expected!r}"
        )
    return tuple(
        GreenplumSessionSettingEvidence(name=name, value=value)
        for name, value in zip(
            ("optimizer", "gp_enable_multiphase_agg", "gp_eager_two_phase_agg"),
            values,
            strict=True,
        )
    )


def _probe_topology(session: _GreengageEndpointSession) -> GreenplumTopology:
    session.prepare_acquisition_statement()
    rows = session.fetch_client_rows(
        TOPOLOGY_QUERY,
        (),
        _MAX_TOPOLOGY_ROWS,
        4_096,
        _MAX_TOPOLOGY_ROWS * 4_096,
        0,
        "greengage_endpoint_topology",
    )
    return parse_greenplum_topology(rows)


def _probe_reader(
    session: _GreengageEndpointSession,
    settings: PostgresConnectionSettings,
) -> GreenplumReaderIdentity:
    session.prepare_acquisition_statement()
    rows = session.fetch_client_rows(
        READER_IDENTITY_QUERY,
        (),
        1,
        4_096,
        4_096,
        0,
        "greengage_endpoint_reader_identity",
    )
    if len(rows) != 1:
        raise GreenplumMetadataError("Greengage endpoint reader identity is unavailable")
    identity = parse_greenplum_reader_identity(rows[0])
    if identity.user_name != settings.user:
        raise GreenplumMetadataError(
            "Greengage authenticated reader differs from the requested role: "
            f"requested={settings.user!r}, actual={identity.user_name!r}"
        )
    return identity


def _probe_hash_capability(session: _GreengageEndpointSession) -> GreengageHashCapability:
    session.prepare_acquisition_statement()
    rows = session.fetch_client_rows(
        GREENGAGE_HASH_CAPABILITY_QUERY,
        (),
        1,
        4_096,
        4_096,
        0,
        "greengage_endpoint_hash_capability",
    )
    return parse_greengage_hash_capability(rows)


def _probe_locks(
    session: _GreengageEndpointSession,
    relations: tuple[GreengageProtectedRelationInspection, ...],
) -> tuple[GreenplumRelationLockEvidence, ...]:
    expected = {
        relation.catalog.relation_oid: relation.acquisition.relation.components
        for relation in relations
    }
    if len(expected) != len(relations):
        raise GreenplumMetadataError(
            "Greengage protected relation closure contains duplicate relation OIDs"
        )
    placeholders = ", ".join("%s::oid" for _ in relations)
    session.prepare_acquisition_statement()
    rows = session.fetch_client_rows(
        "SELECT relation::bigint, mode::text, granted FROM pg_catalog.pg_locks "
        "WHERE pid = pg_catalog.pg_backend_pid() AND locktype = 'relation' "
        "AND mode = 'AccessShareLock' AND granted "
        f"AND relation IN ({placeholders}) ORDER BY relation",
        tuple(expected),
        len(relations),
        4_096,
        len(relations) * 4_096,
        0,
        "greengage_endpoint_relation_locks",
    )
    locks: list[GreenplumRelationLockEvidence] = []
    for index, row in enumerate(rows):
        if len(row) != 3:
            raise GreenplumDataValidationError(
                f"Greengage relation lock row must contain exactly three fields: row_index={index}"
            )
        relation_oid = _require_integer(
            row[0],
            "Greengage locked relation OID",
            1,
            INT64_MAX,
        )
        identity = expected.get(relation_oid)
        mode = _require_text(row[1], "Greengage relation lock mode")
        granted = _require_boolean(row[2], "Greengage relation lock grant")
        if identity is None or mode != "AccessShareLock" or not granted:
            raise GreenplumMetadataError(
                "Greengage protected relation lock evidence is incomplete or unexpected: "
                f"relation_oid={relation_oid}, mode={mode!r}, granted={granted}"
            )
        locks.append(
            GreenplumRelationLockEvidence(
                relation_oid=relation_oid,
                schema_name=identity[0],
                relation_name=identity[1],
                lock_mode=mode,
            )
        )
    if {lock.relation_oid for lock in locks} != set(expected):
        raise GreenplumMetadataError(
            "Greengage protected snapshot does not hold the complete relation lock closure"
        )
    return tuple(sorted(locks, key=lambda lock: (lock.schema_name, lock.relation_name)))


def _driver_evidence() -> GreenplumDriverEvidence:
    return GreenplumDriverEvidence(
        driver_name="psycopg",
        driver_version=_PSYCOPG_VERSION,
        build_libpq_version=pq.__build_version__,
        runtime_libpq_version=pq.version(),
    )


def _extract_product_version(full_version: str, product_marker: str) -> str:
    marker = f"({product_marker} "
    start = full_version.find(marker)
    if start < 0:
        raise UnsupportedGreenplumProfileError(
            "Connected endpoint does not expose the declared Greengage identity: "
            f"required_marker={product_marker!r}, full_version={full_version!r}"
        )
    version_start = start + len(marker)
    version_end = full_version.find(")", version_start)
    if version_end < 0:
        raise UnsupportedGreenplumProfileError(
            "Connected Greengage endpoint exposes a malformed product identity"
        )
    product_version = full_version[version_start:version_end]
    if not product_version:
        raise UnsupportedGreenplumProfileError(
            "Connected Greengage endpoint product identity omits its version"
        )
    return product_version


def _key_summary_query(
    relation: GreengageProtectedRelationInspection,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> GreengageEndpointQuery:
    acquisition = relation.acquisition
    return build_greengage_integer_key_summary_query(
        acquisition.schema,
        acquisition.relation.components[0],
        acquisition.relation.components[1],
        relation.inspection.relation_oid,
        relation.inspection.relation_row_type_oid,
        relation.inspection.bindings,
        relation.inspection.max_identifier_utf8_bytes,
        key_field_index,
        scope,
        max_encoded_envelope_bytes,
    )


def _range_fingerprint_query(
    relation: GreengageProtectedRelationInspection,
    topology: GreenplumTopology,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> GreengageRangeFingerprintQuery:
    acquisition = relation.acquisition
    return build_greengage_integer_range_fingerprint_query(
        acquisition.schema,
        acquisition.relation.components[0],
        acquisition.relation.components[1],
        relation.inspection.relation_row_type_oid,
        relation.inspection.bindings,
        relation.inspection.max_identifier_utf8_bytes,
        topology.primary_content_ids,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
    )


def _range_rows_query(
    relation: GreengageProtectedRelationInspection,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> GreengageEndpointQuery:
    acquisition = relation.acquisition
    return build_greengage_integer_range_rows_query(
        acquisition.schema,
        acquisition.relation.components[0],
        acquisition.relation.components[1],
        relation.inspection.relation_row_type_oid,
        relation.inspection.bindings,
        relation.inspection.max_identifier_utf8_bytes,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
    )


def _parse_key_summary(
    row: DatabaseRow,
    query: GreengageEndpointQuery,
) -> PostgresIntegerKeySummary:
    if len(row) != 9:
        raise GreenplumDataValidationError(
            "Greengage integer-key summary must return exactly nine fields"
        )
    _require_origin_oid(row[0], query, "integer-key summary")
    counts = tuple(
        _parse_unsigned_decimal(value, "Greengage integer-key count", INT64_MAX)
        for value in row[1:6]
    )
    minimum = _parse_optional_int64(row[6], "Greengage integer-key minimum")
    maximum = _parse_optional_int64(row[7], "Greengage integer-key maximum")
    return PostgresIntegerKeySummary(
        row_count=counts[0],
        null_key_count=counts[1],
        invalid_key_count=counts[2],
        valid_key_count=counts[3],
        distinct_key_count=counts[4],
        minimum_key=minimum,
        maximum_key=maximum,
        usable_access_path=_require_boolean(
            row[8],
            "Greengage integer-key access path",
        ),
    )


def _parse_range_fingerprints(
    rows: tuple[DatabaseRow, ...],
    query: GreengageRangeFingerprintQuery,
    deadline: PostgresReadDeadline,
) -> tuple[PostgresRangeFingerprint, ...]:
    if len(rows) != len(query.ranges):
        raise GreenplumDataValidationError(
            "Greengage range fingerprint must return one row per requested range: "
            f"expected={len(query.ranges)}, actual={len(rows)}"
        )
    parsed: list[PostgresRangeFingerprint] = []
    expected_topology = query.primary_content_ids
    for index, (request, row) in enumerate(zip(query.ranges, rows, strict=True)):
        _require_deadline(deadline, "range fingerprint decoding")
        if len(row) != 17:
            raise GreenplumDataValidationError(
                "Greengage range fingerprint row must contain exactly seventeen fields: "
                f"row_index={index}, actual={len(row)}"
            )
        _require_origin_oid(row[0], query, "range fingerprint")
        segment_id = _require_text(row[1], "Greengage range segment ID")
        if segment_id != request.segment_id:
            raise GreenplumDataValidationError(
                "Greengage range fingerprint rows do not follow requested segment order"
            )
        count = _parse_unsigned_decimal(
            row[2],
            "Greengage range valid row count",
            INT64_MAX,
        )
        limbs = tuple(
            _parse_unsigned_decimal(
                row[3 + limb],
                f"Greengage range limb {limb}",
                DECIMAL_38_MAX,
            )
            for limb in range(8)
        )
        invalid = _parse_unsigned_decimal(
            row[11],
            "Greengage range invalid row count",
            INT64_MAX,
        )
        oversized = _parse_unsigned_decimal(
            row[12],
            "Greengage range oversized row count",
            INT64_MAX,
        )
        row_bytes = _parse_unsigned_decimal(
            row[13],
            "Greengage range row envelope bytes",
            INT64_MAX,
        )
        key_bytes = _parse_unsigned_decimal(
            row[14],
            "Greengage range key envelope bytes",
            INT64_MAX,
        )
        topology = _parse_content_ids(row[15], False, "Greengage range topology")
        observed = _parse_content_ids(row[16], True, "Greengage observed segments")
        if topology != expected_topology:
            raise GreenplumContextLostError(
                "Greengage active-primary topology changed during range fingerprint: "
                f"expected={expected_topology!r}, actual={topology!r}"
            )
        unexpected = frozenset(observed) - frozenset(topology)
        if unexpected:
            raise GreenplumContextLostError(
                "Greengage range fingerprint observed rows outside the captured topology: "
                f"unexpected={tuple(sorted(unexpected))!r}"
            )
        if invalid != 0:
            raise GreenplumDataValidationError(
                "Greengage range fingerprint rejected rows that cannot be represented "
                f"losslessly: segment_id={segment_id!r}, invalid_row_count={invalid}"
            )
        if oversized != 0:
            raise GreengageResultLimitError(
                "Greengage range fingerprint found canonical envelopes above the limit: "
                f"segment_id={segment_id!r}, oversized_row_count={oversized}, "
                f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
            )
        try:
            fingerprint = Fingerprint(
                count=count,
                limb_sums=(
                    limbs[0],
                    limbs[1],
                    limbs[2],
                    limbs[3],
                    limbs[4],
                    limbs[5],
                    limbs[6],
                    limbs[7],
                ),
            )
        except FingerprintOverflowError as error:
            raise GreenplumDataValidationError(
                "Greengage range fingerprint violates exact accumulator bounds: "
                f"segment_id={segment_id!r}, reason_type={type(error).__name__}"
            ) from None
        parsed.append(
            PostgresRangeFingerprint(
                segment_id=segment_id,
                fingerprint=fingerprint,
                row_envelope_bytes=row_bytes,
                key_envelope_bytes=key_bytes,
            )
        )
    return tuple(parsed)


def _parse_exact_rows(
    rows: tuple[DatabaseRow, ...],
    query: GreengageEndpointQuery,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    key_field_index: int,
    deadline: PostgresReadDeadline,
) -> tuple[PostgresIntegerExactRow, ...]:
    if type(key_field_index) is not int or not 0 <= key_field_index < len(
        query.context.schema.fields
    ):
        raise GreenplumDataValidationError(
            "Greengage exact-row key index does not identify a schema field"
        )
    key_schema = CanonicalSchema(
        protocol=query.context.schema.protocol,
        fields=(query.context.schema.fields[key_field_index],),
    )
    key_context = prepare_envelope_context(key_schema)
    ordinal_by_id = {request.segment_id: index for index, request in enumerate(ranges)}
    if not rows:
        raise GreenplumDataValidationError(
            "Greengage exact comparison returned no data rows or same-RTE witness"
        )
    parsed: list[PostgresIntegerExactRow] = []
    false_witness_count = 0
    previous_ordinal = -1
    previous_key: int | None = None
    for row_index, row in enumerate(rows):
        _require_deadline(deadline, "exact-row decoding")
        if len(row) != 7:
            raise GreenplumDataValidationError(
                "Greengage exact row must contain exactly seven fields: "
                f"row_index={row_index}, actual={len(row)}"
            )
        _require_origin_oid(row[0], query, "exact comparison")
        has_data = _require_boolean(row[1], "Greengage exact data marker")
        if not has_data:
            if any(value is not None for value in row[2:]):
                raise GreenplumDataValidationError(
                    "Greengage exact same-RTE witness exposed logical row fields"
                )
            false_witness_count += 1
            continue
        segment_id = _require_text(row[2], "Greengage exact segment ID")
        ordinal = ordinal_by_id.get(segment_id)
        if ordinal is None:
            raise GreenplumDataValidationError(
                "Greengage exact row identifies an unrequested range"
            )
        invalid = _require_boolean(row[5], "Greengage exact invalid-row status")
        oversized = _require_boolean(row[6], "Greengage exact oversized-row status")
        if invalid and oversized:
            raise GreenplumDataValidationError(
                "Greengage exact comparison row statuses must be mutually exclusive"
            )
        if invalid:
            raise GreenplumDataValidationError(
                "Greengage exact comparison found a row that cannot be represented losslessly"
            )
        if oversized:
            raise GreengageResultLimitError(
                "Greengage exact comparison found a canonical envelope above the "
                f"configured limit: max_encoded_envelope_bytes="
                f"{query.max_encoded_envelope_bytes}"
            )
        key_value = _require_integer(
            row[3],
            "Greengage exact key value",
            INT64_MIN,
            INT64_MAX,
        )
        row_envelope = _ascii_envelope(row[4], "Greengage canonical row envelope")
        if len(row_envelope) > query.max_encoded_envelope_bytes:
            raise GreengageResultLimitError(
                "Greengage exact comparison row envelope exceeds the configured limit: "
                f"observed_bytes={len(row_envelope)}, "
                f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
            )
        try:
            row_values = decode_row_with_context(query.context, row_envelope)
        except CanonicalizationError as error:
            raise GreenplumDataValidationError(
                "Greengage exact comparison envelope failed reference decoding: "
                f"reason_type={type(error).__name__}"
            ) from None
        if len(row_values) != len(query.context.schema.fields):
            raise GreenplumDataValidationError(
                "Greengage exact comparison row envelope decoded to an unexpected field count"
            )
        row_key_value = row_values[key_field_index]
        if type(row_key_value) is not int:
            raise GreenplumDataValidationError(
                "Greengage exact comparison row key is not logical INT64"
            )
        if key_value != row_key_value:
            raise GreenplumDataValidationError(
                "Greengage exact key value and row envelope disagree"
            )
        try:
            key_envelope = encode_key_with_context(key_context, (key_value,))
        except CanonicalizationError as error:
            raise GreenplumDataValidationError(
                "Greengage exact comparison key failed canonical reconstruction: "
                f"reason_type={type(error).__name__}"
            ) from None
        request = ranges[ordinal]
        if key_value < request.lower_inclusive or (
            request.upper_exclusive is not None and key_value >= request.upper_exclusive
        ):
            raise GreenplumDataValidationError(
                "Greengage exact key falls outside its requested range"
            )
        if ordinal < previous_ordinal or (
            ordinal == previous_ordinal and previous_key is not None and key_value <= previous_key
        ):
            raise GreenplumDataValidationError(
                "Greengage exact rows are not strictly ordered by range and key"
            )
        previous_ordinal = ordinal
        previous_key = key_value
        parsed.append(
            PostgresIntegerExactRow(
                segment_id=segment_id,
                key_value=key_value,
                key_envelope=key_envelope,
                row_envelope=row_envelope,
                values=row_values,
            )
        )
    if parsed and false_witness_count != 0:
        raise GreenplumDataValidationError(
            "Greengage exact comparison mixed a false same-RTE witness with logical rows"
        )
    if not parsed and false_witness_count != 1:
        raise GreenplumDataValidationError(
            "Greengage empty exact comparison must return exactly one false same-RTE witness: "
            f"actual={false_witness_count}"
        )
    _require_deadline(deadline, "exact-row decoding")
    return tuple(parsed)


def _validate_manifest_contract(
    relation: GreengageProtectedRelationInspection,
    columns: ReadinessManifestColumns,
) -> None:
    if not isinstance(cast(object, columns), ReadinessManifestColumns):
        raise TypeError("Greengage readiness columns must be ReadinessManifestColumns")
    semantic_fields = tuple(field.name for field in relation.acquisition.schema.fields)
    if semantic_fields != _MANIFEST_FIELDS:
        raise GreenplumMetadataError(
            "Greengage relation manifest must use the fixed semantic field order: "
            f"expected={_MANIFEST_FIELDS!r}, actual={semantic_fields!r}"
        )
    if columns.values() != relation.acquisition.column_names:
        raise GreenplumMetadataError(
            "Greengage relation manifest mappings differ from the protected column closure"
        )
    bindings = {binding.column_name: binding for binding in relation.inspection.bindings}
    if len(bindings) != len(relation.inspection.bindings):
        raise GreenplumMetadataError(
            "Greengage protected manifest inspection contains duplicate column bindings"
        )
    allowed = (
        ("dataset_id", columns.dataset_id, frozenset((("text", 25), ("varchar", 1043)))),
        ("scope_digest", columns.scope_digest, frozenset((("text", 25), ("varchar", 1043)))),
        ("batch_id", columns.batch_id, frozenset((("text", 25), ("varchar", 1043)))),
        ("state", columns.state, frozenset((("text", 25), ("varchar", 1043)))),
        ("business_date", columns.business_date, frozenset((("date", 1082),))),
        ("source_cut", columns.source_cut, frozenset((("text", 25), ("varchar", 1043)))),
        (
            "dataset_version",
            columns.dataset_version,
            frozenset((("text", 25), ("varchar", 1043))),
        ),
        ("completed_at", columns.completed_at, frozenset((("timestamptz", 1184),))),
    )
    for field_name, column_name, accepted_types in allowed:
        binding = bindings.get(column_name)
        if binding is None:
            raise GreenplumMetadataError(
                "Greengage manifest column is outside the protected inspection: "
                f"field={field_name!r}, column={column_name!r}"
            )
        physical = binding.physical
        identity = (physical.base_type.type_name, physical.base_type.oid)
        if (
            physical.is_domain
            or physical.array_dimensions != 0
            or physical.base_type.schema_name != "pg_catalog"
            or identity not in accepted_types
        ):
            raise GreenplumMetadataError(
                "Greengage manifest column has an unsupported physical type: "
                f"field={field_name!r}, column={column_name!r}, "
                f"physical_type={physical.formatted_type!r}"
            )


def _manifest_statement(
    relation: GreengageProtectedRelationInspection,
    columns: ReadinessManifestColumns,
) -> str:
    table = ".".join(
        _quote_identifier(component) for component in relation.acquisition.relation.components
    )
    names = tuple(_quote_identifier(value) for value in columns.values())
    return (
        "SELECT (pg_catalog.pg_typeof((dfe_manifest.*)))::oid::bigint AS origin_type, "
        f"dfe_manifest.{names[0]} AS dataset_id, "
        f"dfe_manifest.{names[1]} AS scope_digest, "
        f"dfe_manifest.{names[2]} AS batch_id, "
        f"dfe_manifest.{names[3]} AS state, "
        f"dfe_manifest.{names[4]} AS business_date, "
        f"dfe_manifest.{names[5]} AS source_cut, "
        f"dfe_manifest.{names[6]} AS dataset_version, "
        f"dfe_manifest.{names[7]} AS completed_at "
        f"FROM ONLY {table} AS dfe_manifest "
        f"WHERE dfe_manifest.{names[0]} = %s AND dfe_manifest.{names[1]} = %s LIMIT 2"
    )


def _parse_manifest_record(
    row: DatabaseRow,
    query: GreengageEndpointQuery,
) -> PostgresRelationManifestRecord:
    if len(row) != 9:
        raise GreenplumDataValidationError(
            "Greengage relation manifest must return exactly nine fields"
        )
    _require_origin_oid(row[0], query, "relation manifest")
    business_date = row[5]
    if type(business_date) is not date:
        raise GreenplumDataValidationError(
            "Greengage manifest business_date must be a non-null date"
        )
    completed_at = row[8]
    if completed_at is not None and type(completed_at) is not datetime:
        raise GreenplumDataValidationError(
            "Greengage manifest completed_at must be NULL or timestamptz"
        )
    scope_digest = _require_text(row[2], "Greengage manifest scope_digest")
    if _SHA256_HEX.fullmatch(scope_digest) is None:
        raise GreenplumDataValidationError(
            "Greengage manifest scope_digest must be lowercase SHA-256 hex"
        )
    return PostgresRelationManifestRecord(
        dataset_id=_require_text(row[1], "Greengage manifest dataset_id"),
        scope_digest=scope_digest,
        batch_id=_require_text(row[3], "Greengage manifest batch_id"),
        state=_require_text(row[4], "Greengage manifest state"),
        business_date=business_date,
        source_cut=_require_optional_text(row[6], "Greengage manifest source_cut"),
        dataset_version=_require_optional_text(
            row[7],
            "Greengage manifest dataset_version",
        ),
        completed_at=completed_at,
    )


def _require_query_provenance(
    rows: tuple[DatabaseRow, ...],
    query: GreengageEndpointQuery,
    operation: str,
) -> None:
    for row in rows:
        if not row:
            raise GreenplumDataValidationError(
                f"Greengage {operation} returned a row without relation provenance"
            )
        _require_origin_oid(row[0], query, operation)


def _require_origin_oid(
    value: object,
    query: GreengageEndpointQuery,
    operation: str,
) -> None:
    actual = _require_integer(
        value,
        f"Greengage {operation} relation row type OID",
        1,
        (1 << 32) - 1,
    )
    if actual != query.relation_row_type_oid:
        raise GreenplumContextLostError(
            "Greengage query relation provenance was lost inside the protected snapshot: "
            f"operation={operation!r}, expected_row_type_oid="
            f"{query.relation_row_type_oid}, actual_row_type_oid={actual}"
        )


def _read_metrics(
    rows: tuple[DatabaseRow, ...],
    deadline: PostgresReadDeadline,
) -> PostgresReadMetrics:
    result_bytes = 0
    for row in rows:
        _require_deadline(deadline, "read metric calculation")
        result_bytes += _database_row_bytes(row)
    _require_deadline(deadline, "read metric calculation")
    return PostgresReadMetrics(fetched_records=len(rows), result_bytes=result_bytes)


def _exact_read_metrics(
    rows: tuple[PostgresIntegerExactRow, ...],
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
    deadline: PostgresReadDeadline,
) -> PostgresReadMetrics:
    if len(rows) > max_records:
        raise GreengageResultLimitError(
            "Greengage exact rows exceeded the declared logical result limits"
        )
    result_bytes = 0
    for index, row in enumerate(rows):
        if index % _CURSOR_FETCH_RECORDS == 0:
            _require_deadline(deadline, "exact-row logical metric calculation")
        record_bytes = (
            len(row.segment_id.encode("utf-8"))
            + len(row.key_envelope)
            + len(row.row_envelope)
            + _EXACT_STATUS_BYTES
        )
        if record_bytes > max_record_bytes:
            raise GreengageResultLimitError(
                "Greengage exact rows exceeded the declared logical result limits"
            )
        result_bytes += record_bytes
        if result_bytes > max_total_bytes:
            raise GreengageResultLimitError(
                "Greengage exact rows exceeded the declared logical total byte limit"
            )
    _require_deadline(deadline, "exact-row logical metric calculation")
    return PostgresReadMetrics(fetched_records=len(rows), result_bytes=result_bytes)


def _require_deadline(deadline: PostgresReadDeadline, operation: str) -> None:
    if not isinstance(cast(object, deadline), PostgresReadDeadline):
        raise TypeError("Greengage read deadline must be a PostgresReadDeadline")
    if time.monotonic_ns() >= deadline.deadline_nanoseconds:
        raise PostgresReadDeadlineExceededError(
            f"Greengage {operation} exceeded its immutable source deadline"
        )


def _require_full_scans(reserved: int, expected: int, operation: str) -> None:
    if type(reserved) is not int or reserved < 0:
        raise ValueError("Greengage full-scan reservation must be a non-negative integer")
    if reserved != expected:
        raise ValueError(
            f"Greengage {operation} full-scan reservation differs from the connector "
            f"contract: reserved={reserved}, expected={expected}"
        )


def _map_catalog_error(
    error: GreenplumCatalogDataError | GreenplumCatalogMetadataError,
) -> GreenplumDataValidationError | GreenplumMetadataError:
    if isinstance(error, GreenplumCatalogMetadataError):
        return GreenplumMetadataError(str(error))
    return GreenplumDataValidationError(str(error))


def _parse_unsigned_decimal(value: object, label: str, maximum: int) -> int:
    if type(value) is not str or not value or not value.isascii() or not value.isdecimal():
        raise GreenplumDataValidationError(f"{label} must be canonical unsigned decimal text")
    if len(value) > 1 and value.startswith("0"):
        raise GreenplumDataValidationError(f"{label} must not contain leading zeroes")
    parsed = int(value)
    if parsed > maximum:
        raise GreenplumDataValidationError(f"{label} exceeds its exact numeric bound")
    return parsed


def _parse_optional_int64(value: object, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not str or not value or not value.isascii():
        raise GreenplumDataValidationError(f"{label} must be signed decimal text or NULL")
    digits = value[1:] if value.startswith("-") else value
    if not digits.isdecimal() or (len(digits) > 1 and digits.startswith("0")):
        raise GreenplumDataValidationError(f"{label} must be canonical signed decimal text")
    parsed = int(value)
    if not -(1 << 63) <= parsed <= INT64_MAX:
        raise GreenplumDataValidationError(f"{label} is outside the signed-int64 range")
    return parsed


def _parse_content_ids(value: object, allow_empty: bool, label: str) -> tuple[int, ...]:
    text = _require_text_allow_empty(value, label)
    if not text:
        if allow_empty:
            return ()
        raise GreenplumMetadataError(f"{label} must not be empty")
    content_ids = tuple(
        _parse_unsigned_decimal(item, f"{label} item", INT64_MAX) for item in text.split(",")
    )
    if len(set(content_ids)) != len(content_ids):
        raise GreenplumMetadataError(f"{label} contains duplicate content IDs")
    return tuple(sorted(content_ids))


def _ascii_envelope(value: object, label: str) -> bytes:
    text = _require_text(value, label)
    try:
        return text.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise GreenplumDataValidationError(f"{label} contains non-ASCII bytes") from None


def _database_row_bytes(row: DatabaseRow) -> int:
    total = 0
    for value in row:
        if value is None:
            continue
        if type(value) is str:
            try:
                total += len(value.encode("utf-8", errors="strict"))
            except UnicodeEncodeError:
                raise GreenplumDataValidationError(
                    "Greengage returned text containing a surrogate code point"
                ) from None
        elif type(value) is bytes:
            total += len(value)
        elif type(value) is memoryview:
            total += value.nbytes
        elif type(value) is bool:
            total += 1
        elif type(value) is int:
            total += len(str(value).encode("ascii"))
        elif type(value) is datetime:
            total += len(value.isoformat(timespec="microseconds").encode("ascii"))
        elif type(value) is date:
            total += len(value.isoformat().encode("ascii"))
        else:
            raise GreenplumDataValidationError(
                "Greengage returned an unsupported result value type: "
                f"value_type={type(value).__name__}"
            )
    return total


def _validate_result_limits(
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
) -> None:
    for name, value in (
        ("max_records", max_records),
        ("max_record_bytes", max_record_bytes),
        ("max_total_bytes", max_total_bytes),
    ):
        if type(value) is not int or value < 1:
            raise ValueError(f"Greengage {name} must be a positive integer")
    if max_record_bytes > max_total_bytes:
        raise ValueError(
            "Greengage max_record_bytes must not exceed max_total_bytes: "
            f"record={max_record_bytes}, total={max_total_bytes}"
        )


def _require_text(value: object, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise GreenplumDataValidationError(f"{label} must be non-empty text without U+0000")
    return value


def _require_text_allow_empty(value: object, label: str) -> str:
    if type(value) is not str or "\x00" in value:
        raise GreenplumDataValidationError(f"{label} must be text without U+0000")
    return value


def _require_optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, label)


def _require_boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise GreenplumDataValidationError(f"{label} must be a boolean")
    return value


def _require_integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GreenplumDataValidationError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value
