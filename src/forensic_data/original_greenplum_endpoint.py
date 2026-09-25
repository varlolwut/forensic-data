import logging
import re
import time
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from threading import Lock
from types import TracebackType
from typing import LiteralString, Self, cast, final
from uuid import UUID, uuid4

import psycopg2
from psycopg2.extensions import connection as Psycopg2Connection

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
from forensic_data.greenplum import (
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
    UnsupportedGreenplumProfileError,
    _original_greenplum_driver_evidence,  # pyright: ignore[reportPrivateUsage]
    _probe_original_greenplum_profile,  # pyright: ignore[reportPrivateUsage]
    _probe_reader_identity,  # pyright: ignore[reportPrivateUsage]
    _probe_relation_locks,  # pyright: ignore[reportPrivateUsage]
    _probe_topology,  # pyright: ignore[reportPrivateUsage]
)
from forensic_data.greenplum_catalog import (
    ORIGINAL_GREENPLUM_HASH_CAPABILITY_QUERY,
    ORIGINAL_GREENPLUM_RELATION_QUERY,
    GreenplumCatalogDataError,
    GreenplumCatalogMetadataError,
    GreenplumColumnProbe,
    GreenplumReaderIdentity,
    GreenplumRelationRequest,
    GreenplumTopology,
    GreenplumTypeProbe,
    OriginalGreenplumHashCapability,
    OriginalGreenplumRelationCatalog,
    greenplum_type_catalog_query,
    parse_greenplum_type_probe,
    parse_original_greenplum_hash_capability,
    parse_original_greenplum_relation_catalog,
)
from forensic_data.greenplum_profile import GreenplumRuntimeProfile
from forensic_data.greenplum_sql import parse_original_greenplum_fingerprint_plan
from forensic_data.original_greenplum_endpoint_sql import (
    OriginalGreenplumEndpointParameter,
    OriginalGreenplumEndpointQuery,
    OriginalGreenplumRangeFingerprintQuery,
    build_original_greenplum_integer_key_summary_query,
    build_original_greenplum_integer_range_fingerprint_query,
    build_original_greenplum_integer_range_rows_query,
    explain_original_greenplum_endpoint_query,
)
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
    PostgresSourceQueryCharge,
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
_CURSOR_FETCH_RECORDS = 64
_RAW_RESULT_OVERHEAD_BYTES = 32_768
_MAX_METADATA_RECORD_BYTES = 256 * 1_024
_MAX_METADATA_TOTAL_BYTES = 8 * 1024 * 1024
_MAX_EXPLAIN_ROWS = 50_000
_MAX_EXPLAIN_RECORD_BYTES = 256 * 1_024
_MAX_EXPLAIN_TOTAL_BYTES = 8 * 1024 * 1024
_EXPLAIN_ROW_MEMORY_BYTES = 512
_MAX_EXPLAIN_COORDINATOR_BYTES = _MAX_EXPLAIN_TOTAL_BYTES + (
    _MAX_EXPLAIN_ROWS * _EXPLAIN_ROW_MEMORY_BYTES
)
_SESSION_INVARIANT_RECORD_BYTES = 256
_MAX_ROW_TYPE_OID_BYTES = 10
_HAS_DATA_BYTES = 1
_EXACT_STATUS_BYTES = 2
_EMPTY_EXACT_WITNESS_NULL_BYTES = 5
_SHA256_ABC_HEX = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
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


class OriginalGreenplumAcquisitionRaceError(GreenplumMetadataError):
    """A relation changed between discovery and protected acquisition."""


class OriginalGreenplumBudgetExceededError(GreenplumConnectorError):
    """A bounded original Greenplum read exceeded its immutable result budget."""


class OriginalGreenplumResultLimitError(OriginalGreenplumBudgetExceededError):
    """An original Greenplum result exceeded a declared record or byte limit."""


_ORIGINAL_GREENPLUM_RUNTIME_FAILURES = (
    GreenplumConnectionError,
    GreenplumQueryError,
    GreenplumContextLostError,
    GreenplumDataValidationError,
    GreenplumMetadataError,
    UnsupportedGreenplumProfileError,
    OriginalGreenplumBudgetExceededError,
    PostgresDataValidationError,
    PostgresReadDeadlineExceededError,
    PostgresSourceBudgetExceededError,
)


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumRelation:
    components: tuple[str, str]

    def __post_init__(self) -> None:
        if type(self.components) is not tuple or len(self.components) != 2:
            raise ValueError(
                "original Greenplum relation must contain schema and relation components"
            )
        for index, component in enumerate(self.components):
            if type(component) is not str or not component or "\x00" in component:
                raise ValueError(
                    "original Greenplum relation component must be non-empty text "
                    f"without U+0000: index={index}"
                )


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumRelationAcquisition:
    schema: CanonicalSchema
    relation: OriginalGreenplumRelation
    relation_scope: RelationScope
    column_names: tuple[str, ...]
    max_metadata_record_bytes: int
    max_metadata_total_bytes: int

    def __post_init__(self) -> None:
        if type(self.schema) is not CanonicalSchema:
            raise TypeError("original Greenplum acquisition schema must be CanonicalSchema")
        if type(self.relation) is not OriginalGreenplumRelation:
            raise TypeError("original Greenplum acquisition relation has an unexpected type")
        if self.relation_scope is not RelationScope.PHYSICAL_ONLY:
            raise ValueError("original Greenplum endpoint supports physical_only acquisition")
        if type(self.column_names) is not tuple:
            raise TypeError("original Greenplum acquisition columns must be an immutable tuple")
        if len(self.column_names) != len(self.schema.fields):
            raise ValueError(
                "original Greenplum acquisition requires one column per canonical field"
            )
        if len(set(self.column_names)) != len(self.column_names):
            raise ValueError("original Greenplum acquisition columns must be unique")
        for index, column_name in enumerate(self.column_names):
            if type(column_name) is not str or not column_name or "\x00" in column_name:
                raise ValueError(
                    "original Greenplum column name must be non-empty text without U+0000: "
                    f"index={index}"
                )
        _validate_result_limits(
            len(self.column_names) or 1,
            self.max_metadata_record_bytes,
            self.max_metadata_total_bytes,
        )


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumProtectedRelationInspection:
    acquisition: OriginalGreenplumRelationAcquisition
    inspection: PostgresInspectedRelation
    catalog: OriginalGreenplumRelationCatalog
    lock_mode: str
    acquired_before_snapshot: bool

    def __post_init__(self) -> None:
        if type(self.acquisition) is not OriginalGreenplumRelationAcquisition:
            raise TypeError("original Greenplum protected acquisition has an unexpected type")
        if not isinstance(cast(object, self.inspection), PostgresInspectedRelation):
            raise TypeError("original Greenplum protected inspection has an unexpected type")
        if not isinstance(cast(object, self.catalog), OriginalGreenplumRelationCatalog):
            raise TypeError("original Greenplum protected catalog has an unexpected type")
        if self.inspection.relation.components != self.acquisition.relation.components:
            raise ValueError("original Greenplum protected relation differs from acquisition")
        if self.inspection.relation_oid != self.catalog.relation_oid:
            raise ValueError("original Greenplum protected relation OID is inconsistent")
        if self.inspection.relation_row_type_oid != self.catalog.relation_row_type_oid:
            raise ValueError("original Greenplum protected row type OID is inconsistent")
        if self.lock_mode != "access_share" or self.acquired_before_snapshot is not True:
            raise ValueError(
                "original Greenplum relation requires a pre-snapshot access_share lock"
            )
        validate_postgres_inspection(self.acquisition.schema, self.inspection)

    def physical_scan_count(self) -> int:
        return 1


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumProtectedReadContextEvidence:
    context_id: UUID
    runtime_profile: GreenplumRuntimeProfile
    strategy: str
    snapshot_locator: str
    started_at: datetime
    backend_process_id: int
    allowed_concurrency: int
    relation_locks: tuple[GreenplumRelationLockEvidence, ...]
    acquired_before_snapshot: bool
    limitations: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumFingerprintPlanReservation:
    additional_queries: int
    max_fetched_records: int
    max_result_bytes: int
    max_coordinator_bytes: int


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumFingerprintResultReservation:
    additional_record_bytes: int
    additional_result_bytes: int
    additional_fields_per_record: int
    additional_ascii_values: int


@dataclass(frozen=True, slots=True)
class _OriginalGreenplumCandidate:
    acquisition: OriginalGreenplumRelationAcquisition
    request: GreenplumRelationRequest
    relation: OriginalGreenplumRelationCatalog
    types: GreenplumTypeProbe


class _OriginalGreenplumEndpointSession:
    def __init__(
        self,
        connection: Psycopg2Connection,
        source_budget: PostgresSourceBudgetAttempt,
        direction: PostgresSourceDirection,
        statement_timeout_milliseconds: int,
    ) -> None:
        if type(statement_timeout_milliseconds) is not int or statement_timeout_milliseconds < 1:
            raise ValueError("original Greenplum statement timeout must be positive")
        self.connection = connection
        self.source_budget = source_budget
        self.direction = direction
        self.statement_timeout_milliseconds = statement_timeout_milliseconds
        self.closed = False

    def begin_read_only(self, statement_timeout_milliseconds: int) -> None:
        if type(statement_timeout_milliseconds) is not int or statement_timeout_milliseconds < 1:
            raise ValueError("original Greenplum statement timeout must be positive")
        self.command(
            "BEGIN READ ONLY; SET LOCAL search_path TO pg_catalog; "
            "SET LOCAL TimeZone TO 'UTC'; SET LOCAL DateStyle TO 'ISO, YMD'; "
            f"SET LOCAL statement_timeout TO '{statement_timeout_milliseconds}ms'",
            (),
            "original_greenplum_begin_read_only",
        )

    def begin_serializable_read_only(self) -> None:
        if not self.connection.autocommit:
            raise GreenplumContextLostError(
                "original Greenplum protected transaction must begin from autocommit mode"
            )
        self.connection.autocommit = False
        self.command(
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY",
            (),
            "original_greenplum_begin_protected_snapshot",
        )

    def prepare_acquisition_statement(self) -> None:
        timeout_milliseconds = min(
            self.statement_timeout_milliseconds,
            self.source_budget.effective_statement_timeout_milliseconds(),
        )
        self.command(
            f"SET statement_timeout TO {timeout_milliseconds}",
            (),
            "original_greenplum_configure_acquisition_statement_timeout",
        )

    def command(
        self,
        statement: str,
        parameters: tuple[OriginalGreenplumEndpointParameter, ...],
        operation: str,
    ) -> None:
        charge = self.source_budget.dispatch_query(self.direction, 0)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(cast(LiteralString, statement), parameters)
                if cursor.description is not None:
                    rows = tuple(cast(DatabaseRow, row) for row in cursor.fetchall())
                    charge.consume_records(tuple(_database_row_bytes(row) for row in rows))
        except psycopg2.Error as error:
            raise GreenplumQueryError(operation, error.pgcode, type(error).__name__) from None

    def fetch_rows(
        self,
        statement: str,
        parameters: tuple[OriginalGreenplumEndpointParameter, ...],
        max_rows: int,
        operation: str,
    ) -> tuple[DatabaseRow, ...]:
        return self.fetch_client_rows(
            statement,
            parameters,
            max_rows,
            _MAX_METADATA_RECORD_BYTES,
            _MAX_METADATA_TOTAL_BYTES,
            0,
            operation,
        )

    def fetch_bounded_rows(
        self,
        statement: str,
        parameters: tuple[OriginalGreenplumEndpointParameter, ...],
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
        cursor_name = f"dfe_original_gp_{uuid4().hex}"
        try:
            with self.connection.cursor(name=cursor_name) as cursor:
                cursor.itersize = _CURSOR_FETCH_RECORDS
                cursor.execute(cast(LiteralString, statement), parameters)
                while True:
                    charge.require_fetch_deadline()
                    remaining = max_records + 1 - len(records)
                    batch = tuple(
                        cast(DatabaseRow, row)
                        for row in cursor.fetchmany(min(_CURSOR_FETCH_RECORDS, remaining))
                    )
                    if not batch:
                        break
                    total_bytes = _consume_batch(
                        charge,
                        records,
                        batch,
                        total_bytes,
                        max_records,
                        max_record_bytes,
                        max_total_bytes,
                        operation,
                    )
        except psycopg2.Error as error:
            raise GreenplumQueryError(operation, error.pgcode, type(error).__name__) from None
        return tuple(records)

    def fetch_client_rows(
        self,
        statement: str,
        parameters: tuple[OriginalGreenplumEndpointParameter, ...],
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
                        "original Greenplum bounded query returned no row description: "
                        f"operation={operation!r}"
                    )
                while True:
                    charge.require_fetch_deadline()
                    remaining = max_records + 1 - len(records)
                    batch = tuple(
                        cast(DatabaseRow, row)
                        for row in cursor.fetchmany(min(_CURSOR_FETCH_RECORDS, remaining))
                    )
                    if not batch:
                        break
                    total_bytes = _consume_batch(
                        charge,
                        records,
                        batch,
                        total_bytes,
                        max_records,
                        max_record_bytes,
                        max_total_bytes,
                        operation,
                    )
        except psycopg2.Error as error:
            raise GreenplumQueryError(operation, error.pgcode, type(error).__name__) from None
        return tuple(records)

    def close(self, primary_error: BaseException | None) -> None:
        if self.closed:
            return
        self.closed = True
        cleanup_error: psycopg2.Error | None = None
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("ROLLBACK")
        except psycopg2.Error as error:
            cleanup_error = error
        self.connection.close()
        if cleanup_error is None or primary_error is not None:
            return
        raise GreenplumCloseError(
            "original Greenplum protected endpoint cleanup failed: "
            f"sqlstate={cleanup_error.pgcode!r}, "
            f"error_category={type(cleanup_error).__name__!r}"
        ) from None


class OriginalGreenplumProtectedReadContext:
    """One sealed original Greenplum read-only Serializable endpoint snapshot."""

    def __init__(
        self,
        session: _OriginalGreenplumEndpointSession,
        driver: GreenplumDriverEvidence,
        server: GreenplumServerProfile,
        reader: GreenplumReaderIdentity,
        topology: GreenplumTopology,
        hash_capability: OriginalGreenplumHashCapability,
        protected_relations: tuple[OriginalGreenplumProtectedRelationInspection, ...],
        evidence: OriginalGreenplumProtectedReadContextEvidence,
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
    def hash_capability(self) -> OriginalGreenplumHashCapability:
        return self._hash_capability

    @property
    def protected_relations(
        self,
    ) -> tuple[OriginalGreenplumProtectedRelationInspection, ...]:
        return self._protected_relations

    @property
    def evidence(self) -> OriginalGreenplumProtectedReadContextEvidence:
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
    def session_invariant_record_bytes(self) -> int:
        return _SESSION_INVARIANT_RECORD_BYTES

    @property
    def empty_exact_witness_null_bytes(self) -> int:
        return _EMPTY_EXACT_WITNESS_NULL_BYTES

    def fingerprint_plan_reservation(
        self,
        range_count: int,
        base_invariant_record_bytes: int,
    ) -> OriginalGreenplumFingerprintPlanReservation:
        if type(range_count) is not int or range_count < 1:
            raise ValueError("original Greenplum fingerprint range count must be positive")
        if type(base_invariant_record_bytes) is not int or base_invariant_record_bytes < 1:
            raise ValueError("original Greenplum base invariant record bytes must be positive")
        return OriginalGreenplumFingerprintPlanReservation(
            additional_queries=(4 * range_count) - 2,
            max_fetched_records=(range_count * (_MAX_EXPLAIN_ROWS + 2)) - 1,
            max_result_bytes=(
                range_count * (_MAX_EXPLAIN_TOTAL_BYTES + (2 * _SESSION_INVARIANT_RECORD_BYTES))
            )
            - base_invariant_record_bytes,
            max_coordinator_bytes=_MAX_EXPLAIN_COORDINATOR_BYTES,
        )

    def fingerprint_result_reservation(
        self,
        range_count: int,
    ) -> OriginalGreenplumFingerprintResultReservation:
        if type(range_count) is not int or range_count < 1:
            raise ValueError("original Greenplum fingerprint range count must be positive")
        topology_bytes = len(
            ",".join(str(value) for value in self._topology.primary_content_ids).encode("ascii")
        )
        additional_record_bytes = 2 * topology_bytes
        return OriginalGreenplumFingerprintResultReservation(
            additional_record_bytes=additional_record_bytes,
            additional_result_bytes=range_count * additional_record_bytes,
            additional_fields_per_record=2,
            additional_ascii_values=2 * range_count,
        )

    def read_integer_key_summary(
        self,
        protected_relation: OriginalGreenplumProtectedRelationInspection,
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
            "original_greenplum_integer_key_summary",
        )
        try:
            if len(rows) != 1:
                raise GreenplumDataValidationError(
                    "original Greenplum integer-key summary must return exactly one row"
                )
            return PostgresIntegerKeySummaryRead(
                summary=_parse_key_summary(rows[0], query),
                metrics=_read_metrics(rows, deadline),
            )
        except _ORIGINAL_GREENPLUM_RUNTIME_FAILURES as error:
            self._retire(error)
            raise

    def read_integer_range_fingerprints(
        self,
        protected_relation: OriginalGreenplumProtectedRelationInspection,
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
        _require_full_scans(full_scans, len(ranges), "integer-range fingerprint")
        queries = tuple(
            _range_fingerprint_query(
                protected_relation,
                self._topology,
                key_field_index,
                scope,
                requested_range,
                max_encoded_envelope_bytes,
            )
            for requested_range in ranges
        )
        result_reservation = self.fingerprint_result_reservation(len(ranges))
        rows: list[DatabaseRow] = []
        with self._query_lock:
            self._require_active()
            try:
                for query in queries:
                    self._restore_invariants(deadline)
                    plan_rows = self._session.fetch_client_rows(
                        explain_original_greenplum_endpoint_query(query.statement),
                        query.parameters,
                        _MAX_EXPLAIN_ROWS,
                        _MAX_EXPLAIN_RECORD_BYTES,
                        _MAX_EXPLAIN_TOTAL_BYTES,
                        0,
                        "original_greenplum_integer_range_fingerprint_plan",
                    )
                    parse_original_greenplum_fingerprint_plan(
                        plan_rows,
                        query.plan_request,
                        len(self._topology.primary_content_ids),
                        self._hash_capability.function_oid,
                        protected_relation.catalog.storage_kind,
                    )
                    del plan_rows
                    self._restore_invariants(deadline)
                    result_rows = self._session.fetch_bounded_rows(
                        query.statement,
                        query.parameters,
                        1,
                        max_record_bytes
                        + _MAX_ROW_TYPE_OID_BYTES
                        + result_reservation.additional_record_bytes,
                        max_total_bytes
                        + _MAX_ROW_TYPE_OID_BYTES
                        + result_reservation.additional_result_bytes,
                        1,
                        "original_greenplum_integer_range_fingerprint",
                    )
                    _require_query_provenance(
                        result_rows,
                        query,
                        "original_greenplum_integer_range_fingerprint",
                    )
                    if len(result_rows) != 1:
                        raise GreenplumDataValidationError(
                            "original Greenplum range fingerprint must return one row"
                        )
                    rows.extend(result_rows)
            except (GreenplumCatalogDataError, GreenplumCatalogMetadataError) as error:
                mapped = _map_catalog_error(error)
                self._lose(mapped)
                raise mapped from None
            except _ORIGINAL_GREENPLUM_RUNTIME_FAILURES as error:
                self._lose(error)
                raise
        try:
            parsed = tuple(
                _parse_range_fingerprint(row, query, deadline)
                for row, query in zip(rows, queries, strict=True)
            )
            return PostgresRangeFingerprintRead(
                ranges=parsed,
                metrics=_read_metrics(tuple(rows), deadline),
            )
        except _ORIGINAL_GREENPLUM_RUNTIME_FAILURES as error:
            self._retire(error)
            raise

    def read_integer_range_rows(
        self,
        protected_relation: OriginalGreenplumProtectedRelationInspection,
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
            max_record_bytes
            + _MAX_ROW_TYPE_OID_BYTES
            + _HAS_DATA_BYTES
            + _EMPTY_EXACT_WITNESS_NULL_BYTES,
            max_total_bytes
            + (max_records * (_MAX_ROW_TYPE_OID_BYTES + _HAS_DATA_BYTES))
            + _EMPTY_EXACT_WITNESS_NULL_BYTES,
            full_scans,
            deadline,
            "original_greenplum_integer_range_rows",
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
        except _ORIGINAL_GREENPLUM_RUNTIME_FAILURES as error:
            self._retire(error)
            raise

    def read_relation_manifest(
        self,
        protected_relation: OriginalGreenplumProtectedRelationInspection,
        columns: ReadinessManifestColumns,
        dataset_id: str,
        scope_digest: str,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[PostgresRelationManifestRecord, ...]:
        self._require_relation(protected_relation)
        _validate_manifest_contract(protected_relation, columns)
        if type(dataset_id) is not str or not dataset_id or "\x00" in dataset_id:
            raise ValueError("original Greenplum manifest dataset_id must be non-empty text")
        if type(scope_digest) is not str or _SHA256_HEX.fullmatch(scope_digest) is None:
            raise ValueError(
                "original Greenplum manifest scope_digest must be lowercase SHA-256 hex"
            )
        _validate_result_limits(2, max_record_bytes, max_total_bytes)
        query = OriginalGreenplumEndpointQuery(
            statement=_manifest_statement(protected_relation, columns),
            parameters=(dataset_id, scope_digest),
            context=prepare_envelope_context(protected_relation.acquisition.schema),
            relation_row_type_oid=protected_relation.inspection.relation_row_type_oid,
            max_encoded_envelope_bytes=max_record_bytes,
        )
        try:
            deadline = self.source_budget.read_deadline(
                self.source_budget.effective_statement_timeout_milliseconds()
            )
        except PostgresReadDeadlineExceededError as error:
            self._retire(error)
            raise
        rows = self._execute_read(
            query,
            2,
            max_record_bytes + _MAX_ROW_TYPE_OID_BYTES,
            max_total_bytes + (2 * _MAX_ROW_TYPE_OID_BYTES),
            0,
            deadline,
            "original_greenplum_relation_manifest",
        )
        try:
            return tuple(_parse_manifest_record(row, query) for row in rows)
        except _ORIGINAL_GREENPLUM_RUNTIME_FAILURES as error:
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
        query: OriginalGreenplumEndpointQuery,
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
                rows = self._session.fetch_bounded_rows(
                    query.statement,
                    query.parameters,
                    max_records,
                    max_record_bytes,
                    max_total_bytes,
                    full_scans,
                    operation,
                )
                _require_query_provenance(rows, query, operation)
            except _ORIGINAL_GREENPLUM_RUNTIME_FAILURES as error:
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
            "pg_catalog.current_setting('TimeZone'), "
            "pg_catalog.txid_current_snapshot()::text, pg_catalog.pg_backend_pid()",
            (str(timeout_milliseconds),),
            1,
            _SESSION_INVARIANT_RECORD_BYTES,
            _SESSION_INVARIANT_RECORD_BYTES,
            0,
            "original_greenplum_restore_endpoint_invariants",
        )
        if len(rows) != 1 or len(rows[0]) != 6:
            raise GreenplumDataValidationError(
                "original Greenplum endpoint invariant probe returned an unexpected shape"
            )
        actual = tuple(
            _require_text(value, "original Greenplum endpoint setting") for value in rows[0][1:4]
        )
        expected = ("serializable", "on", "UTC")
        snapshot = _require_text(rows[0][4], "original Greenplum snapshot locator")
        backend_process_id = _require_integer(
            rows[0][5],
            "original Greenplum backend process ID",
            1,
            INT64_MAX,
        )
        if (
            actual != expected
            or snapshot != self._evidence.snapshot_locator
            or backend_process_id != self._evidence.backend_process_id
        ):
            raise GreenplumContextLostError(
                "original Greenplum endpoint invariants changed inside the protected snapshot: "
                f"settings={actual!r}, snapshot_matches="
                f"{snapshot == self._evidence.snapshot_locator}, backend_matches="
                f"{backend_process_id == self._evidence.backend_process_id}"
            )

    def _require_relation(
        self,
        protected_relation: OriginalGreenplumProtectedRelationInspection,
    ) -> None:
        self._require_active()
        if not any(candidate is protected_relation for candidate in self._protected_relations):
            raise GreenplumMetadataError(
                "original Greenplum relation does not belong to the protected set"
            )
        if protected_relation.inspection.context_id != self._evidence.context_id:
            raise GreenplumMetadataError(
                "original Greenplum relation belongs to a different read context"
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
                "original Greenplum protected endpoint context is already closed"
            )
        if self._state is ReadContextState.LOST:
            raise GreenplumContextLostError(
                "original Greenplum protected endpoint snapshot was lost"
            )


def open_original_greenplum_protected_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    acquisitions: tuple[OriginalGreenplumRelationAcquisition, ...],
    lock_timeout_milliseconds: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> OriginalGreenplumProtectedReadContext:
    ordered = _validate_acquisitions(acquisitions)
    _validate_lock_timeout(lock_timeout_milliseconds, settings.statement_timeout_milliseconds)
    if direction is not PostgresSourceDirection.REFERENCE:
        raise ValueError("original Greenplum endpoint is source-only")
    last_error: BaseException | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        try:
            connection = _connect_once(settings, source_budget)
            session = _OriginalGreenplumEndpointSession(
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
        except (OriginalGreenplumAcquisitionRaceError, GreenplumConnectionError) as error:
            last_error = error
            LOGGER.warning(
                "Original Greenplum protected endpoint acquisition attempt failed",
                extra={
                    "operation": "open_original_greenplum_protected_read_context",
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
        raise AssertionError("original Greenplum acquisition loop ended without an attempt")
    raise last_error


def _open_once(
    session: _OriginalGreenplumEndpointSession,
    settings: PostgresConnectionSettings,
    acquisitions: tuple[OriginalGreenplumRelationAcquisition, ...],
    lock_timeout_milliseconds: int,
) -> OriginalGreenplumProtectedReadContext:
    succeeded = False
    try:
        session.begin_read_only(
            min(
                settings.statement_timeout_milliseconds,
                session.source_budget.effective_statement_timeout_milliseconds(),
            )
        )
        session.prepare_acquisition_statement()
        discovery_server = _probe_original_greenplum_profile(session, settings)
        candidates = tuple(
            _discover_candidate(session, acquisition, discovery_server)
            for acquisition in acquisitions
        )
        session.command(
            "COMMIT",
            (),
            "original_greenplum_commit_discovery_snapshot",
        )
        started_at = datetime.now(UTC)
        session.begin_serializable_read_only()
        session.prepare_acquisition_statement()
        effective_lock_timeout_milliseconds = min(
            lock_timeout_milliseconds,
            session.source_budget.effective_statement_timeout_milliseconds(),
        )
        session.command(
            "SET LOCAL search_path TO pg_catalog; SET LOCAL TimeZone TO 'UTC'; "
            "SET LOCAL DateStyle TO 'ISO, YMD'; "
            "SET LOCAL statement_timeout TO "
            f"'{effective_lock_timeout_milliseconds}ms'",
            (),
            "original_greenplum_configure_protected_snapshot",
        )
        session.command(
            _lock_statement(acquisitions),
            (),
            "original_greenplum_lock_protected_relations",
        )
        session.prepare_acquisition_statement()
        server = _probe_original_greenplum_profile(session, settings)
        _require_protected_server(server)
        session.prepare_acquisition_statement()
        topology = _probe_topology(session)
        session.prepare_acquisition_statement()
        reader = _probe_reader_identity(session, settings)
        hash_capability = _probe_hash_capability(session)
        context_id = uuid4()
        sealed = tuple(
            _seal_candidate(session, candidate, context_id, server) for candidate in candidates
        )
        session.prepare_acquisition_statement()
        relation_locks = _probe_relation_locks(
            session,
            tuple(relation.catalog for relation in sealed),
            "original_greenplum_endpoint_relation_locks",
        )
        evidence = OriginalGreenplumProtectedReadContextEvidence(
            context_id=context_id,
            runtime_profile=GreenplumRuntimeProfile.ORIGINAL_GREENPLUM,
            strategy="protected_read_only_serializable_distributed",
            snapshot_locator=server.snapshot_locator,
            started_at=started_at,
            backend_process_id=server.backend_process_id,
            allowed_concurrency=1,
            relation_locks=relation_locks,
            acquired_before_snapshot=True,
            limitations=(
                "physical_only",
                "single_coordinator_session",
                "one_legacy_distributed_fingerprint_query_per_range",
            ),
        )
        context = OriginalGreenplumProtectedReadContext(
            session,
            _original_greenplum_driver_evidence(),
            server,
            reader,
            topology,
            hash_capability,
            sealed,
            evidence,
        )
        succeeded = True
        return context
    except OriginalGreenplumAcquisitionRaceError as error:
        session.close(error)
        raise
    except (GreenplumCatalogMetadataError, PostgresLoweringError) as error:
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
) -> Psycopg2Connection:
    try:
        connection = psycopg2.connect(
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
        )
        connection.autocommit = True
        return connection
    except psycopg2.Error as error:
        raise GreenplumConnectionError(
            "original Greenplum protected endpoint connection failed: "
            f"host={settings.host!r}, port={settings.port}, dbname={settings.dbname!r}, "
            f"user={settings.user!r}, sslmode={settings.sslmode.value!r}, "
            f"sqlstate={error.pgcode!r}, error_category={type(error).__name__!r}"
        ) from None


def _discover_candidate(
    session: _OriginalGreenplumEndpointSession,
    acquisition: OriginalGreenplumRelationAcquisition,
    server: GreenplumServerProfile,
) -> _OriginalGreenplumCandidate:
    _validate_identifier_lengths(acquisition, server.max_identifier_utf8_bytes)
    request = _relation_request(acquisition)
    session.prepare_acquisition_statement()
    relation_rows = session.fetch_client_rows(
        ORIGINAL_GREENPLUM_RELATION_QUERY,
        acquisition.relation.components,
        1,
        acquisition.max_metadata_record_bytes,
        acquisition.max_metadata_total_bytes,
        0,
        "original_greenplum_endpoint_candidate_relation",
    )
    relation = parse_original_greenplum_relation_catalog(relation_rows, request)
    type_statement, type_parameters = greenplum_type_catalog_query(
        relation.relation_oid,
        request,
    )
    session.prepare_acquisition_statement()
    type_rows = session.fetch_client_rows(
        type_statement,
        cast(tuple[OriginalGreenplumEndpointParameter, ...], type_parameters),
        len(request.columns),
        acquisition.max_metadata_record_bytes,
        acquisition.max_metadata_total_bytes,
        0,
        "original_greenplum_endpoint_candidate_types",
    )
    return _OriginalGreenplumCandidate(
        acquisition=acquisition,
        request=request,
        relation=relation,
        types=parse_greenplum_type_probe(type_rows, request),
    )


def _seal_candidate(
    session: _OriginalGreenplumEndpointSession,
    candidate: _OriginalGreenplumCandidate,
    context_id: UUID,
    server: GreenplumServerProfile,
) -> OriginalGreenplumProtectedRelationInspection:
    acquisition = candidate.acquisition
    try:
        session.prepare_acquisition_statement()
        relation_rows = session.fetch_client_rows(
            ORIGINAL_GREENPLUM_RELATION_QUERY,
            acquisition.relation.components,
            1,
            acquisition.max_metadata_record_bytes,
            acquisition.max_metadata_total_bytes,
            0,
            "original_greenplum_endpoint_protected_relation",
        )
        relation = parse_original_greenplum_relation_catalog(relation_rows, candidate.request)
        type_statement, type_parameters = greenplum_type_catalog_query(
            relation.relation_oid,
            candidate.request,
        )
        session.prepare_acquisition_statement()
        type_rows = session.fetch_client_rows(
            type_statement,
            cast(tuple[OriginalGreenplumEndpointParameter, ...], type_parameters),
            len(candidate.request.columns),
            acquisition.max_metadata_record_bytes,
            acquisition.max_metadata_total_bytes,
            0,
            "original_greenplum_endpoint_protected_types",
        )
        types = parse_greenplum_type_probe(type_rows, candidate.request)
    except (
        GreenplumCatalogDataError,
        GreenplumCatalogMetadataError,
        GreenplumMetadataError,
    ) as error:
        raise OriginalGreenplumAcquisitionRaceError(
            "original Greenplum metadata stopped matching its discovered shape: "
            f"relation={acquisition.relation.components!r}, "
            f"reason_type={type(error).__name__}"
        ) from None
    if relation != candidate.relation or types != candidate.types:
        raise OriginalGreenplumAcquisitionRaceError(
            "original Greenplum relation identity or type metadata changed between "
            f"discovery and protected acquisition: relation={acquisition.relation.components!r}"
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
        return OriginalGreenplumProtectedRelationInspection(
            acquisition=acquisition,
            inspection=inspection,
            catalog=relation,
            lock_mode="access_share",
            acquired_before_snapshot=True,
        )
    except PostgresLoweringError as error:
        raise GreenplumMetadataError(
            "original Greenplum relation cannot satisfy the canonical schema: "
            f"relation={acquisition.relation.components!r}, detail={str(error)!r}"
        ) from None


def _validate_acquisitions(
    acquisitions: object,
) -> tuple[OriginalGreenplumRelationAcquisition, ...]:
    if type(acquisitions) is not tuple or not acquisitions:
        raise ValueError("original Greenplum acquisitions must be a non-empty immutable tuple")
    typed = cast(tuple[object, ...], acquisitions)
    for index, acquisition in enumerate(typed):
        if not isinstance(acquisition, OriginalGreenplumRelationAcquisition):
            raise TypeError(
                "original Greenplum acquisitions contain an unexpected value: "
                f"index={index}, type={type(acquisition).__name__}"
            )
    ordered = tuple(
        sorted(
            cast(tuple[OriginalGreenplumRelationAcquisition, ...], typed),
            key=lambda acquisition: acquisition.relation.components,
        )
    )
    identities = tuple(acquisition.relation.components for acquisition in ordered)
    if len(set(identities)) != len(identities):
        raise ValueError("original Greenplum acquisitions must identify distinct relations")
    return ordered


def _validate_lock_timeout(
    lock_timeout_milliseconds: object,
    statement_timeout_milliseconds: int,
) -> None:
    if type(lock_timeout_milliseconds) is not int or lock_timeout_milliseconds < 1:
        raise ValueError("original Greenplum lock timeout must be positive")
    if lock_timeout_milliseconds >= statement_timeout_milliseconds:
        raise ValueError(
            "original Greenplum lock timeout must be less than statement timeout: "
            f"lock={lock_timeout_milliseconds}, statement={statement_timeout_milliseconds}"
        )


def _lock_statement(
    acquisitions: tuple[OriginalGreenplumRelationAcquisition, ...],
) -> str:
    relations = ", ".join(
        ".".join(_quote_identifier(component) for component in acquisition.relation.components)
        for acquisition in acquisitions
    )
    return f"LOCK TABLE {relations} IN ACCESS SHARE MODE"


def _relation_request(
    acquisition: OriginalGreenplumRelationAcquisition,
) -> GreenplumRelationRequest:
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


def _validate_identifier_lengths(
    acquisition: OriginalGreenplumRelationAcquisition,
    maximum_bytes: int,
) -> None:
    identifiers = (*acquisition.relation.components, *acquisition.column_names)
    oversized = tuple(value for value in identifiers if len(value.encode("utf-8")) > maximum_bytes)
    if oversized:
        raise GreenplumMetadataError(
            "original Greenplum acquisition identifier exceeds the observed limit: "
            f"maximum_bytes={maximum_bytes}, observed_count={len(oversized)}"
        )


def _require_protected_server(server: GreenplumServerProfile) -> None:
    if (
        server.runtime_profile is not GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
        or server.transaction_isolation != "serializable"
        or server.transaction_read_only is not True
    ):
        raise UnsupportedGreenplumProfileError(
            "original Greenplum protected endpoint requires native read-only Serializable: "
            f"runtime_profile={server.runtime_profile.value!r}, "
            f"transaction_isolation={server.transaction_isolation!r}, "
            f"transaction_read_only={server.transaction_read_only}"
        )


def _probe_hash_capability(
    session: _OriginalGreenplumEndpointSession,
) -> OriginalGreenplumHashCapability:
    session.prepare_acquisition_statement()
    rows = session.fetch_rows(
        ORIGINAL_GREENPLUM_HASH_CAPABILITY_QUERY,
        (),
        2,
        "original_greenplum_endpoint_hash_capability",
    )
    capability = parse_original_greenplum_hash_capability(rows)
    session.prepare_acquisition_statement()
    digest_rows = session.fetch_rows(
        "SELECT candidate.value = pg_catalog.decode(%s, 'hex'), "
        "pg_catalog.octet_length(candidate.value)::integer FROM ("
        "SELECT dfe_ext.digest(pg_catalog.convert_to('abc', 'UTF8'), 'sha256'::text) "
        "AS value) AS candidate",
        (_SHA256_ABC_HEX,),
        1,
        "original_greenplum_endpoint_hash_known_answer",
    )
    if (
        len(digest_rows) != 1
        or len(digest_rows[0]) != 2
        or not _require_boolean(
            digest_rows[0][0],
            "original Greenplum SHA-256 known-answer equality",
        )
        or _require_integer(
            digest_rows[0][1],
            "original Greenplum SHA-256 known-answer byte length",
            0,
            INT64_MAX,
        )
        != 32
    ):
        raise UnsupportedGreenplumProfileError(
            "original Greenplum dfe_ext.digest(bytea, text) failed the protected-snapshot "
            "SHA-256 known-answer check"
        )
    return replace(capability, canonical_sha256_verified=True)


def _key_summary_query(
    relation: OriginalGreenplumProtectedRelationInspection,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> OriginalGreenplumEndpointQuery:
    acquisition = relation.acquisition
    return build_original_greenplum_integer_key_summary_query(
        acquisition.schema,
        acquisition.relation.components[0],
        acquisition.relation.components[1],
        relation.catalog.relation_oid,
        relation.inspection.relation_row_type_oid,
        relation.inspection.bindings,
        relation.inspection.max_identifier_utf8_bytes,
        key_field_index,
        scope,
        max_encoded_envelope_bytes,
    )


def _range_fingerprint_query(
    relation: OriginalGreenplumProtectedRelationInspection,
    topology: GreenplumTopology,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    requested_range: PostgresIntegerRangeRequest,
    max_encoded_envelope_bytes: int,
) -> OriginalGreenplumRangeFingerprintQuery:
    acquisition = relation.acquisition
    return build_original_greenplum_integer_range_fingerprint_query(
        acquisition.schema,
        acquisition.relation.components[0],
        acquisition.relation.components[1],
        relation.inspection.relation_row_type_oid,
        relation.inspection.bindings,
        relation.inspection.max_identifier_utf8_bytes,
        topology.primary_content_ids,
        key_field_index,
        scope,
        requested_range,
        max_encoded_envelope_bytes,
    )


def _range_rows_query(
    relation: OriginalGreenplumProtectedRelationInspection,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> OriginalGreenplumEndpointQuery:
    acquisition = relation.acquisition
    return build_original_greenplum_integer_range_rows_query(
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
    query: OriginalGreenplumEndpointQuery,
) -> PostgresIntegerKeySummary:
    if len(row) != 9:
        raise GreenplumDataValidationError(
            "original Greenplum integer-key summary must return nine fields"
        )
    _require_origin_oid(row[0], query, "integer-key summary")
    counts = tuple(
        _parse_unsigned_decimal(value, "original Greenplum integer-key count", INT64_MAX)
        for value in row[1:6]
    )
    return PostgresIntegerKeySummary(
        row_count=counts[0],
        null_key_count=counts[1],
        invalid_key_count=counts[2],
        valid_key_count=counts[3],
        distinct_key_count=counts[4],
        minimum_key=_parse_optional_int64(row[6], "original Greenplum key minimum"),
        maximum_key=_parse_optional_int64(row[7], "original Greenplum key maximum"),
        usable_access_path=_require_boolean(
            row[8],
            "original Greenplum integer-key access path",
        ),
    )


def _parse_range_fingerprint(
    row: DatabaseRow,
    query: OriginalGreenplumRangeFingerprintQuery,
    deadline: PostgresReadDeadline,
) -> PostgresRangeFingerprint:
    _require_deadline(deadline, "range fingerprint decoding")
    if len(row) != 17:
        raise GreenplumDataValidationError(
            "original Greenplum range fingerprint row must contain seventeen fields: "
            f"actual={len(row)}"
        )
    _require_origin_oid(row[0], query, "range fingerprint")
    segment_id = _require_text(row[1], "original Greenplum range segment ID")
    if segment_id != query.range.segment_id:
        raise GreenplumDataValidationError(
            "original Greenplum fingerprint row does not preserve requested segment identity"
        )
    count = _parse_unsigned_decimal(
        row[2],
        "original Greenplum range valid row count",
        INT64_MAX,
    )
    limbs = tuple(
        _parse_unsigned_decimal(
            row[3 + limb],
            f"original Greenplum range limb {limb}",
            DECIMAL_38_MAX,
        )
        for limb in range(8)
    )
    invalid = _parse_unsigned_decimal(
        row[11],
        "original Greenplum range invalid row count",
        INT64_MAX,
    )
    oversized = _parse_unsigned_decimal(
        row[12],
        "original Greenplum range oversized row count",
        INT64_MAX,
    )
    row_bytes = _parse_unsigned_decimal(
        row[13],
        "original Greenplum row envelope bytes",
        INT64_MAX,
    )
    key_bytes = _parse_unsigned_decimal(
        row[14],
        "original Greenplum key envelope bytes",
        INT64_MAX,
    )
    topology = _parse_content_ids(row[15], False, "original Greenplum range topology")
    observed = _parse_content_ids(row[16], True, "original Greenplum observed segments")
    if topology != query.primary_content_ids:
        raise GreenplumContextLostError(
            "original Greenplum active-primary topology changed during fingerprint: "
            f"expected={query.primary_content_ids!r}, actual={topology!r}"
        )
    unexpected = frozenset(observed) - frozenset(topology)
    if unexpected:
        raise GreenplumContextLostError(
            "original Greenplum fingerprint observed rows outside captured topology: "
            f"unexpected={tuple(sorted(unexpected))!r}"
        )
    if invalid != 0:
        raise GreenplumDataValidationError(
            "original Greenplum fingerprint rejected non-lossless rows: "
            f"segment_id={segment_id!r}, invalid_row_count={invalid}"
        )
    if oversized != 0:
        raise OriginalGreenplumResultLimitError(
            "original Greenplum fingerprint found envelopes above the limit: "
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
            "original Greenplum fingerprint violates exact accumulator bounds: "
            f"segment_id={segment_id!r}, reason_type={type(error).__name__}"
        ) from None
    return PostgresRangeFingerprint(
        segment_id=segment_id,
        fingerprint=fingerprint,
        row_envelope_bytes=row_bytes,
        key_envelope_bytes=key_bytes,
    )


def _parse_exact_rows(
    rows: tuple[DatabaseRow, ...],
    query: OriginalGreenplumEndpointQuery,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    key_field_index: int,
    deadline: PostgresReadDeadline,
) -> tuple[PostgresIntegerExactRow, ...]:
    if type(key_field_index) is not int or not 0 <= key_field_index < len(
        query.context.schema.fields
    ):
        raise GreenplumDataValidationError(
            "original Greenplum exact-row key index does not identify a schema field"
        )
    key_schema = CanonicalSchema(
        protocol=query.context.schema.protocol,
        fields=(query.context.schema.fields[key_field_index],),
    )
    key_context = prepare_envelope_context(key_schema)
    ordinal_by_id = {request.segment_id: index for index, request in enumerate(ranges)}
    if not rows:
        raise GreenplumDataValidationError(
            "original Greenplum exact comparison returned no rows or same-RTE witness"
        )
    parsed: list[PostgresIntegerExactRow] = []
    false_witness_count = 0
    previous_ordinal = -1
    previous_key: int | None = None
    for row_index, row in enumerate(rows):
        _require_deadline(deadline, "exact-row decoding")
        if len(row) != 7:
            raise GreenplumDataValidationError(
                "original Greenplum exact row must contain seven fields: "
                f"row_index={row_index}, actual={len(row)}"
            )
        _require_origin_oid(row[0], query, "exact comparison")
        has_data = _require_boolean(row[1], "original Greenplum exact data marker")
        if not has_data:
            if any(value is not None for value in row[2:]):
                raise GreenplumDataValidationError(
                    "original Greenplum exact same-RTE witness exposed logical fields"
                )
            false_witness_count += 1
            continue
        segment_id = _require_text(row[2], "original Greenplum exact segment ID")
        ordinal = ordinal_by_id.get(segment_id)
        if ordinal is None:
            raise GreenplumDataValidationError(
                "original Greenplum exact row identifies an unrequested range"
            )
        invalid = _require_boolean(row[5], "original Greenplum exact invalid-row status")
        oversized = _require_boolean(
            row[6],
            "original Greenplum exact oversized-row status",
        )
        if invalid and oversized:
            raise GreenplumDataValidationError(
                "original Greenplum exact row statuses must be mutually exclusive"
            )
        if invalid:
            raise GreenplumDataValidationError(
                "original Greenplum exact comparison found a non-lossless row"
            )
        if oversized:
            raise OriginalGreenplumResultLimitError(
                "original Greenplum exact row exceeds the canonical envelope limit: "
                f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
            )
        key_value = _require_integer(
            row[3],
            "original Greenplum exact key value",
            INT64_MIN,
            INT64_MAX,
        )
        row_envelope = _ascii_envelope(row[4], "original Greenplum row envelope")
        if len(row_envelope) > query.max_encoded_envelope_bytes:
            raise OriginalGreenplumResultLimitError(
                "original Greenplum exact envelope exceeds the configured limit: "
                f"observed_bytes={len(row_envelope)}, "
                f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
            )
        try:
            row_values = decode_row_with_context(query.context, row_envelope)
        except CanonicalizationError as error:
            raise GreenplumDataValidationError(
                "original Greenplum exact envelope failed reference decoding: "
                f"reason_type={type(error).__name__}"
            ) from None
        if len(row_values) != len(query.context.schema.fields):
            raise GreenplumDataValidationError(
                "original Greenplum exact envelope decoded to an unexpected field count"
            )
        row_key_value = row_values[key_field_index]
        if type(row_key_value) is not int or key_value != row_key_value:
            raise GreenplumDataValidationError(
                "original Greenplum exact key and canonical row envelope disagree"
            )
        try:
            key_envelope = encode_key_with_context(key_context, (key_value,))
        except CanonicalizationError as error:
            raise GreenplumDataValidationError(
                "original Greenplum exact key reconstruction failed: "
                f"reason_type={type(error).__name__}"
            ) from None
        request = ranges[ordinal]
        if key_value < request.lower_inclusive or (
            request.upper_exclusive is not None and key_value >= request.upper_exclusive
        ):
            raise GreenplumDataValidationError(
                "original Greenplum exact key falls outside its requested range"
            )
        if ordinal < previous_ordinal or (
            ordinal == previous_ordinal and previous_key is not None and key_value <= previous_key
        ):
            raise GreenplumDataValidationError(
                "original Greenplum exact rows are not strictly ordered by range and key"
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
            "original Greenplum exact comparison mixed witness and logical rows"
        )
    if not parsed and false_witness_count != 1:
        raise GreenplumDataValidationError(
            "original Greenplum empty exact comparison requires one same-RTE witness: "
            f"actual={false_witness_count}"
        )
    _require_deadline(deadline, "exact-row decoding")
    return tuple(parsed)


def _validate_manifest_contract(
    relation: OriginalGreenplumProtectedRelationInspection,
    columns: ReadinessManifestColumns,
) -> None:
    if not isinstance(cast(object, columns), ReadinessManifestColumns):
        raise TypeError("original Greenplum readiness columns have an unexpected type")
    semantic_fields = tuple(field.name for field in relation.acquisition.schema.fields)
    if semantic_fields != _MANIFEST_FIELDS:
        raise GreenplumMetadataError(
            "original Greenplum manifest must use the fixed semantic field order: "
            f"expected={_MANIFEST_FIELDS!r}, actual={semantic_fields!r}"
        )
    if columns.values() != relation.acquisition.column_names:
        raise GreenplumMetadataError(
            "original Greenplum manifest mappings differ from the protected closure"
        )
    bindings = {binding.column_name: binding for binding in relation.inspection.bindings}
    if len(bindings) != len(relation.inspection.bindings):
        raise GreenplumMetadataError(
            "original Greenplum manifest inspection contains duplicate bindings"
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
                "original Greenplum manifest column is outside the protected inspection: "
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
                "original Greenplum manifest column has an unsupported type: "
                f"field={field_name!r}, column={column_name!r}, "
                f"physical_type={physical.formatted_type!r}"
            )


def _manifest_statement(
    relation: OriginalGreenplumProtectedRelationInspection,
    columns: ReadinessManifestColumns,
) -> str:
    table = ".".join(
        _quote_identifier(component) for component in relation.acquisition.relation.components
    )
    names = tuple(_quote_identifier(value) for value in columns.values())
    return (
        "SELECT (pg_catalog.pg_typeof(CASE WHEN FALSE THEN (dfe_manifest.*) "
        "ELSE NULL END))::oid::bigint AS origin_type, "
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
    query: OriginalGreenplumEndpointQuery,
) -> PostgresRelationManifestRecord:
    if len(row) != 9:
        raise GreenplumDataValidationError(
            "original Greenplum relation manifest must return nine fields"
        )
    _require_origin_oid(row[0], query, "relation manifest")
    business_date = row[5]
    completed_at = row[8]
    if type(business_date) is not date:
        raise GreenplumDataValidationError("original Greenplum manifest business_date must be date")
    if completed_at is not None and not isinstance(completed_at, datetime):
        raise GreenplumDataValidationError(
            "original Greenplum manifest completed_at must be datetime or null"
        )
    if isinstance(completed_at, datetime) and completed_at.tzinfo is None:
        raise GreenplumDataValidationError(
            "original Greenplum manifest completed_at must include a UTC offset"
        )
    return PostgresRelationManifestRecord(
        dataset_id=_require_text(row[1], "original Greenplum manifest dataset_id"),
        scope_digest=_require_text(row[2], "original Greenplum manifest scope_digest"),
        batch_id=_require_text(row[3], "original Greenplum manifest batch_id"),
        state=_require_text(row[4], "original Greenplum manifest state"),
        business_date=business_date,
        source_cut=_require_optional_text(row[6], "original Greenplum manifest source_cut"),
        dataset_version=_require_optional_text(
            row[7],
            "original Greenplum manifest dataset_version",
        ),
        completed_at=completed_at,
    )


def _require_query_provenance(
    rows: tuple[DatabaseRow, ...],
    query: OriginalGreenplumEndpointQuery | OriginalGreenplumRangeFingerprintQuery,
    operation: str,
) -> None:
    for row_index, row in enumerate(rows):
        if not row:
            raise GreenplumDataValidationError(
                "original Greenplum endpoint returned an empty record: "
                f"operation={operation!r}, row_index={row_index}"
            )
        _require_origin_oid(row[0], query, operation)


def _require_origin_oid(
    value: object,
    query: OriginalGreenplumEndpointQuery | OriginalGreenplumRangeFingerprintQuery,
    operation: str,
) -> None:
    observed = _require_integer(
        value,
        "original Greenplum relation row type OID",
        1,
        (1 << 32) - 1,
    )
    if observed != query.relation_row_type_oid:
        raise GreenplumContextLostError(
            "original Greenplum query provenance changed inside the protected snapshot: "
            f"operation={operation!r}, expected_row_type_oid="
            f"{query.relation_row_type_oid}, actual_row_type_oid={observed}"
        )


def _read_metrics(
    rows: tuple[DatabaseRow, ...],
    deadline: PostgresReadDeadline,
) -> PostgresReadMetrics:
    _require_deadline(deadline, "result accounting")
    return PostgresReadMetrics(
        fetched_records=len(rows),
        result_bytes=sum(_database_row_bytes(row) for row in rows),
    )


def _exact_read_metrics(
    rows: tuple[PostgresIntegerExactRow, ...],
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
    deadline: PostgresReadDeadline,
) -> PostgresReadMetrics:
    _require_deadline(deadline, "exact result accounting")
    if len(rows) > max_records:
        raise OriginalGreenplumResultLimitError(
            "original Greenplum decoded exact rows exceed the record budget: "
            f"observed={len(rows)}, maximum={max_records}"
        )
    sizes = tuple(
        len(row.segment_id.encode("ascii"))
        + len(row.key_envelope)
        + len(row.row_envelope)
        + _EXACT_STATUS_BYTES
        for row in rows
    )
    oversized = next((size for size in sizes if size > max_record_bytes), None)
    if oversized is not None:
        raise OriginalGreenplumResultLimitError(
            "original Greenplum decoded exact row exceeds its byte budget: "
            f"observed_bytes={oversized}, maximum={max_record_bytes}"
        )
    total = sum(sizes)
    if total > max_total_bytes:
        raise OriginalGreenplumResultLimitError(
            "original Greenplum decoded exact rows exceed their total byte budget: "
            f"observed_bytes={total}, maximum={max_total_bytes}"
        )
    return PostgresReadMetrics(fetched_records=len(rows), result_bytes=total)


def _require_deadline(deadline: PostgresReadDeadline, operation: str) -> None:
    if not isinstance(cast(object, deadline), PostgresReadDeadline):
        raise TypeError("original Greenplum read deadline has an unexpected type")
    if time.monotonic_ns() > deadline.deadline_nanoseconds:
        raise PostgresReadDeadlineExceededError(
            f"original Greenplum protected read exceeded its deadline: operation={operation!r}"
        )


def _require_full_scans(reserved: int, expected: int, operation: str) -> None:
    if type(reserved) is not int or reserved != expected:
        raise ValueError(
            "original Greenplum full-scan reservation is inconsistent: "
            f"operation={operation!r}, expected={expected}, actual={reserved!r}"
        )


def _map_catalog_error(
    error: GreenplumCatalogDataError | GreenplumCatalogMetadataError,
) -> GreenplumConnectorError:
    if isinstance(error, GreenplumCatalogMetadataError):
        return GreenplumMetadataError(str(error))
    return GreenplumDataValidationError(str(error))


def _parse_unsigned_decimal(value: object, label: str, maximum: int) -> int:
    text = _require_text(value, label)
    if not text.isascii() or not text.isdecimal():
        raise GreenplumDataValidationError(f"{label} must be unsigned decimal text")
    parsed = int(text)
    if parsed > maximum:
        raise GreenplumDataValidationError(
            f"{label} exceeds its exact bound: value={parsed}, maximum={maximum}"
        )
    return parsed


def _parse_optional_int64(value: object, label: str) -> int | None:
    if value is None:
        return None
    text = _require_text(value, label)
    try:
        parsed = int(text)
    except ValueError:
        raise GreenplumDataValidationError(f"{label} must be signed decimal text") from None
    if str(parsed) != text or not INT64_MIN <= parsed <= INT64_MAX:
        raise GreenplumDataValidationError(f"{label} is outside signed-int64 canonical form")
    return parsed


def _parse_content_ids(value: object, allow_empty: bool, label: str) -> tuple[int, ...]:
    text = _require_text_allow_empty(value, label)
    if text == "":
        if allow_empty:
            return ()
        raise GreenplumDataValidationError(f"{label} must not be empty")
    parsed = tuple(
        _parse_unsigned_decimal(part, f"{label} item {index}", INT64_MAX)
        for index, part in enumerate(text.split(","))
    )
    if len(set(parsed)) != len(parsed):
        raise GreenplumDataValidationError(f"{label} must contain distinct content IDs")
    return tuple(sorted(parsed))


def _ascii_envelope(value: object, label: str) -> bytes:
    text = _require_text(value, label)
    try:
        return text.encode("ascii")
    except UnicodeEncodeError:
        raise GreenplumDataValidationError(f"{label} must contain ASCII text") from None


def _consume_batch(
    charge: PostgresSourceQueryCharge,
    records: list[DatabaseRow],
    batch: tuple[DatabaseRow, ...],
    total_bytes: int,
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
    operation: str,
) -> int:
    batch_bytes = tuple(_database_row_bytes(row) for row in batch)
    charge.consume_records(batch_bytes)
    observed_records = len(records) + len(batch)
    observed_bytes = total_bytes + sum(batch_bytes)
    if observed_records > max_records:
        raise OriginalGreenplumResultLimitError(
            "original Greenplum query exceeded its record budget: "
            f"operation={operation!r}, max_records={max_records}"
        )
    oversized = next((value for value in batch_bytes if value > max_record_bytes), None)
    if oversized is not None:
        raise OriginalGreenplumResultLimitError(
            "original Greenplum query returned a record above its byte budget: "
            f"operation={operation!r}, record_bytes={oversized}, "
            f"max_record_bytes={max_record_bytes}"
        )
    if observed_bytes > max_total_bytes:
        raise OriginalGreenplumResultLimitError(
            "original Greenplum query exceeded its total byte budget: "
            f"operation={operation!r}, observed_bytes={observed_bytes}, "
            f"max_total_bytes={max_total_bytes}"
        )
    records.extend(batch)
    return observed_bytes


def _database_row_bytes(row: DatabaseRow) -> int:
    total = 0
    for value in row:
        if value is None:
            total += 1
        elif type(value) is bool:
            total += 1
        elif type(value) is int:
            total += len(str(value).encode("ascii"))
        elif type(value) is bytes:
            total += len(value)
        elif type(value) is str:
            total += len(value.encode("utf-8"))
        elif type(value) is date:
            total += len(value.isoformat().encode("ascii"))
        elif isinstance(value, datetime):
            total += len(value.isoformat().encode("ascii"))
        else:
            raise GreenplumDataValidationError(
                "original Greenplum query returned an unsupported value type: "
                f"type={type(value).__name__!r}"
            )
    return total


def _validate_result_limits(
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
) -> None:
    for value, label in (
        (max_records, "max records"),
        (max_record_bytes, "max record bytes"),
        (max_total_bytes, "max total bytes"),
    ):
        if type(value) is not int or value < 1:
            raise ValueError(f"original Greenplum {label} must be a positive integer")
    if max_record_bytes > max_total_bytes:
        raise ValueError("original Greenplum record byte limit cannot exceed total byte limit")


def _quote_identifier(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("original Greenplum identifier must be non-empty text without U+0000")
    return '"' + value.replace('"', '""') + '"'


def _require_text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise GreenplumDataValidationError(f"{label} must be non-empty text")
    return value


def _require_text_allow_empty(value: object, label: str) -> str:
    if type(value) is not str:
        raise GreenplumDataValidationError(f"{label} must be text")
    return value


def _require_optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, label)


def _require_boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise GreenplumDataValidationError(f"{label} must be boolean")
    return value


def _require_integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GreenplumDataValidationError(
            f"{label} must be an integer from {minimum} through {maximum}"
        )
    return value
