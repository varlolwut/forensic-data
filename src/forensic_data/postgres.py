import logging
import math
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from threading import Lock
from typing import LiteralString, cast
from uuid import UUID, uuid4

import psycopg
from psycopg import Column, ServerCursor, sql
from psycopg.rows import tuple_row
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from forensic_data.canonical import (
    CanonicalizationError,
    CanonicalSchema,
    DecodedValue,
    Fingerprint,
    FingerprintOverflowError,
    decode_key_with_context,
    decode_row_with_context,
    envelope_sha256,
    prepare_envelope_context,
)
from forensic_data.contracts.model import (
    ExecutionBudgets,
    ReadinessManifestColumns,
    RelationScope,
)
from forensic_data.postgres_sql import (
    MAX_COMPILED_RELATION_MEMBERS,
    PostgresFieldBinding,
    PostgresInspectedRelation,
    PostgresIntegerRangeRequest,
    PostgresParameter,
    PostgresPhysicalField,
    PostgresQuery,
    PostgresQueryRelation,
    PostgresRelation,
    PostgresScopePredicate,
    PostgresTypeIdentity,
    build_postgres_union_fingerprint_query,
    build_postgres_union_integer_key_summary_query,
    build_postgres_union_integer_range_fingerprint_query,
    build_postgres_union_integer_range_rows_query,
    build_postgres_union_row_envelope_query,
    validate_postgres_inspection,
)

LOGGER = logging.getLogger(__name__)
INT64_MAX = (1 << 63) - 1
UINT32_MAX = (1 << 32) - 1
SHA256_BYTES = 32
_CANONICAL_STATUS_BYTES = 2
_MAX_UINT32_DECIMAL_BYTES = 10
_DATA_MARKER_BYTES = 1
_CURSOR_FETCH_RECORDS = 64
_DEADLINE_CHECK_RECORDS = 64
_METADATA_ROW_COLUMNS = 15
_MANIFEST_TEXT_TYPES: frozenset[tuple[str, int]] = frozenset((("text", 25), ("varchar", 1043)))
_MANIFEST_DATE_TYPE: tuple[str, int] = ("date", 1082)
_MANIFEST_TIMESTAMPTZ_TYPE: tuple[str, int] = ("timestamptz", 1184)
_MANIFEST_SEMANTIC_FIELDS: tuple[str, ...] = (
    "dataset_id",
    "scope_digest",
    "batch_id",
    "state",
    "business_date",
    "source_cut",
    "dataset_version",
    "completed_at",
)


class PostgresConnectorError(RuntimeError):
    """Base error for the PostgreSQL connector boundary."""


class PostgresConnectionError(PostgresConnectorError):
    """A PostgreSQL connection or read-context setup failed."""


class UnsupportedPostgresProfileError(PostgresConnectorError):
    """The declared or connected server cannot provide its PostgreSQL profile."""


class PostgresMetadataError(PostgresConnectorError):
    """Required PostgreSQL relation or column provenance is unavailable."""


class PostgresAcquisitionRaceError(PostgresMetadataError):
    """A discovered PostgreSQL relation changed before protected acquisition completed."""


class PostgresContextClosedError(PostgresConnectorError):
    """A query was attempted after the read context was closed."""


class PostgresContextLostError(PostgresConnectorError):
    """A query was attempted after the transaction read context was lost."""


class PostgresQueryError(PostgresConnectorError):
    """A query failed and invalidated its transaction read context."""


class PostgresQueryContextError(PostgresConnectorError):
    """A compiled query was used outside its originating transaction context."""


class PostgresCloseError(PostgresConnectorError):
    """Closing a PostgreSQL read context failed."""


class PostgresDataValidationError(PostgresConnectorError):
    """PostgreSQL returned a value outside the typed adapter contract."""


class PostgresResultLimitError(PostgresConnectorError):
    """A PostgreSQL result exceeded an explicitly reserved byte or record budget."""


class PostgresReadDeadlineExceededError(PostgresConnectorError):
    """A bounded PostgreSQL read exhausted its absolute monotonic deadline."""


class PostgresSourceBudgetExceededError(PostgresConnectorError):
    """The immutable whole-run source budget cannot admit more source work."""


class PostgresSslMode(StrEnum):
    DISABLE = "disable"
    REQUIRE = "require"
    VERIFY_CA = "verify-ca"
    VERIFY_FULL = "verify-full"


class PostgresSourceDirection(StrEnum):
    REFERENCE = "reference"
    TARGET = "target"


class PostgresRelationPersistence(StrEnum):
    PERMANENT = "permanent"


class PostgresRelationKind(StrEnum):
    REGULAR = "r"
    PARTITIONED = "p"


class PostgresInheritanceDetachState(StrEnum):
    ATTACHED = "attached"
    UNSUPPORTED_BY_SERVER = "unsupported_by_server"


class PostgresConnectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: str
    port: int = Field(ge=1, le=65535)
    dbname: str
    user: str
    password: SecretStr
    sslmode: PostgresSslMode
    connect_timeout_seconds: int = Field(ge=1)
    statement_timeout_milliseconds: int = Field(ge=1)
    application_name: str

    @field_validator("host", "dbname", "user", "application_name")
    @classmethod
    def validate_nonempty_text(cls, value: str) -> str:
        if not value:
            raise ValueError("connection text fields must not be empty")
        if "\x00" in value:
            raise ValueError("connection text fields must not contain U+0000")
        return value


@dataclass(frozen=True, slots=True)
class PostgresRetryPolicy:
    max_attempts: int
    delay_seconds: float

    def __post_init__(self) -> None:
        if type(self.max_attempts) is not int or self.max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        if (
            type(self.delay_seconds) is not float
            or not math.isfinite(self.delay_seconds)
            or self.delay_seconds < 0
        ):
            raise ValueError("delay_seconds must be a finite non-negative float")


@dataclass(frozen=True, slots=True)
class PostgresServerProfile:
    driver_version: str
    server_version: str
    server_version_number: int
    server_encoding: str
    client_encoding: str
    integer_datetimes: bool
    timezone: str
    max_identifier_utf8_bytes: int


@dataclass(frozen=True, slots=True)
class PostgresReadContextEvidence:
    context_id: UUID
    engine: str
    server_version: str
    strategy: str
    snapshot_locator: str
    started_at: datetime
    backend_process_id: int
    allowed_concurrency: int
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PostgresProtectedReadContextEvidence(PostgresReadContextEvidence):
    locked_relation_oids: tuple[int, ...]
    lock_mode: str
    relation_persistence: PostgresRelationPersistence
    acquired_before_snapshot: bool


@dataclass(frozen=True, slots=True)
class PostgresRelationAcquisition:
    schema: CanonicalSchema
    relation: PostgresRelation
    relation_scope: RelationScope
    column_names: tuple[str, ...]
    max_metadata_record_bytes: int
    max_metadata_total_bytes: int

    def __post_init__(self) -> None:
        _require_schema(self.schema)
        _require_relation(self.relation)
        if type(self.relation_scope) is not RelationScope:
            raise TypeError("PostgreSQL relation_scope must be a RelationScope")
        if self.relation_scope not in (
            RelationScope.PHYSICAL_ONLY,
            RelationScope.FROZEN_PHYSICAL_UNION,
        ):
            raise ValueError("PostgreSQL relation acquisition requires a supported relation scope")
        _require_column_names(self.column_names, len(self.schema.fields))
        _validate_metadata_limits(
            self.max_metadata_record_bytes,
            self.max_metadata_total_bytes,
        )


@dataclass(frozen=True, slots=True)
class PostgresInheritanceEdge:
    parent_relation_oid: int
    child_relation_oid: int
    sequence: int
    detach_state: PostgresInheritanceDetachState

    def __post_init__(self) -> None:
        _validate_positive_integer(self.parent_relation_oid, "inheritance parent OID")
        _validate_positive_integer(self.child_relation_oid, "inheritance child OID")
        _validate_positive_integer(self.sequence, "inheritance edge sequence")
        if self.parent_relation_oid == self.child_relation_oid:
            raise ValueError("PostgreSQL inheritance edge cannot be self-referential")
        if type(self.detach_state) is not PostgresInheritanceDetachState:
            raise TypeError("detach_state must be a PostgresInheritanceDetachState")


@dataclass(frozen=True, slots=True)
class PostgresProtectedRelationMember:
    inspection: PostgresInspectedRelation
    namespace_oid: int
    relation_kind: PostgresRelationKind
    relation_persistence: PostgresRelationPersistence

    def __post_init__(self) -> None:
        _require_inspected_relation(self.inspection)
        _validate_positive_integer(self.namespace_oid, "member namespace_oid")
        if type(self.relation_kind) is not PostgresRelationKind:
            raise TypeError("relation_kind must be a PostgresRelationKind")
        if self.relation_persistence is not PostgresRelationPersistence.PERMANENT:
            raise ValueError("protected union member must be permanent")


@dataclass(frozen=True, slots=True)
class PostgresProtectedRelationComposition:
    root_relation_oid: int
    members: tuple[PostgresProtectedRelationMember, ...]
    edges: tuple[PostgresInheritanceEdge, ...]

    def __post_init__(self) -> None:
        _validate_positive_integer(self.root_relation_oid, "composition root relation OID")
        if type(self.members) is not tuple or not self.members:
            raise ValueError("protected relation composition requires immutable members")
        if type(self.edges) is not tuple:
            raise TypeError("protected relation composition edges must be an immutable tuple")
        member_oids = tuple(member.inspection.relation_oid for member in self.members)
        if len(set(member_oids)) != len(member_oids):
            raise ValueError("protected relation composition contains duplicate member OIDs")
        if self.root_relation_oid not in member_oids:
            raise ValueError("protected relation composition root is absent from its members")
        expected_member_order = tuple(
            sorted(
                self.members,
                key=lambda member: (
                    member.inspection.relation.components,
                    member.inspection.relation_oid,
                ),
            )
        )
        if self.members != expected_member_order:
            raise ValueError("protected relation composition members are not deterministic")
        member_oid_set = set(member_oids)
        expected_edge_order = tuple(
            sorted(
                self.edges,
                key=lambda edge: (
                    edge.parent_relation_oid,
                    edge.sequence,
                    edge.child_relation_oid,
                ),
            )
        )
        if self.edges != expected_edge_order or len(set(self.edges)) != len(self.edges):
            raise ValueError("protected relation composition edges are not deterministic")
        for edge in self.edges:
            if (
                edge.parent_relation_oid not in member_oid_set
                or edge.child_relation_oid not in member_oid_set
            ):
                raise ValueError("protected relation composition contains a dangling edge")
        _validate_composition_reachability(
            self.root_relation_oid,
            member_oid_set,
            self.edges,
        )


@dataclass(frozen=True, slots=True)
class PostgresProtectedRelationInspection:
    acquisition: PostgresRelationAcquisition
    inspection: PostgresInspectedRelation
    namespace_oid: int
    lock_mode: str
    relation_persistence: PostgresRelationPersistence
    acquired_before_snapshot: bool
    composition: PostgresProtectedRelationComposition | None

    def __post_init__(self) -> None:
        _require_relation_acquisition(self.acquisition)
        _require_inspected_relation(self.inspection)
        _validate_positive_integer(self.namespace_oid, "namespace_oid")
        if self.inspection.relation != self.acquisition.relation:
            raise ValueError("protected inspection relation must match its acquisition")
        if self.lock_mode != "access_share":
            raise ValueError("protected inspection lock_mode must be 'access_share'")
        if self.relation_persistence is not PostgresRelationPersistence.PERMANENT:
            raise ValueError("protected inspection relation_persistence must be permanent")
        if self.acquired_before_snapshot is not True:
            raise ValueError("protected inspection must be acquired before the snapshot")
        if self.acquisition.relation_scope is RelationScope.PHYSICAL_ONLY:
            if self.composition is not None:
                raise ValueError("physical_only inspection cannot contain a union composition")
        elif self.acquisition.relation_scope is RelationScope.FROZEN_PHYSICAL_UNION:
            if not isinstance(self.composition, PostgresProtectedRelationComposition):
                raise ValueError("frozen physical union inspection requires a composition")
            if self.composition.root_relation_oid != self.inspection.relation_oid:
                raise ValueError("protected composition root differs from the root inspection")
            root_members = tuple(
                member
                for member in self.composition.members
                if member.inspection.relation_oid == self.inspection.relation_oid
            )
            if len(root_members) != 1 or root_members[0].inspection is not self.inspection:
                raise ValueError(
                    "protected composition must contain the exact sealed root inspection"
                )
        else:
            raise ValueError("protected inspection has an unsupported relation scope")

    def query_relations(self) -> tuple[PostgresQueryRelation, ...]:
        if self.composition is None:
            return (
                PostgresQueryRelation(
                    inspection=self.inspection,
                    contributes_rows=True,
                ),
            )
        return tuple(
            PostgresQueryRelation(
                inspection=member.inspection,
                contributes_rows=member.relation_kind is PostgresRelationKind.REGULAR,
            )
            for member in self.composition.members
        )

    def physical_scan_count(self) -> int:
        if self.composition is None:
            return 1
        return sum(
            member.relation_kind is PostgresRelationKind.REGULAR
            for member in self.composition.members
        )


def _validate_composition_reachability(
    root_relation_oid: int,
    member_oids: set[int],
    edges: tuple[PostgresInheritanceEdge, ...],
) -> None:
    children_by_parent: dict[int, list[int]] = {oid: [] for oid in member_oids}
    child_sequences: set[tuple[int, int]] = set()
    for edge in edges:
        sequence_identity = (edge.child_relation_oid, edge.sequence)
        if sequence_identity in child_sequences:
            raise ValueError(
                "PostgreSQL relation composition repeats an inheritance sequence for one "
                f"child: child_oid={edge.child_relation_oid}, sequence={edge.sequence}"
            )
        child_sequences.add(sequence_identity)
        children_by_parent.setdefault(edge.parent_relation_oid, []).append(edge.child_relation_oid)

    reachable: set[int] = set()
    active: set[int] = set()
    stack: list[tuple[int, bool]] = [(root_relation_oid, False)]
    while stack:
        relation_oid, exiting = stack.pop()
        if exiting:
            active.remove(relation_oid)
            reachable.add(relation_oid)
            continue
        if relation_oid in reachable:
            continue
        if relation_oid in active:
            raise ValueError(
                "PostgreSQL relation composition contains an inheritance cycle: "
                f"relation_oid={relation_oid}"
            )
        active.add(relation_oid)
        stack.append((relation_oid, True))
        for child_oid in reversed(children_by_parent.get(relation_oid, [])):
            stack.append((child_oid, False))
    if reachable != member_oids:
        raise ValueError(
            "PostgreSQL relation composition contains members unreachable from its root: "
            f"unreachable_oids={tuple(sorted(member_oids - reachable))!r}"
        )


@dataclass(frozen=True, slots=True)
class PostgresCanonicalRow:
    envelope: bytes
    sha256: bytes


@dataclass(frozen=True, slots=True)
class PostgresReadDeadline:
    statement_timeout_milliseconds: int
    deadline_nanoseconds: int

    def __post_init__(self) -> None:
        _validate_positive_integer(
            self.statement_timeout_milliseconds,
            "statement_timeout_milliseconds",
        )
        _validate_nonnegative_integer(self.deadline_nanoseconds, "deadline_nanoseconds")


@dataclass(frozen=True, slots=True)
class PostgresReadMetrics:
    fetched_records: int
    result_bytes: int

    def __post_init__(self) -> None:
        _validate_nonnegative_integer(self.fetched_records, "fetched_records")
        _validate_nonnegative_integer(self.result_bytes, "result_bytes")


@dataclass(frozen=True, slots=True)
class PostgresSourceUsageSnapshot:
    queries: int
    fetched_records: int
    result_bytes: int
    reference_full_scans: int
    target_full_scans: int
    elapsed_milliseconds: int

    def __post_init__(self) -> None:
        for name, value in (
            ("queries", self.queries),
            ("fetched_records", self.fetched_records),
            ("result_bytes", self.result_bytes),
            ("reference_full_scans", self.reference_full_scans),
            ("target_full_scans", self.target_full_scans),
            ("elapsed_milliseconds", self.elapsed_milliseconds),
        ):
            _validate_nonnegative_integer(value, f"source usage {name}")


@dataclass(frozen=True, slots=True)
class PostgresSourceCapacitySnapshot:
    queries: int
    fetched_records: int
    result_bytes: int
    reference_full_scans: int
    target_full_scans: int
    deadline_nanoseconds: int

    def __post_init__(self) -> None:
        for name, value in (
            ("queries", self.queries),
            ("fetched_records", self.fetched_records),
            ("result_bytes", self.result_bytes),
            ("reference_full_scans", self.reference_full_scans),
            ("target_full_scans", self.target_full_scans),
            ("deadline_nanoseconds", self.deadline_nanoseconds),
        ):
            _validate_nonnegative_integer(value, f"source capacity {name}")


@dataclass(slots=True)
class _PostgresSourceUsage:
    queries: int
    fetched_records: int
    result_bytes: int
    reference_full_scans: int
    target_full_scans: int


class PostgresSourceBudgetLedger:
    """One mutable source-work ledger shared by every snapshot attempt of a run."""

    def __init__(self, budgets: ExecutionBudgets) -> None:
        if not isinstance(cast(object, budgets), ExecutionBudgets):
            raise TypeError("source budget ledger requires ExecutionBudgets")
        self._budgets = budgets
        self._started_nanoseconds = time.monotonic_ns()
        self._deadline_nanoseconds = self._started_nanoseconds + (
            budgets.run_timeout_milliseconds * 1_000_000
        )
        self._usage = _PostgresSourceUsage(0, 0, 0, 0, 0)
        self._attempt_ids: set[UUID] = set()
        self._lock = Lock()

    @property
    def deadline_nanoseconds(self) -> int:
        return self._deadline_nanoseconds

    def start_attempt(self, attempt_id: UUID) -> "PostgresSourceBudgetAttempt":
        if type(attempt_id) is not UUID:
            raise TypeError("source budget attempt_id must be a UUID")
        with self._lock:
            if attempt_id in self._attempt_ids:
                raise ValueError("source budget attempt_id has already been started")
            self._attempt_ids.add(attempt_id)
            baseline = _source_usage_snapshot(
                self._usage,
                _elapsed_milliseconds_since(self._started_nanoseconds),
            )
        return PostgresSourceBudgetAttempt(self, attempt_id, baseline, time.monotonic_ns())

    def snapshot(self) -> PostgresSourceUsageSnapshot:
        with self._lock:
            return _source_usage_snapshot(
                self._usage,
                _elapsed_milliseconds_since(self._started_nanoseconds),
            )

    def remaining(self) -> PostgresSourceCapacitySnapshot:
        with self._lock:
            return PostgresSourceCapacitySnapshot(
                queries=max(0, self._budgets.max_queries - self._usage.queries),
                fetched_records=max(
                    0,
                    self._budgets.max_fetched_records - self._usage.fetched_records,
                ),
                result_bytes=max(
                    0,
                    self._budgets.max_application_result_bytes - self._usage.result_bytes,
                ),
                reference_full_scans=max(
                    0,
                    self._budgets.max_full_scans_per_side - self._usage.reference_full_scans,
                ),
                target_full_scans=max(
                    0,
                    self._budgets.max_full_scans_per_side - self._usage.target_full_scans,
                ),
                deadline_nanoseconds=self._deadline_nanoseconds,
            )

    def dispatch_query(
        self,
        direction: PostgresSourceDirection,
        full_scans: int,
    ) -> "PostgresSourceQueryCharge":
        if not isinstance(cast(object, direction), PostgresSourceDirection):
            raise TypeError("source query direction must be PostgresSourceDirection")
        _validate_nonnegative_integer(full_scans, "source query full_scans")
        with self._lock:
            _require_source_deadline(self._deadline_nanoseconds, "source query dispatch")
            if self._usage.queries >= self._budgets.max_queries:
                raise PostgresSourceBudgetExceededError(
                    "next source query exceeds immutable whole-run max_queries"
                )
            if direction is PostgresSourceDirection.REFERENCE:
                if (
                    self._usage.reference_full_scans + full_scans
                    > self._budgets.max_full_scans_per_side
                ):
                    raise PostgresSourceBudgetExceededError(
                        "next reference source query exceeds immutable whole-run "
                        "max_full_scans_per_side"
                    )
                self._usage.reference_full_scans += full_scans
            else:
                if (
                    self._usage.target_full_scans + full_scans
                    > self._budgets.max_full_scans_per_side
                ):
                    raise PostgresSourceBudgetExceededError(
                        "next target source query exceeds immutable whole-run "
                        "max_full_scans_per_side"
                    )
                self._usage.target_full_scans += full_scans
            self._usage.queries += 1
        return PostgresSourceQueryCharge(self)

    def consume_record(self, record_bytes: int) -> None:
        self.consume_records((record_bytes,))

    def consume_records(self, record_bytes: tuple[int, ...]) -> None:
        if type(record_bytes) is not tuple:
            raise TypeError("source result record bytes must be an immutable tuple")
        for value in record_bytes:
            _validate_nonnegative_integer(value, "source result record_bytes")
        with self._lock:
            self._usage.fetched_records += len(record_bytes)
            self._usage.result_bytes += sum(record_bytes)
            if time.monotonic_ns() >= self._deadline_nanoseconds:
                raise PostgresReadDeadlineExceededError(
                    "PostgreSQL source work exceeded the immutable whole-run deadline "
                    "while receiving a result"
                )
            if self._usage.fetched_records > self._budgets.max_fetched_records:
                raise PostgresSourceBudgetExceededError(
                    "source reads exceeded immutable whole-run max_fetched_records"
                )
            if self._usage.result_bytes > self._budgets.max_application_result_bytes:
                raise PostgresSourceBudgetExceededError(
                    "source reads exceeded immutable whole-run max_application_result_bytes"
                )

    def require_result_fetch_deadline(self) -> None:
        with self._lock:
            _require_source_deadline(self._deadline_nanoseconds, "source result fetch")

    def effective_statement_timeout_milliseconds(self) -> int:
        remaining_nanoseconds = self._deadline_nanoseconds - time.monotonic_ns()
        if remaining_nanoseconds <= 0:
            raise PostgresReadDeadlineExceededError(
                "PostgreSQL source work exceeded the immutable whole-run deadline"
            )
        remaining_milliseconds = max(1, remaining_nanoseconds // 1_000_000)
        return min(self._budgets.statement_timeout_milliseconds, remaining_milliseconds)


class PostgresSourceBudgetAttempt:
    """Attempt-scoped view over a run-owned source budget ledger."""

    def __init__(
        self,
        ledger: PostgresSourceBudgetLedger,
        attempt_id: UUID,
        baseline: PostgresSourceUsageSnapshot,
        started_nanoseconds: int,
    ) -> None:
        self._ledger = ledger
        self._attempt_id = attempt_id
        self._baseline = baseline
        self._started_nanoseconds = started_nanoseconds

    @property
    def attempt_id(self) -> UUID:
        return self._attempt_id

    def dispatch_query(
        self,
        direction: PostgresSourceDirection,
        full_scans: int,
    ) -> "PostgresSourceQueryCharge":
        return self._ledger.dispatch_query(direction, full_scans)

    def snapshot(self) -> PostgresSourceUsageSnapshot:
        current = self._ledger.snapshot()
        return PostgresSourceUsageSnapshot(
            queries=current.queries - self._baseline.queries,
            fetched_records=current.fetched_records - self._baseline.fetched_records,
            result_bytes=current.result_bytes - self._baseline.result_bytes,
            reference_full_scans=(
                current.reference_full_scans - self._baseline.reference_full_scans
            ),
            target_full_scans=current.target_full_scans - self._baseline.target_full_scans,
            elapsed_milliseconds=_elapsed_milliseconds_since(self._started_nanoseconds),
        )

    def overall_snapshot(self) -> PostgresSourceUsageSnapshot:
        return self._ledger.snapshot()

    def remaining(self) -> PostgresSourceCapacitySnapshot:
        return self._ledger.remaining()

    def read_deadline(self, statement_timeout_milliseconds: int) -> PostgresReadDeadline:
        _validate_positive_integer(
            statement_timeout_milliseconds,
            "source statement_timeout_milliseconds",
        )
        return PostgresReadDeadline(
            statement_timeout_milliseconds=statement_timeout_milliseconds,
            deadline_nanoseconds=self._ledger.deadline_nanoseconds,
        )

    def effective_statement_timeout_milliseconds(self) -> int:
        return self._ledger.effective_statement_timeout_milliseconds()


class PostgresSourceQueryCharge:
    """A dispatched source query whose returned records are charged as they arrive."""

    def __init__(self, ledger: PostgresSourceBudgetLedger) -> None:
        self._ledger = ledger

    def consume_record(self, record_bytes: int) -> None:
        self._ledger.consume_record(record_bytes)

    def consume_records(self, record_bytes: tuple[int, ...]) -> None:
        self._ledger.consume_records(record_bytes)

    def require_fetch_deadline(self) -> None:
        self._ledger.require_result_fetch_deadline()


def _source_usage_snapshot(
    usage: _PostgresSourceUsage,
    elapsed_milliseconds: int,
) -> PostgresSourceUsageSnapshot:
    return PostgresSourceUsageSnapshot(
        queries=usage.queries,
        fetched_records=usage.fetched_records,
        result_bytes=usage.result_bytes,
        reference_full_scans=usage.reference_full_scans,
        target_full_scans=usage.target_full_scans,
        elapsed_milliseconds=elapsed_milliseconds,
    )


def _elapsed_milliseconds_since(started_nanoseconds: int) -> int:
    return max(0, (time.monotonic_ns() - started_nanoseconds) // 1_000_000)


def _require_source_deadline(deadline_nanoseconds: int, operation: str) -> None:
    if time.monotonic_ns() >= deadline_nanoseconds:
        raise PostgresReadDeadlineExceededError(
            f"PostgreSQL {operation} exceeded the immutable whole-run source deadline"
        )


@dataclass(frozen=True, slots=True)
class PostgresIntegerKeySummary:
    row_count: int
    null_key_count: int
    invalid_key_count: int
    valid_key_count: int
    distinct_key_count: int
    minimum_key: int | None
    maximum_key: int | None
    usable_access_path: bool

    def __post_init__(self) -> None:
        for field_name, value in (
            ("row_count", self.row_count),
            ("null_key_count", self.null_key_count),
            ("invalid_key_count", self.invalid_key_count),
            ("valid_key_count", self.valid_key_count),
            ("distinct_key_count", self.distinct_key_count),
        ):
            _require_bounded_integer(value, field_name, 0, INT64_MAX)
        if self.row_count != self.null_key_count + self.invalid_key_count + self.valid_key_count:
            raise PostgresDataValidationError(
                "PostgreSQL integer-key summary counts do not partition the scoped rows"
            )
        if self.distinct_key_count > self.valid_key_count:
            raise PostgresDataValidationError(
                "PostgreSQL distinct integer-key count exceeds the valid key count"
            )
        if self.valid_key_count == 0:
            if self.minimum_key is not None or self.maximum_key is not None:
                raise PostgresDataValidationError(
                    "PostgreSQL empty integer-key summary must not contain key bounds"
                )
        else:
            minimum = _require_bounded_integer(
                self.minimum_key,
                "minimum_key",
                -(1 << 63),
                INT64_MAX,
            )
            maximum = _require_bounded_integer(
                self.maximum_key,
                "maximum_key",
                -(1 << 63),
                INT64_MAX,
            )
            if minimum > maximum:
                raise PostgresDataValidationError(
                    "PostgreSQL integer-key summary minimum exceeds its maximum"
                )
        if type(self.usable_access_path) is not bool:
            raise PostgresDataValidationError(
                "PostgreSQL integer-key access-path status must be a boolean"
            )


@dataclass(frozen=True, slots=True)
class PostgresIntegerKeySummaryRead:
    summary: PostgresIntegerKeySummary
    metrics: PostgresReadMetrics


@dataclass(frozen=True, slots=True)
class PostgresRangeFingerprint:
    segment_id: str
    fingerprint: Fingerprint
    row_envelope_bytes: int
    key_envelope_bytes: int

    def __post_init__(self) -> None:
        _require_text(self.segment_id, "segment_id")
        if not isinstance(cast(object, self.fingerprint), Fingerprint):
            raise PostgresDataValidationError(
                "PostgreSQL range fingerprint must contain a Fingerprint"
            )
        _validate_nonnegative_integer(self.row_envelope_bytes, "row_envelope_bytes")
        _validate_nonnegative_integer(self.key_envelope_bytes, "key_envelope_bytes")


@dataclass(frozen=True, slots=True)
class PostgresRangeFingerprintRead:
    ranges: tuple[PostgresRangeFingerprint, ...]
    metrics: PostgresReadMetrics


@dataclass(frozen=True, slots=True, repr=False)
class PostgresIntegerExactRow:
    segment_id: str
    key_value: int
    key_envelope: bytes
    row_envelope: bytes
    values: tuple[DecodedValue | None, ...]

    def __post_init__(self) -> None:
        _require_text(self.segment_id, "segment_id")
        _require_bounded_integer(self.key_value, "key_value", -(1 << 63), INT64_MAX)
        if type(self.key_envelope) is not bytes or type(self.row_envelope) is not bytes:
            raise PostgresDataValidationError("PostgreSQL exact comparison envelopes must be bytes")
        if type(self.values) is not tuple:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison values must be an immutable tuple"
            )


@dataclass(frozen=True, slots=True)
class PostgresIntegerExactRowsRead:
    rows: tuple[PostgresIntegerExactRow, ...]
    metrics: PostgresReadMetrics


@dataclass(frozen=True, slots=True)
class PostgresRelationManifestRecord:
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: date
    source_cut: str | None
    dataset_version: str | None
    completed_at: datetime | None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("dataset_id", self.dataset_id),
            ("batch_id", self.batch_id),
            ("state", self.state),
        ):
            _require_text(value, field_name)
        _require_sha256_hex(self.scope_digest, "scope_digest")
        _require_optional_text(self.source_cut, "source_cut")
        _require_optional_text(self.dataset_version, "dataset_version")
        if type(self.business_date) is not date:
            raise PostgresDataValidationError(
                "PostgreSQL relation manifest business_date must be a date"
            )
        if self.completed_at is not None and (
            type(self.completed_at) is not datetime or self.completed_at.utcoffset() != timedelta(0)
        ):
            raise PostgresDataValidationError(
                "PostgreSQL relation manifest completed_at must be a UTC timestamptz"
            )


class ReadContextState(StrEnum):
    ACTIVE = "active"
    LOST = "lost"
    CLOSED = "closed"


type DatabaseRow = tuple[object, ...]
type ExecutableSql = LiteralString | sql.SQL | sql.Composed


@dataclass(frozen=True, slots=True)
class _PostgresRelationMemberCandidate:
    acquisition: PostgresRelationAcquisition
    relation: PostgresRelation
    relation_oid: int
    relation_row_type_oid: int
    namespace_oid: int
    relation_kind: PostgresRelationKind
    relation_persistence: str


@dataclass(frozen=True, slots=True)
class _PostgresRelationCandidate:
    acquisition: PostgresRelationAcquisition
    root_relation_oid: int
    members: tuple[_PostgresRelationMemberCandidate, ...]
    edges: tuple[PostgresInheritanceEdge, ...]


class PostgresReadContext:
    """One sequential PostgreSQL read-only Repeatable Read transaction."""

    def __init__(
        self,
        connection: psycopg.Connection[DatabaseRow],
        profile: PostgresServerProfile,
        evidence: PostgresReadContextEvidence,
        statement_timeout_milliseconds: int,
        source_budget: PostgresSourceBudgetAttempt,
        direction: PostgresSourceDirection,
    ) -> None:
        self._connection = connection
        self._profile = profile
        self._evidence = evidence
        self._statement_timeout_milliseconds = statement_timeout_milliseconds
        if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
            raise TypeError("PostgreSQL read context requires a source budget attempt")
        if not isinstance(cast(object, direction), PostgresSourceDirection):
            raise TypeError("PostgreSQL read context requires a source direction")
        self._source_budget = source_budget
        self._direction = direction
        self._state = ReadContextState.ACTIVE
        self._query_lock = Lock()

    @property
    def profile(self) -> PostgresServerProfile:
        return self._profile

    @property
    def evidence(self) -> PostgresReadContextEvidence:
        return self._evidence

    @property
    def state(self) -> ReadContextState:
        return self._state

    @property
    def source_budget(self) -> PostgresSourceBudgetAttempt:
        return self._source_budget

    @property
    def source_direction(self) -> PostgresSourceDirection:
        return self._direction

    def read_scalar_integer(
        self,
        statement: ExecutableSql,
        parameters: tuple[PostgresParameter, ...],
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> int:
        rows = self._execute_bounded(
            statement,
            parameters,
            1,
            max_record_bytes,
            max_total_bytes,
            0,
        )
        if len(rows) != 1 or len(rows[0]) != 1:
            raise PostgresDataValidationError(
                "PostgreSQL scalar integer query must return exactly one row and one column"
            )
        value = rows[0][0]
        if type(value) is not int:
            raise PostgresDataValidationError(
                "PostgreSQL scalar integer query returned a non-integer value"
            )
        return value

    def inspect_relation(
        self,
        schema: CanonicalSchema,
        relation: PostgresRelation,
        column_names: tuple[str, ...],
        max_metadata_record_bytes: int,
        max_metadata_total_bytes: int,
    ) -> PostgresInspectedRelation:
        _require_schema(schema)
        _require_relation(relation)
        _require_column_names(column_names, len(schema.fields))
        _validate_relation_identifiers(relation, self._profile.max_identifier_utf8_bytes)
        _validate_column_identifiers(column_names, self._profile.max_identifier_utf8_bytes)
        locked_row_type_oid = self._lock_relation(relation)
        relation_oid, relation_row_type_oid, relation_schema, relation_name = (
            self._resolve_relation(
                relation,
                max_metadata_record_bytes,
                max_metadata_total_bytes,
            )
        )
        if relation_row_type_oid != locked_row_type_oid:
            raise PostgresMetadataError(
                "PostgreSQL relation identity changed between lock acquisition and catalog "
                "inspection"
            )
        resolved_relation = PostgresRelation(components=(relation_schema, relation_name))
        if not column_names:
            bindings: tuple[PostgresFieldBinding, ...] = ()
        else:
            statement, parameters = _metadata_query(
                relation_oid,
                relation_schema,
                relation_name,
                column_names,
            )
            rows = self._execute_bounded(
                statement,
                parameters,
                len(column_names),
                max_metadata_record_bytes,
                max_metadata_total_bytes,
                0,
            )
            if len(rows) != len(column_names):
                raise PostgresMetadataError(
                    "PostgreSQL catalog query did not return one row per requested column: "
                    f"expected={len(column_names)}, actual={len(rows)}"
                )
            bindings = tuple(
                postgres_field_binding_from_catalog_row(
                    field.name,
                    column_name,
                    index,
                    row,
                )
                for index, (field, column_name, row) in enumerate(
                    zip(schema.fields, column_names, rows, strict=True)
                )
            )
        inspection = PostgresInspectedRelation(
            context_id=self._evidence.context_id,
            relation_oid=relation_oid,
            relation_row_type_oid=relation_row_type_oid,
            relation=resolved_relation,
            bindings=bindings,
            max_identifier_utf8_bytes=self._profile.max_identifier_utf8_bytes,
        )
        validate_postgres_inspection(schema, inspection)
        return inspection

    def read_canonical_rows(
        self,
        query: PostgresQuery,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[PostgresCanonicalRow, ...]:
        _validate_postgres_query(query)
        self._require_query_context(query)
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        minimum_record_budget = (
            query.max_encoded_envelope_bytes + SHA256_BYTES + _CANONICAL_STATUS_BYTES
        )
        if max_record_bytes < minimum_record_budget:
            raise ValueError(
                "max_record_bytes must reserve the configured envelope and SHA-256 digest: "
                f"required={minimum_record_budget}, actual={max_record_bytes}"
            )
        raw_record_overhead = _MAX_UINT32_DECIMAL_BYTES + _DATA_MARKER_BYTES
        raw_max_records = max_records + len(query.relations)
        rows = self._execute_compiled_query(
            query,
            raw_max_records,
            max_record_bytes + raw_record_overhead,
            max_total_bytes + (raw_max_records * raw_record_overhead),
            _query_physical_scan_count(query),
        )
        parsed: list[PostgresCanonicalRow] = []
        logical_total_bytes = 0
        for row in rows:
            canonical_row = _canonical_row_from_database(row, query)
            if canonical_row is None:
                continue
            if len(parsed) >= max_records:
                raise PostgresResultLimitError(
                    "PostgreSQL canonical query exceeded the reserved logical record budget: "
                    f"max_records={max_records}"
                )
            logical_record_bytes = (
                len(canonical_row.envelope) + SHA256_BYTES + _CANONICAL_STATUS_BYTES
            )
            observed_logical_total_bytes = logical_total_bytes + logical_record_bytes
            if observed_logical_total_bytes > max_total_bytes:
                raise PostgresResultLimitError(
                    "PostgreSQL canonical query exceeded the reserved logical total byte "
                    f"budget: observed_bytes={observed_logical_total_bytes}, "
                    f"max_total_bytes={max_total_bytes}"
                )
            parsed.append(canonical_row)
            logical_total_bytes = observed_logical_total_bytes
        return tuple(parsed)

    def read_fingerprint(
        self,
        query: PostgresQuery,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> Fingerprint:
        _validate_postgres_query(query)
        self._require_query_context(query)
        provenance_bytes = _query_provenance_bytes(query)
        rows = self._execute_compiled_query(
            query,
            1,
            max_record_bytes + provenance_bytes,
            max_total_bytes + provenance_bytes,
            _query_physical_scan_count(query),
        )
        if len(rows) != 1:
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint query must return exactly one row"
            )
        payload = _compiled_query_payload(rows[0], query, 11, "fingerprint")
        values = tuple(
            _parse_unsigned_decimal(value, 19 if index in (0, 9, 10) else 38)
            for index, value in enumerate(payload)
        )
        count = values[0]
        invalid_count = values[9]
        oversized_count = values[10]
        if count > INT64_MAX or invalid_count > INT64_MAX or oversized_count > INT64_MAX:
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint row count exceeds the signed int64 protocol bound"
            )
        if invalid_count > 0:
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint rejected source rows that cannot be represented "
                f"losslessly: invalid_row_count={invalid_count}"
            )
        if oversized_count > 0:
            raise PostgresResultLimitError(
                "PostgreSQL fingerprint rejected canonical envelopes above the configured "
                f"limit: oversized_row_count={oversized_count}, "
                f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
            )
        try:
            return Fingerprint(
                count=count,
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
            raise PostgresDataValidationError(
                "PostgreSQL fingerprint violates canonical accumulator bounds: "
                f"reason_type={type(error).__name__}"
            ) from None

    def read_integer_key_summary(
        self,
        query: PostgresQuery,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresIntegerKeySummaryRead:
        _validate_postgres_query(query)
        self._require_query_context(query)
        _require_postgres_read_deadline(deadline, "integer-key summary read")
        expected_full_scans = _query_physical_scan_count(query)
        _require_compiled_full_scan_reservation(
            full_scans,
            expected_full_scans,
            "integer-key summary",
        )
        provenance_bytes = _query_provenance_bytes(query)
        rows = self._execute_compiled_query_before_deadline(
            query,
            1,
            max_record_bytes + provenance_bytes,
            max_total_bytes + provenance_bytes,
            deadline,
            expected_full_scans,
        )
        if len(rows) != 1:
            raise PostgresDataValidationError(
                "PostgreSQL integer-key summary query must return exactly one row"
            )
        return PostgresIntegerKeySummaryRead(
            summary=_integer_key_summary_from_database(rows[0], query),
            metrics=_read_metrics_before_deadline(rows, deadline),
        )

    def read_integer_range_fingerprints(
        self,
        query: PostgresQuery,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresRangeFingerprintRead:
        _validate_postgres_query(query)
        self._require_query_context(query)
        _require_postgres_read_deadline(deadline, "integer-range fingerprint read")
        expected_full_scans = len(ranges) * _query_physical_scan_count(query)
        _require_compiled_full_scan_reservation(
            full_scans,
            expected_full_scans,
            "integer-range fingerprint",
        )
        provenance_bytes = _query_provenance_bytes(query)
        rows = self._execute_compiled_query_before_deadline(
            query,
            len(ranges),
            max_record_bytes + provenance_bytes,
            max_total_bytes + (len(ranges) * provenance_bytes),
            deadline,
            expected_full_scans,
        )
        parsed = _range_fingerprints_from_database(rows, ranges, query, deadline)
        return PostgresRangeFingerprintRead(
            ranges=parsed,
            metrics=_read_metrics_before_deadline(rows, deadline),
        )

    def read_integer_range_rows(
        self,
        query: PostgresQuery,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        key_field_index: int,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresIntegerExactRowsRead:
        _validate_postgres_query(query)
        self._require_query_context(query)
        _require_postgres_read_deadline(deadline, "integer-range exact read")
        expected_full_scans = len(ranges) * _query_physical_scan_count(query)
        _require_compiled_full_scan_reservation(
            full_scans,
            expected_full_scans,
            "integer-range exact",
        )
        raw_record_overhead = _query_provenance_bytes(query) + _DATA_MARKER_BYTES
        rows = self._execute_compiled_query_before_deadline(
            query,
            max_records,
            max_record_bytes + raw_record_overhead,
            max_total_bytes + (max_records * raw_record_overhead),
            deadline,
            expected_full_scans,
        )
        parsed = _integer_exact_rows_from_database(
            rows,
            ranges,
            key_field_index,
            query,
            deadline,
        )
        return PostgresIntegerExactRowsRead(
            rows=parsed,
            metrics=_exact_read_metrics(rows, query, deadline),
        )

    def close(self) -> None:
        failure: str | None = None
        with self._query_lock:
            if self._state is ReadContextState.CLOSED:
                return
            previous_state = self._state
            self._state = ReadContextState.CLOSED
            if previous_state is ReadContextState.ACTIVE:
                try:
                    self._connection.rollback()
                except psycopg.Error as error:
                    self._connection.close()
                    failure = _database_error_message("close read context", error)
            self._connection.close()
        if failure is not None:
            raise PostgresCloseError(failure)

    def _lock_relation(self, relation: PostgresRelation) -> int:
        # Parenthesized alias.* is a whole-row value even when a column shares the alias name.
        statement = sql.SQL(
            "SELECT CASE WHEN FALSE THEN (dfe_source.*) ELSE NULL END AS origin_type "
            "FROM ONLY {relation} AS dfe_source LIMIT 0"
        ).format(relation=sql.Identifier(*relation.components))
        database_failure: str | None = None
        metadata_failure: str | None = None
        row_type_oid: int | None = None
        with self._query_lock:
            self._require_active()
            cursor_name = f"dfe_{uuid4().hex}"
            try:
                self._restore_session_invariants()
                with self._connection.cursor(name=cursor_name) as cursor:
                    self._source_budget.dispatch_query(self._direction, 0)
                    cursor.execute(statement)
                    row_type_oid = _origin_type_oid(
                        cursor.description,
                        "relation lock",
                    )
            except psycopg.Error as error:
                self._state = ReadContextState.LOST
                self._connection.close()
                if error.sqlstate in ("42P01", "42501"):
                    metadata_failure = _database_error_message(
                        "lock relation for inspection",
                        error,
                    )
                else:
                    database_failure = _database_error_message(
                        "lock relation for inspection",
                        error,
                    )
        if metadata_failure is not None:
            raise PostgresMetadataError(metadata_failure)
        if database_failure is not None:
            raise PostgresQueryError(database_failure)
        if row_type_oid is None:
            raise AssertionError("PostgreSQL relation lock completed without row type provenance")
        return row_type_oid

    def _resolve_relation(
        self,
        relation: PostgresRelation,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[int, int, str, str]:
        statement, parameters = _relation_query(relation)
        rows = self._execute_bounded(
            statement,
            parameters,
            1,
            max_record_bytes,
            max_total_bytes,
            0,
        )
        if not rows:
            raise PostgresMetadataError(
                "PostgreSQL relation is missing, inaccessible, or not a supported physical "
                "regular table"
            )
        row = rows[0]
        if len(row) != 6:
            raise PostgresDataValidationError(
                "PostgreSQL relation catalog probe must return exactly six fields"
            )
        relation_oid = _require_bounded_integer(row[0], "relation OID", 1, UINT32_MAX)
        relation_row_type_oid = _require_bounded_integer(
            row[1],
            "relation row type OID",
            1,
            UINT32_MAX,
        )
        relation_schema = _require_text(row[2], "relation schema")
        relation_name = _require_text(row[3], "relation name")
        relation_kind = _require_text(row[4], "relation kind")
        has_select = _require_boolean(row[5], "relation SELECT privilege")
        if relation_kind != "r":
            raise PostgresMetadataError(
                "PostgreSQL relation kind is unsupported by the v1 physical-table profile: "
                f"relation_kind={relation_kind!r}, allowed=('r',)"
            )
        if not has_select:
            raise PostgresMetadataError(
                "PostgreSQL relation is visible but the read role lacks SELECT privilege"
            )
        return relation_oid, relation_row_type_oid, relation_schema, relation_name

    def _execute_bounded(
        self,
        statement: ExecutableSql,
        parameters: tuple[PostgresParameter, ...],
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        full_scans: int,
    ) -> tuple[DatabaseRow, ...]:
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        database_failure: str | None = None
        records: tuple[DatabaseRow, ...] | None = None
        with self._query_lock:
            self._require_active()
            cursor_name = f"dfe_{uuid4().hex}"
            try:
                self._restore_session_invariants()
                with self._connection.cursor(name=cursor_name) as cursor:
                    charge = self._source_budget.dispatch_query(self._direction, full_scans)
                    cursor.execute(statement, parameters)
                    records = _fetch_bounded_rows(
                        cursor,
                        max_records,
                        max_record_bytes,
                        max_total_bytes,
                        charge,
                    )
            except psycopg.Error as error:
                self._state = ReadContextState.LOST
                self._connection.close()
                database_failure = _database_error_message("execute read-only query", error)
        if database_failure is not None:
            raise PostgresQueryError(database_failure)
        if records is None:
            raise AssertionError("PostgreSQL bounded query completed without a result")
        return records

    def _execute_compiled_query(
        self,
        query: PostgresQuery,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        full_scans: int,
    ) -> tuple[DatabaseRow, ...]:
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        database_failure: str | None = None
        records: tuple[DatabaseRow, ...] | None = None
        with self._query_lock:
            self._require_active()
            cursor_name = f"dfe_{uuid4().hex}"
            try:
                self._restore_session_invariants()
                with self._connection.cursor(name=cursor_name) as cursor:
                    charge = self._source_budget.dispatch_query(self._direction, full_scans)
                    cursor.execute(
                        _executable_statement(query.statement),
                        query.parameters,
                    )
                    _require_compiled_origin_types(
                        cursor.description,
                        query.relations,
                    )
                    records = _fetch_bounded_rows(
                        cursor,
                        max_records,
                        max_record_bytes,
                        max_total_bytes,
                        charge,
                    )
            except psycopg.Error as error:
                self._state = ReadContextState.LOST
                self._connection.close()
                database_failure = _database_error_message("execute compiled query", error)
        if database_failure is not None:
            raise PostgresQueryError(database_failure)
        if records is None:
            raise AssertionError("PostgreSQL compiled query completed without a result")
        _require_compiled_query_provenance(records, query)
        return records

    def _execute_compiled_query_before_deadline(
        self,
        query: PostgresQuery,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> tuple[DatabaseRow, ...]:
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        _require_postgres_read_deadline(deadline, "compiled comparison query")
        database_failure: str | None = None
        records: tuple[DatabaseRow, ...] | None = None
        with self._query_lock:
            self._require_active()
            cursor_name = f"dfe_{uuid4().hex}"
            try:
                self._restore_session_invariants_before_deadline(
                    deadline,
                    "compiled comparison query",
                )
                with self._connection.cursor(name=cursor_name) as cursor:
                    charge = self._source_budget.dispatch_query(self._direction, full_scans)
                    cursor.execute(
                        _executable_statement(query.statement),
                        query.parameters,
                    )
                    _require_compiled_origin_types(
                        cursor.description,
                        query.relations,
                    )
                    records = self._fetch_bounded_rows_before_deadline(
                        cursor,
                        max_records,
                        max_record_bytes,
                        max_total_bytes,
                        deadline,
                        charge,
                    )
            except psycopg.Error as error:
                self._state = ReadContextState.LOST
                self._connection.close()
                database_failure = _database_error_message(
                    "execute deadline-bounded compiled query",
                    error,
                )
        if database_failure is not None:
            raise PostgresQueryError(database_failure)
        if records is None:
            raise AssertionError(
                "PostgreSQL deadline-bounded compiled query completed without a result"
            )
        _require_compiled_query_provenance(records, query)
        return records

    def _fetch_bounded_rows_before_deadline(
        self,
        cursor: ServerCursor[DatabaseRow],
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        charge: PostgresSourceQueryCharge,
    ) -> tuple[DatabaseRow, ...]:
        records: list[DatabaseRow] = []
        total_bytes = 0
        while True:
            _require_postgres_read_deadline(deadline, "comparison portal fetch")
            charge.require_fetch_deadline()
            remaining = max_records + 1 - len(records)
            fetch_records = min(_CURSOR_FETCH_RECORDS, remaining)
            batch = cursor.fetchmany(fetch_records)
            if not batch:
                break
            batch_bytes = tuple(_database_row_bytes(row) for row in batch)
            charge.consume_records(batch_bytes)
            _require_postgres_read_deadline(deadline, "comparison portal fetch")
            observed_records = len(records) + len(batch)
            observed_bytes = total_bytes + sum(batch_bytes)
            if observed_records > max_records:
                raise PostgresResultLimitError(
                    "PostgreSQL query exceeded the reserved record budget: "
                    f"max_records={max_records}"
                )
            oversized_record = next(
                (value for value in batch_bytes if value > max_record_bytes),
                None,
            )
            if oversized_record is not None:
                raise PostgresResultLimitError(
                    "PostgreSQL query returned a record above the byte budget: "
                    f"record_bytes={oversized_record}, max_record_bytes={max_record_bytes}"
                )
            if observed_bytes > max_total_bytes:
                raise PostgresResultLimitError(
                    "PostgreSQL query exceeded the total byte budget: "
                    f"observed_bytes={observed_bytes}, max_total_bytes={max_total_bytes}"
                )
            total_bytes = observed_bytes
            records.extend(batch)
            if len(batch) < fetch_records:
                break
        return tuple(records)

    def _restore_session_invariants_before_deadline(
        self,
        deadline: PostgresReadDeadline,
        operation: str,
    ) -> None:
        timeout_milliseconds = _deadline_statement_timeout_milliseconds(
            self._statement_timeout_milliseconds,
            deadline,
            operation,
        )
        _execute_source_command(
            self._connection,
            "SELECT pg_catalog.set_config('search_path', 'pg_catalog', true), "
            "pg_catalog.set_config('row_security', 'off', true), "
            "pg_catalog.set_config('TimeZone', 'UTC', true), "
            "pg_catalog.set_config('DateStyle', 'ISO, YMD', true), "
            "pg_catalog.set_config('statement_timeout', %s, true)",
            (str(timeout_milliseconds),),
            self._source_budget,
            self._direction,
        )

    def _execute_origin_checked_query(
        self,
        statement: ExecutableSql,
        parameters: tuple[PostgresParameter, ...],
        expected_row_type_oid: int,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[DatabaseRow, ...]:
        _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
        database_failure: str | None = None
        records: tuple[DatabaseRow, ...] | None = None
        with self._query_lock:
            self._require_active()
            cursor_name = f"dfe_{uuid4().hex}"
            try:
                self._restore_session_invariants()
                with self._connection.cursor(name=cursor_name) as cursor:
                    charge = self._source_budget.dispatch_query(self._direction, 0)
                    cursor.execute(statement, parameters)
                    _require_relation_manifest_description(
                        cursor.description,
                        expected_row_type_oid,
                    )
                    records = _fetch_bounded_rows(
                        cursor,
                        max_records,
                        max_record_bytes,
                        max_total_bytes,
                        charge,
                    )
            except psycopg.Error as error:
                self._state = ReadContextState.LOST
                self._connection.close()
                database_failure = _database_error_message(
                    "execute protected relation manifest query",
                    error,
                )
        if database_failure is not None:
            raise PostgresQueryError(database_failure)
        if records is None:
            raise AssertionError("PostgreSQL relation manifest query completed without a result")
        return records

    def _restore_session_invariants(self) -> None:
        _execute_source_command(
            self._connection,
            "SELECT pg_catalog.set_config('search_path', 'pg_catalog', true), "
            "pg_catalog.set_config('row_security', 'off', true), "
            "pg_catalog.set_config('TimeZone', 'UTC', true), "
            "pg_catalog.set_config('DateStyle', 'ISO, YMD', true), "
            "pg_catalog.set_config('statement_timeout', %s, true)",
            (str(self._effective_statement_timeout_milliseconds()),),
            self._source_budget,
            self._direction,
        )

    def _effective_statement_timeout_milliseconds(self) -> int:
        remaining_nanoseconds = (
            self._source_budget.remaining().deadline_nanoseconds - time.monotonic_ns()
        )
        if remaining_nanoseconds <= 0:
            raise PostgresReadDeadlineExceededError(
                "PostgreSQL session setup exceeded the immutable whole-run source deadline"
            )
        remaining_milliseconds = max(1, remaining_nanoseconds // 1_000_000)
        return min(self._statement_timeout_milliseconds, remaining_milliseconds)

    def _require_query_context(self, query: PostgresQuery) -> None:
        for index, relation in enumerate(query.relations):
            query_context_id = relation.inspection.context_id
            if query_context_id != self._evidence.context_id:
                raise PostgresQueryContextError(
                    "PostgreSQL compiled query relation belongs to a different read context: "
                    f"index={index}, query_context_id={query_context_id}, "
                    f"active_context_id={self._evidence.context_id}"
                )

    def _require_active(self) -> None:
        if self._state is ReadContextState.CLOSED:
            raise PostgresContextClosedError("PostgreSQL read context is already closed")
        if self._state is ReadContextState.LOST:
            raise PostgresContextLostError(
                "PostgreSQL transaction context was lost and cannot be reused"
            )


@dataclass(frozen=True, slots=True, repr=False)
class _ProtectedAcquisitionReceipt:
    read_context: PostgresReadContext
    protected_relations: tuple[PostgresProtectedRelationInspection, ...]


class PostgresProtectedReadContext:
    """A pre-acquired set of physical relations in one protected snapshot."""

    def __init__(
        self,
        read_context: PostgresReadContext,
        protected_relations: tuple[PostgresProtectedRelationInspection, ...],
        acquisition_receipt: object,
    ) -> None:
        self._read_context = read_context
        self._protected_relations = protected_relations
        self._acquisition_receipt = acquisition_receipt
        self._require_protected_context_invariant()

    @property
    def profile(self) -> PostgresServerProfile:
        return self._read_context.profile

    @property
    def evidence(self) -> PostgresProtectedReadContextEvidence:
        return self._require_protected_context_invariant()

    @property
    def protected_relations(self) -> tuple[PostgresProtectedRelationInspection, ...]:
        self._require_protected_context_invariant()
        return self._protected_relations

    @property
    def state(self) -> ReadContextState:
        return self._read_context.state

    @property
    def source_budget(self) -> PostgresSourceBudgetAttempt:
        return self._read_context.source_budget

    @property
    def source_direction(self) -> PostgresSourceDirection:
        return self._read_context.source_direction

    def read_canonical_rows(
        self,
        protected_relation: PostgresProtectedRelationInspection,
        max_encoded_envelope_bytes: int,
        max_records: int,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[PostgresCanonicalRow, ...]:
        self._require_protected_relation(protected_relation)
        query = self._build_row_envelope_query(
            protected_relation.acquisition.schema,
            protected_relation.query_relations(),
            max_encoded_envelope_bytes,
        )
        return self._read_context.read_canonical_rows(
            query,
            max_records,
            max_record_bytes,
            max_total_bytes,
        )

    def read_fingerprint(
        self,
        protected_relation: PostgresProtectedRelationInspection,
        max_encoded_envelope_bytes: int,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> Fingerprint:
        self._require_protected_relation(protected_relation)
        query = self._build_fingerprint_query(
            protected_relation.acquisition.schema,
            protected_relation.query_relations(),
            max_encoded_envelope_bytes,
        )
        return self._read_context.read_fingerprint(
            query,
            max_record_bytes,
            max_total_bytes,
        )

    def read_integer_key_summary(
        self,
        protected_relation: PostgresProtectedRelationInspection,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        max_encoded_envelope_bytes: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresIntegerKeySummaryRead:
        self._require_protected_relation(protected_relation)
        query = self._build_integer_key_summary_query(
            protected_relation.acquisition.schema,
            protected_relation.query_relations(),
            key_field_index,
            scope,
            max_encoded_envelope_bytes,
        )
        return self._read_context.read_integer_key_summary(
            query,
            max_record_bytes,
            max_total_bytes,
            deadline,
            full_scans,
        )

    def read_integer_range_fingerprints(
        self,
        protected_relation: PostgresProtectedRelationInspection,
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
        max_record_bytes: int,
        max_total_bytes: int,
        deadline: PostgresReadDeadline,
        full_scans: int,
    ) -> PostgresRangeFingerprintRead:
        self._require_protected_relation(protected_relation)
        query = self._build_integer_range_fingerprint_query(
            protected_relation.acquisition.schema,
            protected_relation.query_relations(),
            key_field_index,
            scope,
            ranges,
            max_encoded_envelope_bytes,
        )
        return self._read_context.read_integer_range_fingerprints(
            query,
            ranges,
            max_record_bytes,
            max_total_bytes,
            deadline,
            full_scans,
        )

    def read_integer_range_rows(
        self,
        protected_relation: PostgresProtectedRelationInspection,
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
        self._require_protected_relation(protected_relation)
        query = build_postgres_union_integer_range_rows_query(
            protected_relation.acquisition.schema,
            protected_relation.query_relations(),
            key_field_index,
            scope,
            ranges,
            max_encoded_envelope_bytes,
        )
        return self._read_context.read_integer_range_rows(
            query,
            ranges,
            key_field_index,
            max_records,
            max_record_bytes,
            max_total_bytes,
            deadline,
            full_scans,
        )

    def _build_row_envelope_query(
        self,
        schema: CanonicalSchema,
        relations: tuple[PostgresQueryRelation, ...],
        max_encoded_envelope_bytes: int,
    ) -> PostgresQuery:
        return build_postgres_union_row_envelope_query(
            schema,
            relations,
            max_encoded_envelope_bytes,
        )

    def _build_fingerprint_query(
        self,
        schema: CanonicalSchema,
        relations: tuple[PostgresQueryRelation, ...],
        max_encoded_envelope_bytes: int,
    ) -> PostgresQuery:
        return build_postgres_union_fingerprint_query(
            schema,
            relations,
            max_encoded_envelope_bytes,
        )

    def _build_integer_range_fingerprint_query(
        self,
        schema: CanonicalSchema,
        relations: tuple[PostgresQueryRelation, ...],
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        ranges: tuple[PostgresIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
    ) -> PostgresQuery:
        return build_postgres_union_integer_range_fingerprint_query(
            schema,
            relations,
            key_field_index,
            scope,
            ranges,
            max_encoded_envelope_bytes,
        )

    def _build_integer_key_summary_query(
        self,
        schema: CanonicalSchema,
        relations: tuple[PostgresQueryRelation, ...],
        key_field_index: int,
        scope: PostgresScopePredicate | None,
        max_encoded_envelope_bytes: int,
    ) -> PostgresQuery:
        return build_postgres_union_integer_key_summary_query(
            schema,
            relations,
            key_field_index,
            scope,
            max_encoded_envelope_bytes,
        )

    def read_relation_manifest(
        self,
        protected_relation: PostgresProtectedRelationInspection,
        columns: ReadinessManifestColumns,
        dataset_id: str,
        scope_digest: str,
        max_record_bytes: int,
        max_total_bytes: int,
    ) -> tuple[PostgresRelationManifestRecord, ...]:
        self._require_protected_relation(protected_relation)
        _require_readiness_manifest_columns(columns)
        _require_nonempty_query_text(dataset_id, "dataset_id")
        _validate_scope_digest_input(scope_digest)
        _validate_result_limits(2, max_record_bytes, max_total_bytes)
        _validate_column_identifiers(
            columns.values(),
            self.profile.max_identifier_utf8_bytes,
        )
        _validate_relation_manifest_contract(protected_relation, columns)
        _validate_relation_manifest_bindings(protected_relation.inspection, columns)
        statement = _relation_manifest_query(protected_relation.inspection.relation, columns)
        rows = self._read_context._execute_origin_checked_query(  # pyright: ignore[reportPrivateUsage]
            statement,
            (dataset_id, scope_digest),
            protected_relation.inspection.relation_row_type_oid,
            2,
            max_record_bytes,
            max_total_bytes,
        )
        return tuple(_relation_manifest_record_from_database(row) for row in rows)

    def _require_protected_relation(
        self,
        protected_relation: PostgresProtectedRelationInspection,
    ) -> None:
        _require_protected_relation_inspection(protected_relation)
        self._require_protected_context_invariant()
        if not any(candidate is protected_relation for candidate in self._protected_relations):
            raise PostgresQueryContextError(
                "PostgreSQL relation inspection does not belong to the exact pre-acquired "
                "protected set: "
                f"relation={protected_relation.inspection.relation.components!r}, "
                f"relation_oid={protected_relation.inspection.relation_oid}"
            )

    def _require_protected_context_invariant(
        self,
    ) -> PostgresProtectedReadContextEvidence:
        _validate_protected_acquisition_receipt(
            self._acquisition_receipt,
            self._read_context,
            self._protected_relations,
        )
        return _validate_protected_context_closure(
            self._read_context,
            self._protected_relations,
        )

    def close(self) -> None:
        self._read_context.close()


def _validate_protected_acquisition_receipt(
    acquisition_receipt: object,
    read_context: PostgresReadContext,
    protected_relations: tuple[PostgresProtectedRelationInspection, ...],
) -> None:
    if not isinstance(acquisition_receipt, _ProtectedAcquisitionReceipt):
        raise PostgresQueryContextError(
            "PostgreSQL protected context requires an internal acquisition receipt"
        )
    if acquisition_receipt.read_context is not read_context:
        raise PostgresQueryContextError(
            "PostgreSQL protected context acquisition receipt belongs to a different read context"
        )
    if acquisition_receipt.protected_relations is not protected_relations:
        raise PostgresQueryContextError(
            "PostgreSQL protected context acquisition receipt belongs to a different relation tuple"
        )


def _validate_protected_context_closure(
    read_context: object,
    protected_relations: object,
) -> PostgresProtectedReadContextEvidence:
    if not isinstance(read_context, PostgresReadContext):
        raise TypeError("read_context must be a PostgresReadContext")
    evidence = read_context.evidence
    if not isinstance(evidence, PostgresProtectedReadContextEvidence):
        raise PostgresQueryContextError(
            "PostgreSQL protected context requires protected acquisition evidence"
        )
    if evidence.strategy != "protected_read_only_repeatable_read":
        raise PostgresQueryContextError(
            "PostgreSQL protected context evidence has an unexpected acquisition strategy: "
            f"strategy={evidence.strategy!r}"
        )
    if evidence.lock_mode != "access_share":
        raise PostgresQueryContextError(
            "PostgreSQL protected context evidence must assert an AccessShareLock"
        )
    if evidence.relation_persistence is not PostgresRelationPersistence.PERMANENT:
        raise PostgresQueryContextError(
            "PostgreSQL protected context evidence must assert permanent relations"
        )
    if evidence.acquired_before_snapshot is not True:
        raise PostgresQueryContextError(
            "PostgreSQL protected context evidence must assert acquisition before the snapshot"
        )
    if type(evidence.locked_relation_oids) is not tuple or not evidence.locked_relation_oids:
        raise PostgresQueryContextError(
            "PostgreSQL protected context evidence must contain locked relation OIDs"
        )
    for index, relation_oid in enumerate(evidence.locked_relation_oids):
        if type(relation_oid) is not int or not 1 <= relation_oid <= UINT32_MAX:
            raise PostgresQueryContextError(
                "PostgreSQL protected context evidence contains an invalid locked relation OID: "
                f"index={index}, relation_oid={relation_oid!r}"
            )
    if len(set(evidence.locked_relation_oids)) != len(evidence.locked_relation_oids):
        raise PostgresQueryContextError(
            "PostgreSQL protected context evidence contains duplicate locked relation OIDs"
        )
    if type(protected_relations) is not tuple or not protected_relations:
        raise PostgresQueryContextError(
            "PostgreSQL protected context must contain an immutable non-empty relation tuple"
        )

    typed_relations = cast(tuple[object, ...], protected_relations)
    members_by_oid: dict[
        int,
        tuple[PostgresRelation, int, int, PostgresRelationKind],
    ] = {}
    previous_relation: tuple[str, ...] | None = None
    for index, value in enumerate(typed_relations):
        if not isinstance(value, PostgresProtectedRelationInspection):
            raise PostgresQueryContextError(
                "PostgreSQL protected context contains an invalid relation inspection: "
                f"index={index}, type={type(value).__name__}"
            )
        protected = value
        inspection = protected.inspection
        acquisition = protected.acquisition
        if inspection.context_id != evidence.context_id:
            raise PostgresQueryContextError(
                "PostgreSQL protected relation belongs to a different read context: "
                f"index={index}, relation_context_id={inspection.context_id}, "
                f"evidence_context_id={evidence.context_id}"
            )
        if inspection.relation != acquisition.relation:
            raise PostgresQueryContextError(
                "PostgreSQL protected relation inspection is outside its acquisition closure: "
                f"index={index}"
            )
        binding_columns = tuple(binding.column_name for binding in inspection.bindings)
        if binding_columns != acquisition.column_names:
            raise PostgresQueryContextError(
                "PostgreSQL protected relation columns differ from the acquired column closure: "
                f"index={index}, acquired={acquisition.column_names!r}, "
                f"inspected={binding_columns!r}"
            )
        validate_postgres_inspection(acquisition.schema, inspection)
        if protected.lock_mode != "access_share":
            raise PostgresQueryContextError(
                f"PostgreSQL protected relation must assert an AccessShareLock: index={index}"
            )
        if protected.relation_persistence is not PostgresRelationPersistence.PERMANENT:
            raise PostgresQueryContextError(
                f"PostgreSQL protected relation must assert permanent persistence: index={index}"
            )
        if protected.acquired_before_snapshot is not True:
            raise PostgresQueryContextError(
                "PostgreSQL protected relation must assert acquisition before the snapshot: "
                f"index={index}"
            )
        relation_components = inspection.relation.components
        if previous_relation is not None and relation_components < previous_relation:
            raise PostgresQueryContextError(
                "PostgreSQL protected relations must remain in deterministic qualified-name "
                f"order: index={index}"
            )
        previous_relation = relation_components
        if protected.composition is None:
            member_closure = (
                PostgresProtectedRelationMember(
                    inspection=inspection,
                    namespace_oid=protected.namespace_oid,
                    relation_kind=PostgresRelationKind.REGULAR,
                    relation_persistence=protected.relation_persistence,
                ),
            )
        else:
            member_closure = protected.composition.members
        for member_index, member in enumerate(member_closure):
            member_inspection = member.inspection
            if member_inspection.context_id != evidence.context_id:
                raise PostgresQueryContextError(
                    "PostgreSQL protected member belongs to a different read context: "
                    f"relation_index={index}, member_index={member_index}"
                )
            member_binding_columns = tuple(
                binding.column_name for binding in member_inspection.bindings
            )
            if member_binding_columns != acquisition.column_names:
                raise PostgresQueryContextError(
                    "PostgreSQL protected member columns differ from the acquired column "
                    f"closure: relation_index={index}, member_index={member_index}"
                )
            validate_postgres_inspection(acquisition.schema, member_inspection)
            identity = (
                member_inspection.relation,
                member_inspection.relation_row_type_oid,
                member.namespace_oid,
                member.relation_kind,
            )
            previous_identity = members_by_oid.get(member_inspection.relation_oid)
            if previous_identity is not None and previous_identity != identity:
                raise PostgresQueryContextError(
                    "PostgreSQL protected member OID maps to conflicting inspected "
                    f"identities: relation_oid={member_inspection.relation_oid}"
                )
            members_by_oid[member_inspection.relation_oid] = identity

    expected_lock_closure = tuple(
        relation_oid
        for relation_oid, _identity in sorted(
            members_by_oid.items(),
            key=lambda item: (item[1][0].components, item[0]),
        )
    )
    if evidence.locked_relation_oids != expected_lock_closure:
        raise PostgresQueryContextError(
            "PostgreSQL protected evidence does not exactly match the deduplicated relation "
            "lock closure: "
            f"evidence={evidence.locked_relation_oids!r}, expected={expected_lock_closure!r}"
        )
    return evidence


def open_postgres_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresReadContext:
    failure_message: str | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        try:
            return _open_once(settings, source_budget, direction)
        except psycopg.OperationalError as error:
            failure_message = _connection_error_message(settings, attempt, error)
            LOGGER.warning(
                "PostgreSQL connection attempt failed",
                extra={
                    "operation": "open_read_context",
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "dbname": settings.dbname,
                    "user": settings.user,
                    "sslmode": settings.sslmode.value,
                    "error_type": type(error).__name__,
                    "sqlstate": error.sqlstate,
                },
            )
            if attempt < retry_policy.max_attempts:
                time.sleep(retry_policy.delay_seconds)
        except psycopg.Error as error:
            failure_message = _connection_error_message(settings, attempt, error)
            break
    if failure_message is None:
        raise AssertionError("connection retry loop ended without an attempt")
    raise PostgresConnectionError(failure_message)


def open_postgres_protected_read_context(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    acquisitions: tuple[PostgresRelationAcquisition, ...],
    lock_timeout_milliseconds: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresProtectedReadContext:
    ordered_acquisitions = _validate_and_order_acquisitions(acquisitions)
    _validate_protected_lock_timeout(
        lock_timeout_milliseconds,
        settings.statement_timeout_milliseconds,
    )
    for acquisition_attempt in range(1, retry_policy.max_attempts + 1):
        connection = _connect_protected(settings, retry_policy, source_budget)
        try:
            return _open_protected_once(
                connection,
                settings,
                ordered_acquisitions,
                lock_timeout_milliseconds,
                source_budget,
                direction,
            )
        except PostgresAcquisitionRaceError as error:
            LOGGER.warning(
                "PostgreSQL protected relation identity changed during acquisition",
                extra={
                    "operation": "open_protected_read_context",
                    "attempt": acquisition_attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "dbname": settings.dbname,
                    "user": settings.user,
                    "error_type": type(error).__name__,
                },
            )
            if acquisition_attempt == retry_policy.max_attempts:
                raise PostgresAcquisitionRaceError(
                    "PostgreSQL protected relation identity did not stabilize within the "
                    "bounded acquisition attempts: "
                    f"host={settings.host!r}, port={settings.port}, "
                    f"dbname={settings.dbname!r}, user={settings.user!r}, "
                    f"attempts={acquisition_attempt}, last_failure={error}"
                ) from None
            time.sleep(retry_policy.delay_seconds)
        except psycopg.Error as error:
            raise PostgresConnectionError(
                _protected_acquisition_database_error_message(settings, error)
            ) from None
    raise AssertionError("protected acquisition retry loop ended without an attempt")


def _connect_protected(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    source_budget: PostgresSourceBudgetAttempt,
) -> psycopg.Connection[DatabaseRow]:
    failure_message: str | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
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
        except psycopg.OperationalError as error:
            failure_message = _connection_error_message(settings, attempt, error)
            LOGGER.warning(
                "PostgreSQL protected connection attempt failed",
                extra={
                    "operation": "connect_protected_read_context",
                    "attempt": attempt,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "dbname": settings.dbname,
                    "user": settings.user,
                    "sslmode": settings.sslmode.value,
                    "error_type": type(error).__name__,
                    "sqlstate": error.sqlstate,
                },
            )
            if attempt < retry_policy.max_attempts:
                time.sleep(retry_policy.delay_seconds)
        except psycopg.Error as error:
            raise PostgresConnectionError(
                _connection_error_message(settings, attempt, error)
            ) from None
    if failure_message is None:
        raise AssertionError("protected connection retry loop ended without an attempt")
    raise PostgresConnectionError(failure_message)


def _open_once(
    settings: PostgresConnectionSettings,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresReadContext:
    connection = psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password.get_secret_value(),
        sslmode=settings.sslmode.value,
        connect_timeout=settings.connect_timeout_seconds,
        application_name=settings.application_name,
        autocommit=True,
        row_factory=tuple_row,
    )
    started_at = datetime.now(UTC)
    try:
        _execute_source_command(
            connection,
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
            (),
            source_budget,
            direction,
        )
        _execute_source_command(
            connection,
            "SELECT pg_catalog.set_config('search_path', 'pg_catalog', true), "
            "pg_catalog.set_config('row_security', 'off', true), "
            "pg_catalog.set_config('TimeZone', 'UTC', true), "
            "pg_catalog.set_config('DateStyle', 'ISO, YMD', true), "
            "pg_catalog.set_config('statement_timeout', %s, true)",
            (str(source_budget.effective_statement_timeout_milliseconds()),),
            source_budget,
            direction,
        )
        rows = _execute_setup_bounded(
            connection,
            "SELECT pg_catalog.current_setting('server_version'), "
            "pg_catalog.current_setting('server_version_num')::integer, "
            "pg_catalog.current_setting('server_encoding'), "
            "pg_catalog.current_setting('client_encoding'), "
            "pg_catalog.current_setting('integer_datetimes') = 'on', "
            "pg_catalog.current_setting('TimeZone'), "
            "pg_catalog.current_setting('max_identifier_length')::integer, "
            "pg_catalog.pg_backend_pid(), pg_catalog.pg_current_snapshot()::text, "
            "pg_catalog.current_setting('transaction_isolation'), "
            "pg_catalog.current_setting('transaction_read_only') = 'on'",
            (),
            1,
            4096,
            4096,
            source_budget,
            direction,
        )
        if not rows:
            raise PostgresDataValidationError("PostgreSQL capability probe returned no row")
        row = rows[0]
        profile, evidence = _profile_and_evidence(row, started_at)
        _validate_profile(profile, row)
    except psycopg.Error:
        connection.close()
        raise
    except PostgresConnectorError:
        connection.close()
        raise
    return PostgresReadContext(
        connection,
        profile,
        evidence,
        settings.statement_timeout_milliseconds,
        source_budget,
        direction,
    )


def _open_protected_once(
    connection: psycopg.Connection[DatabaseRow],
    settings: PostgresConnectionSettings,
    acquisitions: tuple[PostgresRelationAcquisition, ...],
    lock_timeout_milliseconds: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresProtectedReadContext:
    succeeded = False
    try:
        candidates = tuple(
            _discover_relation_candidate(connection, acquisition, source_budget, direction)
            for acquisition in acquisitions
        )
        lock_candidates = _unique_lock_candidates(candidates)
        started_at = datetime.now(UTC)
        _execute_source_command(
            connection,
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
            (),
            source_budget,
            direction,
        )
        for candidate in lock_candidates:
            _configure_protected_lock_timeouts(
                connection,
                settings.statement_timeout_milliseconds,
                lock_timeout_milliseconds,
                source_budget,
                direction,
            )
            _lock_candidate_relation(connection, candidate, source_budget, direction)
        _configure_protected_statement_timeout(
            connection,
            settings.statement_timeout_milliseconds,
            source_budget,
            direction,
        )
        _configure_protected_snapshot_invariants(connection, source_budget, direction)
        profile, evidence = _capture_protected_snapshot(
            connection,
            lock_candidates,
            started_at,
            source_budget,
            direction,
        )
        protected_relations = tuple(
            _inspect_protected_candidate(
                connection,
                candidate,
                profile,
                evidence,
                source_budget,
                direction,
            )
            for candidate in candidates
        )
        read_context = PostgresReadContext(
            connection,
            profile,
            evidence,
            settings.statement_timeout_milliseconds,
            source_budget,
            direction,
        )
        acquisition_receipt = _ProtectedAcquisitionReceipt(
            read_context=read_context,
            protected_relations=protected_relations,
        )
        context = PostgresProtectedReadContext(
            read_context,
            protected_relations,
            acquisition_receipt,
        )
        succeeded = True
        return context
    finally:
        if not succeeded:
            connection.close()


def _validate_and_order_acquisitions(
    acquisitions: object,
) -> tuple[PostgresRelationAcquisition, ...]:
    if type(acquisitions) is not tuple:
        raise TypeError("acquisitions must be an immutable tuple")
    typed_acquisitions = cast(tuple[object, ...], acquisitions)
    if not typed_acquisitions:
        raise ValueError("acquisitions must contain at least one physical relation")
    for index, acquisition in enumerate(typed_acquisitions):
        if not isinstance(acquisition, PostgresRelationAcquisition):
            raise TypeError(
                f"acquisitions must contain only PostgresRelationAcquisition values: index={index}"
            )
    return tuple(
        sorted(
            cast(tuple[PostgresRelationAcquisition, ...], typed_acquisitions),
            key=lambda acquisition: acquisition.relation.components,
        )
    )


def _validate_protected_lock_timeout(
    lock_timeout_milliseconds: object,
    statement_timeout_milliseconds: int,
) -> None:
    _validate_positive_integer(lock_timeout_milliseconds, "lock_timeout_milliseconds")
    if cast(int, lock_timeout_milliseconds) >= statement_timeout_milliseconds:
        raise ValueError(
            "lock_timeout_milliseconds must be less than statement_timeout_milliseconds: "
            f"lock={lock_timeout_milliseconds}, statement={statement_timeout_milliseconds}"
        )


def _discover_relation_candidate(
    connection: psycopg.Connection[DatabaseRow],
    acquisition: PostgresRelationAcquisition,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> _PostgresRelationCandidate:
    if acquisition.relation_scope is RelationScope.PHYSICAL_ONLY:
        return _discover_physical_relation_candidate(
            connection,
            acquisition,
            source_budget,
            direction,
        )
    if acquisition.relation_scope is RelationScope.FROZEN_PHYSICAL_UNION:
        return _discover_frozen_relation_candidate(
            connection,
            acquisition,
            source_budget,
            direction,
        )
    raise ValueError("PostgreSQL acquisition has an unsupported relation scope")


def _discover_physical_relation_candidate(
    connection: psycopg.Connection[DatabaseRow],
    acquisition: PostgresRelationAcquisition,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> _PostgresRelationCandidate:
    statement = sql.SQL(
        "SELECT c.oid::bigint, c.reltype::bigint, n.oid::bigint, n.nspname, c.relname, "
        "c.relkind::text, c.relpersistence::text, "
        "pg_catalog.has_table_privilege(c.oid, 'SELECT'), "
        "c.relrowsecurity, c.relforcerowsecurity, "
        "pg_catalog.has_schema_privilege(n.oid, 'USAGE'), "
        "pg_catalog.current_setting('max_identifier_length')::integer "
        "FROM pg_catalog.pg_class AS c "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = %s AND c.relname = %s"
    )
    rows = _execute_pretransaction_candidate_bounded(
        connection,
        statement,
        acquisition.relation.components,
        1,
        acquisition.max_metadata_record_bytes,
        acquisition.max_metadata_total_bytes,
        source_budget,
        direction,
    )
    if not rows:
        raise PostgresMetadataError(
            "PostgreSQL protected relation is missing or inaccessible during candidate "
            f"discovery: relation={acquisition.relation.components!r}"
        )
    row = rows[0]
    if len(row) != 12:
        raise PostgresDataValidationError(
            "PostgreSQL physical candidate discovery must return exactly twelve typed fields"
        )
    member = _physical_member_candidate_from_row(acquisition, row)
    max_identifier_utf8_bytes = _require_bounded_integer(
        row[11],
        "candidate max_identifier_length",
        1,
        INT64_MAX,
    )
    _validate_relation_identifiers(acquisition.relation, max_identifier_utf8_bytes)
    _validate_column_identifiers(acquisition.column_names, max_identifier_utf8_bytes)
    return _PostgresRelationCandidate(
        acquisition=acquisition,
        root_relation_oid=member.relation_oid,
        members=(member,),
        edges=(),
    )


def _physical_member_candidate_from_row(
    acquisition: PostgresRelationAcquisition,
    row: DatabaseRow,
) -> _PostgresRelationMemberCandidate:
    member = _member_candidate_from_values(acquisition, row[:11])
    if member.relation != acquisition.relation:
        raise PostgresMetadataError(
            "PostgreSQL relation identity changed during physical acquisition: "
            f"requested={acquisition.relation.components!r}, "
            f"actual={member.relation.components!r}"
        )
    if member.relation_kind is not PostgresRelationKind.REGULAR:
        raise PostgresMetadataError(
            "PostgreSQL physical_only acquisition requires a regular table: "
            f"relation={member.relation.components!r}, "
            f"relation_kind={member.relation_kind.value!r}"
        )
    return member


def _discover_frozen_relation_candidate(
    connection: psycopg.Connection[DatabaseRow],
    acquisition: PostgresRelationAcquisition,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> _PostgresRelationCandidate:
    statement = sql.SQL(
        "WITH RECURSIVE dfe_root AS ("
        "SELECT c.oid FROM pg_catalog.pg_class AS c "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = %s AND c.relname = %s"
        "), dfe_members(relation_oid) AS ("
        "SELECT dfe_root.oid FROM dfe_root UNION "
        "SELECT inheritance.inhrelid FROM pg_catalog.pg_inherits AS inheritance "
        "JOIN dfe_members ON inheritance.inhparent = dfe_members.relation_oid"
        ") SELECT c.oid::bigint, c.reltype::bigint, n.oid::bigint, n.nspname, c.relname, "
        "c.relkind::text, c.relpersistence::text, "
        "pg_catalog.has_table_privilege(c.oid, 'SELECT'), "
        "c.relrowsecurity, c.relforcerowsecurity, "
        "pg_catalog.has_schema_privilege(n.oid, 'USAGE'), "
        "c.oid = dfe_root.oid, inheritance.inhparent::bigint, "
        "inheritance.inhseqno::integer, inheritance.inhdetachpending, "
        "pg_catalog.current_setting('max_identifier_length')::integer "
        "FROM dfe_members JOIN pg_catalog.pg_class AS c "
        "ON c.oid = dfe_members.relation_oid "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
        "CROSS JOIN dfe_root LEFT JOIN pg_catalog.pg_inherits AS inheritance "
        "ON inheritance.inhrelid = c.oid "
        "AND inheritance.inhparent IN (SELECT relation_oid FROM dfe_members) "
        "ORDER BY n.nspname, c.relname, c.oid, inheritance.inhseqno, inheritance.inhparent "
        "LIMIT %s"
    )
    max_records = acquisition.max_metadata_total_bytes
    rows = _execute_pretransaction_candidate_bounded(
        connection,
        statement,
        (*acquisition.relation.components, max_records + 1),
        max_records,
        acquisition.max_metadata_record_bytes,
        acquisition.max_metadata_total_bytes,
        source_budget,
        direction,
    )
    if not rows:
        raise PostgresMetadataError(
            "PostgreSQL frozen physical union root is missing or inaccessible during "
            f"candidate discovery: relation={acquisition.relation.components!r}"
        )
    return _frozen_candidate_from_rows(acquisition, rows)


def _frozen_candidate_from_rows(
    acquisition: PostgresRelationAcquisition,
    rows: tuple[DatabaseRow, ...],
) -> _PostgresRelationCandidate:
    members_by_oid: dict[int, _PostgresRelationMemberCandidate] = {}
    oids_by_relation: dict[PostgresRelation, int] = {}
    edges_by_identity: dict[tuple[int, int], PostgresInheritanceEdge] = {}
    root_oids: set[int] = set()
    max_identifier_lengths: set[int] = set()
    for index, row in enumerate(rows):
        if len(row) != 16:
            raise PostgresDataValidationError(
                "PostgreSQL frozen physical union discovery returned an unexpected field "
                f"count: row={index}, expected=16, actual={len(row)}"
            )
        member = _member_candidate_from_values(acquisition, row[:11])
        previous_member = members_by_oid.get(member.relation_oid)
        if previous_member is not None and previous_member != member:
            raise PostgresMetadataError(
                "PostgreSQL hierarchy maps one OID to conflicting member identities: "
                f"relation_oid={member.relation_oid}"
            )
        members_by_oid[member.relation_oid] = member
        previous_oid = oids_by_relation.get(member.relation)
        if previous_oid is not None and previous_oid != member.relation_oid:
            raise PostgresMetadataError(
                "PostgreSQL hierarchy maps one qualified name to conflicting OIDs: "
                f"relation={member.relation.components!r}"
            )
        oids_by_relation[member.relation] = member.relation_oid
        if _require_boolean(row[11], f"hierarchy root marker at row {index}"):
            root_oids.add(member.relation_oid)
        parent_oid = _require_optional_integer(row[12], f"hierarchy parent OID at row {index}")
        sequence = _require_optional_integer(row[13], f"hierarchy sequence at row {index}")
        detach_pending = row[14]
        if parent_oid is None or sequence is None:
            if parent_oid is not None or sequence is not None or detach_pending is not None:
                raise PostgresMetadataError(
                    "PostgreSQL hierarchy returned a malformed partial inheritance edge: "
                    f"row={index}"
                )
        else:
            if _require_boolean(detach_pending, f"hierarchy detach state at row {index}"):
                raise PostgresAcquisitionRaceError(
                    "PostgreSQL hierarchy contains an inheritance edge pending detach: "
                    f"parent_oid={parent_oid}, child_oid={member.relation_oid}, "
                    f"inhseqno={sequence}"
                )
            edge = PostgresInheritanceEdge(
                parent_relation_oid=parent_oid,
                child_relation_oid=member.relation_oid,
                sequence=sequence,
                detach_state=PostgresInheritanceDetachState.ATTACHED,
            )
            edge_identity = (edge.parent_relation_oid, edge.child_relation_oid)
            previous_edge = edges_by_identity.get(edge_identity)
            if previous_edge is not None and previous_edge != edge:
                raise PostgresMetadataError(
                    "PostgreSQL hierarchy returned conflicting direct-edge metadata: "
                    f"parent_oid={parent_oid}, child_oid={member.relation_oid}"
                )
            edges_by_identity[edge_identity] = edge
        max_identifier_lengths.add(
            _require_bounded_integer(
                row[15],
                f"candidate max_identifier_length at row {index}",
                1,
                INT64_MAX,
            )
        )
    if len(root_oids) != 1:
        raise PostgresMetadataError(
            "PostgreSQL frozen physical union discovery did not identify exactly one root: "
            f"root_oids={tuple(sorted(root_oids))!r}"
        )
    root_relation_oid = next(iter(root_oids))
    if len(members_by_oid) > MAX_COMPILED_RELATION_MEMBERS:
        raise PostgresMetadataError(
            "PostgreSQL frozen physical union exceeds the compiled-query member limit: "
            f"members={len(members_by_oid)}, maximum={MAX_COMPILED_RELATION_MEMBERS}"
        )
    root = members_by_oid[root_relation_oid]
    if root.relation != acquisition.relation:
        raise PostgresMetadataError(
            "PostgreSQL frozen physical union root changed qualified identity: "
            f"requested={acquisition.relation.components!r}, "
            f"actual={root.relation.components!r}"
        )
    if len(max_identifier_lengths) != 1:
        raise PostgresDataValidationError(
            "PostgreSQL hierarchy returned inconsistent max_identifier_length values"
        )
    max_identifier_utf8_bytes = next(iter(max_identifier_lengths))
    for member in members_by_oid.values():
        _validate_relation_identifiers(member.relation, max_identifier_utf8_bytes)
    _validate_column_identifiers(acquisition.column_names, max_identifier_utf8_bytes)
    edges = tuple(
        sorted(
            edges_by_identity.values(),
            key=lambda edge: (
                edge.parent_relation_oid,
                edge.sequence,
                edge.child_relation_oid,
            ),
        )
    )
    try:
        _validate_composition_reachability(root_relation_oid, set(members_by_oid), edges)
    except ValueError as error:
        raise PostgresMetadataError(
            "PostgreSQL hierarchy graph is malformed: "
            f"root_relation_oid={root_relation_oid}, reason={error}"
        ) from None
    members = tuple(
        sorted(
            members_by_oid.values(),
            key=lambda member: (member.relation.components, member.relation_oid),
        )
    )
    return _PostgresRelationCandidate(
        acquisition=acquisition,
        root_relation_oid=root_relation_oid,
        members=members,
        edges=edges,
    )


def _member_candidate_from_values(
    acquisition: PostgresRelationAcquisition,
    values: DatabaseRow,
) -> _PostgresRelationMemberCandidate:
    if len(values) != 11:
        raise PostgresDataValidationError(
            "PostgreSQL relation member metadata must contain exactly eleven fields"
        )
    relation_oid = _require_bounded_integer(values[0], "candidate relation OID", 1, UINT32_MAX)
    relation_row_type_oid = _require_bounded_integer(
        values[1],
        "candidate relation row type OID",
        1,
        UINT32_MAX,
    )
    namespace_oid = _require_bounded_integer(
        values[2],
        "candidate namespace OID",
        1,
        UINT32_MAX,
    )
    relation = PostgresRelation(
        components=(
            _require_text(values[3], "candidate relation schema"),
            _require_text(values[4], "candidate relation name"),
        )
    )
    relation_kind_text = _require_text(values[5], "candidate relation kind")
    try:
        relation_kind = PostgresRelationKind(relation_kind_text)
    except ValueError:
        raise PostgresMetadataError(
            "PostgreSQL frozen physical union contains an unsupported relation kind: "
            f"relation={relation.components!r}, relation_kind={relation_kind_text!r}, "
            "allowed=('p', 'r')"
        ) from None
    relation_persistence = _require_text(values[6], "candidate relation persistence")
    _validate_discovered_relation(
        acquisition.relation,
        relation,
        relation_kind,
        relation_persistence,
        _require_boolean(values[7], "candidate relation SELECT privilege"),
        _require_boolean(values[8], "candidate relation RLS enabled"),
        _require_boolean(values[9], "candidate relation RLS forced"),
        _require_boolean(values[10], "candidate schema USAGE privilege"),
    )
    return _PostgresRelationMemberCandidate(
        acquisition=acquisition,
        relation=relation,
        relation_oid=relation_oid,
        relation_row_type_oid=relation_row_type_oid,
        namespace_oid=namespace_oid,
        relation_kind=relation_kind,
        relation_persistence=relation_persistence,
    )


def _validate_discovered_relation(
    requested_relation: PostgresRelation,
    relation: PostgresRelation,
    relation_kind: PostgresRelationKind,
    relation_persistence: str,
    has_select: bool,
    row_security: bool,
    force_row_security: bool,
    has_schema_usage: bool,
) -> None:
    if relation_persistence != "p":
        raise PostgresMetadataError(
            "PostgreSQL protected relation must be permanent: "
            f"root={requested_relation.components!r}, relation={relation.components!r}, "
            f"relation_kind={relation_kind.value!r}, relpersistence={relation_persistence!r}, "
            "required='p'"
        )
    if not has_schema_usage:
        raise PostgresMetadataError(
            "PostgreSQL protected relation lacks direct schema USAGE privilege for the read "
            f"role: relation={relation.components!r}"
        )
    if not has_select:
        raise PostgresMetadataError(
            "PostgreSQL protected relation lacks direct SELECT privilege for the read role: "
            f"relation={relation.components!r}"
        )
    if row_security or force_row_security:
        raise PostgresMetadataError(
            "PostgreSQL protected relation enables row-level security, which is unsupported: "
            f"relation={relation.components!r}, row_security={row_security}, "
            f"force_row_security={force_row_security}"
        )


def _unique_lock_candidates(
    candidates: tuple[_PostgresRelationCandidate, ...],
) -> tuple[_PostgresRelationMemberCandidate, ...]:
    unique_by_oid: dict[int, _PostgresRelationMemberCandidate] = {}
    for candidate in candidates:
        for member in candidate.members:
            previous = unique_by_oid.get(member.relation_oid)
            if previous is not None and (
                previous.relation != member.relation
                or previous.relation_row_type_oid != member.relation_row_type_oid
                or previous.namespace_oid != member.namespace_oid
                or previous.relation_kind is not member.relation_kind
                or previous.relation_persistence != member.relation_persistence
            ):
                raise PostgresMetadataError(
                    "PostgreSQL protected acquisition maps one lock OID to conflicting "
                    f"identities: relation_oid={member.relation_oid}"
                )
            if previous is None:
                unique_by_oid[member.relation_oid] = member
    return tuple(
        sorted(
            unique_by_oid.values(),
            key=lambda member: (member.relation.components, member.relation_oid),
        )
    )


def _configure_protected_lock_timeouts(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
    lock_timeout_milliseconds: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> None:
    effective_statement_timeout = _configure_protected_statement_timeout(
        connection,
        statement_timeout_milliseconds,
        source_budget,
        direction,
    )
    effective_lock_timeout = min(lock_timeout_milliseconds, effective_statement_timeout)
    _execute_source_command(
        connection,
        sql.SQL("SET LOCAL lock_timeout = {}").format(sql.Literal(f"{effective_lock_timeout}ms")),
        (),
        source_budget,
        direction,
    )


def _configure_protected_statement_timeout(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> int:
    effective_statement_timeout = min(
        statement_timeout_milliseconds,
        source_budget.effective_statement_timeout_milliseconds(),
    )
    _execute_source_command(
        connection,
        sql.SQL("SET LOCAL statement_timeout = {}").format(
            sql.Literal(f"{effective_statement_timeout}ms")
        ),
        (),
        source_budget,
        direction,
    )
    return effective_statement_timeout


def _configure_protected_snapshot_invariants(
    connection: psycopg.Connection[DatabaseRow],
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> None:
    _execute_source_command(
        connection,
        "SELECT pg_catalog.set_config('search_path', 'pg_catalog', true), "
        "pg_catalog.set_config('row_security', 'off', true), "
        "pg_catalog.set_config('TimeZone', 'UTC', true), "
        "pg_catalog.set_config('DateStyle', 'ISO, YMD', true)",
        (),
        source_budget,
        direction,
    )


def _lock_candidate_relation(
    connection: psycopg.Connection[DatabaseRow],
    candidate: _PostgresRelationMemberCandidate,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> None:
    statement = sql.SQL("LOCK TABLE ONLY {} IN ACCESS SHARE MODE").format(
        sql.Identifier(*candidate.relation.components)
    )
    try:
        _execute_source_command(connection, statement, (), source_budget, direction)
    except (
        psycopg.errors.UndefinedTable,
        psycopg.errors.InvalidSchemaName,
        psycopg.errors.WrongObjectType,
    ) as error:
        raise PostgresAcquisitionRaceError(
            "PostgreSQL protected relation disappeared or was rebound after candidate "
            "discovery and before lock acquisition: "
            f"relation={candidate.relation.components!r}, "
            f"candidate_oid={candidate.relation_oid}, "
            f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
        ) from None


def _capture_protected_snapshot(
    connection: psycopg.Connection[DatabaseRow],
    lock_candidates: tuple[_PostgresRelationMemberCandidate, ...],
    started_at: datetime,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> tuple[PostgresServerProfile, PostgresProtectedReadContextEvidence]:
    lock_checks = sql.SQL(", ").join(
        sql.SQL(
            "EXISTS(SELECT 1 FROM pg_catalog.pg_locks AS held_lock "
            "WHERE held_lock.locktype = 'relation' "
            "AND held_lock.pid = pg_catalog.pg_backend_pid() "
            "AND held_lock.relation = %s::oid "
            "AND held_lock.mode = 'AccessShareLock' AND held_lock.granted)"
        )
        for _ in lock_candidates
    )
    statement = sql.SQL(
        "SELECT pg_catalog.current_setting('server_version'), "
        "pg_catalog.current_setting('server_version_num')::integer, "
        "pg_catalog.current_setting('server_encoding'), "
        "pg_catalog.current_setting('client_encoding'), "
        "pg_catalog.current_setting('integer_datetimes') = 'on', "
        "pg_catalog.current_setting('TimeZone'), "
        "pg_catalog.current_setting('max_identifier_length')::integer, "
        "pg_catalog.pg_backend_pid(), pg_catalog.pg_current_snapshot()::text, "
        "pg_catalog.current_setting('transaction_isolation'), "
        "pg_catalog.current_setting('transaction_read_only') = 'on', {lock_checks}"
    ).format(lock_checks=lock_checks)
    parameters: tuple[PostgresParameter, ...] = tuple(
        candidate.relation_oid for candidate in lock_candidates
    )
    max_record_bytes = max(
        candidate.acquisition.max_metadata_record_bytes for candidate in lock_candidates
    )
    max_total_bytes = max(
        candidate.acquisition.max_metadata_total_bytes for candidate in lock_candidates
    )
    rows = _execute_setup_bounded(
        connection,
        statement,
        parameters,
        1,
        max_record_bytes,
        max_total_bytes,
        source_budget,
        direction,
    )
    if not rows:
        raise PostgresDataValidationError(
            "PostgreSQL protected snapshot and lock probe returned no row"
        )
    row = rows[0]
    expected_fields = 11 + len(lock_candidates)
    if len(row) != expected_fields:
        raise PostgresDataValidationError(
            "PostgreSQL protected snapshot probe returned an unexpected field count: "
            f"expected={expected_fields}, actual={len(row)}"
        )
    profile_row = row[:11]
    profile, base_evidence = _profile_and_evidence(profile_row, started_at)
    _validate_profile(profile, profile_row)
    for index, (candidate, value) in enumerate(zip(lock_candidates, row[11:], strict=True)):
        if not _require_boolean(value, f"candidate lock proof {index}"):
            raise PostgresAcquisitionRaceError(
                "PostgreSQL protected acquisition cannot prove an AccessShareLock for the "
                "discovered relation before its snapshot: "
                f"relation={candidate.relation.components!r}, "
                f"relation_oid={candidate.relation_oid}"
            )
    locked_relation_oids = tuple(candidate.relation_oid for candidate in lock_candidates)
    evidence = PostgresProtectedReadContextEvidence(
        context_id=base_evidence.context_id,
        engine=base_evidence.engine,
        server_version=base_evidence.server_version,
        strategy="protected_read_only_repeatable_read",
        snapshot_locator=base_evidence.snapshot_locator,
        started_at=base_evidence.started_at,
        backend_process_id=base_evidence.backend_process_id,
        allowed_concurrency=base_evidence.allowed_concurrency,
        limitations=(
            *base_evidence.limitations,
            "every discovered physical relation holds AccessShareLock before the snapshot",
            "only pre-acquired regular members contribute rows through explicit ONLY scans",
        ),
        locked_relation_oids=locked_relation_oids,
        lock_mode="access_share",
        relation_persistence=PostgresRelationPersistence.PERMANENT,
        acquired_before_snapshot=True,
    )
    return profile, evidence


def _inspect_protected_candidate(
    connection: psycopg.Connection[DatabaseRow],
    candidate: _PostgresRelationCandidate,
    profile: PostgresServerProfile,
    evidence: PostgresProtectedReadContextEvidence,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresProtectedRelationInspection:
    acquisition = candidate.acquisition
    try:
        final_candidate = _discover_relation_candidate(
            connection,
            acquisition,
            source_budget,
            direction,
        )
    except PostgresAcquisitionRaceError:
        raise
    except PostgresMetadataError as error:
        raise PostgresAcquisitionRaceError(
            "PostgreSQL protected relation graph became invalid between discovery and the "
            f"protected snapshot: relation={acquisition.relation.components!r}, "
            f"reason={error}"
        ) from None
    return _seal_protected_candidate(
        connection,
        candidate,
        final_candidate,
        profile,
        evidence,
        source_budget,
        direction,
    )


def _seal_protected_candidate(
    connection: psycopg.Connection[DatabaseRow],
    candidate: _PostgresRelationCandidate,
    final_candidate: _PostgresRelationCandidate,
    profile: PostgresServerProfile,
    evidence: PostgresProtectedReadContextEvidence,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresProtectedRelationInspection:
    acquisition = candidate.acquisition
    if final_candidate != candidate:
        raise PostgresAcquisitionRaceError(
            "PostgreSQL protected relation graph changed between candidate discovery and "
            "the protected snapshot: "
            f"relation={acquisition.relation.components!r}, "
            f"expected_root_oid={candidate.root_relation_oid}, "
            f"actual_root_oid={final_candidate.root_relation_oid}"
        )
    protected_members = tuple(
        _inspect_protected_member(
            connection,
            member,
            profile,
            evidence,
            source_budget,
            direction,
        )
        for member in final_candidate.members
    )
    root_members = tuple(
        member
        for member in protected_members
        if member.inspection.relation_oid == candidate.root_relation_oid
    )
    if len(root_members) != 1:
        raise PostgresDataValidationError(
            "PostgreSQL protected relation graph did not produce exactly one inspected root"
        )
    root_member = root_members[0]
    composition = (
        None
        if acquisition.relation_scope is RelationScope.PHYSICAL_ONLY
        else PostgresProtectedRelationComposition(
            root_relation_oid=candidate.root_relation_oid,
            members=protected_members,
            edges=candidate.edges,
        )
    )
    return PostgresProtectedRelationInspection(
        acquisition=acquisition,
        inspection=root_member.inspection,
        namespace_oid=root_member.namespace_oid,
        lock_mode="access_share",
        relation_persistence=PostgresRelationPersistence.PERMANENT,
        acquired_before_snapshot=True,
        composition=composition,
    )


def _inspect_protected_member(
    connection: psycopg.Connection[DatabaseRow],
    candidate: _PostgresRelationMemberCandidate,
    profile: PostgresServerProfile,
    evidence: PostgresProtectedReadContextEvidence,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> PostgresProtectedRelationMember:
    acquisition = candidate.acquisition
    if not acquisition.column_names:
        bindings: tuple[PostgresFieldBinding, ...] = ()
    else:
        metadata_statement, metadata_parameters = _metadata_query(
            candidate.relation_oid,
            candidate.relation.components[0],
            candidate.relation.components[1],
            acquisition.column_names,
        )
        metadata_rows = _execute_setup_bounded(
            connection,
            metadata_statement,
            metadata_parameters,
            len(acquisition.column_names),
            acquisition.max_metadata_record_bytes,
            acquisition.max_metadata_total_bytes,
            source_budget,
            direction,
        )
        if len(metadata_rows) != len(acquisition.column_names):
            raise PostgresMetadataError(
                "PostgreSQL protected column probe did not return one row per requested column: "
                f"expected={len(acquisition.column_names)}, actual={len(metadata_rows)}"
            )
        bindings = tuple(
            postgres_field_binding_from_catalog_row(
                field.name,
                column_name,
                index,
                metadata_row,
            )
            for index, (field, column_name, metadata_row) in enumerate(
                zip(
                    acquisition.schema.fields,
                    acquisition.column_names,
                    metadata_rows,
                    strict=True,
                )
            )
        )
    inspection = PostgresInspectedRelation(
        context_id=evidence.context_id,
        relation_oid=candidate.relation_oid,
        relation_row_type_oid=candidate.relation_row_type_oid,
        relation=candidate.relation,
        bindings=bindings,
        max_identifier_utf8_bytes=profile.max_identifier_utf8_bytes,
    )
    validate_postgres_inspection(acquisition.schema, inspection)
    return PostgresProtectedRelationMember(
        inspection=inspection,
        namespace_oid=candidate.namespace_oid,
        relation_kind=candidate.relation_kind,
        relation_persistence=PostgresRelationPersistence.PERMANENT,
    )


def _execute_setup_bounded(
    connection: psycopg.Connection[DatabaseRow],
    statement: ExecutableSql,
    parameters: tuple[PostgresParameter, ...],
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> tuple[DatabaseRow, ...]:
    _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
    _set_source_statement_timeout(connection, source_budget, direction)
    cursor_name = f"dfe_{uuid4().hex}"
    with connection.cursor(name=cursor_name) as cursor:
        charge = source_budget.dispatch_query(direction, 0)
        cursor.execute(statement, parameters)
        return _fetch_bounded_rows(
            cursor,
            max_records,
            max_record_bytes,
            max_total_bytes,
            charge,
        )


def _execute_pretransaction_candidate_bounded(
    connection: psycopg.Connection[DatabaseRow],
    statement: ExecutableSql,
    parameters: tuple[PostgresParameter, ...],
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> tuple[DatabaseRow, ...]:
    _validate_result_limits(max_records, max_record_bytes, max_total_bytes)
    _set_source_statement_timeout(connection, source_budget, direction)
    charge = source_budget.dispatch_query(direction, 0)
    records: list[DatabaseRow] = []
    observed_bytes = 0
    with connection.cursor() as cursor:
        cursor.execute(statement, parameters)
        while True:
            charge.require_fetch_deadline()
            remaining = max_records + 1 - len(records)
            batch = tuple(cursor.fetchmany(min(_CURSOR_FETCH_RECORDS, remaining)))
            if not batch:
                break
            batch_bytes = tuple(_database_row_bytes(row) for row in batch)
            charge.consume_records(batch_bytes)
            if len(records) + len(batch) > max_records:
                raise PostgresResultLimitError(
                    "PostgreSQL pretransaction candidate query exceeded its record budget: "
                    f"max_records={max_records}"
                )
            oversized_record = next(
                (value for value in batch_bytes if value > max_record_bytes),
                None,
            )
            if oversized_record is not None:
                raise PostgresResultLimitError(
                    "PostgreSQL pretransaction candidate query returned a record above the "
                    f"byte budget: record_bytes={oversized_record}, "
                    f"max_record_bytes={max_record_bytes}"
                )
            observed_bytes += sum(batch_bytes)
            if observed_bytes > max_total_bytes:
                raise PostgresResultLimitError(
                    "PostgreSQL pretransaction candidate query exceeded the total byte "
                    f"budget: observed_bytes={observed_bytes}, "
                    f"max_total_bytes={max_total_bytes}"
                )
            records.extend(batch)
            if len(batch) < min(_CURSOR_FETCH_RECORDS, remaining):
                break
    return tuple(records)


def _execute_source_command(
    connection: psycopg.Connection[DatabaseRow],
    statement: ExecutableSql,
    parameters: tuple[PostgresParameter, ...],
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> None:
    charge = source_budget.dispatch_query(direction, 0)
    with connection.cursor() as cursor:
        cursor.execute(statement, parameters)
        if cursor.description is None:
            return
        charge.require_fetch_deadline()
        rows = cursor.fetchall()
        charge.consume_records(tuple(_database_row_bytes(row) for row in rows))


def _set_source_statement_timeout(
    connection: psycopg.Connection[DatabaseRow],
    source_budget: PostgresSourceBudgetAttempt,
    direction: PostgresSourceDirection,
) -> None:
    timeout_milliseconds = source_budget.effective_statement_timeout_milliseconds()
    _execute_source_command(
        connection,
        "SELECT pg_catalog.set_config('statement_timeout', %s, false)",
        (str(timeout_milliseconds),),
        source_budget,
        direction,
    )


def _profile_and_evidence(
    row: DatabaseRow,
    started_at: datetime,
) -> tuple[PostgresServerProfile, PostgresReadContextEvidence]:
    if len(row) != 11:
        raise PostgresDataValidationError(
            "PostgreSQL capability probe must return exactly eleven typed fields"
        )
    server_version = _require_text(row[0], "server_version")
    server_version_number = _require_integer(row[1], "server_version_num")
    server_encoding = _require_text(row[2], "server_encoding")
    client_encoding = _require_text(row[3], "client_encoding")
    integer_datetimes = _require_boolean(row[4], "integer_datetimes")
    timezone = _require_text(row[5], "TimeZone")
    max_identifier_utf8_bytes = _require_bounded_integer(
        row[6],
        "max_identifier_length",
        1,
        INT64_MAX,
    )
    backend_process_id = _require_integer(row[7], "backend_process_id")
    snapshot_locator = _require_text(row[8], "snapshot_locator")
    profile = PostgresServerProfile(
        driver_version=psycopg.__version__,
        server_version=server_version,
        server_version_number=server_version_number,
        server_encoding=server_encoding,
        client_encoding=client_encoding,
        integer_datetimes=integer_datetimes,
        timezone=timezone,
        max_identifier_utf8_bytes=max_identifier_utf8_bytes,
    )
    evidence = PostgresReadContextEvidence(
        context_id=uuid4(),
        engine="postgresql",
        server_version=server_version,
        strategy="read_only_repeatable_read",
        snapshot_locator=snapshot_locator,
        started_at=started_at,
        backend_process_id=backend_process_id,
        allowed_concurrency=1,
        limitations=(
            "snapshot locator is evidence only and cannot reopen a closed transaction",
            "one active query is allowed for this connection",
            "relation reads target one physical regular table with inheritance expansion disabled",
        ),
    )
    return profile, evidence


def _validate_profile(profile: PostgresServerProfile, row: DatabaseRow) -> None:
    isolation = _require_text(row[9], "transaction_isolation")
    read_only = _require_boolean(row[10], "transaction_read_only")
    failures: list[str] = []
    if profile.server_encoding != "UTF8":
        failures.append(f"server_encoding={profile.server_encoding!r}, required='UTF8'")
    if profile.client_encoding != "UTF8":
        failures.append(f"client_encoding={profile.client_encoding!r}, required='UTF8'")
    if not profile.integer_datetimes:
        failures.append("integer_datetimes=off, required=on")
    if profile.timezone != "UTC":
        failures.append(f"TimeZone={profile.timezone!r}, required='UTC'")
    if isolation != "repeatable read":
        failures.append(f"transaction_isolation={isolation!r}, required='repeatable read'")
    if not read_only:
        failures.append("transaction_read_only=off, required=on")
    if failures:
        raise UnsupportedPostgresProfileError(
            "PostgreSQL capability profile is unsupported: "
            f"server_version={profile.server_version!r}, "
            f"server_version_num={profile.server_version_number}; " + "; ".join(failures)
        )


def _relation_query(
    relation: PostgresRelation,
) -> tuple[ExecutableSql, tuple[PostgresParameter, ...]]:
    relation_expression = sql.SQL(
        "pg_catalog.to_regclass(pg_catalog.quote_ident(%s) || '.' || pg_catalog.quote_ident(%s))"
    )
    parameters: tuple[PostgresParameter, ...] = (
        relation.components[0],
        relation.components[1],
    )
    statement = sql.SQL(
        "SELECT c.oid::bigint, c.reltype::bigint, n.nspname, c.relname, c.relkind::text, "
        "pg_catalog.has_table_privilege(c.oid, 'SELECT') "
        "FROM pg_catalog.pg_class AS c "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE c.oid = {relation_expression}"
    ).format(relation_expression=relation_expression)
    return statement, parameters


def _relation_manifest_query(
    relation: PostgresRelation,
    columns: ReadinessManifestColumns,
) -> ExecutableSql:
    return sql.SQL(
        "SELECT CASE WHEN FALSE THEN (dfe_manifest.*) ELSE NULL END AS origin_type, "
        "dfe_manifest.{dataset_id} AS dataset_id, "
        "dfe_manifest.{scope_digest} AS scope_digest, "
        "dfe_manifest.{batch_id} AS batch_id, "
        "dfe_manifest.{state} AS state, "
        "dfe_manifest.{business_date} AS business_date, "
        "dfe_manifest.{source_cut} AS source_cut, "
        "dfe_manifest.{dataset_version} AS dataset_version, "
        "dfe_manifest.{completed_at} AS completed_at "
        "FROM ONLY {relation} AS dfe_manifest "
        "WHERE dfe_manifest.{dataset_id} = %s AND dfe_manifest.{scope_digest} = %s "
        "LIMIT 2"
    ).format(
        dataset_id=sql.Identifier(columns.dataset_id),
        scope_digest=sql.Identifier(columns.scope_digest),
        batch_id=sql.Identifier(columns.batch_id),
        state=sql.Identifier(columns.state),
        business_date=sql.Identifier(columns.business_date),
        source_cut=sql.Identifier(columns.source_cut),
        dataset_version=sql.Identifier(columns.dataset_version),
        completed_at=sql.Identifier(columns.completed_at),
        relation=sql.Identifier(*relation.components),
    )


def _metadata_query(
    relation_oid: int,
    relation_schema: str,
    relation_name: str,
    column_names: tuple[str, ...],
) -> tuple[ExecutableSql, tuple[PostgresParameter, ...]]:
    requested_rows = sql.SQL(", ").join(sql.SQL("(%s::integer, %s::text)") for _ in column_names)
    statement = sql.SQL(
        "WITH requested(request_ordinal, column_name) AS (VALUES {requested_rows}) "
        "SELECT requested.request_ordinal, requested.column_name, attribute.attname, "
        "pg_catalog.format_type(attribute.atttypid, attribute.atttypmod), "
        "declared_namespace.nspname, declared_type.typname, declared_type.oid::bigint, "
        "base_namespace.nspname, base_type.typname, base_type.oid::bigint, "
        "declared_type.typtype = 'd', attribute.attndims::integer, "
        "information.numeric_precision, information.numeric_scale, information.column_name "
        "FROM requested "
        "LEFT JOIN pg_catalog.pg_attribute AS attribute "
        "ON attribute.attrelid = %s::oid "
        "AND attribute.attname = requested.column_name "
        "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
        "LEFT JOIN pg_catalog.pg_type AS declared_type ON declared_type.oid = attribute.atttypid "
        "LEFT JOIN pg_catalog.pg_namespace AS declared_namespace "
        "ON declared_namespace.oid = declared_type.typnamespace "
        "LEFT JOIN pg_catalog.pg_type AS base_type "
        "ON base_type.oid = CASE WHEN declared_type.typtype = 'd' "
        "THEN declared_type.typbasetype ELSE declared_type.oid END "
        "LEFT JOIN pg_catalog.pg_namespace AS base_namespace "
        "ON base_namespace.oid = base_type.typnamespace "
        "LEFT JOIN information_schema.columns AS information "
        "ON information.table_catalog = current_database() "
        "AND information.table_schema = %s "
        "AND information.table_name = %s "
        "AND information.column_name = requested.column_name "
        "ORDER BY requested.request_ordinal"
    ).format(requested_rows=requested_rows)
    parameters_list: list[PostgresParameter] = []
    for index, column_name in enumerate(column_names, start=1):
        parameters_list.extend((index, column_name))
    parameters_list.extend((relation_oid, relation_schema, relation_name))
    return statement, tuple(parameters_list)


def postgres_field_binding_from_catalog_row(
    field_name: str,
    column_name: str,
    index: int,
    row: DatabaseRow,
) -> PostgresFieldBinding:
    if len(row) != _METADATA_ROW_COLUMNS:
        raise PostgresDataValidationError(
            "PostgreSQL column catalog probe returned an unexpected field count: "
            f"expected={_METADATA_ROW_COLUMNS}, actual={len(row)}"
        )
    ordinal = _require_bounded_integer(row[0], "requested column ordinal", 1, INT64_MAX)
    if ordinal != index + 1:
        raise PostgresDataValidationError(
            "PostgreSQL column catalog probe returned an unexpected ordinal: "
            f"expected={index + 1}, actual={ordinal}"
        )
    requested_name = _require_text(row[1], "requested column name")
    if requested_name != column_name:
        raise PostgresDataValidationError(
            "PostgreSQL column catalog probe changed the requested identifier"
        )
    if row[2] is None or row[14] is None:
        raise PostgresMetadataError(
            "PostgreSQL requested column is missing or not visible to the read role: "
            f"column_index={index}, column_name={column_name!r}"
        )
    actual_name = _require_text(row[2], "column name")
    information_name = _require_text(row[14], "information_schema column name")
    if actual_name != column_name or information_name != column_name:
        raise PostgresDataValidationError(
            "PostgreSQL catalog sources disagree about the requested column identifier: "
            f"column_index={index}"
        )
    declared_type = PostgresTypeIdentity(
        schema_name=_require_text(row[4], "declared type schema"),
        type_name=_require_text(row[5], "declared type name"),
        oid=_require_bounded_integer(row[6], "declared type OID", 1, UINT32_MAX),
    )
    base_type = PostgresTypeIdentity(
        schema_name=_require_text(row[7], "base type schema"),
        type_name=_require_text(row[8], "base type name"),
        oid=_require_bounded_integer(row[9], "base type OID", 1, UINT32_MAX),
    )
    physical = PostgresPhysicalField(
        declared_type=declared_type,
        base_type=base_type,
        formatted_type=_require_text(row[3], "formatted type"),
        is_domain=_require_boolean(row[10], "is_domain"),
        array_dimensions=_require_bounded_integer(
            row[11],
            "array dimensions",
            0,
            INT64_MAX,
        ),
        numeric_precision=_require_optional_integer(row[12], "numeric precision"),
        numeric_scale=_require_optional_integer(row[13], "numeric scale"),
    )
    return PostgresFieldBinding(
        field_name=field_name,
        column_name=column_name,
        physical=physical,
    )


def _validate_relation_manifest_contract(
    protected_relation: PostgresProtectedRelationInspection,
    columns: ReadinessManifestColumns,
) -> None:
    semantic_fields = tuple(field.name for field in protected_relation.acquisition.schema.fields)
    if semantic_fields != _MANIFEST_SEMANTIC_FIELDS:
        raise PostgresMetadataError(
            "PostgreSQL relation manifest acquisition must use the fixed semantic field order: "
            f"expected={_MANIFEST_SEMANTIC_FIELDS!r}, actual={semantic_fields!r}"
        )
    mapped_columns = columns.values()
    if mapped_columns != protected_relation.acquisition.column_names:
        raise PostgresMetadataError(
            "PostgreSQL relation manifest mappings differ from the ordered acquired column "
            "closure: "
            f"acquired={protected_relation.acquisition.column_names!r}, "
            f"requested={mapped_columns!r}"
        )


def _validate_relation_manifest_bindings(
    inspection: PostgresInspectedRelation,
    columns: ReadinessManifestColumns,
) -> None:
    bindings_by_column = {binding.column_name: binding for binding in inspection.bindings}
    if len(bindings_by_column) != len(inspection.bindings):
        raise PostgresMetadataError(
            "PostgreSQL protected inspection contains duplicate physical column bindings"
        )
    requirements: tuple[tuple[str, str, frozenset[tuple[str, int]]], ...] = (
        ("dataset_id", columns.dataset_id, _MANIFEST_TEXT_TYPES),
        ("scope_digest", columns.scope_digest, _MANIFEST_TEXT_TYPES),
        ("batch_id", columns.batch_id, _MANIFEST_TEXT_TYPES),
        ("state", columns.state, _MANIFEST_TEXT_TYPES),
        ("business_date", columns.business_date, frozenset((_MANIFEST_DATE_TYPE,))),
        ("source_cut", columns.source_cut, _MANIFEST_TEXT_TYPES),
        ("dataset_version", columns.dataset_version, _MANIFEST_TEXT_TYPES),
        ("completed_at", columns.completed_at, frozenset((_MANIFEST_TIMESTAMPTZ_TYPE,))),
    )
    for semantic_name, column_name, allowed_types in requirements:
        binding = bindings_by_column.get(column_name)
        if binding is None:
            raise PostgresMetadataError(
                "PostgreSQL relation manifest column is outside the protected inspection: "
                f"field={semantic_name!r}, column={column_name!r}"
            )
        physical = binding.physical
        base_identity = (physical.base_type.type_name, physical.base_type.oid)
        if (
            physical.is_domain
            or physical.array_dimensions != 0
            or physical.base_type.schema_name != "pg_catalog"
            or base_identity not in allowed_types
        ):
            raise PostgresMetadataError(
                "PostgreSQL relation manifest column has an unsupported physical type: "
                f"field={semantic_name!r}, column={column_name!r}, "
                f"physical_type={physical.formatted_type!r}, "
                f"declared_type={physical.declared_type.schema_name}."
                f"{physical.declared_type.type_name}, domain={physical.is_domain}, "
                f"array_dimensions={physical.array_dimensions}"
            )


def _relation_manifest_record_from_database(
    row: DatabaseRow,
) -> PostgresRelationManifestRecord:
    if len(row) != 9:
        raise PostgresDataValidationError(
            "PostgreSQL relation manifest query must return exactly nine typed fields"
        )
    if row[0] is not None:
        raise PostgresDataValidationError(
            "PostgreSQL relation manifest origin type marker must be NULL"
        )
    business_date = row[5]
    if type(business_date) is not date:
        raise PostgresDataValidationError(
            "PostgreSQL relation manifest business_date must be a non-null date"
        )
    completed_at = row[8]
    if completed_at is not None and type(completed_at) is not datetime:
        raise PostgresDataValidationError(
            "PostgreSQL relation manifest completed_at must be NULL or a timestamptz"
        )
    return PostgresRelationManifestRecord(
        dataset_id=_require_text(row[1], "relation manifest dataset_id"),
        scope_digest=_require_sha256_hex(row[2], "relation manifest scope_digest"),
        batch_id=_require_text(row[3], "relation manifest batch_id"),
        state=_require_text(row[4], "relation manifest state"),
        business_date=business_date,
        source_cut=_require_optional_text(row[6], "relation manifest source_cut"),
        dataset_version=_require_optional_text(row[7], "relation manifest dataset_version"),
        completed_at=completed_at,
    )


def _compiled_query_payload(
    row: DatabaseRow,
    query: PostgresQuery,
    expected_payload_fields: int,
    operation: str,
) -> DatabaseRow:
    provenance_fields = len(query.relations)
    expected_fields = provenance_fields + expected_payload_fields
    if len(row) != expected_fields:
        raise PostgresDataValidationError(
            f"PostgreSQL {operation} query returned an unexpected field count: "
            f"expected={expected_fields}, actual={len(row)}, "
            f"provenance_fields={provenance_fields}"
        )
    for index, (value, relation) in enumerate(
        zip(row[:provenance_fields], query.relations, strict=True)
    ):
        if value is None:
            continue
        observed_row_type_oid = _require_bounded_integer(
            value,
            f"{operation} provenance row type OID at index {index}",
            1,
            UINT32_MAX,
        )
        expected_row_type_oid = relation.inspection.relation_row_type_oid
        if observed_row_type_oid != expected_row_type_oid:
            raise PostgresMetadataError(
                f"PostgreSQL {operation} query resolved a member to a different relation "
                "identity through its actual RTE: "
                f"index={index}, expected_row_type_oid={expected_row_type_oid}, "
                f"observed_row_type_oid={observed_row_type_oid}"
            )
    return row[provenance_fields:]


def _canonical_row_from_database(
    row: DatabaseRow,
    query: PostgresQuery,
) -> PostgresCanonicalRow | None:
    payload = _compiled_query_payload(row, query, 5, "canonical row")
    has_data = _require_boolean(payload[0], "canonical row data marker")
    if not has_data:
        return None
    invalid_row = _require_boolean(payload[3], "canonical invalid-row status")
    oversized_row = _require_boolean(payload[4], "canonical oversized-row status")
    if invalid_row and oversized_row:
        raise PostgresDataValidationError(
            "PostgreSQL canonical row statuses must be mutually exclusive"
        )
    if invalid_row or oversized_row:
        if payload[1] is not None or payload[2] is not None:
            raise PostgresDataValidationError(
                "PostgreSQL rejected canonical rows must not expose an envelope or digest"
            )
        if invalid_row:
            raise PostgresDataValidationError(
                "PostgreSQL source row cannot be represented losslessly by the logical schema"
            )
        raise PostgresResultLimitError(
            "PostgreSQL canonical envelope exceeds the configured SQL-side limit: "
            f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
        )
    envelope_text = _require_text(payload[1], "canonical envelope")
    try:
        envelope = envelope_text.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise PostgresDataValidationError(
            "PostgreSQL canonical envelope contains non-ASCII bytes"
        ) from None
    if len(envelope) > query.max_encoded_envelope_bytes:
        raise PostgresDataValidationError(
            "PostgreSQL canonical envelope exceeds its declared SQL-side limit: "
            f"observed={len(envelope)}, limit={query.max_encoded_envelope_bytes}"
        )
    digest = payload[2]
    if type(digest) is memoryview:
        if digest.nbytes != SHA256_BYTES:
            raise PostgresDataValidationError(
                "PostgreSQL canonical row SHA-256 must be exactly 32 bytes"
            )
        digest_bytes = digest.tobytes()
    elif type(digest) is bytes and len(digest) == SHA256_BYTES:
        digest_bytes = digest
    else:
        raise PostgresDataValidationError(
            "PostgreSQL canonical row SHA-256 must be exactly 32 bytes"
        )
    try:
        decode_row_with_context(query.context, envelope)
    except CanonicalizationError as error:
        raise PostgresDataValidationError(
            "PostgreSQL canonical envelope failed reference decoding: "
            f"reason_type={type(error).__name__}"
        ) from None
    expected_digest = envelope_sha256(envelope)
    if digest_bytes != expected_digest:
        raise PostgresDataValidationError(
            "PostgreSQL canonical row SHA-256 does not match the returned envelope"
        )
    return PostgresCanonicalRow(envelope=envelope, sha256=digest_bytes)


def _integer_key_summary_from_database(
    row: DatabaseRow,
    query: PostgresQuery,
) -> PostgresIntegerKeySummary:
    payload = _compiled_query_payload(row, query, 8, "integer-key summary")
    counts = tuple(_parse_unsigned_decimal(value, 19) for value in payload[:5])
    minimum = _parse_optional_int64(payload[5], "integer-key minimum")
    maximum = _parse_optional_int64(payload[6], "integer-key maximum")
    return PostgresIntegerKeySummary(
        row_count=counts[0],
        null_key_count=counts[1],
        invalid_key_count=counts[2],
        valid_key_count=counts[3],
        distinct_key_count=counts[4],
        minimum_key=minimum,
        maximum_key=maximum,
        usable_access_path=_require_boolean(
            payload[7],
            "integer-key usable access path",
        ),
    )


def _range_fingerprints_from_database(
    rows: tuple[DatabaseRow, ...],
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    query: PostgresQuery,
    deadline: PostgresReadDeadline,
) -> tuple[PostgresRangeFingerprint, ...]:
    if len(rows) != len(ranges):
        raise PostgresDataValidationError(
            "PostgreSQL range fingerprint query must return one row per requested range: "
            f"expected={len(ranges)}, actual={len(rows)}"
        )
    parsed: list[PostgresRangeFingerprint] = []
    for index, (range_request, row) in enumerate(zip(ranges, rows, strict=True)):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_postgres_read_deadline(deadline, "range fingerprint decoding")
        payload = _compiled_query_payload(row, query, 14, "range fingerprint")
        segment_id = _require_text(payload[0], "range fingerprint segment_id")
        if segment_id != range_request.segment_id:
            raise PostgresDataValidationError(
                "PostgreSQL range fingerprint rows do not follow requested segment order"
            )
        values = tuple(
            _parse_unsigned_decimal(value, 19 if index in (0, 9, 10) else 38)
            for index, value in enumerate(payload[1:])
        )
        count = values[0]
        invalid_count = values[9]
        oversized_count = values[10]
        if count > INT64_MAX or invalid_count > INT64_MAX or oversized_count > INT64_MAX:
            raise PostgresDataValidationError(
                "PostgreSQL range fingerprint row count exceeds the signed int64 bound"
            )
        if invalid_count > 0:
            raise PostgresDataValidationError(
                "PostgreSQL range fingerprint rejected source rows that cannot be "
                f"represented losslessly: segment_id={segment_id!r}, "
                f"invalid_row_count={invalid_count}"
            )
        if oversized_count > 0:
            raise PostgresResultLimitError(
                "PostgreSQL range fingerprint found canonical envelopes above the "
                f"configured limit: segment_id={segment_id!r}, "
                f"oversized_row_count={oversized_count}, "
                f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
            )
        try:
            fingerprint = Fingerprint(
                count=count,
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
            raise PostgresDataValidationError(
                "PostgreSQL range fingerprint violates canonical accumulator bounds: "
                f"segment_id={segment_id!r}, reason_type={type(error).__name__}"
            ) from None
        parsed.append(
            PostgresRangeFingerprint(
                segment_id=segment_id,
                fingerprint=fingerprint,
                row_envelope_bytes=values[11],
                key_envelope_bytes=values[12],
            )
        )
    _require_postgres_read_deadline(deadline, "range fingerprint decoding")
    return tuple(parsed)


def _integer_exact_rows_from_database(
    rows: tuple[DatabaseRow, ...],
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    key_field_index: int,
    query: PostgresQuery,
    deadline: PostgresReadDeadline,
) -> tuple[PostgresIntegerExactRow, ...]:
    if type(key_field_index) is not int or not 0 <= key_field_index < len(
        query.context.schema.fields
    ):
        raise PostgresDataValidationError(
            "PostgreSQL exact-row key field index does not identify a schema field"
        )
    key_schema = CanonicalSchema(
        protocol=query.context.schema.protocol,
        fields=(query.context.schema.fields[key_field_index],),
    )
    key_context = prepare_envelope_context(key_schema)
    ordinals = {item.segment_id: index for index, item in enumerate(ranges)}
    parsed: list[PostgresIntegerExactRow] = []
    previous_ordinal = -1
    previous_key: int | None = None
    for index, row in enumerate(rows):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_postgres_read_deadline(deadline, "exact-row decoding")
        payload = _compiled_query_payload(row, query, 6, "exact comparison")
        has_data = _require_boolean(payload[0], "exact comparison data marker")
        if not has_data:
            continue
        segment_id = _require_text(payload[1], "exact comparison segment_id")
        ordinal = ordinals.get(segment_id)
        if ordinal is None:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison returned an unrequested segment ID"
            )
        if ordinal < previous_ordinal:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison rows do not follow requested segment order"
            )
        invalid_row = _require_boolean(payload[4], "exact invalid-row status")
        oversized_row = _require_boolean(payload[5], "exact oversized-row status")
        if invalid_row and oversized_row:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison row statuses must be mutually exclusive"
            )
        if invalid_row:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison found a row that cannot be represented losslessly"
            )
        if oversized_row:
            raise PostgresResultLimitError(
                "PostgreSQL exact comparison found a canonical envelope above the "
                f"configured limit: max_encoded_envelope_bytes="
                f"{query.max_encoded_envelope_bytes}"
            )
        key_envelope = _ascii_envelope(payload[2], "exact canonical key envelope")
        row_envelope = _ascii_envelope(payload[3], "exact canonical row envelope")
        if len(row_envelope) > query.max_encoded_envelope_bytes:
            raise PostgresResultLimitError(
                "PostgreSQL exact comparison row envelope exceeds the configured limit: "
                f"observed_bytes={len(row_envelope)}, "
                f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
            )
        try:
            key_values = decode_key_with_context(key_context, key_envelope)
            row_values = decode_row_with_context(query.context, row_envelope)
        except CanonicalizationError as error:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison envelope failed reference decoding: "
                f"reason_type={type(error).__name__}"
            ) from None
        key_value = key_values[0]
        row_key_value = row_values[key_field_index]
        if type(key_value) is not int or type(row_key_value) is not int:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison key envelope is not logical INT64"
            )
        if key_value != row_key_value:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison key and row envelopes disagree"
            )
        requested_range = ranges[ordinal]
        if key_value < requested_range.lower_inclusive or (
            requested_range.upper_exclusive is not None
            and key_value >= requested_range.upper_exclusive
        ):
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison key falls outside its requested range: "
                f"segment_id={segment_id!r}, key_value={key_value}, "
                f"lower_inclusive={requested_range.lower_inclusive}, "
                f"upper_exclusive={requested_range.upper_exclusive!r}"
            )
        if ordinal == previous_ordinal and previous_key is not None and key_value <= previous_key:
            raise PostgresDataValidationError(
                "PostgreSQL exact comparison keys must be strictly increasing within a segment"
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
    _require_postgres_read_deadline(deadline, "exact-row decoding")
    return tuple(parsed)


def _ascii_envelope(value: object, context: str) -> bytes:
    text = _require_text(value, context)
    try:
        return text.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise PostgresDataValidationError(
            f"PostgreSQL {context} contains non-ASCII bytes"
        ) from None


def _read_metrics_before_deadline(
    rows: tuple[DatabaseRow, ...],
    deadline: PostgresReadDeadline,
) -> PostgresReadMetrics:
    result_bytes = 0
    for index, row in enumerate(rows):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_postgres_read_deadline(deadline, "comparison read metric calculation")
        result_bytes += _database_row_bytes(row)
    _require_postgres_read_deadline(deadline, "comparison read metric calculation")
    return PostgresReadMetrics(
        fetched_records=len(rows),
        result_bytes=result_bytes,
    )


def _exact_read_metrics(
    rows: tuple[DatabaseRow, ...],
    query: PostgresQuery,
    deadline: PostgresReadDeadline,
) -> PostgresReadMetrics:
    fetched_records = 0
    result_bytes = 0
    for index, row in enumerate(rows):
        if index % _DEADLINE_CHECK_RECORDS == 0:
            _require_postgres_read_deadline(deadline, "exact read metric calculation")
        payload = _compiled_query_payload(row, query, 6, "exact comparison metric")
        if _require_boolean(payload[0], "exact comparison metric data marker"):
            fetched_records += 1
            result_bytes += _database_row_bytes((None, *payload[1:]))
    _require_postgres_read_deadline(deadline, "exact read metric calculation")
    return PostgresReadMetrics(
        fetched_records=fetched_records,
        result_bytes=result_bytes,
    )


def _origin_type_oid(
    description: Sequence[Column] | None,
    operation: str,
) -> int:
    if description is None or not description:
        raise PostgresDataValidationError(
            f"PostgreSQL {operation} did not expose result type provenance"
        )
    origin_type = description[0]
    if origin_type.name != "origin_type":
        raise PostgresDataValidationError(
            f"PostgreSQL {operation} returned an unexpected provenance column: "
            f"column_name={origin_type.name!r}"
        )
    return _require_bounded_integer(
        origin_type.type_code,
        f"{operation} origin type OID",
        1,
        UINT32_MAX,
    )


def _require_relation_manifest_description(
    description: Sequence[Column] | None,
    expected_row_type_oid: int,
) -> None:
    if description is None or len(description) != 9:
        actual_fields = 0 if description is None else len(description)
        raise PostgresDataValidationError(
            "PostgreSQL relation manifest query returned an unexpected field count: "
            f"expected=9, actual={actual_fields}"
        )
    _require_compiled_origin_type(description, expected_row_type_oid)
    requirements: tuple[tuple[str, frozenset[int]], ...] = (
        ("dataset_id", frozenset((25, 1043))),
        ("scope_digest", frozenset((25, 1043))),
        ("batch_id", frozenset((25, 1043))),
        ("state", frozenset((25, 1043))),
        ("business_date", frozenset((1082,))),
        ("source_cut", frozenset((25, 1043))),
        ("dataset_version", frozenset((25, 1043))),
        ("completed_at", frozenset((1184,))),
    )
    for column, (expected_name, allowed_type_oids) in zip(
        description[1:],
        requirements,
        strict=True,
    ):
        if column.name != expected_name:
            raise PostgresDataValidationError(
                "PostgreSQL relation manifest query returned an unexpected column alias: "
                f"expected={expected_name!r}, actual={column.name!r}"
            )
        type_oid = _require_bounded_integer(
            column.type_code,
            f"relation manifest {expected_name} type OID",
            1,
            UINT32_MAX,
        )
        if type_oid not in allowed_type_oids:
            raise PostgresDataValidationError(
                "PostgreSQL relation manifest query returned an unexpected column type: "
                f"field={expected_name!r}, type_oid={type_oid}, "
                f"allowed_type_oids={tuple(sorted(allowed_type_oids))!r}"
            )


def _require_compiled_origin_type(
    description: Sequence[Column] | None,
    expected_row_type_oid: int,
) -> None:
    observed_row_type_oid = _origin_type_oid(description, "compiled query")
    if observed_row_type_oid != expected_row_type_oid:
        raise PostgresMetadataError(
            "PostgreSQL compiled query resolved to a different relation identity: "
            f"expected_row_type_oid={expected_row_type_oid}, "
            f"observed_row_type_oid={observed_row_type_oid}"
        )


def _require_compiled_origin_types(
    description: Sequence[Column] | None,
    relations: tuple[PostgresQueryRelation, ...],
) -> None:
    if description is None or len(description) < len(relations):
        actual_fields = 0 if description is None else len(description)
        raise PostgresDataValidationError(
            "PostgreSQL compiled union query did not expose every relation provenance "
            f"column: expected_at_least={len(relations)}, actual={actual_fields}"
        )
    for index, _relation in enumerate(relations):
        column = description[index]
        expected_name = "origin_type" if index == 0 else f"origin_type_{index}"
        if column.name != expected_name:
            raise PostgresDataValidationError(
                "PostgreSQL compiled union query returned an unexpected provenance column: "
                f"index={index}, expected={expected_name!r}, actual={column.name!r}"
            )
        observed_row_type_oid = _require_bounded_integer(
            column.type_code,
            f"compiled union provenance descriptor type OID at index {index}",
            1,
            UINT32_MAX,
        )
        if observed_row_type_oid != 20:
            raise PostgresDataValidationError(
                "PostgreSQL compiled union query returned a non-bigint provenance witness: "
                f"index={index}, descriptor_type_oid={observed_row_type_oid}"
            )


def _require_compiled_query_provenance(
    rows: tuple[DatabaseRow, ...],
    query: PostgresQuery,
) -> None:
    provenance_fields = len(query.relations)
    observed_members: set[int] = set()
    for row_index, row in enumerate(rows):
        if len(row) < provenance_fields:
            raise PostgresDataValidationError(
                "PostgreSQL compiled union query returned fewer fields than its provenance "
                f"closure: row={row_index}, expected_at_least={provenance_fields}, "
                f"actual={len(row)}"
            )
        for index, (value, relation) in enumerate(
            zip(row[:provenance_fields], query.relations, strict=True)
        ):
            if value is None:
                continue
            observed_row_type_oid = _require_bounded_integer(
                value,
                f"compiled union provenance row type OID at row {row_index}, index {index}",
                1,
                UINT32_MAX,
            )
            expected_row_type_oid = relation.inspection.relation_row_type_oid
            if observed_row_type_oid != expected_row_type_oid:
                raise PostgresMetadataError(
                    "PostgreSQL compiled union query resolved a member to a different relation "
                    f"identity through its actual RTE: row={row_index}, index={index}, "
                    f"expected_row_type_oid={expected_row_type_oid}, "
                    f"observed_row_type_oid={observed_row_type_oid}"
                )
            observed_members.add(index)
    expected_members = set(range(provenance_fields))
    if observed_members != expected_members:
        raise PostgresMetadataError(
            "PostgreSQL compiled union query did not prove every acquired member's actual "
            "RTE identity: "
            f"missing_member_indexes={tuple(sorted(expected_members - observed_members))!r}"
        )


def _query_provenance_bytes(query: PostgresQuery) -> int:
    return len(query.relations) * _MAX_UINT32_DECIMAL_BYTES


def _query_physical_scan_count(query: PostgresQuery) -> int:
    return sum(1 for relation in query.relations if relation.contributes_rows)


def _require_compiled_full_scan_reservation(
    reserved_full_scans: int,
    expected_full_scans: int,
    operation: str,
) -> None:
    _validate_nonnegative_integer(reserved_full_scans, "reserved full scans")
    if reserved_full_scans != expected_full_scans:
        raise ValueError(
            f"PostgreSQL {operation} full-scan reservation does not match the compiled "
            f"physical query shape: reserved={reserved_full_scans}, "
            f"expected={expected_full_scans}"
        )


def _fetch_bounded_rows(
    cursor: ServerCursor[DatabaseRow],
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
    charge: PostgresSourceQueryCharge,
) -> tuple[DatabaseRow, ...]:
    records: list[DatabaseRow] = []
    total_bytes = 0
    while True:
        charge.require_fetch_deadline()
        remaining = max_records + 1 - len(records)
        fetch_records = min(_CURSOR_FETCH_RECORDS, remaining)
        batch = cursor.fetchmany(fetch_records)
        if not batch:
            break
        batch_bytes = tuple(_database_row_bytes(row) for row in batch)
        charge.consume_records(batch_bytes)
        observed_records = len(records) + len(batch)
        observed_bytes = total_bytes + sum(batch_bytes)
        if observed_records > max_records:
            raise PostgresResultLimitError(
                f"PostgreSQL query exceeded the reserved record budget: max_records={max_records}"
            )
        oversized_record = next(
            (value for value in batch_bytes if value > max_record_bytes),
            None,
        )
        if oversized_record is not None:
            raise PostgresResultLimitError(
                "PostgreSQL query returned a record above the byte budget: "
                f"record_bytes={oversized_record}, max_record_bytes={max_record_bytes}"
            )
        if observed_bytes > max_total_bytes:
            raise PostgresResultLimitError(
                "PostgreSQL query exceeded the total byte budget: "
                f"observed_bytes={observed_bytes}, max_total_bytes={max_total_bytes}"
            )
        total_bytes = observed_bytes
        records.extend(batch)
        if len(batch) < fetch_records:
            break
    return tuple(records)


def _parse_unsigned_decimal(value: object, maximum_digits: int) -> int:
    if type(value) is not str or not value or not value.isascii() or not value.isdecimal():
        raise PostgresDataValidationError(
            "PostgreSQL exact aggregate must be an unsigned canonical decimal string"
        )
    if len(value) > 1 and value[0] == "0":
        raise PostgresDataValidationError(
            "PostgreSQL exact aggregate must not contain leading zeroes"
        )
    if len(value) > maximum_digits:
        raise PostgresDataValidationError(
            "PostgreSQL exact aggregate exceeds its decimal digit bound: "
            f"digits={len(value)}, maximum={maximum_digits}"
        )
    return int(value)


def _parse_optional_int64(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    if type(value) is not str or not value or not value.isascii():
        raise PostgresDataValidationError(
            f"PostgreSQL {field_name} must be a canonical signed decimal string or null"
        )
    digits = value[1:] if value.startswith("-") else value
    if not digits.isdecimal() or (len(digits) > 1 and digits[0] == "0") or value == "-0":
        raise PostgresDataValidationError(
            f"PostgreSQL {field_name} must be a canonical signed decimal string or null"
        )
    parsed = int(value)
    if not -(1 << 63) <= parsed <= INT64_MAX:
        raise PostgresDataValidationError(
            f"PostgreSQL {field_name} is outside the signed int64 range"
        )
    return parsed


def _database_row_bytes(row: DatabaseRow) -> int:
    total = 0
    for value in row:
        if value is None:
            continue
        if type(value) is str:
            try:
                total += len(value.encode("utf-8", errors="strict"))
            except UnicodeEncodeError:
                raise PostgresDataValidationError(
                    "PostgreSQL returned text containing a surrogate code point"
                ) from None
            continue
        if type(value) is bytes:
            total += len(value)
            continue
        if type(value) is memoryview:
            total += value.nbytes
            continue
        if type(value) is bool:
            total += 1
            continue
        if type(value) is int:
            total += len(str(value).encode("ascii"))
            continue
        if type(value) is datetime:
            total += len(value.isoformat(timespec="microseconds").encode("ascii"))
            continue
        if type(value) is date:
            total += len(value.isoformat().encode("ascii"))
            continue
        raise PostgresDataValidationError(
            "PostgreSQL returned an unsupported result value type: "
            f"value_type={type(value).__name__}"
        )
    return total


def _validate_result_limits(
    max_records: int,
    max_record_bytes: int,
    max_total_bytes: int,
) -> None:
    _validate_positive_integer(max_records, "max_records")
    _validate_positive_integer(max_record_bytes, "max_record_bytes")
    _validate_positive_integer(max_total_bytes, "max_total_bytes")
    if max_record_bytes > max_total_bytes:
        raise ValueError(
            "max_record_bytes must not exceed max_total_bytes: "
            f"record={max_record_bytes}, total={max_total_bytes}"
        )


def _validate_metadata_limits(
    max_metadata_record_bytes: int,
    max_metadata_total_bytes: int,
) -> None:
    _validate_positive_integer(max_metadata_record_bytes, "max_metadata_record_bytes")
    _validate_positive_integer(max_metadata_total_bytes, "max_metadata_total_bytes")
    if max_metadata_record_bytes > max_metadata_total_bytes:
        raise ValueError(
            "max_metadata_record_bytes must not exceed max_metadata_total_bytes: "
            f"record={max_metadata_record_bytes}, total={max_metadata_total_bytes}"
        )


def _validate_postgres_query(query: object) -> None:
    if not isinstance(query, PostgresQuery):
        raise TypeError("query must be a PostgresQuery")
    _validate_positive_integer(
        query.max_encoded_envelope_bytes,
        "query.max_encoded_envelope_bytes",
    )
    if type(query.parameters) is not tuple:
        raise TypeError("query.parameters must be an immutable tuple")


def _executable_statement(statement: sql.Composable) -> ExecutableSql:
    if isinstance(statement, (sql.SQL, sql.Composed)):
        return statement
    raise TypeError("query.statement must be psycopg.sql.SQL or psycopg.sql.Composed")


def _require_schema(value: object) -> None:
    if not isinstance(value, CanonicalSchema):
        raise TypeError("schema must be a CanonicalSchema")


def _require_relation(value: object) -> None:
    if not isinstance(value, PostgresRelation):
        raise TypeError("relation must be a PostgresRelation")


def _require_relation_acquisition(value: object) -> None:
    if not isinstance(value, PostgresRelationAcquisition):
        raise TypeError("acquisition must be a PostgresRelationAcquisition")


def _require_inspected_relation(value: object) -> None:
    if not isinstance(value, PostgresInspectedRelation):
        raise TypeError("inspection must be a PostgresInspectedRelation")


def _require_protected_relation_inspection(value: object) -> None:
    if not isinstance(value, PostgresProtectedRelationInspection):
        raise TypeError("protected_relation must be a PostgresProtectedRelationInspection")


def _require_readiness_manifest_columns(value: object) -> None:
    if not isinstance(value, ReadinessManifestColumns):
        raise TypeError("columns must be ReadinessManifestColumns")


def _require_column_names(value: object, expected_count: int) -> None:
    if type(value) is not tuple:
        raise TypeError("column_names must be an immutable tuple")
    column_names = cast(tuple[object, ...], value)
    if len(column_names) != expected_count:
        raise ValueError(
            "column_names count must equal the logical schema field count: "
            f"expected={expected_count}, actual={len(column_names)}"
        )
    for index, column_name in enumerate(column_names):
        if type(column_name) is not str or not column_name or "\x00" in column_name:
            raise ValueError(
                "PostgreSQL column identifiers must be non-empty strings without U+0000: "
                f"column_index={index}"
            )


def _validate_relation_identifiers(relation: PostgresRelation, maximum_bytes: int) -> None:
    for index, component in enumerate(relation.components):
        _validate_identifier_bytes(component, f"relation component {index}", maximum_bytes)


def _validate_column_identifiers(column_names: tuple[str, ...], maximum_bytes: int) -> None:
    for index, column_name in enumerate(column_names):
        _validate_identifier_bytes(column_name, f"column identifier {index}", maximum_bytes)


def _validate_identifier_bytes(value: str, context: str, maximum_bytes: int) -> None:
    try:
        byte_length = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise PostgresMetadataError(
            f"PostgreSQL {context} contains a surrogate code point"
        ) from None
    if byte_length > maximum_bytes:
        raise PostgresMetadataError(
            f"PostgreSQL {context} exceeds the probed identifier limit: "
            f"utf8_bytes={byte_length}, maximum={maximum_bytes}"
        )


def _require_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        raise PostgresDataValidationError(
            f"PostgreSQL field {field_name!r} must be a non-empty string"
        )
    return value


def _require_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field_name)


def _require_nonempty_query_text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if "\x00" in value:
        raise ValueError(f"{field_name} must not contain U+0000")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ValueError(f"{field_name} must not contain surrogate code points") from None
    return value


def _validate_scope_digest_input(value: object) -> None:
    if type(value) is not str:
        raise TypeError("scope_digest must be a string")
    if not _is_sha256_hex(value):
        raise ValueError("scope_digest must be a lowercase hexadecimal SHA-256 digest")


def _require_sha256_hex(value: object, field_name: str) -> str:
    if type(value) is not str or not _is_sha256_hex(value):
        raise PostgresDataValidationError(
            f"PostgreSQL field {field_name!r} must be a lowercase hexadecimal SHA-256 digest"
        )
    return value


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _require_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise PostgresDataValidationError(f"PostgreSQL field {field_name!r} must be an integer")
    return value


def _require_bounded_integer(
    value: object,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    integer = _require_integer(value, field_name)
    if not minimum <= integer <= maximum:
        raise PostgresDataValidationError(
            f"PostgreSQL field {field_name!r} is outside its accepted range: "
            f"minimum={minimum}, maximum={maximum}"
        )
    return integer


def _require_optional_integer(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _require_integer(value, field_name)


def _require_boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise PostgresDataValidationError(f"PostgreSQL field {field_name!r} must be a boolean")
    return value


def _validate_positive_integer(value: object, field_name: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")


def _validate_nonnegative_integer(value: object, field_name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


def _require_postgres_read_deadline(
    deadline: PostgresReadDeadline,
    operation: str,
) -> int:
    if not isinstance(cast(object, deadline), PostgresReadDeadline):
        raise TypeError("deadline must be a PostgresReadDeadline")
    remaining_nanoseconds = deadline.deadline_nanoseconds - time.monotonic_ns()
    remaining_milliseconds = remaining_nanoseconds // 1_000_000
    if remaining_milliseconds < 1:
        raise PostgresReadDeadlineExceededError(
            "PostgreSQL deadline-bounded read exhausted its absolute monotonic deadline: "
            f"operation={operation!r}"
        )
    return remaining_milliseconds


def _deadline_statement_timeout_milliseconds(
    context_statement_timeout_milliseconds: int,
    deadline: PostgresReadDeadline,
    operation: str,
) -> int:
    _validate_positive_integer(
        context_statement_timeout_milliseconds,
        "context_statement_timeout_milliseconds",
    )
    remaining_milliseconds = _require_postgres_read_deadline(deadline, operation)
    return min(
        context_statement_timeout_milliseconds,
        deadline.statement_timeout_milliseconds,
        remaining_milliseconds,
    )


def _database_error_message(operation: str, error: psycopg.Error) -> str:
    return (
        f"PostgreSQL {operation} failed and invalidated the read context: "
        f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
    )


def _connection_error_message(
    settings: PostgresConnectionSettings,
    attempts: int,
    error: psycopg.Error,
) -> str:
    return (
        "PostgreSQL read context setup failed after bounded attempts: "
        f"host={settings.host!r}, port={settings.port}, dbname={settings.dbname!r}, "
        f"user={settings.user!r}, sslmode={settings.sslmode.value!r}, attempts={attempts}, "
        f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
    )


def _protected_acquisition_database_error_message(
    settings: PostgresConnectionSettings,
    error: psycopg.Error,
) -> str:
    return (
        "PostgreSQL protected acquisition failed after connection establishment and was not "
        "retried because the failure did not prove relation identity drift: "
        f"host={settings.host!r}, port={settings.port}, dbname={settings.dbname!r}, "
        f"user={settings.user!r}, error_type={type(error).__name__}, "
        f"sqlstate={error.sqlstate!r}"
    )
