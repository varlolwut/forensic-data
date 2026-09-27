import hashlib
import re
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from typing import Literal, final
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from forensic_data.acquisition import (
    AcquisitionValidationError,
    EarlyExecutionOutcome,
    RelationManifestEvidence,
    validate_relation_manifest_readiness,
)
from forensic_data.clickhouse import (
    ClickHouseDataValidationError,
    ClickHouseTransport,
    UnsupportedClickHouseProfileError,
    parse_clickhouse_json_rows,
    quote_clickhouse_identifier,
    validate_clickhouse_identifier,
    validate_clickhouse_text_scalar,
)
from forensic_data.contracts.errors import ContractValidationError
from forensic_data.contracts.model import LateArrivalPolicy, MinimumEvidence
from forensic_data.contracts.semantics import semantic_value_from_json
from forensic_data.planning import PlanDirection
from forensic_data.result import (
    ConsistencyLevel,
    ExecutionStatus,
    ReasonCode,
    ResultReason,
    SafeParameter,
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_UNSIGNED_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
_READONLY_TABLE_SETTING = re.compile(
    r"(?:^|,\s*)table_readonly\s*=\s*1(?:\s*,|$)",
    re.ASCII,
)
_MANIFEST_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_READINESS_ALIGNMENT_FIELDS = frozenset(("business_date", "source_cut"))
_MAX_TABLE_COLUMNS = 1_024
_READINESS_COLUMN_CONTRACT = (
    ("dataset_id", "String"),
    ("scope_digest", "FixedString(64)"),
    ("batch_id", "String"),
    ("state", "Enum8('building' = 1, 'complete' = 2)"),
    ("business_date", "Date"),
    ("source_cut", "Nullable(String)"),
    ("dataset_version", "Nullable(String)"),
    ("completed_at", "Nullable(DateTime64(6, 'UTC'))"),
    ("completion_revision", "Nullable(UInt64)"),
    ("publication_revision", "UInt64"),
)
_IMMUTABLE_VERSION_STRATEGY = "immutable_named_version"
_IMMUTABLE_VERSION_LIMITATIONS = (
    "HTTP queries do not share a transaction snapshot",
    "the connection endpoint must remain pinned to one ClickHouse server",
    "access-control policies and role assignments must remain stable while metadata is rechecked",
    "version immutability is asserted by the captured loader manifest",
)


class ClickHouseImmutableManifestError(ValueError):
    """A loader manifest cannot establish the declared immutable version."""


class _ImmutableVersionLocatorPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    database: str
    table: str
    uuid: str


class _ImmutableManifestPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[1]
    issuer: str
    dataset_id: str
    scope_digest: str
    expected_batch_id: str
    business_date: str
    source_cut: str
    dataset_version: str
    completed_at: str
    completion_revision: int = Field(ge=1)
    publication_revision: int = Field(ge=1)
    version_locator: _ImmutableVersionLocatorPayload
    immutability: Literal["asserted"]
    late_arrivals: Literal["next_batch"]


class _ReadinessPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_uuid: str
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: str
    source_cut: str | None
    dataset_version: str | None
    completed_at: str | None
    completion_revision: str | None
    publication_revision: str


class _VersionTablePayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    database: str
    table: str
    uuid: str
    server_uuid: str
    database_uuid: str
    database_engine: str
    table_engine: str
    engine_full: str
    partition_key: str
    sorting_key: str
    definition_sha256: str


class _TableColumnPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_uuid: str
    name: str
    type: str
    position: str
    default_kind: str
    default_expression: str


class _PolicyCountPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_uuid: str
    policy_count: str


@final
@dataclass(frozen=True, slots=True)
class ClickHouseReadinessLimits:
    max_response_bytes: int
    max_execution_time_seconds: int

    def __post_init__(self) -> None:
        _require_positive_integer(
            self.max_response_bytes,
            "ClickHouse readiness response byte limit",
        )
        _require_positive_integer(
            self.max_execution_time_seconds,
            "ClickHouse readiness execution time limit",
        )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseColumnIdentity:
    name: str
    declared_type: str
    position: int
    default_kind: str
    default_expression: str

    def __post_init__(self) -> None:
        _require_bounded_text(self.name, "bound column name")
        _require_bounded_text(self.declared_type, "bound column type")
        _require_positive_integer(self.position, "ClickHouse bound column position")
        _require_text(self.default_kind, "bound column default kind")
        _require_text(self.default_expression, "bound column default expression")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseVersionLocator:
    database: str
    table: str
    uuid: UUID

    def __post_init__(self) -> None:
        validate_clickhouse_identifier(self.database, "ClickHouse version database")
        validate_clickhouse_identifier(self.table, "ClickHouse version table")
        if type(self.uuid) is not UUID:
            raise TypeError("ClickHouse version UUID must be a UUID")
        if self.uuid.int == 0:
            raise ValueError("ClickHouse immutable version requires a non-zero table UUID")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseImmutableVersionManifest:
    manifest_version: int
    issuer: str
    dataset_id: str
    scope_digest: str
    expected_batch_id: str
    business_date: date
    source_cut: str
    dataset_version: str
    completed_at: datetime
    completion_revision: int
    publication_revision: int
    version_locator: ClickHouseVersionLocator
    immutability_evidence: ConsistencyLevel
    late_arrivals: LateArrivalPolicy
    artifact_sha256: str

    def __post_init__(self) -> None:
        if type(self.manifest_version) is not int or self.manifest_version != 1:
            raise ClickHouseImmutableManifestError(
                "ClickHouse immutable-version manifest version must be the exact integer 1"
            )
        for value, label in (
            (self.issuer, "manifest issuer"),
            (self.dataset_id, "manifest dataset ID"),
            (self.expected_batch_id, "manifest expected batch ID"),
            (self.source_cut, "manifest source cut"),
            (self.dataset_version, "manifest dataset version"),
        ):
            _require_bounded_text(value, label)
        _require_sha256(self.scope_digest, "manifest scope digest")
        if type(self.business_date) is not date or isinstance(self.business_date, datetime):
            raise ClickHouseImmutableManifestError(
                "ClickHouse manifest business_date must be an exact date"
            )
        _require_utc_datetime(self.completed_at, "manifest completed_at")
        _require_positive_integer(
            self.completion_revision,
            "ClickHouse manifest completion revision",
        )
        _require_positive_integer(
            self.publication_revision,
            "ClickHouse manifest publication revision",
        )
        if type(self.version_locator) is not ClickHouseVersionLocator:
            raise TypeError("version_locator must be ClickHouseVersionLocator")
        if self.immutability_evidence is not ConsistencyLevel.ASSERTED:
            raise ClickHouseImmutableManifestError(
                "ClickHouse loader manifest immutability must remain asserted"
            )
        if self.late_arrivals is not LateArrivalPolicy.NEXT_BATCH:
            raise ClickHouseImmutableManifestError(
                "ClickHouse immutable-version manifest requires late_arrivals='next_batch'"
            )
        _require_sha256(self.artifact_sha256, "manifest artifact digest")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseRelationManifestRecord:
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: date
    source_cut: str | None
    dataset_version: str | None
    completed_at: datetime | None
    completion_revision: int | None
    publication_revision: int

    def __post_init__(self) -> None:
        _require_bounded_text(self.dataset_id, "readiness dataset ID")
        _require_sha256(self.scope_digest, "readiness scope digest")
        _require_bounded_text(self.batch_id, "readiness batch ID")
        if self.state not in ("building", "complete"):
            raise ClickHouseDataValidationError(
                "ClickHouse readiness state must be exactly 'building' or 'complete'"
            )
        if type(self.business_date) is not date or isinstance(self.business_date, datetime):
            raise ClickHouseDataValidationError(
                "ClickHouse readiness business_date must be an exact date"
            )
        _require_optional_bounded_text(self.source_cut, "readiness source cut")
        _require_optional_bounded_text(self.dataset_version, "readiness dataset version")
        if self.completed_at is not None:
            _require_utc_datetime(self.completed_at, "readiness completed_at")
        if self.completion_revision is not None:
            _require_positive_integer(
                self.completion_revision,
                "ClickHouse readiness completion revision",
            )
        _require_positive_integer(
            self.publication_revision,
            "ClickHouse readiness publication revision",
        )
        if self.state == "building":
            return
        if (
            self.source_cut is None
            or self.dataset_version is None
            or self.completed_at is None
            or self.completion_revision is None
        ):
            raise ClickHouseDataValidationError(
                "complete ClickHouse readiness requires source_cut, dataset_version, "
                "completed_at, and completion_revision"
            )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseImmutableVersionRequest:
    direction: PlanDirection
    endpoint_profile: Literal["direct_single_server"]
    readiness_database: str
    readiness_table: str
    expected_issuer: str
    dataset_id: str
    scope_digest: str
    expected_batch_id: str
    alignment_fields: tuple[str, ...]
    minimum_evidence: MinimumEvidence
    late_arrivals: LateArrivalPolicy
    limits: ClickHouseReadinessLimits

    def __post_init__(self) -> None:
        if type(self.direction) is not PlanDirection:
            raise TypeError("ClickHouse readiness direction must be PlanDirection")
        _require_direct_single_server_endpoint(self.endpoint_profile)
        validate_clickhouse_identifier(
            self.readiness_database,
            "ClickHouse readiness database",
        )
        validate_clickhouse_identifier(self.readiness_table, "ClickHouse readiness table")
        _require_bounded_text(self.expected_issuer, "expected manifest issuer")
        _require_bounded_text(self.dataset_id, "readiness dataset ID")
        _require_sha256(self.scope_digest, "readiness scope digest")
        _require_bounded_text(self.expected_batch_id, "expected batch ID")
        if type(self.alignment_fields) is not tuple or not self.alignment_fields:
            raise ValueError(
                "ClickHouse readiness alignment fields must be a non-empty immutable tuple"
            )
        for field_name in self.alignment_fields:
            if type(field_name) is not str:
                raise TypeError("ClickHouse readiness alignment field names must be strings")
            if field_name not in _READINESS_ALIGNMENT_FIELDS:
                raise ValueError(
                    "ClickHouse readiness alignment fields support only business_date "
                    f"and source_cut: observed={field_name!r}"
                )
        if len(set(self.alignment_fields)) != len(self.alignment_fields):
            raise ValueError("ClickHouse readiness alignment field names must be unique")
        if type(self.minimum_evidence) is not MinimumEvidence:
            raise TypeError("ClickHouse minimum evidence must be MinimumEvidence")
        if self.late_arrivals is not LateArrivalPolicy.NEXT_BATCH:
            raise ValueError("ClickHouse readiness requires late_arrivals='next_batch'")
        if type(self.limits) is not ClickHouseReadinessLimits:
            raise TypeError("ClickHouse readiness limits must be ClickHouseReadinessLimits")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseTableIdentity:
    server_uuid: UUID
    database: str
    database_uuid: UUID
    table: str
    uuid: UUID
    database_engine: str
    table_engine: str
    engine_full: str
    partition_key: str
    sorting_key: str
    table_readonly: bool
    definition_sha256: str
    columns: tuple[ClickHouseColumnIdentity, ...]

    def __post_init__(self) -> None:
        if type(self.server_uuid) is not UUID or self.server_uuid.int == 0:
            raise ClickHouseDataValidationError(
                "ClickHouse bound version requires a non-zero server UUID"
            )
        validate_clickhouse_identifier(self.database, "ClickHouse bound version database")
        if type(self.database_uuid) is not UUID or self.database_uuid.int == 0:
            raise ClickHouseDataValidationError(
                "ClickHouse bound version requires a non-zero database UUID"
            )
        validate_clickhouse_identifier(self.table, "ClickHouse bound version table")
        if type(self.uuid) is not UUID or self.uuid.int == 0:
            raise ClickHouseDataValidationError(
                "ClickHouse bound version requires a non-zero table UUID"
            )
        _require_bounded_text(self.database_engine, "bound version database engine")
        _require_bounded_text(self.table_engine, "bound version table engine")
        _require_text(self.engine_full, "bound version full engine definition")
        if not self.engine_full:
            raise ClickHouseDataValidationError(
                "ClickHouse bound version full engine definition must not be empty"
            )
        _require_text(self.partition_key, "bound version partition key")
        _require_text(self.sorting_key, "bound version sorting key")
        if type(self.table_readonly) is not bool:
            raise TypeError("ClickHouse bound version table_readonly must be a boolean")
        _require_sha256(self.definition_sha256, "bound version definition digest")
        if type(self.columns) is not tuple:
            raise TypeError("ClickHouse bound table columns must be an immutable tuple")
        for expected_position, column in enumerate(self.columns, start=1):
            if type(column) is not ClickHouseColumnIdentity:
                raise TypeError("ClickHouse bound table columns must be column identities")
            if column.position != expected_position:
                raise ClickHouseDataValidationError(
                    "ClickHouse bound table column positions must be contiguous from one"
                )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseNamedVersionObservation:
    context_id: UUID
    request: ClickHouseImmutableVersionRequest
    manifest: ClickHouseImmutableVersionManifest
    readiness_record: ClickHouseRelationManifestRecord
    readiness_evidence: RelationManifestEvidence
    readiness_identity: ClickHouseTableIdentity
    version_identity: ClickHouseTableIdentity
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self.context_id) is not UUID:
            raise TypeError("ClickHouse named-version context ID must be a UUID")
        if type(self.request) is not ClickHouseImmutableVersionRequest:
            raise TypeError("request must be ClickHouseImmutableVersionRequest")
        if type(self.manifest) is not ClickHouseImmutableVersionManifest:
            raise TypeError("manifest must be ClickHouseImmutableVersionManifest")
        if type(self.readiness_record) is not ClickHouseRelationManifestRecord:
            raise TypeError("readiness_record must be ClickHouseRelationManifestRecord")
        if type(self.readiness_evidence) is not RelationManifestEvidence:
            raise TypeError("readiness_evidence must be RelationManifestEvidence")
        if type(self.readiness_identity) is not ClickHouseTableIdentity:
            raise TypeError("readiness_identity must be ClickHouseTableIdentity")
        if type(self.version_identity) is not ClickHouseTableIdentity:
            raise TypeError("version_identity must be ClickHouseTableIdentity")
        if self.readiness_evidence.evidence_level is not ConsistencyLevel.VERIFIED:
            raise ValueError("ClickHouse query readiness must remain database-verified")
        _require_utc_datetime(self.observed_at, "named-version observation observed_at")
        _require_request_manifest_closure(self.request, self.manifest)
        _require_manifest_record_closure(self.manifest, self.readiness_record)
        _require_readiness_identity(self.request, self.readiness_identity)
        _require_locator_identity(self.manifest.version_locator, self.version_identity)
        _require_same_server(self.readiness_identity, self.version_identity)
        _require_sealed_named_version_identity(self.version_identity)


@final
@dataclass(frozen=True, slots=True)
class ClickHouseNamedVersionConfirmation:
    observation: ClickHouseNamedVersionObservation
    final_readiness_record: ClickHouseRelationManifestRecord
    final_readiness_evidence: RelationManifestEvidence
    final_readiness_identity: ClickHouseTableIdentity
    final_version_identity: ClickHouseTableIdentity
    confirmed_at: datetime

    def __post_init__(self) -> None:
        if type(self.observation) is not ClickHouseNamedVersionObservation:
            raise TypeError("observation must be ClickHouseNamedVersionObservation")
        if self.final_readiness_record != self.observation.readiness_record:
            raise ValueError("confirmed ClickHouse readiness differs from its observation")
        if self.final_readiness_evidence != self.observation.readiness_evidence:
            raise ValueError("confirmed ClickHouse readiness evidence differs from its observation")
        if self.final_readiness_identity != self.observation.readiness_identity:
            raise ValueError("confirmed ClickHouse readiness identity differs from its observation")
        if self.final_version_identity != self.observation.version_identity:
            raise ValueError("confirmed ClickHouse version identity differs from its observation")
        _require_utc_datetime(self.confirmed_at, "named-version confirmation confirmed_at")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseImmutableVersionBinding:
    context_id: UUID
    strategy: str
    request: ClickHouseImmutableVersionRequest
    manifest: ClickHouseImmutableVersionManifest
    readiness_record: ClickHouseRelationManifestRecord
    readiness_evidence: RelationManifestEvidence
    readiness_identity: ClickHouseTableIdentity
    version_identity: ClickHouseTableIdentity
    stable_read_evidence: ConsistencyLevel
    overall_evidence: ConsistencyLevel
    opened_at: datetime
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.context_id) is not UUID:
            raise TypeError("ClickHouse immutable context ID must be a UUID")
        if self.strategy != _IMMUTABLE_VERSION_STRATEGY:
            raise ValueError("ClickHouse immutable context has an unsupported strategy")
        if type(self.request) is not ClickHouseImmutableVersionRequest:
            raise TypeError("request must be ClickHouseImmutableVersionRequest")
        if type(self.manifest) is not ClickHouseImmutableVersionManifest:
            raise TypeError("manifest must be ClickHouseImmutableVersionManifest")
        if type(self.readiness_record) is not ClickHouseRelationManifestRecord:
            raise TypeError("readiness_record must be ClickHouseRelationManifestRecord")
        if type(self.readiness_evidence) is not RelationManifestEvidence:
            raise TypeError("readiness_evidence must be RelationManifestEvidence")
        if type(self.readiness_identity) is not ClickHouseTableIdentity:
            raise TypeError("readiness_identity must be ClickHouseTableIdentity")
        if type(self.version_identity) is not ClickHouseTableIdentity:
            raise TypeError("version_identity must be ClickHouseTableIdentity")
        if self.readiness_evidence.evidence_level is not ConsistencyLevel.VERIFIED:
            raise ValueError("ClickHouse query readiness must remain database-verified")
        if self.stable_read_evidence is not ConsistencyLevel.ASSERTED:
            raise ValueError("ClickHouse immutable-version stability must remain asserted")
        if self.overall_evidence is not ConsistencyLevel.ASSERTED:
            raise ValueError("ClickHouse overall evidence must equal its asserted weak component")
        _require_utc_datetime(self.opened_at, "immutable context opened_at")
        if self.limitations != _IMMUTABLE_VERSION_LIMITATIONS:
            raise ValueError("ClickHouse immutable context limitations are incomplete")
        _require_request_manifest_closure(self.request, self.manifest)
        _require_manifest_record_closure(self.manifest, self.readiness_record)
        if (
            self.readiness_identity.database != self.request.readiness_database
            or self.readiness_identity.table != self.request.readiness_table
            or self.readiness_identity.database_engine != "Atomic"
            or self.readiness_identity.table_engine != "MergeTree"
            or self.readiness_identity.table_readonly
        ):
            raise ValueError(
                "ClickHouse readiness identity is not the bound writable Atomic MergeTree"
            )
        _require_locator_identity(self.manifest.version_locator, self.version_identity)
        _require_same_server(self.readiness_identity, self.version_identity)
        if (
            self.version_identity.database_engine != "Atomic"
            or self.version_identity.table_engine != "MergeTree"
            or not self.version_identity.table_readonly
        ):
            raise ValueError("ClickHouse immutable version is not a sealed plain Atomic MergeTree")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseImmutableVersionConfirmation:
    binding: ClickHouseImmutableVersionBinding
    final_readiness_record: ClickHouseRelationManifestRecord
    final_readiness_evidence: RelationManifestEvidence
    final_readiness_identity: ClickHouseTableIdentity
    final_version_identity: ClickHouseTableIdentity
    confirmed_at: datetime

    def __post_init__(self) -> None:
        if type(self.binding) is not ClickHouseImmutableVersionBinding:
            raise TypeError("binding must be ClickHouseImmutableVersionBinding")
        if self.final_readiness_record != self.binding.readiness_record:
            raise ValueError("confirmed ClickHouse readiness differs from its initial binding")
        if self.final_readiness_evidence != self.binding.readiness_evidence:
            raise ValueError("confirmed ClickHouse readiness evidence differs from its binding")
        if self.final_readiness_identity != self.binding.readiness_identity:
            raise ValueError("confirmed ClickHouse readiness identity differs from its binding")
        if self.final_version_identity != self.binding.version_identity:
            raise ValueError("confirmed ClickHouse version identity differs from its binding")
        _require_utc_datetime(self.confirmed_at, "immutable context confirmed_at")


def parse_clickhouse_immutable_version_manifest(
    payload: bytes,
    max_bytes: int,
) -> ClickHouseImmutableVersionManifest:
    if type(payload) is not bytes:
        raise TypeError("ClickHouse immutable-version manifest payload must be bytes")
    _require_positive_integer(max_bytes, "ClickHouse manifest byte limit")
    if not payload:
        raise ClickHouseImmutableManifestError(
            "ClickHouse immutable-version manifest must not be empty"
        )
    if len(payload) > max_bytes:
        raise ClickHouseImmutableManifestError(
            "ClickHouse immutable-version manifest exceeds its byte limit: "
            f"max_bytes={max_bytes}, actual_bytes={len(payload)}"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ClickHouseImmutableManifestError(
            "ClickHouse immutable-version manifest is not strict UTF-8: "
            f"byte_start={error.start}, byte_end={error.end}"
        ) from None
    try:
        semantic_value = semantic_value_from_json(text)
        parsed = _ImmutableManifestPayload.model_validate(semantic_value)
    except (ContractValidationError, ValidationError) as error:
        raise ClickHouseImmutableManifestError(
            f"ClickHouse immutable-version manifest is invalid: cause_type={type(error).__name__}"
        ) from None
    try:
        locator = ClickHouseVersionLocator(
            database=parsed.version_locator.database,
            table=parsed.version_locator.table,
            uuid=_parse_uuid(parsed.version_locator.uuid, "manifest version locator UUID"),
        )
        return ClickHouseImmutableVersionManifest(
            manifest_version=parsed.version,
            issuer=parsed.issuer,
            dataset_id=parsed.dataset_id,
            scope_digest=parsed.scope_digest,
            expected_batch_id=parsed.expected_batch_id,
            business_date=_parse_date(parsed.business_date, "manifest business_date"),
            source_cut=parsed.source_cut,
            dataset_version=parsed.dataset_version,
            completed_at=_parse_utc_datetime(parsed.completed_at, "manifest completed_at"),
            completion_revision=parsed.completion_revision,
            publication_revision=parsed.publication_revision,
            version_locator=locator,
            immutability_evidence=ConsistencyLevel(parsed.immutability),
            late_arrivals=LateArrivalPolicy(parsed.late_arrivals),
            artifact_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except (ClickHouseDataValidationError, ValueError) as error:
        raise ClickHouseImmutableManifestError(
            "ClickHouse immutable-version manifest contains invalid typed values: "
            f"cause_type={type(error).__name__}"
        ) from None


def observe_clickhouse_named_version(
    transport: ClickHouseTransport,
    request: ClickHouseImmutableVersionRequest,
    manifest: ClickHouseImmutableVersionManifest,
) -> ClickHouseNamedVersionObservation | EarlyExecutionOutcome:
    _require_transport(transport)
    if type(request) is not ClickHouseImmutableVersionRequest:
        raise TypeError("request must be ClickHouseImmutableVersionRequest")
    if type(manifest) is not ClickHouseImmutableVersionManifest:
        raise TypeError("manifest must be ClickHouseImmutableVersionManifest")
    _require_request_manifest_closure(request, manifest)
    _require_direct_single_server_endpoint(request.endpoint_profile)
    initial_readiness_identity = _inspect_clickhouse_readiness_table(transport, request)
    initial = _read_current_readiness(
        transport,
        request,
        initial_readiness_identity.server_uuid,
    )
    if isinstance(initial, EarlyExecutionOutcome):
        return initial
    if not _manifest_record_matches(manifest, initial.record):
        return _not_ready_outcome(
            request,
            "ClickHouse readiness and immutable-version manifest are not one publication",
        )
    identity = _inspect_clickhouse_named_version_table(
        transport,
        manifest.version_locator,
        request.limits,
    )
    _require_sealed_named_version_identity(identity)
    confirmed = _read_current_readiness(
        transport,
        request,
        initial_readiness_identity.server_uuid,
    )
    if isinstance(confirmed, EarlyExecutionOutcome):
        return confirmed
    if confirmed != initial:
        return _cut_mismatch_outcome(
            request,
            "ClickHouse readiness changed while the immutable version was being bound",
        )
    confirmed_readiness_identity = _inspect_clickhouse_readiness_table(transport, request)
    if confirmed_readiness_identity != initial_readiness_identity:
        return _cut_mismatch_outcome(
            request,
            "ClickHouse readiness table identity changed while the version was being bound",
        )
    confirmed_version_identity = _inspect_clickhouse_named_version_table(
        transport,
        manifest.version_locator,
        request.limits,
    )
    _require_sealed_named_version_identity(confirmed_version_identity)
    if confirmed_version_identity != identity:
        return _cut_mismatch_outcome(
            request,
            "ClickHouse named version table identity changed while it was being bound",
        )
    return ClickHouseNamedVersionObservation(
        context_id=uuid4(),
        request=request,
        manifest=manifest,
        readiness_record=confirmed.record,
        readiness_evidence=confirmed.evidence,
        readiness_identity=confirmed_readiness_identity,
        version_identity=confirmed_version_identity,
        observed_at=datetime.now(UTC),
    )


def confirm_clickhouse_named_version(
    transport: ClickHouseTransport,
    observation: ClickHouseNamedVersionObservation,
) -> ClickHouseNamedVersionConfirmation | EarlyExecutionOutcome:
    _require_transport(transport)
    if type(observation) is not ClickHouseNamedVersionObservation:
        raise TypeError("observation must be ClickHouseNamedVersionObservation")
    first = _read_current_readiness(
        transport,
        observation.request,
        observation.readiness_identity.server_uuid,
    )
    if isinstance(first, EarlyExecutionOutcome):
        return first
    if (
        first.record != observation.readiness_record
        or first.evidence != observation.readiness_evidence
    ):
        return _cut_mismatch_outcome(
            observation.request,
            "ClickHouse readiness cut differs from the bound immutable version",
        )
    readiness_identity = _inspect_clickhouse_readiness_table(
        transport,
        observation.request,
    )
    if readiness_identity != observation.readiness_identity:
        return _cut_mismatch_outcome(
            observation.request,
            "ClickHouse readiness table identity differs from the bound context",
        )
    identity = _inspect_clickhouse_named_version_table(
        transport,
        observation.manifest.version_locator,
        observation.request.limits,
    )
    _require_sealed_named_version_identity(identity)
    if identity != observation.version_identity:
        return _cut_mismatch_outcome(
            observation.request,
            "ClickHouse named version table identity differs from the bound version",
        )
    second = _read_current_readiness(
        transport,
        observation.request,
        observation.readiness_identity.server_uuid,
    )
    if isinstance(second, EarlyExecutionOutcome):
        return second
    if second != first:
        return _cut_mismatch_outcome(
            observation.request,
            "ClickHouse readiness changed during final immutable-version confirmation",
        )
    return ClickHouseNamedVersionConfirmation(
        observation=observation,
        final_readiness_record=second.record,
        final_readiness_evidence=second.evidence,
        final_readiness_identity=readiness_identity,
        final_version_identity=identity,
        confirmed_at=datetime.now(UTC),
    )


def acquire_clickhouse_immutable_version(
    transport: ClickHouseTransport,
    request: ClickHouseImmutableVersionRequest,
    manifest: ClickHouseImmutableVersionManifest,
) -> ClickHouseImmutableVersionBinding | EarlyExecutionOutcome:
    _require_transport(transport)
    if type(request) is not ClickHouseImmutableVersionRequest:
        raise TypeError("request must be ClickHouseImmutableVersionRequest")
    if type(manifest) is not ClickHouseImmutableVersionManifest:
        raise TypeError("manifest must be ClickHouseImmutableVersionManifest")
    _require_request_manifest_closure(request, manifest)
    if request.minimum_evidence is MinimumEvidence.VERIFIED:
        return _unsupported_evidence_outcome(request)
    observation = observe_clickhouse_named_version(transport, request, manifest)
    if isinstance(observation, EarlyExecutionOutcome):
        return observation
    _require_plain_immutable_version_identity(observation.version_identity)
    return ClickHouseImmutableVersionBinding(
        context_id=observation.context_id,
        strategy=_IMMUTABLE_VERSION_STRATEGY,
        request=request,
        manifest=manifest,
        readiness_record=observation.readiness_record,
        readiness_evidence=observation.readiness_evidence,
        readiness_identity=observation.readiness_identity,
        version_identity=observation.version_identity,
        stable_read_evidence=manifest.immutability_evidence,
        overall_evidence=ConsistencyLevel.ASSERTED,
        opened_at=observation.observed_at,
        limitations=_IMMUTABLE_VERSION_LIMITATIONS,
    )


def confirm_clickhouse_immutable_version(
    transport: ClickHouseTransport,
    binding: ClickHouseImmutableVersionBinding,
) -> ClickHouseImmutableVersionConfirmation | EarlyExecutionOutcome:
    _require_transport(transport)
    if type(binding) is not ClickHouseImmutableVersionBinding:
        raise TypeError("binding must be ClickHouseImmutableVersionBinding")
    _require_plain_immutable_version_identity(binding.version_identity)
    observation = ClickHouseNamedVersionObservation(
        context_id=binding.context_id,
        request=binding.request,
        manifest=binding.manifest,
        readiness_record=binding.readiness_record,
        readiness_evidence=binding.readiness_evidence,
        readiness_identity=binding.readiness_identity,
        version_identity=binding.version_identity,
        observed_at=binding.opened_at,
    )
    confirmation = confirm_clickhouse_named_version(transport, observation)
    if isinstance(confirmation, EarlyExecutionOutcome):
        return confirmation
    _require_plain_immutable_version_identity(confirmation.final_version_identity)
    return ClickHouseImmutableVersionConfirmation(
        binding=binding,
        final_readiness_record=confirmation.final_readiness_record,
        final_readiness_evidence=confirmation.final_readiness_evidence,
        final_readiness_identity=confirmation.final_readiness_identity,
        final_version_identity=confirmation.final_version_identity,
        confirmed_at=confirmation.confirmed_at,
    )


def inspect_clickhouse_version_table(
    transport: ClickHouseTransport,
    locator: ClickHouseVersionLocator,
    limits: ClickHouseReadinessLimits,
    endpoint_profile: Literal["direct_single_server"],
) -> ClickHouseTableIdentity:
    _require_transport(transport)
    _require_direct_single_server_endpoint(endpoint_profile)
    if type(locator) is not ClickHouseVersionLocator:
        raise TypeError("locator must be ClickHouseVersionLocator")
    if type(limits) is not ClickHouseReadinessLimits:
        raise TypeError("limits must be ClickHouseReadinessLimits")
    identity = _inspect_clickhouse_named_version_table(
        transport,
        locator,
        limits,
    )
    _require_plain_immutable_version_identity(identity)
    return identity


def _inspect_clickhouse_named_version_table(
    transport: ClickHouseTransport,
    locator: ClickHouseVersionLocator,
    limits: ClickHouseReadinessLimits,
) -> ClickHouseTableIdentity:
    identity = _inspect_clickhouse_table(
        transport,
        locator.database,
        locator.table,
        limits,
        "inspect_immutable_version_table",
    )
    result = replace(
        identity,
        columns=_inspect_clickhouse_columns(
            transport,
            locator.database,
            locator.table,
            limits,
            identity.server_uuid,
        ),
    )
    _require_locator_identity(locator, result)
    if result.database_engine != "Atomic":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse immutable named-version strategy requires an Atomic database: "
            f"database={result.database!r}, observed_engine={result.database_engine!r}"
        )
    return result


def _require_sealed_named_version_identity(identity: ClickHouseTableIdentity) -> None:
    if identity.database_engine != "Atomic" or not identity.table_readonly:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse named-version observation requires a sealed table: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"observed_engine={identity.table_engine!r}, "
            f"table_readonly={identity.table_readonly!r}"
        )


def _require_plain_immutable_version_identity(identity: ClickHouseTableIdentity) -> None:
    if identity.database_engine != "Atomic":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse immutable named-version strategy requires an Atomic database: "
            f"database={identity.database!r}, observed_engine={identity.database_engine!r}"
        )
    if identity.table_engine != "MergeTree" or not identity.table_readonly:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse immutable named-version strategy requires a sealed plain MergeTree: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"observed_engine={identity.table_engine!r}, "
            f"table_readonly={identity.table_readonly!r}"
        )


def _inspect_clickhouse_readiness_table(
    transport: ClickHouseTransport,
    request: ClickHouseImmutableVersionRequest,
) -> ClickHouseTableIdentity:
    identity = _inspect_clickhouse_table(
        transport,
        request.readiness_database,
        request.readiness_table,
        request.limits,
        "inspect_immutable_version_readiness_table",
    )
    result = replace(
        identity,
        columns=_inspect_clickhouse_columns(
            transport,
            request.readiness_database,
            request.readiness_table,
            request.limits,
            identity.server_uuid,
        ),
    )
    if (
        result.database_engine != "Atomic"
        or result.table_engine != "MergeTree"
        or result.table_readonly
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse readiness head requires a writable plain MergeTree in an Atomic "
            "database: "
            f"database={result.database!r}, table={result.table!r}, "
            f"database_engine={result.database_engine!r}, "
            f"table_engine={result.table_engine!r}, table_readonly={result.table_readonly!r}"
        )
    observed_columns = tuple((column.name, column.declared_type) for column in result.columns)
    if observed_columns != _READINESS_COLUMN_CONTRACT or any(
        column.default_kind or column.default_expression for column in result.columns
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse readiness table does not match the exact supported physical "
            "column contract: "
            f"database={result.database!r}, table={result.table!r}, "
            f"observed_columns={observed_columns!r}"
        )
    return result


def _require_readiness_identity(
    request: ClickHouseImmutableVersionRequest,
    identity: ClickHouseTableIdentity,
) -> None:
    if (
        identity.database != request.readiness_database
        or identity.table != request.readiness_table
        or identity.database_engine != "Atomic"
        or identity.table_engine != "MergeTree"
        or identity.table_readonly
    ):
        raise ValueError("ClickHouse readiness identity is not the bound writable Atomic MergeTree")


def _inspect_clickhouse_table(
    transport: ClickHouseTransport,
    database: str,
    table: str,
    limits: ClickHouseReadinessLimits,
    operation: str,
) -> ClickHouseTableIdentity:
    result = transport.execute_raw(
        query=(
            "SELECT database, name AS table, toString(uuid) AS uuid, "
            "toString(serverUUID()) AS server_uuid, "
            "toString((SELECT any(uuid) FROM system.databases "
            "WHERE name = {database:String})) AS database_uuid, "
            "(SELECT any(engine) FROM system.databases "
            "WHERE name = {database:String}) AS database_engine, "
            "engine AS table_engine, engine_full, partition_key, sorting_key, "
            "lower(hex(SHA256(create_table_query))) AS definition_sha256 "
            "FROM system.tables WHERE database = {database:String} "
            "AND name = {table:String} ORDER BY uuid LIMIT 2"
        ),
        parameters={"database": database, "table": table},
        settings=_bounded_settings(limits, 2),
        result_format="JSONEachRow",
        max_response_bytes=limits.max_response_bytes,
        operation=operation,
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _VersionTablePayload,
        "immutable version table catalog",
    )
    if len(rows) != 1:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse table locator must resolve exactly one table: "
            f"database={database!r}, table={table!r}, actual={len(rows)}"
        )
    row = rows[0]
    server_uuid = _parse_uuid(row.server_uuid, "catalog server UUID")
    _require_no_clickhouse_row_policies(
        transport,
        database,
        table,
        limits,
        server_uuid,
    )
    try:
        return ClickHouseTableIdentity(
            server_uuid=server_uuid,
            database=row.database,
            database_uuid=_parse_uuid(row.database_uuid, "catalog database UUID"),
            table=row.table,
            uuid=_parse_uuid(row.uuid, "catalog table UUID"),
            database_engine=row.database_engine,
            table_engine=row.table_engine,
            engine_full=row.engine_full,
            partition_key=row.partition_key,
            sorting_key=row.sorting_key,
            table_readonly=_engine_is_readonly(row.engine_full),
            definition_sha256=row.definition_sha256,
            columns=(),
        )
    except (TypeError, ValueError) as error:
        raise ClickHouseDataValidationError(
            "ClickHouse table catalog contains invalid typed identity values: "
            f"database={database!r}, table={table!r}, "
            f"cause_type={type(error).__name__}"
        ) from None


def _require_no_clickhouse_row_policies(
    transport: ClickHouseTransport,
    database: str,
    table: str,
    limits: ClickHouseReadinessLimits,
    expected_server_uuid: UUID,
) -> None:
    system_policy_result = transport.execute_raw(
        query="SHOW CREATE ROW POLICIES ON system.*",
        parameters={},
        settings=_bounded_settings(limits, 1),
        result_format="TabSeparatedRaw",
        max_response_bytes=limits.max_response_bytes,
        operation="inspect_system_row_policy_visibility",
    )
    if system_policy_result.payload:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse immutable-version strategy requires unfiltered system access-control "
            "metadata; at least one row policy targets system.*"
        )
    target_policy_result = transport.execute_raw(
        query=(
            "SELECT toString(serverUUID()) AS server_uuid, "
            "toString((SELECT count() FROM system.row_policies "
            "WHERE database = {database:String} "
            "AND (table = {table:String} OR empty(table)))) AS policy_count"
        ),
        parameters={"database": database, "table": table},
        settings=_bounded_settings(limits, 1),
        result_format="JSONEachRow",
        max_response_bytes=limits.max_response_bytes,
        operation="inspect_immutable_version_row_policies",
    )
    policy_rows = parse_clickhouse_json_rows(
        target_policy_result.payload,
        _PolicyCountPayload,
        "immutable version row-policy catalog",
    )
    if len(policy_rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse row-policy catalog count must return exactly one row: "
            f"database={database!r}, table={table!r}, actual={len(policy_rows)}"
        )
    _require_matching_server_uuid(
        policy_rows[0].server_uuid,
        expected_server_uuid,
        "row-policy catalog",
    )
    policy_count = _parse_nonnegative_integer(
        policy_rows[0].policy_count,
        "row-policy catalog count",
    )
    if policy_count:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse immutable-version strategy does not support row policies on the "
            "readiness or named-version relation: "
            f"database={database!r}, table={table!r}, policy_count={policy_count}"
        )


def _inspect_clickhouse_columns(
    transport: ClickHouseTransport,
    database: str,
    table: str,
    limits: ClickHouseReadinessLimits,
    expected_server_uuid: UUID,
) -> tuple[ClickHouseColumnIdentity, ...]:
    max_result_rows = _MAX_TABLE_COLUMNS + 1
    result = transport.execute_raw(
        query=(
            "SELECT toString(serverUUID()) AS server_uuid, name, type, "
            "toString(position) AS position, default_kind, "
            "default_expression FROM system.columns AS catalog_column "
            "WHERE database = {database:String} AND table = {table:String} "
            f"ORDER BY catalog_column.position LIMIT {max_result_rows}"
        ),
        parameters={"database": database, "table": table},
        settings=_bounded_settings(limits, max_result_rows),
        result_format="JSONEachRow",
        max_response_bytes=limits.max_response_bytes,
        operation="inspect_immutable_version_columns",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _TableColumnPayload,
        "immutable version column catalog",
    )
    if not rows or len(rows) > _MAX_TABLE_COLUMNS:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse immutable-version table column count is outside the supported "
            f"profile: database={database!r}, table={table!r}, actual={len(rows)}, "
            f"maximum={_MAX_TABLE_COLUMNS}"
        )
    for row in rows:
        _require_matching_server_uuid(
            row.server_uuid,
            expected_server_uuid,
            "column catalog",
        )
    try:
        return tuple(
            ClickHouseColumnIdentity(
                name=row.name,
                declared_type=row.type,
                position=_parse_positive_integer(row.position, "catalog column position"),
                default_kind=row.default_kind,
                default_expression=row.default_expression,
            )
            for row in rows
        )
    except (TypeError, ValueError) as error:
        raise ClickHouseDataValidationError(
            "ClickHouse column catalog contains invalid typed identity values: "
            f"database={database!r}, table={table!r}, "
            f"cause_type={type(error).__name__}"
        ) from None


@final
@dataclass(frozen=True, slots=True)
class _ObservedReadiness:
    record: ClickHouseRelationManifestRecord
    evidence: RelationManifestEvidence


def _read_current_readiness(
    transport: ClickHouseTransport,
    request: ClickHouseImmutableVersionRequest,
    expected_server_uuid: UUID,
) -> _ObservedReadiness | EarlyExecutionOutcome:
    relation = (
        f"{quote_clickhouse_identifier(request.readiness_database)}."
        f"{quote_clickhouse_identifier(request.readiness_table)}"
    )
    result = transport.execute_raw(
        query=(
            "SELECT toString(serverUUID()) AS server_uuid, dataset_id, "
            "toString(scope_digest) AS scope_digest, batch_id, "
            "toString(state) AS state, toString(business_date) AS business_date, "
            "source_cut, dataset_version, "
            "if(completed_at IS NULL, NULL, "
            "formatDateTime(assumeNotNull(completed_at), "
            "'%Y-%m-%dT%H:%i:%S.%fZ', 'UTC')) AS completed_at, "
            "toString(completion_revision) AS completion_revision, "
            "toString(publication_revision) AS publication_revision FROM "
            f"{relation} AS readiness WHERE dataset_id = {{dataset_id:String}} "
            "AND scope_digest = {scope_digest:String} "
            "ORDER BY readiness.publication_revision DESC LIMIT 2"
        ),
        parameters={
            "dataset_id": request.dataset_id,
            "scope_digest": request.scope_digest,
        },
        settings=_bounded_settings(request.limits, 2),
        result_format="JSONEachRow",
        max_response_bytes=request.limits.max_response_bytes,
        operation="read_immutable_version_readiness",
    )
    payload_rows = parse_clickhouse_json_rows(
        result.payload,
        _ReadinessPayload,
        "immutable version readiness",
    )
    for payload_row in payload_rows:
        _require_matching_server_uuid(
            payload_row.server_uuid,
            expected_server_uuid,
            "readiness query",
        )
    records = _current_readiness_records(tuple(_readiness_record(row) for row in payload_rows))
    try:
        evidence = validate_relation_manifest_readiness(
            direction=request.direction,
            rows=records,
            expected_dataset_id=request.dataset_id,
            expected_scope_digest=request.scope_digest,
            expected_batch_id=request.expected_batch_id,
            alignment_fields=request.alignment_fields,
            minimum_evidence=request.minimum_evidence,
            late_arrivals=request.late_arrivals,
        )
    except AcquisitionValidationError as error:
        raise ClickHouseDataValidationError(
            "ClickHouse readiness record violates the typed manifest contract: "
            f"cause_type={type(error).__name__}"
        ) from None
    if isinstance(evidence, EarlyExecutionOutcome):
        return evidence
    if len(records) != 1:
        raise AssertionError("validated ClickHouse readiness must contain exactly one row")
    return _ObservedReadiness(record=records[0], evidence=evidence)


def _current_readiness_records(
    records: tuple[ClickHouseRelationManifestRecord, ...],
) -> tuple[ClickHouseRelationManifestRecord, ...]:
    if len(records) < 2:
        return records
    first, second = records
    if first.publication_revision < second.publication_revision:
        raise ClickHouseDataValidationError(
            "ClickHouse readiness rows violate descending publication revision order"
        )
    if first.publication_revision == second.publication_revision:
        return records
    return (first,)


def _readiness_record(payload: _ReadinessPayload) -> ClickHouseRelationManifestRecord:
    try:
        return ClickHouseRelationManifestRecord(
            dataset_id=payload.dataset_id,
            scope_digest=payload.scope_digest,
            batch_id=payload.batch_id,
            state=payload.state,
            business_date=_parse_date(payload.business_date, "readiness business_date"),
            source_cut=payload.source_cut,
            dataset_version=payload.dataset_version,
            completed_at=(
                None
                if payload.completed_at is None
                else _parse_utc_datetime(payload.completed_at, "readiness completed_at")
            ),
            completion_revision=(
                None
                if payload.completion_revision is None
                else _parse_positive_integer(
                    payload.completion_revision,
                    "readiness completion revision",
                )
            ),
            publication_revision=_parse_positive_integer(
                payload.publication_revision,
                "readiness publication revision",
            ),
        )
    except (TypeError, ValueError) as error:
        raise ClickHouseDataValidationError(
            "ClickHouse readiness row contains invalid typed values: "
            f"cause_type={type(error).__name__}"
        ) from None


def _bounded_settings(
    limits: ClickHouseReadinessLimits,
    max_result_rows: int,
) -> dict[str, str | int]:
    return {
        "session_timezone": "UTC",
        "max_execution_time": limits.max_execution_time_seconds,
        "timeout_overflow_mode": "throw",
        "timeout_overflow_mode_leaf": "throw",
        "read_overflow_mode": "throw",
        "read_overflow_mode_leaf": "throw",
        "max_result_rows": max_result_rows,
        "max_result_bytes": limits.max_response_bytes,
        "result_overflow_mode": "throw",
        "sort_overflow_mode": "throw",
    }


def _require_request_manifest_closure(
    request: ClickHouseImmutableVersionRequest,
    manifest: ClickHouseImmutableVersionManifest,
) -> None:
    if (
        manifest.issuer != request.expected_issuer
        or manifest.dataset_id != request.dataset_id
        or manifest.scope_digest != request.scope_digest
        or manifest.expected_batch_id != request.expected_batch_id
        or manifest.late_arrivals is not request.late_arrivals
    ):
        raise ClickHouseImmutableManifestError(
            "ClickHouse immutable-version manifest does not match the requested "
            "issuer, dataset, scope, batch, and late-arrival policy"
        )


def _require_manifest_record_closure(
    manifest: ClickHouseImmutableVersionManifest,
    record: ClickHouseRelationManifestRecord,
) -> None:
    if not _manifest_record_matches(manifest, record):
        raise ValueError(
            "ClickHouse immutable-version binding combines different manifest and readiness facts"
        )


def _manifest_record_matches(
    manifest: ClickHouseImmutableVersionManifest,
    record: ClickHouseRelationManifestRecord,
) -> bool:
    return (
        record.state == "complete"
        and record.dataset_id == manifest.dataset_id
        and record.scope_digest == manifest.scope_digest
        and record.batch_id == manifest.expected_batch_id
        and record.business_date == manifest.business_date
        and record.source_cut == manifest.source_cut
        and record.dataset_version == manifest.dataset_version
        and record.completed_at == manifest.completed_at
        and record.completion_revision == manifest.completion_revision
        and record.publication_revision == manifest.publication_revision
    )


def _require_locator_identity(
    locator: ClickHouseVersionLocator,
    identity: ClickHouseTableIdentity,
) -> None:
    if (
        identity.database != locator.database
        or identity.table != locator.table
        or identity.uuid != locator.uuid
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse named version locator does not match the Atomic table identity: "
            f"database={locator.database!r}, table={locator.table!r}, "
            f"expected_uuid={str(locator.uuid)!r}, observed_uuid={str(identity.uuid)!r}"
        )


def _require_matching_server_uuid(
    observed_value: str,
    expected_server_uuid: UUID,
    operation: str,
) -> None:
    observed_server_uuid = _parse_uuid(observed_value, f"{operation} server UUID")
    if observed_server_uuid != expected_server_uuid:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse immutable-version queries must remain pinned to one server: "
            f"operation={operation!r}, expected_server_uuid={str(expected_server_uuid)!r}, "
            f"observed_server_uuid={str(observed_server_uuid)!r}"
        )


def _require_same_server(
    readiness_identity: ClickHouseTableIdentity,
    version_identity: ClickHouseTableIdentity,
) -> None:
    if readiness_identity.server_uuid != version_identity.server_uuid:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse readiness and named version must be observed on one server: "
            f"readiness_server_uuid={str(readiness_identity.server_uuid)!r}, "
            f"version_server_uuid={str(version_identity.server_uuid)!r}"
        )
    if (
        readiness_identity.database == version_identity.database
        and readiness_identity.database_uuid != version_identity.database_uuid
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse readiness and named version disagree on their shared Atomic "
            f"database UUID: database={readiness_identity.database!r}"
        )


def _unsupported_evidence_outcome(
    request: ClickHouseImmutableVersionRequest,
) -> EarlyExecutionOutcome:
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.ERROR,
        reason=ResultReason(
            code=ReasonCode.UNSUPPORTED_CAPABILITY,
            operation="acquire_clickhouse_immutable_version",
            message=(
                "asserted ClickHouse immutable-version evidence cannot satisfy a verified "
                "minimum evidence policy"
            ),
            safe_parameters=_request_safe_parameters(request),
            native_error_code=None,
            query_id=None,
            redacted_response=None,
        ),
    )


def _not_ready_outcome(
    request: ClickHouseImmutableVersionRequest,
    message: str,
) -> EarlyExecutionOutcome:
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.INCOMPLETE,
        reason=ResultReason(
            code=ReasonCode.NOT_READY,
            operation="validate_clickhouse_immutable_version",
            message=message,
            safe_parameters=_request_safe_parameters(request),
            native_error_code=None,
            query_id=None,
            redacted_response=None,
        ),
    )


def _cut_mismatch_outcome(
    request: ClickHouseImmutableVersionRequest,
    message: str,
) -> EarlyExecutionOutcome:
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.INCOMPLETE,
        reason=ResultReason(
            code=ReasonCode.CUT_MISMATCH,
            operation="confirm_clickhouse_immutable_version",
            message=message,
            safe_parameters=_request_safe_parameters(request),
            native_error_code=None,
            query_id=None,
            redacted_response=None,
        ),
    )


def _request_safe_parameters(
    request: ClickHouseImmutableVersionRequest,
) -> tuple[SafeParameter, ...]:
    return (
        SafeParameter(name="direction", value=request.direction.value),
        SafeParameter(name="endpoint_profile", value=request.endpoint_profile),
        SafeParameter(name="dataset_id", value=request.dataset_id),
    )


def _parse_date(value: str, label: str) -> date:
    _require_bounded_text(value, label)
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be an ISO calendar date"
        ) from None
    if parsed.isoformat() != value:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must use canonical YYYY-MM-DD form"
        )
    return parsed


def _parse_utc_datetime(value: str, label: str) -> datetime:
    _require_bounded_text(value, label)
    try:
        parsed = datetime.strptime(value, _MANIFEST_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must use canonical UTC microsecond form"
        ) from None
    if parsed.strftime(_MANIFEST_TIMESTAMP_FORMAT) != value:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must preserve exactly six fractional digits"
        )
    return parsed


def _parse_uuid(value: str, label: str) -> UUID:
    _require_bounded_text(value, label)
    try:
        parsed = UUID(value)
    except ValueError:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be a UUID") from None
    if str(parsed) != value:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must use canonical lowercase UUID text"
        )
    return parsed


def _parse_positive_integer(value: str, label: str) -> int:
    if _UNSIGNED_INTEGER.fullmatch(value) is None:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be a canonical unsigned decimal integer"
        )
    parsed = int(value)
    _require_positive_integer(parsed, f"ClickHouse {label}")
    return parsed


def _parse_nonnegative_integer(value: str, label: str) -> int:
    if _UNSIGNED_INTEGER.fullmatch(value) is None:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be a canonical unsigned decimal integer"
        )
    return int(value)


def _engine_is_readonly(engine_full: str) -> bool:
    validate_clickhouse_text_scalar(engine_full, "ClickHouse table engine definition")
    settings_marker = " SETTINGS "
    marker_index = engine_full.rfind(settings_marker)
    if marker_index < 0:
        return False
    settings = engine_full[marker_index + len(settings_marker) :]
    return _READONLY_TABLE_SETTING.search(settings) is not None


def _require_positive_integer(value: int, label: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be a positive exact integer")


def _require_sha256(value: str, label: str) -> None:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise ValueError(f"ClickHouse {label} must be a lowercase SHA-256 digest")


def _require_bounded_text(value: str, label: str) -> None:
    validate_clickhouse_text_scalar(value, f"ClickHouse {label}")
    if len(value.encode("utf-8")) > 512:
        raise ValueError(f"ClickHouse {label} exceeds 512 UTF-8 bytes")


def _require_text(value: str, label: str) -> None:
    if type(value) is not str:
        raise TypeError(f"ClickHouse {label} must be text")
    if "\x00" in value:
        raise ValueError(f"ClickHouse {label} must not contain U+0000")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(
            f"ClickHouse {label} must contain valid Unicode scalar values: "
            f"start={error.start}, end={error.end}"
        ) from None


def _require_optional_bounded_text(value: str | None, label: str) -> None:
    if value is not None:
        _require_bounded_text(value, label)


def _require_utc_datetime(value: datetime, label: str) -> None:
    if type(value) is not datetime:
        raise TypeError(f"ClickHouse {label} must be an exact datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"ClickHouse {label} must use UTC")


def _require_direct_single_server_endpoint(endpoint_profile: object) -> None:
    if endpoint_profile != "direct_single_server":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse immutable-version acquisition requires "
            "endpoint_profile='direct_single_server'; load-balanced endpoints cannot bind "
            "access-control inspection to one server"
        )


def _require_transport(value: object) -> None:
    if not isinstance(value, ClickHouseTransport):
        raise TypeError("transport must be ClickHouseTransport")
