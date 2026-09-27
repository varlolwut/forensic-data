import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Literal, final
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from forensic_data.acquisition import (
    AcquisitionValidationError,
    EarlyExecutionOutcome,
    RelationManifestEvidence,
    validate_relation_manifest_readiness,
)
from forensic_data.canonical import CanonicalSchema
from forensic_data.clickhouse import (
    ClickHouseDataValidationError,
    ClickHouseLegacyProfileProvenance,
    ClickHouseParameter,
    ClickHouseResourceSetting,
    ClickHouseServerProfile,
    ClickHouseTransport,
    UnsupportedClickHouseProfileError,
    parse_clickhouse_json_rows,
    quote_clickhouse_identifier,
    require_clickhouse_resource_setting_value,
    validate_clickhouse_identifier,
    validate_clickhouse_text_scalar,
)
from forensic_data.clickhouse_canonical import (
    ClickHouseCanonicalFingerprint,
    ClickHouseCanonicalLimits,
    ClickHouseCanonicalRelation,
    ClickHouseDirectTableSource,
    inspect_legacy_clickhouse_canonical_relation,
    read_clickhouse_canonical_fingerprint,
)
from forensic_data.clickhouse_profile import ClickHouseRuntimeProfile
from forensic_data.clickhouse_readiness import (
    ClickHouseColumnIdentity,
    ClickHouseImmutableVersionRequest,
    ClickHouseReadinessLimits,
    ClickHouseRelationManifestRecord,
    ClickHouseVersionLocator,
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
_MANIFEST_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_DDL_NUMBER_LITERAL = re.compile(
    r"(?:-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|-?(?:inf|nan))",
    re.ASCII,
)
_DDL_SETTING_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
    re.ASCII,
)
_DDL_IDENTIFIER_PART = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)
_DDL_DELIMITER_PAIRS = {"(": ")", "[": "]", "{": "}"}
_DDL_COLUMN_DEFAULT_KINDS = frozenset({"ALIAS", "DEFAULT", "MATERIALIZED"})
_DDL_BACKTICK_ESCAPES = {
    "\x00": "\\0",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\\": "\\\\",
    "`": "\\`",
}
_DDL_STRING_ESCAPES = {
    "\x00": "\\0",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\\": "\\\\",
    "'": "\\'",
}
_DDL_BACKTICK_ESCAPE_VALUES = {
    "0": "\x00",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "\\": "\\",
    "`": "`",
}
_MAX_UINT64 = (1 << 64) - 1
_LEGACY_SOURCE_STRATEGY = "clickhouse_21_8_asserted_immutable_source"
_LEGACY_IDENTITY_KIND = "operator_configured_macro"
_LEGACY_IDENTITY_MACRO = "dfe_server_uuid"
_LEGACY_LIMITATIONS = (
    "HTTP queries do not share a transaction snapshot",
    "the direct endpoint and operator-configured server identity must remain unique and stable",
    "writer, DDL, mutation, and TTL exclusion remains an independently trusted assertion",
    "pre/post equality detects observed changes but cannot exclude transient writes that revert",
    "ClickHouse 21.8 exposes neither native serverUUID nor table_readonly evidence",
    "physical projection definitions and TTL expressions are unsupported",
)
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
_LEGACY_MUTATION_AVAILABLE_FIELDS = (
    "parts_to_do_names",
    "parts_to_do",
    "is_done",
    "latest_failed_part",
    "latest_fail_time",
    "latest_fail_reason",
)
_LEGACY_MUTATION_UNAVAILABLE_FIELDS = (
    "parts_in_progress_names",
    "is_killed",
    "latest_fail_error_code_name",
)


def validate_clickhouse_legacy_limit_closure(
    readiness_limits: ClickHouseReadinessLimits,
    canonical_limits: ClickHouseCanonicalLimits,
) -> None:
    if type(readiness_limits) is not ClickHouseReadinessLimits:
        raise TypeError("readiness_limits must be ClickHouseReadinessLimits")
    if type(canonical_limits) is not ClickHouseCanonicalLimits:
        raise TypeError("canonical_limits must be ClickHouseCanonicalLimits")
    if (
        readiness_limits.max_response_bytes != canonical_limits.max_response_bytes
        or readiness_limits.max_execution_time_seconds
        != canonical_limits.max_execution_time_seconds
    ):
        raise ValueError(
            "ClickHouse legacy readiness and canonical queries must share one execution limit set"
        )


class ClickHouseLegacyManifestError(ValueError):
    """A trusted legacy source manifest is invalid or incomplete."""


class _LegacyVersionLocatorPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    database: str
    table: str
    uuid: str


class _LegacySealAssertionsPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    direct_single_server: bool
    server_identity_unique: bool
    immutable_named_version: bool
    no_writes_during_attempt: bool
    no_ddl_during_attempt: bool
    no_mutations_during_attempt: bool
    no_ttl_during_attempt: bool


class _LegacyManifestPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: int = Field(ge=1, le=1)
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
    version_locator: _LegacyVersionLocatorPayload
    expected_definition_sha256: str
    server_identity_kind: Literal["operator_configured_macro"]
    server_identity_macro: Literal["dfe_server_uuid"]
    expected_server_uuid: str
    assertions: _LegacySealAssertionsPayload
    immutability: Literal["asserted"]
    late_arrivals: Literal["next_batch"]


class _LegacyCatalogPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    configured_server_uuid: str
    server_hostname: str
    build_id: str
    database: str
    table: str
    uuid: str
    database_uuid: str
    database_engine: str
    table_engine: str
    engine_full: str
    create_table_query: str
    partition_key: str
    primary_key: str
    sorting_key: str
    sampling_key: str
    comment: str
    definition_sha256: str


class _LegacyColumnPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    configured_server_uuid: str
    server_hostname: str
    build_id: str
    name: str
    type: str
    position: str
    default_kind: str
    default_expression: str
    comment: str
    compression_codec: str


class _LegacyPolicyPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    configured_server_uuid: str
    server_hostname: str
    build_id: str
    system_policy_count: str
    relation_policy_count: str


class _LegacyProjectionSettingPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    configured_server_uuid: str
    server_hostname: str
    build_id: str
    name: str
    value: str
    min: str | None
    max: str | None
    readonly: int


class _LegacyProjectionPartsPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    configured_server_uuid: str
    server_hostname: str
    build_id: str
    active_projection_part_count: str


class _LegacyMutationWitnessPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    configured_server_uuid: str
    server_hostname: str
    build_id: str
    mutation_count: str
    pending_mutation_count: str
    failed_mutation_count: str
    mutation_records_sha256: str


class _LegacyPartsWitnessPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    configured_server_uuid: str
    server_hostname: str
    build_id: str
    active_part_count: str
    active_row_count: str
    active_bytes_on_disk: str
    active_part_records_sha256: str


class _LegacyReadinessPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    configured_server_uuid: str
    server_hostname: str
    build_id: str
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


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacySealAssertions:
    direct_single_server: bool
    server_identity_unique: bool
    immutable_named_version: bool
    no_writes_during_attempt: bool
    no_ddl_during_attempt: bool
    no_mutations_during_attempt: bool
    no_ttl_during_attempt: bool

    def __post_init__(self) -> None:
        values = (
            self.direct_single_server,
            self.server_identity_unique,
            self.immutable_named_version,
            self.no_writes_during_attempt,
            self.no_ddl_during_attempt,
            self.no_mutations_during_attempt,
            self.no_ttl_during_attempt,
        )
        if any(type(value) is not bool for value in values):
            raise TypeError("ClickHouse legacy seal assertions must be booleans")
        if not all(values):
            raise ClickHouseLegacyManifestError(
                "ClickHouse legacy source manifest must assert every required exclusion"
            )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacySourceManifest:
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
    expected_definition_sha256: str
    server_identity_kind: str
    server_identity_macro: str
    expected_server_uuid: UUID
    assertions: ClickHouseLegacySealAssertions
    immutability_evidence: ConsistencyLevel
    late_arrivals: LateArrivalPolicy
    artifact_sha256: str

    def __post_init__(self) -> None:
        if type(self.manifest_version) is not int or self.manifest_version != 1:
            raise ClickHouseLegacyManifestError(
                "ClickHouse legacy source manifest version must be the exact integer 1"
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
            raise ClickHouseLegacyManifestError(
                "ClickHouse legacy manifest business_date must be an exact date"
            )
        _require_utc_datetime(self.completed_at, "manifest completed_at")
        _require_positive_integer(self.completion_revision, "manifest completion revision")
        _require_positive_integer(self.publication_revision, "manifest publication revision")
        if type(self.version_locator) is not ClickHouseVersionLocator:
            raise TypeError("version_locator must be ClickHouseVersionLocator")
        _require_sha256(self.expected_definition_sha256, "manifest expected definition digest")
        if self.server_identity_kind != _LEGACY_IDENTITY_KIND:
            raise ClickHouseLegacyManifestError(
                "ClickHouse legacy server identity kind must be operator_configured_macro"
            )
        if self.server_identity_macro != _LEGACY_IDENTITY_MACRO:
            raise ClickHouseLegacyManifestError(
                "ClickHouse legacy server identity macro must be dfe_server_uuid"
            )
        if type(self.expected_server_uuid) is not UUID or self.expected_server_uuid.int == 0:
            raise ClickHouseLegacyManifestError(
                "ClickHouse legacy manifest requires a non-zero expected server UUID"
            )
        if type(self.assertions) is not ClickHouseLegacySealAssertions:
            raise TypeError("assertions must be ClickHouseLegacySealAssertions")
        if self.immutability_evidence is not ConsistencyLevel.ASSERTED:
            raise ClickHouseLegacyManifestError(
                "ClickHouse legacy source immutability evidence must remain asserted"
            )
        if self.late_arrivals is not LateArrivalPolicy.NEXT_BATCH:
            raise ClickHouseLegacyManifestError(
                "ClickHouse legacy source manifest requires late_arrivals='next_batch'"
            )
        _require_sha256(self.artifact_sha256, "manifest artifact digest")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacySourceRequest:
    version_request: ClickHouseImmutableVersionRequest
    schema: CanonicalSchema
    column_names: tuple[str, ...]
    canonical_limits: ClickHouseCanonicalLimits
    max_mutation_records: int
    max_part_records: int

    def __post_init__(self) -> None:
        if type(self.version_request) is not ClickHouseImmutableVersionRequest:
            raise TypeError("version_request must be ClickHouseImmutableVersionRequest")
        if type(self.schema) is not CanonicalSchema:
            raise TypeError("schema must be CanonicalSchema")
        if type(self.column_names) is not tuple or not self.column_names:
            raise ValueError("ClickHouse legacy source columns must be a non-empty tuple")
        if len(self.column_names) != len(self.schema.fields):
            raise ValueError(
                "ClickHouse legacy source column count must equal the logical field count"
            )
        if len(set(self.column_names)) != len(self.column_names):
            raise ValueError("ClickHouse legacy source column names must be unique")
        for column_name in self.column_names:
            validate_clickhouse_identifier(column_name, "ClickHouse legacy source column")
        if type(self.canonical_limits) is not ClickHouseCanonicalLimits:
            raise TypeError("canonical_limits must be ClickHouseCanonicalLimits")
        validate_clickhouse_legacy_limit_closure(
            self.version_request.limits,
            self.canonical_limits,
        )
        _require_positive_integer(self.max_mutation_records, "legacy mutation record limit")
        _require_positive_integer(self.max_part_records, "legacy active-part record limit")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacyServerIdentity:
    kind: str
    macro: str
    asserted_server_uuid: UUID
    hostname: str
    build_id: str
    server_version: str
    server_version_number: int

    def __post_init__(self) -> None:
        if self.kind != _LEGACY_IDENTITY_KIND or self.macro != _LEGACY_IDENTITY_MACRO:
            raise ValueError("ClickHouse legacy server identity provenance is invalid")
        if type(self.asserted_server_uuid) is not UUID or self.asserted_server_uuid.int == 0:
            raise ClickHouseDataValidationError(
                "ClickHouse legacy server identity must be a non-zero UUID"
            )
        for value, label in (
            (self.hostname, "legacy server hostname"),
            (self.build_id, "legacy server build ID"),
            (self.server_version, "legacy server version"),
        ):
            _require_bounded_text(value, label)
        _require_positive_integer(self.server_version_number, "legacy server version number")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacyTableIdentity:
    server: ClickHouseLegacyServerIdentity
    database: str
    database_uuid: UUID
    table: str
    uuid: UUID
    database_engine: str
    table_engine: str
    engine_full: str
    partition_key: str
    sorting_key: str
    definition_sha256: str
    columns: tuple[ClickHouseColumnIdentity, ...]

    def __post_init__(self) -> None:
        if type(self.server) is not ClickHouseLegacyServerIdentity:
            raise TypeError("ClickHouse legacy table identity requires a server identity")
        validate_clickhouse_identifier(self.database, "ClickHouse legacy identity database")
        validate_clickhouse_identifier(self.table, "ClickHouse legacy identity table")
        for value, label in (
            (self.database_uuid, "legacy database UUID"),
            (self.uuid, "legacy table UUID"),
        ):
            if type(value) is not UUID or value.int == 0:
                raise ClickHouseDataValidationError(f"ClickHouse {label} must be non-zero")
        for value, label in (
            (self.database_engine, "legacy database engine"),
            (self.table_engine, "legacy table engine"),
            (self.engine_full, "legacy full engine definition"),
        ):
            _require_bounded_text(value, label)
        for value, label in (
            (self.partition_key, "legacy partition key"),
            (self.sorting_key, "legacy sorting key"),
        ):
            if type(value) is not str:
                raise TypeError(f"ClickHouse {label} must be text")
            if value:
                _require_bounded_text(value, label)
        _require_sha256(self.definition_sha256, "legacy table definition digest")
        if type(self.columns) is not tuple or not self.columns:
            raise ClickHouseDataValidationError(
                "ClickHouse legacy table identity requires an immutable non-empty column tuple"
            )
        for position, column in enumerate(self.columns, start=1):
            if type(column) is not ClickHouseColumnIdentity or column.position != position:
                raise ClickHouseDataValidationError(
                    "ClickHouse legacy table columns must be contiguous typed identities"
                )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacyProjectionSetting:
    name: str
    value: str
    minimum: str | None
    maximum: str | None
    locked: bool

    def __post_init__(self) -> None:
        _require_bounded_text(self.name, "legacy projection setting name")
        _require_bounded_text(self.value, "legacy projection setting value")
        for value, label in (
            (self.minimum, "legacy projection setting minimum"),
            (self.maximum, "legacy projection setting maximum"),
        ):
            if value is not None:
                _require_bounded_text(value, label)
        if type(self.locked) is not bool:
            raise TypeError("ClickHouse legacy projection setting lock must be boolean")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacyProjectionSafetyWitness:
    server: ClickHouseLegacyServerIdentity
    definition_sha256: str
    projection_definition_absent: bool
    ttl_definition_absent: bool
    settings: tuple[ClickHouseLegacyProjectionSetting, ...]
    active_projection_part_count: int

    def __post_init__(self) -> None:
        if type(self.server) is not ClickHouseLegacyServerIdentity:
            raise TypeError("ClickHouse legacy projection witness requires a server identity")
        _require_sha256(self.definition_sha256, "legacy projection definition digest")
        if self.projection_definition_absent is not True or self.ttl_definition_absent is not True:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse legacy projection witness requires projection-free and TTL-free DDL"
            )
        if type(self.settings) is not tuple or len(self.settings) != 2:
            raise ClickHouseDataValidationError(
                "ClickHouse legacy projection witness requires exactly two locked settings"
            )
        by_name = {setting.name: setting for setting in self.settings}
        expected = {
            "allow_experimental_projection_optimization",
            "force_optimize_projection",
        }
        if len(by_name) != 2 or set(by_name) != expected:
            raise ClickHouseDataValidationError(
                "ClickHouse legacy projection witness returned unexpected settings"
            )
        if any(setting.value != "0" or not setting.locked for setting in self.settings):
            raise UnsupportedClickHouseProfileError(
                "ClickHouse legacy projection optimization settings must be locked at zero"
            )
        _require_nonnegative_integer(
            self.active_projection_part_count,
            "active projection part count",
        )
        if self.active_projection_part_count != 0:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse legacy source contains active physical projection parts: "
                f"active_projection_part_count={self.active_projection_part_count}"
            )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacyMutationWitness:
    server: ClickHouseLegacyServerIdentity
    mutation_count: int
    pending_mutation_count: int
    failed_mutation_count: int
    records_sha256: str
    available_fields: tuple[str, ...]
    unavailable_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.server) is not ClickHouseLegacyServerIdentity:
            raise TypeError("ClickHouse legacy mutation witness requires a server identity")
        for value, label in (
            (self.mutation_count, "legacy mutation count"),
            (self.pending_mutation_count, "legacy pending mutation count"),
            (self.failed_mutation_count, "legacy failed mutation count"),
        ):
            _require_nonnegative_integer(value, label)
        if self.pending_mutation_count > self.mutation_count:
            raise ClickHouseDataValidationError(
                "ClickHouse legacy pending mutation count exceeds the inventory"
            )
        if self.failed_mutation_count > self.mutation_count:
            raise ClickHouseDataValidationError(
                "ClickHouse legacy failed mutation count exceeds the inventory"
            )
        _require_sha256(self.records_sha256, "legacy mutation inventory digest")
        if self.available_fields != _LEGACY_MUTATION_AVAILABLE_FIELDS:
            raise ValueError("ClickHouse legacy mutation available-field provenance is incomplete")
        if self.unavailable_fields != _LEGACY_MUTATION_UNAVAILABLE_FIELDS:
            raise ValueError(
                "ClickHouse legacy mutation unavailable-field provenance is incomplete"
            )
        if self.pending_mutation_count or self.failed_mutation_count:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse legacy source has pending or failed mutations: "
                f"pending={self.pending_mutation_count}, failed={self.failed_mutation_count}"
            )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacyBasePartWitness:
    server: ClickHouseLegacyServerIdentity
    active_part_count: int
    active_row_count: int
    active_bytes_on_disk: int
    ordered_records_sha256: str

    def __post_init__(self) -> None:
        if type(self.server) is not ClickHouseLegacyServerIdentity:
            raise TypeError("ClickHouse legacy base-part witness requires a server identity")
        for value, label in (
            (self.active_part_count, "legacy active part count"),
            (self.active_row_count, "legacy active part row count"),
            (self.active_bytes_on_disk, "legacy active part byte count"),
        ):
            _require_nonnegative_integer(value, label)
        _require_sha256(self.ordered_records_sha256, "legacy active-part inventory digest")
        if self.active_part_count == 0 and (
            self.active_row_count != 0 or self.active_bytes_on_disk != 0
        ):
            raise ClickHouseDataValidationError(
                "ClickHouse empty active-part inventory has non-zero rows or bytes"
            )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacyTableWitness:
    identity: ClickHouseLegacyTableIdentity
    row_policy_count: int
    projection_safety: ClickHouseLegacyProjectionSafetyWitness
    mutations: ClickHouseLegacyMutationWitness
    base_parts: ClickHouseLegacyBasePartWitness

    def __post_init__(self) -> None:
        if type(self.identity) is not ClickHouseLegacyTableIdentity:
            raise TypeError("ClickHouse legacy table witness requires a table identity")
        _require_nonnegative_integer(self.row_policy_count, "legacy row-policy count")
        if self.row_policy_count != 0:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse legacy source profile does not support row policies: "
                f"policy_count={self.row_policy_count}"
            )
        for value, label in (
            (self.projection_safety, "projection safety"),
            (self.mutations, "mutation"),
            (self.base_parts, "base-part"),
        ):
            if value.server != self.identity.server:
                raise ClickHouseDataValidationError(
                    f"ClickHouse legacy {label} witness belongs to a different server"
                )
        if self.projection_safety.definition_sha256 != self.identity.definition_sha256:
            raise ClickHouseDataValidationError(
                "ClickHouse legacy projection witness has a different definition digest"
            )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacyReadinessObservation:
    table: ClickHouseLegacyTableWitness
    record: ClickHouseRelationManifestRecord
    evidence: RelationManifestEvidence

    def __post_init__(self) -> None:
        if type(self.table) is not ClickHouseLegacyTableWitness:
            raise TypeError("ClickHouse legacy readiness observation requires a table witness")
        if type(self.record) is not ClickHouseRelationManifestRecord:
            raise TypeError("ClickHouse legacy readiness observation requires a manifest record")
        if type(self.evidence) is not RelationManifestEvidence:
            raise TypeError("ClickHouse legacy readiness observation requires typed evidence")
        if self.evidence.evidence_level is not ConsistencyLevel.VERIFIED:
            raise ValueError("ClickHouse legacy readiness relation evidence must remain verified")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacySourceBinding:
    strategy: str
    context_id: UUID
    attempt_id: UUID
    request: ClickHouseLegacySourceRequest
    manifest: ClickHouseLegacySourceManifest
    readiness: ClickHouseLegacyReadinessObservation
    source: ClickHouseLegacyTableWitness
    relation: ClickHouseCanonicalRelation
    logical_fingerprint: ClickHouseCanonicalFingerprint
    overall_evidence: ConsistencyLevel
    opened_at: datetime
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.strategy != _LEGACY_SOURCE_STRATEGY:
            raise ValueError("ClickHouse legacy source binding strategy is invalid")
        for value, label in (
            (self.context_id, "legacy context ID"),
            (self.attempt_id, "legacy attempt ID"),
        ):
            if type(value) is not UUID or value.int == 0:
                raise ValueError(f"ClickHouse {label} must be a non-zero UUID")
        if type(self.request) is not ClickHouseLegacySourceRequest:
            raise TypeError("ClickHouse legacy binding requires a source request")
        if type(self.manifest) is not ClickHouseLegacySourceManifest:
            raise TypeError("ClickHouse legacy binding requires a source manifest")
        if type(self.readiness) is not ClickHouseLegacyReadinessObservation:
            raise TypeError("ClickHouse legacy binding requires readiness evidence")
        if type(self.source) is not ClickHouseLegacyTableWitness:
            raise TypeError("ClickHouse legacy binding requires source table evidence")
        if type(self.relation) is not ClickHouseCanonicalRelation:
            raise TypeError("ClickHouse legacy binding requires a canonical relation")
        if type(self.logical_fingerprint) is not ClickHouseCanonicalFingerprint:
            raise TypeError("ClickHouse legacy binding requires a canonical fingerprint")
        _require_legacy_binding_closure(self)
        if self.overall_evidence is not ConsistencyLevel.ASSERTED:
            raise ValueError("ClickHouse legacy source evidence must remain asserted")
        _require_utc_datetime(self.opened_at, "legacy binding opened_at")
        if self.limitations != _LEGACY_LIMITATIONS:
            raise ValueError("ClickHouse legacy source limitations are incomplete")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseLegacySourceConfirmation:
    binding: ClickHouseLegacySourceBinding
    final_readiness: ClickHouseLegacyReadinessObservation
    final_source: ClickHouseLegacyTableWitness
    final_logical_fingerprint: ClickHouseCanonicalFingerprint
    confirmed_at: datetime

    def __post_init__(self) -> None:
        if type(self.binding) is not ClickHouseLegacySourceBinding:
            raise TypeError("ClickHouse legacy confirmation requires a source binding")
        if self.final_readiness != self.binding.readiness:
            raise ValueError("ClickHouse legacy readiness evidence changed")
        if self.final_source != self.binding.source:
            raise ValueError("ClickHouse legacy source witnesses changed")
        if self.final_logical_fingerprint != self.binding.logical_fingerprint:
            raise ValueError("ClickHouse legacy logical fingerprint changed")
        _require_utc_datetime(self.confirmed_at, "legacy confirmation confirmed_at")


def acquire_clickhouse_legacy_source(
    transport: ClickHouseTransport,
    profile: ClickHouseServerProfile,
    request: ClickHouseLegacySourceRequest,
    manifest: ClickHouseLegacySourceManifest,
) -> ClickHouseLegacySourceBinding | EarlyExecutionOutcome:
    _require_legacy_inputs(transport, profile, request, manifest)
    unsupported = _unsupported_evidence_outcome(request.version_request)
    if unsupported is not None:
        return unsupported
    _require_legacy_query_limits(profile, request)
    first_readiness = _observe_legacy_readiness(transport, profile, request, manifest)
    if isinstance(first_readiness, EarlyExecutionOutcome):
        return first_readiness
    first_source = _inspect_legacy_table_witness(
        transport,
        profile,
        request,
        manifest,
        manifest.version_locator.database,
        manifest.version_locator.table,
        manifest.version_locator.uuid,
        manifest.expected_definition_sha256,
    )
    relation = inspect_legacy_clickhouse_canonical_relation(
        transport=transport,
        database=manifest.version_locator.database,
        table=manifest.version_locator.table,
        schema=request.schema,
        column_names=request.column_names,
        max_response_bytes=request.canonical_limits.max_response_bytes,
        max_execution_time_seconds=request.canonical_limits.max_execution_time_seconds,
    )
    _require_relation_matches_legacy_identity(relation, first_source.identity)
    fingerprint = _read_valid_legacy_fingerprint(transport, relation, request.canonical_limits)
    _require_part_row_count(first_source.base_parts, fingerprint)
    second_source = _inspect_legacy_table_witness(
        transport,
        profile,
        request,
        manifest,
        manifest.version_locator.database,
        manifest.version_locator.table,
        manifest.version_locator.uuid,
        manifest.expected_definition_sha256,
    )
    second_readiness = _observe_legacy_readiness(transport, profile, request, manifest)
    if isinstance(second_readiness, EarlyExecutionOutcome):
        return second_readiness
    if second_source != first_source or second_readiness != first_readiness:
        return _cut_mismatch_outcome(
            request.version_request,
            "ClickHouse legacy source or readiness evidence changed during acquisition",
        )
    return ClickHouseLegacySourceBinding(
        strategy=_LEGACY_SOURCE_STRATEGY,
        context_id=uuid4(),
        attempt_id=transport.attempt_id,
        request=request,
        manifest=manifest,
        readiness=second_readiness,
        source=second_source,
        relation=relation,
        logical_fingerprint=fingerprint,
        overall_evidence=ConsistencyLevel.ASSERTED,
        opened_at=datetime.now(UTC),
        limitations=_LEGACY_LIMITATIONS,
    )


def confirm_clickhouse_legacy_source(
    transport: ClickHouseTransport,
    profile: ClickHouseServerProfile,
    binding: ClickHouseLegacySourceBinding,
) -> ClickHouseLegacySourceConfirmation | EarlyExecutionOutcome:
    if type(binding) is not ClickHouseLegacySourceBinding:
        raise TypeError("binding must be ClickHouseLegacySourceBinding")
    _require_legacy_inputs(transport, profile, binding.request, binding.manifest)
    transport.require_attempt(binding.attempt_id, "confirm_clickhouse_legacy_source")
    _require_legacy_query_limits(profile, binding.request)
    first_readiness = _observe_legacy_readiness(
        transport,
        profile,
        binding.request,
        binding.manifest,
    )
    if isinstance(first_readiness, EarlyExecutionOutcome):
        return first_readiness
    first_source = _inspect_legacy_table_witness(
        transport,
        profile,
        binding.request,
        binding.manifest,
        binding.source.identity.database,
        binding.source.identity.table,
        binding.source.identity.uuid,
        binding.source.identity.definition_sha256,
    )
    fingerprint = _read_valid_legacy_fingerprint(
        transport,
        binding.relation,
        binding.request.canonical_limits,
    )
    _require_part_row_count(first_source.base_parts, fingerprint)
    second_source = _inspect_legacy_table_witness(
        transport,
        profile,
        binding.request,
        binding.manifest,
        binding.source.identity.database,
        binding.source.identity.table,
        binding.source.identity.uuid,
        binding.source.identity.definition_sha256,
    )
    second_readiness = _observe_legacy_readiness(
        transport,
        profile,
        binding.request,
        binding.manifest,
    )
    if isinstance(second_readiness, EarlyExecutionOutcome):
        return second_readiness
    if (
        first_readiness != binding.readiness
        or second_readiness != first_readiness
        or first_source != binding.source
        or second_source != first_source
        or fingerprint != binding.logical_fingerprint
    ):
        return _cut_mismatch_outcome(
            binding.request.version_request,
            "ClickHouse legacy source evidence differs from the bound context",
        )
    return ClickHouseLegacySourceConfirmation(
        binding=binding,
        final_readiness=second_readiness,
        final_source=second_source,
        final_logical_fingerprint=fingerprint,
        confirmed_at=datetime.now(UTC),
    )


def _require_legacy_binding_closure(binding: ClickHouseLegacySourceBinding) -> None:
    request = binding.request.version_request
    manifest = binding.manifest
    _require_request_manifest_closure(request, manifest)
    if binding.source.identity.server.asserted_server_uuid != manifest.expected_server_uuid:
        raise ValueError("ClickHouse legacy source server identity differs from its manifest")
    if not _manifest_record_matches(manifest, binding.readiness.record):
        raise ValueError("ClickHouse legacy readiness and trusted manifest are not one cut")
    if binding.readiness.table.identity.server != binding.source.identity.server:
        raise ValueError("ClickHouse legacy readiness and source belong to different servers")
    if (
        binding.readiness.table.identity.database != request.readiness_database
        or binding.readiness.table.identity.table != request.readiness_table
    ):
        raise ValueError("ClickHouse legacy readiness witness has the wrong relation identity")
    if (
        binding.readiness.table.identity.database == binding.source.identity.database
        and binding.readiness.table.identity.database_uuid != binding.source.identity.database_uuid
    ):
        raise ValueError(
            "ClickHouse legacy readiness and source disagree on their shared Atomic database"
        )
    if (
        binding.source.identity.database != manifest.version_locator.database
        or binding.source.identity.table != manifest.version_locator.table
        or binding.source.identity.uuid != manifest.version_locator.uuid
        or binding.source.identity.definition_sha256 != manifest.expected_definition_sha256
    ):
        raise ValueError("ClickHouse legacy source identity differs from its trusted manifest")
    if (
        binding.relation.database != binding.source.identity.database
        or binding.relation.table != binding.source.identity.table
        or binding.relation.schema != binding.request.schema
        or binding.relation.runtime_profile is not ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE
    ):
        raise ValueError("ClickHouse legacy canonical relation has inconsistent provenance")
    _require_relation_matches_legacy_identity(binding.relation, binding.source.identity)
    if binding.logical_fingerprint.fingerprint.count != binding.source.base_parts.active_row_count:
        raise ValueError("ClickHouse legacy fingerprint row count differs from active parts")


def _observe_legacy_readiness(
    transport: ClickHouseTransport,
    profile: ClickHouseServerProfile,
    request: ClickHouseLegacySourceRequest,
    manifest: ClickHouseLegacySourceManifest,
) -> ClickHouseLegacyReadinessObservation | EarlyExecutionOutcome:
    version_request = request.version_request
    table = _inspect_legacy_table_witness(
        transport,
        profile,
        request,
        manifest,
        version_request.readiness_database,
        version_request.readiness_table,
        None,
        None,
    )
    observed_columns = tuple(
        (column.name, column.declared_type) for column in table.identity.columns
    )
    if observed_columns != _READINESS_COLUMN_CONTRACT or any(
        column.default_kind or column.default_expression for column in table.identity.columns
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy readiness table does not match the exact physical contract: "
            f"database={table.identity.database!r}, table={table.identity.table!r}, "
            f"observed_columns={observed_columns!r}"
        )
    result = transport.execute_raw(
        query=(
            "SELECT getMacro('dfe_server_uuid') AS configured_server_uuid, "
            "hostName() AS server_hostname, buildId() AS build_id, dataset_id, "
            "toString(scope_digest) AS scope_digest, batch_id, toString(state) AS state, "
            "toString(business_date) AS business_date, source_cut, dataset_version, "
            "if(completed_at IS NULL, NULL, "
            "concat(replaceOne(toString(assumeNotNull(completed_at), 'UTC'), ' ', 'T'), 'Z')) "
            "AS completed_at, toString(completion_revision) AS completion_revision, "
            "toString(publication_revision) AS publication_revision FROM "
            f"{quote_clickhouse_identifier(version_request.readiness_database)}."
            f"{quote_clickhouse_identifier(version_request.readiness_table)} AS readiness "
            "WHERE dataset_id = {dataset_id:String} AND scope_digest = {scope_digest:String} "
            "ORDER BY readiness.publication_revision DESC LIMIT 2"
        ),
        parameters={
            "dataset_id": version_request.dataset_id,
            "scope_digest": version_request.scope_digest,
        },
        settings=_legacy_query_settings(request, 2),
        result_format="JSONEachRow",
        max_response_bytes=version_request.limits.max_response_bytes,
        operation="read_legacy_immutable_version_readiness",
    )
    payloads = parse_clickhouse_json_rows(
        result.payload,
        _LegacyReadinessPayload,
        "legacy immutable version readiness",
    )
    for payload in payloads:
        _require_observed_server(
            payload.configured_server_uuid,
            payload.server_hostname,
            payload.build_id,
            table.identity.server,
            "legacy readiness query",
        )
    records = _current_readiness_records(tuple(_readiness_record(payload) for payload in payloads))
    try:
        evidence = validate_relation_manifest_readiness(
            direction=version_request.direction,
            rows=records,
            expected_dataset_id=version_request.dataset_id,
            expected_scope_digest=version_request.scope_digest,
            expected_batch_id=version_request.expected_batch_id,
            alignment_fields=version_request.alignment_fields,
            minimum_evidence=version_request.minimum_evidence,
            late_arrivals=version_request.late_arrivals,
        )
    except AcquisitionValidationError as error:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy readiness record violates the typed manifest contract: "
            f"cause_type={type(error).__name__}"
        ) from None
    if isinstance(evidence, EarlyExecutionOutcome):
        return evidence
    if len(records) != 1:
        raise AssertionError("validated ClickHouse legacy readiness must contain one row")
    if not _manifest_record_matches(manifest, records[0]):
        return _not_ready_outcome(
            version_request,
            "ClickHouse legacy readiness and trusted manifest are not one publication",
        )
    return ClickHouseLegacyReadinessObservation(
        table=table,
        record=records[0],
        evidence=evidence,
    )


def _inspect_legacy_table_witness(
    transport: ClickHouseTransport,
    profile: ClickHouseServerProfile,
    request: ClickHouseLegacySourceRequest,
    manifest: ClickHouseLegacySourceManifest,
    database: str,
    table: str,
    expected_uuid: UUID | None,
    expected_definition_sha256: str | None,
) -> ClickHouseLegacyTableWitness:
    identity = _inspect_legacy_table_identity(
        transport,
        profile,
        request,
        manifest,
        database,
        table,
        expected_uuid,
        expected_definition_sha256,
    )
    policies = _read_legacy_policy_count(transport, request, identity)
    projection_safety = _read_legacy_projection_safety(
        transport,
        request,
        identity,
    )
    mutations = _read_legacy_mutation_witness(transport, request, identity)
    base_parts = _read_legacy_base_part_witness(transport, request, identity)
    return ClickHouseLegacyTableWitness(
        identity=identity,
        row_policy_count=policies,
        projection_safety=projection_safety,
        mutations=mutations,
        base_parts=base_parts,
    )


def _inspect_legacy_table_identity(
    transport: ClickHouseTransport,
    profile: ClickHouseServerProfile,
    request: ClickHouseLegacySourceRequest,
    manifest: ClickHouseLegacySourceManifest,
    database: str,
    table: str,
    expected_uuid: UUID | None,
    expected_definition_sha256: str | None,
) -> ClickHouseLegacyTableIdentity:
    validate_clickhouse_identifier(database, "ClickHouse legacy catalog database")
    validate_clickhouse_identifier(table, "ClickHouse legacy catalog table")
    result = transport.execute_raw(
        query=(
            "SELECT getMacro('dfe_server_uuid') AS configured_server_uuid, "
            "hostName() AS server_hostname, buildId() AS build_id, database, name AS table, "
            "toString(uuid) AS uuid, toString((SELECT any(uuid) FROM system.databases "
            "WHERE name = {database:String})) AS database_uuid, "
            "(SELECT any(engine) FROM system.databases WHERE name = {database:String}) "
            "AS database_engine, engine AS table_engine, engine_full, create_table_query, "
            "partition_key, primary_key, sorting_key, sampling_key, comment, "
            "lower(hex(SHA256(create_table_query))) "
            "AS definition_sha256 FROM system.tables WHERE database = {database:String} "
            "AND name = {table:String} ORDER BY uuid LIMIT 2"
        ),
        parameters={"database": database, "table": table},
        settings=_legacy_query_settings(request, 2),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_legacy_table_catalog",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _LegacyCatalogPayload,
        "legacy table catalog",
    )
    if len(rows) != 1:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy table locator must resolve exactly one table: "
            f"database={database!r}, table={table!r}, actual={len(rows)}"
        )
    row = rows[0]
    server = _observed_server_identity(
        profile,
        manifest,
        row.configured_server_uuid,
        row.server_hostname,
        row.build_id,
        "legacy table catalog",
    )
    definition_sha256 = hashlib.sha256(
        row.create_table_query.encode("utf-8", errors="strict")
    ).hexdigest()
    if row.definition_sha256 != definition_sha256:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy table definition digest differs between server and client: "
            f"database={database!r}, table={table!r}"
        )
    if expected_definition_sha256 is not None and definition_sha256 != expected_definition_sha256:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy table definition differs from the trusted manifest: "
            f"database={database!r}, table={table!r}"
        )
    table_uuid = _parse_uuid(row.uuid, "legacy table UUID")
    if expected_uuid is not None and table_uuid != expected_uuid:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy table UUID differs from the trusted manifest: "
            f"database={database!r}, table={table!r}"
        )
    columns, column_comments, column_codecs = _inspect_legacy_columns(
        transport,
        request,
        server,
        database,
        table,
    )
    require_clickhouse_legacy_plain_merge_tree_ddl(
        row.create_table_query,
        row.table_engine,
        row.engine_full,
        row.partition_key,
        row.primary_key,
        row.sorting_key,
        row.sampling_key,
        row.comment,
        columns,
        column_comments,
        column_codecs,
    )
    identity = ClickHouseLegacyTableIdentity(
        server=server,
        database=row.database,
        database_uuid=_parse_uuid(row.database_uuid, "legacy database UUID"),
        table=row.table,
        uuid=table_uuid,
        database_engine=row.database_engine,
        table_engine=row.table_engine,
        engine_full=row.engine_full,
        partition_key=row.partition_key,
        sorting_key=row.sorting_key,
        definition_sha256=definition_sha256,
        columns=columns,
    )
    if identity.database_engine != "Atomic" or identity.table_engine != "MergeTree":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse 21.8 source profile requires an Atomic plain MergeTree: "
            f"database_engine={identity.database_engine!r}, "
            f"table_engine={identity.table_engine!r}"
        )
    return identity


def _inspect_legacy_columns(
    transport: ClickHouseTransport,
    request: ClickHouseLegacySourceRequest,
    server: ClickHouseLegacyServerIdentity,
    database: str,
    table: str,
) -> tuple[tuple[ClickHouseColumnIdentity, ...], tuple[str, ...], tuple[str, ...]]:
    result_limit = _MAX_TABLE_COLUMNS + 1
    result = transport.execute_raw(
        query=(
            "SELECT getMacro('dfe_server_uuid') AS configured_server_uuid, "
            "hostName() AS server_hostname, buildId() AS build_id, name, type, "
            "toString(position) AS position, default_kind, default_expression, comment, "
            "compression_codec "
            "FROM system.columns AS catalog_column WHERE database = {database:String} "
            "AND table = {table:String} ORDER BY catalog_column.position "
            f"LIMIT {result_limit}"
        ),
        parameters={"database": database, "table": table},
        settings=_legacy_query_settings(request, result_limit),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_legacy_table_columns",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _LegacyColumnPayload,
        "legacy table column catalog",
    )
    if not rows or len(rows) > _MAX_TABLE_COLUMNS:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy table column count is outside the supported profile: "
            f"database={database!r}, table={table!r}, actual={len(rows)}, "
            f"maximum={_MAX_TABLE_COLUMNS}"
        )
    for row in rows:
        _require_observed_server(
            row.configured_server_uuid,
            row.server_hostname,
            row.build_id,
            server,
            "legacy column catalog",
        )
    try:
        columns = tuple(
            ClickHouseColumnIdentity(
                name=row.name,
                declared_type=row.type,
                position=_parse_positive_integer_text(
                    row.position,
                    "legacy catalog column position",
                ),
                default_kind=row.default_kind,
                default_expression=row.default_expression,
            )
            for row in rows
        )
        return (
            columns,
            tuple(row.comment for row in rows),
            tuple(row.compression_codec for row in rows),
        )
    except (TypeError, ValueError) as error:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy column catalog contains invalid typed identity values: "
            f"database={database!r}, table={table!r}, "
            f"cause_type={type(error).__name__}"
        ) from None


def _read_legacy_policy_count(
    transport: ClickHouseTransport,
    request: ClickHouseLegacySourceRequest,
    identity: ClickHouseLegacyTableIdentity,
) -> int:
    system_policy_result = transport.execute_raw(
        query="SHOW CREATE ROW POLICIES ON system.*",
        parameters={},
        settings=_legacy_query_settings(request, 1),
        result_format="TabSeparatedRaw",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_legacy_row_policies",
    )
    if system_policy_result.payload:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy source requires unfiltered system metadata; at least one "
            "row policy targets system.*"
        )
    result = transport.execute_raw(
        query=(
            "SELECT getMacro('dfe_server_uuid') AS configured_server_uuid, "
            "hostName() AS server_hostname, buildId() AS build_id, "
            "toString(countIf(database = 'system')) AS system_policy_count, "
            "toString(countIf(database = {database:String} AND "
            "(table = {table:String} OR empty(table)))) AS relation_policy_count "
            "FROM system.row_policies"
        ),
        parameters={"database": identity.database, "table": identity.table},
        settings=_legacy_query_settings(request, 1),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_legacy_row_policies",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _LegacyPolicyPayload,
        "legacy row-policy catalog",
    )
    if len(rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy row-policy catalog must return exactly one row: "
            f"database={identity.database!r}, table={identity.table!r}, actual={len(rows)}"
        )
    row = rows[0]
    _require_observed_server(
        row.configured_server_uuid,
        row.server_hostname,
        row.build_id,
        identity.server,
        "legacy row-policy catalog",
    )
    system_count = _parse_nonnegative_integer_text(
        row.system_policy_count,
        "legacy system row-policy count",
    )
    relation_count = _parse_nonnegative_integer_text(
        row.relation_policy_count,
        "legacy relation row-policy count",
    )
    return system_count + relation_count


def _read_legacy_projection_safety(
    transport: ClickHouseTransport,
    request: ClickHouseLegacySourceRequest,
    identity: ClickHouseLegacyTableIdentity,
) -> ClickHouseLegacyProjectionSafetyWitness:
    settings_result = transport.execute_raw(
        query=(
            "SELECT getMacro('dfe_server_uuid') AS configured_server_uuid, "
            "hostName() AS server_hostname, buildId() AS build_id, name, value, min, max, "
            "readonly FROM system.settings WHERE name IN "
            "('allow_experimental_projection_optimization', "
            "'force_optimize_projection') ORDER BY name"
        ),
        parameters={},
        settings=_legacy_query_settings(request, 2),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_legacy_projection_settings",
    )
    setting_rows = parse_clickhouse_json_rows(
        settings_result.payload,
        _LegacyProjectionSettingPayload,
        "legacy projection settings",
    )
    settings: list[ClickHouseLegacyProjectionSetting] = []
    for row in setting_rows:
        _require_observed_server(
            row.configured_server_uuid,
            row.server_hostname,
            row.build_id,
            identity.server,
            "legacy projection settings",
        )
        settings.append(
            ClickHouseLegacyProjectionSetting(
                name=row.name,
                value=row.value,
                minimum=row.min,
                maximum=row.max,
                locked=row.readonly == 1,
            )
        )
    parts_result = transport.execute_raw(
        query=(
            "SELECT getMacro('dfe_server_uuid') AS configured_server_uuid, "
            "hostName() AS server_hostname, buildId() AS build_id, "
            "toString(count()) AS active_projection_part_count "
            "FROM system.projection_parts WHERE database = {database:String} "
            "AND table = {table:String} AND active = 1"
        ),
        parameters={"database": identity.database, "table": identity.table},
        settings=_legacy_query_settings(request, 1),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_legacy_projection_parts",
    )
    part_rows = parse_clickhouse_json_rows(
        parts_result.payload,
        _LegacyProjectionPartsPayload,
        "legacy projection-part catalog",
    )
    if len(part_rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy projection-part catalog must return exactly one row: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"actual={len(part_rows)}"
        )
    part_row = part_rows[0]
    _require_observed_server(
        part_row.configured_server_uuid,
        part_row.server_hostname,
        part_row.build_id,
        identity.server,
        "legacy projection-part catalog",
    )
    return ClickHouseLegacyProjectionSafetyWitness(
        server=identity.server,
        definition_sha256=identity.definition_sha256,
        projection_definition_absent=True,
        ttl_definition_absent=True,
        settings=tuple(settings),
        active_projection_part_count=_parse_nonnegative_integer_text(
            part_row.active_projection_part_count,
            "legacy active projection part count",
        ),
    )


def _read_legacy_mutation_witness(
    transport: ClickHouseTransport,
    request: ClickHouseLegacySourceRequest,
    identity: ClickHouseLegacyTableIdentity,
) -> ClickHouseLegacyMutationWitness:
    result_limit = request.max_mutation_records + 1
    result = transport.execute_raw(
        query=(
            "SELECT getMacro('dfe_server_uuid') AS configured_server_uuid, "
            "hostName() AS server_hostname, buildId() AS build_id, "
            "toString(count()) AS mutation_count, "
            "toString(countIf(is_done = 0 OR parts_to_do > 0 OR "
            "notEmpty(parts_to_do_names))) AS pending_mutation_count, "
            "toString(countIf(notEmpty(latest_failed_part) OR "
            "notEmpty(latest_fail_reason))) AS failed_mutation_count, "
            "lower(hex(SHA256(arrayStringConcat(arraySort(groupArray(record_sha256)), '')))) "
            "AS mutation_records_sha256 FROM (SELECT is_done, parts_to_do, "
            "parts_to_do_names, latest_failed_part, latest_fail_reason, "
            "lower(hex(SHA256(toString(tuple(mutation_id, command, "
            "toString(create_time), parts_to_do_names, toString(parts_to_do), "
            "toString(is_done), latest_failed_part, toString(latest_fail_time), "
            "latest_fail_reason))))) AS record_sha256 FROM system.mutations "
            "WHERE database = {database:String} AND table = {table:String} "
            f"ORDER BY mutation_id LIMIT {result_limit})"
        ),
        parameters={"database": identity.database, "table": identity.table},
        settings=_legacy_query_settings(request, 1),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_legacy_mutations",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _LegacyMutationWitnessPayload,
        "legacy mutation witness",
    )
    if len(rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy mutation witness must return exactly one row: "
            f"database={identity.database!r}, table={identity.table!r}, actual={len(rows)}"
        )
    row = rows[0]
    _require_observed_server(
        row.configured_server_uuid,
        row.server_hostname,
        row.build_id,
        identity.server,
        "legacy mutation witness",
    )
    mutation_count = _parse_nonnegative_integer_text(
        row.mutation_count,
        "legacy mutation count",
    )
    if mutation_count > request.max_mutation_records:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy mutation inventory exceeds its record bound: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"maximum={request.max_mutation_records}, observed_at_least={mutation_count}"
        )
    return ClickHouseLegacyMutationWitness(
        server=identity.server,
        mutation_count=mutation_count,
        pending_mutation_count=_parse_nonnegative_integer_text(
            row.pending_mutation_count,
            "legacy pending mutation count",
        ),
        failed_mutation_count=_parse_nonnegative_integer_text(
            row.failed_mutation_count,
            "legacy failed mutation count",
        ),
        records_sha256=row.mutation_records_sha256,
        available_fields=_LEGACY_MUTATION_AVAILABLE_FIELDS,
        unavailable_fields=_LEGACY_MUTATION_UNAVAILABLE_FIELDS,
    )


def _read_legacy_base_part_witness(
    transport: ClickHouseTransport,
    request: ClickHouseLegacySourceRequest,
    identity: ClickHouseLegacyTableIdentity,
) -> ClickHouseLegacyBasePartWitness:
    result_limit = request.max_part_records + 1
    result = transport.execute_raw(
        query=(
            "SELECT getMacro('dfe_server_uuid') AS configured_server_uuid, "
            "hostName() AS server_hostname, buildId() AS build_id, "
            "toString(count()) AS active_part_count, "
            "toString(sum(rows)) AS active_row_count, "
            "toString(sum(bytes_on_disk)) AS active_bytes_on_disk, "
            "lower(hex(SHA256(arrayStringConcat(arraySort(groupArray(record_sha256)), '')))) "
            "AS active_part_records_sha256 FROM (SELECT rows, bytes_on_disk, "
            "lower(hex(SHA256(toString(tuple(name, toString(uuid), partition_id, "
            "toString(min_block_number), toString(max_block_number), toString(level), "
            "toString(data_version), toString(rows), toString(bytes_on_disk), disk_name, "
            "hash_of_all_files, toString(modification_time)))))) AS record_sha256 "
            "FROM system.parts WHERE database = {database:String} "
            "AND table = {table:String} AND active = 1 "
            f"ORDER BY name LIMIT {result_limit})"
        ),
        parameters={"database": identity.database, "table": identity.table},
        settings=_legacy_query_settings(request, 1),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_legacy_active_parts",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _LegacyPartsWitnessPayload,
        "legacy active-part witness",
    )
    if len(rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy active-part witness must return exactly one row: "
            f"database={identity.database!r}, table={identity.table!r}, actual={len(rows)}"
        )
    row = rows[0]
    _require_observed_server(
        row.configured_server_uuid,
        row.server_hostname,
        row.build_id,
        identity.server,
        "legacy active-part witness",
    )
    part_count = _parse_nonnegative_integer_text(
        row.active_part_count,
        "legacy active part count",
    )
    if part_count > request.max_part_records:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy active-part inventory exceeds its record bound: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"maximum={request.max_part_records}, observed_at_least={part_count}"
        )
    return ClickHouseLegacyBasePartWitness(
        server=identity.server,
        active_part_count=part_count,
        active_row_count=_parse_nonnegative_integer_text(
            row.active_row_count,
            "legacy active part row count",
        ),
        active_bytes_on_disk=_parse_nonnegative_integer_text(
            row.active_bytes_on_disk,
            "legacy active part byte count",
        ),
        ordered_records_sha256=row.active_part_records_sha256,
    )


def _require_legacy_inputs(
    transport: ClickHouseTransport,
    profile: ClickHouseServerProfile,
    request: ClickHouseLegacySourceRequest,
    manifest: ClickHouseLegacySourceManifest,
) -> None:
    if type(transport) is not ClickHouseTransport:
        raise TypeError("transport must be ClickHouseTransport")
    if type(profile) is not ClickHouseServerProfile:
        raise TypeError("profile must be ClickHouseServerProfile")
    if type(request) is not ClickHouseLegacySourceRequest:
        raise TypeError("request must be ClickHouseLegacySourceRequest")
    if type(manifest) is not ClickHouseLegacySourceManifest:
        raise TypeError("manifest must be ClickHouseLegacySourceManifest")
    if transport.runtime_profile is not ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy source acquisition requires runtime profile "
            f"{ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE.value!r}: "
            f"observed={transport.runtime_profile.value!r}"
        )
    provenance = profile.provenance
    if (
        type(provenance) is not ClickHouseLegacyProfileProvenance
        or provenance.runtime_profile is not ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse legacy source profile provenance is inconsistent"
        )
    if request.version_request.direction is not PlanDirection.REFERENCE:
        raise ValueError("ClickHouse legacy source readiness must use reference direction")
    _require_request_manifest_closure(request.version_request, manifest)


def _unsupported_evidence_outcome(
    request: ClickHouseImmutableVersionRequest,
) -> EarlyExecutionOutcome | None:
    if request.minimum_evidence is not MinimumEvidence.VERIFIED:
        return None
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.ERROR,
        reason=ResultReason(
            code=ReasonCode.UNSUPPORTED_CAPABILITY,
            operation="acquire_clickhouse_legacy_source",
            message=(
                "asserted ClickHouse legacy source stability cannot satisfy a verified "
                "minimum evidence policy"
            ),
            safe_parameters=_request_safe_parameters(request),
            native_error_code=None,
            query_id=None,
            redacted_response=None,
        ),
    )


def _require_legacy_query_limits(
    profile: ClickHouseServerProfile,
    request: ClickHouseLegacySourceRequest,
) -> None:
    for requested_value, setting, operation in (
        (
            request.version_request.limits.max_execution_time_seconds,
            ClickHouseResourceSetting.MAX_EXECUTION_TIME,
            "admit_clickhouse_legacy_execution_time",
        ),
        (
            request.version_request.limits.max_response_bytes,
            ClickHouseResourceSetting.MAX_RESULT_BYTES,
            "admit_clickhouse_legacy_result_bytes",
        ),
    ):
        require_clickhouse_resource_setting_value(
            profile,
            setting,
            requested_value,
            operation,
        )
    result_row_limits = tuple(sorted({1, 2, _MAX_TABLE_COLUMNS + 1, len(request.column_names) + 1}))
    for requested_value in result_row_limits:
        require_clickhouse_resource_setting_value(
            profile,
            ClickHouseResourceSetting.MAX_RESULT_ROWS,
            requested_value,
            f"admit_clickhouse_legacy_result_rows_{requested_value}",
        )


def _legacy_query_settings(
    request: ClickHouseLegacySourceRequest,
    max_result_rows: int,
) -> dict[str, ClickHouseParameter]:
    _require_positive_integer(max_result_rows, "legacy query result row limit")
    return {
        "max_execution_time": request.version_request.limits.max_execution_time_seconds,
        "max_result_rows": max_result_rows,
        "max_result_bytes": request.version_request.limits.max_response_bytes,
    }


def _observed_server_identity(
    profile: ClickHouseServerProfile,
    manifest: ClickHouseLegacySourceManifest,
    configured_server_uuid: str,
    hostname: str,
    build_id: str,
    operation: str,
) -> ClickHouseLegacyServerIdentity:
    observed_uuid = _parse_uuid(configured_server_uuid, f"{operation} configured server UUID")
    if observed_uuid != manifest.expected_server_uuid:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy query reached a server outside the trusted direct endpoint: "
            f"operation={operation!r}, expected_server_uuid={manifest.expected_server_uuid}, "
            f"observed_server_uuid={observed_uuid}"
        )
    if build_id != profile.build_id:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy server build changed after profile inspection: "
            f"operation={operation!r}, expected_build_id={profile.build_id!r}, "
            f"observed_build_id={build_id!r}"
        )
    return ClickHouseLegacyServerIdentity(
        kind=manifest.server_identity_kind,
        macro=manifest.server_identity_macro,
        asserted_server_uuid=observed_uuid,
        hostname=hostname,
        build_id=build_id,
        server_version=profile.server_version,
        server_version_number=profile.server_version_number,
    )


def _require_observed_server(
    configured_server_uuid: str,
    hostname: str,
    build_id: str,
    expected: ClickHouseLegacyServerIdentity,
    operation: str,
) -> None:
    observed_uuid = _parse_uuid(configured_server_uuid, f"{operation} configured server UUID")
    if (
        observed_uuid != expected.asserted_server_uuid
        or hostname != expected.hostname
        or build_id != expected.build_id
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse legacy query did not remain on the bound direct server: "
            f"operation={operation!r}, expected_server_uuid={expected.asserted_server_uuid}, "
            f"observed_server_uuid={observed_uuid}, expected_hostname={expected.hostname!r}, "
            f"observed_hostname={hostname!r}, expected_build_id={expected.build_id!r}, "
            f"observed_build_id={build_id!r}"
        )


def _require_relation_matches_legacy_identity(
    relation: ClickHouseCanonicalRelation,
    identity: ClickHouseLegacyTableIdentity,
) -> None:
    if (
        relation.database != identity.database
        or relation.table != identity.table
        or relation.runtime_profile is not ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE
        or type(relation.source) is not ClickHouseDirectTableSource
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse legacy canonical relation does not match its bound table identity"
        )
    columns_by_name = {column.name: column for column in identity.columns}
    if len(columns_by_name) != len(identity.columns):
        raise ClickHouseDataValidationError(
            "ClickHouse legacy table identity contains duplicate column names"
        )
    for binding in relation.bindings:
        column = columns_by_name.get(binding.column_name)
        if column is None or column.declared_type != binding.declared_type:
            raise ClickHouseDataValidationError(
                "ClickHouse legacy canonical binding differs from the bound column identity: "
                f"column={binding.column_name!r}, declared_type={binding.declared_type!r}"
            )


def _read_valid_legacy_fingerprint(
    transport: ClickHouseTransport,
    relation: ClickHouseCanonicalRelation,
    limits: ClickHouseCanonicalLimits,
) -> ClickHouseCanonicalFingerprint:
    if relation.runtime_profile is not ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE:
        raise TypeError("ClickHouse legacy fingerprint requires a legacy canonical relation")
    fingerprint = read_clickhouse_canonical_fingerprint(transport, relation, limits)
    if fingerprint.invalid_row_count != 0 or fingerprint.oversized_row_count != 0:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy canonical fingerprint contains rejected rows: "
            f"invalid={fingerprint.invalid_row_count}, "
            f"oversized={fingerprint.oversized_row_count}"
        )
    return fingerprint


def _require_part_row_count(
    parts: ClickHouseLegacyBasePartWitness,
    fingerprint: ClickHouseCanonicalFingerprint,
) -> None:
    if parts.active_row_count != fingerprint.fingerprint.count:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy logical row count differs from the active-part inventory: "
            f"active_part_rows={parts.active_row_count}, "
            f"logical_rows={fingerprint.fingerprint.count}"
        )


def _current_readiness_records(
    records: tuple[ClickHouseRelationManifestRecord, ...],
) -> tuple[ClickHouseRelationManifestRecord, ...]:
    if len(records) < 2:
        return records
    first, second = records
    if first.publication_revision < second.publication_revision:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy readiness rows violate descending publication revision order"
        )
    if first.publication_revision == second.publication_revision:
        return records
    return (first,)


def _readiness_record(payload: _LegacyReadinessPayload) -> ClickHouseRelationManifestRecord:
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
                else _parse_positive_integer_text(
                    payload.completion_revision,
                    "readiness completion revision",
                )
            ),
            publication_revision=_parse_positive_integer_text(
                payload.publication_revision,
                "readiness publication revision",
            ),
        )
    except (TypeError, ValueError) as error:
        raise ClickHouseDataValidationError(
            "ClickHouse legacy readiness row contains invalid typed values: "
            f"cause_type={type(error).__name__}"
        ) from None


def _require_request_manifest_closure(
    request: ClickHouseImmutableVersionRequest,
    manifest: ClickHouseLegacySourceManifest,
) -> None:
    if (
        manifest.issuer != request.expected_issuer
        or manifest.dataset_id != request.dataset_id
        or manifest.scope_digest != request.scope_digest
        or manifest.expected_batch_id != request.expected_batch_id
        or manifest.late_arrivals is not request.late_arrivals
    ):
        raise ClickHouseLegacyManifestError(
            "ClickHouse legacy source manifest does not match the requested issuer, dataset, "
            "scope, batch, and late-arrival policy"
        )


def _manifest_record_matches(
    manifest: ClickHouseLegacySourceManifest,
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


def _not_ready_outcome(
    request: ClickHouseImmutableVersionRequest,
    message: str,
) -> EarlyExecutionOutcome:
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.INCOMPLETE,
        reason=ResultReason(
            code=ReasonCode.NOT_READY,
            operation="validate_clickhouse_legacy_source",
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
            operation="confirm_clickhouse_legacy_source",
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


def parse_clickhouse_legacy_source_manifest(
    payload: bytes,
    max_bytes: int,
) -> ClickHouseLegacySourceManifest:
    if type(payload) is not bytes:
        raise TypeError("ClickHouse legacy source manifest payload must be bytes")
    _require_positive_integer(max_bytes, "legacy manifest byte limit")
    if not payload:
        raise ClickHouseLegacyManifestError("ClickHouse legacy source manifest must not be empty")
    if len(payload) > max_bytes:
        raise ClickHouseLegacyManifestError(
            "ClickHouse legacy source manifest exceeds its byte limit: "
            f"max_bytes={max_bytes}, actual_bytes={len(payload)}"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ClickHouseLegacyManifestError(
            "ClickHouse legacy source manifest is not strict UTF-8: "
            f"byte_start={error.start}, byte_end={error.end}"
        ) from None
    try:
        semantic_value = semantic_value_from_json(text)
        parsed = _LegacyManifestPayload.model_validate(semantic_value)
    except (ContractValidationError, ValidationError) as error:
        raise ClickHouseLegacyManifestError(
            f"ClickHouse legacy source manifest is invalid: cause_type={type(error).__name__}"
        ) from None
    try:
        return ClickHouseLegacySourceManifest(
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
            version_locator=ClickHouseVersionLocator(
                database=parsed.version_locator.database,
                table=parsed.version_locator.table,
                uuid=_parse_uuid(parsed.version_locator.uuid, "manifest version locator UUID"),
            ),
            expected_definition_sha256=parsed.expected_definition_sha256,
            server_identity_kind=parsed.server_identity_kind,
            server_identity_macro=parsed.server_identity_macro,
            expected_server_uuid=_parse_uuid(
                parsed.expected_server_uuid,
                "manifest expected server UUID",
            ),
            assertions=ClickHouseLegacySealAssertions(
                direct_single_server=parsed.assertions.direct_single_server,
                server_identity_unique=parsed.assertions.server_identity_unique,
                immutable_named_version=parsed.assertions.immutable_named_version,
                no_writes_during_attempt=parsed.assertions.no_writes_during_attempt,
                no_ddl_during_attempt=parsed.assertions.no_ddl_during_attempt,
                no_mutations_during_attempt=parsed.assertions.no_mutations_during_attempt,
                no_ttl_during_attempt=parsed.assertions.no_ttl_during_attempt,
            ),
            immutability_evidence=ConsistencyLevel(parsed.immutability),
            late_arrivals=LateArrivalPolicy(parsed.late_arrivals),
            artifact_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except (ClickHouseDataValidationError, ValueError) as error:
        raise ClickHouseLegacyManifestError(
            "ClickHouse legacy source manifest contains invalid typed values: "
            f"cause_type={type(error).__name__}"
        ) from None


def require_clickhouse_legacy_plain_merge_tree_ddl(
    create_table_query: str,
    table_engine: str,
    engine_full: str,
    partition_key: str,
    primary_key: str,
    sorting_key: str,
    sampling_key: str,
    table_comment: str,
    columns: tuple[ClickHouseColumnIdentity, ...],
    column_comments: tuple[str, ...],
    column_codecs: tuple[str, ...],
) -> None:
    validate_clickhouse_text_scalar(create_table_query, "ClickHouse legacy canonical table DDL")
    validate_clickhouse_text_scalar(table_engine, "ClickHouse legacy table engine")
    validate_clickhouse_text_scalar(engine_full, "ClickHouse legacy full engine definition")
    for expression, label in (
        (partition_key, "partition key"),
        (primary_key, "primary key"),
        (sorting_key, "sorting key"),
        (sampling_key, "sampling key"),
        (table_comment, "table comment"),
    ):
        if type(expression) is not str:
            raise TypeError(f"ClickHouse legacy {label} must be text")
        if expression:
            validate_clickhouse_text_scalar(expression, f"ClickHouse legacy {label}")
    if type(columns) is not tuple or not columns:
        raise TypeError("ClickHouse legacy canonical DDL requires a non-empty column tuple")
    if any(type(column) is not ClickHouseColumnIdentity for column in columns):
        raise TypeError("ClickHouse legacy canonical DDL columns must be column identities")
    if (
        type(column_comments) is not tuple
        or type(column_codecs) is not tuple
        or len(column_comments) != len(columns)
        or len(column_codecs) != len(columns)
        or any(type(comment) is not str for comment in column_comments)
        or any(type(codec) is not str for codec in column_codecs)
    ):
        raise TypeError(
            "ClickHouse legacy canonical DDL requires aligned text comment and codec tuples"
        )
    unquoted = _unquoted_clickhouse_ddl(create_table_query)
    column_entries, column_list_end = _clickhouse_ddl_column_entries(
        create_table_query,
        unquoted,
    )
    _require_clickhouse_ddl_columns(
        column_entries,
        columns,
        column_comments,
        column_codecs,
    )
    expected_storage = f" ENGINE = {engine_full}"
    if create_table_query[column_list_end + 1 :] != expected_storage:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table DDL does not match its catalog engine definition"
        )
    _require_clickhouse_ddl_storage(
        table_engine,
        engine_full,
        partition_key,
        primary_key,
        sorting_key,
        sampling_key,
        table_comment,
    )


def _clickhouse_ddl_column_entries(value: str, unquoted: str) -> tuple[tuple[str, ...], int]:
    if not value.startswith("CREATE TABLE "):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table DDL must start with CREATE TABLE"
        )
    delimiters: list[tuple[str, int]] = []
    entries: list[str] = []
    column_list_start: int | None = None
    entry_start: int | None = None
    column_list_end: int | None = None
    for position, character in enumerate(unquoted):
        if character in _DDL_DELIMITER_PAIRS:
            if not delimiters and column_list_start is None:
                if character != "(" or position == 0 or value[position - 1] != " ":
                    raise ClickHouseDataValidationError(
                        "ClickHouse canonical table DDL has an unrecognized column-list start"
                    )
                column_list_start = position
                entry_start = position + 1
            delimiters.append((character, position))
            continue
        if character in _DDL_DELIMITER_PAIRS.values():
            if not delimiters:
                raise ClickHouseDataValidationError(
                    "ClickHouse canonical table DDL has an unmatched closing delimiter"
                )
            opening, _ = delimiters.pop()
            if _DDL_DELIMITER_PAIRS[opening] != character:
                raise ClickHouseDataValidationError(
                    "ClickHouse canonical table DDL has mismatched delimiters"
                )
            if column_list_start is not None and not delimiters and column_list_end is None:
                if character != ")" or entry_start is None or entry_start == position:
                    raise ClickHouseDataValidationError(
                        "ClickHouse canonical table DDL has an invalid column-list closure"
                    )
                entries.append(value[entry_start:position])
                column_list_end = position
            continue
        if (
            character == ","
            and column_list_start is not None
            and column_list_end is None
            and len(delimiters) == 1
        ):
            if (
                entry_start is None
                or entry_start == position
                or value[position + 1 : position + 2] != " "
            ):
                raise ClickHouseDataValidationError(
                    "ClickHouse canonical table DDL has a non-canonical column separator"
                )
            entries.append(value[entry_start:position])
            entry_start = position + 2
    if delimiters or column_list_start is None or column_list_end is None or not entries:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table DDL has an incomplete column or delimiter structure"
        )
    return tuple(entries), column_list_end


def _require_clickhouse_ddl_columns(
    entries: tuple[str, ...],
    columns: tuple[ClickHouseColumnIdentity, ...],
    column_comments: tuple[str, ...],
    column_codecs: tuple[str, ...],
) -> None:
    column_position = 0
    for entry in entries:
        if entry.startswith("PROJECTION "):
            raise UnsupportedClickHouseProfileError(
                "ClickHouse 21.8 source profile does not support declared projections or TTL: "
                "hazard_token='PROJECTION'"
            )
        if entry.startswith(("INDEX ", "CONSTRAINT ")):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical table DDL contains an unsupported non-column declaration"
            )
        if column_position >= len(columns):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical table DDL declares more columns than its catalog witness"
            )
        _require_clickhouse_ddl_column(
            entry,
            columns[column_position],
            column_comments[column_position],
            column_codecs[column_position],
        )
        column_position += 1
    if column_position != len(columns):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table DDL column count differs from its catalog witness"
        )


def _require_clickhouse_ddl_column(
    entry: str,
    column: ClickHouseColumnIdentity,
    comment: str,
    codec: str,
) -> None:
    expected_prefix = f"{_quote_clickhouse_backtick_identifier(column.name)} {column.declared_type}"
    if not entry.startswith(expected_prefix):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical column declaration differs from its catalog witness: "
            f"column={column.name!r}, position={column.position}"
        )
    position = len(expected_prefix)
    if entry.startswith(" NOT NULL", position):
        position += len(" NOT NULL")
    elif entry.startswith(" NULL", position):
        position += len(" NULL")
    if column.default_kind:
        if column.default_kind not in _DDL_COLUMN_DEFAULT_KINDS or not column.default_expression:
            raise ClickHouseDataValidationError(
                "ClickHouse canonical column default metadata is invalid: "
                f"column={column.name!r}, default_kind={column.default_kind!r}"
            )
        default_clause = f" {column.default_kind} {column.default_expression}"
        if not entry.startswith(default_clause, position):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical column default differs from its catalog witness: "
                f"column={column.name!r}, default_kind={column.default_kind!r}"
            )
        position += len(default_clause)
    elif column.default_expression:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical column has a default expression without a default kind: "
            f"column={column.name!r}"
        )
    comment_clause = f" COMMENT {_quote_clickhouse_string_literal(comment)}"
    if entry.startswith(" COMMENT ", position):
        if not entry.startswith(comment_clause, position):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical column comment differs from its catalog witness: "
                f"column={column.name!r}"
            )
        position += len(comment_clause)
    elif comment:
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical column omits its catalog comment: column={column.name!r}"
        )
    if codec:
        codec_clause = f" {codec}"
        if not entry.startswith(codec_clause, position):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical column codec differs from its catalog witness: "
                f"column={column.name!r}"
            )
        position += len(codec_clause)
    if entry.startswith(" TTL ", position):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse 21.8 source profile does not support declared projections or TTL: "
            "hazard_token='TTL'"
        )
    if position != len(entry):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical column declaration has an unrecognized suffix: "
            f"column={column.name!r}, position={column.position}"
        )


def _require_clickhouse_ddl_storage(
    table_engine: str,
    engine_full: str,
    partition_key: str,
    primary_key: str,
    sorting_key: str,
    sampling_key: str,
    table_comment: str,
) -> None:
    if not engine_full.startswith(table_engine):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical engine definition differs from its table engine"
        )
    position = len(table_engine)
    engine_unquoted = _unquoted_clickhouse_ddl(engine_full)
    engine_arguments: tuple[str, ...] | None = None
    if position < len(engine_full) and engine_full[position] == "(":
        engine_arguments, position = _clickhouse_parenthesized_items(
            engine_full,
            engine_unquoted,
            position,
            "table engine arguments",
        )
    elif position < len(engine_full) and engine_full[position] != " ":
        raise ClickHouseDataValidationError(
            "ClickHouse canonical engine definition has an invalid engine-name boundary"
        )
    if engine_arguments:
        position = _require_clickhouse_old_merge_tree_storage(
            engine_full,
            position,
            engine_arguments,
            partition_key,
            primary_key,
            sorting_key,
            sampling_key,
        )
    else:
        position = _require_clickhouse_extended_merge_tree_storage(
            engine_full,
            position,
            partition_key,
            primary_key,
            sorting_key,
            sampling_key,
        )
    comment_clause = f" COMMENT {_quote_clickhouse_string_literal(table_comment)}"
    if engine_full.startswith(" COMMENT ", position):
        if not engine_full.startswith(comment_clause, position):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical table comment differs from its catalog witness"
            )
        position += len(comment_clause)
    elif table_comment:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table DDL omits its catalog comment"
        )
    if position != len(engine_full):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical engine definition has an unrecognized clause boundary"
        )


def _require_clickhouse_extended_merge_tree_storage(
    engine_full: str,
    position: int,
    partition_key: str,
    primary_key: str,
    sorting_key: str,
    sampling_key: str,
) -> int:
    position, has_partition = _consume_clickhouse_catalog_clause(
        engine_full,
        position,
        "PARTITION BY",
        partition_key,
    )
    if has_partition != bool(partition_key):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical PARTITION BY clause differs from its catalog witness"
        )
    position, has_primary = _consume_clickhouse_key_clause(
        engine_full,
        position,
        "PRIMARY KEY",
        primary_key,
    )
    position, has_order = _consume_clickhouse_key_clause(
        engine_full,
        position,
        "ORDER BY",
        sorting_key,
    )
    if not has_order:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical extended MergeTree definition omits ORDER BY"
        )
    if not has_primary and primary_key != sorting_key:
        raise ClickHouseDataValidationError(
            "ClickHouse inferred primary key differs from its sorting-key witness"
        )
    position, has_sample = _consume_clickhouse_catalog_clause(
        engine_full,
        position,
        "SAMPLE BY",
        sampling_key,
    )
    if has_sample != bool(sampling_key):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical SAMPLE BY clause differs from its catalog witness"
        )
    if engine_full.startswith(" TTL ", position):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse 21.8 source profile does not support declared projections or TTL: "
            "hazard_token='TTL'"
        )
    if engine_full.startswith(" SETTINGS ", position):
        position = _clickhouse_settings_end(
            engine_full,
            position + len(" SETTINGS "),
        )
    return position


def _require_clickhouse_old_merge_tree_storage(
    engine_full: str,
    position: int,
    engine_arguments: tuple[str, ...],
    partition_key: str,
    primary_key: str,
    sorting_key: str,
    sampling_key: str,
) -> int:
    if len(engine_arguments) not in (3, 4):
        raise ClickHouseDataValidationError(
            "ClickHouse old MergeTree syntax must contain three or four engine arguments"
        )
    date_name = _clickhouse_identifier_name(
        engine_arguments[0],
        "old MergeTree date-column argument",
    )
    expected_partition = f"toYYYYMM({_quote_clickhouse_identifier_if_needed(date_name)})"
    if partition_key != expected_partition:
        raise ClickHouseDataValidationError(
            "ClickHouse old MergeTree partition key differs from its date-column argument"
        )
    if primary_key != sorting_key:
        raise ClickHouseDataValidationError(
            "ClickHouse old MergeTree primary key differs from its sorting-key witness"
        )
    if len(engine_arguments) == 4:
        sampling_argument = engine_arguments[1]
        sorting_argument = engine_arguments[2]
        granularity_argument = engine_arguments[3]
        if sampling_key != sampling_argument:
            raise ClickHouseDataValidationError(
                "ClickHouse old MergeTree sampling key differs from its engine argument"
            )
    else:
        sorting_argument = engine_arguments[1]
        granularity_argument = engine_arguments[2]
        if sampling_key:
            raise ClickHouseDataValidationError(
                "ClickHouse old MergeTree catalog unexpectedly declares a sampling key"
            )
    if not _clickhouse_key_definition_matches_catalog(sorting_argument, sorting_key):
        raise ClickHouseDataValidationError(
            "ClickHouse old MergeTree sorting key differs from its engine argument"
        )
    if (
        _UNSIGNED_INTEGER.fullmatch(granularity_argument) is None
        or int(granularity_argument) > _MAX_UINT64
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse old MergeTree index granularity is not a canonical UInt64 literal"
        )
    if engine_full.startswith(" TTL ", position):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse 21.8 source profile does not support declared projections or TTL: "
            "hazard_token='TTL'"
        )
    if engine_full.startswith(" SETTINGS ", position):
        raise ClickHouseDataValidationError(
            "ClickHouse old MergeTree syntax cannot contain a SETTINGS clause"
        )
    return position


def _consume_clickhouse_catalog_clause(
    value: str,
    position: int,
    keyword: str,
    expression: str,
) -> tuple[int, bool]:
    prefix = f" {keyword} "
    if not value.startswith(prefix, position):
        return position, False
    if not expression:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table clause is absent from its catalog witness: "
            f"clause={keyword!r}"
        )
    clause = f"{prefix}{expression}"
    if not value.startswith(clause, position):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table clause differs from its catalog expression: "
            f"clause={keyword!r}"
        )
    return position + len(clause), True


def _consume_clickhouse_key_clause(
    value: str,
    position: int,
    keyword: str,
    expression_list: str,
) -> tuple[int, bool]:
    prefix = f" {keyword} "
    if not value.startswith(prefix, position):
        return position, False
    for definition in _clickhouse_key_definition_candidates(expression_list):
        clause = f"{prefix}{definition}"
        if value.startswith(clause, position):
            return position + len(clause), True
    raise ClickHouseDataValidationError(
        "ClickHouse canonical table key differs from its catalog expression list: "
        f"clause={keyword!r}"
    )


def _clickhouse_key_definition_matches_catalog(
    definition: str,
    expression_list: str,
) -> bool:
    tuple_expression_list = _clickhouse_native_tuple_expression_list(definition)
    if tuple_expression_list is not None:
        return tuple_expression_list == expression_list
    return definition == expression_list


def _clickhouse_key_definition_candidates(expression_list: str) -> tuple[str, ...]:
    expressions = _clickhouse_top_level_items(
        expression_list,
        "key expression list",
    )
    if not expressions:
        candidates = ("tuple()",)
    elif len(expressions) == 1:
        candidates = (f"tuple({expression_list})", expression_list)
    else:
        candidates = (f"({expression_list})",)
    return tuple(
        candidate
        for candidate in candidates
        if _clickhouse_key_definition_matches_catalog(candidate, expression_list)
    )


def _clickhouse_native_tuple_expression_list(value: str) -> str | None:
    if value.startswith("tuple("):
        opening = len("tuple")
        named_tuple = True
    elif value.startswith("("):
        opening = 0
        named_tuple = False
    else:
        return None
    unquoted = _unquoted_clickhouse_ddl(value)
    items, end = _clickhouse_parenthesized_items(
        value,
        unquoted,
        opening,
        "key tuple",
    )
    if end != len(value):
        return None
    if (named_tuple and len(items) > 1) or (not named_tuple and len(items) < 2):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical key tuple does not use its native formatter shape"
        )
    return value[opening + 1 : end - 1]


def _clickhouse_settings_end(value: str, position: int) -> int:
    if position >= len(value):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table SETTINGS clause must contain an assignment"
        )
    while True:
        position = _clickhouse_setting_name_end(value, position)
        if not value.startswith(" = ", position):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical table setting must use the formatter's ' = ' separator"
            )
        position = _clickhouse_native_literal_end(value, position + len(" = "))
        if not value.startswith(", ", position):
            return position
        position += len(", ")
        if position >= len(value):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical table SETTINGS clause has a trailing separator"
            )


def _clickhouse_setting_name_end(value: str, position: int) -> int:
    if position < len(value) and value[position] == "`":
        return _clickhouse_quoted_end(value, position, "table setting name")
    match = _DDL_SETTING_NAME.match(value, position)
    if match is None:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table SETTINGS clause has an invalid setting name"
        )
    return match.end()


def _clickhouse_native_literal_end(value: str, position: int) -> int:
    if position >= len(value):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical table setting must have a native literal value"
        )
    if value[position] == "'":
        return _clickhouse_quoted_end(value, position, "table setting literal")
    if value.startswith("NULL", position):
        return position + len("NULL")
    number_match = _DDL_NUMBER_LITERAL.match(value, position)
    if number_match is not None:
        return number_match.end()
    if value.startswith("tuple(", position):
        return _clickhouse_native_literal_group_end(value, position + len("tuple"))
    if value[position] in ("(", "["):
        return _clickhouse_native_literal_group_end(value, position)
    raise ClickHouseDataValidationError(
        "ClickHouse canonical table setting value is not a native formatter literal"
    )


def _clickhouse_native_literal_group_end(value: str, position: int) -> int:
    opening = value[position]
    closing = _DDL_DELIMITER_PAIRS[opening]
    position += 1
    if position < len(value) and value[position] == closing:
        return position + 1
    while True:
        position = _clickhouse_native_literal_end(value, position)
        if position < len(value) and value[position] == closing:
            return position + 1
        if not value.startswith(", ", position):
            raise ClickHouseDataValidationError(
                "ClickHouse canonical table setting collection has invalid literal separation"
            )
        position += len(", ")


def _clickhouse_parenthesized_items(
    value: str,
    unquoted: str,
    position: int,
    label: str,
) -> tuple[tuple[str, ...], int]:
    end = _clickhouse_parenthesized_end(value, unquoted, position, label)
    return _clickhouse_top_level_items(value[position + 1 : end - 1], label), end


def _clickhouse_top_level_items(value: str, label: str) -> tuple[str, ...]:
    if not value:
        return ()
    unquoted = _unquoted_clickhouse_ddl(value)
    delimiters: list[str] = []
    items: list[str] = []
    item_start = 0
    for position, character in enumerate(unquoted):
        if character in _DDL_DELIMITER_PAIRS:
            delimiters.append(character)
            continue
        if character in _DDL_DELIMITER_PAIRS.values():
            if not delimiters or _DDL_DELIMITER_PAIRS[delimiters.pop()] != character:
                raise ClickHouseDataValidationError(
                    f"ClickHouse canonical {label} has mismatched delimiters"
                )
            continue
        if character != "," or delimiters:
            continue
        item = value[item_start:position]
        if not item or item.startswith(" ") or item.endswith(" "):
            raise ClickHouseDataValidationError(
                f"ClickHouse canonical {label} contains an empty or padded item"
            )
        if value[position + 1 : position + 2] != " ":
            raise ClickHouseDataValidationError(
                f"ClickHouse canonical {label} has a non-canonical item separator"
            )
        items.append(item)
        item_start = position + 2
    if delimiters:
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical {label} has unterminated delimiters"
        )
    item = value[item_start:]
    if not item or item.startswith(" ") or item.endswith(" "):
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical {label} contains an empty or padded item"
        )
    items.append(item)
    return tuple(items)


def _clickhouse_parenthesized_end(
    value: str,
    unquoted: str,
    position: int,
    label: str,
) -> int:
    if position >= len(value) or unquoted[position] != "(":
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical {label} must start with an opening parenthesis"
        )
    delimiters: list[str] = []
    for current in range(position, len(unquoted)):
        character = unquoted[current]
        if character in _DDL_DELIMITER_PAIRS:
            delimiters.append(character)
            continue
        if character not in _DDL_DELIMITER_PAIRS.values():
            continue
        if not delimiters or _DDL_DELIMITER_PAIRS[delimiters.pop()] != character:
            raise ClickHouseDataValidationError(
                f"ClickHouse canonical {label} has mismatched delimiters"
            )
        if not delimiters:
            return current + 1
    raise ClickHouseDataValidationError(f"ClickHouse canonical {label} is unterminated")


def _clickhouse_identifier_name(value: str, label: str) -> str:
    if not value:
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical {label} must be a whole identifier"
        )
    parts: list[str] = []
    position = 0
    while position < len(value):
        if value[position] == "`":
            end = _clickhouse_quoted_end(value, position, label)
            part = _decode_clickhouse_backtick_identifier(value[position:end], label)
        else:
            match = _DDL_IDENTIFIER_PART.match(value, position)
            if match is None:
                raise ClickHouseDataValidationError(
                    f"ClickHouse canonical {label} contains an invalid identifier part"
                )
            end = match.end()
            part = value[position:end]
        parts.append(part)
        if end == len(value):
            break
        if value[end] != "." or end + 1 == len(value):
            raise ClickHouseDataValidationError(
                f"ClickHouse canonical {label} is not a whole compound identifier"
            )
        position = end + 1
    canonical = ".".join(_quote_clickhouse_identifier_if_needed(part) for part in parts)
    if canonical != value:
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical {label} does not use native identifier quoting"
        )
    return ".".join(parts)


def _decode_clickhouse_backtick_identifier(value: str, label: str) -> str:
    if not value.startswith("`") or _clickhouse_quoted_end(value, 0, label) != len(value):
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical {label} contains an incomplete quoted identifier"
        )
    decoded: list[str] = []
    position = 1
    while position < len(value) - 1:
        character = value[position]
        if character == "\\":
            escaped_position = position + 1
            if escaped_position >= len(value) - 1:
                raise ClickHouseDataValidationError(
                    f"ClickHouse canonical {label} contains an incomplete identifier escape"
                )
            escaped = value[escaped_position]
            decoded.append(_DDL_BACKTICK_ESCAPE_VALUES.get(escaped, escaped))
            position += 2
            continue
        if character == "`" and value[position + 1 : position + 2] == "`":
            decoded.append("`")
            position += 2
            continue
        decoded.append(character)
        position += 1
    return "".join(decoded)


def _quote_clickhouse_identifier_if_needed(value: str) -> str:
    if _DDL_IDENTIFIER_PART.fullmatch(value) is not None and value.lower() != "null":
        return value
    return _quote_clickhouse_backtick_identifier(value)


def _quote_clickhouse_backtick_identifier(value: str) -> str:
    escaped = "".join(_DDL_BACKTICK_ESCAPES.get(character, character) for character in value)
    return f"`{escaped}`"


def _quote_clickhouse_string_literal(value: str) -> str:
    escaped = "".join(_DDL_STRING_ESCAPES.get(character, character) for character in value)
    return f"'{escaped}'"


def _clickhouse_quoted_end(value: str, position: int, label: str) -> int:
    if position >= len(value) or value[position] not in ("'", '"', "`"):
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical {label} must start with quoted text"
        )
    quote = value[position]
    position += 1
    while position < len(value):
        character = value[position]
        if character == "\\":
            position += 2
            continue
        if character != quote:
            position += 1
            continue
        if position + 1 < len(value) and value[position + 1] == quote:
            position += 2
            continue
        return position + 1
    raise ClickHouseDataValidationError(
        f"ClickHouse canonical {label} contains unterminated quoted text"
    )


def _unquoted_clickhouse_ddl(value: str) -> str:
    characters = list(value)
    position = 0
    while position < len(characters):
        if characters[position] not in ("'", '"', "`"):
            position += 1
            continue
        quoted_end = _clickhouse_quoted_end(value, position, "table DDL")
        for quoted_position in range(position, quoted_end):
            characters[quoted_position] = " "
        position = quoted_end
    return "".join(characters)


def _parse_uuid(value: str, label: str) -> UUID:
    _require_bounded_text(value, label)
    try:
        parsed = UUID(value)
    except ValueError:
        raise ClickHouseDataValidationError(f"ClickHouse {label} is not a UUID") from None
    if parsed.int == 0 or str(parsed) != value.lower():
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be a canonical non-zero UUID")
    return parsed


def _parse_date(value: str, label: str) -> date:
    _require_bounded_text(value, label)
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise ClickHouseDataValidationError(f"ClickHouse {label} is not an ISO date") from None
    if parsed.isoformat() != value:
        raise ClickHouseDataValidationError(f"ClickHouse {label} is not canonical ISO date text")
    return parsed


def _parse_utc_datetime(value: str, label: str) -> datetime:
    _require_bounded_text(value, label)
    try:
        parsed = datetime.strptime(value, _MANIFEST_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be canonical UTC text with six fractional digits"
        ) from None
    if parsed.strftime(_MANIFEST_TIMESTAMP_FORMAT) != value:
        raise ClickHouseDataValidationError(f"ClickHouse {label} is not canonical UTC text")
    return parsed


def _require_sha256(value: str, label: str) -> None:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be lowercase SHA-256")


def _parse_positive_integer_text(value: str, label: str) -> int:
    parsed = _parse_nonnegative_integer_text(value, label)
    if parsed < 1:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be a positive canonical decimal integer"
        )
    return parsed


def _parse_nonnegative_integer_text(value: str, label: str) -> int:
    if type(value) is not str or _UNSIGNED_INTEGER.fullmatch(value) is None:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be a canonical unsigned decimal integer"
        )
    return int(value)


def _require_positive_integer(value: int, label: str) -> None:
    if type(value) is not int or value < 1:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be a positive integer")


def _require_nonnegative_integer(value: int, label: str) -> None:
    if type(value) is not int or value < 0:
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be a non-negative integer")


def _require_utc_datetime(value: datetime, label: str) -> None:
    if type(value) is not datetime or value.utcoffset() != UTC.utcoffset(value):
        raise ClickHouseDataValidationError(f"ClickHouse {label} must be an exact UTC datetime")


def _require_bounded_text(value: str, label: str) -> None:
    validate_clickhouse_text_scalar(value, f"ClickHouse {label}")
    if len(value.encode("utf-8", errors="strict")) > 4_096:
        raise ClickHouseDataValidationError(f"ClickHouse {label} exceeds its UTF-8 byte bound")


__all__ = [
    "ClickHouseLegacyManifestError",
    "ClickHouseLegacySealAssertions",
    "ClickHouseLegacyServerIdentity",
    "ClickHouseLegacySourceBinding",
    "ClickHouseLegacySourceConfirmation",
    "ClickHouseLegacySourceManifest",
    "ClickHouseLegacySourceRequest",
    "ClickHouseLegacyTableIdentity",
    "acquire_clickhouse_legacy_source",
    "confirm_clickhouse_legacy_source",
    "parse_clickhouse_legacy_source_manifest",
    "require_clickhouse_legacy_plain_merge_tree_ddl",
    "validate_clickhouse_legacy_limit_closure",
]
