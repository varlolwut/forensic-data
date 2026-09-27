import hashlib
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Literal, final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from forensic_data.acquisition import EarlyExecutionOutcome
from forensic_data.canonical import CanonicalSchema
from forensic_data.clickhouse import (
    ClickHouseDataValidationError,
    ClickHouseParameter,
    ClickHouseTransport,
    UnsupportedClickHouseProfileError,
    parse_clickhouse_json_rows,
    quote_clickhouse_identifier,
    validate_clickhouse_identifier,
    validate_clickhouse_text_scalar,
)
from forensic_data.clickhouse_canonical import (
    ClickHouseCanonicalFingerprint,
    ClickHouseCanonicalLimits,
    ClickHouseCanonicalRelation,
    ClickHouseMergeTreeLogicalProjectionSource,
    ClickHouseReplacingMergeTreeLogicalProjectionSource,
    inspect_clickhouse_canonical_relation,
    read_clickhouse_canonical_fingerprint,
)
from forensic_data.clickhouse_readiness import (
    ClickHouseColumnIdentity,
    ClickHouseImmutableVersionBinding,
    ClickHouseImmutableVersionConfirmation,
    ClickHouseImmutableVersionManifest,
    ClickHouseImmutableVersionRequest,
    ClickHouseNamedVersionConfirmation,
    ClickHouseNamedVersionObservation,
    ClickHouseTableIdentity,
    ClickHouseVersionLocator,
    acquire_clickhouse_immutable_version,
    confirm_clickhouse_immutable_version,
    confirm_clickhouse_named_version,
    observe_clickhouse_named_version,
)
from forensic_data.contracts.errors import ContractValidationError
from forensic_data.contracts.model import MinimumEvidence
from forensic_data.contracts.semantics import semantic_value_from_json
from forensic_data.result import (
    ConsistencyLevel,
    ExecutionStatus,
    ReasonCode,
    ResultReason,
    SafeParameter,
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_UNSIGNED_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
_SIMPLE_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_REPLACING_ENGINE = re.compile(
    r"ReplacingMergeTree\(([A-Za-z_][A-Za-z0-9_]*)\) ORDER BY ",
    re.ASCII,
)
_PROJECTION_MANIFEST_STRATEGY = "replacing_merge_tree_final"
_PLAIN_PROJECTION_STRATEGY = "plain_merge_tree"
_REPLACING_PROJECTION_STRATEGY = "replacing_merge_tree_final"
_MAX_PROJECTION_MANIFEST_BYTES = 65_536
_PLAIN_LIMITATIONS = (
    "HTTP queries do not share a transaction snapshot",
    "the connection endpoint must remain pinned to one ClickHouse server",
    "the loader's named-version immutability assertion remains an external precondition",
    "the current mutation catalog does not prove historical mutation freedom",
    "privileged role, policy, and table-setting changes cannot be excluded between queries",
)
_REPLACING_LIMITATIONS = (
    "HTTP queries do not share a transaction snapshot",
    "the connection endpoint must remain pinned to one ClickHouse server",
    "the loader's named-version immutability assertion remains an external precondition",
    "the current mutation catalog does not prove historical mutation freedom",
    "historical equal-version freedom is asserted by the loader projection manifest",
    "runtime tie inspection can observe only contenders that still exist in active parts",
    "privileged role, policy, and table-setting changes cannot be excluded between queries",
)


class ClickHouseProjectionManifestError(ValueError):
    """A loader projection artifact cannot establish the declared logical relation."""


class ClickHouseReplacingVersionAmbiguityError(ClickHouseDataValidationError):
    """A ReplacingMergeTree has more than one observable winner at its maximum version."""


class ClickHouseMutationFailureError(ClickHouseDataValidationError):
    """A retained ClickHouse mutation has failed or was killed."""


class _ProjectionLocatorPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    database: str
    table: str
    uuid: str


class _ReplacingProjectionManifestPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[1]
    issuer: str
    dataset_id: str
    expected_batch_id: str
    immutable_manifest_sha256: str
    publication_revision: int = Field(ge=1)
    version_locator: _ProjectionLocatorPayload
    table_definition_sha256: str
    projection_strategy: Literal["replacing_merge_tree_final"]
    projected_columns: list[str]
    sorting_key_columns: list[str]
    version_column: str
    equal_version_policy: Literal["forbidden"]
    preseal_equal_max_version_key_count: Literal[0]
    physical_row_count: int = Field(ge=0)
    logical_row_count: int = Field(ge=0)
    logical_deletes: Literal["unsupported"]


class _MutationPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_uuid: str
    mutation_id: str
    command_sha256: str
    create_time_epoch: str
    parts_to_do: str
    parts_in_progress: str
    is_done: str
    is_killed: str
    has_failed_part: str
    failure_reason_sha256: str
    failure_error_code_name: str


class _RuntimePayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_uuid: str
    final_setting: str
    apply_mutations_on_fly: str
    apply_patch_parts: str
    merge_across_partitions_final: str
    projection_count: str


class _PartPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_uuid: str
    active_part_count: str
    active_row_count: str
    lightweight_delete_part_count: str
    patch_part_count: str


class _AmbiguityPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_uuid: str
    ambiguous_group_count: str


class _RowCountPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    server_uuid: str
    physical_row_count: str
    logical_row_count: str


@final
@dataclass(frozen=True, slots=True)
class ClickHouseReplacingProjectionManifest:
    manifest_version: int
    issuer: str
    dataset_id: str
    expected_batch_id: str
    immutable_manifest_sha256: str
    publication_revision: int
    version_locator: ClickHouseVersionLocator
    definition_sha256: str
    strategy: str
    projected_columns: tuple[str, ...]
    sorting_key: tuple[str, ...]
    version_column: str
    equal_version_policy: str
    preseal_equal_version_group_count: int
    physical_row_count: int
    logical_row_count: int
    logical_deletes: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        if type(self.manifest_version) is not int or self.manifest_version != 1:
            raise ClickHouseProjectionManifestError(
                "ClickHouse projection manifest version must be the exact integer 1"
            )
        _require_bounded_text(self.issuer, "projection manifest issuer")
        _require_bounded_text(self.dataset_id, "projection manifest dataset ID")
        _require_bounded_text(
            self.expected_batch_id,
            "projection manifest expected batch ID",
        )
        _require_sha256(
            self.immutable_manifest_sha256,
            "projection immutable-manifest digest",
        )
        _require_positive_integer(
            self.publication_revision,
            "projection manifest publication revision",
        )
        if type(self.version_locator) is not ClickHouseVersionLocator:
            raise TypeError("projection version_locator must be ClickHouseVersionLocator")
        _require_sha256(self.definition_sha256, "projection table definition digest")
        if self.strategy != _PROJECTION_MANIFEST_STRATEGY:
            raise ClickHouseProjectionManifestError(
                "ClickHouse projection manifest has an unsupported strategy"
            )
        _require_identifier_tuple(self.projected_columns, "projected column")
        _require_identifier_tuple(self.sorting_key, "sorting-key column")
        _require_simple_identifier(self.version_column, "projection version column")
        if self.version_column in self.sorting_key:
            raise ClickHouseProjectionManifestError(
                "ClickHouse projection version column must not be part of the sorting key"
            )
        if self.equal_version_policy != "forbidden":
            raise ClickHouseProjectionManifestError(
                "ClickHouse projection must declare equal versions forbidden"
            )
        if (
            type(self.preseal_equal_version_group_count) is not int
            or self.preseal_equal_version_group_count != 0
        ):
            raise ClickHouseProjectionManifestError(
                "ClickHouse pre-seal equal-version audit must report exactly zero groups"
            )
        _require_nonnegative_integer(
            self.physical_row_count,
            "projection physical row count",
        )
        _require_nonnegative_integer(
            self.logical_row_count,
            "projection logical row count",
        )
        if self.logical_row_count > self.physical_row_count:
            raise ClickHouseProjectionManifestError(
                "ClickHouse logical row count cannot exceed its physical row count"
            )
        if self.logical_deletes != "unsupported":
            raise ClickHouseProjectionManifestError(
                "ClickHouse projection manifest must declare logical deletes unsupported"
            )
        _require_sha256(self.artifact_sha256, "projection artifact digest")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseProjectionRequest:
    version_request: ClickHouseImmutableVersionRequest
    schema: CanonicalSchema
    column_names: tuple[str, ...]
    canonical_limits: ClickHouseCanonicalLimits
    max_mutation_records: int
    max_tie_groups: int

    def __post_init__(self) -> None:
        if type(self.version_request) is not ClickHouseImmutableVersionRequest:
            raise TypeError("version_request must be ClickHouseImmutableVersionRequest")
        if type(self.schema) is not CanonicalSchema:
            raise TypeError("schema must be CanonicalSchema")
        _require_identifier_tuple(self.column_names, "projection column")
        if len(self.column_names) != len(self.schema.fields):
            raise ValueError(
                "ClickHouse projection column count must equal the logical field count"
            )
        if type(self.canonical_limits) is not ClickHouseCanonicalLimits:
            raise TypeError("canonical_limits must be ClickHouseCanonicalLimits")
        _require_positive_integer(
            self.max_mutation_records,
            "projection mutation record limit",
        )
        _require_positive_integer(self.max_tie_groups, "projection tie group limit")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseMutationRecord:
    mutation_id: str
    command_sha256: str
    create_time_epoch: int
    parts_to_do: int
    parts_in_progress: int
    is_done: bool
    is_killed: bool
    has_failed_part: bool
    failure_reason_sha256: str
    failure_error_code_name: str

    def __post_init__(self) -> None:
        _require_bounded_text(self.mutation_id, "mutation ID")
        _require_sha256(self.command_sha256, "mutation command digest")
        _require_nonnegative_integer(self.create_time_epoch, "mutation create time")
        _require_nonnegative_integer(self.parts_to_do, "mutation parts to do")
        _require_nonnegative_integer(
            self.parts_in_progress,
            "mutation parts in progress",
        )
        if type(self.is_done) is not bool or type(self.is_killed) is not bool:
            raise TypeError("ClickHouse mutation state flags must be booleans")
        if type(self.has_failed_part) is not bool:
            raise TypeError("ClickHouse mutation failure flag must be a boolean")
        if self.failure_reason_sha256:
            _require_sha256(self.failure_reason_sha256, "mutation failure digest")
        _require_optional_bounded_text(
            self.failure_error_code_name,
            "mutation failure error-code name",
        )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseMutationWitness:
    records: tuple[ClickHouseMutationRecord, ...]

    def __post_init__(self) -> None:
        if type(self.records) is not tuple:
            raise TypeError("ClickHouse mutation records must be an immutable tuple")
        for record in self.records:
            if type(record) is not ClickHouseMutationRecord:
                raise TypeError("ClickHouse mutation witness contains an invalid record")
        if tuple(sorted(record.mutation_id for record in self.records)) != tuple(
            record.mutation_id for record in self.records
        ):
            raise ValueError("ClickHouse mutation records must be ordered by mutation ID")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseProjectionRuntimeWitness:
    server_uuid: UUID
    final_setting: int
    apply_mutations_on_fly: int
    apply_patch_parts: int
    merge_across_partitions_final: int
    projection_count: int
    active_part_count: int
    active_row_count: int
    lightweight_delete_part_count: int
    patch_part_count: int

    def __post_init__(self) -> None:
        if type(self.server_uuid) is not UUID or self.server_uuid.int == 0:
            raise ValueError("ClickHouse projection runtime requires a non-zero server UUID")
        for value, label in (
            (self.final_setting, "final setting"),
            (self.apply_mutations_on_fly, "apply_mutations_on_fly setting"),
            (self.apply_patch_parts, "apply_patch_parts setting"),
            (
                self.merge_across_partitions_final,
                "do_not_merge_across_partitions_select_final setting",
            ),
            (self.projection_count, "projection count"),
            (self.active_part_count, "active part count"),
            (self.active_row_count, "active row count"),
            (
                self.lightweight_delete_part_count,
                "lightweight-delete part count",
            ),
            (self.patch_part_count, "patch part count"),
        ):
            _require_nonnegative_integer(value, label)


@final
@dataclass(frozen=True, slots=True)
class ClickHouseReplacingRowCounts:
    physical_row_count: int
    logical_row_count: int

    def __post_init__(self) -> None:
        _require_nonnegative_integer(self.physical_row_count, "physical row count")
        _require_nonnegative_integer(self.logical_row_count, "logical row count")
        if self.logical_row_count > self.physical_row_count:
            raise ValueError("ClickHouse logical row count cannot exceed physical row count")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseMergeTreeProjectionBinding:
    strategy: str
    request: ClickHouseProjectionRequest
    immutable_binding: ClickHouseImmutableVersionBinding
    relation: ClickHouseCanonicalRelation
    mutation_witness: ClickHouseMutationWitness
    runtime_witness: ClickHouseProjectionRuntimeWitness
    logical_fingerprint: ClickHouseCanonicalFingerprint
    overall_evidence: ConsistencyLevel
    opened_at: datetime
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.strategy != _PLAIN_PROJECTION_STRATEGY:
            raise ValueError("ClickHouse plain projection strategy is invalid")
        _require_request(self.request)
        if type(self.immutable_binding) is not ClickHouseImmutableVersionBinding:
            raise TypeError("immutable_binding must be ClickHouseImmutableVersionBinding")
        if self.request.version_request != self.immutable_binding.request:
            raise ValueError("plain projection request has a different version request")
        _require_relation(self.relation)
        if type(self.relation.source) is not ClickHouseMergeTreeLogicalProjectionSource:
            raise ValueError("ClickHouse plain projection requires a plain logical source")
        _require_projection_relation_contract(
            self.request,
            self.immutable_binding.version_identity,
            self.relation,
        )
        _require_projection_witnesses(
            self.mutation_witness,
            self.runtime_witness,
            self.logical_fingerprint,
        )
        _require_ready_mutation_witness(self.mutation_witness)
        _require_ready_runtime(
            self.runtime_witness,
            self.immutable_binding.version_identity,
        )
        if self.runtime_witness.active_row_count != self.logical_fingerprint.fingerprint.count:
            raise ValueError(
                "ClickHouse plain projection row count differs from its logical fingerprint"
            )
        if self.overall_evidence is not ConsistencyLevel.ASSERTED:
            raise ValueError("ClickHouse projection evidence must remain asserted")
        _require_utc_datetime(self.opened_at, "plain projection opened_at")
        if self.limitations != _PLAIN_LIMITATIONS:
            raise ValueError("ClickHouse plain projection limitations are incomplete")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseReplacingMergeTreeProjectionBinding:
    strategy: str
    request: ClickHouseProjectionRequest
    named_version: ClickHouseNamedVersionObservation
    projection_manifest: ClickHouseReplacingProjectionManifest
    relation: ClickHouseCanonicalRelation
    mutation_witness: ClickHouseMutationWitness
    runtime_witness: ClickHouseProjectionRuntimeWitness
    row_counts: ClickHouseReplacingRowCounts
    logical_fingerprint: ClickHouseCanonicalFingerprint
    stable_read_evidence: ConsistencyLevel
    tie_freedom_evidence: ConsistencyLevel
    overall_evidence: ConsistencyLevel
    opened_at: datetime
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.strategy != _REPLACING_PROJECTION_STRATEGY:
            raise ValueError("ClickHouse Replacing projection strategy is invalid")
        _require_request(self.request)
        if type(self.named_version) is not ClickHouseNamedVersionObservation:
            raise TypeError("named_version must be ClickHouseNamedVersionObservation")
        if self.request.version_request != self.named_version.request:
            raise ValueError("Replacing projection request has a different version request")
        if type(self.projection_manifest) is not ClickHouseReplacingProjectionManifest:
            raise TypeError("projection_manifest must be ClickHouseReplacingProjectionManifest")
        _require_projection_manifest_closure(
            self.named_version.manifest,
            self.projection_manifest,
            self.request,
        )
        _require_replacing_profile(
            self.named_version.version_identity,
            self.projection_manifest,
        )
        _require_relation(self.relation)
        if type(self.relation.source) is not ClickHouseReplacingMergeTreeLogicalProjectionSource:
            raise ValueError(
                "ClickHouse Replacing projection requires an explicit FINAL logical source"
            )
        _require_projection_relation_contract(
            self.request,
            self.named_version.version_identity,
            self.relation,
        )
        _require_projection_witnesses(
            self.mutation_witness,
            self.runtime_witness,
            self.logical_fingerprint,
        )
        _require_ready_mutation_witness(self.mutation_witness)
        _require_ready_runtime(
            self.runtime_witness,
            self.named_version.version_identity,
        )
        if type(self.row_counts) is not ClickHouseReplacingRowCounts:
            raise TypeError("row_counts must be ClickHouseReplacingRowCounts")
        _require_manifest_row_counts(
            self.row_counts,
            self.projection_manifest,
            self.named_version.version_identity,
        )
        _require_part_row_count(
            self.runtime_witness,
            self.row_counts,
            self.named_version.version_identity,
        )
        if self.logical_fingerprint.fingerprint.count != self.row_counts.logical_row_count:
            raise ValueError(
                "ClickHouse Replacing projection row count differs from its logical fingerprint"
            )
        if (
            self.stable_read_evidence is not self.named_version.manifest.immutability_evidence
            or self.tie_freedom_evidence is not ConsistencyLevel.ASSERTED
            or self.overall_evidence is not ConsistencyLevel.ASSERTED
        ):
            raise ValueError("ClickHouse Replacing projection evidence must remain asserted")
        _require_utc_datetime(self.opened_at, "Replacing projection opened_at")
        if self.limitations != _REPLACING_LIMITATIONS:
            raise ValueError("ClickHouse Replacing projection limitations are incomplete")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseMergeTreeProjectionConfirmation:
    binding: ClickHouseMergeTreeProjectionBinding
    immutable_confirmation: ClickHouseImmutableVersionConfirmation
    final_mutation_witness: ClickHouseMutationWitness
    final_runtime_witness: ClickHouseProjectionRuntimeWitness
    final_logical_fingerprint: ClickHouseCanonicalFingerprint
    confirmed_at: datetime

    def __post_init__(self) -> None:
        if type(self.binding) is not ClickHouseMergeTreeProjectionBinding:
            raise TypeError("binding must be ClickHouseMergeTreeProjectionBinding")
        if type(self.immutable_confirmation) is not ClickHouseImmutableVersionConfirmation:
            raise TypeError("immutable_confirmation must be ClickHouseImmutableVersionConfirmation")
        if self.immutable_confirmation.binding != self.binding.immutable_binding:
            raise ValueError("plain projection confirmation has a different version binding")
        if self.final_mutation_witness != self.binding.mutation_witness:
            raise ValueError("plain projection mutation witness changed")
        if self.final_runtime_witness != self.binding.runtime_witness:
            raise ValueError("plain projection runtime witness changed")
        if self.final_logical_fingerprint != self.binding.logical_fingerprint:
            raise ValueError("plain projection logical fingerprint changed")
        _require_utc_datetime(self.confirmed_at, "plain projection confirmed_at")


@final
@dataclass(frozen=True, slots=True)
class ClickHouseReplacingMergeTreeProjectionConfirmation:
    binding: ClickHouseReplacingMergeTreeProjectionBinding
    named_version_confirmation: ClickHouseNamedVersionConfirmation
    final_mutation_witness: ClickHouseMutationWitness
    final_runtime_witness: ClickHouseProjectionRuntimeWitness
    final_row_counts: ClickHouseReplacingRowCounts
    final_logical_fingerprint: ClickHouseCanonicalFingerprint
    confirmed_at: datetime

    def __post_init__(self) -> None:
        if type(self.binding) is not ClickHouseReplacingMergeTreeProjectionBinding:
            raise TypeError("binding must be ClickHouseReplacingMergeTreeProjectionBinding")
        if type(self.named_version_confirmation) is not ClickHouseNamedVersionConfirmation:
            raise TypeError("named_version_confirmation must be ClickHouseNamedVersionConfirmation")
        if self.named_version_confirmation.observation != self.binding.named_version:
            raise ValueError(
                "Replacing projection confirmation has a different version observation"
            )
        if self.final_mutation_witness != self.binding.mutation_witness:
            raise ValueError("Replacing projection mutation witness changed")
        if self.final_runtime_witness != self.binding.runtime_witness:
            raise ValueError("Replacing projection runtime witness changed")
        if self.final_row_counts != self.binding.row_counts:
            raise ValueError("Replacing projection row counts changed")
        if self.final_logical_fingerprint != self.binding.logical_fingerprint:
            raise ValueError("Replacing projection logical fingerprint changed")
        _require_utc_datetime(self.confirmed_at, "Replacing projection confirmed_at")


def parse_clickhouse_replacing_projection_manifest(
    payload: bytes,
    max_manifest_bytes: int,
) -> ClickHouseReplacingProjectionManifest:
    if type(payload) is not bytes:
        raise TypeError("ClickHouse projection manifest payload must be bytes")
    _require_positive_integer(max_manifest_bytes, "projection manifest byte limit")
    if max_manifest_bytes > _MAX_PROJECTION_MANIFEST_BYTES:
        raise ValueError(
            "ClickHouse projection manifest byte limit exceeds the supported maximum: "
            f"maximum={_MAX_PROJECTION_MANIFEST_BYTES}"
        )
    if not payload or len(payload) > max_manifest_bytes:
        raise ClickHouseProjectionManifestError(
            "ClickHouse projection manifest payload is empty or exceeds its byte limit: "
            f"actual_bytes={len(payload)}, max_bytes={max_manifest_bytes}"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ClickHouseProjectionManifestError(
            "ClickHouse projection manifest is not strict UTF-8: "
            f"byte_start={error.start}, byte_end={error.end}"
        ) from None
    try:
        semantic_value = semantic_value_from_json(text)
        parsed = _ReplacingProjectionManifestPayload.model_validate(semantic_value)
    except (ContractValidationError, ValidationError) as error:
        raise ClickHouseProjectionManifestError(
            "ClickHouse projection manifest violates its strict schema: "
            f"cause_type={type(error).__name__}"
        ) from None
    try:
        locator = ClickHouseVersionLocator(
            database=parsed.version_locator.database,
            table=parsed.version_locator.table,
            uuid=_parse_uuid(parsed.version_locator.uuid, "projection table UUID"),
        )
        return ClickHouseReplacingProjectionManifest(
            manifest_version=parsed.version,
            issuer=parsed.issuer,
            dataset_id=parsed.dataset_id,
            expected_batch_id=parsed.expected_batch_id,
            immutable_manifest_sha256=parsed.immutable_manifest_sha256,
            publication_revision=parsed.publication_revision,
            version_locator=locator,
            definition_sha256=parsed.table_definition_sha256,
            strategy=parsed.projection_strategy,
            projected_columns=tuple(parsed.projected_columns),
            sorting_key=tuple(parsed.sorting_key_columns),
            version_column=parsed.version_column,
            equal_version_policy=parsed.equal_version_policy,
            preseal_equal_version_group_count=(parsed.preseal_equal_max_version_key_count),
            physical_row_count=parsed.physical_row_count,
            logical_row_count=parsed.logical_row_count,
            logical_deletes=parsed.logical_deletes,
            artifact_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except (ClickHouseDataValidationError, TypeError, ValueError) as error:
        raise ClickHouseProjectionManifestError(
            "ClickHouse projection manifest contains invalid typed values: "
            f"cause_type={type(error).__name__}"
        ) from None


def acquire_clickhouse_merge_tree_projection(
    transport: ClickHouseTransport,
    request: ClickHouseProjectionRequest,
    manifest: ClickHouseImmutableVersionManifest,
) -> ClickHouseMergeTreeProjectionBinding | EarlyExecutionOutcome:
    _require_transport(transport)
    _require_request(request)
    if type(manifest) is not ClickHouseImmutableVersionManifest:
        raise TypeError("manifest must be ClickHouseImmutableVersionManifest")
    immutable = acquire_clickhouse_immutable_version(
        transport,
        request.version_request,
        manifest,
    )
    if isinstance(immutable, EarlyExecutionOutcome):
        return immutable
    _require_requested_columns(immutable.version_identity, request.column_names)
    first_mutations = _read_mutation_witness(
        transport,
        immutable.version_identity,
        request,
    )
    pending = _classify_mutation_witness(
        first_mutations,
        immutable.version_identity,
        request.version_request,
    )
    if pending is not None:
        return pending
    first_runtime = _read_runtime_witness(
        transport,
        immutable.version_identity,
        request,
    )
    _require_ready_runtime(first_runtime, immutable.version_identity)
    relation = _inspect_projection_relation(
        transport,
        request,
        immutable.version_identity,
        ClickHouseMergeTreeLogicalProjectionSource(
            database=immutable.version_identity.database,
            table=immutable.version_identity.table,
        ),
    )
    fingerprint = _read_valid_fingerprint(transport, relation, request)
    if fingerprint.fingerprint.count != first_runtime.active_row_count:
        raise ClickHouseDataValidationError(
            "ClickHouse plain projection row count differs between active parts and the "
            "canonical logical read: "
            f"database={immutable.version_identity.database!r}, "
            f"table={immutable.version_identity.table!r}, "
            f"part_rows={first_runtime.active_row_count}, "
            f"logical_rows={fingerprint.fingerprint.count}"
        )
    second_mutations = _read_mutation_witness(
        transport,
        immutable.version_identity,
        request,
    )
    pending = _classify_mutation_witness(
        second_mutations,
        immutable.version_identity,
        request.version_request,
    )
    if pending is not None:
        return pending
    second_runtime = _read_runtime_witness(
        transport,
        immutable.version_identity,
        request,
    )
    _require_ready_runtime(second_runtime, immutable.version_identity)
    if second_mutations != first_mutations or second_runtime != first_runtime:
        return _cut_mismatch_outcome(
            request.version_request,
            "ClickHouse plain projection state changed during acquisition",
        )
    immutable_confirmation = confirm_clickhouse_immutable_version(transport, immutable)
    if isinstance(immutable_confirmation, EarlyExecutionOutcome):
        return immutable_confirmation
    return ClickHouseMergeTreeProjectionBinding(
        strategy=_PLAIN_PROJECTION_STRATEGY,
        request=request,
        immutable_binding=immutable,
        relation=relation,
        mutation_witness=second_mutations,
        runtime_witness=second_runtime,
        logical_fingerprint=fingerprint,
        overall_evidence=ConsistencyLevel.ASSERTED,
        opened_at=datetime.now(UTC),
        limitations=_PLAIN_LIMITATIONS,
    )


def confirm_clickhouse_merge_tree_projection(
    transport: ClickHouseTransport,
    binding: ClickHouseMergeTreeProjectionBinding,
) -> ClickHouseMergeTreeProjectionConfirmation | EarlyExecutionOutcome:
    _require_transport(transport)
    if type(binding) is not ClickHouseMergeTreeProjectionBinding:
        raise TypeError("binding must be ClickHouseMergeTreeProjectionBinding")
    transport.require_attempt(
        binding.immutable_binding.attempt_id,
        "confirm_clickhouse_merge_tree_projection",
    )
    identity = binding.immutable_binding.version_identity
    first_mutations = _read_mutation_witness(
        transport,
        identity,
        binding.request,
    )
    pending = _classify_mutation_witness(
        first_mutations,
        identity,
        binding.immutable_binding.request,
    )
    if pending is not None:
        return _cut_mismatch_outcome(
            binding.immutable_binding.request,
            "ClickHouse plain projection gained an unfinished mutation",
        )
    first_runtime = _read_runtime_witness(
        transport,
        identity,
        binding.request,
    )
    _require_ready_runtime(first_runtime, identity)
    fingerprint = _read_valid_fingerprint(
        transport,
        binding.relation,
        binding.request,
    )
    second_mutations = _read_mutation_witness(
        transport,
        identity,
        binding.request,
    )
    second_runtime = _read_runtime_witness(
        transport,
        identity,
        binding.request,
    )
    _require_ready_runtime(second_runtime, identity)
    if (
        first_mutations != binding.mutation_witness
        or second_mutations != first_mutations
        or first_runtime != binding.runtime_witness
        or second_runtime != first_runtime
        or fingerprint != binding.logical_fingerprint
    ):
        return _cut_mismatch_outcome(
            binding.immutable_binding.request,
            "ClickHouse plain logical projection differs from the bound context",
        )
    immutable_confirmation = confirm_clickhouse_immutable_version(
        transport,
        binding.immutable_binding,
    )
    if isinstance(immutable_confirmation, EarlyExecutionOutcome):
        return immutable_confirmation
    return ClickHouseMergeTreeProjectionConfirmation(
        binding=binding,
        immutable_confirmation=immutable_confirmation,
        final_mutation_witness=second_mutations,
        final_runtime_witness=second_runtime,
        final_logical_fingerprint=fingerprint,
        confirmed_at=datetime.now(UTC),
    )


def acquire_clickhouse_replacing_merge_tree_projection(
    transport: ClickHouseTransport,
    request: ClickHouseProjectionRequest,
    manifest: ClickHouseImmutableVersionManifest,
    projection_manifest: ClickHouseReplacingProjectionManifest,
) -> ClickHouseReplacingMergeTreeProjectionBinding | EarlyExecutionOutcome:
    _require_transport(transport)
    _require_request(request)
    if type(manifest) is not ClickHouseImmutableVersionManifest:
        raise TypeError("manifest must be ClickHouseImmutableVersionManifest")
    if type(projection_manifest) is not ClickHouseReplacingProjectionManifest:
        raise TypeError("projection_manifest must be ClickHouseReplacingProjectionManifest")
    if request.version_request.minimum_evidence is MinimumEvidence.VERIFIED:
        return _unsupported_projection_evidence_outcome(request.version_request)
    _require_projection_manifest_closure(manifest, projection_manifest, request)
    named_version = observe_clickhouse_named_version(
        transport,
        request.version_request,
        manifest,
    )
    if isinstance(named_version, EarlyExecutionOutcome):
        return named_version
    identity = named_version.version_identity
    _require_replacing_profile(identity, projection_manifest)
    _require_requested_columns(identity, request.column_names)
    first_mutations = _read_mutation_witness(transport, identity, request)
    pending = _classify_mutation_witness(
        first_mutations,
        identity,
        request.version_request,
    )
    if pending is not None:
        return pending
    first_runtime = _read_runtime_witness(transport, identity, request)
    _require_ready_runtime(first_runtime, identity)
    _require_no_replacing_ambiguity(
        transport,
        identity,
        projection_manifest,
        request,
    )
    first_counts = _read_replacing_row_counts(transport, identity, request)
    _require_manifest_row_counts(first_counts, projection_manifest, identity)
    _require_part_row_count(first_runtime, first_counts, identity)
    relation = _inspect_projection_relation(
        transport,
        request,
        identity,
        ClickHouseReplacingMergeTreeLogicalProjectionSource(
            database=identity.database,
            table=identity.table,
        ),
    )
    fingerprint = _read_valid_fingerprint(transport, relation, request)
    if fingerprint.fingerprint.count != first_counts.logical_row_count:
        raise ClickHouseDataValidationError(
            "ClickHouse Replacing projection count differs from its canonical logical "
            "fingerprint: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"logical_rows={first_counts.logical_row_count}, "
            f"fingerprint_rows={fingerprint.fingerprint.count}"
        )
    _require_no_replacing_ambiguity(
        transport,
        identity,
        projection_manifest,
        request,
    )
    second_counts = _read_replacing_row_counts(transport, identity, request)
    second_mutations = _read_mutation_witness(transport, identity, request)
    pending = _classify_mutation_witness(
        second_mutations,
        identity,
        request.version_request,
    )
    if pending is not None:
        return pending
    second_runtime = _read_runtime_witness(transport, identity, request)
    _require_ready_runtime(second_runtime, identity)
    _require_part_row_count(second_runtime, second_counts, identity)
    if (
        second_counts != first_counts
        or second_mutations != first_mutations
        or second_runtime != first_runtime
    ):
        return _cut_mismatch_outcome(
            request.version_request,
            "ClickHouse Replacing projection state changed during acquisition",
        )
    named_confirmation = confirm_clickhouse_named_version(transport, named_version)
    if isinstance(named_confirmation, EarlyExecutionOutcome):
        return named_confirmation
    return ClickHouseReplacingMergeTreeProjectionBinding(
        strategy=_REPLACING_PROJECTION_STRATEGY,
        request=request,
        named_version=named_version,
        projection_manifest=projection_manifest,
        relation=relation,
        mutation_witness=second_mutations,
        runtime_witness=second_runtime,
        row_counts=second_counts,
        logical_fingerprint=fingerprint,
        stable_read_evidence=manifest.immutability_evidence,
        tie_freedom_evidence=ConsistencyLevel.ASSERTED,
        overall_evidence=ConsistencyLevel.ASSERTED,
        opened_at=datetime.now(UTC),
        limitations=_REPLACING_LIMITATIONS,
    )


def confirm_clickhouse_replacing_merge_tree_projection(
    transport: ClickHouseTransport,
    binding: ClickHouseReplacingMergeTreeProjectionBinding,
) -> ClickHouseReplacingMergeTreeProjectionConfirmation | EarlyExecutionOutcome:
    _require_transport(transport)
    if type(binding) is not ClickHouseReplacingMergeTreeProjectionBinding:
        raise TypeError("binding must be ClickHouseReplacingMergeTreeProjectionBinding")
    transport.require_attempt(
        binding.named_version.attempt_id,
        "confirm_clickhouse_replacing_merge_tree_projection",
    )
    request = binding.request
    identity = binding.named_version.version_identity
    first_mutations = _read_mutation_witness(transport, identity, request)
    pending = _classify_mutation_witness(
        first_mutations,
        identity,
        binding.named_version.request,
    )
    if pending is not None:
        return _cut_mismatch_outcome(
            binding.named_version.request,
            "ClickHouse Replacing projection gained an unfinished mutation",
        )
    first_runtime = _read_runtime_witness(transport, identity, request)
    _require_ready_runtime(first_runtime, identity)
    _require_no_replacing_ambiguity(
        transport,
        identity,
        binding.projection_manifest,
        request,
    )
    first_counts = _read_replacing_row_counts(transport, identity, request)
    fingerprint = _read_valid_fingerprint(transport, binding.relation, request)
    _require_no_replacing_ambiguity(
        transport,
        identity,
        binding.projection_manifest,
        request,
    )
    second_counts = _read_replacing_row_counts(transport, identity, request)
    second_mutations = _read_mutation_witness(transport, identity, request)
    second_runtime = _read_runtime_witness(transport, identity, request)
    _require_ready_runtime(second_runtime, identity)
    _require_part_row_count(first_runtime, first_counts, identity)
    _require_part_row_count(second_runtime, second_counts, identity)
    if (
        first_mutations != binding.mutation_witness
        or second_mutations != first_mutations
        or first_runtime != binding.runtime_witness
        or second_runtime != first_runtime
        or first_counts != binding.row_counts
        or second_counts != first_counts
        or fingerprint != binding.logical_fingerprint
    ):
        return _cut_mismatch_outcome(
            binding.named_version.request,
            "ClickHouse Replacing logical projection differs from the bound context",
        )
    named_confirmation = confirm_clickhouse_named_version(
        transport,
        binding.named_version,
    )
    if isinstance(named_confirmation, EarlyExecutionOutcome):
        return named_confirmation
    return ClickHouseReplacingMergeTreeProjectionConfirmation(
        binding=binding,
        named_version_confirmation=named_confirmation,
        final_mutation_witness=second_mutations,
        final_runtime_witness=second_runtime,
        final_row_counts=second_counts,
        final_logical_fingerprint=fingerprint,
        confirmed_at=datetime.now(UTC),
    )


def _read_mutation_witness(
    transport: ClickHouseTransport,
    identity: ClickHouseTableIdentity,
    request: ClickHouseProjectionRequest,
) -> ClickHouseMutationWitness:
    result_limit = request.max_mutation_records + 1
    result = transport.execute_raw(
        query=(
            "SELECT toString(serverUUID()) AS server_uuid, mutation_id, "
            "lower(hex(SHA256(command))) AS command_sha256, "
            "toString(toUnixTimestamp(create_time)) AS create_time_epoch, "
            "toString(parts_to_do) AS parts_to_do, "
            "toString(length(parts_in_progress_names)) AS parts_in_progress, "
            "toString(is_done) AS is_done, toString(is_killed) AS is_killed, "
            "toString(toUInt8(notEmpty(latest_failed_part))) AS has_failed_part, "
            "if(empty(latest_fail_reason), '', "
            "lower(hex(SHA256(latest_fail_reason)))) AS failure_reason_sha256, "
            "latest_fail_error_code_name AS failure_error_code_name "
            "FROM system.mutations WHERE database = {database:String} "
            "AND table = {table:String} ORDER BY mutation_id "
            "LIMIT {result_limit:UInt64}"
        ),
        parameters={
            "database": identity.database,
            "table": identity.table,
            "result_limit": result_limit,
        },
        settings=_projection_query_settings(request, result_limit),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_logical_projection_mutations",
    )
    payloads = parse_clickhouse_json_rows(
        result.payload,
        _MutationPayload,
        "logical projection mutation catalog",
    )
    if len(payloads) > request.max_mutation_records:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse mutation inventory exceeds its explicit record bound: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"maximum={request.max_mutation_records}"
        )
    records: list[ClickHouseMutationRecord] = []
    for payload in payloads:
        _require_matching_server_uuid(
            payload.server_uuid,
            identity.server_uuid,
            "mutation catalog",
        )
        records.append(
            ClickHouseMutationRecord(
                mutation_id=payload.mutation_id,
                command_sha256=payload.command_sha256,
                create_time_epoch=_parse_unsigned(
                    payload.create_time_epoch,
                    "mutation create time",
                ),
                parts_to_do=_parse_unsigned(payload.parts_to_do, "mutation parts to do"),
                parts_in_progress=_parse_unsigned(
                    payload.parts_in_progress,
                    "mutation parts in progress",
                ),
                is_done=_parse_flag(payload.is_done, "mutation is_done"),
                is_killed=_parse_flag(payload.is_killed, "mutation is_killed"),
                has_failed_part=_parse_flag(
                    payload.has_failed_part,
                    "mutation failed-part flag",
                ),
                failure_reason_sha256=payload.failure_reason_sha256,
                failure_error_code_name=payload.failure_error_code_name,
            )
        )
    return ClickHouseMutationWitness(records=tuple(records))


def _classify_mutation_witness(
    witness: ClickHouseMutationWitness,
    identity: ClickHouseTableIdentity,
    request: ClickHouseImmutableVersionRequest,
) -> EarlyExecutionOutcome | None:
    for record in witness.records:
        has_failure = (
            record.has_failed_part
            or bool(record.failure_reason_sha256)
            or bool(record.failure_error_code_name)
        )
        if record.is_killed:
            raise ClickHouseMutationFailureError(
                "ClickHouse logical projection has a killed mutation: "
                f"database={identity.database!r}, table={identity.table!r}, "
                f"mutation_id={record.mutation_id!r}, "
                "error_code='MUTATION_KILLED'"
            )
        if has_failure:
            if not record.failure_error_code_name:
                raise ClickHouseDataValidationError(
                    "ClickHouse failed mutation lacks a safe native error-code name: "
                    f"database={identity.database!r}, table={identity.table!r}, "
                    f"mutation_id={record.mutation_id!r}"
                )
            raise ClickHouseMutationFailureError(
                "ClickHouse logical projection has a failed mutation: "
                f"database={identity.database!r}, table={identity.table!r}, "
                f"mutation_id={record.mutation_id!r}, "
                f"error_code={record.failure_error_code_name!r}"
            )
    if any(not record.is_done for record in witness.records):
        return _not_ready_outcome(
            request,
            "ClickHouse logical projection has an unfinished mutation",
        )
    return None


def _read_runtime_witness(
    transport: ClickHouseTransport,
    identity: ClickHouseTableIdentity,
    request: ClickHouseProjectionRequest,
) -> ClickHouseProjectionRuntimeWitness:
    runtime_result = transport.execute_raw(
        query=(
            "SELECT toString(serverUUID()) AS server_uuid, "
            "toString(toUInt8(getSetting('final'))) AS final_setting, "
            "toString(toUInt8(getSetting('apply_mutations_on_fly'))) "
            "AS apply_mutations_on_fly, "
            "toString(toUInt8(getSetting('apply_patch_parts'))) AS apply_patch_parts, "
            "toString(toUInt8(getSetting("
            "'do_not_merge_across_partitions_select_final'))) "
            "AS merge_across_partitions_final, "
            "toString((SELECT count() FROM system.projections "
            "WHERE database = {database:String} AND table = {table:String})) "
            "AS projection_count"
        ),
        parameters={"database": identity.database, "table": identity.table},
        settings=_projection_query_settings(request, 1),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_logical_projection_runtime",
    )
    runtime_rows = parse_clickhouse_json_rows(
        runtime_result.payload,
        _RuntimePayload,
        "logical projection runtime",
    )
    if len(runtime_rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse projection runtime inspection must return exactly one row: "
            f"actual={len(runtime_rows)}"
        )
    runtime = runtime_rows[0]
    _require_matching_server_uuid(
        runtime.server_uuid,
        identity.server_uuid,
        "projection runtime",
    )
    part_result = transport.execute_raw(
        query=(
            "SELECT toString(serverUUID()) AS server_uuid, "
            "toString(countIf(active)) AS active_part_count, "
            "toString(sumIf(rows, active)) AS active_row_count, "
            "toString(countIf(active AND has_lightweight_delete != 0)) "
            "AS lightweight_delete_part_count, "
            "toString(countIf(active AND startsWith(partition_id, 'patch-'))) "
            "AS patch_part_count FROM system.parts "
            "WHERE database = {database:String} AND table = {table:String}"
        ),
        parameters={"database": identity.database, "table": identity.table},
        settings=_projection_query_settings(request, 1),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_logical_projection_parts",
    )
    part_rows = parse_clickhouse_json_rows(
        part_result.payload,
        _PartPayload,
        "logical projection active parts",
    )
    if len(part_rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse active-part inspection must return exactly one row: "
            f"actual={len(part_rows)}"
        )
    parts = part_rows[0]
    _require_matching_server_uuid(
        parts.server_uuid,
        identity.server_uuid,
        "projection active parts",
    )
    return ClickHouseProjectionRuntimeWitness(
        server_uuid=identity.server_uuid,
        final_setting=_parse_unsigned(runtime.final_setting, "runtime final setting"),
        apply_mutations_on_fly=_parse_unsigned(
            runtime.apply_mutations_on_fly,
            "runtime apply_mutations_on_fly setting",
        ),
        apply_patch_parts=_parse_unsigned(
            runtime.apply_patch_parts,
            "runtime apply_patch_parts setting",
        ),
        merge_across_partitions_final=_parse_unsigned(
            runtime.merge_across_partitions_final,
            "runtime FINAL partition setting",
        ),
        projection_count=_parse_unsigned(
            runtime.projection_count,
            "runtime projection count",
        ),
        active_part_count=_parse_unsigned(
            parts.active_part_count,
            "runtime active part count",
        ),
        active_row_count=_parse_unsigned(
            parts.active_row_count,
            "runtime active row count",
        ),
        lightweight_delete_part_count=_parse_unsigned(
            parts.lightweight_delete_part_count,
            "runtime lightweight-delete part count",
        ),
        patch_part_count=_parse_unsigned(
            parts.patch_part_count,
            "runtime patch part count",
        ),
    )


def _require_ready_runtime(
    witness: ClickHouseProjectionRuntimeWitness,
    identity: ClickHouseTableIdentity,
) -> None:
    if witness.server_uuid != identity.server_uuid:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse projection runtime must remain on the bound server: "
            f"expected_server_uuid={str(identity.server_uuid)!r}, "
            f"observed_server_uuid={str(witness.server_uuid)!r}"
        )
    if (
        witness.final_setting
        or witness.apply_mutations_on_fly
        or witness.apply_patch_parts
        or witness.merge_across_partitions_final
    ):
        raise UnsupportedClickHouseProfileError(
            "ClickHouse logical projection requires final=0, "
            "apply_mutations_on_fly=0, apply_patch_parts=0, and "
            "do_not_merge_across_partitions_select_final=0: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"final={witness.final_setting}, "
            f"apply_mutations_on_fly={witness.apply_mutations_on_fly}, "
            f"apply_patch_parts={witness.apply_patch_parts}, "
            "do_not_merge_across_partitions_select_final="
            f"{witness.merge_across_partitions_final}"
        )
    if witness.projection_count:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse logical projection does not support table projections: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"projection_count={witness.projection_count}"
        )
    if witness.lightweight_delete_part_count or witness.patch_part_count:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse logical projection does not support active lightweight-delete "
            "or patch parts: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"lightweight_delete_parts={witness.lightweight_delete_part_count}, "
            f"patch_parts={witness.patch_part_count}"
        )


def _require_no_replacing_ambiguity(
    transport: ClickHouseTransport,
    identity: ClickHouseTableIdentity,
    manifest: ClickHouseReplacingProjectionManifest,
    request: ClickHouseProjectionRequest,
) -> None:
    key_sql = ", ".join(quote_clickhouse_identifier(name) for name in manifest.sorting_key)
    version_sql = quote_clickhouse_identifier(manifest.version_column)
    relation_sql = _identity_relation_sql(identity)
    result = transport.execute_raw(
        query=(
            "SELECT toString(serverUUID()) AS server_uuid, "
            "toString(count()) AS ambiguous_group_count FROM ("
            f"SELECT {key_sql}, {version_sql}, count() AS version_count, "
            f"max({version_sql}) OVER (PARTITION BY {key_sql}) AS max_version "
            f"FROM {relation_sql} GROUP BY {key_sql}, {version_sql}) "
            f"WHERE {version_sql} = max_version AND version_count > 1"
        ),
        parameters={},
        settings=_tie_query_settings(request),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_replacing_projection_version_ties",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _AmbiguityPayload,
        "Replacing projection version ambiguity",
    )
    if len(rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse Replacing ambiguity inspection must return exactly one row: "
            f"actual={len(rows)}"
        )
    _require_matching_server_uuid(
        rows[0].server_uuid,
        identity.server_uuid,
        "Replacing ambiguity inspection",
    )
    ambiguous_groups = _parse_unsigned(
        rows[0].ambiguous_group_count,
        "Replacing ambiguous group count",
    )
    if ambiguous_groups:
        raise ClickHouseReplacingVersionAmbiguityError(
            "ClickHouse Replacing projection has multiple observable rows at a key's "
            "maximum version: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"sorting_key={manifest.sorting_key!r}, "
            f"version_column={manifest.version_column!r}, "
            f"ambiguous_key_count={ambiguous_groups}"
        )


def _read_replacing_row_counts(
    transport: ClickHouseTransport,
    identity: ClickHouseTableIdentity,
    request: ClickHouseProjectionRequest,
) -> ClickHouseReplacingRowCounts:
    relation_sql = _identity_relation_sql(identity)
    result = transport.execute_raw(
        query=(
            "SELECT toString(serverUUID()) AS server_uuid, "
            f"toString((SELECT count() FROM {relation_sql})) AS physical_row_count, "
            f"toString((SELECT count() FROM {relation_sql} FINAL)) AS logical_row_count"
        ),
        parameters={},
        settings=_projection_query_settings(request, 1),
        result_format="JSONEachRow",
        max_response_bytes=request.version_request.limits.max_response_bytes,
        operation="inspect_replacing_projection_row_counts",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _RowCountPayload,
        "Replacing projection row counts",
    )
    if len(rows) != 1:
        raise ClickHouseDataValidationError(
            "ClickHouse Replacing row-count inspection must return exactly one row: "
            f"actual={len(rows)}"
        )
    _require_matching_server_uuid(
        rows[0].server_uuid,
        identity.server_uuid,
        "Replacing row-count inspection",
    )
    return ClickHouseReplacingRowCounts(
        physical_row_count=_parse_unsigned(
            rows[0].physical_row_count,
            "Replacing physical row count",
        ),
        logical_row_count=_parse_unsigned(
            rows[0].logical_row_count,
            "Replacing logical row count",
        ),
    )


def _inspect_projection_relation(
    transport: ClickHouseTransport,
    request: ClickHouseProjectionRequest,
    identity: ClickHouseTableIdentity,
    source: (
        ClickHouseMergeTreeLogicalProjectionSource
        | ClickHouseReplacingMergeTreeLogicalProjectionSource
    ),
) -> ClickHouseCanonicalRelation:
    direct = inspect_clickhouse_canonical_relation(
        transport=transport,
        database=identity.database,
        table=identity.table,
        schema=request.schema,
        column_names=request.column_names,
        max_response_bytes=request.canonical_limits.max_response_bytes,
        max_execution_time_seconds=request.canonical_limits.max_execution_time_seconds,
    )
    relation = replace(direct, source=source)
    _require_relation_matches_identity(relation, identity)
    return relation


def _read_valid_fingerprint(
    transport: ClickHouseTransport,
    relation: ClickHouseCanonicalRelation,
    request: ClickHouseProjectionRequest,
) -> ClickHouseCanonicalFingerprint:
    fingerprint = read_clickhouse_canonical_fingerprint(
        transport,
        relation,
        request.canonical_limits,
    )
    if fingerprint.invalid_row_count or fingerprint.oversized_row_count:
        raise ClickHouseDataValidationError(
            "ClickHouse logical projection contains rows outside its canonical contract: "
            f"database={relation.database!r}, table={relation.table!r}, "
            f"invalid_rows={fingerprint.invalid_row_count}, "
            f"oversized_rows={fingerprint.oversized_row_count}"
        )
    return fingerprint


def _require_relation_matches_identity(
    relation: ClickHouseCanonicalRelation,
    identity: ClickHouseTableIdentity,
) -> None:
    columns = {column.name: column for column in identity.columns}
    for binding in relation.bindings:
        column = columns.get(binding.column_name)
        if column is None or column.declared_type != binding.declared_type:
            raise ClickHouseDataValidationError(
                "ClickHouse canonical projection binding differs from its bound table "
                "identity: "
                f"database={identity.database!r}, table={identity.table!r}, "
                f"column={binding.column_name!r}"
            )


def _require_projection_manifest_closure(
    manifest: ClickHouseImmutableVersionManifest,
    projection: ClickHouseReplacingProjectionManifest,
    request: ClickHouseProjectionRequest,
) -> None:
    if (
        projection.issuer != manifest.issuer
        or projection.dataset_id != manifest.dataset_id
        or projection.expected_batch_id != manifest.expected_batch_id
        or projection.immutable_manifest_sha256 != manifest.artifact_sha256
        or projection.publication_revision != manifest.publication_revision
        or projection.version_locator != manifest.version_locator
        or projection.projected_columns != request.column_names
    ):
        raise ClickHouseProjectionManifestError(
            "ClickHouse projection manifest does not match the immutable publication, "
            "locator, or requested projected columns"
        )


def _require_replacing_profile(
    identity: ClickHouseTableIdentity,
    manifest: ClickHouseReplacingProjectionManifest,
) -> None:
    if identity.database_engine != "Atomic":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse Replacing projection requires an Atomic database: "
            f"database={identity.database!r}, "
            f"observed_engine={identity.database_engine!r}"
        )
    if identity.table_engine != "ReplacingMergeTree" or not identity.table_readonly:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse Replacing projection requires a sealed ReplacingMergeTree: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"observed_engine={identity.table_engine!r}, "
            f"table_readonly={identity.table_readonly!r}"
        )
    if identity.partition_key:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse Replacing projection currently requires an unpartitioned table: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"partition_key={identity.partition_key!r}"
        )
    expected_sorting_key = ", ".join(manifest.sorting_key)
    if identity.sorting_key != expected_sorting_key:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse Replacing projection sorting key differs from the loader "
            "declaration or uses an unsupported expression: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"expected={expected_sorting_key!r}, observed={identity.sorting_key!r}"
        )
    engine_match = _REPLACING_ENGINE.match(identity.engine_full)
    if engine_match is None or engine_match.group(1) != manifest.version_column:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse Replacing projection requires exact "
            "ReplacingMergeTree(simple_stored_version) engine syntax: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"version_column={manifest.version_column!r}"
        )
    if identity.definition_sha256 != manifest.definition_sha256:
        raise ClickHouseProjectionManifestError(
            "ClickHouse Replacing table definition differs from the loader projection "
            "manifest: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"expected_definition_sha256={manifest.definition_sha256!r}, "
            f"observed_definition_sha256={identity.definition_sha256!r}"
        )
    columns = {column.name: column for column in identity.columns}
    version = columns.get(manifest.version_column)
    if version is None or version.declared_type != "UInt64":
        raise UnsupportedClickHouseProfileError(
            "ClickHouse Replacing projection version column must be stored non-null "
            "UInt64: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"column={manifest.version_column!r}, "
            f"observed_type={(None if version is None else version.declared_type)!r}"
        )
    _require_ordinary_column(version, identity)
    for key_name in manifest.sorting_key:
        key = columns.get(key_name)
        if key is None or "Nullable(" in key.declared_type:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse Replacing projection sorting-key columns must be stored and "
                "non-null: "
                f"database={identity.database!r}, table={identity.table!r}, "
                f"column={key_name!r}, "
                f"observed_type={(None if key is None else key.declared_type)!r}"
            )
        _require_ordinary_column(key, identity)


def _require_requested_columns(
    identity: ClickHouseTableIdentity,
    column_names: tuple[str, ...],
) -> None:
    columns = {column.name: column for column in identity.columns}
    for column_name in column_names:
        column = columns.get(column_name)
        if column is None:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse logical projection requested a missing physical column: "
                f"database={identity.database!r}, table={identity.table!r}, "
                f"column={column_name!r}"
            )
        _require_ordinary_column(column, identity)


def _require_ordinary_column(
    column: ClickHouseColumnIdentity,
    identity: ClickHouseTableIdentity,
) -> None:
    if column.default_kind or column.default_expression:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse logical projection supports only ordinary stored columns: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"column={column.name!r}, default_kind={column.default_kind!r}"
        )


def _require_manifest_row_counts(
    counts: ClickHouseReplacingRowCounts,
    manifest: ClickHouseReplacingProjectionManifest,
    identity: ClickHouseTableIdentity,
) -> None:
    if (
        counts.physical_row_count != manifest.physical_row_count
        or counts.logical_row_count != manifest.logical_row_count
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse Replacing projection row counts differ from the loader audit: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"expected_physical={manifest.physical_row_count}, "
            f"observed_physical={counts.physical_row_count}, "
            f"expected_logical={manifest.logical_row_count}, "
            f"observed_logical={counts.logical_row_count}"
        )


def _require_part_row_count(
    runtime: ClickHouseProjectionRuntimeWitness,
    counts: ClickHouseReplacingRowCounts,
    identity: ClickHouseTableIdentity,
) -> None:
    if runtime.active_row_count != counts.physical_row_count:
        raise ClickHouseDataValidationError(
            "ClickHouse Replacing physical count differs from its active-part inventory: "
            f"database={identity.database!r}, table={identity.table!r}, "
            f"active_part_rows={runtime.active_row_count}, "
            f"physical_rows={counts.physical_row_count}"
        )


def _projection_query_settings(
    request: ClickHouseProjectionRequest,
    max_result_rows: int,
) -> dict[str, ClickHouseParameter]:
    return {
        "session_timezone": "UTC",
        "max_execution_time": request.version_request.limits.max_execution_time_seconds,
        "timeout_overflow_mode": "throw",
        "timeout_overflow_mode_leaf": "throw",
        "read_overflow_mode": "throw",
        "read_overflow_mode_leaf": "throw",
        "max_result_rows": max_result_rows,
        "max_result_bytes": request.version_request.limits.max_response_bytes,
        "result_overflow_mode": "throw",
        "sort_overflow_mode": "throw",
        "final": 0,
        "apply_mutations_on_fly": 0,
        "apply_patch_parts": 0,
        "do_not_merge_across_partitions_select_final": 0,
    }


def _tie_query_settings(
    request: ClickHouseProjectionRequest,
) -> dict[str, ClickHouseParameter]:
    return {
        **_projection_query_settings(request, 1),
        "max_rows_to_group_by": request.max_tie_groups,
        "group_by_overflow_mode": "throw",
    }


def _identity_relation_sql(identity: ClickHouseTableIdentity) -> str:
    return (
        f"{quote_clickhouse_identifier(identity.database)}."
        f"{quote_clickhouse_identifier(identity.table)}"
    )


def _unsupported_projection_evidence_outcome(
    request: ClickHouseImmutableVersionRequest,
) -> EarlyExecutionOutcome:
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.ERROR,
        reason=ResultReason(
            code=ReasonCode.UNSUPPORTED_CAPABILITY,
            operation="acquire_clickhouse_logical_projection",
            message=(
                "asserted ClickHouse logical-projection evidence cannot satisfy a "
                "verified minimum evidence policy"
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
            operation="validate_clickhouse_logical_projection",
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
            operation="confirm_clickhouse_logical_projection",
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


def _require_projection_witnesses(
    mutations: ClickHouseMutationWitness,
    runtime: ClickHouseProjectionRuntimeWitness,
    fingerprint: ClickHouseCanonicalFingerprint,
) -> None:
    if type(mutations) is not ClickHouseMutationWitness:
        raise TypeError("mutation_witness must be ClickHouseMutationWitness")
    if type(runtime) is not ClickHouseProjectionRuntimeWitness:
        raise TypeError("runtime_witness must be ClickHouseProjectionRuntimeWitness")
    if type(fingerprint) is not ClickHouseCanonicalFingerprint:
        raise TypeError("logical_fingerprint must be ClickHouseCanonicalFingerprint")
    if fingerprint.invalid_row_count or fingerprint.oversized_row_count:
        raise ValueError("bound ClickHouse projection fingerprint contains invalid rows")


def _require_ready_mutation_witness(witness: ClickHouseMutationWitness) -> None:
    for record in witness.records:
        if (
            not record.is_done
            or record.is_killed
            or record.has_failed_part
            or bool(record.failure_reason_sha256)
            or bool(record.failure_error_code_name)
        ):
            raise ValueError(
                "bound ClickHouse projection mutation witness must contain only "
                "completed successful mutations"
            )


def _require_projection_relation_contract(
    request: ClickHouseProjectionRequest,
    identity: ClickHouseTableIdentity,
    relation: ClickHouseCanonicalRelation,
) -> None:
    if identity.database != relation.database or identity.table != relation.table:
        raise ValueError(
            "ClickHouse projection relation does not match its physical table identity"
        )
    if relation.schema != request.schema:
        raise ValueError("ClickHouse projection relation schema differs from its request")
    bound_columns = tuple(binding.column_name for binding in relation.bindings)
    if bound_columns != request.column_names:
        raise ValueError("ClickHouse projection relation columns differ from its request")
    _require_requested_columns(identity, request.column_names)
    _require_relation_matches_identity(relation, identity)


def _require_relation(value: object) -> None:
    if type(value) is not ClickHouseCanonicalRelation:
        raise TypeError("relation must be ClickHouseCanonicalRelation")


def _require_request(value: object) -> None:
    if type(value) is not ClickHouseProjectionRequest:
        raise TypeError("request must be ClickHouseProjectionRequest")


def _require_transport(value: object) -> None:
    if not isinstance(value, ClickHouseTransport):
        raise TypeError("transport must be ClickHouseTransport")


def _require_matching_server_uuid(
    observed_value: str,
    expected_server_uuid: UUID,
    operation: str,
) -> None:
    observed = _parse_uuid(observed_value, f"{operation} server UUID")
    if observed != expected_server_uuid:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse projection queries must remain pinned to one server: "
            f"operation={operation!r}, expected_server_uuid={str(expected_server_uuid)!r}, "
            f"observed_server_uuid={str(observed)!r}"
        )


def _require_identifier_tuple(value: tuple[str, ...], label: str) -> None:
    if type(value) is not tuple or not value:
        raise ValueError(f"ClickHouse {label}s must be a nonempty immutable tuple")
    if len(frozenset(value)) != len(value):
        raise ValueError(f"ClickHouse {label}s must be unique")
    for name in value:
        _require_simple_identifier(name, label)


def _require_simple_identifier(value: object, label: str) -> None:
    if type(value) is not str or _SIMPLE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"ClickHouse {label} must be a simple unquoted ASCII identifier")
    validate_clickhouse_identifier(value, f"ClickHouse {label}")


def _parse_flag(value: str, label: str) -> bool:
    if value == "0":
        return False
    if value == "1":
        return True
    raise ClickHouseDataValidationError(f"ClickHouse {label} must be the canonical integer 0 or 1")


def _parse_unsigned(value: str, label: str) -> int:
    if _UNSIGNED_INTEGER.fullmatch(value) is None:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be a canonical unsigned decimal integer"
        )
    return int(value)


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


def _require_positive_integer(value: int, label: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"ClickHouse {label} must be a positive exact integer")


def _require_nonnegative_integer(value: int, label: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"ClickHouse {label} must be a non-negative exact integer")


def _require_sha256(value: str, label: str) -> None:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise ValueError(f"ClickHouse {label} must be a lowercase SHA-256 digest")


def _require_bounded_text(value: str, label: str) -> None:
    validate_clickhouse_text_scalar(value, f"ClickHouse {label}")
    if len(value.encode("utf-8")) > 512:
        raise ValueError(f"ClickHouse {label} exceeds 512 UTF-8 bytes")


def _require_optional_bounded_text(value: str, label: str) -> None:
    if type(value) is not str:
        raise TypeError(f"ClickHouse {label} must be text")
    if not value:
        return
    _require_bounded_text(value, label)


def _require_utc_datetime(value: datetime, label: str) -> None:
    if type(value) is not datetime:
        raise TypeError(f"ClickHouse {label} must be an exact datetime")
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None:
        raise ValueError(f"ClickHouse {label} must use UTC")
    if offset.total_seconds() != 0:
        raise ValueError(f"ClickHouse {label} must use UTC")
