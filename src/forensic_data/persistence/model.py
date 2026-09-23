import hashlib
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import cast, final
from uuid import UUID

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    LogicalType,
    Normalization,
    schema_digest_hex,
    schema_from_metadata_json,
)
from forensic_data.contracts.identity import sql_parameters_semantic_value
from forensic_data.contracts.model import (
    Adapter,
    AssurancePolicy,
    FieldEquality,
    LateArrivalPolicy,
    MinimumEvidence,
    NullPartitionPolicy,
    RelationScope,
    ScopeOperator,
    SqlDialect,
    SqlParameterDefinition,
    StableReadKind,
)
from forensic_data.contracts.semantics import (
    SEMANTIC_DIGEST_PROTOCOL,
    SemanticValue,
    canonical_semantic_json,
    semantic_value_from_json,
)

_SQL_ARTIFACT_KIND = "sql"
_SQL_CAPTURE_DISABLED = "sql_capture_disabled"
_FIELD_EQUALITY_VALUES = frozenset(value.value for value in FieldEquality)
_LATE_ARRIVAL_VALUES = frozenset(value.value for value in LateArrivalPolicy)
_LOGICAL_TYPE_VALUES = frozenset(value.value for value in LogicalType)
_MINIMUM_EVIDENCE_VALUES = frozenset(value.value for value in MinimumEvidence)
_NORMALIZATION_VALUES = frozenset(value.value for value in Normalization)
_NULL_PARTITION_VALUES = frozenset(value.value for value in NullPartitionPolicy)
_SCOPE_OPERATOR_VALUES = frozenset(value.value for value in ScopeOperator)
_STABLE_READ_VALUES = frozenset(value.value for value in StableReadKind)


class ArtifactPurpose(StrEnum):
    PROJECTION = "projection"
    READINESS = "readiness"


class ArtifactDirection(StrEnum):
    REFERENCE = "reference"
    TARGET = "target"


class CodeCaptureState(StrEnum):
    RETAINED = "retained"
    NOT_RETAINED = "not_retained"


class DatasetLocatorKind(StrEnum):
    RELATION = "relation"
    SQL = "sql"


@final
@dataclass(frozen=True, slots=True)
class _SqlArtifactIdentity:
    content_sha256: str
    dialect: str
    parameters_json: str


@final
@dataclass(frozen=True, slots=True)
class _ArtifactExpectation:
    direction: ArtifactDirection
    purpose: ArtifactPurpose
    dataset_id: str
    identity: _SqlArtifactIdentity


@final
@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    checksum_sha256: str
    sql_bytes: bytes = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        _require_positive_integer(self.version, "migration version")
        _require_nonblank_text(self.name, "migration name")
        _require_sha256(self.checksum_sha256, "migration checksum")
        if type(self.sql_bytes) is not bytes or not self.sql_bytes:
            raise ValueError("migration SQL must be nonempty bytes")
        if b"\r" in self.sql_bytes:
            raise ValueError("migration SQL must use LF line endings")
        try:
            sql_text = self.sql_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError("migration SQL must be strict UTF-8") from None
        if sql_text.strip() == "":
            raise ValueError("migration SQL must contain a nonblank statement")
        actual_checksum = hashlib.sha256(self.sql_bytes).hexdigest()
        if actual_checksum != self.checksum_sha256:
            raise ValueError(
                "migration checksum does not match the exact packaged SQL bytes: "
                f"version={self.version}, expected={self.checksum_sha256!r}, "
                f"actual={actual_checksum!r}"
            )


@final
@dataclass(frozen=True, slots=True)
class MigrationReport:
    applied_versions: tuple[int, ...]
    current_version: int

    def __post_init__(self) -> None:
        _require_integer_tuple(self.applied_versions, "applied migration versions")
        if tuple(sorted(set(self.applied_versions))) != self.applied_versions:
            raise ValueError("applied migration versions must be unique and increasing")
        if any(version < 1 for version in self.applied_versions):
            raise ValueError("applied migration versions must be positive")
        _require_nonnegative_integer(self.current_version, "current migration version")
        if self.applied_versions and self.applied_versions[-1] > self.current_version:
            raise ValueError("applied migration version cannot exceed current version")


@final
@dataclass(frozen=True, slots=True)
class CodeArtifactCaptureDefinition:
    direction: ArtifactDirection
    purpose: ArtifactPurpose
    dataset_id: str
    check_id: str
    revision: int
    dialect: SqlDialect
    parameters: tuple[SqlParameterDefinition, ...]
    content_sha256: str
    source_byte_length: int
    capture_state: CodeCaptureState
    content_bytes: bytes | None = dataclass_field(repr=False)
    omission_reason: str | None

    def __post_init__(self) -> None:
        _require_enum(self.direction, ArtifactDirection, "artifact direction")
        _require_enum(self.purpose, ArtifactPurpose, "artifact purpose")
        _require_nonblank_text(self.dataset_id, "artifact dataset id")
        _require_nonblank_text(self.check_id, "artifact check id")
        _require_positive_integer(self.revision, "artifact check revision")
        _require_enum(self.dialect, SqlDialect, "artifact dialect")
        _require_parameters(self.parameters)
        _require_sha256(self.content_sha256, "artifact content digest")
        _require_positive_integer(self.source_byte_length, "artifact source byte length")
        _require_enum(self.capture_state, CodeCaptureState, "artifact capture state")
        if self.capture_state is CodeCaptureState.RETAINED:
            self._validate_retained_content()
            return
        if self.content_bytes is not None:
            raise ValueError("not-retained code artifact cannot contain retained bytes")
        if self.omission_reason != _SQL_CAPTURE_DISABLED:
            raise ValueError(
                "not-retained code artifact requires omission_reason='sql_capture_disabled'"
            )

    def _validate_retained_content(self) -> None:
        if type(self.content_bytes) is not bytes:
            raise ValueError("retained code artifact requires exact bytes")
        if len(self.content_bytes) != self.source_byte_length:
            raise ValueError("retained code artifact byte length does not match source_byte_length")
        if hashlib.sha256(self.content_bytes).hexdigest() != self.content_sha256:
            raise ValueError("retained code artifact bytes do not match content_sha256")
        if self.omission_reason is not None:
            raise ValueError("retained code artifact cannot have an omission reason")


type CodeArtifactRegistration = CodeArtifactCaptureDefinition


@final
@dataclass(frozen=True, slots=True)
class DatasetVersionDefinition:
    dataset_id: str
    semantic_digest: str
    semantic_protocol: str
    canonical_protocol: str
    logical_schema_digest: str
    connection_id: str
    adapter: Adapter
    driver: str
    profile: str
    locator_kind: DatasetLocatorKind
    relation_scope: RelationScope | None
    semantic_payload_json: str = dataclass_field(repr=False)
    resolved_definition_json: str = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        _require_nonblank_text(self.dataset_id, "dataset id")
        _require_sha256(self.semantic_digest, "dataset semantic digest")
        _require_protocols(self.semantic_protocol, self.canonical_protocol)
        _require_sha256(self.logical_schema_digest, "dataset logical schema digest")
        _require_nonblank_text(self.connection_id, "dataset connection id")
        if self.adapter is not Adapter.POSTGRESQL:
            raise ValueError("initial metadata persistence supports only PostgreSQL datasets")
        _require_nonblank_text(self.driver, "dataset driver")
        _require_nonblank_text(self.profile, "dataset profile")
        _require_enum(self.locator_kind, DatasetLocatorKind, "dataset locator kind")
        if self.locator_kind is DatasetLocatorKind.RELATION:
            _require_enum(self.relation_scope, RelationScope, "dataset relation scope")
            if self.relation_scope not in (
                RelationScope.PHYSICAL_ONLY,
                RelationScope.FROZEN_PHYSICAL_UNION,
            ):
                raise ValueError(
                    "relation dataset requires physical_only or frozen_physical_union relation scope"
                )
        elif self.relation_scope is not None:
            raise ValueError("SQL dataset cannot have a relation scope")
        _require_canonical_object_json(self.semantic_payload_json, "dataset semantic payload")
        _require_digest_matches_json(
            self.semantic_digest,
            self.semantic_payload_json,
            "dataset semantic payload",
        )
        _require_canonical_object_json(
            self.resolved_definition_json,
            "dataset resolved definition",
        )
        _require_dataset_payload_closure(self)


@final
@dataclass(frozen=True, slots=True)
class ContractVersionDefinition:
    check_id: str
    revision: int
    config_version: int
    semantic_digest: str
    semantic_protocol: str
    canonical_protocol: str
    comparison_schema_digest: str
    reference_dataset_id: str
    reference_dataset_digest: str
    target_dataset_id: str
    target_dataset_digest: str
    assurance_policy: AssurancePolicy
    semantic_payload_json: str = dataclass_field(repr=False)
    resolved_definition_json: str = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        _require_nonblank_text(self.check_id, "contract check id")
        _require_positive_integer(self.revision, "contract revision")
        if type(self.config_version) is not int or self.config_version != 1:
            raise ValueError("contract config version must be exactly 1")
        _require_sha256(self.semantic_digest, "contract semantic digest")
        _require_protocols(self.semantic_protocol, self.canonical_protocol)
        _require_sha256(self.comparison_schema_digest, "contract comparison schema digest")
        _require_nonblank_text(self.reference_dataset_id, "reference dataset id")
        _require_sha256(self.reference_dataset_digest, "reference dataset digest")
        _require_nonblank_text(self.target_dataset_id, "target dataset id")
        _require_sha256(self.target_dataset_digest, "target dataset digest")
        if self.reference_dataset_id == self.target_dataset_id:
            raise ValueError("contract reference and target datasets must differ")
        _require_enum(self.assurance_policy, AssurancePolicy, "contract assurance policy")
        _require_canonical_object_json(self.semantic_payload_json, "contract semantic payload")
        _require_digest_matches_json(
            self.semantic_digest,
            self.semantic_payload_json,
            "contract semantic payload",
        )
        _require_canonical_object_json(
            self.resolved_definition_json,
            "contract resolved definition",
        )
        _require_contract_payload_closure(self)


@final
@dataclass(frozen=True, slots=True)
class MetadataRegistrationDefinition:
    reference_dataset: DatasetVersionDefinition
    target_dataset: DatasetVersionDefinition
    contract: ContractVersionDefinition
    code_artifacts: tuple[CodeArtifactCaptureDefinition, ...]

    def __post_init__(self) -> None:
        _require_instance(
            self.reference_dataset,
            DatasetVersionDefinition,
            "reference dataset definition",
        )
        _require_instance(
            self.target_dataset,
            DatasetVersionDefinition,
            "target dataset definition",
        )
        _require_instance(self.contract, ContractVersionDefinition, "contract definition")
        _require_artifact_definitions(self.code_artifacts)
        _require_contract_dataset_closure(
            self.contract,
            self.reference_dataset,
            self.target_dataset,
        )
        _require_artifact_closure(self)


@final
@dataclass(frozen=True, slots=True)
class DatasetVersionRecord:
    dataset_version_id: UUID
    definition: DatasetVersionDefinition
    created_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.dataset_version_id, "dataset version id")
        _require_instance(self.definition, DatasetVersionDefinition, "dataset version definition")
        _require_utc_datetime(self.created_at, "dataset version created_at")


@final
@dataclass(frozen=True, slots=True)
class ContractVersionRecord:
    contract_version_id: UUID
    definition: ContractVersionDefinition
    reference_dataset_version_id: UUID
    target_dataset_version_id: UUID
    created_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.contract_version_id, "contract version id")
        _require_instance(self.definition, ContractVersionDefinition, "contract definition")
        _require_uuid(self.reference_dataset_version_id, "reference dataset version id")
        _require_uuid(self.target_dataset_version_id, "target dataset version id")
        if self.reference_dataset_version_id == self.target_dataset_version_id:
            raise ValueError("contract dataset version ids must differ")
        _require_utc_datetime(self.created_at, "contract version created_at")


@final
@dataclass(frozen=True, slots=True)
class CodeArtifactRecord:
    code_artifact_id: UUID
    definition: CodeArtifactCaptureDefinition
    created_at: datetime

    def __post_init__(self) -> None:
        _require_uuid(self.code_artifact_id, "code artifact id")
        _require_instance(
            self.definition,
            CodeArtifactCaptureDefinition,
            "code artifact definition",
        )
        _require_utc_datetime(self.created_at, "code artifact created_at")


@final
@dataclass(frozen=True, slots=True)
class MetadataRegistration:
    reference_dataset: DatasetVersionRecord
    target_dataset: DatasetVersionRecord
    contract: ContractVersionRecord
    code_artifacts: tuple[CodeArtifactRecord, ...]

    def __post_init__(self) -> None:
        _require_instance(self.reference_dataset, DatasetVersionRecord, "reference dataset record")
        _require_instance(self.target_dataset, DatasetVersionRecord, "target dataset record")
        _require_instance(self.contract, ContractVersionRecord, "contract record")
        if type(self.code_artifacts) is not tuple:
            raise ValueError("code artifact records must be an immutable tuple")
        for index, artifact in enumerate(self.code_artifacts):
            _require_instance(artifact, CodeArtifactRecord, f"code artifact record {index}")
        identifiers = tuple(artifact.code_artifact_id for artifact in self.code_artifacts)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("code artifact record ids must be unique")
        MetadataRegistrationDefinition(
            reference_dataset=self.reference_dataset.definition,
            target_dataset=self.target_dataset.definition,
            contract=self.contract.definition,
            code_artifacts=tuple(artifact.definition for artifact in self.code_artifacts),
        )
        if self.contract.reference_dataset_version_id != self.reference_dataset.dataset_version_id:
            raise ValueError("contract record references a different reference dataset version")
        if self.contract.target_dataset_version_id != self.target_dataset.dataset_version_id:
            raise ValueError("contract record references a different target dataset version")


def code_artifact_kind() -> str:
    return _SQL_ARTIFACT_KIND


def sql_capture_disabled_reason() -> str:
    return _SQL_CAPTURE_DISABLED


def _require_contract_dataset_closure(
    contract: ContractVersionDefinition,
    reference: DatasetVersionDefinition,
    target: DatasetVersionDefinition,
) -> None:
    if (
        contract.reference_dataset_id != reference.dataset_id
        or contract.reference_dataset_digest != reference.semantic_digest
    ):
        raise ValueError("contract reference dataset identity is outside registration closure")
    if (
        contract.target_dataset_id != target.dataset_id
        or contract.target_dataset_digest != target.semantic_digest
    ):
        raise ValueError("contract target dataset identity is outside registration closure")
    contract_reference, contract_target = _contract_direction_bodies(contract)
    reference_body = _dataset_semantic_body(reference)
    target_body = _dataset_semantic_body(target)
    _require_semantic_match(
        contract_reference,
        reference_body,
        "contract reference definition and registered dataset payload",
    )
    _require_semantic_match(
        contract_target,
        target_body,
        "contract target definition and registered dataset payload",
    )
    contract_resolved = _semantic_object_from_json(
        contract.resolved_definition_json,
        "contract resolved definition",
    )
    reference_resolved = _semantic_object_from_json(
        reference.resolved_definition_json,
        "reference dataset resolved definition",
    )
    target_resolved = _semantic_object_from_json(
        target.resolved_definition_json,
        "target dataset resolved definition",
    )
    _require_semantic_match(
        contract_resolved["comparison_schema"],
        reference_resolved["logical_schema"],
        "contract comparison schema and reference resolved logical schema",
    )
    _require_semantic_match(
        contract_resolved["comparison_schema"],
        target_resolved["logical_schema"],
        "contract comparison schema and target resolved logical schema",
    )


def _require_artifact_closure(registration: MetadataRegistrationDefinition) -> None:
    expected: list[_ArtifactExpectation] = []
    for direction, dataset in (
        (ArtifactDirection.REFERENCE, registration.reference_dataset),
        (ArtifactDirection.TARGET, registration.target_dataset),
    ):
        identity = _dataset_projection_identity(dataset)
        if identity is not None:
            expected.append(
                _ArtifactExpectation(
                    direction=direction,
                    purpose=ArtifactPurpose.PROJECTION,
                    dataset_id=dataset.dataset_id,
                    identity=identity,
                )
            )
    reference_readiness, target_readiness = _contract_readiness_identities(registration.contract)
    for direction, dataset, identity in (
        (
            ArtifactDirection.REFERENCE,
            registration.reference_dataset,
            reference_readiness,
        ),
        (
            ArtifactDirection.TARGET,
            registration.target_dataset,
            target_readiness,
        ),
    ):
        if identity is not None:
            expected.append(
                _ArtifactExpectation(
                    direction,
                    ArtifactPurpose.READINESS,
                    dataset.dataset_id,
                    identity,
                )
            )
    actual_uses = tuple(
        (artifact.direction, artifact.purpose, artifact.dataset_id)
        for artifact in registration.code_artifacts
    )
    expected_uses = tuple((item.direction, item.purpose, item.dataset_id) for item in expected)
    if actual_uses != expected_uses:
        raise ValueError(
            "code artifacts must contain the ordered projection/readiness closure for the contract"
        )
    for artifact, expectation in zip(
        registration.code_artifacts,
        expected,
        strict=True,
    ):
        if (
            artifact.check_id != registration.contract.check_id
            or artifact.revision != registration.contract.revision
        ):
            raise ValueError("code artifact provenance does not match contract identity")
        _require_capture_identity(
            artifact,
            expectation.identity,
            f"{expectation.direction.value} {expectation.purpose.value} code artifact",
        )


def _require_dataset_payload_closure(definition: DatasetVersionDefinition) -> None:
    payload = _semantic_object_from_json(
        definition.semantic_payload_json,
        "dataset semantic payload",
    )
    _require_exact_semantic_keys(
        payload,
        ("canonical_protocol", "dataset", "semantic_protocol"),
        "dataset semantic payload",
    )
    _require_semantic_match(
        payload["canonical_protocol"],
        definition.canonical_protocol,
        "dataset canonical protocol column and semantic payload",
    )
    _require_semantic_match(
        payload["semantic_protocol"],
        definition.semantic_protocol,
        "dataset semantic protocol column and semantic payload",
    )
    body = _semantic_object(payload["dataset"], "dataset semantic payload dataset")
    resolved_schema = _require_dataset_resolved_definition(definition, payload)
    _require_dataset_body_shape(
        body,
        "dataset semantic payload dataset",
        resolved_schema,
    )
    _require_semantic_match(
        body["dataset_id"],
        definition.dataset_id,
        "dataset id column and semantic payload",
    )
    connection = _semantic_object(
        body["connection"],
        "dataset semantic payload connection",
    )
    for key, expected in (
        ("adapter", definition.adapter.value),
        ("connection_id", definition.connection_id),
        ("driver", definition.driver),
        ("profile", definition.profile),
    ):
        _require_semantic_match(
            connection[key],
            expected,
            f"dataset {key} column and semantic payload",
        )
    logical_schema = _semantic_object(
        body["logical_schema"],
        "dataset semantic payload logical schema",
    )
    _require_semantic_match(
        logical_schema["logical_schema_digest"],
        definition.logical_schema_digest,
        "dataset logical schema digest column and semantic payload",
    )
    locator = _semantic_object(body["locator"], "dataset semantic payload locator")
    locator_kind = _semantic_text(locator["kind"], "dataset semantic payload locator kind")
    if locator_kind != definition.locator_kind.value:
        raise ValueError("dataset locator kind column does not match semantic payload")
    if definition.locator_kind is DatasetLocatorKind.RELATION:
        _require_relation_locator(locator, definition.relation_scope)
    else:
        _sql_artifact_identity(locator, "dataset projection locator")


def _require_contract_payload_closure(definition: ContractVersionDefinition) -> None:
    payload = _semantic_object_from_json(
        definition.semantic_payload_json,
        "contract semantic payload",
    )
    _require_exact_semantic_keys(
        payload,
        (
            "assurance_policy",
            "canonical_protocol",
            "config_version",
            "consistency",
            "direction",
            "invariant",
            "key",
            "logical_schema",
            "scope",
            "semantic_protocol",
        ),
        "contract semantic payload",
    )
    for key, expected in (
        ("assurance_policy", definition.assurance_policy.value),
        ("canonical_protocol", definition.canonical_protocol),
        ("config_version", definition.config_version),
        ("invariant", "row_equivalence"),
        ("semantic_protocol", definition.semantic_protocol),
    ):
        _require_semantic_match(
            payload[key],
            expected,
            f"contract {key} column and semantic payload",
        )
    comparison_schema = _require_contract_resolved_definition(definition, payload)
    logical_schema = _semantic_object(
        payload["logical_schema"],
        "contract semantic payload logical schema",
    )
    _require_logical_schema_semantics(
        logical_schema,
        "contract semantic payload logical schema",
        comparison_schema,
    )
    _require_semantic_match(
        logical_schema["logical_schema_digest"],
        definition.comparison_schema_digest,
        "contract comparison schema digest column and semantic payload",
    )
    key = _require_nonnullable_field_names(
        payload["key"],
        "contract semantic payload key",
        comparison_schema,
    )
    _require_scope_semantics(
        payload["scope"],
        definition.reference_dataset_id,
        definition.target_dataset_id,
    )
    reference, target = _contract_direction_bodies(definition)
    reference_grain = _require_contract_dataset_identity(
        reference,
        definition.reference_dataset_id,
        definition.reference_dataset_digest,
        definition,
        "reference",
        comparison_schema,
    )
    target_grain = _require_contract_dataset_identity(
        target,
        definition.target_dataset_id,
        definition.target_dataset_digest,
        definition,
        "target",
        comparison_schema,
    )
    if key != reference_grain or key != target_grain:
        raise ValueError("contract key must equal both dataset grains")
    _contract_readiness_identities(definition)


def _require_dataset_resolved_definition(
    definition: DatasetVersionDefinition,
    semantic_payload: dict[str, SemanticValue],
) -> CanonicalSchema:
    resolved = _semantic_object_from_json(
        definition.resolved_definition_json,
        "dataset resolved definition",
    )
    _require_exact_semantic_keys(
        resolved,
        ("definition_version", "kind", "logical_schema", "semantic_payload"),
        "dataset resolved definition",
    )
    _require_semantic_match(
        resolved["definition_version"],
        1,
        "dataset resolved definition version",
    )
    _require_semantic_match(resolved["kind"], "dataset", "dataset resolved definition kind")
    _require_semantic_match(
        resolved["semantic_payload"],
        semantic_payload,
        "dataset semantic and resolved payload",
    )
    return _require_resolved_schema_digest(
        resolved["logical_schema"],
        definition.logical_schema_digest,
        "dataset resolved logical schema",
    )


def _require_contract_resolved_definition(
    definition: ContractVersionDefinition,
    semantic_payload: dict[str, SemanticValue],
) -> CanonicalSchema:
    resolved = _semantic_object_from_json(
        definition.resolved_definition_json,
        "contract resolved definition",
    )
    _require_exact_semantic_keys(
        resolved,
        (
            "check_id",
            "comparison_schema",
            "definition_version",
            "kind",
            "revision",
            "semantic_payload",
        ),
        "contract resolved definition",
    )
    for key, expected in (
        ("check_id", definition.check_id),
        ("definition_version", 1),
        ("kind", "row_contract"),
        ("revision", definition.revision),
    ):
        _require_semantic_match(
            resolved[key],
            expected,
            f"contract resolved definition {key}",
        )
    _require_semantic_match(
        resolved["semantic_payload"],
        semantic_payload,
        "contract semantic and resolved payload",
    )
    return _require_resolved_schema_digest(
        resolved["comparison_schema"],
        definition.comparison_schema_digest,
        "contract resolved comparison schema",
    )


def _require_resolved_schema_digest(
    value: SemanticValue,
    expected_digest: str,
    context: str,
) -> CanonicalSchema:
    metadata_json = canonical_semantic_json(value)
    schema = schema_from_metadata_json(metadata_json)
    if schema_digest_hex(schema) != expected_digest:
        raise ValueError(f"{context} does not match its declared schema digest")
    return schema


def _require_contract_dataset_identity(
    body: dict[str, SemanticValue],
    expected_dataset_id: str,
    expected_digest: str,
    contract: ContractVersionDefinition,
    direction: str,
    comparison_schema: CanonicalSchema,
) -> tuple[str, ...]:
    grain = _require_dataset_body_shape(
        body,
        f"contract {direction} dataset",
        comparison_schema,
    )
    _require_semantic_match(
        body["dataset_id"],
        expected_dataset_id,
        f"contract {direction} dataset id column and semantic payload",
    )
    contract_payload = _semantic_object_from_json(
        contract.semantic_payload_json,
        "contract semantic payload",
    )
    _require_semantic_match(
        body["logical_schema"],
        contract_payload["logical_schema"],
        f"contract {direction} and comparison logical schema",
    )
    dataset_payload: SemanticValue = {
        "canonical_protocol": contract.canonical_protocol,
        "dataset": body,
        "semantic_protocol": contract.semantic_protocol,
    }
    actual_digest = hashlib.sha256(
        canonical_semantic_json(dataset_payload).encode("utf-8")
    ).hexdigest()
    if actual_digest != expected_digest:
        raise ValueError(
            f"contract {direction} dataset digest column does not match semantic payload"
        )
    return grain


def _require_dataset_body_shape(
    body: dict[str, SemanticValue],
    context: str,
    resolved_schema: CanonicalSchema,
) -> tuple[str, ...]:
    _require_exact_semantic_keys(
        body,
        ("connection", "dataset_id", "grain", "locator", "logical_schema", "projection"),
        context,
    )
    connection = _semantic_object(body["connection"], f"{context} connection")
    _require_exact_semantic_keys(
        connection,
        ("adapter", "connection_id", "driver", "profile"),
        f"{context} connection",
    )
    _require_semantic_match(
        connection["adapter"],
        Adapter.POSTGRESQL.value,
        f"{context} connection adapter",
    )
    for key in ("connection_id", "driver", "profile"):
        _semantic_text(connection[key], f"{context} connection {key}")
    _semantic_text(body["dataset_id"], f"{context} dataset id")
    grain = _require_nonnullable_field_names(
        body["grain"],
        f"{context} grain",
        resolved_schema,
    )
    _require_projection_semantics(
        body["projection"],
        f"{context} projection",
        resolved_schema,
    )
    logical_schema_value = _semantic_object(
        body["logical_schema"],
        f"{context} logical schema",
    )
    _require_logical_schema_semantics(
        logical_schema_value,
        f"{context} logical schema",
        resolved_schema,
    )
    digest = _semantic_text(
        logical_schema_value["logical_schema_digest"],
        f"{context} logical schema digest",
    )
    _require_sha256(digest, f"{context} logical schema digest")
    locator = _semantic_object(body["locator"], f"{context} locator")
    locator_kind = _semantic_text(locator.get("kind"), f"{context} locator kind")
    if locator_kind == DatasetLocatorKind.RELATION.value:
        _require_dataset_relation_locator(locator, f"{context} locator")
    elif locator_kind == DatasetLocatorKind.SQL.value:
        _sql_artifact_identity(locator, f"{context} locator")
    else:
        raise ValueError(f"{context} locator kind is unsupported")
    return grain


def _require_nonnullable_field_names(
    value: SemanticValue,
    context: str,
    schema: CanonicalSchema,
) -> tuple[str, ...]:
    names = _require_unique_nonempty_text_array(value, context)
    fields = {field.name: field for field in schema.fields}
    for name in names:
        field = fields.get(name)
        if field is None:
            raise ValueError(f"{context} references unknown field {name!r}")
        if field.nullable:
            raise ValueError(f"{context} field {name!r} must be non-nullable")
    return names


def _require_projection_semantics(
    value: SemanticValue,
    context: str,
    schema: CanonicalSchema,
) -> None:
    projection = _semantic_array(value, context)
    field_names: list[str] = []
    for index, item in enumerate(projection):
        item_context = f"{context} item {index}"
        projected = _semantic_object(item, item_context)
        _require_exact_semantic_keys(projected, ("column", "field"), item_context)
        _semantic_nonempty_text(projected["column"], f"{item_context} column")
        field_names.append(_semantic_text(projected["field"], f"{item_context} field"))
    expected = tuple(field.name for field in schema.fields)
    if tuple(field_names) != expected:
        raise ValueError(f"{context} must cover resolved schema fields exactly once and in order")


def _require_logical_schema_semantics(
    value: dict[str, SemanticValue],
    context: str,
    schema: CanonicalSchema,
) -> None:
    _require_exact_semantic_keys(
        value,
        ("equality", "logical_schema_digest"),
        context,
    )
    equality = _semantic_array(value["equality"], f"{context} equality")
    if len(equality) != len(schema.fields):
        raise ValueError(f"{context} equality count must equal resolved schema field count")
    for index, item in enumerate(equality):
        _require_supported_text(
            item,
            _FIELD_EQUALITY_VALUES,
            f"{context} equality item {index}",
        )
    digest = _semantic_text(value["logical_schema_digest"], f"{context} digest")
    _require_sha256(digest, f"{context} digest")


def _require_scope_semantics(
    value: SemanticValue,
    reference_dataset_id: str,
    target_dataset_id: str,
) -> None:
    context = "contract semantic payload scope"
    scope = _semantic_object(value, context)
    _require_exact_semantic_keys(
        scope,
        ("bindings", "null_partition", "parameters"),
        context,
    )
    _require_supported_text(
        scope["null_partition"],
        _NULL_PARTITION_VALUES,
        f"{context} null partition",
    )
    parameters = _semantic_array(scope["parameters"], f"{context} parameters")
    if len(parameters) > 1:
        raise ValueError(f"{context} supports at most one parameter")
    parameter_names: list[str] = []
    for index, item in enumerate(parameters):
        item_context = f"{context} parameter {index}"
        parameter = _semantic_object(item, item_context)
        _require_exact_semantic_keys(parameter, ("name", "type"), item_context)
        name = _semantic_text(parameter["name"], f"{item_context} name")
        if name in parameter_names:
            raise ValueError(f"{context} contains duplicate parameter name {name!r}")
        parameter_names.append(name)
        _require_field_type_semantics(parameter["type"], f"{item_context} type")
    bindings = _semantic_array(scope["bindings"], f"{context} bindings")
    if not parameter_names:
        if bindings:
            raise ValueError(f"{context} without parameters cannot contain bindings")
        return
    dataset_ids: list[str] = []
    for index, item in enumerate(bindings):
        item_context = f"{context} binding {index}"
        binding = _semantic_object(item, item_context)
        _require_exact_semantic_keys(
            binding,
            ("column", "dataset_id", "operator", "parameter"),
            item_context,
        )
        dataset_ids.append(_semantic_text(binding["dataset_id"], f"{item_context} dataset id"))
        _semantic_nonempty_text(binding["column"], f"{item_context} column")
        _require_supported_text(
            binding["operator"],
            _SCOPE_OPERATOR_VALUES,
            f"{item_context} operator",
        )
        parameter_name = _semantic_text(binding["parameter"], f"{item_context} parameter")
        if parameter_name not in parameter_names:
            raise ValueError(
                f"{item_context} references unknown scope parameter {parameter_name!r}"
            )
    if tuple(dataset_ids) != (reference_dataset_id, target_dataset_id):
        raise ValueError(f"{context} bindings must be ordered reference then target datasets")


def _require_field_type_semantics(value: SemanticValue, context: str) -> None:
    field_type = _semantic_object(value, context)
    _require_exact_semantic_keys(
        field_type,
        ("kind", "normalization", "parameters"),
        context,
    )
    kind = _require_supported_text(field_type["kind"], _LOGICAL_TYPE_VALUES, f"{context} kind")
    _require_supported_text(
        field_type["normalization"],
        _NORMALIZATION_VALUES,
        f"{context} normalization",
    )
    parameters = _semantic_object(field_type["parameters"], f"{context} parameters")
    if kind == LogicalType.DECIMAL.value:
        _require_exact_semantic_keys(
            parameters,
            ("precision", "scale"),
            f"{context} parameters",
        )
        precision = _semantic_integer(parameters["precision"], f"{context} precision")
        scale = _semantic_integer(parameters["scale"], f"{context} scale")
        if not 1 <= precision <= 38 or not 0 <= scale <= precision:
            raise ValueError(f"{context} has invalid decimal precision or scale")
        return
    if kind in (LogicalType.TIMESTAMP_LOCAL.value, LogicalType.TIMESTAMP_INSTANT.value):
        _require_exact_semantic_keys(parameters, ("precision",), f"{context} parameters")
        precision = _semantic_integer(parameters["precision"], f"{context} precision")
        if not 0 <= precision <= 9:
            raise ValueError(f"{context} timestamp precision must be in the range 0..9")
        return
    _require_exact_semantic_keys(parameters, (), f"{context} parameters")


def _require_sql_parameters(value: SemanticValue, context: str) -> list[SemanticValue]:
    parameters = _semantic_array(value, context)
    names: set[str] = set()
    for index, item in enumerate(parameters):
        item_context = f"{context} item {index}"
        parameter = _semantic_object(item, item_context)
        _require_exact_semantic_keys(parameter, ("name", "type"), item_context)
        name = _semantic_text(parameter["name"], f"{item_context} name")
        if name in names:
            raise ValueError(f"{context} contains duplicate parameter name {name!r}")
        names.add(name)
        _require_field_type_semantics(parameter["type"], f"{item_context} type")
    return parameters


def _require_unique_nonempty_text_array(
    value: SemanticValue,
    context: str,
) -> tuple[str, ...]:
    values = _semantic_array(value, context)
    if not values:
        raise ValueError(f"{context} must not be empty")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        text = _semantic_text(item, f"{context} item {index}")
        if text in seen:
            raise ValueError(f"{context} contains duplicate value {text!r}")
        result.append(text)
        seen.add(text)
    return tuple(result)


def _require_relation_locator(
    locator: dict[str, SemanticValue],
    relation_scope: RelationScope | None,
) -> None:
    _require_exact_semantic_keys(
        locator,
        ("catalog", "kind", "name", "relation_scope", "schema"),
        "relation locator",
    )
    _require_semantic_match(locator["kind"], "relation", "relation locator kind")
    if relation_scope is None:
        raise ValueError("relation locator requires a relation scope")
    _require_semantic_match(
        locator["relation_scope"],
        relation_scope.value,
        "relation scope column and semantic payload",
    )
    catalog = locator["catalog"]
    if catalog is not None:
        raise ValueError("PostgreSQL relation locator catalog must be null")
    _semantic_nonempty_text(locator["schema"], "relation locator schema")
    _semantic_nonempty_text(locator["name"], "relation locator name")


def _require_dataset_relation_locator(
    locator: dict[str, SemanticValue],
    context: str,
) -> None:
    relation_scope_text = _semantic_text(
        locator.get("relation_scope"),
        f"{context} relation scope",
    )
    try:
        relation_scope = RelationScope(relation_scope_text)
    except ValueError:
        raise ValueError(
            f"{context} relation scope is unsupported: relation_scope={relation_scope_text!r}"
        ) from None
    if relation_scope not in (
        RelationScope.PHYSICAL_ONLY,
        RelationScope.FROZEN_PHYSICAL_UNION,
    ):
        raise ValueError(
            f"{context} relation scope is unsupported: relation_scope={relation_scope_text!r}"
        )
    _require_relation_locator(locator, relation_scope)


def _contract_direction_bodies(
    contract: ContractVersionDefinition,
) -> tuple[dict[str, SemanticValue], dict[str, SemanticValue]]:
    payload = _semantic_object_from_json(
        contract.semantic_payload_json,
        "contract semantic payload",
    )
    direction = _semantic_object(payload["direction"], "contract semantic payload direction")
    _require_exact_semantic_keys(
        direction,
        ("reference", "target"),
        "contract semantic payload direction",
    )
    return (
        _semantic_object(direction["reference"], "contract reference dataset"),
        _semantic_object(direction["target"], "contract target dataset"),
    )


def _dataset_semantic_body(
    dataset: DatasetVersionDefinition,
) -> dict[str, SemanticValue]:
    payload = _semantic_object_from_json(
        dataset.semantic_payload_json,
        "dataset semantic payload",
    )
    return _semantic_object(payload["dataset"], "dataset semantic payload dataset")


def _dataset_projection_identity(
    dataset: DatasetVersionDefinition,
) -> _SqlArtifactIdentity | None:
    locator = _semantic_object(
        _dataset_semantic_body(dataset)["locator"],
        "dataset projection locator",
    )
    if dataset.locator_kind is DatasetLocatorKind.RELATION:
        return None
    return _sql_artifact_identity(locator, "dataset projection locator")


def _contract_readiness_identities(
    contract: ContractVersionDefinition,
) -> tuple[_SqlArtifactIdentity | None, _SqlArtifactIdentity | None]:
    payload = _semantic_object_from_json(
        contract.semantic_payload_json,
        "contract semantic payload",
    )
    consistency = _semantic_object(
        payload["consistency"],
        "contract semantic payload consistency",
    )
    _require_exact_semantic_keys(
        consistency,
        ("alignment_fields", "datasets", "late_arrivals", "minimum_evidence"),
        "contract semantic payload consistency",
    )
    _require_unique_nonempty_text_array(
        consistency["alignment_fields"],
        "contract semantic payload consistency alignment fields",
    )
    _require_supported_text(
        consistency["late_arrivals"],
        _LATE_ARRIVAL_VALUES,
        "contract semantic payload consistency late arrivals",
    )
    _require_supported_text(
        consistency["minimum_evidence"],
        _MINIMUM_EVIDENCE_VALUES,
        "contract semantic payload consistency minimum evidence",
    )
    datasets = _semantic_array(
        consistency["datasets"],
        "contract semantic payload consistency datasets",
    )
    if len(datasets) != 2:
        raise ValueError("contract consistency must contain reference and target datasets")
    direction_bodies = _contract_direction_bodies(contract)
    expected_connections = tuple(
        _semantic_text(
            _semantic_object(body["connection"], f"contract {direction} connection")[
                "connection_id"
            ],
            f"contract {direction} connection id",
        )
        for direction, body in zip(
            ("reference", "target"),
            direction_bodies,
            strict=True,
        )
    )
    identities: list[_SqlArtifactIdentity | None] = []
    for index, (value, expected_dataset_id, expected_connection_id) in enumerate(
        zip(
            datasets,
            (contract.reference_dataset_id, contract.target_dataset_id),
            expected_connections,
            strict=True,
        )
    ):
        context = f"contract consistency dataset {index}"
        dataset = _semantic_object(value, context)
        _require_exact_semantic_keys(
            dataset,
            ("dataset_id", "readiness", "stable_read"),
            context,
        )
        _require_semantic_match(
            dataset["dataset_id"],
            expected_dataset_id,
            f"{context} identity and contract dataset column",
        )
        _require_supported_text(
            dataset["stable_read"],
            _STABLE_READ_VALUES,
            f"{context} stable read",
        )
        readiness = _semantic_object(dataset["readiness"], f"{context} readiness")
        identities.append(
            _readiness_artifact_identity(
                readiness,
                expected_connection_id,
                f"{context} readiness",
            )
        )
    return identities[0], identities[1]


def _readiness_artifact_identity(
    readiness: dict[str, SemanticValue],
    expected_connection_id: str,
    context: str,
) -> _SqlArtifactIdentity | None:
    kind = _semantic_text(readiness.get("kind"), f"{context} kind")
    if kind == _SQL_ARTIFACT_KIND:
        return _sql_artifact_identity(readiness, context)
    if kind != "relation_manifest":
        raise ValueError(f"{context} kind is unsupported")
    _require_exact_semantic_keys(
        readiness,
        ("columns", "connection_id", "kind", "relation"),
        context,
    )
    _require_semantic_match(
        readiness["connection_id"],
        expected_connection_id,
        f"{context} connection and dataset connection",
    )
    relation = _semantic_object(readiness["relation"], f"{context} relation")
    _require_relation_locator(relation, RelationScope.PHYSICAL_ONLY)
    columns = _semantic_object(readiness["columns"], f"{context} columns")
    expected_columns = (
        "batch_id",
        "business_date",
        "completed_at",
        "dataset_id",
        "dataset_version",
        "scope_digest",
        "source_cut",
        "state",
    )
    _require_exact_semantic_keys(columns, expected_columns, f"{context} columns")
    resolved_columns = tuple(
        _semantic_nonempty_text(columns[name], f"{context} {name} column")
        for name in expected_columns
    )
    if len(set(resolved_columns)) != len(resolved_columns):
        raise ValueError(f"{context} columns must reference distinct physical columns")
    return None


def _sql_artifact_identity(
    locator: dict[str, SemanticValue],
    context: str,
) -> _SqlArtifactIdentity:
    _require_exact_semantic_keys(
        locator,
        ("content_sha256", "dialect", "kind", "parameters"),
        context,
    )
    _require_semantic_match(locator["kind"], "sql", f"{context} kind")
    content_sha256 = _semantic_text(locator["content_sha256"], f"{context} digest")
    _require_sha256(content_sha256, f"{context} digest")
    dialect = _semantic_text(locator["dialect"], f"{context} dialect")
    if dialect != SqlDialect.POSTGRESQL.value:
        raise ValueError(f"{context} dialect must be PostgreSQL")
    parameters = _require_sql_parameters(locator["parameters"], f"{context} parameters")
    return _SqlArtifactIdentity(
        content_sha256=content_sha256,
        dialect=dialect,
        parameters_json=canonical_semantic_json(parameters),
    )


def _require_capture_identity(
    capture: CodeArtifactCaptureDefinition,
    expected: _SqlArtifactIdentity,
    context: str,
) -> None:
    if capture.content_sha256 != expected.content_sha256:
        raise ValueError(f"{context} digest does not match its contract artifact reference")
    if capture.dialect.value != expected.dialect:
        raise ValueError(f"{context} dialect does not match its contract artifact reference")
    parameters_json = canonical_semantic_json(sql_parameters_semantic_value(capture.parameters))
    if parameters_json != expected.parameters_json:
        raise ValueError(
            f"{context} ordered parameters do not match its contract artifact reference"
        )


def _require_artifact_definitions(value: object) -> None:
    if type(value) is not tuple:
        raise ValueError("code artifact definitions must be an immutable tuple")
    values = cast(tuple[object, ...], value)
    for index, artifact in enumerate(values):
        _require_instance(
            artifact,
            CodeArtifactCaptureDefinition,
            f"code artifact definition {index}",
        )


def _require_parameters(value: object) -> None:
    if type(value) is not tuple:
        raise ValueError("code artifact parameters must be an immutable tuple")
    names: list[str] = []
    values = cast(tuple[object, ...], value)
    for index, item in enumerate(values):
        parameter = _require_instance(
            item,
            SqlParameterDefinition,
            f"code artifact parameter {index}",
        )
        names.append(parameter.name)
    if len(set(names)) != len(names):
        raise ValueError("code artifact parameter names must be unique")


def _require_protocols(semantic_protocol: object, canonical_protocol: object) -> None:
    if semantic_protocol != SEMANTIC_DIGEST_PROTOCOL:
        raise ValueError(f"semantic protocol must be exactly {SEMANTIC_DIGEST_PROTOCOL!r}")
    if canonical_protocol != PROTOCOL:
        raise ValueError(f"canonical protocol must be exactly {PROTOCOL!r}")


def _require_digest_matches_json(digest: str, payload_json: str, context: str) -> None:
    actual = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    if actual != digest:
        raise ValueError(f"{context} digest mismatch: expected={digest!r}, actual={actual!r}")


def _require_canonical_object_json(value: object, context: str) -> None:
    if type(value) is not str:
        raise ValueError(f"{context} must be canonical JSON text")
    parsed = semantic_value_from_json(value)
    if type(parsed) is not dict:
        raise ValueError(f"{context} must contain a JSON object")
    if canonical_semantic_json(parsed) != value:
        raise ValueError(f"{context} must use canonical semantic JSON encoding")


def _semantic_object_from_json(
    value: str,
    context: str,
) -> dict[str, SemanticValue]:
    return _semantic_object(semantic_value_from_json(value), context)


def _semantic_object(
    value: SemanticValue,
    context: str,
) -> dict[str, SemanticValue]:
    if type(value) is not dict:
        raise ValueError(f"{context} must be an object")
    return cast(dict[str, SemanticValue], value)


def _semantic_array(
    value: SemanticValue,
    context: str,
) -> list[SemanticValue]:
    if type(value) is not list:
        raise ValueError(f"{context} must be an array")
    return cast(list[SemanticValue], value)


def _semantic_text(value: SemanticValue, context: str) -> str:
    if type(value) is not str or value.strip() == "":
        raise ValueError(f"{context} must be nonblank text")
    return value


def _semantic_nonempty_text(value: SemanticValue, context: str) -> str:
    if type(value) is not str or value == "":
        raise ValueError(f"{context} must be nonempty text")
    return value


def _semantic_integer(value: SemanticValue, context: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{context} must be an exact integer")
    return value


def _require_supported_text(
    value: SemanticValue,
    supported: frozenset[str],
    context: str,
) -> str:
    text = _semantic_text(value, context)
    if text not in supported:
        raise ValueError(f"{context} has unsupported value {text!r}")
    return text


def _require_exact_semantic_keys(
    value: dict[str, SemanticValue],
    expected: tuple[str, ...],
    context: str,
) -> None:
    expected_keys = frozenset(expected)
    actual_keys = frozenset(value)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise ValueError(
            f"{context} keys do not match the persistence protocol: "
            f"missing={missing!r}, extra={extra!r}"
        )


def _require_semantic_match(
    actual: SemanticValue,
    expected: SemanticValue,
    context: str,
) -> None:
    if canonical_semantic_json(actual) != canonical_semantic_json(expected):
        raise ValueError(f"{context} do not match")


def _require_sha256(value: object, context: str) -> None:
    if type(value) is not str or len(value) != 64:
        raise ValueError(f"{context} must be 64 lowercase hexadecimal digits")
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{context} must be 64 lowercase hexadecimal digits")


def _require_nonblank_text(value: object, context: str) -> None:
    if type(value) is not str or value.strip() == "":
        raise ValueError(f"{context} must be nonblank text")
    for index, character in enumerate(value):
        code_point = ord(character)
        if code_point == 0 or 0xD800 <= code_point <= 0xDFFF:
            raise ValueError(f"{context} contains an invalid character at index {index}")


def _require_positive_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"{context} must be a positive integer")


def _require_nonnegative_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{context} must be a non-negative integer")


def _require_integer_tuple(value: object, context: str) -> None:
    if type(value) is not tuple:
        raise ValueError(f"{context} must be an immutable tuple of exact integers")
    values = cast(tuple[object, ...], value)
    if any(type(item) is not int for item in values):
        raise ValueError(f"{context} must be an immutable tuple of exact integers")


def _require_uuid(value: object, context: str) -> None:
    if not isinstance(value, UUID) or value.version != 4:
        raise ValueError(f"{context} must be a UUID4 value")


def _require_utc_datetime(value: object, context: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{context} must be a timezone-aware datetime")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{context} must use UTC")


def _require_enum[EnumT](value: object, enum_type: type[EnumT], context: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{context} must be a {enum_type.__name__}")


def _require_instance[ValueT](value: object, expected: type[ValueT], context: str) -> ValueT:
    if not isinstance(value, expected):
        raise ValueError(f"{context} must be a {expected.__name__}")
    return value
