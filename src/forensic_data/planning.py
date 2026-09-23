from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, Self, cast, final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from forensic_data.canonical import (
    PROTOCOL,
    DecimalParameters,
    FieldSchema,
    LogicalType,
    PayloadValidationError,
    TimestampParameters,
    encode_payload,
)
from forensic_data.contracts.errors import ContractReferenceError, ScopeValueError
from forensic_data.contracts.model import (
    Adapter,
    AssurancePolicy,
    DatasetDefinition,
    LoadedContractConfig,
    ReadinessDefinition,
    RelationLocator,
    RelationScope,
    RowCheckDefinition,
    SqlArtifactDefinition,
    SqlDialect,
    SqlParameterDefinition,
)
from forensic_data.contracts.semantics import (
    SEMANTIC_DIGEST_PROTOCOL,
    SemanticValue,
    semantic_digest_hex,
)

type ScopeInputValue = int | bool | str
type DigestHex = str
type PositiveInt = int


@final
@dataclass(frozen=True, slots=True)
class ResolvedScopeParameter:
    name: str
    field: FieldSchema
    value: ScopeInputValue
    canonical_payload: bytes

    def __post_init__(self) -> None:
        if type(self.name) is not str or self.name.strip() == "":
            raise ScopeValueError("resolved scope parameter name must be nonblank text")
        _require_planning_instance(
            self.field,
            FieldSchema,
            "resolved scope parameter field",
        )
        if self.field.name != self.name:
            raise ScopeValueError("resolved scope parameter name must equal its FieldSchema name")
        if self.field.nullable:
            raise ScopeValueError("resolved scope parameters must be non-nullable")
        if type(self.value) not in (bool, int, str):
            raise ScopeValueError(
                f"resolved scope parameter {self.name!r} requires an exact integer, "
                "boolean, or string"
            )
        if type(self.canonical_payload) is not bytes:
            raise ScopeValueError("resolved scope canonical payload must be bytes")
        try:
            expected_payload = encode_payload(self.field, self.value)
        except PayloadValidationError as error:
            raise ScopeValueError(
                f"resolved scope parameter {self.name!r} is invalid for logical type "
                f"{self.field.logical_type.value!r}: {error}"
            ) from None
        if self.canonical_payload != expected_payload:
            raise ScopeValueError(
                f"resolved scope parameter {self.name!r} canonical payload does not "
                "match its typed value"
            )


@final
@dataclass(frozen=True, slots=True)
class ResolvedScope:
    parameters: tuple[ResolvedScopeParameter, ...]
    scope_digest: str

    def __post_init__(self) -> None:
        if type(self.parameters) is not tuple:
            raise ScopeValueError("resolved scope parameters must be an immutable tuple")
        names: list[str] = []
        for index, parameter in enumerate(self.parameters):
            _require_planning_instance(
                parameter,
                ResolvedScopeParameter,
                f"resolved scope parameter at index {index}",
            )
            names.append(parameter.name)
        if len(set(names)) != len(names):
            raise ScopeValueError("resolved scope parameters must have unique names")
        if self.scope_digest != _resolved_scope_digest(self.parameters):
            raise ScopeValueError(
                "resolved scope digest does not match its canonical parameter values"
            )


class PlanProbeStatus(StrEnum):
    REQUIRED_NOT_RUN = "required_not_run"


class PlanStageStatus(StrEnum):
    PLANNED_NOT_RUN = "planned_not_run"


class EstimateStatus(StrEnum):
    UNKNOWN = "unknown"


class PlanDirection(StrEnum):
    REFERENCE = "reference"
    TARGET = "target"


class ArtifactPurpose(StrEnum):
    PROJECTION = "projection"
    READINESS = "readiness"


class _PlanModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    @field_validator("*", mode="after")
    @classmethod
    def validate_unicode_text(cls, value: object) -> object:
        _require_unicode_scalar_values(value)
        return value


class PlanLogicalType(_PlanModel):
    kind: str
    precision: int | None
    scale: int | None

    @model_validator(mode="after")
    def validate_type_parameters(self) -> Self:
        try:
            logical_type = LogicalType(self.kind)
        except ValueError:
            raise ValueError(f"unsupported plan logical type {self.kind!r}") from None
        if logical_type is LogicalType.DECIMAL:
            if (
                type(self.precision) is not int
                or not 1 <= self.precision <= 38
                or type(self.scale) is not int
                or not 0 <= self.scale <= self.precision
            ):
                raise ValueError(
                    "decimal plan type requires precision 1..38 and scale 0..precision"
                )
            return self
        if logical_type in (LogicalType.TIMESTAMP_LOCAL, LogicalType.TIMESTAMP_INSTANT):
            if (
                type(self.precision) is not int
                or not 0 <= self.precision <= 9
                or self.scale is not None
            ):
                raise ValueError("timestamp plan type requires precision 0..9 and no scale")
            return self
        if self.precision is not None or self.scale is not None:
            raise ValueError(f"plan logical type {self.kind!r} does not accept precision or scale")
        return self


class PlanParameter(_PlanModel):
    name: str
    type: PlanLogicalType


class PlanSqlReadiness(_PlanModel):
    kind: Literal["sql"]
    connection_id: str

    @model_validator(mode="after")
    def validate_connection(self) -> Self:
        if self.connection_id.strip() == "":
            raise ValueError("SQL readiness connection id must be nonblank")
        return self


class PlanReadinessManifestColumns(_PlanModel):
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: str
    source_cut: str
    dataset_version: str
    completed_at: str

    @model_validator(mode="after")
    def validate_columns(self) -> Self:
        values = (
            self.dataset_id,
            self.scope_digest,
            self.batch_id,
            self.state,
            self.business_date,
            self.source_cut,
            self.dataset_version,
            self.completed_at,
        )
        if any(value == "" for value in values) or len(set(values)) != len(values):
            raise ValueError(
                "relation manifest plan requires eight distinct nonempty column mappings"
            )
        return self


class PlanReadinessRelation(_PlanModel):
    catalog: str | None
    schema_name: str
    relation_name: str
    relation_scope: RelationScope

    @model_validator(mode="after")
    def validate_relation(self) -> Self:
        if self.catalog is not None:
            raise ValueError("PostgreSQL readiness plan relation catalog must be null")
        if self.schema_name == "" or self.relation_name == "":
            raise ValueError("readiness plan relation requires nonempty schema and name")
        if self.relation_scope is not RelationScope.PHYSICAL_ONLY:
            raise ValueError("readiness plan relation requires physical_only scope")
        return self


class PlanRelationManifestReadiness(_PlanModel):
    kind: Literal["relation_manifest"]
    connection_id: str
    relation: PlanReadinessRelation
    columns: PlanReadinessManifestColumns

    @model_validator(mode="after")
    def validate_connection(self) -> Self:
        if self.connection_id.strip() == "":
            raise ValueError("relation manifest readiness connection id must be nonblank")
        return self


type PlanReadiness = Annotated[
    PlanSqlReadiness | PlanRelationManifestReadiness,
    Field(discriminator="kind"),
]


class PlanDataset(_PlanModel):
    direction: PlanDirection
    dataset_id: str
    dataset_digest: DigestHex = Field(pattern=r"^[0-9a-f]{64}$")
    connection_id: str
    adapter: Adapter
    driver: str
    profile: str
    locator_kind: Literal["relation", "sql"]
    relation_scope: RelationScope | None
    readiness: PlanReadiness

    @model_validator(mode="after")
    def validate_locator_scope(self) -> Self:
        for value, context in (
            (self.dataset_id, "dataset id"),
            (self.connection_id, "connection id"),
            (self.driver, "connection driver"),
            (self.profile, "connection profile"),
        ):
            if value.strip() == "":
                raise ValueError(f"plan {context} must be nonblank")
        if self.locator_kind == "relation" and self.relation_scope not in (
            RelationScope.PHYSICAL_ONLY,
            RelationScope.FROZEN_PHYSICAL_UNION,
        ):
            raise ValueError(
                "relation plan dataset requires physical_only or frozen_physical_union scope"
            )
        if self.locator_kind == "sql" and self.relation_scope is not None:
            raise ValueError("SQL plan dataset cannot carry a relation scope")
        if self.readiness.connection_id != self.connection_id:
            raise ValueError("plan readiness must inherit its dataset connection")
        return self


class PlanArtifact(_PlanModel):
    purpose: ArtifactPurpose
    direction: PlanDirection
    dataset_id: str
    dialect: SqlDialect
    content_sha256: DigestHex = Field(pattern=r"^[0-9a-f]{64}$")
    parameters: tuple[PlanParameter, ...]

    @model_validator(mode="after")
    def validate_parameter_names(self) -> Self:
        if self.dataset_id.strip() == "":
            raise ValueError("plan artifact dataset id must be nonblank")
        names = tuple(parameter.name for parameter in self.parameters)
        if any(name.strip() == "" for name in names) or len(set(names)) != len(names):
            raise ValueError("plan artifact parameters require unique nonblank names")
        return self


class PlanProbe(_PlanModel):
    name: str
    status: PlanProbeStatus
    direction: PlanDirection
    dataset_id: str


class PlanStage(_PlanModel):
    name: str
    status: PlanStageStatus


class PlanEstimate(_PlanModel):
    name: str
    status: EstimateStatus
    unit: str


class PlanReport(_PlanModel):
    schema_version: Literal[1]
    config_version: Literal[1]
    semantic_digest_protocol: Literal["dfe_semantic_v1"]
    canonical_protocol: Literal["dfe_canon_v1"]
    check_id: str
    revision: PositiveInt = Field(ge=1)
    invariant: Literal["row_equivalence"]
    assurance_policy: AssurancePolicy
    logical_schema_digest: DigestHex = Field(pattern=r"^[0-9a-f]{64}$")
    contract_digest: DigestHex = Field(pattern=r"^[0-9a-f]{64}$")
    scope_digest: DigestHex = Field(pattern=r"^[0-9a-f]{64}$")
    reference: PlanDataset
    target: PlanDataset
    ordered_key: tuple[str, ...]
    artifacts: tuple[PlanArtifact, ...]
    probes: tuple[PlanProbe, ...]
    stages: tuple[PlanStage, ...]
    estimates: tuple[PlanEstimate, ...]
    limitations: tuple[str, ...]

    @field_validator("schema_version", "config_version", mode="before")
    @classmethod
    def validate_exact_versions(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("plan versions must be the exact integer 1")
        return value

    @model_validator(mode="after")
    def validate_plan_semantics(self) -> Self:
        if self.check_id.strip() == "":
            raise ValueError("plan check_id must be nonblank")
        if self.reference.direction is not PlanDirection.REFERENCE:
            raise ValueError("plan reference dataset direction must be reference")
        if self.target.direction is not PlanDirection.TARGET:
            raise ValueError("plan target dataset direction must be target")
        if self.reference.dataset_id == self.target.dataset_id:
            raise ValueError("plan reference and target datasets must differ")
        if not self.ordered_key or any(name.strip() == "" for name in self.ordered_key):
            raise ValueError("plan ordered key must contain nonblank fields")
        if len(set(self.ordered_key)) != len(self.ordered_key):
            raise ValueError("plan ordered key must not contain duplicates")
        _validate_plan_artifacts(self)
        _validate_plan_probes(self)
        expected_stages = _expected_stage_names(self.assurance_policy)
        if tuple(stage.name for stage in self.stages) != expected_stages:
            raise ValueError("plan stages do not match the requested assurance policy")
        expected_estimates = (
            ("reference_rows", "records"),
            ("target_rows", "records"),
            ("reference_bytes", "bytes"),
            ("target_bytes", "bytes"),
            ("queries", "queries"),
        )
        if (
            tuple((estimate.name, estimate.unit) for estimate in self.estimates)
            != expected_estimates
        ):
            raise ValueError("plan estimates must contain the version-1 unknown estimate set")
        if not self.limitations or any(value.strip() == "" for value in self.limitations):
            raise ValueError("plan limitations must contain nonblank disclosures")
        return self


def compile_static_plan(
    config: LoadedContractConfig,
    check_id: str,
    scope_values: Mapping[str, ScopeInputValue],
) -> PlanReport:
    check = _find_check(config, check_id)
    resolved_scope = resolve_scope_values(check, scope_values)
    reference_consistency, target_consistency = check.consistency.datasets
    if (
        reference_consistency.dataset_id != check.reference.dataset_id
        or target_consistency.dataset_id != check.target.dataset_id
    ):
        raise ValueError("check consistency readiness is outside the dataset direction closure")
    reference = _plan_dataset(
        check.reference,
        reference_consistency.readiness,
        PlanDirection.REFERENCE,
    )
    target = _plan_dataset(
        check.target,
        target_consistency.readiness,
        PlanDirection.TARGET,
    )
    artifacts = _plan_artifacts(check)
    probes = _plan_probes(check)
    stages = _plan_stages(check)
    estimates = tuple(
        PlanEstimate(name=name, status=EstimateStatus.UNKNOWN, unit=unit)
        for name, unit in (
            ("reference_rows", "records"),
            ("target_rows", "records"),
            ("reference_bytes", "bytes"),
            ("target_bytes", "bytes"),
            ("queries", "queries"),
        )
    )
    limitations = (
        "static plan does not access endpoints or establish readiness, capability, or data equality",
        "all listed probes and execution stages remain required and not run",
        _relation_scope_limitation(reference, target),
        "estimates are unknown until bounded endpoint preflight and execution",
    )
    return PlanReport(
        schema_version=1,
        config_version=1,
        semantic_digest_protocol=SEMANTIC_DIGEST_PROTOCOL,
        canonical_protocol=PROTOCOL,
        check_id=check.check_id,
        revision=check.revision,
        invariant="row_equivalence",
        assurance_policy=check.assurance_policy,
        logical_schema_digest=check.comparison_schema.logical_schema_digest,
        contract_digest=check.contract_digest,
        scope_digest=resolved_scope.scope_digest,
        reference=reference,
        target=target,
        ordered_key=check.key,
        artifacts=artifacts,
        probes=probes,
        stages=stages,
        estimates=estimates,
        limitations=limitations,
    )


def _relation_scope_limitation(reference: PlanDataset, target: PlanDataset) -> str:
    scopes = tuple(
        dataset.relation_scope
        for dataset in (reference, target)
        if dataset.locator_kind == "relation"
    )
    if RelationScope.FROZEN_PHYSICAL_UNION not in scopes:
        return (
            "relation datasets use physical_only semantics with ONLY; existence and relkind are not "
            "statically proven"
        )
    reference_scope = (
        reference.relation_scope.value if reference.relation_scope is not None else "not_applicable"
    )
    target_scope = (
        target.relation_scope.value if target.relation_scope is not None else "not_applicable"
    )
    return (
        "relation dataset scopes are explicitly selected: "
        f"reference={reference_scope}, target={target_scope}; frozen_physical_union resolves a "
        "locked physical hierarchy while physical_only uses ONLY; existence, topology, and relkind "
        "are not statically proven"
    )


def _find_check(config: LoadedContractConfig, check_id: str) -> RowCheckDefinition:
    if type(check_id) is not str or check_id.strip() == "":
        raise ContractReferenceError("static plan check_id must be a nonblank string")
    matches = tuple(check for check in config.checks if check.check_id == check_id)
    if len(matches) != 1:
        raise ContractReferenceError(f"static plan references unknown check {check_id!r}")
    return matches[0]


def resolve_scope_values(
    check: RowCheckDefinition,
    scope_values: Mapping[str, ScopeInputValue],
) -> ResolvedScope:
    _require_planning_instance(check, RowCheckDefinition, "scope check")
    _require_scope_mapping(scope_values)
    untyped_scope = cast(Mapping[object, object], scope_values)
    if any(type(name) is not str for name in untyped_scope):
        raise ScopeValueError("scope value keys must be strings")
    typed_scope = cast(Mapping[str, object], untyped_scope)
    expected_names = tuple(parameter.name for parameter in check.scope.parameters)
    actual_names = tuple(sorted(typed_scope))
    if actual_names != tuple(sorted(expected_names)):
        raise ScopeValueError(
            f"scope values must match declared parameters exactly: "
            f"expected={sorted(expected_names)!r}, actual={list(actual_names)!r}"
        )
    parameters: list[ResolvedScopeParameter] = []
    for parameter in check.scope.parameters:
        value = typed_scope[parameter.name]
        if type(value) not in (bool, int, str):
            raise ScopeValueError(
                f"scope parameter {parameter.name!r} requires an exact integer, boolean, or string"
            )
        typed_value = cast(ScopeInputValue, value)
        try:
            payload = encode_payload(parameter.field, typed_value)
        except PayloadValidationError as error:
            raise ScopeValueError(
                f"scope parameter {parameter.name!r} is invalid for logical type "
                f"{parameter.field.logical_type.value!r}: {error}"
            ) from None
        parameters.append(
            ResolvedScopeParameter(
                name=parameter.name,
                field=parameter.field,
                value=typed_value,
                canonical_payload=payload,
            )
        )
    resolved_parameters = tuple(parameters)
    return ResolvedScope(
        parameters=resolved_parameters,
        scope_digest=_resolved_scope_digest(resolved_parameters),
    )


def resolved_scope_semantic_value(scope: ResolvedScope) -> dict[str, SemanticValue]:
    _require_planning_instance(scope, ResolvedScope, "resolved scope")
    return _resolved_scope_semantics(scope.parameters)


def _resolved_scope_digest(parameters: tuple[ResolvedScopeParameter, ...]) -> str:
    return semantic_digest_hex(_resolved_scope_semantics(parameters))


def _resolved_scope_semantics(
    parameters: tuple[ResolvedScopeParameter, ...],
) -> dict[str, SemanticValue]:
    return {
        "canonical_protocol": PROTOCOL,
        "parameters": [
            {
                "name": parameter.name,
                "payload_hex": parameter.canonical_payload.hex(),
                "type": _scope_type_semantics(parameter.field),
            }
            for parameter in parameters
        ],
        "semantic_protocol": SEMANTIC_DIGEST_PROTOCOL,
    }


def _scope_type_semantics(field: FieldSchema) -> dict[str, SemanticValue]:
    values: dict[str, SemanticValue] = {
        "kind": field.logical_type.value,
        "normalization": field.normalization.value,
    }
    if isinstance(field.parameters, DecimalParameters):
        values["precision"] = field.parameters.precision
        values["scale"] = field.parameters.scale
    elif isinstance(field.parameters, TimestampParameters):
        values["precision"] = field.parameters.precision
    return values


def _plan_dataset(
    dataset: DatasetDefinition,
    readiness: ReadinessDefinition,
    direction: PlanDirection,
) -> PlanDataset:
    if isinstance(dataset.locator, RelationLocator):
        locator_kind: Literal["relation", "sql"] = "relation"
        relation_scope: RelationScope | None = dataset.locator.relation_scope
    else:
        locator_kind = "sql"
        relation_scope = None
    return PlanDataset(
        direction=direction,
        dataset_id=dataset.dataset_id,
        dataset_digest=dataset.semantic_digest,
        connection_id=dataset.connection.connection_id,
        adapter=dataset.connection.adapter,
        driver=dataset.connection.driver,
        profile=dataset.connection.profile,
        locator_kind=locator_kind,
        relation_scope=relation_scope,
        readiness=_plan_readiness(dataset, readiness),
    )


def _plan_readiness(
    dataset: DatasetDefinition,
    readiness: ReadinessDefinition,
) -> PlanReadiness:
    if isinstance(readiness, SqlArtifactDefinition):
        return PlanSqlReadiness(
            kind="sql",
            connection_id=dataset.connection.connection_id,
        )
    if readiness.connection_id != dataset.connection.connection_id:
        raise ValueError("relation manifest readiness must inherit its dataset connection")
    columns = readiness.columns
    relation = readiness.relation
    return PlanRelationManifestReadiness(
        kind="relation_manifest",
        connection_id=readiness.connection_id,
        relation=PlanReadinessRelation(
            catalog=relation.catalog,
            schema_name=relation.schema,
            relation_name=relation.name,
            relation_scope=relation.relation_scope,
        ),
        columns=PlanReadinessManifestColumns(
            dataset_id=columns.dataset_id,
            scope_digest=columns.scope_digest,
            batch_id=columns.batch_id,
            state=columns.state,
            business_date=columns.business_date,
            source_cut=columns.source_cut,
            dataset_version=columns.dataset_version,
            completed_at=columns.completed_at,
        ),
    )


def _plan_artifacts(check: RowCheckDefinition) -> tuple[PlanArtifact, ...]:
    artifacts: list[PlanArtifact] = []
    for direction, dataset in (
        (PlanDirection.REFERENCE, check.reference),
        (PlanDirection.TARGET, check.target),
    ):
        if isinstance(dataset.locator, SqlArtifactDefinition):
            artifacts.append(
                _plan_artifact(
                    ArtifactPurpose.PROJECTION,
                    direction,
                    dataset.dataset_id,
                    dataset.locator,
                )
            )
    for direction, item in zip(
        (PlanDirection.REFERENCE, PlanDirection.TARGET),
        check.consistency.datasets,
        strict=True,
    ):
        if isinstance(item.readiness, SqlArtifactDefinition):
            artifacts.append(
                _plan_artifact(
                    ArtifactPurpose.READINESS,
                    direction,
                    item.dataset_id,
                    item.readiness,
                )
            )
    return tuple(artifacts)


def _plan_artifact(
    purpose: ArtifactPurpose,
    direction: PlanDirection,
    dataset_id: str,
    artifact: SqlArtifactDefinition,
) -> PlanArtifact:
    return PlanArtifact(
        purpose=purpose,
        direction=direction,
        dataset_id=dataset_id,
        dialect=artifact.dialect,
        content_sha256=artifact.content_sha256,
        parameters=tuple(_plan_parameter(parameter) for parameter in artifact.parameters),
    )


def _plan_parameter(parameter: SqlParameterDefinition) -> PlanParameter:
    return PlanParameter(
        name=parameter.name,
        type=_plan_logical_type(parameter.field),
    )


def _plan_logical_type(field: FieldSchema) -> PlanLogicalType:
    precision: int | None = None
    scale: int | None = None
    if isinstance(field.parameters, DecimalParameters):
        precision = field.parameters.precision
        scale = field.parameters.scale
    elif isinstance(field.parameters, TimestampParameters):
        precision = field.parameters.precision
    return PlanLogicalType(
        kind=field.logical_type.value,
        precision=precision,
        scale=scale,
    )


def _plan_probes(check: RowCheckDefinition) -> tuple[PlanProbe, ...]:
    probes: list[PlanProbe] = []
    for direction, dataset in (
        (PlanDirection.REFERENCE, check.reference),
        (PlanDirection.TARGET, check.target),
    ):
        for name in (
            "endpoint_capability",
            "relation_or_projection_schema",
            "readiness",
            "stable_read_context",
        ):
            probes.append(
                PlanProbe(
                    name=name,
                    status=PlanProbeStatus.REQUIRED_NOT_RUN,
                    direction=direction,
                    dataset_id=dataset.dataset_id,
                )
            )
    return tuple(probes)


def _plan_stages(check: RowCheckDefinition) -> tuple[PlanStage, ...]:
    return tuple(
        PlanStage(name=name, status=PlanStageStatus.PLANNED_NOT_RUN)
        for name in _expected_stage_names(check.assurance_policy)
    )


def _expected_stage_names(assurance_policy: AssurancePolicy) -> tuple[str, ...]:
    common_prefix = (
        "open_read_contexts",
        "evaluate_readiness",
        "validate_key_contract",
    )
    if assurance_policy is AssurancePolicy.EXACT_REQUIRED:
        comparison = ("compare_exact_scope",)
    else:
        comparison = ("compare_fingerprints", "compare_exact_leaves")
    return common_prefix + comparison + ("persist_result",)


def _validate_plan_artifacts(plan: PlanReport) -> None:
    datasets = {
        PlanDirection.REFERENCE: plan.reference,
        PlanDirection.TARGET: plan.target,
    }
    seen: set[tuple[PlanDirection, ArtifactPurpose]] = set()
    for artifact in plan.artifacts:
        dataset = datasets[artifact.direction]
        if artifact.dataset_id != dataset.dataset_id:
            raise ValueError("plan artifact dataset does not match its direction")
        identity = (artifact.direction, artifact.purpose)
        if identity in seen:
            raise ValueError("plan artifacts contain a duplicate direction/purpose")
        seen.add(identity)
    expected: set[tuple[PlanDirection, ArtifactPurpose]] = set()
    for direction, dataset in datasets.items():
        if dataset.locator_kind == "sql":
            expected.add((direction, ArtifactPurpose.PROJECTION))
        if dataset.readiness.kind == "sql":
            expected.add((direction, ArtifactPurpose.READINESS))
    if seen != expected:
        raise ValueError("plan artifacts do not match dataset locators and readiness requirements")


def _validate_plan_probes(plan: PlanReport) -> None:
    datasets = {
        PlanDirection.REFERENCE: plan.reference.dataset_id,
        PlanDirection.TARGET: plan.target.dataset_id,
    }
    names = (
        "endpoint_capability",
        "relation_or_projection_schema",
        "readiness",
        "stable_read_context",
    )
    expected = {(direction, name) for direction in datasets for name in names}
    actual: set[tuple[PlanDirection, str]] = set()
    for probe in plan.probes:
        if probe.dataset_id != datasets[probe.direction]:
            raise ValueError("plan probe dataset does not match its direction")
        identity = (probe.direction, probe.name)
        if identity in actual:
            raise ValueError("plan probes contain a duplicate direction/name")
        actual.add(identity)
    if actual != expected:
        raise ValueError("plan probes do not contain the required version-1 probe set")


def _require_unicode_scalar_values(value: object) -> None:
    if type(value) is str:
        text = value
        for character in text:
            code_point = ord(character)
            if code_point == 0 or 0xD800 <= code_point <= 0xDFFF:
                raise ValueError("plan text must contain only non-null Unicode scalar values")
        return
    if isinstance(value, Mapping):
        untyped_mapping = cast(Mapping[object, object], value)
        for key, item in untyped_mapping.items():
            _require_unicode_scalar_values(key)
            _require_unicode_scalar_values(item)
        return
    if isinstance(value, (list, tuple)):
        for item in cast(list[object] | tuple[object, ...], value):
            _require_unicode_scalar_values(item)


def _require_planning_instance[T](
    value: object,
    expected_type: type[T],
    context: str,
) -> T:
    if not isinstance(value, expected_type):
        raise ScopeValueError(f"{context} must be a {expected_type.__name__}")
    return value


def _require_scope_mapping(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ScopeValueError("scope values must be a mapping")
