from collections.abc import Mapping
from enum import StrEnum
from typing import Literal, Self, cast

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
    RelationLocator,
    RelationScope,
    RowCheckDefinition,
    ScopeParameterDefinition,
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
        if (
            self.locator_kind == "relation"
            and self.relation_scope is not RelationScope.PHYSICAL_ONLY
        ):
            raise ValueError("relation plan dataset requires physical_only relation scope")
        if self.locator_kind == "sql" and self.relation_scope is not None:
            raise ValueError("SQL plan dataset cannot carry a relation scope")
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
    scope_digest = _scope_digest(check, scope_values)
    reference = _plan_dataset(check.reference, PlanDirection.REFERENCE)
    target = _plan_dataset(check.target, PlanDirection.TARGET)
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
        "relation datasets use physical_only semantics with ONLY; existence and relkind are not "
        "statically proven",
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
        scope_digest=scope_digest,
        reference=reference,
        target=target,
        ordered_key=check.key,
        artifacts=artifacts,
        probes=probes,
        stages=stages,
        estimates=estimates,
        limitations=limitations,
    )


def _find_check(config: LoadedContractConfig, check_id: str) -> RowCheckDefinition:
    if type(check_id) is not str or check_id.strip() == "":
        raise ContractReferenceError("static plan check_id must be a nonblank string")
    matches = tuple(check for check in config.checks if check.check_id == check_id)
    if len(matches) != 1:
        raise ContractReferenceError(f"static plan references unknown check {check_id!r}")
    return matches[0]


def _scope_digest(
    check: RowCheckDefinition,
    scope_values: object,
) -> str:
    if not isinstance(scope_values, Mapping):
        raise ScopeValueError("scope values must be a mapping")
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
    parameters: list[SemanticValue] = []
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
            {
                "name": parameter.name,
                "payload_hex": payload.hex(),
                "type": _scope_type_semantics(parameter),
            }
        )
    metadata: dict[str, SemanticValue] = {
        "canonical_protocol": PROTOCOL,
        "parameters": parameters,
        "semantic_protocol": SEMANTIC_DIGEST_PROTOCOL,
    }
    return semantic_digest_hex(metadata)


def _scope_type_semantics(parameter: ScopeParameterDefinition) -> dict[str, SemanticValue]:
    field = parameter.field
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


def _plan_dataset(dataset: DatasetDefinition, direction: PlanDirection) -> PlanDataset:
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
    expected = {
        (PlanDirection.REFERENCE, ArtifactPurpose.READINESS),
        (PlanDirection.TARGET, ArtifactPurpose.READINESS),
    }
    for direction, dataset in datasets.items():
        if dataset.locator_kind == "sql":
            expected.add((direction, ArtifactPurpose.PROJECTION))
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
