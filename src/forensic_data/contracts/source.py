import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Annotated, Literal, Self, final

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from forensic_data.contracts.errors import (
    ContractError,
    ContractFileError,
    ContractValidationError,
    SqlArtifactError,
    UnsupportedContractError,
)
from forensic_data.contracts.loader import load_yaml_object

type PositiveInt = Annotated[int, Field(strict=True, ge=1)]
type NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
type NonEmptyText = Annotated[str, Field(strict=True, min_length=1)]

_MAX_SQL_ARTIFACT_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_SQL_ARTIFACT_BYTES = 32 * 1024 * 1024

type _CapturedSqlArtifact = tuple[str, str]


class _InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _Int64TypeInput(_InputModel):
    kind: Literal["int64"]


class _DecimalTypeInput(_InputModel):
    kind: Literal["decimal"]
    precision: PositiveInt
    scale: NonNegativeInt


class _BooleanTypeInput(_InputModel):
    kind: Literal["boolean"]


class _StringTypeInput(_InputModel):
    kind: Literal["string"]


class _DateTypeInput(_InputModel):
    kind: Literal["date"]


class _TimestampLocalTypeInput(_InputModel):
    kind: Literal["timestamp_local"]
    precision: NonNegativeInt


class _TimestampInstantTypeInput(_InputModel):
    kind: Literal["timestamp_instant"]
    precision: NonNegativeInt


type _LogicalTypeInput = Annotated[
    _Int64TypeInput
    | _DecimalTypeInput
    | _BooleanTypeInput
    | _StringTypeInput
    | _DateTypeInput
    | _TimestampLocalTypeInput
    | _TimestampInstantTypeInput,
    Field(discriminator="kind"),
]


class _EqualityInput(_InputModel):
    kind: NonEmptyText


class _SchemaFieldInput(_InputModel):
    name: NonEmptyText
    type: _LogicalTypeInput
    nullable: bool
    normalization: NonEmptyText
    equality: _EqualityInput


class _SchemaInput(_InputModel):
    fields: tuple[_SchemaFieldInput, ...]


class _ConnectionInput(_InputModel):
    adapter: NonEmptyText
    driver: NonEmptyText
    profile: NonEmptyText
    roles: tuple[NonEmptyText, ...]
    secret_ref: NonEmptyText


class _RelationInput(_InputModel):
    catalog: str | None
    schema_name: str | None = Field(alias="schema")
    name: NonEmptyText


class _DatasetRelationInput(_RelationInput):
    relation_scope: NonEmptyText = "physical_only"


class _SqlParameterInput(_InputModel):
    name: NonEmptyText
    type: _LogicalTypeInput


class _SqlArtifactInput(_InputModel):
    path: NonEmptyText
    dialect: NonEmptyText
    parameters: tuple[_SqlParameterInput, ...]


class _ProjectionInput(_InputModel):
    field: NonEmptyText
    column: NonEmptyText


class _DatasetInput(_InputModel):
    connection: NonEmptyText
    relation: _DatasetRelationInput | None = None
    sql: _SqlArtifactInput | None = None
    logical_schema: NonEmptyText
    projection: tuple[_ProjectionInput, ...]
    grain: tuple[NonEmptyText, ...]

    @model_validator(mode="after")
    def require_one_locator(self) -> Self:
        if (self.relation is None) == (self.sql is None):
            raise ValueError("dataset requires exactly one of relation or sql")
        return self


class _ScopeParameterInput(_InputModel):
    type: _LogicalTypeInput


class _ScopeBindingInput(_InputModel):
    column: NonEmptyText
    operator: NonEmptyText
    parameter: NonEmptyText


class _ScopeInput(_InputModel):
    parameters: dict[str, _ScopeParameterInput]
    bindings: dict[str, _ScopeBindingInput]
    null_partition: NonEmptyText


class _ReadinessSqlInput(_InputModel):
    path: NonEmptyText
    dialect: NonEmptyText
    parameters: tuple[_SqlParameterInput, ...]


class _ReadinessManifestColumnsInput(_InputModel):
    dataset_id: NonEmptyText
    scope_digest: NonEmptyText
    batch_id: NonEmptyText
    state: NonEmptyText
    business_date: NonEmptyText
    source_cut: NonEmptyText
    dataset_version: NonEmptyText
    completed_at: NonEmptyText


class _ReadinessRelationManifestInput(_InputModel):
    kind: Literal["relation_manifest"]
    relation: _RelationInput
    columns: _ReadinessManifestColumnsInput


type _ReadinessInput = _ReadinessSqlInput | _ReadinessRelationManifestInput


class _StableReadInput(_InputModel):
    kind: NonEmptyText


class _ConsistencyDatasetInput(_InputModel):
    readiness: _ReadinessInput
    stable_read: _StableReadInput


class _ConsistencyInput(_InputModel):
    minimum_evidence: NonEmptyText
    alignment_fields: tuple[NonEmptyText, ...]
    late_arrivals: NonEmptyText
    datasets: dict[str, _ConsistencyDatasetInput]


class _CheckInput(_InputModel):
    revision: PositiveInt
    invariant: NonEmptyText
    reference: NonEmptyText
    target: NonEmptyText
    comparison_schema: NonEmptyText
    key: tuple[NonEmptyText, ...]
    scope: _ScopeInput | None = None
    scope_ref: NonEmptyText | None = None
    consistency_policy: NonEmptyText
    assurance_policy: NonEmptyText

    @model_validator(mode="after")
    def require_one_scope(self) -> Self:
        if (self.scope is None) == (self.scope_ref is None):
            raise ValueError("check requires exactly one of scope or scope_ref")
        return self


class _ExecutionInput(_InputModel):
    version: int = Field(strict=True)
    max_queries: PositiveInt
    max_fetched_records: PositiveInt
    max_application_result_bytes: PositiveInt
    max_evidence_rows: NonNegativeInt
    max_evidence_bytes: NonNegativeInt
    max_fingerprint_nodes: PositiveInt
    max_coordinator_memory_bytes: PositiveInt
    max_depth: NonNegativeInt
    max_full_scans_per_side: NonNegativeInt
    statement_timeout_milliseconds: PositiveInt
    run_timeout_milliseconds: PositiveInt
    max_attempts: PositiveInt
    max_checks_concurrency: PositiveInt
    max_source_concurrency: PositiveInt

    @field_validator("version", mode="before")
    @classmethod
    def require_exact_version_input(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("execution version must be the exact integer 1")
        return value

    @model_validator(mode="after")
    def require_version_one(self) -> Self:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("execution version must be the exact integer 1")
        return self


class _MetadataInput(_InputModel):
    connection: NonEmptyText


class _EvidenceInput(_InputModel):
    sql_capture: NonEmptyText
    ddl_capture: NonEmptyText
    fields: dict[str, NonEmptyText]
    unspecified_fields: NonEmptyText


class _ConfigInput(_InputModel):
    version: int = Field(strict=True)
    connections: dict[str, _ConnectionInput]
    schemas: dict[str, _SchemaInput]
    datasets: dict[str, _DatasetInput]
    checks: dict[str, _CheckInput]
    scopes: dict[str, _ScopeInput] = Field(default_factory=dict)
    consistency: dict[str, _ConsistencyInput]
    execution: _ExecutionInput
    metadata: _MetadataInput
    evidence: _EvidenceInput

    @field_validator("version", mode="before")
    @classmethod
    def require_exact_version_input(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("contract version must be the exact integer 1")
        return value

    @model_validator(mode="after")
    def require_version_one(self) -> Self:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("contract version must be the exact integer 1")
        return self


@final
@dataclass(frozen=True, slots=True)
class LogicalTypeSource:
    kind: str
    precision: int | None
    scale: int | None


@final
@dataclass(frozen=True, slots=True)
class SchemaFieldSource:
    name: str
    logical_type: LogicalTypeSource
    nullable: bool
    normalization: str
    equality: str


@final
@dataclass(frozen=True, slots=True)
class SchemaSource:
    schema_id: str
    fields: tuple[SchemaFieldSource, ...]


@final
@dataclass(frozen=True, slots=True)
class ConnectionSource:
    connection_id: str
    adapter: str
    driver: str
    profile: str
    roles: tuple[str, ...]
    secret_ref: str = dataclass_field(repr=False)


@final
@dataclass(frozen=True, slots=True)
class RelationSource:
    catalog: str | None
    schema: str | None
    name: str
    relation_scope: str


@final
@dataclass(frozen=True, slots=True)
class SqlParameterSource:
    name: str
    logical_type: LogicalTypeSource


@final
@dataclass(frozen=True, slots=True)
class SqlArtifactSource:
    path: Path = dataclass_field(repr=False)
    dialect: str
    parameters: tuple[SqlParameterSource, ...]
    content: str = dataclass_field(repr=False)
    content_sha256: str


type DatasetLocatorSource = RelationSource | SqlArtifactSource


@final
@dataclass(frozen=True, slots=True)
class ReadinessManifestColumnsSource:
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: str
    source_cut: str
    dataset_version: str
    completed_at: str


@final
@dataclass(frozen=True, slots=True)
class RelationManifestReadinessSource:
    relation: RelationSource
    columns: ReadinessManifestColumnsSource


type ReadinessSource = SqlArtifactSource | RelationManifestReadinessSource


@final
@dataclass(frozen=True, slots=True)
class ProjectionSource:
    field: str
    column: str


@final
@dataclass(frozen=True, slots=True)
class DatasetSource:
    dataset_id: str
    connection_ref: str
    locator: DatasetLocatorSource
    logical_schema_ref: str
    projection: tuple[ProjectionSource, ...]
    grain: tuple[str, ...]


@final
@dataclass(frozen=True, slots=True)
class ScopeParameterSource:
    name: str
    logical_type: LogicalTypeSource


@final
@dataclass(frozen=True, slots=True)
class ScopeBindingSource:
    dataset_ref: str
    column: str
    operator: str
    parameter_ref: str


@final
@dataclass(frozen=True, slots=True)
class ScopeSource:
    parameters: tuple[ScopeParameterSource, ...]
    bindings: tuple[ScopeBindingSource, ...]
    null_partition: str


@final
@dataclass(frozen=True, slots=True)
class ConsistencyDatasetSource:
    dataset_ref: str
    readiness: ReadinessSource
    stable_read: str


@final
@dataclass(frozen=True, slots=True)
class ConsistencySource:
    consistency_id: str
    minimum_evidence: str
    alignment_fields: tuple[str, ...]
    late_arrivals: str
    datasets: tuple[ConsistencyDatasetSource, ...]


@final
@dataclass(frozen=True, slots=True)
class CheckSource:
    check_id: str
    revision: int
    invariant: str
    reference_ref: str
    target_ref: str
    comparison_schema_ref: str
    key: tuple[str, ...]
    inline_scope: ScopeSource | None
    scope_ref: str | None
    consistency_ref: str
    assurance_policy: str


@final
@dataclass(frozen=True, slots=True)
class ExecutionSource:
    version: int
    max_queries: int
    max_fetched_records: int
    max_application_result_bytes: int
    max_evidence_rows: int
    max_evidence_bytes: int
    max_fingerprint_nodes: int
    max_coordinator_memory_bytes: int
    max_depth: int
    max_full_scans_per_side: int
    statement_timeout_milliseconds: int
    run_timeout_milliseconds: int
    max_attempts: int
    max_checks_concurrency: int
    max_source_concurrency: int


@final
@dataclass(frozen=True, slots=True)
class EvidenceSource:
    sql_capture: str
    ddl_capture: str
    fields: tuple[tuple[str, str], ...]
    unspecified_fields: str


@final
@dataclass(frozen=True, slots=True)
class LoadedContractSource:
    version: int
    connections: tuple[ConnectionSource, ...]
    schemas: tuple[SchemaSource, ...]
    datasets: tuple[DatasetSource, ...]
    checks: tuple[CheckSource, ...]
    named_scopes: tuple[tuple[str, ScopeSource], ...]
    consistency: tuple[ConsistencySource, ...]
    execution: ExecutionSource
    metadata_connection_ref: str
    evidence: EvidenceSource


def load_contract_source(path: Path) -> LoadedContractSource:
    resolved_path = _resolve_contract_path(path)
    document = load_yaml_object(resolved_path)
    if "flows" in document:
        raise UnsupportedContractError(
            "contract flows are unsupported in the Phase 02 row endpoint"
        )
    parsed: _ConfigInput | None = None
    validation_failure: ContractError | None = None
    try:
        parsed = _ConfigInput.model_validate(document)
    except ValidationError as error:
        validation_failure = _validation_failure(error)
    if validation_failure is not None:
        raise validation_failure
    if parsed is None:
        raise AssertionError("validated contract input is missing")

    base_directory = resolved_path.parent
    captured_artifacts = _capture_sql_artifacts(
        _configured_sql_artifact_paths(parsed),
        base_directory,
    )
    connections = tuple(
        _connection_source(connection_id, value)
        for connection_id, value in sorted(parsed.connections.items())
    )
    schemas = tuple(
        _schema_source(schema_id, value) for schema_id, value in sorted(parsed.schemas.items())
    )
    datasets = tuple(
        _dataset_source(dataset_id, value, base_directory, captured_artifacts)
        for dataset_id, value in sorted(parsed.datasets.items())
    )
    checks = tuple(
        _check_source(check_id, value) for check_id, value in sorted(parsed.checks.items())
    )
    named_scopes = tuple(
        (scope_id, _scope_source(value)) for scope_id, value in sorted(parsed.scopes.items())
    )
    consistency = tuple(
        _consistency_source(
            consistency_id,
            value,
            base_directory,
            captured_artifacts,
        )
        for consistency_id, value in sorted(parsed.consistency.items())
    )
    execution = _execution_source(parsed.execution)
    evidence = EvidenceSource(
        sql_capture=parsed.evidence.sql_capture,
        ddl_capture=parsed.evidence.ddl_capture,
        fields=tuple(sorted(parsed.evidence.fields.items())),
        unspecified_fields=parsed.evidence.unspecified_fields,
    )
    return LoadedContractSource(
        version=parsed.version,
        connections=connections,
        schemas=schemas,
        datasets=datasets,
        checks=checks,
        named_scopes=named_scopes,
        consistency=consistency,
        execution=execution,
        metadata_connection_ref=parsed.metadata.connection,
        evidence=evidence,
    )


def _validation_failure(error: ValidationError) -> ContractError:
    details = error.errors(include_url=False, include_context=False, include_input=False)
    rendered = tuple(
        f"location={'.'.join(str(part) for part in detail['loc'])!r}, "
        f"type={detail['type']!r}, reason={_safe_validation_reason(detail['type'], detail['msg'])!r}"
        for detail in details
    )
    message = "contract shape validation failed: " + "; ".join(rendered)
    if details and all(detail["type"] == "union_tag_invalid" for detail in details):
        return UnsupportedContractError(message)
    return ContractValidationError(message)


def _safe_validation_reason(error_type: str, reason: str) -> str:
    if error_type == "union_tag_invalid":
        return "unsupported discriminator value"
    return reason


def _resolve_contract_path(path: object) -> Path:
    if not isinstance(path, Path):
        raise TypeError("contract path must be a pathlib.Path")
    resolved: Path | None = None
    failure: ContractFileError | None = None
    try:
        resolved = path.resolve(strict=True)
    except (OSError, ValueError) as error:
        failure = ContractFileError(
            f"contract path cannot be resolved: path={str(path)!r}, "
            f"error_type={type(error).__name__}"
        )
    if failure is not None:
        raise failure
    if resolved is None:
        raise AssertionError("resolved contract path is missing")
    return resolved


def _logical_type_source(value: _LogicalTypeInput) -> LogicalTypeSource:
    if isinstance(value, _DecimalTypeInput):
        return LogicalTypeSource(kind=value.kind, precision=value.precision, scale=value.scale)
    if isinstance(value, (_TimestampLocalTypeInput, _TimestampInstantTypeInput)):
        return LogicalTypeSource(kind=value.kind, precision=value.precision, scale=None)
    return LogicalTypeSource(kind=value.kind, precision=None, scale=None)


def _scope_logical_type_source(value: _ScopeParameterInput) -> LogicalTypeSource:
    return _logical_type_source(value.type)


def _connection_source(connection_id: str, value: _ConnectionInput) -> ConnectionSource:
    return ConnectionSource(
        connection_id=connection_id,
        adapter=value.adapter,
        driver=value.driver,
        profile=value.profile,
        roles=value.roles,
        secret_ref=value.secret_ref,
    )


def _schema_source(schema_id: str, value: _SchemaInput) -> SchemaSource:
    fields = tuple(
        SchemaFieldSource(
            name=field.name,
            logical_type=_logical_type_source(field.type),
            nullable=field.nullable,
            normalization=field.normalization,
            equality=field.equality.kind,
        )
        for field in value.fields
    )
    return SchemaSource(schema_id=schema_id, fields=fields)


def _sql_parameters(values: tuple[_SqlParameterInput, ...]) -> tuple[SqlParameterSource, ...]:
    return tuple(
        SqlParameterSource(name=value.name, logical_type=_logical_type_source(value.type))
        for value in values
    )


def _dataset_source(
    dataset_id: str,
    value: _DatasetInput,
    base_directory: Path,
    captured_artifacts: Mapping[Path, _CapturedSqlArtifact],
) -> DatasetSource:
    if value.relation is not None:
        locator: DatasetLocatorSource = RelationSource(
            catalog=value.relation.catalog,
            schema=value.relation.schema_name,
            name=value.relation.name,
            relation_scope=value.relation.relation_scope,
        )
    elif value.sql is not None:
        locator = _sql_artifact_source(
            value.sql.path,
            value.sql.dialect,
            _sql_parameters(value.sql.parameters),
            base_directory,
            captured_artifacts,
        )
    else:
        raise AssertionError("validated dataset locator is missing")
    return DatasetSource(
        dataset_id=dataset_id,
        connection_ref=value.connection,
        locator=locator,
        logical_schema_ref=value.logical_schema,
        projection=tuple(
            ProjectionSource(field=projected.field, column=projected.column)
            for projected in value.projection
        ),
        grain=value.grain,
    )


def _scope_source(value: _ScopeInput) -> ScopeSource:
    parameters = tuple(
        ScopeParameterSource(
            name=name,
            logical_type=_scope_logical_type_source(parameter),
        )
        for name, parameter in sorted(value.parameters.items())
    )
    bindings = tuple(
        ScopeBindingSource(
            dataset_ref=dataset_ref,
            column=binding.column,
            operator=binding.operator,
            parameter_ref=binding.parameter,
        )
        for dataset_ref, binding in sorted(value.bindings.items())
    )
    return ScopeSource(
        parameters=parameters,
        bindings=bindings,
        null_partition=value.null_partition,
    )


def _check_source(check_id: str, value: _CheckInput) -> CheckSource:
    return CheckSource(
        check_id=check_id,
        revision=value.revision,
        invariant=value.invariant,
        reference_ref=value.reference,
        target_ref=value.target,
        comparison_schema_ref=value.comparison_schema,
        key=value.key,
        inline_scope=None if value.scope is None else _scope_source(value.scope),
        scope_ref=value.scope_ref,
        consistency_ref=value.consistency_policy,
        assurance_policy=value.assurance_policy,
    )


def _consistency_source(
    consistency_id: str,
    value: _ConsistencyInput,
    base_directory: Path,
    captured_artifacts: Mapping[Path, _CapturedSqlArtifact],
) -> ConsistencySource:
    datasets = tuple(
        ConsistencyDatasetSource(
            dataset_ref=dataset_ref,
            readiness=_readiness_source(
                dataset.readiness,
                base_directory,
                captured_artifacts,
            ),
            stable_read=dataset.stable_read.kind,
        )
        for dataset_ref, dataset in sorted(value.datasets.items())
    )
    return ConsistencySource(
        consistency_id=consistency_id,
        minimum_evidence=value.minimum_evidence,
        alignment_fields=value.alignment_fields,
        late_arrivals=value.late_arrivals,
        datasets=datasets,
    )


def _readiness_source(
    value: _ReadinessInput,
    base_directory: Path,
    captured_artifacts: Mapping[Path, _CapturedSqlArtifact],
) -> ReadinessSource:
    if isinstance(value, _ReadinessSqlInput):
        return _sql_artifact_source(
            value.path,
            value.dialect,
            _sql_parameters(value.parameters),
            base_directory,
            captured_artifacts,
        )
    relation = RelationSource(
        catalog=value.relation.catalog,
        schema=value.relation.schema_name,
        name=value.relation.name,
        relation_scope="physical_only",
    )
    columns = value.columns
    return RelationManifestReadinessSource(
        relation=relation,
        columns=ReadinessManifestColumnsSource(
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


def _sql_artifact_source(
    configured_path: str,
    dialect: str,
    parameters: tuple[SqlParameterSource, ...],
    base_directory: Path,
    captured_artifacts: Mapping[Path, _CapturedSqlArtifact],
) -> SqlArtifactSource:
    artifact_path = _resolve_sql_artifact_path(configured_path, base_directory)
    captured = captured_artifacts.get(artifact_path)
    if captured is None:
        raise AssertionError("captured SQL artifact is missing")
    return SqlArtifactSource(
        path=artifact_path,
        dialect=dialect,
        parameters=parameters,
        content=captured[0],
        content_sha256=captured[1],
    )


def _configured_sql_artifact_paths(value: _ConfigInput) -> tuple[str, ...]:
    paths: list[str] = []
    for _, dataset in sorted(value.datasets.items()):
        if dataset.sql is not None:
            paths.append(dataset.sql.path)
    for _, consistency in sorted(value.consistency.items()):
        for _, dataset in sorted(consistency.datasets.items()):
            if isinstance(dataset.readiness, _ReadinessSqlInput):
                paths.append(dataset.readiness.path)
    return tuple(paths)


def _capture_sql_artifacts(
    configured_paths: tuple[str, ...],
    base_directory: Path,
) -> dict[Path, _CapturedSqlArtifact]:
    captured_artifacts: dict[Path, _CapturedSqlArtifact] = {}
    captured_bytes = 0
    for configured_path in configured_paths:
        artifact_path = _resolve_sql_artifact_path(configured_path, base_directory)
        if artifact_path in captured_artifacts:
            continue
        raw = _read_sql_artifact(artifact_path, configured_path)
        captured_bytes += len(raw)
        if captured_bytes > _MAX_TOTAL_SQL_ARTIFACT_BYTES:
            raise SqlArtifactError(
                "distinct SQL artifacts exceed the aggregate capture limit: "
                f"limit_bytes={_MAX_TOTAL_SQL_ARTIFACT_BYTES}, "
                f"captured_bytes={captured_bytes}"
            )
        content = _decode_sql_artifact(raw, configured_path)
        captured_artifacts[artifact_path] = (content, hashlib.sha256(raw).hexdigest())
    return captured_artifacts


def _resolve_sql_artifact_path(configured_path: str, base_directory: Path) -> Path:
    artifact_path: Path | None = None
    path_failure: SqlArtifactError | None = None
    try:
        artifact_path = (base_directory / Path(configured_path)).resolve()
    except (OSError, ValueError) as error:
        path_failure = SqlArtifactError(
            f"SQL artifact path cannot be resolved: configured_path={configured_path!r}, "
            f"error_type={type(error).__name__}"
        )
    if path_failure is not None:
        raise path_failure
    if artifact_path is None:
        raise AssertionError("resolved SQL artifact path is missing")
    return artifact_path


def _read_sql_artifact(artifact_path: Path, configured_path: str) -> bytes:
    read_failure: SqlArtifactError | None = None
    raw = b""
    try:
        with artifact_path.open("rb") as stream:
            raw = stream.read(_MAX_SQL_ARTIFACT_BYTES + 1)
    except OSError as error:
        read_failure = SqlArtifactError(
            f"SQL artifact cannot be read: configured_path={configured_path!r}, "
            f"error_type={type(error).__name__}"
        )
    if read_failure is not None:
        raise read_failure
    if len(raw) > _MAX_SQL_ARTIFACT_BYTES:
        raise SqlArtifactError(
            f"SQL artifact exceeds the {_MAX_SQL_ARTIFACT_BYTES}-byte parser limit: "
            f"configured_path={configured_path!r}, bytes>{_MAX_SQL_ARTIFACT_BYTES}"
        )
    return raw


def _decode_sql_artifact(raw: bytes, configured_path: str) -> str:
    content = ""
    decode_failure: SqlArtifactError | None = None
    try:
        content = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        decode_failure = SqlArtifactError(
            f"SQL artifact is not strict UTF-8: configured_path={configured_path!r}, "
            f"byte_start={error.start}, byte_end={error.end}, reason={error.reason}"
        )
    if decode_failure is not None:
        raise decode_failure
    return content


def _execution_source(value: _ExecutionInput) -> ExecutionSource:
    return ExecutionSource(
        version=value.version,
        max_queries=value.max_queries,
        max_fetched_records=value.max_fetched_records,
        max_application_result_bytes=value.max_application_result_bytes,
        max_evidence_rows=value.max_evidence_rows,
        max_evidence_bytes=value.max_evidence_bytes,
        max_fingerprint_nodes=value.max_fingerprint_nodes,
        max_coordinator_memory_bytes=value.max_coordinator_memory_bytes,
        max_depth=value.max_depth,
        max_full_scans_per_side=value.max_full_scans_per_side,
        statement_timeout_milliseconds=value.statement_timeout_milliseconds,
        run_timeout_milliseconds=value.run_timeout_milliseconds,
        max_attempts=value.max_attempts,
        max_checks_concurrency=value.max_checks_concurrency,
        max_source_concurrency=value.max_source_concurrency,
    )
