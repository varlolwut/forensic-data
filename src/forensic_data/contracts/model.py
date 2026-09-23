import hashlib
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from pathlib import Path
from typing import cast, final

from forensic_data.canonical import CanonicalSchema, FieldSchema, schema_digest_hex
from forensic_data.contracts.errors import ContractValidationError


class Adapter(StrEnum):
    POSTGRESQL = "postgresql"


class ConnectionRole(StrEnum):
    SOURCE = "source"
    TARGET = "target"
    METADATA = "metadata"


class SqlDialect(StrEnum):
    POSTGRESQL = "postgresql"


class FieldEquality(StrEnum):
    EXACT = "exact"


class RelationScope(StrEnum):
    PHYSICAL_ONLY = "physical_only"


class ScopeOperator(StrEnum):
    EQUAL = "eq"


class NullPartitionPolicy(StrEnum):
    REJECT = "reject"


class MinimumEvidence(StrEnum):
    VERIFIED = "verified"
    ASSERTED = "asserted"


class StableReadKind(StrEnum):
    TRANSACTION_SNAPSHOT = "transaction_snapshot"


class LateArrivalPolicy(StrEnum):
    NEXT_BATCH = "next_batch"


class AssurancePolicy(StrEnum):
    FINGERPRINT_ALLOWED = "fingerprint_allowed"
    EXACT_REQUIRED = "exact_required"


class CapturePolicy(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"


class EvidenceAction(StrEnum):
    STORE = "store"
    REDACT = "redact"
    OMIT = "omit"


@final
@dataclass(frozen=True, slots=True)
class ConnectionDefinition:
    connection_id: str
    adapter: Adapter
    driver: str
    profile: str
    roles: tuple[ConnectionRole, ...]
    secret_ref: str = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        _require_logical_text(self.connection_id, "connection id")
        _require_enum(self.adapter, Adapter, "connection adapter")
        _require_logical_text(self.driver, "connection driver")
        _require_logical_text(self.profile, "connection profile")
        _require_nonempty_enum_tuple(self.roles, ConnectionRole, "connection roles")
        if len(set(self.roles)) != len(self.roles):
            raise ContractValidationError("connection roles must not contain duplicates")
        _require_logical_text(self.secret_ref, "connection secret_ref")


@final
@dataclass(frozen=True, slots=True)
class LogicalSchemaDefinition:
    schema_id: str
    schema: CanonicalSchema
    equality: tuple[FieldEquality, ...]
    logical_schema_digest: str

    def __post_init__(self) -> None:
        _require_logical_text(self.schema_id, "logical schema id")
        _require_instance(self.schema, CanonicalSchema, "logical schema")
        _require_enum_tuple(self.equality, FieldEquality, "logical schema equality")
        if len(self.equality) != len(self.schema.fields):
            raise ContractValidationError(
                "logical schema equality count must equal canonical field count"
            )
        _require_sha256(self.logical_schema_digest, "logical schema digest")
        if self.logical_schema_digest != schema_digest_hex(self.schema):
            raise ContractValidationError(
                "logical schema digest does not match canonical schema metadata"
            )


@final
@dataclass(frozen=True, slots=True)
class RelationLocator:
    catalog: str | None
    schema: str
    name: str
    relation_scope: RelationScope

    def __post_init__(self) -> None:
        if self.catalog is not None:
            _require_physical_text(self.catalog, "relation catalog")
        _require_physical_text(self.schema, "relation schema")
        _require_physical_text(self.name, "relation name")
        _require_enum(self.relation_scope, RelationScope, "relation scope")


@final
@dataclass(frozen=True, slots=True)
class SqlParameterDefinition:
    name: str
    field: FieldSchema

    def __post_init__(self) -> None:
        _require_logical_text(self.name, "SQL parameter name")
        _require_parameter_field(self.name, self.field, "SQL parameter")


@final
@dataclass(frozen=True, slots=True)
class SqlArtifactDefinition:
    path: Path = dataclass_field(repr=False)
    dialect: SqlDialect
    parameters: tuple[SqlParameterDefinition, ...]
    content: str = dataclass_field(repr=False)
    content_sha256: str

    def __post_init__(self) -> None:
        _require_instance(self.path, Path, "SQL artifact path")
        _require_enum(self.dialect, SqlDialect, "SQL artifact dialect")
        _require_object_tuple(self.parameters, SqlParameterDefinition, "SQL parameters")
        _require_unique_names(
            tuple(parameter.name for parameter in self.parameters),
            "SQL parameters",
        )
        if type(self.content) is not str or self.content.strip() == "":
            raise ContractValidationError("SQL artifact content must be nonblank text")
        encoding_failure: ContractValidationError | None = None
        encoded = b""
        try:
            encoded = self.content.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            encoding_failure = ContractValidationError(
                "SQL artifact content contains a surrogate code point"
            )
        if encoding_failure is not None:
            raise encoding_failure
        _require_sha256(self.content_sha256, "SQL artifact content digest")
        if hashlib.sha256(encoded).hexdigest() != self.content_sha256:
            raise ContractValidationError(
                "SQL artifact content digest does not match the captured UTF-8 bytes"
            )


type DatasetLocator = RelationLocator | SqlArtifactDefinition


@final
@dataclass(frozen=True, slots=True)
class ReadinessManifestColumns:
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: str
    source_cut: str
    dataset_version: str
    completed_at: str

    def __post_init__(self) -> None:
        values = self.values()
        for name, value in zip(
            (
                "dataset_id",
                "scope_digest",
                "batch_id",
                "state",
                "business_date",
                "source_cut",
                "dataset_version",
                "completed_at",
            ),
            values,
            strict=True,
        ):
            _require_physical_text(value, f"readiness manifest {name} column")
        if len(set(values)) != len(values):
            raise ContractValidationError(
                "readiness manifest column mappings must reference distinct columns"
            )

    def values(self) -> tuple[str, ...]:
        return (
            self.dataset_id,
            self.scope_digest,
            self.batch_id,
            self.state,
            self.business_date,
            self.source_cut,
            self.dataset_version,
            self.completed_at,
        )


@final
@dataclass(frozen=True, slots=True)
class RelationManifestReadiness:
    connection_id: str
    relation: RelationLocator
    columns: ReadinessManifestColumns

    def __post_init__(self) -> None:
        _require_logical_text(self.connection_id, "readiness manifest connection id")
        _require_instance(self.relation, RelationLocator, "readiness manifest relation")
        if self.relation.catalog is not None:
            raise ContractValidationError(
                "PostgreSQL readiness manifest relation catalog must be null"
            )
        if self.relation.relation_scope is not RelationScope.PHYSICAL_ONLY:
            raise ContractValidationError(
                "readiness manifest relation requires physical_only relation scope"
            )
        _require_instance(self.columns, ReadinessManifestColumns, "readiness manifest columns")


type ReadinessDefinition = SqlArtifactDefinition | RelationManifestReadiness


@final
@dataclass(frozen=True, slots=True)
class ProjectedField:
    field_name: str
    column_name: str

    def __post_init__(self) -> None:
        _require_logical_text(self.field_name, "projected field name")
        _require_physical_text(self.column_name, "projected column name")


@final
@dataclass(frozen=True, slots=True)
class DatasetDefinition:
    dataset_id: str
    connection: ConnectionDefinition
    locator: DatasetLocator
    logical_schema: LogicalSchemaDefinition
    projection: tuple[ProjectedField, ...]
    grain: tuple[str, ...]
    semantic_digest: str = dataclass_field(init=False)

    def __post_init__(self) -> None:
        _require_logical_text(self.dataset_id, "dataset id")
        _require_instance(self.connection, ConnectionDefinition, "dataset connection")
        _require_locator(self.locator)
        if (
            isinstance(self.locator, RelationLocator)
            and self.connection.adapter is Adapter.POSTGRESQL
            and self.locator.catalog is not None
        ):
            raise ContractValidationError("PostgreSQL dataset relation catalog must be null")
        _require_instance(
            self.logical_schema,
            LogicalSchemaDefinition,
            "dataset logical schema",
        )
        _require_object_tuple(self.projection, ProjectedField, "dataset projection")
        expected = tuple(field.name for field in self.logical_schema.schema.fields)
        actual = tuple(field.field_name for field in self.projection)
        if actual != expected:
            raise ContractValidationError(
                "dataset projection must cover canonical fields exactly once and in order"
            )
        _require_nonnullable_fields(self.grain, self.logical_schema, "dataset grain")
        from forensic_data.contracts.identity import dataset_digest_hex

        object.__setattr__(self, "semantic_digest", dataset_digest_hex(self))


@final
@dataclass(frozen=True, slots=True)
class ScopeParameterDefinition:
    name: str
    field: FieldSchema

    def __post_init__(self) -> None:
        _require_logical_text(self.name, "scope parameter name")
        _require_parameter_field(self.name, self.field, "scope parameter")


@final
@dataclass(frozen=True, slots=True)
class ScopeBinding:
    dataset_id: str
    column: str
    operator: ScopeOperator
    parameter: str

    def __post_init__(self) -> None:
        _require_logical_text(self.dataset_id, "scope binding dataset id")
        _require_physical_text(self.column, "scope binding column")
        _require_enum(self.operator, ScopeOperator, "scope binding operator")
        _require_logical_text(self.parameter, "scope binding parameter")


@final
@dataclass(frozen=True, slots=True)
class ScopeDefinition:
    parameters: tuple[ScopeParameterDefinition, ...]
    bindings: tuple[ScopeBinding, ...]
    null_partition: NullPartitionPolicy

    def __post_init__(self) -> None:
        _require_object_tuple(self.parameters, ScopeParameterDefinition, "scope parameters")
        _require_object_tuple(self.bindings, ScopeBinding, "scope bindings")
        _require_enum(self.null_partition, NullPartitionPolicy, "scope null partition policy")
        if len(self.parameters) > 1:
            raise ContractValidationError("initial scope supports at most one parameter")
        _require_unique_names(
            tuple(parameter.name for parameter in self.parameters),
            "scope parameters",
        )
        _require_unique_names(
            tuple(binding.dataset_id for binding in self.bindings),
            "scope binding datasets",
        )
        parameter_names = {parameter.name for parameter in self.parameters}
        if not parameter_names and self.bindings:
            raise ContractValidationError("full scope cannot contain bindings")
        for binding in self.bindings:
            if binding.parameter not in parameter_names:
                raise ContractValidationError(
                    f"scope binding references unknown parameter {binding.parameter!r}"
                )


@final
@dataclass(frozen=True, slots=True)
class ConsistencyDatasetDefinition:
    dataset_id: str
    readiness: ReadinessDefinition
    stable_read: StableReadKind

    def __post_init__(self) -> None:
        _require_logical_text(self.dataset_id, "consistency dataset id")
        _require_readiness(self.readiness)
        _require_enum(self.stable_read, StableReadKind, "stable-read strategy")


@final
@dataclass(frozen=True, slots=True)
class ConsistencyDefinition:
    minimum_evidence: MinimumEvidence
    alignment_fields: tuple[str, ...]
    late_arrivals: LateArrivalPolicy
    datasets: tuple[ConsistencyDatasetDefinition, ...]

    def __post_init__(self) -> None:
        _require_enum(self.minimum_evidence, MinimumEvidence, "minimum consistency evidence")
        _require_unique_names(self.alignment_fields, "consistency alignment fields")
        if not self.alignment_fields:
            raise ContractValidationError("consistency alignment fields must not be empty")
        _require_enum(self.late_arrivals, LateArrivalPolicy, "late-arrival policy")
        _require_object_tuple(
            self.datasets,
            ConsistencyDatasetDefinition,
            "consistency datasets",
        )
        if not self.datasets:
            raise ContractValidationError("consistency datasets must not be empty")
        _require_unique_names(
            tuple(dataset.dataset_id for dataset in self.datasets),
            "consistency datasets",
        )


@final
@dataclass(frozen=True, slots=True)
class ExecutionBudgets:
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

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ContractValidationError("execution version must be exactly 1")
        for name, value in (
            ("max_queries", self.max_queries),
            ("max_fetched_records", self.max_fetched_records),
            ("max_application_result_bytes", self.max_application_result_bytes),
            ("max_fingerprint_nodes", self.max_fingerprint_nodes),
            ("max_coordinator_memory_bytes", self.max_coordinator_memory_bytes),
            ("statement_timeout_milliseconds", self.statement_timeout_milliseconds),
            ("run_timeout_milliseconds", self.run_timeout_milliseconds),
            ("max_attempts", self.max_attempts),
            ("max_checks_concurrency", self.max_checks_concurrency),
            ("max_source_concurrency", self.max_source_concurrency),
        ):
            _require_positive_integer(value, f"execution {name}")
        for name, value in (
            ("max_evidence_rows", self.max_evidence_rows),
            ("max_evidence_bytes", self.max_evidence_bytes),
            ("max_depth", self.max_depth),
            ("max_full_scans_per_side", self.max_full_scans_per_side),
        ):
            _require_nonnegative_integer(value, f"execution {name}")


@final
@dataclass(frozen=True, slots=True)
class MetadataDefinition:
    connection: ConnectionDefinition

    def __post_init__(self) -> None:
        _require_instance(self.connection, ConnectionDefinition, "metadata connection")
        if ConnectionRole.METADATA not in self.connection.roles:
            raise ContractValidationError("metadata connection must declare role 'metadata'")


@final
@dataclass(frozen=True, slots=True)
class EvidenceFieldPolicy:
    field_name: str
    action: EvidenceAction

    def __post_init__(self) -> None:
        _require_logical_text(self.field_name, "evidence field name")
        _require_enum(self.action, EvidenceAction, "evidence field action")


@final
@dataclass(frozen=True, slots=True)
class EvidenceDefinition:
    sql_capture: CapturePolicy
    ddl_capture: CapturePolicy
    fields: tuple[EvidenceFieldPolicy, ...]
    unspecified_fields: EvidenceAction

    def __post_init__(self) -> None:
        _require_enum(self.sql_capture, CapturePolicy, "evidence SQL capture policy")
        _require_enum(self.ddl_capture, CapturePolicy, "evidence DDL capture policy")
        _require_object_tuple(self.fields, EvidenceFieldPolicy, "evidence field policies")
        _require_unique_names(
            tuple(field.field_name for field in self.fields),
            "evidence field policies",
        )
        _require_enum(
            self.unspecified_fields,
            EvidenceAction,
            "evidence unspecified-fields policy",
        )


@final
@dataclass(frozen=True, slots=True)
class RowCheckDefinition:
    check_id: str
    revision: int
    reference: DatasetDefinition
    target: DatasetDefinition
    comparison_schema: LogicalSchemaDefinition
    key: tuple[str, ...]
    scope: ScopeDefinition
    consistency: ConsistencyDefinition
    assurance_policy: AssurancePolicy
    contract_digest: str = dataclass_field(init=False)

    def __post_init__(self) -> None:
        _require_logical_text(self.check_id, "check id")
        _require_positive_integer(self.revision, "check revision")
        _require_instance(self.reference, DatasetDefinition, "check reference dataset")
        _require_instance(self.target, DatasetDefinition, "check target dataset")
        if self.reference.dataset_id == self.target.dataset_id:
            raise ContractValidationError("check reference and target datasets must differ")
        if ConnectionRole.SOURCE not in self.reference.connection.roles:
            raise ContractValidationError("check reference connection must declare role 'source'")
        if ConnectionRole.TARGET not in self.target.connection.roles:
            raise ContractValidationError("check target connection must declare role 'target'")
        _require_instance(
            self.comparison_schema,
            LogicalSchemaDefinition,
            "check comparison schema",
        )
        for direction, dataset in (("reference", self.reference), ("target", self.target)):
            if (
                dataset.logical_schema.logical_schema_digest
                != self.comparison_schema.logical_schema_digest
                or dataset.logical_schema.equality != self.comparison_schema.equality
            ):
                raise ContractValidationError(
                    f"check {direction} dataset schema must match comparison schema"
                )
        _require_nonnullable_fields(self.key, self.comparison_schema, "check key")
        if self.reference.grain != self.key or self.target.grain != self.key:
            raise ContractValidationError("check key must equal both dataset grains")
        _require_instance(self.scope, ScopeDefinition, "check scope")
        if self.scope.parameters:
            expected = (self.reference.dataset_id, self.target.dataset_id)
            actual = tuple(binding.dataset_id for binding in self.scope.bindings)
            if actual != expected:
                raise ContractValidationError(
                    "scoped check bindings must be ordered reference then target"
                )
        _require_check_scope_bindings(self.scope, self.reference, self.target)
        expected_parameters = tuple(parameter.field for parameter in self.scope.parameters)
        for direction, dataset in (("reference", self.reference), ("target", self.target)):
            if isinstance(dataset.locator, SqlArtifactDefinition):
                _require_parameter_subset(
                    expected_parameters,
                    tuple(parameter.field for parameter in dataset.locator.parameters),
                    f"check {direction} projection parameters",
                )
        _require_instance(
            self.consistency,
            ConsistencyDefinition,
            "check consistency policy",
        )
        if tuple(item.dataset_id for item in self.consistency.datasets) != (
            self.reference.dataset_id,
            self.target.dataset_id,
        ):
            raise ContractValidationError(
                "check consistency datasets must be ordered reference then target"
            )
        for direction, item, dataset in zip(
            ("reference", "target"),
            self.consistency.datasets,
            (self.reference, self.target),
            strict=True,
        ):
            if isinstance(item.readiness, SqlArtifactDefinition):
                _require_parameter_subset(
                    expected_parameters,
                    tuple(parameter.field for parameter in item.readiness.parameters),
                    f"check {direction} readiness parameters",
                )
            elif item.readiness.connection_id != dataset.connection.connection_id:
                raise ContractValidationError(
                    f"check {direction} readiness manifest must use the dataset connection"
                )
        _require_enum(self.assurance_policy, AssurancePolicy, "check assurance policy")
        from forensic_data.contracts.identity import contract_digest_hex

        object.__setattr__(self, "contract_digest", contract_digest_hex(1, self))


@final
@dataclass(frozen=True, slots=True)
class LoadedContractConfig:
    version: int
    connections: tuple[ConnectionDefinition, ...]
    schemas: tuple[LogicalSchemaDefinition, ...]
    datasets: tuple[DatasetDefinition, ...]
    checks: tuple[RowCheckDefinition, ...]
    named_scopes: tuple[tuple[str, ScopeDefinition], ...]
    consistency: tuple[tuple[str, ConsistencyDefinition], ...]
    execution: ExecutionBudgets
    metadata: MetadataDefinition
    evidence: EvidenceDefinition

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ContractValidationError("contract version must be exactly 1")
        _require_object_tuple(self.connections, ConnectionDefinition, "contract connections")
        _require_object_tuple(self.schemas, LogicalSchemaDefinition, "contract schemas")
        _require_object_tuple(self.datasets, DatasetDefinition, "contract datasets")
        _require_object_tuple(self.checks, RowCheckDefinition, "contract checks")
        if not self.connections or not self.schemas or not self.datasets or not self.checks:
            raise ContractValidationError(
                "contract connections, schemas, datasets, and checks must not be empty"
            )
        _require_unique_names(
            tuple(connection.connection_id for connection in self.connections),
            "contract connections",
        )
        _require_unique_names(
            tuple(schema.schema_id for schema in self.schemas),
            "contract schemas",
        )
        _require_unique_names(
            tuple(dataset.dataset_id for dataset in self.datasets),
            "contract datasets",
        )
        _require_unique_names(
            tuple(check.check_id for check in self.checks),
            "contract checks",
        )
        connections = {connection.connection_id: connection for connection in self.connections}
        schemas = {schema.schema_id: schema for schema in self.schemas}
        datasets = {dataset.dataset_id: dataset for dataset in self.datasets}
        for dataset in self.datasets:
            if connections.get(dataset.connection.connection_id) != dataset.connection:
                raise ContractValidationError(
                    f"dataset {dataset.dataset_id!r} connection is outside contract closure"
                )
            if schemas.get(dataset.logical_schema.schema_id) != dataset.logical_schema:
                raise ContractValidationError(
                    f"dataset {dataset.dataset_id!r} logical schema is outside contract closure"
                )
        for check in self.checks:
            if datasets.get(check.reference.dataset_id) != check.reference:
                raise ContractValidationError(
                    f"check {check.check_id!r} reference is outside contract closure"
                )
            if datasets.get(check.target.dataset_id) != check.target:
                raise ContractValidationError(
                    f"check {check.check_id!r} target is outside contract closure"
                )
            if schemas.get(check.comparison_schema.schema_id) != check.comparison_schema:
                raise ContractValidationError(
                    f"check {check.check_id!r} comparison schema is outside contract closure"
                )
        _require_named_objects(self.named_scopes, ScopeDefinition, "contract named scopes")
        _require_named_objects(
            self.consistency,
            ConsistencyDefinition,
            "contract consistency policies",
        )
        if not self.consistency:
            raise ContractValidationError("contract consistency policies must not be empty")
        _require_instance(self.execution, ExecutionBudgets, "contract execution budgets")
        _require_instance(self.metadata, MetadataDefinition, "contract metadata policy")
        if connections.get(self.metadata.connection.connection_id) != self.metadata.connection:
            raise ContractValidationError("metadata connection is outside contract closure")
        _require_instance(self.evidence, EvidenceDefinition, "contract evidence policy")


def _require_logical_text(value: object, context: str) -> None:
    if type(value) is not str or value.strip() == "":
        raise ContractValidationError(f"{context} must be nonblank text")
    _require_unicode_text(value, context)


def _require_physical_text(value: object, context: str) -> None:
    if type(value) is not str or value == "":
        raise ContractValidationError(f"{context} must be nonempty text")
    _require_unicode_text(value, context)


def _require_unicode_text(value: str, context: str) -> None:
    for index, character in enumerate(value):
        code_point = ord(character)
        if code_point == 0:
            raise ContractValidationError(f"{context} contains U+0000 at character {index}")
        if 0xD800 <= code_point <= 0xDFFF:
            raise ContractValidationError(
                f"{context} contains a surrogate code point at character {index}"
            )


def _require_sha256(value: object, context: str) -> None:
    if type(value) is not str or len(value) != 64:
        raise ContractValidationError(f"{context} must be 64 lowercase hex digits")
    if any(character not in "0123456789abcdef" for character in value):
        raise ContractValidationError(f"{context} must be 64 lowercase hex digits")


def _require_enum[EnumT](value: object, enum_type: type[EnumT], context: str) -> None:
    if not isinstance(value, enum_type):
        raise ContractValidationError(f"{context} must be a {enum_type.__name__}")


def _require_enum_tuple[EnumT](
    values: object,
    enum_type: type[EnumT],
    context: str,
) -> None:
    if type(values) is not tuple:
        raise ContractValidationError(f"{context} must be an immutable tuple")
    typed_values = cast(tuple[object, ...], values)
    for value in typed_values:
        _require_enum(value, enum_type, context)


def _require_nonempty_enum_tuple[EnumT](
    values: object,
    enum_type: type[EnumT],
    context: str,
) -> None:
    _require_enum_tuple(values, enum_type, context)
    if not cast(tuple[object, ...], values):
        raise ContractValidationError(f"{context} must not be empty")


def _require_object_tuple[ObjectT](
    values: object,
    object_type: type[ObjectT],
    context: str,
) -> None:
    if type(values) is not tuple:
        raise ContractValidationError(f"{context} must be an immutable tuple")
    for value in cast(tuple[object, ...], values):
        if not isinstance(value, object_type):
            raise ContractValidationError(
                f"{context} values must be {object_type.__name__} instances"
            )


def _require_unique_names(values: tuple[str, ...], context: str) -> None:
    if type(values) is not tuple:
        raise ContractValidationError(f"{context} names must be an immutable tuple")
    seen: set[str] = set()
    for value in values:
        _require_logical_text(value, context)
        if value in seen:
            raise ContractValidationError(f"{context} contains duplicate name {value!r}")
        seen.add(value)


def _require_parameter_field(name: str, field: object, context: str) -> None:
    if not isinstance(field, FieldSchema):
        raise ContractValidationError(f"{context} field must be a FieldSchema")
    if field.name != name:
        raise ContractValidationError(f"{context} name must equal its FieldSchema name")
    if field.nullable:
        raise ContractValidationError(f"{context} must be non-nullable")


def _require_nonnullable_fields(
    values: tuple[str, ...],
    schema: LogicalSchemaDefinition,
    context: str,
) -> None:
    _require_unique_names(values, context)
    if not values:
        raise ContractValidationError(f"{context} must not be empty")
    by_name = {field.name: field for field in schema.schema.fields}
    for value in values:
        field = by_name.get(value)
        if field is None:
            raise ContractValidationError(f"{context} references unknown field {value!r}")
        if field.nullable:
            raise ContractValidationError(f"{context} field {value!r} must be non-nullable")


def _require_positive_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 1:
        raise ContractValidationError(f"{context} must be a positive exact integer")


def _require_nonnegative_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 0:
        raise ContractValidationError(f"{context} must be a nonnegative exact integer")


def _require_named_objects[ObjectT](
    values: object,
    object_type: type[ObjectT],
    context: str,
) -> None:
    if type(values) is not tuple:
        raise ContractValidationError(f"{context} must be an immutable tuple")
    seen: set[str] = set()
    for raw_value in cast(tuple[object, ...], values):
        if type(raw_value) is not tuple:
            raise ContractValidationError(f"{context} entries must be name/value tuples")
        tuple_value = cast(tuple[object, ...], raw_value)
        if len(tuple_value) != 2:
            raise ContractValidationError(f"{context} entries must be name/value tuples")
        value = tuple_value
        name, item = value
        _require_logical_text(name, context)
        typed_name = cast(str, name)
        if typed_name in seen:
            raise ContractValidationError(f"{context} contains duplicate name {typed_name!r}")
        seen.add(typed_name)
        if not isinstance(item, object_type):
            raise ContractValidationError(
                f"{context} values must be {object_type.__name__} instances"
            )


def _require_instance[ObjectT](
    value: object,
    object_type: type[ObjectT],
    context: str,
) -> None:
    if not isinstance(value, object_type):
        raise ContractValidationError(f"{context} must be a {object_type.__name__}")


def _require_locator(value: object) -> None:
    if not isinstance(value, (RelationLocator, SqlArtifactDefinition)):
        raise ContractValidationError("dataset locator must be a relation or SQL artifact")


def _require_readiness(value: object) -> None:
    if not isinstance(value, (SqlArtifactDefinition, RelationManifestReadiness)):
        raise ContractValidationError(
            "consistency readiness must be a SQL artifact or relation manifest"
        )


def _require_check_scope_bindings(
    scope: ScopeDefinition,
    reference: DatasetDefinition,
    target: DatasetDefinition,
) -> None:
    parameters = {parameter.name: parameter.field for parameter in scope.parameters}
    datasets = {reference.dataset_id: reference, target.dataset_id: target}
    for binding in scope.bindings:
        dataset = datasets.get(binding.dataset_id)
        if dataset is None:
            raise ContractValidationError(
                f"scope binding dataset {binding.dataset_id!r} is outside the check"
            )
        parameter = parameters.get(binding.parameter)
        if parameter is None:
            raise ContractValidationError(
                f"scope binding parameter {binding.parameter!r} is not declared"
            )
        logical_names = tuple(
            projected.field_name
            for projected in dataset.projection
            if projected.column_name == binding.column
        )
        if len(logical_names) > 1:
            raise ContractValidationError(
                f"scope binding column {binding.column!r} maps to more than one field"
            )
        if not logical_names:
            continue
        fields = {field.name: field for field in dataset.logical_schema.schema.fields}
        if not _same_logical_type(fields[logical_names[0]], parameter):
            raise ContractValidationError(
                f"scope binding column {binding.column!r} type does not match its parameter"
            )


def _require_parameter_subset(
    expected: tuple[FieldSchema, ...],
    actual: tuple[FieldSchema, ...],
    context: str,
) -> None:
    expected_positions = {field.name: index for index, field in enumerate(expected)}
    last_position = -1
    for field in actual:
        position = expected_positions.get(field.name)
        if position is None or position <= last_position:
            raise ContractValidationError(
                f"{context} must be an ordered typed subset of scope parameters"
            )
        if not _same_logical_type(expected[position], field):
            raise ContractValidationError(
                f"{context} must be an ordered typed subset of scope parameters"
            )
        last_position = position


def _same_logical_type(left: FieldSchema, right: FieldSchema) -> bool:
    return (
        left.logical_type is right.logical_type
        and left.parameters == right.parameters
        and left.normalization is right.normalization
    )
