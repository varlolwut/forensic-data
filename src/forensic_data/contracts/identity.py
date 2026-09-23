from forensic_data.canonical import PROTOCOL, DecimalParameters, FieldSchema, TimestampParameters
from forensic_data.contracts.model import (
    ConnectionDefinition,
    ConsistencyDefinition,
    DatasetDefinition,
    LogicalSchemaDefinition,
    RelationLocator,
    RowCheckDefinition,
    ScopeDefinition,
    SqlArtifactDefinition,
    SqlParameterDefinition,
)
from forensic_data.contracts.semantics import (
    SEMANTIC_DIGEST_PROTOCOL,
    SemanticValue,
    semantic_digest_hex,
)

_ROW_EQUIVALENCE = "row_equivalence"


def dataset_digest_hex(dataset: DatasetDefinition) -> str:
    return semantic_digest_hex(dataset_semantic_value(dataset))


def contract_digest_hex(config_version: int, check: RowCheckDefinition) -> str:
    return semantic_digest_hex(contract_semantic_value(config_version, check))


def dataset_semantic_value(dataset: DatasetDefinition) -> SemanticValue:
    return {
        "canonical_protocol": PROTOCOL,
        "dataset": _dataset_body_semantics(dataset),
        "semantic_protocol": SEMANTIC_DIGEST_PROTOCOL,
    }


def _dataset_body_semantics(dataset: DatasetDefinition) -> dict[str, SemanticValue]:
    return {
        "connection": _connection_semantics(dataset.connection),
        "dataset_id": dataset.dataset_id,
        "grain": list(dataset.grain),
        "locator": _locator_semantics(dataset.locator),
        "logical_schema": _schema_semantics(dataset.logical_schema),
        "projection": [
            {"column": item.column_name, "field": item.field_name} for item in dataset.projection
        ],
    }


def contract_semantic_value(config_version: int, check: RowCheckDefinition) -> SemanticValue:
    return {
        "assurance_policy": check.assurance_policy.value,
        "canonical_protocol": PROTOCOL,
        "config_version": config_version,
        "consistency": _consistency_semantics(check.consistency),
        "direction": {
            "reference": _dataset_body_semantics(check.reference),
            "target": _dataset_body_semantics(check.target),
        },
        "invariant": _ROW_EQUIVALENCE,
        "key": list(check.key),
        "logical_schema": _schema_semantics(check.comparison_schema),
        "scope": _scope_semantics(check.scope),
        "semantic_protocol": SEMANTIC_DIGEST_PROTOCOL,
    }


def sql_artifact_parameters_semantic_value(
    artifact: SqlArtifactDefinition,
) -> list[SemanticValue]:
    return sql_parameters_semantic_value(artifact.parameters)


def sql_parameters_semantic_value(
    parameters: tuple[SqlParameterDefinition, ...],
) -> list[SemanticValue]:
    return [_sql_parameter_semantics(value) for value in parameters]


def _connection_semantics(connection: ConnectionDefinition) -> SemanticValue:
    return {
        "adapter": connection.adapter.value,
        "connection_id": connection.connection_id,
        "driver": connection.driver,
        "profile": connection.profile,
    }


def _schema_semantics(schema: LogicalSchemaDefinition) -> SemanticValue:
    return {
        "equality": [value.value for value in schema.equality],
        "logical_schema_digest": schema.logical_schema_digest,
    }


def _locator_semantics(locator: RelationLocator | SqlArtifactDefinition) -> SemanticValue:
    if isinstance(locator, RelationLocator):
        return {
            "catalog": locator.catalog,
            "kind": "relation",
            "name": locator.name,
            "relation_scope": locator.relation_scope.value,
            "schema": locator.schema,
        }
    return {
        "content_sha256": locator.content_sha256,
        "dialect": locator.dialect.value,
        "kind": "sql",
        "parameters": sql_artifact_parameters_semantic_value(locator),
    }


def _sql_parameter_semantics(parameter: SqlParameterDefinition) -> SemanticValue:
    return {"name": parameter.name, "type": _field_type_semantics(parameter.field)}


def _field_type_semantics(field: FieldSchema) -> SemanticValue:
    parameters: SemanticValue
    if isinstance(field.parameters, DecimalParameters):
        parameters = {
            "precision": field.parameters.precision,
            "scale": field.parameters.scale,
        }
    elif isinstance(field.parameters, TimestampParameters):
        parameters = {"precision": field.parameters.precision}
    else:
        parameters = {}
    return {
        "kind": field.logical_type.value,
        "normalization": field.normalization.value,
        "parameters": parameters,
    }


def _scope_semantics(scope: ScopeDefinition) -> SemanticValue:
    return {
        "bindings": [
            {
                "column": binding.column,
                "dataset_id": binding.dataset_id,
                "operator": binding.operator.value,
                "parameter": binding.parameter,
            }
            for binding in scope.bindings
        ],
        "null_partition": scope.null_partition.value,
        "parameters": [
            {"name": parameter.name, "type": _field_type_semantics(parameter.field)}
            for parameter in scope.parameters
        ],
    }


def _consistency_semantics(consistency: ConsistencyDefinition) -> SemanticValue:
    return {
        "alignment_fields": list(consistency.alignment_fields),
        "datasets": [
            {
                "dataset_id": item.dataset_id,
                "readiness": _locator_semantics(item.readiness),
                "stable_read": item.stable_read.value,
            }
            for item in consistency.datasets
        ],
        "late_arrivals": consistency.late_arrivals.value,
        "minimum_evidence": consistency.minimum_evidence.value,
    }
