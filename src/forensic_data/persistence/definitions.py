from forensic_data.canonical import PROTOCOL, canonical_schema_json
from forensic_data.contracts.identity import (
    contract_semantic_value,
    dataset_semantic_value,
    sql_parameters_semantic_value,
)
from forensic_data.contracts.model import (
    CapturePolicy,
    ConsistencyDatasetDefinition,
    DatasetDefinition,
    EvidenceDefinition,
    RelationLocator,
    RowCheckDefinition,
    SqlArtifactDefinition,
)
from forensic_data.contracts.semantics import (
    SEMANTIC_DIGEST_PROTOCOL,
    SemanticValue,
    canonical_semantic_json,
    semantic_value_from_json,
)
from forensic_data.persistence.model import (
    ArtifactDirection,
    ArtifactPurpose,
    CodeArtifactCaptureDefinition,
    CodeCaptureState,
    ContractVersionDefinition,
    DatasetLocatorKind,
    DatasetVersionDefinition,
    MetadataRegistrationDefinition,
    sql_capture_disabled_reason,
)


def build_metadata_registration_definition(
    config_version: int,
    check: RowCheckDefinition,
    evidence: EvidenceDefinition,
) -> MetadataRegistrationDefinition:
    if type(config_version) is not int or config_version != 1:
        raise ValueError("metadata registration config version must be exactly 1")
    reference = dataset_version_definition(check.reference)
    target = dataset_version_definition(check.target)
    contract = contract_version_definition(config_version, check)
    code_artifacts = code_artifact_capture_definitions(check, evidence)
    return MetadataRegistrationDefinition(
        reference_dataset=reference,
        target_dataset=target,
        contract=contract,
        code_artifacts=code_artifacts,
    )


def dataset_version_definition(dataset: DatasetDefinition) -> DatasetVersionDefinition:
    semantic_value = dataset_semantic_value(dataset)
    semantic_payload_json = canonical_semantic_json(semantic_value)
    if isinstance(dataset.locator, RelationLocator):
        locator_kind = DatasetLocatorKind.RELATION
        relation_scope = dataset.locator.relation_scope
    else:
        locator_kind = DatasetLocatorKind.SQL
        relation_scope = None
    return DatasetVersionDefinition(
        dataset_id=dataset.dataset_id,
        semantic_digest=dataset.semantic_digest,
        semantic_protocol=SEMANTIC_DIGEST_PROTOCOL,
        canonical_protocol=PROTOCOL,
        logical_schema_digest=dataset.logical_schema.logical_schema_digest,
        connection_id=dataset.connection.connection_id,
        adapter=dataset.connection.adapter,
        driver=dataset.connection.driver,
        profile=dataset.connection.profile,
        locator_kind=locator_kind,
        relation_scope=relation_scope,
        semantic_payload_json=semantic_payload_json,
        resolved_definition_json=_dataset_resolved_definition_json(dataset, semantic_value),
    )


def contract_version_definition(
    config_version: int,
    check: RowCheckDefinition,
) -> ContractVersionDefinition:
    if type(config_version) is not int or config_version != 1:
        raise ValueError("contract version config version must be exactly 1")
    semantic_value = contract_semantic_value(config_version, check)
    semantic_payload_json = canonical_semantic_json(semantic_value)
    return ContractVersionDefinition(
        check_id=check.check_id,
        revision=check.revision,
        config_version=config_version,
        semantic_digest=check.contract_digest,
        semantic_protocol=SEMANTIC_DIGEST_PROTOCOL,
        canonical_protocol=PROTOCOL,
        comparison_schema_digest=check.comparison_schema.logical_schema_digest,
        reference_dataset_id=check.reference.dataset_id,
        reference_dataset_digest=check.reference.semantic_digest,
        target_dataset_id=check.target.dataset_id,
        target_dataset_digest=check.target.semantic_digest,
        assurance_policy=check.assurance_policy,
        semantic_payload_json=semantic_payload_json,
        resolved_definition_json=_contract_resolved_definition_json(check, semantic_value),
    )


def code_artifact_capture_definitions(
    check: RowCheckDefinition,
    evidence: EvidenceDefinition,
) -> tuple[CodeArtifactCaptureDefinition, ...]:
    definitions: list[CodeArtifactCaptureDefinition] = []
    for direction, dataset in (
        (ArtifactDirection.REFERENCE, check.reference),
        (ArtifactDirection.TARGET, check.target),
    ):
        if isinstance(dataset.locator, SqlArtifactDefinition):
            definitions.append(
                _code_artifact_capture_definition(
                    direction,
                    ArtifactPurpose.PROJECTION,
                    dataset.dataset_id,
                    check,
                    dataset.locator,
                    evidence.sql_capture,
                )
            )
    for direction, consistency_dataset in zip(
        (ArtifactDirection.REFERENCE, ArtifactDirection.TARGET),
        check.consistency.datasets,
        strict=True,
    ):
        definitions.append(
            _readiness_capture_definition(
                direction,
                consistency_dataset,
                check,
                evidence.sql_capture,
            )
        )
    return tuple(definitions)


def code_artifact_parameters_json(definition: CodeArtifactCaptureDefinition) -> str:
    return canonical_semantic_json(sql_parameters_semantic_value(definition.parameters))


def code_artifact_descriptor_json(definition: CodeArtifactCaptureDefinition) -> str:
    descriptor: SemanticValue = {
        "dataset_id": definition.dataset_id,
        "descriptor_version": 1,
        "direction": definition.direction.value,
        "purpose": definition.purpose.value,
    }
    return canonical_semantic_json(descriptor)


def code_artifact_provenance_json(definition: CodeArtifactCaptureDefinition) -> str:
    provenance: SemanticValue = {
        "check_id": definition.check_id,
        "provenance_version": 1,
        "revision": definition.revision,
        "source": "contract",
    }
    return canonical_semantic_json(provenance)


def _readiness_capture_definition(
    direction: ArtifactDirection,
    consistency_dataset: ConsistencyDatasetDefinition,
    check: RowCheckDefinition,
    capture_policy: CapturePolicy,
) -> CodeArtifactCaptureDefinition:
    return _code_artifact_capture_definition(
        direction,
        ArtifactPurpose.READINESS,
        consistency_dataset.dataset_id,
        check,
        consistency_dataset.readiness,
        capture_policy,
    )


def _code_artifact_capture_definition(
    direction: ArtifactDirection,
    purpose: ArtifactPurpose,
    dataset_id: str,
    check: RowCheckDefinition,
    artifact: SqlArtifactDefinition,
    capture_policy: CapturePolicy,
) -> CodeArtifactCaptureDefinition:
    content_bytes = artifact.content.encode("utf-8", errors="strict")
    if capture_policy is CapturePolicy.ENABLED:
        capture_state = CodeCaptureState.RETAINED
        retained_content: bytes | None = content_bytes
        omission_reason: str | None = None
    elif capture_policy is CapturePolicy.DISABLED:
        capture_state = CodeCaptureState.NOT_RETAINED
        retained_content = None
        omission_reason = sql_capture_disabled_reason()
    else:
        raise ValueError(f"unsupported SQL capture policy {capture_policy!r}")
    return CodeArtifactCaptureDefinition(
        direction=direction,
        purpose=purpose,
        dataset_id=dataset_id,
        check_id=check.check_id,
        revision=check.revision,
        dialect=artifact.dialect,
        parameters=artifact.parameters,
        content_sha256=artifact.content_sha256,
        source_byte_length=len(content_bytes),
        capture_state=capture_state,
        content_bytes=retained_content,
        omission_reason=omission_reason,
    )


def _dataset_resolved_definition_json(
    dataset: DatasetDefinition,
    semantic_payload: SemanticValue,
) -> str:
    resolved: SemanticValue = {
        "definition_version": 1,
        "kind": "dataset",
        "logical_schema": semantic_value_from_json(
            canonical_schema_json(dataset.logical_schema.schema)
        ),
        "semantic_payload": semantic_payload,
    }
    return canonical_semantic_json(resolved)


def _contract_resolved_definition_json(
    check: RowCheckDefinition,
    semantic_payload: SemanticValue,
) -> str:
    resolved: SemanticValue = {
        "check_id": check.check_id,
        "comparison_schema": semantic_value_from_json(
            canonical_schema_json(check.comparison_schema.schema)
        ),
        "definition_version": 1,
        "kind": "row_contract",
        "revision": check.revision,
        "semantic_payload": semantic_payload,
    }
    return canonical_semantic_json(resolved)
