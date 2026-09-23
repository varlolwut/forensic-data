import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from forensic_data.contracts import load_contract_config
from forensic_data.contracts.semantics import (
    SemanticValue,
    canonical_semantic_json,
    semantic_value_from_json,
)
from forensic_data.persistence import (
    ContractVersionDefinition,
    DatasetVersionDefinition,
    MetadataRegistrationDefinition,
    build_metadata_registration_definition,
)

_EXAMPLE_CONTRACT = Path(__file__).parent.parent / "examples/postgres-row/contract.yaml"


def test_metadata_definition_rejects_inconsistent_identity_closure() -> None:
    config = load_contract_config(_EXAMPLE_CONTRACT)
    definition = build_metadata_registration_definition(
        config.version,
        config.checks[0],
        config.evidence,
    )
    with pytest.raises(ValueError, match="connection"):
        replace(definition.reference_dataset, connection_id="different-connection")
    with pytest.raises(ValueError, match="artifact"):
        MetadataRegistrationDefinition(
            reference_dataset=definition.reference_dataset,
            target_dataset=definition.target_dataset,
            contract=definition.contract,
            code_artifacts=(
                replace(definition.code_artifacts[0], content_sha256="0" * 64),
                *definition.code_artifacts[1:],
            ),
        )


def test_metadata_definition_rejects_malformed_nested_semantics() -> None:
    config = load_contract_config(_EXAMPLE_CONTRACT)
    definition = build_metadata_registration_definition(
        config.version,
        config.checks[0],
        config.evidence,
    )

    dataset_payload = _semantic_object(definition.reference_dataset.semantic_payload_json)
    dataset_body = _semantic_object_value(dataset_payload["dataset"], "dataset")
    invalid_dataset_body = dict(dataset_body)
    invalid_dataset_body["projection"] = [{"field": "order_id"}]
    invalid_dataset_payload = dict(dataset_payload)
    invalid_dataset_payload["dataset"] = invalid_dataset_body
    with pytest.raises(ValueError, match="projection"):
        _dataset_with_semantic_payload(
            definition.reference_dataset,
            invalid_dataset_payload,
        )

    invalid_grain_body = dict(dataset_body)
    invalid_grain_body["grain"] = [123]
    invalid_grain_payload = dict(dataset_payload)
    invalid_grain_payload["dataset"] = invalid_grain_body
    with pytest.raises(ValueError, match="grain"):
        _dataset_with_semantic_payload(
            definition.reference_dataset,
            invalid_grain_payload,
        )

    logical_schema = _semantic_object_value(dataset_body["logical_schema"], "logical schema")
    invalid_logical_schema = dict(logical_schema)
    invalid_equality: list[SemanticValue] = ["unsupported"] * len(
        _semantic_array_value(logical_schema["equality"], "logical schema equality")
    )
    invalid_logical_schema["equality"] = invalid_equality
    invalid_equality_body = dict(dataset_body)
    invalid_equality_body["logical_schema"] = invalid_logical_schema
    invalid_equality_payload = dict(dataset_payload)
    invalid_equality_payload["dataset"] = invalid_equality_body
    with pytest.raises(ValueError, match="equality"):
        _dataset_with_semantic_payload(
            definition.reference_dataset,
            invalid_equality_payload,
        )

    contract_payload = _semantic_object(definition.contract.semantic_payload_json)
    invalid_key_payload = dict(contract_payload)
    invalid_key_payload["key"] = [123]
    with pytest.raises(ValueError, match="key"):
        _contract_with_semantic_payload(definition.contract, invalid_key_payload)

    invalid_scope_payload = dict(contract_payload)
    invalid_scope_payload["scope"] = None
    with pytest.raises(ValueError, match="scope"):
        _contract_with_semantic_payload(definition.contract, invalid_scope_payload)

    consistency = _semantic_object_value(contract_payload["consistency"], "consistency")
    invalid_consistency = dict(consistency)
    invalid_consistency["late_arrivals"] = "unsupported"
    invalid_consistency_payload = dict(contract_payload)
    invalid_consistency_payload["consistency"] = invalid_consistency
    with pytest.raises(ValueError, match="late arrivals"):
        _contract_with_semantic_payload(
            definition.contract,
            invalid_consistency_payload,
        )


def _dataset_with_semantic_payload(
    definition: DatasetVersionDefinition,
    payload: dict[str, SemanticValue],
) -> DatasetVersionDefinition:
    payload_json = canonical_semantic_json(payload)
    resolved = _semantic_object(definition.resolved_definition_json)
    resolved["semantic_payload"] = payload
    return replace(
        definition,
        semantic_digest=hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
        semantic_payload_json=payload_json,
        resolved_definition_json=canonical_semantic_json(resolved),
    )


def _contract_with_semantic_payload(
    definition: ContractVersionDefinition,
    payload: dict[str, SemanticValue],
) -> ContractVersionDefinition:
    payload_json = canonical_semantic_json(payload)
    resolved = _semantic_object(definition.resolved_definition_json)
    resolved["semantic_payload"] = payload
    return replace(
        definition,
        semantic_digest=hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
        semantic_payload_json=payload_json,
        resolved_definition_json=canonical_semantic_json(resolved),
    )


def _semantic_object(value: str) -> dict[str, SemanticValue]:
    return _semantic_object_value(semantic_value_from_json(value), "semantic payload")


def _semantic_object_value(
    value: SemanticValue,
    context: str,
) -> dict[str, SemanticValue]:
    if type(value) is not dict:
        raise AssertionError(f"{context} must be an object")
    return value


def _semantic_array_value(value: SemanticValue, context: str) -> list[SemanticValue]:
    if type(value) is not list:
        raise AssertionError(f"{context} must be an array")
    return value
