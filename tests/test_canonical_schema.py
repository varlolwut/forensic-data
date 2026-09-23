from typing import cast

import pytest

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    SchemaValidationError,
    canonical_schema_json,
    schema_digest,
    schema_digest_hex,
    schema_from_metadata_json,
)
from tests.canonical_vectors import load_canonical_vectors


def test_golden_schema_metadata_and_digests_are_exact_literals() -> None:
    for vector in load_canonical_vectors():
        schema = schema_from_metadata_json(vector.metadata_json)

        assert canonical_schema_json(schema) == vector.metadata_json
        assert schema_digest_hex(schema) == vector.schema_digest_hex
        assert schema_digest(schema) == bytes.fromhex(vector.schema_digest_hex)


def test_schema_json_preserves_scalars_and_uses_exact_escaping() -> None:
    metadata = (
        '{"protocol":"dfe_canon_v1","fields":[{'
        '"type":"string","parameters":{},"nullable":true,'
        '"normalization":"none","name":"z\\u0000😀\u2028\u2029\\b\\t\\n\\f\\r\\u001f/\\"\\\\"'
        "}]}"
    )

    schema = schema_from_metadata_json(metadata)

    assert canonical_schema_json(schema) == (
        '{"fields":[{"name":"z\\u0000😀\u2028\u2029\\b\\t\\n\\f\\r\\u001f/\\"\\\\",'
        '"normalization":"none","nullable":true,"parameters":{},"type":"string"}],'
        '"protocol":"dfe_canon_v1"}'
    )


@pytest.mark.parametrize(
    "metadata",
    (
        '{"protocol":"dfe_canon_v1","protocol":"dfe_canon_v1","fields":[]}',
        '{"protocol":"dfe_canon_v1","fields":[],"extra":0}',
        '{"protocol":"dfe_canon_v1","fields":[{"name":"x","type":"decimal",'
        '"nullable":false,"parameters":{"precision":3.0,"scale":0},'
        '"normalization":"none"}]}',
        '{"protocol":"dfe_canon_v1","fields":[{"name":"x","type":"decimal",'
        '"nullable":false,"parameters":{"precision":0,"scale":0},'
        '"normalization":"none"}]}',
        '{"protocol":"dfe_canon_v1","fields":[{"name":"x","type":"decimal",'
        '"nullable":false,"parameters":{"precision":NaN,"scale":0},'
        '"normalization":"none"}]}',
        '{"protocol":"dfe_canon_v1","fields":[{"name":"x","type":"int64",'
        '"nullable":false,"parameters":{"precision":1},"normalization":"none"}]}',
        '{"protocol":"dfe_canon_v1","fields":[{"name":"x","type":"binary",'
        '"nullable":false,"parameters":{},"normalization":"none"}]}',
        '{"protocol":"wrong","fields":[]}',
        '{"protocol":"dfe_canon_v1","fields":[{"name":"\\ud800","type":"string",'
        '"nullable":false,"parameters":{},"normalization":"none"}]}',
    ),
)
def test_invalid_schema_metadata_is_rejected(metadata: str) -> None:
    with pytest.raises(SchemaValidationError):
        schema_from_metadata_json(metadata)


def test_schema_runtime_boundaries_reject_non_json_and_protocol_impostor() -> None:
    with pytest.raises(SchemaValidationError, match="line=1"):
        schema_from_metadata_json("{")

    deeply_nested = (
        '{"protocol":"dfe_canon_v1","fields":' + ("[" * 10000) + "0" + ("]" * 10000) + "}"
    )
    with pytest.raises(SchemaValidationError, match="nesting exceeds"):
        schema_from_metadata_json(deeply_nested)

    protocol_impostor = cast(str, cast(object, _ProtocolImpostor()))
    with pytest.raises(SchemaValidationError, match="got_type=_ProtocolImpostor"):
        CanonicalSchema(protocol=protocol_impostor, fields=())


class _ProtocolImpostor:
    def __eq__(self, other: object) -> bool:
        return other == PROTOCOL
