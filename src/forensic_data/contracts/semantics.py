import hashlib
import json
from typing import Final, Literal

from forensic_data.contracts.errors import ContractValidationError

SEMANTIC_DIGEST_PROTOCOL: Final[Literal["dfe_semantic_v1"]] = "dfe_semantic_v1"

type SemanticScalar = bool | int | str | None
type SemanticValue = (
    SemanticScalar
    | tuple["SemanticValue", ...]
    | list["SemanticValue"]
    | dict[str, "SemanticValue"]
)


def canonical_semantic_json(value: SemanticValue) -> str:
    _validate_semantic_value(value, "semantic metadata")
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def semantic_digest_hex(value: SemanticValue) -> str:
    metadata = canonical_semantic_json(value).encode("utf-8")
    return hashlib.sha256(metadata).hexdigest()


def _validate_semantic_value(value: SemanticValue, context: str) -> None:
    if value is None or type(value) in (bool, int):
        return
    if type(value) is str:
        _validate_unicode_scalars(value, context)
        return
    if isinstance(value, tuple):
        for index, item in enumerate(value):
            _validate_semantic_value(item, f"{context}[{index}]")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_semantic_value(item, f"{context}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise ContractValidationError(f"{context} object keys must be strings")
            _validate_unicode_scalars(key, f"{context} object key")
            _validate_semantic_value(item, f"{context}.{key}")
        return
    raise ContractValidationError(
        f"{context} contains unsupported value type {type(value).__name__}; "
        "only null, booleans, exact integers, strings, arrays, and objects are permitted"
    )


def _validate_unicode_scalars(value: str, context: str) -> None:
    for index, character in enumerate(value):
        code_point = ord(character)
        if 0xD800 <= code_point <= 0xDFFF:
            raise ContractValidationError(
                f"{context} contains a surrogate code point at character {index}"
            )
