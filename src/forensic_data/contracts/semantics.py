import hashlib
import json
from typing import Final, Literal, Never, cast

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


def semantic_value_from_json(metadata_json: str) -> SemanticValue:
    if type(metadata_json) is not str:
        raise ContractValidationError("semantic metadata JSON must be a string")
    try:
        parsed = cast(
            object,
            json.loads(
                metadata_json,
                object_pairs_hook=_object_without_duplicate_keys,
                parse_float=_reject_json_float,
                parse_int=_parse_json_integer,
                parse_constant=_reject_json_constant,
            ),
        )
    except json.JSONDecodeError as error:
        raise ContractValidationError(
            "semantic metadata is not valid JSON: "
            f"line={error.lineno}, column={error.colno}, reason={error.msg}"
        ) from None
    except RecursionError:
        raise ContractValidationError(
            "semantic metadata JSON nesting exceeds the parser limit"
        ) from None
    value = cast(SemanticValue, parsed)
    _validate_semantic_value(value, "semantic metadata")
    return value


def canonicalize_semantic_json(metadata_json: str) -> str:
    return canonical_semantic_json(semantic_value_from_json(metadata_json))


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


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractValidationError(
                f"semantic metadata JSON contains duplicate object key {key!r}"
            )
        result[key] = value
    return result


def _reject_json_float(token: str) -> Never:
    raise ContractValidationError(
        f"semantic metadata JSON numbers must be exact integers, got {token!r}"
    )


def _parse_json_integer(token: str) -> int:
    try:
        return int(token)
    except ValueError:
        raise ContractValidationError(
            f"semantic metadata JSON integer is too large to validate: digits={len(token)}"
        ) from None


def _reject_json_constant(token: str) -> Never:
    raise ContractValidationError(
        f"semantic metadata JSON does not permit non-finite number {token!r}"
    )


def _validate_unicode_scalars(value: str, context: str) -> None:
    for index, character in enumerate(value):
        code_point = ord(character)
        if 0xD800 <= code_point <= 0xDFFF:
            raise ContractValidationError(
                f"{context} contains a surrogate code point at character {index}"
            )
