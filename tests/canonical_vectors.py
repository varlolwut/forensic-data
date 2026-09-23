import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast, final

from forensic_data.canonical import Sha256Limbs


@final
@dataclass(frozen=True, slots=True)
class GoldenVector:
    name: str
    kind: str
    classification: str
    metadata_json: str
    values: tuple[str | bool, ...]
    schema_digest_hex: str
    envelope_ascii: str
    envelope_hex: str
    sha256_hex: str
    limbs: Sha256Limbs
    segment_prefixes: dict[int, int]
    duplicate_twice_count: int | None
    duplicate_twice_limb_sums: Sha256Limbs | None


def load_canonical_vectors() -> tuple[GoldenVector, ...]:
    fixture_path = Path(__file__).parent / "golden" / "canonical_v1.json"
    parsed = cast(object, json.loads(fixture_path.read_text(encoding="utf-8")))
    root = _require_object(parsed, "golden fixture root")
    if _require_integer(root.get("version"), "golden fixture version") != 1:
        raise ValueError("golden fixture version must be exactly 1")
    vectors = _require_array(root.get("vectors"), "golden fixture vectors")
    return tuple(_parse_vector(value, index) for index, value in enumerate(vectors))


def vector_named(name: str) -> GoldenVector:
    matching = tuple(vector for vector in load_canonical_vectors() if vector.name == name)
    if len(matching) != 1:
        raise ValueError(f"expected exactly one golden vector named {name!r}, got {len(matching)}")
    return matching[0]


def _parse_vector(value: object, index: int) -> GoldenVector:
    context = f"golden vector at index {index}"
    vector = _require_object(value, context)
    duplicate_value = vector.get("duplicate_twice_fingerprint")
    duplicate_count: int | None = None
    duplicate_limb_sums: Sha256Limbs | None = None
    if duplicate_value is not None:
        duplicate = _require_object(duplicate_value, f"{context} duplicate fingerprint")
        duplicate_count = _require_integer(duplicate.get("count"), f"{context} duplicate count")
        duplicate_limb_sums = _require_limbs(
            duplicate.get("limb_sums"), f"{context} duplicate limb sums"
        )
    return GoldenVector(
        name=_require_string(vector.get("name"), f"{context} name"),
        kind=_require_string(vector.get("kind"), f"{context} kind"),
        classification=_require_string(vector.get("classification"), f"{context} classification"),
        metadata_json=_require_string(vector.get("metadata_json"), f"{context} metadata JSON"),
        values=_require_values(vector.get("values"), f"{context} values"),
        schema_digest_hex=_require_string(
            vector.get("schema_digest_hex"), f"{context} schema digest"
        ),
        envelope_ascii=_require_string(vector.get("envelope_ascii"), f"{context} envelope ASCII"),
        envelope_hex=_require_string(vector.get("envelope_hex"), f"{context} envelope hex"),
        sha256_hex=_require_string(vector.get("sha256_hex"), f"{context} SHA-256"),
        limbs=_require_limbs(vector.get("limbs"), f"{context} limbs"),
        segment_prefixes=_require_segment_prefixes(
            vector.get("segment_prefixes"), f"{context} segment prefixes"
        ),
        duplicate_twice_count=duplicate_count,
        duplicate_twice_limb_sums=duplicate_limb_sums,
    )


def _require_object(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError(f"{context} must be an object")
    return cast(dict[str, object], value)


def _require_array(value: object, context: str) -> list[object]:
    if type(value) is not list:
        raise TypeError(f"{context} must be an array")
    return cast(list[object], value)


def _require_string(value: object, context: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{context} must be a string")
    return value


def _require_integer(value: object, context: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{context} must be an integer")
    return value


def _require_values(value: object, context: str) -> tuple[str | bool, ...]:
    result: list[str | bool] = []
    for index, item in enumerate(_require_array(value, context)):
        if type(item) not in (str, bool):
            raise TypeError(f"{context} item {index} must be a string or boolean")
        result.append(cast(str | bool, item))
    return tuple(result)


def _require_limbs(value: object, context: str) -> Sha256Limbs:
    items = tuple(_require_integer(item, context) for item in _require_array(value, context))
    if len(items) != 8:
        raise ValueError(f"{context} must have exactly eight values")
    return (
        items[0],
        items[1],
        items[2],
        items[3],
        items[4],
        items[5],
        items[6],
        items[7],
    )


def _require_segment_prefixes(value: object, context: str) -> dict[int, int]:
    raw = _require_object(value, context)
    result: dict[int, int] = {}
    for depth_text, prefix_value in raw.items():
        try:
            depth = int(depth_text)
        except ValueError as error:
            raise ValueError(f"{context} depth is not an integer: {depth_text!r}") from error
        result[depth] = _require_integer(prefix_value, f"{context} depth {depth}")
    return result
