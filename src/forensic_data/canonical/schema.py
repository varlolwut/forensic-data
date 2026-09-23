import hashlib
import json
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Never, cast, final

from forensic_data.canonical.model import (
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
    SchemaValidationError,
    TimestampParameters,
)

_SCHEMA_KEYS = frozenset(("protocol", "fields"))
_FIELD_KEYS = frozenset(("name", "type", "nullable", "parameters", "normalization"))
_DECIMAL_PARAMETER_KEYS = frozenset(("precision", "scale"))
_TIMESTAMP_PARAMETER_KEYS = frozenset(("precision",))
_ROW_PREFIX = "DFE1R"
_KEY_PREFIX = "DFE1K"


@final
@dataclass(frozen=True, slots=True)
class CanonicalEnvelopeContext:
    schema: CanonicalSchema
    metadata_json: str = dataclass_field(init=False)
    schema_digest: bytes = dataclass_field(init=False)
    schema_digest_hex: str = dataclass_field(init=False)
    row_header: str = dataclass_field(init=False)
    key_header: str = dataclass_field(init=False)

    def __post_init__(self) -> None:
        validated_schema = _require_schema(self.schema)
        metadata_json = canonical_schema_json(validated_schema)
        digest = _metadata_digest(metadata_json)
        digest_hex = digest.hex()
        header_suffix = f"{digest_hex}{len(validated_schema.fields):08x}"
        object.__setattr__(self, "metadata_json", metadata_json)
        object.__setattr__(self, "schema_digest", digest)
        object.__setattr__(self, "schema_digest_hex", digest_hex)
        object.__setattr__(self, "row_header", f"{_ROW_PREFIX}{header_suffix}")
        object.__setattr__(self, "key_header", f"{_KEY_PREFIX}{header_suffix}")


def prepare_envelope_context(schema: CanonicalSchema) -> CanonicalEnvelopeContext:
    return CanonicalEnvelopeContext(schema=schema)


def schema_from_metadata_json(metadata_json: str) -> CanonicalSchema:
    if type(metadata_json) is not str:
        raise SchemaValidationError("schema metadata JSON must be a string")
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
        raise SchemaValidationError(
            "schema metadata is not valid JSON: "
            f"line={error.lineno}, column={error.colno}, reason={error.msg}"
        ) from error
    except RecursionError as error:
        raise SchemaValidationError(
            "schema metadata JSON nesting exceeds the parser limit"
        ) from error

    metadata = _require_object(parsed, "schema metadata")
    _require_exact_keys(metadata, _SCHEMA_KEYS, "schema metadata")

    protocol = metadata["protocol"]
    if type(protocol) is not str:
        raise SchemaValidationError("schema metadata protocol must be a string")
    fields_value = metadata["fields"]
    if type(fields_value) is not list:
        raise SchemaValidationError("schema metadata fields must be an array")
    fields_array = cast(list[object], fields_value)

    fields = tuple(_field_from_json_value(field, index) for index, field in enumerate(fields_array))
    return CanonicalSchema(protocol=protocol, fields=fields)


def canonical_schema_json(schema: CanonicalSchema) -> str:
    schema = _require_schema(schema)
    fields: list[dict[str, object]] = []
    for field in schema.fields:
        fields.append(
            {
                "name": field.name,
                "type": field.logical_type.value,
                "nullable": field.nullable,
                "parameters": _parameters_metadata(field),
                "normalization": field.normalization.value,
            }
        )
    metadata: dict[str, object] = {"protocol": schema.protocol, "fields": fields}
    return json.dumps(
        metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def schema_digest(schema: CanonicalSchema) -> bytes:
    return _metadata_digest(canonical_schema_json(schema))


def schema_digest_hex(schema: CanonicalSchema) -> str:
    return schema_digest(schema).hex()


def _metadata_digest(metadata_json: str) -> bytes:
    return hashlib.sha256(metadata_json.encode("utf-8")).digest()


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaValidationError(
                f"schema metadata JSON contains duplicate object key {key!r}"
            )
        result[key] = value
    return result


def _reject_json_float(token: str) -> Never:
    raise SchemaValidationError(
        f"schema metadata JSON numbers must be exact integers, got {token!r}"
    )


def _parse_json_integer(token: str) -> int:
    try:
        return int(token)
    except ValueError as error:
        raise SchemaValidationError(
            f"schema metadata JSON integer is too large to validate: digits={len(token)}"
        ) from error


def _reject_json_constant(token: str) -> Never:
    raise SchemaValidationError(f"schema metadata JSON does not permit non-finite number {token!r}")


def _require_object(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict:
        raise SchemaValidationError(f"{context} must be an object")
    return cast(dict[str, object], value)


def _require_exact_keys(value: dict[str, object], expected: frozenset[str], context: str) -> None:
    actual = frozenset(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    raise SchemaValidationError(
        f"{context} keys do not match canonical protocol v1: missing={missing!r}, extra={extra!r}"
    )


def _field_from_json_value(value: object, index: int) -> FieldSchema:
    context = f"schema field at index {index}"
    field = _require_object(value, context)
    _require_exact_keys(field, _FIELD_KEYS, context)

    name = field["name"]
    if type(name) is not str:
        raise SchemaValidationError(f"{context} name must be a string")
    logical_type_value = field["type"]
    if type(logical_type_value) is not str:
        raise SchemaValidationError(f"{context} type must be a string")
    try:
        logical_type = LogicalType(logical_type_value)
    except ValueError as error:
        raise SchemaValidationError(
            f"{context} has unsupported logical type {logical_type_value!r}"
        ) from error

    nullable = field["nullable"]
    if type(nullable) is not bool:
        raise SchemaValidationError(f"{context} nullable must be a boolean")
    normalization_value = field["normalization"]
    if normalization_value != Normalization.NONE.value:
        raise SchemaValidationError(f"{context} normalization must be exactly 'none'")
    parameters = _parameters_from_json_value(logical_type, field["parameters"], context)
    return FieldSchema(
        name=name,
        logical_type=logical_type,
        nullable=nullable,
        parameters=parameters,
        normalization=Normalization.NONE,
    )


def _parameters_from_json_value(
    logical_type: LogicalType, value: object, context: str
) -> NoParameters | DecimalParameters | TimestampParameters:
    parameters = _require_object(value, f"{context} parameters")
    if logical_type is LogicalType.DECIMAL:
        _require_exact_keys(parameters, _DECIMAL_PARAMETER_KEYS, f"{context} parameters")
        return DecimalParameters(
            precision=_require_integer(parameters["precision"], f"{context} decimal precision"),
            scale=_require_integer(parameters["scale"], f"{context} decimal scale"),
        )
    if logical_type in (
        LogicalType.TIMESTAMP_LOCAL,
        LogicalType.TIMESTAMP_INSTANT,
    ):
        _require_exact_keys(parameters, _TIMESTAMP_PARAMETER_KEYS, f"{context} parameters")
        return TimestampParameters(
            precision=_require_integer(parameters["precision"], f"{context} timestamp precision")
        )
    _require_exact_keys(parameters, frozenset(), f"{context} parameters")
    return NoParameters()


def _require_integer(value: object, context: str) -> int:
    if type(value) is not int:
        raise SchemaValidationError(f"{context} must be an exact integer")
    return value


def _parameters_metadata(field: FieldSchema) -> dict[str, object]:
    parameters = field.parameters
    if isinstance(parameters, DecimalParameters):
        return {"precision": parameters.precision, "scale": parameters.scale}
    if isinstance(parameters, TimestampParameters):
        return {"precision": parameters.precision}
    return {}


def _require_schema(schema: object) -> CanonicalSchema:
    if not isinstance(schema, CanonicalSchema):
        raise SchemaValidationError("schema must be a CanonicalSchema")
    return schema
