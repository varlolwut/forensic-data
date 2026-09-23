import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import cast

from forensic_data.canonical.model import (
    INT64_MAX,
    UINT64_MAX,
    CanonicalInput,
    CanonicalSchema,
    DecimalParameters,
    DecodedValue,
    FieldSchema,
    FrameValidationError,
    LogicalType,
    NullKeyError,
    PayloadValidationError,
    SchemaValidationError,
    TimestampParameters,
)
from forensic_data.canonical.schema import schema_digest_hex

_ROW_PREFIX = "DFE1R"
_KEY_PREFIX = "DFE1K"
_ENVELOPE_HEADER_LENGTH = 5 + 64 + 8
_FIELD_HEADER_LENGTH = 2 + 1 + 16
_CANONICAL_INTEGER = re.compile(r"(?:0|-?[1-9][0-9]*)\Z", re.ASCII)
_EXACT_DATE = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})\Z",
    re.ASCII,
)
_LOCAL_TIMESTAMP = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?\Z",
    re.ASCII,
)
_INSTANT_TIMESTAMP = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<offset>Z|[+-][0-9]{2}:[0-9]{2})\Z",
    re.ASCII,
)
_DECIMAL_INPUT = re.compile(
    r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z",
    re.ASCII,
)
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_LOWER_HEX_8 = re.compile(r"[0-9a-f]{8}\Z", re.ASCII)
_LOWER_HEX_16 = re.compile(r"[0-9a-f]{16}\Z", re.ASCII)
_LOWER_HEX_PAYLOAD = re.compile(r"(?:[0-9a-f]{2})*\Z", re.ASCII)


@dataclass(frozen=True, slots=True)
class _ParsedField:
    payload: bytes | None


def encode_payload(field: FieldSchema, value: CanonicalInput) -> bytes:
    _require_field(field)
    logical_type = field.logical_type
    if logical_type is LogicalType.INT64:
        return _encode_int64(value)
    if logical_type is LogicalType.DECIMAL:
        parameters = field.parameters
        if not isinstance(parameters, DecimalParameters):
            raise SchemaValidationError("decimal field parameters are inconsistent")
        return _encode_decimal(value, parameters)
    if logical_type is LogicalType.BOOLEAN:
        return _encode_boolean(value)
    if logical_type is LogicalType.STRING:
        return _encode_string(value)
    if logical_type is LogicalType.DATE:
        return _encode_date(value)
    parameters = field.parameters
    if not isinstance(parameters, TimestampParameters):
        raise SchemaValidationError("timestamp field parameters are inconsistent")
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        return _encode_timestamp_local(value, parameters.precision)
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        return _encode_timestamp_instant(value, parameters.precision)
    raise SchemaValidationError(f"unsupported logical type {logical_type!r}")


def decode_payload(field: FieldSchema, payload: bytes) -> DecodedValue:
    _require_field(field)
    if type(payload) is not bytes:
        raise PayloadValidationError("canonical payload must be bytes")
    logical_type = field.logical_type
    if logical_type is LogicalType.INT64:
        return _decode_int64(payload)
    if logical_type is LogicalType.DECIMAL:
        parameters = field.parameters
        if not isinstance(parameters, DecimalParameters):
            raise SchemaValidationError("decimal field parameters are inconsistent")
        return _decode_decimal(payload, parameters)
    if logical_type is LogicalType.BOOLEAN:
        return _decode_boolean(payload)
    if logical_type is LogicalType.STRING:
        return _decode_string(payload)
    if logical_type is LogicalType.DATE:
        return _decode_date(payload)
    parameters = field.parameters
    if not isinstance(parameters, TimestampParameters):
        raise SchemaValidationError("timestamp field parameters are inconsistent")
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        return _decode_timestamp_local(payload, parameters.precision)
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        return _decode_timestamp_instant(payload, parameters.precision)
    raise SchemaValidationError(f"unsupported logical type {logical_type!r}")


def encode_row(schema: CanonicalSchema, values: Sequence[CanonicalInput | None]) -> bytes:
    _require_values(schema, values)
    frames: list[str] = []
    for field, value in zip(schema.fields, values, strict=True):
        if value is None:
            if not field.nullable:
                raise PayloadValidationError(f"nonnull row field {field.name!r} cannot encode NULL")
            frames.append(_null_frame(field))
        else:
            frames.append(_present_frame(field, encode_payload(field, value)))
    return (_envelope_header(_ROW_PREFIX, schema) + "".join(frames)).encode("ascii")


def encode_key(schema: CanonicalSchema, values: Sequence[CanonicalInput | None]) -> bytes:
    _require_values(schema, values)
    frames: list[str] = []
    for field, value in zip(schema.fields, values, strict=True):
        if value is None:
            raise NullKeyError(f"key field {field.name!r} cannot be NULL")
        frames.append(_present_frame(field, encode_payload(field, value)))
    return (_envelope_header(_KEY_PREFIX, schema) + "".join(frames)).encode("ascii")


def decode_row(schema: CanonicalSchema, envelope: bytes) -> tuple[DecodedValue | None, ...]:
    parsed_fields = _parse_envelope(schema, envelope, _ROW_PREFIX)
    values: list[DecodedValue | None] = []
    for field, parsed in zip(schema.fields, parsed_fields, strict=True):
        if parsed.payload is None:
            if not field.nullable:
                raise FrameValidationError(f"nonnull row field {field.name!r} has a NULL frame")
            values.append(None)
        else:
            values.append(decode_payload(field, parsed.payload))
    return tuple(values)


def decode_key(schema: CanonicalSchema, envelope: bytes) -> tuple[DecodedValue, ...]:
    parsed_fields = _parse_envelope(schema, envelope, _KEY_PREFIX)
    values: list[DecodedValue] = []
    for field, parsed in zip(schema.fields, parsed_fields, strict=True):
        if parsed.payload is None:
            raise NullKeyError(f"key field {field.name!r} has a NULL frame")
        values.append(decode_payload(field, parsed.payload))
    return tuple(values)


def _encode_int64(value: CanonicalInput) -> bytes:
    if type(value) is not int:
        raise PayloadValidationError(f"int64 requires a native integer, got {type(value).__name__}")
    if not -(1 << 63) <= value <= INT64_MAX:
        raise PayloadValidationError(
            "int64 value is outside signed 64-bit range: "
            f"negative={value < 0}, bit_length={abs(value).bit_length()}"
        )
    return str(value).encode("ascii")


def _decode_int64(payload: bytes) -> int:
    text = _decode_ascii(payload, "int64")
    if _CANONICAL_INTEGER.fullmatch(text) is None:
        raise PayloadValidationError(f"int64 payload is not canonical: byte_length={len(payload)}")
    negative = text.startswith("-")
    absolute_digits = text[1:] if negative else text
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(absolute_digits) > len(limit) or (
        len(absolute_digits) == len(limit) and absolute_digits > limit
    ):
        raise PayloadValidationError(
            "int64 payload is outside signed 64-bit range: "
            f"negative={negative}, digits={len(absolute_digits)}"
        )
    return int(text)


def _encode_decimal(value: CanonicalInput, parameters: DecimalParameters) -> bytes:
    decimal_value = _decimal_from_input(value)
    if not decimal_value.is_finite():
        raise PayloadValidationError("decimal value must be finite")

    decimal_tuple = decimal_value.as_tuple()
    coefficient_text = ("".join(str(digit) for digit in decimal_tuple.digits) or "0").lstrip("0")
    if not coefficient_text:
        return b"0"
    exponent = decimal_tuple.exponent
    if type(exponent) is not int:
        raise PayloadValidationError("decimal value must have a finite integer exponent")
    shift = exponent + parameters.scale
    if shift >= 0:
        if len(coefficient_text) + shift > parameters.precision:
            raise PayloadValidationError(
                f"decimal scaled integer exceeds declared precision {parameters.precision}"
            )
        scaled_text = coefficient_text + ("0" * shift)
    else:
        removed_digits = -shift
        if removed_digits > len(coefficient_text):
            raise PayloadValidationError(
                f"decimal value would lose nonzero digits at declared scale {parameters.scale}"
            )
        if any(digit != "0" for digit in coefficient_text[-removed_digits:]):
            raise PayloadValidationError(
                f"decimal value would require rounding at declared scale {parameters.scale}"
            )
        scaled_text = coefficient_text[:-removed_digits]
    scaled_text = scaled_text.lstrip("0") or "0"
    if len(scaled_text) > parameters.precision:
        raise PayloadValidationError(
            f"decimal scaled integer exceeds declared precision {parameters.precision}"
        )
    sign = "-" if decimal_tuple.sign == 1 else ""
    return f"{sign}{scaled_text}".encode("ascii")


def _decode_decimal(payload: bytes, parameters: DecimalParameters) -> Decimal:
    text = _decode_ascii(payload, "decimal")
    if _CANONICAL_INTEGER.fullmatch(text) is None:
        raise PayloadValidationError(
            f"decimal payload is not canonical: byte_length={len(payload)}"
        )
    negative = text.startswith("-")
    absolute_digits = text[1:] if negative else text
    if len(absolute_digits) > parameters.precision:
        raise PayloadValidationError(
            "decimal payload scaled integer exceeds declared precision "
            f"{parameters.precision}: negative={negative}, digits={len(absolute_digits)}"
        )
    digits = tuple(int(digit) for digit in absolute_digits)
    return Decimal((1 if negative else 0, digits, -parameters.scale))


def _decimal_from_input(value: CanonicalInput) -> Decimal:
    if type(value) is Decimal:
        return value
    if type(value) is int:
        return Decimal(value)
    if type(value) is str:
        if _DECIMAL_INPUT.fullmatch(value) is None:
            raise PayloadValidationError(
                "decimal string is not an exact numeric representation: "
                f"character_length={len(value)}"
            )
        try:
            return Decimal(value)
        except InvalidOperation as error:
            raise PayloadValidationError(
                f"decimal string cannot be parsed exactly: character_length={len(value)}"
            ) from error
    raise PayloadValidationError(
        f"decimal requires Decimal, int, or an exact decimal string, got {type(value).__name__}"
    )


def _encode_boolean(value: CanonicalInput) -> bytes:
    if type(value) is not bool:
        raise PayloadValidationError(
            f"boolean requires a native boolean, got {type(value).__name__}"
        )
    return b"1" if value else b"0"


def _decode_boolean(payload: bytes) -> bool:
    if payload == b"0":
        return False
    if payload == b"1":
        return True
    _decode_ascii(payload, "boolean")
    raise PayloadValidationError(
        f"boolean payload must be exactly '0' or '1': byte_length={len(payload)}"
    )


def _encode_string(value: CanonicalInput) -> bytes:
    if type(value) is not str:
        raise PayloadValidationError(f"string requires a native string, got {type(value).__name__}")
    _validate_string_scalars(value)
    return value.encode("utf-8", errors="strict")


def _decode_string(payload: bytes) -> str:
    try:
        value = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PayloadValidationError(
            "string payload is not strict UTF-8: "
            f"byte_start={error.start}, byte_end={error.end}, reason={error.reason}"
        ) from error
    _validate_string_scalars(value)
    return value


def _validate_string_scalars(value: str) -> None:
    for index, character in enumerate(value):
        code_point = ord(character)
        if 0xD800 <= code_point <= 0xDFFF:
            raise PayloadValidationError(
                f"string contains a surrogate code point at character {index}"
            )
        if code_point == 0:
            raise PayloadValidationError(
                "string contains U+0000, which is outside the common string profile"
            )


def _encode_date(value: CanonicalInput) -> bytes:
    if type(value) is date:
        return _format_date(value).encode("ascii")
    if type(value) is str:
        parsed = _parse_date(value, "date")
        canonical = _format_date(parsed)
        if value != canonical:
            raise PayloadValidationError(
                f"date value is not canonical: character_length={len(value)}"
            )
        return canonical.encode("ascii")
    raise PayloadValidationError(
        f"date requires datetime.date or canonical text, got {type(value).__name__}"
    )


def _decode_date(payload: bytes) -> date:
    text = _decode_ascii(payload, "date")
    parsed = _parse_date(text, "date payload")
    if text != _format_date(parsed):
        raise PayloadValidationError(f"date payload is not canonical: byte_length={len(payload)}")
    return parsed


def _encode_timestamp_local(value: CanonicalInput, precision: int) -> bytes:
    if type(value) is datetime:
        if value.tzinfo is not None:
            raise PayloadValidationError(
                "timestamp_local datetime must not carry timezone information"
            )
        fraction = _fit_fraction(f"{value.microsecond:06d}", precision, "timestamp_local")
        return _format_timestamp(value, fraction, precision, False).encode("ascii")
    if type(value) is str:
        parsed, input_fraction = _parse_local_timestamp(value, "timestamp_local")
        fraction = _fit_fraction(input_fraction, precision, "timestamp_local")
        return _format_timestamp(parsed, fraction, precision, False).encode("ascii")
    raise PayloadValidationError(
        "timestamp_local requires a naive datetime or exact timestamp text, "
        f"got {type(value).__name__}"
    )


def _decode_timestamp_local(payload: bytes, precision: int) -> str:
    text = _decode_ascii(payload, "timestamp_local")
    canonical = _encode_timestamp_local(text, precision).decode("ascii")
    if text != canonical:
        raise PayloadValidationError(
            f"timestamp_local payload is not canonical: byte_length={len(payload)}"
        )
    return text


def _encode_timestamp_instant(value: CanonicalInput, precision: int) -> bytes:
    if type(value) is datetime:
        if not isinstance(value.tzinfo, timezone):
            raise PayloadValidationError(
                "timestamp_instant datetime requires a built-in fixed UTC offset; "
                "resolve IANA timezone policy upstream"
            )
        try:
            offset = value.utcoffset()
        except (OverflowError, TypeError, ValueError) as error:
            raise PayloadValidationError(
                "timestamp_instant datetime has an invalid UTC offset"
            ) from error
        if offset is None:
            raise PayloadValidationError(
                "timestamp_instant datetime requires an explicit UTC offset"
            )
        try:
            utc_value = value.astimezone(UTC)
        except (OverflowError, TypeError, ValueError) as error:
            raise PayloadValidationError(
                "timestamp_instant UTC conversion failed or is outside the supported calendar range"
            ) from error
        fraction = _fit_fraction(f"{utc_value.microsecond:06d}", precision, "timestamp_instant")
        return _format_timestamp(utc_value, fraction, precision, True).encode("ascii")
    if type(value) is str:
        local_value, input_fraction, offset = _parse_instant_timestamp(value, "timestamp_instant")
        try:
            utc_value = local_value - offset
        except OverflowError as error:
            raise PayloadValidationError(
                "timestamp_instant UTC conversion is outside the supported calendar range"
            ) from error
        fraction = _fit_fraction(input_fraction, precision, "timestamp_instant")
        return _format_timestamp(utc_value, fraction, precision, True).encode("ascii")
    raise PayloadValidationError(
        "timestamp_instant requires an aware datetime or offset-bearing timestamp text, "
        f"got {type(value).__name__}"
    )


def _decode_timestamp_instant(payload: bytes, precision: int) -> str:
    text = _decode_ascii(payload, "timestamp_instant")
    canonical = _encode_timestamp_instant(text, precision).decode("ascii")
    if text != canonical:
        raise PayloadValidationError(
            f"timestamp_instant payload is not canonical: byte_length={len(payload)}"
        )
    return text


def _parse_date(value: str, context: str) -> date:
    match = _EXACT_DATE.fullmatch(value)
    if match is None:
        raise PayloadValidationError(
            f"{context} must use exact YYYY-MM-DD form: character_length={len(value)}"
        )
    try:
        return date(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
        )
    except ValueError as error:
        raise PayloadValidationError(
            f"{context} is not a valid proleptic Gregorian date: reason={error}"
        ) from error


def _parse_local_timestamp(value: str, context: str) -> tuple[datetime, str]:
    match = _LOCAL_TIMESTAMP.fullmatch(value)
    if match is None:
        raise PayloadValidationError(
            f"{context} must be an offset-free ISO timestamp with at most 9 fraction digits: "
            f"character_length={len(value)}"
        )
    return _datetime_from_match(match, context, value), match.group("fraction") or ""


def _parse_instant_timestamp(value: str, context: str) -> tuple[datetime, str, timedelta]:
    match = _INSTANT_TIMESTAMP.fullmatch(value)
    if match is None:
        raise PayloadValidationError(
            f"{context} requires Z or an explicit ±HH:MM offset and at most 9 "
            f"fraction digits: character_length={len(value)}"
        )
    local_value = _datetime_from_match(match, context, value)
    offset_text = match.group("offset")
    if offset_text == "Z":
        offset = timedelta(0)
    else:
        offset_hours = int(offset_text[1:3])
        offset_minutes = int(offset_text[4:6])
        if offset_hours > 23 or offset_minutes > 59:
            raise PayloadValidationError(
                f"{context} has an invalid UTC offset: "
                f"hours_out_of_range={offset_hours > 23}, "
                f"minutes_out_of_range={offset_minutes > 59}"
            )
        offset = timedelta(hours=offset_hours, minutes=offset_minutes)
        if offset_text[0] == "-":
            offset = -offset
    return local_value, match.group("fraction") or "", offset


def _datetime_from_match(match: re.Match[str], context: str, original: str) -> datetime:
    try:
        return datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
        )
    except ValueError as error:
        raise PayloadValidationError(
            f"{context} has invalid calendar or clock fields: "
            f"character_length={len(original)}, reason={error}"
        ) from error


def _fit_fraction(fraction: str, precision: int, context: str) -> str:
    if len(fraction) > precision and any(digit != "0" for digit in fraction[precision:]):
        raise PayloadValidationError(
            f"{context} would lose nonzero fractional digits at precision {precision}"
        )
    return fraction[:precision].ljust(precision, "0")


def _format_date(value: date) -> str:
    return f"{value.year:04d}-{value.month:02d}-{value.day:02d}"


def _format_timestamp(value: datetime, fraction: str, precision: int, append_utc: bool) -> str:
    result = (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}"
        f"T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
    )
    if precision > 0:
        result += f".{fraction}"
    if append_utc:
        result += "Z"
    return result


def _null_frame(field: FieldSchema) -> str:
    return f"{_type_tag(field.logical_type)}0{'0' * 16}"


def _present_frame(field: FieldSchema, payload: bytes) -> str:
    payload_length = len(payload)
    if payload_length > UINT64_MAX:
        raise PayloadValidationError(f"field {field.name!r} payload byte length exceeds uint64")
    return f"{_type_tag(field.logical_type)}1{payload_length:016x}{payload.hex()}"


def _envelope_header(prefix: str, schema: CanonicalSchema) -> str:
    return f"{prefix}{schema_digest_hex(schema)}{len(schema.fields):08x}"


def _parse_envelope(
    schema: CanonicalSchema, envelope: bytes, expected_prefix: str
) -> tuple[_ParsedField, ...]:
    _require_schema(schema)
    if type(envelope) is not bytes:
        raise FrameValidationError("canonical envelope must be bytes")
    try:
        text = envelope.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise FrameValidationError(
            "canonical envelope must contain ASCII only: "
            f"byte_start={error.start}, byte_end={error.end}"
        ) from error
    if len(text) < _ENVELOPE_HEADER_LENGTH:
        raise FrameValidationError("canonical envelope is shorter than the 77-byte protocol header")
    if text[:5] != expected_prefix:
        raise FrameValidationError(
            f"canonical envelope prefix must be {expected_prefix!r}, got {text[:5]!r}"
        )

    digest_text = text[5:69]
    if _LOWER_HEX_64.fullmatch(digest_text) is None:
        raise FrameValidationError(
            "canonical envelope schema digest must be 64 lowercase hex digits"
        )
    expected_digest = schema_digest_hex(schema)
    if digest_text != expected_digest:
        raise FrameValidationError(
            "canonical envelope schema digest does not match the supplied logical schema: "
            f"expected={expected_digest}, actual={digest_text}"
        )

    field_count_text = text[69:77]
    if _LOWER_HEX_8.fullmatch(field_count_text) is None:
        raise FrameValidationError("canonical envelope field count must be 8 lowercase hex digits")
    field_count = int(field_count_text, 16)
    if field_count != len(schema.fields):
        raise FrameValidationError(
            "canonical envelope field count does not match the supplied logical schema: "
            f"header={field_count}, schema={len(schema.fields)}"
        )

    parsed_fields: list[_ParsedField] = []
    offset = _ENVELOPE_HEADER_LENGTH
    for index, field in enumerate(schema.fields):
        if len(text) - offset < _FIELD_HEADER_LENGTH:
            raise FrameValidationError(
                f"canonical envelope ends inside field header at index {index}"
            )
        tag = text[offset : offset + 2]
        presence = text[offset + 2]
        length_text = text[offset + 3 : offset + _FIELD_HEADER_LENGTH]
        expected_tag = _type_tag(field.logical_type)
        if tag != expected_tag:
            raise FrameValidationError(
                f"field {index} tag does not match schema type {field.logical_type.value!r}: "
                f"expected={expected_tag!r}, actual={tag!r}"
            )
        if presence not in ("0", "1"):
            raise FrameValidationError(
                f"field {index} presence must be '0' or '1', got {presence!r}"
            )
        if _LOWER_HEX_16.fullmatch(length_text) is None:
            raise FrameValidationError(f"field {index} byte length must be 16 lowercase hex digits")
        payload_length = int(length_text, 16)
        payload_hex_start = offset + _FIELD_HEADER_LENGTH
        payload_hex_length = payload_length * 2
        if payload_hex_length > len(text) - payload_hex_start:
            raise FrameValidationError(
                f"field {index} declares {payload_length} payload bytes but the envelope ends early"
            )
        payload_hex_end = payload_hex_start + payload_hex_length
        payload_hex = text[payload_hex_start:payload_hex_end]
        if _LOWER_HEX_PAYLOAD.fullmatch(payload_hex) is None:
            raise FrameValidationError(
                f"field {index} payload must contain lowercase hex byte pairs"
            )
        if presence == "0":
            if payload_length != 0:
                raise FrameValidationError(f"NULL field {index} must have zero payload byte length")
            parsed_fields.append(_ParsedField(payload=None))
        else:
            parsed_fields.append(_ParsedField(payload=bytes.fromhex(payload_hex)))
        offset = payload_hex_end

    if offset != len(text):
        raise FrameValidationError(
            f"canonical envelope has {len(text) - offset} trailing ASCII bytes"
        )
    return tuple(parsed_fields)


def _type_tag(logical_type: LogicalType) -> str:
    if logical_type is LogicalType.INT64:
        return "01"
    if logical_type is LogicalType.DECIMAL:
        return "02"
    if logical_type is LogicalType.BOOLEAN:
        return "03"
    if logical_type is LogicalType.STRING:
        return "04"
    if logical_type is LogicalType.DATE:
        return "05"
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        return "06"
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        return "07"
    raise SchemaValidationError(f"unsupported logical type {logical_type!r}")


def _decode_ascii(payload: bytes, context: str) -> str:
    try:
        return payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise PayloadValidationError(
            f"{context} payload must contain ASCII only: "
            f"byte_start={error.start}, byte_end={error.end}"
        ) from error


def _require_field(field: object) -> None:
    if not isinstance(field, FieldSchema):
        raise SchemaValidationError("field must be a FieldSchema")


def _require_schema(schema: object) -> CanonicalSchema:
    if not isinstance(schema, CanonicalSchema):
        raise SchemaValidationError("schema must be a CanonicalSchema")
    return schema


def _require_values(schema: object, values: object) -> None:
    validated_schema = _require_schema(schema)
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise PayloadValidationError("row/key values must be a non-string sequence")
    validated_values = cast(Sequence[object], values)
    if len(validated_values) != len(validated_schema.fields):
        raise PayloadValidationError(
            "row/key value count does not match schema field count: "
            f"values={len(validated_values)}, schema={len(validated_schema.fields)}"
        )
