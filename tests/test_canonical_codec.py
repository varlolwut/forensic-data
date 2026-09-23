from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from typing import cast

import pytest

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalInput,
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    FrameValidationError,
    LogicalType,
    NoParameters,
    Normalization,
    NullKeyError,
    PayloadValidationError,
    TimestampParameters,
    decode_key,
    decode_key_with_context,
    decode_payload,
    decode_row,
    decode_row_with_context,
    encode_key,
    encode_key_with_context,
    encode_payload,
    encode_row,
    encode_row_with_context,
    prepare_envelope_context,
    schema_digest_hex,
    schema_from_metadata_json,
)
from tests.canonical_vectors import vector_named


def test_all_common_types_row_matches_independent_golden_vector() -> None:
    vector = vector_named("all_common_types")
    schema = schema_from_metadata_json(vector.metadata_json)
    values: tuple[CanonicalInput, ...] = (
        -9223372036854775808,
        Decimal("-1780.000"),
        True,
        "A|Б😀e\u0301  ",
        "2024-02-29",
        "2024-02-29T23:59:58.123456",
        "2024-02-29T21:29:58.123456Z",
    )
    context = prepare_envelope_context(schema)

    envelope = encode_row_with_context(context, values)

    assert vector.values == (
        "-9223372036854775808",
        "-1780.000",
        True,
        "A|Б😀e\u0301  ",
        "2024-02-29",
        "2024-02-29T23:59:58.123456",
        "2024-02-29T21:29:58.123456Z",
    )
    assert envelope == vector.envelope_ascii.encode("ascii")
    assert envelope.hex() == vector.envelope_hex
    assert context.metadata_json == vector.metadata_json
    assert context.schema_digest_hex == vector.schema_digest_hex
    assert context.schema_digest == bytes.fromhex(vector.schema_digest_hex)
    assert context.row_header == vector.envelope_ascii[:77]
    assert decode_row_with_context(context, envelope) == (
        -9223372036854775808,
        Decimal("-1780.000"),
        True,
        "A|Б😀e\u0301  ",
        date(2024, 2, 29),
        "2024-02-29T23:59:58.123456",
        "2024-02-29T21:29:58.123456Z",
    )


def test_composite_key_matches_independent_golden_vector() -> None:
    vector = vector_named("composite_key")
    schema = schema_from_metadata_json(vector.metadata_json)
    context = prepare_envelope_context(schema)

    envelope = encode_key_with_context(context, (42, "A|Б😀e\u0301  "))

    assert envelope == vector.envelope_ascii.encode("ascii")
    assert envelope.hex() == vector.envelope_hex
    assert context.key_header == vector.envelope_ascii[:77]
    assert decode_key_with_context(context, envelope) == (42, "A|Б😀e\u0301  ")


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (0, b"0"),
        (-1, b"-1"),
        (-(1 << 63), b"-9223372036854775808"),
        ((1 << 63) - 1, b"9223372036854775807"),
    ),
)
def test_int64_payload_boundaries(value: int, expected: bytes) -> None:
    field = _field("value", LogicalType.INT64, False, NoParameters())

    assert encode_payload(field, value) == expected
    assert decode_payload(field, expected) == value


@pytest.mark.parametrize(
    "payload",
    (b"", b"01", b"+1", b"-0", b" 1", b"9223372036854775808"),
)
def test_int64_decoder_rejects_noncanonical_or_overflow_payload(payload: bytes) -> None:
    field = _field("value", LogicalType.INT64, False, NoParameters())

    with pytest.raises(PayloadValidationError):
        decode_payload(field, payload)


def test_int64_encoder_rejects_boolean_and_overflow() -> None:
    field = _field("value", LogicalType.INT64, False, NoParameters())

    with pytest.raises(PayloadValidationError):
        encode_payload(field, True)
    with pytest.raises(PayloadValidationError):
        encode_payload(field, 1 << 63)


def test_decimal_payload_is_exact_scaled_integer() -> None:
    field = _field("value", LogicalType.DECIMAL, False, DecimalParameters(5, 2))

    assert encode_payload(field, Decimal("120.00")) == b"12000"
    assert encode_payload(field, "1.2E+2") == b"12000"
    assert encode_payload(field, Decimal("-0.00")) == b"0"
    decoded = decode_payload(field, b"12000")
    assert isinstance(decoded, Decimal)
    assert decoded.as_tuple() == Decimal("120.00").as_tuple()


def test_decimal_precision_boundary_and_loss_are_enforced() -> None:
    maximum = _field("value", LogicalType.DECIMAL, False, DecimalParameters(38, 0))
    scale_two = _field("value", LogicalType.DECIMAL, False, DecimalParameters(5, 2))
    scale_equals_precision = _field("value", LogicalType.DECIMAL, False, DecimalParameters(3, 3))

    assert encode_payload(maximum, "9" * 38) == ("9" * 38).encode("ascii")
    assert encode_payload(maximum, (10**38) - 1) == ("9" * 38).encode("ascii")
    assert encode_payload(scale_equals_precision, "0.999") == b"999"
    with pytest.raises(PayloadValidationError, match="precision"):
        encode_payload(maximum, "1" + ("0" * 38))
    with pytest.raises(PayloadValidationError, match="precision"):
        encode_payload(scale_equals_precision, "1.000")
    with pytest.raises(PayloadValidationError, match="precision"):
        encode_payload(maximum, 1 << 1_000_000)
    with pytest.raises(PayloadValidationError, match="rounding"):
        encode_payload(scale_two, Decimal("120.001"))
    with pytest.raises(PayloadValidationError):
        decode_payload(scale_two, b"-0")


def test_boolean_payload_rejects_integer_substitution() -> None:
    field = _field("value", LogicalType.BOOLEAN, False, NoParameters())

    assert encode_payload(field, False) == b"0"
    assert encode_payload(field, True) == b"1"
    assert decode_payload(field, b"0") is False
    assert decode_payload(field, b"1") is True
    with pytest.raises(PayloadValidationError):
        encode_payload(field, 1)
    with pytest.raises(PayloadValidationError):
        decode_payload(field, b"true")


def test_string_payload_preserves_unicode_composition_and_spaces() -> None:
    field = _field("value", LogicalType.STRING, False, NoParameters())
    value = "A|Б😀e\u0301  "
    expected = b"A|\xd0\x91\xf0\x9f\x98\x80e\xcc\x81  "

    assert encode_payload(field, value) == expected
    assert decode_payload(field, expected) == value
    assert encode_payload(field, "é") != encode_payload(field, "e\u0301")
    assert encode_payload(field, "x ") != encode_payload(field, "x")
    assert encode_payload(field, "") == b""


def test_string_payload_rejects_invalid_scalars_and_encoding() -> None:
    field = _field("value", LogicalType.STRING, False, NoParameters())

    with pytest.raises(PayloadValidationError, match=r"U\+0000"):
        encode_payload(field, "a\x00b")
    with pytest.raises(PayloadValidationError, match="surrogate"):
        encode_payload(field, "\ud800")
    with pytest.raises(PayloadValidationError, match="strict UTF-8"):
        decode_payload(field, b"\xff")


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (date(1, 1, 1), b"0001-01-01"),
        ("2024-02-29", b"2024-02-29"),
        (date(9999, 12, 31), b"9999-12-31"),
    ),
)
def test_date_payload_boundaries(value: date | str, expected: bytes) -> None:
    field = _field("value", LogicalType.DATE, False, NoParameters())

    assert encode_payload(field, value) == expected
    assert encode_payload(field, decode_payload(field, expected)) == expected


@pytest.mark.parametrize("value", ("0000-01-01", "2023-02-29", "2024-2-29"))
def test_invalid_dates_are_rejected(value: str) -> None:
    field = _field("value", LogicalType.DATE, False, NoParameters())

    with pytest.raises(PayloadValidationError):
        encode_payload(field, value)


def test_local_timestamp_precision_is_exact_and_lossless() -> None:
    precision_zero = _field("value", LogicalType.TIMESTAMP_LOCAL, False, TimestampParameters(0))
    precision_three = _field("value", LogicalType.TIMESTAMP_LOCAL, False, TimestampParameters(3))
    precision_nine = _field("value", LogicalType.TIMESTAMP_LOCAL, False, TimestampParameters(9))

    assert encode_payload(precision_zero, "2024-01-02T03:04:05.000000") == (b"2024-01-02T03:04:05")
    assert encode_payload(precision_three, datetime(2024, 1, 2, 3, 4, 5, 123000)) == (
        b"2024-01-02T03:04:05.123"
    )
    assert encode_payload(precision_nine, "2024-01-02T03:04:05.123456789") == (
        b"2024-01-02T03:04:05.123456789"
    )
    assert encode_payload(precision_zero, "0001-01-01T00:00:00") == (b"0001-01-01T00:00:00")
    assert encode_payload(precision_nine, "9999-12-31T23:59:59.999999999") == (
        b"9999-12-31T23:59:59.999999999"
    )
    with pytest.raises(PayloadValidationError, match="lose nonzero"):
        encode_payload(precision_three, "2024-01-02T03:04:05.123001")
    with pytest.raises(PayloadValidationError, match="not canonical"):
        decode_payload(precision_three, b"2024-01-02T03:04:05.123000")


def test_instant_timestamp_converts_to_utc_and_requires_offset() -> None:
    field = _field("value", LogicalType.TIMESTAMP_INSTANT, False, TimestampParameters(6))
    aware = datetime(
        2024,
        1,
        1,
        2,
        30,
        0,
        123456,
        tzinfo=timezone(timedelta(hours=2, minutes=30)),
    )

    assert encode_payload(field, aware) == b"2024-01-01T00:00:00.123456Z"
    assert encode_payload(field, "2024-01-01T02:30:00.123456+02:30") == (
        b"2024-01-01T00:00:00.123456Z"
    )
    assert encode_payload(field, datetime(2024, 1, 1, tzinfo=UTC)) == (
        b"2024-01-01T00:00:00.000000Z"
    )
    assert encode_payload(field, "0001-01-01T00:00:00Z") == (b"0001-01-01T00:00:00.000000Z")
    assert encode_payload(field, "9999-12-31T23:59:59.999999Z") == (b"9999-12-31T23:59:59.999999Z")
    with pytest.raises(PayloadValidationError, match="fixed UTC offset"):
        encode_payload(field, datetime(2024, 1, 1))
    with pytest.raises(PayloadValidationError, match="IANA timezone policy upstream"):
        encode_payload(field, datetime(2024, 1, 1, tzinfo=_InvalidOffset()))
    with pytest.raises(PayloadValidationError, match="supported calendar range"):
        encode_payload(field, "0001-01-01T00:00:00.000000+00:01")
    with pytest.raises(PayloadValidationError, match="not canonical"):
        decode_payload(field, b"2024-01-01T00:00:00.123456+00:00")


def test_timestamp_invalid_calendar_leap_second_and_precision_are_rejected() -> None:
    local = _field("value", LogicalType.TIMESTAMP_LOCAL, False, TimestampParameters(9))
    instant = _field("value", LogicalType.TIMESTAMP_INSTANT, False, TimestampParameters(3))

    with pytest.raises(PayloadValidationError):
        encode_payload(local, "2023-02-29T00:00:00.000000000")
    with pytest.raises(PayloadValidationError):
        encode_payload(local, "2024-01-01T00:00:60.000000000")
    with pytest.raises(PayloadValidationError, match="lose nonzero"):
        encode_payload(instant, "2024-01-01T00:00:00.123000001Z")


def test_typed_null_empty_and_delimiter_collisions_remain_distinct() -> None:
    nullable_string = _field("value", LogicalType.STRING, True, NoParameters())
    single = _schema((nullable_string,))
    two_strings = _schema(
        (
            _field("left", LogicalType.STRING, False, NoParameters()),
            _field("right", LogicalType.STRING, False, NoParameters()),
        )
    )

    null_row = encode_row(single, (None,))
    empty_row = encode_row(single, ("",))
    first_split = encode_row(two_strings, ("a|", "b"))
    second_split = encode_row(two_strings, ("a", "|b"))

    assert null_row != empty_row
    assert decode_row(single, null_row) == (None,)
    assert decode_row(single, empty_row) == ("",)
    assert first_split != second_split
    assert decode_row(two_strings, first_split) == ("a|", "b")
    assert decode_row(two_strings, second_split) == ("a", "|b")


def test_null_key_is_rejected_by_encoder_and_decoder() -> None:
    field = _field("id", LogicalType.INT64, True, NoParameters())
    schema = _schema((field,))
    null_key = _envelope_with_frame(schema, "DFE1K", "01", "0", b"")

    with pytest.raises(NullKeyError):
        encode_key(schema, (None,))
    with pytest.raises(NullKeyError):
        decode_key(schema, null_key)


@pytest.mark.parametrize("payload", (b"01", b"+1", b"-0"))
def test_envelope_decoder_rejects_parseable_noncanonical_payload(payload: bytes) -> None:
    schema = _schema((_field("id", LogicalType.INT64, False, NoParameters()),))
    envelope = _envelope_with_frame(schema, "DFE1R", "01", "1", payload)

    with pytest.raises(PayloadValidationError):
        decode_row(schema, envelope)


def test_envelope_decoder_rejects_malformed_headers_and_trailing_bytes() -> None:
    schema = _schema((_field("id", LogicalType.INT64, False, NoParameters()),))
    valid = encode_row(schema, (1,))
    wrong_digest = valid[:5] + (b"0" * 64) + valid[69:]
    wrong_count = valid[:69] + b"00000002" + valid[77:]
    wrong_tag = valid[:77] + b"02" + valid[79:]
    wrong_presence = valid[:79] + b"2" + valid[80:]
    uppercase_length = valid[:80] + b"000000000000000A" + valid[96:]
    excessive_length = valid[:80] + b"ffffffffffffffff" + valid[96:]
    null_with_payload = _envelope_with_frame(schema, "DFE1R", "01", "0", b"1")

    for malformed in (
        valid + b"00",
        b"DFE1K" + valid[5:],
        wrong_digest,
        wrong_count,
        wrong_tag,
        wrong_presence,
        uppercase_length,
        excessive_length,
        null_with_payload,
        valid[:-1],
        b"\xff" + valid[1:],
    ):
        with pytest.raises(FrameValidationError):
            decode_row(schema, malformed)


def test_envelope_decoder_rejects_uppercase_payload_hex_and_nonnull_null() -> None:
    string_schema = _schema((_field("value", LogicalType.STRING, False, NoParameters()),))
    lowercase_payload = _envelope_with_frame(string_schema, "DFE1R", "04", "1", b"\xc3\xa9")
    uppercase_payload = lowercase_payload[:-4] + b"C3A9"
    null_nonnull = _envelope_with_frame(string_schema, "DFE1R", "04", "0", b"")

    with pytest.raises(FrameValidationError, match="lowercase hex"):
        decode_row(string_schema, uppercase_payload)
    with pytest.raises(FrameValidationError, match="nonnull"):
        decode_row(string_schema, null_nonnull)


def test_encoder_rejects_unsupported_physical_type_and_wrong_field_count() -> None:
    schema = _schema((_field("id", LogicalType.INT64, False, NoParameters()),))
    invalid_value = cast(CanonicalInput, cast(object, 1.5))

    with pytest.raises(PayloadValidationError, match="native integer"):
        encode_payload(schema.fields[0], invalid_value)
    with pytest.raises(PayloadValidationError, match="value count"):
        encode_row(schema, ())


def _field(
    name: str,
    logical_type: LogicalType,
    nullable: bool,
    parameters: NoParameters | DecimalParameters | TimestampParameters,
) -> FieldSchema:
    return FieldSchema(
        name=name,
        logical_type=logical_type,
        nullable=nullable,
        parameters=parameters,
        normalization=Normalization.NONE,
    )


def _schema(fields: tuple[FieldSchema, ...]) -> CanonicalSchema:
    return CanonicalSchema(protocol=PROTOCOL, fields=fields)


def _envelope_with_frame(
    schema: CanonicalSchema,
    prefix: str,
    tag: str,
    presence: str,
    payload: bytes,
) -> bytes:
    return (
        f"{prefix}{schema_digest_hex(schema)}00000001"
        f"{tag}{presence}{len(payload):016x}{payload.hex()}"
    ).encode("ascii")


class _InvalidOffset(tzinfo):
    def utcoffset(self, value: datetime | None) -> timedelta | None:
        return timedelta(hours=24)
