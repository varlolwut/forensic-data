from dataclasses import dataclass
from typing import cast, final
from uuid import UUID

from psycopg import sql

from forensic_data.canonical.model import (
    INT64_MAX,
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    LogicalType,
    NoParameters,
    TimestampParameters,
)
from forensic_data.canonical.schema import CanonicalEnvelopeContext, prepare_envelope_context

INT64_MIN = -(1 << 63)
UINT32_MAX = (1 << 32) - 1
_ROW_HEADER_BYTES = 77
_FIELD_FRAME_BYTES = 19


class PostgresLoweringError(ValueError):
    """A logical schema cannot be lowered to the PostgreSQL v1 profile."""


@final
@dataclass(frozen=True, slots=True)
class PostgresTypeIdentity:
    schema_name: str
    type_name: str
    oid: int

    def __post_init__(self) -> None:
        _validate_identifier_text(self.schema_name, "PostgreSQL type schema name")
        _validate_identifier_text(self.type_name, "PostgreSQL type name")
        _validate_positive_integer(self.oid, "PostgreSQL type OID", UINT32_MAX)


@final
@dataclass(frozen=True, slots=True)
class PostgresPhysicalField:
    declared_type: PostgresTypeIdentity
    base_type: PostgresTypeIdentity
    formatted_type: str
    is_domain: bool
    array_dimensions: int
    numeric_precision: int | None
    numeric_scale: int | None

    def __post_init__(self) -> None:
        _require_type_identity(self.declared_type, "PostgreSQL declared type provenance")
        _require_type_identity(self.base_type, "PostgreSQL base type provenance")
        _validate_identifier_text(self.formatted_type, "PostgreSQL formatted type")
        _require_boolean(self.is_domain, "PostgreSQL is_domain provenance")
        identities_match = self.declared_type == self.base_type
        if self.is_domain == identities_match:
            raise PostgresLoweringError(
                "PostgreSQL domain provenance is inconsistent with declared and base type identities"
            )
        _validate_nonnegative_integer(
            self.array_dimensions,
            "PostgreSQL array_dimensions provenance",
        )
        _validate_optional_integer(self.numeric_precision, "PostgreSQL numeric precision")
        _validate_optional_integer(self.numeric_scale, "PostgreSQL numeric scale")


@final
@dataclass(frozen=True, slots=True)
class PostgresRelation:
    components: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_relation_components(self.components)


@final
@dataclass(frozen=True, slots=True)
class PostgresFieldBinding:
    field_name: str
    column_name: str
    physical: PostgresPhysicalField

    def __post_init__(self) -> None:
        _validate_scalar_text(self.field_name, "logical field name")
        _validate_identifier_text(self.column_name, "PostgreSQL column name")
        _require_physical_field(
            self.physical,
            "PostgreSQL field binding physical provenance",
        )


@final
@dataclass(frozen=True, slots=True)
class PostgresInspectedRelation:
    context_id: UUID
    relation_oid: int
    relation_row_type_oid: int
    relation: PostgresRelation
    bindings: tuple[PostgresFieldBinding, ...]
    max_identifier_utf8_bytes: int

    def __post_init__(self) -> None:
        _require_uuid(self.context_id, "PostgreSQL inspected relation context ID")
        _validate_positive_integer(
            self.relation_oid,
            "PostgreSQL inspected relation OID",
            UINT32_MAX,
        )
        _validate_positive_integer(
            self.relation_row_type_oid,
            "PostgreSQL inspected relation row type OID",
            UINT32_MAX,
        )
        _require_relation(self.relation)
        _require_binding_tuple(self.bindings)
        _validate_positive_integer(
            self.max_identifier_utf8_bytes,
            "PostgreSQL max identifier UTF-8 byte length",
            INT64_MAX,
        )
        for index, binding in enumerate(self.bindings):
            _require_field_binding(binding, index)


type PostgresParameter = str | int


@final
@dataclass(frozen=True, slots=True)
class PostgresQuery:
    statement: sql.SQL | sql.Composed
    parameters: tuple[PostgresParameter, ...]
    context: CanonicalEnvelopeContext
    inspected_relation: PostgresInspectedRelation
    max_encoded_envelope_bytes: int

    def __post_init__(self) -> None:
        _require_query_statement(self.statement)
        _require_query_parameters(self.parameters)
        _require_envelope_context(self.context)
        _require_inspected_relation(self.inspected_relation)
        _validate_positive_integer(
            self.max_encoded_envelope_bytes,
            "PostgreSQL max encoded envelope byte length",
            INT64_MAX,
        )


@final
@dataclass(frozen=True, slots=True)
class _PayloadLowering:
    is_valid: sql.Composable
    payload: sql.Composable
    byte_length: sql.Composable


@final
@dataclass(frozen=True, slots=True)
class _FieldLowering:
    is_valid: sql.Composable
    payload_byte_length: sql.Composable
    frame: sql.Composable


@final
@dataclass(frozen=True, slots=True)
class _RowLowering:
    envelope: sql.Composable
    invalid_row: sql.Composable
    oversized_row: sql.Composable


def validate_postgres_inspection(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
) -> None:
    _require_canonical_schema(schema)
    _require_inspected_relation(inspection)
    for component in inspection.relation.components:
        _validate_identifier_byte_length(
            component,
            "PostgreSQL relation component",
            inspection.max_identifier_utf8_bytes,
        )

    if len(inspection.bindings) != len(schema.fields):
        raise PostgresLoweringError(
            "PostgreSQL field binding count must equal the logical schema field count"
        )
    for index, (field, binding) in enumerate(zip(schema.fields, inspection.bindings, strict=True)):
        _require_field_binding(binding, index)
        if field.name != binding.field_name:
            raise PostgresLoweringError(
                "PostgreSQL field bindings must follow logical schema order: "
                f"field index {index} does not match its logical schema name"
            )
        _validate_identifier_byte_length(
            binding.column_name,
            f"PostgreSQL column identifier at field index {index}",
            inspection.max_identifier_utf8_bytes,
        )
        _validate_type_identity_byte_lengths(
            binding.physical.declared_type,
            "declared",
            index,
            inspection.max_identifier_utf8_bytes,
        )
        _validate_type_identity_byte_lengths(
            binding.physical.base_type,
            "base",
            index,
            inspection.max_identifier_utf8_bytes,
        )
        _validate_physical_mapping(field, binding.physical, index)


def build_postgres_row_envelope_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    validate_postgres_inspection(schema, inspection)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "PostgreSQL max encoded envelope byte length",
        INT64_MAX,
    )
    context = prepare_envelope_context(schema)
    row = _row_lowering(schema, inspection.bindings, max_encoded_envelope_bytes)
    # Parenthesized alias.* is a whole-row value even when a column shares the alias name.
    statement = sql.SQL(
        "SELECT dfe_row.origin_type, dfe_row.envelope, "
        "CASE WHEN dfe_row.envelope IS NULL THEN NULL::bytea "
        "ELSE sha256(convert_to(dfe_row.envelope, 'UTF8')) END AS row_hash, "
        "dfe_row.invalid_row, dfe_row.oversized_row "
        "FROM ("
        "SELECT CASE WHEN FALSE THEN (dfe_source.*) ELSE NULL END AS origin_type, "
        "{envelope} AS envelope, {invalid_row} AS invalid_row, "
        "{oversized_row} AS oversized_row FROM ONLY {relation} AS dfe_source"
        ") AS dfe_row"
    ).format(
        envelope=row.envelope,
        invalid_row=row.invalid_row,
        oversized_row=row.oversized_row,
        relation=sql.Identifier(*inspection.relation.components),
    )
    return PostgresQuery(
        statement=statement,
        parameters=(context.schema_digest_hex, len(context.schema.fields)),
        context=context,
        inspected_relation=inspection,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def build_postgres_fingerprint_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    validate_postgres_inspection(schema, inspection)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "PostgreSQL max encoded envelope byte length",
        INT64_MAX,
    )
    context = prepare_envelope_context(schema)
    row = _row_lowering(schema, inspection.bindings, max_encoded_envelope_bytes)
    limb_sums = sql.SQL(", ").join(_limb_sum_expression(index) for index in range(8))
    # Parenthesized alias.* is a whole-row value even when a column shares the alias name.
    statement = sql.SQL(
        "WITH dfe_source AS NOT MATERIALIZED ("
        "SELECT CASE WHEN FALSE THEN (dfe_origin.*) ELSE NULL END AS origin_type, "
        "{envelope} AS envelope, {invalid_row} AS invalid_row, "
        "{oversized_row} AS oversized_row FROM ONLY {relation} AS dfe_origin"
        "), dfe_hash AS NOT MATERIALIZED ("
        "SELECT dfe_source.origin_type, "
        "CASE WHEN dfe_source.envelope IS NULL THEN NULL::bytea "
        "ELSE sha256(convert_to(dfe_source.envelope, 'UTF8')) END AS row_hash, "
        "dfe_source.invalid_row, dfe_source.oversized_row FROM dfe_source"
        ") SELECT (SELECT origin_type FROM dfe_source LIMIT 0) AS origin_type, "
        "count(*) FILTER (WHERE NOT dfe_hash.invalid_row "
        "AND NOT dfe_hash.oversized_row)::text AS valid_row_count, "
        "{limb_sums}, "
        "count(*) FILTER (WHERE dfe_hash.invalid_row)::text AS invalid_row_count, "
        "count(*) FILTER (WHERE dfe_hash.oversized_row)::text AS oversized_row_count "
        "FROM dfe_hash"
    ).format(
        limb_sums=limb_sums,
        envelope=row.envelope,
        invalid_row=row.invalid_row,
        oversized_row=row.oversized_row,
        relation=sql.Identifier(*inspection.relation.components),
    )
    return PostgresQuery(
        statement=statement,
        parameters=(context.schema_digest_hex, len(context.schema.fields)),
        context=context,
        inspected_relation=inspection,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def _row_lowering(
    schema: CanonicalSchema,
    bindings: tuple[PostgresFieldBinding, ...],
    max_encoded_envelope_bytes: int,
) -> _RowLowering:
    field_lowerings = tuple(
        _field_lowering(field, sql.Identifier(binding.column_name))
        for field, binding in zip(schema.fields, bindings, strict=True)
    )

    if field_lowerings:
        fields_valid = sql.SQL(" AND ").join(field.is_valid for field in field_lowerings)
        payload_bytes = sql.SQL(" + ").join(field.payload_byte_length for field in field_lowerings)
        frames = sql.SQL(" || ").join(field.frame for field in field_lowerings)
    else:
        fields_valid = sql.SQL("TRUE")
        payload_bytes = sql.SQL("0::bigint")
        frames = sql.SQL("''::text")

    invalid_row = sql.SQL("NOT ({fields_valid})").format(fields_valid=fields_valid)
    fixed_bytes = _ROW_HEADER_BYTES + (_FIELD_FRAME_BYTES * len(field_lowerings))
    envelope_bytes = sql.SQL("({fixed_bytes}::bigint + (2::bigint * ({payload_bytes})))").format(
        fixed_bytes=sql.Literal(fixed_bytes),
        payload_bytes=payload_bytes,
    )
    exceeds_limit = sql.SQL("{envelope_bytes} > {limit}::bigint").format(
        envelope_bytes=envelope_bytes,
        limit=sql.Literal(max_encoded_envelope_bytes),
    )
    oversized_row = sql.SQL("CASE WHEN {invalid_row} THEN FALSE ELSE {exceeds_limit} END").format(
        invalid_row=invalid_row, exceeds_limit=exceeds_limit
    )
    encoded_envelope = sql.SQL(
        "'DFE1R'::text || (%s)::text || lpad(to_hex((%s)::bigint), 8, '0') || {frames}"
    ).format(frames=frames)
    envelope = sql.SQL(
        "CASE WHEN {invalid_row} THEN NULL::text "
        "WHEN {exceeds_limit} THEN NULL::text ELSE {encoded_envelope} END"
    ).format(
        invalid_row=invalid_row,
        exceeds_limit=exceeds_limit,
        encoded_envelope=encoded_envelope,
    )
    return _RowLowering(
        envelope=envelope,
        invalid_row=invalid_row,
        oversized_row=oversized_row,
    )


def _validate_type_identity_byte_lengths(
    identity: PostgresTypeIdentity,
    identity_role: str,
    field_index: int,
    maximum: int,
) -> None:
    _validate_identifier_byte_length(
        identity.schema_name,
        f"PostgreSQL {identity_role} type schema at field index {field_index}",
        maximum,
    )
    _validate_identifier_byte_length(
        identity.type_name,
        f"PostgreSQL {identity_role} type name at field index {field_index}",
        maximum,
    )


def _validate_physical_mapping(
    field: FieldSchema,
    physical: PostgresPhysicalField,
    field_index: int,
) -> None:
    if physical.is_domain:
        raise PostgresLoweringError(
            "PostgreSQL field mapping is unsupported: "
            f"field_index={field_index}, logical_type={field.logical_type.value}, "
            "physical domains are not accepted; map an explicitly projected base value"
        )
    if physical.array_dimensions != 0:
        raise PostgresLoweringError(
            "PostgreSQL field mapping is unsupported: "
            f"field_index={field_index}, logical_type={field.logical_type.value}, "
            f"array_dimensions={physical.array_dimensions}; arrays require an explicit projection"
        )
    base_type = physical.base_type
    if base_type.schema_name != "pg_catalog":
        raise PostgresLoweringError(
            "PostgreSQL field mapping is unsupported: "
            f"field_index={field_index}, logical_type={field.logical_type.value}, "
            "the unwrapped base type is not a pg_catalog built-in type"
        )

    allowed_types = _allowed_base_types(field.logical_type)
    if base_type.type_name in allowed_types:
        return
    if field.logical_type is LogicalType.STRING and base_type.type_name == "bpchar":
        raise PostgresLoweringError(
            "PostgreSQL field mapping is unsupported: "
            "logical_type=string, physical_type=pg_catalog.bpchar; "
            "blank-padded character values require an explicit projection to text or varchar"
        )
    allowed_text = ", ".join(f"pg_catalog.{name}" for name in allowed_types)
    raise PostgresLoweringError(
        "PostgreSQL field mapping is unsupported: "
        f"field_index={field_index}, logical_type={field.logical_type.value}, "
        f"physical_type=pg_catalog.{base_type.type_name}, allowed_physical_types={allowed_text}"
    )


def _allowed_base_types(logical_type: LogicalType) -> tuple[str, ...]:
    if logical_type in (LogicalType.INT64, LogicalType.DECIMAL):
        return ("int2", "int4", "int8", "numeric")
    if logical_type is LogicalType.BOOLEAN:
        return ("bool",)
    if logical_type is LogicalType.STRING:
        return ("text", "varchar")
    if logical_type is LogicalType.DATE:
        return ("date",)
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        return ("timestamp",)
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        return ("timestamptz",)
    raise PostgresLoweringError(
        f"logical type {logical_type!r} is not supported by the PostgreSQL v1 profile"
    )


def _field_lowering(field: FieldSchema, column: sql.Identifier) -> _FieldLowering:
    payload = _payload_lowering(field, column)
    if field.nullable:
        field_valid = sql.SQL("{column} IS NULL OR ({payload_valid})").format(
            column=column,
            payload_valid=payload.is_valid,
        )
    else:
        field_valid = sql.SQL("{column} IS NOT NULL AND ({payload_valid})").format(
            column=column,
            payload_valid=payload.is_valid,
        )
    payload_byte_length = sql.SQL(
        "CASE WHEN {column} IS NULL THEN 0::bigint "
        "WHEN {payload_valid} THEN ({payload_length})::bigint ELSE 0::bigint END"
    ).format(
        column=column,
        payload_valid=payload.is_valid,
        payload_length=payload.byte_length,
    )

    type_tag = _type_tag(field.logical_type)
    null_frame = sql.SQL("{tag} || '0' || repeat('0', 16)").format(tag=sql.Literal(type_tag))
    present_frame = sql.SQL(
        "{tag} || '1' || lpad(to_hex(({payload_length})::bigint), 16, '0') || "
        "encode({payload}, 'hex')"
    ).format(
        tag=sql.Literal(type_tag),
        payload_length=payload.byte_length,
        payload=payload.payload,
    )
    frame = sql.SQL("CASE WHEN {column} IS NULL THEN {null_frame} ELSE {present_frame} END").format(
        column=column,
        null_frame=null_frame,
        present_frame=present_frame,
    )
    return _FieldLowering(
        is_valid=field_valid,
        payload_byte_length=payload_byte_length,
        frame=frame,
    )


def _payload_lowering(field: FieldSchema, column: sql.Identifier) -> _PayloadLowering:
    logical_type = field.logical_type
    if logical_type is LogicalType.INT64:
        _require_no_parameters(field)
        return _int64_payload(column)
    if logical_type is LogicalType.DECIMAL:
        return _decimal_payload(field, column)
    if logical_type is LogicalType.BOOLEAN:
        _require_no_parameters(field)
        payload = sql.SQL("convert_to(CASE WHEN {column} THEN '1' ELSE '0' END, 'UTF8')").format(
            column=column
        )
        return _PayloadLowering(
            is_valid=sql.SQL("TRUE"),
            payload=payload,
            byte_length=sql.SQL("1::bigint"),
        )
    if logical_type is LogicalType.STRING:
        _require_no_parameters(field)
        return _PayloadLowering(
            is_valid=sql.SQL("TRUE"),
            payload=sql.SQL("convert_to({column}, 'UTF8')").format(column=column),
            byte_length=sql.SQL("octet_length({column})::bigint").format(column=column),
        )
    if logical_type is LogicalType.DATE:
        _require_no_parameters(field)
        return _date_payload(column)
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        return _timestamp_local_payload(field, column)
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        return _timestamp_instant_payload(field, column)
    raise PostgresLoweringError(
        f"logical type {logical_type!r} is not supported by the PostgreSQL v1 profile"
    )


def _int64_payload(column: sql.Identifier) -> _PayloadLowering:
    value = sql.SQL("({column})::numeric").format(column=column)
    in_range = sql.SQL("{value} BETWEEN {minimum}::numeric AND {maximum}::numeric").format(
        value=value,
        minimum=sql.Literal(INT64_MIN),
        maximum=sql.Literal(INT64_MAX),
    )
    is_valid = sql.SQL("CASE WHEN {in_range} THEN {value} = trunc({value}) ELSE FALSE END").format(
        in_range=in_range, value=value
    )
    integer_text = sql.SQL("(trunc({value}))::text").format(value=value)
    return _PayloadLowering(
        is_valid=is_valid,
        payload=sql.SQL("convert_to({integer_text}, 'UTF8')").format(integer_text=integer_text),
        byte_length=sql.SQL("octet_length({integer_text})::bigint").format(
            integer_text=integer_text
        ),
    )


def _decimal_payload(field: FieldSchema, column: sql.Identifier) -> _PayloadLowering:
    if not isinstance(field.parameters, DecimalParameters):
        raise PostgresLoweringError("decimal field requires DecimalParameters")
    precision = field.parameters.precision
    scale = field.parameters.scale
    multiplier = 10**scale
    unscaled_bound = 10 ** (precision - scale)
    value = sql.SQL("({column})::numeric").format(column=column)
    in_range = sql.SQL("{value} > {minimum}::numeric AND {value} < {maximum}::numeric").format(
        value=value,
        minimum=sql.Literal(-unscaled_bound),
        maximum=sql.Literal(unscaled_bound),
    )
    scaled = sql.SQL("({value} * {multiplier}::numeric)").format(
        value=value,
        multiplier=sql.Literal(multiplier),
    )
    is_valid = sql.SQL(
        "CASE WHEN {in_range} THEN {scaled} = trunc({scaled}) ELSE FALSE END"
    ).format(in_range=in_range, scaled=scaled)
    integer_text = sql.SQL("(trunc({scaled}))::text").format(scaled=scaled)
    return _PayloadLowering(
        is_valid=is_valid,
        payload=sql.SQL("convert_to({integer_text}, 'UTF8')").format(integer_text=integer_text),
        byte_length=sql.SQL("octet_length({integer_text})::bigint").format(
            integer_text=integer_text
        ),
    )


def _date_payload(column: sql.Identifier) -> _PayloadLowering:
    year = sql.SQL("extract(year FROM {column})").format(column=column)
    is_valid = sql.SQL("{year} BETWEEN 1 AND 9999").format(year=year)
    payload = sql.SQL("convert_to(to_char({column}, 'YYYY-MM-DD'), 'UTF8')").format(column=column)
    return _PayloadLowering(
        is_valid=is_valid,
        payload=payload,
        byte_length=sql.SQL("10::bigint"),
    )


def _timestamp_local_payload(
    field: FieldSchema,
    column: sql.Identifier,
) -> _PayloadLowering:
    precision = _timestamp_precision(field)
    payload_byte_length = 19 + (precision + 1 if precision > 0 else 0)
    return _timestamp_payload_for_value(
        precision,
        column,
        sql.SQL("''::text"),
        payload_byte_length,
    )


def _timestamp_instant_payload(
    field: FieldSchema,
    column: sql.Identifier,
) -> _PayloadLowering:
    precision = _timestamp_precision(field)
    utc_value = sql.SQL("({column} AT TIME ZONE 'UTC')").format(column=column)
    payload_byte_length = 20 + (precision + 1 if precision > 0 else 0)
    return _timestamp_payload_for_value(
        precision,
        utc_value,
        sql.SQL("'Z'::text"),
        payload_byte_length,
    )


def _timestamp_precision(field: FieldSchema) -> int:
    if not isinstance(field.parameters, TimestampParameters):
        raise PostgresLoweringError("timestamp field requires TimestampParameters")
    return field.parameters.precision


def _timestamp_payload_for_value(
    precision: int,
    value: sql.Composable,
    suffix: sql.Composable,
    payload_byte_length: int,
) -> _PayloadLowering:
    divisor = 10 ** max(0, 6 - precision)
    year = sql.SQL("extract(year FROM {value})").format(value=value)
    has_exact_precision = sql.SQL(
        "mod(extract(microseconds FROM {value})::numeric, {divisor}::numeric) = 0"
    ).format(value=value, divisor=sql.Literal(divisor))
    is_valid = sql.SQL(
        "CASE WHEN {year} BETWEEN 1 AND 9999 THEN {has_exact_precision} ELSE FALSE END"
    ).format(year=year, has_exact_precision=has_exact_precision)

    fraction = sql.SQL("''::text")
    if precision > 0:
        fraction = sql.SQL("'.' || rpad(to_char({value}, 'US'), {precision}, '0')").format(
            value=value, precision=sql.Literal(precision)
        )
    timestamp_text = sql.SQL(
        "to_char({value}, 'YYYY-MM-DD\"T\"HH24:MI:SS') || {fraction} || {suffix}"
    ).format(value=value, fraction=fraction, suffix=suffix)
    return _PayloadLowering(
        is_valid=is_valid,
        payload=sql.SQL("convert_to({timestamp_text}, 'UTF8')").format(
            timestamp_text=timestamp_text
        ),
        byte_length=sql.Literal(payload_byte_length),
    )


def _limb_sum_expression(index: int) -> sql.Composable:
    offset = index * 4
    limb = sql.SQL(
        "get_byte(dfe_hash.row_hash, {b0})::numeric * 16777216 + "
        "get_byte(dfe_hash.row_hash, {b1})::numeric * 65536 + "
        "get_byte(dfe_hash.row_hash, {b2})::numeric * 256 + "
        "get_byte(dfe_hash.row_hash, {b3})::numeric"
    ).format(
        b0=sql.Literal(offset),
        b1=sql.Literal(offset + 1),
        b2=sql.Literal(offset + 2),
        b3=sql.Literal(offset + 3),
    )
    return sql.SQL("coalesce(sum({limb}), 0::numeric)::text AS {alias}").format(
        limb=limb,
        alias=sql.Identifier(f"limb_{index}"),
    )


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
    raise PostgresLoweringError(
        f"logical type {logical_type!r} is not supported by the PostgreSQL v1 profile"
    )


def _require_no_parameters(field: FieldSchema) -> None:
    if not isinstance(field.parameters, NoParameters):
        raise PostgresLoweringError(
            f"{field.logical_type.value} field requires an empty parameters object"
        )


def _validate_relation_components(value: object) -> None:
    if type(value) is not tuple:
        raise PostgresLoweringError("PostgreSQL relation must contain schema and relation names")
    components = cast(tuple[object, ...], value)
    if len(components) != 2:
        raise PostgresLoweringError("PostgreSQL relation must contain schema and relation names")
    for component in components:
        _validate_identifier_text(component, "PostgreSQL relation component")


def _validate_identifier_text(value: object, context: str) -> None:
    if type(value) is not str or not value:
        raise PostgresLoweringError(f"{context} must be a non-empty string")
    _validate_scalar_characters(value, context)
    if "\x00" in value:
        raise PostgresLoweringError(f"{context} must not contain U+0000")


def _validate_scalar_text(value: object, context: str) -> None:
    if type(value) is not str:
        raise PostgresLoweringError(f"{context} must be a string")
    _validate_scalar_characters(value, context)


def _validate_scalar_characters(value: str, context: str) -> None:
    for index, character in enumerate(value):
        code_point = ord(character)
        if 0xD800 <= code_point <= 0xDFFF:
            raise PostgresLoweringError(
                f"{context} contains a surrogate code point at character {index}"
            )


def _validate_identifier_byte_length(value: str, context: str, maximum: int) -> None:
    byte_length = len(value.encode("utf-8", errors="strict"))
    if byte_length > maximum:
        raise PostgresLoweringError(
            f"{context} exceeds the probed PostgreSQL identifier limit: "
            f"utf8_bytes={byte_length}, maximum={maximum}"
        )


def _validate_optional_integer(value: object, context: str) -> None:
    if value is not None and type(value) is not int:
        raise PostgresLoweringError(f"{context} must be an integer or None")


def _validate_nonnegative_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 0:
        raise PostgresLoweringError(f"{context} must be a non-negative integer")


def _validate_positive_integer(value: object, context: str, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise PostgresLoweringError(
            f"{context} must be an integer in the inclusive range 1..{maximum}"
        )


def _require_boolean(value: object, context: str) -> None:
    if type(value) is not bool:
        raise PostgresLoweringError(f"{context} must be a boolean")


def _require_type_identity(value: object, context: str) -> None:
    if not isinstance(value, PostgresTypeIdentity):
        raise PostgresLoweringError(f"{context} must be a PostgresTypeIdentity")


def _require_physical_field(value: object, context: str) -> None:
    if not isinstance(value, PostgresPhysicalField):
        raise PostgresLoweringError(f"{context} must be a PostgresPhysicalField")


def _require_canonical_schema(value: object) -> None:
    if not isinstance(value, CanonicalSchema):
        raise PostgresLoweringError("schema must be a CanonicalSchema")


def _require_relation(value: object) -> None:
    if not isinstance(value, PostgresRelation):
        raise PostgresLoweringError("relation must be a PostgresRelation")


def _require_inspected_relation(value: object) -> None:
    if not isinstance(value, PostgresInspectedRelation):
        raise PostgresLoweringError("inspection must be a PostgresInspectedRelation")


def _require_uuid(value: object, context: str) -> None:
    if not isinstance(value, UUID):
        raise PostgresLoweringError(f"{context} must be a UUID")


def _require_binding_tuple(value: object) -> None:
    if type(value) is not tuple:
        raise PostgresLoweringError("PostgreSQL field bindings must be an immutable tuple")


def _require_field_binding(value: object, field_index: int) -> None:
    if not isinstance(value, PostgresFieldBinding):
        raise PostgresLoweringError(
            f"PostgreSQL field binding at index {field_index} must be a PostgresFieldBinding"
        )


def _require_query_statement(value: object) -> None:
    if not isinstance(value, (sql.SQL, sql.Composed)):
        raise PostgresLoweringError(
            "PostgreSQL query statement must be psycopg.sql.SQL or psycopg.sql.Composed"
        )


def _require_query_parameters(value: object) -> None:
    if type(value) is not tuple:
        raise PostgresLoweringError("PostgreSQL query parameters must be an immutable tuple")
    parameters = cast(tuple[object, ...], value)
    for index, parameter in enumerate(parameters):
        if type(parameter) not in (str, int):
            raise PostgresLoweringError(
                "PostgreSQL query parameter must be an exact string or integer: "
                f"parameter_index={index}"
            )


def _require_envelope_context(value: object) -> None:
    if not isinstance(value, CanonicalEnvelopeContext):
        raise PostgresLoweringError("PostgreSQL query context must be a CanonicalEnvelopeContext")
