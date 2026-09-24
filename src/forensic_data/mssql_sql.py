from dataclasses import dataclass
from typing import cast, final

from forensic_data.canonical.model import (
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    LogicalType,
    NoParameters,
    TimestampParameters,
)
from forensic_data.canonical.schema import CanonicalEnvelopeContext, prepare_envelope_context

UINT8_MAX = (1 << 8) - 1
INT32_MAX = (1 << 31) - 1
MAX_COMPILED_RELATION_MEMBERS = 1_024
_ROW_HEADER_BYTES = 77
_FIELD_FRAME_BYTES = 19
_MAX_BOUNDED_VARCHAR_BYTES = 8_000
_MAX_LOB_BYTES = (1 << 31) - 1
_UTF8_COLLATION = "Latin1_General_100_BIN2_UTF8"
_BUILTIN_TYPE_IDS = {
    "date": 40,
    "datetime2": 42,
    "datetimeoffset": 43,
    "tinyint": 48,
    "smallint": 52,
    "int": 56,
    "bit": 104,
    "decimal": 106,
    "numeric": 108,
    "bigint": 127,
    "varchar": 167,
    "nvarchar": 231,
}


class MssqlLoweringError(ValueError):
    """A logical schema cannot be lowered to the SQL Server 2022 v1 profile."""


@final
@dataclass(frozen=True, slots=True)
class MssqlPhysicalField:
    system_type_name: str
    system_type_id: int
    user_type_id: int
    max_length: int
    precision: int
    scale: int
    collation_name: str | None

    def __post_init__(self) -> None:
        _validate_identifier(self.system_type_name, "SQL Server system type name")
        _validate_positive_integer(
            self.system_type_id,
            "SQL Server system type ID",
            UINT8_MAX,
        )
        _validate_positive_integer(
            self.user_type_id,
            "SQL Server user type ID",
            INT32_MAX,
        )
        if type(self.max_length) is not int or not (
            self.max_length == -1 or 1 <= self.max_length <= _MAX_BOUNDED_VARCHAR_BYTES
        ):
            raise MssqlLoweringError(
                "SQL Server physical maximum length must be -1 or an integer in 1..8000"
            )
        _validate_nonnegative_integer(
            self.precision,
            "SQL Server physical precision",
            38,
        )
        _validate_nonnegative_integer(
            self.scale,
            "SQL Server physical scale",
            38,
        )
        if self.scale > self.precision:
            raise MssqlLoweringError("SQL Server physical scale must not exceed physical precision")
        if self.collation_name is not None:
            _validate_identifier(self.collation_name, "SQL Server physical collation name")


@final
@dataclass(frozen=True, slots=True)
class MssqlRelation:
    schema_name: str
    table_name: str

    def __post_init__(self) -> None:
        _validate_identifier(self.schema_name, "SQL Server schema name")
        _validate_identifier(self.table_name, "SQL Server table name")


@final
@dataclass(frozen=True, slots=True)
class MssqlFieldBinding:
    field_name: str
    column_name: str
    physical: MssqlPhysicalField

    def __post_init__(self) -> None:
        _validate_scalar_text(self.field_name, "SQL Server logical field name")
        _validate_identifier(self.column_name, "SQL Server column name")
        if type(self.physical) is not MssqlPhysicalField:
            raise MssqlLoweringError(
                "SQL Server field binding physical provenance must be MssqlPhysicalField"
            )


@final
@dataclass(frozen=True, slots=True)
class MssqlCanonicalQuery:
    statement: str
    parameters: tuple[str, ...]
    context: CanonicalEnvelopeContext
    relation: MssqlRelation
    bindings: tuple[MssqlFieldBinding, ...]
    max_encoded_envelope_bytes: int

    def __post_init__(self) -> None:
        _validate_scalar_text(self.statement, "SQL Server canonical statement")
        if not self.statement:
            raise MssqlLoweringError("SQL Server canonical statement must not be empty")
        if type(self.parameters) is not tuple or not all(
            type(parameter) is str for parameter in self.parameters
        ):
            raise MssqlLoweringError(
                "SQL Server canonical parameters must be an immutable tuple of text values"
            )
        if not isinstance(cast(object, self.context), CanonicalEnvelopeContext):
            raise MssqlLoweringError(
                "SQL Server canonical query context must be a CanonicalEnvelopeContext"
            )
        if type(self.relation) is not MssqlRelation:
            raise MssqlLoweringError("SQL Server canonical query relation must be MssqlRelation")
        _validate_bindings(self.context.schema, self.bindings)
        _validate_positive_integer(
            self.max_encoded_envelope_bytes,
            "SQL Server maximum encoded envelope bytes",
            _MAX_LOB_BYTES,
        )


@final
@dataclass(frozen=True, slots=True)
class _PayloadLowering:
    is_valid: str
    payload: str


@final
@dataclass(frozen=True, slots=True)
class _RowSource:
    statement: str
    context: CanonicalEnvelopeContext
    parameters: tuple[str, ...]


def build_mssql_row_envelope_query(
    schema: CanonicalSchema,
    relation: MssqlRelation,
    bindings: tuple[MssqlFieldBinding, ...],
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, relation, bindings, max_encoded_envelope_bytes)
    if max_encoded_envelope_bytes > _MAX_BOUNDED_VARCHAR_BYTES:
        raise MssqlLoweringError(
            "SQL Server row-envelope output cannot declare more than 8000 bytes; "
            "use the row-hash query for larger envelopes"
        )
    source = _row_source(schema, relation, bindings, max_encoded_envelope_bytes)
    statement = (
        f"{source.statement} "
        "SELECT "
        f"CONVERT(varchar({max_encoded_envelope_bytes}), [dfe_hash].[envelope]) "
        "AS [envelope], "
        "LOWER(CONVERT(char(64), [dfe_hash].[row_hash], 2)) AS [row_hash_hex], "
        "[dfe_hash].[invalid_row], [dfe_hash].[oversized_row] "
        "FROM [dfe_hash]"
    )
    return _canonical_query(source, relation, bindings, max_encoded_envelope_bytes, statement)


def build_mssql_row_hash_query(
    schema: CanonicalSchema,
    relation: MssqlRelation,
    bindings: tuple[MssqlFieldBinding, ...],
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, relation, bindings, max_encoded_envelope_bytes)
    source = _row_source(schema, relation, bindings, max_encoded_envelope_bytes)
    statement = (
        f"{source.statement} "
        "SELECT [dfe_hash].[envelope_bytes], "
        "LOWER(CONVERT(char(64), [dfe_hash].[row_hash], 2)) AS [row_hash_hex], "
        "CASE WHEN [dfe_hash].[envelope_bytes] <= 8000 "
        "THEN CONVERT(varchar(8000), [dfe_hash].[envelope]) "
        "ELSE CONVERT(varchar(8000), NULL) END AS [bounded_envelope], "
        "[dfe_hash].[invalid_row], [dfe_hash].[oversized_row] "
        "FROM [dfe_hash]"
    )
    return _canonical_query(source, relation, bindings, max_encoded_envelope_bytes, statement)


def build_mssql_fingerprint_query(
    schema: CanonicalSchema,
    relation: MssqlRelation,
    bindings: tuple[MssqlFieldBinding, ...],
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, relation, bindings, max_encoded_envelope_bytes)
    source = _row_source(schema, relation, bindings, max_encoded_envelope_bytes)
    limb_sums = ", ".join(_limb_sum_expression(index) for index in range(8))
    statement = (
        f"{source.statement} "
        "SELECT "
        "COUNT_BIG(CASE WHEN [dfe_hash].[row_hash] IS NOT NULL THEN 1 END) "
        "AS [valid_row_count], "
        f"{limb_sums}, "
        "COUNT_BIG(CASE WHEN [dfe_hash].[invalid_row] = CONVERT(bit, 1) THEN 1 END) "
        "AS [invalid_row_count], "
        "COUNT_BIG(CASE WHEN [dfe_hash].[oversized_row] = CONVERT(bit, 1) THEN 1 END) "
        "AS [oversized_row_count] "
        "FROM [dfe_hash]"
    )
    return _canonical_query(source, relation, bindings, max_encoded_envelope_bytes, statement)


def _canonical_query(
    source: _RowSource,
    relation: MssqlRelation,
    bindings: tuple[MssqlFieldBinding, ...],
    max_encoded_envelope_bytes: int,
    statement: str,
) -> MssqlCanonicalQuery:
    return MssqlCanonicalQuery(
        statement=statement,
        parameters=source.parameters,
        context=source.context,
        relation=relation,
        bindings=bindings,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def _row_source(
    schema: CanonicalSchema,
    relation: MssqlRelation,
    bindings: tuple[MssqlFieldBinding, ...],
    max_encoded_envelope_bytes: int,
) -> _RowSource:
    context = prepare_envelope_context(schema)
    payloads = tuple(
        _payload_lowering(field, binding)
        for field, binding in zip(schema.fields, bindings, strict=True)
    )
    payload_clause = _payload_clause(payloads)
    fields_valid = _fields_valid_expression(schema, bindings, payloads)
    payload_bytes = _payload_bytes_expression(bindings, payloads)
    frames = _frames_expression(schema, bindings, payloads)
    fixed_bytes = _ROW_HEADER_BYTES + (_FIELD_FRAME_BYTES * len(schema.fields))
    relation_sql = (
        f"{_quote_identifier(relation.schema_name)}.{_quote_identifier(relation.table_name)}"
    )
    statement = (
        "WITH [dfe_rows] AS ("
        "SELECT [dfe_row].[envelope], [dfe_validation].[envelope_bytes], "
        "[dfe_validation].[invalid_row], [dfe_row].[oversized_row] "
        f"FROM {relation_sql} AS [dfe_source] "
        f"{payload_clause} "
        "CROSS APPLY (SELECT "
        f"CASE WHEN {fields_valid} THEN CONVERT(bit, 0) ELSE CONVERT(bit, 1) END "
        "AS [invalid_row], "
        f"CONVERT(bigint, {fixed_bytes}) + "
        f"(CONVERT(bigint, 2) * ({payload_bytes})) AS [envelope_bytes]"
        ") AS [dfe_validation] "
        "CROSS APPLY (SELECT "
        "CASE WHEN [dfe_validation].[invalid_row] = CONVERT(bit, 1) "
        f"OR [dfe_validation].[envelope_bytes] > CONVERT(bigint, {max_encoded_envelope_bytes}) "
        "THEN CONVERT(varchar(max), NULL) "
        f"ELSE CONVERT(varchar(max), ?) + {frames} END AS [envelope], "
        "CASE WHEN [dfe_validation].[invalid_row] = CONVERT(bit, 0) "
        f"AND [dfe_validation].[envelope_bytes] > CONVERT(bigint, {max_encoded_envelope_bytes}) "
        "THEN CONVERT(bit, 1) ELSE CONVERT(bit, 0) END AS [oversized_row]"
        ") AS [dfe_row]"
        "), [dfe_hash] AS ("
        "SELECT [dfe_rows].[envelope], [dfe_rows].[envelope_bytes], "
        "CASE WHEN [dfe_rows].[envelope] IS NULL THEN CONVERT(varbinary(32), NULL) "
        "ELSE CONVERT(varbinary(32), HASHBYTES('SHA2_256', "
        "CONVERT(varbinary(max), [dfe_rows].[envelope]))) END AS [row_hash], "
        "[dfe_rows].[invalid_row], [dfe_rows].[oversized_row] "
        "FROM [dfe_rows]"
        ")"
    )
    return _RowSource(
        statement=statement,
        context=context,
        parameters=(context.row_header,),
    )


def _payload_clause(payloads: tuple[_PayloadLowering, ...]) -> str:
    if not payloads:
        return ""
    columns: list[str] = []
    for index, payload in enumerate(payloads):
        columns.extend(
            (
                "CASE WHEN "
                f"{payload.is_valid} THEN CONVERT(bit, 1) ELSE CONVERT(bit, 0) END "
                f"AS {_quote_identifier(f'valid_{index}')}",
                f"{payload.payload} AS {_quote_identifier(f'payload_{index}')}",
            )
        )
    return f"CROSS APPLY (SELECT {', '.join(columns)}) AS [dfe_payload]"


def _fields_valid_expression(
    schema: CanonicalSchema,
    bindings: tuple[MssqlFieldBinding, ...],
    payloads: tuple[_PayloadLowering, ...],
) -> str:
    if not schema.fields:
        return "1 = 1"
    conditions: list[str] = []
    for index, (field, binding, _) in enumerate(
        zip(schema.fields, bindings, payloads, strict=True)
    ):
        column = _qualified_column(binding.column_name)
        payload_valid = f"[dfe_payload].{_quote_identifier(f'valid_{index}')} = CONVERT(bit, 1)"
        if field.nullable:
            conditions.append(f"({column} IS NULL OR {payload_valid})")
        else:
            conditions.append(f"({column} IS NOT NULL AND {payload_valid})")
    return " AND ".join(conditions)


def _payload_bytes_expression(
    bindings: tuple[MssqlFieldBinding, ...],
    payloads: tuple[_PayloadLowering, ...],
) -> str:
    if not payloads:
        return "CONVERT(bigint, 0)"
    terms: list[str] = []
    for index, binding in enumerate(bindings):
        column = _qualified_column(binding.column_name)
        valid = f"[dfe_payload].{_quote_identifier(f'valid_{index}')}"
        payload = f"[dfe_payload].{_quote_identifier(f'payload_{index}')}"
        terms.append(
            "CASE WHEN "
            f"{column} IS NULL OR {valid} = CONVERT(bit, 0) "
            f"THEN CONVERT(bigint, 0) ELSE DATALENGTH({payload}) END"
        )
    return " + ".join(terms)


def _frames_expression(
    schema: CanonicalSchema,
    bindings: tuple[MssqlFieldBinding, ...],
    payloads: tuple[_PayloadLowering, ...],
) -> str:
    if not schema.fields:
        return "CONVERT(varchar(max), '')"
    frames: list[str] = []
    for index, (field, binding, _) in enumerate(
        zip(schema.fields, bindings, payloads, strict=True)
    ):
        column = _qualified_column(binding.column_name)
        payload = f"[dfe_payload].{_quote_identifier(f'payload_{index}')}"
        tag = _type_tag(field.logical_type)
        null_frame = f"'{tag}0{'0' * 16}'"
        present_frame = (
            f"CONVERT(varchar(max), '{tag}1') + "
            "LOWER(CONVERT(char(16), CONVERT(binary(8), "
            f"CONVERT(bigint, DATALENGTH({payload}))), 2)) + "
            f"LOWER(CONVERT(varchar(max), {payload}, 2))"
        )
        frames.append(
            f"CASE WHEN {column} IS NULL THEN CONVERT(varchar(max), {null_frame}) "
            f"ELSE {present_frame} END"
        )
    return " + ".join(frames)


def _payload_lowering(field: FieldSchema, binding: MssqlFieldBinding) -> _PayloadLowering:
    column = _qualified_column(binding.column_name)
    logical_type = field.logical_type
    if logical_type is LogicalType.INT64:
        _require_no_parameters(field)
        return _int64_payload(column, binding.physical)
    if logical_type is LogicalType.DECIMAL:
        return _decimal_payload(field, column, binding.physical)
    if logical_type is LogicalType.BOOLEAN:
        _require_no_parameters(field)
        return _boolean_payload(column)
    if logical_type is LogicalType.STRING:
        _require_no_parameters(field)
        return _string_payload(column, binding.physical)
    if logical_type is LogicalType.DATE:
        _require_no_parameters(field)
        return _date_payload(column)
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        return _timestamp_local_payload(field, column)
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        return _timestamp_instant_payload(field, column)
    raise MssqlLoweringError(
        f"logical type {logical_type!r} is not supported by the SQL Server 2022 v1 profile"
    )


def _int64_payload(column: str, physical: MssqlPhysicalField) -> _PayloadLowering:
    value = f"TRY_CONVERT(bigint, {column})"
    roundtrip = f"TRY_CONVERT({_numeric_physical_type(physical)}, {value})"
    return _PayloadLowering(
        is_valid=f"{value} IS NOT NULL AND {roundtrip} = {column}",
        payload=f"CONVERT(varbinary(max), CONVERT(varchar(20), {value}))",
    )


def _decimal_payload(
    field: FieldSchema,
    column: str,
    physical: MssqlPhysicalField,
) -> _PayloadLowering:
    if not isinstance(field.parameters, DecimalParameters):
        raise MssqlLoweringError("decimal field requires DecimalParameters")
    precision = field.parameters.precision
    scale = field.parameters.scale
    value = f"TRY_CONVERT(decimal({precision}, {scale}), {column})"
    roundtrip = f"TRY_CONVERT({_numeric_physical_type(physical)}, {value})"
    fixed_text = f"CONVERT(varchar(41), {value})"
    scaled = f"TRY_CONVERT(decimal(38, 0), REPLACE({fixed_text}, '.', ''))"
    scaled_text = f"CONVERT(varchar(39), {scaled})"
    return _PayloadLowering(
        is_valid=f"{value} IS NOT NULL AND {roundtrip} = {column} AND {scaled} IS NOT NULL",
        payload=f"CONVERT(varbinary(max), {scaled_text})",
    )


def _boolean_payload(column: str) -> _PayloadLowering:
    return _PayloadLowering(
        is_valid=f"{column} IN (CONVERT(bit, 0), CONVERT(bit, 1))",
        payload=(
            "CASE WHEN "
            f"{column} = CONVERT(bit, 1) THEN CONVERT(varbinary(max), 0x31) "
            f"WHEN {column} = CONVERT(bit, 0) THEN CONVERT(varbinary(max), 0x30) "
            "ELSE CONVERT(varbinary(max), NULL) END"
        ),
    )


def _string_payload(column: str, physical: MssqlPhysicalField) -> _PayloadLowering:
    unicode_value = f"CONVERT(nvarchar(max), {column})"
    utf8_text = f"CONVERT(varchar(max), {unicode_value} COLLATE {_UTF8_COLLATION})"
    payload = f"CONVERT(varbinary(max), {utf8_text})"
    roundtrip_unicode = f"CONVERT(nvarchar(max), ({utf8_text}) COLLATE {_UTF8_COLLATION})"
    unicode_bytes = f"CONVERT(varbinary(max), {unicode_value})"
    roundtrip_bytes = f"CONVERT(varbinary(max), {roundtrip_unicode})"
    lossless_utf8 = (
        f"DATALENGTH({unicode_bytes}) = DATALENGTH({roundtrip_bytes}) "
        f"AND {unicode_bytes} = {roundtrip_bytes}"
    )
    source_roundtrip = _string_source_roundtrip(column, unicode_value, physical)
    no_nul = (
        "NOT EXISTS (SELECT 1 FROM GENERATE_SERIES("
        "CONVERT(bigint, 1), "
        f"COALESCE(DATALENGTH({payload}), CONVERT(bigint, 0)), "
        "CONVERT(bigint, 1)) AS [dfe_utf8_byte] "
        f"WHERE SUBSTRING({payload}, [dfe_utf8_byte].[value], 1) = 0x00)"
    )
    return _PayloadLowering(
        is_valid=(
            f"{unicode_value} IS NOT NULL AND {lossless_utf8} AND {source_roundtrip} AND {no_nul}"
        ),
        payload=payload,
    )


def _string_source_roundtrip(
    column: str,
    unicode_value: str,
    physical: MssqlPhysicalField,
) -> str:
    if physical.system_type_name == "nvarchar":
        return "1 = 1"
    if physical.collation_name is None:
        raise MssqlLoweringError("SQL Server varchar provenance requires a collation")
    source_bytes = f"CONVERT(varbinary(max), CONVERT(varchar(max), {column}))"
    roundtrip_text = (
        "CONVERT(varchar(max), "
        f"{unicode_value} COLLATE {_quote_identifier(physical.collation_name)})"
    )
    roundtrip_bytes = f"CONVERT(varbinary(max), {roundtrip_text})"
    return (
        f"DATALENGTH({source_bytes}) = DATALENGTH({roundtrip_bytes}) "
        f"AND {source_bytes} = {roundtrip_bytes}"
    )


def _date_payload(column: str) -> _PayloadLowering:
    return _PayloadLowering(
        is_valid="1 = 1",
        payload=f"CONVERT(varbinary(max), CONVERT(char(10), {column}, 23))",
    )


def _timestamp_local_payload(field: FieldSchema, column: str) -> _PayloadLowering:
    precision = _timestamp_precision(field)
    return _timestamp_payload(column, column, precision, "")


def _timestamp_instant_payload(field: FieldSchema, column: str) -> _PayloadLowering:
    precision = _timestamp_precision(field)
    utc_value = f"SWITCHOFFSET({column}, '+00:00')"
    timestamp_value = f"CONVERT(datetime2(7), {utc_value})"
    return _timestamp_payload(utc_value, timestamp_value, precision, "Z")


def _timestamp_payload(
    validation_value: str,
    timestamp_value: str,
    precision: int,
    suffix: str,
) -> _PayloadLowering:
    fraction = (
        f"RIGHT('000000000' + CONVERT(varchar(9), DATEPART(nanosecond, {validation_value})), 9)"
    )
    fraction_text = "''" if precision == 0 else f"'.' + LEFT({fraction}, {precision})"
    payload_text = f"CONVERT(char(19), {timestamp_value}, 126) + {fraction_text} + '{suffix}'"
    if precision < 7:
        divisor = 10 ** (9 - precision)
        is_valid = f"DATEPART(nanosecond, {validation_value}) % {divisor} = 0"
    else:
        is_valid = "1 = 1"
    return _PayloadLowering(
        is_valid=is_valid,
        payload=f"CONVERT(varbinary(max), {payload_text})",
    )


def _timestamp_precision(field: FieldSchema) -> int:
    if not isinstance(field.parameters, TimestampParameters):
        raise MssqlLoweringError("timestamp field requires TimestampParameters")
    return field.parameters.precision


def _limb_sum_expression(index: int) -> str:
    offset = (index * 4) + 1
    weights = (16_777_216, 65_536, 256, 1)
    terms = tuple(
        "CONVERT(bigint, CONVERT(tinyint, "
        f"SUBSTRING([dfe_hash].[row_hash], {offset + byte_index}, 1))) * "
        f"CONVERT(bigint, {weight})"
        for byte_index, weight in enumerate(weights)
    )
    limb = " + ".join(terms)
    return (
        "COALESCE(SUM(CASE WHEN [dfe_hash].[row_hash] IS NULL "
        "THEN CONVERT(decimal(38, 0), 0) "
        f"ELSE CONVERT(decimal(38, 0), {limb}) END), "
        "CONVERT(decimal(38, 0), 0)) "
        f"AS {_quote_identifier(f'limb_{index}')}"
    )


def _validate_canonical_inputs(
    schema: CanonicalSchema,
    relation: MssqlRelation,
    bindings: tuple[MssqlFieldBinding, ...],
    max_encoded_envelope_bytes: int,
) -> None:
    if not isinstance(cast(object, schema), CanonicalSchema):
        raise MssqlLoweringError("schema must be a CanonicalSchema")
    if type(relation) is not MssqlRelation:
        raise MssqlLoweringError("relation must be MssqlRelation")
    _validate_bindings(schema, bindings)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "SQL Server maximum encoded envelope bytes",
        _MAX_LOB_BYTES,
    )


def _validate_bindings(
    schema: CanonicalSchema,
    bindings: tuple[MssqlFieldBinding, ...],
) -> None:
    if type(bindings) is not tuple:
        raise MssqlLoweringError("SQL Server field bindings must be an immutable tuple")
    if len(bindings) > MAX_COMPILED_RELATION_MEMBERS:
        raise MssqlLoweringError(
            "SQL Server canonical field count exceeds the executable profile limit: "
            f"fields={len(bindings)}, maximum={MAX_COMPILED_RELATION_MEMBERS}"
        )
    if len(bindings) != len(schema.fields):
        raise MssqlLoweringError(
            "SQL Server field binding count does not match logical schema: "
            f"bindings={len(bindings)}, fields={len(schema.fields)}"
        )
    for index, (field, binding) in enumerate(zip(schema.fields, bindings, strict=True)):
        if type(binding) is not MssqlFieldBinding:
            raise MssqlLoweringError(
                f"SQL Server field binding at index {index} must be MssqlFieldBinding"
            )
        if binding.field_name != field.name:
            raise MssqlLoweringError(
                "SQL Server field binding does not match logical schema order: "
                f"index={index}, expected={field.name!r}, actual={binding.field_name!r}"
            )
        _validate_physical_mapping(field, binding.physical, index)


def _validate_physical_mapping(
    field: FieldSchema,
    physical: MssqlPhysicalField,
    field_index: int,
) -> None:
    expected_type_id = _BUILTIN_TYPE_IDS.get(physical.system_type_name)
    if expected_type_id != physical.system_type_id:
        raise MssqlLoweringError(
            "SQL Server field mapping has an unsupported system type identity: "
            f"field_index={field_index}, system_type_name={physical.system_type_name!r}, "
            f"system_type_id={physical.system_type_id}"
        )
    if physical.user_type_id != physical.system_type_id:
        raise MssqlLoweringError(
            "SQL Server field mapping uses an alias or user-defined type: "
            f"field_index={field_index}, system_type_id={physical.system_type_id}, "
            f"user_type_id={physical.user_type_id}"
        )
    allowed_types = _allowed_base_types(field.logical_type)
    if physical.system_type_name not in allowed_types:
        allowed_text = ", ".join(f"sys.{name}" for name in allowed_types)
        raise MssqlLoweringError(
            "SQL Server field mapping is unsupported: "
            f"field_index={field_index}, logical_type={field.logical_type.value}, "
            f"physical_type=sys.{physical.system_type_name}, "
            f"allowed_physical_types={allowed_text}"
        )
    if physical.system_type_name in ("decimal", "numeric") and physical.precision < 1:
        raise MssqlLoweringError(
            "SQL Server decimal physical provenance requires precision in 1..38: "
            f"field_index={field_index}, precision={physical.precision}"
        )
    if physical.system_type_name in ("varchar", "nvarchar"):
        _validate_string_physical_provenance(physical, field_index)
    if physical.system_type_name in ("datetime2", "datetimeoffset") and physical.scale > 7:
        raise MssqlLoweringError(
            "SQL Server temporal physical scale must be in the range 0..7: "
            f"field_index={field_index}, scale={physical.scale}"
        )


def _validate_string_physical_provenance(
    physical: MssqlPhysicalField,
    field_index: int,
) -> None:
    if physical.collation_name is None:
        raise MssqlLoweringError(
            "SQL Server string physical provenance must include a collation: "
            f"field_index={field_index}"
        )
    if (
        physical.system_type_name == "nvarchar"
        and physical.max_length != -1
        and physical.max_length % 2 != 0
    ):
        raise MssqlLoweringError(
            "SQL Server nvarchar physical maximum length must be even or -1: "
            f"field_index={field_index}, max_length={physical.max_length}"
        )


def _allowed_base_types(logical_type: LogicalType) -> tuple[str, ...]:
    if logical_type in (LogicalType.INT64, LogicalType.DECIMAL):
        return ("tinyint", "smallint", "int", "bigint", "decimal", "numeric")
    if logical_type is LogicalType.BOOLEAN:
        return ("bit",)
    if logical_type is LogicalType.STRING:
        return ("varchar", "nvarchar")
    if logical_type is LogicalType.DATE:
        return ("date",)
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        return ("datetime2",)
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        return ("datetimeoffset",)
    raise MssqlLoweringError(
        f"logical type {logical_type!r} is not supported by the SQL Server 2022 v1 profile"
    )


def _numeric_physical_type(physical: MssqlPhysicalField) -> str:
    type_name = physical.system_type_name
    if type_name in ("decimal", "numeric"):
        return f"{type_name}({physical.precision}, {physical.scale})"
    if type_name in ("tinyint", "smallint", "int", "bigint"):
        return type_name
    raise MssqlLoweringError(
        "SQL Server numeric payload received incompatible physical provenance: "
        f"physical_type={type_name!r}"
    )


def _require_no_parameters(field: FieldSchema) -> None:
    if not isinstance(field.parameters, NoParameters):
        raise MssqlLoweringError(f"logical type {field.logical_type.value!r} requires NoParameters")


def _type_tag(logical_type: LogicalType) -> str:
    tags = {
        LogicalType.INT64: "01",
        LogicalType.DECIMAL: "02",
        LogicalType.BOOLEAN: "03",
        LogicalType.STRING: "04",
        LogicalType.DATE: "05",
        LogicalType.TIMESTAMP_LOCAL: "06",
        LogicalType.TIMESTAMP_INSTANT: "07",
    }
    try:
        return tags[logical_type]
    except KeyError:
        raise MssqlLoweringError(f"unsupported logical type {logical_type!r}") from None


def _qualified_column(column_name: str) -> str:
    return f"[dfe_source].{_quote_identifier(column_name)}"


def _quote_identifier(value: str) -> str:
    return "[" + value.replace("]", "]]") + "]"


def _validate_identifier(value: object, context: str) -> None:
    _validate_scalar_text(value, context)
    if not isinstance(value, str):
        raise AssertionError("validated SQL Server text did not retain its string type")
    if not value:
        raise MssqlLoweringError(f"{context} must not be empty")
    utf16_units = len(value.encode("utf-16-le")) // 2
    if utf16_units > 128:
        raise MssqlLoweringError(f"{context} exceeds the SQL Server 128-character limit")


def _validate_scalar_text(value: object, context: str) -> None:
    if type(value) is not str:
        raise MssqlLoweringError(f"{context} must be text")
    if "\x00" in value:
        raise MssqlLoweringError(f"{context} must not contain U+0000")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise MssqlLoweringError(f"{context} must not contain unpaired surrogates") from None


def _validate_positive_integer(value: object, context: str, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise MssqlLoweringError(f"{context} must be an integer in the range 1..{maximum}")


def _validate_nonnegative_integer(value: object, context: str, maximum: int) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise MssqlLoweringError(f"{context} must be an integer in the range 0..{maximum}")
