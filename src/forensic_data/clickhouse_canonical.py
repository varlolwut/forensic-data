import re
from dataclasses import dataclass
from typing import final

from pydantic import BaseModel, ConfigDict

from forensic_data.canonical import (
    CanonicalEnvelopeContext,
    CanonicalizationError,
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    Fingerprint,
    FingerprintOverflowError,
    LogicalType,
    TimestampParameters,
    decode_key_with_context,
    decode_row_with_context,
    envelope_sha256,
    prepare_envelope_context,
)
from forensic_data.canonical.model import DECIMAL_38_MAX, INT64_MAX
from forensic_data.clickhouse import (
    ClickHouseDataValidationError,
    ClickHouseParameter,
    ClickHouseResultLimitError,
    ClickHouseTransport,
    UnsupportedClickHouseProfileError,
    clickhouse_decimal_reinterpret_function,
    inspect_clickhouse_datetime64_type,
    parse_clickhouse_datetime64_declaration,
    parse_clickhouse_decimal_type,
    parse_clickhouse_json_rows,
    quote_clickhouse_identifier,
    validate_clickhouse_identifier,
    validate_clickhouse_text_scalar,
)

_LOWER_HEX_BYTES = re.compile(r"(?:[0-9a-f]{2})+\Z", re.ASCII)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_UNSIGNED_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
_NULLABLE_TYPE = re.compile(r"Nullable\((.+)\)\Z", re.ASCII)
_SHA256_BYTES = 32


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalFieldBinding:
    field_name: str
    column_name: str
    declared_type: str
    base_type: str
    nullable: bool
    datetime_timezone: str | None

    def __post_init__(self) -> None:
        _validate_logical_field_name(self.field_name)
        validate_clickhouse_identifier(self.column_name, "ClickHouse canonical column")
        validate_clickhouse_text_scalar(
            self.declared_type,
            "ClickHouse declared column type",
        )
        validate_clickhouse_text_scalar(self.base_type, "ClickHouse base column type")
        if type(self.nullable) is not bool:
            raise TypeError("ClickHouse canonical column nullability must be a boolean")
        if self.datetime_timezone is not None:
            validate_clickhouse_text_scalar(
                self.datetime_timezone,
                "ClickHouse DateTime64 effective timezone",
            )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalRelation:
    database: str
    table: str
    schema: CanonicalSchema
    bindings: tuple[ClickHouseCanonicalFieldBinding, ...]

    def __post_init__(self) -> None:
        validate_clickhouse_identifier(self.database, "ClickHouse canonical database")
        validate_clickhouse_identifier(self.table, "ClickHouse canonical table")
        if type(self.schema) is not CanonicalSchema:
            raise TypeError("ClickHouse canonical relation schema must be a CanonicalSchema")
        if type(self.bindings) is not tuple:
            raise TypeError("ClickHouse canonical bindings must be an immutable tuple")
        if not self.bindings:
            raise ValueError("ClickHouse canonical relations require at least one field binding")
        if len(self.bindings) != len(self.schema.fields):
            raise ValueError(
                "ClickHouse canonical binding count must equal the logical field count"
            )
        column_names: set[str] = set()
        for index, (field, binding) in enumerate(
            zip(self.schema.fields, self.bindings, strict=True)
        ):
            if type(binding) is not ClickHouseCanonicalFieldBinding:
                raise TypeError(
                    "ClickHouse canonical binding must be a "
                    f"ClickHouseCanonicalFieldBinding: field_index={index}"
                )
            if binding.field_name != field.name:
                raise ValueError(
                    "ClickHouse canonical bindings must follow logical schema order: "
                    f"field_index={index}, expected={field.name!r}, "
                    f"actual={binding.field_name!r}"
                )
            observed_base_type, observed_nullable = _unwrap_nullable_type(
                binding.declared_type,
                index,
            )
            if observed_base_type != binding.base_type or observed_nullable is not binding.nullable:
                raise ValueError(
                    "ClickHouse canonical binding provenance is inconsistent with its "
                    f"declared type: field_index={index}, "
                    f"declared_type={binding.declared_type!r}"
                )
            if binding.column_name in column_names:
                raise ValueError("ClickHouse canonical binding column names must be unique")
            column_names.add(binding.column_name)
            _validate_physical_mapping(field, binding, index)


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalLimits:
    max_encoded_envelope_bytes: int
    max_response_bytes: int
    max_execution_time_seconds: int

    def __post_init__(self) -> None:
        _validate_positive_integer(
            self.max_encoded_envelope_bytes,
            "ClickHouse canonical envelope byte limit",
            INT64_MAX,
        )
        _validate_positive_integer(
            self.max_response_bytes,
            "ClickHouse canonical response byte limit",
            INT64_MAX,
        )
        _validate_positive_integer(
            self.max_execution_time_seconds,
            "ClickHouse canonical execution time limit",
            INT64_MAX,
        )


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalReadRequest:
    relation: ClickHouseCanonicalRelation
    order_columns: tuple[str, ...]
    max_records: int
    limits: ClickHouseCanonicalLimits

    def __post_init__(self) -> None:
        _require_relation(self.relation)
        if type(self.order_columns) is not tuple or not self.order_columns:
            raise ValueError("ClickHouse canonical row order columns must be a nonempty tuple")
        if len(frozenset(self.order_columns)) != len(self.order_columns):
            raise ValueError("ClickHouse canonical row order columns must be unique")
        for column in self.order_columns:
            validate_clickhouse_identifier(column, "ClickHouse canonical order column")
        _validate_positive_integer(
            self.max_records,
            "ClickHouse canonical row record limit",
            INT64_MAX - 1,
        )
        _require_limits(self.limits)


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalGroupRequest:
    relation: ClickHouseCanonicalRelation
    max_groups: int
    limits: ClickHouseCanonicalLimits

    def __post_init__(self) -> None:
        _require_relation(self.relation)
        _validate_positive_integer(
            self.max_groups,
            "ClickHouse canonical key group limit",
            INT64_MAX - 3,
        )
        _require_limits(self.limits)


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalRow:
    envelope: bytes
    sha256: bytes


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalFingerprint:
    fingerprint: Fingerprint
    invalid_row_count: int
    oversized_row_count: int


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalKeyGroup:
    envelope: bytes
    row_count: int


@final
@dataclass(frozen=True, slots=True)
class ClickHouseCanonicalKeyGroups:
    groups: tuple[ClickHouseCanonicalKeyGroup, ...]
    valid_key_count: int
    invalid_key_count: int
    oversized_key_count: int


class _ClickHouseColumnPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    name: str
    type: str


class _ClickHouseCanonicalRowPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    envelope_hex: str | None
    sha256_hex: str | None
    invalid_row: str
    oversized_row: str


class _ClickHouseFingerprintPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    valid_row_count: str
    limb_0: str
    limb_1: str
    limb_2: str
    limb_3: str
    limb_4: str
    limb_5: str
    limb_6: str
    limb_7: str
    invalid_row_count: str
    oversized_row_count: str


class _ClickHouseKeyGroupPayload(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    invalid_key: str
    oversized_key: str
    envelope_hex: str
    envelope_bytes: str
    row_count: str


@dataclass(frozen=True, slots=True)
class _PayloadLowering:
    is_valid: str
    payload: str
    parameters: tuple[tuple[str, ClickHouseParameter], ...]


@dataclass(frozen=True, slots=True)
class _EnvelopeLowering:
    encoded_envelope: str
    invalid_value: str
    oversized_value: str
    accepted_envelope: str
    parameters: tuple[tuple[str, ClickHouseParameter], ...]


@dataclass(frozen=True, slots=True)
class _FieldLowering:
    frame: str
    payload_is_valid: str
    is_null: str | None
    parameters: tuple[tuple[str, ClickHouseParameter], ...]


def inspect_clickhouse_canonical_relation(
    transport: ClickHouseTransport,
    database: str,
    table: str,
    schema: CanonicalSchema,
    column_names: tuple[str, ...],
    max_response_bytes: int,
    max_execution_time_seconds: int,
) -> ClickHouseCanonicalRelation:
    validate_clickhouse_identifier(database, "ClickHouse canonical database")
    validate_clickhouse_identifier(table, "ClickHouse canonical table")
    if type(schema) is not CanonicalSchema:
        raise TypeError("ClickHouse canonical schema must be a CanonicalSchema")
    if type(column_names) is not tuple or not column_names:
        raise ValueError("ClickHouse canonical column names must be a nonempty tuple")
    if len(column_names) != len(schema.fields):
        raise ValueError("ClickHouse canonical column count must equal the logical field count")
    if len(frozenset(column_names)) != len(column_names):
        raise ValueError("ClickHouse canonical column names must be unique")
    for column_name in column_names:
        validate_clickhouse_identifier(column_name, "ClickHouse canonical column")
    _validate_positive_integer(
        max_response_bytes,
        "ClickHouse canonical catalog response byte limit",
        INT64_MAX,
    )
    _validate_positive_integer(
        max_execution_time_seconds,
        "ClickHouse canonical catalog execution time limit",
        INT64_MAX,
    )
    placeholders = ", ".join(f"{{column_{index}:String}}" for index in range(len(column_names)))
    parameters: dict[str, ClickHouseParameter] = {
        "database": database,
        "table": table,
    }
    parameters.update(
        {f"column_{index}": column_name for index, column_name in enumerate(column_names)}
    )
    result = transport.execute_raw(
        query=(
            "SELECT name, type FROM system.columns "
            "WHERE database = {database:String} AND table = {table:String} "
            f"AND name IN ({placeholders}) ORDER BY position"
        ),
        parameters=parameters,
        settings={
            "session_timezone": "UTC",
            "max_execution_time": max_execution_time_seconds,
            "max_result_rows": len(column_names) + 1,
            "max_result_bytes": max_response_bytes,
            "result_overflow_mode": "throw",
        },
        result_format="JSONEachRow",
        max_response_bytes=max_response_bytes,
        operation="inspect_canonical_relation",
    )
    rows = parse_clickhouse_json_rows(
        result.payload,
        _ClickHouseColumnPayload,
        "canonical relation catalog",
    )
    by_name = {row.name: row for row in rows}
    if (
        len(rows) != len(column_names)
        or len(by_name) != len(column_names)
        or set(by_name) != set(column_names)
    ):
        raise ClickHouseDataValidationError(
            "ClickHouse canonical relation must expose every requested column exactly once: "
            f"database={database!r}, table={table!r}, "
            f"expected_columns={column_names!r}, observed_columns={tuple(by_name)!r}"
        )
    bindings = tuple(
        _inspect_field_binding(
            transport,
            field,
            column_name,
            by_name[column_name].type,
            index,
        )
        for index, (field, column_name) in enumerate(zip(schema.fields, column_names, strict=True))
    )
    return ClickHouseCanonicalRelation(
        database=database,
        table=table,
        schema=schema,
        bindings=bindings,
    )


def read_clickhouse_canonical_rows(
    transport: ClickHouseTransport,
    request: ClickHouseCanonicalReadRequest,
) -> tuple[ClickHouseCanonicalRow, ...]:
    if type(request) is not ClickHouseCanonicalReadRequest:
        raise TypeError("request must be ClickHouseCanonicalReadRequest")
    context = prepare_envelope_context(request.relation.schema)
    lowering = _lower_row_envelope(request.relation, context, request.limits)
    result_limit = request.max_records + 1
    parameters = _parameter_dict((*lowering.parameters, ("result_limit", result_limit)))
    result = transport.execute_raw(
        query=(
            "WITH "
            f"{lowering.encoded_envelope} AS encoded_envelope, "
            f"{lowering.invalid_value} AS invalid_value, "
            f"{lowering.oversized_value} AS oversized_value, "
            f"{lowering.accepted_envelope} AS row_envelope "
            "SELECT "
            "if(isNull(row_envelope), CAST(NULL AS Nullable(String)), "
            "lower(hex(assumeNotNull(row_envelope)))) AS envelope_hex, "
            "if(isNull(row_envelope), CAST(NULL AS Nullable(String)), "
            "lower(hex(SHA256(assumeNotNull(row_envelope))))) AS sha256_hex, "
            "toString(toUInt8(invalid_value)) AS invalid_row, "
            "toString(toUInt8(oversized_value)) AS oversized_row "
            f"FROM {_relation_sql(request.relation)} AS dfe_source "
            f"ORDER BY {_order_sql(request.order_columns)} "
            "LIMIT {result_limit:UInt64}"
        ),
        parameters=parameters,
        settings=_ordered_query_settings(request.limits, result_limit),
        result_format="JSONEachRow",
        max_response_bytes=request.limits.max_response_bytes,
        operation="read_canonical_rows",
    )
    payloads = parse_clickhouse_json_rows(
        result.payload,
        _ClickHouseCanonicalRowPayload,
        "canonical row read",
    )
    if len(payloads) > request.max_records:
        raise ClickHouseResultLimitError(
            "ClickHouse canonical row read exceeded its record bound: "
            f"query_id={result.query_id}, max_records={request.max_records}, "
            f"observed_records_at_least={len(payloads)}"
        )
    return tuple(
        _parse_canonical_row(payload, context, request.limits, index)
        for index, payload in enumerate(payloads, start=1)
    )


def read_clickhouse_canonical_fingerprint(
    transport: ClickHouseTransport,
    relation: ClickHouseCanonicalRelation,
    limits: ClickHouseCanonicalLimits,
) -> ClickHouseCanonicalFingerprint:
    _require_relation(relation)
    _require_limits(limits)
    context = prepare_envelope_context(relation.schema)
    lowering = _lower_row_envelope(relation, context, limits)
    limb_selects = ", ".join(
        "toString(sumIf(CAST("
        "reinterpretAsUInt32(reverse(substring(row_hash, "
        f"{(index * 4) + 1}, 4))) AS Decimal(38, 0)), accepted_row)) AS limb_{index}"
        for index in range(8)
    )
    result = transport.execute_raw(
        query=(
            "WITH "
            f"{lowering.encoded_envelope} AS encoded_envelope, "
            f"{lowering.invalid_value} AS invalid_value, "
            f"{lowering.oversized_value} AS oversized_value, "
            "NOT invalid_value AND NOT oversized_value AS accepted_row, "
            "SHA256(encoded_envelope) AS row_hash "
            "SELECT toString(countIf(accepted_row)) AS valid_row_count, "
            f"{limb_selects}, "
            "toString(countIf(invalid_value)) AS invalid_row_count, "
            "toString(countIf(oversized_value)) AS oversized_row_count "
            f"FROM {_relation_sql(relation)} AS dfe_source"
        ),
        parameters=_parameter_dict(lowering.parameters),
        settings=_common_query_settings(limits, 1),
        result_format="JSONEachRow",
        max_response_bytes=limits.max_response_bytes,
        operation="read_canonical_fingerprint",
    )
    payloads = parse_clickhouse_json_rows(
        result.payload,
        _ClickHouseFingerprintPayload,
        "canonical fingerprint",
    )
    if len(payloads) != 1:
        raise ClickHouseDataValidationError(
            f"ClickHouse canonical fingerprint must return exactly one row: actual={len(payloads)}"
        )
    return _parse_fingerprint(payloads[0], limits)


def read_clickhouse_canonical_key_groups(
    transport: ClickHouseTransport,
    request: ClickHouseCanonicalGroupRequest,
) -> ClickHouseCanonicalKeyGroups:
    if type(request) is not ClickHouseCanonicalGroupRequest:
        raise TypeError("request must be ClickHouseCanonicalGroupRequest")
    context = prepare_envelope_context(request.relation.schema)
    lowering = _lower_key_envelope(request.relation, context, request.limits)
    result_limit = request.max_groups + 3
    result = transport.execute_raw(
        query=(
            "WITH "
            f"{lowering.encoded_envelope} AS encoded_envelope, "
            f"{lowering.invalid_value} AS invalid_value, "
            f"{lowering.oversized_value} AS oversized_value, "
            "if(invalid_value OR oversized_value, '', encoded_envelope) AS key_envelope "
            "SELECT toString(toUInt8(invalid_value)) AS invalid_key, "
            "toString(toUInt8(oversized_value)) AS oversized_key, "
            "if(invalid_value OR oversized_value, '', lower(hex(key_envelope))) "
            "AS envelope_hex, "
            "if(invalid_value OR oversized_value, '0', toString(length(key_envelope))) "
            "AS envelope_bytes, toString(count()) AS row_count "
            f"FROM {_relation_sql(request.relation)} AS dfe_source "
            "GROUP BY invalid_value, oversized_value, key_envelope "
            "ORDER BY invalid_value DESC, oversized_value DESC, key_envelope ASC "
            "LIMIT {result_limit:UInt64}"
        ),
        parameters=_parameter_dict((*lowering.parameters, ("result_limit", result_limit))),
        settings=_key_group_query_settings(request.limits, result_limit),
        result_format="JSONEachRow",
        max_response_bytes=request.limits.max_response_bytes,
        operation="read_canonical_key_groups",
    )
    payloads = parse_clickhouse_json_rows(
        result.payload,
        _ClickHouseKeyGroupPayload,
        "canonical key groups",
    )
    return _parse_key_groups(payloads, context, request)


def _inspect_field_binding(
    transport: ClickHouseTransport,
    field: FieldSchema,
    column_name: str,
    declared_type: str,
    field_index: int,
) -> ClickHouseCanonicalFieldBinding:
    base_type, nullable = _unwrap_nullable_type(declared_type, field_index)
    datetime_timezone: str | None = None
    if field.logical_type in (
        LogicalType.TIMESTAMP_LOCAL,
        LogicalType.TIMESTAMP_INSTANT,
    ):
        datetime_type = inspect_clickhouse_datetime64_type(transport, base_type)
        datetime_timezone = datetime_type.timezone
    binding = ClickHouseCanonicalFieldBinding(
        field_name=field.name,
        column_name=column_name,
        declared_type=declared_type,
        base_type=base_type,
        nullable=nullable,
        datetime_timezone=datetime_timezone,
    )
    return binding


def _unwrap_nullable_type(type_name: str, field_index: int) -> tuple[str, bool]:
    validate_clickhouse_text_scalar(type_name, "ClickHouse canonical physical type")
    match = _NULLABLE_TYPE.fullmatch(type_name)
    if match is None:
        return type_name, False
    base_type = match.group(1)
    if _NULLABLE_TYPE.fullmatch(base_type) is not None:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse canonical field has nested Nullable wrappers: "
            f"field_index={field_index}, physical_type={type_name!r}"
        )
    return base_type, True


def _validate_physical_mapping(
    field: FieldSchema,
    binding: ClickHouseCanonicalFieldBinding,
    field_index: int,
) -> None:
    logical_type = field.logical_type
    base_type = binding.base_type
    if logical_type is LogicalType.INT64:
        _require_base_type(base_type, ("Int64",), logical_type, field_index)
        return
    if logical_type is LogicalType.DECIMAL:
        parameters = field.parameters
        if not isinstance(parameters, DecimalParameters):
            raise TypeError("ClickHouse decimal field parameters are inconsistent")
        parse_clickhouse_decimal_type(base_type)
        return
    if logical_type is LogicalType.BOOLEAN:
        _require_base_type(base_type, ("Bool",), logical_type, field_index)
        return
    if logical_type is LogicalType.STRING:
        _require_base_type(base_type, ("String",), logical_type, field_index)
        return
    if logical_type is LogicalType.DATE:
        _require_base_type(base_type, ("Date", "Date32"), logical_type, field_index)
        return
    if logical_type in (
        LogicalType.TIMESTAMP_LOCAL,
        LogicalType.TIMESTAMP_INSTANT,
    ):
        parameters = field.parameters
        if not isinstance(parameters, TimestampParameters):
            raise TypeError("ClickHouse timestamp field parameters are inconsistent")
        parse_clickhouse_datetime64_declaration(base_type)
        if binding.datetime_timezone is None:
            raise UnsupportedClickHouseProfileError(
                "ClickHouse canonical DateTime64 inspection omitted its effective timezone: "
                f"field_index={field_index}, physical_type={base_type!r}"
            )
        if logical_type is LogicalType.TIMESTAMP_LOCAL and binding.datetime_timezone != "UTC":
            raise UnsupportedClickHouseProfileError(
                "ClickHouse timestamp_local requires an effective UTC DateTime64 column "
                "to avoid ambiguous wall-clock values at timezone folds: "
                f"field_index={field_index}, "
                f"effective_timezone={binding.datetime_timezone!r}"
            )
        return
    raise UnsupportedClickHouseProfileError(
        "ClickHouse canonical profile does not support the logical type: "
        f"field_index={field_index}, logical_type={logical_type.value!r}"
    )


def _require_base_type(
    actual: str,
    allowed: tuple[str, ...],
    logical_type: LogicalType,
    field_index: int,
) -> None:
    if actual not in allowed:
        raise UnsupportedClickHouseProfileError(
            "ClickHouse canonical physical type is unsupported: "
            f"field_index={field_index}, logical_type={logical_type.value!r}, "
            f"physical_type={actual!r}, allowed_physical_types={allowed!r}"
        )


def _lower_row_envelope(
    relation: ClickHouseCanonicalRelation,
    context: CanonicalEnvelopeContext,
    limits: ClickHouseCanonicalLimits,
) -> _EnvelopeLowering:
    fields = tuple(
        _field_lowering(field, binding, index)
        for index, (field, binding) in enumerate(
            zip(relation.schema.fields, relation.bindings, strict=True)
        )
    )
    validities: list[str] = []
    for field, lowering in zip(relation.schema.fields, fields, strict=True):
        if lowering.is_null is None:
            validities.append(f"({lowering.payload_is_valid})")
        elif field.nullable:
            validities.append(f"({lowering.is_null} OR ({lowering.payload_is_valid}))")
        else:
            validities.append(f"(NOT {lowering.is_null} AND ({lowering.payload_is_valid}))")
    return _assemble_envelope(
        context.row_header,
        limits,
        fields,
        tuple(validities),
    )


def _lower_key_envelope(
    relation: ClickHouseCanonicalRelation,
    context: CanonicalEnvelopeContext,
    limits: ClickHouseCanonicalLimits,
) -> _EnvelopeLowering:
    fields = tuple(
        _field_lowering(field, binding, index)
        for index, (field, binding) in enumerate(
            zip(relation.schema.fields, relation.bindings, strict=True)
        )
    )
    validities = tuple(
        (
            f"({field.payload_is_valid})"
            if field.is_null is None
            else f"(NOT {field.is_null} AND ({field.payload_is_valid}))"
        )
        for field in fields
    )
    return _assemble_envelope(
        context.key_header,
        limits,
        fields,
        validities,
    )


def _field_lowering(
    field: FieldSchema,
    binding: ClickHouseCanonicalFieldBinding,
    field_index: int,
) -> _FieldLowering:
    column = _column_sql(binding)
    value = f"assumeNotNull({column})" if binding.nullable else column
    payload = _payload_lowering(field, binding, value, field_index)
    present_frame = (
        f"concat('{_type_tag(field.logical_type)}', '1', "
        "leftPad(lower(hex(toUInt64(length("
        f"{payload.payload})))), 16, '0'), lower(hex({payload.payload})))"
    )
    if not binding.nullable:
        return _FieldLowering(
            frame=present_frame,
            payload_is_valid=payload.is_valid,
            is_null=None,
            parameters=payload.parameters,
        )
    null_frame = f"'{_type_tag(field.logical_type)}00000000000000000'"
    return _FieldLowering(
        frame=f"if(isNull({column}), {null_frame}, {present_frame})",
        payload_is_valid=payload.is_valid,
        is_null=f"isNull({column})",
        parameters=payload.parameters,
    )


def _assemble_envelope(
    header: str,
    limits: ClickHouseCanonicalLimits,
    fields: tuple[_FieldLowering, ...],
    validities: tuple[str, ...],
) -> _EnvelopeLowering:
    parameters: list[tuple[str, ClickHouseParameter]] = [
        ("canonical_header", header),
        ("max_encoded_envelope_bytes", limits.max_encoded_envelope_bytes),
    ]
    for field in fields:
        parameters.extend(field.parameters)
    encoded = (
        "concat({canonical_header:String}, " + ", ".join(field.frame for field in fields) + ")"
    )
    invalid = "NOT (" + " AND ".join(validities) + ")"
    oversized = (
        "if(invalid_value, false, length(encoded_envelope) > {max_encoded_envelope_bytes:UInt64})"
    )
    accepted = (
        "if(invalid_value OR oversized_value, CAST(NULL AS Nullable(String)), encoded_envelope)"
    )
    return _EnvelopeLowering(
        encoded_envelope=encoded,
        invalid_value=invalid,
        oversized_value=oversized,
        accepted_envelope=accepted,
        parameters=tuple(parameters),
    )


def _payload_lowering(
    field: FieldSchema,
    binding: ClickHouseCanonicalFieldBinding,
    value: str,
    field_index: int,
) -> _PayloadLowering:
    logical_type = field.logical_type
    if logical_type is LogicalType.INT64:
        return _PayloadLowering("true", f"toString({value})", ())
    if logical_type is LogicalType.DECIMAL:
        return _decimal_payload_lowering(field, binding, value, field_index)
    if logical_type is LogicalType.BOOLEAN:
        return _PayloadLowering("true", f"if({value}, '1', '0')", ())
    if logical_type is LogicalType.STRING:
        return _PayloadLowering(
            f"isValidUTF8({value}) AND position({value}, char(0)) = 0",
            value,
            (),
        )
    if logical_type is LogicalType.DATE:
        rendered = f"toString({value})"
        return _PayloadLowering(
            f"length({rendered}) = 10 AND substring({rendered}, 1, 4) != '0000'",
            rendered,
            (),
        )
    if logical_type in (
        LogicalType.TIMESTAMP_LOCAL,
        LogicalType.TIMESTAMP_INSTANT,
    ):
        return _timestamp_payload_lowering(field, binding, value, field_index)
    raise UnsupportedClickHouseProfileError(
        "ClickHouse canonical payload lowering does not support the logical type: "
        f"field_index={field_index}, logical_type={logical_type.value!r}"
    )


def _decimal_payload_lowering(
    field: FieldSchema,
    binding: ClickHouseCanonicalFieldBinding,
    value: str,
    field_index: int,
) -> _PayloadLowering:
    parameters = field.parameters
    if not isinstance(parameters, DecimalParameters):
        raise TypeError("ClickHouse decimal field parameters are inconsistent")
    physical = parse_clickhouse_decimal_type(binding.base_type)
    reinterpret = clickhouse_decimal_reinterpret_function(physical.precision)
    scaled = f"toInt256({reinterpret}({value}))"
    if physical.scale < parameters.scale:
        scale_delta = parameters.scale - physical.scale
        scaled_text = f"toString({scaled})"
        digit_count = f"length({scaled_text}) - if({scaled} < 0, toUInt64(1), toUInt64(0))"
        return _PayloadLowering(
            is_valid=(f"{scaled} = 0 OR {digit_count} + {scale_delta} <= {parameters.precision}"),
            payload=(f"if({scaled} = 0, '0', concat({scaled_text}, repeat('0', {scale_delta})))"),
            parameters=(),
        )
    bound_name = f"decimal_bound_{field_index}"
    bound_parameter = ((bound_name, str(10**parameters.precision)),)
    if physical.scale == parameters.scale:
        return _PayloadLowering(
            is_valid=(
                f"{scaled} > -toInt256({{{bound_name}:String}}) AND "
                f"{scaled} < toInt256({{{bound_name}:String}})"
            ),
            payload=f"toString({scaled})",
            parameters=bound_parameter,
        )
    scale_delta = physical.scale - parameters.scale
    divisor_name = f"decimal_divisor_{field_index}"
    logical_scaled = f"intDiv({scaled}, toInt256({{{divisor_name}:String}}))"
    return _PayloadLowering(
        is_valid=(
            f"modulo({scaled}, toInt256({{{divisor_name}:String}})) = 0 AND "
            f"{logical_scaled} > -toInt256({{{bound_name}:String}}) AND "
            f"{logical_scaled} < toInt256({{{bound_name}:String}})"
        ),
        payload=f"toString({logical_scaled})",
        parameters=(
            (divisor_name, str(10**scale_delta)),
            *bound_parameter,
        ),
    )


def _timestamp_payload_lowering(
    field: FieldSchema,
    binding: ClickHouseCanonicalFieldBinding,
    value: str,
    field_index: int,
) -> _PayloadLowering:
    parameters = field.parameters
    if not isinstance(parameters, TimestampParameters):
        raise TypeError("ClickHouse timestamp field parameters are inconsistent")
    timezone = binding.datetime_timezone
    if timezone is None:
        raise TypeError("ClickHouse DateTime64 binding lacks an effective timezone")
    physical_precision = parse_clickhouse_datetime64_declaration(binding.base_type)[0]
    timezone_name = f"datetime_timezone_{field_index}"
    output_timezone = "UTC" if field.logical_type is LogicalType.TIMESTAMP_INSTANT else timezone
    zoned = f"toTimeZone({value}, {{{timezone_name}:String}})"
    physical_text = f"toString({zoned})"
    expected_physical_length = 19 + (physical_precision + 1 if physical_precision else 0)
    validity = (
        f"length({physical_text}) = {expected_physical_length} AND "
        f"substring({physical_text}, 1, 4) != '0000'"
    )
    timestamp_parameters: tuple[tuple[str, ClickHouseParameter], ...] = (
        (timezone_name, output_timezone),
    )
    if physical_precision > parameters.precision:
        scale_delta = physical_precision - parameters.precision
        divisor_name = f"timestamp_divisor_{field_index}"
        validity += f" AND modulo(reinterpretAsInt64({value}), {{{divisor_name}:Int64}}) = 0"
        logical_length = 19 + (parameters.precision + 1 if parameters.precision else 0)
        logical_text = f"substring({physical_text}, 1, {logical_length})"
        timestamp_parameters = (
            *timestamp_parameters,
            (divisor_name, 10**scale_delta),
        )
    elif physical_precision < parameters.precision:
        scale_delta = parameters.precision - physical_precision
        if physical_precision == 0:
            logical_text = f"concat({physical_text}, '.', repeat('0', {parameters.precision}))"
        else:
            logical_text = f"concat({physical_text}, repeat('0', {scale_delta}))"
    else:
        logical_text = physical_text
    rendered = f"replaceOne({logical_text}, ' ', 'T')"
    payload = (
        f"concat({rendered}, 'Z')"
        if field.logical_type is LogicalType.TIMESTAMP_INSTANT
        else rendered
    )
    return _PayloadLowering(
        is_valid=validity,
        payload=payload,
        parameters=timestamp_parameters,
    )


def _parse_canonical_row(
    payload: _ClickHouseCanonicalRowPayload,
    context: CanonicalEnvelopeContext,
    limits: ClickHouseCanonicalLimits,
    row_ordinal: int,
) -> ClickHouseCanonicalRow:
    invalid = _parse_flag(payload.invalid_row, f"canonical row {row_ordinal} invalid status")
    oversized = _parse_flag(
        payload.oversized_row,
        f"canonical row {row_ordinal} oversized status",
    )
    if invalid and oversized:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical row statuses must be mutually exclusive: "
            f"row_ordinal={row_ordinal}"
        )
    if invalid or oversized:
        if payload.envelope_hex is not None or payload.sha256_hex is not None:
            raise ClickHouseDataValidationError(
                "ClickHouse rejected canonical rows must not expose an envelope or digest: "
                f"row_ordinal={row_ordinal}"
            )
        if invalid:
            raise ClickHouseDataValidationError(
                "ClickHouse source row cannot be represented losslessly by the logical schema: "
                f"row_ordinal={row_ordinal}"
            )
        raise ClickHouseResultLimitError(
            "ClickHouse canonical envelope exceeds the configured SQL-side limit: "
            f"row_ordinal={row_ordinal}, "
            f"max_encoded_envelope_bytes={limits.max_encoded_envelope_bytes}"
        )
    envelope = _parse_hex_bytes(payload.envelope_hex, "canonical row envelope", row_ordinal)
    digest = _parse_sha256(payload.sha256_hex, "canonical row SHA-256", row_ordinal)
    if len(envelope) > limits.max_encoded_envelope_bytes:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical row exceeds its declared SQL-side byte limit: "
            f"row_ordinal={row_ordinal}, observed={len(envelope)}, "
            f"limit={limits.max_encoded_envelope_bytes}"
        )
    try:
        decode_row_with_context(context, envelope)
    except CanonicalizationError as error:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical row failed reference decoding: "
            f"row_ordinal={row_ordinal}, reason_type={type(error).__name__}"
        ) from None
    if envelope_sha256(envelope) != digest:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical row SHA-256 does not match its envelope: "
            f"row_ordinal={row_ordinal}"
        )
    return ClickHouseCanonicalRow(envelope=envelope, sha256=digest)


def _parse_fingerprint(
    payload: _ClickHouseFingerprintPayload,
    limits: ClickHouseCanonicalLimits,
) -> ClickHouseCanonicalFingerprint:
    count = _parse_unsigned(payload.valid_row_count, "valid row count", INT64_MAX)
    limb_texts = (
        payload.limb_0,
        payload.limb_1,
        payload.limb_2,
        payload.limb_3,
        payload.limb_4,
        payload.limb_5,
        payload.limb_6,
        payload.limb_7,
    )
    limbs = tuple(
        _parse_unsigned(value, f"fingerprint limb {index}", DECIMAL_38_MAX)
        for index, value in enumerate(limb_texts)
    )
    invalid_count = _parse_unsigned(
        payload.invalid_row_count,
        "invalid row count",
        INT64_MAX,
    )
    oversized_count = _parse_unsigned(
        payload.oversized_row_count,
        "oversized row count",
        INT64_MAX,
    )
    if invalid_count:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical fingerprint rejected source rows that cannot be "
            f"represented losslessly: invalid_row_count={invalid_count}"
        )
    if oversized_count:
        raise ClickHouseResultLimitError(
            "ClickHouse canonical fingerprint found envelopes above the configured limit: "
            f"oversized_row_count={oversized_count}, "
            f"max_encoded_envelope_bytes={limits.max_encoded_envelope_bytes}"
        )
    try:
        fingerprint = Fingerprint(
            count=count,
            limb_sums=(
                limbs[0],
                limbs[1],
                limbs[2],
                limbs[3],
                limbs[4],
                limbs[5],
                limbs[6],
                limbs[7],
            ),
        )
    except FingerprintOverflowError as error:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical fingerprint violates exact accumulator bounds: "
            f"reason_type={type(error).__name__}, reason={str(error)!r}"
        ) from None
    return ClickHouseCanonicalFingerprint(
        fingerprint=fingerprint,
        invalid_row_count=invalid_count,
        oversized_row_count=oversized_count,
    )


def _parse_key_groups(
    payloads: tuple[_ClickHouseKeyGroupPayload, ...],
    context: CanonicalEnvelopeContext,
    request: ClickHouseCanonicalGroupRequest,
) -> ClickHouseCanonicalKeyGroups:
    groups: list[ClickHouseCanonicalKeyGroup] = []
    seen_envelopes: set[bytes] = set()
    valid_count = 0
    invalid_count = 0
    oversized_count = 0
    for ordinal, payload in enumerate(payloads, start=1):
        invalid = _parse_flag(payload.invalid_key, f"key group {ordinal} invalid status")
        oversized = _parse_flag(payload.oversized_key, f"key group {ordinal} oversized status")
        row_count = _parse_unsigned(payload.row_count, f"key group {ordinal} row count", INT64_MAX)
        envelope_bytes = _parse_unsigned(
            payload.envelope_bytes,
            f"key group {ordinal} envelope byte length",
            INT64_MAX,
        )
        if row_count < 1:
            raise ClickHouseDataValidationError(
                "ClickHouse canonical key group row count must be positive: "
                f"group_ordinal={ordinal}"
            )
        if invalid and oversized:
            raise ClickHouseDataValidationError(
                "ClickHouse canonical key statuses must be mutually exclusive: "
                f"group_ordinal={ordinal}"
            )
        if invalid or oversized:
            if payload.envelope_hex or envelope_bytes:
                raise ClickHouseDataValidationError(
                    "ClickHouse rejected canonical key groups must not expose an envelope: "
                    f"group_ordinal={ordinal}"
                )
            if invalid:
                invalid_count = _add_count(invalid_count, row_count, "invalid key count")
            else:
                oversized_count = _add_count(
                    oversized_count,
                    row_count,
                    "oversized key count",
                )
            continue
        envelope = _parse_hex_bytes(
            payload.envelope_hex,
            "canonical key envelope",
            ordinal,
        )
        if len(envelope) != envelope_bytes:
            raise ClickHouseDataValidationError(
                "ClickHouse canonical key byte length does not match its envelope: "
                f"group_ordinal={ordinal}, declared={envelope_bytes}, actual={len(envelope)}"
            )
        if len(envelope) > request.limits.max_encoded_envelope_bytes:
            raise ClickHouseDataValidationError(
                "ClickHouse accepted canonical key exceeds its SQL-side byte limit: "
                f"group_ordinal={ordinal}, observed={len(envelope)}, "
                f"limit={request.limits.max_encoded_envelope_bytes}"
            )
        if envelope in seen_envelopes:
            raise ClickHouseDataValidationError(
                "ClickHouse returned duplicate groups for the same full canonical key: "
                f"group_ordinal={ordinal}"
            )
        try:
            decode_key_with_context(context, envelope)
        except CanonicalizationError as error:
            raise ClickHouseDataValidationError(
                "ClickHouse canonical key failed reference decoding: "
                f"group_ordinal={ordinal}, reason_type={type(error).__name__}"
            ) from None
        seen_envelopes.add(envelope)
        valid_count = _add_count(valid_count, row_count, "valid key count")
        groups.append(ClickHouseCanonicalKeyGroup(envelope=envelope, row_count=row_count))
    if len(groups) > request.max_groups:
        raise ClickHouseResultLimitError(
            "ClickHouse canonical key grouping exceeded its distinct-group bound: "
            f"max_groups={request.max_groups}, observed_groups_at_least={len(groups)}"
        )
    if invalid_count:
        raise ClickHouseDataValidationError(
            "ClickHouse canonical key grouping rejected NULL or unrepresentable keys: "
            f"invalid_key_count={invalid_count}"
        )
    if oversized_count:
        raise ClickHouseResultLimitError(
            "ClickHouse canonical key grouping found envelopes above the configured limit: "
            f"oversized_key_count={oversized_count}, "
            f"max_encoded_envelope_bytes={request.limits.max_encoded_envelope_bytes}"
        )
    return ClickHouseCanonicalKeyGroups(
        groups=tuple(groups),
        valid_key_count=valid_count,
        invalid_key_count=invalid_count,
        oversized_key_count=oversized_count,
    )


def _parse_hex_bytes(value: str | None, label: str, ordinal: int) -> bytes:
    if value is None or _LOWER_HEX_BYTES.fullmatch(value) is None:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be lowercase byte-pair hex: ordinal={ordinal}"
        )
    return bytes.fromhex(value)


def _parse_sha256(value: str | None, label: str, ordinal: int) -> bytes:
    if value is None or _LOWER_SHA256.fullmatch(value) is None:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be exactly 32 lowercase-hex bytes: ordinal={ordinal}"
        )
    digest = bytes.fromhex(value)
    if len(digest) != _SHA256_BYTES:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be exactly 32 bytes: ordinal={ordinal}"
        )
    return digest


def _parse_flag(value: str, label: str) -> bool:
    if value == "0":
        return False
    if value == "1":
        return True
    raise ClickHouseDataValidationError(f"ClickHouse {label} must be encoded as 0 or 1")


def _parse_unsigned(value: str, label: str, maximum: int) -> int:
    if _UNSIGNED_INTEGER.fullmatch(value) is None:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} must be a canonical unsigned decimal integer"
        )
    parsed = int(value)
    if parsed > maximum:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} exceeds its exact protocol bound: "
            f"maximum={maximum}, observed={parsed}"
        )
    return parsed


def _add_count(current: int, value: int, label: str) -> int:
    result = current + value
    if result > INT64_MAX:
        raise ClickHouseDataValidationError(
            f"ClickHouse {label} exceeds the signed int64 protocol bound"
        )
    return result


def _parameter_dict(
    parameters: tuple[tuple[str, ClickHouseParameter], ...],
) -> dict[str, ClickHouseParameter]:
    result: dict[str, ClickHouseParameter] = {}
    for name, value in parameters:
        if name in result:
            raise ValueError(f"duplicate ClickHouse query parameter name: {name!r}")
        result[name] = value
    return result


def _common_query_settings(
    limits: ClickHouseCanonicalLimits,
    max_result_rows: int,
) -> dict[str, ClickHouseParameter]:
    return {
        "session_timezone": "UTC",
        "max_execution_time": limits.max_execution_time_seconds,
        "timeout_overflow_mode": "throw",
        "timeout_overflow_mode_leaf": "throw",
        "read_overflow_mode": "throw",
        "read_overflow_mode_leaf": "throw",
        "max_result_rows": max_result_rows,
        "max_result_bytes": limits.max_response_bytes,
        "result_overflow_mode": "throw",
    }


def _ordered_query_settings(
    limits: ClickHouseCanonicalLimits,
    max_result_rows: int,
) -> dict[str, ClickHouseParameter]:
    return {
        **_common_query_settings(limits, max_result_rows),
        "sort_overflow_mode": "throw",
    }


def _key_group_query_settings(
    limits: ClickHouseCanonicalLimits,
    max_group_rows: int,
) -> dict[str, ClickHouseParameter]:
    return {
        **_ordered_query_settings(limits, max_group_rows),
        "max_rows_to_group_by": max_group_rows,
        "group_by_overflow_mode": "throw",
    }


def _relation_sql(relation: ClickHouseCanonicalRelation) -> str:
    return (
        f"{quote_clickhouse_identifier(relation.database)}."
        f"{quote_clickhouse_identifier(relation.table)}"
    )


def _column_sql(binding: ClickHouseCanonicalFieldBinding) -> str:
    return f"dfe_source.{quote_clickhouse_identifier(binding.column_name)}"


def _order_sql(order_columns: tuple[str, ...]) -> str:
    return ", ".join(
        f"dfe_source.{quote_clickhouse_identifier(column)}" for column in order_columns
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
    raise UnsupportedClickHouseProfileError(
        f"ClickHouse canonical profile does not support logical type {logical_type!r}"
    )


def _require_relation(value: object) -> None:
    if type(value) is not ClickHouseCanonicalRelation:
        raise TypeError("relation must be ClickHouseCanonicalRelation")


def _require_limits(value: object) -> None:
    if type(value) is not ClickHouseCanonicalLimits:
        raise TypeError("limits must be ClickHouseCanonicalLimits")


def _validate_positive_integer(value: int, label: str, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{label} must be an integer in the inclusive range 1..{maximum}")


def _validate_logical_field_name(value: object) -> None:
    if type(value) is not str:
        raise ValueError("ClickHouse logical field name must be text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(
            "ClickHouse logical field name must contain valid Unicode scalar values: "
            f"start={error.start}, end={error.end}"
        ) from None
