import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from sys import getsizeof
from textwrap import indent
from typing import cast, final
from uuid import uuid4

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
    decode_row_with_context,
    envelope_sha256,
    prepare_envelope_context,
)
from forensic_data.canonical.model import DECIMAL_38_MAX, INT64_MAX
from forensic_data.coordinator_memory import (
    BYTES_HEADER_BYTES,
    canonical_decode_scratch_bytes,
    list_storage_bytes,
    slot_object_bytes,
    tuple_storage_bytes,
)
from forensic_data.oracle import (
    OracleBindParameter,
    OracleDataValidationError,
    OracleProjection,
    OracleQuery,
    OracleReadContext,
    OracleReadResult,
    OracleResultLimitError,
    OracleValue,
    oracle_bind_occurrence_names,
    validate_oracle_select_statement,
)
from forensic_data.oracle_limits import (
    MAX_ORACLE_DECIMAL_OBJECT_BYTES,
    MAX_ORACLE_SQL_RAW_BYTES,
    MAX_ORACLE_SQL_VARCHAR2_BYTES,
    OracleProjectionKind,
    OracleTransportLimits,
)

_ORACLE_IDENTIFIER = re.compile(r"[A-Z][A-Z0-9_$#]{0,29}\Z", re.ASCII)
_RESERVED_BIND_PREFIX = "dfe_"
_ROW_HEADER_BYTES = 77
_FIELD_FRAME_BYTES = 19
_SHA256_BYTES = 32
_NUMBER_FORMAT = "FM" + ("9" * 38)
_LENGTH_HEX_FORMAT = "FM" + ("X" * 16)
_DATETIME_LANGUAGE = "NLS_DATE_LANGUAGE=American"
_NUMERIC_NLS = "NLS_NUMERIC_CHARACTERS=''.,''"
_INT64_MIN = -(1 << 63)
_SHA256_LOCAL_BYTES = getsizeof(hashlib.sha256()) + BYTES_HEADER_BYTES + _SHA256_BYTES


class OracleCanonicalLoweringError(ValueError):
    """An Oracle source cannot be lowered without changing canonical values."""


class OracleCanonicalPhysicalType(StrEnum):
    NUMBER = "NUMBER"
    CHAR = "CHAR"
    VARCHAR2 = "VARCHAR2"
    DATE = "DATE"
    TIMESTAMP = "TIMESTAMP"
    TIMESTAMP_WITH_TIME_ZONE = "TIMESTAMP WITH TIME ZONE"


@final
@dataclass(frozen=True, slots=True)
class OracleCanonicalFieldBinding:
    field_name: str
    column_name: str
    physical_type: OracleCanonicalPhysicalType
    nullable: bool
    numeric_precision: int | None
    numeric_scale: int | None
    max_bytes: int | None
    fractional_seconds_precision: int | None

    def __post_init__(self) -> None:
        _validate_scalar_text(self.field_name, "Oracle canonical logical field name")
        _validate_identifier(self.column_name, "Oracle canonical source alias")
        if type(cast(object, self.physical_type)) is not OracleCanonicalPhysicalType:
            raise TypeError("Oracle canonical physical_type must be OracleCanonicalPhysicalType")
        if type(self.nullable) is not bool:
            raise TypeError("Oracle canonical physical nullable provenance must be a boolean")
        if self.physical_type is OracleCanonicalPhysicalType.NUMBER:
            _validate_optional_integer_range(
                self.numeric_precision,
                "Oracle NUMBER precision",
                1,
                38,
            )
            _validate_optional_integer_range(
                self.numeric_scale,
                "Oracle NUMBER scale",
                -84,
                127,
            )
            _require_none(self.max_bytes, "Oracle NUMBER max_bytes")
            _require_none(
                self.fractional_seconds_precision,
                "Oracle NUMBER fractional-seconds precision",
            )
            return
        _require_none(self.numeric_precision, "Oracle non-NUMBER numeric precision")
        _require_none(self.numeric_scale, "Oracle non-NUMBER numeric scale")
        if self.physical_type in (
            OracleCanonicalPhysicalType.CHAR,
            OracleCanonicalPhysicalType.VARCHAR2,
        ):
            maximum = (
                MAX_ORACLE_SQL_RAW_BYTES
                if self.physical_type is OracleCanonicalPhysicalType.CHAR
                else MAX_ORACLE_SQL_VARCHAR2_BYTES
            )
            _validate_required_integer_range(
                self.max_bytes,
                f"Oracle {self.physical_type.value} byte length",
                1,
                maximum,
            )
            _require_none(
                self.fractional_seconds_precision,
                f"Oracle {self.physical_type.value} fractional-seconds precision",
            )
            return
        _require_none(self.max_bytes, "Oracle datetime max_bytes")
        if self.physical_type in (
            OracleCanonicalPhysicalType.TIMESTAMP,
            OracleCanonicalPhysicalType.TIMESTAMP_WITH_TIME_ZONE,
        ):
            _validate_required_integer_range(
                self.fractional_seconds_precision,
                "Oracle TIMESTAMP fractional-seconds precision",
                0,
                9,
            )
            return
        _require_none(
            self.fractional_seconds_precision,
            "Oracle DATE fractional-seconds precision",
        )


@final
@dataclass(frozen=True, slots=True)
class OracleCanonicalSelectSource:
    statement: str
    parameters: tuple[OracleBindParameter, ...]
    schema: CanonicalSchema
    bindings: tuple[OracleCanonicalFieldBinding, ...]
    full_scans: int

    def __post_init__(self) -> None:
        validate_oracle_select_statement(self.statement)
        if "\x00" in self.statement:
            raise ValueError("Oracle canonical source statement must not contain NUL")
        if type(self.parameters) is not tuple:
            raise TypeError("Oracle canonical source parameters must be an immutable tuple")
        parameter_names: set[str] = set()
        for parameter in self.parameters:
            if type(parameter) is not OracleBindParameter:
                raise TypeError(
                    "Oracle canonical source parameters must be OracleBindParameter values"
                )
            if parameter.name.startswith(_RESERVED_BIND_PREFIX):
                raise ValueError(
                    "Oracle canonical source bind names must not use the reserved prefix: "
                    f"prefix={_RESERVED_BIND_PREFIX!r}, bind_name={parameter.name!r}"
                )
            if parameter.name in parameter_names:
                raise ValueError(
                    f"Oracle canonical source has duplicate bind name {parameter.name!r}"
                )
            parameter_names.add(parameter.name)
        occurrence_names = frozenset(oracle_bind_occurrence_names(self.statement))
        reserved_occurrence_names = tuple(
            sorted(name for name in occurrence_names if name.startswith(_RESERVED_BIND_PREFIX))
        )
        if reserved_occurrence_names:
            raise ValueError(
                "Oracle canonical source statement must not use reserved bind placeholders: "
                f"prefix={_RESERVED_BIND_PREFIX!r}, "
                f"bind_names={reserved_occurrence_names!r}"
            )
        if occurrence_names != frozenset(parameter_names):
            raise ValueError(
                "Oracle canonical source bind placeholders must match source parameters exactly: "
                f"placeholder_names={sorted(occurrence_names)!r}, "
                f"parameter_names={sorted(parameter_names)!r}"
            )
        if type(self.schema) is not CanonicalSchema:
            raise TypeError("Oracle canonical source schema must be a CanonicalSchema")
        if type(self.bindings) is not tuple or not self.bindings:
            raise ValueError("Oracle canonical source bindings must be a nonempty tuple")
        if len(self.bindings) != len(self.schema.fields):
            raise OracleCanonicalLoweringError(
                "Oracle canonical binding count must equal the logical field count"
            )
        column_names: set[str] = set()
        for index, (field, binding) in enumerate(
            zip(self.schema.fields, self.bindings, strict=True)
        ):
            if type(binding) is not OracleCanonicalFieldBinding:
                raise TypeError(
                    "Oracle canonical bindings must be OracleCanonicalFieldBinding values: "
                    f"field_index={index}"
                )
            if binding.field_name != field.name:
                raise OracleCanonicalLoweringError(
                    "Oracle canonical bindings must follow logical schema order: "
                    f"field_index={index}, expected={field.name!r}, "
                    f"actual={binding.field_name!r}"
                )
            if binding.column_name in column_names:
                raise OracleCanonicalLoweringError(
                    "Oracle canonical source aliases must be unique: "
                    f"column_name={binding.column_name!r}"
                )
            column_names.add(binding.column_name)
            _validate_physical_mapping(field, binding, index)
        if type(self.full_scans) is not int or self.full_scans < 0:
            raise ValueError("Oracle canonical source full_scans must be non-negative")


@final
@dataclass(frozen=True, slots=True)
class OracleCanonicalLimits:
    field_count: int
    fixed_envelope_bytes: int
    max_total_payload_bytes: int
    max_payload_hex_bytes: int
    max_encoded_envelope_bytes: int
    max_sql_raw_bytes: int
    max_sql_varchar2_bytes: int

    def __post_init__(self) -> None:
        _validate_required_integer_range(
            self.field_count,
            "Oracle canonical field count",
            1,
            256,
        )
        for name, value in (
            ("fixed_envelope_bytes", self.fixed_envelope_bytes),
            ("max_encoded_envelope_bytes", self.max_encoded_envelope_bytes),
            ("max_sql_raw_bytes", self.max_sql_raw_bytes),
            ("max_sql_varchar2_bytes", self.max_sql_varchar2_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"Oracle canonical {name} must be a positive integer")
        for name, value in (
            ("max_total_payload_bytes", self.max_total_payload_bytes),
            ("max_payload_hex_bytes", self.max_payload_hex_bytes),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"Oracle canonical {name} must be a non-negative integer")
        expected_fixed = _ROW_HEADER_BYTES + (_FIELD_FRAME_BYTES * self.field_count)
        if self.fixed_envelope_bytes != expected_fixed:
            raise ValueError("Oracle canonical fixed envelope width is inconsistent")
        expected_payload = (self.max_encoded_envelope_bytes - expected_fixed) // 2
        if self.max_total_payload_bytes != expected_payload:
            raise ValueError("Oracle canonical payload width is inconsistent")
        if self.max_payload_hex_bytes != 2 * self.max_total_payload_bytes:
            raise ValueError("Oracle canonical payload hex width is inconsistent")
        if self.max_encoded_envelope_bytes > self.max_sql_raw_bytes:
            raise ValueError("Oracle canonical envelope exceeds the SQL RAW limit")
        if self.max_encoded_envelope_bytes > self.max_sql_varchar2_bytes:
            raise ValueError("Oracle canonical envelope exceeds the SQL VARCHAR2 limit")


@final
@dataclass(frozen=True, slots=True)
class OracleCanonicalRow:
    envelope: bytes
    sha256: bytes

    def __post_init__(self) -> None:
        if type(self.envelope) is not bytes or not self.envelope:
            raise ValueError("Oracle canonical envelope must be nonempty bytes")
        if type(self.sha256) is not bytes or len(self.sha256) != _SHA256_BYTES:
            raise ValueError("Oracle canonical SHA-256 must be exactly 32 bytes")


@dataclass(frozen=True, slots=True)
class _PayloadLowering:
    is_null: str
    is_valid: str
    payload: str


def build_oracle_canonical_limits(
    transport: OracleTransportLimits,
    schema: CanonicalSchema,
) -> OracleCanonicalLimits:
    if type(transport) is not OracleTransportLimits:
        raise TypeError("Oracle canonical limits require OracleTransportLimits")
    if type(schema) is not CanonicalSchema:
        raise TypeError("Oracle canonical limits require a CanonicalSchema")
    field_count = len(schema.fields)
    if not 1 <= field_count <= transport.max_result_columns:
        raise OracleCanonicalLoweringError(
            "Oracle canonical field count exceeds the shared transport bound: "
            f"field_count={field_count}, maximum={transport.max_result_columns}"
        )
    fixed_envelope_bytes = _ROW_HEADER_BYTES + (_FIELD_FRAME_BYTES * field_count)
    if fixed_envelope_bytes > transport.max_encoded_envelope_bytes:
        raise OracleCanonicalLoweringError(
            "Oracle canonical headers exceed the configured envelope bound: "
            f"fixed_envelope_bytes={fixed_envelope_bytes}, "
            f"max_encoded_envelope_bytes={transport.max_encoded_envelope_bytes}"
        )
    max_total_payload_bytes = (transport.max_encoded_envelope_bytes - fixed_envelope_bytes) // 2
    return OracleCanonicalLimits(
        field_count=field_count,
        fixed_envelope_bytes=fixed_envelope_bytes,
        max_total_payload_bytes=max_total_payload_bytes,
        max_payload_hex_bytes=2 * max_total_payload_bytes,
        max_encoded_envelope_bytes=transport.max_encoded_envelope_bytes,
        max_sql_raw_bytes=transport.max_sql_raw_bytes,
        max_sql_varchar2_bytes=transport.max_sql_varchar2_bytes,
    )


def read_oracle_canonical_rows(
    context: OracleReadContext,
    source: OracleCanonicalSelectSource,
    max_records: int,
) -> tuple[OracleCanonicalRow, ...]:
    _require_read_context(context)
    _require_source(source)
    if type(max_records) is not int or max_records < 1:
        raise ValueError("Oracle canonical max_records must be a positive integer")
    limits = build_oracle_canonical_limits(context.transport_limits, source.schema)
    envelope_context = prepare_envelope_context(source.schema)
    query = _canonical_rows_query(source, envelope_context, limits)
    result = context.read(
        query,
        max_records,
        _canonical_row_completion_bytes(limits, max_records),
    )
    context.require_result_completion(query.query_id, result, "canonical row decoding")
    canonical_rows: list[OracleCanonicalRow] = []
    for index, row in enumerate(result.rows, start=1):
        context.require_result_completion(query.query_id, result, "canonical row decoding")
        try:
            canonical_row = _parse_canonical_row(row, envelope_context, limits, index)
        finally:
            context.require_result_completion(query.query_id, result, "canonical row decoding")
        canonical_rows.append(canonical_row)
    context.require_result_completion(query.query_id, result, "canonical row assembly")
    assembled_rows = tuple(canonical_rows)
    context.require_result_completion(query.query_id, result, "canonical row assembly")
    return assembled_rows


def read_oracle_canonical_fingerprint(
    context: OracleReadContext,
    source: OracleCanonicalSelectSource,
) -> Fingerprint:
    _require_read_context(context)
    _require_source(source)
    limits = build_oracle_canonical_limits(context.transport_limits, source.schema)
    envelope_context = prepare_envelope_context(source.schema)
    query = _canonical_fingerprint_query(source, envelope_context, limits)
    result = context.read(query, 1, _canonical_fingerprint_completion_bytes())
    context.require_result_completion(query.query_id, result, "canonical fingerprint decoding")
    try:
        fingerprint = _parse_canonical_fingerprint(result)
    finally:
        context.require_result_completion(query.query_id, result, "canonical fingerprint decoding")
    return fingerprint


def _canonical_row_completion_bytes(
    limits: OracleCanonicalLimits,
    max_records: int,
) -> int:
    decode_scratch_bytes = (
        canonical_decode_scratch_bytes(
            limits.max_encoded_envelope_bytes,
            limits.field_count,
            MAX_ORACLE_DECIMAL_OBJECT_BYTES,
        )
        + (2 * list_storage_bytes(limits.field_count))
        + (2 * tuple_storage_bytes(limits.field_count))
    )
    retained_rows_bytes = (
        list_storage_bytes(max_records)
        + tuple_storage_bytes(max_records)
        + (max_records * slot_object_bytes(OracleCanonicalRow))
    )
    return retained_rows_bytes + decode_scratch_bytes + _SHA256_LOCAL_BYTES


def _canonical_fingerprint_completion_bytes() -> int:
    return (
        slot_object_bytes(Fingerprint)
        + (2 * tuple_storage_bytes(8))
        + (11 * getsizeof(DECIMAL_38_MAX))
        + MAX_ORACLE_DECIMAL_OBJECT_BYTES
    )


def _canonical_rows_query(
    source: OracleCanonicalSelectSource,
    context: CanonicalEnvelopeContext,
    limits: OracleCanonicalLimits,
) -> OracleQuery:
    row_source = _canonical_row_source(source, context, limits)
    statement = (
        "SELECT\n"
        "    DFE_ENVELOPE_RAW AS ENVELOPE,\n"
        "    CAST(STANDARD_HASH(DFE_ENVELOPE_RAW, 'SHA256') AS RAW(32)) AS ROW_HASH,\n"
        "    CAST(DFE_INVALID_ROW AS NUMBER(1, 0)) AS INVALID_ROW,\n"
        "    CAST(DFE_OVERSIZED_ROW AS NUMBER(1, 0)) AS OVERSIZED_ROW\n"
        "FROM (\n"
        f"{indent(row_source, '    ')}\n"
        ") DFE_CANONICAL_ROWS"
    )
    return OracleQuery(
        query_id=uuid4(),
        statement=statement,
        parameters=_canonical_parameters(source, context, limits),
        projections=(
            OracleProjection(
                "ENVELOPE",
                OracleProjectionKind.RAW,
                True,
                limits.max_encoded_envelope_bytes,
                limits.max_encoded_envelope_bytes,
            ),
            OracleProjection("ROW_HASH", OracleProjectionKind.RAW, True, 32, 32),
            OracleProjection("INVALID_ROW", OracleProjectionKind.DECIMAL, False, 2, 2),
            OracleProjection("OVERSIZED_ROW", OracleProjectionKind.DECIMAL, False, 2, 2),
        ),
        full_scans=source.full_scans,
    )


def _canonical_fingerprint_query(
    source: OracleCanonicalSelectSource,
    context: CanonicalEnvelopeContext,
    limits: OracleCanonicalLimits,
) -> OracleQuery:
    row_source = _canonical_row_source(source, context, limits)
    accepted = "DFE_INVALID_ROW = 0 AND DFE_OVERSIZED_ROW = 0"
    limbs = ",\n".join(
        (
            "    CAST(NVL(SUM(CAST(CASE WHEN "
            f"{accepted} THEN TO_NUMBER(SUBSTR(RAWTOHEX(DFE_ROW_HASH), "
            f"{(index * 8) + 1}, 8), 'XXXXXXXX') ELSE 0 END AS NUMBER(38, 0))), 0) "
            f"AS NUMBER(38, 0)) AS LIMB_{index}"
        )
        for index in range(8)
    )
    statement = (
        "SELECT\n"
        "    CAST(NVL(SUM(CAST(CASE WHEN "
        f"{accepted} THEN 1 ELSE 0 END AS NUMBER(38, 0))), 0) "
        "AS NUMBER(38, 0)) AS VALID_ROW_COUNT,\n"
        f"{limbs},\n"
        "    CAST(NVL(SUM(CAST(DFE_INVALID_ROW AS NUMBER(38, 0))), 0) "
        "AS NUMBER(38, 0)) AS INVALID_ROW_COUNT,\n"
        "    CAST(NVL(SUM(CAST(DFE_OVERSIZED_ROW AS NUMBER(38, 0))), 0) "
        "AS NUMBER(38, 0)) AS OVERSIZED_ROW_COUNT\n"
        "FROM (\n"
        "    SELECT\n"
        "        DFE_HASH_INPUT.*,\n"
        "        CAST(STANDARD_HASH(DFE_ENVELOPE_RAW, 'SHA256') AS RAW(32)) "
        "AS DFE_ROW_HASH\n"
        "    FROM (\n"
        f"{indent(row_source, '        ')}\n"
        "    ) DFE_HASH_INPUT\n"
        ") DFE_CANONICAL_ROWS"
    )
    return OracleQuery(
        query_id=uuid4(),
        statement=statement,
        parameters=_canonical_parameters(source, context, limits),
        projections=(
            _fingerprint_projection("VALID_ROW_COUNT"),
            *(_fingerprint_projection(f"LIMB_{index}") for index in range(8)),
            _fingerprint_projection("INVALID_ROW_COUNT"),
            _fingerprint_projection("OVERSIZED_ROW_COUNT"),
        ),
        full_scans=source.full_scans,
    )


def _canonical_row_source(
    source: OracleCanonicalSelectSource,
    context: CanonicalEnvelopeContext,
    limits: OracleCanonicalLimits,
) -> str:
    lowerings = tuple(
        _payload_lowering(field, binding, index)
        for index, (field, binding) in enumerate(
            zip(source.schema.fields, source.bindings, strict=True)
        )
    )
    payload_columns = ",\n".join(
        (
            f"        {lowering.is_null} AS DFE_N_{index},\n"
            f"        {lowering.is_valid} AS DFE_V_{index},\n"
            f"        {lowering.payload} AS DFE_P_{index}"
        )
        for index, lowering in enumerate(lowerings)
    )
    payload_layer = (
        f"SELECT\n{payload_columns}\nFROM (\n{indent(source.statement, '    ')}\n) DFE_SOURCE"
    )
    length_columns = ",\n".join(
        (
            "        CASE WHEN "
            f"DFE_N_{index} = 1 THEN 0 WHEN DFE_V_{index} = 1 "
            f"THEN LENGTHB(DFE_P_{index}) ELSE 0 END AS DFE_L_{index}"
        )
        for index in range(len(lowerings))
    )
    length_layer = (
        "SELECT\n"
        "        DFE_PAYLOADS.*,\n"
        f"{length_columns}\n"
        "FROM (\n"
        f"{indent(payload_layer, '    ')}\n"
        ") DFE_PAYLOADS"
    )
    invalid_terms = " + ".join(
        f"CASE WHEN DFE_V_{index} = 1 THEN 0 ELSE 1 END" for index in range(len(lowerings))
    )
    payload_length_terms = " + ".join(f"DFE_L_{index}" for index in range(len(lowerings)))
    size_layer = (
        "SELECT\n"
        "        DFE_LENGTHS.*,\n"
        f"        CASE WHEN ({invalid_terms}) = 0 THEN 0 ELSE 1 END "
        "AS DFE_INVALID_ROW,\n"
        f"        {limits.fixed_envelope_bytes} + (2 * ({payload_length_terms})) "
        "AS DFE_ENVELOPE_BYTES\n"
        "FROM (\n"
        f"{indent(length_layer, '    ')}\n"
        ") DFE_LENGTHS"
    )
    frames = " ||\n                ".join(
        _field_frame(field, index) for index, field in enumerate(source.schema.fields)
    )
    encoded_layer = (
        "SELECT\n"
        "        DFE_SIZES.*,\n"
        "        CASE WHEN DFE_INVALID_ROW = 0 "
        "AND DFE_ENVELOPE_BYTES > :dfe_envelope_limit "
        "THEN 1 ELSE 0 END AS DFE_OVERSIZED_ROW,\n"
        "        CASE WHEN DFE_INVALID_ROW = 0 "
        "AND DFE_ENVELOPE_BYTES <= :dfe_envelope_limit THEN\n"
        f"            CAST(:dfe_row_header ||\n                {frames}\n"
        f"            AS VARCHAR2({limits.max_encoded_envelope_bytes} BYTE))\n"
        f"        ELSE CAST(NULL AS VARCHAR2({limits.max_encoded_envelope_bytes} BYTE)) END "
        "AS DFE_ENVELOPE_TEXT\n"
        "FROM (\n"
        f"{indent(size_layer, '    ')}\n"
        ") DFE_SIZES"
    )
    return (
        "SELECT\n"
        "    DFE_ENCODED.*,\n"
        "    CAST(UTL_I18N.STRING_TO_RAW(DFE_ENVELOPE_TEXT, 'AL32UTF8') "
        f"AS RAW({limits.max_encoded_envelope_bytes})) AS DFE_ENVELOPE_RAW\n"
        "FROM (\n"
        f"{indent(encoded_layer, '    ')}\n"
        ") DFE_ENCODED"
    )


def _payload_lowering(
    field: FieldSchema,
    binding: OracleCanonicalFieldBinding,
    index: int,
) -> _PayloadLowering:
    column = f'DFE_SOURCE."{binding.column_name}"'
    nonnull_valid, nonnull_payload = _nonnull_payload(field, column, index)
    null_valid = "1" if field.nullable else "0"
    return _PayloadLowering(
        is_null=f"CASE WHEN {column} IS NULL THEN 1 ELSE 0 END",
        is_valid=(f"CASE WHEN {column} IS NULL THEN {null_valid} ELSE {nonnull_valid} END"),
        payload=(
            f"CASE WHEN {column} IS NULL THEN CAST(NULL AS VARCHAR2(1 BYTE)) "
            f"ELSE {nonnull_payload} END"
        ),
    )


def _nonnull_payload(field: FieldSchema, column: str, index: int) -> tuple[str, str]:
    if field.logical_type is LogicalType.INT64:
        range_condition = f"{column} >= {_INT64_MIN} AND {column} <= {INT64_MAX}"
        integral_condition = f"{column} = TRUNC({column})"
        valid = (
            f"CASE WHEN {range_condition} THEN CASE WHEN {integral_condition} "
            "THEN 1 ELSE 0 END ELSE 0 END"
        )
        payload = (
            f"CASE WHEN {range_condition} THEN CASE WHEN {integral_condition} THEN "
            f"TO_CHAR({column}, '{_NUMBER_FORMAT}', "
            "'NLS_NUMERIC_CHARACTERS=''.,''') ELSE NULL END ELSE NULL END"
        )
        return valid, payload
    if field.logical_type is LogicalType.DECIMAL:
        parameters = field.parameters
        if not isinstance(parameters, DecimalParameters):
            raise OracleCanonicalLoweringError(
                f"Oracle decimal parameters are inconsistent: field_index={index}"
            )
        integer_digits = parameters.precision - parameters.scale
        range_condition = f"{column} > -1E{integer_digits} AND {column} < 1E{integer_digits}"
        exact_scale = f"{column} = TRUNC({column}, {parameters.scale})"
        scaled = f"({column} * 1E{parameters.scale})"
        valid = (
            f"CASE WHEN {range_condition} THEN CASE WHEN {exact_scale} THEN 1 ELSE 0 END ELSE 0 END"
        )
        payload = (
            f"CASE WHEN {range_condition} THEN CASE WHEN {exact_scale} THEN "
            f"TO_CHAR({scaled}, '{_NUMBER_FORMAT}', "
            "'NLS_NUMERIC_CHARACTERS=''.,''') ELSE NULL END ELSE NULL END"
        )
        return valid, payload
    if field.logical_type is LogicalType.BOOLEAN:
        condition = f"{column} = 0 OR {column} = 1"
        return (
            f"CASE WHEN {condition} THEN 1 ELSE 0 END",
            f"CASE WHEN {column} = 0 THEN '0' WHEN {column} = 1 THEN '1' ELSE NULL END",
        )
    if field.logical_type is LogicalType.STRING:
        condition = f"INSTR({column}, CHR(0)) = 0"
        return (
            f"CASE WHEN {condition} THEN 1 ELSE 0 END",
            f"CASE WHEN {condition} THEN {column} ELSE NULL END",
        )
    if field.logical_type is LogicalType.DATE:
        condition = (
            f"EXTRACT(YEAR FROM {column}) BETWEEN 1 AND 9999 AND {column} = TRUNC({column}, 'DD')"
        )
        payload = _date_payload(column)
        return (
            f"CASE WHEN {condition} THEN 1 ELSE 0 END",
            f"CASE WHEN {condition} THEN {payload} ELSE NULL END",
        )
    parameters = field.parameters
    if not isinstance(parameters, TimestampParameters):
        raise OracleCanonicalLoweringError(
            f"Oracle timestamp parameters are inconsistent: field_index={index}"
        )
    value = column
    suffix = ""
    if field.logical_type is LogicalType.TIMESTAMP_INSTANT:
        value = f"SYS_EXTRACT_UTC({column})"
        suffix = " || 'Z'"
    range_condition = f"EXTRACT(YEAR FROM {value}) BETWEEN 1 AND 9999"
    fraction = f"TO_CHAR({value}, 'FF9', '{_DATETIME_LANGUAGE}')"
    precision = parameters.precision
    precision_condition = "1 = 1"
    fraction_payload = ""
    if precision < 9:
        precision_condition = (
            f"SUBSTR({fraction}, {precision + 1}, {9 - precision}) = '{('0' * (9 - precision))}'"
        )
    if precision > 0:
        fraction_payload = f" || '.' || SUBSTR({fraction}, 1, {precision})"
    payload = f"{_timestamp_payload(value)}{fraction_payload}{suffix}"
    valid = (
        f"CASE WHEN {range_condition} THEN CASE WHEN {precision_condition} "
        "THEN 1 ELSE 0 END ELSE 0 END"
    )
    safe_payload = (
        f"CASE WHEN {range_condition} THEN CASE WHEN {precision_condition} "
        f"THEN {payload} ELSE NULL END ELSE NULL END"
    )
    return valid, safe_payload


def _field_frame(field: FieldSchema, index: int) -> str:
    tag = {
        LogicalType.INT64: "01",
        LogicalType.DECIMAL: "02",
        LogicalType.BOOLEAN: "03",
        LogicalType.STRING: "04",
        LogicalType.DATE: "05",
        LogicalType.TIMESTAMP_LOCAL: "06",
        LogicalType.TIMESTAMP_INSTANT: "07",
    }[field.logical_type]
    return (
        f"'{tag}' || CASE WHEN DFE_N_{index} = 1 THEN '0' ELSE '1' END || "
        "TRANSLATE("
        f"LPAD(TO_CHAR(DFE_L_{index}, '{_LENGTH_HEX_FORMAT}'), 16, '0'), "
        "'ABCDEF', 'abcdef') || "
        f"CASE WHEN DFE_N_{index} = 1 THEN NULL ELSE "
        "TRANSLATE("
        f"RAWTOHEX(UTL_I18N.STRING_TO_RAW(DFE_P_{index}, 'AL32UTF8')), "
        "'ABCDEF', 'abcdef') END"
    )


def _date_payload(value: str) -> str:
    return (
        f"TO_CHAR(EXTRACT(YEAR FROM {value}), 'FM0000', '{_NUMERIC_NLS}') || '-' || "
        f"TO_CHAR(EXTRACT(MONTH FROM {value}), 'FM00', '{_NUMERIC_NLS}') || '-' || "
        f"TO_CHAR(EXTRACT(DAY FROM {value}), 'FM00', '{_NUMERIC_NLS}')"
    )


def _timestamp_payload(value: str) -> str:
    return (
        f"{_date_payload(value)} || 'T' || "
        f"TO_CHAR(EXTRACT(HOUR FROM {value}), 'FM00', '{_NUMERIC_NLS}') || ':' || "
        f"TO_CHAR(EXTRACT(MINUTE FROM {value}), 'FM00', '{_NUMERIC_NLS}') || ':' || "
        f"TO_CHAR(TRUNC(EXTRACT(SECOND FROM {value})), 'FM00', '{_NUMERIC_NLS}')"
    )


def _fingerprint_projection(name: str) -> OracleProjection:
    return OracleProjection(
        name,
        OracleProjectionKind.DECIMAL,
        False,
        39,
        39,
    )


def _canonical_parameters(
    source: OracleCanonicalSelectSource,
    context: CanonicalEnvelopeContext,
    limits: OracleCanonicalLimits,
) -> tuple[OracleBindParameter, ...]:
    return (
        *source.parameters,
        OracleBindParameter("dfe_envelope_limit", limits.max_encoded_envelope_bytes),
        OracleBindParameter("dfe_row_header", context.row_header),
    )


def _parse_canonical_row(
    row: tuple[OracleValue, ...],
    context: CanonicalEnvelopeContext,
    limits: OracleCanonicalLimits,
    row_index: int,
) -> OracleCanonicalRow:
    if len(row) != 4:
        raise OracleDataValidationError(
            "Oracle canonical row has an unexpected field count: "
            f"row_index={row_index}, actual={len(row)}, expected=4"
        )
    invalid = _exact_nonnegative_integer(row[2], "invalid row flag")
    oversized = _exact_nonnegative_integer(row[3], "oversized row flag")
    if invalid not in (0, 1) or oversized not in (0, 1):
        raise OracleDataValidationError(
            "Oracle canonical row flags must be exactly zero or one: "
            f"row_index={row_index}, invalid_row={invalid}, oversized_row={oversized}"
        )
    if invalid == 1:
        raise OracleDataValidationError(
            f"Oracle source row cannot be represented without loss: row_index={row_index}"
        )
    if oversized == 1:
        raise OracleResultLimitError(
            "Oracle source row exceeds the canonical envelope bound: "
            f"row_index={row_index}, limit={limits.max_encoded_envelope_bytes}"
        )
    envelope_value = row[0]
    digest_value = row[1]
    if type(envelope_value) is not bytes or type(digest_value) is not bytes:
        raise OracleDataValidationError(
            f"Oracle accepted canonical row returned NULL or non-RAW bytes: row_index={row_index}"
        )
    if len(envelope_value) > limits.max_encoded_envelope_bytes:
        raise OracleDataValidationError(
            "Oracle accepted canonical row exceeded its encoded envelope bound: "
            f"row_index={row_index}, actual={len(envelope_value)}, "
            f"limit={limits.max_encoded_envelope_bytes}"
        )
    try:
        decode_row_with_context(context, envelope_value)
    except CanonicalizationError as error:
        raise OracleDataValidationError(
            "Oracle canonical envelope failed the shared decoder: "
            f"row_index={row_index}, reason_type={type(error).__name__}"
        ) from None
    expected_digest = envelope_sha256(envelope_value)
    if digest_value != expected_digest:
        raise OracleDataValidationError(
            f"Oracle canonical SHA-256 differs from the shared implementation: row_index={row_index}"
        )
    return OracleCanonicalRow(envelope_value, digest_value)


def _parse_canonical_fingerprint(result: OracleReadResult) -> Fingerprint:
    if type(result) is not OracleReadResult:
        raise TypeError("Oracle canonical fingerprint requires OracleReadResult")
    if len(result.rows) != 1:
        raise OracleDataValidationError(
            f"Oracle canonical fingerprint must return exactly one row: actual={len(result.rows)}"
        )
    row = result.rows[0]
    if len(row) != 11:
        raise OracleDataValidationError(
            "Oracle canonical fingerprint has an unexpected field count: "
            f"actual={len(row)}, expected=11"
        )
    valid_count = _exact_nonnegative_integer(row[0], "valid row count")
    limbs = tuple(_exact_nonnegative_integer(row[index + 1], f"limb {index}") for index in range(8))
    invalid_count = _exact_nonnegative_integer(row[9], "invalid row count")
    oversized_count = _exact_nonnegative_integer(row[10], "oversized row count")
    if valid_count > INT64_MAX or invalid_count > INT64_MAX or oversized_count > INT64_MAX:
        raise OracleDataValidationError(
            "Oracle canonical row count exceeds signed int64: "
            f"valid_row_count={valid_count}, invalid_row_count={invalid_count}, "
            f"oversized_row_count={oversized_count}"
        )
    if invalid_count > 0:
        raise OracleDataValidationError(
            "Oracle canonical fingerprint rejected lossy source rows: "
            f"invalid_row_count={invalid_count}"
        )
    if oversized_count > 0:
        raise OracleResultLimitError(
            "Oracle canonical fingerprint rejected oversized source rows: "
            f"oversized_row_count={oversized_count}"
        )
    try:
        return Fingerprint(
            count=valid_count,
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
        raise OracleDataValidationError(
            f"Oracle canonical fingerprint violates shared exact bounds: reason={str(error)!r}"
        ) from None


def _exact_nonnegative_integer(value: OracleValue, label: str) -> int:
    if type(value) is not Decimal or not value.is_finite():
        raise OracleDataValidationError(f"Oracle canonical {label} must be an exact NUMBER integer")
    integral = value.to_integral_value()
    if value != integral or value < 0:
        raise OracleDataValidationError(f"Oracle canonical {label} must be a non-negative integer")
    return int(integral)


def _validate_physical_mapping(
    field: FieldSchema,
    binding: OracleCanonicalFieldBinding,
    field_index: int,
) -> None:
    expected: tuple[OracleCanonicalPhysicalType, ...]
    if field.logical_type in (
        LogicalType.INT64,
        LogicalType.DECIMAL,
        LogicalType.BOOLEAN,
    ):
        expected = (OracleCanonicalPhysicalType.NUMBER,)
    elif field.logical_type is LogicalType.STRING:
        expected = (
            OracleCanonicalPhysicalType.CHAR,
            OracleCanonicalPhysicalType.VARCHAR2,
        )
    elif field.logical_type is LogicalType.DATE:
        expected = (OracleCanonicalPhysicalType.DATE,)
    elif field.logical_type is LogicalType.TIMESTAMP_LOCAL:
        expected = (OracleCanonicalPhysicalType.TIMESTAMP,)
    else:
        expected = (OracleCanonicalPhysicalType.TIMESTAMP_WITH_TIME_ZONE,)
    if binding.physical_type not in expected:
        raise OracleCanonicalLoweringError(
            "Oracle physical type is outside the canonical supported subset: "
            f"field_index={field_index}, logical_type={field.logical_type.value!r}, "
            f"physical_type={binding.physical_type.value!r}, "
            f"supported={tuple(value.value for value in expected)!r}"
        )


def _validate_scalar_text(value: object, label: str) -> None:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"{label} must be nonempty text without NUL")
    for character in value:
        if 0xD800 <= ord(character) <= 0xDFFF:
            raise ValueError(f"{label} must not contain surrogate code points")


def _validate_identifier(value: object, label: str) -> None:
    if type(value) is not str or _ORACLE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(
            f"{label} must use 1..30 uppercase ASCII letters, digits, _, $, or # "
            "and start with a letter"
        )


def _validate_optional_integer_range(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> None:
    if value is None:
        return
    _validate_required_integer_range(value, label, minimum, maximum)


def _validate_required_integer_range(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer in {minimum}..{maximum}")


def _require_none(value: object, label: str) -> None:
    if value is not None:
        raise ValueError(f"{label} must be None for this physical type")


def _require_read_context(value: object) -> None:
    if not isinstance(value, OracleReadContext):
        raise TypeError("Oracle canonical reads require OracleReadContext")


def _require_source(value: object) -> None:
    if type(value) is not OracleCanonicalSelectSource:
        raise TypeError("Oracle canonical reads require OracleCanonicalSelectSource")
