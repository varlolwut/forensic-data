from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from functools import partial
from typing import cast, final
from uuid import UUID

from forensic_data.canonical import CanonicalizationError, decode_payload
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
_MAX_INT64_KEY_ENVELOPE_BYTES = _ROW_HEADER_BYTES + _FIELD_FRAME_BYTES + 40
_MAX_INTEGER_RANGES = 524
_MAX_LOB_BYTES = (1 << 31) - 1
_UTF8_COLLATION = "Latin1_General_100_BIN2_UTF8"
_INTEGER_RANGE_HASH_TABLE = "[#dfe_integer_range_hashes]"
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

type MssqlCanonicalParameter = str | int | Decimal | bytes


class MssqlLoweringError(ValueError):
    """A logical schema cannot be lowered to a supported SQL Server v1 profile."""


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
    column_id: int
    column_name: str
    is_nullable: bool
    physical: MssqlPhysicalField

    def __post_init__(self) -> None:
        _validate_scalar_text(self.field_name, "SQL Server logical field name")
        _validate_positive_integer(
            self.column_id,
            "SQL Server column ID",
            INT32_MAX,
        )
        _validate_identifier(self.column_name, "SQL Server column name")
        if type(self.is_nullable) is not bool:
            raise MssqlLoweringError("SQL Server column nullability must be boolean")
        if type(self.physical) is not MssqlPhysicalField:
            raise MssqlLoweringError(
                "SQL Server field binding physical provenance must be MssqlPhysicalField"
            )


@final
@dataclass(frozen=True, slots=True)
class MssqlInspectedRelation:
    context_id: UUID
    database_id: int
    schema_id: int
    object_id: int
    relation: MssqlRelation
    bindings: tuple[MssqlFieldBinding, ...]

    def __post_init__(self) -> None:
        if type(self.context_id) is not UUID:
            raise MssqlLoweringError("SQL Server inspection context ID must be a UUID")
        _validate_positive_integer(
            self.database_id,
            "SQL Server inspection database ID",
            INT32_MAX,
        )
        _validate_positive_integer(
            self.schema_id,
            "SQL Server inspection schema ID",
            INT32_MAX,
        )
        _validate_positive_integer(
            self.object_id,
            "SQL Server inspection object ID",
            INT32_MAX,
        )
        if type(self.relation) is not MssqlRelation:
            raise MssqlLoweringError("SQL Server inspection relation must be MssqlRelation")
        if type(self.bindings) is not tuple:
            raise MssqlLoweringError("SQL Server inspection bindings must be an immutable tuple")
        seen_column_ids: set[int] = set()
        seen_column_names: set[str] = set()
        for index, binding in enumerate(self.bindings):
            if type(binding) is not MssqlFieldBinding:
                raise MssqlLoweringError(
                    "SQL Server inspection bindings must contain MssqlFieldBinding values: "
                    f"field_index={index}"
                )
            if binding.column_id in seen_column_ids:
                raise MssqlLoweringError(
                    "SQL Server inspection contains a duplicate column ID: "
                    f"column_id={binding.column_id}"
                )
            if binding.column_name in seen_column_names:
                raise MssqlLoweringError(
                    "SQL Server inspection contains a duplicate column name: "
                    f"column_name={binding.column_name!r}"
                )
            seen_column_ids.add(binding.column_id)
            seen_column_names.add(binding.column_name)


@final
@dataclass(frozen=True, slots=True)
class MssqlUtf8HelperBinding:
    database_id: int
    database_name: str
    database_collation: str
    database_compatibility_level: int
    schema_id: int
    schema_name: str
    object_id: int
    object_name: str
    object_type: str
    definition_utf16_bytes: int
    definition_sha256: bytes
    return_type_schema: str
    return_type_name: str
    return_max_length: int
    return_is_output: bool
    return_has_default_value: bool
    input_parameter_name: str
    input_type_schema: str
    input_type_name: str
    input_max_length: int
    input_is_output: bool
    input_has_default_value: bool
    uses_ansi_nulls: bool
    uses_quoted_identifier: bool
    is_schema_bound: bool
    uses_database_collation: bool
    null_on_null_input: bool
    execute_as_principal_id: int | None
    is_deterministic: bool
    is_precise: bool
    is_encrypted: bool
    can_execute: bool
    can_view_definition: bool
    can_alter: bool
    can_control: bool
    ansi_nulls: bool
    ansi_padding: bool
    ansi_warnings: bool
    arithabort: bool
    concat_null_yields_null: bool
    numeric_roundabort: bool
    quoted_identifier: bool

    def __post_init__(self) -> None:
        _validate_positive_integer(self.database_id, "SQL Server helper database ID", INT32_MAX)
        _validate_identifier(self.database_name, "SQL Server helper database name")
        _validate_identifier(self.database_collation, "SQL Server helper database collation")
        _validate_positive_integer(
            self.database_compatibility_level,
            "SQL Server helper database compatibility level",
            INT32_MAX,
        )
        _validate_positive_integer(self.schema_id, "SQL Server helper schema ID", INT32_MAX)
        _validate_identifier(self.schema_name, "SQL Server helper schema name")
        _validate_positive_integer(self.object_id, "SQL Server helper object ID", INT32_MAX)
        _validate_identifier(self.object_name, "SQL Server helper object name")
        _validate_identifier(self.object_type, "SQL Server helper object type")
        _validate_positive_integer(
            self.definition_utf16_bytes,
            "SQL Server helper definition byte length",
            _MAX_LOB_BYTES,
        )
        if self.definition_utf16_bytes % 2 != 0:
            raise MssqlLoweringError(
                "SQL Server helper definition byte length must contain whole UTF-16 code units"
            )
        if type(self.definition_sha256) is not bytes or len(self.definition_sha256) != 32:
            raise MssqlLoweringError(
                "SQL Server helper definition SHA-256 digest must contain exactly 32 bytes"
            )
        _validate_identifier(self.return_type_schema, "SQL Server helper return type schema")
        _validate_identifier(self.return_type_name, "SQL Server helper return type name")
        _validate_catalog_max_length(
            self.return_max_length,
            "SQL Server helper return maximum length",
        )
        _validate_parameter_name(
            self.input_parameter_name,
            "SQL Server helper input parameter name",
        )
        _validate_identifier(self.input_type_schema, "SQL Server helper input type schema")
        _validate_identifier(self.input_type_name, "SQL Server helper input type name")
        _validate_catalog_max_length(
            self.input_max_length,
            "SQL Server helper input maximum length",
        )
        boolean_fields = (
            ("return_is_output", self.return_is_output),
            ("return_has_default_value", self.return_has_default_value),
            ("input_is_output", self.input_is_output),
            ("input_has_default_value", self.input_has_default_value),
            ("uses_ansi_nulls", self.uses_ansi_nulls),
            ("uses_quoted_identifier", self.uses_quoted_identifier),
            ("is_schema_bound", self.is_schema_bound),
            ("uses_database_collation", self.uses_database_collation),
            ("null_on_null_input", self.null_on_null_input),
            ("is_deterministic", self.is_deterministic),
            ("is_precise", self.is_precise),
            ("is_encrypted", self.is_encrypted),
            ("can_execute", self.can_execute),
            ("can_view_definition", self.can_view_definition),
            ("can_alter", self.can_alter),
            ("can_control", self.can_control),
            ("ansi_nulls", self.ansi_nulls),
            ("ansi_padding", self.ansi_padding),
            ("ansi_warnings", self.ansi_warnings),
            ("arithabort", self.arithabort),
            ("concat_null_yields_null", self.concat_null_yields_null),
            ("numeric_roundabort", self.numeric_roundabort),
            ("quoted_identifier", self.quoted_identifier),
        )
        for name, value in boolean_fields:
            if type(value) is not bool:
                raise MssqlLoweringError(f"SQL Server helper {name} must be boolean")
        if self.execute_as_principal_id is not None and (
            type(self.execute_as_principal_id) is not int
            or not -(1 << 31) <= self.execute_as_principal_id <= INT32_MAX
        ):
            raise MssqlLoweringError(
                "SQL Server helper execute-as principal ID must be a signed 32-bit integer or None"
            )


@final
@dataclass(frozen=True, slots=True)
class MssqlScopePredicate:
    field: FieldSchema
    column_name: str
    canonical_payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.field), FieldSchema):
            raise MssqlLoweringError("SQL Server scope field must be a FieldSchema")
        if self.field.nullable:
            raise MssqlLoweringError("SQL Server scope field must be non-nullable")
        _validate_identifier(self.column_name, "SQL Server scope column")
        if type(self.canonical_payload) is not bytes:
            raise MssqlLoweringError("SQL Server scope canonical payload must be bytes")
        try:
            decode_payload(self.field, self.canonical_payload)
        except CanonicalizationError as error:
            raise MssqlLoweringError(
                "SQL Server scope canonical payload does not match its logical field: "
                f"reason_type={type(error).__name__}"
            ) from None


@final
@dataclass(frozen=True, slots=True)
class MssqlIntegerRangeRequest:
    segment_id: str
    lower_inclusive: int
    upper_exclusive: int | None

    def __post_init__(self) -> None:
        _validate_scalar_text(self.segment_id, "SQL Server integer-range segment ID")
        _validate_int64(self.lower_inclusive, "SQL Server integer-range lower bound")
        if self.upper_exclusive is not None:
            _validate_int64(self.upper_exclusive, "SQL Server integer-range upper bound")
            if self.upper_exclusive <= self.lower_inclusive:
                raise MssqlLoweringError(
                    "SQL Server integer-range upper bound must exceed its lower bound"
                )


class MssqlCanonicalResultKind(StrEnum):
    ROWS = "rows"
    FINGERPRINT = "fingerprint"
    KEY_SUMMARY = "key_summary"
    INTEGER_KEY_SUMMARY = "integer_key_summary"
    INTEGER_RANGE_FINGERPRINTS = "integer_range_fingerprints"
    INTEGER_RANGE_ROWS = "integer_range_rows"
    RELATION_MANIFEST = "relation_manifest"


@final
@dataclass(frozen=True, slots=True)
class MssqlCanonicalQuery:
    statement: str
    parameters: tuple[MssqlCanonicalParameter, ...]
    schema: CanonicalSchema
    context: CanonicalEnvelopeContext
    inspection: MssqlInspectedRelation
    max_encoded_envelope_bytes: int
    result_kind: MssqlCanonicalResultKind

    def __post_init__(self) -> None:
        _validate_scalar_text(self.statement, "SQL Server canonical statement")
        if not self.statement:
            raise MssqlLoweringError("SQL Server canonical statement must not be empty")
        if type(self.parameters) is not tuple or not all(
            type(parameter) in (str, int, Decimal, bytes) for parameter in self.parameters
        ):
            raise MssqlLoweringError(
                "SQL Server canonical parameters must be immutable supported scalar values"
            )
        if not isinstance(cast(object, self.context), CanonicalEnvelopeContext):
            raise MssqlLoweringError(
                "SQL Server canonical query context must be a CanonicalEnvelopeContext"
            )
        if not isinstance(cast(object, self.schema), CanonicalSchema):
            raise MssqlLoweringError("SQL Server canonical query schema must be a CanonicalSchema")
        validate_mssql_inspection(self.schema, self.inspection)
        _validate_positive_integer(
            self.max_encoded_envelope_bytes,
            "SQL Server maximum encoded envelope bytes",
            _MAX_LOB_BYTES,
        )
        if type(self.result_kind) is not MssqlCanonicalResultKind:
            raise MssqlLoweringError(
                "SQL Server canonical result kind must be MssqlCanonicalResultKind"
            )

    @property
    def relation(self) -> MssqlRelation:
        return self.inspection.relation

    @property
    def bindings(self) -> tuple[MssqlFieldBinding, ...]:
        return self.inspection.bindings


@final
@dataclass(frozen=True, slots=True)
class _PayloadLowering:
    prelude: str
    is_valid: str
    payload: str


@final
@dataclass(frozen=True, slots=True)
class _RowSource:
    statement: str
    context: CanonicalEnvelopeContext
    parameters: tuple[MssqlCanonicalParameter, ...]


@final
@dataclass(frozen=True, slots=True)
class _IntegerRangeSource:
    statement: str
    context: CanonicalEnvelopeContext
    parameters: tuple[MssqlCanonicalParameter, ...]


type _OriginCteBuilder = Callable[[MssqlInspectedRelation], str]
type _PayloadLowerer = Callable[[FieldSchema, MssqlFieldBinding, int], _PayloadLowering]


def build_mssql_row_envelope_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, inspection, max_encoded_envelope_bytes)
    if max_encoded_envelope_bytes > _MAX_BOUNDED_VARCHAR_BYTES:
        raise MssqlLoweringError(
            "SQL Server row-envelope output cannot declare more than 8000 bytes; "
            "use the row-hash query for larger envelopes"
        )
    source = _row_source(schema, inspection, max_encoded_envelope_bytes)
    provenance = _provenance_projection("dfe_hash", inspection)
    statement = (
        f"{source.statement} "
        f"SELECT {provenance}, "
        f"CONVERT(varchar({max_encoded_envelope_bytes}), [dfe_hash].[envelope]) "
        "AS [envelope], "
        "LOWER(CONVERT(char(64), [dfe_hash].[row_hash], 2)) AS [row_hash_hex], "
        "[dfe_hash].[invalid_row], [dfe_hash].[oversized_row] "
        "FROM [dfe_hash]"
    )
    return _canonical_query(
        source,
        inspection,
        max_encoded_envelope_bytes,
        MssqlCanonicalResultKind.ROWS,
        statement,
    )


def build_mssql_row_hash_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, inspection, max_encoded_envelope_bytes)
    source = _row_source(schema, inspection, max_encoded_envelope_bytes)
    provenance = _provenance_projection("dfe_hash", inspection)
    statement = (
        f"{source.statement} "
        f"SELECT {provenance}, [dfe_hash].[envelope_bytes], "
        "LOWER(CONVERT(char(64), [dfe_hash].[row_hash], 2)) AS [row_hash_hex], "
        "CASE WHEN [dfe_hash].[envelope_bytes] <= 8000 "
        "THEN CONVERT(varchar(8000), [dfe_hash].[envelope]) "
        "ELSE CONVERT(varchar(8000), NULL) END AS [bounded_envelope], "
        "[dfe_hash].[invalid_row], [dfe_hash].[oversized_row] "
        "FROM [dfe_hash]"
    )
    return _canonical_query(
        source,
        inspection,
        max_encoded_envelope_bytes,
        MssqlCanonicalResultKind.ROWS,
        statement,
    )


def build_mssql_fingerprint_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, inspection, max_encoded_envelope_bytes)
    source = _row_source(schema, inspection, max_encoded_envelope_bytes)
    limb_sums = ", ".join(_limb_sum_expression(index) for index in range(8))
    provenance = _aggregate_provenance_projection("dfe_hash", inspection)
    statement = (
        f"{source.statement} "
        f"SELECT {provenance}, "
        "COUNT_BIG(CASE WHEN [dfe_hash].[row_hash] IS NOT NULL THEN 1 END) "
        "AS [valid_row_count], "
        f"{limb_sums}, "
        "COUNT_BIG(CASE WHEN [dfe_hash].[invalid_row] = CONVERT(bit, 1) THEN 1 END) "
        "AS [invalid_row_count], "
        "COUNT_BIG(CASE WHEN [dfe_hash].[oversized_row] = CONVERT(bit, 1) THEN 1 END) "
        "AS [oversized_row_count] "
        "FROM [dfe_hash]"
    )
    return _canonical_query(
        source,
        inspection,
        max_encoded_envelope_bytes,
        MssqlCanonicalResultKind.FINGERPRINT,
        statement,
    )


def build_mssql_key_summary_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    key_field_indexes: tuple[int, ...],
    max_encoded_key_bytes: int,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, inspection, max_encoded_key_bytes)
    _validate_key_field_indexes(schema, key_field_indexes)
    if max_encoded_key_bytes > _MAX_BOUNDED_VARCHAR_BYTES:
        raise MssqlLoweringError("SQL Server canonical key envelope cannot exceed 8000 bytes")
    key_fields = tuple(schema.fields[index] for index in key_field_indexes)
    key_schema = CanonicalSchema(protocol=schema.protocol, fields=key_fields)
    context = prepare_envelope_context(key_schema)
    payloads = tuple(
        _payload_lowering(schema.fields[index], inspection.bindings[index], index)
        for index in key_field_indexes
    )
    payload_clause = _payload_clause(payloads)
    has_null = _key_has_null_expression(key_field_indexes)
    fields_valid = _key_fields_valid_expression(key_field_indexes, payloads)
    payload_bytes = _key_payload_bytes_expression(key_field_indexes, payloads)
    frames = _key_frames_expression(key_fields, key_field_indexes, payloads)
    fixed_bytes = _ROW_HEADER_BYTES + (_FIELD_FRAME_BYTES * len(key_field_indexes))
    origin = _origin_cte(inspection)
    relation_source = _relation_source(inspection)
    origin_identity = _identity_projection("dfe_origin", inspection)
    aggregate_provenance = _aggregate_provenance_projection("dfe_keys", inspection)
    statement = (
        f"WITH {origin}, [dfe_keys] AS ("
        f"SELECT {origin_identity}, "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL THEN CONVERT(bit, 0) "
        "ELSE CONVERT(bit, 1) END AS [dfe_has_data], "
        "[dfe_key].[key_envelope], [dfe_key].[null_key], "
        "[dfe_key].[invalid_key], [dfe_key].[oversized_key] "
        "FROM [dfe_origin] "
        f"LEFT JOIN ({relation_source}) AS [dfe_source] ON 1 = 1 "
        f"{payload_clause} "
        "CROSS APPLY (SELECT "
        f"CASE WHEN {has_null} THEN CONVERT(bit, 1) ELSE CONVERT(bit, 0) END "
        "AS [null_key], "
        f"CASE WHEN NOT ({has_null}) AND NOT ({fields_valid}) "
        "THEN CONVERT(bit, 1) ELSE CONVERT(bit, 0) END AS [invalid_key], "
        f"CONVERT(bigint, {fixed_bytes}) + "
        f"(CONVERT(bigint, 2) * ({payload_bytes})) AS [key_envelope_bytes]"
        ") AS [dfe_validation] "
        "CROSS APPLY (SELECT "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL "
        "OR [dfe_validation].[null_key] = CONVERT(bit, 1) "
        "OR [dfe_validation].[invalid_key] = CONVERT(bit, 1) "
        f"OR [dfe_validation].[key_envelope_bytes] > CONVERT(bigint, {max_encoded_key_bytes}) "
        "THEN CONVERT(varbinary(8000), NULL) "
        f"ELSE CONVERT(varbinary(8000), CONVERT(varchar(max), ?) + {frames}) END "
        "AS [key_envelope], [dfe_validation].[null_key], "
        "[dfe_validation].[invalid_key], "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NOT NULL "
        "AND [dfe_validation].[null_key] = CONVERT(bit, 0) "
        "AND [dfe_validation].[invalid_key] = CONVERT(bit, 0) "
        f"AND [dfe_validation].[key_envelope_bytes] > CONVERT(bigint, {max_encoded_key_bytes}) "
        "THEN CONVERT(bit, 1) ELSE CONVERT(bit, 0) END AS [oversized_key]"
        ") AS [dfe_key]"
        ") "
        f"SELECT {aggregate_provenance}, "
        "COUNT_BIG(CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) THEN 1 END) "
        "AS [row_count], "
        "COUNT_BIG(CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_keys].[null_key] = CONVERT(bit, 1) THEN 1 END) AS [null_key_count], "
        "COUNT_BIG(CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_keys].[invalid_key] = CONVERT(bit, 1) THEN 1 END) "
        "AS [invalid_key_count], "
        "COUNT_BIG(CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_keys].[oversized_key] = CONVERT(bit, 1) THEN 1 END) "
        "AS [oversized_key_count], "
        "COUNT_BIG([dfe_keys].[key_envelope]) AS [valid_key_count], "
        "COUNT_BIG(DISTINCT [dfe_keys].[key_envelope]) AS [distinct_key_count] "
        "FROM [dfe_keys]"
    )
    return MssqlCanonicalQuery(
        statement=statement,
        parameters=(context.key_header,),
        schema=schema,
        context=context,
        inspection=inspection,
        max_encoded_envelope_bytes=max_encoded_key_bytes,
        result_kind=MssqlCanonicalResultKind.KEY_SUMMARY,
    )


def build_mssql_integer_key_summary_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    return _build_mssql_integer_key_summary_query(
        schema,
        inspection,
        key_field_index,
        scope,
        max_encoded_envelope_bytes,
        _origin_cte,
        _payload_lowering,
    )


def build_mssql_2016_integer_key_summary_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    helper: MssqlUtf8HelperBinding,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    origin_cte_builder: _OriginCteBuilder = partial(_mssql_2016_origin_cte, helper)
    payload_lowerer: _PayloadLowerer = partial(_mssql_2016_payload_lowering, helper)
    return _build_mssql_integer_key_summary_query(
        schema,
        inspection,
        key_field_index,
        scope,
        max_encoded_envelope_bytes,
        origin_cte_builder,
        payload_lowerer,
    )


def _build_mssql_integer_key_summary_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    max_encoded_envelope_bytes: int,
    origin_cte_builder: _OriginCteBuilder,
    payload_lowerer: _PayloadLowerer,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, inspection, max_encoded_envelope_bytes)
    _validate_single_integer_key(schema, key_field_index)
    key_column = _qualified_column(key_field_index)
    key_payload = payload_lowerer(
        schema.fields[key_field_index],
        inspection.bindings[key_field_index],
        key_field_index,
    )
    scope_filter, scope_parameters = _scope_filter(inspection, scope, payload_lowerer)
    origin = origin_cte_builder(inspection)
    relation_source = _relation_source(inspection)
    origin_identity = _identity_projection("dfe_origin", inspection)
    aggregate_provenance = _aggregate_provenance_projection("dfe_keys", inspection)
    key_value = f"TRY_CONVERT(bigint, {key_column})"
    access_path = _integer_access_path_expression(
        inspection,
        inspection.bindings[key_field_index].column_id,
    )
    statement = (
        f"WITH {origin}, [dfe_keys] AS ("
        f"SELECT {origin_identity}, "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL THEN CONVERT(bit, 0) "
        "ELSE CONVERT(bit, 1) END AS [dfe_has_data], "
        f"{key_column} AS [dfe_key_source], {key_value} AS [dfe_key_value], "
        f"CASE WHEN {key_payload.is_valid} THEN CONVERT(bit, 1) "
        "ELSE CONVERT(bit, 0) END AS [dfe_key_valid] "
        "FROM [dfe_origin] "
        f"LEFT JOIN ({relation_source}) AS [dfe_source] ON ({scope_filter})"
        ") "
        f"SELECT {aggregate_provenance}, "
        "COUNT_BIG(CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) THEN 1 END) "
        "AS [row_count], "
        "COUNT_BIG(CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_keys].[dfe_key_source] IS NULL THEN 1 END) AS [null_key_count], "
        "COUNT_BIG(CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_keys].[dfe_key_source] IS NOT NULL "
        "AND [dfe_keys].[dfe_key_valid] = CONVERT(bit, 0) THEN 1 END) "
        "AS [invalid_key_count], "
        "COUNT_BIG(CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_keys].[dfe_key_source] IS NOT NULL "
        "AND [dfe_keys].[dfe_key_valid] = CONVERT(bit, 1) THEN 1 END) "
        "AS [valid_key_count], "
        "COUNT_BIG(DISTINCT CASE WHEN [dfe_keys].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_keys].[dfe_key_source] IS NOT NULL "
        "AND [dfe_keys].[dfe_key_valid] = CONVERT(bit, 1) "
        "THEN [dfe_keys].[dfe_key_value] END) AS [distinct_key_count], "
        "MIN(CASE WHEN [dfe_keys].[dfe_key_valid] = CONVERT(bit, 1) "
        "THEN [dfe_keys].[dfe_key_value] END) AS [minimum_key], "
        "MAX(CASE WHEN [dfe_keys].[dfe_key_valid] = CONVERT(bit, 1) "
        "THEN [dfe_keys].[dfe_key_value] END) AS [maximum_key], "
        f"CONVERT(bit, CASE WHEN {access_path} THEN 1 ELSE 0 END) AS [usable_access_path] "
        "FROM [dfe_keys]"
    )
    context = prepare_envelope_context(schema)
    return MssqlCanonicalQuery(
        statement=statement,
        parameters=scope_parameters,
        schema=schema,
        context=context,
        inspection=inspection,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
        result_kind=MssqlCanonicalResultKind.INTEGER_KEY_SUMMARY,
    )


def build_mssql_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    ranges: tuple[MssqlIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    return _build_mssql_integer_range_fingerprint_query(
        schema,
        inspection,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
        _origin_cte,
        _payload_lowering,
    )


def build_mssql_2016_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    helper: MssqlUtf8HelperBinding,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    ranges: tuple[MssqlIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    origin_cte_builder: _OriginCteBuilder = partial(_mssql_2016_origin_cte, helper)
    payload_lowerer: _PayloadLowerer = partial(_mssql_2016_payload_lowering, helper)
    return _build_mssql_integer_range_fingerprint_query(
        schema,
        inspection,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
        origin_cte_builder,
        payload_lowerer,
    )


def _build_mssql_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    ranges: tuple[MssqlIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
    origin_cte_builder: _OriginCteBuilder,
    payload_lowerer: _PayloadLowerer,
) -> MssqlCanonicalQuery:
    source = _integer_range_source(
        schema,
        inspection,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
        origin_cte_builder,
        payload_lowerer,
    )
    limb_sums = ", ".join(_limb_sum_expression(index) for index in range(8))
    provenance = _aggregate_literal_provenance_projection("dfe_hash", inspection)
    bounded_envelope_bytes = min(
        max_encoded_envelope_bytes,
        _MAX_BOUNDED_VARCHAR_BYTES,
        _maximum_bounded_row_envelope_bytes(schema, inspection.bindings),
    )
    maximum_segment_id_bytes = max(len(item.segment_id.encode("ascii")) for item in ranges)
    statement = (
        f"DROP TABLE IF EXISTS {_INTEGER_RANGE_HASH_TABLE}; "
        f"{source.statement} "
        "SELECT [dfe_rows].[segment_id], [dfe_rows].[ordinal], "
        "[dfe_rows].[dfe_has_data], "
        "CASE WHEN [dfe_rows].[row_envelope] IS NULL "
        "THEN CONVERT(varbinary(32), NULL) "
        "ELSE CONVERT(varbinary(32), HASHBYTES('SHA2_256', "
        f"CONVERT(varbinary({bounded_envelope_bytes}), "
        "[dfe_rows].[row_envelope]))) END AS [row_hash], "
        "[dfe_rows].[invalid_row], [dfe_rows].[oversized_row], "
        "[dfe_rows].[envelope_bytes], "
        "CONVERT(bigint, DATALENGTH([dfe_rows].[key_envelope])) "
        "AS [key_envelope_bytes] "
        f"INTO {_INTEGER_RANGE_HASH_TABLE} FROM [dfe_rows] OPTION (FORCE ORDER); "
        f"SELECT {provenance}, CONVERT(varbinary({maximum_segment_id_bytes}), "
        "[dfe_hash].[segment_id]) AS [segment_id], "
        "COUNT_BIG(CASE WHEN [dfe_hash].[row_hash] IS NOT NULL THEN 1 END) "
        "AS [valid_row_count], "
        f"{limb_sums}, "
        "COUNT_BIG(CASE WHEN [dfe_hash].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_hash].[invalid_row] = CONVERT(bit, 1) THEN 1 END) "
        "AS [invalid_row_count], "
        "COUNT_BIG(CASE WHEN [dfe_hash].[dfe_has_data] = CONVERT(bit, 1) "
        "AND [dfe_hash].[oversized_row] = CONVERT(bit, 1) THEN 1 END) "
        "AS [oversized_row_count], "
        "COALESCE(SUM(CASE WHEN [dfe_hash].[row_hash] IS NOT NULL "
        "THEN [dfe_hash].[envelope_bytes] ELSE CONVERT(bigint, 0) END), 0) "
        "AS [row_envelope_bytes], "
        "COALESCE(SUM(CASE WHEN [dfe_hash].[row_hash] IS NOT NULL "
        "THEN [dfe_hash].[key_envelope_bytes] "
        "ELSE CONVERT(bigint, 0) END), 0) AS [key_envelope_bytes] "
        f"FROM {_INTEGER_RANGE_HASH_TABLE} AS [dfe_hash] "
        "GROUP BY [dfe_hash].[ordinal], [dfe_hash].[segment_id] "
        "ORDER BY [dfe_hash].[ordinal]; "
        f"DROP TABLE IF EXISTS {_INTEGER_RANGE_HASH_TABLE}"
    )
    return MssqlCanonicalQuery(
        statement=statement,
        parameters=source.parameters,
        schema=schema,
        context=source.context,
        inspection=inspection,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
        result_kind=MssqlCanonicalResultKind.INTEGER_RANGE_FINGERPRINTS,
    )


def build_mssql_integer_range_rows_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    ranges: tuple[MssqlIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    return _build_mssql_integer_range_rows_query(
        schema,
        inspection,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
        _origin_cte,
        _payload_lowering,
    )


def build_mssql_2016_integer_range_rows_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    helper: MssqlUtf8HelperBinding,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    ranges: tuple[MssqlIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    origin_cte_builder: _OriginCteBuilder = partial(_mssql_2016_origin_cte, helper)
    payload_lowerer: _PayloadLowerer = partial(_mssql_2016_payload_lowering, helper)
    return _build_mssql_integer_range_rows_query(
        schema,
        inspection,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
        origin_cte_builder,
        payload_lowerer,
    )


def _build_mssql_integer_range_rows_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    ranges: tuple[MssqlIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
    origin_cte_builder: _OriginCteBuilder,
    payload_lowerer: _PayloadLowerer,
) -> MssqlCanonicalQuery:
    source = _integer_range_source(
        schema,
        inspection,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
        origin_cte_builder,
        payload_lowerer,
    )
    effective_envelope_limit = min(
        max_encoded_envelope_bytes,
        _MAX_BOUNDED_VARCHAR_BYTES,
    )
    bounded_envelope_bytes = min(
        effective_envelope_limit,
        _maximum_bounded_row_envelope_bytes(schema, inspection.bindings),
    )
    maximum_segment_id_bytes = max(len(item.segment_id.encode("ascii")) for item in ranges)
    provenance = _literal_identity_projection(inspection)
    statement = (
        f"{source.statement} "
        f"SELECT {provenance}, [dfe_exact].[dfe_has_data], "
        f"CONVERT(varbinary({maximum_segment_id_bytes}), CASE WHEN "
        "[dfe_exact].[dfe_has_data] = CONVERT(bit, 1) "
        "THEN [dfe_exact].[segment_id] ELSE NULL END) AS [segment_id], "
        "CONVERT(varbinary("
        f"{_MAX_INT64_KEY_ENVELOPE_BYTES}), CASE WHEN "
        "[dfe_exact].[dfe_has_data] = CONVERT(bit, 1) "
        "THEN [dfe_exact].[key_envelope] ELSE NULL END) AS [key_envelope], "
        f"CONVERT(varbinary({bounded_envelope_bytes}), CASE WHEN "
        "[dfe_exact].[dfe_has_data] = CONVERT(bit, 1) "
        "THEN [dfe_exact].[row_envelope] ELSE NULL END) AS [row_envelope], "
        "CASE WHEN [dfe_exact].[dfe_has_data] = CONVERT(bit, 1) "
        "THEN [dfe_exact].[invalid_row] ELSE CONVERT(bit, NULL) END AS [invalid_row], "
        "CASE WHEN [dfe_exact].[dfe_has_data] = CONVERT(bit, 1) "
        "THEN [dfe_exact].[oversized_row] ELSE CONVERT(bit, NULL) END AS [oversized_row] "
        "FROM (SELECT [dfe_rows].*, "
        "COUNT_BIG(CASE WHEN [dfe_rows].[dfe_has_data] = CONVERT(bit, 1) THEN 1 END) "
        "OVER () AS [data_count], "
        "ROW_NUMBER() OVER (ORDER BY [dfe_rows].[ordinal], [dfe_rows].[key_value]) "
        "AS [witness_ordinal] FROM [dfe_rows]) "
        "AS [dfe_exact] "
        "WHERE [dfe_exact].[dfe_has_data] = CONVERT(bit, 1) "
        "OR ([dfe_exact].[data_count] = 0 AND [dfe_exact].[witness_ordinal] = 1) "
        "ORDER BY [dfe_exact].[ordinal], [dfe_exact].[key_value] "
        "OPTION (FORCE ORDER)"
    )
    return MssqlCanonicalQuery(
        statement=statement,
        parameters=source.parameters,
        schema=schema,
        context=source.context,
        inspection=inspection,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
        result_kind=MssqlCanonicalResultKind.INTEGER_RANGE_ROWS,
    )


def build_mssql_relation_manifest_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    dataset_id: str,
    scope_digest: str,
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    return _build_mssql_relation_manifest_query(
        schema,
        inspection,
        dataset_id,
        scope_digest,
        max_encoded_envelope_bytes,
        _origin_cte,
        _payload_lowering,
    )


def build_mssql_2016_relation_manifest_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    helper: MssqlUtf8HelperBinding,
    dataset_id: str,
    scope_digest: str,
    max_encoded_envelope_bytes: int,
) -> MssqlCanonicalQuery:
    origin_cte_builder: _OriginCteBuilder = partial(_mssql_2016_origin_cte, helper)
    payload_lowerer: _PayloadLowerer = partial(_mssql_2016_payload_lowering, helper)
    return _build_mssql_relation_manifest_query(
        schema,
        inspection,
        dataset_id,
        scope_digest,
        max_encoded_envelope_bytes,
        origin_cte_builder,
        payload_lowerer,
    )


def _build_mssql_relation_manifest_query(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    dataset_id: str,
    scope_digest: str,
    max_encoded_envelope_bytes: int,
    origin_cte_builder: _OriginCteBuilder,
    payload_lowerer: _PayloadLowerer,
) -> MssqlCanonicalQuery:
    _validate_canonical_inputs(schema, inspection, max_encoded_envelope_bytes)
    if len(schema.fields) != 8:
        raise MssqlLoweringError("SQL Server readiness manifest schema must contain eight fields")
    _validate_scalar_text(dataset_id, "SQL Server readiness dataset ID")
    _validate_scalar_text(scope_digest, "SQL Server readiness scope digest")
    payloads = tuple(
        payload_lowerer(field, binding, index)
        for index, (field, binding) in enumerate(
            zip(schema.fields, inspection.bindings, strict=True)
        )
    )
    origin = origin_cte_builder(inspection)
    relation_source = _relation_source(inspection)
    provenance = _provenance_projection("dfe_manifest", inspection)
    dataset_payload = payloads[0]
    scope_payload = payloads[1]
    dataset_filter = _canonical_equality_predicate(dataset_payload)
    scope_filter = _canonical_equality_predicate(scope_payload)
    statement = (
        f"WITH {origin}, [dfe_manifest] AS ("
        f"SELECT {_identity_projection('dfe_origin', inspection)}, "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL THEN CONVERT(bit, 0) "
        "ELSE CONVERT(bit, 1) END AS [dfe_has_data], "
        "[dfe_source].[dfe_field_0] AS [dataset_id], "
        "[dfe_source].[dfe_field_1] AS [scope_digest], "
        "[dfe_source].[dfe_field_2] AS [batch_id], "
        "[dfe_source].[dfe_field_3] AS [state], "
        "CONVERT(char(10), [dfe_source].[dfe_field_4], 23) AS [business_date], "
        "[dfe_source].[dfe_field_5] AS [source_cut], "
        "[dfe_source].[dfe_field_6] AS [dataset_version], "
        "CONVERT(varchar(40), SWITCHOFFSET([dfe_source].[dfe_field_7], '+00:00'), 127) "
        "AS [completed_at] FROM [dfe_origin] "
        f"LEFT JOIN ({relation_source}) AS [dfe_source] ON "
        f"{dataset_filter} AND {scope_filter}"
        ") "
        f"SELECT {provenance}, [dfe_manifest].[dataset_id], "
        "[dfe_manifest].[scope_digest], [dfe_manifest].[batch_id], "
        "[dfe_manifest].[state], [dfe_manifest].[business_date], "
        "[dfe_manifest].[source_cut], [dfe_manifest].[dataset_version], "
        "[dfe_manifest].[completed_at] FROM [dfe_manifest]"
    )
    context = prepare_envelope_context(schema)
    return MssqlCanonicalQuery(
        statement=statement,
        parameters=(
            dataset_id.encode("utf-8", errors="strict"),
            scope_digest.encode("ascii", errors="strict"),
        ),
        schema=schema,
        context=context,
        inspection=inspection,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
        result_kind=MssqlCanonicalResultKind.RELATION_MANIFEST,
    )


def _integer_range_source(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    key_field_index: int,
    scope: MssqlScopePredicate | None,
    ranges: tuple[MssqlIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
    origin_cte_builder: _OriginCteBuilder,
    payload_lowerer: _PayloadLowerer,
) -> _IntegerRangeSource:
    _validate_canonical_inputs(schema, inspection, max_encoded_envelope_bytes)
    _validate_single_integer_key(schema, key_field_index)
    _validate_integer_ranges(ranges)
    context = prepare_envelope_context(schema)
    key_field = schema.fields[key_field_index]
    key_context = prepare_envelope_context(
        CanonicalSchema(protocol=schema.protocol, fields=(key_field,))
    )
    payloads = tuple(
        payload_lowerer(field, binding, index)
        for index, (field, binding) in enumerate(
            zip(schema.fields, inspection.bindings, strict=True)
        )
    )
    payload_clause = _payload_clause(payloads)
    fields_valid = _fields_valid_expression(schema, inspection.bindings, payloads)
    payload_bytes = _payload_bytes_expression(inspection.bindings, payloads)
    frames = _bounded_frames_expression(schema, inspection.bindings, payloads)
    key_column = _qualified_column(key_field_index)
    key_payload = payloads[key_field_index]
    key_value = f"TRY_CONVERT(bigint, {key_column})"
    key_frame = _single_key_frame_expression(key_field, key_field_index)
    effective_envelope_limit = min(
        max_encoded_envelope_bytes,
        _MAX_BOUNDED_VARCHAR_BYTES,
    )
    bounded_envelope_bytes = min(
        effective_envelope_limit,
        _maximum_bounded_row_envelope_bytes(schema, inspection.bindings),
    )
    fixed_bytes = _ROW_HEADER_BYTES + (_FIELD_FRAME_BYTES * len(schema.fields))
    scope_filter, scope_parameters = _scope_filter(inspection, scope, payload_lowerer)
    ranges_statement, range_parameters = _integer_range_values(ranges)
    origin = origin_cte_builder(inspection)
    validated_origin = _validated_origin_cte(inspection)
    relation_source = _relation_source(inspection)
    statement = (
        f"SET NOCOUNT ON; WITH {origin}, {validated_origin}, "
        "[dfe_ranges]([segment_id], [lower_inclusive], "
        f"[upper_exclusive], [has_upper], [ordinal]) AS ({ranges_statement}), "
        "[dfe_rows] AS ("
        "SELECT [dfe_ranges].[segment_id], "
        "[dfe_ranges].[ordinal], "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL THEN CONVERT(bit, 0) "
        "ELSE CONVERT(bit, 1) END AS [dfe_has_data], "
        f"{key_value} AS [key_value], [dfe_key].[key_envelope], "
        "[dfe_row].[row_envelope], [dfe_validation].[envelope_bytes], "
        "[dfe_validation].[invalid_row], [dfe_row].[oversized_row] "
        "FROM [dfe_validated_origin] AS [dfe_origin] CROSS JOIN [dfe_ranges] "
        f"LEFT JOIN ({relation_source}) AS [dfe_source] ON ({scope_filter}) "
        f"AND {key_column} IS NOT NULL AND ({key_payload.is_valid}) "
        f"AND {key_value} >= [dfe_ranges].[lower_inclusive] "
        "AND ([dfe_ranges].[has_upper] = CONVERT(bit, 0) "
        f"OR {key_value} < [dfe_ranges].[upper_exclusive]) "
        f"{payload_clause} "
        "CROSS APPLY (SELECT "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL THEN CONVERT(bit, 0) "
        f"WHEN {fields_valid} THEN CONVERT(bit, 0) ELSE CONVERT(bit, 1) END "
        "AS [invalid_row], "
        f"CONVERT(bigint, {fixed_bytes}) + "
        f"(CONVERT(bigint, 2) * ({payload_bytes})) AS [envelope_bytes]"
        ") AS [dfe_validation] "
        "CROSS APPLY (SELECT "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL "
        "OR [dfe_validation].[invalid_row] = CONVERT(bit, 1) "
        f"OR [dfe_validation].[envelope_bytes] > CONVERT(bigint, {effective_envelope_limit}) "
        f"THEN CONVERT(varchar({bounded_envelope_bytes}), NULL) "
        f"ELSE CONVERT(varchar({bounded_envelope_bytes}), "
        f"CONVERT(varchar({_ROW_HEADER_BYTES}), ?) + {frames}) END AS [row_envelope], "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NOT NULL "
        "AND [dfe_validation].[invalid_row] = CONVERT(bit, 0) "
        f"AND [dfe_validation].[envelope_bytes] > CONVERT(bigint, {effective_envelope_limit}) "
        "THEN CONVERT(bit, 1) ELSE CONVERT(bit, 0) END AS [oversized_row]"
        ") AS [dfe_row] "
        "CROSS APPLY (SELECT CASE WHEN [dfe_source].[dfe_has_data] IS NULL "
        f"THEN CONVERT(varchar({_MAX_INT64_KEY_ENVELOPE_BYTES}), NULL) "
        f"ELSE CONVERT(varchar({_MAX_INT64_KEY_ENVELOPE_BYTES}), "
        f"CONVERT(varchar({_ROW_HEADER_BYTES}), ?) + {key_frame}) END AS [key_envelope]"
        ") AS [dfe_key]"
        ")"
    )
    return _IntegerRangeSource(
        statement=statement,
        context=context,
        parameters=(
            *range_parameters,
            *scope_parameters,
            context.row_header,
            key_context.key_header,
        ),
    )


def _scope_filter(
    inspection: MssqlInspectedRelation,
    scope: MssqlScopePredicate | None,
    payload_lowerer: _PayloadLowerer,
) -> tuple[str, tuple[MssqlCanonicalParameter, ...]]:
    if scope is None:
        return "1 = 1", ()
    if not isinstance(cast(object, scope), MssqlScopePredicate):
        raise MssqlLoweringError("SQL Server scope must be MssqlScopePredicate or None")
    matches = tuple(
        (index, binding)
        for index, binding in enumerate(inspection.bindings)
        if binding.column_name == scope.column_name
    )
    if len(matches) != 1:
        raise MssqlLoweringError(
            "SQL Server scoped comparison requires the scope column to map exactly once: "
            f"column={scope.column_name!r}, matching_fields={len(matches)}"
        )
    field_index, binding = matches[0]
    _validate_physical_mapping(scope.field, binding.physical, field_index)
    column = _qualified_column(field_index)
    payload = payload_lowerer(scope.field, binding, field_index)
    predicate = (
        f"{column} IS NOT NULL AND ({payload.is_valid}) "
        f"AND ({payload.payload}) = CONVERT(varbinary(max), ?)"
    )
    if payload.prelude:
        predicate = _predicate_with_payload_prelude(
            predicate,
            payload.prelude,
            "dfe_scope_seed",
        )
    return (
        predicate,
        (scope.canonical_payload,),
    )


def _integer_range_values(
    ranges: tuple[MssqlIntegerRangeRequest, ...],
) -> tuple[str, tuple[MssqlCanonicalParameter, ...]]:
    rows: list[str] = []
    parameters: list[MssqlCanonicalParameter] = []
    segment_id_characters = max(len(item.segment_id) for item in ranges)
    for ordinal, item in enumerate(ranges):
        upper_value = item.lower_inclusive if item.upper_exclusive is None else item.upper_exclusive
        rows.append(
            f"SELECT CONVERT(varchar({segment_id_characters}), ?), CONVERT(bigint, ?), "
            "CONVERT(bigint, ?), CONVERT(bit, ?), "
            f"CONVERT(int, {ordinal})"
        )
        parameters.extend(
            (
                item.segment_id,
                item.lower_inclusive,
                upper_value,
                0 if item.upper_exclusive is None else 1,
            )
        )
    return " UNION ALL ".join(rows), tuple(parameters)


def _single_key_frame_expression(field: FieldSchema, field_index: int) -> str:
    payload = f"[dfe_payload].{_quote_identifier(f'payload_{field_index}')}"
    tag = _type_tag(field.logical_type)
    return (
        f"CONVERT(varchar(3), '{tag}1') + "
        "LOWER(CONVERT(char(16), CONVERT(binary(8), "
        f"CONVERT(bigint, DATALENGTH({payload}))), 2)) + "
        f"LOWER(CONVERT(varchar(40), {payload}, 2))"
    )


def _integer_access_path_expression(
    inspection: MssqlInspectedRelation,
    key_column_id: int,
) -> str:
    return (
        "EXISTS (SELECT 1 FROM sys.indexes AS [dfe_index] "
        "JOIN sys.index_columns AS [dfe_index_column] "
        "ON [dfe_index_column].[object_id] = [dfe_index].[object_id] "
        "AND [dfe_index_column].[index_id] = [dfe_index].[index_id] "
        f"WHERE [dfe_index].[object_id] = {inspection.object_id} "
        "AND [dfe_index].[type] IN (1, 2) AND [dfe_index].[is_disabled] = 0 "
        "AND [dfe_index].[is_hypothetical] = 0 AND [dfe_index].[has_filter] = 0 "
        "AND [dfe_index_column].[key_ordinal] = 1 "
        f"AND [dfe_index_column].[column_id] = {key_column_id})"
    )


def _validate_single_integer_key(schema: CanonicalSchema, key_field_index: int) -> None:
    if type(key_field_index) is not int or not 0 <= key_field_index < len(schema.fields):
        raise MssqlLoweringError(
            "SQL Server integer-key index must identify a logical schema field"
        )
    field = schema.fields[key_field_index]
    if field.logical_type is not LogicalType.INT64 or field.nullable:
        raise MssqlLoweringError(
            "SQL Server integer-range comparison requires one non-null logical INT64 key"
        )


def _validate_integer_ranges(ranges: tuple[MssqlIntegerRangeRequest, ...]) -> None:
    if type(ranges) is not tuple or not ranges:
        raise MssqlLoweringError(
            "SQL Server integer-range requests must be a non-empty immutable tuple"
        )
    if len(ranges) > _MAX_INTEGER_RANGES:
        raise MssqlLoweringError(
            "SQL Server integer-range request count exceeds the safe 2,100-parameter "
            f"batch bound: observed={len(ranges)}, maximum={_MAX_INTEGER_RANGES}"
        )
    segment_ids: set[str] = set()
    for item in ranges:
        if type(item) is not MssqlIntegerRangeRequest:
            raise MssqlLoweringError(
                "SQL Server integer-range requests must contain MssqlIntegerRangeRequest values"
            )
        if item.segment_id in segment_ids:
            raise MssqlLoweringError(
                f"SQL Server integer-range segment ID is duplicated: {item.segment_id!r}"
            )
        if not item.segment_id.isascii():
            raise MssqlLoweringError("SQL Server integer-range segment ID must be ASCII")
        if len(item.segment_id) > 128:
            raise MssqlLoweringError("SQL Server integer-range segment ID exceeds 128 bytes")
        segment_ids.add(item.segment_id)


def _canonical_query(
    source: _RowSource,
    inspection: MssqlInspectedRelation,
    max_encoded_envelope_bytes: int,
    result_kind: MssqlCanonicalResultKind,
    statement: str,
) -> MssqlCanonicalQuery:
    return MssqlCanonicalQuery(
        statement=statement,
        parameters=source.parameters,
        schema=source.context.schema,
        context=source.context,
        inspection=inspection,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
        result_kind=result_kind,
    )


def _row_source(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> _RowSource:
    bindings = inspection.bindings
    context = prepare_envelope_context(schema)
    payloads = tuple(
        _payload_lowering(field, binding, index)
        for index, (field, binding) in enumerate(zip(schema.fields, bindings, strict=True))
    )
    payload_clause = _payload_clause(payloads)
    fields_valid = _fields_valid_expression(schema, bindings, payloads)
    payload_bytes = _payload_bytes_expression(bindings, payloads)
    frames = _frames_expression(schema, bindings, payloads)
    fixed_bytes = _ROW_HEADER_BYTES + (_FIELD_FRAME_BYTES * len(schema.fields))
    origin = _origin_cte(inspection)
    relation_source = _relation_source(inspection)
    origin_identity = _identity_projection("dfe_origin", inspection)
    row_provenance = _provenance_projection("dfe_rows", inspection)
    statement = (
        f"WITH {origin}, [dfe_rows] AS ("
        f"SELECT {origin_identity}, "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL THEN CONVERT(bit, 0) "
        "ELSE CONVERT(bit, 1) END AS [dfe_has_data], "
        "[dfe_row].[envelope], "
        "[dfe_validation].[envelope_bytes], "
        "[dfe_validation].[invalid_row], [dfe_row].[oversized_row] "
        "FROM [dfe_origin] "
        f"LEFT JOIN ({relation_source}) AS [dfe_source] ON 1 = 1 "
        f"{payload_clause} "
        "CROSS APPLY (SELECT "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL THEN CONVERT(bit, 0) "
        f"WHEN {fields_valid} THEN CONVERT(bit, 0) ELSE CONVERT(bit, 1) END "
        "AS [invalid_row], "
        f"CONVERT(bigint, {fixed_bytes}) + "
        f"(CONVERT(bigint, 2) * ({payload_bytes})) AS [envelope_bytes]"
        ") AS [dfe_validation] "
        "CROSS APPLY (SELECT "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NULL "
        "OR [dfe_validation].[invalid_row] = CONVERT(bit, 1) "
        f"OR [dfe_validation].[envelope_bytes] > CONVERT(bigint, {max_encoded_envelope_bytes}) "
        "THEN CONVERT(varchar(max), NULL) "
        f"ELSE CONVERT(varchar(max), ?) + {frames} END AS [envelope], "
        "CASE WHEN [dfe_source].[dfe_has_data] IS NOT NULL "
        "AND [dfe_validation].[invalid_row] = CONVERT(bit, 0) "
        f"AND [dfe_validation].[envelope_bytes] > CONVERT(bigint, {max_encoded_envelope_bytes}) "
        "THEN CONVERT(bit, 1) ELSE CONVERT(bit, 0) END AS [oversized_row]"
        ") AS [dfe_row]"
        "), [dfe_hash] AS ("
        f"SELECT {row_provenance}, [dfe_rows].[envelope], [dfe_rows].[envelope_bytes], "
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


def _origin_cte(inspection: MssqlInspectedRelation) -> str:
    return _build_origin_cte(
        inspection,
        (
            "AND [dfe_table].[is_external] = 0 "
            "AND [dfe_table].[ledger_type] = 0 "
            "AND [dfe_table].[is_node] = 0 AND [dfe_table].[is_edge] = 0 "
        ),
        "",
    )


def _mssql_2016_origin_cte(
    helper: MssqlUtf8HelperBinding,
    inspection: MssqlInspectedRelation,
) -> str:
    return _build_origin_cte(
        inspection,
        (
            "AND [dfe_table].[is_external] = 0 AND "
            f"{_mssql_2016_supported_storage_predicate('dfe_table', 'dfe_storage_column')} "
        ),
        _mssql_2016_helper_witness(helper),
    )


def _build_origin_cte(
    inspection: MssqlInspectedRelation,
    table_profile_validation: str,
    additional_validation: str,
) -> str:
    relation = inspection.relation
    relation_name = _qualified_relation_name(relation)
    column_validation = _column_validation_predicate(inspection)
    column_ids = ", ".join(
        "CONVERT(int, COLUMNPROPERTY([dfe_table].[object_id], "
        f"{_quote_unicode_literal(binding.column_name)}, N'ColumnId')) "
        f"AS {_quote_identifier(f'dfe_column_id_{index}')}"
        for index, binding in enumerate(inspection.bindings)
    )
    column_projection = f", {column_ids}" if column_ids else ""
    return (
        "[dfe_origin] AS (SELECT CONVERT(int, DB_ID()) AS [dfe_database_id], "
        "CONVERT(int, SCHEMA_ID("
        f"{_quote_unicode_literal(relation.schema_name)})) AS [dfe_schema_id], "
        "CONVERT(int, OBJECT_ID("
        f"{_quote_unicode_literal(relation_name)}, N'U')) AS [dfe_object_id]"
        f"{column_projection} "
        "FROM sys.tables AS [dfe_table] "
        "JOIN sys.schemas AS [dfe_schema] "
        "ON [dfe_schema].[schema_id] = [dfe_table].[schema_id] "
        f"WHERE DB_ID() = {inspection.database_id} "
        f"AND [dfe_schema].[schema_id] = {inspection.schema_id} "
        f"AND [dfe_table].[object_id] = {inspection.object_id} "
        "AND CONVERT(varbinary(256), [dfe_schema].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(relation.schema_name)}) "
        "AND CONVERT(varbinary(256), [dfe_table].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(relation.table_name)}) "
        "AND [dfe_table].[type] = 'U' AND [dfe_table].[is_ms_shipped] = 0 "
        "AND [dfe_table].[is_memory_optimized] = 0 "
        "AND [dfe_table].[temporal_type] = 0 "
        f"{table_profile_validation}"
        "AND HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'VIEW DEFINITION') = 1 "
        f"AND HAS_PERMS_BY_NAME({_quote_unicode_literal(relation_name)}, "
        "N'OBJECT', N'SELECT') = 1 "
        f"AND HAS_PERMS_BY_NAME({_quote_unicode_literal(relation_name)}, "
        "N'OBJECT', N'INSERT') = 0 "
        f"AND HAS_PERMS_BY_NAME({_quote_unicode_literal(relation_name)}, "
        "N'OBJECT', N'UPDATE') = 0 "
        "AND NOT EXISTS (SELECT 1 FROM sys.columns AS [dfe_writable_column] "
        "WHERE [dfe_writable_column].[object_id] = [dfe_table].[object_id] "
        f"AND HAS_PERMS_BY_NAME({_quote_unicode_literal(relation_name)}, "
        "N'OBJECT', N'UPDATE', [dfe_writable_column].[name], N'COLUMN') = 1) "
        f"AND HAS_PERMS_BY_NAME({_quote_unicode_literal(relation_name)}, "
        "N'OBJECT', N'DELETE') = 0 "
        f"AND HAS_PERMS_BY_NAME({_quote_unicode_literal(relation_name)}, "
        "N'OBJECT', N'ALTER') = 0 "
        f"AND HAS_PERMS_BY_NAME({_quote_unicode_literal(relation_name)}, "
        "N'OBJECT', N'CONTROL') = 0 "
        "AND NOT EXISTS (SELECT 1 FROM sys.security_predicates AS [dfe_predicate] "
        "JOIN sys.security_policies AS [dfe_policy] "
        "ON [dfe_policy].[object_id] = [dfe_predicate].[object_id] "
        "WHERE [dfe_predicate].[target_object_id] = [dfe_table].[object_id] "
        "AND [dfe_policy].[is_enabled] = 1) "
        f"{additional_validation}"
        f"{column_validation})"
    )


def _mssql_2016_helper_witness(helper: MssqlUtf8HelperBinding) -> str:
    helper_name = f"{helper.schema_name}.{helper.object_name}"
    execute_as_predicate = (
        "[dfe_helper_module].[execute_as_principal_id] IS NULL"
        if helper.execute_as_principal_id is None
        else (f"[dfe_helper_module].[execute_as_principal_id] = {helper.execute_as_principal_id}")
    )
    return (
        f"AND DB_ID() = {helper.database_id} "
        "AND CONVERT(varbinary(256), DB_NAME()) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.database_name)}) "
        "AND CONVERT(varbinary(256), CONVERT(nvarchar(128), "
        "DATABASEPROPERTYEX(DB_NAME(), N'Collation'))) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.database_collation)}) "
        "AND (SELECT [dfe_helper_database].[compatibility_level] "
        "FROM sys.databases AS [dfe_helper_database] "
        "WHERE [dfe_helper_database].[database_id] = DB_ID()) = "
        f"{helper.database_compatibility_level} "
        "AND EXISTS (SELECT 1 FROM sys.objects AS [dfe_helper_object] "
        "JOIN sys.schemas AS [dfe_helper_schema] "
        "ON [dfe_helper_schema].[schema_id] = [dfe_helper_object].[schema_id] "
        "JOIN sys.sql_modules AS [dfe_helper_module] "
        "ON [dfe_helper_module].[object_id] = [dfe_helper_object].[object_id] "
        f"WHERE [dfe_helper_schema].[schema_id] = {helper.schema_id} "
        "AND CONVERT(varbinary(256), [dfe_helper_schema].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.schema_name)}) "
        f"AND [dfe_helper_object].[object_id] = {helper.object_id} "
        "AND CONVERT(varbinary(256), [dfe_helper_object].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.object_name)}) "
        "AND CONVERT(varbinary(256), CONVERT(nvarchar(2), "
        "[dfe_helper_object].[type])) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.object_type)}) "
        "AND CONVERT(bigint, DATALENGTH([dfe_helper_module].[definition])) = "
        f"CONVERT(bigint, {helper.definition_utf16_bytes}) "
        "AND HASHBYTES('SHA2_256', CONVERT(varbinary(max), "
        "[dfe_helper_module].[definition])) = "
        f"0x{helper.definition_sha256.hex()} "
        "AND [dfe_helper_module].[uses_ansi_nulls] = "
        f"{_boolean_integer(helper.uses_ansi_nulls)} "
        "AND [dfe_helper_module].[uses_quoted_identifier] = "
        f"{_boolean_integer(helper.uses_quoted_identifier)} "
        "AND [dfe_helper_module].[is_schema_bound] = "
        f"{_boolean_integer(helper.is_schema_bound)} "
        "AND [dfe_helper_module].[uses_database_collation] = "
        f"{_boolean_integer(helper.uses_database_collation)} "
        "AND [dfe_helper_module].[null_on_null_input] = "
        f"{_boolean_integer(helper.null_on_null_input)} "
        f"AND {execute_as_predicate} "
        "AND CONVERT(int, OBJECTPROPERTYEX([dfe_helper_object].[object_id], "
        f"N'IsDeterministic')) = {_boolean_integer(helper.is_deterministic)} "
        "AND CONVERT(int, OBJECTPROPERTYEX([dfe_helper_object].[object_id], "
        f"N'IsPrecise')) = {_boolean_integer(helper.is_precise)} "
        "AND CONVERT(int, OBJECTPROPERTYEX([dfe_helper_object].[object_id], "
        f"N'IsEncrypted')) = {_boolean_integer(helper.is_encrypted)} "
        f"AND COALESCE(HAS_PERMS_BY_NAME({_quote_unicode_literal(helper_name)}, "
        "N'OBJECT', N'EXECUTE'), 0) = "
        f"{_boolean_integer(helper.can_execute)} "
        f"AND COALESCE(HAS_PERMS_BY_NAME({_quote_unicode_literal(helper_name)}, "
        "N'OBJECT', N'VIEW DEFINITION'), 0) = "
        f"{_boolean_integer(helper.can_view_definition)} "
        f"AND COALESCE(HAS_PERMS_BY_NAME({_quote_unicode_literal(helper_name)}, "
        "N'OBJECT', N'ALTER'), 0) = "
        f"{_boolean_integer(helper.can_alter)} "
        f"AND COALESCE(HAS_PERMS_BY_NAME({_quote_unicode_literal(helper_name)}, "
        "N'OBJECT', N'CONTROL'), 0) = "
        f"{_boolean_integer(helper.can_control)} "
        "AND (SELECT COUNT_BIG(*) FROM sys.parameters AS [dfe_helper_parameter] "
        "WHERE [dfe_helper_parameter].[object_id] = "
        "[dfe_helper_object].[object_id]) = CONVERT(bigint, 2) "
        "AND EXISTS (SELECT 1 FROM sys.parameters AS [dfe_return_parameter] "
        "JOIN sys.types AS [dfe_return_type] "
        "ON [dfe_return_type].[user_type_id] = [dfe_return_parameter].[user_type_id] "
        "JOIN sys.schemas AS [dfe_return_type_schema] "
        "ON [dfe_return_type_schema].[schema_id] = [dfe_return_type].[schema_id] "
        "WHERE [dfe_return_parameter].[object_id] = [dfe_helper_object].[object_id] "
        "AND [dfe_return_parameter].[parameter_id] = 0 "
        "AND CONVERT(varbinary(256), [dfe_return_type_schema].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.return_type_schema)}) "
        "AND CONVERT(varbinary(256), [dfe_return_type].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.return_type_name)}) "
        f"AND [dfe_return_parameter].[max_length] = {helper.return_max_length} "
        "AND [dfe_return_parameter].[is_output] = "
        f"{_boolean_integer(helper.return_is_output)} "
        "AND [dfe_return_parameter].[has_default_value] = "
        f"{_boolean_integer(helper.return_has_default_value)}) "
        "AND EXISTS (SELECT 1 FROM sys.parameters AS [dfe_input_parameter] "
        "JOIN sys.types AS [dfe_input_type] "
        "ON [dfe_input_type].[user_type_id] = [dfe_input_parameter].[user_type_id] "
        "JOIN sys.schemas AS [dfe_input_type_schema] "
        "ON [dfe_input_type_schema].[schema_id] = [dfe_input_type].[schema_id] "
        "WHERE [dfe_input_parameter].[object_id] = [dfe_helper_object].[object_id] "
        "AND [dfe_input_parameter].[parameter_id] = 1 "
        "AND CONVERT(varbinary(256), [dfe_input_parameter].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.input_parameter_name)}) "
        "AND CONVERT(varbinary(256), [dfe_input_type_schema].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.input_type_schema)}) "
        "AND CONVERT(varbinary(256), [dfe_input_type].[name]) = "
        f"CONVERT(varbinary(256), {_quote_unicode_literal(helper.input_type_name)}) "
        f"AND [dfe_input_parameter].[max_length] = {helper.input_max_length} "
        "AND [dfe_input_parameter].[is_output] = "
        f"{_boolean_integer(helper.input_is_output)} "
        "AND [dfe_input_parameter].[has_default_value] = "
        f"{_boolean_integer(helper.input_has_default_value)})) "
        "AND CONVERT(int, SESSIONPROPERTY(N'ANSI_NULLS')) = "
        f"{_boolean_integer(helper.ansi_nulls)} "
        "AND CONVERT(int, SESSIONPROPERTY(N'ANSI_PADDING')) = "
        f"{_boolean_integer(helper.ansi_padding)} "
        "AND CONVERT(int, SESSIONPROPERTY(N'ANSI_WARNINGS')) = "
        f"{_boolean_integer(helper.ansi_warnings)} "
        "AND CONVERT(int, SESSIONPROPERTY(N'ARITHABORT')) = "
        f"{_boolean_integer(helper.arithabort)} "
        "AND CONVERT(int, SESSIONPROPERTY(N'CONCAT_NULL_YIELDS_NULL')) = "
        f"{_boolean_integer(helper.concat_null_yields_null)} "
        "AND CONVERT(int, SESSIONPROPERTY(N'NUMERIC_ROUNDABORT')) = "
        f"{_boolean_integer(helper.numeric_roundabort)} "
        "AND CONVERT(int, SESSIONPROPERTY(N'QUOTED_IDENTIFIER')) = "
        f"{_boolean_integer(helper.quoted_identifier)} "
    )


def _mssql_2016_supported_storage_predicate(
    table_alias: str,
    column_alias: str,
) -> str:
    _validate_identifier(table_alias, "SQL Server table-catalog alias")
    _validate_identifier(column_alias, "SQL Server column-catalog alias")
    quoted_table_alias = _quote_identifier(table_alias)
    quoted_column_alias = _quote_identifier(column_alias)
    return (
        f"NOT EXISTS (SELECT 1 FROM sys.columns AS {quoted_column_alias} "
        f"WHERE {quoted_column_alias}.[object_id] = {quoted_table_alias}.[object_id] "
        f"AND ({quoted_column_alias}.[is_hidden] = 1 OR "
        f"{quoted_column_alias}.[generated_always_type] <> 0))"
    )


def _validated_origin_cte(inspection: MssqlInspectedRelation) -> str:
    columns = (
        "dfe_database_id",
        "dfe_schema_id",
        "dfe_object_id",
        *(f"dfe_column_id_{index}" for index, _binding in enumerate(inspection.bindings)),
    )
    projection = ", ".join(
        f"MAX([dfe_origin].{_quote_identifier(column)}) AS {_quote_identifier(column)}"
        for column in columns
    )
    return (
        f"[dfe_validated_origin] AS (SELECT {projection} FROM [dfe_origin] "
        "HAVING COUNT_BIG(*) = CONVERT(bigint, 1))"
    )


def _column_validation_predicate(inspection: MssqlInspectedRelation) -> str:
    if not inspection.bindings:
        return ""
    rows = ", ".join(
        "("
        f"{binding.column_id}, {_quote_unicode_literal(binding.column_name)}, "
        f"{_quote_unicode_literal(binding.physical.system_type_name)}, "
        f"{binding.physical.system_type_id}, {binding.physical.user_type_id}, "
        f"{binding.physical.max_length}, {binding.physical.precision}, "
        f"{binding.physical.scale}, {_optional_unicode_literal(binding.physical.collation_name)}, "
        f"{1 if binding.is_nullable else 0}"
        ")"
        for binding in inspection.bindings
    )
    return (
        "AND NOT EXISTS (SELECT 1 FROM (VALUES "
        f"{rows}) AS [dfe_expected]([column_id], [column_name], [system_type_name], "
        "[system_type_id], [user_type_id], [max_length], [precision], [scale], "
        "[collation_name], [is_nullable]) "
        "LEFT JOIN sys.columns AS [dfe_column] "
        "ON [dfe_column].[object_id] = [dfe_table].[object_id] "
        "AND [dfe_column].[column_id] = [dfe_expected].[column_id] "
        "LEFT JOIN sys.types AS [dfe_type] "
        "ON [dfe_type].[user_type_id] = [dfe_column].[system_type_id] "
        "AND [dfe_type].[system_type_id] = [dfe_column].[system_type_id] "
        "WHERE [dfe_column].[column_id] IS NULL "
        "OR CONVERT(varbinary(256), [dfe_column].[name]) <> "
        "CONVERT(varbinary(256), [dfe_expected].[column_name]) "
        "OR CONVERT(varbinary(256), [dfe_type].[name]) <> "
        "CONVERT(varbinary(256), [dfe_expected].[system_type_name]) "
        "OR [dfe_column].[system_type_id] <> [dfe_expected].[system_type_id] "
        "OR [dfe_column].[user_type_id] <> [dfe_expected].[user_type_id] "
        "OR [dfe_column].[max_length] <> [dfe_expected].[max_length] "
        "OR [dfe_column].[precision] <> [dfe_expected].[precision] "
        "OR [dfe_column].[scale] <> [dfe_expected].[scale] "
        "OR ([dfe_column].[collation_name] IS NULL "
        "AND [dfe_expected].[collation_name] IS NOT NULL) "
        "OR ([dfe_column].[collation_name] IS NOT NULL "
        "AND [dfe_expected].[collation_name] IS NULL) "
        "OR CONVERT(varbinary(256), [dfe_column].[collation_name]) <> "
        "CONVERT(varbinary(256), [dfe_expected].[collation_name]) "
        "OR [dfe_column].[is_nullable] <> [dfe_expected].[is_nullable] "
        "OR [dfe_column].[is_computed] <> 0 "
        "OR [dfe_column].[is_hidden] <> 0 "
        "OR [dfe_column].[is_masked] <> 0 "
        "OR [dfe_column].[generated_always_type] <> 0 "
        "OR [dfe_column].[encryption_type] IS NOT NULL) "
    )


def _relation_source(inspection: MssqlInspectedRelation) -> str:
    columns = ", ".join(
        f"[dfe_physical].{_quote_identifier(binding.column_name)} "
        f"AS {_quote_identifier(f'dfe_field_{index}')}"
        for index, binding in enumerate(inspection.bindings)
    )
    column_projection = f", {columns}" if columns else ""
    return (
        "SELECT CONVERT(bit, 1) AS [dfe_has_data]"
        f"{column_projection} FROM {_qualified_relation_name(inspection.relation)} "
        "AS [dfe_physical]"
    )


def _identity_projection(alias: str, inspection: MssqlInspectedRelation) -> str:
    _validate_identifier(alias, "SQL Server internal provenance alias")
    columns = (
        "dfe_database_id",
        "dfe_schema_id",
        "dfe_object_id",
        *(f"dfe_column_id_{index}" for index, _binding in enumerate(inspection.bindings)),
    )
    return ", ".join(
        f"{_quote_identifier(alias)}.{_quote_identifier(column)}" for column in columns
    )


def _literal_identity_projection(inspection: MssqlInspectedRelation) -> str:
    values = (
        ("dfe_database_id", inspection.database_id),
        ("dfe_schema_id", inspection.schema_id),
        ("dfe_object_id", inspection.object_id),
        *(
            (f"dfe_column_id_{index}", binding.column_id)
            for index, binding in enumerate(inspection.bindings)
        ),
    )
    return ", ".join(
        f"CONVERT(int, {value}) AS {_quote_identifier(column)}" for column, value in values
    )


def _provenance_projection(alias: str, inspection: MssqlInspectedRelation) -> str:
    return f"{_identity_projection(alias, inspection)}, [{alias}].[dfe_has_data]"


def _aggregate_provenance_projection(
    alias: str,
    inspection: MssqlInspectedRelation,
) -> str:
    _validate_identifier(alias, "SQL Server internal provenance alias")
    columns = (
        "dfe_database_id",
        "dfe_schema_id",
        "dfe_object_id",
        *(f"dfe_column_id_{index}" for index, _binding in enumerate(inspection.bindings)),
    )
    aggregates = [
        f"MAX([{alias}].{_quote_identifier(column)}) AS {_quote_identifier(column)}"
        for column in columns
    ]
    aggregates.append(
        "CONVERT(bit, COALESCE(MAX(CONVERT(tinyint, "
        f"[{alias}].[dfe_has_data])), 0)) AS [dfe_has_data]"
    )
    return ", ".join(aggregates)


def _aggregate_literal_provenance_projection(
    alias: str,
    inspection: MssqlInspectedRelation,
) -> str:
    _validate_identifier(alias, "SQL Server internal provenance alias")
    return (
        f"{_literal_identity_projection(inspection)}, "
        "CONVERT(bit, COALESCE(MAX(CONVERT(tinyint, "
        f"[{alias}].[dfe_has_data])), 0)) AS [dfe_has_data]"
    )


def _payload_clause(payloads: tuple[_PayloadLowering, ...]) -> str:
    if not payloads:
        return ""
    preludes = "".join(f"{payload.prelude} " for payload in payloads if payload.prelude)
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
    return f"{preludes}CROSS APPLY (SELECT {', '.join(columns)}) AS [dfe_payload]"


def _canonical_equality_predicate(payload: _PayloadLowering) -> str:
    predicate = f"({payload.is_valid}) AND ({payload.payload}) = CONVERT(varbinary(max), ?)"
    if not payload.prelude:
        return predicate
    return _predicate_with_payload_prelude(
        predicate,
        payload.prelude,
        "dfe_equality_seed",
    )


def _predicate_with_payload_prelude(
    predicate: str,
    prelude: str,
    seed_alias: str,
) -> str:
    _validate_identifier(seed_alias, "SQL Server internal canonical predicate seed alias")
    return (
        "EXISTS (SELECT 1 FROM (VALUES (CONVERT(bit, 1))) AS "
        f"{_quote_identifier(seed_alias)}([value]) {prelude} WHERE {predicate})"
    )


def _fields_valid_expression(
    schema: CanonicalSchema,
    bindings: tuple[MssqlFieldBinding, ...],
    payloads: tuple[_PayloadLowering, ...],
) -> str:
    if not schema.fields:
        return "1 = 1"
    conditions: list[str] = []
    for index, (field, _binding, _) in enumerate(
        zip(schema.fields, bindings, payloads, strict=True)
    ):
        column = _qualified_column(index)
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
    for index, _binding in enumerate(bindings):
        column = _qualified_column(index)
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
    for index, (field, _binding, _) in enumerate(
        zip(schema.fields, bindings, payloads, strict=True)
    ):
        column = _qualified_column(index)
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


def _bounded_frames_expression(
    schema: CanonicalSchema,
    bindings: tuple[MssqlFieldBinding, ...],
    payloads: tuple[_PayloadLowering, ...],
) -> str:
    frames: list[str] = []
    for index, (field, _binding, _) in enumerate(
        zip(schema.fields, bindings, payloads, strict=True)
    ):
        column = _qualified_column(index)
        payload = f"[dfe_payload].{_quote_identifier(f'payload_{index}')}"
        tag = _type_tag(field.logical_type)
        null_frame = f"'{tag}0{'0' * 16}'"
        present_frame = (
            f"CONVERT(varchar(3), '{tag}1') + "
            "LOWER(CONVERT(char(16), CONVERT(binary(8), "
            f"CONVERT(bigint, DATALENGTH({payload}))), 2)) + "
            f"LOWER(CONVERT(varchar({_MAX_BOUNDED_VARCHAR_BYTES}), {payload}, 2))"
        )
        frames.append(
            f"CASE WHEN {column} IS NULL THEN CONVERT(varchar(19), {null_frame}) "
            f"ELSE {present_frame} END"
        )
    return " + ".join(frames)


def _key_has_null_expression(key_field_indexes: tuple[int, ...]) -> str:
    return " OR ".join(
        f"{_qualified_column(field_index)} IS NULL" for field_index in key_field_indexes
    )


def _key_fields_valid_expression(
    key_field_indexes: tuple[int, ...],
    payloads: tuple[_PayloadLowering, ...],
) -> str:
    return " AND ".join(
        f"{_qualified_column(field_index)} IS NOT NULL AND "
        f"[dfe_payload].{_quote_identifier(f'valid_{payload_index}')} = CONVERT(bit, 1)"
        for payload_index, (field_index, _payload) in enumerate(
            zip(key_field_indexes, payloads, strict=True)
        )
    )


def _key_payload_bytes_expression(
    key_field_indexes: tuple[int, ...],
    payloads: tuple[_PayloadLowering, ...],
) -> str:
    return " + ".join(
        "CASE WHEN "
        f"{_qualified_column(field_index)} IS NULL OR "
        f"[dfe_payload].{_quote_identifier(f'valid_{payload_index}')} = CONVERT(bit, 0) "
        "THEN CONVERT(bigint, 0) ELSE DATALENGTH("
        f"[dfe_payload].{_quote_identifier(f'payload_{payload_index}')}) END"
        for payload_index, (field_index, _payload) in enumerate(
            zip(key_field_indexes, payloads, strict=True)
        )
    )


def _key_frames_expression(
    key_fields: tuple[FieldSchema, ...],
    key_field_indexes: tuple[int, ...],
    payloads: tuple[_PayloadLowering, ...],
) -> str:
    frames: list[str] = []
    for payload_index, (field, field_index, _payload) in enumerate(
        zip(key_fields, key_field_indexes, payloads, strict=True)
    ):
        column = _qualified_column(field_index)
        payload = f"[dfe_payload].{_quote_identifier(f'payload_{payload_index}')}"
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


def _payload_lowering(
    field: FieldSchema,
    binding: MssqlFieldBinding,
    field_index: int,
) -> _PayloadLowering:
    column = _qualified_column(field_index)
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


def _mssql_2016_payload_lowering(
    helper: MssqlUtf8HelperBinding,
    field: FieldSchema,
    binding: MssqlFieldBinding,
    field_index: int,
) -> _PayloadLowering:
    if field.logical_type is LogicalType.STRING:
        _require_no_parameters(field)
        return _mssql_2016_string_payload(
            helper,
            _qualified_column(field_index),
            binding.physical,
            field_index,
        )
    return _payload_lowering(field, binding, field_index)


def _int64_payload(column: str, physical: MssqlPhysicalField) -> _PayloadLowering:
    value = f"TRY_CONVERT(bigint, {column})"
    roundtrip = f"TRY_CONVERT({_numeric_physical_type(physical)}, {value})"
    return _PayloadLowering(
        prelude="",
        is_valid=f"{value} IS NOT NULL AND {roundtrip} = {column}",
        payload=f"CONVERT(varbinary(20), CONVERT(varchar(20), {value}))",
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
        prelude="",
        is_valid=f"{value} IS NOT NULL AND {roundtrip} = {column} AND {scaled} IS NOT NULL",
        payload=f"CONVERT(varbinary({precision + 1}), {scaled_text})",
    )


def _boolean_payload(column: str) -> _PayloadLowering:
    return _PayloadLowering(
        prelude="",
        is_valid=f"{column} IN (CONVERT(bit, 0), CONVERT(bit, 1))",
        payload=(
            "CASE WHEN "
            f"{column} = CONVERT(bit, 1) THEN CONVERT(varbinary(1), 0x31) "
            f"WHEN {column} = CONVERT(bit, 0) THEN CONVERT(varbinary(1), 0x30) "
            "ELSE CONVERT(varbinary(1), NULL) END"
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
    source_roundtrip = _string_source_roundtrip(
        column,
        unicode_value,
        physical,
        _quote_identifier,
    )
    no_nul = (
        "NOT EXISTS (SELECT 1 FROM GENERATE_SERIES("
        "CONVERT(bigint, 1), "
        f"COALESCE(DATALENGTH({payload}), CONVERT(bigint, 0)), "
        "CONVERT(bigint, 1)) AS [dfe_utf8_byte] "
        f"WHERE SUBSTRING({payload}, [dfe_utf8_byte].[value], 1) = 0x00)"
    )
    return _PayloadLowering(
        prelude="",
        is_valid=(
            f"{unicode_value} IS NOT NULL AND {lossless_utf8} AND {source_roundtrip} AND {no_nul}"
        ),
        payload=payload,
    )


def _mssql_2016_string_payload(
    helper: MssqlUtf8HelperBinding,
    column: str,
    physical: MssqlPhysicalField,
    field_index: int,
) -> _PayloadLowering:
    unicode_value = f"CONVERT(nvarchar(max), {column})"
    helper_name = f"{_quote_identifier(helper.schema_name)}.{_quote_identifier(helper.object_name)}"
    helper_alias = _quote_identifier(f"dfe_utf8_{field_index}")
    payload = f"{helper_alias}.[payload]"
    source_roundtrip = _string_source_roundtrip(
        column,
        unicode_value,
        physical,
        _mssql_2016_collation_name,
    )
    return _PayloadLowering(
        prelude=(
            f"OUTER APPLY (SELECT {helper_name}({unicode_value}) AS [payload]) AS {helper_alias}"
        ),
        is_valid=(f"{unicode_value} IS NOT NULL AND {payload} IS NOT NULL AND {source_roundtrip}"),
        payload=payload,
    )


def _string_source_roundtrip(
    column: str,
    unicode_value: str,
    physical: MssqlPhysicalField,
    collation_renderer: Callable[[str], str],
) -> str:
    if physical.system_type_name == "nvarchar":
        return "1 = 1"
    if physical.collation_name is None:
        raise MssqlLoweringError("SQL Server varchar provenance requires a collation")
    source_bytes = f"CONVERT(varbinary(max), CONVERT(varchar(max), {column}))"
    roundtrip_text = (
        "CONVERT(varchar(max), "
        f"{unicode_value} COLLATE {collation_renderer(physical.collation_name)})"
    )
    roundtrip_bytes = f"CONVERT(varbinary(max), {roundtrip_text})"
    return (
        f"DATALENGTH({source_bytes}) = DATALENGTH({roundtrip_bytes}) "
        f"AND {source_bytes} = {roundtrip_bytes}"
    )


def _date_payload(column: str) -> _PayloadLowering:
    return _PayloadLowering(
        prelude="",
        is_valid="1 = 1",
        payload=f"CONVERT(varbinary(10), CONVERT(char(10), {column}, 23))",
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
    maximum_payload_bytes = 19 + (0 if precision == 0 else precision + 1) + len(suffix)
    return _PayloadLowering(
        prelude="",
        is_valid=is_valid,
        payload=f"CONVERT(varbinary({maximum_payload_bytes}), {payload_text})",
    )


def _timestamp_precision(field: FieldSchema) -> int:
    if not isinstance(field.parameters, TimestampParameters):
        raise MssqlLoweringError("timestamp field requires TimestampParameters")
    return field.parameters.precision


def _maximum_bounded_row_envelope_bytes(
    schema: CanonicalSchema,
    bindings: tuple[MssqlFieldBinding, ...],
) -> int:
    payload_bytes = sum(
        _maximum_bounded_payload_bytes(field, binding.physical)
        for field, binding in zip(schema.fields, bindings, strict=True)
    )
    return _ROW_HEADER_BYTES + (_FIELD_FRAME_BYTES * len(schema.fields)) + (2 * payload_bytes)


def _maximum_bounded_payload_bytes(
    field: FieldSchema,
    physical: MssqlPhysicalField,
) -> int:
    if field.logical_type is LogicalType.INT64:
        return 20
    if field.logical_type is LogicalType.DECIMAL:
        if not isinstance(field.parameters, DecimalParameters):
            raise MssqlLoweringError("decimal field requires DecimalParameters")
        return field.parameters.precision + 1
    if field.logical_type is LogicalType.BOOLEAN:
        return 1
    if field.logical_type is LogicalType.STRING:
        if physical.max_length == -1:
            return _MAX_BOUNDED_VARCHAR_BYTES
        if physical.system_type_name == "nvarchar":
            maximum_utf8_bytes = 3 * (physical.max_length // 2)
        else:
            maximum_utf8_bytes = 4 * physical.max_length
        return min(maximum_utf8_bytes, _MAX_BOUNDED_VARCHAR_BYTES)
    if field.logical_type is LogicalType.DATE:
        return 10
    if field.logical_type is LogicalType.TIMESTAMP_LOCAL:
        precision = _timestamp_precision(field)
        return 19 if precision == 0 else 20 + precision
    if field.logical_type is LogicalType.TIMESTAMP_INSTANT:
        precision = _timestamp_precision(field)
        return 20 if precision == 0 else 21 + precision
    raise MssqlLoweringError(f"logical type {field.logical_type!r} has no SQL Server payload bound")


def _limb_sum_expression(index: int) -> str:
    offset = (index * 4) + 1
    limb = f"CONVERT(bigint, CONVERT(varbinary(4), SUBSTRING([dfe_hash].[row_hash], {offset}, 4)))"
    return (
        "COALESCE(SUM(CASE WHEN [dfe_hash].[row_hash] IS NULL "
        "THEN CONVERT(decimal(38, 0), 0) "
        f"ELSE CONVERT(decimal(38, 0), {limb}) END), "
        "CONVERT(decimal(38, 0), 0)) "
        f"AS {_quote_identifier(f'limb_{index}')}"
    )


def _validate_canonical_inputs(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> None:
    if not isinstance(cast(object, schema), CanonicalSchema):
        raise MssqlLoweringError("schema must be a CanonicalSchema")
    validate_mssql_inspection(schema, inspection)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "SQL Server maximum encoded envelope bytes",
        _MAX_LOB_BYTES,
    )


def validate_mssql_inspection(
    schema: CanonicalSchema,
    inspection: MssqlInspectedRelation,
) -> None:
    if not isinstance(cast(object, schema), CanonicalSchema):
        raise MssqlLoweringError("schema must be a CanonicalSchema")
    if type(inspection) is not MssqlInspectedRelation:
        raise MssqlLoweringError("inspection must be MssqlInspectedRelation")
    bindings = inspection.bindings
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


def _validate_key_field_indexes(
    schema: CanonicalSchema,
    key_field_indexes: tuple[int, ...],
) -> None:
    if type(key_field_indexes) is not tuple or not key_field_indexes:
        raise MssqlLoweringError("SQL Server key field indexes must be a non-empty immutable tuple")
    seen: set[int] = set()
    for key_ordinal, field_index in enumerate(key_field_indexes):
        if type(field_index) is not int or not 0 <= field_index < len(schema.fields):
            raise MssqlLoweringError(
                "SQL Server key field index must identify a logical schema field: "
                f"key_ordinal={key_ordinal}, field_index={field_index!r}"
            )
        if field_index in seen:
            raise MssqlLoweringError(
                "SQL Server key field indexes must not contain duplicates: "
                f"field_index={field_index}"
            )
        if schema.fields[field_index].nullable:
            raise MssqlLoweringError(
                "SQL Server key field must be logically non-nullable: "
                f"key_ordinal={key_ordinal}, field_index={field_index}, "
                f"field_name={schema.fields[field_index].name!r}"
            )
        seen.add(field_index)


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


def _qualified_column(field_index: int) -> str:
    _validate_nonnegative_integer(
        field_index,
        "SQL Server internal field index",
        MAX_COMPILED_RELATION_MEMBERS,
    )
    return f"[dfe_source].{_quote_identifier(f'dfe_field_{field_index}')}"


def _qualified_relation_name(relation: MssqlRelation) -> str:
    return f"{_quote_identifier(relation.schema_name)}.{_quote_identifier(relation.table_name)}"


def _quote_identifier(value: str) -> str:
    return "[" + value.replace("]", "]]") + "]"


def _quote_unicode_literal(value: str) -> str:
    _validate_scalar_text(value, "SQL Server Unicode literal")
    return "N'" + value.replace("'", "''") + "'"


def _mssql_2016_collation_name(value: str) -> str:
    _validate_identifier(value, "SQL Server 2016 collation name")
    if not value.isascii() or not value.replace("_", "").isalnum():
        raise MssqlLoweringError(
            "SQL Server 2016 collation name must contain only ASCII letters, digits, and "
            "underscores"
        )
    return value


def _optional_unicode_literal(value: str | None) -> str:
    if value is None:
        return "CONVERT(nvarchar(128), NULL)"
    return _quote_unicode_literal(value)


def _boolean_integer(value: bool) -> int:
    if type(value) is not bool:
        raise MssqlLoweringError("SQL Server boolean SQL literal must be boolean")
    return 1 if value else 0


def _validate_catalog_max_length(value: object, context: str) -> None:
    if type(value) is not int or not (-1 <= value <= INT32_MAX):
        raise MssqlLoweringError(f"{context} must be -1 or an integer in the range 0..{INT32_MAX}")


def _validate_parameter_name(value: object, context: str) -> None:
    _validate_scalar_text(value, context)
    if not isinstance(value, str):
        raise AssertionError("validated SQL Server parameter name did not retain its string type")
    if not value:
        raise MssqlLoweringError(f"{context} must not be empty")
    utf16_units = len(value.encode("utf-16-le")) // 2
    if utf16_units > 128:
        raise MssqlLoweringError(f"{context} exceeds the SQL Server 128-character limit")


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


def _validate_int64(value: object, context: str) -> None:
    if type(value) is not int or not -(1 << 63) <= value <= (1 << 63) - 1:
        raise MssqlLoweringError(f"{context} must be a signed 64-bit integer")
