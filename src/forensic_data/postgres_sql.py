from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from typing import cast, final
from uuid import UUID

from psycopg import sql

from forensic_data.canonical.codec import decode_payload
from forensic_data.canonical.model import (
    INT64_MAX,
    CanonicalizationError,
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
MAX_COMPILED_RELATION_MEMBERS = 1_600


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


type PostgresParameter = str | int | bytes


@final
@dataclass(frozen=True, slots=True)
class PostgresScopePredicate:
    field: FieldSchema
    column_name: str
    canonical_payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.field), FieldSchema):
            raise PostgresLoweringError("PostgreSQL scope field must be a FieldSchema")
        if self.field.nullable:
            raise PostgresLoweringError("PostgreSQL scope field must be non-nullable")
        _validate_identifier_text(self.column_name, "PostgreSQL scope column")
        if type(self.canonical_payload) is not bytes:
            raise PostgresLoweringError("PostgreSQL scope canonical payload must be bytes")
        try:
            decode_payload(self.field, self.canonical_payload)
        except CanonicalizationError as error:
            raise PostgresLoweringError(
                "PostgreSQL scope canonical payload does not match its logical field: "
                f"reason_type={type(error).__name__}"
            ) from None


@final
@dataclass(frozen=True, slots=True)
class PostgresIntegerRangeRequest:
    segment_id: str
    lower_inclusive: int
    upper_exclusive: int | None

    def __post_init__(self) -> None:
        _validate_scalar_text(self.segment_id, "PostgreSQL integer-range segment ID")
        _validate_int64(self.lower_inclusive, "PostgreSQL integer-range lower bound")
        if self.upper_exclusive is not None:
            _validate_int64(self.upper_exclusive, "PostgreSQL integer-range upper bound")
            if self.upper_exclusive <= self.lower_inclusive:
                raise PostgresLoweringError(
                    "PostgreSQL integer-range upper bound must be greater than its lower bound"
                )


@final
@dataclass(frozen=True, slots=True)
class PostgresQueryRelation:
    inspection: PostgresInspectedRelation
    contributes_rows: bool

    def __post_init__(self) -> None:
        _require_inspected_relation(self.inspection)
        _require_boolean(
            self.contributes_rows,
            "PostgreSQL query relation contributes_rows",
        )


@final
@dataclass(frozen=True, slots=True)
class PostgresQuery:
    statement: sql.SQL | sql.Composed
    parameters: tuple[PostgresParameter, ...]
    context: CanonicalEnvelopeContext
    relations: tuple[PostgresQueryRelation, ...]
    max_encoded_envelope_bytes: int

    def __post_init__(self) -> None:
        _require_query_statement(self.statement)
        _require_query_parameters(self.parameters)
        _require_envelope_context(self.context)
        _require_query_relations(self.relations)
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


@final
@dataclass(frozen=True, slots=True)
class _IntegerKeyLowering:
    column: sql.Identifier
    is_valid: sql.Composable
    envelope: sql.Composable


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


def _single_query_relation(
    inspection: PostgresInspectedRelation,
) -> tuple[PostgresQueryRelation, ...]:
    return (PostgresQueryRelation(inspection=inspection, contributes_rows=True),)


def _validate_query_relations_for_schema(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
) -> None:
    _require_query_relations(relations)
    for relation in relations:
        validate_postgres_inspection(schema, relation.inspection)


def _origin_type_branch_projections(
    relations: tuple[PostgresQueryRelation, ...],
    branch_index: int,
    source_alias: str,
) -> sql.Composable:
    projections: list[sql.Composable] = []
    for index, _relation in enumerate(relations):
        column_alias = "origin_type" if index == 0 else f"origin_type_{index}"
        if index == branch_index:
            expression = sql.SQL("(pg_catalog.pg_typeof(({source_alias}.*)))::oid::bigint").format(
                source_alias=sql.Identifier(source_alias)
            )
        else:
            expression = sql.SQL("NULL::bigint")
        projections.append(
            sql.SQL("{expression} AS {column_alias}").format(
                expression=expression,
                column_alias=sql.Identifier(column_alias),
            )
        )
    return sql.SQL(", ").join(projections)


def _origin_type_columns(
    relations: tuple[PostgresQueryRelation, ...],
    source_alias: str,
) -> sql.Composable:
    return sql.SQL(", ").join(
        sql.SQL("{source_alias}.{column_alias}").format(
            source_alias=sql.Identifier(source_alias),
            column_alias=sql.Identifier("origin_type" if index == 0 else f"origin_type_{index}"),
        )
        for index, _ in enumerate(relations)
    )


def _aggregate_origin_type_projections(
    relations: tuple[PostgresQueryRelation, ...],
    source_alias: str,
) -> sql.Composable:
    return sql.SQL(", ").join(
        sql.SQL("max({source_alias}.{column_alias})::bigint AS {column_alias}").format(
            source_alias=sql.Identifier(source_alias),
            column_alias=sql.Identifier("origin_type" if index == 0 else f"origin_type_{index}"),
        )
        for index, _ in enumerate(relations)
    )


def _window_origin_type_projections(
    relations: tuple[PostgresQueryRelation, ...],
    source_alias: str,
) -> sql.Composable:
    return sql.SQL(", ").join(
        sql.SQL("(max({source_alias}.{column_alias}) OVER ())::bigint AS {column_alias}").format(
            source_alias=sql.Identifier(source_alias),
            column_alias=sql.Identifier("origin_type" if index == 0 else f"origin_type_{index}"),
        )
        for index, _ in enumerate(relations)
    )


def _aggregate_origin_type_branch_projections(
    relations: tuple[PostgresQueryRelation, ...],
    branch_index: int,
    source_alias: str,
) -> sql.Composable:
    projections: list[sql.Composable] = []
    for index, _relation in enumerate(relations):
        column_alias = "origin_type" if index == 0 else f"origin_type_{index}"
        if index == branch_index:
            expression = sql.SQL(
                "(pg_catalog.pg_typeof((pg_catalog.array_agg(({source_alias}.*)) "
                "FILTER (WHERE FALSE))[1]))::oid::bigint"
            ).format(source_alias=sql.Identifier(source_alias))
        else:
            expression = sql.SQL("NULL::bigint")
        projections.append(
            sql.SQL("{expression} AS {column_alias}").format(
                expression=expression,
                column_alias=sql.Identifier(column_alias),
            )
        )
    return sql.SQL(", ").join(projections)


def _contribution_filter(relation: PostgresQueryRelation) -> sql.SQL:
    return sql.SQL("TRUE") if relation.contributes_rows else sql.SQL("FALSE")


def build_postgres_row_envelope_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_union_row_envelope_query(
        schema,
        _single_query_relation(inspection),
        max_encoded_envelope_bytes,
    )


def build_postgres_legacy_row_envelope_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_legacy_union_row_envelope_query(
        schema,
        _single_query_relation(inspection),
        max_encoded_envelope_bytes,
    )


def build_postgres_union_row_envelope_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return _build_postgres_row_envelope_query(
        schema,
        relations,
        max_encoded_envelope_bytes,
        _postgres_17_digest_expression,
    )


def build_postgres_legacy_union_row_envelope_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return _build_postgres_row_envelope_query(
        schema,
        relations,
        max_encoded_envelope_bytes,
        _postgres_9_6_digest_expression,
    )


def _build_postgres_row_envelope_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    max_encoded_envelope_bytes: int,
    digest_expression: Callable[[sql.Composable], sql.Composable],
) -> PostgresQuery:
    _validate_query_relations_for_schema(schema, relations)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "PostgreSQL max encoded envelope byte length",
        INT64_MAX,
    )
    context = prepare_envelope_context(schema)
    branches: list[sql.Composable] = []
    parameters: list[PostgresParameter] = []
    for index, relation in enumerate(relations):
        source_alias = f"dfe_origin_{index}"
        row = _row_lowering_for_alias(
            schema,
            relation.inspection.bindings,
            max_encoded_envelope_bytes,
            source_alias,
        )
        branches.append(
            sql.SQL(
                "SELECT {origin_types}, {envelope} AS envelope, "
                "{invalid_row} AS invalid_row, "
                "{oversized_row} AS oversized_row, "
                "{source_alias}.tableoid IS NOT NULL AS has_data "
                "FROM (VALUES (TRUE)) AS dfe_seed(seed) "
                "LEFT JOIN ONLY {relation} AS {source_alias} ON {contributes_rows}"
            ).format(
                origin_types=_origin_type_branch_projections(
                    relations,
                    index,
                    source_alias,
                ),
                envelope=row.envelope,
                invalid_row=row.invalid_row,
                oversized_row=row.oversized_row,
                relation=sql.Identifier(*relation.inspection.relation.components),
                source_alias=sql.Identifier(source_alias),
                contributes_rows=_contribution_filter(relation),
            )
        )
        parameters.extend((context.schema_digest_hex, len(context.schema.fields)))
    statement = sql.SQL(
        "SELECT {origin_types}, dfe_source.has_data, "
        "CASE WHEN dfe_source.has_data THEN dfe_source.envelope "
        "ELSE NULL::text END AS envelope, "
        "CASE WHEN dfe_source.has_data THEN {row_hash} "
        "ELSE NULL::bytea END AS row_hash, "
        "CASE WHEN dfe_source.has_data THEN dfe_source.invalid_row "
        "ELSE NULL::boolean END AS invalid_row, "
        "CASE WHEN dfe_source.has_data THEN dfe_source.oversized_row "
        "ELSE NULL::boolean END AS oversized_row "
        "FROM ({source_branches}) AS dfe_source"
    ).format(
        source_branches=sql.SQL(" UNION ALL ").join(branches),
        origin_types=_origin_type_columns(relations, "dfe_source"),
        row_hash=digest_expression(sql.SQL("dfe_source.envelope")),
    )
    return PostgresQuery(
        statement=statement,
        parameters=tuple(parameters),
        context=context,
        relations=relations,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def build_postgres_fingerprint_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_union_fingerprint_query(
        schema,
        _single_query_relation(inspection),
        max_encoded_envelope_bytes,
    )


def build_postgres_union_fingerprint_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return _build_postgres_fingerprint_query(
        schema,
        relations,
        max_encoded_envelope_bytes,
        _postgres_17_digest_expression,
    )


def build_postgres_legacy_fingerprint_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_legacy_union_fingerprint_query(
        schema,
        _single_query_relation(inspection),
        max_encoded_envelope_bytes,
    )


def build_postgres_legacy_union_fingerprint_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return _build_postgres_fingerprint_query(
        schema,
        relations,
        max_encoded_envelope_bytes,
        _postgres_9_6_digest_expression,
    )


def _build_postgres_fingerprint_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    max_encoded_envelope_bytes: int,
    digest_expression: Callable[[sql.Composable], sql.Composable],
) -> PostgresQuery:
    _validate_query_relations_for_schema(schema, relations)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "PostgreSQL max encoded envelope byte length",
        INT64_MAX,
    )
    context = prepare_envelope_context(schema)
    branches: list[sql.Composable] = []
    parameters: list[PostgresParameter] = []
    for index, relation in enumerate(relations):
        source_alias = f"dfe_origin_{index}"
        row = _row_lowering_for_alias(
            schema,
            relation.inspection.bindings,
            max_encoded_envelope_bytes,
            source_alias,
        )
        branch_limb_sums = sql.SQL(", ").join(
            _limb_sum_expression(limb_index) for limb_index in range(8)
        )
        branches.append(
            sql.SQL(
                "SELECT {origin_types}, "
                "count(*) FILTER (WHERE NOT dfe_row.invalid_row "
                "AND NOT dfe_row.oversized_row)::text AS valid_row_count, "
                "{limb_sums}, "
                "count(*) FILTER (WHERE dfe_row.invalid_row)::text AS invalid_row_count, "
                "count(*) FILTER (WHERE dfe_row.oversized_row)::text "
                "AS oversized_row_count "
                "FROM ONLY {relation} AS {source_alias} "
                "CROSS JOIN LATERAL (SELECT {envelope} AS envelope, "
                "{invalid_row} AS invalid_row, {oversized_row} AS oversized_row "
                "OFFSET 0) AS dfe_row "
                "CROSS JOIN LATERAL (SELECT {row_hash} AS row_hash OFFSET 0) AS dfe_hash "
                "WHERE {contributes_rows}"
            ).format(
                origin_types=_aggregate_origin_type_branch_projections(
                    relations,
                    index,
                    source_alias,
                ),
                envelope=row.envelope,
                invalid_row=row.invalid_row,
                oversized_row=row.oversized_row,
                relation=sql.Identifier(*relation.inspection.relation.components),
                source_alias=sql.Identifier(source_alias),
                contributes_rows=_contribution_filter(relation),
                row_hash=digest_expression(sql.SQL("dfe_row.envelope")),
                limb_sums=branch_limb_sums,
            )
        )
        parameters.extend((context.schema_digest_hex, len(context.schema.fields)))
    combined_limb_sums = sql.SQL(", ").join(
        sql.SQL(
            "coalesce(sum((dfe_member.{column})::numeric), 0::numeric)::text AS {column}"
        ).format(column=sql.Identifier(f"limb_{index}"))
        for index in range(8)
    )
    statement = sql.SQL(
        "SELECT {origin_types}, "
        "sum((dfe_member.valid_row_count)::numeric)::text AS valid_row_count, "
        "{limb_sums}, "
        "sum((dfe_member.invalid_row_count)::numeric)::text AS invalid_row_count, "
        "sum((dfe_member.oversized_row_count)::numeric)::text AS oversized_row_count "
        "FROM ({source_branches}) AS dfe_member"
    ).format(
        source_branches=sql.SQL(" UNION ALL ").join(branches),
        origin_types=_aggregate_origin_type_projections(relations, "dfe_member"),
        limb_sums=combined_limb_sums,
    )
    return PostgresQuery(
        statement=statement,
        parameters=tuple(parameters),
        context=context,
        relations=relations,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def build_postgres_integer_key_summary_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_union_integer_key_summary_query(
        schema,
        _single_query_relation(inspection),
        key_field_index,
        scope,
        max_encoded_envelope_bytes,
    )


def build_postgres_legacy_integer_key_summary_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_legacy_union_integer_key_summary_query(
        schema,
        _single_query_relation(inspection),
        key_field_index,
        scope,
        max_encoded_envelope_bytes,
    )


def build_postgres_union_integer_key_summary_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return _build_postgres_integer_key_summary_query(
        schema,
        relations,
        key_field_index,
        scope,
        max_encoded_envelope_bytes,
        _usable_integer_key_access_path,
    )


def build_postgres_legacy_union_integer_key_summary_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return _build_postgres_integer_key_summary_query(
        schema,
        relations,
        key_field_index,
        scope,
        max_encoded_envelope_bytes,
        _usable_legacy_integer_key_access_path,
    )


def _build_postgres_integer_key_summary_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    max_encoded_envelope_bytes: int,
    access_path_expression: Callable[[PostgresInspectedRelation, str], sql.Composable],
) -> PostgresQuery:
    _validate_query_relations_for_schema(schema, relations)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "PostgreSQL max encoded envelope byte length",
        INT64_MAX,
    )
    branches: list[sql.Composable] = []
    parameters: list[PostgresParameter] = []
    access_paths: list[sql.Composable] = []
    for index, relation in enumerate(relations):
        inspection = relation.inspection
        source_alias = f"dfe_origin_{index}"
        key = _integer_key_lowering(schema, inspection, key_field_index, source_alias)
        scope_filter, scope_parameters = _scope_filter(inspection, scope, source_alias)
        branches.append(
            sql.SQL(
                "SELECT {origin_types}, ({key_column})::numeric AS key_value, "
                "{key_column} IS NULL AS null_key, "
                "{key_column} IS NOT NULL AND NOT ({key_valid}) AS invalid_key, "
                "{key_column} IS NOT NULL AND ({key_valid}) AS valid_key, "
                "{source_alias}.tableoid IS NOT NULL AS has_data "
                "FROM (VALUES (TRUE)) AS dfe_seed(seed) "
                "LEFT JOIN ONLY {relation} AS {source_alias} ON "
                "({scope_filter}) AND {contributes_rows}"
            ).format(
                origin_types=_origin_type_branch_projections(
                    relations,
                    index,
                    source_alias,
                ),
                key_column=key.column,
                key_valid=key.is_valid,
                relation=sql.Identifier(*inspection.relation.components),
                source_alias=sql.Identifier(source_alias),
                scope_filter=scope_filter,
                contributes_rows=_contribution_filter(relation),
            )
        )
        parameters.extend(scope_parameters)
        if relation.contributes_rows:
            access_paths.append(
                access_path_expression(
                    inspection,
                    inspection.bindings[key_field_index].column_name,
                )
            )
    usable_access_path = sql.SQL(" AND ").join(access_paths) if access_paths else sql.SQL("TRUE")
    statement = sql.SQL(
        "SELECT {origin_types}, "
        "count(*) FILTER (WHERE dfe_source.has_data)::text AS row_count, "
        "count(*) FILTER (WHERE dfe_source.has_data AND dfe_source.null_key)::text "
        "AS null_key_count, "
        "count(*) FILTER (WHERE dfe_source.has_data AND dfe_source.invalid_key)::text "
        "AS invalid_key_count, "
        "count(*) FILTER (WHERE dfe_source.has_data AND dfe_source.valid_key)::text "
        "AS valid_key_count, "
        "count(DISTINCT dfe_source.key_value) FILTER "
        "(WHERE dfe_source.has_data AND dfe_source.valid_key)::text "
        "AS distinct_key_count, "
        "(min(dfe_source.key_value) FILTER "
        "(WHERE dfe_source.has_data AND dfe_source.valid_key))::bigint::text "
        "AS minimum_key, "
        "(max(dfe_source.key_value) FILTER "
        "(WHERE dfe_source.has_data AND dfe_source.valid_key))::bigint::text "
        "AS maximum_key, "
        "{usable_access_path} AS usable_access_path "
        "FROM ({source_branches}) AS dfe_source"
    ).format(
        source_branches=sql.SQL(" UNION ALL ").join(branches),
        origin_types=_aggregate_origin_type_projections(relations, "dfe_source"),
        usable_access_path=usable_access_path,
    )
    return PostgresQuery(
        statement=statement,
        parameters=tuple(parameters),
        context=prepare_envelope_context(schema),
        relations=relations,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def build_postgres_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_union_integer_range_fingerprint_query(
        schema,
        _single_query_relation(inspection),
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
    )


def build_postgres_legacy_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_legacy_union_integer_range_fingerprint_query(
        schema,
        _single_query_relation(inspection),
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
    )


def build_postgres_union_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return _build_postgres_integer_range_fingerprint_query(
        schema,
        relations,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
        _postgres_17_digest_expression,
    )


def build_postgres_legacy_union_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return _build_postgres_integer_range_fingerprint_query(
        schema,
        relations,
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
        _postgres_9_6_digest_expression,
    )


def _build_postgres_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
    digest_expression: Callable[[sql.Composable], sql.Composable],
) -> PostgresQuery:
    _validate_query_relations_for_schema(schema, relations)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "PostgreSQL max encoded envelope byte length",
        INT64_MAX,
    )
    _validate_integer_ranges(ranges)
    context = prepare_envelope_context(schema)
    branches: list[sql.Composable] = []
    parameters: list[PostgresParameter] = []
    for index, relation in enumerate(relations):
        inspection = relation.inspection
        source_alias = f"dfe_origin_{index}"
        row = _row_lowering_for_alias(
            schema,
            inspection.bindings,
            max_encoded_envelope_bytes,
            source_alias,
        )
        key = _integer_key_lowering(schema, inspection, key_field_index, source_alias)
        scope_filter, scope_parameters = _scope_filter(inspection, scope, source_alias)
        branch_limb_sums = sql.SQL(", ").join(
            _limb_sum_expression(limb_index) for limb_index in range(8)
        )
        branches.append(
            sql.SQL(
                "SELECT {origin_types}, dfe_range.segment_id, dfe_range.ordinal, "
                "dfe_member.valid_row_count, {member_limbs}, "
                "dfe_member.invalid_row_count, dfe_member.oversized_row_count, "
                "dfe_member.row_envelope_bytes, dfe_member.key_envelope_bytes "
                "FROM dfe_ranges AS dfe_range CROSS JOIN LATERAL ("
                "SELECT {aggregate_origin_types}, "
                "count(*) FILTER (WHERE NOT dfe_row.invalid_row "
                "AND NOT dfe_row.oversized_row)::text AS valid_row_count, "
                "{branch_limb_sums}, "
                "count(*) FILTER (WHERE dfe_row.invalid_row)::text AS invalid_row_count, "
                "count(*) FILTER (WHERE dfe_row.oversized_row)::text "
                "AS oversized_row_count, "
                "coalesce(sum(octet_length(dfe_row.row_envelope)) FILTER "
                "(WHERE NOT dfe_row.invalid_row AND NOT dfe_row.oversized_row), "
                "0::numeric)::text AS row_envelope_bytes, "
                "coalesce(sum(octet_length(dfe_row.key_envelope)) FILTER "
                "(WHERE NOT dfe_row.invalid_row AND NOT dfe_row.oversized_row), "
                "0::numeric)::text AS key_envelope_bytes "
                "FROM ONLY {relation} AS {source_alias} "
                "CROSS JOIN LATERAL (SELECT {row_envelope} AS row_envelope, "
                "{key_envelope} AS key_envelope, {invalid_row} AS invalid_row, "
                "{oversized_row} AS oversized_row OFFSET 0) AS dfe_row "
                "CROSS JOIN LATERAL (SELECT {row_hash} AS row_hash OFFSET 0) AS dfe_hash "
                "WHERE ({scope_filter}) AND {contributes_rows} "
                "AND {key_column} IS NOT NULL AND ({key_valid}) "
                "AND {key_column} >= dfe_range.lower_inclusive "
                "AND (dfe_range.upper_exclusive IS NULL "
                "OR {key_column} < dfe_range.upper_exclusive)"
                ") AS dfe_member"
            ).format(
                origin_types=_origin_type_columns(relations, "dfe_member"),
                aggregate_origin_types=_aggregate_origin_type_branch_projections(
                    relations,
                    index,
                    source_alias,
                ),
                member_limbs=sql.SQL(", ").join(
                    sql.Identifier("dfe_member", f"limb_{limb_index}") for limb_index in range(8)
                ),
                branch_limb_sums=branch_limb_sums,
                key_column=key.column,
                row_envelope=row.envelope,
                key_envelope=key.envelope,
                invalid_row=row.invalid_row,
                oversized_row=row.oversized_row,
                relation=sql.Identifier(*inspection.relation.components),
                source_alias=sql.Identifier(source_alias),
                scope_filter=scope_filter,
                contributes_rows=_contribution_filter(relation),
                key_valid=key.is_valid,
                row_hash=digest_expression(sql.SQL("dfe_row.row_envelope")),
            )
        )
        parameters.extend((context.schema_digest_hex, len(context.schema.fields)))
        parameters.extend(scope_parameters)
    ranges_values = _integer_range_values(ranges)
    combined_limb_sums = sql.SQL(", ").join(
        sql.SQL(
            "coalesce(sum((dfe_member.{column})::numeric), 0::numeric)::text AS {column}"
        ).format(column=sql.Identifier(f"limb_{index}"))
        for index in range(8)
    )
    statement = sql.SQL(
        "WITH dfe_ranges(segment_id, lower_inclusive, upper_exclusive, ordinal) AS ("
        "VALUES {ranges_values}"
        ") SELECT {origin_types}, dfe_member.segment_id, "
        "coalesce(sum((dfe_member.valid_row_count)::numeric), 0::numeric)::text "
        "AS valid_row_count, {limb_sums}, "
        "coalesce(sum((dfe_member.invalid_row_count)::numeric), 0::numeric)::text "
        "AS invalid_row_count, "
        "coalesce(sum((dfe_member.oversized_row_count)::numeric), 0::numeric)::text "
        "AS oversized_row_count, "
        "coalesce(sum((dfe_member.row_envelope_bytes)::numeric), 0::numeric)::text "
        "AS row_envelope_bytes, "
        "coalesce(sum((dfe_member.key_envelope_bytes)::numeric), 0::numeric)::text "
        "AS key_envelope_bytes "
        "FROM ({source_branches}) AS dfe_member "
        "GROUP BY dfe_member.ordinal, dfe_member.segment_id "
        "ORDER BY dfe_member.ordinal"
    ).format(
        source_branches=sql.SQL(" UNION ALL ").join(branches),
        ranges_values=ranges_values,
        origin_types=_aggregate_origin_type_projections(relations, "dfe_member"),
        limb_sums=combined_limb_sums,
    )
    return PostgresQuery(
        statement=statement,
        parameters=tuple(parameters),
        context=context,
        relations=relations,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def _postgres_17_digest_expression(envelope: sql.Composable) -> sql.Composable:
    return sql.SQL(
        "CASE WHEN {envelope} IS NULL THEN NULL::bytea "
        "ELSE sha256(convert_to({envelope}, 'UTF8')) END"
    ).format(envelope=envelope)


def _postgres_9_6_digest_expression(envelope: sql.Composable) -> sql.Composable:
    return sql.SQL(
        "CASE WHEN {envelope} IS NULL THEN NULL::bytea "
        "ELSE dfe_ext.digest(convert_to({envelope}, 'UTF8'), 'sha256') END"
    ).format(envelope=envelope)


def build_postgres_integer_range_rows_query(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    return build_postgres_union_integer_range_rows_query(
        schema,
        _single_query_relation(inspection),
        key_field_index,
        scope,
        ranges,
        max_encoded_envelope_bytes,
    )


def build_postgres_union_integer_range_rows_query(
    schema: CanonicalSchema,
    relations: tuple[PostgresQueryRelation, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> PostgresQuery:
    _validate_query_relations_for_schema(schema, relations)
    _validate_positive_integer(
        max_encoded_envelope_bytes,
        "PostgreSQL max encoded envelope byte length",
        INT64_MAX,
    )
    _validate_integer_ranges(ranges)
    context = prepare_envelope_context(schema)
    branches: list[sql.Composable] = []
    parameters: list[PostgresParameter] = []
    for index, relation in enumerate(relations):
        inspection = relation.inspection
        source_alias = f"dfe_origin_{index}"
        row = _row_lowering_for_alias(
            schema,
            inspection.bindings,
            max_encoded_envelope_bytes,
            source_alias,
        )
        key = _integer_key_lowering(schema, inspection, key_field_index, source_alias)
        scope_filter, scope_parameters = _scope_filter(inspection, scope, source_alias)
        branches.append(
            sql.SQL(
                "SELECT {origin_types}, dfe_range.segment_id, dfe_range.ordinal, "
                "{branch_ordinal}::integer AS branch_ordinal, "
                "({key_column})::bigint AS key_value, {key_envelope} AS key_envelope, "
                "{row_envelope} AS row_envelope, "
                "{invalid_row} AS invalid_row, {oversized_row} AS oversized_row, "
                "{source_alias}.tableoid IS NOT NULL AS has_data "
                "FROM dfe_ranges AS dfe_range LEFT JOIN ONLY {relation} AS {source_alias} ON "
                "({scope_filter}) AND {contributes_rows} "
                "AND {key_column} IS NOT NULL AND ({key_valid}) "
                "AND {key_column} >= dfe_range.lower_inclusive "
                "AND (dfe_range.upper_exclusive IS NULL "
                "OR {key_column} < dfe_range.upper_exclusive)"
            ).format(
                origin_types=_origin_type_branch_projections(
                    relations,
                    index,
                    source_alias,
                ),
                branch_ordinal=sql.Literal(index),
                key_column=key.column,
                key_envelope=key.envelope,
                row_envelope=row.envelope,
                invalid_row=row.invalid_row,
                oversized_row=row.oversized_row,
                relation=sql.Identifier(*inspection.relation.components),
                source_alias=sql.Identifier(source_alias),
                scope_filter=scope_filter,
                contributes_rows=_contribution_filter(relation),
                key_valid=key.is_valid,
            )
        )
        parameters.extend((context.schema_digest_hex, len(context.schema.fields)))
        parameters.extend(scope_parameters)
    statement = sql.SQL(
        "WITH dfe_ranges(segment_id, lower_inclusive, upper_exclusive, ordinal) AS ("
        "VALUES {ranges_values}"
        ") SELECT {origin_types}, dfe_provenance.has_data, "
        "CASE WHEN dfe_provenance.has_data THEN dfe_provenance.segment_id "
        "ELSE NULL::text END AS segment_id, "
        "CASE WHEN dfe_provenance.has_data THEN dfe_provenance.key_envelope "
        "ELSE NULL::text END AS key_envelope, "
        "CASE WHEN dfe_provenance.has_data THEN dfe_provenance.row_envelope "
        "ELSE NULL::text END AS row_envelope, "
        "CASE WHEN dfe_provenance.has_data THEN dfe_provenance.invalid_row "
        "ELSE NULL::boolean END AS invalid_row, "
        "CASE WHEN dfe_provenance.has_data THEN dfe_provenance.oversized_row "
        "ELSE NULL::boolean END AS oversized_row FROM ("
        "SELECT {window_origin_types}, dfe_source.segment_id, dfe_source.ordinal, "
        "dfe_source.branch_ordinal, dfe_source.key_value, dfe_source.key_envelope, "
        "dfe_source.row_envelope, dfe_source.invalid_row, "
        "dfe_source.oversized_row, dfe_source.has_data, "
        "count(*) FILTER (WHERE dfe_source.has_data) OVER () AS data_count, "
        "row_number() OVER (ORDER BY dfe_source.ordinal, "
        "dfe_source.branch_ordinal) AS witness_ordinal "
        "FROM ({source_branches}) AS dfe_source"
        ") AS dfe_provenance WHERE dfe_provenance.has_data "
        "OR (dfe_provenance.data_count = 0 AND dfe_provenance.witness_ordinal = 1) "
        "ORDER BY dfe_provenance.ordinal, dfe_provenance.key_value"
    ).format(
        source_branches=sql.SQL(" UNION ALL ").join(branches),
        ranges_values=_integer_range_values(ranges),
        origin_types=_origin_type_columns(relations, "dfe_provenance"),
        window_origin_types=_window_origin_type_projections(relations, "dfe_source"),
    )
    return PostgresQuery(
        statement=statement,
        parameters=tuple(parameters),
        context=context,
        relations=relations,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def _integer_key_lowering(
    schema: CanonicalSchema,
    inspection: PostgresInspectedRelation,
    key_field_index: int,
    source_alias: str,
) -> _IntegerKeyLowering:
    _validate_key_field_index(schema, key_field_index)
    field = schema.fields[key_field_index]
    binding = inspection.bindings[key_field_index]
    _validate_identifier_text(source_alias, "PostgreSQL source alias")
    column = sql.Identifier(source_alias, binding.column_name)
    payload = _int64_payload(column)
    frame = _field_lowering(field, column)
    key_schema = CanonicalSchema(protocol=schema.protocol, fields=(field,))
    key_context = prepare_envelope_context(key_schema)
    envelope = sql.SQL("{header} || {frame}").format(
        header=sql.Literal(key_context.key_header),
        frame=frame.frame,
    )
    return _IntegerKeyLowering(
        column=column,
        is_valid=payload.is_valid,
        envelope=envelope,
    )


def _scope_filter(
    inspection: PostgresInspectedRelation,
    scope: PostgresScopePredicate | None,
    source_alias: str,
) -> tuple[sql.Composable, tuple[PostgresParameter, ...]]:
    _validate_identifier_text(source_alias, "PostgreSQL source alias")
    if scope is None:
        return sql.SQL("TRUE"), ()
    if not isinstance(cast(object, scope), PostgresScopePredicate):
        raise PostgresLoweringError("PostgreSQL scope must be a PostgresScopePredicate or None")
    matches = tuple(
        (index, binding)
        for index, binding in enumerate(inspection.bindings)
        if binding.column_name == scope.column_name
    )
    if len(matches) != 1:
        raise PostgresLoweringError(
            "PostgreSQL scoped comparison requires the scope column to map to exactly one "
            "inspected projection field: "
            f"column={scope.column_name!r}, matching_fields={len(matches)}"
        )
    field_index, binding = matches[0]
    _validate_physical_mapping(scope.field, binding.physical, field_index)
    column = sql.Identifier(source_alias, scope.column_name)
    payload = _payload_lowering(scope.field, column)
    decoded = decode_payload(scope.field, scope.canonical_payload)
    native_comparison = _native_scope_comparison(scope.field, column, decoded)
    if native_comparison is not None:
        native_predicate, parameter = native_comparison
        predicate = sql.SQL(
            "{column} IS NOT NULL AND ({is_valid}) AND ({native_predicate})"
        ).format(
            column=column,
            is_valid=payload.is_valid,
            native_predicate=native_predicate,
        )
        return predicate, (parameter,)
    predicate = sql.SQL("{column} IS NOT NULL AND ({is_valid}) AND ({payload}) = %s::bytea").format(
        column=column,
        is_valid=payload.is_valid,
        payload=payload.payload,
    )
    return predicate, (scope.canonical_payload,)


def _native_scope_comparison(
    field: FieldSchema,
    column: sql.Identifier,
    value: object,
) -> tuple[sql.Composable, PostgresParameter] | None:
    logical_type = field.logical_type
    if logical_type is LogicalType.INT64:
        if type(value) is not int:
            raise PostgresLoweringError("decoded INT64 scope value must be an integer")
        return sql.SQL("{column} = %s::bigint").format(column=column), value
    if logical_type is LogicalType.DECIMAL:
        return sql.SQL("({column})::numeric = %s::numeric").format(column=column), str(value)
    if logical_type is LogicalType.BOOLEAN:
        if type(value) is not bool:
            raise PostgresLoweringError("decoded boolean scope value must be a boolean")
        return (
            sql.SQL("{column} = %s::boolean").format(column=column),
            "true" if value else "false",
        )
    if logical_type is LogicalType.DATE:
        if type(value) is not date:
            raise PostgresLoweringError("decoded date scope value must be a date")
        return sql.SQL("{column} = %s::date").format(column=column), value.isoformat()
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        if type(value) is not str:
            raise PostgresLoweringError(
                "decoded timestamp_local scope value must be canonical text"
            )
        return sql.SQL("{column} = %s::timestamp").format(column=column), value
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        if type(value) is not str:
            raise PostgresLoweringError(
                "decoded timestamp_instant scope value must be canonical text"
            )
        return sql.SQL("{column} = %s::timestamptz").format(column=column), value
    if logical_type is LogicalType.STRING:
        return None
    raise PostgresLoweringError(
        f"logical type {logical_type!r} is unsupported for PostgreSQL scope equality"
    )


def _integer_range_values(
    ranges: tuple[PostgresIntegerRangeRequest, ...],
) -> sql.Composable:
    values: list[sql.Composable] = []
    for ordinal, item in enumerate(ranges):
        upper = (
            sql.SQL("NULL::bigint")
            if item.upper_exclusive is None
            else sql.SQL("{value}::bigint").format(value=sql.Literal(item.upper_exclusive))
        )
        values.append(
            sql.SQL("({segment_id}, {lower}::bigint, {upper}, {ordinal}::integer)").format(
                segment_id=sql.Literal(item.segment_id),
                lower=sql.Literal(item.lower_inclusive),
                upper=upper,
                ordinal=sql.Literal(ordinal),
            )
        )
    return sql.SQL(", ").join(values)


def _usable_integer_key_access_path(
    inspection: PostgresInspectedRelation,
    key_column_name: str,
) -> sql.Composable:
    return _usable_integer_key_access_path_with_count_column(
        inspection,
        key_column_name,
        sql.SQL("indnkeyatts"),
    )


def _usable_legacy_integer_key_access_path(
    inspection: PostgresInspectedRelation,
    key_column_name: str,
) -> sql.Composable:
    return _usable_integer_key_access_path_with_count_column(
        inspection,
        key_column_name,
        sql.SQL("indnatts"),
    )


def _usable_integer_key_access_path_with_count_column(
    inspection: PostgresInspectedRelation,
    key_column_name: str,
    key_attribute_count_column: sql.SQL,
) -> sql.Composable:
    return sql.SQL(
        "EXISTS (SELECT 1 FROM pg_catalog.pg_index AS dfe_index "
        "JOIN pg_catalog.pg_class AS dfe_index_relation "
        "ON dfe_index_relation.oid = dfe_index.indexrelid "
        "JOIN pg_catalog.pg_am AS dfe_access_method "
        "ON dfe_access_method.oid = dfe_index_relation.relam "
        "JOIN pg_catalog.pg_opclass AS dfe_opclass "
        "ON dfe_opclass.oid = dfe_index.indclass[0] "
        "JOIN pg_catalog.pg_namespace AS dfe_opclass_namespace "
        "ON dfe_opclass_namespace.oid = dfe_opclass.opcnamespace "
        "JOIN pg_catalog.pg_attribute AS dfe_key_attribute "
        "ON dfe_key_attribute.attrelid = dfe_index.indrelid "
        "AND dfe_key_attribute.attnum = dfe_index.indkey[0] "
        "WHERE dfe_index.indrelid = {relation_oid}::oid "
        "AND dfe_access_method.amname = 'btree' "
        "AND dfe_opclass_namespace.nspname = 'pg_catalog' "
        "AND dfe_key_attribute.attname = {key_column_name} "
        "AND NOT dfe_key_attribute.attisdropped "
        "AND dfe_index.{key_attribute_count_column} >= 1 "
        "AND dfe_index.indisvalid AND dfe_index.indisready AND dfe_index.indislive "
        "AND dfe_index.indpred IS NULL AND dfe_index.indexprs IS NULL)"
    ).format(
        relation_oid=sql.Literal(inspection.relation_oid),
        key_column_name=sql.Literal(key_column_name),
        key_attribute_count_column=key_attribute_count_column,
    )


def _validate_key_field_index(schema: CanonicalSchema, key_field_index: int) -> None:
    if type(key_field_index) is not int or not 0 <= key_field_index < len(schema.fields):
        raise PostgresLoweringError(
            "PostgreSQL integer-key field index must identify a schema field"
        )
    field = schema.fields[key_field_index]
    if field.logical_type is not LogicalType.INT64 or field.nullable:
        raise PostgresLoweringError(
            "PostgreSQL range comparison requires one non-null logical INT64 key field"
        )


def _validate_integer_ranges(value: object) -> None:
    if type(value) is not tuple or not value:
        raise PostgresLoweringError(
            "PostgreSQL integer-range requests must be a non-empty immutable tuple"
        )
    ranges = cast(tuple[object, ...], value)
    seen_ids: set[str] = set()
    previous_upper: int | None = None
    for index, item in enumerate(ranges):
        if not isinstance(item, PostgresIntegerRangeRequest):
            raise PostgresLoweringError(
                f"PostgreSQL integer-range request has an unexpected type: range_index={index}"
            )
        if item.segment_id in seen_ids:
            raise PostgresLoweringError(
                "PostgreSQL integer-range segment IDs must be unique within a query"
            )
        seen_ids.add(item.segment_id)
        if index > 0:
            if previous_upper is None:
                raise PostgresLoweringError("PostgreSQL unbounded integer range must be last")
            if item.lower_inclusive < previous_upper:
                raise PostgresLoweringError(
                    "PostgreSQL integer ranges must be ordered and disjoint"
                )
        previous_upper = item.upper_exclusive


def _row_lowering_for_alias(
    schema: CanonicalSchema,
    bindings: tuple[PostgresFieldBinding, ...],
    max_encoded_envelope_bytes: int,
    source_alias: str,
) -> _RowLowering:
    _validate_identifier_text(source_alias, "PostgreSQL source alias")
    columns = tuple(sql.Identifier(source_alias, binding.column_name) for binding in bindings)
    return _row_lowering_from_columns(schema, columns, max_encoded_envelope_bytes)


def _row_lowering_from_columns(
    schema: CanonicalSchema,
    columns: tuple[sql.Identifier, ...],
    max_encoded_envelope_bytes: int,
) -> _RowLowering:
    field_lowerings = tuple(
        _field_lowering(field, column) for field, column in zip(schema.fields, columns, strict=True)
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
        "get_byte(dfe_hash.row_hash, {b0})::bigint * 16777216::bigint + "
        "get_byte(dfe_hash.row_hash, {b1})::bigint * 65536::bigint + "
        "get_byte(dfe_hash.row_hash, {b2})::bigint * 256::bigint + "
        "get_byte(dfe_hash.row_hash, {b3})::bigint"
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


def _validate_int64(value: object, context: str) -> None:
    if type(value) is not int or not INT64_MIN <= value <= INT64_MAX:
        raise PostgresLoweringError(f"{context} must be a signed int64 integer")


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


def _require_query_relations(value: object) -> None:
    if type(value) is not tuple or not value:
        raise PostgresLoweringError(
            "PostgreSQL query relations must be a non-empty immutable tuple"
        )
    relations = cast(tuple[object, ...], value)
    if len(relations) > MAX_COMPILED_RELATION_MEMBERS:
        raise PostgresLoweringError(
            "PostgreSQL compiled union exceeds the relation member limit: "
            f"members={len(relations)}, maximum={MAX_COMPILED_RELATION_MEMBERS}"
        )
    context_id: UUID | None = None
    seen_oids: set[int] = set()
    for index, relation in enumerate(relations):
        if not isinstance(relation, PostgresQueryRelation):
            raise PostgresLoweringError(
                "PostgreSQL query relations must contain PostgresQueryRelation values: "
                f"index={index}"
            )
        inspection = relation.inspection
        if context_id is None:
            context_id = inspection.context_id
        elif inspection.context_id != context_id:
            raise PostgresLoweringError(
                "PostgreSQL query relations must belong to one read context"
            )
        if inspection.relation_oid in seen_oids:
            raise PostgresLoweringError(
                "PostgreSQL query relations must not contain duplicate relation OIDs: "
                f"relation_oid={inspection.relation_oid}"
            )
        seen_oids.add(inspection.relation_oid)


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
        if type(parameter) not in (str, int, bytes):
            raise PostgresLoweringError(
                "PostgreSQL query parameter must be an exact string, integer, or bytes value: "
                f"parameter_index={index}"
            )


def _require_envelope_context(value: object) -> None:
    if not isinstance(value, CanonicalEnvelopeContext):
        raise PostgresLoweringError("PostgreSQL query context must be a CanonicalEnvelopeContext")
