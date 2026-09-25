from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import LiteralString, cast, final

from psycopg import sql

from forensic_data.canonical import CanonicalSchema, FieldSchema, LogicalType, decode_payload
from forensic_data.canonical.model import INT64_MAX
from forensic_data.canonical.schema import CanonicalEnvelopeContext, prepare_envelope_context
from forensic_data.greenplum_catalog import GreenplumColumnProbe
from forensic_data.greenplum_sql import GreenplumCanonicalProbeRequest
from forensic_data.postgres_sql import (
    PostgresFieldBinding,
    PostgresIntegerRangeRequest,
    PostgresLoweringError,
    PostgresScopePredicate,
    lower_postgres_canonical_row,
    validate_postgres_field_bindings,
)

INT64_MIN = -(1 << 63)
type OriginalGreenplumEndpointParameter = str | int | bytes


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumEndpointQuery:
    statement: str
    parameters: tuple[OriginalGreenplumEndpointParameter, ...]
    context: CanonicalEnvelopeContext
    relation_row_type_oid: int
    max_encoded_envelope_bytes: int


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumRangeFingerprintQuery:
    statement: str
    parameters: tuple[OriginalGreenplumEndpointParameter, ...]
    context: CanonicalEnvelopeContext
    relation_row_type_oid: int
    max_encoded_envelope_bytes: int
    range: PostgresIntegerRangeRequest
    primary_content_ids: tuple[int, ...]
    plan_request: GreenplumCanonicalProbeRequest


def build_original_greenplum_integer_key_summary_query(
    schema: CanonicalSchema,
    schema_name: str,
    relation_name: str,
    relation_oid: int,
    relation_row_type_oid: int,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    max_encoded_envelope_bytes: int,
) -> OriginalGreenplumEndpointQuery:
    _validate_endpoint_inputs(
        schema,
        bindings,
        max_identifier_utf8_bytes,
        key_field_index,
        max_encoded_envelope_bytes,
    )
    source_alias = "dfe_origin"
    key_column, key_valid = _integer_key(schema, bindings, key_field_index, source_alias)
    scope_filter, scope_parameters = _scope_filter(bindings, scope, source_alias)
    relation = sql.Identifier(schema_name, relation_name)
    statement = sql.SQL(
        "SELECT (pg_catalog.pg_typeof(NULL::{relation}))::oid::bigint AS origin_type, "
        "count(*)::text AS row_count, "
        "count(CASE WHEN {key_column} IS NULL THEN 1 ELSE NULL END)::text "
        "AS null_key_count, count(CASE WHEN {key_column} IS NOT NULL "
        "AND NOT ({key_valid}) THEN 1 ELSE NULL END)::text AS invalid_key_count, "
        "count(CASE WHEN {key_column} IS NOT NULL AND ({key_valid}) "
        "THEN 1 ELSE NULL END)::text AS valid_key_count, "
        "count(DISTINCT CASE WHEN {key_column} IS NOT NULL AND ({key_valid}) "
        "THEN ({key_column})::numeric ELSE NULL END)::text AS distinct_key_count, "
        "(min(CASE WHEN {key_column} IS NOT NULL AND ({key_valid}) "
        "THEN ({key_column})::numeric ELSE NULL END))::bigint::text AS minimum_key, "
        "(max(CASE WHEN {key_column} IS NOT NULL AND ({key_valid}) "
        "THEN ({key_column})::numeric ELSE NULL END))::bigint::text AS maximum_key, "
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
        "AND dfe_key_attribute.attname = {key_name} "
        "AND NOT dfe_key_attribute.attisdropped AND dfe_index.indnatts >= 1 "
        "AND dfe_index.indisvalid AND dfe_index.indisready "
        "AND dfe_index.indpred IS NULL AND dfe_index.indexprs IS NULL) "
        "AS usable_access_path FROM ONLY {relation} AS {source} WHERE {scope_filter}"
    ).format(
        relation=relation,
        key_column=key_column,
        key_valid=key_valid,
        relation_oid=sql.Literal(relation_oid),
        key_name=sql.Literal(bindings[key_field_index].column_name),
        source=sql.Identifier(source_alias),
        scope_filter=scope_filter,
    )
    return OriginalGreenplumEndpointQuery(
        statement=statement.as_string(),
        parameters=scope_parameters,
        context=prepare_envelope_context(schema),
        relation_row_type_oid=relation_row_type_oid,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def build_original_greenplum_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    schema_name: str,
    relation_name: str,
    relation_row_type_oid: int,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    primary_content_ids: tuple[int, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    requested_range: PostgresIntegerRangeRequest,
    max_encoded_envelope_bytes: int,
) -> OriginalGreenplumRangeFingerprintQuery:
    _validate_endpoint_inputs(
        schema,
        bindings,
        max_identifier_utf8_bytes,
        key_field_index,
        max_encoded_envelope_bytes,
    )
    _validate_range(requested_range)
    _validate_primary_content_ids(primary_content_ids)
    context = prepare_envelope_context(schema)
    source_alias = "dfe_origin"
    source = sql.Identifier(source_alias)
    relation = sql.Identifier(schema_name, relation_name)
    row = lower_postgres_canonical_row(
        schema,
        bindings,
        max_identifier_utf8_bytes,
        max_encoded_envelope_bytes,
        source_alias,
    )
    key_column, key_valid = _integer_key(schema, bindings, key_field_index, source_alias)
    key_envelope, key_parameters = _key_envelope(
        schema,
        bindings,
        max_identifier_utf8_bytes,
        max_encoded_envelope_bytes,
        key_field_index,
        source_alias,
    )
    scope_filter, scope_parameters = _scope_filter(bindings, scope, source_alias)
    range_filter = _range_condition(requested_range, key_column)
    source_rows = sql.SQL(
        "SELECT gp_segment_id::integer AS segment_id, "
        "CASE WHEN FALSE THEN ({source}.*) ELSE NULL END AS origin_type_seed, "
        "TRUE AS has_data, {row_envelope} AS row_envelope, "
        "{key_envelope} AS key_envelope, {invalid_row} AS invalid_row, "
        "{oversized_row} AS oversized_row FROM ONLY {relation} AS {source} "
        "WHERE {key_column} IS NOT NULL AND ({key_valid}) "
        "AND ({range_filter}) AND ({scope_filter}) "
        "UNION ALL SELECT gp_segment_id::integer AS segment_id, "
        "NULL AS origin_type_seed, FALSE AS has_data, NULL::text AS row_envelope, "
        "NULL::text AS key_envelope, FALSE AS invalid_row, FALSE AS oversized_row "
        "FROM gp_dist_random('gp_id')"
    ).format(
        source=source,
        row_envelope=row.envelope,
        key_envelope=key_envelope,
        invalid_row=row.invalid_row,
        oversized_row=row.oversized_row,
        relation=relation,
        key_column=key_column,
        key_valid=key_valid,
        range_filter=range_filter,
        scope_filter=scope_filter,
    )
    hashed_rows = sql.SQL(
        "SELECT dfe_row.segment_id, "
        "(pg_catalog.pg_typeof(dfe_row.origin_type_seed))::oid::bigint "
        "AS relation_row_type_oid, dfe_row.has_data, dfe_row.row_envelope, "
        "dfe_row.key_envelope, dfe_row.invalid_row, dfe_row.oversized_row, "
        "CASE WHEN NOT dfe_row.has_data OR dfe_row.row_envelope IS NULL "
        "THEN NULL::bytea ELSE dfe_ext.digest("
        "pg_catalog.convert_to(dfe_row.row_envelope, 'UTF8'), 'sha256'::text) "
        "END AS row_hash FROM dfe_source AS dfe_row"
    )
    segment_aggregate = sql.SQL(
        "SELECT dfe_hash.segment_id, "
        "max(dfe_hash.relation_row_type_oid)::bigint AS relation_row_type_oid, "
        "count(CASE WHEN dfe_hash.has_data AND NOT dfe_hash.invalid_row "
        "AND NOT dfe_hash.oversized_row THEN 1 ELSE NULL END)::numeric "
        "AS valid_row_count, {limb_sums}, "
        "count(CASE WHEN dfe_hash.has_data AND dfe_hash.invalid_row "
        "THEN 1 ELSE NULL END)::numeric AS invalid_row_count, "
        "count(CASE WHEN dfe_hash.has_data AND dfe_hash.oversized_row "
        "THEN 1 ELSE NULL END)::numeric AS oversized_row_count, "
        "coalesce(sum(CASE WHEN dfe_hash.has_data AND NOT dfe_hash.invalid_row "
        "AND NOT dfe_hash.oversized_row THEN octet_length(dfe_hash.row_envelope) "
        "ELSE 0 END)::numeric, 0::numeric) AS row_envelope_bytes, "
        "coalesce(sum(CASE WHEN dfe_hash.has_data AND NOT dfe_hash.invalid_row "
        "AND NOT dfe_hash.oversized_row THEN octet_length(dfe_hash.key_envelope) "
        "ELSE 0 END)::numeric, 0::numeric) AS key_envelope_bytes, "
        "count(CASE WHEN dfe_hash.has_data THEN 1 ELSE NULL END)::numeric "
        "AS source_row_count, count(CASE WHEN NOT dfe_hash.has_data "
        "THEN 1 ELSE NULL END)::numeric AS topology_seed_count "
        "FROM dfe_hashed AS dfe_hash GROUP BY dfe_hash.segment_id"
    ).format(limb_sums=_segment_limb_sums())
    statement = sql.SQL(
        "WITH dfe_source AS ({source_rows}), dfe_hashed AS ({hashed_rows}), "
        "dfe_segment AS ({segment_aggregate}), dfe_member AS ("
        "SELECT dfe_segment.segment_id, dfe_segment.relation_row_type_oid, "
        "dfe_segment.valid_row_count, dfe_segment.limb_0, dfe_segment.limb_1, "
        "dfe_segment.limb_2, dfe_segment.limb_3, dfe_segment.limb_4, "
        "dfe_segment.limb_5, dfe_segment.limb_6, dfe_segment.limb_7, "
        "dfe_segment.invalid_row_count, dfe_segment.oversized_row_count, "
        "dfe_segment.row_envelope_bytes, dfe_segment.key_envelope_bytes, "
        "dfe_segment.source_row_count, dfe_segment.topology_seed_count "
        "FROM dfe_segment) SELECT max(dfe_member.relation_row_type_oid)::bigint "
        "AS relation_row_type_oid, {segment_id}::text AS range_id, "
        "coalesce(sum(dfe_member.valid_row_count::numeric), 0::numeric)::text "
        "AS valid_row_count, {combined_limb_sums}, "
        "coalesce(sum(dfe_member.invalid_row_count::numeric), 0::numeric)::text "
        "AS invalid_row_count, coalesce(sum(dfe_member.oversized_row_count::numeric), "
        "0::numeric)::text AS oversized_row_count, "
        "coalesce(sum(dfe_member.row_envelope_bytes::numeric), 0::numeric)::text "
        "AS row_envelope_bytes, coalesce(sum(dfe_member.key_envelope_bytes::numeric), "
        "0::numeric)::text AS key_envelope_bytes, "
        "coalesce(pg_catalog.array_to_string(pg_catalog.array_agg(CASE WHEN "
        "dfe_member.topology_seed_count = 1::numeric THEN dfe_member.segment_id "
        "ELSE NULL::integer END), ','), '') AS topology_content_ids, "
        "coalesce(pg_catalog.array_to_string(pg_catalog.array_agg(CASE WHEN "
        "dfe_member.source_row_count > 0::numeric THEN dfe_member.segment_id "
        "ELSE NULL::integer END), ','), '') AS observed_content_ids FROM dfe_member"
    ).format(
        source_rows=source_rows,
        hashed_rows=hashed_rows,
        segment_aggregate=segment_aggregate,
        segment_id=sql.Literal(requested_range.segment_id),
        combined_limb_sums=_combined_limb_sums(),
    )
    plan_request = GreenplumCanonicalProbeRequest(
        schema_name=schema_name,
        relation_name=relation_name,
        columns=tuple(
            GreenplumColumnProbe(
                field_name=binding.field_name,
                column_name=binding.column_name,
            )
            for binding in bindings
        ),
        schema=schema,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )
    return OriginalGreenplumRangeFingerprintQuery(
        statement=statement.as_string(),
        parameters=(
            context.schema_digest_hex,
            len(context.schema.fields),
            *key_parameters,
            *scope_parameters,
        ),
        context=context,
        relation_row_type_oid=relation_row_type_oid,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
        range=requested_range,
        primary_content_ids=primary_content_ids,
        plan_request=plan_request,
    )


def build_original_greenplum_integer_range_rows_query(
    schema: CanonicalSchema,
    schema_name: str,
    relation_name: str,
    relation_row_type_oid: int,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> OriginalGreenplumEndpointQuery:
    _validate_endpoint_inputs(
        schema,
        bindings,
        max_identifier_utf8_bytes,
        key_field_index,
        max_encoded_envelope_bytes,
    )
    _validate_ranges(ranges)
    context = prepare_envelope_context(schema)
    source_alias = "dfe_origin"
    relation = sql.Identifier(schema_name, relation_name)
    row = lower_postgres_canonical_row(
        schema,
        bindings,
        max_identifier_utf8_bytes,
        max_encoded_envelope_bytes,
        source_alias,
    )
    key_column, key_valid = _integer_key(schema, bindings, key_field_index, source_alias)
    scope_filter, scope_parameters = _scope_filter(bindings, scope, source_alias)
    statement = sql.SQL(
        "WITH dfe_ranges(segment_id, lower_inclusive, upper_exclusive, ordinal) AS "
        "(VALUES {ranges_values}) SELECT dfe_provenance.origin_type, "
        "dfe_provenance.has_data, CASE WHEN dfe_provenance.has_data THEN "
        "dfe_provenance.segment_id ELSE NULL::text END AS segment_id, "
        "CASE WHEN dfe_provenance.has_data THEN dfe_provenance.key_value "
        "ELSE NULL::bigint END AS key_value, CASE WHEN dfe_provenance.has_data "
        "THEN dfe_provenance.row_envelope ELSE NULL::text END AS row_envelope, "
        "CASE WHEN dfe_provenance.has_data THEN dfe_provenance.invalid_row "
        "ELSE NULL::boolean END AS invalid_row, CASE WHEN dfe_provenance.has_data "
        "THEN dfe_provenance.oversized_row ELSE NULL::boolean END AS oversized_row "
        "FROM (SELECT (pg_catalog.pg_typeof(NULL::{relation}))::oid::bigint "
        "AS origin_type, dfe_origin.tableoid IS NOT NULL AS has_data, "
        "dfe_range.segment_id, dfe_range.ordinal, ({key_column})::bigint AS key_value, "
        "{row_envelope} AS row_envelope, {invalid_row} AS invalid_row, "
        "{oversized_row} AS oversized_row, sum(CASE WHEN dfe_origin.tableoid "
        "IS NOT NULL THEN 1 ELSE 0 END) OVER () AS data_count, "
        "row_number() OVER (ORDER BY dfe_range.ordinal, ({key_column})::bigint "
        "NULLS FIRST) AS witness_ordinal FROM dfe_ranges AS dfe_range "
        "LEFT JOIN ONLY {relation} AS dfe_origin ON ({scope_filter}) "
        "AND {key_column} IS NOT NULL AND ({key_valid}) "
        "AND {key_column} >= dfe_range.lower_inclusive "
        "AND (dfe_range.upper_exclusive IS NULL "
        "OR {key_column} < dfe_range.upper_exclusive)) AS dfe_provenance "
        "WHERE dfe_provenance.has_data OR (dfe_provenance.data_count = 0 "
        "AND dfe_provenance.witness_ordinal = 1) ORDER BY "
        "dfe_provenance.ordinal, dfe_provenance.key_value NULLS FIRST"
    ).format(
        ranges_values=_integer_range_values(ranges),
        relation=relation,
        key_column=key_column,
        row_envelope=row.envelope,
        invalid_row=row.invalid_row,
        oversized_row=row.oversized_row,
        scope_filter=scope_filter,
        key_valid=key_valid,
    )
    return OriginalGreenplumEndpointQuery(
        statement=statement.as_string(),
        parameters=(
            context.schema_digest_hex,
            len(context.schema.fields),
            *scope_parameters,
        ),
        context=context,
        relation_row_type_oid=relation_row_type_oid,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def explain_original_greenplum_endpoint_query(statement: str) -> str:
    if type(statement) is not str or not statement:
        raise ValueError("original Greenplum endpoint statement must be non-empty text")
    return "EXPLAIN VERBOSE " + statement


def _validate_endpoint_inputs(
    schema: CanonicalSchema,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    key_field_index: int,
    max_encoded_envelope_bytes: int,
) -> None:
    validate_postgres_field_bindings(schema, bindings, max_identifier_utf8_bytes)
    if type(key_field_index) is not int or not 0 <= key_field_index < len(schema.fields):
        raise PostgresLoweringError(
            "original Greenplum integer-key field index must identify a schema field"
        )
    key_field = schema.fields[key_field_index]
    if key_field.logical_type is not LogicalType.INT64 or key_field.nullable:
        raise PostgresLoweringError(
            "original Greenplum comparison requires one non-null logical INT64 key field"
        )
    if (
        type(max_encoded_envelope_bytes) is not int
        or max_encoded_envelope_bytes < 1
        or max_encoded_envelope_bytes > INT64_MAX
    ):
        raise ValueError(
            "original Greenplum envelope limit must be a positive signed-int64 integer"
        )


def _integer_key(
    schema: CanonicalSchema,
    bindings: tuple[PostgresFieldBinding, ...],
    key_field_index: int,
    source_alias: str,
) -> tuple[sql.Identifier, sql.Composable]:
    field = schema.fields[key_field_index]
    if field.logical_type is not LogicalType.INT64 or field.nullable:
        raise PostgresLoweringError(
            "original Greenplum comparison requires one non-null logical INT64 key field"
        )
    column = sql.Identifier(source_alias, bindings[key_field_index].column_name)
    value = sql.SQL("({column})::numeric").format(column=column)
    valid = sql.SQL(
        "CASE WHEN {value} BETWEEN {minimum}::numeric AND {maximum}::numeric "
        "THEN {value} = trunc({value}) ELSE FALSE END"
    ).format(
        value=value,
        minimum=sql.Literal(INT64_MIN),
        maximum=sql.Literal(INT64_MAX),
    )
    return column, valid


def _key_envelope(
    schema: CanonicalSchema,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    max_encoded_envelope_bytes: int,
    key_field_index: int,
    source_alias: str,
) -> tuple[sql.Composable, tuple[OriginalGreenplumEndpointParameter, ...]]:
    key_schema = CanonicalSchema(
        protocol=schema.protocol,
        fields=(schema.fields[key_field_index],),
    )
    key_context = prepare_envelope_context(key_schema)
    lowered = lower_postgres_canonical_row(
        key_schema,
        (bindings[key_field_index],),
        max_identifier_utf8_bytes,
        max_encoded_envelope_bytes,
        source_alias,
    )
    envelope = sql.SQL(
        "CASE WHEN ({row_envelope}) IS NULL THEN NULL::text "
        "ELSE {key_header}::text || substring(({row_envelope}) "
        "FROM {payload_start}) END"
    ).format(
        row_envelope=lowered.envelope,
        key_header=sql.Literal(key_context.key_header),
        payload_start=sql.Literal(len(key_context.row_header) + 1),
    )
    return envelope, (
        key_context.schema_digest_hex,
        len(key_context.schema.fields),
        key_context.schema_digest_hex,
        len(key_context.schema.fields),
    )


def _scope_filter(
    bindings: tuple[PostgresFieldBinding, ...],
    scope: PostgresScopePredicate | None,
    source_alias: str,
) -> tuple[sql.Composable, tuple[OriginalGreenplumEndpointParameter, ...]]:
    if scope is None:
        return sql.SQL("TRUE"), ()
    if not isinstance(cast(object, scope), PostgresScopePredicate):
        raise PostgresLoweringError(
            "original Greenplum scope must be a PostgresScopePredicate or None"
        )
    matches = tuple(binding for binding in bindings if binding.column_name == scope.column_name)
    if len(matches) != 1:
        raise PostgresLoweringError(
            "original Greenplum scope column must map to exactly one protected field: "
            f"column={scope.column_name!r}, matching_fields={len(matches)}"
        )
    value = decode_payload(scope.field, scope.canonical_payload)
    cast_name, parameter = _scope_parameter(scope.field, value)
    column = sql.Identifier(source_alias, scope.column_name)
    predicate = sql.SQL("{column} IS NOT NULL AND {column} = %s::{cast_name}").format(
        column=column,
        cast_name=sql.SQL(cast(LiteralString, cast_name)),
    )
    return predicate, (parameter,)


def _scope_parameter(
    field: FieldSchema,
    value: int | Decimal | bool | str | date,
) -> tuple[str, OriginalGreenplumEndpointParameter]:
    logical_type = field.logical_type
    if logical_type is LogicalType.INT64 and type(value) is int:
        return "bigint", value
    if logical_type is LogicalType.DECIMAL and isinstance(value, Decimal):
        return "numeric", str(value)
    if logical_type is LogicalType.BOOLEAN and type(value) is bool:
        return "boolean", "true" if value else "false"
    if logical_type is LogicalType.DATE and type(value) is date:
        return "date", value.isoformat()
    if logical_type in (LogicalType.TIMESTAMP_LOCAL, LogicalType.TIMESTAMP_INSTANT):
        if type(value) is not str:
            raise PostgresLoweringError(
                "decoded original Greenplum timestamp scope must be canonical text"
            )
        return (
            "timestamp" if logical_type is LogicalType.TIMESTAMP_LOCAL else "timestamptz"
        ), value
    if logical_type is LogicalType.STRING and type(value) is str:
        return "text", value
    raise PostgresLoweringError(
        f"logical type {logical_type!r} is unsupported for original Greenplum scope equality"
    )


def _validate_range(value: object) -> None:
    if not isinstance(value, PostgresIntegerRangeRequest):
        raise PostgresLoweringError("original Greenplum integer range has an unexpected type")


def _validate_ranges(value: object) -> None:
    if type(value) is not tuple or not value:
        raise PostgresLoweringError("original Greenplum ranges must be a non-empty immutable tuple")
    ranges = cast(tuple[object, ...], value)
    seen_ids: set[str] = set()
    previous_upper: int | None = None
    for index, item in enumerate(ranges):
        _validate_range(item)
        request = cast(PostgresIntegerRangeRequest, item)
        if request.segment_id in seen_ids:
            raise PostgresLoweringError("original Greenplum range segment IDs must be unique")
        seen_ids.add(request.segment_id)
        if index > 0:
            if previous_upper is None:
                raise PostgresLoweringError("original Greenplum unbounded range must be last")
            if request.lower_inclusive < previous_upper:
                raise PostgresLoweringError(
                    "original Greenplum ranges must be ordered and disjoint"
                )
        previous_upper = request.upper_exclusive


def _integer_range_values(
    ranges: tuple[PostgresIntegerRangeRequest, ...],
) -> sql.Composable:
    values: list[sql.Composable] = []
    for ordinal, item in enumerate(ranges):
        upper = (
            sql.SQL("NULL::bigint")
            if item.upper_exclusive is None
            else _bigint_literal(item.upper_exclusive)
        )
        values.append(
            sql.SQL("({segment_id}, {lower}, {upper}, {ordinal}::integer)").format(
                segment_id=sql.Literal(item.segment_id),
                lower=_bigint_literal(item.lower_inclusive),
                upper=upper,
                ordinal=sql.Literal(ordinal),
            )
        )
    return sql.SQL(", ").join(values)


def _range_condition(
    item: PostgresIntegerRangeRequest,
    key_column: sql.Identifier,
) -> sql.Composable:
    scan_key = sql.SQL("({key_column})::numeric").format(key_column=key_column)
    lower = sql.SQL("{scan_key} >= {lower}").format(
        scan_key=scan_key,
        lower=_bigint_literal(item.lower_inclusive),
    )
    if item.upper_exclusive is None:
        return lower
    return sql.SQL("({lower} AND {scan_key} < {upper})").format(
        lower=lower,
        scan_key=scan_key,
        upper=_bigint_literal(item.upper_exclusive),
    )


def _bigint_literal(value: int) -> sql.Composable:
    return sql.SQL("{value}::bigint").format(value=sql.Literal(str(value)))


def _segment_limb_sums() -> sql.Composable:
    return sql.SQL(", ").join(_segment_limb_sum(index) for index in range(8))


def _segment_limb_sum(index: int) -> sql.Composable:
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
    return sql.SQL(
        "coalesce(sum(CASE WHEN dfe_hash.row_hash IS NULL THEN 0::numeric(38, 0) "
        "ELSE ({limb})::numeric(38, 0) END), 0::numeric(38, 0)) AS {alias}"
    ).format(limb=limb, alias=sql.Identifier(f"limb_{index}"))


def _combined_limb_sums() -> sql.Composable:
    return sql.SQL(", ").join(
        sql.SQL(
            "coalesce(sum(dfe_member.{alias}::numeric(38, 0)), 0::numeric(38, 0))::text AS {alias}"
        ).format(alias=sql.Identifier(f"limb_{index}"))
        for index in range(8)
    )


def _validate_primary_content_ids(content_ids: tuple[int, ...]) -> None:
    if type(content_ids) is not tuple or not content_ids:
        raise ValueError("original Greenplum fingerprint requires active primary content IDs")
    for content_id in content_ids:
        if type(content_id) is not int or not 0 <= content_id <= INT64_MAX:
            raise ValueError("original Greenplum primary content ID must be a non-negative integer")
    if tuple(sorted(set(content_ids))) != content_ids:
        raise ValueError("original Greenplum primary content IDs must be distinct and increasing")
