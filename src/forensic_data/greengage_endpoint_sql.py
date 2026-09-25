import re
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from itertools import pairwise
from typing import LiteralString, cast, final

from psycopg import sql

from forensic_data.canonical import CanonicalSchema
from forensic_data.canonical.codec import decode_payload
from forensic_data.canonical.model import INT64_MAX, FieldSchema, LogicalType
from forensic_data.canonical.schema import CanonicalEnvelopeContext, prepare_envelope_context
from forensic_data.greenplum_catalog import (
    GreenplumCatalogMetadataError,
    GreenplumColumnProbe,
    GreenplumStorageKind,
)
from forensic_data.greenplum_sql import (
    GreenplumCanonicalFingerprintPlan,
    GreenplumCanonicalProbeRequest,
    _greenplum_plan_unquoted_text,  # pyright: ignore[reportPrivateUsage]
    _GreenplumCanonicalPlanShape,  # pyright: ignore[reportPrivateUsage]
    _human_subtree_end,  # pyright: ignore[reportPrivateUsage]
    _indent,  # pyright: ignore[reportPrivateUsage]
    _plan_lines,  # pyright: ignore[reportPrivateUsage]
)
from forensic_data.postgres import DatabaseRow
from forensic_data.postgres_sql import (
    PostgresFieldBinding,
    PostgresIntegerRangeRequest,
    PostgresLoweringError,
    PostgresScopePredicate,
    lower_postgres_canonical_row,
    validate_postgres_field_bindings,
)

INT64_MIN = -(1 << 63)

type GreengageEndpointParameter = str | int | bytes


@dataclass(frozen=True, slots=True)
class GreengageEndpointQuery:
    statement: str
    parameters: tuple[GreengageEndpointParameter, ...]
    context: CanonicalEnvelopeContext
    relation_row_type_oid: int
    max_encoded_envelope_bytes: int


@final
@dataclass(frozen=True, slots=True)
class GreengageRangeFingerprintQuery(GreengageEndpointQuery):
    ranges: tuple[PostgresIntegerRangeRequest, ...]
    primary_content_ids: tuple[int, ...]
    plan_request: GreenplumCanonicalProbeRequest


def build_greengage_integer_key_summary_query(
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
) -> GreengageEndpointQuery:
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
    statement = sql.SQL(
        "SELECT (pg_catalog.pg_typeof((pg_catalog.array_agg((dfe_origin.*)) "
        "FILTER (WHERE FALSE))[1]))::oid::bigint AS origin_type, "
        "count(*)::text AS row_count, "
        "count(CASE WHEN {key_column} IS NULL THEN 1 ELSE NULL END)::text "
        "AS null_key_count, "
        "count(CASE WHEN {key_column} IS NOT NULL AND NOT ({key_valid}) "
        "THEN 1 ELSE NULL END)::text AS invalid_key_count, "
        "count(CASE WHEN {key_column} IS NOT NULL AND ({key_valid}) "
        "THEN 1 ELSE NULL END)::text AS valid_key_count, "
        "count(DISTINCT CASE WHEN {key_column} IS NOT NULL AND ({key_valid}) "
        "THEN ({key_column})::numeric ELSE NULL END)::text AS distinct_key_count, "
        "(min(({key_column})::numeric) FILTER (WHERE {key_column} IS NOT NULL "
        "AND ({key_valid})))::bigint::text AS minimum_key, "
        "(max(({key_column})::numeric) FILTER (WHERE {key_column} IS NOT NULL "
        "AND ({key_valid})))::bigint::text AS maximum_key, "
        "EXISTS (SELECT 1 FROM pg_catalog.pg_index AS dfe_index "
        "JOIN pg_catalog.pg_class AS dfe_index_relation "
        "ON dfe_index_relation.oid = dfe_index.indexrelid "
        "JOIN pg_catalog.pg_am AS dfe_access_method "
        "ON dfe_access_method.oid = dfe_index_relation.relam "
        "JOIN pg_catalog.pg_attribute AS dfe_key_attribute "
        "ON dfe_key_attribute.attrelid = dfe_index.indrelid "
        "AND dfe_key_attribute.attnum = dfe_index.indkey[0] "
        "WHERE dfe_index.indrelid = {relation_oid}::oid "
        "AND dfe_access_method.amname = 'btree' "
        "AND dfe_key_attribute.attname = {key_name} "
        "AND NOT dfe_key_attribute.attisdropped "
        "AND dfe_index.indnkeyatts >= 1 AND dfe_index.indisvalid "
        "AND dfe_index.indisready AND dfe_index.indislive "
        "AND dfe_index.indpred IS NULL AND dfe_index.indexprs IS NULL) "
        "AS usable_access_path FROM ONLY {relation} AS dfe_origin "
        "WHERE {scope_filter}"
    ).format(
        key_column=key_column,
        key_valid=key_valid,
        relation_oid=sql.Literal(relation_oid),
        key_name=sql.Literal(bindings[key_field_index].column_name),
        relation=sql.Identifier(schema_name, relation_name),
        scope_filter=scope_filter,
    )
    return GreengageEndpointQuery(
        statement=statement.as_string(),
        parameters=scope_parameters,
        context=prepare_envelope_context(schema),
        relation_row_type_oid=relation_row_type_oid,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )


def build_greengage_integer_range_fingerprint_query(
    schema: CanonicalSchema,
    schema_name: str,
    relation_name: str,
    relation_row_type_oid: int,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    primary_content_ids: tuple[int, ...],
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    max_encoded_envelope_bytes: int,
) -> GreengageRangeFingerprintQuery:
    _validate_endpoint_inputs(
        schema,
        bindings,
        max_identifier_utf8_bytes,
        key_field_index,
        max_encoded_envelope_bytes,
    )
    _validate_ranges(ranges)
    _validate_primary_content_ids(primary_content_ids)
    context = prepare_envelope_context(schema)
    source_alias = "dfe_origin"
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
    ranges_values = _integer_range_values(ranges)
    range_id, range_ordinal, range_filter = _range_projection(ranges, key_column)
    relation = sql.Identifier(schema_name, relation_name)
    source = sql.Identifier(source_alias)
    source_rows = sql.SQL(
        "SELECT gp_segment_id::integer AS segment_id, {range_id} AS range_id, "
        "{range_ordinal} AS ordinal, CASE WHEN FALSE THEN ({source}.*) ELSE NULL END "
        "AS origin_type_seed, TRUE AS has_data, {row_envelope} AS row_envelope, "
        "{key_envelope} AS key_envelope, {invalid_row} AS invalid_row, "
        "{oversized_row} AS oversized_row FROM ONLY {relation} AS {source} WHERE "
        "{key_column} IS NOT NULL AND ({key_valid}) AND ({range_filter}) "
        "AND ({scope_filter}) "
        "UNION ALL SELECT dfe_gp_id.gp_segment_id::integer AS segment_id, "
        "dfe_range.segment_id AS range_id, dfe_range.ordinal, NULL AS origin_type_seed, "
        "FALSE AS has_data, NULL::text AS row_envelope, NULL::text AS key_envelope, "
        "FALSE AS invalid_row, FALSE AS oversized_row "
        "FROM gp_dist_random('gp_id') AS dfe_gp_id "
        "CROSS JOIN (VALUES {ranges_values}) AS "
        "dfe_range(segment_id, lower_inclusive, upper_exclusive, ordinal)"
    ).format(
        source=source,
        range_id=range_id,
        range_ordinal=range_ordinal,
        row_envelope=row.envelope,
        key_envelope=key_envelope,
        invalid_row=row.invalid_row,
        oversized_row=row.oversized_row,
        relation=relation,
        key_column=key_column,
        key_valid=key_valid,
        range_filter=range_filter,
        scope_filter=scope_filter,
        ranges_values=ranges_values,
    )
    hashed_rows = sql.SQL(
        "SELECT dfe_row.segment_id, dfe_row.range_id, dfe_row.ordinal, "
        "(pg_catalog.pg_typeof(dfe_row.origin_type_seed))::oid::bigint "
        "AS relation_row_type_oid, dfe_row.has_data, dfe_row.row_envelope, "
        "dfe_row.key_envelope, dfe_row.invalid_row, dfe_row.oversized_row, "
        "CASE WHEN NOT dfe_row.has_data OR dfe_row.row_envelope IS NULL "
        "THEN NULL::bytea ELSE pg_catalog.sha256("
        "pg_catalog.convert_to(dfe_row.row_envelope, 'UTF8')) END AS row_hash "
        "FROM dfe_source AS dfe_row"
    )
    segment_aggregate = sql.SQL(
        "SELECT dfe_hash.segment_id, dfe_hash.range_id, dfe_hash.ordinal, "
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
        "FROM dfe_hashed AS dfe_hash GROUP BY dfe_hash.segment_id, "
        "dfe_hash.range_id, dfe_hash.ordinal"
    ).format(limb_sums=_segment_limb_sums())
    statement = sql.SQL(
        "WITH dfe_source AS ({source_rows}), "
        "dfe_hashed AS ({hashed_rows}), dfe_segment AS ({segment_aggregate}), "
        "dfe_member AS (SELECT dfe_segment.segment_id, dfe_segment.range_id, "
        "dfe_segment.ordinal, dfe_segment.relation_row_type_oid, "
        "dfe_segment.valid_row_count, dfe_segment.limb_0, dfe_segment.limb_1, "
        "dfe_segment.limb_2, dfe_segment.limb_3, dfe_segment.limb_4, "
        "dfe_segment.limb_5, dfe_segment.limb_6, dfe_segment.limb_7, "
        "dfe_segment.invalid_row_count, dfe_segment.oversized_row_count, "
        "dfe_segment.row_envelope_bytes, dfe_segment.key_envelope_bytes, "
        "dfe_segment.source_row_count, dfe_segment.topology_seed_count "
        "FROM dfe_segment) SELECT max(dfe_member.relation_row_type_oid)::bigint "
        "AS relation_row_type_oid, dfe_member.range_id, "
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
        "ELSE NULL::integer END), ','), '') AS observed_content_ids "
        "FROM dfe_member GROUP BY dfe_member.ordinal, dfe_member.range_id "
        "ORDER BY dfe_member.ordinal"
    ).format(
        source_rows=source_rows,
        hashed_rows=hashed_rows,
        segment_aggregate=segment_aggregate,
        combined_limb_sums=_combined_limb_sums(),
    )
    request = GreenplumCanonicalProbeRequest(
        schema_name=schema_name,
        relation_name=relation_name,
        columns=tuple(
            GreenplumColumnProbe(field_name=binding.field_name, column_name=binding.column_name)
            for binding in bindings
        ),
        schema=schema,
        max_encoded_envelope_bytes=max_encoded_envelope_bytes,
    )
    return GreengageRangeFingerprintQuery(
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
        ranges=ranges,
        primary_content_ids=primary_content_ids,
        plan_request=request,
    )


def build_greengage_integer_range_rows_query(
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
) -> GreengageEndpointQuery:
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
        "FROM (SELECT "
        "(pg_catalog.pg_typeof((dfe_origin.*)))::oid::bigint AS origin_type, "
        "dfe_origin.tableoid IS NOT NULL AS has_data, dfe_range.segment_id, "
        "dfe_range.ordinal, ({key_column})::bigint AS key_value, "
        "{row_envelope} AS row_envelope, "
        "{invalid_row} AS invalid_row, {oversized_row} AS oversized_row, "
        "count(*) FILTER (WHERE dfe_origin.tableoid IS NOT NULL) OVER () "
        "AS data_count, row_number() OVER (ORDER BY dfe_range.ordinal, "
        "({key_column})::bigint NULLS FIRST) AS witness_ordinal "
        "FROM dfe_ranges AS dfe_range LEFT JOIN ONLY {relation} AS dfe_origin ON "
        "({scope_filter}) AND {key_column} IS NOT NULL AND ({key_valid}) "
        "AND {key_column} >= dfe_range.lower_inclusive "
        "AND (dfe_range.upper_exclusive IS NULL "
        "OR {key_column} < dfe_range.upper_exclusive)) AS dfe_provenance "
        "WHERE dfe_provenance.has_data OR (dfe_provenance.data_count = 0 "
        "AND dfe_provenance.witness_ordinal = 1) ORDER BY "
        "dfe_provenance.ordinal, dfe_provenance.key_value NULLS FIRST"
    ).format(
        ranges_values=_integer_range_values(ranges),
        key_column=key_column,
        row_envelope=row.envelope,
        invalid_row=row.invalid_row,
        oversized_row=row.oversized_row,
        relation=sql.Identifier(schema_name, relation_name),
        key_valid=key_valid,
        scope_filter=scope_filter,
    )
    return GreengageEndpointQuery(
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


def validate_greengage_range_fingerprint_plan(
    rows: tuple[DatabaseRow, ...],
    query: GreengageRangeFingerprintQuery,
    storage_kind: GreenplumStorageKind,
) -> GreenplumCanonicalFingerprintPlan:
    shape = _parse_greengage_range_fingerprint_plan_shape(
        rows,
        query.plan_request,
        len(query.primary_content_ids),
        storage_kind,
        len(query.ranges),
    )
    unquoted = _greenplum_plan_unquoted_text(  # pyright: ignore[reportPrivateUsage]
        shape.lower_aggregate_subtree
    )
    if "sha256(" not in unquoted:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan does not hash below Motion"
        )
    _validate_lowest_partial_expressions(shape.lower_aggregate_subtree)
    return GreenplumCanonicalFingerprintPlan(
        lines=shape.lines,
        scanned_relation=(f"{query.plan_request.schema_name}.{query.plan_request.relation_name}"),
        dispatched_primary_count=len(query.primary_content_ids),
        topology_seeded=True,
        execution_locus="greengage_endpoint_segment_aggregate_below_motion",
    )


def _validate_lowest_partial_expressions(partial_metadata: str) -> None:
    aggregate_expressions = tuple(
        _normalize_plan_expression(expression) for expression in _sum_expressions(partial_metadata)
    )
    if len(aggregate_expressions) != 10:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan must expose eight hash-limb sums and two "
            "envelope-byte sums in the innermost partial aggregate below Motion: "
            f"actual_sum_expressions={len(aggregate_expressions)}"
        )
    hash_inputs: list[str] = []
    for index, expression in enumerate(aggregate_expressions[:8]):
        calls = _get_byte_calls(expression)
        offsets = tuple(call[1] for call in calls)
        expected_offsets = tuple(range(index * 4, index * 4 + 4))
        if offsets != expected_offsets or len(calls) != 4 or expression.count("numeric(38,0)") != 2:
            raise GreenplumCatalogMetadataError(
                "Greengage range fingerprint plan has an invalid exact limb sum in the "
                "innermost partial aggregate below "
                f"Motion: limb_index={index}, expected_offsets={expected_offsets!r}, "
                f"actual_offsets={offsets!r}"
            )
        hash_inputs.extend(call[0] for call in calls)
        _require_exact_limb_expression(expression, calls, index)
    if len(frozenset(hash_inputs)) != 1 or not _is_canonical_row_hash(hash_inputs[0]):
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint limb sums do not all consume the same canonical "
            "row-envelope SHA-256 expression"
        )
    expected_byte_sums = (
        "sum(case when (dfe_row.has_data and (not dfe_row.invalid_row) and "
        "(not dfe_row.oversized_row)) then octet_length(dfe_row.row_envelope) "
        "else 0 end)",
        "sum(case when (dfe_row.has_data and (not dfe_row.invalid_row) and "
        "(not dfe_row.oversized_row)) then octet_length(dfe_row.key_envelope) "
        "else 0 end)",
    )
    if aggregate_expressions[8:] != expected_byte_sums:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint innermost partial aggregate does not preserve "
            "distinct exact row-envelope and key-envelope byte sums"
        )


def explain_greengage_endpoint_query(statement: str) -> str:
    if type(statement) is not str or not statement:
        raise ValueError("Greengage endpoint statement must be non-empty text")
    return "EXPLAIN (VERBOSE, COSTS TRUE) " + statement


def _parse_greengage_range_fingerprint_plan_shape(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumCanonicalProbeRequest,
    primary_count: int,
    storage_kind: GreenplumStorageKind,
    range_count: int,
) -> _GreenplumCanonicalPlanShape:
    if type(primary_count) is not int or primary_count < 1:
        raise ValueError("Greengage range fingerprint requires a positive primary count")
    if type(storage_kind) is not GreenplumStorageKind:
        raise TypeError("Greengage storage kind must be a GreenplumStorageKind")
    if type(range_count) is not int or range_count < 1:
        raise ValueError("Greengage range fingerprint requires a positive range count")
    lines = _plan_lines(rows)  # pyright: ignore[reportPrivateUsage]
    human_nodes = tuple((index, line) for index, line in enumerate(lines) if "(cost=" in line)
    if not human_nodes:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan contains no human-readable plan nodes"
        )
    (
        gather_index,
        outer_finalize_index,
        outer_redistribute_index,
        outer_partial_index,
        inner_finalize_index,
        inner_redistribute_index,
        inner_partial_index,
        append_index,
    ) = _range_fingerprint_stage_indexes(human_nodes, primary_count)
    hierarchy = (
        gather_index,
        outer_finalize_index,
        outer_redistribute_index,
        outer_partial_index,
        inner_finalize_index,
        inner_redistribute_index,
        inner_partial_index,
        append_index,
    )
    if hierarchy != tuple(sorted(hierarchy)) or gather_index != human_nodes[0][0]:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan orders its distributed aggregate stages "
            f"unexpectedly: stage_lines={hierarchy!r}, root_line={human_nodes[0][0]}"
        )
    for parent_index, child_index in pairwise(hierarchy):
        parent_end = _human_subtree_end(  # pyright: ignore[reportPrivateUsage]
            human_nodes,
            parent_index,
            len(lines),
        )
        if (
            child_index >= parent_end or _indent(lines[child_index]) <= _indent(lines[parent_index])  # pyright: ignore[reportPrivateUsage]
        ):
            raise GreenplumCatalogMetadataError(
                "Greengage range fingerprint plan does not nest its distributed "
                "aggregate stages exactly: "
                f"parent_line={parent_index}, child_line={child_index}, "
                f"parent_subtree_end={parent_end}"
            )
    _require_plan_key(
        lines,
        human_nodes,
        outer_finalize_index,
        "Group Key:",
        frozenset(("dfe_member.ordinal", "dfe_member.range_id")),
        "outer finalize aggregate",
    )
    _require_plan_key(
        lines,
        human_nodes,
        outer_redistribute_index,
        "Hash Key:",
        frozenset(("dfe_member.ordinal", "dfe_member.range_id")),
        "outer redistribution",
    )
    _require_plan_key(
        lines,
        human_nodes,
        outer_partial_index,
        "Group Key:",
        frozenset(("dfe_member.ordinal", "dfe_member.range_id")),
        "outer partial aggregate",
    )
    _require_plan_key(
        lines,
        human_nodes,
        inner_finalize_index,
        "Group Key:",
        frozenset(("dfe_row.segment_id", "dfe_row.range_id", "dfe_row.ordinal")),
        "inner finalize aggregate",
    )
    _require_plan_key(
        lines,
        human_nodes,
        inner_redistribute_index,
        "Hash Key:",
        frozenset(("dfe_row.segment_id", "dfe_row.range_id", "dfe_row.ordinal")),
        "inner redistribution",
    )
    _require_plan_key(
        lines,
        human_nodes,
        inner_partial_index,
        "Group Key:",
        frozenset(("dfe_row.segment_id", "dfe_row.range_id", "dfe_row.ordinal")),
        "innermost partial aggregate",
    )
    inner_partial_end = _human_subtree_end(  # pyright: ignore[reportPrivateUsage]
        human_nodes,
        inner_partial_index,
        len(lines),
    )
    lower_motion_indexes = tuple(
        index
        for index, line in human_nodes
        if inner_partial_index < index < inner_partial_end and "motion" in line.lower()
    )
    append_subtree_end = _human_subtree_end(  # pyright: ignore[reportPrivateUsage]
        human_nodes,
        append_index,
        len(lines),
    )
    branch_nodes = tuple(
        (index, line) for index, line in human_nodes if append_index < index < append_subtree_end
    )
    if not branch_nodes:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint source append has no physical branches"
        )
    branch_indent = min(
        _indent(line)
        for _, line in branch_nodes  # pyright: ignore[reportPrivateUsage]
    )
    branch_roots = tuple(
        (index, line)
        for index, line in branch_nodes
        if _indent(line) == branch_indent  # pyright: ignore[reportPrivateUsage]
    )
    if len(branch_roots) != 2:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint source append must contain exactly two sibling "
            f"physical branches: actual={len(branch_roots)}"
        )
    relation_scan_index, relation_scan_line = branch_roots[0]
    topology_scan_index, topology_scan_line = branch_roots[1]
    _require_target_scan_identity(
        relation_scan_line,
        request.schema_name,
        request.relation_name,
        storage_kind,
    )
    _require_topology_branch(
        human_nodes,
        topology_scan_index,
        append_subtree_end,
        topology_scan_line,
        range_count,
    )
    relation_scan_end = _human_subtree_end(  # pyright: ignore[reportPrivateUsage]
        human_nodes,
        relation_scan_index,
        len(lines),
    )
    append_indent = _indent(lines[append_index])  # pyright: ignore[reportPrivateUsage]
    relation_indent = _indent(lines[relation_scan_index])  # pyright: ignore[reportPrivateUsage]
    topology_indent = _indent(lines[topology_scan_index])  # pyright: ignore[reportPrivateUsage]
    if (
        lower_motion_indexes
        or relation_scan_index >= append_subtree_end
        or topology_scan_index >= append_subtree_end
        or relation_indent <= append_indent
        or topology_indent != branch_indent
        or topology_scan_index < relation_scan_end
    ):
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan does not preserve sibling relation and "
            "topology-seed branches below the innermost partial aggregate"
        )
    inner_partial_metadata_end = _first_child_plan_node(
        human_nodes,
        inner_partial_index,
        inner_partial_end,
    )
    return _GreenplumCanonicalPlanShape(  # pyright: ignore[reportPrivateUsage]
        lines=lines,
        lower_aggregate_subtree="\n".join(
            lines[inner_partial_index:inner_partial_metadata_end]
        ).lower(),
    )


def _range_fingerprint_stage_indexes(
    nodes: tuple[tuple[int, str], ...],
    primary_count: int,
) -> tuple[int, int, int, int, int, int, int, int]:
    gathers: list[int] = []
    redistributes: list[int] = []
    finalizes: list[int] = []
    partials: list[int] = []
    appends: list[int] = []
    for index, line in nodes:
        header = _plan_node_header(line)
        motion = _parse_motion_header(header)
        if motion is not None:
            kind, source_count, target_count, segment_count = motion
            if kind == "Gather":
                gathers.append(index)
                expected_target_count = 1
            elif kind == "Redistribute":
                redistributes.append(index)
                expected_target_count = primary_count
            else:
                raise GreenplumCatalogMetadataError(
                    "Greengage range fingerprint plan contains an unexpected Motion: "
                    f"kind={kind!r}, line={index}"
                )
            if (
                source_count != primary_count
                or target_count != expected_target_count
                or segment_count != primary_count
            ):
                raise GreenplumCatalogMetadataError(
                    "Greengage range fingerprint Motion has an unexpected exact segment "
                    f"cardinality: line={index}, kind={kind!r}, "
                    f"source_count={source_count}, target_count={target_count}, "
                    f"segments={segment_count}, expected_primaries={primary_count}"
                )
        aggregate_phase = _parse_aggregate_header(header)
        if aggregate_phase == "Finalize":
            finalizes.append(index)
        elif aggregate_phase == "Partial":
            partials.append(index)
        if re.fullmatch(r"Append\s+\(cost=[^)]*\)", header) is not None:
            appends.append(index)
    if (
        len(gathers) != 1
        or len(redistributes) != 2
        or len(finalizes) != 2
        or len(partials) != 2
        or len(appends) != 1
    ):
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan does not expose the required exact "
            "two-stage distributed aggregate hierarchy: "
            f"gather_motions={len(gathers)}, redistribute_motions={len(redistributes)}, "
            f"finalize_aggregates={len(finalizes)}, partial_aggregates={len(partials)}, "
            f"appends={len(appends)}"
        )
    return (
        gathers[0],
        finalizes[0],
        redistributes[0],
        partials[0],
        finalizes[1],
        redistributes[1],
        partials[1],
        appends[0],
    )


def _plan_node_header(line: str) -> str:
    header = line.strip()
    if header.startswith("->"):
        header = header[2:].lstrip()
    return header


def _parse_motion_header(header: str) -> tuple[str, int, int, int] | None:
    if " Motion " not in header:
        return None
    match = re.fullmatch(
        r"([A-Za-z]+) Motion ([0-9]+):([0-9]+)\s+"
        r"\(slice[0-9]+; segments: ([0-9]+)\)\s+\(cost=[^)]*\)",
        header,
    )
    if match is None:
        raise GreenplumCatalogMetadataError(
            f"Greengage range fingerprint plan contains a malformed Motion node: {header!r}"
        )
    return (match.group(1), int(match.group(2)), int(match.group(3)), int(match.group(4)))


def _parse_aggregate_header(header: str) -> str | None:
    if "Aggregate" not in header:
        return None
    match = re.fullmatch(
        r"(Finalize|Partial) (?:Hash|Group)Aggregate\s+\(cost=[^)]*\)",
        header,
    )
    if match is None:
        raise GreenplumCatalogMetadataError(
            f"Greengage range fingerprint plan contains an unexpected aggregate node: {header!r}"
        )
    return match.group(1)


def _require_plan_key(
    lines: tuple[str, ...],
    nodes: tuple[tuple[int, str], ...],
    node_index: int,
    prefix: str,
    expected: frozenset[str],
    label: str,
) -> None:
    subtree_end = _human_subtree_end(  # pyright: ignore[reportPrivateUsage]
        nodes,
        node_index,
        len(lines),
    )
    metadata_end = _first_child_plan_node(nodes, node_index, subtree_end)
    keys = tuple(
        line.strip().removeprefix(prefix).strip()
        for line in lines[node_index + 1 : metadata_end]
        if line.strip().startswith(prefix)
    )
    if len(keys) != 1:
        raise GreenplumCatalogMetadataError(
            f"Greengage range fingerprint {label} must expose exactly one owned {prefix} "
            f"line: actual={len(keys)}"
        )
    values = tuple(value.strip() for value in keys[0].split(","))
    if len(values) != len(expected) or frozenset(values) != expected:
        raise GreenplumCatalogMetadataError(
            f"Greengage range fingerprint {label} has an incomplete or unexpected "
            f"{prefix} value: expected={tuple(sorted(expected))!r}, actual={values!r}"
        )


def _first_child_plan_node(
    nodes: tuple[tuple[int, str], ...],
    node_index: int,
    subtree_end: int,
) -> int:
    child_indexes = tuple(index for index, _ in nodes if node_index < index < subtree_end)
    if not child_indexes:
        raise GreenplumCatalogMetadataError(
            f"Greengage range fingerprint plan node has no physical child: line={node_index}"
        )
    return child_indexes[0]


def _require_target_scan_identity(
    line: str,
    expected_schema: str,
    expected_relation: str,
    storage_kind: GreenplumStorageKind,
) -> None:
    access_method, schema_name, relation_name, alias = _parse_plan_scan_identity(line)
    allowed_access_methods = (
        frozenset(("Seq Scan", "Bitmap Heap Scan", "Index Scan", "Index Only Scan"))
        if storage_kind is GreenplumStorageKind.HEAP
        else frozenset(("Seq Scan",))
    )
    if (
        access_method not in allowed_access_methods
        or schema_name != expected_schema
        or relation_name != expected_relation
        or alias != "dfe_origin"
    ):
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint relation branch has an unexpected exact scan "
            "identity: "
            f"access_method={access_method!r}, schema={schema_name!r}, "
            f"relation={relation_name!r}, alias={alias!r}, "
            f"expected_schema={expected_schema!r}, expected_relation={expected_relation!r}"
        )


def _require_topology_scan_identity(line: str) -> None:
    access_method, schema_name, relation_name, alias = _parse_plan_scan_identity(line)
    if (
        access_method != "Seq Scan"
        or schema_name != "pg_catalog"
        or relation_name != "gp_id"
        or alias != "dfe_gp_id"
    ):
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint topology branch is not the exact dynamic "
            "pg_catalog.gp_id seed scan: "
            f"access_method={access_method!r}, schema={schema_name!r}, "
            f"relation={relation_name!r}, alias={alias!r}"
        )


def _require_topology_branch(
    nodes: tuple[tuple[int, str], ...],
    branch_index: int,
    append_subtree_end: int,
    branch_line: str,
    range_count: int,
) -> None:
    header = _plan_node_header(branch_line)
    if header.startswith("Seq Scan on "):
        if range_count != 1:
            raise GreenplumCatalogMetadataError(
                "Greengage multi-range topology seed cannot omit its range Values branch"
            )
        _require_topology_scan_identity(branch_line)
        return
    if re.fullmatch(r"Nested Loop\s+\(cost=[^)]*\)", header) is None:
        raise GreenplumCatalogMetadataError(
            f"Greengage range fingerprint topology seed has an unexpected branch root: {header!r}"
        )
    if _plan_node_estimated_rows(header) != range_count:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint topology Nested Loop does not preserve one "
            f"seed per range: expected={range_count}, "
            f"actual={_plan_node_estimated_rows(header)}"
        )
    branch_end = _human_subtree_end(  # pyright: ignore[reportPrivateUsage]
        nodes,
        branch_index,
        append_subtree_end,
    )
    child_nodes = tuple((index, line) for index, line in nodes if branch_index < index < branch_end)
    if not child_nodes:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint topology Nested Loop has no physical children"
        )
    child_indent = min(
        _indent(line)
        for _, line in child_nodes  # pyright: ignore[reportPrivateUsage]
    )
    child_roots = tuple(
        (index, line)
        for index, line in child_nodes
        if _indent(line) == child_indent  # pyright: ignore[reportPrivateUsage]
    )
    if len(child_roots) != 2:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint topology Nested Loop must contain exactly the "
            f"gp_id and range Values children: actual={len(child_roots)}"
        )
    _require_topology_scan_identity(child_roots[0][1])
    _require_range_values_scan(child_roots[1][1], range_count)


def _require_range_values_scan(line: str, range_count: int) -> None:
    header = _plan_node_header(line)
    prefix = "Values Scan on "
    if not header.startswith(prefix):
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint topology seed omits its generated Values scan"
        )
    name, position = _consume_plan_identifier(header, len(prefix))
    if name != "*VALUES*" or re.fullmatch(r"\s+\(cost=[^)]*\)", header[position:]) is None:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint topology seed has an unexpected Values identity"
        )
    observed_rows = _plan_node_estimated_rows(header)
    if observed_rows != range_count:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint topology Values scan does not preserve one row "
            f"per requested range: expected={range_count}, actual={observed_rows}"
        )


def _plan_node_estimated_rows(header: str) -> int:
    match = re.search(r"(?:^|\s)rows=([0-9]+)(?:\s|$)", header)
    if match is None:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan node omits its exact estimated row count"
        )
    return int(match.group(1))


def _parse_plan_scan_identity(line: str) -> tuple[str, str, str, str]:
    header = _plan_node_header(line)
    simple_prefixes = (
        ("Bitmap Heap Scan on ", "Bitmap Heap Scan"),
        ("Seq Scan on ", "Seq Scan"),
    )
    for prefix, access_method in simple_prefixes:
        if header.startswith(prefix):
            return _parse_plan_scan_relation(header, len(prefix), access_method)
    index_prefixes = (
        ("Index Only Scan using ", "Index Only Scan"),
        ("Index Scan using ", "Index Scan"),
    )
    for prefix, access_method in index_prefixes:
        if not header.startswith(prefix):
            continue
        _, position = _consume_plan_name(header, len(prefix), 2)
        if not header.startswith(" on ", position):
            raise GreenplumCatalogMetadataError(
                "Greengage range fingerprint index scan omits its exact relation identity"
            )
        return _parse_plan_scan_relation(header, position + len(" on "), access_method)
    raise GreenplumCatalogMetadataError(
        f"Greengage range fingerprint append branch has an unsupported scan node: {header!r}"
    )


def _parse_plan_scan_relation(
    header: str,
    position: int,
    access_method: str,
) -> tuple[str, str, str, str]:
    relation_components, position = _consume_plan_name(header, position, 2)
    if len(relation_components) != 2:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint scan must expose an exact qualified relation name"
        )
    if position >= len(header) or not header[position].isspace():
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint scan omits its stable generated alias"
        )
    position = _skip_plan_spaces(header, position)
    alias, position = _consume_plan_identifier(header, position)
    if re.fullmatch(r"\s+\(cost=[^)]*\)", header[position:]) is None:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint scan has unexpected text after its generated alias"
        )
    return access_method, relation_components[0], relation_components[1], alias


def _consume_plan_name(
    text: str,
    position: int,
    maximum_components: int,
) -> tuple[tuple[str, ...], int]:
    first, position = _consume_plan_identifier(text, position)
    components = [first]
    while len(components) < maximum_components and position < len(text) and text[position] == ".":
        component, position = _consume_plan_identifier(text, position + 1)
        components.append(component)
    return tuple(components), position


def _consume_plan_identifier(text: str, position: int) -> tuple[str, int]:
    if position >= len(text):
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan ends before an identifier"
        )
    if text[position] != '"':
        end = position
        while end < len(text) and text[end] not in {".", " ", "\t", "\r", "\n"}:
            end += 1
        if end == position:
            raise GreenplumCatalogMetadataError(
                "Greengage range fingerprint plan contains an empty identifier"
            )
        return text[position:end], end
    chunks: list[str] = []
    chunk_start = position + 1
    cursor = chunk_start
    while cursor < len(text):
        if text[cursor] != '"':
            cursor += 1
            continue
        chunks.append(text[chunk_start:cursor])
        if cursor + 1 < len(text) and text[cursor + 1] == '"':
            chunks.append('"')
            cursor += 2
            chunk_start = cursor
            continue
        return "".join(chunks), cursor + 1
    raise GreenplumCatalogMetadataError(
        "Greengage range fingerprint plan contains an unterminated quoted identifier"
    )


def _skip_plan_spaces(text: str, position: int) -> int:
    while position < len(text) and text[position].isspace():
        position += 1
    return position


def _normalize_plan_expression(expression: str) -> str:
    return re.sub(r"\s+", " ", expression.strip().lower())


def _get_byte_calls(expression: str) -> tuple[tuple[str, int, str], ...]:
    calls: list[tuple[str, int, str]] = []
    marker = "get_byte("
    search_start = 0
    while True:
        start = expression.find(marker, search_start)
        if start < 0:
            return tuple(calls)
        if start > 0 and (expression[start - 1].isalnum() or expression[start - 1] == "_"):
            search_start = start + len(marker)
            continue
        arguments, end = _parenthesized_content(expression, start + len("get_byte"))
        split_arguments = _split_top_level_arguments(arguments)
        if len(split_arguments) != 2:
            raise GreenplumCatalogMetadataError(
                "Greengage range fingerprint get_byte call must have exactly two arguments"
            )
        offset_text = split_arguments[1].strip()
        if not offset_text.isascii() or not offset_text.isdecimal():
            raise GreenplumCatalogMetadataError(
                "Greengage range fingerprint get_byte offset must be canonical decimal text"
            )
        hash_input = _normalize_plan_expression(split_arguments[0])
        call_text = _normalize_plan_expression(expression[start:end])
        calls.append((hash_input, int(offset_text), call_text))
        search_start = end


def _require_exact_limb_expression(
    expression: str,
    calls: tuple[tuple[str, int, str], ...],
    limb_index: int,
) -> None:
    skeleton = expression
    for index, call in enumerate(calls):
        if skeleton.count(call[2]) != 1:
            raise GreenplumCatalogMetadataError(
                "Greengage range fingerprint limb sum must consume each exact byte once: "
                f"limb_index={limb_index}, byte_offset={call[1]}"
            )
        skeleton = skeleton.replace(call[2], f"dfe_byte_{index}")
    expected_skeleton = (
        f"sum(case when ({calls[0][0]} is null) then '0'::numeric(38,0) else "
        "((((((dfe_byte_0)::bigint * '16777216'::bigint) + "
        "((dfe_byte_1)::bigint * '65536'::bigint)) + "
        "((dfe_byte_2)::bigint * '256'::bigint)) + "
        "(dfe_byte_3)::bigint))::numeric(38,0) end)"
    )
    if skeleton != expected_skeleton:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint limb sum contains unexpected arithmetic: "
            f"limb_index={limb_index}"
        )


def _is_canonical_row_hash(expression: str) -> bool:
    return (
        re.fullmatch(
            r"\(case when \(\(not dfe_row\.has_data\) or "
            r"\(dfe_row\.row_envelope is null\)\) then null::bytea else "
            r"(?:pg_catalog\.)?sha256\(convert_to\(dfe_row\.row_envelope, "
            r"'utf8'::name\)\) end\)",
            expression,
        )
        is not None
    )


def _parenthesized_content(text: str, opening_parenthesis: int) -> tuple[str, int]:
    if opening_parenthesis >= len(text) or text[opening_parenthesis] != "(":
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint plan expression omits an opening parenthesis"
        )
    depth = 0
    for position in range(opening_parenthesis, len(text)):
        character = text[position]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return text[opening_parenthesis + 1 : position], position + 1
    raise GreenplumCatalogMetadataError(
        "Greengage range fingerprint plan contains an unbalanced function call"
    )


def _split_top_level_arguments(arguments: str) -> tuple[str, ...]:
    parts: list[str] = []
    depth = 0
    start = 0
    for position, character in enumerate(arguments):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise GreenplumCatalogMetadataError(
                    "Greengage range fingerprint function arguments are unbalanced"
                )
        elif character == "," and depth == 0:
            parts.append(arguments[start:position])
            start = position + 1
    if depth != 0:
        raise GreenplumCatalogMetadataError(
            "Greengage range fingerprint function arguments are unbalanced"
        )
    parts.append(arguments[start:])
    return tuple(parts)


def _sum_expressions(plan_text: str) -> tuple[str, ...]:
    unquoted_plan = _greenplum_plan_unquoted_text(  # pyright: ignore[reportPrivateUsage]
        plan_text
    )
    marker = "sum("
    expressions: list[str] = []
    search_start = 0
    while True:
        start = unquoted_plan.find(marker, search_start)
        if start < 0:
            break
        if start > 0:
            preceding = unquoted_plan[start - 1]
            if preceding.isalnum() or preceding == "_":
                search_start = start + len(marker)
                continue
        depth = 0
        for position in range(start + len("sum"), len(unquoted_plan)):
            character = unquoted_plan[position]
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    expressions.append(plan_text[start : position + 1])
                    search_start = position + 1
                    break
        else:
            raise GreenplumCatalogMetadataError(
                "Greengage range fingerprint plan contains an unbalanced sum expression: "
                f"start_offset={start}"
            )
    return tuple(expressions)


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
            "Greengage integer-key field index must identify a canonical schema field"
        )
    key_field = schema.fields[key_field_index]
    if key_field.logical_type is not LogicalType.INT64 or key_field.nullable:
        raise PostgresLoweringError(
            "Greengage range comparison requires one non-null logical INT64 key field"
        )
    if (
        type(max_encoded_envelope_bytes) is not int
        or max_encoded_envelope_bytes < 1
        or max_encoded_envelope_bytes > INT64_MAX
    ):
        raise ValueError(
            "Greengage max encoded envelope byte length must be a positive signed-int64 integer"
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
            "Greengage range comparison requires one non-null logical INT64 key field"
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
) -> tuple[sql.Composable, tuple[GreengageEndpointParameter, ...]]:
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
) -> tuple[sql.Composable, tuple[GreengageEndpointParameter, ...]]:
    if scope is None:
        return sql.SQL("TRUE"), ()
    if not isinstance(cast(object, scope), PostgresScopePredicate):
        raise PostgresLoweringError("Greengage scope must be a PostgresScopePredicate or None")
    matches = tuple(binding for binding in bindings if binding.column_name == scope.column_name)
    if len(matches) != 1:
        raise PostgresLoweringError(
            "Greengage scope column must map to exactly one protected field: "
            f"column={scope.column_name!r}, matching_fields={len(matches)}"
        )
    value = decode_payload(scope.field, scope.canonical_payload)
    column = sql.Identifier(source_alias, scope.column_name)
    cast_name, parameter = _scope_parameter(scope.field, value)
    predicate = sql.SQL("{column} IS NOT NULL AND {column} = %s::{cast_name}").format(
        column=column,
        cast_name=sql.SQL(cast(LiteralString, cast_name)),
    )
    return predicate, (parameter,)


def _scope_parameter(
    field: FieldSchema,
    value: int | Decimal | bool | str | date,
) -> tuple[str, GreengageEndpointParameter]:
    logical_type = field.logical_type
    if logical_type is LogicalType.INT64:
        if type(value) is not int:
            raise PostgresLoweringError("decoded Greengage INT64 scope must be an integer")
        return "bigint", value
    if logical_type is LogicalType.DECIMAL:
        if not isinstance(value, Decimal):
            raise PostgresLoweringError("decoded Greengage DECIMAL scope must be a Decimal")
        return "numeric", str(value)
    if logical_type is LogicalType.BOOLEAN:
        if type(value) is not bool:
            raise PostgresLoweringError("decoded Greengage BOOLEAN scope must be a boolean")
        return "boolean", "true" if value else "false"
    if logical_type is LogicalType.DATE:
        if type(value) is not date:
            raise PostgresLoweringError("decoded Greengage DATE scope must be a date")
        return "date", value.isoformat()
    if logical_type is LogicalType.TIMESTAMP_LOCAL:
        if type(value) is not str:
            raise PostgresLoweringError(
                "decoded Greengage local timestamp scope must be canonical text"
            )
        return "timestamp", value
    if logical_type is LogicalType.TIMESTAMP_INSTANT:
        if type(value) is not str:
            raise PostgresLoweringError(
                "decoded Greengage instant timestamp scope must be canonical text"
            )
        return "timestamptz", value
    if logical_type is LogicalType.STRING:
        if type(value) is not str:
            raise PostgresLoweringError("decoded Greengage STRING scope must be text")
        return "text", value
    raise PostgresLoweringError(
        f"logical type {logical_type!r} is unsupported for Greengage scope equality"
    )


def _validate_ranges(value: object) -> None:
    if type(value) is not tuple or not value:
        raise PostgresLoweringError(
            "Greengage integer-range requests must be a non-empty immutable tuple"
        )
    ranges = cast(tuple[object, ...], value)
    seen_ids: set[str] = set()
    previous_upper: int | None = None
    for index, item in enumerate(ranges):
        if not isinstance(item, PostgresIntegerRangeRequest):
            raise PostgresLoweringError(
                f"Greengage integer-range request has an unexpected type: range_index={index}"
            )
        if item.segment_id in seen_ids:
            raise PostgresLoweringError(
                "Greengage integer-range segment IDs must be unique within a query"
            )
        seen_ids.add(item.segment_id)
        if index > 0:
            if previous_upper is None:
                raise PostgresLoweringError("Greengage unbounded integer range must be last")
            if item.lower_inclusive < previous_upper:
                raise PostgresLoweringError("Greengage integer ranges must be ordered and disjoint")
        previous_upper = item.upper_exclusive


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


def _range_projection(
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    key_column: sql.Identifier,
) -> tuple[sql.Composable, sql.Composable, sql.Composable]:
    conditions = tuple(_range_condition(item, key_column) for item in ranges)
    range_id = sql.SQL("CASE {branches} ELSE NULL::text END").format(
        branches=sql.SQL(" ").join(
            sql.SQL("WHEN {condition} THEN {segment_id}::text").format(
                condition=condition,
                segment_id=sql.Literal(item.segment_id),
            )
            for item, condition in zip(ranges, conditions, strict=True)
        )
    )
    range_ordinal = sql.SQL("CASE {branches} ELSE NULL::integer END").format(
        branches=sql.SQL(" ").join(
            sql.SQL("WHEN {condition} THEN {ordinal}::integer").format(
                condition=condition,
                ordinal=sql.Literal(ordinal),
            )
            for ordinal, condition in enumerate(conditions)
        )
    )
    return range_id, range_ordinal, sql.SQL(" OR ").join(conditions)


def _range_condition(
    item: PostgresIntegerRangeRequest,
    key_column: sql.Identifier,
) -> sql.Composable:
    lower = sql.SQL("{key_column} >= {lower}").format(
        key_column=key_column,
        lower=_bigint_literal(item.lower_inclusive),
    )
    if item.upper_exclusive is None:
        return lower
    return sql.SQL("({lower} AND {key_column} < {upper})").format(
        lower=lower,
        key_column=key_column,
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
        raise ValueError("Greengage fingerprint query requires active primary content IDs")
    for content_id in content_ids:
        if type(content_id) is not int or not 0 <= content_id <= INT64_MAX:
            raise ValueError(
                "Greengage primary content ID must be a non-negative signed-int64 integer"
            )
    if tuple(sorted(set(content_ids))) != content_ids:
        raise ValueError("Greengage primary content IDs must be distinct and strictly increasing")
