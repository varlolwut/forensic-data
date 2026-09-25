from collections.abc import Callable
from dataclasses import dataclass
from typing import final

from psycopg import sql

from forensic_data.canonical import (
    CanonicalSchema,
    Fingerprint,
    FingerprintOverflowError,
)
from forensic_data.canonical.model import DECIMAL_38_MAX, UINT32_MAX
from forensic_data.canonical.schema import CanonicalEnvelopeContext, prepare_envelope_context
from forensic_data.greenplum_catalog import (
    GreenplumCatalogDataError,
    GreenplumCatalogMetadataError,
    GreenplumCatalogParameter,
    GreenplumRelationRequest,
)
from forensic_data.postgres import INT64_MAX, DatabaseRow
from forensic_data.postgres_sql import (
    PostgresFieldBinding,
    lower_postgres_canonical_row,
)


@final
@dataclass(frozen=True, slots=True)
class GreenplumCanonicalProbeRequest(GreenplumRelationRequest):
    schema: CanonicalSchema
    max_encoded_envelope_bytes: int

    def __post_init__(self) -> None:
        GreenplumRelationRequest.__post_init__(self)
        if type(self.schema) is not CanonicalSchema:
            raise TypeError("Greenplum canonical probe schema must be a CanonicalSchema")
        field_names = tuple(field.name for field in self.schema.fields)
        requested_field_names = tuple(column.field_name for column in self.columns)
        if requested_field_names != field_names:
            raise ValueError(
                "Greenplum canonical probe columns must follow canonical schema field order"
            )
        if (
            type(self.max_encoded_envelope_bytes) is not int
            or self.max_encoded_envelope_bytes < 1
            or self.max_encoded_envelope_bytes > INT64_MAX
        ):
            raise ValueError(
                "Greenplum canonical envelope limit must be a positive signed-int64 integer"
            )


@final
@dataclass(frozen=True, slots=True)
class GreenplumCanonicalFingerprintQuery:
    statement: str
    parameters: tuple[GreenplumCatalogParameter, ...]
    context: CanonicalEnvelopeContext
    relation_row_type_oid: int
    relation_name: str
    primary_content_ids: tuple[int, ...]
    max_encoded_envelope_bytes: int


@final
@dataclass(frozen=True, slots=True)
class GreenplumCanonicalFingerprintPlan:
    lines: tuple[str, ...]
    scanned_relation: str
    dispatched_primary_count: int
    topology_seeded: bool
    execution_locus: str


@final
@dataclass(frozen=True, slots=True)
class GreenplumCanonicalFingerprint:
    relation_row_type_oid: int
    fingerprint: Fingerprint
    invalid_row_count: int
    oversized_row_count: int
    topology_content_ids: tuple[int, ...]
    observed_content_ids: tuple[int, ...]


@final
@dataclass(frozen=True, slots=True)
class _GreenplumCanonicalPlanShape:
    lines: tuple[str, ...]
    lower_aggregate_subtree: str


def build_original_greenplum_fingerprint_query(
    request: GreenplumCanonicalProbeRequest,
    relation_row_type_oid: int,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    primary_content_ids: tuple[int, ...],
) -> GreenplumCanonicalFingerprintQuery:
    return _build_greenplum_fingerprint_query(
        request,
        relation_row_type_oid,
        bindings,
        max_identifier_utf8_bytes,
        primary_content_ids,
        sql.SQL("dfe_ext.digest(pg_catalog.convert_to(dfe_row.envelope, 'UTF8'), 'sha256'::text)"),
    )


def build_greengage_fingerprint_query(
    request: GreenplumCanonicalProbeRequest,
    relation_row_type_oid: int,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    primary_content_ids: tuple[int, ...],
) -> GreenplumCanonicalFingerprintQuery:
    return _build_greenplum_fingerprint_query(
        request,
        relation_row_type_oid,
        bindings,
        max_identifier_utf8_bytes,
        primary_content_ids,
        sql.SQL("pg_catalog.sha256(pg_catalog.convert_to(dfe_row.envelope, 'UTF8'))"),
    )


def parse_greenplum_canonical_fingerprint(
    rows: tuple[DatabaseRow, ...],
    query: GreenplumCanonicalFingerprintQuery,
) -> GreenplumCanonicalFingerprint:
    if len(rows) != 1:
        raise GreenplumCatalogDataError(
            f"Greenplum canonical fingerprint query must return exactly one row: actual={len(rows)}"
        )
    row = rows[0]
    if len(row) != 14:
        raise GreenplumCatalogDataError(
            "Greenplum canonical fingerprint row must contain exactly fourteen fields: "
            f"actual={len(row)}"
        )
    relation_row_type_oid = _require_integer(
        row[0],
        "Greenplum canonical fingerprint relation row type OID",
        1,
        UINT32_MAX,
    )
    if relation_row_type_oid != query.relation_row_type_oid:
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical fingerprint relation provenance changed: "
            f"expected_row_type_oid={query.relation_row_type_oid}, "
            f"actual_row_type_oid={relation_row_type_oid}"
        )
    valid_row_count = _parse_unsigned_decimal_text(
        row[1],
        "Greenplum canonical fingerprint valid row count",
        INT64_MAX,
    )
    limb_sums = tuple(
        _parse_unsigned_decimal_text(
            row[index],
            f"Greenplum canonical fingerprint limb {index - 2}",
            DECIMAL_38_MAX,
        )
        for index in range(2, 10)
    )
    invalid_row_count = _parse_unsigned_decimal_text(
        row[10],
        "Greenplum canonical fingerprint invalid row count",
        INT64_MAX,
    )
    oversized_row_count = _parse_unsigned_decimal_text(
        row[11],
        "Greenplum canonical fingerprint oversized row count",
        INT64_MAX,
    )
    topology_content_ids = _parse_required_content_ids_text(
        row[12],
        "Greenplum canonical fingerprint live topology content IDs",
    )
    observed_content_ids = _parse_optional_content_ids_text(
        row[13],
        "Greenplum canonical fingerprint observed content IDs",
    )
    expected_content_ids = query.primary_content_ids
    if topology_content_ids != expected_content_ids:
        expected_set = frozenset(expected_content_ids)
        actual_set = frozenset(topology_content_ids)
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical fingerprint active-primary topology changed within the "
            "read-only probe: "
            f"missing_content_ids={tuple(sorted(expected_set - actual_set))!r}, "
            f"unexpected_content_ids={tuple(sorted(actual_set - expected_set))!r}"
        )
    unexpected_content_ids = tuple(
        sorted(frozenset(observed_content_ids) - frozenset(topology_content_ids))
    )
    if unexpected_content_ids:
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical fingerprint encountered segment aggregates outside the "
            "captured active-primary topology: "
            f"unexpected_content_ids={unexpected_content_ids!r}, "
            f"captured_primary_content_ids={expected_content_ids!r}"
        )
    if invalid_row_count != 0:
        raise GreenplumCatalogDataError(
            "Greenplum canonical fingerprint rejected source rows that cannot be "
            f"represented losslessly: invalid_row_count={invalid_row_count}"
        )
    if oversized_row_count != 0:
        raise GreenplumCatalogDataError(
            "Greenplum canonical fingerprint found source rows above the configured "
            "envelope limit: "
            f"oversized_row_count={oversized_row_count}, "
            f"max_encoded_envelope_bytes={query.max_encoded_envelope_bytes}"
        )
    try:
        fingerprint = Fingerprint(
            count=valid_row_count,
            limb_sums=(
                limb_sums[0],
                limb_sums[1],
                limb_sums[2],
                limb_sums[3],
                limb_sums[4],
                limb_sums[5],
                limb_sums[6],
                limb_sums[7],
            ),
        )
    except FingerprintOverflowError as error:
        raise GreenplumCatalogDataError(
            "Greenplum canonical fingerprint violates exact accumulator bounds: "
            f"reason_type={type(error).__name__}, reason={str(error)!r}"
        ) from None
    return GreenplumCanonicalFingerprint(
        relation_row_type_oid=relation_row_type_oid,
        fingerprint=fingerprint,
        invalid_row_count=invalid_row_count,
        oversized_row_count=oversized_row_count,
        topology_content_ids=topology_content_ids,
        observed_content_ids=observed_content_ids,
    )


def parse_original_greenplum_fingerprint_plan(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumCanonicalProbeRequest,
    primary_count: int,
    hash_function_oid: int,
) -> GreenplumCanonicalFingerprintPlan:
    _require_integer(hash_function_oid, "original Greenplum hash function OID", 1, UINT32_MAX)
    shape = _parse_greenplum_fingerprint_plan_shape(rows, request, primary_count)
    serialized_plan = "\n".join(shape.lines)
    for index in range(8):
        if f":resname limb_{index}" not in serialized_plan:
            raise GreenplumCatalogMetadataError(
                "Original Greenplum canonical fingerprint plan omits an exact limb "
                f"aggregate target: limb_index={index}"
            )
    append_index = _find_serialized_plan_node(
        shape.lines,
        "{APPEND",
        0,
        "topology-seeded append",
    )
    data_subquery_index = _find_serialized_plan_node(
        shape.lines,
        "{SUBQUERYSCAN",
        append_index + 1,
        "data aggregate subquery below the topology-seeded append",
    )
    segment_aggregate_index = _find_serialized_plan_node(
        shape.lines,
        "{AGG",
        data_subquery_index + 1,
        "segment aggregate above redistribution",
    )
    redistribute_index = _find_serialized_plan_node(
        shape.lines,
        "{MOTION",
        segment_aggregate_index + 1,
        "segment redistribution motion",
    )
    partial_aggregate_index = _find_serialized_plan_node(
        shape.lines,
        "{AGG",
        redistribute_index + 1,
        "partial segment aggregate below redistribution",
    )
    row_subquery_index = _find_serialized_plan_node(
        shape.lines,
        "{SUBQUERYSCAN",
        partial_aggregate_index + 1,
        "hashed-row subquery below the partial segment aggregate",
    )
    relation_scan_index = _find_serialized_plan_node(
        shape.lines,
        "{SEQSCAN",
        row_subquery_index + 1,
        "canonical relation scan below the partial segment aggregate",
    )
    append_node_id, _ = _serialized_plan_node_identity(
        shape.lines,
        append_index,
        "topology-seeded append",
    )
    data_subquery_node_id, data_subquery_parent_id = _serialized_plan_node_identity(
        shape.lines,
        data_subquery_index,
        "data aggregate subquery",
    )
    segment_aggregate_node_id, segment_aggregate_parent_id = _serialized_plan_node_identity(
        shape.lines,
        segment_aggregate_index,
        "segment aggregate above redistribution",
    )
    redistribute_node_id, redistribute_parent_id = _serialized_plan_node_identity(
        shape.lines,
        redistribute_index,
        "segment redistribution motion",
    )
    partial_aggregate_node_id, partial_aggregate_parent_id = _serialized_plan_node_identity(
        shape.lines,
        partial_aggregate_index,
        "partial segment aggregate",
    )
    row_subquery_node_id, row_subquery_parent_id = _serialized_plan_node_identity(
        shape.lines,
        row_subquery_index,
        "hashed-row subquery",
    )
    _, relation_scan_parent_id = _serialized_plan_node_identity(
        shape.lines,
        relation_scan_index,
        "canonical relation scan",
    )
    actual_parent_ids = (
        data_subquery_parent_id,
        segment_aggregate_parent_id,
        redistribute_parent_id,
        partial_aggregate_parent_id,
        row_subquery_parent_id,
        relation_scan_parent_id,
    )
    expected_parent_ids = (
        append_node_id,
        data_subquery_node_id,
        segment_aggregate_node_id,
        redistribute_node_id,
        partial_aggregate_node_id,
        row_subquery_node_id,
    )
    if actual_parent_ids != expected_parent_ids:
        raise GreenplumCatalogMetadataError(
            "Original Greenplum canonical fingerprint serialized plan does not preserve the "
            "required append-to-relation-scan parent chain: "
            f"expected_parent_ids={expected_parent_ids!r}, "
            f"actual_parent_ids={actual_parent_ids!r}"
        )
    partial_aggregate_prefix = shape.lines[partial_aggregate_index:relation_scan_index]
    numeric_aggregate_count = sum(
        1
        for index, line in enumerate(partial_aggregate_prefix[:-2])
        if line.strip() == "{AGGREF"
        and partial_aggregate_prefix[index + 2].strip() == ":aggtype 1700"
    )
    if numeric_aggregate_count != 8:
        raise GreenplumCatalogMetadataError(
            "Original Greenplum canonical fingerprint plan does not expose eight exact "
            "numeric limb aggregate expressions below redistribution: "
            f"actual={numeric_aggregate_count}"
        )
    hash_function_marker = f":funcid {hash_function_oid}"
    hash_expression_count = sum(
        1
        for index, line in enumerate(partial_aggregate_prefix[:-2])
        if line.strip() == "{FUNCEXPR"
        and partial_aggregate_prefix[index + 1].strip() == hash_function_marker
        and partial_aggregate_prefix[index + 2].strip() == ":funcresulttype 17"
    )
    if hash_expression_count != 1:
        raise GreenplumCatalogMetadataError(
            "Original Greenplum canonical fingerprint plan does not expose exactly one "
            "selected bytea hash expression below redistribution: "
            f"hash_function_oid={hash_function_oid}, actual={hash_expression_count}"
        )
    return _canonical_fingerprint_plan(
        shape.lines,
        request,
        primary_count,
        "original_greenplum_cte_segment_aggregate_below_motion",
    )


def parse_greengage_fingerprint_plan(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumCanonicalProbeRequest,
    primary_count: int,
) -> GreenplumCanonicalFingerprintPlan:
    shape = _parse_greenplum_fingerprint_plan_shape(rows, request, primary_count)
    if "sha256(" not in shape.lower_aggregate_subtree:
        raise GreenplumCatalogMetadataError(
            "Greengage canonical fingerprint plan does not hash below Motion"
        )
    if (
        shape.lower_aggregate_subtree.count("sum(") < 8
        or shape.lower_aggregate_subtree.count("get_byte(") < 32
        or "numeric(38,0)" not in shape.lower_aggregate_subtree
    ):
        raise GreenplumCatalogMetadataError(
            "Greengage canonical fingerprint plan does not expose eight exact numeric limb "
            "sums below Motion"
        )
    full_plan = "\n".join(shape.lines).lower()
    for index in range(8):
        if f"limb_{index}" not in full_plan:
            raise GreenplumCatalogMetadataError(
                "Greengage canonical fingerprint plan omits an exact limb aggregate "
                f"target: limb_index={index}"
            )
    return _canonical_fingerprint_plan(
        shape.lines,
        request,
        primary_count,
        "greengage_cte_segment_aggregate_below_motion",
    )


def _build_greenplum_fingerprint_query(
    request: GreenplumCanonicalProbeRequest,
    relation_row_type_oid: int,
    bindings: tuple[PostgresFieldBinding, ...],
    max_identifier_utf8_bytes: int,
    primary_content_ids: tuple[int, ...],
    digest_expression: sql.Composable,
) -> GreenplumCanonicalFingerprintQuery:
    _validate_integer_argument(
        relation_row_type_oid,
        "Greenplum canonical relation row type OID",
        1,
        UINT32_MAX,
    )
    _validate_primary_content_ids(primary_content_ids)
    context = prepare_envelope_context(request.schema)
    source_alias = "dfe_origin"
    row = lower_postgres_canonical_row(
        request.schema,
        bindings,
        max_identifier_utf8_bytes,
        request.max_encoded_envelope_bytes,
        source_alias,
    )
    relation = sql.Identifier(request.schema_name, request.relation_name)
    source = sql.Identifier(source_alias)
    source_rows = sql.SQL(
        "SELECT gp_segment_id::integer AS segment_id, {envelope} AS envelope, "
        "{invalid_row} AS invalid_row, {oversized_row} AS oversized_row "
        "FROM ONLY {relation} AS {source}"
    ).format(
        envelope=row.envelope,
        invalid_row=row.invalid_row,
        oversized_row=row.oversized_row,
        relation=relation,
        source=source,
    )
    hashed_rows = sql.SQL(
        "SELECT dfe_row.segment_id, dfe_row.invalid_row, dfe_row.oversized_row, "
        "CASE WHEN dfe_row.envelope IS NULL THEN NULL::bytea "
        "ELSE {digest} END AS row_hash FROM dfe_source AS dfe_row"
    ).format(digest=digest_expression)
    segment_limb_sums = sql.SQL(", ").join(
        _segment_limb_sum_expression(index) for index in range(8)
    )
    segment_aggregate = sql.SQL(
        "SELECT dfe_hash.segment_id, "
        "count(CASE WHEN NOT dfe_hash.invalid_row AND NOT dfe_hash.oversized_row "
        "THEN 1 ELSE NULL END)::numeric AS valid_row_count, "
        "{limb_sums}, "
        "count(CASE WHEN dfe_hash.invalid_row THEN 1 ELSE NULL END)::numeric "
        "AS invalid_row_count, "
        "count(CASE WHEN dfe_hash.oversized_row THEN 1 ELSE NULL END)::numeric "
        "AS oversized_row_count "
        "FROM dfe_hashed AS dfe_hash GROUP BY dfe_hash.segment_id"
    ).format(limb_sums=segment_limb_sums)
    combined_limb_sums = sql.SQL(", ").join(
        _combined_limb_sum_expression(index) for index in range(8)
    )
    statement = sql.SQL(
        "WITH dfe_source AS ({source_rows}), "
        "dfe_hashed AS ({hashed_rows}), "
        "dfe_segment AS ({segment_aggregate}), "
        "dfe_member AS ("
        "SELECT dfe_segment.segment_id, dfe_segment.valid_row_count, "
        "dfe_segment.limb_0, dfe_segment.limb_1, dfe_segment.limb_2, "
        "dfe_segment.limb_3, dfe_segment.limb_4, dfe_segment.limb_5, "
        "dfe_segment.limb_6, dfe_segment.limb_7, "
        "dfe_segment.invalid_row_count, dfe_segment.oversized_row_count, "
        "1::integer AS member_kind FROM dfe_segment "
        "UNION ALL SELECT gp_segment_id::integer AS segment_id, "
        "0::numeric AS valid_row_count, 0::numeric(38, 0) AS limb_0, "
        "0::numeric(38, 0) AS limb_1, 0::numeric(38, 0) AS limb_2, "
        "0::numeric(38, 0) AS limb_3, 0::numeric(38, 0) AS limb_4, "
        "0::numeric(38, 0) AS limb_5, 0::numeric(38, 0) AS limb_6, "
        "0::numeric(38, 0) AS limb_7, 0::numeric AS invalid_row_count, "
        "0::numeric AS oversized_row_count, 0::integer AS member_kind "
        "FROM gp_dist_random('gp_id')) "
        "SELECT (pg_catalog.pg_typeof(NULL::{relation}))::oid::bigint "
        "AS relation_row_type_oid, "
        "coalesce(sum(dfe_member.valid_row_count::numeric), "
        "0::numeric)::text AS valid_row_count, {limb_sums}, "
        "coalesce(sum(dfe_member.invalid_row_count::numeric), "
        "0::numeric)::text AS invalid_row_count, "
        "coalesce(sum(dfe_member.oversized_row_count::numeric), "
        "0::numeric)::text AS oversized_row_count, "
        "coalesce(pg_catalog.array_to_string("
        "pg_catalog.array_agg(CASE WHEN dfe_member.member_kind = 0 "
        "THEN dfe_member.segment_id ELSE NULL::integer END), ','), '') "
        "AS topology_content_ids, "
        "coalesce(pg_catalog.array_to_string("
        "pg_catalog.array_agg(CASE WHEN dfe_member.member_kind = 1 "
        "THEN dfe_member.segment_id ELSE NULL::integer END), ','), '') "
        "AS observed_content_ids FROM dfe_member"
    ).format(
        source_rows=source_rows,
        hashed_rows=hashed_rows,
        segment_aggregate=segment_aggregate,
        relation=relation,
        limb_sums=combined_limb_sums,
    )
    return GreenplumCanonicalFingerprintQuery(
        statement=statement.as_string(),
        parameters=(context.schema_digest_hex, len(context.schema.fields)),
        context=context,
        relation_row_type_oid=relation_row_type_oid,
        relation_name=f"{request.schema_name}.{request.relation_name}",
        primary_content_ids=primary_content_ids,
        max_encoded_envelope_bytes=request.max_encoded_envelope_bytes,
    )


def _segment_limb_sum_expression(index: int) -> sql.Composable:
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


def _combined_limb_sum_expression(index: int) -> sql.Composable:
    alias = sql.Identifier(f"limb_{index}")
    return sql.SQL(
        "coalesce(sum(dfe_member.{alias}::numeric(38, 0)), 0::numeric(38, 0))::text AS {alias}"
    ).format(alias=alias)


def _parse_greenplum_fingerprint_plan_shape(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumCanonicalProbeRequest,
    primary_count: int,
) -> _GreenplumCanonicalPlanShape:
    _require_integer(primary_count, "Greenplum primary segment count", 1, INT64_MAX)
    lines = _plan_lines(rows)
    human_nodes = tuple((index, line) for index, line in enumerate(lines) if "(cost=" in line)
    outer_aggregate_index = _find_human_node(
        human_nodes,
        lambda line: "aggregate" in line.lower(),
        0,
        "coordinator aggregate",
    )
    motion_index = _find_human_node(
        human_nodes,
        lambda line: (
            "gather motion" in line.lower() and f"segments: {primary_count}" in line.lower()
        ),
        outer_aggregate_index + 1,
        "distributed gather motion",
    )
    append_index = _find_human_node(
        human_nodes,
        lambda line: "append" in line.lower(),
        motion_index + 1,
        "topology-seeded append",
    )
    relation_scan_index = _find_human_node(
        human_nodes,
        lambda line: "seq scan" in line.lower() and request.relation_name.lower() in line.lower(),
        append_index + 1,
        "canonical relation scan",
    )
    topology_scan_index = _find_human_node(
        human_nodes,
        lambda line: "seq scan" in line.lower() and "gp_id" in line.lower(),
        append_index + 1,
        "dynamic segment topology seed",
    )
    outer_aggregate_indent = _indent(lines[outer_aggregate_index])
    motion_indent = _indent(lines[motion_index])
    append_indent = _indent(lines[append_index])
    motion_subtree_end = _human_subtree_end(human_nodes, motion_index, len(lines))
    append_subtree_end = _human_subtree_end(human_nodes, append_index, len(lines))
    if (
        motion_indent <= outer_aggregate_indent
        or append_indent <= motion_indent
        or append_index >= motion_subtree_end
        or relation_scan_index >= append_subtree_end
        or topology_scan_index >= append_subtree_end
        or _indent(lines[relation_scan_index]) <= append_indent
        or _indent(lines[topology_scan_index]) <= append_indent
    ):
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical fingerprint plan does not keep the data and dynamic "
            "topology branches below distributed Motion"
        )
    aggregate_indexes = tuple(
        index
        for index, line in human_nodes
        if append_index < index < relation_scan_index
        and "aggregate" in line.lower()
        and _indent(line) > append_indent
    )
    if not aggregate_indexes:
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical fingerprint plan does not aggregate on segments below Motion"
        )
    segment_aggregate_index = aggregate_indexes[0]
    segment_aggregate_indent = _indent(lines[segment_aggregate_index])
    if _indent(lines[relation_scan_index]) <= segment_aggregate_indent:
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical relation scan is not below the segment aggregate"
        )
    lower_subtree_end = _human_subtree_end(
        human_nodes,
        segment_aggregate_index,
        len(lines),
    )
    if relation_scan_index >= lower_subtree_end:
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical relation scan is outside the segment aggregate subtree"
        )
    return _GreenplumCanonicalPlanShape(
        lines=lines,
        lower_aggregate_subtree="\n".join(lines[segment_aggregate_index:lower_subtree_end]).lower(),
    )


def _canonical_fingerprint_plan(
    lines: tuple[str, ...],
    request: GreenplumCanonicalProbeRequest,
    primary_count: int,
    execution_locus: str,
) -> GreenplumCanonicalFingerprintPlan:
    return GreenplumCanonicalFingerprintPlan(
        lines=lines,
        scanned_relation=f"{request.schema_name}.{request.relation_name}",
        dispatched_primary_count=primary_count,
        topology_seeded=True,
        execution_locus=execution_locus,
    )


def _plan_lines(rows: tuple[DatabaseRow, ...]) -> tuple[str, ...]:
    if not rows:
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical fingerprint EXPLAIN VERBOSE returned no plan lines"
        )
    lines: list[str] = []
    for index, row in enumerate(rows):
        if len(row) != 1:
            raise GreenplumCatalogDataError(
                "Greenplum canonical fingerprint plan row must contain one field: "
                f"row_index={index}, actual={len(row)}"
            )
        value = row[0]
        if type(value) is not str:
            raise GreenplumCatalogDataError(
                f"Greenplum canonical fingerprint plan line {index} must be text"
            )
        if "\x00" in value:
            raise GreenplumCatalogDataError(
                f"Greenplum canonical fingerprint plan line {index} must not contain U+0000"
            )
        if value:
            lines.append(value)
    if not lines:
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical fingerprint EXPLAIN VERBOSE returned only empty plan lines"
        )
    return tuple(lines)


def _find_human_node(
    nodes: tuple[tuple[int, str], ...],
    predicate: Callable[[str], bool],
    start_line: int,
    label: str,
) -> int:
    for index, line in nodes:
        if index >= start_line and predicate(line):
            return index
    raise GreenplumCatalogMetadataError(
        f"Greenplum canonical fingerprint plan is missing required evidence: {label!r}"
    )


def _find_serialized_plan_node(
    lines: tuple[str, ...],
    node: str,
    start_line: int,
    label: str,
) -> int:
    for index in range(start_line, len(lines)):
        if lines[index].strip() == node:
            return index
    raise GreenplumCatalogMetadataError(
        "Original Greenplum canonical fingerprint plan is missing required serialized "
        f"evidence: {label!r}"
    )


def _serialized_plan_node_identity(
    lines: tuple[str, ...],
    node_index: int,
    label: str,
) -> tuple[int, int]:
    node_id: int | None = None
    parent_node_id: int | None = None
    for line in lines[node_index + 1 :]:
        stripped = line.strip()
        if stripped == ":targetlist (":
            break
        if stripped.startswith(":plan_node_id "):
            node_id = _parse_serialized_plan_node_id(stripped, ":plan_node_id ", label)
        if stripped.startswith(":plan_parent_node_id "):
            parent_node_id = _parse_serialized_plan_node_id(
                stripped,
                ":plan_parent_node_id ",
                label,
            )
    if node_id is None or parent_node_id is None:
        raise GreenplumCatalogMetadataError(
            "Original Greenplum canonical fingerprint serialized plan node omits its identity: "
            f"node={label!r}"
        )
    return node_id, parent_node_id


def _parse_serialized_plan_node_id(line: str, prefix: str, label: str) -> int:
    value = line.removeprefix(prefix)
    if not value or not value.isascii() or not value.isdecimal():
        raise GreenplumCatalogMetadataError(
            "Original Greenplum canonical fingerprint serialized plan node has an invalid "
            f"identity: node={label!r}, value={value!r}"
        )
    return int(value)


def _human_subtree_end(
    nodes: tuple[tuple[int, str], ...],
    root_index: int,
    plan_end: int,
) -> int:
    matching_roots = tuple(line for index, line in nodes if index == root_index)
    if len(matching_roots) != 1:
        raise GreenplumCatalogMetadataError(
            "Greenplum canonical fingerprint plan subtree root is ambiguous"
        )
    root_indent = _indent(matching_roots[0])
    for index, line in nodes:
        if index > root_index and _indent(line) <= root_indent:
            return index
    return plan_end


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _validate_primary_content_ids(content_ids: tuple[int, ...]) -> None:
    if type(content_ids) is not tuple or not content_ids:
        raise ValueError("Greenplum canonical query requires active primary content IDs")
    for content_id in content_ids:
        _validate_integer_argument(
            content_id,
            "Greenplum primary content ID",
            0,
            INT64_MAX,
        )
    if tuple(sorted(set(content_ids))) != content_ids:
        raise ValueError("Greenplum primary content IDs must be distinct and strictly increasing")


def _parse_unsigned_decimal_text(value: object, label: str, maximum: int) -> int:
    if type(value) is not str or not value or not value.isascii() or not value.isdecimal():
        raise GreenplumCatalogDataError(f"{label} must be canonical unsigned decimal text")
    if len(value) > 1 and value.startswith("0"):
        raise GreenplumCatalogDataError(f"{label} must not contain leading zeroes")
    parsed = int(value)
    if parsed > maximum:
        raise GreenplumCatalogDataError(f"{label} exceeds its exact numeric bound")
    return parsed


def _parse_required_content_ids_text(
    value: object,
    label: str,
) -> tuple[int, ...]:
    if type(value) is not str or not value.isascii():
        raise GreenplumCatalogDataError(f"{label} must be ASCII text")
    if value == "":
        raise GreenplumCatalogMetadataError(f"{label} must not be empty")
    return _parse_content_ids(value, label)


def _parse_optional_content_ids_text(
    value: object,
    label: str,
) -> tuple[int, ...]:
    if type(value) is not str or not value.isascii():
        raise GreenplumCatalogDataError(f"{label} must be ASCII text")
    if value == "":
        return ()
    return _parse_content_ids(value, label)


def _parse_content_ids(value: str, label: str) -> tuple[int, ...]:
    content_ids = tuple(
        _parse_unsigned_decimal_text(item, f"{label} item {index}", INT64_MAX)
        for index, item in enumerate(value.split(","))
    )
    if len(frozenset(content_ids)) != len(content_ids):
        raise GreenplumCatalogMetadataError(f"{label} must contain unique segment IDs")
    return tuple(sorted(content_ids))


def _require_integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise GreenplumCatalogDataError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _validate_integer_argument(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must be in [{minimum}, {maximum}]")
