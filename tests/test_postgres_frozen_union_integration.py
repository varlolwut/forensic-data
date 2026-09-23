from typing import cast
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
)
from forensic_data.contracts.model import RelationScope
from forensic_data.postgres import (
    PostgresInheritanceDetachState,
    PostgresIntegerKeySummary,
    PostgresProtectedReadContext,
    PostgresProtectedRelationInspection,
    PostgresRelationAcquisition,
    PostgresRelationKind,
    PostgresRetryPolicy,
    PostgresSourceDirection,
    open_postgres_protected_read_context,
)
from forensic_data.postgres_legacy import open_postgres_9_6_protected_read_context
from forensic_data.postgres_sql import (
    PostgresQuery,
    PostgresRelation,
    build_postgres_legacy_union_integer_key_summary_query,
    build_postgres_union_integer_key_summary_query,
)
from tests.postgres_support import (
    connect_writer,
    required_connection_settings,
    source_budget_attempt,
)

pytestmark = [pytest.mark.integration, pytest.mark.postgres]

_METADATA_RECORD_BYTES = 4_096
_METADATA_TOTAL_BYTES = 65_536
_POSTGRES_17_READER = required_connection_settings(
    "DFE_TEST_POSTGRES_READER_DSN",
    "dfe-p0209-frozen-union-pg17-reader",
)
_POSTGRES_17_WRITER = required_connection_settings(
    "DFE_TEST_POSTGRES_WRITER_DSN",
    "dfe-p0209-frozen-union-pg17-writer",
)
_POSTGRES_9_6_READER = required_connection_settings(
    "DFE_TEST_POSTGRES_LEGACY_SOURCE_DSN",
    "dfe-p0209-frozen-union-pg96-reader",
)
_NO_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)


def test_postgres_17_partition_hierarchy_is_frozen_as_one_physical_union() -> None:
    namespace = f"dfe_union_{uuid4().hex}"
    relation = PostgresRelation(components=(namespace, "union_root"))
    writer = connect_writer(_POSTGRES_17_WRITER)
    context = None
    try:
        _create_postgres_17_partition_hierarchy(writer, namespace)
        context = open_postgres_protected_read_context(
            _POSTGRES_17_READER,
            _NO_RETRY,
            (_acquisition(relation),),
            4_000,
            source_budget_attempt(),
            PostgresSourceDirection.REFERENCE,
        )
        protected = context.protected_relations[0]

        _assert_composition(
            protected,
            {
                "union_root": PostgresRelationKind.PARTITIONED,
                "union_branch": PostgresRelationKind.PARTITIONED,
                "union_empty": PostgresRelationKind.REGULAR,
                "union_high": PostgresRelationKind.REGULAR,
                "union_low": PostgresRelationKind.REGULAR,
            },
            {
                ("union_root", "union_branch", 1),
                ("union_root", "union_empty", 1),
                ("union_branch", "union_high", 1),
                ("union_branch", "union_low", 1),
            },
            PostgresInheritanceDetachState.ATTACHED,
        )
        assert protected.physical_scan_count() == 3
        _exercise_late_membership_changes(writer, namespace, protected)

        summary = _read_key_summary(context, protected)
        assert (
            summary.row_count,
            summary.null_key_count,
            summary.invalid_key_count,
            summary.valid_key_count,
            summary.distinct_key_count,
            summary.minimum_key,
            summary.maximum_key,
            summary.usable_access_path,
        ) == (3, 1, 0, 2, 1, 1, 1, True)

        query = build_postgres_union_integer_key_summary_query(
            _union_schema(),
            protected.query_relations(),
            0,
            None,
            1_024,
        )
        _assert_only_member_scans(
            writer,
            query,
            protected,
            {"union_empty", "union_high", "union_low"},
        )
    finally:
        if context is not None:
            context.close()
        writer.execute(
            sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(namespace))
        )
        writer.close()


def test_postgres_9_6_inheritance_hierarchy_is_frozen_as_one_physical_union() -> None:
    relation = PostgresRelation(components=("dfe_legacy", "union_root"))
    context = open_postgres_9_6_protected_read_context(
        _POSTGRES_9_6_READER,
        _NO_RETRY,
        (_acquisition(relation),),
        4_000,
        source_budget_attempt(),
        PostgresSourceDirection.REFERENCE,
    )
    reader = connect_writer(_POSTGRES_9_6_READER)
    try:
        protected = context.protected_relations[0]
        member_kinds = {
            "union_root": PostgresRelationKind.REGULAR,
            "union_child": PostgresRelationKind.REGULAR,
            "union_empty": PostgresRelationKind.REGULAR,
            "union_grandchild": PostgresRelationKind.REGULAR,
            "union_middle": PostgresRelationKind.REGULAR,
        }
        _assert_composition(
            protected,
            member_kinds,
            {
                ("union_root", "union_child", 1),
                ("union_root", "union_empty", 1),
                ("union_root", "union_middle", 1),
                ("union_middle", "union_grandchild", 1),
            },
            PostgresInheritanceDetachState.UNSUPPORTED_BY_SERVER,
        )
        assert protected.physical_scan_count() == 5

        summary = _read_key_summary(context, protected)
        assert (
            summary.row_count,
            summary.null_key_count,
            summary.invalid_key_count,
            summary.valid_key_count,
            summary.distinct_key_count,
            summary.minimum_key,
            summary.maximum_key,
            summary.usable_access_path,
        ) == (4, 1, 0, 3, 2, 1, 2, True)

        query = build_postgres_legacy_union_integer_key_summary_query(
            _union_schema(),
            protected.query_relations(),
            0,
            None,
            1_024,
        )
        _assert_only_member_scans(reader, query, protected, set(member_kinds))
    finally:
        reader.close()
        context.close()


def _union_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="bucket",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _acquisition(relation: PostgresRelation) -> PostgresRelationAcquisition:
    return PostgresRelationAcquisition(
        schema=_union_schema(),
        relation=relation,
        relation_scope=RelationScope.FROZEN_PHYSICAL_UNION,
        column_names=("id", "bucket"),
        max_metadata_record_bytes=_METADATA_RECORD_BYTES,
        max_metadata_total_bytes=_METADATA_TOTAL_BYTES,
    )


def _create_postgres_17_partition_hierarchy(
    writer: psycopg.Connection[tuple[object, ...]],
    namespace: str,
) -> None:
    writer.execute(
        sql.SQL("CREATE SCHEMA {} AUTHORIZATION dfe_fixture_writer").format(
            sql.Identifier(namespace)
        )
    )
    writer.execute(
        sql.SQL(
            "CREATE TABLE {} (id bigint, bucket bigint NOT NULL) PARTITION BY RANGE (bucket)"
        ).format(sql.Identifier(namespace, "union_root"))
    )
    writer.execute(
        sql.SQL(
            "CREATE TABLE {} PARTITION OF {} FOR VALUES FROM (0) TO (100) "
            "PARTITION BY RANGE (bucket)"
        ).format(
            sql.Identifier(namespace, "union_branch"),
            sql.Identifier(namespace, "union_root"),
        )
    )
    for table_name, lower, upper, parent_name in (
        ("union_low", 0, 50, "union_branch"),
        ("union_high", 50, 100, "union_branch"),
        ("union_empty", 100, 200, "union_root"),
    ):
        writer.execute(
            sql.SQL("CREATE TABLE {} PARTITION OF {} FOR VALUES FROM ({}) TO ({})").format(
                sql.Identifier(namespace, table_name),
                sql.Identifier(namespace, parent_name),
                sql.Literal(lower),
                sql.Literal(upper),
            )
        )
        writer.execute(
            sql.SQL("CREATE INDEX ON {} (id)").format(sql.Identifier(namespace, table_name))
        )
    writer.execute(
        sql.SQL("INSERT INTO {} (id, bucket) VALUES (1, 10), (1, 60), (NULL, 70)").format(
            sql.Identifier(namespace, "union_root")
        )
    )
    writer.execute(
        sql.SQL("CREATE TABLE {} (id bigint, bucket bigint NOT NULL)").format(
            sql.Identifier(namespace, "union_late")
        )
    )
    writer.execute(
        sql.SQL("INSERT INTO {} (id, bucket) VALUES (99, 250)").format(
            sql.Identifier(namespace, "union_late")
        )
    )
    writer.execute(
        sql.SQL("GRANT USAGE ON SCHEMA {} TO dfe_fixture_reader").format(sql.Identifier(namespace))
    )
    writer.execute(
        sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO dfe_fixture_reader").format(
            sql.Identifier(namespace)
        )
    )


def _assert_composition(
    protected: PostgresProtectedRelationInspection,
    expected_members: dict[str, PostgresRelationKind],
    expected_edges: set[tuple[str, str, int]],
    expected_detach_state: PostgresInheritanceDetachState,
) -> None:
    composition = protected.composition
    assert composition is not None
    members_by_name = {
        member.inspection.relation.components[-1]: member for member in composition.members
    }
    assert {
        name: member.relation_kind for name, member in members_by_name.items()
    } == expected_members
    assert composition.root_relation_oid == members_by_name["union_root"].inspection.relation_oid
    names_by_oid = {
        member.inspection.relation_oid: name for name, member in members_by_name.items()
    }
    assert {
        (
            names_by_oid[edge.parent_relation_oid],
            names_by_oid[edge.child_relation_oid],
            edge.sequence,
        )
        for edge in composition.edges
    } == expected_edges
    assert {edge.detach_state for edge in composition.edges} == {expected_detach_state}
    assert members_by_name["union_empty"].inspection.relation_row_type_oid > 0


def _exercise_late_membership_changes(
    writer: psycopg.Connection[tuple[object, ...]],
    namespace: str,
    protected: PostgresProtectedRelationInspection,
) -> None:
    writer.execute(
        sql.SQL("ALTER TABLE {} ATTACH PARTITION {} FOR VALUES FROM (200) TO (300)").format(
            sql.Identifier(namespace, "union_root"),
            sql.Identifier(namespace, "union_late"),
        )
    )
    assert "union_late" not in {
        relation.inspection.relation.components[-1] for relation in protected.query_relations()
    }
    writer.execute("SET lock_timeout = '250ms'")
    try:
        with pytest.raises(psycopg.errors.LockNotAvailable):
            writer.execute(
                sql.SQL("ALTER TABLE {} DETACH PARTITION {}").format(
                    sql.Identifier(namespace, "union_root"),
                    sql.Identifier(namespace, "union_empty"),
                )
            )
    finally:
        writer.execute("RESET lock_timeout")


def _read_key_summary(
    context: PostgresProtectedReadContext,
    protected: PostgresProtectedRelationInspection,
) -> PostgresIntegerKeySummary:
    return context.read_integer_key_summary(
        protected,
        0,
        None,
        1_024,
        4_096,
        65_536,
        context.source_budget.read_deadline(5_000),
        protected.physical_scan_count(),
    ).summary


def _assert_only_member_scans(
    connection: psycopg.Connection[tuple[object, ...]],
    query: PostgresQuery,
    protected: PostgresProtectedRelationInspection,
    expected_scanned_members: set[str],
) -> None:
    rendered = query.statement.as_string(connection)
    member_names = {
        relation.inspection.relation.components[-1] for relation in protected.query_relations()
    }
    for relation in protected.query_relations():
        qualified = ".".join(
            f'"{component}"' for component in relation.inspection.relation.components
        )
        assert f"ONLY {qualified}" in rendered

    row = connection.execute(
        sql.SQL("EXPLAIN (FORMAT JSON) {}").format(query.statement),
        query.parameters,
    ).fetchone()
    assert row is not None and len(row) == 1
    scanned_members = _plan_relation_names(row[0]) & member_names
    assert scanned_members == expected_scanned_members


def _plan_relation_names(value: object) -> set[str]:
    if isinstance(value, list):
        names: set[str] = set()
        for item in cast(list[object], value):
            names.update(_plan_relation_names(item))
        return names
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        names = set()
        relation_name = mapping.get("Relation Name")
        if type(relation_name) is str:
            names.add(relation_name)
        for item in mapping.values():
            names.update(_plan_relation_names(item))
        return names
    return set()
