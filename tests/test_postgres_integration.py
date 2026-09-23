import traceback
from decimal import Decimal
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    Fingerprint,
    LogicalType,
    NoParameters,
    Normalization,
    TimestampParameters,
    decode_row,
    encode_row,
    fingerprint_rows,
    schema_from_metadata_json,
)
from forensic_data.postgres import (
    PostgresContextClosedError,
    PostgresContextLostError,
    PostgresDataValidationError,
    PostgresMetadataError,
    PostgresQueryContextError,
    PostgresQueryError,
    PostgresResultLimitError,
    PostgresSslMode,
    ReadContextState,
)
from forensic_data.postgres_sql import (
    PostgresLoweringError,
    PostgresRelation,
    build_postgres_fingerprint_query,
    build_postgres_row_envelope_query,
)
from tests.canonical_vectors import vector_named
from tests.postgres_support import (
    connect_writer,
    open_reader_context,
    required_connection_settings,
)

pytestmark = [pytest.mark.integration, pytest.mark.postgres]

_METADATA_RECORD_BYTES = 4_096
_METADATA_TOTAL_BYTES = 32_768
_ENVELOPE_BYTES = 4_096
_CANONICAL_RECORD_BYTES = 8_192
_FINGERPRINT_RECORD_BYTES = 1_024


_READER_SETTINGS = required_connection_settings(
    "DFE_TEST_POSTGRES_READER_DSN",
    "dfe-phase01-integration-reader",
)
_WRITER_SETTINGS = required_connection_settings(
    "DFE_TEST_POSTGRES_WRITER_DSN",
    "dfe-phase01-integration-writer",
)


def test_postgres_common_types_match_golden_row_hash_and_fingerprint() -> None:
    vector = vector_named("all_common_types")
    schema = schema_from_metadata_json(vector.metadata_json)
    relation = PostgresRelation(components=("dfe_fixture", "canonical_values"))
    column_names = tuple(field.name for field in schema.fields)
    context = open_reader_context(_READER_SETTINGS)
    try:
        assert _READER_SETTINGS.sslmode is PostgresSslMode.DISABLE
        assert context.profile.server_version_number == 170011
        assert context.profile.server_encoding == "UTF8"
        assert context.profile.client_encoding == "UTF8"
        assert context.profile.timezone == "UTC"
        assert context.profile.max_identifier_utf8_bytes == 63
        inspection = context.inspect_relation(
            schema,
            relation,
            column_names,
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        bindings = inspection.bindings
        assert tuple(binding.physical.base_type.type_name for binding in bindings) == (
            "int8",
            "numeric",
            "bool",
            "text",
            "date",
            "timestamp",
            "timestamptz",
        )
        assert tuple(binding.physical.base_type.oid for binding in bindings) == (
            20,
            1700,
            16,
            25,
            1082,
            1114,
            1184,
        )
        assert tuple(binding.physical.formatted_type for binding in bindings) == (
            "bigint",
            "numeric(38,3)",
            "boolean",
            "text",
            "date",
            "timestamp(6) without time zone",
            "timestamp(6) with time zone",
        )
        assert all(
            binding.physical.declared_type == binding.physical.base_type for binding in bindings
        )
        assert all(binding.physical.base_type.schema_name == "pg_catalog" for binding in bindings)
        assert all(not binding.physical.is_domain for binding in bindings)
        assert all(binding.physical.array_dimensions == 0 for binding in bindings)
        assert bindings[1].physical.numeric_precision == 38
        assert bindings[1].physical.numeric_scale == 3

        row_query = build_postgres_row_envelope_query(
            schema,
            inspection,
            _ENVELOPE_BYTES,
        )
        assert row_query.context.schema is schema
        assert row_query.context.schema_digest_hex == vector.schema_digest_hex
        rows = context.read_canonical_rows(
            row_query,
            1,
            _CANONICAL_RECORD_BYTES,
            _CANONICAL_RECORD_BYTES,
        )
        assert len(rows) == 1
        assert rows[0].envelope == vector.envelope_ascii.encode("ascii")
        assert rows[0].sha256 == bytes.fromhex(vector.sha256_hex)

        fingerprint_query = build_postgres_fingerprint_query(
            schema,
            inspection,
            _ENVELOPE_BYTES,
        )
        assert context.read_fingerprint(
            fingerprint_query,
            _FINGERPRINT_RECORD_BYTES,
            _FINGERPRINT_RECORD_BYTES,
        ) == Fingerprint(count=1, limb_sums=vector.limbs)
    finally:
        context.close()


def test_postgres_numeric_scale_beyond_precision_is_preserved() -> None:
    schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="amount",
                logical_type=LogicalType.DECIMAL,
                nullable=False,
                parameters=DecimalParameters(precision=14, scale=14),
                normalization=Normalization.NONE,
            ),
        ),
    )
    relation = PostgresRelation(components=("dfe_fixture", "wide_scale_values"))
    context = open_reader_context(_READER_SETTINGS)
    try:
        inspection = context.inspect_relation(
            schema,
            relation,
            ("amount",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        physical = inspection.bindings[0].physical
        assert physical.declared_type == physical.base_type
        assert physical.base_type.schema_name == "pg_catalog"
        assert physical.base_type.type_name == "numeric"
        assert physical.base_type.oid == 1700
        assert physical.formatted_type == "numeric(3,14)"
        assert physical.numeric_precision == 3
        assert physical.numeric_scale == 14

        query = build_postgres_row_envelope_query(
            schema,
            inspection,
            512,
        )
        rows = context.read_canonical_rows(query, 1, 1_024, 1_024)
        expected_value = Decimal("0.00000000000123")
        expected_envelope = encode_row(schema, (expected_value,))
        assert len(rows) == 1
        assert rows[0].envelope == expected_envelope
        assert decode_row(schema, rows[0].envelope) == (expected_value,)
    finally:
        context.close()


def test_postgres_fingerprint_matches_duplicate_bag_and_empty_identity() -> None:
    schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    context = open_reader_context(_READER_SETTINGS)
    try:
        bag_inspection = context.inspect_relation(
            schema,
            PostgresRelation(components=("dfe_fixture", "fingerprint_bag_values")),
            ("id",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        bag_query = build_postgres_fingerprint_query(schema, bag_inspection, 512)
        envelope = encode_row(schema, (7,))
        assert context.read_fingerprint(
            bag_query,
            _FINGERPRINT_RECORD_BYTES,
            _FINGERPRINT_RECORD_BYTES,
        ) == fingerprint_rows((envelope, envelope))
        bag_row_query = build_postgres_row_envelope_query(schema, bag_inspection, 512)
        with pytest.raises(PostgresResultLimitError, match="logical record budget"):
            context.read_canonical_rows(bag_row_query, 1, 1_024, 2_048)
        logical_record_bytes = len(envelope) + 34
        tight_bag_row_query = build_postgres_row_envelope_query(
            schema,
            bag_inspection,
            len(envelope),
        )
        with pytest.raises(PostgresResultLimitError, match="logical total byte budget"):
            context.read_canonical_rows(
                tight_bag_row_query,
                2,
                logical_record_bytes,
                (2 * logical_record_bytes) - 1,
            )

        empty_inspection = context.inspect_relation(
            schema,
            PostgresRelation(components=("dfe_fixture", "fingerprint_empty_values")),
            ("id",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        empty_query = build_postgres_fingerprint_query(schema, empty_inspection, 512)
        assert context.read_fingerprint(
            empty_query,
            _FINGERPRINT_RECORD_BYTES,
            _FINGERPRINT_RECORD_BYTES,
        ) == Fingerprint(count=0, limb_sums=(0, 0, 0, 0, 0, 0, 0, 0))
        empty_row_query = build_postgres_row_envelope_query(schema, empty_inspection, 512)
        assert context.read_canonical_rows(empty_row_query, 1, 546, 546) == ()
    finally:
        context.close()


def test_postgres_exactness_guards_reject_precision_loss_and_preserve_null() -> None:
    decimal_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="fractional_amount",
                logical_type=LogicalType.DECIMAL,
                nullable=False,
                parameters=DecimalParameters(precision=3, scale=2),
                normalization=Normalization.NONE,
            ),
        ),
    )
    timestamp_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="local_time",
                logical_type=LogicalType.TIMESTAMP_LOCAL,
                nullable=False,
                parameters=TimestampParameters(precision=3),
                normalization=Normalization.NONE,
            ),
        ),
    )
    nullable_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="nullable_label",
                logical_type=LogicalType.STRING,
                nullable=True,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    relation = PostgresRelation(components=("dfe_fixture", "boundary_values"))
    context = open_reader_context(_READER_SETTINGS)
    try:
        decimal_inspection = context.inspect_relation(
            decimal_schema,
            relation,
            ("fractional_amount",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        decimal_query = build_postgres_fingerprint_query(decimal_schema, decimal_inspection, 512)
        with pytest.raises(PostgresDataValidationError, match="invalid_row_count=1"):
            context.read_fingerprint(
                decimal_query,
                _FINGERPRINT_RECORD_BYTES,
                _FINGERPRINT_RECORD_BYTES,
            )

        timestamp_inspection = context.inspect_relation(
            timestamp_schema,
            relation,
            ("local_time",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        timestamp_query = build_postgres_fingerprint_query(
            timestamp_schema,
            timestamp_inspection,
            512,
        )
        with pytest.raises(PostgresDataValidationError, match="invalid_row_count=1"):
            context.read_fingerprint(
                timestamp_query,
                _FINGERPRINT_RECORD_BYTES,
                _FINGERPRINT_RECORD_BYTES,
            )

        nullable_inspection = context.inspect_relation(
            nullable_schema,
            relation,
            ("nullable_label",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        nullable_query = build_postgres_row_envelope_query(
            nullable_schema,
            nullable_inspection,
            512,
        )
        rows = context.read_canonical_rows(nullable_query, 1, 1_024, 1_024)
        assert tuple(row.envelope for row in rows) == (encode_row(nullable_schema, (None,)),)
    finally:
        context.close()


def test_postgres_rejected_rows_cannot_produce_a_zero_fingerprint() -> None:
    invalid_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="amount",
                logical_type=LogicalType.DECIMAL,
                nullable=True,
                parameters=DecimalParameters(precision=1, scale=0),
                normalization=Normalization.NONE,
            ),
        ),
    )
    invalid_relation = PostgresRelation(components=("dfe_fixture", "invalid_values"))
    int64_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="wide_integer",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    common_vector = vector_named("all_common_types")
    common_schema = schema_from_metadata_json(common_vector.metadata_json)
    common_relation = PostgresRelation(components=("dfe_fixture", "canonical_values"))
    context = open_reader_context(_READER_SETTINGS)
    try:
        invalid_inspection = context.inspect_relation(
            invalid_schema,
            invalid_relation,
            ("amount",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        invalid_query = build_postgres_fingerprint_query(
            invalid_schema,
            invalid_inspection,
            512,
        )
        with pytest.raises(PostgresDataValidationError, match="invalid_row_count=2"):
            context.read_fingerprint(
                invalid_query,
                _FINGERPRINT_RECORD_BYTES,
                _FINGERPRINT_RECORD_BYTES,
            )

        int64_inspection = context.inspect_relation(
            int64_schema,
            invalid_relation,
            ("wide_integer",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        int64_query = build_postgres_fingerprint_query(
            int64_schema,
            int64_inspection,
            512,
        )
        with pytest.raises(PostgresDataValidationError, match="invalid_row_count=1"):
            context.read_fingerprint(
                int64_query,
                _FINGERPRINT_RECORD_BYTES,
                _FINGERPRINT_RECORD_BYTES,
            )

        common_inspection = context.inspect_relation(
            common_schema,
            common_relation,
            tuple(field.name for field in common_schema.fields),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        oversized_query = build_postgres_fingerprint_query(
            common_schema,
            common_inspection,
            100,
        )
        with pytest.raises(PostgresResultLimitError, match="oversized_row_count=1"):
            context.read_fingerprint(
                oversized_query,
                _FINGERPRINT_RECORD_BYTES,
                _FINGERPRINT_RECORD_BYTES,
            )
    finally:
        context.close()


def test_postgres_preflight_rejects_lossy_physical_types() -> None:
    physical_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    string_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="padded_label",
                logical_type=LogicalType.STRING,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    instant_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="local_as_instant",
                logical_type=LogicalType.TIMESTAMP_INSTANT,
                nullable=False,
                parameters=TimestampParameters(precision=6),
                normalization=Normalization.NONE,
            ),
        ),
    )
    relation = PostgresRelation(components=("dfe_fixture", "unsupported_physical_values"))
    volatile_schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="observed_value",
                logical_type=LogicalType.TIMESTAMP_INSTANT,
                nullable=False,
                parameters=TimestampParameters(precision=6),
                normalization=Normalization.NONE,
            ),
        ),
    )
    context = open_reader_context(_READER_SETTINGS)
    try:
        with pytest.raises(PostgresLoweringError, match=r"physical_type=pg_catalog\.bpchar"):
            context.inspect_relation(
                string_schema,
                relation,
                ("padded_label",),
                _METADATA_RECORD_BYTES,
                _METADATA_TOTAL_BYTES,
            )
        with pytest.raises(PostgresLoweringError, match=r"physical_type=pg_catalog\.timestamp"):
            context.inspect_relation(
                instant_schema,
                relation,
                ("local_as_instant",),
                _METADATA_RECORD_BYTES,
                _METADATA_TOTAL_BYTES,
            )
        with pytest.raises(PostgresMetadataError, match=r"relation_kind='v'"):
            context.inspect_relation(
                volatile_schema,
                PostgresRelation(components=("dfe_fixture", "volatile_values")),
                ("observed_value",),
                _METADATA_RECORD_BYTES,
                _METADATA_TOTAL_BYTES,
            )
        with pytest.raises(PostgresMetadataError, match=r"relation_kind='p'"):
            context.inspect_relation(
                physical_schema,
                PostgresRelation(components=("dfe_fixture", "partitioned_values")),
                ("id",),
                _METADATA_RECORD_BYTES,
                _METADATA_TOTAL_BYTES,
            )
        inheritance_inspection = context.inspect_relation(
            physical_schema,
            PostgresRelation(components=("dfe_fixture", "inheritance_parent_values")),
            ("id",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        inheritance_query = build_postgres_fingerprint_query(
            physical_schema,
            inheritance_inspection,
            512,
        )
        parent_envelope = encode_row(physical_schema, (1,))
        assert context.read_fingerprint(
            inheritance_query,
            _FINGERPRINT_RECORD_BYTES,
            _FINGERPRINT_RECORD_BYTES,
        ) == fingerprint_rows((parent_envelope,))
    finally:
        context.close()


def test_postgres_missing_and_rls_relations_fail_as_metadata_errors() -> None:
    schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    for relation_name in ("missing_values", "rls_values"):
        context = open_reader_context(_READER_SETTINGS)
        try:
            with pytest.raises(PostgresMetadataError, match="lock relation for inspection"):
                context.inspect_relation(
                    schema,
                    PostgresRelation(components=("dfe_fixture", relation_name)),
                    ("id",),
                    _METADATA_RECORD_BYTES,
                    _METADATA_TOTAL_BYTES,
                )
        finally:
            context.close()


def test_postgres_inspection_is_context_bound_and_holds_relation_lock() -> None:
    schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    relation = PostgresRelation(components=("dfe_fixture", "fingerprint_bag_values"))
    first_context = open_reader_context(_READER_SETTINGS)
    second_context = open_reader_context(_READER_SETTINGS)
    writer = connect_writer(_WRITER_SETTINGS)
    try:
        inspection = first_context.inspect_relation(
            schema,
            relation,
            ("id",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        query = build_postgres_fingerprint_query(schema, inspection, 512)
        with pytest.raises(PostgresQueryContextError, match="different read context"):
            second_context.read_fingerprint(
                query,
                _FINGERPRINT_RECORD_BYTES,
                _FINGERPRINT_RECORD_BYTES,
            )

        writer.execute("BEGIN")
        try:
            with pytest.raises(psycopg.errors.LockNotAvailable):
                writer.execute(
                    "LOCK TABLE dfe_fixture.fingerprint_bag_values IN ACCESS EXCLUSIVE MODE NOWAIT"
                )
        finally:
            writer.execute("ROLLBACK")
    finally:
        writer.close()
        second_context.close()
        first_context.close()


def test_postgres_compiled_queries_reject_schema_replacement_before_fetch() -> None:
    schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    suffix = uuid4().hex
    source_schema = f"dfe_oid_source_{suffix}"
    replacement_schema = f"dfe_oid_replacement_{suffix}"
    original_schema = f"dfe_oid_original_{suffix}"
    writer = connect_writer(_WRITER_SETTINGS)
    try:
        writer.execute(
            sql.SQL("CREATE SCHEMA {} AUTHORIZATION dfe_fixture_writer").format(
                sql.Identifier(source_schema)
            )
        )
        writer.execute(
            sql.SQL("CREATE SCHEMA {} AUTHORIZATION dfe_fixture_writer").format(
                sql.Identifier(replacement_schema)
            )
        )
        writer.execute(
            sql.SQL(
                "CREATE TABLE {}.source_values ("
                "id bigint NOT NULL, dfe_source bigint, dfe_origin bigint)"
            ).format(sql.Identifier(source_schema))
        )
        writer.execute(
            sql.SQL(
                "CREATE TABLE {}.source_values ("
                "id bigint NOT NULL, dfe_source {}.source_values, "
                "dfe_origin {}.source_values)"
            ).format(
                sql.Identifier(replacement_schema),
                sql.Identifier(source_schema),
                sql.Identifier(source_schema),
            )
        )
        for schema_name in (source_schema, replacement_schema):
            writer.execute(
                sql.SQL("GRANT USAGE ON SCHEMA {} TO dfe_fixture_reader").format(
                    sql.Identifier(schema_name)
                )
            )
            writer.execute(
                sql.SQL("GRANT SELECT ON {}.source_values TO dfe_fixture_reader").format(
                    sql.Identifier(schema_name)
                )
            )
        writer.execute(
            sql.SQL(
                "INSERT INTO {}.source_values (id, dfe_source, dfe_origin) VALUES (7, 11, 13)"
            ).format(sql.Identifier(source_schema))
        )

        context = open_reader_context(_READER_SETTINGS)
        try:
            inspection = context.inspect_relation(
                schema,
                PostgresRelation(components=(source_schema, "source_values")),
                ("id",),
                _METADATA_RECORD_BYTES,
                _METADATA_TOTAL_BYTES,
            )
            row_query = build_postgres_row_envelope_query(schema, inspection, 512)
            fingerprint_query = build_postgres_fingerprint_query(schema, inspection, 512)
            expected_envelope = encode_row(schema, (7,))
            assert tuple(
                row.envelope for row in context.read_canonical_rows(row_query, 1, 1_024, 1_024)
            ) == (expected_envelope,)
            assert context.read_fingerprint(
                fingerprint_query,
                _FINGERPRINT_RECORD_BYTES,
                _FINGERPRINT_RECORD_BYTES,
            ) == fingerprint_rows((expected_envelope,))

            writer.execute(
                sql.SQL("ALTER SCHEMA {} RENAME TO {}").format(
                    sql.Identifier(source_schema),
                    sql.Identifier(original_schema),
                )
            )
            writer.execute(
                sql.SQL("ALTER SCHEMA {} RENAME TO {}").format(
                    sql.Identifier(replacement_schema),
                    sql.Identifier(source_schema),
                )
            )

            with pytest.raises(PostgresMetadataError, match="different relation identity"):
                context.read_canonical_rows(row_query, 1, 1_024, 1_024)
            with pytest.raises(PostgresMetadataError, match="different relation identity"):
                context.read_fingerprint(
                    fingerprint_query,
                    _FINGERPRINT_RECORD_BYTES,
                    _FINGERPRINT_RECORD_BYTES,
                )
        finally:
            context.close()
    finally:
        for schema_name in (source_schema, replacement_schema, original_schema):
            writer.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema_name))
            )
        writer.close()


def test_postgres_repeatable_read_snapshot_ignores_concurrent_writer() -> None:
    context = open_reader_context(_READER_SETTINGS)
    writer = connect_writer(_WRITER_SETTINGS)
    try:
        evidence = context.evidence
        assert evidence.engine == "postgresql"
        assert evidence.strategy == "read_only_repeatable_read"
        assert evidence.snapshot_locator
        assert evidence.backend_process_id > 0
        assert evidence.allowed_concurrency == 1
        assert (
            context.read_scalar_integer(
                sql.SQL(
                    "SELECT observed_value FROM ONLY dfe_fixture.snapshot_values "
                    "WHERE record_id = 1"
                ),
                (),
                128,
                128,
            )
            == 100
        )

        update = writer.execute(
            "UPDATE dfe_fixture.snapshot_values SET observed_value = %s WHERE record_id = 1",
            (200,),
        )
        assert update.rowcount == 1
        assert (
            context.read_scalar_integer(
                sql.SQL(
                    "SELECT observed_value FROM ONLY dfe_fixture.snapshot_values "
                    "WHERE record_id = 1"
                ),
                (),
                128,
                128,
            )
            == 100
        )

        refreshed_context = open_reader_context(_READER_SETTINGS)
        try:
            assert (
                refreshed_context.read_scalar_integer(
                    sql.SQL(
                        "SELECT observed_value FROM ONLY dfe_fixture.snapshot_values "
                        "WHERE record_id = 1"
                    ),
                    (),
                    128,
                    128,
                )
                == 200
            )
        finally:
            refreshed_context.close()

        context.close()
        assert context.state is ReadContextState.CLOSED
        with pytest.raises(PostgresContextClosedError, match="already closed"):
            context.read_scalar_integer(sql.SQL("SELECT 1"), (), 128, 128)
    finally:
        reset = writer.execute(
            "UPDATE dfe_fixture.snapshot_values SET observed_value = %s WHERE record_id = 1",
            (100,),
        )
        assert reset.rowcount == 1
        writer.close()
        context.close()


def test_postgres_read_only_failure_loses_context_and_close_is_terminal() -> None:
    context = open_reader_context(_WRITER_SETTINGS)
    try:
        with pytest.raises(PostgresQueryError, match="sqlstate='25006'"):
            context.read_scalar_integer(
                sql.SQL(
                    "SELECT pg_catalog.nextval("
                    "'dfe_fixture.read_only_probe_sequence'::pg_catalog.regclass)"
                ),
                (),
                128,
                128,
            )
        assert context.state is ReadContextState.LOST
        with pytest.raises(PostgresContextLostError, match="cannot be reused"):
            context.read_scalar_integer(sql.SQL("SELECT 1"), (), 128, 128)
    finally:
        context.close()

    assert context.state is ReadContextState.CLOSED
    with pytest.raises(PostgresContextClosedError, match="already closed"):
        context.read_scalar_integer(sql.SQL("SELECT 1"), (), 128, 128)

    writer = connect_writer(_WRITER_SETTINGS)
    try:
        row = writer.execute(
            "SELECT last_value, is_called FROM dfe_fixture.read_only_probe_sequence"
        ).fetchone()
        assert row == (1, False)
    finally:
        writer.close()


def test_postgres_restores_trusted_search_path_and_redacts_query_errors() -> None:
    schema = CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
    context = open_reader_context(_READER_SETTINGS)
    try:
        assert (
            context.read_scalar_integer(
                sql.SQL(
                    "SELECT CASE WHEN dfe_fixture.sha256("
                    "pg_catalog.convert_to('x', 'UTF8')) = "
                    "pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') "
                    "THEN 1 ELSE 0 END"
                ),
                (),
                128,
                128,
            )
            == 1
        )
        poisoned_path = "dfe_fixture, pg_catalog"
        assert (
            context.read_scalar_integer(
                sql.SQL(
                    "SELECT CASE WHEN pg_catalog.set_config('search_path', %s, true) = %s "
                    "THEN 1 ELSE 0 END"
                ),
                (poisoned_path, poisoned_path),
                128,
                128,
            )
            == 1
        )

        inspection = context.inspect_relation(
            schema,
            PostgresRelation(components=("dfe_fixture", "fingerprint_bag_values")),
            ("id",),
            _METADATA_RECORD_BYTES,
            _METADATA_TOTAL_BYTES,
        )
        query = build_postgres_fingerprint_query(schema, inspection, 512)
        envelope = encode_row(schema, (7,))
        assert context.read_fingerprint(
            query,
            _FINGERPRINT_RECORD_BYTES,
            _FINGERPRINT_RECORD_BYTES,
        ) == fingerprint_rows((envelope, envelope))
        assert (
            context.read_scalar_integer(
                sql.SQL(
                    "SELECT CASE WHEN pg_catalog.set_config('row_security', 'on', true) = 'on' "
                    "THEN 1 ELSE 0 END"
                ),
                (),
                128,
                128,
            )
            == 1
        )
        assert (
            context.read_scalar_integer(
                sql.SQL(
                    "SELECT CASE WHEN pg_catalog.current_setting('row_security') = 'off' "
                    "THEN 1 ELSE 0 END"
                ),
                (),
                128,
                128,
            )
            == 1
        )

        sentinel = "phase01-sensitive-row-value"
        with pytest.raises(PostgresQueryError) as captured:
            context.read_scalar_integer(
                sql.SQL("SELECT (%s)::integer"),
                (sentinel,),
                128,
                128,
            )
        formatted_traceback = "".join(traceback.format_exception(captured.value))
        assert sentinel not in formatted_traceback
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None
    finally:
        context.close()
