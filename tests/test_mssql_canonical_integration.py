import hashlib
from contextlib import ExitStack
from decimal import Decimal

import pyodbc
import pytest

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
    TimestampParameters,
    encode_key,
    encode_row,
    schema_from_metadata_json,
)
from forensic_data.mssql import (
    MssqlContextLostError,
    MssqlFetchLimits,
    MssqlKeySummary,
    MssqlMetadataError,
    MssqlQueryContextError,
    MssqlQueryError,
    MssqlReadContext,
    MssqlReadContextState,
    UnsupportedMssqlProfileError,
    open_mssql_read_context,
)
from forensic_data.mssql_sql import (
    MssqlInspectedRelation,
    MssqlLoweringError,
    MssqlRelation,
    build_mssql_fingerprint_query,
    build_mssql_key_summary_query,
    build_mssql_row_envelope_query,
    build_mssql_row_hash_query,
)
from tests.mssql_support import (
    connect_fixture_admin,
    connect_setup_writer,
    required_rcsi_reader_settings,
    required_reader_settings,
    required_setup_writer_settings,
    single_attempt_retry_policy,
)

pytestmark = [pytest.mark.integration, pytest.mark.mssql]

_SCHEMA_DIGEST = "3ec0a50078a3f5e0ef646955a2fd8fb42122b126236e7dede3f871b95c039639"
_LONG_ENVELOPE_BYTES = 8_333
_LONG_SHA256_HEX = "bf05a0e9d437def4648eada1f7f657a31aa816f626351882f59cb903aac3cace"
_SHORT_ENVELOPE_BYTES = 265
_SHORT_SHA256_HEX = "9be2bfb6b1b725f69670989ad7089e683a07bd73148d4ca05e82a67b42381677"
_SHORT_ENVELOPE = (
    "DFE1R3ec0a50078a3f5e0ef646955a2fd8fb42122b126236e7dede3f871b95c03963900000004"
    "011000000000000001339323233333732303336383534373735383037"
    "021000000000000000a31323334353030303030"
    "0400000000000000000"
    "061000000000000001b393939392d31322d33315432333a35393a35392e39393939393939"
)
_EXPECTED_LIMB_SUMS = (
    Decimal("5820145823"),
    Decimal("6542001386"),
    Decimal("4211033659"),
    Decimal("7767782923"),
    Decimal("1420809321"),
    Decimal("985818402"),
    Decimal("5706309502"),
    Decimal("3975930181"),
)
_SHORT_LIMBS = (
    Decimal("2615328694"),
    Decimal("2981570038"),
    Decimal("2523961498"),
    Decimal("3607666280"),
    Decimal("973585779"),
    Decimal("344804512"),
    Decimal("1585620603"),
    Decimal("1110972023"),
)
_COMMON_METADATA_JSON = (
    '{"fields":[{"name":"id","normalization":"none","nullable":false,'
    '"parameters":{},"type":"int64"},{"name":"amount","normalization":"none",'
    '"nullable":false,"parameters":{"precision":38,"scale":3},"type":"decimal"},'
    '{"name":"active","normalization":"none","nullable":false,"parameters":{},'
    '"type":"boolean"},{"name":"label","normalization":"none","nullable":false,'
    '"parameters":{},"type":"string"},{"name":"business_date","normalization":"none",'
    '"nullable":false,"parameters":{},"type":"date"},{"name":"local_time",'
    '"normalization":"none","nullable":false,"parameters":{"precision":6},'
    '"type":"timestamp_local"},{"name":"instant_time","normalization":"none",'
    '"nullable":false,"parameters":{"precision":6},"type":"timestamp_instant"}],'
    '"protocol":"dfe_canon_v1"}'
)
_COMMON_SCHEMA_DIGEST = "080301070eab887e4bc604cb856cf811d1858d4b7de65ffad3d6683210266814"
_COMMON_ENVELOPE = (
    "DFE1R080301070eab887e4bc604cb856cf811d1858d4b7de65ffad3d668321026681400000007"
    "01100000000000000142d39323233333732303336383534373735383038"
    "02100000000000000082d31373830303030"
    "031000000000000000131"
    "041000000000000000d417cd091f09f988065cc812020"
    "051000000000000000a323032342d30322d3239"
    "061000000000000001a323032342d30322d32395432333a35393a35382e313233343536"
    "071000000000000001b323032342d30322d32395432313a32393a35382e3132333435365a"
)
_COMMON_SHA256_HEX = "20d5266f5cc029d21404ee115ab2d6b229478f96b8cef5b4d4482d17899debdc"
_COMMON_LIMBS = (
    Decimal("550839919"),
    Decimal("1556097490"),
    Decimal("335867409"),
    Decimal("1521669810"),
    Decimal("692555670"),
    Decimal("3100571060"),
    Decimal("3561499927"),
    Decimal("2308828124"),
)
_KEY_SCHEMA_DIGEST = "b57921e563566a35456bb9db228268969886d9680a7ca9d88e2471b77f42ac35"
_SNAPSHOT_SEED_VALUE = "Привет 😀"
_SNAPSHOT_UPDATED_VALUE = "committed-after-snapshot"
_DRIFT_TABLE_NAME = "p03_04_catalog_drift_probe"


def test_mssql_canonical_hash_and_fingerprint_match_independent_oracle() -> None:
    schema = _canonical_probe_schema()
    common_schema = schema_from_metadata_json(_COMMON_METADATA_JSON)
    context = _open_reader_context("dfe-phase03-canonical-conformance")
    try:
        inspection = _inspect_relation(
            context,
            schema,
            MssqlRelation(schema_name="dfe_fixture", table_name="canonical_probe"),
            ("record_id", "amount", "observed_value", "observed_at"),
        )
        common_inspection = _inspect_relation(
            context,
            common_schema,
            MssqlRelation(
                schema_name="dfe_fixture",
                table_name="canonical_common_types",
            ),
            (
                "id",
                "amount",
                "active",
                "label",
                "business_date",
                "local_time",
                "instant_time",
            ),
        )
        row_query = build_mssql_row_hash_query(
            schema,
            inspection,
            _LONG_ENVELOPE_BYTES,
        )
        fingerprint_query = build_mssql_fingerprint_query(
            schema,
            inspection,
            _LONG_ENVELOPE_BYTES,
        )
        tight_fingerprint_query = build_mssql_fingerprint_query(
            schema,
            inspection,
            _LONG_ENVELOPE_BYTES - 1,
        )
        common_row_query = build_mssql_row_envelope_query(
            common_schema,
            common_inspection,
            512,
        )
        common_fingerprint_query = build_mssql_fingerprint_query(
            common_schema,
            common_inspection,
            512,
        )
        assert inspection.context_id == context.evidence.context_id
        assert inspection.database_id == context.profile.database_id
        assert tuple(binding.column_id for binding in inspection.bindings) == (1, 2, 3, 4)
        assert tuple(binding.is_nullable for binding in inspection.bindings) == (
            False,
            False,
            True,
            False,
        )
        assert row_query.context.schema_digest_hex == _SCHEMA_DIGEST
        assert fingerprint_query.context.schema_digest_hex == _SCHEMA_DIGEST
        assert common_row_query.context.schema_digest_hex == _COMMON_SCHEMA_DIGEST
        assert common_fingerprint_query.context.schema_digest_hex == _COMMON_SCHEMA_DIGEST

        row_result = context.read_canonical_rows(
            row_query,
            MssqlFetchLimits(
                fetch_batch_records=2,
                max_records=2,
                max_value_bytes=32_000,
                max_record_bytes=32_512,
                max_total_bytes=65_024,
            ),
        )
        assert len(row_result.rows) == 2
        rows_by_envelope_bytes = {row[0]: row for row in row_result.rows}
        assert set(rows_by_envelope_bytes) == {_LONG_ENVELOPE_BYTES, _SHORT_ENVELOPE_BYTES}
        assert rows_by_envelope_bytes[_LONG_ENVELOPE_BYTES] == (
            _LONG_ENVELOPE_BYTES,
            _LONG_SHA256_HEX,
            None,
            False,
            False,
        )
        assert rows_by_envelope_bytes[_SHORT_ENVELOPE_BYTES] == (
            _SHORT_ENVELOPE_BYTES,
            _SHORT_SHA256_HEX,
            _SHORT_ENVELOPE,
            False,
            False,
        )

        fingerprint_result = context.read_fingerprint(
            fingerprint_query,
            _summary_limits(),
        )
        assert fingerprint_result.rows == ((2, *_EXPECTED_LIMB_SUMS, 0, 0),)

        tight_fingerprint_result = context.read_fingerprint(
            tight_fingerprint_query,
            _summary_limits(),
        )
        assert tight_fingerprint_result.rows == ((1, *_SHORT_LIMBS, 0, 1),)

        common_row_result = context.read_canonical_rows(
            common_row_query,
            MssqlFetchLimits(
                fetch_batch_records=2,
                max_records=2,
                max_value_bytes=2_048,
                max_record_bytes=2_400,
                max_total_bytes=4_800,
            ),
        )
        assert set(common_row_result.rows) == {
            (_COMMON_ENVELOPE, _COMMON_SHA256_HEX, False, False),
            (None, None, True, False),
        }

        common_fingerprint_result = context.read_fingerprint(
            common_fingerprint_query,
            _summary_limits(),
        )
        assert common_fingerprint_result.rows == ((1, *_COMMON_LIMBS, 1, 0),)
    finally:
        context.close()


def test_mssql_transaction_snapshot_is_stable_and_rcsi_only_is_rejected() -> None:
    schema = _snapshot_probe_schema()
    relation = MssqlRelation(schema_name="dfe_fixture", table_name="snapshot_probe")
    with ExitStack() as cleanup:
        writer = connect_setup_writer("dfe-phase03-snapshot-writer")
        cleanup.callback(writer.close)
        _restore_snapshot_probe(writer)
        cleanup.callback(_restore_snapshot_probe, writer)

        context = _open_reader_context("dfe-phase03-snapshot-reader")
        cleanup.callback(context.close)
        assert context.evidence.engine == "mssql"
        assert context.evidence.strategy == "transaction_snapshot"
        assert context.evidence.snapshot_locator is None
        assert context.evidence.transaction_count == 1
        assert context.evidence.transaction_state == 1
        assert context.evidence.transaction_isolation_level == 5
        assert context.evidence.allowed_concurrency == 1
        assert context.profile.snapshot_isolation_state_description == "ON"
        assert context.profile.read_committed_snapshot is False

        inspection = _inspect_relation(
            context,
            schema,
            relation,
            ("observed_value",),
        )
        query = build_mssql_row_envelope_query(schema, inspection, 512)
        expected_seed_row = _expected_string_row(schema, _SNAPSHOT_SEED_VALUE)
        assert context.read_canonical_rows(query, _single_row_limits()).rows == (expected_seed_row,)

        _update_snapshot_probe(writer, _SNAPSHOT_UPDATED_VALUE)
        assert context.read_canonical_rows(query, _single_row_limits()).rows == (expected_seed_row,)

        fresh_context = _open_reader_context("dfe-phase03-snapshot-fresh-reader")
        cleanup.callback(fresh_context.close)
        fresh_inspection = _inspect_relation(
            fresh_context,
            schema,
            relation,
            ("observed_value",),
        )
        fresh_query = build_mssql_row_envelope_query(schema, fresh_inspection, 512)
        assert fresh_context.read_canonical_rows(
            fresh_query,
            _single_row_limits(),
        ).rows == (_expected_string_row(schema, _SNAPSHOT_UPDATED_VALUE),)

        _delete_snapshot_probe(writer)
        empty_context = _open_reader_context("dfe-phase03-snapshot-empty-reader")
        cleanup.callback(empty_context.close)
        empty_inspection = _inspect_relation(
            empty_context,
            schema,
            relation,
            ("observed_value",),
        )
        empty_query = build_mssql_row_envelope_query(schema, empty_inspection, 512)
        empty_result = empty_context.read_canonical_rows(
            empty_query,
            _single_row_limits(),
        )
        assert empty_result.rows == ()
        assert empty_result.metrics.fetched_records == 0

    with pytest.raises(UnsupportedMssqlProfileError) as error:
        open_mssql_read_context(
            required_rcsi_reader_settings("dfe-phase03-rcsi-refusal"),
            single_attempt_retry_policy(),
        )
    message = str(error.value)
    assert "database='dfe_rcsi_fixture'" in message
    assert "snapshot_isolation_state=0" in message
    assert "snapshot_isolation_state_desc='OFF'" in message
    assert "read_committed_snapshot=True" in message


def test_mssql_catalog_bound_key_validation_rejects_unsafe_sources_and_drift() -> None:
    schema = _canonical_key_schema()
    relation = MssqlRelation(schema_name="dfe_fixture", table_name="canonical_key_probe")
    with ExitStack() as cleanup:
        context = _open_reader_context("dfe-phase03-key-reader")
        cleanup.callback(context.close)
        inspection = _inspect_relation(
            context,
            schema,
            relation,
            ("text_key", "numeric_key"),
        )
        _assert_key_inspection(context, inspection)
        query = build_mssql_key_summary_query(schema, inspection, (0, 1), 512)
        assert query.context.schema_digest_hex == _KEY_SCHEMA_DIGEST

        oracle_values = (
            ("A", 10),
            ("a", 10),
            ("é", 10),
            ("é", 10),
            ("x", 10),
            ("x ", 10),
            ("A", 10),
        )
        oracle_keys = tuple(encode_key(schema, values) for values in oracle_values)
        assert all(key.startswith(b"DFE1K") for key in oracle_keys)
        assert len(set(oracle_keys[:6])) == 6
        assert oracle_keys[0] == oracle_keys[-1]
        assert len(set(oracle_keys)) == 6

        summary_read = context.read_key_summary(query, _summary_limits())
        assert summary_read.summary == MssqlKeySummary(
            row_count=10,
            null_key_count=1,
            invalid_key_count=2,
            oversized_key_count=0,
            valid_key_count=len(oracle_keys),
            distinct_key_count=len(set(oracle_keys)),
        )
        assert summary_read.metrics.fetched_records == 1

        other_context = _open_reader_context("dfe-phase03-key-other-reader")
        cleanup.callback(other_context.close)
        with pytest.raises(MssqlQueryContextError, match="different read context"):
            other_context.read_key_summary(query, _summary_limits())
        assert other_context.state is MssqlReadContextState.ACTIVE

        lossy_schema = CanonicalSchema(
            protocol=PROTOCOL,
            fields=(
                FieldSchema(
                    name="text_key",
                    logical_type=LogicalType.INT64,
                    nullable=False,
                    parameters=NoParameters(),
                    normalization=Normalization.NONE,
                ),
            ),
        )
        with pytest.raises(
            MssqlLoweringError,
            match=r"logical_type=int64, physical_type=sys\.nvarchar",
        ):
            _inspect_relation(context, lossy_schema, relation, ("text_key",))

        writer_context = open_mssql_read_context(
            required_setup_writer_settings("dfe-phase03-writer-inspection-refusal"),
            single_attempt_retry_policy(),
        )
        cleanup.callback(writer_context.close)
        with pytest.raises(MssqlMetadataError, match=r"SELECT-only.*update=1"):
            _inspect_relation(
                writer_context,
                schema,
                relation,
                ("text_key", "numeric_key"),
            )

        rls_schema = _single_int64_schema("record_id")
        with pytest.raises(MssqlMetadataError, match="enabled row-level security policy"):
            _inspect_relation(
                context,
                rls_schema,
                MssqlRelation(schema_name="dfe_fixture", table_name="rls_probe"),
                ("record_id",),
            )

        admin = connect_fixture_admin("dfe-phase03-permission-admin")
        cleanup.callback(admin.close)
        try:
            _revoke_reader_view_definition(admin)
            with pytest.raises(MssqlMetadataError, match="physical provenance changed"):
                context.read_key_summary(query, _summary_limits())
            assert context.state is MssqlReadContextState.LOST
            with pytest.raises(MssqlContextLostError, match="was lost"):
                context.read_key_summary(query, _summary_limits())
        finally:
            _grant_reader_view_definition(admin)

    _assert_catalog_drift_fails_closed()


def _canonical_probe_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="record_id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="amount",
                logical_type=LogicalType.DECIMAL,
                nullable=False,
                parameters=DecimalParameters(precision=38, scale=7),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="observed_value",
                logical_type=LogicalType.STRING,
                nullable=True,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="observed_at",
                logical_type=LogicalType.TIMESTAMP_LOCAL,
                nullable=False,
                parameters=TimestampParameters(precision=7),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _snapshot_probe_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="observed_value",
                logical_type=LogicalType.STRING,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _canonical_key_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="text_key",
                logical_type=LogicalType.STRING,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="numeric_key",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _single_int64_schema(field_name: str) -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name=field_name,
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _open_reader_context(application_name: str) -> MssqlReadContext:
    return open_mssql_read_context(
        required_reader_settings(application_name),
        single_attempt_retry_policy(),
    )


def _inspect_relation(
    context: MssqlReadContext,
    schema: CanonicalSchema,
    relation: MssqlRelation,
    column_names: tuple[str, ...],
) -> MssqlInspectedRelation:
    return context.inspect_relation(
        schema,
        relation,
        column_names,
        max_metadata_record_bytes=8_192,
        max_metadata_total_bytes=32_768,
    )


def _single_row_limits() -> MssqlFetchLimits:
    return MssqlFetchLimits(
        fetch_batch_records=1,
        max_records=1,
        max_value_bytes=2_048,
        max_record_bytes=2_400,
        max_total_bytes=2_400,
    )


def _summary_limits() -> MssqlFetchLimits:
    return MssqlFetchLimits(
        fetch_batch_records=1,
        max_records=1,
        max_value_bytes=64,
        max_record_bytes=512,
        max_total_bytes=512,
    )


def _expected_string_row(
    schema: CanonicalSchema,
    value: str,
) -> tuple[str, str, bool, bool]:
    envelope_bytes = encode_row(schema, (value,))
    return (
        envelope_bytes.decode("ascii"),
        hashlib.sha256(envelope_bytes).hexdigest(),
        False,
        False,
    )


def _assert_key_inspection(
    context: MssqlReadContext,
    inspection: MssqlInspectedRelation,
) -> None:
    assert inspection.context_id == context.evidence.context_id
    assert inspection.database_id == context.profile.database_id
    assert inspection.schema_id > 0
    assert inspection.object_id > 0
    assert inspection.relation == MssqlRelation(
        schema_name="dfe_fixture",
        table_name="canonical_key_probe",
    )
    text_binding, numeric_binding = inspection.bindings
    assert (
        text_binding.field_name,
        text_binding.column_id,
        text_binding.column_name,
        text_binding.is_nullable,
    ) == ("text_key", 2, "text_key", True)
    assert (
        text_binding.physical.system_type_name,
        text_binding.physical.system_type_id,
        text_binding.physical.user_type_id,
        text_binding.physical.max_length,
        text_binding.physical.precision,
        text_binding.physical.scale,
        text_binding.physical.collation_name,
    ) == ("nvarchar", 231, 231, 64, 0, 0, "Latin1_General_100_CI_AS_SC")
    assert (
        numeric_binding.field_name,
        numeric_binding.column_id,
        numeric_binding.column_name,
        numeric_binding.is_nullable,
    ) == ("numeric_key", 3, "numeric_key", True)
    assert (
        numeric_binding.physical.system_type_name,
        numeric_binding.physical.system_type_id,
        numeric_binding.physical.user_type_id,
        numeric_binding.physical.max_length,
        numeric_binding.physical.precision,
        numeric_binding.physical.scale,
        numeric_binding.physical.collation_name,
    ) == ("decimal", 106, 106, 17, 38, 7, None)


def _update_snapshot_probe(connection: pyodbc.Connection, value: str) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute(
            "UPDATE [dfe_fixture].[snapshot_probe] SET [observed_value] = ? WHERE [record_id] = 1",
            value,
        )
        if cursor.rowcount != 1:
            connection.rollback()
            raise AssertionError("snapshot_probe update must affect exactly one row")
        connection.commit()
    except pyodbc.Error:
        connection.rollback()
        raise
    finally:
        cursor.close()


def _delete_snapshot_probe(connection: pyodbc.Connection) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM [dfe_fixture].[snapshot_probe] WHERE [record_id] = 1")
        if cursor.rowcount != 1:
            connection.rollback()
            raise AssertionError("snapshot_probe delete must affect exactly one row")
        connection.commit()
    except pyodbc.Error:
        connection.rollback()
        raise
    finally:
        cursor.close()


def _restore_snapshot_probe(connection: pyodbc.Connection) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM [dfe_fixture].[snapshot_probe]")
        cursor.execute(
            "INSERT INTO [dfe_fixture].[snapshot_probe] "
            "([record_id], [observed_value], [amount], [observed_at]) "
            "VALUES (1, ?, CONVERT(decimal(38, 3), N'123.450'), "
            "CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234567', 126))",
            _SNAPSHOT_SEED_VALUE,
        )
        if cursor.rowcount != 1:
            connection.rollback()
            raise AssertionError("snapshot_probe restore must insert exactly one row")
        connection.commit()
    except pyodbc.Error:
        connection.rollback()
        raise
    finally:
        cursor.close()


def _revoke_reader_view_definition(connection: pyodbc.Connection) -> None:
    _execute_admin_statement(
        connection,
        "REVOKE VIEW DEFINITION FROM [dfe_fixture_reader_role]",
    )


def _grant_reader_view_definition(connection: pyodbc.Connection) -> None:
    _execute_admin_statement(
        connection,
        "GRANT VIEW DEFINITION TO [dfe_fixture_reader_role]",
    )


def _assert_catalog_drift_fails_closed() -> None:
    schema = _single_int64_schema("record_id")
    relation = MssqlRelation(schema_name="dfe_fixture", table_name=_DRIFT_TABLE_NAME)
    limits = MssqlFetchLimits(
        fetch_batch_records=1,
        max_records=1,
        max_value_bytes=32_000,
        max_record_bytes=32_512,
        max_total_bytes=32_512,
    )
    with ExitStack() as cleanup:
        admin = connect_fixture_admin("dfe-phase03-drift-admin")
        cleanup.callback(admin.close)
        _replace_drift_probe(admin, 1)
        cleanup.callback(_drop_drift_probe, admin)

        context = _open_reader_context("dfe-phase03-drift-reader")
        cleanup.callback(context.close)
        inspection = _inspect_relation(context, schema, relation, ("record_id",))
        query = build_mssql_row_hash_query(schema, inspection, 512)
        envelope = encode_row(schema, (1,))
        assert context.read_canonical_rows(query, limits).rows == (
            (
                len(envelope),
                hashlib.sha256(envelope).hexdigest(),
                envelope.decode("ascii"),
                False,
                False,
            ),
        )
        _replace_drift_probe(admin, 2)

        with pytest.raises((MssqlMetadataError, MssqlQueryError)) as error:
            context.read_canonical_rows(query, limits)
        assert str(error.value)
        assert context.state is MssqlReadContextState.LOST
        with pytest.raises(MssqlContextLostError, match="was lost"):
            context.read_canonical_rows(query, limits)


def _replace_drift_probe(connection: pyodbc.Connection, record_id: int) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute(
            f"IF OBJECT_ID(N'dfe_fixture.{_DRIFT_TABLE_NAME}', N'U') IS NOT NULL "
            f"DROP TABLE [dfe_fixture].[{_DRIFT_TABLE_NAME}]"
        )
        cursor.execute(
            f"CREATE TABLE [dfe_fixture].[{_DRIFT_TABLE_NAME}] ([record_id] bigint NOT NULL)"
        )
        cursor.execute(
            f"INSERT INTO [dfe_fixture].[{_DRIFT_TABLE_NAME}] ([record_id]) VALUES (?)",
            record_id,
        )
        connection.commit()
    except pyodbc.Error:
        connection.rollback()
        raise
    finally:
        cursor.close()


def _drop_drift_probe(connection: pyodbc.Connection) -> None:
    _execute_admin_statement(
        connection,
        f"IF OBJECT_ID(N'dfe_fixture.{_DRIFT_TABLE_NAME}', N'U') IS NOT NULL "
        f"DROP TABLE [dfe_fixture].[{_DRIFT_TABLE_NAME}]",
    )


def _execute_admin_statement(connection: pyodbc.Connection, statement: str) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute(statement)
        connection.commit()
    except pyodbc.Error:
        connection.rollback()
        raise
    finally:
        cursor.close()
