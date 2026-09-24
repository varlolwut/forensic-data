from decimal import Decimal
from uuid import uuid4

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
    schema_from_metadata_json,
)
from forensic_data.mssql import MssqlFetchLimits, MssqlQuery, open_mssql_transport
from forensic_data.mssql_sql import (
    MssqlFieldBinding,
    MssqlPhysicalField,
    MssqlRelation,
    build_mssql_fingerprint_query,
    build_mssql_row_envelope_query,
    build_mssql_row_hash_query,
)
from tests.mssql_support import required_reader_settings, single_attempt_retry_policy

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


def test_mssql_canonical_hash_and_fingerprint_match_independent_oracle() -> None:
    schema = CanonicalSchema(
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
    relation = MssqlRelation(schema_name="dfe_fixture", table_name="canonical_probe")
    bindings = (
        MssqlFieldBinding(
            field_name="record_id",
            column_name="record_id",
            physical=MssqlPhysicalField(
                system_type_name="bigint",
                system_type_id=127,
                user_type_id=127,
                max_length=8,
                precision=19,
                scale=0,
                collation_name=None,
            ),
        ),
        MssqlFieldBinding(
            field_name="amount",
            column_name="amount",
            physical=MssqlPhysicalField(
                system_type_name="decimal",
                system_type_id=106,
                user_type_id=106,
                max_length=17,
                precision=38,
                scale=7,
                collation_name=None,
            ),
        ),
        MssqlFieldBinding(
            field_name="observed_value",
            column_name="observed_value",
            physical=MssqlPhysicalField(
                system_type_name="nvarchar",
                system_type_id=231,
                user_type_id=231,
                max_length=8_000,
                precision=0,
                scale=0,
                collation_name="Latin1_General_100_CI_AS_SC",
            ),
        ),
        MssqlFieldBinding(
            field_name="observed_at",
            column_name="observed_at",
            physical=MssqlPhysicalField(
                system_type_name="datetime2",
                system_type_id=42,
                user_type_id=42,
                max_length=8,
                precision=27,
                scale=7,
                collation_name=None,
            ),
        ),
    )
    row_query = build_mssql_row_hash_query(
        schema,
        relation,
        bindings,
        _LONG_ENVELOPE_BYTES,
    )
    fingerprint_query = build_mssql_fingerprint_query(
        schema,
        relation,
        bindings,
        _LONG_ENVELOPE_BYTES,
    )
    tight_fingerprint_query = build_mssql_fingerprint_query(
        schema,
        relation,
        bindings,
        _LONG_ENVELOPE_BYTES - 1,
    )
    common_schema = schema_from_metadata_json(_COMMON_METADATA_JSON)
    common_relation = MssqlRelation(
        schema_name="dfe_fixture",
        table_name="canonical_common_types",
    )
    common_bindings = (
        MssqlFieldBinding(
            field_name="id",
            column_name="id",
            physical=MssqlPhysicalField(
                system_type_name="bigint",
                system_type_id=127,
                user_type_id=127,
                max_length=8,
                precision=19,
                scale=0,
                collation_name=None,
            ),
        ),
        MssqlFieldBinding(
            field_name="amount",
            column_name="amount",
            physical=MssqlPhysicalField(
                system_type_name="decimal",
                system_type_id=106,
                user_type_id=106,
                max_length=17,
                precision=38,
                scale=3,
                collation_name=None,
            ),
        ),
        MssqlFieldBinding(
            field_name="active",
            column_name="active",
            physical=MssqlPhysicalField(
                system_type_name="bit",
                system_type_id=104,
                user_type_id=104,
                max_length=1,
                precision=1,
                scale=0,
                collation_name=None,
            ),
        ),
        MssqlFieldBinding(
            field_name="label",
            column_name="label",
            physical=MssqlPhysicalField(
                system_type_name="nvarchar",
                system_type_id=231,
                user_type_id=231,
                max_length=256,
                precision=0,
                scale=0,
                collation_name="Latin1_General_100_CI_AS_SC",
            ),
        ),
        MssqlFieldBinding(
            field_name="business_date",
            column_name="business_date",
            physical=MssqlPhysicalField(
                system_type_name="date",
                system_type_id=40,
                user_type_id=40,
                max_length=3,
                precision=10,
                scale=0,
                collation_name=None,
            ),
        ),
        MssqlFieldBinding(
            field_name="local_time",
            column_name="local_time",
            physical=MssqlPhysicalField(
                system_type_name="datetime2",
                system_type_id=42,
                user_type_id=42,
                max_length=8,
                precision=27,
                scale=7,
                collation_name=None,
            ),
        ),
        MssqlFieldBinding(
            field_name="instant_time",
            column_name="instant_time",
            physical=MssqlPhysicalField(
                system_type_name="datetimeoffset",
                system_type_id=43,
                user_type_id=43,
                max_length=10,
                precision=34,
                scale=7,
                collation_name=None,
            ),
        ),
    )
    common_row_query = build_mssql_row_envelope_query(
        common_schema,
        common_relation,
        common_bindings,
        512,
    )
    common_fingerprint_query = build_mssql_fingerprint_query(
        common_schema,
        common_relation,
        common_bindings,
        512,
    )
    assert row_query.context.schema_digest_hex == _SCHEMA_DIGEST
    assert fingerprint_query.context.schema_digest_hex == _SCHEMA_DIGEST
    assert common_row_query.context.schema_digest_hex == _COMMON_SCHEMA_DIGEST
    assert common_fingerprint_query.context.schema_digest_hex == _COMMON_SCHEMA_DIGEST

    transport = open_mssql_transport(
        required_reader_settings("dfe-phase03-canonical-conformance"),
        single_attempt_retry_policy(),
    )
    try:
        row_result = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=row_query.statement,
                parameters=row_query.parameters,
            ),
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

        long_row = rows_by_envelope_bytes[_LONG_ENVELOPE_BYTES]
        assert long_row == (
            _LONG_ENVELOPE_BYTES,
            _LONG_SHA256_HEX,
            None,
            False,
            False,
        )
        short_row = rows_by_envelope_bytes[_SHORT_ENVELOPE_BYTES]
        assert short_row == (
            _SHORT_ENVELOPE_BYTES,
            _SHORT_SHA256_HEX,
            _SHORT_ENVELOPE,
            False,
            False,
        )

        fingerprint_result = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=fingerprint_query.statement,
                parameters=fingerprint_query.parameters,
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=64,
                max_record_bytes=512,
                max_total_bytes=512,
            ),
        )
        assert fingerprint_result.rows == ((2, *_EXPECTED_LIMB_SUMS, 0, 0),)

        tight_fingerprint_result = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=tight_fingerprint_query.statement,
                parameters=tight_fingerprint_query.parameters,
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=64,
                max_record_bytes=512,
                max_total_bytes=512,
            ),
        )
        assert tight_fingerprint_result.rows == ((1, *_SHORT_LIMBS, 0, 1),)

        common_row_result = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=common_row_query.statement,
                parameters=common_row_query.parameters,
            ),
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

        common_fingerprint_result = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=common_fingerprint_query.statement,
                parameters=common_fingerprint_query.parameters,
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=64,
                max_record_bytes=512,
                max_total_bytes=512,
            ),
        )
        assert common_fingerprint_result.rows == ((1, *_COMMON_LIMBS, 1, 0),)
    finally:
        if not transport.closed:
            transport.close()
