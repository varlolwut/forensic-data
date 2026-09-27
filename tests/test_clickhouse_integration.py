from decimal import Decimal

import clickhouse_connect
import pytest
from clickhouse_connect.driver.exceptions import DatabaseError

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    FieldSchema,
    Fingerprint,
    LogicalType,
    NoParameters,
    Normalization,
    encode_key,
    encode_row,
    envelope_sha256,
    schema_from_metadata_json,
)
from forensic_data.clickhouse import (
    ClickHouseConnectionSettings,
    ClickHouseDataValidationError,
    ClickHouseExactReadRequest,
    ClickHouseExactRow,
    ClickHouseResourceConstraint,
    ClickHouseResourceSetting,
    ClickHouseResultLimitError,
    ClickHouseTransportState,
    inspect_clickhouse_fidelity_relation,
    inspect_clickhouse_server_profile,
    open_clickhouse_transport,
    read_clickhouse_exact_values,
)
from forensic_data.clickhouse_canonical import (
    ClickHouseCanonicalGroupRequest,
    ClickHouseCanonicalLimits,
    ClickHouseCanonicalReadRequest,
    inspect_clickhouse_canonical_relation,
    read_clickhouse_canonical_fingerprint,
    read_clickhouse_canonical_key_groups,
    read_clickhouse_canonical_rows,
)
from tests.canonical_vectors import vector_named
from tests.clickhouse_support import (
    required_clickhouse_reader_settings,
    single_attempt_clickhouse_retry_policy,
)

pytestmark = [pytest.mark.integration, pytest.mark.clickhouse]

_COMMON_TYPE_COLUMNS = (
    "id",
    "amount",
    "active",
    "label",
    "business_date",
    "local_time",
    "instant_time",
)
_ZERO_LIMBS = (0, 0, 0, 0, 0, 0, 0, 0)


def test_clickhouse_canonical_bytes_fingerprint_and_binary_groups_match_shared_oracle() -> None:
    row_vector = vector_named("all_common_types")
    row_schema = schema_from_metadata_json(row_vector.metadata_json)
    key_vector = vector_named("composite_key")
    key_schema = schema_from_metadata_json(key_vector.metadata_json)
    limits = ClickHouseCanonicalLimits(
        max_encoded_envelope_bytes=1_024,
        max_response_bytes=65_536,
        max_execution_time_seconds=5,
    )
    settings = required_clickhouse_reader_settings("dfe-phase05-canonical")
    transport = open_clickhouse_transport(
        settings,
        single_attempt_clickhouse_retry_policy(),
    )
    try:
        relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_common_types",
            schema=row_schema,
            column_names=_COMMON_TYPE_COLUMNS,
            max_response_bytes=16_384,
            max_execution_time_seconds=5,
        )
        rows = read_clickhouse_canonical_rows(
            transport,
            ClickHouseCanonicalReadRequest(
                relation=relation,
                order_columns=("probe_id",),
                max_records=2,
                limits=limits,
            ),
        )
        expected_envelope = row_vector.envelope_ascii.encode("ascii")
        expected_sha256 = bytes.fromhex(row_vector.sha256_hex)
        assert tuple(row.envelope for row in rows) == (expected_envelope, expected_envelope)
        assert tuple(row.sha256 for row in rows) == (expected_sha256, expected_sha256)

        fingerprint = read_clickhouse_canonical_fingerprint(
            transport,
            relation,
            limits,
        )
        assert row_vector.duplicate_twice_count is not None
        assert row_vector.duplicate_twice_limb_sums is not None
        assert fingerprint.fingerprint == Fingerprint(
            count=row_vector.duplicate_twice_count,
            limb_sums=row_vector.duplicate_twice_limb_sums,
        )
        assert fingerprint.invalid_row_count == 0
        assert fingerprint.oversized_row_count == 0

        empty_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_empty_common_types",
            schema=row_schema,
            column_names=_COMMON_TYPE_COLUMNS,
            max_response_bytes=16_384,
            max_execution_time_seconds=5,
        )
        empty_fingerprint = read_clickhouse_canonical_fingerprint(
            transport,
            empty_relation,
            limits,
        )
        assert empty_fingerprint.fingerprint == Fingerprint(
            count=0,
            limb_sums=_ZERO_LIMBS,
        )
        assert empty_fingerprint.invalid_row_count == 0
        assert empty_fingerprint.oversized_row_count == 0

        lossy_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_lossy_common_types",
            schema=row_schema,
            column_names=_COMMON_TYPE_COLUMNS,
            max_response_bytes=16_384,
            max_execution_time_seconds=5,
        )
        with pytest.raises(
            ClickHouseDataValidationError,
            match="invalid_row_count=2",
        ):
            read_clickhouse_canonical_fingerprint(
                transport,
                lossy_relation,
                limits,
            )

        nullable_schema = CanonicalSchema(
            protocol=PROTOCOL,
            fields=(
                FieldSchema(
                    name="label",
                    logical_type=LogicalType.STRING,
                    nullable=True,
                    parameters=NoParameters(),
                    normalization=Normalization.NONE,
                ),
            ),
        )
        nullable_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_nullable_strings",
            schema=nullable_schema,
            column_names=("label",),
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        )
        nullable_rows = read_clickhouse_canonical_rows(
            transport,
            ClickHouseCanonicalReadRequest(
                relation=nullable_relation,
                order_columns=("probe_id",),
                max_records=2,
                limits=limits,
            ),
        )
        expected_nullable_envelopes = (
            encode_row(nullable_schema, (None,)),
            encode_row(nullable_schema, ("",)),
        )
        assert tuple(row.envelope for row in nullable_rows) == expected_nullable_envelopes
        assert tuple(row.sha256 for row in nullable_rows) == tuple(
            envelope_sha256(envelope) for envelope in expected_nullable_envelopes
        )
        assert expected_nullable_envelopes[0] != expected_nullable_envelopes[1]

        key_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_key_groups",
            schema=key_schema,
            column_names=("id", "label"),
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        )
        key_groups = read_clickhouse_canonical_key_groups(
            transport,
            ClickHouseCanonicalGroupRequest(
                relation=key_relation,
                max_groups=4,
                limits=limits,
            ),
        )
        golden_id, golden_label = key_vector.values
        assert type(golden_id) is str
        assert type(golden_label) is str
        expected_groups = {
            encode_key(key_schema, (int(golden_id), golden_label)): 2,
            encode_key(key_schema, (int(golden_id), golden_label[:-1])): 1,
            encode_key(key_schema, (int(golden_id), "A|Б😀é  ")): 1,
            encode_key(key_schema, (int(golden_id) + 1, golden_label)): 1,
        }
        assert {group.envelope: group.row_count for group in key_groups.groups} == expected_groups
        assert key_groups.valid_key_count == 5
        assert key_groups.invalid_key_count == 0
        assert key_groups.oversized_key_count == 0

        overflow_schema = CanonicalSchema(
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
        overflow_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_group_overflow",
            schema=overflow_schema,
            column_names=("id",),
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        )
        with pytest.raises(
            ClickHouseResultLimitError,
            match="exceeded its distinct-group bound",
        ):
            read_clickhouse_canonical_key_groups(
                transport,
                ClickHouseCanonicalGroupRequest(
                    relation=overflow_relation,
                    max_groups=4,
                    limits=limits,
                ),
            )

        null_key_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_null_key",
            schema=key_schema,
            column_names=("id", "label"),
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        )
        with pytest.raises(
            ClickHouseDataValidationError,
            match="invalid_key_count=1",
        ):
            read_clickhouse_canonical_key_groups(
                transport,
                ClickHouseCanonicalGroupRequest(
                    relation=null_key_relation,
                    max_groups=1,
                    limits=limits,
                ),
            )
    finally:
        transport.close()


def test_clickhouse_lts_profile_is_lossless_bounded_and_read_only() -> None:
    settings = required_clickhouse_reader_settings("dfe-phase05-profile")
    transport = open_clickhouse_transport(
        settings,
        single_attempt_clickhouse_retry_policy(),
    )
    try:
        profile = inspect_clickhouse_server_profile(transport, settings)
        assert profile.driver_name == "clickhouse-connect"
        assert profile.driver_version == "1.9.0"
        assert profile.server_version == "26.8.6.5"
        assert profile.build_id == "2B715913B3A50F932D0F7A695FD4CECFBAC50A6A"
        assert profile.server_timezone == "UTC"
        assert profile.session_timezone == "UTC"
        assert profile.current_user == "dfe_fixture_reader"
        assert profile.current_database == "dfe_fixture"
        assert profile.readonly == 1
        assert profile.max_memory_usage == 268_435_456
        assert profile.max_threads == 2
        assert profile.max_execution_time_seconds == Decimal("30")
        assert profile.max_result_rows == 100_000
        assert profile.max_result_bytes == 67_108_864
        assert profile.result_overflow_mode == "throw"
        assert profile.readonly_locked is True
        assert profile.result_overflow_mode_locked is True
        assert profile.resource_constraints == (
            _resource_constraint(
                ClickHouseResourceSetting.MAX_MEMORY_USAGE,
                Decimal("268435456"),
                False,
            ),
            _resource_constraint(
                ClickHouseResourceSetting.MAX_THREADS,
                Decimal("2"),
                False,
            ),
            _resource_constraint(
                ClickHouseResourceSetting.MAX_EXECUTION_TIME,
                Decimal("30"),
                True,
            ),
            _resource_constraint(
                ClickHouseResourceSetting.MAX_RESULT_ROWS,
                Decimal("100000"),
                True,
            ),
            _resource_constraint(
                ClickHouseResourceSetting.MAX_RESULT_BYTES,
                Decimal("67108864"),
                True,
            ),
        )

        relation = inspect_clickhouse_fidelity_relation(
            transport=transport,
            database="dfe_fixture",
            table="fidelity_probe",
            decimal_column='amount\\"quoted',
            datetime_column="observed_at",
        )
        assert relation.decimal_type.precision == 38
        assert relation.decimal_type.scale == 9
        assert relation.datetime_type.precision == 9
        assert relation.datetime_type.declared_timezone == "America/New_York"
        assert relation.datetime_type.timezone == "America/New_York"

        rows = read_clickhouse_exact_values(
            transport,
            ClickHouseExactReadRequest(
                relation=relation,
                order_column="probe_id",
                max_rows=3,
                max_response_bytes=2_048,
                max_execution_time_seconds=5,
            ),
        )
        assert rows == (
            _expected_row(
                order_value=1,
                decimal_scaled=-99_999_999_999_999_999_999_999_999_999_999_999_999,
                decimal_text="-99999999999999999999999999999.999999999",
                datetime_ticks=-876_543_211,
                datetime_text="1969-12-31 23:59:59.123456789",
            ),
            _expected_row(
                order_value=2,
                decimal_scaled=0,
                decimal_text="0.000000000",
                datetime_ticks=0,
                datetime_text="1970-01-01 00:00:00.000000000",
            ),
            _expected_row(
                order_value=3,
                decimal_scaled=99_999_999_999_999_999_999_999_999_999_999_999_999,
                decimal_text="99999999999999999999999999999.999999999",
                datetime_ticks=9_223_372_036_854_775_807,
                datetime_text="2262-04-11 23:47:16.854775807",
            ),
        )
        with pytest.raises(ClickHouseResultLimitError):
            transport.execute_raw(
                query="SELECT repeat('x', {result_size:UInt64})",
                parameters={"result_size": 2_048},
                settings={
                    "session_timezone": "UTC",
                    "max_execution_time": 5,
                    "max_result_rows": 1,
                    "max_result_bytes": 4_096,
                    "result_overflow_mode": "throw",
                },
                result_format="TabSeparatedRaw",
                max_response_bytes=64,
                operation="prove_success_response_byte_bound",
            )
        assert transport.state is ClickHouseTransportState.LOST
    finally:
        if not transport.closed:
            transport.close()

    _require_server_rejects_write(
        settings=settings,
        command=(
            "INSERT INTO dfe_fixture.fidelity_probe VALUES "
            "(4, '1.000000000', '2026-09-25 00:00:00.000000000')"
        ),
        error_fragment="Not enough privileges",
    )
    _require_server_rejects_setting_raise(settings)
    _require_server_rejects_write(
        settings=settings,
        command=(
            "CREATE TABLE dfe_fixture.forbidden_probe "
            "(value UInt8) ENGINE = MergeTree ORDER BY value"
        ),
        error_fragment="Not enough privileges",
    )


def _expected_row(
    order_value: int,
    decimal_scaled: int,
    decimal_text: str,
    datetime_ticks: int,
    datetime_text: str,
) -> ClickHouseExactRow:
    return ClickHouseExactRow(
        order_value=order_value,
        decimal_scaled_value=decimal_scaled,
        decimal_text=decimal_text,
        datetime_ticks=datetime_ticks,
        datetime_text=datetime_text,
    )


def _resource_constraint(
    setting: ClickHouseResourceSetting,
    value: Decimal,
    changeable_in_readonly: bool,
) -> ClickHouseResourceConstraint:
    return ClickHouseResourceConstraint(
        setting=setting,
        value=value,
        minimum=Decimal("1") if changeable_in_readonly else None,
        maximum=value if changeable_in_readonly else None,
        changeable_in_readonly=changeable_in_readonly,
    )


def _require_server_rejects_write(
    settings: ClickHouseConnectionSettings,
    command: str,
    error_fragment: str,
) -> None:
    client = clickhouse_connect.get_client(  # pyright: ignore[reportUnknownMemberType]
        host=settings.host,
        username=settings.user,
        password=settings.password.get_secret_value(),
        database=settings.database,
        interface="http",
        port=settings.port,
        secure=False,
        settings={"session_timezone": "UTC"},
        compress=False,
        query_limit=0,
        query_retries=0,
        connect_timeout=settings.connect_timeout_seconds,
        send_receive_timeout=settings.send_receive_timeout_seconds,
        client_name="forensic-data-p05-readonly-proof",
        verify=True,
        tz_source="server",
        tz_mode="schema",
        show_clickhouse_errors="scrub",
        autogenerate_session_id=False,
        autogenerate_query_id=False,
        form_encode_query_params=True,
        native_codec="python",
    )
    try:
        with pytest.raises(DatabaseError, match=error_fragment):
            client.command(command)  # pyright: ignore[reportUnknownMemberType]
    finally:
        client.close_connections()


def _require_server_rejects_setting_raise(settings: ClickHouseConnectionSettings) -> None:
    client = clickhouse_connect.get_client(  # pyright: ignore[reportUnknownMemberType]
        host=settings.host,
        username=settings.user,
        password=settings.password.get_secret_value(),
        database=settings.database,
        interface="http",
        port=settings.port,
        secure=False,
        settings={"session_timezone": "UTC"},
        compress=False,
        query_limit=0,
        query_retries=0,
        connect_timeout=settings.connect_timeout_seconds,
        send_receive_timeout=settings.send_receive_timeout_seconds,
        client_name="forensic-data-p05-resource-ceiling-proof",
        verify=True,
        tz_source="server",
        tz_mode="schema",
        show_clickhouse_errors="scrub",
        autogenerate_session_id=False,
        autogenerate_query_id=False,
        form_encode_query_params=True,
        native_codec="python",
    )
    try:
        with pytest.raises(DatabaseError, match="shouldn't be greater than 67108864"):
            client.raw_query(  # pyright: ignore[reportUnknownMemberType]
                query="SELECT 1",
                settings={"max_result_bytes": 67_108_865},
                fmt="TabSeparatedRaw",
            )
    finally:
        client.close_connections()
