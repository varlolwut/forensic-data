from decimal import Decimal

import clickhouse_connect
import pytest
from clickhouse_connect.driver.exceptions import DatabaseError

from forensic_data.clickhouse import (
    ClickHouseConnectionSettings,
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
from tests.clickhouse_support import (
    required_clickhouse_reader_settings,
    single_attempt_clickhouse_retry_policy,
)

pytestmark = [pytest.mark.integration, pytest.mark.clickhouse]


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
