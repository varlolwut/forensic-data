import os

from pydantic import SecretStr

from forensic_data.clickhouse import (
    ClickHouseConnectionSettings,
    ClickHouseRetryPolicy,
    ClickHouseTransportSecurity,
)


def required_clickhouse_reader_settings(application_name: str) -> ClickHouseConnectionSettings:
    if type(application_name) is not str or not application_name:
        raise ValueError("application_name must be non-empty text")
    port_text = _required_environment_value("DFE_CLICKHOUSE_HTTP_PORT")
    if not port_text.isascii() or not port_text.isdecimal():
        raise RuntimeError("DFE_CLICKHOUSE_HTTP_PORT must be a positive decimal integer")
    port = int(port_text)
    if not 1 <= port <= 65_535:
        raise RuntimeError("DFE_CLICKHOUSE_HTTP_PORT must be in the range 1..65535")
    return ClickHouseConnectionSettings(
        host="127.0.0.1",
        port=port,
        database="dfe_fixture",
        user="dfe_fixture_reader",
        password=SecretStr(_required_environment_value("DFE_CLICKHOUSE_READER_PASSWORD")),
        transport_security=ClickHouseTransportSecurity.PLAINTEXT_LOCAL_FIXTURE,
        ca_cert=None,
        connect_timeout_seconds=5,
        send_receive_timeout_seconds=30,
        application_name=application_name,
    )


def single_attempt_clickhouse_retry_policy() -> ClickHouseRetryPolicy:
    return ClickHouseRetryPolicy(max_attempts=1, delay_seconds=0.0)


def _required_environment_value(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"{name} is required for ClickHouse integration tests")
    return value
