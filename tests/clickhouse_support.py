import os

from pydantic import SecretStr

from forensic_data.clickhouse import (
    ClickHouseConnectionSettings,
    ClickHouseRetryPolicy,
    ClickHouseTransportSecurity,
)


def required_clickhouse_reader_settings(application_name: str) -> ClickHouseConnectionSettings:
    return _required_clickhouse_settings(
        application_name=application_name,
        user="dfe_fixture_reader",
        password_environment_name="DFE_CLICKHOUSE_READER_PASSWORD",
    )


def required_clickhouse_admin_settings(application_name: str) -> ClickHouseConnectionSettings:
    return _required_clickhouse_settings(
        application_name=application_name,
        user="dfe_fixture_admin",
        password_environment_name="DFE_CLICKHOUSE_ADMIN_PASSWORD",
    )


def required_clickhouse_writer_settings(application_name: str) -> ClickHouseConnectionSettings:
    return _required_clickhouse_settings(
        application_name=application_name,
        user="dfe_fixture_writer",
        password_environment_name="DFE_CLICKHOUSE_WRITER_PASSWORD",
    )


def _required_clickhouse_settings(
    application_name: str,
    user: str,
    password_environment_name: str,
) -> ClickHouseConnectionSettings:
    if type(application_name) is not str or not application_name:
        raise ValueError("application_name must be non-empty text")
    if type(user) is not str or not user:
        raise ValueError("user must be non-empty text")
    if type(password_environment_name) is not str or not password_environment_name:
        raise ValueError("password_environment_name must be non-empty text")
    return ClickHouseConnectionSettings(
        host="127.0.0.1",
        port=_required_clickhouse_port(),
        database="dfe_fixture",
        user=user,
        password=SecretStr(_required_environment_value(password_environment_name)),
        transport_security=ClickHouseTransportSecurity.PLAINTEXT_LOCAL_FIXTURE,
        ca_cert=None,
        connect_timeout_seconds=5,
        send_receive_timeout_seconds=30,
        application_name=application_name,
    )


def _required_clickhouse_port() -> int:
    port_text = _required_environment_value("DFE_CLICKHOUSE_HTTP_PORT")
    if not port_text.isascii() or not port_text.isdecimal():
        raise RuntimeError("DFE_CLICKHOUSE_HTTP_PORT must be a positive decimal integer")
    port = int(port_text)
    if not 1 <= port <= 65_535:
        raise RuntimeError("DFE_CLICKHOUSE_HTTP_PORT must be in the range 1..65535")
    return port


def single_attempt_clickhouse_retry_policy() -> ClickHouseRetryPolicy:
    return ClickHouseRetryPolicy(max_attempts=1, delay_seconds=0.0)


def _required_environment_value(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"{name} is required for ClickHouse integration tests")
    return value
