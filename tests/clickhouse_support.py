import os
import time
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import SecretStr

from forensic_data.clickhouse import (
    ClickHouseConnectionSettings,
    ClickHouseRetryPolicy,
    ClickHouseTransportLimits,
    ClickHouseTransportSecurity,
)
from forensic_data.postgres import PostgresReadDeadline

_CLICKHOUSE_TLS_DIRECTORY = (
    Path(__file__).resolve().parent.parent / ".local" / "p05-05-clickhouse-tls"
)


def required_clickhouse_reader_settings(application_name: str) -> ClickHouseConnectionSettings:
    return _required_clickhouse_settings(
        application_name=application_name,
        user="dfe_fixture_reader",
        password_environment_name="DFE_CLICKHOUSE_READER_PASSWORD",
    )


def required_clickhouse_tls_reader_settings(
    application_name: str,
) -> ClickHouseConnectionSettings:
    return _required_clickhouse_tls_reader_settings(
        application_name,
        _CLICKHOUSE_TLS_DIRECTORY / "fixture-ca.pem",
    )


def required_clickhouse_untrusted_tls_reader_settings(
    application_name: str,
) -> ClickHouseConnectionSettings:
    return _required_clickhouse_tls_reader_settings(
        application_name,
        _CLICKHOUSE_TLS_DIRECTORY / "wrong-ca.pem",
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


def _required_clickhouse_tls_reader_settings(
    application_name: str,
    ca_certificate: Path,
) -> ClickHouseConnectionSettings:
    if type(application_name) is not str or not application_name:
        raise ValueError("application_name must be non-empty text")
    if not ca_certificate.is_file():
        raise RuntimeError(
            "ClickHouse fixture CA certificate is missing: "
            f"path={str(ca_certificate)!r}; start the ClickHouse Compose fixture first"
        )
    return ClickHouseConnectionSettings(
        host="127.0.0.1",
        port=_required_clickhouse_https_port(),
        database="dfe_fixture",
        user="dfe_fixture_reader",
        password=SecretStr(_required_environment_value("DFE_CLICKHOUSE_READER_PASSWORD")),
        transport_security=ClickHouseTransportSecurity.TLS_VERIFY,
        ca_cert=str(ca_certificate),
        connect_timeout_seconds=5,
        send_receive_timeout_seconds=30,
        application_name=application_name,
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


def _required_clickhouse_https_port() -> int:
    port_text = _required_environment_value("DFE_CLICKHOUSE_HTTPS_PORT")
    if not port_text.isascii() or not port_text.isdecimal():
        raise RuntimeError("DFE_CLICKHOUSE_HTTPS_PORT must be a positive decimal integer")
    port = int(port_text)
    if not 1 <= port <= 65_535:
        raise RuntimeError("DFE_CLICKHOUSE_HTTPS_PORT must be in the range 1..65535")
    return port


def single_attempt_clickhouse_retry_policy() -> ClickHouseRetryPolicy:
    return ClickHouseRetryPolicy(max_attempts=1, delay_seconds=0.0)


def standard_clickhouse_transport_limits() -> ClickHouseTransportLimits:
    return ClickHouseTransportLimits(
        max_initialization_response_bytes=64,
        max_error_response_bytes=16_384,
        max_cancellation_response_bytes=131_072,
        max_query_bytes=65_536,
        max_ipc_message_bytes=262_144,
        cancellation_reserve_milliseconds=5_000,
        process_cleanup_timeout_milliseconds=1_000,
    )


def clickhouse_read_deadline(
    statement_timeout_milliseconds: int,
    attempt_timeout_milliseconds: int,
) -> PostgresReadDeadline:
    if type(statement_timeout_milliseconds) is not int or statement_timeout_milliseconds < 1:
        raise ValueError("statement_timeout_milliseconds must be a positive integer")
    if type(attempt_timeout_milliseconds) is not int or attempt_timeout_milliseconds < 1:
        raise ValueError("attempt_timeout_milliseconds must be a positive integer")
    return PostgresReadDeadline(
        statement_timeout_milliseconds=statement_timeout_milliseconds,
        deadline_nanoseconds=time.monotonic_ns() + attempt_timeout_milliseconds * 1_000_000,
    )


def fresh_clickhouse_attempt_id() -> UUID:
    return uuid4()


def _required_environment_value(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"{name} is required for ClickHouse integration tests")
    return value
