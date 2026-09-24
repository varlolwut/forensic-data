import os

from pydantic import SecretStr

from forensic_data.mssql import (
    MssqlConnectionSettings,
    MssqlRetryPolicy,
    MssqlTlsVerification,
)


def required_reader_settings(application_name: str) -> MssqlConnectionSettings:
    return _required_fixture_settings(
        "dfe_fixture",
        "dfe_fixture_reader",
        "DFE_MSSQL_READER_PASSWORD",
        application_name,
    )


def required_admin_settings(application_name: str) -> MssqlConnectionSettings:
    return _required_fixture_settings(
        "master",
        "sa",
        "DFE_MSSQL_SA_PASSWORD",
        application_name,
    )


def _required_fixture_settings(
    database: str,
    user: str,
    password_environment_name: str,
    application_name: str,
) -> MssqlConnectionSettings:
    if type(application_name) is not str or not application_name:
        raise ValueError("application_name must be non-empty text")
    port_text = _required_environment_value("DFE_MSSQL_PORT")
    if not port_text.isascii() or not port_text.isdecimal():
        raise RuntimeError("DFE_MSSQL_PORT must be a positive decimal integer")
    port = int(port_text)
    if not 1 <= port <= 65_535:
        raise RuntimeError("DFE_MSSQL_PORT must be in the range 1..65535")

    return MssqlConnectionSettings(
        host="127.0.0.1",
        port=port,
        database=database,
        user=user,
        password=SecretStr(_required_environment_value(password_environment_name)),
        tls_verification=MssqlTlsVerification.TRUST_FIXTURE_CERTIFICATE,
        login_timeout_seconds=5,
        query_timeout_seconds=30,
        cancellation_acknowledgement_timeout_seconds=5.0,
        application_name=application_name,
    )


def single_attempt_retry_policy() -> MssqlRetryPolicy:
    return MssqlRetryPolicy(max_attempts=1, delay_seconds=0.0)


def _required_environment_value(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"{name} is required for SQL Server integration tests")
    return value
