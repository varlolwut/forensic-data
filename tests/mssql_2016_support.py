import os

import pyodbc
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
        "DFE_MSSQL_2016_READER_PASSWORD",
        application_name,
    )


def required_setup_writer_settings(application_name: str) -> MssqlConnectionSettings:
    return _required_fixture_settings(
        "dfe_fixture",
        "dfe_fixture_setup_writer",
        "DFE_MSSQL_2016_SETUP_WRITER_PASSWORD",
        application_name,
    )


def required_admin_settings(application_name: str) -> MssqlConnectionSettings:
    return _required_fixture_settings(
        "master",
        "sa",
        "DFE_MSSQL_2016_SA_PASSWORD",
        application_name,
    )


def connect_setup_writer(application_name: str) -> pyodbc.Connection:
    return _connect_read_write(required_setup_writer_settings(application_name))


def connect_fixture_admin(application_name: str) -> pyodbc.Connection:
    settings = _required_fixture_settings(
        "dfe_fixture",
        "sa",
        "DFE_MSSQL_2016_SA_PASSWORD",
        application_name,
    )
    return _connect_read_write(settings)


def single_attempt_retry_policy() -> MssqlRetryPolicy:
    return MssqlRetryPolicy(max_attempts=1, delay_seconds=0.0)


def _connect_read_write(settings: MssqlConnectionSettings) -> pyodbc.Connection:
    values = (
        ("Driver", "ODBC Driver 18 for SQL Server"),
        ("Server", f"tcp:{settings.host},{settings.port}"),
        ("Database", settings.database),
        ("UID", settings.user),
        ("PWD", settings.password.get_secret_value()),
        ("Encrypt", "Mandatory"),
        ("TrustServerCertificate", "Yes"),
        ("ApplicationIntent", "ReadWrite"),
        ("MARS_Connection", "No"),
        ("ConnectRetryCount", "0"),
        ("LongAsMax", "Yes"),
        ("APP", settings.application_name),
    )
    connection_string = ";".join(f"{key}={_odbc_braced(value)}" for key, value in values)
    connection = pyodbc.connect(
        connection_string,
        autocommit=False,
        readonly=False,
        timeout=settings.login_timeout_seconds,
    )
    connection.timeout = settings.query_timeout_seconds
    return connection


def _required_fixture_settings(
    database: str,
    user: str,
    password_environment_name: str,
    application_name: str,
) -> MssqlConnectionSettings:
    if type(application_name) is not str or not application_name:
        raise ValueError("application_name must be non-empty text")
    port_text = _required_environment_value("DFE_MSSQL_2016_PORT")
    if not port_text.isascii() or not port_text.isdecimal():
        raise RuntimeError("DFE_MSSQL_2016_PORT must be a positive decimal integer")
    port = int(port_text)
    if not 1 <= port <= 65_535:
        raise RuntimeError("DFE_MSSQL_2016_PORT must be in the range 1..65535")
    return MssqlConnectionSettings(
        host=_required_environment_value("DFE_MSSQL_2016_HOST"),
        port=port,
        database=database,
        user=user,
        password=SecretStr(_required_environment_value(password_environment_name)),
        tls_verification=MssqlTlsVerification.TRUST_FIXTURE_CERTIFICATE,
        login_timeout_seconds=5,
        query_timeout_seconds=60,
        cancellation_acknowledgement_timeout_seconds=5.0,
        application_name=application_name,
    )


def _required_environment_value(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"{name} is required for SQL Server 2016 integration tests")
    return value


def _odbc_braced(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"
