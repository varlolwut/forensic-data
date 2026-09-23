import os
from collections.abc import Mapping
from uuid import uuid4

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import tuple_row
from pydantic import SecretStr

from forensic_data.contracts.model import ExecutionBudgets
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresReadContext,
    PostgresRetryPolicy,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetLedger,
    PostgresSourceDirection,
    PostgresSslMode,
    open_postgres_read_context,
)

_INTEGRATION_EXECUTION_BUDGETS = ExecutionBudgets(
    version=1,
    max_queries=10_000,
    max_fetched_records=1_000_000,
    max_application_result_bytes=1_073_741_824,
    max_evidence_rows=10_000,
    max_evidence_bytes=134_217_728,
    max_fingerprint_nodes=100_000,
    max_coordinator_memory_bytes=134_217_728,
    max_depth=64,
    max_full_scans_per_side=1_000,
    statement_timeout_milliseconds=5_000,
    run_timeout_milliseconds=300_000,
    max_attempts=2,
    max_checks_concurrency=2,
    max_source_concurrency=1,
)


def required_connection_settings(
    environment_variable: str,
    application_name: str,
) -> PostgresConnectionSettings:
    dsn = os.environ.get(environment_variable)
    if dsn is None or not dsn:
        raise RuntimeError(f"{environment_variable} is required for PostgreSQL integration tests")
    try:
        parsed = conninfo_to_dict(dsn)
    except psycopg.ProgrammingError:
        raise RuntimeError(
            f"{environment_variable} must contain a valid PostgreSQL connection string"
        ) from None

    allowed_keys = frozenset(
        (
            "application_name",
            "connect_timeout",
            "dbname",
            "host",
            "password",
            "port",
            "sslmode",
            "user",
        )
    )
    extra_keys = sorted(set(parsed) - allowed_keys)
    if extra_keys:
        raise RuntimeError(
            f"{environment_variable} contains unsupported connection options: keys={extra_keys!r}"
        )

    host = _required_connection_value(parsed, "host", environment_variable)
    port = _positive_integer_connection_value(parsed, "port", environment_variable, 65_535)
    dbname = _required_connection_value(parsed, "dbname", environment_variable)
    user = _required_connection_value(parsed, "user", environment_variable)
    password = _required_connection_value(parsed, "password", environment_variable)
    sslmode_text = PostgresSslMode.DISABLE.value
    if "sslmode" in parsed:
        sslmode_text = _required_connection_value(parsed, "sslmode", environment_variable)
    try:
        sslmode = PostgresSslMode(sslmode_text)
    except ValueError:
        raise RuntimeError(
            f"{environment_variable} contains an unsupported sslmode value"
        ) from None
    connect_timeout_seconds = 5
    if "connect_timeout" in parsed:
        connect_timeout_seconds = _positive_integer_connection_value(
            parsed,
            "connect_timeout",
            environment_variable,
            2_147_483_647,
        )

    configured_application_name = application_name
    if "application_name" in parsed:
        configured_application_name = _required_connection_value(
            parsed,
            "application_name",
            environment_variable,
        )

    return PostgresConnectionSettings(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=SecretStr(password),
        sslmode=sslmode,
        connect_timeout_seconds=connect_timeout_seconds,
        statement_timeout_milliseconds=5_000,
        application_name=configured_application_name,
    )


def open_reader_context(settings: PostgresConnectionSettings) -> PostgresReadContext:
    return open_postgres_read_context(
        settings,
        PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0),
        source_budget_attempt(),
        PostgresSourceDirection.REFERENCE,
    )


def source_budget_attempt() -> PostgresSourceBudgetAttempt:
    ledger = PostgresSourceBudgetLedger(_INTEGRATION_EXECUTION_BUDGETS)
    return ledger.start_attempt(uuid4())


def connect_writer(
    settings: PostgresConnectionSettings,
) -> psycopg.Connection[DatabaseRow]:
    return psycopg.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password.get_secret_value(),
        sslmode=settings.sslmode.value,
        connect_timeout=settings.connect_timeout_seconds,
        application_name=settings.application_name,
        autocommit=True,
        row_factory=tuple_row,
    )


def _required_connection_value(
    parsed: Mapping[str, object],
    key: str,
    environment_variable: str,
) -> str:
    value = parsed.get(key)
    if type(value) is not str or not value:
        raise RuntimeError(
            f"{environment_variable} must provide the PostgreSQL {key!r} connection option"
        )
    return value


def _positive_integer_connection_value(
    parsed: Mapping[str, object],
    key: str,
    environment_variable: str,
    maximum: int,
) -> int:
    text = _required_connection_value(parsed, key, environment_variable)
    if not text.isascii() or not text.isdecimal():
        raise RuntimeError(
            f"{environment_variable} must provide {key!r} as a positive decimal integer"
        )
    value = int(text)
    if not 1 <= value <= maximum:
        raise RuntimeError(f"{environment_variable} must provide {key!r} in the range 1..{maximum}")
    return value
