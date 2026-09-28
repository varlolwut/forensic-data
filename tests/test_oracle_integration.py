import os
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import SecretStr

from forensic_data.contracts.model import ExecutionBudgets
from forensic_data.oracle import (
    OracleBindParameter,
    OracleConnectionSettings,
    OracleProjection,
    OracleProtocol,
    OracleQuery,
    OracleQueryError,
    OracleReadContextState,
    OracleResultLimitError,
    OracleRetryPolicy,
    open_oracle_read_context,
)
from forensic_data.oracle_limits import (
    OracleProjectionKind,
    build_oracle_transport_limits,
)
from forensic_data.oracle_profile import OracleRuntimeProfile
from forensic_data.postgres import PostgresSourceBudgetLedger, PostgresSourceDirection

pytestmark = [pytest.mark.integration, pytest.mark.oracle]

_ORACLE_PORT_ENVIRONMENT = "DFE_TEST_ORACLE_PORT"
_ORACLE_PASSWORD_ENVIRONMENT = "DFE_TEST_ORACLE_READER_PASSWORD"
_ORACLE_USER = "DFE_FIXTURE_READER"
_ORACLE_SERVICE = "FREEPDB1"
_ORACLE_REPORTED_SERVICE = "freepdb1"
_ORACLE_SERVER_VERSION = "23.26.3.0.0"

_EXECUTION_BUDGETS = ExecutionBudgets(
    version=1,
    max_queries=4,
    max_fetched_records=4,
    max_application_result_bytes=65_536,
    max_evidence_rows=0,
    max_evidence_bytes=0,
    max_fingerprint_nodes=1,
    max_coordinator_memory_bytes=8_388_608,
    max_depth=0,
    max_full_scans_per_side=0,
    statement_timeout_milliseconds=30_000,
    run_timeout_milliseconds=120_000,
    max_attempts=1,
    max_checks_concurrency=1,
    max_source_concurrency=1,
)


def test_oracle_context_preserves_scalars_and_rejects_row_locks() -> None:
    settings = OracleConnectionSettings(
        host="127.0.0.1",
        port=_required_oracle_port(),
        service_name=_ORACLE_SERVICE,
        user=_ORACLE_USER,
        password=SecretStr(_required_environment_text(_ORACLE_PASSWORD_ENVIRONMENT)),
        protocol=OracleProtocol.TCP,
        tls_server_dn_match=False,
        wallet_location=None,
        tcp_connect_timeout_seconds=5.0,
        disable_out_of_band_breaks=True,
        application_name="dfe-p06-oracle-free",
    )
    source_budget = PostgresSourceBudgetLedger(_EXECUTION_BUDGETS).start_attempt(uuid4())
    context = open_oracle_read_context(
        settings,
        OracleRetryPolicy(1, 0.0),
        build_oracle_transport_limits(_EXECUTION_BUDGETS),
        source_budget,
        PostgresSourceDirection.REFERENCE,
        OracleRuntimeProfile.THIN_3_4,
    )
    try:
        assert context.state is OracleReadContextState.ACTIVE
        assert context.profile.driver.driver_version == "3.4.2"
        assert context.profile.driver.server_version == _ORACLE_SERVER_VERSION
        assert context.profile.driver.thin_mode is True
        assert context.profile.driver.requested_username == _ORACLE_USER
        assert context.profile.session_user == _ORACLE_USER
        assert context.profile.service_name == _ORACLE_REPORTED_SERVICE
        assert context.profile.database_character_set == "AL32UTF8"
        assert context.evidence.engine == "oracle"
        assert context.evidence.strategy == "transaction_read_only_session_unprotected"
        assert context.evidence.allowed_concurrency == 1

        usage_before_rejection = source_budget.snapshot()
        with pytest.raises(OracleResultLimitError, match="max_request_bytes"):
            context.read(_repeated_bind_limit_query(), 1)
        usage_after_rejection = source_budget.snapshot()
        assert usage_after_rejection.queries == usage_before_rejection.queries
        assert usage_after_rejection.fetched_records == usage_before_rejection.fetched_records
        assert usage_after_rejection.result_bytes == usage_before_rejection.result_bytes
        assert context.state is OracleReadContextState.ACTIVE
        assert context.active_query_id is None

        result = context.read(_scalar_fidelity_query(), 1)
        expected_number = Decimal("-1234567890123456789012345678901.2345678")
        assert result.rows == (
            (
                expected_number,
                "Привет 😀",
                b"\x00\xff\x80",
                "2024-02-29T01:02:03",
                "2024-02-29T01:02:03.123456789",
                "2024-02-29T01:02:03.123456789+05:30",
                None,
                None,
                "A  ",
            ),
        )
        number_tuple = expected_number.as_tuple()
        assert number_tuple.exponent == -7
        assert len(number_tuple.digits) == 38
        assert result.metrics.fetched_records == 1
        assert result.metrics.fetched_bytes == 146
        assert result.metrics.fetch_calls == 2
        assert result.metrics.largest_batch_records == 1

        lock_query = _read_only_lock_query()
        with pytest.raises(OracleQueryError) as raised:
            context.read(lock_query, 1)
        error = raised.value
        assert error.query_id == lock_query.query_id
        assert error.session_id == context.evidence.session_id
        assert error.code == 1_456
        assert error.full_code == "ORA-01456"
        assert error.driver_message == "Oracle native error text was redacted"
        assert error.recoverable is False
        assert error.cleanup_failed is False
        assert "READ_ONLY_PROBE" not in str(error)
        assert context.state is OracleReadContextState.LOST
        assert context.active_query_id is None

        context.close()
        assert context.state is OracleReadContextState.CLOSED
    finally:
        if context.state is not OracleReadContextState.CLOSED:
            context.close()


def _scalar_fidelity_query() -> OracleQuery:
    statement = """
SELECT
    CAST(
        -1234567890123456789012345678901.2345678 AS NUMBER(38, 7)
    ) AS EXACT_NUMBER,
    CAST(
        UNISTR('\\041F\\0440\\0438\\0432\\0435\\0442') ||
        ' ' || UNISTR('\\D83D\\DE00') AS VARCHAR2(64 BYTE)
    ) AS UNICODE_TEXT,
    CAST(HEXTORAW('00FF80') AS RAW(3)) AS RAW_BYTES,
    CAST(
        TO_CHAR(
            TO_DATE(
                '2024-02-29 01:02:03',
                'YYYY-MM-DD HH24:MI:SS',
                'NLS_DATE_LANGUAGE=American'
            ),
            'YYYY-MM-DD"T"HH24:MI:SS',
            'NLS_DATE_LANGUAGE=American'
        ) AS VARCHAR2(19 BYTE)
    ) AS DATE_TEXT,
    CAST(
        TO_CHAR(
            TIMESTAMP '2024-02-29 01:02:03.123456789',
            'YYYY-MM-DD"T"HH24:MI:SS.FF9',
            'NLS_DATE_LANGUAGE=American'
        ) AS VARCHAR2(29 BYTE)
    ) AS TIMESTAMP_TEXT,
    CAST(
        TO_CHAR(
            TIMESTAMP '2024-02-29 01:02:03.123456789 +05:30',
            'YYYY-MM-DD"T"HH24:MI:SS.FF9TZH:TZM',
            'NLS_DATE_LANGUAGE=American'
        ) AS VARCHAR2(35 BYTE)
    ) AS TIMESTAMP_TZ_TEXT,
    CAST('' AS VARCHAR2(1 BYTE)) AS EMPTY_TEXT,
    CAST(NULL AS VARCHAR2(1 BYTE)) AS NULL_TEXT,
    CAST(CAST('A' AS CHAR(3 BYTE)) AS VARCHAR2(3 BYTE)) AS PADDED_CHAR_TEXT
FROM SYS.DUAL
""".strip()
    projections = (
        OracleProjection("EXACT_NUMBER", OracleProjectionKind.DECIMAL, False, 40, 40),
        OracleProjection("UNICODE_TEXT", OracleProjectionKind.TEXT, False, 64, 256),
        OracleProjection("RAW_BYTES", OracleProjectionKind.RAW, False, 3, 3),
        OracleProjection("DATE_TEXT", OracleProjectionKind.ASCII, False, 19, 76),
        OracleProjection("TIMESTAMP_TEXT", OracleProjectionKind.ASCII, False, 29, 116),
        OracleProjection("TIMESTAMP_TZ_TEXT", OracleProjectionKind.ASCII, False, 35, 140),
        OracleProjection("EMPTY_TEXT", OracleProjectionKind.TEXT, True, 1, 4),
        OracleProjection("NULL_TEXT", OracleProjectionKind.TEXT, True, 1, 4),
        OracleProjection("PADDED_CHAR_TEXT", OracleProjectionKind.ASCII, False, 3, 12),
    )
    return OracleQuery(uuid4(), statement, (), projections, 0)


def _repeated_bind_limit_query() -> OracleQuery:
    repeated_expression = " + ".join("LENGTH(:payload)" for _occurrence in range(66))
    statement = f"SELECT CAST({repeated_expression} AS NUMBER(10, 0)) AS VALUE FROM SYS.DUAL"
    return OracleQuery(
        uuid4(),
        statement,
        (OracleBindParameter("payload", "x" * 2_000),),
        (OracleProjection("VALUE", OracleProjectionKind.DECIMAL, False, 11, 11),),
        0,
    )


def _read_only_lock_query() -> OracleQuery:
    statement = """
SELECT CAST(PROBE_ID AS NUMBER(10, 0)) AS PROBE_ID
FROM DFE_FIXTURE_OWNER.READ_ONLY_PROBE
WHERE PROBE_ID = :probe_id
FOR UPDATE
""".strip()
    return OracleQuery(
        uuid4(),
        statement,
        (OracleBindParameter("probe_id", 1),),
        (OracleProjection("PROBE_ID", OracleProjectionKind.DECIMAL, False, 11, 11),),
        0,
    )


def _required_oracle_port() -> int:
    raw_port = _required_environment_text(_ORACLE_PORT_ENVIRONMENT)
    try:
        port = int(raw_port)
    except ValueError:
        raise RuntimeError(f"{_ORACLE_PORT_ENVIRONMENT} must contain a base-10 TCP port") from None
    if not 1 <= port <= 65_535:
        raise RuntimeError(f"{_ORACLE_PORT_ENVIRONMENT} must be in the range 1..65535")
    return port


def _required_environment_text(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"{name} is required for Oracle integration tests")
    return value
