import time
from concurrent.futures import Future, ThreadPoolExecutor
from decimal import Decimal
from queue import Empty, Queue
from uuid import UUID, uuid4

import pytest

from forensic_data.mssql import (
    MssqlCancellationConfirmedError,
    MssqlFetchLimits,
    MssqlLossyTransportError,
    MssqlQuery,
    MssqlReadResult,
    MssqlResultLimitError,
    MssqlTransport,
    MssqlWrongQueryIdError,
    open_mssql_transport,
)
from tests.mssql_support import (
    required_admin_settings,
    required_reader_settings,
    single_attempt_retry_policy,
)

pytestmark = [pytest.mark.integration, pytest.mark.mssql]

_NUMBER_QUERY = (
    "WITH [numbers] AS ("
    "SELECT CONVERT(bigint, 1) AS [number] "
    "UNION ALL SELECT [number] + 1 FROM [numbers] WHERE [number] < 23"
    ") SELECT [number] FROM [numbers] ORDER BY [number]"
)


def test_mssql_transport_is_lossless_and_bounded() -> None:
    transport = _open_reader_transport()
    try:
        assert transport.evidence.pyodbc_version == "5.3.0"
        assert transport.evidence.driver_name == "libmsodbcsql-18.7.so.1.1"
        assert transport.evidence.driver_version == "18.07.0001"
        assert transport.evidence.server_version == "16.0.4295.3"
        assert transport.evidence.session_id > 0

        fidelity = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=(
                    "SELECT [amount], "
                    "CONVERT(decimal(38, 3), "
                    "N'99999999999999999999999999999999999.999'), "
                    "[observed_value], CONVERT(char(27), [observed_at], 126) "
                    "FROM [dfe_fixture].[snapshot_probe] WHERE [record_id] = 1"
                ),
                parameters=(),
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=512,
                max_record_bytes=1_024,
                max_total_bytes=1_024,
                max_declared_value_bytes=512,
                max_declared_record_bytes=1_024,
            ),
        )
        expected_high_precision = Decimal("99999999999999999999999999999999999.999")
        assert fidelity.rows == (
            (
                Decimal("123.450"),
                expected_high_precision,
                "Привет 😀",
                "2026-09-24T01:02:03.1234567",
            ),
        )
        amount = fidelity.rows[0][0]
        assert type(amount) is Decimal
        assert amount.as_tuple().exponent == -3
        assert len(expected_high_precision.as_tuple().digits) == 38
        assert fidelity.metrics.fetched_records == 1
        assert fidelity.metrics.fetch_calls == 2
        assert fidelity.metrics.largest_batch_records == 1
        assert 0 < fidelity.metrics.fetched_bytes <= 1_024

        streamed = transport.execute_bounded(
            MssqlQuery(
                query_id=uuid4(),
                statement=_NUMBER_QUERY,
                parameters=(),
            ),
            MssqlFetchLimits(
                fetch_batch_records=7,
                max_records=23,
                max_value_bytes=64,
                max_record_bytes=64,
                max_total_bytes=1_024,
                max_declared_value_bytes=64,
                max_declared_record_bytes=64,
            ),
        )
        assert streamed.rows == tuple((value,) for value in range(1, 24))
        assert streamed.metrics.fetched_records == 23
        assert streamed.metrics.fetch_calls == 5
        assert streamed.metrics.largest_batch_records == 7
    finally:
        if not transport.closed:
            transport.close()

    record_limited_transport = _open_reader_transport()
    try:
        with pytest.raises(MssqlResultLimitError, match="max_records"):
            record_limited_transport.execute_bounded(
                MssqlQuery(
                    query_id=uuid4(),
                    statement=_NUMBER_QUERY,
                    parameters=(),
                ),
                MssqlFetchLimits(
                    fetch_batch_records=7,
                    max_records=22,
                    max_value_bytes=64,
                    max_record_bytes=64,
                    max_total_bytes=1_024,
                    max_declared_value_bytes=64,
                    max_declared_record_bytes=64,
                ),
            )
        assert record_limited_transport.closed
    finally:
        if not record_limited_transport.closed:
            record_limited_transport.close()

    lossy_transport = _open_reader_transport()
    try:
        with pytest.raises(
            MssqlLossyTransportError,
            match="project temporal values as exact ISO text",
        ):
            lossy_transport.execute_bounded(
                MssqlQuery(
                    query_id=uuid4(),
                    statement=(
                        "SELECT [observed_at] FROM [dfe_fixture].[snapshot_probe] "
                        "WHERE [record_id] = 1"
                    ),
                    parameters=(),
                ),
                MssqlFetchLimits(
                    fetch_batch_records=1,
                    max_records=1,
                    max_value_bytes=128,
                    max_record_bytes=128,
                    max_total_bytes=128,
                    max_declared_value_bytes=128,
                    max_declared_record_bytes=128,
                ),
            )
        assert lossy_transport.closed
    finally:
        if not lossy_transport.closed:
            lossy_transport.close()

    oversized_transport = _open_reader_transport()
    try:
        with pytest.raises(MssqlResultLimitError, match="before fetch"):
            oversized_transport.execute_bounded(
                MssqlQuery(
                    query_id=uuid4(),
                    statement="SELECT CAST(N'x' AS nvarchar(16))",
                    parameters=(),
                ),
                MssqlFetchLimits(
                    fetch_batch_records=1,
                    max_records=1,
                    max_value_bytes=32,
                    max_record_bytes=32,
                    max_total_bytes=32,
                    max_declared_value_bytes=32,
                    max_declared_record_bytes=32,
                ),
            )
        assert oversized_transport.closed
    finally:
        if not oversized_transport.closed:
            oversized_transport.close()


def test_mssql_cancel_discards_result_and_confirms_same_session() -> None:
    query_id = uuid4()
    transport_queue: Queue[MssqlTransport] = Queue(maxsize=1)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="dfe-mssql-owner") as executor:
        future = executor.submit(_execute_long_query, query_id, transport_queue)
        transport = _required_worker_transport(transport_queue, future)
        _wait_for_active_query(transport, query_id)
        with pytest.raises(MssqlWrongQueryIdError, match="does not match"):
            transport.cancel(uuid4())
        _wait_for_server_request(transport.evidence.session_id, query_id)

        cancellation_started = time.monotonic()
        transport.cancel(query_id)
        with pytest.raises(MssqlCancellationConfirmedError) as captured:
            future.result(timeout=5.0)
        cancellation_seconds = time.monotonic() - cancellation_started

    error = captured.value
    assert cancellation_seconds < 5.0
    assert error.query_id == query_id
    assert error.sqlstate == "HY008"
    assert error.session_id == transport.evidence.session_id
    assert error.confirmation_session_id == transport.evidence.session_id
    assert error.confirmation_value == 1
    assert transport.closed


def _open_reader_transport() -> MssqlTransport:
    return open_mssql_transport(
        required_reader_settings("dfe-phase03-transport-spike"),
        single_attempt_retry_policy(),
    )


def _execute_long_query(
    query_id: UUID,
    transport_queue: Queue[MssqlTransport],
) -> MssqlReadResult:
    transport = _open_reader_transport()
    transport_queue.put(transport, timeout=5.0)
    try:
        return transport.execute_bounded(
            MssqlQuery(
                query_id=query_id,
                statement="WAITFOR DELAY '00:00:20'; SELECT CONVERT(int, 7)",
                parameters=(),
            ),
            MssqlFetchLimits(
                fetch_batch_records=1,
                max_records=1,
                max_value_bytes=32,
                max_record_bytes=32,
                max_total_bytes=32,
                max_declared_value_bytes=32,
                max_declared_record_bytes=32,
            ),
        )
    finally:
        if not transport.closed:
            transport.close()


def _required_worker_transport(
    transport_queue: Queue[MssqlTransport],
    future: Future[MssqlReadResult],
) -> MssqlTransport:
    try:
        return transport_queue.get(timeout=10.0)
    except Empty:
        if future.done():
            future.result()
        raise AssertionError("SQL Server worker did not publish its transport") from None


def _wait_for_active_query(transport: MssqlTransport, query_id: UUID) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if transport.active_query_id == query_id:
            return
        time.sleep(0.01)
    raise AssertionError("SQL Server query did not become active before the cancellation deadline")


def _wait_for_server_request(session_id: int, query_id: UUID) -> None:
    observer = open_mssql_transport(
        required_admin_settings("dfe-phase03-cancellation-observer"),
        single_attempt_retry_policy(),
    )
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            observed = observer.execute_bounded(
                MssqlQuery(
                    query_id=uuid4(),
                    statement=(
                        "SELECT CONVERT(int, 1) FROM [sys].[dm_exec_requests] AS [request] "
                        "CROSS APPLY [sys].[dm_exec_sql_text]([request].[sql_handle]) AS [batch] "
                        "WHERE [request].[session_id] = ? AND [batch].[text] LIKE ? "
                        "AND [request].[status] = N'suspended' "
                        "AND [request].[command] = N'WAITFOR' "
                        "AND [request].[wait_type] = N'WAITFOR'"
                    ),
                    parameters=(session_id, f"%dfe_query_id={query_id}%"),
                ),
                MssqlFetchLimits(
                    fetch_batch_records=1,
                    max_records=1,
                    max_value_bytes=32,
                    max_record_bytes=32,
                    max_total_bytes=32,
                    max_declared_value_bytes=32,
                    max_declared_record_bytes=32,
                ),
            )
            if observed.rows == ((1,),):
                return
            time.sleep(0.01)
        raise AssertionError("SQL Server did not observe the WAITFOR request before cancellation")
    finally:
        if not observer.closed:
            observer.close()
