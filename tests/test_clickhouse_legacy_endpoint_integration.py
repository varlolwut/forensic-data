# pyright: reportPrivateUsage=false

import hashlib
import json
import time
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from decimal import Decimal
from io import StringIO
from pathlib import Path
from urllib.parse import urlencode
from uuid import UUID, uuid4

import psycopg
import pytest
from pydantic import SecretStr
from urllib3 import PoolManager, Timeout
from urllib3.response import BaseHTTPResponse

from forensic_data import application as application_module
from forensic_data.application import (
    ClickHousePostgresExecutionServices,
    DiffRequest,
    ExecuteCheckRequest,
    HistoryRequest,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    read_diff,
    read_history,
)
from forensic_data.cli import run_cli
from forensic_data.clickhouse import (
    ClickHouseAttemptDeadlineExceededError,
    ClickHouseCancellationUnconfirmedError,
    ClickHouseConnectionSettings,
    ClickHouseDataValidationError,
    ClickHouseLegacyProfileProvenance,
    ClickHouseQueryCompletion,
    ClickHouseQueryError,
    ClickHouseResponseLimitError,
    ClickHouseTransport,
    ClickHouseTransportState,
    inspect_legacy_clickhouse_server_profile,
    open_legacy_clickhouse_source_transport,
)
from forensic_data.clickhouse_endpoint import _tsv_records
from forensic_data.clickhouse_http import ClickHouseHttpWorkerState
from forensic_data.clickhouse_legacy import (
    ClickHouseLegacySourceManifest,
    parse_clickhouse_legacy_source_manifest,
)
from forensic_data.clickhouse_limits import (
    ClickHouseExecutionLimits,
    build_clickhouse_execution_limits,
)
from forensic_data.comparison import CompletedComparisonArtifact, PartialComparisonArtifact
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import LoadedContractConfig, RowCheckDefinition
from forensic_data.persistence.lifecycle import (
    CompletedComparisonDefinition,
    IntegerRangeFingerprintPersistence,
    PartialComparisonDefinition,
    PersistedInputCut,
    RunAttemptRecord,
)
from forensic_data.persistence.postgres import migrate_postgres_metadata
from forensic_data.planning import ResolvedScope, resolve_scope_values
from forensic_data.postgres import DatabaseRow, PostgresConnectionSettings, PostgresRetryPolicy
from forensic_data.reporting import (
    DetailAvailability,
    DifferenceKind,
    DifferenceRecord,
    EvidenceFieldValue,
    EvidenceValueAvailability,
    HistoryAttemptStatus,
    StoredResultAvailability,
)
from forensic_data.result import (
    ComparisonTotals,
    ConsistencyLevel,
    ExecutionStatus,
    ExitCode,
    Guarantee,
    PersistenceState,
    ReasonCode,
    ResultReason,
    RunResult,
    UnavailableTotal,
    Verdict,
    exit_code_for_result,
)
from tests import test_clickhouse_endpoint_integration as modern_endpoint
from tests import test_postgres_comparison_integration as postgres_comparison
from tests.clickhouse_support import (
    clickhouse_read_deadline,
    fresh_clickhouse_attempt_id,
    required_legacy_clickhouse_admin_settings,
    required_legacy_clickhouse_reader_settings,
    single_attempt_clickhouse_retry_policy,
)
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.postgres_support import connect_writer

pytestmark = [pytest.mark.integration, pytest.mark.clickhouse, pytest.mark.postgres]

_FIXTURE_DIRECTORY = (Path(__file__).parent / "fixtures" / "clickhouse-21-8").resolve()
_CONTRACT_PATH = (_FIXTURE_DIRECTORY / "comparison-contract.yaml").resolve()
_MANIFEST_PATH = (_FIXTURE_DIRECTORY / "manifests" / "reference-orders-v001.json").resolve()
_CHECK_ID = "clickhouse_to_postgres_orders"
_BUSINESS_DATE = date(2024, 2, 29)
_COMPLETED_AT = datetime(2024, 3, 1, 1, 2, 3, 456789, tzinfo=UTC)
_REFERENCE_BATCH = "reference-orders-2024-02-29-v001"
_TARGET_BATCH = "comparison-orders-2024-02-29-v001"
_SOURCE_CUT = "comparison-orders-cut-000001"
_SCOPE_DIGEST = "13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897"
_SERVER_UUID = "77777777-7777-4777-8777-777777777777"
_SOURCE_UUID = "55555555-5555-4555-8555-555555555555"
_BUILD_ID = "5E2BCEFC0773AB45CAD70DB02B740C39044F588F"
_HOSTNAME = "forensic-data-phase05-clickhouse-21-8"
_ISSUER = "dfe_fixture_loader"
_SCOPE_VALUES = (ScopeValue(name="business_date", value="2024-02-29"),)
_SCOPE_JSON = '{"business_date":"2024-02-29"}'
_NO_POSTGRES_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_LABEL_ONE = bytes.fromhex("417cd091f09f988065cc812020").decode("utf-8", errors="strict")
_LABEL_TWO = bytes.fromhex("d09ed0b1d0bdd0bed0b2d0bbd191d0bdd0bdd0bed0b5202020").decode(
    "utf-8", errors="strict"
)
_LABEL_FOUR = bytes.fromhex("747261696c696e672020").decode("utf-8", errors="strict")
_OPTIONAL_LABEL_FOUR = bytes.fromhex("d0bdd183d0bbd18c").decode("utf-8", errors="strict")
_REFERENCE_ROWS = (
    (
        1,
        _BUSINESS_DATE,
        Decimal("100.0000000"),
        _LABEL_ONE,
        None,
        datetime(2024, 2, 29, 10, 0, 1, 111111),
        datetime(2024, 2, 29, 8, 0, 1, 111111, tzinfo=UTC),
    ),
    (
        2,
        _BUSINESS_DATE,
        Decimal("200.0000001"),
        _LABEL_TWO,
        "",
        datetime(2024, 2, 29, 10, 0, 2, 222222),
        datetime(2024, 2, 29, 8, 0, 2, 222222, tzinfo=UTC),
    ),
    (
        3,
        _BUSINESS_DATE,
        Decimal("-9999999999999999999999999999999.9999999"),
        "",
        "",
        datetime(2024, 2, 29, 10, 0, 3, 333333),
        datetime(2024, 2, 29, 8, 0, 3, 333333, tzinfo=UTC),
    ),
    (
        4,
        _BUSINESS_DATE,
        Decimal("0.0000001"),
        _LABEL_FOUR,
        _OPTIONAL_LABEL_FOUR,
        datetime(2024, 2, 29, 10, 0, 4, 444444),
        datetime(2024, 2, 29, 8, 0, 4, 444444, tzinfo=UTC),
    ),
)
_TARGET_ROWS = (
    _REFERENCE_ROWS[0],
    (
        2,
        _BUSINESS_DATE,
        Decimal("200.0000000"),
        _LABEL_TWO,
        None,
        datetime(2024, 2, 29, 10, 0, 2, 222223),
        datetime(2024, 2, 29, 8, 0, 2, 222223, tzinfo=UTC),
    ),
    _REFERENCE_ROWS[3],
    (
        5,
        _BUSINESS_DATE,
        Decimal("500.0000000"),
        "extra|row  ",
        None,
        datetime(2024, 2, 29, 10, 0, 5, 555555),
        datetime(2024, 2, 29, 8, 0, 5, 555555, tzinfo=UTC),
    ),
)


@dataclass(frozen=True, slots=True)
class _RawHttpResponse:
    status_code: int
    response_query_id: str | None
    exception_code: str | None
    payload: bytes


def test_clickhouse_21_8_source_is_bounded_durable_and_loses_changed_seal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_contract_config(_CONTRACT_PATH)
    check = _check(config)
    scope = resolve_scope_values(check, {"business_date": "2024-02-29"})
    assert scope.scope_digest == _SCOPE_DIGEST
    limits = build_clickhouse_execution_limits(config.execution)
    reader = required_legacy_clickhouse_reader_settings("dfe-p0507-reference")
    admin = required_legacy_clickhouse_admin_settings("dfe-p0507-admin")
    assert reader.user == "dfe_legacy_reader"
    assert admin.user == "dfe_legacy_admin"
    assert (reader.host, reader.port, reader.database) == (
        admin.host,
        admin.port,
        admin.database,
    )
    manifest_payload = _MANIFEST_PATH.read_bytes()
    manifest = parse_clickhouse_legacy_source_manifest(manifest_payload, 1_048_576)
    assert str(manifest.expected_server_uuid) == _SERVER_UUID
    assert str(manifest.version_locator.uuid) == _SOURCE_UUID
    assert manifest.artifact_sha256 == hashlib.sha256(manifest_payload).hexdigest()
    completed_artifacts: dict[UUID, CompletedComparisonArtifact] = {}
    partial_artifacts: dict[UUID, PartialComparisonArtifact] = {}
    _capture_real_artifacts(monkeypatch, completed_artifacts, partial_artifacts)

    _exercise_legacy_transport_preflight(reader, admin, limits)

    metadata_request = required_metadata_database_settings()
    target_request = postgres_comparison._new_source_database_settings("target")
    with ExitStack() as restorations:
        restorations.callback(_restore_legacy_source, admin)
        _restore_legacy_source(admin)
        with (
            disposable_metadata_database(metadata_request) as metadata,
            postgres_comparison._disposable_source_database(target_request) as target,
        ):
            migrate_postgres_metadata(metadata.migrator, _NO_POSTGRES_RETRY, 5_000)
            _seed_postgres_target(target, check, scope)
            services = _execution_services(
                config,
                metadata,
                target.reader,
                reader,
                manifest,
                check,
                limits,
            )
            completed = _execute_through_cli_and_api(
                config,
                check,
                scope,
                services,
                target.reader,
                reader,
                metadata.writer,
            )
            artifact = completed_artifacts[completed.attempt_id]
            assert artifact.reference_full_scans == 5
            assert artifact.target_full_scans == 3
            assert completed.metrics.queries == 111
            fresh_metadata = _metadata_services(config, metadata.reader)
            _assert_durable_history_and_diff(
                fresh_metadata,
                check,
                scope,
                completed,
            )
            _assert_legacy_provenance(
                metadata.reader,
                completed,
                "closed",
                True,
                manifest_payload,
                reader,
            )

            _publish_building_readiness(admin)
            _mutate_legacy_source(admin)
            _assert_durable_history_and_diff(
                _metadata_services(config, metadata.reader),
                check,
                scope,
                completed,
            )

            _restore_legacy_source(admin)
            loss = _execute_with_final_seal_loss(
                config,
                check,
                services,
                metadata,
                target,
                admin,
            )
            _assert_final_seal_loss(loss, config)
            partial = partial_artifacts[loss.attempt_id]
            assert partial.reference_full_scans == 4
            assert partial.target_full_scans == 3
            assert loss.metrics.queries == 85
            _assert_durable_history_and_diff(
                _metadata_services(config, metadata.reader),
                check,
                scope,
                loss,
            )
            _assert_legacy_provenance(
                metadata.reader,
                loss,
                "lost",
                False,
                manifest_payload,
                reader,
            )


def _exercise_legacy_transport_preflight(
    reader: ClickHouseConnectionSettings,
    admin: ClickHouseConnectionSettings,
    limits: ClickHouseExecutionLimits,
) -> None:
    profile_transport = _open_preflight_transport(reader, limits, 20_000, 300_000)
    try:
        profile = inspect_legacy_clickhouse_server_profile(profile_transport, reader)
        assert profile.server_version == "21.8.15.7"
        assert profile.server_version_number == 21_008_015
        assert profile.build_id == _BUILD_ID
        assert type(profile.provenance) is ClickHouseLegacyProfileProvenance
        identity = profile_transport.execute_raw(
            query="SELECT getMacro('dfe_server_uuid'), hostName(), buildId()",
            parameters={},
            settings={"max_result_rows": 1, "max_result_bytes": 4_096},
            result_format="TabSeparatedRaw",
            max_response_bytes=4_096,
            operation="prove_legacy_operator_identity",
        )
        identity_fields = _tsv_records(identity.payload, 3, "legacy operator identity")
        assert len(identity_fields) == 1
        assert identity_fields[0][0] == _SERVER_UUID.encode("ascii")
        assert identity_fields[0][1].decode("ascii", errors="strict") == _HOSTNAME
        assert identity_fields[0][2].decode("ascii", errors="strict") == _BUILD_ID
        full = profile_transport.execute_raw(
            query="SELECT repeat('x', {result_size:UInt64})",
            parameters={"result_size": 4_095},
            settings={"max_result_rows": 1, "max_result_bytes": 8_192},
            result_format="TabSeparatedRaw",
            max_response_bytes=4_096,
            operation="prove_legacy_full_bounded_response",
        )
        assert full.payload == (b"x" * 4_095) + b"\n"
        assert full.query_id == profile_transport.last_query_id
    finally:
        _close_active_transport(profile_transport)

    immediate_transport = _open_preflight_transport(reader, limits, 20_000, 300_000)
    try:
        with pytest.raises(ClickHouseQueryError) as captured_immediate:
            immediate_transport.execute_raw(
                query="SELECT throwIf(1, 'immediate-probe')",
                parameters={},
                settings={"max_result_rows": 1, "max_result_bytes": 4_096},
                result_format="TabSeparatedRaw",
                max_response_bytes=4_096,
                operation="prove_legacy_immediate_error",
            )
        immediate = captured_immediate.value
        assert immediate.query_id == immediate_transport.last_query_id
        assert immediate.http_status == 500
        assert immediate.error_code == 395
        assert immediate.error_name is None
        assert immediate.completion is ClickHouseQueryCompletion.SERVER_TERMINAL
        assert 0 < immediate.received_error_bytes <= limits.transport.max_error_response_bytes
        assert immediate.error_response_truncated is False
        assert "immediate-probe" not in str(immediate)
        assert reader.password.get_secret_value() not in str(immediate)
        _assert_retired_transport(immediate_transport, ClickHouseTransportState.LOST)
        _require_legacy_query_absent(admin, immediate.query_id)
    finally:
        _close_active_transport(immediate_transport)

    raw_late_query_id = uuid4()
    raw_late = _legacy_http_post(
        reader,
        (
            "SELECT number, throwIf(number = 2, 'late-probe') + sleepEachRow(0.1) "
            "FROM system.numbers LIMIT 5 FORMAT TabSeparatedRaw"
        ),
        raw_late_query_id,
        (
            ("wait_end_of_query", "0"),
            ("buffer_size", "1"),
            ("max_block_size", "1"),
            ("output_format_parallel_formatting", "0"),
            ("max_execution_time", "29"),
            ("max_result_rows", "5"),
            ("max_result_bytes", "4096"),
        ),
        16_384,
    )
    assert raw_late.status_code == 200
    assert raw_late.response_query_id == str(raw_late_query_id)
    assert raw_late.exception_code is None
    assert raw_late.payload.startswith(b"0\t0\n1\t0\nCode: 395, e.displayText() = DB::Exception: ")
    assert b"DB::Exception: late-probe" in raw_late.payload
    with pytest.raises(ClickHouseDataValidationError):
        _tsv_records(raw_late.payload, 2, "legacy late-error preflight")
    _require_legacy_query_absent(admin, raw_late_query_id)

    late_transport = _open_preflight_transport(reader, limits, 20_000, 300_000)
    try:
        with pytest.raises(ClickHouseQueryError) as captured_late:
            late_transport.execute_raw(
                query=(
                    "SELECT number, throwIf(number = 2, 'late-probe') + sleepEachRow(0.1) "
                    "FROM system.numbers LIMIT 5"
                ),
                parameters={},
                settings={"max_result_rows": 5, "max_result_bytes": 4_096},
                result_format="TabSeparatedRaw",
                max_response_bytes=4_096,
                operation="prove_legacy_terminal_late_error",
            )
        late = captured_late.value
        assert late.query_id == late_transport.last_query_id
        assert late.http_status == 500
        assert late.error_code == 395
        assert late.error_name is None
        assert late.completion is ClickHouseQueryCompletion.SERVER_TERMINAL
        assert 0 < late.received_error_bytes <= limits.transport.max_error_response_bytes
        assert "late-probe" not in str(late)
        assert reader.password.get_secret_value() not in str(late)
        _assert_retired_transport(late_transport, ClickHouseTransportState.LOST)
        _require_legacy_query_absent(admin, late.query_id)
    finally:
        _close_active_transport(late_transport)

    limit_transport = _open_preflight_transport(reader, limits, 20_000, 300_000)
    try:
        limit_error: ClickHouseResponseLimitError | ClickHouseCancellationUnconfirmedError
        try:
            limit_transport.execute_raw(
                query="SELECT repeat('x', {result_size:UInt64})",
                parameters={"result_size": 4_096},
                settings={"max_result_rows": 1, "max_result_bytes": 8_192},
                result_format="TabSeparatedRaw",
                max_response_bytes=4_096,
                operation="prove_legacy_response_limit",
            )
        except (ClickHouseResponseLimitError, ClickHouseCancellationUnconfirmedError) as error:
            limit_error = error
        else:
            raise AssertionError("ClickHouse legacy oversized response was accepted")
        assert limit_error.query_id == limit_transport.last_query_id
        if isinstance(limit_error, ClickHouseResponseLimitError):
            assert limit_error.received_response_bytes == 4_097
            assert limit_error.response_truncated is True
            assert limit_transport.state is ClickHouseTransportState.LOST
            assert limit_transport.source_slot_released is True
        else:
            assert limit_error.trigger_cause == "ResponseLimit"
            assert limit_error.received_response_bytes == 4_097
            assert limit_error.response_truncated is True
            assert limit_transport.state is ClickHouseTransportState.CANCELLATION_UNCONFIRMED
            assert limit_transport.source_slot_released is False
            _kill_legacy_query(admin, limit_error.query_id)
        _assert_transport_workers_reaped(limit_transport)
        _require_legacy_query_absent(admin, limit_error.query_id)
    finally:
        _close_active_transport(limit_transport)

    cancellation_transport = _open_preflight_transport(reader, limits, 1_500, 15_000)
    try:
        with pytest.raises(ClickHouseAttemptDeadlineExceededError) as captured_deadline:
            cancellation_transport.execute_raw(
                query=(
                    "SELECT sum(sipHash64(number)) "
                    "FROM (SELECT number FROM system.numbers LIMIT 1000000000000)"
                ),
                parameters={},
                settings={"max_result_rows": 1, "max_result_bytes": 64},
                result_format="TabSeparatedRaw",
                max_response_bytes=64,
                operation="prove_legacy_same_user_sync_cancellation",
            )
        deadline = captured_deadline.value
        assert deadline.query_id == cancellation_transport.last_query_id
        assert deadline.operation == "prove_legacy_same_user_sync_cancellation"
        assert deadline.completion is ClickHouseQueryCompletion.CANCELLED
        _assert_retired_transport(cancellation_transport, ClickHouseTransportState.LOST)
        _require_legacy_query_absent(admin, deadline.query_id)
    finally:
        _close_active_transport(cancellation_transport)


def _open_preflight_transport(
    reader: ClickHouseConnectionSettings,
    limits: ClickHouseExecutionLimits,
    statement_timeout_milliseconds: int,
    attempt_timeout_milliseconds: int,
) -> ClickHouseTransport:
    return open_legacy_clickhouse_source_transport(
        reader,
        single_attempt_clickhouse_retry_policy(),
        limits.transport,
        clickhouse_read_deadline(
            statement_timeout_milliseconds,
            attempt_timeout_milliseconds,
        ),
        fresh_clickhouse_attempt_id(),
    )


def _assert_retired_transport(
    transport: ClickHouseTransport,
    state: ClickHouseTransportState,
) -> None:
    assert transport.state is state
    assert transport.source_slot_released is True
    _assert_transport_workers_reaped(transport)


def _assert_transport_workers_reaped(transport: ClickHouseTransport) -> None:
    for worker in (transport._data_worker, transport._control_worker):
        assert worker.state is ClickHouseHttpWorkerState.CLOSED
        assert worker._process.is_alive() is False


def _close_active_transport(transport: ClickHouseTransport) -> None:
    if transport.state is ClickHouseTransportState.ACTIVE:
        transport.close()
        assert transport.state is ClickHouseTransportState.CLOSED
        assert transport.source_slot_released is True
        _assert_transport_workers_reaped(transport)


def _legacy_http_post(
    settings: ClickHouseConnectionSettings,
    query: str,
    query_id: UUID,
    query_settings: tuple[tuple[str, str], ...],
    max_response_bytes: int,
) -> _RawHttpResponse:
    parameters = (
        ("database", settings.database),
        ("query_id", str(query_id)),
        *query_settings,
    )
    url = f"http://{settings.host}:{settings.port}/?{urlencode(parameters)}"
    pool = PoolManager(
        timeout=Timeout(
            connect=settings.connect_timeout_seconds,
            read=settings.send_receive_timeout_seconds,
        ),
        retries=False,
    )
    response: BaseHTTPResponse | None = None
    try:
        response = pool.request(
            "POST",
            url,
            body=query.encode("utf-8", errors="strict"),
            headers={
                "X-ClickHouse-User": settings.user,
                "X-ClickHouse-Key": settings.password.get_secret_value(),
                "User-Agent": settings.application_name,
                "Content-Type": "application/octet-stream",
                "Accept-Encoding": "identity",
            },
            preload_content=False,
            redirect=False,
        )
        payload = _read_bounded_http_body(response, max_response_bytes)
        return _RawHttpResponse(
            status_code=response.status,
            response_query_id=response.headers.get("X-ClickHouse-Query-Id"),
            exception_code=response.headers.get("X-ClickHouse-Exception-Code"),
            payload=payload,
        )
    finally:
        if response is not None:
            response.release_conn()
        pool.clear()


def _read_bounded_http_body(response: BaseHTTPResponse, max_response_bytes: int) -> bytes:
    if type(max_response_bytes) is not int or max_response_bytes < 1:
        raise ValueError("HTTP response limit must be a positive integer")
    chunks: list[bytes] = []
    received = 0
    while received <= max_response_bytes:
        chunk = response.read(
            amt=min(65_536, max_response_bytes + 1 - received),
            decode_content=False,
        )
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        received += len(chunk)
    response.close()
    raise AssertionError(
        "legacy fixture HTTP response exceeded its test bound: "
        f"observed_at_least={received}, maximum={max_response_bytes}"
    )


def _execute_legacy_admin(settings: ClickHouseConnectionSettings, query: str) -> bytes:
    response = _legacy_http_post(
        settings,
        query,
        uuid4(),
        (("wait_end_of_query", "1"), ("max_execution_time", "29")),
        65_536,
    )
    if not 200 <= response.status_code < 300 or response.exception_code is not None:
        raise AssertionError(
            "legacy fixture administration failed: "
            f"status={response.status_code}, exception_code={response.exception_code!r}, "
            f"received_bytes={len(response.payload)}"
        )
    return response.payload


def _require_legacy_query_absent(
    admin: ClickHouseConnectionSettings,
    query_id: UUID,
) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        payload = _execute_legacy_admin(
            admin,
            "SELECT count() FROM system.processes "
            f"WHERE query_id = '{query_id!s}' FORMAT TabSeparatedRaw",
        )
        records = _tsv_records(payload, 1, "legacy active-query observation")
        if records == ((b"0",),):
            return
    raise AssertionError(f"legacy ClickHouse query remained active: query_id={query_id}")


def _kill_legacy_query(admin: ClickHouseConnectionSettings, query_id: UUID) -> None:
    _execute_legacy_admin(
        admin,
        f"KILL QUERY WHERE query_id = '{query_id!s}' SYNC",
    )
    _require_legacy_query_absent(admin, query_id)


def _check(config: LoadedContractConfig) -> RowCheckDefinition:
    matches = tuple(check for check in config.checks if check.check_id == _CHECK_ID)
    assert len(matches) == 1
    return matches[0]


def _capture_real_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    completed_artifacts: dict[UUID, CompletedComparisonArtifact],
    partial_artifacts: dict[UUID, PartialComparisonArtifact],
) -> None:
    persist_completed = application_module.completed_comparison_persistence_from_artifact
    persist_partial = application_module.partial_comparison_persistence_from_artifact

    def capture_completed(
        attempt: RunAttemptRecord,
        persisted_cut: PersistedInputCut,
        artifact: CompletedComparisonArtifact,
    ) -> tuple[
        CompletedComparisonDefinition,
        tuple[IntegerRangeFingerprintPersistence, ...],
        tuple[DifferenceRecord, ...],
    ]:
        completed_artifacts[attempt.attempt_id] = artifact
        return persist_completed(attempt, persisted_cut, artifact)

    def capture_partial(
        attempt: RunAttemptRecord,
        persisted_cut: PersistedInputCut,
        artifact: PartialComparisonArtifact,
        execution_status: ExecutionStatus,
        primary_reason: ResultReason,
        additional_reasons: tuple[ResultReason, ...],
    ) -> PartialComparisonDefinition:
        partial_artifacts[attempt.attempt_id] = artifact
        return persist_partial(
            attempt,
            persisted_cut,
            artifact,
            execution_status,
            primary_reason,
            additional_reasons,
        )

    monkeypatch.setattr(
        application_module,
        "completed_comparison_persistence_from_artifact",
        capture_completed,
    )
    monkeypatch.setattr(
        application_module,
        "partial_comparison_persistence_from_artifact",
        capture_partial,
    )


def _seed_postgres_target(
    target: postgres_comparison._SourceDatabaseSettings,
    check: RowCheckDefinition,
    scope: ResolvedScope,
) -> None:
    with connect_writer(target.writer) as connection:
        with connection.transaction():
            connection.execute("CREATE SCHEMA dfe_demo")
            connection.execute("CREATE SCHEMA dfe_control")
            connection.execute(
                "CREATE TABLE dfe_demo.target_orders ("
                "order_id bigint PRIMARY KEY, business_date date NOT NULL, "
                "precise_amount numeric(38, 7) NOT NULL, "
                "label text NOT NULL, optional_label text, "
                "local_time timestamp(6) NOT NULL, "
                "instant_time timestamptz(6) NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE dfe_control.batch_manifest ("
                "dataset_id text NOT NULL, scope_digest text NOT NULL, batch_id text NOT NULL, "
                "state text NOT NULL, business_date date NOT NULL, source_cut text, "
                "dataset_version text, completed_at timestamptz(6), "
                "PRIMARY KEY (dataset_id, scope_digest))"
            )
            with connection.cursor() as cursor:
                cursor.executemany(
                    "INSERT INTO dfe_demo.target_orders ("
                    "order_id, business_date, precise_amount, label, optional_label, "
                    "local_time, instant_time) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    _TARGET_ROWS,
                )
            connection.execute("ANALYZE dfe_demo.target_orders")
            connection.execute(
                "INSERT INTO dfe_control.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                (
                    check.target.dataset_id,
                    scope.scope_digest,
                    _TARGET_BATCH,
                    _BUSINESS_DATE,
                    _SOURCE_CUT,
                    "postgres-target-orders-v1",
                    _COMPLETED_AT,
                ),
            )
            connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_fixture_reader")
            connection.execute(
                "GRANT SELECT ON dfe_demo.target_orders, "
                "dfe_control.batch_manifest TO dfe_fixture_reader"
            )


def _execution_services(
    config: LoadedContractConfig,
    metadata: MetadataDatabaseSettings,
    target: PostgresConnectionSettings,
    reference: ClickHouseConnectionSettings,
    manifest: ClickHouseLegacySourceManifest,
    check: RowCheckDefinition,
    limits: ClickHouseExecutionLimits,
) -> ClickHousePostgresExecutionServices:
    return ClickHousePostgresExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=reference,
        target_connection_id=check.target.connection.connection_id,
        target_settings=target,
        metadata_connection_id="metadata_pg",
        metadata_settings=metadata.writer,
        reference_retry_policy=single_attempt_clickhouse_retry_policy(),
        target_retry_policy=_NO_POSTGRES_RETRY,
        metadata_retry_policy=_NO_POSTGRES_RETRY,
        protected_lock_timeout_milliseconds=28_000,
        reference_transport_limits=limits.transport,
        reference_readiness_limits=limits.readiness,
        reference_canonical_limits=limits.canonical,
        reference_manifest=manifest,
        reference_expected_issuer=_ISSUER,
        reference_max_mutation_records=config.execution.max_fetched_records,
        reference_max_tie_groups=config.execution.max_fetched_records,
        reference_max_part_records=config.execution.max_fetched_records,
        metadata_record_bytes=min(
            config.execution.max_application_result_bytes,
            config.execution.max_coordinator_memory_bytes,
        ),
        metadata_total_bytes=config.execution.max_coordinator_memory_bytes,
    )


def _execute_through_cli_and_api(
    config: LoadedContractConfig,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    services: ClickHousePostgresExecutionServices,
    target: PostgresConnectionSettings,
    reference: ClickHouseConnectionSettings,
    metadata: PostgresConnectionSettings,
) -> RunResult:
    request_id = uuid4()
    reference_secret = {
        "host": reference.host,
        "port": reference.port,
        "database": reference.database,
        "user": reference.user,
        "password": reference.password.get_secret_value(),
        "transport_security": reference.transport_security.value,
        "ca_cert": None,
        "connect_timeout_seconds": reference.connect_timeout_seconds,
        "send_receive_timeout_seconds": reference.send_receive_timeout_seconds,
    }
    assert reference.ca_cert is None
    stdout = StringIO()
    stderr = StringIO()
    exit_code = run_cli(
        (
            "check",
            "--config",
            str(_CONTRACT_PATH),
            "--check",
            check.check_id,
            "--scope-json",
            _SCOPE_JSON,
            "--reference-batch",
            _REFERENCE_BATCH,
            "--target-batch",
            _TARGET_BATCH,
            "--reference-manifest",
            str(_MANIFEST_PATH),
            "--reference-manifest-issuer",
            _ISSUER,
            "--request-id",
            str(request_id),
            "--output",
            "json",
        ),
        {
            "DFE_P0507_CLICKHOUSE_REFERENCE_SECRET": json.dumps(reference_secret),
            "DFE_P0507_POSTGRES_TARGET_DSN": postgres_comparison._connection_dsn(target),
            "DFE_P0507_METADATA_DSN": postgres_comparison._connection_dsn(metadata),
        },
        stdout,
        stderr,
    )
    assert _CONTRACT_PATH.is_absolute()
    assert _MANIFEST_PATH.is_absolute()
    assert stderr.getvalue() == ""
    result = RunResult.model_validate_json(stdout.getvalue())
    assert exit_code == int(ExitCode.MISMATCH), result.reasons
    assert exit_code == int(exit_code_for_result(result))
    replay_services = replace(
        services,
        reference_settings=reference.model_copy(
            update={"password": SecretStr("replay-must-not-open-clickhouse")}
        ),
        target_settings=target.model_copy(
            update={"password": SecretStr("replay-must-not-open-postgres")}
        ),
    )
    replayed = execute_check(
        config,
        ExecuteCheckRequest(
            request_id=request_id,
            check_id=check.check_id,
            scope_values=_SCOPE_VALUES,
            reference_expected_batch_id=_REFERENCE_BATCH,
            target_expected_batch_id=_TARGET_BATCH,
            origin="cli",
        ),
        replay_services,
    )
    assert replayed == result
    modern_endpoint._assert_completed_mismatch(result, check, scope, config)
    return result


def _metadata_services(
    config: LoadedContractConfig,
    settings: PostgresConnectionSettings,
) -> PostgresMetadataServices:
    return PostgresMetadataServices(
        connection_id=config.metadata.connection.connection_id,
        settings=settings,
        retry_policy=_NO_POSTGRES_RETRY,
    )


def _assert_durable_history_and_diff(
    services: PostgresMetadataServices,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    result: RunResult,
) -> None:
    history = read_history(
        HistoryRequest(
            check_id=check.check_id,
            scope_digest=scope.scope_digest,
            limit=10,
            cursor=None,
        ),
        services,
    )
    matches = tuple(item for item in history.items if item.run_id == result.run_id)
    assert len(matches) == 1
    stored = matches[0]
    assert stored.attempt_id == result.attempt_id
    assert stored.stored_result_availability is StoredResultAvailability.AVAILABLE
    assert stored.stored_result == result
    assert stored.status is (
        HistoryAttemptStatus.COMPLETED
        if result.execution_status is ExecutionStatus.COMPLETED
        else HistoryAttemptStatus.INCOMPLETE
    )

    page = read_diff(
        DiffRequest(
            run_id=result.run_id,
            attempt_id=result.attempt_id,
            limit=10,
            cursor=None,
        ),
        services,
    )
    assert page.detail_availability is DetailAvailability.AVAILABLE
    assert page.stored_result == result
    assert page.found_records == 3
    assert page.retained_records == 3
    assert page.next_cursor is None
    details = {modern_endpoint._stored_key(item.key_values): item for item in page.details}
    assert {key: item.kind for key, item in details.items()} == {
        "2": DifferenceKind.MODIFIED,
        "3": DifferenceKind.MISSING,
        "5": DifferenceKind.EXTRA,
    }
    modified = details["2"]
    assert modified.omitted_field_names == ("business_date",)
    assert _stored_text(modified.reference_values, "precise_amount") == "200.0000001"
    assert _stored_text(modified.target_values, "precise_amount") == "200.0000000"
    assert _stored_text(modified.reference_values, "label") == _LABEL_TWO
    assert _stored_text(modified.target_values, "label") == _LABEL_TWO
    assert _stored_text(modified.reference_values, "optional_label") == ""
    optional_target = modern_endpoint._stored_field(modified.target_values, "optional_label")
    assert optional_target.availability is EvidenceValueAvailability.STORED
    assert optional_target.canonical_text is None
    assert _stored_text(modified.reference_values, "local_time") == ("2024-02-29T10:00:02.222222")
    assert _stored_text(modified.target_values, "local_time") == ("2024-02-29T10:00:02.222223")
    assert _stored_text(modified.reference_values, "instant_time") == (
        "2024-02-29T08:00:02.222222Z"
    )
    assert _stored_text(modified.target_values, "instant_time") == ("2024-02-29T08:00:02.222223Z")
    assert _stored_text(details["3"].reference_values, "precise_amount") == (
        "-9999999999999999999999999999999.9999999"
    )
    assert _stored_text(details["3"].reference_values, "label") == ""
    assert _stored_text(details["3"].reference_values, "optional_label") == ""
    assert details["3"].target_values == ()
    assert details["5"].reference_values == ()
    assert _stored_text(details["5"].target_values, "precise_amount") == "500.0000000"
    assert _stored_text(details["5"].target_values, "label") == "extra|row  "
    optional_extra = modern_endpoint._stored_field(
        details["5"].target_values,
        "optional_label",
    )
    assert optional_extra.availability is EvidenceValueAvailability.STORED
    assert optional_extra.canonical_text is None


def _stored_text(values: tuple[EvidenceFieldValue, ...], field_name: str) -> str:
    field = modern_endpoint._stored_field(values, field_name)
    assert field.availability is EvidenceValueAvailability.STORED
    if field.canonical_text is None:
        raise AssertionError(f"stored field {field_name!r} unexpectedly contains NULL")
    return field.canonical_text


def _execute_with_final_seal_loss(
    config: LoadedContractConfig,
    check: RowCheckDefinition,
    services: ClickHousePostgresExecutionServices,
    metadata: MetadataDatabaseSettings,
    target: postgres_comparison._SourceDatabaseSettings,
    admin: ClickHouseConnectionSettings,
) -> RunResult:
    request = ExecuteCheckRequest(
        request_id=uuid4(),
        check_id=check.check_id,
        scope_values=_SCOPE_VALUES,
        reference_expected_batch_id=_REFERENCE_BATCH,
        target_expected_batch_id=_TARGET_BATCH,
        origin="p0507-final-seal-loss-integration",
    )
    with (
        connect_writer(target.writer) as lock_connection,
        connect_writer(target.admin) as target_observer,
        connect_writer(metadata.reader) as metadata_observer,
        ThreadPoolExecutor(max_workers=1, thread_name_prefix="dfe-p0507-seal-loss") as executor,
    ):
        target_oids = _target_relation_oids(target_observer)
        lock_connection.execute("BEGIN")
        try:
            lock_connection.execute(
                "LOCK TABLE dfe_demo.target_orders, dfe_control.batch_manifest "
                "IN ACCESS EXCLUSIVE MODE"
            )
            execution = executor.submit(execute_check, config, request, services)
            _wait_for_reference_context_and_target_lock(
                metadata_observer,
                target_observer,
                request.request_id,
                target.reader.application_name,
                target_oids,
                execution,
                20.0,
            )
            _publish_building_readiness(admin)
            _mutate_legacy_source(admin)
        finally:
            lock_connection.execute("COMMIT")
        return execution.result(timeout=120.0)


def _target_relation_oids(connection: psycopg.Connection[DatabaseRow]) -> tuple[int, int]:
    rows = connection.execute(
        "SELECT required_relation.relation_name, "
        "required_relation.relation_name::regclass::oid AS relation_oid FROM (VALUES "
        "('dfe_control.batch_manifest'), ('dfe_demo.target_orders')) "
        "AS required_relation(relation_name) ORDER BY required_relation.relation_name"
    ).fetchall()
    if len(rows) != 2 or tuple(row[0] for row in rows) != (
        "dfe_control.batch_manifest",
        "dfe_demo.target_orders",
    ):
        raise AssertionError("PostgreSQL target relation OID observation returned invalid rows")
    manifest_oid = rows[0][1]
    target_oid = rows[1][1]
    if type(manifest_oid) is not int or type(target_oid) is not int:
        raise AssertionError("PostgreSQL target relation OIDs must be integers")
    return (manifest_oid, target_oid)


def _wait_for_reference_context_and_target_lock(
    metadata: psycopg.Connection[DatabaseRow],
    target: psycopg.Connection[DatabaseRow],
    request_id: UUID,
    target_application_name: str,
    target_relation_oids: tuple[int, int],
    execution: Future[RunResult],
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        context_row = metadata.execute(
            "SELECT contexts.read_context_id FROM dfe_metadata.runs AS runs "
            "JOIN dfe_metadata.run_attempts AS attempts ON attempts.run_id = runs.run_id "
            "JOIN dfe_metadata.attempt_read_contexts AS contexts "
            "ON contexts.attempt_id = attempts.attempt_id "
            "WHERE runs.request_id = %s AND contexts.direction = 'reference' "
            "AND contexts.engine = 'clickhouse' AND contexts.state = 'active' "
            "ORDER BY attempts.ordinal DESC",
            (request_id,),
        ).fetchall()
        lock_rows = target.execute(
            "SELECT waiting_lock.relation FROM pg_catalog.pg_locks AS waiting_lock "
            "JOIN pg_catalog.pg_stat_activity AS activity ON activity.pid = waiting_lock.pid "
            "WHERE activity.application_name = %s AND waiting_lock.locktype = 'relation' "
            "AND waiting_lock.mode = 'AccessShareLock' "
            "AND waiting_lock.relation IN (%s, %s) AND NOT waiting_lock.granted "
            "ORDER BY waiting_lock.relation",
            (target_application_name, *target_relation_oids),
        ).fetchall()
        if len(context_row) > 1:
            raise AssertionError("seal-loss interlock found multiple active ClickHouse contexts")
        if len(lock_rows) > 1 or (
            len(lock_rows) == 1 and (len(lock_rows[0]) != 1 or type(lock_rows[0][0]) is not int)
        ):
            raise AssertionError("seal-loss lock observation returned invalid rows")
        expected_lock_rows = ((target_relation_oids[0],),)
        if lock_rows and tuple(lock_rows) != expected_lock_rows:
            raise AssertionError(
                "seal-loss interlock blocked on an unexpected PostgreSQL relation: "
                f"expected_relation_oid={target_relation_oids[0]}, observed={lock_rows!r}"
            )
        if len(context_row) == 1 and tuple(lock_rows) == expected_lock_rows:
            if not isinstance(context_row[0][0], UUID):
                raise AssertionError("persisted ClickHouse context ID must be a UUID")
            return
        if execution.done():
            result = execution.result()
            raise AssertionError(
                "comparison completed before the deterministic seal-loss interlock: "
                f"run_id={result.run_id}, attempt_id={result.attempt_id}"
            )
    raise AssertionError(
        "timed out waiting for persisted ClickHouse reference context and PostgreSQL lock: "
        f"request_id={request_id}, application_name={target_application_name!r}"
    )


def _assert_final_seal_loss(result: RunResult, config: LoadedContractConfig) -> None:
    assert config.execution.max_attempts == 1
    assert result.execution_status is ExecutionStatus.INCOMPLETE
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.guarantee is Guarantee.NOT_ESTABLISHED
    assert result.consistency.stable_reads is ConsistencyLevel.UNKNOWN
    assert result.consistency.cut_alignment is ConsistencyLevel.VERIFIED
    assert len(result.consistency.read_context_ids) == 2
    unavailable = UnavailableTotal(
        precision="unavailable",
        value=None,
        reason=ReasonCode.SNAPSHOT_LOST,
    )
    assert result.totals == ComparisonTotals(
        matched=unavailable,
        missing=unavailable,
        extra=unavailable,
        modified=unavailable,
    )
    assert result.persistence.state is PersistenceState.CONFIRMED
    assert result.reasons[0].code is ReasonCode.SNAPSHOT_LOST
    assert result.reasons[0].operation == "confirm_reference"
    assert tuple((reason.code, reason.operation) for reason in result.reasons[1:]) == (
        (ReasonCode.NOT_READY, "validate_readiness"),
    )
    assert all(reason.code is not ReasonCode.DATA_MISMATCH for reason in result.reasons)
    assert exit_code_for_result(result) is ExitCode.INCOMPLETE


def _assert_legacy_provenance(
    metadata: PostgresConnectionSettings,
    result: RunResult,
    expected_state: str,
    expect_confirmation: bool,
    manifest_payload: bytes,
    reference: ClickHouseConnectionSettings,
) -> None:
    with connect_writer(metadata) as connection:
        contexts = connection.execute(
            "SELECT read_context_id, direction, engine, driver_version, server_version, "
            "server_version_number, strategy, snapshot_locator, allowed_concurrency, state, "
            "acquisition_evidence::text, closure_evidence::text "
            "FROM dfe_metadata.attempt_read_contexts WHERE attempt_id = %s "
            "ORDER BY direction",
            (result.attempt_id,),
        ).fetchall()
        observations = connection.execute(
            "SELECT observations.direction, versions.dataset_id, versions.adapter, "
            "versions.driver, versions.profile, versions.locator_kind, "
            "versions.relation_scope, observations.readiness_provider_kind, "
            "observations.readiness_evidence::text, observations.physical_binding::text "
            "FROM dfe_metadata.dataset_observations AS observations "
            "JOIN dfe_metadata.dataset_versions AS versions "
            "ON versions.dataset_version_id = observations.dataset_version_id "
            "WHERE observations.attempt_id = %s ORDER BY observations.direction",
            (result.attempt_id,),
        ).fetchall()
    assert len(contexts) == 2
    assert len(observations) == 2
    reference_context, target_context = contexts
    assert reference_context[0] == result.consistency.read_context_ids[0]
    assert reference_context[1] == "reference"
    assert reference_context[2] == "clickhouse"
    assert type(reference_context[3]) is str and reference_context[3]
    assert reference_context[4] == "21.8.15.7"
    assert reference_context[5] == 21_008_015
    assert reference_context[6] == "clickhouse_21_8_asserted_immutable_source"
    assert reference_context[7] == _SOURCE_UUID
    assert reference_context[8] == 1
    assert reference_context[9] == expected_state
    assert target_context[1] == "target"
    assert target_context[2] == "postgresql"
    assert target_context[11] is None

    acquisition = modern_endpoint._json_object_from_text(
        reference_context[10],
        "legacy ClickHouse acquisition evidence",
    )
    assert acquisition["evidence_version"] == 1
    assert acquisition["kind"] == "clickhouse_legacy_asserted_source"
    payload = modern_endpoint._json_object(
        acquisition["payload"],
        "legacy ClickHouse acquisition payload",
    )
    context = modern_endpoint._json_object(payload["context"], "legacy ClickHouse context")
    assert context["attempt_id"] == str(result.attempt_id)
    assert context["context_id"] == str(result.consistency.read_context_ids[0])
    assert context["engine"] == "clickhouse"
    assert context["source_direction"] == "reference"
    assert context["strategy"] == "clickhouse_21_8_asserted_immutable_source"
    assert context["snapshot_locator"] == _SOURCE_UUID
    assert context["consistency_level"] == "asserted"
    assert context["allowed_concurrency"] == 1
    profile = modern_endpoint._json_object(payload["profile"], "legacy ClickHouse profile")
    assert profile["server_version"] == "21.8.15.7"
    assert profile["server_version_number"] == 21_008_015
    assert profile["build_id"] == _BUILD_ID
    profile_provenance = modern_endpoint._json_object(
        profile["provenance"],
        "legacy ClickHouse profile provenance",
    )
    assert profile_provenance["runtime_profile"] == "clickhouse_21_8_lts"
    assert profile_provenance["response_protocol"] == "legacy_clean_eof"
    assert profile_provenance["timezone_strategy"] == "server_utc_configuration"
    assert profile_provenance["cancel_http_readonly_queries_on_client_close"] == 1
    assert profile_provenance["cancel_http_readonly_queries_on_client_close_locked"] is True
    assert profile_provenance["send_progress_in_http_headers"] == 0
    assert profile_provenance["send_progress_in_http_headers_locked"] is True
    assert profile_provenance["allow_experimental_projection_optimization"] == 0
    assert profile_provenance["allow_experimental_projection_optimization_locked"] is True
    assert profile_provenance["force_optimize_projection"] == 0
    assert profile_provenance["force_optimize_projection_locked"] is True

    source_binding = modern_endpoint._json_object(
        payload["source_binding"],
        "legacy ClickHouse source binding",
    )
    retained_manifest = modern_endpoint._json_object(
        source_binding["manifest"],
        "legacy ClickHouse retained manifest",
    )
    manifest_json = modern_endpoint._json_object(
        json.loads(manifest_payload),
        "legacy ClickHouse manifest artifact",
    )
    assert retained_manifest["artifact_sha256"] == hashlib.sha256(manifest_payload).hexdigest()
    assert (
        retained_manifest["expected_definition_sha256"]
        == manifest_json["expected_definition_sha256"]
    )
    assert retained_manifest["expected_server_uuid"] == _SERVER_UUID
    assert retained_manifest["server_identity_macro"] == "dfe_server_uuid"
    assertions = modern_endpoint._json_object(
        retained_manifest["assertions"],
        "legacy ClickHouse manifest assertions",
    )
    assert set(assertions.values()) == {True}
    source = modern_endpoint._json_object(source_binding["source"], "legacy source witness")
    source_identity = modern_endpoint._json_object(source["identity"], "legacy source identity")
    assert source_identity["database"] == "dfe_fixture"
    assert source_identity["table"] == "comparison_orders_v001"
    assert source_identity["uuid"] == _SOURCE_UUID
    assert source_identity["table_engine"] == "MergeTree"
    assert source_identity["partition_key"] == "toYYYYMM(business_date)"
    assert source_identity["sorting_key"] == "order_id"
    assert source_identity["definition_sha256"] == manifest_json["expected_definition_sha256"]
    server = modern_endpoint._json_object(
        source_identity["server"],
        "legacy source server identity",
    )
    assert server["asserted_server_uuid"] == _SERVER_UUID
    assert server["macro"] == "dfe_server_uuid"
    assert server["build_id"] == _BUILD_ID
    assert server["server_version"] == "21.8.15.7"
    assert server["server_version_number"] == 21_008_015
    projection = modern_endpoint._json_object(
        source["projection_safety"],
        "legacy source projection safety",
    )
    assert projection["projection_definition_absent"] is True
    assert projection["ttl_definition_absent"] is True
    assert projection["active_projection_part_count"] == 0
    mutation = modern_endpoint._json_object(source["mutations"], "legacy source mutations")
    assert mutation["mutation_count"] == 0
    base_parts = modern_endpoint._json_object(source["base_parts"], "legacy source parts")
    assert base_parts["active_row_count"] == 4

    closure_text = reference_context[11]
    if expect_confirmation:
        closure = modern_endpoint._json_object_from_text(
            closure_text,
            "legacy ClickHouse closure evidence",
        )
        assert closure["evidence_version"] == 1
        assert closure["kind"] == "clickhouse_legacy_asserted_source_final_confirmation"
        closure_payload = modern_endpoint._json_object(
            closure["payload"],
            "legacy ClickHouse closure payload",
        )
        assert closure_payload["attempt_id"] == str(result.attempt_id)
        assert closure_payload["read_context_id"] == str(result.consistency.read_context_ids[0])
        assert (
            closure_payload["raw_manifest_sha256"] == hashlib.sha256(manifest_payload).hexdigest()
        )
        final_source = modern_endpoint._json_object(
            closure_payload["final_source"],
            "legacy ClickHouse final source witness",
        )
        final_identity = modern_endpoint._json_object(
            final_source["identity"],
            "legacy ClickHouse final source identity",
        )
        assert final_identity == source_identity
    else:
        assert closure_text is None

    reference_observation, target_observation = observations
    assert reference_observation[:8] == (
        "reference",
        "clickhouse_reference_orders",
        "clickhouse",
        "clickhouse-connect",
        "clickhouse_21_8_lts",
        "relation",
        "physical_only",
        "relation_manifest",
    )
    assert target_observation[0] == "target"
    assert target_observation[2] == "postgresql"
    readiness = modern_endpoint._json_object_from_text(
        reference_observation[8],
        "legacy ClickHouse retained readiness evidence",
    )
    assert readiness["kind"] == "relation_manifest"
    assert readiness["state"] == "complete"
    physical = modern_endpoint._json_object_from_text(
        reference_observation[9],
        "legacy ClickHouse retained physical binding",
    )
    assert physical["engine"] == "clickhouse"
    physical_payload = modern_endpoint._json_object(
        physical["payload"],
        "legacy ClickHouse retained physical payload",
    )
    physical_source = modern_endpoint._json_object(
        physical_payload["source_binding"],
        "legacy ClickHouse retained physical source binding",
    )
    assert physical_source == source_binding

    retained_text = f"{reference_context[10]}{closure_text or ''}{reference_observation[9]}"
    retained_keys = modern_endpoint._json_keys(acquisition) | modern_endpoint._json_keys(physical)
    if closure_text is not None:
        retained_keys.update(
            modern_endpoint._json_keys(
                modern_endpoint._json_object_from_text(
                    closure_text,
                    "legacy ClickHouse retained closure",
                )
            )
        )
    assert reference.password.get_secret_value() not in retained_text
    assert "password" not in retained_keys
    assert "ca_cert" not in retained_keys
    assert "200.0000001" not in retained_text
    assert _LABEL_TWO not in retained_text


def _publish_building_readiness(admin: ClickHouseConnectionSettings) -> None:
    _execute_legacy_admin(admin, "TRUNCATE TABLE dfe_fixture.immutable_version_readiness")
    _execute_legacy_admin(
        admin,
        "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
        "('clickhouse_reference_orders', "
        f"'{_SCOPE_DIGEST}', 'reference-orders-building', 'building', "
        "toDate('2024-02-29'), NULL, NULL, NULL, NULL, toUInt64(12))",
    )


def _mutate_legacy_source(admin: ClickHouseConnectionSettings) -> None:
    _execute_legacy_admin(
        admin,
        "INSERT INTO dfe_fixture.comparison_orders_v001 VALUES "
        "(99, toDate('2024-03-01'), '999.0000000', 'out-of-scope', NULL, "
        "toDateTime64('2024-03-01 10:00:00.000000', 6, 'UTC'), "
        "toDateTime64('2024-03-01 08:00:00.000000', 6, 'UTC'))",
    )


def _restore_legacy_source(admin: ClickHouseConnectionSettings) -> None:
    _publish_building_readiness(admin)
    _execute_legacy_admin(
        admin,
        "TRUNCATE TABLE dfe_fixture.comparison_orders_v001",
    )
    _execute_legacy_admin(
        admin,
        "INSERT INTO dfe_fixture.comparison_orders_v001 VALUES "
        "(1, toDate('2024-02-29'), '100.0000000', "
        "unhex('417cd091f09f988065cc812020'), NULL, "
        "toDateTime64('2024-02-29 10:00:01.111111', 6, 'UTC'), "
        "toDateTime64('2024-02-29 08:00:01.111111', 6, 'UTC')), "
        "(2, toDate('2024-02-29'), '200.0000001', "
        "unhex('d09ed0b1d0bdd0bed0b2d0bbd191d0bdd0bdd0bed0b5202020'), "
        "'', "
        "toDateTime64('2024-02-29 10:00:02.222222', 6, 'UTC'), "
        "toDateTime64('2024-02-29 08:00:02.222222', 6, 'UTC')), "
        "(3, toDate('2024-02-29'), "
        "'-9999999999999999999999999999999.9999999', '', '', "
        "toDateTime64('2024-02-29 10:00:03.333333', 6, 'UTC'), "
        "toDateTime64('2024-02-29 08:00:03.333333', 6, 'UTC')), "
        "(4, toDate('2024-02-29'), '0.0000001', "
        "unhex('747261696c696e672020'), unhex('d0bdd183d0bbd18c'), "
        "toDateTime64('2024-02-29 10:00:04.444444', 6, 'UTC'), "
        "toDateTime64('2024-02-29 08:00:04.444444', 6, 'UTC'))",
    )
    _execute_legacy_admin(admin, "TRUNCATE TABLE dfe_fixture.immutable_version_readiness")
    _execute_legacy_admin(
        admin,
        "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
        "('clickhouse_reference_orders', "
        f"'{_SCOPE_DIGEST}', '{_REFERENCE_BATCH}', 'complete', "
        "toDate('2024-02-29'), 'comparison-orders-cut-000001', "
        "'comparison_orders_v001', "
        "toDateTime64('2024-03-01 01:02:03.456789', 6, 'UTC'), "
        "toUInt64(7), toUInt64(11))",
    )
