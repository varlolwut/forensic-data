from dataclasses import replace
from datetime import date
from decimal import Decimal
from pathlib import Path
from time import monotonic, sleep
from uuid import UUID

import clickhouse_connect
import pytest
from clickhouse_connect.driver.client import Client
from clickhouse_connect.driver.exceptions import DatabaseError

from forensic_data.acquisition import EarlyExecutionOutcome
from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    Fingerprint,
    LogicalType,
    NoParameters,
    Normalization,
    encode_key,
    encode_row,
    envelope_sha256,
    fingerprint_rows,
    schema_from_metadata_json,
)
from forensic_data.clickhouse import (
    ClickHouseAttemptDeadlineExceededError,
    ClickHouseCancellationUnconfirmedError,
    ClickHouseConnectionError,
    ClickHouseConnectionSettings,
    ClickHouseDataValidationError,
    ClickHouseExactReadRequest,
    ClickHouseExactRow,
    ClickHouseQueryCompletion,
    ClickHouseQueryError,
    ClickHouseResourceConstraint,
    ClickHouseResourceSetting,
    ClickHouseResponseLimitError,
    ClickHouseResultLimitError,
    ClickHouseTransport,
    ClickHouseTransportAttemptMismatchError,
    ClickHouseTransportState,
    UnsupportedClickHouseProfileError,
    inspect_clickhouse_fidelity_relation,
    inspect_clickhouse_server_profile,
    open_clickhouse_transport,
    read_clickhouse_exact_values,
)
from forensic_data.clickhouse_canonical import (
    ClickHouseCanonicalGroupRequest,
    ClickHouseCanonicalLimits,
    ClickHouseCanonicalReadRequest,
    ClickHouseMergeTreeLogicalProjectionSource,
    ClickHouseReplacingMergeTreeLogicalProjectionSource,
    inspect_clickhouse_canonical_relation,
    read_clickhouse_canonical_fingerprint,
    read_clickhouse_canonical_key_groups,
    read_clickhouse_canonical_rows,
)
from forensic_data.clickhouse_http import (
    CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES,
)
from forensic_data.clickhouse_projection import (
    ClickHouseMergeTreeProjectionBinding,
    ClickHouseMergeTreeProjectionConfirmation,
    ClickHouseMutationFailureError,
    ClickHouseProjectionRequest,
    ClickHouseReplacingMergeTreeProjectionBinding,
    ClickHouseReplacingMergeTreeProjectionConfirmation,
    ClickHouseReplacingVersionAmbiguityError,
    acquire_clickhouse_merge_tree_projection,
    acquire_clickhouse_replacing_merge_tree_projection,
    confirm_clickhouse_merge_tree_projection,
    confirm_clickhouse_replacing_merge_tree_projection,
    parse_clickhouse_replacing_projection_manifest,
)
from forensic_data.clickhouse_readiness import (
    ClickHouseImmutableVersionBinding,
    ClickHouseImmutableVersionConfirmation,
    ClickHouseImmutableVersionManifest,
    ClickHouseImmutableVersionRequest,
    ClickHouseReadinessLimits,
    acquire_clickhouse_immutable_version,
    confirm_clickhouse_immutable_version,
    parse_clickhouse_immutable_version_manifest,
)
from forensic_data.contracts.model import LateArrivalPolicy, MinimumEvidence
from forensic_data.planning import PlanDirection
from forensic_data.result import ConsistencyLevel, ExecutionStatus, ReasonCode
from tests.canonical_vectors import vector_named
from tests.clickhouse_support import (
    clickhouse_read_deadline,
    fresh_clickhouse_attempt_id,
    required_clickhouse_admin_settings,
    required_clickhouse_reader_settings,
    required_clickhouse_tls_reader_settings,
    required_clickhouse_untrusted_tls_reader_settings,
    required_clickhouse_writer_settings,
    single_attempt_clickhouse_retry_policy,
    standard_clickhouse_transport_limits,
)

pytestmark = [pytest.mark.integration, pytest.mark.clickhouse]

_COMMON_TYPE_COLUMNS = (
    "id",
    "amount",
    "active",
    "label",
    "business_date",
    "local_time",
    "instant_time",
)
_ZERO_LIMBS = (0, 0, 0, 0, 0, 0, 0, 0)
_CLICKHOUSE_MANIFESTS = Path(__file__).parent / "fixtures" / "clickhouse" / "manifests"


def test_clickhouse_canonical_bytes_fingerprint_and_binary_groups_match_shared_oracle() -> None:
    row_vector = vector_named("all_common_types")
    row_schema = schema_from_metadata_json(row_vector.metadata_json)
    key_vector = vector_named("composite_key")
    key_schema = schema_from_metadata_json(key_vector.metadata_json)
    limits = ClickHouseCanonicalLimits(
        max_encoded_envelope_bytes=1_024,
        max_response_bytes=65_536,
        max_execution_time_seconds=5,
    )
    settings = required_clickhouse_reader_settings("dfe-phase05-canonical")
    transport = open_clickhouse_transport(
        settings,
        single_attempt_clickhouse_retry_policy(),
        standard_clickhouse_transport_limits(),
        clickhouse_read_deadline(20_000, 300_000),
        fresh_clickhouse_attempt_id(),
    )
    try:
        relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_common_types",
            schema=row_schema,
            column_names=_COMMON_TYPE_COLUMNS,
            max_response_bytes=16_384,
            max_execution_time_seconds=5,
        )
        rows = read_clickhouse_canonical_rows(
            transport,
            ClickHouseCanonicalReadRequest(
                relation=relation,
                order_columns=("probe_id",),
                max_records=2,
                limits=limits,
            ),
        )
        expected_envelope = row_vector.envelope_ascii.encode("ascii")
        expected_sha256 = bytes.fromhex(row_vector.sha256_hex)
        assert tuple(row.envelope for row in rows) == (expected_envelope, expected_envelope)
        assert tuple(row.sha256 for row in rows) == (expected_sha256, expected_sha256)

        fingerprint = read_clickhouse_canonical_fingerprint(
            transport,
            relation,
            limits,
        )
        assert row_vector.duplicate_twice_count is not None
        assert row_vector.duplicate_twice_limb_sums is not None
        assert fingerprint.fingerprint == Fingerprint(
            count=row_vector.duplicate_twice_count,
            limb_sums=row_vector.duplicate_twice_limb_sums,
        )
        assert fingerprint.invalid_row_count == 0
        assert fingerprint.oversized_row_count == 0

        empty_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_empty_common_types",
            schema=row_schema,
            column_names=_COMMON_TYPE_COLUMNS,
            max_response_bytes=16_384,
            max_execution_time_seconds=5,
        )
        empty_fingerprint = read_clickhouse_canonical_fingerprint(
            transport,
            empty_relation,
            limits,
        )
        assert empty_fingerprint.fingerprint == Fingerprint(
            count=0,
            limb_sums=_ZERO_LIMBS,
        )
        assert empty_fingerprint.invalid_row_count == 0
        assert empty_fingerprint.oversized_row_count == 0

        lossy_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_lossy_common_types",
            schema=row_schema,
            column_names=_COMMON_TYPE_COLUMNS,
            max_response_bytes=16_384,
            max_execution_time_seconds=5,
        )
        with pytest.raises(
            ClickHouseDataValidationError,
            match="invalid_row_count=2",
        ):
            read_clickhouse_canonical_fingerprint(
                transport,
                lossy_relation,
                limits,
            )

        nullable_schema = CanonicalSchema(
            protocol=PROTOCOL,
            fields=(
                FieldSchema(
                    name="label",
                    logical_type=LogicalType.STRING,
                    nullable=True,
                    parameters=NoParameters(),
                    normalization=Normalization.NONE,
                ),
            ),
        )
        nullable_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_nullable_strings",
            schema=nullable_schema,
            column_names=("label",),
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        )
        nullable_rows = read_clickhouse_canonical_rows(
            transport,
            ClickHouseCanonicalReadRequest(
                relation=nullable_relation,
                order_columns=("probe_id",),
                max_records=2,
                limits=limits,
            ),
        )
        expected_nullable_envelopes = (
            encode_row(nullable_schema, (None,)),
            encode_row(nullable_schema, ("",)),
        )
        assert tuple(row.envelope for row in nullable_rows) == expected_nullable_envelopes
        assert tuple(row.sha256 for row in nullable_rows) == tuple(
            envelope_sha256(envelope) for envelope in expected_nullable_envelopes
        )
        assert expected_nullable_envelopes[0] != expected_nullable_envelopes[1]

        key_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_key_groups",
            schema=key_schema,
            column_names=("id", "label"),
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        )
        key_groups = read_clickhouse_canonical_key_groups(
            transport,
            ClickHouseCanonicalGroupRequest(
                relation=key_relation,
                max_groups=4,
                limits=limits,
            ),
        )
        golden_id, golden_label = key_vector.values
        assert type(golden_id) is str
        assert type(golden_label) is str
        expected_groups = {
            encode_key(key_schema, (int(golden_id), golden_label)): 2,
            encode_key(key_schema, (int(golden_id), golden_label[:-1])): 1,
            encode_key(key_schema, (int(golden_id), "A|Б😀é  ")): 1,
            encode_key(key_schema, (int(golden_id) + 1, golden_label)): 1,
        }
        assert {group.envelope: group.row_count for group in key_groups.groups} == expected_groups
        assert key_groups.valid_key_count == 5
        assert key_groups.invalid_key_count == 0
        assert key_groups.oversized_key_count == 0

        overflow_schema = CanonicalSchema(
            protocol=PROTOCOL,
            fields=(
                FieldSchema(
                    name="id",
                    logical_type=LogicalType.INT64,
                    nullable=False,
                    parameters=NoParameters(),
                    normalization=Normalization.NONE,
                ),
            ),
        )
        overflow_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_group_overflow",
            schema=overflow_schema,
            column_names=("id",),
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        )
        with pytest.raises(
            ClickHouseResultLimitError,
            match="exceeded its distinct-group bound",
        ):
            read_clickhouse_canonical_key_groups(
                transport,
                ClickHouseCanonicalGroupRequest(
                    relation=overflow_relation,
                    max_groups=4,
                    limits=limits,
                ),
            )

        null_key_relation = inspect_clickhouse_canonical_relation(
            transport=transport,
            database="dfe_fixture",
            table="canonical_null_key",
            schema=key_schema,
            column_names=("id", "label"),
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        )
        with pytest.raises(
            ClickHouseDataValidationError,
            match="invalid_key_count=1",
        ):
            read_clickhouse_canonical_key_groups(
                transport,
                ClickHouseCanonicalGroupRequest(
                    relation=null_key_relation,
                    max_groups=1,
                    limits=limits,
                ),
            )
    finally:
        transport.close()


def test_clickhouse_lts_profile_is_lossless_bounded_and_read_only() -> None:
    settings = required_clickhouse_reader_settings("dfe-phase05-profile")
    transport = open_clickhouse_transport(
        settings,
        single_attempt_clickhouse_retry_policy(),
        standard_clickhouse_transport_limits(),
        clickhouse_read_deadline(20_000, 300_000),
        fresh_clickhouse_attempt_id(),
    )
    try:
        profile = inspect_clickhouse_server_profile(transport, settings)
        assert profile.binding_library_name == "clickhouse-connect"
        assert profile.binding_library_version == "1.9.0"
        assert profile.transport_library_name == "urllib3"
        assert profile.transport_library_version == "2.8.0"
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
        # The server watchdog includes one second for parent-side cancellation.
        assert profile.effective_max_execution_time_seconds == Decimal("21")
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
            ClickHouseResourceConstraint(
                setting=ClickHouseResourceSetting.MAX_EXECUTION_TIME,
                value=Decimal("21"),
                minimum=Decimal("1"),
                maximum=Decimal("30"),
                changeable_in_readonly=True,
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
            ClickHouseResourceConstraint(
                setting=ClickHouseResourceSetting.MAX_ROWS_TO_GROUP_BY,
                value=Decimal("1"),
                minimum=Decimal("1"),
                maximum=Decimal("100000"),
                changeable_in_readonly=True,
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
        with pytest.raises(ClickHouseResponseLimitError) as complete_response_limit:
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
        assert complete_response_limit.value.received_response_bytes == 2_049
        assert complete_response_limit.value.response_truncated is False
        assert transport.state is ClickHouseTransportState.LOST
        assert transport.source_slot_released is True
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


def test_clickhouse_http_transport_rejects_ambiguous_results_and_reaps_queries() -> None:
    manifest = parse_clickhouse_immutable_version_manifest(
        (_CLICKHOUSE_MANIFESTS / "immutable-orders-v001.json").read_bytes(),
        1_024,
    )
    request = _immutable_version_request(manifest)
    admin_settings = required_clickhouse_admin_settings("dfe-phase05-transport-admin")
    reader_settings = required_clickhouse_tls_reader_settings("dfe-phase05-transport-reader")
    untrusted_reader_settings = required_clickhouse_untrusted_tls_reader_settings(
        "dfe-phase05-untrusted-tls-reader"
    )
    bounded_error_limits = replace(
        standard_clickhouse_transport_limits(),
        max_error_response_bytes=1_024,
    )
    bounded_initialization_limits = replace(
        standard_clickhouse_transport_limits(),
        max_initialization_response_bytes=5,
    )
    minimal_cancellation_limits = replace(
        standard_clickhouse_transport_limits(),
        cancellation_reserve_milliseconds=1,
    )

    _reset_immutable_version_readiness(admin_settings)
    admin = _open_clickhouse_fixture_client(admin_settings)
    try:
        unexpected_untrusted_transport: ClickHouseTransport | None = None
        try:
            with pytest.raises(ClickHouseConnectionError) as untrusted_tls:
                unexpected_untrusted_transport = open_clickhouse_transport(
                    untrusted_reader_settings,
                    single_attempt_clickhouse_retry_policy(),
                    standard_clickhouse_transport_limits(),
                    clickhouse_read_deadline(20_000, 300_000),
                    fresh_clickhouse_attempt_id(),
                )
        finally:
            if unexpected_untrusted_transport is not None:
                _close_and_cleanup_clickhouse_transport(
                    unexpected_untrusted_transport,
                    admin,
                )
        untrusted_tls_error = untrusted_tls.value
        assert untrusted_tls_error.connection_attempts == 1
        assert untrusted_tls_error.query_id is None
        assert untrusted_tls_error.http_status is None
        assert untrusted_tls_error.error_code is None
        assert untrusted_tls_error.error_name is None
        assert untrusted_tls_error.received_error_bytes == 0
        assert untrusted_tls_error.error_response_truncated is False
        assert untrusted_tls_error.cause_type == "SSLError"
        assert reader_settings.password.get_secret_value() not in str(untrusted_tls_error)

        unexpected_initialization_transport: ClickHouseTransport | None = None
        try:
            with pytest.raises(ClickHouseConnectionError) as bounded_initialization:
                unexpected_initialization_transport = open_clickhouse_transport(
                    reader_settings,
                    single_attempt_clickhouse_retry_policy(),
                    bounded_initialization_limits,
                    clickhouse_read_deadline(20_000, 300_000),
                    fresh_clickhouse_attempt_id(),
                )
        finally:
            if unexpected_initialization_transport is not None:
                _close_and_cleanup_clickhouse_transport(
                    unexpected_initialization_transport,
                    admin,
                )
        initialization_error = bounded_initialization.value
        assert initialization_error.connection_attempts == 1
        assert initialization_error.http_status == 200
        assert initialization_error.received_error_bytes == 10
        assert initialization_error.error_response_truncated is False
        assert initialization_error.cause_type == "InitializationResponseLimit"
        assert initialization_error.query_id is not None
        _require_clickhouse_query_absent(admin, initialization_error.query_id)

        source_transport = open_clickhouse_transport(
            reader_settings,
            single_attempt_clickhouse_retry_policy(),
            standard_clickhouse_transport_limits(),
            clickhouse_read_deadline(20_000, 300_000),
            fresh_clickhouse_attempt_id(),
        )
        try:
            binding = acquire_clickhouse_immutable_version(
                source_transport,
                request,
                manifest,
            )
            assert isinstance(binding, ClickHouseImmutableVersionBinding)
        finally:
            source_transport.close()

        bounded_error_transport = open_clickhouse_transport(
            reader_settings,
            single_attempt_clickhouse_retry_policy(),
            bounded_error_limits,
            clickhouse_read_deadline(20_000, 300_000),
            fresh_clickhouse_attempt_id(),
        )
        try:
            request_count_before_mismatch = bounded_error_transport.physical_request_count
            with pytest.raises(ClickHouseTransportAttemptMismatchError):
                confirm_clickhouse_immutable_version(bounded_error_transport, binding)
            assert bounded_error_transport.physical_request_count == request_count_before_mismatch

            with pytest.raises(ValueError):
                bounded_error_transport.execute_raw(
                    query="SELECT 1",
                    parameters={},
                    settings={"http_write_exception_in_output_format": 1},
                    result_format="TabSeparatedRaw",
                    max_response_bytes=8,
                    operation="reject_exception_frame_override",
                )
            assert bounded_error_transport.physical_request_count == request_count_before_mismatch

            with pytest.raises(ClickHouseCancellationUnconfirmedError) as oversized_error:
                bounded_error_transport.execute_raw(
                    query="SELECT throwIf(1, repeat('~', {message_size:UInt64}))",
                    parameters={"message_size": 200_000},
                    settings={"session_timezone": "UTC"},
                    result_format="TabSeparatedRaw",
                    max_response_bytes=64,
                    operation="prove_bounded_clickhouse_error_response",
                )
            bounded_error = oversized_error.value
            assert bounded_error.trigger_cause == "ErrorResponseLimit"
            assert bounded_error.cancellation_cause == "KillQueryNotFinished"
            assert bounded_error.http_status == 500
            assert bounded_error.error_code == 395
            assert bounded_error.received_response_bytes == 1_025
            assert bounded_error.response_truncated is True
            assert "~" not in str(bounded_error)
            assert reader_settings.password.get_secret_value() not in str(bounded_error)
            assert (
                bounded_error_transport.state is ClickHouseTransportState.CANCELLATION_UNCONFIRMED
            )
            assert bounded_error_transport.source_slot_released is False
            _cleanup_clickhouse_query(admin, bounded_error.query_id)
        finally:
            _close_and_cleanup_clickhouse_transport(bounded_error_transport, admin)

        capped_transport = open_clickhouse_transport(
            reader_settings,
            single_attempt_clickhouse_retry_policy(),
            standard_clickhouse_transport_limits(),
            clickhouse_read_deadline(20_000, 300_000),
            fresh_clickhouse_attempt_id(),
        )
        try:
            with pytest.raises(ClickHouseCancellationUnconfirmedError) as capped_result:
                capped_transport.execute_raw(
                    query="SELECT repeat('x', {result_size:UInt64})",
                    parameters={"result_size": 20_000},
                    settings={"session_timezone": "UTC"},
                    result_format="TabSeparatedRaw",
                    max_response_bytes=64,
                    operation="prove_incomplete_response_is_never_accepted",
                )
            capped_error = capped_result.value
            assert capped_error.trigger_cause == "ResponseLimit"
            assert capped_error.cancellation_cause == "KillQueryNotFinished"
            assert capped_error.received_response_bytes == (
                64 + CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES + 1
            )
            assert capped_error.response_truncated is True
            assert capped_transport.state is ClickHouseTransportState.CANCELLATION_UNCONFIRMED
            assert capped_transport.source_slot_released is False
            _cleanup_clickhouse_query(admin, capped_error.query_id)
        finally:
            _close_and_cleanup_clickhouse_transport(capped_transport, admin)

        late_error_transport = open_clickhouse_transport(
            reader_settings,
            single_attempt_clickhouse_retry_policy(),
            standard_clickhouse_transport_limits(),
            clickhouse_read_deadline(20_000, 300_000),
            fresh_clickhouse_attempt_id(),
        )
        try:
            with pytest.raises(ClickHouseQueryError) as late_server_error:
                late_error_transport.execute_raw(
                    query=(
                        "SELECT sleepEachRow(0.1), "
                        "throwIf(number = 2, 'late-probe') FROM numbers(5)"
                    ),
                    parameters={},
                    settings={
                        "session_timezone": "UTC",
                        "http_wait_end_of_query": 0,
                        "max_block_size": 1,
                    },
                    result_format="TabSeparatedRaw",
                    max_response_bytes=8,
                    operation="prove_late_clickhouse_exception_frame",
                )
            late_error = late_server_error.value
            assert late_error.http_status == 200
            assert late_error.error_code == 395
            assert late_error.error_name == "FUNCTION_THROW_IF_VALUE_IS_NON_ZERO"
            assert late_error.completion is ClickHouseQueryCompletion.SERVER_TERMINAL
            assert (
                8
                < late_error.received_error_bytes
                <= (8 + CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES)
            )
            assert late_error.error_response_truncated is False
            assert "late-probe" not in str(late_error)
            assert reader_settings.password.get_secret_value() not in str(late_error)
            assert late_error_transport.state is ClickHouseTransportState.LOST
            assert late_error_transport.source_slot_released is True
            _require_clickhouse_query_absent(admin, late_error.query_id)
        finally:
            _close_and_cleanup_clickhouse_transport(late_error_transport, admin)

        deadline_transport = open_clickhouse_transport(
            reader_settings,
            single_attempt_clickhouse_retry_policy(),
            standard_clickhouse_transport_limits(),
            clickhouse_read_deadline(1_500, 15_000),
            fresh_clickhouse_attempt_id(),
        )
        try:
            with pytest.raises(ClickHouseAttemptDeadlineExceededError) as deadline_exceeded:
                deadline_transport.execute_raw(
                    query=("SELECT sum(sipHash64(number)) FROM numbers(1000000000000)"),
                    parameters={},
                    settings={
                        "session_timezone": "UTC",
                        "max_result_rows": 1,
                        "max_result_bytes": 64,
                        "result_overflow_mode": "throw",
                    },
                    result_format="TabSeparatedRaw",
                    max_response_bytes=64,
                    operation="prove_clickhouse_deadline_cancellation",
                )
            deadline_error = deadline_exceeded.value
            assert deadline_error.completion is ClickHouseQueryCompletion.CANCELLED
            assert deadline_transport.state is ClickHouseTransportState.LOST
            assert deadline_transport.source_slot_released is True
            _require_clickhouse_query_absent(admin, deadline_error.query_id)
        finally:
            _close_and_cleanup_clickhouse_transport(deadline_transport, admin)

        unconfirmed_deadline_transport = open_clickhouse_transport(
            reader_settings,
            single_attempt_clickhouse_retry_policy(),
            minimal_cancellation_limits,
            clickhouse_read_deadline(1_500, 15_000),
            fresh_clickhouse_attempt_id(),
        )
        try:
            with pytest.raises(ClickHouseCancellationUnconfirmedError) as unconfirmed_deadline:
                unconfirmed_deadline_transport.execute_raw(
                    query=("SELECT sum(sipHash64(number)) FROM numbers(1000000000000)"),
                    parameters={},
                    settings={
                        "session_timezone": "UTC",
                        "max_result_rows": 1,
                        "max_result_bytes": 64,
                        "result_overflow_mode": "throw",
                    },
                    result_format="TabSeparatedRaw",
                    max_response_bytes=64,
                    operation="prove_bounded_unconfirmed_clickhouse_cancellation",
                )
            unconfirmed_error = unconfirmed_deadline.value
            assert unconfirmed_error.trigger_cause == "AttemptDeadlineExceeded"
            assert (
                unconfirmed_error.cancellation_cause
                == "CancellationAcknowledgementDeadlineExceeded"
            )
            assert (
                unconfirmed_deadline_transport.state
                is ClickHouseTransportState.CANCELLATION_UNCONFIRMED
            )
            assert unconfirmed_deadline_transport.source_slot_released is False
            _cleanup_clickhouse_query(admin, unconfirmed_error.query_id)
        finally:
            _close_and_cleanup_clickhouse_transport(unconfirmed_deadline_transport, admin)
    finally:
        try:
            admin.close_connections()
        finally:
            _reset_immutable_version_readiness(admin_settings)


def test_clickhouse_immutable_versions_bind_only_complete_append_only_publications() -> None:
    v001_manifest = parse_clickhouse_immutable_version_manifest(
        (_CLICKHOUSE_MANIFESTS / "immutable-orders-v001.json").read_bytes(),
        1_024,
    )
    v002_manifest = parse_clickhouse_immutable_version_manifest(
        (_CLICKHOUSE_MANIFESTS / "immutable-orders-v002.json").read_bytes(),
        1_024,
    )
    v001_request = _immutable_version_request(v001_manifest)
    v002_request = _immutable_version_request(v002_manifest)
    admin_settings = required_clickhouse_admin_settings("dfe-phase05-readiness-reset")
    reader_settings = required_clickhouse_reader_settings("dfe-phase05-readiness-reader")
    writer_settings = required_clickhouse_writer_settings("dfe-phase05-readiness-writer")

    try:
        _reset_immutable_version_readiness(admin_settings)
        reader = open_clickhouse_transport(
            reader_settings,
            single_attempt_clickhouse_retry_policy(),
            standard_clickhouse_transport_limits(),
            clickhouse_read_deadline(20_000, 300_000),
            fresh_clickhouse_attempt_id(),
        )
        try:
            v001_binding = acquire_clickhouse_immutable_version(
                reader,
                v001_request,
                v001_manifest,
            )
            assert isinstance(v001_binding, ClickHouseImmutableVersionBinding)
            assert v001_binding.readiness_evidence.evidence_level is ConsistencyLevel.VERIFIED
            assert v001_binding.stable_read_evidence is ConsistencyLevel.ASSERTED
            assert v001_binding.overall_evidence is ConsistencyLevel.ASSERTED
            v001_confirmation = confirm_clickhouse_immutable_version(reader, v001_binding)
            assert isinstance(
                v001_confirmation,
                ClickHouseImmutableVersionConfirmation,
            )

            before_write = reader.execute_raw(
                query="SELECT count() FROM dfe_fixture.immutable_orders_v001",
                parameters={},
                settings={
                    "session_timezone": "UTC",
                    "max_execution_time": 5,
                    "max_result_rows": 1,
                    "max_result_bytes": 64,
                    "result_overflow_mode": "throw",
                },
                result_format="TabSeparatedRaw",
                max_response_bytes=64,
                operation="count_sealed_immutable_version_before_rejected_write",
            )
            assert before_write.payload == b"2\n"

            sealed_writer = _open_clickhouse_fixture_client(writer_settings)
            try:
                insert_grant = sealed_writer.command(  # pyright: ignore[reportUnknownMemberType]
                    "CHECK GRANT INSERT ON dfe_fixture.immutable_orders_v001"
                )
                assert insert_grant == 1
                alter_grant = sealed_writer.command(  # pyright: ignore[reportUnknownMemberType]
                    "CHECK GRANT ALTER TABLE ON dfe_fixture.immutable_orders_v001"
                )
                assert alter_grant == 0
                with pytest.raises(DatabaseError) as rejected_write:
                    sealed_writer.command(  # pyright: ignore[reportUnknownMemberType]
                        "INSERT INTO dfe_fixture.immutable_orders_v001 VALUES "
                        "(3, '30.000', toDate('2024-02-29'), "
                        "'immutable-orders-2024-02-29-v001')"
                    )
                assert rejected_write.value.name == "TABLE_IS_PERMANENTLY_READ_ONLY"
            finally:
                sealed_writer.close_connections()

            after_write = reader.execute_raw(
                query="SELECT count() FROM dfe_fixture.immutable_orders_v001",
                parameters={},
                settings={
                    "session_timezone": "UTC",
                    "max_execution_time": 5,
                    "max_result_rows": 1,
                    "max_result_bytes": 64,
                    "result_overflow_mode": "throw",
                },
                result_format="TabSeparatedRaw",
                max_response_bytes=64,
                operation="count_sealed_immutable_version_after_rejected_write",
            )
            assert after_write.payload == before_write.payload

            readiness_writer = _open_clickhouse_fixture_client(writer_settings)
            try:
                _append_building_readiness(readiness_writer, v002_manifest, 2)
                building_outcome = acquire_clickhouse_immutable_version(
                    reader,
                    v002_request,
                    v002_manifest,
                )
                assert isinstance(building_outcome, EarlyExecutionOutcome)
                assert building_outcome.execution_status is ExecutionStatus.INCOMPLETE
                assert building_outcome.reason.code is ReasonCode.NOT_READY

                _append_complete_readiness(readiness_writer, v002_manifest)
            finally:
                readiness_writer.close_connections()

            superseded_v001 = confirm_clickhouse_immutable_version(reader, v001_binding)
            assert isinstance(superseded_v001, EarlyExecutionOutcome)
            assert superseded_v001.execution_status is ExecutionStatus.INCOMPLETE
            assert superseded_v001.reason.code is ReasonCode.NOT_READY

            v002_binding = acquire_clickhouse_immutable_version(
                reader,
                v002_request,
                v002_manifest,
            )
            assert isinstance(v002_binding, ClickHouseImmutableVersionBinding)
            assert v002_binding.readiness_evidence.evidence_level is ConsistencyLevel.VERIFIED
            assert v002_binding.stable_read_evidence is ConsistencyLevel.ASSERTED
            assert v002_binding.overall_evidence is ConsistencyLevel.ASSERTED
            v002_confirmation = confirm_clickhouse_immutable_version(reader, v002_binding)
            assert isinstance(
                v002_confirmation,
                ClickHouseImmutableVersionConfirmation,
            )

            policy_admin = _open_clickhouse_fixture_client(admin_settings)
            try:
                _drop_readiness_row_policy(policy_admin)
                policy_admin.command(  # pyright: ignore[reportUnknownMemberType]
                    "CREATE ROW POLICY dfe_p05_readiness_head_visibility "
                    "ON dfe_fixture.immutable_version_readiness FOR SELECT "
                    "USING publication_revision < 2 TO dfe_fixture_reader"
                )
                filtered_revisions = reader.execute_raw(
                    query=(
                        "SELECT toString(publication_revision) FROM "
                        "dfe_fixture.immutable_version_readiness "
                        "WHERE dataset_id = {dataset_id:String} "
                        "AND scope_digest = {scope_digest:String} "
                        "ORDER BY publication_revision"
                    ),
                    parameters={
                        "dataset_id": v001_manifest.dataset_id,
                        "scope_digest": v001_manifest.scope_digest,
                    },
                    settings={
                        "session_timezone": "UTC",
                        "max_execution_time": 5,
                        "max_result_rows": 3,
                        "max_result_bytes": 64,
                        "result_overflow_mode": "throw",
                    },
                    result_format="TabSeparatedRaw",
                    max_response_bytes=64,
                    operation="prove_readiness_row_policy_hides_newer_publications",
                )
                assert filtered_revisions.payload == b"1\n"
                with pytest.raises(UnsupportedClickHouseProfileError):
                    acquire_clickhouse_immutable_version(
                        reader,
                        v001_request,
                        v001_manifest,
                    )
            finally:
                try:
                    _drop_readiness_row_policy(policy_admin)
                finally:
                    policy_admin.close_connections()
        finally:
            reader.close()
    finally:
        _reset_immutable_version_readiness(admin_settings)


def test_clickhouse_logical_projection_is_explicit_tie_free_and_mutation_ready() -> None:
    immutable_manifest = parse_clickhouse_immutable_version_manifest(
        (_CLICKHOUSE_MANIFESTS / "immutable-orders-v001.json").read_bytes(),
        1_024,
    )
    logical_manifest = parse_clickhouse_immutable_version_manifest(
        (_CLICKHOUSE_MANIFESTS / "logical-orders-v001.json").read_bytes(),
        1_024,
    )
    projection_payload = (
        _CLICKHOUSE_MANIFESTS / "logical-orders-v001-projection.json"
    ).read_bytes()
    projection_manifest = parse_clickhouse_replacing_projection_manifest(
        projection_payload,
        4_096,
    )
    logical_schema = _logical_orders_schema()
    canonical_limits = ClickHouseCanonicalLimits(
        max_encoded_envelope_bytes=1_024,
        max_response_bytes=65_536,
        max_execution_time_seconds=5,
    )
    projected_columns = ("order_id", "amount", "business_date")
    plain_request = _projection_request(
        immutable_manifest,
        logical_schema,
        projected_columns,
        canonical_limits,
    )
    replacing_request = _projection_request(
        logical_manifest,
        logical_schema,
        projected_columns,
        canonical_limits,
    )
    alias_projection_payload = projection_payload.replace(
        b'    "amount",',
        b'    "amount_alias",',
        1,
    )
    assert alias_projection_payload != projection_payload
    alias_projection_manifest = parse_clickhouse_replacing_projection_manifest(
        alias_projection_payload,
        4_096,
    )
    alias_request = _projection_request(
        logical_manifest,
        logical_schema,
        ("order_id", "amount_alias", "business_date"),
        canonical_limits,
    )
    admin_settings = required_clickhouse_admin_settings("dfe-phase05-projection-reset")
    reader_settings = required_clickhouse_reader_settings("dfe-phase05-projection-reader")
    admin = _open_clickhouse_fixture_client(admin_settings)
    reader = None
    mutation_id: str | None = None
    try:
        _reset_logical_orders_projection(admin)
        _reset_immutable_version_readiness(admin_settings)
        reader = open_clickhouse_transport(
            reader_settings,
            single_attempt_clickhouse_retry_policy(),
            standard_clickhouse_transport_limits(),
            clickhouse_read_deadline(20_000, 300_000),
            fresh_clickhouse_attempt_id(),
        )

        plain_binding = acquire_clickhouse_merge_tree_projection(
            reader,
            plain_request,
            immutable_manifest,
        )
        assert isinstance(plain_binding, ClickHouseMergeTreeProjectionBinding)
        assert type(plain_binding.relation.source) is ClickHouseMergeTreeLogicalProjectionSource
        plain_envelopes = (
            encode_row(
                logical_schema,
                (1, Decimal("10.000"), date(2024, 2, 29)),
            ),
            encode_row(
                logical_schema,
                (2, Decimal("20.000"), date(2024, 2, 29)),
            ),
        )
        plain_rows = read_clickhouse_canonical_rows(
            reader,
            ClickHouseCanonicalReadRequest(
                relation=plain_binding.relation,
                order_columns=("order_id",),
                max_records=2,
                limits=canonical_limits,
            ),
        )
        assert tuple(row.envelope for row in plain_rows) == plain_envelopes
        assert tuple(row.sha256 for row in plain_rows) == tuple(
            envelope_sha256(envelope) for envelope in plain_envelopes
        )
        assert plain_binding.logical_fingerprint.fingerprint == fingerprint_rows(plain_envelopes)
        assert plain_binding.logical_fingerprint.invalid_row_count == 0
        assert plain_binding.logical_fingerprint.oversized_row_count == 0
        assert plain_binding.overall_evidence is ConsistencyLevel.ASSERTED
        plain_confirmation = confirm_clickhouse_merge_tree_projection(
            reader,
            plain_binding,
        )
        assert isinstance(
            plain_confirmation,
            ClickHouseMergeTreeProjectionConfirmation,
        )

        replacing_binding = acquire_clickhouse_replacing_merge_tree_projection(
            reader,
            replacing_request,
            logical_manifest,
            projection_manifest,
        )
        assert isinstance(
            replacing_binding,
            ClickHouseReplacingMergeTreeProjectionBinding,
        )
        assert (
            type(replacing_binding.relation.source)
            is ClickHouseReplacingMergeTreeLogicalProjectionSource
        )
        assert replacing_binding.row_counts.physical_row_count == 5
        assert replacing_binding.row_counts.logical_row_count == 3
        replacing_envelopes = (
            encode_row(
                logical_schema,
                (1, Decimal("11.000"), date(2024, 2, 29)),
            ),
            encode_row(
                logical_schema,
                (2, Decimal("20.000"), date(2024, 2, 29)),
            ),
            encode_row(
                logical_schema,
                (3, Decimal("30.000"), date(2024, 2, 29)),
            ),
        )
        replacing_rows = read_clickhouse_canonical_rows(
            reader,
            ClickHouseCanonicalReadRequest(
                relation=replacing_binding.relation,
                order_columns=("order_id",),
                max_records=3,
                limits=canonical_limits,
            ),
        )
        assert tuple(row.envelope for row in replacing_rows) == replacing_envelopes
        assert tuple(row.sha256 for row in replacing_rows) == tuple(
            envelope_sha256(envelope) for envelope in replacing_envelopes
        )
        assert replacing_binding.logical_fingerprint.fingerprint == fingerprint_rows(
            replacing_envelopes
        )
        assert replacing_binding.logical_fingerprint.invalid_row_count == 0
        assert replacing_binding.logical_fingerprint.oversized_row_count == 0
        assert replacing_binding.stable_read_evidence is ConsistencyLevel.ASSERTED
        assert replacing_binding.tie_freedom_evidence is ConsistencyLevel.ASSERTED
        assert replacing_binding.overall_evidence is ConsistencyLevel.ASSERTED
        replacing_confirmation = confirm_clickhouse_replacing_merge_tree_projection(
            reader,
            replacing_binding,
        )
        assert isinstance(
            replacing_confirmation,
            ClickHouseReplacingMergeTreeProjectionConfirmation,
        )

        with pytest.raises(
            UnsupportedClickHouseProfileError,
            match="supports only ordinary stored columns",
        ):
            acquire_clickhouse_replacing_merge_tree_projection(
                reader,
                alias_request,
                logical_manifest,
                alias_projection_manifest,
            )

        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 0"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "INSERT INTO dfe_fixture.logical_orders_v001 "
            "(order_id, amount, business_date, poison, row_version) VALUES "
            "(1, '12.000', toDate('2024-02-29'), '12', toUInt64(2))"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 1"
        )
        with pytest.raises(ClickHouseReplacingVersionAmbiguityError):
            acquire_clickhouse_replacing_merge_tree_projection(
                reader,
                replacing_request,
                logical_manifest,
                projection_manifest,
            )

        _reset_logical_orders_projection(admin)
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 0"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.logical_orders_v001 "
            "UPDATE amount = CAST(poison AS Decimal(38, 3)) WHERE order_id = 2 "
            "SETTINGS mutations_sync = 0"
        )
        mutation_id = _single_logical_orders_mutation_id(admin)
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 1"
        )
        pending_mutation = acquire_clickhouse_replacing_merge_tree_projection(
            reader,
            replacing_request,
            logical_manifest,
            projection_manifest,
        )
        assert isinstance(pending_mutation, EarlyExecutionOutcome)
        assert pending_mutation.execution_status is ExecutionStatus.INCOMPLETE
        assert pending_mutation.reason.code is ReasonCode.NOT_READY
        assert (
            pending_mutation.reason.message
            == "ClickHouse logical projection has an unfinished mutation"
        )

        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 0"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "SYSTEM START MERGES dfe_fixture.logical_orders_v001"
        )
        mutation_error_code = _wait_for_logical_orders_mutation_failure(
            admin,
            mutation_id,
            10.0,
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "SYSTEM STOP MERGES dfe_fixture.logical_orders_v001"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 1"
        )
        with pytest.raises(ClickHouseMutationFailureError) as mutation_failure:
            acquire_clickhouse_replacing_merge_tree_projection(
                reader,
                replacing_request,
                logical_manifest,
                projection_manifest,
            )
        assert str(mutation_failure.value) == (
            "ClickHouse logical projection has a failed mutation: "
            "database='dfe_fixture', table='logical_orders_v001', "
            f"mutation_id={mutation_id!r}, error_code={mutation_error_code!r}"
        )
        assert "mutation-failure" not in str(mutation_failure.value)
    finally:
        if reader is not None and not reader.closed:
            reader.close()
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 0"
        )
        if mutation_id is not None:
            admin.command(  # pyright: ignore[reportUnknownMemberType]
                "KILL MUTATION WHERE database = {database:String} "
                "AND table = {table:String} AND mutation_id = {mutation_id:String} SYNC",
                parameters={
                    "database": "dfe_fixture",
                    "table": "logical_orders_v001",
                    "mutation_id": mutation_id,
                },
            )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "SYSTEM START MERGES dfe_fixture.logical_orders_v001"
        )
        _reset_logical_orders_projection(admin)
        admin.close_connections()
        _reset_immutable_version_readiness(admin_settings)


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


def _cleanup_clickhouse_query(client: Client, query_id: UUID) -> None:
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "KILL QUERY WHERE query_id = {query_id:String} SYNC",
        parameters={"query_id": str(query_id)},
    )
    _require_clickhouse_query_absent(client, query_id)


def _close_and_cleanup_clickhouse_transport(
    transport: ClickHouseTransport,
    admin: Client,
) -> None:
    try:
        if transport.state is ClickHouseTransportState.ACTIVE:
            transport.close()
    finally:
        if not transport.source_slot_released and transport.last_query_id is not None:
            _cleanup_clickhouse_query(admin, transport.last_query_id)


def _require_clickhouse_query_absent(client: Client, query_id: UUID) -> None:
    observation_deadline = monotonic() + 5.0
    while True:
        active_count = client.command(  # pyright: ignore[reportUnknownMemberType]
            "SELECT count() FROM system.processes WHERE query_id = {query_id:String}",
            parameters={"query_id": str(query_id)},
        )
        if type(active_count) is not int:
            raise AssertionError("ClickHouse active-query count must be an integer")
        if active_count == 0:
            return
        if monotonic() >= observation_deadline:
            raise AssertionError(
                f"ClickHouse query remained active after its transport retired: query_id={query_id}"
            )
        sleep(0.05)


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


def _immutable_version_request(
    manifest: ClickHouseImmutableVersionManifest,
) -> ClickHouseImmutableVersionRequest:
    return ClickHouseImmutableVersionRequest(
        direction=PlanDirection.REFERENCE,
        endpoint_profile="direct_single_server",
        readiness_database="dfe_fixture",
        readiness_table="immutable_version_readiness",
        expected_issuer="dfe_fixture_loader",
        dataset_id=manifest.dataset_id,
        scope_digest=manifest.scope_digest,
        expected_batch_id=manifest.expected_batch_id,
        alignment_fields=("business_date", "source_cut"),
        minimum_evidence=MinimumEvidence.ASSERTED,
        late_arrivals=LateArrivalPolicy.NEXT_BATCH,
        limits=ClickHouseReadinessLimits(
            max_response_bytes=8_192,
            max_execution_time_seconds=5,
        ),
    )


def _logical_orders_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="order_id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="amount",
                logical_type=LogicalType.DECIMAL,
                nullable=False,
                parameters=DecimalParameters(precision=38, scale=3),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="business_date",
                logical_type=LogicalType.DATE,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _projection_request(
    manifest: ClickHouseImmutableVersionManifest,
    schema: CanonicalSchema,
    column_names: tuple[str, ...],
    canonical_limits: ClickHouseCanonicalLimits,
) -> ClickHouseProjectionRequest:
    return ClickHouseProjectionRequest(
        version_request=_immutable_version_request(manifest),
        schema=schema,
        column_names=column_names,
        canonical_limits=canonical_limits,
        max_mutation_records=8,
        max_tie_groups=8,
    )


def _reset_immutable_version_readiness(settings: ClickHouseConnectionSettings) -> None:
    admin = _open_clickhouse_fixture_client(settings)
    try:
        _drop_readiness_row_policy(admin)
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "DROP TABLE IF EXISTS dfe_fixture.immutable_orders_v001 SYNC"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "CREATE TABLE dfe_fixture.immutable_orders_v001 "
            "UUID '11111111-1111-4111-8111-111111111111' "
            "(order_id Int64, amount Decimal(38, 3), business_date Date, batch_id String) "
            "ENGINE = MergeTree ORDER BY order_id"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "INSERT INTO dfe_fixture.immutable_orders_v001 VALUES "
            "(1, '10.000', toDate('2024-02-29'), "
            "'immutable-orders-2024-02-29-v001'), "
            "(2, '20.000', toDate('2024-02-29'), "
            "'immutable-orders-2024-02-29-v001')"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "ALTER TABLE dfe_fixture.immutable_orders_v001 MODIFY SETTING table_readonly = 1"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "TRUNCATE TABLE dfe_fixture.immutable_version_readiness SYNC"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
            "('immutable_orders', "
            "'5689623b7c5d8424c827123d15d6fdbb011108a79efa1c7586d0f392230697e1', "
            "'immutable-orders-2024-02-29-v001', 'complete', "
            "toDate('2024-02-29'), 'source-orders-cut-000001', "
            "'immutable_orders_v001', "
            "toDateTime64('2024-03-01 00:00:00.000000', 6, 'UTC'), "
            "toUInt64(1), toUInt64(1))"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
            "('logical_orders', "
            "'8e9db77eac98d983fe0053501478a2f52fa3fd35bca9ea56cbb3e6b44f3430e7', "
            "'logical-orders-2024-02-29-v001', 'complete', "
            "toDate('2024-02-29'), 'logical-orders-cut-000001', "
            "'logical_orders_v001', "
            "toDateTime64('2024-03-01 00:10:00.000000', 6, 'UTC'), "
            "toUInt64(1), toUInt64(1))"
        )
        admin.command(  # pyright: ignore[reportUnknownMemberType]
            "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
            "('clickhouse_target_orders', "
            "'13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897', "
            "'comparison-orders-2024-02-29-v001', 'complete', "
            "toDate('2024-02-29'), 'comparison-orders-cut-000001', "
            "'comparison_orders_v001', "
            "toDateTime64('2024-03-01 01:02:03.456789', 6, 'UTC'), "
            "toUInt64(7), toUInt64(11))"
        )
        restored_datasets = admin.raw_query(  # pyright: ignore[reportUnknownMemberType]
            "SELECT dataset_id FROM dfe_fixture.immutable_version_readiness ORDER BY dataset_id",
            fmt="TabSeparatedRaw",
        )
        assert restored_datasets == (
            b"clickhouse_target_orders\nimmutable_orders\nlogical_orders\n"
        )
    finally:
        admin.close_connections()


def _reset_logical_orders_projection(client: Client) -> None:
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "SYSTEM START MERGES dfe_fixture.logical_orders_v001"
    )
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "DROP TABLE IF EXISTS dfe_fixture.logical_orders_v001 SYNC"
    )
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "CREATE TABLE dfe_fixture.logical_orders_v001 "
        "UUID '33333333-3333-4333-8333-333333333333' "
        "(order_id Int64, amount Decimal(38, 3), business_date Date, "
        "poison String, row_version UInt64, "
        "amount_default Decimal(38, 3) DEFAULT amount, "
        "amount_materialized Decimal(38, 3) MATERIALIZED amount, "
        "amount_alias Decimal(38, 3) ALIAS amount) "
        "ENGINE = ReplacingMergeTree(row_version) ORDER BY order_id"
    )
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "SYSTEM STOP MERGES dfe_fixture.logical_orders_v001"
    )
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "INSERT INTO dfe_fixture.logical_orders_v001 "
        "(order_id, amount, business_date, poison, row_version) VALUES "
        "(1, '10.000', toDate('2024-02-29'), '10', toUInt64(1)), "
        "(2, '20.000', toDate('2024-02-29'), 'mutation-failure', toUInt64(2)), "
        "(3, '30.000', toDate('2024-02-29'), '30', toUInt64(1))"
    )
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "INSERT INTO dfe_fixture.logical_orders_v001 "
        "(order_id, amount, business_date, poison, row_version) VALUES "
        "(1, '11.000', toDate('2024-02-29'), '11', toUInt64(2)), "
        "(2, '19.000', toDate('2024-02-29'), '19', toUInt64(1))"
    )
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 1"
    )


def _single_logical_orders_mutation_id(client: Client) -> str:
    payload = client.raw_query(  # pyright: ignore[reportUnknownMemberType]
        "SELECT mutation_id FROM system.mutations "
        "WHERE database = 'dfe_fixture' AND table = 'logical_orders_v001' "
        "ORDER BY mutation_id",
        fmt="TabSeparatedRaw",
    )
    mutation_ids = tuple(line for line in payload.decode("utf-8").splitlines() if line)
    if len(mutation_ids) != 1:
        raise AssertionError(
            "logical_orders_v001 must expose exactly one mutation after the mutation command: "
            f"actual={len(mutation_ids)}"
        )
    return mutation_ids[0]


def _wait_for_logical_orders_mutation_failure(
    client: Client,
    mutation_id: str,
    timeout_seconds: float,
) -> str:
    deadline = monotonic() + timeout_seconds
    while True:
        payload = client.raw_query(  # pyright: ignore[reportUnknownMemberType]
            "SELECT latest_fail_error_code_name FROM system.mutations "
            "WHERE database = {database:String} AND table = {table:String} "
            "AND mutation_id = {mutation_id:String}",
            parameters={
                "database": "dfe_fixture",
                "table": "logical_orders_v001",
                "mutation_id": mutation_id,
            },
            fmt="TabSeparatedRaw",
        )
        error_codes = payload.decode("utf-8").splitlines()
        if len(error_codes) == 1 and error_codes[0]:
            return error_codes[0]
        if monotonic() >= deadline:
            raise AssertionError(
                "logical_orders_v001 mutation did not retain a native failure code "
                f"within {timeout_seconds} seconds: mutation_id={mutation_id!r}"
            )
        sleep(0.05)


def _append_building_readiness(
    client: Client,
    manifest: ClickHouseImmutableVersionManifest,
    publication_revision: int,
) -> None:
    client.command(  # pyright: ignore[reportUnknownMemberType]
        (
            "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
            "({dataset_id:String}, {scope_digest:String}, {batch_id:String}, "
            "'building', toDate({business_date:String}), NULL, NULL, NULL, NULL, "
            "{publication_revision:UInt64})"
        ),
        parameters={
            "dataset_id": manifest.dataset_id,
            "scope_digest": manifest.scope_digest,
            "batch_id": manifest.expected_batch_id,
            "business_date": manifest.business_date.isoformat(),
            "publication_revision": publication_revision,
        },
    )


def _append_complete_readiness(
    client: Client,
    manifest: ClickHouseImmutableVersionManifest,
) -> None:
    client.command(  # pyright: ignore[reportUnknownMemberType]
        (
            "INSERT INTO dfe_fixture.immutable_version_readiness VALUES "
            "({dataset_id:String}, {scope_digest:String}, {batch_id:String}, "
            "'complete', toDate({business_date:String}), {source_cut:String}, "
            "{dataset_version:String}, "
            "toDateTime64({completed_at:String}, 6, 'UTC'), "
            "{completion_revision:UInt64}, {publication_revision:UInt64})"
        ),
        parameters={
            "dataset_id": manifest.dataset_id,
            "scope_digest": manifest.scope_digest,
            "batch_id": manifest.expected_batch_id,
            "business_date": manifest.business_date.isoformat(),
            "source_cut": manifest.source_cut,
            "dataset_version": manifest.dataset_version,
            "completed_at": manifest.completed_at.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "completion_revision": manifest.completion_revision,
            "publication_revision": manifest.publication_revision,
        },
    )


def _drop_readiness_row_policy(client: Client) -> None:
    client.command(  # pyright: ignore[reportUnknownMemberType]
        "DROP ROW POLICY IF EXISTS dfe_p05_readiness_head_visibility "
        "ON dfe_fixture.immutable_version_readiness"
    )


def _open_clickhouse_fixture_client(settings: ClickHouseConnectionSettings) -> Client:
    return clickhouse_connect.get_client(  # pyright: ignore[reportUnknownMemberType]
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
        client_name=settings.application_name,
        verify=True,
        tz_source="server",
        tz_mode="schema",
        show_clickhouse_errors="scrub",
        autogenerate_session_id=False,
        autogenerate_query_id=False,
        form_encode_query_params=True,
        native_codec="python",
    )
