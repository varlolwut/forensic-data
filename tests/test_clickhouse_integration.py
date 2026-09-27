from decimal import Decimal
from pathlib import Path

import clickhouse_connect
import pytest
from clickhouse_connect.driver.client import Client
from clickhouse_connect.driver.exceptions import DatabaseError

from forensic_data.acquisition import EarlyExecutionOutcome
from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    FieldSchema,
    Fingerprint,
    LogicalType,
    NoParameters,
    Normalization,
    encode_key,
    encode_row,
    envelope_sha256,
    schema_from_metadata_json,
)
from forensic_data.clickhouse import (
    ClickHouseConnectionSettings,
    ClickHouseDataValidationError,
    ClickHouseExactReadRequest,
    ClickHouseExactRow,
    ClickHouseResourceConstraint,
    ClickHouseResourceSetting,
    ClickHouseResultLimitError,
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
    inspect_clickhouse_canonical_relation,
    read_clickhouse_canonical_fingerprint,
    read_clickhouse_canonical_key_groups,
    read_clickhouse_canonical_rows,
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
    required_clickhouse_admin_settings,
    required_clickhouse_reader_settings,
    required_clickhouse_writer_settings,
    single_attempt_clickhouse_retry_policy,
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
    )
    try:
        profile = inspect_clickhouse_server_profile(transport, settings)
        assert profile.driver_name == "clickhouse-connect"
        assert profile.driver_version == "1.9.0"
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
            _resource_constraint(
                ClickHouseResourceSetting.MAX_EXECUTION_TIME,
                Decimal("30"),
                True,
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
        with pytest.raises(ClickHouseResultLimitError):
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
        assert transport.state is ClickHouseTransportState.LOST
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
    finally:
        admin.close_connections()


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
