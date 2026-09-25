from contextlib import ExitStack
from hashlib import sha256
from typing import LiteralString, cast

import psycopg
import psycopg2
import pytest
from psycopg import pq
from psycopg.rows import tuple_row
from psycopg2.extensions import (
    TRANSACTION_STATUS_IDLE,
)
from psycopg2.extensions import (
    connection as Psycopg2Connection,
)
from psycopg2.extensions import (
    cursor as Psycopg2Cursor,
)

from forensic_data.canonical import Fingerprint, schema_from_metadata_json
from forensic_data.greenplum import (
    GreengageCanonicalRelationEvidence,
    GreenplumCanonicalReadContextEvidence,
    OriginalGreenplumCanonicalRelationEvidence,
    open_greengage_canonical_read_context,
    open_original_greenplum_canonical_read_context,
    probe_greengage,
    probe_greengage_canonical_fingerprints,
    probe_original_greenplum,
    probe_original_greenplum_canonical_fingerprints,
)
from forensic_data.greenplum_catalog import (
    GreenplumColumnProbe,
    GreenplumDistributedHashPlan,
    GreenplumDistributedHashRow,
    GreenplumRelationProbeRequest,
    GreenplumStorageKind,
    GreenplumStorageProfile,
    GreenplumTopology,
    GreenplumTypeProbe,
)
from forensic_data.greenplum_profile import GreenplumRuntimeProfile
from forensic_data.greenplum_sql import GreenplumCanonicalProbeRequest
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresRetryPolicy,
    ReadContextState,
)
from tests.canonical_vectors import vector_named
from tests.postgres_support import required_connection_settings

pytestmark = [pytest.mark.integration, pytest.mark.greenplum]

_CAPABILITY_REQUEST = GreenplumRelationProbeRequest(
    schema_name="dfe_fixture",
    relation_name="capability_types",
    columns=(
        GreenplumColumnProbe(field_name="record_id", column_name="record_id"),
        GreenplumColumnProbe(field_name="amount", column_name="amount"),
        GreenplumColumnProbe(field_name="active", column_name="active"),
        GreenplumColumnProbe(field_name="label", column_name="label"),
        GreenplumColumnProbe(field_name="business_date", column_name="business_date"),
        GreenplumColumnProbe(field_name="local_time", column_name="local_time"),
        GreenplumColumnProbe(field_name="instant_time", column_name="instant_time"),
    ),
    hash_record_id_column="record_id",
    hash_input_column="label",
    hash_row_limit=32,
)
_RETRY_POLICY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.1)
_CANONICAL_MULTIPLICITY = 32_768
_CANONICAL_VECTOR = vector_named("all_common_types")
_CANONICAL_SCHEMA = schema_from_metadata_json(_CANONICAL_VECTOR.metadata_json)
_CANONICAL_COLUMNS = tuple(
    GreenplumColumnProbe(field_name=field.name, column_name=field.name)
    for field in _CANONICAL_SCHEMA.fields
)
_CANONICAL_REQUESTS = tuple(
    GreenplumCanonicalProbeRequest(
        schema_name="dfe_fixture",
        relation_name=relation_name,
        columns=_CANONICAL_COLUMNS,
        schema=_CANONICAL_SCHEMA,
        max_encoded_envelope_bytes=4_096,
    )
    for relation_name in ("canonical_values", "canonical_empty_values")
)
_STORAGE_RELATION_NAMES = (
    "snapshot_heap_values",
    "snapshot_ao_values",
    "snapshot_aoco_values",
)
_STORAGE_REQUESTS = tuple(
    GreenplumCanonicalProbeRequest(
        schema_name="dfe_fixture",
        relation_name=relation_name,
        columns=_CANONICAL_COLUMNS,
        schema=_CANONICAL_SCHEMA,
        max_encoded_envelope_bytes=4_096,
    )
    for relation_name in _STORAGE_RELATION_NAMES
)
_STORAGE_MULTIPLICITY = 32
_EXPECTED_HEAP_STORAGE_PROFILE = GreenplumStorageProfile(
    kind=GreenplumStorageKind.HEAP,
    append_only_catalog_present=False,
    relation_options=(),
    block_size_bytes=None,
    compression_type=None,
    compression_level=None,
    checksum=None,
    column_store=None,
)
_EXPECTED_ORIGINAL_STORAGE_PROFILES = (
    _EXPECTED_HEAP_STORAGE_PROFILE,
    GreenplumStorageProfile(
        kind=GreenplumStorageKind.APPEND_OPTIMIZED_ROW,
        append_only_catalog_present=True,
        relation_options=(),
        block_size_bytes=32_768,
        compression_type="none",
        compression_level=0,
        checksum=True,
        column_store=False,
    ),
    GreenplumStorageProfile(
        kind=GreenplumStorageKind.APPEND_OPTIMIZED_COLUMN,
        append_only_catalog_present=True,
        relation_options=(),
        block_size_bytes=32_768,
        compression_type="none",
        compression_level=0,
        checksum=True,
        column_store=True,
    ),
)
_EXPECTED_GREENGAGE_AO_OPTIONS = (
    ("blocksize", "32768"),
    ("checksum", "true"),
    ("compresslevel", "0"),
    ("compresstype", "none"),
)
_EXPECTED_GREENGAGE_STORAGE_PROFILES = (
    _EXPECTED_HEAP_STORAGE_PROFILE,
    GreenplumStorageProfile(
        kind=GreenplumStorageKind.APPEND_OPTIMIZED_ROW,
        append_only_catalog_present=True,
        relation_options=_EXPECTED_GREENGAGE_AO_OPTIONS,
        block_size_bytes=32_768,
        compression_type="none",
        compression_level=0,
        checksum=True,
        column_store=False,
    ),
    GreenplumStorageProfile(
        kind=GreenplumStorageKind.APPEND_OPTIMIZED_COLUMN,
        append_only_catalog_present=True,
        relation_options=_EXPECTED_GREENGAGE_AO_OPTIONS,
        block_size_bytes=32_768,
        compression_type="none",
        compression_level=0,
        checksum=True,
        column_store=True,
    ),
)
_WRITER_DISTRIBUTION_ID = 33
_WRITER_ROW_PARAMETERS: tuple[int | str | bool, ...] = (
    _WRITER_DISTRIBUTION_ID,
    *_CANONICAL_VECTOR.values,
)
_WRITER_INSERT_STATEMENTS = tuple(
    (
        f"INSERT INTO dfe_fixture.{relation_name} ("
        "distribution_id, id, amount, active, label, business_date, local_time, instant_time"
        ") VALUES ("
        "%s::bigint, %s::bigint, %s::numeric(38, 3), %s::boolean, %s::text, "
        "%s::date, %s::timestamp(6) without time zone, "
        "%s::timestamp(6) with time zone)"
    )
    for relation_name in _STORAGE_RELATION_NAMES
)
_WRITER_DELETE_STATEMENTS = tuple(
    f"DELETE FROM dfe_fixture.{relation_name} WHERE distribution_id = %s::bigint"
    for relation_name in _STORAGE_RELATION_NAMES
)
_WRITER_STORAGE_COUNTS_QUERY = (
    "SELECT "
    "(SELECT count(*)::bigint FROM dfe_fixture.snapshot_heap_values), "
    "(SELECT count(*)::bigint FROM dfe_fixture.snapshot_ao_values), "
    "(SELECT count(*)::bigint FROM dfe_fixture.snapshot_aoco_values)"
)
_WRITER_PRIVILEGES_QUERY = (
    "SELECT current_user, "
    "pg_catalog.current_setting('default_transaction_read_only') = 'off', "
    "pg_catalog.current_setting('transaction_read_only') = 'off', "
    "pg_catalog.current_setting('transaction_isolation') = 'read committed', "
    "pg_catalog.has_database_privilege(current_user, current_database(), 'CONNECT'), "
    "NOT pg_catalog.has_database_privilege(current_user, current_database(), 'CREATE'), "
    "NOT pg_catalog.has_database_privilege(current_user, current_database(), 'TEMP'), "
    "pg_catalog.has_schema_privilege(current_user, 'dfe_fixture', 'USAGE'), "
    "NOT pg_catalog.has_schema_privilege(current_user, 'dfe_fixture', 'CREATE'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_heap_values', 'SELECT'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_heap_values', 'INSERT'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_heap_values', 'DELETE'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_heap_values', 'UPDATE'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_heap_values', 'TRUNCATE'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_ao_values', 'SELECT'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_ao_values', 'INSERT'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_ao_values', 'DELETE'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_ao_values', 'UPDATE'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_ao_values', 'TRUNCATE'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_aoco_values', 'SELECT'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_aoco_values', 'INSERT'), "
    "pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_aoco_values', 'DELETE'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_aoco_values', 'UPDATE'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.snapshot_aoco_values', 'TRUNCATE'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.capability_types', 'SELECT'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.canonical_values', 'SELECT'), "
    "NOT pg_catalog.has_table_privilege(current_user, "
    "'dfe_fixture.canonical_empty_values', 'SELECT')"
)


def test_original_greenplum_connector_catalog_types_and_hash_probe() -> None:
    settings = required_connection_settings(
        "DFE_TEST_ORIGINAL_GREENPLUM_READER_DSN",
        "dfe-phase04-original-greenplum-probe",
    )
    evidence = probe_original_greenplum(settings, _RETRY_POLICY, _CAPABILITY_REQUEST)
    canonical_evidence = probe_original_greenplum_canonical_fingerprints(
        settings,
        _RETRY_POLICY,
        _CANONICAL_REQUESTS,
    )

    assert evidence.driver.driver_name == "psycopg2"
    assert evidence.driver.driver_version == "2.9.13"
    assert evidence.driver.build_libpq_version == 170011
    assert evidence.driver.runtime_libpq_version == 170011
    assert evidence.server.runtime_profile is GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
    assert evidence.server.product_version == "4.3.99.00 build dev"
    assert evidence.server.compatibility_version == "8.3.23"
    assert evidence.server.compatibility_version_number == 80323
    assert "Greenplum Database 4.3.99.00 build dev" in evidence.server.full_version
    assert evidence.server.server_encoding == "UTF8"
    assert evidence.server.client_encoding == "UTF8"
    assert evidence.server.integer_datetimes
    assert evidence.server.timezone == "UTC"
    assert evidence.server.max_identifier_utf8_bytes == 63
    assert evidence.server.gp_role == "dispatch"
    assert evidence.server.gp_session_role == "dispatch"
    assert evidence.server.database_name == "dfe_fixture"
    assert evidence.server.backend_process_id > 0
    assert evidence.server.transaction_isolation == "read committed"
    assert evidence.server.transaction_read_only

    assert tuple(
        (
            segment.content_id,
            segment.role,
            segment.preferred_role,
            segment.status,
        )
        for segment in evidence.topology.segments
    ) == (
        (-1, "p", "p", "u"),
        (0, "m", "m", "u"),
        (0, "p", "p", "u"),
        (1, "m", "m", "u"),
        (1, "p", "p", "u"),
    )
    assert evidence.topology.primary_content_ids == (0, 1)

    assert evidence.reader.user_name == "dfe_original_greenplum_reader"
    assert not evidence.reader.is_superuser
    assert not evidence.reader.can_create_role
    assert not evidence.reader.can_create_database
    assert evidence.reader.can_login
    assert not evidence.reader.default_transaction_read_only
    assert evidence.reader.transaction_read_only

    assert evidence.relation.relation_oid > 0
    assert evidence.relation.relation_row_type_oid > 0
    assert evidence.relation.schema_name == "dfe_fixture"
    assert evidence.relation.relation_name == "capability_types"
    assert evidence.relation.relation_kind == "r"
    assert evidence.relation.storage_code == "h"
    assert evidence.relation.has_distribution_policy
    assert evidence.relation.distribution_attribute_numbers == (1,)
    assert evidence.relation.reader_has_select
    assert not evidence.relation.reader_has_insert
    assert not evidence.relation.reader_has_update
    assert not evidence.relation.reader_has_delete
    assert not evidence.relation.reader_has_truncate
    assert evidence.relation.reader_has_schema_usage
    _assert_capability_type_bindings(evidence.types)

    assert evidence.hash_capability.schema_name == "dfe_ext"
    assert evidence.hash_capability.function_name == "digest"
    assert evidence.hash_capability.function_oid > 0
    assert evidence.hash_capability.argument_type_oids == (17, 25)
    assert evidence.hash_capability.result_type_oid == 17
    assert evidence.hash_capability.volatility_code == "i"
    assert evidence.hash_capability.is_strict
    assert evidence.hash_capability.reader_has_execute
    assert evidence.hash_capability.reader_has_schema_usage
    assert evidence.hash_capability.selected_strategy == "unpackaged_contrib_sql"
    assert evidence.required_extensions == ()
    assert evidence.hash_plan.execution_locus == "seqscan_targetlist_below_motion"
    _assert_distributed_hash_evidence(
        evidence.topology,
        evidence.hash_plan,
        evidence.hash_rows,
    )
    assert canonical_evidence.topology == evidence.topology
    assert canonical_evidence.hash_capability == evidence.hash_capability
    assert canonical_evidence.planning_settings == ()
    assert canonical_evidence.required_extensions == ()
    _assert_canonical_evidence(
        canonical_evidence.topology,
        canonical_evidence.relations,
        "original_greenplum_cte_segment_aggregate_below_motion",
    )

    writer_settings = required_connection_settings(
        "DFE_TEST_ORIGINAL_GREENPLUM_WRITER_DSN",
        "dfe-phase04-original-greenplum-writer",
    )
    with ExitStack() as cleanup:
        writer = _connect_original_greenplum_writer(writer_settings)
        cleanup.callback(writer.close)
        _restore_original_greenplum_storage_fixture(writer)
        cleanup.callback(_restore_original_greenplum_storage_fixture, writer)
        _assert_original_greenplum_writer_privileges(writer)

        context = open_original_greenplum_canonical_read_context(
            settings,
            _RETRY_POLICY,
            _STORAGE_REQUESTS,
        )
        cleanup.callback(context.close)
        assert context.state is ReadContextState.ACTIVE
        assert context.driver == evidence.driver
        assert context.server.runtime_profile is GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
        assert context.server.transaction_isolation == "serializable"
        assert context.server.transaction_read_only
        assert context.reader == evidence.reader
        assert context.topology == evidence.topology
        assert context.hash_capability == evidence.hash_capability
        assert context.evidence.runtime_profile is GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
        assert context.evidence.strategy == "read_only_serializable"
        assert context.evidence.snapshot_locator == context.server.snapshot_locator
        assert context.evidence.snapshot_locator
        assert context.evidence.backend_process_id == context.server.backend_process_id
        assert context.evidence.backend_process_id > 0
        assert context.evidence.allowed_concurrency == 1
        assert context.evidence.planning_settings == ()
        assert context.evidence.limitations

        initial_relations = context.read_canonical_fingerprints()
        _assert_original_greenplum_storage_evidence(
            context.topology,
            initial_relations,
            _STORAGE_MULTIPLICITY,
        )
        _assert_storage_context_locks(context.evidence, initial_relations)

        _insert_original_greenplum_storage_writer_row(writer)
        _assert_original_greenplum_storage_counts(writer, _STORAGE_MULTIPLICITY + 1)
        stable_relations = context.read_canonical_fingerprints()
        assert stable_relations == initial_relations

        fresh_context = open_original_greenplum_canonical_read_context(
            settings,
            _RETRY_POLICY,
            _STORAGE_REQUESTS,
        )
        cleanup.callback(fresh_context.close)
        assert fresh_context.state is ReadContextState.ACTIVE
        assert fresh_context.evidence.context_id != context.evidence.context_id
        assert fresh_context.evidence.backend_process_id != context.evidence.backend_process_id
        assert fresh_context.server.transaction_isolation == "serializable"
        assert fresh_context.server.transaction_read_only
        fresh_relations = fresh_context.read_canonical_fingerprints()
        _assert_original_greenplum_storage_evidence(
            fresh_context.topology,
            fresh_relations,
            _STORAGE_MULTIPLICITY + 1,
        )
        _assert_storage_context_locks(fresh_context.evidence, fresh_relations)

        fresh_context.close()
        assert fresh_context.state is ReadContextState.CLOSED
        context.close()
        assert context.state is ReadContextState.CLOSED


def test_greengage_connector_catalog_types_and_hash_probe() -> None:
    settings = required_connection_settings(
        "DFE_TEST_GREENGAGE_READER_DSN",
        "dfe-phase04-greengage-probe",
    )
    evidence = probe_greengage(settings, _RETRY_POLICY, _CAPABILITY_REQUEST)
    canonical_evidence = probe_greengage_canonical_fingerprints(
        settings,
        _RETRY_POLICY,
        _CANONICAL_REQUESTS,
    )

    assert evidence.driver.driver_name == "psycopg"
    assert evidence.driver.driver_version == "3.3.6"
    assert evidence.driver.build_libpq_version == 170011
    assert evidence.driver.runtime_libpq_version == 170011
    assert evidence.server.runtime_profile is GreenplumRuntimeProfile.GREENGAGE
    assert (
        evidence.server.product_version
        == "7.5.0 build commit:677398e45766110a32e318266f186cf0cbe720a5"
    )
    assert evidence.server.compatibility_version == "12.22"
    assert evidence.server.compatibility_version_number == 120022
    assert (
        "Greengage Database "
        "7.5.0 build commit:677398e45766110a32e318266f186cf0cbe720a5"
        in evidence.server.full_version
    )
    assert evidence.server.server_encoding == "UTF8"
    assert evidence.server.client_encoding == "UTF8"
    assert evidence.server.integer_datetimes
    assert evidence.server.timezone == "UTC"
    assert evidence.server.max_identifier_utf8_bytes == 63
    assert evidence.server.gp_role == "dispatch"
    assert evidence.server.gp_session_role == "dispatch"
    assert evidence.server.database_name == "dfe_fixture"
    assert evidence.server.backend_process_id > 0
    assert evidence.server.transaction_isolation == "read committed"
    assert evidence.server.transaction_read_only

    assert tuple(
        (
            segment.content_id,
            segment.role,
            segment.preferred_role,
            segment.status,
        )
        for segment in evidence.topology.segments
    ) == (
        (-1, "p", "p", "u"),
        (0, "p", "p", "u"),
        (1, "p", "p", "u"),
    )
    assert evidence.topology.primary_content_ids == (0, 1)

    assert evidence.reader.user_name == "dfe_greengage_reader"
    assert not evidence.reader.is_superuser
    assert not evidence.reader.can_create_role
    assert not evidence.reader.can_create_database
    assert evidence.reader.can_login
    assert evidence.reader.default_transaction_read_only
    assert evidence.reader.transaction_read_only

    assert evidence.relation.relation_oid > 0
    assert evidence.relation.relation_row_type_oid > 0
    assert evidence.relation.schema_name == "dfe_fixture"
    assert evidence.relation.relation_name == "capability_types"
    assert evidence.relation.relation_kind == "r"
    assert evidence.relation.persistence_code == "p"
    assert not evidence.relation.row_security_enabled
    assert not evidence.relation.row_security_forced
    assert evidence.relation.access_method == "heap"
    assert not evidence.relation.is_append_optimized
    assert evidence.relation.has_distribution_policy
    assert evidence.relation.distribution_policy_type == "p"
    assert evidence.relation.distribution_segment_count == 2
    assert evidence.relation.distribution_attribute_numbers == (1,)
    assert evidence.relation.reader_has_select
    assert not evidence.relation.reader_has_insert
    assert not evidence.relation.reader_has_update
    assert not evidence.relation.reader_has_delete
    assert not evidence.relation.reader_has_truncate
    assert evidence.relation.reader_has_schema_usage
    _assert_capability_type_bindings(evidence.types)

    assert evidence.hash_capability.schema_name == "pg_catalog"
    assert evidence.hash_capability.function_name == "sha256"
    assert evidence.hash_capability.function_oid > 0
    assert evidence.hash_capability.argument_type_oids == (17,)
    assert evidence.hash_capability.result_type_oid == 17
    assert evidence.hash_capability.volatility_code == "i"
    assert evidence.hash_capability.is_strict
    assert evidence.hash_capability.reader_has_execute
    assert evidence.hash_capability.reader_has_schema_usage
    assert evidence.hash_capability.selected_strategy == "pg_catalog_builtin"
    assert evidence.required_extensions == ()
    assert evidence.hash_plan.execution_locus == "seqscan_output_below_motion"
    _assert_distributed_hash_evidence(
        evidence.topology,
        evidence.hash_plan,
        evidence.hash_rows,
    )
    assert canonical_evidence.topology == evidence.topology
    assert canonical_evidence.hash_capability == evidence.hash_capability
    assert tuple(
        (setting.name, setting.value) for setting in canonical_evidence.planning_settings
    ) == (
        ("optimizer", "off"),
        ("gp_enable_multiphase_agg", "on"),
        ("gp_eager_two_phase_agg", "on"),
    )
    assert canonical_evidence.required_extensions == ()
    assert all(
        not relation.relation.row_security_enabled and not relation.relation.row_security_forced
        for relation in canonical_evidence.relations
    )
    _assert_canonical_evidence(
        canonical_evidence.topology,
        canonical_evidence.relations,
        "greengage_cte_segment_aggregate_below_motion",
    )

    writer_settings = required_connection_settings(
        "DFE_TEST_GREENGAGE_WRITER_DSN",
        "dfe-phase04-greengage-writer",
    )
    with ExitStack() as cleanup:
        writer = _connect_greengage_writer(writer_settings)
        cleanup.callback(writer.close)
        _restore_greengage_storage_fixture(writer)
        cleanup.callback(_restore_greengage_storage_fixture, writer)
        _assert_greengage_writer_privileges(writer)

        context = open_greengage_canonical_read_context(
            settings,
            _RETRY_POLICY,
            _STORAGE_REQUESTS,
        )
        cleanup.callback(context.close)
        assert context.state is ReadContextState.ACTIVE
        assert context.driver == evidence.driver
        assert context.server.runtime_profile is GreenplumRuntimeProfile.GREENGAGE
        assert context.server.transaction_isolation == "repeatable read"
        assert context.server.transaction_read_only
        assert context.reader == evidence.reader
        assert context.topology == evidence.topology
        assert context.hash_capability == evidence.hash_capability
        assert context.evidence.runtime_profile is GreenplumRuntimeProfile.GREENGAGE
        assert context.evidence.strategy == "read_only_repeatable_read"
        assert context.evidence.snapshot_locator == context.server.snapshot_locator
        assert context.evidence.snapshot_locator
        assert context.evidence.backend_process_id == context.server.backend_process_id
        assert context.evidence.backend_process_id > 0
        assert context.evidence.allowed_concurrency == 1
        assert tuple(
            (setting.name, setting.value) for setting in context.evidence.planning_settings
        ) == (
            ("optimizer", "off"),
            ("gp_enable_multiphase_agg", "on"),
            ("gp_eager_two_phase_agg", "on"),
        )
        assert context.evidence.limitations

        initial_relations = context.read_canonical_fingerprints()
        _assert_greengage_storage_evidence(
            context.topology,
            initial_relations,
            _STORAGE_MULTIPLICITY,
        )
        _assert_storage_context_locks(context.evidence, initial_relations)

        _insert_greengage_storage_writer_row(writer)
        _assert_greengage_storage_counts(writer, _STORAGE_MULTIPLICITY + 1)
        stable_relations = context.read_canonical_fingerprints()
        assert stable_relations == initial_relations

        fresh_context = open_greengage_canonical_read_context(
            settings,
            _RETRY_POLICY,
            _STORAGE_REQUESTS,
        )
        cleanup.callback(fresh_context.close)
        assert fresh_context.state is ReadContextState.ACTIVE
        assert fresh_context.evidence.context_id != context.evidence.context_id
        assert fresh_context.evidence.backend_process_id != context.evidence.backend_process_id
        assert fresh_context.server.transaction_isolation == "repeatable read"
        assert fresh_context.server.transaction_read_only
        fresh_relations = fresh_context.read_canonical_fingerprints()
        _assert_greengage_storage_evidence(
            fresh_context.topology,
            fresh_relations,
            _STORAGE_MULTIPLICITY + 1,
        )
        _assert_storage_context_locks(fresh_context.evidence, fresh_relations)

        fresh_context.close()
        assert fresh_context.state is ReadContextState.CLOSED
        context.close()
        assert context.state is ReadContextState.CLOSED


def _assert_capability_type_bindings(probe: GreenplumTypeProbe) -> None:
    bindings = probe.bindings
    assert tuple(binding.field_name for binding in bindings) == (
        "record_id",
        "amount",
        "active",
        "label",
        "business_date",
        "local_time",
        "instant_time",
    )
    assert tuple(binding.column_name for binding in bindings) == (
        "record_id",
        "amount",
        "active",
        "label",
        "business_date",
        "local_time",
        "instant_time",
    )
    assert "ignored_payload" not in tuple(binding.column_name for binding in bindings)
    assert tuple(binding.physical.formatted_type for binding in bindings) == (
        "bigint",
        "numeric(38,4)",
        "boolean",
        "text",
        "date",
        "timestamp(6) without time zone",
        "timestamp(6) with time zone",
    )
    assert tuple(binding.physical.base_type.type_name for binding in bindings) == (
        "int8",
        "numeric",
        "bool",
        "text",
        "date",
        "timestamp",
        "timestamptz",
    )
    assert tuple(binding.physical.base_type.oid for binding in bindings) == (
        20,
        1700,
        16,
        25,
        1082,
        1114,
        1184,
    )
    assert tuple(binding.physical.numeric_precision for binding in bindings) == (
        64,
        38,
        None,
        None,
        None,
        None,
        None,
    )
    assert tuple(binding.physical.numeric_scale for binding in bindings) == (
        0,
        4,
        None,
        None,
        None,
        None,
        None,
    )
    assert all(binding.physical.declared_type == binding.physical.base_type for binding in bindings)
    assert all(binding.physical.base_type.schema_name == "pg_catalog" for binding in bindings)
    assert all(not binding.physical.is_domain for binding in bindings)
    assert all(binding.physical.array_dimensions == 0 for binding in bindings)


def _assert_distributed_hash_evidence(
    topology: GreenplumTopology,
    plan: GreenplumDistributedHashPlan,
    rows: tuple[GreenplumDistributedHashRow, ...],
) -> None:
    assert plan.lines
    assert plan.scanned_relation == "dfe_fixture.capability_types"
    assert plan.dispatched_primary_count == len(topology.primary_content_ids)
    assert plan.row_dependent_input_column == "label"
    assert any("scan" in line.lower() and "capability_types" in line.lower() for line in plan.lines)
    assert any(
        "motion" in line.lower()
        and f"segments: {len(topology.primary_content_ids)}" in line.lower()
        for line in plan.lines
    )

    assert len(rows) == 32
    assert tuple(sorted(row.record_id for row in rows)) == tuple(range(1, 33))
    assert tuple(sorted({row.segment_id for row in rows})) == topology.primary_content_ids
    for row in rows:
        assert row.input_text == f"segment-hash-{row.record_id}"
        assert row.digest == sha256(row.input_text.encode("utf-8")).digest()


def _assert_canonical_evidence(
    topology: GreenplumTopology,
    relations: tuple[OriginalGreenplumCanonicalRelationEvidence, ...]
    | tuple[GreengageCanonicalRelationEvidence, ...],
    expected_execution_locus: str,
) -> None:
    assert len(relations) == 2
    values_relation, empty_relation = relations
    assert values_relation.relation.relation_name == "canonical_values"
    assert empty_relation.relation.relation_name == "canonical_empty_values"
    _assert_canonical_relation(
        topology,
        values_relation,
        _expected_repeated_golden_fingerprint(_CANONICAL_MULTIPLICITY),
        len(topology.primary_content_ids),
        expected_execution_locus,
    )
    _assert_canonical_relation(
        topology,
        empty_relation,
        Fingerprint(count=0, limb_sums=(0, 0, 0, 0, 0, 0, 0, 0)),
        0,
        expected_execution_locus,
    )


def _assert_original_greenplum_storage_evidence(
    topology: GreenplumTopology,
    relations: tuple[OriginalGreenplumCanonicalRelationEvidence, ...],
    multiplicity: int,
) -> None:
    assert tuple(relation.relation.relation_name for relation in relations) == (
        _STORAGE_RELATION_NAMES
    )
    assert tuple(relation.relation.storage_code for relation in relations) == (
        "h",
        "a",
        "c",
    )
    assert tuple(relation.relation.storage_profile for relation in relations) == (
        _EXPECTED_ORIGINAL_STORAGE_PROFILES
    )
    _assert_storage_fingerprints(
        topology,
        relations,
        multiplicity,
        "original_greenplum_cte_segment_aggregate_below_motion",
    )


def _assert_greengage_storage_evidence(
    topology: GreenplumTopology,
    relations: tuple[GreengageCanonicalRelationEvidence, ...],
    multiplicity: int,
) -> None:
    assert tuple(relation.relation.relation_name for relation in relations) == (
        _STORAGE_RELATION_NAMES
    )
    assert tuple(relation.relation.access_method for relation in relations) == (
        "heap",
        "ao_row",
        "ao_column",
    )
    assert tuple(relation.relation.is_append_optimized for relation in relations) == (
        False,
        True,
        True,
    )
    assert tuple(relation.relation.storage_profile for relation in relations) == (
        _EXPECTED_GREENGAGE_STORAGE_PROFILES
    )
    _assert_storage_fingerprints(
        topology,
        relations,
        multiplicity,
        "greengage_cte_segment_aggregate_below_motion",
    )


def _assert_storage_fingerprints(
    topology: GreenplumTopology,
    relations: tuple[OriginalGreenplumCanonicalRelationEvidence, ...]
    | tuple[GreengageCanonicalRelationEvidence, ...],
    multiplicity: int,
    expected_execution_locus: str,
) -> None:
    assert len(relations) == len(_STORAGE_RELATION_NAMES)
    expected = _expected_repeated_golden_fingerprint(multiplicity)
    for relation in relations:
        _assert_canonical_relation(
            topology,
            relation,
            expected,
            len(topology.primary_content_ids),
            expected_execution_locus,
        )


def _assert_storage_context_locks(
    evidence: GreenplumCanonicalReadContextEvidence,
    relations: tuple[OriginalGreenplumCanonicalRelationEvidence, ...]
    | tuple[GreengageCanonicalRelationEvidence, ...],
) -> None:
    assert evidence.acquired_before_snapshot
    assert len(evidence.relation_locks) == len(_STORAGE_RELATION_NAMES)
    actual_oids: dict[str, int] = {}
    for lock in evidence.relation_locks:
        assert lock.schema_name == "dfe_fixture"
        assert lock.relation_name in _STORAGE_RELATION_NAMES
        assert lock.relation_oid > 0
        assert lock.lock_mode == "AccessShareLock"
        assert lock.relation_name not in actual_oids
        actual_oids[lock.relation_name] = lock.relation_oid
    assert actual_oids == {
        relation.relation.relation_name: relation.relation.relation_oid for relation in relations
    }


def _assert_canonical_relation(
    topology: GreenplumTopology,
    evidence: OriginalGreenplumCanonicalRelationEvidence | GreengageCanonicalRelationEvidence,
    expected_fingerprint: Fingerprint,
    expected_observed_segment_count: int,
    expected_execution_locus: str,
) -> None:
    relation = evidence.relation
    assert relation.relation_oid > 0
    assert relation.relation_row_type_oid > 0
    assert relation.schema_name == "dfe_fixture"
    assert relation.relation_kind == "r"
    assert relation.has_distribution_policy
    assert relation.distribution_attribute_numbers == (1,)
    assert relation.reader_has_select
    assert not relation.reader_has_insert
    assert not relation.reader_has_update
    assert not relation.reader_has_delete
    assert not relation.reader_has_truncate
    assert relation.reader_has_schema_usage
    _assert_canonical_type_bindings(evidence.types)

    assert evidence.query.context.schema is _CANONICAL_SCHEMA
    assert evidence.query.context.schema_digest_hex == _CANONICAL_VECTOR.schema_digest_hex
    assert evidence.query.relation_row_type_oid == relation.relation_row_type_oid
    assert evidence.query.relation_name == f"dfe_fixture.{relation.relation_name}"
    assert evidence.query.primary_content_ids == topology.primary_content_ids

    assert evidence.plan.lines
    assert evidence.plan.scanned_relation == evidence.query.relation_name
    assert evidence.plan.dispatched_primary_count == len(topology.primary_content_ids)
    assert evidence.plan.topology_seeded
    assert evidence.plan.execution_locus == expected_execution_locus
    assert any("append" in line.lower() for line in evidence.plan.lines)
    assert any("scan" in line.lower() and "gp_id" in line.lower() for line in evidence.plan.lines)
    assert any(
        "motion" in line.lower()
        and f"segments: {len(topology.primary_content_ids)}" in line.lower()
        for line in evidence.plan.lines
    )
    assert any(
        "scan" in line.lower() and relation.relation_name in line.lower()
        for line in evidence.plan.lines
    )

    fingerprint = evidence.fingerprint
    assert fingerprint.relation_row_type_oid == relation.relation_row_type_oid
    assert fingerprint.fingerprint == expected_fingerprint
    assert fingerprint.invalid_row_count == 0
    assert fingerprint.oversized_row_count == 0
    assert fingerprint.topology_content_ids == topology.primary_content_ids
    assert len(fingerprint.observed_content_ids) == expected_observed_segment_count
    assert frozenset(fingerprint.observed_content_ids).issubset(fingerprint.topology_content_ids)


def _assert_canonical_type_bindings(probe: GreenplumTypeProbe) -> None:
    bindings = probe.bindings
    assert tuple(binding.field_name for binding in bindings) == tuple(
        field.name for field in _CANONICAL_SCHEMA.fields
    )
    assert tuple(binding.column_name for binding in bindings) == tuple(
        field.name for field in _CANONICAL_SCHEMA.fields
    )
    assert "distribution_id" not in tuple(binding.column_name for binding in bindings)
    assert tuple(binding.physical.formatted_type for binding in bindings) == (
        "bigint",
        "numeric(38,3)",
        "boolean",
        "text",
        "date",
        "timestamp(6) without time zone",
        "timestamp(6) with time zone",
    )
    assert bindings[1].physical.numeric_precision == 38
    assert bindings[1].physical.numeric_scale == 3
    assert all(binding.physical.declared_type == binding.physical.base_type for binding in bindings)
    assert all(binding.physical.base_type.schema_name == "pg_catalog" for binding in bindings)
    assert all(not binding.physical.is_domain for binding in bindings)
    assert all(binding.physical.array_dimensions == 0 for binding in bindings)


def _expected_repeated_golden_fingerprint(multiplicity: int) -> Fingerprint:
    limbs = _CANONICAL_VECTOR.limbs
    return Fingerprint(
        count=multiplicity,
        limb_sums=(
            multiplicity * limbs[0],
            multiplicity * limbs[1],
            multiplicity * limbs[2],
            multiplicity * limbs[3],
            multiplicity * limbs[4],
            multiplicity * limbs[5],
            multiplicity * limbs[6],
            multiplicity * limbs[7],
        ),
    )


def _connect_original_greenplum_writer(
    settings: PostgresConnectionSettings,
) -> Psycopg2Connection:
    connection = psycopg2.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password.get_secret_value(),
        sslmode=settings.sslmode.value,
        connect_timeout=settings.connect_timeout_seconds,
        application_name=settings.application_name,
    )
    connection.autocommit = False
    return connection


def _connect_greengage_writer(
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
        autocommit=False,
        row_factory=tuple_row,
    )


def _assert_original_greenplum_writer_privileges(
    connection: Psycopg2Connection,
) -> None:
    _require_original_greenplum_writer_idle(connection)
    try:
        with connection.cursor() as cursor:
            _configure_original_greenplum_writer_transaction(cursor)
            cursor.execute(_WRITER_PRIVILEGES_QUERY)
            row = cursor.fetchone()
            _assert_writer_privilege_row(row, "dfe_original_greenplum_writer")
        connection.commit()
    except (psycopg2.Error, AssertionError):
        connection.rollback()
        raise
    _require_original_greenplum_writer_idle(connection)


def _assert_greengage_writer_privileges(
    connection: psycopg.Connection[DatabaseRow],
) -> None:
    _require_greengage_writer_idle(connection)
    try:
        with connection.cursor() as cursor:
            _configure_greengage_writer_transaction(cursor)
            cursor.execute(_WRITER_PRIVILEGES_QUERY)
            row = cursor.fetchone()
            _assert_writer_privilege_row(row, "dfe_greengage_writer")
        connection.commit()
    except (psycopg.Error, AssertionError):
        connection.rollback()
        raise
    _require_greengage_writer_idle(connection)


def _restore_original_greenplum_storage_fixture(
    connection: Psycopg2Connection,
) -> None:
    _require_original_greenplum_writer_idle(connection)
    try:
        with connection.cursor() as cursor:
            _configure_original_greenplum_writer_transaction(cursor)
            for statement in _WRITER_DELETE_STATEMENTS:
                cursor.execute(statement, (_WRITER_DISTRIBUTION_ID,))
        connection.commit()
    except psycopg2.Error:
        connection.rollback()
        raise
    _require_original_greenplum_writer_idle(connection)
    _assert_original_greenplum_storage_counts(connection, _STORAGE_MULTIPLICITY)


def _restore_greengage_storage_fixture(
    connection: psycopg.Connection[DatabaseRow],
) -> None:
    _require_greengage_writer_idle(connection)
    try:
        with connection.cursor() as cursor:
            _configure_greengage_writer_transaction(cursor)
            for statement in _WRITER_DELETE_STATEMENTS:
                cursor.execute(
                    cast(LiteralString, statement),
                    (_WRITER_DISTRIBUTION_ID,),
                )
        connection.commit()
    except psycopg.Error:
        connection.rollback()
        raise
    _require_greengage_writer_idle(connection)
    _assert_greengage_storage_counts(connection, _STORAGE_MULTIPLICITY)


def _insert_original_greenplum_storage_writer_row(
    connection: Psycopg2Connection,
) -> None:
    _require_original_greenplum_writer_idle(connection)
    try:
        with connection.cursor() as cursor:
            _configure_original_greenplum_writer_transaction(cursor)
            for statement in _WRITER_INSERT_STATEMENTS:
                cursor.execute(statement, _WRITER_ROW_PARAMETERS)
                assert cursor.rowcount == 1
        connection.commit()
    except (psycopg2.Error, AssertionError):
        connection.rollback()
        raise
    _require_original_greenplum_writer_idle(connection)


def _insert_greengage_storage_writer_row(
    connection: psycopg.Connection[DatabaseRow],
) -> None:
    _require_greengage_writer_idle(connection)
    try:
        with connection.cursor() as cursor:
            _configure_greengage_writer_transaction(cursor)
            for statement in _WRITER_INSERT_STATEMENTS:
                cursor.execute(cast(LiteralString, statement), _WRITER_ROW_PARAMETERS)
                assert cursor.rowcount == 1
        connection.commit()
    except (psycopg.Error, AssertionError):
        connection.rollback()
        raise
    _require_greengage_writer_idle(connection)


def _assert_original_greenplum_storage_counts(
    connection: Psycopg2Connection,
    expected_count: int,
) -> None:
    _require_original_greenplum_writer_idle(connection)
    try:
        with connection.cursor() as cursor:
            _configure_original_greenplum_writer_transaction(cursor)
            cursor.execute(_WRITER_STORAGE_COUNTS_QUERY)
            row = cursor.fetchone()
            _assert_storage_count_row(row, expected_count)
        connection.commit()
    except (psycopg2.Error, AssertionError):
        connection.rollback()
        raise
    _require_original_greenplum_writer_idle(connection)


def _assert_greengage_storage_counts(
    connection: psycopg.Connection[DatabaseRow],
    expected_count: int,
) -> None:
    _require_greengage_writer_idle(connection)
    try:
        with connection.cursor() as cursor:
            _configure_greengage_writer_transaction(cursor)
            cursor.execute(_WRITER_STORAGE_COUNTS_QUERY)
            row = cursor.fetchone()
            _assert_storage_count_row(row, expected_count)
        connection.commit()
    except (psycopg.Error, AssertionError):
        connection.rollback()
        raise
    _require_greengage_writer_idle(connection)


def _configure_original_greenplum_writer_transaction(cursor: Psycopg2Cursor) -> None:
    cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
    cursor.execute("SET LOCAL statement_timeout = '5000ms'")


def _configure_greengage_writer_transaction(cursor: psycopg.Cursor[DatabaseRow]) -> None:
    cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ WRITE")
    cursor.execute("SET LOCAL statement_timeout = '5000ms'")


def _assert_writer_privilege_row(row: object, expected_user: str) -> None:
    if type(row) is not tuple:
        raise AssertionError("Greenplum writer privilege query must return one tuple row")
    values = cast(tuple[object, ...], row)
    assert len(values) == 27
    assert values[0] == expected_user
    assert all(value is True for value in values[1:])


def _assert_storage_count_row(row: object, expected_count: int) -> None:
    if type(row) is not tuple:
        raise AssertionError("Greenplum writer count query must return one tuple row")
    values = cast(tuple[object, ...], row)
    assert values == (expected_count, expected_count, expected_count)


def _require_original_greenplum_writer_idle(connection: Psycopg2Connection) -> None:
    assert connection.get_transaction_status() == TRANSACTION_STATUS_IDLE


def _require_greengage_writer_idle(
    connection: psycopg.Connection[DatabaseRow],
) -> None:
    assert connection.info.transaction_status is pq.TransactionStatus.IDLE
