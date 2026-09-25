from hashlib import sha256

import pytest

from forensic_data.greenplum import probe_greengage, probe_original_greenplum
from forensic_data.greenplum_catalog import (
    GreenplumColumnProbe,
    GreenplumDistributedHashPlan,
    GreenplumDistributedHashRow,
    GreenplumRelationProbeRequest,
    GreenplumTopology,
    GreenplumTypeProbe,
)
from forensic_data.greenplum_profile import GreenplumRuntimeProfile
from forensic_data.postgres import PostgresRetryPolicy
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


def test_original_greenplum_connector_catalog_types_and_hash_probe() -> None:
    settings = required_connection_settings(
        "DFE_TEST_ORIGINAL_GREENPLUM_READER_DSN",
        "dfe-phase04-original-greenplum-probe",
    )
    evidence = probe_original_greenplum(settings, _RETRY_POLICY, _CAPABILITY_REQUEST)

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
    assert evidence.reader.default_transaction_read_only
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


def test_greengage_connector_catalog_types_and_hash_probe() -> None:
    settings = required_connection_settings(
        "DFE_TEST_GREENGAGE_READER_DSN",
        "dfe-phase04-greengage-probe",
    )
    evidence = probe_greengage(settings, _RETRY_POLICY, _CAPABILITY_REQUEST)

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
