from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest

from forensic_data.application import (
    DiffRequest,
    ExecuteCheckRequest,
    PostgresExecutionServices,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    read_diff,
)
from forensic_data.contracts import load_contract_config
from forensic_data.persistence.postgres import migrate_postgres_metadata
from forensic_data.postgres import PostgresRetryPolicy
from forensic_data.reporting import DetailAvailability
from forensic_data.result import ExecutionStatus, Guarantee, Verdict
from tests.metadata_postgres_support import (
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.postgres_support import connect_writer, required_connection_settings

pytestmark = [pytest.mark.integration, pytest.mark.postgres]

_CONTRACT_PATH = Path(__file__).parent / "fixtures/postgres-legacy/contract.yaml"
_REFERENCE_BATCH = "legacy-reference-2026-09-23"
_TARGET_BATCH = "legacy-target-2026-09-23"
_NO_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)


def test_postgres_9_6_source_to_postgres_17_target_is_exact_and_persisted() -> None:
    metadata_request = required_metadata_database_settings()
    reference = required_connection_settings(
        "DFE_TEST_POSTGRES_LEGACY_SOURCE_DSN",
        "forensic-data-legacy-reference",
    )
    target = required_connection_settings(
        "DFE_TEST_POSTGRES_LEGACY_TARGET_DSN",
        "forensic-data-legacy-target",
    )

    with disposable_metadata_database(metadata_request) as metadata:
        migrate_postgres_metadata(metadata.migrator, _NO_RETRY, 5_000)
        config = load_contract_config(_CONTRACT_PATH)
        check = config.checks[0]
        result = execute_check(
            config,
            ExecuteCheckRequest(
                request_id=uuid4(),
                check_id=check.check_id,
                scope_values=(ScopeValue(name="business_date", value="2026-09-23"),),
                reference_expected_batch_id=_REFERENCE_BATCH,
                target_expected_batch_id=_TARGET_BATCH,
                origin="legacy-postgres-integration",
            ),
            PostgresExecutionServices(
                reference_connection_id=check.reference.connection.connection_id,
                reference_settings=reference,
                target_connection_id=check.target.connection.connection_id,
                target_settings=target,
                metadata_connection_id=config.metadata.connection.connection_id,
                metadata_settings=metadata.writer,
                source_retry_policy=_NO_RETRY,
                metadata_retry_policy=_NO_RETRY,
                protected_lock_timeout_milliseconds=2_000,
                metadata_record_bytes=4_096,
                metadata_total_bytes=32_768,
            ),
        )

        assert result.execution_status is ExecutionStatus.COMPLETED, result.model_dump_json(
            indent=2
        )
        assert result.verdict is Verdict.MISMATCH
        assert result.guarantee is Guarantee.EXACT
        assert tuple(
            (total.precision, total.value)
            for total in (
                result.totals.matched,
                result.totals.missing,
                result.totals.extra,
                result.totals.modified,
            )
        ) == (("exact", "1"), ("exact", "1"), ("exact", "1"), ("exact", "1"))
        assert result.evidence_coverage.found_records == 3
        assert result.evidence_coverage.retained_records == 3

        page = read_diff(
            DiffRequest(
                run_id=result.run_id,
                attempt_id=result.attempt_id,
                limit=10,
                cursor=None,
            ),
            PostgresMetadataServices(
                connection_id=config.metadata.connection.connection_id,
                settings=metadata.reader,
                retry_policy=_NO_RETRY,
            ),
        )
        assert page.detail_availability is DetailAvailability.AVAILABLE
        assert len(page.details) == 3
        assert all(detail.omitted_field_names == ("business_date",) for detail in page.details)
        assert all(
            tuple(value.field_name for value in detail.key_values) == ("order_id",)
            for detail in page.details
        )
        details_by_key = {detail.key_values[0].canonical_text: detail for detail in page.details}
        assert set(details_by_key) == {"1002", "1003", "1004"}

        modified = details_by_key["1002"]
        assert modified.kind.value == "modified"
        assert tuple(value.field_name for value in modified.reference_values) == ("amount",)
        assert tuple(value.canonical_text for value in modified.reference_values) == ("20.00",)
        assert tuple(value.field_name for value in modified.target_values) == ("amount",)
        assert tuple(value.canonical_text for value in modified.target_values) == ("20.25",)

        missing = details_by_key["1003"]
        assert missing.kind.value == "missing"
        assert tuple(value.field_name for value in missing.reference_values) == ("amount",)
        assert tuple(value.canonical_text for value in missing.reference_values) == ("30.00",)
        assert missing.target_values == ()

        extra = details_by_key["1004"]
        assert extra.kind.value == "extra"
        assert extra.reference_values == ()
        assert tuple(value.field_name for value in extra.target_values) == ("amount",)
        assert tuple(value.canonical_text for value in extra.target_values) == ("40.00",)

        with connect_writer(metadata.reader) as connection:
            contexts = connection.execute(
                "SELECT direction, driver_version, server_version_number, state "
                "FROM dfe_metadata.attempt_read_contexts "
                "WHERE run_id = %s AND attempt_id = %s ORDER BY direction",
                (result.run_id, result.attempt_id),
            ).fetchall()
            numeric_difference = connection.execute(
                "SELECT anomaly_kind, field_name, reference_value, target_value, "
                "target_minus_reference FROM dfe_metadata.numeric_differences "
                "WHERE run_id = %s AND attempt_id = %s "
                "AND anomaly_kind = 'modified' AND field_name = 'amount'",
                (result.run_id, result.attempt_id),
            ).fetchone()

        assert tuple((row[0], str(row[1]).split()[0], row[2], row[3]) for row in contexts) == (
            ("reference", "2.9.13", 90_624, "closed"),
            ("target", "3.3.6", 170_011, "closed"),
        )
        assert numeric_difference == (
            "modified",
            "amount",
            Decimal("20.00"),
            Decimal("20.25"),
            Decimal("0.25"),
        )
