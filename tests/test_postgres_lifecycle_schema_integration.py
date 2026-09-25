import hashlib
from pathlib import Path
from typing import Literal, LiteralString, cast
from uuid import UUID, uuid4

import psycopg
import pytest

from forensic_data.contracts import load_contract_config
from forensic_data.contracts.semantics import (
    SemanticValue,
    canonical_semantic_json,
    semantic_digest_hex,
)
from forensic_data.persistence.definitions import build_metadata_registration_definition
from forensic_data.persistence.errors import MetadataMigrationApplyError
from forensic_data.persistence.migrations import load_postgres_metadata_migrations
from forensic_data.persistence.model import MetadataRegistration, Migration
from forensic_data.persistence.postgres import (
    migrate_postgres_metadata,
    register_postgres_metadata,
)
from forensic_data.postgres import DatabaseRow, PostgresRetryPolicy
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.postgres_support import connect_writer

_EXAMPLE_CONTRACT = (
    Path(__file__).parent.parent / "examples/postgres-relation-manifest/contract.yaml"
)
_RETRY_POLICY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)
_DIGEST_BYTES = bytes.fromhex("11" * 32)


@pytest.mark.integration
@pytest.mark.postgres
def test_lifecycle_schema_enforces_aggregate_closure_and_least_privilege() -> None:
    requested = required_metadata_database_settings()
    with disposable_metadata_database(requested) as settings:
        migration_report = migrate_postgres_metadata(settings.migrator, _RETRY_POLICY, 5_000)
        assert migration_report.applied_versions == (1, 2, 3, 4, 5, 6, 7)
        assert migration_report.current_version == 7
        assert (
            migrate_postgres_metadata(
                settings.migrator,
                _RETRY_POLICY,
                5_000,
            ).applied_versions
            == ()
        )

        registration = _register_relation_manifest_metadata(settings)
        run_id = uuid4()
        attempt_id = uuid4()
        reference_context_id = uuid4()
        target_context_id = uuid4()
        scope_payload = _scope_payload()
        scope_digest = bytes.fromhex(semantic_digest_hex(scope_payload))
        budgets_payload = _execution_budgets_payload()
        request_payload = _request_payload(registration, scope_payload, budgets_payload)
        request_digest = hashlib.sha256(request_payload.encode("utf-8")).digest()
        input_cut_payload = _input_cut_payload(registration, scope_digest.hex())
        input_cut_digest = bytes.fromhex(semantic_digest_hex(input_cut_payload))

        with connect_writer(settings.writer) as connection:
            connection.execute("SET ROLE dfe_metadata_writer")
            _insert_run(
                connection,
                run_id,
                registration.contract.contract_version_id,
                request_digest,
                request_payload,
                scope_digest,
            )

            with pytest.raises(psycopg.errors.CheckViolation):
                connection.execute(
                    "INSERT INTO dfe_metadata.runs ("
                    "run_id, creation_operation_id, request_id, request_identity_digest, "
                    "request_payload, contract_version_id, origin, scope_digest"
                    ") VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s)",
                    (
                        uuid4(),
                        uuid4(),
                        uuid4(),
                        _DIGEST_BYTES,
                        request_payload,
                        registration.contract.contract_version_id,
                        "integration_test",
                        b"short",
                    ),
                )

            _insert_attempt(connection, attempt_id, run_id, 1, budgets_payload)
            with pytest.raises(psycopg.errors.UniqueViolation):
                _insert_attempt(connection, uuid4(), run_id, 2, budgets_payload)

            _insert_context(
                connection,
                reference_context_id,
                run_id,
                attempt_id,
                registration.reference_dataset.dataset_version_id,
                "reference",
                scope_digest,
            )
            _insert_context(
                connection,
                target_context_id,
                run_id,
                attempt_id,
                registration.target_dataset.dataset_version_id,
                "target",
                scope_digest,
            )

            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                _insert_observation(
                    connection,
                    run_id,
                    attempt_id,
                    reference_context_id,
                    registration.target_dataset.dataset_version_id,
                    "target",
                    scope_digest,
                    input_cut_digest,
                    input_cut_payload,
                    None,
                    "relation_manifest",
                )

            with pytest.raises(psycopg.errors.CheckViolation):
                _insert_observation(
                    connection,
                    run_id,
                    attempt_id,
                    reference_context_id,
                    registration.reference_dataset.dataset_version_id,
                    "reference",
                    scope_digest,
                    input_cut_digest,
                    input_cut_payload,
                    uuid4(),
                    "relation_manifest",
                )

            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                _insert_observation(
                    connection,
                    run_id,
                    attempt_id,
                    reference_context_id,
                    registration.reference_dataset.dataset_version_id,
                    "reference",
                    scope_digest,
                    input_cut_digest,
                    input_cut_payload,
                    uuid4(),
                    "sql",
                )

            _insert_observation(
                connection,
                run_id,
                attempt_id,
                reference_context_id,
                registration.reference_dataset.dataset_version_id,
                "reference",
                scope_digest,
                input_cut_digest,
                input_cut_payload,
                None,
                "relation_manifest",
            )
            _insert_observation(
                connection,
                run_id,
                attempt_id,
                target_context_id,
                registration.target_dataset.dataset_version_id,
                "target",
                scope_digest,
                input_cut_digest,
                input_cut_payload,
                None,
                "relation_manifest",
            )

            with pytest.raises(psycopg.errors.CheckViolation):
                connection.execute(
                    "UPDATE dfe_metadata.runs SET bound_input_cut_digest = %s WHERE run_id = %s",
                    (input_cut_digest, run_id),
                )

            cut_operation_id = uuid4()
            input_cut_json = canonical_semantic_json(input_cut_payload)
            connection.execute(
                "UPDATE dfe_metadata.run_attempts SET "
                "input_cut_digest = %s, cut_operation_id = %s, "
                "cut_observed_at = CURRENT_TIMESTAMP "
                "WHERE attempt_id = %s",
                (input_cut_digest, cut_operation_id, attempt_id),
            )
            connection.execute(
                "UPDATE dfe_metadata.runs SET "
                "bound_input_cut_digest = %s, bound_input_cut_payload = %s::jsonb, "
                "cut_binding_operation_id = %s, cut_bound_at = CURRENT_TIMESTAMP "
                "WHERE run_id = %s",
                (input_cut_digest, input_cut_json, cut_operation_id, run_id),
            )

            _close_context(connection, reference_context_id)
            _close_context(connection, target_context_id)
            terminal_operation_id = uuid4()
            connection.execute(
                "UPDATE dfe_metadata.run_attempts SET "
                "status = 'incomplete', end_operation_id = %s, "
                "terminal_reason_code = 'cut_mismatch', terminal_reason = %s::jsonb, "
                "ended_at = CURRENT_TIMESTAMP WHERE attempt_id = %s",
                (terminal_operation_id, _terminal_reason_payload(), attempt_id),
            )

            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                connection.execute(
                    "UPDATE dfe_metadata.runs SET "
                    "selected_terminal_attempt_id = %s, terminal_operation_id = %s, "
                    "terminal_at = CURRENT_TIMESTAMP WHERE run_id = %s",
                    (uuid4(), uuid4(), run_id),
                )

            connection.execute(
                "UPDATE dfe_metadata.runs SET "
                "selected_terminal_attempt_id = %s, terminal_operation_id = %s, "
                "terminal_at = CURRENT_TIMESTAMP WHERE run_id = %s",
                (attempt_id, terminal_operation_id, run_id),
            )

            _assert_privilege_denied(
                connection,
                "UPDATE dfe_metadata.runs SET origin = origin WHERE false",
            )
            _assert_privilege_denied(
                connection,
                "UPDATE dfe_metadata.dataset_observations "
                "SET physical_binding = physical_binding WHERE false",
            )
            _assert_privilege_denied(
                connection,
                "DELETE FROM dfe_metadata.run_attempts WHERE false",
            )
            _assert_privilege_denied(
                connection,
                "TRUNCATE TABLE dfe_metadata.dataset_observations",
            )
            _assert_privilege_denied(
                connection,
                "CREATE TABLE dfe_metadata.writer_forbidden (value integer)",
            )

        with connect_writer(settings.reader) as connection:
            connection.execute("SET ROLE dfe_metadata_reader")
            connection.execute("SET default_transaction_read_only TO off")
            row = connection.execute(
                "SELECT selected_terminal_attempt_id, bound_input_cut_digest "
                "FROM dfe_metadata.runs WHERE run_id = %s",
                (run_id,),
            ).fetchone()
            assert row == (attempt_id, input_cut_digest)
            _assert_observation_closure(
                connection,
                run_id,
                input_cut_payload,
                input_cut_digest,
            )
            _assert_privilege_denied(
                connection,
                "INSERT INTO dfe_metadata.runs (run_id) "
                "VALUES ('00000000-0000-0000-0000-000000000001')",
            )
            _assert_privilege_denied(
                connection,
                "UPDATE dfe_metadata.run_attempts SET status = status WHERE false",
            )

        with connect_writer(settings.migrator) as connection:
            connection.execute("SET ROLE dfe_metadata_migrator")
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                connection.execute(
                    "DELETE FROM dfe_metadata.contract_versions WHERE contract_version_id = %s",
                    (registration.contract.contract_version_id,),
                )


@pytest.mark.integration
@pytest.mark.postgres
def test_lifecycle_migration_extends_v1_history_and_rolls_back_atomically() -> None:
    migrations = load_postgres_metadata_migrations()
    assert tuple((item.version, item.name) for item in migrations) == (
        (1, "0001_initial.sql"),
        (2, "0002_run_lifecycle.sql"),
        (3, "0003_completed_comparisons.sql"),
        (4, "0004_retained_anomalies.sql"),
        (5, "0005_frozen_physical_union.sql"),
        (6, "0006_mssql_dataset_adapter.sql"),
        (7, "0007_greengage_dataset_adapter.sql"),
    )

    upgrade_request = required_metadata_database_settings()
    with disposable_metadata_database(upgrade_request) as settings:
        _install_v1(settings, migrations[0])
        report = migrate_postgres_metadata(settings.migrator, _RETRY_POLICY, 5_000)
        assert report.applied_versions == (2, 3, 4, 5, 6, 7)
        assert report.current_version == 7
        with connect_writer(settings.reader) as connection:
            connection.execute("SET ROLE dfe_metadata_reader")
            rows = connection.execute(
                "SELECT version, name FROM dfe_metadata.migrations ORDER BY version"
            ).fetchall()
            assert rows == [
                (1, "0001_initial.sql"),
                (2, "0002_run_lifecycle.sql"),
                (3, "0003_completed_comparisons.sql"),
                (4, "0004_retained_anomalies.sql"),
                (5, "0005_frozen_physical_union.sql"),
                (6, "0006_mssql_dataset_adapter.sql"),
                (7, "0007_greengage_dataset_adapter.sql"),
            ]

    rollback_request = required_metadata_database_settings()
    with disposable_metadata_database(rollback_request) as settings:
        _install_v1(settings, migrations[0])
        with connect_writer(settings.migrator) as connection:
            connection.execute("SET ROLE dfe_metadata_migrator")
            connection.execute("CREATE TABLE dfe_metadata.run_attempts (conflict integer)")

        with pytest.raises(MetadataMigrationApplyError):
            migrate_postgres_metadata(settings.migrator, _RETRY_POLICY, 5_000)

        with connect_writer(settings.admin) as connection:
            row = connection.execute(
                "SELECT "
                "pg_catalog.to_regclass('dfe_metadata.runs'), "
                "pg_catalog.to_regclass('dfe_metadata.run_attempts'), "
                "pg_catalog.to_regclass('dfe_metadata.attempt_lease_renewals'), "
                "pg_catalog.to_regclass('dfe_metadata.attempt_read_contexts'), "
                "pg_catalog.to_regclass('dfe_metadata.dataset_observations')"
            ).fetchone()
            history = connection.execute(
                "SELECT version, name FROM dfe_metadata.migrations ORDER BY version"
            ).fetchall()
        assert row is not None
        assert row[0] is None
        assert row[1] is not None
        assert row[2:] == (None, None, None)
        assert history == [(1, "0001_initial.sql")]


def _register_relation_manifest_metadata(
    settings: MetadataDatabaseSettings,
) -> MetadataRegistration:
    config = load_contract_config(_EXAMPLE_CONTRACT)
    return register_postgres_metadata(
        settings.writer,
        _RETRY_POLICY,
        build_metadata_registration_definition(
            config.version,
            config.checks[0],
            config.evidence,
        ),
    )


def _scope_payload() -> dict[str, SemanticValue]:
    return {
        "canonical_protocol": "dfe_canon_v1",
        "parameters": [
            {
                "name": "business_date",
                "payload_hex": "2026-09-23".encode("ascii").hex(),
                "type": {"kind": "date", "normalization": "none"},
            }
        ],
        "semantic_protocol": "dfe_semantic_v1",
    }


def _execution_budgets_payload() -> dict[str, SemanticValue]:
    return {
        "max_application_result_bytes": 1_000_000,
        "max_attempts": 2,
        "max_checks_concurrency": 1,
        "max_coordinator_memory_bytes": 1_000_000,
        "max_depth": 4,
        "max_evidence_bytes": 100_000,
        "max_evidence_rows": 100,
        "max_fetched_records": 10_000,
        "max_fingerprint_nodes": 1_000,
        "max_full_scans_per_side": 1,
        "max_queries": 100,
        "max_source_concurrency": 1,
        "run_timeout_milliseconds": 60_000,
        "statement_timeout_milliseconds": 5_000,
        "version": 1,
    }


def _request_payload(
    registration: MetadataRegistration,
    scope_payload: dict[str, SemanticValue],
    budgets_payload: dict[str, SemanticValue],
) -> str:
    payload: SemanticValue = {
        "contract_version_id": str(registration.contract.contract_version_id),
        "evidence_policy": {
            "ddl_capture": "disabled",
            "field_rules": [],
            "policy_version": 1,
            "sql_capture": "disabled",
            "unspecified_fields": "omit",
        },
        "execution_policy": budgets_payload,
        "expected_batches": [
            {
                "batch_id": "reference-batch-2026-09-23",
                "dataset_id": registration.reference_dataset.definition.dataset_id,
                "direction": "reference",
            },
            {
                "batch_id": "target-batch-2026-09-23",
                "dataset_id": registration.target_dataset.definition.dataset_id,
                "direction": "target",
            },
        ],
        "origin": "integration_test",
        "request_version": 1,
        "scope": scope_payload,
    }
    return canonical_semantic_json(payload)


def _input_cut_payload(
    registration: MetadataRegistration,
    scope_digest: str,
) -> dict[str, SemanticValue]:
    return {
        "canonical_protocol": "dfe_canon_v1",
        "datasets": [
            {
                "alignment_values": [
                    _canonical_value("business_date", "2026-09-23", "date", {}),
                    _canonical_value("source_cut", "source-cut-42", "string", {}),
                ],
                "batch_id": _canonical_value(
                    "batch_id",
                    "reference-batch-2026-09-23",
                    "string",
                    {},
                ),
                "business_date": _canonical_value("business_date", "2026-09-23", "date", {}),
                "completed_at": _canonical_value(
                    "completed_at",
                    "2026-09-23T00:00:00.000000Z",
                    "timestamp_instant",
                    {"precision": 6},
                ),
                "dataset_id": registration.reference_dataset.definition.dataset_id,
                "dataset_version": _canonical_value(
                    "dataset_version",
                    "reference-version-1",
                    "string",
                    {},
                ),
                "direction": "reference",
                "source_cut": _canonical_value("source_cut", "source-cut-42", "string", {}),
            },
            {
                "alignment_values": [
                    _canonical_value("business_date", "2026-09-23", "date", {}),
                    _canonical_value("source_cut", "source-cut-42", "string", {}),
                ],
                "batch_id": _canonical_value(
                    "batch_id",
                    "target-batch-2026-09-23",
                    "string",
                    {},
                ),
                "business_date": _canonical_value("business_date", "2026-09-23", "date", {}),
                "completed_at": _canonical_value(
                    "completed_at",
                    "2026-09-23T00:00:00.000000Z",
                    "timestamp_instant",
                    {"precision": 6},
                ),
                "dataset_id": registration.target_dataset.definition.dataset_id,
                "dataset_version": _canonical_value(
                    "dataset_version",
                    "target-version-1",
                    "string",
                    {},
                ),
                "direction": "target",
                "source_cut": _canonical_value("source_cut", "source-cut-42", "string", {}),
            },
        ],
        "input_cut_version": 1,
        "late_arrivals": "next_batch",
        "scope_digest": scope_digest,
    }


def _insert_run(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    contract_version_id: UUID,
    request_digest: bytes,
    request_payload: str,
    scope_digest: bytes,
) -> None:
    connection.execute(
        "INSERT INTO dfe_metadata.runs ("
        "run_id, creation_operation_id, request_id, request_identity_digest, "
        "request_payload, contract_version_id, origin, scope_digest"
        ") VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s)",
        (
            run_id,
            uuid4(),
            uuid4(),
            request_digest,
            request_payload,
            contract_version_id,
            "integration_test",
            scope_digest,
        ),
    )


def _insert_attempt(
    connection: psycopg.Connection[DatabaseRow],
    attempt_id: UUID,
    run_id: UUID,
    ordinal: int,
    budgets_payload: dict[str, SemanticValue],
) -> None:
    connection.execute(
        "INSERT INTO dfe_metadata.run_attempts ("
        "attempt_id, run_id, ordinal, start_operation_id, execution_budgets, "
        "owner_token, initial_lease_expires_at, lease_expires_at"
        ") VALUES (%s, %s, %s, %s, %s::jsonb, %s, "
        "CURRENT_TIMESTAMP + INTERVAL '5 minutes', "
        "CURRENT_TIMESTAMP + INTERVAL '5 minutes')",
        (
            attempt_id,
            run_id,
            ordinal,
            uuid4(),
            canonical_semantic_json(budgets_payload),
            uuid4(),
        ),
    )


def _insert_context(
    connection: psycopg.Connection[DatabaseRow],
    context_id: UUID,
    run_id: UUID,
    attempt_id: UUID,
    dataset_version_id: UUID,
    direction: Literal["reference", "target"],
    scope_digest: bytes,
) -> None:
    acquisition_payload: SemanticValue = {
        "evidence_version": 1,
        "kind": "postgresql_protected_relations",
        "payload": {
            "acquired_before_snapshot": True,
            "lock_mode": "access_share",
            "relations": [{"relation_oid": 16_384}],
        },
    }
    connection.execute(
        "INSERT INTO dfe_metadata.attempt_read_contexts ("
        "read_context_id, run_id, attempt_id, dataset_version_id, direction, "
        "acquisition_operation_id, scope_digest, engine, driver_version, server_version, "
        "server_version_number, strategy, snapshot_locator, backend_process_id, "
        "allowed_concurrency, limitations, acquisition_evidence, started_at"
        ") VALUES ("
        "%s, %s, %s, %s, %s, %s, %s, 'postgresql', '3.3.6', '17.11', 170011, "
        "'protected_read_only_repeatable_read', '1:1:', 1234, 1, %s::jsonb, %s::jsonb, "
        "CURRENT_TIMESTAMP"
        ")",
        (
            context_id,
            run_id,
            attempt_id,
            dataset_version_id,
            direction,
            uuid4(),
            scope_digest,
            canonical_semantic_json(["snapshot locator is evidence only"]),
            canonical_semantic_json(acquisition_payload),
        ),
    )


def _insert_observation(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    attempt_id: UUID,
    context_id: UUID,
    dataset_version_id: UUID,
    direction: Literal["reference", "target"],
    scope_digest: bytes,
    input_cut_digest: bytes,
    input_cut_payload: dict[str, SemanticValue],
    readiness_capture_id: UUID | None,
    readiness_provider_kind: Literal["relation_manifest", "sql"],
) -> None:
    cut_dataset = _input_cut_dataset(input_cut_payload, direction)
    readiness_payload: SemanticValue = {
        "alignment_values": cut_dataset["alignment_values"],
        "batch_id": cut_dataset["batch_id"],
        "business_date": cut_dataset["business_date"],
        "completed_at": cut_dataset["completed_at"],
        "dataset_version": cut_dataset["dataset_version"],
        "evidence_version": 1,
        "kind": readiness_provider_kind,
        "late_arrivals": "next_batch",
        "scope_digest": scope_digest.hex(),
        "source_cut": cut_dataset["source_cut"],
        "state": "complete",
    }
    physical_binding: SemanticValue = {
        "binding_version": 1,
        "engine": "postgresql",
        "payload": {
            "namespace_oid": 2_200,
            "relation_oid": 16_384,
            "relation_row_type_oid": 16_385,
            "relkind": "r",
        },
    }
    physical_binding_json = canonical_semantic_json(physical_binding)
    physical_binding_digest = hashlib.sha256(physical_binding_json.encode("utf-8")).digest()
    connection.execute(
        "INSERT INTO dfe_metadata.dataset_observations ("
        "observation_id, observation_operation_id, run_id, attempt_id, read_context_id, "
        "dataset_version_id, direction, scope_digest, input_cut_digest, "
        "readiness_evidence, physical_schema_digest, physical_binding_digest, "
        "physical_binding, projection_code_artifact_id, readiness_provider_kind, "
        "readiness_code_artifact_id, observed_at"
        ") VALUES ("
        "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb, "
        "NULL, %s, %s, CURRENT_TIMESTAMP"
        ")",
        (
            uuid4(),
            uuid4(),
            run_id,
            attempt_id,
            context_id,
            dataset_version_id,
            direction,
            scope_digest,
            input_cut_digest,
            canonical_semantic_json(readiness_payload),
            _DIGEST_BYTES,
            physical_binding_digest,
            physical_binding_json,
            readiness_provider_kind,
            readiness_capture_id,
        ),
    )


def _input_cut_dataset(
    input_cut_payload: dict[str, SemanticValue],
    direction: Literal["reference", "target"],
) -> dict[str, SemanticValue]:
    datasets = input_cut_payload["datasets"]
    assert isinstance(datasets, list)
    for dataset in datasets:
        if isinstance(dataset, dict) and dataset.get("direction") == direction:
            return dataset
    raise AssertionError(f"input cut has no {direction!r} dataset")


def _assert_observation_closure(
    connection: psycopg.Connection[DatabaseRow],
    run_id: UUID,
    input_cut_payload: dict[str, SemanticValue],
    input_cut_digest: bytes,
) -> None:
    rows = connection.execute(
        "SELECT direction, input_cut_digest, readiness_evidence, "
        "physical_binding_digest, physical_binding "
        "FROM dfe_metadata.dataset_observations "
        "WHERE run_id = %s ORDER BY direction",
        (run_id,),
    ).fetchall()
    assert tuple(row[0] for row in rows) == ("reference", "target")
    for row in rows:
        direction = cast(Literal["reference", "target"], row[0])
        readiness = cast(dict[str, SemanticValue], row[2])
        expected = _input_cut_dataset(input_cut_payload, direction)
        assert row[1] == input_cut_digest
        assert readiness["batch_id"] == expected["batch_id"]
        assert readiness["business_date"] == expected["business_date"]
        assert readiness["dataset_version"] == expected["dataset_version"]
        assert readiness["completed_at"] == expected["completed_at"]
        assert readiness["alignment_values"] == expected["alignment_values"]
        assert readiness["source_cut"] == expected["source_cut"]
        physical_binding = cast(dict[str, SemanticValue], row[4])
        expected_binding_digest = hashlib.sha256(
            canonical_semantic_json(physical_binding).encode("utf-8")
        ).digest()
        assert row[3] == expected_binding_digest


def _canonical_value(
    name: str,
    value: str,
    kind: str,
    parameters: dict[str, SemanticValue],
) -> dict[str, SemanticValue]:
    return {
        "name": name,
        "payload_hex": value.encode("utf-8").hex(),
        "type": {
            "kind": kind,
            "normalization": "none",
            "parameters": parameters,
        },
    }


def _close_context(
    connection: psycopg.Connection[DatabaseRow],
    context_id: UUID,
) -> None:
    connection.execute(
        "UPDATE dfe_metadata.attempt_read_contexts SET "
        "state = 'closed', end_operation_id = %s, ended_at = CURRENT_TIMESTAMP "
        "WHERE read_context_id = %s",
        (uuid4(), context_id),
    )


def _terminal_reason_payload() -> str:
    payload: SemanticValue = {
        "message": "Ready cuts do not align",
        "native_error_code": None,
        "operation": "align_input_cut",
        "query_id": None,
        "reason_version": 1,
        "redacted_response": None,
        "safe_parameters": [],
    }
    return canonical_semantic_json(payload)


def _install_v1(
    settings: MetadataDatabaseSettings,
    migration: Migration,
) -> None:
    assert migration.version == 1
    with connect_writer(settings.migrator) as connection:
        connection.execute("BEGIN")
        connection.execute("SET LOCAL ROLE dfe_metadata_migrator")
        connection.execute(migration.sql_bytes)
        connection.execute(
            "INSERT INTO dfe_metadata.migrations (version, name, checksum_sha256) "
            "VALUES (%s, %s, %s)",
            (
                migration.version,
                migration.name,
                bytes.fromhex(migration.checksum_sha256),
            ),
        )
        connection.execute("COMMIT")


def _assert_privilege_denied(
    connection: psycopg.Connection[DatabaseRow],
    statement: LiteralString,
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as denied:
        connection.execute(statement)
    assert denied.value.sqlstate == "42501"
