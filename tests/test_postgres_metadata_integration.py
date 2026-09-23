import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import LiteralString
from uuid import UUID

import psycopg
import pytest

from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import AssurancePolicy, CapturePolicy
from forensic_data.persistence.definitions import build_metadata_registration_definition
from forensic_data.persistence.errors import (
    CodeArtifactIntegrityError,
    ImmutableContractRevisionConflictError,
    MetadataMigrationApplyError,
    MetadataMigrationChecksumError,
)
from forensic_data.persistence.model import (
    CodeCaptureState,
    MetadataRegistration,
)
from forensic_data.persistence.postgres import (
    METADATA_MIGRATION_ADVISORY_LOCK_KEYS,
    migrate_postgres_metadata,
    read_postgres_contract_version,
    read_postgres_metadata_registration,
    register_postgres_metadata,
)
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresRetryPolicy,
)
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    apply_metadata_bootstrap,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.postgres_support import connect_writer

_EXAMPLE_CONTRACT = Path(__file__).parent.parent / "examples/postgres-row/contract.yaml"
_RETRY_POLICY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)


@pytest.mark.integration
@pytest.mark.postgres
def test_metadata_migrations_roles_and_immutable_registration() -> None:
    requested = required_metadata_database_settings()
    with disposable_metadata_database(requested) as settings:
        apply_metadata_bootstrap(settings.admin)
        _assert_bootstrap_rejects_incompatible_acls(settings)

        first_migration = migrate_postgres_metadata(
            settings.migrator,
            _RETRY_POLICY,
            5_000,
        )
        assert first_migration.applied_versions == (1, 2, 3, 4, 5)
        assert first_migration.current_version == 5
        repeated_migration = migrate_postgres_metadata(
            settings.migrator,
            _RETRY_POLICY,
            5_000,
        )
        assert repeated_migration.applied_versions == ()
        assert repeated_migration.current_version == 5

        config = load_contract_config(_EXAMPLE_CONTRACT)
        check = config.checks[0]
        disabled_definition = build_metadata_registration_definition(
            config.version,
            check,
            config.evidence,
        )
        disabled = register_postgres_metadata(
            settings.writer,
            _RETRY_POLICY,
            disabled_definition,
        )
        assert all(
            artifact.definition.capture_state is CodeCaptureState.NOT_RETAINED
            for artifact in disabled.code_artifacts
        )
        assert (
            read_postgres_metadata_registration(
                settings.reader,
                _RETRY_POLICY,
                disabled,
            )
            == disabled
        )
        assert (
            read_postgres_contract_version(
                settings.reader,
                _RETRY_POLICY,
                check.check_id,
                check.revision,
            )
            == disabled.contract
        )

        repeated = register_postgres_metadata(
            settings.writer,
            _RETRY_POLICY,
            disabled_definition,
        )
        assert repeated.reference_dataset == disabled.reference_dataset
        assert repeated.target_dataset == disabled.target_dataset
        assert repeated.contract == disabled.contract
        assert tuple(item.code_artifact_id for item in repeated.code_artifacts) != tuple(
            item.code_artifact_id for item in disabled.code_artifacts
        )

        enabled_evidence = replace(config.evidence, sql_capture=CapturePolicy.ENABLED)
        enabled = register_postgres_metadata(
            settings.writer,
            _RETRY_POLICY,
            build_metadata_registration_definition(
                config.version,
                check,
                enabled_evidence,
            ),
        )
        assert enabled.reference_dataset == disabled.reference_dataset
        assert enabled.target_dataset == disabled.target_dataset
        assert enabled.contract == disabled.contract
        assert all(
            artifact.definition.capture_state is CodeCaptureState.RETAINED
            for artifact in enabled.code_artifacts
        )
        assert (
            read_postgres_metadata_registration(
                settings.reader,
                _RETRY_POLICY,
                enabled,
            )
            == enabled
        )

        next_revision_check = replace(check, revision=check.revision + 1)
        next_revision = register_postgres_metadata(
            settings.writer,
            _RETRY_POLICY,
            build_metadata_registration_definition(
                config.version,
                next_revision_check,
                enabled_evidence,
            ),
        )
        assert next_revision.contract.contract_version_id != disabled.contract.contract_version_id
        assert (
            next_revision.contract.definition.semantic_digest
            == disabled.contract.definition.semantic_digest
        )

        changed_check = replace(check, assurance_policy=AssurancePolicy.EXACT_REQUIRED)
        with pytest.raises(ImmutableContractRevisionConflictError):
            register_postgres_metadata(
                settings.writer,
                _RETRY_POLICY,
                build_metadata_registration_definition(
                    config.version,
                    changed_check,
                    config.evidence,
                ),
            )

        _assert_runtime_role_privileges(settings, disabled)
        _corrupt_retained_artifact(settings, enabled.code_artifacts[0].code_artifact_id)
        with pytest.raises(CodeArtifactIntegrityError):
            read_postgres_metadata_registration(
                settings.reader,
                _RETRY_POLICY,
                enabled,
            )

        with connect_writer(settings.migrator) as connection:
            connection.execute("SET ROLE dfe_metadata_migrator")
            connection.execute(
                "UPDATE dfe_metadata.migrations "
                "SET checksum_sha256 = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex') "
                "WHERE version = 1"
            )
        with pytest.raises(MetadataMigrationChecksumError) as checksum_failure:
            migrate_postgres_metadata(
                settings.migrator,
                _RETRY_POLICY,
                5_000,
            )
        assert "version=1" in str(checksum_failure.value)
        assert "0001_initial.sql" in str(checksum_failure.value)


@pytest.mark.integration
@pytest.mark.postgres
def test_metadata_migration_batch_rolls_back_and_lock_serializes() -> None:
    rollback_request = required_metadata_database_settings()
    with disposable_metadata_database(rollback_request) as rollback_settings:
        with connect_writer(rollback_settings.migrator) as connection:
            connection.execute("SET ROLE dfe_metadata_migrator")
            connection.execute("CREATE TABLE dfe_metadata.contract_versions (conflict integer)")
        with pytest.raises(MetadataMigrationApplyError):
            migrate_postgres_metadata(
                rollback_settings.migrator,
                _RETRY_POLICY,
                5_000,
            )
        with connect_writer(rollback_settings.admin) as connection:
            row = connection.execute(
                "SELECT pg_catalog.to_regclass('dfe_metadata.migrations'), "
                "pg_catalog.to_regclass('dfe_metadata.code_artifacts'), "
                "pg_catalog.to_regclass('dfe_metadata.dataset_versions'), "
                "pg_catalog.to_regclass('dfe_metadata.contract_versions')"
            ).fetchone()
        assert row is not None
        assert row[:3] == (None, None, None)
        assert row[3] is not None

    lock_request = required_metadata_database_settings()
    with disposable_metadata_database(lock_request) as lock_settings:
        initial = migrate_postgres_metadata(
            lock_settings.migrator,
            _RETRY_POLICY,
            5_000,
        )
        assert initial.applied_versions == (1, 2, 3, 4, 5)
        lock_connection = connect_writer(lock_settings.migrator)
        try:
            lock_connection.execute("BEGIN")
            lock_connection.execute("SET LOCAL ROLE dfe_metadata_migrator")
            lock_connection.execute(
                "SELECT pg_catalog.pg_advisory_xact_lock(%s, %s)",
                METADATA_MIGRATION_ADVISORY_LOCK_KEYS,
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    migrate_postgres_metadata,
                    lock_settings.migrator,
                    _RETRY_POLICY,
                    5_000,
                )
                _wait_for_advisory_lock_waiter(lock_settings.admin)
                lock_connection.execute("COMMIT")
                serialized = future.result(timeout=10)
            assert serialized.applied_versions == ()
            assert serialized.current_version == 5
        finally:
            lock_connection.close()


def _assert_bootstrap_rejects_incompatible_acls(
    settings: MetadataDatabaseSettings,
) -> None:
    with connect_writer(settings.admin) as connection:
        connection.execute("GRANT CREATE ON SCHEMA dfe_metadata TO dfe_fixture_reader")
    with pytest.raises(psycopg.Error) as bootstrap_failure:
        apply_metadata_bootstrap(settings.admin)
    assert bootstrap_failure.value.sqlstate == "P0001"
    with connect_writer(settings.admin) as connection:
        connection.execute("REVOKE CREATE ON SCHEMA dfe_metadata FROM dfe_fixture_reader")
        connection.execute(
            "ALTER DEFAULT PRIVILEGES FOR ROLE dfe_metadata_migrator "
            "IN SCHEMA dfe_metadata GRANT INSERT ON TABLES TO dfe_metadata_writer"
        )
    with pytest.raises(psycopg.Error) as bootstrap_failure:
        apply_metadata_bootstrap(settings.admin)
    assert bootstrap_failure.value.sqlstate == "P0001"
    with connect_writer(settings.admin) as connection:
        connection.execute(
            "ALTER DEFAULT PRIVILEGES FOR ROLE dfe_metadata_migrator "
            "IN SCHEMA dfe_metadata REVOKE INSERT ON TABLES FROM dfe_metadata_writer"
        )
    apply_metadata_bootstrap(settings.admin)


def _assert_runtime_role_privileges(
    settings: MetadataDatabaseSettings,
    registration: MetadataRegistration,
) -> None:
    with connect_writer(settings.reader) as connection:
        connection.execute("SET default_transaction_read_only TO off")
        content = connection.execute(
            "SELECT content_bytes FROM dfe_metadata.code_artifacts WHERE code_artifact_id = %s",
            (registration.code_artifacts[0].code_artifact_id,),
        ).fetchone()
        assert content == (None,)
        _assert_privilege_denied(
            connection,
            "INSERT INTO dfe_metadata.dataset_versions (dataset_version_id) "
            "VALUES ('00000000-0000-0000-0000-000000000001')",
        )
        _assert_privilege_denied(
            connection,
            "CREATE TABLE dfe_metadata.reader_forbidden (value integer)",
        )
    with connect_writer(settings.writer) as connection:
        _assert_privilege_denied(
            connection,
            "UPDATE dfe_metadata.dataset_versions SET dataset_id = dataset_id WHERE false",
        )
        _assert_privilege_denied(
            connection,
            "DELETE FROM dfe_metadata.contract_versions WHERE false",
        )
        _assert_privilege_denied(
            connection,
            "INSERT INTO dfe_metadata.migrations (version, name, checksum_sha256) "
            "VALUES (999, 'forbidden', pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'))",
        )
        _assert_privilege_denied(
            connection,
            "CREATE TABLE dfe_metadata.writer_forbidden (value integer)",
        )


def _assert_privilege_denied(
    connection: psycopg.Connection[DatabaseRow],
    statement: LiteralString,
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as denied:
        connection.execute(statement)
    assert denied.value.sqlstate == "42501"


def _corrupt_retained_artifact(
    settings: MetadataDatabaseSettings,
    artifact_id: UUID,
) -> None:
    with connect_writer(settings.migrator) as connection:
        connection.execute("SET ROLE dfe_metadata_migrator")
        connection.execute(
            "UPDATE dfe_metadata.code_artifacts "
            "SET content_bytes = pg_catalog.set_byte("
            "content_bytes, 0, (pg_catalog.get_byte(content_bytes, 0) + 1) %% 256) "
            "WHERE code_artifact_id = %s",
            (artifact_id,),
        )


def _wait_for_advisory_lock_waiter(
    admin_settings: PostgresConnectionSettings,
) -> None:
    deadline = time.monotonic() + 5.0
    with connect_writer(admin_settings) as connection:
        while time.monotonic() < deadline:
            row = connection.execute(
                "SELECT pg_catalog.count(*) FROM pg_catalog.pg_locks "
                "WHERE locktype = 'advisory' AND NOT granted "
                "AND database = ("
                "SELECT oid FROM pg_catalog.pg_database "
                "WHERE datname = pg_catalog.current_database()"
                ") "
                "AND classid = %s::integer::oid "
                "AND objid = %s::integer::oid "
                "AND objsubid = 2",
                METADATA_MIGRATION_ADVISORY_LOCK_KEYS,
            ).fetchone()
            if row == (1,):
                return
            time.sleep(0.02)
    raise AssertionError("metadata migration did not wait on the advisory lock")
