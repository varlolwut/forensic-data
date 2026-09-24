import hashlib
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Final, LiteralString
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
from psycopg.rows import tuple_row

from forensic_data.contracts.model import Adapter, AssurancePolicy, RelationScope
from forensic_data.contracts.semantics import canonicalize_semantic_json
from forensic_data.persistence.definitions import (
    code_artifact_descriptor_json,
    code_artifact_parameters_json,
    code_artifact_provenance_json,
)
from forensic_data.persistence.errors import (
    CodeArtifactIntegrityError,
    DatasetIdentityConflictError,
    ImmutableContractRevisionConflictError,
    MetadataConnectionError,
    MetadataMigrationApplyError,
    MetadataMigrationChecksumError,
    MetadataMigrationError,
    MetadataMigrationHistoryError,
    MetadataPersistenceError,
    MetadataProfileError,
    StoredMetadataIntegrityError,
)
from forensic_data.persistence.migrations import load_postgres_metadata_migrations
from forensic_data.persistence.model import (
    CodeArtifactCaptureDefinition,
    CodeArtifactRecord,
    CodeCaptureState,
    ContractVersionDefinition,
    ContractVersionRecord,
    DatasetLocatorKind,
    DatasetVersionDefinition,
    DatasetVersionRecord,
    MetadataRegistration,
    MetadataRegistrationDefinition,
    Migration,
    MigrationReport,
    code_artifact_kind,
)
from forensic_data.postgres import (
    DatabaseRow,
    PostgresConnectionSettings,
    PostgresRetryPolicy,
)

LOGGER = logging.getLogger(__name__)

METADATA_MIGRATION_ADVISORY_LOCK_KEYS: Final[tuple[int, int]] = (
    1_145_455_922,
    -661_538_192,
)
_MIGRATOR_ROLE: Final[str] = "dfe_metadata_migrator"
_WRITER_ROLE: Final[str] = "dfe_metadata_writer"
_READER_ROLE: Final[str] = "dfe_metadata_reader"
_MIGRATIONS_RELATION: Final[str] = "dfe_metadata.migrations"


def migrate_postgres_metadata(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    lock_timeout_milliseconds: int,
) -> MigrationReport:
    _require_positive_integer(lock_timeout_milliseconds, "migration lock timeout")
    migrations = load_postgres_metadata_migrations()
    return _run_with_retries(
        settings,
        retry_policy,
        "migrate_metadata",
        lambda connection: _migrate_once(
            connection,
            settings.statement_timeout_milliseconds,
            lock_timeout_milliseconds,
            migrations,
        ),
    )


def register_postgres_metadata(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    definition: MetadataRegistrationDefinition,
) -> MetadataRegistration:
    definition = _require_registration_definition(definition)
    reference_id = uuid4()
    target_id = uuid4()
    contract_id = uuid4()
    artifact_ids = tuple(uuid4() for _ in definition.code_artifacts)
    return _run_with_retries(
        settings,
        retry_policy,
        "register_metadata",
        lambda connection: _register_once(
            connection,
            settings.statement_timeout_milliseconds,
            definition,
            reference_id,
            target_id,
            contract_id,
            artifact_ids,
        ),
    )


def read_postgres_contract_version(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    check_id: str,
    revision: int,
) -> ContractVersionRecord:
    _require_nonblank_text(check_id, "check id")
    _require_positive_integer(revision, "contract revision")
    return _run_with_retries(
        settings,
        retry_policy,
        "read_contract_version",
        lambda connection: _read_contract_once(
            connection,
            settings.statement_timeout_milliseconds,
            check_id,
            revision,
        ),
    )


def read_postgres_metadata_registration(
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    expected: MetadataRegistration,
) -> MetadataRegistration:
    expected = _require_registration(expected)
    return _run_with_retries(
        settings,
        retry_policy,
        "read_metadata_registration",
        lambda connection: _read_registration_once(
            connection,
            settings.statement_timeout_milliseconds,
            expected,
        ),
    )


def _run_with_retries[ResultT](
    settings: PostgresConnectionSettings,
    retry_policy: PostgresRetryPolicy,
    operation: str,
    callback: Callable[[psycopg.Connection[DatabaseRow]], ResultT],
) -> ResultT:
    last_error: psycopg.OperationalError | None = None
    for attempt in range(1, retry_policy.max_attempts + 1):
        connection: psycopg.Connection[DatabaseRow] | None = None
        attempt_error: psycopg.OperationalError | None = None
        try:
            connection = _connect(settings)
            _validate_metadata_profile(connection)
            return callback(connection)
        except psycopg.OperationalError as error:
            last_error = error
            attempt_error = error
        except psycopg.Error as error:
            raise MetadataConnectionError(
                _database_error_message(operation, error, settings, attempt)
            ) from None
        finally:
            if connection is not None:
                connection.close()
        LOGGER.warning(
            "PostgreSQL metadata operation attempt failed",
            extra={
                "operation": operation,
                "attempt": attempt,
                "max_attempts": retry_policy.max_attempts,
                "host": settings.host,
                "port": settings.port,
                "dbname": settings.dbname,
                "user": settings.user,
                "error_type": type(attempt_error).__name__,
                "sqlstate": attempt_error.sqlstate,
            },
        )
        if attempt < retry_policy.max_attempts:
            time.sleep(retry_policy.delay_seconds)
    if last_error is None:
        raise AssertionError("metadata retry loop ended without an attempt")
    raise MetadataConnectionError(
        _database_error_message(
            operation,
            last_error,
            settings,
            retry_policy.max_attempts,
        )
    ) from None


def _connect(
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
        options=f"-c statement_timeout={settings.statement_timeout_milliseconds}",
        autocommit=True,
        row_factory=tuple_row,
    )


def _validate_metadata_profile(connection: psycopg.Connection[DatabaseRow]) -> None:
    try:
        row = connection.execute(
            "SELECT pg_catalog.current_setting('server_version_num')::integer, "
            "pg_catalog.current_setting('server_version'), "
            "pg_catalog.current_setting('server_encoding')"
        ).fetchone()
    except psycopg.OperationalError:
        raise
    except psycopg.Error as error:
        raise MetadataProfileError(
            "PostgreSQL metadata profile probe failed: "
            f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
        ) from None
    if row is None or len(row) != 3:
        raise MetadataProfileError("PostgreSQL metadata profile probe returned an invalid row")
    version_number = _row_integer(row[0], "server version number")
    version_text = _row_text(row[1], "server version")
    encoding = _row_text(row[2], "server encoding")
    if encoding != "UTF8":
        raise MetadataProfileError(
            "PostgreSQL metadata store requires UTF8 server encoding: "
            f"server_version={version_text!r}, server_version_number={version_number}, "
            f"actual={encoding!r}"
        )


def _migrate_once(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
    lock_timeout_milliseconds: int,
    migrations: tuple[Migration, ...],
) -> MigrationReport:
    current_migration: Migration | None = None
    lock_stage = "advisory_lock"
    try:
        _begin_migrator_transaction(
            connection,
            statement_timeout_milliseconds,
        )
        connection.execute(
            "SELECT pg_catalog.set_config('lock_timeout', %s, true)",
            (f"{lock_timeout_milliseconds}ms",),
        )
        connection.execute(
            "SELECT pg_catalog.pg_advisory_xact_lock(%s, %s)",
            METADATA_MIGRATION_ADVISORY_LOCK_KEYS,
        )
        lock_stage = "migration_journal"
        applied_count = _validate_migration_history(connection, migrations)
        pending = migrations[applied_count:]
        for migration in pending:
            current_migration = migration
            lock_stage = f"migration_{migration.version}"
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
    except psycopg.errors.LockNotAvailable as error:
        raise MetadataMigrationError(
            "PostgreSQL metadata migration lock wait timed out: "
            f"stage={lock_stage!r}, "
            f"timeout_milliseconds={lock_timeout_milliseconds}, "
            f"sqlstate={error.sqlstate!r}"
        ) from None
    except psycopg.OperationalError:
        raise
    except (MetadataMigrationHistoryError, MetadataMigrationChecksumError):
        raise
    except psycopg.Error as error:
        migration_context = "migration_batch"
        if current_migration is not None:
            migration_context = (
                f"version={current_migration.version}, name={current_migration.name!r}"
            )
        raise MetadataMigrationApplyError(
            "PostgreSQL metadata migration transaction failed and was rolled back: "
            f"{migration_context}, error_type={type(error).__name__}, "
            f"sqlstate={error.sqlstate!r}"
        ) from None
    current_version = migrations[-1].version if migrations else 0
    return MigrationReport(
        applied_versions=tuple(migration.version for migration in pending),
        current_version=current_version,
    )


def _validate_migration_history(
    connection: psycopg.Connection[DatabaseRow],
    migrations: tuple[Migration, ...],
) -> int:
    relation_row = connection.execute(
        "SELECT pg_catalog.to_regclass(%s)::pg_catalog.oid",
        (_MIGRATIONS_RELATION,),
    ).fetchone()
    if relation_row is None or len(relation_row) != 1:
        raise MetadataMigrationHistoryError(
            "PostgreSQL migration journal lookup returned an invalid row"
        )
    relation_oid = relation_row[0]
    if relation_oid is None:
        return 0
    if type(relation_oid) is not int or relation_oid < 1:
        raise MetadataMigrationHistoryError(
            "PostgreSQL migration journal lookup returned an invalid relation identity"
        )
    rows = connection.execute(
        "SELECT version, name, checksum_sha256 FROM dfe_metadata.migrations ORDER BY version"
    ).fetchall()
    if not rows:
        raise MetadataMigrationHistoryError(
            "PostgreSQL migration journal exists but contains no applied migration"
        )
    if len(rows) > len(migrations):
        unknown_version = _row_integer(rows[len(migrations)][0], "migration version")
        raise MetadataMigrationHistoryError(
            "PostgreSQL migration journal contains an unknown newer migration: "
            f"version={unknown_version}, packaged_latest={len(migrations)}"
        )
    for index, row in enumerate(rows):
        if len(row) != 3:
            raise MetadataMigrationHistoryError(
                "PostgreSQL migration journal returned an invalid row shape"
            )
        stored_version = _row_integer(row[0], "migration version")
        stored_name = _row_text(row[1], "migration name")
        stored_checksum = _row_bytes(row[2], "migration checksum")
        expected = migrations[index]
        if stored_version != expected.version:
            raise MetadataMigrationHistoryError(
                "PostgreSQL migration journal is not a contiguous packaged prefix: "
                f"position={index + 1}, expected_version={expected.version}, "
                f"actual_version={stored_version}"
            )
        if stored_name != expected.name:
            raise MetadataMigrationHistoryError(
                "PostgreSQL migration journal name differs from the packaged migration: "
                f"version={expected.version}, expected_name={expected.name!r}, "
                f"actual_name={stored_name!r}"
            )
        actual_checksum = stored_checksum.hex()
        if actual_checksum != expected.checksum_sha256:
            raise MetadataMigrationChecksumError(
                "PostgreSQL migration checksum differs from the packaged SQL bytes: "
                f"version={expected.version}, name={expected.name!r}, "
                f"expected_checksum={expected.checksum_sha256!r}, "
                f"actual_checksum={actual_checksum!r}"
            )
    return len(rows)


def _register_once(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
    definition: MetadataRegistrationDefinition,
    reference_id: UUID,
    target_id: UUID,
    contract_id: UUID,
    artifact_ids: tuple[UUID, ...],
) -> MetadataRegistration:
    try:
        _begin_writer_transaction(
            connection,
            statement_timeout_milliseconds,
        )
        _require_current_schema(connection)
        reference = _register_dataset(
            connection,
            definition.reference_dataset,
            reference_id,
        )
        target = _register_dataset(
            connection,
            definition.target_dataset,
            target_id,
        )
        contract = _register_contract(
            connection,
            definition.contract,
            contract_id,
            reference.dataset_version_id,
            target.dataset_version_id,
        )
        artifacts = tuple(
            _register_code_artifact(connection, artifact_id, artifact)
            for artifact_id, artifact in zip(
                artifact_ids,
                definition.code_artifacts,
                strict=True,
            )
        )
        result = MetadataRegistration(
            reference_dataset=reference,
            target_dataset=target,
            contract=contract,
            code_artifacts=artifacts,
        )
        connection.execute("COMMIT")
        return result
    except psycopg.OperationalError:
        raise
    except (
        CodeArtifactIntegrityError,
        DatasetIdentityConflictError,
        ImmutableContractRevisionConflictError,
        StoredMetadataIntegrityError,
    ):
        raise
    except psycopg.Error as error:
        raise MetadataPersistenceError(
            "PostgreSQL metadata registration failed and was rolled back: "
            f"check_id={definition.contract.check_id!r}, "
            f"revision={definition.contract.revision}, "
            f"contract_digest={definition.contract.semantic_digest!r}, "
            f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
        ) from None


def _register_dataset(
    connection: psycopg.Connection[DatabaseRow],
    definition: DatasetVersionDefinition,
    candidate_id: UUID,
) -> DatasetVersionRecord:
    connection.execute(
        "INSERT INTO dfe_metadata.dataset_versions ("
        "dataset_version_id, dataset_id, semantic_digest, semantic_protocol, "
        "canonical_protocol, logical_schema_digest, connection_id, adapter, driver, "
        "profile, locator_kind, relation_scope, semantic_payload, resolved_definition"
        ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, "
        "%s::jsonb) ON CONFLICT (dataset_id, semantic_digest) DO NOTHING",
        (
            candidate_id,
            definition.dataset_id,
            bytes.fromhex(definition.semantic_digest),
            definition.semantic_protocol,
            definition.canonical_protocol,
            bytes.fromhex(definition.logical_schema_digest),
            definition.connection_id,
            definition.adapter.value,
            definition.driver,
            definition.profile,
            definition.locator_kind.value,
            definition.relation_scope.value if definition.relation_scope is not None else None,
            definition.semantic_payload_json,
            definition.resolved_definition_json,
        ),
    )
    row = connection.execute(
        sql.SQL(_DATASET_SELECT + " WHERE dataset_id = %s AND semantic_digest = %s"),
        (definition.dataset_id, bytes.fromhex(definition.semantic_digest)),
    ).fetchone()
    if row is None:
        raise StoredMetadataIntegrityError(
            "PostgreSQL dataset registration produced no durable identity row: "
            f"dataset_id={definition.dataset_id!r}, digest={definition.semantic_digest!r}"
        )
    record = _dataset_record(row)
    if record.definition != definition:
        raise DatasetIdentityConflictError(
            "PostgreSQL dataset semantic identity is bound to a different immutable "
            "definition: "
            f"dataset_id={definition.dataset_id!r}, digest={definition.semantic_digest!r}"
        )
    return record


def _register_contract(
    connection: psycopg.Connection[DatabaseRow],
    definition: ContractVersionDefinition,
    candidate_id: UUID,
    reference_dataset_version_id: UUID,
    target_dataset_version_id: UUID,
) -> ContractVersionRecord:
    connection.execute(
        "INSERT INTO dfe_metadata.contract_versions ("
        "contract_version_id, check_id, revision, config_version, semantic_digest, "
        "semantic_protocol, canonical_protocol, comparison_schema_digest, "
        "reference_dataset_version_id, target_dataset_version_id, assurance_policy, "
        "semantic_payload, resolved_definition"
        ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, "
        "%s::jsonb) ON CONFLICT (check_id, revision) DO NOTHING",
        (
            candidate_id,
            definition.check_id,
            definition.revision,
            definition.config_version,
            bytes.fromhex(definition.semantic_digest),
            definition.semantic_protocol,
            definition.canonical_protocol,
            bytes.fromhex(definition.comparison_schema_digest),
            reference_dataset_version_id,
            target_dataset_version_id,
            definition.assurance_policy.value,
            definition.semantic_payload_json,
            definition.resolved_definition_json,
        ),
    )
    row = connection.execute(
        sql.SQL(_CONTRACT_SELECT + " WHERE contract.check_id = %s AND contract.revision = %s"),
        (definition.check_id, definition.revision),
    ).fetchone()
    if row is None:
        raise StoredMetadataIntegrityError(
            "PostgreSQL contract registration produced no durable revision row: "
            f"check_id={definition.check_id!r}, revision={definition.revision}"
        )
    record = _contract_record(row)
    if (
        record.definition != definition
        or record.reference_dataset_version_id != reference_dataset_version_id
        or record.target_dataset_version_id != target_dataset_version_id
    ):
        raise ImmutableContractRevisionConflictError(
            "PostgreSQL check revision is already bound to a different immutable "
            "contract: "
            f"check_id={definition.check_id!r}, revision={definition.revision}, "
            f"requested_digest={definition.semantic_digest!r}, "
            f"stored_digest={record.definition.semantic_digest!r}"
        )
    return record


def _register_code_artifact(
    connection: psycopg.Connection[DatabaseRow],
    artifact_id: UUID,
    definition: CodeArtifactCaptureDefinition,
) -> CodeArtifactRecord:
    parameters_json = code_artifact_parameters_json(definition)
    descriptor_json = code_artifact_descriptor_json(definition)
    provenance_json = code_artifact_provenance_json(definition)
    connection.execute(
        "INSERT INTO dfe_metadata.code_artifacts ("
        "code_artifact_id, artifact_kind, dialect, content_sha256, source_byte_length, "
        "parameters, retention_state, omission_reason, content_bytes, descriptor, provenance"
        ") VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s::jsonb, %s::jsonb) "
        "ON CONFLICT (code_artifact_id) DO NOTHING",
        (
            artifact_id,
            code_artifact_kind(),
            definition.dialect.value,
            bytes.fromhex(definition.content_sha256),
            definition.source_byte_length,
            parameters_json,
            definition.capture_state.value,
            definition.omission_reason,
            definition.content_bytes,
            descriptor_json,
            provenance_json,
        ),
    )
    row = connection.execute(
        sql.SQL(_ARTIFACT_SELECT + " WHERE code_artifact_id = %s"),
        (artifact_id,),
    ).fetchone()
    if row is None:
        raise CodeArtifactIntegrityError(
            "PostgreSQL code artifact registration produced no capture row: "
            f"code_artifact_id={artifact_id}"
        )
    return _code_artifact_record(
        row,
        definition,
        parameters_json,
        descriptor_json,
        provenance_json,
    )


def _read_contract_once(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
    check_id: str,
    revision: int,
) -> ContractVersionRecord:
    try:
        _begin_reader_transaction(
            connection,
            statement_timeout_milliseconds,
        )
        _require_current_schema(connection)
        row = connection.execute(
            sql.SQL(_CONTRACT_SELECT + " WHERE contract.check_id = %s AND contract.revision = %s"),
            (check_id, revision),
        ).fetchone()
        if row is None:
            raise StoredMetadataIntegrityError(
                "PostgreSQL contract revision was not found: "
                f"check_id={check_id!r}, revision={revision}"
            )
        record = _contract_record(row)
        connection.execute("COMMIT")
        return record
    except psycopg.OperationalError:
        raise
    except StoredMetadataIntegrityError:
        raise
    except psycopg.Error as error:
        raise MetadataPersistenceError(
            "PostgreSQL metadata contract read failed: "
            f"check_id={check_id!r}, revision={revision}, "
            f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
        ) from None


def _read_registration_once(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
    expected: MetadataRegistration,
) -> MetadataRegistration:
    try:
        _begin_reader_transaction(
            connection,
            statement_timeout_milliseconds,
        )
        _require_current_schema(connection)
        reference = _read_expected_dataset(connection, expected.reference_dataset)
        target = _read_expected_dataset(connection, expected.target_dataset)
        contract = _read_expected_contract(connection, expected.contract)
        artifacts = tuple(
            _read_expected_code_artifact(connection, artifact)
            for artifact in expected.code_artifacts
        )
        result = MetadataRegistration(
            reference_dataset=reference,
            target_dataset=target,
            contract=contract,
            code_artifacts=artifacts,
        )
        connection.execute("COMMIT")
        return result
    except psycopg.OperationalError:
        raise
    except (CodeArtifactIntegrityError, StoredMetadataIntegrityError):
        raise
    except psycopg.Error as error:
        raise MetadataPersistenceError(
            "PostgreSQL metadata registration read failed: "
            f"check_id={expected.contract.definition.check_id!r}, "
            f"revision={expected.contract.definition.revision}, "
            f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
        ) from None


def _read_expected_dataset(
    connection: psycopg.Connection[DatabaseRow],
    expected: DatasetVersionRecord,
) -> DatasetVersionRecord:
    row = connection.execute(
        sql.SQL(_DATASET_SELECT + " WHERE dataset_version_id = %s"),
        (expected.dataset_version_id,),
    ).fetchone()
    if row is None:
        raise StoredMetadataIntegrityError(
            "PostgreSQL dataset version was not found: "
            f"dataset_version_id={expected.dataset_version_id}"
        )
    actual = _dataset_record(row)
    if actual != expected:
        raise StoredMetadataIntegrityError(
            "PostgreSQL dataset version differs from its registered immutable value: "
            f"dataset_version_id={expected.dataset_version_id}"
        )
    return actual


def _read_expected_contract(
    connection: psycopg.Connection[DatabaseRow],
    expected: ContractVersionRecord,
) -> ContractVersionRecord:
    row = connection.execute(
        sql.SQL(_CONTRACT_SELECT + " WHERE contract.contract_version_id = %s"),
        (expected.contract_version_id,),
    ).fetchone()
    if row is None:
        raise StoredMetadataIntegrityError(
            "PostgreSQL contract version was not found: "
            f"contract_version_id={expected.contract_version_id}"
        )
    actual = _contract_record(row)
    if actual != expected:
        raise StoredMetadataIntegrityError(
            "PostgreSQL contract version differs from its registered immutable value: "
            f"contract_version_id={expected.contract_version_id}"
        )
    return actual


def _read_expected_code_artifact(
    connection: psycopg.Connection[DatabaseRow],
    expected: CodeArtifactRecord,
) -> CodeArtifactRecord:
    row = connection.execute(
        sql.SQL(_ARTIFACT_SELECT + " WHERE code_artifact_id = %s"),
        (expected.code_artifact_id,),
    ).fetchone()
    if row is None:
        raise CodeArtifactIntegrityError(
            "PostgreSQL code artifact capture was not found: "
            f"code_artifact_id={expected.code_artifact_id}"
        )
    return _code_artifact_record(
        row,
        expected.definition,
        code_artifact_parameters_json(expected.definition),
        code_artifact_descriptor_json(expected.definition),
        code_artifact_provenance_json(expected.definition),
    )


def _dataset_record(row: DatabaseRow) -> DatasetVersionRecord:
    if len(row) != 15:
        raise StoredMetadataIntegrityError(
            "PostgreSQL dataset version row has an invalid column count"
        )
    relation_scope_text = _row_optional_text(row[11], "dataset relation scope")
    try:
        adapter = Adapter(_row_text(row[7], "dataset adapter"))
        locator_kind = DatasetLocatorKind(_row_text(row[10], "dataset locator kind"))
        relation_scope = (
            RelationScope(relation_scope_text) if relation_scope_text is not None else None
        )
        definition = DatasetVersionDefinition(
            dataset_id=_row_text(row[1], "dataset id"),
            semantic_digest=_row_bytes(row[2], "dataset semantic digest").hex(),
            semantic_protocol=_row_text(row[3], "dataset semantic protocol"),
            canonical_protocol=_row_text(row[4], "dataset canonical protocol"),
            logical_schema_digest=_row_bytes(row[5], "logical schema digest").hex(),
            connection_id=_row_text(row[6], "dataset connection id"),
            adapter=adapter,
            driver=_row_text(row[8], "dataset driver"),
            profile=_row_text(row[9], "dataset profile"),
            locator_kind=locator_kind,
            relation_scope=relation_scope,
            semantic_payload_json=_canonical_database_json(
                row[12],
                "dataset semantic payload",
            ),
            resolved_definition_json=_canonical_database_json(
                row[13],
                "dataset resolved definition",
            ),
        )
        return DatasetVersionRecord(
            dataset_version_id=_row_uuid(row[0], "dataset version id"),
            definition=definition,
            created_at=_row_datetime(row[14], "dataset created_at"),
        )
    except ValueError as error:
        raise StoredMetadataIntegrityError(
            f"PostgreSQL dataset version row violates the typed metadata protocol: reason={error}"
        ) from None


def _contract_record(row: DatabaseRow) -> ContractVersionRecord:
    if len(row) != 18:
        raise StoredMetadataIntegrityError(
            "PostgreSQL contract version row has an invalid column count"
        )
    try:
        definition = ContractVersionDefinition(
            check_id=_row_text(row[1], "contract check id"),
            revision=_row_integer(row[2], "contract revision"),
            config_version=_row_integer(row[3], "contract config version"),
            semantic_digest=_row_bytes(row[4], "contract semantic digest").hex(),
            semantic_protocol=_row_text(row[5], "contract semantic protocol"),
            canonical_protocol=_row_text(row[6], "contract canonical protocol"),
            comparison_schema_digest=_row_bytes(
                row[7],
                "comparison schema digest",
            ).hex(),
            reference_dataset_id=_row_text(row[14], "reference dataset id"),
            reference_dataset_digest=_row_bytes(
                row[15],
                "reference dataset digest",
            ).hex(),
            target_dataset_id=_row_text(row[16], "target dataset id"),
            target_dataset_digest=_row_bytes(
                row[17],
                "target dataset digest",
            ).hex(),
            assurance_policy=AssurancePolicy(_row_text(row[10], "contract assurance policy")),
            semantic_payload_json=_canonical_database_json(
                row[11],
                "contract semantic payload",
            ),
            resolved_definition_json=_canonical_database_json(
                row[12],
                "contract resolved definition",
            ),
        )
        return ContractVersionRecord(
            contract_version_id=_row_uuid(row[0], "contract version id"),
            definition=definition,
            reference_dataset_version_id=_row_uuid(
                row[8],
                "reference dataset version id",
            ),
            target_dataset_version_id=_row_uuid(
                row[9],
                "target dataset version id",
            ),
            created_at=_row_datetime(row[13], "contract created_at"),
        )
    except ValueError as error:
        raise StoredMetadataIntegrityError(
            f"PostgreSQL contract version row violates the typed metadata protocol: reason={error}"
        ) from None


def _code_artifact_record(
    row: DatabaseRow,
    expected: CodeArtifactCaptureDefinition,
    expected_parameters_json: str,
    expected_descriptor_json: str,
    expected_provenance_json: str,
) -> CodeArtifactRecord:
    if len(row) != 12:
        raise CodeArtifactIntegrityError("PostgreSQL code artifact row has an invalid column count")
    artifact_id = _row_uuid(row[0], "code artifact id")
    stored_content = _row_optional_bytes(row[9], "code artifact content")
    actual_digest = _row_bytes(row[3], "code artifact digest").hex()
    actual_size = _row_integer(row[4], "code artifact source byte length")
    actual_state = _row_text(row[6], "code artifact retention state")
    actual_omission_reason = _row_optional_text(row[7], "code artifact omission reason")
    if stored_content is not None:
        retained_digest = hashlib.sha256(stored_content).hexdigest()
        if len(stored_content) != actual_size or retained_digest != actual_digest:
            raise CodeArtifactIntegrityError(
                "PostgreSQL retained code artifact bytes do not match their declared "
                "digest or size: "
                f"code_artifact_id={artifact_id}, declared_digest={actual_digest!r}, "
                f"declared_size={actual_size}, actual_size={len(stored_content)}"
            )
    actual_fields = (
        _row_text(row[1], "code artifact kind"),
        _row_text(row[2], "code artifact dialect"),
        actual_digest,
        actual_size,
        _canonical_database_json(row[5], "code artifact parameters"),
        actual_state,
        actual_omission_reason,
        stored_content,
        _canonical_database_json(row[8], "code artifact descriptor"),
        _canonical_database_json(row[10], "code artifact provenance"),
    )
    expected_fields = (
        code_artifact_kind(),
        expected.dialect.value,
        expected.content_sha256,
        expected.source_byte_length,
        expected_parameters_json,
        expected.capture_state.value,
        expected.omission_reason,
        expected.content_bytes,
        expected_descriptor_json,
        expected_provenance_json,
    )
    if actual_fields != expected_fields:
        raise CodeArtifactIntegrityError(
            "PostgreSQL code artifact capture differs from its immutable registered value: "
            f"code_artifact_id={artifact_id}, digest={expected.content_sha256!r}, "
            f"capture_state={expected.capture_state.value!r}"
        )
    try:
        CodeCaptureState(actual_state)
        return CodeArtifactRecord(
            code_artifact_id=artifact_id,
            definition=expected,
            created_at=_row_datetime(row[11], "code artifact created_at"),
        )
    except ValueError as error:
        raise CodeArtifactIntegrityError(
            "PostgreSQL code artifact row violates the typed metadata protocol: "
            f"code_artifact_id={artifact_id}, reason={error}"
        ) from None


def _begin_migrator_transaction(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
) -> None:
    connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE")
    connection.execute("SET LOCAL ROLE dfe_metadata_migrator")
    _configure_transaction(connection, statement_timeout_milliseconds)


def _begin_writer_transaction(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
) -> None:
    connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE")
    connection.execute("SET LOCAL ROLE dfe_metadata_writer")
    _configure_transaction(connection, statement_timeout_milliseconds)


def _begin_reader_transaction(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
) -> None:
    connection.execute("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY")
    connection.execute("SET LOCAL ROLE dfe_metadata_reader")
    _configure_transaction(connection, statement_timeout_milliseconds)


def _configure_transaction(
    connection: psycopg.Connection[DatabaseRow],
    statement_timeout_milliseconds: int,
) -> None:
    connection.execute("SET LOCAL search_path TO pg_catalog")
    connection.execute("SET LOCAL TIME ZONE 'UTC'")
    connection.execute("SET LOCAL DateStyle TO 'ISO, YMD'")
    connection.execute(
        "SELECT pg_catalog.set_config('statement_timeout', %s, true)",
        (f"{statement_timeout_milliseconds}ms",),
    )


_DATASET_SELECT: Final[LiteralString] = (
    "SELECT dataset_version_id, dataset_id, semantic_digest, semantic_protocol, "
    "canonical_protocol, logical_schema_digest, connection_id, adapter, driver, profile, "
    "locator_kind, relation_scope, semantic_payload::text, resolved_definition::text, "
    "created_at FROM dfe_metadata.dataset_versions"
)

_CONTRACT_SELECT: Final[LiteralString] = (
    "SELECT contract.contract_version_id, contract.check_id, contract.revision, "
    "contract.config_version, contract.semantic_digest, contract.semantic_protocol, "
    "contract.canonical_protocol, contract.comparison_schema_digest, "
    "contract.reference_dataset_version_id, contract.target_dataset_version_id, "
    "contract.assurance_policy, contract.semantic_payload::text, "
    "contract.resolved_definition::text, contract.created_at, "
    "reference.dataset_id, reference.semantic_digest, target.dataset_id, "
    "target.semantic_digest "
    "FROM dfe_metadata.contract_versions AS contract "
    "JOIN dfe_metadata.dataset_versions AS reference "
    "ON reference.dataset_version_id = contract.reference_dataset_version_id "
    "JOIN dfe_metadata.dataset_versions AS target "
    "ON target.dataset_version_id = contract.target_dataset_version_id"
)


def _require_current_schema(connection: psycopg.Connection[DatabaseRow]) -> None:
    migrations = load_postgres_metadata_migrations()
    applied_count = _validate_migration_history(connection, migrations)
    if applied_count != len(migrations):
        next_version = migrations[applied_count].version
        raise MetadataMigrationHistoryError(
            "PostgreSQL metadata schema is behind the packaged runtime and must be "
            "migrated before use: "
            f"applied_version={applied_count}, required_version={migrations[-1].version}, "
            f"next_version={next_version}"
        )


_ARTIFACT_SELECT: Final[LiteralString] = (
    "SELECT code_artifact_id, artifact_kind, dialect, content_sha256, "
    "source_byte_length, parameters::text, retention_state, omission_reason, "
    "descriptor::text, content_bytes, provenance::text, created_at "
    "FROM dfe_metadata.code_artifacts"
)


def _canonical_database_json(value: object, context: str) -> str:
    text = _row_text(value, context)
    try:
        return canonicalize_semantic_json(text)
    except ValueError as error:
        raise StoredMetadataIntegrityError(
            f"PostgreSQL {context} is not canonical semantic JSON: reason={error}"
        ) from None


def _row_text(value: object, context: str) -> str:
    if type(value) is not str:
        raise StoredMetadataIntegrityError(f"PostgreSQL {context} must be text")
    return value


def _row_optional_text(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _row_text(value, context)


def _row_integer(value: object, context: str) -> int:
    if type(value) is not int:
        raise StoredMetadataIntegrityError(f"PostgreSQL {context} must be an integer")
    return value


def _row_bytes(value: object, context: str) -> bytes:
    if type(value) is bytes:
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    raise StoredMetadataIntegrityError(f"PostgreSQL {context} must be bytes")


def _row_optional_bytes(value: object, context: str) -> bytes | None:
    if value is None:
        return None
    return _row_bytes(value, context)


def _row_uuid(value: object, context: str) -> UUID:
    if not isinstance(value, UUID):
        raise StoredMetadataIntegrityError(f"PostgreSQL {context} must be a UUID")
    return value


def _row_datetime(value: object, context: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise StoredMetadataIntegrityError(
            f"PostgreSQL {context} must be a timezone-aware timestamp"
        )
    return value.astimezone(UTC)


def _require_positive_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"{context} must be a positive integer")


def _require_nonblank_text(value: object, context: str) -> None:
    if type(value) is not str or value.strip() == "":
        raise ValueError(f"{context} must be nonblank text")


def _require_registration_definition(value: object) -> MetadataRegistrationDefinition:
    if not isinstance(value, MetadataRegistrationDefinition):
        raise ValueError("metadata registration must be a MetadataRegistrationDefinition")
    return value


def _require_registration(value: object) -> MetadataRegistration:
    if not isinstance(value, MetadataRegistration):
        raise ValueError("expected metadata registration must be a MetadataRegistration")
    return value


def _database_error_message(
    operation: str,
    error: psycopg.Error,
    settings: PostgresConnectionSettings,
    attempts: int,
) -> str:
    return (
        "PostgreSQL metadata operation failed after bounded attempts: "
        f"operation={operation!r}, host={settings.host!r}, port={settings.port}, "
        f"dbname={settings.dbname!r}, user={settings.user!r}, attempts={attempts}, "
        f"error_type={type(error).__name__}, sqlstate={error.sqlstate!r}"
    )
