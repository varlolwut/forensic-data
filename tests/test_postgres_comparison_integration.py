import re
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4

import pytest
from psycopg import sql

from forensic_data.acquisition import (
    InputCutDefinition,
    RelationManifestEvidence,
    RunRequestDefinition,
    build_input_cut_definition,
    build_run_request_definition,
    validate_relation_manifest_readiness,
)
from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
    TimestampParameters,
)
from forensic_data.comparison import execute_postgres_integer_key_comparison
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import (
    EvidenceDefinition,
    ExecutionBudgets,
    RelationLocator,
    RelationManifestReadiness,
    RowCheckDefinition,
)
from forensic_data.persistence.definitions import build_metadata_registration_definition
from forensic_data.persistence.lifecycle import (
    AlignedInputCutPersistence,
    ClaimedRun,
    ReadContextPersistence,
    RelationManifestObservationPersistence,
    RunAttemptRecord,
    claim_postgres_run,
    close_postgres_read_context,
    completed_comparison_persistence_from_artifact,
    persist_postgres_aligned_input_cut,
    persist_postgres_read_context,
    publish_postgres_completed_comparison,
    read_postgres_completed_comparison,
    start_postgres_run_attempt,
)
from forensic_data.persistence.model import DatasetVersionRecord, MetadataRegistration
from forensic_data.persistence.postgres import (
    migrate_postgres_metadata,
    register_postgres_metadata,
)
from forensic_data.planning import PlanDirection, ResolvedScope, resolve_scope_values
from forensic_data.postgres import (
    PostgresConnectionSettings,
    PostgresProtectedReadContext,
    PostgresProtectedRelationInspection,
    PostgresRelationAcquisition,
    PostgresRetryPolicy,
    open_postgres_protected_read_context,
)
from forensic_data.postgres_sql import PostgresRelation
from forensic_data.result import (
    ComparisonTotals,
    ConsistencyLevel,
    ExecutionStatus,
    ExitCode,
    Guarantee,
    InferredTotal,
    PersistenceState,
    ReasonCode,
    RunResult,
    Verdict,
    exit_code_for_result,
)
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.postgres_support import (
    connect_writer,
    required_connection_settings,
)

pytestmark = [pytest.mark.integration, pytest.mark.postgres]

_CONTRACT_PATH = Path(__file__).parents[1] / "examples/postgres-relation-manifest/contract.yaml"
_DATABASE_NAME_PATTERN = re.compile(r"\Adfe_comparison_(?:reference|target)_[0-9a-f]{32}\Z")
_BUSINESS_DATE = date(2026, 9, 23)
_OUT_OF_SCOPE_DATE = date(2026, 9, 22)
_BASELINE_COMPLETED_AT = datetime(2026, 9, 23, 12, 30, 45, 123456, tzinfo=UTC)
_CORRUPT_COMPLETED_AT = datetime(2026, 9, 23, 13, 30, 45, 123456, tzinfo=UTC)
_BASELINE_SOURCE_CUT = "orders-cut-baseline"
_CORRUPT_SOURCE_CUT = "orders-cut-corrupt"
_REFERENCE_BASELINE_BATCH = "reference-orders-baseline"
_TARGET_BASELINE_BATCH = "target-orders-baseline"
_REFERENCE_CORRUPT_BATCH = "reference-orders-corrupt"
_TARGET_CORRUPT_BATCH = "target-orders-corrupt"
_NO_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_SOURCE_RETRY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)


@dataclass(frozen=True, slots=True)
class _SourceDatabaseSettings:
    database_name: str
    admin: PostgresConnectionSettings
    writer: PostgresConnectionSettings
    reader: PostgresConnectionSettings


@dataclass(frozen=True, slots=True)
class _AcquiredSide:
    context: PostgresProtectedReadContext
    dataset_relation: PostgresProtectedRelationInspection
    readiness_relation: PostgresProtectedRelationInspection
    evidence: RelationManifestEvidence


def test_postgres_integer_range_comparison_persists_baseline_and_corruption() -> None:
    metadata_request = required_metadata_database_settings()
    reference_request = _new_source_database_settings("reference")
    target_request = _new_source_database_settings("target")
    with (
        disposable_metadata_database(metadata_request) as metadata,
        _disposable_source_database(reference_request) as reference,
        _disposable_source_database(target_request) as target,
    ):
        migrate_postgres_metadata(metadata.migrator, _NO_RETRY, 5_000)
        config = load_contract_config(_CONTRACT_PATH)
        check = config.checks[0]
        registration = register_postgres_metadata(
            metadata.writer,
            _NO_RETRY,
            build_metadata_registration_definition(config.version, check, config.evidence),
        )
        scope = resolve_scope_values(check, {"business_date": "2026-09-23"})
        _seed_source_database(
            reference,
            "reference_orders",
            registration.reference_dataset.definition.dataset_id,
            scope.scope_digest,
            _REFERENCE_BASELINE_BATCH,
            _BASELINE_SOURCE_CUT,
            "reference-orders-v1",
            "900.00",
        )
        _seed_source_database(
            target,
            "target_orders",
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
            _TARGET_BASELINE_BATCH,
            _BASELINE_SOURCE_CUT,
            "target-orders-v1",
            "901.00",
        )

        baseline, baseline_readback = _execute_completed_comparison(
            metadata,
            reference.reader,
            target.reader,
            registration,
            check,
            scope,
            config.execution,
            config.evidence,
            _REFERENCE_BASELINE_BATCH,
            _TARGET_BASELINE_BATCH,
        )
        assert baseline_readback == baseline
        _assert_baseline_result(baseline, check, scope, config.execution)

        _advance_reference_manifest(
            reference,
            registration.reference_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        _corrupt_target_and_advance_manifest(
            target,
            registration.target_dataset.definition.dataset_id,
            scope.scope_digest,
        )
        corrupt, corrupt_readback = _execute_completed_comparison(
            metadata,
            reference.reader,
            target.reader,
            registration,
            check,
            scope,
            config.execution,
            config.evidence,
            _REFERENCE_CORRUPT_BATCH,
            _TARGET_CORRUPT_BATCH,
        )
        assert corrupt_readback == corrupt
        assert corrupt.run_id != baseline.run_id
        assert corrupt.attempt_id != baseline.attempt_id
        _assert_corrupt_result(corrupt, check, scope, config.execution)


def _new_source_database_settings(
    database_label: Literal["reference", "target"],
) -> _SourceDatabaseSettings:
    database_name = f"dfe_comparison_{database_label}_{uuid4().hex}"
    admin = required_connection_settings(
        "DFE_TEST_POSTGRES_ADMIN_DSN",
        f"forensic-data-comparison-{database_label}-admin",
    )
    writer = required_connection_settings(
        "DFE_TEST_POSTGRES_WRITER_DSN",
        f"forensic-data-comparison-{database_label}-writer",
    )
    reader = required_connection_settings(
        "DFE_TEST_POSTGRES_READER_DSN",
        f"forensic-data-comparison-{database_label}-reader",
    )
    return _SourceDatabaseSettings(
        database_name=database_name,
        admin=_for_database(admin, database_name),
        writer=_for_database(writer, database_name),
        reader=_with_statement_timeout(_for_database(reader, database_name), 30_000),
    )


@contextmanager
def _disposable_source_database(
    settings: _SourceDatabaseSettings,
) -> Generator[_SourceDatabaseSettings, None, None]:
    if _DATABASE_NAME_PATTERN.fullmatch(settings.database_name) is None:
        raise ValueError(
            "comparison source database name must use the generated role and UUID form"
        )
    cluster_admin = required_connection_settings(
        "DFE_TEST_POSTGRES_ADMIN_DSN",
        "forensic-data-comparison-cluster-admin",
    )
    created = False
    try:
        with connect_writer(cluster_admin) as connection:
            connection.execute(
                sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'UTF8'").format(
                    sql.Identifier(settings.database_name),
                    sql.Identifier("dfe_fixture_writer"),
                )
            )
            created = True
            connection.execute(
                sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
                    sql.Identifier(settings.database_name)
                )
            )
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}, {}").format(
                    sql.Identifier(settings.database_name),
                    sql.Identifier("dfe_fixture_writer"),
                    sql.Identifier("dfe_fixture_reader"),
                )
            )
        yield settings
    finally:
        if created:
            with connect_writer(cluster_admin) as connection:
                connection.execute(
                    sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                        sql.Identifier(settings.database_name)
                    )
                )


def _for_database(
    settings: PostgresConnectionSettings,
    database_name: str,
) -> PostgresConnectionSettings:
    return PostgresConnectionSettings(
        host=settings.host,
        port=settings.port,
        dbname=database_name,
        user=settings.user,
        password=settings.password,
        sslmode=settings.sslmode,
        connect_timeout_seconds=settings.connect_timeout_seconds,
        statement_timeout_milliseconds=settings.statement_timeout_milliseconds,
        application_name=settings.application_name,
    )


def _with_statement_timeout(
    settings: PostgresConnectionSettings,
    statement_timeout_milliseconds: int,
) -> PostgresConnectionSettings:
    return PostgresConnectionSettings(
        host=settings.host,
        port=settings.port,
        dbname=settings.dbname,
        user=settings.user,
        password=settings.password,
        sslmode=settings.sslmode,
        connect_timeout_seconds=settings.connect_timeout_seconds,
        statement_timeout_milliseconds=statement_timeout_milliseconds,
        application_name=settings.application_name,
    )


def _seed_source_database(
    settings: _SourceDatabaseSettings,
    relation_name: Literal["reference_orders", "target_orders"],
    dataset_id: str,
    scope_digest: str,
    batch_id: str,
    source_cut: str,
    dataset_version: str,
    sentinel_amount: str,
) -> None:
    relation = sql.Identifier("dfe_demo", relation_name)
    key_type = (
        sql.SQL("numeric(21, 2)") if relation_name == "reference_orders" else sql.SQL("bigint")
    )
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            connection.execute("CREATE SCHEMA dfe_demo")
            connection.execute("CREATE SCHEMA dfe_control")
            connection.execute(
                sql.SQL(
                    "CREATE TABLE {} ("
                    "order_id {} PRIMARY KEY, "
                    "business_date date NOT NULL, "
                    "amount numeric(18, 2) NOT NULL)"
                ).format(relation, key_type)
            )
            connection.execute(
                "CREATE TABLE dfe_control.batch_manifest ("
                "dataset_id text NOT NULL, scope_digest text NOT NULL, batch_id text NOT NULL, "
                "state text NOT NULL, business_date date NOT NULL, source_cut text, "
                "dataset_version text, completed_at timestamp(6) with time zone, "
                "PRIMARY KEY (dataset_id, scope_digest))"
            )
            connection.execute(
                sql.SQL(
                    "INSERT INTO {} (order_id, business_date, amount) "
                    "SELECT (dfe_seed.value * 2)::bigint, %s, 100.00::numeric(18, 2) "
                    "FROM pg_catalog.generate_series(1, 1000) AS dfe_seed(value) "
                    "UNION ALL "
                    "SELECT (1000000 + dfe_seed.value)::bigint, %s, "
                    "100.00::numeric(18, 2) "
                    "FROM pg_catalog.generate_series(1, 999000) AS dfe_seed(value)"
                ).format(relation),
                (_BUSINESS_DATE, _BUSINESS_DATE),
            )
            connection.execute(
                sql.SQL(
                    "INSERT INTO {} (order_id, business_date, amount) VALUES (1, %s, %s)"
                ).format(relation),
                (_OUT_OF_SCOPE_DATE, sentinel_amount),
            )
            connection.execute(sql.SQL("ANALYZE {}").format(relation))
            connection.execute(
                "INSERT INTO dfe_control.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) "
                "VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                (
                    dataset_id,
                    scope_digest,
                    batch_id,
                    _BUSINESS_DATE,
                    source_cut,
                    dataset_version,
                    _BASELINE_COMPLETED_AT,
                ),
            )
            connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_fixture_reader")
            connection.execute(
                sql.SQL("GRANT SELECT ON {}, {} TO dfe_fixture_reader").format(
                    relation,
                    sql.Identifier("dfe_control", "batch_manifest"),
                )
            )


def _advance_reference_manifest(
    settings: _SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        connection.execute(
            "UPDATE dfe_control.batch_manifest "
            "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
            "WHERE dataset_id = %s AND scope_digest = %s",
            (
                _REFERENCE_CORRUPT_BATCH,
                _CORRUPT_SOURCE_CUT,
                "reference-orders-v2",
                _CORRUPT_COMPLETED_AT,
                dataset_id,
                scope_digest,
            ),
        )


def _corrupt_target_and_advance_manifest(
    settings: _SourceDatabaseSettings,
    dataset_id: str,
    scope_digest: str,
) -> None:
    with connect_writer(settings.writer) as connection:
        with connection.transaction():
            connection.execute(
                "DELETE FROM dfe_demo.target_orders "
                "WHERE business_date = %s AND order_id BETWEEN 1000 AND 1040",
                (_BUSINESS_DATE,),
            )
            connection.execute(
                "UPDATE dfe_demo.target_orders SET amount = amount + 10.00 "
                "WHERE business_date = %s AND order_id BETWEEN 1100 AND 1122",
                (_BUSINESS_DATE,),
            )
            connection.execute(
                "INSERT INTO dfe_demo.target_orders (order_id, business_date, amount) VALUES "
                "(1201, %s, 50.00), (1203, %s, 50.00), "
                "(1205, %s, 50.00), (1207, %s, 50.00)",
                (_BUSINESS_DATE, _BUSINESS_DATE, _BUSINESS_DATE, _BUSINESS_DATE),
            )
            connection.execute(
                "UPDATE dfe_control.batch_manifest "
                "SET batch_id = %s, source_cut = %s, dataset_version = %s, completed_at = %s "
                "WHERE dataset_id = %s AND scope_digest = %s",
                (
                    _TARGET_CORRUPT_BATCH,
                    _CORRUPT_SOURCE_CUT,
                    "target-orders-v2",
                    _CORRUPT_COMPLETED_AT,
                    dataset_id,
                    scope_digest,
                ),
            )


def _run_request(
    registration: MetadataRegistration,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
    reference_batch_id: str,
    target_batch_id: str,
) -> RunRequestDefinition:
    return build_run_request_definition(
        request_id=uuid4(),
        contract_version_id=registration.contract.contract_version_id,
        origin="pytest",
        check=check,
        scope=scope,
        reference_expected_batch_id=reference_batch_id,
        target_expected_batch_id=target_batch_id,
        execution_policy=execution_policy,
        evidence_policy=evidence_policy,
    )


def _claim_and_start_attempt(
    settings: MetadataDatabaseSettings,
    registration: MetadataRegistration,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
    reference_batch_id: str,
    target_batch_id: str,
) -> tuple[ClaimedRun, RunAttemptRecord]:
    request = _run_request(
        registration,
        check,
        scope,
        execution_policy,
        evidence_policy,
        reference_batch_id,
        target_batch_id,
    )
    run = claim_postgres_run(
        settings.writer,
        _NO_RETRY,
        uuid4(),
        uuid4(),
        request,
    )
    attempt = start_postgres_run_attempt(
        settings.writer,
        _NO_RETRY,
        run,
        uuid4(),
        uuid4(),
        uuid4(),
        datetime.now(UTC) + timedelta(minutes=10),
        execution_policy,
    )
    return run, attempt


def _execute_completed_comparison(
    metadata: MetadataDatabaseSettings,
    reference_settings: PostgresConnectionSettings,
    target_settings: PostgresConnectionSettings,
    registration: MetadataRegistration,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
    reference_batch_id: str,
    target_batch_id: str,
) -> tuple[RunResult, RunResult]:
    run, attempt = _claim_and_start_attempt(
        metadata,
        registration,
        check,
        scope,
        execution_policy,
        evidence_policy,
        reference_batch_id,
        target_batch_id,
    )
    reference = _acquire_side(
        reference_settings,
        check,
        PlanDirection.REFERENCE,
        scope.scope_digest,
        reference_batch_id,
    )
    try:
        target = _acquire_side(
            target_settings,
            check,
            PlanDirection.TARGET,
            scope.scope_digest,
            target_batch_id,
        )
        try:
            persisted_reference = persist_postgres_read_context(
                metadata.writer,
                _NO_RETRY,
                attempt,
                _context_definition(
                    registration.reference_dataset,
                    PlanDirection.REFERENCE,
                    reference,
                ),
            )
            persisted_target = persist_postgres_read_context(
                metadata.writer,
                _NO_RETRY,
                attempt,
                _context_definition(
                    registration.target_dataset,
                    PlanDirection.TARGET,
                    target,
                ),
            )
            input_cut = build_input_cut_definition(reference.evidence, target.evidence)
            persisted_cut = persist_postgres_aligned_input_cut(
                metadata.writer,
                _NO_RETRY,
                attempt,
                _cut_persistence(
                    input_cut,
                    registration,
                    reference,
                    target,
                ),
            )
            artifact = execute_postgres_integer_key_comparison(
                reference.context,
                reference.dataset_relation,
                target.context,
                target.dataset_relation,
                check,
                scope,
                input_cut,
                execution_policy,
            )
            assert artifact.reference_full_scans <= execution_policy.max_full_scans_per_side
            assert artifact.target_full_scans <= execution_policy.max_full_scans_per_side
        finally:
            target.context.close()
    finally:
        reference.context.close()

    contexts_closed_at = datetime.now(UTC)
    close_postgres_read_context(
        metadata.writer,
        _NO_RETRY,
        attempt,
        persisted_reference.read_context_id,
        uuid4(),
        contexts_closed_at,
    )
    close_postgres_read_context(
        metadata.writer,
        _NO_RETRY,
        attempt,
        persisted_target.read_context_id,
        uuid4(),
        contexts_closed_at,
    )
    comparison, segments = completed_comparison_persistence_from_artifact(
        attempt,
        persisted_cut,
        artifact,
    )
    published = publish_postgres_completed_comparison(
        metadata.writer,
        _NO_RETRY,
        attempt,
        uuid4(),
        comparison,
        segments,
        datetime.now(UTC),
    )
    readback = read_postgres_completed_comparison(
        metadata.reader,
        _NO_RETRY,
        run.run_id,
        attempt.attempt_id,
    )
    return published, readback


def _acquire_side(
    settings: PostgresConnectionSettings,
    check: RowCheckDefinition,
    direction: PlanDirection,
    scope_digest: str,
    batch_id: str,
) -> _AcquiredSide:
    dataset = check.reference if direction is PlanDirection.REFERENCE else check.target
    consistency = check.consistency.datasets[0 if direction is PlanDirection.REFERENCE else 1]
    readiness = consistency.readiness
    assert isinstance(dataset.locator, RelationLocator)
    assert isinstance(readiness, RelationManifestReadiness)
    dataset_relation = PostgresRelation(components=(dataset.locator.schema, dataset.locator.name))
    readiness_relation = PostgresRelation(
        components=(readiness.relation.schema, readiness.relation.name)
    )
    context = open_postgres_protected_read_context(
        settings,
        _SOURCE_RETRY,
        (
            _acquisition(
                dataset.logical_schema.schema,
                dataset_relation,
                tuple(item.column_name for item in dataset.projection),
            ),
            _acquisition(_manifest_schema(), readiness_relation, readiness.columns.values()),
        ),
        2_000,
    )
    dataset_protected = _protected_relation(context.protected_relations, dataset_relation)
    readiness_protected = _protected_relation(context.protected_relations, readiness_relation)
    rows = context.read_relation_manifest(
        readiness_protected,
        readiness.columns,
        dataset.dataset_id,
        scope_digest,
        4_096,
        32_768,
    )
    evidence = validate_relation_manifest_readiness(
        direction=direction,
        rows=rows,
        expected_dataset_id=dataset.dataset_id,
        expected_scope_digest=scope_digest,
        expected_batch_id=batch_id,
        alignment_fields=check.consistency.alignment_fields,
        minimum_evidence=check.consistency.minimum_evidence,
        late_arrivals=check.consistency.late_arrivals,
    )
    assert isinstance(evidence, RelationManifestEvidence)
    return _AcquiredSide(context, dataset_protected, readiness_protected, evidence)


def _protected_relation(
    protected: tuple[PostgresProtectedRelationInspection, ...],
    relation: PostgresRelation,
) -> PostgresProtectedRelationInspection:
    for item in protected:
        if item.inspection.relation == relation:
            return item
    raise AssertionError(f"protected relation is missing: {relation.components!r}")


def _acquisition(
    schema: CanonicalSchema,
    relation: PostgresRelation,
    columns: tuple[str, ...],
) -> PostgresRelationAcquisition:
    return PostgresRelationAcquisition(
        schema=schema,
        relation=relation,
        column_names=columns,
        max_metadata_record_bytes=4_096,
        max_metadata_total_bytes=32_768,
    )


def _manifest_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            _string_field("dataset_id", False),
            _string_field("scope_digest", False),
            _string_field("batch_id", False),
            _string_field("state", False),
            FieldSchema(
                name="business_date",
                logical_type=LogicalType.DATE,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            _string_field("source_cut", True),
            _string_field("dataset_version", True),
            FieldSchema(
                name="completed_at",
                logical_type=LogicalType.TIMESTAMP_INSTANT,
                nullable=True,
                parameters=TimestampParameters(precision=6),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _string_field(name: str, nullable: bool) -> FieldSchema:
    return FieldSchema(
        name=name,
        logical_type=LogicalType.STRING,
        nullable=nullable,
        parameters=NoParameters(),
        normalization=Normalization.NONE,
    )


def _context_definition(
    dataset: DatasetVersionRecord,
    direction: PlanDirection,
    acquired: _AcquiredSide,
) -> ReadContextPersistence:
    return ReadContextPersistence(
        acquisition_operation_id=uuid4(),
        dataset=dataset,
        direction=direction,
        protected_context=acquired.context,
    )


def _cut_persistence(
    cut: InputCutDefinition,
    registration: MetadataRegistration,
    reference: _AcquiredSide,
    target: _AcquiredSide,
) -> AlignedInputCutPersistence:
    recorded_at = datetime.now(UTC)
    reference_for_cut = replace(
        reference,
        evidence=replace(
            reference.evidence,
            late_arrivals=cut.late_arrivals,
            cut=cut.reference,
        ),
    )
    target_for_cut = replace(
        target,
        evidence=replace(
            target.evidence,
            late_arrivals=cut.late_arrivals,
            cut=cut.target,
        ),
    )
    return AlignedInputCutPersistence(
        cut_binding_operation_id=uuid4(),
        attempt_cut_operation_id=uuid4(),
        input_cut=cut,
        reference=_observation(
            registration.reference_dataset,
            PlanDirection.REFERENCE,
            reference_for_cut,
            recorded_at,
        ),
        target=_observation(
            registration.target_dataset,
            PlanDirection.TARGET,
            target_for_cut,
            recorded_at,
        ),
        recorded_at=recorded_at,
    )


def _observation(
    dataset: DatasetVersionRecord,
    direction: PlanDirection,
    acquired: _AcquiredSide,
    observed_at: datetime,
) -> RelationManifestObservationPersistence:
    return RelationManifestObservationPersistence(
        observation_id=uuid4(),
        observation_operation_id=uuid4(),
        dataset=dataset,
        direction=direction,
        readiness=acquired.evidence,
        protected_context=acquired.context,
        dataset_relation=acquired.dataset_relation,
        readiness_relation=acquired.readiness_relation,
        projection_code_artifact=None,
        observed_at=observed_at,
    )


def _assert_common_completed_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    assert result.check_id == check.check_id
    assert result.contract_digest == check.contract_digest
    assert result.scope_digest == scope.scope_digest
    assert result.execution_status is ExecutionStatus.COMPLETED
    assert result.guarantee is Guarantee.FINGERPRINT
    assert result.consistency.stable_reads is ConsistencyLevel.VERIFIED
    assert result.consistency.cut_alignment is ConsistencyLevel.VERIFIED
    assert len(result.consistency.read_context_ids) == 2
    assert result.comparison_coverage.total_partitions == 1
    assert result.comparison_coverage.covered_partitions == 1
    assert result.comparison_coverage.pruned_segments > 0
    assert result.comparison_coverage.unresolved_segments == 0
    assert result.comparison_coverage.unresolved_reasons == ()
    assert result.evidence_coverage.retained_records == 0
    assert result.evidence_coverage.retained_bytes == 0
    assert result.metrics.queries <= execution_policy.max_queries
    assert result.metrics.fetched_records <= execution_policy.max_fetched_records
    assert result.metrics.result_bytes <= execution_policy.max_application_result_bytes
    assert result.metrics.fingerprint_nodes <= execution_policy.max_fingerprint_nodes
    assert result.metrics.coordinator_peak_bytes <= execution_policy.max_coordinator_memory_bytes
    assert result.metrics.elapsed_milliseconds <= execution_policy.run_timeout_milliseconds
    assert result.persistence.state is PersistenceState.CONFIRMED
    assert result.persistence.operation_id is not None
    assert result.persistence.reason is None


def _assert_baseline_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    _assert_common_completed_result(result, check, scope, execution_policy)
    assert result.verdict is Verdict.MATCH
    assert exit_code_for_result(result) is ExitCode.MATCH
    assert result.comparison_coverage.exact_segments == 0
    assert result.totals == ComparisonTotals(
        matched=InferredTotal(precision="inferred_under_fingerprint", value="1000000"),
        missing=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        extra=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        modified=InferredTotal(precision="inferred_under_fingerprint", value="0"),
    )
    assert result.evidence_coverage.found_records == 0
    assert result.evidence_coverage.found_bytes == 0
    assert result.reasons == ()


def _assert_corrupt_result(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    execution_policy: ExecutionBudgets,
) -> None:
    _assert_common_completed_result(result, check, scope, execution_policy)
    assert result.verdict is Verdict.MISMATCH
    assert exit_code_for_result(result) is ExitCode.MISMATCH
    assert result.comparison_coverage.exact_segments > 0
    assert result.totals == ComparisonTotals(
        matched=InferredTotal(precision="inferred_under_fingerprint", value="999967"),
        missing=InferredTotal(precision="inferred_under_fingerprint", value="21"),
        extra=InferredTotal(precision="inferred_under_fingerprint", value="4"),
        modified=InferredTotal(precision="inferred_under_fingerprint", value="12"),
    )
    assert result.evidence_coverage.found_records == 37
    assert result.evidence_coverage.found_bytes == 0
    assert tuple(reason.code for reason in result.reasons) == (ReasonCode.DATA_MISMATCH,)
