# pyright: reportPrivateUsage=false

from contextlib import ExitStack, closing
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pyodbc
import pytest

from forensic_data.application import (
    DiffRequest,
    ExecuteCheckRequest,
    MssqlPostgresExecutionServices,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    read_diff,
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
from forensic_data.contracts import load_contract_config
from forensic_data.contracts.model import LoadedContractConfig, RelationScope, RowCheckDefinition
from forensic_data.contracts.semantics import (
    SemanticValue,
    canonical_semantic_json,
    canonicalize_semantic_json,
)
from forensic_data.mssql import (
    MssqlContextLostError,
    MssqlDataValidationError,
    MssqlMetadataError,
    MssqlProtectedReadContext,
    MssqlReadContextState,
    MssqlRelationAcquisition,
)
from forensic_data.mssql_legacy import open_mssql_2016_protected_read_context
from forensic_data.mssql_resources import (
    MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256,
    MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES,
    load_mssql_2016_canonical_utf8_helper_sql,
)
from forensic_data.mssql_sql import MssqlInspectedRelation, MssqlRelation
from forensic_data.persistence.postgres import migrate_postgres_metadata
from forensic_data.planning import resolve_scope_values
from forensic_data.postgres import (
    PostgresIntegerExactRowsRead,
    PostgresIntegerRangeRequest,
    PostgresRangeFingerprintRead,
    PostgresRetryPolicy,
    PostgresSourceDirection,
)
from forensic_data.reporting import DetailAvailability
from forensic_data.result import (
    ExecutionStatus,
    Guarantee,
    PersistenceState,
    Verdict,
)
from tests import test_postgres_comparison_integration as pg_comparison
from tests.metadata_postgres_support import (
    MetadataDatabaseSettings,
    disposable_metadata_database,
    required_metadata_database_settings,
)
from tests.mssql_2016_support import (
    connect_fixture_admin,
    connect_setup_writer,
    required_reader_settings,
    single_attempt_retry_policy,
)
from tests.postgres_support import connect_writer, source_budget_attempt

pytestmark = [pytest.mark.integration, pytest.mark.mssql, pytest.mark.mssql_legacy]

_CONTRACT_PATH = Path(__file__).parent / "fixtures/mssql-2016/comparison-contract.yaml"
_BUSINESS_DATE = date(2026, 9, 23)
_BUSINESS_DATE_TEXT = "2026-09-23"
_REFERENCE_BATCH = "mssql-2016-reference-batch"
_TARGET_BATCH = "mssql-2016-target-batch"
_SOURCE_CUT = "mssql-2016-cut"
_HELPER_SHA256 = MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256.hex()
_UNICODE_ORACLE = "😀|é|e\u0301|tail  "
_CYRILLIC_ORACLE = "Привет"
_NO_POSTGRES_RETRY = PostgresRetryPolicy(max_attempts=1, delay_seconds=0.0)
_SOURCE_POSTGRES_RETRY = PostgresRetryPolicy(max_attempts=2, delay_seconds=0.0)
_SCOPE_VALUES = (ScopeValue(name="business_date", value=_BUSINESS_DATE_TEXT),)
_METADATA_RECORD_BYTES = 8_192
_METADATA_TOTAL_BYTES = 65_536
_MAX_ENVELOPE_BYTES = 4_096
_MAX_RESULT_BYTES = 65_536


@pytest.mark.postgres
def test_mssql_2016_source_to_postgres_17_is_exact_and_persists_helper_evidence() -> None:
    _restore_canonical_helper()
    _replace_comparison_tables()
    try:
        metadata_request = required_metadata_database_settings()
        target_request = pg_comparison._new_source_database_settings("target")
        with (
            disposable_metadata_database(metadata_request) as metadata,
            pg_comparison._disposable_source_database(target_request) as target,
        ):
            migrate_postgres_metadata(metadata.migrator, _NO_POSTGRES_RETRY, 5_000)
            config = load_contract_config(_CONTRACT_PATH)
            check = config.checks[0]
            scope = resolve_scope_values(
                check,
                {"business_date": _BUSINESS_DATE_TEXT},
            )
            _seed_mssql_comparison(scope.scope_digest)
            _seed_postgres_target(target, scope.scope_digest)

            result = execute_check(
                config,
                ExecuteCheckRequest(
                    request_id=uuid4(),
                    check_id=check.check_id,
                    scope_values=_SCOPE_VALUES,
                    reference_expected_batch_id=_REFERENCE_BATCH,
                    target_expected_batch_id=_TARGET_BATCH,
                    origin="mssql-2016-postgres-17-integration",
                ),
                _execution_services(config, metadata, target, check),
            )

            assert result.execution_status is ExecutionStatus.COMPLETED, result.model_dump_json(
                indent=2
            )
            assert result.verdict is Verdict.MISMATCH
            assert result.guarantee is Guarantee.EXACT
            assert result.persistence.state is PersistenceState.CONFIRMED
            assert tuple(
                (total.precision, total.value)
                for total in (
                    result.totals.matched,
                    result.totals.modified,
                    result.totals.missing,
                    result.totals.extra,
                )
            ) == (("exact", "1"), ("exact", "1"), ("exact", "1"), ("exact", "1"))
            assert result.evidence_coverage.found_records == 3
            assert result.evidence_coverage.retained_records == 3

            _assert_comparison_details(config, metadata, result.run_id, result.attempt_id)
            _assert_mssql_2016_persistence(metadata, result.run_id, result.attempt_id)
    finally:
        _drop_comparison_tables()


def test_mssql_2016_protected_context_rejects_lossy_values_and_helper_drift() -> None:
    _restore_canonical_helper()
    _replace_lifecycle_table()
    with ExitStack() as cleanup:
        cleanup.callback(_drop_lifecycle_table)
        cleanup.callback(_restore_canonical_helper)
        _seed_lifecycle_rows()
        context = _open_lifecycle_context("dfe-mssql-2016-lifecycle-reader")
        cleanup.callback(context.close)
        protected = context.protected_relations[0]
        assert context.evidence.strategy == "transaction_snapshot"
        assert context.evidence.transaction_count == 1
        assert context.evidence.transaction_state == 1
        assert context.evidence.transaction_isolation_level == 5
        assert context.state is MssqlReadContextState.ACTIVE

        summary = context.read_integer_key_summary(
            protected,
            0,
            None,
            _MAX_ENVELOPE_BYTES,
            4_096,
            _MAX_RESULT_BYTES,
            context.source_budget.read_deadline(60_000),
            1,
        ).summary
        assert (
            summary.row_count,
            summary.null_key_count,
            summary.invalid_key_count,
            summary.valid_key_count,
            summary.distinct_key_count,
            summary.minimum_key,
            summary.maximum_key,
            summary.usable_access_path,
        ) == (5, 0, 0, 5, 5, 1, 5, True)

        initial_fingerprint = _read_lifecycle_fingerprint(context, protected, 1, 3)
        assert initial_fingerprint.ranges[0].fingerprint.count == 2
        initial_rows = _read_lifecycle_rows(context, protected, 1, 3)
        assert tuple(row.values for row in initial_rows.rows) == (
            (1, "snapshot-seed", "2026-09-24T01:02:03.123456"),
            (2, None, None),
        )

        _update_lifecycle_seed_row()
        assert _read_lifecycle_fingerprint(context, protected, 1, 3).ranges == (
            initial_fingerprint.ranges
        )
        assert _read_lifecycle_rows(context, protected, 1, 3).rows == initial_rows.rows

        for lower_inclusive, upper_exclusive in ((3, 4), (4, 5), (5, 6)):
            with pytest.raises(MssqlDataValidationError, match="invalid_row_count=1"):
                _read_lifecycle_fingerprint(
                    context,
                    protected,
                    lower_inclusive,
                    upper_exclusive,
                )
            assert context.state is MssqlReadContextState.ACTIVE

        assert _read_lifecycle_fingerprint(context, protected, 1, 3).ranges == (
            initial_fingerprint.ranges
        )
        _alter_canonical_helper()
        with pytest.raises(MssqlMetadataError, match="provenance"):
            _read_lifecycle_fingerprint(context, protected, 1, 3)
        assert context.state is MssqlReadContextState.LOST
        with pytest.raises(MssqlContextLostError, match="was lost"):
            _read_lifecycle_fingerprint(context, protected, 1, 3)

        context.close()
        _restore_canonical_helper()
        restored_context = _open_lifecycle_context("dfe-mssql-2016-restored-reader")
        cleanup.callback(restored_context.close)
        restored = _read_lifecycle_rows(
            restored_context,
            restored_context.protected_relations[0],
            1,
            3,
        )
        assert tuple(row.values for row in restored.rows) == (
            (1, "snapshot-updated", "2026-09-24T01:02:03.654321"),
            (2, None, None),
        )


def _execution_services(
    config: LoadedContractConfig,
    metadata: MetadataDatabaseSettings,
    target: pg_comparison._SourceDatabaseSettings,
    check: RowCheckDefinition,
) -> MssqlPostgresExecutionServices:
    return MssqlPostgresExecutionServices(
        reference_connection_id=check.reference.connection.connection_id,
        reference_settings=required_reader_settings("dfe-mssql-2016-comparison-reader"),
        target_connection_id=check.target.connection.connection_id,
        target_settings=target.reader,
        metadata_connection_id=config.metadata.connection.connection_id,
        metadata_settings=metadata.writer,
        reference_retry_policy=single_attempt_retry_policy(),
        target_retry_policy=_SOURCE_POSTGRES_RETRY,
        metadata_retry_policy=_NO_POSTGRES_RETRY,
        protected_lock_timeout_milliseconds=2_000,
        metadata_record_bytes=_METADATA_RECORD_BYTES,
        metadata_total_bytes=_METADATA_TOTAL_BYTES,
    )


def _assert_comparison_details(
    config: LoadedContractConfig,
    metadata: MetadataDatabaseSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> None:
    page = read_diff(
        DiffRequest(
            run_id=run_id,
            attempt_id=attempt_id,
            limit=10,
            cursor=None,
        ),
        PostgresMetadataServices(
            connection_id=config.metadata.connection.connection_id,
            settings=metadata.reader,
            retry_policy=_NO_POSTGRES_RETRY,
        ),
    )
    assert page.detail_availability is DetailAvailability.AVAILABLE
    assert len(page.details) == 3
    assert all(detail.omitted_field_names == ("business_date",) for detail in page.details)
    details_by_key = {detail.key_values[0].canonical_text: detail for detail in page.details}
    assert set(details_by_key) == {"1002", "1003", "1004"}

    modified = details_by_key["1002"]
    assert modified.kind.value == "modified"
    retained_fields = (
        "unicode_value",
        "legacy_value",
        "amount",
        "observed_at",
    )
    assert tuple(value.field_name for value in modified.reference_values) == retained_fields
    assert tuple(value.canonical_text for value in modified.reference_values) == (
        "modified-row",
        "Москва",
        "-9999999999999999999999999999999.7654321",
        "2026-09-23T02:03:04.654321",
    )
    assert tuple(value.field_name for value in modified.target_values) == retained_fields
    assert tuple(value.canonical_text for value in modified.target_values) == (
        "modified-row",
        "Москва",
        "-9999999999999999999999999999999.7654320",
        "2026-09-23T02:03:04.654321",
    )
    assert details_by_key["1003"].kind.value == "missing"
    assert details_by_key["1004"].kind.value == "extra"


def _assert_mssql_2016_persistence(
    metadata: MetadataDatabaseSettings,
    run_id: UUID,
    attempt_id: UUID,
) -> None:
    with connect_writer(metadata.reader) as connection:
        dataset = connection.execute(
            "SELECT driver, profile FROM dfe_metadata.dataset_versions "
            "WHERE dataset_id = 'reference_legacy_records'"
        ).fetchone()
        context = connection.execute(
            "SELECT engine, strategy, driver_version, server_version, "
            "server_version_number, state, "
            "acquisition_evidence ->> 'kind', "
            "acquisition_evidence #>> '{payload,driver,driver_name}', "
            "acquisition_evidence #>> '{payload,driver,driver_version}', "
            "acquisition_evidence #>> '{payload,driver,pyodbc_version}', "
            "acquisition_evidence #>> '{payload,profile,product_version}', "
            "acquisition_evidence #>> '{payload,profile,product_update_reference}', "
            "acquisition_evidence #>> '{payload,profile,compatibility_level}', "
            "acquisition_evidence #>> '{payload,profile,canonical_utf8_strategy}', "
            "acquisition_evidence #>> "
            "'{payload,profile,canonical_utf8_helper,definition_sha256}', "
            "acquisition_evidence #>> "
            "'{payload,profile,canonical_utf8_helper,database_collation}', "
            "acquisition_evidence #>> '{payload,context,transaction_count}', "
            "acquisition_evidence #>> '{payload,context,transaction_state}', "
            "acquisition_evidence #>> '{payload,context,transaction_isolation_level}', "
            "(acquisition_evidence #> "
            "'{payload,profile,canonical_utf8_helper}')::text, "
            "acquisition_evidence #>> "
            "'{payload,profile,canonical_utf8_helper,database_id}', "
            "acquisition_evidence #>> "
            "'{payload,profile,canonical_utf8_helper,schema_id}', "
            "acquisition_evidence #>> "
            "'{payload,profile,canonical_utf8_helper,object_id}' "
            "FROM dfe_metadata.attempt_read_contexts "
            "WHERE run_id = %s AND attempt_id = %s AND direction = 'reference'",
            (run_id, attempt_id),
        ).fetchone()
        binding_helper = connection.execute(
            "SELECT (physical_binding #> "
            "'{payload,profile,canonical_utf8_helper}')::text "
            "FROM dfe_metadata.dataset_observations "
            "WHERE run_id = %s AND attempt_id = %s AND direction = 'reference'",
            (run_id, attempt_id),
        ).fetchone()

    assert dataset == ("pyodbc", "mssql_2016")
    assert context is not None
    assert context[:19] == (
        "mssql",
        "transaction_snapshot",
        "5.3.0",
        "13.0.6500.1",
        13,
        "closed",
        "mssql_snapshot_relations",
        "libmsodbcsql-18.7.so.1.1",
        "18.07.0001",
        "5.3.0",
        "13.0.6500.1",
        "KB5102340",
        "130",
        "owner_installed_scalar_function_v1",
        _HELPER_SHA256,
        "Latin1_General_100_CI_AS_SC",
        "1",
        "1",
        "5",
    )
    helper_json, database_id_text, schema_id_text, object_id_text = context[19:23]
    assert type(helper_json) is str
    assert type(database_id_text) is str and database_id_text.isdecimal()
    assert type(schema_id_text) is str and schema_id_text.isdecimal()
    assert type(object_id_text) is str and object_id_text.isdecimal()
    expected_helper = _expected_helper_semantic_value(
        int(database_id_text),
        int(schema_id_text),
        int(object_id_text),
    )
    expected_helper_json = canonical_semantic_json(expected_helper)
    assert canonicalize_semantic_json(helper_json) == expected_helper_json
    assert binding_helper is not None and len(binding_helper) == 1
    binding_helper_json = binding_helper[0]
    assert type(binding_helper_json) is str
    assert canonicalize_semantic_json(binding_helper_json) == expected_helper_json


def _expected_helper_semantic_value(
    database_id: int,
    schema_id: int,
    object_id: int,
) -> dict[str, SemanticValue]:
    assert database_id > 0
    assert schema_id > 0
    assert object_id > 0
    return {
        "ansi_nulls": True,
        "ansi_padding": True,
        "ansi_warnings": True,
        "arithabort": True,
        "can_alter": False,
        "can_control": False,
        "can_execute": True,
        "can_view_definition": True,
        "concat_null_yields_null": True,
        "database_collation": "Latin1_General_100_CI_AS_SC",
        "database_compatibility_level": 130,
        "database_id": database_id,
        "database_name": "dfe_fixture",
        "definition_sha256": _HELPER_SHA256,
        "definition_utf16_bytes": MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES,
        "execute_as_principal_id": None,
        "input_has_default_value": False,
        "input_is_output": False,
        "input_max_length": -1,
        "input_parameter_name": "@value",
        "input_type_name": "nvarchar",
        "input_type_schema": "sys",
        "is_deterministic": True,
        "is_encrypted": False,
        "is_precise": True,
        "is_schema_bound": True,
        "null_on_null_input": True,
        "numeric_roundabort": False,
        "object_id": object_id,
        "object_name": "canonical_utf8_v1",
        "object_type": "FN",
        "quoted_identifier": True,
        "return_has_default_value": False,
        "return_is_output": True,
        "return_max_length": -1,
        "return_type_name": "varbinary",
        "return_type_schema": "sys",
        "schema_id": schema_id,
        "schema_name": "dfe_ext",
        "uses_ansi_nulls": True,
        "uses_database_collation": True,
        "uses_quoted_identifier": True,
    }


def _replace_comparison_tables() -> None:
    statement = (
        "SET XACT_ABORT ON; "
        "IF OBJECT_ID(N'dfe_fixture.legacy_batch_manifest', N'U') IS NOT NULL "
        "DROP TABLE [dfe_fixture].[legacy_batch_manifest]; "
        "IF OBJECT_ID(N'dfe_fixture.legacy_comparison_records', N'U') IS NOT NULL "
        "DROP TABLE [dfe_fixture].[legacy_comparison_records]; "
        "CREATE TABLE [dfe_fixture].[legacy_comparison_records] ("
        "[record_id] bigint NOT NULL PRIMARY KEY, "
        "[business_date] date NOT NULL, "
        "[unicode_value] nvarchar(256) COLLATE Latin1_General_100_BIN2 NULL, "
        "[legacy_value] varchar(256) COLLATE Cyrillic_General_100_CI_AS NOT NULL, "
        "[amount] decimal(38, 7) NOT NULL, "
        "[observed_at] datetime2(7) NOT NULL); "
        "CREATE TABLE [dfe_fixture].[legacy_batch_manifest] ("
        "[dataset_id] nvarchar(128) NOT NULL, "
        "[scope_digest] nvarchar(64) NOT NULL, "
        "[batch_id] nvarchar(128) NOT NULL, "
        "[state] nvarchar(32) NOT NULL, "
        "[business_date] date NOT NULL, "
        "[source_cut] nvarchar(128) NULL, "
        "[dataset_version] nvarchar(128) NULL, "
        "[completed_at] datetimeoffset(6) NULL, "
        "PRIMARY KEY ([dataset_id], [scope_digest]));"
    )
    _execute_admin_statement("dfe-mssql-2016-comparison-ddl", statement)


def _drop_comparison_tables() -> None:
    _execute_admin_statement(
        "dfe-mssql-2016-comparison-cleanup",
        "SET XACT_ABORT ON; "
        "IF OBJECT_ID(N'dfe_fixture.legacy_batch_manifest', N'U') IS NOT NULL "
        "DROP TABLE [dfe_fixture].[legacy_batch_manifest]; "
        "IF OBJECT_ID(N'dfe_fixture.legacy_comparison_records', N'U') IS NOT NULL "
        "DROP TABLE [dfe_fixture].[legacy_comparison_records];",
    )


def _seed_mssql_comparison(scope_digest: str) -> None:
    with closing(connect_setup_writer("dfe-mssql-2016-comparison-seed")) as connection:
        with connection:
            _insert_mssql_comparison_row(
                connection,
                1001,
                _UNICODE_ORACLE,
                _CYRILLIC_ORACLE,
                "1234567890123456789012345678901.2345678",
                "2026-09-23T01:02:03.1234560",
            )
            _insert_mssql_comparison_row(
                connection,
                1002,
                "modified-row",
                "Москва",
                "-9999999999999999999999999999999.7654321",
                "2026-09-23T02:03:04.6543210",
            )
            _insert_mssql_comparison_row(
                connection,
                1003,
                None,
                "Данные",
                "0.0000001",
                "2026-09-23T03:04:05.0000010",
            )
            connection.execute(
                "INSERT INTO [dfe_fixture].[legacy_batch_manifest] ("
                "[dataset_id], [scope_digest], [batch_id], [state], [business_date], "
                "[source_cut], [dataset_version], [completed_at]) "
                "VALUES (?, ?, ?, N'complete', CONVERT(date, ?, 23), ?, ?, "
                "CONVERT(datetimeoffset(6), N'2026-09-23T12:30:45.123456+00:00', 127))",
                "reference_legacy_records",
                scope_digest,
                _REFERENCE_BATCH,
                _BUSINESS_DATE_TEXT,
                _SOURCE_CUT,
                "mssql-2016-reference-v1",
            )
            row = connection.execute(
                "SELECT COUNT_BIG(*), "
                "MAX(CASE WHEN [record_id] = 1001 THEN "
                "CONVERT(varbinary(max), [legacy_value]) END) "
                "FROM [dfe_fixture].[legacy_comparison_records]"
            ).fetchone()
            if row is None or tuple(row) != (3, _CYRILLIC_ORACLE.encode("cp1251")):
                raise AssertionError(
                    "SQL Server 2016 comparison fixture did not preserve the Cyrillic bytes"
                )


def _insert_mssql_comparison_row(
    connection: pyodbc.Connection,
    record_id: int,
    unicode_value: str | None,
    legacy_value: str,
    amount_text: str,
    observed_at_text: str,
) -> None:
    connection.execute(
        "INSERT INTO [dfe_fixture].[legacy_comparison_records] ("
        "[record_id], [business_date], [unicode_value], [legacy_value], [amount], "
        "[observed_at]) VALUES (?, CONVERT(date, ?, 23), ?, ?, "
        "CONVERT(decimal(38, 7), ?), CONVERT(datetime2(7), ?, 126))",
        record_id,
        _BUSINESS_DATE_TEXT,
        unicode_value,
        legacy_value,
        amount_text,
        observed_at_text,
    )


def _seed_postgres_target(
    target: pg_comparison._SourceDatabaseSettings,
    scope_digest: str,
) -> None:
    with connect_writer(target.writer) as connection:
        with connection.transaction():
            connection.execute("CREATE SCHEMA dfe_demo")
            connection.execute("CREATE SCHEMA dfe_control")
            connection.execute(
                "CREATE TABLE dfe_demo.target_legacy_records ("
                "record_id bigint PRIMARY KEY, business_date date NOT NULL, "
                "unicode_value text NULL, legacy_value text NOT NULL, "
                "amount numeric(38, 7) NOT NULL, observed_at timestamp(6) NOT NULL)"
            )
            _insert_postgres_target_row(
                connection,
                1001,
                _UNICODE_ORACLE,
                _CYRILLIC_ORACLE,
                Decimal("1234567890123456789012345678901.2345678"),
                datetime(2026, 9, 23, 1, 2, 3, 123456),
            )
            _insert_postgres_target_row(
                connection,
                1002,
                "modified-row",
                "Москва",
                Decimal("-9999999999999999999999999999999.7654320"),
                datetime(2026, 9, 23, 2, 3, 4, 654321),
            )
            _insert_postgres_target_row(
                connection,
                1004,
                "extra-row",
                "Лишняя",
                Decimal("4.0000000"),
                datetime(2026, 9, 23, 4, 5, 6, 1),
            )
            connection.execute(
                "CREATE TABLE dfe_control.batch_manifest ("
                "dataset_id text NOT NULL, scope_digest text NOT NULL, "
                "batch_id text NOT NULL, state text NOT NULL, business_date date NOT NULL, "
                "source_cut text NULL, dataset_version text NULL, "
                "completed_at timestamp(6) with time zone NULL, "
                "PRIMARY KEY (dataset_id, scope_digest))"
            )
            connection.execute(
                "INSERT INTO dfe_control.batch_manifest ("
                "dataset_id, scope_digest, batch_id, state, business_date, source_cut, "
                "dataset_version, completed_at) VALUES (%s, %s, %s, 'complete', %s, %s, %s, %s)",
                (
                    "target_legacy_records",
                    scope_digest,
                    _TARGET_BATCH,
                    _BUSINESS_DATE,
                    _SOURCE_CUT,
                    "postgres-17-target-v1",
                    datetime(2026, 9, 23, 12, 30, 45, 123456, tzinfo=UTC),
                ),
            )
            connection.execute("ANALYZE dfe_demo.target_legacy_records")
            connection.execute("GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_fixture_reader")
            connection.execute(
                "GRANT SELECT ON dfe_demo.target_legacy_records, "
                "dfe_control.batch_manifest TO dfe_fixture_reader"
            )


def _insert_postgres_target_row(
    connection: psycopg.Connection[tuple[object, ...]],
    record_id: int,
    unicode_value: str,
    legacy_value: str,
    amount: Decimal,
    observed_at: datetime,
) -> None:
    connection.execute(
        "INSERT INTO dfe_demo.target_legacy_records ("
        "record_id, business_date, unicode_value, legacy_value, amount, observed_at) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (record_id, _BUSINESS_DATE, unicode_value, legacy_value, amount, observed_at),
    )


def _lifecycle_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="record_id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="unicode_value",
                logical_type=LogicalType.STRING,
                nullable=True,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
            FieldSchema(
                name="observed_at",
                logical_type=LogicalType.TIMESTAMP_LOCAL,
                nullable=True,
                parameters=TimestampParameters(precision=6),
                normalization=Normalization.NONE,
            ),
        ),
    )


def _open_lifecycle_context(application_name: str) -> MssqlProtectedReadContext:
    acquisition = MssqlRelationAcquisition(
        schema=_lifecycle_schema(),
        relation=MssqlRelation(
            schema_name="dfe_fixture",
            table_name="legacy_lifecycle_probe",
        ),
        relation_scope=RelationScope.PHYSICAL_ONLY,
        column_names=("record_id", "unicode_value", "observed_at"),
        max_metadata_record_bytes=_METADATA_RECORD_BYTES,
        max_metadata_total_bytes=_METADATA_TOTAL_BYTES,
    )
    return open_mssql_2016_protected_read_context(
        required_reader_settings(application_name),
        single_attempt_retry_policy(),
        (acquisition,),
        source_budget_attempt(),
        PostgresSourceDirection.REFERENCE,
    )


def _read_lifecycle_fingerprint(
    context: MssqlProtectedReadContext,
    protected: MssqlInspectedRelation,
    lower_inclusive: int,
    upper_exclusive: int,
) -> PostgresRangeFingerprintRead:
    return context.read_integer_range_fingerprints(
        protected,
        0,
        None,
        (
            PostgresIntegerRangeRequest(
                segment_id=f"range-{lower_inclusive}-{upper_exclusive}",
                lower_inclusive=lower_inclusive,
                upper_exclusive=upper_exclusive,
            ),
        ),
        _MAX_ENVELOPE_BYTES,
        4_096,
        _MAX_RESULT_BYTES,
        context.source_budget.read_deadline(60_000),
        1,
    )


def _read_lifecycle_rows(
    context: MssqlProtectedReadContext,
    protected: MssqlInspectedRelation,
    lower_inclusive: int,
    upper_exclusive: int,
) -> PostgresIntegerExactRowsRead:
    return context.read_integer_range_rows(
        protected,
        0,
        None,
        (
            PostgresIntegerRangeRequest(
                segment_id=f"range-{lower_inclusive}-{upper_exclusive}",
                lower_inclusive=lower_inclusive,
                upper_exclusive=upper_exclusive,
            ),
        ),
        _MAX_ENVELOPE_BYTES,
        10,
        8_192,
        _MAX_RESULT_BYTES,
        context.source_budget.read_deadline(60_000),
        1,
    )


def _replace_lifecycle_table() -> None:
    _execute_admin_statement(
        "dfe-mssql-2016-lifecycle-ddl",
        "SET XACT_ABORT ON; "
        "IF OBJECT_ID(N'dfe_fixture.legacy_lifecycle_probe', N'U') IS NOT NULL "
        "DROP TABLE [dfe_fixture].[legacy_lifecycle_probe]; "
        "CREATE TABLE [dfe_fixture].[legacy_lifecycle_probe] ("
        "[record_id] bigint NOT NULL PRIMARY KEY, "
        "[unicode_value] nvarchar(128) COLLATE Latin1_General_100_BIN2 NULL, "
        "[observed_at] datetime2(7) NULL);",
    )


def _drop_lifecycle_table() -> None:
    _execute_admin_statement(
        "dfe-mssql-2016-lifecycle-cleanup",
        "SET XACT_ABORT ON; "
        "IF OBJECT_ID(N'dfe_fixture.legacy_lifecycle_probe', N'U') IS NOT NULL "
        "DROP TABLE [dfe_fixture].[legacy_lifecycle_probe];",
    )


def _seed_lifecycle_rows() -> None:
    with closing(connect_setup_writer("dfe-mssql-2016-lifecycle-seed")) as connection:
        with connection:
            connection.execute(
                "INSERT INTO [dfe_fixture].[legacy_lifecycle_probe] "
                "([record_id], [unicode_value], [observed_at]) VALUES "
                "(1, N'snapshot-seed', "
                "CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234560', 126)), "
                "(2, NULL, NULL), "
                "(3, CONVERT(nvarchar(1), 0x0000), "
                "CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234560', 126)), "
                "(4, CONVERT(nvarchar(1), 0x3DD8), "
                "CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234560', 126)), "
                "(5, N'excess-precision', "
                "CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234567', 126))"
            )


def _update_lifecycle_seed_row() -> None:
    with closing(connect_setup_writer("dfe-mssql-2016-lifecycle-update")) as connection:
        with connection:
            cursor = connection.execute(
                "UPDATE [dfe_fixture].[legacy_lifecycle_probe] "
                "SET [unicode_value] = N'snapshot-updated', "
                "[observed_at] = "
                "CONVERT(datetime2(7), N'2026-09-24T01:02:03.6543210', 126) "
                "WHERE [record_id] = 1"
            )
            if cursor.rowcount != 1:
                raise AssertionError("SQL Server 2016 lifecycle update must affect exactly one row")


def _alter_canonical_helper() -> None:
    with closing(connect_fixture_admin("dfe-mssql-2016-helper-drift")) as connection:
        with connection:
            connection.execute("SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON;")
            connection.execute(
                "ALTER FUNCTION [dfe_ext].[canonical_utf8_v1] "
                "(@value nvarchar(max)) RETURNS varbinary(max) "
                "WITH SCHEMABINDING, RETURNS NULL ON NULL INPUT AS BEGIN "
                "RETURN CONVERT(varbinary(max), 0x00); END"
            )


def _restore_canonical_helper() -> None:
    batches = _sql_batches(load_mssql_2016_canonical_utf8_helper_sql())
    with closing(connect_fixture_admin("dfe-mssql-2016-helper-restore")) as connection:
        with connection:
            connection.execute(
                "IF OBJECT_ID(N'dfe_ext.canonical_utf8_v1', N'FN') IS NOT NULL "
                "DROP FUNCTION [dfe_ext].[canonical_utf8_v1]"
            )
            for batch in batches:
                connection.execute(batch)
            connection.execute(
                "GRANT EXECUTE ON OBJECT::[dfe_ext].[canonical_utf8_v1] "
                "TO [dfe_fixture_reader_role]"
            )
            connection.execute(
                "GRANT VIEW DEFINITION ON OBJECT::[dfe_ext].[canonical_utf8_v1] "
                "TO [dfe_fixture_reader_role]"
            )


def _sql_batches(sql_text: str) -> tuple[str, ...]:
    batches: list[str] = []
    current: list[str] = []
    for line in sql_text.splitlines(keepends=True):
        if line.rstrip("\r\n").strip().upper() == "GO":
            batch = "".join(current).strip()
            if batch:
                batches.append(batch)
            current = []
        else:
            current.append(line)
    batch = "".join(current).strip()
    if batch:
        batches.append(batch)
    return tuple(batches)


def _execute_admin_statement(application_name: str, statement: str) -> None:
    with closing(connect_fixture_admin(application_name)) as connection:
        with connection:
            connection.execute(statement)
