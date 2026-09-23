from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from forensic_data.canonical import LogicalType
from forensic_data.contracts import (
    ContractReferenceError,
    ContractValidationError,
    ContractYamlError,
    DuplicateYamlKeyError,
    ScopeValueError,
    SqlArtifactError,
    UnsupportedContractError,
    compile_contract,
    load_contract_config,
    load_contract_source,
)
from forensic_data.contracts.model import (
    Adapter,
    AssurancePolicy,
    ConnectionDefinition,
    ConnectionRole,
    RelationLocator,
    RowCheckDefinition,
    SqlArtifactDefinition,
    SqlDialect,
)
from forensic_data.planning import (
    EstimateStatus,
    PlanProbeStatus,
    PlanReport,
    PlanStageStatus,
    compile_static_plan,
)

_TARGET_SQL = b"SELECT order_id, business_date, amount AS amount_target FROM target_orders\r\n"
_REFERENCE_READINESS_SQL = b"SELECT 'ready' AS state WHERE %(business_date)s IS NOT NULL\n"
_TARGET_READINESS_SQL = b"SELECT 'ready' AS state WHERE %(business_date)s IS NOT NULL\n"

_VALID_CONTRACT = """\
version: 1
connections:
  source_pg:
    adapter: postgresql
    driver: psycopg
    profile: postgresql_17
    roles: [source]
    secret_ref: env:DFE_SOURCE_DSN
  target_pg:
    adapter: postgresql
    driver: psycopg
    profile: postgresql_17
    roles: [target]
    secret_ref: env:DFE_TARGET_DSN
  metadata_pg:
    adapter: postgresql
    driver: psycopg
    profile: postgresql_17
    roles: [metadata]
    secret_ref: env:DFE_METADATA_DSN
schemas:
  order_line_v1:
    fields:
      - name: order_id
        type: {kind: int64}
        nullable: false
        normalization: none
        equality: {kind: exact}
      - name: business_date
        type: {kind: date}
        nullable: false
        normalization: none
        equality: {kind: exact}
      - name: amount
        type: {kind: decimal, precision: 18, scale: 2}
        nullable: true
        normalization: none
        equality: {kind: exact}
datasets:
  legacy_orders:
    connection: source_pg
    relation: {catalog: null, schema: public, name: legacy_orders}
    logical_schema: order_line_v1
    projection:
      - {field: order_id, column: order_id}
      - {field: business_date, column: business_date}
      - {field: amount, column: amount}
    grain: [order_id]
  target_orders:
    connection: target_pg
    sql:
      path: sql/target.sql
      dialect: postgresql
      parameters:
        - {name: business_date, type: {kind: date}}
    logical_schema: order_line_v1
    projection:
      - {field: order_id, column: order_id_target}
      - {field: business_date, column: business_date_target}
      - {field: amount, column: amount_target}
    grain: [order_id]
scopes:
  daily_scope:
    parameters:
      business_date: {type: {kind: date}}
    bindings:
      legacy_orders: {column: business_date, operator: eq, parameter: business_date}
      target_orders: {column: business_date_target, operator: eq, parameter: business_date}
    null_partition: reject
checks:
  daily_orders:
    revision: 1
    invariant: row_equivalence
    reference: legacy_orders
    target: target_orders
    comparison_schema: order_line_v1
    key: [order_id]
    scope_ref: daily_scope
    consistency_policy: daily_cut
    assurance_policy: fingerprint_allowed
consistency:
  daily_cut:
    minimum_evidence: asserted
    alignment_fields: [business_date, source_cut]
    late_arrivals: next_batch
    datasets:
      legacy_orders:
        readiness:
          path: sql/reference_readiness.sql
          dialect: postgresql
          parameters:
            - {name: business_date, type: {kind: date}}
        stable_read: {kind: transaction_snapshot}
      target_orders:
        readiness:
          path: sql/target_readiness.sql
          dialect: postgresql
          parameters:
            - {name: business_date, type: {kind: date}}
        stable_read: {kind: transaction_snapshot}
execution:
  version: 1
  max_queries: 100
  max_fetched_records: 10000
  max_application_result_bytes: 1048576
  max_evidence_rows: 50
  max_evidence_bytes: 65536
  max_fingerprint_nodes: 1000
  max_coordinator_memory_bytes: 8388608
  max_depth: 8
  max_full_scans_per_side: 4
  statement_timeout_milliseconds: 30000
  run_timeout_milliseconds: 300000
  max_attempts: 2
  max_checks_concurrency: 2
  max_source_concurrency: 1
metadata:
  connection: metadata_pg
evidence:
  sql_capture: disabled
  ddl_capture: enabled
  fields:
    order_id: store
    amount: redact
  unspecified_fields: omit
"""


def test_contract_load_compile_and_static_plan_are_deterministic(tmp_path: Path) -> None:
    contract_path = _write_contract(tmp_path, _VALID_CONTRACT, _TARGET_SQL)
    source = load_contract_source(contract_path)

    assert "DFE_SOURCE_DSN" not in repr(source)
    assert "SELECT order_id" not in repr(source)
    assert "target.sql" not in repr(source)

    (tmp_path / "sql" / "target.sql").write_bytes(_TARGET_SQL + b"-- changed after capture\n")
    config = compile_contract(source)
    check = config.checks[0]
    plan = compile_static_plan(config, "daily_orders", {"business_date": "2026-09-23"})

    assert (
        check.comparison_schema.logical_schema_digest
        == "de67352bf0871ac5524178fcdb8dd3a3dc7636cea9bf6a114d5182c495105a7e"
    )
    assert (
        check.contract_digest == "84569fea8697e4d268eb015db98217cc72f44ac6ba63d2c417d422fab2a19e7b"
    )
    assert (
        check.reference.semantic_digest
        == "0f9bd195fdf323068442f0a9f07d5694ee0a98738b785875c18c3b144eb00abb"
    )
    assert (
        check.target.semantic_digest
        == "3b614b30bfd3ddd0f383d972989a65e2c8bd3bea5dede8c654deacf9d99ecf4f"
    )
    assert plan.scope_digest == "df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab"
    assert plan.reference.dataset_id == "legacy_orders"
    assert plan.target.dataset_id == "target_orders"
    assert plan.ordered_key == ("order_id",)
    assert all(probe.status is PlanProbeStatus.REQUIRED_NOT_RUN for probe in plan.probes)
    assert all(stage.status is PlanStageStatus.PLANNED_NOT_RUN for stage in plan.stages)
    assert all(estimate.status is EstimateStatus.UNKNOWN for estimate in plan.estimates)
    assert PlanReport.model_validate_json(plan.model_dump_json()) == plan
    assert "DFE_SOURCE_DSN" not in plan.model_dump_json()
    assert "SELECT order_id" not in plan.model_dump_json()
    assert str(tmp_path) not in plan.model_dump_json()

    reloaded = load_contract_config(contract_path)
    assert reloaded.checks[0].contract_digest != check.contract_digest


def test_contract_digest_tracks_semantics_but_not_operational_settings(tmp_path: Path) -> None:
    baseline = _load_check(tmp_path / "baseline", _VALID_CONTRACT, _TARGET_SQL)

    operational_text = _reorder_top_level(
        _VALID_CONTRACT.replace("env:DFE_SOURCE_DSN", "vault:source/rotated").replace(
            "max_queries: 100", "max_queries: 101"
        )
    )
    operational = _load_check(
        tmp_path / "operational",
        "# mapping order, comments, secrets, and budgets are non-semantic\n" + operational_text,
        _TARGET_SQL,
    )
    assert operational.contract_digest == baseline.contract_digest

    renamed_dependencies = _load_check(
        tmp_path / "renamed_dependencies",
        _VALID_CONTRACT.replace("order_line_v1", "renamed_schema")
        .replace("daily_scope", "renamed_scope")
        .replace("daily_cut", "renamed_consistency"),
        _TARGET_SQL,
    )
    assert renamed_dependencies.contract_digest == baseline.contract_digest

    renamed = _load_check(
        tmp_path / "renamed",
        _VALID_CONTRACT.replace("daily_orders:", "renamed_check:").replace(
            "revision: 1", "revision: 2"
        ),
        _TARGET_SQL,
    )
    assert renamed.contract_digest == baseline.contract_digest

    projection = _load_check(
        tmp_path / "projection",
        _VALID_CONTRACT.replace("column: amount_target", "column: amount_target_v2"),
        _TARGET_SQL,
    )
    assert projection.contract_digest != baseline.contract_digest

    keyed_text = _VALID_CONTRACT.replace("grain: [order_id]", "grain: [order_id, business_date]")
    keyed_text = keyed_text.replace("key: [order_id]", "key: [order_id, business_date]")
    keyed = _load_check(tmp_path / "keyed", keyed_text, _TARGET_SQL)
    assert keyed.contract_digest != baseline.contract_digest

    schema = _load_check(
        tmp_path / "schema",
        _VALID_CONTRACT.replace("precision: 18", "precision: 19"),
        _TARGET_SQL,
    )
    assert schema.contract_digest != baseline.contract_digest
    assert (
        schema.comparison_schema.logical_schema_digest
        != baseline.comparison_schema.logical_schema_digest
    )

    sql = _load_check(tmp_path / "sql", _VALID_CONTRACT, _TARGET_SQL + b" ")
    assert sql.contract_digest != baseline.contract_digest

    semantic_texts = (
        _VALID_CONTRACT.replace("driver: psycopg", "driver: psycopg3", 1),
        _VALID_CONTRACT.replace("name: legacy_orders}", "name: legacy_orders_v2}"),
        _VALID_CONTRACT.replace(
            "target_orders: {column: business_date_target, operator: eq",
            "target_orders: {column: target_partition_date, operator: eq",
        ),
        _VALID_CONTRACT.replace("source_cut]", "source_watermark]"),
        _VALID_CONTRACT.replace("fingerprint_allowed", "exact_required"),
    )
    for index, text in enumerate(semantic_texts):
        changed = _load_check(tmp_path / f"semantic-{index}", text, _TARGET_SQL)
        assert changed.contract_digest != baseline.contract_digest

    readiness_path = _write_contract(
        tmp_path / "readiness",
        _VALID_CONTRACT,
        _TARGET_SQL,
    )
    (readiness_path.parent / "sql" / "reference_readiness.sql").write_bytes(
        _REFERENCE_READINESS_SQL + b" "
    )
    readiness = load_contract_config(readiness_path).checks[0]
    assert readiness.contract_digest != baseline.contract_digest


def test_derived_digests_recompute_and_exclude_artifact_paths(tmp_path: Path) -> None:
    check = _load_check(tmp_path, _VALID_CONTRACT, _TARGET_SQL)
    target = check.target
    assert isinstance(target.locator, SqlArtifactDefinition)

    relocated = replace(target.locator, path=tmp_path / "relocated.sql")
    assert replace(target, locator=relocated).semantic_digest == target.semantic_digest

    parameter = target.locator.parameters[0]
    changed_field = replace(parameter.field, logical_type=LogicalType.STRING)
    changed_parameter = replace(parameter, field=changed_field)
    changed_locator = replace(target.locator, parameters=(changed_parameter,))
    assert replace(target, locator=changed_locator).semantic_digest != target.semantic_digest

    changed_check = replace(check, assurance_policy=AssurancePolicy.EXACT_REQUIRED)
    assert changed_check.contract_digest != check.contract_digest
    with pytest.raises(ValueError, match="init=False"):
        replace(check, contract_digest="0" * 64)

    reversed_scope = replace(check.scope, bindings=tuple(reversed(check.scope.bindings)))
    with pytest.raises(ContractValidationError, match="ordered reference then target"):
        replace(check, scope=reversed_scope)


def test_runtime_scope_changes_only_scope_digest(tmp_path: Path) -> None:
    config = load_contract_config(_write_contract(tmp_path, _VALID_CONTRACT, _TARGET_SQL))
    first = compile_static_plan(config, "daily_orders", {"business_date": "2026-09-22"})
    second = compile_static_plan(config, "daily_orders", {"business_date": "2026-09-23"})

    assert first.contract_digest == second.contract_digest
    assert first.logical_schema_digest == second.logical_schema_digest
    assert first.scope_digest != second.scope_digest

    with pytest.raises(ScopeValueError, match="must match declared parameters exactly"):
        compile_static_plan(config, "daily_orders", {})

    malformed_keys = cast(Mapping[str, int | bool | str], {1: "not-a-name"})
    with pytest.raises(ScopeValueError, match="keys must be strings"):
        compile_static_plan(config, "daily_orders", malformed_keys)

    not_a_mapping = cast(Mapping[str, int | bool | str], ("business_date",))
    with pytest.raises(ScopeValueError, match="must be a mapping"):
        compile_static_plan(config, "daily_orders", not_a_mapping)


def test_exact_required_plan_does_not_plan_fingerprint_pruning(tmp_path: Path) -> None:
    text = _VALID_CONTRACT.replace(
        "assurance_policy: fingerprint_allowed",
        "assurance_policy: exact_required",
    )
    config = load_contract_config(_write_contract(tmp_path, text, _TARGET_SQL))
    plan = compile_static_plan(
        config,
        "daily_orders",
        {"business_date": "2026-09-23"},
    )

    assert plan.assurance_policy is AssurancePolicy.EXACT_REQUIRED
    assert tuple(stage.name for stage in plan.stages) == (
        "open_read_contexts",
        "evaluate_readiness",
        "validate_key_contract",
        "compare_exact_scope",
        "persist_result",
    )


def test_explicit_empty_scope_is_a_full_scope(tmp_path: Path) -> None:
    scope_block = """\
    parameters:
      business_date: {type: {kind: date}}
    bindings:
      legacy_orders: {column: business_date, operator: eq, parameter: business_date}
      target_orders: {column: business_date_target, operator: eq, parameter: business_date}
"""
    full_scope_block = """\
    parameters: {}
    bindings: {}
"""
    readiness_parameters = """\
          parameters:
            - {name: business_date, type: {kind: date}}
"""
    projection_parameters = """\
      parameters:
        - {name: business_date, type: {kind: date}}
"""
    text = (
        _VALID_CONTRACT.replace(scope_block, full_scope_block)
        .replace(readiness_parameters, "          parameters: []\n")
        .replace(projection_parameters, "      parameters: []\n")
    )
    config = load_contract_config(_write_contract(tmp_path, text, _TARGET_SQL))
    plan = compile_static_plan(config, "daily_orders", {})

    assert config.checks[0].scope.parameters == ()
    assert config.checks[0].scope.bindings == ()
    assert len(plan.scope_digest) == 64


def test_scope_columns_and_artifact_parameters_follow_static_boundary(tmp_path: Path) -> None:
    unprojected_scope = _VALID_CONTRACT.replace(
        "legacy_orders: {column: business_date, operator: eq",
        "legacy_orders: {column: legacy_partition_date, operator: eq",
    ).replace(
        "target_orders: {column: business_date_target, operator: eq",
        "target_orders: {column: target_partition_date, operator: eq",
    )
    config = load_contract_config(
        _write_contract(tmp_path / "unprojected", unprojected_scope, _TARGET_SQL)
    )
    assert tuple(binding.column for binding in config.checks[0].scope.bindings) == (
        "legacy_partition_date",
        "target_partition_date",
    )

    parameter_free_projection = _VALID_CONTRACT.replace(
        "      parameters:\n        - {name: business_date, type: {kind: date}}",
        "      parameters: []",
        1,
    )
    load_contract_config(
        _write_contract(tmp_path / "subset", parameter_free_projection, _TARGET_SQL)
    )

    unknown_projection_parameter = _VALID_CONTRACT.replace(
        "      parameters:\n        - {name: business_date, type: {kind: date}}",
        "      parameters:\n        - {name: unknown_date, type: {kind: date}}",
        1,
    )
    with pytest.raises(ContractValidationError, match="ordered typed subset"):
        load_contract_config(
            _write_contract(tmp_path / "unknown", unknown_projection_parameter, _TARGET_SQL)
        )


def test_resolved_records_reject_invalid_state(tmp_path: Path) -> None:
    with pytest.raises(ContractValidationError, match="connection id"):
        ConnectionDefinition(
            connection_id="",
            adapter=Adapter.POSTGRESQL,
            driver="psycopg",
            profile="postgresql_17",
            roles=(ConnectionRole.SOURCE,),
            secret_ref="env:DFE_SOURCE_DSN",
        )

    with pytest.raises(ContractValidationError, match="does not match"):
        SqlArtifactDefinition(
            path=tmp_path / "query.sql",
            dialect=SqlDialect.POSTGRESQL,
            parameters=(),
            content="SELECT 1",
            content_sha256="0" * 64,
        )

    config = load_contract_config(
        _write_contract(tmp_path / "config", _VALID_CONTRACT, _TARGET_SQL)
    )
    reference = config.checks[0].reference
    assert isinstance(reference.locator, RelationLocator)
    with pytest.raises(ContractValidationError, match="catalog must be null"):
        replace(reference, locator=replace(reference.locator, catalog="other_database"))

    source = load_contract_source(
        _write_contract(tmp_path / "source", _VALID_CONTRACT, _TARGET_SQL)
    )
    conflicting_check = replace(
        source.checks[0],
        inline_scope=source.named_scopes[0][1],
    )
    with pytest.raises(ContractValidationError, match="exactly one"):
        compile_contract(replace(source, checks=(conflicting_check,)))


def test_duplicate_and_unknown_yaml_keys_are_rejected_without_value_leakage(
    tmp_path: Path,
) -> None:
    duplicate = _VALID_CONTRACT.replace(
        "    secret_ref: env:DFE_SOURCE_DSN",
        "    secret_ref: env:DFE_SOURCE_DSN\n    secret_ref: env:SHOULD_NOT_LEAK",
    )
    duplicate_path = _write_contract(tmp_path / "duplicate", duplicate, _TARGET_SQL)
    with pytest.raises(DuplicateYamlKeyError, match="line=") as duplicate_error:
        load_contract_source(duplicate_path)
    assert "SHOULD_NOT_LEAK" not in str(duplicate_error.value)

    merged = _VALID_CONTRACT.replace(
        "connections:\n  source_pg:",
        "connections:\n  source_pg:\n    <<: &source_defaults\n      adapter: postgresql",
    )
    merged_path = _write_contract(tmp_path / "merged", merged, _TARGET_SQL)
    with pytest.raises(DuplicateYamlKeyError, match="adapter"):
        load_contract_source(merged_path)

    repeated_merge_path = tmp_path / "repeated-merge.yaml"
    repeated_merge_path.write_text(
        "defaults: &defaults {value: one}\nitem:\n  <<: *defaults\n  <<: *defaults\n",
        encoding="utf-8",
    )
    with pytest.raises(ContractYamlError, match="aliases are unsupported"):
        load_contract_source(repeated_merge_path)

    unknown = _VALID_CONTRACT.replace(
        "    secret_ref: env:DFE_SOURCE_DSN",
        "    secret_ref: env:DFE_SOURCE_DSN\n    password: SHOULD_NOT_LEAK",
    )
    unknown_path = _write_contract(tmp_path / "unknown", unknown, _TARGET_SQL)
    with pytest.raises(ContractValidationError, match=r"connections\.source_pg\.password") as error:
        load_contract_source(unknown_path)
    assert "SHOULD_NOT_LEAK" not in str(error.value)


def test_invalid_references_schema_and_locator_fail_before_any_endpoint(
    tmp_path: Path,
) -> None:
    missing_reference = _VALID_CONTRACT.replace(
        "reference: legacy_orders", "reference: missing_orders"
    )
    with pytest.raises(ContractReferenceError, match="missing_orders"):
        load_contract_config(_write_contract(tmp_path / "missing", missing_reference, _TARGET_SQL))

    second_schema = """\
  target_order_line_v1:
    fields:
      - name: order_id
        type: {kind: int64}
        nullable: false
        normalization: none
        equality: {kind: exact}
      - name: business_date
        type: {kind: date}
        nullable: false
        normalization: none
        equality: {kind: exact}
      - name: amount
        type: {kind: decimal, precision: 19, scale: 2}
        nullable: true
        normalization: none
        equality: {kind: exact}
"""
    incompatible = _VALID_CONTRACT.replace("datasets:\n", second_schema + "datasets:\n", 1)
    incompatible = incompatible.replace(
        "    logical_schema: order_line_v1\n    projection:\n"
        "      - {field: order_id, column: order_id_target}",
        "    logical_schema: target_order_line_v1\n    projection:\n"
        "      - {field: order_id, column: order_id_target}",
    )
    with pytest.raises(ContractValidationError, match="does not match comparison schema"):
        load_contract_config(_write_contract(tmp_path / "incompatible", incompatible, _TARGET_SQL))

    both_locators = _VALID_CONTRACT.replace(
        "    relation: {catalog: null, schema: public, name: legacy_orders}",
        "    relation: {catalog: null, schema: public, name: legacy_orders}\n"
        "    sql: {path: sql/target.sql, dialect: postgresql, parameters: []}",
    )
    with pytest.raises(ContractValidationError, match=r"datasets\.legacy_orders"):
        load_contract_source(_write_contract(tmp_path / "locators", both_locators, _TARGET_SQL))


def test_sql_artifact_must_be_strict_utf8(tmp_path: Path) -> None:
    contract_path = _write_contract(tmp_path, _VALID_CONTRACT, b"\xff")
    with pytest.raises(SqlArtifactError, match="strict UTF-8") as error:
        load_contract_config(contract_path)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_yaml_limits_and_constructor_failures_are_typed(tmp_path: Path) -> None:
    huge_integer = tmp_path / "huge-integer.yaml"
    huge_integer.write_text("value: " + ("9" * 5_000), encoding="utf-8")
    with pytest.raises(ContractYamlError, match="cannot be constructed safely") as error:
        load_contract_source(huge_integer)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None

    nested = tmp_path / "nested.yaml"
    nested.write_text("value: " + ("[" * 70) + "0" + ("]" * 70), encoding="utf-8")
    with pytest.raises(ContractYamlError, match="nesting exceeds 64"):
        load_contract_source(nested)

    alias = tmp_path / "alias.yaml"
    alias.write_text("base: &base [value]\ncopy: *base\n", encoding="utf-8")
    with pytest.raises(ContractYamlError, match="aliases are unsupported"):
        load_contract_source(alias)


def test_version_and_unsupported_type_fail_with_specific_errors(tmp_path: Path) -> None:
    boolean_version = _VALID_CONTRACT.replace("version: 1", "version: true", 1)
    with pytest.raises(ContractValidationError, match="exact integer 1"):
        load_contract_source(_write_contract(tmp_path / "version", boolean_version, _TARGET_SQL))

    private_marker = "postgresql://reader:PRIVATE_DIAGNOSTIC_MARKER@localhost/db"
    unsupported_type = _VALID_CONTRACT.replace(
        "{kind: int64}",
        f'{{kind: "{private_marker}"}}',
        1,
    )
    with pytest.raises(UnsupportedContractError, match="union_tag_invalid") as error:
        load_contract_source(
            _write_contract(tmp_path / "unsupported", unsupported_type, _TARGET_SQL)
        )
    assert private_marker not in str(error.value)


def test_plan_report_rejects_invalid_version_and_direction(tmp_path: Path) -> None:
    config = load_contract_config(_write_contract(tmp_path, _VALID_CONTRACT, _TARGET_SQL))
    plan = compile_static_plan(config, "daily_orders", {"business_date": "2026-09-23"})
    serialized = plan.model_dump_json()

    with pytest.raises(ValidationError):
        PlanReport.model_validate_json(
            serialized.replace('"schema_version":1', '"schema_version":true')
        )
    with pytest.raises(ValidationError):
        PlanReport.model_validate_json(
            serialized.replace('"direction":"reference"', '"direction":"target"', 1)
        )


def test_absolute_sql_paths_are_operator_managed_and_nonsemantic(tmp_path: Path) -> None:
    baseline = _load_check(tmp_path / "baseline", _VALID_CONTRACT, _TARGET_SQL)
    absolute_sql = tmp_path / "operator-managed.sql"
    absolute_sql.write_bytes(_TARGET_SQL)
    text = _VALID_CONTRACT.replace("sql/target.sql", absolute_sql.as_posix(), 1)
    absolute = _load_check(tmp_path / "absolute", text, _TARGET_SQL)

    assert absolute.target.semantic_digest == baseline.target.semantic_digest
    assert absolute.contract_digest == baseline.contract_digest


def test_documented_example_loads_and_plans_without_endpoint_access() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    config = load_contract_config(repository_root / "examples" / "postgres-row" / "contract.yaml")
    plan = compile_static_plan(config, "daily_orders", {"business_date": "2026-09-23"})

    assert plan.check_id == "daily_orders"
    assert all(probe.status is PlanProbeStatus.REQUIRED_NOT_RUN for probe in plan.probes)


def _write_contract(directory: Path, text: str, target_sql: bytes) -> Path:
    sql_directory = directory / "sql"
    sql_directory.mkdir(parents=True)
    (sql_directory / "target.sql").write_bytes(target_sql)
    (sql_directory / "reference_readiness.sql").write_bytes(_REFERENCE_READINESS_SQL)
    (sql_directory / "target_readiness.sql").write_bytes(_TARGET_READINESS_SQL)
    contract_path = directory / "contract.yaml"
    contract_path.write_text(text, encoding="utf-8", newline="")
    return contract_path


def _load_check(directory: Path, text: str, target_sql: bytes) -> RowCheckDefinition:
    return load_contract_config(_write_contract(directory, text, target_sql)).checks[0]


def _reorder_top_level(text: str) -> str:
    blocks: list[list[str]] = []
    for line in text.splitlines(keepends=True):
        if line and not line[0].isspace():
            blocks.append([])
        blocks[-1].append(line)
    return "".join("".join(block) for block in reversed(blocks))
