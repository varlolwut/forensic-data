import argparse
import contextlib
import json
import math
import os
import re
import shlex
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from pathlib import Path
from typing import Final, NoReturn, TextIO, cast
from uuid import UUID

import psycopg
from psycopg.conninfo import conninfo_to_dict
from pydantic import BaseModel, SecretStr, ValidationError

from forensic_data.application import (
    ApplicationError,
    DiffRequest,
    ExecuteCheckRequest,
    HistoryRequest,
    MssqlGreengageExecutionServices,
    MssqlPostgresExecutionServices,
    PlanCheckRequest,
    PostgresExecutionServices,
    PostgresGreengageExecutionServices,
    PostgresMetadataServices,
    ScopeValue,
    execute_check,
    plan_check,
    read_diff,
    read_history,
)
from forensic_data.canonical import (
    DecimalParameters,
    FieldSchema,
    LogicalType,
    TimestampParameters,
    decode_payload,
)
from forensic_data.contracts.compiler import load_contract_config
from forensic_data.contracts.errors import ContractError
from forensic_data.contracts.model import (
    Adapter,
    ConnectionDefinition,
    DatasetDefinition,
    LoadedContractConfig,
    RelationLocator,
    RowCheckDefinition,
)
from forensic_data.greenplum import GreenplumConnectorError
from forensic_data.mssql import (
    MssqlConnectionSettings,
    MssqlRetryPolicy,
    MssqlTlsVerification,
)
from forensic_data.persistence.errors import MetadataError
from forensic_data.persistence.postgres import migrate_postgres_metadata
from forensic_data.planning import (
    PlanReport,
    ResolvedScope,
    ResolvedScopeParameter,
    resolve_scope_values,
)
from forensic_data.postgres import (
    PostgresConnectionSettings,
    PostgresConnectorError,
    PostgresRetryPolicy,
    PostgresSslMode,
)
from forensic_data.reporting import (
    ComparisonContext,
    ComparisonDirection,
    ComparisonField,
    ComparisonScopeValue,
    ComparisonSideIdentity,
    DiffCursor,
    DifferenceKind,
    DifferenceRecord,
    DiffPage,
    EvidenceFieldValue,
    EvidenceValueAvailability,
    HistoryCursor,
    HistoryPage,
    RelationComparisonLocator,
    SqlComparisonLocator,
)
from forensic_data.result import (
    Guarantee,
    ReasonCode,
    RunResult,
    Total,
    UnavailableTotal,
    exit_code_for_result,
)

_ENV_SECRET_REF_PATTERN: Final[re.Pattern[str]] = re.compile(r"^env:([A-Za-z_][A-Za-z0-9_]*)$")
_FILE_SECRET_REF_PREFIX: Final[str] = "file:"
_MAX_SECRET_FILE_BYTES: Final[int] = 16_384
_REQUIRED_DSN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "host",
        "port",
        "dbname",
        "user",
        "password",
        "sslmode",
        "connect_timeout",
    }
)
_REQUIRED_MSSQL_DSN_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "host",
        "port",
        "database",
        "user",
        "password",
        "tls_verification",
        "login_timeout",
        "query_timeout",
        "cancellation_acknowledgement_timeout",
    }
)
_CONNECTION_RETRY_DELAY_SECONDS: Final[float] = 1.0
_CONNECTION_RETRY_ATTEMPTS: Final[int] = 3
_MAX_PROTECTED_LOCK_TIMEOUT_MILLISECONDS: Final[int] = 5_000
_CLI_ORIGIN: Final[str] = "cli"
_TRUSTED_ARGUMENT_NAMES: Final[frozenset[str]] = frozenset(
    {
        "command",
        "metadata_command",
        "--attempt-id",
        "--check",
        "--config",
        "--lock-timeout-milliseconds",
        "--limit",
        "--reference-batch",
        "--request-id",
        "--run-id",
        "--secret-ref",
        "--scope-json",
        "--statement-timeout-milliseconds",
        "--target-batch",
    }
)
_STRUCTURAL_SUMMARY_PARAMETER_NAMES: Final[tuple[str, ...]] = (
    "reference_row_count",
    "reference_null_key_count",
    "reference_invalid_key_count",
    "reference_valid_key_count",
    "reference_distinct_key_count",
    "target_row_count",
    "target_null_key_count",
    "target_invalid_key_count",
    "target_valid_key_count",
    "target_distinct_key_count",
)

type _ScopeInput = bool | int | str
type _JsonObject = dict[str, object]


class CliInputError(ValueError):
    """A command-line value is invalid without exposing its raw contents."""


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        required_prefix = "the following arguments are required: "
        if message.startswith(required_prefix):
            names = tuple(message.removeprefix(required_prefix).split(", "))
            if names and all(name in _TRUSTED_ARGUMENT_NAMES for name in names):
                raise CliInputError("missing required command arguments: " + ", ".join(names))
        raise CliInputError("invalid command arguments; run 'forensics --help' for usage")


class _Arguments(argparse.Namespace):
    command: str
    metadata_command: str
    config: Path
    check: str
    scope_json: str
    output: str
    reference_batch: str
    target_batch: str
    request_id: str
    limit: int
    cursor_json: str | None
    run_id: str
    attempt_id: str
    secret_ref: str
    statement_timeout_milliseconds: int
    lock_timeout_milliseconds: int


def main() -> int:
    return run_cli(tuple(sys.argv[1:]), os.environ, sys.stdout, sys.stderr)


def run_cli(
    arguments: Sequence[str],
    environment: Mapping[str, str],
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    output_json = _requests_json_output(arguments)
    parser = _build_parser()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            parsed = parser.parse_args(list(arguments), namespace=_Arguments())
        return _dispatch(parsed, environment, stdout)
    except SystemExit as error:
        return _system_exit_code(error)
    except ContractError as error:
        return _write_error(stderr, output_json, "invalid_contract", str(error))
    except ApplicationError as error:
        return _write_error(stderr, output_json, "application_error", str(error))
    except MetadataError as error:
        return _write_error(stderr, output_json, "metadata_error", str(error))
    except PostgresConnectorError as error:
        return _write_error(stderr, output_json, "postgres_error", str(error))
    except GreenplumConnectorError as error:
        return _write_error(stderr, output_json, "greengage_error", str(error))
    except ValidationError:
        return _write_error(
            stderr,
            output_json,
            "invalid_input",
            "input does not satisfy the version-1 typed API contract",
        )
    except CliInputError as error:
        return _write_error(stderr, output_json, "invalid_input", str(error))
    except ValueError as error:
        return _write_error(stderr, output_json, "invalid_value", str(error))


def _build_parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(
        prog="forensics",
        description="Plan, run, and inspect bounded data-forensics checks.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    plan_parser = commands.add_parser(
        "plan",
        help="compile a static plan without resolving secrets or connecting to endpoints",
    )
    _add_check_scope_arguments(plan_parser)
    _add_output_argument(plan_parser)

    check_parser = commands.add_parser(
        "check",
        help="execute and durably record one check",
    )
    _add_check_scope_arguments(check_parser)
    check_parser.add_argument(
        "--reference-batch", required=True, help="expected reference batch ID"
    )
    check_parser.add_argument("--target-batch", required=True, help="expected target batch ID")
    check_parser.add_argument("--request-id", required=True, help="idempotency request UUID")
    _add_output_argument(check_parser)

    history_parser = commands.add_parser(
        "history",
        help="read a bounded attempt history page from metadata only",
    )
    _add_check_scope_arguments(history_parser)
    history_parser.add_argument("--limit", required=True, type=int, help="page size, from 1 to 100")
    history_parser.add_argument(
        "--cursor-json",
        help="HistoryCursor JSON returned by the previous page",
    )
    _add_output_argument(history_parser)

    diff_parser = commands.add_parser(
        "diff",
        help="page retained difference evidence from metadata only",
    )
    diff_parser.add_argument("--config", required=True, type=Path, help="contract YAML path")
    diff_parser.add_argument("--run-id", required=True, help="full run UUID")
    diff_parser.add_argument("--attempt-id", required=True, help="full attempt UUID")
    diff_parser.add_argument("--limit", required=True, type=int, help="page size, from 1 to 100")
    diff_parser.add_argument(
        "--cursor-json",
        help="DiffCursor JSON returned by the previous page",
    )
    _add_output_argument(diff_parser)

    metadata_parser = commands.add_parser(
        "metadata",
        help="run explicit metadata-store administration",
    )
    metadata_commands = metadata_parser.add_subparsers(
        dest="metadata_command",
        required=True,
    )
    migrate_parser = metadata_commands.add_parser(
        "migrate",
        help="validate and apply packaged metadata migrations",
    )
    migrate_parser.add_argument(
        "--secret-ref",
        required=True,
        help="metadata migrator DSN reference (env:NAME or file:/absolute/path)",
    )
    migrate_parser.add_argument(
        "--statement-timeout-milliseconds",
        required=True,
        type=int,
        help="positive PostgreSQL statement timeout in milliseconds",
    )
    migrate_parser.add_argument(
        "--lock-timeout-milliseconds",
        required=True,
        type=int,
        help="positive metadata migration lock timeout in milliseconds",
    )
    _add_migration_output_argument(migrate_parser)
    return parser


def _add_check_scope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", required=True, type=Path, help="contract YAML path")
    parser.add_argument("--check", required=True, help="check ID from the contract")
    parser.add_argument(
        "--scope-json",
        required=True,
        help='exact JSON object of typed scope values, for example {"business_date":"2026-09-23"}',
    )


def _add_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output",
        choices=("human", "json"),
        default="human",
        help="render a readable summary or the exact JSON v1 API model (default: human)",
    )


def _add_migration_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output",
        choices=("human", "json"),
        default="human",
        help="render a readable migration report or stable JSON (default: human)",
    )


def _dispatch(
    arguments: _Arguments,
    environment: Mapping[str, str],
    stdout: TextIO,
) -> int:
    if arguments.command == "plan":
        return _run_plan(arguments, stdout)
    if arguments.command == "check":
        return _run_check(arguments, environment, stdout)
    if arguments.command == "history":
        return _run_history(arguments, environment, stdout)
    if arguments.command == "diff":
        return _run_diff(arguments, environment, stdout)
    if arguments.command == "metadata" and arguments.metadata_command == "migrate":
        return _run_metadata_migrate(arguments, environment, stdout)
    raise CliInputError("unknown command; run 'forensics --help' for usage")


def _run_plan(arguments: _Arguments, stdout: TextIO) -> int:
    config = load_contract_config(arguments.config)
    report = plan_check(config, _plan_request(arguments.check, arguments.scope_json))
    _write_plan(report, _output_format(arguments.output), stdout)
    return 0


def _run_check(
    arguments: _Arguments,
    environment: Mapping[str, str],
    stdout: TextIO,
) -> int:
    config = load_contract_config(arguments.config)
    request = ExecuteCheckRequest(
        request_id=_parse_uuid(arguments.request_id, "request ID"),
        check_id=arguments.check,
        scope_values=_scope_values(arguments.scope_json),
        reference_expected_batch_id=arguments.reference_batch,
        target_expected_batch_id=arguments.target_batch,
        origin=_CLI_ORIGIN,
    )
    check = _find_check(config, request.check_id)
    services = _execution_services(
        config, check.reference.connection, check.target.connection, environment
    )
    scope = resolve_scope_values(
        check,
        {value.name: value.value for value in request.scope_values},
    )
    result = execute_check(config, request, services)
    _require_renderable_result_identity(result, check, scope)
    _write_run_result(
        result,
        _comparison_context(check, scope),
        _output_format(arguments.output),
        stdout,
    )
    return int(exit_code_for_result(result))


def _run_history(
    arguments: _Arguments,
    environment: Mapping[str, str],
    stdout: TextIO,
) -> int:
    config = load_contract_config(arguments.config)
    request = _plan_request(arguments.check, arguments.scope_json)
    plan = plan_check(config, request)
    page = read_history(
        HistoryRequest(
            check_id=plan.check_id,
            scope_digest=plan.scope_digest,
            limit=arguments.limit,
            cursor=_history_cursor(arguments.cursor_json),
        ),
        _metadata_services(config, environment, "dfe-cli-history"),
    )
    _write_history(page, _output_format(arguments.output), stdout)
    return 0


def _run_diff(
    arguments: _Arguments,
    environment: Mapping[str, str],
    stdout: TextIO,
) -> int:
    config = load_contract_config(arguments.config)
    page = read_diff(
        DiffRequest(
            run_id=_parse_uuid(arguments.run_id, "run ID"),
            attempt_id=_parse_uuid(arguments.attempt_id, "attempt ID"),
            limit=arguments.limit,
            cursor=_diff_cursor(arguments.cursor_json),
        ),
        _metadata_services(config, environment, "dfe-cli-diff"),
    )
    _write_diff(page, _output_format(arguments.output), stdout)
    return 0


def _run_metadata_migrate(
    arguments: _Arguments,
    environment: Mapping[str, str],
    stdout: TextIO,
) -> int:
    statement_timeout_milliseconds = _positive_argument_integer(
        arguments.statement_timeout_milliseconds,
        "statement timeout",
    )
    lock_timeout_milliseconds = _positive_argument_integer(
        arguments.lock_timeout_milliseconds,
        "migration lock timeout",
    )
    settings = _connection_settings_from_secret_ref(
        "metadata_migrator",
        arguments.secret_ref,
        environment,
        statement_timeout_milliseconds,
        "dfe-cli-metadata-migrate",
    )
    report = migrate_postgres_metadata(
        settings,
        _retry_policy(),
        lock_timeout_milliseconds,
    )
    if _output_format(arguments.output) == "json":
        stdout.write(
            json.dumps(
                {
                    "schema_version": 1,
                    "current_version": report.current_version,
                    "applied_versions": list(report.applied_versions),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        stdout.write("\n")
        return 0
    applied = ", ".join(str(version) for version in report.applied_versions)
    stdout.write(f"Metadata schema version: {report.current_version}\n")
    stdout.write(f"Applied migrations: {applied if applied else 'none (already current)'}\n")
    return 0


def _plan_request(check_id: str, scope_json: str) -> PlanCheckRequest:
    return PlanCheckRequest(check_id=check_id, scope_values=_scope_values(scope_json))


def _scope_values(value: str) -> tuple[ScopeValue, ...]:
    decoded = _decode_json(value, "scope")
    if type(decoded) is not dict:
        raise CliInputError("scope JSON must be an object")
    raw_scope = cast(dict[object, object], decoded)
    values: list[ScopeValue] = []
    for raw_name in sorted(raw_scope, key=_scope_name_sort_key):
        if type(raw_name) is not str:
            raise CliInputError("scope JSON property names must be strings")
        raw_value = raw_scope[raw_name]
        if type(raw_value) not in (bool, int, str):
            raise CliInputError("scope JSON values must be exact booleans, integers, or strings")
        values.append(ScopeValue(name=raw_name, value=cast(_ScopeInput, raw_value)))
    return tuple(values)


def _scope_name_sort_key(value: object) -> str:
    if type(value) is not str:
        raise CliInputError("scope JSON property names must be strings")
    return value


def _history_cursor(value: str | None) -> HistoryCursor | None:
    if value is None:
        return None
    decoded = _decode_json(value, "history cursor")
    if type(decoded) is not dict:
        raise CliInputError("history cursor JSON must be an object")
    return HistoryCursor.model_validate_json(
        json.dumps(decoded, ensure_ascii=False, separators=(",", ":"))
    )


def _diff_cursor(value: str | None) -> DiffCursor | None:
    if value is None:
        return None
    decoded = _decode_json(value, "diff cursor")
    if type(decoded) is not dict:
        raise CliInputError("diff cursor JSON must be an object")
    return DiffCursor.model_validate_json(
        json.dumps(decoded, ensure_ascii=False, separators=(",", ":"))
    )


def _decode_json(value: str, context: str) -> object:
    try:
        return cast(
            object,
            json.loads(
                value,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            ),
        )
    except json.JSONDecodeError:
        raise CliInputError(f"{context} must be valid strict JSON") from None


def _unique_json_object(pairs: list[tuple[str, object]]) -> _JsonObject:
    result: _JsonObject = {}
    for name, value in pairs:
        if name in result:
            raise CliInputError("JSON objects must not contain duplicate property names")
        result[name] = value
    return result


def _reject_json_constant(value: str) -> object:
    del value
    raise CliInputError("JSON must not contain non-finite numeric constants")


def _parse_uuid(value: str, context: str) -> UUID:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise CliInputError(f"{context} must be a UUID") from None
    if str(parsed) != value.lower():
        raise CliInputError(f"{context} must use canonical UUID text")
    return parsed


def _find_check(config: LoadedContractConfig, check_id: str) -> RowCheckDefinition:
    matches = tuple(check for check in config.checks if check.check_id == check_id)
    if len(matches) != 1:
        raise CliInputError("check ID does not identify exactly one configured check")
    return matches[0]


def _require_renderable_result_identity(
    result: RunResult,
    check: RowCheckDefinition,
    scope: ResolvedScope,
) -> None:
    expected = (check.check_id, check.contract_digest, scope.scope_digest)
    actual = (result.check_id, result.contract_digest, result.scope_digest)
    if actual != expected:
        raise ApplicationError(
            "check result identity differs from the validated contract and scope; "
            "refusing to render current endpoint labels for a different durable result"
        )


def _comparison_context(
    check: RowCheckDefinition,
    scope: ResolvedScope,
) -> ComparisonContext:
    return ComparisonContext(
        reference=_comparison_side(ComparisonDirection.REFERENCE, check.reference),
        target=_comparison_side(ComparisonDirection.TARGET, check.target),
        scope=tuple(
            ComparisonScopeValue(
                name=parameter.name,
                logical_type=parameter.field.logical_type,
                canonical_value=_scope_value_text(parameter),
            )
            for parameter in scope.parameters
        ),
        comparison_fields=tuple(
            _comparison_field(field) for field in check.comparison_schema.schema.fields
        ),
        ordered_key=check.key,
    )


def _comparison_side(
    direction: ComparisonDirection,
    dataset: DatasetDefinition,
) -> ComparisonSideIdentity:
    locator = dataset.locator
    if isinstance(locator, RelationLocator):
        reporting_locator: RelationComparisonLocator | SqlComparisonLocator = (
            RelationComparisonLocator(
                locator_type="relation",
                catalog=locator.catalog,
                schema=locator.schema,
                name=locator.name,
                relation_scope=locator.relation_scope,
            )
        )
    else:
        reporting_locator = SqlComparisonLocator(
            locator_type="sql",
            dialect=locator.dialect,
            content_sha256=locator.content_sha256,
        )
    return ComparisonSideIdentity(
        direction=direction,
        connection_id=dataset.connection.connection_id,
        dataset_id=dataset.dataset_id,
        locator=reporting_locator,
    )


def _scope_value_text(parameter: ResolvedScopeParameter) -> str:
    value = decode_payload(parameter.field, parameter.canonical_payload)
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if type(value) is str:
        return value
    return str(value)


def _comparison_field(field: FieldSchema) -> ComparisonField:
    decimal_precision: int | None = None
    decimal_scale: int | None = None
    timestamp_precision: int | None = None
    if isinstance(field.parameters, DecimalParameters):
        decimal_precision = field.parameters.precision
        decimal_scale = field.parameters.scale
    elif isinstance(field.parameters, TimestampParameters):
        timestamp_precision = field.parameters.precision
    return ComparisonField(
        field_name=field.name,
        logical_type=field.logical_type,
        decimal_precision=decimal_precision,
        decimal_scale=decimal_scale,
        timestamp_precision=timestamp_precision,
    )


def _execution_services(
    config: LoadedContractConfig,
    reference: ConnectionDefinition,
    target: ConnectionDefinition,
    environment: Mapping[str, str],
) -> (
    PostgresExecutionServices
    | MssqlPostgresExecutionServices
    | PostgresGreengageExecutionServices
    | MssqlGreengageExecutionServices
):
    statement_timeout = config.execution.statement_timeout_milliseconds
    if statement_timeout < 2:
        raise CliInputError(
            "execution statement_timeout_milliseconds must be at least 2 for protected reads"
        )
    if target.adapter not in (Adapter.POSTGRESQL, Adapter.GREENGAGE):
        raise CliInputError(f"target connection adapter {target.adapter.value!r} is unsupported")
    if reference.adapter not in (Adapter.POSTGRESQL, Adapter.MSSQL):
        raise CliInputError(
            f"reference connection adapter {reference.adapter.value!r} is unsupported"
        )
    metadata_record_bytes = min(
        config.execution.max_application_result_bytes,
        config.execution.max_coordinator_memory_bytes,
    )
    target_settings = _connection_settings(
        target,
        environment,
        statement_timeout,
        "dfe-cli-check-target",
    )
    metadata_settings = _connection_settings(
        config.metadata.connection,
        environment,
        statement_timeout,
        "dfe-cli-check-metadata",
    )
    protected_lock_timeout_milliseconds = min(
        _MAX_PROTECTED_LOCK_TIMEOUT_MILLISECONDS,
        statement_timeout - 1,
    )
    if reference.adapter is Adapter.MSSQL and target.adapter is Adapter.GREENGAGE:
        return MssqlGreengageExecutionServices(
            reference_connection_id=reference.connection_id,
            reference_settings=_mssql_connection_settings(
                reference,
                environment,
                "dfe-cli-check-reference",
            ),
            target_connection_id=target.connection_id,
            target_settings=target_settings,
            metadata_connection_id=config.metadata.connection.connection_id,
            metadata_settings=metadata_settings,
            reference_retry_policy=_mssql_retry_policy(),
            target_retry_policy=_retry_policy(),
            metadata_retry_policy=_retry_policy(),
            protected_lock_timeout_milliseconds=protected_lock_timeout_milliseconds,
            metadata_record_bytes=metadata_record_bytes,
            metadata_total_bytes=config.execution.max_coordinator_memory_bytes,
        )
    if reference.adapter is Adapter.MSSQL:
        return MssqlPostgresExecutionServices(
            reference_connection_id=reference.connection_id,
            reference_settings=_mssql_connection_settings(
                reference,
                environment,
                "dfe-cli-check-reference",
            ),
            target_connection_id=target.connection_id,
            target_settings=target_settings,
            metadata_connection_id=config.metadata.connection.connection_id,
            metadata_settings=metadata_settings,
            reference_retry_policy=_mssql_retry_policy(),
            target_retry_policy=_retry_policy(),
            metadata_retry_policy=_retry_policy(),
            protected_lock_timeout_milliseconds=protected_lock_timeout_milliseconds,
            metadata_record_bytes=metadata_record_bytes,
            metadata_total_bytes=config.execution.max_coordinator_memory_bytes,
        )
    if target.adapter is Adapter.GREENGAGE:
        return PostgresGreengageExecutionServices(
            reference_connection_id=reference.connection_id,
            reference_settings=_connection_settings(
                reference,
                environment,
                statement_timeout,
                "dfe-cli-check-reference",
            ),
            target_connection_id=target.connection_id,
            target_settings=target_settings,
            metadata_connection_id=config.metadata.connection.connection_id,
            metadata_settings=metadata_settings,
            reference_retry_policy=_retry_policy(),
            target_retry_policy=_retry_policy(),
            metadata_retry_policy=_retry_policy(),
            protected_lock_timeout_milliseconds=protected_lock_timeout_milliseconds,
            metadata_record_bytes=metadata_record_bytes,
            metadata_total_bytes=config.execution.max_coordinator_memory_bytes,
        )
    return PostgresExecutionServices(
        reference_connection_id=reference.connection_id,
        reference_settings=_connection_settings(
            reference,
            environment,
            statement_timeout,
            "dfe-cli-check-reference",
        ),
        target_connection_id=target.connection_id,
        target_settings=target_settings,
        metadata_connection_id=config.metadata.connection.connection_id,
        metadata_settings=metadata_settings,
        source_retry_policy=_retry_policy(),
        metadata_retry_policy=_retry_policy(),
        protected_lock_timeout_milliseconds=protected_lock_timeout_milliseconds,
        metadata_record_bytes=metadata_record_bytes,
        metadata_total_bytes=config.execution.max_coordinator_memory_bytes,
    )


def _retry_policy() -> PostgresRetryPolicy:
    return PostgresRetryPolicy(
        max_attempts=_CONNECTION_RETRY_ATTEMPTS,
        delay_seconds=_CONNECTION_RETRY_DELAY_SECONDS,
    )


def _mssql_retry_policy() -> MssqlRetryPolicy:
    return MssqlRetryPolicy(
        max_attempts=_CONNECTION_RETRY_ATTEMPTS,
        delay_seconds=_CONNECTION_RETRY_DELAY_SECONDS,
    )


def _metadata_services(
    config: LoadedContractConfig,
    environment: Mapping[str, str],
    application_name: str,
) -> PostgresMetadataServices:
    connection = config.metadata.connection
    return PostgresMetadataServices(
        connection_id=connection.connection_id,
        settings=_connection_settings(
            connection,
            environment,
            config.execution.statement_timeout_milliseconds,
            application_name,
        ),
        retry_policy=_retry_policy(),
    )


def _connection_settings(
    connection: ConnectionDefinition,
    environment: Mapping[str, str],
    statement_timeout_milliseconds: int,
    application_name: str,
) -> PostgresConnectionSettings:
    return _connection_settings_from_secret_ref(
        connection.connection_id,
        connection.secret_ref,
        environment,
        statement_timeout_milliseconds,
        application_name,
    )


def _connection_settings_from_secret_ref(
    connection_id: str,
    secret_ref: str,
    environment: Mapping[str, str],
    statement_timeout_milliseconds: int,
    application_name: str,
) -> PostgresConnectionSettings:
    dsn, source_description = _resolve_connection_secret(
        connection_id,
        secret_ref,
        environment,
    )
    required_values = _parse_postgres_dsn(dsn, source_description)
    return PostgresConnectionSettings(
        host=required_values["host"],
        port=_positive_integer(required_values["port"], "PostgreSQL DSN port"),
        dbname=required_values["dbname"],
        user=required_values["user"],
        password=SecretStr(required_values["password"]),
        sslmode=_sslmode(required_values["sslmode"]),
        connect_timeout_seconds=_positive_integer(
            required_values["connect_timeout"],
            "PostgreSQL DSN connect_timeout",
        ),
        statement_timeout_milliseconds=statement_timeout_milliseconds,
        application_name=application_name,
    )


def _mssql_connection_settings(
    connection: ConnectionDefinition,
    environment: Mapping[str, str],
    application_name: str,
) -> MssqlConnectionSettings:
    dsn, source_description = _resolve_connection_secret(
        connection.connection_id,
        connection.secret_ref,
        environment,
    )
    required_values = _parse_mssql_dsn(dsn, source_description)
    return MssqlConnectionSettings(
        host=required_values["host"],
        port=_positive_integer(required_values["port"], "SQL Server DSN port"),
        database=required_values["database"],
        user=required_values["user"],
        password=SecretStr(required_values["password"]),
        tls_verification=_mssql_tls_verification(required_values["tls_verification"]),
        login_timeout_seconds=_positive_integer(
            required_values["login_timeout"],
            "SQL Server DSN login_timeout",
        ),
        query_timeout_seconds=_positive_integer(
            required_values["query_timeout"],
            "SQL Server DSN query_timeout",
        ),
        cancellation_acknowledgement_timeout_seconds=_positive_finite_float(
            required_values["cancellation_acknowledgement_timeout"],
            "SQL Server DSN cancellation_acknowledgement_timeout",
        ),
        application_name=application_name,
    )


def _resolve_connection_secret(
    connection_id: str,
    secret_ref: str,
    environment: Mapping[str, str],
) -> tuple[str, str]:
    environment_match = _ENV_SECRET_REF_PATTERN.fullmatch(secret_ref)
    if environment_match is not None:
        variable_name = environment_match.group(1)
        dsn = environment.get(variable_name)
        if dsn is None or dsn == "":
            raise CliInputError(
                f"connection {connection_id!r} requires environment variable {variable_name!r}"
            )
        return dsn, f"environment variable {variable_name!r}"

    if secret_ref.startswith(_FILE_SECRET_REF_PREFIX):
        path = Path(secret_ref.removeprefix(_FILE_SECRET_REF_PREFIX))
        if not path.is_absolute():
            raise CliInputError(
                f"connection {connection_id!r} file secret reference must use an absolute path"
            )
        return (
            _read_secret_file(path, connection_id),
            f"secret file for connection {connection_id!r}",
        )

    raise CliInputError(
        f"connection {connection_id!r} must use an env:NAME or file:/absolute/path secret reference"
    )


def _read_secret_file(path: Path, connection_id: str) -> str:
    unavailable_message = (
        f"connection {connection_id!r} secret file must be a readable regular file"
    )
    try:
        path_mode = path.stat().st_mode
    except (OSError, ValueError):
        raise CliInputError(unavailable_message) from None
    if not stat.S_ISREG(path_mode):
        raise CliInputError(unavailable_message)
    try:
        with path.open("rb") as secret_file:
            if not stat.S_ISREG(os.fstat(secret_file.fileno()).st_mode):
                raise CliInputError(unavailable_message)
            payload = secret_file.read(_MAX_SECRET_FILE_BYTES + 1)
    except OSError:
        raise CliInputError(unavailable_message) from None

    if len(payload) > _MAX_SECRET_FILE_BYTES:
        raise CliInputError(
            f"connection {connection_id!r} secret file exceeds the "
            f"{_MAX_SECRET_FILE_BYTES}-byte limit"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise CliInputError(
            f"connection {connection_id!r} secret file must contain strict UTF-8"
        ) from None

    if text.endswith("\r\n"):
        dsn = text[:-2]
    elif text.endswith("\n"):
        dsn = text[:-1]
    else:
        dsn = text
    if dsn == "" or dsn.splitlines() != [dsn]:
        raise CliInputError(
            f"connection {connection_id!r} secret file must contain exactly one non-empty DSN line"
        )
    return dsn


def _parse_postgres_dsn(dsn: str, source_description: str) -> dict[str, str]:
    try:
        values = conninfo_to_dict(dsn)
    except psycopg.ProgrammingError:
        raise CliInputError(f"{source_description} must contain a valid PostgreSQL DSN") from None
    fields = frozenset(values)
    missing = tuple(sorted(_REQUIRED_DSN_FIELDS - fields))
    unsupported = tuple(sorted(fields - _REQUIRED_DSN_FIELDS))
    if missing:
        raise CliInputError(
            f"PostgreSQL DSN from {source_description} is missing required fields: "
            f"{', '.join(missing)}"
        )
    if unsupported:
        raise CliInputError(
            f"PostgreSQL DSN from {source_description} contains unsupported fields: "
            f"{', '.join(unsupported)}"
        )
    required_values = cast(dict[str, str], values)
    if any(required_values[name] == "" for name in _REQUIRED_DSN_FIELDS):
        raise CliInputError(
            f"PostgreSQL DSN from {source_description} must not contain empty required fields"
        )
    return required_values


def _parse_mssql_dsn(dsn: str, source_description: str) -> dict[str, str]:
    try:
        tokens = shlex.split(dsn, posix=True)
    except ValueError:
        raise CliInputError(
            f"SQL Server DSN from {source_description} contains invalid quoting"
        ) from None
    values: dict[str, str] = {}
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator == "" or key == "" or value == "":
            raise CliInputError(
                f"SQL Server DSN from {source_description} must use non-empty key=value fields"
            )
        if key in values:
            raise CliInputError(f"SQL Server DSN from {source_description} repeats field {key!r}")
        values[key] = value
    fields = frozenset(values)
    missing = tuple(sorted(_REQUIRED_MSSQL_DSN_FIELDS - fields))
    unsupported = tuple(sorted(fields - _REQUIRED_MSSQL_DSN_FIELDS))
    if missing:
        raise CliInputError(
            f"SQL Server DSN from {source_description} is missing required fields: "
            f"{', '.join(missing)}"
        )
    if unsupported:
        raise CliInputError(
            f"SQL Server DSN from {source_description} contains unsupported fields: "
            f"{', '.join(unsupported)}"
        )
    return values


def _positive_integer(value: str, context: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise CliInputError(f"{context} must be a positive decimal integer")
    parsed = int(value)
    if parsed < 1:
        raise CliInputError(f"{context} must be a positive decimal integer")
    return parsed


def _positive_finite_float(value: str, context: str) -> float:
    try:
        parsed = float(value)
    except ValueError:
        raise CliInputError(f"{context} must be a positive finite number") from None
    if not math.isfinite(parsed) or parsed <= 0:
        raise CliInputError(f"{context} must be a positive finite number")
    return parsed


def _positive_argument_integer(value: int, context: str) -> int:
    if type(value) is not int or value < 1:
        raise CliInputError(f"{context} must be a positive integer")
    return value


def _sslmode(value: str) -> PostgresSslMode:
    try:
        return PostgresSslMode(value)
    except ValueError:
        supported = ", ".join(mode.value for mode in PostgresSslMode)
        raise CliInputError(f"PostgreSQL DSN sslmode must be one of: {supported}") from None


def _mssql_tls_verification(value: str) -> MssqlTlsVerification:
    try:
        return MssqlTlsVerification(value)
    except ValueError:
        supported = ", ".join(mode.value for mode in MssqlTlsVerification)
        raise CliInputError(
            f"SQL Server DSN tls_verification must be one of: {supported}"
        ) from None


def _output_format(value: str) -> str:
    if value not in {"human", "json"}:
        raise CliInputError("output must be 'human' or 'json'")
    return value


def _write_plan(report: PlanReport, output: str, stdout: TextIO) -> None:
    if output == "json":
        _write_json_model(report, stdout)
        return
    lines = (
        f"Check: {report.check_id} (revision {report.revision})",
        f"Scope: {report.scope_digest}",
        f"Requested assurance: {report.assurance_policy.value}",
        f"Reference: {report.reference.dataset_id} via {report.reference.connection_id}",
        f"Target: {report.target.dataset_id} via {report.target.connection_id}",
        "Stages: " + ", ".join(f"{stage.name}={stage.status.value}" for stage in report.stages),
        "No endpoints were contacted; readiness and equality remain unestablished.",
    )
    _write_lines(stdout, lines)


def _write_run_result(
    result: RunResult,
    comparison_context: ComparisonContext,
    output: str,
    stdout: TextIO,
) -> None:
    if output == "json":
        _write_json_model(result, stdout)
        return
    coverage = result.comparison_coverage
    lines = [
        f"Run: {result.run_id}",
        f"Attempt: {result.attempt_id}",
        f"Check: {result.check_id}",
        f"Status: {result.execution_status.value}",
        f"Verdict: {result.verdict.value}",
        f"Guarantee: {result.guarantee.value}",
        f"Coverage: {coverage.covered_partitions}/{coverage.total_partitions} partitions; "
        f"{coverage.resolved_segments} resolved, {coverage.unresolved_segments} unresolved segments",
        "Totals: "
        f"matched={_total_text(result.totals.matched)}, "
        f"missing={_total_text(result.totals.missing)}, "
        f"extra={_total_text(result.totals.extra)}, "
        f"modified={_total_text(result.totals.modified)}",
        f"Persistence: {result.persistence.state.value}",
    ]
    lines.extend(_comparison_context_lines(comparison_context))
    lines.extend(f"Reason: {reason.code.value} — {reason.message}" for reason in result.reasons)
    lines.extend(_structural_summary_lines(result))
    _write_lines(stdout, tuple(lines))


def _write_history(page: HistoryPage, output: str, stdout: TextIO) -> None:
    if output == "json":
        _write_json_model(page, stdout)
        return
    lines = [
        f"History for check {page.check_id}",
        f"Scope: {page.scope_digest}",
        f"Attempts returned: {len(page.items)} (limit {page.requested_limit})",
    ]
    for item in page.items:
        outcome = (
            f"verdict={item.stored_result.verdict.value}"
            if item.stored_result is not None
            else "reason="
            f"{item.terminal_reason.code.value if item.terminal_reason is not None else 'pending'}"
        )
        lines.append(
            f"{item.started_at.isoformat()}  {item.status.value}  "
            f"run={item.run_id} attempt={item.attempt_id} {outcome}"
        )
    if page.next_cursor is None:
        lines.append("Next cursor: none")
    else:
        lines.append(f"Next cursor: {page.next_cursor.model_dump_json()}")
    _write_lines(stdout, tuple(lines))


def _write_diff(page: DiffPage, output: str, stdout: TextIO) -> None:
    if output == "json":
        _write_json_model(page, stdout)
        return
    result = page.stored_result
    lines = [
        f"Run: {page.run_id}",
        f"Attempt: {page.attempt_id}",
        f"Stored verdict: {result.verdict.value} ({result.guarantee.value})",
        f"Row details: {page.detail_availability.value}",
        f"Difference records found: {page.found_records}",
        f"Retained row details: {page.retained_records}; source endpoints were not queried.",
    ]
    lines.extend(_comparison_context_lines(page.comparison_context))
    lines.extend(f"Reason: {reason.code.value} — {reason.message}" for reason in result.reasons)
    lines.extend(_structural_summary_lines(result))
    lines.extend(_difference_record_line(detail) for detail in page.details)
    if page.next_cursor is None:
        lines.append("Next cursor: none")
    else:
        lines.append(f"Next cursor: {page.next_cursor.model_dump_json()}")
    _write_lines(stdout, tuple(lines))


def _difference_record_line(detail: DifferenceRecord) -> str:
    key = ", ".join(_evidence_field_text(value) for value in detail.key_values)
    omitted = ", ".join(_escape_inline_text(name) for name in detail.omitted_field_names)
    reference = _difference_side_text(
        detail.reference_values,
        detail.kind is not DifferenceKind.EXTRA,
    )
    target = _difference_side_text(
        detail.target_values,
        detail.kind is not DifferenceKind.MISSING,
    )
    return (
        f"Difference {detail.sequence}: {detail.kind.value}; "
        f"key=[{key if key else '<unavailable>'}]; "
        f"omitted=[{omitted if omitted else '<none>'}]; "
        f"reference={reference}; target={target}"
    )


def _difference_side_text(
    values: tuple[EvidenceFieldValue, ...],
    side_present: bool,
) -> str:
    if not side_present:
        return "<absent>"
    rendered = ", ".join(_evidence_field_text(value) for value in values)
    return f"[{rendered if rendered else '<no retained values>'}]"


def _comparison_context_lines(context: ComparisonContext) -> tuple[str, ...]:
    scope = ", ".join(
        f"{_escape_inline_text(value.name)}({value.logical_type.value})="
        f"{json.dumps(value.canonical_value, ensure_ascii=False)}"
        for value in context.scope
    )
    return (
        _comparison_side_line(context.reference),
        _comparison_side_line(context.target),
        f"Scope values: {scope if scope else '<none>'}",
    )


def _comparison_side_line(side: ComparisonSideIdentity) -> str:
    locator = side.locator
    if isinstance(locator, RelationComparisonLocator):
        components = (() if locator.catalog is None else (locator.catalog,)) + (
            locator.schema_name,
            locator.name,
        )
        locator_text = (
            "relation="
            + ".".join(_quote_identifier(component) for component in components)
            + f" relation_scope={locator.relation_scope.value}"
        )
    else:
        locator_text = (
            f"sql_dialect={_escape_inline_text(locator.dialect.value)} "
            f"sql_sha256={locator.content_sha256}"
        )
    return (
        f"{side.direction.value.title()}: "
        f"connection={_escape_inline_text(side.connection_id)} "
        f"dataset={_escape_inline_text(side.dataset_id)} {locator_text}"
    )


def _quote_identifier(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _escape_inline_text(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)[1:-1]


def _evidence_field_text(value: EvidenceFieldValue) -> str:
    field_name = _escape_inline_text(value.field_name)
    if value.availability is EvidenceValueAvailability.REDACTED:
        return f"{field_name}=<redacted>"
    if value.is_null:
        return f"{field_name}=NULL"
    canonical_value = (
        value.canonical_text if value.canonical_text is not None else value.canonical_hex
    )
    if canonical_value is None:
        raise ApplicationError("stored evidence field is missing its canonical value")
    rendered_value = (
        json.dumps(canonical_value, ensure_ascii=False)
        if value.logical_type is LogicalType.STRING
        else canonical_value
    )
    return f"{field_name}={rendered_value}"


def _structural_summary_lines(result: RunResult) -> tuple[str, ...]:
    if result.guarantee is not Guarantee.STRUCTURAL:
        return ()
    reasons = tuple(
        reason for reason in result.reasons if reason.code is ReasonCode.CONTRACT_VIOLATION
    )
    if len(reasons) != 1:
        raise ApplicationError("structural result requires one contract-violation summary")
    reason = reasons[0]
    names = tuple(parameter.name for parameter in reason.safe_parameters)
    if names != _STRUCTURAL_SUMMARY_PARAMETER_NAMES:
        raise ApplicationError("structural result has an unsupported key-summary shape")
    values = {
        parameter.name: _canonical_summary_count(parameter.value, parameter.name)
        for parameter in reason.safe_parameters
    }
    lines: list[str] = []
    for label, prefix in (("Reference", "reference"), ("Target", "target")):
        valid = values[f"{prefix}_valid_key_count"]
        distinct = values[f"{prefix}_distinct_key_count"]
        if distinct > valid:
            raise ApplicationError("structural result has invalid distinct-key counts")
        lines.append(
            f"{label} key summary: rows={values[f'{prefix}_row_count']}, "
            f"null_keys={values[f'{prefix}_null_key_count']}, "
            f"duplicate_excess={valid - distinct}, valid_keys={valid}, "
            f"distinct_keys={distinct}"
        )
    return tuple(lines)


def _canonical_summary_count(value: str, name: str) -> int:
    if not value.isascii() or not value.isdecimal() or (len(value) > 1 and value[0] == "0"):
        raise ApplicationError(f"structural result parameter {name!r} is not canonical decimal")
    return int(value)


def _total_text(total: Total) -> str:
    if isinstance(total, UnavailableTotal):
        return f"unavailable ({total.reason.value})"
    return f"{total.value} ({total.precision})"


def _write_json_model(model: BaseModel, stdout: TextIO) -> None:
    stdout.write(model.model_dump_json())
    stdout.write("\n")


def _write_lines(stdout: TextIO, lines: tuple[str, ...]) -> None:
    stdout.write("\n".join(lines))
    stdout.write("\n")


def _requests_json_output(arguments: Sequence[str]) -> bool:
    for index, value in enumerate(arguments):
        if value == "--output" and index + 1 < len(arguments):
            return arguments[index + 1] == "json"
        if value == "--output=json":
            return True
    return False


def _write_error(stderr: TextIO, output_json: bool, code: str, message: str) -> int:
    if output_json:
        payload = {
            "schema_version": 1,
            "error": {
                "code": code,
                "message": message,
            },
        }
        stderr.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        stderr.write("\n")
    else:
        stderr.write(f"Error [{code}]: {message}\n")
    return 2


def _system_exit_code(error: SystemExit) -> int:
    if type(error.code) is int:
        return error.code
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
