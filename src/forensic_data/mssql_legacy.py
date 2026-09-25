# pyright: reportPrivateUsage=false

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from forensic_data.canonical import CanonicalSchema
from forensic_data.mssql import (
    INT32_MAX,
    MssqlConnectionSettings,
    MssqlDataValidationError,
    MssqlFetchLimits,
    MssqlInspectedRelation,
    MssqlMetadataError,
    MssqlProtectedReadContext,
    MssqlQuery,
    MssqlReadContext,
    MssqlReadContextEvidence,
    MssqlRelationAcquisition,
    MssqlRetryPolicy,
    MssqlRow,
    MssqlServerProfile,
    MssqlSnapshotMetadataChangedQueryError,
    MssqlTransport,
    MssqlTransportError,
    MssqlValue,
    UnsupportedMssqlProfileError,
    UnsupportedMssqlRelationError,
    _close_opening_transport,
    _mssql_source_deadline,
    _open_mssql_transport_budgeted,
    _read_context_evidence_from_row,
    _require_boolean,
    _require_bounded_integer,
    _require_integer,
    _require_optional_integer,
    _require_text,
    _server_profile_from_row,
    _snapshot_metadata_changed_error,
    _validated_relation_metadata,
)
from forensic_data.mssql_profile import MssqlRuntimeProfile
from forensic_data.mssql_resources import (
    MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256,
    MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES,
)
from forensic_data.mssql_sql import (
    MssqlCanonicalQuery,
    MssqlIntegerRangeRequest,
    MssqlLoweringError,
    MssqlRelation,
    MssqlScopePredicate,
    MssqlUtf8HelperBinding,
    _mssql_2016_supported_storage_predicate,
    build_mssql_2016_integer_key_summary_query,
    build_mssql_2016_integer_range_fingerprint_query,
    build_mssql_2016_integer_range_rows_query,
    build_mssql_2016_relation_manifest_query,
)
from forensic_data.postgres import (
    PostgresReadDeadlineExceededError,
    PostgresSourceBudgetAttempt,
    PostgresSourceBudgetExceededError,
    PostgresSourceDirection,
)

_EXPECTED_HELPER_SCHEMA = "dfe_ext"
_EXPECTED_HELPER_NAME = "canonical_utf8_v1"
_EXPECTED_HELPER_DEFINITION_BYTES = MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES
_EXPECTED_HELPER_DEFINITION_SHA256 = MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256
_EXPECTED_HELPER_PARAMETER_COUNT = 2
_EXPECTED_HELPER_VECTOR_COUNT = 12
_SESSION_SET_OPTIONS = (
    "SET ANSI_NULLS ON; "
    "SET ANSI_PADDING ON; "
    "SET ANSI_WARNINGS ON; "
    "SET ARITHABORT ON; "
    "SET CONCAT_NULL_YIELDS_NULL ON; "
    "SET NUMERIC_ROUNDABORT OFF; "
    "SET QUOTED_IDENTIFIER ON; "
)


class Mssql2016ReadContext(MssqlReadContext):
    def _build_relation_metadata_query(self, relation: MssqlRelation) -> MssqlQuery:
        return _mssql_2016_relation_metadata_query(relation)

    def _relation_identity(
        self,
        relation: MssqlRelation,
        relation_rows: tuple[MssqlRow, ...],
    ) -> tuple[int, int, int]:
        if len(relation_rows) != 1:
            raise MssqlMetadataError(
                "SQL Server relation is missing or not visible to the reader: "
                f"schema={relation.schema_name!r}, table={relation.table_name!r}"
            )
        return _validated_relation_metadata(
            relation_rows[0],
            relation,
            self.profile,
            _validated_mssql_2016_relation_storage,
        )


class Mssql2016ProtectedReadContext(MssqlProtectedReadContext):
    def __init__(
        self,
        read_context: Mssql2016ReadContext,
        acquisitions: tuple[MssqlRelationAcquisition, ...],
        source_budget: PostgresSourceBudgetAttempt,
        source_direction: PostgresSourceDirection,
    ) -> None:
        helper = read_context.profile.canonical_utf8_helper
        if type(helper) is not MssqlUtf8HelperBinding:
            raise UnsupportedMssqlProfileError(
                "SQL Server 2016 protected context requires a frozen UTF-8 helper binding"
            )
        super().__init__(read_context, acquisitions, source_budget, source_direction)
        self._helper = helper

    @property
    def runtime_profile(self) -> MssqlRuntimeProfile:
        return MssqlRuntimeProfile.MSSQL_2016

    def _build_integer_key_summary_query(
        self,
        schema: CanonicalSchema,
        inspection: MssqlInspectedRelation,
        key_field_index: int,
        scope: MssqlScopePredicate | None,
        max_encoded_envelope_bytes: int,
    ) -> MssqlCanonicalQuery:
        return build_mssql_2016_integer_key_summary_query(
            schema,
            inspection,
            self._helper,
            key_field_index,
            scope,
            max_encoded_envelope_bytes,
        )

    def _build_integer_range_fingerprint_query(
        self,
        schema: CanonicalSchema,
        inspection: MssqlInspectedRelation,
        key_field_index: int,
        scope: MssqlScopePredicate | None,
        ranges: tuple[MssqlIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
    ) -> MssqlCanonicalQuery:
        return build_mssql_2016_integer_range_fingerprint_query(
            schema,
            inspection,
            self._helper,
            key_field_index,
            scope,
            ranges,
            max_encoded_envelope_bytes,
        )

    def _build_integer_range_rows_query(
        self,
        schema: CanonicalSchema,
        inspection: MssqlInspectedRelation,
        key_field_index: int,
        scope: MssqlScopePredicate | None,
        ranges: tuple[MssqlIntegerRangeRequest, ...],
        max_encoded_envelope_bytes: int,
    ) -> MssqlCanonicalQuery:
        return build_mssql_2016_integer_range_rows_query(
            schema,
            inspection,
            self._helper,
            key_field_index,
            scope,
            ranges,
            max_encoded_envelope_bytes,
        )

    def _build_relation_manifest_query(
        self,
        schema: CanonicalSchema,
        inspection: MssqlInspectedRelation,
        dataset_id: str,
        scope_digest: str,
        max_record_bytes: int,
    ) -> MssqlCanonicalQuery:
        return build_mssql_2016_relation_manifest_query(
            schema,
            inspection,
            self._helper,
            dataset_id,
            scope_digest,
            max_record_bytes,
        )


def open_mssql_2016_protected_read_context(
    settings: MssqlConnectionSettings,
    retry_policy: MssqlRetryPolicy,
    acquisitions: tuple[MssqlRelationAcquisition, ...],
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> MssqlProtectedReadContext:
    _validate_protected_open_request(acquisitions, source_budget, source_direction)
    context = _open_mssql_2016_read_context_budgeted(
        settings,
        retry_policy,
        source_budget,
        source_direction,
    )
    try:
        for acquisition in acquisitions:
            context.inspect_relation_budgeted(
                acquisition.schema,
                acquisition.relation,
                acquisition.column_names,
                acquisition.max_metadata_record_bytes,
                acquisition.max_metadata_total_bytes,
                source_budget,
                source_direction,
                _mssql_source_deadline(source_budget),
            )
        return Mssql2016ProtectedReadContext(
            context,
            acquisitions,
            source_budget,
            source_direction,
        )
    except MssqlLoweringError as error:
        context.close()
        message = str(error).strip()
        if not message:
            raise MssqlDataValidationError(
                "SQL Server 2016 relation inspection failed without an actionable explanation"
            ) from error
        raise UnsupportedMssqlRelationError(message) from error
    except (
        MssqlTransportError,
        PostgresReadDeadlineExceededError,
        PostgresSourceBudgetExceededError,
        TypeError,
        ValueError,
    ):
        context.close()
        raise


def _validate_protected_open_request(
    acquisitions: tuple[MssqlRelationAcquisition, ...],
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> None:
    if type(acquisitions) is not tuple or not acquisitions:
        raise ValueError(
            "SQL Server 2016 protected context requires a non-empty immutable acquisition set"
        )
    if not isinstance(cast(object, source_budget), PostgresSourceBudgetAttempt):
        raise TypeError("SQL Server 2016 protected context requires PostgresSourceBudgetAttempt")
    if not isinstance(cast(object, source_direction), PostgresSourceDirection):
        raise TypeError("SQL Server 2016 protected context requires PostgresSourceDirection")
    for acquisition in acquisitions:
        if type(acquisition) is not MssqlRelationAcquisition:
            raise TypeError(
                "SQL Server 2016 protected acquisitions must contain MssqlRelationAcquisition"
            )
    if len({item.relation for item in acquisitions}) != len(acquisitions):
        raise ValueError("SQL Server 2016 protected acquisitions must reference distinct relations")


def _open_mssql_2016_read_context_budgeted(
    settings: MssqlConnectionSettings,
    retry_policy: MssqlRetryPolicy,
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> Mssql2016ReadContext:
    if type(settings) is not MssqlConnectionSettings:
        raise TypeError("settings must be MssqlConnectionSettings")
    if type(retry_policy) is not MssqlRetryPolicy:
        raise TypeError("retry_policy must be MssqlRetryPolicy")
    transport = _open_mssql_transport_budgeted(
        settings,
        retry_policy,
        source_budget,
        source_direction,
    )
    try:
        profile = _read_mssql_2016_profile(
            transport,
            source_budget,
            source_direction,
        )
        started_at = datetime.now(UTC)
        transport.configure_snapshot_transaction()
        evidence = _read_mssql_2016_snapshot_evidence(
            transport,
            profile,
            started_at,
            source_budget,
            source_direction,
        )
        return Mssql2016ReadContext(transport, profile, evidence)
    except MssqlSnapshotMetadataChangedQueryError as error:
        _close_opening_transport(transport)
        raise _snapshot_metadata_changed_error(error) from error
    except (
        MssqlTransportError,
        PostgresReadDeadlineExceededError,
        PostgresSourceBudgetExceededError,
        TypeError,
        ValueError,
    ):
        _close_opening_transport(transport)
        raise


def _read_mssql_2016_profile(
    transport: MssqlTransport,
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> MssqlServerProfile:
    result = transport.execute_budgeted(
        MssqlQuery(
            query_id=uuid4(),
            statement=_mssql_2016_profile_query(),
            parameters=(),
        ),
        _profile_fetch_limits(),
        source_budget.dispatch_query(source_direction, 0),
        _mssql_source_deadline(source_budget),
    )
    if len(result.rows) != 1:
        raise MssqlDataValidationError(
            "SQL Server 2016 capability and helper probe must return exactly one row"
        )
    row = result.rows[0]
    if len(row) != 63:
        raise MssqlDataValidationError(
            "SQL Server 2016 capability and helper probe returned an unexpected field count: "
            f"expected=63, actual={len(row)}"
        )
    profile = _server_profile_from_row(transport.evidence, row[:20])
    if not profile.can_view_definition:
        raise UnsupportedMssqlProfileError(
            "SQL Server 2016 capability profile is unsupported: "
            f"database={profile.database_name!r}, database_id={profile.database_id}; "
            "reader lacks database VIEW DEFINITION required to prove the UTF-8 helper "
            "and complete row-level-security absence"
        )
    helper = _helper_binding_from_row(row[20:])
    legacy_profile = replace(profile, canonical_utf8_helper=helper)
    _validate_mssql_2016_profile(legacy_profile)
    return legacy_profile


def _read_mssql_2016_snapshot_evidence(
    transport: MssqlTransport,
    profile: MssqlServerProfile,
    started_at: datetime,
    source_budget: PostgresSourceBudgetAttempt,
    source_direction: PostgresSourceDirection,
) -> MssqlReadContextEvidence:
    result = transport.execute_budgeted(
        MssqlQuery(
            query_id=uuid4(),
            statement=_mssql_2016_snapshot_query(),
            parameters=(),
        ),
        _profile_fetch_limits(),
        source_budget.dispatch_query(source_direction, 0),
        _mssql_source_deadline(source_budget),
    )
    if len(result.rows) != 1:
        raise MssqlDataValidationError(
            "SQL Server 2016 SNAPSHOT helper proof must return exactly one row"
        )
    row = result.rows[0]
    if len(row) != 53:
        raise MssqlDataValidationError(
            "SQL Server 2016 SNAPSHOT helper proof returned an unexpected field count: "
            f"expected=53, actual={len(row)}"
        )
    evidence = _read_context_evidence_from_row(
        profile,
        row[:10],
        started_at,
        "UTF-8 helper vector witness",
    )
    active_helper = _helper_binding_from_row(row[10:])
    if active_helper != profile.canonical_utf8_helper:
        raise UnsupportedMssqlProfileError(
            "SQL Server 2016 UTF-8 helper binding changed before the SNAPSHOT context was sealed: "
            f"database={profile.database_name!r}, helper="
            f"{_EXPECTED_HELPER_SCHEMA}.{_EXPECTED_HELPER_NAME}"
        )
    return evidence


def _profile_fetch_limits() -> MssqlFetchLimits:
    return MssqlFetchLimits(
        fetch_batch_records=1,
        max_records=1,
        max_value_bytes=1_024,
        max_record_bytes=16_384,
        max_total_bytes=16_384,
        max_declared_value_bytes=1_024,
        max_declared_record_bytes=16_384,
    )


def _validate_mssql_2016_profile(profile: MssqlServerProfile) -> None:
    helper = profile.canonical_utf8_helper
    if type(helper) is not MssqlUtf8HelperBinding:
        raise UnsupportedMssqlProfileError(
            "SQL Server 2016 capability profile omitted the required UTF-8 helper binding"
        )
    failures: list[str] = []
    if (
        profile.snapshot_isolation_state != 1
        or profile.snapshot_isolation_state_description != "ON"
    ):
        failures.append(
            "ALLOW_SNAPSHOT_ISOLATION is not ON: "
            f"snapshot_isolation_state={profile.snapshot_isolation_state}, "
            "snapshot_isolation_state_desc="
            f"{profile.snapshot_isolation_state_description!r}, "
            f"read_committed_snapshot={profile.read_committed_snapshot}"
        )
    if profile.canonical_utf8_code_page != 65_001:
        failures.append(
            "canonical helper output code page differs from UTF-8: "
            f"code_page={profile.canonical_utf8_code_page}, required=65001"
        )
    if not profile.can_view_definition:
        failures.append(
            "reader lacks database VIEW DEFINITION required to prove complete "
            "row-level-security absence"
        )
    if profile.product_version != profile.driver.server_version:
        failures.append(
            "driver and capability probes disagree on server version: "
            f"driver={profile.driver.server_version!r}, capability={profile.product_version!r}"
        )
    failures.extend(_helper_binding_failures(helper, profile))
    if failures:
        raise UnsupportedMssqlProfileError(
            "SQL Server 2016 capability profile is unsupported: "
            f"database={profile.database_name!r}, database_id={profile.database_id}; "
            + "; ".join(failures)
        )


def _helper_binding_failures(
    helper: MssqlUtf8HelperBinding,
    profile: MssqlServerProfile,
) -> list[str]:
    failures: list[str] = []
    if (
        helper.database_id != profile.database_id
        or helper.database_name != profile.database_name
        or helper.database_collation != profile.database_collation
        or helper.database_compatibility_level != profile.compatibility_level
    ):
        failures.append(
            "helper database binding differs from the active database: "
            f"actual=({helper.database_id}, {helper.database_name!r}, "
            f"{helper.database_collation!r}, {helper.database_compatibility_level}), "
            f"expected=({profile.database_id}, {profile.database_name!r}, "
            f"{profile.database_collation!r}, {profile.compatibility_level})"
        )
    if (
        helper.schema_name != _EXPECTED_HELPER_SCHEMA
        or helper.object_name != _EXPECTED_HELPER_NAME
        or helper.object_type != "FN"
    ):
        failures.append(
            "helper object identity differs from the fixed scalar function contract: "
            f"actual={helper.schema_name}.{helper.object_name}, type={helper.object_type!r}"
        )
    if helper.definition_utf16_bytes != _EXPECTED_HELPER_DEFINITION_BYTES:
        failures.append(
            "helper definition length differs from the provisioned contract: "
            f"actual={helper.definition_utf16_bytes}, "
            f"required={_EXPECTED_HELPER_DEFINITION_BYTES}"
        )
    if helper.definition_sha256 != _EXPECTED_HELPER_DEFINITION_SHA256:
        failures.append(
            "helper definition digest differs from the provisioned contract: "
            f"actual={helper.definition_sha256.hex()}, "
            f"required={_EXPECTED_HELPER_DEFINITION_SHA256.hex()}"
        )
    return_signature = (
        helper.return_type_schema,
        helper.return_type_name,
        helper.return_max_length,
        helper.return_is_output,
        helper.return_has_default_value,
    )
    if return_signature != ("sys", "varbinary", -1, True, False):
        failures.append(
            f"helper return signature differs from sys.varbinary(max): actual={return_signature!r}"
        )
    input_signature = (
        helper.input_parameter_name,
        helper.input_type_schema,
        helper.input_type_name,
        helper.input_max_length,
        helper.input_is_output,
        helper.input_has_default_value,
    )
    if input_signature != ("@value", "sys", "nvarchar", -1, False, False):
        failures.append(
            "helper input signature differs from @value sys.nvarchar(max): "
            f"actual={input_signature!r}"
        )
    module_properties = (
        helper.uses_ansi_nulls,
        helper.uses_quoted_identifier,
        helper.is_schema_bound,
        helper.uses_database_collation,
        helper.null_on_null_input,
        helper.execute_as_principal_id,
        helper.is_deterministic,
        helper.is_precise,
        helper.is_encrypted,
    )
    if module_properties != (True, True, True, True, True, None, True, True, False):
        failures.append(
            f"helper module properties differ from the fixed contract: actual={module_properties!r}"
        )
    if (
        not helper.can_execute
        or not helper.can_view_definition
        or helper.can_alter
        or helper.can_control
    ):
        failures.append(
            "reader lacks required helper permissions: "
            f"execute={helper.can_execute}, view_definition={helper.can_view_definition}, "
            f"alter={helper.can_alter}, control={helper.can_control}"
        )
    session_options = (
        helper.ansi_nulls,
        helper.ansi_padding,
        helper.ansi_warnings,
        helper.arithabort,
        helper.concat_null_yields_null,
        helper.numeric_roundabort,
        helper.quoted_identifier,
    )
    if session_options != (True, True, True, True, True, False, True):
        failures.append(
            "reader session SET options differ from the canonical helper contract: "
            f"actual={session_options!r}"
        )
    return failures


def _helper_binding_from_row(row: tuple[MssqlValue, ...]) -> MssqlUtf8HelperBinding:
    if len(row) != 43:
        raise MssqlDataValidationError(
            "SQL Server 2016 helper catalog probe returned an unexpected field count: "
            f"expected=43, actual={len(row)}"
        )
    parameter_count = _require_bounded_integer(
        row[0],
        "helper_parameter_count",
        0,
        INT32_MAX,
    )
    if parameter_count != _EXPECTED_HELPER_PARAMETER_COUNT:
        raise UnsupportedMssqlProfileError(
            "SQL Server 2016 UTF-8 helper parameter count differs from the contract: "
            f"actual={parameter_count}, required={_EXPECTED_HELPER_PARAMETER_COUNT}"
        )
    return MssqlUtf8HelperBinding(
        database_id=_require_bounded_integer(row[1], "helper_database_id", 1, INT32_MAX),
        database_name=_require_text(row[2], "helper_database_name"),
        database_collation=_require_text(row[3], "helper_database_collation"),
        database_compatibility_level=_require_bounded_integer(
            row[4], "helper_database_compatibility_level", 1, INT32_MAX
        ),
        schema_id=_require_bounded_integer(row[5], "helper_schema_id", 1, INT32_MAX),
        schema_name=_require_text(row[6], "helper_schema_name"),
        object_id=_require_bounded_integer(row[7], "helper_object_id", 1, INT32_MAX),
        object_name=_require_text(row[8], "helper_object_name"),
        object_type=_require_text(row[9], "helper_object_type"),
        definition_utf16_bytes=_require_bounded_integer(
            row[10],
            "helper_definition_utf16_bytes",
            1,
            INT32_MAX,
        ),
        definition_sha256=_require_sha256(row[11]),
        return_type_schema=_require_text(row[12], "helper_return_type_schema"),
        return_type_name=_require_text(row[13], "helper_return_type_name"),
        return_max_length=_require_integer(row[14], "helper_return_max_length"),
        return_is_output=_require_boolean(row[15], "helper_return_is_output"),
        return_has_default_value=_require_boolean(
            row[16],
            "helper_return_has_default_value",
        ),
        input_parameter_name=_require_text(row[17], "helper_input_parameter_name"),
        input_type_schema=_require_text(row[18], "helper_input_type_schema"),
        input_type_name=_require_text(row[19], "helper_input_type_name"),
        input_max_length=_require_integer(row[20], "helper_input_max_length"),
        input_is_output=_require_boolean(row[21], "helper_input_is_output"),
        input_has_default_value=_require_boolean(
            row[22],
            "helper_input_has_default_value",
        ),
        uses_ansi_nulls=_require_boolean(row[23], "helper_uses_ansi_nulls"),
        uses_quoted_identifier=_require_boolean(row[24], "helper_uses_quoted_identifier"),
        is_schema_bound=_require_boolean(row[25], "helper_is_schema_bound"),
        uses_database_collation=_require_boolean(
            row[26],
            "helper_uses_database_collation",
        ),
        null_on_null_input=_require_boolean(row[27], "helper_null_on_null_input"),
        execute_as_principal_id=_require_optional_integer(
            row[28],
            "helper_execute_as_principal_id",
        ),
        is_deterministic=_require_boolean(row[29], "helper_is_deterministic"),
        is_precise=_require_boolean(row[30], "helper_is_precise"),
        is_encrypted=_require_boolean(row[31], "helper_is_encrypted"),
        can_execute=_require_boolean(row[32], "helper_can_execute"),
        can_view_definition=_require_boolean(row[33], "helper_can_view_definition"),
        can_alter=_require_boolean(row[34], "helper_can_alter"),
        can_control=_require_boolean(row[35], "helper_can_control"),
        ansi_nulls=_require_boolean(row[36], "helper_session_ansi_nulls"),
        ansi_padding=_require_boolean(row[37], "helper_session_ansi_padding"),
        ansi_warnings=_require_boolean(row[38], "helper_session_ansi_warnings"),
        arithabort=_require_boolean(row[39], "helper_session_arithabort"),
        concat_null_yields_null=_require_boolean(
            row[40],
            "helper_session_concat_null_yields_null",
        ),
        numeric_roundabort=_require_boolean(row[41], "helper_session_numeric_roundabort"),
        quoted_identifier=_require_boolean(row[42], "helper_session_quoted_identifier"),
    )


def _require_sha256(value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise MssqlDataValidationError(
            "SQL Server 2016 helper definition digest must contain exactly 32 binary bytes"
        )
    return value


def _mssql_2016_profile_query() -> str:
    return (
        f"{_SESSION_SET_OPTIONS}"
        "SELECT CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')), "
        "TRY_CONVERT(int, SERVERPROPERTY(N'ProductMajorVersion')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductBuild')), "
        "TRY_CONVERT(int, SERVERPROPERTY(N'EngineEdition')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'Edition')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductLevel')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateLevel')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateReference')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'Collation')), "
        "CONVERT(int, DB_ID()), CONVERT(nvarchar(128), DB_NAME()), "
        "CONVERT(int, [dfe_database].[compatibility_level]), "
        "CONVERT(nvarchar(128), [dfe_database].[collation_name]), "
        "CONVERT(int, [dfe_database].[snapshot_isolation_state]), "
        "CONVERT(nvarchar(60), [dfe_database].[snapshot_isolation_state_desc]), "
        "CONVERT(bit, [dfe_database].[is_read_committed_snapshot_on]), "
        "CONVERT(bit, [dfe_database].[is_read_only]), "
        "CONVERT(nvarchar(128), DATABASEPROPERTYEX(DB_NAME(), N'Updateability')), "
        "CONVERT(int, 65001), "
        "CONVERT(bit, HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'VIEW DEFINITION')), "
        f"{_helper_projection()} "
        f"{_helper_source()} "
        "WHERE [dfe_database].[database_id] = DB_ID()"
    )


def _mssql_2016_snapshot_query() -> str:
    return (
        "SET NOCOUNT ON; "
        "DECLARE @dfe_vectors TABLE ("
        "[ordinal] int NOT NULL PRIMARY KEY, "
        "[input] nvarchar(max) NULL, "
        "[expected_exact] varbinary(max) NULL, "
        "[expected_length] bigint NULL, "
        "[expected_sha256] binary(32) NULL, "
        "[expect_null] bit NOT NULL); "
        "INSERT INTO @dfe_vectors VALUES "
        "(1, N'', 0x, CONVERT(bigint, 0), NULL, CONVERT(bit, 0)), "
        "(2, CONVERT(nvarchar(max), N'A|Б') + CONVERT(nvarchar(max), 0x3DD800DE) "
        "+ N'e' + NCHAR(0x0301) + N'  ', 0x417CD091F09F988065CC812020, "
        "CONVERT(bigint, 13), NULL, CONVERT(bit, 0)), "
        "(3, NCHAR(0x00E9), 0xC3A9, CONVERT(bigint, 2), NULL, CONVERT(bit, 0)), "
        "(4, N'e' + NCHAR(0x0301), 0x65CC81, CONVERT(bigint, 3), NULL, "
        "CONVERT(bit, 0)), "
        "(5, N'x ', 0x7820, CONVERT(bigint, 2), NULL, CONVERT(bit, 0)), "
        "(6, CONVERT(nvarchar(max), 0x00D800DC), 0xF0908080, CONVERT(bigint, 4), "
        "NULL, CONVERT(bit, 0)), "
        "(7, CONVERT(nvarchar(max), 0xFFDBFFDF), 0xF48FBFBF, CONVERT(bigint, 4), "
        "NULL, CONVERT(bit, 0)), "
        "(8, REPLICATE(CONVERT(nvarchar(max), N'Б'), 5000), NULL, "
        "CONVERT(bigint, 10000), "
        "0x6725D4195F0BDE14F5069D8E46F4E454E97BC2C4B5160B8A67AEBA1DFED208C5, "
        "CONVERT(bit, 0)), "
        "(9, CONVERT(nvarchar(max), 0x0000), NULL, NULL, NULL, CONVERT(bit, 1)), "
        "(10, CONVERT(nvarchar(max), 0x3DD8), NULL, NULL, NULL, CONVERT(bit, 1)), "
        "(11, CONVERT(nvarchar(max), 0x00DC), NULL, NULL, NULL, CONVERT(bit, 1)), "
        "(12, NULL, NULL, NULL, NULL, CONVERT(bit, 1)); "
        "DECLARE @dfe_results TABLE ("
        "[ordinal] int NOT NULL PRIMARY KEY, [actual] varbinary(max) NULL); "
        "INSERT INTO @dfe_results ([ordinal], [actual]) "
        "SELECT [dfe_vector].[ordinal], "
        "[dfe_ext].[canonical_utf8_v1]([dfe_vector].[input]) "
        "FROM @dfe_vectors AS [dfe_vector]; "
        "SELECT CONVERT(int, DB_ID()), "
        "CONVERT(int, [dfe_database].[compatibility_level]), "
        "CONVERT(int, [dfe_database].[snapshot_isolation_state]), "
        "CONVERT(bit, [dfe_database].[is_read_committed_snapshot_on]), "
        "CONVERT(int, @@SPID), CONVERT(int, @@TRANCOUNT), "
        "CONVERT(int, XACT_STATE()), "
        "CONVERT(int, [dfe_session].[transaction_isolation_level]), "
        "CONVERT(int, [dfe_session].[open_transaction_count]), "
        "CONVERT(bigint, CASE WHEN "
        f"(SELECT COUNT_BIG(*) FROM @dfe_results) = {_EXPECTED_HELPER_VECTOR_COUNT} "
        "AND NOT EXISTS ("
        "SELECT 1 FROM @dfe_vectors AS [dfe_vector] "
        "JOIN @dfe_results AS [dfe_result] "
        "ON [dfe_result].[ordinal] = [dfe_vector].[ordinal] "
        "WHERE ([dfe_vector].[expect_null] = CONVERT(bit, 1) "
        "AND [dfe_result].[actual] IS NOT NULL) "
        "OR ([dfe_vector].[expect_null] = CONVERT(bit, 0) AND ("
        "[dfe_result].[actual] IS NULL "
        "OR DATALENGTH([dfe_result].[actual]) <> [dfe_vector].[expected_length] "
        "OR ([dfe_vector].[expected_exact] IS NOT NULL "
        "AND [dfe_result].[actual] <> [dfe_vector].[expected_exact]) "
        "OR ([dfe_vector].[expected_sha256] IS NOT NULL AND ("
        "HASHBYTES('SHA2_256', [dfe_result].[actual]) IS NULL "
        "OR HASHBYTES('SHA2_256', [dfe_result].[actual]) "
        "<> [dfe_vector].[expected_sha256]))))"
        ") THEN 1 ELSE 0 END), "
        f"{_helper_projection()} "
        f"{_helper_source()} "
        "JOIN sys.dm_exec_sessions AS [dfe_session] "
        "ON [dfe_session].[session_id] = @@SPID "
        "WHERE [dfe_database].[database_id] = DB_ID()"
    )


def _helper_projection() -> str:
    return (
        "CONVERT(int, (SELECT COUNT_BIG(*) FROM sys.parameters AS [dfe_count_parameter] "
        "WHERE [dfe_count_parameter].[object_id] = [dfe_object].[object_id])), "
        "CONVERT(int, DB_ID()), CONVERT(nvarchar(128), DB_NAME()), "
        "CONVERT(nvarchar(128), [dfe_database].[collation_name]), "
        "CONVERT(int, [dfe_database].[compatibility_level]), "
        "CONVERT(int, [dfe_schema].[schema_id]), "
        "CONVERT(nvarchar(128), [dfe_schema].[name]), "
        "CONVERT(int, [dfe_object].[object_id]), "
        "CONVERT(nvarchar(128), [dfe_object].[name]), "
        "CONVERT(nvarchar(2), RTRIM([dfe_object].[type])), "
        "CONVERT(bigint, DATALENGTH([dfe_module].[definition])), "
        "CONVERT(varbinary(32), HASHBYTES('SHA2_256', "
        "CONVERT(varbinary(max), [dfe_module].[definition]))), "
        "CONVERT(nvarchar(128), [dfe_return_type_schema].[name]), "
        "CONVERT(nvarchar(128), [dfe_return_type].[name]), "
        "CONVERT(int, [dfe_return].[max_length]), "
        "CONVERT(bit, [dfe_return].[is_output]), "
        "CONVERT(bit, [dfe_return].[has_default_value]), "
        "CONVERT(nvarchar(128), [dfe_input].[name]), "
        "CONVERT(nvarchar(128), [dfe_input_type_schema].[name]), "
        "CONVERT(nvarchar(128), [dfe_input_type].[name]), "
        "CONVERT(int, [dfe_input].[max_length]), "
        "CONVERT(bit, [dfe_input].[is_output]), "
        "CONVERT(bit, [dfe_input].[has_default_value]), "
        "CONVERT(bit, [dfe_module].[uses_ansi_nulls]), "
        "CONVERT(bit, [dfe_module].[uses_quoted_identifier]), "
        "CONVERT(bit, [dfe_module].[is_schema_bound]), "
        "CONVERT(bit, [dfe_module].[uses_database_collation]), "
        "CONVERT(bit, [dfe_module].[null_on_null_input]), "
        "CONVERT(int, [dfe_module].[execute_as_principal_id]), "
        "CONVERT(bit, OBJECTPROPERTYEX([dfe_object].[object_id], N'IsDeterministic')), "
        "CONVERT(bit, OBJECTPROPERTYEX([dfe_object].[object_id], N'IsPrecise')), "
        "CONVERT(bit, OBJECTPROPERTYEX([dfe_object].[object_id], N'IsEncrypted')), "
        "CONVERT(bit, COALESCE(HAS_PERMS_BY_NAME("
        "N'dfe_ext.canonical_utf8_v1', N'OBJECT', N'EXECUTE'), 0)), "
        "CONVERT(bit, COALESCE(HAS_PERMS_BY_NAME("
        "N'dfe_ext.canonical_utf8_v1', N'OBJECT', N'VIEW DEFINITION'), 0)), "
        "CONVERT(bit, COALESCE(HAS_PERMS_BY_NAME("
        "N'dfe_ext.canonical_utf8_v1', N'OBJECT', N'ALTER'), 0)), "
        "CONVERT(bit, COALESCE(HAS_PERMS_BY_NAME("
        "N'dfe_ext.canonical_utf8_v1', N'OBJECT', N'CONTROL'), 0)), "
        "CONVERT(bit, SESSIONPROPERTY(N'ANSI_NULLS')), "
        "CONVERT(bit, SESSIONPROPERTY(N'ANSI_PADDING')), "
        "CONVERT(bit, SESSIONPROPERTY(N'ANSI_WARNINGS')), "
        "CONVERT(bit, SESSIONPROPERTY(N'ARITHABORT')), "
        "CONVERT(bit, SESSIONPROPERTY(N'CONCAT_NULL_YIELDS_NULL')), "
        "CONVERT(bit, SESSIONPROPERTY(N'NUMERIC_ROUNDABORT')), "
        "CONVERT(bit, SESSIONPROPERTY(N'QUOTED_IDENTIFIER'))"
    )


def _helper_source() -> str:
    return (
        "FROM sys.databases AS [dfe_database] "
        "LEFT JOIN sys.objects AS [dfe_object] "
        "ON [dfe_object].[object_id] = OBJECT_ID("
        "N'dfe_ext.canonical_utf8_v1', N'FN') "
        "LEFT JOIN sys.schemas AS [dfe_schema] "
        "ON [dfe_schema].[schema_id] = [dfe_object].[schema_id] "
        "LEFT JOIN sys.sql_modules AS [dfe_module] "
        "ON [dfe_module].[object_id] = [dfe_object].[object_id] "
        "LEFT JOIN sys.parameters AS [dfe_return] "
        "ON [dfe_return].[object_id] = [dfe_object].[object_id] "
        "AND [dfe_return].[parameter_id] = 0 "
        "LEFT JOIN sys.types AS [dfe_return_type] "
        "ON [dfe_return_type].[user_type_id] = [dfe_return].[user_type_id] "
        "LEFT JOIN sys.schemas AS [dfe_return_type_schema] "
        "ON [dfe_return_type_schema].[schema_id] = [dfe_return_type].[schema_id] "
        "LEFT JOIN sys.parameters AS [dfe_input] "
        "ON [dfe_input].[object_id] = [dfe_object].[object_id] "
        "AND [dfe_input].[parameter_id] = 1 "
        "LEFT JOIN sys.types AS [dfe_input_type] "
        "ON [dfe_input_type].[user_type_id] = [dfe_input].[user_type_id] "
        "LEFT JOIN sys.schemas AS [dfe_input_type_schema] "
        "ON [dfe_input_type_schema].[schema_id] = [dfe_input_type].[schema_id]"
    )


def _mssql_2016_relation_metadata_query(relation: MssqlRelation) -> MssqlQuery:
    securable = "QUOTENAME([dfe_schema].[name]) + N'.' + QUOTENAME([dfe_table].[name])"
    supported_storage = _mssql_2016_supported_storage_predicate(
        "dfe_table",
        "dfe_storage_column",
    )
    statement = (
        "SELECT CONVERT(int, DB_ID()), CONVERT(nvarchar(128), DB_NAME()), "
        "CONVERT(int, [dfe_schema].[schema_id]), "
        "CONVERT(nvarchar(128), [dfe_schema].[name]), "
        "CONVERT(int, [dfe_table].[object_id]), "
        "CONVERT(nvarchar(128), [dfe_table].[name]), "
        "CONVERT(nvarchar(2), RTRIM([dfe_table].[type])), "
        "CONVERT(bit, [dfe_table].[is_ms_shipped]), "
        "CONVERT(bit, [dfe_table].[is_memory_optimized]), "
        "CONVERT(int, [dfe_table].[temporal_type]), "
        "CONVERT(bit, [dfe_table].[is_external]), "
        f"CONVERT(bit, CASE WHEN {supported_storage} THEN 0 ELSE 1 END), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'SELECT')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'INSERT')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'UPDATE')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'DELETE')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'ALTER')), "
        f"CONVERT(int, HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'CONTROL')), "
        "CONVERT(bit, CASE WHEN EXISTS ("
        "SELECT 1 FROM sys.columns AS [dfe_writable_column] "
        "WHERE [dfe_writable_column].[object_id] = [dfe_table].[object_id] "
        f"AND HAS_PERMS_BY_NAME({securable}, N'OBJECT', N'UPDATE', "
        "[dfe_writable_column].[name], N'COLUMN') = 1) THEN 1 ELSE 0 END), "
        "CONVERT(bit, HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'VIEW DEFINITION')), "
        "CONVERT(bit, CASE WHEN EXISTS ("
        "SELECT 1 FROM sys.security_predicates AS [dfe_predicate] "
        "JOIN sys.security_policies AS [dfe_policy] "
        "ON [dfe_policy].[object_id] = [dfe_predicate].[object_id] "
        "WHERE [dfe_predicate].[target_object_id] = [dfe_table].[object_id] "
        "AND [dfe_policy].[is_enabled] = 1) THEN 1 ELSE 0 END) "
        "FROM sys.schemas AS [dfe_schema] "
        "JOIN sys.tables AS [dfe_table] "
        "ON [dfe_table].[schema_id] = [dfe_schema].[schema_id] "
        "WHERE [dfe_schema].[name] = ? AND [dfe_table].[name] = ?"
    )
    return MssqlQuery(
        query_id=uuid4(),
        statement=statement,
        parameters=(relation.schema_name, relation.table_name),
    )


def _validated_mssql_2016_relation_storage(
    row: MssqlRow,
) -> tuple[int, tuple[str, ...]]:
    if len(row) != 21:
        raise MssqlDataValidationError(
            "SQL Server 2016 relation catalog probe returned an unexpected field count: "
            f"expected=21, actual={len(row)}"
        )
    has_hidden_or_generated_storage = _require_boolean(
        row[11],
        "has_hidden_or_generated_storage",
    )
    if not has_hidden_or_generated_storage:
        return 12, ()
    return (
        12,
        (
            "relation has hidden or GENERATED ALWAYS storage columns associated with an "
            "unsupported graph, ledger, temporal, or other system-managed table profile",
        ),
    )
