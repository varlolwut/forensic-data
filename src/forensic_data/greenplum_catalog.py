from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import cast, final

from forensic_data.postgres import (
    INT64_MAX,
    UINT32_MAX,
    DatabaseRow,
    PostgresDataValidationError,
    PostgresMetadataError,
    postgres_field_binding_from_catalog_row,
)
from forensic_data.postgres_sql import MAX_COMPILED_RELATION_MEMBERS, PostgresFieldBinding

_BYTEA_OID = 17
_INT8_OID = 20
_INT2_OID = 21
_INT4_OID = 23
_TEXT_OID = 25
_SHA256_BYTES = 32
_MAX_HASH_ROWS = 10_000
_INTEGER_TYPE_OIDS = (_INT2_OID, _INT4_OID, _INT8_OID)

type GreenplumCatalogParameter = str | int


class GreenplumStorageKind(StrEnum):
    HEAP = "heap"
    APPEND_OPTIMIZED_ROW = "append_optimized_row"
    APPEND_OPTIMIZED_COLUMN = "append_optimized_column"


@final
@dataclass(frozen=True, slots=True)
class GreenplumStorageProfile:
    kind: GreenplumStorageKind
    append_only_catalog_present: bool
    relation_options: tuple[tuple[str, str], ...]
    block_size_bytes: int | None
    compression_type: str | None
    compression_level: int | None
    checksum: bool | None
    column_store: bool | None


class GreenplumCatalogError(ValueError):
    """Base error for malformed or absent Greenplum catalog evidence."""


class GreenplumCatalogDataError(GreenplumCatalogError):
    """A Greenplum catalog returned a value outside the typed probe contract."""


class GreenplumCatalogMetadataError(GreenplumCatalogError):
    """Required Greenplum catalog metadata is absent or invisible."""


@final
@dataclass(frozen=True, slots=True)
class GreenplumColumnProbe:
    field_name: str
    column_name: str

    def __post_init__(self) -> None:
        _validate_text(self.field_name, "Greenplum logical field name")
        _validate_identifier(self.column_name, "Greenplum column name")


@dataclass(frozen=True, slots=True)
class GreenplumRelationRequest:
    schema_name: str
    relation_name: str
    columns: tuple[GreenplumColumnProbe, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.schema_name, "Greenplum schema name")
        _validate_identifier(self.relation_name, "Greenplum relation name")
        if type(self.columns) is not tuple or not self.columns:
            raise ValueError("Greenplum relation probe requires an immutable column mapping")
        if len(self.columns) > MAX_COMPILED_RELATION_MEMBERS:
            raise ValueError(
                "Greenplum relation probe column count exceeds the supported maximum: "
                f"columns={len(self.columns)}, maximum={MAX_COMPILED_RELATION_MEMBERS}"
            )
        for index, column in enumerate(self.columns):
            if type(column) is not GreenplumColumnProbe:
                raise TypeError(
                    "Greenplum relation probe column must be a GreenplumColumnProbe: "
                    f"index={index}, type={type(column).__name__}"
                )
        field_names = tuple(column.field_name for column in self.columns)
        column_names = tuple(column.column_name for column in self.columns)
        if len(set(field_names)) != len(field_names):
            raise ValueError("Greenplum relation probe logical field names must be unique")
        if len(set(column_names)) != len(column_names):
            raise ValueError("Greenplum relation probe column names must be unique")

    def column_names(self) -> tuple[str, ...]:
        return tuple(column.column_name for column in self.columns)


@final
@dataclass(frozen=True, slots=True)
class GreenplumRelationProbeRequest(GreenplumRelationRequest):
    hash_record_id_column: str
    hash_input_column: str
    hash_row_limit: int

    def __post_init__(self) -> None:
        GreenplumRelationRequest.__post_init__(self)
        column_names = self.column_names()
        _validate_identifier(
            self.hash_record_id_column,
            "Greenplum distributed hash record ID column",
        )
        _validate_identifier(
            self.hash_input_column,
            "Greenplum distributed hash input column",
        )
        if self.hash_record_id_column not in column_names:
            raise ValueError(
                "Greenplum distributed hash record ID column must be in the requested columns"
            )
        if self.hash_input_column not in column_names:
            raise ValueError(
                "Greenplum distributed hash input column must be in the requested columns"
            )
        if (
            type(self.hash_row_limit) is not int
            or self.hash_row_limit < 1
            or self.hash_row_limit > _MAX_HASH_ROWS
        ):
            raise ValueError(
                "Greenplum distributed hash row limit must be an integer between "
                f"1 and {_MAX_HASH_ROWS}"
            )


@final
@dataclass(frozen=True, slots=True)
class GreenplumSegment:
    content_id: int
    role: str
    preferred_role: str
    status: str


@final
@dataclass(frozen=True, slots=True)
class GreenplumTopology:
    segments: tuple[GreenplumSegment, ...]
    primary_content_ids: tuple[int, ...]


@final
@dataclass(frozen=True, slots=True)
class GreenplumReaderIdentity:
    user_name: str
    is_superuser: bool
    can_create_role: bool
    can_create_database: bool
    can_login: bool
    default_transaction_read_only: bool
    transaction_read_only: bool


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumRelationCatalog:
    relation_oid: int
    relation_row_type_oid: int
    schema_name: str
    relation_name: str
    relation_kind: str
    storage_code: str
    storage_kind: GreenplumStorageKind
    storage_profile: GreenplumStorageProfile
    has_distribution_policy: bool
    distribution_attribute_numbers: tuple[int, ...]
    reader_has_select: bool
    reader_has_insert: bool
    reader_has_update: bool
    reader_has_delete: bool
    reader_has_truncate: bool
    reader_has_schema_usage: bool


@final
@dataclass(frozen=True, slots=True)
class GreengageRelationCatalog:
    relation_oid: int
    relation_row_type_oid: int
    schema_name: str
    relation_name: str
    relation_kind: str
    persistence_code: str
    row_security_enabled: bool
    row_security_forced: bool
    access_method: str
    is_append_optimized: bool
    storage_kind: GreenplumStorageKind
    storage_profile: GreenplumStorageProfile
    has_distribution_policy: bool
    distribution_policy_type: str
    distribution_segment_count: int
    distribution_attribute_numbers: tuple[int, ...]
    reader_has_select: bool
    reader_has_insert: bool
    reader_has_update: bool
    reader_has_delete: bool
    reader_has_truncate: bool
    reader_has_schema_usage: bool


@final
@dataclass(frozen=True, slots=True)
class GreenplumTypeProbe:
    bindings: tuple[PostgresFieldBinding, ...]


@final
@dataclass(frozen=True, slots=True)
class OriginalGreenplumHashCapability:
    schema_name: str
    function_name: str
    function_oid: int
    argument_type_oids: tuple[int, ...]
    result_type_oid: int
    volatility_code: str
    is_strict: bool
    reader_has_execute: bool
    reader_has_schema_usage: bool
    selected_strategy: str
    canonical_sha256_verified: bool


@final
@dataclass(frozen=True, slots=True)
class GreengageHashCapability:
    schema_name: str
    function_name: str
    function_oid: int
    argument_type_oids: tuple[int, ...]
    result_type_oid: int
    volatility_code: str
    is_strict: bool
    reader_has_execute: bool
    reader_has_schema_usage: bool
    selected_strategy: str


@final
@dataclass(frozen=True, slots=True)
class GreenplumDistributedHashRow:
    segment_id: int
    record_id: int
    input_text: str
    digest: bytes


@final
@dataclass(frozen=True, slots=True)
class GreenplumDistributedHashPlan:
    lines: tuple[str, ...]
    scanned_relation: str
    dispatched_primary_count: int
    row_dependent_input_column: str
    execution_locus: str


TOPOLOGY_QUERY = (
    "SELECT content::integer, role::text, preferred_role::text, status::text "
    "FROM pg_catalog.gp_segment_configuration ORDER BY content, role, preferred_role"
)

READER_IDENTITY_QUERY = (
    "SELECT roles.rolname, roles.rolsuper, roles.rolcreaterole, roles.rolcreatedb, "
    "roles.rolcanlogin, "
    "pg_catalog.current_setting('default_transaction_read_only') = 'on', "
    "pg_catalog.current_setting('transaction_read_only') = 'on' "
    "FROM pg_catalog.pg_roles AS roles WHERE roles.rolname = current_user"
)

ORIGINAL_GREENPLUM_RELATION_QUERY = (
    "SELECT relation.oid::bigint, relation.reltype::bigint, namespace.nspname, "
    "relation.relname, relation.relkind::text, relation.relstorage::text, "
    "policy.localoid IS NOT NULL, "
    "pg_catalog.array_to_string(policy.attrnums, ','), "
    "pg_catalog.has_table_privilege(relation.oid, 'SELECT'), "
    "pg_catalog.has_schema_privilege(namespace.oid, 'USAGE'), "
    "append_only.relid IS NOT NULL, append_only.blocksize::integer, "
    "append_only.compresstype::text, append_only.compresslevel::integer, "
    "append_only.checksum, append_only.columnstore, "
    "pg_catalog.has_table_privilege(relation.oid, 'INSERT'), "
    "pg_catalog.has_table_privilege(relation.oid, 'UPDATE'), "
    "pg_catalog.has_table_privilege(relation.oid, 'DELETE'), "
    "pg_catalog.has_table_privilege(relation.oid, 'TRUNCATE') "
    "FROM pg_catalog.pg_class AS relation "
    "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
    "LEFT JOIN pg_catalog.pg_appendonly AS append_only ON append_only.relid = relation.oid "
    "LEFT JOIN pg_catalog.gp_distribution_policy AS policy "
    "ON policy.localoid = relation.oid "
    "WHERE namespace.nspname = %s AND relation.relname = %s"
)

GREENGAGE_RELATION_QUERY = (
    "SELECT relation.oid::bigint, relation.reltype::bigint, namespace.nspname, "
    "relation.relname, relation.relkind::text, relation.relpersistence::text, "
    "relation.relrowsecurity, relation.relforcerowsecurity, access_method.amname, "
    "append_only.relid IS NOT NULL, policy.localoid IS NOT NULL, "
    "policy.policytype::text, policy.numsegments::integer, "
    "pg_catalog.array_to_string(policy.distkey, ','), "
    "pg_catalog.has_table_privilege(relation.oid, 'SELECT'), "
    "pg_catalog.has_schema_privilege(namespace.oid, 'USAGE'), relation.reloptions, "
    "pg_catalog.has_table_privilege(relation.oid, 'INSERT'), "
    "pg_catalog.has_table_privilege(relation.oid, 'UPDATE'), "
    "pg_catalog.has_table_privilege(relation.oid, 'DELETE'), "
    "pg_catalog.has_table_privilege(relation.oid, 'TRUNCATE') "
    "FROM pg_catalog.pg_class AS relation "
    "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
    "LEFT JOIN pg_catalog.pg_am AS access_method ON access_method.oid = relation.relam "
    "LEFT JOIN pg_catalog.pg_appendonly AS append_only ON append_only.relid = relation.oid "
    "LEFT JOIN pg_catalog.gp_distribution_policy AS policy "
    "ON policy.localoid = relation.oid "
    "WHERE namespace.nspname = %s AND relation.relname = %s"
)

ORIGINAL_GREENPLUM_HASH_CAPABILITY_QUERY = (
    "SELECT namespace.nspname, procedure.proname, procedure.oid::bigint, "
    "procedure.proargtypes::text, procedure.prorettype::integer, "
    "procedure.provolatile::text, procedure.proisstrict, "
    "pg_catalog.has_function_privilege(procedure.oid, 'EXECUTE'), "
    "pg_catalog.has_schema_privilege(namespace.oid, 'USAGE') "
    "FROM pg_catalog.pg_proc AS procedure "
    "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace "
    "WHERE namespace.nspname = 'dfe_ext' AND procedure.proname = 'digest' "
    "AND procedure.proargtypes = '17 25'::oidvector"
)

GREENGAGE_HASH_CAPABILITY_QUERY = (
    "SELECT namespace.nspname, procedure.proname, procedure.oid::bigint, "
    "procedure.proargtypes::text, procedure.prorettype::integer, "
    "procedure.provolatile::text, procedure.proisstrict, "
    "pg_catalog.has_function_privilege(procedure.oid, 'EXECUTE'), "
    "pg_catalog.has_schema_privilege(namespace.oid, 'USAGE') "
    "FROM pg_catalog.pg_proc AS procedure "
    "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace "
    "WHERE namespace.nspname = 'pg_catalog' AND procedure.proname = 'sha256' "
    "AND procedure.proargtypes = '17'::oidvector"
)


def greenplum_type_catalog_query(
    relation_oid: int,
    request: GreenplumRelationRequest,
) -> tuple[str, tuple[GreenplumCatalogParameter, ...]]:
    _require_bounded_integer(relation_oid, "Greenplum relation OID", 1, UINT32_MAX)
    requested_rows = ", ".join("(%s::integer, %s::text)" for _ in request.columns)
    statement = (
        f"WITH requested(request_ordinal, column_name) AS (VALUES {requested_rows}) "
        "SELECT requested.request_ordinal, requested.column_name, attribute.attname, "
        "pg_catalog.format_type(attribute.atttypid, attribute.atttypmod), "
        "declared_namespace.nspname, declared_type.typname, declared_type.oid::bigint, "
        "base_namespace.nspname, base_type.typname, base_type.oid::bigint, "
        "declared_type.typtype = 'd', attribute.attndims::integer, "
        "information.numeric_precision, information.numeric_scale, information.column_name "
        "FROM requested "
        "LEFT JOIN pg_catalog.pg_attribute AS attribute "
        "ON attribute.attrelid = %s::oid "
        "AND attribute.attname = requested.column_name "
        "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
        "LEFT JOIN pg_catalog.pg_type AS declared_type "
        "ON declared_type.oid = attribute.atttypid "
        "LEFT JOIN pg_catalog.pg_namespace AS declared_namespace "
        "ON declared_namespace.oid = declared_type.typnamespace "
        "LEFT JOIN pg_catalog.pg_type AS base_type "
        "ON base_type.oid = CASE WHEN declared_type.typtype = 'd' "
        "THEN declared_type.typbasetype ELSE declared_type.oid END "
        "LEFT JOIN pg_catalog.pg_namespace AS base_namespace "
        "ON base_namespace.oid = base_type.typnamespace "
        "LEFT JOIN information_schema.columns AS information "
        "ON information.table_catalog = current_database() "
        "AND information.table_schema = %s "
        "AND information.table_name = %s "
        "AND information.column_name = requested.column_name "
        "ORDER BY requested.request_ordinal"
    )
    parameters: list[GreenplumCatalogParameter] = []
    for index, column in enumerate(request.columns, start=1):
        parameters.extend((index, column.column_name))
    parameters.extend((relation_oid, request.schema_name, request.relation_name))
    return statement, tuple(parameters)


def original_greenplum_distributed_hash_query(
    request: GreenplumRelationProbeRequest,
) -> tuple[str, tuple[GreenplumCatalogParameter, ...]]:
    relation = _qualified_relation(request.schema_name, request.relation_name)
    record_id = _quote_identifier(request.hash_record_id_column)
    hash_input = _quote_identifier(request.hash_input_column)
    statement = (
        f"SELECT gp_segment_id::integer, {record_id}::bigint, {hash_input}::text, "
        f"dfe_ext.digest(pg_catalog.convert_to({hash_input}::text, 'UTF8'), 'sha256'::text) "
        f"FROM {relation} ORDER BY {record_id} LIMIT %s"
    )
    return statement, (request.hash_row_limit,)


def greengage_distributed_hash_query(
    request: GreenplumRelationProbeRequest,
) -> tuple[str, tuple[GreenplumCatalogParameter, ...]]:
    relation = _qualified_relation(request.schema_name, request.relation_name)
    record_id = _quote_identifier(request.hash_record_id_column)
    hash_input = _quote_identifier(request.hash_input_column)
    statement = (
        f"SELECT gp_segment_id::integer, {record_id}::bigint, {hash_input}::text, "
        f"pg_catalog.sha256(pg_catalog.convert_to({hash_input}::text, 'UTF8')) "
        f"FROM {relation} ORDER BY {record_id} LIMIT %s"
    )
    return statement, (request.hash_row_limit,)


def explain_query(statement: str) -> str:
    return f"EXPLAIN VERBOSE {statement}"


def parse_greenplum_topology(rows: tuple[DatabaseRow, ...]) -> GreenplumTopology:
    if not rows:
        raise GreenplumCatalogMetadataError(
            "Greenplum topology catalog returned no segment configuration rows"
        )
    segments: list[GreenplumSegment] = []
    for index, row in enumerate(rows):
        _require_field_count(row, 4, f"Greenplum topology row {index}")
        segments.append(
            GreenplumSegment(
                content_id=_require_bounded_integer(
                    row[0],
                    f"Greenplum topology content at row {index}",
                    -1,
                    INT64_MAX,
                ),
                role=_require_code(row[1], f"Greenplum topology role at row {index}"),
                preferred_role=_require_code(
                    row[2],
                    f"Greenplum topology preferred role at row {index}",
                ),
                status=_require_code(row[3], f"Greenplum topology status at row {index}"),
            )
        )
    segment_tuple = tuple(segments)
    if len(set(segment_tuple)) != len(segment_tuple):
        raise GreenplumCatalogDataError(
            "Greenplum topology catalog returned duplicate segment configuration rows"
        )
    active_primaries = tuple(
        segment for segment in segment_tuple if segment.role == "p" and segment.status == "u"
    )
    coordinator_rows = tuple(segment for segment in active_primaries if segment.content_id == -1)
    primary_content_ids = tuple(
        sorted(segment.content_id for segment in active_primaries if segment.content_id >= 0)
    )
    if len(coordinator_rows) != 1:
        raise GreenplumCatalogMetadataError(
            "Greenplum topology requires exactly one active coordinator: "
            f"actual={len(coordinator_rows)}"
        )
    if not primary_content_ids or len(set(primary_content_ids)) != len(primary_content_ids):
        raise GreenplumCatalogMetadataError(
            "Greenplum topology requires distinct active primary contents"
        )
    return GreenplumTopology(
        segments=segment_tuple,
        primary_content_ids=primary_content_ids,
    )


def parse_greenplum_reader_identity(row: DatabaseRow) -> GreenplumReaderIdentity:
    _require_field_count(row, 7, "Greenplum reader identity row")
    identity = GreenplumReaderIdentity(
        user_name=_require_text(row[0], "Greenplum reader role name"),
        is_superuser=_require_boolean(row[1], "Greenplum reader superuser flag"),
        can_create_role=_require_boolean(row[2], "Greenplum reader create-role flag"),
        can_create_database=_require_boolean(row[3], "Greenplum reader create-database flag"),
        can_login=_require_boolean(row[4], "Greenplum reader login flag"),
        default_transaction_read_only=_require_boolean(
            row[5],
            "Greenplum reader default read-only flag",
        ),
        transaction_read_only=_require_boolean(
            row[6],
            "Greenplum reader transaction read-only flag",
        ),
    )
    if identity.is_superuser or identity.can_create_role or identity.can_create_database:
        raise GreenplumCatalogMetadataError(
            "Greenplum reader role has prohibited administrative privileges: "
            f"user={identity.user_name!r}, superuser={identity.is_superuser}, "
            f"create_role={identity.can_create_role}, "
            f"create_database={identity.can_create_database}"
        )
    if not identity.can_login:
        raise GreenplumCatalogMetadataError(
            f"Greenplum reader role cannot log in: user={identity.user_name!r}"
        )
    if not identity.transaction_read_only:
        raise GreenplumCatalogMetadataError(
            "Greenplum reader must currently use a read-only transaction: "
            f"user={identity.user_name!r}, "
            f"default_transaction_read_only={identity.default_transaction_read_only}"
        )
    return identity


def parse_original_greenplum_relation_catalog(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumRelationRequest,
) -> OriginalGreenplumRelationCatalog:
    row = _require_single_row(rows, "original Greenplum relation catalog")
    _require_field_count(row, 20, "original Greenplum relation catalog row")
    schema_name = _require_text(row[2], "original Greenplum relation schema")
    relation_name = _require_text(row[3], "original Greenplum relation name")
    _require_requested_relation(schema_name, relation_name, request)
    has_distribution_policy = _require_boolean(
        row[6],
        "original Greenplum distribution-policy presence",
    )
    if not has_distribution_policy:
        raise GreenplumCatalogMetadataError(
            "original Greenplum relation has no distribution policy: "
            f"relation={request.schema_name!r}.{request.relation_name!r}"
        )
    storage_code = _require_code(row[5], "original Greenplum storage code")
    storage_profile = _parse_original_greenplum_storage_profile(
        storage_code,
        row[10],
        row[11],
        row[12],
        row[13],
        row[14],
        row[15],
        request,
    )
    reader_has_select = _require_boolean(
        row[8],
        "original Greenplum reader SELECT privilege",
    )
    reader_has_schema_usage = _require_boolean(
        row[9],
        "original Greenplum reader schema USAGE privilege",
    )
    reader_has_insert = _require_boolean(
        row[16],
        "original Greenplum reader INSERT privilege",
    )
    reader_has_update = _require_boolean(
        row[17],
        "original Greenplum reader UPDATE privilege",
    )
    reader_has_delete = _require_boolean(
        row[18],
        "original Greenplum reader DELETE privilege",
    )
    reader_has_truncate = _require_boolean(
        row[19],
        "original Greenplum reader TRUNCATE privilege",
    )
    catalog = OriginalGreenplumRelationCatalog(
        relation_oid=_require_bounded_integer(
            row[0],
            "original Greenplum relation OID",
            1,
            UINT32_MAX,
        ),
        relation_row_type_oid=_require_bounded_integer(
            row[1],
            "original Greenplum relation row type OID",
            1,
            UINT32_MAX,
        ),
        schema_name=schema_name,
        relation_name=relation_name,
        relation_kind=_require_code(row[4], "original Greenplum relation kind"),
        storage_code=storage_code,
        storage_kind=storage_profile.kind,
        storage_profile=storage_profile,
        has_distribution_policy=has_distribution_policy,
        distribution_attribute_numbers=_parse_original_greenplum_attribute_numbers(
            row[7],
            "original Greenplum distribution attributes",
        ),
        reader_has_select=reader_has_select,
        reader_has_insert=reader_has_insert,
        reader_has_update=reader_has_update,
        reader_has_delete=reader_has_delete,
        reader_has_truncate=reader_has_truncate,
        reader_has_schema_usage=reader_has_schema_usage,
    )
    _require_relation_privileges(
        catalog.reader_has_select,
        catalog.reader_has_insert,
        catalog.reader_has_update,
        catalog.reader_has_delete,
        catalog.reader_has_truncate,
        catalog.reader_has_schema_usage,
        request,
    )
    return catalog


def parse_greengage_relation_catalog(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumRelationRequest,
) -> GreengageRelationCatalog:
    row = _require_single_row(rows, "Greengage relation catalog")
    _require_field_count(row, 21, "Greengage relation catalog row")
    schema_name = _require_text(row[2], "Greengage relation schema")
    relation_name = _require_text(row[3], "Greengage relation name")
    _require_requested_relation(schema_name, relation_name, request)
    has_distribution_policy = _require_boolean(
        row[10],
        "Greengage distribution-policy presence",
    )
    if not has_distribution_policy:
        raise GreenplumCatalogMetadataError(
            "Greengage relation has no distribution policy: "
            f"relation={request.schema_name!r}.{request.relation_name!r}"
        )
    access_method = _require_text(row[8], "Greengage relation access method")
    is_append_optimized = _require_boolean(row[9], "Greengage append-only flag")
    storage_profile = _parse_greengage_storage_profile(
        access_method,
        is_append_optimized,
        row[16],
        request,
    )
    reader_has_select = _require_boolean(row[14], "Greengage reader SELECT privilege")
    reader_has_schema_usage = _require_boolean(
        row[15],
        "Greengage reader schema USAGE privilege",
    )
    reader_has_insert = _require_boolean(row[17], "Greengage reader INSERT privilege")
    reader_has_update = _require_boolean(row[18], "Greengage reader UPDATE privilege")
    reader_has_delete = _require_boolean(row[19], "Greengage reader DELETE privilege")
    reader_has_truncate = _require_boolean(row[20], "Greengage reader TRUNCATE privilege")
    catalog = GreengageRelationCatalog(
        relation_oid=_require_bounded_integer(
            row[0],
            "Greengage relation OID",
            1,
            UINT32_MAX,
        ),
        relation_row_type_oid=_require_bounded_integer(
            row[1],
            "Greengage relation row type OID",
            1,
            UINT32_MAX,
        ),
        schema_name=schema_name,
        relation_name=relation_name,
        relation_kind=_require_code(row[4], "Greengage relation kind"),
        persistence_code=_require_code(row[5], "Greengage relation persistence"),
        row_security_enabled=_require_boolean(row[6], "Greengage row-security flag"),
        row_security_forced=_require_boolean(row[7], "Greengage forced row-security flag"),
        access_method=access_method,
        is_append_optimized=is_append_optimized,
        storage_kind=storage_profile.kind,
        storage_profile=storage_profile,
        has_distribution_policy=has_distribution_policy,
        distribution_policy_type=_require_code(
            row[11],
            "Greengage distribution policy type",
        ),
        distribution_segment_count=_require_bounded_integer(
            row[12],
            "Greengage distribution segment count",
            1,
            INT64_MAX,
        ),
        distribution_attribute_numbers=_parse_greengage_attribute_numbers(
            row[13],
            "Greengage distribution attributes",
        ),
        reader_has_select=reader_has_select,
        reader_has_insert=reader_has_insert,
        reader_has_update=reader_has_update,
        reader_has_delete=reader_has_delete,
        reader_has_truncate=reader_has_truncate,
        reader_has_schema_usage=reader_has_schema_usage,
    )
    _require_relation_privileges(
        catalog.reader_has_select,
        catalog.reader_has_insert,
        catalog.reader_has_update,
        catalog.reader_has_delete,
        catalog.reader_has_truncate,
        catalog.reader_has_schema_usage,
        request,
    )
    return catalog


def _original_greenplum_storage_kind(
    storage_code: str,
    request: GreenplumRelationRequest,
) -> GreenplumStorageKind:
    kinds = {
        "h": GreenplumStorageKind.HEAP,
        "a": GreenplumStorageKind.APPEND_OPTIMIZED_ROW,
        "c": GreenplumStorageKind.APPEND_OPTIMIZED_COLUMN,
    }
    kind = kinds.get(storage_code)
    if kind is None:
        raise GreenplumCatalogMetadataError(
            "original Greenplum relation uses an unsupported physical storage code: "
            f"relation={request.schema_name!r}.{request.relation_name!r}, "
            f"storage_code={storage_code!r}"
        )
    return kind


def _parse_original_greenplum_storage_profile(
    storage_code: str,
    append_only_catalog_value: object,
    block_size_value: object,
    compression_type_value: object,
    compression_level_value: object,
    checksum_value: object,
    column_store_value: object,
    request: GreenplumRelationRequest,
) -> GreenplumStorageProfile:
    kind = _original_greenplum_storage_kind(storage_code, request)
    append_only_catalog_present = _require_boolean(
        append_only_catalog_value,
        "original Greenplum append-only catalog presence",
    )
    if kind is GreenplumStorageKind.HEAP:
        option_values = (
            block_size_value,
            compression_type_value,
            compression_level_value,
            checksum_value,
            column_store_value,
        )
        if append_only_catalog_present or any(value is not None for value in option_values):
            raise GreenplumCatalogMetadataError(
                "original Greenplum heap relation exposes append-only storage metadata: "
                f"relation={request.schema_name!r}.{request.relation_name!r}, "
                f"append_only_catalog_present={append_only_catalog_present}, "
                f"option_presence={tuple(value is not None for value in option_values)!r}"
            )
        return GreenplumStorageProfile(
            kind=kind,
            append_only_catalog_present=False,
            relation_options=(),
            block_size_bytes=None,
            compression_type=None,
            compression_level=None,
            checksum=None,
            column_store=None,
        )
    if not append_only_catalog_present:
        raise GreenplumCatalogMetadataError(
            "original Greenplum append-optimized relation is absent from pg_appendonly: "
            f"relation={request.schema_name!r}.{request.relation_name!r}, "
            f"storage_kind={kind.value!r}"
        )
    block_size_bytes = _require_integer(
        block_size_value,
        "original Greenplum append-only block size",
    )
    compression_type = _require_text_allow_empty(
        compression_type_value,
        "original Greenplum append-only compression type",
    )
    compression_level = _require_integer(
        compression_level_value,
        "original Greenplum append-only compression level",
    )
    checksum = _require_boolean(
        checksum_value,
        "original Greenplum append-only checksum flag",
    )
    column_store = _require_boolean(
        column_store_value,
        "original Greenplum append-only column-store flag",
    )
    expected_column_store = kind is GreenplumStorageKind.APPEND_OPTIMIZED_COLUMN
    if column_store is not expected_column_store:
        raise GreenplumCatalogMetadataError(
            "original Greenplum append-optimized storage orientation contradicts relstorage: "
            f"relation={request.schema_name!r}.{request.relation_name!r}, "
            f"storage_kind={kind.value!r}, column_store={column_store}, "
            f"required_column_store={expected_column_store}"
        )
    return GreenplumStorageProfile(
        kind=kind,
        append_only_catalog_present=True,
        relation_options=(),
        block_size_bytes=block_size_bytes,
        compression_type=compression_type,
        compression_level=compression_level,
        checksum=checksum,
        column_store=column_store,
    )


def _greengage_storage_kind(
    access_method: str,
    is_append_optimized: bool,
    request: GreenplumRelationRequest,
) -> GreenplumStorageKind:
    kinds = {
        ("heap", False): GreenplumStorageKind.HEAP,
        ("ao_row", True): GreenplumStorageKind.APPEND_OPTIMIZED_ROW,
        ("ao_column", True): GreenplumStorageKind.APPEND_OPTIMIZED_COLUMN,
    }
    kind = kinds.get((access_method, is_append_optimized))
    if kind is None:
        raise GreenplumCatalogMetadataError(
            "Greengage relation uses an unsupported physical storage profile: "
            f"relation={request.schema_name!r}.{request.relation_name!r}, "
            f"access_method={access_method!r}, "
            f"is_append_optimized={is_append_optimized}"
        )
    return kind


def _parse_greengage_storage_profile(
    access_method: str,
    append_only_catalog_present: bool,
    reloptions_value: object,
    request: GreenplumRelationRequest,
) -> GreenplumStorageProfile:
    kind = _greengage_storage_kind(
        access_method,
        append_only_catalog_present,
        request,
    )
    relation_options = _parse_greengage_reloptions(reloptions_value)
    if kind is GreenplumStorageKind.HEAP:
        return GreenplumStorageProfile(
            kind=kind,
            append_only_catalog_present=False,
            relation_options=relation_options,
            block_size_bytes=None,
            compression_type=None,
            compression_level=None,
            checksum=None,
            column_store=None,
        )
    option_values = dict(relation_options)
    return GreenplumStorageProfile(
        kind=kind,
        append_only_catalog_present=True,
        relation_options=relation_options,
        block_size_bytes=_parse_optional_greengage_integer_option(
            option_values,
            "blocksize",
        ),
        compression_type=option_values.get("compresstype"),
        compression_level=_parse_optional_greengage_integer_option(
            option_values,
            "compresslevel",
        ),
        checksum=_parse_optional_greengage_boolean_option(
            option_values,
            "checksum",
        ),
        column_store=kind is GreenplumStorageKind.APPEND_OPTIMIZED_COLUMN,
    )


def _parse_greengage_reloptions(value: object) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if type(value) is not list:
        raise GreenplumCatalogDataError(
            "Greengage relation reloptions must be a text array or NULL"
        )
    raw_options = cast(list[object], value)
    options: dict[str, str] = {}
    for index, item in enumerate(raw_options):
        text = _require_text(item, f"Greengage reloption at index {index}")
        name, separator, option_value = text.partition("=")
        if separator != "=" or not name:
            raise GreenplumCatalogDataError(
                "Greengage reloption must contain a non-empty name and an equals sign: "
                f"index={index}, value={text!r}"
            )
        if name in options:
            raise GreenplumCatalogDataError(
                f"Greengage relation reloptions contain a duplicate option: name={name!r}"
            )
        options[name] = option_value
    return tuple(sorted(options.items()))


def _parse_optional_greengage_integer_option(
    options: dict[str, str],
    option_name: str,
) -> int | None:
    value = options.get(option_name)
    if value is None:
        return None
    try:
        return int(value, 10)
    except ValueError as error:
        raise GreenplumCatalogDataError(
            "Greengage integer relation option has a non-integer value: "
            f"option_name={option_name!r}, value={value!r}"
        ) from error


def _parse_optional_greengage_boolean_option(
    options: dict[str, str],
    option_name: str,
) -> bool | None:
    value = options.get(option_name)
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in ("true", "yes", "on", "1"):
        return True
    if normalized in ("false", "no", "off", "0"):
        return False
    raise GreenplumCatalogDataError(
        "Greengage boolean relation option has a non-boolean value: "
        f"option_name={option_name!r}, value={value!r}"
    )


def parse_greenplum_type_probe(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumRelationRequest,
) -> GreenplumTypeProbe:
    if len(rows) != len(request.columns):
        raise GreenplumCatalogMetadataError(
            "Greenplum type catalog did not return one row per requested column: "
            f"expected={len(request.columns)}, actual={len(rows)}"
        )
    bindings: list[PostgresFieldBinding] = []
    for index, (column, row) in enumerate(zip(request.columns, rows, strict=True)):
        try:
            binding = postgres_field_binding_from_catalog_row(
                column.field_name,
                column.column_name,
                index,
                row,
            )
        except PostgresMetadataError as error:
            raise GreenplumCatalogMetadataError(
                "Greenplum requested column metadata is unavailable: "
                f"column_index={index}, column_name={column.column_name!r}, reason={error}"
            ) from None
        except PostgresDataValidationError as error:
            raise GreenplumCatalogDataError(
                "Greenplum requested column metadata is malformed: "
                f"column_index={index}, column_name={column.column_name!r}, reason={error}"
            ) from None
        bindings.append(binding)
    return GreenplumTypeProbe(bindings=tuple(bindings))


def require_hash_record_id_integer_type(
    probe: GreenplumTypeProbe,
    request: GreenplumRelationProbeRequest,
) -> None:
    matching_bindings = tuple(
        binding
        for binding in probe.bindings
        if binding.column_name == request.hash_record_id_column
    )
    if len(matching_bindings) != 1:
        raise GreenplumCatalogMetadataError(
            "Greenplum distributed hash record ID metadata must resolve exactly once: "
            f"column_name={request.hash_record_id_column!r}, "
            f"actual={len(matching_bindings)}"
        )
    binding = matching_bindings[0]
    if binding.physical.base_type.oid not in _INTEGER_TYPE_OIDS:
        raise GreenplumCatalogMetadataError(
            "Greenplum distributed hash record ID column must use an integer base type: "
            f"column_name={request.hash_record_id_column!r}, "
            "base_type_identity=("
            f"{binding.physical.base_type.schema_name!r}, "
            f"{binding.physical.base_type.type_name!r}, "
            f"{binding.physical.base_type.oid})"
        )


def parse_original_greenplum_hash_capability(
    rows: tuple[DatabaseRow, ...],
) -> OriginalGreenplumHashCapability:
    row = _require_hash_capability_row(rows, "original Greenplum pgcrypto")
    capability = OriginalGreenplumHashCapability(
        schema_name=_require_text(row[0], "original Greenplum hash schema"),
        function_name=_require_text(row[1], "original Greenplum hash function"),
        function_oid=_require_bounded_integer(
            row[2],
            "original Greenplum hash function OID",
            1,
            UINT32_MAX,
        ),
        argument_type_oids=_parse_oid_vector(
            row[3],
            "original Greenplum hash argument OIDs",
        ),
        result_type_oid=_require_bounded_integer(
            row[4],
            "original Greenplum hash result OID",
            1,
            UINT32_MAX,
        ),
        volatility_code=_require_code(row[5], "original Greenplum hash volatility"),
        is_strict=_require_boolean(row[6], "original Greenplum hash strictness"),
        reader_has_execute=_require_boolean(
            row[7],
            "original Greenplum hash EXECUTE privilege",
        ),
        reader_has_schema_usage=_require_boolean(
            row[8],
            "original Greenplum hash schema USAGE privilege",
        ),
        selected_strategy="unpackaged_contrib_sql",
        canonical_sha256_verified=False,
    )
    _validate_hash_capability(
        capability.schema_name,
        capability.function_name,
        capability.argument_type_oids,
        capability.result_type_oid,
        capability.volatility_code,
        capability.is_strict,
        capability.reader_has_execute,
        capability.reader_has_schema_usage,
        "dfe_ext",
        "digest",
        (_BYTEA_OID, _TEXT_OID),
        "original Greenplum pgcrypto",
    )
    return capability


def parse_greengage_hash_capability(
    rows: tuple[DatabaseRow, ...],
) -> GreengageHashCapability:
    row = _require_hash_capability_row(rows, "Greengage native SHA-256")
    capability = GreengageHashCapability(
        schema_name=_require_text(row[0], "Greengage hash schema"),
        function_name=_require_text(row[1], "Greengage hash function"),
        function_oid=_require_bounded_integer(
            row[2],
            "Greengage hash function OID",
            1,
            UINT32_MAX,
        ),
        argument_type_oids=_parse_oid_vector(row[3], "Greengage hash argument OIDs"),
        result_type_oid=_require_bounded_integer(
            row[4],
            "Greengage hash result OID",
            1,
            UINT32_MAX,
        ),
        volatility_code=_require_code(row[5], "Greengage hash volatility"),
        is_strict=_require_boolean(row[6], "Greengage hash strictness"),
        reader_has_execute=_require_boolean(row[7], "Greengage hash EXECUTE privilege"),
        reader_has_schema_usage=_require_boolean(
            row[8],
            "Greengage hash schema USAGE privilege",
        ),
        selected_strategy="pg_catalog_builtin",
    )
    _validate_hash_capability(
        capability.schema_name,
        capability.function_name,
        capability.argument_type_oids,
        capability.result_type_oid,
        capability.volatility_code,
        capability.is_strict,
        capability.reader_has_execute,
        capability.reader_has_schema_usage,
        "pg_catalog",
        "sha256",
        (_BYTEA_OID,),
        "Greengage native SHA-256",
    )
    return capability


def parse_greenplum_distributed_hash_rows(
    rows: tuple[DatabaseRow, ...],
) -> tuple[GreenplumDistributedHashRow, ...]:
    if not rows:
        raise GreenplumCatalogMetadataError(
            "Greenplum distributed hash probe returned no fixture rows"
        )
    parsed: list[GreenplumDistributedHashRow] = []
    for index, row in enumerate(rows):
        _require_field_count(row, 4, f"Greenplum distributed hash row {index}")
        input_text = _require_text(row[2], f"Greenplum hash input at row {index}")
        digest = _require_bytes(row[3], f"Greenplum SHA-256 digest at row {index}")
        expected_digest = sha256(input_text.encode("utf-8")).digest()
        if len(digest) != _SHA256_BYTES or digest != expected_digest:
            raise GreenplumCatalogDataError(
                "Greenplum distributed SHA-256 result does not match its row-dependent input: "
                f"row_index={index}"
            )
        parsed.append(
            GreenplumDistributedHashRow(
                segment_id=_require_private_bounded_integer(
                    row[0],
                    f"Greenplum segment ID at hash row {index}",
                    0,
                    INT64_MAX,
                ),
                record_id=_require_private_bounded_integer(
                    row[1],
                    f"Greenplum record ID at hash row {index}",
                    -(1 << 63),
                    INT64_MAX,
                ),
                input_text=input_text,
                digest=digest,
            )
        )
    if len({row.record_id for row in parsed}) != len(parsed):
        raise GreenplumCatalogDataError(
            "Greenplum distributed hash probe returned duplicate record IDs"
        )
    return tuple(parsed)


def parse_original_greenplum_distributed_hash_plan(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumRelationProbeRequest,
    primary_count: int,
) -> GreenplumDistributedHashPlan:
    lines = _greenplum_hash_plan_lines(rows)
    _require_distributed_relation_scan(lines, request, primary_count)
    motion_index = _find_stripped_plan_line(lines, "{MOTION", 0)
    seqscan_index = _find_stripped_plan_line(lines, "{SEQSCAN", motion_index + 1)
    rtable_index = _find_stripped_plan_line(lines, ":rtable (", seqscan_index + 1)
    digest_index = _find_stripped_plan_line(lines, ":resname digest", seqscan_index + 1)
    if digest_index >= rtable_index:
        raise GreenplumCatalogMetadataError(
            "Original Greenplum verbose plan does not place the digest target below Motion"
        )
    target_entry_indexes = tuple(
        index
        for index in range(seqscan_index + 1, digest_index)
        if lines[index].strip() == "{TARGETENTRY"
    )
    if not target_entry_indexes:
        raise GreenplumCatalogMetadataError(
            "Original Greenplum verbose plan omits the digest target entry below Motion"
        )
    target_entry_index = target_entry_indexes[-1]
    function_expression = any(
        line.strip() == "{FUNCEXPR" for line in lines[target_entry_index:digest_index]
    )
    if not function_expression:
        raise GreenplumCatalogMetadataError(
            "Original Greenplum verbose plan does not compute digest in the scan targetlist"
        )
    return GreenplumDistributedHashPlan(
        lines=lines,
        scanned_relation=f"{request.schema_name}.{request.relation_name}",
        dispatched_primary_count=primary_count,
        row_dependent_input_column=request.hash_input_column,
        execution_locus="seqscan_targetlist_below_motion",
    )


def parse_greengage_distributed_hash_plan(
    rows: tuple[DatabaseRow, ...],
    request: GreenplumRelationProbeRequest,
    primary_count: int,
) -> GreenplumDistributedHashPlan:
    lines = _greenplum_hash_plan_lines(rows)
    _require_distributed_relation_scan(lines, request, primary_count)
    dispatch_marker = f"segments: {primary_count}"
    motion_index = _find_matching_plan_line(
        lines,
        lambda line: "motion" in line.lower() and dispatch_marker in line.lower(),
        0,
        "Greengage distributed Motion",
    )
    scan_index = _find_matching_plan_line(
        lines,
        lambda line: "seq scan" in line.lower() and request.relation_name.lower() in line.lower(),
        motion_index + 1,
        "Greengage relation scan",
    )
    output_index = _find_matching_plan_line(
        lines,
        lambda line: (
            "output:" in line.lower()
            and "sha256(" in line.lower()
            and request.hash_input_column.lower() in line.lower()
        ),
        scan_index + 1,
        "Greengage SHA-256 scan output",
    )
    motion_indent = len(lines[motion_index]) - len(lines[motion_index].lstrip())
    scan_indent = len(lines[scan_index]) - len(lines[scan_index].lstrip())
    output_indent = len(lines[output_index]) - len(lines[output_index].lstrip())
    if scan_indent <= motion_indent or output_indent <= scan_indent:
        raise GreenplumCatalogMetadataError(
            "Greengage verbose plan does not place the SHA-256 scan output below Motion"
        )
    return GreenplumDistributedHashPlan(
        lines=lines,
        scanned_relation=f"{request.schema_name}.{request.relation_name}",
        dispatched_primary_count=primary_count,
        row_dependent_input_column=request.hash_input_column,
        execution_locus="seqscan_output_below_motion",
    )


def _greenplum_hash_plan_lines(rows: tuple[DatabaseRow, ...]) -> tuple[str, ...]:
    if not rows:
        raise GreenplumCatalogMetadataError(
            "Greenplum distributed hash EXPLAIN VERBOSE returned no plan lines"
        )
    lines: list[str] = []
    for index, row in enumerate(rows):
        _require_field_count(row, 1, f"Greenplum distributed hash plan row {index}")
        value = row[0]
        if type(value) is not str:
            raise GreenplumCatalogDataError(f"Greenplum hash plan line {index} must be text")
        if "\x00" in value:
            raise GreenplumCatalogDataError(
                f"Greenplum hash plan line {index} must not contain U+0000"
            )
        if value:
            lines.append(value)
    if not lines:
        raise GreenplumCatalogMetadataError(
            "Greenplum distributed hash EXPLAIN VERBOSE returned only empty plan lines"
        )
    return tuple(lines)


def _require_distributed_relation_scan(
    lines: tuple[str, ...],
    request: GreenplumRelationProbeRequest,
    primary_count: int,
) -> None:
    _require_bounded_integer(primary_count, "Greenplum primary segment count", 1, INT64_MAX)
    relation_scan = any(
        "scan" in line.lower() and request.relation_name.lower() in line.lower() for line in lines
    )
    dispatch_marker = f"segments: {primary_count}"
    distributed_motion = any(
        "motion" in line.lower() and dispatch_marker in line.lower() for line in lines
    )
    if not relation_scan or not distributed_motion:
        raise GreenplumCatalogMetadataError(
            "Greenplum SHA-256 plan is not a distributed relation scan: "
            f"primary_count={primary_count}, relation_scan={relation_scan}, "
            f"distributed_motion={distributed_motion}"
        )


def _find_stripped_plan_line(
    lines: tuple[str, ...],
    expected: str,
    start: int,
) -> int:
    return _find_matching_plan_line(
        lines,
        lambda line: line.strip() == expected,
        start,
        expected,
    )


def _find_matching_plan_line(
    lines: tuple[str, ...],
    predicate: Callable[[str], bool],
    start: int,
    label: str,
) -> int:
    for index in range(start, len(lines)):
        if predicate(lines[index]):
            return index
    raise GreenplumCatalogMetadataError(
        f"Greenplum verbose plan is missing required evidence: evidence={label!r}"
    )


def require_hash_rows_cover_topology(
    rows: tuple[GreenplumDistributedHashRow, ...],
    topology: GreenplumTopology,
) -> None:
    observed_content_ids = tuple(sorted({row.segment_id for row in rows}))
    if observed_content_ids != topology.primary_content_ids:
        raise GreenplumCatalogMetadataError(
            "Greenplum distributed hash rows do not cover every active primary content: "
            f"expected={topology.primary_content_ids!r}, actual={observed_content_ids!r}"
        )


def _require_hash_capability_row(
    rows: tuple[DatabaseRow, ...],
    label: str,
) -> DatabaseRow:
    row = _require_single_row(rows, f"{label} function catalog")
    _require_field_count(row, 9, f"{label} function catalog row")
    return row


def _validate_hash_capability(
    schema_name: str,
    function_name: str,
    argument_type_oids: tuple[int, ...],
    result_type_oid: int,
    volatility_code: str,
    is_strict: bool,
    reader_has_execute: bool,
    reader_has_schema_usage: bool,
    required_schema_name: str,
    required_function_name: str,
    required_argument_type_oids: tuple[int, ...],
    label: str,
) -> None:
    failures: list[str] = []
    if schema_name != required_schema_name:
        failures.append(f"schema={schema_name!r}, required={required_schema_name!r}")
    if function_name != required_function_name:
        failures.append(f"function={function_name!r}, required={required_function_name!r}")
    if argument_type_oids != required_argument_type_oids:
        failures.append(
            f"argument_type_oids={argument_type_oids!r}, required={required_argument_type_oids!r}"
        )
    if result_type_oid != _BYTEA_OID:
        failures.append(f"result_type_oid={result_type_oid}, required={_BYTEA_OID}")
    if volatility_code != "i":
        failures.append(f"volatility={volatility_code!r}, required='i'")
    if not is_strict:
        failures.append("strict=false, required=true")
    if not reader_has_execute:
        failures.append("reader_execute=false, required=true")
    if not reader_has_schema_usage:
        failures.append("reader_schema_usage=false, required=true")
    if failures:
        raise GreenplumCatalogMetadataError(
            f"{label} capability is unavailable or unsafe: " + "; ".join(failures)
        )


def _require_relation_privileges(
    reader_has_select: bool,
    reader_has_insert: bool,
    reader_has_update: bool,
    reader_has_delete: bool,
    reader_has_truncate: bool,
    reader_has_schema_usage: bool,
    request: GreenplumRelationRequest,
) -> None:
    if not reader_has_select or not reader_has_schema_usage:
        raise GreenplumCatalogMetadataError(
            "Greenplum reader lacks required relation privileges: "
            f"relation={request.schema_name!r}.{request.relation_name!r}, "
            f"select={reader_has_select}, schema_usage={reader_has_schema_usage}"
        )
    if reader_has_insert or reader_has_update or reader_has_delete or reader_has_truncate:
        raise GreenplumCatalogMetadataError(
            "Greenplum reader has prohibited relation write privileges: "
            f"relation={request.schema_name!r}.{request.relation_name!r}, "
            f"insert={reader_has_insert}, update={reader_has_update}, "
            f"delete={reader_has_delete}, truncate={reader_has_truncate}"
        )


def _require_requested_relation(
    schema_name: str,
    relation_name: str,
    request: GreenplumRelationRequest,
) -> None:
    if schema_name != request.schema_name or relation_name != request.relation_name:
        raise GreenplumCatalogDataError(
            "Greenplum relation catalog returned a different relation identity: "
            f"requested={request.schema_name!r}.{request.relation_name!r}, "
            f"actual={schema_name!r}.{relation_name!r}"
        )


def _parse_original_greenplum_attribute_numbers(
    value: object,
    label: str,
) -> tuple[int, ...]:
    if value is None:
        return ()
    return _parse_text_attribute_numbers(value, label)


def _parse_greengage_attribute_numbers(
    value: object,
    label: str,
) -> tuple[int, ...]:
    return _parse_text_attribute_numbers(value, label)


def _parse_text_attribute_numbers(value: object, label: str) -> tuple[int, ...]:
    if type(value) is str and value == "":
        return ()
    text = _require_text(value, label)
    values: list[int] = []
    for item in text.split(","):
        try:
            number = int(item)
        except ValueError:
            raise GreenplumCatalogDataError(
                f"{label} contains a non-integer attribute number: value={text!r}"
            ) from None
        values.append(_require_bounded_integer(number, label, 1, INT64_MAX))
    result = tuple(values)
    if len(set(result)) != len(result):
        raise GreenplumCatalogDataError(
            f"{label} contains duplicate attribute numbers: value={text!r}"
        )
    return result


def _parse_oid_vector(value: object, label: str) -> tuple[int, ...]:
    text = _require_text(value, label)
    if text == "":
        return ()
    return tuple(
        _require_bounded_integer(_parse_decimal_integer(item, label), label, 1, UINT32_MAX)
        for item in text.split()
    )


def _parse_decimal_integer(value: str, label: str) -> int:
    try:
        return int(value)
    except ValueError:
        raise GreenplumCatalogDataError(
            f"{label} contains a non-integer OID: value={value!r}"
        ) from None


def _qualified_relation(schema_name: str, relation_name: str) -> str:
    return f"{_quote_identifier(schema_name)}.{_quote_identifier(relation_name)}"


def _quote_identifier(value: str) -> str:
    _validate_identifier(value, "Greenplum SQL identifier")
    return '"' + value.replace('"', '""') + '"'


def _validate_identifier(value: str, label: str) -> None:
    _validate_text(value, label)
    if "." in value:
        raise ValueError(f"{label} must be one identifier component")


def _validate_text(value: str, label: str) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be non-empty text")
    if "\x00" in value:
        raise ValueError(f"{label} must not contain U+0000")


def _require_single_row(rows: tuple[DatabaseRow, ...], label: str) -> DatabaseRow:
    if len(rows) != 1:
        raise GreenplumCatalogMetadataError(
            f"{label} must return exactly one row: actual={len(rows)}"
        )
    return rows[0]


def _require_field_count(row: DatabaseRow, expected: int, label: str) -> None:
    if len(row) != expected:
        raise GreenplumCatalogDataError(
            f"{label} returned an unexpected field count: expected={expected}, actual={len(row)}"
        )


def _require_text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise GreenplumCatalogDataError(f"{label} must be non-empty text")
    if "\x00" in value:
        raise GreenplumCatalogDataError(f"{label} must not contain U+0000")
    return value


def _require_text_allow_empty(value: object, label: str) -> str:
    if type(value) is not str:
        raise GreenplumCatalogDataError(f"{label} must be text")
    if "\x00" in value:
        raise GreenplumCatalogDataError(f"{label} must not contain U+0000")
    return value


def _require_code(value: object, label: str) -> str:
    code = _require_text(value, label)
    if len(code) != 1:
        raise GreenplumCatalogDataError(f"{label} must be a one-character catalog code")
    return code


def _require_boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise GreenplumCatalogDataError(f"{label} must be boolean")
    return value


def _require_integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise GreenplumCatalogDataError(f"{label} must be an integer")
    return value


def _require_bounded_integer(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise GreenplumCatalogDataError(
            f"{label} must be an integer in [{minimum}, {maximum}]: value={value!r}"
        )
    return value


def _require_private_bounded_integer(
    value: object,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise GreenplumCatalogDataError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _require_bytes(value: object, label: str) -> bytes:
    if type(value) is bytes:
        return value
    if type(value) is memoryview:
        return value.tobytes()
    raise GreenplumCatalogDataError(f"{label} must be a byte string")
