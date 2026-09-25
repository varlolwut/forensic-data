from pathlib import Path

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    DecimalParameters,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
    SchemaValidationError,
    TimestampParameters,
    schema_digest_hex,
)
from forensic_data.contracts.errors import (
    ContractReferenceError,
    ContractValidationError,
    UnsupportedContractError,
)
from forensic_data.contracts.model import (
    Adapter,
    AssurancePolicy,
    CapturePolicy,
    ConnectionDefinition,
    ConnectionRole,
    ConsistencyDatasetDefinition,
    ConsistencyDefinition,
    DatasetDefinition,
    EvidenceAction,
    EvidenceDefinition,
    EvidenceFieldPolicy,
    ExecutionBudgets,
    FieldEquality,
    LateArrivalPolicy,
    LoadedContractConfig,
    LogicalSchemaDefinition,
    MetadataDefinition,
    MinimumEvidence,
    NullPartitionPolicy,
    ProjectedField,
    ReadinessManifestColumns,
    RelationLocator,
    RelationManifestReadiness,
    RelationScope,
    RowCheckDefinition,
    ScopeBinding,
    ScopeDefinition,
    ScopeOperator,
    ScopeParameterDefinition,
    SqlArtifactDefinition,
    SqlDialect,
    SqlParameterDefinition,
    StableReadKind,
)
from forensic_data.contracts.source import (
    CheckSource,
    ConnectionSource,
    ConsistencySource,
    DatasetLocatorSource,
    DatasetSource,
    EvidenceSource,
    LoadedContractSource,
    LogicalTypeSource,
    RelationManifestReadinessSource,
    RelationSource,
    SchemaSource,
    ScopeSource,
    SqlArtifactSource,
    load_contract_source,
)
from forensic_data.greenplum_profile import (
    GREENGAGE_DRIVER,
    GREENGAGE_PROFILE,
    GreenplumRuntimeProfile,
    match_greenplum_runtime_profile,
)
from forensic_data.mssql_profile import (
    MSSQL_2016_DRIVER,
    MSSQL_2016_PROFILE,
    MSSQL_2022_DRIVER,
    MSSQL_2022_PROFILE,
    match_mssql_runtime_profile,
)
from forensic_data.postgres_profile import (
    POSTGRES_17_DRIVER,
    POSTGRES_17_PROFILE,
    PostgresRuntimeProfile,
    match_postgres_runtime_profile,
)

_ROW_EQUIVALENCE = "row_equivalence"


def load_contract_config(path: Path) -> LoadedContractConfig:
    return compile_contract(load_contract_source(path))


def compile_contract(source: LoadedContractSource) -> LoadedContractConfig:
    if type(source.version) is not int or source.version != 1:
        raise ContractValidationError("contract version must be exactly 1")

    connection_pairs = tuple(
        (item.connection_id, _compile_connection(item)) for item in source.connections
    )
    connections = _unique_pairs(connection_pairs, "connection")
    if not connections:
        raise ContractValidationError("contract must define at least one connection")

    schema_pairs = tuple((item.schema_id, _compile_schema(item)) for item in source.schemas)
    schemas = _unique_pairs(schema_pairs, "logical schema")
    if not schemas:
        raise ContractValidationError("contract must define at least one logical schema")

    dataset_pairs = tuple(
        (item.dataset_id, _compile_dataset(item, connections, schemas)) for item in source.datasets
    )
    datasets = _unique_pairs(dataset_pairs, "dataset")
    if not datasets:
        raise ContractValidationError("contract must define at least one dataset")

    named_scope_pairs = tuple(
        (scope_id, _compile_scope(scope, datasets, f"scope {scope_id!r}"))
        for scope_id, scope in source.named_scopes
    )
    named_scopes = _unique_pairs(named_scope_pairs, "scope")

    consistency_pairs = tuple(
        (
            item.consistency_id,
            _compile_consistency(item, datasets),
        )
        for item in source.consistency
    )
    consistency = _unique_pairs(consistency_pairs, "consistency policy")
    if not consistency:
        raise ContractValidationError("contract must define at least one consistency policy")

    check_pairs = tuple(
        (
            item.check_id,
            _compile_check(
                item,
                datasets,
                schemas,
                named_scopes,
                consistency,
            ),
        )
        for item in source.checks
    )
    checks = _unique_pairs(check_pairs, "check")
    if not checks:
        raise ContractValidationError("contract must define at least one check")

    metadata_connection = _required_reference(
        connections,
        source.metadata_connection_ref,
        "metadata connection",
    )
    if ConnectionRole.METADATA not in metadata_connection.roles:
        raise ContractValidationError(
            f"metadata connection {metadata_connection.connection_id!r} must declare role 'metadata'"
        )
    if metadata_connection.adapter is not Adapter.POSTGRESQL or (
        match_postgres_runtime_profile(
            metadata_connection.driver,
            metadata_connection.profile,
        )
        is not PostgresRuntimeProfile.POSTGRES_17
    ):
        raise UnsupportedContractError(
            f"metadata connection {metadata_connection.connection_id!r} requires "
            f"driver={POSTGRES_17_DRIVER!r} and profile={POSTGRES_17_PROFILE!r}"
        )

    execution = _compile_execution(source)
    evidence = _compile_evidence(source.evidence, schemas)
    return LoadedContractConfig(
        version=source.version,
        connections=tuple(value for _, value in sorted(connections.items())),
        schemas=tuple(value for _, value in sorted(schemas.items())),
        datasets=tuple(value for _, value in sorted(datasets.items())),
        checks=tuple(value for _, value in sorted(checks.items())),
        named_scopes=tuple(sorted(named_scopes.items())),
        consistency=tuple(sorted(consistency.items())),
        execution=execution,
        metadata=MetadataDefinition(connection=metadata_connection),
        evidence=evidence,
    )


def _compile_connection(source: ConnectionSource) -> ConnectionDefinition:
    connection_id = _logical_name(source.connection_id, "connection id")
    try:
        adapter = Adapter(source.adapter)
    except ValueError:
        raise UnsupportedContractError(
            f"connection {connection_id!r} adapter is unsupported: adapter={source.adapter!r}"
        ) from None
    driver = _logical_name(source.driver, f"connection {connection_id!r} driver")
    profile = _logical_name(source.profile, f"connection {connection_id!r} profile")
    secret_ref = _logical_name(source.secret_ref, f"connection {connection_id!r} secret_ref")
    if not source.roles:
        raise ContractValidationError(
            f"connection {connection_id!r} must declare at least one role"
        )
    roles: list[ConnectionRole] = []
    for raw_role in source.roles:
        try:
            role = ConnectionRole(raw_role)
        except ValueError:
            raise UnsupportedContractError(
                f"connection {connection_id!r} role is unsupported: role={raw_role!r}"
            ) from None
        if role in roles:
            raise ContractValidationError(
                f"connection {connection_id!r} contains duplicate role {role.value!r}"
            )
        roles.append(role)
    if adapter is Adapter.MSSQL:
        if match_mssql_runtime_profile(driver, profile) is None:
            raise UnsupportedContractError(
                f"connection {connection_id!r} MSSQL endpoint requires an exact supported "
                "driver/profile pair: "
                f"({MSSQL_2022_DRIVER!r}, {MSSQL_2022_PROFILE!r}) or "
                f"({MSSQL_2016_DRIVER!r}, {MSSQL_2016_PROFILE!r})"
            )
        if roles != [ConnectionRole.SOURCE]:
            raise UnsupportedContractError(
                f"connection {connection_id!r} profile {profile!r} is source-only "
                "and must declare exactly role 'source'"
            )
    if adapter is Adapter.GREENGAGE:
        if (
            match_greenplum_runtime_profile(driver, profile)
            is not GreenplumRuntimeProfile.GREENGAGE
        ):
            raise UnsupportedContractError(
                f"connection {connection_id!r} Greengage endpoint requires exact "
                f"driver/profile pair ({GREENGAGE_DRIVER!r}, {GREENGAGE_PROFILE!r})"
            )
        if ConnectionRole.TARGET not in roles:
            raise UnsupportedContractError(
                f"connection {connection_id!r} profile {profile!r} must declare role 'target'"
            )
    return ConnectionDefinition(
        connection_id=connection_id,
        adapter=adapter,
        driver=driver,
        profile=profile,
        roles=tuple(roles),
        secret_ref=secret_ref,
    )


def _compile_schema(source: SchemaSource) -> LogicalSchemaDefinition:
    schema_id = _logical_name(source.schema_id, "logical schema id")
    if not source.fields:
        raise ContractValidationError(f"logical schema {schema_id!r} must contain fields")
    names: set[str] = set()
    fields: list[FieldSchema] = []
    equalities: list[FieldEquality] = []
    for field_source in source.fields:
        name = _logical_name(field_source.name, f"logical schema {schema_id!r} field name")
        if name in names:
            raise ContractValidationError(
                f"logical schema {schema_id!r} contains duplicate field {name!r}"
            )
        names.add(name)
        if field_source.normalization != Normalization.NONE.value:
            raise UnsupportedContractError(
                f"logical schema {schema_id!r} field {name!r} normalization is unsupported: "
                f"normalization={field_source.normalization!r}"
            )
        if field_source.equality != FieldEquality.EXACT.value:
            raise UnsupportedContractError(
                f"logical schema {schema_id!r} field {name!r} equality is unsupported: "
                f"equality={field_source.equality!r}"
            )
        fields.append(
            _field_schema(
                name,
                field_source.logical_type,
                field_source.nullable,
                f"logical schema {schema_id!r} field {name!r}",
            )
        )
        equalities.append(FieldEquality.EXACT)
    schema = CanonicalSchema(protocol=PROTOCOL, fields=tuple(fields))
    return LogicalSchemaDefinition(
        schema_id=schema_id,
        schema=schema,
        equality=tuple(equalities),
        logical_schema_digest=schema_digest_hex(schema),
    )


def _compile_dataset(
    source: DatasetSource,
    connections: dict[str, ConnectionDefinition],
    schemas: dict[str, LogicalSchemaDefinition],
) -> DatasetDefinition:
    dataset_id = _logical_name(source.dataset_id, "dataset id")
    connection = _required_reference(
        connections,
        source.connection_ref,
        f"dataset {dataset_id!r} connection",
    )
    logical_schema = _required_reference(
        schemas,
        source.logical_schema_ref,
        f"dataset {dataset_id!r} logical schema",
    )
    locator = _compile_dataset_locator(source.locator, connection, dataset_id)

    expected_fields = tuple(field.name for field in logical_schema.schema.fields)
    projected_fields = tuple(projected.field for projected in source.projection)
    if projected_fields != expected_fields:
        raise ContractValidationError(
            f"dataset {dataset_id!r} projection must cover logical schema fields exactly once "
            f"and in order: expected={expected_fields!r}, actual={projected_fields!r}"
        )
    projection = tuple(
        ProjectedField(
            field_name=_logical_name(
                projected.field,
                f"dataset {dataset_id!r} projected field",
            ),
            column_name=_physical_name(
                projected.column,
                f"dataset {dataset_id!r} projected column",
            ),
        )
        for projected in source.projection
    )
    grain = _ordered_known_fields(
        source.grain,
        logical_schema,
        f"dataset {dataset_id!r} grain",
    )
    return DatasetDefinition(
        dataset_id=dataset_id,
        connection=connection,
        locator=locator,
        logical_schema=logical_schema,
        projection=projection,
        grain=grain,
    )


def _compile_dataset_locator(
    source: DatasetLocatorSource,
    connection: ConnectionDefinition,
    dataset_id: str,
) -> RelationLocator | SqlArtifactDefinition:
    if isinstance(source, RelationSource):
        if source.catalog is not None:
            raise UnsupportedContractError(
                f"dataset {dataset_id!r} {connection.adapter.value} relation catalog is "
                "unsupported; use null"
            )
        if source.schema is None:
            raise UnsupportedContractError(
                f"dataset {dataset_id!r} {connection.adapter.value} relation requires an "
                "explicit schema"
            )
        try:
            relation_scope = RelationScope(source.relation_scope)
        except ValueError:
            raise UnsupportedContractError(
                f"dataset {dataset_id!r} {connection.adapter.value} relation scope is "
                "unsupported: "
                f"relation_scope={source.relation_scope!r}"
            ) from None
        if (
            connection.adapter in (Adapter.MSSQL, Adapter.GREENGAGE)
            and relation_scope is not RelationScope.PHYSICAL_ONLY
        ):
            raise UnsupportedContractError(
                f"dataset {dataset_id!r} {connection.adapter.value} relation requires "
                "physical_only scope: "
                f"relation_scope={relation_scope.value!r}"
            )
        return RelationLocator(
            catalog=None,
            schema=_physical_name(source.schema, f"dataset {dataset_id!r} relation schema"),
            name=_physical_name(source.name, f"dataset {dataset_id!r} relation name"),
            relation_scope=relation_scope,
        )
    return _compile_sql_artifact(
        source,
        connection.adapter,
        f"dataset {dataset_id!r} SQL artifact",
    )


def _compile_sql_artifact(
    source: SqlArtifactSource,
    adapter: Adapter,
    context: str,
) -> SqlArtifactDefinition:
    if source.dialect != SqlDialect.POSTGRESQL.value:
        raise UnsupportedContractError(
            f"{context} dialect is unsupported: dialect={source.dialect!r}"
        )
    dialect = SqlDialect.POSTGRESQL
    if adapter is not Adapter.POSTGRESQL:
        raise UnsupportedContractError(
            f"{context} dialect {dialect.value!r} does not match adapter {adapter.value!r}"
        )
    if source.content.strip() == "":
        raise ContractValidationError(f"{context} must not be empty")
    if len(source.content_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in source.content_sha256
    ):
        raise ContractValidationError(f"{context} content digest must be 64 lowercase hex digits")
    names: set[str] = set()
    parameters: list[SqlParameterDefinition] = []
    for parameter in source.parameters:
        name = _logical_name(parameter.name, f"{context} parameter name")
        if name in names:
            raise ContractValidationError(f"{context} contains duplicate parameter {name!r}")
        names.add(name)
        parameters.append(
            SqlParameterDefinition(
                name=name,
                field=_field_schema(
                    name,
                    parameter.logical_type,
                    False,
                    f"{context} parameter {name!r}",
                ),
            )
        )
    return SqlArtifactDefinition(
        path=source.path,
        dialect=dialect,
        parameters=tuple(parameters),
        content=source.content,
        content_sha256=source.content_sha256,
    )


def _compile_scope(
    source: ScopeSource,
    datasets: dict[str, DatasetDefinition],
    context: str,
) -> ScopeDefinition:
    try:
        null_partition = NullPartitionPolicy(source.null_partition)
    except ValueError:
        raise UnsupportedContractError(
            f"{context} null partition policy is unsupported: policy={source.null_partition!r}"
        ) from None

    if len(source.parameters) > 1:
        raise UnsupportedContractError(
            f"{context} has {len(source.parameters)} parameters; the initial profile supports one"
        )
    parameter_names: set[str] = set()
    parameters: list[ScopeParameterDefinition] = []
    for parameter in source.parameters:
        name = _logical_name(parameter.name, f"{context} parameter name")
        if name in parameter_names:
            raise ContractValidationError(f"{context} contains duplicate parameter {name!r}")
        parameter_names.add(name)
        parameters.append(
            ScopeParameterDefinition(
                name=name,
                field=_field_schema(
                    name,
                    parameter.logical_type,
                    False,
                    f"{context} parameter {name!r}",
                ),
            )
        )
    if not parameters and source.bindings:
        raise ContractValidationError(f"{context} cannot have bindings without parameters")
    if parameters and not source.bindings:
        raise ContractValidationError(f"{context} parameters require per-side bindings")

    bindings: list[ScopeBinding] = []
    dataset_refs: set[str] = set()
    for binding_source in source.bindings:
        dataset = _required_reference(
            datasets,
            binding_source.dataset_ref,
            f"{context} binding dataset",
        )
        if dataset.dataset_id in dataset_refs:
            raise ContractValidationError(
                f"{context} contains more than one binding for dataset {dataset.dataset_id!r}"
            )
        dataset_refs.add(dataset.dataset_id)
        parameter = next(
            (item for item in parameters if item.name == binding_source.parameter_ref),
            None,
        )
        if parameter is None:
            raise ContractReferenceError(
                f"{context} binding for dataset {dataset.dataset_id!r} references unknown "
                f"parameter {binding_source.parameter_ref!r}"
            )
        try:
            operator = ScopeOperator(binding_source.operator)
        except ValueError:
            raise UnsupportedContractError(
                f"{context} binding operator is unsupported: operator={binding_source.operator!r}"
            ) from None
        column = _physical_name(
            binding_source.column,
            f"{context} binding column for dataset {dataset.dataset_id!r}",
        )
        projected_field = _projected_field_for_column(dataset, column, context)
        if projected_field is not None and not _same_logical_type(
            projected_field,
            parameter.field,
        ):
            raise ContractValidationError(
                f"{context} binding column {column!r} for dataset {dataset.dataset_id!r} "
                f"does not match parameter {parameter.name!r} logical type"
            )
        bindings.append(
            ScopeBinding(
                dataset_id=dataset.dataset_id,
                column=column,
                operator=operator,
                parameter=parameter.name,
            )
        )
    return ScopeDefinition(
        parameters=tuple(parameters),
        bindings=tuple(bindings),
        null_partition=null_partition,
    )


def _compile_consistency(
    source: ConsistencySource,
    datasets: dict[str, DatasetDefinition],
) -> ConsistencyDefinition:
    consistency_id = _logical_name(source.consistency_id, "consistency policy id")
    context = f"consistency policy {consistency_id!r}"
    try:
        minimum_evidence = MinimumEvidence(source.minimum_evidence)
    except ValueError:
        raise UnsupportedContractError(
            f"{context} minimum evidence is unsupported: value={source.minimum_evidence!r}"
        ) from None
    try:
        late_arrivals = LateArrivalPolicy(source.late_arrivals)
    except ValueError:
        raise UnsupportedContractError(
            f"{context} late-arrival policy is unsupported: value={source.late_arrivals!r}"
        ) from None
    alignment_fields = _ordered_unique_text(
        source.alignment_fields,
        f"{context} alignment fields",
    )
    compiled_datasets: list[ConsistencyDatasetDefinition] = []
    seen: set[str] = set()
    for item in source.datasets:
        dataset = _required_reference(
            datasets,
            item.dataset_ref,
            f"{context} dataset",
        )
        if dataset.dataset_id in seen:
            raise ContractValidationError(
                f"{context} contains duplicate dataset {dataset.dataset_id!r}"
            )
        seen.add(dataset.dataset_id)
        try:
            stable_read = StableReadKind(item.stable_read)
        except ValueError:
            raise UnsupportedContractError(
                f"{context} stable-read strategy is unsupported for dataset "
                f"{dataset.dataset_id!r}: kind={item.stable_read!r}"
            ) from None
        readiness_context = f"{context} readiness for dataset {dataset.dataset_id!r}"
        if isinstance(item.readiness, SqlArtifactSource):
            readiness = _compile_sql_artifact(
                item.readiness,
                dataset.connection.adapter,
                f"{readiness_context} artifact",
            )
        else:
            readiness = _compile_relation_manifest_readiness(
                item.readiness,
                dataset,
                readiness_context,
            )
        compiled_datasets.append(
            ConsistencyDatasetDefinition(
                dataset_id=dataset.dataset_id,
                readiness=readiness,
                stable_read=stable_read,
            )
        )
    if not compiled_datasets:
        raise ContractValidationError(f"{context} must define dataset readiness")
    return ConsistencyDefinition(
        minimum_evidence=minimum_evidence,
        alignment_fields=alignment_fields,
        late_arrivals=late_arrivals,
        datasets=tuple(compiled_datasets),
    )


def _compile_relation_manifest_readiness(
    source: RelationManifestReadinessSource,
    dataset: DatasetDefinition,
    context: str,
) -> RelationManifestReadiness:
    if source.relation.catalog is not None:
        raise UnsupportedContractError(
            f"{context} {dataset.connection.adapter.value} relation catalog is unsupported; "
            "use null"
        )
    if source.relation.schema is None:
        raise UnsupportedContractError(
            f"{context} {dataset.connection.adapter.value} relation requires an explicit schema"
        )
    if source.relation.relation_scope != RelationScope.PHYSICAL_ONLY.value:
        raise UnsupportedContractError(
            f"{context} relation requires physical_only scope: "
            f"relation_scope={source.relation.relation_scope!r}"
        )
    relation = RelationLocator(
        catalog=None,
        schema=_physical_name(source.relation.schema, f"{context} relation schema"),
        name=_physical_name(source.relation.name, f"{context} relation name"),
        relation_scope=RelationScope.PHYSICAL_ONLY,
    )
    columns = source.columns
    return RelationManifestReadiness(
        connection_id=dataset.connection.connection_id,
        relation=relation,
        columns=ReadinessManifestColumns(
            dataset_id=_physical_name(columns.dataset_id, f"{context} dataset_id column"),
            scope_digest=_physical_name(
                columns.scope_digest,
                f"{context} scope_digest column",
            ),
            batch_id=_physical_name(columns.batch_id, f"{context} batch_id column"),
            state=_physical_name(columns.state, f"{context} state column"),
            business_date=_physical_name(
                columns.business_date,
                f"{context} business_date column",
            ),
            source_cut=_physical_name(columns.source_cut, f"{context} source_cut column"),
            dataset_version=_physical_name(
                columns.dataset_version,
                f"{context} dataset_version column",
            ),
            completed_at=_physical_name(
                columns.completed_at,
                f"{context} completed_at column",
            ),
        ),
    )


def _compile_check(
    source: CheckSource,
    datasets: dict[str, DatasetDefinition],
    schemas: dict[str, LogicalSchemaDefinition],
    named_scopes: dict[str, ScopeDefinition],
    consistency: dict[str, ConsistencyDefinition],
) -> RowCheckDefinition:
    check_id = _logical_name(source.check_id, "check id")
    context = f"check {check_id!r}"
    if (source.inline_scope is None) == (source.scope_ref is None):
        raise ContractValidationError(
            f"{context} requires exactly one of inline_scope or scope_ref"
        )
    if source.revision < 1:
        raise ContractValidationError(f"{context} revision must be positive")
    if source.invariant != _ROW_EQUIVALENCE:
        raise UnsupportedContractError(
            f"{context} invariant is unsupported: invariant={source.invariant!r}"
        )
    reference = _required_reference(datasets, source.reference_ref, f"{context} reference")
    target = _required_reference(datasets, source.target_ref, f"{context} target")
    if reference.dataset_id == target.dataset_id:
        raise ContractValidationError(f"{context} reference and target datasets must differ")
    if ConnectionRole.SOURCE not in reference.connection.roles:
        raise ContractValidationError(
            f"{context} reference connection {reference.connection.connection_id!r} "
            "must declare role 'source'"
        )
    if ConnectionRole.TARGET not in target.connection.roles:
        raise ContractValidationError(
            f"{context} target connection {target.connection.connection_id!r} "
            "must declare role 'target'"
        )
    comparison_schema = _required_reference(
        schemas,
        source.comparison_schema_ref,
        f"{context} comparison schema",
    )
    for direction, dataset in (("reference", reference), ("target", target)):
        if dataset.logical_schema.logical_schema_digest != comparison_schema.logical_schema_digest:
            raise ContractValidationError(
                f"{context} {direction} dataset {dataset.dataset_id!r} logical schema does not "
                f"match comparison schema {comparison_schema.schema_id!r}"
            )
        if dataset.logical_schema.equality != comparison_schema.equality:
            raise ContractValidationError(
                f"{context} {direction} dataset {dataset.dataset_id!r} equality policy does not "
                f"match comparison schema {comparison_schema.schema_id!r}"
            )
    key = _ordered_known_fields(source.key, comparison_schema, f"{context} key")
    if reference.grain != key or target.grain != key:
        raise ContractValidationError(
            f"{context} ordered key must equal both dataset grains: key={key!r}, "
            f"reference_grain={reference.grain!r}, target_grain={target.grain!r}"
        )

    if source.inline_scope is not None:
        scope = _compile_scope(source.inline_scope, datasets, f"{context} inline scope")
    elif source.scope_ref is not None:
        scope = _required_reference(named_scopes, source.scope_ref, f"{context} scope")
    else:
        raise AssertionError("validated check scope is missing")
    _validate_check_scope(scope, reference, target, context)
    scope = _order_check_scope(scope, reference, target)
    _validate_projection_parameters(reference, target, scope, context)

    selected_consistency = _required_reference(
        consistency,
        source.consistency_ref,
        f"{context} consistency policy",
    )
    resolved_consistency = _select_consistency(
        selected_consistency,
        reference,
        target,
        scope,
        context,
    )
    try:
        assurance_policy = AssurancePolicy(source.assurance_policy)
    except ValueError:
        raise UnsupportedContractError(
            f"{context} assurance policy is unsupported: value={source.assurance_policy!r}"
        ) from None

    return RowCheckDefinition(
        check_id=check_id,
        revision=source.revision,
        reference=reference,
        target=target,
        comparison_schema=comparison_schema,
        key=key,
        scope=scope,
        consistency=resolved_consistency,
        assurance_policy=assurance_policy,
    )


def _validate_check_scope(
    scope: ScopeDefinition,
    reference: DatasetDefinition,
    target: DatasetDefinition,
    context: str,
) -> None:
    if not scope.parameters:
        if scope.bindings:
            raise ContractValidationError(f"{context} full scope cannot contain bindings")
        return
    expected = {reference.dataset_id, target.dataset_id}
    actual = {binding.dataset_id for binding in scope.bindings}
    if actual != expected or len(scope.bindings) != 2:
        raise UnsupportedContractError(
            f"{context} scoped comparison requires exactly one binding for each side: "
            f"expected={sorted(expected)!r}, actual={sorted(actual)!r}"
        )


def _order_check_scope(
    scope: ScopeDefinition,
    reference: DatasetDefinition,
    target: DatasetDefinition,
) -> ScopeDefinition:
    if not scope.bindings:
        return scope
    by_dataset = {binding.dataset_id: binding for binding in scope.bindings}
    return ScopeDefinition(
        parameters=scope.parameters,
        bindings=(
            by_dataset[reference.dataset_id],
            by_dataset[target.dataset_id],
        ),
        null_partition=scope.null_partition,
    )


def _select_consistency(
    consistency: ConsistencyDefinition,
    reference: DatasetDefinition,
    target: DatasetDefinition,
    scope: ScopeDefinition,
    context: str,
) -> ConsistencyDefinition:
    by_dataset = {item.dataset_id: item for item in consistency.datasets}
    selected: list[ConsistencyDatasetDefinition] = []
    expected_parameters = tuple(parameter.field for parameter in scope.parameters)
    for direction, dataset in (("reference", reference), ("target", target)):
        item = by_dataset.get(dataset.dataset_id)
        if item is None:
            raise ContractReferenceError(
                f"{context} consistency policy does not define {direction} dataset "
                f"{dataset.dataset_id!r}"
            )
        if isinstance(item.readiness, SqlArtifactDefinition):
            actual_parameters = tuple(parameter.field for parameter in item.readiness.parameters)
            if not _parameter_definitions_are_ordered_subset(
                expected_parameters,
                actual_parameters,
            ):
                raise ContractValidationError(
                    f"{context} readiness parameters for {direction} dataset "
                    f"{dataset.dataset_id!r} must be an ordered typed subset of the scope "
                    "parameters"
                )
        elif item.readiness.connection_id != dataset.connection.connection_id:
            raise ContractValidationError(
                f"{context} readiness relation for {direction} dataset "
                f"{dataset.dataset_id!r} must use the dataset connection"
            )
        selected.append(item)
    return ConsistencyDefinition(
        minimum_evidence=consistency.minimum_evidence,
        alignment_fields=consistency.alignment_fields,
        late_arrivals=consistency.late_arrivals,
        datasets=tuple(selected),
    )


def _validate_projection_parameters(
    reference: DatasetDefinition,
    target: DatasetDefinition,
    scope: ScopeDefinition,
    context: str,
) -> None:
    expected = tuple(parameter.field for parameter in scope.parameters)
    for direction, dataset in (("reference", reference), ("target", target)):
        if isinstance(dataset.locator, RelationLocator):
            continue
        actual = tuple(parameter.field for parameter in dataset.locator.parameters)
        if not _parameter_definitions_are_ordered_subset(expected, actual):
            raise ContractValidationError(
                f"{context} projection parameters for {direction} dataset "
                f"{dataset.dataset_id!r} must be an ordered typed subset of the scope parameters"
            )


def _compile_execution(source: LoadedContractSource) -> ExecutionBudgets:
    value = source.execution
    if type(value.version) is not int or value.version != 1:
        raise ContractValidationError("execution version must be exactly 1")
    positive = (
        ("max_queries", value.max_queries),
        ("max_fetched_records", value.max_fetched_records),
        ("max_application_result_bytes", value.max_application_result_bytes),
        ("max_fingerprint_nodes", value.max_fingerprint_nodes),
        ("max_coordinator_memory_bytes", value.max_coordinator_memory_bytes),
        ("statement_timeout_milliseconds", value.statement_timeout_milliseconds),
        ("run_timeout_milliseconds", value.run_timeout_milliseconds),
        ("max_attempts", value.max_attempts),
        ("max_checks_concurrency", value.max_checks_concurrency),
        ("max_source_concurrency", value.max_source_concurrency),
    )
    nonnegative = (
        ("max_evidence_rows", value.max_evidence_rows),
        ("max_evidence_bytes", value.max_evidence_bytes),
        ("max_depth", value.max_depth),
        ("max_full_scans_per_side", value.max_full_scans_per_side),
    )
    for name, amount in positive:
        if type(amount) is not int or amount < 1:
            raise ContractValidationError(f"execution {name} must be a positive exact integer")
    for name, amount in nonnegative:
        if type(amount) is not int or amount < 0:
            raise ContractValidationError(f"execution {name} must be a nonnegative exact integer")
    return ExecutionBudgets(
        version=value.version,
        max_queries=value.max_queries,
        max_fetched_records=value.max_fetched_records,
        max_application_result_bytes=value.max_application_result_bytes,
        max_evidence_rows=value.max_evidence_rows,
        max_evidence_bytes=value.max_evidence_bytes,
        max_fingerprint_nodes=value.max_fingerprint_nodes,
        max_coordinator_memory_bytes=value.max_coordinator_memory_bytes,
        max_depth=value.max_depth,
        max_full_scans_per_side=value.max_full_scans_per_side,
        statement_timeout_milliseconds=value.statement_timeout_milliseconds,
        run_timeout_milliseconds=value.run_timeout_milliseconds,
        max_attempts=value.max_attempts,
        max_checks_concurrency=value.max_checks_concurrency,
        max_source_concurrency=value.max_source_concurrency,
    )


def _compile_evidence(
    source: EvidenceSource,
    schemas: dict[str, LogicalSchemaDefinition],
) -> EvidenceDefinition:
    try:
        sql_capture = CapturePolicy(source.sql_capture)
    except ValueError:
        raise UnsupportedContractError(
            f"evidence SQL capture policy is unsupported: value={source.sql_capture!r}"
        ) from None
    try:
        ddl_capture = CapturePolicy(source.ddl_capture)
    except ValueError:
        raise UnsupportedContractError(
            f"evidence DDL capture policy is unsupported: value={source.ddl_capture!r}"
        ) from None
    try:
        unspecified_fields = EvidenceAction(source.unspecified_fields)
    except ValueError:
        raise UnsupportedContractError(
            "evidence unspecified-fields policy is unsupported: "
            f"value={source.unspecified_fields!r}"
        ) from None
    known_fields = {field.name for schema in schemas.values() for field in schema.schema.fields}
    policies: list[EvidenceFieldPolicy] = []
    seen: set[str] = set()
    for raw_name, raw_action in source.fields:
        name = _logical_name(raw_name, "evidence field name")
        if name in seen:
            raise ContractValidationError(f"evidence contains duplicate field {name!r}")
        seen.add(name)
        if name not in known_fields:
            raise ContractReferenceError(f"evidence references unknown logical field {name!r}")
        try:
            action = EvidenceAction(raw_action)
        except ValueError:
            raise UnsupportedContractError(
                f"evidence action is unsupported for field {name!r}: value={raw_action!r}"
            ) from None
        policies.append(EvidenceFieldPolicy(field_name=name, action=action))
    return EvidenceDefinition(
        sql_capture=sql_capture,
        ddl_capture=ddl_capture,
        fields=tuple(policies),
        unspecified_fields=unspecified_fields,
    )


def _field_schema(
    name: str,
    source: LogicalTypeSource,
    nullable: bool,
    context: str,
) -> FieldSchema:
    if type(nullable) is not bool:
        raise ContractValidationError(f"{context} nullable must be a boolean")
    try:
        if source.kind == LogicalType.DECIMAL.value:
            if source.precision is None or source.scale is None:
                raise ContractValidationError(f"{context} decimal requires precision and scale")
            parameters = DecimalParameters(precision=source.precision, scale=source.scale)
            logical_type = LogicalType.DECIMAL
        elif source.kind in (
            LogicalType.TIMESTAMP_LOCAL.value,
            LogicalType.TIMESTAMP_INSTANT.value,
        ):
            if source.precision is None or source.scale is not None:
                raise ContractValidationError(
                    f"{context} timestamp requires precision and does not accept scale"
                )
            parameters = TimestampParameters(precision=source.precision)
            logical_type = LogicalType(source.kind)
        else:
            if source.precision is not None or source.scale is not None:
                raise ContractValidationError(
                    f"{context} type {source.kind!r} does not accept precision or scale"
                )
            try:
                logical_type = LogicalType(source.kind)
            except ValueError:
                raise UnsupportedContractError(
                    f"{context} logical type is unsupported: kind={source.kind!r}"
                ) from None
            parameters = NoParameters()
        return FieldSchema(
            name=name,
            logical_type=logical_type,
            nullable=nullable,
            parameters=parameters,
            normalization=Normalization.NONE,
        )
    except SchemaValidationError as error:
        raise ContractValidationError(f"{context} is invalid: {error}") from error


def _ordered_known_fields(
    raw_names: tuple[str, ...],
    schema: LogicalSchemaDefinition,
    context: str,
) -> tuple[str, ...]:
    names = _ordered_unique_text(raw_names, context)
    by_name = {field.name: field for field in schema.schema.fields}
    for name in names:
        field = by_name.get(name)
        if field is None:
            raise ContractReferenceError(f"{context} references unknown field {name!r}")
        if field.nullable:
            raise ContractValidationError(f"{context} field {name!r} must be non-nullable")
    return names


def _ordered_unique_text(
    values: tuple[str, ...],
    context: str,
) -> tuple[str, ...]:
    if not values:
        raise ContractValidationError(f"{context} must not be empty")
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        name = _logical_name(value, context)
        if name in seen:
            raise ContractValidationError(f"{context} contains duplicate value {name!r}")
        seen.add(name)
        result.append(name)
    return tuple(result)


def _projected_field_for_column(
    dataset: DatasetDefinition,
    column: str,
    context: str,
) -> FieldSchema | None:
    matching_names = tuple(
        projected.field_name for projected in dataset.projection if projected.column_name == column
    )
    if len(matching_names) > 1:
        raise ContractReferenceError(
            f"{context} binding column {column!r} maps to more than one projected field "
            f"in dataset {dataset.dataset_id!r}; matches={len(matching_names)}"
        )
    if not matching_names:
        return None
    fields = {field.name: field for field in dataset.logical_schema.schema.fields}
    return fields[matching_names[0]]


def _same_logical_type(left: FieldSchema, right: FieldSchema) -> bool:
    return (
        left.logical_type is right.logical_type
        and left.parameters == right.parameters
        and left.normalization is right.normalization
    )


def _parameter_definitions_are_ordered_subset(
    expected: tuple[FieldSchema, ...],
    actual: tuple[FieldSchema, ...],
) -> bool:
    expected_positions = {field.name: index for index, field in enumerate(expected)}
    last_position = -1
    for field in actual:
        position = expected_positions.get(field.name)
        if position is None or position <= last_position:
            return False
        if not _same_logical_type(expected[position], field):
            return False
        last_position = position
    return True


def _logical_name(value: str, context: str) -> str:
    _validate_text(value, context)
    if value.strip() == "":
        raise ContractValidationError(f"{context} must not be blank")
    return value


def _physical_name(value: str, context: str) -> str:
    _validate_text(value, context)
    if value == "":
        raise ContractValidationError(f"{context} must not be empty")
    return value


def _validate_text(value: str, context: str) -> None:
    if type(value) is not str:
        raise ContractValidationError(f"{context} must be a string")
    for index, character in enumerate(value):
        code_point = ord(character)
        if code_point == 0:
            raise ContractValidationError(f"{context} contains U+0000 at character {index}")
        if 0xD800 <= code_point <= 0xDFFF:
            raise ContractValidationError(
                f"{context} contains a surrogate code point at character {index}"
            )


def _required_reference[ValueT](
    values: dict[str, ValueT],
    reference: str,
    context: str,
) -> ValueT:
    validated_reference = _logical_name(reference, context)
    result = values.get(validated_reference)
    if result is None:
        raise ContractReferenceError(f"{context} references unknown id {validated_reference!r}")
    return result


def _unique_pairs[ValueT](
    pairs: tuple[tuple[str, ValueT], ...],
    entity_name: str,
) -> dict[str, ValueT]:
    result: dict[str, ValueT] = {}
    for raw_name, value in pairs:
        name = _logical_name(raw_name, f"{entity_name} id")
        if name in result:
            raise ContractValidationError(f"duplicate {entity_name} id {name!r}")
        result[name] = value
    return result
