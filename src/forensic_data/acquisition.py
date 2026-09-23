from dataclasses import dataclass
from datetime import date, datetime, timedelta
from enum import StrEnum
from typing import Protocol, final, runtime_checkable
from uuid import UUID

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalInput,
    DecimalParameters,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
    PayloadValidationError,
    TimestampParameters,
    decode_payload,
    encode_payload,
)
from forensic_data.contracts.model import (
    DatasetDefinition,
    EvidenceDefinition,
    ExecutionBudgets,
    LateArrivalPolicy,
    MinimumEvidence,
    ReadinessDefinition,
    RelationLocator,
    RelationManifestReadiness,
    RelationScope,
    RowCheckDefinition,
    SqlArtifactDefinition,
)
from forensic_data.contracts.semantics import SemanticValue, semantic_digest_hex
from forensic_data.planning import (
    ArtifactPurpose,
    PlanDirection,
    ResolvedScope,
    resolved_scope_semantic_value,
)
from forensic_data.result import (
    ConsistencyLevel,
    ExecutionStatus,
    ReasonCode,
    ResultReason,
    SafeParameter,
)

__all__ = (
    "AcquisitionOperation",
    "AcquisitionValidationError",
    "ArtifactCaptureSelection",
    "ArtifactSelection",
    "BuildingReadinessRecord",
    "CanonicalValueDefinition",
    "CompleteReadinessRecord",
    "DatasetInputCutDefinition",
    "EarlyExecutionOutcome",
    "ExecutionBudgets",
    "ExpectedBatchDefinition",
    "InputCutDefinition",
    "ReadinessProviderKind",
    "RelationManifestEvidence",
    "RelationManifestRecord",
    "RelationManifestRow",
    "RunRequestDefinition",
    "artifact_selection_for_check",
    "build_input_cut_definition",
    "build_run_request_definition",
    "canonical_alignment_value",
    "canonical_value",
    "classify_bound_input_cut",
    "classify_check_acquisition",
    "classify_dataset_acquisition",
    "classify_input_cut_alignment",
    "classify_readiness_acquisition",
    "input_cut_semantic_value",
    "readiness_evidence_semantic_value",
    "run_request_semantic_value",
    "validate_artifact_selection",
    "validate_relation_manifest_readiness",
)


class AcquisitionValidationError(ValueError):
    """An acquisition identity or observation violates its immutable closure."""


class AcquisitionOperation(StrEnum):
    RESOLVE_DATASET_DEPENDENCIES = "resolve_dataset_dependencies"
    RESOLVE_READINESS_DEPENDENCIES = "resolve_readiness_dependencies"
    VALIDATE_ALIGNMENT_FIELDS = "validate_alignment_fields"
    VALIDATE_READINESS = "validate_readiness"
    ALIGN_INPUT_CUT = "align_input_cut"
    VALIDATE_BOUND_INPUT_CUT = "validate_bound_input_cut"


class ReadinessProviderKind(StrEnum):
    RELATION_MANIFEST = "relation_manifest"


_STRING_PARAMETERS = NoParameters()
_BATCH_ID_FIELD = FieldSchema(
    name="batch_id",
    logical_type=LogicalType.STRING,
    nullable=False,
    parameters=_STRING_PARAMETERS,
    normalization=Normalization.NONE,
)
_BUSINESS_DATE_FIELD = FieldSchema(
    name="business_date",
    logical_type=LogicalType.DATE,
    nullable=False,
    parameters=_STRING_PARAMETERS,
    normalization=Normalization.NONE,
)
_SOURCE_CUT_FIELD = FieldSchema(
    name="source_cut",
    logical_type=LogicalType.STRING,
    nullable=False,
    parameters=_STRING_PARAMETERS,
    normalization=Normalization.NONE,
)
_DATASET_VERSION_FIELD = FieldSchema(
    name="dataset_version",
    logical_type=LogicalType.STRING,
    nullable=False,
    parameters=_STRING_PARAMETERS,
    normalization=Normalization.NONE,
)
_COMPLETED_AT_FIELD = FieldSchema(
    name="completed_at",
    logical_type=LogicalType.TIMESTAMP_INSTANT,
    nullable=False,
    parameters=TimestampParameters(precision=6),
    normalization=Normalization.NONE,
)
_ALIGNMENT_FIELDS: dict[str, FieldSchema] = {
    _BUSINESS_DATE_FIELD.name: _BUSINESS_DATE_FIELD,
    _SOURCE_CUT_FIELD.name: _SOURCE_CUT_FIELD,
}


@final
@dataclass(frozen=True, slots=True)
class CanonicalValueDefinition:
    field: FieldSchema
    canonical_payload: bytes

    def __post_init__(self) -> None:
        _require_instance(self.field, FieldSchema, "canonical value field")
        _require_nonblank_text(self.field.name, "canonical value field name")
        if self.field.nullable:
            raise AcquisitionValidationError(
                f"canonical value field {self.field.name!r} must be non-nullable"
            )
        if type(self.canonical_payload) is not bytes:
            raise AcquisitionValidationError("canonical value payload must be bytes")
        try:
            decoded = decode_payload(self.field, self.canonical_payload)
            if encode_payload(self.field, decoded) != self.canonical_payload:
                raise AcquisitionValidationError(
                    f"canonical value field {self.field.name!r} payload is not canonical"
                )
        except PayloadValidationError as error:
            raise AcquisitionValidationError(
                f"canonical value field {self.field.name!r} payload is invalid for logical "
                f"type {self.field.logical_type.value!r}: {error}"
            ) from None


@runtime_checkable
class RelationManifestRow(Protocol):
    @property
    def dataset_id(self) -> str: ...

    @property
    def scope_digest(self) -> str: ...

    @property
    def batch_id(self) -> str: ...

    @property
    def state(self) -> str: ...

    @property
    def business_date(self) -> date: ...

    @property
    def source_cut(self) -> str | None: ...

    @property
    def dataset_version(self) -> str | None: ...

    @property
    def completed_at(self) -> datetime | None: ...


@final
@dataclass(frozen=True, slots=True)
class BuildingReadinessRecord:
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: date
    source_cut: str | None
    dataset_version: str | None
    completed_at: datetime | None

    def __post_init__(self) -> None:
        _validate_manifest_identity(
            self.dataset_id,
            self.scope_digest,
            self.batch_id,
            self.business_date,
        )
        if type(self.state) is not str or self.state != "building":
            raise AcquisitionValidationError("building readiness state must be exactly 'building'")
        _require_optional_nonblank_text(self.source_cut, "building readiness source cut")
        _require_optional_nonblank_text(
            self.dataset_version,
            "building readiness dataset version",
        )
        _require_optional_utc_datetime(
            self.completed_at,
            "building readiness completed_at",
        )


@final
@dataclass(frozen=True, slots=True)
class CompleteReadinessRecord:
    dataset_id: str
    scope_digest: str
    batch_id: str
    state: str
    business_date: date
    source_cut: str
    dataset_version: str
    completed_at: datetime

    def __post_init__(self) -> None:
        _validate_manifest_identity(
            self.dataset_id,
            self.scope_digest,
            self.batch_id,
            self.business_date,
        )
        if type(self.state) is not str or self.state != "complete":
            raise AcquisitionValidationError("complete readiness state must be exactly 'complete'")
        _require_nonblank_text(self.source_cut, "readiness source cut")
        _require_nonblank_text(self.dataset_version, "readiness dataset version")
        if type(self.completed_at) is not datetime:
            raise AcquisitionValidationError(
                "readiness completed_at must be an exact timezone-aware datetime"
            )
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() != timedelta(0):
            raise AcquisitionValidationError("readiness completed_at must use UTC")
        canonical_value(_BUSINESS_DATE_FIELD, self.business_date)
        canonical_value(_SOURCE_CUT_FIELD, self.source_cut)
        canonical_value(_BATCH_ID_FIELD, self.batch_id)
        canonical_value(_DATASET_VERSION_FIELD, self.dataset_version)
        canonical_value(_COMPLETED_AT_FIELD, self.completed_at)


type RelationManifestRecord = BuildingReadinessRecord | CompleteReadinessRecord


@final
@dataclass(frozen=True, slots=True)
class DatasetInputCutDefinition:
    direction: PlanDirection
    dataset_id: str
    scope_digest: str
    batch_id: CanonicalValueDefinition
    business_date: CanonicalValueDefinition
    source_cut: CanonicalValueDefinition
    dataset_version: CanonicalValueDefinition
    completed_at: CanonicalValueDefinition
    alignment_values: tuple[CanonicalValueDefinition, ...]

    def __post_init__(self) -> None:
        _require_instance(self.direction, PlanDirection, "input cut direction")
        _require_nonblank_text(self.dataset_id, "input cut dataset id")
        _require_sha256(self.scope_digest, "input cut scope digest")
        _require_fixed_canonical_value(self.batch_id, _BATCH_ID_FIELD, "input cut batch id")
        _require_canonical_nonblank_string(self.batch_id, "input cut batch id")
        _require_fixed_canonical_value(
            self.business_date,
            _BUSINESS_DATE_FIELD,
            "input cut business_date",
        )
        _require_fixed_canonical_value(
            self.source_cut,
            _SOURCE_CUT_FIELD,
            "input cut source cut",
        )
        _require_canonical_nonblank_string(self.source_cut, "input cut source cut")
        _require_fixed_canonical_value(
            self.dataset_version,
            _DATASET_VERSION_FIELD,
            "input cut dataset version",
        )
        _require_canonical_nonblank_string(
            self.dataset_version,
            "input cut dataset version",
        )
        _require_fixed_canonical_value(
            self.completed_at,
            _COMPLETED_AT_FIELD,
            "input cut completed_at",
        )
        if type(self.alignment_values) is not tuple or not self.alignment_values:
            raise AcquisitionValidationError(
                "input cut alignment values must be a nonempty immutable tuple"
            )
        names: list[str] = []
        for index, value in enumerate(self.alignment_values):
            _require_instance(
                value,
                CanonicalValueDefinition,
                f"input cut alignment value at index {index}",
            )
            expected_field = _ALIGNMENT_FIELDS.get(value.field.name)
            if expected_field is None or value.field != expected_field:
                raise AcquisitionValidationError(
                    f"input cut alignment field {value.field.name!r} is unsupported; "
                    "expected business_date or source_cut"
                )
            fixed_value = (
                self.business_date
                if value.field.name == _BUSINESS_DATE_FIELD.name
                else self.source_cut
            )
            if value.canonical_payload != fixed_value.canonical_payload:
                raise AcquisitionValidationError(
                    f"input cut alignment field {value.field.name!r} must equal its fixed "
                    "per-side readiness fact"
                )
            names.append(value.field.name)
        if len(set(names)) != len(names):
            raise AcquisitionValidationError("input cut alignment field names must be unique")


@final
@dataclass(frozen=True, slots=True)
class RelationManifestEvidence:
    provider_kind: ReadinessProviderKind
    evidence_level: ConsistencyLevel
    state: str
    late_arrivals: LateArrivalPolicy
    cut: DatasetInputCutDefinition

    def __post_init__(self) -> None:
        if self.provider_kind is not ReadinessProviderKind.RELATION_MANIFEST:
            raise AcquisitionValidationError(
                "relation manifest evidence requires relation_manifest provider kind"
            )
        if self.evidence_level is not ConsistencyLevel.VERIFIED:
            raise AcquisitionValidationError("relation manifest evidence level must be verified")
        if type(self.state) is not str or self.state != "complete":
            raise AcquisitionValidationError(
                "relation manifest evidence state must be exactly 'complete'"
            )
        _require_instance(
            self.late_arrivals,
            LateArrivalPolicy,
            "relation manifest late-arrival policy",
        )
        _require_instance(
            self.cut,
            DatasetInputCutDefinition,
            "relation manifest evidence cut",
        )


@final
@dataclass(frozen=True, slots=True)
class InputCutDefinition:
    reference: DatasetInputCutDefinition
    target: DatasetInputCutDefinition
    late_arrivals: LateArrivalPolicy
    input_cut_digest: str

    def __post_init__(self) -> None:
        _require_instance(
            self.reference,
            DatasetInputCutDefinition,
            "input cut reference",
        )
        _require_instance(
            self.target,
            DatasetInputCutDefinition,
            "input cut target",
        )
        if self.reference.direction is not PlanDirection.REFERENCE:
            raise AcquisitionValidationError("input cut reference direction must be reference")
        if self.target.direction is not PlanDirection.TARGET:
            raise AcquisitionValidationError("input cut target direction must be target")
        if self.reference.dataset_id == self.target.dataset_id:
            raise AcquisitionValidationError(
                "input cut reference and target dataset ids must differ"
            )
        if self.reference.scope_digest != self.target.scope_digest:
            raise AcquisitionValidationError(
                "input cut reference and target must bind the same scope digest"
            )
        reference_fields = tuple(value.field for value in self.reference.alignment_values)
        target_fields = tuple(value.field for value in self.target.alignment_values)
        if reference_fields != target_fields:
            raise AcquisitionValidationError(
                "input cut reference and target must use identical ordered alignment fields"
            )
        _require_instance(
            self.late_arrivals,
            LateArrivalPolicy,
            "input cut late-arrival policy",
        )
        _require_sha256(self.input_cut_digest, "input cut digest")
        expected_digest = semantic_digest_hex(
            _input_cut_semantics(self.reference, self.target, self.late_arrivals)
        )
        if self.input_cut_digest != expected_digest:
            raise AcquisitionValidationError(
                "input cut digest does not match its full canonical payload"
            )


@final
@dataclass(frozen=True, slots=True)
class ExpectedBatchDefinition:
    direction: PlanDirection
    dataset_id: str
    batch_id: str

    def __post_init__(self) -> None:
        _require_instance(self.direction, PlanDirection, "expected batch direction")
        _require_nonblank_text(self.dataset_id, "expected batch dataset id")
        _require_nonblank_text(self.batch_id, "expected batch id")


@final
@dataclass(frozen=True, slots=True)
class RunRequestDefinition:
    request_id: UUID
    contract_version_id: UUID
    origin: str
    scope: ResolvedScope
    expected_batches: tuple[ExpectedBatchDefinition, ...]
    execution_policy: ExecutionBudgets
    evidence_policy: EvidenceDefinition
    request_identity_digest: str

    def __post_init__(self) -> None:
        _require_uuid(self.request_id, "run request id")
        _require_uuid(self.contract_version_id, "run request contract version id")
        _require_nonblank_text(self.origin, "run request origin")
        _require_instance(self.scope, ResolvedScope, "run request scope")
        if type(self.expected_batches) is not tuple or len(self.expected_batches) != 2:
            raise AcquisitionValidationError(
                "run request expected batches must be an immutable reference/target pair"
            )
        for index, expected in enumerate(self.expected_batches):
            _require_instance(
                expected,
                ExpectedBatchDefinition,
                f"run request expected batch at index {index}",
            )
        if tuple(item.direction for item in self.expected_batches) != (
            PlanDirection.REFERENCE,
            PlanDirection.TARGET,
        ):
            raise AcquisitionValidationError(
                "run request expected batches must be ordered reference then target"
            )
        if self.expected_batches[0].dataset_id == self.expected_batches[1].dataset_id:
            raise AcquisitionValidationError(
                "run request reference and target dataset ids must differ"
            )
        _require_instance(
            self.execution_policy,
            ExecutionBudgets,
            "run request execution policy",
        )
        _require_instance(
            self.evidence_policy,
            EvidenceDefinition,
            "run request evidence policy",
        )
        _require_sha256(self.request_identity_digest, "run request identity digest")
        expected_digest = semantic_digest_hex(
            _run_request_semantics(
                self.contract_version_id,
                self.origin,
                self.scope,
                self.expected_batches,
                self.execution_policy,
                self.evidence_policy,
            )
        )
        if self.request_identity_digest != expected_digest:
            raise AcquisitionValidationError(
                "run request identity digest does not match its full canonical payload"
            )


@final
@dataclass(frozen=True, slots=True)
class ArtifactCaptureSelection:
    direction: PlanDirection
    purpose: ArtifactPurpose
    dataset_id: str
    code_artifact_id: UUID

    def __post_init__(self) -> None:
        _require_instance(self.direction, PlanDirection, "artifact capture direction")
        _require_instance(self.purpose, ArtifactPurpose, "artifact capture purpose")
        _require_nonblank_text(self.dataset_id, "artifact capture dataset id")
        _require_uuid(self.code_artifact_id, "artifact capture id")


@final
@dataclass(frozen=True, slots=True)
class ArtifactSelection:
    check_id: str
    revision: int
    contract_digest: str
    captures: tuple[ArtifactCaptureSelection, ...]

    def __post_init__(self) -> None:
        _require_nonblank_text(self.check_id, "artifact selection check id")
        if type(self.revision) is not int or self.revision < 1:
            raise AcquisitionValidationError(
                "artifact selection revision must be a positive exact integer"
            )
        _require_sha256(self.contract_digest, "artifact selection contract digest")
        if type(self.captures) is not tuple:
            raise AcquisitionValidationError("artifact captures must be an immutable tuple")
        identities: list[tuple[PlanDirection, ArtifactPurpose, str]] = []
        identifiers: list[UUID] = []
        for index, capture in enumerate(self.captures):
            _require_instance(
                capture,
                ArtifactCaptureSelection,
                f"artifact capture at index {index}",
            )
            identities.append((capture.direction, capture.purpose, capture.dataset_id))
            identifiers.append(capture.code_artifact_id)
        if len(set(identities)) != len(identities):
            raise AcquisitionValidationError(
                "artifact selection must contain at most one capture per artifact use"
            )
        if len(set(identifiers)) != len(identifiers):
            raise AcquisitionValidationError("artifact selection capture ids must be unique")


@final
@dataclass(frozen=True, slots=True)
class EarlyExecutionOutcome:
    execution_status: ExecutionStatus
    reason: ResultReason

    def __post_init__(self) -> None:
        _require_instance(self.reason, ResultReason, "early acquisition outcome reason")
        if self.execution_status is ExecutionStatus.INCOMPLETE:
            if self.reason.code not in {ReasonCode.CUT_MISMATCH, ReasonCode.NOT_READY}:
                raise AcquisitionValidationError(
                    "incomplete acquisition outcome requires cut_mismatch or not_ready"
                )
            return
        if self.execution_status is ExecutionStatus.ERROR:
            if self.reason.code is not ReasonCode.UNSUPPORTED_CAPABILITY:
                raise AcquisitionValidationError(
                    "error acquisition outcome requires unsupported_capability"
                )
            return
        raise AcquisitionValidationError("early acquisition outcome must be incomplete or error")


def canonical_value(
    field: FieldSchema,
    value: CanonicalInput,
) -> CanonicalValueDefinition:
    _require_instance(field, FieldSchema, "canonical field")
    try:
        payload = encode_payload(field, value)
    except PayloadValidationError as error:
        raise AcquisitionValidationError(
            f"canonical field {field.name!r} value is invalid for logical type "
            f"{field.logical_type.value!r}: {error}"
        ) from None
    return CanonicalValueDefinition(field=field, canonical_payload=payload)


def canonical_alignment_value(
    field: FieldSchema,
    value: CanonicalInput,
) -> CanonicalValueDefinition:
    return canonical_value(field, value)


def validate_relation_manifest_readiness(
    direction: PlanDirection,
    rows: tuple[RelationManifestRow, ...],
    expected_dataset_id: str,
    expected_scope_digest: str,
    expected_batch_id: str,
    alignment_fields: tuple[str, ...],
    minimum_evidence: MinimumEvidence,
    late_arrivals: LateArrivalPolicy,
) -> RelationManifestEvidence | EarlyExecutionOutcome:
    _require_instance(direction, PlanDirection, "readiness direction")
    if type(rows) is not tuple:
        raise AcquisitionValidationError("readiness rows must be an immutable tuple")
    normalized_rows: list[RelationManifestRecord] = []
    for index, row in enumerate(rows):
        typed_row = _require_instance(
            row,
            RelationManifestRow,
            f"readiness row at index {index}",
        )
        normalized_rows.append(_copy_relation_manifest_row(typed_row))
    _require_nonblank_text(expected_dataset_id, "expected readiness dataset id")
    _require_sha256(expected_scope_digest, "expected readiness scope digest")
    _require_nonblank_text(expected_batch_id, "expected readiness batch id")
    _validate_alignment_fields(alignment_fields)
    _require_instance(
        minimum_evidence,
        MinimumEvidence,
        "minimum readiness evidence",
    )
    _require_instance(
        late_arrivals,
        LateArrivalPolicy,
        "readiness late-arrival policy",
    )
    if len(normalized_rows) != 1:
        return _not_ready_outcome(
            "readiness manifest must return exactly one current record",
            direction,
            expected_dataset_id,
        )
    row = normalized_rows[0]
    if row.dataset_id != expected_dataset_id:
        raise AcquisitionValidationError(
            "readiness manifest record dataset_id does not match the bound dataset identity"
        )
    if row.scope_digest != expected_scope_digest:
        raise AcquisitionValidationError(
            "readiness manifest record scope_digest does not match the bound scope identity"
        )
    if row.batch_id != expected_batch_id:
        return _not_ready_outcome(
            "readiness manifest record does not match the expected batch",
            direction,
            expected_dataset_id,
        )
    if isinstance(row, BuildingReadinessRecord):
        return _not_ready_outcome(
            "readiness manifest record is not complete",
            direction,
            expected_dataset_id,
        )
    cut = DatasetInputCutDefinition(
        direction=direction,
        dataset_id=row.dataset_id,
        scope_digest=row.scope_digest,
        batch_id=canonical_value(_BATCH_ID_FIELD, row.batch_id),
        business_date=canonical_value(_BUSINESS_DATE_FIELD, row.business_date),
        source_cut=canonical_value(_SOURCE_CUT_FIELD, row.source_cut),
        dataset_version=canonical_value(_DATASET_VERSION_FIELD, row.dataset_version),
        completed_at=canonical_value(_COMPLETED_AT_FIELD, row.completed_at),
        alignment_values=_alignment_values(row, alignment_fields),
    )
    return RelationManifestEvidence(
        provider_kind=ReadinessProviderKind.RELATION_MANIFEST,
        evidence_level=ConsistencyLevel.VERIFIED,
        state=row.state,
        late_arrivals=late_arrivals,
        cut=cut,
    )


def readiness_evidence_semantic_value(
    evidence: RelationManifestEvidence,
) -> dict[str, SemanticValue]:
    _require_instance(evidence, RelationManifestEvidence, "readiness evidence")
    cut = evidence.cut
    return {
        "alignment_values": [_canonical_value_semantics(value) for value in cut.alignment_values],
        "batch_id": _canonical_value_semantics(cut.batch_id),
        "business_date": _canonical_value_semantics(cut.business_date),
        "completed_at": _canonical_value_semantics(cut.completed_at),
        "dataset_version": _canonical_value_semantics(cut.dataset_version),
        "evidence_version": 1,
        "kind": evidence.provider_kind.value,
        "late_arrivals": evidence.late_arrivals.value,
        "scope_digest": cut.scope_digest,
        "source_cut": _canonical_value_semantics(cut.source_cut),
        "state": evidence.state,
    }


def build_input_cut_definition(
    reference: RelationManifestEvidence,
    target: RelationManifestEvidence,
) -> InputCutDefinition:
    _require_instance(reference, RelationManifestEvidence, "reference readiness evidence")
    _require_instance(target, RelationManifestEvidence, "target readiness evidence")
    if reference.late_arrivals is not target.late_arrivals:
        raise AcquisitionValidationError(
            "reference and target readiness evidence must use the same late-arrival policy"
        )
    metadata = _input_cut_semantics(reference.cut, target.cut, reference.late_arrivals)
    return InputCutDefinition(
        reference=reference.cut,
        target=target.cut,
        late_arrivals=reference.late_arrivals,
        input_cut_digest=semantic_digest_hex(metadata),
    )


def input_cut_semantic_value(input_cut: InputCutDefinition) -> dict[str, SemanticValue]:
    _require_instance(input_cut, InputCutDefinition, "input cut")
    return _input_cut_semantics(
        input_cut.reference,
        input_cut.target,
        input_cut.late_arrivals,
    )


def classify_input_cut_alignment(
    input_cut: InputCutDefinition,
) -> EarlyExecutionOutcome | None:
    _require_instance(input_cut, InputCutDefinition, "input cut")
    reference_payloads = tuple(
        value.canonical_payload for value in input_cut.reference.alignment_values
    )
    target_payloads = tuple(value.canonical_payload for value in input_cut.target.alignment_values)
    if reference_payloads == target_payloads:
        return None
    return _cut_mismatch_outcome(
        AcquisitionOperation.ALIGN_INPUT_CUT,
        "reference and target readiness cuts do not align",
    )


def classify_bound_input_cut(
    bound: InputCutDefinition,
    observed: InputCutDefinition,
) -> EarlyExecutionOutcome | None:
    _require_instance(bound, InputCutDefinition, "bound input cut")
    _require_instance(observed, InputCutDefinition, "observed input cut")
    if input_cut_semantic_value(bound) == input_cut_semantic_value(observed):
        return None
    return _cut_mismatch_outcome(
        AcquisitionOperation.VALIDATE_BOUND_INPUT_CUT,
        "observed readiness cut differs from the cut already bound to the run",
    )


def build_run_request_definition(
    request_id: UUID,
    contract_version_id: UUID,
    origin: str,
    check: RowCheckDefinition,
    scope: ResolvedScope,
    reference_expected_batch_id: str,
    target_expected_batch_id: str,
    execution_policy: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
) -> RunRequestDefinition:
    _require_uuid(request_id, "run request id")
    _require_uuid(contract_version_id, "run request contract version id")
    _require_nonblank_text(origin, "run request origin")
    _require_instance(check, RowCheckDefinition, "run request check")
    _require_instance(scope, ResolvedScope, "run request scope")
    _require_instance(execution_policy, ExecutionBudgets, "run request execution policy")
    _require_instance(evidence_policy, EvidenceDefinition, "run request evidence policy")
    expected_scope_fields = tuple(
        (parameter.name, parameter.field) for parameter in check.scope.parameters
    )
    actual_scope_fields = tuple((parameter.name, parameter.field) for parameter in scope.parameters)
    if actual_scope_fields != expected_scope_fields:
        raise AcquisitionValidationError(
            "run request resolved scope is outside the requested check closure"
        )
    expected_batches = (
        ExpectedBatchDefinition(
            direction=PlanDirection.REFERENCE,
            dataset_id=check.reference.dataset_id,
            batch_id=reference_expected_batch_id,
        ),
        ExpectedBatchDefinition(
            direction=PlanDirection.TARGET,
            dataset_id=check.target.dataset_id,
            batch_id=target_expected_batch_id,
        ),
    )
    metadata = _run_request_semantics(
        contract_version_id,
        origin,
        scope,
        expected_batches,
        execution_policy,
        evidence_policy,
    )
    return RunRequestDefinition(
        request_id=request_id,
        contract_version_id=contract_version_id,
        origin=origin,
        scope=scope,
        expected_batches=expected_batches,
        execution_policy=execution_policy,
        evidence_policy=evidence_policy,
        request_identity_digest=semantic_digest_hex(metadata),
    )


def run_request_semantic_value(
    request: RunRequestDefinition,
) -> dict[str, SemanticValue]:
    _require_instance(request, RunRequestDefinition, "run request")
    return _run_request_semantics(
        request.contract_version_id,
        request.origin,
        request.scope,
        request.expected_batches,
        request.execution_policy,
        request.evidence_policy,
    )


def artifact_selection_for_check(
    check: RowCheckDefinition,
    captures: tuple[ArtifactCaptureSelection, ...],
) -> ArtifactSelection:
    _require_instance(check, RowCheckDefinition, "artifact selection check")
    selection = ArtifactSelection(
        check_id=check.check_id,
        revision=check.revision,
        contract_digest=check.contract_digest,
        captures=captures,
    )
    validate_artifact_selection(check, selection)
    return selection


def validate_artifact_selection(
    check: RowCheckDefinition,
    selection: ArtifactSelection,
) -> None:
    _require_instance(check, RowCheckDefinition, "artifact selection check")
    _require_instance(selection, ArtifactSelection, "artifact selection")
    if (
        selection.check_id != check.check_id
        or selection.revision != check.revision
        or selection.contract_digest != check.contract_digest
    ):
        raise AcquisitionValidationError(
            "artifact selection check identity is outside the requested contract closure"
        )
    actual = tuple(
        (capture.direction, capture.purpose, capture.dataset_id) for capture in selection.captures
    )
    expected = _expected_artifact_uses(check)
    if actual != expected:
        raise AcquisitionValidationError(
            "artifact selection must contain the exact ordered SQL artifact closure"
        )


def classify_dataset_acquisition(
    direction: PlanDirection,
    dataset: DatasetDefinition,
) -> EarlyExecutionOutcome | None:
    _require_instance(direction, PlanDirection, "dataset acquisition direction")
    _require_instance(dataset, DatasetDefinition, "dataset acquisition definition")
    if isinstance(dataset.locator, RelationLocator):
        if dataset.locator.relation_scope is not RelationScope.PHYSICAL_ONLY:
            raise AcquisitionValidationError(
                "relation dataset acquisition requires physical_only scope"
            )
        return None
    return _unsupported_capability_outcome(
        AcquisitionOperation.RESOLVE_DATASET_DEPENDENCIES,
        "opaque SQL dataset dependencies cannot be protected before the read snapshot",
        direction,
        dataset.dataset_id,
    )


def classify_readiness_acquisition(
    direction: PlanDirection,
    dataset_id: str,
    readiness: ReadinessDefinition,
) -> EarlyExecutionOutcome | None:
    _require_instance(direction, PlanDirection, "readiness acquisition direction")
    _require_nonblank_text(dataset_id, "readiness dataset id")
    _require_readiness_definition(readiness)
    if isinstance(readiness, RelationManifestReadiness):
        if readiness.relation.relation_scope is not RelationScope.PHYSICAL_ONLY:
            raise AcquisitionValidationError(
                "relation manifest readiness requires physical_only scope"
            )
        return None
    return _unsupported_capability_outcome(
        AcquisitionOperation.RESOLVE_READINESS_DEPENDENCIES,
        "opaque SQL readiness dependencies cannot be protected before the read snapshot",
        direction,
        dataset_id,
    )


def classify_check_acquisition(
    check: RowCheckDefinition,
) -> EarlyExecutionOutcome | None:
    _require_instance(check, RowCheckDefinition, "acquisition check")
    datasets = (
        (PlanDirection.REFERENCE, check.reference),
        (PlanDirection.TARGET, check.target),
    )
    for direction, dataset in datasets:
        outcome = classify_dataset_acquisition(direction, dataset)
        if outcome is not None:
            return outcome
    relation_manifest_datasets = tuple(
        (direction, consistency_dataset.dataset_id)
        for direction, consistency_dataset in zip(
            (PlanDirection.REFERENCE, PlanDirection.TARGET),
            check.consistency.datasets,
            strict=True,
        )
        if isinstance(consistency_dataset.readiness, RelationManifestReadiness)
    )
    unsupported_alignment_fields = tuple(
        field_name
        for field_name in check.consistency.alignment_fields
        if field_name not in _ALIGNMENT_FIELDS
    )
    if relation_manifest_datasets and unsupported_alignment_fields:
        direction, dataset_id = relation_manifest_datasets[0]
        return _unsupported_capability_outcome(
            AcquisitionOperation.VALIDATE_ALIGNMENT_FIELDS,
            "relation manifest runtime supports only business_date and source_cut alignment fields",
            direction,
            dataset_id,
        )
    for (direction, dataset), consistency_dataset in zip(
        datasets,
        check.consistency.datasets,
        strict=True,
    ):
        if consistency_dataset.dataset_id != dataset.dataset_id:
            raise AcquisitionValidationError(
                "consistency readiness dataset is outside the check direction closure"
            )
        readiness = consistency_dataset.readiness
        if (
            isinstance(readiness, RelationManifestReadiness)
            and readiness.connection_id != dataset.connection.connection_id
        ):
            raise AcquisitionValidationError(
                "relation manifest readiness must use its dataset connection"
            )
        outcome = classify_readiness_acquisition(
            direction,
            consistency_dataset.dataset_id,
            readiness,
        )
        if outcome is not None:
            return outcome
    return None


def _copy_relation_manifest_row(row: RelationManifestRow) -> RelationManifestRecord:
    if row.state == "building":
        return BuildingReadinessRecord(
            dataset_id=row.dataset_id,
            scope_digest=row.scope_digest,
            batch_id=row.batch_id,
            state=row.state,
            business_date=row.business_date,
            source_cut=row.source_cut,
            dataset_version=row.dataset_version,
            completed_at=row.completed_at,
        )
    if row.state != "complete":
        raise AcquisitionValidationError("readiness state must be exactly 'building' or 'complete'")
    if row.source_cut is None:
        raise AcquisitionValidationError("complete readiness source_cut must be non-null text")
    if row.dataset_version is None:
        raise AcquisitionValidationError("complete readiness dataset_version must be non-null text")
    if row.completed_at is None:
        raise AcquisitionValidationError(
            "complete readiness completed_at must be non-null timestamptz"
        )
    return CompleteReadinessRecord(
        dataset_id=row.dataset_id,
        scope_digest=row.scope_digest,
        batch_id=row.batch_id,
        state=row.state,
        business_date=row.business_date,
        source_cut=row.source_cut,
        dataset_version=row.dataset_version,
        completed_at=row.completed_at,
    )


def _alignment_values(
    row: CompleteReadinessRecord,
    alignment_fields: tuple[str, ...],
) -> tuple[CanonicalValueDefinition, ...]:
    values: list[CanonicalValueDefinition] = []
    for field_name in alignment_fields:
        if field_name == _BUSINESS_DATE_FIELD.name:
            values.append(canonical_value(_BUSINESS_DATE_FIELD, row.business_date))
        elif field_name == _SOURCE_CUT_FIELD.name:
            values.append(canonical_value(_SOURCE_CUT_FIELD, row.source_cut))
        else:
            raise AssertionError("validated alignment field is unsupported")
    return tuple(values)


def _validate_alignment_fields(alignment_fields: tuple[str, ...]) -> None:
    if type(alignment_fields) is not tuple or not alignment_fields:
        raise AcquisitionValidationError(
            "readiness alignment fields must be a nonempty immutable tuple"
        )
    for index, field_name in enumerate(alignment_fields):
        if type(field_name) is not str or field_name not in _ALIGNMENT_FIELDS:
            raise AcquisitionValidationError(
                f"readiness alignment field at index {index} is unsupported; "
                "expected business_date or source_cut"
            )
    if len(set(alignment_fields)) != len(alignment_fields):
        raise AcquisitionValidationError("readiness alignment field names must be unique")


def _input_cut_semantics(
    reference: DatasetInputCutDefinition,
    target: DatasetInputCutDefinition,
    late_arrivals: LateArrivalPolicy,
) -> dict[str, SemanticValue]:
    return {
        "canonical_protocol": PROTOCOL,
        "datasets": [
            _dataset_input_cut_semantics(reference),
            _dataset_input_cut_semantics(target),
        ],
        "input_cut_version": 1,
        "late_arrivals": late_arrivals.value,
        "scope_digest": reference.scope_digest,
    }


def _dataset_input_cut_semantics(
    dataset_cut: DatasetInputCutDefinition,
) -> dict[str, SemanticValue]:
    return {
        "alignment_values": [
            _canonical_value_semantics(value) for value in dataset_cut.alignment_values
        ],
        "batch_id": _canonical_value_semantics(dataset_cut.batch_id),
        "business_date": _canonical_value_semantics(dataset_cut.business_date),
        "completed_at": _canonical_value_semantics(dataset_cut.completed_at),
        "dataset_id": dataset_cut.dataset_id,
        "dataset_version": _canonical_value_semantics(dataset_cut.dataset_version),
        "direction": dataset_cut.direction.value,
        "source_cut": _canonical_value_semantics(dataset_cut.source_cut),
    }


def _canonical_value_semantics(
    value: CanonicalValueDefinition,
) -> dict[str, SemanticValue]:
    return {
        "name": value.field.name,
        "payload_hex": value.canonical_payload.hex(),
        "type": _field_type_semantics(value.field),
    }


def _run_request_semantics(
    contract_version_id: UUID,
    origin: str,
    scope: ResolvedScope,
    expected_batches: tuple[ExpectedBatchDefinition, ...],
    execution_policy: ExecutionBudgets,
    evidence_policy: EvidenceDefinition,
) -> dict[str, SemanticValue]:
    return {
        "contract_version_id": str(contract_version_id),
        "evidence_policy": _evidence_policy_semantics(evidence_policy),
        "execution_policy": _execution_policy_semantics(execution_policy),
        "expected_batches": [
            {
                "batch_id": expected.batch_id,
                "dataset_id": expected.dataset_id,
                "direction": expected.direction.value,
            }
            for expected in expected_batches
        ],
        "origin": origin,
        "request_version": 1,
        "scope": resolved_scope_semantic_value(scope),
    }


def _execution_policy_semantics(
    policy: ExecutionBudgets,
) -> dict[str, SemanticValue]:
    return {
        "max_application_result_bytes": policy.max_application_result_bytes,
        "max_attempts": policy.max_attempts,
        "max_checks_concurrency": policy.max_checks_concurrency,
        "max_coordinator_memory_bytes": policy.max_coordinator_memory_bytes,
        "max_depth": policy.max_depth,
        "max_evidence_bytes": policy.max_evidence_bytes,
        "max_evidence_rows": policy.max_evidence_rows,
        "max_fetched_records": policy.max_fetched_records,
        "max_fingerprint_nodes": policy.max_fingerprint_nodes,
        "max_full_scans_per_side": policy.max_full_scans_per_side,
        "max_queries": policy.max_queries,
        "max_source_concurrency": policy.max_source_concurrency,
        "run_timeout_milliseconds": policy.run_timeout_milliseconds,
        "statement_timeout_milliseconds": policy.statement_timeout_milliseconds,
        "version": policy.version,
    }


def _evidence_policy_semantics(
    policy: EvidenceDefinition,
) -> dict[str, SemanticValue]:
    return {
        "ddl_capture": policy.ddl_capture.value,
        "field_rules": [
            {"action": field.action.value, "field_name": field.field_name}
            for field in policy.fields
        ],
        "sql_capture": policy.sql_capture.value,
        "unspecified_fields": policy.unspecified_fields.value,
    }


def _expected_artifact_uses(
    check: RowCheckDefinition,
) -> tuple[tuple[PlanDirection, ArtifactPurpose, str], ...]:
    expected: list[tuple[PlanDirection, ArtifactPurpose, str]] = []
    for direction, dataset in (
        (PlanDirection.REFERENCE, check.reference),
        (PlanDirection.TARGET, check.target),
    ):
        if isinstance(dataset.locator, SqlArtifactDefinition):
            expected.append((direction, ArtifactPurpose.PROJECTION, dataset.dataset_id))
    for direction, readiness in zip(
        (PlanDirection.REFERENCE, PlanDirection.TARGET),
        check.consistency.datasets,
        strict=True,
    ):
        if isinstance(readiness.readiness, SqlArtifactDefinition):
            expected.append((direction, ArtifactPurpose.READINESS, readiness.dataset_id))
    return tuple(expected)


def _not_ready_outcome(
    message: str,
    direction: PlanDirection,
    dataset_id: str,
) -> EarlyExecutionOutcome:
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.INCOMPLETE,
        reason=ResultReason(
            code=ReasonCode.NOT_READY,
            operation=AcquisitionOperation.VALIDATE_READINESS.value,
            message=message,
            safe_parameters=(
                SafeParameter(name="direction", value=direction.value),
                SafeParameter(name="dataset_id", value=dataset_id),
            ),
            native_error_code=None,
            query_id=None,
            redacted_response=None,
        ),
    )


def _cut_mismatch_outcome(
    operation: AcquisitionOperation,
    message: str,
) -> EarlyExecutionOutcome:
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.INCOMPLETE,
        reason=ResultReason(
            code=ReasonCode.CUT_MISMATCH,
            operation=operation.value,
            message=message,
            safe_parameters=(),
            native_error_code=None,
            query_id=None,
            redacted_response=None,
        ),
    )


def _unsupported_capability_outcome(
    operation: AcquisitionOperation,
    message: str,
    direction: PlanDirection,
    dataset_id: str,
) -> EarlyExecutionOutcome:
    return EarlyExecutionOutcome(
        execution_status=ExecutionStatus.ERROR,
        reason=ResultReason(
            code=ReasonCode.UNSUPPORTED_CAPABILITY,
            operation=operation.value,
            message=message,
            safe_parameters=(
                SafeParameter(name="direction", value=direction.value),
                SafeParameter(name="dataset_id", value=dataset_id),
            ),
            native_error_code=None,
            query_id=None,
            redacted_response=None,
        ),
    )


def _field_type_semantics(field: FieldSchema) -> dict[str, SemanticValue]:
    parameters: dict[str, SemanticValue]
    if isinstance(field.parameters, DecimalParameters):
        parameters = {
            "precision": field.parameters.precision,
            "scale": field.parameters.scale,
        }
    elif isinstance(field.parameters, TimestampParameters):
        parameters = {"precision": field.parameters.precision}
    else:
        parameters = {}
    return {
        "kind": field.logical_type.value,
        "normalization": field.normalization.value,
        "parameters": parameters,
    }


def _require_fixed_canonical_value(
    value: object,
    expected_field: FieldSchema,
    context: str,
) -> None:
    if not isinstance(value, CanonicalValueDefinition):
        raise AcquisitionValidationError(f"{context} must be a CanonicalValueDefinition")
    if value.field != expected_field:
        raise AcquisitionValidationError(
            f"{context} must use canonical field {expected_field.name!r}"
        )


def _require_canonical_nonblank_string(
    value: CanonicalValueDefinition,
    context: str,
) -> None:
    decoded = decode_payload(value.field, value.canonical_payload)
    _require_nonblank_text(decoded, context)


def _validate_manifest_identity(
    dataset_id: object,
    scope_digest: object,
    batch_id: object,
    business_date: object,
) -> None:
    _require_nonblank_text(dataset_id, "readiness dataset id")
    _require_sha256(scope_digest, "readiness scope digest")
    _require_nonblank_text(batch_id, "readiness batch id")
    if type(business_date) is not date:
        raise AcquisitionValidationError("readiness business_date must be an exact date")


def _require_optional_nonblank_text(value: object, context: str) -> None:
    if value is not None:
        _require_nonblank_text(value, context)


def _require_optional_utc_datetime(value: object, context: str) -> None:
    if value is None:
        return
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise AcquisitionValidationError(f"{context} must be NULL or an exact UTC datetime")


def _require_nonblank_text(value: object, context: str) -> None:
    if type(value) is not str or value.strip() == "":
        raise AcquisitionValidationError(f"{context} must be nonblank text")
    for index, character in enumerate(value):
        code_point = ord(character)
        if code_point == 0 or 0xD800 <= code_point <= 0xDFFF:
            raise AcquisitionValidationError(
                f"{context} contains a forbidden code point at character {index}"
            )


def _require_sha256(value: object, context: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AcquisitionValidationError(
            f"{context} must be a lowercase hexadecimal SHA-256 digest"
        )


def _require_uuid(value: object, context: str) -> None:
    if type(value) is not UUID:
        raise AcquisitionValidationError(f"{context} must be an exact UUID")


def _require_readiness_definition(value: object) -> None:
    if not isinstance(value, (SqlArtifactDefinition, RelationManifestReadiness)):
        raise AcquisitionValidationError(
            "readiness acquisition definition must be a SQL artifact or relation manifest"
        )


def _require_instance[T](value: object, expected_type: type[T], context: str) -> T:
    if not isinstance(value, expected_type):
        raise AcquisitionValidationError(f"{context} must be a {expected_type.__name__}")
    return value
