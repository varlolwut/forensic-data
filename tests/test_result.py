from collections.abc import Callable
from uuid import UUID

import pytest
from pydantic import TypeAdapter, ValidationError

from forensic_data.result import (
    ComparisonCoverage,
    ComparisonTotals,
    ConsistencyLevel,
    ConsistencyStatus,
    EvidenceCoverage,
    ExactTotal,
    ExecutionStatus,
    ExitCode,
    Guarantee,
    InferredTotal,
    LowerBoundTotal,
    PersistenceState,
    PersistenceStatus,
    ReasonCode,
    ResultMetrics,
    ResultReason,
    RunResult,
    Total,
    UnavailableTotal,
    Verdict,
    exit_code_for_result,
)

RUN_ID = UUID("2fa76f28-4bb3-4ede-8b84-4ec3a89b4b7a")
ATTEMPT_ID = UUID("12f84f3a-9e7d-49a2-9f1f-403d3f889e75")
PERSISTENCE_OPERATION_ID = UUID("991b9e84-ff47-4683-9f23-aa7673d024fd")
READ_CONTEXT_ID = UUID("7bfdb32f-6f61-4262-bcd3-43839d01f340")
DIGEST = "0123456789abcdef" * 4
TOTAL_ADAPTER = TypeAdapter[Total](Total)

EXACT_TOTALS = ComparisonTotals(
    matched=ExactTotal(precision="exact", value="4"),
    missing=ExactTotal(precision="exact", value="0"),
    extra=ExactTotal(precision="exact", value="0"),
    modified=ExactTotal(precision="exact", value="0"),
)
EXACT_MISMATCH_TOTALS = ComparisonTotals(
    matched=ExactTotal(precision="exact", value="3"),
    missing=ExactTotal(precision="exact", value="0"),
    extra=ExactTotal(precision="exact", value="0"),
    modified=ExactTotal(precision="exact", value="1"),
)
PARTIAL_MISMATCH_TOTALS = ComparisonTotals(
    matched=UnavailableTotal(
        precision="unavailable",
        value=None,
        reason=ReasonCode.BUDGET_EXHAUSTED,
    ),
    missing=LowerBoundTotal(precision="lower_bound", value="0"),
    extra=LowerBoundTotal(precision="lower_bound", value="0"),
    modified=LowerBoundTotal(precision="lower_bound", value="1"),
)
UNAVAILABLE_CONTRACT_TOTALS = ComparisonTotals(
    matched=UnavailableTotal(
        precision="unavailable",
        value=None,
        reason=ReasonCode.CONTRACT_VIOLATION,
    ),
    missing=UnavailableTotal(
        precision="unavailable",
        value=None,
        reason=ReasonCode.CONTRACT_VIOLATION,
    ),
    extra=UnavailableTotal(
        precision="unavailable",
        value=None,
        reason=ReasonCode.CONTRACT_VIOLATION,
    ),
    modified=UnavailableTotal(
        precision="unavailable",
        value=None,
        reason=ReasonCode.CONTRACT_VIOLATION,
    ),
)
RESOLVED_COVERAGE = ComparisonCoverage(
    total_partitions=1,
    covered_partitions=1,
    resolved_segments=1,
    pruned_segments=0,
    exact_segments=1,
    unresolved_segments=0,
    unresolved_reasons=(),
)
NOT_READY_COVERAGE = ComparisonCoverage(
    total_partitions=1,
    covered_partitions=0,
    resolved_segments=0,
    pruned_segments=0,
    exact_segments=0,
    unresolved_segments=0,
    unresolved_reasons=(),
)
QUERY_ERROR_COVERAGE = ComparisonCoverage(
    total_partitions=1,
    covered_partitions=0,
    resolved_segments=0,
    pruned_segments=0,
    exact_segments=0,
    unresolved_segments=1,
    unresolved_reasons=(ReasonCode.QUERY_ERROR,),
)
PARTIAL_MISMATCH_COVERAGE = ComparisonCoverage(
    total_partitions=3,
    covered_partitions=1,
    resolved_segments=2,
    pruned_segments=1,
    exact_segments=1,
    unresolved_segments=1,
    unresolved_reasons=(ReasonCode.BUDGET_EXHAUSTED,),
)
EMPTY_EVIDENCE_COVERAGE = EvidenceCoverage(
    found_records=0,
    retained_records=0,
    found_bytes=0,
    retained_bytes=0,
)
CONFIRMED_PERSISTENCE = PersistenceStatus(
    state=PersistenceState.CONFIRMED,
    operation_id=PERSISTENCE_OPERATION_ID,
    reason=None,
)
NO_PERSISTENCE = PersistenceStatus(
    state=PersistenceState.NOT_ATTEMPTED,
    operation_id=None,
    reason=None,
)
VERIFIED_CONSISTENCY = ConsistencyStatus(
    stable_reads=ConsistencyLevel.VERIFIED,
    cut_alignment=ConsistencyLevel.VERIFIED,
    read_context_ids=(READ_CONTEXT_ID,),
)
UNKNOWN_CONSISTENCY = ConsistencyStatus(
    stable_reads=ConsistencyLevel.UNKNOWN,
    cut_alignment=ConsistencyLevel.UNKNOWN,
    read_context_ids=(),
)
EMPTY_METRICS = ResultMetrics(
    queries=0,
    fetched_records=0,
    result_bytes=0,
    fingerprint_nodes=0,
    coordinator_peak_bytes=0,
    elapsed_milliseconds=0,
)


def _reason(code: ReasonCode) -> ResultReason:
    return ResultReason(
        code=code,
        operation="compare",
        message=f"Result reason: {code.value}",
        safe_parameters=(),
        native_error_code=None,
        query_id=None,
        redacted_response=None,
    )


def _unavailable_totals(reason: ReasonCode) -> ComparisonTotals:
    total = UnavailableTotal(precision="unavailable", value=None, reason=reason)
    return ComparisonTotals(matched=total, missing=total, extra=total, modified=total)


def _result(
    execution_status: ExecutionStatus,
    verdict: Verdict,
    reasons: tuple[ResultReason, ...],
    persistence: PersistenceStatus,
    consistency: ConsistencyStatus,
    guarantee: Guarantee,
    coverage: ComparisonCoverage,
    totals: ComparisonTotals,
) -> RunResult:
    return RunResult(
        schema_version=1,
        run_id=RUN_ID,
        attempt_id=ATTEMPT_ID,
        check_id="orders",
        contract_digest=DIGEST,
        scope_digest=DIGEST,
        execution_status=execution_status,
        verdict=verdict,
        consistency=consistency,
        guarantee=guarantee,
        comparison_coverage=coverage,
        totals=totals,
        evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
        metrics=EMPTY_METRICS,
        reasons=reasons,
        persistence=persistence,
    )


@pytest.mark.parametrize(
    ("payload", "expected_type"),
    [
        ('{"precision":"exact","value":"3"}', ExactTotal),
        ('{"precision":"lower_bound","value":"3"}', LowerBoundTotal),
        (
            '{"precision":"inferred_under_fingerprint","value":"3"}',
            InferredTotal,
        ),
        (
            '{"precision":"unavailable","value":null,"reason":"budget_exhausted"}',
            UnavailableTotal,
        ),
    ],
)
def test_total_variants_validate_from_json(
    payload: str,
    expected_type: type[ExactTotal]
    | type[LowerBoundTotal]
    | type[InferredTotal]
    | type[UnavailableTotal],
) -> None:
    total = TOTAL_ADAPTER.validate_json(payload)

    assert isinstance(total, expected_type)


@pytest.mark.parametrize(
    "payload",
    [
        '{"precision":"exact","value":null}',
        '{"precision":"exact","value":3}',
        '{"precision":"lower_bound","value":true}',
        '{"precision":"lower_bound","value":"03"}',
        '{"precision":"inferred_under_fingerprint","value":"-1"}',
        ('{"precision":"unavailable","value":3,"reason":"budget_exhausted"}'),
    ],
)
def test_total_variants_reject_mixed_or_coerced_states(payload: str) -> None:
    with pytest.raises(ValidationError):
        TOTAL_ADAPTER.validate_json(payload)


def test_protocol_models_are_frozen_and_ignore_external_metadata() -> None:
    total = ExactTotal.model_validate_json(
        '{"precision":"exact","value":"3","server_metadata":"ignored"}'
    )

    assert total == ExactTotal(precision="exact", value="3")
    with pytest.raises(ValidationError):
        total.value = "4"


@pytest.mark.parametrize(
    (
        "execution_status",
        "verdict",
        "reasons",
        "persistence",
        "consistency",
        "guarantee",
        "coverage",
        "totals",
        "expected",
    ),
    [
        (
            ExecutionStatus.COMPLETED,
            Verdict.MATCH,
            (),
            CONFIRMED_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.EXACT,
            RESOLVED_COVERAGE,
            EXACT_TOTALS,
            ExitCode.MATCH,
        ),
        (
            ExecutionStatus.COMPLETED,
            Verdict.MISMATCH,
            (_reason(ReasonCode.DATA_MISMATCH),),
            CONFIRMED_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.EXACT,
            RESOLVED_COVERAGE,
            EXACT_MISMATCH_TOTALS,
            ExitCode.MISMATCH,
        ),
        (
            ExecutionStatus.INCOMPLETE,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.NOT_READY),),
            NO_PERSISTENCE,
            UNKNOWN_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            NOT_READY_COVERAGE,
            _unavailable_totals(ReasonCode.NOT_READY),
            ExitCode.INCOMPLETE,
        ),
        (
            ExecutionStatus.INCOMPLETE,
            Verdict.MISMATCH,
            (
                _reason(ReasonCode.DATA_MISMATCH),
                _reason(ReasonCode.BUDGET_EXHAUSTED),
            ),
            NO_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            PARTIAL_MISMATCH_COVERAGE,
            PARTIAL_MISMATCH_TOTALS,
            ExitCode.INCOMPLETE,
        ),
        (
            ExecutionStatus.ERROR,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.QUERY_ERROR),),
            NO_PERSISTENCE,
            UNKNOWN_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            QUERY_ERROR_COVERAGE,
            _unavailable_totals(ReasonCode.QUERY_ERROR),
            ExitCode.ERROR,
        ),
        (
            ExecutionStatus.ERROR,
            Verdict.MISMATCH,
            (
                _reason(ReasonCode.DATA_MISMATCH),
                _reason(ReasonCode.QUERY_ERROR),
            ),
            NO_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            PARTIAL_MISMATCH_COVERAGE,
            PARTIAL_MISMATCH_TOTALS,
            ExitCode.ERROR,
        ),
    ],
)
def test_exit_code_precedence(
    execution_status: ExecutionStatus,
    verdict: Verdict,
    reasons: tuple[ResultReason, ...],
    persistence: PersistenceStatus,
    consistency: ConsistencyStatus,
    guarantee: Guarantee,
    coverage: ComparisonCoverage,
    totals: ComparisonTotals,
    expected: ExitCode,
) -> None:
    result = _result(
        execution_status,
        verdict,
        reasons,
        persistence,
        consistency,
        guarantee,
        coverage,
        totals,
    )

    assert exit_code_for_result(result) is expected


@pytest.mark.parametrize(
    ("execution_status", "verdict", "reasons", "persistence"),
    [
        (
            ExecutionStatus.COMPLETED,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.DATA_MISMATCH),),
            CONFIRMED_PERSISTENCE,
        ),
        (
            ExecutionStatus.INCOMPLETE,
            Verdict.MATCH,
            (_reason(ReasonCode.NOT_READY),),
            NO_PERSISTENCE,
        ),
        (
            ExecutionStatus.ERROR,
            Verdict.MATCH,
            (_reason(ReasonCode.QUERY_ERROR),),
            NO_PERSISTENCE,
        ),
    ],
)
def test_invalid_status_verdict_combinations_are_rejected(
    execution_status: ExecutionStatus,
    verdict: Verdict,
    reasons: tuple[ResultReason, ...],
    persistence: PersistenceStatus,
) -> None:
    with pytest.raises(ValidationError, match="execution cannot have"):
        _result(
            execution_status,
            verdict,
            reasons,
            persistence,
            VERIFIED_CONSISTENCY,
            Guarantee.EXACT,
            RESOLVED_COVERAGE,
            EXACT_TOTALS,
        )


def test_completed_result_requires_resolved_coverage_and_persistence() -> None:
    unresolved_coverage = ComparisonCoverage(
        total_partitions=1,
        covered_partitions=0,
        resolved_segments=0,
        pruned_segments=0,
        exact_segments=0,
        unresolved_segments=1,
        unresolved_reasons=(ReasonCode.BUDGET_EXHAUSTED,),
    )

    with pytest.raises(ValidationError, match="unresolved segments"):
        RunResult(
            schema_version=1,
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            check_id="orders",
            contract_digest=DIGEST,
            scope_digest=DIGEST,
            execution_status=ExecutionStatus.COMPLETED,
            verdict=Verdict.MATCH,
            consistency=VERIFIED_CONSISTENCY,
            guarantee=Guarantee.EXACT,
            comparison_coverage=unresolved_coverage,
            totals=EXACT_TOTALS,
            evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
            metrics=EMPTY_METRICS,
            reasons=(),
            persistence=CONFIRMED_PERSISTENCE,
        )

    with pytest.raises(ValidationError, match="confirmed persistence"):
        _result(
            ExecutionStatus.COMPLETED,
            Verdict.MATCH,
            (),
            NO_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.EXACT,
            RESOLVED_COVERAGE,
            EXACT_TOTALS,
        )


def test_guarantee_represents_achieved_full_scope() -> None:
    with pytest.raises(ValidationError, match="cannot be completed or match"):
        _result(
            ExecutionStatus.COMPLETED,
            Verdict.MATCH,
            (),
            CONFIRMED_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            RESOLVED_COVERAGE,
            EXACT_TOTALS,
        )

    fully_enumerated_unestablished = _result(
        ExecutionStatus.ERROR,
        Verdict.INCONCLUSIVE,
        (_reason(ReasonCode.QUERY_ERROR),),
        NO_PERSISTENCE,
        UNKNOWN_CONSISTENCY,
        Guarantee.NOT_ESTABLISHED,
        RESOLVED_COVERAGE,
        _unavailable_totals(ReasonCode.QUERY_ERROR),
    )
    assert fully_enumerated_unestablished.guarantee is Guarantee.NOT_ESTABLISHED

    with pytest.raises(ValidationError, match="incomplete execution requires not_established"):
        _result(
            ExecutionStatus.INCOMPLETE,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.BUDGET_EXHAUSTED),),
            NO_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.EXACT,
            RESOLVED_COVERAGE,
            EXACT_TOTALS,
        )

    empty_frontier = ComparisonCoverage(
        total_partitions=0,
        covered_partitions=0,
        resolved_segments=0,
        pruned_segments=0,
        exact_segments=0,
        unresolved_segments=0,
        unresolved_reasons=(),
    )
    with pytest.raises(ValidationError, match="verified root partition"):
        _result(
            ExecutionStatus.ERROR,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.QUERY_ERROR),),
            NO_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.EXACT,
            empty_frontier,
            EXACT_TOTALS,
        )

    omitted_partition_coverage = ComparisonCoverage(
        total_partitions=2,
        covered_partitions=1,
        resolved_segments=1,
        pruned_segments=1,
        exact_segments=0,
        unresolved_segments=0,
        unresolved_reasons=(),
    )
    inferred_totals = ComparisonTotals(
        matched=InferredTotal(precision="inferred_under_fingerprint", value="4"),
        missing=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        extra=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        modified=InferredTotal(precision="inferred_under_fingerprint", value="0"),
    )
    with pytest.raises(ValidationError, match="complete resolved frontier"):
        _result(
            ExecutionStatus.COMPLETED,
            Verdict.MATCH,
            (),
            CONFIRMED_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.FINGERPRINT,
            omitted_partition_coverage,
            inferred_totals,
        )


def test_coverage_rejects_over_retention_and_inconsistent_segments() -> None:
    invalid_coverage_builders: tuple[Callable[[], ComparisonCoverage | EvidenceCoverage], ...] = (
        lambda: ComparisonCoverage(
            total_partitions=1,
            covered_partitions=2,
            resolved_segments=1,
            pruned_segments=0,
            exact_segments=1,
            unresolved_segments=0,
            unresolved_reasons=(),
        ),
        lambda: ComparisonCoverage(
            total_partitions=1,
            covered_partitions=1,
            resolved_segments=0,
            pruned_segments=0,
            exact_segments=0,
            unresolved_segments=0,
            unresolved_reasons=(),
        ),
        lambda: ComparisonCoverage(
            total_partitions=1,
            covered_partitions=1,
            resolved_segments=1,
            pruned_segments=0,
            exact_segments=1,
            unresolved_segments=1,
            unresolved_reasons=(ReasonCode.BUDGET_EXHAUSTED,),
        ),
        lambda: ComparisonCoverage(
            total_partitions=1,
            covered_partitions=1,
            resolved_segments=2,
            pruned_segments=0,
            exact_segments=1,
            unresolved_segments=0,
            unresolved_reasons=(),
        ),
        lambda: EvidenceCoverage(
            found_records=1,
            retained_records=2,
            found_bytes=3,
            retained_bytes=3,
        ),
    )

    for build_invalid_coverage in invalid_coverage_builders:
        with pytest.raises(ValidationError):
            build_invalid_coverage()


@pytest.mark.parametrize(
    ("execution_status", "guarantee", "higher_reason"),
    [
        (ExecutionStatus.COMPLETED, Guarantee.EXACT, ReasonCode.BUDGET_EXHAUSTED),
        (ExecutionStatus.COMPLETED, Guarantee.EXACT, ReasonCode.QUERY_ERROR),
        (
            ExecutionStatus.INCOMPLETE,
            Guarantee.NOT_ESTABLISHED,
            ReasonCode.QUERY_ERROR,
        ),
    ],
)
def test_higher_severity_reason_requires_higher_precedence_status(
    execution_status: ExecutionStatus,
    guarantee: Guarantee,
    higher_reason: ReasonCode,
) -> None:
    reasons = (_reason(ReasonCode.DATA_MISMATCH), _reason(higher_reason))

    with pytest.raises(ValidationError, match="reason severity requires"):
        _result(
            execution_status,
            Verdict.MISMATCH,
            reasons,
            CONFIRMED_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            guarantee,
            RESOLVED_COVERAGE,
            EXACT_MISMATCH_TOTALS,
        )


def test_nested_reason_requires_governing_status_and_detailed_reason() -> None:
    with pytest.raises(ValidationError, match="reason severity requires error"):
        _result(
            ExecutionStatus.INCOMPLETE,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.BUDGET_EXHAUSTED),),
            NO_PERSISTENCE,
            UNKNOWN_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            QUERY_ERROR_COVERAGE,
            _unavailable_totals(ReasonCode.QUERY_ERROR),
        )

    with pytest.raises(ValidationError, match="requires a detailed top-level reason"):
        _result(
            ExecutionStatus.ERROR,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.BUDGET_EXHAUSTED),),
            NO_PERSISTENCE,
            UNKNOWN_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            QUERY_ERROR_COVERAGE,
            _unavailable_totals(ReasonCode.QUERY_ERROR),
        )

    with pytest.raises(ValidationError, match="requires a detailed top-level reason"):
        _result(
            ExecutionStatus.INCOMPLETE,
            Verdict.INCONCLUSIVE,
            (),
            NO_PERSISTENCE,
            UNKNOWN_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            NOT_READY_COVERAGE,
            _unavailable_totals(ReasonCode.NOT_READY),
        )


@pytest.mark.parametrize("field_name", ["missing", "extra", "modified"])
def test_match_rejects_positive_difference_totals(field_name: str) -> None:
    totals_data = EXACT_TOTALS.model_dump()
    totals_data[field_name] = {"precision": "exact", "value": "1"}

    with pytest.raises(ValidationError, match="zero difference totals"):
        RunResult(
            schema_version=1,
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            check_id="orders",
            contract_digest=DIGEST,
            scope_digest=DIGEST,
            execution_status=ExecutionStatus.COMPLETED,
            verdict=Verdict.MATCH,
            consistency=VERIFIED_CONSISTENCY,
            guarantee=Guarantee.EXACT,
            comparison_coverage=RESOLVED_COVERAGE,
            totals=ComparisonTotals.model_validate(totals_data),
            evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
            metrics=EMPTY_METRICS,
            reasons=(),
            persistence=CONFIRMED_PERSISTENCE,
        )


@pytest.mark.parametrize("guarantee", [Guarantee.AGGREGATE, Guarantee.STRUCTURAL])
def test_non_fingerprint_match_requires_exact_absence_totals(guarantee: Guarantee) -> None:
    lower_bound_zero_totals = ComparisonTotals(
        matched=ExactTotal(precision="exact", value="4"),
        missing=LowerBoundTotal(precision="lower_bound", value="0"),
        extra=LowerBoundTotal(precision="lower_bound", value="0"),
        modified=LowerBoundTotal(precision="lower_bound", value="0"),
    )

    with pytest.raises(ValidationError, match="requires exact zero difference totals"):
        _result(
            ExecutionStatus.COMPLETED,
            Verdict.MATCH,
            (),
            CONFIRMED_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            guarantee,
            RESOLVED_COVERAGE,
            lower_bound_zero_totals,
        )


def test_exact_guarantee_rejects_inferred_totals() -> None:
    inferred_totals = ComparisonTotals(
        matched=InferredTotal(precision="inferred_under_fingerprint", value="4"),
        missing=ExactTotal(precision="exact", value="0"),
        extra=ExactTotal(precision="exact", value="0"),
        modified=ExactTotal(precision="exact", value="0"),
    )

    with pytest.raises(ValidationError, match="exact guarantee requires exact totals"):
        RunResult(
            schema_version=1,
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            check_id="orders",
            contract_digest=DIGEST,
            scope_digest=DIGEST,
            execution_status=ExecutionStatus.COMPLETED,
            verdict=Verdict.MATCH,
            consistency=VERIFIED_CONSISTENCY,
            guarantee=Guarantee.EXACT,
            comparison_coverage=RESOLVED_COVERAGE,
            totals=inferred_totals,
            evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
            metrics=EMPTY_METRICS,
            reasons=(),
            persistence=CONFIRMED_PERSISTENCE,
        )


def test_fingerprint_match_allows_only_zero_inferred_difference_totals() -> None:
    coverage = ComparisonCoverage(
        total_partitions=1,
        covered_partitions=1,
        resolved_segments=1,
        pruned_segments=1,
        exact_segments=0,
        unresolved_segments=0,
        unresolved_reasons=(),
    )
    totals = ComparisonTotals(
        matched=InferredTotal(precision="inferred_under_fingerprint", value="4"),
        missing=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        extra=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        modified=InferredTotal(precision="inferred_under_fingerprint", value="0"),
    )

    result = RunResult(
        schema_version=1,
        run_id=RUN_ID,
        attempt_id=ATTEMPT_ID,
        check_id="orders",
        contract_digest=DIGEST,
        scope_digest=DIGEST,
        execution_status=ExecutionStatus.COMPLETED,
        verdict=Verdict.MATCH,
        consistency=VERIFIED_CONSISTENCY,
        guarantee=Guarantee.FINGERPRINT,
        comparison_coverage=coverage,
        totals=totals,
        evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
        metrics=EMPTY_METRICS,
        reasons=(),
        persistence=CONFIRMED_PERSISTENCE,
    )

    assert exit_code_for_result(result) is ExitCode.MATCH

    invalid_totals = totals.model_copy(
        update={
            "missing": InferredTotal(
                precision="inferred_under_fingerprint",
                value="1",
            )
        }
    )
    with pytest.raises(ValidationError, match="must be zero"):
        RunResult(
            schema_version=1,
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            check_id="orders",
            contract_digest=DIGEST,
            scope_digest=DIGEST,
            execution_status=ExecutionStatus.COMPLETED,
            verdict=Verdict.MATCH,
            consistency=VERIFIED_CONSISTENCY,
            guarantee=Guarantee.FINGERPRINT,
            comparison_coverage=coverage,
            totals=invalid_totals,
            evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
            metrics=EMPTY_METRICS,
            reasons=(),
            persistence=CONFIRMED_PERSISTENCE,
        )


def test_fingerprint_guarantee_rejects_exact_matched_total() -> None:
    coverage = ComparisonCoverage(
        total_partitions=1,
        covered_partitions=1,
        resolved_segments=1,
        pruned_segments=1,
        exact_segments=0,
        unresolved_segments=0,
        unresolved_reasons=(),
    )

    with pytest.raises(ValidationError, match="cannot claim an exact matched total"):
        RunResult(
            schema_version=1,
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            check_id="orders",
            contract_digest=DIGEST,
            scope_digest=DIGEST,
            execution_status=ExecutionStatus.COMPLETED,
            verdict=Verdict.MISMATCH,
            consistency=VERIFIED_CONSISTENCY,
            guarantee=Guarantee.FINGERPRINT,
            comparison_coverage=coverage,
            totals=EXACT_MISMATCH_TOTALS,
            evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
            metrics=EMPTY_METRICS,
            reasons=(_reason(ReasonCode.DATA_MISMATCH),),
            persistence=CONFIRMED_PERSISTENCE,
        )


def test_completed_fingerprint_evidence_survives_persistence_error_json_round_trip() -> None:
    coverage = ComparisonCoverage(
        total_partitions=1,
        covered_partitions=1,
        resolved_segments=1,
        pruned_segments=1,
        exact_segments=0,
        unresolved_segments=0,
        unresolved_reasons=(),
    )
    totals = ComparisonTotals(
        matched=InferredTotal(precision="inferred_under_fingerprint", value="4"),
        missing=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        extra=InferredTotal(precision="inferred_under_fingerprint", value="0"),
        modified=InferredTotal(precision="inferred_under_fingerprint", value="0"),
    )
    failed_persistence = PersistenceStatus(
        state=PersistenceState.FAILED,
        operation_id=PERSISTENCE_OPERATION_ID,
        reason=_reason(ReasonCode.PERSISTENCE_ERROR),
    )
    result = _result(
        ExecutionStatus.ERROR,
        Verdict.INCONCLUSIVE,
        (),
        failed_persistence,
        VERIFIED_CONSISTENCY,
        Guarantee.FINGERPRINT,
        coverage,
        totals,
    )

    assert exit_code_for_result(result) is ExitCode.ERROR
    assert RunResult.model_validate_json(result.model_dump_json()) == result

    with pytest.raises(ValidationError, match="fingerprint data_mismatch requires"):
        _result(
            ExecutionStatus.ERROR,
            Verdict.MISMATCH,
            (_reason(ReasonCode.DATA_MISMATCH),),
            failed_persistence,
            VERIFIED_CONSISTENCY,
            Guarantee.FINGERPRINT,
            coverage,
            totals,
        )

    erased_totals = totals.model_copy(
        update={
            "modified": UnavailableTotal(
                precision="unavailable",
                value=None,
                reason=ReasonCode.PERSISTENCE_ERROR,
            )
        }
    )
    with pytest.raises(ValidationError, match="requires preserved inferred totals"):
        _result(
            ExecutionStatus.ERROR,
            Verdict.INCONCLUSIVE,
            (),
            failed_persistence,
            VERIFIED_CONSISTENCY,
            Guarantee.FINGERPRINT,
            coverage,
            erased_totals,
        )


def test_verdict_requires_and_preserves_proven_mismatch() -> None:
    with pytest.raises(ValidationError, match="requires mismatch verdict"):
        _result(
            ExecutionStatus.INCOMPLETE,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.BUDGET_EXHAUSTED),),
            NO_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            PARTIAL_MISMATCH_COVERAGE,
            PARTIAL_MISMATCH_TOTALS,
        )

    with pytest.raises(ValidationError, match="requires a proven difference"):
        _result(
            ExecutionStatus.INCOMPLETE,
            Verdict.MISMATCH,
            (_reason(ReasonCode.BUDGET_EXHAUSTED),),
            NO_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            PARTIAL_MISMATCH_COVERAGE,
            _unavailable_totals(ReasonCode.BUDGET_EXHAUSTED),
        )

    with pytest.raises(ValidationError, match="positive exact difference"):
        _result(
            ExecutionStatus.COMPLETED,
            Verdict.MISMATCH,
            (_reason(ReasonCode.DATA_MISMATCH),),
            CONFIRMED_PERSISTENCE,
            VERIFIED_CONSISTENCY,
            Guarantee.EXACT,
            RESOLVED_COVERAGE,
            EXACT_TOTALS,
        )


@pytest.mark.parametrize(
    "consistency",
    [
        UNKNOWN_CONSISTENCY,
        ConsistencyStatus(
            stable_reads=ConsistencyLevel.VERIFIED,
            cut_alignment=ConsistencyLevel.VERIFIED,
            read_context_ids=(),
        ),
    ],
)
def test_partial_data_mismatch_requires_comparable_contexts(
    consistency: ConsistencyStatus,
) -> None:
    with pytest.raises(ValidationError, match="proven data mismatch requires known consistency"):
        _result(
            ExecutionStatus.INCOMPLETE,
            Verdict.MISMATCH,
            (
                _reason(ReasonCode.DATA_MISMATCH),
                _reason(ReasonCode.BUDGET_EXHAUSTED),
            ),
            NO_PERSISTENCE,
            consistency,
            Guarantee.NOT_ESTABLISHED,
            PARTIAL_MISMATCH_COVERAGE,
            PARTIAL_MISMATCH_TOTALS,
        )


def test_contract_violation_requires_unavailable_row_totals() -> None:
    contract_violation = RunResult(
        schema_version=1,
        run_id=RUN_ID,
        attempt_id=ATTEMPT_ID,
        check_id="orders",
        contract_digest=DIGEST,
        scope_digest=DIGEST,
        execution_status=ExecutionStatus.COMPLETED,
        verdict=Verdict.MISMATCH,
        consistency=VERIFIED_CONSISTENCY,
        guarantee=Guarantee.STRUCTURAL,
        comparison_coverage=RESOLVED_COVERAGE,
        totals=UNAVAILABLE_CONTRACT_TOTALS,
        evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
        metrics=EMPTY_METRICS,
        reasons=(_reason(ReasonCode.CONTRACT_VIOLATION),),
        persistence=CONFIRMED_PERSISTENCE,
    )

    assert exit_code_for_result(contract_violation) is ExitCode.MISMATCH

    with pytest.raises(ValidationError, match="requires unavailable row totals"):
        RunResult(
            schema_version=1,
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            check_id="orders",
            contract_digest=DIGEST,
            scope_digest=DIGEST,
            execution_status=ExecutionStatus.COMPLETED,
            verdict=Verdict.MISMATCH,
            consistency=VERIFIED_CONSISTENCY,
            guarantee=Guarantee.STRUCTURAL,
            comparison_coverage=RESOLVED_COVERAGE,
            totals=EXACT_TOTALS,
            evidence_coverage=EMPTY_EVIDENCE_COVERAGE,
            metrics=EMPTY_METRICS,
            reasons=(_reason(ReasonCode.CONTRACT_VIOLATION),),
            persistence=CONFIRMED_PERSISTENCE,
        )


def test_persistence_reason_codes_match_state_across_typed_locations() -> None:
    with pytest.raises(ValidationError, match=r"persistence_error.*must appear together"):
        _result(
            ExecutionStatus.ERROR,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.QUERY_ERROR),),
            NO_PERSISTENCE,
            UNKNOWN_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            QUERY_ERROR_COVERAGE,
            _unavailable_totals(ReasonCode.PERSISTENCE_ERROR),
        )

    failed_persistence = PersistenceStatus(
        state=PersistenceState.FAILED,
        operation_id=PERSISTENCE_OPERATION_ID,
        reason=_reason(ReasonCode.PERSISTENCE_ERROR),
    )
    with pytest.raises(ValidationError, match=r"commit_unknown.*must appear together"):
        _result(
            ExecutionStatus.ERROR,
            Verdict.INCONCLUSIVE,
            (_reason(ReasonCode.COMMIT_UNKNOWN),),
            failed_persistence,
            UNKNOWN_CONSISTENCY,
            Guarantee.NOT_ESTABLISHED,
            NOT_READY_COVERAGE,
            _unavailable_totals(ReasonCode.PERSISTENCE_ERROR),
        )


def test_established_guarantee_requires_context_and_known_consistency() -> None:
    verified_without_context = ConsistencyStatus(
        stable_reads=ConsistencyLevel.VERIFIED,
        cut_alignment=ConsistencyLevel.VERIFIED,
        read_context_ids=(),
    )
    unknown_consistency = ConsistencyStatus(
        stable_reads=ConsistencyLevel.UNKNOWN,
        cut_alignment=ConsistencyLevel.UNKNOWN,
        read_context_ids=(READ_CONTEXT_ID,),
    )
    failed_persistence = PersistenceStatus(
        state=PersistenceState.FAILED,
        operation_id=PERSISTENCE_OPERATION_ID,
        reason=_reason(ReasonCode.PERSISTENCE_ERROR),
    )

    with pytest.raises(ValidationError, match="at least one read context"):
        _result(
            ExecutionStatus.ERROR,
            Verdict.INCONCLUSIVE,
            (),
            failed_persistence,
            verified_without_context,
            Guarantee.EXACT,
            RESOLVED_COVERAGE,
            EXACT_TOTALS,
        )

    with pytest.raises(ValidationError, match="known consistency evidence"):
        _result(
            ExecutionStatus.ERROR,
            Verdict.INCONCLUSIVE,
            (),
            failed_persistence,
            unknown_consistency,
            Guarantee.EXACT,
            RESOLVED_COVERAGE,
            EXACT_TOTALS,
        )
