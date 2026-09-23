import os
import sys
from io import StringIO
from pathlib import Path

from forensic_data.cli import run_cli
from forensic_data.result import ExecutionStatus, Guarantee, RunResult, Verdict

CONFIG_PATH = Path("/config/contract.yaml")
OUTPUT_PATH = Path("/output/check.json")
SCOPE_JSON = '{"business_date":"2026-09-23"}'
REQUEST_ID = "7fa700c4-7c5d-42eb-8f55-50e372ed0e25"


def invoke(output: str) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    exit_code = run_cli(
        (
            "check",
            "--config",
            str(CONFIG_PATH),
            "--check",
            "daily_orders",
            "--scope-json",
            SCOPE_JSON,
            "--reference-batch",
            "reference-demo-2026-09-23",
            "--target-batch",
            "target-demo-2026-09-23",
            "--request-id",
            REQUEST_ID,
            "--output",
            output,
        ),
        os.environ,
        stdout,
        stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue()


def validate_result(result: RunResult) -> None:
    coverage = result.comparison_coverage
    totals = result.totals
    evidence = result.evidence_coverage
    if (
        result.execution_status is not ExecutionStatus.COMPLETED
        or result.verdict is not Verdict.MISMATCH
        or result.guarantee is not Guarantee.EXACT
        or (
            coverage.total_partitions,
            coverage.covered_partitions,
            coverage.resolved_segments,
            coverage.pruned_segments,
            coverage.exact_segments,
            coverage.unresolved_segments,
        )
        != (1, 1, 1, 0, 1, 0)
        or coverage.unresolved_reasons != ()
        or (
            (totals.matched.precision, totals.matched.value),
            (totals.missing.precision, totals.missing.value),
            (totals.extra.precision, totals.extra.value),
            (totals.modified.precision, totals.modified.value),
        )
        != (
            ("exact", "1"),
            ("exact", "1"),
            ("exact", "1"),
            ("exact", "1"),
        )
        or evidence.found_records != 3
        or evidence.retained_records != 3
    ):
        raise RuntimeError("demo check did not produce the expected exact 1/1/1 mismatch")


def preserve_or_verify_result(result: RunResult, json_output: str) -> None:
    if OUTPUT_PATH.exists():
        if not OUTPUT_PATH.is_file():
            raise RuntimeError("/output/check.json is not a regular file")
        saved_result = RunResult.model_validate_json(OUTPUT_PATH.read_text(encoding="utf-8"))
        if saved_result != result:
            raise RuntimeError("demo check replay differs from the saved result")
        return
    OUTPUT_PATH.write_text(json_output, encoding="utf-8")


def main() -> int:
    exit_code, json_output, error_output = invoke("json")
    if exit_code != 1:
        sys.stdout.write(json_output)
        sys.stderr.write(error_output)
        sys.stderr.write(f"Expected a completed mismatch (exit 1), received exit {exit_code}.\n")
        return 1

    result = RunResult.model_validate_json(json_output)
    validate_result(result)
    preserve_or_verify_result(result, json_output)

    replay_exit, human_output, replay_error = invoke("human")
    if replay_exit != 1:
        sys.stdout.write(human_output)
        sys.stderr.write(replay_error)
        sys.stderr.write(f"Expected mismatch replay exit 1, received exit {replay_exit}.\n")
        return 1

    print("Demo scope: daily_orders for business_date=2026-09-23")
    sys.stdout.write(human_output)
    print("Exit 1 is the expected completed mismatch, not an engine failure.")
    print("Next action: run 'docker compose run --rm demo-diff' to inspect retained rows.")
    print("Machine result: /output/check.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
