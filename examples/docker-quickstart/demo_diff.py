import os
import sys
from io import StringIO
from pathlib import Path

from forensic_data.cli import run_cli
from forensic_data.reporting import DetailAvailability, DifferenceKind, DiffPage
from forensic_data.result import RunResult

CONFIG_PATH = Path("/config/contract.yaml")
CHECK_RESULT_PATH = Path("/output/check.json")
OUTPUT_PATH = Path("/output/diff.json")


def load_check_result() -> RunResult:
    if not CHECK_RESULT_PATH.is_file():
        raise RuntimeError("/output/check.json is missing; run demo-check first")
    return RunResult.model_validate_json(CHECK_RESULT_PATH.read_text(encoding="utf-8"))


def invoke(run_id: str, attempt_id: str, output: str) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    exit_code = run_cli(
        (
            "diff",
            "--config",
            str(CONFIG_PATH),
            "--run-id",
            run_id,
            "--attempt-id",
            attempt_id,
            "--limit",
            "20",
            "--output",
            output,
        ),
        os.environ,
        stdout,
        stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue()


def validate_page(page: DiffPage, result: RunResult) -> None:
    observed_details = tuple(
        (
            detail.sequence,
            detail.kind,
            detail.omitted_field_names,
            tuple((value.field_name, value.canonical_text) for value in detail.key_values),
            tuple((value.field_name, value.canonical_text) for value in detail.reference_values),
            tuple((value.field_name, value.canonical_text) for value in detail.target_values),
        )
        for detail in page.details
    )
    expected_details = (
        (
            0,
            DifferenceKind.MODIFIED,
            ("business_date",),
            (("order_id", "1002"),),
            (("amount", "20.00"),),
            (("amount", "20.25"),),
        ),
        (
            1,
            DifferenceKind.MISSING,
            ("business_date",),
            (("order_id", "1003"),),
            (("amount", "30.00"),),
            (),
        ),
        (
            2,
            DifferenceKind.EXTRA,
            ("business_date",),
            (("order_id", "1004"),),
            (),
            (("amount", "40.00"),),
        ),
    )
    if (
        page.stored_result != result
        or page.detail_availability is not DetailAvailability.AVAILABLE
        or page.found_records != 3
        or page.retained_records != 3
        or page.next_cursor is not None
        or observed_details != expected_details
    ):
        raise RuntimeError("demo diff does not contain the expected three retained differences")


def preserve_or_verify_page(page: DiffPage, json_output: str) -> None:
    if OUTPUT_PATH.exists():
        if not OUTPUT_PATH.is_file():
            raise RuntimeError("/output/diff.json is not a regular file")
        saved_page = DiffPage.model_validate_json(OUTPUT_PATH.read_text(encoding="utf-8"))
        if saved_page != page:
            raise RuntimeError("demo diff changed after it was first saved")
        return
    OUTPUT_PATH.write_text(json_output, encoding="utf-8")


def main() -> int:
    result = load_check_result()
    run_id = str(result.run_id)
    attempt_id = str(result.attempt_id)
    exit_code, json_output, error_output = invoke(run_id, attempt_id, "json")
    if exit_code != 0:
        sys.stdout.write(json_output)
        sys.stderr.write(error_output)
        return exit_code
    page = DiffPage.model_validate_json(json_output)
    validate_page(page, result)
    preserve_or_verify_page(page, json_output)

    human_exit, human_output, human_error = invoke(run_id, attempt_id, "human")
    if human_exit != 0:
        sys.stdout.write(human_output)
        sys.stderr.write(human_error)
        return human_exit
    sys.stdout.write(human_output)
    print("Diff came only from retained metadata; source tables were not queried.")
    print("Next action: inspect order 1002, the missing 1003, and the extra 1004.")
    print("Machine result: /output/diff.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
