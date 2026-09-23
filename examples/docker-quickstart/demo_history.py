import os
import sys
from io import StringIO
from pathlib import Path

from forensic_data.cli import run_cli
from forensic_data.reporting import (
    HistoryAttemptStatus,
    HistoryPage,
    StoredResultAvailability,
)
from forensic_data.result import RunResult

CONFIG_PATH = Path("/config/contract.yaml")
CHECK_RESULT_PATH = Path("/output/check.json")
OUTPUT_PATH = Path("/output/history.json")
SCOPE_JSON = '{"business_date":"2026-09-23"}'


def invoke(output: str) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    exit_code = run_cli(
        (
            "history",
            "--config",
            str(CONFIG_PATH),
            "--check",
            "daily_orders",
            "--scope-json",
            SCOPE_JSON,
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


def load_check_result() -> RunResult:
    if not CHECK_RESULT_PATH.is_file():
        raise RuntimeError("/output/check.json is missing; run demo-check first")
    return RunResult.model_validate_json(CHECK_RESULT_PATH.read_text(encoding="utf-8"))


def validate_page(page: HistoryPage, result: RunResult) -> None:
    if len(page.items) != 1 or page.next_cursor is not None:
        raise RuntimeError("demo history must contain exactly one completed attempt")
    item = page.items[0]
    if (
        item.status is not HistoryAttemptStatus.COMPLETED
        or item.stored_result_availability is not StoredResultAvailability.AVAILABLE
        or item.run_id != result.run_id
        or item.attempt_id != result.attempt_id
        or item.stored_result != result
    ):
        raise RuntimeError("demo history does not contain the saved comparison result")


def preserve_or_verify_page(page: HistoryPage, json_output: str) -> None:
    if OUTPUT_PATH.exists():
        if not OUTPUT_PATH.is_file():
            raise RuntimeError("/output/history.json is not a regular file")
        saved_page = HistoryPage.model_validate_json(OUTPUT_PATH.read_text(encoding="utf-8"))
        if saved_page != page:
            raise RuntimeError("demo history changed after it was first saved")
        return
    OUTPUT_PATH.write_text(json_output, encoding="utf-8")


def main() -> int:
    result = load_check_result()
    exit_code, json_output, error_output = invoke("json")
    if exit_code != 0:
        sys.stdout.write(json_output)
        sys.stderr.write(error_output)
        return exit_code
    page = HistoryPage.model_validate_json(json_output)
    validate_page(page, result)
    preserve_or_verify_page(page, json_output)

    human_exit, human_output, human_error = invoke("human")
    if human_exit != 0:
        sys.stdout.write(human_output)
        sys.stderr.write(human_error)
        return human_exit
    sys.stdout.write(human_output)
    print("History came only from the persistent metadata store.")
    print("Machine result: /output/history.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
