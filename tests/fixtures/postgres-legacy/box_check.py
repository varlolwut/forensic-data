import os
import shutil
from decimal import Decimal
from importlib.metadata import version
from io import StringIO
from pathlib import Path

import psycopg
import psycopg2
from psycopg.rows import tuple_row

from forensic_data.cli import run_cli
from forensic_data.result import ExecutionStatus, Guarantee, RunResult, Verdict

CONFIG_PATH = Path(__file__).with_name("contract.yaml")
REQUEST_ID = "729c8f70-6f4f-4fcf-973b-ae79acc74b31"


def main() -> int:
    unexpected_tools = tuple(
        tool for tool in ("cc", "gcc", "make", "pg_config") if shutil.which(tool) is not None
    )
    if unexpected_tools or Path("/usr/include/postgresql/libpq-fe.h").exists():
        raise RuntimeError(
            f"runtime image contains build-only PostgreSQL tooling: tools={unexpected_tools!r}"
        )
    if psycopg.__version__ != "3.3.6" or psycopg.pq.__impl__ != "c":
        raise RuntimeError("box requires the Psycopg 3.3.6 C implementation")
    if psycopg.pq.version() != 170_011:
        raise RuntimeError("Psycopg must use the pinned libpq 17.11 runtime")
    if version("psycopg2") != "2.9.13":
        raise RuntimeError("box requires Psycopg2 2.9.13")
    if psycopg2.__libpq_version__ != 170_011:
        raise RuntimeError("Psycopg2 must be built against the pinned libpq 17.11 runtime")
    if psycopg2.extensions.libpq_version() != 170_011:
        raise RuntimeError("Psycopg2 must load the pinned libpq 17.11 runtime")

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
            '{"business_date":"2026-09-23"}',
            "--reference-batch",
            "legacy-reference-2026-09-23",
            "--target-batch",
            "legacy-target-2026-09-23",
            "--request-id",
            REQUEST_ID,
            "--output",
            "json",
        ),
        os.environ,
        stdout,
        stderr,
    )
    if exit_code != 1 or stderr.getvalue():
        raise RuntimeError(
            "legacy box check did not return the expected completed mismatch: "
            f"exit_code={exit_code}, stderr={stderr.getvalue()!r}"
        )
    result = RunResult.model_validate_json(stdout.getvalue())
    if (
        result.execution_status is not ExecutionStatus.COMPLETED
        or result.verdict is not Verdict.MISMATCH
        or result.guarantee is not Guarantee.EXACT
        or tuple((total.precision, total.value) for total in result.totals.values())
        != (("exact", "1"), ("exact", "1"), ("exact", "1"), ("exact", "1"))
        or result.evidence_coverage.retained_records != 3
    ):
        raise RuntimeError("legacy box check returned an unexpected comparison result")

    metadata_dsn = os.environ.get("DFE_TEST_POSTGRES_METADATA_WRITER_DSN")
    if metadata_dsn is None or not metadata_dsn:
        raise RuntimeError("DFE_TEST_POSTGRES_METADATA_WRITER_DSN is required")
    with psycopg.connect(metadata_dsn, row_factory=tuple_row) as connection:
        contexts = connection.execute(
            "SELECT direction, driver_version, server_version_number, state "
            "FROM dfe_metadata.attempt_read_contexts "
            "WHERE run_id = %s AND attempt_id = %s ORDER BY direction",
            (result.run_id, result.attempt_id),
        ).fetchall()
        numeric_difference = connection.execute(
            "SELECT reference_value, target_value, target_minus_reference "
            "FROM dfe_metadata.numeric_differences "
            "WHERE run_id = %s AND attempt_id = %s "
            "AND anomaly_kind = 'modified' AND field_name = 'amount'",
            (result.run_id, result.attempt_id),
        ).fetchone()

    if tuple((row[0], str(row[1]).split()[0], row[2], row[3]) for row in contexts) != (
        ("reference", "2.9.13", 90_624, "closed"),
        ("target", "3.3.6", 170_011, "closed"),
    ):
        raise RuntimeError("legacy box check did not persist the expected read contexts")
    if numeric_difference != (Decimal("20.00"), Decimal("20.25"), Decimal("0.25")):
        raise RuntimeError("legacy box check did not persist the expected numeric difference")

    print("PostgreSQL 9.6.24 source to PostgreSQL 17.11 box check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
