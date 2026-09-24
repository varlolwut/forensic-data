#!/usr/bin/env bash
set -euo pipefail

: "${SQLCMDPASSWORD:?SQLCMDPASSWORD is required}"

readonly SQLCMD=/opt/mssql-tools18/bin/sqlcmd
readonly VERIFY_SQL=/opt/forensic-data/mssql-2022/verify.sql

if [[ -v MSSQL_SA_PASSWORD || -v DFE_MSSQL_SETUP_WRITER_PASSWORD ]]; then
  echo "The fixture reader received a setup credential." >&2
  exit 1
fi
if [[ ! -x "${SQLCMD}" ]]; then
  echo "SQL Server 2022 CU27 fixture requires ${SQLCMD}." >&2
  exit 1
fi

run_reader_query() {
  local query="$1"
  "${SQLCMD}" \
    -S tcp:sqlserver,1433 \
    -U dfe_fixture_reader \
    -d dfe_fixture \
    -Nm \
    -C \
    -l 15 \
    -t 30 \
    -b \
    -V 11 \
    -r 1 \
    -Q "${query}"
}

expect_reader_denial() {
  local operation="$1"
  local query="$2"
  local output_path="/tmp/${operation}.log"

  if run_reader_query "${query}" >"${output_path}" 2>&1; then
    echo "Fixture reader unexpectedly completed ${operation}." >&2
    return 1
  fi
  if ! grep --quiet --extended-regexp '^Msg (229|262),' "${output_path}"; then
    echo "Fixture reader ${operation} failed for an unexpected reason." >&2
    sed -n '1,20p' "${output_path}" >&2
    return 1
  fi
}

"${SQLCMD}" \
  -S tcp:sqlserver,1433 \
  -U dfe_fixture_reader \
  -d dfe_fixture \
  -Nm \
  -C \
  -l 15 \
  -t 30 \
  -b \
  -V 11 \
  -r 1 \
  -W \
  -s '|' \
  -i "${VERIFY_SQL}"

expect_reader_denial \
  reader-dml \
  "UPDATE [dfe_fixture].[snapshot_probe] SET [observed_value] = N'forbidden' WHERE [record_id] = 1;"
expect_reader_denial \
  reader-ddl \
  "CREATE TABLE [dfe_fixture].[reader_should_not_create] ([record_id] bigint NOT NULL);"

run_reader_query \
  "SET NOCOUNT ON; IF EXISTS (SELECT 1 FROM [dfe_fixture].[snapshot_probe] WHERE [record_id] = 1 AND [observed_value] = N'forbidden') THROW 51000, N'Reader changed fixture data.', 1; IF OBJECT_ID(N'dfe_fixture.reader_should_not_create', N'U') IS NOT NULL THROW 51000, N'Reader created a table.', 1;"

echo "SQL Server 2022 CU27 SNAPSHOT and least-privilege fixture verification passed."
