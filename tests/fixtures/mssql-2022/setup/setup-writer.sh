#!/usr/bin/env bash
set -euo pipefail

: "${SQLCMDPASSWORD:?SQLCMDPASSWORD is required}"

readonly SQLCMD=/opt/mssql-tools18/bin/sqlcmd
readonly FIXTURE_SQL=/opt/forensic-data/mssql-2022/seed.sql

if [[ -v MSSQL_SA_PASSWORD ]]; then
  echo "The setup writer must not receive the SQL Server administrator credential." >&2
  exit 1
fi
if [[ ! -x "${SQLCMD}" ]]; then
  echo "SQL Server 2022 CU27 fixture requires ${SQLCMD}." >&2
  exit 1
fi

"${SQLCMD}" \
  -S tcp:sqlserver,1433 \
  -U dfe_fixture_setup_writer \
  -d dfe_fixture \
  -Nm \
  -C \
  -l 15 \
  -t 30 \
  -b \
  -V 11 \
  -r 1 \
  -i "${FIXTURE_SQL}"
