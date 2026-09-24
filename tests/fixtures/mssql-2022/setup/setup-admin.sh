#!/usr/bin/env bash
set -euo pipefail

: "${SQLCMDPASSWORD:?SQLCMDPASSWORD is required}"
: "${DFE_MSSQL_READER_PASSWORD:?DFE_MSSQL_READER_PASSWORD is required}"
: "${DFE_MSSQL_SETUP_WRITER_PASSWORD:?DFE_MSSQL_SETUP_WRITER_PASSWORD is required}"

readonly SQLCMD=/opt/mssql-tools18/bin/sqlcmd
readonly FIXTURE_SQL=/opt/forensic-data/mssql-2022/admin.sql

if [[ ! -x "${SQLCMD}" ]]; then
  echo "SQL Server 2022 CU27 fixture requires ${SQLCMD}." >&2
  exit 1
fi

validate_login_password() {
  local variable_name="$1"
  local password="$2"

  if (( ${#password} < 12 || ${#password} > 128 )); then
    echo "${variable_name} must contain 12 to 128 characters." >&2
    return 1
  fi
  if [[ ! "${password}" =~ ^[A-Za-z0-9!@#%_+=.,:-]+$ ]]; then
    echo "${variable_name} contains a character unsupported by the fixture SQL boundary." >&2
    return 1
  fi
  if [[ ! "${password}" =~ [A-Z] || ! "${password}" =~ [a-z] || ! "${password}" =~ [0-9] || ! "${password}" =~ [!@#%_+=.,:-] ]]; then
    echo "${variable_name} must contain upper-case, lower-case, numeric, and symbol characters." >&2
    return 1
  fi
}

require_distinct_passwords() {
  local first_name="$1"
  local first_password="$2"
  local second_name="$3"
  local second_password="$4"

  if [[ "${first_password}" == "${second_password}" ]]; then
    echo "${first_name} and ${second_name} must be distinct." >&2
    return 1
  fi
}

validate_login_password DFE_MSSQL_READER_PASSWORD "${DFE_MSSQL_READER_PASSWORD}"
validate_login_password DFE_MSSQL_SETUP_WRITER_PASSWORD "${DFE_MSSQL_SETUP_WRITER_PASSWORD}"
require_distinct_passwords \
  DFE_MSSQL_SA_PASSWORD \
  "${SQLCMDPASSWORD}" \
  DFE_MSSQL_READER_PASSWORD \
  "${DFE_MSSQL_READER_PASSWORD}"
require_distinct_passwords \
  DFE_MSSQL_SA_PASSWORD \
  "${SQLCMDPASSWORD}" \
  DFE_MSSQL_SETUP_WRITER_PASSWORD \
  "${DFE_MSSQL_SETUP_WRITER_PASSWORD}"
require_distinct_passwords \
  DFE_MSSQL_READER_PASSWORD \
  "${DFE_MSSQL_READER_PASSWORD}" \
  DFE_MSSQL_SETUP_WRITER_PASSWORD \
  "${DFE_MSSQL_SETUP_WRITER_PASSWORD}"

"${SQLCMD}" \
  -S tcp:sqlserver,1433 \
  -U sa \
  -d master \
  -Nm \
  -C \
  -l 15 \
  -t 60 \
  -b \
  -V 11 \
  -r 1 \
  -i "${FIXTURE_SQL}"
