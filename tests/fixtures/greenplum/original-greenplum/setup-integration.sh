#!/usr/bin/env bash
set -euo pipefail

readonly GREENPLUM_HOME=/usr/local/gpdb
readonly MASTER_DATA_DIRECTORY=/home/gpadmin/gpdemo-data/qddir/demoDataDir-1
readonly READER_ROLE=dfe_original_greenplum_reader
readonly FIXTURE_DATABASE=dfe_fixture
readonly EXPECTED_SHA256=a19a1686cc6fb7aeaef72c8b287ef52d4a0084b323193919c0d3b84e977210ee
readonly PGCRYPTO_SQL=/usr/local/gpdb/share/postgresql/contrib/pgcrypto.sql
readonly HBA_FILE=/home/gpadmin/gpdemo-data/qddir/demoDataDir-1/pg_hba.conf
readonly HBA_LINE='host dfe_fixture dfe_original_greenplum_reader samenet md5'
readonly EXPECTED_COLUMNS=$'record_id|bigint|t\namount|numeric(38,4)|t\nactive|boolean|t\nlabel|text|t\nbusiness_date|date|t\nlocal_time|timestamp(6) without time zone|t\ninstant_time|timestamp(6) with time zone|t\nignored_payload|bytea|f'
export MASTER_DATA_DIRECTORY

fail() {
  local message="$1"
  printf 'Original Greenplum integration setup failed: %s\n' "${message}" >&2
  exit 1
}

psql_as_gpadmin() {
  local database="$1"
  shift
  runuser --user gpadmin -- \
    env HOME=/home/gpadmin USER=gpadmin LOGNAME=gpadmin \
    PATH="${GREENPLUM_HOME}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LD_LIBRARY_PATH="${GREENPLUM_HOME}/lib" \
    MASTER_DATA_DIRECTORY="${MASTER_DATA_DIRECTORY}" \
    PGPORT=15432 \
    psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname "${database}" "$@"
}

query_scalar() {
  local database="$1"
  local query="$2"
  psql_as_gpadmin "${database}" --tuples-only --no-align --command "${query}"
}

require_count() {
  local observed="$1"
  local expected="$2"
  local description="$3"
  if [[ "${observed}" != "${expected}" ]]; then
    fail "${description}: expected ${expected}, observed ${observed}"
  fi
}

if (( $# != 1 )); then
  fail 'expected the reader password secret-file path as the only argument'
fi
readonly READER_PASSWORD_FILE="$1"
if [[ ! -f "${READER_PASSWORD_FILE}" ]]; then
  fail "reader password secret file does not exist: ${READER_PASSWORD_FILE}"
fi
if [[ ! -s "${READER_PASSWORD_FILE}" ]]; then
  fail "reader password secret file is empty: ${READER_PASSWORD_FILE}"
fi

reader_password="$(<"${READER_PASSWORD_FILE}")"
if [[ -z "${reader_password}" ]]; then
  fail "reader password secret file contains no password: ${READER_PASSWORD_FILE}"
fi
if [[ "${reader_password}" == *$'\n'* || "${reader_password}" == *$'\r'* ]]; then
  fail "reader password secret file must contain exactly one line: ${READER_PASSWORD_FILE}"
fi
password_digest="$(printf '%s%s' "${reader_password}" "${READER_ROLE}" | md5sum | cut --delimiter=' ' --fields=1)"
unset reader_password
readonly password_verifier="md5${password_digest}"
unset password_digest

role_count="$(query_scalar template1 \
  "SELECT count(*) FROM pg_roles WHERE rolname = '${READER_ROLE}';")"
case "${role_count}" in
  0)
    printf 'CREATE ROLE %s;\n' "${READER_ROLE}" | psql_as_gpadmin template1
    ;;
  1) ;;
  *) fail "reader role catalog lookup returned ${role_count} rows" ;;
esac
printf "ALTER ROLE %s WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '%s';\n" \
  "${READER_ROLE}" "${password_verifier}" \
  | psql_as_gpadmin template1
printf "ALTER ROLE %s SET default_transaction_read_only = 'on';\n" "${READER_ROLE}" \
  | psql_as_gpadmin template1

database_count="$(query_scalar template1 \
  "SELECT count(*) FROM pg_database WHERE datname = '${FIXTURE_DATABASE}';")"
case "${database_count}" in
  0)
    printf "CREATE DATABASE %s OWNER gpadmin ENCODING 'UTF8';\n" "${FIXTURE_DATABASE}" \
      | psql_as_gpadmin template1
    ;;
  1) ;;
  *) fail "fixture database catalog lookup returned ${database_count} rows" ;;
esac
database_owner="$(query_scalar template1 \
  "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '${FIXTURE_DATABASE}';")"
if [[ "${database_owner}" != gpadmin ]]; then
  fail "fixture database owner must be gpadmin, observed ${database_owner}"
fi

for schema_name in dfe_ext dfe_fixture; do
  schema_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_namespace WHERE nspname = '${schema_name}';")"
  case "${schema_count}" in
    0)
      printf 'CREATE SCHEMA %s AUTHORIZATION gpadmin;\n' "${schema_name}" \
        | psql_as_gpadmin "${FIXTURE_DATABASE}"
      ;;
    1) ;;
    *) fail "schema ${schema_name} catalog lookup returned ${schema_count} rows" ;;
  esac
  schema_owner="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = '${schema_name}';")"
  if [[ "${schema_owner}" != gpadmin ]]; then
    fail "schema ${schema_name} owner must be gpadmin, observed ${schema_owner}"
  fi
done

if [[ ! -s "${PGCRYPTO_SQL}" ]]; then
  fail "installed upstream pgcrypto SQL is missing or empty: ${PGCRYPTO_SQL}"
fi
search_path_count="$(awk '$0 == "SET search_path = public;" { count += 1 } END { print count + 0 }' \
  "${PGCRYPTO_SQL}")"
require_count "${search_path_count}" 1 'upstream pgcrypto search_path statement count'
temporary_sql="$(mktemp /tmp/dfe-original-pgcrypto.XXXXXX.sql)"
readonly temporary_sql
trap 'rm -f "${temporary_sql}"' EXIT
sed 's/^SET search_path = public;$/SET search_path = dfe_ext;/' \
  "${PGCRYPTO_SQL}" >"${temporary_sql}"
rewritten_count="$(awk '$0 == "SET search_path = dfe_ext;" { count += 1 } END { print count + 0 }' \
  "${temporary_sql}")"
require_count "${rewritten_count}" 1 'rewritten pgcrypto search_path statement count'
if grep --fixed-strings --line-regexp --quiet 'SET search_path = public;' "${temporary_sql}"; then
  fail 'rewritten pgcrypto SQL still targets the public schema'
fi
psql_as_gpadmin "${FIXTURE_DATABASE}" <"${temporary_sql}"

function_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dfe_ext';")"
if [[ "${function_count}" == 0 ]]; then
  fail 'upstream pgcrypto SQL created no functions in dfe_ext'
fi
function_revoke_sql="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT 'REVOKE ALL PRIVILEGES ON FUNCTION ' || quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || oidvectortypes(p.proargtypes) || ') FROM PUBLIC; REVOKE ALL PRIVILEGES ON FUNCTION ' || quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || oidvectortypes(p.proargtypes) || ') FROM ${READER_ROLE};' FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dfe_ext' ORDER BY p.oid;")"
if [[ -z "${function_revoke_sql}" ]]; then
  fail 'could not generate pgcrypto function revocations'
fi
printf '%s\n' "${function_revoke_sql}" | psql_as_gpadmin "${FIXTURE_DATABASE}"

table_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = 'capability_types' AND c.relkind = 'r';")"
case "${table_count}" in
  0)
    psql_as_gpadmin "${FIXTURE_DATABASE}" <<'SQL'
CREATE TABLE dfe_fixture.capability_types (
  record_id bigint NOT NULL,
  amount numeric(38, 4) NOT NULL,
  active boolean NOT NULL,
  label text NOT NULL,
  business_date date NOT NULL,
  local_time timestamp(6) without time zone NOT NULL,
  instant_time timestamp(6) with time zone NOT NULL,
  ignored_payload bytea NULL
) DISTRIBUTED BY (record_id);
SQL
    ;;
  1) ;;
  *) fail "capability_types catalog lookup returned ${table_count} rows" ;;
esac

observed_columns="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT a.attname || '|' || format_type(a.atttypid, a.atttypmod) || '|' || CASE WHEN a.attnotnull THEN 't' ELSE 'f' END FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = 'capability_types' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum;")"
if [[ "${observed_columns}" != "${EXPECTED_COLUMNS}" ]]; then
  fail "capability_types has an unexpected physical schema"
fi
distribution_key="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT array_to_string(attrnums, ',') FROM gp_distribution_policy WHERE localoid = 'dfe_fixture.capability_types'::regclass;")"
if [[ "${distribution_key}" != 1 ]]; then
  fail "capability_types must be distributed by record_id, observed policy key ${distribution_key}"
fi

psql_as_gpadmin "${FIXTURE_DATABASE}" <<'SQL'
TRUNCATE TABLE dfe_fixture.capability_types;
INSERT INTO dfe_fixture.capability_types (
  record_id,
  amount,
  active,
  label,
  business_date,
  local_time,
  instant_time,
  ignored_payload
)
SELECT
  generated.record_id,
  (generated.record_id::numeric / 10000)::numeric(38, 4),
  (generated.record_id % 2 = 0),
  'segment-hash-' || generated.record_id::text,
  DATE '2024-02-29',
  TIMESTAMP '2024-02-29 23:59:58.123456',
  TIMESTAMP WITH TIME ZONE '2024-02-29 21:29:58.123456+00',
  NULL::bytea
FROM generate_series(1, 32) AS generated(record_id);
SQL

row_count="$(query_scalar "${FIXTURE_DATABASE}" \
  'SELECT count(*) FROM dfe_fixture.capability_types;')"
require_count "${row_count}" 32 'capability_types row count'
primary_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM gp_segment_configuration WHERE content >= 0 AND role = 'p' AND status = 'u';")"
covered_primary_count="$(query_scalar "${FIXTURE_DATABASE}" \
  'SELECT count(DISTINCT gp_segment_id) FROM dfe_fixture.capability_types;')"
require_count "${covered_primary_count}" "${primary_count}" \
  'capability_types covered primary segment count'

psql_as_gpadmin "${FIXTURE_DATABASE}" <<SQL
REVOKE ALL PRIVILEGES ON DATABASE ${FIXTURE_DATABASE} FROM PUBLIC;
REVOKE ALL PRIVILEGES ON DATABASE ${FIXTURE_DATABASE} FROM ${READER_ROLE};
GRANT CONNECT ON DATABASE ${FIXTURE_DATABASE} TO ${READER_ROLE};
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA dfe_ext FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA dfe_ext FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON SCHEMA dfe_fixture FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA dfe_fixture FROM ${READER_ROLE};
GRANT USAGE ON SCHEMA dfe_ext, dfe_fixture TO ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.capability_types FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.capability_types FROM ${READER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.capability_types TO ${READER_ROLE};
GRANT EXECUTE ON FUNCTION dfe_ext.digest(bytea, text) TO ${READER_ROLE};
GRANT EXECUTE ON FUNCTION dfe_ext.digest(text, text) TO ${READER_ROLE};
SQL

capability_state="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT (SELECT count(*) FROM pg_extension WHERE extname = 'pgcrypto') = 0 AND (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dfe_ext' AND p.proname = 'digest' AND p.prorettype = 'bytea'::regtype AND p.provolatile = 'i' AND p.proisstrict) = 2 AND has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'CONNECT') AND NOT has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'CREATE') AND NOT has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'TEMP') AND has_schema_privilege('${READER_ROLE}', 'dfe_ext', 'USAGE') AND has_schema_privilege('${READER_ROLE}', 'dfe_fixture', 'USAGE') AND NOT has_schema_privilege('${READER_ROLE}', 'dfe_fixture', 'CREATE') AND has_table_privilege('${READER_ROLE}', 'dfe_fixture.capability_types', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.capability_types', 'INSERT') AND has_function_privilege('${READER_ROLE}', 'dfe_ext.digest(bytea,text)', 'EXECUTE') AND has_function_privilege('${READER_ROLE}', 'dfe_ext.digest(text,text)', 'EXECUTE') AND NOT has_function_privilege('${READER_ROLE}', 'dfe_ext.hmac(bytea,bytea,text)', 'EXECUTE') AND encode(dfe_ext.digest('dfe-greenplum-capability'::text, 'sha256'), 'hex') = '${EXPECTED_SHA256}';")"
if [[ "${capability_state}" != t ]]; then
  fail 'reader privileges or pgcrypto SHA-256 capability do not match the required state'
fi

role_state="$(query_scalar template1 \
  "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND array_to_string(rolconfig, ',') LIKE '%default_transaction_read_only=on%' FROM pg_roles WHERE rolname = '${READER_ROLE}';")"
if [[ "${role_state}" != t ]]; then
  fail 'reader role attributes do not match the required read-only state'
fi
membership_count="$(query_scalar template1 \
  "SELECT count(*) FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = '${READER_ROLE}');")"
require_count "${membership_count}" 0 'reader role membership count'
owned_object_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT (SELECT count(*) FROM pg_namespace WHERE nspowner = (SELECT oid FROM pg_roles WHERE rolname = '${READER_ROLE}')) + (SELECT count(*) FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = '${READER_ROLE}')) + (SELECT count(*) FROM pg_proc WHERE proowner = (SELECT oid FROM pg_roles WHERE rolname = '${READER_ROLE}'));")"
require_count "${owned_object_count}" 0 'reader-owned object count'

if ! grep --fixed-strings --line-regexp --quiet "${HBA_LINE}" "${HBA_FILE}"; then
  printf '%s\n' "${HBA_LINE}" >>"${HBA_FILE}"
fi
hba_line_count="$(awk -v expected="${HBA_LINE}" '$0 == expected { count += 1 } END { print count + 0 }' "${HBA_FILE}")"
require_count "${hba_line_count}" 1 'coordinator reader HBA line count'
reload_state="$(query_scalar template1 'SELECT pg_reload_conf();')"
if [[ "${reload_state}" != t ]]; then
  fail 'coordinator configuration reload returned false'
fi
