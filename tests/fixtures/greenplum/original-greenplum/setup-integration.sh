#!/usr/bin/env bash
set -euo pipefail

readonly GREENPLUM_HOME=/usr/local/gpdb
readonly MASTER_DATA_DIRECTORY=/home/gpadmin/gpdemo-data/qddir/demoDataDir-1
readonly READER_ROLE=dfe_original_greenplum_reader
readonly WRITER_ROLE=dfe_original_greenplum_writer
readonly FIXTURE_DATABASE=dfe_fixture
readonly EXPECTED_SHA256=a19a1686cc6fb7aeaef72c8b287ef52d4a0084b323193919c0d3b84e977210ee
readonly CANONICAL_MULTIPLICITY=32768
readonly SNAPSHOT_MULTIPLICITY=32
readonly PGCRYPTO_SQL=/usr/local/gpdb/share/postgresql/contrib/pgcrypto.sql
readonly HBA_FILE=/home/gpadmin/gpdemo-data/qddir/demoDataDir-1/pg_hba.conf
readonly READER_HBA_LINE='host dfe_fixture dfe_original_greenplum_reader samenet md5'
readonly WRITER_HBA_LINE='host dfe_fixture dfe_original_greenplum_writer samenet md5'
readonly EXPECTED_COLUMNS=$'record_id|bigint|t\namount|numeric(38,4)|t\nactive|boolean|t\nlabel|text|t\nbusiness_date|date|t\nlocal_time|timestamp(6) without time zone|t\ninstant_time|timestamp(6) with time zone|t\nignored_payload|bytea|f'
readonly EXPECTED_CANONICAL_COLUMNS=$'distribution_id|bigint|t\nid|bigint|t\namount|numeric(38,3)|t\nactive|boolean|t\nlabel|text|t\nbusiness_date|date|t\nlocal_time|timestamp(6) without time zone|t\ninstant_time|timestamp(6) with time zone|t'
readonly EXPECTED_ENDPOINT_COLUMNS=$'order_id|bigint|t\nbusiness_date|date|t\nprecise_amount|numeric(38,7)|f\nlocal_time|timestamp(6) without time zone|t\ninstant_time|timestamp(6) with time zone|t'
readonly EXPECTED_ENDPOINT_MANIFEST_COLUMNS=$'dataset_id|text|t\nscope_digest|text|t\nbatch_id|text|t\nstate|text|t\nbusiness_date|date|t\nsource_cut|text|f\ndataset_version|text|f\ncompleted_at|timestamp(6) with time zone|f'
readonly -a SNAPSHOT_RELATIONS=(snapshot_heap_values snapshot_ao_values snapshot_aoco_values)
readonly -a SNAPSHOT_STORAGE_CLAUSES=(
  'WITH (appendonly=false)'
  'WITH (appendonly=true, orientation=row, blocksize=32768, compresstype=none, compresslevel=0, checksum=true)'
  'WITH (appendonly=true, orientation=column, blocksize=32768, compresstype=none, compresslevel=0, checksum=true)'
)
readonly -a SNAPSHOT_STORAGE_CODES=(h a c)
readonly -a SNAPSHOT_APPENDONLY_COUNTS=(0 1 1)
readonly -a SNAPSHOT_APPENDONLY_STATES=('' '32768|0|t|none|row' '32768|0|t|none|column')
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

password_verifier_from_file() {
  local password_file="$1"
  local role_name="$2"
  local role_label="$3"
  local role_password
  local password_digest

  if [[ ! -f "${password_file}" ]]; then
    fail "${role_label} password secret file does not exist: ${password_file}"
  fi
  if [[ ! -s "${password_file}" ]]; then
    fail "${role_label} password secret file is empty: ${password_file}"
  fi
  role_password="$(<"${password_file}")"
  if [[ -z "${role_password}" ]]; then
    fail "${role_label} password secret file contains no password: ${password_file}"
  fi
  if [[ "${role_password}" == *$'\n'* || "${role_password}" == *$'\r'* ]]; then
    fail "${role_label} password secret file must contain exactly one line: ${password_file}"
  fi
  password_digest="$(printf '%s%s' "${role_password}" "${role_name}" | md5sum | cut --delimiter=' ' --fields=1)"
  unset role_password
  printf 'md5%s\n' "${password_digest}"
}

if (( $# != 2 )); then
  fail 'expected the reader and writer password secret-file paths as arguments'
fi
readonly READER_PASSWORD_FILE="$1"
readonly WRITER_PASSWORD_FILE="$2"
readonly reader_password_verifier="$(password_verifier_from_file "${READER_PASSWORD_FILE}" "${READER_ROLE}" reader)"
readonly writer_password_verifier="$(password_verifier_from_file "${WRITER_PASSWORD_FILE}" "${WRITER_ROLE}" writer)"

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
  "${READER_ROLE}" "${reader_password_verifier}" \
  | psql_as_gpadmin template1
printf "ALTER ROLE %s SET default_transaction_read_only = 'off';\n" "${READER_ROLE}" \
  | psql_as_gpadmin template1

role_count="$(query_scalar template1 \
  "SELECT count(*) FROM pg_roles WHERE rolname = '${WRITER_ROLE}';")"
case "${role_count}" in
  0)
    printf 'CREATE ROLE %s;\n' "${WRITER_ROLE}" | psql_as_gpadmin template1
    ;;
  1) ;;
  *) fail "writer role catalog lookup returned ${role_count} rows" ;;
esac
printf "ALTER ROLE %s WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '%s';\n" \
  "${WRITER_ROLE}" "${writer_password_verifier}" \
  | psql_as_gpadmin template1
printf "ALTER ROLE %s SET default_transaction_read_only = 'off';\n" "${WRITER_ROLE}" \
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
  "SELECT 'REVOKE ALL PRIVILEGES ON FUNCTION ' || quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || oidvectortypes(p.proargtypes) || ') FROM PUBLIC; REVOKE ALL PRIVILEGES ON FUNCTION ' || quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || oidvectortypes(p.proargtypes) || ') FROM ${READER_ROLE}; REVOKE ALL PRIVILEGES ON FUNCTION ' || quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || oidvectortypes(p.proargtypes) || ') FROM ${WRITER_ROLE};' FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dfe_ext' ORDER BY p.oid;")"
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

for relation_name in canonical_values canonical_empty_values; do
  table_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = '${relation_name}' AND c.relkind = 'r';")"
  case "${table_count}" in
    0)
      psql_as_gpadmin "${FIXTURE_DATABASE}" <<SQL
CREATE TABLE dfe_fixture.${relation_name} (
  distribution_id bigint NOT NULL,
  id bigint NOT NULL,
  amount numeric(38, 3) NOT NULL,
  active boolean NOT NULL,
  label text NOT NULL,
  business_date date NOT NULL,
  local_time timestamp(6) without time zone NOT NULL,
  instant_time timestamp(6) with time zone NOT NULL
) DISTRIBUTED BY (distribution_id);
SQL
      ;;
    1) ;;
    *) fail "${relation_name} catalog lookup returned ${table_count} rows" ;;
  esac
  observed_canonical_columns="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT a.attname || '|' || format_type(a.atttypid, a.atttypmod) || '|' || CASE WHEN a.attnotnull THEN 't' ELSE 'f' END FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = '${relation_name}' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum;")"
  if [[ "${observed_canonical_columns}" != "${EXPECTED_CANONICAL_COLUMNS}" ]]; then
    fail "${relation_name} has an unexpected physical schema"
  fi
  canonical_distribution_key="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT array_to_string(attrnums, ',') FROM gp_distribution_policy WHERE localoid = 'dfe_fixture.${relation_name}'::regclass;")"
  if [[ "${canonical_distribution_key}" != 1 ]]; then
    fail "${relation_name} must be distributed by distribution_id, observed policy key ${canonical_distribution_key}"
  fi
done

for snapshot_index in "${!SNAPSHOT_RELATIONS[@]}"; do
  relation_name="${SNAPSHOT_RELATIONS[${snapshot_index}]}"
  storage_clause="${SNAPSHOT_STORAGE_CLAUSES[${snapshot_index}]}"
  expected_storage_code="${SNAPSHOT_STORAGE_CODES[${snapshot_index}]}"
  expected_appendonly_count="${SNAPSHOT_APPENDONLY_COUNTS[${snapshot_index}]}"
  expected_appendonly_state="${SNAPSHOT_APPENDONLY_STATES[${snapshot_index}]}"

  table_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = '${relation_name}' AND c.relkind = 'r';")"
  case "${table_count}" in
    0)
      psql_as_gpadmin "${FIXTURE_DATABASE}" <<SQL
CREATE TABLE dfe_fixture.${relation_name} (
  distribution_id bigint NOT NULL,
  id bigint NOT NULL,
  amount numeric(38, 3) NOT NULL,
  active boolean NOT NULL,
  label text NOT NULL,
  business_date date NOT NULL,
  local_time timestamp(6) without time zone NOT NULL,
  instant_time timestamp(6) with time zone NOT NULL
) ${storage_clause} DISTRIBUTED BY (distribution_id);
SQL
      ;;
    1) ;;
    *) fail "${relation_name} catalog lookup returned ${table_count} rows" ;;
  esac

  observed_snapshot_columns="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT a.attname || '|' || format_type(a.atttypid, a.atttypmod) || '|' || CASE WHEN a.attnotnull THEN 't' ELSE 'f' END FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = '${relation_name}' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum;")"
  if [[ "${observed_snapshot_columns}" != "${EXPECTED_CANONICAL_COLUMNS}" ]]; then
    fail "${relation_name} has an unexpected physical schema; retained fixture tables are never replaced"
  fi
  physical_attribute_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_attribute WHERE attrelid = 'dfe_fixture.${relation_name}'::regclass AND attnum > 0;")"
  require_count "${physical_attribute_count}" 8 \
    "${relation_name} physical attribute count including dropped columns"
  snapshot_owner="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'dfe_fixture.${relation_name}'::regclass;")"
  if [[ "${snapshot_owner}" != gpadmin ]]; then
    fail "${relation_name} owner must be gpadmin, observed ${snapshot_owner}"
  fi
  snapshot_default_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_attrdef WHERE adrelid = 'dfe_fixture.${relation_name}'::regclass;")"
  require_count "${snapshot_default_count}" 0 "${relation_name} column default count"
  snapshot_constraint_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_constraint WHERE conrelid = 'dfe_fixture.${relation_name}'::regclass;")"
  require_count "${snapshot_constraint_count}" 0 "${relation_name} table constraint count"
  snapshot_index_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_index WHERE indrelid = 'dfe_fixture.${relation_name}'::regclass;")"
  require_count "${snapshot_index_count}" 0 "${relation_name} index count"
  snapshot_distribution_key="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT array_to_string(attrnums, ',') FROM gp_distribution_policy WHERE localoid = 'dfe_fixture.${relation_name}'::regclass;")"
  if [[ "${snapshot_distribution_key}" != 1 ]]; then
    fail "${relation_name} must be distributed by distribution_id, observed policy key ${snapshot_distribution_key}; retained fixture tables are never redistributed"
  fi
  observed_storage_code="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT c.relstorage FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = '${relation_name}';")"
  if [[ "${observed_storage_code}" != "${expected_storage_code}" ]]; then
    fail "${relation_name} has storage code ${observed_storage_code}, expected ${expected_storage_code}; retained fixture tables are never converted"
  fi
  appendonly_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_appendonly WHERE relid = 'dfe_fixture.${relation_name}'::regclass;")"
  require_count "${appendonly_count}" "${expected_appendonly_count}" \
    "${relation_name} pg_appendonly row count"
  if [[ "${expected_appendonly_count}" == 1 ]]; then
    observed_appendonly_state="$(query_scalar "${FIXTURE_DATABASE}" \
      "SELECT blocksize::text || '|' || compresslevel::text || '|' || CASE WHEN checksum THEN 't' ELSE 'f' END || '|' || CASE WHEN compresstype::text = '' THEN 'none' ELSE compresstype::text END || '|' || CASE WHEN columnstore THEN 'column' ELSE 'row' END FROM pg_appendonly WHERE relid = 'dfe_fixture.${relation_name}'::regclass;")"
    if [[ "${observed_appendonly_state}" != "${expected_appendonly_state}" ]]; then
      fail "${relation_name} has append-optimized state ${observed_appendonly_state}, expected ${expected_appendonly_state}; retained fixture tables are never converted"
    fi
  fi
done

comparison_orders_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = 'comparison_orders' AND c.relkind = 'r';")"
case "${comparison_orders_count}" in
  0)
    psql_as_gpadmin "${FIXTURE_DATABASE}" <<'SQL'
CREATE TABLE dfe_fixture.comparison_orders (
  order_id bigint NOT NULL,
  business_date date NOT NULL,
  precise_amount numeric(38, 7) NULL,
  local_time timestamp(6) without time zone NOT NULL,
  instant_time timestamp(6) with time zone NOT NULL,
  PRIMARY KEY (order_id)
) WITH (appendonly=false) DISTRIBUTED BY (order_id);
SQL
    ;;
  1) ;;
  *) fail "comparison_orders catalog lookup returned ${comparison_orders_count} rows" ;;
esac

comparison_manifest_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = 'comparison_batch_manifest' AND c.relkind = 'r';")"
case "${comparison_manifest_count}" in
  0)
    psql_as_gpadmin "${FIXTURE_DATABASE}" <<'SQL'
CREATE TABLE dfe_fixture.comparison_batch_manifest (
  dataset_id text NOT NULL,
  scope_digest text NOT NULL,
  batch_id text NOT NULL,
  state text NOT NULL,
  business_date date NOT NULL,
  source_cut text NULL,
  dataset_version text NULL,
  completed_at timestamp(6) with time zone NULL,
  PRIMARY KEY (dataset_id, scope_digest)
) WITH (appendonly=false) DISTRIBUTED BY (dataset_id, scope_digest);
SQL
    ;;
  1) ;;
  *) fail "comparison_batch_manifest catalog lookup returned ${comparison_manifest_count} rows" ;;
esac

observed_comparison_columns="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT a.attname || '|' || format_type(a.atttypid, a.atttypmod) || '|' || CASE WHEN a.attnotnull THEN 't' ELSE 'f' END FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = 'comparison_orders' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum;")"
if [[ "${observed_comparison_columns}" != "${EXPECTED_ENDPOINT_COLUMNS}" ]]; then
  fail 'comparison_orders has an unexpected physical schema'
fi
comparison_physical_attribute_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_attribute WHERE attrelid = 'dfe_fixture.comparison_orders'::regclass AND attnum > 0;")"
require_count "${comparison_physical_attribute_count}" 5 \
  'comparison_orders physical attribute count including dropped columns'
comparison_owner="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'dfe_fixture.comparison_orders'::regclass;")"
if [[ "${comparison_owner}" != gpadmin ]]; then
  fail "comparison_orders owner must be gpadmin, observed ${comparison_owner}"
fi
comparison_storage_code="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT relstorage FROM pg_class WHERE oid = 'dfe_fixture.comparison_orders'::regclass;")"
if [[ "${comparison_storage_code}" != h ]]; then
  fail "comparison_orders must use heap storage, observed storage code ${comparison_storage_code}"
fi
comparison_appendonly_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_appendonly WHERE relid = 'dfe_fixture.comparison_orders'::regclass;")"
require_count "${comparison_appendonly_count}" 0 'comparison_orders pg_appendonly row count'
comparison_distribution_key="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT array_to_string(attrnums, ',') FROM gp_distribution_policy WHERE localoid = 'dfe_fixture.comparison_orders'::regclass;")"
if [[ "${comparison_distribution_key}" != 1 ]]; then
  fail "comparison_orders must be distributed by order_id, observed policy key ${comparison_distribution_key}"
fi
comparison_default_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_attrdef WHERE adrelid = 'dfe_fixture.comparison_orders'::regclass;")"
require_count "${comparison_default_count}" 0 'comparison_orders column default count'
comparison_constraint_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_constraint WHERE conrelid = 'dfe_fixture.comparison_orders'::regclass;")"
require_count "${comparison_constraint_count}" 1 'comparison_orders table constraint count'
comparison_index_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_index WHERE indrelid = 'dfe_fixture.comparison_orders'::regclass;")"
require_count "${comparison_index_count}" 1 'comparison_orders index count'
comparison_primary_constraint_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_constraint WHERE conrelid = 'dfe_fixture.comparison_orders'::regclass AND conname = 'comparison_orders_pkey' AND contype = 'p' AND conkey::text = '{1}' AND NOT condeferrable AND NOT condeferred;")"
require_count "${comparison_primary_constraint_count}" 1 \
  'comparison_orders primary key constraint definition count'
comparison_primary_index_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_index index_record JOIN pg_class index_relation ON index_relation.oid = index_record.indexrelid JOIN pg_namespace index_namespace ON index_namespace.oid = index_relation.relnamespace JOIN pg_am access_method ON access_method.oid = index_relation.relam WHERE index_record.indrelid = 'dfe_fixture.comparison_orders'::regclass AND index_namespace.nspname = 'dfe_fixture' AND index_relation.relname = 'comparison_orders_pkey' AND index_record.indnatts = 1 AND index_record.indkey::text = '1' AND index_record.indisunique AND index_record.indisprimary AND index_record.indisvalid AND index_record.indisready AND index_record.indexprs IS NULL AND index_record.indpred IS NULL AND access_method.amname = 'btree' AND pg_get_userbyid(index_relation.relowner) = 'gpadmin';")"
require_count "${comparison_primary_index_count}" 1 \
  'comparison_orders primary B-tree index definition count'

observed_comparison_manifest_columns="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT a.attname || '|' || format_type(a.atttypid, a.atttypmod) || '|' || CASE WHEN a.attnotnull THEN 't' ELSE 'f' END FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = 'comparison_batch_manifest' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum;")"
if [[ "${observed_comparison_manifest_columns}" != "${EXPECTED_ENDPOINT_MANIFEST_COLUMNS}" ]]; then
  fail 'comparison_batch_manifest has an unexpected physical schema'
fi
comparison_manifest_physical_attribute_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_attribute WHERE attrelid = 'dfe_fixture.comparison_batch_manifest'::regclass AND attnum > 0;")"
require_count "${comparison_manifest_physical_attribute_count}" 8 \
  'comparison_batch_manifest physical attribute count including dropped columns'
comparison_manifest_owner="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'dfe_fixture.comparison_batch_manifest'::regclass;")"
if [[ "${comparison_manifest_owner}" != gpadmin ]]; then
  fail "comparison_batch_manifest owner must be gpadmin, observed ${comparison_manifest_owner}"
fi
comparison_manifest_storage_code="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT relstorage FROM pg_class WHERE oid = 'dfe_fixture.comparison_batch_manifest'::regclass;")"
if [[ "${comparison_manifest_storage_code}" != h ]]; then
  fail "comparison_batch_manifest must use heap storage, observed storage code ${comparison_manifest_storage_code}"
fi
comparison_manifest_appendonly_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_appendonly WHERE relid = 'dfe_fixture.comparison_batch_manifest'::regclass;")"
require_count "${comparison_manifest_appendonly_count}" 0 \
  'comparison_batch_manifest pg_appendonly row count'
comparison_manifest_distribution_key="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT array_to_string(attrnums, ',') FROM gp_distribution_policy WHERE localoid = 'dfe_fixture.comparison_batch_manifest'::regclass;")"
if [[ "${comparison_manifest_distribution_key}" != 1,2 ]]; then
  fail "comparison_batch_manifest must be distributed by dataset_id and scope_digest, observed policy key ${comparison_manifest_distribution_key}"
fi
comparison_manifest_default_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_attrdef WHERE adrelid = 'dfe_fixture.comparison_batch_manifest'::regclass;")"
require_count "${comparison_manifest_default_count}" 0 \
  'comparison_batch_manifest column default count'
comparison_manifest_constraint_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_constraint WHERE conrelid = 'dfe_fixture.comparison_batch_manifest'::regclass;")"
require_count "${comparison_manifest_constraint_count}" 1 \
  'comparison_batch_manifest table constraint count'
comparison_manifest_index_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_index WHERE indrelid = 'dfe_fixture.comparison_batch_manifest'::regclass;")"
require_count "${comparison_manifest_index_count}" 1 \
  'comparison_batch_manifest index count'
comparison_manifest_primary_constraint_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_constraint WHERE conrelid = 'dfe_fixture.comparison_batch_manifest'::regclass AND conname = 'comparison_batch_manifest_pkey' AND contype = 'p' AND conkey::text = '{1,2}' AND NOT condeferrable AND NOT condeferred;")"
require_count "${comparison_manifest_primary_constraint_count}" 1 \
  'comparison_batch_manifest primary key constraint definition count'
comparison_manifest_primary_index_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_index index_record JOIN pg_class index_relation ON index_relation.oid = index_record.indexrelid JOIN pg_namespace index_namespace ON index_namespace.oid = index_relation.relnamespace JOIN pg_am access_method ON access_method.oid = index_relation.relam WHERE index_record.indrelid = 'dfe_fixture.comparison_batch_manifest'::regclass AND index_namespace.nspname = 'dfe_fixture' AND index_relation.relname = 'comparison_batch_manifest_pkey' AND index_record.indnatts = 2 AND index_record.indkey::text = '1 2' AND index_record.indisunique AND index_record.indisprimary AND index_record.indisvalid AND index_record.indisready AND index_record.indexprs IS NULL AND index_record.indpred IS NULL AND access_method.amname = 'btree' AND pg_get_userbyid(index_relation.relowner) = 'gpadmin';")"
require_count "${comparison_manifest_primary_index_count}" 1 \
  'comparison_batch_manifest primary B-tree index definition count'

psql_as_gpadmin "${FIXTURE_DATABASE}" <<'SQL'
BEGIN;
TRUNCATE TABLE dfe_fixture.comparison_orders;
TRUNCATE TABLE dfe_fixture.comparison_batch_manifest;
COMMIT;
SQL

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

psql_as_gpadmin "${FIXTURE_DATABASE}" <<SQL
TRUNCATE TABLE dfe_fixture.canonical_values;
TRUNCATE TABLE dfe_fixture.canonical_empty_values;
INSERT INTO dfe_fixture.canonical_values (
  distribution_id,
  id,
  amount,
  active,
  label,
  business_date,
  local_time,
  instant_time
)
SELECT
  generated.distribution_id,
  (-9223372036854775807::bigint - 1),
  (-1780.000)::numeric(38, 3),
  TRUE,
  'A|Б😀é  ',
  DATE '2024-02-29',
  TIMESTAMP '2024-02-29 23:59:58.123456',
  TIMESTAMP WITH TIME ZONE '2024-02-29 21:29:58.123456+00'
FROM generate_series(1, ${CANONICAL_MULTIPLICITY}) AS generated(distribution_id);
SQL

psql_as_gpadmin "${FIXTURE_DATABASE}" <<SQL
BEGIN;
TRUNCATE TABLE
  dfe_fixture.snapshot_heap_values,
  dfe_fixture.snapshot_ao_values,
  dfe_fixture.snapshot_aoco_values;
INSERT INTO dfe_fixture.snapshot_heap_values (
  distribution_id,
  id,
  amount,
  active,
  label,
  business_date,
  local_time,
  instant_time
)
SELECT
  generated.distribution_id,
  (-9223372036854775807::bigint - 1),
  (-1780.000)::numeric(38, 3),
  TRUE,
  'A|Б😀é  ',
  DATE '2024-02-29',
  TIMESTAMP '2024-02-29 23:59:58.123456',
  TIMESTAMP WITH TIME ZONE '2024-02-29 21:29:58.123456+00'
FROM generate_series(1, ${SNAPSHOT_MULTIPLICITY}) AS generated(distribution_id)
ORDER BY generated.distribution_id;
INSERT INTO dfe_fixture.snapshot_ao_values (
  distribution_id,
  id,
  amount,
  active,
  label,
  business_date,
  local_time,
  instant_time
)
SELECT
  generated.distribution_id,
  (-9223372036854775807::bigint - 1),
  (-1780.000)::numeric(38, 3),
  TRUE,
  'A|Б😀é  ',
  DATE '2024-02-29',
  TIMESTAMP '2024-02-29 23:59:58.123456',
  TIMESTAMP WITH TIME ZONE '2024-02-29 21:29:58.123456+00'
FROM generate_series(1, ${SNAPSHOT_MULTIPLICITY}) AS generated(distribution_id)
ORDER BY generated.distribution_id;
INSERT INTO dfe_fixture.snapshot_aoco_values (
  distribution_id,
  id,
  amount,
  active,
  label,
  business_date,
  local_time,
  instant_time
)
SELECT
  generated.distribution_id,
  (-9223372036854775807::bigint - 1),
  (-1780.000)::numeric(38, 3),
  TRUE,
  'A|Б😀é  ',
  DATE '2024-02-29',
  TIMESTAMP '2024-02-29 23:59:58.123456',
  TIMESTAMP WITH TIME ZONE '2024-02-29 21:29:58.123456+00'
FROM generate_series(1, ${SNAPSHOT_MULTIPLICITY}) AS generated(distribution_id)
ORDER BY generated.distribution_id;
COMMIT;
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
canonical_row_count="$(query_scalar "${FIXTURE_DATABASE}" \
  'SELECT count(*) FROM dfe_fixture.canonical_values;')"
require_count "${canonical_row_count}" "${CANONICAL_MULTIPLICITY}" \
  'canonical_values row count'
canonical_primary_count="$(query_scalar "${FIXTURE_DATABASE}" \
  'SELECT count(DISTINCT gp_segment_id) FROM dfe_fixture.canonical_values;')"
require_count "${canonical_primary_count}" "${primary_count}" \
  'canonical_values covered primary segment count'
canonical_empty_count="$(query_scalar "${FIXTURE_DATABASE}" \
  'SELECT count(*) FROM dfe_fixture.canonical_empty_values;')"
require_count "${canonical_empty_count}" 0 'canonical_empty_values row count'
comparison_orders_row_count="$(query_scalar "${FIXTURE_DATABASE}" \
  'SELECT count(*) FROM dfe_fixture.comparison_orders;')"
require_count "${comparison_orders_row_count}" 0 'comparison_orders initial row count'
comparison_manifest_row_count="$(query_scalar "${FIXTURE_DATABASE}" \
  'SELECT count(*) FROM dfe_fixture.comparison_batch_manifest;')"
require_count "${comparison_manifest_row_count}" 0 \
  'comparison_batch_manifest initial row count'

for relation_name in "${SNAPSHOT_RELATIONS[@]}"; do
  snapshot_row_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM dfe_fixture.${relation_name};")"
  require_count "${snapshot_row_count}" "${SNAPSHOT_MULTIPLICITY}" \
    "${relation_name} row count"
  snapshot_key_state="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT min(distribution_id)::text || '|' || max(distribution_id)::text || '|' || count(DISTINCT distribution_id)::text FROM dfe_fixture.${relation_name};")"
  if [[ "${snapshot_key_state}" != "1|${SNAPSHOT_MULTIPLICITY}|${SNAPSHOT_MULTIPLICITY}" ]]; then
    fail "${relation_name} distribution IDs are not the deterministic 1..${SNAPSHOT_MULTIPLICITY} seed"
  fi
  snapshot_payload_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM dfe_fixture.${relation_name} WHERE id = (-9223372036854775807::bigint - 1) AND amount = (-1780.000)::numeric(38, 3) AND active AND label = 'A|Б😀é  ' AND business_date = DATE '2024-02-29' AND local_time = TIMESTAMP '2024-02-29 23:59:58.123456' AND instant_time = TIMESTAMP WITH TIME ZONE '2024-02-29 21:29:58.123456+00';")"
  require_count "${snapshot_payload_count}" "${SNAPSHOT_MULTIPLICITY}" \
    "${relation_name} golden payload row count"
  reserved_writer_row_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM dfe_fixture.${relation_name} WHERE distribution_id = 33;")"
  require_count "${reserved_writer_row_count}" 0 \
    "${relation_name} reserved writer row count"
  snapshot_primary_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(DISTINCT gp_segment_id) FROM dfe_fixture.${relation_name};")"
  require_count "${snapshot_primary_count}" "${primary_count}" \
    "${relation_name} covered primary segment count"
done

psql_as_gpadmin "${FIXTURE_DATABASE}" <<SQL
REVOKE ALL PRIVILEGES ON DATABASE ${FIXTURE_DATABASE} FROM PUBLIC;
REVOKE ALL PRIVILEGES ON DATABASE ${FIXTURE_DATABASE} FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON DATABASE ${FIXTURE_DATABASE} FROM ${WRITER_ROLE};
GRANT CONNECT ON DATABASE ${FIXTURE_DATABASE} TO ${READER_ROLE};
GRANT CONNECT ON DATABASE ${FIXTURE_DATABASE} TO ${WRITER_ROLE};
REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA dfe_ext FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA dfe_ext FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON SCHEMA dfe_ext FROM ${WRITER_ROLE};
REVOKE ALL PRIVILEGES ON SCHEMA dfe_fixture FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA dfe_fixture FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON SCHEMA dfe_fixture FROM ${WRITER_ROLE};
GRANT USAGE ON SCHEMA dfe_ext, dfe_fixture TO ${READER_ROLE};
GRANT USAGE ON SCHEMA dfe_fixture TO ${WRITER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.capability_types FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.capability_types FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.capability_types FROM ${WRITER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.capability_types TO ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.canonical_values FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.canonical_values FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.canonical_values FROM ${WRITER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.canonical_values TO ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.canonical_empty_values FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.canonical_empty_values FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.canonical_empty_values FROM ${WRITER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.canonical_empty_values TO ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.comparison_orders FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.comparison_orders FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.comparison_orders FROM ${WRITER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.comparison_orders TO ${READER_ROLE};
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE dfe_fixture.comparison_orders TO ${WRITER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.comparison_batch_manifest FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.comparison_batch_manifest FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.comparison_batch_manifest FROM ${WRITER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.comparison_batch_manifest TO ${READER_ROLE};
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE dfe_fixture.comparison_batch_manifest TO ${WRITER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_heap_values FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_heap_values FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_heap_values FROM ${WRITER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.snapshot_heap_values TO ${READER_ROLE};
GRANT SELECT, INSERT, DELETE ON TABLE dfe_fixture.snapshot_heap_values TO ${WRITER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_ao_values FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_ao_values FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_ao_values FROM ${WRITER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.snapshot_ao_values TO ${READER_ROLE};
GRANT SELECT, INSERT, DELETE ON TABLE dfe_fixture.snapshot_ao_values TO ${WRITER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_aoco_values FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_aoco_values FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON TABLE dfe_fixture.snapshot_aoco_values FROM ${WRITER_ROLE};
GRANT SELECT ON TABLE dfe_fixture.snapshot_aoco_values TO ${READER_ROLE};
GRANT SELECT, INSERT, DELETE ON TABLE dfe_fixture.snapshot_aoco_values TO ${WRITER_ROLE};
GRANT EXECUTE ON FUNCTION dfe_ext.digest(bytea, text) TO ${READER_ROLE};
GRANT EXECUTE ON FUNCTION dfe_ext.digest(text, text) TO ${READER_ROLE};
SQL

capability_state="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT (SELECT count(*) FROM pg_extension WHERE extname = 'pgcrypto') = 0 AND (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'dfe_ext' AND p.proname = 'digest' AND p.prorettype = 'bytea'::regtype AND p.provolatile = 'i' AND p.proisstrict) = 2 AND has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'CONNECT') AND NOT has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'CREATE') AND NOT has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'TEMP') AND has_schema_privilege('${READER_ROLE}', 'dfe_ext', 'USAGE') AND has_schema_privilege('${READER_ROLE}', 'dfe_fixture', 'USAGE') AND NOT has_schema_privilege('${READER_ROLE}', 'dfe_fixture', 'CREATE') AND has_table_privilege('${READER_ROLE}', 'dfe_fixture.capability_types', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.capability_types', 'INSERT') AND has_function_privilege('${READER_ROLE}', 'dfe_ext.digest(bytea,text)', 'EXECUTE') AND has_function_privilege('${READER_ROLE}', 'dfe_ext.digest(text,text)', 'EXECUTE') AND NOT has_function_privilege('${READER_ROLE}', 'dfe_ext.hmac(bytea,bytea,text)', 'EXECUTE') AND encode(dfe_ext.digest('dfe-greenplum-capability'::text, 'sha256'), 'hex') = '${EXPECTED_SHA256}';")"
if [[ "${capability_state}" != t ]]; then
  fail 'reader privileges or pgcrypto SHA-256 capability do not match the required state'
fi
writer_scope_state="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT has_database_privilege('${WRITER_ROLE}', '${FIXTURE_DATABASE}', 'CONNECT') AND NOT has_database_privilege('${WRITER_ROLE}', '${FIXTURE_DATABASE}', 'CREATE') AND NOT has_database_privilege('${WRITER_ROLE}', '${FIXTURE_DATABASE}', 'TEMP') AND NOT has_schema_privilege('${WRITER_ROLE}', 'dfe_ext', 'USAGE') AND has_schema_privilege('${WRITER_ROLE}', 'dfe_fixture', 'USAGE') AND NOT has_schema_privilege('${WRITER_ROLE}', 'dfe_fixture', 'CREATE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.capability_types', 'SELECT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.capability_types', 'INSERT') AND NOT has_function_privilege('${WRITER_ROLE}', 'dfe_ext.digest(bytea,text)', 'EXECUTE') AND NOT has_function_privilege('${WRITER_ROLE}', 'dfe_ext.digest(text,text)', 'EXECUTE');")"
if [[ "${writer_scope_state}" != t ]]; then
  fail 'writer database, schema, capability-table, or function privileges exceed the required scope'
fi
canonical_privilege_state="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT has_table_privilege('${READER_ROLE}', 'dfe_fixture.canonical_values', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.canonical_values', 'INSERT') AND has_table_privilege('${READER_ROLE}', 'dfe_fixture.canonical_empty_values', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.canonical_empty_values', 'INSERT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_values', 'SELECT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_values', 'INSERT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_values', 'DELETE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_empty_values', 'SELECT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_empty_values', 'INSERT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_empty_values', 'DELETE');")"
if [[ "${canonical_privilege_state}" != t ]]; then
  fail 'reader or writer privileges on canonical relations do not match the required state'
fi

for relation_name in comparison_orders comparison_batch_manifest; do
  comparison_privilege_state="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'INSERT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'UPDATE') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'DELETE') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'TRUNCATE') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'REFERENCES') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'TRIGGER') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'SELECT') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'INSERT') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'UPDATE') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'DELETE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'TRUNCATE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'REFERENCES') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'TRIGGER');")"
  if [[ "${comparison_privilege_state}" != t ]]; then
    fail "reader or writer privileges on ${relation_name} do not match the required state"
  fi
done

for relation_name in "${SNAPSHOT_RELATIONS[@]}"; do
  snapshot_privilege_state="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'INSERT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'UPDATE') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'DELETE') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'TRUNCATE') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'SELECT') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'INSERT') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'DELETE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'UPDATE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'TRUNCATE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'REFERENCES') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'TRIGGER');")"
  if [[ "${snapshot_privilege_state}" != t ]]; then
    fail "reader or writer privileges on ${relation_name} do not match the required state"
  fi
done

reader_role_state="$(query_scalar template1 \
  "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND array_to_string(rolconfig, ',') LIKE '%default_transaction_read_only=off%' FROM pg_roles WHERE rolname = '${READER_ROLE}';")"
if [[ "${reader_role_state}" != t ]]; then
  fail 'reader role attributes do not match the required non-admin login state'
fi
writer_role_state="$(query_scalar template1 \
  "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND array_to_string(rolconfig, ',') LIKE '%default_transaction_read_only=off%' FROM pg_roles WHERE rolname = '${WRITER_ROLE}';")"
if [[ "${writer_role_state}" != t ]]; then
  fail 'writer role attributes do not match the required narrow read-write state'
fi
for role_name in "${READER_ROLE}" "${WRITER_ROLE}"; do
  membership_count="$(query_scalar template1 \
    "SELECT count(*) FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = '${role_name}') OR roleid = (SELECT oid FROM pg_roles WHERE rolname = '${role_name}');")"
  require_count "${membership_count}" 0 "${role_name} role membership count"
  owned_object_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT (SELECT count(*) FROM pg_namespace WHERE nspowner = (SELECT oid FROM pg_roles WHERE rolname = '${role_name}')) + (SELECT count(*) FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = '${role_name}')) + (SELECT count(*) FROM pg_proc WHERE proowner = (SELECT oid FROM pg_roles WHERE rolname = '${role_name}'));")"
  require_count "${owned_object_count}" 0 "${role_name}-owned object count"
done

for hba_line in "${READER_HBA_LINE}" "${WRITER_HBA_LINE}"; do
  if ! grep --fixed-strings --line-regexp --quiet "${hba_line}" "${HBA_FILE}"; then
    printf '%s\n' "${hba_line}" >>"${HBA_FILE}"
  fi
  hba_line_count="$(awk -v expected="${hba_line}" '$0 == expected { count += 1 } END { print count + 0 }' "${HBA_FILE}")"
  require_count "${hba_line_count}" 1 "coordinator HBA line count for ${hba_line}"
done
reload_state="$(query_scalar template1 'SELECT pg_reload_conf();')"
if [[ "${reload_state}" != t ]]; then
  fail 'coordinator configuration reload returned false'
fi
