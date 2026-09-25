#!/usr/bin/env bash
set -euo pipefail

readonly GREENGAGE_HOME=/opt/greengagedb/greengage7
readonly COORDINATOR_DATA_DIRECTORY=/data/coordinator/ggseg-1
readonly READER_ROLE=dfe_greengage_reader
readonly WRITER_ROLE=dfe_greengage_writer
readonly FIXTURE_DATABASE=dfe_fixture
readonly EXPECTED_SHA256=a19a1686cc6fb7aeaef72c8b287ef52d4a0084b323193919c0d3b84e977210ee
readonly CANONICAL_MULTIPLICITY=32768
readonly SNAPSHOT_MULTIPLICITY=32
readonly HBA_FILE=/data/coordinator/ggseg-1/pg_hba.conf
readonly READER_HBA_LINE='host dfe_fixture dfe_greengage_reader samenet md5'
readonly WRITER_HBA_LINE='host dfe_fixture dfe_greengage_writer samenet md5'
readonly EXPECTED_COLUMNS=$'record_id|bigint|t\namount|numeric(38,4)|t\nactive|boolean|t\nlabel|text|t\nbusiness_date|date|t\nlocal_time|timestamp(6) without time zone|t\ninstant_time|timestamp(6) with time zone|t\nignored_payload|bytea|f'
readonly EXPECTED_CANONICAL_COLUMNS=$'distribution_id|bigint|t\nid|bigint|t\namount|numeric(38,3)|t\nactive|boolean|t\nlabel|text|t\nbusiness_date|date|t\nlocal_time|timestamp(6) without time zone|t\ninstant_time|timestamp(6) with time zone|t'
readonly -a SNAPSHOT_RELATIONS=(snapshot_heap_values snapshot_ao_values snapshot_aoco_values)
readonly -a SNAPSHOT_STORAGE_CLAUSES=(
  'USING heap'
  'USING ao_row WITH (blocksize=32768, compresstype=none, compresslevel=0, checksum=true)'
  'USING ao_column WITH (blocksize=32768, compresstype=none, compresslevel=0, checksum=true)'
)
readonly -a SNAPSHOT_ACCESS_METHODS=(heap ao_row ao_column)
readonly -a SNAPSHOT_APPENDONLY_COUNTS=(0 1 1)
readonly -a SNAPSHOT_RELOPTIONS_STATES=('0|0' '4|4' '4|4')
export COORDINATOR_DATA_DIRECTORY

fail() {
  local message="$1"
  printf 'Greengage integration setup failed: %s\n' "${message}" >&2
  exit 1
}

psql_as_gpadmin() {
  local database="$1"
  shift
  runuser --user gpadmin -- \
    env HOME=/home/gpadmin USER=gpadmin LOGNAME=gpadmin \
    PATH="${GREENGAGE_HOME}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    LD_LIBRARY_PATH="${GREENGAGE_HOME}/lib" \
    COORDINATOR_DATA_DIRECTORY="${COORDINATOR_DATA_DIRECTORY}" \
    PGPORT=5432 \
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

role_count="$(query_scalar postgres \
  "SELECT count(*) FROM pg_roles WHERE rolname = '${READER_ROLE}';")"
case "${role_count}" in
  0)
    printf 'CREATE ROLE %s;\n' "${READER_ROLE}" | psql_as_gpadmin postgres
    ;;
  1) ;;
  *) fail "reader role catalog lookup returned ${role_count} rows" ;;
esac
printf "ALTER ROLE %s WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '%s';\n" \
  "${READER_ROLE}" "${reader_password_verifier}" \
  | psql_as_gpadmin postgres
printf "ALTER ROLE %s SET default_transaction_read_only = 'on';\n" "${READER_ROLE}" \
  | psql_as_gpadmin postgres

role_count="$(query_scalar postgres \
  "SELECT count(*) FROM pg_roles WHERE rolname = '${WRITER_ROLE}';")"
case "${role_count}" in
  0)
    printf 'CREATE ROLE %s;\n' "${WRITER_ROLE}" | psql_as_gpadmin postgres
    ;;
  1) ;;
  *) fail "writer role catalog lookup returned ${role_count} rows" ;;
esac
printf "ALTER ROLE %s WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '%s';\n" \
  "${WRITER_ROLE}" "${writer_password_verifier}" \
  | psql_as_gpadmin postgres
printf "ALTER ROLE %s SET default_transaction_read_only = 'off';\n" "${WRITER_ROLE}" \
  | psql_as_gpadmin postgres

database_count="$(query_scalar postgres \
  "SELECT count(*) FROM pg_database WHERE datname = '${FIXTURE_DATABASE}';")"
case "${database_count}" in
  0)
    printf "CREATE DATABASE %s OWNER gpadmin ENCODING 'UTF8';\n" "${FIXTURE_DATABASE}" \
      | psql_as_gpadmin postgres
    ;;
  1) ;;
  *) fail "fixture database catalog lookup returned ${database_count} rows" ;;
esac
database_owner="$(query_scalar postgres \
  "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '${FIXTURE_DATABASE}';")"
if [[ "${database_owner}" != gpadmin ]]; then
  fail "fixture database owner must be gpadmin, observed ${database_owner}"
fi

schema_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM pg_namespace WHERE nspname = 'dfe_fixture';")"
case "${schema_count}" in
  0)
    printf 'CREATE SCHEMA dfe_fixture AUTHORIZATION gpadmin;\n' \
      | psql_as_gpadmin "${FIXTURE_DATABASE}"
    ;;
  1) ;;
  *) fail "dfe_fixture schema catalog lookup returned ${schema_count} rows" ;;
esac
schema_owner="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'dfe_fixture';")"
if [[ "${schema_owner}" != gpadmin ]]; then
  fail "schema dfe_fixture owner must be gpadmin, observed ${schema_owner}"
fi
primary_count="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT count(*) FROM gp_segment_configuration WHERE content >= 0 AND role = 'p' AND status = 'u';")"

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
  fail 'capability_types has an unexpected physical schema'
fi
distribution_policy="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT policytype || '|' || numsegments::text || '|' || distkey::text FROM gp_distribution_policy WHERE localoid = 'dfe_fixture.capability_types'::regclass;")"
if [[ "${distribution_policy}" != "p|${primary_count}|1" ]]; then
  fail "capability_types must be distributed by record_id, observed policy ${distribution_policy}"
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
  canonical_distribution_policy="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT policytype || '|' || numsegments::text || '|' || distkey::text FROM gp_distribution_policy WHERE localoid = 'dfe_fixture.${relation_name}'::regclass;")"
  if [[ "${canonical_distribution_policy}" != "p|${primary_count}|1" ]]; then
    fail "${relation_name} must be distributed by distribution_id, observed policy ${canonical_distribution_policy}"
  fi
done

for snapshot_index in "${!SNAPSHOT_RELATIONS[@]}"; do
  relation_name="${SNAPSHOT_RELATIONS[${snapshot_index}]}"
  storage_clause="${SNAPSHOT_STORAGE_CLAUSES[${snapshot_index}]}"
  expected_access_method="${SNAPSHOT_ACCESS_METHODS[${snapshot_index}]}"
  expected_appendonly_count="${SNAPSHOT_APPENDONLY_COUNTS[${snapshot_index}]}"
  expected_reloptions_state="${SNAPSHOT_RELOPTIONS_STATES[${snapshot_index}]}"

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
  snapshot_distribution_policy="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT policytype || '|' || numsegments::text || '|' || distkey::text FROM gp_distribution_policy WHERE localoid = 'dfe_fixture.${relation_name}'::regclass;")"
  if [[ "${snapshot_distribution_policy}" != "p|${primary_count}|1" ]]; then
    fail "${relation_name} must use all ${primary_count} primary segments and be distributed by distribution_id, observed policy ${snapshot_distribution_policy}; retained fixture tables are never redistributed"
  fi
  observed_access_method="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT am.amname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_am am ON am.oid = c.relam WHERE n.nspname = 'dfe_fixture' AND c.relname = '${relation_name}';")"
  if [[ "${observed_access_method}" != "${expected_access_method}" ]]; then
    fail "${relation_name} uses access method ${observed_access_method}, expected ${expected_access_method}; retained fixture tables are never converted"
  fi
  appendonly_count="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT count(*) FROM pg_appendonly WHERE relid = 'dfe_fixture.${relation_name}'::regclass;")"
  require_count "${appendonly_count}" "${expected_appendonly_count}" \
    "${relation_name} pg_appendonly row count"
  observed_reloptions_state="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT (SELECT count(*) FROM pg_options_to_table(c.reloptions))::text || '|' || (SELECT count(*) FROM pg_options_to_table(c.reloptions) o WHERE (o.option_name = 'blocksize' AND o.option_value = '32768') OR (o.option_name = 'compresstype' AND o.option_value = 'none') OR (o.option_name = 'compresslevel' AND o.option_value = '0') OR (o.option_name = 'checksum' AND o.option_value = 'true'))::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'dfe_fixture' AND c.relname = '${relation_name}';")"
  if [[ "${observed_reloptions_state}" != "${expected_reloptions_state}" ]]; then
    fail "${relation_name} has relation-options state ${observed_reloptions_state}, expected ${expected_reloptions_state}; retained fixture tables are never converted"
  fi
done

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
REVOKE ALL PRIVILEGES ON SCHEMA dfe_fixture FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA dfe_fixture FROM ${READER_ROLE};
REVOKE ALL PRIVILEGES ON SCHEMA dfe_fixture FROM ${WRITER_ROLE};
GRANT USAGE ON SCHEMA dfe_fixture TO ${READER_ROLE};
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
SQL

capability_state="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT (SELECT count(*) FROM pg_extension WHERE extname = 'pgcrypto') = 0 AND (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'pg_catalog' AND p.proname = 'sha256' AND p.proargtypes = '17'::oidvector AND p.prorettype = 'bytea'::regtype AND p.provolatile = 'i' AND p.proisstrict) = 1 AND has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'CONNECT') AND NOT has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'CREATE') AND NOT has_database_privilege('${READER_ROLE}', '${FIXTURE_DATABASE}', 'TEMP') AND has_schema_privilege('${READER_ROLE}', 'dfe_fixture', 'USAGE') AND NOT has_schema_privilege('${READER_ROLE}', 'dfe_fixture', 'CREATE') AND has_table_privilege('${READER_ROLE}', 'dfe_fixture.capability_types', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.capability_types', 'INSERT') AND has_function_privilege('${READER_ROLE}', 'pg_catalog.sha256(bytea)', 'EXECUTE') AND encode(pg_catalog.sha256(convert_to('dfe-greenplum-capability', 'UTF8')), 'hex') = '${EXPECTED_SHA256}';")"
if [[ "${capability_state}" != t ]]; then
  fail 'reader privileges or core SHA-256 capability do not match the required state'
fi
writer_scope_state="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT has_database_privilege('${WRITER_ROLE}', '${FIXTURE_DATABASE}', 'CONNECT') AND NOT has_database_privilege('${WRITER_ROLE}', '${FIXTURE_DATABASE}', 'CREATE') AND NOT has_database_privilege('${WRITER_ROLE}', '${FIXTURE_DATABASE}', 'TEMP') AND has_schema_privilege('${WRITER_ROLE}', 'dfe_fixture', 'USAGE') AND NOT has_schema_privilege('${WRITER_ROLE}', 'dfe_fixture', 'CREATE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.capability_types', 'SELECT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.capability_types', 'INSERT');")"
if [[ "${writer_scope_state}" != t ]]; then
  fail 'writer database, schema, or capability-table privileges exceed the required scope'
fi
canonical_privilege_state="$(query_scalar "${FIXTURE_DATABASE}" \
  "SELECT has_table_privilege('${READER_ROLE}', 'dfe_fixture.canonical_values', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.canonical_values', 'INSERT') AND has_table_privilege('${READER_ROLE}', 'dfe_fixture.canonical_empty_values', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.canonical_empty_values', 'INSERT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_values', 'SELECT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_values', 'INSERT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_values', 'DELETE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_empty_values', 'SELECT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_empty_values', 'INSERT') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.canonical_empty_values', 'DELETE');")"
if [[ "${canonical_privilege_state}" != t ]]; then
  fail 'reader or writer privileges on canonical relations do not match the required state'
fi

for relation_name in "${SNAPSHOT_RELATIONS[@]}"; do
  snapshot_privilege_state="$(query_scalar "${FIXTURE_DATABASE}" \
    "SELECT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'SELECT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'INSERT') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'UPDATE') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'DELETE') AND NOT has_table_privilege('${READER_ROLE}', 'dfe_fixture.${relation_name}', 'TRUNCATE') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'SELECT') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'INSERT') AND has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'DELETE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'UPDATE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'TRUNCATE') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'REFERENCES') AND NOT has_table_privilege('${WRITER_ROLE}', 'dfe_fixture.${relation_name}', 'TRIGGER');")"
  if [[ "${snapshot_privilege_state}" != t ]]; then
    fail "reader or writer privileges on ${relation_name} do not match the required state"
  fi
done

reader_role_state="$(query_scalar postgres \
  "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit AND array_to_string(rolconfig, ',') LIKE '%default_transaction_read_only=on%' FROM pg_roles WHERE rolname = '${READER_ROLE}';")"
if [[ "${reader_role_state}" != t ]]; then
  fail 'reader role attributes do not match the required read-only state'
fi
writer_role_state="$(query_scalar postgres \
  "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit AND array_to_string(rolconfig, ',') LIKE '%default_transaction_read_only=off%' FROM pg_roles WHERE rolname = '${WRITER_ROLE}';")"
if [[ "${writer_role_state}" != t ]]; then
  fail 'writer role attributes do not match the required narrow read-write state'
fi
for role_name in "${READER_ROLE}" "${WRITER_ROLE}"; do
  membership_count="$(query_scalar postgres \
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
reload_state="$(query_scalar postgres 'SELECT pg_reload_conf();')"
if [[ "${reload_state}" != t ]]; then
  fail 'coordinator configuration reload returned false'
fi
