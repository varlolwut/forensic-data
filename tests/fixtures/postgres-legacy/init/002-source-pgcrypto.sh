#!/usr/bin/env bash
set -euo pipefail

psql \
  --set=ON_ERROR_STOP=1 \
  --username "${POSTGRES_USER}" \
  --dbname "${POSTGRES_DB}" <<'SQL'
BEGIN;

CREATE SCHEMA dfe_ext AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA dfe_ext FROM PUBLIC;
CREATE EXTENSION pgcrypto WITH SCHEMA dfe_ext;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA dfe_ext FROM PUBLIC;
GRANT USAGE ON SCHEMA dfe_ext TO dfe_legacy_reader;
GRANT EXECUTE ON FUNCTION dfe_ext.digest(bytea, text) TO dfe_legacy_reader;

DO $validation$
DECLARE
  installed_version text;
BEGIN
  SELECT extension.extversion
  INTO STRICT installed_version
  FROM pg_catalog.pg_extension AS extension
  INNER JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = extension.extnamespace
  WHERE extension.extname = 'pgcrypto'
    AND namespace.nspname = 'dfe_ext';

  IF installed_version <> '1.3' THEN
    RAISE EXCEPTION 'fixture requires pgcrypto 1.3, observed %', installed_version;
  END IF;

  IF pg_catalog.encode(
    dfe_ext.digest(pg_catalog.convert_to('abc', 'UTF8'), 'sha256'),
    'hex'
  ) <> 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' THEN
    RAISE EXCEPTION 'fixture pgcrypto SHA-256 validation failed';
  END IF;
END
$validation$;

COMMIT;
SQL
