#!/usr/bin/env bash
set -euo pipefail

: "${DFE_LEGACY_READER_PASSWORD:?DFE_LEGACY_READER_PASSWORD is required}"

psql \
  --set=ON_ERROR_STOP=1 \
  --set=reader_password="${DFE_LEGACY_READER_PASSWORD}" \
  --username "${POSTGRES_USER}" \
  --dbname "${POSTGRES_DB}" <<'SQL'
BEGIN;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CONNECT, TEMPORARY ON DATABASE dfe_legacy FROM PUBLIC;

CREATE ROLE dfe_legacy_reader
  LOGIN
  PASSWORD :'reader_password'
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

ALTER ROLE dfe_legacy_reader SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE dfe_legacy TO dfe_legacy_reader;

CREATE SCHEMA dfe_legacy AUTHORIZATION postgres;
CREATE SCHEMA dfe_control AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA dfe_legacy, dfe_control FROM PUBLIC;
GRANT USAGE ON SCHEMA dfe_legacy, dfe_control TO dfe_legacy_reader;

CREATE TABLE dfe_legacy.daily_orders (
  order_id bigint PRIMARY KEY,
  business_date date NOT NULL,
  amount numeric(18, 2)
);

CREATE TABLE dfe_control.batch_manifest (
  dataset_id text NOT NULL,
  scope_digest text NOT NULL,
  batch_id text NOT NULL,
  state text NOT NULL,
  business_date date NOT NULL,
  source_cut text,
  dataset_version text,
  completed_at timestamp(6) with time zone,
  PRIMARY KEY (dataset_id, scope_digest)
);

\ir /opt/forensic-data/data.sql

REVOKE ALL ON dfe_legacy.daily_orders, dfe_control.batch_manifest FROM PUBLIC;
GRANT SELECT ON dfe_legacy.daily_orders, dfe_control.batch_manifest
  TO dfe_legacy_reader;

COMMIT;
SQL
