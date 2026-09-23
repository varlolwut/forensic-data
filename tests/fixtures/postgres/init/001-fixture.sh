#!/usr/bin/env bash
set -euo pipefail

: "${DFE_PG_READER_PASSWORD:?DFE_PG_READER_PASSWORD is required}"
: "${DFE_PG_WRITER_PASSWORD:?DFE_PG_WRITER_PASSWORD is required}"

psql \
  --set=ON_ERROR_STOP=1 \
  --set=reader_password="${DFE_PG_READER_PASSWORD}" \
  --set=writer_password="${DFE_PG_WRITER_PASSWORD}" \
  --username "${POSTGRES_USER}" \
  --dbname "${POSTGRES_DB}" <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE ROLE dfe_fixture_writer
  LOGIN
  PASSWORD :'writer_password'
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;

CREATE ROLE dfe_fixture_reader
  LOGIN
  PASSWORD :'reader_password'
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;

ALTER ROLE dfe_fixture_reader SET default_transaction_read_only = on;

CREATE SCHEMA dfe_fixture AUTHORIZATION dfe_fixture_writer;
REVOKE ALL ON SCHEMA dfe_fixture FROM PUBLIC;
GRANT USAGE ON SCHEMA dfe_fixture TO dfe_fixture_reader;

SET ROLE dfe_fixture_writer;

CREATE TABLE dfe_fixture.snapshot_values (
  record_id bigint PRIMARY KEY,
  observed_value bigint NOT NULL
);

CREATE TABLE dfe_fixture.canonical_values (
  id bigint NOT NULL,
  amount numeric(38, 3) NOT NULL,
  active boolean NOT NULL,
  label text NOT NULL,
  business_date date NOT NULL,
  local_time timestamp(6) without time zone NOT NULL,
  instant_time timestamp(6) with time zone NOT NULL
);

CREATE TABLE dfe_fixture.wide_scale_values (
  amount numeric(3, 14) NOT NULL
);

CREATE TABLE dfe_fixture.invalid_values (
  amount numeric NULL,
  wide_integer numeric NOT NULL
);

CREATE TABLE dfe_fixture.unsupported_physical_values (
  padded_label character(3) NOT NULL,
  local_as_instant timestamp(6) without time zone NOT NULL
);

INSERT INTO dfe_fixture.snapshot_values (record_id, observed_value)
VALUES (1, 100);

INSERT INTO dfe_fixture.canonical_values (
  id,
  amount,
  active,
  label,
  business_date,
  local_time,
  instant_time
)
VALUES (
  -9223372036854775808,
  -1780.000,
  true,
  'A|Б😀é  ',
  DATE '2024-02-29',
  TIMESTAMP '2024-02-29 23:59:58.123456',
  TIMESTAMPTZ '2024-02-29 21:29:58.123456+00'
);

INSERT INTO dfe_fixture.wide_scale_values (amount)
VALUES (0.00000000000123);

INSERT INTO dfe_fixture.invalid_values (amount, wide_integer)
VALUES
  (10, 9223372036854775808),
  (11, 0),
  (NULL, 0);

INSERT INTO dfe_fixture.unsupported_physical_values (padded_label, local_as_instant)
VALUES ('x ', TIMESTAMP '2024-02-29 21:29:58.123456');

RESET ROLE;

GRANT SELECT ON ALL TABLES IN SCHEMA dfe_fixture TO dfe_fixture_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE dfe_fixture_writer IN SCHEMA dfe_fixture
  GRANT SELECT ON TABLES TO dfe_fixture_reader;
SQL
