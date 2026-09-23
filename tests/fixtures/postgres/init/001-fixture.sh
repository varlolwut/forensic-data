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
GRANT CREATE ON DATABASE dfe_fixture TO dfe_fixture_writer;

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

CREATE TABLE dfe_fixture.fingerprint_bag_values (
  id bigint NOT NULL
);

CREATE TABLE dfe_fixture.fingerprint_empty_values (
  id bigint NOT NULL
);

CREATE TABLE dfe_fixture.boundary_values (
  nullable_label text NULL,
  fractional_amount numeric NOT NULL,
  local_time timestamp(6) without time zone NOT NULL
);

CREATE TABLE dfe_fixture.rls_values (
  id bigint NOT NULL
);

ALTER TABLE dfe_fixture.rls_values ENABLE ROW LEVEL SECURITY;

CREATE TABLE dfe_fixture.partitioned_values (
  id bigint NOT NULL
) PARTITION BY RANGE (id);

CREATE TABLE dfe_fixture.partitioned_values_low
PARTITION OF dfe_fixture.partitioned_values
FOR VALUES FROM (MINVALUE) TO (10);

CREATE TABLE dfe_fixture.inheritance_parent_values (
  id bigint NOT NULL
);

CREATE TABLE dfe_fixture.inheritance_child_values ()
INHERITS (dfe_fixture.inheritance_parent_values);

CREATE SEQUENCE dfe_fixture.read_only_probe_sequence;

CREATE VIEW dfe_fixture.volatile_values AS
SELECT clock_timestamp() AS observed_value;

CREATE FUNCTION dfe_fixture.sha256(source_value bytea)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS 'SELECT pg_catalog.decode(pg_catalog.repeat(''00'', 32), ''hex'')';

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

INSERT INTO dfe_fixture.fingerprint_bag_values (id)
VALUES (7), (7);

INSERT INTO dfe_fixture.boundary_values (nullable_label, fractional_amount, local_time)
VALUES (NULL, 1.001, TIMESTAMP '2024-02-29 21:29:58.123456');

INSERT INTO dfe_fixture.rls_values (id)
VALUES (1);

INSERT INTO dfe_fixture.inheritance_parent_values (id)
VALUES (1);

INSERT INTO dfe_fixture.inheritance_child_values (id)
VALUES (2);

RESET ROLE;

GRANT SELECT ON ALL TABLES IN SCHEMA dfe_fixture TO dfe_fixture_reader;
GRANT EXECUTE ON FUNCTION dfe_fixture.sha256(bytea) TO dfe_fixture_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE dfe_fixture_writer IN SCHEMA dfe_fixture
  GRANT SELECT ON TABLES TO dfe_fixture_reader;
SQL
