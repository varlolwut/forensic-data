\getenv demo_reader_password DFE_DEMO_READER_PASSWORD

CREATE ROLE dfe_demo_reader
  LOGIN
  PASSWORD :'demo_reader_password'
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

ALTER ROLE dfe_demo_reader SET default_transaction_read_only = on;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA dfe_demo AUTHORIZATION postgres;
CREATE SCHEMA dfe_control AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA dfe_demo, dfe_control FROM PUBLIC;
GRANT USAGE ON SCHEMA dfe_demo, dfe_control TO dfe_demo_reader;

CREATE TABLE dfe_demo.reference_orders (
  order_id bigint PRIMARY KEY,
  business_date date NOT NULL,
  amount numeric(18, 2)
);

CREATE TABLE dfe_demo.target_orders (
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

INSERT INTO dfe_demo.reference_orders (order_id, business_date, amount)
VALUES
  (1001, DATE '2026-09-23', 10.00),
  (1002, DATE '2026-09-23', 20.00),
  (1003, DATE '2026-09-23', 30.00);

INSERT INTO dfe_demo.target_orders (order_id, business_date, amount)
VALUES
  (1001, DATE '2026-09-23', 10.00),
  (1002, DATE '2026-09-23', 20.25),
  (1004, DATE '2026-09-23', 40.00);

INSERT INTO dfe_control.batch_manifest (
  dataset_id,
  scope_digest,
  batch_id,
  state,
  business_date,
  source_cut,
  dataset_version,
  completed_at
)
VALUES
  (
    'reference_orders',
    'df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab',
    'reference-demo-2026-09-23',
    'complete',
    DATE '2026-09-23',
    'demo-cut-1',
    'reference-orders-v1',
    TIMESTAMPTZ '2026-09-23 00:00:00+00'
  ),
  (
    'target_orders',
    'df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab',
    'target-demo-2026-09-23',
    'complete',
    DATE '2026-09-23',
    'demo-cut-1',
    'target-orders-v1',
    TIMESTAMPTZ '2026-09-23 00:00:00+00'
  );

GRANT SELECT ON dfe_demo.reference_orders, dfe_demo.target_orders,
  dfe_control.batch_manifest TO dfe_demo_reader;
