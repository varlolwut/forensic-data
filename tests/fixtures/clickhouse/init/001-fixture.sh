#!/usr/bin/env bash
set -euo pipefail

: "${CLICKHOUSE_USER:?CLICKHOUSE_USER is required}"
: "${CLICKHOUSE_PASSWORD:?CLICKHOUSE_PASSWORD is required}"
: "${DFE_CLICKHOUSE_READER_PASSWORD:?DFE_CLICKHOUSE_READER_PASSWORD is required}"
: "${DFE_CLICKHOUSE_WRITER_PASSWORD:?DFE_CLICKHOUSE_WRITER_PASSWORD is required}"

clickhouse-client \
  --user "${CLICKHOUSE_USER}" \
  --password "${CLICKHOUSE_PASSWORD}" \
  --param_reader_password "${DFE_CLICKHOUSE_READER_PASSWORD}" \
  --param_writer_password "${DFE_CLICKHOUSE_WRITER_PASSWORD}" \
  --multiquery <<'SQL'
SELECT throwIf(version() != '26.8.6.5', 'fixture requires ClickHouse 26.8.6.5');

DROP TABLE IF EXISTS dfe_fixture.fidelity_probe;

CREATE TABLE dfe_fixture.fidelity_probe
(
    probe_id UInt8,
    `amount\\"quoted` Decimal(38, 9),
    observed_at DateTime64(9, 'America/New_York')
)
ENGINE = MergeTree
ORDER BY probe_id;

INSERT INTO dfe_fixture.fidelity_probe VALUES
(
    1,
    '-99999999999999999999999999999.999999999',
    toDateTime64(toDecimal256('-0.876543211', 9), 9, 'America/New_York')
),
(
    2,
    '0.000000000',
    toDateTime64(toDecimal256('0.000000000', 9), 9, 'America/New_York')
),
(
    3,
    '99999999999999999999999999999.999999999',
    toDateTime64(toDecimal256('9223372036.854775807', 9), 9, 'America/New_York')
);

DROP TABLE IF EXISTS dfe_fixture.canonical_common_types;

CREATE TABLE dfe_fixture.canonical_common_types
(
    probe_id UInt8,
    id Int64,
    amount Decimal(38, 6),
    active Bool,
    label String,
    business_date Date,
    local_time DateTime64(9, 'UTC'),
    instant_time DateTime64(9, 'UTC')
)
ENGINE = MergeTree
ORDER BY probe_id;

INSERT INTO dfe_fixture.canonical_common_types VALUES
(
    1,
    toInt64('-9223372036854775808'),
    '-1780.000000',
    true,
    unhex('417cd091f09f988065cc812020'),
    toDate('2024-02-29'),
    toDateTime64('2024-02-29 23:59:58.123456000', 9, 'UTC'),
    toDateTime64('2024-02-29 21:29:58.123456000', 9, 'UTC')
),
(
    2,
    toInt64('-9223372036854775808'),
    '-1780.000000',
    true,
    unhex('417cd091f09f988065cc812020'),
    toDate('2024-02-29'),
    toDateTime64('2024-02-29 23:59:58.123456000', 9, 'UTC'),
    toDateTime64('2024-02-29 21:29:58.123456000', 9, 'UTC')
);

DROP TABLE IF EXISTS dfe_fixture.canonical_empty_common_types;

CREATE TABLE dfe_fixture.canonical_empty_common_types
(
    probe_id UInt8,
    id Int64,
    amount Decimal(38, 6),
    active Bool,
    label String,
    business_date Date,
    local_time DateTime64(9, 'UTC'),
    instant_time DateTime64(9, 'UTC')
)
ENGINE = MergeTree
ORDER BY probe_id;

DROP TABLE IF EXISTS dfe_fixture.canonical_lossy_common_types;

CREATE TABLE dfe_fixture.canonical_lossy_common_types
(
    probe_id UInt8,
    id Int64,
    amount Decimal(38, 6),
    active Bool,
    label String,
    business_date Date,
    local_time DateTime64(9, 'UTC'),
    instant_time DateTime64(9, 'UTC')
)
ENGINE = MergeTree
ORDER BY probe_id;

INSERT INTO dfe_fixture.canonical_lossy_common_types VALUES
(
    1,
    toInt64('-9223372036854775808'),
    '-1780.000001',
    true,
    unhex('417cd091f09f988065cc812020'),
    toDate('2024-02-29'),
    toDateTime64('2024-02-29 23:59:58.123456000', 9, 'UTC'),
    toDateTime64('2024-02-29 21:29:58.123456000', 9, 'UTC')
),
(
    2,
    toInt64('-9223372036854775808'),
    '-1780.000000',
    true,
    unhex('417cd091f09f988065cc812020'),
    toDate('2024-02-29'),
    toDateTime64('2024-02-29 23:59:58.123456001', 9, 'UTC'),
    toDateTime64('2024-02-29 21:29:58.123456000', 9, 'UTC')
);

DROP TABLE IF EXISTS dfe_fixture.canonical_nullable_strings;

CREATE TABLE dfe_fixture.canonical_nullable_strings
(
    probe_id UInt8,
    label Nullable(String)
)
ENGINE = MergeTree
ORDER BY probe_id;

INSERT INTO dfe_fixture.canonical_nullable_strings VALUES
    (1, NULL),
    (2, '');

DROP TABLE IF EXISTS dfe_fixture.canonical_key_groups;

CREATE TABLE dfe_fixture.canonical_key_groups
(
    probe_id UInt8,
    id Int64,
    label String
)
ENGINE = MergeTree
ORDER BY probe_id;

INSERT INTO dfe_fixture.canonical_key_groups VALUES
    (1, 42, unhex('417cd091f09f988065cc812020')),
    (2, 42, unhex('417cd091f09f988065cc812020')),
    (3, 42, unhex('417cd091f09f988065cc8120')),
    (4, 42, unhex('417cd091f09f9880c3a92020')),
    (5, 43, unhex('417cd091f09f988065cc812020'));

DROP TABLE IF EXISTS dfe_fixture.canonical_null_key;

CREATE TABLE dfe_fixture.canonical_null_key
(
    probe_id UInt8,
    id Int64,
    label Nullable(String)
)
ENGINE = MergeTree
ORDER BY probe_id;

INSERT INTO dfe_fixture.canonical_null_key VALUES (1, 42, NULL);

DROP VIEW IF EXISTS dfe_fixture.canonical_group_overflow;

CREATE VIEW dfe_fixture.canonical_group_overflow AS
SELECT toInt64(1) AS id
UNION ALL
SELECT toInt64(2) AS id
UNION ALL
SELECT toInt64(3) AS id
UNION ALL
SELECT toInt64(4) AS id
UNION ALL
SELECT toInt64(5) AS id;

DROP TABLE IF EXISTS dfe_fixture.immutable_version_readiness;

CREATE TABLE dfe_fixture.immutable_version_readiness
(
    dataset_id String,
    scope_digest FixedString(64),
    batch_id String,
    state Enum8('building' = 1, 'complete' = 2),
    business_date Date,
    source_cut Nullable(String),
    dataset_version Nullable(String),
    completed_at Nullable(DateTime64(6, 'UTC')),
    completion_revision Nullable(UInt64),
    publication_revision UInt64
)
ENGINE = MergeTree
ORDER BY (dataset_id, scope_digest, publication_revision);

INSERT INTO dfe_fixture.immutable_version_readiness VALUES
(
    'immutable_orders',
    '5689623b7c5d8424c827123d15d6fdbb011108a79efa1c7586d0f392230697e1',
    'immutable-orders-2024-02-29-v001',
    'complete',
    toDate('2024-02-29'),
    'source-orders-cut-000001',
    'immutable_orders_v001',
    toDateTime64('2024-03-01 00:00:00.000000', 6, 'UTC'),
    toUInt64(1),
    toUInt64(1)
);

INSERT INTO dfe_fixture.immutable_version_readiness VALUES
(
    'logical_orders',
    '8e9db77eac98d983fe0053501478a2f52fa3fd35bca9ea56cbb3e6b44f3430e7',
    'logical-orders-2024-02-29-v001',
    'complete',
    toDate('2024-02-29'),
    'logical-orders-cut-000001',
    'logical_orders_v001',
    toDateTime64('2024-03-01 00:10:00.000000', 6, 'UTC'),
    toUInt64(1),
    toUInt64(1)
);

INSERT INTO dfe_fixture.immutable_version_readiness VALUES
(
    'clickhouse_target_orders',
    '13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897',
    'comparison-orders-2024-02-29-v001',
    'complete',
    toDate('2024-02-29'),
    'comparison-orders-cut-000001',
    'comparison_orders_v001',
    toDateTime64('2024-03-01 01:02:03.456789', 6, 'UTC'),
    toUInt64(7),
    toUInt64(11)
);

DROP TABLE IF EXISTS dfe_fixture.immutable_orders_staging;

CREATE TABLE dfe_fixture.immutable_orders_staging
(
    order_id Int64,
    amount Decimal(38, 3),
    business_date Date,
    batch_id String
)
ENGINE = MergeTree
ORDER BY order_id;

INSERT INTO dfe_fixture.immutable_orders_staging VALUES
    (1, '10.000', toDate('2024-02-29'), 'immutable-orders-2024-02-29-v002'),
    (2, '21.000', toDate('2024-02-29'), 'immutable-orders-2024-02-29-v002'),
    (3, '30.000', toDate('2024-02-29'), 'immutable-orders-2024-02-29-v002');

DROP TABLE IF EXISTS dfe_fixture.immutable_orders_v001 SYNC;

CREATE TABLE dfe_fixture.immutable_orders_v001 UUID '11111111-1111-4111-8111-111111111111'
(
    order_id Int64,
    amount Decimal(38, 3),
    business_date Date,
    batch_id String
)
ENGINE = MergeTree
ORDER BY order_id;

INSERT INTO dfe_fixture.immutable_orders_v001 VALUES
    (1, '10.000', toDate('2024-02-29'), 'immutable-orders-2024-02-29-v001'),
    (2, '20.000', toDate('2024-02-29'), 'immutable-orders-2024-02-29-v001');

ALTER TABLE dfe_fixture.immutable_orders_v001 MODIFY SETTING table_readonly = 1;

DROP TABLE IF EXISTS dfe_fixture.immutable_orders_v002 SYNC;

CREATE TABLE dfe_fixture.immutable_orders_v002 UUID '22222222-2222-4222-8222-222222222222'
(
    order_id Int64,
    amount Decimal(38, 3),
    business_date Date,
    batch_id String
)
ENGINE = MergeTree
ORDER BY order_id;

INSERT INTO dfe_fixture.immutable_orders_v002 VALUES
    (1, '10.000', toDate('2024-02-29'), 'immutable-orders-2024-02-29-v002'),
    (2, '21.000', toDate('2024-02-29'), 'immutable-orders-2024-02-29-v002'),
    (3, '30.000', toDate('2024-02-29'), 'immutable-orders-2024-02-29-v002');

ALTER TABLE dfe_fixture.immutable_orders_v002 MODIFY SETTING table_readonly = 1;

DROP TABLE IF EXISTS dfe_fixture.comparison_orders_v001 SYNC;

CREATE TABLE dfe_fixture.comparison_orders_v001
UUID '44444444-4444-4444-8444-444444444444'
(
    order_id Int64,
    business_date Date,
    precise_amount Decimal(38, 7),
    local_time DateTime64(6, 'UTC'),
    instant_time DateTime64(6, 'UTC')
)
ENGINE = MergeTree
ORDER BY order_id;

INSERT INTO dfe_fixture.comparison_orders_v001 VALUES
(
    1,
    toDate('2024-02-29'),
    '100.0000000',
    toDateTime64('2024-02-29 10:00:01.111111', 6, 'UTC'),
    toDateTime64('2024-02-29 08:00:01.111111', 6, 'UTC')
),
(
    2,
    toDate('2024-02-29'),
    '200.0000001',
    toDateTime64('2024-02-29 10:00:02.222223', 6, 'UTC'),
    toDateTime64('2024-02-29 08:00:02.222223', 6, 'UTC')
),
(
    4,
    toDate('2024-02-29'),
    '400.0000000',
    toDateTime64('2024-02-29 10:00:04.444444', 6, 'UTC'),
    toDateTime64('2024-02-29 08:00:04.444444', 6, 'UTC')
),
(
    5,
    toDate('2024-02-29'),
    '500.0000000',
    toDateTime64('2024-02-29 10:00:05.555555', 6, 'UTC'),
    toDateTime64('2024-02-29 08:00:05.555555', 6, 'UTC')
);

ALTER TABLE dfe_fixture.comparison_orders_v001 MODIFY SETTING table_readonly = 1;

DROP TABLE IF EXISTS dfe_fixture.logical_orders_v001 SYNC;

CREATE TABLE dfe_fixture.logical_orders_v001 UUID '33333333-3333-4333-8333-333333333333'
(
    order_id Int64,
    amount Decimal(38, 3),
    business_date Date,
    poison String,
    row_version UInt64,
    amount_default Decimal(38, 3) DEFAULT amount,
    amount_materialized Decimal(38, 3) MATERIALIZED amount,
    amount_alias Decimal(38, 3) ALIAS amount
)
ENGINE = ReplacingMergeTree(row_version)
ORDER BY order_id;

SYSTEM STOP MERGES dfe_fixture.logical_orders_v001;

INSERT INTO dfe_fixture.logical_orders_v001
    (order_id, amount, business_date, poison, row_version) VALUES
    (1, '10.000', toDate('2024-02-29'), '10', toUInt64(1)),
    (2, '20.000', toDate('2024-02-29'), 'mutation-failure', toUInt64(2)),
    (3, '30.000', toDate('2024-02-29'), '30', toUInt64(1));

INSERT INTO dfe_fixture.logical_orders_v001
    (order_id, amount, business_date, poison, row_version) VALUES
    (1, '11.000', toDate('2024-02-29'), '11', toUInt64(2)),
    (2, '19.000', toDate('2024-02-29'), '19', toUInt64(1));

ALTER TABLE dfe_fixture.logical_orders_v001 MODIFY SETTING table_readonly = 1;

DROP USER IF EXISTS dfe_fixture_reader;
DROP USER IF EXISTS dfe_fixture_writer;

CREATE USER dfe_fixture_reader
IDENTIFIED WITH sha256_password BY {reader_password:String}
SETTINGS
    readonly = 1 CONST,
    cancel_http_readonly_queries_on_client_close = 1 CONST,
    session_timezone = 'UTC' CONST,
    max_memory_usage = 268435456 CONST,
    max_threads = 2 CONST,
    max_block_size = 65536 MIN 1 MAX 65536 CHANGEABLE_IN_READONLY,
    http_wait_end_of_query = 1 MIN 0 MAX 1 CHANGEABLE_IN_READONLY,
    max_execution_time = 30 MIN 1 MAX 30 CHANGEABLE_IN_READONLY,
    max_result_rows = 100000 MIN 1 MAX 100000 CHANGEABLE_IN_READONLY,
    max_result_bytes = 67108864 MIN 1 MAX 67108864 CHANGEABLE_IN_READONLY,
    max_rows_to_group_by = 1 MIN 1 MAX 100000 CHANGEABLE_IN_READONLY,
    group_by_overflow_mode = 'any' CHANGEABLE_IN_READONLY,
    result_overflow_mode = 'throw' CONST,
    final = 0 CONST,
    apply_mutations_on_fly = 0 CONST,
    apply_patch_parts = 0 CONST,
    do_not_merge_across_partitions_select_final = 0 CONST;

GRANT SELECT ON dfe_fixture.* TO dfe_fixture_reader;
GRANT SELECT ON system.build_options TO dfe_fixture_reader;
GRANT SELECT ON system.mutations TO dfe_fixture_reader;
GRANT SELECT ON system.parts TO dfe_fixture_reader;
GRANT SELECT ON system.processes TO dfe_fixture_reader;
GRANT SELECT ON system.projections TO dfe_fixture_reader;
GRANT SHOW ROW POLICIES ON *.* TO dfe_fixture_reader;

CREATE USER dfe_fixture_writer
IDENTIFIED WITH sha256_password BY {writer_password:String}
SETTINGS
    readonly = 0 CONST,
    session_timezone = 'UTC' CONST,
    max_memory_usage = 268435456 CONST,
    max_threads = 2 CONST,
    max_execution_time = 30 MIN 1 MAX 30,
    max_result_rows = 100000 MIN 1 MAX 100000,
    max_result_bytes = 67108864 MIN 1 MAX 67108864,
    result_overflow_mode = 'throw' CONST;

GRANT SELECT, INSERT ON dfe_fixture.immutable_orders_staging TO dfe_fixture_writer;
GRANT INSERT ON dfe_fixture.immutable_version_readiness TO dfe_fixture_writer;
GRANT INSERT ON dfe_fixture.immutable_orders_v001 TO dfe_fixture_writer;
GRANT INSERT ON dfe_fixture.immutable_orders_v002 TO dfe_fixture_writer;
SQL
