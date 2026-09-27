#!/usr/bin/env bash
set -euo pipefail

: "${CLICKHOUSE_USER:?CLICKHOUSE_USER is required}"
: "${CLICKHOUSE_PASSWORD:?CLICKHOUSE_PASSWORD is required}"
: "${DFE_CLICKHOUSE_READER_PASSWORD:?DFE_CLICKHOUSE_READER_PASSWORD is required}"

clickhouse-client \
  --user "${CLICKHOUSE_USER}" \
  --password "${CLICKHOUSE_PASSWORD}" \
  --param_reader_password "${DFE_CLICKHOUSE_READER_PASSWORD}" \
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

DROP USER IF EXISTS dfe_fixture_reader;

CREATE USER dfe_fixture_reader
IDENTIFIED WITH sha256_password BY {reader_password:String}
SETTINGS
    readonly = 1 CONST,
    session_timezone = 'UTC' CONST,
    max_memory_usage = 268435456 CONST,
    max_threads = 2 CONST,
    max_execution_time = 30 MIN 1 MAX 30 CHANGEABLE_IN_READONLY,
    max_result_rows = 100000 MIN 1 MAX 100000 CHANGEABLE_IN_READONLY,
    max_result_bytes = 67108864 MIN 1 MAX 67108864 CHANGEABLE_IN_READONLY,
    max_rows_to_group_by = 1 MIN 1 MAX 100000 CHANGEABLE_IN_READONLY,
    group_by_overflow_mode = 'any' CHANGEABLE_IN_READONLY,
    result_overflow_mode = 'throw' CONST;

GRANT SELECT ON dfe_fixture.* TO dfe_fixture_reader;
SQL
