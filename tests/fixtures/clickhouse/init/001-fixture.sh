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
    result_overflow_mode = 'throw' CONST;

GRANT SELECT ON dfe_fixture.* TO dfe_fixture_reader;
SQL
