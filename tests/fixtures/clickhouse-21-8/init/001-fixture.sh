#!/usr/bin/env bash
set -euo pipefail

: "${CLICKHOUSE_USER:?CLICKHOUSE_USER is required}"
: "${CLICKHOUSE_PASSWORD:?CLICKHOUSE_PASSWORD is required}"
: "${DFE_CLICKHOUSE_LEGACY_READER_PASSWORD:?DFE_CLICKHOUSE_LEGACY_READER_PASSWORD is required}"

admin_client=(
  clickhouse-client
  --host 127.0.0.1
  --user "${CLICKHOUSE_USER}"
  --password "${CLICKHOUSE_PASSWORD}"
)

reader_password_sha256="$(printf '%s' "${DFE_CLICKHOUSE_LEGACY_READER_PASSWORD}" | sha256sum)"
reader_password_sha256="${reader_password_sha256%% *}"
if [[ ! "${reader_password_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Failed to derive the ClickHouse reader SHA-256 password hash." >&2
  exit 1
fi

database_count="$(
  "${admin_client[@]}" --query="SELECT count() FROM system.databases WHERE name = 'dfe_fixture' FORMAT TabSeparatedRaw"
)"
reader_count="$(
  "${admin_client[@]}" --query="SELECT count() FROM system.users WHERE name = 'dfe_legacy_reader' FORMAT TabSeparatedRaw"
)"

if [[ "${database_count}" == "1" && "${reader_count}" == "1" ]]; then
  existing_fixture_is_exact="$(
    "${admin_client[@]}" --query="SELECT
      (SELECT engine = 'Atomic'
        AND uuid = toUUID('44444444-4444-4444-8444-444444444444')
        FROM system.databases WHERE name = 'dfe_fixture')
      AND (SELECT uuid = toUUID('55555555-5555-4555-8555-555555555555')
        FROM system.tables
        WHERE database = 'dfe_fixture' AND name = 'comparison_orders_v001')
      AND (SELECT uuid = toUUID('66666666-6666-4666-8666-666666666666')
        FROM system.tables
        WHERE database = 'dfe_fixture' AND name = 'immutable_version_readiness')
      AND (SELECT count() FROM dfe_fixture.comparison_orders_v001) = 4
      AND (SELECT count() FROM dfe_fixture.immutable_version_readiness) = 1
      FORMAT TabSeparatedRaw"
  )"
  if [[ "${existing_fixture_is_exact}" != "1" ]]; then
    echo "Existing dfe_fixture state does not match the owned ClickHouse 21.8 fixture; refusing to overwrite it." >&2
    exit 1
  fi
  if ! clickhouse-client \
    --host 127.0.0.1 \
    --user dfe_legacy_reader \
    --password "${DFE_CLICKHOUSE_LEGACY_READER_PASSWORD}" \
    --database dfe_fixture \
    --query="SELECT 1 FORMAT TabSeparatedRaw" >/dev/null; then
    echo "Existing dfe_legacy_reader credentials do not match the supplied fixture secret; refusing to alter the user." >&2
    exit 1
  fi
  exit 0
fi

if [[ "${database_count}" != "0" || "${reader_count}" != "0" ]]; then
  echo "ClickHouse fixture ownership is inconsistent: expected both dfe_fixture and dfe_legacy_reader to be absent or present exactly once." >&2
  exit 1
fi

"${admin_client[@]}" --multiquery <<'SQL'
SELECT throwIf(version() != '21.8.15.7', 'fixture requires ClickHouse 21.8.15.7');

CREATE DATABASE dfe_fixture
UUID '44444444-4444-4444-8444-444444444444'
ENGINE = Atomic;

CREATE TABLE dfe_fixture.comparison_orders_v001
UUID '55555555-5555-4555-8555-555555555555'
(
    order_id Int64,
    business_date Date,
    precise_amount Decimal(38, 7),
    label String,
    optional_label Nullable(String),
    local_time DateTime64(6, 'UTC'),
    instant_time DateTime64(6, 'UTC')
)
ENGINE = MergeTree(business_date, order_id, 8192);

INSERT INTO dfe_fixture.comparison_orders_v001 VALUES (1, toDate('2024-02-29'), '100.0000000', unhex('417cd091f09f988065cc812020'), NULL, toDateTime64('2024-02-29 10:00:01.111111', 6, 'UTC'), toDateTime64('2024-02-29 08:00:01.111111', 6, 'UTC')), (2, toDate('2024-02-29'), '200.0000001', unhex('d09ed0b1d0bdd0bed0b2d0bbd191d0bdd0bdd0bed0b5202020'), '', toDateTime64('2024-02-29 10:00:02.222222', 6, 'UTC'), toDateTime64('2024-02-29 08:00:02.222222', 6, 'UTC')), (3, toDate('2024-02-29'), '-9999999999999999999999999999999.9999999', '', '', toDateTime64('2024-02-29 10:00:03.333333', 6, 'UTC'), toDateTime64('2024-02-29 08:00:03.333333', 6, 'UTC')), (4, toDate('2024-02-29'), '0.0000001', unhex('747261696c696e672020'), unhex('d0bdd183d0bbd18c'), toDateTime64('2024-02-29 10:00:04.444444', 6, 'UTC'), toDateTime64('2024-02-29 08:00:04.444444', 6, 'UTC'));

CREATE TABLE dfe_fixture.immutable_version_readiness
UUID '66666666-6666-4666-8666-666666666666'
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
ORDER BY tuple();

INSERT INTO dfe_fixture.immutable_version_readiness VALUES ('clickhouse_reference_orders', '13da3e93058f4e53db4d7989380a57597b0fb5a86dc0e9a80ae33bd1b11f9897', 'reference-orders-2024-02-29-v001', 'complete', toDate('2024-02-29'), 'comparison-orders-cut-000001', 'comparison_orders_v001', toDateTime64('2024-03-01 01:02:03.456789', 6, 'UTC'), toUInt64(7), toUInt64(11));
SQL

"${admin_client[@]}" --multiquery <<SQL
CREATE USER dfe_legacy_reader
IDENTIFIED WITH SHA256_HASH BY '${reader_password_sha256}'
SETTINGS
    readonly = 2 READONLY,
    cancel_http_readonly_queries_on_client_close = 1 READONLY,
    send_progress_in_http_headers = 0 READONLY,
    allow_experimental_projection_optimization = 0 READONLY,
    force_optimize_projection = 0 READONLY,
    max_memory_usage = 268435456 READONLY,
    max_threads = 2 READONLY,
    max_block_size = 65536 MIN 1 MAX 65536,
    max_execution_time = 30 MIN 1 MAX 30,
    max_result_rows = 120000 MIN 1 MAX 120000,
    max_result_bytes = 67108864 MIN 1 MAX 67108864,
    max_rows_to_group_by = 120000 MIN 1 MAX 120000,
    result_overflow_mode = 'throw' READONLY,
    timeout_overflow_mode = 'throw' READONLY,
    read_overflow_mode = 'throw' READONLY,
    read_overflow_mode_leaf = 'throw' READONLY,
    sort_overflow_mode = 'throw' READONLY,
    group_by_overflow_mode = 'throw' READONLY;

GRANT SELECT ON dfe_fixture.comparison_orders_v001 TO dfe_legacy_reader;
GRANT SELECT ON dfe_fixture.immutable_version_readiness TO dfe_legacy_reader;
GRANT SELECT ON system.build_options TO dfe_legacy_reader;
GRANT SELECT ON system.columns TO dfe_legacy_reader;
GRANT SELECT ON system.databases TO dfe_legacy_reader;
GRANT SELECT ON system.mutations TO dfe_legacy_reader;
GRANT SELECT ON system.parts TO dfe_legacy_reader;
GRANT SELECT ON system.processes TO dfe_legacy_reader;
GRANT SELECT ON system.projection_parts TO dfe_legacy_reader;
GRANT SELECT ON system.row_policies TO dfe_legacy_reader;
GRANT SELECT ON system.settings TO dfe_legacy_reader;
GRANT SELECT ON system.tables TO dfe_legacy_reader;
GRANT SHOW ROW POLICIES ON *.* TO dfe_legacy_reader;
SQL
