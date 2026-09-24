# SQL Server source profile

[README](../README.md) · [Docker quickstart](docker-quickstart.md) · [CLI and contracts](cli-and-contracts.md) · [PostgreSQL](postgresql.md) · [SQL Server](sql-server.md) · [Development](development.md)

SQL Server support is source-only. SQL Server 2022 is the current verified configuration;
other server versions remain unverified and are not rejected solely by their version number.

## Verified source role

A source-only SQL Server path is verified against the exact SQL Server 2022 Developer CU27 build
`16.0.4295.3` on Linux/amd64 with pyodbc 5.3.0, Microsoft ODBC Driver 18.7.1.1-1, and the explicit
`pyodbc` / `mssql_2022` pair. Its target and metadata connections use PostgreSQL. The
current cross-engine executor requires one `physical_only` table, relation-manifest readiness, and
a non-null logical INT64 key with a confirmed leading, non-partial access path on both sides. The
exact verified fixture and the broader runtime-admission boundary are distinguished below. SQL
Server is not accepted as a target or metadata store. The separate SQL Server 2016 source profile is
not implemented and not verified.

## SQL Server 2022 source profile and fixture

SQL Server support is source-only and intentionally separates an exact verified conformance point
from the wider capability boundary admitted by the runtime:

| Status | Profile | Direction and boundary |
|---|---|---|
| Verified | SQL Server 2022 Developer CU27 `16.0.4295.3`, `pyodbc` / `mssql_2022` | Reference/source only; target and metadata remain PostgreSQL 17.11. |
| Runtime-admitted, not verified | `ALLOW_SNAPSHOT_ISOLATION=ON`, canonical UTF-8 code page 65001, database `VIEW DEFINITION`, matching driver/server identity, and the SQL/catalog operations required by the selected strategy | Reference/source only. Server versions, editions, compatibility levels, and driver patches are not numeric allowlists. Actual operations, including the `GENERATE_SERIES` snapshot witness, must succeed. |
| Unimplemented | Any driver/profile pair other than `pyodbc` / `mssql_2022`; SQL Server target or metadata roles | No fallback or silent profile substitution. A separate legacy SQL strategy is not yet implemented or verified. |

The verified fixture is exact:

| Component | Verified value |
|---|---|
| Server image | `mcr.microsoft.com/mssql/server:2022-CU27-ubuntu-22.04@sha256:4402d880dd4c34bfa7d8705e56a86cd6c88da80a1f6bbbe741f999e76264a090` |
| Server | Developer Edition (64-bit), CU27, build `16.0.4295.3`; Ubuntu 22.04.5 LTS on Linux/amd64 |
| Python and ODBC client | pyodbc 5.3.0; package `msodbcsql18` 18.7.1.1-1; library `libmsodbcsql-18.7.so.1.1`; reported driver version `18.07.0001` |
| Positive database | Compatibility 160; collation `Latin1_General_100_CI_AS_SC`; `ALLOW_SNAPSHOT_ISOLATION=ON`; RCSI OFF |
| Canonical Unicode path | `Latin1_General_100_BIN2_UTF8`, code page 65001 |
| Reader | Least-privilege SELECT-only relation access; `VIEW DEFINITION` and fixture-hardening grant `VIEW SECURITY DEFINITION`; no enabled row-level security |
| Transport | `Encrypt=Mandatory`; production uses `TrustServerCertificate=No`; only the disposable localhost fixture uses the explicit trust exception |

The profile name selects a SQL and driver strategy, not an allowed server version. The runtime
records the exact build, edition text, compatibility level, server/database collations, database
updateability, RCSI state, pyodbc version, ODBC library, and ODBC version as evidence. Missing SQL
or catalog capabilities fail explicitly. A successful connection does not verify an untested version.

The canonical comparison type matrix is:

| Logical field | Accepted direct `sys` physical types | Lossless requirement |
|---|---|---|
| `int64` | `tinyint`, `smallint`, `int`, `bigint`, `decimal`, `numeric` | Integral, signed-INT64 range, and exact physical round-trip |
| `decimal(p,s)` | `tinyint`, `smallint`, `int`, `bigint`, `decimal`, `numeric` | Each value must convert exactly to logical `(p,s)` and round-trip to its physical type; no rounding |
| `boolean` | `bit` | Exact `0` or `1` |
| `string` | `varchar`, `nvarchar`, including `max` | Lossless source-to-Unicode-to-UTF-8 round-trip; U+0000 rejected |
| `date` | `date` | Exact date representation |
| `timestamp_local(p)` | `datetime2` | Logical precision `0..9`, physical scale `0..7`; discarded digits must be zero |
| `timestamp_instant(p)` | `datetimeoffset` | Same precision rule, normalized to UTC without rounding |

All other SQL Server physical types are rejected by this comparison profile. Known examples include
`char`, `nchar`, `text`, `ntext`, `binary`, `varbinary`, `image`, `rowversion`/`timestamp`, `real`,
`float`, `money`, `smallmoney`, `datetime`, `smalldatetime`, `time`, `uniqueidentifier`, `xml`,
`sql_variant`, `hierarchyid`, `geometry`, and `geography`. Alias/user-defined, CLR, and table types
are rejected even when based on an accepted type. This is the comparison allowlist, not the
lower-level bounded transport's value-type list. Identity is inspected but identity alone is not a
refusal.

The relation and read boundary is equally explicit:

| Requirement | Refusal or enforced behavior |
|---|---|
| One exact `physical_only` user table | Views, system tables, memory-optimized, temporal, external, ledger, node, and edge tables are rejected. |
| Direct projected columns | Missing, alias/user-defined/assembly/table-typed, computed, generated, encrypted, hidden, or masked columns are rejected. |
| SELECT-only reader | INSERT, UPDATE, DELETE, ALTER, CONTROL, or column UPDATE capability is rejected. `ApplicationIntent=ReadOnly` is not the security boundary. |
| Complete security metadata | Missing database `VIEW DEFINITION` or enabled row-level security is rejected. `VIEW SECURITY DEFINITION` is a fixture hardening grant, not a separate runtime gate. |
| Comparison key and access path | Exactly one non-null logical INT64 key equal to both dataset grains. SQL Server requires a leading, enabled, non-hypothetical, unfiltered clustered or nonclustered rowstore index. PostgreSQL requires a leading, valid, ready, live, non-partial, non-expression B-tree index with a `pg_catalog` operator class. |
| Scope | Full scope or one equality parameter bound once to the projected scope field on each side. |
| Assurance | `fingerprint_allowed`; the current cross-engine executor rejects `exact_required`. |
| Protected read | One transaction-level `SNAPSHOT` context, one active query, sequential use, rollback-only close, and same-statement physical provenance checks. |

The selected Python client uses encrypted transport and a least-privilege login. The connector sets
`ApplicationIntent=ReadOnly`, disables MARS and connection retries, and enables `LongAsMax`, but the
verified grants and explicit permission inspection provide the write-safety boundary.

The connector-generated canonical query projects `datetime2` and `datetimeoffset` through
deterministic ISO text so seventh-digit precision can be checked before Python's six-digit
`datetime` boundary. Decimal values remain `Decimal` and `nvarchar` remains Unicode.
`fetchmany(batch_size)` bounds the number of materialized rows, but not the size of one
`varchar(max)`, `nvarchar(max)`, or `varbinary(max)` value; the transport therefore also caps each
declared value, row, transient batch, and retained result. Those decoded-payload limits are not a
measurement of process RSS.

Compatibility level 160 is required. The Unicode path normalizes to `nvarchar(max)`, converts
through `Latin1_General_100_BIN2_UTF8`, and uses `GENERATE_SERIES` with binary `SUBSTRING` to reject
U+0000 without collation-dependent character searches. Canonical frames introduce a MAX operand
before concatenation, including general canonical rows whose envelope exceeds 8,000 bytes; SHA-256
remains internal, counts use `COUNT_BIG`, and every digest limb is widened to `decimal(38,0)` before
`SUM`. SQL Server 2016 has neither this UTF-8 collation nor `GENERATE_SERIES`; its separate legacy
encoding/driver profile must not be replaced by a silent fallback.

The protected context selects transaction-level `SNAPSHOT` through the ODBC connection attribute
before its first protected query, then proves the same session has `@@TRANCOUNT=1`,
`XACT_STATE()=1`, and isolation level 5. `READ_COMMITTED_SNAPSHOT` is recorded but never substitutes
for `ALLOW_SNAPSHOT_ISOLATION=ON`; the separate RCSI-only fixture is rejected before relation
inspection. Every canonical query rechecks database/schema/object/column provenance in the same
statement and loses the context on missing or changed metadata rather than silently rebinding.

Key summaries encode the complete key with canonical v1 framing and use `COUNT_BIG` to report null,
invalid, oversized, valid, and distinct `varbinary` envelopes. They do not use source-collation
equality, so case, trailing-space, and Unicode-normalization adversaries remain distinct whenever
their canonical bytes differ.

Integer-range fingerprinting hashes each validated row once into a session-local temporary table
in `tempdb`, aggregates compact hash records, and confirms the terminal `DROP` before returning. It
creates no permanent object and requires no extra reader grant, but it is real temporary-storage
work. The published limits and measured point are:

| Limit | Meaning |
|---|---|
| Projected columns | Maximum 1,024. |
| Integer-range batch | Maximum 524 ranges, a project-derived bound that keeps the generated request below SQL Server's 2,100-parameter ceiling. |
| Cross-engine exact-row envelope | Maximum 8,000 bytes for the integer-range comparison path; an oversize row is explicit and is never truncated. |
| Protected concurrency | One active query per SQL Server context; contexts are sequential and rollback-only. |
| Current mixed fixture budgets | ODBC query timeout 60 seconds, statement budget 60,000 ms, whole-run budget 300,000 ms. Each statement receives the minimum of the connection query timeout, immutable statement budget, and remaining run budget. |
| Measured temporary storage | The 1,000,000-row root allocated 9,104 × 8 KiB user-object pages (71.125 MiB); 8,936 pages remained attributed until the SNAPSHOT context closed. This is a measurement, not a sizing formula. |
| Readiness timestamp | Six logical fractional digits; a seventh digit is accepted only when it is zero and removable without loss. |

The measured root completed in 24.334 seconds under the earlier 30-second test setting. That timing
is a conformance observation, not a latency guarantee or the current fixture limit; size `tempdb`
and execution budgets for the expected concurrent source workload.

For safe structured diagnostics, run `check --output json` and inspect `reasons`, `metrics`,
`native_error_code`, `query_id`, and `safe_parameters`. DSNs, credentials, and source row values are
not emitted.

| Result | Meaning and next action |
|---|---|
| `unsupported_capability` / `open_source` | An admitted `pyodbc` / `mssql_2022` source failed a server/database/transaction prerequisite such as major, edition class, compatibility, SNAPSHOT, UTF-8, or metadata visibility. The reason identifies the failed capability; compare it with the runtime-admission row. |
| `unsupported_capability` / `inspect_source_relation` | The exact relation, projected physical type, column semantics, permissions, or RLS state is unsupported. The reason identifies the field or relation boundary; correct the contract/source and use a new request UUID. |
| `snapshot_lost` / `read_source` | Protected physical provenance changed after the context opened. Re-establish the declared table and retry with a new request UUID; the failed context is never resumed. |
| `budget_exhausted` / `read_source` with `HYT00` or `HYT01` | `MssqlQueryTimeoutError`: the ODBC query timeout or immutable execution deadline ended the statement. Measure the workload and set explicit aligned budgets. |
| `lossy_transport` / `validate_key_mapping` | A scoped key cannot map exactly to logical INT64. Correct the contract or source data; the engine will not round. |
| `protocol_violation`, `query_error`, or `cancellation_unconfirmed` | Inspect the available safe fields and server/driver health. Timeout and cancellation results carry their structured native/query identity where available; the protected context is retired. |

Human `check` output includes the reason message. Human `history` is intentionally compact; use
`history --output json` for the full durable terminal reason. Reusing the same request UUID replays
the already-published outcome rather than rerunning it. Unsupported declared driver/profile pairs
and SQL Server target or metadata roles fail contract/application validation before a run is
created, so they do not produce a durable `open_source` result.

The development fixture requires Linux/amd64 Docker, reserves a 3 GiB container limit with 2 GiB
available to SQL Server, and uses disposable local credentials. Copy its ignored environment and
start the engine:

```console
# POSIX
cp tests/fixtures/mssql-2022/.env.example tests/fixtures/mssql-2022/.env

# PowerShell
Copy-Item tests/fixtures/mssql-2022/.env.example tests/fixtures/mssql-2022/.env

docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml up --detach --wait sqlserver
```

Run the explicit administrator bootstrap, seed through the separate setup-writer login, and verify
the restricted reader:

```console
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml run --rm setup-admin
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml run --rm setup-writer
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml run --rm verify
```

Run the SQL Server integration tests with the fixture-only port, reader password, setup-writer
password, and disposable administrator password. Start the PostgreSQL 17 fixture too for the mixed
endpoint test. Administrator and setup-writer connections are fixture orchestration only; product
reads still use the least-privilege reader. The tests construct fixed localhost connections and
their explicit test-only certificate exception:

```console
uv run --env-file tests/fixtures/postgres/.env --env-file tests/fixtures/mssql-2022/.env pytest tests/test_mssql_integration.py tests/test_mssql_canonical_integration.py tests/test_mssql_postgres_comparison_integration.py
```

The bootstrap recreates the main and RCSI-only fixture databases and their two fixture logins.
Verification requires the exact `16.0.4295.3` Developer build, compatibility level 160,
`ALLOW_SNAPSHOT_ISOLATION=ON` for the main database, `SNAPSHOT=OFF` plus RCSI ON for the negative
fixture, and denied reader DML and DDL. The reader and setup-writer services never receive the `sa`
credential. The SQL Server 2022-to-PostgreSQL endpoint verifies the million-row baseline, exact
`999,967 matched / 21 missing / 4 extra / 12 modified` corruption oracle, 37 retained differences,
physical provenance, and metadata-only history/diff after later source mutation. The real SQL
Server 2016 source profile is not yet implemented or verified.

The `sa` password is persisted in the SQL Server system databases. If you change it in the ignored
environment file, remove only this disposable fixture and its owned volume before starting again:

```console
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml down --volumes --remove-orphans
```
