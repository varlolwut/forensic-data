# Forensic Data Engine

Forensic Data Engine compares scoped datasets across database systems, reports matches and concrete
discrepancies, and preserves durable evidence that can still be reviewed after source access
changes. It refuses to silently round, normalize, or drop values.

The current `0.1.0.dev0` package is a development release with a typed Python API and a `forensics`
CLI. Source connections are read-only. It supports verified PostgreSQL comparisons and the verified
SQL Server 2022-source-to-PostgreSQL workflow, with bounded reads, protected readiness acquisition,
durable history, retained typed differences, and explicit completed, incomplete, or error outcomes.

There is no scheduler integration or background service yet. Static planning does not connect to a
database or prove readiness, capability, schema presence, or data equality.

## First run

The primary delivery is a one-shot, non-root DFE container plus a dedicated PostgreSQL 17.11
metadata store. Start with the [complete Docker quickstart](guides/docker-quickstart.md), which
includes the required Linux and Docker Desktop credential-generation steps. After generating those
local secrets, the common first-run path is:

```console
docker compose build dfe
docker compose --profile demo up --detach --wait metadata demo-postgres
docker compose run --rm metadata-init
docker compose run --rm metadata-migrate
docker compose run --rm demo-check
docker compose run --rm demo-history
docker compose run --rm demo-diff
docker compose --profile demo down
```

The demo intentionally returns a completed mismatch under exact coverage: one modified row, one
missing row, and one extra row. The underlying `forensics check` exit code is `1`, meaning a
completed data mismatch rather than an engine failure. The demo wrapper validates that result and
writes machine JSON to `.local/docker-quickstart/output/{check,history,diff}.json`.

## Verified matrix

| Verified database/version | Source | Target | Metadata store |
|---|---|---|---|
| PostgreSQL 17.11 | Verified | Verified | Verified |
| PostgreSQL 9.6.24 | Verified source-only profile | Not supported | Not supported |
| SQL Server 2022 Developer CU27 `16.0.4295.3` | Verified source-only profile | Not supported | Not supported |

Other PostgreSQL majors and PostgreSQL 9.6 patches are not verified. SQL Server 2016/2017/2019 are
not implemented or verified, and there is no silent profile fallback.

Runtime capability admission is wider than an exact verified conformance point and does not certify
untested builds, editions, operating systems, or driver patches. See the
[PostgreSQL guide](guides/postgresql.md) and [SQL Server guide](guides/sql-server.md) for relation,
type, snapshot, provenance, assurance, and resource limits.

## Commands

| Command | Purpose |
|---|---|
| `forensics plan` | Compile and inspect a contract without opening database connections. |
| `forensics check` | Execute a bounded comparison and publish its durable outcome. |
| `forensics history` | Read bounded durable attempt history from metadata only. |
| `forensics diff` | Page immutable retained evidence from metadata only. |
| `forensics metadata migrate` | Apply packaged metadata migrations with a migrator-only connection. |

Human output is the default; `--output json` returns the schema-version 1 typed model. A completed
match exits `0`, a completed mismatch exits `1`, an error exits `2`, and an incomplete check exits
`3`. Full invocation, pagination, secret-reference, retention, and API details are in
[CLI and contracts](guides/cli-and-contracts.md).

## Guides

- [Docker quickstart](guides/docker-quickstart.md) — secrets, first run, persistence proof, shutdown,
  backup, and connecting your own data.
- [CLI and contracts](guides/cli-and-contracts.md) — commands, typed API, static planning, retention,
  pagination, output, and exit behavior.
- [PostgreSQL profiles and operation](guides/postgresql.md) — modern and 9.6 source profiles,
  physical scopes, readiness, budgets, and metadata bootstrap.
- [SQL Server source profile](guides/sql-server.md) — the exact SQL Server 2022 conformance point,
  runtime boundary, type matrix, diagnostics, and fixture.
- [Development and verification](guides/development.md) — locked environment, real fixtures,
  required checks, cleanup, and package/container builds.

## Examples

- [Docker quickstart contract](examples/docker-quickstart/contract.yaml)
- [PostgreSQL relation-manifest contract](examples/postgres-relation-manifest/contract.yaml)
- [PostgreSQL SQL-backed contract](examples/postgres-row/contract.yaml)
- [SQL Server-to-PostgreSQL fixture contract](tests/fixtures/mssql-2022/comparison-contract.yaml)
