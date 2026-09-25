# Forensic Data Engine

Forensic Data Engine compares scoped datasets across database systems, reports matches and concrete
discrepancies, and preserves durable evidence that can still be reviewed after source access
changes. It refuses to silently round, normalize, or drop values.

The current `0.1.0.dev0` package is a development release with a typed Python API and a `forensics`
CLI. Source connections are read-only. It supports verified PostgreSQL comparisons, verified SQL
Server 2016- and 2022-source-to-PostgreSQL workflows, and verified PostgreSQL 17.11- and SQL Server
2022-source-to-Greengage 7.5 target workflows. Reads are bounded and protected by readiness
acquisition, with durable history, retained typed differences, and explicit completed, incomplete,
or error outcomes.

There is no scheduler integration or background service yet. Static planning does not connect to a
database or prove readiness, capability, schema presence, or data equality.

## First run

The primary delivery is a one-shot, non-root DFE container plus a dedicated PostgreSQL 17.11
database that stores runs, results, and retained evidence for comparisons across all source systems.
Start with the [complete Docker quickstart](guides/docker-quickstart.md), which
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

| Verified database/version | Source | Target |
|---|---|---|
| PostgreSQL 17.11 | Verified | Verified |
| PostgreSQL 9.6.24 | Verified | Not yet verified |
| SQL Server 2016 SP3 GDR `13.0.6500.1` | Verified | Not yet implemented or verified |
| SQL Server 2022 Developer CU27 `16.0.4295.3` | Verified | Not yet implemented or verified |
| Greengage 7.5.0 | Not yet verified | Verified |

This matrix records tested configurations, not a version allowlist. Database connections are not
rejected solely because their server version, edition, or driver patch is untested. The selected
adapter strategy must still satisfy its SQL, encoding, type, and read-consistency requirements.
The legacy PostgreSQL strategy can be selected for either comparison side. SQL Server source
strategies are selected explicitly as `mssql_2016` or `mssql_2022`; there is no silent profile
fallback. SQL Server 2017 and 2019 have not been verified.

The [Greenplum-family guide](guides/greenplum.md) covers the verified Greengage 7.5 target endpoint,
including its verified relation and type coverage, and separately records the real distributed
artifact evidence for original Greenplum `4.3.99.00 build dev` and Greengage 7.5.0. Original
Greenplum source admission and execution remain unverified.

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
- [SQL Server source profiles](guides/sql-server.md) — the exact SQL Server 2016 and 2022
  conformance points, explicit strategies, owner-installed legacy helper, protected reads,
  fixtures, and resource limits.
- [Greengage target and Greenplum-family artifacts](guides/greenplum.md) — verified Greengage
  target operation, current endpoint limits, and exact distributed artifact provenance.
- [Development and verification](guides/development.md) — locked environment, real fixtures,
  required checks, cleanup, and package/container builds.

## Examples

- [Docker quickstart contract](examples/docker-quickstart/contract.yaml)
- [PostgreSQL relation-manifest contract](examples/postgres-relation-manifest/contract.yaml)
- [PostgreSQL SQL-backed contract](examples/postgres-row/contract.yaml)
- [SQL Server-to-PostgreSQL fixture contract](tests/fixtures/mssql-2022/comparison-contract.yaml)
