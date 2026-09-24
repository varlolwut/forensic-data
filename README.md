# Forensic Data Engine

Forensic Data Engine is a typed, read-only foundation for detecting data differences and producing
explicit evidence of agreement across database systems without silently rounding, normalizing, or
dropping values.

The current `0.1.0.dev0` package is a development release with a typed application API and a
`forensics` CLI for the PostgreSQL relation-manifest workflow. It provides:

- strict comparison-result models with distinct completed, incomplete, and error outcomes;
- the versioned `dfe_canon_v1` row/key envelope, schema digest, SHA-256 fingerprint, and segment
  identity primitives;
- a strict version-1 YAML contract loader, pure reference/schema resolver, semantic digests, and
  static plan report;
- a bounded PostgreSQL read connector, protected relation-manifest readiness acquisition, and SQL
  lowering for the initial common type profile;
- versioned PostgreSQL metadata migrations, typed immutable contract registration, durable
  run/acquisition lifecycle records, and completed or interrupted comparison results;
- bounded PostgreSQL check execution, idempotent request IDs, attempt history, retained typed
  difference evidence, and metadata-only result replay; and
- reproducible Python package, PostgreSQL fixture, container, and CI builds.

There is no scheduler integration, background service, or multi-engine execution workflow yet.
Static planning does not connect to a database or prove readiness, capability, schema presence, or
data equality.

## Docker quickstart

The primary delivery is a one-shot, non-root DFE container plus a dedicated PostgreSQL 17.11
metadata store. The synthetic source is opt-in through the `demo` profile; the default box does not
contain or connect to a production warehouse. This path needs Docker with Compose, not host Python,
`uv`, or `psql`.

The commands below were verified on Linux/amd64 containers with Docker Desktop 4.86.0, Docker
Engine 29.7.2, and Docker Compose 5.3.1. A lower Docker/Compose or resource minimum has not yet been
certified.

From a clean checkout, generate random local credentials and an output directory. The generator is
idempotent and never overwrites existing secrets:

```console
mkdir -p .local/docker-quickstart
DFE_HOST_UID="$(id -u)" DFE_HOST_GID="$(id -g)" \
  docker compose --file examples/docker-quickstart/secrets.compose.yaml run --rm generate
docker compose --file examples/docker-quickstart/secrets.compose.yaml down
```

On Docker Desktop for Windows, use PowerShell; the host IDs default to the container UID/GID
`10001`:

```powershell
New-Item -ItemType Directory -Force .local/docker-quickstart | Out-Null
docker compose --file examples/docker-quickstart/secrets.compose.yaml run --rm generate
docker compose --file examples/docker-quickstart/secrets.compose.yaml down
```

On native Linux, pass the host IDs as shown in the first block so the protected secret directory and
output remain accessible to the invoking account. Pre-creating the state path also prevents Docker
from creating an undeletable root-owned `.local` parent.

The generated files live under the ignored `.local/docker-quickstart` directory. They are mounted
through Compose secrets and are never copied into the image. Keep them with the metadata backup: if
one is lost after initialization, restore that original secret rather than generating a new set.

Build the DFE image, start the persistent metadata database and opt-in synthetic source, then run
the explicit bootstrap and migrations:

```console
docker compose build dfe
docker compose --profile demo up --detach --wait metadata demo-postgres
docker compose run --rm metadata-init
docker compose run --rm metadata-migrate
```

`metadata-init` has the admin and login-password secrets. `metadata-migrate` has only the migrator
DSN. Neither `up` nor a normal DFE command silently bootstraps, migrates, resets, or deletes the
metadata volume. Both setup commands are safe to repeat against compatible state; a repeated
migration reports `Applied migrations: none (already current)`.

Run the real comparison, then inspect durable history and retained row differences:

```console
docker compose run --rm demo-check
docker compose run --rm demo-history
docker compose run --rm demo-diff
```

The demo intentionally returns a completed mismatch: one modified row, one missing row, and one
extra row, all under exact coverage. The underlying `forensics check` exit code is `1`, meaning a
completed data mismatch rather than an engine failure; the demo wrapper validates that expected
outcome and exits successfully. It prints the verdict, coverage, totals, and next action. Machine
JSON is written to `.local/docker-quickstart/output/{check,history,diff}.json` through the separate
writable output bind. The check service receives only source-reader and metadata runtime-writer
secrets; history and diff receive only the metadata-reader secret and never query the source.

To prove persistence, stop the demo source, recreate the metadata container without deleting its
named volume, and read the same stored result again:

```console
docker compose stop demo-postgres
docker compose stop metadata
docker compose rm --force metadata
docker compose up --detach --wait metadata
docker compose run --rm demo-history
docker compose run --rm demo-diff
```

Normal shutdown preserves both named volumes:

```console
docker compose --profile demo down
```

Do not use `down --volumes` for normal shutdown or upgrade. Before changing the DFE or PostgreSQL
image, back up the `forensic-data_metadata-data` volume and the matching secret files using the
organization's PostgreSQL backup procedure, start the compatible metadata service, and run the
explicit `metadata-init` and `metadata-migrate` commands. Migration refuses gaps, changed checksums,
and unknown newer versions rather than resetting the store.

For your own data, start from `examples/docker-quickstart/contract.yaml`, replace the synthetic
relations and manifests, and mount one full PostgreSQL DSN per connection at the absolute
`file:/run/secrets/...` paths named by the contract. Add those secret mounts with a local Compose
override so each one-shot service receives only the endpoints it uses. Source logins must be
read-only; the metadata runtime login needs both writer and reader capability memberships. The
standalone CLI and orchestrators may continue to use `env:NAME` references. The generated demo DSNs
use `sslmode=disable` only on the private local Compose network; use the organization's required TLS
mode and certificates for external endpoints.

## Verified scope

The modern PostgreSQL path is verified against PostgreSQL 17.11 on Linux/amd64 with Psycopg 3.3.6
and the explicit `psycopg` / `postgresql_17` driver-profile pair. Modern source, target, and metadata
connections require PostgreSQL 17.x, UTF-8 server/client encodings, integer datetimes, UTC, and a
read-only Repeatable Read transaction for source data.

An additional source-only path is verified against the exact PostgreSQL 9.6.24 official
Linux/amd64 image with Psycopg2 2.9.13 and the explicit `psycopg2` / `postgresql_9_6` pair. Its
target and metadata connections must remain on the modern profile. The legacy source must use
UTF-8, integer datetimes, UTC, and read-only Repeatable Read, and must already have pgcrypto 1.3 in
schema `dfe_ext`; the reader needs `USAGE` on that schema and `EXECUTE` on
`dfe_ext.digest(bytea,text)`. Runtime validates these capabilities and the canonical SHA-256 result;
it never installs the extension or silently changes drivers. Other PostgreSQL 9.6 patches, other
PostgreSQL majors, and other database engines are not verified by the current code.

Relations must be given as an exact `(schema, table)` pair and select one explicit scope. The
default `physical_only` scope reads one permanent regular table with `FROM ONLY`: ordinary
inheritance children are excluded, a partition leaf can be addressed directly, and partitioned
parents and views are rejected. The opt-in `frozen_physical_union` scope resolves the root's full
inheritance or partition hierarchy, accepts only permanent regular or partitioned members, and
reads every discovered regular member through an explicit `ONLY` branch. Partitioned members are
retained as topology-only evidence and do not contribute their own rows.

Protected acquisition resolves and holds every selected dataset member plus the physical-only
readiness manifest with `ACCESS SHARE` locks before the first snapshot-forming query in the
read-only Repeatable Read transaction. It then proves the hierarchy again inside that snapshot.
Qualified identities, direct edges, row types, and projected physical bindings are sealed for the
life of the context, including across empty reads. A relation attached after that frozen closure is
not added to the query; detaching or replacing a locked member is blocked until the context closes.

The initial logical-to-physical mappings are:

| Logical type | Accepted PostgreSQL base types |
|---|---|
| `int64` | `smallint`, `integer`, `bigint`, exact integral `numeric` |
| `decimal(p,s)` | `smallint`, `integer`, `bigint`, exact `numeric` |
| `boolean` | `boolean` |
| `string` | `text`, `varchar` |
| `date` | `date` |
| `timestamp_local(p)` | `timestamp without time zone` |
| `timestamp_instant(p)` | `timestamp with time zone` |

Domains, arrays, blank-padded `character`, lossy decimal/timestamp values, unsupported relation
kinds, and envelopes above the configured byte budget fail explicitly. Fingerprint mismatch proves
a content difference; fingerprint match must be treated as probabilistic.

Relation comparison charges by the compiled physical query shape. If a side has `C` row-contributing
regular members, its summary reserves `C` full-scan-equivalents and a request containing `R`
fingerprint or exact ranges reserves `R × C`; topology-only partitioned members contribute zero
scans. The physical-only relation-manifest example still has `C = 1`, so its corruption path
reserves five per side: one summary, one root fingerprint range, two child fingerprint ranges, and
one exact range. A budget of four cannot complete that path. Result-byte and coordinator-memory
reservations also include every member's bounded provenance witness and the empty-result sentinel.
Reported `coordinator_peak_bytes` is the conservative reservation high-water estimate for retained
and decoded coordinator data, not a measurement of process RSS or allocator peak usage.

## Developer setup

- Python 3.12
- [uv](https://docs.astral.sh/uv/) 0.12.18
- Docker with Compose for PostgreSQL and SQL Server integration tests

The locked PostgreSQL drivers are C extensions built from source. A direct host installation
therefore needs a C toolchain plus `pg_config` and matching libpq development headers. The
production Docker build provides the reproducible path: it builds Psycopg 3.3.6 and Psycopg2
2.9.13 against the same pinned libpq 17.11, installs the pinned Microsoft ODBC Driver
18.7.1.1-1 runtime for pyodbc 5.3.0, and excludes compilers and headers from the runtime image.

Install the locked development environment:

```console
uv sync --frozen --all-groups
uv run python -c "import forensic_data; print(forensic_data.__version__)"
```

## CLI and application workflow

The installed `forensics` command exposes four bounded data operations plus explicit metadata
migration administration. The relation-manifest example uses the check and scope names shown below:

```console
uv run forensics plan --config examples/postgres-relation-manifest/contract.yaml --check daily_orders --scope-json '{"business_date":"2026-09-23"}' --output json

uv run forensics check --config examples/postgres-relation-manifest/contract.yaml --check daily_orders --scope-json '{"business_date":"2026-09-23"}' --reference-batch reference-batch-42 --target-batch target-batch-42 --request-id 7fa700c4-7c5d-42eb-8f55-50e372ed0e25 --output json

uv run forensics history --config examples/postgres-relation-manifest/contract.yaml --check daily_orders --scope-json '{"business_date":"2026-09-23"}' --limit 20 --output json

uv run forensics diff --config examples/postgres-relation-manifest/contract.yaml --run-id 04be2d56-6c2f-4f66-8c84-4cfdb33a79ea --attempt-id 2d4d807a-a079-424a-8a67-a48b27777386 --limit 20 --output json

uv run forensics diff --config examples/postgres-relation-manifest/contract.yaml --run-id 04be2d56-6c2f-4f66-8c84-4cfdb33a79ea --attempt-id 2d4d807a-a079-424a-8a67-a48b27777386 --limit 20 --cursor-json '{"run_id":"04be2d56-6c2f-4f66-8c84-4cfdb33a79ea","attempt_id":"2d4d807a-a079-424a-8a67-a48b27777386","check_id":"daily_orders","result_operation_id":"6c499e11-e120-484b-945a-c49960e2d17c","sequence":19}' --output json
```

Scope input is an exact JSON object whose values are booleans, integers, or strings. `check`
requires both expected batch IDs and a canonical request UUID; repeating that request reads the
same durable outcome instead of silently creating a different run. History and diff pagination use
`--cursor-json` with the exact `next_cursor` object returned by the previous page. A diff cursor is
bound to the run, attempt, check, immutable result operation, and last retained sequence, so it
cannot be reused for another result.

For every connection a command resolves, the CLI accepts endpoint secrets through an exact
`env:NAME` or `file:/absolute/path` contract reference. Either source must contain one complete
PostgreSQL DSN with `host`, `port`, `dbname`, `user`, `password`, `sslmode`, and `connect_timeout`;
there is no raw-DSN command-line flag or provider fallback. A secret file must be a readable regular
file of at most 16 KiB containing exactly one non-empty UTF-8 DSN line. Errors never print its path
or contents. `plan` neither resolves secret references nor opens a connection. `history` and `diff`
resolve only the metadata connection and never query a source or target endpoint.

The metadata login used by `check` or `execute_check` must be a member of both
`dfe_metadata_writer` and `dfe_metadata_reader`. The login used by `history`, `diff`,
`read_history`, or `read_diff` needs only `dfe_metadata_reader`. Keep those capability roles
separate and grant both memberships to the runtime writer login; metadata migrator and database
administrator credentials are only for setup and bootstrap.

Packaged metadata migrations are applied explicitly with a migrator-only connection:

```console
forensics metadata migrate --secret-ref file:/run/secrets/metadata_migrator_dsn --statement-timeout-milliseconds 30000 --lock-timeout-milliseconds 5000
```

The command validates the PostgreSQL 17 profile, takes the migration advisory lock, checks the
entire stored checksum prefix, and applies the pending batch transactionally. It is never invoked by
`check`, `history`, or `diff`.

Evidence retention is explicit per projected field. `store` retains the typed canonical value;
`redact` retains the field/type and an explicit unavailable marker but not the raw value; `omit`
retains no value for that field. `unspecified_fields` applies the declared action to every field
without an explicit entry. The shipped relation-manifest example stores `order_id` and `amount`,
omits `business_date`, and omits any otherwise unspecified field. A key digest exists only when the
complete key is retained; no key digest is emitted for a redacted or omitted key.
Human diff rows show a missing side as `<absent>`, a retained SQL null as `NULL`, and a redacted
value as `<redacted>`; omitted field names are listed separately from both nulls and absent sides.

Human output is the default. `--output json` emits the exact schema-version 1 typed model returned
by the corresponding application API: `PlanReport`, `RunResult`, `HistoryPage`, or `DiffPage`.
In `forensic_data.application`, `plan_check` accepts a compiled contract and typed request,
`execute_check` adds explicit PostgreSQL execution services, and `read_history`/`read_diff` accept
typed requests with metadata-only services. A `PlanReport` is informational and cannot be supplied
to `execute_check`; execution resolves and validates the compiled contract again.

Human `check` and `diff` output names the logical connection and dataset, the quoted qualified
relation (or SQL dialect and content digest), and canonical scope values. It never prints a DSN,
secret reference, or credential. `check` renders current labels only after the returned result
identity matches the validated check, contract, and scope. Historical `diff` uses the immutable
comparison context stored with the result rather than relabeling it from the current YAML.

| Exit code | Meaning |
|---:|---|
| `0` | Command succeeded; for `check`, the completed result is a match. |
| `1` | The check completed with a mismatch. |
| `2` | The check ended in error, or command/configuration input failed. |
| `3` | The check is incomplete, such as when readiness or a required execution budget was not established. |

History returns bounded durable attempt metadata and an optional stored result. Diff is also a
metadata-only view: it pages immutable retained evidence and never revisits the compared endpoints,
so later source mutations cannot change an already published page. `found_records` describes the
comparison findings while `retained_records` and `detail_availability` truthfully describe what the
evidence row/byte policy allowed the metadata store to keep. A completed full manifest supports
full replay only after the complete ordered retained-evidence manifest validates; partial retention
is explicitly marked and completeness must not be inferred from a count or a final page alone.

If a query, snapshot, or execution budget interrupts comparison after useful work, the attempt keeps
an immutable partial result with its established totals, coverage frontier, metrics, reasons, and
any policy-permitted anomaly prefix. It remains an incomplete or error outcome rather than being
reported as completed. Replaying the same request returns that durable outcome and diff pages expose
only its retained prefix, with truncation explicit.

## Canonical API example

```python
from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    FieldSchema,
    LogicalType,
    NoParameters,
    Normalization,
    encode_row,
    fingerprint_rows,
)

schema = CanonicalSchema(
    protocol=PROTOCOL,
    fields=(
        FieldSchema(
            name="record_id",
            logical_type=LogicalType.INT64,
            nullable=False,
            parameters=NoParameters(),
            normalization=Normalization.NONE,
        ),
    ),
)
envelope = encode_row(schema, (42,))
fingerprint = fingerprint_rows((envelope,))
```

The envelope bytes are the comparison input. Do not substitute database-native text formatting or
hash a different serialization and call it protocol-compatible.

## Static contract and plan

The version-1 contract requires explicit `connections`, `schemas`, `datasets`, `checks`,
`consistency`, `execution`, `metadata`, and `evidence` mappings. Named `scopes` are optional, but
every check must provide exactly one inline scope or resolvable scope reference. Unknown or duplicate
YAML keys fail validation. Connections contain a `secret_ref`; inline credentials and DSNs are not
part of the contract shape.

Datasets use exactly one relation locator or SQL artifact. A relation locator defaults to
`relation_scope: physical_only`; `relation_scope: frozen_physical_union` must be selected explicitly
and is part of the dataset's immutable semantic identity. Readiness relations remain
`physical_only`. Relative SQL artifact paths are resolved from the contract directory; absolute and
UNC paths are also accepted for operator-managed files.
The loader assumes the contract and artifacts remain stable while they are captured, reads each
distinct artifact once as strict UTF-8, and binds its exact bytes by SHA-256. Contract input is
bounded to 1 MiB, composed YAML to 10,000 nodes, and nesting to 64 levels; YAML aliases are rejected.
Each SQL artifact is bounded to 4 MiB and all distinct SQL artifacts to 32 MiB. The compiler resolves
every reference and validates ordered schemas, projection, grain, keys, scope bindings, readiness
parameters, and direction roles without opening an endpoint.

```python
from pathlib import Path

from forensic_data.contracts import load_contract_config
from forensic_data.planning import compile_static_plan

config = load_contract_config(Path("examples/postgres-row/contract.yaml"))
plan = compile_static_plan(
    config,
    "daily_orders",
    {"business_date": "2026-09-23"},
)
print(plan.model_dump_json(indent=2))
```

The checked-in [SQL-backed example](examples/postgres-row/contract.yaml) is complete and loadable,
but planning it remains static. Its readiness SQL describes operator-managed batch-manifest
evidence; capturing that SQL does not execute it or prove the sources ready. SQL dataset locators
and opaque SQL readiness artifacts are not supported by the current runtime acquisition path.

The [native relation-manifest example](examples/postgres-relation-manifest/contract.yaml) shows the
runtime-supported readiness form. Static planning is still informational for this example and does
not itself acquire a snapshot or compare data.

`contract_digest` identifies the resolved comparison semantics but excludes runtime scope values,
secrets, paths, budgets, evidence settings, and metadata settings. `scope_digest` binds the typed
values for this invocation. A `PlanReport` is not a comparison result: its live probes and execution
stages remain explicitly `required_not_run` or `planned_not_run`, and its estimates remain
`unknown`. It is unsigned informational output, not an authenticated executable contract; digest
fields in a deserialized report are sender claims. Execution must load and compile the source
contract again rather than trusting a supplied report.

## Native readiness and durable acquisition

The native `relation_manifest` provider runs on the same connection as its dataset and requires an
explicit mapping for exactly eight facts: `dataset_id`, `scope_digest`, `batch_id`, `state`,
`business_date`, `source_cut`, `dataset_version`, and `completed_at`. It reads the current manifest
head for the requested dataset and scope, then checks the expected batch in application code. Zero
rows, more than one row, a `building` row, or a different batch produces a typed `NOT_READY`
outcome. Unknown state values, malformed identities, invalid physical types, and malformed
completion facts are errors.

The runtime request supplies expected batch IDs separately for the reference and target; they may
differ, and the provider never chooses a latest batch automatically. The loader must publish the
dataset and its current manifest head consistently, mark a row `complete` only after the data is
ready, issue a new `dataset_version` whenever the published dataset cut changes, and keep
`source_cut` consistent with the upstream cut. `VERIFIED` means that these facts were observed in
the protected snapshot under that publication protocol, not that the provider independently proved
the manifest's truthfulness.

Metadata persistence records immutable run requests, leased attempts, protected read contexts,
per-dataset readiness observations, and completed or partial comparison results. The first aligned
input cut is bound once to the run; retries may use a new snapshot but cannot silently change that
cut. Observations and retained anomalies must belong to the same attempt, so a retry cannot publish
evidence captured under an earlier snapshot. Attempts may be completed, incomplete, error, or
abandoned. A result is published only after its observations, closed protected contexts, comparison
output, retained-evidence manifest, and terminal attempt state pass durable closure validation.

Internal retries within one `forensics check` invocation share one owner token and one in-memory
whole-run source budget. A fresh process, including an Airflow task retry, cannot resume a
nonterminal run that already admitted an attempt: inspect its durable history and start the retry
with a new request UUID. Version 0.1 deliberately does not persist cross-process source-budget
usage, so treating an external retry as continuation would make the configured whole-run limits
untruthful.

## PostgreSQL metadata bootstrap

Metadata installation is an explicit administrator operation. The packaged bootstrap creates and
validates three fixed `NOLOGIN` capability roles and the `dfe_metadata` schema; it never creates
login accounts, stores passwords, or takes over an incompatible existing role, schema, or ACL. An
operator grants the appropriate capability role to separately managed login accounts.

Render and review the exact packaged bootstrap before applying it to the dedicated metadata
database:

```console
python -c "from pathlib import Path; from forensic_data.persistence import load_postgres_metadata_bootstrap_sql as load; Path('dfe-metadata-bootstrap.sql').write_bytes(load().encode('utf-8'))"
psql "$DFE_METADATA_ADMIN_DSN" --set=ON_ERROR_STOP=1 --file dfe-metadata-bootstrap.sql
```

After bootstrap, `migrate_postgres_metadata(settings, retry_policy,
lock_timeout_milliseconds)` applies the packaged numbered SQL with an advisory transaction lock.
The journal must be an exact checksum-matching prefix of the package; unknown, missing, renamed, or
changed migrations fail explicitly. Repeating an up-to-date migration is a no-op. Runtime reader
and writer roles can validate the journal version but cannot change it or perform schema DDL.

`build_metadata_registration_definition(...)` creates the safe persistence boundary from a
validated row check. `register_postgres_metadata(...)` then stores immutable dataset and contract
versions and append-only SQL capture records. Secret references, artifact paths, budgets, and SQL
bytes disabled by the evidence policy are never stored. A later enabled capture creates a separate
record without mutating the semantic version. Migration `0002` adds run, attempt, protected
read-context, and dataset-observation records plus narrow immutable lease-renewal receipts;
migration `0003` adds completed check results and segment fingerprints; migration `0004` adds
partial check results, immutable retained anomalies and their full-replay manifest, plus the typed
numeric-difference inspection view; migration `0005` admits the immutable
`frozen_physical_union` dataset scope. Dataset observations keep each side's root and complete
member/edge composition with per-member binding digests; the composition digest is evidence of the
observed protected closure, not an equality requirement between source and target physical OIDs.

## PostgreSQL fixture and checks

Copy the disposable local fixture environment. The checked-in values are development-only
credentials bound to `127.0.0.1` with `sslmode=disable`; replace the security profile if the
fixture is used anywhere else.

If you change `DFE_PG_PORT`, update the port in every test DSN in the same environment file. If you
change a fixture password, update the matching password in its DSN too.

```console
# POSIX
cp tests/fixtures/postgres/.env.example tests/fixtures/postgres/.env
cp tests/fixtures/postgres-legacy/.env.example tests/fixtures/postgres-legacy/.env
cp tests/fixtures/mssql-2022/.env.example tests/fixtures/mssql-2022/.env

# PowerShell
Copy-Item tests/fixtures/postgres/.env.example tests/fixtures/postgres/.env
Copy-Item tests/fixtures/postgres-legacy/.env.example tests/fixtures/postgres-legacy/.env
Copy-Item tests/fixtures/mssql-2022/.env.example tests/fixtures/mssql-2022/.env
```

Start the pinned PostgreSQL fixtures and the SQL Server fixture, configure SQL Server through its
separate setup identities, then run the full gate. The host running pytest must have Microsoft ODBC
Driver 18.7.1.1 installed; CI and the production image install the exact package automatically.

```console
docker compose --env-file tests/fixtures/postgres/.env --file tests/fixtures/postgres/compose.yaml up --detach --wait
docker compose --env-file tests/fixtures/postgres-legacy/.env --file tests/fixtures/postgres-legacy/compose.yaml up --detach --wait
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml up --detach --wait sqlserver
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml run --rm setup-admin
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml run --rm setup-writer
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml run --rm verify
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run --env-file tests/fixtures/postgres/.env --env-file tests/fixtures/postgres-legacy/.env --env-file tests/fixtures/mssql-2022/.env pytest
```

PostgreSQL applies these credentials only when its data volume is initialized. If the fixture was
previously started with different values, run the cleanup command below before starting it again.

The protocol/result tests can run without Docker, but this does not verify database support:

```console
uv run pytest --ignore=tests/test_mssql_integration.py --ignore=tests/test_postgres_integration.py --ignore=tests/test_postgres_metadata_integration.py --ignore=tests/test_postgres_protected_integration.py --ignore=tests/test_postgres_lifecycle_schema_integration.py --ignore=tests/test_postgres_lifecycle_integration.py --ignore=tests/test_postgres_comparison_integration.py --ignore=tests/test_postgres_legacy_integration.py
```

Stop and remove only these disposable fixtures and their data volumes:

```console
docker compose --env-file tests/fixtures/postgres/.env --file tests/fixtures/postgres/compose.yaml down --volumes
docker compose --env-file tests/fixtures/postgres-legacy/.env --file tests/fixtures/postgres-legacy/compose.yaml down --volumes
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml down --volumes --remove-orphans
```

The integration suite exercises real catalog inspection, canonical row/hash equivalence, bounded
server-side cursors, duplicate bags, empty tables, precision rejection, relation replacement, row
level security, read-only enforcement, concurrent-writer snapshot stability, protected
dataset/manifest locking, metadata migration serialization and rollback, role separation, immutable
registration/readback, lifecycle fencing and identity constraints, million-row retained-difference
paging after source mutation, typed numeric evidence, durable partial-result replay, and frozen
partition/inheritance compositions with concurrent membership-change behavior and durable
per-endpoint evidence.
The legacy endpoint gate additionally proves the exact PostgreSQL 9.6.24 source profile, its
preinstalled pgcrypto capability, PostgreSQL 17.11 target interoperability, persisted driver/server
provenance, and an exact retained `1 matched / 1 missing / 1 extra / 1 modified` result.

## SQL Server 2022 fixture

The development fixture pins the official SQL Server 2022 Developer CU27 Ubuntu 22.04 image by
digest. It requires Linux/amd64 Docker and reserves a 3 GiB container limit with 2 GiB available to
SQL Server. Copy the development-only environment and start the engine:

The selected Python client is pyodbc 5.3.0 over Microsoft ODBC Driver 18.7.1.1-1. External
connections must use encrypted transport with certificate validation
(`Encrypt=Mandatory;TrustServerCertificate=No`) and a least-privilege login. The localhost fixture
alone uses `TrustServerCertificate=Yes` because its disposable endpoint has no trusted certificate;
that fixture exception is not a production trust policy.

SQL Server `datetime2(7)` must be projected as deterministic ISO-126 text and validated as text:
Python `datetime` preserves only six fractional digits. Decimal values remain `Decimal` and
`nvarchar` remains Unicode. `fetchmany(batch_size)` bounds the number of materialized rows, but it
does not bound one `varchar(max)`, `nvarchar(max)`, or `varbinary(max)` value; queries must separately
bound or reject oversized values. The transport separately caps a declared value, row, transient
batch, and retained result; those decoded-payload limits are not a measurement of process RSS.

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

Run the SQL Server integration tests with the fixture-only port, reader password, and disposable
administrator password. The administrator connection only observes the in-flight cancellation
probe; product reads still use the least-privilege reader. The tests construct fixed localhost
connections and their explicit test-only certificate exception:

```console
uv run --env-file tests/fixtures/mssql-2022/.env pytest tests/test_mssql_integration.py
```

The bootstrap recreates only the fixture database and its two fixture logins. Verification requires
the exact `16.0.4295.3` Developer build, `ALLOW_SNAPSHOT_ISOLATION=ON`,
`READ_COMMITTED_SNAPSHOT=OFF`, an actual reader data access inside a transaction-level `SNAPSHOT`,
and denied reader DML and DDL. The reader and setup-writer services never receive the `sa`
credential. This fixture proves the P03-01 environment boundary, not a completed MSSQL adapter or
cross-engine comparison.

The `sa` password is persisted in the SQL Server system databases. If you change it in the ignored
environment file, remove only this disposable fixture and its owned volume before starting again:

```console
docker compose --env-file tests/fixtures/mssql-2022/.env --file tests/fixtures/mssql-2022/compose.yaml down --volumes --remove-orphans
```

## Build artifacts

Build the wheel/source distribution and the non-root one-shot CLI image:

```console
uv sync --frozen --only-group build
uv lock --check
uv build --no-build-isolation --no-create-gitignore --clear
docker build --platform linux/amd64 --tag forensic-data:dev .
docker run --rm forensic-data:dev
```

The default container command prints CLI help. Supply a normal `forensics` argument list after the
image name; the image remains a one-shot process rather than a long-running service.
