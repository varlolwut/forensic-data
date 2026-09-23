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

## Verified scope

The PostgreSQL path is verified against PostgreSQL 17.11 on Linux/amd64 with Psycopg 3.3.6. The
connector requires a PostgreSQL 17.x server, UTF-8 server/client encodings, integer datetimes, UTC,
and a read-only Repeatable Read transaction. Other PostgreSQL majors and other database engines are
not verified by the current code.

Relations must be given as an exact `(schema, table)` pair. The connector reads one physical
regular table with `FROM ONLY`:

- ordinary inheritance children are deliberately excluded;
- a partition leaf can be addressed directly as a physical table;
- partitioned parents and views are rejected; and
- changing the qualified name to a different relation is detected before any result row is used.

Protected acquisition applies the same physical-only rule to both the dataset and its readiness
manifest: each must be a permanent regular table. On each dataset connection, both relations are
resolved and held with `ACCESS SHARE` locks before the first snapshot-forming query in the
read-only Repeatable Read transaction. This keeps the exact relation identities protected for the
life of that read context, including across empty reads.

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

Relation comparison charges one full-scan-equivalent per side for the summary, each fingerprint
range, and each exact range. The relation-manifest example's corruption path therefore reserves five
per side: one summary, one root fingerprint range, two child fingerprint ranges, and one exact
range. A budget of four cannot complete that path. Its reported `coordinator_peak_bytes` is the
conservative reservation high-water estimate for retained and decoded coordinator data, not a
measurement of process RSS or allocator peak usage.

## Prerequisites

- Python 3.12
- [uv](https://docs.astral.sh/uv/) 0.12.18
- Docker with Compose for the PostgreSQL integration tests

Install the locked development environment:

```console
uv sync --frozen --all-groups
uv run python -c "import forensic_data; print(forensic_data.__version__)"
```

## CLI and application workflow

The installed `forensics` command exposes four bounded operations. The relation-manifest example
uses the check and scope names shown below:

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

For every connection a command resolves, the CLI accepts endpoint secrets only through contract
references of the form `env:NAME`. The referenced variable must contain a complete PostgreSQL DSN
with `host`, `port`, `dbname`, `user`, `password`, `sslmode`, and `connect_timeout`; there is no
raw-DSN command-line flag or fallback. `plan` neither resolves secret references nor opens a
connection. `history` and `diff` resolve only the metadata connection and never query a source or
target endpoint.

The metadata login used by `check` or `execute_check` must be a member of both
`dfe_metadata_writer` and `dfe_metadata_reader`. The login used by `history`, `diff`,
`read_history`, or `read_diff` needs only `dfe_metadata_reader`. Keep those capability roles
separate and grant both memberships to the runtime writer login; metadata migrator and database
administrator credentials are only for setup and bootstrap.

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

Datasets use exactly one relation locator or SQL artifact. Relative SQL artifact paths are resolved
from the contract directory; absolute and UNC paths are also accepted for operator-managed files.
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
numeric-difference inspection view.

## PostgreSQL fixture and checks

Copy the disposable local fixture environment. The checked-in values are development-only
credentials bound to `127.0.0.1` with `sslmode=disable`; replace the security profile if the
fixture is used anywhere else.

If you change `DFE_PG_PORT`, update the port in every test DSN in the same environment file. If you
change a fixture password, update the matching password in its DSN too.

```console
# POSIX
cp tests/fixtures/postgres/.env.example tests/fixtures/postgres/.env

# PowerShell
Copy-Item tests/fixtures/postgres/.env.example tests/fixtures/postgres/.env
```

Start the pinned PostgreSQL 17.11 fixture and run the full gate:

```console
docker compose --env-file tests/fixtures/postgres/.env --file tests/fixtures/postgres/compose.yaml up --detach --wait
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run --env-file tests/fixtures/postgres/.env pytest
```

PostgreSQL applies these credentials only when its data volume is initialized. If the fixture was
previously started with different values, run the cleanup command below before starting it again.

The protocol/result tests can run without Docker, but this does not verify PostgreSQL support:

```console
uv run pytest --ignore=tests/test_postgres_integration.py --ignore=tests/test_postgres_metadata_integration.py --ignore=tests/test_postgres_protected_integration.py --ignore=tests/test_postgres_lifecycle_schema_integration.py --ignore=tests/test_postgres_lifecycle_integration.py --ignore=tests/test_postgres_comparison_integration.py
```

Stop and remove only this disposable fixture and its data volume:

```console
docker compose --env-file tests/fixtures/postgres/.env --file tests/fixtures/postgres/compose.yaml down --volumes
```

The integration suite exercises real catalog inspection, canonical row/hash equivalence, bounded
server-side cursors, duplicate bags, empty tables, precision rejection, relation replacement, row
level security, read-only enforcement, concurrent-writer snapshot stability, protected
dataset/manifest locking, metadata migration serialization and rollback, role separation, immutable
registration/readback, lifecycle fencing and identity constraints, million-row retained-difference
paging after source mutation, typed numeric evidence, and durable partial-result replay.

## Build artifacts

Build the wheel/source distribution and the non-root container smoke image:

```console
uv sync --frozen --only-group build
uv lock --check
uv build --no-build-isolation --no-create-gitignore --clear
docker build --platform linux/amd64 --tag forensic-data:dev .
docker run --rm forensic-data:dev
```

The current container is a build smoke image whose default command prints the installed package
version. The installed package includes the `forensics` CLI, but the image is not configured as a
long-running service.
