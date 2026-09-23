# Forensic Data Engine

Forensic Data Engine is a typed, read-only foundation for detecting data differences and producing
explicit evidence of agreement across database systems without silently rounding, normalizing, or
dropping values.

The current `0.1.0.dev0` package is a development library, not yet an end-to-end reconciliation
application. It provides:

- strict comparison-result models with distinct completed, incomplete, and error outcomes;
- the versioned `dfe_canon_v1` row/key envelope, schema digest, SHA-256 fingerprint, and segment
  identity primitives;
- a strict version-1 YAML contract loader, pure reference/schema resolver, semantic digests, and
  static plan report;
- a bounded PostgreSQL read connector, protected relation-manifest readiness acquisition, and SQL
  lowering for the initial common type profile;
- versioned PostgreSQL metadata migrations, typed immutable contract registration, and durable
  run/acquisition lifecycle records; and
- reproducible Python package, PostgreSQL fixture, container, and CI builds.

There is no end-user CLI, scheduler integration, or multi-engine execution workflow yet. Static
planning does not connect to a database or prove readiness, capability, schema presence, or data
equality. Import the Python APIs directly for development and protocol experiments.

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

Metadata persistence records immutable run requests, leased attempts, protected read contexts, and
per-dataset readiness observations. The first aligned input cut is bound once to the run; retries
may use a new snapshot but cannot silently change that cut. Attempt outcomes are currently limited
to incomplete, error, or abandoned. No completed comparison result can be published until the
comparison stages exist.

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
record without mutating the semantic version. The lifecycle migration adds run, attempt, protected
read-context, and dataset-observation records plus narrow immutable lease-renewal receipts; it does
not pre-create result, check, segment, or anomaly records.

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
uv run pytest --ignore=tests/test_postgres_integration.py --ignore=tests/test_postgres_metadata_integration.py --ignore=tests/test_postgres_protected_integration.py --ignore=tests/test_postgres_lifecycle_schema_integration.py --ignore=tests/test_postgres_lifecycle_integration.py
```

Stop and remove only this disposable fixture and its data volume:

```console
docker compose --env-file tests/fixtures/postgres/.env --file tests/fixtures/postgres/compose.yaml down --volumes
```

The integration suite exercises real catalog inspection, canonical row/hash equivalence, bounded
server-side cursors, duplicate bags, empty tables, precision rejection, relation replacement, row
level security, read-only enforcement, concurrent-writer snapshot stability, protected
dataset/manifest locking, metadata migration serialization and rollback, role separation, immutable
registration/readback, and lifecycle fencing and identity constraints.

## Build artifacts

Build the wheel/source distribution and the non-root container smoke image:

```console
uv sync --frozen --only-group build
uv lock --check
uv build --no-build-isolation --no-create-gitignore --clear
docker build --platform linux/amd64 --tag forensic-data:dev .
docker run --rm forensic-data:dev
```

The current container verifies the installed package and prints its version. It is not yet a
long-running service or CLI.
