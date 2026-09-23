# Forensic Data Engine

Forensic Data Engine is a typed, read-only foundation for detecting data differences and producing
explicit evidence of agreement across database systems without silently rounding, normalizing, or
dropping values.

The current `0.1.0.dev0` package is a development library, not yet an end-to-end reconciliation
application. It provides:

- strict comparison-result models with distinct completed, incomplete, and error outcomes;
- the versioned `dfe_canon_v1` row/key envelope, schema digest, SHA-256 fingerprint, and segment
  identity primitives;
- a bounded PostgreSQL read connector and SQL lowering for the initial common type profile; and
- reproducible Python package, PostgreSQL fixture, container, and CI builds.

There is no end-user CLI, configuration file format, metadata store, scheduler integration, or
multi-engine execution workflow yet. Import the Python APIs directly for development and protocol
experiments.

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

## PostgreSQL fixture and checks

Copy the disposable local fixture environment. The checked-in values are development-only
credentials bound to `127.0.0.1` with `sslmode=disable`; replace the security profile if the
fixture is used anywhere else.

If you change `DFE_PG_PORT`, update the port in both test DSNs in the same environment file. If you
change the reader or writer password, update the matching password in its DSN too.

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
uv run pytest --ignore=tests/test_postgres_integration.py
```

Stop and remove only this disposable fixture and its data volume:

```console
docker compose --env-file tests/fixtures/postgres/.env --file tests/fixtures/postgres/compose.yaml down --volumes
```

The integration suite exercises real catalog inspection, canonical row/hash equivalence, bounded
server-side cursors, duplicate bags, empty tables, precision rejection, relation replacement, row
level security, read-only enforcement, and concurrent-writer snapshot stability.

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
