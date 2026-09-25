# Development and verification

[README](../README.md) · [Docker quickstart](docker-quickstart.md) · [CLI and contracts](cli-and-contracts.md) · [PostgreSQL](postgresql.md) · [SQL Server](sql-server.md) · [Development](development.md)

Run all commands from the repository root. Passing protocol-only tests does not establish database support; use the real fixtures for engine claims.

## Developer setup

- Python 3.12
- [uv](https://docs.astral.sh/uv/) 0.12.18
- Docker with Compose for PostgreSQL, SQL Server, and Greenplum-family integration tests

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

## Database fixtures and checks

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

Start the pinned PostgreSQL fixtures and the SQL Server 2022 fixture, configure SQL Server through
its separate setup identities, then run the main gate. The host running pytest must have Microsoft
ODBC Driver 18.7.1.1 installed; CI and the production image install the exact package automatically.

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
uv run --env-file tests/fixtures/postgres/.env --env-file tests/fixtures/postgres-legacy/.env --env-file tests/fixtures/mssql-2022/.env pytest -m "not mssql_legacy"
```

Run the separately provisioned [SQL Server 2016 critical gate](sql-server.md#sql-server-2016-development-fixture)
to verify the legacy profile; it is intentionally not part of the Docker-based main gate above.
On each push and pull request, CI runs lint, formatting, type checks, the existing tests marked
`not integration`, and wheel/source-distribution build and wheel smoke checks. These runs do not
start databases, download database images, or build a Docker image.

Explicitly dispatch the `CI` workflow for a selected ref when database integration or Docker
delivery verification is required. It runs the PostgreSQL 17 / PostgreSQL 9.6-to-17 / SQL Server
2022 fixtures, the integration suite, and Docker export/import, box and persistence smoke checks.
Run the relevant checks when handing off changes that affect their behavior and before release;
do not repeat passed integration checks for unrelated documentation or CI orchestration edits.
The Docker build reuses the GitHub Actions BuildKit layer cache. A new hosted runner still downloads
required fixture images and cached layers. Containers, database volumes, guest disks, and generated
credentials are never shared through that cache.

The hosted `SQL Server 2016 compatibility` workflow is also explicitly dispatched for a selected
ref. It installs a disposable Windows guest. A green ordinary CI run does not by itself establish
database compatibility or Docker delivery. Retain each separate integration result and its commit
SHA. Full version-matrix testing is separate from these targeted checks.

The hosted `Greenplum family artifact fixture` workflow is explicitly dispatched as well. It
builds and verifies the exact original Greenplum and Greengage artifacts, proves their clean
restart over retained volumes, starts PostgreSQL 17.11, and runs the critical original-Greenplum
heap-source comparisons to PostgreSQL and Greengage. See the
[Greenplum-family guide](greenplum.md) for the exact provenance and endpoint limits; ordinary CI
does not make this compatibility claim.

PostgreSQL applies these credentials only when its data volume is initialized. If the fixture was
previously started with different values, run the cleanup command below before starting it again.

The protocol/result tests can run without Docker, but this does not verify database support:

```console
uv run pytest --ignore=tests/test_mssql_integration.py --ignore=tests/test_mssql_canonical_integration.py --ignore=tests/test_mssql_postgres_comparison_integration.py --ignore=tests/test_mssql_2016_postgres_comparison_integration.py --ignore=tests/test_postgres_integration.py --ignore=tests/test_postgres_frozen_union_integration.py --ignore=tests/test_postgres_metadata_integration.py --ignore=tests/test_postgres_protected_integration.py --ignore=tests/test_postgres_lifecycle_schema_integration.py --ignore=tests/test_postgres_lifecycle_integration.py --ignore=tests/test_postgres_comparison_integration.py --ignore=tests/test_postgres_legacy_integration.py
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
