# Docker quickstart

[README](../README.md) · [Docker quickstart](docker-quickstart.md) · [CLI and contracts](cli-and-contracts.md) · [PostgreSQL](postgresql.md) · [SQL Server](sql-server.md) · [Development](development.md)

This is the complete first-run and persistence path for the one-shot DFE container and its dedicated metadata store.

## Run the Docker box

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
relations and manifests, and mount one complete connection secret in the adapter's accepted format
at each absolute `file:/run/secrets/...` path named by the contract. Add those secret mounts with a
local Compose override so each one-shot service receives only the endpoints it uses. Source logins
must be read-only; the metadata runtime login needs both writer and reader capability memberships.
The standalone CLI and orchestrators may continue to use `env:NAME` references. The generated demo
PostgreSQL DSNs use `sslmode=disable` only on the private local Compose network; use the
organization's required TLS mode and certificates for external endpoints.
