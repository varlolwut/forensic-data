# Original Greenplum source and Greengage target

[README](../README.md) · [Docker quickstart](docker-quickstart.md) · [CLI and contracts](cli-and-contracts.md) · [PostgreSQL](postgresql.md) · [SQL Server](sql-server.md) · [Greenplum family](greenplum.md) · [Development](development.md)

Forensic Data Engine provides a verified Greengage 7.5 target endpoint for durable integer-key
comparisons from PostgreSQL 17.11, SQL Server 2022, and the exact original Greenplum artifact
identified as `4.3.99.00 build dev`. That original Greenplum artifact is also a verified source to
PostgreSQL 17.11. Contracts select each adapter, driver, and profile explicitly. Version entries
here record verification evidence rather than a runtime allowlist; admission depends on the
required SQL, catalog, encoding, type, topology, storage, and snapshot capabilities.

The verified endpoint evidence covers physical heap relations, a relation-manifest readiness cut,
and exact `int64`, decimal, date, local-timestamp, and instant-timestamp values. It does not claim
Greengage as a source endpoint or original Greenplum as a target endpoint. Append-optimized row
and column endpoint behavior has not been verified.

## Using the Greengage target

The complete [PostgreSQL/SQL Server to Greengage contract](../tests/fixtures/greenplum/greengage/comparison-contract.yaml)
shows both verified source paths, their readiness manifests, bounded execution policy, and retained
evidence fields. Its target connection is declared as:

```yaml
connections:
  target_greengage:
    adapter: greengage
    driver: psycopg
    profile: greengage
    roles: [target]
    secret_ref: env:DFE_GREENGAGE_TARGET_DSN
```

Apply the packaged metadata migrations through `forensics metadata migrate`; migration
`0007_greengage_dataset_adapter.sql` records the Greengage dataset adapter and durable binding.
Run the selected check through `forensics check` or the typed Python API, then inspect the durable
result with `forensics history` and page retained row differences with `forensics diff`. See
[CLI and contracts](cli-and-contracts.md) for invocation, output, and pagination details.

## Using original Greenplum as a source

The complete [original Greenplum source contract](../tests/fixtures/greenplum/original-greenplum/comparison-contract.yaml)
contains the verified original-Greenplum-to-PostgreSQL and original-Greenplum-to-Greengage checks.
It selects `adapter: greenplum`, `driver: psycopg2`, and `profile: original_greenplum` explicitly.
The fixture connection declares both source and target roles to prove that source admission accepts
additional declared roles, but both executed checks use that connection only as their reference
source. Original Greenplum target execution is not implemented or verified.

Before opening the protected snapshot, the source adapter completes read-only catalog and type
discovery. It then starts a native `SERIALIZABLE READ ONLY` transaction and acquires
`ACCESS SHARE` locks for the complete deterministic dataset-and-manifest relation set before its
first protected `SELECT`. The adapter records the actual relation bindings and OIDs, seals that
closure, and uses the same snapshot for relation-manifest readiness, fingerprints, and exact rows.
There is no weaker isolation fallback.

The verified heap contract covers an `int64` key, `decimal(38,7)`, date, microsecond local
timestamp, and microsecond instant timestamp. Migration `0008_greenplum_dataset_adapter.sql`
admits the explicit Greenplum profile and physical-relation scope in the durable metadata schema;
runtime lifecycle persistence records the concrete binding and OIDs. Both verified target pairs
execute through the CLI, replay the same request idempotently through the typed API, retain the
exact mismatch evidence in PostgreSQL metadata, and can replay history and differences after the
live source and manifest change.

## Functions-based miniature load boundary

The current real PostgreSQL source and Greengage target fixtures each use a native
`SECURITY INVOKER` stored function to publish a miniature batch. A fixture writer invokes its
engine's function, which writes the batch rows and then its relation-manifest completion record
atomically in one transaction. `EXECUTE` is revoked from `PUBLIC` and the DFE reader and granted
only to the fixture writer.

DFE connects through separate read-only reader DSNs. It neither calls these load functions nor
issues load DML; it only compares a batch after both completion records are visible. Loading
therefore remains outside the DFE runtime, while the fixture verifies the writer/reader boundary
on the supported PostgreSQL-to-Greengage example.

The original Greenplum source fixture has a separate, narrowly privileged writer used only by the
test harness to seed and later mutate its heap relation and completion manifest. That fixture path
does not install or claim a load stored function, and the DFE runtime receives only the read-only
source connection.

## Verified artifact pair

| Product | Exact artifact | Verified fixture behavior |
|---|---|---|
| Original Greenplum | `greenplum-db/gpdb-archive` commit `62378f1767f22217f7f0474260abfeeb5c2615b9`, committed 2016-12-30, source identity `4.3.99.00 build dev` | Source-built coordinator, two primaries, two mirrors, catalog topology, distributed execution across both primary content IDs, and a verified heap source endpoint to PostgreSQL 17.11 and Greengage 7.5 |
| Greengage | Official Ubuntu 22.04 amd64 package `greengage7=7.5.0`, source commit `677398e45766110a32e318266f186cf0cbe720a5` | Coordinator, two primaries, catalog topology, and distributed execution across both primary content IDs |

The original Greenplum artifact is a development snapshot and is not a GA 4.3 release. Greengage
is a separate product and is not relabeled as original Greenplum. PostgreSQL compatibility, a wire
connection, or success on one product does not certify the other.

The complete URLs, byte sizes, SHA-256 digests, tag object, pinned base-image manifests, historical
package trust data, sanitized-source derivation, and product classifications are recorded in the fixture's
[`provenance.json`](../tests/fixtures/greenplum/provenance.json).

## Reproducing the evidence

Use the commands and resource prerequisites in the fixture
[`README`](../tests/fixtures/greenplum/README.md). Preparation admits only the exact source archive
and product package recorded above, plus the exact Ubuntu TLS-bootstrap package recorded in
provenance. The modern build then uses only a direct, dated Ubuntu snapshot and treats every index
retrieval error as fatal. The historical build uses exact CentOS 7 package versions from an
immutable archive mirror. Its one EPEL dependency is downloaded as an exact RPM, hash-checked, and
verified with the pinned EPEL 7 signing key. Before Docker sees the historical source, a
deterministic derivation removes unused upstream CI trees containing legacy credential material;
only the separately hashed sanitized archive enters the named context. Each image records its
resolved package manifest.

Both services have explicit 4 GiB memory, four-CPU, and 1 GiB shared-memory limits; publish no host
ports; and use `restart: "no"`. Runtime startup generates the self-SSH material required by the
distributed database tools, so generated private keys are not part of an image or build context.
Verification also checks those isolation and resource properties. Endpoint operation requires
separate authenticated roles: the DFE reader is read-only and least-privileged, while fixture
writers remain outside the reader path.

The separately dispatched `Greenplum family artifact fixture` workflow builds, starts, verifies,
stops cleanly, recreates both containers over retained volumes, proves volume persistence, verifies
again, starts the PostgreSQL 17.11 fixture, and runs the critical endpoint comparisons before
removing all three fixtures. The normal push and pull-request gates remain light. Artifact startup
alone does not establish endpoint support; connector, catalog, type, read-consistency, durable
evidence, and cross-engine execution are separate gates. The heap, append-optimized row, and
append-optimized column snapshot probes are artifact-level snapshot evidence only and do not imply
endpoint verification. End-to-end original Greenplum source and Greengage target verification
currently covers physical heap relations; AO and AOCO endpoint behavior has not been verified.
