# Greenplum-family artifact boundary

[README](../README.md) · [Docker quickstart](docker-quickstart.md) · [CLI and contracts](cli-and-contracts.md) · [PostgreSQL](postgresql.md) · [SQL Server](sql-server.md) · [Greenplum family](greenplum.md) · [Development](development.md)

Greenplum-family runtime support is not implemented yet. This phase first establishes a legitimate,
reproducible pair of real distributed database artifacts so later connector and comparison claims
can be tested against the intended products rather than against PostgreSQL substitutes.

## Verified artifact pair

| Product | Exact artifact | Verified fixture behavior |
|---|---|---|
| Original Greenplum | `greenplum-db/gpdb-archive` commit `62378f1767f22217f7f0474260abfeeb5c2615b9`, committed 2016-12-30, source identity `4.3.99.00 build dev` | Source-built coordinator, two primaries, two mirrors, catalog topology, and distributed execution across both primary content IDs |
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
Verification also checks those isolation and resource properties. A later connector gate must add
deliberate authentication and least-privilege database access before publishing an endpoint.

The separately dispatched `Greenplum family artifact fixture` workflow builds, starts, verifies,
stops cleanly, recreates both containers over retained volumes, proves volume persistence, verifies
again, and removes both fixtures. The normal push and pull-request gates remain light. Artifact
startup alone does not add a Greenplum or Greengage adapter to the product; connector, catalog,
type, read-consistency, and cross-engine evidence are separate gates.
