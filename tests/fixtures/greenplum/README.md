# Greenplum-family artifact fixture

This manual-only fixture runs the exact two artifacts recorded in
[`provenance.json`](provenance.json): the original Greenplum archive commit
`62378f1767f22217f7f0474260abfeeb5c2615b9` and the separate Greengage 7.5.0
product. The historical source identifies itself as `4.3.99.00 build dev`; it is not described as a
Greenplum 4.3 GA release.

The fixture proves product identity, a live coordinator, two live primary segments, and a query
executed on both segments. Original Greenplum also starts two mirrors. It does not claim that the
Forensic Data Engine runtime supports either product yet.

## Run locally

The fixture requires Linux/amd64 containers, Python 3.12, Docker Compose 2.17 or newer with
compatible BuildKit additional-context support, about 6 GB of free disk, and enough Docker capacity
for two containers limited to 4 GiB and four CPUs each. From the repository root:

```console
bash tests/fixtures/greenplum/prepare-artifacts.sh
docker compose --file tests/fixtures/greenplum/compose.yaml build
docker compose --file tests/fixtures/greenplum/compose.yaml up --detach --wait
bash tests/fixtures/greenplum/verify.sh
docker compose --file tests/fixtures/greenplum/compose.yaml down --volumes --remove-orphans
```

Preparation downloads the two pinned product artifacts and the exact Ubuntu package needed to
bootstrap TLS trust on the pinned minimal base image. Every download is checked by exact size and
SHA-256 digest. The raw historical archive remains in an ignored cache that is outside every Docker
build context. A deterministic sanitizer removes the unused upstream `ci/` and `concourse/` trees,
which include legacy CI credential material, and emits the exact derived source archive recorded in
`provenance.json`. The original Greenplum named context admits only that sanitized archive.
Greengage dependencies are resolved only from the direct, dated Ubuntu snapshot URL; any index
retrieval error fails the build.

No container port is published to the host in this artifact-only gate. SSH is internal to each
single-host distributed fixture. Host and `gpadmin` SSH keys are generated when a container starts;
no generated private key is stored in either image or build context. A later connector gate must
add deliberate authentication and least-privilege access before exposing a database endpoint.

The workflow named `Greenplum family artifact fixture` runs the same gate only when explicitly
dispatched. Ordinary pushes and pull requests do not build these historical artifacts.
