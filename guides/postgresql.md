# PostgreSQL profiles and operation

[README](../README.md) · [Docker quickstart](docker-quickstart.md) · [CLI and contracts](cli-and-contracts.md) · [PostgreSQL](postgresql.md) · [SQL Server](sql-server.md) · [Development](development.md)

This guide records the verified modern and legacy PostgreSQL profiles, protected relation semantics, and metadata-store administration boundary.

## Verified PostgreSQL scope

The modern PostgreSQL path is verified against PostgreSQL 17.11 on Linux/amd64 with Psycopg 3.3.6
and the explicit `psycopg` / `postgresql_17` driver-profile pair. The profile name identifies a SQL
and driver strategy, not an allowed server version. Other versions, including PostgreSQL 18, may
use it without a version-number rejection. Source and target reads require UTF-8 server/client
encodings, integer datetimes, UTC, and a read-only Repeatable Read transaction. Required SQL and
catalog capabilities must be present; incompatible operations fail explicitly. An untested version
is not certified by a successful connection alone.

An additional legacy path is source-verified against the exact PostgreSQL 9.6.24 official
Linux/amd64 image with Psycopg2 2.9.13 and the explicit `psycopg2` / `postgresql_9_6` pair. Its
strategy can be selected for either source or target; the target direction remains unverified.
The Docker box uses its separate modern PostgreSQL metadata store. The legacy endpoint must use
UTF-8, integer datetimes, UTC, and read-only Repeatable Read, and must already have pgcrypto in
schema `dfe_ext`; the reader needs `USAGE` on that schema and `EXECUTE` on
`dfe_ext.digest(bytea,text)`. Runtime validates these capabilities and the canonical SHA-256 result;
it never installs the extension or silently changes drivers. The observed server version is retained
as evidence, not checked against a version allowlist. Other PostgreSQL versions remain unverified
until their real integration gates have run.

PostgreSQL relations must be given as an exact `(schema, table)` pair and select one explicit scope. The
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
