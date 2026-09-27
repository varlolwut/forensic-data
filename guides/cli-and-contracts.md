# CLI and contracts

[README](../README.md) · [Docker quickstart](docker-quickstart.md) · [CLI and contracts](cli-and-contracts.md) · [PostgreSQL](postgresql.md) · [SQL Server](sql-server.md) · [Development](development.md)

Use this guide for command behavior, typed application entry points, contract compilation, result retention, and automation output.

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
PostgreSQL DSN with `host`, `port`, `dbname`, `user`, `password`, `sslmode`, and `connect_timeout`,
one SQL Server DSN with the exact fields shown below, or one exact ClickHouse JSON object as
described in the next section. There is no raw-DSN command-line flag or provider fallback. A secret
file must be a readable regular file of at most 16 KiB containing exactly one non-empty UTF-8 line.
Errors never print its path or contents. `plan` neither resolves secret references nor opens a
connection. `history` and `diff` resolve only the metadata connection and never query a source or
target endpoint.

```text
host=sql.example.internal port=1433 database=warehouse user=dfe_reader password='replace with secret value' tls_verification=verify-server-certificate login_timeout=5 query_timeout=30 cancellation_acknowledgement_timeout=5
```

The SQL Server form is a whitespace-separated, shell-style `key=value` record; it is not an ODBC
semicolon connection string. Quote a password containing spaces or shell metacharacters as one
shell-style value. Production endpoints use `verify-server-certificate`;
`trust-fixture-certificate` must be used only for the disposable localhost fixture. Put the whole
record in the environment variable named by `env:NAME`, or in the one-line file named by
`file:/absolute/path`. The [mixed-engine fixture contract](../tests/fixtures/mssql-2022/comparison-contract.yaml)
shows the SQL Server reference plus PostgreSQL target/metadata wiring and uses the same `forensics
check` invocation shape shown above.

### ClickHouse target inputs

A ClickHouse target secret is strict JSON with exactly these fields:

```json
{"host":"clickhouse.example.internal","port":8443,"database":"mart","user":"dfe_reader","password":"replace with secret value","transport_security":"tls-verify","ca_cert":"/run/secrets/clickhouse-ca.pem","connect_timeout_seconds":5,"send_receive_timeout_seconds":30}
```

Use `transport_security: "tls-verify"` for a real endpoint. `ca_cert` is the CA bundle path visible
inside the DFE container and must be absolute when provided, or `null` when the container's system
trust store already contains the issuer. The only plaintext mode is `plaintext-local-fixture`,
which is rejected for non-localhost hosts and requires `ca_cert: null`.

Each ClickHouse check also requires the immutable-version manifest and its independently trusted
issuer on the command line. The manifest path must be absolute inside the runtime environment, and
the issuer is a nonblank identifier rather than a path:

```console
forensics check --config /run/config/contract.yaml --check daily_orders --scope-json '{"business_date":"2026-09-23"}' --reference-batch source-batch-42 --target-batch mart-v042 --target-manifest /run/manifests/mart-v042.json --target-manifest-issuer warehouse-release --request-id 7fa700c4-7c5d-42eb-8f55-50e372ed0e25 --output json
```

The [ClickHouse target example](../examples/clickhouse-target/contract.yaml) includes a matching
[connection-secret template](../examples/clickhouse-target/clickhouse-secret.json.example) and
[immutable manifest template](../examples/clickhouse-target/manifest.json.example). Replace the
manifest template's scope digest with the `scope_digest` emitted by `forensics plan` for the exact
scope before the version is published.

The target contract must use adapter `clickhouse`, driver `clickhouse-connect`, profile
`clickhouse_lts`, role `target`, a `physical_only` relation, relation-manifest readiness,
`stable_read: immutable_named_version`, and explicit `minimum_evidence: asserted`. The manifest is
bounded to 1 MiB. The durable target currently accepts a sealed plain `MergeTree` in an `Atomic`
database; `ReplacingMergeTree` is not exposed by this endpoint. Readiness marked verified does not
upgrade the stable-read claim: a ClickHouse immutable named version remains asserted, and
publication succeeds only after a final same-attempt identity and projection confirmation.

The ClickHouse reader needs `SELECT` on the target relations and on `system.build_options`,
`system.mutations`, `system.parts`, `system.processes`, and `system.projections`, plus `SHOW ROW
POLICIES ON *.*`. These read-only catalog grants let the adapter record exact server provenance and
verify that no mutation or row-policy state invalidates the immutable-version claim.

### ClickHouse 21.8 legacy source inputs

The legacy source path is verified against ClickHouse 21.8.15.7 with `clickhouse-connect`. That
version is an evidence point, not a numeric runtime allowlist. Select the path explicitly with
adapter `clickhouse`, driver `clickhouse-connect`, profile `clickhouse_21_8_lts`, and exactly
`roles: [source]`; the profile never silently falls back to the modern target strategy. The
verified pairing uses PostgreSQL 17.11 as the target.

The source must be a `physical_only` plain `MergeTree` in an `Atomic` database, with
relation-manifest readiness, `stable_read: immutable_named_version`, and explicit
`minimum_evidence: asserted`. It uses the same strict one-line ClickHouse JSON connection format
shown above through `secret_ref`. The
[legacy source example](../examples/clickhouse-legacy-source/contract.yaml) includes matching
[connection-secret](../examples/clickhouse-legacy-source/clickhouse-secret.json.example) and
[manifest](../examples/clickhouse-legacy-source/manifest.json.example) templates.

Before publication, replace the template values with the exact scope digest emitted by
`forensics plan`, an independently captured SHA-256 of `system.tables.create_table_query`, the
source table UUID, and a unique operator-configured `dfe_server_uuid` macro. The manifest issuer is
an independently trusted identifier. DFE checks that identifier, validates the bounded manifest,
and records its digest; it does not verify a signature and must not derive replacement trust values
from the live source during a check.

Pass the absolute runtime manifest path and trusted issuer with the reference flags:

```console
forensics check --config /run/config/clickhouse-legacy-source.yaml --check daily_orders --scope-json '{"business_date":"2026-09-23"}' --reference-batch orders-v042 --target-batch target-batch-42 --reference-manifest /run/manifests/orders-v042.json --reference-manifest-issuer archive-release --request-id 7fa700c4-7c5d-42eb-8f55-50e372ed0e25 --output json
```

Overall stable-read evidence remains `ASSERTED`. ClickHouse 21.8 HTTP reads do not share a
transaction snapshot; unique direct-server identity and the exclusions for writes, DDL, mutations,
and TTL are operator assertions. Equal pre/post identity, readiness, part, mutation, and logical
fingerprint witnesses detect observed changes but cannot exclude a transient write that reverted.
ClickHouse 21.8 exposes neither native server-UUID evidence nor table-readonly evidence. The path
rejects row policies, physical projections, TTL expressions, pending or failed mutations, and a
final witness that differs from acquisition.

The legacy reader needs `SELECT` on both bound relations and on `system.build_options`,
`system.columns`, `system.databases`, `system.mutations`, `system.parts`, `system.processes`,
`system.projection_parts`, `system.row_policies`, `system.settings`, and `system.tables`, plus `SHOW
ROW POLICIES ON *.*`. No write or `KILL QUERY` grant is part of the verified profile.

The example uses a 29,000 ms statement timeout beneath a 30-second ClickHouse
`max_execution_time` ceiling. Keep the server ceiling at least one second above the rounded-up
statement timeout so the adapter retains time to confirm or cancel the server query itself.

The CLI and Python API share the same ClickHouse limit calculation. For Python integrations,
derive the three target limits from the loaded contract's execution budgets:

```python
from forensic_data.clickhouse_limits import build_clickhouse_execution_limits

limits = build_clickhouse_execution_limits(config.execution)
```

For a ClickHouse target, pass `limits.transport`, `limits.readiness`, and `limits.canonical` as
`target_transport_limits`, `target_readiness_limits`, and `target_canonical_limits` when
constructing `PostgresClickHouseExecutionServices`, `OriginalGreenplumClickHouseExecutionServices`,
or `MssqlClickHouseExecutionServices`. For the legacy source path, construct the typed
`ClickHousePostgresExecutionServices` and pass the same single assembly as
`reference_transport_limits`, `reference_readiness_limits`, and `reference_canonical_limits`.
Manually supplied limits must fit the transport capacity and the comparison's encoded-row
requirement. Transport capacity is checked at service construction; for physical-only sources, row
capacity is checked before metadata registration or source reads. For a PostgreSQL physical union,
row capacity also depends on the discovered members and is checked after discovery. A rejected
configuration does not silently widen or clamp the supplied limits.

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
`execute_check` adds explicit engine-specific execution services, and `read_history`/`read_diff`
accept typed requests with metadata-only services. A `PlanReport` is informational and cannot be
supplied to `execute_check`; execution resolves and validates the compiled contract again.

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

The checked-in [SQL-backed example](../examples/postgres-row/contract.yaml) is complete and loadable,
but planning it remains static. Its readiness SQL describes operator-managed batch-manifest
evidence; capturing that SQL does not execute it or prove the sources ready. SQL dataset locators
and opaque SQL readiness artifacts are not supported by the current runtime acquisition path.

The [native relation-manifest example](../examples/postgres-relation-manifest/contract.yaml) shows the
runtime-supported readiness form. Static planning is still informational for this example and does
not itself acquire a snapshot or compare data.

`contract_digest` identifies the resolved comparison semantics but excludes runtime scope values,
secrets, paths, budgets, evidence settings, and metadata settings. `scope_digest` binds the typed
values for this invocation. A `PlanReport` is not a comparison result: its live probes and execution
stages remain explicitly `required_not_run` or `planned_not_run`, and its estimates remain
`unknown`. It is unsigned informational output, not an authenticated executable contract; digest
fields in a deserialized report are sender claims. Execution must load and compile the source
contract again rather than trusting a supplied report.
