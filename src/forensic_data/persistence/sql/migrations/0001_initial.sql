CREATE TABLE dfe_metadata.migrations (
  version integer PRIMARY KEY,
  name text NOT NULL,
  checksum_sha256 bytea NOT NULL,
  applied_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  applied_by text NOT NULL DEFAULT session_user,
  CONSTRAINT migrations_version_positive CHECK (version > 0),
  CONSTRAINT migrations_name_nonblank CHECK (pg_catalog.btrim(name) <> ''),
  CONSTRAINT migrations_name_unique UNIQUE (name),
  CONSTRAINT migrations_checksum_sha256_length CHECK (
    pg_catalog.octet_length(checksum_sha256) = 32
  )
);

CREATE TABLE dfe_metadata.code_artifacts (
  code_artifact_id uuid PRIMARY KEY,
  artifact_kind text NOT NULL,
  dialect text NOT NULL,
  content_sha256 bytea NOT NULL,
  source_byte_length bigint NOT NULL,
  parameters jsonb NOT NULL,
  retention_state text NOT NULL,
  omission_reason text NULL,
  content_bytes bytea NULL,
  descriptor jsonb NOT NULL,
  provenance jsonb NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT code_artifacts_kind_supported CHECK (artifact_kind = 'sql'),
  CONSTRAINT code_artifacts_dialect_supported CHECK (dialect = 'postgresql'),
  CONSTRAINT code_artifacts_content_sha256_length CHECK (
    pg_catalog.octet_length(content_sha256) = 32
  ),
  CONSTRAINT code_artifacts_source_byte_length_positive CHECK (source_byte_length > 0),
  CONSTRAINT code_artifacts_parameters_array CHECK (
    pg_catalog.jsonb_typeof(parameters) = 'array'
  ),
  CONSTRAINT code_artifacts_retention_state_supported CHECK (
    retention_state IN ('retained', 'not_retained')
  ),
  CONSTRAINT code_artifacts_content_retention_consistent CHECK (
    (
      retention_state = 'retained'
      AND content_bytes IS NOT NULL
      AND omission_reason IS NULL
    )
    OR (
      retention_state = 'not_retained'
      AND content_bytes IS NULL
      AND omission_reason IS NOT NULL
      AND pg_catalog.btrim(omission_reason) <> ''
    )
  ),
  CONSTRAINT code_artifacts_content_size_consistent CHECK (
    content_bytes IS NULL
    OR pg_catalog.octet_length(content_bytes) = source_byte_length
  ),
  CONSTRAINT code_artifacts_descriptor_object CHECK (
    pg_catalog.jsonb_typeof(descriptor) = 'object'
  ),
  CONSTRAINT code_artifacts_provenance_object CHECK (
    pg_catalog.jsonb_typeof(provenance) = 'object'
  )
);

CREATE INDEX code_artifacts_content_sha256_idx
  ON dfe_metadata.code_artifacts (content_sha256);

CREATE TABLE dfe_metadata.dataset_versions (
  dataset_version_id uuid PRIMARY KEY,
  dataset_id text NOT NULL,
  semantic_digest bytea NOT NULL,
  semantic_protocol text NOT NULL,
  canonical_protocol text NOT NULL,
  logical_schema_digest bytea NOT NULL,
  connection_id text NOT NULL,
  adapter text NOT NULL,
  driver text NOT NULL,
  profile text NOT NULL,
  locator_kind text NOT NULL,
  relation_scope text NULL,
  semantic_payload jsonb NOT NULL,
  resolved_definition jsonb NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT dataset_versions_dataset_id_nonblank CHECK (
    pg_catalog.btrim(dataset_id) <> ''
  ),
  CONSTRAINT dataset_versions_semantic_digest_length CHECK (
    pg_catalog.octet_length(semantic_digest) = 32
  ),
  CONSTRAINT dataset_versions_semantic_protocol_supported CHECK (
    semantic_protocol = 'dfe_semantic_v1'
  ),
  CONSTRAINT dataset_versions_canonical_protocol_supported CHECK (
    canonical_protocol = 'dfe_canon_v1'
  ),
  CONSTRAINT dataset_versions_logical_schema_digest_length CHECK (
    pg_catalog.octet_length(logical_schema_digest) = 32
  ),
  CONSTRAINT dataset_versions_connection_id_nonblank CHECK (
    pg_catalog.btrim(connection_id) <> ''
  ),
  CONSTRAINT dataset_versions_adapter_supported CHECK (adapter = 'postgresql'),
  CONSTRAINT dataset_versions_driver_nonblank CHECK (pg_catalog.btrim(driver) <> ''),
  CONSTRAINT dataset_versions_profile_nonblank CHECK (pg_catalog.btrim(profile) <> ''),
  CONSTRAINT dataset_versions_locator_supported CHECK (
    (
      locator_kind = 'relation'
      AND relation_scope IS NOT NULL
      AND relation_scope = 'physical_only'
    )
    OR (locator_kind = 'sql' AND relation_scope IS NULL)
  ),
  CONSTRAINT dataset_versions_semantic_payload_object CHECK (
    pg_catalog.jsonb_typeof(semantic_payload) = 'object'
  ),
  CONSTRAINT dataset_versions_resolved_definition_object CHECK (
    pg_catalog.jsonb_typeof(resolved_definition) = 'object'
  ),
  CONSTRAINT dataset_versions_identity_unique UNIQUE (dataset_id, semantic_digest)
);

CREATE TABLE dfe_metadata.contract_versions (
  contract_version_id uuid PRIMARY KEY,
  check_id text NOT NULL,
  revision bigint NOT NULL,
  config_version smallint NOT NULL,
  semantic_digest bytea NOT NULL,
  semantic_protocol text NOT NULL,
  canonical_protocol text NOT NULL,
  comparison_schema_digest bytea NOT NULL,
  reference_dataset_version_id uuid NOT NULL,
  target_dataset_version_id uuid NOT NULL,
  assurance_policy text NOT NULL,
  semantic_payload jsonb NOT NULL,
  resolved_definition jsonb NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT contract_versions_check_id_nonblank CHECK (pg_catalog.btrim(check_id) <> ''),
  CONSTRAINT contract_versions_revision_positive CHECK (revision > 0),
  CONSTRAINT contract_versions_config_version_supported CHECK (config_version = 1),
  CONSTRAINT contract_versions_semantic_digest_length CHECK (
    pg_catalog.octet_length(semantic_digest) = 32
  ),
  CONSTRAINT contract_versions_semantic_protocol_supported CHECK (
    semantic_protocol = 'dfe_semantic_v1'
  ),
  CONSTRAINT contract_versions_canonical_protocol_supported CHECK (
    canonical_protocol = 'dfe_canon_v1'
  ),
  CONSTRAINT contract_versions_comparison_schema_digest_length CHECK (
    pg_catalog.octet_length(comparison_schema_digest) = 32
  ),
  CONSTRAINT contract_versions_datasets_distinct CHECK (
    reference_dataset_version_id <> target_dataset_version_id
  ),
  CONSTRAINT contract_versions_assurance_policy_supported CHECK (
    assurance_policy IN ('fingerprint_allowed', 'exact_required')
  ),
  CONSTRAINT contract_versions_semantic_payload_object CHECK (
    pg_catalog.jsonb_typeof(semantic_payload) = 'object'
  ),
  CONSTRAINT contract_versions_resolved_definition_object CHECK (
    pg_catalog.jsonb_typeof(resolved_definition) = 'object'
  ),
  CONSTRAINT contract_versions_identity_unique UNIQUE (check_id, revision),
  CONSTRAINT contract_versions_reference_dataset_fk FOREIGN KEY (
    reference_dataset_version_id
  ) REFERENCES dfe_metadata.dataset_versions (dataset_version_id) ON DELETE RESTRICT,
  CONSTRAINT contract_versions_target_dataset_fk FOREIGN KEY (
    target_dataset_version_id
  ) REFERENCES dfe_metadata.dataset_versions (dataset_version_id) ON DELETE RESTRICT
);

CREATE INDEX contract_versions_semantic_digest_idx
  ON dfe_metadata.contract_versions (semantic_digest);

CREATE INDEX contract_versions_reference_dataset_idx
  ON dfe_metadata.contract_versions (reference_dataset_version_id);

CREATE INDEX contract_versions_target_dataset_idx
  ON dfe_metadata.contract_versions (target_dataset_version_id);

REVOKE ALL ON ALL TABLES IN SCHEMA dfe_metadata FROM PUBLIC;

GRANT USAGE ON SCHEMA dfe_metadata TO dfe_metadata_reader, dfe_metadata_writer;

GRANT SELECT ON TABLE
  dfe_metadata.migrations,
  dfe_metadata.code_artifacts,
  dfe_metadata.dataset_versions,
  dfe_metadata.contract_versions
TO dfe_metadata_reader, dfe_metadata_writer;

GRANT INSERT (
  code_artifact_id,
  artifact_kind,
  dialect,
  content_sha256,
  source_byte_length,
  parameters,
  retention_state,
  omission_reason,
  content_bytes,
  descriptor,
  provenance
) ON dfe_metadata.code_artifacts TO dfe_metadata_writer;

GRANT INSERT (
  dataset_version_id,
  dataset_id,
  semantic_digest,
  semantic_protocol,
  canonical_protocol,
  logical_schema_digest,
  connection_id,
  adapter,
  driver,
  profile,
  locator_kind,
  relation_scope,
  semantic_payload,
  resolved_definition
) ON dfe_metadata.dataset_versions TO dfe_metadata_writer;

GRANT INSERT (
  contract_version_id,
  check_id,
  revision,
  config_version,
  semantic_digest,
  semantic_protocol,
  canonical_protocol,
  comparison_schema_digest,
  reference_dataset_version_id,
  target_dataset_version_id,
  assurance_policy,
  semantic_payload,
  resolved_definition
) ON dfe_metadata.contract_versions TO dfe_metadata_writer;
