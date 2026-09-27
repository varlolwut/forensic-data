ALTER TABLE dfe_metadata.dataset_versions
  DROP CONSTRAINT dataset_versions_clickhouse_profile_supported;

ALTER TABLE dfe_metadata.dataset_versions
  ADD CONSTRAINT dataset_versions_clickhouse_profile_supported CHECK (
    adapter <> 'clickhouse'
    OR (
      driver = 'clickhouse-connect'
      AND profile IN ('clickhouse_lts', 'clickhouse_21_8_lts')
    )
  );

ALTER TABLE dfe_metadata.attempt_read_contexts
  DROP CONSTRAINT attempt_read_contexts_clickhouse_closure_evidence_shape;

ALTER TABLE dfe_metadata.attempt_read_contexts
  ADD CONSTRAINT attempt_read_contexts_clickhouse_closure_evidence_shape CHECK (
    closure_evidence IS NULL
    OR COALESCE(
      pg_catalog.jsonb_typeof(closure_evidence) = 'object'
      AND closure_evidence ?& ARRAY['evidence_version', 'kind', 'payload']
      AND closure_evidence - ARRAY[
        'evidence_version',
        'kind',
        'payload'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(closure_evidence -> 'evidence_version') = 'number'
      AND closure_evidence ->> 'evidence_version' = '1'
      AND pg_catalog.jsonb_typeof(closure_evidence -> 'payload') = 'object'
      AND (
        (
          closure_evidence ->> 'kind' = 'clickhouse_merge_tree_final_confirmation'
          AND (closure_evidence -> 'payload') ?& ARRAY[
            'acquisition_evidence_sha256',
            'attempt_id',
            'binding_sha256',
            'confirmed_at',
            'end_operation_id',
            'ended_at',
            'final_logical_fingerprint',
            'final_mutation_witness',
            'final_readiness_evidence',
            'final_readiness_identity',
            'final_readiness_record',
            'final_runtime_witness',
            'final_version_identity',
            'immutable_confirmed_at',
            'manifest_completion_revision',
            'manifest_publication_revision',
            'physical_query_provenance',
            'raw_manifest_sha256',
            'read_context_id',
            'run_id'
          ]
          AND (closure_evidence -> 'payload') - ARRAY[
            'acquisition_evidence_sha256',
            'attempt_id',
            'binding_sha256',
            'confirmed_at',
            'end_operation_id',
            'ended_at',
            'final_logical_fingerprint',
            'final_mutation_witness',
            'final_readiness_evidence',
            'final_readiness_identity',
            'final_readiness_record',
            'final_runtime_witness',
            'final_version_identity',
            'immutable_confirmed_at',
            'manifest_completion_revision',
            'manifest_publication_revision',
            'physical_query_provenance',
            'raw_manifest_sha256',
            'read_context_id',
            'run_id'
          ] = '{}'::jsonb
          AND pg_catalog.jsonb_typeof(
            closure_evidence -> 'payload' -> 'final_mutation_witness'
          ) = 'object'
          AND pg_catalog.jsonb_typeof(
            closure_evidence -> 'payload' -> 'final_readiness_evidence'
          ) = 'object'
          AND pg_catalog.jsonb_typeof(
            closure_evidence -> 'payload' -> 'final_readiness_identity'
          ) = 'object'
          AND pg_catalog.jsonb_typeof(
            closure_evidence -> 'payload' -> 'final_readiness_record'
          ) = 'object'
          AND pg_catalog.jsonb_typeof(
            closure_evidence -> 'payload' -> 'final_runtime_witness'
          ) = 'object'
          AND pg_catalog.jsonb_typeof(
            closure_evidence -> 'payload' -> 'final_version_identity'
          ) = 'object'
        )
        OR (
          closure_evidence ->> 'kind'
            = 'clickhouse_legacy_asserted_source_final_confirmation'
          AND (closure_evidence -> 'payload') ?& ARRAY[
            'acquisition_evidence_sha256',
            'attempt_id',
            'binding_sha256',
            'confirmed_at',
            'end_operation_id',
            'ended_at',
            'final_logical_fingerprint',
            'final_readiness',
            'final_source',
            'manifest_completion_revision',
            'manifest_publication_revision',
            'physical_query_provenance',
            'raw_manifest_sha256',
            'read_context_id',
            'run_id'
          ]
          AND (closure_evidence -> 'payload') - ARRAY[
            'acquisition_evidence_sha256',
            'attempt_id',
            'binding_sha256',
            'confirmed_at',
            'end_operation_id',
            'ended_at',
            'final_logical_fingerprint',
            'final_readiness',
            'final_source',
            'manifest_completion_revision',
            'manifest_publication_revision',
            'physical_query_provenance',
            'raw_manifest_sha256',
            'read_context_id',
            'run_id'
          ] = '{}'::jsonb
          AND pg_catalog.jsonb_typeof(
            closure_evidence -> 'payload' -> 'final_readiness'
          ) = 'object'
          AND pg_catalog.jsonb_typeof(
            closure_evidence -> 'payload' -> 'final_source'
          ) = 'object'
          AND closure_evidence -> 'payload' ->> 'manifest_completion_revision'
            ~ '^[1-9][0-9]*$'
          AND closure_evidence -> 'payload' ->> 'manifest_publication_revision'
            ~ '^[1-9][0-9]*$'
        )
      )
      AND closure_evidence -> 'payload' ->> 'acquisition_evidence_sha256'
        ~ '^[0-9a-f]{64}$'
      AND closure_evidence -> 'payload' ->> 'binding_sha256' ~ '^[0-9a-f]{64}$'
      AND closure_evidence -> 'payload' ->> 'raw_manifest_sha256' ~ '^[0-9a-f]{64}$'
      AND pg_catalog.jsonb_typeof(
        closure_evidence -> 'payload' -> 'manifest_completion_revision'
      ) = 'number'
      AND closure_evidence -> 'payload' ->> 'manifest_completion_revision'
        ~ '^(0|[1-9][0-9]*)$'
      AND pg_catalog.jsonb_typeof(
        closure_evidence -> 'payload' -> 'manifest_publication_revision'
      ) = 'number'
      AND closure_evidence -> 'payload' ->> 'manifest_publication_revision'
        ~ '^(0|[1-9][0-9]*)$'
      AND pg_catalog.jsonb_typeof(
        closure_evidence -> 'payload' -> 'final_logical_fingerprint'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        closure_evidence -> 'payload' -> 'physical_query_provenance'
      ) = 'object'
      AND (closure_evidence -> 'payload' -> 'physical_query_provenance')
        ?& ARRAY[
          'attempt_id',
          'connection_attempts',
          'final_query_id',
          'physical_request_count'
        ]
      AND (closure_evidence -> 'payload' -> 'physical_query_provenance') - ARRAY[
        'attempt_id',
        'connection_attempts',
        'final_query_id',
        'physical_request_count'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(
        closure_evidence -> 'payload' -> 'physical_query_provenance'
          -> 'connection_attempts'
      ) = 'number'
      AND closure_evidence -> 'payload' -> 'physical_query_provenance'
        ->> 'connection_attempts' ~ '^[1-9][0-9]*$'
      AND pg_catalog.jsonb_typeof(
        closure_evidence -> 'payload' -> 'physical_query_provenance'
          -> 'physical_request_count'
      ) = 'number'
      AND closure_evidence -> 'payload' -> 'physical_query_provenance'
        ->> 'physical_request_count' ~ '^[1-9][0-9]*$'
      AND NOT (closure_evidence -> 'payload') @? '$.* ? (@.type() == "null")'
      AND NOT (
        closure_evidence -> 'payload' -> 'physical_query_provenance'
      ) @? '$.* ? (@.type() == "null")',
      false
    )
  );
