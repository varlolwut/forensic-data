ALTER TABLE dfe_metadata.check_results
  ADD COLUMN evidence_manifest_digest bytea NULL,
  ADD CONSTRAINT check_results_evidence_manifest_digest_length CHECK (
    evidence_manifest_digest IS NULL
    OR pg_catalog.octet_length(evidence_manifest_digest) = 32
  ),
  ADD CONSTRAINT check_results_evidence_parent_closure_unique UNIQUE (
    run_id,
    attempt_id,
    check_id,
    result_operation_id
  );

CREATE TABLE dfe_metadata.partial_check_results (
  run_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  check_id text NOT NULL,
  end_operation_id uuid NOT NULL,
  contract_digest bytea NOT NULL,
  scope_digest bytea NOT NULL,
  input_cut_digest bytea NOT NULL,
  reference_observation_id uuid NOT NULL,
  reference_direction text NOT NULL,
  target_observation_id uuid NOT NULL,
  target_direction text NOT NULL,
  execution_status text NOT NULL,
  verdict text NOT NULL,
  guarantee text NOT NULL,
  result_digest bytea NOT NULL,
  result_payload jsonb NOT NULL,
  frontier_digest bytea NOT NULL,
  frontier_payload jsonb NOT NULL,
  evidence_manifest_digest bytea NOT NULL,
  ended_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT partial_check_results_pk PRIMARY KEY (attempt_id, check_id),
  CONSTRAINT partial_check_results_closure_unique UNIQUE (
    run_id,
    attempt_id,
    check_id
  ),
  CONSTRAINT partial_check_results_operation_unique UNIQUE (end_operation_id),
  CONSTRAINT partial_check_results_evidence_parent_closure_unique UNIQUE (
    run_id,
    attempt_id,
    check_id,
    end_operation_id
  ),
  CONSTRAINT partial_check_results_attempt_fk FOREIGN KEY (run_id, attempt_id)
    REFERENCES dfe_metadata.run_attempts (run_id, attempt_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT partial_check_results_terminal_operation_fk FOREIGN KEY (
    run_id,
    attempt_id,
    end_operation_id
  ) REFERENCES dfe_metadata.run_attempts (
    run_id,
    attempt_id,
    end_operation_id
  ) ON UPDATE RESTRICT ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT partial_check_results_reference_observation_fk FOREIGN KEY (
    run_id,
    attempt_id,
    reference_observation_id,
    reference_direction
  ) REFERENCES dfe_metadata.dataset_observations (
    run_id,
    attempt_id,
    observation_id,
    direction
  ) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT partial_check_results_target_observation_fk FOREIGN KEY (
    run_id,
    attempt_id,
    target_observation_id,
    target_direction
  ) REFERENCES dfe_metadata.dataset_observations (
    run_id,
    attempt_id,
    observation_id,
    direction
  ) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT partial_check_results_check_id_nonblank CHECK (
    pg_catalog.btrim(check_id) <> ''
  ),
  CONSTRAINT partial_check_results_contract_digest_length CHECK (
    pg_catalog.octet_length(contract_digest) = 32
  ),
  CONSTRAINT partial_check_results_scope_digest_length CHECK (
    pg_catalog.octet_length(scope_digest) = 32
  ),
  CONSTRAINT partial_check_results_input_cut_digest_length CHECK (
    pg_catalog.octet_length(input_cut_digest) = 32
  ),
  CONSTRAINT partial_check_results_observation_directions CHECK (
    reference_direction = 'reference'
    AND target_direction = 'target'
    AND reference_observation_id <> target_observation_id
  ),
  CONSTRAINT partial_check_results_execution_status_supported CHECK (
    execution_status IN ('incomplete', 'error')
  ),
  CONSTRAINT partial_check_results_verdict_supported CHECK (
    verdict IN ('inconclusive', 'mismatch')
  ),
  CONSTRAINT partial_check_results_guarantee_supported CHECK (
    guarantee = 'not_established'
  ),
  CONSTRAINT partial_check_results_result_digest_length CHECK (
    pg_catalog.octet_length(result_digest) = 32
  ),
  CONSTRAINT partial_check_results_frontier_digest_length CHECK (
    pg_catalog.octet_length(frontier_digest) = 32
  ),
  CONSTRAINT partial_check_results_evidence_manifest_digest_length CHECK (
    pg_catalog.octet_length(evidence_manifest_digest) = 32
  ),
  CONSTRAINT partial_check_results_frontier_payload_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(frontier_payload) = 'object'
      AND frontier_payload ?& ARRAY['topology', 'unresolved']
      AND frontier_payload - ARRAY['topology', 'unresolved'] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(frontier_payload -> 'topology') = 'array'
      AND pg_catalog.jsonb_typeof(frontier_payload -> 'unresolved') = 'array',
      false
    )
  ),
  CONSTRAINT partial_check_results_result_payload_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(result_payload) = 'object'
      AND result_payload ?& ARRAY[
        'attempt_id',
        'check_id',
        'comparison_coverage',
        'consistency',
        'contract_digest',
        'evidence_coverage',
        'execution_status',
        'guarantee',
        'metrics',
        'persistence',
        'reasons',
        'run_id',
        'schema_version',
        'scope_digest',
        'totals',
        'verdict'
      ]
      AND result_payload - ARRAY[
        'attempt_id',
        'check_id',
        'comparison_coverage',
        'consistency',
        'contract_digest',
        'evidence_coverage',
        'execution_status',
        'guarantee',
        'metrics',
        'persistence',
        'reasons',
        'run_id',
        'schema_version',
        'scope_digest',
        'totals',
        'verdict'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(result_payload -> 'schema_version') = 'number'
      AND result_payload ->> 'schema_version' = '1'
      AND result_payload ->> 'run_id' = run_id::text
      AND result_payload ->> 'attempt_id' = attempt_id::text
      AND result_payload ->> 'check_id' = check_id
      AND result_payload ->> 'contract_digest'
        = pg_catalog.encode(contract_digest, 'hex')
      AND result_payload ->> 'scope_digest' = pg_catalog.encode(scope_digest, 'hex')
      AND result_payload ->> 'execution_status' = execution_status
      AND result_payload ->> 'verdict' = verdict
      AND result_payload ->> 'guarantee' = guarantee
      AND pg_catalog.jsonb_typeof(result_payload -> 'consistency') = 'object'
      AND pg_catalog.jsonb_typeof(result_payload -> 'comparison_coverage') = 'object'
      AND pg_catalog.jsonb_typeof(result_payload -> 'totals') = 'object'
      AND pg_catalog.jsonb_typeof(result_payload -> 'evidence_coverage') = 'object'
      AND pg_catalog.jsonb_typeof(result_payload -> 'metrics') = 'object'
      AND pg_catalog.jsonb_typeof(result_payload -> 'reasons') = 'array'
      AND pg_catalog.jsonb_typeof(result_payload -> 'persistence') = 'object'
      AND result_payload -> 'persistence' ->> 'state' = 'confirmed'
      AND result_payload -> 'persistence' ->> 'operation_id'
        = end_operation_id::text
      AND pg_catalog.jsonb_typeof(
        result_payload -> 'persistence' -> 'reason'
      ) = 'null',
      false
    )
  )
);

CREATE INDEX partial_check_results_history_idx
  ON dfe_metadata.partial_check_results (
    check_id,
    scope_digest,
    created_at DESC
  );

CREATE TABLE dfe_metadata.anomalies (
  run_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  check_id text NOT NULL,
  end_operation_id uuid NOT NULL,
  anomaly_sequence bigint NOT NULL,
  segment_sequence bigint NOT NULL,
  anomaly_kind text NOT NULL,
  key_digest bytea NULL,
  reference_observation_id uuid NOT NULL,
  reference_direction text NOT NULL,
  target_observation_id uuid NOT NULL,
  target_direction text NOT NULL,
  evidence_payload jsonb NOT NULL,
  payload_digest bytea NOT NULL,
  payload_byte_length bigint NOT NULL,
  record_digest bytea NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT anomalies_pk PRIMARY KEY (
    attempt_id,
    check_id,
    anomaly_sequence
  ),
  CONSTRAINT anomalies_terminal_receipt_fk FOREIGN KEY (
    run_id,
    attempt_id,
    end_operation_id
  ) REFERENCES dfe_metadata.run_attempts (
    run_id,
    attempt_id,
    end_operation_id
  ) ON UPDATE RESTRICT ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT anomalies_reference_observation_fk FOREIGN KEY (
    run_id,
    attempt_id,
    reference_observation_id,
    reference_direction
  ) REFERENCES dfe_metadata.dataset_observations (
    run_id,
    attempt_id,
    observation_id,
    direction
  ) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT anomalies_target_observation_fk FOREIGN KEY (
    run_id,
    attempt_id,
    target_observation_id,
    target_direction
  ) REFERENCES dfe_metadata.dataset_observations (
    run_id,
    attempt_id,
    observation_id,
    direction
  ) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT anomalies_check_id_nonblank CHECK (
    pg_catalog.btrim(check_id) <> ''
  ),
  CONSTRAINT anomalies_sequence_nonnegative CHECK (anomaly_sequence >= 0),
  CONSTRAINT anomalies_segment_sequence_nonnegative CHECK (segment_sequence >= 0),
  CONSTRAINT anomalies_kind_supported CHECK (
    anomaly_kind IN ('missing', 'extra', 'modified')
  ),
  CONSTRAINT anomalies_observation_directions CHECK (
    reference_direction = 'reference'
    AND target_direction = 'target'
    AND reference_observation_id <> target_observation_id
  ),
  CONSTRAINT anomalies_payload_digest_length CHECK (
    pg_catalog.octet_length(payload_digest) = 32
  ),
  CONSTRAINT anomalies_payload_byte_length_positive CHECK (
    payload_byte_length > 0
  ),
  CONSTRAINT anomalies_record_digest_length CHECK (
    pg_catalog.octet_length(record_digest) = 32
  ),
  CONSTRAINT anomalies_evidence_payload_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(evidence_payload) = 'object'
      AND evidence_payload ?& ARRAY[
        'key_availability',
        'key_digest',
        'key_values',
        'kind',
        'omitted_field_names',
        'reference_values',
        'segment_sequence',
        'sequence',
        'target_values'
      ]
      AND evidence_payload - ARRAY[
        'key_availability',
        'key_digest',
        'key_values',
        'kind',
        'omitted_field_names',
        'reference_values',
        'segment_sequence',
        'sequence',
        'target_values'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(evidence_payload -> 'sequence') = 'number'
      AND evidence_payload ->> 'sequence' = anomaly_sequence::text
      AND pg_catalog.jsonb_typeof(evidence_payload -> 'segment_sequence') = 'number'
      AND evidence_payload ->> 'segment_sequence' = segment_sequence::text
      AND evidence_payload ->> 'kind' = anomaly_kind
      AND evidence_payload ->> 'key_availability'
        IN ('available', 'keyset_unavailable')
      AND (
        (
          evidence_payload ->> 'key_availability' = 'available'
          AND key_digest IS NOT NULL
          AND pg_catalog.octet_length(key_digest) = 32
          AND evidence_payload ->> 'key_digest'
            = pg_catalog.encode(key_digest, 'hex')
        )
        OR (
          evidence_payload ->> 'key_availability' = 'keyset_unavailable'
          AND key_digest IS NULL
          AND pg_catalog.jsonb_typeof(evidence_payload -> 'key_digest') = 'null'
        )
      )
      AND pg_catalog.jsonb_typeof(evidence_payload -> 'key_values') = 'array'
      AND pg_catalog.jsonb_typeof(evidence_payload -> 'omitted_field_names') = 'array'
      AND pg_catalog.jsonb_typeof(evidence_payload -> 'reference_values') = 'array'
      AND pg_catalog.jsonb_typeof(evidence_payload -> 'target_values') = 'array',
      false
    )
  )
);

CREATE INDEX anomalies_attempt_sequence_idx
  ON dfe_metadata.anomalies (
    run_id,
    attempt_id,
    anomaly_sequence
  );

CREATE INDEX anomalies_attempt_kind_sequence_idx
  ON dfe_metadata.anomalies (
    run_id,
    attempt_id,
    anomaly_kind,
    anomaly_sequence
  );

CREATE VIEW dfe_metadata.numeric_differences
WITH (security_barrier = true)
AS
SELECT
  anomaly.run_id,
  anomaly.attempt_id,
  anomaly.check_id,
  anomaly.end_operation_id,
  anomaly.anomaly_sequence,
  anomaly.segment_sequence,
  anomaly.anomaly_kind,
  anomaly.reference_observation_id,
  anomaly.target_observation_id,
  COALESCE(
    field_pair.reference_value ->> 'field_name',
    field_pair.target_value ->> 'field_name'
  ) AS field_name,
  COALESCE(
    field_pair.reference_value ->> 'logical_type',
    field_pair.target_value ->> 'logical_type'
  ) AS logical_type,
  field_pair.reference_value ->> 'availability' AS reference_availability,
  field_pair.target_value ->> 'availability' AS target_availability,
  CASE
    WHEN field_pair.reference_value ->> 'availability' = 'stored'
      AND field_pair.reference_value ->> 'raw_available' = 'true'
      AND field_pair.reference_value ->> 'is_null' = 'false'
    THEN (field_pair.reference_value ->> 'canonical_text')::numeric
    ELSE NULL
  END AS reference_value,
  CASE
    WHEN field_pair.target_value ->> 'availability' = 'stored'
      AND field_pair.target_value ->> 'raw_available' = 'true'
      AND field_pair.target_value ->> 'is_null' = 'false'
    THEN (field_pair.target_value ->> 'canonical_text')::numeric
    ELSE NULL
  END AS target_value,
  CASE
    WHEN field_pair.reference_value ->> 'availability' = 'stored'
      AND field_pair.reference_value ->> 'raw_available' = 'true'
      AND field_pair.reference_value ->> 'is_null' = 'false'
      AND field_pair.target_value ->> 'availability' = 'stored'
      AND field_pair.target_value ->> 'raw_available' = 'true'
      AND field_pair.target_value ->> 'is_null' = 'false'
    THEN
      (field_pair.target_value ->> 'canonical_text')::numeric
      - (field_pair.reference_value ->> 'canonical_text')::numeric
    ELSE NULL
  END AS target_minus_reference
FROM dfe_metadata.anomalies AS anomaly
CROSS JOIN LATERAL (
  SELECT
    reference_field.value AS reference_value,
    target_field.value AS target_value
  FROM pg_catalog.jsonb_array_elements(
    anomaly.evidence_payload -> 'reference_values'
  ) AS reference_field(value)
  FULL OUTER JOIN pg_catalog.jsonb_array_elements(
    anomaly.evidence_payload -> 'target_values'
  ) AS target_field(value)
    ON reference_field.value ->> 'field_name'
      = target_field.value ->> 'field_name'
) AS field_pair
WHERE COALESCE(
  field_pair.reference_value ->> 'logical_type',
  field_pair.target_value ->> 'logical_type'
) IN ('int64', 'decimal')
AND (
  anomaly.anomaly_kind <> 'modified'
  OR field_pair.reference_value ->> 'availability'
    IS DISTINCT FROM field_pair.target_value ->> 'availability'
  OR field_pair.reference_value ->> 'is_null'
    IS DISTINCT FROM field_pair.target_value ->> 'is_null'
  OR field_pair.reference_value ->> 'canonical_text'
    IS DISTINCT FROM field_pair.target_value ->> 'canonical_text'
  OR field_pair.reference_value ->> 'canonical_hex'
    IS DISTINCT FROM field_pair.target_value ->> 'canonical_hex'
);

REVOKE ALL ON TABLE
  dfe_metadata.partial_check_results,
  dfe_metadata.anomalies,
  dfe_metadata.numeric_differences
FROM PUBLIC;

GRANT SELECT ON TABLE
  dfe_metadata.partial_check_results,
  dfe_metadata.anomalies,
  dfe_metadata.numeric_differences
TO dfe_metadata_reader, dfe_metadata_writer;

GRANT INSERT (evidence_manifest_digest)
ON dfe_metadata.check_results TO dfe_metadata_writer;

GRANT INSERT (
  run_id,
  attempt_id,
  check_id,
  end_operation_id,
  contract_digest,
  scope_digest,
  input_cut_digest,
  reference_observation_id,
  reference_direction,
  target_observation_id,
  target_direction,
  execution_status,
  verdict,
  guarantee,
  result_digest,
  result_payload,
  frontier_digest,
  frontier_payload,
  evidence_manifest_digest,
  ended_at
) ON dfe_metadata.partial_check_results TO dfe_metadata_writer;

GRANT INSERT (
  run_id,
  attempt_id,
  check_id,
  end_operation_id,
  anomaly_sequence,
  segment_sequence,
  anomaly_kind,
  key_digest,
  reference_observation_id,
  reference_direction,
  target_observation_id,
  target_direction,
  evidence_payload,
  payload_digest,
  payload_byte_length,
  record_digest
) ON dfe_metadata.anomalies TO dfe_metadata_writer;
