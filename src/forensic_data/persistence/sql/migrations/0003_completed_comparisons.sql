ALTER TABLE dfe_metadata.run_attempts
  DROP CONSTRAINT run_attempts_status_supported,
  DROP CONSTRAINT run_attempts_terminal_state_consistent,
  DROP CONSTRAINT run_attempts_terminal_reason_supported;

ALTER TABLE dfe_metadata.run_attempts
  ADD CONSTRAINT run_attempts_status_supported CHECK (
    status IN ('running', 'completed', 'incomplete', 'error', 'abandoned')
  ),
  ADD CONSTRAINT run_attempts_terminal_state_consistent CHECK (
    (
      status = 'running'
      AND end_operation_id IS NULL
      AND terminal_reason_code IS NULL
      AND terminal_reason IS NULL
      AND ended_at IS NULL
    )
    OR (
      status = 'completed'
      AND end_operation_id IS NOT NULL
      AND terminal_reason_code IS NULL
      AND terminal_reason IS NULL
      AND ended_at IS NOT NULL
    )
    OR (
      status IN ('incomplete', 'error', 'abandoned')
      AND end_operation_id IS NOT NULL
      AND terminal_reason_code IS NOT NULL
      AND terminal_reason IS NOT NULL
      AND ended_at IS NOT NULL
    )
  ),
  ADD CONSTRAINT run_attempts_terminal_reason_supported CHECK (
    terminal_reason_code IS NULL
    OR (status = 'incomplete' AND terminal_reason_code IN (
      'not_ready',
      'cut_mismatch',
      'snapshot_lost',
      'budget_exhausted',
      'cancelled',
      'cancellation_unconfirmed',
      'oversized_record'
    ))
    OR (status = 'error' AND terminal_reason_code IN (
      'invalid_contract',
      'unsupported_capability',
      'lossy_transport',
      'query_error',
      'persistence_error',
      'commit_unknown',
      'protocol_violation'
    ))
    OR (status = 'abandoned' AND terminal_reason_code = 'snapshot_lost')
  ),
  ADD CONSTRAINT run_attempts_terminal_operation_closure_unique UNIQUE (
    run_id,
    attempt_id,
    end_operation_id
  );

ALTER TABLE dfe_metadata.dataset_observations
  ADD CONSTRAINT dataset_observations_segment_closure_unique UNIQUE (
    run_id,
    attempt_id,
    observation_id,
    direction
  );

CREATE TABLE dfe_metadata.segment_fingerprints (
  observation_id uuid NOT NULL,
  run_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  direction text NOT NULL,
  segment_sequence bigint NOT NULL,
  parent_segment_sequence bigint NULL,
  depth integer NOT NULL,
  boundary_kind text NOT NULL,
  lower_inclusive bigint NOT NULL,
  upper_exclusive bigint NULL,
  traversal_state text NOT NULL,
  canonical_protocol text NOT NULL,
  fingerprint_protocol text NOT NULL,
  row_count bigint NOT NULL,
  limb_0 numeric(38, 0) NOT NULL,
  limb_1 numeric(38, 0) NOT NULL,
  limb_2 numeric(38, 0) NOT NULL,
  limb_3 numeric(38, 0) NOT NULL,
  limb_4 numeric(38, 0) NOT NULL,
  limb_5 numeric(38, 0) NOT NULL,
  limb_6 numeric(38, 0) NOT NULL,
  limb_7 numeric(38, 0) NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT segment_fingerprints_pk PRIMARY KEY (
    observation_id,
    segment_sequence
  ),
  CONSTRAINT segment_fingerprints_observation_fk FOREIGN KEY (
    run_id,
    attempt_id,
    observation_id,
    direction
  ) REFERENCES dfe_metadata.dataset_observations (
    run_id,
    attempt_id,
    observation_id,
    direction
  ) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT segment_fingerprints_parent_fk FOREIGN KEY (
    observation_id,
    parent_segment_sequence
  ) REFERENCES dfe_metadata.segment_fingerprints (
    observation_id,
    segment_sequence
  ) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT segment_fingerprints_direction_supported CHECK (
    direction IN ('reference', 'target')
  ),
  CONSTRAINT segment_fingerprints_sequence_nonnegative CHECK (
    segment_sequence >= 0
  ),
  CONSTRAINT segment_fingerprints_parent_precedes_child CHECK (
    parent_segment_sequence IS NULL
    OR (
      parent_segment_sequence >= 0
      AND parent_segment_sequence < segment_sequence
    )
  ),
  CONSTRAINT segment_fingerprints_depth_consistent CHECK (
    (depth = 0 AND parent_segment_sequence IS NULL)
    OR (depth > 0 AND parent_segment_sequence IS NOT NULL)
  ),
  CONSTRAINT segment_fingerprints_boundary_kind_supported CHECK (
    boundary_kind = 'integer_range'
  ),
  CONSTRAINT segment_fingerprints_boundary_order CHECK (
    upper_exclusive IS NULL OR upper_exclusive > lower_inclusive
  ),
  CONSTRAINT segment_fingerprints_state_supported CHECK (
    traversal_state IN (
      'split',
      'fingerprint_match',
      'exact_match',
      'exact_mismatch'
    )
  ),
  CONSTRAINT segment_fingerprints_canonical_protocol_supported CHECK (
    canonical_protocol = 'dfe_canon_v1'
  ),
  CONSTRAINT segment_fingerprints_fingerprint_protocol_supported CHECK (
    fingerprint_protocol = 'sha256_sum32_v1'
  ),
  CONSTRAINT segment_fingerprints_count_nonnegative CHECK (
    row_count >= 0
  ),
  CONSTRAINT segment_fingerprints_limb_bounds CHECK (
    limb_0 BETWEEN 0 AND row_count::numeric * 4294967295::numeric
    AND limb_1 BETWEEN 0 AND row_count::numeric * 4294967295::numeric
    AND limb_2 BETWEEN 0 AND row_count::numeric * 4294967295::numeric
    AND limb_3 BETWEEN 0 AND row_count::numeric * 4294967295::numeric
    AND limb_4 BETWEEN 0 AND row_count::numeric * 4294967295::numeric
    AND limb_5 BETWEEN 0 AND row_count::numeric * 4294967295::numeric
    AND limb_6 BETWEEN 0 AND row_count::numeric * 4294967295::numeric
    AND limb_7 BETWEEN 0 AND row_count::numeric * 4294967295::numeric
  )
);

CREATE INDEX segment_fingerprints_attempt_sequence_idx
  ON dfe_metadata.segment_fingerprints (
    run_id,
    attempt_id,
    segment_sequence,
    direction
  );

CREATE TABLE dfe_metadata.check_results (
  run_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  check_id text NOT NULL,
  result_operation_id uuid NOT NULL,
  contract_digest bytea NOT NULL,
  scope_digest bytea NOT NULL,
  execution_status text NOT NULL,
  verdict text NOT NULL,
  guarantee text NOT NULL,
  result_digest bytea NOT NULL,
  result_payload jsonb NOT NULL,
  completed_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT check_results_pk PRIMARY KEY (attempt_id, check_id),
  CONSTRAINT check_results_closure_unique UNIQUE (
    run_id,
    attempt_id,
    check_id
  ),
  CONSTRAINT check_results_operation_unique UNIQUE (result_operation_id),
  CONSTRAINT check_results_attempt_fk FOREIGN KEY (run_id, attempt_id)
    REFERENCES dfe_metadata.run_attempts (run_id, attempt_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT check_results_terminal_operation_fk FOREIGN KEY (
    run_id,
    attempt_id,
    result_operation_id
  ) REFERENCES dfe_metadata.run_attempts (
    run_id,
    attempt_id,
    end_operation_id
  ) ON UPDATE RESTRICT ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT check_results_check_id_nonblank CHECK (
    pg_catalog.btrim(check_id) <> ''
  ),
  CONSTRAINT check_results_contract_digest_length CHECK (
    pg_catalog.octet_length(contract_digest) = 32
  ),
  CONSTRAINT check_results_scope_digest_length CHECK (
    pg_catalog.octet_length(scope_digest) = 32
  ),
  CONSTRAINT check_results_execution_completed CHECK (
    execution_status = 'completed'
  ),
  CONSTRAINT check_results_verdict_supported CHECK (
    verdict IN ('match', 'mismatch')
  ),
  CONSTRAINT check_results_guarantee_supported CHECK (
    guarantee IN ('exact', 'fingerprint', 'aggregate', 'structural')
  ),
  CONSTRAINT check_results_result_digest_length CHECK (
    pg_catalog.octet_length(result_digest) = 32
  ),
  CONSTRAINT check_results_result_payload_shape CHECK (
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
        = result_operation_id::text
      AND pg_catalog.jsonb_typeof(
        result_payload -> 'persistence' -> 'reason'
      ) = 'null',
      false
    )
  )
);

CREATE INDEX check_results_history_idx
  ON dfe_metadata.check_results (
    check_id,
    scope_digest,
    created_at DESC
  );

REVOKE ALL ON TABLE
  dfe_metadata.segment_fingerprints,
  dfe_metadata.check_results
FROM PUBLIC;

GRANT SELECT ON TABLE
  dfe_metadata.segment_fingerprints,
  dfe_metadata.check_results
TO dfe_metadata_reader, dfe_metadata_writer;

GRANT INSERT (
  observation_id,
  run_id,
  attempt_id,
  direction,
  segment_sequence,
  parent_segment_sequence,
  depth,
  boundary_kind,
  lower_inclusive,
  upper_exclusive,
  traversal_state,
  canonical_protocol,
  fingerprint_protocol,
  row_count,
  limb_0,
  limb_1,
  limb_2,
  limb_3,
  limb_4,
  limb_5,
  limb_6,
  limb_7
) ON dfe_metadata.segment_fingerprints TO dfe_metadata_writer;

GRANT INSERT (
  run_id,
  attempt_id,
  check_id,
  result_operation_id,
  contract_digest,
  scope_digest,
  execution_status,
  verdict,
  guarantee,
  result_digest,
  result_payload,
  completed_at
) ON dfe_metadata.check_results TO dfe_metadata_writer;
