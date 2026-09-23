CREATE TABLE dfe_metadata.runs (
  run_id uuid PRIMARY KEY,
  creation_operation_id uuid NOT NULL,
  request_id uuid NOT NULL,
  request_identity_digest bytea NOT NULL,
  request_payload jsonb NOT NULL,
  contract_version_id uuid NOT NULL,
  origin text NOT NULL,
  scope_digest bytea NOT NULL,
  bound_input_cut_digest bytea NULL,
  bound_input_cut_payload jsonb NULL,
  cut_binding_operation_id uuid NULL,
  cut_bound_at timestamp with time zone NULL,
  selected_terminal_attempt_id uuid NULL,
  terminal_operation_id uuid NULL,
  terminal_at timestamp with time zone NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT runs_creation_operation_unique UNIQUE (creation_operation_id),
  CONSTRAINT runs_request_id_unique UNIQUE (request_id),
  CONSTRAINT runs_request_identity_digest_length CHECK (
    pg_catalog.octet_length(request_identity_digest) = 32
  ),
  CONSTRAINT runs_request_payload_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(request_payload) = 'object'
      AND request_payload ?& ARRAY[
        'contract_version_id',
        'evidence_policy',
        'execution_policy',
        'expected_batches',
        'origin',
        'request_version',
        'scope'
      ]
      AND request_payload - ARRAY[
        'contract_version_id',
        'evidence_policy',
        'execution_policy',
        'expected_batches',
        'origin',
        'request_version',
        'scope'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(request_payload -> 'request_version') = 'number'
      AND request_payload ->> 'request_version' = '1'
      AND pg_catalog.jsonb_typeof(request_payload -> 'contract_version_id') = 'string'
      AND request_payload ->> 'contract_version_id' = contract_version_id::text
      AND pg_catalog.jsonb_typeof(request_payload -> 'scope') = 'object'
      AND (request_payload -> 'scope') ?& ARRAY[
        'canonical_protocol',
        'parameters',
        'semantic_protocol'
      ]
      AND (request_payload -> 'scope') - ARRAY[
        'canonical_protocol',
        'parameters',
        'semantic_protocol'
      ] = '{}'::jsonb
      AND request_payload -> 'scope' ->> 'canonical_protocol' = 'dfe_canon_v1'
      AND request_payload -> 'scope' ->> 'semantic_protocol' = 'dfe_semantic_v1'
      AND pg_catalog.jsonb_typeof(
        request_payload -> 'scope' -> 'parameters'
      ) = 'array'
      AND pg_catalog.jsonb_typeof(request_payload -> 'expected_batches') = 'array'
      AND pg_catalog.jsonb_array_length(request_payload -> 'expected_batches') = 2
      AND (request_payload -> 'expected_batches' -> 0) ?& ARRAY[
        'batch_id',
        'dataset_id',
        'direction'
      ]
      AND (request_payload -> 'expected_batches' -> 0) - ARRAY[
        'batch_id',
        'dataset_id',
        'direction'
      ] = '{}'::jsonb
      AND (request_payload -> 'expected_batches' -> 1) ?& ARRAY[
        'batch_id',
        'dataset_id',
        'direction'
      ]
      AND (request_payload -> 'expected_batches' -> 1) - ARRAY[
        'batch_id',
        'dataset_id',
        'direction'
      ] = '{}'::jsonb
      AND request_payload -> 'expected_batches' -> 0 ->> 'direction' = 'reference'
      AND request_payload -> 'expected_batches' -> 1 ->> 'direction' = 'target'
      AND pg_catalog.jsonb_typeof(
        request_payload -> 'expected_batches' -> 0 -> 'dataset_id'
      ) = 'string'
      AND pg_catalog.btrim(
        request_payload -> 'expected_batches' -> 0 ->> 'dataset_id'
      ) <> ''
      AND pg_catalog.jsonb_typeof(
        request_payload -> 'expected_batches' -> 0 -> 'batch_id'
      ) = 'string'
      AND pg_catalog.btrim(
        request_payload -> 'expected_batches' -> 0 ->> 'batch_id'
      ) <> ''
      AND pg_catalog.jsonb_typeof(
        request_payload -> 'expected_batches' -> 1 -> 'dataset_id'
      ) = 'string'
      AND pg_catalog.btrim(
        request_payload -> 'expected_batches' -> 1 ->> 'dataset_id'
      ) <> ''
      AND pg_catalog.jsonb_typeof(
        request_payload -> 'expected_batches' -> 1 -> 'batch_id'
      ) = 'string'
      AND pg_catalog.btrim(
        request_payload -> 'expected_batches' -> 1 ->> 'batch_id'
      ) <> ''
      AND pg_catalog.jsonb_typeof(request_payload -> 'execution_policy') = 'object'
      AND pg_catalog.jsonb_typeof(
        request_payload -> 'execution_policy' -> 'version'
      ) = 'number'
      AND request_payload -> 'execution_policy' ->> 'version' = '1'
      AND pg_catalog.jsonb_typeof(request_payload -> 'evidence_policy') = 'object'
      AND pg_catalog.jsonb_typeof(request_payload -> 'origin') = 'string'
      AND request_payload ->> 'origin' = origin,
      false
    )
  ),
  CONSTRAINT runs_contract_version_fk FOREIGN KEY (contract_version_id)
    REFERENCES dfe_metadata.contract_versions (contract_version_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT runs_origin_nonblank CHECK (pg_catalog.btrim(origin) <> ''),
  CONSTRAINT runs_scope_digest_length CHECK (
    pg_catalog.octet_length(scope_digest) = 32
  ),
  CONSTRAINT runs_input_cut_all_or_none CHECK (
    (
      bound_input_cut_digest IS NULL
      AND bound_input_cut_payload IS NULL
      AND cut_binding_operation_id IS NULL
      AND cut_bound_at IS NULL
    )
    OR (
      bound_input_cut_digest IS NOT NULL
      AND bound_input_cut_payload IS NOT NULL
      AND cut_binding_operation_id IS NOT NULL
      AND cut_bound_at IS NOT NULL
    )
  ),
  CONSTRAINT runs_input_cut_digest_length CHECK (
    bound_input_cut_digest IS NULL
    OR pg_catalog.octet_length(bound_input_cut_digest) = 32
  ),
  CONSTRAINT runs_input_cut_payload_shape CHECK (
    bound_input_cut_payload IS NULL
    OR COALESCE(
      pg_catalog.jsonb_typeof(bound_input_cut_payload) = 'object'
      AND bound_input_cut_payload ?& ARRAY[
        'canonical_protocol',
        'datasets',
        'input_cut_version',
        'late_arrivals',
        'scope_digest'
      ]
      AND bound_input_cut_payload - ARRAY[
        'canonical_protocol',
        'datasets',
        'input_cut_version',
        'late_arrivals',
        'scope_digest'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'input_cut_version'
      ) = 'number'
      AND bound_input_cut_payload ->> 'input_cut_version' = '1'
      AND bound_input_cut_payload ->> 'canonical_protocol' = 'dfe_canon_v1'
      AND bound_input_cut_payload ->> 'scope_digest'
        = pg_catalog.encode(scope_digest, 'hex')
      AND bound_input_cut_payload ->> 'late_arrivals' = 'next_batch'
      AND pg_catalog.jsonb_typeof(bound_input_cut_payload -> 'datasets') = 'array'
      AND pg_catalog.jsonb_array_length(bound_input_cut_payload -> 'datasets') = 2
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 0
      ) = 'object'
      AND (bound_input_cut_payload -> 'datasets' -> 0) ?& ARRAY[
        'alignment_values',
        'batch_id',
        'business_date',
        'completed_at',
        'dataset_id',
        'dataset_version',
        'direction',
        'source_cut'
      ]
      AND (bound_input_cut_payload -> 'datasets' -> 0) - ARRAY[
        'alignment_values',
        'batch_id',
        'business_date',
        'completed_at',
        'dataset_id',
        'dataset_version',
        'direction',
        'source_cut'
      ] = '{}'::jsonb
      AND bound_input_cut_payload -> 'datasets' -> 0 ->> 'direction' = 'reference'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 0 -> 'dataset_id'
      ) = 'string'
      AND pg_catalog.btrim(
        bound_input_cut_payload -> 'datasets' -> 0 ->> 'dataset_id'
      ) <> ''
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 0 -> 'batch_id'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 0 -> 'business_date'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 0 -> 'dataset_version'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 0 -> 'completed_at'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 0 -> 'source_cut'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 0 -> 'alignment_values'
      ) = 'array'
      AND pg_catalog.jsonb_array_length(
        bound_input_cut_payload -> 'datasets' -> 0 -> 'alignment_values'
      ) > 0
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 1
      ) = 'object'
      AND (bound_input_cut_payload -> 'datasets' -> 1) ?& ARRAY[
        'alignment_values',
        'batch_id',
        'business_date',
        'completed_at',
        'dataset_id',
        'dataset_version',
        'direction',
        'source_cut'
      ]
      AND (bound_input_cut_payload -> 'datasets' -> 1) - ARRAY[
        'alignment_values',
        'batch_id',
        'business_date',
        'completed_at',
        'dataset_id',
        'dataset_version',
        'direction',
        'source_cut'
      ] = '{}'::jsonb
      AND bound_input_cut_payload -> 'datasets' -> 1 ->> 'direction' = 'target'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 1 -> 'dataset_id'
      ) = 'string'
      AND pg_catalog.btrim(
        bound_input_cut_payload -> 'datasets' -> 1 ->> 'dataset_id'
      ) <> ''
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 1 -> 'batch_id'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 1 -> 'business_date'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 1 -> 'dataset_version'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 1 -> 'completed_at'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 1 -> 'source_cut'
      ) = 'object'
      AND pg_catalog.jsonb_typeof(
        bound_input_cut_payload -> 'datasets' -> 1 -> 'alignment_values'
      ) = 'array'
      AND pg_catalog.jsonb_array_length(
        bound_input_cut_payload -> 'datasets' -> 1 -> 'alignment_values'
      ) > 0,
      false
    )
  ),
  CONSTRAINT runs_cut_binding_operation_unique UNIQUE (cut_binding_operation_id),
  CONSTRAINT runs_terminal_all_or_none CHECK (
    (
      selected_terminal_attempt_id IS NULL
      AND terminal_operation_id IS NULL
      AND terminal_at IS NULL
    )
    OR (
      selected_terminal_attempt_id IS NOT NULL
      AND terminal_operation_id IS NOT NULL
      AND terminal_at IS NOT NULL
    )
  ),
  CONSTRAINT runs_terminal_operation_unique UNIQUE (terminal_operation_id),
  CONSTRAINT runs_cut_timestamp_order CHECK (
    cut_bound_at IS NULL OR cut_bound_at >= created_at
  ),
  CONSTRAINT runs_terminal_timestamp_order CHECK (
    terminal_at IS NULL OR terminal_at >= created_at
  )
);

CREATE INDEX runs_contract_scope_created_idx
  ON dfe_metadata.runs (contract_version_id, scope_digest, created_at DESC);

CREATE TABLE dfe_metadata.run_attempts (
  attempt_id uuid PRIMARY KEY,
  run_id uuid NOT NULL,
  ordinal bigint NOT NULL,
  start_operation_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'running',
  execution_budgets jsonb NOT NULL,
  owner_token uuid NOT NULL,
  lease_revision bigint NOT NULL DEFAULT 0,
  initial_lease_expires_at timestamp with time zone NOT NULL,
  lease_expires_at timestamp with time zone NOT NULL,
  lease_operation_id uuid NULL,
  input_cut_digest bytea NULL,
  cut_operation_id uuid NULL,
  cut_observed_at timestamp with time zone NULL,
  end_operation_id uuid NULL,
  terminal_reason_code text NULL,
  terminal_reason jsonb NULL,
  started_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ended_at timestamp with time zone NULL,
  CONSTRAINT run_attempts_run_attempt_unique UNIQUE (run_id, attempt_id),
  CONSTRAINT run_attempts_run_ordinal_unique UNIQUE (run_id, ordinal),
  CONSTRAINT run_attempts_start_operation_unique UNIQUE (start_operation_id),
  CONSTRAINT run_attempts_run_fk FOREIGN KEY (run_id)
    REFERENCES dfe_metadata.runs (run_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT run_attempts_ordinal_positive CHECK (ordinal > 0),
  CONSTRAINT run_attempts_status_supported CHECK (
    status IN ('running', 'incomplete', 'error', 'abandoned')
  ),
  CONSTRAINT run_attempts_execution_budgets_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(execution_budgets) = 'object'
      AND execution_budgets ?& ARRAY[
        'max_application_result_bytes',
        'max_attempts',
        'max_checks_concurrency',
        'max_coordinator_memory_bytes',
        'max_depth',
        'max_evidence_bytes',
        'max_evidence_rows',
        'max_fetched_records',
        'max_fingerprint_nodes',
        'max_full_scans_per_side',
        'max_queries',
        'max_source_concurrency',
        'run_timeout_milliseconds',
        'statement_timeout_milliseconds',
        'version'
      ]
      AND execution_budgets - ARRAY[
        'max_application_result_bytes',
        'max_attempts',
        'max_checks_concurrency',
        'max_coordinator_memory_bytes',
        'max_depth',
        'max_evidence_bytes',
        'max_evidence_rows',
        'max_fetched_records',
        'max_fingerprint_nodes',
        'max_full_scans_per_side',
        'max_queries',
        'max_source_concurrency',
        'run_timeout_milliseconds',
        'statement_timeout_milliseconds',
        'version'
      ] = '{}'::jsonb
      AND NOT execution_budgets @? '$.* ? (@.type() != "number")'
      AND pg_catalog.jsonb_typeof(execution_budgets -> 'version') = 'number'
      AND execution_budgets ->> 'version' = '1'
      AND execution_budgets ->> 'max_queries' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'max_fetched_records' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'max_application_result_bytes' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'max_evidence_rows' ~ '^(0|[1-9][0-9]*)$'
      AND execution_budgets ->> 'max_evidence_bytes' ~ '^(0|[1-9][0-9]*)$'
      AND execution_budgets ->> 'max_fingerprint_nodes' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'max_coordinator_memory_bytes' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'max_depth' ~ '^(0|[1-9][0-9]*)$'
      AND execution_budgets ->> 'max_full_scans_per_side' ~ '^(0|[1-9][0-9]*)$'
      AND execution_budgets ->> 'statement_timeout_milliseconds' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'run_timeout_milliseconds' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'max_attempts' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'max_checks_concurrency' ~ '^[1-9][0-9]*$'
      AND execution_budgets ->> 'max_source_concurrency' ~ '^[1-9][0-9]*$',
      false
    )
  ),
  CONSTRAINT run_attempts_lease_revision_nonnegative CHECK (lease_revision >= 0),
  CONSTRAINT run_attempts_lease_operation_consistent CHECK (
    (lease_revision = 0 AND lease_operation_id IS NULL)
    OR (lease_revision > 0 AND lease_operation_id IS NOT NULL)
  ),
  CONSTRAINT run_attempts_lease_operation_unique UNIQUE (lease_operation_id),
  CONSTRAINT run_attempts_lease_timestamp_order CHECK (
    initial_lease_expires_at > started_at
    AND lease_expires_at >= initial_lease_expires_at
  ),
  CONSTRAINT run_attempts_input_cut_all_or_none CHECK (
    (
      input_cut_digest IS NULL
      AND cut_operation_id IS NULL
      AND cut_observed_at IS NULL
    )
    OR (
      input_cut_digest IS NOT NULL
      AND cut_operation_id IS NOT NULL
      AND cut_observed_at IS NOT NULL
    )
  ),
  CONSTRAINT run_attempts_input_cut_digest_length CHECK (
    input_cut_digest IS NULL
    OR pg_catalog.octet_length(input_cut_digest) = 32
  ),
  CONSTRAINT run_attempts_cut_operation_unique UNIQUE (cut_operation_id),
  CONSTRAINT run_attempts_terminal_state_consistent CHECK (
    (
      status = 'running'
      AND end_operation_id IS NULL
      AND terminal_reason_code IS NULL
      AND terminal_reason IS NULL
      AND ended_at IS NULL
    )
    OR (
      status <> 'running'
      AND end_operation_id IS NOT NULL
      AND terminal_reason_code IS NOT NULL
      AND terminal_reason IS NOT NULL
      AND ended_at IS NOT NULL
    )
  ),
  CONSTRAINT run_attempts_terminal_reason_supported CHECK (
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
  CONSTRAINT run_attempts_terminal_reason_shape CHECK (
    terminal_reason IS NULL
    OR COALESCE(
      pg_catalog.jsonb_typeof(terminal_reason) = 'object'
      AND terminal_reason ?& ARRAY[
        'message',
        'native_error_code',
        'operation',
        'query_id',
        'reason_version',
        'redacted_response',
        'safe_parameters'
      ]
      AND terminal_reason - ARRAY[
        'message',
        'native_error_code',
        'operation',
        'query_id',
        'reason_version',
        'redacted_response',
        'safe_parameters'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(terminal_reason -> 'reason_version') = 'number'
      AND terminal_reason ->> 'reason_version' = '1'
      AND pg_catalog.jsonb_typeof(terminal_reason -> 'operation') = 'string'
      AND pg_catalog.btrim(terminal_reason ->> 'operation') <> ''
      AND pg_catalog.jsonb_typeof(terminal_reason -> 'message') = 'string'
      AND pg_catalog.btrim(terminal_reason ->> 'message') <> ''
      AND pg_catalog.jsonb_typeof(terminal_reason -> 'safe_parameters') = 'array'
      AND pg_catalog.jsonb_typeof(terminal_reason -> 'native_error_code')
        IN ('null', 'string')
      AND pg_catalog.jsonb_typeof(terminal_reason -> 'query_id') IN ('null', 'string')
      AND pg_catalog.jsonb_typeof(terminal_reason -> 'redacted_response')
        IN ('null', 'string'),
      false
    )
  ),
  CONSTRAINT run_attempts_end_operation_unique UNIQUE (end_operation_id),
  CONSTRAINT run_attempts_cut_timestamp_order CHECK (
    cut_observed_at IS NULL OR cut_observed_at >= started_at
  ),
  CONSTRAINT run_attempts_end_timestamp_order CHECK (
    ended_at IS NULL OR ended_at >= started_at
  )
);

CREATE UNIQUE INDEX run_attempts_one_running_per_run_idx
  ON dfe_metadata.run_attempts (run_id)
  WHERE status = 'running';

CREATE TABLE dfe_metadata.attempt_lease_renewals (
  lease_operation_id uuid PRIMARY KEY,
  run_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  owner_token uuid NOT NULL,
  expected_lease_revision bigint NOT NULL,
  requested_lease_expires_at timestamp with time zone NOT NULL,
  resulting_lease_revision bigint NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT attempt_lease_renewals_attempt_revision_unique UNIQUE (
    attempt_id,
    expected_lease_revision
  ),
  CONSTRAINT attempt_lease_renewals_attempt_fk FOREIGN KEY (run_id, attempt_id)
    REFERENCES dfe_metadata.run_attempts (run_id, attempt_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT attempt_lease_renewals_revision_nonnegative CHECK (
    expected_lease_revision >= 0
  ),
  CONSTRAINT attempt_lease_renewals_result_revision CHECK (
    resulting_lease_revision = expected_lease_revision + 1
  )
);

ALTER TABLE dfe_metadata.runs
  ADD CONSTRAINT runs_selected_terminal_attempt_fk FOREIGN KEY (
    run_id,
    selected_terminal_attempt_id
  ) REFERENCES dfe_metadata.run_attempts (run_id, attempt_id)
  ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE TABLE dfe_metadata.attempt_read_contexts (
  read_context_id uuid PRIMARY KEY,
  run_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  dataset_version_id uuid NOT NULL,
  direction text NOT NULL,
  acquisition_operation_id uuid NOT NULL,
  scope_digest bytea NOT NULL,
  engine text NOT NULL,
  driver_version text NOT NULL,
  server_version text NOT NULL,
  server_version_number bigint NOT NULL,
  strategy text NOT NULL,
  snapshot_locator text NULL,
  backend_process_id bigint NULL,
  allowed_concurrency integer NOT NULL,
  limitations jsonb NOT NULL,
  acquisition_evidence jsonb NOT NULL,
  state text NOT NULL DEFAULT 'active',
  end_operation_id uuid NULL,
  started_at timestamp with time zone NOT NULL,
  ended_at timestamp with time zone NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT attempt_read_contexts_attempt_dataset_unique UNIQUE (
    attempt_id,
    dataset_version_id
  ),
  CONSTRAINT attempt_read_contexts_closure_unique UNIQUE (
    run_id,
    attempt_id,
    read_context_id,
    dataset_version_id,
    direction
  ),
  CONSTRAINT attempt_read_contexts_acquisition_operation_unique UNIQUE (
    acquisition_operation_id
  ),
  CONSTRAINT attempt_read_contexts_attempt_fk FOREIGN KEY (run_id, attempt_id)
    REFERENCES dfe_metadata.run_attempts (run_id, attempt_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT attempt_read_contexts_dataset_fk FOREIGN KEY (dataset_version_id)
    REFERENCES dfe_metadata.dataset_versions (dataset_version_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT attempt_read_contexts_direction_supported CHECK (
    direction IN ('reference', 'target')
  ),
  CONSTRAINT attempt_read_contexts_scope_digest_length CHECK (
    pg_catalog.octet_length(scope_digest) = 32
  ),
  CONSTRAINT attempt_read_contexts_engine_nonblank CHECK (
    pg_catalog.btrim(engine) <> ''
  ),
  CONSTRAINT attempt_read_contexts_driver_version_nonblank CHECK (
    pg_catalog.btrim(driver_version) <> ''
  ),
  CONSTRAINT attempt_read_contexts_server_version_nonblank CHECK (
    pg_catalog.btrim(server_version) <> ''
  ),
  CONSTRAINT attempt_read_contexts_server_version_positive CHECK (
    server_version_number > 0
  ),
  CONSTRAINT attempt_read_contexts_strategy_nonblank CHECK (
    pg_catalog.btrim(strategy) <> ''
  ),
  CONSTRAINT attempt_read_contexts_snapshot_locator_nonblank CHECK (
    snapshot_locator IS NULL OR pg_catalog.btrim(snapshot_locator) <> ''
  ),
  CONSTRAINT attempt_read_contexts_backend_process_positive CHECK (
    backend_process_id IS NULL OR backend_process_id > 0
  ),
  CONSTRAINT attempt_read_contexts_concurrency_positive CHECK (
    allowed_concurrency > 0
  ),
  CONSTRAINT attempt_read_contexts_limitations_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(limitations) = 'array'
      AND pg_catalog.jsonb_array_length(limitations) > 0
      AND NOT limitations @? '$[*] ? (@.type() != "string")',
      false
    )
  ),
  CONSTRAINT attempt_read_contexts_acquisition_evidence_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(acquisition_evidence) = 'object'
      AND acquisition_evidence ?& ARRAY['evidence_version', 'kind', 'payload']
      AND acquisition_evidence - ARRAY[
        'evidence_version',
        'kind',
        'payload'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(acquisition_evidence -> 'evidence_version') = 'number'
      AND acquisition_evidence ->> 'evidence_version' = '1'
      AND pg_catalog.jsonb_typeof(acquisition_evidence -> 'kind') = 'string'
      AND pg_catalog.btrim(acquisition_evidence ->> 'kind') <> ''
      AND pg_catalog.jsonb_typeof(acquisition_evidence -> 'payload') = 'object',
      false
    )
  ),
  CONSTRAINT attempt_read_contexts_state_supported CHECK (
    state IN ('active', 'closed', 'lost')
  ),
  CONSTRAINT attempt_read_contexts_end_state_consistent CHECK (
    (
      state = 'active'
      AND end_operation_id IS NULL
      AND ended_at IS NULL
    )
    OR (
      state <> 'active'
      AND end_operation_id IS NOT NULL
      AND ended_at IS NOT NULL
    )
  ),
  CONSTRAINT attempt_read_contexts_end_operation_unique UNIQUE (end_operation_id),
  CONSTRAINT attempt_read_contexts_end_timestamp_order CHECK (
    ended_at IS NULL OR ended_at >= started_at
  )
);

CREATE INDEX attempt_read_contexts_dataset_idx
  ON dfe_metadata.attempt_read_contexts (dataset_version_id);

CREATE TABLE dfe_metadata.dataset_observations (
  observation_id uuid PRIMARY KEY,
  observation_operation_id uuid NOT NULL,
  run_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  read_context_id uuid NOT NULL,
  dataset_version_id uuid NOT NULL,
  direction text NOT NULL,
  scope_digest bytea NOT NULL,
  input_cut_digest bytea NOT NULL,
  readiness_evidence jsonb NOT NULL,
  physical_schema_digest bytea NOT NULL,
  physical_binding_digest bytea NOT NULL,
  physical_binding jsonb NOT NULL,
  projection_code_artifact_id uuid NULL,
  readiness_provider_kind text NOT NULL,
  readiness_code_artifact_id uuid NULL,
  observed_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT dataset_observations_operation_unique UNIQUE (observation_operation_id),
  CONSTRAINT dataset_observations_attempt_dataset_unique UNIQUE (
    attempt_id,
    dataset_version_id
  ),
  CONSTRAINT dataset_observations_context_fk FOREIGN KEY (
    run_id,
    attempt_id,
    read_context_id,
    dataset_version_id,
    direction
  ) REFERENCES dfe_metadata.attempt_read_contexts (
    run_id,
    attempt_id,
    read_context_id,
    dataset_version_id,
    direction
  ) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT dataset_observations_projection_capture_fk FOREIGN KEY (
    projection_code_artifact_id
  ) REFERENCES dfe_metadata.code_artifacts (code_artifact_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT dataset_observations_readiness_capture_fk FOREIGN KEY (
    readiness_code_artifact_id
  ) REFERENCES dfe_metadata.code_artifacts (code_artifact_id)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CONSTRAINT dataset_observations_direction_supported CHECK (
    direction IN ('reference', 'target')
  ),
  CONSTRAINT dataset_observations_readiness_provider_supported CHECK (
    readiness_provider_kind IN ('relation_manifest', 'sql')
  ),
  CONSTRAINT dataset_observations_readiness_capture_consistent CHECK (
    (
      readiness_provider_kind = 'relation_manifest'
      AND readiness_code_artifact_id IS NULL
    )
    OR (
      readiness_provider_kind = 'sql'
      AND readiness_code_artifact_id IS NOT NULL
    )
  ),
  CONSTRAINT dataset_observations_scope_digest_length CHECK (
    pg_catalog.octet_length(scope_digest) = 32
  ),
  CONSTRAINT dataset_observations_input_cut_digest_length CHECK (
    pg_catalog.octet_length(input_cut_digest) = 32
  ),
  CONSTRAINT dataset_observations_readiness_evidence_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(readiness_evidence) = 'object'
      AND readiness_evidence ?& ARRAY[
        'alignment_values',
        'batch_id',
        'business_date',
        'completed_at',
        'dataset_version',
        'evidence_version',
        'kind',
        'late_arrivals',
        'scope_digest',
        'source_cut',
        'state'
      ]
      AND readiness_evidence - ARRAY[
        'alignment_values',
        'batch_id',
        'business_date',
        'completed_at',
        'dataset_version',
        'evidence_version',
        'kind',
        'late_arrivals',
        'scope_digest',
        'source_cut',
        'state'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(readiness_evidence -> 'evidence_version') = 'number'
      AND readiness_evidence ->> 'evidence_version' = '1'
      AND readiness_evidence ->> 'kind' = readiness_provider_kind
      AND readiness_evidence ->> 'state' = 'complete'
      AND readiness_evidence ->> 'scope_digest'
        = pg_catalog.encode(scope_digest, 'hex')
      AND readiness_evidence ->> 'late_arrivals' = 'next_batch'
      AND pg_catalog.jsonb_typeof(readiness_evidence -> 'batch_id') = 'object'
      AND pg_catalog.jsonb_typeof(readiness_evidence -> 'business_date') = 'object'
      AND pg_catalog.jsonb_typeof(readiness_evidence -> 'dataset_version') = 'object'
      AND pg_catalog.jsonb_typeof(readiness_evidence -> 'completed_at') = 'object'
      AND pg_catalog.jsonb_typeof(readiness_evidence -> 'source_cut') = 'object'
      AND pg_catalog.jsonb_typeof(readiness_evidence -> 'alignment_values') = 'array'
      AND pg_catalog.jsonb_array_length(readiness_evidence -> 'alignment_values') > 0,
      false
    )
  ),
  CONSTRAINT dataset_observations_physical_schema_digest_length CHECK (
    pg_catalog.octet_length(physical_schema_digest) = 32
  ),
  CONSTRAINT dataset_observations_physical_binding_digest_length CHECK (
    pg_catalog.octet_length(physical_binding_digest) = 32
  ),
  CONSTRAINT dataset_observations_physical_binding_shape CHECK (
    COALESCE(
      pg_catalog.jsonb_typeof(physical_binding) = 'object'
      AND physical_binding ?& ARRAY['binding_version', 'engine', 'payload']
      AND physical_binding - ARRAY[
        'binding_version',
        'engine',
        'payload'
      ] = '{}'::jsonb
      AND pg_catalog.jsonb_typeof(physical_binding -> 'binding_version') = 'number'
      AND physical_binding ->> 'binding_version' = '1'
      AND pg_catalog.jsonb_typeof(physical_binding -> 'engine') = 'string'
      AND pg_catalog.btrim(physical_binding ->> 'engine') <> ''
      AND pg_catalog.jsonb_typeof(physical_binding -> 'payload') = 'object',
      false
    )
  ),
  CONSTRAINT dataset_observations_capture_roles_distinct CHECK (
    projection_code_artifact_id IS NULL
    OR projection_code_artifact_id <> readiness_code_artifact_id
  )
);

CREATE INDEX dataset_observations_context_idx
  ON dfe_metadata.dataset_observations (
    run_id,
    attempt_id,
    read_context_id,
    dataset_version_id,
    direction
  );

CREATE INDEX dataset_observations_projection_capture_idx
  ON dfe_metadata.dataset_observations (projection_code_artifact_id)
  WHERE projection_code_artifact_id IS NOT NULL;

CREATE INDEX dataset_observations_readiness_capture_idx
  ON dfe_metadata.dataset_observations (readiness_code_artifact_id);

REVOKE ALL ON TABLE
  dfe_metadata.runs,
  dfe_metadata.run_attempts,
  dfe_metadata.attempt_lease_renewals,
  dfe_metadata.attempt_read_contexts,
  dfe_metadata.dataset_observations
FROM PUBLIC;

GRANT SELECT ON TABLE
  dfe_metadata.runs,
  dfe_metadata.run_attempts,
  dfe_metadata.attempt_lease_renewals,
  dfe_metadata.attempt_read_contexts,
  dfe_metadata.dataset_observations
TO dfe_metadata_reader, dfe_metadata_writer;

GRANT INSERT (
  run_id,
  creation_operation_id,
  request_id,
  request_identity_digest,
  request_payload,
  contract_version_id,
  origin,
  scope_digest
) ON dfe_metadata.runs TO dfe_metadata_writer;

GRANT UPDATE (
  bound_input_cut_digest,
  bound_input_cut_payload,
  cut_binding_operation_id,
  cut_bound_at,
  selected_terminal_attempt_id,
  terminal_operation_id,
  terminal_at
) ON dfe_metadata.runs TO dfe_metadata_writer;

GRANT INSERT (
  attempt_id,
  run_id,
  ordinal,
  start_operation_id,
  execution_budgets,
  owner_token,
  initial_lease_expires_at,
  lease_expires_at
) ON dfe_metadata.run_attempts TO dfe_metadata_writer;

GRANT INSERT (
  lease_operation_id,
  run_id,
  attempt_id,
  owner_token,
  expected_lease_revision,
  requested_lease_expires_at,
  resulting_lease_revision
) ON dfe_metadata.attempt_lease_renewals TO dfe_metadata_writer;

GRANT UPDATE (
  status,
  lease_revision,
  lease_expires_at,
  lease_operation_id,
  input_cut_digest,
  cut_operation_id,
  cut_observed_at,
  end_operation_id,
  terminal_reason_code,
  terminal_reason,
  ended_at
) ON dfe_metadata.run_attempts TO dfe_metadata_writer;

GRANT INSERT (
  read_context_id,
  run_id,
  attempt_id,
  dataset_version_id,
  direction,
  acquisition_operation_id,
  scope_digest,
  engine,
  driver_version,
  server_version,
  server_version_number,
  strategy,
  snapshot_locator,
  backend_process_id,
  allowed_concurrency,
  limitations,
  acquisition_evidence,
  started_at
) ON dfe_metadata.attempt_read_contexts TO dfe_metadata_writer;

GRANT UPDATE (
  state,
  end_operation_id,
  ended_at
) ON dfe_metadata.attempt_read_contexts TO dfe_metadata_writer;

GRANT INSERT (
  observation_id,
  observation_operation_id,
  run_id,
  attempt_id,
  read_context_id,
  dataset_version_id,
  direction,
  scope_digest,
  input_cut_digest,
  readiness_evidence,
  physical_schema_digest,
  physical_binding_digest,
  physical_binding,
  projection_code_artifact_id,
  readiness_provider_kind,
  readiness_code_artifact_id,
  observed_at
) ON dfe_metadata.dataset_observations TO dfe_metadata_writer;
