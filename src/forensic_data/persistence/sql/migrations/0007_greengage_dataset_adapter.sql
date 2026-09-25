ALTER TABLE dfe_metadata.dataset_versions
  DROP CONSTRAINT dataset_versions_adapter_supported;

ALTER TABLE dfe_metadata.dataset_versions
  ADD CONSTRAINT dataset_versions_adapter_supported CHECK (
    adapter IN ('postgresql', 'mssql', 'greengage')
  );

ALTER TABLE dfe_metadata.dataset_versions
  ADD CONSTRAINT dataset_versions_greengage_profile_supported CHECK (
    adapter <> 'greengage'
    OR (
      driver = 'psycopg'
      AND profile = 'greengage'
    )
  );

ALTER TABLE dfe_metadata.dataset_versions
  ADD CONSTRAINT dataset_versions_greengage_relation_supported CHECK (
    adapter <> 'greengage'
    OR (
      locator_kind = 'relation'
      AND relation_scope = 'physical_only'
    )
  );

ALTER TABLE dfe_metadata.dataset_observations
  ADD CONSTRAINT dataset_observations_greengage_code_artifacts_absent CHECK (
    physical_binding ->> 'engine' <> 'greengage'
    OR (
      projection_code_artifact_id IS NULL
      AND readiness_code_artifact_id IS NULL
    )
  );
