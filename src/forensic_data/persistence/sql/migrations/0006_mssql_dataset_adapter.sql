ALTER TABLE dfe_metadata.dataset_versions
  DROP CONSTRAINT dataset_versions_adapter_supported;

ALTER TABLE dfe_metadata.dataset_versions
  ADD CONSTRAINT dataset_versions_adapter_supported CHECK (
    adapter IN ('postgresql', 'mssql')
  );

ALTER TABLE dfe_metadata.dataset_versions
  ADD CONSTRAINT dataset_versions_mssql_relation_supported CHECK (
    adapter <> 'mssql'
    OR (
      locator_kind = 'relation'
      AND relation_scope = 'physical_only'
    )
  );

ALTER TABLE dfe_metadata.dataset_observations
  ADD CONSTRAINT dataset_observations_mssql_code_artifacts_absent CHECK (
    physical_binding ->> 'engine' <> 'mssql'
    OR (
      projection_code_artifact_id IS NULL
      AND readiness_code_artifact_id IS NULL
    )
  );
