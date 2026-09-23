ALTER TABLE dfe_metadata.dataset_versions
  DROP CONSTRAINT dataset_versions_locator_supported;

ALTER TABLE dfe_metadata.dataset_versions
  ADD CONSTRAINT dataset_versions_locator_supported CHECK (
    (
      locator_kind = 'relation'
      AND relation_scope IS NOT NULL
      AND relation_scope IN ('physical_only', 'frozen_physical_union')
    )
    OR (locator_kind = 'sql' AND relation_scope IS NULL)
  );
