SELECT dataset_id, batch_id, state, business_date, source_cut, dataset_version, completed_at
FROM dfe_control.batch_manifest
WHERE dataset_id = 'target_orders'
  AND business_date = %(business_date)s
  AND state = 'complete'
