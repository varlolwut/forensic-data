INSERT INTO dfe_legacy.daily_orders (order_id, business_date, amount)
VALUES
  (1001, DATE '2026-09-23', 10.00),
  (1002, DATE '2026-09-23', 20.00),
  (1003, DATE '2026-09-23', 30.00);

INSERT INTO dfe_control.batch_manifest (
  dataset_id,
  scope_digest,
  batch_id,
  state,
  business_date,
  source_cut,
  dataset_version,
  completed_at
)
VALUES (
  'reference_orders',
  'df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab',
  'legacy-reference-2026-09-23',
  'complete',
  DATE '2026-09-23',
  'legacy-cut-1',
  'legacy-reference-v1',
  TIMESTAMPTZ '2026-09-23 00:00:00+00'
);
