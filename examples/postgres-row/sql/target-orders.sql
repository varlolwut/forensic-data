SELECT
    order_id AS order_id_target,
    business_date AS business_date_target,
    amount AS amount_target
FROM public.target_orders
WHERE business_date = %(business_date)s
