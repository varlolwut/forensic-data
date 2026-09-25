SET NOCOUNT ON;
SET XACT_ABORT ON;

BEGIN TRANSACTION;

DELETE FROM [dfe_fixture].[snapshot_probe];
DELETE FROM [dfe_fixture].[canonical_probe];
DELETE FROM [dfe_fixture].[canonical_common_types];
DELETE FROM [dfe_fixture].[canonical_key_probe];
DELETE FROM [dfe_fixture].[comparison_orders];
DELETE FROM [dfe_fixture].[comparison_batch_manifest];
DELETE FROM [dfe_fixture].[rls_probe];

INSERT INTO [dfe_fixture].[snapshot_probe]
(
    [record_id],
    [observed_value],
    [amount],
    [observed_at]
)
VALUES
(
    1,
    N'Привет 😀',
    CONVERT(decimal(38, 3), N'123.450'),
    CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234567', 126)
);

INSERT INTO [dfe_fixture].[canonical_probe]
(
    [record_id],
    [amount],
    [observed_value],
    [observed_at]
)
VALUES
(
    CONVERT(bigint, N'-9223372036854775808'),
    CONVERT(decimal(38, 7), N'-9999999999999999999999999999999.9999999'),
    REPLICATE(CONVERT(nvarchar(max), N'x'), 3991) + N'A|Б😀é  ',
    CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234567', 126)
),
(
    CONVERT(bigint, N'9223372036854775807'),
    CONVERT(decimal(38, 7), N'123.4500000'),
    NULL,
    CONVERT(datetime2(7), N'9999-12-31T23:59:59.9999999', 126)
);

INSERT INTO [dfe_fixture].[canonical_common_types]
(
    [probe_id],
    [id],
    [amount],
    [active],
    [label],
    [business_date],
    [local_time],
    [instant_time]
)
VALUES
(
    1,
    CONVERT(bigint, N'-9223372036854775808'),
    CONVERT(decimal(38, 3), N'-1780.000'),
    CONVERT(bit, 1),
    N'A|Б😀é  ',
    CONVERT(date, N'2024-02-29', 23),
    CONVERT(datetime2(7), N'2024-02-29T23:59:58.1234560', 126),
    CONVERT(datetimeoffset(7), N'2024-02-29T21:29:58.1234560+00:00', 127)
),
(
    2,
    CONVERT(bigint, 0),
    CONVERT(decimal(38, 3), N'0.000'),
    CONVERT(bit, 0),
    N'invalid precision',
    CONVERT(date, N'2024-02-29', 23),
    CONVERT(datetime2(7), N'2024-02-29T23:59:58.1234567', 126),
    CONVERT(datetimeoffset(7), N'2024-02-29T21:29:58.1234560+00:00', 127)
);

INSERT INTO [dfe_fixture].[canonical_key_probe]
(
    [probe_id],
    [text_key],
    [numeric_key]
)
VALUES
    (1, N'A', CONVERT(decimal(38, 7), N'10.0000000')),
    (2, N'a', CONVERT(decimal(38, 7), N'10.0000000')),
    (3, NCHAR(0x00E9), CONVERT(decimal(38, 7), N'10.0000000')),
    (4, N'e' + NCHAR(0x0301), CONVERT(decimal(38, 7), N'10.0000000')),
    (5, N'x', CONVERT(decimal(38, 7), N'10.0000000')),
    (6, N'x ', CONVERT(decimal(38, 7), N'10.0000000')),
    (7, NULL, CONVERT(decimal(38, 7), N'10.0000000')),
    (8, N'z', CONVERT(decimal(38, 7), N'1.5000000')),
    (9, N'z', CONVERT(decimal(38, 7), N'9223372036854775808.0000000')),
    (10, N'A', CONVERT(decimal(38, 7), N'10.0000000'));

INSERT INTO [dfe_fixture].[comparison_orders]
(
    [order_id],
    [business_date],
    [amount],
    [precise_amount],
    [local_time],
    [instant_time]
)
SELECT
    CONVERT(decimal(21, 2), [value] * 2),
    CONVERT(date, N'2026-09-23', 23),
    CONVERT(decimal(18, 2), N'100.00'),
    CONVERT(decimal(38, 7), N'1234567890123456789012345678901.1234567'),
    CONVERT(datetime2(7), N'2026-09-23T11:22:33.1234560', 126),
    CONVERT(datetimeoffset(7), N'2026-09-23T08:22:33.1234560+00:00', 127)
FROM GENERATE_SERIES(1, 1000, 1)
UNION ALL
SELECT
    CONVERT(decimal(21, 2), 1000000 + [value]),
    CONVERT(date, N'2026-09-23', 23),
    CONVERT(decimal(18, 2), N'100.00'),
    CONVERT(decimal(38, 7), N'1234567890123456789012345678901.1234567'),
    CONVERT(datetime2(7), N'2026-09-23T11:22:33.1234560', 126),
    CONVERT(datetimeoffset(7), N'2026-09-23T08:22:33.1234560+00:00', 127)
FROM GENERATE_SERIES(1, 999000, 1);

INSERT INTO [dfe_fixture].[comparison_orders]
(
    [order_id],
    [business_date],
    [amount],
    [precise_amount],
    [local_time],
    [instant_time]
)
VALUES
(
    CONVERT(decimal(21, 2), N'1.00'),
    CONVERT(date, N'2026-09-22', 23),
    CONVERT(decimal(18, 2), N'900.00'),
    CONVERT(decimal(38, 7), N'900.0000000'),
    CONVERT(datetime2(7), N'2026-09-22T11:22:33.1234560', 126),
    CONVERT(datetimeoffset(7), N'2026-09-22T08:22:33.1234560+00:00', 127)
);

INSERT INTO [dfe_fixture].[comparison_batch_manifest]
(
    [dataset_id],
    [scope_digest],
    [batch_id],
    [state],
    [business_date],
    [source_cut],
    [dataset_version],
    [completed_at]
)
VALUES
(
    N'reference_orders',
    N'df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab',
    N'reference-orders-baseline',
    N'complete',
    CONVERT(date, N'2026-09-23', 23),
    N'orders-cut-baseline',
    N'reference-orders-v1',
    CONVERT(datetimeoffset(6), N'2026-09-23T12:30:45.123456+00:00', 127)
);

INSERT INTO [dfe_fixture].[rls_probe]
(
    [record_id],
    [visible_to_reader],
    [observed_value]
)
VALUES
    (1, CONVERT(bit, 1), N'visible'),
    (2, CONVERT(bit, 0), N'filtered');

IF (SELECT COUNT_BIG(*) FROM [dfe_fixture].[rls_probe]) <> 2
BEGIN
    THROW 51000, N'RLS fixture writer must see both seeded rows.', 1;
END;

COMMIT TRANSACTION;

SELECT
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[snapshot_probe]) AS [snapshot_rows],
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[canonical_probe]) AS [canonical_rows],
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[canonical_common_types])
        AS [common_type_rows],
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[canonical_key_probe])
        AS [canonical_key_rows],
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders])
        AS [comparison_order_rows],
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_batch_manifest])
        AS [comparison_manifest_rows],
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[rls_probe])
        AS [rls_writer_visible_rows];
