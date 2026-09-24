SET NOCOUNT ON;
SET XACT_ABORT ON;

BEGIN TRANSACTION;

DELETE FROM [dfe_fixture].[snapshot_probe];
DELETE FROM [dfe_fixture].[canonical_probe];
DELETE FROM [dfe_fixture].[canonical_common_types];
DELETE FROM [dfe_fixture].[canonical_key_probe];
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
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[rls_probe])
        AS [rls_writer_visible_rows];
