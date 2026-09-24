SET NOCOUNT ON;
SET XACT_ABORT ON;

BEGIN TRANSACTION;

DELETE FROM [dfe_fixture].[snapshot_probe];
DELETE FROM [dfe_fixture].[canonical_probe];
DELETE FROM [dfe_fixture].[canonical_common_types];

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

COMMIT TRANSACTION;

SELECT
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[snapshot_probe]) AS [snapshot_rows],
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[canonical_probe]) AS [canonical_rows],
    (SELECT COUNT_BIG(*) FROM [dfe_fixture].[canonical_common_types])
        AS [common_type_rows];
