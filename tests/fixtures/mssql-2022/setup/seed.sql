SET NOCOUNT ON;
SET XACT_ABORT ON;

BEGIN TRANSACTION;

DELETE FROM [dfe_fixture].[snapshot_probe];

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

COMMIT TRANSACTION;

SELECT COUNT_BIG(*) AS [seeded_rows]
FROM [dfe_fixture].[snapshot_probe];
