SET NOCOUNT ON;
SET XACT_ABORT ON;

IF CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')) <> N'16.0.4295.3'
BEGIN
    THROW 51000, N'Unexpected SQL Server product version.', 1;
END;

IF CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateLevel')) <> N'CU27'
BEGIN
    THROW 51000, N'Unexpected SQL Server update level.', 1;
END;

IF CONVERT(nvarchar(128), SERVERPROPERTY(N'Edition')) <> N'Developer Edition (64-bit)'
BEGIN
    THROW 51000, N'Fixture requires SQL Server Developer Edition.', 1;
END;

IF CONVERT(nvarchar(128), DATABASEPROPERTYEX(DB_NAME(), N'Collation'))
    <> N'Latin1_General_100_CI_AS_SC'
BEGIN
    THROW 51000, N'Unexpected fixture database collation.', 1;
END;

IF NOT EXISTS
(
    SELECT 1
    FROM sys.databases
    WHERE [name] = DB_NAME()
      AND [snapshot_isolation_state_desc] = N'ON'
      AND [is_read_committed_snapshot_on] = 0
      AND [compatibility_level] = 160
)
BEGIN
    THROW 51000,
        N'Fixture requires compatibility level 160, SNAPSHOT ON, and READ_COMMITTED_SNAPSHOT OFF.',
        1;
END;

IF IS_SRVROLEMEMBER(N'sysadmin') <> 0
   OR IS_ROLEMEMBER(N'db_owner') <> 0
   OR IS_ROLEMEMBER(N'dfe_fixture_reader_role') <> 1
   OR IS_ROLEMEMBER(N'dfe_fixture_setup_writer_role') <> 0
BEGIN
    THROW 51000, N'Fixture reader role membership is not least privilege.', 1;
END;

SET TRANSACTION ISOLATION LEVEL SNAPSHOT;
BEGIN TRANSACTION;

DECLARE @transaction_isolation_level smallint;
SELECT @transaction_isolation_level = [transaction_isolation_level]
FROM sys.dm_exec_sessions
WHERE [session_id] = @@SPID;

IF @transaction_isolation_level <> 5
BEGIN
    THROW 51000, N'Fixture reader did not enter transaction-level SNAPSHOT.', 1;
END;

IF NOT EXISTS
(
    SELECT 1
    FROM [dfe_fixture].[snapshot_probe]
    WHERE [record_id] = 1
      AND [observed_value] = N'Привет 😀'
      AND [amount] = CONVERT(decimal(38, 3), N'123.450')
      AND [observed_at] = CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234567', 126)
)
BEGIN
    THROW 51000, N'Setup writer seed is missing or changed.', 1;
END;

IF (SELECT COUNT_BIG(*) FROM [dfe_fixture].[canonical_probe]) <> 2
   OR NOT EXISTS
   (
       SELECT 1
       FROM [dfe_fixture].[canonical_probe]
       WHERE [record_id] = CONVERT(bigint, N'-9223372036854775808')
         AND [amount] = CONVERT(
             decimal(38, 7),
             N'-9999999999999999999999999999999.9999999'
         )
         AND DATALENGTH([observed_value]) = 8000
         AND RIGHT([observed_value], 8) = N'A|Б😀é  '
         AND [observed_at] = CONVERT(datetime2(7), N'2026-09-24T01:02:03.1234567', 126)
   )
BEGIN
    THROW 51000, N'Canonical conformance seed is missing or changed.', 1;
END;

IF NOT EXISTS
(
    SELECT 1
    FROM [dfe_fixture].[canonical_probe]
    WHERE [record_id] = CONVERT(bigint, N'9223372036854775807')
      AND [amount] = CONVERT(decimal(38, 7), N'123.4500000')
      AND [observed_value] IS NULL
      AND [observed_at] = CONVERT(datetime2(7), N'9999-12-31T23:59:59.9999999', 126)
)
BEGIN
    THROW 51000, N'Canonical NULL conformance seed is missing or changed.', 1;
END;

IF (SELECT COUNT_BIG(*) FROM [dfe_fixture].[canonical_common_types]) <> 2
   OR NOT EXISTS
   (
       SELECT 1
       FROM [dfe_fixture].[canonical_common_types]
       WHERE [probe_id] = 1
         AND [id] = CONVERT(bigint, N'-9223372036854775808')
         AND [amount] = CONVERT(decimal(38, 3), N'-1780.000')
         AND [active] = CONVERT(bit, 1)
         AND [label] = N'A|Б😀é  '
         AND DATALENGTH([label]) = 18
         AND [business_date] = CONVERT(date, N'2024-02-29', 23)
         AND [local_time] = CONVERT(datetime2(7), N'2024-02-29T23:59:58.1234560', 126)
         AND [instant_time] = CONVERT(
             datetimeoffset(7),
             N'2024-02-29T21:29:58.1234560+00:00',
             127
         )
   )
   OR NOT EXISTS
   (
       SELECT 1
       FROM [dfe_fixture].[canonical_common_types]
       WHERE [probe_id] = 2
         AND [local_time] = CONVERT(datetime2(7), N'2024-02-29T23:59:58.1234567', 126)
   )
BEGIN
    THROW 51000, N'Canonical common-type conformance seed is missing or changed.', 1;
END;

ROLLBACK TRANSACTION;

SELECT
    CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')) AS [product_version],
    CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateLevel')) AS [update_level],
    CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateReference')) AS [update_reference],
    CONVERT(nvarchar(128), SERVERPROPERTY(N'Edition')) AS [edition],
    CONVERT(nvarchar(128), DATABASEPROPERTYEX(DB_NAME(), N'Collation')) AS [database_collation],
    (SELECT [compatibility_level] FROM sys.databases WHERE [name] = DB_NAME())
        AS [compatibility_level],
    N'SNAPSHOT' AS [reader_isolation],
    N'RCSI_OFF' AS [read_committed_snapshot];
