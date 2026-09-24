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
)
BEGIN
    THROW 51000, N'Fixture requires SNAPSHOT ON and READ_COMMITTED_SNAPSHOT OFF.', 1;
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

ROLLBACK TRANSACTION;

SELECT
    CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')) AS [product_version],
    CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateLevel')) AS [update_level],
    CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateReference')) AS [update_reference],
    CONVERT(nvarchar(128), SERVERPROPERTY(N'Edition')) AS [edition],
    CONVERT(nvarchar(128), DATABASEPROPERTYEX(DB_NAME(), N'Collation')) AS [database_collation],
    N'SNAPSHOT' AS [reader_isolation],
    N'RCSI_OFF' AS [read_committed_snapshot];
