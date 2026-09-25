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

IF NOT EXISTS
(
    SELECT 1
    FROM sys.databases
    WHERE [name] = N'dfe_rcsi_fixture'
      AND [snapshot_isolation_state_desc] = N'OFF'
      AND [is_read_committed_snapshot_on] = 1
      AND [compatibility_level] = 160
)
BEGIN
    THROW 51000,
        N'RCSI-only fixture requires compatibility level 160, SNAPSHOT OFF, and READ_COMMITTED_SNAPSHOT ON.',
        1;
END;

IF IS_SRVROLEMEMBER(N'sysadmin') <> 0
   OR IS_ROLEMEMBER(N'db_owner') <> 0
   OR IS_ROLEMEMBER(N'dfe_fixture_reader_role') <> 1
   OR IS_ROLEMEMBER(N'dfe_fixture_setup_writer_role') <> 0
BEGIN
    THROW 51000, N'Fixture reader role membership is not least privilege.', 1;
END;

IF HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'VIEW SECURITY DEFINITION') <> 1
BEGIN
    THROW 51000, N'Fixture reader cannot prove complete security-policy metadata.', 1;
END;

IF HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'VIEW DEFINITION') <> 1
BEGIN
    THROW 51000, N'Fixture reader cannot enumerate every security-policy object.', 1;
END;

IF
(
    SELECT COUNT_BIG(*)
    FROM sys.security_policies AS [policy]
    JOIN sys.schemas AS [schema]
      ON [schema].[schema_id] = [policy].[schema_id]
    WHERE [schema].[name] = N'dfe_fixture'
      AND [policy].[name] = N'rls_probe_policy'
      AND [policy].[is_enabled] = 1
) <> 1
BEGIN
    THROW 51000, N'Fixture reader cannot see the enabled RLS policy metadata.', 1;
END;

IF
(
    SELECT COUNT_BIG(*)
    FROM sys.security_predicates AS [predicate]
    JOIN sys.security_policies AS [policy]
      ON [policy].[object_id] = [predicate].[object_id]
    WHERE [policy].[object_id] = OBJECT_ID(N'dfe_fixture.rls_probe_policy', N'SP')
      AND [predicate].[target_object_id] = OBJECT_ID(N'dfe_fixture.rls_probe', N'U')
      AND [predicate].[predicate_type] = 0
      AND [predicate].[operation] IS NULL
) <> 1
BEGIN
    THROW 51000, N'Fixture reader cannot see the RLS filter-predicate metadata.', 1;
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

DECLARE @expected_canonical_keys TABLE
(
    [probe_id] int NOT NULL PRIMARY KEY,
    [text_key_bytes] varbinary(64) NULL,
    [numeric_key] decimal(38, 7) NULL
);

INSERT INTO @expected_canonical_keys
([probe_id], [text_key_bytes], [numeric_key])
VALUES
    (1, CONVERT(varbinary(64), N'A'), CONVERT(decimal(38, 7), N'10.0000000')),
    (2, CONVERT(varbinary(64), N'a'), CONVERT(decimal(38, 7), N'10.0000000')),
    (3, CONVERT(varbinary(64), NCHAR(0x00E9)), CONVERT(decimal(38, 7), N'10.0000000')),
    (4, CONVERT(varbinary(64), N'e' + NCHAR(0x0301)), CONVERT(decimal(38, 7), N'10.0000000')),
    (5, CONVERT(varbinary(64), N'x'), CONVERT(decimal(38, 7), N'10.0000000')),
    (6, CONVERT(varbinary(64), N'x '), CONVERT(decimal(38, 7), N'10.0000000')),
    (7, NULL, CONVERT(decimal(38, 7), N'10.0000000')),
    (8, CONVERT(varbinary(64), N'z'), CONVERT(decimal(38, 7), N'1.5000000')),
    (9, CONVERT(varbinary(64), N'z'), CONVERT(decimal(38, 7), N'9223372036854775808.0000000')),
    (10, CONVERT(varbinary(64), N'A'), CONVERT(decimal(38, 7), N'10.0000000'));

IF EXISTS
(
    SELECT [probe_id], CONVERT(varbinary(64), [text_key]), [numeric_key]
    FROM [dfe_fixture].[canonical_key_probe]
    EXCEPT
    SELECT [probe_id], [text_key_bytes], [numeric_key]
    FROM @expected_canonical_keys
)
   OR EXISTS
   (
       SELECT [probe_id], [text_key_bytes], [numeric_key]
       FROM @expected_canonical_keys
       EXCEPT
       SELECT [probe_id], CONVERT(varbinary(64), [text_key]), [numeric_key]
       FROM [dfe_fixture].[canonical_key_probe]
   )
BEGIN
    THROW 51000, N'Canonical key-validation seed is missing or changed.', 1;
END;

IF
(
    SELECT COUNT_BIG(*)
    FROM
    (
        SELECT [text_key]
        FROM [dfe_fixture].[canonical_key_probe]
        WHERE [probe_id] BETWEEN 1 AND 6
        GROUP BY [text_key]
    ) AS [native_groups]
) <> 3
BEGIN
    THROW 51000, N'Canonical key fixture no longer exercises native collation collapse.', 1;
END;

IF (SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_orders]) <> 1000001
   OR
   (
       SELECT COUNT_BIG(*)
       FROM [dfe_fixture].[comparison_orders]
       WHERE [business_date] = CONVERT(date, N'2026-09-23', 23)
   ) <> 1000000
   OR NOT EXISTS
   (
       SELECT 1
       FROM [dfe_fixture].[comparison_orders]
       WHERE [order_id] = CONVERT(decimal(21, 2), N'1.00')
         AND [business_date] = CONVERT(date, N'2026-09-22', 23)
         AND [amount] = CONVERT(decimal(18, 2), N'900.00')
         AND [precise_amount] = CONVERT(decimal(38, 7), N'900.0000000')
         AND [local_time] = CONVERT(datetime2(7), N'2026-09-22T11:22:33.1234560', 126)
         AND [instant_time] = CONVERT(
             datetimeoffset(7),
             N'2026-09-22T08:22:33.1234560+00:00',
             127
         )
   )
   OR EXISTS
   (
       SELECT 1
       FROM [dfe_fixture].[comparison_orders]
       WHERE [business_date] = CONVERT(date, N'2026-09-23', 23)
         AND
         (
             [amount] IS NULL
             OR [amount] <> CONVERT(decimal(18, 2), N'100.00')
             OR [precise_amount] IS NULL
             OR [precise_amount]
                <> CONVERT(decimal(38, 7), N'1234567890123456789012345678901.1234567')
             OR [local_time]
                <> CONVERT(datetime2(7), N'2026-09-23T11:22:33.1234560', 126)
             OR [instant_time] <> CONVERT(
                 datetimeoffset(7),
                 N'2026-09-23T08:22:33.1234560+00:00',
                 127
             )
             OR NOT
             (
                 ([order_id] BETWEEN 2 AND 2000 AND [order_id] % 2 = 0)
                 OR [order_id] BETWEEN 1000001 AND 1999000
             )
         )
   )
BEGIN
    THROW 51000, N'Cross-engine comparison seed is missing or changed.', 1;
END;

IF (SELECT COUNT_BIG(*) FROM [dfe_fixture].[comparison_batch_manifest]) <> 1
   OR NOT EXISTS
   (
       SELECT 1
       FROM [dfe_fixture].[comparison_batch_manifest]
       WHERE [dataset_id] = N'reference_orders'
         AND [scope_digest]
             = N'df903aeb9157fcc8da48575be4a841781a2df049299fdf8b3623f719ee5465ab'
         AND [batch_id] = N'reference-orders-baseline'
         AND [state] = N'complete'
         AND [business_date] = CONVERT(date, N'2026-09-23', 23)
         AND [source_cut] = N'orders-cut-baseline'
         AND [dataset_version] = N'reference-orders-v1'
         AND [completed_at] = CONVERT(
             datetimeoffset(6),
             N'2026-09-23T12:30:45.123456+00:00',
             127
         )
   )
BEGIN
    THROW 51000, N'Cross-engine comparison manifest seed is missing or changed.', 1;
END;

IF (SELECT COUNT_BIG(*) FROM [dfe_fixture].[rls_probe]) <> 1
   OR NOT EXISTS
   (
       SELECT 1
       FROM [dfe_fixture].[rls_probe]
       WHERE [record_id] = 1
         AND [visible_to_reader] = CONVERT(bit, 1)
         AND [observed_value] = N'visible'
   )
   OR EXISTS
   (
       SELECT 1
       FROM [dfe_fixture].[rls_probe]
       WHERE [record_id] = 2
   )
BEGIN
    THROW 51000, N'Enabled RLS policy did not filter the restricted reader.', 1;
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
    N'RCSI_OFF' AS [read_committed_snapshot],
    (SELECT [snapshot_isolation_state_desc]
     FROM sys.databases
     WHERE [name] = N'dfe_rcsi_fixture') AS [rcsi_fixture_snapshot_isolation],
    (SELECT [is_read_committed_snapshot_on]
     FROM sys.databases
     WHERE [name] = N'dfe_rcsi_fixture') AS [rcsi_fixture_read_committed_snapshot];
