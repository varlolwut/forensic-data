SET NOCOUNT ON;
SET XACT_ABORT ON;
USE [master];

IF CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')) <> N'16.0.4295.3'
BEGIN
    THROW 51000, N'Fixture requires SQL Server build 16.0.4295.3.', 1;
END;

IF CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateLevel')) <> N'CU27'
BEGIN
    THROW 51000, N'Fixture requires SQL Server 2022 CU27.', 1;
END;

IF DB_ID(N'dfe_fixture') IS NOT NULL
BEGIN
    ALTER DATABASE [dfe_fixture] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE [dfe_fixture];
END;

IF SUSER_ID(N'dfe_fixture_reader') IS NOT NULL
BEGIN
    DROP LOGIN [dfe_fixture_reader];
END;

IF SUSER_ID(N'dfe_fixture_setup_writer') IS NOT NULL
BEGIN
    DROP LOGIN [dfe_fixture_setup_writer];
END;

CREATE LOGIN [dfe_fixture_reader]
WITH PASSWORD = N'$(DFE_MSSQL_READER_PASSWORD)',
    CHECK_POLICY = ON,
    CHECK_EXPIRATION = OFF,
    DEFAULT_DATABASE = [master];

CREATE LOGIN [dfe_fixture_setup_writer]
WITH PASSWORD = N'$(DFE_MSSQL_SETUP_WRITER_PASSWORD)',
    CHECK_POLICY = ON,
    CHECK_EXPIRATION = OFF,
    DEFAULT_DATABASE = [master];

CREATE DATABASE [dfe_fixture] COLLATE Latin1_General_100_CI_AS_SC;
ALTER DATABASE [dfe_fixture] SET ALLOW_SNAPSHOT_ISOLATION ON;
ALTER DATABASE [dfe_fixture] SET READ_COMMITTED_SNAPSHOT OFF;
ALTER LOGIN [dfe_fixture_reader] WITH DEFAULT_DATABASE = [dfe_fixture];
ALTER LOGIN [dfe_fixture_setup_writer] WITH DEFAULT_DATABASE = [dfe_fixture];
GO

USE [dfe_fixture];
GO

CREATE SCHEMA [dfe_fixture] AUTHORIZATION [dbo];
GO

CREATE TABLE [dfe_fixture].[snapshot_probe]
(
    [record_id] bigint NOT NULL,
    [observed_value] nvarchar(128) NOT NULL,
    [amount] decimal(38, 3) NOT NULL,
    [observed_at] datetime2(7) NOT NULL,
    CONSTRAINT [PK_dfe_fixture_snapshot_probe] PRIMARY KEY ([record_id])
);

CREATE USER [dfe_fixture_reader]
FOR LOGIN [dfe_fixture_reader]
WITH DEFAULT_SCHEMA = [dfe_fixture];

CREATE USER [dfe_fixture_setup_writer]
FOR LOGIN [dfe_fixture_setup_writer]
WITH DEFAULT_SCHEMA = [dfe_fixture];

CREATE ROLE [dfe_fixture_reader_role] AUTHORIZATION [dbo];
CREATE ROLE [dfe_fixture_setup_writer_role] AUTHORIZATION [dbo];

ALTER ROLE [dfe_fixture_reader_role] ADD MEMBER [dfe_fixture_reader];
ALTER ROLE [dfe_fixture_setup_writer_role] ADD MEMBER [dfe_fixture_setup_writer];

GRANT CONNECT TO [dfe_fixture_reader];
GRANT CONNECT TO [dfe_fixture_setup_writer];
GRANT SELECT ON SCHEMA::[dfe_fixture] TO [dfe_fixture_reader_role];
GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::[dfe_fixture]
TO [dfe_fixture_setup_writer_role];

DENY INSERT, UPDATE, DELETE ON SCHEMA::[dfe_fixture]
TO [dfe_fixture_reader_role];
DENY CREATE TABLE, CREATE VIEW, CREATE PROCEDURE, CREATE FUNCTION
TO [dfe_fixture_reader];

IF NOT EXISTS
(
    SELECT 1
    FROM sys.databases
    WHERE [name] = N'dfe_fixture'
      AND [snapshot_isolation_state_desc] = N'ON'
      AND [is_read_committed_snapshot_on] = 0
)
BEGIN
    THROW 51000, N'Fixture requires SNAPSHOT ON and READ_COMMITTED_SNAPSHOT OFF.', 1;
END;

SELECT
    CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')) AS [product_version],
    CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateLevel')) AS [update_level],
    [snapshot_isolation_state_desc],
    [is_read_committed_snapshot_on]
FROM sys.databases
WHERE [name] = N'dfe_fixture';
