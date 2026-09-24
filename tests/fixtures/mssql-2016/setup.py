"""Provision or validate the dedicated SQL Server 2016 integration fixture."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import pyodbc

from forensic_data.mssql_resources import (
    MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256,
    MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES,
    load_mssql_2016_canonical_utf8_helper_sql,
)

_LOGGER = logging.getLogger("forensic_data.mssql_2016_setup")
_DATABASE = "dfe_fixture"
_READER_LOGIN = "dfe_fixture_reader"
_WRITER_LOGIN = "dfe_fixture_setup_writer"
_READER_ROLE = "dfe_fixture_reader_role"
_WRITER_ROLE = "dfe_fixture_setup_writer_role"
_EXPECTED_PRODUCT_VERSION = "13.0.6500.1"
_EXPECTED_PRODUCT_BUILD = "6500"
_EXPECTED_PRODUCT_LEVEL = "SP3"
_EXPECTED_UPDATE_LEVEL: str | None = None
_EXPECTED_UPDATE_REFERENCE = "KB5102340"
_EXPECTED_ENGINE_EDITION = 4
_EXPECTED_EDITION = "Express Edition (64-bit)"
_EXPECTED_COLLATION = "Latin1_General_100_CI_AS_SC"
_DATABASE_OWNERSHIP_PROPERTY = "dfe_fixture_setup_contract"
_DATABASE_OWNERSHIP_VALUE = "dfe-mssql-2016-sp3-gdr-v1"
_CONNECT_ATTEMPTS = 3
_CONNECT_RETRY_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class _SetupSettings:
    host: str
    port: int
    sa_password: str
    reader_password: str
    writer_password: str


@dataclass(frozen=True, slots=True)
class _ConnectionRequest:
    host: str
    port: int
    database: str
    user: str
    password: str
    application_name: str
    application_intent: str
    autocommit: bool
    readonly: bool


@dataclass(frozen=True, slots=True)
class _ServerState:
    database_exists: bool
    reader_login_exists: bool
    writer_login_exists: bool

    def is_fresh(self) -> bool:
        return not (self.database_exists or self.reader_login_exists or self.writer_login_exists)

    def is_complete(self) -> bool:
        return self.database_exists and self.reader_login_exists and self.writer_login_exists


@dataclass(frozen=True, slots=True)
class _DatabaseObjectState:
    ownership_value: str | None
    helper_schema_exists: bool
    fixture_schema_exists: bool
    helper_object_exists: bool
    reader_user_exists: bool
    writer_user_exists: bool
    reader_role_exists: bool
    writer_role_exists: bool

    def is_empty(self) -> bool:
        return not any(
            (
                self.helper_schema_exists,
                self.fixture_schema_exists,
                self.helper_object_exists,
                self.reader_user_exists,
                self.writer_user_exists,
                self.reader_role_exists,
                self.writer_role_exists,
            )
        )

    def is_complete(self) -> bool:
        return all(
            (
                self.helper_schema_exists,
                self.fixture_schema_exists,
                self.helper_object_exists,
                self.reader_user_exists,
                self.writer_user_exists,
                self.reader_role_exists,
                self.writer_role_exists,
            )
        )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = _load_settings()
    admin = _connect_admin(settings, "master", "dfe-mssql-2016-setup-master")
    try:
        state = _inspect_server(admin)
        if state.is_fresh():
            _provision_fresh_master_fixture(admin, settings)
        elif not state.is_complete():
            raise RuntimeError(
                "SQL Server 2016 fixture setup found a partial reserved-name collision and "
                "will not drop or overwrite it: "
                f"database_exists={state.database_exists}, "
                f"reader_login_exists={state.reader_login_exists}, "
                f"writer_login_exists={state.writer_login_exists}. "
                "Use a fresh disposable SQL Server 2016 instance or remove only the confirmed "
                "fixture-owned objects before retrying."
            )
        _validate_master_fixture(admin)
    finally:
        admin.close()

    fixture_admin = _connect_admin(
        settings,
        _DATABASE,
        "dfe-mssql-2016-setup-validation",
    )
    try:
        database_state = _inspect_database_object_state(fixture_admin)
        if database_state.is_empty():
            if database_state.ownership_value != _DATABASE_OWNERSHIP_VALUE:
                raise RuntimeError(
                    "SQL Server 2016 fixture database is empty but does not contain the exact "
                    "setup ownership marker; refusing to provision a pre-existing database: "
                    f"database={_DATABASE!r}, marker={database_state.ownership_value!r}"
                )
            provision_database_objects = True
        elif not database_state.is_complete():
            raise RuntimeError(
                "SQL Server 2016 fixture database contains a partial reserved-object collision "
                "and will not drop, overwrite, or repair it: "
                f"state={database_state!r}. Use a fresh disposable SQL Server 2016 instance."
            )
        else:
            if database_state.ownership_value not in (None, _DATABASE_OWNERSHIP_VALUE):
                raise RuntimeError(
                    "SQL Server 2016 fixture database ownership marker differs from the setup "
                    f"contract: actual={database_state.ownership_value!r}, "
                    f"required={_DATABASE_OWNERSHIP_VALUE!r}"
                )
            _validate_database_fixture(fixture_admin)
            provision_database_objects = False
    finally:
        fixture_admin.close()

    if provision_database_objects:
        fixture_provisioner = _connect_fixture_provisioner(settings)
        try:
            database_state = _inspect_database_object_state(fixture_provisioner)
            if (
                database_state.ownership_value != _DATABASE_OWNERSHIP_VALUE
                or not database_state.is_empty()
            ):
                raise RuntimeError(
                    "SQL Server 2016 fixture database changed before transactional "
                    f"provisioning began: state={database_state!r}"
                )
            _provision_database_objects(fixture_provisioner)
        finally:
            fixture_provisioner.close()

        fixture_admin = _connect_admin(
            settings,
            _DATABASE,
            "dfe-mssql-2016-setup-post-provision-validation",
        )
        try:
            _validate_database_fixture(fixture_admin)
        finally:
            fixture_admin.close()
    _validate_reader_login(settings)
    _validate_writer_login(settings)
    print(
        "SQL Server 2016 fixture is ready: "
        "database=dfe_fixture, compatibility_level=130, snapshot_isolation=ON, "
        "read_committed_snapshot=OFF, helper=dfe_ext.canonical_utf8_v1"
    )


def _load_settings() -> _SetupSettings:
    host = _required_environment("DFE_MSSQL_2016_HOST")
    port_text = _required_environment("DFE_MSSQL_2016_PORT")
    if not port_text.isascii() or not port_text.isdecimal():
        raise RuntimeError("DFE_MSSQL_2016_PORT must be a positive decimal integer")
    port = int(port_text)
    if not 1 <= port <= 65_535:
        raise RuntimeError("DFE_MSSQL_2016_PORT must be in the range 1..65535")
    sa_password = _required_password("DFE_MSSQL_2016_SA_PASSWORD")
    reader_password = _required_password("DFE_MSSQL_2016_READER_PASSWORD")
    writer_password = _required_password("DFE_MSSQL_2016_SETUP_WRITER_PASSWORD")
    named_passwords = (
        ("DFE_MSSQL_2016_SA_PASSWORD", sa_password),
        ("DFE_MSSQL_2016_READER_PASSWORD", reader_password),
        ("DFE_MSSQL_2016_SETUP_WRITER_PASSWORD", writer_password),
    )
    for index, (left_name, left_value) in enumerate(named_passwords):
        for right_name, right_value in named_passwords[index + 1 :]:
            if left_value == right_value:
                raise RuntimeError(f"{left_name} and {right_name} must be distinct")
    return _SetupSettings(
        host=host,
        port=port,
        sa_password=sa_password,
        reader_password=reader_password,
        writer_password=writer_password,
    )


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"{name} is required for SQL Server 2016 fixture setup")
    return value


def _required_password(name: str) -> str:
    value = _required_environment(name)
    if not 12 <= len(value) <= 128:
        raise RuntimeError(f"{name} must contain 12 to 128 characters")
    if any(not character.isprintable() or character.isspace() for character in value):
        raise RuntimeError(f"{name} must not contain whitespace or control characters")
    if not any(character.isupper() for character in value):
        raise RuntimeError(f"{name} must contain an upper-case character")
    if not any(character.islower() for character in value):
        raise RuntimeError(f"{name} must contain a lower-case character")
    if not any(character.isdigit() for character in value):
        raise RuntimeError(f"{name} must contain a numeric character")
    if not any(not character.isalnum() for character in value):
        raise RuntimeError(f"{name} must contain a symbol character")
    return value


def _connect_admin(
    settings: _SetupSettings,
    database: str,
    application_name: str,
) -> pyodbc.Connection:
    return _connect_with_retry(
        _ConnectionRequest(
            host=settings.host,
            port=settings.port,
            database=database,
            user="sa",
            password=settings.sa_password,
            application_name=application_name,
            application_intent="ReadWrite",
            autocommit=True,
            readonly=False,
        )
    )


def _connect_reader(settings: _SetupSettings) -> pyodbc.Connection:
    return _connect_with_retry(
        _ConnectionRequest(
            host=settings.host,
            port=settings.port,
            database=_DATABASE,
            user=_READER_LOGIN,
            password=settings.reader_password,
            application_name="dfe-mssql-2016-setup-reader-validation",
            application_intent="ReadOnly",
            autocommit=True,
            readonly=True,
        )
    )


def _connect_writer(settings: _SetupSettings) -> pyodbc.Connection:
    return _connect_with_retry(
        _ConnectionRequest(
            host=settings.host,
            port=settings.port,
            database=_DATABASE,
            user=_WRITER_LOGIN,
            password=settings.writer_password,
            application_name="dfe-mssql-2016-setup-writer-validation",
            application_intent="ReadWrite",
            autocommit=True,
            readonly=False,
        )
    )


def _connect_fixture_provisioner(settings: _SetupSettings) -> pyodbc.Connection:
    return _connect_with_retry(
        _ConnectionRequest(
            host=settings.host,
            port=settings.port,
            database=_DATABASE,
            user="sa",
            password=settings.sa_password,
            application_name="dfe-mssql-2016-setup-database-provision",
            application_intent="ReadWrite",
            autocommit=False,
            readonly=False,
        )
    )


def _connect_with_retry(request: _ConnectionRequest) -> pyodbc.Connection:
    last_error: pyodbc.Error | None = None
    for attempt in range(1, _CONNECT_ATTEMPTS + 1):
        try:
            connection = pyodbc.connect(
                _connection_string(request),
                autocommit=request.autocommit,
                readonly=request.readonly,
                timeout=15,
            )
            connection.timeout = 60
            return connection
        except pyodbc.Error as error:
            last_error = error
            if attempt < _CONNECT_ATTEMPTS:
                _LOGGER.warning(
                    "SQL Server fixture connection attempt failed",
                    extra={
                        "attempt": attempt,
                        "database": request.database,
                        "host": request.host,
                        "port": request.port,
                        "user": request.user,
                    },
                )
                time.sleep(_CONNECT_RETRY_SECONDS)
    if last_error is None:
        raise RuntimeError("SQL Server fixture connection retry loop produced no result")
    raise RuntimeError(
        "SQL Server fixture connection failed after retries: "
        f"host={request.host!r}, port={request.port}, database={request.database!r}, "
        f"user={request.user!r}, error={last_error}"
    ) from last_error


def _connection_string(request: _ConnectionRequest) -> str:
    values = (
        ("Driver", "ODBC Driver 18 for SQL Server"),
        ("Server", f"tcp:{request.host},{request.port}"),
        ("Database", request.database),
        ("UID", request.user),
        ("PWD", request.password),
        ("Encrypt", "Mandatory"),
        ("TrustServerCertificate", "Yes"),
        ("ApplicationIntent", request.application_intent),
        ("MARS_Connection", "No"),
        ("ConnectRetryCount", "0"),
        ("LongAsMax", "Yes"),
        ("APP", request.application_name),
    )
    return ";".join(f"{key}={_odbc_braced(value)}" for key, value in values)


def _odbc_braced(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"


def _inspect_server(connection: pyodbc.Connection) -> _ServerState:
    row = _fetch_one(
        connection,
        "SELECT CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')), "
        "TRY_CONVERT(int, SERVERPROPERTY(N'ProductMajorVersion')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductBuild')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductLevel')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateLevel')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductUpdateReference')), "
        "TRY_CONVERT(int, SERVERPROPERTY(N'EngineEdition')), "
        "CONVERT(nvarchar(128), SERVERPROPERTY(N'Edition')), "
        "CONVERT(bit, CASE WHEN DB_ID(N'dfe_fixture') IS NULL THEN 0 ELSE 1 END), "
        "CONVERT(bit, CASE WHEN SUSER_ID(N'dfe_fixture_reader') IS NULL THEN 0 ELSE 1 END), "
        "CONVERT(bit, CASE WHEN SUSER_ID(N'dfe_fixture_setup_writer') IS NULL "
        "THEN 0 ELSE 1 END)",
        (),
        "inspect SQL Server 2016 fixture prerequisites",
        11,
    )
    actual_profile = (
        _require_text(row[0], "product_version"),
        _require_integer(row[1], "product_major_version"),
        _require_text(row[2], "product_build"),
        _require_text(row[3], "product_level"),
        _require_optional_text(row[4], "product_update_level"),
        _require_text(row[5], "product_update_reference"),
        _require_integer(row[6], "engine_edition"),
        _require_text(row[7], "edition"),
    )
    required_profile = (
        _EXPECTED_PRODUCT_VERSION,
        13,
        _EXPECTED_PRODUCT_BUILD,
        _EXPECTED_PRODUCT_LEVEL,
        _EXPECTED_UPDATE_LEVEL,
        _EXPECTED_UPDATE_REFERENCE,
        _EXPECTED_ENGINE_EDITION,
        _EXPECTED_EDITION,
    )
    if actual_profile != required_profile:
        raise RuntimeError(
            "SQL Server 2016 fixture requires the exact tested Express SP3 KB5102340 "
            f"identity: actual={actual_profile!r}, required={required_profile!r}"
        )
    return _ServerState(
        database_exists=_require_boolean(row[8], "database_exists"),
        reader_login_exists=_require_boolean(row[9], "reader_login_exists"),
        writer_login_exists=_require_boolean(row[10], "writer_login_exists"),
    )


def _provision_fresh_master_fixture(
    master: pyodbc.Connection,
    settings: _SetupSettings,
) -> None:
    try:
        _execute(
            master,
            "CREATE LOGIN [dfe_fixture_reader] WITH PASSWORD = "
            f"{_unicode_literal(settings.reader_password)}, CHECK_POLICY = ON, "
            "CHECK_EXPIRATION = OFF, DEFAULT_DATABASE = [master]",
            (),
            "create SQL Server 2016 reader login",
        )
        _execute(
            master,
            "CREATE LOGIN [dfe_fixture_setup_writer] WITH PASSWORD = "
            f"{_unicode_literal(settings.writer_password)}, CHECK_POLICY = ON, "
            "CHECK_EXPIRATION = OFF, DEFAULT_DATABASE = [master]",
            (),
            "create SQL Server 2016 setup-writer login",
        )
        _execute(
            master,
            "CREATE DATABASE [dfe_fixture] COLLATE Latin1_General_100_CI_AS_SC",
            (),
            "create SQL Server 2016 fixture database",
        )
        _execute(
            master,
            "ALTER DATABASE [dfe_fixture] SET COMPATIBILITY_LEVEL = 130",
            (),
            "set SQL Server 2016 fixture compatibility level",
        )
        _execute(
            master,
            "ALTER DATABASE [dfe_fixture] SET ALLOW_SNAPSHOT_ISOLATION ON",
            (),
            "enable SQL Server 2016 SNAPSHOT isolation",
        )
        _execute(
            master,
            "ALTER DATABASE [dfe_fixture] SET READ_COMMITTED_SNAPSHOT OFF",
            (),
            "disable SQL Server 2016 READ_COMMITTED_SNAPSHOT",
        )
        _execute(
            master,
            "ALTER LOGIN [dfe_fixture_reader] WITH DEFAULT_DATABASE = [dfe_fixture]",
            (),
            "set SQL Server 2016 reader default database",
        )
        _execute(
            master,
            "ALTER LOGIN [dfe_fixture_setup_writer] WITH DEFAULT_DATABASE = [dfe_fixture]",
            (),
            "set SQL Server 2016 setup-writer default database",
        )
        _execute(
            master,
            "EXEC [dfe_fixture].[sys].[sp_addextendedproperty] "
            f"@name = N'{_DATABASE_OWNERSHIP_PROPERTY}', "
            f"@value = N'{_DATABASE_OWNERSHIP_VALUE}'",
            (),
            "mark the fresh SQL Server 2016 fixture database as setup-owned",
        )
    except RuntimeError as error:
        raise RuntimeError(
            "SQL Server 2016 fresh fixture provisioning stopped after a database operation. "
            "The disposable instance may now contain partial reserved objects; discard the "
            "instance or remove only confirmed fixture-owned objects before retrying."
        ) from error


def _inspect_database_object_state(connection: pyodbc.Connection) -> _DatabaseObjectState:
    row = _fetch_one(
        connection,
        "SELECT CONVERT(nvarchar(128), (SELECT [property].[value] "
        "FROM sys.extended_properties AS [property] "
        "WHERE [property].[class] = 0 AND [property].[major_id] = 0 "
        "AND [property].[minor_id] = 0 "
        f"AND [property].[name] = N'{_DATABASE_OWNERSHIP_PROPERTY}')), "
        "CONVERT(bit, CASE WHEN SCHEMA_ID(N'dfe_ext') IS NULL THEN 0 ELSE 1 END), "
        "CONVERT(bit, CASE WHEN SCHEMA_ID(N'dfe_fixture') IS NULL THEN 0 ELSE 1 END), "
        "CONVERT(bit, CASE WHEN OBJECT_ID(N'dfe_ext.canonical_utf8_v1') IS NULL "
        "THEN 0 ELSE 1 END), "
        "CONVERT(bit, CASE WHEN DATABASE_PRINCIPAL_ID(N'dfe_fixture_reader') IS NULL "
        "THEN 0 ELSE 1 END), "
        "CONVERT(bit, CASE WHEN DATABASE_PRINCIPAL_ID(N'dfe_fixture_setup_writer') IS NULL "
        "THEN 0 ELSE 1 END), "
        "CONVERT(bit, CASE WHEN DATABASE_PRINCIPAL_ID(N'dfe_fixture_reader_role') IS NULL "
        "THEN 0 ELSE 1 END), "
        "CONVERT(bit, CASE WHEN DATABASE_PRINCIPAL_ID(N'dfe_fixture_setup_writer_role') "
        "IS NULL THEN 0 ELSE 1 END)",
        (),
        "inspect SQL Server 2016 database-local fixture state",
        8,
    )
    return _DatabaseObjectState(
        ownership_value=_require_optional_text(row[0], "fixture_ownership_marker"),
        helper_schema_exists=_require_boolean(row[1], "helper_schema_exists"),
        fixture_schema_exists=_require_boolean(row[2], "fixture_schema_exists"),
        helper_object_exists=_require_boolean(row[3], "helper_object_exists"),
        reader_user_exists=_require_boolean(row[4], "reader_user_exists"),
        writer_user_exists=_require_boolean(row[5], "writer_user_exists"),
        reader_role_exists=_require_boolean(row[6], "reader_role_exists"),
        writer_role_exists=_require_boolean(row[7], "writer_role_exists"),
    )


def _provision_database_objects(connection: pyodbc.Connection) -> None:
    try:
        _execute(
            connection,
            "SET XACT_ABORT ON",
            (),
            "enable atomic SQL Server 2016 database-local provisioning",
        )
        _execute(
            connection,
            "CREATE SCHEMA [dfe_ext] AUTHORIZATION [dbo]",
            (),
            "create SQL Server 2016 helper schema",
        )
        _execute(
            connection,
            "CREATE SCHEMA [dfe_fixture] AUTHORIZATION [dbo]",
            (),
            "create SQL Server 2016 fixture schema",
        )
        for index, batch in enumerate(
            _sql_batches(load_mssql_2016_canonical_utf8_helper_sql()),
            start=1,
        ):
            _execute(
                connection,
                batch,
                (),
                f"install SQL Server 2016 canonical UTF-8 helper batch {index}",
            )
        _execute(
            connection,
            "CREATE USER [dfe_fixture_reader] FOR LOGIN [dfe_fixture_reader] "
            "WITH DEFAULT_SCHEMA = [dfe_fixture]; "
            "CREATE USER [dfe_fixture_setup_writer] FOR LOGIN [dfe_fixture_setup_writer] "
            "WITH DEFAULT_SCHEMA = [dfe_fixture]; "
            "CREATE ROLE [dfe_fixture_reader_role] AUTHORIZATION [dbo]; "
            "CREATE ROLE [dfe_fixture_setup_writer_role] AUTHORIZATION [dbo]; "
            "ALTER ROLE [dfe_fixture_reader_role] ADD MEMBER [dfe_fixture_reader]; "
            "ALTER ROLE [dfe_fixture_setup_writer_role] ADD MEMBER [dfe_fixture_setup_writer]; "
            "GRANT CONNECT TO [dfe_fixture_reader]; "
            "GRANT CONNECT TO [dfe_fixture_setup_writer]; "
            "GRANT VIEW DEFINITION TO [dfe_fixture_reader_role]; "
            "GRANT SELECT ON SCHEMA::[dfe_fixture] TO [dfe_fixture_reader_role]; "
            "GRANT EXECUTE ON OBJECT::[dfe_ext].[canonical_utf8_v1] "
            "TO [dfe_fixture_reader_role]; "
            "GRANT VIEW DEFINITION ON OBJECT::[dfe_ext].[canonical_utf8_v1] "
            "TO [dfe_fixture_reader_role]; "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::[dfe_fixture] "
            "TO [dfe_fixture_setup_writer_role]; "
            "DENY INSERT, UPDATE, DELETE ON SCHEMA::[dfe_fixture] "
            "TO [dfe_fixture_reader_role]; "
            "DENY CREATE TABLE, CREATE VIEW, CREATE PROCEDURE, CREATE FUNCTION "
            "TO [dfe_fixture_reader]",
            (),
            "create SQL Server 2016 fixture principals and permissions",
        )
        _validate_database_fixture(connection)
        _commit_database_provisioning(connection)
    except RuntimeError as error:
        try:
            connection.rollback()
        except pyodbc.Error as rollback_error:
            raise RuntimeError(
                "SQL Server 2016 database-local provisioning failed and rollback could not "
                f"be confirmed: rollback_error={rollback_error}. Re-run setup to validate "
                "the exact owned state before taking any cleanup action."
            ) from error
        raise RuntimeError(
            "SQL Server 2016 database-local provisioning failed; rollback was requested. "
            "Re-run setup to resume only from the exact empty owned state."
        ) from error


def _commit_database_provisioning(connection: pyodbc.Connection) -> None:
    try:
        connection.commit()
    except pyodbc.Error as error:
        raise RuntimeError(
            f"commit SQL Server 2016 database-local provisioning failed: error={error}"
        ) from error


def _validate_master_fixture(connection: pyodbc.Connection) -> None:
    database = _fetch_one(
        connection,
        "SELECT [compatibility_level], [snapshot_isolation_state], "
        "[snapshot_isolation_state_desc], [is_read_committed_snapshot_on], "
        "[is_read_only], [state_desc], [user_access_desc], SUSER_SNAME([owner_sid]) "
        "FROM sys.databases WHERE [name] = N'dfe_fixture'",
        (),
        "validate SQL Server 2016 fixture database profile",
        8,
    )
    expected_database = (130, 1, "ON", False, False, "ONLINE", "MULTI_USER", "sa")
    actual_database = (
        _require_integer(database[0], "compatibility_level"),
        _require_integer(database[1], "snapshot_isolation_state"),
        _require_text(database[2], "snapshot_isolation_state_description"),
        _require_boolean(database[3], "read_committed_snapshot"),
        _require_boolean(database[4], "database_read_only"),
        _require_text(database[5], "database_state"),
        _require_text(database[6], "database_user_access"),
        _require_text(database[7], "database_owner"),
    )
    if actual_database != expected_database:
        raise RuntimeError(
            "existing dfe_fixture database does not match the SQL Server 2016 fixture "
            f"contract: actual={actual_database!r}, required={expected_database!r}"
        )
    rows = _fetch_all(
        connection,
        "SELECT [name], [type_desc], [default_database_name], [is_disabled], "
        "[is_policy_checked], [is_expiration_checked] FROM sys.sql_logins "
        "WHERE [name] IN (N'dfe_fixture_reader', N'dfe_fixture_setup_writer') "
        "ORDER BY [name]",
        (),
        "validate SQL Server 2016 fixture logins",
        6,
    )
    expected_logins = (
        (_READER_LOGIN, "SQL_LOGIN", _DATABASE, False, True, False),
        (_WRITER_LOGIN, "SQL_LOGIN", _DATABASE, False, True, False),
    )
    if rows != expected_logins:
        raise RuntimeError(
            "existing SQL Server logins do not match the fixture contract: "
            f"actual={rows!r}, required={expected_logins!r}"
        )
    _validate_server_security(connection)


def _validate_server_security(connection: pyodbc.Connection) -> None:
    memberships = _fetch_all(
        connection,
        "SELECT [role_principal].[name], [member_principal].[name] "
        "FROM sys.server_role_members AS [membership] "
        "JOIN sys.server_principals AS [role_principal] "
        "ON [role_principal].[principal_id] = [membership].[role_principal_id] "
        "JOIN sys.server_principals AS [member_principal] "
        "ON [member_principal].[principal_id] = [membership].[member_principal_id] "
        "WHERE [member_principal].[name] IN (N'dfe_fixture_reader', "
        "N'dfe_fixture_setup_writer') "
        "ORDER BY [role_principal].[name], [member_principal].[name]",
        (),
        "validate SQL Server 2016 fixture server-role membership",
        2,
    )
    if memberships:
        raise RuntimeError(
            "fixture logins have unexpected server-role memberships: "
            f"actual={memberships!r}, required=()"
        )
    permissions = _fetch_all(
        connection,
        "SELECT [grantee].[name], [permission].[class], [permission].[class_desc], "
        "[permission].[major_id], [permission].[permission_name], "
        "[permission].[state], [permission].[state_desc] "
        "FROM sys.server_permissions AS [permission] "
        "JOIN sys.server_principals AS [grantee] "
        "ON [grantee].[principal_id] = [permission].[grantee_principal_id] "
        "WHERE [grantee].[name] IN (N'dfe_fixture_reader', "
        "N'dfe_fixture_setup_writer') "
        "ORDER BY [grantee].[name], [permission].[class], [permission].[major_id], "
        "[permission].[permission_name], [permission].[state]",
        (),
        "validate SQL Server 2016 fixture server permissions",
        7,
    )
    expected_permissions = (
        (_READER_LOGIN, 100, "SERVER", 0, "CONNECT SQL", "G", "GRANT"),
        (_WRITER_LOGIN, 100, "SERVER", 0, "CONNECT SQL", "G", "GRANT"),
    )
    if permissions != expected_permissions:
        raise RuntimeError(
            "fixture login server permissions differ from the least-privilege contract: "
            f"actual={permissions!r}, required={expected_permissions!r}"
        )
    owned_principals = _fetch_all(
        connection,
        "SELECT [owned_principal].[name], [owner_principal].[name] "
        "FROM sys.server_principals AS [owned_principal] "
        "JOIN sys.server_principals AS [owner_principal] "
        "ON [owner_principal].[principal_id] = [owned_principal].[owning_principal_id] "
        "WHERE [owner_principal].[name] IN (N'dfe_fixture_reader', "
        "N'dfe_fixture_setup_writer') "
        "ORDER BY [owned_principal].[name], [owner_principal].[name]",
        (),
        "validate SQL Server 2016 fixture server-principal ownership",
        2,
    )
    if owned_principals:
        raise RuntimeError(
            "fixture logins unexpectedly own server principals: "
            f"actual={owned_principals!r}, required=()"
        )


def _validate_database_fixture(connection: pyodbc.Connection) -> None:
    database = _fetch_one(
        connection,
        "SELECT DB_NAME(), CONVERT(nvarchar(128), DATABASEPROPERTYEX(DB_NAME(), "
        "N'Collation')), [compatibility_level], [snapshot_isolation_state], "
        "[snapshot_isolation_state_desc], [is_read_committed_snapshot_on] "
        "FROM sys.databases WHERE [database_id] = DB_ID()",
        (),
        "validate active SQL Server 2016 fixture database profile",
        6,
    )
    expected_database = (_DATABASE, _EXPECTED_COLLATION, 130, 1, "ON", False)
    if database != expected_database:
        raise RuntimeError(
            "active dfe_fixture database does not match the SQL Server 2016 fixture "
            f"contract: actual={database!r}, required={expected_database!r}"
        )
    principals = _fetch_all(
        connection,
        "SELECT [name], [type], [default_schema_name], "
        "USER_NAME([owning_principal_id]), "
        "CONVERT(bit, CASE WHEN [name] IN (N'dfe_fixture_reader', "
        "N'dfe_fixture_setup_writer') AND [sid] = SUSER_SID([name]) THEN 1 "
        "WHEN [name] IN (N'dfe_fixture_reader_role', "
        "N'dfe_fixture_setup_writer_role') THEN 1 ELSE 0 END) "
        "FROM sys.database_principals WHERE [name] IN ("
        "N'dfe_fixture_reader', N'dfe_fixture_setup_writer', "
        "N'dfe_fixture_reader_role', N'dfe_fixture_setup_writer_role') ORDER BY [name]",
        (),
        "validate SQL Server 2016 database principals",
        5,
    )
    expected_principals = (
        (_READER_LOGIN, "S", "dfe_fixture", None, True),
        (_READER_ROLE, "R", None, "dbo", True),
        (_WRITER_LOGIN, "S", "dfe_fixture", None, True),
        (_WRITER_ROLE, "R", None, "dbo", True),
    )
    if principals != expected_principals:
        raise RuntimeError(
            "existing SQL Server database principals do not match the fixture contract: "
            f"actual={principals!r}, required={expected_principals!r}"
        )
    memberships = _fetch_all(
        connection,
        "SELECT [role_principal].[name], [member_principal].[name] "
        "FROM sys.database_role_members AS [membership] "
        "JOIN sys.database_principals AS [role_principal] "
        "ON [role_principal].[principal_id] = [membership].[role_principal_id] "
        "JOIN sys.database_principals AS [member_principal] "
        "ON [member_principal].[principal_id] = [membership].[member_principal_id] "
        "WHERE [role_principal].[name] IN (N'dfe_fixture_reader_role', "
        "N'dfe_fixture_setup_writer_role') OR [member_principal].[name] IN ("
        "N'dfe_fixture_reader', N'dfe_fixture_setup_writer', "
        "N'dfe_fixture_reader_role', N'dfe_fixture_setup_writer_role') "
        "ORDER BY [role_principal].[name], [member_principal].[name]",
        (),
        "validate SQL Server 2016 fixture role membership",
        2,
    )
    expected_memberships = (
        (_READER_ROLE, _READER_LOGIN),
        (_WRITER_ROLE, _WRITER_LOGIN),
    )
    if memberships != expected_memberships:
        raise RuntimeError(
            "existing SQL Server role membership does not match the fixture contract: "
            f"actual={memberships!r}, required={expected_memberships!r}"
        )
    schemas = _fetch_all(
        connection,
        "SELECT [schema_principal].[name], [owner_principal].[name] "
        "FROM sys.schemas AS [schema_principal] "
        "JOIN sys.database_principals AS [owner_principal] "
        "ON [owner_principal].[principal_id] = [schema_principal].[principal_id] "
        "WHERE [schema_principal].[name] IN (N'dfe_ext', N'dfe_fixture') "
        "OR [owner_principal].[name] IN (N'dfe_fixture_reader', "
        "N'dfe_fixture_setup_writer', N'dfe_fixture_reader_role', "
        "N'dfe_fixture_setup_writer_role') ORDER BY [schema_principal].[name]",
        (),
        "validate SQL Server 2016 fixture schemas",
        2,
    )
    if schemas != (("dfe_ext", "dbo"), ("dfe_fixture", "dbo")):
        raise RuntimeError(
            f"existing SQL Server schemas do not match the fixture contract: actual={schemas!r}"
        )
    _validate_database_permissions(connection)


def _validate_database_permissions(connection: pyodbc.Connection) -> None:
    permissions = _fetch_all(
        connection,
        "SELECT [grantee].[name], CASE "
        "WHEN [permission].[class] = 0 AND [permission].[major_id] = 0 "
        "THEN N'DATABASE' "
        "WHEN [permission].[class] = 1 AND [permission].[major_id] = "
        "OBJECT_ID(N'dfe_ext.canonical_utf8_v1', N'FN') "
        "THEN N'OBJECT::dfe_ext.canonical_utf8_v1' "
        "WHEN [permission].[class] = 3 AND [permission].[major_id] = "
        "SCHEMA_ID(N'dfe_fixture') THEN N'SCHEMA::dfe_fixture' "
        "ELSE N'UNEXPECTED:class=' + CONVERT(nvarchar(10), [permission].[class]) "
        "+ N',major_id=' + CONVERT(nvarchar(20), [permission].[major_id]) END, "
        "[permission].[minor_id], [permission].[permission_name], "
        "[permission].[state_desc] FROM sys.database_permissions AS [permission] "
        "JOIN sys.database_principals AS [grantee] "
        "ON [grantee].[principal_id] = [permission].[grantee_principal_id] "
        "WHERE [grantee].[name] IN (N'dfe_fixture_reader', "
        "N'dfe_fixture_setup_writer', N'dfe_fixture_reader_role', "
        "N'dfe_fixture_setup_writer_role') "
        "ORDER BY [grantee].[name], 2, [permission].[minor_id], "
        "[permission].[permission_name], [permission].[state_desc]",
        (),
        "validate SQL Server 2016 fixture database permissions",
        5,
    )
    expected_permissions = (
        (_READER_LOGIN, "DATABASE", 0, "CONNECT", "GRANT"),
        (_READER_LOGIN, "DATABASE", 0, "CREATE FUNCTION", "DENY"),
        (_READER_LOGIN, "DATABASE", 0, "CREATE PROCEDURE", "DENY"),
        (_READER_LOGIN, "DATABASE", 0, "CREATE TABLE", "DENY"),
        (_READER_LOGIN, "DATABASE", 0, "CREATE VIEW", "DENY"),
        (_READER_ROLE, "DATABASE", 0, "VIEW DEFINITION", "GRANT"),
        (_READER_ROLE, "OBJECT::dfe_ext.canonical_utf8_v1", 0, "EXECUTE", "GRANT"),
        (
            _READER_ROLE,
            "OBJECT::dfe_ext.canonical_utf8_v1",
            0,
            "VIEW DEFINITION",
            "GRANT",
        ),
        (_READER_ROLE, "SCHEMA::dfe_fixture", 0, "DELETE", "DENY"),
        (_READER_ROLE, "SCHEMA::dfe_fixture", 0, "INSERT", "DENY"),
        (_READER_ROLE, "SCHEMA::dfe_fixture", 0, "SELECT", "GRANT"),
        (_READER_ROLE, "SCHEMA::dfe_fixture", 0, "UPDATE", "DENY"),
        (_WRITER_LOGIN, "DATABASE", 0, "CONNECT", "GRANT"),
        (_WRITER_ROLE, "SCHEMA::dfe_fixture", 0, "DELETE", "GRANT"),
        (_WRITER_ROLE, "SCHEMA::dfe_fixture", 0, "INSERT", "GRANT"),
        (_WRITER_ROLE, "SCHEMA::dfe_fixture", 0, "SELECT", "GRANT"),
        (_WRITER_ROLE, "SCHEMA::dfe_fixture", 0, "UPDATE", "GRANT"),
    )
    if permissions != expected_permissions:
        raise RuntimeError(
            "fixture database permissions differ from the exact least-privilege contract: "
            f"actual={permissions!r}, required={expected_permissions!r}"
        )


def _validate_reader_login(settings: _SetupSettings) -> None:
    connection = _connect_reader(settings)
    try:
        _execute(
            connection,
            "SET ANSI_NULLS ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON; "
            "SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; "
            "SET NUMERIC_ROUNDABORT OFF; SET QUOTED_IDENTIFIER ON",
            (),
            "configure SQL Server 2016 reader validation session",
        )
        row = _fetch_one(
            connection,
            "SELECT ORIGINAL_LOGIN(), SUSER_SNAME(), USER_NAME(), DB_NAME(), "
            "IS_ROLEMEMBER(N'dfe_fixture_reader_role'), "
            "HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'VIEW DEFINITION'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'SELECT'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'INSERT'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'UPDATE'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'DELETE'), "
            "HAS_PERMS_BY_NAME(N'dfe_ext.canonical_utf8_v1', N'OBJECT', N'EXECUTE'), "
            "HAS_PERMS_BY_NAME(N'dfe_ext.canonical_utf8_v1', N'OBJECT', N'VIEW DEFINITION'), "
            "HAS_PERMS_BY_NAME(N'dfe_ext.canonical_utf8_v1', N'OBJECT', N'ALTER'), "
            "HAS_PERMS_BY_NAME(N'dfe_ext.canonical_utf8_v1', N'OBJECT', N'CONTROL'), "
            "DATALENGTH([module].[definition]), "
            "HASHBYTES('SHA2_256', CONVERT(varbinary(max), [module].[definition])), "
            "[module].[uses_ansi_nulls], [module].[uses_quoted_identifier], "
            "[module].[is_schema_bound], [module].[uses_database_collation], "
            "[module].[null_on_null_input], [module].[execute_as_principal_id], "
            "CONVERT(bit, OBJECTPROPERTYEX([object].[object_id], N'IsDeterministic')), "
            "CONVERT(bit, OBJECTPROPERTYEX([object].[object_id], N'IsPrecise')), "
            "CONVERT(bit, OBJECTPROPERTYEX([object].[object_id], N'IsEncrypted')), "
            "[dfe_ext].[canonical_utf8_v1](N'A|Б' + "
            "CONVERT(nvarchar(max), 0x3DD800DE) + N'e' + NCHAR(0x0301) + N'  '), "
            "[dfe_ext].[canonical_utf8_v1](CONVERT(nvarchar(max), 0x0000)), "
            "CONVERT(bit, SESSIONPROPERTY(N'ANSI_NULLS')), "
            "CONVERT(bit, SESSIONPROPERTY(N'ANSI_PADDING')), "
            "CONVERT(bit, SESSIONPROPERTY(N'ANSI_WARNINGS')), "
            "CONVERT(bit, SESSIONPROPERTY(N'ARITHABORT')), "
            "CONVERT(bit, SESSIONPROPERTY(N'CONCAT_NULL_YIELDS_NULL')), "
            "CONVERT(bit, SESSIONPROPERTY(N'NUMERIC_ROUNDABORT')), "
            "CONVERT(bit, SESSIONPROPERTY(N'QUOTED_IDENTIFIER')) "
            "FROM sys.objects AS [object] JOIN sys.sql_modules AS [module] "
            "ON [module].[object_id] = [object].[object_id] "
            "WHERE [object].[object_id] = "
            "OBJECT_ID(N'dfe_ext.canonical_utf8_v1', N'FN')",
            (),
            "validate SQL Server 2016 reader and canonical helper",
            34,
        )
        expected = (
            _READER_LOGIN,
            _READER_LOGIN,
            _READER_LOGIN,
            _DATABASE,
            1,
            1,
            1,
            0,
            0,
            0,
            1,
            1,
            0,
            0,
            MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES,
            MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256,
            True,
            True,
            True,
            True,
            True,
            None,
            True,
            True,
            False,
            bytes.fromhex("417cd091f09f988065cc812020"),
            None,
            True,
            True,
            True,
            True,
            True,
            False,
            True,
        )
        if row != expected:
            raise RuntimeError(
                "SQL Server 2016 reader/helper validation differs from the fixture contract: "
                f"actual={row!r}, required={expected!r}"
            )
    finally:
        connection.close()


def _validate_writer_login(settings: _SetupSettings) -> None:
    connection = _connect_writer(settings)
    try:
        row = _fetch_one(
            connection,
            "SELECT ORIGINAL_LOGIN(), SUSER_SNAME(), USER_NAME(), DB_NAME(), "
            "IS_ROLEMEMBER(N'dfe_fixture_setup_writer_role'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'SELECT'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'INSERT'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'UPDATE'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'DELETE'), "
            "HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'CREATE TABLE'), "
            "HAS_PERMS_BY_NAME(N'dfe_fixture', N'SCHEMA', N'ALTER')",
            (),
            "validate SQL Server 2016 setup-writer permissions",
            11,
        )
        expected = (
            _WRITER_LOGIN,
            _WRITER_LOGIN,
            _WRITER_LOGIN,
            _DATABASE,
            1,
            1,
            1,
            1,
            1,
            0,
            0,
        )
        if row != expected:
            raise RuntimeError(
                "SQL Server 2016 setup-writer validation differs from the fixture contract: "
                f"actual={row!r}, required={expected!r}"
            )
    finally:
        connection.close()


def _sql_batches(sql_text: str) -> tuple[str, ...]:
    batches: list[str] = []
    current: list[str] = []
    for line in sql_text.splitlines(keepends=True):
        if line.rstrip("\r\n").strip().upper() == "GO":
            batch = "".join(current).strip()
            if batch:
                batches.append(batch)
            current = []
        else:
            current.append(line)
    batch = "".join(current).strip()
    if batch:
        batches.append(batch)
    return tuple(batches)


def _unicode_literal(value: str) -> str:
    return "N'" + value.replace("'", "''") + "'"


def _execute(
    connection: pyodbc.Connection,
    statement: str,
    parameters: tuple[object, ...],
    operation: str,
) -> None:
    try:
        connection.execute(statement, *parameters).close()
    except pyodbc.Error as error:
        raise RuntimeError(f"{operation} failed: error={error}") from error


def _fetch_one(
    connection: pyodbc.Connection,
    statement: str,
    parameters: tuple[object, ...],
    operation: str,
    expected_fields: int,
) -> tuple[object, ...]:
    try:
        row = connection.execute(statement, *parameters).fetchone()
    except pyodbc.Error as error:
        raise RuntimeError(f"{operation} failed: error={error}") from error
    if row is None:
        raise RuntimeError(f"{operation} returned no row")
    values = tuple(row)
    if len(values) != expected_fields:
        raise RuntimeError(
            f"{operation} returned an unexpected field count: "
            f"expected={expected_fields}, actual={len(values)}"
        )
    return values


def _fetch_all(
    connection: pyodbc.Connection,
    statement: str,
    parameters: tuple[object, ...],
    operation: str,
    expected_fields: int,
) -> tuple[tuple[object, ...], ...]:
    try:
        rows = connection.execute(statement, *parameters).fetchall()
    except pyodbc.Error as error:
        raise RuntimeError(f"{operation} failed: error={error}") from error
    values = tuple(tuple(row) for row in rows)
    for index, row in enumerate(values):
        if len(row) != expected_fields:
            raise RuntimeError(
                f"{operation} returned an unexpected field count: "
                f"row_index={index}, expected={expected_fields}, actual={len(row)}"
            )
    return values


def _require_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        raise RuntimeError(
            f"SQL Server 2016 setup expected non-empty text for {field_name}: "
            f"actual_type={type(value).__name__}"
        )
    return value


def _require_optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field_name)


def _require_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise RuntimeError(
            f"SQL Server 2016 setup expected an integer for {field_name}: "
            f"actual_type={type(value).__name__}"
        )
    return value


def _require_boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise RuntimeError(
            f"SQL Server 2016 setup expected a boolean for {field_name}: "
            f"actual_type={type(value).__name__}"
        )
    return value


if __name__ == "__main__":
    main()
