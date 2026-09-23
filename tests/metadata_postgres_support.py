import re
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import uuid4

from psycopg import sql

from forensic_data.persistence.migrations import load_postgres_metadata_bootstrap_sql
from forensic_data.postgres import PostgresConnectionSettings
from tests.postgres_support import connect_writer, required_connection_settings

_DATABASE_NAME_PATTERN = re.compile(r"\Adfe_metadata_test_[0-9a-f]{32}\Z")
_MIGRATOR_ROLE = "dfe_metadata_migrator"
_WRITER_ROLE = "dfe_metadata_writer"
_READER_ROLE = "dfe_metadata_reader"


@dataclass(frozen=True, slots=True)
class MetadataDatabaseSettings:
    database_name: str
    admin: PostgresConnectionSettings
    migrator: PostgresConnectionSettings
    writer: PostgresConnectionSettings
    reader: PostgresConnectionSettings


def required_metadata_database_settings() -> MetadataDatabaseSettings:
    admin = required_connection_settings(
        "DFE_TEST_POSTGRES_ADMIN_DSN",
        "forensic-data-metadata-test-admin",
    )
    migrator = required_connection_settings(
        "DFE_TEST_POSTGRES_METADATA_MIGRATOR_DSN",
        "forensic-data-metadata-test-migrator",
    )
    writer = required_connection_settings(
        "DFE_TEST_POSTGRES_METADATA_WRITER_DSN",
        "forensic-data-metadata-test-writer",
    )
    reader = required_connection_settings(
        "DFE_TEST_POSTGRES_METADATA_READER_DSN",
        "forensic-data-metadata-test-reader",
    )
    database_name = f"dfe_metadata_test_{uuid4().hex}"
    return MetadataDatabaseSettings(
        database_name=database_name,
        admin=_for_database(admin, database_name),
        migrator=_for_database(migrator, database_name),
        writer=_for_database(writer, database_name),
        reader=_for_database(reader, database_name),
    )


@contextmanager
def disposable_metadata_database(
    settings: MetadataDatabaseSettings,
) -> Generator[MetadataDatabaseSettings, None, None]:
    _require_database_name(settings.database_name)
    cluster_admin = required_connection_settings(
        "DFE_TEST_POSTGRES_ADMIN_DSN",
        "forensic-data-metadata-test-admin-cluster",
    )
    created = False
    try:
        with connect_writer(cluster_admin) as connection:
            connection.execute(
                sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'UTF8'").format(
                    sql.Identifier(settings.database_name),
                    sql.Identifier(_MIGRATOR_ROLE),
                )
            )
            created = True
            connection.execute(
                sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
                    sql.Identifier(settings.database_name)
                )
            )
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}, {}, {}").format(
                    sql.Identifier(settings.database_name),
                    sql.Identifier(_MIGRATOR_ROLE),
                    sql.Identifier(_WRITER_ROLE),
                    sql.Identifier(_READER_ROLE),
                )
            )
        apply_metadata_bootstrap(settings.admin)
        yield settings
    finally:
        if created:
            with connect_writer(cluster_admin) as connection:
                connection.execute(
                    sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                        sql.Identifier(settings.database_name)
                    )
                )


def apply_metadata_bootstrap(settings: PostgresConnectionSettings) -> None:
    with connect_writer(settings) as connection:
        connection.execute(load_postgres_metadata_bootstrap_sql().encode("utf-8"))


def _for_database(
    settings: PostgresConnectionSettings,
    database_name: str,
) -> PostgresConnectionSettings:
    return PostgresConnectionSettings(
        host=settings.host,
        port=settings.port,
        dbname=database_name,
        user=settings.user,
        password=settings.password,
        sslmode=settings.sslmode,
        connect_timeout_seconds=settings.connect_timeout_seconds,
        statement_timeout_milliseconds=settings.statement_timeout_milliseconds,
        application_name=settings.application_name,
    )


def _require_database_name(database_name: str) -> None:
    if _DATABASE_NAME_PATTERN.fullmatch(database_name) is None:
        raise ValueError(
            "metadata test database name must use the generated dfe_metadata_test UUID form"
        )
