import hashlib
from importlib.resources import files
from typing import Final

from forensic_data.persistence.model import Migration

_BOOTSTRAP_RESOURCE: Final[str] = "sql/bootstrap.sql"
_MIGRATION_RESOURCES: Final[tuple[tuple[int, str], ...]] = (
    (1, "0001_initial.sql"),
    (2, "0002_run_lifecycle.sql"),
    (3, "0003_completed_comparisons.sql"),
)


def load_postgres_metadata_bootstrap_sql() -> str:
    bootstrap_bytes = _read_package_resource(_BOOTSTRAP_RESOURCE)
    return _strict_sql_text(bootstrap_bytes, "metadata bootstrap")


def load_postgres_metadata_migrations() -> tuple[Migration, ...]:
    migrations = tuple(
        _load_migration(version, resource_name) for version, resource_name in _MIGRATION_RESOURCES
    )
    expected_versions = tuple(range(1, len(migrations) + 1))
    actual_versions = tuple(migration.version for migration in migrations)
    if actual_versions != expected_versions:
        raise RuntimeError(
            "packaged metadata migration versions must be contiguous from 1: "
            f"expected={expected_versions!r}, actual={actual_versions!r}"
        )
    return migrations


def _load_migration(version: int, resource_name: str) -> Migration:
    resource_path = f"sql/migrations/{resource_name}"
    sql_bytes = _read_package_resource(resource_path)
    _strict_sql_text(sql_bytes, f"metadata migration {version}")
    return Migration(
        version=version,
        name=resource_name,
        checksum_sha256=hashlib.sha256(sql_bytes).hexdigest(),
        sql_bytes=sql_bytes,
    )


def _read_package_resource(resource_path: str) -> bytes:
    components = resource_path.split("/")
    resource = files("forensic_data.persistence")
    for component in components:
        resource = resource.joinpath(component)
    try:
        value = resource.read_bytes()
    except (FileNotFoundError, OSError) as error:
        raise RuntimeError(
            "packaged metadata SQL resource is unavailable: "
            f"resource={resource_path!r}, error_type={type(error).__name__}"
        ) from None
    if not value:
        raise RuntimeError(
            f"packaged metadata SQL resource must not be empty: resource={resource_path!r}"
        )
    return value


def _strict_sql_text(sql_bytes: bytes, context: str) -> str:
    if b"\r" in sql_bytes or not sql_bytes.endswith(b"\n"):
        raise RuntimeError(f"{context} must use LF line endings and end with a newline")
    try:
        sql_text = sql_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{context} must be strict UTF-8: byte_offset={error.start}") from None
    if sql_text.strip() == "":
        raise RuntimeError(f"{context} must contain at least one SQL statement")
    return sql_text
