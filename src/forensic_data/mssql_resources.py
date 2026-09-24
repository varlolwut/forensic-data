import hashlib
from importlib.resources import files
from typing import Final

MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES: Final[int] = 4_934
MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256: Final[bytes] = bytes.fromhex(
    "ff2cf373a0c4701086de184212993ba2c07f196b47981d0d741980bc12338d1b"
)
MSSQL_2016_CANONICAL_UTF8_HELPER_SCRIPT_UTF8_BYTES: Final[int] = 2_520
MSSQL_2016_CANONICAL_UTF8_HELPER_SCRIPT_SHA256: Final[bytes] = bytes.fromhex(
    "d25668f6901529d41839dcdd58d01384c27f0726f4c1f3ea613107281436504c"
)

_HELPER_RESOURCE: Final[str] = "sql/mssql_2016/canonical_utf8_v1.sql"
_CREATE_PREFIX: Final[str] = "CREATE FUNCTION [dfe_ext].[canonical_utf8_v1]"
_FINAL_BATCH_SEPARATOR: Final[str] = "\nGO\n"


def load_mssql_2016_canonical_utf8_helper_sql() -> str:
    resource = files("forensic_data")
    for component in _HELPER_RESOURCE.split("/"):
        resource = resource.joinpath(component)
    try:
        sql_bytes = resource.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError) as error:
        raise RuntimeError(
            "packaged SQL Server 2016 canonical UTF-8 helper SQL is unavailable: "
            f"resource={_HELPER_RESOURCE!r}, error_type={type(error).__name__}"
        ) from error
    script_sha256 = hashlib.sha256(sql_bytes).digest()
    if (
        len(sql_bytes) != MSSQL_2016_CANONICAL_UTF8_HELPER_SCRIPT_UTF8_BYTES
        or script_sha256 != MSSQL_2016_CANONICAL_UTF8_HELPER_SCRIPT_SHA256
    ):
        raise RuntimeError(
            "packaged SQL Server 2016 canonical UTF-8 helper script differs from its "
            "provisioning identity: "
            f"resource={_HELPER_RESOURCE!r}, utf8_bytes={len(sql_bytes)}, "
            f"sha256={script_sha256.hex()}, "
            "required_utf8_bytes="
            f"{MSSQL_2016_CANONICAL_UTF8_HELPER_SCRIPT_UTF8_BYTES}, "
            "required_sha256="
            f"{MSSQL_2016_CANONICAL_UTF8_HELPER_SCRIPT_SHA256.hex()}"
        )
    if not sql_bytes or b"\r" in sql_bytes or not sql_bytes.endswith(b"\n"):
        raise RuntimeError(
            "packaged SQL Server 2016 canonical UTF-8 helper SQL must be non-empty, "
            "LF-normalized, and end with a newline: "
            f"resource={_HELPER_RESOURCE!r}"
        )
    try:
        sql_text = sql_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError(
            "packaged SQL Server 2016 canonical UTF-8 helper SQL must be strict UTF-8: "
            f"resource={_HELPER_RESOURCE!r}"
        ) from error
    definition = _helper_definition(sql_text)
    definition_bytes = definition.encode("utf-16-le", errors="strict")
    definition_sha256 = hashlib.sha256(definition_bytes).digest()
    if (
        len(definition_bytes) != MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES
        or definition_sha256 != MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256
    ):
        raise RuntimeError(
            "packaged SQL Server 2016 canonical UTF-8 helper definition differs from its "
            "admission identity: "
            f"resource={_HELPER_RESOURCE!r}, utf16_bytes={len(definition_bytes)}, "
            f"sha256={definition_sha256.hex()}, "
            "required_utf16_bytes="
            f"{MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_UTF16_BYTES}, "
            "required_sha256="
            f"{MSSQL_2016_CANONICAL_UTF8_HELPER_DEFINITION_SHA256.hex()}"
        )
    return sql_text


def _helper_definition(sql_text: str) -> str:
    if sql_text.count(_CREATE_PREFIX) != 1 or not sql_text.endswith(_FINAL_BATCH_SEPARATOR):
        raise RuntimeError(
            "packaged SQL Server 2016 canonical UTF-8 helper SQL has an unexpected batch "
            f"layout: resource={_HELPER_RESOURCE!r}"
        )
    definition_start = sql_text.index(_CREATE_PREFIX)
    definition = sql_text[definition_start : -len(_FINAL_BATCH_SEPARATOR)]
    if not definition.endswith("\nEND;"):
        raise RuntimeError(
            "packaged SQL Server 2016 canonical UTF-8 helper definition has an unexpected "
            f"terminator: resource={_HELPER_RESOURCE!r}"
        )
    return definition
