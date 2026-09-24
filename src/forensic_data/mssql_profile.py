from enum import StrEnum

MSSQL_2022_DRIVER = "pyodbc"
MSSQL_2022_PROFILE = "mssql_2022"
MSSQL_2016_DRIVER = "pyodbc"
MSSQL_2016_PROFILE = "mssql_2016"


class MssqlRuntimeProfile(StrEnum):
    MSSQL_2016 = MSSQL_2016_PROFILE
    MSSQL_2022 = MSSQL_2022_PROFILE


def match_mssql_runtime_profile(
    driver: str,
    profile: str,
) -> MssqlRuntimeProfile | None:
    if (driver, profile) == (MSSQL_2022_DRIVER, MSSQL_2022_PROFILE):
        return MssqlRuntimeProfile.MSSQL_2022
    if (driver, profile) == (MSSQL_2016_DRIVER, MSSQL_2016_PROFILE):
        return MssqlRuntimeProfile.MSSQL_2016
    return None
