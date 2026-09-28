from enum import StrEnum

ORACLE_THIN_DRIVER = "oracledb"
ORACLE_THIN_3_4_PROFILE = "oracle_thin_3_4"


class OracleRuntimeProfile(StrEnum):
    THIN_3_4 = ORACLE_THIN_3_4_PROFILE


def match_oracle_runtime_profile(
    driver: str,
    profile: str,
) -> OracleRuntimeProfile | None:
    if (driver, profile) == (ORACLE_THIN_DRIVER, ORACLE_THIN_3_4_PROFILE):
        return OracleRuntimeProfile.THIN_3_4
    return None
