from enum import StrEnum

ORIGINAL_GREENPLUM_DRIVER = "psycopg2"
ORIGINAL_GREENPLUM_PROFILE = "original_greenplum"
GREENGAGE_DRIVER = "psycopg"
GREENGAGE_PROFILE = "greengage"


class GreenplumRuntimeProfile(StrEnum):
    ORIGINAL_GREENPLUM = ORIGINAL_GREENPLUM_PROFILE
    GREENGAGE = GREENGAGE_PROFILE


def match_greenplum_runtime_profile(
    driver: str,
    profile: str,
) -> GreenplumRuntimeProfile | None:
    if (driver, profile) == (ORIGINAL_GREENPLUM_DRIVER, ORIGINAL_GREENPLUM_PROFILE):
        return GreenplumRuntimeProfile.ORIGINAL_GREENPLUM
    if (driver, profile) == (GREENGAGE_DRIVER, GREENGAGE_PROFILE):
        return GreenplumRuntimeProfile.GREENGAGE
    return None
