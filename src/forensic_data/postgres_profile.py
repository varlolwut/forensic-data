from enum import StrEnum

POSTGRES_17_DRIVER = "psycopg"
POSTGRES_17_PROFILE = "postgresql_17"
POSTGRES_9_6_DRIVER = "psycopg2"
POSTGRES_9_6_PROFILE = "postgresql_9_6"


class PostgresRuntimeProfile(StrEnum):
    POSTGRES_17 = POSTGRES_17_PROFILE
    POSTGRES_9_6 = POSTGRES_9_6_PROFILE


def match_postgres_runtime_profile(
    driver: str,
    profile: str,
) -> PostgresRuntimeProfile | None:
    if (driver, profile) == (POSTGRES_17_DRIVER, POSTGRES_17_PROFILE):
        return PostgresRuntimeProfile.POSTGRES_17
    if (driver, profile) == (POSTGRES_9_6_DRIVER, POSTGRES_9_6_PROFILE):
        return PostgresRuntimeProfile.POSTGRES_9_6
    return None
