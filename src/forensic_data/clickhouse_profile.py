from enum import StrEnum

CLICKHOUSE_CONNECT_DRIVER = "clickhouse-connect"
CLICKHOUSE_LTS_PROFILE = "clickhouse_lts"
CLICKHOUSE_21_8_LTS_SOURCE_PROFILE = "clickhouse_21_8_lts"


class ClickHouseRuntimeProfile(StrEnum):
    LTS = CLICKHOUSE_LTS_PROFILE
    LEGACY_21_8_LTS_SOURCE = CLICKHOUSE_21_8_LTS_SOURCE_PROFILE


def match_clickhouse_runtime_profile(
    driver: str,
    profile: str,
) -> ClickHouseRuntimeProfile | None:
    if (driver, profile) == (CLICKHOUSE_CONNECT_DRIVER, CLICKHOUSE_LTS_PROFILE):
        return ClickHouseRuntimeProfile.LTS
    if (driver, profile) == (
        CLICKHOUSE_CONNECT_DRIVER,
        CLICKHOUSE_21_8_LTS_SOURCE_PROFILE,
    ):
        return ClickHouseRuntimeProfile.LEGACY_21_8_LTS_SOURCE
    return None
