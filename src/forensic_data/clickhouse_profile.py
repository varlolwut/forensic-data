from enum import StrEnum

CLICKHOUSE_CONNECT_DRIVER = "clickhouse-connect"
CLICKHOUSE_LTS_PROFILE = "clickhouse_lts"


class ClickHouseRuntimeProfile(StrEnum):
    LTS = CLICKHOUSE_LTS_PROFILE


def match_clickhouse_runtime_profile(
    driver: str,
    profile: str,
) -> ClickHouseRuntimeProfile | None:
    if (driver, profile) == (CLICKHOUSE_CONNECT_DRIVER, CLICKHOUSE_LTS_PROFILE):
        return ClickHouseRuntimeProfile.LTS
    return None
