from dataclasses import dataclass
from typing import final

from forensic_data.clickhouse import (
    ClickHouseTransportLimits,
    required_clickhouse_ipc_message_bytes,
)
from forensic_data.clickhouse_canonical import ClickHouseCanonicalLimits
from forensic_data.clickhouse_readiness import ClickHouseReadinessLimits
from forensic_data.contracts.model import ExecutionBudgets


@final
@dataclass(frozen=True, slots=True)
class ClickHouseExecutionLimits:
    transport: ClickHouseTransportLimits
    readiness: ClickHouseReadinessLimits
    canonical: ClickHouseCanonicalLimits


def build_clickhouse_execution_limits(budgets: ExecutionBudgets) -> ClickHouseExecutionLimits:
    if type(budgets) is not ExecutionBudgets:
        raise TypeError("ClickHouse execution limits require ExecutionBudgets")
    statement_timeout = budgets.statement_timeout_milliseconds
    cancellation_reserve = max(1, min(5_000, statement_timeout // 4))
    response_bytes = min(
        budgets.max_application_result_bytes,
        budgets.max_coordinator_memory_bytes,
    )
    execution_time_seconds = max(1, (statement_timeout + 999) // 1_000)
    return ClickHouseExecutionLimits(
        transport=ClickHouseTransportLimits(
            max_initialization_response_bytes=4_096,
            max_error_response_bytes=16_384,
            max_cancellation_response_bytes=131_072,
            max_query_bytes=65_536,
            max_ipc_message_bytes=max(
                262_144,
                required_clickhouse_ipc_message_bytes(response_bytes),
            ),
            cancellation_reserve_milliseconds=cancellation_reserve,
            process_cleanup_timeout_milliseconds=1_000,
        ),
        readiness=ClickHouseReadinessLimits(
            max_response_bytes=response_bytes,
            max_execution_time_seconds=execution_time_seconds,
        ),
        canonical=ClickHouseCanonicalLimits(
            max_encoded_envelope_bytes=response_bytes,
            max_response_bytes=response_bytes,
            max_execution_time_seconds=execution_time_seconds,
        ),
    )
