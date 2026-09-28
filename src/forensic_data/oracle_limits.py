from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from sys import getsizeof
from typing import cast, final

from forensic_data.contracts.model import ExecutionBudgets
from forensic_data.coordinator_memory import (
    BYTES_HEADER_BYTES,
    list_storage_bytes,
    tuple_storage_bytes,
)

MAX_ORACLE_QUERY_BYTES = 65_536
MAX_ORACLE_BIND_VALUE_BYTES = 2_000
MAX_ORACLE_BIND_TOTAL_BYTES = 65_536
MAX_ORACLE_BIND_PARAMETERS = 256
MAX_ORACLE_BIND_OCCURRENCES = 256
MAX_ORACLE_RESULT_COLUMNS = 256
MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS = (1 << 32) - 1
MAX_ORACLE_SQL_RAW_BYTES = 2_000
MAX_ORACLE_SQL_VARCHAR2_BYTES = 4_000
MAX_ORACLE_DECIMAL_OBJECT_BYTES = getsizeof(Decimal("9" * 38))
MAX_ORACLE_DECIMAL_INSPECTION_DIGITS = 76
if (
    getsizeof(Decimal("9" * MAX_ORACLE_DECIMAL_INSPECTION_DIGITS)) > MAX_ORACLE_DECIMAL_OBJECT_BYTES
    or getsizeof(Decimal("9" * (MAX_ORACLE_DECIMAL_INSPECTION_DIGITS + 1)))
    <= MAX_ORACLE_DECIMAL_OBJECT_BYTES
):
    raise RuntimeError("Python Decimal allocation profile differs from the audited boundary")
ORACLE_DECIMAL_TUPLE_SCRATCH_BYTES = (
    getsizeof(Decimal("9" * MAX_ORACLE_DECIMAL_INSPECTION_DIGITS).as_tuple())
    + tuple_storage_bytes(MAX_ORACLE_DECIMAL_INSPECTION_DIGITS)
    + getsizeof(-130)
)
ORACLE_THIN_BASELINE_RETAINED_BYTES = 65_536 + 8 * 16

_MAX_ORACLE_FETCH_BATCH_RECORDS = 64
_MAX_ORACLE_REQUEST_BYTES = MAX_ORACLE_QUERY_BYTES + MAX_ORACLE_BIND_TOTAL_BYTES
_MAX_ORACLE_CANONICAL_ENVELOPE_BYTES = 2_000
_MAX_ORACLE_CANCELLATION_RESERVE_MILLISECONDS = 5_000
_MIN_ORACLE_COORDINATOR_BYTES = 1_048_576
_MAX_UNICODE_TEXT_BASE_BYTES = getsizeof("\U0010ffff")
_ORACLE_DRIVER_COLUMN_RESERVATION_BYTES = 4_096
_ORACLE_RESULT_RESERVATION_BYTES = 2_048
_ORACLE_THIN_CHUNK_BYTES = 65_536
_ORACLE_THIN_LONG_LENGTH_THRESHOLD_BYTES = 252
_ORACLE_THIN_CHUNK_DESCRIPTOR_BYTES = 16
_ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK = 8


class OracleProjectionKind(StrEnum):
    ASCII = "ascii"
    TEXT = "text"
    RAW = "raw"
    DECIMAL = "decimal"


@final
@dataclass(frozen=True, slots=True)
class OracleTransportLimits:
    max_query_bytes: int
    max_bind_value_bytes: int
    max_bind_total_bytes: int
    max_bind_parameters: int
    max_bind_occurrences: int
    max_request_bytes: int
    max_response_bytes: int
    max_coordinator_bytes: int
    max_fetch_batch_records: int
    max_result_columns: int
    max_sql_raw_bytes: int
    max_sql_varchar2_bytes: int
    max_encoded_envelope_bytes: int
    cancellation_reserve_milliseconds: int
    cleanup_timeout_milliseconds: int

    def __post_init__(self) -> None:
        for name, value in (
            ("max_query_bytes", self.max_query_bytes),
            ("max_bind_value_bytes", self.max_bind_value_bytes),
            ("max_bind_total_bytes", self.max_bind_total_bytes),
            ("max_bind_parameters", self.max_bind_parameters),
            ("max_bind_occurrences", self.max_bind_occurrences),
            ("max_request_bytes", self.max_request_bytes),
            ("max_response_bytes", self.max_response_bytes),
            ("max_coordinator_bytes", self.max_coordinator_bytes),
            ("max_fetch_batch_records", self.max_fetch_batch_records),
            ("max_result_columns", self.max_result_columns),
            ("max_sql_raw_bytes", self.max_sql_raw_bytes),
            ("max_sql_varchar2_bytes", self.max_sql_varchar2_bytes),
            ("max_encoded_envelope_bytes", self.max_encoded_envelope_bytes),
            ("cancellation_reserve_milliseconds", self.cancellation_reserve_milliseconds),
            ("cleanup_timeout_milliseconds", self.cleanup_timeout_milliseconds),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"Oracle {name} must be a positive integer")
        if self.max_bind_value_bytes > self.max_bind_total_bytes:
            raise ValueError("Oracle bind value limit cannot exceed the bind total limit")
        if self.max_query_bytes > self.max_request_bytes:
            raise ValueError("Oracle query limit cannot exceed the request limit")
        if self.max_bind_total_bytes > self.max_request_bytes:
            raise ValueError("Oracle bind total limit cannot exceed the request limit")
        if self.max_encoded_envelope_bytes > self.max_response_bytes:
            raise ValueError("Oracle envelope limit cannot exceed the response limit")
        if self.max_sql_raw_bytes > MAX_ORACLE_SQL_RAW_BYTES:
            raise ValueError("Oracle SQL RAW limit exceeds the supported standard profile")
        if self.max_sql_varchar2_bytes > MAX_ORACLE_SQL_VARCHAR2_BYTES:
            raise ValueError("Oracle SQL VARCHAR2 limit exceeds the supported standard profile")
        if self.max_encoded_envelope_bytes > self.max_sql_raw_bytes:
            raise ValueError("Oracle envelope limit cannot exceed the SQL RAW limit")
        if self.max_encoded_envelope_bytes > self.max_sql_varchar2_bytes:
            raise ValueError("Oracle envelope limit cannot exceed the SQL VARCHAR2 limit")
        if self.cleanup_timeout_milliseconds > self.cancellation_reserve_milliseconds:
            raise ValueError("Oracle cleanup timeout cannot exceed the cancellation reserve")
        if self.cancellation_reserve_milliseconds > MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS:
            raise ValueError("Oracle cancellation reserve exceeds python-oracledb call_timeout")
        if self.cleanup_timeout_milliseconds > MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS:
            raise ValueError("Oracle cleanup timeout exceeds python-oracledb call_timeout")


@final
@dataclass(frozen=True, slots=True)
class OracleFetchLimits:
    fetch_batch_records: int
    max_records: int
    max_received_records: int
    max_value_bytes: int
    max_record_bytes: int
    max_received_record_bytes: int
    max_total_bytes: int
    max_received_bytes: int
    coordinator_response_bytes: int
    local_completion_bytes: int
    prior_thin_chunk_buffer_bytes: int
    retained_thin_chunk_buffer_bytes: int
    projection_kinds: tuple[OracleProjectionKind, ...]
    projection_max_bytes: tuple[int, ...]
    projection_driver_max_bytes: tuple[int, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("fetch_batch_records", self.fetch_batch_records),
            ("max_records", self.max_records),
            ("max_received_records", self.max_received_records),
            ("max_value_bytes", self.max_value_bytes),
            ("max_record_bytes", self.max_record_bytes),
            ("max_received_record_bytes", self.max_received_record_bytes),
            ("max_total_bytes", self.max_total_bytes),
            ("max_received_bytes", self.max_received_bytes),
            ("coordinator_response_bytes", self.coordinator_response_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"Oracle {name} must be a positive integer")
        if type(self.local_completion_bytes) is not int or self.local_completion_bytes < 0:
            raise ValueError("Oracle local_completion_bytes must be a non-negative integer")
        for name, value in (
            ("prior_thin_chunk_buffer_bytes", self.prior_thin_chunk_buffer_bytes),
            ("retained_thin_chunk_buffer_bytes", self.retained_thin_chunk_buffer_bytes),
        ):
            if type(value) is not int or value < ORACLE_THIN_BASELINE_RETAINED_BYTES:
                raise ValueError(
                    f"Oracle {name} must cover the Thin connection baseline: "
                    f"minimum={ORACLE_THIN_BASELINE_RETAINED_BYTES}"
                )
        if type(self.projection_max_bytes) is not tuple or not self.projection_max_bytes:
            raise ValueError("Oracle projection byte limits must be a non-empty tuple")
        if type(self.projection_kinds) is not tuple or not self.projection_kinds:
            raise ValueError("Oracle projection kinds must be a non-empty tuple")
        if len(self.projection_kinds) != len(self.projection_max_bytes):
            raise ValueError("Oracle projection kinds and byte limits must have equal length")
        if type(self.projection_driver_max_bytes) is not tuple or len(
            self.projection_driver_max_bytes
        ) != len(self.projection_max_bytes):
            raise ValueError(
                "Oracle projection driver byte limits must match the logical projection limits"
            )
        for kind in self.projection_kinds:
            if type(cast(object, kind)) is not OracleProjectionKind:
                raise TypeError("Oracle projection kinds must be OracleProjectionKind values")
        for value in self.projection_max_bytes:
            if type(value) is not int or value < 1:
                raise ValueError("Oracle projection byte limits must be positive integers")
        for logical_bytes, driver_bytes in zip(
            self.projection_max_bytes,
            self.projection_driver_max_bytes,
            strict=True,
        ):
            if type(driver_bytes) is not int or driver_bytes < logical_bytes:
                raise ValueError(
                    "Oracle projection driver byte limits must be integers no smaller than "
                    "their logical limits"
                )
        if self.max_value_bytes != max(self.projection_max_bytes):
            raise ValueError("Oracle max_value_bytes must equal the largest projection limit")
        if self.max_record_bytes != sum(self.projection_max_bytes):
            raise ValueError("Oracle max_record_bytes must equal all projection limits")
        if self.max_received_record_bytes != sum(self.projection_driver_max_bytes):
            raise ValueError(
                "Oracle max_received_record_bytes must equal all driver projection limits"
            )
        if self.max_received_records != self.max_records + 1:
            raise ValueError("Oracle received-record limit must include one overflow probe")
        if self.max_total_bytes != self.max_records * self.max_record_bytes:
            raise ValueError("Oracle retained byte limit must cover every admitted record")
        if self.max_received_bytes != self.max_received_records * self.max_received_record_bytes:
            raise ValueError("Oracle received byte limit must cover the overflow probe")
        if self.max_record_bytes > self.max_total_bytes:
            raise ValueError("Oracle record limit cannot exceed the total response limit")
        if self.fetch_batch_records * self.max_record_bytes > self.max_total_bytes:
            raise ValueError("Oracle response limit must admit one worst-case fetch batch")
        expected_response_bytes = _oracle_response_memory_bytes(
            self.max_records,
            self.fetch_batch_records,
            self.projection_kinds,
            self.projection_max_bytes,
            self.projection_driver_max_bytes,
            self.prior_thin_chunk_buffer_bytes,
            self.local_completion_bytes,
        )
        if self.coordinator_response_bytes != expected_response_bytes:
            raise ValueError(
                "Oracle coordinator response reservation differs from its typed projection"
            )
        expected_retained_chunk_bytes = max(
            self.prior_thin_chunk_buffer_bytes,
            _oracle_thin_retained_chunk_buffer_bytes(
                self.projection_kinds,
                self.projection_driver_max_bytes,
            ),
        )
        if self.retained_thin_chunk_buffer_bytes != expected_retained_chunk_bytes:
            raise ValueError("Oracle retained Thin chunk reservation differs from its projection")


def build_oracle_transport_limits(budgets: ExecutionBudgets) -> OracleTransportLimits:
    if type(budgets) is not ExecutionBudgets:
        raise TypeError("Oracle transport limits require ExecutionBudgets")
    effective_call_timeout = min(
        budgets.statement_timeout_milliseconds,
        budgets.run_timeout_milliseconds,
    )
    if effective_call_timeout < 2:
        raise ValueError(
            "Oracle effective statement/run timeout must be at least 2 milliseconds to "
            "reserve cleanup time: "
            f"effective_timeout_milliseconds={effective_call_timeout}"
        )
    if effective_call_timeout > MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS:
        raise ValueError(
            "Oracle effective statement timeout exceeds python-oracledb call_timeout: "
            f"effective_timeout_milliseconds={effective_call_timeout}, "
            f"maximum={MAX_ORACLE_CALL_TIMEOUT_MILLISECONDS}"
        )
    if budgets.max_coordinator_memory_bytes < _MIN_ORACLE_COORDINATOR_BYTES:
        raise ValueError(
            "Oracle coordinator memory budget is below the bounded connector minimum: "
            f"max_coordinator_memory_bytes={budgets.max_coordinator_memory_bytes}, "
            f"minimum={_MIN_ORACLE_COORDINATOR_BYTES}"
        )
    request_bytes = min(
        _MAX_ORACLE_REQUEST_BYTES,
        budgets.max_coordinator_memory_bytes // 4,
    )
    response_bytes = min(
        budgets.max_application_result_bytes,
        (budgets.max_coordinator_memory_bytes - 2 * request_bytes) // 2,
    )
    cancellation_reserve = max(
        1,
        min(
            _MAX_ORACLE_CANCELLATION_RESERVE_MILLISECONDS,
            effective_call_timeout // 4,
        ),
    )
    return OracleTransportLimits(
        max_query_bytes=min(MAX_ORACLE_QUERY_BYTES, request_bytes),
        max_bind_value_bytes=min(MAX_ORACLE_BIND_VALUE_BYTES, request_bytes),
        max_bind_total_bytes=min(MAX_ORACLE_BIND_TOTAL_BYTES, request_bytes),
        max_bind_parameters=MAX_ORACLE_BIND_PARAMETERS,
        max_bind_occurrences=MAX_ORACLE_BIND_OCCURRENCES,
        max_request_bytes=request_bytes,
        max_response_bytes=response_bytes,
        max_coordinator_bytes=budgets.max_coordinator_memory_bytes,
        max_fetch_batch_records=min(
            _MAX_ORACLE_FETCH_BATCH_RECORDS,
            budgets.max_fetched_records,
        ),
        max_result_columns=MAX_ORACLE_RESULT_COLUMNS,
        max_sql_raw_bytes=MAX_ORACLE_SQL_RAW_BYTES,
        max_sql_varchar2_bytes=MAX_ORACLE_SQL_VARCHAR2_BYTES,
        max_encoded_envelope_bytes=min(
            _MAX_ORACLE_CANONICAL_ENVELOPE_BYTES,
            MAX_ORACLE_SQL_RAW_BYTES,
            MAX_ORACLE_SQL_VARCHAR2_BYTES,
            response_bytes,
        ),
        cancellation_reserve_milliseconds=cancellation_reserve,
        cleanup_timeout_milliseconds=cancellation_reserve,
    )


def build_oracle_fetch_limits(
    transport: OracleTransportLimits,
    max_records: int,
    projection_kinds: tuple[OracleProjectionKind, ...],
    projection_max_bytes: tuple[int, ...],
    projection_driver_max_bytes: tuple[int, ...],
    prior_thin_chunk_buffer_bytes: int,
    local_completion_bytes: int,
) -> OracleFetchLimits:
    if type(transport) is not OracleTransportLimits:
        raise TypeError("Oracle fetch limits require OracleTransportLimits")
    if type(max_records) is not int or max_records < 1:
        raise ValueError("Oracle max_records must be a positive integer")
    if type(local_completion_bytes) is not int or local_completion_bytes < 0:
        raise ValueError("Oracle local completion reservation must be a non-negative integer")
    if (
        type(prior_thin_chunk_buffer_bytes) is not int
        or prior_thin_chunk_buffer_bytes < ORACLE_THIN_BASELINE_RETAINED_BYTES
    ):
        raise ValueError(
            "Oracle prior Thin chunk reservation must cover the connection baseline: "
            f"minimum={ORACLE_THIN_BASELINE_RETAINED_BYTES}"
        )
    if type(projection_max_bytes) is not tuple or not projection_max_bytes:
        raise ValueError("Oracle projection byte limits must be a non-empty tuple")
    if type(projection_kinds) is not tuple or not projection_kinds:
        raise ValueError("Oracle projection kinds must be a non-empty tuple")
    if len(projection_kinds) != len(projection_max_bytes):
        raise ValueError("Oracle projection kinds and byte limits must have equal length")
    if type(projection_driver_max_bytes) is not tuple or len(projection_driver_max_bytes) != len(
        projection_max_bytes
    ):
        raise ValueError(
            "Oracle projection driver byte limits must match the logical projection limits"
        )
    for kind in projection_kinds:
        if type(cast(object, kind)) is not OracleProjectionKind:
            raise TypeError("Oracle projection kinds must be OracleProjectionKind values")
    if len(projection_max_bytes) > transport.max_result_columns:
        raise ValueError(
            "Oracle projection count exceeds the configured result-column limit: "
            f"projection_count={len(projection_max_bytes)}, "
            f"max_result_columns={transport.max_result_columns}"
        )
    for value in projection_max_bytes:
        if type(value) is not int or value < 1:
            raise ValueError("Oracle projection byte limits must be positive integers")
    for logical_bytes, driver_bytes in zip(
        projection_max_bytes,
        projection_driver_max_bytes,
        strict=True,
    ):
        if type(driver_bytes) is not int or driver_bytes < logical_bytes:
            raise ValueError(
                "Oracle projection driver byte limits must be integers no smaller than their "
                "logical limits"
            )
    max_record_bytes = sum(projection_max_bytes)
    if max_record_bytes > transport.max_response_bytes:
        raise ValueError(
            "Oracle declared result row exceeds the response budget before dispatch: "
            f"declared_record_bytes={max_record_bytes}, "
            f"max_response_bytes={transport.max_response_bytes}"
        )
    declared_result_bytes = max_records * max_record_bytes
    if declared_result_bytes > transport.max_response_bytes:
        raise ValueError(
            "Oracle declared retained result exceeds the response budget before dispatch: "
            f"declared_result_bytes={declared_result_bytes}, "
            f"max_response_bytes={transport.max_response_bytes}"
        )
    admitted_batch_records = transport.max_response_bytes // max_record_bytes
    fetch_batch_records = min(
        transport.max_fetch_batch_records,
        max_records,
        admitted_batch_records,
    )
    coordinator_response_bytes = _oracle_response_memory_bytes(
        max_records,
        fetch_batch_records,
        projection_kinds,
        projection_max_bytes,
        projection_driver_max_bytes,
        prior_thin_chunk_buffer_bytes,
        local_completion_bytes,
    )
    if coordinator_response_bytes > transport.max_coordinator_bytes:
        raise ValueError(
            "Oracle declared result exceeds the coordinator memory budget before dispatch: "
            f"coordinator_response_bytes={coordinator_response_bytes}, "
            f"local_completion_bytes={local_completion_bytes}, "
            f"max_coordinator_bytes={transport.max_coordinator_bytes}"
        )
    return OracleFetchLimits(
        fetch_batch_records=fetch_batch_records,
        max_records=max_records,
        max_received_records=max_records + 1,
        max_value_bytes=max(projection_max_bytes),
        max_record_bytes=max_record_bytes,
        max_received_record_bytes=sum(projection_driver_max_bytes),
        max_total_bytes=declared_result_bytes,
        max_received_bytes=(max_records + 1) * sum(projection_driver_max_bytes),
        coordinator_response_bytes=coordinator_response_bytes,
        local_completion_bytes=local_completion_bytes,
        prior_thin_chunk_buffer_bytes=prior_thin_chunk_buffer_bytes,
        retained_thin_chunk_buffer_bytes=max(
            prior_thin_chunk_buffer_bytes,
            _oracle_thin_retained_chunk_buffer_bytes(
                projection_kinds,
                projection_driver_max_bytes,
            ),
        ),
        projection_kinds=projection_kinds,
        projection_max_bytes=projection_max_bytes,
        projection_driver_max_bytes=projection_driver_max_bytes,
    )


def _oracle_response_memory_bytes(
    max_records: int,
    fetch_batch_records: int,
    projection_kinds: tuple[OracleProjectionKind, ...],
    projection_max_bytes: tuple[int, ...],
    projection_driver_max_bytes: tuple[int, ...],
    prior_thin_chunk_buffer_bytes: int,
    local_completion_bytes: int,
) -> int:
    column_count = len(projection_max_bytes)
    row_tuple_bytes = tuple_storage_bytes(column_count)
    row_value_bytes = sum(
        _oracle_value_memory_bytes(kind, max_bytes)
        for kind, max_bytes in zip(projection_kinds, projection_max_bytes, strict=True)
    )
    retained_row_bytes = row_tuple_bytes + row_value_bytes
    retained_rows_bytes = (
        (2 * list_storage_bytes(max_records))
        + (max_records * retained_row_bytes)
        + tuple_storage_bytes(max_records)
    )
    raw_batch_bytes = (2 * list_storage_bytes(fetch_batch_records)) + (
        fetch_batch_records * retained_row_bytes
    )
    validated_batch_bytes = (2 * list_storage_bytes(fetch_batch_records)) + (
        fetch_batch_records * row_tuple_bytes
    )
    record_byte_size = getsizeof(sum(projection_max_bytes))
    accounting_bytes = (
        (2 * list_storage_bytes(fetch_batch_records))
        + tuple_storage_bytes(fetch_batch_records)
        + (fetch_batch_records * record_byte_size)
    )
    description_bytes = (
        (3 * tuple_storage_bytes(column_count))
        + (2 * list_storage_bytes(column_count))
        + (column_count * _ORACLE_DRIVER_COLUMN_RESERVATION_BYTES)
    )
    driver_batch_bytes = fetch_batch_records * sum(projection_driver_max_bytes)
    thin_chunk_buffer_bytes = max(
        prior_thin_chunk_buffer_bytes,
        _oracle_thin_chunk_buffer_peak_bytes(
            projection_kinds,
            projection_driver_max_bytes,
        ),
    )
    retained_thin_chunk_buffer_bytes = max(
        prior_thin_chunk_buffer_bytes,
        _oracle_thin_retained_chunk_buffer_bytes(
            projection_kinds,
            projection_driver_max_bytes,
        ),
    )
    row_assembly_bytes = 2 * list_storage_bytes(column_count)
    conversion_scratch_bytes = max(
        BYTES_HEADER_BYTES + max(projection_max_bytes),
        ORACLE_DECIMAL_TUPLE_SCRATCH_BYTES,
    )
    fetch_peak_bytes = (
        retained_rows_bytes
        + raw_batch_bytes
        + validated_batch_bytes
        + accounting_bytes
        + description_bytes
        + driver_batch_bytes
        + thin_chunk_buffer_bytes
        + row_assembly_bytes
        + conversion_scratch_bytes
        + _ORACLE_RESULT_RESERVATION_BYTES
    )
    finalization_peak_bytes = (
        list_storage_bytes(max_records)
        + tuple_storage_bytes(max_records)
        + (max_records * retained_row_bytes)
        + description_bytes
        + retained_thin_chunk_buffer_bytes
        + _ORACLE_RESULT_RESERVATION_BYTES
    )
    consumer_peak_bytes = (
        tuple_storage_bytes(max_records)
        + (max_records * retained_row_bytes)
        + retained_thin_chunk_buffer_bytes
        + _ORACLE_RESULT_RESERVATION_BYTES
        + local_completion_bytes
    )
    return max(fetch_peak_bytes, finalization_peak_bytes, consumer_peak_bytes)


def _oracle_thin_chunk_buffer_peak_bytes(
    projection_kinds: tuple[OracleProjectionKind, ...],
    projection_max_bytes: tuple[int, ...],
) -> int:
    max_long_value_bytes = _oracle_max_long_value_bytes(
        projection_kinds,
        projection_max_bytes,
    )
    if max_long_value_bytes == 0:
        return ORACLE_THIN_BASELINE_RETAINED_BYTES
    rounded_value_bytes = (
        (max_long_value_bytes + _ORACLE_THIN_CHUNK_BYTES - 1)
        // _ORACLE_THIN_CHUNK_BYTES
        * _ORACLE_THIN_CHUNK_BYTES
    )
    chunk_count = rounded_value_bytes // _ORACLE_THIN_CHUNK_BYTES
    descriptor_count = (
        (chunk_count + _ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK - 1)
        // _ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK
        * _ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK
    )
    descriptor_peak_count = descriptor_count
    if descriptor_count > _ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK:
        descriptor_peak_count += descriptor_count - _ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK
    return 2 * rounded_value_bytes + descriptor_peak_count * _ORACLE_THIN_CHUNK_DESCRIPTOR_BYTES


def _oracle_thin_retained_chunk_buffer_bytes(
    projection_kinds: tuple[OracleProjectionKind, ...],
    projection_max_bytes: tuple[int, ...],
) -> int:
    max_long_value_bytes = _oracle_max_long_value_bytes(
        projection_kinds,
        projection_max_bytes,
    )
    if max_long_value_bytes == 0:
        return ORACLE_THIN_BASELINE_RETAINED_BYTES
    rounded_value_bytes = (
        (max_long_value_bytes + _ORACLE_THIN_CHUNK_BYTES - 1)
        // _ORACLE_THIN_CHUNK_BYTES
        * _ORACLE_THIN_CHUNK_BYTES
    )
    chunk_count = rounded_value_bytes // _ORACLE_THIN_CHUNK_BYTES
    descriptor_count = (
        (chunk_count + _ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK - 1)
        // _ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK
        * _ORACLE_THIN_CHUNK_DESCRIPTOR_BLOCK
    )
    return rounded_value_bytes + descriptor_count * _ORACLE_THIN_CHUNK_DESCRIPTOR_BYTES


def _oracle_max_long_value_bytes(
    projection_kinds: tuple[OracleProjectionKind, ...],
    projection_max_bytes: tuple[int, ...],
) -> int:
    return max(
        (
            max_bytes
            for kind, max_bytes in zip(
                projection_kinds,
                projection_max_bytes,
                strict=True,
            )
            if kind is not OracleProjectionKind.DECIMAL
            and max_bytes > _ORACLE_THIN_LONG_LENGTH_THRESHOLD_BYTES
        ),
        default=0,
    )


def _oracle_value_memory_bytes(kind: OracleProjectionKind, max_bytes: int) -> int:
    if kind is OracleProjectionKind.ASCII:
        return _MAX_UNICODE_TEXT_BASE_BYTES + (4 * max_bytes)
    if kind is OracleProjectionKind.TEXT:
        return _MAX_UNICODE_TEXT_BASE_BYTES + (4 * max_bytes)
    if kind is OracleProjectionKind.RAW:
        return BYTES_HEADER_BYTES + max_bytes
    if kind is OracleProjectionKind.DECIMAL:
        return MAX_ORACLE_DECIMAL_OBJECT_BYTES
    raise AssertionError("Oracle projection kind is unsupported")
