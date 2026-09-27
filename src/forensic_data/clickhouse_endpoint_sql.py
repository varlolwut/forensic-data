from dataclasses import dataclass
from typing import cast, final

from forensic_data.canonical.model import INT64_MAX
from forensic_data.clickhouse import ClickHouseParameter
from forensic_data.clickhouse_canonical import (
    ClickHouseCanonicalLimits,
    ClickHouseCanonicalRelation,
    clickhouse_comparison_aggregate_settings,
    clickhouse_comparison_ordered_settings,
    lower_clickhouse_integer_comparison,
)
from forensic_data.postgres_sql import (
    PostgresIntegerRangeRequest,
    PostgresScopePredicate,
)


@final
@dataclass(frozen=True, slots=True)
class ClickHouseEndpointQuery:
    statement: str
    parameters: dict[str, ClickHouseParameter]
    settings: dict[str, ClickHouseParameter]
    max_response_bytes: int
    operation: str
    full_scans: int

    def __post_init__(self) -> None:
        if type(self.statement) is not str or not self.statement:
            raise ValueError("ClickHouse endpoint query statement must be non-empty text")
        if type(self.parameters) is not dict or type(self.settings) is not dict:
            raise TypeError("ClickHouse endpoint query bindings must be dictionaries")
        _require_positive_integer(self.max_response_bytes, "response byte limit")
        if type(self.operation) is not str or not self.operation:
            raise ValueError("ClickHouse endpoint query operation must be non-empty text")
        if type(self.full_scans) is not int or self.full_scans < 0:
            raise ValueError("ClickHouse endpoint full scans must be a non-negative integer")


def build_clickhouse_integer_key_summary_query(
    relation: ClickHouseCanonicalRelation,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    limits: ClickHouseCanonicalLimits,
    usable_access_path: bool,
    max_total_bytes: int,
    full_scans: int,
) -> ClickHouseEndpointQuery:
    if type(usable_access_path) is not bool:
        raise TypeError("ClickHouse usable access-path evidence must be a boolean")
    _require_positive_integer(max_total_bytes, "summary total byte limit")
    lowering = lower_clickhouse_integer_comparison(
        relation,
        key_field_index,
        scope,
        limits,
    )
    parameters = lowering.parameter_dict()
    parameters["usable_access_path"] = int(usable_access_path)
    raw_response_limit = _raw_response_limit(max_total_bytes, 1, 8, limits)
    statement = (
        "SELECT toString(count()) AS row_count, "
        f"toString(countIf(isNull({lowering.key_column}))) AS null_key_count, "
        "toString(countIf(NOT isNull("
        f"{lowering.key_column}) AND NOT ({lowering.key_is_valid}))) AS invalid_key_count, "
        "toString(countIf(NOT isNull("
        f"{lowering.key_column}) AND ({lowering.key_is_valid}))) AS valid_key_count, "
        "toString(uniqExactIf("
        f"{lowering.key_column}, NOT isNull({lowering.key_column}) AND "
        f"({lowering.key_is_valid}))) AS distinct_key_count, "
        "if(countIf(NOT isNull("
        f"{lowering.key_column}) AND ({lowering.key_is_valid})) = 0, '', "
        "toString(minIf("
        f"{lowering.key_column}, NOT isNull({lowering.key_column}) AND "
        f"({lowering.key_is_valid})))) AS minimum_key, "
        "if(countIf(NOT isNull("
        f"{lowering.key_column}) AND ({lowering.key_is_valid})) = 0, '', "
        "toString(maxIf("
        f"{lowering.key_column}, NOT isNull({lowering.key_column}) AND "
        f"({lowering.key_is_valid})))) AS maximum_key, "
        "toString({usable_access_path:UInt8}) AS usable_access_path "
        f"FROM {lowering.source_sql} WHERE {lowering.scope_filter}"
    )
    return ClickHouseEndpointQuery(
        statement=statement,
        parameters=parameters,
        settings=clickhouse_comparison_aggregate_settings(
            relation,
            limits,
            1,
            raw_response_limit,
        ),
        max_response_bytes=raw_response_limit,
        operation="clickhouse_integer_key_summary",
        full_scans=full_scans,
    )


def build_clickhouse_integer_range_fingerprint_query(
    relation: ClickHouseCanonicalRelation,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    limits: ClickHouseCanonicalLimits,
    max_total_bytes: int,
    full_scans: int,
) -> ClickHouseEndpointQuery:
    _validate_ranges(ranges)
    _require_positive_integer(max_total_bytes, "fingerprint total byte limit")
    lowering = lower_clickhouse_integer_comparison(
        relation,
        key_field_index,
        scope,
        limits,
    )
    parameters = lowering.parameter_dict()
    parameters.update(_range_parameters(ranges))
    classifier = _range_classifier(lowering.key_column, ranges)
    range_array = _range_array(ranges)
    limb_selects = ", ".join(
        f"toString(ifNull(dfe_aggregate.limb_{index}, CAST(0 AS Decimal(38, 0)))) AS limb_{index}"
        for index in range(8)
    )
    branch_limb_selects = ", ".join(
        "sumIf(CAST(reinterpretAsUInt32(reverse(substring(row_hash, "
        f"{(index * 4) + 1}, 4))) AS Decimal(38, 0)), accepted_row) AS limb_{index}"
        for index in range(8)
    )
    raw_response_limit = _raw_response_limit(
        max_total_bytes,
        len(ranges),
        14,
        limits,
    )
    statement = (
        "SELECT tupleElement(dfe_range, 2) AS segment_id, "
        "toString(ifNull(dfe_aggregate.valid_row_count, toUInt64(0))) "
        "AS valid_row_count, "
        f"{limb_selects}, "
        "toString(ifNull(dfe_aggregate.invalid_row_count, toUInt64(0))) "
        "AS invalid_row_count, "
        "toString(ifNull(dfe_aggregate.oversized_row_count, toUInt64(0))) "
        "AS oversized_row_count, "
        "toString(ifNull(dfe_aggregate.row_envelope_bytes, "
        "CAST(0 AS Decimal(38, 0)))) "
        "AS row_envelope_bytes, "
        "toString(ifNull(dfe_aggregate.key_envelope_bytes, "
        "CAST(0 AS Decimal(38, 0)))) "
        "AS key_envelope_bytes "
        f"FROM (SELECT arrayJoin([{range_array}]) AS dfe_range) AS dfe_ranges "
        "LEFT JOIN (WITH "
        f"{lowering.encoded_row_envelope} AS encoded_envelope, "
        f"{lowering.invalid_row} AS invalid_value, "
        f"{lowering.oversized_row} AS oversized_value, "
        f"{lowering.row_envelope} AS row_envelope, "
        f"{lowering.key_envelope} AS key_envelope, "
        f"{classifier} AS dfe_ordinal, "
        "NOT invalid_value AND NOT oversized_value AS accepted_row, "
        "SHA256(ifNull(row_envelope, '')) AS row_hash "
        "SELECT dfe_ordinal, countIf(accepted_row) AS valid_row_count, "
        f"{branch_limb_selects}, "
        "countIf(invalid_value) AS invalid_row_count, "
        "countIf(oversized_value) AS oversized_row_count, "
        "sumIf(CAST(ifNull(length(row_envelope), toUInt64(0)) "
        "AS Decimal(38, 0)), accepted_row) "
        "AS row_envelope_bytes, "
        "sumIf(CAST(length(key_envelope) AS Decimal(38, 0)), accepted_row) "
        "AS key_envelope_bytes "
        f"FROM {lowering.source_sql} WHERE ({lowering.scope_filter}) "
        f"AND NOT isNull({lowering.key_column}) AND ({lowering.key_is_valid}) "
        f"AND dfe_ordinal < toUInt64({len(ranges)}) GROUP BY dfe_ordinal"
        ") AS dfe_aggregate ON dfe_aggregate.dfe_ordinal = tupleElement(dfe_range, 1) "
        "ORDER BY tupleElement(dfe_range, 1)"
    )
    settings = clickhouse_comparison_ordered_settings(
        relation,
        limits,
        len(ranges),
        raw_response_limit,
    )
    settings.update(
        {
            "max_rows_to_group_by": len(ranges) + 1,
            "group_by_overflow_mode": "throw",
        }
    )
    return ClickHouseEndpointQuery(
        statement=statement,
        parameters=parameters,
        settings=settings,
        max_response_bytes=raw_response_limit,
        operation="clickhouse_integer_range_fingerprints",
        full_scans=full_scans,
    )


def build_clickhouse_integer_range_rows_query(
    relation: ClickHouseCanonicalRelation,
    key_field_index: int,
    scope: PostgresScopePredicate | None,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
    limits: ClickHouseCanonicalLimits,
    max_records: int,
    max_total_bytes: int,
    full_scans: int,
) -> ClickHouseEndpointQuery:
    _validate_ranges(ranges)
    _require_positive_integer(max_records, "exact-row record limit")
    _require_positive_integer(max_total_bytes, "exact-row total byte limit")
    lowering = lower_clickhouse_integer_comparison(
        relation,
        key_field_index,
        scope,
        limits,
    )
    parameters = lowering.parameter_dict()
    parameters.update(_range_parameters(ranges))
    classifier = _range_classifier(lowering.key_column, ranges)
    segment_classifier = _segment_classifier(ranges)
    result_limit = max_records + 1
    raw_response_limit = _raw_response_limit(
        max_total_bytes,
        result_limit,
        5,
        limits,
    )
    parameters["result_limit"] = result_limit
    statement = (
        "WITH "
        f"{lowering.encoded_row_envelope} AS encoded_envelope, "
        f"{lowering.invalid_row} AS invalid_value, "
        f"{lowering.oversized_row} AS oversized_value, "
        f"{lowering.row_envelope} AS accepted_row_envelope, "
        f"{lowering.key_envelope} AS key_envelope, "
        f"{classifier} AS dfe_ordinal "
        f"SELECT {segment_classifier} AS segment_id, key_envelope, "
        "ifNull(accepted_row_envelope, '') AS row_envelope, "
        "toString(toUInt8(invalid_value)) AS invalid_row, "
        "toString(toUInt8(oversized_value)) AS oversized_row "
        f"FROM {lowering.source_sql} WHERE ({lowering.scope_filter}) "
        f"AND NOT isNull({lowering.key_column}) AND ({lowering.key_is_valid}) "
        f"AND dfe_ordinal < toUInt64({len(ranges)}) "
        f"ORDER BY dfe_ordinal, {lowering.key_column} "
        "LIMIT {result_limit:UInt64}"
    )
    return ClickHouseEndpointQuery(
        statement=statement,
        parameters=parameters,
        settings=clickhouse_comparison_ordered_settings(
            relation,
            limits,
            result_limit,
            # ClickHouse counts native block bytes; transport bounds serialized TSV bytes.
            limits.max_response_bytes,
        ),
        max_response_bytes=raw_response_limit,
        operation="clickhouse_integer_range_rows",
        full_scans=full_scans,
    )


def _range_parameters(
    ranges: tuple[PostgresIntegerRangeRequest, ...],
) -> dict[str, ClickHouseParameter]:
    parameters: dict[str, ClickHouseParameter] = {}
    for index, item in enumerate(ranges):
        parameters[f"range_{index}_segment"] = item.segment_id
        parameters[f"range_{index}_lower"] = item.lower_inclusive
        parameters[f"range_{index}_has_upper"] = int(item.upper_exclusive is not None)
        parameters[f"range_{index}_upper"] = (
            0 if item.upper_exclusive is None else item.upper_exclusive
        )
    return parameters


def _range_classifier(
    key_column: str,
    ranges: tuple[PostgresIntegerRangeRequest, ...],
) -> str:
    branches: list[str] = []
    for index in range(len(ranges)):
        branches.extend(
            (
                (
                    f"{key_column} >= {{range_{index}_lower:Int64}} AND "
                    f"({{range_{index}_has_upper:UInt8}} = 0 OR "
                    f"{key_column} < {{range_{index}_upper:Int64}})"
                ),
                f"toUInt64({index})",
            )
        )
    return "multiIf(" + ", ".join((*branches, f"toUInt64({len(ranges)})")) + ")"


def _segment_classifier(ranges: tuple[PostgresIntegerRangeRequest, ...]) -> str:
    branches: list[str] = []
    for index in range(len(ranges)):
        branches.extend(
            (
                f"dfe_ordinal = toUInt64({index})",
                f"{{range_{index}_segment:String}}",
            )
        )
    return "multiIf(" + ", ".join((*branches, "''")) + ")"


def _range_array(ranges: tuple[PostgresIntegerRangeRequest, ...]) -> str:
    return ", ".join(
        f"tuple(toUInt64({index}), {{range_{index}_segment:String}})"
        for index in range(len(ranges))
    )


def _raw_response_limit(
    max_total_bytes: int,
    max_records: int,
    delimiters_per_record: int,
    limits: ClickHouseCanonicalLimits,
) -> int:
    _require_positive_integer(max_total_bytes, "logical result byte limit")
    _require_positive_integer(max_records, "logical result record limit")
    _require_positive_integer(delimiters_per_record, "result delimiter reservation")
    requested = max_total_bytes + (max_records * delimiters_per_record)
    if requested > limits.max_response_bytes:
        raise ValueError(
            "ClickHouse serialized response limit exceeds the accepted response limit: "
            f"requested={requested}, accepted={limits.max_response_bytes}"
        )
    return requested


def _validate_ranges(value: object) -> None:
    if type(value) is not tuple or not value:
        raise ValueError("ClickHouse integer ranges must be a non-empty immutable tuple")
    ranges = cast(tuple[object, ...], value)
    previous_upper: int | None = None
    segment_ids: set[str] = set()
    for index, item in enumerate(ranges):
        if not isinstance(item, PostgresIntegerRangeRequest):
            raise TypeError(f"ClickHouse integer range has an unexpected type: range_index={index}")
        if item.segment_id in segment_ids:
            raise ValueError("ClickHouse integer range segment IDs must be unique")
        segment_ids.add(item.segment_id)
        if index > 0:
            if previous_upper is None:
                raise ValueError("ClickHouse unbounded integer range must be last")
            if item.lower_inclusive < previous_upper:
                raise ValueError("ClickHouse integer ranges must be ordered and disjoint")
        previous_upper = item.upper_exclusive


def _require_positive_integer(value: int, label: str) -> None:
    if type(value) is not int or not 1 <= value <= INT64_MAX:
        raise ValueError(f"ClickHouse endpoint {label} must be a positive int64")
