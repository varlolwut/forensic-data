from sys import getsizeof

POINTER_BYTES = getsizeof((None,)) - getsizeof(())
EMPTY_TUPLE_BYTES = getsizeof(())
EMPTY_LIST_BYTES = getsizeof([])
EMPTY_DICT_BYTES = getsizeof({})
DICT_ENTRY_RESERVATION_BYTES = getsizeof({0: None}) - EMPTY_DICT_BYTES
ASCII_TEXT_HEADER_BYTES = getsizeof("")
BYTES_HEADER_BYTES = getsizeof(b"")


def slot_object_bytes(value_type: type[object]) -> int:
    return getsizeof(object.__new__(value_type))


def tuple_storage_bytes(item_count: int) -> int:
    _require_nonnegative_integer(item_count, "tuple item count")
    return EMPTY_TUPLE_BYTES + (item_count * POINTER_BYTES)


def list_storage_bytes(item_count: int) -> int:
    _require_nonnegative_integer(item_count, "list item count")
    if item_count == 0:
        return EMPTY_LIST_BYTES
    reserved_items = item_count + (item_count // 8) + 6
    return EMPTY_LIST_BYTES + (reserved_items * POINTER_BYTES)


def dict_storage_bytes(item_count: int) -> int:
    _require_nonnegative_integer(item_count, "dictionary item count")
    return EMPTY_DICT_BYTES + (item_count * DICT_ENTRY_RESERVATION_BYTES)


def canonical_decode_field_reservation_bytes(max_value_object_bytes: int) -> int:
    _require_nonnegative_integer(max_value_object_bytes, "canonical decoded value object bytes")
    return (
        (6 * POINTER_BYTES) + ASCII_TEXT_HEADER_BYTES + BYTES_HEADER_BYTES + max_value_object_bytes
    )


def canonical_decode_scratch_bytes(
    max_encoded_envelope_bytes: int,
    field_count: int,
    max_value_object_bytes: int,
) -> int:
    _require_nonnegative_integer(
        max_encoded_envelope_bytes,
        "canonical encoded envelope bytes",
    )
    _require_nonnegative_integer(field_count, "canonical decoded field count")
    return (6 * max_encoded_envelope_bytes) + (
        field_count * canonical_decode_field_reservation_bytes(max_value_object_bytes)
    )


def _require_nonnegative_integer(value: object, context: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{context} must be a non-negative integer")
