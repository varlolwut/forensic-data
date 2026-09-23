from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import final

PROTOCOL = "dfe_canon_v1"
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
INT64_MAX = (1 << 63) - 1
DECIMAL_38_MAX = (10**38) - 1


class CanonicalizationError(ValueError):
    """Base error for canonical protocol violations."""


class SchemaValidationError(CanonicalizationError):
    """The logical schema metadata is not valid for canonical protocol v1."""


class PayloadValidationError(CanonicalizationError):
    """A logical value cannot be represented by its declared canonical type."""


class FrameValidationError(CanonicalizationError):
    """A row or key envelope violates canonical protocol v1 framing."""


class NullKeyError(FrameValidationError):
    """A key contains a NULL field."""


class FingerprintOverflowError(CanonicalizationError):
    """A fingerprint exceeds a protocol v1 exact accumulator bound."""


class SegmentValidationError(CanonicalizationError):
    """A segment identity is outside the SHA-256 prefix domain."""


class LogicalType(StrEnum):
    INT64 = "int64"
    DECIMAL = "decimal"
    BOOLEAN = "boolean"
    STRING = "string"
    DATE = "date"
    TIMESTAMP_LOCAL = "timestamp_local"
    TIMESTAMP_INSTANT = "timestamp_instant"


class Normalization(StrEnum):
    NONE = "none"


@final
@dataclass(frozen=True, slots=True)
class NoParameters:
    pass


@final
@dataclass(frozen=True, slots=True)
class DecimalParameters:
    precision: int
    scale: int

    def __post_init__(self) -> None:
        if type(self.precision) is not int or not 1 <= self.precision <= 38:
            raise SchemaValidationError(
                "decimal precision must be an integer in the inclusive range 1..38"
            )
        if type(self.scale) is not int or not 0 <= self.scale <= self.precision:
            raise SchemaValidationError(
                "decimal scale must be an integer in the inclusive range 0..precision"
            )


@final
@dataclass(frozen=True, slots=True)
class TimestampParameters:
    precision: int

    def __post_init__(self) -> None:
        if type(self.precision) is not int or not 0 <= self.precision <= 9:
            raise SchemaValidationError(
                "timestamp precision must be an integer in the inclusive range 0..9"
            )


type FieldParameters = NoParameters | DecimalParameters | TimestampParameters


@final
@dataclass(frozen=True, slots=True)
class FieldSchema:
    name: str
    logical_type: LogicalType
    nullable: bool
    parameters: FieldParameters
    normalization: Normalization

    def __post_init__(self) -> None:
        _validate_unicode_scalars(self.name, "field name")
        if not _is_logical_type(self.logical_type):
            raise SchemaValidationError("field logical_type must be a LogicalType")
        if type(self.nullable) is not bool:
            raise SchemaValidationError("field nullable must be a boolean")
        if self.normalization is not Normalization.NONE:
            raise SchemaValidationError(
                "field normalization must be exactly 'none' in canonical protocol v1"
            )

        if self.logical_type is LogicalType.DECIMAL:
            if not isinstance(self.parameters, DecimalParameters):
                raise SchemaValidationError("decimal fields require precision and scale parameters")
            return
        if self.logical_type in (
            LogicalType.TIMESTAMP_LOCAL,
            LogicalType.TIMESTAMP_INSTANT,
        ):
            if not isinstance(self.parameters, TimestampParameters):
                raise SchemaValidationError("timestamp fields require a precision parameter")
            return
        if not isinstance(self.parameters, NoParameters):
            raise SchemaValidationError(
                f"{self.logical_type.value} fields require an empty parameters object"
            )


@final
@dataclass(frozen=True, slots=True)
class CanonicalSchema:
    protocol: str
    fields: tuple[FieldSchema, ...]

    def __post_init__(self) -> None:
        if type(self.protocol) is not str or self.protocol != PROTOCOL:
            raise SchemaValidationError(
                f"schema protocol must be exactly {PROTOCOL!r}, "
                f"got_type={type(self.protocol).__name__}"
            )
        if type(self.fields) is not tuple:
            raise SchemaValidationError("schema fields must be an immutable tuple")
        if len(self.fields) > UINT32_MAX:
            raise SchemaValidationError("schema field count exceeds uint32")
        for index, field in enumerate(self.fields):
            _validate_field_schema(field, index)


type CanonicalInput = int | Decimal | bool | str | date | datetime
type DecodedValue = int | Decimal | bool | str | date


def _validate_unicode_scalars(value: object, context: str) -> None:
    if type(value) is not str:
        raise SchemaValidationError(f"{context} must be a string")
    for index, character in enumerate(value):
        code_point = ord(character)
        if 0xD800 <= code_point <= 0xDFFF:
            raise SchemaValidationError(
                f"{context} contains a surrogate code point at character {index}"
            )


def _is_logical_type(value: object) -> bool:
    return isinstance(value, LogicalType)


def _validate_field_schema(value: object, index: int) -> None:
    if not isinstance(value, FieldSchema):
        raise SchemaValidationError(f"schema field at index {index} must be a FieldSchema")
