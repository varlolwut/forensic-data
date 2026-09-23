import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import final

from forensic_data.canonical.model import (
    DECIMAL_38_MAX,
    INT64_MAX,
    UINT32_MAX,
    FingerprintOverflowError,
    FrameValidationError,
    SegmentValidationError,
)

type Sha256Limbs = tuple[int, int, int, int, int, int, int, int]

_ROW_PREFIX = b"DFE1R"
_KEY_PREFIX = b"DFE1K"
_ENVELOPE_HEADER_LENGTH = 5 + 64 + 8


@final
@dataclass(frozen=True, slots=True)
class Fingerprint:
    count: int
    limb_sums: Sha256Limbs

    def __post_init__(self) -> None:
        if type(self.count) is not int or not 0 <= self.count <= INT64_MAX:
            raise FingerprintOverflowError(
                "fingerprint count must be an integer in signed int64 nonnegative range"
            )
        if type(self.limb_sums) is not tuple or len(self.limb_sums) != 8:
            raise FingerprintOverflowError(
                "fingerprint limb_sums must be an immutable tuple of eight integers"
            )
        maximum_sum = self.count * UINT32_MAX
        for index, limb_sum in enumerate(self.limb_sums):
            if type(limb_sum) is not int or not 0 <= limb_sum <= DECIMAL_38_MAX:
                raise FingerprintOverflowError(
                    f"fingerprint limb sum {index} is outside exact decimal(38,0) range"
                )
            if limb_sum > maximum_sum:
                raise FingerprintOverflowError(
                    f"fingerprint limb sum {index} exceeds count * uint32 maximum"
                )


@final
@dataclass(frozen=True, slots=True)
class SegmentIdentity:
    depth: int
    prefix: int

    def __post_init__(self) -> None:
        if type(self.depth) is not int or not 0 <= self.depth <= 256:
            raise SegmentValidationError(
                "segment depth must be an integer in the inclusive range 0..256"
            )
        if type(self.prefix) is not int or not 0 <= self.prefix < (1 << self.depth):
            raise SegmentValidationError(
                f"segment prefix must fit exactly within depth={self.depth} high bits"
            )


def envelope_sha256(envelope: bytes) -> bytes:
    if type(envelope) is not bytes:
        raise FrameValidationError("canonical envelope hash input must be bytes")
    return hashlib.sha256(envelope).digest()


def sha256_limbs(digest: bytes) -> Sha256Limbs:
    _require_sha256(digest)
    return (
        int.from_bytes(digest[0:4], "big", signed=False),
        int.from_bytes(digest[4:8], "big", signed=False),
        int.from_bytes(digest[8:12], "big", signed=False),
        int.from_bytes(digest[12:16], "big", signed=False),
        int.from_bytes(digest[16:20], "big", signed=False),
        int.from_bytes(digest[20:24], "big", signed=False),
        int.from_bytes(digest[24:28], "big", signed=False),
        int.from_bytes(digest[28:32], "big", signed=False),
    )


def fingerprint_hashes(digests: Iterable[bytes]) -> Fingerprint:
    _require_nonbyte_iterable(digests, "fingerprint hashes")
    count = 0
    sums = [0, 0, 0, 0, 0, 0, 0, 0]
    for digest in digests:
        if count == INT64_MAX:
            raise FingerprintOverflowError("fingerprint count exceeds signed int64 maximum")
        limbs = sha256_limbs(digest)
        count += 1
        for index, limb in enumerate(limbs):
            sums[index] += limb
            if sums[index] > DECIMAL_38_MAX:
                raise FingerprintOverflowError(
                    f"fingerprint limb sum {index} exceeds exact decimal(38,0)"
                )
    return Fingerprint(count=count, limb_sums=_limb_tuple(sums))


def fingerprint_rows(envelopes: Iterable[bytes]) -> Fingerprint:
    _require_nonbyte_iterable(envelopes, "fingerprint rows")
    return fingerprint_hashes(_row_envelope_sha256(envelope) for envelope in envelopes)


def combine_fingerprints(fingerprints: Iterable[Fingerprint]) -> Fingerprint:
    _require_fingerprint_iterable(fingerprints)
    count = 0
    sums = [0, 0, 0, 0, 0, 0, 0, 0]
    for fingerprint in fingerprints:
        _require_fingerprint(fingerprint)
        count += fingerprint.count
        if count > INT64_MAX:
            raise FingerprintOverflowError("fingerprint count exceeds signed int64 maximum")
        for index, limb_sum in enumerate(fingerprint.limb_sums):
            sums[index] += limb_sum
            if sums[index] > DECIMAL_38_MAX:
                raise FingerprintOverflowError(
                    f"fingerprint limb sum {index} exceeds exact decimal(38,0)"
                )
    return Fingerprint(count=count, limb_sums=_limb_tuple(sums))


def segment_identity(digest: bytes, total_depth: int) -> SegmentIdentity:
    _require_sha256(digest)
    if type(total_depth) is not int or not 0 <= total_depth <= 256:
        raise SegmentValidationError(
            "segment total depth must be an integer in the inclusive range 0..256"
        )
    prefix = 0
    if total_depth > 0:
        prefix = int.from_bytes(digest, "big", signed=False) >> (256 - total_depth)
    return SegmentIdentity(depth=total_depth, prefix=prefix)


def row_segment(envelope: bytes, total_depth: int) -> SegmentIdentity:
    return segment_identity(_row_envelope_sha256(envelope), total_depth)


def key_segment(envelope: bytes, total_depth: int) -> SegmentIdentity:
    return segment_identity(_key_envelope_sha256(envelope), total_depth)


def row_bucket(envelope: bytes, bucket_bits: int) -> int:
    return row_segment(envelope, bucket_bits).prefix


def key_bucket(envelope: bytes, bucket_bits: int) -> int:
    return key_segment(envelope, bucket_bits).prefix


def _require_sha256(digest: bytes) -> None:
    if type(digest) is not bytes or len(digest) != 32:
        raise FrameValidationError("SHA-256 digest must be exactly 32 bytes")


def _row_envelope_sha256(envelope: bytes) -> bytes:
    _require_envelope_kind(envelope, _ROW_PREFIX, "row")
    return envelope_sha256(envelope)


def _key_envelope_sha256(envelope: bytes) -> bytes:
    _require_envelope_kind(envelope, _KEY_PREFIX, "key")
    return envelope_sha256(envelope)


def _require_envelope_kind(envelope: object, expected_prefix: bytes, context: str) -> None:
    if type(envelope) is not bytes:
        raise FrameValidationError(f"{context} envelope must be bytes")
    if len(envelope) < _ENVELOPE_HEADER_LENGTH:
        raise FrameValidationError(
            f"{context} envelope is shorter than the 77-byte protocol header"
        )
    if not envelope.isascii():
        raise FrameValidationError(f"{context} envelope must contain ASCII only")
    if not envelope.startswith(expected_prefix):
        raise FrameValidationError(
            f"{context} envelope must start with {expected_prefix.decode('ascii')!r}"
        )


def _require_nonbyte_iterable(value: object, context: str) -> None:
    if isinstance(value, (bytes, bytearray)) or not isinstance(value, Iterable):
        raise FrameValidationError(f"{context} must be a non-byte iterable")


def _require_fingerprint_iterable(value: object) -> None:
    if not isinstance(value, Iterable):
        raise FingerprintOverflowError("fingerprints must be an iterable of Fingerprint values")


def _require_fingerprint(value: object) -> None:
    if not isinstance(value, Fingerprint):
        raise FingerprintOverflowError("fingerprint collection contains a non-Fingerprint value")


def _limb_tuple(values: list[int]) -> Sha256Limbs:
    if len(values) != 8:
        raise FingerprintOverflowError("fingerprint requires exactly eight limb sums")
    return (
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
    )
