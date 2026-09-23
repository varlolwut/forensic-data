import pytest

from forensic_data.canonical import (
    PROTOCOL,
    CanonicalSchema,
    FieldSchema,
    Fingerprint,
    FingerprintOverflowError,
    FrameValidationError,
    LogicalType,
    NoParameters,
    Normalization,
    SegmentIdentity,
    SegmentValidationError,
    combine_fingerprints,
    encode_row,
    envelope_sha256,
    fingerprint_hashes,
    fingerprint_rows,
    key_bucket,
    key_segment,
    row_bucket,
    row_segment,
    segment_identity,
    sha256_limbs,
)
from tests.canonical_vectors import vector_named

_ZERO_LIMBS = (0, 0, 0, 0, 0, 0, 0, 0)


def test_sha256_limbs_and_segments_match_independent_golden_literals() -> None:
    for vector_name in ("all_common_types", "composite_key"):
        vector = vector_named(vector_name)
        envelope = vector.envelope_ascii.encode("ascii")
        digest = envelope_sha256(envelope)

        assert digest == bytes.fromhex(vector.sha256_hex)
        assert sha256_limbs(digest) == vector.limbs
        for depth, expected_prefix in vector.segment_prefixes.items():
            assert segment_identity(digest, depth) == SegmentIdentity(
                depth=depth, prefix=expected_prefix
            )


def test_empty_and_duplicate_fingerprints_use_exact_integer_sums() -> None:
    vector = vector_named("all_common_types")
    envelope = vector.envelope_ascii.encode("ascii")
    expected_count = vector.duplicate_twice_count
    expected_sums = vector.duplicate_twice_limb_sums
    assert expected_count is not None
    assert expected_sums is not None

    assert fingerprint_rows(()) == Fingerprint(count=0, limb_sums=_ZERO_LIMBS)
    assert fingerprint_rows((envelope, envelope)) == Fingerprint(
        count=expected_count,
        limb_sums=expected_sums,
    )


def test_fingerprint_combination_adds_distinct_partial_results_exactly() -> None:
    row = vector_named("all_common_types")
    key = vector_named("composite_key")
    row_fingerprint = fingerprint_hashes((bytes.fromhex(row.sha256_hex),))
    key_fingerprint = fingerprint_hashes((bytes.fromhex(key.sha256_hex),))

    assert combine_fingerprints((row_fingerprint, key_fingerprint)) == Fingerprint(
        count=2,
        limb_sums=(
            4652154295,
            1941649509,
            3510700748,
            4163684498,
            1777899068,
            6242954518,
            7489897011,
            5857962413,
        ),
    )


def test_fingerprint_rejects_impossible_values_and_count_overflow() -> None:
    maximum_count = Fingerprint(count=(1 << 63) - 1, limb_sums=_ZERO_LIMBS)
    one = Fingerprint(count=1, limb_sums=_ZERO_LIMBS)

    with pytest.raises(FingerprintOverflowError, match="count"):
        combine_fingerprints((maximum_count, one))
    with pytest.raises(FingerprintOverflowError, match=r"count \* uint32"):
        Fingerprint(count=0, limb_sums=(1, 0, 0, 0, 0, 0, 0, 0))


def test_hash_and_segment_bounds_are_strict() -> None:
    digest = bytes.fromhex(vector_named("all_common_types").sha256_hex)

    assert segment_identity(digest, 0) == SegmentIdentity(depth=0, prefix=0)
    assert segment_identity(digest, 256) == SegmentIdentity(
        depth=256, prefix=int.from_bytes(digest, "big", signed=False)
    )
    with pytest.raises(FrameValidationError):
        sha256_limbs(b"short")
    with pytest.raises(SegmentValidationError):
        segment_identity(digest, 257)
    with pytest.raises(SegmentValidationError):
        SegmentIdentity(depth=1, prefix=2)


def test_different_full_rows_can_share_a_bucket_without_becoming_equal() -> None:
    schema = _int_schema()
    first = encode_row(schema, (0,))
    second = encode_row(schema, (1,))

    assert first != second
    assert envelope_sha256(first).hex() == (
        "84a8b323bc9eab1eb6e82257cbbbc04dc22aae5d34aa21d5b07bb74dae1c6392"
    )
    assert envelope_sha256(second).hex() == (
        "91fe43d00e199d38c6abbd232b65bb65b3c05741d00f517af2b997b242fb5a22"
    )
    assert row_bucket(first, 2) == 2
    assert row_bucket(second, 2) == 2
    assert row_segment(first, 13) != row_segment(second, 13)


def test_row_and_key_bucket_functions_use_total_high_bit_depth() -> None:
    row = vector_named("all_common_types")
    key = vector_named("composite_key")
    row_envelope = row.envelope_ascii.encode("ascii")
    key_envelope = key.envelope_ascii.encode("ascii")

    assert row_bucket(row_envelope, 13) == 1050
    assert row_segment(row_envelope, 13) == SegmentIdentity(depth=13, prefix=1050)
    assert key_bucket(key_envelope, 13) == 7822
    assert key_segment(key_envelope, 13) == SegmentIdentity(depth=13, prefix=7822)
    with pytest.raises(FrameValidationError, match="row envelope"):
        row_bucket(key_envelope, 13)


def _int_schema() -> CanonicalSchema:
    return CanonicalSchema(
        protocol=PROTOCOL,
        fields=(
            FieldSchema(
                name="id",
                logical_type=LogicalType.INT64,
                nullable=False,
                parameters=NoParameters(),
                normalization=Normalization.NONE,
            ),
        ),
    )
