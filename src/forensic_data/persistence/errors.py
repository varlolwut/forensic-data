class MetadataError(RuntimeError):
    """Base error for the metadata persistence boundary."""


class MetadataConnectionError(MetadataError):
    """A metadata PostgreSQL connection could not be established."""


class MetadataProfileError(MetadataError):
    """The metadata PostgreSQL server does not satisfy the required profile."""


class MetadataMigrationError(MetadataError):
    """A metadata schema migration operation failed."""


class MetadataMigrationHistoryError(MetadataMigrationError):
    """Stored migration history is not an exact prefix of packaged migrations."""


class MetadataMigrationChecksumError(MetadataMigrationHistoryError):
    """A stored migration checksum differs from the packaged migration bytes."""


class MetadataMigrationApplyError(MetadataMigrationError):
    """A pending metadata migration could not be applied atomically."""


class MetadataPersistenceError(MetadataError):
    """A metadata registration or lookup failed."""


class DatasetIdentityConflictError(MetadataPersistenceError):
    """A dataset semantic identity conflicts with an immutable stored definition."""


class ImmutableContractRevisionConflictError(MetadataPersistenceError):
    """A check revision is already bound to a different contract identity."""


class CodeArtifactIntegrityError(MetadataPersistenceError):
    """A retained code artifact does not match its declared digest or size."""


class StoredMetadataIntegrityError(MetadataPersistenceError):
    """Stored metadata violates the typed persistence protocol."""
