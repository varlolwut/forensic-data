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


class LifecyclePersistenceError(MetadataPersistenceError):
    """A run-lifecycle persistence operation failed."""


class RunRequestConflictError(LifecyclePersistenceError):
    """A request UUID is already bound to a different immutable run request."""


class LifecycleOperationConflictError(LifecyclePersistenceError):
    """An operation UUID is already bound to a different lifecycle mutation."""


class RunLifecycleStateError(LifecyclePersistenceError):
    """A run or attempt is not in the required lifecycle state."""


class ActiveRunAttemptError(RunLifecycleStateError):
    """A run already has a running attempt, including an expired fenced attempt."""


class RunAttemptLimitError(RunLifecycleStateError):
    """A run has exhausted the request's immutable attempt budget."""


class AttemptFenceError(RunLifecycleStateError):
    """An attempt mutation failed its owner, running-state, or lease fence."""


class InputCutMismatchError(RunLifecycleStateError):
    """An observed cut differs from the run's immutable first aligned cut."""


class StoredLifecycleIntegrityError(StoredMetadataIntegrityError):
    """Stored lifecycle rows violate their typed aggregate closure."""


class LifecycleCommitUnknownError(LifecyclePersistenceError):
    """A lifecycle COMMIT could not be confirmed by its durable operation receipt."""


class LifecycleTransactionError(LifecyclePersistenceError):
    """A lifecycle transaction definitively failed without a durable receipt."""
