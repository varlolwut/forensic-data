import logging
import math
import time
from dataclasses import dataclass
from datetime import date, datetime
from datetime import time as datetime_time
from decimal import Decimal
from enum import StrEnum
from threading import Condition, Lock, get_ident
from typing import cast
from uuid import UUID

import pyodbc
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

LOGGER = logging.getLogger(__name__)
_DRIVER_NAME = "ODBC Driver 18 for SQL Server"
_CONFIRMATION_SENTINEL = 1

type MssqlParameter = str | int | Decimal | bytes
type MssqlValue = bool | int | Decimal | str | bytes | None
type MssqlRow = tuple[MssqlValue, ...]


class MssqlTransportError(RuntimeError):
    """Base error for the SQL Server transport boundary."""


class MssqlConnectionError(MssqlTransportError):
    """Opening or profiling a SQL Server connection failed."""


class MssqlQueryError(MssqlTransportError):
    """A SQL Server statement failed and its transport was retired."""

    def __init__(self, query_id: UUID, session_id: int, sqlstate: str) -> None:
        self.query_id = query_id
        self.session_id = session_id
        self.sqlstate = sqlstate
        super().__init__(
            "SQL Server query failed: "
            f"query_id={query_id}, session_id={session_id}, sqlstate={sqlstate!r}"
        )


class MssqlDataValidationError(MssqlTransportError):
    """SQL Server or its driver returned data outside the typed transport contract."""


class MssqlLossyTransportError(MssqlDataValidationError):
    """A driver value cannot cross the transport boundary without information loss."""


class MssqlResultLimitError(MssqlTransportError):
    """A SQL Server result exceeded an explicit transport limit."""


class MssqlCancellationError(MssqlTransportError):
    """Base error for SQL Server query cancellation."""


class MssqlCancellationConfirmedError(MssqlCancellationError):
    """The requested statement ended and the same SQL Server session was confirmed."""

    def __init__(
        self,
        query_id: UUID,
        session_id: int,
        sqlstate: str,
        confirmation_session_id: int,
        confirmation_value: int,
    ) -> None:
        self.query_id = query_id
        self.session_id = session_id
        self.sqlstate = sqlstate
        self.confirmation_session_id = confirmation_session_id
        self.confirmation_value = confirmation_value
        super().__init__(
            "SQL Server query cancellation was confirmed: "
            f"query_id={query_id}, session_id={session_id}, sqlstate={sqlstate!r}"
        )


class MssqlCancellationUnconfirmedError(MssqlCancellationError):
    """A cancellation request could not be proven complete on its original session."""

    def __init__(self, query_id: UUID, session_id: int, reason: str) -> None:
        self.query_id = query_id
        self.session_id = session_id
        self.reason = reason
        super().__init__(
            "SQL Server query cancellation could not be confirmed: "
            f"query_id={query_id}, session_id={session_id}, reason={reason!r}"
        )


class MssqlCancellationRequestTimeoutError(MssqlCancellationError):
    """The worker did not acknowledge a cancellation request within its deadline."""


class MssqlTransportClosedError(MssqlTransportError):
    """An operation was attempted on a retired SQL Server transport."""


class MssqlCloseError(MssqlTransportError):
    """A SQL Server cursor or connection could not be closed explicitly."""


class MssqlNoActiveQueryError(MssqlCancellationError):
    """Cancellation was requested without an active SQL Server statement."""


class MssqlWrongQueryIdError(MssqlCancellationError):
    """Cancellation targeted a query other than the currently active statement."""


class MssqlThreadOwnershipError(MssqlTransportError):
    """A connection operation was attempted outside its owner thread."""


class MssqlQueryTimeoutError(MssqlQueryError):
    """ODBC timed out a statement and same-session completion was confirmed."""


class MssqlTlsVerification(StrEnum):
    VERIFY_SERVER_CERTIFICATE = "verify-server-certificate"
    TRUST_FIXTURE_CERTIFICATE = "trust-fixture-certificate"


class MssqlConnectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: str
    port: int = Field(ge=1, le=65_535)
    database: str
    user: str
    password: SecretStr
    tls_verification: MssqlTlsVerification
    login_timeout_seconds: int = Field(ge=1)
    query_timeout_seconds: int = Field(ge=1)
    cancellation_acknowledgement_timeout_seconds: float = Field(gt=0)
    application_name: str

    @field_validator("host", "database", "user", "application_name")
    @classmethod
    def validate_nonempty_connection_text(cls, value: str) -> str:
        if not value:
            raise ValueError("SQL Server connection text fields must not be empty")
        _validate_odbc_text_scalar(value, "SQL Server connection text fields")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: SecretStr) -> SecretStr:
        password = value.get_secret_value()
        if not password:
            raise ValueError("SQL Server password must not be empty")
        _validate_odbc_text_scalar(password, "SQL Server password")
        return value

    @field_validator("cancellation_acknowledgement_timeout_seconds")
    @classmethod
    def validate_finite_cancellation_timeout(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("cancellation acknowledgement timeout must be finite")
        return value


@dataclass(frozen=True, slots=True)
class MssqlRetryPolicy:
    max_attempts: int
    delay_seconds: float

    def __post_init__(self) -> None:
        if type(self.max_attempts) is not int or self.max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        if (
            type(self.delay_seconds) is not float
            or not math.isfinite(self.delay_seconds)
            or self.delay_seconds < 0
        ):
            raise ValueError("delay_seconds must be a finite non-negative float")


@dataclass(frozen=True, slots=True)
class MssqlQuery:
    query_id: UUID
    statement: str
    parameters: tuple[MssqlParameter, ...]

    def __post_init__(self) -> None:
        if type(self.query_id) is not UUID:
            raise TypeError("query_id must be a UUID")
        if type(self.statement) is not str or not self.statement:
            raise ValueError("statement must be non-empty text")
        _validate_odbc_text_scalar(self.statement, "statement")
        if type(self.parameters) is not tuple:
            raise TypeError("parameters must be a tuple")
        for parameter in self.parameters:
            _validate_parameter(parameter)


@dataclass(frozen=True, slots=True)
class MssqlFetchLimits:
    """Bounds retained rows and one transient fetch batch, not process RSS."""

    fetch_batch_records: int
    max_records: int
    max_value_bytes: int
    max_record_bytes: int
    max_total_bytes: int

    def __post_init__(self) -> None:
        for name, value in (
            ("fetch_batch_records", self.fetch_batch_records),
            ("max_records", self.max_records),
            ("max_value_bytes", self.max_value_bytes),
            ("max_record_bytes", self.max_record_bytes),
            ("max_total_bytes", self.max_total_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_value_bytes > self.max_record_bytes:
            raise ValueError("max_value_bytes must not exceed max_record_bytes")
        if self.max_record_bytes > self.max_total_bytes:
            raise ValueError("max_record_bytes must not exceed max_total_bytes")
        maximum_batch_bytes = self.fetch_batch_records * self.max_record_bytes
        if maximum_batch_bytes > self.max_total_bytes:
            raise ValueError(
                "max_total_bytes must admit one worst-case fetch batch: "
                f"required={maximum_batch_bytes}"
            )


@dataclass(frozen=True, slots=True)
class MssqlDriverEvidence:
    pyodbc_version: str
    driver_name: str
    driver_version: str
    server_version: str
    session_id: int


@dataclass(frozen=True, slots=True)
class MssqlReadMetrics:
    fetched_records: int
    fetched_bytes: int
    fetch_calls: int
    largest_batch_records: int


@dataclass(frozen=True, slots=True)
class MssqlReadResult:
    rows: tuple[MssqlRow, ...]
    metrics: MssqlReadMetrics


@dataclass(frozen=True, slots=True)
class _MssqlCancellationEvidence:
    requested: bool
    confirmation_session_id: int
    confirmation_value: int


class MssqlTransport:
    """A single-owner pyodbc transport with query-scoped cross-thread cancellation.

    A native SQLCancel call remains driver-controlled. If it stalls, the statement handle stays
    active and cannot be closed or reported complete until that call returns.
    Acknowledgement is timely only when the supervisor observes terminal detachment by its deadline.
    """

    def __init__(
        self,
        connection: pyodbc.Connection,
        evidence: MssqlDriverEvidence,
        cancellation_acknowledgement_timeout_seconds: float,
    ) -> None:
        self._connection = connection
        self._evidence = evidence
        self._cancellation_acknowledgement_timeout_seconds = (
            cancellation_acknowledgement_timeout_seconds
        )
        self._owner_thread_id = get_ident()
        self._state_changed = Condition(Lock())
        self._closed = False
        self._active_query_id: UUID | None = None
        self._active_cursor: pyodbc.Cursor | None = None
        self._cancel_requested = False
        self._cancel_calls = 0

    @property
    def evidence(self) -> MssqlDriverEvidence:
        return self._evidence

    @property
    def closed(self) -> bool:
        with self._state_changed:
            return self._closed

    @property
    def active_query_id(self) -> UUID | None:
        with self._state_changed:
            return self._active_query_id

    def execute_bounded(
        self,
        query: MssqlQuery,
        limits: MssqlFetchLimits,
    ) -> MssqlReadResult:
        self._require_owner_thread()
        self._require_open()
        cursor: pyodbc.Cursor | None = None
        published = False
        rows: list[MssqlRow] = []
        fetched_bytes = 0
        fetch_calls = 0
        largest_batch_records = 0
        try:
            cursor = self._connection.cursor()
            cursor.arraysize = limits.fetch_batch_records
            self._publish_active_query(query.query_id, cursor)
            published = True
            if self._is_cancel_requested(query.query_id):
                self._raise_confirmed_cancellation(cursor, query.query_id, "before-dispatch")

            statement = f"/* dfe_query_id={query.query_id} */\n{query.statement}"
            if query.parameters:
                cursor.execute(statement, query.parameters)
            else:
                cursor.execute(statement)
            if self._is_cancel_requested(query.query_id):
                self._raise_confirmed_cancellation(cursor, query.query_id, "raced-success")
            expected_column_count = _validate_result_description(cursor.description, limits)

            while True:
                remaining_with_overflow_probe = limits.max_records + 1 - len(rows)
                fetch_size = min(limits.fetch_batch_records, remaining_with_overflow_probe)
                raw_batch = cursor.fetchmany(fetch_size)
                fetch_calls += 1
                largest_batch_records = max(largest_batch_records, len(raw_batch))
                if self._is_cancel_requested(query.query_id):
                    self._raise_confirmed_cancellation(
                        cursor,
                        query.query_id,
                        "raced-success",
                    )
                if not raw_batch:
                    break

                validated_batch: list[MssqlRow] = []
                batch_bytes = 0
                for raw_row in raw_batch:
                    row, row_bytes = _validated_driver_row(
                        raw_row,
                        expected_column_count,
                        limits.max_value_bytes,
                        limits.max_record_bytes,
                    )
                    validated_batch.append(row)
                    batch_bytes += row_bytes

                if len(rows) + len(validated_batch) > limits.max_records:
                    raise MssqlResultLimitError(
                        "SQL Server result exceeded max_records: "
                        f"query_id={query.query_id}, max_records={limits.max_records}"
                    )
                if fetched_bytes + batch_bytes > limits.max_total_bytes:
                    raise MssqlResultLimitError(
                        "SQL Server result exceeded max_total_bytes: "
                        f"query_id={query.query_id}, max_total_bytes={limits.max_total_bytes}"
                    )
                rows.extend(validated_batch)
                fetched_bytes += batch_bytes

            if self._finish_success(query.query_id, cursor):
                self._raise_confirmed_cancellation(cursor, query.query_id, "raced-success")
            return MssqlReadResult(
                rows=tuple(rows),
                metrics=MssqlReadMetrics(
                    fetched_records=len(rows),
                    fetched_bytes=fetched_bytes,
                    fetch_calls=fetch_calls,
                    largest_batch_records=largest_batch_records,
                ),
            )
        except pyodbc.Error as error:
            sqlstate = _sqlstate(error)
            if published and cursor is not None:
                cancel_requested = self._detach_terminal_cursor(query.query_id, cursor)
                if cancel_requested:
                    self._raise_confirmed_cancellation_from_detached(
                        cursor,
                        query.query_id,
                        sqlstate,
                    )
                if sqlstate in ("HYT00", "HYT01"):
                    self._raise_confirmed_timeout_from_detached(
                        cursor,
                        query.query_id,
                        sqlstate,
                    )
            self._retire_after_query_error(cursor, query.query_id)
            raise MssqlQueryError(query.query_id, self._evidence.session_id, sqlstate) from None
        except UnicodeDecodeError:
            if published and cursor is not None:
                cancellation_evidence = self._interrupt_and_retire(cursor, query.query_id)
                self._raise_raced_cancellation(query.query_id, cancellation_evidence)
            elif cursor is not None:
                self._close_unpublished_cursor(cursor, query.query_id)
            raise MssqlLossyTransportError(
                f"ODBC returned text that cannot be decoded losslessly: query_id={query.query_id}"
            ) from None
        except OverflowError:
            if published and cursor is not None:
                cancellation_evidence = self._interrupt_and_retire(cursor, query.query_id)
                self._raise_raced_cancellation(query.query_id, cancellation_evidence)
            elif cursor is not None:
                self._close_unpublished_cursor(cursor, query.query_id)
            raise MssqlDataValidationError(
                "ODBC value conversion exceeded its supported numeric range: "
                f"query_id={query.query_id}"
            ) from None
        except MssqlCloseError:
            raise
        except MssqlCancellationError:
            raise
        except MssqlTransportError:
            if published and cursor is not None:
                cancellation_evidence = self._interrupt_and_retire(cursor, query.query_id)
                self._raise_raced_cancellation(query.query_id, cancellation_evidence)
            elif cursor is not None:
                self._close_unpublished_cursor(cursor, query.query_id)
            raise

    def cancel(self, query_id: UUID) -> None:
        if type(query_id) is not UUID:
            raise TypeError("query_id must be a UUID")
        if get_ident() == self._owner_thread_id:
            raise MssqlThreadOwnershipError(
                "SQL Server cancel must be called from the transport owner's supervisor thread"
            )
        deadline = time.monotonic() + self._cancellation_acknowledgement_timeout_seconds
        with self._state_changed:
            self._validate_cancellation_target_locked(query_id)
            if self._cancel_requested:
                self._wait_for_cancellation_acknowledgement_locked(query_id, deadline)
                return
            self._cancel_requested = True
        while True:
            with self._state_changed:
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise self._cancellation_request_timeout(query_id)
                if self._active_query_id != query_id or self._active_cursor is None:
                    return
                cursor = self._active_cursor
                self._cancel_calls += 1
            try:
                cursor.cancel()
            except pyodbc.Error as error:
                LOGGER.warning(
                    "SQL Server cancellation request returned an ODBC diagnostic",
                    extra={
                        "query_id": str(query_id),
                        "session_id": self._evidence.session_id,
                        "sqlstate": _sqlstate(error),
                    },
                )
            finally:
                with self._state_changed:
                    self._cancel_calls -= 1
                    self._state_changed.notify_all()
            with self._state_changed:
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise self._cancellation_request_timeout(query_id)
                if not self._query_handle_is_active_locked(query_id):
                    return
                self._state_changed.wait(min(0.05, remaining_seconds))

    def close(self) -> None:
        self._require_owner_thread()
        with self._state_changed:
            if self._closed:
                return
            if self._active_query_id is not None:
                raise MssqlTransportError(
                    "SQL Server transport cannot close while a query is active: "
                    f"query_id={self._active_query_id}"
                )
            self._closed = True
            self._state_changed.notify_all()
        try:
            self._connection.close()
        except pyodbc.Error:
            raise MssqlCloseError("SQL Server connection close failed") from None

    def _publish_active_query(self, query_id: UUID, cursor: pyodbc.Cursor) -> None:
        with self._state_changed:
            if self._closed:
                raise MssqlTransportClosedError("SQL Server transport is already closed")
            if self._active_query_id is not None:
                raise MssqlTransportError(
                    "SQL Server transport already has an active query: "
                    f"query_id={self._active_query_id}"
                )
            if self._cancel_calls != 0:
                raise MssqlTransportError(
                    "SQL Server cancellation bookkeeping was not quiescent before dispatch"
                )
            self._active_query_id = query_id
            self._active_cursor = cursor
            self._cancel_requested = False
            self._state_changed.notify_all()

    def _validate_cancellation_target_locked(self, query_id: UUID) -> None:
        if self._closed:
            raise MssqlTransportClosedError("SQL Server transport is already closed")
        if self._active_query_id is None:
            raise MssqlNoActiveQueryError("SQL Server transport has no active query")
        if self._active_query_id != query_id:
            raise MssqlWrongQueryIdError(
                "SQL Server cancellation query_id does not match the active query: "
                f"requested={query_id}, active={self._active_query_id}"
            )
        if self._active_cursor is None:
            raise MssqlNoActiveQueryError(
                "SQL Server query reached its atomic terminal point before cancellation"
            )

    def _is_cancel_requested(self, query_id: UUID) -> bool:
        with self._state_changed:
            return self._active_query_id == query_id and self._cancel_requested

    def _finish_success(self, query_id: UUID, cursor: pyodbc.Cursor) -> bool:
        with self._state_changed:
            if self._active_query_id != query_id or self._active_cursor is not cursor:
                raise MssqlTransportError(
                    "SQL Server active query state changed before successful completion"
                )
            if self._cancel_requested:
                return True
            while self._cancel_calls > 0:
                self._state_changed.wait()
                if self._cancel_requested:
                    return True
            self._clear_active_query_locked()
            self._state_changed.notify_all()
        try:
            cursor.close()
        except pyodbc.Error:
            self._retire_connection_after_terminal_query(query_id)
            raise MssqlCloseError(
                "SQL Server cursor close failed after a successful bounded read: "
                f"query_id={query_id}"
            ) from None
        return False

    def _raise_confirmed_cancellation(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
        sqlstate: str,
    ) -> None:
        self._detach_terminal_cursor(query_id, cursor)
        self._raise_confirmed_cancellation_from_detached(cursor, query_id, sqlstate)

    def _raise_confirmed_cancellation_from_detached(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
        sqlstate: str,
    ) -> None:
        confirmation_session_id, confirmation_value = self._confirm_detached_terminal_statement(
            cursor, query_id
        )
        raise MssqlCancellationConfirmedError(
            query_id,
            self._evidence.session_id,
            sqlstate,
            confirmation_session_id,
            confirmation_value,
        )

    def _raise_confirmed_timeout_from_detached(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
        sqlstate: str,
    ) -> None:
        self._confirm_detached_terminal_statement(cursor, query_id)
        raise MssqlQueryTimeoutError(query_id, self._evidence.session_id, sqlstate)

    def _interrupt_and_retire(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
    ) -> _MssqlCancellationEvidence:
        cancel_requested = self._detach_terminal_cursor(query_id, cursor)
        try:
            cursor.cancel()
        except pyodbc.Error as error:
            LOGGER.warning(
                "SQL Server result interruption returned an ODBC diagnostic",
                extra={
                    "query_id": str(query_id),
                    "session_id": self._evidence.session_id,
                    "sqlstate": _sqlstate(error),
                },
            )
        confirmation_session_id, confirmation_value = self._confirm_detached_terminal_statement(
            cursor, query_id
        )
        return _MssqlCancellationEvidence(
            requested=cancel_requested,
            confirmation_session_id=confirmation_session_id,
            confirmation_value=confirmation_value,
        )

    def _raise_raced_cancellation(
        self,
        query_id: UUID,
        evidence: _MssqlCancellationEvidence,
    ) -> None:
        if evidence.requested:
            raise MssqlCancellationConfirmedError(
                query_id,
                self._evidence.session_id,
                "raced-local-failure",
                evidence.confirmation_session_id,
                evidence.confirmation_value,
            )

    def _confirm_detached_terminal_statement(
        self,
        cursor: pyodbc.Cursor,
        query_id: UUID,
    ) -> tuple[int, int]:
        try:
            cursor.close()
            self._connection.timeout = max(
                1,
                math.ceil(self._cancellation_acknowledgement_timeout_seconds),
            )
            confirmation_cursor = self._connection.cursor()
            try:
                confirmation_row = confirmation_cursor.execute(
                    "SELECT CONVERT(int, @@SPID), CONVERT(int, 1)"
                ).fetchone()
            finally:
                confirmation_cursor.close()
            confirmation_session_id, confirmation_value = _validated_confirmation_row(
                confirmation_row
            )
            if confirmation_session_id != self._evidence.session_id:
                raise MssqlCancellationUnconfirmedError(
                    query_id,
                    self._evidence.session_id,
                    "confirmation used a different SQL Server session",
                )
            if confirmation_value != _CONFIRMATION_SENTINEL:
                raise MssqlCancellationUnconfirmedError(
                    query_id,
                    self._evidence.session_id,
                    "confirmation sentinel was not returned",
                )
        except MssqlCancellationUnconfirmedError:
            self._retire_connection_after_terminal_query(query_id)
            raise
        except (pyodbc.Error, MssqlDataValidationError):
            self._retire_connection_after_terminal_query(query_id)
            raise MssqlCancellationUnconfirmedError(
                query_id,
                self._evidence.session_id,
                "same-session completion probe failed",
            ) from None

        self._retire_connection_after_terminal_query(query_id)
        return confirmation_session_id, confirmation_value

    def _detach_terminal_cursor(self, query_id: UUID, cursor: pyodbc.Cursor) -> bool:
        with self._state_changed:
            while self._cancel_calls > 0:
                self._state_changed.wait()
            identity_matches = self._active_query_id == query_id and self._active_cursor is cursor
            if identity_matches:
                cancel_requested = self._cancel_requested
                self._active_cursor = None
                self._state_changed.notify_all()
                return cancel_requested
        self._retire_connection_after_terminal_query(query_id)
        raise MssqlCancellationUnconfirmedError(
            query_id,
            self._evidence.session_id,
            "active statement identity changed before confirmation",
        )

    def _retire_after_query_error(
        self,
        cursor: pyodbc.Cursor | None,
        query_id: UUID,
    ) -> None:
        with self._state_changed:
            if self._active_query_id == query_id:
                self._active_cursor = None
                self._state_changed.notify_all()
        if cursor is not None:
            try:
                cursor.close()
            except pyodbc.Error:
                LOGGER.warning(
                    "SQL Server cursor close failed during query-error retirement",
                    extra={
                        "query_id": str(query_id),
                        "session_id": self._evidence.session_id,
                    },
                )
        self._retire_connection_after_terminal_query(query_id)

    def _close_unpublished_cursor(self, cursor: pyodbc.Cursor, query_id: UUID) -> None:
        try:
            cursor.close()
        except pyodbc.Error:
            LOGGER.warning(
                "SQL Server unpublished cursor close failed",
                extra={
                    "query_id": str(query_id),
                    "session_id": self._evidence.session_id,
                },
            )

    def _retire_connection_after_terminal_query(self, query_id: UUID) -> None:
        with self._state_changed:
            self._clear_active_query_locked()
            self._closed = True
            self._state_changed.notify_all()
        try:
            self._connection.close()
        except pyodbc.Error:
            LOGGER.warning(
                "SQL Server connection close failed during terminal retirement",
                extra={
                    "query_id": str(query_id),
                    "session_id": self._evidence.session_id,
                },
            )

    def _clear_active_query_locked(self) -> None:
        self._active_query_id = None
        self._active_cursor = None
        self._cancel_requested = False

    def _wait_for_cancellation_acknowledgement_locked(
        self,
        query_id: UUID,
        deadline: float,
    ) -> None:
        while self._active_query_id == query_id and self._active_cursor is not None:
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise self._cancellation_request_timeout(query_id)
            self._state_changed.wait(remaining_seconds)
        if deadline - time.monotonic() <= 0:
            raise self._cancellation_request_timeout(query_id)

    def _query_handle_is_active_locked(self, query_id: UUID) -> bool:
        return self._active_query_id == query_id and self._active_cursor is not None

    def _cancellation_request_timeout(
        self,
        query_id: UUID,
    ) -> MssqlCancellationRequestTimeoutError:
        return MssqlCancellationRequestTimeoutError(
            "SQL Server worker did not acknowledge cancellation before the deadline: "
            f"query_id={query_id}, session_id={self._evidence.session_id}"
        )

    def _require_owner_thread(self) -> None:
        if get_ident() != self._owner_thread_id:
            raise MssqlThreadOwnershipError(
                "SQL Server connection operations must run on the transport owner thread"
            )

    def _require_open(self) -> None:
        with self._state_changed:
            if self._closed:
                raise MssqlTransportClosedError("SQL Server transport is already closed")


def open_mssql_transport(
    settings: MssqlConnectionSettings,
    retry_policy: MssqlRetryPolicy,
) -> MssqlTransport:
    if type(settings) is not MssqlConnectionSettings:
        raise TypeError("settings must be MssqlConnectionSettings")
    if type(retry_policy) is not MssqlRetryPolicy:
        raise TypeError("retry_policy must be MssqlRetryPolicy")

    last_error: MssqlConnectionError | None = None
    for attempt_number in range(1, retry_policy.max_attempts + 1):
        try:
            return _open_mssql_transport_once(settings)
        except MssqlConnectionError as error:
            last_error = error
            if attempt_number == retry_policy.max_attempts:
                break
            LOGGER.warning(
                "SQL Server connection attempt failed",
                extra={
                    "attempt_number": attempt_number,
                    "max_attempts": retry_policy.max_attempts,
                    "host": settings.host,
                    "port": settings.port,
                    "database": settings.database,
                    "user": settings.user,
                },
            )
            time.sleep(retry_policy.delay_seconds)

    if last_error is None:
        raise AssertionError("SQL Server connection retry loop did not execute")
    raise last_error


def _open_mssql_transport_once(settings: MssqlConnectionSettings) -> MssqlTransport:
    connection: pyodbc.Connection | None = None
    try:
        connection = pyodbc.connect(
            _build_connection_string(settings),
            autocommit=False,
            readonly=True,
            timeout=settings.login_timeout_seconds,
        )
        connection.timeout = settings.query_timeout_seconds
        evidence = _read_driver_evidence(connection)
        return MssqlTransport(
            connection,
            evidence,
            settings.cancellation_acknowledgement_timeout_seconds,
        )
    except pyodbc.Error as error:
        connection_close_failed = _close_failed_connection(connection)
        raise MssqlConnectionError(
            "SQL Server connection or profile query failed: "
            f"host={settings.host!r}, port={settings.port}, "
            f"database={settings.database!r}, user={settings.user!r}, "
            f"sqlstate={_sqlstate(error)!r}, "
            f"connection_close_failed={connection_close_failed}"
        ) from None
    except MssqlDataValidationError as error:
        connection_close_failed = _close_failed_connection(connection)
        raise MssqlConnectionError(
            "SQL Server profile validation failed: "
            f"host={settings.host!r}, port={settings.port}, "
            f"database={settings.database!r}, user={settings.user!r}, "
            f"validation_error={type(error).__name__!r}, "
            f"connection_close_failed={connection_close_failed}"
        ) from None


def _read_driver_evidence(connection: pyodbc.Connection) -> MssqlDriverEvidence:
    driver_name = _required_driver_text(connection.getinfo(pyodbc.SQL_DRIVER_NAME), "driver name")
    driver_version = _required_driver_text(
        connection.getinfo(pyodbc.SQL_DRIVER_VER),
        "driver version",
    )
    cursor = connection.cursor()
    try:
        row = cursor.execute(
            "SELECT CONVERT(nvarchar(128), SERVERPROPERTY(N'ProductVersion')), CONVERT(int, @@SPID)"
        ).fetchone()
    finally:
        cursor.close()
    if row is None or len(row) != 2:
        raise MssqlDataValidationError("SQL Server profile query did not return one profile row")
    server_version: object = row[0]
    session_id: object = row[1]
    if type(server_version) is not str or not server_version:
        raise MssqlDataValidationError("SQL Server profile returned an invalid server version")
    if type(session_id) is not int or session_id < 1:
        raise MssqlDataValidationError("SQL Server profile returned an invalid session ID")
    connection.rollback()
    return MssqlDriverEvidence(
        pyodbc_version=pyodbc.version,
        driver_name=driver_name,
        driver_version=driver_version,
        server_version=server_version,
        session_id=session_id,
    )


def _close_failed_connection(connection: pyodbc.Connection | None) -> bool:
    if connection is None:
        return False
    try:
        connection.close()
    except pyodbc.Error:
        return True
    return False


def _build_connection_string(settings: MssqlConnectionSettings) -> str:
    trust_server_certificate = (
        "Yes"
        if settings.tls_verification is MssqlTlsVerification.TRUST_FIXTURE_CERTIFICATE
        else "No"
    )
    values = (
        ("Driver", _DRIVER_NAME),
        ("Server", f"tcp:{settings.host},{settings.port}"),
        ("Database", settings.database),
        ("UID", settings.user),
        ("PWD", settings.password.get_secret_value()),
        ("Encrypt", "Mandatory"),
        ("TrustServerCertificate", trust_server_certificate),
        ("ApplicationIntent", "ReadOnly"),
        ("MARS_Connection", "No"),
        ("ConnectRetryCount", "0"),
        ("LongAsMax", "Yes"),
        ("APP", settings.application_name),
    )
    return ";".join(f"{key}={_odbc_braced(value)}" for key, value in values)


def _odbc_braced(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"


def _required_driver_text(value: object, field_name: str) -> str:
    if type(value) is not str or not value:
        raise MssqlDataValidationError(f"ODBC returned an invalid {field_name}")
    return value


def _validate_parameter(parameter: object) -> None:
    if type(parameter) is str:
        _validate_odbc_text_scalar(parameter, "SQL Server string parameters")
        return
    if type(parameter) in (int, bytes):
        return
    if type(parameter) is Decimal and parameter.is_finite():
        return
    raise TypeError("SQL Server parameters must be finite Decimal, str, int, or bytes values")


def _validate_odbc_text_scalar(value: str, field_name: str) -> None:
    if "\x00" in value:
        raise ValueError(f"{field_name} must not contain U+0000")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ValueError(f"{field_name} must not contain unpaired surrogates") from None


def _validate_result_description(
    description: object,
    limits: MssqlFetchLimits,
) -> int:
    if type(description) is not tuple or not description:
        raise MssqlDataValidationError("SQL Server query must return a described result set")
    columns = cast(tuple[object, ...], description)
    declared_record_bytes = 0
    for column_index, raw_column in enumerate(columns):
        if type(raw_column) is not tuple:
            raise MssqlDataValidationError(
                f"ODBC returned invalid result metadata: column_index={column_index}"
            )
        column = cast(tuple[object, ...], raw_column)
        if len(column) != 7:
            raise MssqlDataValidationError(
                f"ODBC returned invalid result metadata: column_index={column_index}"
            )
        type_code: object = column[1]
        column_size: object = column[3]
        if type(column_size) is not int or column_size < 1:
            raise MssqlResultLimitError(
                "SQL Server result column has unknown or unbounded size: "
                f"column_index={column_index}"
            )
        declared_max_bytes = _declared_value_max_bytes(type_code, column_size, column_index)
        if declared_max_bytes > limits.max_value_bytes:
            raise MssqlResultLimitError(
                "SQL Server result column exceeds max_value_bytes before fetch: "
                f"column_index={column_index}, declared_max_bytes={declared_max_bytes}, "
                f"max_value_bytes={limits.max_value_bytes}"
            )
        declared_record_bytes += declared_max_bytes
    if declared_record_bytes > limits.max_record_bytes:
        raise MssqlResultLimitError(
            "SQL Server declared row exceeds max_record_bytes before fetch: "
            f"declared_max_bytes={declared_record_bytes}, "
            f"max_record_bytes={limits.max_record_bytes}"
        )
    return len(columns)


def _declared_value_max_bytes(
    type_code: object,
    column_size: int,
    column_index: int,
) -> int:
    if type_code is str:
        return column_size * 4
    if type_code is Decimal:
        return column_size + 3
    if type_code is int:
        return column_size + 1
    if type_code is bool:
        return 1
    if type_code is bytes:
        return column_size
    if (
        type_code is float
        or type_code is date
        or type_code is datetime
        or type_code is datetime_time
    ):
        return max(column_size * 4, 64)
    raise MssqlDataValidationError(
        "ODBC returned unsupported result type metadata: "
        f"column_index={column_index}, type_code={type_code!r}"
    )


def _validated_driver_row(
    raw_row: object,
    expected_column_count: int,
    max_value_bytes: int,
    max_record_bytes: int,
) -> tuple[MssqlRow, int]:
    if not isinstance(raw_row, pyodbc.Row):
        raise MssqlDataValidationError("ODBC fetch returned a non-row value")
    if len(raw_row) != expected_column_count:
        raise MssqlDataValidationError(
            "ODBC row arity differs from its result description: "
            f"expected={expected_column_count}, actual={len(raw_row)}"
        )
    values: list[MssqlValue] = []
    record_bytes = 0
    for column_index in range(len(raw_row)):
        raw_value: object = raw_row[column_index]
        value, value_bytes = _validated_driver_value(raw_value, column_index)
        if value_bytes > max_value_bytes:
            raise MssqlResultLimitError(
                "SQL Server value exceeds max_value_bytes after fetch: "
                f"column_index={column_index}, value_bytes={value_bytes}, "
                f"max_value_bytes={max_value_bytes}"
            )
        values.append(value)
        record_bytes += value_bytes
    if record_bytes > max_record_bytes:
        raise MssqlResultLimitError(
            "SQL Server row exceeds max_record_bytes after fetch: "
            f"record_bytes={record_bytes}, max_record_bytes={max_record_bytes}"
        )
    return tuple(values), record_bytes


def _validated_driver_value(raw_value: object, column_index: int) -> tuple[MssqlValue, int]:
    if raw_value is None:
        return None, 0
    if type(raw_value) is bool:
        return raw_value, 1
    if type(raw_value) is int:
        return raw_value, len(str(raw_value).encode("ascii"))
    if type(raw_value) is Decimal:
        if not raw_value.is_finite():
            raise MssqlDataValidationError(
                f"ODBC returned a non-finite Decimal: column_index={column_index}"
            )
        return raw_value, len(format(raw_value, "f").encode("ascii"))
    if type(raw_value) is str:
        try:
            encoded = raw_value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise MssqlLossyTransportError(
                f"ODBC returned text containing an unpaired surrogate: column_index={column_index}"
            ) from None
        return raw_value, len(encoded)
    if type(raw_value) is bytes:
        return raw_value, len(raw_value)
    if isinstance(raw_value, (float, date, datetime, datetime_time)):
        raise MssqlLossyTransportError(
            "ODBC returned a value with a lossy or unsupported native mapping: "
            f"column_index={column_index}, python_type={type(raw_value).__name__!r}; "
            "project temporal values as exact ISO text"
        )
    raise MssqlDataValidationError(
        "ODBC returned an unsupported Python value type: "
        f"column_index={column_index}, python_type={type(raw_value).__name__!r}"
    )


def _validated_confirmation_row(row: pyodbc.Row | None) -> tuple[int, int]:
    if row is None or len(row) != 2:
        raise MssqlDataValidationError("SQL Server cancellation probe returned no row")
    session_id: object = row[0]
    sentinel: object = row[1]
    if type(session_id) is not int or session_id < 1:
        raise MssqlDataValidationError(
            "SQL Server cancellation probe returned an invalid session ID"
        )
    if type(sentinel) is not int:
        raise MssqlDataValidationError("SQL Server cancellation probe returned an invalid sentinel")
    return session_id, sentinel


def _sqlstate(error: pyodbc.Error) -> str:
    if error.args and type(error.args[0]) is str:
        sqlstate = error.args[0]
        if len(sqlstate) == 5 and sqlstate.isascii() and sqlstate.isalnum():
            return sqlstate.upper()
    return "unknown"
