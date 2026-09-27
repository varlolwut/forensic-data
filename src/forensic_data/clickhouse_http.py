import math
import pickle
import re
import select
import socket
import struct
import time
from dataclasses import dataclass
from enum import StrEnum
from http.client import IncompleteRead as HttpIncompleteRead
from multiprocessing import get_context
from multiprocessing.context import BaseContext
from multiprocessing.process import BaseProcess
from typing import cast

from urllib3 import PoolManager, Timeout
from urllib3.exceptions import (
    ConnectTimeoutError,
    HTTPError,
    MaxRetryError,
    NameResolutionError,
    NewConnectionError,
    ProtocolError,
)
from urllib3.response import HTTPResponse

_CLICKHOUSE_ERROR_NAME = re.compile(
    rb"\(([A-Z][A-Z0-9_]*)\)(?: \(version [^\r\n]*\))?\s*\Z",
)
_CLICKHOUSE_ERROR_CODE = re.compile(r"[1-9][0-9]{0,9}\Z", re.ASCII)
_CLICKHOUSE_ERROR_CODE_IN_MESSAGE = re.compile(rb"(?:\A|\n)Code: ([1-9][0-9]{0,9})\.")
_CLICKHOUSE_MAX_ERROR_CODE = 2_147_483_647
_IDENTITY_ENCODINGS = frozenset((None, "", "identity"))
_IPC_HEADER = struct.Struct("!Q")
_IPC_OVERHEAD_BYTES = 65_536
CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES = 16 * 1024


class ClickHouseHttpDispatchState(StrEnum):
    NOT_SENT = "not_sent"
    UNKNOWN = "unknown"
    RESPONSE_RECEIVED = "response_received"


class ClickHouseHttpOutcomeKind(StrEnum):
    SUCCESS = "success"
    SERVER_ERROR = "server_error"
    RESULT_LIMIT = "result_limit"
    PROTOCOL_ERROR = "protocol_error"
    TRANSPORT_ERROR = "transport_error"


class ClickHouseHttpWorkerState(StrEnum):
    READY = "ready"
    BUSY = "busy"
    CLOSED = "closed"
    CLEANUP_UNCONFIRMED = "cleanup_unconfirmed"


class _BoundedBodyTerminalStatus(StrEnum):
    CLEAN = "clean"
    INCOMPLETE_PROTOCOL = "incomplete_protocol"
    ERROR = "error"


class ClickHouseHttpWorkerError(RuntimeError):
    """The isolated ClickHouse HTTP worker could not be started or reaped."""


class ClickHouseHttpWorkerStartupError(ClickHouseHttpWorkerError):
    """The isolated ClickHouse HTTP worker failed before accepting requests."""

    def __init__(self, cause_type: str, retryable: bool) -> None:
        if type(cause_type) is not str or not cause_type:
            raise ValueError("cause_type must be non-empty text")
        if type(retryable) is not bool:
            raise TypeError("retryable must be a boolean")
        self.cause_type = cause_type
        self.retryable = retryable
        super().__init__(
            "ClickHouse HTTP worker failed before accepting requests: "
            f"cause_type={cause_type!r}, retryable={retryable}"
        )


@dataclass(frozen=True, slots=True)
class ClickHouseHttpPoolConfig:
    ca_cert: str | None
    tls_preflight_url: str | None
    connect_timeout_seconds: int
    read_timeout_seconds: int
    max_ipc_message_bytes: int

    def __post_init__(self) -> None:
        for name, value in (
            ("connect_timeout_seconds", self.connect_timeout_seconds),
            ("read_timeout_seconds", self.read_timeout_seconds),
            ("max_ipc_message_bytes", self.max_ipc_message_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.ca_cert is not None and (type(self.ca_cert) is not str or not self.ca_cert):
            raise ValueError("ca_cert must be non-empty text when provided")
        if self.tls_preflight_url is not None and (
            type(self.tls_preflight_url) is not str
            or not self.tls_preflight_url.startswith("https://")
            or not self.tls_preflight_url.endswith("/ping")
        ):
            raise ValueError("tls_preflight_url must be an HTTPS /ping URL when provided")


@dataclass(frozen=True, slots=True)
class ClickHouseHttpRequest:
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    query_id: str
    max_response_bytes: int
    max_error_response_bytes: int
    dispatch_deadline_nanoseconds: int
    io_deadline_nanoseconds: int

    def __post_init__(self) -> None:
        for name, value in (("url", self.url), ("query_id", self.query_id)):
            if type(value) is not str or not value:
                raise ValueError(f"{name} must be non-empty text")
        if type(self.headers) is not tuple:
            raise TypeError("headers must be an immutable tuple")
        for header in self.headers:
            if (
                type(header) is not tuple
                or len(header) != 2
                or type(header[0]) is not str
                or type(header[1]) is not str
                or not header[0]
            ):
                raise TypeError("each HTTP header must be a non-empty text pair")
        if type(self.body) is not bytes:
            raise TypeError("body must be bytes")
        for name, value in (
            ("max_response_bytes", self.max_response_bytes),
            ("max_error_response_bytes", self.max_error_response_bytes),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name, value in (
            ("dispatch_deadline_nanoseconds", self.dispatch_deadline_nanoseconds),
            ("io_deadline_nanoseconds", self.io_deadline_nanoseconds),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.dispatch_deadline_nanoseconds > self.io_deadline_nanoseconds:
            raise ValueError("dispatch deadline must not exceed the HTTP I/O deadline")


@dataclass(frozen=True, slots=True)
class ClickHouseHttpOutcome:
    kind: ClickHouseHttpOutcomeKind
    dispatch_state: ClickHouseHttpDispatchState
    payload: bytes
    status_code: int | None
    response_query_id: str | None
    error_code: int | None
    error_name: str | None
    received_bytes: int
    truncated: bool
    cause_type: str | None

    def __post_init__(self) -> None:
        if type(self.kind) is not ClickHouseHttpOutcomeKind:
            raise TypeError("kind must be ClickHouseHttpOutcomeKind")
        if type(self.dispatch_state) is not ClickHouseHttpDispatchState:
            raise TypeError("dispatch_state must be ClickHouseHttpDispatchState")
        if type(self.payload) is not bytes:
            raise TypeError("payload must be bytes")
        if self.status_code is not None and (
            type(self.status_code) is not int or not 100 <= self.status_code <= 599
        ):
            raise ValueError("status_code must be a valid HTTP status when provided")
        for name, value in (
            ("response_query_id", self.response_query_id),
            ("error_name", self.error_name),
            ("cause_type", self.cause_type),
        ):
            if value is not None and (type(value) is not str or not value):
                raise ValueError(f"{name} must be non-empty text when provided")
        if self.error_code is not None and type(self.error_code) is not int:
            raise TypeError("error_code must be an integer when provided")
        if type(self.received_bytes) is not int or self.received_bytes < 0:
            raise ValueError("received_bytes must be a non-negative integer")
        if type(self.truncated) is not bool:
            raise TypeError("truncated must be a boolean")


@dataclass(frozen=True, slots=True)
class ClickHouseHttpExecution:
    outcome: ClickHouseHttpOutcome | None
    deadline_exceeded: bool

    def __post_init__(self) -> None:
        if self.outcome is not None and type(self.outcome) is not ClickHouseHttpOutcome:
            raise TypeError("outcome must be ClickHouseHttpOutcome when provided")
        if type(self.deadline_exceeded) is not bool:
            raise TypeError("deadline_exceeded must be a boolean")
        if self.outcome is None and not self.deadline_exceeded:
            raise ValueError("a missing HTTP outcome requires an exceeded deadline")


@dataclass(frozen=True, slots=True)
class _BoundedBodyRead:
    payload: bytes
    truncated: bool
    terminal_status: _BoundedBodyTerminalStatus
    cause_type: str | None


@dataclass(frozen=True, slots=True)
class _WorkerReady:
    pass


@dataclass(frozen=True, slots=True)
class _WorkerStartupFailure:
    cause_type: str
    retryable: bool


@dataclass(frozen=True, slots=True)
class _WorkerStop:
    pass


@dataclass(frozen=True, slots=True)
class _WorkerStopped:
    pass


class ClickHouseHttpWorker:
    """Single-owner process containing one retry-free urllib3 connection pool."""

    def __init__(
        self,
        process: BaseProcess,
        channel: socket.socket,
        max_ipc_message_bytes: int,
        cleanup_timeout_seconds: float,
    ) -> None:
        self._process = process
        self._channel = channel
        self._max_ipc_message_bytes = max_ipc_message_bytes
        self._cleanup_timeout_seconds = cleanup_timeout_seconds
        self._state = ClickHouseHttpWorkerState.READY

    @property
    def state(self) -> ClickHouseHttpWorkerState:
        return self._state

    def execute(
        self,
        request: ClickHouseHttpRequest,
        deadline_nanoseconds: int,
    ) -> ClickHouseHttpExecution:
        if self._state is not ClickHouseHttpWorkerState.READY:
            raise ClickHouseHttpWorkerError(
                f"ClickHouse HTTP worker is not ready: state={self._state.value!r}"
            )
        _require_deadline_value(deadline_nanoseconds)
        remaining_seconds = _remaining_seconds(deadline_nanoseconds)
        if remaining_seconds <= 0:
            return ClickHouseHttpExecution(
                outcome=_transport_error_outcome(
                    ClickHouseHttpDispatchState.NOT_SENT,
                    "AbsoluteDeadlineExceededBeforeIpcDispatch",
                ),
                deadline_exceeded=True,
            )
        try:
            _send_message(
                self._channel,
                request,
                deadline_nanoseconds,
                self._max_ipc_message_bytes,
            )
        except ClickHouseHttpWorkerError as error:
            return ClickHouseHttpExecution(
                outcome=_transport_error_outcome(
                    ClickHouseHttpDispatchState.NOT_SENT,
                    type(error).__name__,
                ),
                deadline_exceeded=False,
            )
        except TimeoutError:
            self._state = ClickHouseHttpWorkerState.BUSY
            return ClickHouseHttpExecution(outcome=None, deadline_exceeded=True)
        except (BrokenPipeError, EOFError, OSError) as error:
            self._state = ClickHouseHttpWorkerState.BUSY
            return ClickHouseHttpExecution(
                outcome=_transport_error_outcome(
                    ClickHouseHttpDispatchState.UNKNOWN,
                    type(error).__name__,
                ),
                deadline_exceeded=False,
            )
        self._state = ClickHouseHttpWorkerState.BUSY
        try:
            outcome = self._receive_outcome(deadline_nanoseconds)
            self._state = ClickHouseHttpWorkerState.READY
            return ClickHouseHttpExecution(
                outcome=outcome,
                deadline_exceeded=time.monotonic_ns() >= deadline_nanoseconds,
            )
        except TimeoutError:
            return ClickHouseHttpExecution(outcome=None, deadline_exceeded=True)

    def close(self) -> None:
        if self._state is ClickHouseHttpWorkerState.CLOSED:
            return
        if self._state is ClickHouseHttpWorkerState.BUSY:
            self.terminate()
            raise ClickHouseHttpWorkerError(
                "ClickHouse HTTP worker required forced cleanup for an active request"
            )
        cleanup_deadline = time.monotonic_ns() + int(self._cleanup_timeout_seconds * 1_000_000_000)
        try:
            try:
                _send_message(
                    self._channel,
                    _WorkerStop(),
                    cleanup_deadline,
                    self._max_ipc_message_bytes,
                )
                message = _receive_message(
                    self._channel,
                    cleanup_deadline,
                    self._max_ipc_message_bytes,
                )
                if type(message) is not _WorkerStopped:
                    raise ClickHouseHttpWorkerError(
                        "ClickHouse HTTP worker returned an invalid shutdown acknowledgement"
                    )
                self._process.join(_remaining_seconds(cleanup_deadline))
                if self._process.is_alive():
                    self._terminate_process(cleanup_deadline)
            except (
                BrokenPipeError,
                ClickHouseHttpWorkerError,
                EOFError,
                OSError,
                TimeoutError,
            ):
                self._terminate_process(cleanup_deadline)
        except ClickHouseHttpWorkerError:
            self._state = ClickHouseHttpWorkerState.CLEANUP_UNCONFIRMED
            self._channel.close()
            raise
        else:
            self._state = ClickHouseHttpWorkerState.CLOSED
            self._channel.close()

    def terminate(self) -> None:
        if self._state is ClickHouseHttpWorkerState.CLOSED:
            return
        cleanup_deadline = time.monotonic_ns() + int(self._cleanup_timeout_seconds * 1_000_000_000)
        try:
            self._terminate_process(cleanup_deadline)
        except ClickHouseHttpWorkerError:
            self._state = ClickHouseHttpWorkerState.CLEANUP_UNCONFIRMED
            self._channel.close()
            raise
        else:
            self._state = ClickHouseHttpWorkerState.CLOSED
            self._channel.close()

    def _receive_outcome(self, deadline_nanoseconds: int) -> ClickHouseHttpOutcome:
        try:
            message = _receive_message(
                self._channel,
                deadline_nanoseconds,
                self._max_ipc_message_bytes,
            )
        except TimeoutError:
            raise
        except (ClickHouseHttpWorkerError, EOFError, OSError) as error:
            return _transport_error_outcome(
                ClickHouseHttpDispatchState.UNKNOWN,
                type(error).__name__,
            )
        if type(message) is not ClickHouseHttpOutcome:
            return _transport_error_outcome(
                ClickHouseHttpDispatchState.UNKNOWN,
                "InvalidWorkerResponse",
            )
        return message

    def _terminate_process(self, cleanup_deadline: int) -> None:
        try:
            if not self._process.is_alive():
                self._process.join(0.0)
                return
            self._process.terminate()
            self._process.join(_remaining_seconds(cleanup_deadline))
            if not self._process.is_alive():
                return
            self._process.kill()
            self._process.join(_remaining_seconds(cleanup_deadline))
            if self._process.is_alive():
                raise ClickHouseHttpWorkerError(
                    "ClickHouse HTTP worker remained alive after terminate and kill"
                )
        except OSError as error:
            raise ClickHouseHttpWorkerError(
                "ClickHouse HTTP worker process cleanup failed: "
                f"cause_type={type(error).__name__!r}"
            ) from None


def start_clickhouse_http_worker(
    config: ClickHouseHttpPoolConfig,
    deadline_nanoseconds: int,
    cleanup_timeout_seconds: float,
) -> ClickHouseHttpWorker:
    if type(config) is not ClickHouseHttpPoolConfig:
        raise TypeError("config must be ClickHouseHttpPoolConfig")
    _require_deadline_value(deadline_nanoseconds)
    if (
        type(cleanup_timeout_seconds) is not float
        or not math.isfinite(cleanup_timeout_seconds)
        or cleanup_timeout_seconds <= 0
    ):
        raise ValueError("cleanup_timeout_seconds must be a finite positive float")
    context: BaseContext = get_context("spawn")
    parent_channel, child_channel = socket.socketpair()
    parent_channel.setblocking(False)
    process = context.Process(
        target=_clickhouse_http_worker_main,
        args=(child_channel, config, deadline_nanoseconds),
        daemon=True,
    )
    try:
        process.start()
    except (AssertionError, OSError, RuntimeError) as error:
        parent_channel.close()
        child_channel.close()
        raise ClickHouseHttpWorkerError(
            "failed to start the isolated ClickHouse HTTP worker: "
            f"cause_type={type(error).__name__!r}"
        ) from None
    child_channel.close()
    worker = ClickHouseHttpWorker(
        process,
        parent_channel,
        config.max_ipc_message_bytes,
        cleanup_timeout_seconds,
    )
    try:
        message = _receive_message(
            parent_channel,
            deadline_nanoseconds,
            config.max_ipc_message_bytes,
        )
    except (EOFError, OSError, TimeoutError) as error:
        worker.terminate()
        raise ClickHouseHttpWorkerError(
            "ClickHouse HTTP worker did not become ready before the absolute deadline: "
            f"cause_type={type(error).__name__!r}"
        ) from None
    if type(message) is _WorkerStartupFailure:
        worker.terminate()
        raise ClickHouseHttpWorkerStartupError(message.cause_type, message.retryable)
    if type(message) is not _WorkerReady:
        worker.terminate()
        raise ClickHouseHttpWorkerError(
            "ClickHouse HTTP worker returned an invalid startup acknowledgement"
        )
    return worker


def _clickhouse_http_worker_main(
    channel: socket.socket,
    config: ClickHouseHttpPoolConfig,
    startup_deadline_nanoseconds: int,
) -> None:
    channel.setblocking(False)
    pool: PoolManager | None = None
    try:
        pool = _new_pool_manager(config)
        if config.tls_preflight_url is not None:
            _verify_tls_pool(pool, config, startup_deadline_nanoseconds)
    except (ClickHouseHttpWorkerError, HTTPError, OSError, TimeoutError, ValueError) as error:
        if pool is not None:
            pool.clear()
        try:
            _send_message(
                channel,
                _WorkerStartupFailure(
                    cause_type=_startup_cause_type(error),
                    retryable=_startup_failure_is_retryable(error),
                ),
                startup_deadline_nanoseconds,
                config.max_ipc_message_bytes,
            )
        finally:
            channel.close()
        return
    try:
        _send_message(
            channel,
            _WorkerReady(),
            startup_deadline_nanoseconds,
            config.max_ipc_message_bytes,
        )
    except (BrokenPipeError, EOFError, OSError, TimeoutError):
        pool.clear()
        channel.close()
        return
    try:
        while True:
            try:
                message = _receive_message(
                    channel,
                    None,
                    config.max_ipc_message_bytes,
                )
            except (EOFError, OSError):
                return
            if type(message) is _WorkerStop:
                pool.clear()
                _send_message(
                    channel,
                    _WorkerStopped(),
                    time.monotonic_ns() + 1_000_000_000,
                    config.max_ipc_message_bytes,
                )
                return
            if type(message) is not ClickHouseHttpRequest:
                _send_message(
                    channel,
                    _transport_error_outcome(
                        ClickHouseHttpDispatchState.NOT_SENT,
                        "InvalidWorkerRequest",
                    ),
                    time.monotonic_ns() + 1_000_000_000,
                    config.max_ipc_message_bytes,
                )
                continue
            try:
                _send_message(
                    channel,
                    _execute_http_request(pool, config, message),
                    message.io_deadline_nanoseconds,
                    config.max_ipc_message_bytes,
                )
            except TimeoutError:
                return
    finally:
        pool.clear()
        channel.close()


def _new_pool_manager(config: ClickHouseHttpPoolConfig) -> PoolManager:
    if config.ca_cert is not None:
        return PoolManager(
            num_pools=1,
            maxsize=1,
            block=True,
            cert_reqs="CERT_REQUIRED",
            ca_certs=config.ca_cert,
        )
    return PoolManager(
        num_pools=1,
        maxsize=1,
        block=True,
        cert_reqs="CERT_REQUIRED",
    )


def _verify_tls_pool(
    pool: PoolManager,
    config: ClickHouseHttpPoolConfig,
    deadline_nanoseconds: int,
) -> None:
    if config.tls_preflight_url is None:
        raise ValueError("TLS pool preflight requires an HTTPS /ping URL")
    remaining_seconds = _remaining_seconds(deadline_nanoseconds)
    if remaining_seconds <= 0:
        raise TimeoutError("TLS pool preflight deadline expired before dispatch")
    timeout = Timeout(
        total=remaining_seconds,
        connect=min(float(config.connect_timeout_seconds), remaining_seconds),
        read=min(float(config.read_timeout_seconds), remaining_seconds),
    )
    response = pool.request(
        "GET",
        config.tls_preflight_url,
        preload_content=False,
        decode_content=False,
        redirect=False,
        retries=False,
        timeout=timeout,
        pool_timeout=remaining_seconds,
    )
    if not isinstance(response, HTTPResponse):
        raise ClickHouseHttpWorkerError("TLS pool preflight returned an invalid HTTP response")
    try:
        body_read = _read_bounded_body(response, 4)
        if (
            response.status != 200
            or response.headers.get("Content-Encoding") not in _IDENTITY_ENCODINGS
            or body_read.payload != b"Ok.\n"
            or body_read.truncated
            or body_read.terminal_status is not _BoundedBodyTerminalStatus.CLEAN
        ):
            raise ClickHouseHttpWorkerError(
                "TLS pool preflight did not return the bounded ClickHouse ping response"
            )
    finally:
        _discard_response(response)


def _execute_http_request(
    pool: PoolManager,
    config: ClickHouseHttpPoolConfig,
    request: ClickHouseHttpRequest,
) -> ClickHouseHttpOutcome:
    remaining_io_seconds = _remaining_seconds(request.io_deadline_nanoseconds)
    if remaining_io_seconds <= 0:
        return _transport_error_outcome(
            ClickHouseHttpDispatchState.NOT_SENT,
            "AbsoluteHttpDeadlineExceededBeforeDispatch",
        )
    remaining_dispatch_seconds = _remaining_seconds(request.dispatch_deadline_nanoseconds)
    if remaining_dispatch_seconds <= 0:
        return _transport_error_outcome(
            ClickHouseHttpDispatchState.NOT_SENT,
            "AbsoluteDispatchDeadlineExceededBeforeDispatch",
        )
    timeout = Timeout(
        total=remaining_io_seconds,
        connect=min(float(config.connect_timeout_seconds), remaining_dispatch_seconds),
        read=min(float(config.read_timeout_seconds), remaining_io_seconds),
    )
    if time.monotonic_ns() >= request.dispatch_deadline_nanoseconds:
        return _transport_error_outcome(
            ClickHouseHttpDispatchState.NOT_SENT,
            "AbsoluteDispatchDeadlineExceededBeforeDispatch",
        )
    try:
        response = pool.request(
            "POST",
            request.url,
            body=request.body,
            headers=dict(request.headers),
            preload_content=False,
            decode_content=False,
            redirect=False,
            retries=False,
            timeout=timeout,
            pool_timeout=remaining_dispatch_seconds,
        )
    except HTTPError as error:
        return _transport_error_outcome(
            _http_error_dispatch_state(error),
            _safe_cause_type(error),
        )
    except OSError as error:
        return _transport_error_outcome(
            ClickHouseHttpDispatchState.UNKNOWN,
            type(error).__name__,
        )
    if not isinstance(response, HTTPResponse):
        return _transport_error_outcome(
            ClickHouseHttpDispatchState.UNKNOWN,
            "InvalidHttpResponse",
        )
    return _read_http_response(response, request)


def _read_http_response(
    response: HTTPResponse,
    request: ClickHouseHttpRequest,
) -> ClickHouseHttpOutcome:
    status_code = response.status
    response_query_id = response.headers.get("X-ClickHouse-Query-Id")
    exception_code_text = response.headers.get("X-ClickHouse-Exception-Code")
    exception_tag = response.headers.get("X-ClickHouse-Exception-Tag")
    exception_code = _parse_error_code(exception_code_text)
    has_error_status = not 200 <= status_code < 300
    has_error_header = exception_code is not None
    if response_query_id != request.query_id:
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.PROTOCOL_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.UNKNOWN,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=exception_code,
            error_name=None,
            received_bytes=0,
            truncated=False,
            cause_type="QueryIdMismatch",
        )
    if exception_code_text is not None and exception_code is None:
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.PROTOCOL_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.UNKNOWN,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=None,
            error_name=None,
            received_bytes=0,
            truncated=False,
            cause_type="InvalidClickHouseExceptionCode",
        )
    if not _valid_exception_tag(exception_tag):
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.PROTOCOL_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.UNKNOWN,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=exception_code,
            error_name=None,
            received_bytes=0,
            truncated=False,
            cause_type="InvalidClickHouseExceptionTag",
        )
    content_encoding = response.headers.get("Content-Encoding")
    if content_encoding not in _IDENTITY_ENCODINGS:
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.PROTOCOL_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.RESPONSE_RECEIVED,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=_parse_error_code(exception_code_text),
            error_name=None,
            received_bytes=0,
            truncated=False,
            cause_type="UnexpectedContentEncoding",
        )
    response_limit = (
        request.max_error_response_bytes
        if has_error_status or has_error_header
        else request.max_response_bytes
    )
    capture_limit = (
        response_limit
        if has_error_status or has_error_header
        else response_limit + CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES
    )
    body_read = _read_bounded_body(response, capture_limit)
    exception_message = (
        None
        if body_read.truncated
        else _clickhouse_exception_message(body_read.payload, exception_tag)
    )
    has_incomplete_exception_frame = exception_message is None and _has_exception_frame_opening(
        body_read.payload,
        exception_tag,
    )
    expected_broken_protocol = (
        body_read.terminal_status is _BoundedBodyTerminalStatus.INCOMPLETE_PROTOCOL
        and exception_message is not None
    )
    if (
        body_read.terminal_status is not _BoundedBodyTerminalStatus.CLEAN
        and not expected_broken_protocol
    ):
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.PROTOCOL_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.UNKNOWN,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=exception_code,
            error_name=None,
            received_bytes=len(body_read.payload),
            truncated=body_read.truncated,
            cause_type=body_read.cause_type,
        )
    if has_incomplete_exception_frame:
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.PROTOCOL_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.UNKNOWN,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=exception_code,
            error_name=None,
            received_bytes=len(body_read.payload),
            truncated=body_read.truncated,
            cause_type="InvalidClickHouseExceptionFrame",
        )
    frame_error_code = (
        None if exception_message is None else _parse_error_code_from_body(exception_message)
    )
    frame_error_name = None if exception_message is None else _parse_error_name(exception_message)
    if (
        exception_message is not None
        and exception_code is not None
        and frame_error_code is not None
        and exception_code != frame_error_code
    ):
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.PROTOCOL_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.UNKNOWN,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=exception_code,
            error_name=None,
            received_bytes=len(body_read.payload),
            truncated=body_read.truncated,
            cause_type="InvalidClickHouseExceptionFrame",
        )
    if has_error_header or exception_message is not None:
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.SERVER_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.RESPONSE_RECEIVED,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=exception_code or frame_error_code,
            error_name=frame_error_name or _parse_error_name(body_read.payload),
            received_bytes=len(body_read.payload),
            truncated=body_read.truncated,
            cause_type=None,
        )
    if has_error_status:
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.PROTOCOL_ERROR,
            dispatch_state=ClickHouseHttpDispatchState.UNKNOWN,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=None,
            error_name=None,
            received_bytes=len(body_read.payload),
            truncated=body_read.truncated,
            cause_type="UnverifiedHttpError",
        )
    if len(body_read.payload) > request.max_response_bytes:
        _discard_response(response)
        return ClickHouseHttpOutcome(
            kind=ClickHouseHttpOutcomeKind.RESULT_LIMIT,
            dispatch_state=ClickHouseHttpDispatchState.RESPONSE_RECEIVED,
            payload=b"",
            status_code=status_code,
            response_query_id=response_query_id,
            error_code=None,
            error_name=None,
            received_bytes=len(body_read.payload),
            truncated=body_read.truncated,
            cause_type=None,
        )
    response.release_conn()
    return ClickHouseHttpOutcome(
        kind=ClickHouseHttpOutcomeKind.SUCCESS,
        dispatch_state=ClickHouseHttpDispatchState.RESPONSE_RECEIVED,
        payload=body_read.payload,
        status_code=status_code,
        response_query_id=response_query_id,
        error_code=None,
        error_name=None,
        received_bytes=len(body_read.payload),
        truncated=False,
        cause_type=None,
    )


def _read_bounded_body(response: HTTPResponse, limit: int) -> _BoundedBodyRead:
    chunks: list[bytes] = []
    received = 0
    while received <= limit:
        try:
            chunk = response.read1(
                min(65_536, limit + 1 - received),
                decode_content=False,
            )
        except ProtocolError as error:
            return _bounded_body_read_failure(
                chunks,
                received,
                limit,
                error,
                _BoundedBodyTerminalStatus.INCOMPLETE_PROTOCOL,
            )
        except HttpIncompleteRead as error:
            return _bounded_body_read_failure(
                chunks,
                received,
                limit,
                error,
                _BoundedBodyTerminalStatus.INCOMPLETE_PROTOCOL,
            )
        except HTTPError as error:
            return _bounded_body_read_failure(
                chunks,
                received,
                limit,
                error,
                _BoundedBodyTerminalStatus.ERROR,
            )
        except OSError as error:
            return _BoundedBodyRead(
                payload=b"".join(chunks),
                truncated=False,
                terminal_status=_BoundedBodyTerminalStatus.ERROR,
                cause_type=type(error).__name__,
            )
        if not chunk:
            terminal_status = (
                _BoundedBodyTerminalStatus.CLEAN
                if _response_eof_is_framed(response)
                else _BoundedBodyTerminalStatus.INCOMPLETE_PROTOCOL
            )
            return _BoundedBodyRead(
                payload=b"".join(chunks),
                truncated=False,
                terminal_status=terminal_status,
                cause_type=(
                    None
                    if terminal_status is _BoundedBodyTerminalStatus.CLEAN
                    else "UnframedHttpResponseEof"
                ),
            )
        chunks.append(chunk)
        received += len(chunk)
    return _BoundedBodyRead(
        payload=b"".join(chunks),
        truncated=True,
        terminal_status=_BoundedBodyTerminalStatus.CLEAN,
        cause_type=None,
    )


def _bounded_body_read_failure(
    chunks: list[bytes],
    received: int,
    limit: int,
    error: BaseException,
    terminal_status: _BoundedBodyTerminalStatus,
) -> _BoundedBodyRead:
    partial = _incomplete_read_partial(error)
    remaining_capacity = limit + 1 - received
    bounded_partial = partial[:remaining_capacity]
    payload = b"".join((*chunks, bounded_partial))
    return _BoundedBodyRead(
        payload=payload,
        truncated=len(partial) > remaining_capacity or len(payload) > limit,
        terminal_status=terminal_status,
        cause_type=(
            _safe_cause_type(error) if isinstance(error, HTTPError) else type(error).__name__
        ),
    )


def _response_eof_is_framed(response: HTTPResponse) -> bool:
    return response.chunked is True or response.length_remaining == 0


def _incomplete_read_partial(error: BaseException) -> bytes:
    for candidate in (error, error.__cause__, error.__context__):
        if isinstance(candidate, HttpIncompleteRead) and type(candidate.partial) is bytes:
            return candidate.partial
    return b""


def _discard_response(response: HTTPResponse) -> None:
    response.close()
    response.release_conn()


def _parse_error_code(value: str | None) -> int | None:
    if value is None or _CLICKHOUSE_ERROR_CODE.fullmatch(value) is None:
        return None
    code = int(value)
    return code if code <= _CLICKHOUSE_MAX_ERROR_CODE else None


def _parse_error_name(body: bytes) -> str | None:
    match = _CLICKHOUSE_ERROR_NAME.search(body)
    if match is None:
        return None
    return match.group(1).decode("ascii")


def _parse_error_code_from_body(body: bytes) -> int | None:
    match = _CLICKHOUSE_ERROR_CODE_IN_MESSAGE.search(body)
    if match is None:
        return None
    code = int(match.group(1))
    return code if code <= _CLICKHOUSE_MAX_ERROR_CODE else None


def _valid_exception_tag(exception_tag: str | None) -> bool:
    if exception_tag is None:
        return False
    try:
        tag = exception_tag.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        return False
    return len(tag) == 16


def _clickhouse_exception_message(body: bytes, exception_tag: str | None) -> bytes | None:
    if not _valid_exception_tag(exception_tag):
        return None
    if exception_tag is None:
        raise AssertionError("validated ClickHouse exception tag is missing")
    tag = exception_tag.encode("ascii", errors="strict")
    opening = b"\r\n__exception__\r\n" + tag + b"\r\n"
    closing = b" " + tag + b"\r\n__exception__\r\n"
    if not body.endswith(closing):
        return None
    closing_start = len(body) - len(closing)
    length_start = body.rfind(b"\n", 0, closing_start)
    if length_start < 0:
        return None
    length_start += 1
    length_text = body[length_start:closing_start]
    if re.fullmatch(rb"[1-9][0-9]{0,7}", length_text) is None:
        return None
    message_length = int(length_text)
    message_start = length_start - message_length
    opening_start = message_start - len(opening)
    if opening_start < 0 or body[opening_start:message_start] != opening:
        return None
    message = body[message_start:length_start]
    if not message.endswith(b"\n"):
        return None
    frame = body[opening_start:]
    if len(frame) > CLICKHOUSE_HTTP_EXCEPTION_FRAME_MAX_BYTES:
        return None
    return message


def _has_exception_frame_opening(body: bytes, exception_tag: str | None) -> bool:
    if not _valid_exception_tag(exception_tag):
        return False
    if exception_tag is None:
        raise AssertionError("validated ClickHouse exception tag is missing")
    tag = exception_tag.encode("ascii", errors="strict")
    return b"\r\n__exception__\r\n" + tag + b"\r\n" in body


def _http_error_dispatch_state(error: HTTPError) -> ClickHouseHttpDispatchState:
    candidate: BaseException = error
    if isinstance(error, MaxRetryError) and error.reason is not None:
        candidate = error.reason
    if isinstance(
        candidate,
        (ConnectTimeoutError, NameResolutionError, NewConnectionError),
    ):
        return ClickHouseHttpDispatchState.NOT_SENT
    return ClickHouseHttpDispatchState.UNKNOWN


def _safe_cause_type(error: HTTPError) -> str:
    if isinstance(error, MaxRetryError):
        return type(error.reason).__name__
    return type(error).__name__


def _startup_cause_type(error: BaseException) -> str:
    if isinstance(error, HTTPError):
        return _safe_cause_type(error)
    return type(error).__name__


def _startup_failure_is_retryable(error: BaseException) -> bool:
    candidate = error.reason if isinstance(error, MaxRetryError) else error
    return isinstance(
        candidate,
        (ConnectTimeoutError, NameResolutionError, NewConnectionError),
    )


def _transport_error_outcome(
    dispatch_state: ClickHouseHttpDispatchState,
    cause_type: str,
) -> ClickHouseHttpOutcome:
    return ClickHouseHttpOutcome(
        kind=ClickHouseHttpOutcomeKind.TRANSPORT_ERROR,
        dispatch_state=dispatch_state,
        payload=b"",
        status_code=None,
        response_query_id=None,
        error_code=None,
        error_name=None,
        received_bytes=0,
        truncated=False,
        cause_type=cause_type,
    )


def _remaining_seconds(deadline_nanoseconds: int) -> float:
    return max(0.0, (deadline_nanoseconds - time.monotonic_ns()) / 1_000_000_000)


def _require_deadline_value(deadline_nanoseconds: int) -> None:
    if type(deadline_nanoseconds) is not int or deadline_nanoseconds < 0:
        raise ValueError("deadline_nanoseconds must be a non-negative integer")


def _send_message(
    channel: socket.socket,
    message: object,
    deadline_nanoseconds: int,
    max_message_bytes: int,
) -> None:
    if _remaining_seconds(deadline_nanoseconds) <= 0:
        raise TimeoutError("ClickHouse HTTP IPC send exceeded its absolute deadline")
    payload = pickle.dumps(message, protocol=pickle.HIGHEST_PROTOCOL)
    if _remaining_seconds(deadline_nanoseconds) <= 0:
        raise TimeoutError("ClickHouse HTTP IPC serialization exceeded its absolute deadline")
    if len(payload) > max_message_bytes:
        raise ClickHouseHttpWorkerError(
            "ClickHouse HTTP IPC message exceeds its explicit byte bound: "
            f"max_message_bytes={max_message_bytes}, actual_message_bytes={len(payload)}"
        )
    framed = _IPC_HEADER.pack(len(payload)) + payload
    sent = 0
    while sent < len(framed):
        remaining_seconds = _remaining_seconds(deadline_nanoseconds)
        if remaining_seconds <= 0:
            raise TimeoutError("ClickHouse HTTP IPC send exceeded its absolute deadline")
        _, writable, _ = select.select([], [channel], [], remaining_seconds)
        if not writable:
            raise TimeoutError("ClickHouse HTTP IPC send exceeded its absolute deadline")
        written = channel.send(framed[sent:])
        if written == 0:
            raise EOFError("ClickHouse HTTP IPC channel closed during send")
        sent += written


def _receive_message(
    channel: socket.socket,
    deadline_nanoseconds: int | None,
    max_message_bytes: int,
) -> object:
    header = _receive_exact(channel, _IPC_HEADER.size, deadline_nanoseconds)
    (payload_size,) = _IPC_HEADER.unpack(header)
    if payload_size > max_message_bytes:
        raise ClickHouseHttpWorkerError(
            "ClickHouse HTTP IPC peer declared a message above the explicit byte bound: "
            f"max_message_bytes={max_message_bytes}, declared_message_bytes={payload_size}"
        )
    payload = _receive_exact(channel, payload_size, deadline_nanoseconds)
    return cast(
        object,
        pickle.loads(payload),
    )


def _receive_exact(
    channel: socket.socket,
    byte_count: int,
    deadline_nanoseconds: int | None,
) -> bytes:
    chunks: list[bytes] = []
    received = 0
    while received < byte_count:
        timeout_seconds = (
            None if deadline_nanoseconds is None else _remaining_seconds(deadline_nanoseconds)
        )
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise TimeoutError("ClickHouse HTTP IPC receive exceeded its absolute deadline")
        readable, _, _ = select.select([channel], [], [], timeout_seconds)
        if not readable:
            raise TimeoutError("ClickHouse HTTP IPC receive exceeded its absolute deadline")
        chunk = channel.recv(min(65_536, byte_count - received))
        if not chunk:
            raise EOFError("ClickHouse HTTP IPC channel closed during receive")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)
