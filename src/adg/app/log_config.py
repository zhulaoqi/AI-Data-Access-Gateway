"""Process-wide logging: one logfmt line per event, every line carries the request id.

Line layout (same as the gateway's Java services)::

    2026-10-28T14:25:51.123+08:00 INFO  sqlgw-executor [thread] logger rid=<id> event=... k=v

The request id comes from the caller's ``X-Request-Id`` (the control plane and the JDBC entry send
one) or is generated here, and is echoed back in the response. Never pass API keys, passwords,
hashes or SQL text to a log call; log ids, reason codes, counts and durations instead.
The event catalogue shared by all gateway services is ``sql-gateway/docs/ops/logging.md``.
"""

import logging
import re
import sys
import time
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any

APP_NAME = "sqlgw-executor"

_request_id: ContextVar[str | None] = ContextVar("adg_request_id", default=None)
_RID_SAFE = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")
_BARE = re.compile(r"^[^\s\"=]+$")
_QUIET_PATHS = frozenset(
    {"/health", "/ready", "/admin/ext/metrics", "/admin/ext/metrics/prometheus"}
)
_HANDLER_MARK = "_adg_logfmt"
_LOGGED_MARK = "_adg_logged"

access_logger = logging.getLogger("adg.access")
_error_logger = logging.getLogger("adg.error")


def current_request_id() -> str | None:
    return _request_id.get()


def kv(**fields: Any) -> str:
    """``key=value`` pairs; values with spaces, quotes or ``=`` are quoted, empty becomes ``-``."""

    parts = []
    for key, value in fields.items():
        if value is None or value == "":
            text = "-"
        elif isinstance(value, bool):
            text = "true" if value else "false"
        else:
            text = str(value).replace("\n", " ").replace("\r", " ")
            if not _BARE.match(text):
                text = '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
        parts.append(f"{key}={text}")
    return " ".join(parts)


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.rid = _request_id.get() or "-"
        return True


class _DropLoggedErrors(logging.Filter):
    """uvicorn repeats the traceback of an exception the request middleware already logged."""

    def filter(self, record: logging.LogRecord) -> bool:
        exc = record.exc_info[1] if record.exc_info else None
        return not (exc is not None and getattr(exc, _LOGGED_MARK, False))


class LogfmtFormatter(logging.Formatter):
    def __init__(self, app: str = APP_NAME) -> None:
        super().__init__()
        self._app = app

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="milliseconds")
        line = (
            f"{ts} {record.levelname:<5} {self._app} [{record.threadName}] {record.name} "
            f"rid={getattr(record, 'rid', '-')} {record.getMessage()}"
        )
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def configure_logging(level: str = "INFO", log_file: str = "") -> None:
    """Install the logfmt handlers on the root logger once; later calls only adjust the level."""

    root = logging.getLogger()
    root.setLevel(level.upper() if isinstance(level, str) else level)
    if not any(getattr(h, _HANDLER_MARK, False) for h in root.handlers):
        handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
        if log_file:
            handlers.append(
                RotatingFileHandler(
                    log_file, maxBytes=200 * 1024 * 1024, backupCount=10, encoding="utf-8"
                )
            )
        for handler in handlers:
            setattr(handler, _HANDLER_MARK, True)
            handler.setFormatter(LogfmtFormatter())
            handler.addFilter(_RequestIdFilter())
            root.addHandler(handler)
    # uvicorn installs its own handlers before the app factory runs: route its lines through ours
    # and replace its access log with the one written by ``RequestContextMiddleware``.
    for name in ("uvicorn", "uvicorn.error"):
        uv = logging.getLogger(name)
        uv.handlers.clear()
        uv.propagate = True
    uv_error = logging.getLogger("uvicorn.error")
    if not any(isinstance(f, _DropLoggedErrors) for f in uv_error.filters):
        uv_error.addFilter(_DropLoggedErrors())
    # one INFO line per outgoing request: the revocation and blocklist pollers would flood the log
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    uv_access = logging.getLogger("uvicorn.access")
    uv_access.handlers.clear()
    uv_access.propagate = False
    uv_access.disabled = True


def _incoming_request_id(scope: dict[str, Any]) -> str | None:
    for name, value in scope.get("headers") or []:
        if name == b"x-request-id":
            text = value.decode("latin-1").strip()
            return text if _RID_SAFE.match(text) else None
    return None


class RequestContextMiddleware:
    """Pure ASGI: binds the request id, echoes it back, writes one access line per request.

    An exception escaping the app is logged here once (with the request id and traceback) and
    re-raised unchanged, so the error response and test behaviour stay as before.
    """

    def __init__(self, app: Any, client_ip: Callable[[], str | None] | None = None) -> None:
        self.app = app
        self._client_ip = client_ip

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        rid = _incoming_request_id(scope) or f"ex-{uuid.uuid4().hex[:16]}"
        token = _request_id.set(rid)
        method = scope.get("method", "-")
        path = scope.get("path", "-")
        client = self._client_ip() if self._client_ip else None
        if client is None:
            client = (scope.get("client") or (None, None))[0]
        started = time.perf_counter()
        status = 0

        async def send_with_id(message: dict[str, Any]) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers") or [])
                headers.append((b"x-request-id", rid.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception as exc:
            status = status or 500
            _error_logger.error(
                kv(event="unhandled", method=method, path=path, error=type(exc).__name__),
                exc_info=True,
            )
            try:
                setattr(exc, _LOGGED_MARK, True)
            except AttributeError:
                pass
            raise
        finally:
            ms = int((time.perf_counter() - started) * 1000)
            line = kv(event="http", method=method, path=path, status=status, ms=ms, client=client)
            if path in _QUIET_PATHS and status < 400:
                access_logger.debug(line)
            else:
                access_logger.info(line)
            _request_id.reset(token)
