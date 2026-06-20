"""Daemon control-plane server: request/response over a 0600 control socket (#288, ADR-0038).

Multi-connection request/response (one request -> one response -> close per connection),
in contrast to the comms wire's one-shot bidirectional pump (ADR-0031). Reuses the shared
local-socket security primitives (peer-uid auth, owner-only bind) so the control plane
does not fork a second copy of the socket security code.

**Resilient, but never silently swallowing a security-audit failure.** A
malformed / over-bound / unknown-method request on one connection is answered (or
loud-closed) WITHOUT wedging the server — the accept loop keeps serving other clients (a
control-plane outage would blind the operator worse than a single bad request). The ONE
exception (hard rule #7): a FAILED audit-write of a peer-reject is a security event — it
ESCALATES loud (a distinct ``log.error``), it is NOT folded into the generic
resilient-connection swallow (sec-LOW-1).

**DoS bounds (the #1/#2 security asks).** Every per-connection exchange (authenticate ->
read -> respond) runs under an :func:`asyncio.timeout` so a peer that connects and never
writes a newline cannot hold a serve task + fd forever (sec-HIGH-1). Live serve tasks are
gated by a bounded :class:`asyncio.Semaphore` — past the ceiling a connection is closed
immediately, not queued unboundedly (sec-HIGH-2). ``backlog`` bounds only the kernel
accept queue, not the number of live tasks, so the semaphore is the real cap.

The ``status.query`` result is built LIVE from the in-process observer + reconciler at
query time (no snapshot, no staleness). The method router is extensible: G6-5 adds
``gateway.adapters`` / ``--wait-ready`` (a client-side poll over repeated ``status.query``
keeps the server stateless — ADR-0038).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Final

import structlog

from alfred.cli.daemon._daemon_control_protocol import (
    STATUS_QUERY_METHOD,
    UNKNOWN_REQUEST_ID,
    ControlRequest,
    ControlResponse,
    DaemonStatusResult,
    build_daemon_status_result,
)
from alfred.plugins._local_socket import (
    MAX_LOCAL_SOCKET_LINE_BYTES,
    bind_owner_only_unix_socket,
    peer_uid_authorized,
    resolve_peer_uid,
    runtime_dir,
)
from alfred.plugins.comms_wire import CommsProtocolError

if TYPE_CHECKING:
    from pathlib import Path

    from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
    from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

log = structlog.get_logger(__name__)

_CONTROL_SOCKET_NAME: Final[str] = "control.sock"
_CONTROL_LOG_PREFIX: Final[str] = "daemon.control"

# sec-HIGH-1: the whole per-connection exchange (auth -> read -> respond) must complete
# within this deadline; a never-writing peer is dropped (5s is generous for a localhost
# same-uid request/response).
_CONTROL_EXCHANGE_TIMEOUT_S: Final[float] = 5.0

# sec-HIGH-2: cap concurrent live serve tasks. Past the ceiling a connection is closed
# immediately rather than queued (the kernel ``backlog`` does NOT bound live tasks).
_MAX_CONCURRENT_SERVE: Final[int] = 24

# arch-H3: handlers are ASYNC so G6-5's blocking readiness handler does not re-type the
# seam. A handler reads the parsed request and returns the result mapping (or raises).
_Handler = Callable[[ControlRequest], Awaitable[Mapping[str, object]]]


def default_control_socket_path() -> Path:
    """``~/.run/alfred/control.sock`` (call-time ``$HOME``)."""
    return runtime_dir() / _CONTROL_SOCKET_NAME


class DaemonControlServer:
    """Bind + serve the daemon control socket; reap on every exit path."""

    def __init__(
        self,
        *,
        observer: AdapterStatusObserver | None,
        reconciler: CrashIncidentReconciler | None,
        path: Path | None = None,
        on_peer_rejected: Callable[[int | None], Awaitable[None]] | None = None,
        max_line_bytes: int = MAX_LOCAL_SOCKET_LINE_BYTES,
    ) -> None:
        self._observer = observer
        self._reconciler = reconciler
        self._path = path if path is not None else default_control_socket_path()
        self._on_peer_rejected = on_peer_rejected
        self._max_line_bytes = max_line_bytes
        self._server: asyncio.AbstractServer | None = None
        # sec-HIGH-2: a plain in-flight counter, NOT a semaphore. The cap is enforced by
        # a check-then-increment that runs SYNCHRONOUSLY (no ``await`` between the
        # ``>= cap`` read and the ``+= 1``) — race-free in single-threaded asyncio, where
        # a coroutine is never preempted between two non-awaiting statements. The earlier
        # ``Semaphore.locked()`` check-then-``acquire()`` was a check-then-acquire race
        # (CR T4): two connections could both observe "not locked" before either
        # acquired. The counter has no such gap.
        self._in_flight = 0
        # The method router — extensible (G6-5 adds gateway.adapters / --wait-ready).
        self._handlers: dict[str, _Handler] = {STATUS_QUERY_METHOD: self._handle_status_query}

    async def _handle_status_query(self, _request: ControlRequest) -> Mapping[str, object]:
        # A zero-adapter daemon binds the SAME control plane but has no observer /
        # reconciler (no comms graph): it answers an EMPTY adapter map (the
        # ``adapters_none`` render), NOT "unavailable". The control plane is a DAEMON
        # control plane, not an adapter-specific one (CR T0).
        if self._observer is None or self._reconciler is None:
            return DaemonStatusResult().model_dump()
        result = build_daemon_status_result(observer=self._observer, reconciler=self._reconciler)
        return result.model_dump()

    async def start(self) -> None:
        """Bind the 0600 control socket + start accepting (multi-connection)."""
        sock = bind_owner_only_unix_socket(self._path)
        self._server = await asyncio.start_unix_server(
            self._on_connect, sock=sock, limit=self._max_line_bytes
        )

    async def _on_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # sec-HIGH-2: refuse past the ceiling WITHOUT awaiting a slot (a queued wait
        # would be the unbounded growth the cap exists to prevent). The check-and-claim
        # is SYNCHRONOUS — no ``await`` separates the ``>= cap`` read from the increment,
        # so two concurrent connects cannot both slip past the ceiling (CR T4: this is
        # the race the prior ``Semaphore.locked()``-then-``acquire()`` had).
        if self._in_flight >= _MAX_CONCURRENT_SERVE:
            log.warning(f"{_CONTROL_LOG_PREFIX}.at_capacity")
            await self._close(writer)
            return
        self._in_flight += 1
        try:
            # sec-HIGH-1: bound the WHOLE exchange so a never-writing peer cannot hold
            # the serve task + fd forever.
            async with asyncio.timeout(_CONTROL_EXCHANGE_TIMEOUT_S):
                await self._serve_connection(reader, writer)
        except TimeoutError:
            log.warning(f"{_CONTROL_LOG_PREFIX}.request_timed_out")
        except CommsProtocolError:
            # An over-bound request line: the server raises BEFORE writing, so the peer
            # sees EOF (silent close). Loud-logged, connection closed, server keeps
            # serving (test-H3 pins the silent-close).
            log.warning(f"{_CONTROL_LOG_PREFIX}.request_over_bound")
        except _RejectAuditEscalationError:
            # sec-LOW-1 / hard rule #7: a FAILED audit-write of a peer-reject is a
            # security event — it must NOT be swallowed by the resilient guard below.
            # Re-raised here past the resilient ``except Exception`` and surfaced loud.
            raise
        except Exception as exc:  # resilient: one bad connection never wedges the server
            log.warning(f"{_CONTROL_LOG_PREFIX}.connection_failed", error=type(exc).__name__)
        finally:
            self._in_flight -= 1
            await self._close(writer)

    async def _serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_uid = resolve_peer_uid(
            writer.get_extra_info("socket"), log_prefix=_CONTROL_LOG_PREFIX, log_to=log
        )
        if not peer_uid_authorized(reported_uid=peer_uid):
            await self._reject_peer(peer_uid)
            return
        await self._serve_one(reader, writer)

    async def _reject_peer(self, peer_uid: int | None) -> None:
        """Loud-audit a refused different-uid dial; ESCALATE a failed audit-write.

        A mismatched-uid peer is an EXPECTED adversarial event (a same-uid race / a
        wider-perm misconfig), so the reject itself does not wedge the server — the
        connection is closed and the accept loop continues. But a FAILED audit-write of
        the reject is hard-rule-#7 territory: it is wrapped in :class:`_RejectAuditEscalationError`
        so it surfaces loud rather than folding into the resilient-connection swallow
        (sec-LOW-1; mirrors the comms socket's escalation).
        """
        log.warning(f"{_CONTROL_LOG_PREFIX}.peer_uid_rejected", peer_uid=peer_uid)
        if self._on_peer_rejected is None:
            return
        try:
            await self._on_peer_rejected(peer_uid)
        except Exception as exc:
            log.error(f"{_CONTROL_LOG_PREFIX}.reject_audit_failed", error=type(exc).__name__)
            raise _RejectAuditEscalationError from exc

    async def _serve_one(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await reader.readline()
        except (ValueError, asyncio.LimitOverrunError) as exc:
            # The StreamReader limit (pinned at ``start``) tripped on an over-bound
            # line. Surface it as a protocol error — the server raises BEFORE writing so
            # the peer sees EOF (silent close), not a partial response (test-H3).
            raise CommsProtocolError("control request exceeds frame bound") from exc
        if not raw:
            return
        if len(raw) > self._max_line_bytes:
            # Belt-and-braces over the StreamReader limit: a line at exactly the reader
            # limit can slip through without raising; raise BEFORE writing too.
            raise CommsProtocolError("control request exceeds frame bound")
        response = await self._route(raw)
        writer.write(json.dumps(response.model_dump()).encode() + b"\n")
        await writer.drain()

    async def _route(self, raw: bytes) -> ControlResponse:
        try:
            request = ControlRequest.model_validate_json(raw)
        except ValueError as exc:
            # The request id is unknowable on a parse failure — echo the sentinel.
            return ControlResponse(
                id=UNKNOWN_REQUEST_ID, error=f"malformed_request:{type(exc).__name__}"
            )
        handler = self._handlers.get(request.method)
        if handler is None:
            return ControlResponse(id=request.id, error=f"unknown_method:{request.method}")
        try:
            result = await handler(request)
            return ControlResponse(id=request.id, result=dict(result))
        except Exception as exc:  # a handler fault answers an error, never crashes the server
            log.warning(
                f"{_CONTROL_LOG_PREFIX}.handler_failed",
                method=request.method,
                error=type(exc).__name__,
            )
            # Only ``type(exc).__name__`` reaches the wire — NEVER ``str(exc)`` (no
            # exception message ever leaks — sec-MEDIUM-4).
            return ControlResponse(id=request.id, error=f"handler_error:{type(exc).__name__}")

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    async def aclose(self) -> None:
        """Stop accepting, close the server, and unlink the socket file (idempotent)."""
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()


class _RejectAuditEscalationError(Exception):
    """A failed peer-reject audit-write — escalated past the resilient-connection guard."""


__all__ = ["DaemonControlServer", "default_control_socket_path"]
