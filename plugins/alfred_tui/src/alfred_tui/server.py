#!/usr/bin/env python3
"""TUI adapter MCP stdio server entry point (PR-S4-10, #206).

The host transport speaks line-delimited JSON-RPC (matching
``plugins/alfred_discord`` / ``alfred_comms_test``); the ADR-0024 method names
appear LITERALLY on the wire.

Host -> plugin requests this server answers:

* ``lifecycle.start``  -> record the adapter id on the :class:`TuiSession`
* ``lifecycle.stop``   -> flush the keystroke buffer; report the discarded count
* ``adapter.health``   -> :meth:`TuiSession.health_snapshot`
* ``outbound.message`` -> :func:`alfred_tui.outbound.handle_outbound_message`
  (render a dm into the conversation log; refuse any other mode)

The single plugin -> host notification (``inbound.message``) is emitted by the
session through an injected async sink. In Shape A (ADR-0031 PR-S4-237-2) that
sink writes one line-delimited JSON frame to the 0600 unix SOCKET the foreground
``alfred chat`` dials into — NOT to stdout (Textual owns stdin/stdout on the PTY).
The TUI has no gateway, broker, or secrets — it authenticates nothing (the
operator IS the trusted user), so lifecycle.start is a pure state transition with
no credential fetch.
"""

from __future__ import annotations

import asyncio
from typing import Any, Final

import structlog

from alfred.comms_mcp.plugin_logging import configure_stderr_json_logging
from alfred.comms_mcp.protocol import (
    AdapterHealthRequest,
    HealthReport,
    LifecycleStartRequest,
    LifecycleStartResult,
    LifecycleStopRequest,
    LifecycleStopResult,
    OutboundMessageRequest,
)
from alfred_tui import __version__
from alfred_tui.outbound import handle_outbound_message
from alfred_tui.session import TuiSession

_log = structlog.get_logger(__name__)

# ADR-0024 wire method names — host -> plugin requests.
_METHOD_LIFECYCLE_START: Final[str] = "lifecycle.start"
_METHOD_LIFECYCLE_STOP: Final[str] = "lifecycle.stop"
_METHOD_ADAPTER_HEALTH: Final[str] = "adapter.health"
_METHOD_OUTBOUND_MESSAGE: Final[str] = "outbound.message"

# The wire ``adapter_kind`` the host binds the 0600 comms socket on (ADR-0031):
# the daemon's ``CommsSocketListener(adapter_id=wire.adapter_kind)`` keys the
# socket path on ``"tui"``, so the foreground co-host dials the IDENTICAL key.
_ADAPTER_KIND: Final[str] = "tui"

# The closed, manifest-declared method set. Exposed via ``list_methods`` so a
# caller (and the test suite) can assert the surface is closed — an undeclared
# method is refused with ``Method not found`` at dispatch.
_METHODS: Final[frozenset[str]] = frozenset(
    {
        _METHOD_LIFECYCLE_START,
        _METHOD_LIFECYCLE_STOP,
        _METHOD_ADAPTER_HEALTH,
        _METHOD_OUTBOUND_MESSAGE,
    }
)


class TuiServer:
    """Routes decoded JSON-RPC request frames to the four request handlers."""

    def __init__(self, *, session: TuiSession) -> None:
        self._session = session

    def list_methods(self) -> frozenset[str]:
        """The closed set of wire method names this server binds."""
        return _METHODS

    async def dispatch(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Route one request frame to its handler; return the response frame.

        None of the four methods is a notification, so a well-formed request
        always yields a response. A malformed frame (missing/empty method)
        yields an ``Invalid Request``; an unknown method yields
        ``Method not found``.
        """
        has_response_id = "id" in request
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        if not isinstance(method, str) or not method:
            return _invalid_request(req_id if has_response_id else None)

        result = await self._handle(method, params)
        if result is None:
            return _method_not_found(method, req_id if has_response_id else None)

        response: dict[str, Any] = {"jsonrpc": "2.0", "result": result}
        if has_response_id:
            response["id"] = req_id
        return response

    async def _handle(self, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        """Return the result body for ``method``, or ``None`` if unrecognised."""
        if method == _METHOD_LIFECYCLE_START:
            start_req = LifecycleStartRequest.model_validate(params)
            await self._session.start(adapter_id=start_req.adapter_id)
            return LifecycleStartResult(ok=True, plugin_version=__version__).model_dump(mode="json")
        if method == _METHOD_LIFECYCLE_STOP:
            stop_req = LifecycleStopRequest.model_validate(params)
            flushed = await self._session.stop(reason=stop_req.reason)
            return LifecycleStopResult(ok=True, flushed_messages=flushed).model_dump(mode="json")
        if method == _METHOD_ADAPTER_HEALTH:
            AdapterHealthRequest.model_validate(params)
            snap = self._session.health_snapshot()
            return HealthReport(
                ok=snap.ok,
                last_inbound_at=snap.last_inbound_at,
                queue_depth=snap.queue_depth,
                error_count=snap.error_count,
            ).model_dump(mode="json")
        if method == _METHOD_OUTBOUND_MESSAGE:
            outbound_req = OutboundMessageRequest.model_validate(params)
            result = await handle_outbound_message(outbound_req, session=self._session)
            # ``result`` is the OutboundMessageResult discriminated-union alias;
            # bind the dump through a typed local so mypy --strict does not treat
            # the union member's ``model_dump`` as ``Any``.
            dumped: dict[str, Any] = result.model_dump(mode="json")
            return dumped
        return None


# ---------------------------------------------------------------------------
# JSON-RPC envelope helpers (mirrors plugins/alfred_discord/server.py)
# ---------------------------------------------------------------------------


def _method_not_found(method: str, req_id: object) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _invalid_request(req_id: object) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32600, "message": "Invalid Request"},
    }


def build_server(*, session: TuiSession | None = None) -> TuiServer:
    """Construct the MCP server with the four wire methods bound.

    Used directly by the unit tests for the dispatch surface. In production the
    co-host (:func:`alfred_tui.cohost.run_cohosted`) constructs the session with
    the SOCKET-backed inbound sink and the server from it; this default-session
    helper keeps the dispatch tests terminal-free (a no-op sink). ``set_render_hook``
    is left for ``alfred_tui.render.build_app`` to call once the Textual app is
    constructed (the foreground PTY owns rendering).
    """
    if session is None:
        session = TuiSession()
    return TuiServer(session=session)


def bind_self_id_from_env() -> str | None:
    """Bind the launcher-supplied ``ALFRED_PLUGIN_ADAPTER_ID`` into log context.

    The launcher-spawn seam (``alfred.cli._launcher_spawn``) delivers the
    per-instance adapter id on ``ALFRED_PLUGIN_ADAPTER_ID`` for traceability
    (review F7 — the var was previously written but read by nothing). The wire
    ``lifecycle.start`` still carries the AUTHORITATIVE id; this is only the
    plugin's self-id for the stderr logs it emits BEFORE that request arrives.
    Bound into structlog contextvars so every pre-lifecycle log line carries it.

    Returns the bound id (or ``None`` when the var is absent/blank, e.g. a
    direct ``python -m alfred_tui.server`` invocation outside the launcher).
    """
    import os

    adapter_id = os.environ.get("ALFRED_PLUGIN_ADAPTER_ID", "").strip()
    if not adapter_id:
        return None
    structlog.contextvars.bind_contextvars(adapter_id=adapter_id)
    return adapter_id


async def serve() -> int:  # pragma: no cover - process entrypoint
    """Dial the daemon's comms socket and co-host the Textual app + the wire.

    Shape A (ADR-0031 PR-S4-237-2, #237): ``alfred chat`` runs the TUI IN ITS OWN
    process and DIALS the already-running daemon's 0600 unix socket — it is no
    longer a daemon-spawned subprocess. This entry mounts the real
    ``AlfredTuiApp`` and the socket serve loop on one asyncio loop via
    :func:`alfred_tui.cohost.run_cohosted`, so ``alfred chat`` is functional
    end-to-end (a turn round-trips through the daemon and the stubbed ``ack``
    paints into the conversation log). This retires the #237 "wire contract only"
    stub and the daemon-spawned stdio carrier.

    Structlog is pinned to stderr-JSON (review F4) so the operator's PTY (which
    Textual owns) is never corrupted by a stray console-rendered log line.

    The ``adapter_id`` dialed is the wire ``adapter_kind`` (``"tui"``) the daemon
    binds its socket on — NOT the per-instance launcher id. A dial failure
    (daemon absent) raises out of ``run_cohosted`` for the caller to map.
    """
    from alfred_tui.cohost import run_cohosted

    configure_stderr_json_logging()
    bind_self_id_from_env()
    return await run_cohosted(adapter_id=_ADAPTER_KIND)


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    raise SystemExit(asyncio.run(serve()))


__all__ = ["TuiServer", "bind_self_id_from_env", "build_server", "serve"]
