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
session through an injected async sink; in production the sink writes one
line-delimited JSON frame to stdout, mirroring the Discord adapter's
``StdoutNotificationSink``. The TUI has no gateway, broker, or secrets — it
authenticates nothing (the operator IS the trusted user), so lifecycle.start is
a pure state transition with no credential fetch.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Final

import structlog

from alfred.comms_mcp.protocol import (
    AdapterHealthRequest,
    HealthReport,
    InboundMessageNotification,
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

# Plugin -> host notification method name.
_NOTIFY_INBOUND: Final[str] = "inbound.message"

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


def _parse_error(detail: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32700, "message": "Parse error", "data": {"detail": detail}},
    }


def build_server(*, session: TuiSession | None = None) -> TuiServer:
    """Construct the stdio MCP server with the four wire methods bound.

    The session's inbound sink is wired to stdout so a keystroke-batch flush
    emits an ``inbound.message`` notification to the host. ``set_render_hook``
    is left for ``alfred_tui.render.build_app`` to call once the Textual app is
    constructed (the foreground PTY owns rendering).
    """
    if session is None:
        session = TuiSession(notify=_stdout_inbound_sink)
    return TuiServer(session=session)


async def _stdout_inbound_sink(
    note: InboundMessageNotification,
) -> None:  # pragma: no cover - prod IO
    """Write one ``inbound.message`` JSON-RPC notification frame to stdout."""
    frame = {
        "jsonrpc": "2.0",
        "method": _NOTIFY_INBOUND,
        "params": note.model_dump(mode="json"),
    }
    await asyncio.to_thread(_write_frame, frame)


def _write_frame(frame: dict[str, Any]) -> None:  # pragma: no cover - prod IO
    sys.stdout.write(json.dumps(frame) + "\n")
    sys.stdout.flush()


async def _serve_stdin_stdout(server: TuiServer) -> None:  # pragma: no cover - subprocess loop
    """MCP stdio loop: read JSON-RPC frames, answer requests.

    Covered end-to-end by integration tests that spawn this module as a
    subprocess; :meth:`TuiServer.dispatch` carries the unit coverage.
    """
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            _write_frame(_parse_error(str(exc)))
            continue
        if not isinstance(request, dict):
            _write_frame(_invalid_request(None))
            continue
        response = await server.dispatch(request)
        if response is not None:
            _write_frame(response)


async def serve() -> None:  # pragma: no cover - process entrypoint
    """Run the adapter's stdio loop."""
    await _serve_stdin_stdout(build_server())


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    asyncio.run(serve())


__all__ = ["TuiServer", "build_server", "serve"]
