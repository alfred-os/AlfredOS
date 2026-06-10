#!/usr/bin/env python3
"""Discord adapter MCP stdio server skeleton (Task C3, PR-S4-9 #206).

The host transport speaks line-delimited JSON-RPC (matching
``alfred_comms_test`` / ``alfred_web_fetch`` / ``alfred_quarantined_llm``); the
ADR-0024 method names appear LITERALLY on the wire.

Host -> plugin requests this skeleton answers:

* ``lifecycle.start``  -> :meth:`DiscordLifecycle.start`
* ``lifecycle.stop``   -> :meth:`DiscordLifecycle.stop`
* ``adapter.health``   -> :meth:`DiscordLifecycle.health`
* ``outbound.message`` -> Wave-3 SEAM (typed ``not_implemented`` refusal)

The plugin -> host notifications (``inbound.message``,
``adapter.binding_request``, ``adapter.rate_limit_signal``,
``adapter.crashed``) and the real ``outbound.message`` send-path + the
``discord_gateway`` wiring land in Wave 3. They are left as clear seams here:
:meth:`DiscordServer._handle_outbound_message` returns a loud, typed terminal
failure rather than silently dropping an outbound, and the gateway is injected
into :class:`DiscordLifecycle` (constructed in :func:`main`).
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Final

import structlog

from plugins.alfred_discord.lifecycle import DiscordLifecycle

_log = structlog.get_logger(__name__)

# ADR-0024 wire method names — host -> plugin requests.
_METHOD_LIFECYCLE_START: Final[str] = "lifecycle.start"
_METHOD_LIFECYCLE_STOP: Final[str] = "lifecycle.stop"
_METHOD_ADAPTER_HEALTH: Final[str] = "adapter.health"
_METHOD_OUTBOUND_MESSAGE: Final[str] = "outbound.message"


class DiscordServer:
    """Routes decoded JSON-RPC request frames to the four request handlers."""

    def __init__(self, *, lifecycle: DiscordLifecycle) -> None:
        self._lifecycle = lifecycle

    async def dispatch(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Route one request frame to its handler; return the response frame.

        Returns ``None`` only for a frame with no ``id`` AND a recognised
        notification method — none of the four request methods is a
        notification, so a well-formed request always yields a response. A
        malformed frame (missing/empty method) yields an ``Invalid Request``.
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
            return (await self._lifecycle.start()).model_dump(mode="json")
        if method == _METHOD_LIFECYCLE_STOP:
            return (await self._lifecycle.stop()).model_dump(mode="json")
        if method == _METHOD_ADAPTER_HEALTH:
            return self._lifecycle.health().model_dump(mode="json")
        if method == _METHOD_OUTBOUND_MESSAGE:
            return self._handle_outbound_message(params)
        return None

    def _handle_outbound_message(self, _params: dict[str, Any]) -> dict[str, Any]:
        """Wave-3 SEAM: the real send-path lands with ``discord_gateway`` wiring.

        Until then, return a typed ``terminal_failure`` (matching
        ``OutboundMessageResult``) so the host records a loud, structured refusal
        rather than a silent drop. ``detail_redacted`` carries no platform bytes.
        """
        _log.warning("comms.outbound.not_implemented", adapter="discord")
        return {
            "outcome": "terminal_failure",
            "error_class": "NotImplementedError",
            "detail_redacted": "outbound.message send-path lands in Wave 3 (#206)",
        }


# ---------------------------------------------------------------------------
# JSON-RPC envelope helpers
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


async def _serve_stdin_stdout(server: DiscordServer) -> None:  # pragma: no cover - subprocess loop
    """MCP stdio loop: read JSON-RPC frames, answer requests.

    Covered end-to-end by integration tests that spawn this module as a
    subprocess; :meth:`DiscordServer.dispatch` carries the unit coverage.
    """
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    writer_transport, _writer_protocol = await loop.connect_write_pipe(
        asyncio.BaseProtocol, sys.stdout.buffer
    )

    def _emit(frame: dict[str, Any]) -> None:
        writer_transport.write((json.dumps(frame) + "\n").encode())

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            _emit(_parse_error(str(exc)))
            continue
        if not isinstance(request, dict):
            _emit(_invalid_request(None))
            continue
        response = await server.dispatch(request)
        if response is not None:
            _emit(response)


def _build_server() -> DiscordServer:  # pragma: no cover - wiring assembled in Wave 3
    """Assemble the server with its lifecycle + gateway.

    Wave-3 SEAM: the real ``SecretBroker`` + ``discord_gateway`` gateway are
    wired here. Wave 2 ships the dispatch skeleton; this assembly is exercised
    once the gateway module lands.
    """
    raise NotImplementedError("gateway + broker wiring lands in Wave 3 (#206)")


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    asyncio.run(_serve_stdin_stdout(_build_server()))
