#!/usr/bin/env python3
"""Alfred comms-test MCP stdio plugin — reference echo adapter.

comms-002 + comms-003 architecture:

* ``lifecycle.start`` / ``lifecycle.stop`` / ``adapter.health`` are
  host → plugin, routed as literal JSON-RPC methods per the
  ``WIRE_METHOD_NAMES`` constant in
  :mod:`alfred.comms.mcp_protocol`.
* ``inbound.message`` is plugin → host: the spec §9.1 direction is
  adapter → orchestrator. The echo plugin demonstrates this by
  emitting an ``inbound.message`` JSON-RPC NOTIFICATION (no ``id``
  field) to the host after ``lifecycle.start`` completes. The host
  registers a notification handler in :class:`AlfredPluginSession`
  (PR-S3-3a) to receive it.

The plan's reference implementation (lines 2125-2173 of the Slice 3
build plan) shows the MCP SDK's ``Server`` + ``@server.request_handler``
shape. The real reference plugins (``alfred_quarantined_llm``,
``alfred_web_fetch``) and the host transport
(:mod:`alfred.plugins.stdio_transport`) use line-delimited JSON-RPC,
not the MCP SDK's framing. This implementation matches the actual
in-repo plugin convention: hand-rolled stdio loop, JSON-RPC method
names appear LITERALLY on the wire (no ``tools/call`` wrap), method
mapping matches ``WIRE_METHOD_NAMES`` verbatim.

The ``mcp`` SDK is NOT a runtime dependency: the ``HAS_MCP`` probe
exists so this plugin runs anywhere a Python interpreter does, with no
extra wheel install. When the SDK is added in a future slice the probe
becomes a hard import.

This plugin is for TEST USE ONLY — it has no production functionality.
Authorised by ADR-0017 (Slice-3 trust-tier completion + MCP plugin
transport).
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Final

# R8 (PR-S3-6 polish): construct the inbound.message params from the
# canonical :class:`alfred.comms.mcp_protocol.InboundMessage` Pydantic
# model and dump it, rather than authoring a dict literal that drifts
# from the wire schema. Pydantic raises ValidationError at construction
# time if a field is missing — catching the same kinds of regressions
# the host's ``extra="forbid"`` check catches at receive time, but on
# the sender side.
#
# Plugin-side import discipline: the canonical reference plugin
# ``alfred_web_fetch.web_fetch_plugin`` already imports from
# ``alfred.plugins.web_fetch.*``, so a controlled, side-effect-free
# import from ``alfred.comms.mcp_protocol`` is consistent with the
# existing convention. The supervisor's trust boundary is enforced by
# process isolation + the capability gate, not by import-level
# ignorance.
from alfred.comms.mcp_protocol import InboundMessage

try:
    # Optional probe so the file imports on an interpreter that does not
    # have the ``mcp`` SDK wheel installed. Slice 3 ships without the
    # SDK; Slice 4 may add it. The plugin does not use the SDK's
    # primitives because the host transport is line-delimited JSON-RPC
    # (matching ``alfred_web_fetch`` and ``alfred_quarantined_llm``),
    # NOT MCP's length-prefixed envelope.
    import mcp  # type: ignore[import-not-found,unused-ignore]  # noqa: F401

    HAS_MCP = True
except ImportError:
    HAS_MCP = False


# comms-002: literal JSON-RPC method names on the wire. Mirrors the
# ``WIRE_METHOD_NAMES`` mapping in ``alfred.comms.mcp_protocol`` so the
# plugin and the host agree on the wire vocabulary. Duplicating the
# string constants here keeps the wire vocabulary readable from the
# plugin source without needing to chase the mapping in the host
# package — a documentation choice, not a trust-boundary one. The
# supervisor's trust boundary is enforced by process isolation + the
# capability gate at the host, not by import-level ignorance.
_METHOD_LIFECYCLE_START: Final[str] = "lifecycle.start"
_METHOD_LIFECYCLE_STOP: Final[str] = "lifecycle.stop"
_METHOD_ADAPTER_HEALTH: Final[str] = "adapter.health"
_NOTIFICATION_INBOUND_MESSAGE: Final[str] = "inbound.message"


# Adapter state — tracked across one subprocess lifetime. ``_running``
# distinguishes ``status=ok`` from ``status=degraded`` per
# :class:`AdapterHealthResponse`.
_running: bool = False


def _build_inbound_message_notification() -> dict[str, Any]:
    """Return the one-shot ``inbound.message`` notification frame.

    Spec §9.1 + comms-001: ``platform``, ``platform_user_id``,
    ``content`` and ``language`` are all REQUIRED on the wire.
    ``language`` is a BCP-47 tag (CLAUDE.md i18n rule #3 — every stored
    user-content row carries a BCP-47 tag).

    No ``id`` field — this is a JSON-RPC NOTIFICATION (plugin → host).
    Adding an ``id`` would make it a request and the host would block
    waiting for a response that the host does not send for upstream
    inbound traffic.

    R8 (PR-S3-6 polish): the ``params`` payload is now sourced from
    :class:`alfred.comms.mcp_protocol.InboundMessage` and serialised
    via ``model_dump()``. The earlier dict literal could silently
    drift from the wire schema; constructing the model raises
    :class:`pydantic.ValidationError` at build time if a field is
    missing or wrongly typed, matching what the host's
    ``extra="forbid"`` check enforces on receive.
    """
    params = InboundMessage(
        platform="test",
        platform_user_id="echo-plugin",
        content="echo plugin started",
        language="en-US",
    ).model_dump()
    return {
        "jsonrpc": "2.0",
        "method": _NOTIFICATION_INBOUND_MESSAGE,
        "params": params,
    }


def _handle_lifecycle_start(_params: dict[str, Any]) -> dict[str, Any]:
    """Mark the adapter running. Caller emits the inbound notification.

    Pulled out as a sync handler so the routing arm in
    :func:`_serve_stdin_stdout` stays free of state-machine logic and
    the unit tests in
    ``tests/unit/comms/test_mcp_identity_boundary.py`` can call the
    handler directly without spawning a subprocess.
    """
    global _running
    _running = True
    return {"status": "started"}


def _handle_lifecycle_stop(_params: dict[str, Any]) -> dict[str, Any]:
    """Mark the adapter stopped."""
    global _running
    _running = False
    return {"status": "stopped"}


def _handle_adapter_health(_params: dict[str, Any]) -> dict[str, Any]:
    """Return ``AdapterHealthResponse``-shaped payload.

    Spec §9.1 + comms-009: Slice 3's :class:`AdapterHealthResponse`
    accepts the narrow ``{"ok", "degraded"}`` Literal. The echo plugin
    reports ``"ok"`` while running and ``"degraded"`` while stopped
    (matching the docstring on the Pydantic model — ``degraded`` is a
    running-but-reduced-capability snapshot, which is closer to the
    semantics of "lifecycle.start has not been called yet" than
    ``"unhealthy"`` — and Slice 3 has no ``"unhealthy"`` value to
    return regardless).
    """
    status = "ok" if _running else "degraded"
    detail = "echo plugin running" if _running else "lifecycle.start not yet received"
    return {"status": status, "detail": detail}


def _build_method_not_found(method: str) -> dict[str, Any]:
    """Build the JSON-RPC ``-32601`` error envelope for unknown methods.

    CR-149 protocol compliance: every wire frame this plugin emits
    carries the mandatory ``jsonrpc: "2.0"`` member so a strict host
    parser (the future ``StdioTransport`` round-trip in Slice 4) does
    not reject our reply as malformed.
    """
    return {
        "jsonrpc": "2.0",
        "error": {
            "code": -32601,
            "message": f"Method not found: {method}",
        },
    }


def _build_parse_error(detail: str) -> dict[str, Any]:
    """Build the JSON-RPC ``-32700`` error envelope for malformed frames.

    err-004 boundary discipline: malformed JSON returns a structured
    response so the orchestrator never hangs waiting for a frame that
    never arrives.

    CR-149: includes the mandatory ``jsonrpc: "2.0"`` member so the
    error envelope is wire-compliant on the spec §9 surface.
    """
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": -32700,
            "message": "Parse error",
            "data": {"detail": detail},
        },
    }


def _build_invalid_request(req_id: object) -> dict[str, Any]:
    """Build the JSON-RPC ``-32600`` error envelope for non-object requests.

    CR-149: ``json.loads`` legally returns lists, strings, numbers, or
    ``null`` for valid JSON that is NOT a JSON-RPC request. The
    previous code called ``.get(...)`` unconditionally and crashed the
    subprocess on the first such frame, leaving the host hanging
    waiting for a response. The Invalid Request envelope is the
    spec-compliant reply — the host observes the structured error and
    proceeds.

    ``req_id`` is echoed back when it can be extracted; otherwise we
    follow the spec and pass ``None``.
    """
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {
            "code": -32600,
            "message": "Invalid Request",
        },
    }


async def _serve_stdin_stdout() -> None:
    """MCP stdio loop: read JSON-RPC requests, write responses + notifications.

    Mirrors the framing convention used by
    :mod:`plugins.alfred_web_fetch.web_fetch_plugin`. JSON-decode
    errors return a structured ``-32700`` parse-error frame so the
    orchestrator gets a response and does not hang. Any other
    exception in a handler propagates to crash the subprocess so the
    host detects the failure via the ``plugin.lifecycle.crashed``
    audit row (silent swallowing produces a hung host).
    """
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_event_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    writer_transport, _writer_protocol = await loop.connect_write_pipe(
        lambda: asyncio.BaseProtocol(), sys.stdout.buffer
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
            _emit(_build_parse_error(str(exc)))
            continue

        # CR-149: ``json.loads`` legally returns lists / strings / numbers /
        # ``None`` for valid JSON that does NOT conform to the JSON-RPC
        # request shape. Calling ``.get(...)`` unconditionally would
        # crash the subprocess on the first such frame, leaving the
        # host hanging on a never-arriving response. We refuse the
        # frame with a structured Invalid Request envelope (-32600)
        # and continue the loop so the boundary stays resilient.
        if not isinstance(request, dict):
            _emit(_build_invalid_request(None))
            continue

        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params") or {}

        if method == _METHOD_LIFECYCLE_START:
            # CR-149 protocol compliance: every reply envelope carries
            # ``jsonrpc: "2.0"`` alongside ``result`` / ``id`` so the
            # spec §9 wire surface accepts the frame without rejecting
            # it as version-less.
            response: dict[str, Any] = {
                "jsonrpc": "2.0",
                "result": _handle_lifecycle_start(params),
            }
            # comms-003: emit the plugin → host inbound.message
            # notification after the lifecycle handler runs so the host
            # observes the response → notification ordering.
            response["id"] = req_id
            _emit(response)
            _emit(_build_inbound_message_notification())
            continue
        if method == _METHOD_LIFECYCLE_STOP:
            response = {"jsonrpc": "2.0", "result": _handle_lifecycle_stop(params)}
        elif method == _METHOD_ADAPTER_HEALTH:
            response = {"jsonrpc": "2.0", "result": _handle_adapter_health(params)}
        else:
            response = _build_method_not_found(method)

        response["id"] = req_id
        _emit(response)


if __name__ == "__main__":
    asyncio.run(_serve_stdin_stdout())
