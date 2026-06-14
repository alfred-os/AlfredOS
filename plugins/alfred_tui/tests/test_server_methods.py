"""Server binds the four ADR-0024 host->plugin methods over JSON-RPC.

Mirrors the ``plugins/alfred_discord`` wire contract: a hand-rolled
line-delimited JSON-RPC server whose ``dispatch(frame)`` routes a decoded
request to one of the four method handlers. The method names appear LITERALLY on
the wire. ``list_methods`` exposes the closed, manifest-declared method set.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from alfred_tui.server import build_server

from alfred.comms_mcp.protocol import OutboundMessageRequest
from alfred.security.dlp import OutboundDlp, ScannedOutboundBody


def _scanned(text: str) -> ScannedOutboundBody:
    class _StubBroker:
        def redact(self, value: str) -> str:
            return value

    def _audit(*, event: str, subject: object) -> None: ...

    return OutboundDlp(broker=_StubBroker(), audit=_audit).scan_for_outbound(text)


def test_server_exposes_the_four_wire_methods() -> None:
    methods = build_server().list_methods()
    assert "lifecycle.start" in methods
    assert "lifecycle.stop" in methods
    assert "adapter.health" in methods
    assert "outbound.message" in methods


def test_server_method_set_is_closed() -> None:
    # Out-of-scope refusal: the manifest-declared method set is closed.
    methods = build_server().list_methods()
    assert "outbound.binary_blob" not in methods
    assert set(methods) == {
        "lifecycle.start",
        "lifecycle.stop",
        "adapter.health",
        "outbound.message",
    }


@pytest.mark.asyncio
async def test_dispatch_lifecycle_start_returns_ok_result() -> None:
    server = build_server()
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "lifecycle.start",
        "params": {
            "adapter_id": "tui",
            "credentials_ref": "n/a",
            "policies_snapshot_hash": "deadbeef",
        },
    }
    response = await server.dispatch(frame)
    assert response is not None
    assert response["id"] == 1
    assert response["result"]["ok"] is True
    assert response["result"]["plugin_version"]


@pytest.mark.asyncio
async def test_dispatch_adapter_health_returns_snapshot() -> None:
    server = build_server()
    response = await server.dispatch(
        {"jsonrpc": "2.0", "id": 2, "method": "adapter.health", "params": {"adapter_id": "tui"}}
    )
    assert response is not None
    assert "ok" in response["result"]
    assert "queue_depth" in response["result"]


@pytest.mark.asyncio
async def test_dispatch_outbound_message_delivered() -> None:
    server = build_server()
    req = OutboundMessageRequest(
        adapter_id="tui",
        idempotency_key=uuid4(),
        target_platform_id="local-operator",
        body=_scanned("rendered"),
        attachments_refs=(),
        addressing_mode="dm",
    )
    response = await server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "outbound.message",
            "params": req.model_dump(mode="json"),
        }
    )
    assert response is not None
    assert response["result"]["outcome"] == "delivered"


@pytest.mark.asyncio
async def test_dispatch_unknown_method_is_method_not_found() -> None:
    # Error path: an unrecognised method yields a JSON-RPC -32601 error frame.
    server = build_server()
    response = await server.dispatch(
        {"jsonrpc": "2.0", "id": 4, "method": "outbound.binary_blob", "params": {}}
    )
    assert response is not None
    assert response["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_dispatch_malformed_frame_is_invalid_request() -> None:
    # Error path: a frame with no method string is an Invalid Request (-32600).
    server = build_server()
    response = await server.dispatch({"jsonrpc": "2.0", "id": 5, "params": {}})
    assert response is not None
    assert response["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_dispatch_unknown_idless_notification_is_ignored() -> None:
    """Spec A G3-2 (#237): an unknown id-less NOTIFICATION returns ``None`` (ignored).

    The daemon now broadcasts ``daemon.lifecycle.ready`` / ``...going_down`` id-less
    notifications onto the wire. The TUI has no handler for them and they carry no
    ``id``, so the correct JSON-RPC behaviour is to log + ignore — NEVER reply with a
    malformed ``id:null`` error frame.
    """
    server = build_server()
    response = await server.dispatch(
        {
            "jsonrpc": "2.0",
            "method": "daemon.lifecycle.ready",
            "params": {"epoch": "a" * 32},
        }
    )
    assert response is None


@pytest.mark.asyncio
async def test_dispatch_unknown_method_with_id_still_returns_method_not_found() -> None:
    """A REQUEST (has ``id``) with an unknown method STILL returns -32601 (security M-4).

    The notification-ignored branch must not swallow a real request: only an id-LESS
    unknown method is ignored; an unknown method carrying an ``id`` is still a
    method-not-found error.
    """
    server = build_server()
    response = await server.dispatch(
        {"jsonrpc": "2.0", "id": 7, "method": "daemon.lifecycle.ready", "params": {}}
    )
    assert response is not None
    assert response["error"]["code"] == -32601
