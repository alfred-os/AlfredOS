"""MCP server dispatch skeleton for the Discord adapter (Task C3).

``DiscordServer.dispatch`` is the pure-ish core of the stdio JSON-RPC loop: it
routes a decoded request frame to one of the four ADR-0024 host->plugin request
handlers and returns the JSON-RPC response frame (or ``None`` for a
notification — none of the four request methods is a notification, so a
well-formed request always yields a response).

``outbound.message`` is a Wave-3 SEAM: the handler returns a clear
``not_implemented`` terminal-failure-shaped stub so the host sees a loud,
typed refusal rather than a silent drop while the gateway send-path is built.
"""

from __future__ import annotations

import pytest

from plugins.alfred_discord.lifecycle import DiscordLifecycle
from plugins.alfred_discord.server import DiscordServer


class _FakeGateway:
    def __init__(self) -> None:
        self.connected_with: str | None = None

    async def connect(self, token: str) -> None:
        self.connected_with = token

    async def close(self) -> int:
        return 0

    @property
    def queue_depth(self) -> int:
        return 0


class _FakeBroker:
    def get(self, name: str) -> str:
        return "tok"


def _server() -> DiscordServer:
    lifecycle = DiscordLifecycle(broker=_FakeBroker(), gateway=_FakeGateway())
    return DiscordServer(lifecycle=lifecycle)


def _req(
    method: str, *, req_id: int = 1, params: dict[str, object] | None = None
) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}


@pytest.mark.asyncio
async def test_dispatch_lifecycle_start() -> None:
    server = _server()
    resp = await server.dispatch(_req("lifecycle.start"))
    assert resp is not None
    assert resp["id"] == 1
    assert resp["result"]["ok"] is True
    assert resp["result"]["plugin_version"]


@pytest.mark.asyncio
async def test_dispatch_lifecycle_stop() -> None:
    server = _server()
    await server.dispatch(_req("lifecycle.start"))
    resp = await server.dispatch(_req("lifecycle.stop", req_id=2))
    assert resp is not None
    assert resp["result"]["ok"] is True
    assert resp["result"]["flushed_messages"] == 0


@pytest.mark.asyncio
async def test_dispatch_adapter_health() -> None:
    server = _server()
    await server.dispatch(_req("lifecycle.start"))
    resp = await server.dispatch(_req("adapter.health", req_id=3))
    assert resp is not None
    assert resp["result"]["ok"] is True
    assert resp["result"]["queue_depth"] == 0


@pytest.mark.asyncio
async def test_dispatch_outbound_message_unwired_is_typed_refusal() -> None:
    # An unwired server (no OutboundDispatcher injected) returns a loud, typed
    # terminal refusal — never a silent drop. The wired path is covered by
    # test_server_outbound_wired.py.
    server = _server()
    resp = await server.dispatch(_req("outbound.message", req_id=4))
    assert resp is not None
    assert resp["result"]["outcome"] == "terminal_failure"
    assert resp["result"]["error_class"] == "OutboundDispatcherUnwired"


@pytest.mark.asyncio
async def test_dispatch_unknown_method_returns_method_not_found() -> None:
    server = _server()
    resp = await server.dispatch(_req("does.not.exist", req_id=5))
    assert resp is not None
    assert resp["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_dispatch_missing_method_is_invalid_request() -> None:
    server = _server()
    resp = await server.dispatch({"jsonrpc": "2.0", "id": 6})
    assert resp is not None
    assert resp["error"]["code"] == -32600
