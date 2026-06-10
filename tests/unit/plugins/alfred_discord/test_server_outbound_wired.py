"""``DiscordServer`` routes ``outbound.message`` to the real send-path (Task H2, #206).

Wave 2 left ``outbound.message`` a typed ``not_implemented`` stub; this wires it
to the real :class:`OutboundDispatcher` (which fronts
``OutboundHandler.handle_outbound`` + the comms-3 rate-limit ordering). The
handler parses the raw JSON params into an ``OutboundMessageRequest`` and returns
the ``OutboundMessageResult`` discriminated-union dict.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from alfred.comms_mcp.protocol import OutboundMessageRequest
from alfred.security.dlp import OutboundDlp
from plugins.alfred_discord.idempotency_store import IdempotencyStore
from plugins.alfred_discord.outbound_dispatcher import OutboundDispatcher
from plugins.alfred_discord.outbound_handler import OutboundHandler
from plugins.alfred_discord.rate_limit_emitter import RateLimitEmitter
from plugins.alfred_discord.server import DiscordServer, idempotency_db_path
from tests.support.discord_mocks import DiscordMockFactory, DiscordMockSendable

_ADAPTER = "discord"


class _StubBroker:
    def redact(self, text: str) -> str:
        return text


class _NullSink:
    async def emit(self, frame: object) -> None:
        return None


class _Resolver:
    def __init__(self, target: DiscordMockSendable) -> None:
        self._target = target

    async def resolve(self, target_platform_id: str, addressing_mode: str) -> DiscordMockSendable:
        return self._target


def _outbound_params() -> dict[str, object]:
    dlp = OutboundDlp(broker=_StubBroker(), audit=lambda *, event, subject: None)
    request = OutboundMessageRequest(
        adapter_id=_ADAPTER,
        idempotency_key=uuid4(),
        target_platform_id="777",
        body=dlp.scan_for_outbound("hi there"),
        attachments_refs=(),
        addressing_mode="dm",
    )
    return request.model_dump(mode="json")


def _server(tmp_path: Path, target: DiscordMockSendable) -> DiscordServer:
    store = IdempotencyStore(db_path=tmp_path / "idempotency.db")
    handler = OutboundHandler(resolver=_Resolver(target), store=store)
    emitter = RateLimitEmitter(adapter_id=_ADAPTER, sink=_NullSink())
    dispatcher = OutboundDispatcher(handler=handler, rate_limit_emitter=emitter)
    return DiscordServer(lifecycle=None, outbound_dispatcher=dispatcher)


def test_idempotency_db_path_honours_runtime_dir_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # M1: the override env var (set by the sandbox launcher / tests) wins, so
    # the ledger lands directly under the writable runtime dir.
    monkeypatch.setenv("ALFRED_DISCORD_RUNTIME_DIR", str(tmp_path))
    assert idempotency_db_path() == tmp_path / "idempotency.db"


def test_idempotency_db_path_falls_back_to_private_0700_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # M1/L3: with no override and no sandbox tmpfs, the fallback dir under the
    # system temp root is created 0700 so a world-readable /tmp never exposes
    # the ledger.
    monkeypatch.delenv("ALFRED_DISCORD_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    # Force the tmpfs branch closed: the sandbox mount does not exist in a bare
    # shell, so resolution falls through to the private temp dir.
    path = idempotency_db_path()
    parent = path.parent
    assert parent == tmp_path / "alfred" / "plugin-alfred.discord"
    assert path.name == "idempotency.db"
    assert parent.is_dir()
    assert (parent.stat().st_mode & 0o777) == 0o700


async def test_outbound_message_delivers_via_real_handler(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    target = discord_mock_factory.sendable(sent_id=314)
    server = _server(tmp_path, target)
    resp = await server.dispatch(
        {"jsonrpc": "2.0", "id": 7, "method": "outbound.message", "params": _outbound_params()}
    )
    assert resp is not None
    assert resp["result"]["outcome"] == "delivered"
    assert resp["result"]["platform_message_id"] == "314"
    assert target.sent == ["hi there"]
