"""The per-frame wire seq travels WITH its own dispatched frame (Spec A G4b-2a-pre).

F1 (CRITICAL): the runner's pump detaches each notification's dispatch as a
background task then immediately reads the next frame. A shared per-transport
``last_received_seq`` slot would be OVERWRITTEN by the next read before the
dispatched task built its notification — the wrong seq stamped on the wrong
frame. This test drives TWO back-to-back inbound frames (``seq=5`` then
``seq=6``) under that concurrent dispatch and asserts each notification's
``wire_seq`` matches ITS OWN payload, never the other's.

The reserved ``WIRE_SEQ_FRAME_KEY`` is what the socket carrier's ``read_frame``
folds onto the returned frame; here the fake transport supplies it directly so
the test isolates the runner -> session threading (the race-prone leg).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.comms_mcp.handlers import BindingHandler, CrashHandler, RateLimitHandler
from alfred.comms_mcp.protocol import InboundMessageNotification
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.comms_seq_codec import WIRE_SEQ_FRAME_KEY
from alfred.plugins.session import AlfredPluginSession
from tests.helpers.gates import make_permissive_fixture_gate

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "alfred_comms_test"

_MANIFEST = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred_comms_test"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"

[sandbox]
kind = "none"
"""

_HANDSHAKE_OK: Mapping[str, object] = {
    "jsonrpc": "2.0",
    "id": 0,
    "result": {"ok": True, "plugin_version": "0.1.0"},
}


class _FakeTransport:
    def __init__(self, inbound: list[Any]) -> None:
        self._inbound = inbound
        self.sent: list[Mapping[str, object]] = []
        self.closed = False

    async def spawn(self) -> None:
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(frame)

    async def read_frame(self) -> Mapping[str, object] | None:
        if not self._inbound:
            return None
        return self._inbound.pop(0)  # type: ignore[no-any-return]

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        return None


class _RecordingInboundHandler:
    """Records every (validated) notification it processes, in dispatch order."""

    def __init__(self) -> None:
        self.processed: list[InboundMessageNotification] = []

    async def process(self, notification: InboundMessageNotification) -> None:
        # Yield once so two concurrently-dispatched tasks genuinely interleave —
        # if the seq were read from a shared slot AFTER the next frame's read,
        # this await is exactly where the wrong value would be observed.
        await asyncio.sleep(0)
        self.processed.append(notification)


def _inbound_frame(*, inbound_id: str, wire_seq: int | None) -> dict[str, object]:
    frame: dict[str, object] = {
        "jsonrpc": "2.0",
        "method": "inbound.message",
        "params": {
            "adapter_id": _ADAPTER_ID,
            "inbound_id": inbound_id,
            "platform_user_id": "discord:42",
            "body": {"content": "hello"},
            "sub_payload_refs": [],
            "received_at": "2026-06-10T00:00:00+00:00",
            "addressing_signal": "dm",
        },
    }
    if wire_seq is not None:
        frame[WIRE_SEQ_FRAME_KEY] = wire_seq
    return frame


async def _make_session(*, transport: Any, inbound_handler: Any) -> AlfredPluginSession:
    return await AlfredPluginSession.for_comms_adapter(
        adapter_id=_ADAPTER_ID,
        manifest_raw=_MANIFEST,
        audit_writer=_audit(),
        gate=make_permissive_fixture_gate(),
        supervisor=MagicMock(),
        inbound_handler=inbound_handler,
        binding_handler=MagicMock(spec=BindingHandler),
        rate_limit_handler=MagicMock(spec=RateLimitHandler),
        crash_handler=MagicMock(spec=CrashHandler),
        transport=transport,  # type: ignore[arg-type]
    )


def _audit() -> MagicMock:
    writer = MagicMock()
    writer.append_schema = AsyncMock()
    return writer


async def test_each_back_to_back_frame_carries_its_own_wire_seq() -> None:
    """Two interleaved dispatches each stamp their OWN seq (the anti-race assertion)."""
    inbound_handler = _RecordingInboundHandler()
    transport = _FakeTransport(
        [
            dict(_HANDSHAKE_OK),
            _inbound_frame(inbound_id="frame-5", wire_seq=5),
            _inbound_frame(inbound_id="frame-6", wire_seq=6),
        ]
    )
    session = await _make_session(transport=transport, inbound_handler=inbound_handler)
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    by_id = {n.inbound_id: n.wire_seq for n in inbound_handler.processed}
    assert by_id == {"frame-5": 5, "frame-6": 6}


async def test_plain_frame_without_reserved_key_yields_none_wire_seq() -> None:
    """A frame with no reserved seq key (stdio / un-upgraded peer) carries None."""
    inbound_handler = _RecordingInboundHandler()
    transport = _FakeTransport(
        [dict(_HANDSHAKE_OK), _inbound_frame(inbound_id="frame-plain", wire_seq=None)]
    )
    session = await _make_session(transport=transport, inbound_handler=inbound_handler)
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    assert len(inbound_handler.processed) == 1
    assert inbound_handler.processed[0].wire_seq is None


async def test_payload_smuggled_wire_seq_is_cleared_by_the_authoritative_host() -> None:
    """A peer-smuggled ``params["wire_seq"]`` on an un-sequenced unit must NOT reach the
    host ack tracker.

    ``wire_seq`` is carrier HEADER metadata, never payload-derived (ADR-0032). On an
    un-sequenced (mixed-wire) socket unit the host folds ``None``; the dispatch sets
    ``wire_seq`` UNCONDITIONALLY, so the host's ``None`` actively CLEARS the smuggled
    value rather than letting it through to ``observe()``.
    """
    smuggle = _inbound_frame(inbound_id="frame-smuggle", wire_seq=None)
    params = smuggle["params"]
    assert isinstance(params, dict)
    params["wire_seq"] = 99  # payload smuggle on an un-sequenced unit
    inbound_handler = _RecordingInboundHandler()
    transport = _FakeTransport([dict(_HANDSHAKE_OK), smuggle])
    session = await _make_session(transport=transport, inbound_handler=inbound_handler)
    session._inbound_handler = inbound_handler  # type: ignore[assignment]
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    await runner.run()

    assert len(inbound_handler.processed) == 1
    assert inbound_handler.processed[0].wire_seq is None  # the smuggled 99 was cleared
