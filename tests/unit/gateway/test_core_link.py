"""Unit tests for ``GatewayCoreLink._peer_handshake`` (Spec A G3-3b / ADR-0032).

The gateway is the PEER on the core leg: the core (daemon, running
``CommsPluginRunner`` as host) SENDS ``lifecycle.start`` first and the gateway
RECEIVES it, validates the epoch, captures it, and RESPONDS with an ack. These
tests drive the peer half with an in-memory fake transport implementing the
``_CommsTransportLike`` seam, mirroring the host-side coverage in
``tests/unit/plugins/`` for the runner's ``_handshake``.
"""

from __future__ import annotations

import collections
from collections.abc import Mapping
from uuid import uuid4

import pytest

from alfred.gateway.core_link import (
    GATEWAY_PLUGIN_VERSION,
    GatewayCoreLink,
    GatewayCoreLinkError,
)
from alfred.plugins.comms_seq_codec import SEQ_VERSION


class _FakeCoreTransport:
    """In-memory ``_CommsTransportLike`` driving the peer handshake from a queue.

    ``inbound`` is the sequence of frames the core "sends"; ``read_frame`` pops
    them in order and returns ``None`` (clean EOF) once drained. ``sent`` records
    every frame the gateway writes back.
    """

    def __init__(self, inbound: list[Mapping[str, object]]) -> None:
        self._inbound: collections.deque[Mapping[str, object]] = collections.deque(inbound)
        self.sent: list[dict[str, object]] = []
        self.seq_ack_enabled = False
        self.closed = False

    async def spawn(self) -> None:  # pragma: no cover - unused on the peer leg
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(dict(frame))

    async def read_frame(self) -> Mapping[str, object] | None:
        return self._inbound.popleft() if self._inbound else None

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        self.seq_ack_enabled = True


def _start_frame(
    *,
    epoch: object,
    seq_ack: Mapping[str, object] | None,
    frame_id: object = 0,
) -> dict[str, object]:
    params: dict[str, object] = {"adapter_id": "tui"}
    if epoch is not None:
        params["epoch"] = epoch
    if seq_ack is not None:
        params["seq_ack"] = seq_ack
    return {
        "jsonrpc": "2.0",
        "id": frame_id,
        "method": "lifecycle.start",
        "params": params,
    }


@pytest.mark.asyncio
async def test_peer_handshake_negotiates_seq_ack_and_captures_epoch() -> None:
    epoch = uuid4().hex
    transport = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})])
    link = GatewayCoreLink()

    await link._peer_handshake(transport)

    assert transport.sent == [
        {
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "ok": True,
                "plugin_version": GATEWAY_PLUGIN_VERSION,
                "seq_ack": {"version": SEQ_VERSION},
            },
        }
    ]
    assert transport.seq_ack_enabled is True
    assert link._core_epoch == epoch


@pytest.mark.asyncio
async def test_peer_handshake_plain_wire_when_seq_ack_omitted() -> None:
    epoch = uuid4().hex
    transport = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack=None)])
    link = GatewayCoreLink()

    await link._peer_handshake(transport)

    assert transport.sent == [
        {
            "jsonrpc": "2.0",
            "id": 0,
            "result": {"ok": True, "plugin_version": GATEWAY_PLUGIN_VERSION},
        }
    ]
    assert transport.seq_ack_enabled is False
    assert link._core_epoch == epoch


@pytest.mark.asyncio
async def test_peer_handshake_echoes_non_zero_frame_id() -> None:
    epoch = uuid4().hex
    transport = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack=None, frame_id=7)])
    link = GatewayCoreLink()

    await link._peer_handshake(transport)

    assert transport.sent[0]["id"] == 7


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_epoch",
    [
        "0" * 31,  # 31 hex — too short
        "0" * 33,  # 33 hex — too long
        ("A" * 32),  # uppercase — pattern rejects
        ("g" * 32),  # non-hex char
        None,  # absent
    ],
)
async def test_peer_handshake_rejects_malformed_epoch(bad_epoch: object) -> None:
    transport = _FakeCoreTransport([_start_frame(epoch=bad_epoch, seq_ack=None)])
    link = GatewayCoreLink()

    with pytest.raises(GatewayCoreLinkError):
        await link._peer_handshake(transport)

    assert transport.sent == []
    assert link._core_epoch is None


@pytest.mark.asyncio
async def test_peer_handshake_rejects_eof_before_start() -> None:
    transport = _FakeCoreTransport([])
    link = GatewayCoreLink()

    with pytest.raises(GatewayCoreLinkError):
        await link._peer_handshake(transport)

    assert transport.sent == []


@pytest.mark.asyncio
async def test_peer_handshake_warns_and_drops_pre_handshake_frame() -> None:
    epoch = uuid4().hex
    pre = {"jsonrpc": "2.0", "method": "inbound.message", "params": {}}
    transport = _FakeCoreTransport(
        [pre, _start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})]
    )
    link = GatewayCoreLink()

    await link._peer_handshake(transport)

    assert link._core_epoch == epoch
    assert transport.sent[0]["result"] == {  # type: ignore[index]
        "ok": True,
        "plugin_version": GATEWAY_PLUGIN_VERSION,
        "seq_ack": {"version": SEQ_VERSION},
    }
