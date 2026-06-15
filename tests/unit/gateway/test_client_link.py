"""Tests for the gateway's client-leg HOST handshake (Spec A G3-3b-2b / ADR-0031).

The gateway is the HOST on its client leg: it SENDS ``lifecycle.start`` to the
dialed-in TUI and reads the TUI's result — the mirror image of
:meth:`alfred.plugins.comms_runner.CommsPluginRunner._handshake`, WITHOUT a
session/gate. These tests drive ``client_handshake`` with a fake transport that
plays the TUI PEER (a recorder of sent frames + a deque of inbound results).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping

import pytest

from alfred.comms_mcp.protocol import LifecycleStartRequest
from alfred.gateway.client_link import (
    _CLIENT_ADAPTER_ID,
    _MAX_PRE_ACK_FRAMES,
    GatewayHandshakeError,
    client_handshake,
)
from alfred.plugins.comms_seq_codec import SEQ_VERSION


class _FakeTuiTransport:
    """A fake transport that plays the dialed-in TUI peer.

    Records every frame the gateway SENDS, replays a queue of inbound frames
    on each ``read_frame``, and flips a flag when ``enable_seq_ack`` is called.
    """

    def __init__(self, inbound: list[Mapping[str, object] | None]) -> None:
        self.sent: list[Mapping[str, object]] = []
        self._inbound: deque[Mapping[str, object] | None] = deque(inbound)
        self.seq_ack_enabled = False

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(frame)

    async def read_frame(self) -> Mapping[str, object] | None:
        if not self._inbound:
            return None
        return self._inbound.popleft()

    def enable_seq_ack(self) -> None:
        self.seq_ack_enabled = True


def _ack(*, ok: bool = True, seq_ack: object = "absent") -> dict[str, object]:
    """Build a TUI ``lifecycle.start`` result frame (id matches the request)."""
    result: dict[str, object] = {"ok": ok, "plugin_version": "0.1.0"}
    if seq_ack != "absent":
        result["seq_ack"] = seq_ack
    return {"jsonrpc": "2.0", "id": 0, "result": result}


def _sent_params(transport: _FakeTuiTransport) -> Mapping[str, object]:
    """The params of the single ``lifecycle.start`` the gateway sent."""
    assert len(transport.sent) == 1
    frame = transport.sent[0]
    assert frame["method"] == "lifecycle.start"
    params = frame["params"]
    assert isinstance(params, Mapping)
    return params


@pytest.mark.asyncio
async def test_sent_params_are_a_relaxed_lifecycle_start_request() -> None:
    transport = _FakeTuiTransport([_ack(seq_ack=None)])

    await client_handshake(transport)

    params = _sent_params(transport)
    # The SENT shape validates as a (now-relaxed) LifecycleStartRequest.
    req = LifecycleStartRequest.model_validate(params)
    assert req.adapter_id == _CLIENT_ADAPTER_ID == "tui"
    assert req.seq_ack is not None
    assert req.seq_ack.version == SEQ_VERSION
    # No sentinel credentials, no policies hash, no epoch on the client leg.
    assert "credentials_ref" not in params
    assert "policies_snapshot_hash" not in params
    assert "epoch" not in params


@pytest.mark.asyncio
async def test_plain_leg_returns_false_and_never_enables_seq_ack() -> None:
    transport = _FakeTuiTransport([_ack(seq_ack=None)])

    enabled = await client_handshake(transport)

    assert enabled is False
    # Security L1 — half-negotiated seq/ack is a corruption surface: the flip
    # must NOT happen when the peer did not echo the version.
    assert transport.seq_ack_enabled is False


@pytest.mark.asyncio
async def test_negotiated_leg_returns_true_and_enables_seq_ack() -> None:
    transport = _FakeTuiTransport([_ack(seq_ack={"version": SEQ_VERSION})])

    enabled = await client_handshake(transport)

    assert enabled is True
    assert transport.seq_ack_enabled is True


@pytest.mark.asyncio
async def test_not_ok_result_fails_closed() -> None:
    transport = _FakeTuiTransport([_ack(ok=False, seq_ack=None)])

    with pytest.raises(GatewayHandshakeError):
        await client_handshake(transport)
    assert transport.seq_ack_enabled is False


@pytest.mark.asyncio
async def test_missing_plugin_version_fails_closed() -> None:
    bad = {"jsonrpc": "2.0", "id": 0, "result": {"ok": True}}
    transport = _FakeTuiTransport([bad])

    with pytest.raises(GatewayHandshakeError):
        await client_handshake(transport)


@pytest.mark.asyncio
async def test_non_mapping_result_fails_closed() -> None:
    bad = {"jsonrpc": "2.0", "id": 0, "result": "not-a-mapping"}
    transport = _FakeTuiTransport([bad])

    with pytest.raises(GatewayHandshakeError):
        await client_handshake(transport)


@pytest.mark.asyncio
async def test_eof_before_ack_fails_closed() -> None:
    transport = _FakeTuiTransport([None])

    with pytest.raises(GatewayHandshakeError):
        await client_handshake(transport)


@pytest.mark.asyncio
async def test_one_pre_ack_frame_is_warn_dropped_then_ack_processes() -> None:
    # A single non-matching frame (different id) before the ack is dropped; the
    # real ack that follows is processed.
    pre = {"jsonrpc": "2.0", "id": 99, "result": {"ok": True, "plugin_version": "x"}}
    transport = _FakeTuiTransport([pre, _ack(seq_ack={"version": SEQ_VERSION})])

    enabled = await client_handshake(transport)

    assert enabled is True
    assert transport.seq_ack_enabled is True


@pytest.mark.asyncio
async def test_pre_ack_cap_fails_closed_without_infinite_loop() -> None:
    # A hostile/torn peer streams MORE than the cap of non-matching frames before
    # the ack — the bounded cap fails closed rather than looping forever.
    pre = {"jsonrpc": "2.0", "id": 99}
    flood: list[Mapping[str, object] | None] = [pre] * (_MAX_PRE_ACK_FRAMES + 1)
    flood.append(_ack(seq_ack={"version": SEQ_VERSION}))
    transport = _FakeTuiTransport(flood)

    with pytest.raises(GatewayHandshakeError):
        await client_handshake(transport)
    assert transport.seq_ack_enabled is False


@pytest.mark.asyncio
async def test_pre_ack_cap_exact_boundary_still_processes_the_ack() -> None:
    # Exactly _MAX_PRE_ACK_FRAMES non-matching frames are tolerated; the ack on
    # the next read still processes (the cap is a drop count, not a read count).
    pre = {"jsonrpc": "2.0", "id": 99}
    flood: list[Mapping[str, object] | None] = [pre] * _MAX_PRE_ACK_FRAMES
    flood.append(_ack(seq_ack=None))
    transport = _FakeTuiTransport(flood)

    enabled = await client_handshake(transport)

    assert enabled is False
