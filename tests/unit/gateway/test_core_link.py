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
import structlog.testing

from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    LinkReconnectingNotification,
    LinkRestoredNotification,
)
from alfred.gateway.client_listener import LinkControlNotification
from alfred.gateway.core_link import (
    GATEWAY_PLUGIN_VERSION,
    GatewayCoreLink,
    GatewayCoreLinkError,
)
from alfred.gateway.link_state import GatewayLinkState
from alfred.gateway.metrics import CORE_LINK_UP
from alfred.plugins.comms_seq_codec import SEQ_VERSION


class _RecordingClientListener:
    """A fake :class:`GatewayClientListener` recording every ``send_control`` call.

    The core-link feeds the merged machine and routes the emitted control frame
    through ``send_control``; this recorder lets a test assert exactly which (if
    any) ``link.*`` notification the gateway pushed to the client.
    """

    def __init__(self) -> None:
        self.controls: list[LinkControlNotification] = []

    async def send_control(self, notification: LinkControlNotification) -> None:
        self.controls.append(notification)


def _link_with_epoch(epoch: str) -> tuple[GatewayCoreLink, _RecordingClientListener]:
    """Build a core-link with a captured handshake epoch + a recording listener."""
    recorder = _RecordingClientListener()
    link = GatewayCoreLink(client_listener=recorder)  # type: ignore[arg-type]
    link._core_epoch = epoch
    return link, recorder


def _events_of(captured: list[dict[str, object]]) -> list[object]:
    return [c.get("event") for c in captured]


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
    link = GatewayCoreLink(client_listener=_RecordingClientListener())

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
    link = GatewayCoreLink(client_listener=_RecordingClientListener())

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
    link = GatewayCoreLink(client_listener=_RecordingClientListener())

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
    link = GatewayCoreLink(client_listener=_RecordingClientListener())

    with pytest.raises(GatewayCoreLinkError):
        await link._peer_handshake(transport)

    assert transport.sent == []
    assert link._core_epoch is None


@pytest.mark.asyncio
async def test_peer_handshake_rejects_eof_before_start() -> None:
    transport = _FakeCoreTransport([])
    link = GatewayCoreLink(client_listener=_RecordingClientListener())

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
    link = GatewayCoreLink(client_listener=_RecordingClientListener())

    await link._peer_handshake(transport)

    assert link._core_epoch == epoch
    assert transport.sent[0]["result"] == {  # type: ignore[index]
        "ok": True,
        "plugin_version": GATEWAY_PLUGIN_VERSION,
        "seq_ack": {"version": SEQ_VERSION},
    }


# ---------------------------------------------------------------------------
# Task 4 — lifecycle-frame consume + epoch-reconcile forgery defense
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_consume_going_down_feeds_reconnecting_and_drops_gauge() -> None:
    epoch = uuid4().hex
    link, recorder = _link_with_epoch(epoch)

    await link._consume_frame(
        {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
    )

    # A planned drain opens a gap: the machine emits reconnecting, the gateway pushes
    # the LinkReconnectingNotification, and CORE_LINK_UP drops to 0 (state != UP).
    assert len(recorder.controls) == 1
    assert isinstance(recorder.controls[0], LinkReconnectingNotification)
    assert link._machine.state is not GatewayLinkState.UP
    assert CORE_LINK_UP._value.get() == 0


@pytest.mark.asyncio
async def test_consume_ready_matching_epoch_is_idempotent_from_up() -> None:
    epoch = uuid4().hex
    link, recorder = _link_with_epoch(epoch)
    CORE_LINK_UP.set(1)

    # A ready whose epoch MATCHES the captured handshake epoch is valid. From UP the
    # machine emits nothing (the gap is already closed); the gauge stays 1.
    await link._consume_frame({"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": epoch}})

    assert recorder.controls == []
    assert link._machine.state is GatewayLinkState.UP
    assert CORE_LINK_UP._value.get() == 1


@pytest.mark.asyncio
async def test_consume_ready_matching_epoch_closes_an_open_gap() -> None:
    epoch = uuid4().hex
    link, recorder = _link_with_epoch(epoch)

    # Open a gap first (going_down -> reconnecting), then a matching-epoch ready closes
    # it (-> restored) and the gauge returns to 1.
    await link._consume_frame(
        {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
    )
    await link._consume_frame({"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": epoch}})

    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert link._machine.state is GatewayLinkState.UP
    assert CORE_LINK_UP._value.get() == 1


@pytest.mark.asyncio
async def test_consume_ready_with_forged_epoch_is_rejected_loud() -> None:
    """THE FORGERY: a valid-shaped ``ready`` whose epoch != the captured handshake
    epoch is a false-liveness injection (a same-uid peer past SO_PEERCRED lying). It
    must be REJECTED: no feed, no control frame, loud ``ready_epoch_mismatch`` — a
    false ``restored`` is an attack surface.
    """
    epoch = uuid4().hex
    forged = uuid4().hex
    assert forged != epoch
    link, recorder = _link_with_epoch(epoch)
    CORE_LINK_UP.set(1)

    with structlog.testing.capture_logs() as captured:
        await link._consume_frame({"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": forged}})

    # No feed, no control frame: the machine stays UP and the client sees nothing.
    assert recorder.controls == []
    assert link._machine.state is GatewayLinkState.UP
    # Loud + warning (CLAUDE.md hard rule #7): the forgery is test-observable now.
    mismatch = [c for c in captured if c.get("event") == "gateway.core_link.ready_epoch_mismatch"]
    assert len(mismatch) == 1, captured
    assert mismatch[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_forged_ready_while_gapped_never_emits_restored() -> None:
    """THE LOAD-BEARING FORGERY: a forged ``ready`` arriving WHILE GAPPED.

    The UP-state forgery test above passes even with the epoch guard removed (from UP
    a matching OR forged ``ready`` emits nothing — UP+core_ready -> UP). The
    security-relevant case is a forged ``ready`` arriving while a gap is OPEN: WITHOUT
    the epoch guard, ``CORE_READY`` would feed the machine and emit a real
    ``LinkRestoredNotification`` — a false all-clear reaching the client. With the
    guard, the gap stays open: the recorder controls END ``[reconnecting]`` ONLY (NO
    ``restored``), the machine is still NOT UP, and ``ready_epoch_mismatch`` fired.

    Deleting the ``parsed.epoch != self._core_epoch`` guard in ``_consume_ready`` MUST
    make this test FAIL (a forged ``restored`` would then reach the client).
    """
    epoch = uuid4().hex
    forged = uuid4().hex
    assert forged != epoch
    link, recorder = _link_with_epoch(epoch)

    # Open a gap first: a valid going_down -> reconnecting (recorder observes it).
    await link._consume_frame(
        {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
    )
    assert [type(c) for c in recorder.controls] == [LinkReconnectingNotification]
    assert link._machine.state is not GatewayLinkState.UP

    # THEN a forged-epoch ready arrives while gapped. The guard rejects it: no feed,
    # no control frame — so the recorder STILL ends [reconnecting] only.
    with structlog.testing.capture_logs() as captured:
        await link._consume_frame({"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": forged}})

    assert [type(c) for c in recorder.controls] == [LinkReconnectingNotification]
    assert not any(isinstance(c, LinkRestoredNotification) for c in recorder.controls)
    assert link._machine.state is not GatewayLinkState.UP
    assert CORE_LINK_UP._value.get() == 0
    mismatch = [c for c in captured if c.get("event") == "gateway.core_link.ready_epoch_mismatch"]
    assert len(mismatch) == 1, captured
    assert mismatch[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_consume_malformed_going_down_is_loud_no_feed() -> None:
    epoch = uuid4().hex
    link, recorder = _link_with_epoch(epoch)

    with structlog.testing.capture_logs() as captured:
        # ``reason`` is a closed Literal["shutdown"]; "drain" fails validation.
        await link._consume_frame(
            {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "drain"}}
        )

    assert recorder.controls == []
    assert link._machine.state is GatewayLinkState.UP
    assert "gateway.core_link.malformed_lifecycle_frame" in _events_of(captured)


@pytest.mark.asyncio
async def test_consume_malformed_ready_is_loud_no_feed() -> None:
    epoch = uuid4().hex
    link, recorder = _link_with_epoch(epoch)

    with structlog.testing.capture_logs() as captured:
        # Bad epoch shape (not 32-hex) -> ValidationError -> malformed, no feed.
        await link._consume_frame(
            {"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": "not-32-hex"}}
        )

    assert recorder.controls == []
    assert link._machine.state is GatewayLinkState.UP
    assert "gateway.core_link.malformed_lifecycle_frame" in _events_of(captured)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "frame",
    [
        {"method": "inbound.message", "params": {"adapter_id": "tui"}},  # a payload frame
        {"id": 7, "result": {}},  # a JSON-RPC response (no method)
    ],
)
async def test_consume_payload_or_response_frame_is_dropped_and_counted(
    frame: Mapping[str, object],
) -> None:
    epoch = uuid4().hex
    link, recorder = _link_with_epoch(epoch)

    await link._consume_frame(frame)

    # T1 carrier: a payload body / a response is dropped + counted, never fed, never
    # json.loads'd or acted on. The relay is G3-3b-2.
    assert recorder.controls == []
    assert link._machine.state is GatewayLinkState.UP
    assert link._dropped_payload_frames == 1
