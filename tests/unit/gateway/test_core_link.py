"""Unit tests for ``GatewayCoreLink._peer_handshake`` (Spec A G3-3b / ADR-0032).

The gateway is the PEER on the core leg: the core (daemon, running
``CommsPluginRunner`` as host) SENDS ``lifecycle.start`` first and the gateway
RECEIVES it, validates the epoch, captures it, and RESPONDS with an ack. These
tests drive the peer half with an in-memory fake transport implementing the
``_CommsTransportLike`` seam, mirroring the host-side coverage in
``tests/unit/plugins/`` for the runner's ``_handshake``.
"""

from __future__ import annotations

import asyncio
import collections
import json
import time
from collections.abc import Mapping
from uuid import uuid4

import pytest
import structlog.testing
from hypothesis import given
from hypothesis import strategies as st

from alfred.comms_mcp.protocol import (
    DAEMON_COMMS_ACK,
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    LinkReconnectingNotification,
    LinkRestoredNotification,
)
from alfred.gateway.client_listener import LinkControlNotification
from alfred.gateway.core_link import (
    _MIN_RECONNECT_DELAY_SECONDS,
    GATEWAY_PLUGIN_VERSION,
    GatewayCoreLink,
    GatewayCoreLinkError,
)
from alfred.gateway.link_state import (
    GatewayLinkEvent,
    GatewayLinkState,
    LinkStateMachine,
)
from alfred.gateway.metrics import (
    CORE_LINK_UP,
    CORE_UNAVAILABLE_SECONDS,
    RECONNECT_ATTEMPTS,
)
from alfred.gateway.replay_buffer import ReplayBuffer
from alfred.plugins.comms_seq_codec import SEQ_VERSION, SeqFrame
from alfred.plugins.comms_wire import CommsPeerAuthError, CommsProtocolError


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
        # Spec A G3-3b-2 relay seam: a queue of raw units ``read_payload_unit`` pops,
        # the payloads/acks ``send_payload_unit`` records, and an optional injected
        # error a single ``send_payload_unit`` raises (the broken-pipe drop tests).
        self.units: collections.deque[SeqFrame] = collections.deque()
        # Spec A G4b-2-pre (#237): records (payload, seq, ack) — the caller now OWNS
        # the wire seq it passes (no internal counter).
        self.sent_units: list[tuple[bytes, int, int]] = []
        self.send_unit_error: BaseException | None = None

    async def spawn(self) -> None:  # pragma: no cover - unused on the peer leg
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(dict(frame))

    async def read_frame(self) -> Mapping[str, object] | None:
        return self._inbound.popleft() if self._inbound else None

    async def read_payload_unit(self) -> SeqFrame | None:
        return self.units.popleft() if self.units else None

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        if self.send_unit_error is not None:
            raise self.send_unit_error
        self.sent_units.append((payload, seq, ack))

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


class _OrderRecordingCoreTransport(_FakeCoreTransport):
    """Records, per ``send``, whether ``enable_seq_ack`` had already been called.

    The handshake ack MUST go out PLAIN: ``enable_seq_ack`` may only flip AFTER
    the ack is on the wire (the core reads the ack with its framing still OFF —
    flip-after-read). ``send_seq_states`` captures ``seq_ack_enabled`` at the
    instant of each ``send`` so the test can assert the ack was written plain and
    the flip happened strictly afterwards.
    """

    def __init__(self, inbound: list[Mapping[str, object]]) -> None:
        super().__init__(inbound)
        self.send_seq_states: list[bool] = []

    async def send(self, frame: Mapping[str, object]) -> None:
        self.send_seq_states.append(self.seq_ack_enabled)
        await super().send(frame)


@pytest.mark.asyncio
async def test_peer_handshake_ack_is_plain_then_flips_seq_ack_after() -> None:
    """The negotiated ack is sent PLAIN; ``enable_seq_ack`` flips strictly AFTER.

    Mutation guard for the G5 chain bug: the merged code flipped
    ``enable_seq_ack`` BEFORE sending the ack, so the ack went out seq-framed and
    the core rejected it as malformed JSON. Both peers must flip-after-read, so
    the ack frame must be on the wire while framing is still OFF, and the flip
    must follow. Reordering back to flip-before-send fails this assertion.
    """
    epoch = uuid4().hex
    transport = _OrderRecordingCoreTransport(
        [_start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})]
    )
    link = GatewayCoreLink(client_listener=_RecordingClientListener())

    await link._peer_handshake(transport)

    # Exactly one frame (the ack) was sent, and at that instant framing was OFF.
    assert transport.send_seq_states == [False]
    # The result CONTENT still advertises seq_ack (the core learns we support it).
    assert transport.sent[0]["result"] == {  # type: ignore[index]
        "ok": True,
        "plugin_version": GATEWAY_PLUGIN_VERSION,
        "seq_ack": {"version": SEQ_VERSION},
    }
    # …and the transport framing flipped ON only AFTER the plain ack — the NEXT
    # frame would be seq-framed.
    assert transport.seq_ack_enabled is True


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
async def test_peer_handshake_resets_core_tracker_per_fresh_connect() -> None:
    """THE RESUME-CORRECTNESS RESET: each fresh core handshake is a NEW seq space.

    ``_core_tracker`` is the core->gateway RECEIVE tracker the gateway acks the core
    from. It is process-lifetime, but every fresh core transport is a NEW boot starting
    its seq run at 0 (a new epoch). After a reconnect the OLD boot's high-water (say
    1000) would make the new boot's low seqs (0,1,2) look already-settled, so
    ``cumulative_ack()`` would stay stuck at the stale high-water and the gateway would
    ack the new boot for frames it never sent (the corruption G4 builds on).

    ``_peer_handshake`` must RESET ``_core_tracker`` on EVERY (re)connect. Drive an
    initial handshake + a contiguous run so the tracker's high-water advances, then a
    SECOND handshake (the reconnect) → the tracker is fresh (``cumulative_ack() == -1``)
    and the new boot's ``seq 0`` advances it to 0 (NOT stuck at the stale high-water).
    Deleting the reset MUST make this FAIL (the stale high-water survives the reconnect).
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]

    # Initial handshake, then a contiguous core-leg receive run 0..999 (high-water 999).
    await link._peer_handshake(
        _FakeCoreTransport([_start_frame(epoch=epoch1, seq_ack={"version": SEQ_VERSION})])
    )
    for seq in range(1000):
        link._core_tracker.observe(seq)
    assert link._core_tracker.cumulative_ack() == 999

    # A reconnect: a fresh handshake (new boot, new epoch) must reset the tracker.
    await link._peer_handshake(
        _FakeCoreTransport([_start_frame(epoch=epoch2, seq_ack={"version": SEQ_VERSION})])
    )

    # Fresh tracker: nothing acked yet, NOT the stale 999.
    assert link._core_tracker.cumulative_ack() == -1
    # The new boot's seq 0 advances the fresh high-water to 0 — not "already settled".
    link._core_tracker.observe(0)
    assert link._core_tracker.cumulative_ack() == 0


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


# ---------------------------------------------------------------------------
# Task 5 — reconnect/backoff loop with full jitter
# ---------------------------------------------------------------------------


class _DialRecorder:
    """A controllable ``dial`` seam: a queue of outcomes consumed one per call.

    Each entry is either a callable returning a transport (a successful dial) or an
    exception INSTANCE to raise (a failed dial). The recorder also tracks how many
    times it was called so a test can assert the loop dialed exactly once per retry.
    """

    def __init__(self, outcomes: list[object]) -> None:
        self._outcomes: collections.deque[object] = collections.deque(outcomes)
        self.calls = 0

    async def __call__(self) -> _FakeCoreTransport:
        self.calls += 1
        outcome = self._outcomes.popleft()
        if isinstance(outcome, BaseException):
            raise outcome
        assert callable(outcome)
        return outcome()  # type: ignore[no-any-return]


def _ready_transport(epoch: str) -> _FakeCoreTransport:
    """A transport queued with a valid ``lifecycle.start`` so the handshake succeeds."""
    return _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack=None)])


def _gapped_machine() -> LinkStateMachine:
    """A machine with an OPEN gap — the loop's precondition.

    ``_reconnect`` is only entered AFTER a gap opens (a ``CORE_GOING_DOWN`` /
    ``CORE_CRASH_EOF`` drove the link out of UP); UP forbids ``REDIAL_STARTED`` by
    design (no gap to redial). Drive the machine to DOWN_CRASH so the first
    ``REDIAL_STARTED`` is a defined transition.
    """
    machine = LinkStateMachine()
    machine.feed(GatewayLinkEvent.CORE_CRASH_EOF)  # UP -> DOWN_CRASH
    return machine


def _link_for_reconnect(
    *,
    dial: object,
    sleep: object,
    jitter: object | None = None,
    machine: LinkStateMachine | None = None,
) -> tuple[GatewayCoreLink, _RecordingClientListener]:
    recorder = _RecordingClientListener()
    link = GatewayCoreLink(
        client_listener=recorder,  # type: ignore[arg-type]
        machine=machine if machine is not None else _gapped_machine(),
        dial=dial,  # type: ignore[arg-type]
        sleep=sleep,  # type: ignore[arg-type]
        jitter=jitter,  # type: ignore[arg-type]
    )
    return link, recorder


@pytest.mark.asyncio
async def test_reconnect_first_delay_is_initial_never_zero() -> None:
    epoch = uuid4().hex
    slept: list[float] = []

    async def _sleep(delay: float) -> None:
        slept.append(delay)

    dial = _DialRecorder([lambda: _ready_transport(epoch)])
    link, _ = _link_for_reconnect(dial=dial, sleep=_sleep, jitter=lambda hi: hi)

    transport = await link._reconnect()

    # Identity jitter (lambda hi: hi) reads the bare SCHEDULE ceiling: the first
    # attempt's ceiling is exactly INITIAL (the schedule floor never starts at a 0
    # ceiling). The real full-jitter draw is a uniform pick in [0, ceiling].
    assert slept == [0.25]
    assert isinstance(transport, _FakeCoreTransport)


@pytest.mark.asyncio
async def test_reconnect_backoff_schedule_doubles_capped_at_max() -> None:
    epoch = uuid4().hex
    slept: list[float] = []

    async def _sleep(delay: float) -> None:
        slept.append(delay)

    # Eight failed dials then a success — the success is never reached because we
    # only assert the failed-attempt schedule; queue a final success so the loop ends.
    fails: list[object] = [ConnectionRefusedError()] * 8
    dial = _DialRecorder([*fails, lambda: _ready_transport(epoch)])
    link, _ = _link_for_reconnect(dial=dial, sleep=_sleep, jitter=lambda hi: hi)

    await link._reconnect()

    # The identity jitter exposes the bare schedule: INITIAL, then doubling, capped at MAX.
    assert slept[:8] == [0.25, 0.5, 1.0, 2.0, 4.0, 5.0, 5.0, 5.0]


@pytest.mark.asyncio
async def test_reconnect_each_attempt_feeds_redial_started_and_increments_metric() -> None:
    epoch = uuid4().hex

    async def _sleep(_delay: float) -> None:
        return None

    # Drive from an OPEN gap so REDIAL_STARTED is a defined transition (UP forbids it).
    machine = LinkStateMachine()
    machine.feed(GatewayLinkEvent.CORE_CRASH_EOF)  # UP -> DOWN_CRASH

    dial = _DialRecorder(
        [ConnectionRefusedError(), ConnectionRefusedError(), lambda: _ready_transport(epoch)]
    )
    link, _ = _link_for_reconnect(dial=dial, sleep=_sleep, jitter=lambda hi: hi, machine=machine)

    before = RECONNECT_ATTEMPTS._value.get()
    await link._reconnect()
    after = RECONNECT_ATTEMPTS._value.get()

    # Three attempts (two fail, one succeeds): three REDIAL_STARTED feeds, three
    # metric increments, and the machine ends UP via the final CORE_READY.
    assert dial.calls == 3
    assert after - before == 3
    assert machine.state is GatewayLinkState.UP


@pytest.mark.asyncio
async def test_reconnect_retries_transient_errors_then_succeeds_and_restores() -> None:
    epoch = uuid4().hex

    async def _sleep(_delay: float) -> None:
        return None

    # A gap is already open + a redial began: the machine is REDIALING, so the
    # success-path CORE_READY emits ``restored`` (spec §9: no restored without a
    # preceding reconnecting/redial).
    machine = LinkStateMachine()
    machine.feed(GatewayLinkEvent.CORE_CRASH_EOF)  # UP -> DOWN_CRASH
    machine.feed(GatewayLinkEvent.REDIAL_STARTED)  # DOWN_CRASH -> REDIALING

    dial = _DialRecorder(
        [
            FileNotFoundError(),
            ConnectionRefusedError(),
            CommsPeerAuthError("peer uid mismatch"),
            lambda: _ready_transport(epoch),
        ]
    )
    link, recorder = _link_for_reconnect(
        dial=dial, sleep=_sleep, jitter=lambda hi: hi, machine=machine
    )

    transport = await link._reconnect()

    assert dial.calls == 4
    assert machine.state is GatewayLinkState.UP
    # The successful handshake captured the epoch and emitted ``restored`` to the client.
    assert link._core_epoch == epoch
    assert isinstance(recorder.controls[-1], LinkRestoredNotification)
    assert isinstance(transport, _FakeCoreTransport)


@pytest.mark.asyncio
async def test_reconnect_loud_on_each_failed_attempt() -> None:
    epoch = uuid4().hex

    async def _sleep(_delay: float) -> None:
        return None

    dial = _DialRecorder([ConnectionRefusedError(), lambda: _ready_transport(epoch)])
    link, _ = _link_for_reconnect(dial=dial, sleep=_sleep, jitter=lambda hi: hi)

    with structlog.testing.capture_logs() as captured:
        await link._reconnect()

    failed = [c for c in captured if c.get("event") == "gateway.core_link.reconnect_failed"]
    assert len(failed) == 1
    assert failed[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_reconnect_closes_half_open_transport_when_handshake_fails() -> None:
    epoch = uuid4().hex

    async def _sleep(_delay: float) -> None:
        return None

    # The first dial SUCCEEDS (returns a transport) but its queued lifecycle.start has
    # a malformed epoch, so the handshake raises GatewayCoreLinkError. The half-open
    # transport must be close()d before the loop retries (no FD leak).
    half_open = _FakeCoreTransport([_start_frame(epoch="not-32-hex", seq_ack=None)])
    good = _ready_transport(epoch)
    dial = _DialRecorder([lambda: half_open, lambda: good])
    link, _ = _link_for_reconnect(dial=dial, sleep=_sleep, jitter=lambda hi: hi)

    transport = await link._reconnect()

    assert half_open.closed is True
    assert transport is good
    assert link._core_epoch == epoch


@pytest.mark.asyncio
async def test_default_dial_delegates_to_dial_comms_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default ``dial`` thunk connects the keyed adapter's comms socket.

    The thunk imports ``dial_comms_socket`` LAZILY (inside the function) to keep
    importing this trust-boundary module cheap and cycle-free, so patch the symbol
    on its source module and assert the keyed ``adapter_id`` threads through.
    """
    epoch = uuid4().hex
    sentinel = _ready_transport(epoch)
    seen: list[str] = []

    async def _fake_dial(adapter_id: str) -> _FakeCoreTransport:
        seen.append(adapter_id)
        return sentinel

    monkeypatch.setattr("alfred.plugins.comms_socket_transport.dial_comms_socket", _fake_dial)
    link = GatewayCoreLink(
        client_listener=_RecordingClientListener(),  # type: ignore[arg-type]
        dial_adapter_id="gateway",
    )

    result = await link._default_dial()

    assert result is sentinel
    assert seen == ["gateway"]


@pytest.mark.asyncio
async def test_reconnect_full_jitter_default_bounds_delay() -> None:
    epoch = uuid4().hex
    slept: list[float] = []

    async def _sleep(delay: float) -> None:
        slept.append(delay)

    # No jitter override -> the default full-jitter draw in [0, backoff] is used, CLAMPED
    # to [_MIN_RECONNECT_DELAY_SECONDS, backoff]. With a single successful dial the
    # backoff is INITIAL, so the realised delay is in [0.05, 0.25] — never 0 (spec §4) —
    # assert the floored bound, not an exact value (the draw is random).
    dial = _DialRecorder([lambda: _ready_transport(epoch)])
    link = GatewayCoreLink(
        client_listener=_RecordingClientListener(),  # type: ignore[arg-type]
        machine=_gapped_machine(),
        dial=dial,  # type: ignore[arg-type]
        sleep=_sleep,
    )

    await link._reconnect()

    assert len(slept) == 1
    assert _MIN_RECONNECT_DELAY_SECONDS <= slept[0] <= 0.25


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_draw", [0.0, -1.0])
async def test_reconnect_clamps_zero_or_negative_jitter_to_floor(bad_draw: float) -> None:
    """Spec §4 in CODE: a jitter draw of 0 (the default full-jitter CAN return ~0) or a
    pathological negative injected draw is FLOORED to ``_MIN_RECONNECT_DELAY_SECONDS`` —
    never a 0-delay (or negative) first retry. Deleting the ``max(..., floor)`` clamp in
    ``_reconnect`` MUST make this FAIL (the slept delay would be 0.0 / -1.0).
    """
    epoch = uuid4().hex
    slept: list[float] = []

    async def _sleep(delay: float) -> None:
        slept.append(delay)

    dial = _DialRecorder([lambda: _ready_transport(epoch)])
    link, _ = _link_for_reconnect(dial=dial, sleep=_sleep, jitter=lambda _hi: bad_draw)

    await link._reconnect()

    assert slept == [_MIN_RECONNECT_DELAY_SECONDS]


@pytest.mark.asyncio
async def test_reconnect_clamps_oversized_jitter_to_backoff() -> None:
    """The clamp's UPPER bound: a pathological injected jitter returning MORE than the
    current backoff is pinned back to ``backoff`` (the first attempt's ceiling is
    ``INITIAL_BACKOFF_SECONDS``), so the realised delay never exceeds the schedule.
    """
    epoch = uuid4().hex
    slept: list[float] = []

    async def _sleep(delay: float) -> None:
        slept.append(delay)

    dial = _DialRecorder([lambda: _ready_transport(epoch)])
    # A jitter returning far above the backoff ceiling on attempt 1 (backoff == 0.25).
    link, _ = _link_for_reconnect(dial=dial, sleep=_sleep, jitter=lambda _hi: 999.0)

    await link._reconnect()

    assert slept == [0.25]


# ---------------------------------------------------------------------------
# Task 6 — run(): supervised dial / handshake / pump / reconnect lifecycle
# ---------------------------------------------------------------------------


class _ScriptedCoreTransport:
    """A fake ``_CommsTransportLike`` whose reads follow a single queued script.

    Each script entry is one of:
      * a ``Mapping`` — a frame ``read_frame`` returns (the handshake ``start``),
      * a :class:`SeqFrame` — a raw unit ``read_payload_unit`` returns (the relay path),
      * ``None`` — a clean EOF (the read returns ``None``),
      * a :class:`BaseException` INSTANCE — a transport-crash the read raises,
      * an :class:`asyncio.Event` — the read AWAITS the event, then (once set) returns
        ``None`` (a genuinely-pending read used to drive the shutdown race).

    The SAME ``_script`` feeds both ``read_frame`` (the handshake) and
    ``read_payload_unit`` (the post-handshake relay pump), so a single scripted
    transport drives handshake-then-relay end to end. ``sent`` records writebacks
    (the handshake ack), ``sent_units`` records relay-back payloads, ``closed`` flips
    on ``close()``.
    """

    def __init__(self, script: list[object]) -> None:
        self._script: collections.deque[object] = collections.deque(script)
        self.sent: list[dict[str, object]] = []
        # Spec A G4b-2-pre (#237): records (payload, seq, ack) — caller-owned seq.
        self.sent_units: list[tuple[bytes, int, int]] = []
        self.seq_ack_enabled = False
        self.closed = False

    async def spawn(self) -> None:  # pragma: no cover - unused on the peer leg
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(dict(frame))

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        self.sent_units.append((payload, seq, ack))

    async def _next(self) -> object | None:
        """Pop the next script entry, awaiting an ``Event`` / raising a crash."""
        if not self._script:
            return None
        entry = self._script.popleft()
        if isinstance(entry, asyncio.Event):
            await entry.wait()
            return None
        if isinstance(entry, BaseException):
            raise entry
        return entry

    async def read_frame(self) -> Mapping[str, object] | None:
        entry = await self._next()
        if entry is None:
            return None
        assert isinstance(entry, Mapping)
        return entry

    async def read_payload_unit(self) -> SeqFrame | None:
        entry = await self._next()
        if entry is None:
            return None
        assert isinstance(entry, SeqFrame)
        return entry

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        self.seq_ack_enabled = True


def _start_only(epoch: str) -> dict[str, object]:
    """A ``lifecycle.start`` frame (no following frames) for the handshake."""
    return _start_frame(epoch=epoch, seq_ack=None)


def _going_down_frame() -> dict[str, object]:
    return {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}


def _run_link(
    *,
    dial: object,
    shutdown_event: asyncio.Event | None = None,
    monotonic: object | None = None,
    sleep: object | None = None,
    machine: LinkStateMachine | None = None,
    payload_relay: object | None = None,
) -> tuple[GatewayCoreLink, _RecordingClientListener]:
    recorder = _RecordingClientListener()

    async def _instant_sleep(_delay: float) -> None:
        return None

    link = GatewayCoreLink(
        client_listener=recorder,  # type: ignore[arg-type]
        machine=machine,
        dial=dial,  # type: ignore[arg-type]
        sleep=sleep if sleep is not None else _instant_sleep,  # type: ignore[arg-type]
        jitter=lambda hi: hi,
        shutdown_event=shutdown_event,
        monotonic=monotonic if monotonic is not None else time.monotonic,  # type: ignore[arg-type]
        payload_relay=payload_relay,  # type: ignore[arg-type]
    )
    return link, recorder


@pytest.mark.asyncio
async def test_run_end_to_end_going_down_then_reconnect_emits_reconnecting_then_restored() -> None:
    """§9 end-to-end: UP start (no banner) -> going_down (reconnecting) -> EOF
    (idempotent, no 2nd banner) -> reconnect to a NEW epoch (restored). Exactly
    ``[reconnecting, restored]`` across the single gap.
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()

    # First transport: handshake start, then a going_down, then EOF (gap).
    first = _ScriptedCoreTransport([_start_only(epoch1), _going_down_frame(), None])
    # Second transport: a fresh-epoch handshake start, then a read that blocks on a
    # SEPARATE never-set event (so only the shutdown waiter — not this read — wins the
    # race; reusing the shutdown event here would let the read return EOF first).
    blocked = asyncio.Event()
    second = _ScriptedCoreTransport([_start_only(epoch2), blocked])

    dial = _DialRecorder([lambda: first, lambda: second])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown)

    task = asyncio.ensure_future(link.run())
    # Let the pump reach the second transport's blocking read, then signal shutdown.
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent:  # the second handshake completed -> pump is on the new leg
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # Exactly one gap: reconnecting (going_down), then restored (the reconnect).
    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert link._core_epoch == epoch2
    assert first.closed is True
    assert second.closed is True


@pytest.mark.asyncio
async def test_run_crash_gap_emits_reconnecting_then_restored() -> None:
    """A crash gap (EOF with no preceding going_down): UP -> EOF (reconnecting) ->
    reconnect (restored). Exactly ``[reconnecting, restored]``.
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()

    blocked = asyncio.Event()
    first = _ScriptedCoreTransport([_start_only(epoch1), None])  # start then immediate EOF
    second = _ScriptedCoreTransport([_start_only(epoch2), blocked])

    dial = _DialRecorder([lambda: first, lambda: second])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert first.closed is True
    assert second.closed is True


@pytest.mark.asyncio
async def test_run_crash_via_transport_exception_emits_reconnecting_then_restored() -> None:
    """A crash surfaced as a transport-crash EXCEPTION (not a clean EOF) opens the
    gap the same way as an EOF: reconnecting -> restored.
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()

    blocked = asyncio.Event()
    first = _ScriptedCoreTransport([_start_only(epoch1), ConnectionResetError()])
    second = _ScriptedCoreTransport([_start_only(epoch2), blocked])

    dial = _DialRecorder([lambda: first, lambda: second])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert first.closed is True
    assert second.closed is True


@pytest.mark.asyncio
async def test_run_shutdown_while_blocked_returns_without_spurious_reconnecting() -> None:
    """Shutdown fired while the pump is BLOCKED on a read returns ``run()`` promptly
    with NO ``reconnecting`` emitted (a shutdown is a clean close, not a gap) and the
    live transport closed.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    read_blocked = asyncio.Event()

    # Start (handshake), then a read that blocks until ``read_blocked`` is set. The
    # read is genuinely pending when shutdown fires.
    only = _ScriptedCoreTransport([_start_only(epoch), read_blocked])
    dial = _DialRecorder([lambda: only])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown)

    task = asyncio.ensure_future(link.run())
    # Let the pump complete the handshake and block on the read.
    for _ in range(50):
        await asyncio.sleep(0)
        if only.sent:
            break
    assert only.sent, "handshake should have completed before shutdown"
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # A clean UP start then shutdown: NO banner at all, transport closed.
    assert recorder.controls == []
    assert only.closed is True


@pytest.mark.asyncio
async def test_run_failed_initial_dial_opens_gap_and_reconnects() -> None:
    """A failed INITIAL dial does not crash ``run()``: it opens the gap
    (reconnecting) and reconnects (restored).
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()

    blocked = asyncio.Event()
    second = _ScriptedCoreTransport([_start_only(epoch), blocked])
    # The first dial FAILS; the reconnect loop's next dial succeeds.
    dial = _DialRecorder([ConnectionRefusedError(), lambda: second])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert link._core_epoch == epoch
    assert second.closed is True


@pytest.mark.asyncio
async def test_run_accrues_core_unavailable_seconds_across_one_gap() -> None:
    """``CORE_UNAVAILABLE_SECONDS`` accrues the wall-seconds the link spent not-UP.

    A scripted monotonic clock makes the gap exactly 3.0s: it stamps the UP->not-UP
    edge at the gap open and the not-UP->UP edge 3.0s later at the restore.
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()

    blocked = asyncio.Event()
    first = _ScriptedCoreTransport([_start_only(epoch1), _going_down_frame(), None])
    second = _ScriptedCoreTransport([_start_only(epoch2), blocked])
    dial = _DialRecorder([lambda: first, lambda: second])

    # Scripted clock: the gap-open edge reads 10.0, the restore edge reads 13.0
    # (delta 3.0). Extra trailing values guard against an unexpected extra read.
    ticks = collections.deque([10.0, 13.0, 13.0, 13.0, 13.0])

    def _monotonic() -> float:
        return ticks.popleft() if ticks else 13.0

    link, _ = _run_link(dial=dial, shutdown_event=shutdown, monotonic=_monotonic)

    before = CORE_UNAVAILABLE_SECONDS._value.get()
    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)
    after = CORE_UNAVAILABLE_SECONDS._value.get()

    assert after - before == pytest.approx(3.0)


@pytest.mark.asyncio
async def test_run_returns_at_loop_top_when_shutdown_already_set() -> None:
    """Shutdown set BEFORE the first pump read: the top-of-loop check returns the
    handshake-only run cleanly (no read race, no banner, transport closed).
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    shutdown.set()  # already signalled before run() starts

    only = _ScriptedCoreTransport([_start_only(epoch)])  # handshake only
    dial = _DialRecorder([lambda: only])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown)

    await asyncio.wait_for(link.run(), timeout=1.0)

    # The handshake completed (UP, no banner); the loop's top-check returned at once.
    assert recorder.controls == []
    assert only.sent  # the ack went out
    assert only.closed is True


@pytest.mark.asyncio
async def test_run_initial_handshake_failure_closes_half_open_then_reconnects() -> None:
    """The INITIAL dial CONNECTS but its handshake RAISES: the half-open transport is
    closed (no FD leak), the gap opens (reconnecting), and the reconnect restores.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()

    # First transport handshakes with a malformed epoch -> GatewayCoreLinkError.
    half_open = _ScriptedCoreTransport([_start_frame(epoch="not-32-hex", seq_ack=None)])
    blocked = asyncio.Event()
    good = _ScriptedCoreTransport([_start_only(epoch), blocked])
    dial = _DialRecorder([lambda: half_open, lambda: good])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if good.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert half_open.closed is True
    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert link._core_epoch == epoch
    assert good.closed is True


@pytest.mark.asyncio
async def test_run_initial_handshake_read_crash_gaps_and_reconnects_no_leak() -> None:
    """The INITIAL handshake's first ``read_frame`` RAISES a read-crash (EOFError /
    its ``asyncio.IncompleteReadError`` subclass): ``_initial_connect`` must gap +
    reconnect (NOT crash ``run``) and CLOSE the half-open transport (no FD leak).

    Without ``EOFError`` in ``_INITIAL_DIAL_EXCEPTIONS`` this read-crash would escape
    ``_initial_connect`` uncaught, leak the half-open leg, and crash ``run`` with no
    reconnect — even though the steady-state pump tolerates the same family.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()

    # The first dialed transport CONNECTS but its handshake read raises a read-crash.
    half_open = _ScriptedCoreTransport([asyncio.IncompleteReadError(b"", 1)])
    blocked = asyncio.Event()
    good = _ScriptedCoreTransport([_start_only(epoch), blocked])
    dial = _DialRecorder([lambda: half_open, lambda: good])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if good.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # The half-open leg is closed (no FD leak); the gap opened + the reconnect restored.
    assert half_open.closed is True
    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert link._core_epoch == epoch
    assert good.closed is True


@pytest.mark.asyncio
async def test_read_frame_or_shutdown_bare_read_when_no_event() -> None:
    """With NO shutdown event wired, the read is a bare ``read_frame`` await."""
    epoch = uuid4().hex
    frame = _start_only(epoch)
    transport = _ScriptedCoreTransport([frame])
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]

    result = await link._read_frame_or_shutdown(transport)  # type: ignore[arg-type]

    assert result == frame


@pytest.mark.asyncio
async def test_read_frame_or_shutdown_cancel_cancels_both_children() -> None:
    """A force-cancel WHILE the read race is pending cancels both children and
    re-raises ``CancelledError`` (cancellation-safety, no leaked tasks).
    """
    shutdown = asyncio.Event()
    blocked = asyncio.Event()  # never set: the read stays genuinely pending
    transport = _ScriptedCoreTransport([blocked])
    link = GatewayCoreLink(
        client_listener=_RecordingClientListener(),  # type: ignore[arg-type]
        shutdown_event=shutdown,
    )

    task = asyncio.ensure_future(link._read_frame_or_shutdown(transport))  # type: ignore[arg-type]
    # Let the race reach ``asyncio.wait`` (both children pending), then cancel it.
    for _ in range(10):
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# ---------------------------------------------------------------------------
# FIX B — honour shutdown WHILE reconnecting (not just while pumping)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_shutdown_between_reconnect_attempts_returns_promptly() -> None:
    """Shutdown signalled BETWEEN reconnect attempts ends ``run()`` promptly via the
    reconnect loop's top-of-iteration check: no further dial, no spurious banner.

    The initial dial FAILS (opening the gap → ``reconnecting``), then the reconnect
    loop's first dial also fails and SETS the shutdown event; the loop's next
    top-of-iteration check raises ``_Shutdown`` BEFORE any further dial. Removing that
    top-of-loop check would make the loop dial forever and this test would hang/timeout.
    """
    shutdown = asyncio.Event()
    dial_calls: list[int] = []

    async def _failing_dial_then_signal() -> _FakeCoreTransport:
        dial_calls.append(1)
        if len(dial_calls) >= 2:
            # The reconnect loop's first dial: fail AND signal shutdown so the NEXT
            # top-of-iteration check ends the loop before a third dial.
            shutdown.set()
        raise ConnectionRefusedError

    link, recorder = _run_link(dial=_failing_dial_then_signal, shutdown_event=shutdown)

    await asyncio.wait_for(link.run(), timeout=1.0)

    # The initial dial (1) + exactly one reconnect-loop dial (2); the top-of-loop check
    # then ends the loop — NO third dial.
    assert len(dial_calls) == 2
    # A gap opened (reconnecting) but shutdown is a clean stop: NO ``restored`` follows.
    assert [type(c) for c in recorder.controls] == [LinkReconnectingNotification]


@pytest.mark.asyncio
async def test_run_shutdown_during_reconnect_backoff_sleep_returns_promptly() -> None:
    """Shutdown signalled DURING the reconnect backoff sleep returns ``run()`` promptly
    (racing the sleep) instead of waiting out the full backoff.

    The injected ``_sleep`` BLOCKS on an event the test controls; once the pump reaches
    that blocking sleep the test sets shutdown, so ``_sleep_or_shutdown``'s race resolves
    on the shutdown waiter (NOT the still-blocked sleep) and raises ``_Shutdown``. Without
    racing the sleep against shutdown, ``run()`` would hang on the blocked sleep and this
    test would time out. Deterministic — no wall-clock wait.
    """
    shutdown = asyncio.Event()
    sleep_entered = asyncio.Event()
    sleep_release = asyncio.Event()  # never set: the sleep stays genuinely blocked

    async def _blocking_sleep(_delay: float) -> None:
        sleep_entered.set()
        await sleep_release.wait()

    # The initial dial FAILS → the gap opens and the reconnect loop sleeps (blocking).
    dial = _DialRecorder([ConnectionRefusedError()])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown, sleep=_blocking_sleep)

    task = asyncio.ensure_future(link.run())
    # Let the reconnect loop reach the blocking backoff sleep, then signal shutdown.
    await asyncio.wait_for(sleep_entered.wait(), timeout=1.0)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # The sleep was still blocked (never released); the shutdown waiter won the race and
    # ``run()`` returned cleanly. A gap opened (reconnecting) but NO ``restored``.
    assert not sleep_release.is_set()
    assert [type(c) for c in recorder.controls] == [LinkReconnectingNotification]


@pytest.mark.asyncio
async def test_sleep_or_shutdown_cancel_cancels_both_children() -> None:
    """A force-cancel WHILE the sleep/shutdown race is pending cancels both children and
    re-raises ``CancelledError`` (cancellation-safety, no leaked tasks) — mirrors the
    ``_read_frame_or_shutdown`` cancel arm.
    """
    shutdown = asyncio.Event()
    sleep_release = asyncio.Event()  # never set: the sleep stays genuinely pending

    async def _blocking_sleep(_delay: float) -> None:
        await sleep_release.wait()

    link = GatewayCoreLink(
        client_listener=_RecordingClientListener(),  # type: ignore[arg-type]
        sleep=_blocking_sleep,
        shutdown_event=shutdown,
    )

    task = asyncio.ensure_future(link._sleep_or_shutdown(0.25))
    # Let the race reach ``asyncio.wait`` (both children pending), then cancel it.
    for _ in range(10):
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# ---------------------------------------------------------------------------
# Task 2 — raw-unit relay sink + relay_to_core (Spec A G3-3b-2 / ADR-0032)
# ---------------------------------------------------------------------------


class _RelaySink:
    """A recording relay sink: every opaque payload byte run the gateway forwards."""

    def __init__(self) -> None:
        self.received: list[bytes] = []

    async def __call__(self, payload: bytes) -> None:
        self.received.append(payload)


def _payload_unit(body: bytes, *, seq: int | None = None) -> SeqFrame:
    """A raw :class:`SeqFrame` carrying ``body`` as its opaque payload."""
    return SeqFrame(seq=seq, ack=0, payload=body)


def _link_with_relay(
    *, epoch: str | None = None
) -> tuple[GatewayCoreLink, _RecordingClientListener, _RelaySink]:
    """A core-link wired with a recording relay sink + (optionally) a captured epoch."""
    recorder = _RecordingClientListener()
    sink = _RelaySink()
    link = GatewayCoreLink(client_listener=recorder, payload_relay=sink)  # type: ignore[arg-type]
    if epoch is not None:
        link._core_epoch = epoch
    return link, recorder, sink


@pytest.mark.asyncio
async def test_route_unit_forwards_payload_bytes_byte_for_byte() -> None:
    """A payload frame is forwarded to the sink VERBATIM (not re-serialized)."""
    link, _recorder, sink = _link_with_relay()
    # A payload whose JSON would re-serialize differently (extra spaces) — proving the
    # relay forwards the ORIGINAL bytes, not a re-dumped form.
    body = b'{"method": "inbound.message" ,  "params": {}}'

    await link._route_unit(_payload_unit(body))

    assert sink.received == [body]
    assert link._dropped_payload_frames == 0


@pytest.mark.asyncio
async def test_route_unit_consumes_going_down_does_not_relay() -> None:
    """A ``going_down`` unit is CONSUMED (feeds the machine -> reconnecting), NOT relayed."""
    epoch = uuid4().hex
    link, recorder, sink = _link_with_relay(epoch=epoch)
    body = json.dumps(
        {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
    ).encode()

    await link._route_unit(_payload_unit(body))

    assert sink.received == []
    assert len(recorder.controls) == 1
    assert isinstance(recorder.controls[0], LinkReconnectingNotification)
    assert link._machine.state is not GatewayLinkState.UP
    # security L2: a consumed lifecycle frame never bumps the dropped-payload counter.
    assert link._dropped_payload_frames == 0


@pytest.mark.asyncio
async def test_route_unit_consumes_daemon_comms_ack_does_not_relay() -> None:
    """A ``daemon.comms.ack`` unit is CONSUMED in its OWN arm — not relayed, not a feed.

    Spec A G4b-2a-pre (#237 — F4): the daemon's durable-intake ack is a host control
    frame the gateway consumes (``trim_to_ack`` lands in G4b-2a; this PR no-ops the
    body). It must NOT fall into the relay ``else`` (which would leak the control
    frame to the client as an opaque body) NOR into ``_consume_frame`` (which would
    trip epoch validation — the ack has no epoch and is not a LinkStateMachine
    event). It is not a dropped payload frame either.
    """
    epoch = uuid4().hex
    link, recorder, sink = _link_with_relay(epoch=epoch)
    body = json.dumps({"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": 4}}).encode()

    await link._route_unit(_payload_unit(body))

    assert sink.received == []  # NOT relayed to the client
    assert recorder.controls == []  # NOT a link-state feed (no reconnecting/restored)
    assert link._machine.state is GatewayLinkState.UP  # epoch validation never ran
    assert link._dropped_payload_frames == 0  # not counted as a dropped payload


@pytest.mark.asyncio
async def test_route_unit_consumes_daemon_comms_ack_with_malformed_body_does_not_relay() -> None:
    """A ``daemon.comms.ack`` whose body is malformed is still CONSUMED, never relayed.

    The consume arm is payload-blind for this PR (no ``trim_to_ack`` yet), so a
    missing/garbage ``cumulative_ack`` must not fall through to the relay — the
    gateway never leaks a host control frame to the client even when its body is junk.
    """
    epoch = uuid4().hex
    link, _recorder, sink = _link_with_relay(epoch=epoch)
    body = json.dumps({"method": DAEMON_COMMS_ACK, "params": {}}).encode()

    await link._route_unit(_payload_unit(body))

    assert sink.received == []
    assert link._dropped_payload_frames == 0


@pytest.mark.asyncio
async def test_route_unit_parse_failure_fails_toward_relay() -> None:
    """A payload that is NOT valid JSON is RELAYED (fail-toward-relay), never dropped.

    security SEC-3 / hard rule #7: the gateway is a T1 carrier; an un-parseable body
    is still forwarded byte-for-byte, never consumed-as-lifecycle and never silently
    dropped. Deleting the ``except`` fail-toward-relay arm would let the garbage
    bytes never reach the sink.
    """
    link, _recorder, sink = _link_with_relay()
    garbage = b"\x00garbage-not-json"

    await link._route_unit(_payload_unit(garbage))

    assert sink.received == [garbage]
    assert link._dropped_payload_frames == 0


@pytest.mark.asyncio
async def test_route_unit_no_method_response_is_relayed() -> None:
    """A JSON-RPC response (no ``method`` key) is relayed, not consumed."""
    link, _recorder, sink = _link_with_relay()
    body = json.dumps({"id": 7, "result": {}}).encode()

    await link._route_unit(_payload_unit(body))

    assert sink.received == [body]


@pytest.mark.asyncio
async def test_route_unit_forged_ready_rejected_no_relay_no_feed() -> None:
    """THE FORGERY ON THE RAW PATH: a ``ready`` unit whose epoch != the handshake
    epoch is rejected — no feed (no false ``restored``) AND not relayed-as-payload.

    The raw relay path peeks the method and routes a lifecycle ``ready`` through the
    SAME merged forgery-defended ``_consume_frame``; the epoch guard still rejects the
    forgery loud. It is NOT forwarded to the sink (a lifecycle frame is consumed, not
    relayed) and the machine stays out of UP.
    """
    epoch = uuid4().hex
    forged = uuid4().hex
    assert forged != epoch
    link, recorder, sink = _link_with_relay(epoch=epoch)
    # Open a gap first so a (forged) ready would otherwise emit a real ``restored``.
    await link._route_unit(
        _payload_unit(
            json.dumps(
                {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
            ).encode()
        )
    )
    assert [type(c) for c in recorder.controls] == [LinkReconnectingNotification]

    with structlog.testing.capture_logs() as captured:
        await link._route_unit(
            _payload_unit(
                json.dumps({"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": forged}}).encode()
            )
        )

    # No false restored, no relay-as-payload, the gap stays open, loud mismatch fired.
    assert [type(c) for c in recorder.controls] == [LinkReconnectingNotification]
    assert sink.received == []
    assert link._machine.state is not GatewayLinkState.UP
    mismatch = [c for c in captured if c.get("event") == "gateway.core_link.ready_epoch_mismatch"]
    assert len(mismatch) == 1, captured
    assert mismatch[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_route_unit_valid_ready_matching_epoch_closes_gap_no_relay() -> None:
    """A VALID ``ready`` (matching epoch) on the raw path closes the gap (restored),
    is consumed not relayed — the positive arm mirroring the forgery test.
    """
    epoch = uuid4().hex
    link, recorder, sink = _link_with_relay(epoch=epoch)
    await link._route_unit(
        _payload_unit(
            json.dumps(
                {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
            ).encode()
        )
    )
    await link._route_unit(
        _payload_unit(
            json.dumps({"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": epoch}}).encode()
        )
    )

    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert sink.received == []
    assert link._machine.state is GatewayLinkState.UP


@pytest.mark.asyncio
async def test_relay_to_core_sends_payload_with_cumulative_ack() -> None:
    """``relay_to_core`` writes the opaque payload to the core leg with the receive
    tracker's cumulative ack.
    """
    link, _recorder, _sink = _link_with_relay()
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport
    # Feed the core-leg tracker a contiguous 0,1,2 run -> cumulative ack 2.
    for seq in (0, 1, 2):
        link._core_tracker.observe(seq)

    await link.relay_to_core(b'{"id":1,"result":{}}')

    # First relay call on a fresh leg mints seq 0; ack is the cumulative 2.
    assert transport.sent_units == [(b'{"id":1,"result":{}}', 0, 2)]


# ---------------------------------------------------------------------------
# Spec A G4b-2-pre (#237) / ADR-0032: the gateway OWNS the client->core send-seq.
# ``relay_to_core`` mints a contiguous per-leg seq and passes it explicitly; a fresh
# ``_peer_handshake`` resets it to 0 (a new core leg is a new seq space).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relay_to_core_mints_contiguous_seq_and_passes_it_explicitly() -> None:
    """``relay_to_core`` mints 0,1,2,... and passes each as the explicit send seq."""
    link, _recorder, _sink = _link_with_relay()
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    await link.relay_to_core(b"one")
    await link.relay_to_core(b"two")

    assert [(p, s) for (p, s, _a) in transport.sent_units] == [(b"one", 0), (b"two", 1)]


@pytest.mark.asyncio
async def test_relay_to_core_loud_drop_still_advances_the_send_seq() -> None:
    """A broken-pipe loud drop STILL consumes its wire seq (G4b-2a buffer-key alignment).

    The seq is minted + advanced BEFORE the write attempt (the mint is past the
    None-transport check but ahead of the ``try``), so a broken-pipe drop consumes seq
    0; the next successful send must carry seq 1, never re-use 0. A refactor moving the
    increment inside the ``try`` (freeing a dropped send's seq) would desync the wire
    seq from the future ReplayBuffer key — this pins against exactly that regression,
    which branch coverage alone cannot catch (the post-increment runs unconditionally).
    """
    link, _recorder, _sink = _link_with_relay()
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    transport.send_unit_error = BrokenPipeError()
    with structlog.testing.capture_logs():
        await link.relay_to_core(b"dropped")  # loud drop — consumes seq 0
    assert transport.sent_units == []  # nothing reached the wire

    transport.send_unit_error = None
    await link.relay_to_core(b"after")  # succeeds on the live leg
    # seq CONTINUED at 1 — the dropped frame consumed seq 0 and did not free it.
    assert transport.sent_units == [(b"after", 1, 0)]


@pytest.mark.asyncio
async def test_relay_to_core_none_transport_drop_does_not_consume_a_seq() -> None:
    """A no-transport loud drop happens BEFORE the mint, so it does NOT consume a seq —
    the next real send on a live leg still starts at 0 (design §3.2)."""
    link, _recorder, _sink = _link_with_relay()
    link._current_core_transport = None

    with structlog.testing.capture_logs():
        await link.relay_to_core(b"dropped")  # no transport -> loud drop, no mint

    transport = _FakeCoreTransport([])
    link._current_core_transport = transport
    await link.relay_to_core(b"first-real")

    assert [(p, s) for (p, s, _a) in transport.sent_units] == [(b"first-real", 0)]


@pytest.mark.asyncio
async def test_peer_handshake_resets_the_client_to_core_seq() -> None:
    """A fresh handshake (new core leg) resets the send-seq to 0 — per-connection space."""
    link, _recorder, _sink = _link_with_relay()
    transport1 = _FakeCoreTransport([])
    link._current_core_transport = transport1
    await link.relay_to_core(b"a")
    await link.relay_to_core(b"b")  # _client_to_core_seq now at 2

    epoch = uuid4().hex
    transport2 = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})])
    await link._peer_handshake(transport2)  # fresh leg resets the seq space
    link._current_core_transport = transport2
    await link.relay_to_core(b"c")

    assert transport2.sent_units[-1][1] == 0  # reset to 0 on the new leg


@given(st.lists(st.binary(min_size=0, max_size=8), min_size=0, max_size=30))
def test_minted_core_seqs_are_contiguous_within_a_leg(payloads: list[bytes]) -> None:
    """Each ``relay_to_core`` mints the next contiguous seq within a single leg.

    Hypothesis drives a sync body that runs the async relay via ``asyncio.run`` (the
    project's @given+async pattern avoids the function-scoped-loop pitfall of combining
    @given with @pytest.mark.asyncio).
    """

    async def _drive() -> list[int]:
        link, _recorder, _sink = _link_with_relay()
        transport = _FakeCoreTransport([])
        link._current_core_transport = transport
        for p in payloads:
            await link.relay_to_core(p)
        return [s for (_p, s, _a) in transport.sent_units]

    assert asyncio.run(_drive()) == list(range(len(payloads)))


@pytest.mark.asyncio
async def test_relay_to_core_drops_loud_on_broken_pipe() -> None:
    """A ``BrokenPipeError`` mid-write is a LOUD drop — no raise, no buffering."""
    link, _recorder, _sink = _link_with_relay()
    transport = _FakeCoreTransport([])
    transport.send_unit_error = BrokenPipeError()
    link._current_core_transport = transport
    link._core_tracker.observe(0)

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"payload")  # must NOT raise

    dropped = [c for c in captured if c.get("event") == "gateway.relay.core_send_dropped"]
    assert len(dropped) == 1
    assert dropped[0].get("log_level") == "warning"
    # The drop does NOT disturb the receive tracker's cumulative ack.
    assert link._core_tracker.cumulative_ack() == 0


@pytest.mark.asyncio
async def test_relay_to_core_drops_loud_on_none_transport() -> None:
    """A None current transport (the reconnect-race write window — architect M3) is a
    loud drop, never a raise.
    """
    link, _recorder, _sink = _link_with_relay()
    link._current_core_transport = None

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"payload")  # must NOT raise

    dropped = [c for c in captured if c.get("event") == "gateway.relay.core_send_dropped"]
    assert len(dropped) == 1
    assert dropped[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_reconnect_closing_clears_current_transport_before_close() -> None:
    """``_reconnect_closing`` drops ``_current_core_transport`` to ``None`` BEFORE closing
    the gapped leg (architect M3), so a concurrent ``relay_to_core`` racing the gap snapshots
    ``None`` (the clean None-drop) instead of the closing transport.

    The stale transport's ``close()`` BLOCKS on an event the test controls; while it is
    blocked we assert ``_current_core_transport`` is already ``None`` and a ``relay_to_core``
    issued in that window loud-drops via the None path (``reason="no_core_transport"``),
    NOT via a write into the half-closed leg. Moving the clear to AFTER ``stale.close()``
    would let the snapshot see the closing transport and this assertion would FAIL.
    """
    close_entered = asyncio.Event()
    close_release = asyncio.Event()

    class _SlowCloseTransport(_FakeCoreTransport):
        async def close(self) -> None:
            close_entered.set()
            await close_release.wait()
            await super().close()

    epoch = uuid4().hex
    stale = _SlowCloseTransport([])
    fresh = _ready_transport(epoch)

    async def _instant_sleep(_delay: float) -> None:
        return None

    link = GatewayCoreLink(
        client_listener=_RecordingClientListener(),  # type: ignore[arg-type]
        machine=_gapped_machine(),
        dial=_DialRecorder([lambda: fresh]),  # type: ignore[arg-type]
        sleep=_instant_sleep,
        jitter=lambda hi: hi,
    )
    link._current_core_transport = stale

    reconnect_task = asyncio.ensure_future(link._reconnect_closing(stale))
    await asyncio.wait_for(close_entered.wait(), timeout=1.0)

    # The clear already happened (before the blocking close): a racing relay snapshots None.
    assert link._current_core_transport is None
    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"payload")  # races the in-flight close
    dropped = [c for c in captured if c.get("event") == "gateway.relay.core_send_dropped"]
    assert len(dropped) == 1
    assert dropped[0].get("reason") == "no_core_transport"
    # The racing send never reached the stale transport's send path.
    assert stale.sent_units == []

    close_release.set()
    result = await asyncio.wait_for(reconnect_task, timeout=1.0)
    assert result is fresh
    assert stale.closed is True


@pytest.mark.asyncio
async def test_relay_to_core_drops_loud_on_connection_reset() -> None:
    """A ``ConnectionResetError`` mid-write is also a loud drop (no raise)."""
    link, _recorder, _sink = _link_with_relay()
    transport = _FakeCoreTransport([])
    transport.send_unit_error = ConnectionResetError()
    link._current_core_transport = transport

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"payload")

    dropped = [c for c in captured if c.get("event") == "gateway.relay.core_send_dropped"]
    assert len(dropped) == 1


@pytest.mark.asyncio
async def test_relay_to_core_drops_loud_on_closed_transport_runtime_error() -> None:
    """A ``RuntimeError`` from a write to a transport ``close()``d mid-reconnect-swap is
    a LOUD drop — never a raw TaskGroup crash, never a disturbed receive tracker.
    """
    link, _recorder, _sink = _link_with_relay()
    transport = _FakeCoreTransport([])
    transport.send_unit_error = RuntimeError("unable to perform operation on closed transport")
    link._current_core_transport = transport
    link._core_tracker.observe(0)

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"payload")  # must NOT raise

    dropped = [c for c in captured if c.get("event") == "gateway.relay.core_send_dropped"]
    assert len(dropped) == 1
    assert dropped[0].get("log_level") == "warning"
    assert link._core_tracker.cumulative_ack() == 0


@pytest.mark.asyncio
async def test_relay_to_core_drops_loud_on_encode_value_error() -> None:
    """A ``ValueError`` (``encode_seq_frame`` send-seq decimal-width exhaustion) is a
    LOUD drop — never a raw TaskGroup crash.
    """
    link, _recorder, _sink = _link_with_relay()
    transport = _FakeCoreTransport([])
    transport.send_unit_error = ValueError("send seq exceeds the encodable decimal width")
    link._current_core_transport = transport

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"payload")  # must NOT raise

    dropped = [c for c in captured if c.get("event") == "gateway.relay.core_send_dropped"]
    assert len(dropped) == 1
    assert dropped[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_relay_to_core_drops_loud_on_over_bound_reframe() -> None:
    """A ``CommsProtocolError`` (over-bound reframe) is a LOUD drop — never a raw
    TaskGroup crash.
    """
    link, _recorder, _sink = _link_with_relay()
    transport = _FakeCoreTransport([])
    transport.send_unit_error = CommsProtocolError("reframed unit exceeds the bound")
    link._current_core_transport = transport

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"payload")  # must NOT raise

    dropped = [c for c in captured if c.get("event") == "gateway.relay.core_send_dropped"]
    assert len(dropped) == 1
    assert dropped[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_run_relay_pump_feeds_tracker_and_forwards_payload() -> None:
    """End-to-end ``run`` with a relay sink: a seq-framed payload unit on the core leg
    feeds the receive tracker AND is forwarded to the sink byte-for-byte.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    sink = _RelaySink()
    body = b'{"method":"inbound.message","params":{}}'
    blocked = asyncio.Event()
    # Handshake start (read via read_frame), then ONE seq=0 payload unit (read via
    # read_payload_unit), then a blocked read so shutdown can end the pump cleanly.
    transport = _ScriptedCoreTransport([_start_only(epoch), _payload_unit(body, seq=0), blocked])
    dial = _DialRecorder([lambda: transport])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown, payload_relay=sink)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if sink.received:  # the payload reached the sink -> pump processed the unit
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert sink.received == [body]
    # The seq=0 unit advanced the receive tracker's cumulative ack to 0.
    assert link._core_tracker.cumulative_ack() == 0
    assert recorder.controls == []  # a payload frame emits no link.* control
    assert transport.closed is True


@pytest.mark.asyncio
async def test_run_relay_pump_consumes_going_down_unit() -> None:
    """With a relay sink wired, a ``going_down`` SeqFrame unit is CONSUMED (drives the
    machine -> reconnecting), not relayed — the raw path honours lifecycle consume.
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()
    sink = _RelaySink()
    going_down = _payload_unit(json.dumps(_going_down_frame()).encode(), seq=0)
    first = _ScriptedCoreTransport([_start_only(epoch1), going_down, None])
    blocked = asyncio.Event()
    second = _ScriptedCoreTransport([_start_only(epoch2), blocked])
    dial = _DialRecorder([lambda: first, lambda: second])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown, payload_relay=sink)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # The going_down was consumed (gap), not relayed; the reconnect restored.
    assert sink.received == []
    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]


@pytest.mark.asyncio
async def test_run_relay_pump_eof_gaps_and_reconnects() -> None:
    """The relay pump's clean-EOF arm opens the gap + reconnects (identical to the
    parsed-pump EOF arm), so the relay path keeps the reconnect machinery.
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()
    sink = _RelaySink()
    first = _ScriptedCoreTransport([_start_only(epoch1), None])  # start then immediate EOF
    blocked = asyncio.Event()
    second = _ScriptedCoreTransport([_start_only(epoch2), blocked])
    dial = _DialRecorder([lambda: first, lambda: second])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown, payload_relay=sink)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]
    assert first.closed is True
    assert second.closed is True


@pytest.mark.asyncio
async def test_run_relay_pump_crash_exception_gaps_and_reconnects() -> None:
    """The relay pump's transport-crash arm (a raised read) gaps + reconnects too."""
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()
    sink = _RelaySink()
    first = _ScriptedCoreTransport([_start_only(epoch1), ConnectionResetError()])
    blocked = asyncio.Event()
    second = _ScriptedCoreTransport([_start_only(epoch2), blocked])
    dial = _DialRecorder([lambda: first, lambda: second])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown, payload_relay=sink)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]


@pytest.mark.asyncio
async def test_run_relay_pump_shutdown_at_loop_top_returns_clean() -> None:
    """The relay pump's top-of-loop shutdown check returns cleanly (no banner)."""
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    shutdown.set()
    sink = _RelaySink()
    only = _ScriptedCoreTransport([_start_only(epoch)])  # handshake only
    dial = _DialRecorder([lambda: only])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown, payload_relay=sink)

    await asyncio.wait_for(link.run(), timeout=1.0)

    assert recorder.controls == []
    assert only.closed is True


@pytest.mark.asyncio
async def test_run_relay_pump_shutdown_while_blocked_returns_clean() -> None:
    """Shutdown while the relay pump is BLOCKED on a payload read returns clean."""
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    sink = _RelaySink()
    read_blocked = asyncio.Event()
    only = _ScriptedCoreTransport([_start_only(epoch), read_blocked])
    dial = _DialRecorder([lambda: only])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown, payload_relay=sink)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if only.sent:
            break
    assert only.sent, "handshake should have completed before shutdown"
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert recorder.controls == []
    assert only.closed is True


@pytest.mark.asyncio
async def test_run_relay_pump_unit_without_seq_skips_tracker() -> None:
    """A relay unit with ``seq is None`` (a plain non-negotiated frame on the leg) is
    still FORWARDED but does NOT touch the receive tracker — the ``_pump_once``
    seq-None branch.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    sink = _RelaySink()
    body = b'{"method":"inbound.message","params":{}}'
    blocked = asyncio.Event()
    # A unit with seq=None (a plain frame) followed by a blocked read.
    transport = _ScriptedCoreTransport([_start_only(epoch), _payload_unit(body, seq=None), blocked])
    dial = _DialRecorder([lambda: transport])
    link, recorder = _run_link(dial=dial, shutdown_event=shutdown, payload_relay=sink)

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if sink.received:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert sink.received == [body]
    # No seq -> the receive tracker never advanced past its initial -1.
    assert link._core_tracker.cumulative_ack() == -1
    assert recorder.controls == []


def test_init_stores_injected_replay_buffer() -> None:
    """Spec A G4b-2a (#237): an injected ``ReplayBuffer`` is stored on the link.

    The first foundation step: the (already-merged, pure) un-acked-inbound retention
    buffer is constructor-injected so later G4b-2a tasks can append/trim against it.
    """
    buf = ReplayBuffer()
    link = GatewayCoreLink(client_listener=_RecordingClientListener(), replay_buffer=buf)  # type: ignore[arg-type]
    assert link._replay_buffer is buf


def test_init_replay_buffer_defaults_to_none() -> None:
    """No ``replay_buffer`` kwarg leaves buffering OFF — the merged G3 relay tests
    construct unchanged (``None`` is the default, so no behaviour shifts).
    """
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    assert link._replay_buffer is None
