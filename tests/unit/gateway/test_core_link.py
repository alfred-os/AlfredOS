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
    LinkUnavailableNotification,
)
from alfred.gateway.client_listener import LinkControlNotification
from alfred.gateway.core_link import (
    _BUFFER_EVICT_INTERVAL_SECONDS,
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
    BUFFER_CAP_RATIO,
    BUFFER_DEPTH_BYTES,
    BUFFER_DEPTH_FRAMES,
    CIRCUIT_BREAKER_OPEN,
    CORE_LINK_UP,
    CORE_UNAVAILABLE_SECONDS,
    RECONNECT_ATTEMPTS,
)
from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError, ReplayFrame
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
    replay_buffer: ReplayBuffer | None = None,
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
        replay_buffer=replay_buffer,
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


# ---------------------------------------------------------------------------
# Task 4 (Spec A G4b-2a / ADR-0032): the daemon.comms.ack trims the ReplayBuffer.
# The daemon emits the ack ONLY on its G0 durable-intake commit, so the cumulative
# ack is epoch-validated by construction; trim drops the seq<=ack leading prefix.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_route_unit_daemon_comms_ack_trims_the_replay_buffer() -> None:
    """A ``daemon.comms.ack`` with ``cumulative_ack=2`` trims seqs 0,1,2 — seq 3 stays.

    The ack unit is CONSUMED (never relayed) and ``trim_to_ack(2)`` removes the leading
    prefix, leaving only the un-acked seq 3.
    """
    epoch = uuid4().hex
    buf = ReplayBuffer()
    for seq in (0, 1, 2, 3):
        buf.append(seq, b"x", now=float(seq))
    link, _recorder, sink = _link_with_relay_and_buffer(buffer=buf)
    link._core_epoch = epoch
    body = json.dumps({"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": 2}}).encode()

    await link._route_unit(_payload_unit(body))

    assert buf.depth_frames == 1  # only seq 3 retained
    assert buf.unacked_frames()[0].seq == 3
    assert sink.received == []  # the ack unit was NOT forwarded to the client


@pytest.mark.parametrize(
    "params",
    [
        {},  # no cumulative_ack at all
        {"cumulative_ack": "2"},  # non-int
        {"cumulative_ack": True},  # a JSON ``true`` must NOT be treated as ack=1
        {"cumulative_ack": -1},  # negative
    ],
)
@pytest.mark.asyncio
async def test_route_unit_daemon_comms_ack_malformed_does_not_trim(
    params: dict[str, object],
) -> None:
    """A malformed/missing ``cumulative_ack`` is CONSUMED, never trims, never raises."""
    epoch = uuid4().hex
    buf = ReplayBuffer()
    for seq in (0, 1, 2):
        buf.append(seq, b"x", now=float(seq))
    link, _recorder, sink = _link_with_relay_and_buffer(buffer=buf)
    link._core_epoch = epoch
    body = json.dumps({"method": DAEMON_COMMS_ACK, "params": params}).encode()

    with structlog.testing.capture_logs() as captured:
        await link._route_unit(_payload_unit(body))  # must NOT raise

    assert buf.depth_frames == 3  # unchanged — no trim
    assert sink.received == []  # still consumed, never relayed
    malformed = [
        c for c in captured if c.get("event") == "gateway.core_link.daemon_comms_ack_malformed"
    ]
    assert len(malformed) == 1
    assert malformed[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_route_unit_daemon_comms_ack_no_buffer_is_noop() -> None:
    """With NO buffer injected, the ack consume is the existing no-op (not relayed)."""
    epoch = uuid4().hex
    link, _recorder, sink = _link_with_relay(epoch=epoch)  # default replay_buffer=None
    assert link._replay_buffer is None
    body = json.dumps({"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": 4}}).encode()

    await link._route_unit(_payload_unit(body))  # no crash

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


# ---------------------------------------------------------------------------
# Task 3 (Spec A G4b-2a / ADR-0032): append-before-send into the ReplayBuffer.
# ``relay_to_core`` appends the inbound frame keyed on its wire seq BEFORE the
# best-effort send, so a loud-dropped send still leaves the frame durably held.
# ---------------------------------------------------------------------------


def _link_with_relay_and_buffer(
    *, buffer: ReplayBuffer
) -> tuple[GatewayCoreLink, _RecordingClientListener, _RelaySink]:
    """A relay-wired core link with an injected :class:`ReplayBuffer`."""
    recorder = _RecordingClientListener()
    sink = _RelaySink()
    link = GatewayCoreLink(
        client_listener=recorder,  # type: ignore[arg-type]
        payload_relay=sink,  # type: ignore[arg-type]
        replay_buffer=buffer,
    )
    return link, recorder, sink


@pytest.mark.asyncio
async def test_relay_to_core_appends_inbound_frame_keyed_on_wire_seq() -> None:
    """With a buffer injected, ``relay_to_core`` appends ``(seq=0, payload)`` then sends.

    The buffered seq is the EXACT wire seq passed to the transport — append-before-send
    keys the durable record on the same counter the send carries.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    await link.relay_to_core(b"x")

    assert buf.depth_frames == 1
    # The seq passed to the transport equals the buffered seq (0).
    wire_seq = transport.sent_units[0][1]
    assert wire_seq == 0
    assert buf.unacked_frames()[0].seq == wire_seq


@pytest.mark.asyncio
async def test_relay_to_core_loud_drop_still_leaves_frame_buffered() -> None:
    """A loud-dropped send STILL leaves the appended frame in the buffer.

    Append happens BEFORE the send, so a broken-pipe drop does not unwind the durable
    record — G4b-2b replays the held frame once the leg is back.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport([])
    transport.send_unit_error = BrokenPipeError()
    link._current_core_transport = transport

    with structlog.testing.capture_logs():
        await link.relay_to_core(b"x")  # send loud-drops; append already happened

    assert transport.sent_units == []  # nothing reached the wire
    assert buf.depth_frames == 1  # the frame is still durably held


@pytest.mark.asyncio
async def test_relay_to_core_no_buffer_still_advances_seq() -> None:
    """With NO buffer (default ``None``), ``relay_to_core`` behaves exactly as before.

    No crash on a buffer-less link, and the send-seq still advances: a second call
    mints seq 1.
    """
    link, _recorder, _sink = _link_with_relay()  # default replay_buffer=None
    assert link._replay_buffer is None
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    await link.relay_to_core(b"one")
    await link.relay_to_core(b"two")

    assert [(p, s) for (p, s, _a) in transport.sent_units] == [(b"one", 0), (b"two", 1)]


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


def test_init_pending_replay_starts_empty() -> None:
    """Spec A G4b-2b (#237): a fresh link's ``_pending_replay`` stash is the empty tuple.

    The reconnect-replay foundation: the un-acked frames captured before a reconnect
    reset land here awaiting re-send. A fresh link / first connect has none pending.
    """
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    assert link._pending_replay == ()


def test_init_replay_pending_gate_starts_set() -> None:
    """Spec A G4b-2b (#237): the replay-pending gate is an ``asyncio.Event``, SET at ctor.

    The relay's client->core pump awaits this gate; SET = the pump may run. A fresh link
    has no reconnect-replay pending, so the gate starts SET.
    """
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    assert isinstance(link.replay_pending_gate, asyncio.Event)
    assert link.replay_pending_gate.is_set() is True


# ---------------------------------------------------------------------------
# Task 5 (Spec A G4b-2b / ADR-0032): a fresh core leg is a fresh seq space, so any
# frames still held under the OLD epoch are CAPTURED before the floor-reset (replacing
# the G4b-2a loud-drop) so they can be replayed on epoch B's leg — replayed frames take
# the lowest seqs (precede fresh input). The capture clears the replay-pending gate so
# the relay's client->core pump HOLDS until the flush re-sends them; an empty buffer
# (first connect / fully-acked reconnect) is a no-op and the gate stays set. The
# floor-reset stays unconditional (comms-1). No ``buffer_reset_input_loss`` row is
# emitted in 2b — capture, not loss.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_peer_handshake_captures_unacked_and_clears_gate_on_reconnect() -> None:
    """A reconnect handshake CAPTURES held epoch-A frames for replay, then resets epoch B.

    Pre-load two frames via the REAL relay path (faithful: append-before-send keys on
    the wire seq), drive a fresh ``_peer_handshake``, and assert ``_pending_replay`` holds
    the captured frames (FIFO, original seqs), the replay-pending gate is CLEARED (the
    pump must hold), an emptied + un-tripped buffer afterwards, and a subsequent epoch-B
    ``relay_to_core`` appending seq 0 WITHOUT raising (the strict-increase guard would
    otherwise reject 0 after seq N). NO loss row is emitted — 2b captures, never drops.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport1 = _FakeCoreTransport([])
    link._current_core_transport = transport1
    await link.relay_to_core(b"a")  # buffered seq 0
    await link.relay_to_core(b"b")  # buffered seq 1
    assert buf.depth_frames == 2

    epoch = uuid4().hex
    transport2 = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})])
    with structlog.testing.capture_logs() as captured:
        await link._peer_handshake(transport2)  # fresh leg -> capture + reset

    # The un-acked remainder is captured for replay, FIFO, carrying its ORIGINAL seqs.
    assert [f.seq for f in link._pending_replay] == [0, 1]
    assert [f.payload for f in link._pending_replay] == [b"a", b"b"]
    # The pump must HOLD until the flush re-sends these: the gate is cleared.
    assert link.replay_pending_gate.is_set() is False
    # 2b captures, never drops: no loud input-loss row survives the handshake.
    loss = [c for c in captured if c.get("event") == "gateway.comms.buffer_reset_input_loss"]
    assert loss == []
    assert buf.depth_frames == 0  # the held frames are gone from the buffer (captured + reset)
    assert buf.breaker_tripped is False  # the reset cleared the latch too

    # Epoch B: the send-seq restarted at 0, and the buffer floor reset accepts it.
    link._current_core_transport = transport2
    await link.relay_to_core(b"fresh")  # must NOT raise the strict-increase guard
    assert buf.depth_frames == 1
    assert buf.unacked_frames()[0].seq == 0


@pytest.mark.asyncio
async def test_peer_handshake_prepends_deferred_remainder_ahead_of_fresh_capture() -> None:
    """A deferred remainder (R1) survives the next handshake, replaying BEFORE the capture.

    The FIFO-merge guarantee (review): when a prior None-transport flush re-stashed an
    un-sent remainder into ``_pending_replay`` (which is NOT in the buffer, so
    ``unacked_frames()`` excludes it), the NEXT ``_peer_handshake`` must PREPEND that
    deferred remainder ahead of this epoch's freshly-captured frames — never overwrite it
    (the pre-fix overwrite silently lost the deferred frames, breaking R1 no-silent-loss).
    Deferred frames are older in the stream, so they replay FIRST; the core dedups any
    already-committed re-send on the in-payload ``inbound_id``.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    # Simulate a prior defer: two un-sent frames (NOT in the buffer) stashed for replay.
    deferred = (ReplayFrame(seq=7, payload=b"d0"), ReplayFrame(seq=8, payload=b"d1"))
    link._pending_replay = deferred
    # One fresh un-acked frame appended to the buffer via the REAL relay path.
    transport1 = _FakeCoreTransport([])
    link._current_core_transport = transport1
    await link.relay_to_core(b"fresh0")  # buffered seq 0
    assert buf.depth_frames == 1

    epoch = uuid4().hex
    transport2 = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})])
    with structlog.testing.capture_logs():
        await link._peer_handshake(transport2)

    # FIFO: the deferred remainder leads, then this epoch's freshly-captured frame.
    assert link._pending_replay == (*deferred, ReplayFrame(seq=0, payload=b"fresh0"))
    # A non-empty merged stash holds the pump (the gate is cleared) and empties the buffer.
    assert link.replay_pending_gate.is_set() is False
    assert buf.depth_frames == 0


@pytest.mark.asyncio
async def test_peer_handshake_no_deferred_remainder_captures_fresh_only() -> None:
    """The normal case (no deferred remainder): the handshake captures only the fresh frame.

    With ``_pending_replay`` already the empty tuple (no prior defer), the FIFO-merge is a
    no-op prepend: ``_pending_replay`` ends as exactly this epoch's freshly-captured frame.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    assert link._pending_replay == ()  # no prior defer
    transport1 = _FakeCoreTransport([])
    link._current_core_transport = transport1
    await link.relay_to_core(b"only0")  # buffered seq 0

    epoch = uuid4().hex
    transport2 = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})])
    with structlog.testing.capture_logs():
        await link._peer_handshake(transport2)

    assert link._pending_replay == (ReplayFrame(seq=0, payload=b"only0"),)
    assert link.replay_pending_gate.is_set() is False
    assert buf.depth_frames == 0


@pytest.mark.asyncio
async def test_peer_handshake_reset_prevents_cross_epoch_trim() -> None:
    """After the reset, a fresh-leg ack over the OLD seqs removes nothing epoch B holds.

    The epoch-A frames are already gone (dropped + reset), so a ``daemon.comms.ack``
    whose ``cumulative_ack`` is >= the old high-water trims only what epoch B appended —
    never silently losing a frame the NEW core never committed.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    epoch_a_transport = _FakeCoreTransport([])
    link._current_core_transport = epoch_a_transport
    await link.relay_to_core(b"a")  # epoch-A seq 0
    await link.relay_to_core(b"b")  # epoch-A seq 1

    epoch = uuid4().hex
    transport2 = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})])
    with structlog.testing.capture_logs():
        await link._peer_handshake(transport2)  # drop epoch-A frames + reset
    link._current_core_transport = transport2
    await link.relay_to_core(b"fresh")  # epoch-B seq 0
    assert buf.depth_frames == 1  # only the epoch-B frame

    # An ack carrying a cumulative_ack >= the old epoch-A high-water (1). It can only
    # trim epoch B's seq-0 frame (which IS <= 5) — there is nothing stale left to lose.
    body = json.dumps({"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": 5}}).encode()
    await link._route_unit(_payload_unit(body))
    assert buf.depth_frames == 0  # only the epoch-B append was ever reflected, then trimmed


@pytest.mark.asyncio
async def test_peer_handshake_first_connect_empty_buffer_is_noop() -> None:
    """The VERY FIRST handshake (empty buffer) captures nothing and leaves the gate SET.

    The floor reset runs UNCONDITIONALLY (comms-1), but an empty buffer has no
    retained frames, so ``unacked_frames()`` is empty -> nothing captured, the
    replay-pending gate stays SET (no flush to wait on), and the reset is a no-op beyond
    the (already-fresh) floor rebind — no ``_has_connected`` flag needed.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport(
        [_start_frame(epoch=uuid4().hex, seq_ack={"version": SEQ_VERSION})]
    )

    with structlog.testing.capture_logs() as captured:
        await link._peer_handshake(transport)  # empty buffer -> nothing captured, gate stays set

    assert link._pending_replay == ()  # nothing held -> nothing captured
    assert link.replay_pending_gate.is_set() is True  # no flush pending -> pump runs free
    loss = [c for c in captured if c.get("event") == "gateway.comms.buffer_reset_input_loss"]
    assert loss == []  # 2b never emits a loss row
    assert buf.depth_frames == 0


@pytest.mark.asyncio
async def test_peer_handshake_fully_acked_reconnect_resets_floor_no_crash() -> None:
    """A FULLY-ACKED reconnect (empty buffer, stale-high floor) resets the floor cleanly.

    The crash (comms-1): ``trim_to_ack`` empties the buffer WITHOUT resetting
    ``_last_seq`` (stale-frame rejection by design). So a reconnect after the daemon
    acked everything hits the handshake with ``depth_frames == 0`` — a depth>0 reset
    guard would SKIP the floor reset, leave ``_last_seq`` stale-high, and the next
    ``relay_to_core`` epoch-B ``append(0, …)`` would trip the strict-increase guard and
    crash the relay pump. The fix resets the floor UNCONDITIONALLY: assert the post-
    reconnect ``relay_to_core(b"x")`` appends seq 0 WITHOUT raising, that NOTHING was
    captured for replay (an empty buffer has no un-acked remainder), and the replay-
    pending gate stays SET (nothing to flush).
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport1 = _FakeCoreTransport([])
    link._current_core_transport = transport1
    await link.relay_to_core(b"a")  # buffered seq 0
    await link.relay_to_core(b"b")  # buffered seq 1
    # The daemon durably acks EVERYTHING — the buffer drains but _last_seq stays high (1).
    buf.trim_to_ack(1)
    assert buf.depth_frames == 0
    assert buf._last_seq == 1  # stale-high floor: the bug's precondition

    epoch = uuid4().hex
    transport2 = _FakeCoreTransport([_start_frame(epoch=epoch, seq_ack={"version": SEQ_VERSION})])
    with structlog.testing.capture_logs() as captured:
        await link._peer_handshake(transport2)  # reconnect: must reset the floor

    # Empty buffer -> nothing captured, gate stays set, no loss row.
    assert link._pending_replay == ()
    assert link.replay_pending_gate.is_set() is True
    loss = [c for c in captured if c.get("event") == "gateway.comms.buffer_reset_input_loss"]
    assert loss == []
    # Epoch B: the floor reset accepts a fresh seq-0 append WITHOUT the strict-increase
    # crash that would otherwise escape the relay pump and tear the gateway down.
    link._current_core_transport = transport2
    await link.relay_to_core(b"x")  # must NOT raise ReplayBufferError("seq must strictly increase")
    assert buf.depth_frames == 1
    assert buf.unacked_frames()[0].seq == 0


@pytest.mark.asyncio
async def test_peer_handshake_no_buffer_injected_does_not_crash() -> None:
    """A link with ``replay_buffer=None`` handshakes normally — no buffer touched."""
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    assert link._replay_buffer is None
    transport = _FakeCoreTransport(
        [_start_frame(epoch=uuid4().hex, seq_ack={"version": SEQ_VERSION})]
    )

    with structlog.testing.capture_logs() as captured:
        await link._peer_handshake(transport)  # must NOT crash on a None buffer

    assert link._core_epoch is not None  # the handshake still captured the epoch
    assert link._pending_replay == ()  # no buffer -> nothing captured
    assert link.replay_pending_gate.is_set() is True  # gate stays set with no buffer
    loss = [c for c in captured if c.get("event") == "gateway.comms.buffer_reset_input_loss"]
    assert loss == []


# ---------------------------------------------------------------------------
# Task 6 (Spec A G4b-2a / ADR-0032): a ReplayBuffer soft-cap breach latches the
# breaker; ``relay_to_core`` feeds BREAKER_TRIPPED UNCONDITIONALLY and the link-state
# machine (NOT a gateway-local flag) escalates to UNAVAILABLE exactly ONCE — emitting
# a single ``link.unavailable`` control to the client + ONE loud audit row. A repeat
# tripped append re-feeds the absorbing machine, which returns ``None`` (no second
# control, no second row). CLAUDE.md hard rule #7 — back-pressure is never silent.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relay_to_core_breaker_trip_escalates_link_unavailable_once() -> None:
    """A soft-cap breach sends ONE ``link.unavailable`` + ONE ``breaker_tripped`` row.

    ``max_frames=1`` -> the first append (depth 1) does NOT trip; the second append
    (depth 2 > 1) trips the breaker. On that tripped ``relay_to_core`` the gateway
    feeds BREAKER_TRIPPED, the machine escalates UP -> UNAVAILABLE emitting
    ``LinkControl.UNAVAILABLE``, and the gateway pushes a single
    :class:`LinkUnavailableNotification` to the client + writes ONE loud structlog row
    carrying the buffer depth.
    """
    buf = ReplayBuffer(max_frames=1)
    link, recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"one")  # depth 1 — no trip, no escalation
        assert not buf.breaker_tripped
        assert recorder.controls == []
        await link.relay_to_core(b"two")  # depth 2 > 1 — trips + escalates

    assert buf.breaker_tripped
    # The client received exactly ONE link.unavailable control frame (listener spy).
    assert [type(c) for c in recorder.controls] == [LinkUnavailableNotification]
    # Exactly ONE loud audit row, carrying the buffer depth (no secrets).
    rows = [c for c in captured if c.get("event") == "gateway.comms.breaker_tripped"]
    assert len(rows) == 1
    assert rows[0].get("log_level") == "warning"
    assert rows[0].get("depth_frames") == buf.depth_frames
    assert rows[0].get("depth_bytes") == buf.depth_bytes


@pytest.mark.asyncio
async def test_relay_to_core_breaker_idempotent_refeed_no_second_escalation() -> None:
    """A repeat tripped append re-feeds the absorbing machine — NO second control/row.

    ``max_frames=2`` -> hard ceiling = 4 frames. Depths 1,2 do not trip; depth 3 (> 2)
    trips + escalates; depth 4 (> 2, latch held) is the IDEMPOTENT re-feed. The machine
    is UNAVAILABLE (absorbing) on that second tripped append, so ``_feed`` returns
    ``None``: the client sees only ONE ``link.unavailable`` and only ONE row across BOTH
    tripped appends. Depth 4 stays strictly under the hard ceiling (4 frames), so the
    second append does not raise.
    """
    buf = ReplayBuffer(max_frames=2)
    link, recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"a")  # depth 1
        await link.relay_to_core(b"b")  # depth 2 — at cap, no trip
        await link.relay_to_core(b"c")  # depth 3 > 2 — trips + escalates ONCE
        await link.relay_to_core(b"d")  # depth 4 > 2 — latch held, idempotent re-feed

    assert buf.breaker_tripped
    assert buf.depth_frames == 4  # all four held; hard ceiling (4) NOT breached
    # Exactly ONE escalation reached the client despite TWO tripped appends.
    assert [type(c) for c in recorder.controls] == [LinkUnavailableNotification]
    rows = [c for c in captured if c.get("event") == "gateway.comms.breaker_tripped"]
    assert len(rows) == 1  # the absorbing re-feed returned None -> no second row


@pytest.mark.asyncio
async def test_relay_to_core_under_cap_no_breaker_escalation() -> None:
    """An append that stays under the cap feeds NO BREAKER_TRIPPED + writes no row."""
    buf = ReplayBuffer(max_frames=8)
    link, recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"x")

    assert not buf.breaker_tripped
    assert recorder.controls == []  # no escalation
    assert link._machine.state is GatewayLinkState.UP  # machine untouched by the breaker
    rows = [c for c in captured if c.get("event") == "gateway.comms.breaker_tripped"]
    assert rows == []


@pytest.mark.asyncio
async def test_relay_to_core_no_buffer_never_references_breaker() -> None:
    """With ``replay_buffer=None`` the breaker branch is never entered (no escalation)."""
    link, recorder, _sink = _link_with_relay()  # default replay_buffer=None
    assert link._replay_buffer is None
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    with structlog.testing.capture_logs() as captured:
        await link.relay_to_core(b"one")

    assert recorder.controls == []  # buffer-less link never escalates
    rows = [c for c in captured if c.get("event") == "gateway.comms.breaker_tripped"]
    assert rows == []


# ---------------------------------------------------------------------------
# Spec A G4b-2a (#237 / R4): the relay's client read-halt seams on GatewayCoreLink —
# a read-only ``replay_buffer_tripped`` property the relay polls, and a
# ``wait_for_shutdown`` park the halted pump blocks on until the relay TaskGroup
# cancels it (the latch is TERMINAL in 2a; 2b adds the reset that clears it).
# ---------------------------------------------------------------------------


def test_replay_buffer_tripped_is_false_with_no_buffer() -> None:
    """No buffer injected -> the property is ``False`` (buffering off)."""
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    assert link._replay_buffer is None
    assert link.replay_buffer_tripped is False


def test_replay_buffer_tripped_is_false_with_untripped_buffer() -> None:
    """An injected but un-latched buffer -> ``False``."""
    buf = ReplayBuffer()
    link = GatewayCoreLink(client_listener=_RecordingClientListener(), replay_buffer=buf)  # type: ignore[arg-type]
    assert buf.breaker_tripped is False
    assert link.replay_buffer_tripped is False


@pytest.mark.asyncio
async def test_replay_buffer_tripped_is_true_after_breaker_latches() -> None:
    """Once the injected buffer's breaker latches (soft-cap breach), the property is ``True``.

    Drive a real trip via the relay path on a ``max_frames=1`` buffer: the second
    append breaches the soft cap and latches the breaker.
    """
    buf = ReplayBuffer(max_frames=1)
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    assert link.replay_buffer_tripped is False
    with structlog.testing.capture_logs():
        await link.relay_to_core(b"one")  # depth 1 — no trip
        assert link.replay_buffer_tripped is False
        await link.relay_to_core(b"two")  # depth 2 > 1 — trips

    assert buf.breaker_tripped is True
    assert link.replay_buffer_tripped is True


@pytest.mark.asyncio
async def test_wait_for_shutdown_returns_when_wired_event_set() -> None:
    """With a wired shutdown event, ``wait_for_shutdown`` RETURNS once the event fires."""
    shutdown = asyncio.Event()
    link = GatewayCoreLink(
        client_listener=_RecordingClientListener(),  # type: ignore[arg-type]
        shutdown_event=shutdown,
    )

    shutdown.set()
    # Returns promptly (the event is already set) — no timeout.
    await asyncio.wait_for(link.wait_for_shutdown(), timeout=1.0)


@pytest.mark.asyncio
async def test_wait_for_shutdown_blocks_forever_with_no_event() -> None:
    """With NO shutdown event wired, ``wait_for_shutdown`` BLOCKS (parks until cancelled).

    Covers the ``shutdown_event is None`` else branch: the park does not complete within
    a short window, so ``asyncio.wait_for`` times out (the throwaway block-forever Event
    is never set; only a cancel — which ``wait_for`` raises here as a timeout — ends it).
    """
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    assert link._shutdown_event is None

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(link.wait_for_shutdown(), timeout=0.05)


# ---------------------------------------------------------------------------
# Spec A G4b-2a (#237): buffer observability gauges + the supervised TTL-eviction
# timer. The gauges track the live buffer after every mutation; the evict loop
# periodically drops TTL-expired un-acked frames, auditing each as input-loss.
# ---------------------------------------------------------------------------


def _reset_buffer_gauges() -> None:
    """Zero the process-global buffer gauges so a test reads only its own writes.

    The four gauges are module-level singletons shared across every test; resetting
    at the top of a test that asserts a gauge VALUE keeps it independent of ordering.
    """
    BUFFER_DEPTH_FRAMES.set(0)
    BUFFER_DEPTH_BYTES.set(0)
    BUFFER_CAP_RATIO.set(0)
    CIRCUIT_BREAKER_OPEN.set(0)


@pytest.mark.asyncio
async def test_buffer_evict_loop_audits_each_dropped_seq_and_refreshes_gauges() -> None:
    """One sweep evicts the TTL-expired prefix, audits each seq, and pushes the gauges.

    Pre-load three frames, advance the injected monotonic clock past the TTL, and run
    ONE evict sweep: every evicted seq gets a ``gateway.comms.buffer_evicted`` warn row,
    and the depth gauges reflect the post-evict (empty) buffer.
    """
    _reset_buffer_gauges()
    buf = ReplayBuffer(max_frames=8, max_bytes=1024, ttl_seconds=30.0)
    for seq in range(3):
        buf.append(seq, b"x", now=float(seq))

    clock = {"now": 100.0}  # 100 > 2 (last enqueue) + 30 (ttl) -> all three expired

    sweeps = {"n": 0}

    async def _sleep(_delay: float) -> None:
        # Return immediately on the FIRST call (so the loop body runs one sweep), then
        # park forever on every later call until the test cancels the loop task — a
        # second sweep would find an empty buffer (the 0-evict branch has its own test).
        sweeps["n"] += 1
        if sweeps["n"] == 1:
            return
        await asyncio.Event().wait()

    link, _recorder = _run_link(
        dial=_DialRecorder([]),
        sleep=_sleep,
        monotonic=lambda: clock["now"],
        replay_buffer=buf,
    )

    with structlog.testing.capture_logs() as captured:
        task = asyncio.ensure_future(link._buffer_evict_loop())
        for _ in range(50):
            await asyncio.sleep(0)
            if buf.depth_frames == 0:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    evicted = [c for c in captured if c.get("event") == "gateway.comms.buffer_evicted"]
    assert [c.get("seq") for c in evicted] == [0, 1, 2]
    assert all(c.get("log_level") == "warning" for c in evicted)
    assert all(c.get("reason") == "ttl_expired" for c in evicted)
    assert buf.depth_frames == 0
    assert BUFFER_DEPTH_FRAMES._value.get() == 0
    assert BUFFER_DEPTH_BYTES._value.get() == 0


@pytest.mark.asyncio
async def test_buffer_evict_loop_empty_sweep_audits_nothing() -> None:
    """A sweep that evicts NOTHING (no frame expired) writes no input-loss row.

    Covers the empty per-seq loop branch: the buffer holds an un-expired frame, so the
    single sweep evicts nothing and emits no ``buffer_evicted`` audit.
    """
    _reset_buffer_gauges()
    buf = ReplayBuffer(max_frames=8, max_bytes=1024, ttl_seconds=30.0)
    buf.append(0, b"x", now=0.0)

    sweeps = {"n": 0}

    async def _sleep(_delay: float) -> None:
        # One sweep, then park (as in the eviction test) so the body runs exactly once.
        sweeps["n"] += 1
        if sweeps["n"] == 1:
            return
        await asyncio.Event().wait()

    link, _recorder = _run_link(
        dial=_DialRecorder([]),
        sleep=_sleep,
        monotonic=lambda: 1.0,  # 1 - 0 = 1 <= 30 ttl -> nothing expired
        replay_buffer=buf,
    )

    with structlog.testing.capture_logs() as captured:
        task = asyncio.ensure_future(link._buffer_evict_loop())
        for _ in range(10):
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert [c for c in captured if c.get("event") == "gateway.comms.buffer_evicted"] == []
    assert buf.depth_frames == 1  # the un-expired frame is retained


@pytest.mark.asyncio
async def test_buffer_evict_loop_is_loud_and_continues_when_a_sweep_raises() -> None:
    """A sweep that raises ``ReplayBufferError`` is LOUD and the loop CONTINUES (H2).

    The TTL bound is a security property (spec §6) — a one-off sweep fault (e.g. a
    regressed monotonic read) must NOT silently end enforcement (hard rule #7). Inject a
    buffer whose ``evict_expired`` raises ONCE then succeeds; assert the loop logs
    ``gateway.comms.buffer_evict_failed`` on the first tick and goes on to evict on the
    second (proving it did not die).
    """
    _reset_buffer_gauges()
    buf = ReplayBuffer(max_frames=8, max_bytes=1024, ttl_seconds=30.0)
    buf.append(0, b"x", now=0.0)
    clock = {"now": 100.0}  # 100 > 0 + 30 ttl -> seq 0 is expired on the real sweep

    real_evict = buf.evict_expired
    calls = {"n": 0}

    def _evict_once_raises(*, now: float) -> tuple[int, ...]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ReplayBufferError("simulated regressed-clock sweep fault")
        return real_evict(now=now)

    buf.evict_expired = _evict_once_raises  # type: ignore[method-assign]

    sweeps = {"n": 0}

    async def _sleep(_delay: float) -> None:
        # Two sweeps (the raise, then the success), then park forever.
        sweeps["n"] += 1
        if sweeps["n"] <= 2:
            return
        await asyncio.Event().wait()

    link, _recorder = _run_link(
        dial=_DialRecorder([]),
        sleep=_sleep,
        monotonic=lambda: clock["now"],
        replay_buffer=buf,
    )

    with structlog.testing.capture_logs() as captured:
        task = asyncio.ensure_future(link._buffer_evict_loop())
        for _ in range(50):
            await asyncio.sleep(0)
            if buf.depth_frames == 0:  # the SECOND (successful) sweep evicted seq 0
                break
        assert not task.done(), "the loop must survive the raising sweep, not die"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    failed = [c for c in captured if c.get("event") == "gateway.comms.buffer_evict_failed"]
    assert len(failed) == 1  # the first sweep raised -> loud, exactly once
    assert failed[0].get("log_level") == "error"
    # The loop CONTINUED: the second sweep evicted seq 0 (the loop did not die on the raise).
    evicted = [c for c in captured if c.get("event") == "gateway.comms.buffer_evicted"]
    assert [c.get("seq") for c in evicted] == [0]
    assert buf.depth_frames == 0


@pytest.mark.asyncio
async def test_on_evict_task_done_is_loud_on_failure_silent_on_cancel() -> None:
    """``_on_evict_task_done`` logs ``buffer_evict_loop_died`` on a failed task, and is
    SILENT on a cancelled one (the loop's normal reap path).

    A pure callback test: it inspects the task's cancelled/exception state (the futures
    are constructed under a running loop). The done-callback is the backstop that makes
    an unexpected (non-cancelled) loop death loud (H2 / hard rule #7).
    """
    loop = asyncio.get_running_loop()
    # A failed task: an exception escaped the loop -> loud death row.
    failed_task: asyncio.Future[None] = loop.create_future()
    failed_task.set_exception(ReplayBufferError("loop died unexpectedly"))
    with structlog.testing.capture_logs() as captured:
        GatewayCoreLink._on_evict_task_done(failed_task)  # type: ignore[arg-type]
    died = [c for c in captured if c.get("event") == "gateway.comms.buffer_evict_loop_died"]
    assert len(died) == 1
    assert died[0].get("log_level") == "error"
    failed_task.exception()  # retrieve so the loop does not warn about an un-retrieved exc

    # A cancelled task: the normal reap path -> NO row (the callback returns early).
    cancelled_task: asyncio.Future[None] = loop.create_future()
    cancelled_task.cancel()
    with structlog.testing.capture_logs() as captured:
        GatewayCoreLink._on_evict_task_done(cancelled_task)  # type: ignore[arg-type]
    assert [c for c in captured if c.get("event") == "gateway.comms.buffer_evict_loop_died"] == []

    # A normally-completed task (no exception, not cancelled): also SILENT. The loop is
    # ``while True`` so it never returns cleanly in production, but the callback is a
    # generic done-handler and the ``exc is None`` exit branch must stay covered.
    done_task: asyncio.Future[None] = loop.create_future()
    done_task.set_result(None)
    with structlog.testing.capture_logs() as captured:
        GatewayCoreLink._on_evict_task_done(done_task)  # type: ignore[arg-type]
    assert [c for c in captured if c.get("event") == "gateway.comms.buffer_evict_loop_died"] == []


@pytest.mark.asyncio
async def test_run_spawns_and_reaps_the_evict_task_when_a_buffer_is_injected() -> None:
    """``run`` spawns the evict loop after the initial connect and cancels it on shutdown.

    With a buffer injected, the supervised lifecycle creates the evict task; when the
    shutdown event fires ``run`` returns and the evict task is reaped (done) — no leak.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    blocked = asyncio.Event()
    transport = _ScriptedCoreTransport([_start_only(epoch), blocked])
    dial = _DialRecorder([lambda: transport])

    async def _evict_sleep(_delay: float) -> None:
        await asyncio.Event().wait()  # the evict loop parks; shutdown reaps it

    buf = ReplayBuffer()
    link, _recorder = _run_link(
        dial=dial, shutdown_event=shutdown, sleep=_evict_sleep, replay_buffer=buf
    )

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if transport.sent:  # handshake done -> the evict task has been spawned
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # The evict task was created AND reaped: run() left no leaked background task.
    assert transport.closed is True


@pytest.mark.asyncio
async def test_run_does_not_spawn_evict_task_with_no_buffer() -> None:
    """With NO buffer injected, ``run`` takes the buffer-None branch: no evict task.

    The run() lifecycle is unchanged for a buffer-less gateway — exercised by driving a
    full handshake-then-shutdown with ``replay_buffer=None`` (the merged-G3 default).
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    blocked = asyncio.Event()
    transport = _ScriptedCoreTransport([_start_only(epoch), blocked])
    dial = _DialRecorder([lambda: transport])
    link, _recorder = _run_link(dial=dial, shutdown_event=shutdown)  # replay_buffer=None
    assert link._replay_buffer is None

    task = asyncio.ensure_future(link.run())
    for _ in range(50):
        await asyncio.sleep(0)
        if transport.sent:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert transport.closed is True


@pytest.mark.asyncio
async def test_refresh_buffer_metrics_tracks_append_trim_and_reset() -> None:
    """The gauges follow the live buffer: append moves them, trim moves them back,
    a reconnect reset zeroes them.
    """
    _reset_buffer_gauges()
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    await link.relay_to_core(b"abc")  # append seq 0 (3 bytes)
    assert BUFFER_DEPTH_FRAMES._value.get() == 1
    assert BUFFER_DEPTH_BYTES._value.get() == 3

    # A daemon ack trims seq 0 -> the gauges fall back to empty.
    body = json.dumps({"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": 0}}).encode()
    await link._route_unit(_payload_unit(body))
    assert BUFFER_DEPTH_FRAMES._value.get() == 0
    assert BUFFER_DEPTH_BYTES._value.get() == 0

    # Re-load, then a reconnect handshake resets the buffer -> the gauges zero again.
    await link.relay_to_core(b"defgh")  # append seq 1 (5 bytes)
    assert BUFFER_DEPTH_FRAMES._value.get() == 1
    assert BUFFER_DEPTH_BYTES._value.get() == 5
    handshake = _FakeCoreTransport(
        [_start_frame(epoch=uuid4().hex, seq_ack={"version": SEQ_VERSION})]
    )
    with structlog.testing.capture_logs():
        await link._peer_handshake(handshake)
    assert BUFFER_DEPTH_FRAMES._value.get() == 0
    assert BUFFER_DEPTH_BYTES._value.get() == 0


@pytest.mark.asyncio
async def test_refresh_buffer_metrics_sets_breaker_gauge_on_trip() -> None:
    """The ``CIRCUIT_BREAKER_OPEN`` gauge flips to 1 once the soft cap breaks."""
    _reset_buffer_gauges()
    buf = ReplayBuffer(max_frames=2, max_bytes=1024)
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    transport = _FakeCoreTransport([])
    link._current_core_transport = transport

    with structlog.testing.capture_logs():
        for _ in range(3):  # third append breaches the 2-frame soft cap
            await link.relay_to_core(b"x")

    assert buf.breaker_tripped is True
    assert CIRCUIT_BREAKER_OPEN._value.get() == 1
    assert BUFFER_CAP_RATIO._value.get() == 3 / 2


def test_refresh_buffer_metrics_is_a_noop_with_no_buffer() -> None:
    """``_refresh_buffer_metrics`` on a buffer-less link is a no-op (the None branch)."""
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    assert link._replay_buffer is None
    link._refresh_buffer_metrics()  # must not crash


# ---------------------------------------------------------------------------
# Task 4 (Spec A G4b-2b / ADR-0032): ``_flush_pending_replay`` re-sends the captured
# un-acked remainder on the freshly-bound leg, in FIFO order with fresh per-connection
# seqs (the core G0-dedups on the in-payload inbound_id), then SETS the replay-pending
# gate so the held client->core pump resumes. Security-reviewed shape (R1): a leg that
# vanishes mid-flush (a None transport — reconnect race) RE-STASHES the un-sent
# remainder and leaves the gate CLEARED (no accept-drop — that would be hard-rule-#7
# silent cross-restart loss + a lying ``buffer_replayed`` audit). A complete/empty flush
# (or even a stray ``relay_to_core`` raise — the S5 DoS fail-safe) sets the gate.
# ---------------------------------------------------------------------------


async def _capture_replay(link: GatewayCoreLink, payloads: list[bytes]) -> None:
    """Relay ``payloads`` on a throwaway leg, then handshake a fresh leg to CAPTURE them.

    Drives the REAL relay + capture path (Task 2): each ``relay_to_core`` appends to the
    buffer keyed on its wire seq, then the fresh ``_peer_handshake`` stashes the un-acked
    remainder into ``_pending_replay`` (clearing the gate) and resets the buffer floor —
    leaving the link in the exact pre-flush state ``run`` reaches after a reconnect binds.
    """
    leg1 = _FakeCoreTransport([])
    link._current_core_transport = leg1
    for payload in payloads:
        await link.relay_to_core(payload)
    handshake = _FakeCoreTransport(
        [_start_frame(epoch=uuid4().hex, seq_ack={"version": SEQ_VERSION})]
    )
    with structlog.testing.capture_logs():
        await link._peer_handshake(handshake)


@pytest.mark.asyncio
async def test_flush_pending_replay_resends_fifo_fresh_seqs_and_releases_gate() -> None:
    """A reconnect flush re-sends the captured frames FIFO with fresh seqs 0,1,2.

    Capture 3 frames, bind a fresh leg, flush: the leg receives the 3 payloads with
    seqs ``0,1,2`` in FIFO order; the buffer re-holds them (append-before-send), one
    ``buffer_replayed`` row per seq, the stash is cleared, and the gate is SET.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    await _capture_replay(link, [b"a", b"b", b"c"])
    assert link.replay_pending_gate.is_set() is False  # capture cleared it

    fresh = _FakeCoreTransport([])
    link._current_core_transport = fresh
    with structlog.testing.capture_logs() as captured:
        await link._flush_pending_replay()

    # FIFO payloads, fresh per-connection seqs 0,1,2 (the captured original seqs were
    # also 0,1,2, but the FLUSH mints its own via relay_to_core on the new leg).
    assert fresh.sent_units == [(b"a", 0, 0), (b"b", 1, 0), (b"c", 2, 0)]
    # append-before-send re-buffered all 3 on the fresh leg (un-acked).
    assert buf.depth_frames == 3
    replayed = [c for c in captured if c.get("event") == "gateway.comms.buffer_replayed"]
    assert [c.get("seq") for c in replayed] == [0, 1, 2]
    assert link._pending_replay == ()
    assert link.replay_pending_gate.is_set() is True


@pytest.mark.asyncio
async def test_flush_pending_replay_empty_stash_is_noop_gate_stays_set() -> None:
    """An empty stash (the initial-connect case) sends nothing and leaves the gate SET."""
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    fresh = _FakeCoreTransport([])
    link._current_core_transport = fresh
    assert link._pending_replay == ()
    assert link.replay_pending_gate.is_set() is True

    with structlog.testing.capture_logs() as captured:
        await link._flush_pending_replay()

    assert fresh.sent_units == []
    assert [c for c in captured if c.get("event") == "gateway.comms.buffer_replayed"] == []
    assert link.replay_pending_gate.is_set() is True


@pytest.mark.asyncio
async def test_flush_pending_replay_none_transport_defers_no_loss() -> None:
    """R1: a None transport before the first send RE-STASHES all frames, gate stays CLEAR.

    Zero sends, ``_pending_replay`` holds all 3 (re-stashed), one ``buffer_replay_deferred``
    row (``deferred=3``), no ``buffer_replayed`` row, and the gate is CLEARED — the next
    bind's flush retries. Mutation guard: removing the None-check loses the frames.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    await _capture_replay(link, [b"a", b"b", b"c"])
    captured_frames = link._pending_replay  # snapshot the captured remainder

    link._current_core_transport = None
    with structlog.testing.capture_logs() as captured:
        await link._flush_pending_replay()

    assert link._pending_replay == captured_frames  # all 3 re-stashed, none lost
    deferred = [c for c in captured if c.get("event") == "gateway.comms.buffer_replay_deferred"]
    assert len(deferred) == 1
    assert deferred[0].get("deferred") == 3
    assert [c for c in captured if c.get("event") == "gateway.comms.buffer_replayed"] == []
    assert link.replay_pending_gate.is_set() is False  # stays clear -> next bind retries


@pytest.mark.asyncio
async def test_flush_pending_replay_partial_defer_on_mid_flush_loss() -> None:
    """R1 partial: the leg vanishes after the 1st send -> 1 replayed, 2 deferred.

    A leg whose ``send_payload_unit`` nulls ``_current_core_transport`` after the first
    call: one ``buffer_replayed``, then a defer with the remaining 2 re-stashed, a
    ``buffer_replay_deferred`` (``deferred=2``), and the gate CLEARED.
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    await _capture_replay(link, [b"a", b"b", b"c"])

    class _LegThatVanishesAfterFirstSend(_FakeCoreTransport):
        async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
            await super().send_payload_unit(payload, seq=seq, ack=ack)
            link._current_core_transport = None

    fresh = _LegThatVanishesAfterFirstSend([])
    link._current_core_transport = fresh
    with structlog.testing.capture_logs() as captured:
        await link._flush_pending_replay()

    assert fresh.sent_units == [(b"a", 0, 0)]  # only the first frame went out
    replayed = [c for c in captured if c.get("event") == "gateway.comms.buffer_replayed"]
    assert len(replayed) == 1
    deferred = [c for c in captured if c.get("event") == "gateway.comms.buffer_replay_deferred"]
    assert len(deferred) == 1
    assert deferred[0].get("deferred") == 2
    assert [f.payload for f in link._pending_replay] == [b"b", b"c"]
    assert link.replay_pending_gate.is_set() is False


@pytest.mark.asyncio
async def test_flush_pending_replay_relay_raise_still_sets_gate() -> None:
    """S5 fail-safe: a ``relay_to_core`` that RAISES mid-flush still SETS the gate.

    Production ``relay_to_core`` never raises (it loud-drops), but a stray raise must not
    wedge the client->core pump: the ``finally`` sets the gate on a complete-or-empty
    stash even as the exception propagates. (Here the stash IS emptied at entry, so the
    finally's ``not self._pending_replay`` is True -> gate set.)
    """
    buf = ReplayBuffer()
    link, _recorder, _sink = _link_with_relay_and_buffer(buffer=buf)
    await _capture_replay(link, [b"a"])
    fresh = _FakeCoreTransport([])
    link._current_core_transport = fresh

    async def _boom(_payload: bytes) -> None:
        raise RuntimeError("relay blew up")

    link.relay_to_core = _boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="relay blew up"):
        await link._flush_pending_replay()

    assert link.replay_pending_gate.is_set() is True  # no wedge


@pytest.mark.asyncio
async def test_run_reconnect_flushes_replay_before_pump_resumes() -> None:
    """run() through a reconnect: the captured frames replay on the NEW leg, gate ends SET.

    The first leg handshakes, the test relays one client->core frame (buffered), then the
    first leg EOFs -> reconnect. The second leg's handshake CAPTURES the un-acked frame and
    the reconnect-arm ``_flush_pending_replay`` re-sends it on the new leg BEFORE the pump
    resumes. Assert the second leg received the replayed payload and the gate ends SET.
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()
    sink = _RelaySink()
    buf = ReplayBuffer()

    # First leg: handshake, then a read that BLOCKS until we release it (so we can relay a
    # client->core frame onto the live first leg before it EOFs).
    first_eof = asyncio.Event()
    first = _ScriptedCoreTransport([_start_only(epoch1), first_eof])
    blocked = asyncio.Event()
    second = _ScriptedCoreTransport([_start_only(epoch2), blocked])
    dial = _DialRecorder([lambda: first, lambda: second])

    async def _sleep(delay: float) -> None:
        # The buffer-injected ``run`` spawns the TTL-evict loop, whose 30s sweep cadence
        # shares this ``_sleep`` seam with the reconnect backoff. PARK the evict sweep (so
        # it does not busy-spin and starve the loop) while keeping the (sub-second)
        # reconnect backoff instant — yielding once so the reconnect still progresses.
        if delay >= _BUFFER_EVICT_INTERVAL_SECONDS:
            await asyncio.Event().wait()
        await asyncio.sleep(0)

    link, _recorder = _run_link(
        dial=dial,
        shutdown_event=shutdown,
        payload_relay=sink,
        replay_buffer=buf,
        sleep=_sleep,
    )

    task = asyncio.ensure_future(link.run())
    # Wait for the first handshake to complete (pump live on leg 1).
    for _ in range(50):
        await asyncio.sleep(0)
        if first.sent:
            break
    # Relay one client->core frame onto the live first leg -> buffered un-acked seq 0.
    await link.relay_to_core(b"buffered")
    assert buf.depth_frames == 1
    # Release the first leg's read -> EOF -> reconnect to leg 2 (capture + flush).
    first_eof.set()
    for _ in range(50):
        await asyncio.sleep(0)
        if second.sent_units:  # the flush replayed onto leg 2
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # The buffered frame was replayed on the NEW leg (fresh seq 0).
    assert [payload for payload, _seq, _ack in second.sent_units] == [b"buffered"]
    assert link.replay_pending_gate.is_set() is True
    assert link._pending_replay == ()
