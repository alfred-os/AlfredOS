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
from alfred.gateway.link_state import (
    GatewayLinkEvent,
    GatewayLinkState,
    LinkStateMachine,
)
from alfred.gateway.metrics import CORE_LINK_UP, RECONNECT_ATTEMPTS
from alfred.plugins.comms_seq_codec import SEQ_VERSION
from alfred.plugins.comms_wire import CommsPeerAuthError


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
    link, _ = _link_for_reconnect(
        dial=dial, sleep=_sleep, jitter=lambda hi: hi, machine=machine
    )

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

    monkeypatch.setattr(
        "alfred.plugins.comms_socket_transport.dial_comms_socket", _fake_dial
    )
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

    # No jitter override -> the default full-jitter draw in [0, backoff] is used. With
    # a single successful dial the backoff is INITIAL, so the slept delay is in
    # [0, 0.25] — assert the bound, not an exact value (the draw is random).
    dial = _DialRecorder([lambda: _ready_transport(epoch)])
    link = GatewayCoreLink(
        client_listener=_RecordingClientListener(),  # type: ignore[arg-type]
        machine=_gapped_machine(),
        dial=dial,  # type: ignore[arg-type]
        sleep=_sleep,
    )

    await link._reconnect()

    assert len(slept) == 1
    assert 0.0 <= slept[0] <= 0.25
