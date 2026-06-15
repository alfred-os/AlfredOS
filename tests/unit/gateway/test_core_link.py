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
import time
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
from alfred.gateway.metrics import (
    CORE_LINK_UP,
    CORE_UNAVAILABLE_SECONDS,
    RECONNECT_ATTEMPTS,
)
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


# ---------------------------------------------------------------------------
# Task 6 — run(): supervised dial / handshake / pump / reconnect lifecycle
# ---------------------------------------------------------------------------


class _ScriptedCoreTransport:
    """A fake ``_CommsTransportLike`` whose ``read_frame`` follows a queued script.

    Each script entry is one of:
      * a ``Mapping`` — a frame ``read_frame`` returns,
      * ``None`` — a clean EOF (``read_frame`` returns ``None``),
      * a :class:`BaseException` INSTANCE — a transport-crash ``read_frame`` raises,
      * an :class:`asyncio.Event` — ``read_frame`` AWAITS the event, then (once set)
        returns ``None`` (a genuinely-pending read used to drive the shutdown race).

    ``sent`` records writebacks (the handshake ack), ``closed`` flips on ``close()``.
    """

    def __init__(self, script: list[object]) -> None:
        self._script: collections.deque[object] = collections.deque(script)
        self.sent: list[dict[str, object]] = []
        self.seq_ack_enabled = False
        self.closed = False

    async def spawn(self) -> None:  # pragma: no cover - unused on the peer leg
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(dict(frame))

    async def read_frame(self) -> Mapping[str, object] | None:
        if not self._script:
            return None
        entry = self._script.popleft()
        if isinstance(entry, asyncio.Event):
            await entry.wait()
            return None
        if isinstance(entry, BaseException):
            raise entry
        if entry is None:
            return None
        assert isinstance(entry, Mapping)
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
