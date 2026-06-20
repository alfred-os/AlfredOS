"""Adversarial: the resume-gateway reconnect-replay must not lose, leak, or reorder.

**Threat model** (Spec A G4b-2b / ADR-0032, #237 — §6 reconnect-replay). The
always-up ``alfred-gateway`` holds the operator's client (TUI) connection across a
core restart and buffers the un-acked client->core inbound in its
:class:`~alfred.gateway.replay_buffer.ReplayBuffer` until the (freshly-restarted)
core durably acks it. On a core BOUNCE the gateway must RE-SEND that un-acked
remainder on the new leg so nothing the operator typed is lost (spec §5). That
replay is the highest-value moment in the gateway's lifecycle and therefore its
biggest attack surface. The §6 guarantees this corpus pins — each is a defense
whose removal a test below must catch:

* A core restart must NOT lose typed input. The captured un-acked frames are
  re-sent on the fresh leg, re-buffered un-acked, then drained by the new core's
  ack (``test_reconnect_replays_unacked_frames_round_trip``).
* The replay must NOT let fresh input jump ahead of replayed input. A fresh client
  frame arriving DURING the replay window is held behind the replay-pending gate so
  every replayed seq is lower than any post-reconnect fresh seq — FIFO across the
  restart (``test_replay_precedes_fresh_input_fifo_barrier``).
* The replay must NOT be triggerable by a forged ``ready``. A stale/forged-epoch
  ``ready`` is epoch-rejected before any flush — ``_flush_pending_replay`` is never
  called and the captured stash is untouched
  (``test_forged_ready_does_not_trigger_flush``).
* The replay must NOT leak / decode a pre-DLP body. The carrier ``json.loads`` NO
  replayed body across a full round-trip — hard rule #5, release-blocking
  (``test_replay_is_payload_blind``).
* The replay must NOT silently drop on a flush race. A leg that vanishes mid-flush
  (None transport) writes ZERO ``buffer_replayed`` rows, ONE loud
  ``buffer_replay_deferred``, re-stashes the remainder, and leaves the gate CLEARED
  (``test_none_transport_defer_is_loud_not_silent``).
* The replay must NOT pin pre-DLP refs after it completes. A complete flush leaves
  ``_pending_replay`` empty — no lingering plaintext copy in the always-up process
  (``test_complete_flush_leaves_no_lingering_stash``).
* A new core's early ack landing mid-flush must NOT corrupt the ascending replay
  (``test_trim_mid_flush_is_benign``).

Standalone adversarial module (a wire-protocol resume-integrity property, not a
corpus content payload). In-process and NON-ROOT — it drives the real
``GatewayCoreLink`` reconnect/flush + the relay's ``_client_to_core_pump`` directly,
so it runs on the standard release-blocking adversarial gate (a root-gated launcher
test that proved the same wire contract would be a paper gate — the #245 lesson).
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import structlog.testing

from alfred.comms_mcp.protocol import DAEMON_COMMS_ACK, DAEMON_LIFECYCLE_READY
from alfred.gateway.client_listener import LinkControlNotification
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_gate import PerAdapterIngressGate
from alfred.gateway.metrics import CIRCUIT_BREAKER_OPEN, CORE_LINK_UP
from alfred.gateway.relay import GatewayRelay
from alfred.gateway.replay_buffer import ReplayBuffer
from alfred.plugins.comms_seq_codec import SeqFrame

# Reuse the established production-shape fakes (do NOT reinvent — the #237 wire-shape
# fakes the merged relay + flood tests drive): the in-memory client/core transport,
# the lifecycle.start frame builder, and the SeqFrame unit helper.
from tests.unit.gateway.test_relay import _FakeTransport, _start_frame, _unit

pytestmark = pytest.mark.asyncio

# Small N so the round-trip is fast and the seq assertions are exact: the client
# floods N distinct un-acked frames that buffer, gap, then replay on the fresh leg.
_N = 3


class _RecordingClientListener:
    """Records every ``send_control`` so a test can assert the client-leg controls."""

    def __init__(self) -> None:
        self.controls: list[LinkControlNotification] = []

    async def send_control(self, notification: LinkControlNotification) -> None:
        self.controls.append(notification)


class _RecordingCoreTransport:
    """A live core leg that ACCEPTS ``send_payload_unit`` but NEVER acks (no reads).

    Mirrors the wedged-flood test's transport: ``send_payload_unit`` records
    ``(payload, seq, ack)`` and returns — the leg is "UP" to the gateway — so
    ``relay_to_core`` succeeds and the un-acked buffer fills. No ``daemon.comms.ack``
    is ever fed back, so the held frames stay un-acked until the test drives the
    reconnect + flush itself.
    """

    def __init__(self) -> None:
        self.sent_units: list[tuple[bytes, int, int]] = []

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        self.sent_units.append((payload, seq, ack))


def _reset_gauges() -> None:
    """Reset the process-global breaker/up gauges (singletons leak across tests)."""
    CIRCUIT_BREAKER_OPEN.set(0)
    CORE_LINK_UP.set(0)


def _link_with_buffer(buf: ReplayBuffer) -> tuple[GatewayCoreLink, _RecordingClientListener]:
    """A real ``GatewayCoreLink`` wired with ``buf`` + a relay payload sink (relay-ON).

    Binds a no-op ``_payload_relay`` so the relay-ON ``_route_unit`` path (the one that
    consumes ``daemon.comms.ack`` and drives ``trim_to_ack``) is active — exactly the
    shape ``submit_tui_unit`` + the reconnect flush run in. G6-4a (#288): the TUI is the
    FIRST GatewayLeg wrapping ``buf`` (non-binding gate + a cap ceiling strictly above the
    buffer hard ceiling, PR2).
    """
    recorder = _RecordingClientListener()
    gate = PerAdapterIngressGate(
        "tui",
        sustained_rate_per_s=1e9,
        burst=10**9,
        max_inflight=10**9,
        ttl_seconds=1e9,
        max_frame_bytes=1 << 30,
        now=lambda: 0.0,
    )
    leg = GatewayLeg(
        adapter_id="tui",
        buffer=buf,
        ingress_gate=gate,
        global_cap=GlobalReplayCap(max_total_bytes=buf._max_bytes * 4),
        now=lambda: 0.0,
    )
    link = GatewayCoreLink(
        client_listener=recorder,  # type: ignore[arg-type]
        tui_leg=leg,
    )

    async def _sink(_payload: bytes) -> None:
        return None

    link._payload_relay = _sink
    return link, recorder


async def _bounce_to_fresh_leg(link: GatewayCoreLink, fresh_core: _RecordingCoreTransport) -> None:
    """Drive the core BOUNCE: a fresh leg handshakes (capture), then bind it + flush.

    Reproduces, in-process, exactly what ``run`` does on a reconnect: the fresh leg's
    ``_peer_handshake`` CAPTURES the un-acked remainder into ``_pending_replay`` and
    clears the gate; ``run`` then rebinds ``_current_core_transport`` to the new leg and
    calls ``_flush_pending_replay`` BEFORE the pump resumes.
    """
    handshake = _FakeTransport(frames=[_start_frame(uuid4().hex, seq_ack=True)])
    await link._peer_handshake(handshake)  # type: ignore[arg-type]
    link._current_core_transport = fresh_core  # type: ignore[assignment]
    await link._flush_pending_replay()


# ---------------------------------------------------------------------------
# 1) Round-trip resume — the core guarantee (spec §5).
# ---------------------------------------------------------------------------


async def test_reconnect_replays_unacked_frames_round_trip() -> None:
    """The N un-acked frames are re-sent on the fresh leg (seqs 0..N-1, FIFO), re-held
    un-acked, then drained by the new core's ack.

    Mutation note: commenting out ``_flush_pending_replay``'s send loop (the
    ``await self.relay_to_core(frame.payload)`` line) loses the frames — the fresh leg
    receives nothing and the buffer stays empty, so this test FAILS. Pins the flush.
    """
    _reset_gauges()
    buf = ReplayBuffer()
    link, _recorder = _link_with_buffer(buf)

    # Epoch A: relay N distinct client frames onto a live-but-never-acks leg. Each
    # ``relay_to_core`` append-before-sends, so the buffer holds them un-acked.
    leg_a = _RecordingCoreTransport()
    link._current_core_transport = leg_a  # type: ignore[assignment]
    bodies = [f'{{"inbound_id":"m{i}"}}'.encode() for i in range(_N)]
    for body in bodies:
        await link.submit_tui_unit(body)
    assert [f.seq for f in buf.unacked_frames()] == list(range(_N))  # 0..N-1 held
    assert [p for (p, _s, _a) in leg_a.sent_units] == bodies

    # Core BOUNCE: fresh leg handshakes (fresh epoch) -> capture + reset -> flush.
    leg_b = _RecordingCoreTransport()
    await _bounce_to_fresh_leg(link, leg_b)

    # The N frames were RE-SENT on the NEW leg with FRESH per-connection seqs 0..N-1
    # in FIFO order (the bodies are identical; the core G0-dedups on the in-payload
    # inbound_id, ADR-0032 §6.2). Re-appended to the buffer (un-acked on the new leg).
    assert leg_b.sent_units == [(bodies[i], i, 0) for i in range(_N)]
    assert [f.seq for f in buf.unacked_frames()] == list(range(_N))  # re-held un-acked
    assert link.replay_pending_gate.is_set() is True  # complete flush set the gate

    # The NEW core durably acks the replayed remainder -> trim_to_ack drains it.
    ack_body = json.dumps(
        {"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": _N - 1}}
    ).encode()
    await link._route_unit(SeqFrame(seq=0, ack=0, payload=ack_body))
    assert buf.depth_frames == 0  # the new core's ack drained the replayed frames
    assert buf.unacked_frames() == ()


# ---------------------------------------------------------------------------
# 2) Replay precedes fresh input — the FIFO barrier (spec §4).
# ---------------------------------------------------------------------------


async def test_replay_precedes_fresh_input_fifo_barrier() -> None:
    """A fresh client frame arriving DURING the replay window gets a seq >= N — every
    replayed seq is strictly lower than any post-reconnect fresh seq.

    Drives the REAL relay pump: capture N frames (gate CLEARED), start the pump with one
    fresh client unit ready. The pump HOLDS on the cleared gate (never forwards the fresh
    unit). The flush then re-sends the N replayed frames (seqs 0..N-1) and SETS the gate;
    only then does the pump resume and forward the fresh unit, which mints seq N. Pins the
    ``replay_pending_gate`` hold: without it the fresh unit would race ahead of the replay.
    """
    _reset_gauges()
    buf = ReplayBuffer()
    link, _recorder = _link_with_buffer(buf)

    # Epoch A: relay N frames (buffered, un-acked).
    leg_a = _RecordingCoreTransport()
    link._current_core_transport = leg_a  # type: ignore[assignment]
    replay_bodies = [f'{{"inbound_id":"r{i}"}}'.encode() for i in range(_N)]
    for body in replay_bodies:
        await link.submit_tui_unit(body)

    # Capture (clears the gate) — but DO NOT flush yet. The fresh leg is the same
    # recording transport the pump's relay_to_core will also send onto.
    leg_b = _RecordingCoreTransport()
    handshake = _FakeTransport(frames=[_start_frame(uuid4().hex, seq_ack=True)])
    await link._peer_handshake(handshake)  # type: ignore[arg-type]
    link._current_core_transport = leg_b  # type: ignore[assignment]
    assert link.replay_pending_gate.is_set() is False  # gate held: pump must wait

    fresh_body = b'{"inbound_id":"fresh"}'
    client = _FakeTransport(units=[_unit(fresh_body), asyncio.Event()])
    relay = GatewayRelay(core_link=link, client_transport=client, client_seq_enabled=False)

    # Start the client->core pump. It must PARK on the cleared gate — the fresh unit is
    # NOT forwarded while the replay is pending.
    pump = asyncio.ensure_future(relay._client_to_core_pump())
    for _ in range(20):
        await asyncio.sleep(0)
    assert not pump.done()
    assert leg_b.sent_units == []  # nothing on the new leg yet — pump held

    # Now flush the replay: re-sends seqs 0..N-1 then SETS the gate, releasing the pump.
    await link._flush_pending_replay()
    for _ in range(50):
        await asyncio.sleep(0)
        if len(leg_b.sent_units) > _N:
            break

    pump.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pump

    # SEQ-ORDER BARRIER: the replayed frames hold seqs 0..N-1; the fresh frame got seq N.
    by_seq = sorted(leg_b.sent_units, key=lambda u: u[1])
    replayed = [u for u in by_seq if u[0] in replay_bodies]
    fresh = [u for u in by_seq if u[0] == fresh_body]
    assert len(replayed) == _N
    assert len(fresh) == 1
    replayed_max_seq = max(seq for (_p, seq, _a) in replayed)
    fresh_seq = fresh[0][1]
    assert fresh_seq > replayed_max_seq  # fresh input strictly follows the replay
    assert fresh_seq == _N
    assert [seq for (_p, seq, _a) in replayed] == list(range(_N))


# ---------------------------------------------------------------------------
# 3) Forged ready -> flush NOT called (R3a). Pins the epoch gate.
# ---------------------------------------------------------------------------


async def test_forged_ready_does_not_trigger_flush() -> None:
    """A forged/stale-epoch ``ready`` fed to ``_consume_ready`` must NOT call
    ``_flush_pending_replay`` and must leave ``_pending_replay`` untouched.

    Spy ``_flush_pending_replay`` (assert call_count == 0). Mirrors
    ``test_gateway_ready_epoch_forgery.py``'s forged-ready construction: the captured
    epoch differs from the forged one, so ``_consume_ready`` rejects with NO feed. Pins
    the epoch reconcile — an attacker who could trigger a flush via a forged liveness
    signal could force a pre-DLP re-send at a moment of their choosing.
    """
    _reset_gauges()
    buf = ReplayBuffer()
    link, _recorder = _link_with_buffer(buf)

    # Seed a captured genuine epoch + a pending replay stash (as if a real reconnect had
    # just captured an un-acked remainder, awaiting the fresh leg's flush).
    captured_epoch = uuid4().hex
    forged_epoch = uuid4().hex
    assert forged_epoch != captured_epoch
    link._core_epoch = captured_epoch
    leg = _RecordingCoreTransport()
    link._current_core_transport = leg  # type: ignore[assignment]
    await link.submit_tui_unit(b'{"inbound_id":"pinned"}')
    link._pending_replay = buf.unacked_frames()
    link._replay_pending.clear()
    stash_before = link._pending_replay

    flush_spy = AsyncMock(wraps=link._flush_pending_replay)
    link._flush_pending_replay = flush_spy  # type: ignore[method-assign]

    with structlog.testing.capture_logs() as captured:
        await link._consume_frame(
            {"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": forged_epoch}}
        )

    # The forged ready triggered NO flush and the captured stash is byte-for-byte intact.
    assert flush_spy.call_count == 0
    assert link._pending_replay == stash_before
    assert link.replay_pending_gate.is_set() is False  # still held — no spurious release
    mismatch = [c for c in captured if c.get("event") == "gateway.core_link.ready_epoch_mismatch"]
    assert len(mismatch) == 1, captured
    assert mismatch[0].get("log_level") == "warning"


# ---------------------------------------------------------------------------
# 4) Payload-blind replay (R3b) — CLAUDE.md hard rule #5, release-blocking.
# ---------------------------------------------------------------------------


async def test_replay_is_payload_blind(monkeypatch: pytest.MonkeyPatch) -> None:
    """Across a full replay round-trip the carrier ``json.loads`` NO replayed body.

    Spy BOTH ``alfred.gateway.relay.json.loads`` AND
    ``alfred.gateway.core_link.json.loads`` into ONE list, then run the entire capture ->
    bounce -> flush path. The replay re-sends bytes verbatim via ``relay_to_core`` (no
    method-peek), so the carrier decodes nothing — pins the T1-carrier contract that pre
    -DLP bodies are never inspected in the always-up process. (We feed NO ``daemon.*``
    control frame through ``_route_unit`` here, so the only thing that COULD decode is a
    replayed body — and it must not.)
    """
    _reset_gauges()
    import alfred.gateway.core_link as core_link_mod
    import alfred.gateway.relay as relay_mod

    loads_calls: list[object] = []
    real_loads = json.loads

    def _spy(*args: object, **kwargs: object) -> object:
        loads_calls.append(args[0] if args else None)
        return real_loads(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(relay_mod.json, "loads", _spy)
    monkeypatch.setattr(core_link_mod.json, "loads", _spy)

    buf = ReplayBuffer()
    link, _recorder = _link_with_buffer(buf)
    leg_a = _RecordingCoreTransport()
    link._current_core_transport = leg_a  # type: ignore[assignment]
    bodies = [f'{{"inbound_id":"b{i}"}}'.encode() for i in range(_N)]
    for body in bodies:
        await link.submit_tui_unit(body)

    leg_b = _RecordingCoreTransport()
    await _bounce_to_fresh_leg(link, leg_b)

    assert leg_b.sent_units == [(bodies[i], i, 0) for i in range(_N)]  # replay happened
    assert loads_calls == []  # …and decoded NOTHING (hard rule #5)


# ---------------------------------------------------------------------------
# 5) Stash residency (R3c) — no lingering pre-DLP ref after a complete flush.
# ---------------------------------------------------------------------------


async def test_complete_flush_leaves_no_lingering_stash() -> None:
    """After a COMPLETE flush ``_pending_replay`` is empty — no pinned pre-DLP copy.

    The stash is the one place a replay holds an extra plaintext copy of pre-DLP input in
    the always-up process; a complete flush must release it (the buffer re-holds the
    frames, which the new core's ack then zeroes — but the stash itself must not linger).
    """
    _reset_gauges()
    buf = ReplayBuffer()
    link, _recorder = _link_with_buffer(buf)
    leg_a = _RecordingCoreTransport()
    link._current_core_transport = leg_a  # type: ignore[assignment]
    for i in range(_N):
        await link.submit_tui_unit(f'{{"inbound_id":"s{i}"}}'.encode())

    leg_b = _RecordingCoreTransport()
    await _bounce_to_fresh_leg(link, leg_b)

    assert link._pending_replay == ()  # no lingering pre-DLP refs pinned in-process
    assert link.replay_pending_gate.is_set() is True


# ---------------------------------------------------------------------------
# 6) None-transport defer is LOUD, not silent (R3d). Pins R1.
# ---------------------------------------------------------------------------


async def test_none_transport_defer_is_loud_not_silent() -> None:
    """A leg that vanished at flush (None transport) writes ZERO ``buffer_replayed``
    rows, ONE loud ``buffer_replay_deferred``, re-stashes the remainder, gate stays CLEAR.

    The reconnect-race: ``run`` bound the fresh leg but it dropped before the first send.
    A silent drop here would be hard-rule-#7 cross-restart input loss (the operator's
    typed input vanishes) PLUS a lying audit. Pins the None-check defer.
    """
    _reset_gauges()
    buf = ReplayBuffer()
    link, _recorder = _link_with_buffer(buf)
    leg_a = _RecordingCoreTransport()
    link._current_core_transport = leg_a  # type: ignore[assignment]
    for i in range(_N):
        await link.submit_tui_unit(f'{{"inbound_id":"d{i}"}}'.encode())

    # Capture (clears the gate), then the fresh leg vanishes BEFORE the flush sends.
    handshake = _FakeTransport(frames=[_start_frame(uuid4().hex, seq_ack=True)])
    await link._peer_handshake(handshake)  # type: ignore[arg-type]
    captured_stash = link._pending_replay
    assert len(captured_stash) == _N
    link._current_core_transport = None  # the reconnect-race window

    with structlog.testing.capture_logs() as captured:
        await link._flush_pending_replay()

    replayed = [c for c in captured if c.get("event") == "gateway.comms.buffer_replayed"]
    deferred = [c for c in captured if c.get("event") == "gateway.comms.buffer_replay_deferred"]
    assert replayed == []  # ZERO frames went out
    assert len(deferred) == 1  # exactly ONE loud defer row
    assert deferred[0].get("log_level") == "warning"
    assert deferred[0].get("deferred") == _N
    assert link._pending_replay == captured_stash  # remainder re-stashed, none lost
    assert link.replay_pending_gate.is_set() is False  # gate stays CLEAR -> next retry


# ---------------------------------------------------------------------------
# 7) trim-mid-flush is benign (R3f / R4).
# ---------------------------------------------------------------------------


async def test_trim_mid_flush_is_benign() -> None:
    """A new core's early ack arriving DURING the flush trims only ``seq <= ack`` and
    does not corrupt the ascending replay of the un-acked remainder.

    A fresh leg whose first ``send_payload_unit`` injects a ``daemon.comms.ack`` covering
    only seq 0: the buffer trims frame 0, but the flush keeps re-sending frames 1..N-1 in
    ascending order with no loss/corruption. trim_to_ack removes a leading prefix only, so
    the in-flight ascending replay survives a mid-flush trim.
    """
    _reset_gauges()
    buf = ReplayBuffer()
    link, _recorder = _link_with_buffer(buf)
    leg_a = _RecordingCoreTransport()
    link._current_core_transport = leg_a  # type: ignore[assignment]
    bodies = [f'{{"inbound_id":"t{i}"}}'.encode() for i in range(_N)]
    for body in bodies:
        await link.submit_tui_unit(body)

    handshake = _FakeTransport(frames=[_start_frame(uuid4().hex, seq_ack=True)])
    await link._peer_handshake(handshake)  # type: ignore[arg-type]

    class _LegThatAcksFrameZeroOnFirstSend(_RecordingCoreTransport):
        """On the FIRST replayed send, route a cumulative_ack=0 through the link.

        Reproduces the new core durably-acking the first replayed frame WHILE the flush is
        still iterating the remainder — the trim must not derail the ascending re-send.
        """

        def __init__(self, link: GatewayCoreLink) -> None:
            super().__init__()
            self._link = link
            self._acked = False

        async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
            await super().send_payload_unit(payload, seq=seq, ack=ack)
            if not self._acked:
                self._acked = True
                ack_body = json.dumps(
                    {"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": 0}}
                ).encode()
                await self._link._route_unit(SeqFrame(seq=0, ack=0, payload=ack_body))

    leg_b = _LegThatAcksFrameZeroOnFirstSend(link)
    link._current_core_transport = leg_b  # type: ignore[assignment]
    await link._flush_pending_replay()

    # All N frames were re-sent in ascending FIFO seq order despite the mid-flush trim.
    assert leg_b.sent_units == [(bodies[i], i, 0) for i in range(_N)]
    assert link.replay_pending_gate.is_set() is True
    # The mid-flush ack removed ONLY seq 0; the remainder (1..N-1, re-appended by the
    # flush's append-before-send) is intact and un-corrupted.
    assert [f.seq for f in buf.unacked_frames()] == list(range(1, _N))
