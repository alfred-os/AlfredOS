"""Adversarial: a WEDGED core leg cannot OOM / unbounded-pin pre-DLP input.

**Threat model** (Spec A G4b-2a / ADR-0032, #237 — §6(d) wedged-core flood). The
``alfred-gateway`` is the always-up external-I/O chokepoint: it holds the client
(TUI) connection across a core restart and buffers the operator's un-acked
client->core inbound in its :class:`~alfred.gateway.replay_buffer.ReplayBuffer`
until the (possibly freshly-restarted) core durably acks it. The attack: a core
leg that ACCEPTS the socket (``send_payload_unit`` succeeds — the leg is "UP") but
NEVER emits a ``daemon.comms.ack`` (it never durably intakes anything — a wedged,
deadlocked, or impostor core). Un-acked inbound then accumulates UNBOUNDED in the
security-critical front door: an OOM / pre-DLP-input-pinning attack on a process
that, by design, cannot drop the operator's typed input silently.

The defenses under test (deleting ANY of them must fail this module):

* **Bounded.** :meth:`ReplayBuffer.append` KEEPS the frame on a soft-cap breach
  (no silent drop) and trips the back-pressure breaker; the relay's
  :meth:`GatewayRelay._client_to_core_pump` polls
  :attr:`GatewayCoreLink.replay_buffer_tripped` at the TOP of its loop and HALTS —
  it stops draining the client socket (OS-buffer back-pressure to the TUI), so
  growth is bounded to soft-cap + the single tripping frame, well under the
  ``2x`` hard ceiling. The hard-ceiling raise is the fail-closed backstop if that
  read-halt were ever buggy.
* **Loud.** The trip feeds ``BREAKER_TRIPPED`` -> ``LinkControl.UNAVAILABLE`` ->
  exactly one ``link.unavailable`` control to the client + exactly one loud
  ``gateway.comms.breaker_tripped`` structlog row (CLAUDE.md hard rule #7 — back
  -pressure is never silent).
* **Payload-blind.** The client->core carrier NEVER ``json.loads`` a body
  (CLAUDE.md hard rule #5, now release-blocking): the gateway is a T1 carrier and
  T3 tagging stays in the core. We spy ``alfred.gateway.relay.json.loads`` (the
  established H3 spy) and assert it is never called during the flood.

A SECOND test pins the security HIGH (R1): on reconnect the held OLD-epoch frames
are CAPTURED into ``_pending_replay`` for replay on the fresh leg (G4b-2b) and the
buffer floor is reset — a FRESH-leg ack can NOT silently "confirm" (trim) input the
new core never received. The buffer only ever reflects epoch-B state; the captured
stash awaits fresh-seq replay.

Standalone adversarial module (a wire-protocol / resource-bound integrity property,
not a corpus content payload). In-process and NON-ROOT — it drives the relay's
``_client_to_core_pump`` directly so the read-halt is the bound under test, and so
it runs on the standard release-blocking adversarial gate (a root-gated launcher
test would be a paper gate — the #245 lesson).
"""

from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
import structlog.testing

from alfred.comms_mcp.protocol import (
    DAEMON_COMMS_ACK,
    LinkUnavailableNotification,
)
from alfred.gateway.client_listener import LinkControlNotification
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.metrics import CIRCUIT_BREAKER_OPEN, CORE_LINK_UP
from alfred.gateway.relay import GatewayRelay
from alfred.gateway.replay_buffer import ReplayBuffer
from alfred.plugins.comms_seq_codec import SeqFrame

# The flood harness reuses the established fake transports + relay wiring from the
# unit relay suite (do not reinvent — match the production-shape fakes the merged
# tests drive).
from tests.unit.gateway.test_relay import _FakeTransport, _start_frame, _unit

pytestmark = pytest.mark.asyncio

# Small caps so the flood is fast and the bound is exact: soft cap 4 -> the breaker
# trips on the 5th append (depth 5 > 4), the hard ceiling is 2x = 8 frames (a 9th
# append would raise). The read-halt bounds growth to soft-cap + 1 = 5.
_MAX_FRAMES = 4
_SOFT_TRIP_DEPTH = _MAX_FRAMES + 1  # 5 — first depth that latches the breaker
_HARD_CEILING = _MAX_FRAMES * 2  # 8 — the append-raise backstop
_FLOOD_SIZE = 20  # more than the hard ceiling: a naive (un-halted) drain would OOM


class _RecordingClientListener:
    """Records every ``send_control`` so the test can assert the client-leg controls."""

    def __init__(self) -> None:
        self.controls: list[LinkControlNotification] = []

    async def send_control(self, notification: LinkControlNotification) -> None:
        self.controls.append(notification)


class _WedgedCoreTransport:
    """A live core leg that ACCEPTS sends but NEVER acks — the §6(d) wedge.

    ``send_payload_unit`` records and returns (the socket accepts — the leg is "UP"
    to the gateway), but the core never durably intakes: no ``daemon.comms.ack`` is
    ever fed back, so the gateway's ``trim_to_ack`` never runs and the un-acked
    buffer grows until the soft-cap breaker latches.
    """

    def __init__(self) -> None:
        self.sent_units: list[tuple[bytes, int, int]] = []

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        self.sent_units.append((payload, seq, ack))


def _reset_gauges() -> None:
    """Reset the process-global breaker/up gauges (singletons leak across tests)."""
    CIRCUIT_BREAKER_OPEN.set(0)
    CORE_LINK_UP.set(0)


def _flood_client(read_calls: list[int]) -> _FakeTransport:
    """A client transport yielding ``_FLOOD_SIZE`` distinct units then blocking.

    Each unit carries a UNIQUE body so the buffered frames are distinguishable; the
    trailing :class:`asyncio.Event` blocks the read forever after the flood (the pump
    would park there if it did NOT halt first — so any extra reads past the halt show
    up as consumed flood units, which the bound assertion catches). ``read_calls``
    records the count of attempted reads (each pop) so the test can prove the pump
    consumed FEWER than all ``_FLOOD_SIZE`` units (the halt actually stopped the drain).
    """
    units: list[object] = [_unit(f'{{"id":{i},"flood":"x"}}'.encode()) for i in range(_FLOOD_SIZE)]
    units.append(asyncio.Event())  # blocks forever once the flood is drained
    transport = _FakeTransport(units=units)
    original = transport.read_payload_unit

    async def _counting_read() -> SeqFrame | None:
        read_calls.append(1)
        return await original()

    transport.read_payload_unit = _counting_read  # type: ignore[method-assign]
    return transport


def _wedged_relay(
    *, buf: ReplayBuffer, client: _FakeTransport, shutdown: asyncio.Event
) -> tuple[GatewayRelay, GatewayCoreLink, _RecordingClientListener, _WedgedCoreTransport]:
    """Wire a real link (with ``buf``) + relay over a wedged core that accepts-not-acks."""
    recorder = _RecordingClientListener()
    wedged = _WedgedCoreTransport()
    link = GatewayCoreLink(
        client_listener=recorder,  # type: ignore[arg-type]
        shutdown_event=shutdown,
        replay_buffer=buf,
    )
    # Simulate a live UP core leg WITHOUT running the dial/handshake pump: bind the
    # current transport directly so ``relay_to_core`` sends succeed (the wedge accepts).
    link._current_core_transport = wedged  # type: ignore[assignment]
    relay = GatewayRelay(
        core_link=link,
        client_transport=client,  # type: ignore[arg-type]
        client_seq_enabled=False,  # production shape: the TUI leg is plain.
    )
    return relay, link, recorder, wedged


async def _drive_until_halted(task: asyncio.Task[None], buf: ReplayBuffer) -> None:
    """Step the loop until the pump has tripped the breaker and parked at the halt."""
    for _ in range(200):
        await asyncio.sleep(0)
        if buf.breaker_tripped and not task.done():
            # One more turn so the loop-top halt check runs after the trip.
            await asyncio.sleep(0)
            return
        if task.done():
            return


async def test_wedged_core_flood_is_bounded_loud_and_payload_blind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The §6(d) corpus contract: bounded growth, loud + link.unavailable, payload-blind.

    Drive the relay's client->core pump against a wedged core (accepts, never acks)
    while the client floods ``_FLOOD_SIZE`` units. The buffer soft-cap breaker trips,
    the read-halt parks the pump, the client is told ``link.unavailable`` exactly once
    with a single loud audit row, growth is bounded WELL under the hard ceiling, the
    tripping frame is BUFFERED (not dropped), and the carrier never decoded a body.
    """
    _reset_gauges()
    # Spy ``json.loads`` in BOTH gateway modules on the client->core leg (the established
    # H3 zero-parse spy, widened): the flood drives ``_client_to_core_pump`` ->
    # ``relay_to_core``, so a regression that decodes the client->core body could land in
    # EITHER module — ``relay`` (where the pump lives) or ``core_link`` (where
    # ``relay_to_core`` lives). Accumulate both into ONE ``loads_calls`` list so a decode
    # in either trips the assertion; the carrier must NEVER decode a body during the flood.
    import alfred.gateway.core_link as core_link_mod
    import alfred.gateway.relay as relay_mod

    loads_calls: list[object] = []
    real_loads = json.loads

    def _spy(*args: object, **kwargs: object) -> object:
        loads_calls.append(args[0] if args else None)
        return real_loads(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(relay_mod.json, "loads", _spy)
    monkeypatch.setattr(core_link_mod.json, "loads", _spy)

    buf = ReplayBuffer(max_frames=_MAX_FRAMES)
    shutdown = asyncio.Event()
    read_calls: list[int] = []
    client = _flood_client(read_calls)
    relay, _link, recorder, wedged = _wedged_relay(buf=buf, client=client, shutdown=shutdown)

    task = asyncio.ensure_future(relay._client_to_core_pump())
    await _drive_until_halted(task, buf)
    # The pump is now PARKED on the read-halt (wait_for_shutdown). Release it cleanly.
    assert not task.done(), "pump should be parked at the read-halt, not returned"
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # 1) BOUNDED: depth never exceeded the hard ceiling, and the read-halt bounded it to
    #    soft-cap + the single tripping frame — the pump consumed FAR FEWER than all
    #    _FLOOD_SIZE units (a naive un-halted drain would have read every one).
    assert buf.depth_frames <= _HARD_CEILING
    assert buf.depth_frames == _SOFT_TRIP_DEPTH  # exactly soft-cap + 1 (the tripping frame)
    assert len(read_calls) < _FLOOD_SIZE, "read-halt must stop the drain before all flood units"
    assert len(wedged.sent_units) == _SOFT_TRIP_DEPTH  # every buffered frame WAS sent (accept)

    # 2) BREAKER LATCHED: the pure buffer latch + the exported gauge both reflect it.
    assert buf.breaker_tripped is True
    assert CIRCUIT_BREAKER_OPEN._value.get() == 1

    # 3) LOUD + link.unavailable: exactly ONE control (link.unavailable) reached the
    #    client and exactly ONE loud breaker-tripped audit row fired (rule #7).
    assert [type(c) for c in recorder.controls] == [LinkUnavailableNotification]

    # 4) PAYLOAD-BLIND (CLAUDE.md hard rule #5): the client->core carrier decoded NO body
    #    during the flood — in NEITHER the relay pump NOR ``relay_to_core``. The spy is on
    #    both gateway modules' ``json.loads`` on this leg; a regression adding a decode in
    #    either trips this. T1 carrier: T3 tagging stays in the core, never the gateway.
    assert loads_calls == []


async def test_wedged_core_flood_emits_exactly_one_loud_breaker_row() -> None:
    """The trip is LOUD exactly once (CLAUDE.md hard rule #7) and the tripping frame
    is BUFFERED, not silently dropped (append-before-send).

    A separate test so the structlog capture wraps only the flood (the spy-monkeypatch
    test above keeps its assertions tight). Same wedged-flood harness.
    """
    _reset_gauges()
    buf = ReplayBuffer(max_frames=_MAX_FRAMES)
    shutdown = asyncio.Event()
    read_calls: list[int] = []
    client = _flood_client(read_calls)
    relay, _link, recorder, _wedged = _wedged_relay(buf=buf, client=client, shutdown=shutdown)

    with structlog.testing.capture_logs() as captured:
        task = asyncio.ensure_future(relay._client_to_core_pump())
        await _drive_until_halted(task, buf)
        assert not task.done()
        shutdown.set()
        await asyncio.wait_for(task, timeout=1.0)

    # Exactly ONE loud breaker-tripped row, at warning (the once-only escalation edge).
    tripped = [c for c in captured if c.get("event") == "gateway.comms.breaker_tripped"]
    assert len(tripped) == 1, captured
    assert tripped[0].get("log_level") == "warning"

    # 4) NO SILENT DROP: the frame whose append TRIPPED the breaker is present in the
    #    buffer (append-before-send kept it — it was buffered, not dropped). The last
    #    retained seq is the highest minted seq; every buffered seq is contiguous 0..N.
    held_seqs = [f.seq for f in buf.unacked_frames()]
    assert held_seqs == list(range(_SOFT_TRIP_DEPTH))  # 0..4 — the tripping frame (seq 4) is held
    assert [type(c) for c in recorder.controls] == [LinkUnavailableNotification]


async def test_reconnect_captures_old_epoch_no_trim_by_fresh_ack() -> None:
    """Security HIGH: held OLD-epoch frames are CAPTURED for replay + the buffer is
    reset on reconnect, and a FRESH-leg ack can NOT trim/resurrect them.

    G4b-2b: on reconnect the held un-acked frames are captured into ``_pending_replay``
    (for re-send on the fresh leg with FRESH seqs — the core G0-dedups on the in-payload
    ``inbound_id``, not ``(leg, seq)``) and the buffer floor is reset, so the buffer no
    longer holds any OLD-epoch seq. A fresh-leg ``daemon.comms.ack`` whose
    ``cumulative_ack`` covers the OLD epoch's seqs therefore trims NOTHING from the (empty)
    buffer and CANNOT touch the captured stash — it cannot silently "confirm" input the
    NEW core never durably intook. (G4b-2a dropped the held frames with a loud loss row;
    G4b-2b replaces that drop with capture-and-replay so nothing typed is lost.)
    """
    _reset_gauges()
    buf = ReplayBuffer(max_frames=_MAX_FRAMES)
    shutdown = asyncio.Event()
    read_calls: list[int] = []
    client = _flood_client(read_calls)
    relay, link, _recorder, _wedged = _wedged_relay(buf=buf, client=client, shutdown=shutdown)

    # Flood + trip under epoch A: frames 0..4 held un-acked.
    task = asyncio.ensure_future(relay._client_to_core_pump())
    await _drive_until_halted(task, buf)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)
    held_a = [f.seq for f in buf.unacked_frames()]
    assert held_a == list(range(_SOFT_TRIP_DEPTH))  # epoch-A frames 0..4 are held
    assert buf.breaker_tripped is True

    # Reconnect: a FRESH core leg handshakes (epoch B). The held epoch-A frames are
    # CAPTURED into _pending_replay (not dropped), the replay-pending gate is cleared,
    # and the buffer floor is reset. NO loud loss row (that was the G4b-2a behaviour).
    epoch_b = uuid4().hex
    fresh_core = _FakeTransport(frames=[_start_frame(epoch_b, seq_ack=True)])
    with structlog.testing.capture_logs() as captured:
        await link._peer_handshake(fresh_core)  # type: ignore[arg-type]

    assert [c for c in captured if c.get("event") == "gateway.comms.buffer_reset_input_loss"] == []
    # The held epoch-A frames were captured for replay (FIFO, original seqs), gate cleared.
    assert [f.seq for f in link._pending_replay] == held_a
    assert link.replay_pending_gate.is_set() is False
    # The buffer itself is now EMPTY and the breaker is cleared — no OLD-epoch seq remains
    # IN THE BUFFER (the captured copies live in the stash, awaiting fresh-seq replay).
    assert buf.depth_frames == 0
    assert buf.breaker_tripped is False
    assert buf.unacked_frames() == ()

    # A FRESH-leg durable-intake ack whose cumulative_ack covers the OLD epoch-A seqs.
    # Route it through the relay-ON path exactly as the core would (a wedged-then-fresh
    # core finally acks). It must NOT resurrect/trim anything — the old frames are GONE
    # (reset, not trimmed), so a fresh-leg ack cannot silently "confirm" old input.
    ack_body = json.dumps(
        {"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": _SOFT_TRIP_DEPTH + 10}}
    ).encode()
    # The relay-ON router needs a payload sink bound (the relay bound it at construction).
    await link._route_unit(SeqFrame(seq=0, ack=0, payload=ack_body))

    # The fresh-leg ack confirmed NOTHING that wasn't there: the buffer stays EMPTY.
    # (trim_to_ack on an empty buffer is a no-op; the point is no resurrection of A.)
    assert buf.depth_frames == 0
    assert buf.unacked_frames() == ()
    # The ack covers OLD-epoch seqs but CANNOT touch the captured stash — the replay re-mints
    # FRESH seqs, so the new core dedups on inbound_id, never on these stale (leg, seq) values.
    assert [f.seq for f in link._pending_replay] == held_a
    # And the carrier relayed NO ack control to the client (it is consumed, not relayed).
    assert isinstance(ack_body, bytes)  # payload-blind: the ack was bytes, never an object
