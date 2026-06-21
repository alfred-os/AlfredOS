"""Unit tests for ``GatewayRelay`` — the two-direction opaque relay (Spec A G3-3b-2).

The relay binds two pumps:

* **core->client** IS :meth:`GatewayCoreLink.run` (the merged supervised pump), whose
  ``payload_relay`` sink the relay wires to :meth:`GatewayRelay._send_to_client` — so a
  payload the core leg forwards is written to the client transport.
* **client->core** is the relay's own :meth:`GatewayRelay._client_to_core_pump`: it
  reads the client transport's raw units and calls :meth:`GatewayCoreLink.submit_tui_unit`
  (the leg-routed send — G6-4a), doing ZERO body parse on that leg (pure opaque forward;
  security H3).

The PRIMARY suite is the PRODUCTION shape: the core leg is seq/ack-ENABLED, the client
(TUI) leg is PLAIN. A SECONDARY suite drives seq-enabled-BOTH (forward-looking, G4/G5),
proving RESEQ — the client-leg seq the gateway mints is a fresh per-client counter, not
the core-leg seq passed through.

These tests use the same in-memory fake transports as ``test_core_link.py`` (the
``_CommsTransportLike`` shape) so the relay's wiring is exercised without a real socket;
the real-loopback wire-contract proof lives in ``test_relay_wire_contract.py``.
"""

from __future__ import annotations

import asyncio
import collections
import json
from collections.abc import Mapping
from uuid import uuid4

import pytest
import structlog.testing

from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    LinkReconnectingNotification,
    LinkRestoredNotification,
)
from alfred.gateway.client_listener import LinkControlNotification
from alfred.gateway.core_link import _BUFFER_EVICT_INTERVAL_SECONDS, GatewayCoreLink
from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_gate import PerAdapterIngressGate
from alfred.gateway.leg_router import LegRouter
from alfred.gateway.leg_scheduler import GatewayLegScheduler
from alfred.gateway.relay import GatewayRelay
from alfred.gateway.replay_buffer import ReplayBuffer
from alfred.plugins.comms_seq_codec import SeqFrame
from alfred.plugins.comms_wire import CommsProtocolError


class _RecordingClientListener:
    """A fake ``GatewayClientListener`` recording every ``send_control`` call."""

    def __init__(self) -> None:
        self.controls: list[LinkControlNotification] = []

    async def send_control(self, notification: LinkControlNotification) -> None:
        self.controls.append(notification)


class _FakeTransport:
    """In-memory ``_CommsTransportLike`` — a queue of inbound units + recorded sends.

    Drives BOTH legs in these tests: as a CORE transport it pops ``read_frame`` frames
    (the handshake) and ``read_payload_unit`` units (the pump), recording writebacks via
    ``sent`` / ``sent_units``; as a CLIENT transport it pops ``read_payload_unit`` units
    (what the TUI sends up) and records ``send_payload_unit`` calls (what the relay
    writes down to the client). ``send_unit_error`` lets a single ``send_payload_unit``
    raise (the reconnect-race drop tests).
    """

    def __init__(
        self,
        *,
        frames: list[Mapping[str, object]] | None = None,
        units: list[object] | None = None,
        seq_ack_enabled: bool = False,
    ) -> None:
        self._frames: collections.deque[Mapping[str, object]] = collections.deque(frames or [])
        self._units: collections.deque[object] = collections.deque(units or [])
        self.sent: list[dict[str, object]] = []
        # Spec A G4b-2-pre (#237): records (payload, seq, ack) — caller-owned seq.
        self.sent_units: list[tuple[bytes, int, int]] = []
        self.seq_ack_enabled = seq_ack_enabled
        self.closed = False
        self.send_unit_error: BaseException | None = None

    async def spawn(self) -> None:  # pragma: no cover - unused on these legs
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(dict(frame))

    async def read_frame(self) -> Mapping[str, object] | None:
        return self._frames.popleft() if self._frames else None

    async def read_payload_unit(self) -> SeqFrame | None:
        if not self._units:
            return None
        entry = self._units.popleft()
        if entry is None:
            # An explicit clean EOF entry in the script (a core leg that drops).
            return None
        if isinstance(entry, tuple):
            # A ``(gate, frame)`` pair: AWAIT the gate event, THEN return the frame —
            # lets a test order a client read AFTER a core-leg condition holds (no race).
            gate, frame = entry
            await gate.wait()
            return frame
        if isinstance(entry, asyncio.Event):
            await entry.wait()
            return None
        if isinstance(entry, BaseException):
            # A scripted READ FAULT: a torn/malformed client frame the pump must isolate
            # (the FIX-D client-leg fault-isolation tests).
            raise entry
        assert isinstance(entry, SeqFrame)
        return entry

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        if self.send_unit_error is not None:
            raise self.send_unit_error
        self.sent_units.append((payload, seq, ack))

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        self.seq_ack_enabled = True


def _start_frame(epoch: str, *, seq_ack: bool) -> dict[str, object]:
    params: dict[str, object] = {"adapter_id": "gateway", "epoch": epoch}
    if seq_ack:
        params["seq_ack"] = {"version": "1"}
    return {"jsonrpc": "2.0", "id": 0, "method": "lifecycle.start", "params": params}


def _unit(body: bytes, *, seq: int | None = None) -> SeqFrame:
    return SeqFrame(seq=seq, ack=0, payload=body)


def _make_tui_leg() -> GatewayLeg:
    """A non-binding TUI leg for the relay tests (G6-4a, #288).

    The relay's client->core pump routes through ``submit_tui_unit`` -> ``record_for_send``
    -> ``write_leg_unit``, so a real core-link needs a leg wired. Non-binding ingress gate +
    a GlobalReplayCap ceiling strictly above the buffer hard ceiling (PR2) — behavior-preserving.
    """
    buf = ReplayBuffer()
    gate = PerAdapterIngressGate(
        "tui",
        sustained_rate_per_s=1e9,
        burst=10**9,
        max_inflight=10**9,
        ttl_seconds=1e9,
        max_frame_bytes=1 << 30,
        now=lambda: 0.0,
    )
    return GatewayLeg(
        adapter_id="tui",
        buffer=buf,
        ingress_gate=gate,
        global_cap=GlobalReplayCap(max_total_bytes=buf.max_bytes * 4),
        now=lambda: 0.0,
    )


def _build_relay(
    *,
    core: _FakeTransport,
    client: _FakeTransport,
    client_seq_enabled: bool,
    shutdown: asyncio.Event,
) -> tuple[GatewayRelay, GatewayCoreLink, _RecordingClientListener]:
    """Wire a real ``GatewayCoreLink`` (seq-on core) + a ``GatewayRelay`` over fakes."""
    recorder = _RecordingClientListener()

    async def _dial() -> _FakeTransport:
        return core

    async def _instant_sleep(delay: float) -> None:
        # G6-4a (#288): the leg-wired core-link now spawns the TTL-evict sweep (the leg owns
        # a buffer). PARK the (30s) evict-interval sweep so it does not busy-spin under the
        # instant-sleep seam; the sub-second reconnect backoff stays instant. Mirrors
        # ``test_core_link``'s run-driving ``_sleep``.
        if delay >= _BUFFER_EVICT_INTERVAL_SECONDS:
            await asyncio.Event().wait()
        return

    tui_leg = _make_tui_leg()
    core_link = GatewayCoreLink(
        client_listener=recorder,  # type: ignore[arg-type]
        dial=_dial,  # type: ignore[arg-type]
        sleep=_instant_sleep,
        jitter=lambda hi: hi,
        shutdown_event=shutdown,
        tui_leg=tui_leg,
    )
    # Spec B G6-4 Task 7 (#288): wire the leg scheduler + router so ``submit_tui_unit``
    # ENQUEUES; the relay co-runs the scheduler drain pump under its TaskGroup, so the
    # client->core forward still reaches the core leg (now via the single drain writer).
    scheduler = GatewayLegScheduler(core_link, max_per_leg_queue_bytes=1 << 30)
    scheduler.register_leg(tui_leg)
    core_link.set_leg_router(LegRouter(scheduler))
    relay = GatewayRelay(
        core_link=core_link,
        client_transport=client,  # type: ignore[arg-type]
        client_seq_enabled=client_seq_enabled,
        scheduler=scheduler,
    )
    return relay, core_link, recorder


async def _drive_until(predicate: object, *, task: asyncio.Task[None]) -> None:
    """Step the loop until ``predicate()`` is true (bounded), then return."""
    assert callable(predicate)
    for _ in range(100):
        await asyncio.sleep(0)
        if predicate():
            return
        if task.done():
            return


# ---------------------------------------------------------------------------
# PRIMARY suite — production shape: core seq-ENABLED, client seq-DISABLED.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_payload_relay_sink_is_wired_to_send_to_client() -> None:
    """Constructing the relay binds ``core_link.payload_relay`` to its client sink."""
    core = _FakeTransport()
    client = _FakeTransport()
    shutdown = asyncio.Event()
    relay, core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )
    assert core_link._payload_relay == relay._send_to_client


@pytest.mark.asyncio
async def test_core_to_client_forwards_payload_byte_for_byte_plain_client() -> None:
    """A payload unit on the seq-on core leg is forwarded to the PLAIN client leg
    byte-for-byte, with ``ack=0`` (the plain client transport ignores ack).

    The inner JSON-RPC ``id`` survives unchanged in the relayed bytes.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    body = b'{"jsonrpc":"2.0","id":42,"method":"inbound.message","params":{}}'
    blocked = asyncio.Event()
    core = _FakeTransport(
        frames=[_start_frame(epoch, seq_ack=True)],
        units=[_unit(body, seq=0), blocked],
    )
    client = _FakeTransport(units=[asyncio.Event()])  # client never sends
    relay, _core_link, recorder = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    await _drive_until(lambda: bool(client.sent_units), task=task)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert client.sent_units == [(body, 0, 0)]  # (payload, minted seq, ack)
    # The JSON-RPC id is intact in the relayed bytes (byte-for-byte, same id run).
    assert b'"id":42' in client.sent_units[0][0]
    assert recorder.controls == []


@pytest.mark.asyncio
async def test_client_to_core_forwards_with_core_cumulative_ack() -> None:
    """A client->core unit carries ``ack = core_link._core_tracker.cumulative_ack()`` —
    the gateway's REAL contiguous ack of what the CORE sent it.

    Drive a core-leg seq run (0,1) so cumulative_ack is 1, then a client unit must be
    forwarded to the core with ack=1.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    client_body = b'{"jsonrpc":"2.0","id":7,"method":"chat.send","params":{}}'
    blocked_core = asyncio.Event()
    core = _FakeTransport(
        frames=[_start_frame(epoch, seq_ack=True)],
        units=[_unit(b'{"id":1}', seq=0), _unit(b'{"id":2}', seq=1), blocked_core],
    )
    # Gate the client send behind ``client_gate`` so it is forwarded only AFTER the core
    # leg has observed seqs 0,1 (cumulative ack 1) — deterministic, no read race.
    client_gate = asyncio.Event()
    client = _FakeTransport(units=[(client_gate, _unit(client_body)), asyncio.Event()])
    relay, core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    # Wait until the core tracker has the contiguous 0,1 run, THEN release the client.
    await _drive_until(lambda: core_link._core_tracker.cumulative_ack() == 1, task=task)
    client_gate.set()
    await _drive_until(lambda: bool(core.sent_units), task=task)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # The client body reached the core carrying the minted seq 0 + cumulative ack 1.
    assert core.sent_units == [(client_body, 0, 1)]
    assert core_link._core_tracker.cumulative_ack() == 1


@pytest.mark.asyncio
async def test_client_to_core_pump_does_zero_body_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    """The client->core leg NEVER ``json.loads`` the body (pure opaque forward; H3).

    Spy on ``json.loads`` in the relay module: a client unit forwarded to the core must
    not have triggered a parse on the relay's leg.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    import alfred.gateway.relay as relay_mod

    calls: list[object] = []
    real_loads = json.loads

    def _spy(*args: object, **kwargs: object) -> object:
        calls.append(args[0] if args else None)
        return real_loads(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(relay_mod.json, "loads", _spy)

    client_body = b'{"jsonrpc":"2.0","id":3,"method":"chat.send","params":{}}'
    blocked_core = asyncio.Event()
    core = _FakeTransport(frames=[_start_frame(epoch, seq_ack=True)], units=[blocked_core])
    client = _FakeTransport(units=[_unit(client_body), asyncio.Event()])
    relay, _core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    await _drive_until(lambda: bool(core.sent_units), task=task)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # The core leg observed no seqs, so the cumulative ack is its initial -1, FLOORED to
    # the wire's a=0 placeholder by ``relay_to_core`` (a -1 ack would crash the codec).
    # (payload, minted seq 0, floored ack 0).
    assert core.sent_units == [(client_body, 0, 0)]
    # The relay module never parsed the client body (pure opaque forward; H3).
    assert client_body not in calls


@pytest.mark.asyncio
async def test_client_eof_ends_client_pump_then_shutdown_ends_relay() -> None:
    """Client EOF (``read_payload_unit`` -> None) returns the client pump; the relay
    then waits on the core pump until shutdown ends it.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    blocked_core = asyncio.Event()
    core = _FakeTransport(frames=[_start_frame(epoch, seq_ack=True)], units=[blocked_core])
    client = _FakeTransport(units=[])  # immediate EOF
    relay, _core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    # The client pump returns on EOF; the relay stays up on the core pump until shutdown.
    for _ in range(20):
        await asyncio.sleep(0)
    assert not task.done()  # core pump still running
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)
    assert core.closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        CommsProtocolError("malformed client frame"),
        BrokenPipeError(),
        ConnectionResetError(),
        asyncio.IncompleteReadError(b"", 1),
        EOFError(),
        ValueError("seq must be non-negative: -1"),
    ],
    ids=["protocol_error", "broken_pipe", "conn_reset", "incomplete_read", "eof", "value_error"],
)
async def test_client_read_fault_isolated_from_core_pump(error: BaseException) -> None:
    """A malformed/torn client frame (``CommsProtocolError`` / a transport tear) or a
    negative client seq (``ValueError`` from ``observe``) is ISOLATED to the client leg:
    the client pump loud-logs ``gateway.relay.client_read_failed`` and RETURNS, the relay
    then rides the core pump to a clean shutdown — NO unhandled ``ExceptionGroup`` crash.

    Without the ``try/except`` in ``_client_to_core_pump`` the raise would abort the whole
    ``asyncio.TaskGroup`` (tearing down the core pump too) as an un-triaged crash, and
    ``relay.run()`` would raise an ``ExceptionGroup`` — this test would FAIL.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    blocked_core = asyncio.Event()
    core = _FakeTransport(frames=[_start_frame(epoch, seq_ack=True)], units=[blocked_core])
    # The client read raises the fault on its FIRST read. A negative-seq ValueError needs a
    # seq-enabled client (so ``observe`` runs); the others fire from ``read_payload_unit``.
    client_seq_enabled = isinstance(error, ValueError)
    if client_seq_enabled:
        # A unit carrying a negative seq -> ``observe`` raises ValueError inside the pump.
        client = _FakeTransport(
            units=[SeqFrame(seq=-1, ack=0, payload=b"{}")], seq_ack_enabled=True
        )
    else:
        client = _FakeTransport(units=[error])
    relay, _core_link, _recorder = _build_relay(
        core=core, client=client, client_seq_enabled=client_seq_enabled, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    with structlog.testing.capture_logs() as captured:
        await _drive_until(
            lambda: any(c.get("event") == "gateway.relay.client_read_failed" for c in captured),
            task=task,
        )
        shutdown.set()
        # No ExceptionGroup: ``run()`` returns cleanly despite the client-leg fault.
        await asyncio.wait_for(task, timeout=1.0)

    failed = [c for c in captured if c.get("event") == "gateway.relay.client_read_failed"]
    assert len(failed) == 1
    assert failed[0].get("log_level") == "warning"
    # The client fault never reached the core (nothing forwarded) and the core pump shut
    # down cleanly — the fault was isolated, not propagated.
    assert core.sent_units == []
    assert core.closed is True


@pytest.mark.asyncio
async def test_send_to_client_drops_loud_on_broken_pipe() -> None:
    """A ``BrokenPipeError`` writing to the client is a LOUD drop — the core pump is
    NOT crashed by a dead client (``gateway.relay.client_send_dropped``).
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    body = b'{"id":1}'
    blocked = asyncio.Event()
    core = _FakeTransport(
        frames=[_start_frame(epoch, seq_ack=True)], units=[_unit(body, seq=0), blocked]
    )
    client = _FakeTransport(units=[asyncio.Event()])
    client.send_unit_error = BrokenPipeError()
    relay, _core_link, _recorder = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    with structlog.testing.capture_logs() as captured:
        await _drive_until(
            lambda: any(c.get("event") == "gateway.relay.client_send_dropped" for c in captured),
            task=task,
        )
        shutdown.set()
        await asyncio.wait_for(task, timeout=1.0)

    dropped = [c for c in captured if c.get("event") == "gateway.relay.client_send_dropped"]
    assert len(dropped) == 1
    assert dropped[0].get("log_level") == "warning"
    # The dead client did not crash the relay — it shut down cleanly.
    assert core.closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("unable to perform operation on closed transport"),
        ValueError("send seq exceeds the encodable decimal width"),
        CommsProtocolError("reframed unit exceeds the bound"),
    ],
    ids=["closed_transport_runtime_error", "encode_value_error", "over_bound_reframe"],
)
async def test_send_to_client_drops_loud_on_widened_send_fault(error: Exception) -> None:
    """A write to the client transport ``close()``d mid-reconnect-swap (``RuntimeError``),
    an ``encode_seq_frame`` exhaustion (``ValueError``), or an over-bound reframe
    (``CommsProtocolError``) is a LOUD drop — never a raw TaskGroup crash into the core
    pump (``gateway.relay.client_send_dropped``).
    """
    shutdown = asyncio.Event()
    client = _FakeTransport()
    client.send_unit_error = error
    relay, _core_link, _recorder = _build_relay(
        core=_FakeTransport(), client=client, client_seq_enabled=False, shutdown=shutdown
    )

    with structlog.testing.capture_logs() as captured:
        await relay._send_to_client(b'{"id":1}')  # must NOT raise

    dropped = [c for c in captured if c.get("event") == "gateway.relay.client_send_dropped"]
    assert len(dropped) == 1
    assert dropped[0].get("log_level") == "warning"


@pytest.mark.asyncio
async def test_client_to_core_on_gapped_core_drops_loud_ack_stalls() -> None:
    """A client->core unit while the core leg is GAPPED is a LOUD drop (no buffering),
    and the core tracker's cumulative_ack STALLS at the gap.

    Force the gap by making the core ``send_payload_unit`` raise (the reconnect-race
    write window analogue): ``relay_to_core`` drops loud, and because we never advance
    the core tracker the ack stays where it was.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    client_body = b'{"id":9}'
    blocked_core = asyncio.Event()
    # Core sends seq=0 only (cumulative ack 0), then blocks. A subsequent client send
    # to the core raises -> loud drop.
    core = _FakeTransport(
        frames=[_start_frame(epoch, seq_ack=True)], units=[_unit(b'{"id":1}', seq=0), blocked_core]
    )
    core.send_unit_error = ConnectionResetError()
    client = _FakeTransport(units=[_unit(client_body), asyncio.Event()])
    relay, core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    with structlog.testing.capture_logs() as captured:
        await _drive_until(
            lambda: any(c.get("event") == "gateway.relay.core_send_dropped" for c in captured),
            task=task,
        )
        shutdown.set()
        await asyncio.wait_for(task, timeout=1.0)

    dropped = [c for c in captured if c.get("event") == "gateway.relay.core_send_dropped"]
    assert len(dropped) == 1
    # Dropped, NOT buffered — the core never recorded the client unit.
    assert core.sent_units == []
    # The receive tracker's cumulative ack stalled at the last contiguous seq (0).
    assert core_link._core_tracker.cumulative_ack() == 0


@pytest.mark.asyncio
async def test_relayed_frame_does_not_bump_dropped_payload_counter() -> None:
    """A relayed core->client frame does NOT increment ``_dropped_payload_frames`` — the
    counter still means 'a frame neither consumed nor relayed', so its meaning is stable.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    body = b'{"id":1,"result":{}}'
    blocked = asyncio.Event()
    core = _FakeTransport(
        frames=[_start_frame(epoch, seq_ack=True)], units=[_unit(body, seq=0), blocked]
    )
    client = _FakeTransport(units=[asyncio.Event()])
    relay, core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    await _drive_until(lambda: bool(client.sent_units), task=task)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert client.sent_units == [(body, 0, 0)]  # (payload, minted seq, ack)
    assert core_link._dropped_payload_frames == 0


@pytest.mark.asyncio
async def test_core_going_down_consumed_emits_reconnecting_not_relayed() -> None:
    """A ``going_down`` unit on the core leg is CONSUMED (emits reconnecting), never
    relayed to the client — the relay rides the core-link's lifecycle consume.
    """
    epoch1 = uuid4().hex
    epoch2 = uuid4().hex
    shutdown = asyncio.Event()
    going_down = _unit(
        json.dumps(
            {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
        ).encode(),
        seq=0,
    )
    core1 = _FakeTransport(frames=[_start_frame(epoch1, seq_ack=True)], units=[going_down, None])
    blocked = asyncio.Event()
    core2 = _FakeTransport(frames=[_start_frame(epoch2, seq_ack=True)], units=[blocked])
    client = _FakeTransport(units=[asyncio.Event()])
    recorder = _RecordingClientListener()

    cores = collections.deque([core1, core2])

    async def _dial() -> _FakeTransport:
        return cores.popleft()

    async def _instant_sleep(delay: float) -> None:
        # G6-4a (#288): the leg-wired core-link now spawns the TTL-evict sweep (the leg owns
        # a buffer). PARK the (30s) evict-interval sweep so it does not busy-spin under the
        # instant-sleep seam; the sub-second reconnect backoff stays instant. Mirrors
        # ``test_core_link``'s run-driving ``_sleep``.
        if delay >= _BUFFER_EVICT_INTERVAL_SECONDS:
            await asyncio.Event().wait()
        return

    core_link = GatewayCoreLink(
        client_listener=recorder,  # type: ignore[arg-type]
        dial=_dial,  # type: ignore[arg-type]
        sleep=_instant_sleep,
        jitter=lambda hi: hi,
        shutdown_event=shutdown,
        tui_leg=_make_tui_leg(),
    )
    relay = GatewayRelay(
        core_link=core_link,
        client_transport=client,
        client_seq_enabled=False,  # type: ignore[arg-type]
    )

    task = asyncio.ensure_future(relay.run())
    await _drive_until(lambda: bool(core2.sent), task=task)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert client.sent_units == []  # the going_down was consumed, not relayed
    assert [type(c) for c in recorder.controls] == [
        LinkReconnectingNotification,
        LinkRestoredNotification,
    ]


# ---------------------------------------------------------------------------
# SECONDARY suite — forward-looking: seq-enabled on BOTH legs (G4/G5).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seq_enabled_client_resequences_not_pass_through() -> None:
    """With a seq-ENABLED client leg, the client-leg ``ack`` the relay sends is the
    gateway's OWN client-receive cumulative ack — NOT the core-leg seq passed through.

    Feed the client leg a seq run (0,1) so the client tracker's cumulative ack is 1;
    a core->client payload then carries ack=1 (the resequenced client ack), proving the
    relay maintains a SEPARATE client tracker (RESEQ), not a pass-through of core acks.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    core_body = b'{"id":1,"result":{}}'
    blocked_core = asyncio.Event()
    blocked_client = asyncio.Event()
    core = _FakeTransport(
        frames=[_start_frame(epoch, seq_ack=True)],
        units=[_unit(core_body, seq=5), blocked_core],
    )
    # The client SENDS two units (seq 0,1) BEFORE the core payload is relayed down, so
    # the client tracker's cumulative ack is 1 when the relay writes to the client.
    client = _FakeTransport(
        units=[_unit(b'{"id":100}', seq=0), _unit(b'{"id":101}', seq=1), blocked_client],
        seq_ack_enabled=True,
    )
    relay, _core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=True, shutdown=shutdown
    )

    task = asyncio.ensure_future(relay.run())
    await _drive_until(lambda: bool(client.sent_units), task=task)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert len(client.sent_units) == 1
    relayed_payload, relayed_seq, relayed_ack = client.sent_units[0]
    assert relayed_payload == core_body
    assert relayed_seq == 0  # the relay mints its own core->client seq (first = 0)
    # RESEQ: the client-leg ack is the gateway's client-receive ack (1), NOT the
    # core-leg seq the payload arrived with (5).
    assert relayed_ack == 1
    assert relayed_ack != 5


# ---------------------------------------------------------------------------
# Spec A G4b-2-pre (#237) / ADR-0032: the relay OWNS its core->client send-seq.
# ``_send_to_client`` mints a contiguous per-relay seq and passes it explicitly (the
# post-G4b-2-pre ``send_payload_unit`` signature requires one). On the plain production
# TUI leg the transport ignores the seq, but the call must still carry it.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_to_client_passes_an_explicit_minted_seq() -> None:
    """``_send_to_client`` mints its own core->client seq and passes it explicitly.

    On the production plain-client leg the seq is ignored by the transport, but the
    call must still pass one (the post-G4b-2-pre signature requires it).
    """
    core = _FakeTransport()
    client = _FakeTransport(seq_ack_enabled=True)
    shutdown = asyncio.Event()
    relay, _core_link, _recorder = _build_relay(
        core=core, client=client, client_seq_enabled=True, shutdown=shutdown
    )

    await relay._send_to_client(b"x")
    await relay._send_to_client(b"y")

    assert [(p, s) for (p, s, _a) in client.sent_units] == [(b"x", 0), (b"y", 1)]


@pytest.mark.asyncio
async def test_seq_enabled_client_tracker_independent_of_core_seq() -> None:
    """The client tracker (used for the client-leg ack) is wholly separate from the
    core tracker — they advance on DIFFERENT streams.
    """
    core = _FakeTransport()
    client = _FakeTransport(seq_ack_enabled=True)
    shutdown = asyncio.Event()
    relay, core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=True, shutdown=shutdown
    )
    # Advance ONLY the client tracker; the core tracker must be untouched.
    relay._client_tracker.observe(0)
    relay._client_tracker.observe(1)
    assert relay._client_tracker.cumulative_ack() == 1
    assert core_link._core_tracker.cumulative_ack() == -1


# ---------------------------------------------------------------------------
# Spec A G4b-2a (#237 / R4): client read-halt back-pressure. When the core-link's
# ReplayBuffer breaker latches, ``_client_to_core_pump`` STOPS draining the client
# socket (OS socket-buffer back-pressure to the TUI; loss-free) and PARKS on the
# core-link's ``wait_for_shutdown`` until the relay TaskGroup cancels the parked pump.
# ---------------------------------------------------------------------------


class _HaltStubCoreLink:
    """A minimal ``GatewayCoreLink`` stand-in exposing only the two halt seams.

    ``replay_buffer_tripped`` is the controllable latch the pump polls;
    ``wait_for_shutdown`` parks on a test-controlled event so a test can release the
    halt deterministically. ``submit_tui_unit`` records forwards (asserted untouched while
    tripped). ``_payload_relay`` is the sink slot the relay binds at construction.
    """

    def __init__(self, *, tripped: bool, replay_pending: bool = False) -> None:
        self.replay_buffer_tripped = tripped
        self._release = asyncio.Event()
        self.forwarded: list[bytes] = []
        self._payload_relay: object | None = None
        # Spec A G4b-2b (#237): the replay-pending gate the pump awaits before reading a
        # fresh client frame. SET == no replay pending (the normal case, pump proceeds);
        # CLEARED == a captured reconnect-replay is waiting to flush (pump holds). Default
        # SET so the existing read-halt tests (which never touch it) stay byte-for-byte.
        self._replay_pending_gate = asyncio.Event()
        if not replay_pending:
            self._replay_pending_gate.set()

    @property
    def replay_pending_gate(self) -> asyncio.Event:
        return self._replay_pending_gate

    async def wait_for_shutdown(self) -> None:
        await self._release.wait()

    def release(self) -> None:
        self._release.set()

    async def submit_tui_unit(self, payload: bytes) -> None:
        self.forwarded.append(payload)


def _read_spy_transport(*, units: list[object] | None = None) -> _FakeTransport:
    """A client ``_FakeTransport`` that counts ``read_payload_unit`` invocations."""
    transport = _FakeTransport(units=units)
    transport.read_calls = 0  # type: ignore[attr-defined]
    original = transport.read_payload_unit

    async def _counting_read() -> SeqFrame | None:
        transport.read_calls += 1  # type: ignore[attr-defined]
        return await original()

    transport.read_payload_unit = _counting_read  # type: ignore[method-assign]
    return transport


@pytest.mark.asyncio
async def test_client_to_core_pump_halts_while_buffer_tripped() -> None:
    """While the breaker is tripped the pump PARKS — it NEVER reads the client socket.

    Run ``_client_to_core_pump`` against a stub core-link whose
    ``replay_buffer_tripped`` is ``True``: the pump must park on ``wait_for_shutdown``
    and never await ``read_payload_unit`` (read spy stays at 0). Releasing the park (the
    wired-shutdown analogue) returns the pump cleanly.
    """
    core_link = _HaltStubCoreLink(tripped=True)
    client = _read_spy_transport(units=[_unit(b"never-read")])
    relay = GatewayRelay(
        core_link=core_link,  # type: ignore[arg-type]
        client_transport=client,
        client_seq_enabled=False,
    )

    task = asyncio.ensure_future(relay._client_to_core_pump())
    # Let the pump reach the park; the read is never attempted while tripped.
    for _ in range(20):
        await asyncio.sleep(0)
    assert not task.done()  # parked, not returned
    assert client.read_calls == 0  # type: ignore[attr-defined]
    assert core_link.forwarded == []

    # Release the park (a wired shutdown firing): the pump returns cleanly.
    core_link.release()
    await asyncio.wait_for(task, timeout=1.0)
    assert client.read_calls == 0  # type: ignore[attr-defined]  # still never read


@pytest.mark.asyncio
async def test_client_to_core_pump_halt_park_is_cancellable() -> None:
    """Cancelling the PARKED pump (no shutdown fired) propagates ``CancelledError`` cleanly.

    The TaskGroup cancels the parked client pump on the core pump's shutdown return; the
    park must surface that cancel (the halt is OUTSIDE the read ``try`` so it is never
    swallowed by the read's except family).
    """
    core_link = _HaltStubCoreLink(tripped=True)  # never released
    client = _read_spy_transport(units=[_unit(b"never-read")])
    relay = GatewayRelay(
        core_link=core_link,  # type: ignore[arg-type]
        client_transport=client,
        client_seq_enabled=False,
    )

    task = asyncio.ensure_future(relay._client_to_core_pump())
    for _ in range(20):
        await asyncio.sleep(0)
    assert not task.done()  # parked
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert client.read_calls == 0  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_client_to_core_pump_reads_when_not_tripped() -> None:
    """When the breaker is NOT tripped the pump reads + forwards exactly as before.

    A real ``GatewayCoreLink`` with NO buffer (``replay_buffer_tripped`` always
    ``False``) forwards the client unit to the core leg — the no-halt path is unchanged.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    client_body = b'{"id":7,"method":"chat.send","params":{}}'
    blocked_core = asyncio.Event()
    core = _FakeTransport(frames=[_start_frame(epoch, seq_ack=True)], units=[blocked_core])
    client = _FakeTransport(units=[_unit(client_body), asyncio.Event()])
    relay, core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )
    assert core_link.replay_buffer_tripped is False

    task = asyncio.ensure_future(relay.run())
    await _drive_until(lambda: bool(core.sent_units), task=task)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    # The client body reached the core (the not-tripped path read + forwarded it).
    assert core.sent_units == [(client_body, 0, 0)]


# ---------------------------------------------------------------------------
# Spec A G4b-2b (#237): reconnect-replay pending-gate hold. After the breaker
# back-pressure halt and BEFORE the read, ``_client_to_core_pump`` awaits the
# core-link's ``replay_pending_gate`` — so replayed frames (re-sent by run()'s
# flush, taking seqs 0..N-1) precede fresh client input in seq order (spec §4).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_to_core_pump_holds_while_replay_pending_gate_cleared() -> None:
    """While a reconnect-replay is pending (gate CLEARED) the pump HOLDS — no fresh read.

    With ``replay_buffer_tripped`` False but ``replay_pending_gate`` CLEARED, the pump must
    park on the gate and NEVER await ``read_payload_unit`` (read spy stays at 0). SETTING
    the gate (run()'s flush completing) releases the hold: the pump then reads + forwards.
    """
    core_link = _HaltStubCoreLink(tripped=False, replay_pending=True)
    client = _read_spy_transport(units=[_unit(b"held-then-read"), asyncio.Event()])
    relay = GatewayRelay(
        core_link=core_link,  # type: ignore[arg-type]
        client_transport=client,
        client_seq_enabled=False,
    )

    task = asyncio.ensure_future(relay._client_to_core_pump())
    # Let the pump reach the gate hold; the read is never attempted while the gate is clear.
    for _ in range(20):
        await asyncio.sleep(0)
    assert not task.done()  # held on the gate, not returned
    assert client.read_calls == 0  # type: ignore[attr-defined]
    assert core_link.forwarded == []

    # SET the gate (replay flush done): the pump resumes, reads the unit, and forwards it.
    core_link.replay_pending_gate.set()
    await _drive_until(lambda: bool(core_link.forwarded), task=task)
    assert client.read_calls >= 1  # type: ignore[attr-defined]
    assert core_link.forwarded == [b"held-then-read"]

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_client_to_core_pump_replay_gate_hold_is_cancellable() -> None:
    """Cancelling the pump while it HOLDS on the replay gate propagates ``CancelledError``.

    The gate ``wait()`` is OUTSIDE the read ``try`` (a shutdown cancel must not be swallowed
    by the read's except family), so cancelling the held pump surfaces the cancel cleanly.
    """
    core_link = _HaltStubCoreLink(tripped=False, replay_pending=True)  # gate never set
    client = _read_spy_transport(units=[_unit(b"never-read")])
    relay = GatewayRelay(
        core_link=core_link,  # type: ignore[arg-type]
        client_transport=client,
        client_seq_enabled=False,
    )

    task = asyncio.ensure_future(relay._client_to_core_pump())
    for _ in range(20):
        await asyncio.sleep(0)
    assert not task.done()  # held on the gate
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert client.read_calls == 0  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_client_to_core_pump_passes_through_when_replay_gate_set() -> None:
    """The normal case (gate SET) reads + forwards with zero hold overhead.

    A real ``GatewayCoreLink`` on a fresh link has its ``replay_pending_gate`` SET, so the
    pump never holds — the existing read/forward path is unchanged.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    client_body = b'{"id":9,"method":"chat.send","params":{}}'
    blocked_core = asyncio.Event()
    core = _FakeTransport(frames=[_start_frame(epoch, seq_ack=True)], units=[blocked_core])
    client = _FakeTransport(units=[_unit(client_body), asyncio.Event()])
    relay, core_link, _ = _build_relay(
        core=core, client=client, client_seq_enabled=False, shutdown=shutdown
    )
    assert core_link.replay_pending_gate.is_set() is True

    task = asyncio.ensure_future(relay.run())
    await _drive_until(lambda: bool(core.sent_units), task=task)
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert core.sent_units == [(client_body, 0, 0)]


@pytest.mark.asyncio
async def test_client_to_core_pump_tripped_breaker_halts_before_gate_wait() -> None:
    """The breaker halt is checked BEFORE the gate wait: a tripped breaker still parks.

    With BOTH ``replay_buffer_tripped`` True AND ``replay_pending_gate`` SET, the pump must
    still take the breaker back-pressure park (``wait_for_shutdown``), not the gate path —
    the ordering guarantees a latched breaker wins even when no replay is pending.
    """
    core_link = _HaltStubCoreLink(tripped=True, replay_pending=False)  # gate SET, breaker on
    client = _read_spy_transport(units=[_unit(b"never-read")])
    relay = GatewayRelay(
        core_link=core_link,  # type: ignore[arg-type]
        client_transport=client,
        client_seq_enabled=False,
    )

    task = asyncio.ensure_future(relay._client_to_core_pump())
    for _ in range(20):
        await asyncio.sleep(0)
    assert not task.done()  # parked on the breaker halt, not reading
    assert client.read_calls == 0  # type: ignore[attr-defined]

    # Releasing the breaker park (a wired shutdown) returns the pump — proving it parked on
    # ``wait_for_shutdown`` (the breaker path), not the already-SET gate.
    core_link.release()
    await asyncio.wait_for(task, timeout=1.0)
    assert client.read_calls == 0  # type: ignore[attr-defined]
