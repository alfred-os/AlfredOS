"""Unit tests for the ``GatewayLegScheduler`` fair egress scheduler (Spec B G6-4, K3).

K3: fair round-robin-by-frame drain of N legs (+ the TUI leg) onto the SINGLE physical
``core_link`` writer, so a chatty / large-payload leg cannot starve another adapter or
the live TUI. A bounded per-leg send queue (in BYTES, perf-M3) back-pressures only that
leg; a faulting leg's pump is isolated (perf-M4 — discard its buffer + release its budget,
others survive); the TUI leg gets a reserved minimum credit so its latency has a floor.
"""

from __future__ import annotations

import asyncio

import pytest

from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_gate import PerAdapterIngressGate
from alfred.gateway.leg_scheduler import GatewayLegScheduler, LegQueueFullError
from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError

pytestmark = pytest.mark.asyncio


class _FakeClock:
    def __init__(self) -> None:
        self._now = 0.0

    def __call__(self) -> float:
        return self._now


class _RecordingCoreLink:
    """A fake core_link that records (adapter_id, payload) writes in order.

    Exposes a controllable ``replay_pending_gate`` (Spec B G6-4 Task 7 / Option A): the
    scheduler's drain pump awaits it before each round, so a CLEARED gate (a reconnect
    replay in flight) parks the scheduler while the direct flush re-sends the captured
    remainder. The gate starts SET (no replay pending) so every existing test drains as
    before; a test that exercises the gate calls :meth:`clear_gate` / :meth:`set_gate`.
    """

    def __init__(self) -> None:
        self.writes: list[tuple[str, bytes, int, int]] = []
        self._ack = 0
        self._gate = asyncio.Event()
        self._gate.set()

    def core_cumulative_ack(self) -> int:
        return self._ack

    def replay_pending_gate(self) -> asyncio.Event:
        return self._gate

    def clear_gate(self) -> None:
        self._gate.clear()

    def set_gate(self) -> None:
        self._gate.set()

    async def write_leg_unit(self, adapter_id: str, payload: bytes, *, seq: int, ack: int) -> None:
        self.writes.append((adapter_id, payload, seq, ack))


class _RaisingLeg(GatewayLeg):
    """A leg whose record_for_send raises once, to exercise per-leg isolation."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.torn_down = False

    def record_for_send(self, payload: bytes) -> int:
        raise ReplayBufferError("boom")

    def teardown(self) -> None:
        self.torn_down = True
        super().teardown()


def _make_leg(
    adapter_id: str, cap: GlobalReplayCap, *, cls: type[GatewayLeg] = GatewayLeg
) -> GatewayLeg:
    clock = _FakeClock()
    return cls(
        adapter_id=adapter_id,
        buffer=ReplayBuffer(max_frames=1000, max_bytes=1_000_000, ttl_seconds=30.0),
        ingress_gate=PerAdapterIngressGate(
            adapter_id,
            sustained_rate_per_s=1000.0,
            burst=1000,
            max_inflight=1000,
            ttl_seconds=30.0,
            max_frame_bytes=1_000_000,
            now=clock,
        ),
        global_cap=cap,
        now=clock,
    )


async def _drain_until(pred, *, ticks: int = 500) -> bool:
    for _ in range(ticks):
        if pred():
            return True
        await asyncio.sleep(0)
    return pred()


# --------------------------------------------------------------------------- #
# Registration + bounded queue                                                #
# --------------------------------------------------------------------------- #


async def test_non_positive_queue_bytes_raises() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=0)


async def test_enqueue_requires_registered_leg() -> None:
    sched = GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=100)
    with pytest.raises(KeyError):
        sched.enqueue("not-registered", b"x")


async def test_deregister_absent_leg_is_noop() -> None:
    sched = GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=100)
    sched.deregister_leg("never-registered")  # no raise
    assert sched.registered_adapters == frozenset()


async def test_adapter_ids_and_leg_accessors() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    sched = GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=100)
    leg = _make_leg("a", cap)
    sched.register_leg(leg)
    assert tuple(sched.adapter_ids()) == ("a",)
    assert sched.leg("a") is leg


async def test_pump_parks_when_idle_then_wakes_on_enqueue() -> None:
    # Exercises the idle-park + lost-wakeup re-check branch: the pump parks with empty
    # queues, then a late enqueue wakes it and the frame drains.
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    sched.register_leg(_make_leg("a", cap))
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        await asyncio.sleep(0)  # let the pump reach the idle park
        sched.enqueue("a", b"late")
        await _drain_until(lambda: len(core.writes) == 1)
        pump.cancel()
    assert core.writes[0][0] == "a"


async def test_full_per_leg_queue_back_pressures_only_that_leg() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=4)
    sched.register_leg(_make_leg("a", cap))
    sched.register_leg(_make_leg("b", cap))
    # 'a' fills its 4-byte queue; the next enqueue raises LegQueueFullError.
    assert sched.enqueue("a", b"aaaa") is None
    with pytest.raises(LegQueueFullError):
        sched.enqueue("a", b"x")
    # 'b' is unaffected — its queue is independent.
    assert sched.enqueue("b", b"bbbb") is None


# --------------------------------------------------------------------------- #
# Fair round-robin drain order (K3 — exact order, not set/count)               #
# --------------------------------------------------------------------------- #


async def test_two_saturated_legs_interleave_fairly() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    sched.register_leg(_make_leg("a", cap))
    sched.register_leg(_make_leg("b", cap))
    # Pre-load BOTH queues fully BEFORE the pump runs (deterministic saturation).
    for i in range(3):
        sched.enqueue("a", f"a{i}".encode())
        sched.enqueue("b", f"b{i}".encode())
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        await _drain_until(lambda: len(core.writes) == 6)
        pump.cancel()
    order = [adapter for adapter, *_ in core.writes]
    # RR-by-frame: neither leg is drained ahead of the other.
    assert order == ["a", "b", "a", "b", "a", "b"]


async def test_tui_leg_not_starved_by_a_saturated_adapter() -> None:
    # K3: the TUI frame position is <= 1 behind a saturated adapter (reserved credit).
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    sched.register_leg(_make_leg("discord", cap))
    sched.register_leg(_make_leg("tui", cap))
    # Saturate discord, then a single late TUI frame.
    for i in range(10):
        sched.enqueue("discord", f"d{i}".encode())
    sched.enqueue("tui", b"hello")
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        await _drain_until(lambda: any(a == "tui" for a, *_ in core.writes))
        pump.cancel()
    order = [a for a, *_ in core.writes]
    assert "tui" in order
    assert order.index("tui") <= 1  # at most one adapter frame ahead of the TUI frame


# --------------------------------------------------------------------------- #
# Per-leg isolation (perf-M4)                                                  #
# --------------------------------------------------------------------------- #


async def test_faulting_leg_is_isolated_and_torn_down_others_survive() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    faulter = _make_leg("bad", cap, cls=_RaisingLeg)
    good = _make_leg("good", cap)
    sched.register_leg(faulter)
    sched.register_leg(good)
    sched.enqueue("bad", b"boom")
    sched.enqueue("good", b"ok")
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        await _drain_until(lambda: any(a == "good" for a, *_ in core.writes))
        pump.cancel()
    # The good leg's frame was written; the faulter was torn down + deregistered.
    assert ("good", b"ok", 0, 0) in core.writes
    assert isinstance(faulter, _RaisingLeg) and faulter.torn_down is True
    assert "bad" not in sched.registered_adapters
    assert "good" in sched.registered_adapters


# --------------------------------------------------------------------------- #
# record_for_send is what the drain calls (seq mint + buffer append)           #
# --------------------------------------------------------------------------- #


async def test_drain_records_via_leg_and_writes_with_seq_and_ack() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    core._ack = 7
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    leg = _make_leg("a", cap)
    sched.register_leg(leg)
    sched.enqueue("a", b"first")
    sched.enqueue("a", b"second")
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        await _drain_until(lambda: len(core.writes) == 2)
        pump.cancel()
    # Seqs are minted by the leg at drain time, monotone; ack is the core's cumulative ack.
    assert core.writes[0] == ("a", b"first", 0, 7)
    assert core.writes[1] == ("a", b"second", 1, 7)
    # The frames were appended to the leg's buffer (durable for replay).
    assert leg.depth_frames == 2


# --------------------------------------------------------------------------- #
# Replay-pending gate (Spec B G6-4 Task 7 / Option A — resume-oracle preserving) #
# --------------------------------------------------------------------------- #


async def test_pump_parks_while_replay_gate_is_clear_then_drains_when_set() -> None:
    # The reconnect-replay window: while the gate is CLEAR the scheduler must NOT drain
    # (record_for_send not called, nothing written) — the direct flush owns the writer; once
    # the flush SETS the gate the queued fresh frame drains behind the replay.
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    core.clear_gate()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    leg = _make_leg("a", cap)
    sched.register_leg(leg)
    sched.enqueue("a", b"fresh")
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        # Spin several ticks: the gate is clear, so NOTHING may drain (no seq minted).
        for _ in range(20):
            await asyncio.sleep(0)
        assert core.writes == []
        assert leg.depth_frames == 0  # record_for_send never ran while parked
        # The flush sets the gate -> the scheduler resumes and drains the fresh frame.
        core.set_gate()
        assert await _drain_until(lambda: len(core.writes) == 1)
        pump.cancel()
    assert core.writes[0] == ("a", b"fresh", 0, 0)


async def test_replay_precedes_fresh_input_across_the_gate() -> None:
    # The resume-ordering oracle in miniature: while the gate is CLEAR a direct flush writes
    # the replayed frames (seqs 0,1 minted on the leg), THEN sets the gate; the pre-queued
    # fresh frame drains AFTER, taking the next fresh seq (2). Physical write order [0,1,2].
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    core.clear_gate()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    leg = _make_leg("a", cap)
    sched.register_leg(leg)
    sched.enqueue("a", b"post")  # a fresh frame queued during the gap
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        for _ in range(10):
            await asyncio.sleep(0)
        assert core.writes == []  # parked: the fresh frame is held behind the replay
        # The direct flush re-sends the captured remainder (seqs 0,1) — the sanctioned
        # reconnect-internal writer, exactly as core_link._flush_pending_replay does.
        for payload in (b"replay-0", b"replay-1"):
            seq = leg.record_for_send(payload)
            await core.write_leg_unit("a", payload, seq=seq, ack=core.core_cumulative_ack())
        core.set_gate()
        assert await _drain_until(lambda: len(core.writes) == 3)
        pump.cancel()
    assert [seq for _a, _p, seq, _ack in core.writes] == [0, 1, 2]
    assert [p for _a, p, _s, _ack in core.writes] == [b"replay-0", b"replay-1", b"post"]


# --------------------------------------------------------------------------- #
# Deregister + teardown                                                        #
# --------------------------------------------------------------------------- #


async def test_deregister_tears_down_the_leg() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    sched = GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=100)
    leg = _make_leg("a", cap)
    sched.register_leg(leg)
    leg_a = sched.enqueue("a", b"x")  # noqa: F841 — enqueue side effect only
    sched.deregister_leg("a")
    assert "a" not in sched.registered_adapters
    assert cap.leg_bytes("a") == 0  # teardown released the budget


async def test_register_duplicate_leg_is_loud() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    sched = GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=100)
    sched.register_leg(_make_leg("a", cap))
    with pytest.raises(ValueError, match="already registered"):
        sched.register_leg(_make_leg("a", cap))


async def test_aclose_tears_down_all_legs() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    sched = GatewayLegScheduler(_RecordingCoreLink(), max_per_leg_queue_bytes=100)
    sched.register_leg(_make_leg("a", cap))
    sched.register_leg(_make_leg("b", cap))
    sched.enqueue("a", b"x")
    sched.enqueue("b", b"y")
    sched.aclose()
    assert sched.registered_adapters == frozenset()
    assert cap.total_bytes == 0
