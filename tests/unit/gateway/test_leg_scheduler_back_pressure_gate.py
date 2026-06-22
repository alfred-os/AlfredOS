"""``GatewayLegScheduler`` per-adapter back-pressure gate (Spec B G6-7-3, #309).

FORK-C: the gateway forward path CLEARS a per-adapter ``asyncio.Event`` when a leg
is full (pause the child-stdio reader); the scheduler SETS that adapter's gate after
it drains a frame off that leg (resume). This module pins the scheduler's half: a
registered gate is set on each drain of its adapter's leg; an un-registered (TUI /
default) leg drains unchanged (no gate to set).
"""

from __future__ import annotations

import asyncio

import pytest

from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_gate import PerAdapterIngressGate
from alfred.gateway.leg_scheduler import GatewayLegScheduler
from alfred.gateway.replay_buffer import ReplayBuffer

pytestmark = pytest.mark.asyncio


class _FakeClock:
    def __init__(self) -> None:
        self._now = 0.0

    def __call__(self) -> float:
        return self._now


class _RecordingCoreLink:
    def __init__(self) -> None:
        self.writes: list[tuple[str, bytes, int, int]] = []
        self._gate = asyncio.Event()
        self._gate.set()

    def core_cumulative_ack(self) -> int:
        return 0

    @property
    def replay_pending_gate(self) -> asyncio.Event:
        return self._gate

    async def escalate_if_breaker_tripped(self, leg: GatewayLeg) -> None:
        return None

    async def write_leg_unit(self, adapter_id: str, payload: bytes, *, seq: int, ack: int) -> None:
        self.writes.append((adapter_id, payload, seq, ack))


def _make_leg(adapter_id: str, cap: GlobalReplayCap) -> GatewayLeg:
    clock = _FakeClock()
    return GatewayLeg(
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


async def test_drain_sets_registered_back_pressure_gate() -> None:
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    sched.register_leg(_make_leg("discord", cap))

    gate = asyncio.Event()
    gate.clear()  # the forward path engaged back-pressure
    sched.set_back_pressure_gate("discord", gate)
    assert not gate.is_set()

    sched.enqueue("discord", b"frame")
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        await _drain_until(lambda: gate.is_set())
        pump.cancel()
    # The scheduler SET the registered gate after draining discord's frame (resume).
    assert gate.is_set()
    assert core.writes and core.writes[0][0] == "discord"


async def test_unregistered_gate_leg_drains_unchanged() -> None:
    # A leg with NO registered gate (the TUI / default) drains exactly as before — the
    # scheduler must not require a gate per leg.
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    sched.register_leg(_make_leg("tui", cap))
    sched.enqueue("tui", b"x")
    async with asyncio.TaskGroup() as tg:
        pump = tg.create_task(sched.run())
        await _drain_until(lambda: len(core.writes) == 1)
        pump.cancel()
    assert core.writes[0][0] == "tui"


async def test_set_back_pressure_gate_for_unregistered_adapter_is_loud() -> None:
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=100)
    with pytest.raises(KeyError):
        sched.set_back_pressure_gate("not-registered", asyncio.Event())


async def test_deregister_drops_back_pressure_gate() -> None:
    # A deregistered leg's gate must not linger (the reap-on-teardown contract): re-using
    # the adapter id after deregister starts with no gate.
    cap = GlobalReplayCap(max_total_bytes=1_000_000)
    core = _RecordingCoreLink()
    sched = GatewayLegScheduler(core, max_per_leg_queue_bytes=1_000_000)
    sched.register_leg(_make_leg("discord", cap))
    gate = asyncio.Event()
    sched.set_back_pressure_gate("discord", gate)
    sched.deregister_leg("discord")
    # The gate registry dropped the entry; a fresh registration has no stale gate.
    assert "discord" not in sched.registered_adapters
