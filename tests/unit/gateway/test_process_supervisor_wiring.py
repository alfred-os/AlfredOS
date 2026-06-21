"""G6-2b-2a (#288): GatewayProcess wires the supervisor live with an empty adapter set.

The adapter supervisor is wired LIVE into the gateway process boot (its status emitter
bound to the live ``core_link.send_status_frame`` leg), but with an EMPTY configured
adapter set (gap b) — the plumbing is live, no child is spawned until G6-3. The
supervised supervisor task is cancelled/reaped on gateway-process shutdown (correction
#5) so a future NON-empty set cannot block the shutdown forever.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable

import pytest
import structlog.testing

from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    GatewayAdapterSupervisor,
)
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_gate import PerAdapterIngressGate
from alfred.gateway.leg_scheduler import GatewayLegScheduler
from alfred.gateway.process import (
    GatewayProcess,
    _CoreEpochCredSeam,
    _UnspawnedAdapterChildFactory,
)
from alfred.gateway.replay_buffer import ReplayBuffer


def _instant_then_park_sleep() -> Callable[[float], Awaitable[None]]:
    """A sleep that returns once (instant) then PARKS — drives a single sweep iteration.

    The K5 sweep loop is ``while True: await sleep(interval); sweep()``. This makes the FIRST
    sleep instant (so one sweep runs) and every subsequent sleep park on a never-set event,
    so the loop does not busy-spin under the test (mirrors the harness parking-sleep).
    """
    park = asyncio.Event()
    fired = False

    async def _sleep(delay: float) -> None:
        nonlocal fired
        del delay
        if not fired:
            fired = True
            return
        await park.wait()

    return _sleep


def _make_core_link() -> GatewayCoreLink:
    return GatewayCoreLink(client_listener=GatewayClientListener())


def _make_scheduler(core_link: GatewayCoreLink) -> GatewayLegScheduler:
    """An empty leg scheduler over ``core_link`` (Spec B G6-4 Task 7).

    ``_run_relay_and_scheduler`` reaps the supervisor + the K5 sweeper + tears the scheduler
    down on exit. With no leg registered the sweeper is a no-op and ``aclose`` is a no-op —
    these tests exercise the supervisor/relay reaping arms, not the leg lifecycle.
    """
    return GatewayLegScheduler(core_link, max_per_leg_queue_bytes=1 << 20)


def test_process_builds_status_sink_and_supervisor_for_core_link() -> None:
    """The process builds a GatewayAdapterSupervisor bound to a core link's status leg.

    2b-2a wires the plumbing and spawns nothing — the configured adapter set is empty.
    """
    process = GatewayProcess(shutdown_event=asyncio.Event())
    core_link = _make_core_link()
    supervisor = process._build_adapter_supervisor(core_link)
    assert isinstance(supervisor, GatewayAdapterSupervisor)
    assert process._adapter_ids == []  # 2b-2a wires the plumbing, spawns nothing


async def test_supervise_empty_set_is_a_clean_noop() -> None:
    """supervise_all([]) returns immediately — live-wired, spawns nothing (gap b)."""
    process = GatewayProcess(shutdown_event=asyncio.Event())
    core_link = _make_core_link()
    supervisor = process._build_adapter_supervisor(core_link)
    await asyncio.wait_for(supervisor.supervise_all(process._adapter_ids), timeout=1.0)


async def test_unspawned_child_factory_fails_closed() -> None:
    """The placeholder child factory raises GatewayAdapterSpawnError (fail-closed, gap b).

    With the empty adapter set it is never called; if a future non-empty set is passed
    before the real factory lands, the spawn fails LOUD rather than running a
    credential-less adapter.
    """

    async def _noop_deliver(_write_fd: int) -> None:  # pragma: no cover - never reached
        pass

    factory = _UnspawnedAdapterChildFactory()
    with __import__("pytest").raises(GatewayAdapterSpawnError):
        await factory.spawn_and_handshake(
            adapter_id="discord", epoch="a" * 32, deliver_credential=_noop_deliver
        )


def test_process_builds_supervisor_with_real_credential_client() -> None:
    """G6-3 (#288): the process wires the supervisor with the REAL credential client.

    The supervisor's at-spawn credential acquirer is a live
    GatewayAdapterCredentialClient holding the core link (the credential round-trip's
    gateway half), the cred seam is the cheap live-epoch probe, and the epoch is
    sourced LIVE from the core link (H1) — never a construction-time snapshot.
    """
    from alfred.gateway.adapter_credential_client import GatewayAdapterCredentialClient

    process = GatewayProcess(shutdown_event=asyncio.Event())
    core_link = _make_core_link()
    supervisor = process._build_adapter_supervisor(core_link)
    # The supervisor holds the real client + the live epoch source (not a snapshot).
    assert isinstance(supervisor._credential_client, GatewayAdapterCredentialClient)
    assert isinstance(supervisor._cred, _CoreEpochCredSeam)
    # The epoch source is the core link's LIVE accessor (H1).
    assert supervisor._epoch_source == core_link.current_core_epoch


async def test_core_epoch_cred_seam_tracks_link_liveness() -> None:
    """The cheap pre-spawn probe is available iff the core link has captured an epoch.

    A fresh core link has no epoch (link not handshaked) -> unavailable -> AWAITING_CORE.
    Once the link captures a 32-hex epoch the probe reports available (G6-3 / H2 part i).
    """
    core_link = _make_core_link()
    seam = _CoreEpochCredSeam(core_link=core_link)
    assert await seam.is_available(adapter_id="discord") is False
    core_link._core_epoch = "0123456789abcdef0123456789abcdef"
    assert await seam.is_available(adapter_id="discord") is True


async def test_supervisor_task_is_cancelled_on_shutdown() -> None:
    """Correction #5: the supervised supervisor task is cancelled/reaped on shutdown.

    Drives ``_run_relay_and_supervisor`` with a NON-empty adapter set so the supervisor
    would otherwise park forever (the placeholder cred seam never makes the adapter
    available — it stays in AWAITING_CORE). A fake relay returns as soon as shutdown is
    signalled; the helper must then cancel the parked supervisor task and return, never
    hang. A hang fails the ``wait_for`` timeout LOUD (hard rule #7).
    """
    shutdown = asyncio.Event()
    process = GatewayProcess(shutdown_event=shutdown, adapter_ids=["discord"])
    core_link = _make_core_link()
    supervisor = process._build_adapter_supervisor(core_link)
    scheduler = _make_scheduler(core_link)

    class _FakeRelay:
        async def run(self) -> None:
            # Stand in for the real relay: end as soon as shutdown is signalled.
            await shutdown.wait()

    async def _signal_shutdown_soon() -> None:
        await asyncio.sleep(0.05)
        shutdown.set()

    signal_task = asyncio.ensure_future(_signal_shutdown_soon())
    try:
        # If the supervisor/sweeper tasks were NOT cancelled on the relay's clean return,
        # this would hang (the discord adapter parks in AWAITING_CORE forever) -> timeout.
        await asyncio.wait_for(
            process._run_relay_and_scheduler(_FakeRelay(), supervisor, scheduler),  # type: ignore[arg-type]
            timeout=2.0,
        )
    finally:
        await signal_task


async def test_supervisor_spawn_failure_aborts_and_cancels_the_relay() -> None:
    """A fail-closed supervisor spawn error surfaces LOUD and cancels the running relay.

    The supervisor (not the relay) finishes first WITH a raise — the helper re-raises it
    (so a real G6-3 spawn failure is never swallowed) and the ``finally`` cancels the
    still-running relay so it never outlives the aborted process (covers the relay-cancel
    arm).
    """
    process = GatewayProcess(shutdown_event=asyncio.Event(), adapter_ids=["discord"])
    scheduler = _make_scheduler(_make_core_link())

    class _RaisingSupervisor:
        async def supervise_all(self, adapter_ids: list[str]) -> None:
            raise GatewayAdapterSpawnError("spawn refused (fail-closed)")

    relay_cancelled = asyncio.Event()

    class _ForeverRelay:
        async def run(self) -> None:
            try:
                await asyncio.Event().wait()  # runs until cancelled
            except asyncio.CancelledError:
                relay_cancelled.set()
                raise

    with pytest.raises(GatewayAdapterSpawnError):
        await asyncio.wait_for(
            process._run_relay_and_scheduler(_ForeverRelay(), _RaisingSupervisor(), scheduler),  # type: ignore[arg-type]
            timeout=2.0,
        )
    assert relay_cancelled.is_set()


# ---------------------------------------------------------------------------
# Spec B G6-4 Task 7 / K5 — the active ingress TTL sweeper.
# ---------------------------------------------------------------------------


class _Clock:
    """A hand-advanced monotonic seam for the ingress-gate TTL boundary."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def _binding_leg(adapter_id: str, clock: _Clock, *, ttl_seconds: float) -> GatewayLeg:
    """A leg with a FINITE-TTL ingress gate so a held in-flight slot can stall (K5)."""
    buf = ReplayBuffer()
    gate = PerAdapterIngressGate(
        adapter_id,
        sustained_rate_per_s=1e9,
        burst=10**9,
        max_inflight=10**9,
        ttl_seconds=ttl_seconds,
        max_frame_bytes=1 << 30,
        now=clock,
    )
    return GatewayLeg(
        adapter_id=adapter_id,
        buffer=buf,
        ingress_gate=gate,
        global_cap=GlobalReplayCap(max_total_bytes=buf.max_bytes * 4),
        now=clock,
    )


async def test_ingress_sweep_loop_reclaims_a_stalled_slot_loud() -> None:
    """K5: the active sweeper reclaims an in-flight slot held past the gate TTL + audits it.

    A leg admits a slot (held, never released) and the clock advances past the TTL with NO
    fresh admit to trigger an on-admit eviction — exactly the IDLE-but-wedged case the active
    sweep exists for. ONE sweep iteration evicts the slot and emits a loud
    ``gateway.ingress.slot_evicted`` breadcrumb (hard rule #7), then the loop parks.
    """
    clock = _Clock()
    leg = _binding_leg("discord", clock, ttl_seconds=30.0)
    admit = leg.try_admit(frame_bytes=10)
    assert admit.token is not None
    assert leg.inflight_count == 1
    clock.t = 31.0  # advance past the TTL (no fresh admit -> only the sweep can reclaim)

    process = GatewayProcess(shutdown_event=asyncio.Event(), sleep=_instant_then_park_sleep())
    scheduler = _make_scheduler(_make_core_link())
    scheduler.register_leg(leg)

    with structlog.testing.capture_logs() as captured:
        sweep_task = asyncio.ensure_future(process._ingress_sweep_loop(scheduler))
        # The first iteration sleeps (instant), sweeps (evicts the stalled slot), then the
        # second iteration parks forever on the injected sleep.
        for _ in range(20):
            await asyncio.sleep(0)
            if leg.inflight_count == 0:
                break
        sweep_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sweep_task

    assert leg.inflight_count == 0  # the stalled slot was reclaimed by the sweep
    evicted = [c for c in captured if c.get("event") == "gateway.ingress.slot_evicted"]
    assert len(evicted) == 1
    assert evicted[0].get("adapter_id") == "discord"
    assert evicted[0].get("reason") == "ttl_expired"


async def test_ingress_sweep_tolerates_a_leg_deregistered_mid_sweep() -> None:
    """CR (Spec B G6-4 #288): a leg isolated between the id-snapshot and the per-leg lookup is
    SKIPPED, not a sweeper crash.

    The sweep snapshots ``scheduler.adapter_ids()`` then looks each up via ``scheduler.leg``.
    Those two steps are not atomic: the perf-M4 isolation path can deregister a faulting leg in
    between, so ``leg(stale_id)`` raises ``KeyError``. The sweeper must tolerate it (skip the
    stale id) — crashing would silently end K5 enforcement (hard rule #7). A scheduler stub
    yields one stale id whose ``leg`` raises; the sweep completes one clean iteration, evicts
    nothing, and the loop parks (never raises).
    """

    class _StaleScheduler:
        def adapter_ids(self) -> tuple[str, ...]:
            return ("isolated-mid-sweep",)  # snapshot includes a now-gone leg

        def leg(self, adapter_id: str) -> GatewayLeg:
            raise KeyError(adapter_id)  # deregistered between snapshot and lookup

    process = GatewayProcess(shutdown_event=asyncio.Event(), sleep=_instant_then_park_sleep())
    with structlog.testing.capture_logs() as captured:
        sweep_task = asyncio.ensure_future(
            process._ingress_sweep_loop(_StaleScheduler())  # type: ignore[arg-type]
        )
        for _ in range(10):
            await asyncio.sleep(0)  # let the one instant iteration run, then it parks
        assert not sweep_task.done()  # parked, NOT crashed on the KeyError
        sweep_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sweep_task
    # The stale id was skipped — no eviction breadcrumb, no crash.
    assert [c for c in captured if c.get("event") == "gateway.ingress.slot_evicted"] == []


async def test_run_relay_and_scheduler_surfaces_a_sweeper_crash_loud() -> None:
    """A sweeper that RAISES first is surfaced loud (the sweep_task.result() re-raise arm).

    Guards the background-crash-never-swallowed branch (hard rule #7): if the K5 sweep loop
    dies with a non-cancelled exception it must propagate out of the runner, not be silently
    dropped. A relay that parks forever + a sweeper that raises immediately makes the sweeper
    finish first WITH a raise; the runner re-raises it and the ``finally`` reaps the relay.
    """
    process = GatewayProcess(shutdown_event=asyncio.Event())
    scheduler = _make_scheduler(_make_core_link())

    class _ForeverRelay:
        async def run(self) -> None:
            await asyncio.Event().wait()

    class _NoopSupervisor:
        async def supervise_all(self, adapter_ids: list[str]) -> None:
            await asyncio.Event().wait()  # park (the empty-set no-op would also do)

    boom = RuntimeError("sweeper boom")

    async def _raising_sweep(_sched: object) -> None:
        raise boom

    process._ingress_sweep_loop = _raising_sweep  # type: ignore[method-assign,assignment]

    with pytest.raises(RuntimeError, match="sweeper boom"):
        await asyncio.wait_for(
            process._run_relay_and_scheduler(_ForeverRelay(), _NoopSupervisor(), scheduler),  # type: ignore[arg-type]
            timeout=2.0,
        )
