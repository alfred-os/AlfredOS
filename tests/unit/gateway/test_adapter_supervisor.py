"""Tests for ``GatewayAdapterSupervisor`` against fake child/cred/sink seams.

G6-2b-1 (Spec B §3/§4/§6 / #288). The supervisor is the imperative shell that
drives the pure :class:`AdapterLifecycleMachine`: it acquires the (FAKE, in 2b-1)
credential, spawns the child through the (FAKE) child factory, runs the handshake,
emits each lifecycle transition's ``gateway.adapter.*`` frame to the injected sink,
detects a crash, restarts with bounded decorrelated-jitter backoff, and trips a
per-adapter circuit breaker on a crash-loop.

EVERY seam is injectable so the whole surface runs NON-ROOT / in-process on the
required gate (the G2/#245 + G6-0b paper-gate lesson): no bwrap, no real launcher,
no real credential. The real bwrap spawn is G6-3; the live gateway->core status
leg is 2b-2 (this PR emits to a fake sink). This file covers Task 4 (spawn +
handshake -> up, fail-closed spawn), Task 5 (crash -> backoff restart), Task 6
(breaker), Task 7 (concurrent boot) and the every-transition-emits-by-construction
invariant (correction #2).
"""

from __future__ import annotations

import asyncio
import random
from collections import Counter as MultiCounter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import pytest
from prometheus_client import REGISTRY

from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    GatewayAdapterSupervisor,
    _AdapterRun,
)

pytestmark = pytest.mark.asyncio

# A 32-hex epoch the supervisor stamps onto every ``up`` frame (mirrors the
# per-core-boot epoch the daemon would supply; AdapterUpNotification.epoch enforces
# the 32-hex rule, so a wrong shape would raise at the producer).
_EPOCH = "0123456789abcdef0123456789abcdef"

# adapter_ids must be members of the closed ``adapter_kind`` set (AdapterId
# validator), so the frame models accept them.
_A = "discord"
_B = "tui"
_C = "alfred_comms_test"


def _restarts_total(adapter_id: str) -> float:
    """Current value of the process-global restarts counter for ``adapter_id`` (0 if
    the series has not been touched yet). Tests assert a DELTA on this, never an
    absolute, because the counter accumulates across the whole test session."""
    value = REGISTRY.get_sample_value("gateway_adapter_restarts_total", {"adapter": adapter_id})
    return value or 0.0


# ---------------------------------------------------------------------------
# Fake seams
# ---------------------------------------------------------------------------


@dataclass
class _RecordingSink:
    """Fake status sink: records every ``(method, params)`` the emitter produces."""

    frames: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    async def emit(self, method: str, params: dict[str, object]) -> None:
        self.frames.append((method, params))

    def methods(self) -> list[str]:
        return [m for m, _ in self.frames]


@dataclass
class _FakeChild:
    """A spawned-child handle whose exit the test drives.

    ``exit_future`` resolves with an (error_class, detail) crash tuple when the test
    wants to simulate a process exit, or stays pending for a healthy child.
    """

    adapter_id: str
    spawned_at: float
    exit_future: asyncio.Future[tuple[str, str]]

    async def wait_until_exit(self) -> tuple[str, str]:
        return await self.exit_future


class _FakeChildFactory:
    """Fake child factory: hands out controllable :class:`_FakeChild` handles.

    ``spawn_outcomes`` is a per-call script: ``"ok"`` spawns a healthy child,
    ``"spawn_error"`` raises (fail-closed spawn), ``"handshake_fail"`` returns a
    child that has already crashed at handshake. A queue per adapter_id lets a test
    script the crash-then-recover sequence Task 5/6 need.
    """

    def __init__(self) -> None:
        self.outcomes: dict[str, list[str]] = {}
        self.children: list[_FakeChild] = []
        self.spawn_count: MultiCounter[str] = MultiCounter()

    def script(self, adapter_id: str, outcomes: list[str]) -> None:
        self.outcomes[adapter_id] = list(outcomes)

    async def spawn_and_handshake(self, *, adapter_id: str, epoch: str) -> _FakeChild:
        self.spawn_count[adapter_id] += 1
        queue = self.outcomes.get(adapter_id) or ["ok"]
        outcome = queue.pop(0) if queue else "ok"
        if outcome == "spawn_error":
            raise GatewayAdapterSpawnError(f"fake launcher spawn refused for {adapter_id!r}")
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[tuple[str, str]] = loop.create_future()
        child = _FakeChild(
            adapter_id=adapter_id,
            spawned_at=float(self.spawn_count[adapter_id]),
            exit_future=fut,
        )
        self.children.append(child)
        if outcome == "handshake_fail":
            raise GatewayAdapterSpawnError(f"fake handshake failed for {adapter_id!r}")
        return child


@dataclass
class _FakeCredSeam:
    """Fake credential seam (the 2b cred stand-in; real cred is G6-3).

    ``available`` decides whether a spawn may proceed. A test can flip it to model
    the cred-down -> AWAITING_CORE edge and back.
    """

    available: bool = True

    async def is_available(self, *, adapter_id: str) -> bool:
        return self.available


class _RecordingSleep:
    """A sleep seam that records each requested delay and never actually sleeps."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


class _StopDuringBackoffSleep:
    """A sleep seam that lands an operator stop INSIDE the backoff window.

    The supervisor calls ``sleep(delay)`` as the restart backoff (in
    ``_handle_crash``). On the ``trigger_on``-th call this seam fires
    ``on_backoff`` — the test wires that to ``request_stop`` so the stop lands
    AFTER the crash but BEFORE the restart spawn (the exact window CR's finding
    #3 covers). Records every delay so the test can still assert backoff shape.
    """

    def __init__(self, on_backoff: Callable[[], Awaitable[None]], *, trigger_on: int = 1) -> None:
        self.delays: list[float] = []
        self._on_backoff = on_backoff
        self._trigger_on = trigger_on

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)
        if len(self.delays) == self._trigger_on:
            await self._on_backoff()


def _make_supervisor(
    *,
    factory: _FakeChildFactory,
    cred: _FakeCredSeam,
    sink: _RecordingSink,
    rng_seed: int = 1,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], object] | None = None,
) -> GatewayAdapterSupervisor:
    emitter = AdapterStatusEmitter(sink=sink)
    # Deterministic seams: a no-op (or recording) sleep, a seeded RNG for
    # decorrelated jitter, and a synthetic clock.
    return GatewayAdapterSupervisor(
        child_factory=factory,
        cred_seam=cred,
        emitter=emitter,
        epoch=_EPOCH,
        sleep=sleep or _instant_sleep,  # type: ignore[arg-type]
        rng=random.Random(rng_seed),  # noqa: S311 — deterministic test jitter, not a crypto primitive
        monotonic=monotonic or _FakeClock().monotonic,
    )


async def _instant_sleep(_seconds: float) -> None:
    """A sleep seam that never actually sleeps (tests drive the schedule directly)."""


class _FakeClock:
    def __init__(self) -> None:
        self._t = 0.0

    def monotonic(self) -> float:
        self._t += 1.0
        return self._t


class _ScriptedClock:
    """A monotonic clock that returns a scripted sequence of timestamps.

    Lets a test place crashes far enough apart to fall OUTSIDE the breaker window so
    the stale-crash eviction (``recent_crashes.popleft``) arm runs. The last value is
    held once the script is exhausted.
    """

    def __init__(self, stamps: list[float]) -> None:
        self._stamps = list(stamps)
        self._last = stamps[-1] if stamps else 0.0

    def monotonic(self) -> float:
        if self._stamps:
            self._last = self._stamps.pop(0)
        return self._last


# ---------------------------------------------------------------------------
# Task 4 — single-adapter spawn + handshake -> up
# ---------------------------------------------------------------------------


async def test_spawn_handshake_reaches_up_and_emits_single_up_with_epoch() -> None:
    factory = _FakeChildFactory()
    factory.script(_A, ["ok"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    # Drive one adapter; stop it once it is UP so the coroutine terminates.
    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A)

    # Exactly one ``up`` frame, carrying the supervisor's epoch.
    up_frames = [(m, p) for m, p in sink.frames if m == "gateway.adapter.up"]
    assert len(up_frames) == 1
    assert up_frames[0][1] == {"adapter_id": _A, "epoch": _EPOCH, "host_restart_seq": 0}
    assert REGISTRY.get_sample_value("gateway_adapter_up", {"adapter": _A}) == 1.0

    await sup.request_stop(_A)
    await task
    # The planned stop emitted exactly one ``down``.
    assert sink.methods().count("gateway.adapter.down") == 1


async def test_cred_unavailable_routes_to_awaiting_core_and_emits_no_up() -> None:
    factory = _FakeChildFactory()
    cred = _FakeCredSeam(available=False)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_awaiting_core(_A)

    assert "gateway.adapter.up" not in sink.methods()
    assert REGISTRY.get_sample_value("gateway_adapter_awaiting_core", {"adapter": _A}) == 1.0
    # The factory was never asked to spawn (cred gate is BEFORE spawn).
    assert factory.spawn_count[_A] == 0

    await sup.request_stop(_A)
    await task


async def test_fail_closed_spawn_raises_typed_error_not_log_and_continue() -> None:
    """A fake child whose spawn raises surfaces GatewayAdapterSpawnError loudly."""
    factory = _FakeChildFactory()
    factory.script(_A, ["spawn_error"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    with pytest.raises(GatewayAdapterSpawnError):
        await sup.supervise_one(_A)
    # No false ``up`` was emitted for a child that never started.
    assert "gateway.adapter.up" not in sink.methods()


# ---------------------------------------------------------------------------
# Task 5 — crash detection -> bounded decorrelated-jitter restart
# ---------------------------------------------------------------------------


async def test_child_exit_emits_crashed_with_redacted_bounded_detail_then_restarts() -> None:
    factory = _FakeChildFactory()
    factory.script(_A, ["ok", "ok"])  # first crashes, second is the restart
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sleep = _RecordingSleep()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink, sleep=sleep)

    # The restarts counter is a process-global accumulator; assert a DELTA, not an
    # absolute (other tests increment the same {adapter=discord} series).
    restarts_before = _restarts_total(_A)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A)

    # Crash the first child with a detail carrying a secret-shaped token longer than
    # the crash-detail bound, so we prove BOTH redaction AND bounding on the wire.
    secret = "sk-" + "A" * 40
    long_detail = (secret + " ") * 50  # >256 chars, secret repeated
    first_child = factory.children[0]
    first_child.exit_future.set_result(("BrokenPipeError", long_detail))

    # The restart brings the adapter back UP (the second scripted child = 2nd up).
    await sup.wait_until_up(_A, incarnation=2)

    crashed = [p for m, p in sink.frames if m == "gateway.adapter.crashed"]
    assert len(crashed) == 1
    detail_on_wire = crashed[0]["detail"]
    assert isinstance(detail_on_wire, str)
    # REDACTED (no sk- fragment survives) AND BOUND (<= _MAX_CRASH_DETAIL_LEN).
    assert "sk-" not in detail_on_wire
    assert "[REDACTED:api-key-shape]" in detail_on_wire
    assert len(detail_on_wire) <= 256
    assert crashed[0]["error_class"] == "BrokenPipeError"

    # A restart was scheduled with a bounded, non-zero backoff drawn from the seam.
    assert len(sleep.delays) == 1
    assert 0.05 <= sleep.delays[0] <= 30.0
    assert _restarts_total(_A) == restarts_before + 1.0

    await sup.request_stop(_A)
    await task


async def test_status_frames_carry_aligned_host_restart_seq() -> None:
    """SEC-01 (#288): up(N) and crashed(N) align to the SAME incarnation.

    The first crash emits ``host_restart_seq=0`` (the crashed frame is emitted
    BEFORE ``restart_count += 1``, so it carries the PRE-increment value = the
    incarnation that exited). The matching up frame for that incarnation also
    carries 0; the second up (after one restart) carries 1, and a second crash
    carries 1 — so the reconciler can fold up(N)+crashed(N) onto one incarnation.
    """
    factory = _FakeChildFactory()
    factory.script(_A, ["ok", "ok", "ok"])  # crash twice, then steady
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sleep = _RecordingSleep()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink, sleep=sleep)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A, incarnation=1)
    factory.children[0].exit_future.set_result(("BrokenPipeError", "boom"))
    await sup.wait_until_up(_A, incarnation=2)
    factory.children[1].exit_future.set_result(("BrokenPipeError", "boom"))
    await sup.wait_until_up(_A, incarnation=3)

    await sup.request_stop(_A)
    await task

    up_seqs = [p["host_restart_seq"] for m, p in sink.frames if m == "gateway.adapter.up"]
    crashed_seqs = [p["host_restart_seq"] for m, p in sink.frames if m == "gateway.adapter.crashed"]
    # Three serving incarnations: 0, 1, 2 (restart_count at HANDSHAKE_OK time).
    assert up_seqs == [0, 1, 2]
    # Two crashes: the 0th and 1st incarnations exited (PRE-increment restart_count).
    assert crashed_seqs == [0, 1]


async def test_backoff_is_decorrelated_per_adapter() -> None:
    """Two adapters with DISTINCT seeds draw INDEPENDENT restart-delay sequences.

    Proves no stampede (spec §4 [fleet perf-004]): coincident crashes do not collapse
    onto one lockstep delay. We crash each adapter a few times under a no-breaker
    threshold (kept below the trip count) and compare the captured delay sequences.
    """
    delays_by_seed: dict[int, list[float]] = {}
    for seed in (1, 999):
        factory = _FakeChildFactory()
        factory.script(_A, ["ok", "ok", "ok"])  # up, crash, up, crash, up
        cred = _FakeCredSeam(available=True)
        sink = _RecordingSink()
        sleep = _RecordingSleep()
        sup = _make_supervisor(factory=factory, cred=cred, sink=sink, rng_seed=seed, sleep=sleep)

        task = asyncio.ensure_future(sup.supervise_one(_A))
        # Two crashes (below the breaker threshold of 3) -> two restart delays. Each
        # iteration waits for the i-th up, crashes that child, then the (i+1)-th up.
        for i in range(2):
            await sup.wait_until_up(_A, incarnation=i + 1)
            factory.children[i].exit_future.set_result(("BrokenPipeError", ""))
            await sup.wait_until_up(_A, incarnation=i + 2)
        await sup.request_stop(_A)
        await task
        delays_by_seed[seed] = list(sleep.delays)

    # Independent draws given distinct seeds: the two sequences differ.
    assert delays_by_seed[1] != delays_by_seed[999]
    # Both still respect the clamp window.
    for seq in delays_by_seed.values():
        for d in seq:
            assert 0.05 <= d <= 30.0


# ---------------------------------------------------------------------------
# Task 6 — per-adapter circuit breaker -> BREAKER_OPEN
# ---------------------------------------------------------------------------


async def test_crash_loop_trips_breaker_once_terminal_absorbing() -> None:
    """Three crashes in the window trip the per-adapter breaker -> BREAKER_OPEN.

    Exactly one AdapterBreakerOpenNotification (retry_after_seconds >= 0); the machine
    is terminal-absorbing afterwards (no second breaker emit); supervise_one returns.
    """
    factory = _FakeChildFactory()
    # Three healthy spawns that each then crash; the 3rd crash trips the breaker.
    factory.script(_A, ["ok", "ok", "ok"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    # Crash each incarnation; the 3rd crash trips the breaker (threshold 3).
    for i in range(3):
        await sup.wait_until_up(_A, incarnation=i + 1)
        factory.children[i].exit_future.set_result(("BrokenPipeError", ""))
    # supervise_one returns on the terminal breaker trip.
    await task

    breaker_frames = [p for m, p in sink.frames if m == "gateway.adapter.breaker_open"]
    assert len(breaker_frames) == 1
    retry_after = breaker_frames[0]["retry_after_seconds"]
    assert isinstance(retry_after, int)
    assert retry_after >= 0
    # Three crashes -> three crashed frames, then exactly one breaker_open.
    assert sink.methods().count("gateway.adapter.crashed") == 3
    assert sink.methods().count("gateway.adapter.breaker_open") == 1

    # Metrics: breaker open == 1, up == 0.
    assert REGISTRY.get_sample_value("gateway_adapter_breaker_open", {"adapter": _A}) == 1.0
    assert REGISTRY.get_sample_value("gateway_adapter_up", {"adapter": _A}) == 0.0


async def test_breaker_open_is_observable_via_helper() -> None:
    """``wait_until_breaker_open`` resolves when the breaker trips (observability)."""
    factory = _FakeChildFactory()
    factory.script(_A, ["ok", "ok", "ok"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    for i in range(3):
        await sup.wait_until_up(_A, incarnation=i + 1)
        factory.children[i].exit_future.set_result(("BrokenPipeError", ""))
    await sup.wait_until_breaker_open(_A)
    await task
    assert "gateway.adapter.breaker_open" in sink.methods()


# ---------------------------------------------------------------------------
# Task 7 — concurrent multi-adapter boot under a bounded TaskGroup
# ---------------------------------------------------------------------------


class _BarrierChildFactory:
    """Factory whose spawns all rendezvous at a barrier before any completes.

    Each ``spawn_and_handshake`` records its start and waits until ``started_count``
    reaches ``parties``; only then does any spawn return. If the supervisor SERIALISED
    the boots, the first spawn would block forever waiting for the others to start —
    so the boots all reaching ``up`` PROVES they overlapped (spec §4 [fleet perf-004]).
    """

    def __init__(self, parties: int) -> None:
        self._parties = parties
        self._started = 0
        self._all_started = asyncio.Event()
        self.start_order: list[str] = []
        self.children: dict[str, _FakeChild] = {}

    async def spawn_and_handshake(self, *, adapter_id: str, epoch: str) -> _FakeChild:
        self.start_order.append(adapter_id)
        self._started += 1
        if self._started >= self._parties:
            self._all_started.set()
        await self._all_started.wait()  # rendezvous: deadlocks if boots serialise
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[tuple[str, str]] = loop.create_future()
        child = _FakeChild(adapter_id=adapter_id, spawned_at=0.0, exit_future=fut)
        self.children[adapter_id] = child
        return child


async def test_supervise_all_boots_adapters_concurrently() -> None:
    factory = _BarrierChildFactory(parties=3)
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)  # type: ignore[arg-type]

    boot = asyncio.ensure_future(sup.supervise_all([_A, _B, _C]))
    for adapter in (_A, _B, _C):
        await sup.wait_until_up(adapter)
    # All three started spawning before any completed -> the barrier released, which
    # only happens when all three are concurrently inside spawn_and_handshake.
    assert set(factory.start_order) == {_A, _B, _C}
    up_ids = {p["adapter_id"] for m, p in sink.frames if m == "gateway.adapter.up"}
    assert up_ids == {_A, _B, _C}

    for adapter in (_A, _B, _C):
        await sup.request_stop(adapter)
    await boot


class _OneFailsFactory:
    """Healthy spawns for every adapter EXCEPT ``failing_id``, which raises a
    fail-closed spawn error only AFTER the siblings have reached up.

    Proves one adapter's fail-closed spawn does not prevent the siblings booting: the
    failure is gated behind ``siblings_up`` so the surviving adapters demonstrably
    emit their ``up`` frames before the TaskGroup aggregates the one failure.
    """

    def __init__(self, *, failing_id: str, sibling_count: int) -> None:
        self._failing_id = failing_id
        self._sibling_count = sibling_count
        self._siblings_up = 0
        self._siblings_done = asyncio.Event()
        self.children: dict[str, _FakeChild] = {}

    def mark_sibling_up(self) -> None:
        self._siblings_up += 1
        if self._siblings_up >= self._sibling_count:
            self._siblings_done.set()

    async def spawn_and_handshake(self, *, adapter_id: str, epoch: str) -> _FakeChild:
        if adapter_id == self._failing_id:
            # Wait until the siblings are up, THEN fail closed.
            await self._siblings_done.wait()
            raise GatewayAdapterSpawnError(f"fake spawn refused for {adapter_id!r}")
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[tuple[str, str]] = loop.create_future()
        child = _FakeChild(adapter_id=adapter_id, spawned_at=0.0, exit_future=fut)
        self.children[adapter_id] = child
        return child


async def test_one_fail_closed_spawn_does_not_block_siblings() -> None:
    factory = _OneFailsFactory(failing_id=_C, sibling_count=2)
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)  # type: ignore[arg-type]

    boot = asyncio.ensure_future(sup.supervise_all([_A, _B, _C]))
    # The two siblings reach up; tell the factory so the failing one may now raise.
    for adapter in (_A, _B):
        await sup.wait_until_up(adapter)
        factory.mark_sibling_up()

    # supervise_all aggregates the one fail-closed spawn into an ExceptionGroup; the
    # TaskGroup cancels the (healthy, never-terminating) siblings as it unwinds.
    with pytest.raises(BaseExceptionGroup) as excinfo:
        await boot
    spawn_errors = [e for e in excinfo.value.exceptions if isinstance(e, GatewayAdapterSpawnError)]
    assert len(spawn_errors) == 1

    # The surviving two adapters demonstrably emitted their ``up`` frames before the
    # failure unwound the group.
    up_ids = {p["adapter_id"] for m, p in sink.frames if m == "gateway.adapter.up"}
    assert {_A, _B} <= up_ids
    assert _C not in up_ids  # the failing adapter never reached up


# ---------------------------------------------------------------------------
# Correction #2 — every lifecycle transition emits its frame BY CONSTRUCTION
# ---------------------------------------------------------------------------


async def test_every_emitting_transition_produces_exactly_its_frame() -> None:
    """Drive the supervisor through every CONTROL-emitting transition and assert each
    produced exactly the matching ``gateway.adapter.*`` frame on the injected sink.

    The emitter is wired into the supervisor's single transition applicator (_apply),
    so a transition that emits a control inseparably emits its frame — this test pins
    that all four (up / crashed / breaker_open / down) fire, none can be silently
    dropped (Spec B §6 / correction #2). The crash arm (3 crashes -> breaker) covers
    up+crashed+breaker_open in ONE run; a second short run covers the planned-stop
    down.
    """
    # Run 1: up -> 3x crashed -> breaker_open (no planned stop here).
    factory = _FakeChildFactory()
    factory.script(_A, ["ok", "ok", "ok"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)
    task = asyncio.ensure_future(sup.supervise_one(_A))
    for i in range(3):
        await sup.wait_until_up(_A, incarnation=i + 1)
        factory.children[i].exit_future.set_result(("BrokenPipeError", "boom"))
    await task

    methods = MultiCounter(m for m, _ in sink.frames)
    assert methods["gateway.adapter.up"] == 3  # one per incarnation
    assert methods["gateway.adapter.crashed"] == 3
    assert methods["gateway.adapter.breaker_open"] == 1
    assert methods["gateway.adapter.down"] == 0  # no planned stop in this run

    # Run 2: up -> planned stop -> down (the one transition run 1 did not exercise).
    factory2 = _FakeChildFactory()
    factory2.script(_B, ["ok"])
    sink2 = _RecordingSink()
    sup2 = _make_supervisor(factory=factory2, cred=_FakeCredSeam(available=True), sink=sink2)
    task2 = asyncio.ensure_future(sup2.supervise_one(_B))
    await sup2.wait_until_up(_B)
    await sup2.request_stop(_B)
    await task2
    methods2 = MultiCounter(m for m, _ in sink2.frames)
    assert methods2["gateway.adapter.up"] == 1
    assert methods2["gateway.adapter.down"] == 1


# ---------------------------------------------------------------------------
# Trust-boundary recovery — AWAITING_CORE -> CRED_AVAILABLE
# ---------------------------------------------------------------------------


async def test_awaiting_core_recovers_to_up_when_cred_becomes_available() -> None:
    """A cred-down adapter parks in AWAITING_CORE, then RECOVERS once the cred returns.

    Covers the trust-boundary recovery arm (``make_cred_available`` ->
    ``_wait_cred_or_stop`` cred-came-back -> ``CRED_AVAILABLE`` -> RESTARTING ->
    re-spawn -> UP). 2b-1's cred seam is fake, but the recovery EDGE is the real one
    the core-supplied credential will drive in G6-3, so it must be proven now.
    """
    factory = _FakeChildFactory()
    factory.script(_A, ["ok"])  # the spawn AFTER the cred returns reaches up
    cred = _FakeCredSeam(available=False)  # start cred-down -> park
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_awaiting_core(_A)
    # Parked: no spawn yet, awaiting_core gauge is hot, no up frame.
    assert factory.spawn_count[_A] == 0
    assert REGISTRY.get_sample_value("gateway_adapter_awaiting_core", {"adapter": _A}) == 1.0
    assert "gateway.adapter.up" not in sink.methods()

    # The cred becomes available; signal the parked adapter -> it recovers.
    cred.available = True
    sup.make_cred_available(_A)

    await sup.wait_until_up(_A)
    assert factory.spawn_count[_A] == 1  # spawned exactly once, AFTER the cred returned
    up_frames = [(m, p) for m, p in sink.frames if m == "gateway.adapter.up"]
    assert len(up_frames) == 1
    assert up_frames[0][1] == {"adapter_id": _A, "epoch": _EPOCH, "host_restart_seq": 0}
    # The awaiting_core gauge cleared on the recovery.
    assert REGISTRY.get_sample_value("gateway_adapter_awaiting_core", {"adapter": _A}) == 0.0

    await sup.request_stop(_A)
    await task


async def test_awaiting_core_then_planned_stop_is_terminal_down() -> None:
    """A planned stop while parked in AWAITING_CORE wins the race -> DOWN (terminal).

    Covers ``_wait_cred_or_stop``'s stop-wins arm: the adapter never spawns, emits a
    single ``down``, and ``supervise_one`` returns.
    """
    factory = _FakeChildFactory()
    cred = _FakeCredSeam(available=False)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_awaiting_core(_A)
    await sup.request_stop(_A)
    await task  # supervise_one returns on the terminal DOWN

    assert factory.spawn_count[_A] == 0  # never spawned (cred never returned)
    assert "gateway.adapter.up" not in sink.methods()
    assert sink.methods().count("gateway.adapter.down") == 1
    assert REGISTRY.get_sample_value("gateway_adapter_awaiting_core", {"adapter": _A}) == 0.0


# ---------------------------------------------------------------------------
# Fail-closed spawn FAILURE on a SUBSEQUENT restart (not just the first)
# ---------------------------------------------------------------------------


async def test_subsequent_restart_spawn_failure_routes_through_breaker_not_reraise() -> None:
    """A crash -> restart whose RE-SPAWN itself fails does NOT re-raise; it routes
    through the crash/breaker arm. Three crashes (1 process-exit + 2 spawn-fails) trip
    the breaker -> BREAKER_OPEN (terminal).

    This is the distinct-from-first-attempt path: the FIRST spawn failure surfaces
    loudly (a boot can refuse the adapter), but a spawn failure on a LATER restart is
    just another crash of an already-running supervision cycle, so it must be absorbed
    by the breaker, never re-raised out of ``supervise_one``.
    """
    factory = _FakeChildFactory()
    # up -> crash(process exit) -> restart spawn fails -> restart spawn fails -> breaker.
    factory.script(_A, ["ok", "spawn_error", "spawn_error"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    restarts_before = _restarts_total(_A)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A, incarnation=1)
    # Crash the live child (crash #1) -> backoff -> the two scripted spawn-fails follow.
    factory.children[0].exit_future.set_result(("BrokenPipeError", "first crash"))

    # supervise_one returns on the terminal breaker trip; it must NOT raise the
    # subsequent GatewayAdapterSpawnError out (it's absorbed by the crash arm).
    await sup.wait_until_breaker_open(_A)
    await task  # returns cleanly, no exception

    # Three crashed frames (1 child-exit + 2 handshake/spawn-fails), one breaker_open.
    assert sink.methods().count("gateway.adapter.crashed") == 3
    assert sink.methods().count("gateway.adapter.breaker_open") == 1
    assert REGISTRY.get_sample_value("gateway_adapter_breaker_open", {"adapter": _A}) == 1.0
    # Two restarts were scheduled (after crash #1 and crash #2); the 3rd crash tripped.
    assert _restarts_total(_A) == restarts_before + 2.0
    # The accessor reflects the same count.
    assert sup.restart_count(_A) == 2


# ---------------------------------------------------------------------------
# Breaker window — stale crashes age out (recent_crashes eviction)
# ---------------------------------------------------------------------------


async def test_stale_crashes_age_out_of_breaker_window() -> None:
    """Crashes spaced beyond the 300s window are evicted, so the breaker never trips.

    Drives the ``recent_crashes.popleft`` eviction arm: each crash lands >300s after
    the previous one (per the scripted clock), so the window only ever holds one
    crash and the threshold (3) is never reached — the adapter keeps recovering.
    """
    factory = _FakeChildFactory()
    factory.script(_A, ["ok", "ok", "ok", "ok"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    # Each crash records a monotonic stamp 1000s after the previous -> always evicts.
    clock = _ScriptedClock([1000.0, 2000.0, 3000.0, 4000.0])
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink, monotonic=clock.monotonic)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    # Three crashes that would trip a naive (non-evicting) breaker; here each one is
    # outside the prior's window, so the breaker NEVER trips.
    for i in range(3):
        await sup.wait_until_up(_A, incarnation=i + 1)
        factory.children[i].exit_future.set_result(("BrokenPipeError", ""))
    await sup.wait_until_up(_A, incarnation=4)  # recovered every time

    assert "gateway.adapter.breaker_open" not in sink.methods()
    assert sink.methods().count("gateway.adapter.crashed") == 3

    await sup.request_stop(_A)
    await task


# ---------------------------------------------------------------------------
# Fix #4 — shared-RNG no stampede: two adapters under ONE supervisor
# ---------------------------------------------------------------------------


async def test_two_adapters_one_supervisor_shared_rng_distinct_backoffs() -> None:
    """Two adapters under ONE supervisor (ONE shared RNG) get DISTINCT backoff delays.

    Production shares a single ``random.Random()`` across all adapters. The
    no-stampede property comes from each draw being an independent sample of that
    shared stream: two adapters crashing together take CONSECUTIVE (distinct) draws,
    so they never redial in lockstep. This proves the actual shared-RNG behaviour the
    docstring describes (not a per-adapter-stream claim).
    """
    factory = _FakeChildFactory()
    factory.script(_A, ["ok", "ok"])  # _A: up, crash, up
    factory.script(_B, ["ok", "ok"])  # _B: up, crash, up
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()

    # ONE supervisor -> ONE shared rng. Capture each adapter's backoff draw keyed by
    # adapter_id so we can compare the two adapters' delays from the shared stream.
    delays: dict[str, list[float]] = {_A: [], _B: []}

    sup = GatewayAdapterSupervisor(
        child_factory=factory,
        cred_seam=cred,
        emitter=AdapterStatusEmitter(sink=sink),
        epoch=_EPOCH,
        sleep=_instant_sleep,  # type: ignore[arg-type]
        rng=random.Random(1234),  # noqa: S311 — deterministic test jitter, not a crypto primitive
        monotonic=_FakeClock().monotonic,
    )

    # Wrap _next_backoff to capture which adapter drew which delay from the shared rng.
    original_next_backoff = sup._next_backoff

    def _capturing(run: _AdapterRun) -> float:
        delay = original_next_backoff(run)
        delays[run.adapter_id].append(delay)
        return delay

    sup._next_backoff = _capturing  # type: ignore[method-assign]

    task_a = asyncio.ensure_future(sup.supervise_one(_A))
    task_b = asyncio.ensure_future(sup.supervise_one(_B))
    # Bring both up, crash both (drawing one backoff each from the SHARED rng), recover.
    await sup.wait_until_up(_A, incarnation=1)
    await sup.wait_until_up(_B, incarnation=1)
    factory.children[0].exit_future.set_result(("BrokenPipeError", ""))
    factory.children[1].exit_future.set_result(("BrokenPipeError", ""))
    await sup.wait_until_up(_A, incarnation=2)
    await sup.wait_until_up(_B, incarnation=2)

    await sup.request_stop(_A)
    await sup.request_stop(_B)
    await task_a
    await task_b

    # Each adapter drew exactly one backoff from the shared stream.
    assert len(delays[_A]) == 1
    assert len(delays[_B]) == 1
    # Consecutive draws from one shared RNG are distinct -> no lockstep stampede.
    assert delays[_A][0] != delays[_B][0]
    for d in (delays[_A][0], delays[_B][0]):
        assert 0.05 <= d <= 30.0


# ---------------------------------------------------------------------------
# Default monotonic seam (production clock)
# ---------------------------------------------------------------------------


async def test_default_monotonic_seam_is_real_clock() -> None:
    """With no ``monotonic`` injected, the supervisor uses the real monotonic clock.

    Covers the production default-clock path (``_default_monotonic``): a crash records
    a real, non-decreasing timestamp toward the breaker window. We assert the adapter
    crashes + restarts using the real clock (no synthetic clock injected).
    """
    factory = _FakeChildFactory()
    factory.script(_A, ["ok", "ok"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()
    # Note: monotonic is NOT injected -> the real _default_monotonic seam is used.
    sup = GatewayAdapterSupervisor(
        child_factory=factory,
        cred_seam=cred,
        emitter=AdapterStatusEmitter(sink=sink),
        epoch=_EPOCH,
        sleep=_instant_sleep,  # type: ignore[arg-type]
        rng=random.Random(7),  # noqa: S311 — deterministic test jitter, not a crypto primitive
    )

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A, incarnation=1)
    factory.children[0].exit_future.set_result(("BrokenPipeError", ""))
    await sup.wait_until_up(_A, incarnation=2)  # restarted using the real clock window

    assert sink.methods().count("gateway.adapter.crashed") == 1

    await sup.request_stop(_A)
    await task


async def test_cancelling_a_parked_adapter_propagates_and_cleans_up() -> None:
    """Cancelling ``supervise_one`` while parked in AWAITING_CORE re-raises cleanly.

    Covers ``_wait_cred_or_stop``'s ``CancelledError`` arm: the gateway's structured
    shutdown (a TaskGroup unwind) can cancel an adapter while it is blocked awaiting
    the credential. The cancellation must propagate (never be swallowed — CLAUDE.md
    hard rule #7), and the inner cred/stop waiter tasks must be cancelled so no task is
    left dangling.
    """
    factory = _FakeChildFactory()
    cred = _FakeCredSeam(available=False)  # park in AWAITING_CORE, then cancel
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_awaiting_core(_A)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The adapter never spawned and never emitted a down (a cancellation is not a
    # planned stop) — it was torn down mid-park.
    assert factory.spawn_count[_A] == 0
    assert "gateway.adapter.down" not in sink.methods()


# ---------------------------------------------------------------------------
# CR finding #3 — STOP_REQUESTED landing during the restart backoff window
# ---------------------------------------------------------------------------


async def test_stop_during_backoff_short_circuits_no_respawn_no_extra_up() -> None:
    """A stop landing AFTER a process-exit crash but BEFORE the restart spawn must
    short-circuit to the terminal ``down`` — no respawn, no second ``up``.

    Spec B §6: STOP_REQUESTED is honoured in EVERY live state, not only UP /
    AWAITING_CORE. A stop arriving while the supervisor is in the crash backoff
    window (``CRASHED`` / ``RESTARTING``) must NOT let the loop spin back round and
    bring the adapter up again — that would emit a spurious ``up`` after a stop was
    requested, violating the lifecycle contract. Exactly one terminal ``down`` is
    emitted and exactly one ``up`` (the pre-crash incarnation) ever fires.
    """
    factory = _FakeChildFactory()
    # Script a SECOND healthy child: if the stop fails to short-circuit, the loop
    # would respawn and reach a (spurious) 2nd ``up`` — the bug this test pins.
    factory.script(_A, ["ok", "ok"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()

    sup: GatewayAdapterSupervisor

    async def _land_stop() -> None:
        await sup.request_stop(_A)

    # The stop lands on the FIRST backoff sleep — i.e. after crash #1, before respawn.
    sleep = _StopDuringBackoffSleep(_land_stop, trigger_on=1)
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink, sleep=sleep)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A, incarnation=1)
    # Crash the live child -> backoff -> the stop fires INSIDE the backoff window.
    factory.children[0].exit_future.set_result(("BrokenPipeError", "boom"))

    await task  # supervise_one returns on the terminal DOWN (no hang, no breaker)

    methods = MultiCounter(m for m, _ in sink.frames)
    # Exactly one up (the pre-crash incarnation); NO second up after the stop.
    assert methods["gateway.adapter.up"] == 1
    # Exactly one terminal down; the crash emitted exactly one crashed.
    assert methods["gateway.adapter.down"] == 1
    assert methods["gateway.adapter.crashed"] == 1
    # The breaker never tripped (the stop won, not a crash-loop).
    assert methods["gateway.adapter.breaker_open"] == 0
    # The adapter never respawned after the stop (only the original spawn happened).
    assert factory.spawn_count[_A] == 1
    assert REGISTRY.get_sample_value("gateway_adapter_up", {"adapter": _A}) == 0.0


async def test_stop_during_backoff_after_spawn_fail_short_circuits_no_respawn() -> None:
    """A stop landing during the backoff that follows a SPAWN-fail crash short-circuits.

    Mirrors the process-exit case but for the ``_spawn_or_terminal`` recursion arm:
    crash #1 is a live-child exit, the restart's RE-SPAWN itself fails (another
    crash), and the stop lands in the backoff AFTER that spawn-fail — so the
    re-spawn recursion must NOT spawn again. No second ``up``, exactly one ``down``.
    """
    factory = _FakeChildFactory()
    # up -> crash(exit) -> respawn fails (crash #2) -> [stop lands] -> would respawn.
    factory.script(_A, ["ok", "spawn_error", "ok"])
    cred = _FakeCredSeam(available=True)
    sink = _RecordingSink()

    sup: GatewayAdapterSupervisor

    async def _land_stop() -> None:
        await sup.request_stop(_A)

    # Two backoffs run (after crash #1 and crash #2); land the stop on the SECOND,
    # i.e. inside the backoff that follows the spawn-fail, before the next re-spawn.
    sleep = _StopDuringBackoffSleep(_land_stop, trigger_on=2)
    sup = _make_supervisor(factory=factory, cred=cred, sink=sink, sleep=sleep)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A, incarnation=1)
    factory.children[0].exit_future.set_result(("BrokenPipeError", "boom"))

    await task  # terminal DOWN; no hang, no spurious up

    methods = MultiCounter(m for m, _ in sink.frames)
    assert methods["gateway.adapter.up"] == 1  # only the pre-crash incarnation
    assert methods["gateway.adapter.down"] == 1
    assert methods["gateway.adapter.breaker_open"] == 0
    # Two crashed frames: the process-exit + the spawn-fail; then the stop short-circuited.
    assert methods["gateway.adapter.crashed"] == 2
    # Spawned exactly twice (the original + the one that failed); never a third.
    assert factory.spawn_count[_A] == 2


# ---------------------------------------------------------------------------
# CR finding #1 — non-positive max_concurrent_boots is a deadlock guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_value", [0, -1])
async def test_non_positive_max_concurrent_boots_rejected(bad_value: int) -> None:
    """``max_concurrent_boots < 1`` makes the boot semaphore unacquirable, so
    ``supervise_all`` would hang forever — reject it loudly at construction."""
    factory = _FakeChildFactory()
    with pytest.raises(ValueError, match="max_concurrent_boots"):
        GatewayAdapterSupervisor(
            child_factory=factory,
            cred_seam=_FakeCredSeam(available=True),
            emitter=AdapterStatusEmitter(sink=_RecordingSink()),
            epoch=_EPOCH,
            max_concurrent_boots=bad_value,
        )


async def test_default_max_concurrent_boots_is_accepted() -> None:
    """The existing default constructs without error (guard keeps the default)."""
    sup = _make_supervisor(
        factory=_FakeChildFactory(), cred=_FakeCredSeam(available=True), sink=_RecordingSink()
    )
    assert sup is not None
