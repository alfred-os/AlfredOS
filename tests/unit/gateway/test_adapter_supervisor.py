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
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest
from prometheus_client import REGISTRY

from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    GatewayAdapterSupervisor,
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
    assert up_frames[0][1] == {"adapter_id": _A, "epoch": _EPOCH}
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
    assert REGISTRY.get_sample_value("gateway_adapter_restarts_total", {"adapter": _A}) == 1.0

    await sup.request_stop(_A)
    await task


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
