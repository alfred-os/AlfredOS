"""``GatewayAdapterSupervisor`` — the gateway's per-adapter supervision shell.

G6-2b-1 (Spec B §3/§4/§6 / #288). The always-up gateway SUPERVISES each
sandbox-spawned comms adapter child (ADR-0036 inversion: the gateway hosts the
adapter, the core only OBSERVES). This module is the imperative shell that drives
the pure :class:`alfred.gateway.adapter_lifecycle.AdapterLifecycleMachine`:

* acquire the (FAKE, in 2b-1) credential before a spawn — a cred-down defers to
  ``AWAITING_CORE`` instead of spawning credential-less;
* spawn the child through the child factory + run the handshake;
* emit each lifecycle transition's ``gateway.adapter.*`` frame (BY CONSTRUCTION —
  the emitter is wired into the single transition applicator :meth:`_apply`, so a
  transition that emits a control inseparably puts its frame on the sink, Spec B §6
  / correction #2);
* detect a crash (the child process exit), restart with bounded decorrelated-jitter
  backoff (per-adapter, no stampede — spec §4 ``[fleet perf-004]``);
* trip a per-adapter circuit breaker on a crash-loop -> ``BREAKER_OPEN`` (spec §6(c):
  never silently dark).

**Fake seams, non-root (the paper-gate guard).** Every collaborator is injected:
the child factory (FAKE child; real bwrap spawn is G6-3), the credential seam (FAKE;
real cred is G6-3), the status sink (FAKE; the live gateway->core status leg is
2b-2), and the determinism seams ``sleep`` / ``rng`` / ``monotonic`` (mirror
:class:`alfred.gateway.core_link`). So the whole surface runs in-process on the
required NON-ROOT gate — there is no bwrap, no launcher, no real credential here.

**Stateless-beyond-connection breaker (divergence note).** The daemon
:class:`alfred.supervisor.breaker.CircuitBreaker` is Postgres-backed; the gateway is
"stateless beyond a small connection buffer" per the comms-adapter contract, so this
supervisor uses a small IN-MEMORY per-adapter crash window (NOT the daemon breaker,
which is NOT imported). A gateway restart re-arms every adapter from scratch — that
is the correct posture for an always-up front door whose durable state lives in the
core.

**Constructed-but-not-wired-live (dormant, like G6-1).** 2b-1 ships this fully
unit-tested but NOT wired into :mod:`alfred.gateway.process` — the live
gateway->core status leg + the boot-graph registration are 2b-2. The real child
factory that constructs a per-adapter :class:`CommsPluginRunner` +
:class:`CommsStdioTransport` (share-in-place reuse, ADR-0036) is also 2b-2/G6-3
territory; 2b-1's tests drive a fake factory.
"""

from __future__ import annotations

import asyncio
import random
from collections import deque
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Final, Protocol

import structlog

from alfred.errors import AlfredError
from alfred.gateway.adapter_lifecycle import (
    AdapterControl,
    AdapterLifecycleEvent,
    AdapterLifecycleMachine,
    AdapterLifecycleState,
)
from alfred.gateway.adapter_metrics import (
    ADAPTER_AWAITING_CORE,
    ADAPTER_BREAKER_OPEN,
    ADAPTER_INFLIGHT,
    ADAPTER_RESTARTS,
    ADAPTER_UP,
)

if TYPE_CHECKING:
    from alfred.comms_mcp.protocol import AdapterDownReason
    from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter

log = structlog.get_logger(__name__)

# Decorrelated-jitter backoff window (mirrors core_link.py's clamp rationale): a
# non-zero floor so a pathological jitter draw can never collapse to a 0-delay
# tight-spin (spec §4: never a 0-delay first retry), and an upper clamp so a
# crash-loop's next attempt is bounded. The realised delay always lands in
# ``[_MIN_BACKOFF_SECONDS, _MAX_BACKOFF_SECONDS]``.
_MIN_BACKOFF_SECONDS: Final[float] = 0.05
_MAX_BACKOFF_SECONDS: Final[float] = 30.0
_INITIAL_BACKOFF_SECONDS: Final[float] = 0.25
_BACKOFF_FACTOR: Final[float] = 2.0

# Per-adapter in-memory crash window: this many crashes within the window trips the
# per-adapter breaker. Small + in-memory (NOT the Postgres daemon breaker — see the
# module docstring). The breaker's ``retry_after_seconds`` is the current backoff
# the adapter would have used, clamped.
_BREAKER_FAILURE_THRESHOLD: Final[int] = 3
_BREAKER_WINDOW_SECONDS: Final[float] = 300.0

# Max concurrent supervised-adapter boots under the bounded TaskGroup (Task 7). A
# handful of first-party adapters; the cap exists so a misconfigured fleet cannot
# fan out unboundedly.
_DEFAULT_MAX_CONCURRENT_BOOTS: Final[int] = 8


class GatewayAdapterSpawnError(AlfredError):
    """A launcher-spawn / handshake failure for one adapter (fail-closed).

    A FRESH gateway-local error — NOT a reuse of
    :class:`alfred.security.quarantine_child_io.QuarantineChildSpawnError` (a
    different subsystem). The supervisor raises it LOUDLY (CLAUDE.md hard rule #7)
    and refuses THAT adapter; under :meth:`GatewayAdapterSupervisor.supervise_all`
    the bounded ``TaskGroup`` surfaces it in the aggregated ``ExceptionGroup`` while
    sibling adapters still boot — one adapter's fail-closed spawn never kills the
    gateway or its siblings.
    """


class _AdapterChildLike(Protocol):
    """A spawned + handshaked adapter child whose process exit the supervisor awaits."""

    async def wait_until_exit(self) -> tuple[str, str]:
        """Block until the child process exits; return ``(error_class, detail)``.

        The detail is redacted at the emitter (REDACT-then-bound), never here.
        """
        ...


class _AdapterChildFactoryLike(Protocol):
    """Spawns + handshakes one adapter child (FAKE in 2b-1; real launcher in G6-3).

    The real implementation (2b-2/G6-3) constructs a per-adapter
    :class:`CommsPluginRunner` + :class:`CommsStdioTransport` (share-in-place reuse)
    and runs ``start_and_handshake``. 2b-1's tests inject a fake. A spawn / handshake
    failure MUST raise :class:`GatewayAdapterSpawnError` (fail-closed) — never
    log-and-continue.
    """

    async def spawn_and_handshake(self, *, adapter_id: str, epoch: str) -> _AdapterChildLike: ...


class _CredSeamLike(Protocol):
    """The (FAKE, in 2b-1) credential gate consulted BEFORE a spawn.

    Real credential ``spawn_request`` / ``spawn_grant`` / fd-3 delivery is G6-3; 2b-1
    uses this stand-in. ``is_available`` False routes the machine to ``AWAITING_CORE``
    rather than spawning credential-less.
    """

    async def is_available(self, *, adapter_id: str) -> bool: ...


class _AdapterRun:
    """Per-adapter mutable supervision state (one spawn lifetime's worth)."""

    def __init__(self, adapter_id: str) -> None:
        self.adapter_id = adapter_id
        self.machine = AdapterLifecycleMachine()
        self.stop_event = asyncio.Event()
        self.cred_event = asyncio.Event()
        self.up_event = asyncio.Event()
        self.awaiting_core_event = asyncio.Event()
        self.breaker_open_event = asyncio.Event()
        # In-memory crash timestamps (monotonic) for the per-adapter breaker window.
        self.recent_crashes: deque[float] = deque()
        # The current exponential backoff base (doubles per crash, clamped).
        self.backoff_base = _INITIAL_BACKOFF_SECONDS
        self.restart_count = 0
        # The most recent process-exit ``(error_class, detail)`` awaiting the crash
        # arm's EMIT_CRASHED (set by :meth:`_await_exit_or_stop`).
        self.pending_crash: tuple[str, str] = ("AdapterChildExited", "")


class GatewayAdapterSupervisor:
    """Drives the per-adapter lifecycle machine: spawn/handshake/crash/backoff/breaker.

    Construct one per gateway process; :meth:`supervise_one` runs a single adapter to
    a terminal (DOWN / BREAKER_OPEN), :meth:`supervise_all` boots a fleet concurrently
    under a bounded ``TaskGroup``. Every lifecycle transition emits its
    ``gateway.adapter.*`` frame BY CONSTRUCTION (via :meth:`_apply`).
    """

    def __init__(
        self,
        *,
        child_factory: _AdapterChildFactoryLike,
        cred_seam: _CredSeamLike,
        emitter: AdapterStatusEmitter,
        epoch: str,
        sleep: Callable[[float], Coroutine[object, object, None]] = asyncio.sleep,
        rng: random.Random | None = None,
        monotonic: Callable[[], float] | None = None,
        max_concurrent_boots: int = _DEFAULT_MAX_CONCURRENT_BOOTS,
    ) -> None:
        self._factory = child_factory
        self._cred = cred_seam
        self._emitter = emitter
        self._epoch = epoch
        self._sleep = sleep
        # Decorrelated jitter: each adapter draws its backoff from its OWN seeded RNG
        # stream so two adapters that crash together do not redial in lockstep (spec
        # §4 anti-stampede). The default RNG is unseeded; jitter is NOT a security
        # primitive (no token/nonce derives from it), so the non-crypto PRNG is
        # correct (S311 would be a false positive on a CSPRNG demand).
        self._rng = rng if rng is not None else random.Random()  # noqa: S311
        self._monotonic = monotonic if monotonic is not None else _default_monotonic
        self._max_concurrent_boots = max_concurrent_boots
        self._runs: dict[str, _AdapterRun] = {}

    # ------------------------------------------------------------------
    # Test/observability synchronisation helpers
    # ------------------------------------------------------------------

    async def wait_until_up(self, adapter_id: str) -> None:
        """Await the adapter reaching the ``up`` state (test/observability helper)."""
        await self._run(adapter_id).up_event.wait()

    async def wait_until_awaiting_core(self, adapter_id: str) -> None:
        """Await the adapter parking in ``AWAITING_CORE`` (cred-down)."""
        await self._run(adapter_id).awaiting_core_event.wait()

    async def wait_until_breaker_open(self, adapter_id: str) -> None:
        """Await the per-adapter breaker tripping to ``BREAKER_OPEN``."""
        await self._run(adapter_id).breaker_open_event.wait()

    async def request_stop(self, adapter_id: str) -> None:
        """Request a planned/operator stop of one adapter (-> DOWN, EMIT_DOWN once)."""
        self._run(adapter_id).stop_event.set()

    def make_cred_available(self, adapter_id: str) -> None:
        """Signal a parked (AWAITING_CORE) adapter that its credential is back."""
        self._run(adapter_id).cred_event.set()

    def restart_count(self, adapter_id: str) -> int:
        return self._run(adapter_id).restart_count

    # ------------------------------------------------------------------
    # Supervision entry points
    # ------------------------------------------------------------------

    async def supervise_all(self, adapter_ids: list[str]) -> None:
        """Boot every adapter CONCURRENTLY under a bounded ``TaskGroup`` (Task 7).

        A bounded semaphore caps concurrent boots. One adapter's fail-closed
        :class:`GatewayAdapterSpawnError` does NOT stop the siblings — the
        ``TaskGroup`` aggregates the failure into an ``ExceptionGroup`` while the
        others still reach ``up``.
        """
        semaphore = asyncio.BoundedSemaphore(self._max_concurrent_boots)

        async def _bounded(adapter_id: str) -> None:
            async with semaphore:
                await self.supervise_one(adapter_id)

        async with asyncio.TaskGroup() as tg:
            for adapter_id in adapter_ids:
                tg.create_task(_bounded(adapter_id))

    async def supervise_one(self, adapter_id: str) -> None:
        """Run one adapter from spawn to a terminal (DOWN / BREAKER_OPEN).

        Raises :class:`GatewayAdapterSpawnError` fail-closed if the child factory
        refuses the spawn / handshake AND the breaker has not yet absorbed the failure
        into a restart cycle — the FIRST spawn failure surfaces loudly so a boot can
        refuse that adapter; later crash-loop failures route through the backoff /
        breaker arms (Task 5/6).
        """
        run = self._run(adapter_id)
        try:
            while True:
                # Cred gate BEFORE spawn — a cred-down parks in AWAITING_CORE.
                if not await self._cred.is_available(adapter_id=adapter_id):
                    await self._enter_awaiting_core(run)
                    if await self._wait_cred_or_stop(run):
                        break
                    continue

                child = await self._spawn_or_terminal(run)
                if child is None:
                    break  # the spawn failure tripped the breaker (terminal)

                # Reached UP.
                await self._enter_up(run)

                # Steady state: race the child's exit against a planned stop.
                if await self._await_exit_or_stop(run, child):
                    break  # planned stop -> DOWN

                # The child crashed -> backoff / breaker decision.
                if await self._handle_crash(run):
                    break  # breaker tripped -> BREAKER_OPEN (terminal)
                # else: backoff elapsed, loop to restart.
        finally:
            self._clear_transient_metrics(run)

    # ------------------------------------------------------------------
    # Lifecycle arms (each drives the machine via _apply, so emission is by
    # construction)
    # ------------------------------------------------------------------

    async def _spawn_or_terminal(self, run: _AdapterRun) -> _AdapterChildLike | None:
        """Spawn + handshake. Returns the child on success.

        On a :class:`GatewayAdapterSpawnError`: feed ``HANDSHAKE_FAILED`` (-> CRASHED,
        EMIT_CRASHED by construction), then run the same crash arm as a process exit.
        If the crash tripped the breaker, returns ``None`` (terminal). If this is the
        FIRST spawn attempt of the adapter (no prior crash), the error is re-raised
        fail-closed so a boot can refuse the adapter (Task 4).
        """
        run.machine.state = AdapterLifecycleState.SPAWNING
        await self._apply(run, AdapterLifecycleEvent.SPAWN_STARTED)  # -> HANDSHAKING
        ADAPTER_INFLIGHT.labels(adapter=run.adapter_id).set(1)
        try:
            child = await self._factory.spawn_and_handshake(
                adapter_id=run.adapter_id, epoch=self._epoch
            )
        except GatewayAdapterSpawnError as exc:
            ADAPTER_INFLIGHT.labels(adapter=run.adapter_id).set(0)
            first_attempt = run.restart_count == 0 and not run.recent_crashes
            await self._apply(
                run,
                AdapterLifecycleEvent.HANDSHAKE_FAILED,
                error_class=type(exc).__name__,
                detail=str(exc),
            )  # -> CRASHED, EMIT_CRASHED
            if first_attempt:
                # Fail-closed: the very first spawn failed; surface it so the boot can
                # refuse this adapter (never log-and-continue). Record nothing toward
                # the breaker — the boot is aborting this adapter.
                raise
            if await self._handle_crash(run):
                return None  # breaker tripped
            return await self._spawn_or_terminal(run)  # backoff elapsed -> retry
        ADAPTER_INFLIGHT.labels(adapter=run.adapter_id).set(0)
        return child

    async def _enter_up(self, run: _AdapterRun) -> None:
        await self._apply(run, AdapterLifecycleEvent.HANDSHAKE_OK)  # -> UP, EMIT_UP
        run.up_event.set()
        run.awaiting_core_event.clear()
        # A fresh, healthy incarnation: reset the backoff ramp.
        run.backoff_base = _INITIAL_BACKOFF_SECONDS

    async def _enter_awaiting_core(self, run: _AdapterRun) -> None:
        run.machine.state = AdapterLifecycleState.RESTARTING
        await self._apply(run, AdapterLifecycleEvent.CRED_UNAVAILABLE)  # -> AWAITING_CORE
        ADAPTER_AWAITING_CORE.labels(adapter=run.adapter_id).set(1)
        run.awaiting_core_event.set()

    async def _await_exit_or_stop(self, run: _AdapterRun, child: _AdapterChildLike) -> bool:
        """Race the child's process exit against a planned stop.

        Returns True if a stop won (-> DOWN, terminal); False if the child exited
        (caller runs the crash arm). The crash ``(error_class, detail)`` is stashed on
        the run for :meth:`_handle_crash` to emit.
        """
        exit_task = asyncio.ensure_future(child.wait_until_exit())
        stop_task = asyncio.ensure_future(run.stop_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {exit_task, stop_task}, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            exit_task.cancel()
            stop_task.cancel()
            raise
        if stop_task in done:
            exit_task.cancel()
            await self._stop(run)
            return True
        stop_task.cancel()
        run.pending_crash = exit_task.result()
        return False

    async def _stop(self, run: _AdapterRun) -> None:
        ADAPTER_UP.labels(adapter=run.adapter_id).set(0)
        run.up_event.clear()
        await self._apply(
            run, AdapterLifecycleEvent.STOP_REQUESTED, reason="operator"
        )  # -> DOWN, EMIT_DOWN

    async def _handle_crash(self, run: _AdapterRun) -> bool:
        """Run the crash arm: emit crashed, then breaker-or-backoff decision.

        Returns True if the breaker tripped (-> BREAKER_OPEN, terminal); False if a
        backoff was scheduled (caller loops to restart). The ``crashed`` frame is
        emitted by the CHILD_EXITED transition unless the crash already arrived via a
        HANDSHAKE_FAILED (which emitted it). This method handles the process-exit case.
        """
        error_class, detail = run.pending_crash
        if run.machine.state is AdapterLifecycleState.UP:
            ADAPTER_UP.labels(adapter=run.adapter_id).set(0)
            run.up_event.clear()
            await self._apply(
                run,
                AdapterLifecycleEvent.CHILD_EXITED,
                error_class=error_class,
                detail=detail,
            )  # -> CRASHED, EMIT_CRASHED
        # Record the crash toward the per-adapter breaker window.
        now = self._monotonic()
        cutoff = now - _BREAKER_WINDOW_SECONDS
        while run.recent_crashes and run.recent_crashes[0] <= cutoff:
            run.recent_crashes.popleft()
        run.recent_crashes.append(now)

        if len(run.recent_crashes) >= _BREAKER_FAILURE_THRESHOLD:
            await self._trip_breaker(run)
            return True

        # Schedule a bounded decorrelated-jitter restart.
        delay = self._next_backoff(run)
        run.restart_count += 1
        ADAPTER_RESTARTS.labels(adapter=run.adapter_id).inc()
        await self._sleep(delay)
        run.machine.state = AdapterLifecycleState.CRASHED
        await self._apply(run, AdapterLifecycleEvent.BACKOFF_ELAPSED)  # -> RESTARTING
        return False

    async def _trip_breaker(self, run: _AdapterRun) -> None:
        retry_after = int(min(run.backoff_base, _MAX_BACKOFF_SECONDS))
        run.machine.state = AdapterLifecycleState.CRASHED
        await self._apply(
            run,
            AdapterLifecycleEvent.BREAKER_TRIPPED,
            retry_after_seconds=retry_after,
        )  # -> BREAKER_OPEN, EMIT_BREAKER_OPEN
        ADAPTER_BREAKER_OPEN.labels(adapter=run.adapter_id).set(1)
        ADAPTER_UP.labels(adapter=run.adapter_id).set(0)
        run.breaker_open_event.set()
        log.warning(
            "gateway.adapter.breaker_open",
            adapter_id=run.adapter_id,
            restart_count=run.restart_count,
        )

    async def _wait_cred_or_stop(self, run: _AdapterRun) -> bool:
        """Park in AWAITING_CORE until cred returns or a stop arrives.

        Returns True if a stop won (-> DOWN, terminal); False if the cred came back
        (caller loops to retry the spawn). On cred-return, feed ``CRED_AVAILABLE``.
        """
        cred_task = asyncio.ensure_future(run.cred_event.wait())
        stop_task = asyncio.ensure_future(run.stop_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {cred_task, stop_task}, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            cred_task.cancel()
            stop_task.cancel()
            raise
        if stop_task in done:
            cred_task.cancel()
            ADAPTER_AWAITING_CORE.labels(adapter=run.adapter_id).set(0)
            run.awaiting_core_event.clear()
            await self._stop(run)
            return True
        stop_task.cancel()
        run.cred_event.clear()
        ADAPTER_AWAITING_CORE.labels(adapter=run.adapter_id).set(0)
        run.awaiting_core_event.clear()
        await self._apply(run, AdapterLifecycleEvent.CRED_AVAILABLE)  # -> RESTARTING
        return False

    # ------------------------------------------------------------------
    # The single transition applicator — emission BY CONSTRUCTION (correction #2)
    # ------------------------------------------------------------------

    async def _apply(
        self,
        run: _AdapterRun,
        event: AdapterLifecycleEvent,
        *,
        error_class: str = "",
        detail: str = "",
        reason: str = "operator",
        retry_after_seconds: int = 0,
    ) -> None:
        """Feed ``event`` to the machine and EMIT the resulting frame inseparably.

        This is the ONLY place the machine is fed, so every lifecycle transition that
        emits a control ALSO emits its ``gateway.adapter.*`` frame — emission is
        non-skippable by construction (Spec B §6 / correction #2), not an optional
        call a future edit could drop. The control->frame mapping (correction #6):
        EMIT_UP -> up(epoch); EMIT_DOWN -> down(reason); EMIT_CRASHED ->
        crashed(error_class, redacted detail); EMIT_BREAKER_OPEN ->
        breaker_open(retry_after_seconds).
        """
        control = run.machine.feed(event)
        if control is None:
            return
        adapter_id = run.adapter_id
        match control:
            case AdapterControl.EMIT_UP:
                await self._emitter.emit_up(adapter_id=adapter_id, epoch=self._epoch)
                ADAPTER_UP.labels(adapter=adapter_id).set(1)
            case AdapterControl.EMIT_DOWN:
                await self._emitter.emit_down(adapter_id=adapter_id, reason=_down_reason(reason))
            case AdapterControl.EMIT_CRASHED:
                await self._emitter.emit_crashed(
                    adapter_id=adapter_id,
                    error_class=error_class or "AdapterChildExited",
                    detail=detail,
                )
            case AdapterControl.EMIT_BREAKER_OPEN:
                await self._emitter.emit_breaker_open(
                    adapter_id=adapter_id, retry_after_seconds=retry_after_seconds
                )

    # ------------------------------------------------------------------
    # Backoff + bookkeeping
    # ------------------------------------------------------------------

    def _next_backoff(self, run: _AdapterRun) -> float:
        """A decorrelated-jitter backoff for this adapter, clamped to the window.

        Full jitter: draw uniformly in ``[0, base]`` from the adapter's OWN RNG stream
        (independent draws => no stampede), then CLAMP to
        ``[_MIN_BACKOFF_SECONDS, _MAX_BACKOFF_SECONDS]`` so a 0 / negative / oversized
        draw can never tight-spin or stall (mirrors core_link.py). The base doubles per
        crash up to the cap.
        """
        raw = self._rng.uniform(0.0, run.backoff_base)
        clamped = max(_MIN_BACKOFF_SECONDS, min(raw, _MAX_BACKOFF_SECONDS))
        run.backoff_base = min(run.backoff_base * _BACKOFF_FACTOR, _MAX_BACKOFF_SECONDS)
        return clamped

    def _clear_transient_metrics(self, run: _AdapterRun) -> None:
        """Zero the transient gauges on a terminal exit (inflight/awaiting_core)."""
        ADAPTER_INFLIGHT.labels(adapter=run.adapter_id).set(0)
        ADAPTER_AWAITING_CORE.labels(adapter=run.adapter_id).set(0)

    def _run(self, adapter_id: str) -> _AdapterRun:
        run = self._runs.get(adapter_id)
        if run is None:
            run = _AdapterRun(adapter_id)
            self._runs[adapter_id] = run
        return run


def _down_reason(reason: str) -> AdapterDownReason:
    """Coerce a stop reason to the closed AdapterDownReason vocabulary.

    The model validates the literal; an unexpected reason defaults to ``operator``
    (the planned-stop default) so a programming slip surfaces as the wrong-but-valid
    reason rather than a producer ValidationError that would mask the stop.
    """
    match reason:
        case "operator" | "supervisor" | "config_reload" | "shutdown":
            return reason
        case _:
            return "operator"


def _default_monotonic() -> float:
    import time

    return time.monotonic()


__all__ = [
    "GatewayAdapterSpawnError",
    "GatewayAdapterSupervisor",
]
