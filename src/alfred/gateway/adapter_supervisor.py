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
  backoff (one shared RNG, distinct consecutive draws => no stampede — spec §4
  ``[fleet perf-004]``);
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
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Final, Protocol

import structlog

from alfred.comms_mcp.adapter_credential_resolver import AdapterCredentialError
from alfred.comms_mcp.protocol import AdapterDownReason
from alfred.errors import AlfredError
from alfred.gateway.adapter_lifecycle import (
    AdapterControl,
    AdapterLifecycleEvent,
    AdapterLifecycleMachine,
    AdapterLifecycleState,
    AdapterLifecycleStateError,
)
from alfred.gateway.adapter_metrics import (
    ADAPTER_AWAITING_CORE,
    ADAPTER_BREAKER_OPEN,
    ADAPTER_INFLIGHT,
    ADAPTER_RESTARTS,
    ADAPTER_UP,
)
from alfred.gateway.core_link import CredentialLegDownError

if TYPE_CHECKING:
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

# Awaiting-core terminal ceiling (G6-3 / Task 4): the number of consecutive non-spin
# bounded-backoff re-probes the supervisor will wait for the credential leg to recover
# before declaring the adapter DURABLY down (tripping the breaker — the distinct loud
# terminal alert, NEVER a silent forever-park). The re-probe is non-spin (each wait is
# a bounded backoff), so the ceiling bounds the dark window, not the probe rate. An
# explicit cred-event signal (an operator/test re-arm) short-circuits the wait.
_AWAITING_CORE_CEILING: Final[int] = 12


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


class GatewayAdapterCredentialError(GatewayAdapterSpawnError):
    """A first-attempt OPERATOR-CREDENTIAL spawn refusal (missing/mismatched/undeliverable
    secret) — distinct from a bare GatewayAdapterSpawnError (a launcher/handshake fault or a
    programming bug), which stays loud. start_gateway catches ONLY this subclass to render a
    friendly, actionable refusal (#469 [R1]); the base type keeps surfacing as a raw
    traceback so hard rule #7 holds. Carries the closed-vocab credential ``reason``."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class _AdapterChildLike(Protocol):
    """A spawned + handshaked adapter child whose process exit the supervisor awaits."""

    async def wait_until_exit(self) -> tuple[str, str]:
        """Block until the child process exits; return ``(error_class, detail)``.

        The detail is redacted at the emitter (REDACT-then-bound), never here.
        """
        ...

    async def aclose(self) -> None:
        """Terminate + reap the child (H1, Spec B G6-5 / #288).

        The supervisor calls this on the crash/restart AND planned-stop paths so a
        still-live sandbox child is terminate-and-reaped BEFORE a restart spawns a new
        one and on shutdown — never leaked across a crash-loop. Idempotent (a second
        call is a no-op). The real :class:`alfred.gateway.adapter_child_factory.
        _GatewayAdapterChild` SIGTERMs the bwrap Popen + closes the transport here.
        """
        ...


# The credential-delivery callback the supervisor hands the factory (G6-3 / Task 5a).
# The factory invokes it with the child's fd-3 WRITE END at the right moment in the
# spawn — AFTER the synchronous fd-3-clobber window has closed, BEFORE the handshake
# (the child blocks on ``os.read(3)`` until the credential arrives). The callback runs
# the ``spawn_request -> spawn_grant`` round-trip + the atomic ``writev`` delivery
# (which closes the write end itself). A failure raises loud (the factory lets it
# propagate as a spawn failure — fail-closed, no child without its credential).
_DeliverCredential = Callable[[int], Awaitable[None]]


class _AdapterChildFactoryLike(Protocol):
    """Spawns + handshakes one adapter child, delivering the credential over fd 3 (G6-3).

    The real implementation (G6-3 / Task 9) constructs a per-adapter
    :class:`CommsPluginRunner` + :class:`CommsStdioTransport`, OWNS the fd-3 pipe
    (``os.pipe()`` — read-end onto the child's literal fd 3, write-end handed to
    ``deliver_credential``), spawns SYNCHRONOUSLY inside the dup2->Popen->restore
    window (the "no ``await`` while fd 3 is clobbered" discipline — see
    :mod:`alfred.security.quarantine_child_io`), then invokes ``deliver_credential``
    with the write end (after the window closes, before the handshake). 2b-1's tests
    inject a fake. A spawn / handshake failure MUST raise
    :class:`GatewayAdapterSpawnError` (fail-closed) — never log-and-continue.

    ``deliver_credential`` is the supervisor's at-spawn credential hook (Task 5b): the
    factory MUST call it (with the fd-3 write end) on the success path so the child
    receives its credential out-of-band; a raise from it aborts the spawn.

    **G6-5 implementer contract — do NOT wrap the credential exceptions.** A
    :class:`alfred.gateway.core_link.CredentialLegDownError` or an
    :class:`alfred.comms_mcp.adapter_credential_resolver.AdapterCredentialError` raised
    by ``deliver_credential`` MUST propagate UNWRAPPED out of ``spawn_and_handshake``.
    The supervisor's spawn arm (:meth:`_spawn_one`) catches each distinctly:
    ``CredentialLegDownError`` parks the machine in AWAITING_CORE (a down leg is NOT a
    crash), while ``AdapterCredentialError`` joins the crash/breaker arm with a distinct
    spawn-aborted audit row. Re-wrapping either as ``GatewayAdapterSpawnError`` would
    DEFEAT the AWAITING_CORE arm (a leg-down would crash-loop a dead leg) — so wrap ONLY
    a genuine spawn/handshake fault, never the credential exceptions.
    """

    async def spawn_and_handshake(
        self, *, adapter_id: str, epoch: str, deliver_credential: _DeliverCredential
    ) -> _AdapterChildLike: ...


class _CredSeamLike(Protocol):
    """The CHEAP pre-spawn credential-availability probe (correction H2 part i).

    A LOCAL link-state liveness check — NOT a full ``spawn_request`` + core decrypt
    (that would be wasteful + a minor harvest-amplification surface). The real
    implementation reads ``GatewayCoreLink.current_core_epoch() is not None`` (the leg
    is up + handshaked). ``is_available`` False routes the machine to ``AWAITING_CORE``
    rather than spawning toward a down leg; the actual credential is acquired at spawn
    time by the :class:`_DeliverCredential` hook (Task 5b).
    """

    async def is_available(self, *, adapter_id: str) -> bool: ...


class _CredentialClientLike(Protocol):
    """The at-spawn credential acquirer the supervisor drives (G6-3 / Task 5b).

    Satisfied by :class:`alfred.gateway.adapter_credential_client.GatewayAdapterCredentialClient`.
    ``acquire_and_deliver`` runs the ``spawn_request -> spawn_grant`` round-trip over
    the core leg, verifies the grant, and delivers the credential to ``write_fd`` (the
    child's fd-3 write end). It raises ``CredentialLegDownError`` on a down leg (the
    supervisor routes to AWAITING_CORE) and ``AdapterCredentialError`` on a refusal /
    delivery fault (fail-closed spawn abort). It closes ``write_fd`` on every path.
    """

    async def acquire_and_deliver(
        self, *, adapter_id: str, host_restart_seq: int, write_fd: int, epoch: str
    ) -> None: ...


class _AdapterRun:
    """Per-adapter mutable supervision state (one spawn lifetime's worth)."""

    def __init__(self, adapter_id: str) -> None:
        self.adapter_id = adapter_id
        self.machine = AdapterLifecycleMachine()
        self.stop_event = asyncio.Event()
        self.cred_event = asyncio.Event()
        self.awaiting_core_event = asyncio.Event()
        self.breaker_open_event = asyncio.Event()
        # Incarnation-aware UP signalling: ``up_incarnation`` counts how many times the
        # adapter has reached the serving state (one per spawn that handshakes OK).
        # ``up_cond`` lets an observer await a SPECIFIC incarnation (e.g. "the 2nd up,
        # after the 1st crashed") without racing a still-set one-shot event.
        self.up_cond = asyncio.Condition()
        self.up_incarnation = 0
        self.is_up = False
        # In-memory crash timestamps (monotonic) for the per-adapter breaker window.
        self.recent_crashes: deque[float] = deque()
        # The current exponential backoff base (doubles per crash, clamped).
        self.backoff_base = _INITIAL_BACKOFF_SECONDS
        self.restart_count = 0
        # The most recent process-exit ``(error_class, detail)`` awaiting the crash
        # arm's EMIT_CRASHED (set by :meth:`_await_exit_or_stop`).
        self.pending_crash: tuple[str, str] = ("AdapterChildExited", "")
        # H1 (G6-3 / #288): the epoch this incarnation was SPAWNED under, captured live
        # in ``_spawn_or_terminal`` and stamped onto the ``up`` frame so a core bounce
        # mid-life cannot make the ``up`` epoch drift from the spawn/grant epoch. ``None``
        # before the first spawn (no ``up`` is emitted then).
        self.spawn_epoch: str | None = None


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
        credential_client: _CredentialClientLike,
        emitter: AdapterStatusEmitter,
        epoch_source: Callable[[], str | None],
        # ``Awaitable`` (not the narrower ``Coroutine``): the supervisor only ``await``s
        # the result, so any awaitable-returning sleep seam (the production
        # ``asyncio.sleep``, a test's plain ``async def`` fake, or ``GatewayProcess._sleep``)
        # satisfies it without a call-site ``type: ignore``.
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: random.Random | None = None,
        monotonic: Callable[[], float] | None = None,
        max_concurrent_boots: int = _DEFAULT_MAX_CONCURRENT_BOOTS,
    ) -> None:
        if max_concurrent_boots < 1:
            # A 0 / negative cap makes the boot semaphore in supervise_all
            # unacquirable -> the whole fleet boot hangs forever (a silent
            # deadlock). Fail loud at construction (CLAUDE.md hard rule #7).
            raise ValueError(f"max_concurrent_boots must be >= 1, got {max_concurrent_boots!r}")
        self._factory = child_factory
        self._cred = cred_seam
        # G6-3 (#288): the real credential acquirer. The supervisor hands the factory a
        # ``deliver_credential`` closure that runs ``acquire_and_deliver`` over the fd-3
        # write end the factory creates. A ``CredentialLegDownError`` from it routes the
        # adapter to AWAITING_CORE (Task 4); any other AdapterCredentialError aborts the
        # spawn fail-closed.
        self._credential_client = credential_client
        self._emitter = emitter
        # H1 (correction): the epoch is sourced LIVE at spawn time from the core link,
        # NOT a construction-time snapshot — a core bounce mints a new epoch, and a
        # stale snapshot would either DoS every spawn (refused epoch) or accept a
        # wrong-epoch grant. ``None`` means the leg is not yet handshaked (link-down).
        self._epoch_source = epoch_source
        self._sleep = sleep
        # Decorrelated jitter: every adapter draws its backoff from this ONE shared RNG
        # stream. The anti-stampede property does NOT require a per-adapter stream — it
        # comes from each draw being an independent sample: two adapters that crash
        # together take CONSECUTIVE draws from the shared sequence, which are distinct,
        # so they do not redial in lockstep (spec §4 anti-stampede). The default RNG is
        # unseeded; jitter is NOT a security primitive (no token/nonce derives from it),
        # so the non-crypto PRNG is correct (S311 would be a false positive on a CSPRNG
        # demand).
        self._rng = rng if rng is not None else random.Random()  # noqa: S311
        self._monotonic = monotonic if monotonic is not None else _default_monotonic
        self._max_concurrent_boots = max_concurrent_boots
        self._runs: dict[str, _AdapterRun] = {}

    # ------------------------------------------------------------------
    # Test/observability synchronisation helpers
    # ------------------------------------------------------------------

    async def wait_until_up(self, adapter_id: str, *, incarnation: int = 1) -> None:
        """Await the adapter reaching its ``incarnation``-th ``up`` state.

        ``incarnation=1`` is the first serving state; ``incarnation=2`` is the up
        after the first crash+restart, and so on. Count-based (not a one-shot event)
        so an observer can await "the up AFTER the crash" without racing a stale set.
        """
        run = self._run(adapter_id)
        async with run.up_cond:
            await run.up_cond.wait_for(lambda: run.up_incarnation >= incarnation)

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
                # STOP gate BEFORE any (re)spawn (Spec B §6: STOP_REQUESTED is
                # honoured in EVERY live state, not only UP / AWAITING_CORE). A stop
                # that landed during a crash backoff (CRASHED / RESTARTING) must
                # short-circuit to the terminal ``down`` here, NOT let the loop spin
                # back round and bring the adapter up again (which would emit a
                # spurious ``up`` after a stop was requested).
                if run.stop_event.is_set():
                    await self._stop(run)
                    break
                # CHEAP pre-spawn liveness probe (correction H2 part i): a LOCAL
                # link-state check (the leg is up + handshaked), NOT a full spawn_request
                # + core decrypt. A cred-down parks in AWAITING_CORE.
                if not await self._cred.is_available(adapter_id=adapter_id):
                    await self._enter_awaiting_core(run)
                    if await self._wait_cred_or_stop(run):
                        break
                    continue

                try:
                    child = await self._spawn_or_terminal(run)
                except CredentialLegDownError:
                    # The leg dropped DURING the at-spawn credential round-trip (Task 4):
                    # NOT a crash. Park in AWAITING_CORE (non-spin bounded wait) instead
                    # of crash-looping a dead leg — loud + audited inside.
                    await self._enter_awaiting_core(run, reason="credential_leg_down")
                    if await self._wait_cred_or_stop(run):
                        break
                    continue
                if child is None:
                    break  # the spawn failure tripped the breaker (terminal)

                # Reached UP.
                await self._enter_up(run)

                # Steady state: race the child's exit against a planned stop.
                if await self._await_exit_or_stop(run, child):
                    break  # planned stop -> DOWN (the live child reaped inside)

                # H1 (Spec B G6-5 / #288): the child exited (crash). Terminate-and-reap it
                # BEFORE the restart spawns a new one — a sandbox child that exited its main
                # loop can leave a live bwrap wrapper, so reap on the restart path too.
                await self._reap_child(run, child)

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
        # H1 (correction): source the epoch LIVE per spawn — a core bounce mints a new
        # epoch and a stale construction-time snapshot would DoS every spawn (refused
        # epoch) or accept a wrong-epoch grant. ``None`` means the leg is not handshaked
        # yet (link-down) — route to AWAITING_CORE, never spawn against a dead leg.
        epoch = self._epoch_source()
        if epoch is None:
            raise CredentialLegDownError(
                f"core leg has no epoch; cannot spawn (adapter_id={run.adapter_id!r})"
            )
        # Stamp the spawn epoch so the eventual ``up`` frame carries the SAME epoch the
        # credential grant was bound to (H1) — not a later-bounced core's epoch.
        run.spawn_epoch = epoch
        run.machine.state = AdapterLifecycleState.SPAWNING
        await self._apply(run, AdapterLifecycleEvent.SPAWN_STARTED)  # -> HANDSHAKING
        ADAPTER_INFLIGHT.labels(adapter=run.adapter_id).set(1)
        # The at-spawn credential delivery hook (Task 5b): the factory invokes this with
        # the child's fd-3 write end (after the sync spawn window closes, before the
        # handshake). It runs the round-trip + the atomic writev (which closes the write
        # end). A ``CredentialLegDownError`` propagates so this method routes to
        # AWAITING_CORE; an ``AdapterCredentialError`` (refusal / delivery fault) is a
        # fail-closed spawn abort. The epoch + host_restart_seq are captured per spawn.
        host_restart_seq = run.restart_count

        async def _deliver(write_fd: int) -> None:
            await self._credential_client.acquire_and_deliver(
                adapter_id=run.adapter_id,
                host_restart_seq=host_restart_seq,
                write_fd=write_fd,
                epoch=epoch,
            )

        try:
            child = await self._factory.spawn_and_handshake(
                adapter_id=run.adapter_id, epoch=epoch, deliver_credential=_deliver
            )
        except CredentialLegDownError:
            # Link-down during the credential round-trip: NOT a crash. Roll back the
            # in-flight gauge + machine to RESTARTING and re-raise so ``supervise_one``
            # parks in AWAITING_CORE (Task 4) rather than crash-looping a dead leg.
            ADAPTER_INFLIGHT.labels(adapter=run.adapter_id).set(0)
            run.machine.state = AdapterLifecycleState.RESTARTING
            raise
        except (GatewayAdapterSpawnError, AdapterCredentialError) as exc:
            # A fail-closed spawn / credential abort (launcher fail, grant refusal /
            # mismatch, fd-3 fault): NEVER log-and-continue. A credential abort ALSO
            # emits the distinct spawn-aborted audit row before joining the shared crash
            # arm, so the breaker/backoff applies on a persistent credential failure
            # exactly as on a launcher crash-loop.
            ADAPTER_INFLIGHT.labels(adapter=run.adapter_id).set(0)
            if isinstance(exc, AdapterCredentialError):
                # The distinct fail-closed spawn-abort audit row (closed-vocab reason).
                # The credential is structurally absent from the row (maintainer C1). The
                # error is WRAPPED as GatewayAdapterSpawnError (L1 hierarchy) so the
                # supervisor's existing crash/breaker arm + the boot-refusal re-raise
                # treat it uniformly with a launcher spawn failure. The audit row carries
                # the error's DISTINCT closed-vocab reason (grant_mismatch / delivery_failed
                # / missing_secret / ...) — the G6-3 failure-path contract — never collapsed
                # to the generic ``credential_refused``.
                await self._audit_spawn_aborted(run, reason=exc.reason)
                spawn_error: GatewayAdapterSpawnError = GatewayAdapterCredentialError(
                    f"credential pipeline aborted the spawn (adapter_id={run.adapter_id!r}, "
                    f"reason={exc.reason!r})",
                    reason=exc.reason,
                )
            else:
                spawn_error = exc
            first_attempt = run.restart_count == 0 and not run.recent_crashes
            await self._apply(
                run,
                AdapterLifecycleEvent.HANDSHAKE_FAILED,
                error_class=type(spawn_error).__name__,
                detail=str(spawn_error),
            )  # -> CRASHED, EMIT_CRASHED
            if first_attempt:
                # Fail-closed: the very first spawn failed; surface it so the boot can
                # refuse this adapter (never log-and-continue). Record nothing toward
                # the breaker — the boot is aborting this adapter. A credential abort is
                # raised as GatewayAdapterSpawnError ``from`` the original so the cause
                # chain is preserved while the boot sees one uniform spawn-failure type.
                if spawn_error is exc:
                    raise
                raise spawn_error from exc
            if await self._handle_crash(run):
                return None  # breaker tripped
            if run.stop_event.is_set():
                # A stop landed during the spawn-fail backoff (Spec B §6): emit the
                # terminal ``down`` here instead of recursing into another re-spawn.
                # Returning None makes supervise_one take its terminal break (the
                # ``down`` is already on the wire, exactly once).
                await self._stop(run)
                return None
            return await self._spawn_or_terminal(run)  # backoff elapsed -> retry
        ADAPTER_INFLIGHT.labels(adapter=run.adapter_id).set(0)
        return child

    async def _enter_up(self, run: _AdapterRun) -> None:
        await self._apply(run, AdapterLifecycleEvent.HANDSHAKE_OK)  # -> UP, EMIT_UP
        async with run.up_cond:
            run.up_incarnation += 1
            run.is_up = True
            run.up_cond.notify_all()
        run.awaiting_core_event.clear()
        # A fresh, healthy incarnation: reset the backoff ramp.
        run.backoff_base = _INITIAL_BACKOFF_SECONDS

    async def _enter_awaiting_core(
        self, run: _AdapterRun, *, reason: str = "credential_unavailable"
    ) -> None:
        run.machine.state = AdapterLifecycleState.RESTARTING
        await self._apply(run, AdapterLifecycleEvent.CRED_UNAVAILABLE)  # -> AWAITING_CORE
        ADAPTER_AWAITING_CORE.labels(adapter=run.adapter_id).set(1)
        run.awaiting_core_event.set()
        self._audit_awaiting_core(run, reason=reason)

    def _audit_awaiting_core(self, run: _AdapterRun, *, reason: str) -> None:
        """Write the honest gateway-side awaiting-core audit row (Task 4).

        The gateway holds NO signing key (the comms-adapter contract: stateless
        beyond a connection buffer), so its audit is a LOUD structlog row keyed on
        ``GATEWAY_ADAPTER_AWAITING_CORE_FIELDS`` (mirrors ``core_link``'s honest
        back-pressure audit). The signed-log reconcile into the CORE log over the
        status leg is a tracked ADR-0036 follow-up. No credential is in the row.
        """
        log.warning(
            "gateway.adapter.awaiting_core",
            adapter_id=run.adapter_id,
            host_restart_seq=run.restart_count,
            reason=reason,
        )

    async def _audit_spawn_aborted(self, run: _AdapterRun, *, reason: str) -> None:
        """Write the honest gateway-side fail-closed spawn-abort audit row (Task 5b).

        A distinct LOUD row for a credential-pipeline spawn abort (grant refusal /
        mismatch / fd-3 fault) — keyed on ``GATEWAY_ADAPTER_SPAWN_ABORTED_FIELDS``,
        closed-vocab ``reason``, NO credential (maintainer C1). Same gateway-has-no-DB
        honest-structlog posture as :meth:`_audit_awaiting_core`.
        """
        log.warning(
            "gateway.adapter.spawn_aborted",
            adapter_id=run.adapter_id,
            host_restart_seq=run.restart_count,
            reason=reason,
        )

    async def _await_exit_or_stop(self, run: _AdapterRun, child: _AdapterChildLike) -> bool:
        """Race the child's process exit against a planned stop.

        Returns True if a stop won (-> DOWN, terminal); False if the child exited
        (caller runs the crash arm). The crash ``(error_class, detail)`` is stashed on
        the run for :meth:`_handle_crash` to emit.

        H1 (Spec B G6-5 / #288): process shutdown CANCELS the supervisor task DIRECTLY
        (distinct from a crash or ``request_stop`` — those reap on their own arms). The
        steady-state UP wait is where that cancellation lands, so the cancellation unwind
        MUST terminate-and-reap the LIVE child before re-raising — else a still-running
        bwrap child leaks on shutdown (CLAUDE.md hard rule #7 — no leaked sandbox child).
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
            # Reap the LIVE child on the shutdown-cancellation path. ``_reap_child`` is
            # best-effort + fail-loud (it never raises) and its ``aclose`` ->
            # ``run_in_executor`` reap is cancellation-resilient, so the cleanup completes
            # before the ``CancelledError`` propagates — no leaked sandbox child.
            await self._reap_child(run, child)
            raise
        if stop_task in done:
            exit_task.cancel()
            # H1 (Spec B G6-5 / #288): a planned stop reaps the LIVE child (it may still be
            # running — the stop won the race, the child never exited). Reap before the
            # terminal ``down`` so a bwrap child is not leaked on shutdown.
            await self._reap_child(run, child)
            await self._stop(run)
            return True
        stop_task.cancel()
        run.pending_crash = exit_task.result()
        return False

    async def _reap_child(self, run: _AdapterRun, child: _AdapterChildLike) -> None:
        """Terminate + reap a child on the crash/restart/stop path (H1, fail-loud).

        The supervisor cancels :meth:`_AdapterChildLike.wait_until_exit` on a stop /
        re-spawn, but cancelling the wait does NOT terminate the underlying sandbox
        process — without this, a still-live bwrap child leaks across a crash-loop or
        shutdown (the flagged H1 gap). :meth:`_AdapterChildLike.aclose` is idempotent.

        Best-effort + fail-LOUD (CLAUDE.md hard rule #7): a reap fault is logged on the
        distinct ``gateway.adapter.reap_failed`` row at ERROR — a failed reap means a
        possibly-LEAKED sandbox (bwrap) child, which is operator-actionable, NOT routine
        back-pressure — then absorbed so a single bad reap cannot wedge the restart loop
        (which would leave the adapter dark forever) nor block shutdown.
        """
        try:
            await child.aclose()
        except Exception as exc:
            log.error(
                "gateway.adapter.reap_failed",
                adapter_id=run.adapter_id,
                error_class=type(exc).__name__,
            )

    async def _stop(self, run: _AdapterRun) -> None:
        ADAPTER_UP.labels(adapter=run.adapter_id).set(0)
        run.is_up = False
        # 2b-1 only ever stops an adapter via an operator/planned request; the broader
        # AdapterDownReason vocabulary (supervisor / config_reload / shutdown) arrives
        # in 2b-2, at which point _stop will take the reason as a parameter.
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
            run.is_up = False
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
        """Park in AWAITING_CORE with a non-spin bounded re-probe + terminal ceiling.

        The await-core wait (Task 4): NON-spin (each iteration is a bounded backoff
        sleep racing the stop/cred events), bounded (re-probes the cheap link-state
        availability after each backoff), and TERMINAL-CEILINGED — after
        :data:`_AWAITING_CORE_CEILING` consecutive failed re-probes the adapter is
        declared DURABLY down via the breaker (the distinct loud terminal alert, NEVER a
        silent forever-park — spec §6(c) no-quiet-dark, CLAUDE.md hard rule #7).

        Returns True if the wait ended TERMINALLY (a stop -> DOWN, or the ceiling ->
        BREAKER_OPEN) so ``supervise_one`` breaks; False if the leg recovered (caller
        loops to retry the spawn), feeding ``CRED_AVAILABLE``. An explicit ``cred_event``
        (operator/test re-arm) short-circuits a backoff wait.
        """
        for _attempt in range(_AWAITING_CORE_CEILING):
            stopped = await self._await_core_backoff_or_stop(run)
            if stopped:
                ADAPTER_AWAITING_CORE.labels(adapter=run.adapter_id).set(0)
                run.awaiting_core_event.clear()
                await self._stop(run)
                return True
            # Re-probe the cheap link-state liveness after the bounded wait. The leg back
            # up -> resume the spawn; still down -> loop (counting toward the ceiling).
            if run.cred_event.is_set() or await self._cred.is_available(adapter_id=run.adapter_id):
                run.cred_event.clear()
                ADAPTER_AWAITING_CORE.labels(adapter=run.adapter_id).set(0)
                run.awaiting_core_event.clear()
                await self._apply(run, AdapterLifecycleEvent.CRED_AVAILABLE)  # -> RESTARTING
                return False
            self._audit_awaiting_core(run, reason="awaiting_core_reprobe")
        # Ceiling exceeded: the leg never came back. Declare the adapter durably down via
        # the breaker (the distinct terminal alert) rather than park dark forever.
        ADAPTER_AWAITING_CORE.labels(adapter=run.adapter_id).set(0)
        run.awaiting_core_event.clear()
        log.warning(
            "gateway.adapter.awaiting_core_ceiling_exceeded",
            adapter_id=run.adapter_id,
            ceiling=_AWAITING_CORE_CEILING,
        )
        await self._trip_breaker(run)
        return True

    async def _await_core_backoff_or_stop(self, run: _AdapterRun) -> bool:
        """One non-spin awaiting-core wait: a bounded backoff racing stop/cred.

        Returns True iff a stop won (the caller takes the terminal DOWN). The sleep is
        a bounded decorrelated-jitter backoff (the same ramp the crash arm uses) so the
        re-probe is non-spin; an explicit ``cred_event`` or ``stop_event`` ends the wait
        early. The losing tasks are cancelled so neither leaks.
        """
        delay = self._next_backoff(run)
        sleep_task = asyncio.ensure_future(self._sleep(delay))
        cred_task = asyncio.ensure_future(run.cred_event.wait())
        stop_task = asyncio.ensure_future(run.stop_event.wait())
        try:
            await asyncio.wait(
                {sleep_task, cred_task, stop_task}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for task in (sleep_task, cred_task, stop_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(sleep_task, cred_task, stop_task, return_exceptions=True)
        return run.stop_event.is_set()

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
        reason: AdapterDownReason = "operator",
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
                # SEC-01 (#288): stamp the incarnation being STARTED. At HANDSHAKE_OK
                # time ``restart_count`` is the count of prior restarts, i.e. the
                # serving incarnation index (first up -> 0; the up after one
                # crash+restart -> 1, since ``_handle_crash`` did ``restart_count += 1``
                # before looping back). The core reconciler advances its current
                # incarnation to this on the accepted up.
                # H1 (#288): stamp the epoch this incarnation was SPAWNED under (captured
                # live in ``_spawn_or_terminal``), so a core bounce mid-life cannot drift
                # the ``up`` epoch from the credential-grant epoch. ``spawn_epoch`` is set
                # before any HANDSHAKE_OK can feed EMIT_UP, so it is non-None here.
                spawn_epoch = run.spawn_epoch
                if spawn_epoch is None:  # pragma: no cover - EMIT_UP follows a spawn
                    raise AdapterLifecycleStateError(
                        f"EMIT_UP without a captured spawn epoch (adapter_id={adapter_id!r})"
                    )
                await self._emitter.emit_up(
                    adapter_id=adapter_id, epoch=spawn_epoch, host_restart_seq=run.restart_count
                )
                ADAPTER_UP.labels(adapter=adapter_id).set(1)
            case AdapterControl.EMIT_DOWN:
                await self._emitter.emit_down(adapter_id=adapter_id, reason=reason)
            case AdapterControl.EMIT_CRASHED:
                # LOAD-BEARING ORDERING (#288): EMIT_CRASHED runs BEFORE
                # ``run.restart_count += 1`` (in ``_handle_crash``), so ``restart_count``
                # here is the PRE-increment value = the incarnation that EXITED (first
                # crash -> 0). This aligns crashed(N) with up(N) on the same incarnation
                # so the core reconciler folds them into one incident. Do NOT move the
                # increment before this emit.
                await self._emitter.emit_crashed(
                    adapter_id=adapter_id,
                    error_class=error_class or "AdapterChildExited",
                    detail=detail,
                    host_restart_seq=run.restart_count,
                )
            case AdapterControl.EMIT_BREAKER_OPEN:
                await self._emitter.emit_breaker_open(
                    adapter_id=adapter_id, retry_after_seconds=retry_after_seconds
                )
            case _:  # pragma: no cover - exhaustive over the closed AdapterControl enum
                # Defensive: AdapterControl is a closed 4-member enum and ``control is
                # None`` is already filtered above, so every reachable value matches a
                # case. A new control added to the kernel without a frame here is a
                # programming error — fail loud (CLAUDE.md hard rule #7) rather than
                # silently dropping a status frame.
                raise AdapterLifecycleStateError(
                    f"no status frame mapped for adapter control {control!r}"
                )

    # ------------------------------------------------------------------
    # Backoff + bookkeeping
    # ------------------------------------------------------------------

    def _next_backoff(self, run: _AdapterRun) -> float:
        """A decorrelated-jitter backoff for this adapter, clamped to the window.

        Full jitter: draw uniformly in ``[0, base]`` from the supervisor's single
        SHARED RNG stream, then CLAMP to ``[_MIN_BACKOFF_SECONDS, _MAX_BACKOFF_SECONDS]``
        so a 0 / negative / oversized draw can never tight-spin or stall (mirrors
        core_link.py). The base doubles per crash up to the cap. The no-stampede
        guarantee comes from each draw being an independent sample of the shared stream:
        two adapters crashing together take consecutive (distinct) draws, so they never
        redial in lockstep — a per-adapter RNG is NOT required for that property.
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


def _default_monotonic() -> float:
    import time

    return time.monotonic()


__all__ = [
    "GatewayAdapterCredentialError",
    "GatewayAdapterSpawnError",
    "GatewayAdapterSupervisor",
]
