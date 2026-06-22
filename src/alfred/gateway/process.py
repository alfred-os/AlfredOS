"""``GatewayProcess`` — the runnable ``alfred-gateway`` front door (Spec A G3-3b-2b / ADR-0031).

This is the process that joins every gateway half into a runnable whole. It mirrors the
daemon's socket-carrier (:func:`alfred.cli.daemon._commands._listen_socket_comms_adapter`):

* **bind the client listener inline (fail-closed)** — binding the ``0600`` owner-only
  client socket under the ``0700`` runtime dir is a gateway-owned, startup-time operation,
  so a bind failure (``OSError``) propagates LOUD and REFUSES the start (CLAUDE.md hard
  rule #7) — never a half-bound front door;
* **accept ONE client, racing shutdown** — the client connection is held for the life of
  the process (single-accept-for-life, architect L1); the accept is raced against the
  shutdown event so a clean stop before a client ever connects returns promptly;
* **run the client-leg HOST handshake** — the gateway stands in for the daemon toward an
  unmodified TUI: it SENDS ``lifecycle.start`` and reads the ack. A handshake failure
  (:class:`GatewayHandshakeError`) propagates LOUD (fail-closed) — never a half-wired relay;
* **build + supervise the relay** — the merged :class:`GatewayCoreLink` (core dial +
  handshake + reconnect + the §9 lifecycle signal) and the :class:`GatewayRelay` (the
  two-direction opaque payload pump) are constructed and ``relay.run()`` is awaited;
* **reap on EVERY exit path** — the listener (its accepted transport + the socket file) is
  reaped in a ``finally`` on every exit: a clean shutdown, a handshake/bind raise, OR a
  cancel/``KeyboardInterrupt`` unwind (the security-M2 cancel reap). The core transport is
  reaped by :meth:`GatewayCoreLink.run`'s own ``finally``; the client transport by the
  listener's :meth:`GatewayClientListener.aclose`.

**Payload-blind (CLAUDE.md hard rule #5).** This process adds NO payload parse — it only
wires the legs. The single method-peek in the whole gateway lives in the core-link's
lifecycle router; everything else is forwarded as opaque bytes.

**No ``t()`` here (operator strings are the CLI's job, Task 5).** This module emits only
structlog keys; the operator-facing ``alfred gateway`` command text lands in the CLI cut.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from typing import Final

import structlog

from alfred.gateway.adapter_child_factory import GatewayAdapterChildFactory, _RunnerLike
from alfred.gateway.adapter_credential_client import GatewayAdapterCredentialClient
from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.gateway.adapter_stdio_transport import GatewayAdapterStdioTransport
from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    GatewayAdapterSupervisor,
)
from alfred.gateway.client_link import client_handshake
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink, _CommsTransportLike
from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.inbound_forward_runner import GatewayInboundForwardRunner
from alfred.gateway.ingress_gate import PerAdapterIngressGate
from alfred.gateway.leg_router import LegRouter
from alfred.gateway.leg_scheduler import GatewayLegScheduler
from alfred.gateway.metrics import PEER_AUTH_REJECTED
from alfred.gateway.relay import GatewayRelay
from alfred.gateway.replay_buffer import ReplayBuffer
from alfred.gateway.status_leg import GatewayCoreLinkStatusSink

# Spec B G6-4a (#288): the TUI dial-in is the FIRST GatewayLeg. With a SINGLE leg there is
# no aggregate-across-legs constraint, so the per-leg ReplayBuffer's OWN hard ceiling is the
# binding back-pressure bound; the GlobalReplayCap becomes binding only when G6-4 adds a 2nd
# leg. Its ceiling is set STRICTLY ABOVE the buffer hard ceiling (PR2) — the buffer's own
# hard-ceiling raise ALWAYS fires first, so the cap never refuses on the single TUI leg
# (behavior-preserving for G5). The ingress gate is NON-BINDING (unbounded tokens / in-flight
# / size) so the TUI is NOT throttled — G6-4's real adapter legs + the TUI's priority-credit
# config land when the scheduler is wired.
_TUI_LEG_ADAPTER_ID: Final[str] = "tui"
_TUI_GLOBAL_CAP_MULTIPLIER: Final[int] = 4  # ceiling = buffer max_bytes * 4 (> the * 2 hard cap)
_NON_BINDING_RATE_PER_S: Final[float] = 1e9
_NON_BINDING_COUNT: Final[int] = 10**9
_NON_BINDING_TTL_SECONDS: Final[float] = 1e9
_NON_BINDING_MAX_FRAME_BYTES: Final[int] = 1 << 30

# Spec B G6-5 Task 6 / L1 (#288): the BINDING ingress config for a hosted adapter leg
# (Discord). Unlike the interactive TUI leg, an external adapter is adversary-exposed,
# so its leg gets a FINITE volumetric bound (rate / burst / in-flight / size) that the
# non-binding TUI sentinels above intentionally lack. The Discord manifest declares NO
# rate fields today, so these are explicit module-level constants with sensible
# first-party defaults; sourcing the caps from the adapter manifest is a deferred
# follow-up (L1). Values bound a chatty/large-payload adapter from exhausting the shared
# core link or the bounded pre-DLP retention budget, while staying generous enough that a
# normal conversational adapter is never throttled.
_ADAPTER_LEG_RATE_PER_S: Final[float] = 50.0  # sustained admits/s (refilled lazily)
# Burst >= max-inflight so the in-flight cap is the binding concurrency bound (a smaller
# burst would make the rate tier refuse before the in-flight cap is ever reachable —
# leaving the in-flight cap dead config).
_ADAPTER_LEG_BURST: Final[int] = 256  # token-bucket ceiling (a short burst)
_ADAPTER_LEG_MAX_INFLIGHT: Final[int] = 256  # concurrent un-completed admits
_ADAPTER_LEG_TTL_SECONDS: Final[float] = 300.0  # in-flight slot TTL (wedge guard / sweep)
_ADAPTER_LEG_MAX_FRAME_BYTES: Final[int] = 1 << 20  # 1 MiB per inbound frame
_ADAPTER_GLOBAL_CAP_MULTIPLIER: Final[int] = 4  # ceiling = buffer max_bytes * 4 (> hard cap)

# Spec B G6-4 Task 7 (#288): the per-leg scheduler send-queue byte bound (perf-M3). This is
# pre-append working memory the GlobalReplayCap does not see, so it is bounded independently;
# the TUI leg is interactive (one turn at a time), so a generous-but-finite ceiling never
# back-pressures a real operator yet caps a runaway producer. A real adapter leg (G6-5) sets
# its own from its manifest.
_LEG_SEND_QUEUE_BYTES: Final[int] = 1 << 20

# Spec B G6-4 Task 7 / K5: the cadence of the per-gate in-flight TTL sweep. The ingress
# gate's TTL is the real wedge bound; this is just how often the active sweeper reclaims a
# slot a stalled-IDLE leg holds (a leg that admitted a frame that never completed AND has no
# new admits to trigger an on-admit eviction). 30s mirrors the buffer-evict cadence — small
# relative to a sensible TTL without busy-sweeping. The TUI gate is non-binding (TTL 1e9) so
# the sweep is a no-op there; it is wired + reaped so a future binding adapter leg is covered.
_INGRESS_SWEEP_INTERVAL_SECONDS: Final[float] = 30.0

log = structlog.get_logger(__name__)


def build_tui_leg(
    *,
    replay_buffer_factory: Callable[[], ReplayBuffer] = ReplayBuffer,
    monotonic: Callable[[], float] = time.monotonic,
) -> GatewayLeg:
    """Build the single proving TUI dial-in ``GatewayLeg`` (G6-4a, #288).

    Factored out of :meth:`GatewayProcess._build_tui_leg` so the production process AND the
    gateway-chain integration proofs construct the leg IDENTICALLY (same SECURITY caps,
    non-binding ingress gate, monotonic seam). Wraps a fresh per-client ``ReplayBuffer`` (at
    its own caps) in the FIRST ``GatewayLeg`` (``adapter_id="tui"``); the leg's ``now`` is
    wired to the SAME ``monotonic`` the evict loop reads. The ``GlobalReplayCap`` ceiling is
    strictly above the buffer hard ceiling (PR2 — the buffer's own hard-ceiling raise fires
    first), and the ``PerAdapterIngressGate`` is NON-BINDING (the interactive path is never
    throttled).
    """
    buffer = replay_buffer_factory()
    cap = GlobalReplayCap(max_total_bytes=buffer.max_bytes * _TUI_GLOBAL_CAP_MULTIPLIER)
    gate = PerAdapterIngressGate(
        _TUI_LEG_ADAPTER_ID,
        sustained_rate_per_s=_NON_BINDING_RATE_PER_S,
        burst=_NON_BINDING_COUNT,
        max_inflight=_NON_BINDING_COUNT,
        ttl_seconds=_NON_BINDING_TTL_SECONDS,
        max_frame_bytes=_NON_BINDING_MAX_FRAME_BYTES,
        now=monotonic,
    )
    return GatewayLeg(
        adapter_id=_TUI_LEG_ADAPTER_ID,
        buffer=buffer,
        ingress_gate=gate,
        global_cap=cap,
        now=monotonic,
    )


def build_adapter_leg(
    adapter_id: str,
    *,
    replay_buffer_factory: Callable[[], ReplayBuffer] = ReplayBuffer,
    monotonic: Callable[[], float] = time.monotonic,
) -> GatewayLeg:
    """Build a BINDING ``GatewayLeg`` for one hosted adapter (Spec B G6-5 Task 6 / L1, #288).

    Mirrors :func:`build_tui_leg` but with a BINDING :class:`PerAdapterIngressGate`: an
    external adapter (Discord) is adversary-exposed, so its leg enforces a FINITE
    volumetric bound (the ``_ADAPTER_LEG_*`` ``Final`` constants — rate / burst /
    in-flight / TTL / max-frame-bytes) where the interactive TUI leg is intentionally
    non-binding. The per-leg ``ReplayBuffer`` (retention / zeroing / caps) and the
    ``GlobalReplayCap`` (ceiling strictly above the buffer hard cap) are wired exactly as
    the TUI leg's, so this leg reaps + accounts identically. The leg's ``now`` is the SAME
    ``monotonic`` the gate + evict loop read.
    """
    buffer = replay_buffer_factory()
    cap = GlobalReplayCap(max_total_bytes=buffer.max_bytes * _ADAPTER_GLOBAL_CAP_MULTIPLIER)
    gate = PerAdapterIngressGate(
        adapter_id,
        sustained_rate_per_s=_ADAPTER_LEG_RATE_PER_S,
        burst=_ADAPTER_LEG_BURST,
        max_inflight=_ADAPTER_LEG_MAX_INFLIGHT,
        ttl_seconds=_ADAPTER_LEG_TTL_SECONDS,
        max_frame_bytes=_ADAPTER_LEG_MAX_FRAME_BYTES,
        now=monotonic,
    )
    return GatewayLeg(
        adapter_id=adapter_id,
        buffer=buffer,
        ingress_gate=gate,
        global_cap=cap,
        now=monotonic,
    )


def wire_leg_scheduler(core_link: GatewayCoreLink, tui_leg: GatewayLeg) -> GatewayLegScheduler:
    """Build + attach the K1 leg scheduler/router for ``core_link`` over ``tui_leg``.

    The single coherent client->core routing path (Spec B G6-4 Task 7 / K1, #288), factored
    out so the production :meth:`GatewayProcess.run` AND the gateway-chain integration proofs
    wire it IDENTICALLY — a test that hand-builds the legs but forgets the scheduler/router
    would leave ``submit_tui_unit`` with no drainer (the frame enqueues but never drains). The
    scheduler drains onto ``core_link.write_leg_unit`` + reads ``core_link.replay_pending_gate``;
    the :class:`LegRouter` (the K4 forged-adapter refusal) is built over the scheduler and
    attached to the link via :meth:`GatewayCoreLink.set_leg_router` (the same post-construction
    late-binding the relay uses for ``_payload_relay``). The leg is registered with the
    scheduler. Returns the scheduler so the caller can pass it to :class:`GatewayRelay` (the
    relay co-runs its drain pump) and reap it on exit.
    """
    scheduler = GatewayLegScheduler(core_link, max_per_leg_queue_bytes=_LEG_SEND_QUEUE_BYTES)
    scheduler.register_leg(tui_leg)
    core_link.set_leg_router(LegRouter(scheduler))
    return scheduler


def _unwired_runner_factory(
    *, transport: GatewayAdapterStdioTransport, adapter_id: str
) -> _RunnerLike:
    """Fail-loud default ``runner_factory`` for :class:`GatewayAdapterChildFactory` (G6-5).

    The real session-bearing :class:`alfred.plugins.comms_runner.CommsPluginRunner`
    needs the daemon boot graph (a full ``AlfredPluginSession`` + the inbound / binding /
    crash / rate-limit handlers + the credential resolver), which the standalone
    ``alfred-gateway`` process does NOT build (those are daemon-side collaborators —
    see the G6-5 Task-5 collaborator flag). So the production process passes its own
    ``adapter_runner_factory`` in; if a non-empty ``adapter_ids`` is configured without
    one, the spawn refuses LOUD (CLAUDE.md hard rule #7) rather than handshaking against
    a session-less runner. ``transport`` is accepted to satisfy the factory's
    ``runner_factory`` signature; it is never used on this fail-closed path.
    """
    del transport
    raise GatewayAdapterSpawnError(
        f"no adapter runner factory wired for adapter_id={adapter_id!r}; "
        "GatewayProcess(adapter_runner_factory=...) must supply the session-bearing runner"
    )


class _CoreEpochCredSeam:
    """G6-3 pre-spawn liveness probe: the credential leg is up iff the core epoch is set.

    The CHEAP local link-state check (correction H2 part i): a credential round-trip is
    only possible once the gateway has handshaked the core leg and captured the per-boot
    epoch (``GatewayCoreLink.current_core_epoch() is not None``). This is NOT a full
    ``spawn_request`` (no core decrypt) — the real credential is acquired at spawn time
    by the :class:`GatewayAdapterCredentialClient`. A ``None`` epoch routes the adapter
    to AWAITING_CORE rather than spawning against a dead leg.
    """

    def __init__(self, *, core_link: GatewayCoreLink) -> None:
        self._core_link = core_link

    async def is_available(self, *, adapter_id: str) -> bool:
        del adapter_id  # the probe is per-leg, not per-adapter (the leg carries all)
        return self._core_link.current_core_epoch() is not None


class GatewayProcess:
    """The runnable ``alfred-gateway`` process: bind, accept, handshake, supervise, reap.

    Construct one per gateway process with the shutdown event the runner signals on a clean
    stop. :meth:`run` is the entry point; it returns cleanly on a shutdown won before/during
    the relay, and raises LOUD (fail-closed) on a bind or client-handshake failure — always
    reaping the listener in its ``finally``.
    """

    def __init__(
        self,
        *,
        shutdown_event: asyncio.Event,
        dial_adapter_id: str = "tui",
        core_dial: Callable[[], Awaitable[_CommsTransportLike]] | None = None,
        replay_buffer_factory: Callable[[], ReplayBuffer] = ReplayBuffer,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[float], float] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        adapter_ids: list[str] | None = None,
        adapter_runner_factory: Callable[..., _RunnerLike] = _unwired_runner_factory,
    ) -> None:
        self._shutdown_event = shutdown_event
        self._dial_adapter_id = dial_adapter_id
        # G6-5 (#288): the session-bearing runner factory the real
        # ``GatewayAdapterChildFactory`` drives over each spawned child. Defaults to the
        # fail-loud :func:`_unwired_runner_factory` — the daemon-side boot-graph
        # collaborators it needs are not built by the standalone gateway process (the
        # Task-5 collaborator flag), so a production deployment that hosts a real adapter
        # injects the session-bearing factory here.
        self._adapter_runner_factory = adapter_runner_factory
        # The configured comms-adapter set the gateway supervises (Spec B G6-2b-2a / #288).
        # EMPTY in 2b-2a (gap b): the supervisor is wired LIVE but spawns nothing —
        # ``supervise_all([])`` is a clean no-op. G6-3 supplies the real ids (Discord) +
        # a real credential client + child factory.
        self._adapter_ids: list[str] = list(adapter_ids or [])
        # The core dial is injectable so a test drives a fake core leg; ``None`` defers to
        # :meth:`GatewayCoreLink._default_dial` (the production socket dial).
        self._core_dial = core_dial
        # G5 resume seams (Spec A G5 / #237). ``replay_buffer_factory`` is a ZERO-arg
        # factory: the production default ``ReplayBuffer`` constructs the always-up
        # retention buffer at its own SECURITY caps (4096 frames / 8 MiB / 300 s TTL), and
        # a fresh one is minted per accepted client in :meth:`run`. ``sleep`` / ``jitter`` /
        # ``monotonic`` are the core-link's determinism seams (reconnect backoff + TTL
        # eviction): a test injects fakes; the production defaults preserve live behaviour —
        # ``jitter=None`` defers to :class:`GatewayCoreLink`'s own full-jitter default.
        self._replay_buffer_factory = replay_buffer_factory
        self._sleep = sleep
        self._jitter = jitter
        self._monotonic = monotonic

    def _build_tui_leg(self) -> GatewayLeg:
        """Build the single proving TUI leg for this accepted client (G6-4a, #288).

        Delegates to the module-level :func:`build_tui_leg` (shared with the integration
        proofs) so the leg's SECURITY caps / non-binding gate / monotonic seam are wired
        IDENTICALLY in production and under test. One leg only — the scheduler / fair-share
        is wired separately via :func:`wire_leg_scheduler`.
        """
        return build_tui_leg(
            replay_buffer_factory=self._replay_buffer_factory, monotonic=self._monotonic
        )

    def _register_adapter_legs(self, scheduler: GatewayLegScheduler) -> None:
        """Build + register one BINDING leg per configured adapter id (G6-5 Task 6, #288).

        Mirrors the single TUI-leg registration but for each hosted adapter: a
        :func:`build_adapter_leg` BINDING leg (finite ingress caps, L1) is registered
        with the scheduler so the multi-leg router (the K4 forged-id refusal) routes a
        Discord frame to its own buffer + the fair scheduler drains it onto the single
        core writer. EMPTY ``_adapter_ids`` registers nothing — only the TUI leg remains
        (behaviour-preserving for G5). Each registered leg is reaped on exit by the
        scheduler's :meth:`GatewayLegScheduler.aclose` (the same reap the TUI leg gets),
        which :meth:`_run_relay_and_scheduler`'s ``finally`` calls on EVERY exit path.
        """
        for adapter_id in self._adapter_ids:
            scheduler.register_leg(
                build_adapter_leg(
                    adapter_id,
                    replay_buffer_factory=self._replay_buffer_factory,
                    monotonic=self._monotonic,
                )
            )

    async def _on_peer_rejected(self, peer_uid: int | None) -> None:
        """The client-leg peer-auth reject seam: increment the metric + emit the loud row.

        Fired by the listener at the ``SO_PEERCRED`` reject point for a mismatched-uid
        client. The reject is an EXPECTED adversarial event, so it does NOT tear the
        process down (refusing here would be a self-inflicted DoS — an attacker racing the
        socket could kill the front door); the listener keeps waiting for the real peer.
        The durable, signed reject AUDIT row is G4 — this CALLBACK preserves ``peer_uid``
        in the structlog breadcrumb so the durable row can attribute it later.
        """
        PEER_AUTH_REJECTED.inc()
        log.warning(
            "gateway.process.peer_uid_rejected",
            peer_uid=peer_uid,
            expected_uid=os.getuid(),
        )

    def _build_adapter_runner_factory(
        self, core_link: GatewayCoreLink, scheduler: GatewayLegScheduler
    ) -> Callable[..., _RunnerLike]:
        """Build the REAL session-less forward-runner factory (Spec B G6-7-3 / #309).

        The production ``adapter_runner_factory`` the
        :class:`GatewayAdapterChildFactory` drives over each spawned child. The closure,
        per spawned ``(transport, adapter_id)``:

        1. mints a per-adapter back-pressure :class:`asyncio.Event` (starts SET — no
           back-pressure) and REGISTERS it with the scheduler
           (:meth:`GatewayLegScheduler.set_back_pressure_gate`) so the scheduler's drain
           RESUMES the reader when the leg drains (FORK-C — the back-pressure loop is
           bidirectional only if the gate is registered);
        2. builds a :class:`GatewayInboundForwardRunner` (session-LESS, FORK-A) whose
           forward sink is ``core_link.forward_adapter_inbound`` and whose
           ``back_pressure_gate`` is the minted event — so a full leg pauses the reader
           and a drain resumes it.

        The adapter leg MUST already be registered (``_register_adapter_legs`` runs in
        :meth:`run` before this factory is ever called at spawn time), so
        ``set_back_pressure_gate`` finds the leg. The forward target is the SPAWN-BINDING
        ``adapter_id`` (SEC-309-1) — the closure binds it from the factory call, never the
        body.
        """

        def _factory(*, transport: _CommsTransportLike, adapter_id: str) -> _RunnerLike:
            gate = asyncio.Event()
            gate.set()  # no back-pressure until a full leg clears it
            scheduler.set_back_pressure_gate(adapter_id, gate)
            return GatewayInboundForwardRunner(
                transport=transport,
                adapter_id=adapter_id,
                forward=core_link.forward_adapter_inbound,
                shutdown_event=self._shutdown_event,
                back_pressure_gate=gate,
            )

        return _factory

    def _build_adapter_supervisor(
        self, core_link: GatewayCoreLink, scheduler: GatewayLegScheduler
    ) -> GatewayAdapterSupervisor:
        """Build the live-wired adapter supervisor for this gateway process (#288).

        Spec B G6-2b-2a: bind the supervisor's status emitter to the LIVE gateway->core
        status leg (:class:`GatewayCoreLinkStatusSink` over ``core_link.send_status_frame``),
        replacing 2b-1's fake sink. The adapter set is EMPTY in 2b-2a (gap b) — the
        plumbing is live but no child is spawned until G6-3 supplies a real credential
        client + child factory. The epoch is read LAZILY from the core link at emit time
        (gap c): the supervisor ctor's ``epoch`` snapshot is unused for the empty set (no
        ``up`` is emitted), and G6-3 reads ``core_link.current_core_epoch()`` per spawn.
        """
        sink = GatewayCoreLinkStatusSink(core_link=core_link)
        emitter = AdapterStatusEmitter(sink=sink)
        # G6-3 (#288): the REAL credential client holds the core leg (the credential
        # round-trip's gateway half). The cred seam is the cheap live-epoch liveness
        # probe; the epoch is sourced LIVE per spawn from the core link (H1). The adapter
        # set is EMPTY in 2b-2a (gap b) — the plumbing is live but no child is spawned
        # until a real adapter id + child factory land (the real Discord factory is the
        # privileged-lane G6-3 Task 9; an unspawned-factory placeholder fails loud).
        credential_client = GatewayAdapterCredentialClient(core_link=core_link)
        # G6-5 (#288): the REAL bwrap adapter-child factory replaces the retired
        # ``_UnspawnedAdapterChildFactory`` placeholder. It owns the fd-3 pipe + the
        # synchronous dup2->Popen->restore spawn window + the launcher exec; the
        # credential never passes through it (the supervisor's ``deliver_credential``
        # hook over the credential client owns that).
        #
        # Spec B G6-7-3 (#309): the runner_factory is the REAL session-less forward-runner
        # factory (bound to ``core_link.forward_adapter_inbound`` + the scheduler's
        # per-adapter back-pressure gate) — UNLESS the constructor injected an override
        # (the test seam). The default ``_unwired_runner_factory`` no longer reaches
        # production: it is replaced HERE by the forward factory so a hosted child's
        # ``inbound.message`` actually forwards (the production-unwired trap guard). An
        # explicitly-injected factory still wins (a test drives its own).
        runner_factory = (
            self._build_adapter_runner_factory(core_link, scheduler)
            if self._adapter_runner_factory is _unwired_runner_factory
            else self._adapter_runner_factory
        )
        child_factory = GatewayAdapterChildFactory(
            runner_factory=runner_factory,
        )
        return GatewayAdapterSupervisor(
            child_factory=child_factory,
            cred_seam=_CoreEpochCredSeam(core_link=core_link),
            credential_client=credential_client,
            emitter=emitter,
            epoch_source=core_link.current_core_epoch,
            sleep=self._sleep,
        )

    async def _ingress_sweep_loop(self, scheduler: GatewayLegScheduler) -> None:
        """K5: periodically reclaim ingress in-flight slots held past the gate TTL.

        A supervised background task (reaped in :meth:`_run_relay_and_scheduler`'s
        ``finally``). The gate's :meth:`PerAdapterIngressGate.evict_stalled` only fires when
        called; a leg that admitted a frame which never completed AND has no fresh admits to
        trigger an on-admit eviction would otherwise hold that slot forever (the wedge). This
        sleep-driven sweep (NOT busy-wait, NOT on-admit-only) reclaims such slots for EVERY
        registered leg every :data:`_INGRESS_SWEEP_INTERVAL_SECONDS`. Each reclaimed slot is
        a LOUD audit breadcrumb (CLAUDE.md hard rule #7 — the wedge guard is observable). The
        TUI gate is non-binding (TTL 1e9) so this is a no-op there; it is wired so a future
        binding adapter leg (G6-5) is covered with zero new wiring.
        """
        while True:
            await self._sleep(_INGRESS_SWEEP_INTERVAL_SECONDS)
            # Iterate a SNAPSHOT of the adapter ids; the snapshot is not atomic with the
            # per-leg lookup, so a leg the scheduler ISOLATED/deregistered (the perf-M4 fault
            # path) between the snapshot and ``scheduler.leg(adapter_id)`` is gone. Tolerate
            # the ``KeyError`` and SKIP it (CR / Spec B G6-4 #288) — a stale id is not a sweep
            # failure, and crashing the sweeper would silently end K5 enforcement (hard #7).
            for adapter_id in tuple(scheduler.adapter_ids()):
                try:
                    leg = scheduler.leg(adapter_id)
                except KeyError:
                    continue
                for token in leg.evict_stalled_admits():
                    log.warning(
                        "gateway.ingress.slot_evicted",
                        adapter_id=adapter_id,
                        token=token,
                        reason="ttl_expired",
                    )

    async def _run_relay_and_scheduler(
        self,
        relay: GatewayRelay,
        supervisor: GatewayAdapterSupervisor,
        scheduler: GatewayLegScheduler,
    ) -> None:
        """Run the relay (serving lifetime) + supervisor + leg scheduler + K5 ingress sweep.

        The RELAY's lifetime is the process's serving lifetime — it returns on a clean
        shutdown. The relay co-runs the leg scheduler's DRAIN pump under its own TaskGroup
        (Task 7 — the single steady-state writer shares the relay lifetime). The supervisor
        (correction #5) and the K5 ingress TTL sweeper run CONCURRENTLY here and are CANCELLED
        + reaped when the relay returns (or a raise unwinds), so neither outlives the process
        (CLAUDE.md hard rule #7 — no leaked task). The sweeper parks on its sleep and never
        completes on its own — the relay is the sole completion anchor.

        A supervisor that RAISES a fail-closed :class:`GatewayAdapterSpawnError` BEFORE the
        relay returns is surfaced loudly (it aborts the relay too) so a real spawn failure is
        never swallowed; a supervisor empty-set no-op return is ignored. The sweeper never
        completes on its own, so its completion can only be a raise.

        **Keep monitoring the sweeper until the relay ends (CR / Spec B G6-4 #288).** With the
        default EMPTY adapter set the supervisor's ``supervise_all([])`` no-op returns FIRST,
        long before shutdown. We must NOT then await ONLY the relay — a later
        :meth:`_ingress_sweep_loop` raise would be left for the ``finally``'s
        ``gather(..., return_exceptions=True)``, which SWALLOWS it (K5 enforcement dies
        silent — hard rule #7). Instead we loop on ``FIRST_COMPLETED`` over the
        STILL-running tasks: each time a background task completes we call ``.result()`` (a
        no-op return is ignored; a raise re-surfaces LOUD), and we keep looping until the
        relay itself completes — so a sweeper crash AFTER the supervisor no-op is surfaced
        promptly, not absorbed at teardown.

        **Reap on EVERY exit (perf-M4 / security).** The ``finally`` cancels + reaps all
        tasks, then ``scheduler.aclose()`` tears down EVERY registered leg — discarding its
        ReplayBuffer (zeroing the pre-DLP T1 bytes) and releasing its global-cap budget — on
        the shutdown path AND on any assembly/boot raise that unwinds through here. The core
        link's own ``run`` ``finally`` ALSO discards the (shared) TUI leg buffer; both are
        idempotent (discard zeroes+empties; teardown removes the cap entry).
        """
        relay_task: asyncio.Task[None] = asyncio.ensure_future(relay.run())
        supervisor_task: asyncio.Task[None] = asyncio.ensure_future(
            supervisor.supervise_all(self._adapter_ids)
        )
        sweep_task: asyncio.Task[None] = asyncio.ensure_future(self._ingress_sweep_loop(scheduler))
        background = (supervisor_task, sweep_task)
        try:
            # Loop until the relay (the serving-lifetime anchor) completes. Each round waits on
            # whatever is still running; a completed BACKGROUND task is ``.result()``-ed so a
            # raise (a fail-closed spawn error, or a sweeper crash AFTER the supervisor no-op)
            # surfaces LOUD immediately, while a clean no-op return is ignored. This keeps the
            # sweeper monitored for its whole life instead of awaiting only the relay after the
            # supervisor returns (CR / hard rule #7).
            pending: set[asyncio.Task[None]] = {relay_task, *background}
            while not relay_task.done():
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if task is not relay_task:
                        # A background task completed: a no-op return is ignored; a raise
                        # re-surfaces here (the ``finally`` then cancels the remaining tasks).
                        task.result()
            # ``.result()`` re-raises a genuine relay error once the relay has completed.
            relay_task.result()
        finally:
            # Cancel + reap ALL on EVERY exit (the relay returned, or a raise is unwinding):
            # never leave a parked supervisor / sweeper outliving the process. Then tear down
            # every leg (discard buffer -> zero pre-DLP bytes + release the global-cap budget)
            # — the perf-M4 / security reap. The relay already reaped its co-run scheduler
            # drain pump; ``aclose`` is the leg-teardown half (idempotent w.r.t. the core
            # link's own buffer discard).
            for task in (relay_task, *background):
                if not task.done():
                    task.cancel()
            await asyncio.gather(relay_task, *background, return_exceptions=True)
            scheduler.aclose()

    async def run(self) -> None:
        """Bind, accept ONE client (racing shutdown), handshake, supervise the relay, reap.

        **Fail-closed (CLAUDE.md hard rule #7).** A listener bind ``OSError`` and a client
        ``GatewayHandshakeError`` both propagate LOUD — the process REFUSES rather than
        running a half-wired front door. **Clean stop:** a shutdown won BEFORE a client
        connects returns without dialing the core.

        **Reap on EVERY exit (security M2).** The listener (accepted transport + socket
        file) is reaped in the ``finally`` on every path — clean shutdown, a bind/handshake
        raise, or a cancel/``KeyboardInterrupt`` unwind. The core transport is reaped by
        :meth:`GatewayCoreLink.run`'s own ``finally``.
        """
        listener = GatewayClientListener(on_peer_rejected=self._on_peer_rejected)
        await listener.bind()  # fail-closed: an OSError propagates loud (refuse).
        try:
            client_transport = await self._accept_racing_shutdown(listener)
            if client_transport is None:
                # Shutdown won the accept race before a client connected — a clean stop.
                # No core dial, no relay; the ``finally`` unlinks the bound socket.
                return
            # The client-leg HOST handshake. A GatewayHandshakeError propagates LOUD
            # (fail-closed) — never build a relay over an unusable client leg.
            client_seq_enabled = await client_handshake(client_transport)
            # G5 production resume activation (Spec A G5 / #237). The always-up gateway now
            # buffers + replays un-acked client->core input across a core restart (spec §5),
            # activating the resume + the back-pressure breaker + TTL-eviction in the front
            # door. The buffer is minted ONCE per accepted client; its caps / TTL / zeroing
            # bound the pre-DLP operator-input exposure the retention introduces. Passing
            # ``self._jitter`` (default ``None``) preserves production behaviour:
            # ``GatewayCoreLink`` maps ``None`` to its own full-jitter default.
            # Spec B G6-4 Task 7 (#288): build the TUI leg ONCE and share it between the
            # core link (which owns the buffer lifecycle + the breaker escalation) and the
            # leg scheduler (the SINGLE steady-state drainer). The scheduler is constructed
            # OVER the core link (it drains onto ``write_leg_unit`` + reads
            # ``replay_pending_gate``); the router (the K4 forged-adapter refusal) is built
            # over the scheduler and attached to the link so ``submit_tui_unit`` enqueues
            # through it. The leg is registered with the scheduler; the scheduler ``run()``
            # pump + the K5 ingress TTL sweeper are spawned + reaped in
            # :meth:`_run_relay_and_scheduler`.
            tui_leg = self._build_tui_leg()
            core_link = GatewayCoreLink(
                client_listener=listener,
                shutdown_event=self._shutdown_event,
                dial_adapter_id=self._dial_adapter_id,
                dial=self._core_dial,
                tui_leg=tui_leg,
                sleep=self._sleep,
                jitter=self._jitter,
                monotonic=self._monotonic,
            )
            # Build + attach the K1 leg scheduler/router over the link + leg (the same
            # wiring the integration proofs reuse via :func:`wire_leg_scheduler`): the
            # scheduler drains onto ``write_leg_unit`` + reads ``replay_pending_gate``, and
            # the router (the K4 forged-adapter refusal) is attached post-construction (the
            # same late-binding pattern the relay uses for ``core_link._payload_relay``) —
            # the core link stays leg-agnostic; this process is the one place that knows the
            # leg<->scheduler topology.
            scheduler = wire_leg_scheduler(core_link, tui_leg)
            # Spec B G6-5 Task 6 (#288): register one BINDING leg per configured hosted
            # adapter alongside the non-binding TUI leg, so a real Discord frame routes to
            # its own per-leg buffer + ingress gate. Each is reaped by ``scheduler.aclose``
            # in ``_run_relay_and_scheduler``'s ``finally`` (the same reap the TUI leg gets).
            self._register_adapter_legs(scheduler)
            relay = GatewayRelay(
                core_link=core_link,
                client_transport=client_transport,
                client_seq_enabled=client_seq_enabled,
                scheduler=scheduler,
            )
            # Spec B G6-2b-2a (#288): the adapter supervisor is wired LIVE (its status
            # emitter bound to ``core_link.send_status_frame``) alongside the relay, with
            # an EMPTY configured set (spawns nothing until G6-3). It is cancelled/reaped
            # on shutdown (correction #5) so a future non-empty set cannot block the stop.
            supervisor = self._build_adapter_supervisor(core_link, scheduler)
            await self._run_relay_and_scheduler(relay, supervisor, scheduler)
        finally:
            # Reap the accepted transport + the socket file on EVERY exit path, including a
            # cancel/KeyboardInterrupt unwind (security M2 — no leaked inode on shutdown).
            await listener.aclose()

    async def _accept_racing_shutdown(
        self, listener: GatewayClientListener
    ) -> _CommsTransportLike | None:
        """Await ONE client, racing the shutdown event; ``None`` if shutdown wins.

        Mirrors the daemon socket-carrier's ``_accept_and_pump`` accept-vs-shutdown idiom
        (:func:`alfred.cli.daemon._commands._listen_socket_comms_adapter`): the
        ``listener.accept()`` races ``shutdown_event.wait()`` (FIRST_COMPLETED). The loser
        is cancelled + awaited so neither child leaks a "Task was destroyed but it is
        pending" warning. A shutdown win returns ``None`` (a clean stop — never accept a
        client after the process has begun stopping); an accept win returns the held
        transport (:attr:`GatewayClientListener.transport`).
        """
        accept_task = asyncio.ensure_future(listener.accept())
        shutdown_wait = asyncio.ensure_future(self._shutdown_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {accept_task, shutdown_wait}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            # Cancel + reap whichever lost so no pending-task / unretrieved-exception
            # warning escapes (mirrors the daemon carrier's finally).
            for task in (accept_task, shutdown_wait):
                if not task.done():
                    task.cancel()
            await asyncio.gather(accept_task, shutdown_wait, return_exceptions=True)
        if shutdown_wait in done and accept_task not in done:
            # Only shutdown completed — the clean stop. ``accept_task`` is still pending and
            # the ``finally`` already cancelled it; no client was accepted.
            return None
        # Accept completed (possibly on the SAME tick as shutdown — the held client is
        # still usable, so prefer it). ``.result()`` re-raises any genuine accept error.
        accept_task.result()
        return listener.transport


__all__ = [
    "GatewayProcess",
    "_CoreEpochCredSeam",
    "build_adapter_leg",
    "build_tui_leg",
    "wire_leg_scheduler",
]
