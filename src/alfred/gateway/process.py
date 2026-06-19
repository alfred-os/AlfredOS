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

from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    GatewayAdapterSupervisor,
    _AdapterChildLike,
)
from alfred.gateway.client_link import client_handshake
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink, _CommsTransportLike
from alfred.gateway.metrics import PEER_AUTH_REJECTED
from alfred.gateway.relay import GatewayRelay
from alfred.gateway.replay_buffer import ReplayBuffer
from alfred.gateway.status_leg import GatewayCoreLinkStatusSink

log = structlog.get_logger(__name__)

# 2b-2a empty-set placeholder epoch: no ``up`` is emitted on the empty adapter set, so
# this 32-hex placeholder is NEVER put on the wire. G6-3 reads the live captured epoch
# via ``core_link.current_core_epoch()`` per spawn instead of this snapshot.
_PLACEHOLDER_EPOCH: Final[str] = "0" * 32


class _UnspawnedAdapterChildFactory:
    """G6-2b-2a placeholder: refuses to spawn (no real launcher until G6-3).

    With the 2b-2a empty adapter set this is NEVER called. It raises
    :class:`GatewayAdapterSpawnError` loud (fail-closed, CLAUDE.md hard rule #7)
    rather than fabricating a child, so a premature non-empty adapter set fails
    audibly instead of running a credential-less / child-less adapter.
    """

    async def spawn_and_handshake(self, *, adapter_id: str, epoch: str) -> _AdapterChildLike:
        # ``epoch`` is part of the factory Protocol (G6-3 stamps it onto the spawned
        # child); this placeholder never spawns, so it is referenced only in the
        # fail-closed error for forensic context. The ``_AdapterChildLike`` return type
        # satisfies the factory Protocol; the method always raises, so it never returns.
        raise GatewayAdapterSpawnError(
            f"adapter child spawn is not wired until G6-3 "
            f"(adapter_id={adapter_id!r}, epoch={epoch!r})"
        )


class _UnavailableCredSeam:
    """G6-2b-2a placeholder cred seam: always unavailable (real cred is G6-3)."""

    async def is_available(self, *, adapter_id: str) -> bool:
        # ``adapter_id`` is part of the cred Protocol; this placeholder is uniformly
        # unavailable (real per-adapter credential lookup is G6-3), so it is unused here.
        del adapter_id
        return False


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
    ) -> None:
        self._shutdown_event = shutdown_event
        self._dial_adapter_id = dial_adapter_id
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

    def _build_adapter_supervisor(self, core_link: GatewayCoreLink) -> GatewayAdapterSupervisor:
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
        return GatewayAdapterSupervisor(
            child_factory=_UnspawnedAdapterChildFactory(),
            cred_seam=_UnavailableCredSeam(),
            emitter=emitter,
            # Empty-set boot: no ``up`` emits, so this placeholder epoch is never put on
            # the wire. G6-3 reads the live ``core_link.current_core_epoch()`` per spawn.
            epoch=core_link.current_core_epoch() or _PLACEHOLDER_EPOCH,
            sleep=self._sleep,
        )

    async def _run_relay_and_supervisor(
        self, relay: GatewayRelay, supervisor: GatewayAdapterSupervisor
    ) -> None:
        """Run the relay (the serving lifetime) + supervised adapter supervisor.

        The RELAY's lifetime is the process's serving lifetime — it returns on a clean
        shutdown. The supervisor runs CONCURRENTLY; correction #5: it is CANCELLED +
        reaped when the relay returns rather than awaited to its own completion.
        ``supervise_all([])`` returns immediately today (empty set), but a future
        NON-empty set (G6-3) would otherwise park forever (an adapter in AWAITING_CORE /
        steady state never returns on its own), so leaving it un-reaped would hang the
        gateway shutdown.

        A supervisor that RAISES a fail-closed :class:`GatewayAdapterSpawnError` BEFORE
        the relay returns is surfaced loudly (it aborts the relay too) so a real spawn
        failure is never swallowed; a supervisor that simply returns (empty-set no-op) is
        ignored — the relay keeps serving. The relay is the sole completion anchor.
        """
        relay_task: asyncio.Task[None] = asyncio.ensure_future(relay.run())
        supervisor_task: asyncio.Task[None] = asyncio.ensure_future(
            supervisor.supervise_all(self._adapter_ids)
        )
        try:
            done, _pending = await asyncio.wait(
                {relay_task, supervisor_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if supervisor_task in done:
                # The supervisor finished first. A fail-closed spawn error must surface
                # (``.result()`` re-raises it, and the ``finally`` then cancels the relay);
                # a clean empty-set no-op return is ignored — keep serving until the relay
                # itself ends below.
                supervisor_task.result()
            if relay_task not in done:
                # The relay is the serving-lifetime anchor: wait for IT to end (shutdown)
                # even after the empty-set supervisor returned.
                await relay_task
            # ``.result()`` re-raises a genuine relay error (the prior bare-await
            # behaviour) once the relay has completed.
            relay_task.result()
        finally:
            # Cancel + reap both on EVERY exit (the relay returned, or a raise is
            # unwinding): never leave a parked supervisor/relay task outliving the process.
            if not supervisor_task.done():
                supervisor_task.cancel()
            if not relay_task.done():
                relay_task.cancel()
            await asyncio.gather(relay_task, supervisor_task, return_exceptions=True)

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
            core_link = GatewayCoreLink(
                client_listener=listener,
                shutdown_event=self._shutdown_event,
                dial_adapter_id=self._dial_adapter_id,
                dial=self._core_dial,
                replay_buffer=self._replay_buffer_factory(),
                sleep=self._sleep,
                jitter=self._jitter,
                monotonic=self._monotonic,
            )
            relay = GatewayRelay(
                core_link=core_link,
                client_transport=client_transport,
                client_seq_enabled=client_seq_enabled,
            )
            # Spec B G6-2b-2a (#288): the adapter supervisor is wired LIVE (its status
            # emitter bound to ``core_link.send_status_frame``) alongside the relay, with
            # an EMPTY configured set (spawns nothing until G6-3). It is cancelled/reaped
            # on shutdown (correction #5) so a future non-empty set cannot block the stop.
            supervisor = self._build_adapter_supervisor(core_link)
            await self._run_relay_and_supervisor(relay, supervisor)
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
    "_UnavailableCredSeam",
    "_UnspawnedAdapterChildFactory",
]
