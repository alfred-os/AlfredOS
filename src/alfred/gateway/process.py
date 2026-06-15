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
from collections.abc import Awaitable, Callable

import structlog

from alfred.gateway.client_link import client_handshake
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink, _CommsTransportLike
from alfred.gateway.metrics import PEER_AUTH_REJECTED
from alfred.gateway.relay import GatewayRelay

log = structlog.get_logger(__name__)


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
    ) -> None:
        self._shutdown_event = shutdown_event
        self._dial_adapter_id = dial_adapter_id
        # The core dial is injectable so a test drives a fake core leg; ``None`` defers to
        # :meth:`GatewayCoreLink._default_dial` (the production socket dial).
        self._core_dial = core_dial

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
            core_link = GatewayCoreLink(
                client_listener=listener,
                shutdown_event=self._shutdown_event,
                dial_adapter_id=self._dial_adapter_id,
                dial=self._core_dial,
            )
            relay = GatewayRelay(
                core_link=core_link,
                client_transport=client_transport,
                client_seq_enabled=client_seq_enabled,
            )
            await relay.run()
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


__all__ = ["GatewayProcess"]
