"""``GatewayClientListener`` — the gateway's client-facing socket (Spec A G3-3a).

The gateway terminates ONE client connection on a stable ``0600`` AF_UNIX socket and
holds it ACROSS core restarts (spec §1). This listener is the thin client-facing half
of the gateway kernel: it REUSES the merged :class:`CommsSocketListener` (the
``0600``/``0700`` posture + ``SO_PEERCRED`` peer-auth) keyed on ``adapter_id="gateway"``
(socket ``comms-gateway.sock``, the gateway's own stable externally-owned path per
spec §10), and adds :meth:`send_control` to push the id-less link-state control frames
(:class:`LinkReconnectingNotification` / ``Restored`` / ``Unavailable``) to the client.

**Single-accept-for-life (architect L1).** The client connection is held across core
gaps; the listener accepts ONE client and never re-accepts on a core gap. All reconnect
churn is on ``GatewayCoreLink`` (G3-3b), never a client re-accept.

**No payload relay here.** G3-3a is the kernel: accept + emit control frames. The
payload relay loop (client<->core, byte-for-byte) is G3-3b.

**Reuse the transport's ``send`` (security L1).** :meth:`send_control` routes the
id-less frame through the accepted transport's :meth:`CommsSocketTransport.send` — NOT
a bespoke serialize — so it inherits the transport's single-writer lock and the future
client-leg seq/ack wrapping G3-3b adds. A write to a dead client is LOUD (a structlog
warning ``comms.gateway.control_send_failed``) and re-raised (security M2 — never a
silent failure on a security-adjacent path).

**No audit sink in 3a (security M3).** The merged peer-auth reject seam
(``on_peer_rejected``) is a structlog-only stub here (the listener already warns
``comms.socket.peer_uid_rejected`` itself). The durable, signed reject audit row + the
``gateway_peer_auth_rejected_total`` metric land with the gateway's audit sink in
G3-3b/G4.
"""

from __future__ import annotations

from pathlib import Path

import structlog

from alfred.comms_mcp.protocol import (
    LINK_RECONNECTING,
    LINK_RESTORED,
    LINK_UNAVAILABLE,
    LinkReconnectingNotification,
    LinkRestoredNotification,
    LinkUnavailableNotification,
)
from alfred.plugins.comms_socket_transport import (
    CommsSocketListener,
    CommsSocketTransport,
)

log = structlog.get_logger(__name__)

# The gateway's own stable client-facing socket id (spec §10). The one-time client
# dial-target change from ``comms-tui.sock`` -> ``comms-gateway.sock`` is G5's job
# (it already owns "re-point ``alfred chat`` at the gateway"), so 3a only binds the
# gateway-side path.
_GATEWAY_ADAPTER_ID = "gateway"

# A link-control notification is one of the three id-less link.* state-signal models.
LinkControlNotification = (
    LinkReconnectingNotification | LinkRestoredNotification | LinkUnavailableNotification
)

# Map each control-frame model type to its wire method constant, so the id-less frame
# carries the right ``method`` string. The model and the constant are the SAME string
# by construction in ``protocol.py``; this table is the single bind point.
_METHOD_BY_MODEL: dict[type[LinkControlNotification], str] = {
    LinkReconnectingNotification: LINK_RECONNECTING,
    LinkRestoredNotification: LINK_RESTORED,
    LinkUnavailableNotification: LINK_UNAVAILABLE,
}


async def _structlog_only_peer_rejected(peer_uid: int | None) -> None:
    """G3-3a's ``on_peer_rejected`` stub: structlog-only, no audit sink (security M3).

    The listener already emits ``comms.socket.peer_uid_rejected`` at the reject point;
    this callback adds the gateway-scoped breadcrumb. The durable signed reject audit
    row + the ``gateway_peer_auth_rejected_total`` metric are G3-3b/G4.
    """
    log.warning("comms.gateway.peer_uid_rejected", peer_uid=peer_uid)


class GatewayClientListener:
    """Binds the gateway's client-facing socket; accepts ONE client; emits control frames.

    Composes :class:`CommsSocketListener` (``adapter_id="gateway"``). Single-accept-for-
    life: the accepted transport is held across core restarts (architect L1). Adds
    :meth:`send_control` for the id-less link-state frames; reaps on :meth:`aclose`.
    Does NOT relay payload (G3-3b).
    """

    def __init__(self) -> None:
        self._listener = CommsSocketListener(
            adapter_id=_GATEWAY_ADAPTER_ID,
            on_peer_rejected=_structlog_only_peer_rejected,
        )
        self._transport: CommsSocketTransport | None = None

    @property
    def path(self) -> Path:
        """The bound socket path (delegates to the composed listener)."""
        return self._listener.path

    async def bind(self) -> None:
        """Create the 0600 owner-only client-facing socket (delegates)."""
        await self._listener.bind()

    async def accept(self) -> None:
        """Await the single client connection; hold the transport for control-frame emit.

        Single-accept-for-life (architect L1) — the held connection survives core gaps;
        the listener NEVER re-accepts on a core gap.
        """
        self._transport = await self._listener.accept()

    async def send_control(self, notification: LinkControlNotification) -> None:
        """Push an id-less link-state control frame to the accepted client.

        Routes the frame through the accepted transport's :meth:`send` (NOT a bespoke
        serialize — inherits its single-writer lock + the future client-leg seq/ack
        wrapping, security L1). A write to a dead client is LOUD and re-raised
        (``comms.gateway.control_send_failed``; security M2).
        """
        if self._transport is None:
            raise RuntimeError("GatewayClientListener.send_control() called before accept()")
        frame = {
            "jsonrpc": "2.0",
            "method": _METHOD_BY_MODEL[type(notification)],
            "params": notification.model_dump(),
        }
        try:
            await self._transport.send(frame)
            # A successful link-state control frame IS an operator-visible event (a
            # gap opened or closed) — log it at INFO so a reconnect/restore is
            # observable in 3a, not just the failure paths (security SEC-G33A-1). Low
            # volume (one per gap); the pure state machine stays logger-free.
            log.info("comms.gateway.control_sent", method=frame["method"])
        except (BrokenPipeError, ConnectionResetError):
            # The client died mid-conversation. A control frame that cannot be
            # delivered is a real failure on a security-adjacent path (the operator's
            # reconnect banner will be wrong), so it is LOUD + re-raised — never
            # swallowed (CLAUDE.md hard rule #7).
            log.warning(
                "comms.gateway.control_send_failed",
                method=frame["method"],
            )
            raise

    async def aclose(self) -> None:
        """Reap the accepted transport + the listener on EVERY exit path; idempotent."""
        try:
            if self._transport is not None:
                await self._transport.close()
                self._transport = None
        finally:
            # The listener reap MUST run even if the transport close raised — the
            # "every exit path" cleanup contract (CR #271): a transport-close fault
            # must not leak the bound socket / accept state.
            await self._listener.aclose()


__all__ = ["GatewayClientListener"]
