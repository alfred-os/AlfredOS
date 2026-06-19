"""``GatewayCoreLinkStatusSink`` — the live status-frame sink (G6-2b-2a / #288).

Adapts the :class:`alfred.gateway.adapter_status_emitter.AdapterStatusEmitter`
sink interface (``async def emit(method: str, params: dict) -> None``) to the
SEPARATE status channel on the gateway's core link
(:meth:`alfred.gateway.core_link.GatewayCoreLink.send_status_frame`) — replacing
the 2b-1 fake/recording sink with the live gateway->core leg.

**Payload-blind (CLAUDE.md hard rule #5).** Status frames ride
``send_status_frame`` (a method-bearing JSON-RPC frame over the transport's
``send``), NEVER the opaque T3 ``_payload_relay`` / ``send_payload_unit`` channel.
This sink does no body parse; it forwards the emitter's already-validated
``(method, params)`` straight to the core link.
"""

from __future__ import annotations

from collections.abc import Mapping

from alfred.gateway.core_link import GatewayCoreLink


class GatewayCoreLinkStatusSink:
    """The live ``AdapterStatusEmitter`` sink: forward each frame to the core link."""

    def __init__(self, *, core_link: GatewayCoreLink) -> None:
        self._core_link = core_link

    async def emit(self, method: str, params: Mapping[str, object]) -> None:
        """Forward one built+validated ``gateway.adapter.*`` frame to the core link.

        Loud-drop on a gapped leg is the core link's contract
        (:meth:`GatewayCoreLink.send_status_frame`) — this sink adds no buffering.
        """
        await self._core_link.send_status_frame(method, params)


__all__ = ["GatewayCoreLinkStatusSink"]
