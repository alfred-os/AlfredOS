"""``LegRouter`` — forged/unknown-adapter envelope refusal at gateway ingress (Spec B G6-4).

Keystone K4 (the #1 security add). The multiplexed gateway<->core link carries an
out-of-band envelope ``adapter_id`` so the gateway can route a frame to the right per-leg
buffer / scheduler queue. That id is gateway-controlled (chosen at spawn, a member of the
bounded registered-leg set) — but a forged/replayed frame could name an ``adapter_id`` that
matches NO registered leg. This router is the single admission point that refuses such a
frame:

* it routes to the registered leg's scheduler queue iff ``adapter_id`` is a REGISTERED leg;
* otherwise it REFUSES — :func:`record_unknown_adapter_refusal` (a SENTINEL-labelled metric
  + a loud bounded-field audit row) — and the opaque body is dropped: NEVER default-routed
  to some leg, NEVER silently dropped, NEVER minting a per-id metric label (cardinality DoS
  / audit-injection). The forged body never reaches a buffer or a log.

**arch-M3 (route-only, no new core wire field).** The core already derives ``adapter_id``
from the inbound notification it parses (its G0 ``commit_once`` keys on
``(adapter_id, inbound_id)`` from the notification body), so this gateway-side envelope
``adapter_id`` is used ONLY for LOCAL per-leg routing — no new core-side wire field is
added, and "pure gateway-side" holds. The gateway stays payload-blind: it routes on the
envelope id, never parsing the opaque T3 body.
"""

from __future__ import annotations

import enum

from alfred.gateway.ingress_audit import record_unknown_adapter_refusal
from alfred.gateway.leg_scheduler import GatewayLegScheduler


class RouteOutcome(enum.Enum):
    """The outcome of routing one inbound envelope through :meth:`LegRouter.route`."""

    ROUTED = "routed"
    REFUSED_UNKNOWN_ADAPTER = "refused_unknown_adapter"


class LegRouter:
    """Routes inbound frames to registered legs; refuses a forged/unknown-adapter envelope."""

    def __init__(self, scheduler: GatewayLegScheduler) -> None:
        self._scheduler = scheduler

    def route(self, adapter_id: str, payload: bytes) -> RouteOutcome:
        """Enqueue ``payload`` on ``adapter_id``'s leg iff registered; else REFUSE loud (K4).

        A registered ``adapter_id`` enqueues onto its leg's bounded send queue and returns
        :data:`RouteOutcome.ROUTED`. An unregistered (forged/replayed) id returns
        :data:`RouteOutcome.REFUSED_UNKNOWN_ADAPTER` after a sentinel-labelled metric + a
        loud audit row — the body is dropped, never default-routed / silent-dropped /
        per-id-labelled. The id is validated against the bounded registered set BEFORE any
        use as a routing key or label (the K4 ordering invariant).
        """
        if adapter_id not in self._scheduler.registered_adapters:
            record_unknown_adapter_refusal(adapter_id)
            return RouteOutcome.REFUSED_UNKNOWN_ADAPTER
        self._scheduler.enqueue(adapter_id, payload)
        return RouteOutcome.ROUTED


__all__ = ["LegRouter", "RouteOutcome"]
