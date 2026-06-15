"""Gateway core-link Prometheus instrumentation (Spec A G3-3b-1, #237).

The core-link manager (:mod:`alfred.gateway.core_link`, built in this same PR)
emits three metrics that let an operator see, at a glance, whether the gateway is
holding its core leg up:

* :data:`CORE_LINK_UP` — gauge ``gateway_core_link_up``; ``1`` while the core leg
  is UP, ``0`` during a gap.
* :data:`RECONNECT_ATTEMPTS` — counter exposed as
  ``gateway_reconnect_attempts_total``; one increment per core-leg dial attempt
  after a gap.
* :data:`CORE_UNAVAILABLE_SECONDS` — counter exposed as
  ``gateway_core_unavailable_seconds_total``; cumulative seconds the core link
  spent not-UP.

Module-level construction mirrors :mod:`alfred.comms_mcp.observability`: each
collector registers on the default :class:`~prometheus_client.CollectorRegistry`
at import, so the per-event path is a pure ``set`` / ``inc`` call and a
duplicate-name regression surfaces loudly at import time. No labels are attached —
the gateway is payload-blind and the per-user identity stays core-side, so there
is no per-user cardinality surface that could leak onto a metric label.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Gauge

CORE_LINK_UP: Final[Gauge] = Gauge(
    "gateway_core_link_up",
    "1 when the gateway's core link is UP, 0 during a gap.",
)

RECONNECT_ATTEMPTS: Final[Counter] = Counter(
    "gateway_reconnect_attempts",
    "Count of core-leg dial attempts after a gap.",
)

CORE_UNAVAILABLE_SECONDS: Final[Counter] = Counter(
    "gateway_core_unavailable_seconds",
    "Cumulative seconds the core link spent not-UP.",
)


__all__ = [
    "CORE_LINK_UP",
    "CORE_UNAVAILABLE_SECONDS",
    "RECONNECT_ATTEMPTS",
]
