"""Gateway core-link Prometheus instrumentation (Spec A G3-3b-1, #237).

The core-link manager (:mod:`alfred.gateway.core_link`) emits metrics that let an
operator see, at a glance, whether the gateway is holding its core leg up and how
full its un-acked-inbound ReplayBuffer is.

The core-leg liveness metrics (Spec A G3-3b-1):

* :data:`CORE_LINK_UP` — gauge ``gateway_core_link_up``; ``1`` while the core leg
  is UP, ``0`` during a gap.
* :data:`RECONNECT_ATTEMPTS` — counter exposed as
  ``gateway_reconnect_attempts_total``; one increment per core-leg dial attempt
  after a gap.
* :data:`CORE_UNAVAILABLE_SECONDS` — counter exposed as
  ``gateway_core_unavailable_seconds_total``; cumulative seconds the core link
  spent not-UP.
* :data:`PEER_AUTH_REJECTED` — counter ``gateway_peer_auth_rejected_total``; one
  increment per client-leg ``SO_PEERCRED`` peer-uid rejection.

The ReplayBuffer observability gauges (Spec A G4b-2a), refreshed after every buffer
mutation (append / trim / reset / evict):

* :data:`BUFFER_DEPTH_FRAMES` — gauge ``gateway_buffer_depth_frames``; un-acked
  inbound frames currently retained.
* :data:`BUFFER_DEPTH_BYTES` — gauge ``gateway_buffer_depth_bytes``; sum of retained
  un-acked payload bytes.
* :data:`BUFFER_CAP_RATIO` — gauge ``gateway_buffer_cap_ratio``; fullness as a
  fraction of the soft cap (``>= 1.0`` once the breaker latched).
* :data:`CIRCUIT_BREAKER_OPEN` — gauge ``gateway_circuit_breaker_open``; ``1`` while
  the back-pressure breaker is latched, else ``0``.

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

PEER_AUTH_REJECTED: Final[Counter] = Counter(
    "gateway_peer_auth_rejected",
    "Count of client-leg SO_PEERCRED peer-uid rejections at the gateway's client socket.",
)

# Spec A G4b-2a (#237): ReplayBuffer observability. The always-up gateway buffers
# un-acked inbound frames across a core restart; these gauges let an operator watch
# how full that buffer is and whether its back-pressure breaker has latched. The
# core_link refreshes them after every buffer mutation (append/trim/reset/evict).
BUFFER_DEPTH_FRAMES: Final[Gauge] = Gauge(
    "gateway_buffer_depth_frames",
    "Un-acked inbound frames currently retained in the gateway ReplayBuffer.",
)
BUFFER_DEPTH_BYTES: Final[Gauge] = Gauge(
    "gateway_buffer_depth_bytes",
    "Sum of retained un-acked inbound payload bytes in the gateway ReplayBuffer.",
)
BUFFER_CAP_RATIO: Final[Gauge] = Gauge(
    "gateway_buffer_cap_ratio",
    "ReplayBuffer fullness as a fraction of its soft cap (>= 1.0 once the breaker latched).",
)
CIRCUIT_BREAKER_OPEN: Final[Gauge] = Gauge(
    "gateway_circuit_breaker_open",
    "1 while the ReplayBuffer back-pressure breaker is latched, else 0.",
)


__all__ = [
    "BUFFER_CAP_RATIO",
    "BUFFER_DEPTH_BYTES",
    "BUFFER_DEPTH_FRAMES",
    "CIRCUIT_BREAKER_OPEN",
    "CORE_LINK_UP",
    "CORE_UNAVAILABLE_SECONDS",
    "PEER_AUTH_REJECTED",
    "RECONNECT_ATTEMPTS",
]
