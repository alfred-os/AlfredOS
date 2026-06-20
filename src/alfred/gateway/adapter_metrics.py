"""Per-adapter Prometheus instrumentation for the gateway adapter supervisor.

G6-2b-1 (Spec B §7 / #288). The always-up gateway supervises each comms-adapter
child; these five collectors let an operator see, per adapter, whether it is
serving, how often it has restarted, whether its breaker is open, how many spawns
are in flight, and whether it is parked awaiting a core-supplied credential.

**Sole ``adapter`` label — cardinality-safe.** Unlike the Spec-A gateway gauges
(:mod:`alfred.gateway.metrics`), which are payload-blind and therefore unlabelled,
these carry EXACTLY one label, ``adapter``. That is safe because the label value is
the ``adapter_id`` the GATEWAY itself chose when it spawned the child (a member of
the closed :data:`alfred.comms_mcp.protocol.adapter_kind` set) — it is NEVER
payload-derived and never per-user, so there is no per-user cardinality surface
that could leak onto a metric label. The label set is bounded by the number of
enabled adapters (a handful), not by traffic.

Module-level construction mirrors :mod:`alfred.gateway.metrics`: each collector
registers on the default :class:`~prometheus_client.CollectorRegistry` at import,
so the per-event path is a pure ``.labels(adapter=...).set()`` / ``.inc()`` call and
a duplicate-name regression surfaces loudly at import time. A LABELLED collector
yields NO sample for a given label value until ``.labels(adapter=...)`` is first
called — the supervisor touches ``.labels()`` on the spawn path so the series
exists before any scrape.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Gauge

# The sole label name. See the module docstring for the cardinality-safety
# rationale (gateway-known adapter_id, never payload-derived).
_ADAPTER_LABEL: Final[str] = "adapter"

ADAPTER_UP: Final[Gauge] = Gauge(
    "gateway_adapter_up",
    "1 while the supervised adapter is in the serving (up) state, else 0.",
    labelnames=[_ADAPTER_LABEL],
)

ADAPTER_RESTARTS: Final[Counter] = Counter(
    "gateway_adapter_restarts",
    "Count of restart attempts the gateway has scheduled for the adapter after a crash.",
    labelnames=[_ADAPTER_LABEL],
)

ADAPTER_BREAKER_OPEN: Final[Gauge] = Gauge(
    "gateway_adapter_breaker_open",
    "1 while the adapter's per-adapter circuit breaker is open (crash-loop), else 0.",
    labelnames=[_ADAPTER_LABEL],
)

ADAPTER_INFLIGHT: Final[Gauge] = Gauge(
    "gateway_adapter_inflight",
    "Number of in-flight spawn/handshake attempts for the adapter (0 once up or down).",
    labelnames=[_ADAPTER_LABEL],
)

ADAPTER_AWAITING_CORE: Final[Gauge] = Gauge(
    "gateway_adapter_awaiting_core",
    "1 while the adapter is parked awaiting a core-supplied credential, else 0.",
    labelnames=[_ADAPTER_LABEL],
)

# Spec B G6-4 (#288): per-adapter ReplayBuffer depth. The Spec-A
# ``gateway_buffer_depth_{frames,bytes}`` gauges (:mod:`alfred.gateway.metrics`) are
# UNLABELLED single-buffer gauges from the one-leg G5 era; G6-4 multiplexes N legs, each
# with its OWN buffer, so these per-adapter gauges let an operator see which leg is full.
# Refreshed AFTER each per-leg buffer mutation, touching ONLY the mutated leg's series
# (perf-H3 — never an O(N) sweep over all legs). Sole label ``adapter`` (cardinality-safe,
# gateway-chosen id; see the module docstring).
ADAPTER_BUFFER_DEPTH_FRAMES: Final[Gauge] = Gauge(
    "gateway_adapter_buffer_depth_frames",
    "Un-acked inbound frames currently retained in this adapter leg's ReplayBuffer.",
    labelnames=[_ADAPTER_LABEL],
)

ADAPTER_BUFFER_DEPTH_BYTES: Final[Gauge] = Gauge(
    "gateway_adapter_buffer_depth_bytes",
    "Sum of retained un-acked inbound payload bytes in this adapter leg's ReplayBuffer.",
    labelnames=[_ADAPTER_LABEL],
)


__all__ = [
    "ADAPTER_AWAITING_CORE",
    "ADAPTER_BREAKER_OPEN",
    "ADAPTER_BUFFER_DEPTH_BYTES",
    "ADAPTER_BUFFER_DEPTH_FRAMES",
    "ADAPTER_INFLIGHT",
    "ADAPTER_RESTARTS",
    "ADAPTER_UP",
]
