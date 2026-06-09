"""Comms-MCP Prometheus instrumentation (PR-S4-8, #152 — Task 62).

Spec §13 done-item 7 names four metrics the comms path must expose:

* :data:`INBOUND_DISPATCH_HISTOGRAM` — ``alfred_comms_inbound_dispatch_seconds``;
  wall time of one ``_on_post_handshake_method`` comms-notification dispatch.
* :data:`QUARANTINED_EXTRACT_HISTOGRAM` —
  ``alfred_comms_quarantined_extract_seconds``; wall time of one
  :meth:`Orchestrator.quarantined_extract` call.
* :data:`BURST_LIMITER_WAIT_HISTOGRAM` —
  ``alfred_comms_burst_limiter_wait_seconds``; observed ``Acquired.waited_seconds``.
* :data:`HANDLER_FAILURES_COUNTER` — ``alfred_comms_handler_failures_total``;
  one increment per ``COMMS_HANDLER_FAILED_FIELDS`` emit.

Module-level construction mirrors :mod:`alfred.supervisor.observability`: a
:class:`prometheus_client.Histogram` / :class:`Counter` registers on the default
:class:`CollectorRegistry` at import, so the per-event path is a pure
``observe`` / ``inc`` call and a duplicate-name regression surfaces loudly at
import time. No labels are attached — these are aggregate-percentile metrics, so
there is no per-user cardinality surface to firewall (the per-user identity stays
host-side and never reaches a label, per the §8.2 identity invariant).
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Histogram

# Sub-second-skewed buckets: comms dispatch + extract are expected to complete in
# tens of milliseconds; the burst-limiter wait can reach the 30s drop ceiling, so
# the bound set straddles that. ``+Inf`` is appended automatically.
_LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.001,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    float("inf"),
)

INBOUND_DISPATCH_HISTOGRAM: Final[Histogram] = Histogram(
    "alfred_comms_inbound_dispatch_seconds",
    "Wall time of one comms-notification dispatch through _on_post_handshake_method.",
    buckets=_LATENCY_BUCKETS,
)

QUARANTINED_EXTRACT_HISTOGRAM: Final[Histogram] = Histogram(
    "alfred_comms_quarantined_extract_seconds",
    "Wall time of one Orchestrator.quarantined_extract call on the comms inbound path.",
    buckets=_LATENCY_BUCKETS,
)

BURST_LIMITER_WAIT_HISTOGRAM: Final[Histogram] = Histogram(
    "alfred_comms_burst_limiter_wait_seconds",
    "Backpressure wait an inbound message incurred at the per-(user, persona) burst limiter.",
    buckets=_LATENCY_BUCKETS,
)

HANDLER_FAILURES_COUNTER: Final[Counter] = Counter(
    "alfred_comms_handler_failures_total",
    "Count of comms notification-handler exceptions (one per COMMS_HANDLER_FAILED_FIELDS emit).",
)


def record_inbound_dispatch_seconds(seconds: float) -> None:
    """Observe one comms-notification dispatch duration."""
    INBOUND_DISPATCH_HISTOGRAM.observe(seconds)


def record_quarantined_extract_seconds(seconds: float) -> None:
    """Observe one quarantined-extract duration on the comms inbound path."""
    QUARANTINED_EXTRACT_HISTOGRAM.observe(seconds)


def record_burst_limiter_wait_seconds(seconds: float) -> None:
    """Observe one burst-limiter backpressure wait (``Acquired.waited_seconds``)."""
    BURST_LIMITER_WAIT_HISTOGRAM.observe(seconds)


def record_handler_failure() -> None:
    """Increment the comms handler-failure counter (one per handler exception)."""
    HANDLER_FAILURES_COUNTER.inc()


__all__ = [
    "BURST_LIMITER_WAIT_HISTOGRAM",
    "HANDLER_FAILURES_COUNTER",
    "INBOUND_DISPATCH_HISTOGRAM",
    "QUARANTINED_EXTRACT_HISTOGRAM",
    "record_burst_limiter_wait_seconds",
    "record_handler_failure",
    "record_inbound_dispatch_seconds",
    "record_quarantined_extract_seconds",
]
