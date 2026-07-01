"""Canonical G7-5 egress metric contract (Spec C PR-A).

ONE registration home for the two operator-observable egress families:

* ``gateway_egress_denied_total{plane,reason}`` — per-plane, per-reason deny counter.
* ``gateway_egress_inflight{plane}`` — a SINGLE shared custom collector that reads
  ``len(conns)`` for each registered plane AT SCRAPE TIME (so it cannot drift from a
  missed ``.set()`` and cannot emit duplicate families). A deliberate, review-approved
  departure from the plain-Gauge ``gateway_adapter_inflight`` precedent — the multi-
  instance producer set (provider proxy + adapter proxy + relay) makes a per-instance
  gauge either double-count or leave stale series on teardown; the register/deregister
  seam here keeps exactly one sample per live plane.

There is deliberately NO ``gateway_egress_up`` gauge: proxy/relay are fail-closed
(a bind failure exits the gateway), so a reachable ``/metrics`` implies they are up;
the adapter plane's presence is read from the existing ``gateway_adapter_up``.
"""

from __future__ import annotations

from collections.abc import Collection, Iterator, Sized
from typing import Final

from prometheus_client import REGISTRY, CollectorRegistry, Counter
from prometheus_client.core import GaugeMetricFamily

from alfred.egress.relay_protocol import EgressRelayDenyReason
from alfred.gateway.egress_audit import EgressDenyReason

_PLANE_LABEL: Final[str] = "plane"
_REASON_LABEL: Final[str] = "reason"
_INFLIGHT_NAME: Final[str] = "gateway_egress_inflight"
_DENIED_NAME: Final[str] = "gateway_egress_denied_total"


class EgressInflightCollector:
    """A single collector yielding one ``gateway_egress_inflight`` sample per plane.

    Each producer registers its live connection set on serve and deregisters on
    teardown; ``collect`` reads ``len`` at scrape time.
    """

    def __init__(self) -> None:
        self._planes: dict[str, Sized] = {}

    def register(self, plane: str, conns: Sized) -> None:
        self._planes[plane] = conns

    def deregister(self, plane: str) -> None:
        self._planes.pop(plane, None)

    def collect(self) -> Iterator[GaugeMetricFamily]:
        family = GaugeMetricFamily(
            _INFLIGHT_NAME,
            "In-flight egress connections per plane (proxy/relay/adapter).",
            labels=[_PLANE_LABEL],
        )
        # Snapshot before iteration: register/deregister mutate _planes from the asyncio
        # event-loop thread while collect() may run on the /metrics daemon thread.
        for plane, conns in list(self._planes.items()):
            family.add_metric([plane], float(len(conns)))
        yield family


def build_denied_counter(registry: CollectorRegistry) -> Counter:
    """Construct the deny counter on ``registry`` (production uses the default REGISTRY).

    sec-355-1 (#333): pre-initialises all 16 CLOSED planexreason children to 0 so that a
    FIRST one-shot deny (counter 0→1) produces a visible non-zero rate — lazy creation on
    the first ``.inc()`` would make the series appear flat-at-1 and the critical
    ``GatewayEgressSecurityDenySpike`` alert would miss the first occurrence entirely.
    """
    counter = Counter(
        _DENIED_NAME,
        "Gateway egress denials, per plane and closed-enum reason (Spec C G7-5).",
        [_PLANE_LABEL, _REASON_LABEL],
        registry=registry,
    )
    # Pre-init all closed plane x reason children to 0 (sec-355-1/#333):
    # proxy and adapter planes use EgressDenyReason (4 values each = 8 children);
    # relay uses EgressRelayDenyReason (8 values = 8 children) — total 16.
    for deny_reason in EgressDenyReason:
        counter.labels(plane="proxy", reason=deny_reason.value)
        counter.labels(plane="adapter", reason=deny_reason.value)
    for relay_reason in EgressRelayDenyReason:
        counter.labels(plane="relay", reason=relay_reason.value)
    return counter


# Production singletons: one collector + one counter on the default REGISTRY.
EGRESS_INFLIGHT_COLLECTOR: Final[EgressInflightCollector] = EgressInflightCollector()
REGISTRY.register(EGRESS_INFLIGHT_COLLECTOR)
GATEWAY_EGRESS_DENIED: Final[Counter] = build_denied_counter(REGISTRY)


def register_egress_inflight(plane: str, conns: Collection[object]) -> None:
    """A producer registers its live ``_conns`` set for the shared inflight collector."""
    EGRESS_INFLIGHT_COLLECTOR.register(plane, conns)


def deregister_egress_inflight(plane: str) -> None:
    """A producer deregisters on teardown so no stale ``inflight{plane}`` series remains."""
    EGRESS_INFLIGHT_COLLECTOR.deregister(plane)


__all__ = [
    "EGRESS_INFLIGHT_COLLECTOR",
    "GATEWAY_EGRESS_DENIED",
    "EgressInflightCollector",
    "build_denied_counter",
    "deregister_egress_inflight",
    "register_egress_inflight",
]
