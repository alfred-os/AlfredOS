"""Tests for the per-adapter gateway metrics (G6-2b-1, Spec B §7 / #288).

Pins (correction #4 / SEC-2):

* the EXACT metric names from spec §7 exist on the default registry;
* each carries EXACTLY the sole ``adapter`` label (cardinality-safe — ``adapter_id``
  is gateway-known, never payload-derived);
* the counter is exposed under its ``_total`` suffix;
* a labelled collector yields NO sample until ``.labels(adapter=...)`` is first
  called — so the tests call ``.labels()`` before asserting a sample exists.
"""

from __future__ import annotations

import pytest
from prometheus_client import REGISTRY, Counter, Gauge

from alfred.gateway.adapter_metrics import (
    ADAPTER_AWAITING_CORE,
    ADAPTER_BREAKER_OPEN,
    ADAPTER_INFLIGHT,
    ADAPTER_RESTARTS,
    ADAPTER_UP,
)

_A = "discord"


@pytest.mark.parametrize(
    ("gauge", "name"),
    [
        (ADAPTER_UP, "gateway_adapter_up"),
        (ADAPTER_BREAKER_OPEN, "gateway_adapter_breaker_open"),
        (ADAPTER_INFLIGHT, "gateway_adapter_inflight"),
        (ADAPTER_AWAITING_CORE, "gateway_adapter_awaiting_core"),
    ],
)
def test_gauge_exists_with_sole_adapter_label(gauge: Gauge, name: str) -> None:
    # A labelled collector yields a sample only AFTER .labels() is first touched, so
    # touch it before asserting the sample exists.
    gauge.labels(adapter=_A).set(1)
    assert REGISTRY.get_sample_value(name, {"adapter": _A}) == 1.0
    # Sole label (cardinality-safe: gateway-known adapter_id, never payload-derived).
    assert gauge._labelnames == ("adapter",)


def test_restarts_counter_exposed_as_total_with_sole_adapter_label() -> None:
    assert isinstance(ADAPTER_RESTARTS, Counter)
    assert ADAPTER_RESTARTS._labelnames == ("adapter",)
    # The counter is exposed under its ``_total`` suffix; touch .labels() first so the
    # series exists, then assert the exposed sample name.
    before = REGISTRY.get_sample_value("gateway_adapter_restarts_total", {"adapter": _A}) or 0.0
    ADAPTER_RESTARTS.labels(adapter=_A).inc()
    after = REGISTRY.get_sample_value("gateway_adapter_restarts_total", {"adapter": _A})
    assert after == before + 1.0


def test_no_collector_carries_a_per_user_label() -> None:
    """Cardinality-safety: the ONLY label any collector carries is ``adapter``.

    A per-user / payload-derived label would be a cardinality + privacy leak; pin that
    the sole label across all five collectors is the gateway-known ``adapter``.
    """
    for collector in (
        ADAPTER_UP,
        ADAPTER_BREAKER_OPEN,
        ADAPTER_INFLIGHT,
        ADAPTER_AWAITING_CORE,
        ADAPTER_RESTARTS,
    ):
        assert collector._labelnames == ("adapter",)
