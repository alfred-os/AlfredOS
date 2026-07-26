"""Unit tests for the service-set derivation + independent floor guard."""

from __future__ import annotations

import pytest

from tests.e2e import _services


def test_parse_services_splits_and_strips() -> None:
    out = "alfred-postgres\nalfred-redis\nalfred-core\n\n"
    assert _services.parse_services(out) == ("alfred-postgres", "alfred-redis", "alfred-core")


def test_floor_passes_on_full_stack() -> None:
    _services.assert_service_floor(["a", "b", "c", "d", "e", "f"])  # no raise


def test_floor_fails_on_collapsed_config() -> None:
    with pytest.raises(AssertionError, match="below the independent floor"):
        _services.assert_service_floor([])


def test_baseline_app_and_xfail_partition_covers_the_six() -> None:
    # Disjoint AND covering = a genuine partition across the three buckets (CR: assert
    # pairwise-disjoint, not just the union — a service mis-classified into two buckets
    # would still satisfy the union alone).
    baseline = _services.BASELINE_SERVICES
    app = _services.HEALTHY_APP_SERVICES
    xfail = set(_services.XFAIL_SERVICES)
    assert baseline.isdisjoint(app)
    assert baseline.isdisjoint(xfail)
    assert app.isdisjoint(xfail)
    known = baseline | app | xfail
    assert known == {
        "alfred-postgres",
        "alfred-redis",
        "alfred-prometheus",
        "alfred-grafana",
        "alfred-gateway",
        "alfred-core",
    }
    # The ratchet has advanced: both gateway and core are asserted-healthy; xfail is empty.
    assert app == {"alfred-gateway", "alfred-core"}
    assert xfail == set()
    # test-005: an empty xfail bucket makes the isdisjoint asserts trivially true, so ALSO
    # assert the concrete membership + that baseline/app carry the six and are non-empty —
    # the guard that actually catches a mis-move.
    assert baseline == {"alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana"}
    assert (baseline | app | xfail) == {
        "alfred-postgres",
        "alfred-redis",
        "alfred-prometheus",
        "alfred-grafana",
        "alfred-gateway",
        "alfred-core",
    }
