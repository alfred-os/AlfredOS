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


def test_baseline_and_xfail_partition_covers_the_six() -> None:
    known = _services.BASELINE_SERVICES | set(_services.XFAIL_SERVICES)
    assert known == {
        "alfred-postgres",
        "alfred-redis",
        "alfred-prometheus",
        "alfred-grafana",
        "alfred-gateway",
        "alfred-core",
    }
