"""``alfred.gateway.metrics`` exposes the three core-link collectors (G3-3b-1)."""

from __future__ import annotations

from prometheus_client import REGISTRY, Counter, Gauge

from alfred.gateway import metrics


def test_core_link_up_is_a_gauge() -> None:
    assert isinstance(metrics.CORE_LINK_UP, Gauge)


def test_core_link_up_registered_under_its_exposed_name() -> None:
    # A Gauge's exposed series name is unchanged (no suffix).
    assert REGISTRY.get_sample_value("gateway_core_link_up") is not None


def test_reconnect_attempts_is_a_counter() -> None:
    assert isinstance(metrics.RECONNECT_ATTEMPTS, Counter)


def test_reconnect_attempts_exposes_total_suffix() -> None:
    # prometheus appends ``_total`` to a Counter's exposed series.
    assert REGISTRY.get_sample_value("gateway_reconnect_attempts_total") is not None


def test_core_unavailable_seconds_is_a_counter() -> None:
    assert isinstance(metrics.CORE_UNAVAILABLE_SECONDS, Counter)


def test_core_unavailable_seconds_exposes_total_suffix() -> None:
    assert REGISTRY.get_sample_value("gateway_core_unavailable_seconds_total") is not None


def test_peer_auth_rejected_is_a_counter() -> None:
    assert isinstance(metrics.PEER_AUTH_REJECTED, Counter)


def test_peer_auth_rejected_exposes_total_suffix() -> None:
    assert REGISTRY.get_sample_value("gateway_peer_auth_rejected_total") is not None
