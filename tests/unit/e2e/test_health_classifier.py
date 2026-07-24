"""Self-test of the health-state classifier (prove the detector works before trusting it)."""

from __future__ import annotations

from tests.e2e._health import ServiceHealth, classify_health


def _with_health(status: str) -> list[dict[str, object]]:
    return [{"State": {"Status": "running", "Health": {"Status": status}}}]


def test_healthy_payload() -> None:
    assert classify_health(_with_health("healthy")) is ServiceHealth.HEALTHY


def test_unhealthy_payload() -> None:
    assert classify_health(_with_health("unhealthy")) is ServiceHealth.UNHEALTHY


def test_starting_payload_is_starting_not_unhealthy() -> None:
    # Under restart: unless-stopped a boot-refusing service crash-loops as perpetual
    # `starting`, NOT `unhealthy` (review ops-004). The classifier must not conflate them.
    assert classify_health(_with_health("starting")) is ServiceHealth.STARTING


def test_unknown_status_is_starting_never_a_silent_pass() -> None:
    # An unrecognised Docker health string must degrade to STARTING (still coming up),
    # never to HEALTHY (review test-engineer: the fallback branch must be covered).
    assert classify_health(_with_health("reloading")) is ServiceHealth.STARTING


def test_empty_inspect_is_not_created() -> None:
    assert classify_health([]) is ServiceHealth.NOT_CREATED


def test_no_health_block_is_no_healthcheck() -> None:
    assert classify_health([{"State": {"Status": "running"}}]) is ServiceHealth.NO_HEALTHCHECK
