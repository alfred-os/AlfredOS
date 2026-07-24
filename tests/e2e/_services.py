"""Service-set derivation for the e2e boot lane, with an independent floor guard.

The asserted set is derived at runtime from ``docker compose config --services`` so a
future service (e.g. Qdrant) is observed automatically. The non-vacuity floor is an
INDEPENDENT literal — never re-derived from the same command being validated — so a
collapsed ``docker compose config`` cannot yield ``0 == 0`` and false-green (test-003).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

# Independent literal floor: docker-compose.yaml ships exactly these 6 services (no
# `profiles:` keys). If it collapses to fewer, the lane must RED, not pass vacuously.
MIN_SERVICE_FLOOR = 6

BASELINE_SERVICES: frozenset[str] = frozenset(
    {"alfred-postgres", "alfred-redis", "alfred-prometheus", "alfred-grafana"}
)

# Known-blocked services -> the roadmap issue that un-blocks them (refs finalized in Task 10).
# Shrinks toward empty as blockers land (the ratchet).
XFAIL_SERVICES: Mapping[str, str] = {
    "alfred-gateway": "#A",
    "alfred-core": "#B",
}


def parse_services(config_services_stdout: str) -> tuple[str, ...]:
    """Split the newline-delimited ``docker compose config --services`` output."""
    return tuple(line.strip() for line in config_services_stdout.splitlines() if line.strip())


def assert_service_floor(services: Sequence[str]) -> None:
    """Fail loud if fewer than ``MIN_SERVICE_FLOOR`` services were discovered."""
    assert len(services) >= MIN_SERVICE_FLOOR, (
        f"discovered {len(services)} compose service(s) {tuple(services)!r} — below the "
        f"independent floor of {MIN_SERVICE_FLOOR}; `docker compose config` may have collapsed."
    )
