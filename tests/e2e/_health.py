"""Pure health-state classifier for the e2e boot lane.

Oracle = Docker's own health status (independent of the app's notion of health).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum


class ServiceHealth(StrEnum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    NOT_CREATED = "not_created"
    NO_HEALTHCHECK = "no_healthcheck"


_DOCKER_STATUS: Mapping[str, ServiceHealth] = {
    "healthy": ServiceHealth.HEALTHY,
    "unhealthy": ServiceHealth.UNHEALTHY,
    "starting": ServiceHealth.STARTING,
}


def classify_health(inspect: Sequence[Mapping[str, object]]) -> ServiceHealth:
    """Map a parsed ``docker inspect`` result (0-or-1 container objects) to a state.

    Empty list => container does not exist (NOT_CREATED). No ``State.Health`` block =>
    no healthcheck declared (NO_HEALTHCHECK). Any unrecognised health string => STARTING
    (still coming up), never a silent pass.
    """
    if not inspect:
        return ServiceHealth.NOT_CREATED
    state = inspect[0].get("State")
    if not isinstance(state, Mapping):
        return ServiceHealth.NOT_CREATED
    health = state.get("Health")
    if not isinstance(health, Mapping):
        return ServiceHealth.NO_HEALTHCHECK
    status = health.get("Status")
    if isinstance(status, str):
        return _DOCKER_STATUS.get(status, ServiceHealth.STARTING)
    return ServiceHealth.STARTING
