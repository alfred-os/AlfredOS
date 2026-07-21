"""The exact set of collectors the core /metrics exposes — one source of truth (#470).

Importing this module registers all ten on the DEFAULT registry at import (side effect of
importing the four observability modules), so build_core_registry has live references AND
alfred_quarantine_capability_revoked_total reads 0 from t=0. The collectors are NOT moved off
the default registry (the duplicate-name-loud property + the gateway process depend on them).
"""

from __future__ import annotations

from typing import Final

from prometheus_client import CollectorRegistry
from prometheus_client.registry import Collector

from alfred.comms_mcp.observability import (
    BURST_LIMITER_WAIT_HISTOGRAM,
    HANDLER_FAILURES_COUNTER,
    INBOUND_DISPATCH_HISTOGRAM,
    QUARANTINED_EXTRACT_HISTOGRAM,
)
from alfred.plugins._observability import (
    DISPATCH_DURATION,
    INBOUND_SCANNER_SCAN_DURATION,
    OUTBOUND_DLP_SCAN_DURATION,
    PLUGIN_SPAWN_DURATION,
)
from alfred.security.observability import CAPABILITY_REVOKED_COUNTER
from alfred.supervisor.observability import ACTION_DURATION_HISTOGRAM

CORE_OWNED_COLLECTORS: Final[tuple[Collector, ...]] = (
    CAPABILITY_REVOKED_COUNTER,
    INBOUND_DISPATCH_HISTOGRAM,
    QUARANTINED_EXTRACT_HISTOGRAM,
    BURST_LIMITER_WAIT_HISTOGRAM,
    HANDLER_FAILURES_COUNTER,
    ACTION_DURATION_HISTOGRAM,
    DISPATCH_DURATION,
    OUTBOUND_DLP_SCAN_DURATION,
    INBOUND_SCANNER_SCAN_DURATION,
    PLUGIN_SPAWN_DURATION,
)


def build_core_registry() -> CollectorRegistry:
    """A dedicated registry holding core-owned collectors (drops stale gateway_*)."""
    registry = CollectorRegistry()
    for collector in CORE_OWNED_COLLECTORS:
        registry.register(collector)
    return registry


__all__ = ["CORE_OWNED_COLLECTORS", "build_core_registry"]
