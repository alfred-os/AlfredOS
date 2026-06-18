"""Prometheus HTTP exposition for the gateway's default-registry collectors (G6-0).

The gateway registers its collectors on the default ``prometheus_client`` registry at
import (see :mod:`alfred.gateway.metrics`), but nothing has ever *served* them. This
module starts the standard ``prometheus_client`` HTTP exposition so a Prometheus
scrape can read ``gateway_*`` series. It is the first ``/metrics`` endpoint in the
system; the daemon / supervisor can reuse the pattern later.

A metrics-port bind failure is LOUD-AND-CONTINUE (we log loudly and keep the relay
alive, because observability must never drop the chat data plane). The two-tier
healthcheck (:func:`alfred.cli.gateway._commands.healthcheck_gateway`) then marks the
container unhealthy, so a misconfigured port is still surfaced.
"""

from __future__ import annotations

import os
from typing import Final

import structlog
from prometheus_client import start_http_server

log = structlog.get_logger(__name__)

_DEFAULT_METRICS_PORT: Final[int] = 9464
_METRICS_PORT_ENV: Final[str] = "ALFRED_GATEWAY_METRICS_PORT"


def resolve_metrics_port() -> int:
    """Resolve the metrics port from ``ALFRED_GATEWAY_METRICS_PORT`` (default 9464).

    Raises ``ValueError`` loudly on a non-integer value (operator misconfig — never
    silently fall back).
    """
    raw = os.environ.get(_METRICS_PORT_ENV)
    if raw is None or raw == "":
        return _DEFAULT_METRICS_PORT
    return int(raw)


def start_metrics_server(port: int) -> bool:
    """Start the Prometheus exposition on ``port``; return True on success.

    Loud-and-continue on an ``OSError`` (e.g. EADDRINUSE): logs
    ``gateway.metrics.bind_failed`` and returns False rather than raising.
    """
    try:
        start_http_server(port)
    except OSError as exc:
        log.warning("gateway.metrics.bind_failed", port=port, error=repr(exc))
        return False
    log.info("gateway.metrics.serving", port=port)
    return True


__all__ = ["resolve_metrics_port", "start_metrics_server"]
