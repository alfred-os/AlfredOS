"""Prometheus HTTP exposition + loopback fetch — shared by the gateway and the core daemon.

Loud-and-continue on a bind failure (observability must never drop a data plane); a
healthcheck surfaces the degraded endpoint. Promoted from alfred.gateway.metrics_server so
the connectivity-free core daemon can reuse it (its second consumer) — #470.
"""

from __future__ import annotations

import http.client
import os
from typing import Final

import structlog
from prometheus_client import CollectorRegistry, start_http_server

log = structlog.get_logger(__name__)

_FETCH_TIMEOUT_S: Final[float] = 2.0


def resolve_metrics_port(env_var: str, default: int) -> int:
    """Resolve a metrics port from ``env_var`` (default ``default``).

    Raises loudly on a bad value.
    """
    raw = os.environ.get(env_var)
    if raw is None or raw == "":
        return default
    port = int(raw)  # ValueError on a non-int surfaces loud.
    if not 1 <= port <= 65535:
        raise ValueError(f"{env_var} must be in 1..65535, got {port}")
    return port


def start_metrics_server(port: int, registry: CollectorRegistry | None = None) -> bool:
    """Start the Prometheus exposition on ``port`` serving ``registry`` (default registry if None).

    Loud-and-continue on OSError (e.g. EADDRINUSE): logs ``metrics.bind_failed`` and returns False.
    """
    try:
        if registry is None:
            start_http_server(port)
        else:
            start_http_server(port, registry=registry)
    except OSError as exc:
        log.warning("metrics.bind_failed", port=port, error=repr(exc))
        return False
    log.info("metrics.serving", port=port)
    return True


def fetch_metrics_text(host: str, port: int) -> str:
    """GET the /metrics exposition over loopback via http.client (fixed host — no SSRF surface).

    Raises OSError when unreachable. Lossless-safe decode so a non-UTF-8 body never raises.
    """
    conn = http.client.HTTPConnection(host, port, timeout=_FETCH_TIMEOUT_S)
    try:
        conn.request("GET", "/metrics")
        body: bytes = conn.getresponse().read()
    finally:
        conn.close()
    return body.decode("utf-8", errors="replace")


__all__ = ["fetch_metrics_text", "resolve_metrics_port", "start_metrics_server"]
