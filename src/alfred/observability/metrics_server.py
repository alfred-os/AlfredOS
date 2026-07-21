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

# sec-001: the destination host is a module CONSTANT, never a parameter. This module is
# imported on the core boot path, and the in-core HTTP-egress AST ratchet exempts
# ``http.client`` — so the "no SSRF surface" guarantee has to come from CONSTRUCTION (the
# caller cannot express a non-loopback destination), not from a docstring convention every
# call site must remember. Every consumer (daemon healthcheck, gateway healthcheck,
# ``alfred gateway egress``) scrapes its OWN process over loopback; there is no legitimate
# cross-host scrape — Prometheus does that itself, from outside.
_LOOPBACK_HOST: Final[str] = "127.0.0.1"

# The only status a Prometheus exposition ever answers with. Anything else (a 404 from a
# non-metrics HTTP server squatting on the port, a 500 from a wedged handler) is a FAILED
# probe — see fetch_metrics_text.
_HTTP_OK: Final[int] = 200

# sec-005: a bounded read. ``.read()`` with no limit lets whatever answers on the metrics
# port stream unbounded bytes into the healthcheck process's memory. A real exposition is
# orders of magnitude below this ceiling (the core serves ten families), so exceeding it is
# an anomaly worth failing LOUD on rather than silently truncating into a half-parsed body.
_MAX_METRICS_BYTES: Final[int] = 8 * 1024 * 1024

# The env var + fallback port for the CORE daemon's Prometheus exposition (#470). ONE source
# of truth for the pair: the daemon boot seam (``alfred.cli.daemon._commands.
# _start_core_metrics_server``) binds it and ``alfred daemon healthcheck``
# (``alfred.cli.daemon._healthcheck``) probes it — if those two ever drifted apart, the
# healthcheck would go permanently red and the only mechanism that surfaces a metrics bind
# failure would be dead (rev-001 / sec-003). They live HERE rather than in the daemon's
# ``_commands.py`` (which is where the gateway's twin pair lives, next to its own start
# call) because ``_healthcheck.py`` must stay cheap to import: it runs every 15s under the
# container healthcheck, and importing the daemon boot graph to read two constants would
# make an operator pay the whole supervisor/comms/security import chain per probe.
CORE_METRICS_PORT_ENV: Final[str] = "ALFRED_CORE_METRICS_PORT"
CORE_METRICS_DEFAULT_PORT: Final[int] = 9465


def resolve_metrics_port(env_var: str, default: int) -> int:
    """Resolve a metrics port from ``env_var`` (default ``default``).

    Raises ``ValueError`` loudly on a bad value — never a silent fall back to the default,
    which would serve on a port the operator did not ask for. Both refusal arms (non-integer
    and out-of-range) name the env var, the accepted range, AND the offending value, so the
    message is directly actionable when a caller surfaces it to an operator (dx-001).
    """
    raw = os.environ.get(env_var)
    if raw is None or raw == "":
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{env_var} must be an integer in 1..65535, got {raw!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{env_var} must be an integer in 1..65535, got {port}")
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


def fetch_metrics_text(port: int) -> str:
    """GET the /metrics exposition from ``127.0.0.1:port`` over http.client.

    The host is the module constant :data:`_LOOPBACK_HOST` and is deliberately NOT a
    parameter — the no-SSRF property is structural, not a convention (sec-001).

    Raises ``OSError`` on every failure mode, so each consumer's single ``except OSError``
    stays the whole catch surface and their "never a raw traceback" contract holds:

    * unreachable / torn socket — ``OSError`` from ``http.client`` directly;
    * a non-HTTP responder squatting on the port — ``http.client.HTTPException`` (e.g.
      ``BadStatusLine`` / ``IncompleteRead``) is NOT an ``OSError`` subclass, so it is
      re-raised (chained) as one;
    * a non-200 answer — a 404/500 body is NOT an exposition. Without this check the
      healthcheck reads a wedged or mis-routed endpoint as HEALTHY, which is precisely the
      failure it exists to catch (CR-A);
    * an over-large body — see :data:`_MAX_METRICS_BYTES` (sec-005).

    Lossless-safe decode so a non-UTF-8 body never raises.
    """
    conn = http.client.HTTPConnection(_LOOPBACK_HOST, port, timeout=_FETCH_TIMEOUT_S)
    try:
        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        if resp.status != _HTTP_OK:
            raise OSError(f"metrics endpoint answered HTTP {resp.status}, expected {_HTTP_OK}")
        # Read one byte PAST the ceiling so "exactly at the cap" and "over the cap" are
        # distinguishable — a plain read(cap) would silently truncate an over-large body.
        body: bytes = resp.read(_MAX_METRICS_BYTES + 1)
        if len(body) > _MAX_METRICS_BYTES:
            raise OSError(f"metrics exposition exceeded {_MAX_METRICS_BYTES} bytes")
    except http.client.HTTPException as exc:
        raise OSError(f"malformed HTTP response from metrics endpoint: {exc!r}") from exc
    finally:
        conn.close()
    return body.decode("utf-8", errors="replace")


__all__ = [
    "CORE_METRICS_DEFAULT_PORT",
    "CORE_METRICS_PORT_ENV",
    "fetch_metrics_text",
    "resolve_metrics_port",
    "start_metrics_server",
]
