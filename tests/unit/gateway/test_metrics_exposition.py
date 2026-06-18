"""A real bind+GET+parse round-trip for the gateway exposition (G6-0)."""

from __future__ import annotations

import socket
import urllib.request

from alfred.gateway import metrics
from alfred.gateway.metrics_server import start_metrics_server


def _serve_on_free_port() -> int:
    """Bind the metrics server on a free loopback port, retrying past TOCTOU races.

    Probing a port then re-binding it has a free-port race (the probe releases the port
    before ``start_metrics_server`` claims it, so another listener can steal it). The
    wrapper returns ``False`` on an ``EADDRINUSE`` collision, so we retry on a fresh
    port rather than risk a flaky ``EADDRINUSE`` (CodeRabbit #289 follow-up).
    """
    for _ in range(20):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        if start_metrics_server(port):
            return port
    raise RuntimeError("could not bind the gateway metrics server on a free loopback port")


def test_metrics_endpoint_serves_gateway_series() -> None:
    metrics.CIRCUIT_BREAKER_OPEN.set(0)
    port = _serve_on_free_port()
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2.0) as resp:
        body = resp.read().decode("utf-8")
    assert "# TYPE gateway_circuit_breaker_open gauge" in body
    assert "gateway_circuit_breaker_open 0.0" in body
