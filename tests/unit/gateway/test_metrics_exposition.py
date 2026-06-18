"""A real bind+GET+parse round-trip for the gateway exposition (G6-0)."""

from __future__ import annotations

import urllib.request

from alfred.gateway import metrics
from alfred.gateway.metrics_server import start_metrics_server


def _free_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_metrics_endpoint_serves_gateway_series() -> None:
    metrics.CIRCUIT_BREAKER_OPEN.set(0)
    port = _free_port()
    assert start_metrics_server(port) is True
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2.0) as resp:
        body = resp.read().decode("utf-8")
    assert "# TYPE gateway_circuit_breaker_open gauge" in body
    assert "gateway_circuit_breaker_open 0.0" in body
