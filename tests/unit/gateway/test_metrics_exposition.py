"""A real bind+GET+parse round-trip for the gateway exposition (G6-0) + its leak guard.

The exposition MECHANISM (``resolve_metrics_port`` / ``start_metrics_server`` /
``fetch_metrics_text``) lives in ``alfred.observability.metrics_server`` and is covered
there — see ``tests/unit/observability/test_metrics_server.py``. #470 deleted the
``alfred.gateway.metrics_server`` re-export shim (it had no external consumer and, because
``resolve_metrics_port`` gained two required parameters, it was not actually back-compatible),
so this module dials the promoted seam directly. What is GATEWAY-specific — and therefore
lives here — is the round-trip over a real socket and the served-label leak guard.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import urllib.request

from alfred.gateway import metrics
from alfred.observability.metrics_server import start_metrics_server


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


def test_gateway_exposition_has_no_per_user_labels() -> None:
    """Leak guard (security): the gateway /metrics endpoint is unauthenticated and the
    gateway is payload-blind, so its served series must carry NO per-user / per-plugin
    label keys. Checked in a SUBPROCESS that imports the REAL gateway process import
    graph (catches transitive leaks); an in-process check would be polluted by modules
    pytest already imported.
    """
    code = (
        "import alfred.gateway.process, alfred.gateway.metrics\n"
        "import alfred.observability.metrics_server\n"
        "from prometheus_client import REGISTRY\n"
        "forbidden = {'user_id_bucket', 'user_id', 'plugin', 'plugin_id', 'persona'}\n"
        "bad = sorted({k for fam in REGISTRY.collect() for s in fam.samples "
        "for k in s.labels if k in forbidden})\n"
        "assert not bad, f'gateway /metrics leaks per-user/per-plugin labels: {bad}'\n"
        "print('OK')\n"
    )
    result = subprocess.run(  # noqa: S603 - hardcoded code string, no untrusted input
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={**os.environ, "ALFRED_ENVIRONMENT": "test"},
        timeout=20,  # bound runtime: an import-path regression must fail, not hang CI (CR #289)
    )
    assert result.returncode == 0, (
        f"gateway exposition leak-guard failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
