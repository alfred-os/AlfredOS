"""Unit tests for the gateway's back-compat Prometheus exposition shim (G6-0 / #470).

The exposition logic itself was promoted to ``alfred.observability.metrics_server``
(and is fully covered there — see ``tests/unit/observability/test_metrics_server.py``).
These tests confirm the shim re-exports the SAME callables and that the gateway's own
env-var/default continue to work through it — no behavior change for existing callers.
"""

from __future__ import annotations

import pytest

from alfred.gateway import metrics_server
from alfred.observability import metrics_server as observability_metrics_server


def test_resolve_port_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_GATEWAY_METRICS_PORT", raising=False)
    assert metrics_server.resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464) == 9464


def test_resolve_port_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "9999")
    assert metrics_server.resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464) == 9999


def test_resolve_port_rejects_nonint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "notaport")
    with pytest.raises(ValueError):
        metrics_server.resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464)


def test_resolve_port_rejects_out_of_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "99999")
    with pytest.raises(ValueError):
        metrics_server.resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464)
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "0")
    with pytest.raises(ValueError):
        metrics_server.resolve_metrics_port("ALFRED_GATEWAY_METRICS_PORT", 9464)


def test_start_calls_prometheus_and_returns_true(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(
        observability_metrics_server, "start_http_server", lambda port: calls.append(port)
    )
    assert metrics_server.start_metrics_server(9464) is True
    assert calls == [9464]


def test_start_loud_and_continue_on_bind_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(port: int) -> None:
        raise OSError("address in use")

    monkeypatch.setattr(observability_metrics_server, "start_http_server", _boom)
    assert metrics_server.start_metrics_server(9464) is False  # loud-and-continue, no raise


def test_gateway_exposition_has_no_per_user_labels() -> None:
    """Leak guard (security): the gateway /metrics endpoint is unauthenticated and the
    gateway is payload-blind, so its served series must carry NO per-user / per-plugin
    label keys. Checked in a SUBPROCESS that imports the REAL gateway process import
    graph (catches transitive leaks); an in-process check would be polluted by modules
    pytest already imported.
    """
    import os
    import subprocess
    import sys

    code = (
        "import alfred.gateway.process, alfred.gateway.metrics, alfred.gateway.metrics_server\n"
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
