"""Unit tests for the gateway Prometheus HTTP exposition wrapper (G6-0)."""

from __future__ import annotations

import pytest

from alfred.gateway import metrics_server


def test_resolve_port_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_GATEWAY_METRICS_PORT", raising=False)
    assert metrics_server.resolve_metrics_port() == 9464


def test_resolve_port_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "9999")
    assert metrics_server.resolve_metrics_port() == 9999


def test_resolve_port_rejects_nonint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "notaport")
    with pytest.raises(ValueError):
        metrics_server.resolve_metrics_port()


def test_start_calls_prometheus_and_returns_true(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(metrics_server, "start_http_server", lambda port: calls.append(port))
    assert metrics_server.start_metrics_server(9464) is True
    assert calls == [9464]


def test_start_loud_and_continue_on_bind_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(port: int) -> None:
        raise OSError("address in use")

    monkeypatch.setattr(metrics_server, "start_http_server", _boom)
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
    )
    assert result.returncode == 0, (
        f"gateway exposition leak-guard failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
