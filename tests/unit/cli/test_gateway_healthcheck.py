"""`alfred gateway healthcheck` — two-tier liveness/readiness probe (G6-0)."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import _commands, gateway_app


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


def _patch_fetch(monkeypatch: pytest.MonkeyPatch, text: str | None) -> None:
    def _fake_fetch(port: int) -> str:
        if text is None:
            raise OSError("connection refused")
        return text

    monkeypatch.setattr(_commands, "_fetch_metrics_text", _fake_fetch)


def test_healthcheck_registered() -> None:
    result = CliRunner().invoke(gateway_app, ["--help"])
    assert result.exit_code == 0
    assert "healthcheck" in result.stdout


def test_healthy_when_breaker_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(
        monkeypatch,
        "# TYPE gateway_circuit_breaker_open gauge\ngateway_circuit_breaker_open 0.0\n",
    )
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_healthy_when_core_down_but_breaker_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, "gateway_core_link_up 0.0\ngateway_circuit_breaker_open 0.0\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_healthy_when_breaker_metric_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, "gateway_core_link_up 0.0\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_ignores_help_comment_line(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(
        monkeypatch,
        "# HELP gateway_circuit_breaker_open 1 while latched\ngateway_circuit_breaker_open 0.0\n",
    )
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_unhealthy_when_breaker_open(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, "gateway_circuit_breaker_open 1.0\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 1


def test_unhealthy_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, None)
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 1


def test_malformed_sample_is_not_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_fetch(monkeypatch, "gateway_circuit_breaker_open NaNgarbage extra\n")
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code in (0, 1)
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_malformed_sample_treated_as_not_latched(monkeypatch: pytest.MonkeyPatch) -> None:
    # A garbled breaker value must parse as NOT latched (healthy), not silently unhealthy.
    _patch_fetch(monkeypatch, "gateway_circuit_breaker_open NaNgarbage\n")
    assert CliRunner().invoke(gateway_app, ["healthcheck"]).exit_code == 0


def test_bad_port_env_is_unhealthy_not_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    # A malformed ALFRED_GATEWAY_METRICS_PORT must exit unhealthy, never raw-traceback.
    monkeypatch.setenv("ALFRED_GATEWAY_METRICS_PORT", "notaport")
    result = CliRunner().invoke(gateway_app, ["healthcheck"])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
