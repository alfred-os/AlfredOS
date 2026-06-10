"""``ALFRED_PLUGIN_ADAPTER_ID`` self-id binding (PR-S4-10 review F7, #206).

The launcher-spawn seam writes the per-instance adapter id to
``ALFRED_PLUGIN_ADAPTER_ID``; the var was previously read by nothing (a dead
env). ``alfred_tui.server.bind_self_id_from_env`` now consumes it, binding the
id into structlog contextvars so the plugin's pre-lifecycle stderr logs carry a
self-id. The wire ``lifecycle.start`` remains the authoritative source.
"""

from __future__ import annotations

import json

import pytest
import structlog
from alfred_tui.server import bind_self_id_from_env

from alfred.comms_mcp.plugin_logging import configure_stderr_json_logging


@pytest.fixture(autouse=True)
def _reset() -> object:
    yield
    structlog.contextvars.clear_contextvars()
    structlog.reset_defaults()


def test_binds_adapter_id_when_env_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """A present ``ALFRED_PLUGIN_ADAPTER_ID`` is bound and surfaced in logs."""
    monkeypatch.setenv("ALFRED_PLUGIN_ADAPTER_ID", "tui-abc123")
    configure_stderr_json_logging()

    bound = bind_self_id_from_env()

    assert bound == "tui-abc123"


def test_bound_id_appears_in_log_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The bound self-id rides on every subsequent log line (via contextvars)."""
    monkeypatch.setenv("ALFRED_PLUGIN_ADAPTER_ID", "tui-deadbeef")
    configure_stderr_json_logging()
    bind_self_id_from_env()

    structlog.get_logger("alfred_tui.test").info("pre_lifecycle")

    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["adapter_id"] == "tui-deadbeef"
    assert payload["event"] == "pre_lifecycle"


def test_returns_none_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """No env var -> no binding (a direct ``python -m`` invocation, not launched)."""
    monkeypatch.delenv("ALFRED_PLUGIN_ADAPTER_ID", raising=False)
    assert bind_self_id_from_env() is None


def test_returns_none_when_env_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    """A blank/whitespace var is treated as absent (no bogus empty self-id)."""
    monkeypatch.setenv("ALFRED_PLUGIN_ADAPTER_ID", "   ")
    assert bind_self_id_from_env() is None
