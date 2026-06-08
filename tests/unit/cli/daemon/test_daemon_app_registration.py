"""alfred --help lists daemon; alfred daemon --help lists subcommands (#174)."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


def test_daemon_appears_in_root_help() -> None:
    from alfred.cli.main import app

    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "daemon" in result.stdout


def test_daemon_subcommands_listed() -> None:
    from alfred.cli.main import app

    result = CliRunner().invoke(app, ["daemon", "--help"])
    assert result.exit_code == 0
    assert "start" in result.stdout
    assert "stop" in result.stdout
    assert "status" in result.stdout
