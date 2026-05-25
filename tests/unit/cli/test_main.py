"""Tests for the Typer-based `alfred` CLI."""

from __future__ import annotations

from pytest import MonkeyPatch
from typer.testing import CliRunner

from alfred.cli.main import app

runner = CliRunner()


def test_alfred_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "chat" in result.stdout
    assert "status" in result.stdout


def test_alfred_status_exits_zero(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "deepseek" in result.stdout.lower()


def test_alfred_migrate_command_is_registered() -> None:
    # Verifies the subcommand is wired into the Typer app and its docstring
    # mentions alembic/migrations so an operator running ``alfred migrate
    # --help`` lands on something useful. Actually running alembic against a
    # live DB is covered by the smoke test in Task 17.
    result = runner.invoke(app, ["migrate", "--help"])
    assert result.exit_code == 0
    assert "migrations" in result.stdout.lower() or "alembic" in result.stdout.lower()
