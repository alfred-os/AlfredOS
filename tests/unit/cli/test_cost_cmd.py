"""Unit tests for ``alfred cost report``.

Same isolation strategy as ``test_audit_cmd.py``: in-memory SQLite engine,
monkeypatched bootstrap, ``CliRunner`` against the Typer surface.

SQLite implements ``count``, ``sum``, ``avg``, and ``coalesce`` with
the same semantics the report relies on, so unit tests here exercise
the real SQL path (no aggregate mocking).
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from typer.testing import CliRunner

from alfred.cli import cost_cmd
from alfred.memory.models import AuditEntry, Base


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def cost_cli_setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker[Session]]:
    """Wire ``cost_cmd`` against an in-memory SQLite engine.

    ``COLUMNS=200`` widens Rich's auto-detected terminal so cell-value
    substring assertions are not truncated by the 80-col default.
    """
    monkeypatch.setenv("COLUMNS", "200")
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, future=True)

    settings = MagicMock()
    settings.operator_language = "en-US"
    monkeypatch.setattr(cost_cmd, "load_settings_or_die", lambda: settings)
    monkeypatch.setattr(cost_cmd, "sync_db_url", lambda _settings: "sqlite:///:memory:")
    monkeypatch.setattr(cost_cmd, "create_engine", lambda _url: engine)
    monkeypatch.setattr(engine, "dispose", lambda: None)

    try:
        yield factory
    finally:
        Engine.dispose(engine)


def _insert(
    factory: sessionmaker[Session],
    *,
    actor_user_id: str | None,
    actor_persona: str,
    cost_actual_usd: float | None,
    event: str = "provider.call",
) -> None:
    """Insert one audit row with the provided spend attribution."""
    with factory() as session:
        session.add(
            AuditEntry(
                id=uuid.uuid4(),
                created_at=dt.datetime.now(dt.UTC),
                trace_id="t",
                event=event,
                actor_user_id=actor_user_id,
                actor_persona=actor_persona,
                subject={},
                trust_tier_of_trigger="T2",
                result="success",
                cost_estimate_usd=0.0,
                cost_actual_usd=cost_actual_usd,
                language="en-US",
            )
        )
        session.commit()


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_cost_report_groups_by_persona_descending(
    runner: CliRunner,
    cost_cli_setup: sessionmaker[Session],
) -> None:
    """``--by persona`` (default) groups + sorts by total descending."""
    # Alfred: 0.01 + 0.02 = 0.03 total
    _insert(cost_cli_setup, actor_user_id="alice", actor_persona="alfred", cost_actual_usd=0.01)
    _insert(cost_cli_setup, actor_user_id="alice", actor_persona="alfred", cost_actual_usd=0.02)
    # Lucius: 0.005 total
    _insert(cost_cli_setup, actor_user_id="alice", actor_persona="lucius", cost_actual_usd=0.005)
    # Zero-cost row gets filtered out — confirms the WHERE clause.
    _insert(cost_cli_setup, actor_user_id="alice", actor_persona="alfred", cost_actual_usd=0.0)

    result = runner.invoke(cost_cmd.cost_app, ["report"])

    assert result.exit_code == 0, result.stderr
    assert "persona" in result.stdout  # column heading
    assert "alfred" in result.stdout
    assert "lucius" in result.stdout
    # Alfred row appears before Lucius row (descending by total).
    assert result.stdout.index("alfred") < result.stdout.index("lucius")
    # Sums are formatted to six decimals.
    assert "0.030000" in result.stdout
    assert "0.005000" in result.stdout


def test_cost_report_by_user_groups_by_actor_user_id(
    runner: CliRunner,
    cost_cli_setup: sessionmaker[Session],
) -> None:
    """``--by user`` groups by actor_user_id and coalesces NULLs to a marker."""
    _insert(cost_cli_setup, actor_user_id="alice", actor_persona="alfred", cost_actual_usd=0.1)
    _insert(cost_cli_setup, actor_user_id="bob", actor_persona="alfred", cost_actual_usd=0.05)
    # NULL actor_user_id collapses to the localised "<unknown>" bucket.
    _insert(cost_cli_setup, actor_user_id=None, actor_persona="alfred", cost_actual_usd=0.02)

    result = runner.invoke(cost_cmd.cost_app, ["report", "--by", "user"])

    assert result.exit_code == 0, result.stderr
    assert "user" in result.stdout
    assert "alice" in result.stdout
    assert "bob" in result.stdout
    assert "<unknown>" in result.stdout


# --------------------------------------------------------------------------- #
# Empty state
# --------------------------------------------------------------------------- #


def test_cost_report_empty_window_prints_localised_hint(
    runner: CliRunner,
    cost_cli_setup: sessionmaker[Session],
) -> None:
    """No billable rows → localised hint, no Rich table."""
    del cost_cli_setup
    result = runner.invoke(cost_cmd.cost_app, ["report"])
    assert result.exit_code == 0, result.stderr
    assert "No billable activity" in result.stdout


# --------------------------------------------------------------------------- #
# --since validation (shared with audit_cmd)
# --------------------------------------------------------------------------- #


def test_cost_report_rejects_malformed_since(
    runner: CliRunner,
    cost_cli_setup: sessionmaker[Session],
) -> None:
    """``--since`` reuses the audit duration parser; malformed → exit 2."""
    del cost_cli_setup
    result = runner.invoke(cost_cmd.cost_app, ["report", "--since", "garbage"])
    assert result.exit_code == 2
    assert "Invalid --since" in result.stderr
