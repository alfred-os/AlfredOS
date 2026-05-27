"""Unit tests for ``alfred audit log``.

Isolation strategy mirrors ``tests/unit/identity/test_cli.py``: spin up
an in-memory SQLite engine with the AlfredOS schema mirrored via
``Base.metadata.create_all``, monkeypatch the command module's
``load_settings_or_die`` + ``sync_db_url`` to point at it, and exercise
the Typer surface through ``CliRunner``.

We assert the CLI **contract** — exit codes, filter behaviour, the
column shape rendered to stdout, and the empty-state hint — not the
SQL the command emits (that's covered by the engine's own correctness
on the integration layer).
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

from alfred.cli import audit_cmd
from alfred.memory.models import AuditEntry, Base


@pytest.fixture
def runner() -> CliRunner:
    """Default Typer test runner. Click 8.2 keeps stderr separate by default."""
    return CliRunner()


@pytest.fixture
def audit_cli_setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker[Session]]:
    """Wire ``audit_cmd`` against an in-memory SQLite engine.

    The command opens its own engine via ``create_engine(sync_db_url(...))``;
    we monkeypatch ``create_engine`` in the audit_cmd namespace to return
    a shared in-process engine, and ``load_settings_or_die`` to return a
    ``MagicMock`` settings shim (the command only reads
    ``operator_language`` off it, so a typed Settings is overkill for a
    unit test). The ``sync_db_url`` patch is irrelevant once
    ``create_engine`` is hijacked — but kept for symmetry with future
    tests that might bypass ``create_engine`` itself.

    ``COLUMNS=200`` widens Rich's auto-detected terminal so column-
    header and cell-value substring assertions are not truncated by
    the 80-col default — ``CliRunner`` runs without a tty so Rich
    falls back to ``COLUMNS`` for sizing.
    """
    monkeypatch.setenv("COLUMNS", "200")
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, future=True)

    settings = MagicMock()
    settings.operator_language = "en-US"
    monkeypatch.setattr(audit_cmd, "load_settings_or_die", lambda: settings)
    monkeypatch.setattr(audit_cmd, "sync_db_url", lambda _settings: "sqlite:///:memory:")
    monkeypatch.setattr(audit_cmd, "create_engine", lambda _url: engine)
    monkeypatch.setattr(engine, "dispose", lambda: None)

    try:
        yield factory
    finally:
        # Real disposal — the monkeypatch above replaced ``dispose`` with
        # a no-op so the schema survives the CLI invocation; reach for
        # the underlying ``Engine.dispose`` directly to actually close
        # the pool when the test exits.
        Engine.dispose(engine)


def _insert_audit_row(
    factory: sessionmaker[Session],
    *,
    event: str = "provider.call",
    actor_user_id: str | None = "operator",
    actor_persona: str = "alfred",
    result: str = "success",
    cost_actual_usd: float | None = 0.001234,
    created_at: dt.datetime | None = None,
    subject: dict[str, object] | None = None,
    trace_id: str | None = None,
) -> None:
    """Insert one ``AuditEntry`` for the given attributes."""
    with factory() as session:
        session.add(
            AuditEntry(
                id=uuid.uuid4(),
                created_at=created_at or dt.datetime.now(dt.UTC),
                trace_id=trace_id or "test-trace",
                event=event,
                actor_user_id=actor_user_id,
                actor_persona=actor_persona,
                subject=subject or {"model": "deepseek-chat"},
                trust_tier_of_trigger="T2",
                result=result,
                cost_estimate_usd=0.001,
                cost_actual_usd=cost_actual_usd,
                language="en-US",
            )
        )
        session.commit()


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_audit_log_renders_recent_rows(
    runner: CliRunner,
    audit_cli_setup: sessionmaker[Session],
) -> None:
    """A populated audit_log renders a Rich table with the expected columns."""
    _insert_audit_row(audit_cli_setup, event="provider.call", actor_user_id="operator")
    _insert_audit_row(audit_cli_setup, event="user.add", actor_user_id="operator")

    result = runner.invoke(audit_cmd.audit_app, ["log"])

    assert result.exit_code == 0, result.stderr
    # Column headers ride through ``t()`` → the rendered English label
    # appears verbatim because the catalog ships the same English text.
    assert "event" in result.stdout
    assert "actor_user_id" in result.stdout
    assert "tier" in result.stdout
    assert "cost_usd" in result.stdout
    # Both inserted rows surface.
    assert "provider.call" in result.stdout
    assert "user.add" in result.stdout
    # Cost is formatted to six decimals.
    assert "0.001234" in result.stdout


# --------------------------------------------------------------------------- #
# Empty state
# --------------------------------------------------------------------------- #


def test_audit_log_empty_window_prints_localised_hint(
    runner: CliRunner,
    audit_cli_setup: sessionmaker[Session],
) -> None:
    """No rows → the empty-state hint, not a 0-row table."""
    del audit_cli_setup  # fixture seeds nothing
    result = runner.invoke(audit_cmd.audit_app, ["log"])
    assert result.exit_code == 0, result.stderr
    assert "No audit rows" in result.stdout


# --------------------------------------------------------------------------- #
# --user filter
# --------------------------------------------------------------------------- #


def test_audit_log_user_filter_excludes_other_users(
    runner: CliRunner,
    audit_cli_setup: sessionmaker[Session],
) -> None:
    """``--user`` constrains the rendered set to one actor_user_id."""
    _insert_audit_row(audit_cli_setup, event="evt.alice", actor_user_id="alice")
    _insert_audit_row(audit_cli_setup, event="evt.bob", actor_user_id="bob")

    result = runner.invoke(audit_cmd.audit_app, ["log", "--user", "alice"])

    assert result.exit_code == 0, result.stderr
    assert "evt.alice" in result.stdout
    assert "evt.bob" not in result.stdout


# --------------------------------------------------------------------------- #
# --since validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", ["bogus", "5", "5x", "-1h", "0d"])
def test_audit_log_rejects_malformed_since(
    runner: CliRunner,
    audit_cli_setup: sessionmaker[Session],
    bad: str,
) -> None:
    """``--since`` rejects garbage with exit 2 + a localised error."""
    del audit_cli_setup  # parser failure short-circuits before any read
    result = runner.invoke(audit_cmd.audit_app, ["log", "--since", bad])
    assert result.exit_code == 2
    assert "Invalid --since" in result.stderr


def test_audit_log_rejects_oversize_limit(
    runner: CliRunner,
    audit_cli_setup: sessionmaker[Session],
) -> None:
    """``--limit`` above the cap exits 2 with the localised error."""
    del audit_cli_setup
    result = runner.invoke(audit_cmd.audit_app, ["log", "--limit", "99999"])
    assert result.exit_code == 2
    assert "Invalid --limit" in result.stderr
