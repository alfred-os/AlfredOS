"""Unit tests for ``alfred memory show <slug>``.

Same isolation strategy as ``test_audit_cmd.py``: in-memory SQLite +
monkeypatched bootstrap + ``CliRunner``.
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

from alfred.cli import memory_cmd
from alfred.cli.memory_cmd import _CONTENT_DISPLAY_MAX
from alfred.identity.models import Authorization, User
from alfred.memory.models import Base, Episode


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def memory_cli_setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker[Session]]:
    """Wire ``memory_cmd`` against an in-memory SQLite engine.

    ``COLUMNS=200`` widens Rich's auto-detected terminal so cell-value
    substring assertions are not truncated by the 80-col default.
    """
    monkeypatch.setenv("COLUMNS", "200")
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, future=True)

    settings = MagicMock()
    settings.operator_language = "en-US"
    monkeypatch.setattr(memory_cmd, "load_settings_or_die", lambda: settings)
    monkeypatch.setattr(memory_cmd, "sync_db_url", lambda _settings: "sqlite:///:memory:")
    monkeypatch.setattr(memory_cmd, "create_engine", lambda _url: engine)
    monkeypatch.setattr(engine, "dispose", lambda: None)

    try:
        yield factory
    finally:
        Engine.dispose(engine)


def _insert_user(factory: sessionmaker[Session], *, slug: str = "operator") -> None:
    """Seed one user row matching the Slice-2 operator shape."""
    with factory() as session:
        session.add(
            User(
                slug=slug,
                display_name=slug.title(),
                authorization=Authorization.OPERATOR.value,
                daily_budget_usd=1.5,
                language="en-US",
            )
        )
        session.commit()


def _insert_episode(
    factory: sessionmaker[Session],
    *,
    user_id: str,
    role: str,
    content: str,
    created_at: dt.datetime | None = None,
) -> None:
    """Seed one episode row for the given user."""
    with factory() as session:
        session.add(
            Episode(
                id=uuid.uuid4(),
                created_at=created_at or dt.datetime.now(dt.UTC),
                user_id=user_id,
                persona="alfred",
                role=role,
                content=content,
                trust_tier="T2",
                language="en-US",
            )
        )
        session.commit()


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_memory_show_renders_user_and_recent_episodes(
    runner: CliRunner,
    memory_cli_setup: sessionmaker[Session],
) -> None:
    """Existing user → summary block + Rich episode table + working-pool hint."""
    _insert_user(memory_cli_setup, slug="operator")
    _insert_episode(memory_cli_setup, user_id="operator", role="user", content="hello")
    _insert_episode(memory_cli_setup, user_id="operator", role="assistant", content="hi there")

    result = runner.invoke(memory_cmd.memory_app, ["show", "operator"])

    assert result.exit_code == 0, result.stderr
    # Summary block uses the shared cli.user.list.column.* labels.
    assert "slug: operator" in result.stdout
    assert "display name: Operator" in result.stdout
    assert "authorization: operator" in result.stdout
    assert "daily budget (USD): 1.50" in result.stdout
    assert "language: en-US" in result.stdout
    # Episodes table — column headers + per-row content.
    assert "role" in result.stdout
    assert "content" in result.stdout
    assert "hello" in result.stdout
    assert "hi there" in result.stdout
    # Working-memory hint always trails the output.
    assert "per-process state" in result.stdout


def test_memory_show_truncates_long_content_for_display(
    runner: CliRunner,
    memory_cli_setup: sessionmaker[Session],
) -> None:
    """Content beyond the display max gets the ellipsis treatment."""
    _insert_user(memory_cli_setup, slug="operator")
    long_content = "x" * (_CONTENT_DISPLAY_MAX + 20)
    _insert_episode(memory_cli_setup, user_id="operator", role="user", content=long_content)

    result = runner.invoke(memory_cmd.memory_app, ["show", "operator"])

    assert result.exit_code == 0, result.stderr
    # The trailing ellipsis is present; full content is NOT.
    assert "…" in result.stdout
    assert long_content not in result.stdout


# --------------------------------------------------------------------------- #
# Empty state
# --------------------------------------------------------------------------- #


def test_memory_show_user_with_no_episodes(
    runner: CliRunner,
    memory_cli_setup: sessionmaker[Session],
) -> None:
    """User exists, episodes empty → summary + localised episodes hint."""
    _insert_user(memory_cli_setup, slug="operator")
    result = runner.invoke(memory_cmd.memory_app, ["show", "operator"])
    assert result.exit_code == 0, result.stderr
    assert "slug: operator" in result.stdout
    assert "No episodes recorded" in result.stdout


# --------------------------------------------------------------------------- #
# Unknown user
# --------------------------------------------------------------------------- #


def test_memory_show_unknown_slug_exits_two(
    runner: CliRunner,
    memory_cli_setup: sessionmaker[Session],
) -> None:
    """Missing user → exit 2 + localised error on stderr."""
    del memory_cli_setup
    result = runner.invoke(memory_cmd.memory_app, ["show", "no-such-user"])
    assert result.exit_code == 2
    assert "No user with slug 'no-such-user'" in result.stderr
