"""Unit tests for ``src/alfred/identity/cli.py``.

The CLI is a thin Typer wrapper around :class:`IdentityResolver` plus an
:class:`AuditWriter` call per mutation. These tests pin the wrapper's
**contract** — exit codes, stdout/stderr content, audit-row shape — not
the resolver's internals (those are exercised in ``test_resolver.py``).

Isolation strategy
------------------

* The resolver and its session factory are constructed against an
  in-memory SQLite engine in the ``cli_setup`` fixture. The fixture
  monkeypatches ``alfred.identity.cli._resolver_factory`` so every
  ``runner.invoke`` call picks up the SAME resolver — passing a fresh
  factory per invocation would defeat soft-delete-history tests (the
  CLI invocation that creates the user would then be looking at a
  different engine than the one that asserts on the row).
* Audit writes go through the ``audit_buffer`` fixture
  (``tests/unit/conftest.py``) — that monkeypatches
  ``AuditWriter.append`` to append the kwargs dict to a list. The CLI
  construction path still builds an :class:`AuditWriter`, but the
  ``append`` call inside is a coroutine that never touches the DB.
* ``typer.testing.CliRunner`` is the entry point. Click 8.2 dropped the
  ``mix_stderr`` kwarg; ``Result.stdout`` and ``Result.stderr`` are
  always separate, so the runner uses default construction.

Why these tests do not exercise the catalog
-------------------------------------------

The translator returns the key verbatim if no catalog is shipped (see
``alfred/i18n/translator.py``). T4 populated every ``cli.user.*`` key
this CLI emits, so the assertions look for the rendered English
template substring (e.g. ``"Added user Alice"``) rather than the bare
catalog key — that keeps tests symmetric with production output and
catches regressions where a code-path stops routing through ``t()``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from typer.testing import CliRunner

from alfred.audit.log import AuditWriter
from alfred.identity import (
    Authorization,
    IdentityResolver,
    IdentityVersionCounter,
    Platform,
    _NullRateLimiter,
)
from alfred.identity import cli as identity_cli
from alfred.memory.models import Base

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def runner() -> CliRunner:
    """``typer.testing.CliRunner``.

    Click 8.2 dropped the ``mix_stderr=False`` kwarg — ``Result.stdout`` and
    ``Result.stderr`` are always separate properties now, so tests can assert
    on each stream independently without any per-runner configuration.
    """
    return CliRunner()


@pytest.fixture
def cli_setup(
    monkeypatch: pytest.MonkeyPatch,
    audit_buffer: list[dict[str, Any]],
) -> Iterator[IdentityResolver]:
    """Wire the CLI module to an in-memory SQLite resolver for one test.

    Yields the resolver itself so tests can pre-seed users (``resolver.add(...)``)
    before invoking the CLI, and assert on the database state after the
    invocation without round-tripping through the CLI again.

    The monkeypatched ``_resolver_factory`` returns the SAME resolver on
    every call — see module docstring for why a fresh factory per call
    would break soft-delete tests.
    """
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, future=True)
    resolver = IdentityResolver(
        session_factory=factory,
        version_counter=IdentityVersionCounter(),
        rate_limiter=_NullRateLimiter(),
    )

    # The CLI builds an AuditWriter from a session factory; the
    # audit_buffer fixture already monkeypatched ``AuditWriter.append``
    # so the writer's session-factory argument is never exercised. A
    # MagicMock keeps construction cheap and explicit.
    audit_writer = AuditWriter(session_factory=MagicMock())

    monkeypatch.setattr(identity_cli, "_resolver_factory", lambda: resolver)
    monkeypatch.setattr(identity_cli, "_audit_writer_factory", lambda: audit_writer)

    try:
        yield resolver
    finally:
        engine.dispose()


# --------------------------------------------------------------------------- #
# add
# --------------------------------------------------------------------------- #


def test_add_minimal(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    audit_buffer: list[dict[str, Any]],
) -> None:
    """Apostrophe in display name produces a clean slug + writes audit row."""
    result = runner.invoke(identity_cli.user_app, ["add", "--name", "Alice O'Connor"])

    assert result.exit_code == 0, result.stderr
    assert "alice-o-connor" in result.stdout
    assert "Added user" in result.stdout

    user = cli_setup.show(slug="alice-o-connor")
    assert user is not None
    assert user.display_name == "Alice O'Connor"

    assert len(audit_buffer) == 1
    entry = audit_buffer[0]
    assert entry["event"] == "user.add"
    assert entry["subject"]["slug"] == "alice-o-connor"


def test_add_output_slug_short_circuits(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    audit_buffer: list[dict[str, Any]],
) -> None:
    """``--output-slug`` prints ONLY the slug + newline; no confirmation echo."""
    result = runner.invoke(identity_cli.user_app, ["add", "--name", "Bob", "--output-slug"])

    assert result.exit_code == 0, result.stderr
    assert result.stdout == "bob\n"


def test_add_authorization_kebab_and_snake_equivalent(
    runner: CliRunner, cli_setup: IdentityResolver
) -> None:
    """``read-only`` and ``read_only`` both reach the DB as the snake_case enum value."""
    r1 = runner.invoke(
        identity_cli.user_app,
        ["add", "--name", "Kebab", "--authorization", "read-only"],
    )
    r2 = runner.invoke(
        identity_cli.user_app,
        ["add", "--name", "Snake", "--authorization", "read_only"],
    )

    assert r1.exit_code == 0, r1.stderr
    assert r2.exit_code == 0, r2.stderr
    kebab_user = cli_setup.show(slug="kebab")
    snake_user = cli_setup.show(slug="snake")
    assert kebab_user is not None
    assert snake_user is not None
    assert kebab_user.authorization == Authorization.READ_ONLY.value
    assert snake_user.authorization == Authorization.READ_ONLY.value


def test_add_invalid_language_exits_2(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """Bogus BCP-47 tag fails fast with the localised error message."""
    result = runner.invoke(
        identity_cli.user_app,
        ["add", "--name", "Bob", "--language", "wat-NOT-VALID"],
    )

    assert result.exit_code == 2
    assert "Invalid BCP-47 language tag" in result.stderr


def test_add_zero_budget_refused(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """``--daily-budget-usd 0`` fails CHECK-mirror validation in the resolver."""
    result = runner.invoke(
        identity_cli.user_app,
        ["add", "--name", "Bob", "--daily-budget-usd", "0"],
    )

    assert result.exit_code == 2
    assert "must be > 0" in result.stderr


def test_add_second_operator_without_replace_refused(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """A second ``--authorization operator`` must name the operator to replace."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)

    result = runner.invoke(
        identity_cli.user_app,
        ["add", "--name", "Bob", "--authorization", "operator"],
    )

    assert result.exit_code == 2
    assert "operator already exists" in result.stderr.lower()
    assert "alice" in result.stderr


def test_add_second_operator_with_replace(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    audit_buffer: list[dict[str, Any]],
) -> None:
    """``--replace-operator alice`` demotes alice + promotes bob atomically."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)
    audit_buffer.clear()

    result = runner.invoke(
        identity_cli.user_app,
        [
            "add",
            "--name",
            "Bob",
            "--authorization",
            "operator",
            "--replace-operator",
            "alice",
        ],
    )

    assert result.exit_code == 0, result.stderr
    op = cli_setup.get_operator()
    assert op.slug == "bob"
    alice = cli_setup.show(slug="alice")
    assert alice is not None
    # Demoted to TRUSTED per spec §2 architect-001 and the
    # ``cli.user.operator_replaced`` catalog entry — the resolver and the
    # operator-facing copy now agree.
    assert alice.authorization == Authorization.TRUSTED.value
    assert any(e["event"] == "user.add" for e in audit_buffer)


# --------------------------------------------------------------------------- #
# list / show
# --------------------------------------------------------------------------- #


def test_list_table_headers_localised(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """Default table renders the six i18n'd column headers."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)

    result = runner.invoke(identity_cli.user_app, ["list"])

    assert result.exit_code == 0, result.stderr
    for header in (
        "slug",
        "display name",
        "authorization",
        "daily budget",
        "platforms",
        "language",
    ):
        assert header in result.stdout.lower()


def test_list_empty_hint(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """Empty deployment renders the empty_hint pointing at ``alfred user add``."""
    result = runner.invoke(identity_cli.user_app, ["list"])

    assert result.exit_code == 0, result.stderr
    assert "No users yet" in result.stdout


def test_list_json_stable_schema(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """``--json`` emits an array of objects keyed on User ORM column names."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)

    result = runner.invoke(identity_cli.user_app, ["list", "--json"])

    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)
    assert len(payload) == 1
    row = payload[0]
    for field in (
        "slug",
        "display_name",
        "authorization",
        "daily_budget_usd",
        "language",
        "rate_limit_per_min",
        "rate_limit_per_day",
        "created_at",
        "deleted_at",
    ):
        assert field in row, f"missing field {field}"


def test_list_include_deleted_marks_strikethrough(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """Soft-deleted rows render with the localised ``(deleted)`` annotation."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)
    bob = cli_setup.add(display_name="Bob", authorization=Authorization.STANDARD)
    cli_setup.remove(slug=bob.slug)

    result = runner.invoke(identity_cli.user_app, ["list", "--include-deleted"])

    assert result.exit_code == 0, result.stderr
    assert "(deleted)" in result.stdout
    assert "bob" in result.stdout


def test_show_renders_override_indicator(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """When ``rate_limit_per_min`` is set, ``show`` flags it as ``(override)``."""
    cli_setup.add(
        display_name="Alice",
        authorization=Authorization.STANDARD,
        rate_limit_per_min=42,
    )

    result = runner.invoke(identity_cli.user_app, ["show", "alice"])

    assert result.exit_code == 0, result.stderr
    assert "42" in result.stdout
    assert "(override)" in result.stdout


# --------------------------------------------------------------------------- #
# remove
# --------------------------------------------------------------------------- #


def test_remove_last_operator_refused(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """The only-operator gate exits 2 with the localised refusal message."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)

    result = runner.invoke(identity_cli.user_app, ["remove", "alice", "--yes"])

    assert result.exit_code == 2
    assert "last operator" in result.stderr.lower()


def test_remove_non_tty_without_yes_refused(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """Non-TTY without ``--yes`` exits 2 — never auto-confirms destructive ops."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)
    cli_setup.add(display_name="Bob", authorization=Authorization.STANDARD)

    # CliRunner's default input stream is non-TTY.
    result = runner.invoke(identity_cli.user_app, ["remove", "bob"])

    assert result.exit_code == 2
    assert "non-TTY" in result.stderr or "non-tty" in result.stderr.lower()


def test_remove_with_yes_soft_deletes(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    audit_buffer: list[dict[str, Any]],
) -> None:
    """``--yes`` skips the prompt and soft-deletes the row."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)
    cli_setup.add(display_name="Bob", authorization=Authorization.STANDARD)
    audit_buffer.clear()

    result = runner.invoke(identity_cli.user_app, ["remove", "bob", "--yes"])

    assert result.exit_code == 0, result.stderr
    bob = cli_setup.show(slug="bob")
    assert bob is not None
    assert bob.deleted_at is not None

    assert any(e["event"] == "user.remove" for e in audit_buffer)


# --------------------------------------------------------------------------- #
# bind / unbind
# --------------------------------------------------------------------------- #


def test_bind_then_resolve(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    audit_buffer: list[dict[str, Any]],
) -> None:
    """``bind`` makes the (platform, platform_id) resolvable."""
    cli_setup.add(display_name="Alice", authorization=Authorization.STANDARD)
    audit_buffer.clear()

    result = runner.invoke(
        identity_cli.user_app,
        ["bind", "alice", "--platform", "discord", "--id", "111"],
    )

    assert result.exit_code == 0, result.stderr
    resolved = cli_setup.resolve(Platform.DISCORD, "111")
    assert resolved is not None
    assert resolved.slug == "alice"

    assert any(e["event"] == "user.bind" for e in audit_buffer)


def test_bind_double_platform_refused(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """A user already bound on a platform cannot bind again on the same one."""
    cli_setup.add(display_name="Alice", authorization=Authorization.STANDARD)
    cli_setup.bind(user_slug="alice", platform=Platform.DISCORD, platform_id="111")

    result = runner.invoke(
        identity_cli.user_app,
        ["bind", "alice", "--platform", "discord", "--id", "222"],
    )

    assert result.exit_code == 2
    assert "already bound" in result.stderr.lower()


# --------------------------------------------------------------------------- #
# set
# --------------------------------------------------------------------------- #


def test_set_rate_limit_unset_clears_to_null(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    audit_buffer: list[dict[str, Any]],
) -> None:
    """``--rate-limit-per-min unset`` writes NULL into the column."""
    cli_setup.add(
        display_name="Alice",
        authorization=Authorization.STANDARD,
        rate_limit_per_min=42,
    )
    audit_buffer.clear()

    result = runner.invoke(
        identity_cli.user_app,
        ["set", "alice", "--rate-limit-per-min", "unset"],
    )

    assert result.exit_code == 0, result.stderr
    alice = cli_setup.show(slug="alice")
    assert alice is not None
    assert alice.rate_limit_per_min is None

    assert any(e["event"] == "user.set" for e in audit_buffer)


# --------------------------------------------------------------------------- #
# Audit attribution
# --------------------------------------------------------------------------- #


def test_audit_actor_is_operator_when_present(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    audit_buffer: list[dict[str, Any]],
) -> None:
    """After bootstrap, every mutation's ``actor_user_id`` is the operator slug."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)
    audit_buffer.clear()

    result = runner.invoke(identity_cli.user_app, ["add", "--name", "Bob"])

    assert result.exit_code == 0, result.stderr
    assert audit_buffer[-1]["actor_user_id"] == "alice"


def test_audit_actor_is_bootstrap_for_first_operator(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    audit_buffer: list[dict[str, Any]],
) -> None:
    """The very first operator add has no prior operator → actor is ``<bootstrap>``."""
    result = runner.invoke(
        identity_cli.user_app,
        ["add", "--name", "Alice", "--authorization", "operator"],
    )

    assert result.exit_code == 0, result.stderr
    assert audit_buffer[-1]["actor_user_id"] == "<bootstrap>"


# --------------------------------------------------------------------------- #
# Cancel
# --------------------------------------------------------------------------- #


def test_remove_keyboard_interrupt_exits_130(
    runner: CliRunner,
    cli_setup: IdentityResolver,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ctrl-C inside the confirm prompt surfaces as exit 130 (POSIX SIGINT)."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)
    cli_setup.add(display_name="Bob", authorization=Authorization.STANDARD)

    # Force the TTY check to PASS so the code path enters typer.confirm, then
    # raise KeyboardInterrupt out of the prompt to simulate Ctrl-C.
    monkeypatch.setattr(identity_cli, "_stdin_is_tty", lambda: True)

    def _raise_kbi(*_args: Any, **_kwargs: Any) -> bool:
        raise KeyboardInterrupt

    monkeypatch.setattr("typer.confirm", _raise_kbi)

    result = runner.invoke(identity_cli.user_app, ["remove", "bob"])

    assert result.exit_code == 130


# --------------------------------------------------------------------------- #
# Sanity: every audit-emitting test ran exactly one asyncio coroutine for the
# capture path. ``asyncio.run`` inside the CLI must not leak a running loop
# across tests; this tiny sanity test runs last (lex order) to catch that.
# --------------------------------------------------------------------------- #


def test_no_running_event_loop_after_invocations(
    runner: CliRunner,
    cli_setup: IdentityResolver,
) -> None:
    """Each CLI invocation closes its own asyncio loop — no leaks."""
    cli_setup.add(display_name="Alice", authorization=Authorization.OPERATOR)
    result = runner.invoke(identity_cli.user_app, ["add", "--name", "Bob"])

    assert result.exit_code == 0, result.stderr
    with pytest.raises(RuntimeError):
        asyncio.get_running_loop()
