"""Tests for the Typer-based `alfred` CLI."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from pytest import MonkeyPatch
from typer.testing import CliRunner

from alfred.cli.main import _build_adapter_dlp_audit_sink, app
from alfred.security.secrets import SecretBroker, SecretBrokerConfigError

runner = CliRunner()


def test_alfred_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "chat" in result.stdout
    assert "status" in result.stdout


def test_alfred_status_exits_zero(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "deepseek" in result.stdout.lower()


def test_alfred_status_secrets_config_error_exits_cleanly(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """A bad secrets file surfaces as a clean Exit(2), NOT a raw traceback (#368)."""
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    bad = tmp_path / "secrets-is-a-dir.toml"
    bad.mkdir()  # a directory where a regular file is required
    monkeypatch.setenv("ALFRED_SECRETS_FILE", str(bad))
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 2
    # Clean exit — no unhandled SecretBrokerConfigError bubbled to the runner
    # (the old `build_broker` path let it surface as a raw traceback; #368's
    # `build_broker_or_die` catches it and converts to `typer.Exit(2)`).
    assert not isinstance(result.exception, SecretBrokerConfigError)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    # The operator sees the actionable secrets message (the offending path is
    # interpolated into t("secrets.path_is_directory", ...)) — a positive check
    # that build_broker_or_die echoed str(exc), not a vacuous "no Traceback".
    assert str(bad) in result.stdout


def test_alfred_status_shows_resolved_secrets_path(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """#370 item 3: ``alfred status`` reports WHICH secrets-file path resolved.

    On the happy path the operator otherwise never sees which layer the broker
    resolved (constructor arg / ALFRED_SECRETS_FILE / the ~/.config default), so
    a secrets problem means reading the ADR to know where to look. Assert the
    resolved path appears in the status output.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    parent = tmp_path / "alfred"
    parent.mkdir(mode=0o700)
    secrets = parent / "secrets.toml"
    secrets.write_text('discord_bot_token = "x"\n')
    secrets.chmod(0o600)
    monkeypatch.setenv("ALFRED_SECRETS_FILE", str(secrets))

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0
    # Rendered on the labelled secrets line (not merely present somewhere).
    assert "secrets file:" in result.stdout.lower()
    assert str(secrets) in result.stdout


def test_alfred_status_marks_absent_secrets_file(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """A configured-but-absent secrets file is marked 'not found', not shown as loaded.

    #370 item 3 / devex HIGH: the broker resolves the path but silently falls
    back to env-only when the file is absent. Showing the path unqualified would
    mislead the env-var operator ('why isn't my secret loading?') into editing a
    file that isn't the source, so status marks it not-found.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    absent = tmp_path / "alfred" / "secrets.toml"  # never created
    monkeypatch.setenv("ALFRED_SECRETS_FILE", str(absent))

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0
    assert str(absent) in result.stdout
    assert "not found" in result.stdout.lower()


def test_alfred_status_env_only_when_no_file_layer(monkeypatch: MonkeyPatch) -> None:
    """The env-only status branch (``secrets_file_path is None``) is exercised.

    That branch is defensive/unreachable through the real ``alfred status`` today
    (``build_broker_or_die`` → ``from_settings`` passes the non-optional
    ``Settings.secrets_file`` XDG default), so we inject an env-only broker whose
    accessor returns ``None`` to pin the env-only render. If ``Settings.secrets_file``
    ever becomes optional, this keeps the branch from silently losing coverage (CR).
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    env_only = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "test"})
    assert env_only.secrets_file_path is None  # precondition: no file layer
    monkeypatch.setattr(
        "alfred.cli._bootstrap.build_broker_or_die",
        lambda _settings: env_only,
    )

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0
    assert "environment variables only" in result.stdout.lower()


def test_alfred_migrate_command_is_registered() -> None:
    # Verifies the subcommand is wired into the Typer app and its docstring
    # mentions alembic/migrations so an operator running ``alfred migrate
    # --help`` lands on something useful. Actually running alembic against a
    # live DB is covered by the smoke test in Task 17.
    result = runner.invoke(app, ["migrate", "--help"])
    assert result.exit_code == 0
    assert "migrations" in result.stdout.lower() or "alembic" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Adapter DLP audit sink (PR D1 follow-up)
# ---------------------------------------------------------------------------


class _RecordingAuditWriter:
    """Captures calls to ``.append`` for the DLP audit-sink wiring test."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def append(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


def test_adapter_dlp_audit_sink_persists_modification_event() -> None:
    """Adapter outbound DLP must route audit rows to ``AuditWriter.append``.

    Regression: PR D1 originally wired ``OutboundDlp`` with
    ``_structlog_audit_sink`` (no-op) for the adapter path too. Audit-
    on-modification is the DLP layer's security objective (CLAUDE.md
    hard rule #7); routing it to a no-op silently drops every outbound-
    redaction event. The bridge MUST schedule a real
    ``AuditWriter.append`` for each modification.
    """

    async def run() -> None:
        writer = _RecordingAuditWriter()
        sink = _build_adapter_dlp_audit_sink(
            audit_writer=writer,  # type: ignore[arg-type]  # reason: structural fake
            operator_user_id="alice",
            language="en-US",
        )
        sink(event="dlp.outbound_redacted", subject={"stages_triggered": ("broker",)})
        # The sink schedules a task on the running loop; yield once so
        # the task body runs to completion before we assert.
        await asyncio.sleep(0)
        assert len(writer.calls) == 1
        call = writer.calls[0]
        assert call["event"] == "dlp.outbound_redacted"
        assert call["actor_user_id"] == "alice"
        assert call["language"] == "en-US"
        assert call["trust_tier_of_trigger"] == "T2"
        assert call["result"] == "modified"
        assert call["cost_estimate_usd"] == 0.0
        # Subject is widened from ``Mapping`` to ``dict`` by the bridge.
        assert call["subject"] == {"stages_triggered": ("broker",)}

    asyncio.run(run())


def test_adapter_dlp_audit_sink_surfaces_writer_failure_via_logger(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failing ``AuditWriter.append`` must NOT be swallowed silently.

    CLAUDE.md hard rule #7: no silent failures in security paths. The
    sync sink schedules an async task; we re-surface a task exception
    through structlog at ``error`` level rather than dropping it.
    """

    class _FailingWriter:
        async def append(self, **kwargs: Any) -> None:
            raise RuntimeError("audit DB exploded")

    async def run() -> None:
        sink = _build_adapter_dlp_audit_sink(
            audit_writer=_FailingWriter(),  # type: ignore[arg-type]  # reason: structural fake
            operator_user_id="alice",
            language="en-US",
        )
        sink(event="dlp.outbound_redacted", subject={})
        # Let the scheduled task run + the done_callback fire.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    asyncio.run(run())
    # structlog default config renders to stdout in tests; an ``error``-
    # level event for ``dlp.audit_write_failed`` MUST surface there so
    # the operator sees the failure rather than a silent drop.
    captured = capsys.readouterr().out
    assert "dlp.audit_write_failed" in captured
    assert "audit DB exploded" in captured
