"""Tests for the Typer-based `alfred` CLI."""

from __future__ import annotations

import asyncio
import sys
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


def test_alfred_status_reports_the_quarantine_provider(monkeypatch: MonkeyPatch) -> None:
    """devex-002 (#586/#587): ``alfred status`` names the quarantine half of the split.

    ``ALFRED_QUARANTINE_PROVIDER`` decides which provider the quarantined child dials
    (and therefore which key it needs); ``ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION``
    decides whether a privileged/quarantined collision refuses boot or merely warns.
    Neither was rendered anywhere, so an operator could only recover them by reading
    ``.env`` back. Asserted on a NON-DEFAULT value so the test cannot pass on a
    hardcoded string.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", "deepseek")
    monkeypatch.setenv("ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION", "true")

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0, result.output
    flat = " ".join(result.stdout.split()).lower()
    assert "quarantine provider: deepseek" in flat, flat
    assert "quarantine provider separation enforced: yes" in flat, flat


def test_alfred_status_reports_separation_not_enforced_by_default(
    monkeypatch: MonkeyPatch,
) -> None:
    """Oracle guard for the pair above: the default (permissive) posture renders "no".

    Without this, a status line hardcoded to "yes" — or one reading the wrong field —
    would keep the test above green while telling every default deployment that a
    protection it does not have is switched on.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.delenv("ALFRED_QUARANTINE_PROVIDER", raising=False)
    monkeypatch.delenv("ALFRED_REQUIRE_QUARANTINE_PROVIDER_SEPARATION", raising=False)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0, result.output
    flat = " ".join(result.stdout.split()).lower()
    assert "quarantine provider: anthropic" in flat, flat
    assert "quarantine provider separation enforced: no" in flat, flat


def test_alfred_status_refuses_credential_shaped_primary_provider_without_echoing_it(
    monkeypatch: MonkeyPatch,
) -> None:
    """#589: the actual end-to-end regression. ``alfred status`` — standing in for
    every top-level command that goes through ``alfred.cli._bootstrap.load_settings_
    or_die`` except ``alfred daemon start`` (``chat``, ``login``, ``supervisor *``,
    ``user *``, ``operator-session *``) — used to echo a credential-shaped
    ``ALFRED_PRIMARY_PROVIDER`` in FULL via pydantic's ``ValidationError.__str__()``
    (which embeds ``input_value=<raw input>`` for a rejected Literal). The
    daemon-boot path was fixed first and had its own test
    (``test_boot_refuses_credential_shaped_primary_provider_without_logging_it``,
    ``tests/unit/cli/daemon/test_daemon_boot_egress_refuse.py``) — this is the
    WIDER exposure that fix left open, reproduced and closed here.
    """
    credential = "not-a-real-secret-primary-provider-test-placeholder"
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_PRIMARY_PROVIDER", credential)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 2, result.output
    flat = " ".join(result.output.split())
    assert credential not in flat, flat
    assert "input_value" not in flat, flat
    assert "primary_provider" in flat, flat
    assert "anthropic" in flat and "deepseek" in flat, flat


def test_alfred_status_refuses_credential_shaped_quarantine_provider_without_echoing_it(
    monkeypatch: MonkeyPatch,
) -> None:
    """Sibling of the test above: ``quarantine_provider`` became a ``Literal`` in an
    EARLIER commit of this same PR and carried the identical exposure the whole
    time — the leak was never specific to ``primary_provider``, it was specific to
    ``load_settings_or_die``'s renderer, which is what actually got fixed."""
    credential = "not-a-real-secret-quarantine-provider-test-placeholder"
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_QUARANTINE_PROVIDER", credential)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 2, result.output
    flat = " ".join(result.output.split())
    assert credential not in flat, flat
    assert "input_value" not in flat, flat
    assert "quarantine_provider" in flat, flat
    assert "anthropic" in flat and "deepseek" in flat, flat


def test_alfred_status_refuses_credential_shaped_deepseek_base_url_without_echoing_it(
    monkeypatch: MonkeyPatch,
) -> None:
    """test-003 (review-fleet, deferred here rather than to a boot-log test):
    ``deepseek_base_url`` is never interpolated into a boot-log line (unlike
    ``primary_provider`` before its fix), so the daemon-boot surface has no
    equivalent leak to close — ``load_settings_or_die``'s interactive echo is the
    ONLY real sink for this field, and this same fix closes it too.
    ``_validate_deepseek_base_url`` already strips userinfo/malformed components
    with a value-free message of its own; this pins that BOTH layers hold —
    the validator's own discipline AND the renderer's.
    """
    credential_bearing = "https://user:hunter2@relay.internal/v1"
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_DEEPSEEK_BASE_URL", credential_bearing)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 2, result.output
    flat = " ".join(result.output.split())
    assert "hunter2" not in flat, flat
    assert credential_bearing not in flat, flat
    assert "input_value" not in flat, flat
    assert "deepseek_base_url" in flat, flat


def test_alfred_status_refuses_credential_shaped_fallback_provider_without_echoing_it(
    monkeypatch: MonkeyPatch,
) -> None:
    """sec-002/test-002 (review-fleet): ``fallback_provider`` had the identical
    "closed-set routing config, safe to echo" shape ``primary_provider`` did before
    ITS fix — but a DIFFERENT mechanism: as a bare ``str``, a credential-shaped
    value simply VALIDATED (there was nothing to reject it) and was echoed in full
    on ``alfred status``'s SUCCESS path (``status.fallback_provider``), no
    exception involved at all. Now a ``Literal``, the same value fails Settings
    construction and renders through the same value-free renderer as every other
    closed-set provider field.
    """
    credential = "not-a-real-secret-fallback-provider-test-placeholder"
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_FALLBACK_PROVIDER", credential)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 2, result.output
    flat = " ".join(result.output.split())
    assert credential not in flat, flat
    assert "input_value" not in flat, flat
    assert "fallback_provider" in flat, flat
    assert "anthropic" in flat and "deepseek" in flat, flat


def test_alfred_status_missing_required_key_names_the_field_not_the_value(
    monkeypatch: MonkeyPatch,
) -> None:
    """Pins the named-field-without-choices arm end to end: a required field with
    no accepted-value set (not a Literal) still gets a curated, field-named
    message — never pydantic's raw envelope."""
    monkeypatch.delenv("ALFRED_DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 2, result.output
    flat = " ".join(result.output.split())
    assert "deepseek_api_key" in flat, flat
    assert "input_value" not in flat, flat


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family (_validate_secrets_file_security calls "
    "os.getuid() before the is-directory check, so the AttributeError on Windows "
    "surfaces as an uncaught exit-1, not the expected Exit(2))",
)
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family (_validate_secrets_file_security calls "
    "os.getuid(), which does not exist on Windows, so the real secrets file "
    "construction raises AttributeError instead of succeeding)",
)
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
