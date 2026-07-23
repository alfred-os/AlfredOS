"""Settings.environment missing → DAEMON_BOOT_FAILED + audit-before-exit (#174).

sec-001 closure: the AuditWriter is constructed BEFORE the environment
check, so the most common misconfig emits a DAEMON_BOOT_FAILED_FIELDS row
then exits 2 — never a silent failure.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.i18n import t


def test_environment_not_set_refuses_and_audits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    # I-1 (final-review): hermetic against a real repo-root .env — the resolver's
    # lowest layer is CWD-relative, and this branch ships an uncommented
    # ALFRED_ENVIRONMENT=production in .env.example (bin/alfred-setup.sh copies it
    # to .env on first run). Without chdir, a developer/CI checkout with a real
    # .env at the repo root reads a valid value from it and this test fails.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    # A DAEMON_BOOT_FAILED row was emitted with environment_not_set.
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_not_set"


def test_post_env_settings_error_audits_settings_invalid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A ``SettingsError`` from ``Settings()`` — env value present, so past the
    unset guard — is a DISTINCT failure from an unresolved environment (#469
    Blocker 1 Task 3): some OTHER required field (a secret, a DSN, a numeric
    bound) failed validation, not the environment. Audits ``settings_invalid``
    (exit 2), never a raw traceback and never the environment's own reason.

    Retires the former ``test_settings_error_after_valid_env_refuses`` (#256
    PR-4), which asserted the pre-Task-3 behavior of collapsing this case into
    ``environment_not_set`` — a right-failure/wrong-reason bug this task fixes.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.chdir(tmp_path)
    # Hermetic: never let a real host /etc/alfred/environment participate —
    # matches every sibling test in this file (resolve_environment reads /etc
    # unconditionally, ahead of the precedence loop, per err-01 fail-closed).
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    from alfred.config.settings import SettingsError

    def _raise_settings_error(**_kw: object) -> object:
        raise SettingsError("settings blew up after the env was already validated")

    monkeypatch.setattr("alfred.config.settings.Settings", _raise_settings_error)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "settings_invalid"
    assert subject["environment_source"] == "env_var"


def test_settings_invalid_message_never_leaks_exception_detail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Security (devex-03 review, Important 2): the ``settings_invalid`` refusal
    must never echo ``str(exc)``.

    A ``SettingsError`` from some OTHER required field (e.g. a bad
    ``database_url``) can carry a secret in its OWN message — pydantic
    decorates a ``ValidationError`` with the offending value. The curated
    ``daemon.boot.settings_invalid`` catalog string must render instead of
    the raw detail: the refusal message reaches ``typer.echo(..., err=True)``
    (stderr), which for a backgrounded daemon is commonly captured into
    durable container/system logs, not just a live operator terminal
    (CLAUDE.md hard rule #1 — never log secrets).
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.chdir(tmp_path)
    # Hermetic: never let a real host /etc/alfred/environment participate.
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    from alfred.config.settings import SettingsError

    fake_secret = "SUPERSECRETPW"  # noqa: S105 -- fabricated leak marker, not a real credential

    def _raise_settings_error(**_kw: object) -> object:
        raise SettingsError(f"invalid database_url: postgresql://u:{fake_secret}@h/db")

    monkeypatch.setattr("alfred.config.settings.Settings", _raise_settings_error)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "settings_invalid"
    assert fake_secret not in result.output, (
        f"the fake secret leaked into the operator-facing refusal output: {result.output!r}"
    )


def test_settings_invalid_names_offending_field_without_leaking_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """M2 (fleet review): the ``settings_invalid`` message names the offending FIELD
    (pydantic's ``loc``) when a REAL chained ``ValidationError`` is available — never
    the invalid VALUE itself.

    Unlike the sibling no-leak test above (which monkeypatches ``Settings`` away
    entirely and so never exercises the ``__cause__`` chain), this drives the REAL
    ``Settings()`` construction with a malformed ``database_url`` whose raw value
    embeds a fabricated secret — proving the field NAME reaches output while the
    VALUE never does.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    fake_secret = "SUPERSECRETPW2"  # noqa: S105 -- fabricated leak marker, not a real credential
    monkeypatch.setenv("ALFRED_DATABASE_URL", f"not-a-valid-dsn-with-{fake_secret}")

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert fake_secret not in result.output, (
        f"the fake secret leaked into the operator-facing refusal output: {result.output!r}"
    )
    assert "database_url" in result.output, (
        f"the offending field name did not reach output: {result.output!r}"
    )
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "settings_invalid"


def test_placeholder_api_key_settings_error_shows_curated_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``_bootstrap_settings_message``'s placeholder-key branch (#469 Blocker 1
    devops-004): a ``SettingsError`` whose message contains ``placeholder_api_key``
    (the operator copied ``.env.example`` but never edited the DeepSeek key) gets
    the SAME curated ``error.placeholder_api_key`` hint the interactive CLI
    bootstrap path (``alfred.cli._bootstrap.load_settings_or_die``) shows — not the
    generic ``daemon.boot.settings_invalid`` fallback the sibling tests above cover.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.chdir(tmp_path)
    # Hermetic: never let a real host /etc/alfred/environment participate.
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    from alfred.config.settings import SettingsError

    def _raise_settings_error(**_kw: object) -> object:
        raise SettingsError(
            "1 validation error for Settings\ndeepseek_api_key\n  Value error, placeholder_api_key"
        )

    monkeypatch.setattr("alfred.config.settings.Settings", _raise_settings_error)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert t("error.placeholder_api_key") in result.output
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "settings_invalid"


def test_environment_source_unreadable_refuses_and_audits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A present-but-unreadable ``/etc/alfred/environment`` fails CLOSED (err-01).

    Distinct from ``environment_not_set``: the middle-precedence source EXISTED
    but the daemon process could not read it (here: it's a directory, so the
    read raises ``IsADirectoryError``) — never silently falls through to
    ``.env``/unset handling.
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    etc_dir = tmp_path / "environment"
    etc_dir.mkdir()
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        etc_dir,
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_source_unreadable"
    assert subject["environment_source"] == "unreadable"


def test_environment_not_set_exits_3_when_audit_unwritable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """sec-003: an audit-write failure during refusal quarantines with exit 3."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    # H2 (fleet review): hermetic against a real repo-root .env — matches every
    # sibling test in this file (see the comment on
    # ``test_environment_not_set_refuses_and_audits`` above). Without this, a
    # developer/CI checkout with a real .env at the repo root (shipping an
    # uncommented ``ALFRED_ENVIRONMENT=production`` per .env.example) reads a
    # valid value from it and this test silently exercises the
    # ``settings_invalid`` path instead of ``environment_not_set`` — and STILL
    # passed, because it only asserted ``exit_code == 3`` (both refusal paths
    # quarantine identically on an unwritable audit write).
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    class _BrokenWriter:
        append_schema = AsyncMock(
            side_effect=OperationalError("pg down", None, Exception("refused"))
        )

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _BrokenWriter(),
    )

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 3
    # H2: pin the FAILURE PATH, not just the exit code — the attempted (but
    # unwritable) audit row must be for environment_not_set, proving this test
    # exercises the intended refusal rather than silently passing via
    # settings_invalid on an unresolved-environment host with a real .env.
    _, kwargs = _BrokenWriter.append_schema.call_args
    subject = kwargs["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_not_set"


def test_environment_unrecognised_echoes_typo_and_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """devex-222-01: a typo'd value echoes the typo + the accepted list.

    The operator set ALFRED_ENVIRONMENT to a value that is NOT one of
    development/production/test. The refusal must distinguish this from
    "unset" by echoing what they typed via the
    ``daemon.boot.environment_unrecognised`` message.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "staging")  # not a valid value
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    # The unrecognised message (with the echoed typo) was printed.
    assert t("daemon.boot.environment_unrecognised", value="staging") in result.output
    assert "staging" in result.output
    # The failed audit row still records the canonical failure_reason.
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_not_set"
    assert subject["environment_source"] == "unrecognised"


def test_environment_unrecognised_etc_sourced_typo_renders_correct_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """M3 (fleet review): an ``/etc``-sourced typo renders the SAME curated message.

    ``/etc/alfred/environment`` holds a BARE value (no ``ALFRED_ENVIRONMENT=``
    prefix) — the message must echo the offending value without asserting a
    ``KEY=value`` shape, which would misrepresent the file format for this source
    (only the env-var case was pinned before this test).
    """
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.chdir(tmp_path)
    etc_file = tmp_path / "environment"
    etc_file.write_text("staging\n", encoding="utf-8")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        etc_file,
    )

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert t("daemon.boot.environment_unrecognised", value="staging") in result.output
    assert "staging" in result.output
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_not_set"
    assert subject["environment_source"] == "unrecognised"


def test_environment_unrecognised_dotenv_sourced_typo_renders_correct_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """M3 (fleet review): a ``.env``-sourced typo (env var + ``/etc`` both unset)
    ALSO renders the non-``KEY=value`` message — ``.env`` holds ``ALFRED_ENVIRONMENT=
    <value>`` (a real ``KEY=value`` line), but the resolver hands the daemon only the
    stripped raw value, same as every other source, so the rendered message must not
    assume any one source's on-disk shape.
    """
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )
    (tmp_path / ".env").write_text("ALFRED_ENVIRONMENT=staging\n", encoding="utf-8")

    appended: list[dict[str, object]] = []

    class _FakeWriter:
        async def append_schema(self, **kw: object) -> None:
            appended.append(kw)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _FakeWriter(),
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    assert t("daemon.boot.environment_unrecognised", value="staging") in result.output
    assert "staging" in result.output
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_not_set"
    assert subject["environment_source"] == "unrecognised"
