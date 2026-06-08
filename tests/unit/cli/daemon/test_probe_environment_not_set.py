"""Settings.environment missing → DAEMON_BOOT_FAILED + audit-before-exit (#174).

sec-001 closure: the AuditWriter is constructed BEFORE the environment
check, so the most common misconfig emits a DAEMON_BOOT_FAILED_FIELDS row
then exits 2 — never a silent failure.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app


def test_environment_not_set_refuses_and_audits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
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

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 2
    # A DAEMON_BOOT_FAILED row was emitted with environment_not_set.
    assert appended, "no audit row emitted before exit (sec-001 violated)"
    subject = appended[0]["subject"]
    assert isinstance(subject, dict)
    assert subject["failure_reason"] == "environment_not_set"


def test_environment_not_set_exits_3_when_audit_unwritable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """sec-003: an audit-write failure during refusal quarantines with exit 3."""
    monkeypatch.delenv("ALFRED_ENVIRONMENT", raising=False)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(
        "alfred.config._environment_loader._DEFAULT_ETC_PATH",
        tmp_path / "absent",
    )

    class _BrokenWriter:
        append_schema = AsyncMock(side_effect=RuntimeError("pg down"))

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.build_boot_audit_writer",
        lambda **_kw: _BrokenWriter(),
    )

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 3
