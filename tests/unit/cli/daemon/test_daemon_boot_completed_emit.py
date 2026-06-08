"""All probes pass → DAEMON_BOOT row + PID file + success message (#174)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app

from .conftest import FakeAuditWriter, FakeSupervisor


def test_boot_completed_emits_row_and_writes_pidfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    rows = boot_success_env.rows_for("DAEMON_BOOT_FIELDS")
    assert len(rows) == 1
    subject = rows[0]["subject"]
    assert subject["slice_version"] == "4"
    assert subject["state_git_head_sha"] == "deadbeefcafe"
    assert subject["environment"] == "test"
    assert subject["policies_snapshot_hash"]
    assert subject["boot_id"]

    # Supervisor was constructed with the state.git path + stub kwargs and
    # cleanly started + stopped.
    sup = FakeSupervisor.last_instance
    assert sup is not None
    assert sup.started is True
    assert sup.stopped is True
    assert sup.kwargs["policies_ref"] is not None
    assert sup.kwargs["operator_session_resolver"] is not None

    # PID file was written then cleaned up on shutdown.
    assert not (tmp_path / "daemon.pid").exists()


def test_boot_completed_exits_3_when_completion_audit_unwritable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """sec-003: a persistence failure writing the completion row → exit 3."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    async def _boom(**_kw: object) -> None:
        # err-002: a DB-write failure (SQLAlchemyError) is the genuine
        # audit-unwritable case → quarantine exit 3.
        raise OperationalError("pg down on completion write", None, Exception("refused"))

    monkeypatch.setattr(boot_success_env, "append_schema", _boom)

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])
    assert result.exit_code == 3
