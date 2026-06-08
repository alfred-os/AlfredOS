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


def test_boot_completed_row_not_emitted_when_supervisor_start_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """CR #2: declare boot complete only AFTER supervisor.start() succeeds.

    If ``supervisor.start()`` raises, the daemon never actually completed
    its boot, so no ``daemon.boot.completed`` audit row may be emitted and
    no "started" message may be printed — emitting either would lie to the
    operator + the audit trail about a boot that did not happen.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    stop_calls: list[None] = []

    class _FailingStartSupervisor(FakeSupervisor):
        async def start(self) -> None:
            raise RuntimeError("supervisor failed to start")

        async def stop(self) -> None:
            # CR: the boot's single try/finally must still drain the
            # supervisor even when start() raised.
            stop_calls.append(None)
            await super().stop()

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.Supervisor",
        _FailingStartSupervisor,
    )

    runner = CliRunner()
    result = runner.invoke(daemon_app, ["start"])

    # The boot crashed (start raised) — the command exits non-zero and the
    # exception is not swallowed.
    assert result.exit_code != 0
    # No completion row was written for a boot that never completed.
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # No "started" confirmation was printed (an empty output trivially
    # satisfies this — the redundant disjunct was dropped).
    assert "boot_id" not in result.output
    # The PID file was cleaned up (or never persisted past the failed start).
    assert not (tmp_path / "daemon.pid").exists()
    # The single try/finally drained the supervisor despite the start crash.
    assert stop_calls == [None]
