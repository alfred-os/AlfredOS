"""The drain ``finally``'s None-guards skip the reap for resources never created (#256 PR-4).

The boot ``try/finally`` declares ``supervisor`` / ``pidfile_path`` as ``None``
BEFORE the ``try`` so the reap ``finally`` can never ``NameError`` on an
early-in-``try`` failure (the #255 leak-guard shape). If ``Supervisor(...)``
construction itself raises — before ``write_pidfile`` runs — the finally must
skip ``supervisor.stop()`` and ``delete_pidfile()`` (both guarded ``is not None``)
and let the original exception propagate. This pins those two defensive branches
(``_commands.py`` ``supervisor is None`` / ``pidfile_path is None``) so the
whole-file 100% gate covers them rather than pragma-ing a leak-guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app

from .conftest import FakeAuditWriter


def test_reap_finally_skips_absent_supervisor_and_pidfile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    class _RaisingSupervisor:
        """Blows up during construction, before the PID file is written."""

        def __init__(self, **_kwargs: object) -> None:
            raise RuntimeError("supervisor construction blew up mid-boot")

    # Override the boot-success FakeSupervisor patch: enter the boot try, then
    # raise at Supervisor(...) so supervisor + pidfile_path stay None in the finally.
    monkeypatch.setattr("alfred.cli.daemon._commands.Supervisor", _RaisingSupervisor)

    result = CliRunner().invoke(daemon_app, ["start"])

    # Not a _BootRefusedError → the RuntimeError propagates out of start_daemon
    # (start_daemon only translates _BootRefusedError into typer.Exit).
    assert result.exit_code != 0
    assert isinstance(result.exception, RuntimeError)
    # The reap finally ran with both resources absent — no NameError, no reap crash,
    # no completion row, and no PID file left behind.
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    assert not (tmp_path / "daemon.pid").exists()
