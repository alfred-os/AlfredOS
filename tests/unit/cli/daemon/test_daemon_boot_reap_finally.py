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

import sys
from pathlib import Path
from typing import Any

import pytest
import structlog.testing
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._boot_audit import _BootRefusedError

from .conftest import FakeAuditWriter, FakeSupervisor

# The three drain-finally arms below drive a FULL successful boot to reach
# ``wait_for_shutdown``/``supervisor.stop()``, which writes the pidfile via
# ``os.O_NOFOLLOW`` — a POSIX-only flag. On Windows the boot fails at
# ``write_pidfile`` with ``AttributeError('module os has no attribute O_NOFOLLOW')``
# before ever reaching the code under test. Same architectural constraint the sibling
# ``test_tui_adapter_listener_reaped_even_when_supervisor_stop_raises`` already guards;
# the supported Windows path is WSL2 (= Linux). A DECORATOR, never a runtime skip inside
# a helper (a helper-internal guard can be ordered wrong). ``test_reap_finally_skips_
# absent_supervisor_and_pidfile`` below needs NO guard — it raises at Supervisor
# construction, before ``write_pidfile``.
_posix_boot_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: the real daemon-boot pipeline writes the pidfile with os.O_NOFOLLOW",
)


def _async_raise(exc: BaseException) -> Any:
    """A ``wait_for_shutdown`` replacement that raises ``exc`` once the daemon is up."""

    async def _raiser(*_a: object, **_k: object) -> None:
        raise exc

    return _raiser


@_posix_boot_only
def test_a_failing_supervisor_stop_does_not_mask_a_boot_refusal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """A cleanup exception must not replace the audited failure in flight (#472 finding 3).

    ``supervisor.stop()`` raising during a boot REFUSAL previously propagated in place of
    the ``_BootRefusedError`` — so ``start_daemon`` (which only translates
    ``_BootRefusedError`` into ``typer.Exit``) saw a raw ``RuntimeError`` and the operator
    got the wrong exit code for a failure the daemon had already audited. The cleanup must
    be suppressed here, but LOUDLY (HARD #7) — never silently.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(FakeSupervisor, "fail_stop", True)
    # A refusal arriving AFTER the supervisor is up: the finally then runs the raising
    # stop(), which must not overwrite this _BootRefusedError.
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.wait_for_shutdown", _async_raise(_BootRefusedError(2))
    )

    with structlog.testing.capture_logs() as logs:
        result = CliRunner().invoke(daemon_app, ["start"])

    # The refusal survived: exit code is the refusal's (2), not the generic RuntimeError
    # exit start_daemon would produce for an untranslated error.
    assert result.exit_code == 2, f"stop()'s RuntimeError masked the refusal: {result.exception!r}"
    # The cleanup failure was made visible, not swallowed silently.
    stop_failed = [e for e in logs if e["event"] == "daemon.shutdown.supervisor_stop_failed"]
    assert stop_failed, "the failing supervisor.stop() was suppressed SILENTLY (HARD #7)"
    assert stop_failed[0]["error_class"] == "RuntimeError"
    # The reap chain still ran (the #255 leak guard is not regressed).
    assert not (tmp_path / "daemon.pid").exists()


@_posix_boot_only
def test_a_failing_supervisor_stop_on_a_clean_shutdown_stays_visible(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """On a CLEAN shutdown, stop() raising is the ONLY signal — it must NOT be swallowed.

    Distinguishes "cleanup can no longer mask a failure in flight" from "cleanup silently
    swallowed a real problem". With no exception in flight (``wait_for_shutdown`` returned),
    a raising ``stop()`` — a persistence failure re-raised by core err-002, or an unwritable
    shutdown audit — must still surface: non-zero exit AND a loud row.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(FakeSupervisor, "fail_stop", True)
    # wait_for_shutdown returns normally (the boot_success_env default) → clean shutdown.

    with structlog.testing.capture_logs() as logs:
        result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code != 0, "a clean-shutdown stop() failure was silently swallowed (exit 0)"
    stop_failed = [e for e in logs if e["event"] == "daemon.shutdown.supervisor_stop_failed"]
    assert stop_failed, "the clean-shutdown stop() failure produced no loud row (HARD #7)"
    assert stop_failed[0]["error_class"] == "RuntimeError"
    assert not (tmp_path / "daemon.pid").exists()


@_posix_boot_only
def test_a_succeeding_supervisor_stop_on_a_clean_shutdown_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """The non-raising arm: a clean shutdown with a well-behaved stop() exits 0, no loud row."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(FakeSupervisor, "fail_stop", False)

    with structlog.testing.capture_logs() as logs:
        result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code == 0, f"a clean boot+shutdown did not exit 0: {result.exception!r}"
    assert not [e for e in logs if e["event"] == "daemon.shutdown.supervisor_stop_failed"]
    assert not (tmp_path / "daemon.pid").exists()


@_posix_boot_only
def test_a_failing_stop_does_not_mask_a_going_down_audit_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """A raising stop() must not mask a HARD #5 going_down audit failure (#472 review).

    The ``boot_failure`` sentinel tracks the boot BODY, but ``_emit_going_down`` runs
    LATER in the drain finally. On a clean shutdown where the going_down audit emit fails
    (fail-loud, exit 3) AND ``supervisor.stop()`` also fails, stop()'s error must be
    suppressed so the going_down failure — the primary, audited one — survives, rather than
    being replaced by the cleanup error. CodeRabbit + the reviewer lane converged here.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(FakeSupervisor, "fail_stop", True)

    async def _failing_going_down(*_a: object, **_k: object) -> None:
        raise RuntimeError("going_down audit failed (fake)")

    monkeypatch.setattr("alfred.cli.daemon._commands._emit_going_down", _failing_going_down)

    with structlog.testing.capture_logs() as logs:
        result = CliRunner().invoke(daemon_app, ["start"])

    # The going_down failure survived — stop()'s RuntimeError did not replace it.
    assert isinstance(result.exception, RuntimeError)
    assert "going_down" in str(result.exception), (
        f"stop()'s error masked the going_down audit failure: {result.exception!r}"
    )
    # stop() was still attempted and its failure logged loud (then suppressed).
    assert [e for e in logs if e["event"] == "daemon.shutdown.supervisor_stop_failed"]
    # The reap chain still ran despite both failures (no #255 leak).
    assert not (tmp_path / "daemon.pid").exists()


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
