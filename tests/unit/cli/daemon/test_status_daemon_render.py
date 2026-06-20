"""alfred daemon status — per-adapter snapshot render (G6-2b-2c / #288)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._daemon_pidfile import write_pidfile
from alfred.cli.daemon._daemon_status_snapshot import (
    AdapterStatusLine,
    DaemonStatusSnapshot,
    LatestCrashSummary,
    write_status_snapshot,
)


def _wire_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    pidfile = tmp_path / "daemon.pid"
    snapshot = tmp_path / "daemon-status.json"
    monkeypatch.setattr("alfred.cli.daemon._commands.default_pidfile_path", lambda: pidfile)
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.default_status_snapshot_path", lambda: snapshot
    )
    return pidfile, snapshot


def _write_live_pidfile(pidfile: Path, boot_id: str) -> None:
    write_pidfile(pidfile, pid=os.getpid(), boot_id=boot_id, started_at="2026-06-20T00:00:00+00:00")


def test_status_renders_adapter_lines_when_boot_id_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pidfile, snapshot = _wire_paths(monkeypatch, tmp_path)
    _write_live_pidfile(pidfile, "boot-A")
    write_status_snapshot(
        snapshot,
        DaemonStatusSnapshot(
            boot_id="boot-A",
            written_at="2026-06-20T00:00:01+00:00",
            adapters={
                "discord": AdapterStatusLine(
                    adapter_id="discord",
                    state="crashed",
                    current_incarnation=1,
                    crash_incident_count=2,
                )
            },
        ),
    )
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert "discord" in result.stdout
    assert "crashed" in result.stdout  # the LOCALIZED state token (correction #11)


def test_status_renders_latest_crash_via_catalog_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # correction #11 (T12): a populated LatestCrashSummary with source ``both``
    # renders the seq + source through the catalog key, framed as diagnostic origin
    # (NOT authenticated corroboration — SEC-02).
    pidfile, snapshot = _wire_paths(monkeypatch, tmp_path)
    _write_live_pidfile(pidfile, "boot-A")
    write_status_snapshot(
        snapshot,
        DaemonStatusSnapshot(
            boot_id="boot-A",
            written_at="x",
            adapters={
                "discord": AdapterStatusLine(
                    adapter_id="discord",
                    state="crashed",
                    current_incarnation=2,
                    crash_incident_count=1,
                    latest_crash=LatestCrashSummary(
                        host_restart_seq=2,
                        crash_signal_source="both",
                        crash_incident_id="abc",
                    ),
                )
            },
        ),
    )
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert "2" in result.stdout  # the incarnation/seq of the latest crash
    assert "both" in result.stdout  # the diagnostic-origin source label


def test_status_ignores_snapshot_with_mismatched_boot_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pidfile, snapshot = _wire_paths(monkeypatch, tmp_path)
    _write_live_pidfile(pidfile, "boot-A")
    write_status_snapshot(
        snapshot,
        DaemonStatusSnapshot(
            boot_id="STALE",
            written_at="x",
            adapters={"discord": AdapterStatusLine(adapter_id="discord", state="up")},
        ),
    )
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0
    # A stale snapshot (prior incarnation's boot_id) is ignored -> no adapter section.
    assert "discord" not in result.stdout


def test_status_without_snapshot_still_renders_pidfile_subset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pidfile, _snapshot = _wire_paths(monkeypatch, tmp_path)
    _write_live_pidfile(pidfile, "boot-A")
    result = CliRunner().invoke(daemon_app, ["status"])
    # No snapshot file -> back-compat: just the pidfile subset, exit 0.
    assert result.exit_code == 0
    assert "boot-A" in result.stdout


def test_status_skips_present_but_malformed_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # correction #9 (T6.H4): a PRESENT, correct-mode, but malformed-JSON snapshot ->
    # the loader raises DaemonStatusSnapshotFileError -> render exits 0 with no
    # adapter section (the except-and-return back-compat branch).
    pidfile, snapshot = _wire_paths(monkeypatch, tmp_path)
    _write_live_pidfile(pidfile, "boot-A")
    fd = os.open(str(snapshot), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"{ not valid json")
    os.close(fd)
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0
    assert "discord" not in result.stdout


def test_status_renders_empty_adapters_none_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A matching snapshot with NO adapters -> the "none reported" line (exercises the
    # empty-adapters branch).
    pidfile, snapshot = _wire_paths(monkeypatch, tmp_path)
    _write_live_pidfile(pidfile, "boot-A")
    write_status_snapshot(
        snapshot,
        DaemonStatusSnapshot(boot_id="boot-A", written_at="x", adapters={}),
    )
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0
