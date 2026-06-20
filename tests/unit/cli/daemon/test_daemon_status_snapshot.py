"""DaemonStatusSnapshot model + builder + file IO (G6-2b-2c / #288)."""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from alfred.cli.daemon._daemon_status_snapshot import (
    AdapterStatusLine,
    DaemonStatusSnapshot,
    DaemonStatusSnapshotFileError,
    LatestCrashSummary,
    build_daemon_status_snapshot,
    default_status_snapshot_path,
    delete_status_snapshot,
    load_status_snapshot,
    write_status_snapshot,
)
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

_NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)
_EPOCH = "0" * 32


class _Audit:
    async def append_schema(self, **_: object) -> None: ...


def _observer_with(reconciler: CrashIncidentReconciler) -> AdapterStatusObserver:
    return AdapterStatusObserver(
        audit=_Audit(),
        expected_epoch=lambda: _EPOCH,
        now=lambda: _NOW,
        reconciler=reconciler,
    )


# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #


async def test_builder_folds_state_and_incident_summary_per_adapter() -> None:
    reconciler = CrashIncidentReconciler()
    observer = _observer_with(reconciler)
    await observer.observe(
        "gateway.adapter.up",
        {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 1},
    )
    await observer.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "RuntimeError",
            "detail": "boom",
            "host_restart_seq": 1,
        },
    )
    snap = build_daemon_status_snapshot(
        boot_id="boot-xyz", written_at=_NOW, observer=observer, reconciler=reconciler
    )
    assert snap.boot_id == "boot-xyz"
    line = snap.adapters["discord"]
    assert line.state == "crashed"
    assert line.current_incarnation == 1
    assert line.crash_incident_count == 1
    assert line.latest_crash is not None
    assert line.latest_crash.crash_signal_source == "gateway"
    assert line.latest_crash.host_restart_seq == 1
    # NO secret / raw-detail fields exist on the model (json round-trips clean).
    dumped = snap.model_dump_json()
    assert "boom" not in dumped and "RuntimeError" not in dumped


async def test_builder_unions_observer_and_reconciler_adapters() -> None:
    reconciler = CrashIncidentReconciler()
    observer = _observer_with(reconciler)
    # An adapter known only to the reconciler (child-only crash, no gateway state).
    reconciler.observe_child_crash(adapter_id="telegram")
    await observer.observe(
        "gateway.adapter.up",
        {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 0},
    )
    snap = build_daemon_status_snapshot(
        boot_id="b", written_at=_NOW, observer=observer, reconciler=reconciler
    )
    assert set(snap.adapters) == {"discord", "telegram"}
    # telegram has a crash incident but no observed gateway state -> "unknown".
    assert snap.adapters["telegram"].state == "unknown"
    assert snap.adapters["telegram"].crash_incident_count == 1


async def test_builder_latest_crash_is_none_when_no_incidents() -> None:
    # correction #10 (T7): an adapter with observed ``up`` state and ZERO crash
    # incidents -> latest_crash is None, crash_incident_count == 0, state == "up".
    reconciler = CrashIncidentReconciler()
    observer = _observer_with(reconciler)
    await observer.observe(
        "gateway.adapter.up",
        {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 0},
    )
    snap = build_daemon_status_snapshot(
        boot_id="b", written_at=_NOW, observer=observer, reconciler=reconciler
    )
    line = snap.adapters["discord"]
    assert line.state == "up"
    assert line.crash_incident_count == 0
    assert line.latest_crash is None


async def test_builder_latest_crash_picks_most_recent_incarnation() -> None:
    # correction #8 (T5/H3): "latest crash" == incidents[-1] (most-recently-opened
    # incarnation). Two incidents at distinct incarnations -> the LATEST seq wins.
    reconciler = CrashIncidentReconciler()
    observer = _observer_with(reconciler)
    reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=0)
    reconciler.note_incarnation(adapter_id="discord", host_restart_seq=2)
    reconciler.observe_gateway_crash(adapter_id="discord", host_restart_seq=2)
    snap = build_daemon_status_snapshot(
        boot_id="b", written_at=_NOW, observer=observer, reconciler=reconciler
    )
    line = snap.adapters["discord"]
    assert line.crash_incident_count == 2
    assert line.latest_crash is not None
    assert line.latest_crash.host_restart_seq == 2


def test_model_field_sets_are_locked() -> None:
    # correction #4 (sec-MEDIUM-1): the no-secret guarantee is enforced by an EXACT
    # field-set lock, not only ``extra="forbid"``. A future field addition fails CI
    # here and forces reviewer justification (no secret/T3 field may sneak on).
    assert set(AdapterStatusLine.model_fields) == {
        "adapter_id",
        "state",
        "occurred_at",
        "current_incarnation",
        "crash_incident_count",
        "latest_crash",
    }
    assert set(LatestCrashSummary.model_fields) == {
        "host_restart_seq",
        "crash_signal_source",
        "crash_incident_id",
    }
    assert set(DaemonStatusSnapshot.model_fields) == {"boot_id", "written_at", "adapters"}


# --------------------------------------------------------------------------- #
# File IO (mirrors the pidfile discipline)
# --------------------------------------------------------------------------- #


def _snap() -> DaemonStatusSnapshot:
    return DaemonStatusSnapshot(boot_id="b1", written_at="2026-06-20T00:00:00+00:00", adapters={})


def test_write_then_load_round_trips_at_mode_0600(tmp_path: Path) -> None:
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = load_status_snapshot(path)
    assert loaded.boot_id == "b1"


def test_load_refuses_a_world_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap())
    path.chmod(0o644)
    with pytest.raises(DaemonStatusSnapshotFileError):
        load_status_snapshot(path)


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(DaemonStatusSnapshotFileError):
        load_status_snapshot(tmp_path / "nope.json")


def test_load_raises_malformed_on_garbage_bytes(tmp_path: Path) -> None:
    # correction #9 (T6.H4): garbage bytes at the correct mode -> malformed_snapshot
    # (the same branch an oversized truncated file hits). Write garbage at 0600 by
    # hand so the fstat gate passes and the JSON parse is what fails.
    path = tmp_path / "daemon-status.json"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"\xff not json {{{")
    os.close(fd)
    with pytest.raises(DaemonStatusSnapshotFileError) as exc:
        load_status_snapshot(path)
    assert "malformed_snapshot" in str(exc.value)


def test_load_refuses_a_non_regular_file(tmp_path: Path) -> None:
    # A planted FIFO / device / socket could block on read or feed garbage; the
    # O_NONBLOCK open returns immediately and the fstat S_ISREG check refuses it
    # before any read (mirrors the pidfile discipline).
    fifo = tmp_path / "daemon-status.json"
    os.mkfifo(fifo, mode=0o600)
    with pytest.raises(DaemonStatusSnapshotFileError, match="not_a_regular_file"):
        load_status_snapshot(fifo)


def test_load_refuses_a_foreign_owned_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A same-mode file owned by another uid is refused (spoof st_uid via fstat,
    # mirroring the pidfile suite — a real chown needs privileges).
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap())
    real_fstat = os.fstat

    def _fake_fstat(fd: int) -> os.stat_result:
        fields = list(real_fstat(fd))
        fields[4] = 999_999  # st_uid -> a uid that is not ours
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", _fake_fstat)
    with pytest.raises(DaemonStatusSnapshotFileError, match="bad_file_owner"):
        load_status_snapshot(path)


def test_delete_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap())
    delete_status_snapshot(path)
    delete_status_snapshot(path)  # a missing file is not an error
    assert not path.exists()


def test_write_is_atomic_no_temp_left_behind(tmp_path: Path) -> None:
    path = tmp_path / "daemon-status.json"
    write_status_snapshot(path, _snap())
    assert [p.name for p in tmp_path.iterdir()] == ["daemon-status.json"]


def test_write_cleans_temp_on_post_open_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # correction #10 (T9): a failure AFTER os.open succeeds (rename raises) must
    # remove the .tmp, leave the target untouched, and propagate (hits the
    # ``except BaseException`` cleanup arm).
    path = tmp_path / "daemon-status.json"

    def _boom(self: Path, target: object) -> None:
        raise OSError("rename refused")

    monkeypatch.setattr(Path, "rename", _boom)
    with pytest.raises(OSError, match="rename refused"):
        write_status_snapshot(path, _snap())
    # No target written, and no orphaned temp left behind.
    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


def test_default_path_resolves_home_at_call_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # correction #1 (arch-H1): the path must resolve ``Path.home()`` at CALL time
    # so a test that monkeypatches $HOME sees the redirected location.
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_status_snapshot_path() == tmp_path / ".run" / "alfred" / "daemon-status.json"
