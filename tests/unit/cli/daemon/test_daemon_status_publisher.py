"""DaemonStatusSnapshotPublisher — periodic write-if-changed (G6-2b-2c / #288)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from structlog.testing import capture_logs

from alfred.cli.daemon._daemon_status_publisher import DaemonStatusSnapshotPublisher
from alfred.cli.daemon._daemon_status_snapshot import load_status_snapshot
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

_EPOCH = "0" * 32
_NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)


class _Audit:
    async def append_schema(self, **_: object) -> None: ...


def _observer(reconciler: CrashIncidentReconciler) -> AdapterStatusObserver:
    return AdapterStatusObserver(
        audit=_Audit(),
        expected_epoch=lambda: _EPOCH,
        now=lambda: _NOW,
        reconciler=reconciler,
    )


def _publisher(
    path: Path,
    observer: AdapterStatusObserver,
    reconciler: CrashIncidentReconciler,
    *,
    now: Callable[[], datetime] = lambda: _NOW,
) -> DaemonStatusSnapshotPublisher:
    return DaemonStatusSnapshotPublisher(
        path=path,
        boot_id="boot-1",
        observer=observer,
        reconciler=reconciler,
        now=now,
        interval_seconds=0.01,
    )


async def test_refresh_once_writes_current_state(tmp_path: Path) -> None:
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    await observer.observe(
        "gateway.adapter.up",
        {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 0},
    )
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    await pub.refresh_once()
    loaded = load_status_snapshot(path)
    assert loaded.adapters["discord"].state == "up"
    assert loaded.boot_id == "boot-1"


async def test_refresh_skips_write_when_unchanged(tmp_path: Path) -> None:
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    await pub.refresh_once()
    first_mtime = path.stat().st_mtime_ns
    await pub.refresh_once()  # nothing changed -> no rewrite
    assert path.stat().st_mtime_ns == first_mtime


async def test_refresh_rewrites_on_real_state_change(tmp_path: Path) -> None:
    # correction #5 (test-C1): prove the REWRITE half. A ``_last_json`` that never
    # updated would false-green the skip-on-unchanged test, so drive a REAL state
    # change and assert both the content AND the rewrite.
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    await observer.observe(
        "gateway.adapter.up",
        {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 0},
    )
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    await pub.refresh_once()
    before = path.read_bytes()
    assert load_status_snapshot(path).adapters["discord"].state == "up"
    # A REAL adapter-state change.
    await observer.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "RuntimeError",
            "detail": "boom",
            "host_restart_seq": 0,
        },
    )
    await pub.refresh_once()
    after = path.read_bytes()
    assert after != before
    assert load_status_snapshot(path).adapters["discord"].state == "crashed"


async def test_advancing_clock_alone_does_not_rewrite(tmp_path: Path) -> None:
    # correction #6 (test-C2a): the content-key EXCLUDES written_at, so an advancing
    # clock with unchanged adapter state must NOT rewrite (timestamp-only diff
    # suppressed -> no churn).
    clock = {"t": _NOW}
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler, now=lambda: clock["t"])
    await pub.refresh_once()
    first_mtime = path.stat().st_mtime_ns
    clock["t"] = _NOW + timedelta(minutes=5)  # only the clock advanced
    await pub.refresh_once()
    assert path.stat().st_mtime_ns == first_mtime


async def test_constant_clock_real_change_still_rewrites(tmp_path: Path) -> None:
    # correction #6 (test-C2b): a CONSTANT clock with a real state change must
    # rewrite (a same-second real change is NOT falsely suppressed by the
    # written_at-excluded content key).
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)  # constant clock _NOW
    await pub.refresh_once()
    before = path.read_bytes()
    await observer.observe(
        "gateway.adapter.up",
        {"adapter_id": "discord", "epoch": _EPOCH, "host_restart_seq": 0},
    )
    await pub.refresh_once()
    assert path.read_bytes() != before


async def test_aclose_cancels_task_and_deletes_file(tmp_path: Path) -> None:
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    pub.start()
    await pub.refresh_once()
    assert path.exists()
    await pub.aclose()
    assert not path.exists()  # reaped like the pidfile


async def test_start_is_idempotent(tmp_path: Path) -> None:
    # correction #10 (T10): start() twice yields exactly one task.
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    pub = _publisher(tmp_path / "daemon-status.json", observer, reconciler)
    pub.start()
    first = pub._task
    pub.start()
    assert pub._task is first
    await pub.aclose()


async def test_aclose_on_never_started_publisher_is_safe(tmp_path: Path) -> None:
    # correction #10 (T11): aclose() without start() — no raise, file still reaped.
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    await pub.refresh_once()  # write the file but never start the loop
    assert path.exists()
    await pub.aclose()  # must not raise
    assert not path.exists()


async def test_write_failure_is_loud_but_non_fatal(tmp_path: Path) -> None:
    # correction #2 (sec-MEDIUM-4 + test-H2): a write failure must NOT raise
    # (observability is best-effort) but MUST be logged LOUD (never silent).
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    # Point the snapshot's PARENT at a regular file so mkdir/open fails.
    bad_parent = tmp_path / "afile"
    bad_parent.write_text("x")
    pub = _publisher(bad_parent / "daemon-status.json", observer, reconciler)
    with capture_logs() as logs:
        await pub.refresh_once()  # must not raise
    assert any(e["event"] == "daemon_status_snapshot_write_failed" for e in logs)


async def test_run_loop_survives_a_bad_refresh(tmp_path: Path) -> None:
    # correction #2 (test-H2 / _run resilience): a single bad refresh logs and the
    # supervised loop CONTINUES (a silently-dead publisher misleads worse than no
    # snapshot). A ``_build`` fault is caught by ``refresh_once`` itself (logged
    # ``..._write_failed``); the loop must keep iterating and HEAL once the fault
    # clears, eventually writing the file.
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    calls = {"n": 0}
    real_build = pub._build

    def _flaky():  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient build fault")
        return real_build()

    pub._build = _flaky  # type: ignore[method-assign]
    healed = False
    with capture_logs() as logs:
        pub.start()
        # Let the loop run a few iterations: first raises (logged, not fatal),
        # later iterations heal + write. Observe the heal BEFORE aclose (which reaps
        # the file).
        for _ in range(50):
            await asyncio.sleep(0.01)
            if path.exists():
                healed = True
                break
        await pub.aclose()
    assert calls["n"] >= 2  # the loop did NOT die on the first fault
    assert healed  # it healed and wrote on a later iteration
    assert any(e["event"] == "daemon_status_snapshot_write_failed" for e in logs)


async def test_run_loop_survives_a_fault_outside_refresh_once(tmp_path: Path) -> None:
    # correction #2 (_run resilience, the OTHER arm): a fault that escapes
    # ``refresh_once`` (here, a patched ``refresh_once`` that raises) is caught by
    # the loop body guard, logged ``..._refresh_failed``, and the loop continues
    # (it does not silently die). Heals once the patch clears.
    reconciler = CrashIncidentReconciler()
    observer = _observer(reconciler)
    path = tmp_path / "daemon-status.json"
    pub = _publisher(path, observer, reconciler)
    real_refresh = pub.refresh_once
    calls = {"n": 0}

    async def _flaky() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("fault outside refresh_once")
        await real_refresh()

    pub.refresh_once = _flaky  # type: ignore[method-assign]
    with capture_logs() as logs:
        pub.start()
        for _ in range(50):
            await asyncio.sleep(0.01)
            if path.exists():
                break
        await pub.aclose()
    assert calls["n"] >= 2
    assert any(e["event"] == "daemon_status_snapshot_refresh_failed" for e in logs)
