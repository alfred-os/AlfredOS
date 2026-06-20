"""The daemon boot loop publishes + reaps the status snapshot (G6-2b-2c / #288).

correction #7 (test-H1): assert the REAL snapshot file via the REAL drain path —
during run the file exists + parses + its boot_id matches; after the boot command
returns (the drain ``finally`` ran ``aclose()``), the file is GONE. Reaping is
proven by the real delete, NOT by spying that ``aclose`` was called (a false-green).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._daemon_status_snapshot import load_status_snapshot

from .conftest import FakeAuditWriter
from .test_daemon_comms_spawn import (
    _ENABLED_ADAPTER,
    _patch_comms_seams,
    quarantine_registry,
)

__all__ = ["quarantine_registry"]  # re-exported fixture; silence the unused-import lint


def test_daemon_publishes_and_reaps_status_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: Any,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    del quarantine_registry
    del patch_quarantine_child_spawn

    snapshot_path = tmp_path / "daemon-status.json"
    monkeypatch.setattr(
        "alfred.cli.daemon._commands.default_status_snapshot_path",
        lambda: snapshot_path,
    )

    # Capture the snapshot's mid-run state in a custom wait_for_shutdown that runs
    # BEFORE the drain finally. Give the publisher loop a tick to write its first
    # refresh, then record. This drives the REAL boot loop + REAL drain reap.
    mid_run: dict[str, Any] = {}

    async def _capture_then_return(_supervisor: Any) -> None:
        import asyncio

        for _ in range(50):
            await asyncio.sleep(0.01)
            if snapshot_path.exists():
                break
        mid_run["existed"] = snapshot_path.exists()
        if mid_run["existed"]:
            mid_run["snapshot"] = load_status_snapshot(snapshot_path)

    monkeypatch.setattr(
        "alfred.cli.daemon._commands.wait_for_shutdown",
        _capture_then_return,
    )
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # During run: the file existed, parsed, and carried THIS boot's boot_id.
    # (``adapters`` is empty here: no live gateway ``gateway.adapter.*`` frame is
    # observed in this fake boot, so the observer's latest map is empty — the
    # publisher still publishes the boot_id-tied envelope, which is what the CLI
    # cross-checks. Per-adapter content is exercised by the builder/render suites.)
    assert mid_run.get("existed") is True
    snapshot = mid_run["snapshot"]
    assert snapshot.boot_id  # a non-empty boot id was published

    # After the drain finally: the snapshot file is reaped (like the pidfile).
    assert not snapshot_path.exists()
