"""``PoliciesSnapshotRef.current()`` is synchronous (PR-S4-4 Task 6).

perf-002 closure: ``current()`` is a GIL-atomic single-attribute load — no
``await`` trampoline. Consumers call ``ref.current().rate_limits.x``.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from alfred.policies.snapshot_ref import PoliciesSnapshotRef

from ._factories import make_snapshot


def test_current_is_synchronous_callable() -> None:
    ref = PoliciesSnapshotRef(make_snapshot())
    assert not inspect.iscoroutinefunction(ref.current)


def test_current_returns_active_snapshot_directly() -> None:
    initial = make_snapshot()
    ref = PoliciesSnapshotRef(initial)
    assert ref.current() is initial


def test_snapshot_hash_returns_active_sha() -> None:
    initial = make_snapshot(file_path=Path("/x.yaml"))
    ref = PoliciesSnapshotRef(initial)
    assert ref.snapshot_hash() == initial.file_sha256


def test_snapshot_carries_absolute_file_path() -> None:
    snap = make_snapshot(file_path=Path("/etc/alfred/policies.yaml"))
    assert snap.file_path == Path("/etc/alfred/policies.yaml")
