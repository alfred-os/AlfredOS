"""``swap()`` is audit-then-swap; audit failure aborts (PR-S4-4 Tasks 7-8).

err-004 closure: the audit row is written BEFORE the active-snapshot pointer
moves. If the audit write raises, the active snapshot stays at the previous
value (the watcher catches the raise and emits a rejected row).

rev-001 / arch-001 closure: the ``CONFIG_RELOAD_FIELDS`` row's ``file_path``
comes from ``new.file_path`` (the absolute YAML path) — NEVER a stringified
mtime float.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from alfred.audit.audit_row_schemas import CONFIG_RELOAD_FIELDS
from alfred.policies.snapshot_ref import PoliciesSnapshotRef

from ._audit_spy import SpyAudit
from ._factories import make_policies, make_snapshot

pytestmark = pytest.mark.asyncio


async def test_swap_emits_config_reload_audit_before_assignment() -> None:
    initial = make_snapshot()
    new = make_snapshot(
        policies=make_policies(rate_limits={"web_fetch_per_user_per_hour": 120}),
        file_path=Path("/etc/alfred/policies.yaml"),
    )
    audit = SpyAudit()
    ref = PoliciesSnapshotRef(initial)

    await ref.swap(new, audit=audit, trace_id="t-1")

    assert ref.current() is new
    subjects = audit.subjects_for("CONFIG_RELOAD_FIELDS")
    assert len(subjects) == 1
    row = subjects[0]
    assert row["file_path"] == "/etc/alfred/policies.yaml"
    assert row["prev_sha256"] == initial.file_sha256
    assert row["new_sha256"] == new.file_sha256
    assert row["operator_session_id"] is None
    assert "rate_limits.web_fetch_per_user_per_hour" in row["changed_keys"]


async def test_swap_uses_new_file_path_not_mtime() -> None:
    """Regression for the removed placeholder ``file_path=str(new.file_mtime)``."""
    initial = make_snapshot()
    new = make_snapshot(
        policies=make_policies(rate_limits={"web_fetch_per_user_per_hour": 120}),
        file_path=Path("/srv/policies.yaml"),
        file_mtime=1717000000.5,
    )
    audit = SpyAudit()
    ref = PoliciesSnapshotRef(initial)
    await ref.swap(new, audit=audit, trace_id="t-2")
    row = audit.subjects_for("CONFIG_RELOAD_FIELDS")[0]
    assert row["file_path"] == "/srv/policies.yaml"
    assert "1717000000" not in row["file_path"]


async def test_swap_audit_failure_aborts_assignment() -> None:
    initial = make_snapshot()
    new = make_snapshot(policies=make_policies(rate_limits={"web_fetch_per_user_per_hour": 120}))
    audit = SpyAudit()
    audit.raise_on("CONFIG_RELOAD_FIELDS", RuntimeError("audit-store outage"))
    ref = PoliciesSnapshotRef(initial)
    with pytest.raises(RuntimeError):
        await ref.swap(new, audit=audit, trace_id="t-3")
    assert ref.current() is initial


async def test_swap_writes_audit_even_when_sha_matches() -> None:
    """sec-007: the SHA short-circuit is the WATCHER's job, not swap()'s.

    A hand-constructed swap with a same-SHA snapshot still emits the audit row.
    """
    initial = make_snapshot()
    same_sha_new = make_snapshot(sha=initial.file_sha256, file_path=Path("/x.yaml"))
    audit = SpyAudit()
    ref = PoliciesSnapshotRef(initial)
    await ref.swap(same_sha_new, audit=audit, trace_id="t-4")
    assert audit.subjects_for("CONFIG_RELOAD_FIELDS")
    assert ref.current() is same_sha_new


async def test_swap_passes_operator_session_id_through() -> None:
    initial = make_snapshot()
    new = make_snapshot(policies=make_policies(rate_limits={"web_fetch_per_user_per_hour": 120}))
    audit = SpyAudit()
    ref = PoliciesSnapshotRef(initial)
    await ref.swap(new, audit=audit, trace_id="t-5", operator_session_id="op-abc")
    row = audit.subjects_for("CONFIG_RELOAD_FIELDS")[0]
    assert row["operator_session_id"] == "op-abc"
    assert frozenset(row.keys()) == CONFIG_RELOAD_FIELDS
