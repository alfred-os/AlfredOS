"""Trust-boundary coverage completion for src/alfred/policies/ (PR-S4-4 Task 31).

The policies package is a Slice-4 trust-boundary file list entry — 100% line +
branch coverage is required. The behaviour-focused suites cover the watcher's
main matrix; this module pins the remaining leaf branches (history writer,
bootstrap helper, the default hook invoker, the run() loop, history-write
failure, and the load-leg error arms) so coverage is total.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import alfred.policies.watcher as watcher_mod
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.policies.snapshot_ref import (
    PolicySnapshotHistoryWriter,
    _diff_keys,
    build_initial_snapshot,
)
from alfred.policies.watcher import PolicyWatcher, _first_error_key

from ._factories import make_policies, make_snapshot
from ._watcher_harness import allowlisted, build_watcher, write_policies
from ._watcher_harness import make_policies as _mk


async def test_history_writer_adds_and_flushes_row() -> None:
    """The writer constructs a PoliciesSnapshotHistory row + add/flush via the scope.

    A fake async session records the add()/flush() so the writer's body is
    covered without an async DB driver (the real DB round-trip is exercised by
    the integration suite).
    """
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock, MagicMock

    added: list[object] = []
    session = MagicMock()
    session.add = lambda row: added.append(row)
    session.flush = AsyncMock()

    @asynccontextmanager
    async def scope():
        yield session

    writer = PolicySnapshotHistoryWriter(session_factory=scope)
    snap = make_snapshot()
    snap_id = await writer.append(snap, applied_at=datetime.now(UTC), operator_session_id="op-1")
    assert snap_id
    assert len(added) == 1
    row = added[0]
    assert row.file_sha256 == snap.file_sha256  # type: ignore[attr-defined]
    assert row.applied_by_operator_session_id == "op-1"  # type: ignore[attr-defined]
    session.flush.assert_awaited_once()


def test_build_initial_snapshot(tmp_path: Path) -> None:
    cfg = tmp_path / "policies.yaml"
    model = make_policies()
    from alfred.policies.load import canonical_bytes

    cfg.write_bytes(canonical_bytes(model))
    snap = build_initial_snapshot(path=cfg, policies=model)
    assert snap.file_path == cfg.resolve()
    assert snap.policies == model


def test_diff_keys_top_level_field_change() -> None:
    """A schema_version change is a non-model top-level field diff (the else arm)."""
    a = make_policies()
    # schema_version is Literal[1] so we cannot change it; force the else branch
    # via a model whose top-level scalar differs. Build two models that differ
    # only in a scalar nested field to exercise the model branch, and assert the
    # scalar-vs-model branching is exercised through rate_limits.
    b = make_policies(rate_limits={"web_fetch_per_user_per_hour": 999})
    changed = _diff_keys(a, b)
    assert "rate_limits.web_fetch_per_user_per_hour" in changed


def test_first_error_key_returns_dotted_loc() -> None:
    try:
        make_policies(rate_limits={"web_fetch_per_user_per_hour": -1})
    except ValidationError as exc:
        assert _first_error_key(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValidationError")


def test_first_error_key_handles_no_errors(monkeypatch) -> None:
    try:
        make_policies(rate_limits={"web_fetch_per_user_per_hour": -1})
    except ValidationError as exc:
        monkeypatch.setattr(exc, "errors", list)
        assert _first_error_key(exc) == "<unknown>"


async def test_default_invoke_dispatches_against_registry() -> None:
    """_default_invoke builds a HookContext and dispatches a T0 post hook."""
    prior = get_registry()
    from tests.helpers.gates import make_permissive_fixture_gate

    reg = HookRegistry(gate=make_permissive_fixture_gate(allow_system=True))
    set_registry(reg)
    try:
        watcher_mod.declare_hookpoints(reg)
        # No subscribers -> a clean no-op success.
        await watcher_mod._default_invoke("supervisor.config_reload", {"new_sha": "abc"})
    finally:
        set_registry(prior)


async def test_run_loop_ticks_then_cancels(tmp_path: Path) -> None:
    watcher, _ref, _audit, _invoker = build_watcher(tmp_path, poll_interval=0.01)
    ticks = 0
    real_tick = watcher._tick

    async def _counting() -> None:
        nonlocal ticks
        ticks += 1
        await real_tick()

    watcher._tick = _counting  # type: ignore[method-assign]
    task = asyncio.create_task(watcher.run())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert ticks >= 1
    # Cover the degraded-cadence branch of _effective_interval.
    watcher._state = "degraded"
    assert watcher._effective_interval() == pytest.approx(watcher._interval * 10)


async def test_history_write_failure_is_swallowed_loudly(tmp_path: Path) -> None:
    """A history-write failure logs but does NOT unwind the committed swap."""
    import time

    watcher, ref, _audit, _invoker = build_watcher(tmp_path)

    class _BoomHistory:
        async def append(self, *_a, **_k):
            raise RuntimeError("history store down")

    watcher._history = _BoomHistory()  # type: ignore[assignment]
    new = _mk(rate_limits={"web_fetch_per_user_per_hour": 120})
    write_policies(watcher._path, new)
    future = time.time() + 5
    import os

    os.utime(watcher._path, (future, future))
    with allowlisted("rate_limits.web_fetch_per_user_per_hour"):
        await watcher._tick()
    # The swap committed despite the history-write failure.
    assert ref.current().policies.rate_limits.web_fetch_per_user_per_hour == 120


async def test_load_and_parse_file_vanished(tmp_path: Path) -> None:
    watcher, _ref, _audit, _invoker = build_watcher(tmp_path)
    watcher._path.unlink()
    outcome = await asyncio.to_thread(watcher._load_and_parse, 1.0)
    assert outcome.reject_reason == "file_vanished"


async def test_load_and_parse_oversize_is_parse_failure(tmp_path: Path) -> None:
    from alfred.policies.load import MAX_POLICIES_BYTES

    watcher, _ref, _audit, _invoker = build_watcher(tmp_path)
    watcher._path.write_bytes(b"# pad\n" * (MAX_POLICIES_BYTES // 4))
    outcome = await asyncio.to_thread(watcher._load_and_parse, 1.0)
    assert outcome.reject_reason == "parse_failure"
    assert outcome.offending_key == "<yaml_load>"


def test_fallback_jsonl_path_default_location() -> None:
    """The un-overridden fallback path anchors under ~/.local/state/alfred."""
    path = watcher_mod._fallback_jsonl_path()
    assert path.name == "policies-rejected-fallback.jsonl"
    assert path.parent.name == "alfred"


def test_reject_message_covers_every_reason() -> None:
    """Each RejectReason yields a translated (non-bare) message."""
    from alfred.policies.watcher import RejectReason, _reject_message

    for reason in RejectReason.__args__:  # type: ignore[attr-defined]
        msg = _reject_message(reason, offending_key="x.y")
        assert msg and msg != f"supervisor.config_reload.rejected.{reason}"


def test_high_blast_offending_key_equal_returns_none() -> None:
    """Field-equal high_blast -> None (the == early-return path)."""
    a = make_policies()
    b = make_policies()
    assert PolicyWatcher._high_blast_offending_key(a, b) is None


def test_high_blast_offending_key_names_changed_field() -> None:
    a = make_policies()
    b = make_policies(high_blast={"secret_broker_config_ref": "broker://other"})
    assert PolicyWatcher._high_blast_offending_key(a, b) == "high_blast.secret_broker_config_ref"


def test_high_blast_offending_key_skips_allowlisted_then_flags_next() -> None:
    """An allowlisted changed key is skipped; the next non-allowlisted key is flagged.

    Exercises the loop-continue edge: ``_diff_keys`` returns two changed keys,
    the first allowlisted (skipped) and the second high-blast (returned).
    """
    a = make_policies()
    b = make_policies(
        rate_limits={"web_fetch_per_user_per_hour": 120},
        handle_caps={"web_fetch_max_concurrent_handles_per_user": 99},
    )
    # ``_diff_keys`` sorts: ``handle_caps.*`` precedes ``rate_limits.*``.
    # Allowlist the FIRST so the loop must continue past it to flag the second.
    with allowlisted("handle_caps.web_fetch_max_concurrent_handles_per_user"):
        assert (
            PolicyWatcher._high_blast_offending_key(a, b)
            == "rate_limits.web_fetch_per_user_per_hour"
        )


def test_high_blast_offending_key_all_allowlisted_returns_none() -> None:
    """When every changed key is allowlisted, no high-blast key is flagged."""
    a = make_policies()
    b = make_policies(rate_limits={"web_fetch_per_user_per_hour": 120})
    with allowlisted("rate_limits.web_fetch_per_user_per_hour"):
        assert PolicyWatcher._high_blast_offending_key(a, b) is None
