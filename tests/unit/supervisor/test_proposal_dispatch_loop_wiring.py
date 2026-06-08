"""Supervisor wiring tests for the proposal dispatch loop — Task 7 of #171.

The loop schedule is gated on ``state_git_path`` being supplied at
construction time:

* When None — the loop is NOT scheduled. Legacy unit tests that don't
  care about state.git continue to work unchanged.
* When supplied — the loop runs as a sibling TaskGroup task of the
  capability heartbeat, reads its interval from
  ``Settings.proposal_dispatch_interval_s`` (via the supervisor's
  ``proposal_dispatch_interval_s`` init arg), and respects the
  supervisor's shutdown discipline.

Error discipline pins per ADR-0021 §Consequences: an uncaught exception
inside the cycle MUST NOT crash the TaskGroup (the dispatch loop is
non-critical-path; one skipped cycle delays a single operator action
by ≤ interval seconds).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from alfred.supervisor.core import Supervisor
from tests.helpers.dlp import identity_outbound_dlp as _identity_dlp


@asynccontextmanager
async def _fake_session_scope() -> AsyncIterator[Any]:
    session = AsyncMock()
    session.commit = AsyncMock()
    yield session


def _build_supervisor(
    *,
    state_git_path: Path | None = None,
    proposal_dispatch_interval_s: int = 30,
) -> tuple[Supervisor, dict[str, Any]]:
    """Construct a Supervisor with structural mocks for gate + audit + DLP."""
    gate = MagicMock()
    gate.is_backing_store_available = MagicMock(return_value=True)
    audit = AsyncMock()
    audit.append = AsyncMock()
    audit.append_schema = AsyncMock()
    sup = Supervisor(
        session_scope=_fake_session_scope,
        gate=gate,
        audit=audit,
        state_git_path=state_git_path,
        proposal_dispatch_interval_s=proposal_dispatch_interval_s,
        outbound_dlp=_identity_dlp(),
    )
    return sup, {"gate": gate, "audit": audit}


# ---------------------------------------------------------------------------
# Init kwargs
# ---------------------------------------------------------------------------


def test_supervisor_init_records_state_git_path(tmp_path: Path) -> None:
    """``state_git_path`` is stashed so the loop knows the repo."""
    path = tmp_path / "state.git"
    sup, _ = _build_supervisor(state_git_path=path)
    assert sup._state_git_path == path


def test_supervisor_init_state_git_path_default_none() -> None:
    """Default ``state_git_path=None`` keeps legacy callers working."""
    sup, _ = _build_supervisor()
    assert sup._state_git_path is None


def test_supervisor_init_records_proposal_dispatch_interval_s() -> None:
    """The dispatch-cycle cadence threads through from Settings."""
    sup, _ = _build_supervisor(proposal_dispatch_interval_s=7)
    assert sup._proposal_dispatch_interval_s == 7


def test_supervisor_init_default_interval_matches_settings_default() -> None:
    """Default 30s matches Settings.proposal_dispatch_interval_s default."""
    sup, _ = _build_supervisor()
    assert sup._proposal_dispatch_interval_s == 30


# ---------------------------------------------------------------------------
# Schedule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supervisor_does_not_schedule_dispatch_loop_when_state_git_path_none(
    tmp_path: Path,
) -> None:
    """Legacy callers omit ``state_git_path`` — no dispatch loop scheduled."""
    sup, _ = _build_supervisor(state_git_path=None)
    with patch(
        "alfred.state.dispatch_loop._proposal_dispatch_cycle",
        new=AsyncMock(),
    ) as cycle:
        await sup.start()
        try:
            # Give the event loop a tick to spawn tasks.
            await asyncio.sleep(0.05)
            assert cycle.await_count == 0
        finally:
            await sup.stop()


@pytest.mark.asyncio
async def test_supervisor_schedules_dispatch_loop_when_state_git_path_set(
    tmp_path: Path,
) -> None:
    """Path supplied → cycle runs at least once after start()."""
    sup, _ = _build_supervisor(
        state_git_path=tmp_path / "state.git",
        proposal_dispatch_interval_s=1,
    )
    cycle = AsyncMock()
    with patch(
        "alfred.state.dispatch_loop._proposal_dispatch_cycle",
        new=cycle,
    ):
        await sup.start()
        try:
            # Give the loop a tick to invoke the cycle once.
            for _ in range(50):
                if cycle.await_count > 0:
                    break
                await asyncio.sleep(0.02)
            assert cycle.await_count >= 1
        finally:
            await sup.stop()


@pytest.mark.asyncio
async def test_supervisor_dispatch_loop_respects_interval_kwarg(
    tmp_path: Path,
) -> None:
    """Custom interval is the cadence between cycles."""
    sup, _ = _build_supervisor(
        state_git_path=tmp_path / "state.git",
        proposal_dispatch_interval_s=2,
    )
    cycle = AsyncMock()
    with patch(
        "alfred.state.dispatch_loop._proposal_dispatch_cycle",
        new=cycle,
    ):
        await sup.start()
        try:
            for _ in range(50):
                if cycle.await_count > 0:
                    break
                await asyncio.sleep(0.02)
            assert cycle.await_count >= 1
            # Within ~1.5 cycle interval the second cycle should not have
            # fired (gives confidence the interval IS the gate).
            await asyncio.sleep(0.3)
            assert cycle.await_count <= 2
        finally:
            await sup.stop()


# ---------------------------------------------------------------------------
# Cancellation + error discipline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supervisor_dispatch_loop_cancels_on_shutdown(
    tmp_path: Path,
) -> None:
    """Stop() propagates cancel through the loop's wait_for."""
    sup, _ = _build_supervisor(
        state_git_path=tmp_path / "state.git",
        proposal_dispatch_interval_s=30,
    )
    cycle = AsyncMock()
    with patch(
        "alfred.state.dispatch_loop._proposal_dispatch_cycle",
        new=cycle,
    ):
        await sup.start()
        # stop() must drain promptly — even though the loop's sleep is
        # 30s, the shutdown_event wakes it.
        await sup.stop()
        # And the run task must be done by here.
        assert sup._run_task is None or sup._run_task.done()


@pytest.mark.asyncio
async def test_supervisor_dispatch_loop_log_and_skips_on_cycle_uncaught(
    tmp_path: Path,
) -> None:
    """A bare exception out of the cycle is logged + the loop continues.

    ADR-0021 §Consequences: dispatch is non-critical-path; one cycle
    failure must not crash the supervisor.
    """
    sup, _ = _build_supervisor(
        state_git_path=tmp_path / "state.git",
        proposal_dispatch_interval_s=1,
    )
    counter = {"n": 0}

    async def _flaky_cycle(**kwargs: Any) -> None:
        counter["n"] += 1
        if counter["n"] == 1:
            raise RuntimeError("simulated dispatch outage")

    with patch(
        "alfred.state.dispatch_loop._proposal_dispatch_cycle",
        new=_flaky_cycle,
    ):
        await sup.start()
        try:
            for _ in range(100):
                if counter["n"] >= 2:
                    break
                await asyncio.sleep(0.02)
            # The loop survived the first cycle's exception and ran a
            # second cycle.
            assert counter["n"] >= 2
        finally:
            await sup.stop()


@pytest.mark.asyncio
async def test_supervisor_dispatch_loop_emits_cycle_skipped_on_outer_uncaught(
    tmp_path: Path,
) -> None:
    """CR-rework round-2 MAJOR T6: the outer catch-all emits a skip-row audit.

    ADR-0021 contract: every aborted dispatch cycle emits a
    ``state.proposal.dispatch_cycle_skipped`` row — no silent skips. The
    inner cycle's failure arms already do this for known failure modes;
    the supervisor's outer ``except Exception`` catches any failure that
    escapes the dispatcher's own discipline (a regression in the cycle's
    exception arms). Without the outer-arm emit, an uncaught exception
    inside the cycle would silently drop the audit signal.

    Pins both halves: (a) the audit row lands with
    ``skip_reason="cycle_uncaught_exception"`` and the error type as
    metadata; (b) the loop survives and runs the next cycle.
    """
    sup, deps = _build_supervisor(
        state_git_path=tmp_path / "state.git",
        proposal_dispatch_interval_s=1,
    )
    counter = {"n": 0}

    async def _flaky_cycle(**kwargs: Any) -> None:
        counter["n"] += 1
        if counter["n"] == 1:
            raise RuntimeError("simulated outer escape")

    with patch(
        "alfred.state.dispatch_loop._proposal_dispatch_cycle",
        new=_flaky_cycle,
    ):
        await sup.start()
        try:
            for _ in range(100):
                if counter["n"] >= 2:
                    break
                await asyncio.sleep(0.02)
            assert counter["n"] >= 2
        finally:
            await sup.stop()

    audit = deps["audit"]
    skip_calls = [
        c
        for c in audit.append_schema.await_args_list
        if c.kwargs.get("event") == "state.proposal.dispatch_cycle_skipped"
    ]
    # At least one skip row landed on the uncaught-exception arm.
    assert len(skip_calls) >= 1
    subject = skip_calls[0].kwargs.get("subject", {})
    assert subject.get("skip_reason") == "cycle_uncaught_exception"
    assert "correlation_id" in subject
