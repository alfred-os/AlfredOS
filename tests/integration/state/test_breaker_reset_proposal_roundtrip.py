"""End-to-end round-trip for ``BreakerResetProposal`` — Task 10 of #171.

ADR-0021 §First user. Walks the full dispatch path:

1. Write a tripped breaker row to ``circuit_breakers``.
2. Bootstrap the dispatcher's sentinel via a real cycle.
3. Land a ``BreakerResetProposal`` blob on the state.git fixture's
   ``main`` (simulating the reviewer merge — direct write to the
   merged-tree, matching the precedent for grant proposals).
4. Invoke ``_proposal_dispatch_cycle``.
5. Assert:
   * ``processed_proposals`` row landed with ``result="applied"``.
   * ``ctx.effects.reset_breaker`` was called (recorded via the
     mock effects).
   * The supervisor-side ``supervisor.breaker.reset`` audit row was
     emitted.
   * The state.proposal.processed audit row was emitted.
   * Replay is safe — re-running the cycle is a no-op.

The failure path:

* Unknown ``component_id`` → handler returns ``failed`` → ledger row
  with ``result="failed_handler"``, ``failure_kind="handler_returned_failed"``.
* Audit row + ledger row both land; re-running the cycle does NOT
  re-invoke the handler.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.memory.models import Base, ProcessedProposal, ProcessedProposalsHead
from alfred.security.dlp import OutboundDlp
from alfred.state.dispatch_loop import _proposal_dispatch_cycle
from alfred.state.dispatch_registry import (
    PROPOSAL_HANDLERS,
    ProposalContext,
    ProposalEffectsProtocol,
)
from alfred.supervisor.errors import NoSuchComponentError


def _identity_dlp() -> OutboundDlp:
    """An OutboundDlp whose stages are no-ops — satisfies the required field."""

    class _IdentityBroker:
        def redact(self, text: str) -> str:
            return text

    def _sink(*, event: str, subject: object) -> None:
        return None

    return OutboundDlp(broker=_IdentityBroker(), audit=_sink)


pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


@pytest.fixture
async def session_scope_factory(
    postgres_url: str,
) -> AsyncIterator[Callable[[], AbstractAsyncContextManager[AsyncSession]]]:
    """Real Postgres session_scope mirroring the production wiring."""
    engine = create_async_engine(postgres_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sm = async_sessionmaker(bind=engine, expire_on_commit=False)

    @asynccontextmanager
    async def _scope() -> AsyncIterator[AsyncSession]:
        async with sm() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    try:
        # Seed sentinel row as the migration does.
        async with _scope() as s:
            s.add(ProcessedProposalsHead(id=1, head_sha=None))
        yield _scope
    finally:
        await engine.dispose()


@pytest.fixture
def state_git_repo(tmp_path: Path) -> Path:
    """Real bare-shaped git repo for the dispatcher to walk."""
    repo = tmp_path / "state.git"
    repo.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "init", "-q", "-b", "main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "config", "user.name", "test"],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "commit", "--allow-empty", "-m", "init", "-q"],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", "HEAD"],  # noqa: S607
        check=True,
    )
    return repo


def _commit_proposal(
    repo: Path,
    proposal_id: str,
    component_id: str,
    operator_user_id: str = "operator-1",
) -> str:
    """Materialise a BreakerResetProposal blob via the canonical writer convention."""
    rel = f"policies/breaker-resets/{proposal_id}.json"
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "component_id": component_id,
                "operator_user_id": operator_user_id,
                "reason": "operator_initiated",
            },
            indent=2,
            sort_keys=True,
        )
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "add", rel],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "commit", "-m", "add proposal", "-q"],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", "HEAD"],  # noqa: S607
        check=True,
    )
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _make_effects() -> AsyncMock:
    """Mocked ProposalEffectsProtocol; ``reset_breaker`` records calls."""
    return AsyncMock(spec=ProposalEffectsProtocol)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_breaker_reset_proposal_round_trip_happy_path(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """End-to-end: write proposal → cycle → ledger + reset_breaker + replay safety."""
    effects = _make_effects()
    audit = AsyncMock(spec=AuditWriter)
    ctx = ProposalContext(
        audit_writer=audit,
        effects=effects,
        logger=structlog.get_logger("test"),
        outbound_dlp=_identity_dlp(),
    )

    # Bootstrap.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
    )

    # Reviewer merge — write the blob to main (matches the precedent
    # in tests/integration/state/test_state_git_writer_consolidation.py).
    commit_sha = _commit_proposal(
        state_git_repo, proposal_id="abc123def4567890", component_id="alfred.web-fetch"
    )

    # Cycle picks it up and dispatches.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
    )

    # (a) Ledger row landed with applied result.
    async with session_scope_factory() as s:
        row = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    assert row.result == "applied"
    assert row.failure_kind is None
    assert row.commit_sha == commit_sha
    assert row.operator_user_id == "operator-1"

    # (b) reset_breaker was called with the payload fields.
    # CR rework round-1 HIGH #17: ``component_id`` is positional;
    # ``operator_user_id`` is keyword-only.
    effects.reset_breaker.assert_awaited_once_with(
        "alfred.web-fetch",
        operator_user_id="operator-1",
    )

    # (c) The dispatcher emitted state.proposal.processed.
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]
    assert "state.proposal.processed" in events

    # (d) Replay: a second cycle is a no-op — no second reset_breaker call.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
    )
    assert effects.reset_breaker.await_count == 1


# ---------------------------------------------------------------------------
# Failure path — NoSuchComponentError
# ---------------------------------------------------------------------------


async def test_breaker_reset_proposal_round_trip_unknown_component(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Unknown component_id → handler returns failed; ledger + audit row + no replay.

    Uses the REAL ``_handle_breaker_reset`` (not a mocked-handler stub) so
    the actual dispatcher path through ``NoSuchComponentError`` →
    ``DispatchOutcome.failed`` is exercised end-to-end.
    """
    effects = _make_effects()
    effects.reset_breaker.side_effect = NoSuchComponentError(
        "component alfred.totally-bogus not registered"
    )
    audit = AsyncMock(spec=AuditWriter)
    ctx = ProposalContext(
        audit_writer=audit,
        effects=effects,
        logger=structlog.get_logger("test"),
        outbound_dlp=_identity_dlp(),
    )

    # Bootstrap.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=PROPOSAL_HANDLERS,
    )

    _commit_proposal(
        state_git_repo,
        proposal_id="abc9990000000000",
        component_id="alfred.totally-bogus",
    )

    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=PROPOSAL_HANDLERS,
    )

    # Ledger row landed with handler-failed result + closed-vocab kind.
    async with session_scope_factory() as s:
        row = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc9990000000000")
            )
        ).scalar_one()
    assert row.result == "failed_handler"
    assert row.failure_kind == "handler_returned_failed"
    assert row.failure_detail == "component_id_not_registered"
    assert row.operator_user_id == "operator-1"

    # The processed audit row fired (handler-returned-failed lives on
    # the PROCESSED family per ADR-0021 §Failure handling).
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]
    assert "state.proposal.processed" in events

    # No replay: a second cycle does NOT re-invoke the handler.
    audit.append_schema.reset_mock()
    effects.reset_breaker.reset_mock()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=PROPOSAL_HANDLERS,
    )
    effects.reset_breaker.assert_not_called()


# ---------------------------------------------------------------------------
# Crash recovery
# ---------------------------------------------------------------------------


async def test_breaker_reset_proposal_crash_after_ledger_before_sentinel_safe(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Simulate a crash between ledger insert and sentinel bump.

    Plant a ledger row + leave the sentinel at the OLD head. The
    recovery cycle walks from the old sentinel, re-sees the blob,
    finds the ledger row, and skips the handler invocation.
    """
    effects = _make_effects()
    audit = AsyncMock(spec=AuditWriter)
    ctx = ProposalContext(
        audit_writer=audit,
        effects=effects,
        logger=structlog.get_logger("test"),
        outbound_dlp=_identity_dlp(),
    )

    # Bootstrap so the sentinel is populated.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
    )
    bootstrap_head = subprocess.run(  # noqa: S603
        ["git", "-C", str(state_git_repo), "rev-parse", "origin/main"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    commit_sha = _commit_proposal(
        state_git_repo, proposal_id="c1a510000000beef", component_id="alfred.web-fetch"
    )

    # Plant the ledger row, leave sentinel at old.
    async with session_scope_factory() as s:
        s.add(
            ProcessedProposal(
                proposal_type="breaker-reset",
                proposal_id="c1a510000000beef",
                blob_sha="0" * 40,
                commit_sha=commit_sha,
                result="applied",
                handler_version=1,
                processed_at=dt.datetime.now(dt.UTC),
            )
        )
        sentinel = (
            await s.execute(select(ProcessedProposalsHead).where(ProcessedProposalsHead.id == 1))
        ).scalar_one()
        sentinel.head_sha = bootstrap_head

    # Recovery cycle.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
    )
    # Handler NOT invoked (composite-PK check filtered it).
    effects.reset_breaker.assert_not_called()
    async with session_scope_factory() as s:
        sentinel = (
            await s.execute(select(ProcessedProposalsHead).where(ProcessedProposalsHead.id == 1))
        ).scalar_one()
    # Sentinel advanced to current head.
    assert sentinel.head_sha == commit_sha


# ---------------------------------------------------------------------------
# CR rework round-1 HIGH #14 — round-trip against a real Supervisor + real
# CircuitBreakerState row (not a mocked Protocol).
# ---------------------------------------------------------------------------


async def test_breaker_reset_proposal_round_trip_real_supervisor(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """End-to-end against a real :class:`Supervisor` instance.

    HIGH #14: the existing happy-path tests mocked
    ``ProposalEffectsProtocol``; this variant builds a real Supervisor,
    inserts a tripped ``CircuitBreakerState`` row, runs the dispatch
    cycle against the production handler chain, and asserts the
    supervisor-side ``supervisor.breaker.reset`` audit row fires +
    the ``circuit_breakers.state`` flips to ``CLOSED`` + the second
    cycle is a no-op (replay safety).
    """
    from unittest.mock import AsyncMock, MagicMock

    from alfred.audit.log import AuditWriter
    from alfred.memory.models import CircuitBreakerState
    from alfred.supervisor.core import Supervisor

    # Seed a tripped breaker row.
    async with session_scope_factory() as s:
        s.add(
            CircuitBreakerState(
                component_id="alfred.web-fetch",
                state="OPEN",
                trip_count=3,
                last_trip_at=dt.datetime.now(dt.UTC),
                last_failure_type="TimeoutError",
            )
        )

    audit = AsyncMock(spec=AuditWriter)
    supervisor = Supervisor(
        session_scope=session_scope_factory,
        gate=MagicMock(),
        audit=audit,
    )
    # Register the breaker in the supervisor's in-memory map so
    # reset_breaker finds it.
    breaker = supervisor.get_or_create_breaker("alfred.web-fetch")
    async with session_scope_factory() as s:
        await breaker.load_from_db(s)
    assert breaker.state.value == "OPEN"

    ctx = ProposalContext(
        audit_writer=audit,
        effects=supervisor,
        logger=structlog.get_logger("test"),
        outbound_dlp=_identity_dlp(),
    )

    # Bootstrap.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=PROPOSAL_HANDLERS,
    )

    _commit_proposal(
        state_git_repo, proposal_id="abcdef0123456789", component_id="alfred.web-fetch"
    )

    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=PROPOSAL_HANDLERS,
    )

    # (c) supervisor.breaker.reset emitted.
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]
    assert "supervisor.breaker.reset" in events

    # (d) circuit_breakers row flipped to CLOSED.
    async with session_scope_factory() as s:
        row = (
            await s.execute(
                select(CircuitBreakerState).where(
                    CircuitBreakerState.component_id == "alfred.web-fetch"
                )
            )
        ).scalar_one()
    assert row.state == "CLOSED"

    # (e) Replay: a second cycle is a no-op for the supervisor surface.
    audit.append_schema.reset_mock()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=PROPOSAL_HANDLERS,
    )
    events_second = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]
    assert "supervisor.breaker.reset" not in events_second
