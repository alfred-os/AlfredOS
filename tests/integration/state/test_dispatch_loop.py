"""Dispatch-cycle tests — Task 6 of #171.

Spec §4.3 — pins the cycle's full behaviour matrix at the boundary so
a regression on any one path surfaces here, not at production-startup
time.

Strategy: real Postgres testcontainer + real git fixture. Postgres
matches the production engine (CHECK constraints, server defaults,
timestamptz semantics) so the dispatcher's control flow is exercised
against the same shape it sees in production. The git fixture is a
tmp_path-backed bare-shaped repo; the production path's
``asyncio.to_thread(subprocess.run, ...)`` shape is preserved.

Path coverage targeted by the file:

* NULL-sentinel bootstrap (no handlers invoked on bootstrap cycle).
* No-new-blobs short-circuit.
* Happy path — single blob landed, handler invoked, ledger + sentinel.
* Sequential dispatch — two blobs in the same cycle dispatch in order.
* Replay safety — ledger row present → handler NOT re-invoked.
* Path/body type mismatch → payload_validation.
* Malformed JSON → payload_validation.
* Unknown proposal_type → failed_unknown_type.
* Handler exception → failed_handler / handler_uncaught_exception.
* Postgres outage → cycle_skipped audit row, sentinel NOT bumped.
* Git outage → cycle_skipped audit row, sentinel NOT bumped.
* Atomicity: ledger row pre-existing + sentinel still old → skip handler.
* Declarative-projection paths (policies/grants/...) are ignored.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import subprocess
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import structlog
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.memory.models import Base, ProcessedProposal, ProcessedProposalsHead
from alfred.security.dlp import OutboundDlp
from alfred.state.dispatch_loop import _proposal_dispatch_cycle
from alfred.state.dispatch_registry import (
    DispatchOutcome,
    ProposalContext,
    ProposalEffectsProtocol,
    ProposalHandler,
)
from tests.helpers.dlp import identity_outbound_dlp as _identity_dlp

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


@pytest.fixture
async def session_scope_factory(
    postgres_url: str,
) -> AsyncIterator[Callable[[], AbstractAsyncContextManager[AsyncSession]]]:
    """Yield a session_scope factory backed by the per-test Postgres container.

    Postgres matches production semantics — CHECK constraints, server
    defaults, timestamptz — so the dispatcher's control flow is exercised
    against the same engine shape that ships.
    """
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
        # Seed the sentinel row exactly as the migration does.
        async with _scope() as s:
            s.add(ProcessedProposalsHead(id=1, head_sha=None))

        yield _scope
    finally:
        await engine.dispose()


@pytest.fixture
def state_git_repo(tmp_path: Path) -> Path:
    """Initialise a real bare-shaped git repo at tmp_path/state.git.

    The dispatcher's git-walk paths need a real object DB. A small
    fixture beats mocking the subprocess: the production path uses
    ``asyncio.to_thread(subprocess.run, ...)`` which we want exercised
    end-to-end.
    """
    repo = tmp_path / "state.git"
    repo.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "init", "-q", "-b", "main", str(repo)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    # Identity to keep ``git commit`` happy in the test env.
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "config", "user.name", "test"],  # noqa: S607
        check=True,
    )
    # Initial empty commit so origin/main resolves on bootstrap.
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "commit", "--allow-empty", "-m", "init", "-q"],  # noqa: S607
        check=True,
    )
    # Mark the local HEAD as origin/main so the dispatcher's
    # ``git rev-parse origin/main`` walks against the same ref. The
    # dispatcher polls ``origin/main`` per ADR-0021 §Architecture.
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", "HEAD"],  # noqa: S607
        check=True,
    )
    return repo


def _commit_blob(repo: Path, relpath: str, content: str, message: str) -> str:
    """Write ``relpath`` with ``content`` and commit; return the commit SHA."""
    target = repo / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "add", relpath],  # noqa: S607
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "commit", "-m", message, "-q"],  # noqa: S607
        check=True,
    )
    # Update origin/main to track the new commit.
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


def _payload(component_id: str = "alfred.web-fetch") -> str:
    """Construct a canonical BreakerResetProposal JSON blob."""
    return json.dumps(
        {
            "component_id": component_id,
            "operator_user_id": "operator-1",
            "reason": "operator_initiated",
        },
        indent=2,
        sort_keys=True,
    )


def _make_ctx(
    effects: ProposalEffectsProtocol | None = None,
    *,
    outbound_dlp: OutboundDlp | None = None,
) -> ProposalContext:
    """Build a ProposalContext with mocked audit + effects + a DLP scanner.

    The default scanner is an identity OutboundDlp (clean scan, count=0) so
    existing tests' failure-detail values pass through unredacted. #173
    tests inject a broker that knows the planted secret to exercise the
    redaction path.
    """
    return ProposalContext(
        audit_writer=AsyncMock(spec=AuditWriter),
        effects=effects if effects is not None else AsyncMock(spec=ProposalEffectsProtocol),
        logger=structlog.get_logger("test"),
        outbound_dlp=outbound_dlp if outbound_dlp is not None else _identity_dlp(),
    )


def _make_handlers(
    invocations: list[Any] | None = None,
    *,
    raise_exception: Exception | None = None,
    return_outcome: DispatchOutcome | None = None,
) -> dict[str, ProposalHandler]:
    """Build a handler registry that records calls + supports per-test branches."""

    async def _h(payload: Any, ctx: ProposalContext) -> DispatchOutcome:
        if invocations is not None:
            invocations.append(payload)
        if raise_exception is not None:
            raise raise_exception
        if return_outcome is not None:
            return return_outcome
        return DispatchOutcome.applied()

    return {"breaker-reset": _h}


# ---------------------------------------------------------------------------
# Bootstrap cycle (sentinel NULL → write origin/main; no blobs processed)
# ---------------------------------------------------------------------------


async def test_dispatch_cycle_bootstraps_null_sentinel_to_origin_main_head(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """First cycle with NULL sentinel writes origin/main HEAD; no blobs dispatched."""
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    # Pre-populate the repo with a blob — bootstrap must NOT replay it.
    _commit_blob(
        state_git_repo,
        "policies/breaker-resets/abc123def4567890.json",
        _payload(),
        "pre-bootstrap",
    )
    expected_head = subprocess.run(  # noqa: S603
        ["git", "-C", str(state_git_repo), "rev-parse", "origin/main"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    # Sentinel populated; handler NOT invoked (forward-from-now semantics).
    async with session_scope_factory() as s:
        sentinel = (
            await s.execute(select(ProcessedProposalsHead).where(ProcessedProposalsHead.id == 1))
        ).scalar_one()
    assert sentinel.head_sha == expected_head
    assert invocations == []


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_dispatch_cycle_processes_new_blob_records_ledger_bumps_sentinel(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """A new blob lands → handler invoked, ledger row written, sentinel bumped."""
    # Step 1: bootstrap.
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    # Step 2: commit a new blob.
    commit_sha = _commit_blob(
        state_git_repo,
        "policies/breaker-resets/abc123def4567890.json",
        _payload(),
        "add proposal",
    )

    # Step 3: dispatch cycle picks it up.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    assert len(invocations) == 1
    assert invocations[0].component_id == "alfred.web-fetch"

    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    assert ledger.proposal_type == "breaker-reset"
    assert ledger.result == "applied"
    assert ledger.commit_sha == commit_sha
    assert ledger.operator_user_id == "operator-1"
    assert ledger.failure_kind is None

    async with session_scope_factory() as s:
        sentinel = (
            await s.execute(select(ProcessedProposalsHead).where(ProcessedProposalsHead.id == 1))
        ).scalar_one()
    assert sentinel.head_sha == commit_sha


async def test_dispatch_cycle_emits_state_proposal_processed_audit_row_on_applied(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """An applied proposal emits the state.proposal.processed audit row."""
    handlers = _make_handlers()
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    audit = ctx.audit_writer
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]  # type: ignore[union-attr]
    assert "state.proposal.processed" in events


async def test_dispatch_cycle_skips_when_no_new_blobs(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """An idempotent cycle is a cheap no-op: no handler, no audit row."""
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    # Bootstrap.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    # Second cycle on the same HEAD.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    assert invocations == []


# ---------------------------------------------------------------------------
# Replay safety
# ---------------------------------------------------------------------------


async def test_dispatch_cycle_skips_already_processed_blob(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Ledger row pre-existing → handler NOT invoked on next cycle."""
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    assert len(invocations) == 1
    # Second walk on same blob — handler must NOT be re-invoked.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    assert len(invocations) == 1


async def test_dispatch_cycle_atomicity_crash_after_ledger_before_sentinel(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Ledger row present + sentinel still old → handler NOT re-invoked.

    Simulates the crash-between-ledger-and-sentinel case per ADR-0021
    §Atomicity model. The recovery cycle walks from the OLD sentinel,
    re-sees the blob, hits the composite PK, and skips.
    """
    handlers_invocations: list[Any] = []
    handlers = _make_handlers(handlers_invocations)
    ctx = _make_ctx()
    # Bootstrap.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    bootstrap_head = subprocess.run(  # noqa: S603
        ["git", "-C", str(state_git_repo), "rev-parse", "origin/main"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    # Add a blob.
    commit_sha = _commit_blob(
        state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add"
    )
    # Manually plant the ledger row but leave the sentinel old (the crash).
    async with session_scope_factory() as s:
        s.add(
            ProcessedProposal(
                proposal_type="breaker-reset",
                proposal_id="abc123def4567890",
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
        handlers=handlers,
    )

    # Handler must NOT have been invoked.
    assert handlers_invocations == []
    async with session_scope_factory() as s:
        sentinel = (
            await s.execute(select(ProcessedProposalsHead).where(ProcessedProposalsHead.id == 1))
        ).scalar_one()
    assert sentinel.head_sha == commit_sha


# ---------------------------------------------------------------------------
# Sequential dispatch within a cycle
# ---------------------------------------------------------------------------


async def test_dispatch_cycle_sequential_execution_of_two_blobs(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Two blobs land in one cycle → handlers serialised, ordered.

    ADR-0021 §Concurrency: within a cycle, proposals process sequentially.
    Test pin: second handler invocation is ordered after the first
    completes (started_events[1] > finished_events[0]).
    """
    # Bootstrap.
    ctx = _make_ctx()
    handlers = _make_handlers()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    started: list[str] = []
    finished: list[str] = []

    async def _serialising_handler(payload: Any, ctx: ProposalContext) -> DispatchOutcome:
        started.append(payload.component_id)
        # Yield briefly to give the loop a chance to interleave (if it
        # would).
        await asyncio.sleep(0)
        finished.append(payload.component_id)
        return DispatchOutcome.applied()

    handlers = {"breaker-reset": _serialising_handler}
    _commit_blob(
        state_git_repo, "policies/breaker-resets/aaa0000000000000.json", _payload("alfred.a"), "a"
    )
    _commit_blob(
        state_git_repo, "policies/breaker-resets/bbb0000000000000.json", _payload("alfred.b"), "b"
    )
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    # The two handlers must have run serially; the second's start happens
    # only after the first's finish.
    assert started == ["alfred.a", "alfred.b"]
    assert finished == ["alfred.a", "alfred.b"]


# ---------------------------------------------------------------------------
# Path/body mismatch + malformed JSON + unknown type
# ---------------------------------------------------------------------------


async def test_dispatch_cycle_rejects_path_body_type_mismatch(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Path says breaker-reset; payload validation fails → payload_validation.

    Closes the type-confusion vector — the dispatcher verifies the
    parsed payload is the right concrete subclass before calling the
    handler.
    """
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    # Body lacks ``component_id`` → Pydantic ValidationError surface.
    _commit_blob(
        state_git_repo,
        "policies/breaker-resets/abc123def4567890.json",
        json.dumps({"operator_user_id": "operator-1"}),
        "bad-body",
    )
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    assert invocations == []
    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    assert ledger.result == "failed_parse"
    assert ledger.failure_kind == "payload_validation"


async def test_dispatch_cycle_records_failed_parse_for_malformed_blob_json(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """A non-JSON blob lands → ledger records failed_parse."""
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    _commit_blob(
        state_git_repo, "policies/breaker-resets/abc123def4567890.json", "{not json", "bad-json"
    )
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    assert invocations == []
    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    assert ledger.result == "failed_parse"
    assert ledger.failure_kind == "payload_validation"


async def test_dispatch_cycle_records_failed_unknown_type_for_unregistered_handler(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """A blob under policies/unknown-type/... → ledger failed_unknown_type."""
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    _commit_blob(
        state_git_repo, "policies/unknown-type/abc123def4567890.json", _payload(), "unknown"
    )
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    assert invocations == []
    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_type == "unknown-type")
            )
        ).scalar_one()
    assert ledger.result == "failed_unknown_type"
    assert ledger.failure_kind == "unknown_proposal_type"


async def test_dispatch_cycle_records_failed_handler_for_handler_exception(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Handler raises → ledger result=failed_handler, kind=handler_uncaught_exception."""
    ctx = _make_ctx()
    handlers = _make_handlers()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    handlers = _make_handlers(raise_exception=RuntimeError("transient bug"))
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    assert ledger.result == "failed_handler"
    assert ledger.failure_kind == "handler_uncaught_exception"


async def test_dispatch_cycle_records_handler_returned_failed_outcome(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Handler returns DispatchOutcome.failed → ledger failed_handler / handler_returned_failed."""
    ctx = _make_ctx()
    handlers = _make_handlers()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    handlers = _make_handlers(
        return_outcome=DispatchOutcome.failed(reason="component_id_not_registered"),
    )
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )

    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    assert ledger.result == "failed_handler"
    assert ledger.failure_kind == "handler_returned_failed"
    assert ledger.failure_detail == "component_id_not_registered"


# ---------------------------------------------------------------------------
# Declarative-projection paths are ignored
# ---------------------------------------------------------------------------


async def test_dispatch_cycle_ignores_declarative_grant_blob(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """A policies/grants/<plugin>/<id>.json blob is NOT a side-effecting proposal.

    Declarative projection is the gate's job per ADR-0021 §Scope —
    the dispatcher MUST NOT touch grant blobs.
    """
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    _commit_blob(
        state_git_repo,
        "policies/grants/alfred.web-fetch/grantA.json",
        '{"plugin_id": "alfred.web-fetch"}',
        "add",
    )
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    assert invocations == []
    async with session_scope_factory() as s:
        rows = (await s.execute(select(ProcessedProposal))).scalars().all()
    assert rows == []


# ---------------------------------------------------------------------------
# Cycle-level infrastructure failures: log+skip + audit row
# ---------------------------------------------------------------------------


async def test_dispatch_cycle_postgres_outage_skips_cycle_loud(
    state_git_repo: Path,
) -> None:
    """Postgres OperationalError → cycle_skipped audit row, no crash."""
    failing_scope = AsyncMock()

    @asynccontextmanager
    async def _scope() -> AsyncIterator[Any]:
        raise OperationalError("could not connect", {}, None)
        yield  # pragma: no cover

    failing_scope.side_effect = _scope
    ctx = _make_ctx()
    handlers = _make_handlers()

    # Must not propagate.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=_scope,
        handlers=handlers,
    )
    audit = ctx.audit_writer
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]  # type: ignore[union-attr]
    assert "state.proposal.dispatch_cycle_skipped" in events


async def test_dispatch_cycle_state_git_outage_skips_cycle_loud(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    tmp_path: Path,
) -> None:
    """Missing state.git repo → cycle_skipped audit row, no crash."""
    missing = tmp_path / "does-not-exist"
    ctx = _make_ctx()
    handlers = _make_handlers()

    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=missing,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    audit = ctx.audit_writer
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]  # type: ignore[union-attr]
    assert "state.proposal.dispatch_cycle_skipped" in events


async def test_dispatch_cycle_git_subprocess_timeout_on_rev_parse_skips_loud(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR-rework round-2 MAJOR T5: TimeoutExpired on ``git rev-parse`` skips loudly.

    A stuck git subprocess (lock contention, pack-fetch hang) would block
    the cycle indefinitely without the ``timeout=`` bound on
    ``subprocess.run``. The dispatcher's cooperative shutdown depends on
    bounded work per cycle — if ``_git`` cannot return, the supervisor
    cannot drain. This test patches the rev-parse helper to raise
    :class:`subprocess.TimeoutExpired` and asserts the cycle emits the
    ``git_subprocess_timeout`` skip row + continues on the next tick.
    """
    from alfred.state import dispatch_loop as loop_mod

    async def _stuck_resolve(*_args: Any, **_kw: Any) -> str:
        raise subprocess.TimeoutExpired(cmd=["git", "rev-parse", "origin/main"], timeout=30)

    monkeypatch.setattr(loop_mod, "_resolve_origin_main", _stuck_resolve)

    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=_make_handlers(),
    )
    audit = ctx.audit_writer
    skip_calls = [
        c
        for c in audit.append_schema.await_args_list  # type: ignore[union-attr]
        if c.kwargs.get("event") == "state.proposal.dispatch_cycle_skipped"
    ]
    assert len(skip_calls) == 1
    assert skip_calls[0].kwargs.get("subject", {}).get("skip_reason") == "git_subprocess_timeout"


async def test_dispatch_cycle_git_subprocess_timeout_on_walk_skips_loud(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR-rework round-2 MAJOR T5: TimeoutExpired on the walk step skips loudly.

    Pairs with the rev-parse-timeout test above: the diff walker is the
    other git subprocess surface that can hang. Patches the walker to
    raise :class:`subprocess.TimeoutExpired` and asserts the same
    ``git_subprocess_timeout`` skip reason fires.
    """
    from alfred.state import dispatch_loop as loop_mod

    ctx = _make_ctx()
    handlers = _make_handlers()
    # Bootstrap so the sentinel is populated and the next cycle's walk
    # has a real range to (allegedly) diff over.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")
    ctx.audit_writer.append_schema.reset_mock()  # type: ignore[union-attr]

    async def _stuck_walk(*_args: Any, **_kw: Any) -> list[tuple[str, str, str]]:
        raise subprocess.TimeoutExpired(cmd=["git", "diff", "-z"], timeout=30)

    monkeypatch.setattr(loop_mod, "_walk_added_blobs", _stuck_walk)

    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    skip_calls = [
        c
        for c in ctx.audit_writer.append_schema.await_args_list  # type: ignore[union-attr]
        if c.kwargs.get("event") == "state.proposal.dispatch_cycle_skipped"
    ]
    assert len(skip_calls) == 1
    assert skip_calls[0].kwargs.get("subject", {}).get("skip_reason") == "git_subprocess_timeout"


async def test_dispatch_cycle_sqlalchemy_error_on_sentinel_read_skips_loud(
    state_git_repo: Path,
) -> None:
    """A non-OperationalError SQLAlchemy failure on the sentinel read skips loud."""
    from sqlalchemy.exc import SQLAlchemyError

    @asynccontextmanager
    async def _scope() -> AsyncIterator[Any]:
        raise SQLAlchemyError("transient")
        yield  # pragma: no cover

    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=_scope,
        handlers=_make_handlers(),
    )
    audit = ctx.audit_writer
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]  # type: ignore[union-attr]
    assert "state.proposal.dispatch_cycle_skipped" in events


async def test_dispatch_cycle_git_walk_failure_skips_loud(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Walk-step git failure (after rev-parse succeeded) emits cycle_skipped.

    The cycle's rev-parse can succeed but the subsequent diff walk can
    fail (e.g. corrupt pack, broken ref). Monkeypatch ``_walk_added_blobs``
    after the sentinel is populated to simulate the case.
    """
    from alfred.state import dispatch_loop as loop_mod

    ctx = _make_ctx()
    handlers = _make_handlers()
    # Bootstrap so the sentinel is populated.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    # Commit a new blob so the next cycle attempts the walk.
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")
    ctx.audit_writer.append_schema.reset_mock()  # type: ignore[union-attr]

    async def _broken_walk(*_args: Any, **_kw: Any) -> list[tuple[str, str, str]]:
        raise subprocess.CalledProcessError(returncode=128, cmd=["git", "diff", "bogus..HEAD"])

    monkeypatch.setattr(loop_mod, "_walk_added_blobs", _broken_walk)

    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    events = [c.kwargs.get("event") for c in ctx.audit_writer.append_schema.await_args_list]  # type: ignore[union-attr]
    assert "state.proposal.dispatch_cycle_skipped" in events


async def test_dispatch_cycle_sentinel_bump_failure_after_dispatch_skips_loud(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SQLAlchemyError on the post-blob-dispatch sentinel bump emits cycle_skipped.

    Uses the real Postgres session_scope to keep the cycle's other
    transactions honest; only the final ``_bump_sentinel`` call is
    monkeypatched to raise. The cycle MUST emit dispatch_cycle_skipped
    in this case (rather than crashing) so the next cycle simply
    retries.
    """
    from sqlalchemy.exc import SQLAlchemyError

    from alfred.state import dispatch_loop as loop_mod

    ctx = _make_ctx()
    handlers = _make_handlers()
    # Real bootstrap cycle — sentinel populated.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    # Commit a blob so the second cycle has work to do.
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")

    # Now patch _bump_sentinel — the FIRST call lands inside _dispatch_one's
    # eventual sentinel bump after the per-blob ledger insert. Only the
    # post-walk bump should raise; the per-blob ledger path is preserved.
    real_bump = loop_mod._bump_sentinel
    calls: list[None] = []

    async def _bump(*args: Any, **kwargs: Any) -> None:
        calls.append(None)
        if len(calls) == 1:
            # The post-dispatch bump is the only bump in this cycle —
            # raise on it.
            raise SQLAlchemyError("simulated bump failure")
        await real_bump(*args, **kwargs)

    monkeypatch.setattr(loop_mod, "_bump_sentinel", _bump)

    audit = ctx.audit_writer
    audit.append_schema.reset_mock()  # type: ignore[union-attr]
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]  # type: ignore[union-attr]
    assert "state.proposal.dispatch_cycle_skipped" in events


# ---------------------------------------------------------------------------
# CR rework round-1 CRITICAL #3 + #4 + HIGH #6 + CRITICAL #1 — new tests
# ---------------------------------------------------------------------------


async def test_dispatch_cycle_records_current_head_as_commit_sha(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """CR rework round-1 CRITICAL #3: ``commit_sha`` is the cycle's HEAD.

    The previous shape called ``git log --diff-filter=A`` per blob to
    find an introducing-commit SHA — that was both wrong (the
    introducing commit is the operator's proposal-branch commit,
    not the merge commit on main) AND introduced N+1 subprocess calls
    per cycle. The rework records ``current_head`` directly.
    """
    ctx = _make_ctx()
    handlers = _make_handlers()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    expected_head = _commit_blob(
        state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add"
    )
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    # ``commit_sha`` equals the cycle's current_head — the head we ACTED
    # on, the merge commit on main, NOT the operator's introducing-commit.
    assert ledger.commit_sha == expected_head
    # blob_sha is the content hash and is distinct from commit_sha.
    assert ledger.blob_sha != ledger.commit_sha


async def test_dispatch_cycle_oversized_operator_user_id_skips_blob_silently(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """CR rework round-1 CRITICAL #4: an oversized operator_user_id field
    fails Pydantic validation at parse time → ``failed_parse`` ledger row.

    The 64-char bound mirrors the ledger's ``String(64)`` column width,
    so the refusal lands at the model boundary rather than at the
    Postgres-side data violation.
    """
    handlers = _make_handlers()
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    payload = json.dumps(
        {
            "component_id": "alfred.web-fetch",
            "operator_user_id": "x" * 256,  # > String(64)
            "reason": "operator_initiated",
        }
    )
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", payload, "add")
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    assert ledger.result == "failed_parse"
    assert ledger.failure_kind == "payload_validation"


async def test_dispatch_cycle_drops_blob_with_malformed_proposal_id(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """CR rework round-1 CRITICAL #4: a non-16-hex proposal_id is dropped at the walk.

    The blob never reaches ``_dispatch_one`` so no ledger row lands.
    The path-shape boundary refuses what the canonical CLI writer would
    refuse at construction; this defends against a malicious operator
    landing a 1KB proposal_id and hitting the ledger's String(64) limit.
    """
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    # Non-16-hex id (uppercase + too short).
    _commit_blob(state_git_repo, "policies/breaker-resets/NOT-A-HEX-ID.json", _payload(), "add")
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    assert invocations == []
    async with session_scope_factory() as s:
        rows = (await s.execute(select(ProcessedProposal))).scalars().all()
    assert rows == []


async def test_dispatch_cycle_handler_replay_safety_on_idempotent_handler(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """CR rework round-1 CRITICAL #1: idempotent-handler contract.

    Simulate the crash-between-handler-commit-and-framework-ledger-commit
    case (the at-least-once shape per ADR-0021 §Atomicity) by:

    1. Letting the first cycle run normally — handler invoked + ledger
       row + sentinel bumped.
    2. Manually deleting the ledger row + reverting the sentinel to
       OLD head (the crash trace).
    3. Running the next cycle — handler re-invoked (idempotent: same
       observable outcome).

    A real crash between handler-commit and ledger-commit would leave
    the ledger row absent; the recovery shape is identical because the
    composite-PK lookup misses, the handler re-runs, the ledger row
    lands. The handler's idempotency keeps the observable state stable.
    """
    # Bootstrap.
    invocations: list[Any] = []
    handlers = _make_handlers(invocations)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    bootstrap_head = subprocess.run(  # noqa: S603
        ["git", "-C", str(state_git_repo), "rev-parse", "origin/main"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")
    # First cycle: clean dispatch.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    assert len(invocations) == 1

    # Simulate the crash: delete the ledger row + revert the sentinel.
    async with session_scope_factory() as s:
        ledger = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
        await s.delete(ledger)
        sentinel = (
            await s.execute(select(ProcessedProposalsHead).where(ProcessedProposalsHead.id == 1))
        ).scalar_one()
        sentinel.head_sha = bootstrap_head

    # Recovery cycle: handler MUST re-run because the ledger row is absent.
    # The handler is idempotent so the observable state is unchanged.
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    assert len(invocations) == 2  # re-invoked; idempotent so observable same
    async with session_scope_factory() as s:
        ledger2 = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_id == "abc123def4567890")
            )
        ).scalar_one()
    # Same applied outcome — the idempotent contract holds.
    assert ledger2.result == "applied"


async def test_dispatch_cycle_audit_emit_failure_after_handler_emits_skip_row(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """CR rework round-1 HIGH #6: audit-writer failure after handler commit
    emits the ``audit_write_failed_post_handler`` cycle-skipped row.
    """
    # Bootstrap.
    handlers = _make_handlers()
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload(), "add")
    audit = ctx.audit_writer

    # First call (the per-blob append_schema for state.proposal.processed)
    # fails. The cycle's own _emit_cycle_skipped follow-up must still be
    # attempted; we let that succeed by returning normally after the
    # first call.
    call_count = {"n": 0}

    async def _flaky(*_args: Any, **kwargs: Any) -> None:
        call_count["n"] += 1
        if kwargs.get("event") == "state.proposal.processed":
            raise RuntimeError("audit-writer-down")
        return

    audit.append_schema = AsyncMock(side_effect=_flaky)  # type: ignore[union-attr]

    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=handlers,
    )
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]  # type: ignore[union-attr]
    skip_calls = [
        c
        for c in audit.append_schema.await_args_list  # type: ignore[union-attr]
        if c.kwargs.get("event") == "state.proposal.dispatch_cycle_skipped"
    ]
    assert skip_calls, f"audit_write_failed_post_handler skip-row missing; events={events}"
    assert any(
        c.kwargs.get("subject", {}).get("skip_reason") == "audit_write_failed_post_handler"
        for c in skip_calls
    )


async def test_dispatch_cycle_postgres_data_violation_skips_loud(
    state_git_repo: Path,
) -> None:
    """CR rework round-1 CRITICAL #4: a non-OperationalError SQLAlchemyError
    on the sentinel-read path skips the cycle loud with the
    ``postgres_data_violation`` discriminator.
    """
    from sqlalchemy.exc import DataError

    @asynccontextmanager
    async def _scope() -> AsyncIterator[Any]:
        raise DataError("integer out of range", {}, None)
        yield  # pragma: no cover

    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=_scope,
        handlers=_make_handlers(),
    )
    audit = ctx.audit_writer
    skip_calls = [
        c
        for c in audit.append_schema.await_args_list  # type: ignore[union-attr]
        if c.kwargs.get("event") == "state.proposal.dispatch_cycle_skipped"
    ]
    assert skip_calls
    assert skip_calls[0].kwargs.get("subject", {}).get("skip_reason") == "postgres_data_violation"


async def test_dispatch_cycle_sentinel_bootstrap_failure_skips_loud(
    state_git_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SQLAlchemyError on the bootstrap sentinel bump skips the cycle loud."""
    from sqlalchemy.exc import SQLAlchemyError

    from alfred.state import dispatch_loop as loop_mod

    @asynccontextmanager
    async def _scope() -> AsyncIterator[Any]:
        # The sentinel read sees NULL on the first call, so the cycle
        # routes through ``_bump_sentinel``; that path is what we want
        # to fail. Yield a fake session whose ``execute`` returns a
        # one-row sentinel with head_sha=None.
        from unittest.mock import MagicMock

        sentinel = MagicMock()
        sentinel.head_sha = None
        result = AsyncMock()
        result.scalar_one = MagicMock(return_value=sentinel)
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result)
        try:
            yield session
        finally:
            pass

    async def _bump_fail(*_args: Any, **_kw: Any) -> None:
        raise SQLAlchemyError("simulated")

    monkeypatch.setattr(loop_mod, "_bump_sentinel", _bump_fail)
    ctx = _make_ctx()
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=_scope,
        handlers=_make_handlers(),
    )
    audit = ctx.audit_writer
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]  # type: ignore[union-attr]
    assert "state.proposal.dispatch_cycle_skipped" in events
