"""Adversarial replay-safety + type-confusion suite — Task 10 of #171.

These tests are release-blocking per CLAUDE.md Security rules: the
dispatcher is a privileged surface that turns reviewer-approved git
blobs into runtime state mutations. Every adversarial property below
defends a specific bypass vector:

* **Replay** — a supervisor restart MUST NOT re-execute proposals the
  ledger says were already applied. The composite-PK check is the
  primary defence; this test pins it end-to-end.
* **Unknown type** — a blob at ``policies/unknown-type/<id>.json``
  MUST land in the ledger with ``failed_unknown_type`` rather than
  being silently dropped (no silent skip per CLAUDE.md hard rule #7).
* **Operator-supplied unknown component_id** — the supervisor.breaker.reset
  audit row MUST NOT fire when the handler returns failed
  (the reset NEVER crossed the supervisor boundary; emitting the
  terminal row would lie about the system state).
* **Declarative-projection paths ignored** — a ``policies/grants/...``
  blob MUST NOT reach the dispatcher's handler path. Declarative
  projection is the gate's responsibility per ADR-0021 §Scope; a
  dispatcher that ran a grant blob would double-emit the audit row
  + race the gate's rebuild_from_state_git.
"""

from __future__ import annotations

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
        async with _scope() as s:
            s.add(ProcessedProposalsHead(id=1, head_sha=None))
        yield _scope
    finally:
        await engine.dispose()


@pytest.fixture
def state_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "state.git"
    repo.mkdir()
    for argv in (
        ["git", "init", "-q", "-b", "main", str(repo)],
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        ["git", "-C", str(repo), "config", "user.name", "test"],
        ["git", "-C", str(repo), "commit", "--allow-empty", "-m", "init", "-q"],
        ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", "HEAD"],
    ):
        subprocess.run(argv, check=True, capture_output=True)  # noqa: S603
    return repo


def _commit_blob(repo: Path, relpath: str, content: str) -> None:
    target = repo / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    for argv in (
        ["git", "-C", str(repo), "add", relpath],
        ["git", "-C", str(repo), "commit", "-m", "add", "-q"],
        ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", "HEAD"],
    ):
        subprocess.run(argv, check=True, capture_output=True)  # noqa: S603


def _payload(component_id: str = "alfred.web-fetch") -> str:
    return json.dumps(
        {
            "component_id": component_id,
            "operator_user_id": "operator-1",
            "reason": "operator_initiated",
        },
        indent=2,
        sort_keys=True,
    )


# ---------------------------------------------------------------------------
# Replay safety across supervisor restart
# ---------------------------------------------------------------------------


async def test_dispatch_does_not_replay_processed_proposal_on_supervisor_restart(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """A supervisor restart MUST NOT re-execute an already-applied proposal.

    Two distinct dispatcher contexts (different ProposalContext instances
    sharing the same Postgres session_scope + the same state.git repo)
    simulate the restart: the first ctx runs the cycle and applies the
    proposal; the second ctx (the "fresh supervisor") walks from the
    sentinel and must not re-invoke the handler.
    """
    effects_1 = AsyncMock(spec=ProposalEffectsProtocol)
    audit_1 = AsyncMock(spec=AuditWriter)
    ctx_1 = ProposalContext(
        audit_writer=audit_1,
        effects=effects_1,
        logger=structlog.get_logger("ctx1"),
        outbound_dlp=_identity_dlp(),
    )

    # First-supervisor lifetime.
    await _proposal_dispatch_cycle(
        ctx=ctx_1, repo_path=state_git_repo, session_scope=session_scope_factory
    )
    _commit_blob(state_git_repo, "policies/breaker-resets/abc123def4567890.json", _payload())
    await _proposal_dispatch_cycle(
        ctx=ctx_1, repo_path=state_git_repo, session_scope=session_scope_factory
    )
    effects_1.reset_breaker.assert_awaited_once()

    # Second-supervisor lifetime starts — fresh ctx, fresh effects mock,
    # same Postgres + same repo. The sentinel survives the "restart".
    effects_2 = AsyncMock(spec=ProposalEffectsProtocol)
    audit_2 = AsyncMock(spec=AuditWriter)
    ctx_2 = ProposalContext(
        audit_writer=audit_2,
        effects=effects_2,
        logger=structlog.get_logger("ctx2"),
        outbound_dlp=_identity_dlp(),
    )
    await _proposal_dispatch_cycle(
        ctx=ctx_2, repo_path=state_git_repo, session_scope=session_scope_factory
    )
    effects_2.reset_breaker.assert_not_called()


# ---------------------------------------------------------------------------
# Unknown proposal_type is loud
# ---------------------------------------------------------------------------


async def test_dispatch_records_unknown_proposal_type_loud(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """A blob under an unregistered proposal_type lands as failed_unknown_type.

    Defends against the silent-drop bypass: an attacker (or a future
    operator typo) landing a blob at ``policies/<unknown-type>/<id>.json``
    MUST NOT bypass the audit trail. The ledger row + the audit row
    are the forensic signal — without them the dispatcher would
    silently ignore the blob and the breach would be invisible.
    """
    effects = AsyncMock(spec=ProposalEffectsProtocol)
    audit = AsyncMock(spec=AuditWriter)
    ctx = ProposalContext(
        audit_writer=audit,
        effects=effects,
        logger=structlog.get_logger("test"),
        outbound_dlp=_identity_dlp(),
    )

    await _proposal_dispatch_cycle(
        ctx=ctx, repo_path=state_git_repo, session_scope=session_scope_factory
    )
    _commit_blob(
        state_git_repo,
        "policies/unknown-type/abcdef0123456789.json",
        json.dumps({"surprise": "payload"}),
    )
    await _proposal_dispatch_cycle(
        ctx=ctx, repo_path=state_git_repo, session_scope=session_scope_factory
    )

    async with session_scope_factory() as s:
        row = (
            await s.execute(
                select(ProcessedProposal).where(ProcessedProposal.proposal_type == "unknown-type")
            )
        ).scalar_one()
    assert row.result == "failed_unknown_type"
    assert row.failure_kind == "unknown_proposal_type"
    # The dispatch_failed audit row fired.
    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]
    assert "state.proposal.dispatch_failed" in events


# ---------------------------------------------------------------------------
# Unknown component_id does NOT emit the terminal supervisor row
# ---------------------------------------------------------------------------


async def test_dispatch_rejects_proposal_referencing_unknown_component_id(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """Operator-supplied unknown component_id → handler-returned-failed
    + NO supervisor.breaker.reset audit emit.

    The terminal ``supervisor.breaker.reset`` audit row lives on the
    supervisor side and fires only on a real state mutation. The reset
    never crossed that boundary, so the row MUST NOT appear in the
    audit log — emitting it would lie about the breaker's actual state
    (the breaker is unchanged on the failure path).

    The dispatcher's ``state.proposal.processed`` row carries the
    failure metadata for forensic continuity; the supervisor row stays
    silent.
    """
    effects = AsyncMock(spec=ProposalEffectsProtocol)
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

    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=PROPOSAL_HANDLERS,
    )
    _commit_blob(
        state_git_repo,
        "policies/breaker-resets/baad000000000000.json",
        _payload(component_id="alfred.totally-bogus"),
    )
    await _proposal_dispatch_cycle(
        ctx=ctx,
        repo_path=state_git_repo,
        session_scope=session_scope_factory,
        handlers=PROPOSAL_HANDLERS,
    )

    events = [c.kwargs.get("event") for c in audit.append_schema.await_args_list]
    # The processed row IS emitted (operator-caused failure path).
    assert "state.proposal.processed" in events
    # The terminal supervisor row is NOT emitted (no state mutation).
    assert "supervisor.breaker.reset" not in events


# ---------------------------------------------------------------------------
# Declarative-projection paths are ignored
# ---------------------------------------------------------------------------


async def test_dispatch_does_not_invoke_handler_for_declarative_proposal_types(
    session_scope_factory: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    state_git_repo: Path,
) -> None:
    """policies/grants/<plugin>/<id>.json MUST NOT reach a handler.

    Declarative projection is the gate's responsibility per
    ADR-0021 §Scope; the dispatcher operates on the side-effecting
    layer only. A dispatcher that ran a grant blob would race the
    gate's ``rebuild_from_state_git`` and double-emit the grant
    audit trail.
    """
    effects = AsyncMock(spec=ProposalEffectsProtocol)
    audit = AsyncMock(spec=AuditWriter)
    ctx = ProposalContext(
        audit_writer=audit,
        effects=effects,
        logger=structlog.get_logger("test"),
        outbound_dlp=_identity_dlp(),
    )

    await _proposal_dispatch_cycle(
        ctx=ctx, repo_path=state_git_repo, session_scope=session_scope_factory
    )
    _commit_blob(
        state_git_repo,
        "policies/grants/alfred.web-fetch/grantA.json",
        json.dumps({"plugin_id": "alfred.web-fetch"}),
    )
    await _proposal_dispatch_cycle(
        ctx=ctx, repo_path=state_git_repo, session_scope=session_scope_factory
    )

    effects.reset_breaker.assert_not_called()
    async with session_scope_factory() as s:
        rows = (await s.execute(select(ProcessedProposal))).scalars().all()
    assert rows == []
