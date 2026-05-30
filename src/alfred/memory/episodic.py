"""Slice-1 episodic memory: writer + recent-turns loader.

Writes every conversation turn to the `episodes` table. On startup, loads the
most recent N turns so Alfred has cross-restart continuity. Slice 4 replaces
this with the full summarization + semantic-fact consolidation pass.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.memory.models import Episode
from alfred.providers.base import Role


@dataclass(frozen=True, slots=True)
class EpisodicRecordInput:
    """Immutable carrier for one :meth:`EpisodicMemory.record` call.

    PR-B Task 2+ routes ``record`` through :func:`alfred.hooks.invoking`
    so every persistence call fans out across five hookpoints
    (pre/post/error/observe) before/after the DB write. The hook
    dispatcher needs a single hashable, value-equal snapshot of the
    call shape to hand subscribers — that's this class.

    The field shape is locked 1:1 to ``record``'s signature (same names,
    types, defaults, order); ``tests/unit/memory/
    test_episodic_record_input.py`` is the drift-guard. Don't add a
    kwarg to ``record`` without adding the matching field here.

    Frozen + slots is load-bearing: subscribers receive the input at the
    pre stage and must not be able to mutate the snapshot the dispatcher
    will re-hand to post / observe subscribers later in the chain.

    No methods by design — produce a modified copy via
    :func:`dataclasses.replace`, never in-place mutation.
    """

    user_id: str
    role: Role
    content: str
    trust_tier: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    persona: str = "alfred"
    persona_id: str | None = None
    language: str = "en-US"


class EpisodicMemory:
    """Append turns to the episodes table; read the most recent for context."""

    def __init__(self, *, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        *,
        user_id: str,
        role: Role,
        content: str,
        trust_tier: str,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cost_usd: float = 0.0,
        persona: str = "alfred",
        persona_id: str | None = None,
        language: str = "en-US",
    ) -> None:
        """Persist one turn. `language` is BCP-47 (CLAUDE.md i18n rule #3).

        Default ``"en-US"`` for ``language`` keeps backward-compat for paths
        not yet threaded with it; the orchestrator passes
        ``language=settings.operator_language`` explicitly per turn.

        ``persona_id`` is the new Slice-2 per-row column added in migration
        0004 (nullable). It identifies WHICH persona authored the row so the
        audit graph can attribute multi-persona traffic (Slice 5+) without a
        join. Defaults to ``None`` for pre-multi-persona callers; the
        orchestrator passes ``"alfred"`` so Slice-1+2 rows are non-null.
        The pre-existing ``persona`` column stays for backward compatibility
        with downstream analytics that already read it.

        The body is intentionally trivial: collect kwargs into an
        :class:`EpisodicRecordInput` snapshot and hand it to
        :meth:`_persist`. PR-B Task 4-5 will wrap that single dispatch
        call in :func:`alfred.hooks.invoking` so subscribers see the
        same frozen carrier at pre / post / observe stages. Keeping
        ``record`` thin means the hookpoint wiring lands as one
        localized edit instead of an interleaving rewrite.
        """
        inp = EpisodicRecordInput(
            user_id=user_id,
            role=role,
            content=content,
            trust_tier=trust_tier,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost_usd,
            persona=persona,
            persona_id=persona_id,
            language=language,
        )
        await self._persist(inp)

    async def _persist(self, inp: EpisodicRecordInput) -> None:
        """Write one ``Episode`` row from a frozen input snapshot.

        Pure extraction of the pre-Task-2 body of :meth:`record` — the
        ``Episode(...)`` constructor call, the ``session.add`` and the
        awaited ``flush`` are unchanged, only their argument source
        (``inp.<field>`` instead of local params). The four
        characterization tests in
        ``tests/unit/memory/test_episodic_hooks_wiring.py`` pin the
        golden-row shape across this refactor.

        Private because the hook-wiring in PR-B Task 4-5 wraps this
        method — not ``record`` — so the dispatcher can hand the same
        :class:`EpisodicRecordInput` snapshot to subscribers and to the
        DB write without a second carrier construction.
        """
        episode = Episode(
            user_id=inp.user_id,
            persona=inp.persona,
            persona_id=inp.persona_id,
            role=inp.role,
            content=inp.content,
            trust_tier=inp.trust_tier,
            tokens_in=inp.tokens_in,
            tokens_out=inp.tokens_out,
            cost_usd=inp.cost_usd,
            language=inp.language,
        )
        self._session.add(episode)
        await self._session.flush()

    async def recent(
        self, *, user_id: str, limit: int = 20, persona: str | None = None
    ) -> list[Episode]:
        """Most recent N turns for a user, in chronological order (oldest first).

        Lands on the composite index ``ix_episodes_user_id_created_at`` (Task 3).
        DB returns newest-first; we reverse client-side so the orchestrator can
        consume in chronological prompt-assembly order.

        ``persona`` is the PR-B per-persona scope (PRD §5.3). When ``None``,
        the historic Slice-1 behaviour is preserved — all rows for the user
        are eligible. When set, only rows whose ``persona`` column matches
        are returned, which is what :class:`~alfred.memory.working_pool.
        WorkingMemoryPool` uses to keep persona context strictly isolated
        on rehydrate.
        """
        stmt = select(Episode).where(Episode.user_id == user_id)
        if persona is not None:
            stmt = stmt.where(Episode.persona == persona)
        stmt = stmt.order_by(Episode.created_at.desc()).limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        rows.reverse()
        return rows
