"""Slice-1 episodic memory: writer + recent-turns loader.

Writes every conversation turn to the `episodes` table. On startup, loads the
most recent N turns so Alfred has cross-restart continuity. Slice 4 replaces
this with the full summarization + semantic-fact consolidation pass.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.hooks import invoking
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

        Task 4 (Slice-2.5 PR-B) wraps the persistence path in
        :func:`alfred.hooks.invoking` so every action callsite shares one
        lifecycle: ``pre → body → post / error / cancel``. The two ``pre``
        hookpoints fire BEFORE the DB write:

        * ``before_validate`` — open hookpoint; any tier may subscribe.
          Default ``fail_closed=False`` so a crashing subscriber falls
          through to the next stage with the last-good ctx (the registry
          still emits :data:`HOOKS_SUBSCRIBER_ERROR` for attribution).
          The canonical use is i18n/persona rewriting BEFORE the
          structural guard runs.
        * ``before_db_write`` — security stage. Locked to
          ``subscribable_tiers={"system","operator"}`` so a user-plugin
          cannot wedge into the redactor seam, ``refusable_tiers={"system"}``
          so only DLP-style system-tier subscribers may refuse the write
          (§6.5), and ``fail_closed=True`` so a timed-out / erroring
          redactor MUST NOT write (CLAUDE.md hard rule #7 — no silent
          failures in security paths). The canonical use is DLP
          redaction / refusal.

        The three terminal hookpoints — ``after_flush`` (post),
        ``write_failed`` (error), ``cancelled`` (cancel) — are bound by
        name on the :meth:`Flow.body` call; PR-B Task 5 adds spy
        subscribers for each. The names are load-bearing: spec §7 fixes
        ``after_flush`` (NOT ``committed``), ``write_failed``, and
        ``cancelled`` as the canonical chain identifiers for episodic
        writes.
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
        async with invoking("memory.episodic.record", inp) as flow:
            # ``before_validate`` — open hookpoint, all tiers eligible,
            # default ``fail_closed=False``. A crashing subscriber is
            # audited and treated as pass-through so the action body
            # still runs; ``_validate`` is the next guard. Reassigning
            # ``flow`` to ``await flow.pre(...)`` is the PR-A Task-13
            # contract: the helper returns the SAME flow object with
            # ``_ctx`` rebound to the chain's output, so reading
            # ``flow.input`` immediately after reflects any subscriber's
            # ``with_input`` mutation.
            flow = await flow.pre("before_validate")
            self._validate(flow.input)
            # ``before_db_write`` — security stage. The three kwargs are
            # the load-bearing security-stage values from spec §7;
            # weakening any of the three is a trust-boundary defect.
            flow = await flow.pre(
                "before_db_write",
                subscribable_tiers=frozenset({"system", "operator"}),
                refusable_tiers=frozenset({"system"}),
                fail_closed=True,
            )
            # The terminal hookpoint names are fixed by spec §7 —
            # ``after_flush`` (NOT ``committed``), ``write_failed``,
            # ``cancelled``. Subscriber spies for these chains land in
            # PR-B Task 5; the names are pinned here so the dispatcher
            # wiring is verifiable before any subscriber exists.
            async with flow.body(
                post="after_flush",
                error="write_failed",
                cancel="cancelled",
            ):
                await self._persist(flow.input)

    def _validate(self, inp: EpisodicRecordInput) -> None:
        """Synchronous structural guard run between ``before_validate``
        and ``before_db_write``.

        No-op stub this slice. PR-B Task 6 grows the body to enforce
        the structural invariants the writer relies on (BCP-47 language
        well-formedness, trust-tier vocabulary, non-empty user_id /
        content). Sync on purpose: the guard is pure CPU and a sync
        signature keeps the failure mode (raise → :func:`Flow.body` 's
        ``except Exception`` arm → ``write_failed`` error chain) easy
        to audit. The hookpoint wiring around it is verifiable today
        with this stub so Task 6 ships against a known-good seam.
        """
        del inp  # Task 6 consumes; see docstring.

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
