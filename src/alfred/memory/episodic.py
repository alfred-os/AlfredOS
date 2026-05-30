"""Slice-1 episodic memory: writer + recent-turns loader.

Writes every conversation turn to the `episodes` table. On startup, loads the
most recent N turns so Alfred has cross-restart continuity. Slice 4 replaces
this with the full summarization + semantic-fact consolidation pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from alfred.hooks import (
    OPEN_TIERS,
    SYSTEM_ONLY_TIERS,
    SYSTEM_OPERATOR_TIERS,
    HookRegistry,
    get_registry,
    invoking,
)
from alfred.memory.models import Episode
from alfred.providers.base import Role

# The runtime vocabulary of the ``Role`` ``Literal``. PEP 586's
# ``typing.get_args(Role)`` would compute this dynamically, but
# materializing the tuple at import time keeps the membership check in
# :meth:`EpisodicMemory._validate` a constant-time set lookup and lets
# the drift-guard in
# :func:`tests.unit.memory.test_episodic_hooks_wiring.TestValidateGuard.
# test_validate_rejects_unknown_role` lock the exact set without
# depending on ``typing`` internals. If a new ``Role`` member is added
# to :mod:`alfred.providers.base`, the test fails the moment
# ``role="..."`` is no longer rejected here — surfacing the drift
# before a writer can persist a row whose role the closed-domain DB
# constraint would later reject at commit time.
_VALID_ROLES: frozenset[str] = frozenset({"system", "user", "assistant"})


# The five hookpoint names :meth:`EpisodicMemory.record` invokes.
# Centralised so :func:`declare_hookpoints` and ``record``'s invoke
# calls share one source of truth (a typo on either side would surface
# as a register-time strict-declaration failure under #119, but
# centralising names removes the typo surface entirely).
_HOOKPOINT_BEFORE_VALIDATE: Final[str] = "before_validate"
_HOOKPOINT_BEFORE_DB_WRITE: Final[str] = "before_db_write"
_HOOKPOINT_AFTER_FLUSH: Final[str] = "after_flush"
_HOOKPOINT_WRITE_FAILED: Final[str] = "write_failed"
_HOOKPOINT_CANCELLED: Final[str] = "cancelled"


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Declare every hookpoint :meth:`EpisodicMemory.record` invokes.

    Idempotent — re-running this against the same registry is a no-op
    (the registry's :meth:`HookRegistry.register_hookpoint` is
    idempotent on equal metadata). This is what makes it safe to call
    from BOTH module-init AND :meth:`EpisodicMemory.__init__`: the
    second call's metadata equals the first call's, so the registry
    short-circuits.

    Why both call sites:

    * **Module-init** (called at the bottom of this file) — the
      production path. The first ``from alfred.memory.episodic import
      EpisodicMemory`` triggers the declaration against the global
      singleton, and subsequent subscriber registrations succeed.
    * **Per-instance** (called from :meth:`EpisodicMemory.__init__`) —
      the test path. A test fixture swaps :func:`get_registry`'s
      singleton with a fresh registry; the module-init declaration
      went to the prior registry, NOT the fresh one. Re-declaring on
      the active registry at instance construction time ensures the
      hookpoints land on whichever registry the test is using.

    Idempotency means "called twice on the same registry" is safe.
    Production code never sees the second call (the test swap doesn't
    happen there); test code triggers both but the second is a no-op.

    Args:
        registry: The registry to declare against. Defaults to
            :func:`get_registry`'s active singleton. The test fixtures
            pass the fresh registry explicitly to be unambiguous.
    """
    target = registry if registry is not None else get_registry()

    # ``before_validate`` — open hookpoint, all tiers eligible,
    # ``fail_closed=False``. Refusals from any tier are authorized.
    target.register_hookpoint(
        name=_HOOKPOINT_BEFORE_VALIDATE,
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
    )

    # ``before_db_write`` — security stage. ``user-plugin`` cannot
    # subscribe (would let a third-party plugin wedge into the
    # redactor seam); only system-tier subscribers may refuse;
    # ``fail_closed=True`` because a crashing redactor MUST NOT let
    # the un-redacted write proceed (CLAUDE.md hard rule #7).
    #
    # The tier sets here MUST equal the invoke-site values in
    # :meth:`EpisodicMemory.record` — Group I's dispatch-time drift
    # check raises :class:`HookError` on any disagreement. CR cycle-1
    # MAJ-4: routing both sides through the public
    # :data:`alfred.hooks.SYSTEM_OPERATOR_TIERS` /
    # :data:`alfred.hooks.SYSTEM_ONLY_TIERS` constants makes
    # one-side edits impossible — both sites pin to the SAME object.
    target.register_hookpoint(
        name=_HOOKPOINT_BEFORE_DB_WRITE,
        subscribable_tiers=SYSTEM_OPERATOR_TIERS,
        refusable_tiers=SYSTEM_ONLY_TIERS,
        fail_closed=True,
    )

    # The three terminal hookpoints inherit the defaults — open
    # subscription, open refusal (though §6.5 says refusal is pre-only
    # so post/error/cancel refusals propagate uncaught regardless),
    # not fail-closed (post is observability-shaped; error and cancel
    # have their own special re-raise semantics).
    target.register_hookpoint(
        name=_HOOKPOINT_AFTER_FLUSH,
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
    )
    target.register_hookpoint(
        name=_HOOKPOINT_WRITE_FAILED,
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
    )
    target.register_hookpoint(
        name=_HOOKPOINT_CANCELLED,
        subscribable_tiers=OPEN_TIERS,
        refusable_tiers=OPEN_TIERS,
        fail_closed=False,
    )


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
        # Idempotently re-declare the hookpoints against the active
        # registry. Production already declared at module-init
        # (no-op); tests that swap the singleton via
        # :func:`alfred.hooks.set_registry` get the declarations on
        # whichever registry is active when the instance is
        # constructed. The call is microseconds — five idempotent
        # dict-and-equality checks.
        declare_hookpoints()

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
            flow = await flow.pre(
                _HOOKPOINT_BEFORE_VALIDATE,
                subscribable_tiers=OPEN_TIERS,
                refusable_tiers=OPEN_TIERS,
                fail_closed=False,
            )
            self._validate(flow.input)
            # ``before_db_write`` — security stage. The three kwargs are
            # the load-bearing security-stage values from spec §7;
            # weakening any of the three is a trust-boundary defect.
            # Under #119 the values MUST equal
            # :func:`declare_hookpoints`'s declaration for this
            # hookpoint — the dispatch-time defense-in-depth re-check
            # raises :class:`HookError` on drift. CR cycle-1 MAJ-4:
            # both sides pin to the SAME public constants
            # (:data:`alfred.hooks.SYSTEM_OPERATOR_TIERS` /
            # :data:`alfred.hooks.SYSTEM_ONLY_TIERS`) so one-side
            # edits are impossible.
            flow = await flow.pre(
                _HOOKPOINT_BEFORE_DB_WRITE,
                subscribable_tiers=SYSTEM_OPERATOR_TIERS,
                refusable_tiers=SYSTEM_ONLY_TIERS,
                fail_closed=True,
            )
            # The terminal hookpoint names are fixed by spec §7 —
            # ``after_flush`` (NOT ``committed``), ``write_failed``,
            # ``cancelled``. PR-B Task 5 pins each with a spy subscriber
            # in ``tests/unit/memory/test_episodic_hooks_wiring.py``.
            #
            # mem-1 / Decision 3.1 — WHY ``after_flush`` and not
            # ``committed``:
            # :meth:`_persist` only ``flush``-es; the durable COMMIT
            # happens in the caller's ``session_scope`` (see
            # ``src/alfred/db.py``). Until commit, a later same-turn
            # failure can still roll back this row. A subscriber wired
            # to a hookpoint named ``committed`` would therefore be a
            # durability lie — it would fire BEFORE the row is durable
            # and any side-effect it took on that promise (queue a
            # notification, count a metric as "persisted") could become
            # an externalised falsehood. ``after_flush`` is honest
            # about the lifecycle stage and leaves the durability
            # signal to a future ``after_commit`` hookpoint owned by
            # ``session_scope`` (out of scope this slice).
            async with flow.body(
                post=_HOOKPOINT_AFTER_FLUSH,
                error=_HOOKPOINT_WRITE_FAILED,
                cancel=_HOOKPOINT_CANCELLED,
            ):
                await self._persist(flow.input)

    def _validate(self, inp: EpisodicRecordInput) -> None:
        """Synchronous structural guard run AFTER the
        ``before_validate`` chain and BEFORE the ``before_db_write``
        security stage.

        Minimal by design — the anchor that makes the
        ``before_validate`` hookpoint name meaningful. Subscribers on
        ``before_validate`` may rewrite ``content`` / ``user_id`` /
        any other field BEFORE this runs; ``_validate``'s rejection
        short-circuits the chain before the DLP / redactor seam fires
        and before :meth:`_persist` writes the row.

        Sync on purpose: the guard is pure CPU. A sync signature
        keeps the failure mode (raise → :class:`Flow.body`'s
        exception arm → ``write_failed`` error chain) easy to audit
        and keeps the call site one line in :meth:`record`.

        Pure function of its input: no I/O, no DB access, no
        registry lookup. Raises loudly at the boundary
        (CLAUDE.md hard rule #7 — no silent failures in write paths).

        Two guards this slice — kept minimal so the "what does the
        validate stage check?" answer fits in two lines. Growing
        business rules (BCP-47 well-formedness, trust-tier vocabulary,
        content-length caps) belongs to a later slice that adds the
        corresponding test pins.

        Args:
            inp: the post-``before_validate``-chain carrier.

        Raises:
            ValueError: if ``user_id`` is empty (per-user partition
                anchor; a row with no owner is a partition-leak
                class defect — CLAUDE.md memory rule #2), or if
                ``role`` is not a member of the ``Role`` Literal
                vocabulary
                (``"system"`` / ``"user"`` / ``"assistant"``).
        """
        if not inp.user_id:
            raise ValueError(
                "EpisodicMemory.record rejected: user_id must not be empty "
                "(per-user partition anchor)"
            )
        if inp.role not in _VALID_ROLES:
            raise ValueError(
                f"EpisodicMemory.record rejected: role must be one of "
                f"{sorted(_VALID_ROLES)!r}, got {inp.role!r}"
            )

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


# Module-init declaration — #119 / spec §6.2 "publishers declare at
# import time". The call is idempotent (re-declaring with the same
# args is a no-op) so re-importing this module under pytest test
# isolation is safe. Test fixtures that swap :func:`get_registry`'s
# singleton get the declaration via :meth:`EpisodicMemory.__init__`'s
# call to :func:`declare_hookpoints`, which targets the active
# registry at instance construction time.
declare_hookpoints()
