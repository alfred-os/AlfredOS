"""Characterization + hookpoint-wiring tests for :meth:`EpisodicMemory.record`.

Slice-2.5 PR-B Tasks 2 + 4. The Task-2 tests (``TestRecordPersistsGoldenRow``)
pin the *golden row* — the exact shape and side-effects of today's
``record`` — across Task 2's ``_persist`` extraction and Task 4's
``invoking()`` wiring. The Task-4 tests (``TestRecordPreHookpointWiring``)
pin the two ``pre`` hookpoints ``before_validate`` and ``before_db_write``
that ``record`` now threads through :func:`alfred.hooks.invoking`.

The characterization tests intentionally pass against both the pre-refactor
body (a single inline ``Episode(...) + add + flush`` block), the
post-refactor body (``inp = EpisodicRecordInput(...); await self._persist(inp)``),
and the post-Task-4 ``invoking()``-wrapped body. Their job is to fail
loudly if any commit drifts the persisted-row shape, the call count,
the awaited-once flush, or the "no other session method touched"
invariant the caller's ``session_scope`` depends on.

The hookpoint-wiring tests pin Task 4's load-bearing security-stage
values for ``before_db_write``:

* ``subscribable_tiers={"system","operator"}`` — a user-plugin tier
  cannot subscribe to the security-stage redactor seam.
* ``refusable_tiers={"system"}`` — only system-tier subscribers
  (DLP-style writers) may refuse the persistence step. An operator-tier
  refusal is unauthorized and audited (§6.5).
* ``fail_closed=True`` — a timed-out / erroring redactor MUST NOT write
  (hard rule #7).

Four characterization invariants pinned:

* **Exactly one ``Episode`` is added per ``record`` call.** A bug where
  the refactor double-counts (e.g. a leftover inline ``add`` plus a new
  ``_persist`` ``add``) trips immediately.
* **All 10 input fields land on the persisted ``Episode`` verbatim.**
  Catches a field-mapping regression — e.g. a refactor that drops
  ``persona_id`` because it has a default — without needing to read the
  ``Episode(...)`` constructor at review time.
* **``session.flush()`` is awaited exactly once.** Pins the
  "one-flush-per-record" contract the caller relies on for ordered
  visibility before the next read.
* **No other session method (``commit``, ``rollback``, ``execute``,
  ``begin``) is invoked.** ``record`` is a writer; transactional
  control belongs to the caller's ``session_scope``. Catches a
  refactor that "helpfully" adds a commit and breaks atomicity across
  multi-record turns.

Six hookpoint-wiring invariants pinned (Task 4):

* **Stage order** — ``before_validate`` fires → ``_validate`` runs →
  ``before_db_write`` fires → ``_persist`` runs.
* **``before_validate`` sees the input** the function was called with.
* **``before_validate`` mutation reaches ``before_db_write``**.
* **``before_db_write`` mutation reaches ``_persist``**.
* **``before_db_write`` refusal short-circuits** ``_persist`` (no row
  written).
* **``before_db_write`` ``fail_closed=True``** — a non-refusal
  exception from a system-tier subscriber wraps as
  :class:`HookSubscriberError` instead of silently treating as
  pass-through.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.hooks import HookContext, HookRefusal, HookSubscriberError
from alfred.hooks.invoke import ERROR_EXC_METADATA_KEY
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.memory.episodic import EpisodicMemory, EpisodicRecordInput, declare_hookpoints
from alfred.memory.models import Episode
from tests.helpers.gates import make_permissive_fixture_gate

# Representative kwargs covering every parameter — including non-default
# values for the six fields with defaults — so the "fields match input"
# assertions exercise the real mapping, not just whatever the defaults
# happen to be today.
_RECORD_KWARGS: dict[str, object] = {
    "user_id": "operator",
    "role": "user",
    "content": "hello alfred",
    "trust_tier": "T2",
    "tokens_in": 7,
    "tokens_out": 13,
    "cost_usd": 0.000_123,
    "persona": "alfred",
    "persona_id": "alfred",
    "language": "en-US",
}


def _mock_session() -> AsyncMock:
    """AsyncSession surrogate matching :mod:`tests.unit.memory.test_episodic`:
    ``add`` is sync (override the AsyncMock default), ``flush`` / ``execute``
    stay async. Keeping the helper local rather than importing keeps the
    characterization isolated — if the canonical mock helper changes its
    shape, this test still pins today's behaviour.
    """
    session = AsyncMock()
    session.add = MagicMock()
    return session


@pytest.mark.asyncio
class TestRecordPersistsGoldenRow:
    """Locks the persistence side-effects of ``record`` so Task 2's
    extraction of ``_persist`` and Task 4-5's hook wiring are provably
    behaviour-preserving."""

    async def test_record_adds_exactly_one_episode(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert session.add.call_count == 1
        added = session.add.call_args_list[0].args[0]
        assert isinstance(added, Episode)

    async def test_record_maps_every_input_field_onto_episode(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        added: Episode = session.add.call_args_list[0].args[0]
        # Iterate the kwargs rather than spelling each assertion out so
        # adding an 11th kwarg to ``record`` + ``Episode`` is covered
        # the moment ``_RECORD_KWARGS`` is updated. The drift-guard in
        # ``test_episodic_record_input.py`` already enforces that the
        # carrier's field list mirrors ``record``'s signature, so the
        # set of names traversed here cannot silently shrink.
        for field_name, expected_value in _RECORD_KWARGS.items():
            assert getattr(added, field_name) == expected_value, (
                f"field {field_name!r} did not land on the persisted Episode"
            )

    async def test_record_awaits_flush_exactly_once(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        session.flush.assert_awaited_once()

    async def test_record_touches_no_other_session_method(self) -> None:
        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        # Transactional control (``commit`` / ``rollback`` / ``begin``)
        # belongs to the caller's ``session_scope``. ``execute`` is the
        # read path and has no business firing on a write. AsyncMock
        # records ``await_count`` for awaitable methods; ``call_count``
        # for sync. Both must be zero.
        assert session.commit.await_count == 0
        assert session.rollback.await_count == 0
        assert session.execute.await_count == 0
        assert session.begin.call_count == 0


# ──────────────────────────────────────────────────────────────────────
# Task 4 — pre-hookpoint wiring fixtures + tests
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def fresh_registry_allow_system() -> Iterator[HookRegistry]:
    """Yield a fresh :class:`HookRegistry` with the system tier granted.

    Task 4 wires ``before_db_write`` with
    ``refusable_tiers={"system"}`` — verifying that the system-only
    refusal contract holds and that a ``fail_closed=True`` chain raises
    :class:`HookSubscriberError` when a system-tier subscriber crashes
    requires a registry whose fixture-parity gate
    (:func:`make_permissive_fixture_gate(allow_system=True)`) permits
    system-tier registration. The pre-test singleton is captured and
    restored on teardown so the test never leaks a permissive
    registry into a sibling test (CLAUDE.md hard rule #4 — the gate
    is the security layer; tests do not stub it away with an
    always-allow shim).

    Mirrors the fixture shape in :mod:`tests.unit.hooks.conftest` but
    lives here because the memory unit tests sit on a sibling tree and
    pytest will not discover hook-package conftest fixtures from this
    directory.
    """
    prior = get_registry()
    registry = HookRegistry(gate=make_permissive_fixture_gate(allow_system=True))
    set_registry(registry)
    # #119 — declare the episodic publisher's hookpoints on the fresh
    # registry BEFORE any subscriber registers. Production code reaches
    # the same declaration via the module-init call at the bottom of
    # ``src/alfred/memory/episodic.py``; tests swap the singleton so we
    # re-run the declaration on the fresh one explicitly. The call is
    # idempotent, so a future test that also constructs an
    # :class:`EpisodicMemory` doesn't double-declare.
    declare_hookpoints(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


@pytest.mark.asyncio
class TestRecordPreHookpointWiring:
    """Task 4 — verify ``record`` threads ``before_validate`` +
    ``before_db_write`` via :func:`alfred.hooks.invoking`.

    Each test owns ONE responsibility so a refactor risk surfaces as
    a single failing test, not a clustered diagnostic. The
    ``fresh_registry_allow_system`` fixture is the only setup seam; no
    test stubs the capability gate.
    """

    # ------------------------------------------------------------------
    # 1. Order: before_validate → _validate → before_db_write → _persist
    # ------------------------------------------------------------------

    async def test_pre_hookpoints_fire_in_documented_order(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """Stage order is load-bearing: ``before_validate`` runs FIRST so
        a subscriber may rewrite the payload before the synchronous
        guard, then ``_validate`` runs, then ``before_db_write`` runs
        with the (possibly mutated) payload, then ``_persist`` writes.

        A regression here — e.g. ``_validate`` running before
        ``before_validate`` — would let a malformed payload abort the
        action before any operator-tier rewriter could correct it,
        breaking the documented redaction-then-validate contract.
        """
        order: list[str] = []

        async def before_validate_spy(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            order.append("memory.episodic.record.before_validate")
            return None

        async def before_db_write_spy(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            order.append("memory.episodic.record.before_db_write")
            return None

        fresh_registry_allow_system.register(
            hook_fn=before_validate_spy,
            hookpoint="memory.episodic.record.before_validate",
            kind="pre",
            tier="operator",
        )
        fresh_registry_allow_system.register(
            hook_fn=before_db_write_spy,
            hookpoint="memory.episodic.record.before_db_write",
            kind="pre",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)

        # Monkey-patch ``_validate`` and ``_persist`` to observe order
        # without rewriting them — keeps the test agnostic to the body
        # of either method. The patches still call through so the
        # session-level invariants stay intact for the next assertions.
        original_validate = mem._validate
        original_persist = mem._persist

        def validate_observer(inp: EpisodicRecordInput) -> None:
            order.append("_validate")
            original_validate(inp)

        async def persist_observer(inp: EpisodicRecordInput) -> None:
            order.append("_persist")
            await original_persist(inp)

        mem._validate = validate_observer  # type: ignore[method-assign]
        mem._persist = persist_observer  # type: ignore[method-assign]

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert order == [
            "memory.episodic.record.before_validate",
            "_validate",
            "memory.episodic.record.before_db_write",
            "_persist",
        ]

    # ------------------------------------------------------------------
    # 2. before_validate sees the input the function was called with
    # ------------------------------------------------------------------

    async def test_before_validate_receives_input_built_from_kwargs(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """The ``before_validate`` subscriber's ctx carries an
        :class:`EpisodicRecordInput` whose 10 fields match the
        function's kwargs verbatim. A field-mapping regression in
        ``record`` — e.g. dropping ``persona_id`` from the constructed
        carrier — surfaces here before any subscriber gets the chance
        to make incorrect assumptions about the payload shape.
        """
        captured: list[HookContext[EpisodicRecordInput]] = []

        async def capture(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            captured.append(ctx)
            return None

        fresh_registry_allow_system.register(
            hook_fn=capture,
            hookpoint="memory.episodic.record.before_validate",
            kind="pre",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)
        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert len(captured) == 1
        inp = captured[0].input
        assert isinstance(inp, EpisodicRecordInput)
        for field_name, expected_value in _RECORD_KWARGS.items():
            assert getattr(inp, field_name) == expected_value, (
                f"field {field_name!r} did not match the record kwarg"
            )

    # ------------------------------------------------------------------
    # 3. before_validate mutation flows to before_db_write
    # ------------------------------------------------------------------

    async def test_before_validate_mutation_visible_at_before_db_write(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """A ``before_validate`` subscriber that returns
        ``ctx.with_input(replace(ctx.input, content="A-mutated"))``
        rewrites the payload for the rest of the chain. The
        ``before_db_write`` subscriber observes the mutated content.

        Pins the threading contract — ``flow.pre()`` rebinds the flow's
        ``_ctx`` holder to the chain's output frozen ctx, so the next
        ``flow.pre()`` call's view reflects the mutation.
        """
        seen_at_db_write: list[str] = []

        async def mutator(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput]:
            return ctx.with_input(replace(ctx.input, content="A-mutated"))

        async def observer(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            seen_at_db_write.append(ctx.input.content)
            return None

        fresh_registry_allow_system.register(
            hook_fn=mutator,
            hookpoint="memory.episodic.record.before_validate",
            kind="pre",
            tier="operator",
        )
        fresh_registry_allow_system.register(
            hook_fn=observer,
            hookpoint="memory.episodic.record.before_db_write",
            kind="pre",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)
        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert seen_at_db_write == ["A-mutated"]

    # ------------------------------------------------------------------
    # 4. before_db_write mutation flows to _persist
    # ------------------------------------------------------------------

    async def test_before_db_write_mutation_flows_to_persist(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """A ``before_db_write`` subscriber that mutates ``content``
        rewrites the payload the action body writes. The
        :class:`Episode` persisted via ``session.add`` carries the
        post-mutation content.

        This is the load-bearing redactor seam — a DLP-style
        subscriber registered on ``before_db_write`` MUST be able to
        rewrite the row before it lands. A regression where
        ``_persist`` reads from a stale carrier would let unredacted
        content reach the DB (CLAUDE.md hard rule #1).
        """

        async def mutator(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput]:
            return ctx.with_input(replace(ctx.input, content="B-mutated"))

        fresh_registry_allow_system.register(
            hook_fn=mutator,
            hookpoint="memory.episodic.record.before_db_write",
            kind="pre",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)
        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert session.add.call_count == 1
        added: Episode = session.add.call_args_list[0].args[0]
        assert added.content == "B-mutated"

    # ------------------------------------------------------------------
    # 5. before_db_write HookRefusal short-circuits _persist
    # ------------------------------------------------------------------

    async def test_before_db_write_refusal_short_circuits_persist(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """A ``system``-tier ``before_db_write`` subscriber that raises
        :class:`HookRefusal` aborts the action — ``_persist`` never
        runs, no ``session.add`` / ``session.flush`` fires, and the
        :class:`HookRefusal` propagates to the caller.

        This is the DLP-block contract — a system-tier policy
        subscriber that detects T3 leakage MUST be able to refuse the
        write. The ``refusable_tiers={"system"}`` configuration on the
        ``before_db_write`` stage is what authorizes the refusal to
        propagate (§6.5).
        """

        async def refuser(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            raise HookRefusal(
                hook_id="dlp-block",
                action_id="memory.episodic.record",
                reason="policy",
                correlation_id=ctx.correlation_id,
            )

        fresh_registry_allow_system.register(
            hook_fn=refuser,
            hookpoint="memory.episodic.record.before_db_write",
            kind="pre",
            tier="system",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)

        with pytest.raises(HookRefusal):
            await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        # _persist never ran: no add, no flush, no read-path execute.
        assert session.add.call_count == 0
        assert session.flush.await_count == 0
        assert session.execute.await_count == 0

    # ------------------------------------------------------------------
    # 6. before_db_write fail_closed=True wraps subscriber errors
    # ------------------------------------------------------------------

    async def test_before_db_write_fail_closed_wraps_subscriber_error(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """A ``system``-tier ``before_db_write`` subscriber that raises a
        non-:class:`HookRefusal` exception (e.g. a redactor whose
        backend is down) wraps as :class:`HookSubscriberError` under
        ``fail_closed=True`` and ``_persist`` never runs.

        This is the "timed-out / erroring redactor MUST NOT write"
        invariant from the spec. A regression where the subscriber's
        exception was silently treated as pass-through would let a
        non-redacted row land — a security-stage failure.

        Pins ``fail_closed=True`` at the ``before_db_write`` stage.
        """

        async def crasher(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            raise ValueError("redactor backend down")

        fresh_registry_allow_system.register(
            hook_fn=crasher,
            hookpoint="memory.episodic.record.before_db_write",
            kind="pre",
            tier="system",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)

        with pytest.raises(HookSubscriberError):
            await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        # _persist never ran — the wrap raised before the body.
        assert session.add.call_count == 0
        assert session.flush.await_count == 0

    # ------------------------------------------------------------------
    # 7. _validate is invoked between the two pre stages
    # ------------------------------------------------------------------

    async def test_validate_invoked_between_pre_stages(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """``_validate`` is called exactly once per ``record`` call,
        BETWEEN ``before_validate`` and ``before_db_write``.

        Distinct from the order test above (test 1) which observes the
        full four-step sequence: this test isolates ``_validate``'s
        call count + carrier identity so the Task-6 evolution of the
        method's body (currently a ``pass`` stub) is grounded in a
        known-good wiring. A regression where ``_validate`` is called
        AFTER ``_persist`` (or twice, or never) trips immediately.
        """
        validate_called_with: list[EpisodicRecordInput] = []
        before_validate_seen: list[bool] = []
        before_db_write_seen: list[bool] = []

        async def before_validate_spy(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            before_validate_seen.append(True)
            # _validate must NOT yet have run.
            assert validate_called_with == []
            return None

        async def before_db_write_spy(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            before_db_write_seen.append(True)
            # _validate must have run exactly once by this point.
            assert len(validate_called_with) == 1
            return None

        fresh_registry_allow_system.register(
            hook_fn=before_validate_spy,
            hookpoint="memory.episodic.record.before_validate",
            kind="pre",
            tier="operator",
        )
        fresh_registry_allow_system.register(
            hook_fn=before_db_write_spy,
            hookpoint="memory.episodic.record.before_db_write",
            kind="pre",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)

        original_validate = mem._validate

        def validate_observer(inp: EpisodicRecordInput) -> None:
            validate_called_with.append(inp)
            original_validate(inp)

        mem._validate = validate_observer  # type: ignore[method-assign]

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert before_validate_seen == [True]
        assert len(validate_called_with) == 1
        assert before_db_write_seen == [True]


# ──────────────────────────────────────────────────────────────────────
# Task 5 — terminal hookpoint wiring: after_flush / write_failed /
# cancelled
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestRecordTerminalHookpointWiring:
    """Task 5 — pin the three terminal chains the :meth:`Flow.body`
    helper drives on behalf of :meth:`EpisodicMemory.record`:

    * ``after_flush`` (post) fires on success.
    * ``write_failed`` (error) fires when ``_persist`` raises a
      non-cancellation exception, and the upstream ``exc`` re-raises
      when no subscriber substitutes (CLAUDE.md hard rule #7 — no
      silent failures).
    * ``cancelled`` (cancel) fires on :class:`asyncio.CancelledError`,
      and the ``write_failed`` chain MUST NOT fire on that path
      (test-102 — cancel-before-error invariant; a regression would
      corrupt audit attribution and risk T3 leakage into the wrong
      audit arm).

    The names themselves are wired by Task 4's ``flow.body(...)`` call
    on :class:`EpisodicMemory.record`. Task 5 PROVES they work by
    observing spies through the real dispatcher path — the PoC
    registers NO terminal-chain subscriber in production wiring, only
    these tests do (cancel-chain dispatch is PR-A-tested at the
    dispatcher level; here we prove the action wires all four kinds
    correctly).
    """

    # ------------------------------------------------------------------
    # 1. after_flush post chain fires on success
    # ------------------------------------------------------------------

    async def test_after_flush_post_chain_fires_on_success(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """``after_flush`` fires post-:meth:`AsyncSession.flush`,
        pre-commit — the durability invariant lives on the caller's
        ``session_scope``, not this hook (mem-1 / Decision 3.1).

        A regression that renamed the hookpoint to ``committed`` would
        let a subscriber fire BEFORE the row was durable; any
        notification / metric / counter the subscriber externalised
        on that signal would become a falsehood if a later same-turn
        write rolled back. The spec §7 fix on ``after_flush`` is the
        load-bearing choice this test pins.
        """
        seen: list[HookContext[EpisodicRecordInput]] = []

        async def post_spy(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            seen.append(ctx)
            return None

        fresh_registry_allow_system.register(
            hook_fn=post_spy,
            hookpoint="memory.episodic.record.after_flush",
            kind="post",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)

        await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert len(seen) == 1
        assert seen[0].kind == "post"
        assert seen[0].hookpoint == "memory.episodic.record.after_flush"
        # Sanity: _persist did run (the post chain fires only after
        # the body completes successfully).
        assert session.add.call_count == 1
        session.flush.assert_awaited_once()

    # ------------------------------------------------------------------
    # 2. write_failed error chain fires when _persist raises
    # ------------------------------------------------------------------

    async def test_write_failed_error_chain_fires_on_persist_raise(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """A non-:class:`asyncio.CancelledError` exception from
        :meth:`_persist` routes through the ``write_failed`` chain.

        Contract pinned:

        * the spy receives the upstream exception via
          ``ctx.metadata[ERROR_EXC_METADATA_KEY]`` (the dispatcher's
          stash key — read by import, not string literal, so a future
          rename surfaces at this read site);
        * :meth:`_persist` was called (the exception is from the
          body, not earlier in the chain);
        * the spy returns ``None`` so the upstream :class:`ValueError`
          re-raises unchanged (no silent suppression — CLAUDE.md hard
          rule #7).
        """
        seen_exc: list[BaseException] = []

        async def error_spy(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            upstream = ctx.metadata.get(ERROR_EXC_METADATA_KEY)
            assert isinstance(upstream, BaseException)
            seen_exc.append(upstream)
            return None

        fresh_registry_allow_system.register(
            hook_fn=error_spy,
            hookpoint="memory.episodic.record.write_failed",
            kind="error",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)

        boom = ValueError("persist failed")

        async def failing_persist(_inp: EpisodicRecordInput) -> None:
            raise boom

        mem._persist = failing_persist  # type: ignore[method-assign]

        with pytest.raises(ValueError) as exc_info:
            await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        # Identity preserved — same instance, not a re-wrap.
        assert exc_info.value is boom
        assert len(seen_exc) == 1
        assert seen_exc[0] is boom

    # ------------------------------------------------------------------
    # 3. cancelled cancel chain fires + write_failed does NOT fire
    # ------------------------------------------------------------------

    async def test_cancelled_chain_fires_and_write_failed_does_not(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """**test-102 regression pin — cancel-before-error invariant.**

        When :meth:`_persist` raises :class:`asyncio.CancelledError`:

        * the ``cancelled`` cancel chain fires;
        * the ``write_failed`` error chain does NOT fire (a regression
          here would let an error subscriber observe a cancellation as
          if it were a non-cancellation failure — corrupting audit
          attribution and risking T3 leakage into the wrong audit arm);
        * the :class:`asyncio.CancelledError` propagates so the
          surrounding task's cancellation is preserved.

        The PoC registers no production cancel subscriber (the
        cancel-chain dispatch is PR-A-tested at the dispatcher level);
        this spy exists only to prove the action wires the cancel
        hookpoint correctly.
        """
        cancel_seen: list[HookContext[EpisodicRecordInput]] = []
        error_seen: list[HookContext[EpisodicRecordInput]] = []

        async def cancel_spy(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            cancel_seen.append(ctx)
            return None

        async def error_spy(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            error_seen.append(ctx)
            return None

        fresh_registry_allow_system.register(
            hook_fn=cancel_spy,
            hookpoint="memory.episodic.record.cancelled",
            kind="cancel",
            tier="operator",
        )
        fresh_registry_allow_system.register(
            hook_fn=error_spy,
            hookpoint="memory.episodic.record.write_failed",
            kind="error",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)

        async def cancelling_persist(_inp: EpisodicRecordInput) -> None:
            raise asyncio.CancelledError

        mem._persist = cancelling_persist  # type: ignore[method-assign]

        with pytest.raises(asyncio.CancelledError):
            await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        # Cancel chain ran; error chain did NOT.
        assert len(cancel_seen) == 1
        assert cancel_seen[0].kind == "cancel"
        assert cancel_seen[0].hookpoint == "memory.episodic.record.cancelled"
        assert error_seen == []

    # ------------------------------------------------------------------
    # 4. after_flush does NOT fire when _persist raises
    # ------------------------------------------------------------------

    async def test_after_flush_does_not_fire_on_persist_raise(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """``after_flush`` is the success-arm hookpoint; it must NOT
        fire when the body raised.

        A regression where ``after_flush`` fired on the error path
        would be a worse durability lie than the ``committed``-vs-
        ``after_flush`` choice itself: a subscriber would observe the
        post-success signal on a FAILED write. Pins the
        :meth:`Flow.body`'s ``else``-vs-``except`` branch routing for
        episodic-record specifically.
        """
        post_seen: list[bool] = []

        async def post_spy(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            post_seen.append(True)
            return None

        fresh_registry_allow_system.register(
            hook_fn=post_spy,
            hookpoint="memory.episodic.record.after_flush",
            kind="post",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)

        async def failing_persist(_inp: EpisodicRecordInput) -> None:
            raise ValueError("persist failed")

        mem._persist = failing_persist  # type: ignore[method-assign]

        with pytest.raises(ValueError):
            await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        assert post_seen == []


# ──────────────────────────────────────────────────────────────────────
# Task 4 — drift guard: any *_ flow-driver kwargs typo would silently
# regress the order test (above) into a green pass, so we also pin the
# zero-subscriber path stays identical to the pre-Task-4 shape.
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zero_subscriber_path_persists_one_row(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """With NO subscribers registered, ``record`` still adds one row
    and flushes once.

    Pins that the ``invoking()`` wrap is a NO-OP when the registry is
    empty — the action body's persistence step runs unchanged. The
    integration golden-row test (Task 3) provides the byte-level
    pin; this is the unit-level equivalent so a CI failure can be
    diagnosed without the testcontainer fixture.

    Use ``allow_system=True`` so the fixture context is identical to
    the rest of this test module — keeps the "what's different here?"
    surface narrow.
    """
    session = _mock_session()
    mem = EpisodicMemory(session=session)

    await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

    assert session.add.call_count == 1
    session.flush.assert_awaited_once()


# ──────────────────────────────────────────────────────────────────────
# Task 6 — `_validate` guard semantics
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestValidateGuard:
    """Task 6 — pin the minimal structural guard that makes the
    ``before_validate`` hookpoint name meaningful.

    ``_validate`` is the anchor between the ``before_validate`` pre
    stage (open hookpoint; subscribers may mutate the payload) and the
    ``before_db_write`` security stage. Without a real guard in this
    slot, ``before_validate`` would be a hookpoint whose name lies
    about its position in the lifecycle — there would be no validate
    step to run "before".

    The guard is minimal by design (Task 6 spec): non-empty
    ``user_id`` and a ``role`` drawn from the ``Role`` Literal
    vocabulary. Growing business rules here is out of scope; the
    point of these tests is to pin the EXISTENCE of the guard, its
    failure mode (loud :class:`ValueError`), and its position in the
    chain (sees post-``before_validate`` mutation, short-circuits
    ``before_db_write`` + ``_persist``).
    """

    # ------------------------------------------------------------------
    # 1. Empty user_id is rejected loudly + does NOT persist
    # ------------------------------------------------------------------

    async def test_validate_rejects_empty_user_id(self) -> None:
        """``_validate`` raises :class:`ValueError` when the input
        carries an empty ``user_id``, and the body's write never runs.

        The guard's failure mode is load-bearing: a silent acceptance
        of an empty ``user_id`` would let a per-user-partitioned row
        land under no owner — a partition-leak class defect
        (CLAUDE.md memory rule #2). Loud at the boundary is the only
        acceptable behaviour.
        """
        session = _mock_session()
        mem = EpisodicMemory(session=session)
        kwargs = dict(_RECORD_KWARGS, user_id="")

        with pytest.raises(ValueError, match="user_id"):
            await mem.record(**kwargs)  # type: ignore[arg-type]

        # The body never ran: no row added, no flush.
        assert session.add.call_count == 0
        assert session.flush.await_count == 0

    # ------------------------------------------------------------------
    # 2. Unknown role string is rejected
    # ------------------------------------------------------------------

    async def test_validate_rejects_unknown_role(self) -> None:
        """``_validate`` raises :class:`ValueError` when ``role`` is
        not one of the ``Role`` Literal members
        (``system`` / ``user`` / ``assistant``).

        Distinct from the DB-level ``ck_episodes_role`` constraint
        which only fires on COMMIT (and only for ``user`` /
        ``assistant``). Failing fast in Python lets the orchestrator's
        budget guard and audit writer attribute the rejection to the
        WRITER tier, not to a Postgres integrity error at session
        commit time.
        """
        session = _mock_session()
        mem = EpisodicMemory(session=session)
        kwargs = dict(_RECORD_KWARGS, role="not-a-role")

        with pytest.raises(ValueError, match="role"):
            await mem.record(**kwargs)  # type: ignore[arg-type]

        assert session.add.call_count == 0
        assert session.flush.await_count == 0

    # ------------------------------------------------------------------
    # 3. Validate rejection short-circuits before_db_write + _persist
    # ------------------------------------------------------------------

    async def test_validate_rejection_short_circuits_before_db_write(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """A ``_validate`` rejection aborts the action BEFORE the
        ``before_db_write`` security stage fires.

        This is the order anchor the Task-6 plan names: the
        ``before_validate`` chain runs → ``_validate`` runs → on
        rejection, the chain stops. The ``before_db_write``
        subscribers never see the bad row, and ``_persist`` never
        writes it. If ``_validate`` ran AFTER ``before_db_write``,
        a malformed row would already have been through DLP / redactor
        seams before the structural check rejected it — wasted
        security-stage work and a worse audit story.
        """
        before_db_write_calls: list[bool] = []

        async def before_db_write_spy(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            before_db_write_calls.append(True)
            return None

        fresh_registry_allow_system.register(
            hook_fn=before_db_write_spy,
            hookpoint="memory.episodic.record.before_db_write",
            kind="pre",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)
        kwargs = dict(_RECORD_KWARGS, user_id="")

        with pytest.raises(ValueError):
            await mem.record(**kwargs)  # type: ignore[arg-type]

        # before_db_write spy never fired — the chain short-circuited
        # at _validate, BEFORE the security stage.
        assert before_db_write_calls == []
        assert session.add.call_count == 0
        assert session.flush.await_count == 0

    # ------------------------------------------------------------------
    # 4. _validate sees the post-`before_validate`-mutation input
    # ------------------------------------------------------------------

    async def test_validate_sees_before_validate_mutation(
        self,
        fresh_registry_allow_system: HookRegistry,
    ) -> None:
        """A ``before_validate`` subscriber that mutates ``user_id``
        to ``""`` causes ``_validate`` to reject.

        This is the chain-order pin from the Task-6 plan: WITHOUT the
        subscriber, the call would persist (valid kwargs). WITH the
        subscriber, ``_validate`` raises because it now sees the
        mutated empty ``user_id``. The only way for that to be true
        is if ``_validate`` runs AFTER ``before_validate``'s output —
        proving the position of the guard in the documented sequence.

        A regression where ``_validate`` ran on the pre-mutation
        carrier would let a malformed row past the guard whenever a
        subscriber later in the ``before_validate`` chain made it
        invalid — defeating the whole point of having mutation hooks
        before validation.
        """

        async def empty_user_id_mutator(
            ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput]:
            return ctx.with_input(replace(ctx.input, user_id=""))

        fresh_registry_allow_system.register(
            hook_fn=empty_user_id_mutator,
            hookpoint="memory.episodic.record.before_validate",
            kind="pre",
            tier="operator",
        )

        session = _mock_session()
        mem = EpisodicMemory(session=session)
        # Valid kwargs (non-empty user_id) — the mutator is what makes
        # it invalid by the time _validate sees it.
        with pytest.raises(ValueError, match="user_id"):
            await mem.record(**_RECORD_KWARGS)  # type: ignore[arg-type]

        # _persist never ran — the post-mutation carrier failed the
        # guard, short-circuiting the chain.
        assert session.add.call_count == 0
        assert session.flush.await_count == 0
