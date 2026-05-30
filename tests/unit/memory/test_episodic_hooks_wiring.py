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

from collections.abc import Iterator
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.hooks import HookContext, HookRefusal, HookSubscriberError
from alfred.hooks.capability import DevGate
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.memory.episodic import EpisodicMemory, EpisodicRecordInput
from alfred.memory.models import Episode

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
    requires a registry whose :class:`DevGate` permits system-tier
    registration. The pre-test singleton is captured and restored on
    teardown so the test never leaks a permissive registry into a
    sibling test (CLAUDE.md hard rule #4 — the gate is the security
    layer; tests do not stub it away with an always-allow shim).

    Mirrors the fixture shape in :mod:`tests.unit.hooks.conftest` but
    lives here because the memory unit tests sit on a sibling tree and
    pytest will not discover hook-package conftest fixtures from this
    directory.
    """
    prior = get_registry()
    registry = HookRegistry(gate=DevGate(allow_system=True))
    set_registry(registry)
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
            order.append("before_validate")
            return None

        async def before_db_write_spy(
            _ctx: HookContext[EpisodicRecordInput],
        ) -> HookContext[EpisodicRecordInput] | None:
            order.append("before_db_write")
            return None

        fresh_registry_allow_system.register(
            hook_fn=before_validate_spy,
            hookpoint="before_validate",
            kind="pre",
            tier="operator",
        )
        fresh_registry_allow_system.register(
            hook_fn=before_db_write_spy,
            hookpoint="before_db_write",
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
            "before_validate",
            "_validate",
            "before_db_write",
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
            hookpoint="before_validate",
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
            hookpoint="before_validate",
            kind="pre",
            tier="operator",
        )
        fresh_registry_allow_system.register(
            hook_fn=observer,
            hookpoint="before_db_write",
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
            hookpoint="before_db_write",
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
            hookpoint="before_db_write",
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
            hookpoint="before_db_write",
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
            hookpoint="before_validate",
            kind="pre",
            tier="operator",
        )
        fresh_registry_allow_system.register(
            hook_fn=before_db_write_spy,
            hookpoint="before_db_write",
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
