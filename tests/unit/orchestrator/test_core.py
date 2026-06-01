"""Tests for the Slice-2 PR-B per-user OODA orchestrator.

PR-B reshapes the orchestrator into a stateless-per-turn dispatcher:

* The constructor caches the single household operator (via
  ``IdentityResolverLike.get_operator()``) instead of holding raw name + language.
* ``handle_user_message`` is called with the per-turn ``user`` value object, a
  ``TaggedContent[T2]`` payload (the adapter tags now, not the orchestrator),
  and a pool-acquired ``WorkingMemory`` instance.
* Budget calls thread ``user.slug``; episodic + audit rows thread
  ``user.language`` + ``persona``/``actor_persona="alfred"``.
* The persona prompt's ``<user_context>`` tail carries the operator's
  display_name + the addressed user's display_name + the user's language.
* A new 7th audit branch (``result="unknown_budget_user"``) surfaces a
  ``UnknownBudgetUserError`` from ``BudgetGuard`` — defense-in-depth audit row
  with ``subject["phase"]="budget_pre_check"`` or ``"budget_post_charge"``.

Spec: docs/superpowers/plans/2026-05-26-slice-2-pr-B-budget-memory-orchestrator.md
(Phase 4 Tasks 10-11), with the prior slice-1 invariants kept intact
(WorkingMemory is async per ADR-0002; constructor kwargs are keyword-only;
``source=`` is passed at every ``tag()`` site).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.budget.guard import BudgetError, PerCallCapExceededError, UnknownBudgetUserError
from alfred.memory.working import Turn
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse
from alfred.security.tiers import T2, TaggedContent, tag


@dataclass(frozen=True)
class _StubUser:
    """Minimal duck-typed stand-in for ``alfred.identity.models.User``.

    The orchestrator reads only ``slug``, ``display_name``, ``language``.
    Keeping the test surface independent of SQLAlchemy session machinery
    matches the ``_StubUser`` pattern used in ``tests/unit/budget/test_guard.py``.
    """

    slug: str
    display_name: str
    language: str


def _default_operator() -> _StubUser:
    """The household operator returned by the default IdentityResolver stub."""
    return _StubUser(slug="bruce", display_name="Bruce", language="en-US")


def _default_user() -> _StubUser:
    """Per-turn requesting user used by tests that don't override.

    Defaults to the operator (Bruce) so existing single-operator-shaped tests
    read naturally — the operator is also the addressed user in Slice 1+2
    until Discord multi-user lands in PR D2.
    """
    return _default_operator()


def _tag_t2(content: str) -> TaggedContent[T2]:
    """T2-tagged content as the adapter would produce it.

    PR-B moves the tag boundary outward to the adapter (CLI / TUI / Discord);
    the orchestrator receives an already-tagged value, never a raw ``str``.
    """
    return tag(T2, content, source="test.adapter")


def _make_budget(*, estimate: float = 0.01, would_exceed: bool = False) -> MagicMock:
    """Per-user budget mock — every method takes ``user_id`` as the first positional."""
    budget = MagicMock()
    budget.estimate_for = MagicMock(return_value=estimate)
    budget.would_exceed = MagicMock(return_value=would_exceed)
    budget.check_and_charge = MagicMock(return_value=None)
    return budget


def _make_session_scope() -> tuple[Any, MagicMock]:
    """Return (scope_callable, session_mock) — the scope is an async ctx manager
    that yields the session. The session has an async ``rollback``."""
    session = MagicMock()
    session.rollback = AsyncMock()

    @asynccontextmanager
    async def scope() -> AsyncIterator[MagicMock]:
        yield session

    return scope, session


def _make_episodic_audit() -> tuple[MagicMock, MagicMock]:
    episodic = MagicMock()
    episodic.record = AsyncMock()
    audit = MagicMock()
    audit.append = AsyncMock()
    return episodic, audit


def _build(
    *,
    working: MagicMock | None = None,
    router: MagicMock | None = None,
    budget: MagicMock | None = None,
    operator: _StubUser | None = None,
    redactor: Any = None,
    # ``episodic_factory`` lets a test inject a custom EpisodicMemory stand-in —
    # used by the cancellation tests to make a specific record() call cancel
    # mid-await. Default = the shared mock created by `_make_episodic_audit`.
    episodic_factory: Any = None,
    # PR-S3-3b Task 12: per-action deadline + autocommit audit writer for
    # supervisor.action_timeout rows. The deadline defaults to a value far
    # larger than any test's expected runtime so existing tests stay flake-
    # free; timeout tests override to a sub-millisecond value. The autocommit
    # writer defaults to a distinct mock so the test can assert that the
    # session-bound writer (``m["audit"]``) is NOT the surface used by the
    # timeout-row emission.
    deadline_seconds: float = 30.0,
    autocommit_audit: MagicMock | None = None,
) -> tuple[Orchestrator, dict[str, Any]]:
    if working is None:
        # A simple in-memory stand-in: append accumulates Turns; turns() returns
        # the accumulated list. Lets the orchestrator's "append user, assemble
        # request from history" sequence work end-to-end through the mock.
        buffer: list[Turn] = []

        async def _append(*, role: str, content: str) -> None:
            buffer.append(Turn(role=role, content=content))  # type: ignore[arg-type]

        async def _turns() -> list[Turn]:
            return list(buffer)

        working = MagicMock(
            turns=AsyncMock(side_effect=_turns),
            append=AsyncMock(side_effect=_append),
            clear=AsyncMock(),
        )
    if router is None:
        router = MagicMock()
        router.complete = AsyncMock(
            return_value=CompletionResponse(
                content="Very good, Sir.",
                tokens_in=12,
                tokens_out=4,
                cost_usd=0.0005,
                model="deepseek-chat",
            )
        )
    if budget is None:
        budget = _make_budget()
    scope, session = _make_session_scope()
    episodic, audit = _make_episodic_audit()
    # If a test supplied a custom factory, route through it (and resolve the
    # episodic mock the test owns); otherwise wire the default shared mock so
    # assertions on m["episodic"] continue to work.
    if episodic_factory is not None:
        resolved_factory = episodic_factory
        episodic = episodic_factory(session)
    else:
        resolved_factory = lambda _s: episodic  # noqa: E731 — mock seam stays one-liner.
    # IdentityResolverLike stub: ``get_operator()`` is called exactly once at
    # construction; the orchestrator caches the result for its lifetime so a
    # later operator reassignment does not silently swap mid-turn. A MagicMock
    # is more than enough — tests assert call_count to prove the once-only
    # contract where it matters.
    resolved_operator = operator if operator is not None else _default_operator()
    identity_resolver = MagicMock()
    identity_resolver.get_operator = MagicMock(return_value=resolved_operator)
    if autocommit_audit is None:
        autocommit_audit = MagicMock()
        autocommit_audit.append = AsyncMock()
    kwargs: dict[str, Any] = {
        "identity_resolver": identity_resolver,
        "session_scope": scope,
        "router": router,
        "budget": budget,
        "episodic_factory": resolved_factory,
        "audit_factory": lambda _f: audit,
        "autocommit_audit_factory": lambda _f: autocommit_audit,
        "deadline_seconds": deadline_seconds,
    }
    if redactor is not None:
        kwargs["redactor"] = redactor
    orch = Orchestrator(**kwargs)
    return orch, {
        "working": working,
        "router": router,
        "budget": budget,
        "session": session,
        "episodic": episodic,
        "audit": audit,
        "autocommit_audit": autocommit_audit,
        "identity_resolver": identity_resolver,
        "operator": resolved_operator,
    }


async def _send(
    orch: Orchestrator,
    m: dict[str, Any],
    text: str,
    *,
    user: _StubUser | None = None,
) -> str:
    """Drive one turn — adapter-shaped: tag T2, pass the pool-acquired WM in."""
    requester = user if user is not None else _default_user()
    return await orch.handle_user_message(
        user=requester,
        content=_tag_t2(text),
        working_memory=m["working"],
    )


class TestOrchestratorHappyPath:
    async def test_records_episode_calls_provider_and_audits(self) -> None:
        orch, m = _build()
        reply = await _send(orch, m, "Good morning, Alfred.")

        assert reply == "Very good, Sir."

        # Working memory: one append for the user turn, one for the assistant turn.
        assert m["working"].append.await_count == 2
        user_call = m["working"].append.await_args_list[0]
        assistant_call = m["working"].append.await_args_list[1]
        assert user_call.kwargs == {"role": "user", "content": "Good morning, Alfred."}
        assert assistant_call.kwargs == {"role": "assistant", "content": "Very good, Sir."}

        # Episodic: two records, both pinned to en-US + persona="alfred".
        assert m["episodic"].record.await_count == 2
        for call in m["episodic"].record.await_args_list:
            assert call.kwargs["language"] == "en-US"
            assert call.kwargs["persona"] == "alfred"
        ep_user = m["episodic"].record.await_args_list[0].kwargs
        ep_asst = m["episodic"].record.await_args_list[1].kwargs
        assert ep_user["role"] == "user"
        assert ep_user["trust_tier"] == "T2"
        assert ep_user["content"] == "Good morning, Alfred."
        assert ep_asst["role"] == "assistant"
        # ADR-0008: assistant output is T2 in Slice 1 (at-most-as-trusted as
        # the T2 input that triggered it). T0 is reserved for AlfredOS
        # internals/code/prompts/configs per PRD §7.1.
        assert ep_asst["trust_tier"] == "T2"
        assert ep_asst["tokens_in"] == 12
        assert ep_asst["tokens_out"] == 4
        assert ep_asst["cost_usd"] == pytest.approx(0.0005)

        # Provider request: first message is the system prompt; user message follows.
        req = m["router"].complete.await_args.args[0]
        assert req.messages[0].role == "system"
        # The persona prompt's <user_context> tail carries the operator name +
        # addressed-user name + language (PR-B Phase 3).
        assert "<operator_name>Bruce</operator_name>" in req.messages[0].content
        assert "<addressed_user_name>Bruce</addressed_user_name>" in req.messages[0].content
        assert "<addressed_user_language>en-US</addressed_user_language>" in req.messages[0].content
        # Working memory was empty, so the user message must come from this turn.
        assert any(msg.role == "user" and "Good morning" in msg.content for msg in req.messages)

        # Budget pre-check happened; the charge succeeded.
        assert m["budget"].estimate_for.call_count == 1
        assert m["budget"].would_exceed.call_count == 1
        assert m["budget"].check_and_charge.call_count == 1
        # PR-B Phase 4: every budget call threads ``user.slug`` as the first
        # positional argument.
        m["budget"].check_and_charge.assert_called_with("bruce", pytest.approx(0.0005))

        # Audit: one row, success, with language + actor_persona threaded.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["event"] == "orchestrator.turn"
        assert audit_kwargs["result"] == "success"
        assert audit_kwargs["trust_tier_of_trigger"] == "T2"
        assert audit_kwargs["language"] == "en-US"
        assert audit_kwargs["actor_persona"] == "alfred"
        assert audit_kwargs["actor_user_id"] == "bruce"
        assert audit_kwargs["cost_actual_usd"] == pytest.approx(0.0005)
        assert audit_kwargs["subject"]["model"] == "deepseek-chat"
        assert audit_kwargs["subject"]["charge_result"] == "success"

        # Session was not rolled back.
        m["session"].rollback.assert_not_awaited()

    async def test_get_operator_called_exactly_once_at_construction(self) -> None:
        """The operator identity is captured at __init__ and cached for the
        orchestrator's lifetime. Re-resolving every turn would let a mid-flight
        operator demotion silently swap identity inside an open turn — and
        would also undo the single-DB-hit-per-start contract PR-A established."""
        orch, m = _build()
        # Construction has already happened. Drive a couple of turns — the
        # resolver must NOT be touched again.
        await _send(orch, m, "first")
        await _send(orch, m, "second")
        assert m["identity_resolver"].get_operator.call_count == 1


class TestOrchestratorBudgetBlocked:
    async def test_pre_check_refusal_audits_and_raises(self) -> None:
        budget = _make_budget(estimate=0.50, would_exceed=True)
        orch, m = _build(budget=budget)
        with pytest.raises(BudgetError):
            await _send(orch, m, "a long request")

        # Provider must not be called.
        m["router"].complete.assert_not_awaited()
        # Charge must not be made (the call never happened).
        m["budget"].check_and_charge.assert_not_called()
        # Audit row was still written with the right result.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "budget_blocked"
        assert audit_kwargs["cost_estimate_usd"] == pytest.approx(0.50)
        assert audit_kwargs["cost_actual_usd"] == 0.0
        # The user-input episode was still written; the assistant one was not.
        roles = [c.kwargs["role"] for c in m["episodic"].record.await_args_list]
        assert roles == ["user"]
        # Session rolled back because we raised out of the scope.
        m["session"].rollback.assert_awaited()


class TestOrchestratorProviderFailure:
    async def test_provider_exception_is_audited_and_re_raised(self) -> None:
        router = MagicMock()
        router.complete = AsyncMock(side_effect=RuntimeError("upstream 503"))
        orch, m = _build(router=router)

        with pytest.raises(RuntimeError, match="upstream 503"):
            await _send(orch, m, "ping?")

        # One audit row recording the failure.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "provider_failed"
        assert audit_kwargs["subject"]["error_type"] == "RuntimeError"
        assert "upstream 503" in audit_kwargs["subject"]["error"]
        assert audit_kwargs["cost_actual_usd"] == 0.0
        # No charge on a failed call.
        m["budget"].check_and_charge.assert_not_called()
        # Working memory got the user turn but not an assistant turn.
        assert m["working"].append.await_count == 1
        # Rollback fired on the way out.
        m["session"].rollback.assert_awaited()


class TestOrchestratorAuditFailureIsLoud:
    async def test_post_success_audit_failure_propagates(self) -> None:
        orch, m = _build()
        m["audit"].append = AsyncMock(side_effect=RuntimeError("audit table missing"))

        with pytest.raises(RuntimeError, match="audit table missing"):
            await _send(orch, m, "hi")

        # The provider call still happened and the assistant turn was buffered.
        m["router"].complete.assert_awaited()
        assert m["working"].append.await_count == 2
        # Rollback fired because we propagated out of the session scope.
        m["session"].rollback.assert_awaited()


class TestOrchestratorBudgetOverrun:
    """Covers the post-success-but-over-cap branch: provider call succeeded,
    actual cost blew the per-call cap, so the work happened but the audit row
    records ``charge_result=budget_overrun`` and we don't re-raise."""

    async def test_charge_overrun_records_truthfully_and_does_not_raise(self) -> None:
        budget = _make_budget()
        budget.check_and_charge = MagicMock(
            side_effect=PerCallCapExceededError("cost $0.50 exceeds per-call cap $0.10")
        )
        orch, m = _build(budget=budget)

        reply = await _send(orch, m, "expensive request")
        assert reply == "Very good, Sir."

        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "budget_overrun"
        assert audit_kwargs["subject"]["charge_result"] == "budget_overrun"
        assert audit_kwargs["cost_actual_usd"] == pytest.approx(0.0005)
        # The episode for the assistant turn still recorded the actual cost.
        assistant_call = m["episodic"].record.await_args_list[1].kwargs
        assert assistant_call["cost_usd"] == pytest.approx(0.0005)


class TestOrchestratorPersonaPromptThreading:
    """The persona prompt's <user_context> tail carries:

    * operator_name = household operator's display_name (from cached
      ``IdentityResolverLike.get_operator()``).
    * addressed_user_name = the per-turn requesting user's display_name.
    * addressed_user_language = the per-turn requesting user's language.

    These three must come from DIFFERENT sources — the operator stays
    constant for the orchestrator's lifetime; the addressed user changes
    every turn (Discord multi-user lands in PR D2 but the wiring is here).
    """

    async def test_persona_prompt_carries_operator_and_requesting_user(self) -> None:
        operator = _StubUser(slug="bruce", display_name="Bruce", language="en-US")
        alice = _StubUser(slug="alice", display_name="Alice", language="en-GB")
        orch, m = _build(operator=operator)

        await _send(orch, m, "hello", user=alice)

        req = m["router"].complete.await_args.args[0]
        system_prompt = req.messages[0].content
        # Operator field is the household owner (Bruce), NOT the requester.
        assert "<operator_name>Bruce</operator_name>" in system_prompt
        # Addressed-user field is the requester (Alice), NOT the operator.
        assert "<addressed_user_name>Alice</addressed_user_name>" in system_prompt
        # Language is the requester's, not the operator's.
        assert "<addressed_user_language>en-GB</addressed_user_language>" in system_prompt
        # The BCP-47 imperative survives in the cacheable prefix
        # (CLAUDE.md i18n rule #2 / spec i18n-002 — losing this re-monolinguals
        # the bot silently).
        assert "BCP-47" in system_prompt


class TestOrchestratorPerUserAudit:
    """Per-row attribution: every audit + episodic write carries the
    requesting user's language and ``persona/actor_persona="alfred"``.
    CLAUDE.md i18n rule #3 + Slice-2 per-row persona attribution column
    (migration 0004) — both must be non-null on every orchestrator-written row.
    """

    async def test_audit_row_carries_user_language_and_alfred_persona(self) -> None:
        # The requesting user's language is what audit rows must reflect —
        # not the operator's — so Discord users in their own locale produce
        # locale-tagged rows even though the operator is en-US.
        alice = _StubUser(slug="alice", display_name="Alice", language="de-DE")
        orch, m = _build()

        await _send(orch, m, "Guten Morgen", user=alice)

        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["language"] == "de-DE"
        assert audit_kwargs["actor_persona"] == "alfred"
        assert audit_kwargs["actor_user_id"] == "alice"

    async def test_episodic_record_carries_user_language_and_alfred_persona(self) -> None:
        alice = _StubUser(slug="alice", display_name="Alice", language="de-DE")
        orch, m = _build()

        await _send(orch, m, "Guten Morgen", user=alice)

        assert m["episodic"].record.await_count == 2
        for call in m["episodic"].record.await_args_list:
            assert call.kwargs["language"] == "de-DE"
            assert call.kwargs["persona"] == "alfred"
            assert call.kwargs["user_id"] == "alice"


class TestOrchestratorOperatorAndRequesterSeparation:
    """The legacy slice-1 ``operator_name`` was both the orchestrator's
    household identity AND the per-turn user_id. PR-B splits these: the
    operator stays cached; the user comes in per turn.
    """

    async def test_requesting_user_threads_to_episodes_and_audit(self) -> None:
        alice = _StubUser(slug="alice", display_name="Alice", language="en-US")
        orch, m = _build()
        await _send(orch, m, "good morning", user=alice)

        # Both episodes (user + assistant) carry the REQUESTING user's slug.
        for call in m["episodic"].record.await_args_list:
            assert call.kwargs["user_id"] == "alice"

        # The success-path audit row carries the requesting user's slug.
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["actor_user_id"] == "alice"

    async def test_requesting_user_threads_on_budget_block(self) -> None:
        alice = _StubUser(slug="alice", display_name="Alice", language="en-US")
        budget = _make_budget(estimate=0.50, would_exceed=True)
        orch, m = _build(budget=budget)
        with pytest.raises(BudgetError):
            await _send(orch, m, "expensive", user=alice)
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["actor_user_id"] == "alice"
        # User-input episode also carries the requester's slug.
        assert m["episodic"].record.await_args_list[0].kwargs["user_id"] == "alice"
        # The budget pre-check itself was keyed on the requester's slug.
        m["budget"].would_exceed.assert_called_with("alice", pytest.approx(0.50))

    async def test_requesting_user_threads_on_provider_failure(self) -> None:
        alice = _StubUser(slug="alice", display_name="Alice", language="en-US")
        router = MagicMock()
        router.complete = AsyncMock(side_effect=RuntimeError("upstream"))
        orch, m = _build(router=router)
        with pytest.raises(RuntimeError):
            await _send(orch, m, "ping", user=alice)
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["actor_user_id"] == "alice"


class TestOrchestratorCancellation:
    """``asyncio.CancelledError`` is a ``BaseException``, not ``Exception``.

    CLAUDE.md hard rule #7 forbids silent cancellation: every awaited step in
    the turn (working-memory append, episodic write, pre-/post-provider
    audit, provider call itself) must produce a `cancelled` audit row, not
    only cancellation that lands inside ``_router.complete``. The top-level
    ``handle_user_message`` arm is the backstop; these tests exercise three
    points of the turn (pre-provider, provider, post-provider) to prove the
    backstop fires regardless of WHERE the cancellation lands.
    """

    async def test_user_cancellation_inside_provider_call_is_audited(self) -> None:
        router = MagicMock()
        router.complete = AsyncMock(side_effect=asyncio.CancelledError())
        orch, m = _build(router=router)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "midway-cancel")

        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "cancelled"
        assert audit_kwargs["subject"]["phase"] == "turn_cancelled"
        assert audit_kwargs["cost_actual_usd"] == 0.0
        # The cancellation audit references the requesting user, not the
        # operator (in the default fixture they happen to be the same).
        assert audit_kwargs["actor_user_id"] == "bruce"
        assert audit_kwargs["language"] == "en-US"
        # Assistant turn never buffered (provider call was cancelled).
        assert m["working"].append.await_count == 1
        # User-content txn rolled back as part of the outer BaseException arm.
        m["session"].rollback.assert_awaited()

    async def test_cancellation_before_provider_call_is_still_audited(self) -> None:
        # Cancellation lands inside ``WorkingMemory.append`` — the FIRST
        # awaited step after T2-tagging. Pre-fix this would have skipped the
        # audit (the inner provider-call arm never executed). The top-level
        # backstop now writes the cancellation row regardless.
        working = MagicMock()
        working.append = AsyncMock(side_effect=asyncio.CancelledError())
        working.turns = AsyncMock(return_value=[])
        orch, m = _build(working=working)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "cancel-before-provider")

        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "cancelled"
        assert audit_kwargs["subject"]["phase"] == "turn_cancelled"
        # Provider was never called.
        assert m["router"].complete.await_count == 0
        m["session"].rollback.assert_awaited()

    async def test_cancellation_after_provider_call_is_still_audited(self) -> None:
        # Provider succeeded; cancellation lands during the post-provider
        # episodic write (operator hit Esc between turns). The completed
        # response is discarded — the user-content txn rolls back — but the
        # audit row still lands so the cancelled turn is visible in the trail.
        from alfred.providers.base import CompletionResponse

        response = CompletionResponse(
            content="reply", tokens_in=4, tokens_out=2, cost_usd=0.0001, model="m"
        )
        router = MagicMock()
        router.complete = AsyncMock(return_value=response)
        # First episodic.record() (user turn) succeeds; second (assistant)
        # cancels. This simulates a cancellation that arrives between the
        # successful provider call and the assistant-turn persistence.
        episodic = MagicMock()
        episodic.record = AsyncMock(side_effect=[None, asyncio.CancelledError()])

        def _episodic_factory(_session: object) -> MagicMock:
            return episodic

        orch, m = _build(router=router, episodic_factory=_episodic_factory)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "cancel-after-provider")

        # Only the cancellation-audit row should have landed; the post-provider
        # success-audit never executed because cancellation interrupted first.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "cancelled"
        assert audit_kwargs["subject"]["phase"] == "turn_cancelled"
        m["session"].rollback.assert_awaited()


class TestOrchestratorSevenAuditBranches:
    """Spec §5 line 792 — the 7th audit branch.

    PR-B adds ``result="unknown_budget_user"`` as a defense-in-depth audit
    row when ``BudgetGuard`` rejects a slug the resolver should have caught
    upstream. The orchestrator discriminates on ``isinstance(exc,
    UnknownBudgetUserError)`` inside its existing ``BudgetError`` try/except
    arms — one branch for the pre-check call, one for the post-charge call —
    and re-raises so the adapter can surface a generic error to the user.
    """

    async def test_unknown_budget_user_on_pre_check_audits_and_reraises(self) -> None:
        budget = _make_budget()
        budget.would_exceed = MagicMock(
            side_effect=UnknownBudgetUserError(user_id="phantom"),
        )
        orch, m = _build(budget=budget)

        with pytest.raises(UnknownBudgetUserError):
            await _send(orch, m, "who am I")

        # Provider must NOT have been called — the rejection happened in pre-check.
        m["router"].complete.assert_not_awaited()
        # Exactly one audit row, with the 7th branch's distinctive result.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "unknown_budget_user"
        # ``phase`` tells the audit reader WHICH budget call raised — needed
        # because the two arms (pre-check vs post-charge) share the result
        # label but differ on whether the provider call already happened.
        assert audit_kwargs["subject"]["phase"] == "budget_pre_check"
        # Cost numbers stay zero: the call never went out.
        assert audit_kwargs["cost_actual_usd"] == 0.0
        # Session rolled back on the way out.
        m["session"].rollback.assert_awaited()

    async def test_unknown_budget_user_on_post_charge_audits_and_reraises(self) -> None:
        # The provider call succeeds; the post-success ``check_and_charge``
        # raises UnknownBudgetUserError. This shouldn't happen in practice
        # (the pre-check would have surfaced it first) but the orchestrator
        # still records the 7th branch so a partial-state bug never silently
        # eats the audit trail.
        budget = _make_budget()
        budget.check_and_charge = MagicMock(
            side_effect=UnknownBudgetUserError(user_id="phantom"),
        )
        orch, m = _build(budget=budget)

        with pytest.raises(UnknownBudgetUserError):
            await _send(orch, m, "expensive")

        # Provider call already happened — that's the whole reason this branch
        # exists distinctly from the pre-check one.
        m["router"].complete.assert_awaited()
        # Exactly one audit row, post-charge phase.
        assert m["audit"].append.await_count == 1
        audit_kwargs = m["audit"].append.await_args.kwargs
        assert audit_kwargs["result"] == "unknown_budget_user"
        assert audit_kwargs["subject"]["phase"] == "budget_post_charge"
        # Session rolled back on the way out.
        m["session"].rollback.assert_awaited()


class TestOrchestratorRedactsAuditSubject:
    """Provider SDK exceptions stringify with URLs / Authorization headers /
    API keys. The redactor must run over every str value in the audit subject
    so secrets never reach the audit log.
    """

    async def test_provider_failure_subject_is_redacted(self) -> None:
        router = MagicMock()
        router.complete = AsyncMock(
            side_effect=RuntimeError(
                "401 Unauthorized for https://api.example.com (Authorization: Bearer sk-LEAKED)"
            )
        )
        # Redactor that scrubs the canary string.
        orch, m = _build(
            router=router,
            redactor=lambda s: s.replace("sk-LEAKED", "[REDACTED]"),
        )

        with pytest.raises(RuntimeError):
            await _send(orch, m, "hi")

        audit_kwargs = m["audit"].append.await_args.kwargs
        assert "sk-LEAKED" not in audit_kwargs["subject"]["error"]
        assert "[REDACTED]" in audit_kwargs["subject"]["error"]


class TestOrchestratorActionDeadline:
    """Per-action deadline wraps ``handle_user_message`` body (spec §10.5).

    PR-S3-3b Task 12 wires :class:`alfred.supervisor.deadline.DeadlineWrapper`
    around the turn body. When the deadline fires:

    * ``DeadlineWrapper.run`` re-raises ``asyncio.TimeoutError`` (core-002 —
      never reclassifies a real cancel as timeout).
    * The orchestrator's new ``except asyncio.TimeoutError`` arm emits the
      ``supervisor.action_timeout`` audit row via the **autocommit** writer
      so the row survives the outer session rollback (core-003 + CR-R3 #7).
    * The orchestrator ALSO emits an ``orchestrator.turn`` ``result=cancelled``
      row via the autocommit writer (CR-R3 #7 fix) — using the session-bound
      writer would lose the row to the rollback that follows.
    * The session is rolled back and ``CancelledError`` is re-raised so
      higher-level cancellation handling stays unchanged.
    """

    async def test_timeout_emits_supervisor_action_timeout_via_autocommit(self) -> None:
        """The supervisor.action_timeout row lands on the autocommit writer.

        Asserts the row CARRIES the subject keys spec §10.5 / migration 0007
        requires: ``user_id``, ``deadline_seconds``, ``phase_at_timeout``,
        ``action_duration_seconds``, ``correlation_id``. The row also has
        ``result="cancelled"`` per migration 0007.
        """
        # Slow router → the deadline fires before the provider returns.
        router = MagicMock()

        async def _slow_complete(*_args: Any, **_kwargs: Any) -> Any:
            await asyncio.sleep(10)
            return None  # pragma: no cover — deadline fires first

        router.complete = AsyncMock(side_effect=_slow_complete)
        orch, m = _build(router=router, deadline_seconds=0.001)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "deadline-fires")

        # Both timeout-path rows landed on the AUTOCOMMIT writer, never the
        # session-bound one (CR-R3 #7).
        autocommit_events = [
            call.kwargs["event"] for call in m["autocommit_audit"].append.await_args_list
        ]
        assert "supervisor.action_timeout" in autocommit_events
        assert "orchestrator.turn" in autocommit_events
        # The session-bound writer is NOT used for the timeout rows.
        for call in m["audit"].append.await_args_list:
            assert call.kwargs.get("event") != "supervisor.action_timeout"

        # Inspect the supervisor.action_timeout row in detail.
        timeout_call = next(
            call
            for call in m["autocommit_audit"].append.await_args_list
            if call.kwargs.get("event") == "supervisor.action_timeout"
        )
        timeout_kwargs = timeout_call.kwargs
        assert timeout_kwargs["result"] == "cancelled"
        assert timeout_kwargs["actor_user_id"] == "bruce"
        assert timeout_kwargs["actor_persona"] == "supervisor"
        assert timeout_kwargs["trust_tier_of_trigger"] == "T0"
        subject = timeout_kwargs["subject"]
        assert subject["user_id"] == "bruce"
        assert subject["deadline_seconds"] == 0.001
        # phase_at_timeout is a best-effort label; "unknown" is the Slice 3 default
        # (Slice 4+ refines this via the OTel span hierarchy).
        assert subject["phase_at_timeout"] == "unknown"
        assert subject["correlation_id"] is not None

    async def test_timeout_emits_orchestrator_turn_cancelled_via_autocommit(self) -> None:
        """The orchestrator.turn cancellation row also goes to the autocommit writer.

        CR-R3 #7: emitting this row via the session-bound writer would lose it
        when the parent session rolls back. Using the autocommit writer ensures
        the row commits independently of the outer rollback.
        """
        router = MagicMock()

        async def _slow_complete(*_args: Any, **_kwargs: Any) -> Any:
            await asyncio.sleep(10)
            return None  # pragma: no cover — deadline fires first

        router.complete = AsyncMock(side_effect=_slow_complete)
        orch, m = _build(router=router, deadline_seconds=0.001)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "deadline-fires")

        # The orchestrator.turn cancellation row sits on the autocommit writer,
        # NOT on the session-bound one — the session-bound writer would lose
        # the row to the session.rollback that follows the timeout arm.
        turn_calls = [
            call
            for call in m["autocommit_audit"].append.await_args_list
            if call.kwargs.get("event") == "orchestrator.turn"
        ]
        assert len(turn_calls) == 1
        kwargs = turn_calls[0].kwargs
        assert kwargs["result"] == "cancelled"
        assert kwargs["subject"]["phase"] == "turn_timeout"
        assert kwargs["actor_user_id"] == "bruce"
        # No orchestrator.turn cancellation row on the session-bound writer.
        for call in m["audit"].append.await_args_list:
            if call.kwargs.get("event") == "orchestrator.turn":
                assert call.kwargs.get("result") != "cancelled"

    async def test_timeout_rolls_back_user_content_session(self) -> None:
        """The outer session.rollback() is called when the deadline fires."""
        router = MagicMock()

        async def _slow_complete(*_args: Any, **_kwargs: Any) -> Any:
            await asyncio.sleep(10)
            return None  # pragma: no cover — deadline fires first

        router.complete = AsyncMock(side_effect=_slow_complete)
        orch, m = _build(router=router, deadline_seconds=0.001)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "deadline-fires")

        m["session"].rollback.assert_awaited()

    async def test_timeout_reraises_cancelled_error_not_timeout(self) -> None:
        """The orchestrator re-raises CancelledError after the timeout.

        Spec §10.5 + plan §1453: the timeout path normalises onto the existing
        cancellation contract so higher-level callers (the TUI, the adapter
        loop) only have to handle one cancel-shaped propagation.
        """
        router = MagicMock()

        async def _slow_complete(*_args: Any, **_kwargs: Any) -> Any:
            await asyncio.sleep(10)
            return None  # pragma: no cover — deadline fires first

        router.complete = AsyncMock(side_effect=_slow_complete)
        orch, m = _build(router=router, deadline_seconds=0.001)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "deadline-fires")

    async def test_no_timeout_path_under_normal_completion(self) -> None:
        """A normal-speed turn never emits supervisor.action_timeout.

        Default deadline is 30s; a router that returns immediately must NOT
        produce a timeout row even if the autocommit writer would accept one.
        """
        orch, m = _build()  # default deadline_seconds=30.0

        reply = await _send(orch, m, "hi")
        assert reply == "Very good, Sir."

        # No autocommit-writer audit calls at all on the happy path — the
        # only writes go to the session-bound writer.
        assert m["autocommit_audit"].append.await_count == 0

    async def test_external_cancellation_uses_session_bound_writer(self) -> None:
        """A non-timeout CancelledError still uses the session-bound writer.

        Pre-PR-S3-3b cancellation contract: operator-cancel mid-turn writes
        the orchestrator.turn ``result=cancelled`` row via the session-bound
        writer. The session is then rolled back — the row is intentionally
        tied to the rolled-back work (the user did NOT consent to a
        committed turn).

        This test pins that the new timeout-path autocommit writer does NOT
        accidentally absorb the existing non-timeout cancellation arm.
        """
        router = MagicMock()
        router.complete = AsyncMock(side_effect=asyncio.CancelledError())
        orch, m = _build(router=router)  # default 30s deadline; cancel is external

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "external-cancel")

        # The non-timeout cancellation row is on the SESSION-BOUND writer (pre-PR-S3-3b).
        # Autocommit writer is not touched.
        assert m["autocommit_audit"].append.await_count == 0
        # Session-bound writer recorded the cancellation row.
        cancel_calls = [
            call
            for call in m["audit"].append.await_args_list
            if call.kwargs.get("result") == "cancelled"
            and call.kwargs.get("subject", {}).get("phase") == "turn_cancelled"
        ]
        assert len(cancel_calls) == 1


class TestOrchestratorActionDurationHistogram:
    """``alfred_orchestrator_action_duration_seconds`` emission (spec §7a.3).

    PR-S3-3b Tasks 13 + 14 wire
    :func:`alfred.supervisor.observability.record_action_duration` into the
    orchestrator action path. The histogram observation lands on three
    outcomes:

    * ``success`` — fired after the provider response is audited and the
      reply is about to return.
    * ``timeout`` — fired from inside ``_emit_supervisor_timeout_row`` so
      the histogram observation is bound to the same correlation as the
      ``supervisor.action_timeout`` audit row.
    * ``cancelled`` — fired from the session-bound cancellation arm so an
      operator-initiated cancel still contributes to the per-user p99.

    ``user_id`` is the raw slug; the observability module buckets it
    internally (perf-001). ``breaker_state="UNKNOWN"`` is the Slice-3
    default until Task 17's :class:`Supervisor` wires real breaker state
    into the orchestrator (PR-S3-4+ scope).
    """

    async def test_success_path_records_duration(self, monkeypatch: Any) -> None:
        """Happy-path turn observes one ``success`` outcome with the raw user_id."""
        recorder = MagicMock()
        monkeypatch.setattr(
            "alfred.orchestrator.core.record_action_duration",
            recorder,
        )

        orch, m = _build()
        reply = await _send(orch, m, "good morning")
        assert reply == "Very good, Sir."

        recorder.assert_called_once()
        kwargs = recorder.call_args.kwargs
        assert kwargs["user_id"] == "bruce"  # raw slug — bucketing happens inside
        assert kwargs["action_outcome"] == "success"
        assert kwargs["breaker_state"] == "UNKNOWN"
        # Sanity: duration is non-negative real number.
        assert isinstance(kwargs["duration_seconds"], float)
        assert kwargs["duration_seconds"] >= 0.0

    async def test_timeout_path_records_duration(self, monkeypatch: Any) -> None:
        """Deadline-fired turn observes one ``timeout`` outcome."""
        recorder = MagicMock()
        monkeypatch.setattr(
            "alfred.orchestrator.core.record_action_duration",
            recorder,
        )

        router = MagicMock()

        async def _slow_complete(*_args: Any, **_kwargs: Any) -> Any:
            await asyncio.sleep(10)
            return None  # pragma: no cover — deadline fires first

        router.complete = AsyncMock(side_effect=_slow_complete)
        orch, m = _build(router=router, deadline_seconds=0.001)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "deadline-fires")

        # Exactly one observation; outcome is "timeout" with the raw user_id.
        recorder.assert_called_once()
        kwargs = recorder.call_args.kwargs
        assert kwargs["user_id"] == "bruce"
        assert kwargs["action_outcome"] == "timeout"
        assert kwargs["breaker_state"] == "UNKNOWN"
        # The observed duration is bounded by the wall-clock that elapsed
        # between handle_user_message entry and the timeout — it must be
        # >= the configured deadline (sub-millisecond) and < the test's
        # generous upper bound.
        assert kwargs["duration_seconds"] >= 0.0
        assert kwargs["duration_seconds"] < 5.0

    async def test_external_cancellation_records_duration(self, monkeypatch: Any) -> None:
        """Operator-cancelled turn observes one ``cancelled`` outcome.

        Distinct from the timeout path: this is a CancelledError raised by
        the provider call mid-turn (operator interrupt), not the deadline
        wrapper firing. The histogram contract pins both outcomes so
        per-user p99 captures every action regardless of how it ended.
        """
        recorder = MagicMock()
        monkeypatch.setattr(
            "alfred.orchestrator.core.record_action_duration",
            recorder,
        )

        router = MagicMock()
        router.complete = AsyncMock(side_effect=asyncio.CancelledError())
        orch, m = _build(router=router)

        with pytest.raises(asyncio.CancelledError):
            await _send(orch, m, "external-cancel")

        recorder.assert_called_once()
        kwargs = recorder.call_args.kwargs
        assert kwargs["user_id"] == "bruce"
        assert kwargs["action_outcome"] == "cancelled"
        assert kwargs["breaker_state"] == "UNKNOWN"
