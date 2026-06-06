"""Slice-2 UAT layer: TUI end-to-end smoke test.

Drives the real :class:`AlfredTuiApp` (Textual) through its in-process
test harness (``app.run_test()`` + ``Pilot``) against a real Postgres
testcontainer, the real :class:`Orchestrator`, the real
:class:`WorkingMemoryPool`, the real :class:`BudgetGuard`, the real
:class:`IdentityResolver`. A mock provider router stands in for the LLM
on the mock-provider tests; a real DeepSeek call runs only when
``ALFRED_SMOKE_PROVIDER_KEY`` is set.

Spike outcome (Step 1b.1)
-------------------------

Textual's built-in headless test harness (``app.run_test()`` +
``Pilot``) is used directly. The existing TUI unit tests in
``tests/unit/comms/test_tui.py`` already prove the harness can:

* Submit input by ``press("a", "b", "enter")``.
* Read the visible RichLog buffer via ``app.query_one("#conversation_log").lines``.
* Observe the ContextVar-scoped ``t()`` substitution path — the harness
  shares the test's event loop (and therefore its ContextVar context),
  so ``set_language()`` calls made in the test propagate into the TUI
  widget's ``t()``-routed renders.

That spike outcome rules out ``pexpect``: in-process is faster
(no PTY round-trip), deterministic (no terminal-size flake), and gives
us direct read access to the orchestrator + budget + WM pool for
assertion. ``pexpect`` is kept on the table only if a future test
needs to observe terminal-control-sequence rendering specifically;
none of the Slice-2 UAT assertions do.

Three test functions
--------------------

1. ``test_tui_mock_provider_round_trip`` — drives one operator turn
   through the TUI; asserts the response renders, an ``episodes`` row
   pair lands, an ``audit_log`` row carries the PR-B seven-branch
   shape, and the operator's per-user ``BudgetGuard._spent`` advanced.

2. ``test_tui_real_provider_round_trip`` — gated by
   ``ALFRED_SMOKE_PROVIDER_KEY``. Boots the same harness against the
   real DeepSeek provider; sends the deterministic prompt "respond
   with exactly the word OK and nothing else"; asserts ``"OK"`` is in
   the rendered response and the audit row's ``model=`` is the real
   provider model (not a mock sentinel).

3. ``test_tui_rehydrate_cadence_across_invocations`` — drives two
   consecutive in-process TUI sessions against the SAME testcontainer
   Postgres. Invocation 1 says ``"remember the word artichoke"``;
   invocation 2 (a fresh AlfredTuiApp + fresh WorkingMemoryPool, same
   DB) asks ``"what word did i ask you to remember?"``. The mock
   provider in invocation 2 inspects the messages list it receives:
   the slice-1 rehydrate cadence (PR-B's :meth:`WorkingMemoryPool._rehydrate`)
   must have populated the WM from episodic *before* the orchestrator
   dispatched the second turn, so the messages list MUST contain the
   prior turn's content. This is the load-bearing assertion: if the
   pool's lazy-rehydrate regresses, this test fails loud.

CLAUDE.md hard-rule alignment
-----------------------------

* No real LLM calls except when ``ALFRED_SMOKE_PROVIDER_KEY`` is set.
* Mock router never returns secrets (uses the literal "OK" or a tag
  with the rehydrated content). DLP scan still runs but has nothing
  to redact.
* Skip-vs-pass discipline: missing env var → SKIPPED, never PASSED.
* Test owns its testcontainer lifecycle — never touches a live DB.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker
from testcontainers.postgres import PostgresContainer
from textual.widgets import Input

from alfred.budget.guard import BudgetGuard
from alfred.comms.tui import AlfredTuiApp
from alfred.identity import (
    IdentityResolver,
    IdentityVersionCounter,
    NullRateLimiter,
    Platform,
)
from alfred.identity.models import User
from alfred.memory.episodic import EpisodicMemory
from alfred.memory.models import AuditEntry, Episode
from alfred.memory.working_pool import WorkingMemoryPool
from alfred.orchestrator.core import Orchestrator
from alfred.providers.base import CompletionResponse

_PROVIDER_KEY_ENV = "ALFRED_SMOKE_PROVIDER_KEY"
_DETERMINISTIC_PROMPT = "respond with exactly the word OK and nothing else"

# Minimum plausible API key length. DeepSeek keys are ~35 chars, Anthropic
# ~80 chars; anything shorter is structurally a placeholder. Keeps the
# real-provider smoke from running with a stub secret and emitting a
# misleading 401 (#184 item 4 — the repo secret was set to a literal
# "placeholder" string and CI surfaced the 401 as a hard fail).
_MIN_PROVIDER_KEY_LEN = 20
# Substrings that mark a value as a stub even when it is long enough to
# pass the length check. Lower-cased before comparison so authors don't
# have to remember the exact casing they used.
_PLACEHOLDER_MARKERS = ("placeholder", "todo", "fixme", "not-a-real", "stub", "xxxxx")


def _is_placeholder_provider_key(value: str | None) -> bool:
    """True for unset / blank / placeholder-shaped values.

    Anchored deliberately at the env-read boundary so the skip reason
    distinguishes "unset" from "set to a stub" — the operator who set
    the stub deserves a hint that the key is the reason the test isn't
    actually running.
    """
    if value is None:
        return True
    stripped = value.strip()
    if not stripped or len(stripped) < _MIN_PROVIDER_KEY_LEN:
        return True
    lowered = stripped.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


# ---------------------------------------------------------------------------
# Shared fixtures (testcontainer Postgres + dep-graph builder)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _pg_stack(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[_Stack]:
    """Boot a Postgres testcontainer, run alembic, and yield a wired stack.

    Mirrors ``test_hello_alfred.py`` end-to-end so the assertions about
    persisted shape are made against the same migration set production
    runs. The single difference: the TUI smoke shares one container
    across two consecutive in-process sessions (for the rehydrate
    cadence test), so the container lifecycle is hoisted into a context
    manager rather than ``with PostgresContainer(...)`` inside each
    test body.
    """
    with PostgresContainer("postgres:16") as pg:
        async_url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        monkeypatch.setenv("ALFRED_DATABASE_URL", async_url)
        # Only seed the placeholder when the caller hasn't already supplied
        # a real key (the real-provider test sets ALFRED_DEEPSEEK_API_KEY
        # before entering this fixture and would otherwise have its key
        # clobbered by the placeholder, masking real auth failures).
        if not os.environ.get("ALFRED_DEEPSEEK_API_KEY"):
            monkeypatch.setenv(
                "ALFRED_DEEPSEEK_API_KEY",
                "not-a-real-secret-smoke-test-placeholder",
            )

        alembic_cfg = Config("alembic.ini")
        await asyncio.to_thread(command.upgrade, alembic_cfg, "head")

        engine = create_async_engine(async_url, future=True)
        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        sync_url = async_url.replace("+asyncpg", "+psycopg")
        sync_engine = create_engine(sync_url, future=True)
        sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)

        try:
            yield _Stack(
                async_url=async_url,
                sync_factory=sync_factory,
                session_scope=session_scope,
                async_session_factory=sm,
            )
        finally:
            sync_engine.dispose()
            await engine.dispose()


@dataclass(frozen=True, slots=True)
class _Stack:
    """Bundle of wired Postgres-backed primitives shared across two sessions.

    Holds the things both TUI invocations need (session factories, the
    async/sync engines for lifecycle) so the rehydrate cadence test can
    create two AlfredTuiApp + Orchestrator stacks against the SAME DB
    without re-running migrations.

    Frozen so the rehydrate test can't accidentally swap one engine for
    another mid-test and silently de-couple the two invocations.
    """

    async_url: str
    sync_factory: Callable[..., Session]
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]]
    async_session_factory: async_sessionmaker[AsyncSession]


def _build_session_app(
    stack: _Stack,
    *,
    router: object,
) -> tuple[AlfredTuiApp, IdentityResolver, BudgetGuard, WorkingMemoryPool, User]:
    """Wire the full slice-2 dep graph against ``stack`` and return the TUI.

    Returns ``(app, resolver, budget, working_pool, operator)``. Each
    invocation gets its own resolver + budget + pool (mirrors the
    real process-per-`alfred chat` lifecycle); the stack-shared bits
    (DB session factories) are reused so episodic rows from session 1
    are visible to session 2's rehydrate.
    """
    version_counter = IdentityVersionCounter()
    resolver = IdentityResolver(
        session_factory=stack.sync_factory,
        version_counter=version_counter,
        rate_limiter=NullRateLimiter(),
    )
    operator = resolver.resolve(Platform.TUI, "operator")
    assert operator is not None, "migration 0004 must backfill the operator binding"

    budget = BudgetGuard(
        user_loader=lambda user_id: resolver.show(slug=user_id),
        per_call_max_usd=0.10,
        version_counter=version_counter,
    )

    working_pool = WorkingMemoryPool(
        episodic_factory=lambda session: EpisodicMemory(session=session),
        pool_session_scope=stack.session_scope,
        active_user_count=lambda: 1,
    )

    orchestrator = Orchestrator(
        identity_resolver=resolver,
        session_scope=stack.session_scope,
        router=router,
        budget=budget,
    )
    app = AlfredTuiApp(
        orchestrator=orchestrator,
        identity_resolver=resolver,
        working_pool=working_pool,
    )
    return app, resolver, budget, working_pool, operator


def _rendered(app: AlfredTuiApp) -> str:
    """Stringify the visible RichLog buffer.

    Matches the convention in ``tests/unit/comms/test_tui.py`` — Textual's
    ``RichLog.lines`` holds ``Strip`` objects whose ``__str__`` renders
    the visible text. Joining with newlines mirrors what the operator
    sees on the terminal.
    """
    log = app.query_one("#conversation_log")
    return "\n".join(str(line) for line in log.lines)


async def _drive_turn(app: AlfredTuiApp, text: str) -> None:
    """Submit ``text`` through the TUI and pump until the response renders.

    The Textual harness defaults focus to the first focusable widget
    in the compose tree (the RichLog), so an explicit ``Input.focus()``
    is required before keystrokes — same pattern as the unit tests.
    Two pauses cover dispatch + repaint after ``await``.
    """
    app.query_one("#user_input", Input).focus()
    # ``Input.insert_text_at_cursor`` would also work but emitting the
    # keystrokes through the pilot exercises the real input handler.
    pilot = app._test_pilot  # type: ignore[attr-defined]
    # Type the text one character at a time then submit. Pilot's ``press``
    # accepts a tuple of keys; a single multi-char string is treated as
    # one key by Textual, which fails for multi-char strings.
    keys = [*list(text), "enter"]
    await pilot.press(*keys)
    # Pump enough cycles for on_input_submitted to dispatch, the
    # orchestrator to round-trip, and the response line to repaint.
    # If ``_in_flight`` never clears (orchestrator hang / provider
    # timeout), fail loudly rather than silently dropping into stale
    # assertions downstream.
    max_pumps = 20
    for _ in range(max_pumps):
        await pilot.pause()
        if app._in_flight is None:
            break
    else:
        pytest.fail(
            f"TUI turn did not complete within {max_pumps} pump cycles; "
            "orchestrator hang or provider timeout — downstream assertions "
            "would run on stale state."
        )


# ---------------------------------------------------------------------------
# Test 1 — mock-provider e2e (runs unconditionally)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
async def test_tui_mock_provider_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    """One full TUI turn against a mock provider + real Postgres.

    Asserts the four PR-B persistence invariants (episode pair, audit
    row with seven-branch shape, language tag, per-user budget moved)
    via the operator-visible TUI surface. This is the unconditional
    smoke that runs on every PR, never gated.
    """
    async with _pg_stack(monkeypatch) as stack:
        router = MagicMock()
        router.complete = AsyncMock(
            return_value=CompletionResponse(
                content="Good evening, operator.",
                tokens_in=12,
                tokens_out=5,
                cost_usd=0.00001,
                model="mock-provider",
            )
        )
        app, _resolver, budget, _pool, operator = _build_session_app(stack, router=router)

        async with app.run_test() as pilot:
            # Stash the pilot on the app so ``_drive_turn`` can pump it
            # without needing it threaded through every helper.
            app._test_pilot = pilot  # type: ignore[attr-defined]
            await _drive_turn(app, "hi alfred")
            rendered = _rendered(app)
            assert "Good evening, operator." in rendered, (
                f"expected mock-provider response on the TUI; got {rendered!r}"
            )

        # PR-B persistence invariants: pair of episodes + one audit row.
        async with stack.async_session_factory() as session:
            ep_rows = (await session.execute(select(Episode))).scalars().all()
            assert len(ep_rows) == 2, "expected user + assistant episodes"
            assert {r.role for r in ep_rows} == {"user", "assistant"}
            assert all(ep.language == operator.language for ep in ep_rows)
            assert all(ep.user_id == operator.slug for ep in ep_rows)
            assert all(ep.persona_id == "alfred" for ep in ep_rows)

            audit_rows = (await session.execute(select(AuditEntry))).scalars().all()
            assert len(audit_rows) == 1
            entry = audit_rows[0]
            assert entry.event == "orchestrator.turn"
            assert entry.actor_user_id == operator.slug
            assert entry.language == operator.language
            assert entry.actor_persona == "alfred"
            assert entry.persona_id == "alfred"
            assert entry.trust_tier_of_trigger == "T2"
            assert entry.result == "success"

        # Per-user budget moved (PR-B Phase 1). Mock cost was 0.00001.
        spent = budget.spent_today(operator.slug)
        assert spent > 0, f"BudgetGuard._spent[{operator.slug}] did not move; got {spent!r}"


# ---------------------------------------------------------------------------
# Test 2 — real-provider e2e (gated by ALFRED_SMOKE_PROVIDER_KEY)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.skipif(
    _is_placeholder_provider_key(os.getenv(_PROVIDER_KEY_ENV)),
    reason=(
        f"{_PROVIDER_KEY_ENV} is unset or placeholder-shaped; this smoke "
        "targets a real DeepSeek (or Anthropic fallback) provider and is "
        "skipped on fork PRs, unconfigured local boxes, and CI environments "
        "where the repo secret is a stub value (set to e.g. 'placeholder' "
        "while a real throwaway key is provisioned)."
    ),
)
async def test_tui_real_provider_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    """One full TUI turn against the real provider with a deterministic prompt.

    Sends the prompt "respond with exactly the word OK and nothing
    else" so the assertion is provider-version-stable. Asserts that
    the rendered response contains ``"OK"`` and the audit row carries
    the real model id (not the mock sentinel).
    """
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", os.environ[_PROVIDER_KEY_ENV])
    async with _pg_stack(monkeypatch) as stack:
        # Build the real router via the bootstrap helper so the model
        # selection + provider construction matches production verbatim.
        # Local import keeps the heavy provider modules off the
        # collection-time path for the unconditional mock-provider test.
        from alfred.cli._bootstrap import build_broker, build_router
        from alfred.config.settings import Settings

        settings = Settings()  # type: ignore[call-arg]  # reads env populated above
        broker = build_broker(settings)
        router = build_router(broker, settings)

        app, _resolver, _budget, _pool, operator = _build_session_app(stack, router=router)

        async with app.run_test() as pilot:
            app._test_pilot = pilot  # type: ignore[attr-defined]
            await _drive_turn(app, _DETERMINISTIC_PROMPT)
            rendered = _rendered(app)
            assert "OK" in rendered, (
                f"expected real-provider response to contain 'OK'; got {rendered!r}"
            )

        async with stack.async_session_factory() as session:
            audit_rows = (await session.execute(select(AuditEntry))).scalars().all()
            assert len(audit_rows) == 1
            entry = audit_rows[0]
            assert entry.event == "orchestrator.turn"
            assert entry.actor_user_id == operator.slug
            # Real provider audit row must NOT carry the mock sentinel.
            # The orchestrator stores the provider model under the audit
            # row's ``subject["model"]`` (JSON column) — assert it's
            # something other than the placeholder we'd use for mocks.
            model = entry.subject.get("model") if isinstance(entry.subject, dict) else None
            assert isinstance(model, str) and model, (
                f"expected a model string on the audit row's subject; got {entry.subject!r}"
            )
            assert "mock" not in model.lower(), (
                f"expected real provider model on the audit row; got {model!r}"
            )


# ---------------------------------------------------------------------------
# Test 3 — slice-1 rehydrate cadence (load-bearing UAT signal)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
async def test_tui_rehydrate_cadence_across_invocations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two consecutive TUI sessions share episodic state via the rehydrate path.

    PR-B's :class:`WorkingMemoryPool` lazy-rehydrate is what makes the
    second turn's provider see the first turn's content even after the
    process-level WM pool was thrown away. We exercise this by:

    1. Booting a fresh AlfredTuiApp against the testcontainer; saying
       "remember the word artichoke"; letting the mock router echo a
       trivial response. The first turn writes a user + assistant
       episode pair.
    2. Tearing down the app (and its pool); booting a SECOND
       AlfredTuiApp against the SAME testcontainer with a fresh pool;
       saying "what word did i ask you to remember?". The mock router
       in this invocation inspects its received messages list and
       records what it saw. The assertion: the messages list contains
       "artichoke" (sourced from the rehydrated WM, NOT from the
       current turn's user input).

    If the lazy-rehydrate regresses (e.g. pool returns an empty WM,
    or skips the episodic read), the second invocation's mock will
    not see "artichoke" in its messages and this test fails loud.
    """
    async with _pg_stack(monkeypatch) as stack:
        # ---- Invocation 1: write the memory anchor ---------------------
        router_1 = MagicMock()
        router_1.complete = AsyncMock(
            return_value=CompletionResponse(
                content="Noted; remembering 'artichoke'.",
                tokens_in=8,
                tokens_out=4,
                cost_usd=0.00001,
                model="mock-provider",
            )
        )
        app_1, _r1, _b1, _p1, operator = _build_session_app(stack, router=router_1)
        async with app_1.run_test() as pilot:
            app_1._test_pilot = pilot  # type: ignore[attr-defined]
            await _drive_turn(app_1, "remember the word artichoke")

        # Verify the first invocation persisted: two episodes (user +
        # assistant) for the operator's persona pair. Without these,
        # the rehydrate in invocation 2 has nothing to find.
        async with stack.async_session_factory() as session:
            ep_rows = (await session.execute(select(Episode))).scalars().all()
            assert len(ep_rows) == 2, (
                f"invocation 1 must persist user+assistant episodes; got {len(ep_rows)}"
            )
            user_contents = [r.content for r in ep_rows if r.role == "user"]
            assert any("artichoke" in c for c in user_contents), (
                f"expected 'artichoke' in persisted user episode; got {user_contents!r}"
            )

        # ---- Invocation 2: capture the rehydrated messages -----------
        captured_messages: list[object] = []

        async def capture_then_respond(request: object) -> CompletionResponse:
            """Record the messages list, then return a deterministic answer.

            The router's ``complete`` is what the orchestrator hands the
            assembled messages to; capturing here gives us a direct view
            of what the WM-driven prompt assembly produced for the second
            invocation. If the rehydrate fired, the prior user turn ("...
            artichoke ...") MUST be in this list.
            """
            # Defensive: surface a clear failure if the router request shape
            # ever drifts (e.g. dict, renamed attribute) rather than letting a
            # bare `AttributeError` swallow the diagnosis.
            assert hasattr(request, "messages"), (
                "router request shape changed — expected `.messages` attribute; "
                "update this test to match the new router contract"
            )
            captured_messages.append(request.messages)
            return CompletionResponse(
                content="The word was artichoke.",
                tokens_in=12,
                tokens_out=6,
                cost_usd=0.00001,
                model="mock-provider",
            )

        router_2 = MagicMock()
        router_2.complete = AsyncMock(side_effect=capture_then_respond)
        app_2, _r2, _b2, _p2, _op2 = _build_session_app(stack, router=router_2)

        async with app_2.run_test() as pilot:
            app_2._test_pilot = pilot  # type: ignore[attr-defined]
            await _drive_turn(app_2, "what word did i ask you to remember?")

        # The captured messages from invocation 2's only provider call.
        assert len(captured_messages) == 1, (
            f"expected exactly one provider call in invocation 2; got {len(captured_messages)}"
        )
        messages = captured_messages[0]
        # Stringify everything (Message objects are dataclass-ish; the
        # exact shape is provider-router-internal). The load-bearing
        # assertion is that "artichoke" survives from invocation 1 into
        # invocation 2's prompt — which only happens via the
        # WorkingMemoryPool lazy-rehydrate path.
        joined = "\n".join(str(m) for m in messages)
        assert "artichoke" in joined, (
            "lazy-rehydrate regression: invocation 2's provider prompt did NOT "
            f"contain 'artichoke' from invocation 1's persisted episode. "
            f"Messages: {joined!r}"
        )

        # Sanity: the operator's audit log now has two rows (one per
        # invocation). Confirms each invocation rendered an end-to-end
        # turn via the persistence path, not just an in-memory echo.
        async with stack.async_session_factory() as session:
            audit_rows = (await session.execute(select(AuditEntry))).scalars().all()
            assert len(audit_rows) == 2, (
                f"expected two audit rows across two invocations; got {len(audit_rows)}"
            )
            assert all(r.actor_user_id == operator.slug for r in audit_rows)
