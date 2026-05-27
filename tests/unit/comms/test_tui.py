"""Tests for the Slice-1/2 Textual TUI.

Spec: docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md (Task 14)
+ PR-B Phase 5 plan (Task 13/14) — the TUI now tags input as T2 at the
adapter boundary, acquires + releases a pooled :class:`WorkingMemory` per
turn, and dispatches the orchestrator with the kwargs-only contract.

Test fixtures
-------------
* ``_FakeUser`` is a frozen dataclass that satisfies the orchestrator's
  ``UserLike`` Protocol structurally (the orchestrator reads ``slug``,
  ``display_name``, ``language``). Frozen so a test can never accidentally
  mutate identity mid-turn.
* The identity-resolver double exposes the single method the TUI calls
  (``get_operator``). Sync — matches the resolver's real surface.
* The pool double's ``acquire`` returns a fresh :class:`WorkingMemory` and
  ``release`` is a no-op AsyncMock. Tests assert acquire/release symmetry
  so a future ``finally``-block regression is caught here.

Original notes (PR #89 cover-the-branches sweep):
  * (#5) RichLog read-back: installed Textual (8.2.7) has ``RichLog.render()``
    but it does not return the user-visible buffer; the writes live on
    ``RichLog.lines`` as ``Strip`` objects whose ``__str__`` renders to text.
    We stringify the strips for the assertion.
  * The original happy-path test left four branches of ``on_input_submitted``
    uncovered (Esc cancel, provider timeout, provider exception, second-
    submit-while-busy). Those four are added here. Each test mirrors the
    happy-path's pattern of explicitly focusing the Input widget before
    keystrokes — Textual 8.x defaults focus to the first focusable widget in
    the compose tree (the RichLog), not the Input, so keystrokes silently
    scroll the log without the explicit focus.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest import MonkeyPatch
from textual.widgets import Input

from alfred.comms.tui import AlfredTuiApp
from alfred.memory.working import WorkingMemory
from alfred.security.tiers import T2, TaggedContent


@dataclass(frozen=True, slots=True)
class _FakeUser:
    """Minimal value object satisfying the orchestrator's ``UserLike`` Protocol.

    Frozen so a test that mutates ``slug`` would surface as a hard error
    rather than as a silent mid-test identity swap.
    """

    slug: str = "operator"
    display_name: str = "Operator"
    language: str = "en-US"


def _build_doubles(orch_response: Any) -> tuple[AsyncMock, MagicMock, MagicMock, _FakeUser]:
    """Construct the four collaborators every TUI test needs.

    Returns ``(orch, resolver, pool, user)``. The pool's ``acquire`` returns
    a real :class:`WorkingMemory` instance — using a MagicMock there would
    accept any kwargs and hide a future signature drift. ``release`` stays
    an AsyncMock so tests can assert it was awaited.
    """
    user = _FakeUser()
    resolver = MagicMock()
    resolver.get_operator = MagicMock(return_value=user)
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=WorkingMemory())
    pool.release = AsyncMock(return_value=None)
    orch = AsyncMock()
    # ``side_effect`` covers both raised exceptions and gated async functions;
    # plain return values still go through ``return_value`` so the AsyncMock
    # awaits cleanly.
    if isinstance(orch_response, BaseException) or callable(orch_response):
        orch.handle_user_message = AsyncMock(side_effect=orch_response)
    else:
        orch.handle_user_message = AsyncMock(return_value=orch_response)
    return orch, resolver, pool, user


def _rendered(app: AlfredTuiApp) -> str:
    """Stringify the visible RichLog buffer for assertion."""
    log = app.query_one("#conversation_log")
    return "\n".join(str(line) for line in log.lines)


def _assert_dispatched_once(
    orch: AsyncMock,
    *,
    user: _FakeUser,
    expected_text: str,
) -> None:
    """Verify the orchestrator was called once with the PR-B kwargs contract.

    Asserting the kwargs individually (rather than passing the whole
    TaggedContent through ``assert_awaited_once_with``) means the test
    doesn't have to reconstruct the exact ``TaggedContent`` instance the
    TUI built — which would couple the test to ``tag()``'s internal
    metadata defaults. We assert the four invariants instead:

    * called exactly once
    * ``user=`` is the resolved operator
    * ``content`` is a TaggedContent[T2] wrapping the original text with
      ``source="comms.tui.input"`` (the adapter-boundary provenance)
    * ``working_memory`` is a real WorkingMemory instance (not a mock)
    """
    assert orch.handle_user_message.await_count == 1
    call = orch.handle_user_message.await_args
    assert call is not None
    assert call.kwargs["user"] is user
    content = call.kwargs["content"]
    assert isinstance(content, TaggedContent)
    assert content.tier is T2
    assert content.content == expected_text
    assert content.source == "comms.tui.input"
    assert isinstance(call.kwargs["working_memory"], WorkingMemory)


@pytest.mark.asyncio
async def test_user_submission_dispatches_to_orchestrator_and_displays_response() -> None:
    orch, resolver, pool, user = _build_doubles(orch_response="Good evening, operator.")
    app = AlfredTuiApp(orchestrator=orch, identity_resolver=resolver, working_pool=pool)
    async with app.run_test() as pilot:
        # Textual 8.x sends keystrokes to whichever widget holds focus, and
        # the default focus on mount falls on the first focusable widget in
        # the compose tree (the RichLog), not the Input. Slice-1 lives with
        # that; the CLI wiring gives the Input explicit initial focus. The
        # test mimics that here.
        app.query_one("#user_input", Input).focus()
        await pilot.pause()
        await pilot.press("h", "i")
        await pilot.press("enter")
        # Two pauses: one to dispatch on_input_submitted, one to let the
        # await asyncio.wait_for(...) on the AsyncMock complete + repaint.
        await pilot.pause()
        await pilot.pause()
        rendered = _rendered(app)
        assert "Good evening" in rendered
        _assert_dispatched_once(orch, user=user, expected_text="hi")
        # Pool acquire/release symmetry: one acquire, one release, both
        # keyed on (persona, slug). A regression in the finally-block
        # would surface as release.await_count == 0.
        pool.acquire.assert_awaited_once_with(("alfred", user.slug))
        assert pool.release.await_count == 1
        release_call = pool.release.await_args
        assert release_call is not None
        assert release_call.args[0] == ("alfred", user.slug)
        assert isinstance(release_call.args[1], WorkingMemory)


@pytest.mark.asyncio
async def test_esc_cancels_in_flight_turn_and_renders_cancelled_message() -> None:
    """Esc during an in-flight turn paints the translated cancellation line.

    ``pilot.press('enter')`` waits for all messages to drain, including the
    ``on_input_submitted`` handler itself, so a gated orchestrator would
    deadlock the pilot. We instead dispatch the submit via a background task
    that calls the handler directly, then trigger the cancel via
    ``action_cancel_turn``. This exercises exactly the same handler code
    path (CancelledError branch + paint + finally-clear) without touching
    the pilot's wait-for-idle semantics.
    """
    gate = asyncio.Event()

    async def blocked_response(**_kwargs: object) -> str:
        await gate.wait()  # never set in the cancellation path
        return "should not be rendered"

    orch, resolver, pool, _user = _build_doubles(orch_response=blocked_response)
    app = AlfredTuiApp(orchestrator=orch, identity_resolver=resolver, working_pool=pool)
    try:
        async with app.run_test() as pilot:
            input_widget = app.query_one("#user_input", Input)
            # Dispatch the submit as a background task so the handler can
            # suspend on the gated orchestrator without blocking the pilot.
            submit_task = asyncio.create_task(
                app.on_input_submitted(Input.Submitted(input_widget, value="hi"))
            )
            # Yield until the handler reaches its `await asyncio.wait_for(...)`
            # — `_in_flight` is set inside the handler before that await.
            for _ in range(20):
                await pilot.pause()
                if app._in_flight is not None:
                    break
            assert app._in_flight is not None, "in-flight task should be set"
            await app.action_cancel_turn()
            # Pump the loop so the CancelledError propagates through
            # `wait_for`, the handler's except-arm paints, and the finally
            # clause clears `_in_flight`.
            for _ in range(20):
                await pilot.pause()
                if submit_task.done():
                    break
            await submit_task
            rendered = _rendered(app)
            assert "turn cancelled" in rendered
            assert app._in_flight is None
            # Cancellation still releases the buffer back to the pool — the
            # TUI's finally block is what guarantees the in_use set does not
            # accumulate orphaned keys across cancelled turns.
            assert pool.release.await_count == 1
    finally:
        gate.set()


@pytest.mark.asyncio
async def test_provider_timeout_renders_translated_timeout_message(
    monkeypatch: MonkeyPatch,
) -> None:
    """When the per-turn cap elapses the TUI paints ``tui.turn_timeout``.

    We patch ``TURN_TIMEOUT_SECONDS`` to a tiny value so the
    ``asyncio.wait_for`` wrapper fires its ``TimeoutError`` branch
    deterministically without slowing the suite.
    """

    async def too_slow(**_kwargs: object) -> str:
        await asyncio.sleep(1.0)
        return "never rendered"

    monkeypatch.setattr("alfred.comms.tui.TURN_TIMEOUT_SECONDS", 0.05)
    orch, resolver, pool, _user = _build_doubles(orch_response=too_slow)
    app = AlfredTuiApp(orchestrator=orch, identity_resolver=resolver, working_pool=pool)
    async with app.run_test() as pilot:
        app.query_one("#user_input", Input).focus()
        await pilot.pause()
        await pilot.press("h", "i")
        await pilot.press("enter")
        # First pause dispatches submit; second covers the wait_for + repaint
        # after the timeout fires.
        await pilot.pause()
        await pilot.pause(0.15)
        rendered = _rendered(app)
        # The .po template is "no response within {seconds}s; cancelled" —
        # the substituted ``seconds`` value is a float we render as-is.
        assert "no response within" in rendered
        assert "cancelled" in rendered
        # Timeout still releases the pool entry.
        assert pool.release.await_count == 1


@pytest.mark.asyncio
async def test_provider_exception_renders_friendly_alfred_error() -> None:
    """A provider raising paints ``tui.alfred_error`` with the message.

    We assert the user sees ``alfred error: boom`` (the English template
    with ``{error}`` substituted) and NOT a Python traceback. The
    orchestrator audited the failure on its side; the TUI's only job here
    is to paint a friendly one-liner.
    """
    orch, resolver, pool, _user = _build_doubles(orch_response=RuntimeError("boom"))
    app = AlfredTuiApp(orchestrator=orch, identity_resolver=resolver, working_pool=pool)
    async with app.run_test() as pilot:
        app.query_one("#user_input", Input).focus()
        await pilot.pause()
        await pilot.press("h", "i")
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()
        rendered = _rendered(app)
        assert "alfred error" in rendered
        assert "boom" in rendered
        # Tracebacks would render "Traceback" or "RuntimeError" — confirm
        # the friendly path swallowed the raw exception class name.
        assert "Traceback" not in rendered
        # Exception still releases the pool entry — the finally block.
        assert pool.release.await_count == 1


@pytest.mark.asyncio
async def test_second_submit_while_busy_is_silently_ignored() -> None:
    """Slice-1 policy: one turn at a time.

    Verifies the in-flight guard directly (same pilot-bypass pattern as
    the Esc test above — ``pilot.press('enter')`` would deadlock against
    a gated orchestrator). First submit goes via a background task; while
    it's pending we synthesise a second ``on_input_submitted`` call and
    confirm the guard returns early without invoking the orchestrator
    again. Release the gate, the first response renders.
    """
    gate = asyncio.Event()

    async def gated_response(**_kwargs: object) -> str:
        await gate.wait()
        return "one response"

    orch, resolver, pool, user = _build_doubles(orch_response=gated_response)
    app = AlfredTuiApp(orchestrator=orch, identity_resolver=resolver, working_pool=pool)
    try:
        async with app.run_test() as pilot:
            input_widget = app.query_one("#user_input", Input)
            submit_task = asyncio.create_task(
                app.on_input_submitted(Input.Submitted(input_widget, value="hi"))
            )
            for _ in range(20):
                await pilot.pause()
                if app._in_flight is not None:
                    break
            assert app._in_flight is not None
            assert not app._in_flight.done()
            # Second submission while the first is in flight. The
            # in-flight guard should silently return without a second
            # orchestrator invocation. The guard fires BEFORE the pool
            # acquire so a busy-state submit also must NOT acquire a
            # second buffer — verified by the acquire await_count.
            await app.on_input_submitted(Input.Submitted(input_widget, value="hi-again"))
            assert orch.handle_user_message.await_count == 1
            assert pool.acquire.await_count == 1
            gate.set()
            for _ in range(20):
                await pilot.pause()
                if submit_task.done():
                    break
            await submit_task
            rendered = _rendered(app)
            assert "one response" in rendered
            _assert_dispatched_once(orch, user=user, expected_text="hi")
    finally:
        gate.set()
