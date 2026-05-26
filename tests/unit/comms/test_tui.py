"""Tests for the Slice-1 Textual TUI.

Spec: docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md (Task 14)
with the parent agent's spec-bug fixes applied:
  * (#5) RichLog read-back: installed Textual (8.2.7) has ``RichLog.render()``
    but it does not return the user-visible buffer; the writes live on
    ``RichLog.lines`` as ``Strip`` objects whose ``__str__`` renders to text.
    We stringify the strips for the assertion.

PR #89 review (comms-2 + reviewer high): the original happy-path test left
four branches of ``on_input_submitted`` uncovered (Esc cancel, provider
timeout, provider exception, second-submit-while-busy). Those four are
added here. Each test mirrors the happy-path's pattern of explicitly
focusing the Input widget before keystrokes — Textual 8.x defaults focus
to the first focusable widget in the compose tree (the RichLog), not the
Input, so keystrokes silently scroll the log without the explicit focus.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from pytest import MonkeyPatch
from textual.widgets import Input

from alfred.comms.tui import AlfredTuiApp


def _rendered(app: AlfredTuiApp) -> str:
    """Stringify the visible RichLog buffer for assertion."""
    log = app.query_one("#conversation_log")
    return "\n".join(str(line) for line in log.lines)


@pytest.mark.asyncio
async def test_user_submission_dispatches_to_orchestrator_and_displays_response() -> None:
    orch = AsyncMock()
    orch.handle_user_message = AsyncMock(return_value="Good evening, operator.")
    app = AlfredTuiApp(orchestrator=orch)
    async with app.run_test() as pilot:
        # Textual 8.x sends keystrokes to whichever widget holds focus, and
        # the default focus on mount falls on the first focusable widget in
        # the compose tree (the RichLog), not the Input. Slice-1 lives with
        # that; the CLI wiring (Task 15) gives the Input explicit initial
        # focus. The test mimics that here.
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
        orch.handle_user_message.assert_awaited_once_with("hi")


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

    async def blocked_response(_text: str) -> str:
        await gate.wait()  # never set in the cancellation path
        return "should not be rendered"

    orch = AsyncMock()
    orch.handle_user_message = AsyncMock(side_effect=blocked_response)
    app = AlfredTuiApp(orchestrator=orch)
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

    async def too_slow(_text: str) -> str:
        await asyncio.sleep(1.0)
        return "never rendered"

    monkeypatch.setattr("alfred.comms.tui.TURN_TIMEOUT_SECONDS", 0.05)
    orch = AsyncMock()
    orch.handle_user_message = AsyncMock(side_effect=too_slow)
    app = AlfredTuiApp(orchestrator=orch)
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


@pytest.mark.asyncio
async def test_provider_exception_renders_friendly_alfred_error() -> None:
    """A provider raising paints ``tui.alfred_error`` with the message.

    We assert the user sees ``alfred error: boom`` (the English template
    with ``{error}`` substituted) and NOT a Python traceback. The
    orchestrator audited the failure on its side; the TUI's only job here
    is to paint a friendly one-liner.
    """
    orch = AsyncMock()
    orch.handle_user_message = AsyncMock(side_effect=RuntimeError("boom"))
    app = AlfredTuiApp(orchestrator=orch)
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

    async def gated_response(_text: str) -> str:
        await gate.wait()
        return "one response"

    orch = AsyncMock()
    orch.handle_user_message = AsyncMock(side_effect=gated_response)
    app = AlfredTuiApp(orchestrator=orch)
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
            # orchestrator invocation.
            await app.on_input_submitted(Input.Submitted(input_widget, value="hi-again"))
            assert orch.handle_user_message.await_count == 1
            gate.set()
            for _ in range(20):
                await pilot.pause()
                if submit_task.done():
                    break
            await submit_task
            rendered = _rendered(app)
            assert "one response" in rendered
            orch.handle_user_message.assert_awaited_once_with("hi")
    finally:
        gate.set()
