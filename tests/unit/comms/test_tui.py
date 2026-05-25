"""Tests for the Slice-1 Textual TUI.

Spec: docs/superpowers/plans/2026-05-24-slice-1-hello-alfred.md (Task 14)
with the parent agent's spec-bug fixes applied:
  * (#5) RichLog read-back: installed Textual (8.2.7) has ``RichLog.render()``
    but it does not return the user-visible buffer; the writes live on
    ``RichLog.lines`` as ``Strip`` objects whose ``__str__`` renders to text.
    We stringify the strips for the assertion.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from textual.widgets import Input

from alfred.comms.tui import AlfredTuiApp


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
        log = app.query_one("#conversation_log")
        # Textual 8.x stores RichLog writes as Strip objects on ``.lines``;
        # render() does not expose the visible buffer (see test docstring).
        rendered = "\n".join(str(line) for line in log.lines)
        assert "Good evening" in rendered
        orch.handle_user_message.assert_awaited_once_with("hi")
