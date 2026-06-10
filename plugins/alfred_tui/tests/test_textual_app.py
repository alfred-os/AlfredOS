"""The moved Textual app feeds input into the session and renders outbound.

Verbatim move from ``src/alfred/comms/tui.py`` (PR-S4-10): the widget tree
(input area + RichLog) is preserved; only the *bindings* to the surrounding
adapter change — the app now feeds a session's ``consume_user_input`` (which the
plugin's wire layer turns into an ``inbound.message`` notification) instead of
calling an in-process orchestrator.
"""

from __future__ import annotations

import pytest
from alfred_tui.textual.app import AlfredTuiApp
from textual.widgets import Input, RichLog


class _RecordingSession:
    """Structural ``_SessionLike`` double recording consumed input."""

    def __init__(self) -> None:
        self.consumed: list[str] = []
        self.flushed: int = 0

    async def consume_user_input(self, chunk: str) -> None:
        self.consumed.append(chunk)

    async def flush_keystroke_batch(self) -> None:
        self.flushed += 1


@pytest.mark.asyncio
async def test_enter_submits_input_to_session() -> None:
    session = _RecordingSession()
    app = AlfredTuiApp(session=session)
    async with app.run_test() as pilot:
        app.query_one("#user_input", Input).value = "hello alfred"
        await pilot.press("enter")
        await pilot.pause()
    assert session.consumed == ["hello alfred"]
    assert session.flushed == 1


@pytest.mark.asyncio
async def test_outbound_render_writes_visible_richlog_line() -> None:
    session = _RecordingSession()
    app = AlfredTuiApp(session=session)
    async with app.run_test() as pilot:
        app.write_outbound("hello back from alfred")
        await pilot.pause()
        log = app.query_one("#conversation_log", RichLog)
        rendered = "\n".join(str(line) for line in log.lines)
    assert "hello back from alfred" in rendered
