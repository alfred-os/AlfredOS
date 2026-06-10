"""render.build_app wires the session's render hook to the app's RichLog.

``run_tui_render`` blocks on the Textual main loop, so the testable seam is
``build_app(session)``: it constructs the :class:`AlfredTuiApp`, installs the
app's ``write_outbound`` as the session's render hook, and returns the app. A
subsequent ``session.render_outbound(body)`` must therefore paint a visible
RichLog line through the wired app.
"""

from __future__ import annotations

import pytest
from alfred_tui.render import build_app
from alfred_tui.session import TuiSession
from textual.widgets import RichLog


@pytest.mark.asyncio
async def test_build_app_wires_session_render_hook_to_richlog() -> None:
    session = TuiSession()
    app = build_app(session)
    async with app.run_test() as pilot:
        await session.render_outbound("wired outbound line")
        await pilot.pause()
        log = app.query_one("#conversation_log", RichLog)
        rendered = "\n".join(str(line) for line in log.lines)
    assert "wired outbound line" in rendered
