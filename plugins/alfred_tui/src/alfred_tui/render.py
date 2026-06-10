"""Textual app shell wiring + blocking run entry.

Mounts the widget tree from ``alfred_tui.textual.app`` and ties it to the
session: the app feeds operator input into ``session.consume_user_input`` (the
inbound path), and the session paints host-delivered outbound through the app's
``write_outbound`` (the outbound path). The shell does not own the wire
contract — ``alfred_tui.server`` is the wire-binding layer.
"""

from __future__ import annotations

from alfred_tui.session import TuiSession
from alfred_tui.textual.app import AlfredTuiApp


def build_app(session: TuiSession) -> AlfredTuiApp:
    """Construct the app and cross-wire it with the session's render hook.

    The app is built FROM the session (it feeds ``consume_user_input``), and the
    session's outbound render hook is set TO the app's ``write_outbound`` — so a
    host ``outbound.message`` painted via ``session.render_outbound`` lands in
    the app's RichLog. Returned (not run) so callers can drive it under a test
    pilot; ``run_tui_render`` is the blocking production entry.
    """
    app = AlfredTuiApp(session=session)
    session.set_render_hook(app.write_outbound)
    return app


def run_tui_render(session: TuiSession) -> None:
    """Synchronous entry; blocks until the Textual app exits."""
    build_app(session).run()


__all__ = ["build_app", "run_tui_render"]
