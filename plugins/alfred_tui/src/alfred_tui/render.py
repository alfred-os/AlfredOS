"""Textual app shell wiring + app construction.

Mounts the widget tree from ``alfred_tui.textual.app`` and ties it to the
session: the app feeds operator input into ``session.consume_user_input`` (the
inbound path), and the session paints host-delivered outbound through the app's
``write_outbound`` (the outbound path). The shell does not own the wire
contract — ``alfred_tui.server`` is the wire-binding layer.

PRODUCTION uses :func:`build_app` + the app's async ``run_async()`` co-host
(``alfred_tui.cohost.run_cohosted``, ADR-0031 Shape A) so Textual co-exists on the
same asyncio loop as the socket serve loop. The blocking :func:`run_tui_render`
(``App.run()``) is NOT used in production — it would own the loop and starve the
wire task; it is retained only for a manual / standalone blocking launch.
"""

from __future__ import annotations

from alfred_tui.session import TuiSession
from alfred_tui.textual.app import AlfredTuiApp


def build_app(session: TuiSession) -> AlfredTuiApp:
    """Construct the app and cross-wire it with the session's render hook.

    The app is built FROM the session (it feeds ``consume_user_input``), and the
    session's outbound render hook is set TO the app's ``write_outbound`` — so a
    host ``outbound.message`` painted via ``session.render_outbound`` lands in
    the app's RichLog. Returned (not run) so the co-host can drive it via
    ``run_async()`` (production) or a test pilot.
    """
    app = AlfredTuiApp(session=session)
    session.set_render_hook(app.write_outbound)
    return app


def run_tui_render(session: TuiSession) -> None:  # pragma: no cover - blocking manual entry
    """Synchronous blocking launch; NOT used in production (see module docstring).

    Retained for a standalone / manual blocking run. Production co-hosts the app
    via ``run_async()`` (``alfred_tui.cohost.run_cohosted``) so Textual shares the
    loop with the socket serve loop; ``App.run()`` here would own the loop.
    """
    build_app(session).run()


__all__ = ["build_app", "run_tui_render"]
