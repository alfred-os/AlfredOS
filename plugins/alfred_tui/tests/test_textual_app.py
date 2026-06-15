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
from textual.widgets import Input, RichLog, Static

from alfred.comms_mcp.protocol import (
    LINK_RECONNECTING,
    LINK_RESTORED,
    LINK_UNAVAILABLE,
)
from alfred.i18n import t


def _plain_text(log: RichLog) -> str:
    """The visible plain text of a RichLog, stripped of style metadata.

    ``str(strip)`` renders the Strip *repr* (Segment + Style noise), which would
    let a markup assertion pass on style attributes rather than literal glyphs.
    Joining each strip's ``Segment.text`` gives exactly what the operator sees,
    so an assertion on literal ``[red]…[/red]`` glyphs is meaningful.
    """
    return "\n".join("".join(seg.text for seg in strip) for strip in log.lines)


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
        rendered = _plain_text(log)
    assert "hello back from alfred" in rendered


@pytest.mark.asyncio
async def test_outbound_markup_in_body_is_rendered_literally_not_interpreted() -> None:
    """Console markup in a host-delivered outbound body must NOT be interpreted.

    The outbound ``body`` is persona output that can carry T3-derived content;
    the RichLog runs ``markup=True``, so an attacker-influenced ``[red]…[/red]``
    (or ``[link=…]``) would otherwise be parsed as a Rich style tag (markup
    injection). The app escapes the untrusted body so the brackets show as
    literal text. The app-controlled label prefix keeps its legitimate markup.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session)
    async with app.run_test() as pilot:
        app.write_outbound("[red]evil[/red]")
        await pilot.pause()
        log = app.query_one("#conversation_log", RichLog)
        rendered = _plain_text(log)
    assert "[red]evil[/red]" in rendered, (
        "outbound markup was interpreted, not escaped — markup-injection vector"
    )


@pytest.mark.asyncio
async def test_echoed_user_input_markup_is_rendered_literally_not_interpreted() -> None:
    """Console markup typed by the operator is echoed literally, not interpreted.

    Symmetric to the outbound guard: the echoed user line is interpolated into
    the same ``markup=True`` RichLog, so it gets escaped too.
    """
    session = _RecordingSession()
    app = AlfredTuiApp(session=session)
    async with app.run_test() as pilot:
        app.query_one("#user_input", Input).value = "[blink]boom[/blink]"
        await pilot.press("enter")
        await pilot.pause()
        log = app.query_one("#conversation_log", RichLog)
        rendered = _plain_text(log)
    assert "[blink]boom[/blink]" in rendered, (
        "echoed user markup was interpreted, not escaped — markup-injection vector"
    )


# ---------------------------------------------------------------------------
# Reconnect banner — gateway link-state render (Spec A G5 / ADR-0031).
#
# The gateway sends only the STATE (the ``link.*`` method); the TUI paints its
# OWN localized banner text via ``t("tui.banner.*")`` (no operator text on the
# wire). ``set_link_state`` is invoked by the cohost pump on the SAME loop as the
# Textual app (M1) — a direct reactive set, never ``call_from_thread``.
# ---------------------------------------------------------------------------


def _banner(app: AlfredTuiApp) -> Static:
    return app.query_one("#link_banner", Static)


@pytest.mark.asyncio
async def test_banner_hidden_on_mount() -> None:
    """No link gap yet: the banner is not displayed when the app first mounts."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        await pilot.pause()
        banner = _banner(app)
        assert banner.display is False


@pytest.mark.asyncio
async def test_reconnecting_state_shows_localized_banner() -> None:
    """``link.reconnecting`` paints the localized reconnecting banner text."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        app.set_link_state(LINK_RECONNECTING)
        await pilot.pause()
        banner = _banner(app)
        assert banner.display is True
        assert _plain_text_static(banner) == t("tui.banner.reconnecting")


@pytest.mark.asyncio
async def test_restored_state_clears_the_banner() -> None:
    """``link.restored`` hides the banner after a prior gap."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        app.set_link_state(LINK_RECONNECTING)
        await pilot.pause()
        app.set_link_state(LINK_RESTORED)
        await pilot.pause()
        banner = _banner(app)
        assert banner.display is False


@pytest.mark.asyncio
async def test_unavailable_state_shows_localized_banner() -> None:
    """``link.unavailable`` (G4-latent) paints the localized unavailable text."""
    app = AlfredTuiApp(session=_RecordingSession())
    async with app.run_test() as pilot:
        app.set_link_state(LINK_UNAVAILABLE)
        await pilot.pause()
        banner = _banner(app)
        assert banner.display is True
        assert _plain_text_static(banner) == t("tui.banner.unavailable")


def _plain_text_static(banner: Static) -> str:
    """The visible plain text of the banner ``Static``, stripped of style noise."""
    from rich.console import Console
    from rich.text import Text

    renderable = banner.render()
    if isinstance(renderable, str):
        return renderable
    if isinstance(renderable, Text):
        return renderable.plain
    # Any other Rich renderable: render to a throwaway console and read the glyphs.
    return "".join(seg.text for seg in Console().render(renderable)).rstrip("\n")
