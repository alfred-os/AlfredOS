"""Textual app shell for the AlfredOS TUI MCP-plugin adapter.

Verbatim move from ``src/alfred/comms/tui.py`` (PR-S4-10). The widget tree
(scrolling RichLog conversation log + bottom Input box) is preserved one-for-one
from the Slice-1/2 in-process TUI; only the *bindings* between the widgets and
the surrounding adapter changed.

The Slice-1/2 app called an in-process orchestrator inside ``on_input_submitted``
and owned the trust-tier tagging + working-memory lifecycle itself. In the
comms-MCP rewrite those responsibilities move host-side: the app now feeds a
:class:`_SessionLike` collaborator's ``consume_user_input`` + ``flush_keystroke_batch``
on Enter (the session turns each batch into an ``inbound.message`` wire
notification), and renders host-delivered outbound via :meth:`write_outbound`
(the ``outbound.message`` wire handler calls into it). The app holds NO
orchestrator, identity resolver, working pool, or tier-tagging logic — that all
lives across the wire boundary now.

Operator-facing strings go through ``alfred.i18n.t`` using the EXISTING ``tui.*``
catalog keys (unchanged from the Slice-1 app); no new catalog entries are
introduced by the move.
"""

from __future__ import annotations

from typing import Protocol

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Input, RichLog

from alfred.i18n import t


class _SessionLike(Protocol):
    """The structural seam the app needs from its session.

    Keeping the app decoupled from the concrete :class:`alfred_tui.session.TuiSession`
    (via a Protocol, not a direct import) preserves the Slice-1 discipline of a
    widget tree that is testable without the surrounding adapter — a recording
    double satisfies this Protocol in the widget tests.
    """

    async def consume_user_input(self, chunk: str) -> None:
        raise NotImplementedError

    async def flush_keystroke_batch(self) -> None:
        raise NotImplementedError


class AlfredTuiApp(App[None]):
    """Textual app: scrolling conversation log + bottom input box.

    Enter feeds the typed line into the session as one keystroke-batch; the
    session emits the ``inbound.message`` notification. Host-delivered outbound
    is painted via :meth:`write_outbound`.
    """

    CSS = """
    Screen { layout: vertical; }
    #conversation_log { height: 1fr; border: solid white; padding: 1; }
    #user_input { dock: bottom; }
    #user_input.busy { background: $boost; color: $text-muted; }
    """

    BINDINGS = [  # noqa: RUF012  # Textual reads BINDINGS off the class; mutable is the documented contract.
        # Footer descriptions are operator-facing and go through t() per
        # CLAUDE.md i18n hard rule #1. Existing tui.* catalog keys (unchanged
        # from the Slice-1 app) — the move introduces no new catalog entries.
        Binding("ctrl+c", "quit", t("tui.binding.quit"), show=True, priority=True),
        Binding("ctrl+q", "quit", t("tui.binding.quit"), show=True),
    ]

    def __init__(self, *, session: _SessionLike) -> None:
        super().__init__()
        self._session = session

    def compose(self) -> ComposeResult:
        yield Vertical(
            RichLog(id="conversation_log", highlight=True, markup=True, wrap=True),
            Input(placeholder=t("tui.input_placeholder"), id="user_input"),
        )

    async def on_mount(self) -> None:
        """Place initial focus on the input box.

        Textual defaults focus to the first focusable widget in the compose
        tree — that's the RichLog, not the Input — so without this the first
        keystrokes silently scroll the log rather than typing into the input.
        """
        self.query_one("#user_input", Input).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter: feed the typed line to the session as one keystroke-batch.

        Empty submissions are dropped (the session's flush is a no-op on an
        empty buffer too — belt and braces). The line is echoed into the log so
        the operator sees their own turn, mirroring the Slice-1 affordance.
        """
        text = event.value.strip()
        if not text:
            return
        log = self.query_one("#conversation_log", RichLog)
        # ``text`` is operator-typed and echoed into a ``markup=True`` RichLog;
        # escape it so any ``[red]``/``[link=…]`` is shown literally, not parsed
        # as Rich console markup. The app-controlled label prefix keeps its
        # legitimate markup. (PR-S4-10 review #1 — markup-injection guard.)
        log.write(f"[bold cyan]{t('tui.label_you')}[/]: {escape(text)}")
        event.input.value = ""
        await self._session.consume_user_input(text)
        await self._session.flush_keystroke_batch()

    def write_outbound(self, body: str) -> None:
        """Paint a host-delivered outbound message into the conversation log.

        Called from the ``outbound.message`` wire handler (via the session's
        render hook). Synchronous: a RichLog write is non-blocking and the
        outbound handler awaits nothing on the render itself.
        """
        log = self.query_one("#conversation_log", RichLog)
        # ``body`` is host-delivered persona output that can carry T3-derived
        # content; escape it so console markup in the body renders literally
        # rather than being interpreted by the ``markup=True`` RichLog. The
        # app-controlled label prefix keeps its legitimate markup.
        # (PR-S4-10 review #1 — markup-injection guard.)
        log.write(f"[bold green]{t('tui.label_alfred')}[/]: {escape(body)}")
