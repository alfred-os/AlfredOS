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
from textual.reactive import reactive
from textual.widgets import Input, RichLog, Static

from alfred.comms_mcp.protocol import LINK_RECONNECTING, LINK_UNAVAILABLE
from alfred.i18n import t

# Map the gateway's id-less ``link.*`` STATE method (Spec A G5 / ADR-0031) to the
# LOCAL catalog key the TUI renders. The gateway carries NO operator text — only
# the state — so the banner copy is the TUI's own localized ``t()`` render. The
# ``link.restored`` state is absent: it CLEARS the banner (no text to show).
# ``link.unavailable`` is vocab-complete but latent until G4 wires its trigger.
_LINK_STATE_BANNER_KEY: dict[str, str] = {
    LINK_RECONNECTING: "tui.banner.reconnecting",
    LINK_UNAVAILABLE: "tui.banner.unavailable",
}


def _reserve_banner_catalog_keys() -> None:
    """Pybabel-extraction anchor for the reconnect-banner catalog keys.

    The banner copy is rendered via ``t(banner_key)`` where ``banner_key`` comes
    from :data:`_LINK_STATE_BANNER_KEY` — a VARIABLE, which ``pybabel extract``
    cannot follow. These literal ``t(...)`` calls give the extractor a static
    reference so ``tui.banner.*`` are active msgids (not marked obsolete on the
    next ``pybabel update``, which the i18n drift gate trips on). The
    ``tui.banner.restored`` key is reserved for symmetry/future use even though
    the restored STATE clears the banner rather than rendering text. Never called.
    """
    t("tui.banner.reconnecting")
    t("tui.banner.restored")
    t("tui.banner.unavailable")


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
    #link_banner { dock: top; width: 100%; padding: 0 1; background: $warning; color: $text; }
    #conversation_log { height: 1fr; border: solid white; padding: 1; }
    #user_input { dock: bottom; }
    #user_input.busy { background: $boost; color: $text-muted; }
    """

    # The current gateway link-state banner key, or ``None`` when the link is
    # healthy (banner hidden). A Textual ``reactive`` so a ``set_link_state``
    # mutation drives the ``watch_*`` render on the app's own loop (M1) — no
    # off-loop ``call_from_thread`` (the cohost pump shares this loop).
    _link_banner_key: reactive[str | None] = reactive[str | None](None)

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
        # The reconnect banner is mounted hidden (``display=False``); it is shown
        # and its text set by ``watch__link_banner_key`` when the gateway signals a
        # core-link gap, and re-hidden on restore.
        banner = Static(id="link_banner")
        banner.display = False
        yield banner
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

    def set_link_state(self, method: str) -> None:
        """Update the reconnect banner from a gateway ``link.*`` state method.

        Invoked by the cohost wire pump (``run_cohosted``'s ``on_link_state``) on
        the SAME asyncio loop as this app (M1 — the pump and ``run_async()`` share
        one ``TaskGroup``/loop), so this is a DIRECT reactive set, NOT
        ``call_from_thread`` (which is for OFF-loop threads). Mutating the reactive
        drives ``watch__link_banner_key`` on the next render cycle.

        ``link.reconnecting`` / ``link.unavailable`` show the matching localized
        banner; ``link.restored`` clears it. ``link.unavailable`` is vocab-complete
        but latent until G4 wires its trigger (the gateway only emits
        ``reconnecting`` / ``restored`` today).
        """
        self._link_banner_key = _LINK_STATE_BANNER_KEY.get(method)

    def watch__link_banner_key(self, banner_key: str | None) -> None:
        """Paint or hide the reconnect banner when the link-state reactive changes.

        ``None`` (healthy / restored) hides the banner; a catalog key shows it with
        the TUI's OWN localized ``t()`` render — the gateway sends only state, never
        operator text (Spec A G5). The banner text is app-controlled (a fixed
        catalog string, no untrusted interpolation), so no markup-escape is needed.
        """
        banner = self.query_one("#link_banner", Static)
        if banner_key is None:
            banner.display = False
            return
        banner.update(t(banner_key))
        banner.display = True
