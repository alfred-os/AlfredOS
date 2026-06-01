"""Slice-1/2 TUI built on Textual.

Scrolling conversation log + bottom input box. Enter submits through the
orchestrator; response renders in the log. Slice-1 affordances:
- Ctrl+C / Ctrl+Q exits cleanly.
- A pending submission disables the input + shows a "thinking" hint so a stalled
  provider doesn't look like a frozen UI. Esc cancels the in-flight turn.
- Errors render as a one-line message routed through t() — never a raw traceback.

PR-B Phase 5: the TUI is now the adapter that owns the trust-tier tag and
working-memory lifecycle for each turn. ``_run_turn`` calls
``identity_resolver.get_operator()`` to find the requesting user (slice 2
single-operator: that's always the operator), tags the raw text using
:func:`alfred.identity._ingest._ingest_tier` (which yields ``T1`` for
operator-role users on the TUI adapter and ``T2`` everywhere else per
spec §3.6), then acquires the pooled :class:`WorkingMemory` for
``("alfred", user.slug)`` and releases it in a ``finally`` block so a
crash inside the orchestrator can't leave the entry stuck in-use.

arch-001 (slice-3 retrospective): pre-fix the TUI hard-coded
``tag(T2, ...)`` even though ``_ingest_tier`` had landed for the T1
ingress path. T1 was reachable only via test fixtures — production
operator turns ran under T2. This module is now the FIRST production
producer for T1 ingress: an operator-role user typing in the TUI
produces ``TaggedContent[T1]``; the orchestrator's T1|T2 widening
accepts both. Discord stays T2 because the adapter name differs (the
``_ingest_tier`` rule is hard-coded TUI-only — Discord is
broadcast-shaped per §3.6 and never T1).

Slice 2+ adds streaming UX.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol, cast

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Input, RichLog

from alfred.i18n import t
from alfred.identity._ingest import _ingest_tier
from alfred.security.tiers import T1, T2, tag

if TYPE_CHECKING:
    from alfred.identity.models import User
    from alfred.memory.working import WorkingMemory
    from alfred.orchestrator.core import UserLike
    from alfred.security.tiers import TaggedContent, TrustTier

# Per-turn wall-clock cap. If the provider doesn't respond in this long, the TUI
# cancels the turn and renders a friendly timeout message. Slice 2+ may make this
# per-persona configurable.
TURN_TIMEOUT_SECONDS = 90


class _IdentityResolverLike(Protocol):
    """Structural type the TUI needs from its identity resolver.

    The TUI calls :meth:`get_operator` exactly once per turn (Slice-2
    single-operator scope — every turn is "the operator typing"). The
    resolver's in-process LRU + version-counter coupling means the call
    is a memory read on the cache-hit path and a single DB round-trip
    when the cache is invalidated by an ``alfred user *`` mutation in
    the same process.

    Return type is the concrete :class:`alfred.identity.models.User`
    (matching the orchestrator's ``IdentityResolverLike`` Protocol in
    ``alfred.orchestrator.core``) rather than a structural ``UserLike``
    because pyright's variance check on SQLAlchemy-mapped columns
    (``Mapped[str]`` vs ``str``) refuses the structural form. Slice-1's
    audit-row writes already depend on the concrete row type, so the
    extra coupling here is honest, not speculative.
    """

    # Protocol bodies need *some* body; ``raise NotImplementedError`` is
    # preferred over ``...`` so accidental instantiation fails loudly and
    # CodeQL's py/ineffectual-statement does not flag the ellipsis.
    def get_operator(self) -> User:
        raise NotImplementedError


class _WorkingPoolLike(Protocol):
    """Structural type the TUI needs from its working-memory pool.

    Slice 2+ adapter contract: the adapter ``acquire`` -- ``release`` is
    what owns the WorkingMemory lifecycle for the turn, NOT the
    orchestrator. The pool's per-key ``asyncio.Lock`` registry serialises
    concurrent acquires of the same key on its side.
    """

    async def acquire(self, key: tuple[str, str]) -> WorkingMemory:
        raise NotImplementedError

    async def release(self, key: tuple[str, str], wm: WorkingMemory) -> None:
        raise NotImplementedError


class _OrchestratorLike(Protocol):
    """Structural type the TUI needs from its orchestrator.

    Letting the TUI depend on a Protocol (not the concrete Orchestrator class)
    keeps the comms layer decoupled from the core wiring — exactly what slice 2's
    plugin-supervised comms adapter pattern needs. The test substitutes an
    AsyncMock that matches this shape.

    Signature (PR-B Phase 5): ``user`` is the resolved requester; ``content``
    is the already-T2-tagged input from this adapter; ``working_memory`` is
    the pool-acquired buffer for this (persona, user.slug) pair. The
    ``user`` parameter is the orchestrator's own ``UserLike`` Protocol so
    a concrete :class:`Orchestrator` satisfies this Protocol without a
    cast at the TUI's call site.
    """

    async def handle_user_message(
        self,
        *,
        user: UserLike,
        content: TaggedContent[T1] | TaggedContent[T2],
        working_memory: WorkingMemory,
    ) -> str:
        raise NotImplementedError


class AlfredTuiApp(App[None]):
    CSS = """
    Screen { layout: vertical; }
    #conversation_log { height: 1fr; border: solid white; padding: 1; }
    #user_input { dock: bottom; }
    #user_input.busy { background: $boost; color: $text-muted; }
    """

    BINDINGS = [  # noqa: RUF012  # Textual reads BINDINGS off the class; mutable is the documented contract.
        # Footer descriptions are operator-facing and go through t() per
        # CLAUDE.md i18n hard rule #1. Resolution happens at class-definition
        # time against the default ``_active_lang`` ("en-US"); slice-2's
        # per-session language switch would need ``App.refresh_bindings`` to
        # repaint, but the keys themselves stay stable.
        Binding("ctrl+c", "quit", t("tui.binding.quit"), show=True, priority=True),
        Binding("ctrl+q", "quit", t("tui.binding.quit"), show=True),
        Binding("escape", "cancel_turn", t("tui.binding.cancel_turn"), show=True),
    ]

    def __init__(
        self,
        *,
        orchestrator: _OrchestratorLike,
        identity_resolver: _IdentityResolverLike,
        working_pool: _WorkingPoolLike,
    ) -> None:
        super().__init__()
        self._orchestrator = orchestrator
        self._identity_resolver = identity_resolver
        self._working_pool = working_pool
        self._in_flight: asyncio.Task[str] | None = None
        # Tracks whether the most recent CancelledError originated from the
        # user pressing Esc (``action_cancel_turn``). When False, a
        # CancelledError reaching ``on_input_submitted`` is Textual's own
        # shutdown signal and MUST propagate — masking it would block the
        # app from exiting cleanly.
        self._user_cancelled: bool = False

    def compose(self) -> ComposeResult:
        yield Vertical(
            RichLog(id="conversation_log", highlight=True, markup=True, wrap=True),
            Input(placeholder=t("tui.input_placeholder"), id="user_input"),
        )

    async def on_mount(self) -> None:
        """Place initial focus on the input box.

        Textual 8.x defaults focus to the first focusable widget in the
        compose tree — that's the RichLog, not the Input — so without this
        the first ``alfred chat`` keystrokes silently scroll the log rather
        than typing into the input. Test pilots set focus explicitly so this
        is intentionally not covered by ``tests/unit/comms/test_tui.py``;
        the value is on real-terminal launch via the CLI.
        """
        self.query_one("#user_input", Input).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        if self._in_flight is not None and not self._in_flight.done():
            # Slice-1 policy: one turn at a time. Slice 3+ revisits when persona
            # coordination needs concurrent inbound turns.
            return
        log = self.query_one("#conversation_log", RichLog)
        input_widget = self.query_one("#user_input", Input)
        log.write(f"[bold cyan]{t('tui.label_you')}[/]: {text}")
        event.input.value = ""

        input_widget.disabled = True
        input_widget.add_class("busy")
        log.write(f"[dim]{t('tui.thinking')}[/]")

        # Reset the user-cancelled flag at the start of each turn so a stale
        # Esc from a prior turn cannot mask a fresh Textual shutdown signal.
        self._user_cancelled = False
        self._in_flight = asyncio.create_task(self._run_turn(text))
        try:
            response = await asyncio.wait_for(self._in_flight, timeout=TURN_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            # Only swallow the cancellation when the user pressed Esc. Any
            # other CancelledError reaching here is Textual's own shutdown
            # signal and must propagate so the app exits cleanly.
            if not self._user_cancelled:
                raise
            log.write(f"[yellow]{t('tui.turn_cancelled')}[/]")
            return
        except TimeoutError:
            log.write(f"[bold red]{t('tui.turn_timeout', seconds=TURN_TIMEOUT_SECONDS)}[/]")
            return
        except Exception as exc:
            # Friendly render of every failure mode: BudgetError, provider crash,
            # audit-write failure. The orchestrator already audited; we just paint.
            log.write(f"[bold red]{t('tui.alfred_error', error=str(exc))}[/]")
            return
        finally:
            input_widget.remove_class("busy")
            input_widget.disabled = False
            input_widget.focus()
            self._in_flight = None

        log.write(f"[bold green]{t('tui.label_alfred')}[/]: {response}")

    async def _run_turn(self, text: str) -> str:
        """Tag the input via ``_ingest_tier``, acquire the buffer, dispatch.

        The TUI is the adapter at the security boundary per CLAUDE.md hard
        rule #3 — every function that ingests external content tags it at
        the boundary. ``source="comms.tui.input"`` is the audit-traceable
        provenance string that lets a future DLP / canary trip name the
        adapter that admitted the content.

        arch-001 (slice-3 retrospective): the tier is derived from the
        role x adapter pair via :func:`alfred.identity._ingest._ingest_tier`
        rather than hard-coded as T2. The rule (spec §3.6) maps an
        operator-role user on the TUI adapter to ``T1`` and everything
        else to ``T2``. The orchestrator's content parameter accepts
        ``TaggedContent[T1] | TaggedContent[T2]`` so both flows land on
        the same dispatch path; the audit row picks up the resolved
        tier name without per-call branching here.

        The :func:`alfred.security.tiers.tag` factory routes ``tier=T1``
        and ``tier=T2`` through the open construction path (only
        ``tier=T3`` is capability-gated), so the dispatch is identical
        in shape to the prior T2-only call — only the tier argument
        moves from a hard-coded constant to a derived value.

        The pool ``acquire`` / ``release`` is a try/finally because the
        orchestrator may raise (BudgetError, provider crash, cancellation)
        and a leaked ``_in_use`` entry would block the pool's LRU trim
        from ever evicting it. ``release`` is a no-op on a pool entry
        that was force-evicted under us (see
        :meth:`WorkingMemoryPool.release` docstring), so it's safe to
        call unconditionally in the finally block.
        """
        user = self._identity_resolver.get_operator()
        # arch-001: derive the ingress tier from the role x adapter pair
        # via the single source of truth in ``alfred.identity._ingest``.
        # The adapter name is the literal ``"tui"`` — same value
        # :class:`alfred.comms.adapter.TuiAdapter` registers under (the
        # ``_ingest_tier`` rule keys on that exact string per spec §3.6).
        # Cast at the call site, not inside ``_ingest_tier``, so a wrong
        # adapter name surfaces as a type error rather than a silent T2
        # default.
        ingress_tier: type[TrustTier] = _ingest_tier(user, adapter_name="tui")
        # Both T1 and T2 routes through the open ``tag()`` path (T3 is
        # the capability-gated tier — out of scope here). The cast keeps
        # mypy's overload resolution happy: ``tag`` is overloaded per
        # tier, and the union return type is what the orchestrator
        # expects.
        content = tag(
            cast("type[T1] | type[T2]", ingress_tier),
            text,
            source="comms.tui.input",
        )
        key = ("alfred", user.slug)
        wm = await self._working_pool.acquire(key)
        try:
            # ``user`` is a real ``alfred.identity.models.User`` ORM
            # instance. It satisfies the orchestrator's ``UserLike``
            # Protocol structurally on mypy (with the SQLAlchemy plugin
            # that unwraps ``Mapped[str]`` → ``str``) but pyright's
            # standard typing-mode treats ``Mapped[str]`` as a distinct
            # descriptor type and refuses the assignment. The cast is the
            # documented escape hatch — see ADR-0007 on the pyright /
            # SQLAlchemy interop trade-off.
            return await self._orchestrator.handle_user_message(
                user=cast("UserLike", user),
                content=content,
                working_memory=wm,
            )
        finally:
            await self._working_pool.release(key, wm)

    async def action_cancel_turn(self) -> None:
        """Esc: cancel the in-flight turn if any.

        The orchestrator audits the cancellation on its side; the TUI's
        ``on_input_submitted`` handler catches the resulting CancelledError
        and paints ``tui.turn_cancelled``. We set ``_user_cancelled`` before
        triggering the cancel so the handler can distinguish a user-driven
        cancellation from a Textual shutdown signal.
        """
        if self._in_flight is not None and not self._in_flight.done():
            self._user_cancelled = True
            self._in_flight.cancel()
