"""CommsAdapter Protocol — the Slice-2 in-process comms-adapter seam.

Slice-2 ships two concrete adapters that satisfy this Protocol: the
:class:`alfred.comms.tui_adapter.TuiAdapter` (PR D1) and the
``DiscordAdapter`` (PR D2). Slice 3 inverts the polarity to an MCP-transport
contract — at that point the Protocol body in this module is rewritten and
every consumer that imports it picks up the new shape without touching the
call site. ADR-0009 documents the Slice-2-only nature of this Protocol and
the planned Slice-3 rewrite.

CLAUDE.md PRD §5 invariant ("plugins are MCP processes, not in-process
Protocols") is bounded here: the deviation is documented in ADR-0009 and
the AST-scan ``tests/unit/comms/test_no_direct_adapter_imports.py``
enforces that no consumer outside ``src/alfred/comms/`` imports a concrete
adapter — they consume this Protocol. That gate is what makes the Slice-3
swap a single-module rewrite rather than a cross-cutting refactor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from alfred.comms.tui import _IdentityResolverLike, _OrchestratorLike, _WorkingPoolLike
    from alfred.identity.rate_limit import RateLimiter
    from alfred.security.dlp import OutboundDlp
    from alfred.security.secrets import SecretBroker


@dataclass(frozen=True)
class AdapterHealth:
    """Point-in-time adapter health snapshot.

    Three fields, shape-compatible with both the Textual TUI and the future
    Discord gateway:

    * ``gateway_connected`` — Discord-specific signal that the gateway
      websocket is currently alive. TUI returns ``True`` while the Textual
      loop is running (the in-process loop is the "gateway" for the TUI).
    * ``last_on_ready_at`` — Discord-specific timestamp of the most recent
      ``on_ready`` event. TUI returns its ``start()`` time.
    * ``recent_reconnect_count`` — Discord-specific recent-window counter.
      TUI returns ``0`` (no reconnect concept).

    Slice-3's MCP transport carries an analogous shape so the supervisor
    can compare adapter health across transports uniformly.
    """

    gateway_connected: bool
    last_on_ready_at: datetime | None
    recent_reconnect_count: int


@runtime_checkable
class CommsAdapter(Protocol):
    """Comms-adapter lifecycle + health surface.

    The supervisor (Slice-2: ``_chat_main``; Slice-3+: a real supervisor)
    drives every adapter through this Protocol. Three async lifecycle
    methods plus a synchronous health-snapshot accessor.

    ``name`` is the stable adapter identity used in audit rows + the
    supervisor's status table. It MUST match the value of
    :class:`alfred.identity.models.Platform` for adapters that bind to a
    platform-native id (e.g. ``"tui"``, ``"discord"``) so identity
    resolution and adapter routing share one vocabulary.
    """

    name: str

    async def start(self) -> None:
        """Bring the adapter to a ready-to-serve state.

        Must be idempotent: a re-``start()`` after a clean ``stop()``
        returns the adapter to a runnable state. Raises on hard-failure
        configuration errors (e.g. the operator row is missing — the TUI
        surfaces ``t("cli.user.error.no_operator")`` per ADR-0009).
        """
        raise NotImplementedError

    async def run(self) -> None:
        """Run the adapter's main loop until ``stop()`` is called.

        For the TUI this delegates to ``AlfredTuiApp.run_async()``; for
        Discord (PR D2) this awaits the gateway connection forever. The
        coroutine returns cleanly when ``stop()`` has been requested.
        """
        raise NotImplementedError

    async def stop(self) -> None:
        """Request a clean shutdown of the adapter's main loop.

        Must be idempotent. A second ``stop()`` is a no-op so the
        supervisor can drive the shutdown sequence without tracking which
        adapters have already finished.
        """
        raise NotImplementedError

    def health(self) -> AdapterHealth:
        """Return a synchronous health snapshot.

        Synchronous because the supervisor's status table reads it from a
        non-async surface (the ``alfred status`` Typer command). The
        snapshot is immutable; callers don't see torn reads even if the
        adapter is mid-reconnect when the snapshot is taken.
        """
        raise NotImplementedError


def build_tui_adapter(
    *,
    orchestrator: _OrchestratorLike,
    identity_resolver: _IdentityResolverLike,
    outbound_dlp: OutboundDlp,
    rate_limiter: RateLimiter,
    broker: SecretBroker,
    working_pool: _WorkingPoolLike,
) -> CommsAdapter:
    """Factory for the Slice-2 TUI adapter.

    Returns a :class:`CommsAdapter` Protocol — the concrete class
    ``TuiAdapter`` is an implementation detail intentionally NOT
    re-exported from this module. The CLI bootstrap calls this factory
    rather than ``TuiAdapter(...)`` directly so the adapter-import
    boundary test stays clean: every consumer reaches the concrete class
    indirectly through this allowlisted module.

    PR D2 ships ``build_discord_adapter(...)`` alongside this factory
    for the Discord adapter; same shape, same return type.
    """
    # Local import keeps the heavy ``alfred.comms.tui_adapter`` (and via
    # it, Textual) off the import path of pure consumers like
    # ``alfred status`` that never construct a TUI.
    from alfred.comms.tui_adapter import TuiAdapter

    return TuiAdapter(
        orchestrator=orchestrator,
        identity_resolver=identity_resolver,
        outbound_dlp=outbound_dlp,
        rate_limiter=rate_limiter,
        broker=broker,
        working_pool=working_pool,
    )
