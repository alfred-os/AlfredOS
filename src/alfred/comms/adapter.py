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

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

# ``AdapterHealth`` lives in a leaf module so both this Protocol module
# and ``alfred.comms.tui_adapter`` can import it without forming the
# static import cycle CodeQL flagged on PR D1. The symbol is re-exported
# below for backwards compatibility with consumers that already do
# ``from alfred.comms.adapter import AdapterHealth``.
from alfred.comms._types import AdapterHealth

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.comms.tui import _IdentityResolverLike, _OrchestratorLike, _WorkingPoolLike
    from alfred.identity.rate_limit import RateLimiter
    from alfred.identity.resolver import IdentityResolver
    from alfred.memory.working_pool import WorkingMemoryPool
    from alfred.orchestrator.core import Orchestrator
    from alfred.security.dlp import OutboundDlp
    from alfred.security.secrets import SecretBroker


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


async def run_discord_verify_probe(
    *,
    broker: SecretBroker,
    outbound_dlp: OutboundDlp,
    timeout_s: float,
    client_factory: Any = None,
) -> tuple[int, str, Mapping[str, object]]:
    """Allowlisted seam for the ``alfred discord verify`` subcommand.

    The CLI cannot import :mod:`alfred.comms.discord` directly — the
    import-isolation test locks the allowlist to three modules. This
    function lives inside the allowlisted ``alfred.comms.adapter``
    module so the CLI consumes only the public seam.

    Returns ``(exit_code, event_key, event_kwargs)``. The exit code is
    the typed verify-exit value (0/1/2/3/4/130). The CLI maps it onto
    its own ``_VerifyExitCode`` enum and emits the structlog event with
    the returned key + kwargs.

    Deferred import: the heavy ``discord.py`` import stays inside
    :mod:`alfred.comms.discord`, so importing this seam does not pay
    the gateway-client cost until ``alfred discord verify`` actually
    runs.
    """
    from alfred.comms.discord import run_verify_probe

    return await run_verify_probe(
        broker=broker,
        outbound_dlp=outbound_dlp,
        timeout_s=timeout_s,
        client_factory=client_factory,
    )


def build_discord_adapter(
    *,
    orchestrator: Orchestrator,
    identity_resolver: IdentityResolver,
    broker: SecretBroker,
    outbound_dlp: OutboundDlp,
    rate_limiter: RateLimiter,
    working_pool: WorkingMemoryPool,
    audit: AuditWriter,
) -> CommsAdapter:
    """Factory for the Slice-2 Discord adapter.

    Mirrors :func:`build_tui_adapter` — returns the
    :class:`CommsAdapter` Protocol so callers in ``src/alfred/cli/``
    consume only the allowlisted seam. The concrete
    :class:`alfred.comms.discord.DiscordAdapter` is intentionally NOT
    re-exported from this module: the import-isolation test
    (``tests/unit/comms/test_no_direct_adapter_imports.py``) locks the
    allowlist to three modules; this factory keeps the CLI bootstrap
    on the right side of that boundary.

    The local import avoids dragging ``discord.py`` (and via it
    ``aiohttp``, ``yarl``, …) into the import path of consumers like
    ``alfred status`` that never spin up the Discord gateway.
    """
    from alfred.comms.discord import DiscordAdapter

    return cast(
        "CommsAdapter",
        DiscordAdapter(
            orchestrator=orchestrator,
            identity_resolver=identity_resolver,
            broker=broker,
            outbound_dlp=outbound_dlp,
            rate_limiter=rate_limiter,
            working_pool=working_pool,
            audit=audit,
        ),
    )
