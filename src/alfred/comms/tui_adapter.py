"""TuiAdapter — the Slice-2 wrap around :class:`AlfredTuiApp`.

The CLI bootstrap (``_chat_main`` in ``src/alfred/cli/main.py``) constructs
this adapter rather than ``AlfredTuiApp`` directly so the consumer side
of the comms layer depends only on the
:class:`alfred.comms.adapter.CommsAdapter` Protocol. PR D2's
``DiscordAdapter`` will plug into the same supervisor surface with the
same inject set, and the Slice-3 MCP-transport rewrite (ADR-0009)
rewrites this seam without touching the CLI call site.

The constructor inject set is the canonical Slice-2 shape:

* ``orchestrator`` — handles user turns.
* ``identity_resolver`` — resolves the platform-native id to a canonical
  :class:`User`.
* ``outbound_dlp`` — every adapter outbound passes through this (PR D1
  contract).
* ``rate_limiter`` — every adapter inbound runs through ``allow()`` even
  for the operator (so the path-shape parity test catches a future
  regression).
* ``broker`` — secret broker handle, threaded through for adapters that
  need direct secret access at run time (the TUI does not, but the
  Discord adapter will).
* ``working_pool`` — pool-acquired :class:`WorkingMemory` per turn, in
  the same shape PR-B Phase 5 introduced.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

# Import ``AdapterHealth`` from the leaf ``_types`` module rather than
# ``alfred.comms.adapter`` to avoid the static cycle CodeQL flagged:
# ``adapter`` -> ``tui_adapter`` (lazy, inside ``build_tui_adapter``) and
# ``tui_adapter`` -> ``adapter`` (eager, for the dataclass) formed a
# diamond at static-analysis time.
from alfred.comms._types import AdapterHealth
from alfred.comms.tui import (
    AlfredTuiApp,
    _IdentityResolverLike,
    _OrchestratorLike,
    _WorkingPoolLike,
)

if TYPE_CHECKING:
    from alfred.identity.rate_limit import RateLimiter
    from alfred.security.dlp import OutboundDlp
    from alfred.security.secrets import SecretBroker


class TuiAdapter:
    """Wraps :class:`AlfredTuiApp` behind the
    :class:`alfred.comms.adapter.CommsAdapter` Protocol.

    Lifecycle:

    * ``start()`` is a no-op for the TUI today — the slice-1 CLI already
      resolved the operator and constructed the app. Slice-3+ promotes
      identity resolution into ``start()`` so the adapter contract
      uniformly fails closed on a missing operator row.
    * ``run()`` delegates to ``AlfredTuiApp.run_async()`` — the Textual
      main loop.
    * ``stop()`` calls ``AlfredTuiApp.exit()``; safe to call before
      ``start()`` (Textual treats it as a no-op).
    """

    name: str = "tui"

    def __init__(
        self,
        *,
        orchestrator: _OrchestratorLike,
        identity_resolver: _IdentityResolverLike,
        outbound_dlp: OutboundDlp,
        rate_limiter: RateLimiter,
        broker: SecretBroker,
        working_pool: _WorkingPoolLike,
    ) -> None:
        # All five canonical injects PR D2 will take, plus the working
        # pool the slice-1 TUI already owns. The DLP / rate-limiter /
        # broker are unused by the existing AlfredTuiApp send loop in
        # Slice-2 — they live on the adapter so the inject set is
        # stable across PR D1 → PR D2 → Slice 3 (the Slice-3 MCP
        # transport plugs into the same shape).
        self._orchestrator = orchestrator
        self._identity_resolver = identity_resolver
        self._outbound_dlp = outbound_dlp
        self._rate_limiter = rate_limiter
        self._broker = broker
        self._working_pool = working_pool
        self._app: AlfredTuiApp | None = None
        self._started_at: datetime | None = None

    def _build_app(self) -> AlfredTuiApp:
        return AlfredTuiApp(
            orchestrator=self._orchestrator,
            identity_resolver=self._identity_resolver,
            working_pool=self._working_pool,
        )

    async def start(self) -> None:
        # Idempotent: a re-start (e.g. after a clean stop) rebuilds the
        # app instance. Textual's App is single-shot — once ``exit()``
        # has been called it cannot be re-run, so we recreate.
        self._app = self._build_app()
        self._started_at = datetime.now(UTC)

    async def run(self) -> None:
        if self._app is None:
            # Defensive: a supervisor that calls ``run()`` before
            # ``start()`` is buggy, but the contract should still
            # fail loud rather than ``AttributeError`` on a None.
            raise RuntimeError("TuiAdapter.run() called before start()")
        await self._app.run_async()

    async def stop(self) -> None:
        # ``app.exit()`` is idempotent — Textual no-ops a second call.
        # Clear the handle after exit so ``health().gateway_connected``
        # flips back to False; otherwise the supervisor's status table
        # reports a dead adapter as "connected" and a future re-``start()``
        # (which rebuilds the app) would shadow the existing handle
        # without an explicit reset.
        if self._app is not None:
            self._app.exit()
            self._app = None

    def health(self) -> AdapterHealth:
        # TUI is "gateway-connected" while the Textual loop is alive
        # (i.e. ``start()`` ran). ``recent_reconnect_count`` is 0 by
        # design (no reconnect concept in-process).
        return AdapterHealth(
            gateway_connected=self._app is not None,
            last_on_ready_at=self._started_at,
            recent_reconnect_count=0,
        )
