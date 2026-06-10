"""Discord adapter lifecycle handlers: ``lifecycle.start`` / ``stop`` / ``health``.

``DiscordLifecycle`` is the stateful machine the MCP server's request handlers
dispatch into. It:

* authenticates by fetching ``discord_bot_token`` from the injected secret
  broker — NEVER reading the token from the process environment directly, and
  NEVER logging the token bytes (the structlog events below carry only the
  ``error_class``, never the secret);
* opens the Discord WSS through an injected ``GatewayProtocol`` seam. The real
  ``discord.Client`` wrapper lands in Wave 3 (``discord_gateway.py``); injecting
  the seam keeps the lifecycle logic unit-testable without a live gateway;
* reports the ADR-0024 protocol-model results
  (:class:`LifecycleStartResult` / :class:`LifecycleStopResult` /
  :class:`HealthReport`) so the wire contract matches the host exactly.

structlog event names stay English + machine-readable (closure i18n-2's explicit
carve-out for log lines); no user-facing ``t()`` string originates here.
"""

from __future__ import annotations

import asyncio
from typing import Final, Protocol

import structlog

from alfred.comms_mcp.protocol import HealthReport, LifecycleStartResult, LifecycleStopResult

_log = structlog.get_logger(__name__)

# Self-reported adapter version (spec §8.1), threaded into the host's lifecycle
# audit. Module-level constant mirrors the reference plugin's precedent.
_PLUGIN_VERSION: Final[str] = "0.1.0"

# The broker key (a secret IDENTIFIER, not a secret value) the adapter fetches
# at lifecycle.start. The broker substitutes the real bytes; this code never
# holds a hardcoded credential.
_BROKER_KEY: Final[str] = "discord_bot_token"


class GatewayError(RuntimeError):
    """Raised by a :class:`GatewayProtocol` implementation on connect failure.

    The message must never embed the bot token — the lifecycle handler logs only
    the exception's class name, not its rendered text, to keep the redaction
    contract trivially auditable.
    """


class BrokerProtocol(Protocol):
    """The subset of ``SecretBroker`` the lifecycle needs (token fetch)."""

    def get(self, name: str) -> str: ...


class GatewayProtocol(Protocol):
    """The Discord WSS seam the lifecycle drives (Wave-3 ``discord_gateway.py``)."""

    async def connect(self, token: str) -> None: ...

    async def close(self) -> int: ...

    @property
    def queue_depth(self) -> int: ...


class DiscordLifecycle:
    """Stateful lifecycle machine for the Discord adapter (one subprocess lifetime)."""

    def __init__(self, *, broker: BrokerProtocol, gateway: GatewayProtocol) -> None:
        self._broker = broker
        self._gateway = gateway
        self._running = False
        self._error_count = 0
        # Serialises ``start`` / ``stop`` transitions. Without it two overlapping
        # ``start`` calls can both pass the ``_running`` check and both open the
        # gateway, and a ``stop`` can interleave mid-start — duplicating sessions
        # or tearing down a half-opened gateway. The lock makes the check + the
        # gateway call + the ``_running`` update one atomic transition.
        self._transition_lock = asyncio.Lock()

    async def start(self) -> LifecycleStartResult:
        """Authenticate + open the gateway; idempotent and serialized.

        A failure — broker, transport, or gateway — is reported as ``ok=False``
        (never a raised exception across the wire) with a loud, secret-free
        structlog event so the supervisor can act. The transition is serialised
        under ``_transition_lock`` so concurrent callers cannot open the gateway
        twice or race a ``stop``.
        """
        async with self._transition_lock:
            if self._running:
                # Idempotent: a repeated start does not reopen the gateway.
                return LifecycleStartResult(ok=True, plugin_version=_PLUGIN_VERSION)

            try:
                # Fetch the secret INSIDE the try: a missing broker secret (or any
                # broker/transport error) must surface as ``ok=False``, never as a
                # raised exception across the RPC boundary.
                token = self._broker.get(_BROKER_KEY)
                await self._gateway.connect(token)
            except Exception as exc:  # wire contract: never raise across the RPC boundary
                self._error_count += 1
                # Log the error CLASS only — never the rendered message (which a
                # buggy gateway/broker could let leak the token) and never the
                # token itself.
                _log.error(
                    "comms.lifecycle.start_failed",
                    adapter="discord",
                    error_class=type(exc).__name__,
                )
                return LifecycleStartResult(ok=False, plugin_version=_PLUGIN_VERSION)

            self._running = True
            _log.info("comms.lifecycle.started", adapter="discord")
            return LifecycleStartResult(ok=True, plugin_version=_PLUGIN_VERSION)

    async def stop(self) -> LifecycleStopResult:
        """Close the gateway, flushing in-flight outbound; report the flushed count.

        Serialised under the same ``_transition_lock`` as :meth:`start` so a stop
        cannot interleave with a concurrent start and leave a half-open gateway.
        """
        async with self._transition_lock:
            flushed = await self._gateway.close()
            self._running = False
            _log.info("comms.lifecycle.stopped", adapter="discord", flushed_messages=flushed)
            return LifecycleStopResult(ok=True, flushed_messages=flushed)

    def health(self) -> HealthReport:
        """Report a health snapshot: running state + queue depth + error count.

        ``last_inbound_at`` is ``None`` in Wave 2 — the inbound-receipt timestamp
        is threaded in by Wave 3's gateway event loop.
        """
        return HealthReport(
            ok=self._running,
            last_inbound_at=None,
            queue_depth=self._gateway.queue_depth,
            error_count=self._error_count,
        )


__all__ = [
    "BrokerProtocol",
    "DiscordLifecycle",
    "GatewayError",
    "GatewayProtocol",
]
