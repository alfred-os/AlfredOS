"""Outbound send-path → ``OutboundMessageResult`` (Task F2, PR-S4-9 #206).

:class:`OutboundHandler` consumes a host ``OutboundMessageRequest`` and returns
the ADR-0024 ``OutboundMessageResult`` discriminated union. It owns four
trust-boundary-adjacent responsibilities:

1. **Restart-survivable idempotency.** A redelivered request (same host-minted
   ``idempotency_key``) returns the cached ``_OutboundDelivered`` WITHOUT hitting
   Discord again, even across a plugin crash+respawn (the store is on-disk).
2. **Addressing-mode routing.** ``dm`` / ``mention`` / ``channel`` / ``thread``
   each resolve to the right Discord target via the injected
   :class:`TargetResolver` seam; ``mention`` prefixes the body with Discord's
   ``<@id>`` mention syntax.
3. **Failure mapping.** discord.py's send exceptions map onto the union:
   ``HTTPException(429)`` → ``_OutboundRetryable`` (with the platform's
   ``retry_after``, rounded UP); other 5xx → ``_OutboundRetryable`` with a
   default backoff; ``Forbidden`` / ``NotFound`` / ``InvalidData`` →
   ``_OutboundTerminal``.
4. **In-plugin DLP-lite.** ``_OutboundTerminal.detail_redacted`` is scrubbed
   (closure sec-2) so a leaked secret in an exception string never crosses
   stdio raw; the host re-scans on receive.

The handler resolves the send target through an injected ``TargetResolver`` (the
gateway provides the real one) so it is unit-testable without a live gateway.
The body text is the DLP-scanned ``req.body[0]`` — the redacted string the host
minted via ``OutboundDlp.scan_for_outbound``; the adapter never re-scans, never
un-redacts.
"""

from __future__ import annotations

import math
from typing import Protocol

import discord
import structlog

from alfred.comms_mcp.protocol import (
    OutboundMessageRequest,
    OutboundMessageResult,
    PersonaAddressingMode,
    _OutboundDelivered,
    _OutboundRetryable,
    _OutboundTerminal,
)
from plugins.alfred_discord.dlp_lite import scrub_in_plugin
from plugins.alfred_discord.idempotency_store import IdempotencyStore

_log = structlog.get_logger(__name__)

# Default backoff for a non-429 retryable failure (5xx) where the platform gives
# no explicit ``retry_after``. A conservative fixed pause the host's OutboundQueue
# honours before requeueing.
_DEFAULT_RETRY_AFTER_SECONDS = 5

# Bound for the terminal-failure detail field (matches the wire schema's
# ``Field(max_length=256)``); the scrubbed string is truncated to fit.
_DETAIL_MAX_LEN = 256


class _Sendable(Protocol):
    """A resolved Discord send target (``User`` / ``TextChannel`` / ``Thread``)."""

    async def send(self, content: str) -> discord.Message: ...


class TargetResolver(Protocol):
    """Resolves a ``target_platform_id`` + ``addressing_mode`` to a send target.

    The gateway implements this against the live ``discord.Client`` (fetching the
    user / channel / thread). Injecting it keeps :class:`OutboundHandler` free of
    any live-gateway dependency.
    """

    async def resolve(
        self, target_platform_id: str, addressing_mode: PersonaAddressingMode
    ) -> _Sendable: ...


class OutboundHandler:
    """Stateful send-path: dedupe → resolve → send → map outcome."""

    def __init__(self, *, resolver: TargetResolver, store: IdempotencyStore) -> None:
        self._resolver = resolver
        self._store = store

    async def handle_outbound(self, req: OutboundMessageRequest) -> OutboundMessageResult:
        """Deliver ``req`` to Discord, returning the typed delivery outcome."""
        key = str(req.idempotency_key)

        cached = self._store.lookup(key)
        if cached is not None:
            # Redelivery: the host already saw this key succeed. Return the
            # recorded result without a second platform send.
            _log.info("comms.outbound.deduped", adapter=req.adapter_id)
            return _OutboundDelivered(outcome="delivered", platform_message_id=cached)

        # ``body`` is the DLP-scanned ScannedOutboundBody tuple: index 0 is the
        # redacted text the host already minted. The adapter sends it verbatim.
        body_text = req.body[0]
        content = self._render(req.addressing_mode, req.target_platform_id, body_text)

        try:
            target = await self._resolver.resolve(req.target_platform_id, req.addressing_mode)
            sent = await target.send(content)
        except (discord.Forbidden, discord.NotFound) as exc:
            # Terminal HTTP subclasses — caught BEFORE the broader HTTPException
            # clause (except order is significant; these subclass HTTPException).
            return self._terminal(exc)
        except discord.HTTPException as exc:
            return self._map_http_exception(exc)
        except discord.InvalidData as exc:
            return self._terminal(exc)

        platform_message_id = str(sent.id)
        self._store.record(key, platform_message_id)
        _log.info("comms.outbound.delivered", adapter=req.adapter_id)
        return _OutboundDelivered(outcome="delivered", platform_message_id=platform_message_id)

    @staticmethod
    def _render(mode: PersonaAddressingMode, target_platform_id: str, body_text: str) -> str:
        """Render the wire body for ``mode`` — prefixing the @mention for ``mention``."""
        if mode == "mention":
            return f"<@{target_platform_id}> {body_text}"
        return body_text

    def _map_http_exception(self, exc: discord.HTTPException) -> OutboundMessageResult:
        """Map an ``HTTPException``: 429 → rate-limited retryable; else 5xx retryable.

        Note ``Forbidden`` / ``NotFound`` subclass ``HTTPException`` but are caught
        by the more specific ``except`` clause in :meth:`handle_outbound`, so this
        method only ever sees a non-terminal HTTP error.
        """
        status = getattr(exc, "status", None)
        if status == 429:
            retry_after = self._read_retry_after(exc)
            return _OutboundRetryable(
                outcome="retryable_failure",
                retry_after_seconds=retry_after,
                error_class="discord_rate_limited",
            )
        # Other HTTP errors (5xx, transient gateway errors) are retryable with a
        # default backoff.
        return _OutboundRetryable(
            outcome="retryable_failure",
            retry_after_seconds=_DEFAULT_RETRY_AFTER_SECONDS,
            error_class="discord_server_error",
        )

    @staticmethod
    def _read_retry_after(exc: discord.HTTPException) -> int:
        """Read the platform's ``retry_after`` (seconds), rounded UP to an int.

        discord.py does not expose ``retry_after`` as a native ``HTTPException``
        attribute (it reads it from the 429 response on the rate-limit path), so
        this reads it defensively: the attribute if present, else the
        ``Retry-After`` response header, else the default backoff. Rounded UP so
        the host never resumes BEFORE the platform's window elapses.
        """
        raw = getattr(exc, "retry_after", None)
        if raw is None:
            response = getattr(exc, "response", None)
            headers = getattr(response, "headers", None)
            if headers is not None:
                raw = headers.get("Retry-After")
        try:
            return math.ceil(float(raw)) if raw is not None else _DEFAULT_RETRY_AFTER_SECONDS
        except (TypeError, ValueError):
            return _DEFAULT_RETRY_AFTER_SECONDS

    def _terminal(self, exc: Exception) -> _OutboundTerminal:
        """Build a terminal-failure result with a DLP-scrubbed, bounded detail.

        sec-2: the exception string is scrubbed IN-PLUGIN before it can reach the
        wire ``detail_redacted`` field — a leaked secret never crosses stdio raw.
        """
        error_class = _TERMINAL_ERROR_CLASS.get(type(exc), "discord_terminal_failure")
        detail = scrub_in_plugin(str(exc))[:_DETAIL_MAX_LEN]
        _log.warning("comms.outbound.terminal", adapter="discord", error_class=error_class)
        return _OutboundTerminal(
            outcome="terminal_failure",
            error_class=error_class,
            detail_redacted=detail,
        )


_TERMINAL_ERROR_CLASS: dict[type[Exception], str] = {
    discord.Forbidden: "discord_forbidden",
    discord.NotFound: "discord_not_found",
    discord.InvalidData: "discord_invalid_data",
}


__all__ = ["OutboundHandler", "TargetResolver"]
