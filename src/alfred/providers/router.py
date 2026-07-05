"""Slice-1 provider router. Primary + optional fallback. No tiered routing yet."""

from __future__ import annotations

import structlog

from alfred.providers.base import (
    CompletionRequest,
    CompletionResponse,
    Provider,
    ProviderToolUnsupportedError,
)

_log = structlog.get_logger()


class ProviderRouter:
    """Try the primary; on exception, try the fallback (if any)."""

    def __init__(self, *, primary: Provider, fallback: Provider | None = None) -> None:
        self._primary = primary
        self._fallback = fallback

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        try:
            return await self._primary.complete(request)
        except ProviderToolUnsupportedError:
            # A capability refusal is a loud operator-misconfiguration signal,
            # NOT a transient failure — do NOT silently paper over it by using
            # the fallback for every tool turn (spec §4.1; "no capability
            # routing"). Re-raise so the caller sees the misconfiguration.
            raise
        # Broad except is intentional at the fallback boundary: provider SDKs
        # raise different exception hierarchies across versions, and slice 1's
        # stance is "primary fails -> try fallback once". Tiered routing in a
        # later slice will tighten this with capability-aware classification.
        except Exception as exc:
            if self._fallback is None:
                raise
            _log.warning(
                "provider.primary.failed",
                primary=self._primary.name,
                fallback=self._fallback.name,
                error=str(exc),
            )
            return await self._fallback.complete(request)
