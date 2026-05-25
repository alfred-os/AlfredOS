"""Slice-1 provider router. Primary + optional fallback. No tiered routing yet."""

from __future__ import annotations

import structlog

from alfred.providers.base import CompletionRequest, CompletionResponse, Provider

_log = structlog.get_logger()


class ProviderRouter:
    """Try the primary; on exception, try the fallback (if any)."""

    def __init__(self, *, primary: Provider, fallback: Provider | None = None) -> None:
        self._primary = primary
        self._fallback = fallback

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        try:
            return await self._primary.complete(request)
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
