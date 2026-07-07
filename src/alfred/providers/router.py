"""Slice-1 provider router. Primary + optional fallback. No tiered routing yet."""

from __future__ import annotations

import structlog

from alfred.providers.base import (
    CompletionRequest,
    CompletionResponse,
    Provider,
    ProviderMalformedToolArgumentsError,
    ProviderToolNameCollisionError,
    ProviderToolUnsupportedError,
)

_log = structlog.get_logger()

# Provider tool-protocol errors are NOT transient provider failures, so the
# router must NOT try the fallback on them (that would mask the real cause).
# A tool-name collision is a deterministic config error: the fallback builds
# the SAME name-map from the SAME tools and would raise identically — retrying
# it is pointless and mislabels the cause, so it re-raises here too.
_TOOL_PROTOCOL_ERRORS = (
    ProviderToolUnsupportedError,
    ProviderMalformedToolArgumentsError,
    ProviderToolNameCollisionError,
)


class ProviderRouter:
    """Try the primary; on exception, try the fallback (if any)."""

    def __init__(self, *, primary: Provider, fallback: Provider | None = None) -> None:
        self._primary = primary
        self._fallback = fallback

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        try:
            return await self._primary.complete(request)
        except _TOOL_PROTOCOL_ERRORS as tool_exc:
            # A capability refusal is operator misconfiguration; a malformed
            # tool-call response must reach the act-phase loop (#339 PR3) as an
            # error tool_result. Blindly falling back would mask both (spec §4.1,
            # §4.3). Log loud and re-raise rather than trying the fallback.
            _log.warning(
                "provider.tool_protocol_error",
                primary=self._primary.name,
                error_type=type(tool_exc).__name__,
            )
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
