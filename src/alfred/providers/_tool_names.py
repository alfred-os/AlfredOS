"""Sanitize AlfredOS's canonical dotted tool names for the provider SDK
function-name grammar, and reverse the mapping when parsing a tool-call
response back into AlfredOS's canonical name space.

AlfredOS's tool registry, audit rows, and i18n keys are all keyed on the
canonical dotted name (``web.fetch``, ``clock.now`` — see
``alfred.orchestrator.builtin_tools``). OpenAI/DeepSeek require function
names matching ``^[a-zA-Z0-9_-]+$`` and Anthropic requires
``^[a-zA-Z0-9_-]{1,64}$``; both forbid dots, so a raw ``tool.name`` 400s at
the first live call. Sanitization is applied ONLY at the provider<->SDK
boundary (``deepseek.py`` / ``anthropic_native.py``); every other subsystem
keeps seeing the canonical dotted name — this module is single-purpose so
that boundary can't leak.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from alfred.i18n import t
from alfred.providers.base import ProviderToolNameCollisionError, ToolDefinition

# Everything OUTSIDE this character class is replaced with "_". This is the
# intersection of the OpenAI/DeepSeek grammar (^[a-zA-Z0-9_-]+$) and the
# Anthropic grammar (^[a-zA-Z0-9_-]{1,64}$) — sanitizing to the intersection
# means the same pass is safe to reuse across both adapters.
_UNSAFE_TOOL_NAME_CHAR = re.compile(r"[^a-zA-Z0-9_-]")


def sanitize_tool_name(name: str) -> str:
    """Replace every character outside ``[a-zA-Z0-9_-]`` with ``_``.

    Pure and deterministic; idempotent on an already-safe name (no unsafe
    character -> no substitution, so re-sanitizing a sanitized name is a
    no-op). ``web.fetch`` -> ``web_fetch``, ``clock.now`` -> ``clock_now``.
    """
    return _UNSAFE_TOOL_NAME_CHAR.sub("_", name)


def build_tool_name_map(tools: Sequence[ToolDefinition]) -> Mapping[str, str]:
    """Build ``{provider_safe_name: canonical_name}`` for one request's tools.

    Threaded into each adapter's response parser so a provider echoing back
    ``web_fetch`` reverse-maps to the canonical ``web.fetch`` the rest of
    AlfredOS (tool-registry dispatch, audit rows, i18n keys) expects.

    Raises :class:`~alfred.providers.base.ProviderToolNameCollisionError` if
    two DISTINCT canonical names sanitize to the same provider-safe name.
    The same canonical name appearing more than once (e.g. a caller-side
    duplicate) is not a collision — it maps to itself unambiguously.
    """
    safe_to_canonical: dict[str, str] = {}
    for tool in tools:
        safe = sanitize_tool_name(tool.name)
        existing = safe_to_canonical.get(safe)
        if existing is not None and existing != tool.name:
            raise ProviderToolNameCollisionError(
                t(
                    "providers.tool_name_collision",
                    name_a=existing,
                    name_b=tool.name,
                    safe_name=safe,
                )
            )
        safe_to_canonical[safe] = tool.name
    return safe_to_canonical
