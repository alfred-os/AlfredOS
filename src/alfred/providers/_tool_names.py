"""Sanitize AlfredOS's canonical dotted tool names for the provider SDK
function-name grammar, and reverse the mapping when parsing a tool-call
response back into AlfredOS's canonical name space.

AlfredOS's tool registry, audit rows, and i18n keys are all keyed on the
canonical dotted name (``web.fetch``, ``clock.now`` — see
``alfred.orchestrator.builtin_tools``). OpenAI/DeepSeek require function
names matching ``^[a-zA-Z0-9_-]+$`` and Anthropic requires
``^[a-zA-Z0-9_-]{1,64}$``; both forbid dots, so a raw ``tool.name`` 400s at
the first live call. The 64-char bound is ENFORCED here (not just cited) —
a canonical name whose char-class-sanitized form exceeds 64 chars (a real
future case: MCP tool names of the shape
``mcp__plugin_{name}_{server}__{tool}`` routinely exceed it) is truncated
and disambiguated with a content hash so it still fits both grammars.
Sanitization is applied ONLY at the provider<->SDK boundary
(``deepseek.py`` / ``anthropic_native.py``); every other subsystem keeps
seeing the canonical dotted name — this module is single-purpose so that
boundary can't leak.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence

from alfred.i18n import t
from alfred.providers.base import ProviderToolNameCollisionError, ToolDefinition

# Everything OUTSIDE this character class is replaced with "_". This is the
# intersection of the OpenAI/DeepSeek grammar (^[a-zA-Z0-9_-]+$) and the
# Anthropic grammar (^[a-zA-Z0-9_-]{1,64}$) — sanitizing to the intersection
# means the same pass is safe to reuse across both adapters.
_UNSAFE_TOOL_NAME_CHAR = re.compile(r"[^a-zA-Z0-9_-]")

# Anthropic's hard upper bound (^[a-zA-Z0-9_-]{1,64}$); OpenAI/DeepSeek have
# no length bound, so enforcing the tighter one keeps a single sanitized
# name valid on both wires.
_MAX_PROVIDER_TOOL_NAME_LENGTH = 64

# Truncated names keep this many original characters, leaving room for the
# "_" separator + 8 hex digits of disambiguating hash so the total stays
# within _MAX_PROVIDER_TOOL_NAME_LENGTH (55 + 1 + 8 == 64).
_TRUNCATED_PREFIX_LENGTH = 55
_HASH_DIGEST_LENGTH = 8


def sanitize_tool_name(name: str) -> str:
    """Sanitize ``name`` into the provider-safe grammar ``^[a-zA-Z0-9_-]{1,64}$``.

    Pure and deterministic. First replaces every character outside
    ``[a-zA-Z0-9_-]`` with ``_`` (``web.fetch`` -> ``web_fetch``,
    ``clock.now`` -> ``clock_now``); idempotent on an already-safe name (no
    unsafe character -> no substitution). If the result exceeds
    :data:`_MAX_PROVIDER_TOOL_NAME_LENGTH`, it is truncated to
    :data:`_TRUNCATED_PREFIX_LENGTH` characters and suffixed with an
    8-hex-digit sha1 digest of the ORIGINAL (pre-sanitize) ``name`` — this
    keeps the result deterministic (same input -> same output) while
    disambiguating two distinct long names that happen to share the same
    truncated prefix.
    """
    safe = _UNSAFE_TOOL_NAME_CHAR.sub("_", name)
    if len(safe) > _MAX_PROVIDER_TOOL_NAME_LENGTH:
        digest = hashlib.sha1(name.encode(), usedforsecurity=False).hexdigest()[
            :_HASH_DIGEST_LENGTH
        ]
        safe = f"{safe[:_TRUNCATED_PREFIX_LENGTH]}_{digest}"
    return safe


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
