"""The single named hookpoint for orchestrator tool dispatch (#339 PR2).

``dispatch_tool`` (a later PR2 task, not this module) gates every tool
call on ``gate.check(plugin_id=..., hookpoint="tool.dispatch",
requested_tier="system")``; the hookpoint is the audit-graph join key
(spec §10). Declared here — mirroring
:func:`alfred.security.capability_gate.proposals.declare_hookpoints` —
and registered in ``KNOWN_HOOKPOINTS`` so the manifest-sync test stays
green.

``carrier_tier=T0``: the dispatch decision itself is system-internal
attribution (which plugin, which hookpoint), not user- or web-sourced
content — the same rationale
:func:`alfred.security.capability_gate.proposals.declare_hookpoints`
uses for its ``plugin.grant.*`` hookpoints. This is deliberately NOT a
meta hookpoint (``carrier_tier=None`` is reserved for the
carrier-substitution observability pair in
:mod:`alfred.hooks._known_hookpoints`); ``tool.dispatch`` gates real
content-bearing dispatch, so it takes a concrete carrier tier like
every other content-gating hookpoint in the codebase.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from alfred.hooks.registry import SYSTEM_ONLY_TIERS, get_registry
from alfred.security.tiers import T0

if TYPE_CHECKING:
    from alfred.hooks.registry import HookRegistry

TOOL_DISPATCH_HOOKPOINT: Final[str] = "tool.dispatch"
# Stable attribution for the per-dispatch capability check (spec §10). The
# grant is seeded first-party; a real turn cannot dispatch a tool without it.
TOOL_DISPATCH_PLUGIN_ID: Final[str] = "alfred.orchestrator.tool_dispatch"


def declare_tool_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register ``tool.dispatch``. Idempotent on equal metadata.

    Mirrors the module-init discipline of
    :func:`alfred.security.capability_gate.proposals.declare_hookpoints`:
    publishers declare at module-init time, and the per-call shim
    makes the declaration discoverable by tests that swap the global
    registry singleton with a fresh instance.

    Args:
        registry: The :class:`HookRegistry` to declare against.
            Defaults to :func:`get_registry`'s active singleton; tests
            pass the fresh registry explicitly to be unambiguous.
    """
    target = registry if registry is not None else get_registry()
    target.register_hookpoint(
        name=TOOL_DISPATCH_HOOKPOINT,
        subscribable_tiers=SYSTEM_ONLY_TIERS,
        refusable_tiers=SYSTEM_ONLY_TIERS,
        fail_closed=True,
        # system-internal dispatch gating — T0 (NOT None: register_hookpoint
        # raises HookError for a non-meta hookpoint with carrier_tier=None).
        # Mirrors proposals.py's declare_hookpoints.
        carrier_tier=T0,
    )


# Module-init declaration — mirrors alfred.security.capability_gate.proposals'
# bottom-of-module call so the KNOWN_HOOKPOINTS import-sweep sync test
# (tests/unit/hooks/test_known_hookpoints_sync.py) sees tool.dispatch
# registered at runtime. Idempotent on equal metadata, so re-importing
# under pytest test isolation is safe.
declare_tool_hookpoints()
