"""Canonical declaration registry of every AlfredOS hookpoint name.

Imported eagerly by the CLI validator (issue #151). Independent of
which subsystems happen to be imported by the running process — a
property the runtime registry's ``_hookpoints`` dict does NOT have
(#149 CR-1).

Sync invariant: every name listed here MUST be registered by exactly
one subsystem's ``declare_hookpoints()`` (or equivalent eager-init
call) at runtime. Pinned by
``tests/unit/hooks/test_known_hookpoints_sync.py``: any drift between
the manifest and the runtime registry after a full subsystem-import
sweep fails the test.

Grouping: by declaring module so a future addition lands in one
place. The grouping is canonical for two consumers — operator-facing
documentation and the drift-detector test
(``tests/unit/hooks/test_known_hookpoints_sync.py``, which walks
``KNOWN_HOOKPOINTS.keys()`` to know which subsystems to import). The
CLI validator's hot path consults the flat tuple returned by
:func:`all_known_hookpoints` rather than the per-subsystem dict, so
both members of ``__all__`` are public-by-design.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

# PR-S4-3 (ADR-0022): the carrier-substitution meta-hookpoint names.
# Module-level constants so the manifest tuple and
# ``declare_meta_hookpoints`` share one source of truth (no string
# duplication that could drift).
CARRIER_SUBSTITUTED_HOOKPOINT: Final[str] = "hooks.carrier_substituted"
CARRIER_SUBSTITUTION_REFUSED_HOOKPOINT: Final[str] = "hooks.carrier_substitution_refused"

# Hand-maintained source of truth. Adding a new hookpoint:
#
# 1. Decide the declaring subsystem (the module whose
#    ``declare_hookpoints()`` / equivalent eager-init call will
#    register the name).
# 2. Append the name to that subsystem's tuple below.
# 3. The sync test (``tests/unit/hooks/test_known_hookpoints_sync.py``)
#    will fail loud if the runtime registry — after importing every
#    listed subsystem — does not contain exactly this flat set.
#
# The supervisor's hookpoints are registered inside
# :meth:`alfred.supervisor.core.Supervisor._register_hookpoints` rather
# than a module-level ``declare_hookpoints()`` (core-010 rejected
# import-time registration for that subsystem to keep test isolation
# clean). The sync test reaches them via
# ``Supervisor._register_hookpoints(object())`` — the method body only
# uses ``self`` to dispatch to ``register_hookpoint`` on the global
# registry, not to read any instance state, so the bare-object dispatch
# is safe.
KNOWN_HOOKPOINTS: Final[Mapping[str, tuple[str, ...]]] = {
    "alfred.memory.episodic": (
        "memory.episodic.record.before_validate",
        "memory.episodic.record.before_db_write",
        "memory.episodic.record.after_flush",
        "memory.episodic.record.write_failed",
        "memory.episodic.record.cancelled",
    ),
    "alfred.identity._ingest": (
        "identity.t1_ingress",
        "identity.t1_downgrade",
    ),
    "alfred.security.capability_gate.proposals": (
        "plugin.grant.requested",
        "plugin.grant.approved",
        "plugin.grant.denied",
        "plugin.grant.revoked",
    ),
    "alfred.security.quarantine": ("security.quarantined.extract",),
    "alfred.plugins.web_fetch": ("tool.web.fetch",),
    "alfred.supervisor.core": (
        "supervisor.breaker.tripped",
        "supervisor.breaker.reset",
        "supervisor.action_timeout",
        "plugin.lifecycle.loaded",
        "plugin.lifecycle.crashed",
        "plugin.lifecycle.quarantined",
    ),
    # PR-S4-3 (ADR-0022): the two observation-only carrier-substitution
    # meta-hookpoints. They describe the substitution machinery itself
    # and carry carrier_tier=None + allow_error_substitution=False so
    # they cannot recurse. Registered by ``declare_meta_hookpoints``.
    "alfred.hooks._known_hookpoints": (
        CARRIER_SUBSTITUTED_HOOKPOINT,
        CARRIER_SUBSTITUTION_REFUSED_HOOKPOINT,
    ),
}


def all_known_hookpoints() -> tuple[str, ...]:
    """Return every declared hookpoint name as a flat tuple.

    Order matches the manifest's grouping (subsystem -> names).
    The CLI validator consults this on every call.
    """
    return tuple(name for names in KNOWN_HOOKPOINTS.values() for name in names)


def declare_meta_hookpoints(registry: object | None = None) -> None:
    """Register the two observation-only carrier-substitution meta-hookpoints.

    PR-S4-3 (ADR-0022). Both meta-hookpoints carry ``carrier_tier=None``
    and ``allow_error_substitution=False`` so a subscriber against them
    cannot substitute the meta-event's payload — closing the recursion
    loop the recoverable-carrier semantic would otherwise open.

    Called once at bootstrap by the same orchestrator that fires the
    per-subsystem ``declare_hookpoints()`` calls. Idempotent on equal
    metadata (the registry's standard re-declaration guard).

    Args:
        registry: The :class:`alfred.hooks.registry.HookRegistry` to
            declare against. Defaults to the process singleton via
            :func:`alfred.hooks.get_registry`.
    """
    from alfred.hooks import get_registry
    from alfred.hooks.registry import SYSTEM_ONLY_TIERS, HookRegistry

    # Fail fast on a wrong-typed injection (CR closure): ``None`` means
    # "use the process singleton", a real ``HookRegistry`` is used as-is,
    # but any OTHER object is a caller bug — silently falling back to the
    # global singleton would mask it and mutate global state unexpectedly.
    if registry is None:
        reg: HookRegistry = get_registry()
    elif isinstance(registry, HookRegistry):
        reg = registry
    else:
        raise TypeError(
            f"declare_meta_hookpoints(registry=) expects a HookRegistry or None, "
            f"got {type(registry).__name__}"
        )
    for name in (CARRIER_SUBSTITUTED_HOOKPOINT, CARRIER_SUBSTITUTION_REFUSED_HOOKPOINT):
        reg.register_hookpoint(
            name=name,
            subscribable_tiers=SYSTEM_ONLY_TIERS,
            refusable_tiers=frozenset(),
            fail_closed=False,
            carrier_tier=None,
            allow_error_substitution=False,
        )


__all__ = ["KNOWN_HOOKPOINTS", "all_known_hookpoints", "declare_meta_hookpoints"]
