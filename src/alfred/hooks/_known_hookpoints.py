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
        # PR-S4-6 (ADR-0015): sandbox-launcher posture/refusal hookpoints.
        # All carrier_tier=T0; sandbox_refused is fail_closed=True, the two
        # boot rows are informational (fail_closed=False).
        "supervisor.plugin.sandbox_refused",
        # PR-S4-7: dev/test-only unsandboxed-exec observability row, the
        # sandbox_refused sibling. carrier_tier=T0 + fail_closed=True.
        "supervisor.plugin.sandbox_stub_used",
        "supervisor.boot.mlock_unavailable",
        "supervisor.boot.core_dumps_disabled",
    ),
    # PR-S4-1 (#174): the daemon-boot + dispatch-failure hookpoints. All
    # three are system-internal (carrier_tier=T0) + fail_closed=True.
    # Registered by ``alfred.cli.daemon.declare_hookpoints`` at module
    # import time (bottom-of-module call), mirroring
    # ``alfred.identity._ingest``.
    "alfred.cli.daemon": (
        "daemon.boot.completed",
        "daemon.boot.failed",
        "proposal.dispatch.failed",
    ),
    # PR-S4-3 (ADR-0022): the two observation-only carrier-substitution
    # meta-hookpoints. They describe the substitution machinery itself
    # and carry carrier_tier=None + allow_error_substitution=False so
    # they cannot recurse. Registered by ``declare_meta_hookpoints``.
    "alfred.hooks._known_hookpoints": (
        CARRIER_SUBSTITUTED_HOOKPOINT,
        CARRIER_SUBSTITUTION_REFUSED_HOOKPOINT,
    ),
    # PR-S4-4 (ADR-0023, #159): the PolicyWatcher's operational hookpoints.
    # All carrier_tier=T0 + fail_closed=True — system-internal config-reload
    # signals (no operator/untrusted content). Registered by
    # ``alfred.policies.watcher.declare_hookpoints`` at module import.
    # ``supervisor.config_watcher.degraded`` fires on the stat-failure
    # state-machine transition; ``policies.watcher.degraded`` fires when the
    # audit store is unwritable (closure sec-4 fallback).
    "alfred.policies.watcher": (
        "supervisor.config_reload",
        "supervisor.config_reload_rejected",
        "supervisor.config_watcher.recovered",
        "supervisor.config_watcher.degraded",
        "policies.watcher.degraded",
    ),
    # PR-S4-5 (#153): the operator-session lifecycle hookpoints. All three
    # carry carrier_tier=T1 (operator-attributable content: user_id, host,
    # machine_id_hash) + fail_closed=True. Registered by
    # ``alfred.identity.operator_session.declare_hookpoints`` at module
    # import (bottom-of-module call), mirroring ``alfred.cli.daemon``.
    "alfred.identity.operator_session": (
        "operator.session.created",
        "operator.session.revoked",
        "operator.session.refused",
    ),
    # PR-S4-8 (#152, spec §10): the two comms-MCP hookpoints. Both
    # fail_closed=True + allow_error_substitution=False.
    # ``comms.inbound.t3_promoted`` carries carrier_tier=T3 (system+operator
    # subscribers only); ``comms.adapter.crashed`` carries carrier_tier=T0
    # (all tiers). Registered by ``alfred.comms_mcp.hookpoints.declare_hookpoints``
    # at module import (bottom-of-module call). The binding_requested /
    # rate_limit_signal hookpoints belong to PR-S4-9 (§3) and are NOT listed here.
    "alfred.comms_mcp.hookpoints": (
        "comms.inbound.t3_promoted",
        "comms.adapter.crashed",
    ),
    # PR-S4-9 (#206, spec §10): the two Discord comms-MCP hookpoints. Both
    # fail_closed=False + allow_error_substitution=True.
    # ``comms.adapter.binding_requested`` carries carrier_tier=T3 (system+operator
    # subscribers — hashed identity metadata only, never the raw T3 body);
    # ``comms.adapter.rate_limit_signal`` carries carrier_tier=T0 (operational
    # signal). Registered by ``alfred.comms_mcp.discord_hookpoints.declare_hookpoints``
    # at module import (bottom-of-module call), mirroring
    # ``alfred.comms_mcp.hookpoints``.
    "alfred.comms_mcp.discord_hookpoints": (
        "comms.adapter.binding_requested",
        "comms.adapter.rate_limit_signal",
    ),
    # #339 PR2 Task 1 (spec §10): the single orchestrator tool-dispatch
    # hookpoint. carrier_tier=T0 (system-internal dispatch attribution) +
    # fail_closed=True. Registered by
    # ``alfred.orchestrator.tool_hookpoints.declare_tool_hookpoints`` at
    # module import (bottom-of-module call), mirroring
    # ``alfred.security.capability_gate.proposals``.
    "alfred.orchestrator.tool_hookpoints": ("tool.dispatch",),
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
