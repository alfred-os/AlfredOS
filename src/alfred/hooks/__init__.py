"""AlfredOS pluggable hooks subsystem — public surface (spec §3.1).

This package exposes the contract every hook author, every subscriber, and
every dispatch site in the orchestrator codes against. The fourteen names
listed in :data:`__all__` ARE the spec'd surface; nothing else may be
imported from the top-level package.

Submodule-only by design (NOT re-exported here):

* :class:`alfred.hooks.invoke.Flow` — internal receipt-pattern carrier;
  callers reach it through :func:`invoking` only (Task-13 security M-3).
* :class:`alfred.hooks.registry.Subscriber` — registry's internal carrier;
  callers that need introspection import from ``alfred.hooks.registry``.
* :class:`alfred.hooks.audit_sink.StructlogAuditSink` — default
  implementation of the :class:`AuditSink` Protocol; PR-B's
  ``EpisodicAuditSink`` replaces it. Constructing the default directly
  requires the explicit submodule import.
* The six ``HOOKS_*`` event-name constants in
  ``alfred.hooks.audit_sink`` — audit sinks bind by event-name string.
* The private dispatch internals (``_invoke_internal``, ``_run_*``,
  ``_handle_chain_timeout``, ``_dispatch_by_kind``, ``_spawn_subscriber``,
  ``_EMPTY``, ``_TIER_RANK``, ``_reentry``, the four ``_*_AUDIT_FIELDS``
  schema constants, ``_CLEANUP_DEADLINE_SECONDS``) — sec-008 forbids
  exposing the re-entry bypass; the rest are dispatch implementation
  detail and would create a wider contract than the spec permits.

The public-surface lock is enforced by
``tests/unit/hooks/test_public_surface.py`` and the per-package 100%
line+branch coverage gate wired in ``.github/workflows/ci.yml``.
"""

from alfred.hooks.audit_sink import AuditSink
from alfred.hooks.capability import CapabilityGate, DevGate
from alfred.hooks.context import HookContext, HookKind
from alfred.hooks.decorators import hook
from alfred.hooks.errors import HookError, HookRefusal, HookSubscriberError
from alfred.hooks.invoke import invoke, invoking
from alfred.hooks.registry import (
    OPEN_TIERS,
    SYSTEM_ONLY_TIERS,
    SYSTEM_OPERATOR_TIERS,
    HookRegistry,
    get_registry,
    set_registry,
)

__all__ = [
    "OPEN_TIERS",
    "SYSTEM_ONLY_TIERS",
    "SYSTEM_OPERATOR_TIERS",
    "AuditSink",
    "CapabilityGate",
    "DevGate",
    "HookContext",
    "HookError",
    "HookKind",
    "HookRefusal",
    "HookRegistry",
    "HookSubscriberError",
    "get_registry",
    "hook",
    "invoke",
    "invoking",
    "set_registry",
]
