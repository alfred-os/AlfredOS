"""Production boot :class:`HookRegistry` construction (PR-S4-11b0 / ADR-0026).

Until this module, the only process-wide :class:`HookRegistry` in
production was the lazy :func:`alfred.hooks.registry.get_registry`
fallback, wired to the fail-closed
:class:`alfred.hooks.registry._DenyAllGate` that denies EVERY subscriber
registration. That is the correct bootstrap default — but it means a
production :class:`alfred.security.quarantine.QuarantinedExtractor`
(whose ``__init__`` registers the system-tier
``security.quarantined.extract`` DLP subscriber) can never construct,
because the deny-all gate refuses the registration.

This module is the production install seam (the precedent the
:class:`alfred.memory.hooks_audit_sink.EpisodicAuditSink` docstring
flagged as "deferred to Slice 3"): the daemon builds a fresh
:class:`HookRegistry` wired to the real Postgres-backed gate and the
durable boot audit sink, RE-DECLARES every subsystem's hookpoints
against it, and installs it as the process singleton via
:func:`alfred.hooks.registry.set_registry`.

Two design points the trust boundary depends on:

* **Signature takes a raw :class:`CapabilityGate`.** The daemon must
  pass the RAW :class:`alfred.security.capability_gate._gate.RealGate`
  (the object whose ``check`` consults the grant policy), NOT the
  ``_SupervisorBootGate`` wrapper (which exposes only
  ``is_backing_store_available`` and would fail registration with an
  ``AttributeError`` on ``check`` — a fail-open smell). Typing the
  parameter as :class:`CapabilityGate` makes the wrong object a type
  error at the call site.

* **Full re-declaration, zero subscribers.** Declaring a hookpoint is
  NOT registering a subscriber (spec §6.2). :func:`build_boot_hook_registry`
  re-declares every subsystem hookpoint so subscribers CAN register
  later, but wires no subscriber itself — the boot registry's subscriber
  buckets are empty until the extractor (and future plugins) register.
  The blast radius of the build is therefore exactly "hookpoints are
  declarable", nothing more. The dispatch path
  (:func:`alfred.hooks.invoke.invoke`) does not consult the capability
  gate, so re-declaration cannot widen any dispatch authority.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alfred.hooks.registry import HookRegistry, set_registry

if TYPE_CHECKING:
    from alfred.hooks.audit_sink import AuditSink
    from alfred.hooks.capability import CapabilityGate


def _declare_all_subsystem_hookpoints(registry: HookRegistry) -> None:
    """Re-declare every first-party subsystem's hookpoints against ``registry``.

    Imports each subsystem's ``declare_hookpoints`` and calls it with the
    explicit ``registry`` so the declaration lands on the boot registry
    rather than the lazy process singleton (the module-bottom
    ``declare_hookpoints()`` calls those modules run at import time target
    whatever singleton was active THEN — not this fresh registry).

    Imports are local to keep ``alfred.hooks.boot`` import-light and to
    avoid an import cycle: these subsystem modules import
    ``alfred.hooks`` at their top level, so importing them at THIS
    module's top level would re-enter ``alfred.hooks`` during its own
    import. The daemon calls this at boot, long after both packages are
    fully imported.

    Idempotent on equal metadata: each subsystem's
    :meth:`HookRegistry.register_hookpoint` is a no-op on an identical
    re-declaration and raises :class:`alfred.hooks.errors.HookError` only
    on genuine metadata drift (spec §6.2). Re-running this function
    against the same registry therefore never raises.

    The list is the COMPLETE set of in-tree ``declare_hookpoints``
    publishers (grep ``def declare_hookpoints`` in ``src/alfred``); a new
    subsystem publisher MUST be added here so its hookpoints are
    declarable at boot.
    """
    from alfred.cli.daemon import declare_hookpoints as declare_daemon
    from alfred.comms_mcp.discord_hookpoints import (
        declare_hookpoints as declare_discord,
    )
    from alfred.comms_mcp.hookpoints import declare_hookpoints as declare_comms
    from alfred.identity._ingest import declare_hookpoints as declare_ingest
    from alfred.identity.operator_session import (
        declare_hookpoints as declare_operator_session,
    )
    from alfred.memory.episodic import declare_hookpoints as declare_episodic
    from alfred.policies.watcher import declare_hookpoints as declare_watcher
    from alfred.security.capability_gate.proposals import (
        declare_hookpoints as declare_proposals,
    )
    from alfred.security.quarantine import declare_hookpoints as declare_quarantine
    from alfred.supervisor.hookpoints import declare_hookpoints as declare_supervisor

    declare_episodic(registry)
    declare_operator_session(registry)
    declare_ingest(registry)
    declare_quarantine(registry)
    declare_proposals(registry)
    declare_daemon(registry)
    declare_watcher(registry)
    declare_comms(registry)
    declare_discord(registry)
    declare_supervisor(registry)


def build_boot_hook_registry(
    gate: CapabilityGate,
    *,
    sink: AuditSink,
) -> HookRegistry:
    """Build a fresh boot :class:`HookRegistry` (gate + sink + all hookpoints).

    Constructs a :class:`HookRegistry` over the supplied ``gate`` and
    ``sink`` (the production posture: a real RealGate and the durable boot
    audit sink), then re-declares every subsystem hookpoint against it via
    :func:`_declare_all_subsystem_hookpoints` so subscribers can register.

    ``strict_declarations`` is left at its security-critical default
    (``True``) — the boot registry MUST enforce the register-time
    tier-allowlist + the dispatch-time defense-in-depth re-check.

    Args:
        gate: The capability gate consulted at subscriber-register time.
            MUST be the RAW :class:`CapabilityGate` (the RealGate whose
            ``check`` consults the grant policy), NOT the supervisor
            boot-gate wrapper.
        sink: The audit sink the dispatcher emits fault/refusal rows
            through. Production wires the durable boot
            :class:`alfred.memory.hooks_audit_sink.EpisodicAuditSink`
            over the boot :class:`alfred.audit.log.AuditWriter` so a
            DLP-deny refusal row is durable (NOT the gate's no-op sink).

    Returns:
        A ready :class:`HookRegistry` with every subsystem hookpoint
        declared and ZERO subscribers wired.
    """
    registry = HookRegistry(gate=gate, sink=sink)
    _declare_all_subsystem_hookpoints(registry)
    return registry


def install_boot_hook_registry(
    gate: CapabilityGate,
    *,
    sink: AuditSink,
) -> HookRegistry:
    """Build the boot registry and install it as the process singleton.

    :func:`build_boot_hook_registry` then
    :func:`alfred.hooks.registry.set_registry`. After this call,
    :func:`alfred.hooks.registry.get_registry` returns the boot registry,
    so a subsequently-constructed
    :class:`alfred.security.quarantine.QuarantinedExtractor` registers its
    DLP subscriber against the production gate.

    This is the ONE intentional production ``set_registry`` swap — the
    daemon's single boot-time install. See ``gate`` / ``sink`` on
    :func:`build_boot_hook_registry`.
    """
    registry = build_boot_hook_registry(gate, sink=sink)
    set_registry(registry)
    return registry


__all__ = [
    "build_boot_hook_registry",
    "install_boot_hook_registry",
]
