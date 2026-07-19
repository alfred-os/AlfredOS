"""Declares the ``egress.broker.*`` hookpoints (#340 golive Task 10).

The pre-gate PR #462 shipped :class:`alfred.egress.broker_audit.EgressBrokerAuditor`
DORMANT — its ``invoke()`` calls already target ``egress.broker.connected`` /
``egress.broker.refused``, but neither event was declared anywhere in the strict
hook registry (the auditor's own unit tests monkeypatch ``alfred.hooks.invoke.invoke``
at its source module specifically to sidestep this — see
``tests/unit/egress/test_broker_audit.py``'s module docstring). Declaring both here
is what makes the auditor's first LIVE dispatch (wired onto
:class:`alfred.security.quarantine_transport.QuarantineStdioTransport` in
``daemon_runtime.py``) succeed instead of raising
:class:`alfred.hooks.errors.HookError` under ``strict_declarations=True`` (spec §21 /
golive rev.2 carry-forward #1).

Both events mirror ``supervisor.plugin.sandbox_refused``'s declaration
(:mod:`alfred.supervisor.hookpoints`, PR-S4-6 / ADR-0015): ``carrier_tier=T0``
(system-internal attribution — a bare ``destination`` + closed-vocab ``reason``,
never T3 content) and ``fail_closed=True`` (a subscriber-timeout on an egress-audit
event must not silently swallow the row — HARD #7).

This declaration MUST exactly match the ``subscribable_tiers`` / ``fail_closed``
arguments :meth:`EgressBrokerAuditor._write` passes to ``invoke()``
(``SYSTEM_ONLY_TIERS`` / ``True`` — see ``alfred/egress/broker_audit.py``): a
mismatch on either field trips the dispatch-time defense-in-depth drift check
(``alfred.hooks.invoke._enforce_subscribable_tiers``) and raises ``HookError`` on
EVERY live call, exactly the failure this module exists to prevent.
``refusable_tiers`` is declared as the empty set (mirroring ``sandbox_refused``) —
the auditor's ``invoke()`` call is ``kind="post"``, which never threads
``refusable_tiers`` through the drift check (§6.5 refusal semantics are ``pre``-only),
so this field's value is inert for THIS publisher but still must be a concrete set
(``register_hookpoint`` has no ``None`` default).

Registered at module-bottom import time (mirrors
:func:`alfred.orchestrator.tool_hookpoints.declare_tool_hookpoints` /
:func:`alfred.security.capability_gate.proposals.declare_hookpoints`) AND
explicitly listed in :func:`alfred.hooks.boot._declare_all_subsystem_hookpoints` —
the module-bottom call alone only lands on whatever registry singleton happens to
be active at first import, which is NOT guaranteed to be the fresh boot registry
:func:`alfred.hooks.boot.install_boot_hook_registry` constructs (see that module's
docstring for why). The explicit boot-list entry is what deterministically makes
both hookpoints declarable against the REAL production registry regardless of
import ordering elsewhere in the daemon's boot graph.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from alfred.hooks.registry import SYSTEM_ONLY_TIERS, get_registry
from alfred.security.tiers import T0

if TYPE_CHECKING:
    from alfred.hooks.registry import HookRegistry

EGRESS_BROKER_CONNECTED_HOOKPOINT: Final[str] = "egress.broker.connected"
EGRESS_BROKER_REFUSED_HOOKPOINT: Final[str] = "egress.broker.refused"


def declare_hookpoints(registry: HookRegistry | None = None) -> None:
    """Register ``egress.broker.connected`` + ``egress.broker.refused``.

    Idempotent on equal metadata (mirrors every other subsystem's
    ``declare_hookpoints``) — safe to call once at module-init time AND again
    at daemon boot against a fresh registry (:mod:`alfred.hooks.boot`).

    Args:
        registry: The :class:`HookRegistry` to declare against. Defaults to
            :func:`get_registry`'s active singleton; the boot seam passes the
            fresh boot registry explicitly.
    """
    target = registry if registry is not None else get_registry()
    for name in (EGRESS_BROKER_CONNECTED_HOOKPOINT, EGRESS_BROKER_REFUSED_HOOKPOINT):
        target.register_hookpoint(
            name=name,
            subscribable_tiers=SYSTEM_ONLY_TIERS,
            refusable_tiers=frozenset(),
            fail_closed=True,
            carrier_tier=T0,
        )


# Module-init declaration — mirrors alfred.orchestrator.tool_hookpoints' bottom-of-
# module call so the KNOWN_HOOKPOINTS import-sweep sync test
# (tests/unit/hooks/test_known_hookpoints_sync.py) sees both events registered at
# runtime on a bare import. Idempotent on equal metadata, so re-importing under
# pytest test isolation is safe. Production correctness for the REAL boot registry
# additionally requires the explicit alfred.hooks.boot._declare_all_subsystem_hookpoints
# entry (see module docstring) — this call alone is a test/dev-import convenience,
# not a substitute for the boot-list entry.
declare_hookpoints()


__all__ = [
    "EGRESS_BROKER_CONNECTED_HOOKPOINT",
    "EGRESS_BROKER_REFUSED_HOOKPOINT",
    "declare_hookpoints",
]
