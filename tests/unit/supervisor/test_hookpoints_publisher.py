"""The supervisor is a boot-declarable hookpoint publisher (#443 PR1).

Prerequisite for PR2's in-spawn handshake, which dispatches
``supervisor.plugin.sandbox_refused`` before ``Supervisor(...)`` exists. Also the
fix #444 is blocked on. core-001 is LATENT today — see the plan's rationale.
"""

from __future__ import annotations

from alfred.hooks.boot import _declare_all_subsystem_hookpoints
from alfred.hooks.registry import HookRegistry
from alfred.security.tiers import T0
from alfred.supervisor.hookpoints import declare_hookpoints
from tests.helpers.gates import make_deny_all_gate


def _registry() -> HookRegistry:
    """A real registry over a deny-all fixture gate.

    ``gate`` is keyword-only with no default (registry.py:515-522). Declaration is
    not gated — only subscription is — so deny-all is correct here and honours
    CLAUDE.md hard rule #2 (never stub the gate to "always allow").
    """
    return HookRegistry(gate=make_deny_all_gate())


def test_sandbox_refused_is_declared_fail_closed_t0() -> None:
    """PR2's target: the fail-closed T0 row, declarable without a Supervisor.

    Named independently of the tuple — an oracle that iterates the tuple and asks
    the tuple what the tuple says kills zero mutants.
    """
    registry = _registry()

    declare_hookpoints(registry)

    meta = registry.hookpoint_meta("supervisor.plugin.sandbox_refused")
    assert meta is not None
    assert meta.carrier_tier is T0
    assert meta.fail_closed is True


def test_declare_hookpoints_honours_the_registry_argument() -> None:
    """The passed registry is used, not the global singleton.

    Kills the "ignores the ``registry`` arg and calls get_registry()" mutant —
    which is exactly what the boot seam depends on.
    """
    registry = _registry()

    declare_hookpoints(registry)

    assert registry.hookpoint_meta("supervisor.breaker.tripped") is not None


def test_declare_hookpoints_is_idempotent() -> None:
    """Re-declaration on equal metadata is a no-op, not a drift raise.

    Load-bearing: the boot seam declares, then Supervisor.__init__ re-declares.
    """
    registry = _registry()

    declare_hookpoints(registry)
    declare_hookpoints(registry)  # must not raise


def test_boot_seam_declares_sandbox_refused_without_a_supervisor() -> None:
    """The core-001 oracle: the boot registry carries the row with no Supervisor.

    Fails before this task: the seam registers 27 hookpoints and this one is not
    among them.
    """
    registry = _registry()

    _declare_all_subsystem_hookpoints(registry)

    meta = registry.hookpoint_meta("supervisor.plugin.sandbox_refused")
    assert meta is not None, "core-001: sandbox_refused undeclared at boot"
    assert meta.fail_closed is True
