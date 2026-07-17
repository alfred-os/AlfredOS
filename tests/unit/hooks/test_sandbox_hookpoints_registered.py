"""Sandbox/posture hookpoint registration (PR-S4-6 Component H).

PR-S4-6 ships three supervisor hookpoints, registered via
:func:`alfred.supervisor.hookpoints.declare_hookpoints` (#443 PR1):

* ``supervisor.plugin.sandbox_refused`` — T0, fail_closed=True. Fires on
  every ``SANDBOX_REFUSED_FIELDS`` emit.
* ``supervisor.boot.mlock_unavailable`` — T0, fail_closed=False
  (informational; boot proceeds).
* ``supervisor.boot.core_dumps_disabled`` — T0, fail_closed=False
  (informational).

All three are system-internal observability (no operator/untrusted content),
so the carrier tier is T0.
"""

from __future__ import annotations

from alfred.hooks import get_registry
from alfred.hooks.registry import HookRegistry
from alfred.security.tiers import T0
from alfred.supervisor.hookpoints import declare_hookpoints as declare_supervisor


def _fresh_registry_with_supervisor_hookpoints() -> HookRegistry:
    declare_supervisor()
    return get_registry()


def test_sandbox_refused_hookpoint_registered() -> None:
    reg = _fresh_registry_with_supervisor_hookpoints()
    meta = reg.hookpoint_meta("supervisor.plugin.sandbox_refused")
    assert meta is not None
    assert meta.carrier_tier is T0
    assert meta.fail_closed is True


def test_sandbox_stub_used_hookpoint_registered() -> None:
    # PR-S4-7: the dev/test-only unsandboxed-exec observability row, the
    # sandbox_refused sibling. T0 (carries only plugin_id/policy_ref/host_os/
    # environment — no operator/untrusted content) + fail_closed=True
    # (mirrors sandbox_refused verbatim; #167 per-kind override deferred).
    reg = _fresh_registry_with_supervisor_hookpoints()
    meta = reg.hookpoint_meta("supervisor.plugin.sandbox_stub_used")
    assert meta is not None
    assert meta.carrier_tier is T0
    assert meta.fail_closed is True


def test_mlock_unavailable_hookpoint_registered() -> None:
    reg = _fresh_registry_with_supervisor_hookpoints()
    meta = reg.hookpoint_meta("supervisor.boot.mlock_unavailable")
    assert meta is not None
    assert meta.carrier_tier is T0
    assert meta.fail_closed is False


def test_core_dumps_disabled_hookpoint_registered() -> None:
    reg = _fresh_registry_with_supervisor_hookpoints()
    meta = reg.hookpoint_meta("supervisor.boot.core_dumps_disabled")
    assert meta is not None
    assert meta.carrier_tier is T0
    assert meta.fail_closed is False
