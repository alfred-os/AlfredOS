"""Tests for the ``tool.dispatch`` named hookpoint declaration (#339 PR2 Task 1).

Spec §10 — ``dispatch_tool`` (a later PR2 task, not this one) gates
every tool call on ``gate.check(plugin_id=..., hookpoint="tool.dispatch",
requested_tier="system")``. This module only pins the hookpoint's
*declaration*: that :func:`declare_tool_hookpoints` registers
``tool.dispatch`` on the active :class:`HookRegistry` with the spec's
system-only, fail-closed metadata, and that the declaration is
idempotent under re-import (pytest test isolation, the same discipline
:mod:`alfred.identity._ingest` and
:mod:`alfred.security.capability_gate.proposals` rely on).

The tests use a fresh registry via :func:`set_registry` swap-and-
restore — same fixture pattern as
:mod:`tests.unit.identity.test_t1_hookpoint_declaration` — so the
global singleton's state is preserved across the test run.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from alfred.hooks.registry import (
    SYSTEM_ONLY_TIERS,
    HookRegistry,
    get_registry,
    set_registry,
)
from alfred.orchestrator.tool_hookpoints import (
    TOOL_DISPATCH_HOOKPOINT,
    declare_tool_hookpoints,
)
from tests.helpers.gates import make_permissive_fixture_gate


@pytest.fixture
def fresh_registry() -> Iterator[HookRegistry]:
    """Install a fresh :class:`HookRegistry` for the test body's duration.

    The default fixture-parity gate (:func:`make_permissive_fixture_gate`,
    ``allow_system=False``) denies the ``system`` tier — fine here
    because :meth:`HookRegistry.register_hookpoint` does not consult
    the gate (the gate only fires on subscriber registration). Swap-
    and-restore so a sibling test's view of the global singleton is
    unaffected.
    """
    prior = get_registry()
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


def test_declare_registers_tool_dispatch_hookpoint(fresh_registry: HookRegistry) -> None:
    """After ``declare_tool_hookpoints`` runs, ``tool.dispatch`` exists on
    the active registry with the spec §10 metadata: system-only
    subscribe/refuse tiers, fail-closed."""
    declare_tool_hookpoints(fresh_registry)
    meta = fresh_registry.hookpoint_meta(TOOL_DISPATCH_HOOKPOINT)
    assert meta is not None
    assert meta.name == TOOL_DISPATCH_HOOKPOINT
    assert meta.subscribable_tiers == SYSTEM_ONLY_TIERS
    assert meta.refusable_tiers == SYSTEM_ONLY_TIERS
    assert meta.fail_closed is True


def test_declare_is_idempotent(fresh_registry: HookRegistry) -> None:
    """Re-running ``declare_tool_hookpoints`` against the same registry is
    a no-op. :meth:`HookRegistry.register_hookpoint` is idempotent on
    equal metadata; re-importing the declaring module under pytest test
    isolation relies on this."""
    declare_tool_hookpoints(fresh_registry)
    declare_tool_hookpoints(fresh_registry)  # equal metadata → no raise
    meta = fresh_registry.hookpoint_meta(TOOL_DISPATCH_HOOKPOINT)
    assert meta is not None
    assert meta.fail_closed is True


def test_declare_default_target_uses_active_registry() -> None:
    """Calling ``declare_tool_hookpoints()`` with no arg targets
    :func:`get_registry`'s active singleton — the path the module-init
    call uses, so this guards against a regression that breaks
    production declaration."""
    prior = get_registry()
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    set_registry(registry)
    try:
        declare_tool_hookpoints()
        assert registry.hookpoint_meta(TOOL_DISPATCH_HOOKPOINT) is not None
    finally:
        set_registry(prior)


def test_hookpoint_constant_matches_spec_name() -> None:
    """The dotted name in the public constant matches spec §10 verbatim."""
    assert TOOL_DISPATCH_HOOKPOINT == "tool.dispatch"
