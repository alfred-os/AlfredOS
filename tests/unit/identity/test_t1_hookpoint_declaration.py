"""Tests for ``identity.t1_ingress`` + ``identity.t1_downgrade`` hookpoint
declaration (PR-S3-1 Task 29).

Spec §6.7 / §14 — both hookpoints are declared by
``src/alfred/identity/_ingest.py`` at module import time. The dispatch-
time invoke sites land in PR-S3-4; this PR only ships the stub
declarations so the registry knows about the names. Three invariants
this module pins:

* Both hookpoints exist on the active registry after
  :func:`declare_hookpoints` runs.
* Both carry the spec §14 metadata verbatim:
  ``subscribable_tiers=SYSTEM_OPERATOR_TIERS``, ``refusable_tiers=
  frozenset()``, ``fail_closed=False``.
* :func:`declare_hookpoints` is idempotent — re-calling against the
  same registry with the same metadata is a no-op (the precedent the
  :mod:`alfred.memory.episodic` publisher relies on for pytest test
  isolation).

The tests use a fresh registry via :func:`set_registry` swap-and-
restore — same fixture pattern as
:mod:`tests.unit.memory.test_episodic_hooks_wiring` — so the global
singleton's state is preserved across the test run.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from alfred.hooks.registry import (
    SYSTEM_OPERATOR_TIERS,
    HookRegistry,
    get_registry,
    set_registry,
)
from alfred.identity._ingest import (
    HOOKPOINT_T1_DOWNGRADE,
    HOOKPOINT_T1_INGRESS,
    declare_hookpoints,
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


def test_declare_hookpoints_registers_t1_ingress(fresh_registry: HookRegistry) -> None:
    """After ``declare_hookpoints`` runs, ``identity.t1_ingress`` exists
    on the active registry with the spec §14 metadata."""
    declare_hookpoints(fresh_registry)
    meta = fresh_registry.hookpoint_meta(HOOKPOINT_T1_INGRESS)
    assert meta is not None
    assert meta.name == HOOKPOINT_T1_INGRESS
    assert meta.subscribable_tiers == SYSTEM_OPERATOR_TIERS
    assert meta.refusable_tiers == frozenset()
    assert meta.fail_closed is False


def test_declare_hookpoints_registers_t1_downgrade(fresh_registry: HookRegistry) -> None:
    """After ``declare_hookpoints`` runs, ``identity.t1_downgrade`` exists
    on the active registry with the spec §14 metadata."""
    declare_hookpoints(fresh_registry)
    meta = fresh_registry.hookpoint_meta(HOOKPOINT_T1_DOWNGRADE)
    assert meta is not None
    assert meta.name == HOOKPOINT_T1_DOWNGRADE
    assert meta.subscribable_tiers == SYSTEM_OPERATOR_TIERS
    assert meta.refusable_tiers == frozenset()
    assert meta.fail_closed is False


def test_declare_hookpoints_idempotent_on_same_metadata(
    fresh_registry: HookRegistry,
) -> None:
    """Re-running ``declare_hookpoints`` against the same registry is a
    no-op. The :meth:`HookRegistry.register_hookpoint` contract is
    idempotent on equal metadata; the dual-call discipline (module-init
    + per-call from PR-S3-4's invoke site) relies on it.
    """
    declare_hookpoints(fresh_registry)
    declare_hookpoints(fresh_registry)  # MUST NOT raise
    # Both hookpoints still resolve with the same metadata
    ingress = fresh_registry.hookpoint_meta(HOOKPOINT_T1_INGRESS)
    downgrade = fresh_registry.hookpoint_meta(HOOKPOINT_T1_DOWNGRADE)
    assert ingress is not None
    assert downgrade is not None
    assert ingress.subscribable_tiers == SYSTEM_OPERATOR_TIERS
    assert downgrade.subscribable_tiers == SYSTEM_OPERATOR_TIERS


def test_declare_hookpoints_default_target_uses_active_registry() -> None:
    """Calling ``declare_hookpoints()`` with no arg targets
    :func:`get_registry`'s active singleton. The default-arg path is the
    one the module-init call uses, so this guards against a regression
    that breaks production declaration."""
    prior = get_registry()
    registry = HookRegistry(gate=make_permissive_fixture_gate())
    set_registry(registry)
    try:
        declare_hookpoints()
        assert registry.hookpoint_meta(HOOKPOINT_T1_INGRESS) is not None
        assert registry.hookpoint_meta(HOOKPOINT_T1_DOWNGRADE) is not None
    finally:
        set_registry(prior)


def test_hookpoint_constants_match_spec_names() -> None:
    """The dotted names in the public constants match spec §14 verbatim.

    Pinning these in a test catches a typo-rename of the constants that
    would not surface until PR-S3-4 wires the invoke site. The strings
    here are the source of truth — if the spec changes, both this test
    and the constants in ``_ingest.py`` move together.
    """
    assert HOOKPOINT_T1_INGRESS == "identity.t1_ingress"
    assert HOOKPOINT_T1_DOWNGRADE == "identity.t1_downgrade"
