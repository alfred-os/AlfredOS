"""Test-only :class:`CapabilityGate` factories — RealGate, no Postgres.

``DevGate`` was removed from ``src/alfred/hooks/capability.py`` at the
end of Slice 3 (PR-S3-7, spec §15.1). This module re-establishes the
ergonomic deny-path / system-grant fixture shapes the old
``DevGate(...)`` constructions used to provide — but ONLY for use in
tests, never in production code. Importing from ``tests.helpers.*``
inside ``src/`` is a layering violation; the public-surface invariant
test pins that the ``alfred.hooks`` package exports no ``DevGate``
symbol.

The production gate is :class:`alfred.security.capability_gate._gate.RealGate`,
constructed by :mod:`alfred.bootstrap.gate_factory` based on the
``ALFRED_ENV`` env var.

Two helper shapes ship here:

* :func:`make_deny_all_gate` / :func:`make_allow_system_gate` —
  :class:`RealGate` wrapped over an in-memory stub backend, seeded
  with zero grants or one wildcard system grant respectively. These
  are the canonical post-removal deny-path / granted-path helpers and
  they consult the same :class:`alfred.security.capability_gate.policy.GatePolicy`
  code the production hot path uses. **Deny-path security tests
  MUST use these** (Slice-3 spec §15.1) — asserting against
  :class:`RealGate`'s deny path is what prevents a RealGate regression
  from being hidden by a test-side shim.

* :func:`make_permissive_fixture_gate` (and the implementing
  :class:`_DevGateLikeFixture`) — a pure test fixture gate that
  mimics the Slice-2.5 ``DevGate(...)`` semantics: operator and
  user-plugin are always granted, system is gated on
  ``allow_system``. This is the **fixture-parity** path the
  :func:`tests.unit.hooks.conftest.fresh_registry` family uses so
  the Slice-2.5 tests that registered an ``operator``-tier subscriber
  via the default fixture keep working without per-test rework. The
  fixture-parity gate is NOT :class:`RealGate`-shaped — it deliberately
  ignores ``plugin_id`` / ``hookpoint`` the same way ``DevGate`` did,
  so a test that registers under an arbitrary module-named ``plugin_id``
  (the default attribution shape in :class:`alfred.hooks.registry.HookRegistry.register`)
  continues to register cleanly.

  The fixture-parity gate is **structurally** a
  :class:`alfred.hooks.capability.CapabilityGate` (the Protocol is
  ``@runtime_checkable``) so dispatcher code that type-narrows on the
  Protocol still works with it. It is **not** a parallel production
  gate hierarchy — it is a test double, kept out of ``src/`` per the
  flag-day removal.

  **NEVER use** :func:`make_permissive_fixture_gate` **for a deny-
  path security test.** The shim's permissive posture makes the
  deny outcome a function of shim logic, not :class:`RealGate`'s
  grant policy — a RealGate regression would be invisible. Use
  :func:`make_deny_all_gate` instead. The naming pin is deliberately
  loud: a reviewer who sees ``make_permissive_fixture_gate`` in a
  test whose assertion is ``HookError raised`` should ask "why are
  you asserting a deny outcome against a permissive gate?".

Tests that want the strict RealGate semantics (empty grants ⇒ deny
operator too, exact plugin_id match) use :func:`make_deny_all_gate`
directly. The fixture family in
:mod:`tests.unit.hooks.conftest` is composed of
:func:`make_permissive_fixture_gate`-style fixtures so the Slice-2.5
test bodies don't need per-test rework.

Usage::

    from tests.helpers.gates import (
        make_allow_system_gate,
        make_deny_all_gate,
        make_permissive_fixture_gate,
    )

    # Strict RealGate semantics (every check denies) — the deny-path
    # security-test canonical helper:
    gate = make_deny_all_gate()

    # DevGate-default parity (operator + user-plugin granted, system denied).
    # NEVER for deny-path security tests; only for tests whose semantic
    # legitimately requires operator + user-plugin to register cleanly:
    gate = make_permissive_fixture_gate()

    # DevGate(allow_system=True) parity (everything granted):
    gate = make_permissive_fixture_gate(allow_system=True)

    # RealGate with one wildcard system grant for a specific plugin id:
    gate = make_allow_system_gate(plugin_id="alfred.web-fetch")
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from alfred.hooks.capability import CapabilityGate
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow

# The three tier strings the fixture-parity gate recognises. Module-level
# so a maintainer changing the closed set surfaces the change next to
# the policy logic (mirrors the layout :mod:`alfred.security.capability_gate.policy`
# uses for its own closed-domain set).
_FIXTURE_TIERS_GRANTED_UNCONDITIONALLY: frozenset[str] = frozenset({"operator", "user-plugin"})
_FIXTURE_TIER_GATED_BY_ALLOW_SYSTEM: str = "system"


def _make_in_memory_backend(grants: Iterable[GrantRow] = ()) -> Any:
    """Return a :class:`StorageBackend`-shaped stub pre-loaded with ``grants``.

    The stub satisfies the structural :class:`StorageBackend` Protocol
    without any database I/O: every async method is an :class:`AsyncMock`.
    Tests that drive the test-shim gate consult the in-memory
    :class:`GatePolicy` snapshot, not the backend, so the backend's
    return values only matter on the heartbeat path — which tests can
    opt out of by leaving ``start_heartbeat=False``.
    """
    backend = MagicMock()
    backend.ping = AsyncMock(return_value=None)
    backend.load_grants = AsyncMock(return_value=frozenset(grants))
    backend.get_sync_hash = AsyncMock(return_value=None)
    backend.set_sync_hash = AsyncMock(return_value=None)
    backend.upsert_grant = AsyncMock(return_value=None)
    backend.revoke_grant = AsyncMock(return_value=None)
    backend.apply_atomic = AsyncMock(return_value=None)
    return backend


def _make_no_op_audit_sink() -> Any:
    """Return an audit-sink stub for tests that don't assert on rows.

    err-003: :meth:`RealGate.create` requires an audit sink so a
    fail-closed state transition cannot land without an audit row. The
    test shim is only used in deny-path / granted-path fixtures where
    audit emission isn't the property under test — the no-op sink
    satisfies the constructor contract without inflating the test
    surface area.
    """
    sink = MagicMock()
    sink.append_schema = AsyncMock(return_value=None)
    return sink


def make_deny_all_gate() -> CapabilityGate:
    """Return a :class:`RealGate` with an empty grant store.

    Strict RealGate semantics: every :meth:`RealGate.check` /
    :meth:`RealGate.check_plugin_load` /
    :meth:`RealGate.check_content_clearance` call returns ``False`` —
    including for ``operator`` and ``user-plugin`` tiers (RealGate does
    not have the Slice-2.5 ``DevGate`` "operator always granted"
    shortcut). Tests that need the DevGate-default fixture-parity
    semantics use :func:`make_permissive_fixture_gate` instead —
    but only for tests whose semantic legitimately requires a
    permissive gate (never for deny-path security tests).

    Synchronous construction (no ``await``) so this can be called from
    pytest fixtures without ``@pytest.mark.asyncio`` overhead — bypasses
    the :meth:`RealGate.create` async factory and goes through
    :meth:`RealGate.__init__` directly with a pre-built empty
    :class:`GatePolicy`. The heartbeat task is NOT started, so callers
    don't need to manage cancellation in a fixture teardown.
    """
    return RealGate(
        policy=GatePolicy(grants=frozenset()),
        backend=_make_in_memory_backend(),
        audit_sink=_make_no_op_audit_sink(),
    )


def make_allow_system_gate(
    *,
    plugin_id: str = "test-plugin",
    hookpoint: str = "*",
) -> CapabilityGate:
    """Return a :class:`RealGate` with one ``system``-tier grant seeded.

    Strict RealGate semantics: a ``system`` request that doesn't match
    ``(plugin_id, hookpoint, "system")`` still denies. Tests that need
    the broad "every system request grants" posture should pass the
    default ``hookpoint="*"`` (wildcard) so any hookpoint matches
    under that plugin_id. Tests that need the broader
    ``DevGate(allow_system=True)``-style posture (operator /
    user-plugin / system all granted regardless of plugin_id) use
    :func:`make_permissive_fixture_gate` with ``allow_system=True``.

    The default ``plugin_id="test-plugin"`` is a placeholder; tests
    that rely on a specific plugin id should pass it explicitly.

    The seeded grant carries:

    * ``subscriber_tier="system"`` — the axis under test.
    * ``content_tier=None`` — no content-tier restriction (the
      orthogonal trust axis isn't asserted by the system-tier path).
    * ``proposal_branch="test-fixture"`` — an obviously-test value so
      audit-graph queries don't surface this as a real proposal.
    """
    grant = GrantRow(
        plugin_id=plugin_id,
        subscriber_tier="system",
        hookpoint=hookpoint,
        content_tier=None,
        proposal_branch="test-fixture",
    )
    return RealGate(
        policy=GatePolicy(grants=frozenset({grant})),
        backend=_make_in_memory_backend(grants={grant}),
        audit_sink=_make_no_op_audit_sink(),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class _DevGateLikeFixture:
    """Test-only fixture gate that mimics Slice-2.5 ``DevGate`` semantics.

    **THIS IS NOT** :class:`RealGate`. It is a permissive test
    fixture: operator and user-plugin tiers are granted
    UNCONDITIONALLY (no grant-table consult), and system is gated on
    the constructor-set ``allow_system`` flag. Plugin id and
    hookpoint are ignored entirely.

    **DO NOT use for deny-path security tests.** Slice-3 spec §15.1
    mandates deny-path security tests assert against :class:`RealGate`
    (via :func:`make_deny_all_gate`) so a regression in RealGate's
    deny path cannot be hidden by this shim's "always allow operator
    + user-plugin" semantics. A reviewer who sees this class —
    or its public constructor :func:`make_permissive_fixture_gate` —
    in a test asserting ``HookError raised`` should reject the
    PR: the assertion's load-bearing target is the shim, not the
    production gate.

    **Legitimate uses** (Slice-3 spec §15.1 — "tests that genuinely
    need the shim's 'operator + user-plugin allowed unconditionally'
    semantics because they're testing OTHER code paths, not the gate"):

    * Dispatcher fault-semantics tests that register an operator-tier
      hook and exercise the chain's timeout / exception / re-entry
      paths (:mod:`tests.unit.hooks.test_fault_semantics`,
      :mod:`tests.unit.hooks.test_dispatch_publisher_drift`).
    * Hookpoint declaration / metadata tests that never call
      :meth:`HookRegistry.register` (:mod:`tests.unit.identity.test_t1_hookpoint_declaration`,
      :mod:`tests.unit.security.capability_gate.test_audit_wiring`,
      :mod:`tests.unit.cli.test_plugin_grant_audit_wiring`).
    * Positive-control tests where the gate must grant so the
      hookpoint-allowlist arm becomes the test's load-bearing
      assertion (the deny-path arm pairs with this in
      :mod:`tests.unit.hooks.test_registration_enforcement`).
    * Plugin-load contract tests that exercise the shim's
      ``check_plugin_load`` fail-open posture (Slice-2.5 parity;
      :mod:`tests.integration.test_comms_mcp_contract`).
    * Performance benchmarks that need a constant-time grant decision
      so the measurement target is the dispatcher hot path, not the
      gate's grant lookup (:mod:`tests.perf.test_hook_dispatch_perf`).
    * The :func:`fresh_registry`-family fixtures themselves
      (:mod:`tests.unit.hooks.conftest`), which underpin hundreds of
      non-gate tests.

    The class is private and lives in :mod:`tests.helpers.gates` so
    no ``src/`` code can import it. It is **structurally** a
    :class:`alfred.hooks.capability.CapabilityGate` (the Protocol is
    ``@runtime_checkable``); the dispatcher's type-narrowing finds it
    via :func:`isinstance` exactly as it would the production
    :class:`RealGate`.

    Frozen+slots discipline mirrors the production gate types — the
    test fixture can't drift away from the production posture.
    """

    allow_system: bool = False

    def check(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        requested_tier: str,
    ) -> bool:
        """Return the DevGate-shaped yes/no for the requested tier.

        ``operator`` / ``user-plugin`` always grant; ``system`` grants
        iff ``allow_system=True``. Unknown / typo'd / case-mismatched
        tiers deny fail-closed. The ``plugin_id`` and ``hookpoint``
        parameters are accepted per the Protocol contract but unused —
        same shape as the Slice-2.5 ``DevGate``.
        """
        del plugin_id, hookpoint
        if requested_tier in _FIXTURE_TIERS_GRANTED_UNCONDITIONALLY:
            return True
        if requested_tier == _FIXTURE_TIER_GATED_BY_ALLOW_SYSTEM:
            return self.allow_system
        return False

    def check_plugin_load(
        self,
        *,
        plugin_id: str,
        manifest_tier: str,
    ) -> bool:
        """Fixture-parity stub: defer to :meth:`check` with wildcard hookpoint.

        Slice-2.5 ``DevGate.check_plugin_load`` was a fail-open stub
        for the same reason — until a real grant table existed, plugin
        load couldn't be gated meaningfully. The fixture preserves
        that semantic: a plugin load passes iff the subscriber tier
        it declares passes the :meth:`check` rules above.
        """
        return self.check(
            plugin_id=plugin_id,
            hookpoint="*",
            requested_tier=manifest_tier,
        )

    def check_content_clearance(
        self,
        *,
        plugin_id: str,
        hookpoint: str,
        content_tier: str,
    ) -> bool:
        """Fixture-parity stub: fail-open on the content-tier axis.

        Slice-2.5 ``DevGate.check_content_clearance`` returned
        ``True`` unconditionally so dispatch tests didn't double-gate
        on the orthogonal content axis. The fixture preserves that
        posture — tests that exercise the content-tier deny path
        construct :class:`RealGate` via :func:`make_deny_all_gate`
        instead.
        """
        del plugin_id, hookpoint, content_tier
        return True


def make_permissive_fixture_gate(*, allow_system: bool = False) -> CapabilityGate:
    """Return a permissive fixture-parity gate matching Slice-2.5 ``DevGate`` semantics.

    ``operator`` and ``user-plugin`` are always granted; ``system``
    grants iff ``allow_system=True``. The gate ignores ``plugin_id``
    and ``hookpoint`` (per the Slice-2.5 :class:`DevGate` shape), so
    a test that registers a subscriber under an arbitrary module-named
    plugin id continues to register cleanly.

    **NEVER use for deny-path security tests** — Slice-3 spec §15.1
    mandates those assert against :class:`RealGate` (via
    :func:`make_deny_all_gate`). See :class:`_DevGateLikeFixture`'s
    docstring for the full list of legitimate uses (dispatcher fault
    paths, hookpoint declaration metadata, positive controls,
    plugin-load contract, performance benchmarks, the
    :func:`fresh_registry` fixture family). The "permissive" name
    is deliberately loud: a reviewer who sees this in a test asserting
    refusal should question why.

    Used by the registry-fixture family in
    :mod:`tests.unit.hooks.conftest` — the Slice-2.5 test bodies that
    register an ``operator``-tier subscriber under a default fixture
    keep working without per-test rework. Tests that need strict
    :class:`RealGate` semantics (empty grants ⇒ deny operator too,
    exact ``plugin_id`` match) use :func:`make_deny_all_gate` /
    :func:`make_allow_system_gate` directly.

    The returned object is structurally a
    :class:`alfred.hooks.capability.CapabilityGate` (:func:`isinstance`
    check passes) but is not a :class:`RealGate` instance — it's the
    private :class:`_DevGateLikeFixture` test double.
    """
    return _DevGateLikeFixture(allow_system=allow_system)


__all__ = [
    "make_allow_system_gate",
    "make_deny_all_gate",
    "make_permissive_fixture_gate",
]
