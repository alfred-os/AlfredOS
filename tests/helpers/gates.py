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
from typing import cast
from unittest.mock import create_autospec

from alfred.hooks.capability import CapabilityGate
from alfred.security.capability_gate._audit_protocols import _AuditSink
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.backend import StorageBackend
from alfred.security.capability_gate.policy import GatePolicy, GrantRow

# The three tier strings the fixture-parity gate recognises. Module-level
# so a maintainer changing the closed set surfaces the change next to
# the policy logic (mirrors the layout :mod:`alfred.security.capability_gate.policy`
# uses for its own closed-domain set).
_FIXTURE_TIERS_GRANTED_UNCONDITIONALLY: frozenset[str] = frozenset({"operator", "user-plugin"})
_FIXTURE_TIER_GATED_BY_ALLOW_SYSTEM: str = "system"


def _make_in_memory_backend(grants: Iterable[GrantRow] = ()) -> StorageBackend:
    """Return a :class:`StorageBackend`-shaped stub pre-loaded with ``grants``.

    The stub satisfies the structural :class:`StorageBackend` Protocol
    without any database I/O. Built via
    :func:`unittest.mock.create_autospec` against the Protocol with
    ``spec_set=True``: every async method auto-binds as an
    :class:`AsyncMock` whose signature matches the Protocol's, so a
    typo'd method name or an unexpected keyword on a hot-path call
    (e.g. ``backend.apply_atomic(revoke=...)`` instead of
    ``revokes=...``) raises :class:`AttributeError` /
    :class:`TypeError` immediately instead of silently accepting the
    call. Without ``spec_set`` a regression in :meth:`RealGate._apply_grants`
    could swap a kwarg name and keep tests green — CLAUDE.md hard rule
    #7 (no silent failures in security paths) forbids that shape.

    Tests that drive the test-shim gate consult the in-memory
    :class:`GatePolicy` snapshot, not the backend, so the backend's
    return values only matter on the heartbeat path — which tests can
    opt out of by leaving ``start_heartbeat=False``. ``load_grants``
    gets a seeded return value so :class:`RealGate.__init__` can read
    a deterministic snapshot when callers pass ``grants``.

    Return type is the :class:`StorageBackend` Protocol, not :class:`Any`:
    the Protocol is ``@runtime_checkable`` and the caller feeds the
    result to :class:`RealGate.__init__`'s ``backend: StorageBackend``
    parameter, so the structural type hint is the load-bearing contract.
    Mirrors the production-side stub builder
    :func:`alfred.bootstrap.gate_factory._make_in_memory_backend` (the
    pair is duplicated by design per ADR-0019 — the production stub
    cannot live under ``src/`` AND be importable from tests, and the
    test stub cannot live under ``tests/`` AND be importable from
    ``src/``).
    """
    backend = create_autospec(StorageBackend, spec_set=True, instance=True)
    backend.load_grants.return_value = frozenset(grants)
    # ``create_autospec`` returns ``Any`` (per the stdlib stubs); the cast
    # restores the Protocol contract for the caller. ``isinstance`` against
    # the ``@runtime_checkable`` Protocol still passes at runtime — the
    # cast carries the type information across the mypy boundary that the
    # mock library's typing erases.
    return cast(StorageBackend, backend)


def _make_no_op_audit_sink() -> _AuditSink:
    """Return an audit-sink stub for tests that don't assert on rows.

    err-003: :meth:`RealGate.create` requires an audit sink so a
    fail-closed state transition cannot land without an audit row. The
    test shim is only used in deny-path / granted-path fixtures where
    audit emission isn't the property under test — the no-op sink
    satisfies the constructor contract without inflating the test
    surface area.

    Built via :func:`unittest.mock.create_autospec` against the
    :class:`_AuditSink` Protocol with ``spec_set=True``: a future
    addition to the Protocol surfaces here as an
    :class:`AttributeError`, and a kwarg-name drift on
    :meth:`_AuditSink.append_schema` (e.g. ``schema=...`` instead of
    ``schema_name=...``) raises :class:`TypeError` immediately. Without
    ``spec_set`` a security regression could rename a kwarg and keep
    tests green — CLAUDE.md hard rule #7 forbids that shape.

    Return type is the :class:`_AuditSink` Protocol (shared with
    :mod:`alfred.security.capability_gate.proposals` per
    :mod:`alfred.security.capability_gate._audit_protocols`), not
    :class:`Any`. Mirrors
    :func:`alfred.bootstrap.gate_factory._make_no_op_audit_sink`
    (duplicated by design per ADR-0019).
    """
    # ``create_autospec`` returns ``Any`` (per the stdlib stubs); the cast
    # restores the Protocol contract for the caller. ``isinstance`` against
    # the ``@runtime_checkable`` Protocol still passes at runtime.
    return cast(_AuditSink, create_autospec(_AuditSink, spec_set=True, instance=True))


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


def make_quarantined_extract_chain_gate(
    *,
    plugin_id: str = "alfred.security._extract_dlp_subscriber",
    allow_sibling_operator: bool = False,
    sibling_operator_plugin_id: str | None = None,
    extra_system_plugin_ids: Iterable[str] = (),
    extra_operator_plugin_ids: Iterable[str] = (),
    grant_dereference_t3: bool = False,
    dereference_plugin_id: str = "alfred.quarantined-llm",
    grant_downgrade_t3: bool = False,
) -> CapabilityGate:
    """Return a :class:`RealGate` scoped to the
    ``security.quarantined.extract`` chain — the canonical scoped-grant
    posture for #158-era trust-boundary tests.

    Slice-3 spec §15.1 + CLAUDE.md hard rule #2: tests on the
    trust-boundary MUST use scoped fixture grants, NOT
    :func:`make_permissive_fixture_gate(allow_system=True)`. The
    permissive shim ignores ``plugin_id`` / ``hookpoint`` so a
    regression in the grant-policy check is invisible at test time —
    exactly what CLAUDE.md hard rule #2 forbids.

    The returned gate seeds:

    * **system-tier grant** for ``(plugin_id, "security.quarantined.extract")``
      — covers :class:`OutboundDlpExtractSubscriber` registration via
      :func:`register_extract_dlp_subscriber`, which uses
      ``OutboundDlpExtractSubscriber.__call__.__module__`` (=
      ``"alfred.security._extract_dlp_subscriber"``) as its plugin_id.
    * **operator-tier grant** (only when ``allow_sibling_operator=True``)
      for ``(sibling_operator_plugin_id or plugin_id,
      "security.quarantined.extract")`` — covers tests that register a
      sibling operator-tier subscriber (e.g. a future telemetry observer)
      next to the system DLP scan to assert that the helper's
      idempotency check skips past unrelated subscribers. Tests that
      don't register siblings leave ``allow_sibling_operator=False``;
      the gate denies any operator request on the chain.
    * **content-tier T3 grant** for ``(dereference_plugin_id,
      "quarantine.dereference")`` (only when
      ``grant_dereference_t3=True``) — covers the
      :func:`quarantined_to_structured` content-clearance check on the
      T3 boundary (PRD §7.1). CR-158 round 2 caught the gap: the
      helper previously seeded only subscriber-tier grants, so
      ``check_content_clearance()`` on the T3 boundary was never
      exercised against :class:`RealGate` and a grant-matching
      regression there would have stayed green in CI. Tests that
      construct an extractor and exercise dereference on the same
      fixture pass ``grant_dereference_t3=True``; tests that only
      register the DLP subscriber leave it :data:`False` so the deny
      path remains explicit.
      Downgrade authorization is a SEPARATE
      ``(plugin_id, hookpoint)`` grant covered by the distinct
      ``grant_downgrade_t3`` flag (see argument docs below); the
      ``quarantine.dereference`` grant alone does NOT authorize the
      ``t3.downgrade_to_orchestrator`` clearance check.

    The grants are EXACT (``hookpoint="security.quarantined.extract"``,
    not ``"*"``) so a future test that registers a system-tier
    subscriber on a DIFFERENT hookpoint is denied — the gate's grant
    posture is the load-bearing security signal, not a permissive
    backstop.

    Args:
        plugin_id: The plugin id the system-tier grant covers. Defaults
            to ``"alfred.security._extract_dlp_subscriber"`` — the
            attribution the production helper passes when registering
            the canonical DLP scan.
        allow_sibling_operator: Seed the operator-tier grant when
            :data:`True`. Default :data:`False`.
        sibling_operator_plugin_id: Override the plugin_id covered by
            the operator-tier grant. When :data:`None` (default) the
            grant covers ``plugin_id`` itself; tests registering a
            sibling whose ``__module__`` differs from the DLP
            subscriber's pass the sibling's module name here.
        extra_system_plugin_ids: Additional plugin_ids that should
            receive a system-tier grant for the chain. Tests that
            register ad-hoc system-tier observers (e.g. pre/error-stage
            test subscribers whose ``__module__`` resolves to the test
            module) pass their module names here so the scoped gate
            grants them without resorting to a permissive shim.
        extra_operator_plugin_ids: Same shape as
            ``extra_system_plugin_ids`` but for operator-tier
            registrations.
        grant_dereference_t3: Seed the content-tier T3 grant for the
            ``quarantine.dereference`` hookpoint when :data:`True`.
            Default :data:`False`. Tests that exercise
            :func:`quarantined_to_structured` /
            :func:`downgrade_to_orchestrator` against the returned
            :class:`RealGate` pass :data:`True`; tests that pin the
            deny path leave it :data:`False` (an unscoped gate denies
            content clearance fail-closed).
        dereference_plugin_id: Override the plugin_id covered by the
            ``quarantine.dereference`` content-tier T3 grant.
            Default ``"alfred.quarantined-llm"`` — the attribution
            :func:`quarantined_to_structured` passes at the
            content-clearance call site
            (:data:`alfred.security.quarantine.QuarantinedExtractor._PLUGIN_ID`).
        grant_downgrade_t3: Seed the content-tier T3 grant for the
            ``t3.downgrade_to_orchestrator`` hookpoint when
            :data:`True`. Default :data:`False`. The downgrade path
            uses a DIFFERENT
            (plugin_id, hookpoint) tuple from the dereference path
            (``("t3.downgrade_to_orchestrator",
            "t3.downgrade_to_orchestrator")``); tests that exercise
            :func:`downgrade_to_orchestrator` against the returned
            :class:`RealGate` pass :data:`True`.

    Returns:
        A :class:`RealGate` instance — production gate code, not a
        test shim. ``check`` consults the seeded grant set; any
        request outside the seeded scope denies fail-closed.

    Use this in place of :func:`make_permissive_fixture_gate` for
    every test that:

    * Constructs a :class:`alfred.security.quarantine.QuarantinedExtractor`
      (the constructor calls :func:`register_extract_dlp_subscriber`
      which fails closed without a granted gate post-CR-156 round 7),
      OR
    * Calls :func:`register_extract_dlp_subscriber` directly,
      OR
    * Dispatches through the ``security.quarantined.extract`` chain.
    """
    grants: set[GrantRow] = {
        GrantRow(
            plugin_id=plugin_id,
            subscriber_tier="system",
            hookpoint="security.quarantined.extract",
            content_tier=None,
            proposal_branch="test-fixture",
        )
    }
    if allow_sibling_operator:
        grants.add(
            GrantRow(
                plugin_id=sibling_operator_plugin_id or plugin_id,
                subscriber_tier="operator",
                hookpoint="security.quarantined.extract",
                content_tier=None,
                proposal_branch="test-fixture",
            )
        )
    for extra_plugin_id in extra_system_plugin_ids:
        grants.add(
            GrantRow(
                plugin_id=extra_plugin_id,
                subscriber_tier="system",
                hookpoint="security.quarantined.extract",
                content_tier=None,
                proposal_branch="test-fixture",
            )
        )
    for extra_plugin_id in extra_operator_plugin_ids:
        grants.add(
            GrantRow(
                plugin_id=extra_plugin_id,
                subscriber_tier="operator",
                hookpoint="security.quarantined.extract",
                content_tier=None,
                proposal_branch="test-fixture",
            )
        )
    if grant_dereference_t3:
        # The content-clearance check at the T3 boundary is the
        # gate-first short-circuit in :func:`quarantined_to_structured`.
        # ``subscriber_tier`` is set to ``"system"`` because
        # :class:`GrantRow` requires a value from the closed domain
        # ``{"system", "operator", "user-plugin"}`` (CR-139 finding
        # #4); the production content-clearance check
        # (:meth:`GatePolicy.check_content_clearance`) consults
        # ``content_tier`` only (spec §4.3 — orthogonal axes), so
        # the subscriber-tier value on this row is structurally
        # required but functionally inert at the
        # ``quarantine.dereference`` call site.
        grants.add(
            GrantRow(
                plugin_id=dereference_plugin_id,
                subscriber_tier="system",
                hookpoint="quarantine.dereference",
                content_tier="T3",
                proposal_branch="test-fixture",
            )
        )
    if grant_downgrade_t3:
        # :func:`downgrade_to_orchestrator` uses a distinct
        # (plugin_id, hookpoint) tuple from
        # :func:`quarantined_to_structured` — the downgrade has its
        # own forensic anchor (``T3_DERIVED_DOWNGRADE_FIELDS``) so
        # the gate row is also distinct. Same subscriber_tier rationale
        # as the dereference row above.
        grants.add(
            GrantRow(
                plugin_id="t3.downgrade_to_orchestrator",
                subscriber_tier="system",
                hookpoint="t3.downgrade_to_orchestrator",
                content_tier="T3",
                proposal_branch="test-fixture",
            )
        )
    frozen_grants = frozenset(grants)
    return RealGate(
        policy=GatePolicy(grants=frozen_grants),
        backend=_make_in_memory_backend(grants=frozen_grants),
        audit_sink=_make_no_op_audit_sink(),
    )


__all__ = [
    "make_allow_system_gate",
    "make_deny_all_gate",
    "make_permissive_fixture_gate",
    "make_quarantined_extract_chain_gate",
]
