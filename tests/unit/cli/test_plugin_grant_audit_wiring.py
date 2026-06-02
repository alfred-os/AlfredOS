"""Task 19 — Component K: ``plugin.grant.*`` hookpoint + audit wiring (CLI).

This module pins the CLI-side contract for Component K:

* The ``alfred plugin`` CLI module imports the canonical
  :data:`alfred.audit.audit_row_schemas.PLUGIN_GRANT_FIELDS` constant.
  A future refactor that drops the import (or shadows it with a local
  copy) silently desyncs the CLI's audit-row shape from the schema
  module; this test fails loudly the moment that happens.
* The four spec §14 ``plugin.grant.*`` hookpoints are declared on the
  process registry at the moment the CLI sub-app loads. They are
  declared by :mod:`alfred.security.capability_gate.proposals` at
  module-import time; the CLI module imports the same proposal stack
  transitively via ``StateGitProposalClient`` callers, so by the time
  any operator invokes ``alfred plugin grant`` the registry already
  carries the four hookpoint metadata records.

The audit-row emission itself lives in
:func:`alfred.security.capability_gate.proposals.create_proposal_branch`,
which has its own 100% line+branch unit-test coverage in
:mod:`tests.unit.security.capability_gate.test_audit_wiring`. The CLI's
:class:`StateGitProposalClient` writes the proposal branch but does NOT
emit the audit row directly: that's the responsibility of the
asynchronous proposal-flow path that PR-S3-7 will surface up through
the Typer command (see ``src/alfred/cli/plugin.py`` module docstring
for the deferral rationale). Until then, this module guards the
constants + hookpoint declarations the CLI relies on.
"""

from __future__ import annotations

import pytest

from alfred.audit.audit_row_schemas import PLUGIN_GRANT_FIELDS
from alfred.hooks.registry import (
    SYSTEM_ONLY_TIERS,
    HookRegistry,
    get_registry,
    set_registry,
)
from alfred.security.capability_gate.proposals import (
    HOOKPOINT_GRANT_APPROVED,
    HOOKPOINT_GRANT_DENIED,
    HOOKPOINT_GRANT_REQUESTED,
    HOOKPOINT_GRANT_REVOKED,
)
from tests.helpers.gates import make_default_test_gate


def test_plugin_cli_imports_plugin_grant_fields_constant() -> None:
    """The CLI module re-exposes the canonical PLUGIN_GRANT_FIELDS frozenset.

    PR-S3-7 wires the audit-row emission through the CLI command path;
    when that lands, the emitter MUST reference this constant (not a
    locally-copied tuple) so the schema-module test corpus stays the
    single source of truth for grant audit-row shape. Importing the
    constant at the CLI module level both documents the contract today
    and ensures a ``from alfred.audit.audit_row_schemas import
    PLUGIN_GRANT_FIELDS`` line in ``plugin.py`` cannot be silently
    dropped by a future refactor.
    """
    from alfred.cli import plugin as plugin_cli

    assert plugin_cli.PLUGIN_GRANT_FIELDS is PLUGIN_GRANT_FIELDS
    # Pin the canonical set so a future schema edit that drops or
    # renames a field surfaces here too. Six fields per spec §14 /
    # PR-S3-0a's PLUGIN_GRANT_FIELDS declaration.
    assert (
        frozenset(
            {
                "plugin_id",
                "subscriber_tier",
                "hookpoint",
                "operator_user_id",
                "proposal_branch",
                "correlation_id",
            }
        )
        == PLUGIN_GRANT_FIELDS
    )


@pytest.fixture()
def isolated_registry(request: pytest.FixtureRequest) -> HookRegistry:
    """Install a fresh :class:`HookRegistry` and restore on teardown.

    The default fixture-parity gate (:func:`make_default_test_gate`,
    ``allow_system=False``) denies the ``system`` tier — fine here
    because :meth:`HookRegistry.register_hookpoint` does not consult
    the gate (the gate only fires on subscriber registration). Swap-
    and-restore so a sibling test's view of the global singleton is
    unaffected — same pattern as
    :mod:`tests.unit.identity.test_t1_hookpoint_declaration`.
    """
    prior = get_registry()
    registry = HookRegistry(gate=make_default_test_gate())
    set_registry(registry)

    def _restore() -> None:
        set_registry(prior)

    request.addfinalizer(_restore)
    return registry


def test_plugin_grant_hookpoints_declared_via_cli_module_import(
    isolated_registry: HookRegistry,
) -> None:
    """Importing the proposal module declares the four ``plugin.grant.*``
    hookpoints on the active registry.

    The CLI sub-app's :func:`_queue_grant_proposal` reaches the proposal
    layer via :class:`StateGitProposalClient`; the proposal module's
    module-level ``declare_hookpoints()`` call ensures the hookpoints
    are present in the active registry before any CLI command runs.

    CR-149: the previous shape called ``declare_hookpoints`` directly
    against the isolated registry, which proves the helper is
    idempotent but does NOT prove the spec §14 contract that
    "importing the proposal stack registers ``plugin.grant.*`` on the
    active registry". The proposal module's module-level import
    already executed before ``isolated_registry`` swapped the
    singleton — so the original test passed trivially. We now use
    :func:`importlib.reload` against ``alfred.security.capability_gate.proposals``
    so its module-level ``declare_hookpoints(get_registry())`` call
    re-runs against the freshly-installed isolated registry. This
    catches a regression that drops the module-level call (the
    invariant the CLI relies on) by inspecting the registry the
    reload populated, not one the test populated by hand.
    """
    import importlib

    import alfred.security.capability_gate.proposals as proposals_mod

    importlib.reload(proposals_mod)

    for name in (
        HOOKPOINT_GRANT_REQUESTED,
        HOOKPOINT_GRANT_APPROVED,
        HOOKPOINT_GRANT_DENIED,
        HOOKPOINT_GRANT_REVOKED,
    ):
        meta = isolated_registry.hookpoint_meta(name)
        assert meta is not None, (
            f"declare_hookpoints did not register {name!r}; "
            "the CLI's grant flow would emit hookpoint invocations "
            "the registry rejects with HookpointNotDeclared."
        )
        # Spec §14: system-only subscribable, no refusable tier. The
        # CLI inherits these -- a user-plugin subscriber to
        # ``plugin.grant.approved`` would observe every operator grant
        # approval, which is an exfiltration path the system-only
        # restriction closes.
        #
        # CR-149 round-3: ``fail_closed=False`` matches the spec §14
        # hookpoint table for every ``plugin.grant.*`` row. The
        # trust-boundary audit row that pins the reviewer's decision
        # is emitted via the supervisor's
        # :meth:`AuditWriter.append_schema` BEFORE the observer chain
        # runs, so a crashing observer cannot hide the grant from the
        # audit log — the row is already durable. The earlier
        # ``fail_closed=True`` choice (sec-pr-s3-6-05) was an override
        # that drifted from the spec table; round-3 reviewer pushed
        # back and the implementation now follows the spec.
        assert meta.subscribable_tiers == SYSTEM_ONLY_TIERS
        assert meta.refusable_tiers == frozenset()
        assert meta.fail_closed is False
