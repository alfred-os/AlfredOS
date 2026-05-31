"""Tests for ``alfred.security.capability_gate.policy`` — pure policy matching.

The :class:`GatePolicy` module is the in-memory layer above the Postgres
read in :class:`RealGate`. It is pure: no I/O, no env reads, no external
state. Spec §8.1 (Fork 7) requires that hot-path checks dispatch through
this layer; spec §8.5 pins the ``subscriber_tier`` (not ``tier``) field
name to match the manifest naming rule in §4.3.

Invariants pinned here:

* **Frozen rows** — :class:`GrantRow` is a frozen dataclass; mutation
  raises :class:`dataclasses.FrozenInstanceError`. The policy snapshot
  cannot be tampered with at runtime.
* **Wildcard semantics** — a grant with ``hookpoint="*"`` covers every
  hookpoint for the matching ``(plugin_id, subscriber_tier)`` pair. Used
  for plugin-load grants.
* **Empty grants always deny** — the default state of a fresh
  :class:`GatePolicy` (no grants) denies every check. CLAUDE.md hard
  rule #7 (no silent failures) requires the empty case fail-closed.
* **sec-007 (no env reads in policy)** — ``policy.py`` must NOT
  ``import os`` (no env reads, no path lookups). An AST-scan in this
  module enforces the source-level pin; the corresponding
  capability.py guard lives in ``tests/unit/hooks/`` (Slice-2.5).
"""

from __future__ import annotations

import pytest

from alfred.security.capability_gate.policy import GatePolicy, GrantRow


def test_grant_row_is_frozen() -> None:
    """:class:`GrantRow` is a frozen dataclass; post-init mutation raises."""
    row = GrantRow(
        plugin_id="test.plugin",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
        proposal_branch="proposal/policy-grant-abc",
    )
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        row.plugin_id = "other"  # type: ignore[misc]


def test_gate_policy_check_returns_true_for_matching_grant() -> None:
    """A grant present in the policy snapshot grants on ``check()``."""
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="test.plugin",
                    subscriber_tier="operator",
                    hookpoint="tool.web.fetch",
                    content_tier=None,
                    proposal_branch="proposal/policy-grant-abc",
                )
            }
        )
    )
    assert (
        policy.check(
            plugin_id="test.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is True
    )


def test_gate_policy_check_returns_false_for_no_matching_grant() -> None:
    """An empty :class:`GatePolicy` denies every ``check()``."""
    policy = GatePolicy(grants=frozenset())
    assert (
        policy.check(
            plugin_id="test.plugin",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is False
    )


def test_gate_policy_check_plugin_load_uses_subscriber_tier() -> None:
    """``check_plugin_load`` consults the subscriber-tier axis only.

    Spec §8.2: ``manifest_tier`` is matched against the grant's
    ``subscriber_tier``. A grant declared at ``system`` does NOT cover
    an ``operator`` plugin-load request even when the plugin id matches.
    """
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="mypl",
                    subscriber_tier="system",
                    hookpoint="*",
                    content_tier=None,
                    proposal_branch="proposal/policy-grant-xyz",
                )
            }
        )
    )
    assert policy.check_plugin_load(plugin_id="mypl", manifest_tier="system") is True
    assert policy.check_plugin_load(plugin_id="mypl", manifest_tier="operator") is False


def test_gate_policy_check_content_clearance_matches_content_tier() -> None:
    """``check_content_clearance`` consults the orthogonal content-tier axis.

    Spec §8.2: ``content_tier`` matching is exact — a ``T3`` grant
    does not grant ``T2`` access (and vice versa). ``plugin_id`` must
    also match: a ``T3`` grant for ``quarantine.host`` does NOT clear
    ``other.plugin`` for ``T3`` content.
    """
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="quarantine.host",
                    subscriber_tier="system",
                    hookpoint="tag.T3",
                    content_tier="T3",
                    proposal_branch="proposal/policy-grant-t3",
                )
            }
        )
    )
    assert (
        policy.check_content_clearance(
            plugin_id="quarantine.host",
            hookpoint="tag.T3",
            content_tier="T3",
        )
        is True
    )
    assert (
        policy.check_content_clearance(
            plugin_id="other.plugin",
            hookpoint="tag.T3",
            content_tier="T3",
        )
        is False
    )


def test_gate_policy_wildcard_hookpoint_matches_any() -> None:
    """A grant with ``hookpoint="*"`` covers every hookpoint string.

    Used for plugin-load grants: a single ``hookpoint="*"`` row covers
    all subsequent invocations of the plugin under that subscriber_tier.
    """
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="mypl",
                    subscriber_tier="system",
                    hookpoint="*",
                    content_tier=None,
                    proposal_branch="proposal/policy-grant-xyz",
                )
            }
        )
    )
    assert (
        policy.check(
            plugin_id="mypl",
            hookpoint="any.hookpoint.at.all",
            requested_tier="system",
        )
        is True
    )


def test_gate_policy_empty_grants_always_denies() -> None:
    """A :class:`GatePolicy` with no grants denies every check method.

    CLAUDE.md hard rule #7: the fail-closed default is the no-silent-
    failures contract. An empty-grants policy is also the bootstrap
    state before :meth:`RealGate._apply_grants` runs.
    """
    policy = GatePolicy(grants=frozenset())
    assert policy.check(plugin_id="x", hookpoint="y", requested_tier="system") is False
    assert policy.check_plugin_load(plugin_id="x", manifest_tier="system") is False
    assert policy.check_content_clearance(plugin_id="x", hookpoint="y", content_tier="T3") is False


def test_gate_policy_check_content_clearance_wildcard_hookpoint() -> None:
    """A T-grant with ``hookpoint="*"`` covers every hookpoint at that content_tier.

    Used by future quarantine.host grants that need to clear T3 across
    every hookpoint without enumerating each one.
    """
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="quarantine.host",
                    subscriber_tier="system",
                    hookpoint="*",
                    content_tier="T3",
                    proposal_branch="proposal/policy-grant-t3-wild",
                )
            }
        )
    )
    assert (
        policy.check_content_clearance(
            plugin_id="quarantine.host",
            hookpoint="any.hookpoint",
            content_tier="T3",
        )
        is True
    )


def test_gate_policy_check_skips_grants_with_wrong_plugin_id() -> None:
    """Grants for other plugins are skipped silently — branch coverage for plugin_id mismatch."""
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="other.plugin",
                    subscriber_tier="operator",
                    hookpoint="tool.web.fetch",
                    content_tier=None,
                    proposal_branch="proposal/policy-grant-other",
                )
            }
        )
    )
    assert (
        policy.check(
            plugin_id="mypl",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is False
    )


def test_gate_policy_check_skips_grants_with_wrong_subscriber_tier() -> None:
    """Grants with non-matching subscriber_tier are skipped — branch coverage for tier mismatch."""
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="mypl",
                    subscriber_tier="system",
                    hookpoint="tool.web.fetch",
                    content_tier=None,
                    proposal_branch="proposal/policy-grant-sys",
                )
            }
        )
    )
    assert (
        policy.check(
            plugin_id="mypl",
            hookpoint="tool.web.fetch",
            requested_tier="operator",
        )
        is False
    )


def test_gate_policy_check_skips_grants_with_wrong_hookpoint() -> None:
    """Branch coverage: ``check`` skips grants whose hookpoint is specific and does not match.

    Exercises the loop-continue branch where ``plugin_id`` and
    ``subscriber_tier`` both match but the grant's ``hookpoint`` is a
    specific (non-wildcard) string different from the requested one.
    The loop body falls through to the next iteration; with no further
    grants, ``check`` returns ``False``.
    """
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="mypl",
                    subscriber_tier="operator",
                    hookpoint="tool.web.fetch",  # specific, not wildcard
                    content_tier=None,
                    proposal_branch="proposal/policy-grant-narrow",
                )
            }
        )
    )
    assert (
        policy.check(
            plugin_id="mypl",
            hookpoint="tool.other.hookpoint",  # different from grant's hookpoint
            requested_tier="operator",
        )
        is False
    )


def test_gate_policy_check_content_clearance_skips_wrong_plugin_id() -> None:
    """Branch coverage: content-clearance skips grants whose plugin_id does not match."""
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="other.plugin",
                    subscriber_tier="system",
                    hookpoint="tag.T3",
                    content_tier="T3",
                    proposal_branch="proposal/policy-grant-other-t3",
                )
            }
        )
    )
    assert (
        policy.check_content_clearance(
            plugin_id="quarantine.host",
            hookpoint="tag.T3",
            content_tier="T3",
        )
        is False
    )


def test_gate_policy_check_content_clearance_skips_wrong_content_tier() -> None:
    """Branch coverage: content-clearance skips grants whose content_tier does not match."""
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="quarantine.host",
                    subscriber_tier="system",
                    hookpoint="tag.T3",
                    content_tier="T2",  # different content tier
                    proposal_branch="proposal/policy-grant-t2",
                )
            }
        )
    )
    assert (
        policy.check_content_clearance(
            plugin_id="quarantine.host",
            hookpoint="tag.T3",
            content_tier="T3",
        )
        is False
    )


def test_gate_policy_check_content_clearance_skips_wrong_hookpoint() -> None:
    """Branch coverage: content-clearance skips when hookpoint differs and is not wildcard."""
    policy = GatePolicy(
        grants=frozenset(
            {
                GrantRow(
                    plugin_id="quarantine.host",
                    subscriber_tier="system",
                    hookpoint="tag.T3",  # specific, not wildcard
                    content_tier="T3",
                    proposal_branch="proposal/policy-grant-t3-narrow",
                )
            }
        )
    )
    assert (
        policy.check_content_clearance(
            plugin_id="quarantine.host",
            hookpoint="other.hookpoint",
            content_tier="T3",
        )
        is False
    )


def test_policy_module_does_not_import_os() -> None:
    """AST-scan: ``policy.py`` must NOT import ``os`` (sec-007 extension).

    The same source-level pin enforced for ``capability.py`` in Slice-2.5
    is enforced here for the capability-gate policy module. No env reads,
    no path lookups, no environment-dependent grant decisions. DSN /
    ALFRED_ENV selection lives in ``gate_factory.py`` (PR-S3-2 Task 14
    cousin work).
    """
    import ast
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[4]
        / "src"
        / "alfred"
        / "security"
        / "capability_gate"
        / "policy.py"
    )
    tree = ast.parse(src.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "os", "policy.py must not import os"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "os", "policy.py must not from os import ..."
