"""CapabilityGate Protocol + RealGate deny-path tests.

``DevGate`` was removed in PR-S3-7 (spec §15.1 flag-day). These tests
assert the deny-path invariants against the real :class:`RealGate`
implementation, constructed via the :mod:`tests.helpers.gates`
factories that wrap :class:`RealGate` with an in-memory stub backend
(no testcontainer, no Postgres).

Hard rules preserved:

* **CLAUDE.md hard rule #4** — never bypass the capability layer. The
  deny paths assert against the real :class:`RealGate` refusal, never
  a stub or "always allow" double. The unknown-tier and
  no-grant-for-system branches MUST return ``False`` and the test
  verifies that directly.
* **CLAUDE.md hard rule #7** — no silent failures. An unknown / typo'd
  / case-mismatched tier denies fail-closed. Empty string,
  alternate-case variants of known tiers (``"SYSTEM"``), and unknown
  names (``"root"``) all return ``False`` even when a system-tier
  grant exists for the (plugin_id, hookpoint) pair.
* **sec-007 (no env reads)** — :mod:`alfred.hooks.capability` imports
  nothing from :mod:`os`. The AST-scan in :func:`test_capability_py_reads_no_env`
  is the source-level pin against any future re-introduction;
  ``ALFRED_ENV`` selection lives in
  :mod:`alfred.bootstrap.gate_factory`, not in :mod:`capability`.
* **Structural subtyping** — :class:`RealGate` satisfies the
  :class:`CapabilityGate` Protocol structurally. Pinning
  ``isinstance(make_deny_all_gate(), CapabilityGate)`` lets dispatcher
  code type-narrow on :class:`CapabilityGate` without a registry of
  concrete subclasses.
* **§15.1 flag-day** — :class:`DevGate` is gone from ``src/``. The
  regression guard at the bottom of this file asserts the import
  raises :class:`ImportError`; the dedicated
  ``test_devgate_removed.py`` module is the small focused twin.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from alfred.hooks.capability import CapabilityGate
from tests.helpers.gates import make_allow_system_gate, make_deny_all_gate


def test_realgate_deny_all_with_empty_store() -> None:
    """:class:`RealGate` with an empty grant store denies all check() calls.

    This is the equivalent deny-path invariant that ``DevGate()``
    (no args) provided — no grants ⇒ every check denies fail-closed
    (spec §8.1).
    """
    gate = make_deny_all_gate()
    assert not gate.check(plugin_id="test", hookpoint="tool.web.fetch", requested_tier="system")
    assert not gate.check(plugin_id="test", hookpoint="tool.web.fetch", requested_tier="operator")
    assert not gate.check(
        plugin_id="test", hookpoint="tool.web.fetch", requested_tier="user-plugin"
    )


@pytest.mark.parametrize("bad_tier", ["SYSTEM", "System", "root", "None", "t3"])
def test_realgate_deny_unknown_tier(bad_tier: str) -> None:
    """Unknown / typo'd / case-mismatched tier strings deny (fail-closed).

    CLAUDE.md hard rule #7: no silent failures. Unrecognised input
    denies even when a wildcard system grant exists for the
    (plugin_id, hookpoint) pair — the grant table is exact-match on
    the tier string, so ``"SYSTEM"`` (uppercase) never matches a
    stored ``"system"`` grant.
    """
    gate = make_allow_system_gate(plugin_id="test", hookpoint="*")
    assert not gate.check(plugin_id="test", hookpoint="anything", requested_tier=bad_tier), (
        f"Expected deny for tier={bad_tier!r}"
    )


def test_realgate_deny_empty_string_tier() -> None:
    """An empty tier string denies — the empty-string deny path is its own row.

    Parametrising the empty string alongside the alphabetic bad tiers
    in :func:`test_realgate_deny_unknown_tier` produces an ugly pytest
    nodeid (``[]``). Keeping the empty-string case as its own test
    keeps the report readable while preserving the deny-path coverage.
    """
    gate = make_allow_system_gate(plugin_id="test", hookpoint="*")
    assert not gate.check(plugin_id="test", hookpoint="anything", requested_tier="")


def test_realgate_with_system_grant_allows_system() -> None:
    """:class:`RealGate` with a seeded system-tier grant allows check() for system.

    Equivalent to ``DevGate(allow_system=True)`` — the grant exists,
    so the check passes for the (plugin_id, hookpoint, ``"system"``)
    triple that matches the seeded row.
    """
    gate = make_allow_system_gate(plugin_id="test-plugin", hookpoint="tool.web.fetch")
    assert gate.check(
        plugin_id="test-plugin",
        hookpoint="tool.web.fetch",
        requested_tier="system",
    )


def test_realgate_with_system_grant_wildcard_matches_any_hookpoint() -> None:
    """A wildcard system grant covers every hookpoint at that plugin id.

    The default ``hookpoint="*"`` on :func:`make_allow_system_gate`
    mirrors the convention used by the Slice-2.5 fixtures, where
    ``DevGate(allow_system=True)`` granted ``system`` regardless of
    the hookpoint argument. The :class:`alfred.security.capability_gate.policy.GatePolicy`
    wildcard semantics preserve that posture under :class:`RealGate`.
    """
    gate = make_allow_system_gate()  # plugin_id="test-plugin", hookpoint="*"
    assert gate.check(
        plugin_id="test-plugin",
        hookpoint="anything.at.all",
        requested_tier="system",
    )


def test_realgate_with_system_grant_denies_other_plugin() -> None:
    """A system grant for one plugin does NOT cover a different plugin.

    The grant table is keyed on ``plugin_id``; a wildcard system grant
    for ``test-plugin`` denies the same tier request from
    ``other-plugin``. This is the load-bearing invariant that prevents
    one plugin's grant from authorising another plugin's dispatch.
    """
    gate = make_allow_system_gate(plugin_id="test-plugin")
    assert not gate.check(
        plugin_id="other-plugin",
        hookpoint="tool.web.fetch",
        requested_tier="system",
    )


def test_realgate_check_plugin_load_deny_without_grant() -> None:
    """:meth:`RealGate.check_plugin_load` returns ``False`` without a grant.

    Spec §8.2: plugin-load is gated against the same (plugin_id,
    manifest_tier) projection — no grant means the supervisor refuses
    to open the plugin's stdio transport.
    """
    gate = make_deny_all_gate()
    assert not gate.check_plugin_load(plugin_id="new-plugin", manifest_tier="system")
    assert not gate.check_plugin_load(plugin_id="new-plugin", manifest_tier="operator")


def test_realgate_check_content_clearance_deny_without_grant() -> None:
    """:meth:`RealGate.check_content_clearance` returns ``False`` without a grant.

    Spec §8.2 / Fork 7: T3 content must not reach T2-only paths. With
    no content-tier grant the gate denies on every content tier —
    fail-closed default on the orthogonal trust axis.
    """
    gate = make_deny_all_gate()
    assert not gate.check_content_clearance(plugin_id="test", hookpoint="tag.T3", content_tier="T3")


def test_realgate_satisfies_capability_gate_protocol() -> None:
    """:class:`RealGate` is structurally a :class:`CapabilityGate`.

    The Protocol is ``@runtime_checkable``; the test-helper factories
    return :class:`RealGate` instances, so the structural membership
    check passes against the production gate type — no parallel test
    gate hierarchy.
    """
    assert isinstance(make_deny_all_gate(), CapabilityGate)
    assert isinstance(make_allow_system_gate(), CapabilityGate)


def test_realgate_check_is_keyword_only() -> None:
    """:meth:`RealGate.check` is keyword-only on every parameter.

    The verbatim spec §0 signature reads ``check(self, *, plugin_id,
    hookpoint, requested_tier) -> bool`` — the ``*,`` is the contract.
    A caller cannot accidentally swap ``plugin_id`` and ``hookpoint``
    via positional args; the type system enforces the boundary.
    """
    gate = make_deny_all_gate()
    with pytest.raises(TypeError):
        gate.check("p", "h", "operator")  # type: ignore[misc]


def test_capability_module_has_no_devgate() -> None:
    """``DevGate`` must not exist in :mod:`alfred.hooks.capability`.

    Regression guard per spec §15.1: the flag-day PR removes the
    Slice-2.5 :class:`DevGate` class. The dedicated
    ``test_devgate_removed.py`` test is the focused twin; this
    assertion lives alongside the rest of the capability surface so a
    re-introduction surfaces here as well.
    """
    with pytest.raises(ImportError):
        from alfred.hooks.capability import DevGate  # type: ignore[attr-defined]  # noqa: F401


def test_capability_py_reads_no_env() -> None:
    """:mod:`alfred.hooks.capability` must not read environment variables.

    sec-007: ``ALFRED_ENV`` selection lives in
    :mod:`alfred.bootstrap.gate_factory`, not here. The AST scan asserts
    no ``os.environ`` attribute access, no ``os.environ.get``-style call,
    and no ``os.getenv`` call appears in the module source. The
    behavioural pin against env-driven gate behaviour now lives in
    ``test_capability_sec007.py``; this is the source-level guard.
    """
    source = Path("src/alfred/hooks/capability.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    class EnvReadVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.violations: list[tuple[int, str]] = []

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if (
                isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "environ"
            ):
                self.violations.append((node.lineno, "os.environ.attr"))
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "os"
                    and node.func.value.attr == "environ"
                ):
                    self.violations.append((node.lineno, "os.environ.method"))
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr == "getenv"
                ):
                    self.violations.append((node.lineno, "os.getenv"))
            self.generic_visit(node)

    visitor = EnvReadVisitor()
    visitor.visit(tree)
    assert not visitor.violations, (
        "capability.py must not read environment variables (sec-007). "
        f"Violations: {visitor.violations}"
    )


def test_capability_gate_protocol_has_check_plugin_load() -> None:
    """:class:`CapabilityGate` Protocol exposes ``check_plugin_load``.

    PR-S3-2 (spec §8.2) extended the Protocol with this method so the
    supervisor can refuse a plugin at handshake time when no
    subscriber-tier grant exists. The signature is keyword-only on
    ``plugin_id`` / ``manifest_tier`` and every gate implementation
    MUST honour it.
    """
    import inspect

    assert "check_plugin_load" in dir(CapabilityGate)
    sig = inspect.signature(CapabilityGate.check_plugin_load)
    assert "plugin_id" in sig.parameters
    assert "manifest_tier" in sig.parameters


def test_capability_gate_protocol_has_check_content_clearance() -> None:
    """:class:`CapabilityGate` Protocol exposes ``check_content_clearance``.

    PR-S3-2 (spec §8.2) extended the Protocol with the orthogonal
    content-trust axis. The quarantined-LLM plugin host and
    StdioTransport are the only authorised callers for
    ``content_tier="T3"``; every other caller receives a refusal.
    """
    import inspect

    assert "check_content_clearance" in dir(CapabilityGate)
    sig = inspect.signature(CapabilityGate.check_content_clearance)
    assert "plugin_id" in sig.parameters
    assert "hookpoint" in sig.parameters
    assert "content_tier" in sig.parameters
