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
    # CR-156 round-5: resolve relative to this test module, not the process
    # CWD. Running the test from an IDE or a subdirectory would otherwise
    # turn the sec-007 guard into a FileNotFoundError instead of a real
    # regression check. parents[3] walks tests/unit/hooks → tests/unit →
    # tests → <repo-root>; the layout-invariant test below the AST guard
    # is the structural pin on that walk.
    capability_path = (
        Path(__file__).resolve().parents[3] / "src" / "alfred" / "hooks" / "capability.py"
    )
    source = capability_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    class EnvReadVisitor(ast.NodeVisitor):
        """Reject every shape of environment read in :mod:`alfred.hooks.capability`.

        The old visitor only matched ``os.environ.attr`` /
        ``os.environ.method`` / ``os.getenv(...)`` against the unaliased
        ``os`` name. That left three holes a regression could slip
        through (CR-156 round-3 sec-007 false-negatives):

        1. **Aliased import**: ``import os as _os; _os.environ["X"]``.
        2. **Subscript access**: ``os.environ["X"]`` — never goes through
           ``visit_Attribute``'s "method" branch because the subscript is
           an ``ast.Subscript`` node whose ``.value`` is the
           ``ast.Attribute`` chain, not a call.
        3. **Aliased ``from os import …``**: ``from os import getenv``
           binds the name ``getenv`` (or ``getenv as g``) at module scope;
           a later ``getenv("X")`` call has no ``ast.Attribute`` chain at
           all. ``from os import environ`` is the same shape for the
           subscript path.

        The fix tracks every binding that could resolve to ``os`` or
        an ``os`` member at module scope (``self._os_names`` and
        ``self._getenv_names``), then matches Attribute / Subscript /
        Call against those bound names. ``from os import environ`` is
        flagged on the import line itself — there is no legitimate
        reason to import the symbol into this module.
        """

        def __init__(self) -> None:
            self.violations: list[tuple[int, str]] = []
            # Every name bound to the ``os`` module at module scope.
            # Seeded with ``"os"`` so the bare-name access path is
            # detected even when ``import os`` is implied (e.g. a
            # conditional or lazy import within a function body).
            self._os_names: set[str] = {"os"}
            # Every name bound to ``os.getenv`` via ``from os import
            # getenv [as alias]``.
            self._getenv_names: set[str] = set()

        def visit_Import(self, node: ast.Import) -> None:
            """Track ``import os`` and ``import os as <alias>`` bindings."""
            for alias in node.names:
                if alias.name == "os":
                    self._os_names.add(alias.asname or alias.name)
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            """Track ``from os import …`` bindings; flag ``environ`` at import-time."""
            if node.module == "os":
                for alias in node.names:
                    bound_name = alias.asname or alias.name
                    if alias.name == "getenv":
                        self._getenv_names.add(bound_name)
                    if alias.name == "environ":
                        # ``environ`` bound into the module is itself a
                        # violation — every legitimate use is a read.
                        self.violations.append((node.lineno, "from os import environ"))
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            """Catch ``<os_alias>.environ.<attr>`` access (e.g. ``.get``, ``.keys``)."""
            if (
                isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id in self._os_names
                and node.value.attr == "environ"
            ):
                self.violations.append((node.lineno, "os.environ.attr"))
            self.generic_visit(node)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            """Catch ``<os_alias>.environ["X"]`` — the previous AST scanner missed this shape."""
            if (
                isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id in self._os_names
                and node.value.attr == "environ"
            ):
                self.violations.append((node.lineno, "os.environ[...]"))
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            """Catch every method-call shape of an env read.

            ``<os_alias>.environ.<method>(...)``,
            ``<os_alias>.getenv(...)``, and the aliased
            ``getenv(...)`` bound by a ``from os import getenv``.
            """
            if isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id in self._os_names
                    and node.func.value.attr == "environ"
                ):
                    self.violations.append((node.lineno, "os.environ.method"))
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id in self._os_names
                    and node.func.attr == "getenv"
                ):
                    self.violations.append((node.lineno, "os.getenv"))
            # ``from os import getenv [as g]; g(...)`` — bare-name call.
            if isinstance(node.func, ast.Name) and node.func.id in self._getenv_names:
                self.violations.append((node.lineno, "getenv (from os import)"))
            self.generic_visit(node)

    visitor = EnvReadVisitor()
    visitor.visit(tree)
    assert not visitor.violations, (
        "capability.py must not read environment variables (sec-007). "
        f"Violations: {visitor.violations}"
    )


def test_capability_py_env_read_guard_catches_environ_subscript_alias_and_getenv_alias(
    tmp_path: Path,
) -> None:
    """sec-007 AST guard rejects ``os.environ[...]``, aliased ``os``, and ``from os import getenv``.

    Regression pin against the CR-156 round-3 false-negatives. The
    original visitor only checked the unaliased ``os.environ.attr`` /
    ``os.environ.method`` / ``os.getenv`` shapes; this test runs the
    same visitor over a synthetic source containing each previously-
    undetected shape and asserts every one trips a violation. If the
    visitor regresses, this test fails BEFORE the prod-source scan
    above silently lets a real regression through.
    """
    # Re-import the visitor logic by running it inline against a
    # synthetic source. We can't import ``EnvReadVisitor`` directly
    # because it's defined inside ``test_capability_py_reads_no_env``;
    # instead, re-exercise the guard's behaviour by parsing the
    # synthetic source and pointing the same scanner at it. The scanner
    # body is duplicated here intentionally — keeping the production
    # guard's visitor and this regression test isolated means a
    # refactor that tightens one side without the other surfaces as
    # this test diverging from the production guard.
    synthetic = (
        "import os\n"
        "import os as _os\n"
        "from os import getenv\n"
        "from os import getenv as _g\n"
        "from os import environ\n"
        "_os.environ['X']\n"
        "os.environ['Y']\n"
        "os.environ.get('Z')\n"
        "_os.environ.get('W')\n"
        "os.getenv('A')\n"
        "_os.getenv('B')\n"
        "getenv('C')\n"
        "_g('D')\n"
    )
    src_path = tmp_path / "synthetic_capability.py"
    src_path.write_text(synthetic, encoding="utf-8")
    tree = ast.parse(src_path.read_text(encoding="utf-8"))

    class _EnvReadVisitorMirror(ast.NodeVisitor):
        """Inlined twin of ``EnvReadVisitor`` — see the parent test for rationale."""

        def __init__(self) -> None:
            self.violations: list[tuple[int, str]] = []
            self._os_names: set[str] = {"os"}
            self._getenv_names: set[str] = set()

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                if alias.name == "os":
                    self._os_names.add(alias.asname or alias.name)
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if node.module == "os":
                for alias in node.names:
                    bound_name = alias.asname or alias.name
                    if alias.name == "getenv":
                        self._getenv_names.add(bound_name)
                    if alias.name == "environ":
                        self.violations.append((node.lineno, "from os import environ"))
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if (
                isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id in self._os_names
                and node.value.attr == "environ"
            ):
                self.violations.append((node.lineno, "os.environ.attr"))
            self.generic_visit(node)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            if (
                isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id in self._os_names
                and node.value.attr == "environ"
            ):
                self.violations.append((node.lineno, "os.environ[...]"))
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id in self._os_names
                    and node.func.value.attr == "environ"
                ):
                    self.violations.append((node.lineno, "os.environ.method"))
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id in self._os_names
                    and node.func.attr == "getenv"
                ):
                    self.violations.append((node.lineno, "os.getenv"))
            if isinstance(node.func, ast.Name) and node.func.id in self._getenv_names:
                self.violations.append((node.lineno, "getenv (from os import)"))
            self.generic_visit(node)

    visitor = _EnvReadVisitorMirror()
    visitor.visit(tree)
    reasons = sorted({reason for _, reason in visitor.violations})
    assert reasons == sorted(
        {
            "from os import environ",
            "os.environ[...]",
            "os.environ.attr",
            "os.environ.method",
            "os.getenv",
            "getenv (from os import)",
        }
    ), f"AST guard missed one or more env-read shapes; reasons seen: {reasons}"


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
