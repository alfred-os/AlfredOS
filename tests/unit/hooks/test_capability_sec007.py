"""sec-007 AST-scan regression guard for ``alfred.hooks.capability``.

Task-4 of Slice-2.5 PR-A. The behavioural pin
(``test_capability.py::test_devgate_does_not_read_environment``) proves that
*today's* :class:`DevGate` ignores a monkeypatched env var. This module is
the *structural* pin: it parses ``src/alfred/hooks/capability.py`` on every
CI run and fails loudly if a future commit reintroduces an
``os.environ`` / ``os.getenv`` access — the ambient-escalation hazard
catalogued as sec-007 in the Slice-2.5 spec.

Why a separate file: ``test_capability.py`` covers behavioural invariants
(grant table, fail-closed, Protocol structural subtyping, keyword-only
contract). The AST scanner is a different shape of test — it inspects
source bytes, not runtime behaviour — and lives next door so the two pins
stay legible side-by-side without cross-pollination.

Why a bespoke scanner rather than reusing
``tests/unit/security/test_no_direct_env_reads.py``: the PR-C scan checks a
*subset* of env keys (``ALFRED_<SUPPORTED_SECRET>``) with a
broker-pointing remediation (ADR-0012). The sec-007 contract on
``capability.py`` is stricter — **no** env read for **any** key, with a
spec-pointing remediation (Slice-2.5 spec §6.3 / sec-007). The two scans
share the same AST shape (``ast.NodeVisitor`` + alias tracking + literal
line-numbered failures) so a reader who has seen one recognises the other,
but the rule-set and remediation pointer are scoped to this module.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import NamedTuple

_CAPABILITY_PATH = (
    Path(__file__).resolve().parents[3] / "src" / "alfred" / "hooks" / "capability.py"
)

_REMEDIATION = (
    "src/alfred/hooks/capability.py must not read the environment. "
    "`allow_system` is constructor-only by the sec-007 contract; see the "
    "Slice-2.5 pluggable-hooks spec §6.3."
)


class _Hit(NamedTuple):
    """One offending env-read shape located by :class:`_EnvAccess`.

    Mirrors the PR-C / PR-D1 ``ImportViolation`` precedent
    (``tests/unit/_shared/import_violation.py``) so positive-test
    assertions read ``hits[0].lineno`` instead of ``hits[0][0]``.
    Local to this module because the field set (lineno, col_offset,
    fragment) is sec-007-specific.
    """

    lineno: int
    col_offset: int
    fragment: str


class _EnvAccess(ast.NodeVisitor):
    """Collect every env-read shape in a module's AST.

    Tracks four forbidden patterns:

    1. ``<os-alias>.environ[<key>]`` — ``ast.Subscript`` whose value is
       ``os.environ`` (including ``import os as <alias>`` rebindings).
    2. ``<environ-alias>[<key>]`` — bare ``environ`` after
       ``from os import environ [as <alias>]``.
    3. ``<os-alias>.environ.get(...)`` and bare-``environ``.get(...).
    4. ``<os-alias>.getenv(...)`` and ``from os import getenv [as <alias>]``;
       ``<alias>(...)``.

    Alias bookkeeping mirrors
    ``tests/unit/security/test_no_direct_env_reads.py`` so the failure
    surface is consistent across the two AST scans.

    On top of import-level aliasing, this scan ALSO tracks
    ``name = os.environ`` and ``name = os.getenv`` (and their
    bare-/already-aliased counterparts) — assign-time rebindings that
    would otherwise evade the import-only allowlist. The set is
    monotonically grown; we do NOT track reassignment-to-non-env, which
    would require flow analysis. A future adversarial rebinding shape
    (e.g. ``env = something_else; env = os.environ``) still falls into
    the alias set and is flagged on every subsequent read — false
    positives on the rebinding shape are acceptable because the scan
    is deliberately strict for ``capability.py``.

    Unlike the import-only scan that complements it, this one captures
    **every** env read in the target module — no allowlisted key set,
    no exempt callers. ``capability.py`` has zero legitimate reasons to
    touch ``os.environ``.
    """

    def __init__(self) -> None:
        # Local names bound to the ``os`` module. Seeded with the canonical
        # name; ``import os as foo`` rebindings extend it.
        self._os_aliases: set[str] = {"os"}
        # Local names bound directly to ``os.environ``.
        self._environ_aliases: set[str] = set()
        # Local names bound directly to ``os.getenv``.
        self._getenv_aliases: set[str] = set()
        # One :class:`_Hit` per offending node.
        self.hits: list[_Hit] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "os":
                self._os_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "os":
            for alias in node.names:
                if alias.name == "environ":
                    self._environ_aliases.add(alias.asname or alias.name)
                elif alias.name == "getenv":
                    self._getenv_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Track ``name = <env-source>`` rebindings so a subsequent read
        # through ``name`` is flagged. We only handle simple single-name
        # targets (``a = ...``); tuple-unpacking / starred targets are
        # not env-source shapes in practice and would only add scanner
        # complexity without a real-world plant they would catch.
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            value = node.value
            # name = os.environ  OR  name = environ (bare/aliased)
            if self._is_os_environ_attr(value) or self._is_bare_environ(value):
                self._environ_aliases.add(target_name)
            # name = os.getenv  OR  name = getenv (bare/aliased)
            elif (
                isinstance(value, ast.Attribute)
                and value.attr == "getenv"
                and isinstance(value.value, ast.Name)
                and value.value.id in self._os_aliases
            ) or (isinstance(value, ast.Name) and value.id in self._getenv_aliases):
                self._getenv_aliases.add(target_name)
        self.generic_visit(node)

    def _is_os_environ_attr(self, node: ast.expr) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and node.value.id in self._os_aliases
        )

    def _is_bare_environ(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Name) and node.id in self._environ_aliases

    def _record(self, node: ast.expr, fragment: str) -> None:
        self.hits.append(_Hit(node.lineno, node.col_offset, fragment))

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._is_os_environ_attr(node.value):
            self._record(node, "os.environ[...]")
        elif self._is_bare_environ(node.value):
            self._record(node, "environ[...]")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # os.getenv(...) OR `from os import getenv as g; g(...)`
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "getenv"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self._os_aliases
        ):
            self._record(node, "os.getenv(...)")
        elif isinstance(node.func, ast.Name) and node.func.id in self._getenv_aliases:
            self._record(node, f"{node.func.id}(...)  # aliased os.getenv")

        # os.environ.get(...) OR `from os import environ as e; e.get(...)`
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            target = node.func.value
            if self._is_os_environ_attr(target):
                self._record(node, "os.environ.get(...)")
            elif self._is_bare_environ(target):
                self._record(node, "environ.get(...)")

        self.generic_visit(node)


def _scan(source_path: Path) -> list[_Hit]:
    """Parse ``source_path`` from disk and return every env-read hit."""
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    scanner = _EnvAccess()
    scanner.visit(tree)
    return scanner.hits


def _format_hits(path: Path, hits: list[_Hit]) -> str:
    header = f"sec-007 violation in {path}:"
    body = "\n".join(f"  line {h.lineno}, col {h.col_offset}: {h.fragment}" for h in hits)
    return f"{header}\n{body}\n{_REMEDIATION}"


def test_devgate_reads_no_environment() -> None:
    """sec-007 regression guard: ``capability.py`` must not read the env.

    AST-parses ``src/alfred/hooks/capability.py`` on every CI run and
    asserts the source contains no ``os.environ`` subscript, no
    ``os.environ.get(...)`` / ``environ.get(...)`` call, and no
    ``os.getenv(...)`` / aliased-``getenv`` call. The behavioural pin in
    ``test_capability.py`` proves *today's* :class:`DevGate` ignores a
    monkeypatched env var; this structural pin prevents a future commit
    from reintroducing the ambient-escalation hazard at the source level.

    Failure renders the file, line number, column offset, and source
    fragment of every offending node so the breakage is debuggable from
    the assertion text alone.
    """
    hits = _scan(_CAPABILITY_PATH)
    assert hits == [], _format_hits(_CAPABILITY_PATH, hits)


def test_scanner_detects_os_environ_subscript(tmp_path: Path) -> None:
    """Positive test: ``os.environ["X"]`` is caught."""
    fixture = tmp_path / "subscript.py"
    fixture.write_text('import os\ntoken = os.environ["ALFRED_HOOKS_ALLOW_SYSTEM"]\n')
    hits = _scan(fixture)
    assert len(hits) == 1
    assert hits[0].lineno == 2
    assert "os.environ[...]" in hits[0].fragment


def test_scanner_detects_os_environ_get(tmp_path: Path) -> None:
    """Positive test: ``os.environ.get("X")`` is caught."""
    fixture = tmp_path / "envget.py"
    fixture.write_text('import os\nv = os.environ.get("ALFRED_HOOKS_ALLOW_SYSTEM", "")\n')
    hits = _scan(fixture)
    assert len(hits) == 1
    assert "os.environ.get(...)" in hits[0].fragment


def test_scanner_detects_os_getenv(tmp_path: Path) -> None:
    """Positive test: ``os.getenv("X")`` — the canonical sec-007 plant — is caught."""
    fixture = tmp_path / "getenv.py"
    fixture.write_text('import os\nv = os.getenv("ALFRED_HOOKS_ALLOW_SYSTEM")\n')
    hits = _scan(fixture)
    assert len(hits) == 1
    assert "os.getenv(...)" in hits[0].fragment


def test_scanner_detects_aliased_os_import(tmp_path: Path) -> None:
    """``import os as <alias>`` does not bypass the scan."""
    fixture = tmp_path / "aliased.py"
    fixture.write_text('import os as _o\nv = _o.environ["ALFRED_HOOKS_ALLOW_SYSTEM"]\n')
    hits = _scan(fixture)
    assert len(hits) == 1
    assert hits[0].lineno == 2


def test_scanner_detects_from_os_import_environ(tmp_path: Path) -> None:
    """``from os import environ`` bypass is caught."""
    fixture = tmp_path / "fromimport.py"
    fixture.write_text('from os import environ\nv = environ.get("ALFRED_HOOKS_ALLOW_SYSTEM")\n')
    hits = _scan(fixture)
    assert len(hits) == 1
    assert "environ.get(...)" in hits[0].fragment


def test_scanner_detects_aliased_getenv(tmp_path: Path) -> None:
    """``from os import getenv as <alias>`` bypass is caught."""
    fixture = tmp_path / "aliased_getenv.py"
    fixture.write_text('from os import getenv as g\nv = g("ALFRED_HOOKS_ALLOW_SYSTEM")\n')
    hits = _scan(fixture)
    assert len(hits) == 1


def test_format_hits_renders_remediation_pointer(tmp_path: Path) -> None:
    """Failure message names the file, line, and remediation pointer.

    A future reader debugging a CI failure should be able to act on the
    assertion text alone — no need to grep for ``sec-007`` separately.
    """
    fixture = tmp_path / "violator.py"
    fixture.write_text('import os\nv = os.getenv("X")\n')
    hits = _scan(fixture)
    rendered = _format_hits(fixture, hits)
    assert "sec-007" in rendered
    assert str(fixture) in rendered
    assert "line 2" in rendered
    assert "constructor-only" in rendered


def test_scanner_ignores_clean_module(tmp_path: Path) -> None:
    """Negative test: a module with no env access produces no hits."""
    fixture = tmp_path / "clean.py"
    fixture.write_text(
        "from __future__ import annotations\n"
        "class Foo:\n"
        "    def __init__(self, *, flag: bool = False) -> None:\n"
        "        self._flag = flag\n"
    )
    assert _scan(fixture) == []


def test_scanner_detects_assigned_os_environ_subscript(tmp_path: Path) -> None:
    """Assign-time rebinding: ``env = os.environ; env["KEY"]`` is caught.

    The assign-tracking branch of :meth:`_EnvAccess.visit_Assign` extends
    :attr:`_environ_aliases` so the subscript at the read site is
    flagged. Without the assign tracking, the canonical sec-007 hazard
    plant (binding an alias to dodge the import-only scan) would slip
    through.
    """
    fixture = tmp_path / "assigned_subscript.py"
    fixture.write_text('import os\nenv = os.environ\ntoken = env["ALFRED_HOOKS_ALLOW_SYSTEM"]\n')
    hits = _scan(fixture)
    assert len(hits) == 1
    assert hits[0].lineno == 3
    assert "environ[...]" in hits[0].fragment


def test_scanner_detects_assigned_os_environ_get(tmp_path: Path) -> None:
    """Assign-time rebinding: ``env = os.environ; env.get("KEY")`` is caught.

    Symmetric to the subscript shape — the ``.get(...)`` call on the
    rebound alias must trip the same scan as direct ``os.environ.get``.
    """
    fixture = tmp_path / "assigned_environ_get.py"
    fixture.write_text('import os\nenv = os.environ\nv = env.get("ALFRED_HOOKS_ALLOW_SYSTEM")\n')
    hits = _scan(fixture)
    assert len(hits) == 1
    assert hits[0].lineno == 3
    assert "environ.get(...)" in hits[0].fragment


def test_scanner_detects_assigned_os_getenv(tmp_path: Path) -> None:
    """Assign-time rebinding: ``g = os.getenv; g("KEY")`` is caught.

    The third shape of the canonical alias-rebinding bypass. Combined
    with the two ``environ`` rebinding tests above, the assign-tracking
    branch of :meth:`_EnvAccess.visit_Assign` covers every realistic
    plant of the form "stash the env source under a local name, read
    through the local name".
    """
    fixture = tmp_path / "assigned_getenv.py"
    fixture.write_text('import os\ng = os.getenv\nv = g("ALFRED_HOOKS_ALLOW_SYSTEM")\n')
    hits = _scan(fixture)
    assert len(hits) == 1
    assert hits[0].lineno == 3
    assert "aliased os.getenv" in hits[0].fragment
