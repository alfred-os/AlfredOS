"""Boundary-enforcement: only ``alfred.comms`` modules import concrete adapters.

CLAUDE.md PRD §5 says plugins are MCP processes, not in-process objects;
PR D1's CommsAdapter Protocol bounds that invariant for Slice-2 only,
and ADR-0009 documents the bound. The bound is enforced statically by
this AST-scan: any module under ``src/alfred/`` (except for the
``alfred.comms`` package itself) that imports a concrete-adapter module
or symbol — ``alfred.comms.tui_adapter``, ``alfred.comms.discord`` (PR
D2), or any future ``alfred.comms.*Adapter`` class — fails the build.

The allowlist below is the SHORT, EXPLICIT set of ``alfred.comms.*``
modules safe to import from outside the package:

* ``alfred.comms.adapter`` — the Protocol surface.
* ``alfred.comms.discord_types`` — the structural shim PR D2 publishes
  for its test-stub client.
* ``alfred.comms.markdown_split`` — pure utility.

Anything else under ``alfred.comms`` imported from outside the package
fails. The failure message names the offending file:line and points the
contributor at ``src/alfred/comms/adapter.py`` + ADR-0009.
"""

from __future__ import annotations

import ast
import pathlib
from collections.abc import Iterator

import pytest

from tests.unit._shared.import_violation import ImportViolation, _remediation_message

_ALLOWED_COMMS_IMPORTS: frozenset[str] = frozenset(
    {
        "alfred.comms.adapter",
        "alfred.comms.discord_types",
        "alfred.comms.markdown_split",
    }
)

_SRC_ROOT = pathlib.Path(__file__).resolve().parents[3] / "src" / "alfred"
_COMMS_PACKAGE = _SRC_ROOT / "comms"


def _walk_scanned_files() -> Iterator[pathlib.Path]:
    """Yield every ``.py`` file under ``src/alfred/`` outside the comms package."""
    for path in _SRC_ROOT.rglob("*.py"):
        # Skip files inside the comms package itself — they're allowed
        # to import each other freely.
        try:
            path.relative_to(_COMMS_PACKAGE)
        except ValueError:
            yield path


def _is_comms_module(module: str | None) -> bool:
    if not module:
        return False
    return module == "alfred.comms" or module.startswith("alfred.comms.")


def _resolve_relative_import(
    *,
    file_path: pathlib.Path,
    level: int,
    module: str | None,
    package_root: pathlib.Path = _SRC_ROOT,
) -> str | None:
    """Translate a relative ``from .x import Y`` into its absolute module name.

    Returns ``None`` if the source file is outside the package tree
    rooted at ``package_root`` (no relative resolution is meaningful) or
    if ``level`` would overshoot the package root. Otherwise returns
    the resolved dotted module path (e.g. ``alfred.comms.tui_adapter``).

    ``package_root`` defaults to the real ``src/alfred`` tree; the
    parameter exists so the scanner's own unit tests can synthesize a
    fake package layout under ``tmp_path``.
    """
    try:
        rel = file_path.resolve().relative_to(package_root)
    except ValueError:
        return None
    # The importing package equals the file's parent relative to alfred.
    # E.g. ``src/alfred/cli/main.py`` -> parent parts ``("cli",)``,
    # ``src/alfred/comms/tui_adapter.py`` -> ``("comms",)``.
    parent_parts: tuple[str, ...] = (package_root.name,) + tuple(rel.parts[:-1])
    if level > len(parent_parts):
        return None
    base_parts = parent_parts[: len(parent_parts) - level + 1]
    if module:
        return ".".join((*base_parts, module))
    return ".".join(base_parts)


def _scan_file(
    path: pathlib.Path,
    *,
    package_root: pathlib.Path = _SRC_ROOT,
) -> list[ImportViolation]:
    """Return any ImportViolation entries for ``path``.

    Relative imports (``from .comms.x import Y``) are normalized to
    their absolute dotted form before the comms-boundary check runs so
    a contributor cannot bypass the gate by switching to a relative
    spelling. ``package_root`` is the package-tree root used for the
    relative-import resolver — production scans use the real
    ``src/alfred`` tree; the scanner's own unit tests pass a fake root.
    """
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:  # pragma: no cover - linter catches syntax errors first
        return []
    violations: list[ImportViolation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_comms_module(alias.name) and alias.name not in _ALLOWED_COMMS_IMPORTS:
                    violations.append(
                        ImportViolation(
                            file=path,
                            lineno=node.lineno,
                            symbol=alias.name,
                            category="adapter_import",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            level = node.level or 0
            if level > 0:
                # ``from . import x`` or ``from .x import Y`` — resolve.
                module = _resolve_relative_import(
                    file_path=path,
                    level=level,
                    module=module,
                    package_root=package_root,
                )
            if not _is_comms_module(module):
                continue
            # ``from alfred.comms import X`` — every X is suspect unless
            # it resolves to an allowed sub-module name.
            if module == "alfred.comms":
                for alias in node.names:
                    full = f"alfred.comms.{alias.name}"
                    if full not in _ALLOWED_COMMS_IMPORTS:
                        violations.append(
                            ImportViolation(
                                file=path,
                                lineno=node.lineno,
                                symbol=full,
                                category="adapter_import",
                            )
                        )
            # ``from alfred.comms.X import Y`` — module name itself must
            # be in the allowlist regardless of Y.
            elif module not in _ALLOWED_COMMS_IMPORTS:
                violations.append(
                    ImportViolation(
                        file=path,
                        lineno=node.lineno,
                        symbol=module or "<unknown>",
                        category="adapter_import",
                    )
                )
    return violations


def test_no_direct_adapter_imports_outside_comms_package() -> None:
    """Every src module outside ``alfred.comms`` imports only the allowlist.

    Failure renders the ``ImportViolation`` set via the shared
    remediation helper so the message shape matches PR C's env-read
    scan.
    """
    violations: list[ImportViolation] = []
    for path in _walk_scanned_files():
        violations.extend(_scan_file(path))
    if violations:
        pytest.fail(_remediation_message(violations))


def test_scanner_detects_concrete_adapter_import(tmp_path: pathlib.Path) -> None:
    fixture = tmp_path / "violator.py"
    fixture.write_text(
        "from alfred.comms.tui_adapter import TuiAdapter\n",
        encoding="utf-8",
    )
    violations = _scan_file(fixture)
    assert len(violations) == 1
    assert "alfred.comms.tui_adapter" in violations[0].symbol


def test_scanner_detects_module_level_import(tmp_path: pathlib.Path) -> None:
    fixture = tmp_path / "violator2.py"
    fixture.write_text(
        "import alfred.comms.discord\n",
        encoding="utf-8",
    )
    violations = _scan_file(fixture)
    assert len(violations) == 1
    assert "alfred.comms.discord" in violations[0].symbol


def test_scanner_detects_from_alfred_comms_import_name(tmp_path: pathlib.Path) -> None:
    fixture = tmp_path / "violator3.py"
    fixture.write_text(
        "from alfred.comms import tui_adapter\n",
        encoding="utf-8",
    )
    violations = _scan_file(fixture)
    assert len(violations) == 1
    assert violations[0].symbol == "alfred.comms.tui_adapter"


def test_scanner_allows_protocol_import(tmp_path: pathlib.Path) -> None:
    """The Protocol surface IS allowed."""
    fixture = tmp_path / "legit.py"
    fixture.write_text(
        "from alfred.comms.adapter import CommsAdapter\n",
        encoding="utf-8",
    )
    assert _scan_file(fixture) == []


def test_scanner_allows_markdown_split(tmp_path: pathlib.Path) -> None:
    fixture = tmp_path / "legit2.py"
    fixture.write_text(
        "from alfred.comms.markdown_split import _split_for_discord\n",
        encoding="utf-8",
    )
    assert _scan_file(fixture) == []


def test_scanner_ignores_unrelated_imports(tmp_path: pathlib.Path) -> None:
    fixture = tmp_path / "innocent.py"
    fixture.write_text(
        "from typing import Protocol\nimport asyncio\n",
        encoding="utf-8",
    )
    assert _scan_file(fixture) == []


def test_scanner_detects_relative_import_of_concrete_adapter(tmp_path: pathlib.Path) -> None:
    """A consumer cannot bypass the gate via relative spelling.

    Simulates a file at ``alfred/cli/foo.py`` doing
    ``from ..comms.tui_adapter import TuiAdapter``. The scanner must
    resolve the relative path to ``alfred.comms.tui_adapter`` and flag
    it — otherwise the AST gate has a one-character bypass.
    """
    pkg_root = tmp_path / "alfred"
    (pkg_root / "cli").mkdir(parents=True)
    (pkg_root / "__init__.py").write_text("", encoding="utf-8")
    (pkg_root / "cli" / "__init__.py").write_text("", encoding="utf-8")
    fixture = pkg_root / "cli" / "violator.py"
    fixture.write_text(
        "from ..comms.tui_adapter import TuiAdapter\n",
        encoding="utf-8",
    )
    violations = _scan_file(fixture, package_root=pkg_root)
    assert len(violations) == 1
    assert "alfred.comms.tui_adapter" in violations[0].symbol


def test_scanner_detects_single_dot_relative_import(tmp_path: pathlib.Path) -> None:
    """``from .comms.tui_adapter import X`` from inside the alfred package."""
    pkg_root = tmp_path / "alfred"
    pkg_root.mkdir()
    (pkg_root / "__init__.py").write_text("", encoding="utf-8")
    fixture = pkg_root / "violator.py"
    fixture.write_text(
        "from .comms.tui_adapter import TuiAdapter\n",
        encoding="utf-8",
    )
    violations = _scan_file(fixture, package_root=pkg_root)
    assert len(violations) == 1
    assert "alfred.comms.tui_adapter" in violations[0].symbol


def test_scanner_allows_relative_import_to_allowlisted_module(tmp_path: pathlib.Path) -> None:
    """The relative-import path resolves to the same allowlist."""
    pkg_root = tmp_path / "alfred"
    (pkg_root / "cli").mkdir(parents=True)
    (pkg_root / "__init__.py").write_text("", encoding="utf-8")
    (pkg_root / "cli" / "__init__.py").write_text("", encoding="utf-8")
    fixture = pkg_root / "cli" / "legit.py"
    fixture.write_text(
        "from ..comms.adapter import CommsAdapter\n",
        encoding="utf-8",
    )
    assert _scan_file(fixture, package_root=pkg_root) == []


def test_allowlist_is_locked_to_three_entries() -> None:
    """The allowlist size is part of the contract.

    Adding a fourth entry without a coordinated cross-PR review widens
    the Slice-3 swap surface silently. Bumping this test's count is the
    intentional gate — it forces the contributor to look at the
    allowlist and read ADR-0009 first.
    """
    assert len(_ALLOWED_COMMS_IMPORTS) == 3
