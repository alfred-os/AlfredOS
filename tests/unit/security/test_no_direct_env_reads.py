"""Boundary-enforcement: only :mod:`alfred.security.secrets` reads ALFRED_* env.

CLAUDE.md security hard rule #6: secrets live in the broker, not in env vars
accessible to plugins. This AST-scan enforces the rule statically: any module
under ``src/alfred/`` (except the broker itself) that reads
``os.environ["ALFRED_<SUPPORTED_SECRET>"]`` — directly or via
``os.environ.get(...)`` — fails the build.

The matcher imports :data:`alfred.security.secrets.SUPPORTED_SECRETS` live so
adding a new secret to the broker automatically expands this guard.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from alfred.security.secrets import SUPPORTED_SECRETS
from tests.unit._shared.import_violation import (
    ImportViolation,
    _remediation_message,
)

_SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "alfred"
_BROKER_PATH = _SRC_ROOT / "security" / "secrets.py"


def _env_keys_for_supported_secrets() -> frozenset[str]:
    """Return ``{ "ALFRED_<UPPER>" }`` for every name in SUPPORTED_SECRETS."""
    return frozenset(f"ALFRED_{name.upper()}" for name in SUPPORTED_SECRETS)


def _is_os_environ_attr(node: ast.expr, os_aliases: set[str]) -> bool:
    """True iff ``node`` is the AST shape for ``<os-alias>.environ``.

    ``os_aliases`` carries every local name bound to the ``os`` module — the
    default ``"os"`` plus anything from ``import os as foo`` rebindings. This
    closes the bypass where a contributor could rename ``os`` on import and
    sidestep a naive ``node.value.id == "os"`` check.
    """
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and isinstance(node.value, ast.Name)
        and node.value.id in os_aliases
    )


def _is_bare_environ_name(node: ast.expr, env_aliases: set[str]) -> bool:
    """True iff ``node`` is a bare ``environ`` (after ``from os import environ``)."""
    return isinstance(node, ast.Name) and node.id in env_aliases


def _literal_str(node: ast.expr | None) -> str | None:
    """Return the literal string if ``node`` is a string constant, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _EnvScanner(ast.NodeVisitor):
    """Collects ``os.environ[...]`` and ``os.environ.get(...)`` accesses."""

    def __init__(self, file: Path, banned_keys: frozenset[str]) -> None:
        self.file = file
        self.banned_keys = banned_keys
        self.violations: list[ImportViolation] = []
        # Local names bound to the ``os`` module. Seeded with the canonical
        # name; ``import os as foo`` rebindings extend it.
        self.os_aliases: set[str] = {"os"}
        # Local names bound to ``os.environ`` directly via
        # ``from os import environ [as <alias>]``.
        self.env_aliases: set[str] = set()
        # Local names bound to ``os.getenv`` via
        # ``from os import getenv [as <alias>]``.
        self.getenv_aliases: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "os":
                self.os_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "os":
            for alias in node.names:
                if alias.name == "environ":
                    self.env_aliases.add(alias.asname or alias.name)
                elif alias.name == "getenv":
                    self.getenv_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _record_if_banned(self, key: str | None, lineno: int) -> None:
        if key is None:
            return
        if key in self.banned_keys:
            self.violations.append(
                ImportViolation(
                    file=self.file,
                    lineno=lineno,
                    symbol=f'os.environ["{key}"]',
                    category="env_read",
                )
            )

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _is_os_environ_attr(node.value, self.os_aliases) or _is_bare_environ_name(
            node.value, self.env_aliases
        ):
            key = _literal_str(node.slice)
            self._record_if_banned(key, node.lineno)
        self.generic_visit(node)

    def _first_key_arg(self, node: ast.Call) -> str | None:
        """Extract the literal key from ``node.args[0]`` or ``key=`` kwarg.

        Closes the keyword-arg bypass where a contributor writes
        ``os.environ.get(key="ALFRED_X")`` instead of the positional form.
        """
        if node.args:
            return _literal_str(node.args[0])
        for kw in node.keywords:
            if kw.arg == "key":
                return _literal_str(kw.value)
        return None

    def visit_Call(self, node: ast.Call) -> None:
        # os.getenv("ALFRED_X") OR
        # from os import getenv as g; g("ALFRED_X")
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "getenv"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.os_aliases
        ) or (isinstance(node.func, ast.Name) and node.func.id in self.getenv_aliases):
            self._record_if_banned(self._first_key_arg(node), node.lineno)

        # os.environ.get("ALFRED_X") OR environ.get(key="ALFRED_X")
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            target = node.func.value
            if _is_os_environ_attr(target, self.os_aliases) or _is_bare_environ_name(
                target, self.env_aliases
            ):
                self._record_if_banned(self._first_key_arg(node), node.lineno)

        self.generic_visit(node)


def _scan_file(path: Path, banned: frozenset[str]) -> list[ImportViolation]:
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:  # pragma: no cover - the linter catches syntax errors
        return []
    scanner = _EnvScanner(file=path, banned_keys=banned)
    scanner.visit(tree)
    return scanner.violations


def test_no_direct_env_reads_for_supported_secrets() -> None:
    """No module other than the broker reads ALFRED_<SUPPORTED_SECRET> from env.

    The legitimate broker module is excluded from the scan. Every other
    ``src/alfred/**.py`` file is parsed and any matching subscript or
    ``.get()`` call against ``os.environ`` for a banned key produces a
    violation. Failure renders via the shared remediation helper so the
    output shape matches PR D1's adapter-import scan.
    """
    banned = _env_keys_for_supported_secrets()
    violations: list[ImportViolation] = []
    for path in _SRC_ROOT.rglob("*.py"):
        if path.resolve() == _BROKER_PATH.resolve():
            continue
        violations.extend(_scan_file(path, banned))
    if violations:
        pytest.fail(_remediation_message(violations))


def test_scanner_detects_synthetic_subscript_violation(tmp_path: Path) -> None:
    """Positive test: a synthetic file containing the forbidden pattern is caught."""
    fixture = tmp_path / "violator.py"
    fixture.write_text('import os\ntoken = os.environ["ALFRED_DEEPSEEK_API_KEY"]\n')
    banned = _env_keys_for_supported_secrets()
    violations = _scan_file(fixture, banned)
    assert len(violations) == 1
    assert violations[0].lineno == 2
    assert "DEEPSEEK" in violations[0].symbol


def test_scanner_detects_environ_get_call(tmp_path: Path) -> None:
    fixture = tmp_path / "violator2.py"
    fixture.write_text('import os\ntoken = os.environ.get("ALFRED_DISCORD_BOT_TOKEN", "")\n')
    banned = _env_keys_for_supported_secrets()
    violations = _scan_file(fixture, banned)
    assert len(violations) == 1
    assert "DISCORD" in violations[0].symbol


def test_scanner_detects_bare_environ_after_from_os_import(tmp_path: Path) -> None:
    fixture = tmp_path / "violator3.py"
    fixture.write_text('from os import environ\ntoken = environ["ALFRED_ANTHROPIC_API_KEY"]\n')
    banned = _env_keys_for_supported_secrets()
    violations = _scan_file(fixture, banned)
    assert len(violations) == 1


def test_scanner_detects_aliased_os_import(tmp_path: Path) -> None:
    """``import os as <alias>`` must not bypass the env-read scan.

    Without alias tracking the matcher only catches ``os.environ`` literally;
    a contributor could rename the import and slip past it. The scanner walks
    ``Import`` nodes and binds every alias back to the ``os`` module.
    """
    fixture = tmp_path / "violator4.py"
    fixture.write_text('import os as _os\ntoken = _os.environ["ALFRED_ANTHROPIC_API_KEY"]\n')
    banned = _env_keys_for_supported_secrets()
    violations = _scan_file(fixture, banned)
    assert len(violations) == 1
    assert violations[0].lineno == 2
    assert "ANTHROPIC" in violations[0].symbol


def test_scanner_detects_aliased_environ_from_import(tmp_path: Path) -> None:
    """``from os import environ as <alias>`` is also caught."""
    fixture = tmp_path / "violator5.py"
    fixture.write_text(
        'from os import environ as _env\ntoken = _env.get("ALFRED_ANTHROPIC_API_KEY")\n'
    )
    banned = _env_keys_for_supported_secrets()
    violations = _scan_file(fixture, banned)
    assert len(violations) == 1


def test_scanner_ignores_non_alfred_env_keys(tmp_path: Path) -> None:
    fixture = tmp_path / "innocent.py"
    fixture.write_text('import os\nhome = os.environ["HOME"]\npath = os.environ.get("PATH")\n')
    banned = _env_keys_for_supported_secrets()
    assert _scan_file(fixture, banned) == []


def test_scanner_ignores_non_string_subscripts(tmp_path: Path) -> None:
    fixture = tmp_path / "varkey.py"
    fixture.write_text(
        "import os\n"
        'name = "ALFRED_DEEPSEEK_API_KEY"\n'
        "v = os.environ[name]\n"  # dynamic key — out of scope for the scan
    )
    banned = _env_keys_for_supported_secrets()
    assert _scan_file(fixture, banned) == []


def test_scanner_ignores_environ_get_with_no_args(tmp_path: Path) -> None:
    # Defensive: os.environ.get() with no args is unusual, but the scanner
    # must not crash on it.
    fixture = tmp_path / "nargs.py"
    fixture.write_text("import os\nos.environ.get()\n")
    banned = _env_keys_for_supported_secrets()
    assert _scan_file(fixture, banned) == []


def test_scanner_detects_os_getenv_call(tmp_path: Path) -> None:
    """`os.getenv("ALFRED_X")` is a direct env read and must be flagged."""
    fixture = tmp_path / "violator_getenv.py"
    fixture.write_text('import os\ntoken = os.getenv("ALFRED_DEEPSEEK_API_KEY")\n')
    banned = _env_keys_for_supported_secrets()
    violations = _scan_file(fixture, banned)
    assert len(violations) == 1


def test_scanner_detects_aliased_getenv_call(tmp_path: Path) -> None:
    """`from os import getenv as g; g("ALFRED_X")` is the alias bypass."""
    fixture = tmp_path / "violator_aliased_getenv.py"
    fixture.write_text('from os import getenv as g\ntoken = g("ALFRED_ANTHROPIC_API_KEY")\n')
    banned = _env_keys_for_supported_secrets()
    violations = _scan_file(fixture, banned)
    assert len(violations) == 1


def test_scanner_detects_environ_get_keyword_key_arg(tmp_path: Path) -> None:
    """`environ.get(key="ALFRED_X")` is the keyword-arg bypass on the get() path."""
    fixture = tmp_path / "violator_kw.py"
    fixture.write_text(
        'from os import environ\ntoken = environ.get(key="ALFRED_ANTHROPIC_API_KEY")\n'
    )
    banned = _env_keys_for_supported_secrets()
    violations = _scan_file(fixture, banned)
    assert len(violations) == 1
