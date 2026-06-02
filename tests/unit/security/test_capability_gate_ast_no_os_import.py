"""AST-scan: capability-gate modules MUST NOT import :mod:`os`.

Spec §8.4 + sec-007 extension. The capability gate's hot-path modules
must be DI-driven; an :func:`os.environ` read at import time would make
the gate's behaviour depend on global state rather than the constructor
arguments tests can substitute. The canonical reader for
``ALFRED_ENV`` is :mod:`alfred.bootstrap.gate_factory`; every other
capability-gate module must route through that bootstrap seam.

This test is the source-level guard that backs the runtime invariant.
Mirrors the sec-007 guard the Slice-2.5 PR-A landing pinned on
:mod:`alfred.hooks.capability` (now Protocol-only — the Slice-2.5
:class:`DevGate` class was removed in PR-S3-7, but the no-env-read
contract still applies to the file).

What the scan rejects:

* ``import os`` — any top-level or nested ``ast.Import`` whose alias
  name is ``"os"``.
* ``from os import …`` — any ``ast.ImportFrom`` whose ``module``
  attribute is ``"os"``.

What it does NOT reject:

* References to ``"os"`` inside docstrings, comments, or string
  constants. A future refactor that DOCUMENTS the sanctioned read
  site in a comment is fine; an actual import is not.
* Other modules' ``import os`` — only the listed capability-gate
  modules are scanned. The bootstrap factory
  (:mod:`alfred.bootstrap.gate_factory`) is the explicit exception
  and is intentionally absent from the forbidden list.

Test files themselves are exempt (the file lives under ``tests/`` and
the parametrize ids only list ``src/alfred/`` paths). The scan opens
each forbidden module's source bytes through :func:`pathlib.Path.read_text`
and parses with :func:`ast.parse`; bytecode caches under ``__pycache__``
are never touched.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[3] / "src" / "alfred"

# The five capability-gate modules pinned by spec §8.4. Any future
# capability-gate module added under ``src/alfred/security/capability_gate/``
# SHOULD be appended here so the no-os-import guard extends to it; a
# new module that needs ``os`` is the signal that the responsibility
# belongs on the bootstrap seam, not inside the gate.
_FORBIDDEN_MODULES = [
    _SRC / "hooks" / "capability.py",
    _SRC / "security" / "capability_gate" / "policy.py",
    _SRC / "security" / "capability_gate" / "_gate.py",
    _SRC / "security" / "capability_gate" / "backend.py",
    _SRC / "security" / "capability_gate" / "proposals.py",
]


def _scan_os_imports(path: Path) -> list[str]:
    """Return one descriptor per ``import os`` / ``from os import …`` node.

    Uses :func:`ast.walk` rather than recursive descent: imports nested
    inside a function body (a lazy-import pattern) are still violations
    because the nested ``os`` symbol could read ``ALFRED_ENV`` at first
    call. The walk surfaces them with the same line-number attribution
    a top-level import would carry.
    """
    if not path.exists():
        return []
    tree = ast.parse(path.read_text())
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os":
                    violations.append(f"Line {node.lineno}: import os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            violations.append(f"Line {node.lineno}: from os import ...")
    return violations


@pytest.mark.parametrize(
    "module_path",
    _FORBIDDEN_MODULES,
    ids=lambda p: p.name,
)
def test_no_os_import_in_capability_gate_module(module_path: Path) -> None:
    """Each capability-gate module must not import :mod:`os` (sec-007 extension).

    Spec §8.4: ``ALFRED_ENV`` selection lives in
    :mod:`alfred.bootstrap.gate_factory`. The capability gate's hot-path
    modules — :class:`CapabilityGate` Protocol, :class:`GatePolicy`,
    :class:`RealGate`, :class:`StorageBackend`, and the proposal flow
    — must be DI-driven. A leaked ``import os`` would invite a future
    refactor that reads the env inside the gate itself, undoing the
    bootstrap-seam isolation that makes the invariant testable from
    the constructor surface. PR-S3-7 removed the Slice-2.5
    :class:`DevGate` class from ``alfred.hooks.capability``; the
    no-os-import contract still applies to the now-Protocol-only file.

    On failure the diagnostic lists every offending line so the fix
    site is unambiguous — relocate the read to
    :mod:`alfred.bootstrap.gate_factory`, or inject the value through
    the constructor.
    """
    assert module_path.exists(), (
        f"Forbidden-module list references {module_path}, which is missing. "
        "Remove the entry if the module was deleted intentionally."
    )
    violations = _scan_os_imports(module_path)
    if violations:
        pytest.fail(
            f"{module_path.name} imports os (sec-007 extension).\n"
            f"Violations:\n" + "\n".join(violations) + "\n"
            "Move any ALFRED_ENV reads to "
            "src/alfred/bootstrap/gate_factory.py."
        )
