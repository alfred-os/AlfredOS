#!/usr/bin/env python3
"""CI grep gate: reject unauthorised ``tag(T3`` and ``cast(TaggedContent[`` uses.

Invoked by ``make check`` and CI. Exits 0 if clean; exits 1 with violation
messages if any non-approved file contains:

- ``tag(T3``                 — direct calls to the capability-gated factory
                               from outside the two approved homes
                               (``security/tiers.py`` and
                               ``security/quarantine.py``).
- ``cast(TaggedContent[``    — type-erasure bypasses that discard provenance.
- ``# type: ignore`` on a line containing ``TaggedContent`` — suppressing the
                               type error that prevents cast-bypass detection.

Spec §3.2, §3.3, §3.7-3.8.

Authorised callers (the EXACT list — keep in sync with the briefing):

- ``src/alfred/security/tiers.py``      — the ``tag`` overload bodies
                                          (the home of the factory itself).
- ``src/alfred/security/quarantine.py`` — the ``downgrade_to_orchestrator``
                                          boundary that bridges T3 ➜ T3DerivedData.
- ``tests/unit/security/**``            — tests assert the gate's behaviour
                                          using the same patterns.

Usage:

    python scripts/check_tag_t3.py [file_or_dir ...]

If no arguments are given, scans ``src/alfred/`` recursively.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Patterns that are disallowed in non-approved src/ files.
_VIOLATIONS: list[tuple[str, re.Pattern[str]]] = [
    (
        "tag(T3, ...) direct call — use tag_t3_with_nonce() with injected nonce",
        re.compile(r"tag\(\s*T3\s*,"),
    ),
    (
        "cast(TaggedContent[...]) — use AnyTaggedContent for observers (spec §3.3)",
        re.compile(r"cast\(\s*TaggedContent\["),
    ),
    (
        "# type: ignore on TaggedContent line — fix the type, don't suppress",
        re.compile(r"TaggedContent.*#\s*type:\s*ignore"),
    ),
]

# Authorised non-test homes (matched against any path containing this suffix).
# Keep this list short and explicit: every additional entry widens the gate.
_APPROVED_SUFFIXES: tuple[str, ...] = (
    "src/alfred/security/tiers.py",
    "src/alfred/security/quarantine.py",
)

# Test paths are always exempt. Tests assert the patterns the gate forbids.
_TEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(^|/)tests/"),
    re.compile(r"(^|/)test_[^/]+\.py$"),
)


def _is_exempt(path: Path) -> bool:
    """Return True if ``path`` is allowed to contain the disallowed patterns.

    Exempt set:
      * any path under a ``tests/`` directory,
      * any ``test_*.py`` filename (catches tmp-path test fixtures),
      * the explicit authorised homes in ``_APPROVED_SUFFIXES``.
    """
    # Normalise to forward slashes so the suffix and regex checks work the
    # same on POSIX and (theoretically) Windows checkouts.
    path_str = str(path).replace("\\", "/")
    for pat in _TEST_PATTERNS:
        if pat.search(path_str):
            return True
    return any(path_str.endswith(suffix) for suffix in _APPROVED_SUFFIXES)


def _scan_file(path: Path) -> list[str]:
    """Return a list of violation messages for ``path``. Empty list = clean."""
    violations: list[str] = []
    if _is_exempt(path):
        return violations
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # Unreadable files are not violations — the type-checker / linter
        # will catch them elsewhere. This script is for grep-level patterns
        # only.
        return violations
    for lineno, line in enumerate(text.splitlines(), 1):
        for description, pattern in _VIOLATIONS:
            if pattern.search(line):
                violations.append(f"{path}:{lineno}: {description}")
                violations.append(f"  {line.rstrip()}")
    return violations


def _collect_paths(argv: list[str]) -> list[Path]:
    """Expand the CLI arg list into a flat list of ``.py`` paths to scan."""
    if not argv:
        return list(Path("src/alfred").rglob("*.py"))
    paths: list[Path] = []
    for arg in argv:
        candidate = Path(arg)
        if candidate.is_dir():
            paths.extend(candidate.rglob("*.py"))
        else:
            paths.append(candidate)
    return paths


def main(argv: list[str]) -> int:
    all_violations: list[str] = []
    for path in sorted(_collect_paths(argv)):
        all_violations.extend(_scan_file(path))

    if all_violations:
        print("check_tag_t3: violations found:", file=sys.stderr)
        for line in all_violations:
            print(line, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
