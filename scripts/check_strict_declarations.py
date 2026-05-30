#!/usr/bin/env python3
"""CI lint guard — the assignment ``strict_declarations=False`` MUST NOT
appear anywhere in ``src/``.

#119 SEC-Med-1 + ARCH-002 rationale:

* ``HookRegistry(strict_declarations=False)`` silently disables BOTH
  halves of the #119 register-time + dispatch-time enforcement. A
  subscriber whose tier is NOT in the publisher-declared
  ``subscribable_tiers`` registers cleanly and runs at dispatch —
  defeating the whole purpose of the security stage.
* The non-strict mode exists ONLY as a transitional opt-out for the
  pre-#119 unit-test corpus. Production code paths construct the
  singleton with the default ``True``; ``strict_declarations=False``
  appearing inside ``src/`` is a release-blocking regression.

The check is intentionally a ``grep -rnE`` of a small regex rather than
an AST walker: the assignment text is the surface a future maintainer
would type to introduce the regression, and a whitespace-tolerant
regex catches both ``strict_declarations=False`` (the keyword-arg
shape) AND ``strict_declarations = False`` (the assignment shape a
formatter could rewrite the keyword-arg into).

The CR cycle-1 review flagged the pre-fix plain ``grep`` (substring
match for ``strict_declarations=False``) as defeating itself: a
formatter writing the spaced form slipped past the gate. The regex
fix below ``strict_declarations[[:space:]]*=[[:space:]]*False`` covers
both forms with a single rule.

False positives (e.g. the literal inside a docstring example) are
surfaced as the lint failing — the correct disposition is either
deleting the example or restating the example without the literal.

Wired into ``make check`` via the ``strict-declarations-lint`` target.
CI runs ``make check``, so this guard fires on every PR without
additional workflow changes.

Exit codes:
* 0 — clean (no occurrences in ``src/``)
* 1 — at least one occurrence (with file:line:content reported), OR
  ``grep`` itself failed (rc >= 2: unreadable path, encoding issue).
  We fail closed on the error arm: a silently-skipped lint is the same
  shape as a SEC-Med-1 regression slipping past CI.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_PATTERN: str = r"strict_declarations[[:space:]]*=[[:space:]]*False"
"""POSIX-ERE regex matching both forms:

* ``strict_declarations=False`` — the keyword-arg shape (pre-formatter).
* ``strict_declarations = False`` — the assignment shape any formatter
  (ruff format, black, autopep8) may rewrite the keyword arg into.

``[[:space:]]*`` covers zero-or-more whitespace characters on each
side of the ``=`` so the lint is robust against future formatter
spacing changes.
"""


def main() -> int:
    """Return 0 if the assignment is absent from ``src/``, 1 otherwise.

    The three exit arms (CR-TR-2 hardening):

    * ``rc == 0`` — ``grep`` matched at least one line; a SEC-Med-1
      regression. Print the matches and fail.
    * ``rc == 1`` — ``grep`` matched nothing; the clean path.
    * ``rc >= 2`` — ``grep`` errored (unreadable path, encoding issue,
      etc.). Fail closed so a silently-skipped lint never ships green.
    """
    # Anchored to the repository root so the check runs the same way
    # from CI (cwd = repo root) and from a dev shell (cwd = anywhere).
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src"
    if not src_dir.is_dir():
        print(f"FAIL: {src_dir} does not exist", file=sys.stderr)
        return 1

    res = subprocess.run(
        ["grep", "-rnE", _PATTERN, str(src_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode == 0:
        # Matches found — a SEC-Med-1 regression.
        print(
            "FAIL: strict_declarations=False (or = False) found in src/ — "
            "see SEC-Med-1 / #119. The non-strict mode is a test-only "
            "opt-out; production code paths MUST use the default (True).",
            file=sys.stderr,
        )
        print(res.stdout, file=sys.stderr)
        return 1
    if res.returncode == 1:
        # No matches — clean.
        print("OK: no strict_declarations=False (or = False) in src/")
        return 0
    # rc >= 2: grep itself errored. Fail closed — a silently-skipped
    # lint is the same shape as the regression we are guarding against.
    print(
        f"FAIL: grep returned rc={res.returncode}: {res.stderr.strip()}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
