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

Two callers:

* ``make check`` via the ``strict-declarations-lint`` target (local).
* the ``strict-declarations-lint`` job in
  ``.github/workflows/pr-validate-python.yml`` (CI).

The CI job was added in the #543 follow-up. Until then this docstring
claimed "CI runs ``make check``, so this guard fires on every PR" — which
was false: no workflow runs ``make check`` and none referenced this script,
so a SEC-Med-1 regression could land with every check green. Do not remove
the workflow job on the strength of the ``make check`` wiring; the local
target is not a gate.

Exit codes:
* 0 — clean (no occurrences in ``src/``)
* 1 — at least one occurrence (with file:line:content reported), OR
  ``grep`` itself failed (rc >= 2: unreadable path, encoding issue), OR
  ``grep`` could not be EXECUTED at all (absent from ``PATH``, not
  executable). We fail closed on both error arms: a silently-skipped lint
  is the same shape as a SEC-Med-1 regression slipping past CI.
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

    The FOUR exit arms (CR-TR-2 hardening; the fourth from #543 review,
    err-003):

    * ``rc == 0`` — ``grep`` matched at least one line; a SEC-Med-1
      regression. Print the matches and fail.
    * ``rc == 1`` — ``grep`` matched nothing; the clean path.
    * ``rc >= 2`` — ``grep`` errored (unreadable path, encoding issue,
      etc.). Fail closed so a silently-skipped lint never ships green.
    * the process never STARTED — ``grep`` absent from ``PATH`` or not
      executable. ``check=False`` suppresses ``CalledProcessError`` for a
      non-zero exit; it does nothing about the OS refusing to launch the
      child, which raises ``OSError`` before any ``returncode`` exists.
      The docstring used to call the first three exhaustive and reproduction
      showed a raw ``FileNotFoundError`` traceback escaping instead — the CI
      job pins ``ubuntu-latest`` where ``grep`` is always present, so the
      exposure was the local ``make check`` path getting a crash rather than
      the documented diagnostic.
    """
    # Anchored to the repository root so the check runs the same way
    # from CI (cwd = repo root) and from a dev shell (cwd = anywhere).
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src"
    if not src_dir.is_dir():
        print(f"FAIL: {src_dir} does not exist", file=sys.stderr)
        return 1

    # #546, and the PR-#549 review that corrected it. A non-regular file under
    # `src/` is refused HERE, in Python, before grep is invoked at all.
    #
    # The first attempt was `grep --devices=skip`, and it was wrong twice over.
    #
    # It made the gate SILENT. `--devices=skip` does not report the file it
    # declines to read: rc=1, empty output, and `main` prints "OK: no
    # strict_declarations=False in src/" for a tree it did not fully scan.
    # This script's own docstring calls a silently-skipped lint the same shape
    # as the regression it guards against, and the sibling gate
    # (`check_tag_t3.py`) REPORTS an unreadable path as a violation. One flag
    # would have left two sibling gates with opposite philosophies.
    #
    # And it was a PAPER GATE on the runner that matters. The claim that "both
    # greps hang without the flag" was measured on BSD grep only and asserted
    # for GNU. Re-probed on real `ubuntu:24.04`: GNU grep 3.11 returns rc=1
    # with AND without the flag — it already skips a FIFO reached by recursion.
    # So the regression test could not fail on the CI leg, and removing the
    # flag would have gone green there (#245/#514).
    #
    # A `stat`-based refusal has neither problem: it is loud, and it behaves
    # identically on every platform, so the test that pins it can fail
    # anywhere. `rglob` only stats — it cannot block on the FIFO it is finding.
    #
    # WHAT THIS PRE-SCAN CANNOT DO (#549 review). It is a whole-tree walk that
    # finishes before `grep` starts, so the window between them is far wider
    # than the `stat`/`open` gap `check_tag_t3.py` documents on a single path.
    # A file swapped from regular to a FIFO inside that window reaches `grep`
    # unclassified — and on BSD grep that is the original hang, restored.
    #
    # So `--devices=skip` goes BACK ON, as a second layer rather than the only
    # one. Everything above still holds against it as a PRIMARY guard: silent,
    # and untestable on the GNU runner. Behind a loud pre-scan neither applies
    # — the pre-scan supplies the diagnosis and the portable, pinnable
    # behaviour, and the flag only ever acts on a path that appeared after the
    # walk. It downgrades that residual from "the gate hangs with no output" to
    # "one file created mid-scan went unread", which is the better failure of
    # the two and the only one that leaves the operator a working gate.
    strays = sorted(
        path
        for path in src_dir.rglob("*")
        if not path.is_dir() and not path.is_file()  # follows symlinks; S_ISREG underneath
    )
    if strays:
        print(
            f"FAIL: {len(strays)} non-regular file(s) under {src_dir} — the gate "
            f"cannot read them, and refuses to report a tree it did not fully "
            f"scan as clean: " + ", ".join(str(p) for p in strays),
            file=sys.stderr,
        )
        return 1

    # S603/S607: ``grep`` is intentionally invoked by PATH lookup with a
    # hard-coded argv (regex literal + repo-resolved src/ path). No untrusted
    # input flows through this subprocess; the security stage's CI is the
    # only caller. The findings are doc-level FPs for this guard.
    try:
        res = subprocess.run(  # noqa: S603
            # `--devices=skip` is the SECOND layer only — see the pre-scan
            # above for why it must never be the first. It bounds the
            # pre-scan-to-grep race, nothing else.
            ["grep", "--devices=skip", "-rnE", _PATTERN, str(src_dir)],  # noqa: S607
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            check=False,
        )
    except OSError as exc:
        # The launch itself failed — no `returncode` was ever produced, so
        # none of the three arms below can fire. Caught as the CLASS, not as
        # `FileNotFoundError`: `PermissionError` (a non-executable `grep` on
        # PATH) and `NotADirectoryError` reach here too, and enumerating the
        # ones we thought of is the #518 mistake.
        print(f"FAIL: grep could not be executed: {exc}", file=sys.stderr)
        return 1
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
