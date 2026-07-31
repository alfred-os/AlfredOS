"""``make help`` must list every documented target (#543 review, dx-002).

The help target's awk pattern was ``^[a-zA-Z_-]+:.*?## `` — no digit class —
so any target whose name contains a digit failed to match and was dropped from
the listing **with no error**. Measured on the shipped Makefile: 22 targets
listed of 26 documented, silently omitting ``tag-t3-check`` (the gate enforcing
CLAUDE.md hard rule #3), ``i18n-check``, ``i18n-fix`` and ``test-e2e``.

CLAUDE.md's discoverability bar is that a feature has a path from the README or
the CLI help to find it. A one-character regression in a display filter took
that away for four gates, and nothing said a word — the same silent-omission
shape this branch is otherwise about, on the operator-facing surface.

**Oracle independence.** The expectation is derived in PYTHON, from the
Makefile's own ``## `` doc-comment convention; the thing under test is the
AWK program in the help target. Re-using the awk pattern to compute the
expectation would be the tautological oracle this repo has shipped twice — it
would pass on the unfixed Makefile, because both sides would drop the same
four targets.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_MAKEFILE: Path = _REPO_ROOT / "Makefile"

# The convention the Makefile documents itself with. `\S+` is deliberately
# WIDER than the help target's own class: the point is to catch a target the
# help filter cannot see, so the oracle must be able to see more than it does.
_DOCUMENTED_TARGET_RE: re.Pattern[str] = re.compile(r"^(\S+):.*?## ", re.MULTILINE)

# The help target colourises the name with SGR escapes, so the raw line starts
# `\x1b[36mtag-t3-check\x1b[0m`. Stripping them is not cosmetic: without it
# every name mismatches and the assertion reds for the wrong reason, which
# reads exactly like the bug under test.
_ANSI_RE: re.Pattern[str] = re.compile(r"\x1b\[[0-9;]*m")

_NEEDS_MAKE = pytest.mark.skipif(
    shutil.which("make") is None or sys.platform == "win32",
    reason="`make help` needs GNU make; the Windows unit leg has none",
)


def _documented_targets() -> set[str]:
    return set(_DOCUMENTED_TARGET_RE.findall(_MAKEFILE.read_text(encoding="utf-8")))


def test_the_documented_target_set_is_not_empty() -> None:
    """Anti-vacuity: an oracle that finds nothing agrees with everything.

    Names targets that MUST be documented rather than only asserting a count —
    a count would survive the convention changing under it.
    """
    documented = _documented_targets()

    assert {"help", "check", "tag-t3-check", "i18n-check"} <= documented, (
        f"the `## ` doc-comment convention no longer parses; found {sorted(documented)}"
    )


@_NEEDS_MAKE
def test_make_help_lists_every_documented_target() -> None:
    """The real invocation. Every documented target must reach the operator."""
    listed = subprocess.run(
        ["make", "help"],  # noqa: S607 — `make` resolved from PATH by design
        capture_output=True,
        text=True,
        check=True,
        cwd=_REPO_ROOT,
        # `make` inherits MAKEFLAGS from an outer `make check` and can be
        # dragged into a parallel/keep-going mode that reorders output.
        env={k: v for k, v in os.environ.items() if k != "MAKEFLAGS"},
    ).stdout

    shown = {
        stripped.split()[0]
        for line in listed.splitlines()
        if (stripped := _ANSI_RE.sub("", line).strip())
    }
    missing = sorted(_documented_targets() - shown)

    assert not missing, (
        f"`make help` documents these targets with `## ` but never lists them: "
        f"{missing}. The help target's awk character class is dropping them — a "
        f"target whose name contains a digit needs `[a-zA-Z0-9_-]+` (#543 dx-002)."
    )


def test_the_help_pattern_admits_a_digit_bearing_target_name() -> None:
    """Mutation-test the fix at the character class, not at the output.

    `make help` is skipped on the Windows unit leg, so without this the fix
    would be pinned by nothing on that runner. Asserted against the pattern
    text lifted from the Makefile, so reverting the one character reds here on
    every platform.
    """
    text = _MAKEFILE.read_text(encoding="utf-8")
    classes = re.findall(r"/\^(\[[^]]+\])\+:\.\*\?## /", text)

    assert classes, "the help target's awk pattern is no longer recognisable"
    for character_class in classes:
        assert "0-9" in character_class, (
            f"the help awk pattern uses {character_class}, which silently drops "
            f"every target whose name contains a digit — tag-t3-check, i18n-check, "
            f"i18n-fix and test-e2e (#543 dx-002)"
        )
