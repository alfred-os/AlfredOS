"""Tally guard for the e2e boot lane — the load-bearing non-vacuity gate.

Reads a JSON tally written from pytest's OWN ``terminalreporter.stats`` (Task 7 conftest
hook), which already separates ``xfailed``/``skipped``/``xpassed`` — so there is no XML to
parse (no XXE surface, no new ``defusedxml`` dep) and no re-derivation of pytest's own
classification. A collapsed run reds via the independent floor.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from tests.e2e._services import MIN_SERVICE_FLOOR

# 6 compose services + the setup.sh-completes check.
_MIN_COLLECTED = MIN_SERVICE_FLOOR + 1
_KEYS = ("collected", "passed", "failed", "error", "skipped", "xfailed", "xpassed")


def write_tally(counts: Mapping[str, int], dest: Path) -> None:
    """Serialize the outcome counts as JSON (stdlib only)."""
    dest.write_text(json.dumps({k: int(counts.get(k, 0)) for k in _KEYS}))


def assert_boot_lane_tally(tally_path: Path) -> None:
    """Raise ``AssertionError`` unless the tally is the expected non-vacuous shape."""
    raw = json.loads(tally_path.read_text())
    t = {k: int(raw.get(k, 0)) for k in _KEYS}

    assert t["collected"] >= _MIN_COLLECTED, (
        f"collected {t['collected']} — below the independent floor {_MIN_COLLECTED} "
        f"(6 services + setup.sh); a collapsed run or collection error is masked otherwise."
    )
    assert t["failed"] == 0, (
        f"{t['failed']} failure(s) — a baseline regression OR a strict XPASS "
        f"(a known blocker was fixed: drop its xfail and assert healthy)."
    )
    assert t["error"] == 0, f"{t['error']} test error(s) — the stack likely never came up."
    assert t["skipped"] == 0, (
        f"{t['skipped']} plain skip(s) — the lane must never skip-green; every non-pass "
        f"must be a strict xfail on a known blocker, not a skip."
    )
    assert t["xpassed"] == 0, f"{t['xpassed']} xpass(es) — a non-strict xfail leaked; use strict."
    assert t["passed"] >= 1, "no genuine passes — the green baseline did not run."
    assert t["xfailed"] >= 1, "no xfails — the known-blocker assertions did not run."


def main(argv: Sequence[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m tests.e2e._assert_ran <tally.json>", file=sys.stderr)
        return 2
    tally = Path(argv[0])
    if not tally.is_file():
        msg = f"tally file {tally} missing — pytest never wrote it (session errored?)"
        print(msg, file=sys.stderr)
        return 1
    try:
        assert_boot_lane_tally(tally)
    except AssertionError as exc:
        print(f"e2e boot-lane tally FAILED: {exc}", file=sys.stderr)
        return 1
    print("e2e boot-lane tally OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
