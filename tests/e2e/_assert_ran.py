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

# The main boot lane collects the service/app health checks (>= the service floor). The
# setup.sh full run graduated to its OWN lane at #501, so it is no longer the "+1" here.
_MIN_COLLECTED = MIN_SERVICE_FLOOR
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
        f"(the service/app health checks; setup.sh runs in its own lane since #501); a "
        f"collapsed run or collection error is masked otherwise."
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
    assert t["xfailed"] == 0, (
        f"{t['xfailed']} xfail(s) — the lane graduated to fully green at #501; a reappearing "
        f"strict-xfail means a blocker regressed or a new one was added without its own lane."
    )
    assert t["passed"] >= _MIN_COLLECTED, (
        f"only {t['passed']} passes — below the service floor {_MIN_COLLECTED}; a baseline "
        f"check did not run or did not pass."
    )


def assert_setup_lane_tally(tally_path: Path) -> None:
    """Raise unless the isolated full-setup lane ran exactly one genuine pass (#245 non-vacuity).

    A marker typo -> 0 collected -> red; a silent skip -> skipped>0 -> red. The lane must never
    skip-green.
    """
    raw = json.loads(tally_path.read_text())
    t = {k: int(raw.get(k, 0)) for k in _KEYS}
    assert t["collected"] == 1, f"setup lane collected {t['collected']} (expected exactly 1)."
    assert t["passed"] == 1, f"setup lane passed {t['passed']} (expected 1) — did it run?"
    for bad in ("failed", "error", "skipped", "xfailed", "xpassed"):
        assert t[bad] == 0, f"setup lane {bad}={t[bad]} (expected 0)."


def main(argv: Sequence[str]) -> int:
    args = list(argv)
    setup = False
    if args and args[0] == "--setup":
        setup = True
        args = args[1:]
    if len(args) != 1:
        print("usage: python -m tests.e2e._assert_ran [--setup] <tally.json>", file=sys.stderr)
        return 2
    tally = Path(args[0])
    if not tally.is_file():
        msg = f"tally file {tally} missing — pytest never wrote it (session errored?)"
        print(msg, file=sys.stderr)
        return 1
    check = assert_setup_lane_tally if setup else assert_boot_lane_tally
    try:
        check(tally)
    except (AssertionError, json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
        # JSONDecodeError: `write_tally` isn't atomic, so a CI cancellation can leave a truncated
        # tally. TypeError/AttributeError/ValueError: a well-formed-but-wrong-shape tally (a
        # top-level JSON list, or a null field) must also red cleanly, not raise a traceback
        # (CodeRabbit). Every malformed tally is a loud red, never a silent pass.
        print(f"e2e {'setup' if setup else 'boot'}-lane tally FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"e2e {'setup' if setup else 'boot'}-lane tally OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
