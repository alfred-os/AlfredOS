"""Unit tests for the tally guard — the load-bearing non-vacuity gate.

Graduated at #501: the last strict-xfail blocker is gone, so the boot lane is fully green
(xfailed == 0), and the isolated full-setup run has its own single-test non-vacuity guard.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.e2e._assert_ran import (
    assert_boot_lane_tally,
    assert_setup_lane_tally,
    main,
    write_tally,
)

# Graduated boot lane (#501): fully green, NO xfails. 7 passes (4 baseline + service-
# classification + gateway + core), 0 xfailed.
_HEALTHY = {
    "collected": 7,
    "passed": 7,
    "failed": 0,
    "error": 0,
    "skipped": 0,
    "xfailed": 0,
    "xpassed": 0,
}
_REGRESSION = {**_HEALTHY, "passed": 6, "failed": 1}  # a baseline service went red
_LEAKED_XFAIL = {**_HEALTHY, "passed": 6, "xfailed": 1}  # a strict-xfail reappeared -> red
_XPASS = {**_HEALTHY, "passed": 6, "xpassed": 1}  # a non-strict xfail leaked
_COLLAPSED = {k: 0 for k in _HEALTHY}  # collection error / stack never came up
_PLAIN_SKIP = {**_HEALTHY, "passed": 6, "skipped": 1}  # a real skip sneaking in -> skip-green guard
_ERRORED = {**_HEALTHY, "error": 2}  # fixture/setup blew up

# Setup lane: exactly one genuine pass.
_SETUP_OK = {
    "collected": 1,
    "passed": 1,
    "failed": 0,
    "error": 0,
    "skipped": 0,
    "xfailed": 0,
    "xpassed": 0,
}
_SETUP_SKIPPED = {**_SETUP_OK, "passed": 0, "skipped": 1}  # skip-green guard
_SETUP_NONE = {k: 0 for k in _SETUP_OK}  # marker typo -> 0 collected
_SETUP_FAILED = {**_SETUP_OK, "passed": 0, "failed": 1}


def _write(tmp_path: Path, counts: Mapping[str, int]) -> Path:
    p = tmp_path / "tally.json"
    write_tally(counts, p)
    return p


def test_write_tally_roundtrips(tmp_path: Path) -> None:
    assert json.loads(_write(tmp_path, _HEALTHY).read_text()) == _HEALTHY


def test_healthy_tally_passes(tmp_path: Path) -> None:
    assert_boot_lane_tally(_write(tmp_path, _HEALTHY))  # no raise


@pytest.mark.parametrize(
    "counts", [_REGRESSION, _LEAKED_XFAIL, _XPASS, _COLLAPSED, _PLAIN_SKIP, _ERRORED]
)
def test_bad_tally_reds(tmp_path: Path, counts: Mapping[str, int]) -> None:
    with pytest.raises(AssertionError):
        assert_boot_lane_tally(_write(tmp_path, counts))


# Targeted tests for the graduated assertions.


def test_leaked_xfail_reds(tmp_path: Path) -> None:
    """A reappearing strict-xfail (blocker regressed) must red — the lane is fully green now."""
    with pytest.raises(AssertionError, match="fully green"):
        assert_boot_lane_tally(_write(tmp_path, _LEAKED_XFAIL))


def test_xpassed_assertion(tmp_path: Path) -> None:
    """xpassed>0 with everything else fine must fail."""
    with pytest.raises(AssertionError, match="non-strict xfail"):
        assert_boot_lane_tally(_write(tmp_path, {**_HEALTHY, "xpassed": 1}))


def test_too_few_passes_reds(tmp_path: Path) -> None:
    """passed below the service floor must fail (a baseline check did not run/pass).

    collected stays >= floor so the collected-floor assertion does not fire first — this
    isolates the passes-floor check (a corrupt tally: collected inflated, passes too few)."""
    with pytest.raises(AssertionError, match="below the service floor"):
        assert_boot_lane_tally(_write(tmp_path, {**_HEALTHY, "passed": 3}))


# Setup-lane guard.


def test_setup_lane_ok(tmp_path: Path) -> None:
    assert_setup_lane_tally(_write(tmp_path, _SETUP_OK))  # no raise


@pytest.mark.parametrize("counts", [_SETUP_SKIPPED, _SETUP_NONE, _SETUP_FAILED])
def test_setup_lane_reds(tmp_path: Path, counts: Mapping[str, int]) -> None:
    with pytest.raises(AssertionError):
        assert_setup_lane_tally(_write(tmp_path, counts))


# main() CLI.


def test_main_missing_file() -> None:
    assert main(["/nonexistent/tally.json"]) == 1


def test_main_bad_usage() -> None:
    assert main([]) == 2


def test_main_with_healthy_tally(tmp_path: Path) -> None:
    assert main([str(_write(tmp_path, _HEALTHY))]) == 0


def test_main_with_bad_tally(tmp_path: Path) -> None:
    assert main([str(_write(tmp_path, _REGRESSION))]) == 1


def test_main_setup_flag_ok(tmp_path: Path) -> None:
    assert main(["--setup", str(_write(tmp_path, _SETUP_OK))]) == 0


def test_main_setup_flag_reds(tmp_path: Path) -> None:
    assert main(["--setup", str(_write(tmp_path, _SETUP_NONE))]) == 1


def test_main_with_corrupt_tally_reds(tmp_path: Path) -> None:
    """main() treats a truncated/corrupt tally JSON as a red (return 1), not an uncaught
    traceback — write_tally isn't atomic, so a CI cancellation can leave a partial file (devex)."""
    tally_path = tmp_path / "tally.json"
    tally_path.write_text('{"collected": 7, "passed":')  # truncated mid-write
    assert main([str(tally_path)]) == 1


@pytest.mark.parametrize(
    "payload",
    ["[1, 2, 3]", '{"collected": null, "passed": 7}', '"a string"', "42"],
)
def test_main_with_wrong_shape_tally_reds(tmp_path: Path, payload: str) -> None:
    """A well-formed-but-wrong-shape tally (top-level list, null field, scalar) must red cleanly
    (return 1), not raise a TypeError/AttributeError traceback (CodeRabbit)."""
    tally_path = tmp_path / "tally.json"
    tally_path.write_text(payload)
    assert main([str(tally_path)]) == 1
