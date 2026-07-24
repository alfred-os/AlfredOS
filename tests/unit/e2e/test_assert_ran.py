"""Unit tests for the tally guard — the load-bearing non-vacuity gate."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.e2e._assert_ran import assert_boot_lane_tally, main, write_tally

# Healthy today-shape: 5 passes (4 baseline + service-classification) + 3 xfails = 8.
_HEALTHY = {
    "collected": 8,
    "passed": 5,
    "failed": 0,
    "error": 0,
    "skipped": 0,
    "xfailed": 3,
    "xpassed": 0,
}
_XPASS = {**_HEALTHY, "xfailed": 2, "failed": 1}
# a blocker fixed -> strict xpass -> pytest 'failed'
_REGRESSION = {**_HEALTHY, "passed": 4, "failed": 1}
# a baseline service went red
_COLLAPSED = {
    "collected": 0,
    "passed": 0,
    "failed": 0,
    "error": 0,
    "skipped": 0,
    "xfailed": 0,
    "xpassed": 0,
}
_PLAIN_SKIP = {**_HEALTHY, "passed": 4, "skipped": 1}
# a real skip sneaking in -> skip-green guard
_ERRORED = {**_HEALTHY, "error": 2}
# fixture/setup blew up -> stack never came up


def _write(tmp_path: Path, counts: Mapping[str, int]) -> Path:
    p = tmp_path / "tally.json"
    write_tally(counts, p)
    return p


def test_write_tally_roundtrips(tmp_path: Path) -> None:
    assert json.loads(_write(tmp_path, _HEALTHY).read_text()) == _HEALTHY


def test_healthy_tally_passes(tmp_path: Path) -> None:
    assert_boot_lane_tally(_write(tmp_path, _HEALTHY))  # no raise


@pytest.mark.parametrize("counts", [_XPASS, _REGRESSION, _COLLAPSED, _PLAIN_SKIP, _ERRORED])
def test_bad_tally_reds(tmp_path: Path, counts: Mapping[str, int]) -> None:
    with pytest.raises(AssertionError):
        assert_boot_lane_tally(_write(tmp_path, counts))


# Additional targeted tests for each of the 7 assertions.


def test_xpassed_assertion(tmp_path: Path) -> None:
    """xpassed>0 with everything else fine must fail (case a)."""
    xpass_bad = {**_HEALTHY, "xpassed": 1}
    with pytest.raises(AssertionError, match="xpass.*non-strict xfail"):
        assert_boot_lane_tally(_write(tmp_path, xpass_bad))


def test_passed_zero_assertion(tmp_path: Path) -> None:
    """passed==0 with collected>=floor must fail (case b)."""
    no_pass = {**_HEALTHY, "passed": 0}
    with pytest.raises(AssertionError, match="no genuine passes"):
        assert_boot_lane_tally(_write(tmp_path, no_pass))


def test_xfailed_zero_assertion(tmp_path: Path) -> None:
    """xfailed==0 with collected>=floor must fail (case c)."""
    no_xfail = {**_HEALTHY, "xfailed": 0}
    with pytest.raises(AssertionError, match="no xfails"):
        assert_boot_lane_tally(_write(tmp_path, no_xfail))


def test_main_missing_file() -> None:
    """main() returns 1 when tally file is missing."""
    result = main(["/nonexistent/tally.json"])
    assert result == 1


def test_main_bad_usage() -> None:
    """main() returns 2 when called with wrong argument count."""
    result = main([])
    assert result == 2


def test_main_with_healthy_tally(tmp_path: Path) -> None:
    """main() returns 0 for a healthy tally."""
    tally_path = _write(tmp_path, _HEALTHY)
    result = main([str(tally_path)])
    assert result == 0


def test_main_with_bad_tally(tmp_path: Path) -> None:
    """main() returns 1 for a bad tally."""
    tally_path = _write(tmp_path, _REGRESSION)
    result = main([str(tally_path)])
    assert result == 1
