"""#340 PR2b golive Task 15: the ``alfred config set action-deadline`` floor-guard.

``action-deadline`` (-> ``orchestrator.action_deadline_seconds``) is the OUTER bound of
the quarantine timeout nesting: ``action_deadline(30) > host_read(25) > child_budget(20)
> SDK_read(8)``. PR2b-prep raised the host read-frame floor to ``_READ_FRAME_TIMEOUT_S =
25``, so the operator-safe band is ``(25s, 30s]``. Writing an ``action_deadline <=`` the
host read-frame timeout would let the orchestrator tear a live extraction at its deadline
BEFORE the framing/child bounds fire — surfacing as a misleading "action deadline
exceeded" with no hint the value is below the quarantine floor (devex-lens).

The floor-guard refuses a ``<= floor`` set with an actionable ``t()`` message naming the
floor + why, instead of silently accepting a nesting-inverting value. The floor is bound
to the REAL ``_READ_FRAME_TIMEOUT_S`` so the two can't drift.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from alfred.cli.config import config_app
from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S


@pytest.fixture()
def runner() -> CliRunner:
    """Typer test runner (Click 8.2 — separate stdout/stderr properties)."""
    return CliRunner()


@pytest.fixture()
def policies(tmp_path: Path) -> Path:
    """An empty ``policies.yaml`` the low-blast write path targets."""
    path = tmp_path / "policies.yaml"
    path.write_text("")
    return path


# --------------------------------------------------------------------------- #
# Accepted — strictly above the floor.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["26", "30", "45", "25.5"])
def test_action_deadline_above_floor_is_accepted(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """A value strictly greater than the host read-frame floor writes policies.yaml."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", value])
    assert result.exit_code == 0, result.stderr
    assert "action_deadline_seconds" in policies.read_text()


# --------------------------------------------------------------------------- #
# Rejected — at or below the floor (nesting inversion).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["25", "20", "0", "24.9"])
def test_action_deadline_at_or_below_floor_is_rejected(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """A value <= the floor is refused with a non-zero exit and NOT written to policies.yaml."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", value])
    assert result.exit_code != 0
    # The rejection is actionable: it names the floor value so the operator can recover.
    assert str(int(_READ_FRAME_TIMEOUT_S)) in result.stderr
    # Fail-closed: nothing was written to the config file.
    assert "action_deadline_seconds" not in policies.read_text()


@pytest.mark.parametrize("value", ["-1", "-5"])
def test_action_deadline_negative_reaches_the_floor_guard(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """A negative value (past the ``--`` option terminator) is refused by the floor-guard.

    Click's parser intercepts a bare leading-dash token as an option, so a real
    ``alfred config set action-deadline -5`` is already rejected at the CLI boundary; the
    ``--`` terminator lets the negative value reach the guard so its ``parsed <= floor``
    branch is exercised (a negative deadline is nonsensical and refused loud).
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", "--", value])
    assert result.exit_code != 0
    assert str(int(_READ_FRAME_TIMEOUT_S)) in result.stderr
    assert "action_deadline_seconds" not in policies.read_text()


def test_action_deadline_nonnumeric_is_rejected(runner: CliRunner, policies: Path) -> None:
    """A non-numeric value can't satisfy the numeric floor — refuse rather than write junk."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", "soon"])
    assert result.exit_code != 0
    assert "action_deadline_seconds" not in policies.read_text()


def test_rejection_message_explains_why(runner: CliRunner, policies: Path) -> None:
    """The rejection names the quarantine-read-frame reason, not just a bare bound."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", "10"])
    assert result.exit_code != 0
    # Actionable: references the read-frame / extraction framing the floor protects.
    assert "read-frame" in result.stderr or "extraction" in result.stderr


# --------------------------------------------------------------------------- #
# Scoping — the floor-guard is action-deadline ONLY.
# --------------------------------------------------------------------------- #


def test_other_low_blast_keys_are_not_floor_guarded(runner: CliRunner, policies: Path) -> None:
    """A small ``extraction-max-retries`` is unaffected — the guard is action-deadline only."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "extraction-max-retries", "1"])
    assert result.exit_code == 0, result.stderr
    assert "extraction_max_retries: 1" in policies.read_text()
