"""#340 PR2b golive: the ``alfred config set action-deadline`` WINDOW-guard.

``action-deadline`` (-> ``orchestrator.action_deadline_seconds``) is the OUTER bound of
the quarantine timeout nesting and is bounded on BOTH sides:

* FLOOR ``preamble(4) + host_read(25) = 29``. The broker preamble is SEQUENTIAL with the
  host read-frame bound, so a live extraction can occupy their SUM; at or below it the
  orchestrator tears a healthy extraction before the framing/child bounds fire, surfacing
  as a misleading "action deadline exceeded" (devex-lens).
* CEILING ``2 x host_read = 50``. ``read_frame`` bounds header and body reads SEPARATELY,
  so only the outer ``asyncio.timeout(action_deadline)`` caps a wedged child's per-frame
  cost; at or above 50 that wrap stops dominating.

So the operator-safe band is ``(29s, 50s)``, with the shipped default 30 inside it.

Two guard defects this file now pins, both of which shipped accepted-but-wrong values:

1. The floor was bound to ``host_read`` (25) ALONE, admitting ``(25, 29]`` — values that
   still tear a live extraction, because the preamble runs before the read even starts.
2. There was NO ceiling, so ``config set action-deadline 50`` was accepted and silently
   inverted the invariant that ``test_action_deadline_dominates_the_two_phase_read_frame_bound``
   pins — that sibling test only pins the DEFAULT constant, never an operator-set value.

Both bounds are bound to the REAL shipped constants so the guard and runtime can't drift.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from alfred.cli.config import config_app
from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S
from alfred.security.quarantine_transport import _BROKER_PREAMBLE_TIMEOUT_S

_FLOOR = _BROKER_PREAMBLE_TIMEOUT_S + _READ_FRAME_TIMEOUT_S
_CEILING = 2 * _READ_FRAME_TIMEOUT_S


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


@pytest.mark.parametrize("value", ["30", "45", "29.5", "49.9"])
def test_action_deadline_inside_the_window_is_accepted(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """A value strictly INSIDE ``(floor, ceiling)`` writes policies.yaml."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", value])
    assert result.exit_code == 0, result.stderr
    assert "action_deadline_seconds" in policies.read_text()


# --------------------------------------------------------------------------- #
# Rejected — at or below the floor (nesting inversion).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["29", "25", "20", "0", "24.9"])
def test_action_deadline_at_or_below_floor_is_rejected(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """A value <= the floor is refused with a non-zero exit and NOT written to policies.yaml."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", value])
    assert result.exit_code != 0
    # The rejection is actionable: it names the floor value so the operator can recover.
    assert str(int(_FLOOR)) in result.stderr
    # Fail-closed: nothing was written to the config file.
    assert "action_deadline_seconds" not in policies.read_text()


@pytest.mark.parametrize("value", ["26", "27", "28", "29"])
def test_values_between_host_read_and_the_preamble_sum_are_rejected(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """REGRESSION: ``(host_read, preamble+host_read]`` was accepted while still unsafe.

    These sit ABOVE the old ``host_read``-only floor (25) but at or below the real
    sequential floor (29), so the pre-fix guard wrote them happily even though the
    orchestrator would tear a healthy extraction: the broker preamble runs BEFORE the host
    read starts, so the two costs add rather than nest.
    """
    assert _READ_FRAME_TIMEOUT_S < float(value) <= _FLOOR  # the band is real, not empty
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", value])
    assert result.exit_code != 0
    assert "action_deadline_seconds" not in policies.read_text()


# --------------------------------------------------------------------------- #
# Rejected — at or above the ceiling (the outer wrap stops dominating).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["50", "60", "50.0", "1000"])
def test_action_deadline_at_or_above_ceiling_is_rejected(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """REGRESSION: a value >= ``2 x host_read`` was silently accepted and inverted §17.

    ``test_action_deadline_dominates_the_two_phase_read_frame_bound`` pins this invariant
    for the DEFAULT constant only; nothing stopped an operator writing 50 and letting a
    wedged child hang the full two-phase per-frame bound.
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", value])
    assert result.exit_code != 0
    # Actionable: names the ceiling so the operator can pick a legal value.
    assert str(int(_CEILING)) in result.stderr
    assert "action_deadline_seconds" not in policies.read_text()


def test_rejection_messages_name_the_whole_window(runner: CliRunner, policies: Path) -> None:
    """BOTH refusals state the full legal window, not just the bound that tripped.

    An operator who trips the ceiling still needs the floor to choose a replacement value
    (and vice versa) — naming one end alone forces a second failed attempt.
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        low = runner.invoke(config_app, ["set", "action-deadline", "10"])
        high = runner.invoke(config_app, ["set", "action-deadline", "99"])
    for result in (low, high):
        assert result.exit_code != 0
        assert str(int(_FLOOR)) in result.stderr
        assert str(int(_CEILING)) in result.stderr


def test_bounds_render_without_a_bare_float_tail(runner: CliRunner, policies: Path) -> None:
    """The bounds render as ``29``/``50``, not Python's ``29.0``/``50.0`` (devex).

    ``str(float)`` leaked a ``.0`` tail into operator output; ``babel.numbers`` renders
    the value the way the active locale would write it.
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", "10"])
    assert result.exit_code != 0
    assert f"{_FLOOR:.1f}" not in result.stderr  # no "29.0"
    assert f"{_CEILING:.1f}" not in result.stderr  # no "50.0"


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
    assert str(int(_FLOOR)) in result.stderr
    assert "action_deadline_seconds" not in policies.read_text()


def test_action_deadline_nonnumeric_is_rejected(runner: CliRunner, policies: Path) -> None:
    """A non-numeric value can't satisfy the numeric floor — refuse rather than write junk."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", "soon"])
    assert result.exit_code != 0
    assert "action_deadline_seconds" not in policies.read_text()


# --------------------------------------------------------------------------- #
# Type errors get their OWN message — a typo is not a bounds violation.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["abc", "3O", "soon", "30s", ""])
def test_nonnumeric_action_deadline_is_told_it_is_not_a_number(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """A non-numeric value is a TYPE error, and must not be reported as a floor violation.

    ``_parse_scalar`` returns the raw ``str`` when neither ``int()`` nor ``float()``
    accepts it, and the window guard's ``isinstance`` check then routes it into the FLOOR
    branch. The operator who fat-fingers ``3O`` (letter O) for ``30`` was therefore told
    the value is "at or below the floor (got 3O)" and handed a paragraph of timeout-nesting
    prose about sequential preamble and read-frame bounds — an explanation of a constraint
    they did not violate, which actively obstructs finding the real problem (a typo).

    The remedy for a type error is "type a number"; the remedy for a floor violation is
    "pick a bigger number". Different problems, different messages.
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", value])

    assert result.exit_code != 0, result.stderr
    assert "action_deadline_seconds" not in policies.read_text()
    # Names the real fault…
    assert "not a number" in result.stderr, (
        f"non-numeric {value!r} was not told it is not a number. Got: {result.stderr!r}"
    )
    # …and does NOT mis-attribute it to the floor/nesting constraint.
    assert "floor" not in result.stderr.lower(), (
        f"non-numeric {value!r} was mis-reported as a floor violation. Got: {result.stderr!r}"
    )
    assert "read-frame" not in result.stderr, (
        f"non-numeric {value!r} got timeout-nesting prose it does not need. Got: {result.stderr!r}"
    )


def test_the_type_error_still_states_the_accepted_window(runner: CliRunner, policies: Path) -> None:
    """Naming the fault is not enough — the operator still needs the band to retype into.

    Dropping the bounds would trade one unhelpful message for another.
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", "abc"])
    assert str(int(_FLOOR)) in result.stderr
    assert str(int(_CEILING)) in result.stderr
    assert "{" not in result.stderr and "}" not in result.stderr


def test_numeric_below_floor_still_gets_the_floor_message(
    runner: CliRunner, policies: Path
) -> None:
    """Negative control for the split above: a real floor violation keeps its own message.

    Without this, deleting the floor branch entirely would still pass the type-error tests.
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", "10"])
    assert result.exit_code != 0
    assert "not a number" not in result.stderr
    assert "read-frame" in result.stderr or "extraction" in result.stderr


# --------------------------------------------------------------------------- #
# Floor / ceiling render their rejected value the SAME way.
# --------------------------------------------------------------------------- #


def test_floor_and_ceiling_render_the_rejected_value_symmetrically(
    runner: CliRunner, policies: Path
) -> None:
    """Both branches locale-format the rejected value; neither leaks ``str(float)``.

    The floor branch echoed ``str(parsed)`` raw while the ceiling branch ran the value
    through ``_format_seconds``. So ``config set action-deadline 10.0`` reported ``10.0``
    at the floor but ``99`` at the ceiling — the same operator input rendered two ways by
    the same command, and the floor path re-introduced the exact ``.0`` tail
    ``test_bounds_render_without_a_bare_float_tail`` removed from the BOUNDS.
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        below = runner.invoke(config_app, ["set", "action-deadline", "10.0"])
        above = runner.invoke(config_app, ["set", "action-deadline", "99.0"])

    assert below.exit_code != 0 and above.exit_code != 0
    assert "10.0" not in below.stderr, (
        f"floor branch leaked a bare float tail for the rejected value: {below.stderr!r}"
    )
    assert "99.0" not in above.stderr
    assert "10" in below.stderr
    assert "99" in above.stderr


def test_rejection_message_explains_why(runner: CliRunner, policies: Path) -> None:
    """The rejection names the quarantine-read-frame reason, not just a bare bound."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", "10"])
    assert result.exit_code != 0
    # Actionable: references the read-frame / extraction framing the floor protects.
    assert "read-frame" in result.stderr or "extraction" in result.stderr


@pytest.mark.parametrize(
    "value",
    [
        "10",  # numeric, below floor
        "29",  # exactly at the floor (rejected — the bound is strict)
        "soon",  # non-numeric: falls into the floor branch via the isinstance guard
        "50",  # exactly at the ceiling
        "99",  # above the ceiling
    ],
)
def test_window_refusals_fully_substitute_every_placeholder(
    runner: CliRunner, policies: Path, value: str
) -> None:
    """No window refusal may leak a literal ``{value}`` / ``{floor}`` / ``{ceiling}``.

    i18n-002 at the CALL SITE. :mod:`tests.unit.cli.test_i18n_key_coverage` also runs a
    placeholder-leak guard over these two msgids, but it supplies its OWN kwargs — so it
    proves the TEMPLATE is renderable, never that the live ``t(...)`` call passes the
    names the template asks for. Those are different failures with the same symptom.

    The gap is silent by construction: ``alfred.i18n.t`` swallows the ``KeyError`` that
    ``str.format`` raises on a missing kwarg and returns the UNSUBSTITUTED template. So
    renaming ``value=`` in ``_reject_action_deadline_outside_window`` ships a raw
    ``{value}`` to the operator.

    Measured honestly: TODAY that specific mutation is also caught collaterally — because
    ``str.format`` fails all-or-nothing, a bad ``value=`` also strands ``{floor}`` and
    ``{ceiling}``, so the sibling bound-assertions above go red too (8 of them). That
    coverage is INCIDENTAL, not designed, and it evaporates the moment this msgstr's only
    un-asserted placeholder is the one that breaks — e.g. a future re-phrase that drops
    the bounds from the floor body but keeps ``{value}``. This test states the invariant
    directly so the failure names its real cause, instead of surfacing as a confusing
    "29 not in stderr".

    Both branches are covered, including the non-numeric input that reaches the floor
    branch through the ``isinstance`` guard rather than a numeric comparison.
    """
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "action-deadline", value])

    assert result.exit_code != 0, result.stderr
    assert "{" not in result.stderr and "}" not in result.stderr, (
        f"action-deadline refusal for {value!r} leaked an un-substituted placeholder -- "
        f"the msgstr references a name the CLI call site does not pass (alfred.i18n.t "
        f"swallows the KeyError and returns the raw template). Got: {result.stderr!r}"
    )
    # The refusal must still carry the operator's rejected input, not just the bounds:
    # a silently-dropped ``value=`` would otherwise satisfy the brace check above.
    assert value in result.stderr


# --------------------------------------------------------------------------- #
# Scoping — the floor-guard is action-deadline ONLY.
# --------------------------------------------------------------------------- #


def test_other_low_blast_keys_are_not_floor_guarded(runner: CliRunner, policies: Path) -> None:
    """A small ``extraction-max-retries`` is unaffected — the guard is action-deadline only."""
    with patch("alfred.cli.config._policies_yaml_path", policies):
        result = runner.invoke(config_app, ["set", "extraction-max-retries", "1"])
    assert result.exit_code == 0, result.stderr
    assert "extraction_max_retries: 1" in policies.read_text()
