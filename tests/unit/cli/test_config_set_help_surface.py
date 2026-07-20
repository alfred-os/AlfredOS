"""``alfred config set --help`` names the whole closed key set and the window.

CLAUDE.md's command table tells the reader to "see `alfred config set --help` for the
closed key set". UAT drove it and the help named only two of the six keys —
``web-fetch-budget, quarantined-provider`` — with no ``action-deadline`` and no mention
of the accepted window. So the one place the docs point at for the authoritative list
was the one place that did not have it, and the guarded key was invisible until the
operator guessed its name and got refused.

Two invariants:

* the help enumerates every key ``set`` accepts, generated from ``_KEY_TO_YAML_PATH`` +
  ``_HIGH_BLAST_KEYS`` rather than retyped, so adding a key updates the help for free; and
* the window bounds printed in the help equal the REAL shipped constants.

The second needs its own guard because the bounds are a hardcoded string in the catalog.
They cannot be interpolated at decoration time: ``_reject_action_deadline_outside_window``
imports ``_READ_FRAME_TIMEOUT_S`` / ``_BROKER_PREAMBLE_TIMEOUT_S`` LAZILY on purpose (both
modules carry an egress-adjacent import closure, and pulling it into module scope would
load it on every ``alfred --help``). Rendering the help eagerly would defeat that. So the
numbers live in the catalog and this test — which pays the import cost harmlessly — is
what stops them drifting from the constants they describe.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from alfred.cli.config import _HIGH_BLAST_KEYS, _KEY_TO_YAML_PATH, config_app
from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S
from alfred.security.quarantine_transport import _BROKER_PREAMBLE_TIMEOUT_S

_FLOOR = _BROKER_PREAMBLE_TIMEOUT_S + _READ_FRAME_TIMEOUT_S
_CEILING = 2 * _READ_FRAME_TIMEOUT_S


@pytest.fixture()
def help_text() -> str:
    """``alfred config set --help`` as an operator sees it, de-wrapped.

    Click hard-wraps to the terminal width, so a key name can be split across lines.
    Collapsing whitespace keeps the assertions about CONTENT, not layout.
    """
    result = CliRunner().invoke(config_app, ["set", "--help"])
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


@pytest.mark.parametrize("key", sorted(set(_KEY_TO_YAML_PATH) | _HIGH_BLAST_KEYS))
def test_help_names_every_settable_key(help_text: str, key: str) -> None:
    """Every key ``set`` accepts is discoverable from its own ``--help``."""
    assert key in help_text, (
        f"`alfred config set --help` does not name the settable key {key!r}. "
        f"CLAUDE.md points operators here for the closed key set."
    )


def test_help_states_the_action_deadline_window(help_text: str) -> None:
    """The guarded key advertises its band up front, not only on refusal.

    Discovering a closed window by tripping it is a worse experience than reading it.
    """
    assert str(int(_FLOOR)) in help_text, (
        f"help does not state the action-deadline floor ({int(_FLOOR)}s)"
    )
    assert str(int(_CEILING)) in help_text, (
        f"help does not state the action-deadline ceiling ({int(_CEILING)}s)"
    )


def test_help_bounds_have_not_drifted_from_the_constants(help_text: str) -> None:
    """The catalog's hardcoded bounds still match the shipped constants.

    If someone retunes ``_READ_FRAME_TIMEOUT_S`` this goes red, which is the whole point:
    a help text quoting a window the guard no longer enforces is worse than none.
    """
    stale = {"25", "29", "50", "54"} - {str(int(_FLOOR)), str(int(_CEILING))}
    for number in sorted(stale):
        assert f"above {number}s" not in help_text, (
            f"help quotes a stale action-deadline bound ({number}s); "
            f"the live window is ({int(_FLOOR)}s, {int(_CEILING)}s)"
        )


def test_help_explains_the_two_write_tracks(help_text: str) -> None:
    """A reviewer-gated key behaves nothing like a direct write — say so before it happens.

    ``config set quarantined-provider ...`` returns "pending review" and changes nothing
    yet; an operator who expected the ``policies.yaml`` write path reads that as a failure.
    """
    lowered = help_text.lower()
    assert "policies.yaml" in lowered
    assert "review" in lowered


def test_help_renders_no_unsubstituted_placeholder(help_text: str) -> None:
    """The generated key list is really interpolated.

    ``alfred.i18n.t`` swallows a missing-kwarg ``KeyError`` and returns the RAW template,
    so a help text reading "Keys: {keys}." would otherwise ship silently.
    """
    assert "{" not in help_text and "}" not in help_text, (
        f"`config set --help` leaked an un-substituted placeholder: {help_text!r}"
    )
