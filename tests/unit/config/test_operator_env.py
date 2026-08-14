"""``operator_display_name()`` — the shared operator-identity resolver (#592).

The function has exactly one job: turn ``$ALFRED_OPERATOR_NAME`` into a display
name, defaulting (and normalising blank/whitespace) to ``"operator"`` so it
agrees with Compose's ``${ALFRED_OPERATOR_NAME:-operator}`` fallback — see the
module docstring for why blank-normalisation lives here rather than at either
call site.
"""

from __future__ import annotations

import pytest

from alfred.config.operator_env import DEFAULT_OPERATOR_NAME, operator_display_name


def test_unset_env_defaults_to_operator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALFRED_OPERATOR_NAME", raising=False)
    assert operator_display_name() == "operator"
    assert operator_display_name() == DEFAULT_OPERATOR_NAME


def test_set_name_is_returned_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_OPERATOR_NAME", "Bruce Wayne")
    assert operator_display_name() == "Bruce Wayne"


def test_empty_string_normalizes_to_operator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_OPERATOR_NAME", "")
    assert operator_display_name() == "operator"


def test_whitespace_only_normalizes_to_operator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_OPERATOR_NAME", "   ")
    assert operator_display_name() == "operator"


def test_surrounding_whitespace_is_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_OPERATOR_NAME", "  Bruce  ")
    assert operator_display_name() == "Bruce"
