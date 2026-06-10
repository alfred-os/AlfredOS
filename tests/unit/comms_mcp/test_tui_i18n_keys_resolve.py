"""Live TUI plugin ``t()`` keys resolve to real English (PR-S4-10 review F1, #206).

The TUI render layer moved to ``plugins/alfred_tui`` in the comms-MCP flag-day.
Wave-3's deletion marked the ``tui.*`` keys obsolete because the i18n CI extract
scanned ``src/alfred`` ONLY, so ``pybabel compile`` dropped them and operators
saw raw ``tui.label_you:`` keys instead of rendered text.

This test is the regression guard:

1. It discovers EVERY ``t("...")`` literal key actually called under
   ``plugins/`` (via AST — so it tracks the code, not a hand-list).
2. It asserts each one resolves through ``alfred.i18n.t`` to a NON-key,
   non-empty English string — i.e. the key is an active (non-obsolete) catalog
   entry that survived ``pybabel compile``.

A future move/rename that drops a live plugin key from the extract scope (or
re-obsoletes it) fails here before an operator sees a bare key on screen.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from alfred.i18n import set_language, t

_PLUGINS_ROOT = Path(__file__).resolve().parents[3] / "plugins"


def _live_plugin_t_keys() -> list[str]:
    """Every string-literal ``t(...)`` key called in any ``plugins/`` module."""
    keys: set[str] = set()
    for source in _PLUGINS_ROOT.rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "t"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                keys.add(node.args[0].value)
    return sorted(keys)


def test_at_least_the_known_tui_keys_are_discovered() -> None:
    """Sanity: the four live ``tui.*`` keys are among the discovered set.

    Guards against the discovery walker silently matching nothing (which would
    make the resolution test below vacuously pass).
    """
    discovered = set(_live_plugin_t_keys())
    expected = {
        "tui.binding.quit",
        "tui.input_placeholder",
        "tui.label_you",
        "tui.label_alfred",
    }
    assert expected <= discovered


@pytest.mark.parametrize("key", _live_plugin_t_keys())
def test_live_plugin_t_key_resolves_to_non_key_english(key: str) -> None:
    """Each live plugin ``t()`` key resolves to a non-key, non-empty English string.

    A result equal to the bare key means the catalog entry is missing/obsolete
    (the F1 failure mode); an empty result means a blank msgstr. Either is a
    release-blocking i18n regression.
    """
    set_language("en")
    rendered = t(key)
    assert rendered, f"{key!r} rendered empty"
    assert rendered != key, (
        f"{key!r} did not resolve — it is missing or obsolete in the catalog "
        "(PR-S4-10 review F1: the extract must scan plugins/ and the key must "
        "be an active, compiled msgstr)"
    )
