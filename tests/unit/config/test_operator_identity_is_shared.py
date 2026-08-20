"""#592 keystone: the migration's operator seed and the shared helper AGREE.

Migration 0004's ``_install_operator`` seeds ``users.display_name`` and the
``platform_identities(platform='tui', platform_id=<display name>)`` row from
``_operator_name()``. The TUI client stamps ``platform_user_id`` on every
inbound notification from ``operator_display_name()``. Before #592 these were
two hand-copied expressions (and the TUI's was a THIRD, unrelated one,
``os.environ.get("USER")``) that stayed in sync only by luck.

``_operator_name()`` now delegates to ``operator_display_name()`` (see
``src/alfred/memory/migrations/versions/0004_users_and_identities.py``), so
this test makes the "they agree" claim falsifiable rather than aspirational:
if the delegation is ever reverted or re-diverged, this test fails.
"""

from __future__ import annotations

import importlib

import pytest

from alfred.config.operator_env import operator_display_name

# File-name-with-leading-digit forces ``importlib.import_module``;
# ``from alfred.memory.migrations.versions import 0004_…`` is a syntax error.
# Same idiom as ``tests/integration/test_migration_0004_backfill.py``.
_v0004 = importlib.import_module("alfred.memory.migrations.versions.0004_users_and_identities")


@pytest.mark.parametrize(
    "env_value",
    [None, "operator", "Bruce Wayne", "", "  Bruce  ", "   "],
    ids=["unset", "operator", "Bruce Wayne", "empty", "padded", "whitespace-only"],
)
def test_migration_and_tui_readers_agree(
    env_value: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if env_value is None:
        monkeypatch.delenv("ALFRED_OPERATOR_NAME", raising=False)
    else:
        monkeypatch.setenv("ALFRED_OPERATOR_NAME", env_value)

    assert _v0004._operator_name() == operator_display_name()
