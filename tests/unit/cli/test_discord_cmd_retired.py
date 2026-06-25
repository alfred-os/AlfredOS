"""Retirement guard: the standalone ``alfred discord`` command is gone (#309).

Spec B G6-7-8 (#309) deletes ``src/alfred/cli/discord_cmd.py`` and removes the
``app.add_typer(discord_app, name="discord")`` registration from ``main.py``.
Discord is now gateway-hosted and accessed via
``alfred gateway adapters --wait-ready discord``.

This test is a regression guard: if anyone re-adds the registration, or if a
rebase resurrects ``discord_cmd.py`` and the ``add_typer`` call, this test turns
red immediately — before the operator-facing surface changes.
"""

from __future__ import annotations

from typer.testing import CliRunner

from alfred.cli.main import app


def test_alfred_discord_command_is_retired() -> None:
    """Spec B G6-7-8 (#309): the standalone ``alfred discord`` CLI is gone.

    The correct operator path is ``alfred gateway adapters --wait-ready discord``.
    """
    result = CliRunner().invoke(app, ["discord", "--help"])
    assert result.exit_code != 0
