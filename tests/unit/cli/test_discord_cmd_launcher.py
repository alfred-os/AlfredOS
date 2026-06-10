"""``alfred discord`` boot + verify spawn plugins/alfred_discord via the launcher.

PR-S4-10 (#206), Task 4f. The Slice-2 ``alfred discord`` boot path and
``alfred discord verify`` probe constructed the in-process
``alfred.comms.adapter.DiscordAdapter`` graph. PR-S4-9 shipped the
launcher-spawned ``plugins/alfred_discord`` plugin; PR-S4-10 finishes the
flag-day by repointing the CLI at it so the ``src/alfred/comms/`` deletion
breaks nothing.

The full ``alfred discord verify`` exit-code table (login/intents/timeout) was
a property of the deleted in-process probe; PR-S4-9's plan defers its Slice-4
equivalent (``alfred plugin verify alfred_discord``) to Slice 5. Until then the
CLI delegates to a launcher-spawn readiness check: a clean spawn within the
probe window is healthy; a launcher failure surfaces a ``t()`` string and a
non-zero exit.

These unit tests substitute ``ALFRED_PLUGIN_LAUNCHER`` so they need neither a
sandbox-capable host nor a Discord token.
"""

from __future__ import annotations

from typer.testing import CliRunner

from alfred.cli.discord_cmd import discord_app

# ``t()`` falls back to the bare key when the catalog lacks an entry; assert on
# the key|english alternation so the test is catalog-presence robust.
_BOOT_KEY = "cli.discord.daemon_required"
_BOOT_FRAGMENT = "daemon"


def test_discord_boot_with_failing_launcher_exits_nonzero() -> None:
    """Bare ``alfred discord`` with a failing launcher -> non-zero exit + message."""
    runner = CliRunner()
    result = runner.invoke(discord_app, [], env={"ALFRED_PLUGIN_LAUNCHER": "/usr/bin/false"})
    assert result.exit_code != 0
    assert _BOOT_KEY in result.stderr or _BOOT_FRAGMENT in result.stderr


def test_discord_verify_with_failing_launcher_exits_nonzero() -> None:
    """``alfred discord verify`` with a failing launcher -> non-zero exit + message."""
    runner = CliRunner()
    result = runner.invoke(
        discord_app,
        ["verify"],
        env={"ALFRED_PLUGIN_LAUNCHER": "/usr/bin/false"},
    )
    assert result.exit_code != 0
    assert _BOOT_KEY in result.stderr or _BOOT_FRAGMENT in result.stderr


def test_discord_cmd_does_not_import_legacy_comms_adapter() -> None:
    """The migrated module must not IMPORT the to-be-deleted in-process adapter.

    Guards the deletion-safety invariant: ``src/alfred/comms/`` has no
    production consumer outside itself after PR-S4-10. A regression that
    re-introduces ``from alfred.comms... import ...`` (or ``import
    alfred.comms``) would break the Component C deletion. The check parses the
    AST so a historical reference in a docstring/comment does not trip it —
    only real import statements count.
    """
    import ast
    import inspect

    import alfred.cli.discord_cmd as mod

    tree = ast.parse(inspect.getsource(mod))
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.append(node.module)
        elif isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)

    legacy = [m for m in imported_modules if m == "alfred.comms" or m.startswith("alfred.comms.")]
    assert not legacy, f"discord_cmd still imports the to-be-deleted package: {legacy}"
