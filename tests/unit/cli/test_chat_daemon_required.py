"""``alfred chat`` surfaces the daemon-required t() string when the launcher fails.

PR-S4-10 (#206): Slice-2's in-process Textual launch is replaced by a thin
spawn of ``plugins/alfred_tui`` via ``bin/alfred-plugin-launcher.sh``. The
daemon must already be running (spec §3.1). When the launcher exits non-zero
within the handshake-probe window — or never finishes spawning — the CLI maps
that to the parameterless ``comms.tui.daemon_required_to_chat`` t() string on
stderr and exits with code 3 (the existing ``_chat_main`` startup-failure
code, alongside the Postgres-unreachable branch).

The ``ALFRED_PLUGIN_LAUNCHER`` env var lets these unit tests substitute a
deterministic stand-in for the real sandbox launcher so they need neither a
daemon nor a sandbox-capable host.
"""

from __future__ import annotations

from typer.testing import CliRunner

from alfred.cli.main import app

# The catalog routes ``comms.tui.daemon_required_to_chat`` to the spec §8.7
# prose; ``t()`` falls back to the bare key when the catalog is unavailable.
# Assert on either so the test is locale/catalog-presence robust.
_DAEMON_FRAGMENT = "alfred chat needs the daemon"
_KEY = "comms.tui.daemon_required_to_chat"


def test_chat_with_failing_launcher_prints_daemon_required_string() -> None:
    """A launcher that exits non-zero -> daemon-required message + exit 3."""
    runner = CliRunner()
    result = runner.invoke(app, ["chat"], env={"ALFRED_PLUGIN_LAUNCHER": "/usr/bin/false"})
    assert result.exit_code == 3
    assert _DAEMON_FRAGMENT in result.stderr or _KEY in result.stderr


def test_chat_with_missing_launcher_prints_daemon_required_string() -> None:
    """A launcher path that does not exist -> daemon-required message + exit 3."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["chat"],
        env={"ALFRED_PLUGIN_LAUNCHER": "/nonexistent/alfred-plugin-launcher.sh"},
    )
    assert result.exit_code == 3
    assert _DAEMON_FRAGMENT in result.stderr or _KEY in result.stderr
