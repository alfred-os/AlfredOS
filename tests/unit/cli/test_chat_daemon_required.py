"""``alfred chat`` surfaces the daemon-required t() string when the dial fails.

PR-S4-237-2 (#237), ADR-0031 Shape A: ``alfred chat`` no longer spawns the TUI
via the launcher — it runs the TUI IN ITS OWN process and DIALS the running
daemon's 0600 unix socket. When the daemon is absent the socket file is missing
(``FileNotFoundError``) or unbound (``ConnectionRefusedError``); ``_chat_main``
maps that dial failure to the parameterless ``comms.tui.daemon_required_to_chat``
t() string on stderr and exits with code 3 (the same startup-failure code the
launcher-exit branch used pre-flip) — only the DETECTION moves from "launcher
exited nonzero" to "dial failed".
"""

from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

import alfred.cli.main as main_mod
from alfred.cli.main import app

# The catalog routes ``comms.tui.daemon_required_to_chat`` to the spec §8.7
# prose; ``t()`` falls back to the bare key when the catalog is unavailable.
# Assert on either so the test is locale/catalog-presence robust.
_DAEMON_FRAGMENT = "alfred chat needs the daemon"
_KEY = "comms.tui.daemon_required_to_chat"


def test_chat_with_no_daemon_socket_prints_daemon_required_string(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """No daemon -> the dial raises FileNotFoundError -> daemon-required + exit 3.

    Point ``$HOME`` at a fresh tmp dir so ``~/.run/alfred/comms-tui.sock`` cannot
    exist (no daemon has bound it), making the dial fail deterministically with no
    daemon running.
    """
    runner = CliRunner()
    result = runner.invoke(app, ["chat"], env={"HOME": str(tmp_path)})
    assert result.exit_code == 3
    assert _DAEMON_FRAGMENT in result.stderr or _KEY in result.stderr


def test_chat_maps_oserror_from_dial_to_daemon_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``dial`` raising OSError -> ``DaemonUnavailableError`` -> daemon-required + exit 3.

    Drives the REAL mapping end to end: patching the ``dial`` seam (not ``run_cohosted``)
    exercises ``run_cohosted``'s wrap of the dial-OSError into ``DaemonUnavailableError``,
    which ``_chat_main`` then maps to the operator string + exit 3. Any ``OSError`` family
    member from the dial (``ConnectionRefusedError`` / ``FileNotFoundError`` / a bare
    ``OSError``) is the "daemon/socket unavailable" condition.
    """

    async def _boom_dial(_adapter_id: str) -> object:
        raise OSError("simulated dial failure")

    # ``_chat_main`` calls ``run_cohosted(adapter_id="tui")`` with the production ``dial``
    # default; patch the dial symbol so the real OSError-wrap path runs.
    import alfred_tui.cohost as cohost_mod

    monkeypatch.setattr(cohost_mod, "dial_comms_socket", _boom_dial)

    runner = CliRunner()
    result = runner.invoke(app, ["chat"])
    assert result.exit_code == 3
    assert _DAEMON_FRAGMENT in result.stderr or _KEY in result.stderr


def test_chat_does_not_swallow_post_dial_oserror_as_daemon_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A POST-dial OSError (PTY/render) surfaces LOUD — NOT mislabelled daemon-required.

    Only the dial's OSError is the daemon-unavailable condition. An OSError raised AFTER a
    successful dial (e.g. a broken render pipe) must NOT be mapped to exit 3 — it is an
    unrelated failure and must surface loud rather than be silently mislabelled.
    """

    async def _boom_cohost(**_kwargs: object) -> int:
        # An OSError raised from inside the co-host AFTER the dial succeeded — not a
        # ``DaemonUnavailableError``, so ``_chat_main`` must NOT catch it.
        raise OSError("broken render pipe")

    import alfred_tui.cohost as cohost_mod

    monkeypatch.setattr(cohost_mod, "run_cohosted", _boom_cohost)

    with pytest.raises(OSError, match="broken render pipe"):
        asyncio.run(main_mod._chat_main())


def test_chat_main_returns_clean_on_successful_cohost(monkeypatch: pytest.MonkeyPatch) -> None:
    """A clean co-host (operator quit) returns without raising — no Exit(3).

    The happy path needs no new i18n key: a successful ``run_cohosted`` (the
    operator quit Textual) simply returns, so ``_chat_main`` completes with no
    operator-facing error.
    """

    async def _ok_cohost(**_kwargs: object) -> int:
        return 0

    import alfred_tui.cohost as cohost_mod

    monkeypatch.setattr(cohost_mod, "run_cohosted", _ok_cohost)

    # Drive ``_chat_main`` directly (the Typer command wraps it in asyncio.run); a
    # clean return must not raise typer.Exit.
    asyncio.run(main_mod._chat_main())
