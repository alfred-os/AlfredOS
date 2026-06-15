"""``alfred chat`` dials the GATEWAY socket and surfaces a gateway-required t() string.

Spec A G5 (#237): ``alfred chat`` no longer dials the daemon's ``comms-tui.sock``
directly — there is NO dual-mode. It dials the gateway's own stable
``comms-gateway.sock`` (``adapter_id=_GATEWAY_ADAPTER_ID``, the shared id the
gateway binds on), and the gateway sits between chat and the daemon. When the
gateway is absent the socket file is missing (``FileNotFoundError``) or unbound
(``ConnectionRefusedError``); ``_chat_main`` maps that dial failure to the
parameterless ``comms.tui.gateway_required_to_chat`` t() string on stderr and
exits with code 3 — only the DIAL TARGET (and the operator message) moves from
"daemon" to "gateway".
"""

from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

import alfred.cli.main as main_mod
from alfred.cli.main import app
from alfred.gateway.client_listener import _GATEWAY_ADAPTER_ID

# The catalog routes ``comms.tui.gateway_required_to_chat`` to the spec §8.7
# prose; ``t()`` falls back to the bare key when the catalog is unavailable.
# Assert on either so the test is locale/catalog-presence robust.
_GATEWAY_FRAGMENT = "alfred chat needs the gateway"
_KEY = "comms.tui.gateway_required_to_chat"


def test_chat_with_no_gateway_socket_prints_gateway_required_string(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """No gateway -> the dial raises FileNotFoundError -> gateway-required + exit 3.

    Point ``$HOME`` at a fresh tmp dir so ``~/.run/alfred/comms-gateway.sock`` cannot
    exist (no gateway has bound it), making the dial fail deterministically with no
    gateway running.
    """
    runner = CliRunner()
    result = runner.invoke(app, ["chat"], env={"HOME": str(tmp_path)})
    assert result.exit_code == 3
    assert _GATEWAY_FRAGMENT in result.stderr or _KEY in result.stderr


def test_chat_main_dials_the_gateway_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_chat_main`` dials ``adapter_id=_GATEWAY_ADAPTER_ID`` ("gateway") — NOT "tui".

    Spec A G5 (#237): the chat client's dial target is the gateway's own stable
    ``comms-gateway.sock`` (no dual-mode "tui" direct-dial). Capture the ``adapter_id``
    that reaches the production ``dial`` seam and assert it is the shared gateway id,
    so the dialed path provably resolves to ``comms-gateway.sock``.
    """
    seen: dict[str, str] = {}

    async def _record_cohost(*, adapter_id: str, **_kwargs: object) -> int:
        seen["adapter_id"] = adapter_id
        return 0

    import alfred_tui.cohost as cohost_mod

    monkeypatch.setattr(cohost_mod, "run_cohosted", _record_cohost)

    runner = CliRunner()
    result = runner.invoke(app, ["chat"])
    assert result.exit_code == 0
    assert seen["adapter_id"] == _GATEWAY_ADAPTER_ID == "gateway"


def test_chat_maps_oserror_from_dial_to_gateway_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``dial`` raising OSError -> ``DaemonUnavailableError`` -> gateway-required + exit 3.

    Drives the REAL mapping end to end: patching the ``dial`` seam (not ``run_cohosted``)
    exercises ``run_cohosted``'s wrap of the dial-OSError into ``DaemonUnavailableError``,
    which ``_chat_main`` then maps to the operator string + exit 3. Any ``OSError`` family
    member from the dial (``ConnectionRefusedError`` / ``FileNotFoundError`` / a bare
    ``OSError``) is the "gateway/socket unavailable" condition.
    """

    async def _boom_dial(_adapter_id: str) -> object:
        raise OSError("simulated dial failure")

    # ``_chat_main`` calls ``run_cohosted(adapter_id=_GATEWAY_ADAPTER_ID)`` with the
    # production ``dial`` default; patch the dial symbol so the real OSError-wrap path runs.
    import alfred_tui.cohost as cohost_mod

    monkeypatch.setattr(cohost_mod, "dial_comms_socket", _boom_dial)

    runner = CliRunner()
    result = runner.invoke(app, ["chat"])
    assert result.exit_code == 3
    assert _GATEWAY_FRAGMENT in result.stderr or _KEY in result.stderr


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


def test_no_tui_direct_dial_remains_in_either_chat_dial_site() -> None:
    """Both chat-client dial sites dial the GATEWAY id — no "tui" direct-dial fallback.

    Spec A G5 (#237): NO dual-mode. The chat client (``alfred.cli.main._chat_main`` AND
    the ``alfred_tui.server.serve()`` entrypoint) must dial the gateway's stable id, never
    the daemon-side ``"tui"`` socket. The daemon STILL binds ``comms-tui.sock`` on the
    gateway<->daemon leg (``_SOCKET_BACKED_ADAPTER_KIND="tui"``), so this guard is scoped to
    the two chat-CLIENT dial sites only — it asserts neither passes ``adapter_id="tui"``
    to ``run_cohosted`` and both reference the shared gateway id.
    """
    import inspect
    import re

    import alfred_tui.server as server_mod

    # Normalize whitespace around ``=`` so the membership test catches the
    # spaced form (``adapter_id = "tui"``) too — a bare ``'adapter_id="tui"' not in``
    # would pass FALSELY on a reformatted spaced literal. This guard is a BACKSTOP;
    # the behavioral ``test_chat_main_dials_the_gateway_socket`` is the real proof
    # that the gateway id (not "tui") reaches ``run_cohosted``.
    def _normalize(src: str) -> str:
        return re.sub(r"\s*=\s*", "=", src)

    chat_src = _normalize(inspect.getsource(main_mod._chat_main))
    serve_src = _normalize(inspect.getsource(server_mod.serve))

    # No "tui" literal direct-dial from the chat path (the daemon-side binding lives
    # elsewhere and is out of scope). Whitespace-normalized above so the spaced form
    # cannot slip past.
    assert 'adapter_id="tui"' not in chat_src
    assert 'adapter_id="tui"' not in serve_src

    # Both dial the shared gateway id. ``_chat_main`` references the constant by name;
    # ``serve()`` pins its ``_ADAPTER_KIND`` to the gateway id.
    assert "_GATEWAY_ADAPTER_ID" in chat_src
    assert server_mod._ADAPTER_KIND == _GATEWAY_ADAPTER_ID == "gateway"
