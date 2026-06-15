"""``alfred gateway start | status`` CLI surface (Spec A G3-3b-2b / #237).

Mirrors ``tests/unit/cli/daemon/test_daemon_app_registration.py`` +
``test_daemon_status_*``: the gateway Typer group exposes the long-running
:class:`alfred.gateway.process.GatewayProcess` (``start``) and a Settings-only
health line (``status``) without ever dialing the socket (security L3).

The heavy gateway graph (``alfred.gateway.relay`` / ``process``) is imported
LAZILY inside the command bodies (perf-001), so ``alfred --help`` never pulls
the relay chain — pinned by ``test_main_lazy_imports.py``; the registration
test here is the complementary surface check.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import gateway_app
from alfred.i18n import t


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


# ---------------------------------------------------------------------------
# Registration + help surface
# ---------------------------------------------------------------------------


def test_gateway_appears_in_root_help() -> None:
    from alfred.cli.main import app

    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "gateway" in result.stdout


def test_gateway_subcommands_listed() -> None:
    result = CliRunner().invoke(gateway_app, ["--help"])
    assert result.exit_code == 0
    assert "start" in result.stdout
    assert "status" in result.stdout


# ---------------------------------------------------------------------------
# ``alfred gateway start``
# ---------------------------------------------------------------------------


def test_start_constructs_and_runs_gateway_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """``start`` builds a ``GatewayProcess(shutdown_event=...)`` and awaits ``run``.

    The process ``run`` is replaced with an immediately-returning coroutine so the
    test asserts the wiring (a shutdown event is constructed, a process is built
    with it, and its ``run`` is awaited under ``asyncio.run``) without a real socket.
    """
    captured: dict[str, object] = {}

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            captured["shutdown_event"] = shutdown_event
            captured["built"] = True

        async def run(self) -> None:
            captured["ran"] = True

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert captured.get("built") is True
    assert captured.get("ran") is True
    assert isinstance(captured.get("shutdown_event"), asyncio.Event)


def test_start_signal_handler_unavailable_logs_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-main-thread loop (``add_signal_handler`` raises) is loud-and-continue.

    The signal-handler install failure (``NotImplementedError`` / ``ValueError`` on
    a platform / non-main-thread loop) MUST NOT abort the start — it logs the loud
    ``gateway.cli.signal_handler_unavailable`` key and the process still runs.
    """
    ran = asyncio.Event()

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            self._shutdown = shutdown_event

        async def run(self) -> None:
            ran.set()

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)

    def _raise_no_signals(*_args: object, **_kw: object) -> None:
        raise NotImplementedError("loop cannot install signal handlers")

    monkeypatch.setattr(
        asyncio.unix_events._UnixSelectorEventLoop,  # type: ignore[attr-defined]
        "add_signal_handler",
        _raise_no_signals,
        raising=False,
    )

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert ran.is_set()


def test_start_unavailable_socket_is_friendly_not_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A core/socket-setup failure is a friendly message + non-zero exit, not a raw trace."""
    from alfred.comms_mcp.errors import DaemonUnavailableError

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            pass

        async def run(self) -> None:
            raise DaemonUnavailableError("core socket unreachable")

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code != 0
    # The friendly message renders, not a bare traceback. ``CliRunner`` captures
    # an uncaught exception in ``result.exception`` — assert none escaped.
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.start.unavailable") in result.stdout


# ---------------------------------------------------------------------------
# ``alfred gateway status``  (MUST NOT dial — security L3)
# ---------------------------------------------------------------------------


def test_status_socket_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".run" / "alfred"
    runtime_dir.mkdir(mode=0o700, parents=True)
    sock = runtime_dir / "comms-gateway.sock"
    sock.touch()

    monkeypatch.setattr(
        "alfred.cli.gateway._commands.default_comms_socket_path",
        lambda _adapter_id: sock,
    )

    result = CliRunner().invoke(gateway_app, ["status"])

    assert result.exit_code == 0, result.stdout
    # The present-line template carries ``{path}`` / ``{runtime_mode}`` / ``{uid}``;
    # assert against the rendered line (path substituted) so the message identity is
    # pinned to the catalog key, not raw English.
    expected = t(
        "gateway.status.socket_present",
        path=str(sock),
        runtime_mode=f"{0o700:#o}",
        uid=os.getuid(),
    )
    assert expected in result.stdout


def test_status_socket_absent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sock = tmp_path / ".run" / "alfred" / "comms-gateway.sock"

    monkeypatch.setattr(
        "alfred.cli.gateway._commands.default_comms_socket_path",
        lambda _adapter_id: sock,
    )

    result = CliRunner().invoke(gateway_app, ["status"])

    assert result.exit_code == 0, result.stdout
    assert t("gateway.status.socket_absent", path=str(sock)) in result.stdout


def test_status_never_dials_the_socket(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Status is a ``Path.exists`` + stat probe only — it MUST NOT open a connection."""
    runtime_dir = tmp_path / ".run" / "alfred"
    runtime_dir.mkdir(mode=0o700, parents=True)
    sock = runtime_dir / "comms-gateway.sock"
    sock.touch()

    monkeypatch.setattr(
        "alfred.cli.gateway._commands.default_comms_socket_path",
        lambda _adapter_id: sock,
    )

    dialed: list[object] = []

    async def _forbidden_dial(*args: object, **kwargs: object) -> object:
        dialed.append((args, kwargs))
        raise AssertionError("status dialed the socket — security L3 violation")

    monkeypatch.setattr(asyncio, "open_unix_connection", _forbidden_dial)

    result = CliRunner().invoke(gateway_app, ["status"])

    assert result.exit_code == 0
    assert dialed == []
