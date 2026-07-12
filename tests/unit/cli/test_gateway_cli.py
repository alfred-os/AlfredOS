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
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import gateway_app
from alfred.i18n import t


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")


@pytest.fixture(autouse=True)
def _patch_egress_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the co-run L7 egress proxy with a no-op (Spec C G7-1b / #333).

    ``alfred gateway start`` now serves the egress forward-proxy alongside the process; a
    real listener bind has no place in these pure-wiring CLI tests (the proxy's mount + its
    fail-closed behaviour are covered by ``test_egress_proxy_mount.py``). The no-op
    ``serve`` returns at once so the co-run TaskGroup unwinds on the gateway leg's exit.
    """

    class _NoopProxy:
        def __init__(self, **_kw: object) -> None:
            pass

        async def serve(self, shutdown_event: asyncio.Event) -> None:
            del shutdown_event

    monkeypatch.setattr("alfred.gateway.egress_proxy.EgressForwardProxy", _NoopProxy)


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
    assert "healthcheck" in result.stdout


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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "POSIX-only: asyncio.unix_events._UnixSelectorEventLoop and "
        "Unix signal-handler APIs are unavailable on Windows"
    ),
)
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


def test_start_bind_oserror_is_friendly_not_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bind ``OSError`` (e.g. ``EADDRINUSE``) is a friendly message + non-zero exit.

    Another gateway already holding the socket is an EXPECTED operator condition, not a
    programming bug — it must surface a next-step line, never a raw traceback.
    """

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            pass

        async def run(self) -> None:
            raise OSError("address already in use")

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.start.bind_failed") in result.stdout
    # The bind-failed line is DISTINCT from the core-unavailable / handshake lines.
    assert t("gateway.start.unavailable") not in result.stdout
    assert t("gateway.start.handshake_failed") not in result.stdout


def test_start_handshake_error_is_friendly_not_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``GatewayHandshakeError`` (the TUI client handshake failed) is a friendly line.

    A torn / not-ok / malformed client leg is an EXPECTED operator condition, so it
    surfaces a next-step message + a distinct non-zero exit, never a raw traceback.
    """
    from alfred.gateway.client_link import GatewayHandshakeError

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            pass

        async def run(self) -> None:
            raise GatewayHandshakeError("client link closed before lifecycle.start ack")

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.start.handshake_failed") in result.stdout
    # The handshake-failed line is DISTINCT from the bind / core-unavailable lines.
    assert t("gateway.start.bind_failed") not in result.stdout
    assert t("gateway.start.unavailable") not in result.stdout


def test_start_manifest_oserror_is_config_fault_not_bind_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A manifest ``OSError`` during adapter-id resolution is a CONFIG fault, not a bind fault.

    ``_resolve_hosted_adapter_ids`` does manifest I/O. If it raises ``OSError`` (an
    unreadable / vanished manifest), the failure is a config fault and MUST surface the
    config-fault line — never the socket-``bind_failed`` line, which mislabels the cause
    and points the operator at the wrong remediation (CLAUDE.md hard rule #7).
    """

    def _boom() -> list[str]:
        raise OSError("manifest.toml is unreadable")

    monkeypatch.setattr("alfred.cli.gateway._commands._resolve_hosted_adapter_ids", _boom)

    # The process must never be constructed — the config fault refuses before any
    # socket work.
    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            raise AssertionError("GatewayProcess built despite a config-resolution fault")

        async def run(self) -> None:  # pragma: no cover - never reached
            raise AssertionError("run() reached despite a config-resolution fault")

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    # The config-fault line renders — NOT the bind-failed line (the mislabel CR flagged).
    assert t("gateway.start.config_failed") in result.stdout
    assert t("gateway.start.bind_failed") not in result.stdout


def test_start_programming_bug_still_surfaces_loud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-EXPECTED error (a programming bug) is NOT mapped to a friendly line.

    FIX 6 maps only EXPECTED operator conditions (``DaemonUnavailableError`` / bind
    ``OSError`` / ``GatewayHandshakeError``); a ``ValueError`` is a bug and MUST still
    surface LOUD (CLAUDE.md hard rule #7 — no silent / friendly-masked failures).
    """

    class _FakeProcess:
        def __init__(self, *, shutdown_event: asyncio.Event, **_kw: object) -> None:
            pass

        async def run(self) -> None:
            raise ValueError("a real programming bug")

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code != 0
    # The bug escapes as a real exception — not masked by any friendly line.
    assert isinstance(result.exception, ValueError)
    assert t("gateway.start.bind_failed") not in result.stdout
    assert t("gateway.start.handshake_failed") not in result.stdout


# ---------------------------------------------------------------------------
# ``alfred gateway status``  (MUST NOT dial — security L3)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family",
)
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


def test_status_runtime_dir_vanishes_between_checks_is_friendly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A TOCTOU race — the runtime dir vanishes after ``exists()`` but before the parent
    ``stat()`` — falls back to the friendly socket-absent line + exit 0, NOT a traceback.

    The present-branch ``socket_path.parent.stat()`` would raise ``OSError`` if a
    concurrent reaper / ``rm -rf ~/.run`` removed the dir between the two probes; the
    command's "never a raw traceback" contract requires the friendly fallback instead.
    """
    runtime_dir = tmp_path / ".run" / "alfred"
    runtime_dir.mkdir(mode=0o700, parents=True)
    sock = runtime_dir / "comms-gateway.sock"
    sock.touch()

    monkeypatch.setattr(
        "alfred.cli.gateway._commands.default_comms_socket_path",
        lambda _adapter_id: sock,
    )

    # Make the PARENT-dir ``stat()`` raise (the dir vanished post-``exists()``), while
    # the ``socket_path.exists()`` probe still reports present. Patch ``Path.stat`` to
    # raise only for the parent dir so the existence check is unaffected.
    real_stat = Path.stat

    def _vanishing_stat(self: Path, *args: object, **kwargs: object) -> object:
        if self == sock.parent:
            raise OSError("runtime dir vanished mid-probe")
        return real_stat(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "stat", _vanishing_stat)

    result = CliRunner().invoke(gateway_app, ["status"])

    assert result.exit_code == 0, result.stdout
    # No traceback escaped — the friendly socket-absent fallback rendered.
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert t("gateway.status.socket_absent", path=str(sock)) in result.stdout


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
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
