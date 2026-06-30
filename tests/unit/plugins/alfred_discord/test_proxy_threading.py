"""Tests for discord.py proxy threading + supervised in-child shim (Task 8, G7-4 #333).

Covers:
- ``AlfredDiscordBot.__init__`` accepts and forwards ``proxy=``.
- ``serve()`` starts the shim before the stdin loop (source-order invariant).
- No webhook/voice egress introduced (static symbol guard).
- ``_route_shim_failure`` behaviour for the three terminal states of a done task.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

import plugins.alfred_discord.server as server_mod
from plugins.alfred_discord.discord_gateway import AlfredDiscordBot
from plugins.alfred_discord.server import _route_shim_failure

# ---------------------------------------------------------------------------
# Structural / source-order invariants
# ---------------------------------------------------------------------------


def test_bot_accepts_and_forwards_proxy() -> None:
    """AlfredDiscordBot.__init__ must accept proxy= and forward it to super().__init__."""
    sig = inspect.signature(AlfredDiscordBot.__init__)
    assert "proxy" in sig.parameters
    src = inspect.getsource(AlfredDiscordBot.__init__)
    assert "proxy=proxy" in src  # forwarded to commands.Bot / discord.py Client


def test_server_starts_shim_before_stdin_loop() -> None:
    """serve() must start the shim before entering the stdin/stdout MCP loop."""
    src = inspect.getsource(server_mod.serve)
    assert "start_shim" in src, "serve() must call start_shim()"
    assert src.index("start_shim") < src.index("_serve_stdin_stdout"), (
        "start_shim must appear before _serve_stdin_stdout in serve()"
    )


def test_no_webhook_or_voice_egress() -> None:
    """Guard: server.py must not introduce Webhook or VoiceClient (they bypass Client.proxy)."""
    text = inspect.getsource(server_mod)
    assert "Webhook" not in text, "server.py must not reference discord Webhook"
    assert "VoiceClient" not in text, "server.py must not reference VoiceClient"


# ---------------------------------------------------------------------------
# _route_shim_failure handler — three terminal task states
# ---------------------------------------------------------------------------


class _StubTask:
    """Minimal done-task stand-in for _route_shim_failure tests.

    Mirrors the real ``asyncio.Task`` semantics: ``exception()`` raises
    ``asyncio.CancelledError`` when the task was cancelled (so the cancelled-path
    assertions exercise real semantics even if ``_route_shim_failure`` ever stops
    checking ``cancelled()`` first).
    """

    def __init__(self, *, exception: BaseException | None = None, cancelled: bool = False) -> None:
        self._exc = exception
        self._cancelled = cancelled

    def cancelled(self) -> bool:
        return self._cancelled

    def exception(self) -> BaseException | None:
        if self._cancelled:
            raise asyncio.CancelledError
        return self._exc


class _FakeCrashEmitter:
    """Test double: records handle_crash calls without raising SystemExit."""

    def __init__(self) -> None:
        self.calls: list[BaseException] = []

    def handle_crash(self, exc: BaseException) -> None:
        self.calls.append(exc)


def test_route_shim_failure_calls_handle_crash_on_exception() -> None:
    """A task whose exception() is an OSError routes through crash_emitter.handle_crash."""
    crash = _FakeCrashEmitter()
    exc = OSError("shim server died")
    task = _StubTask(exception=exc)
    _route_shim_failure(task, crash)
    assert crash.calls == [exc]


def test_route_shim_failure_ignores_cancelled_task() -> None:
    """A cancelled task (graceful adapter shutdown) must NOT trigger a crash."""
    crash = _FakeCrashEmitter()
    task = _StubTask(cancelled=True)
    _route_shim_failure(task, crash)
    assert crash.calls == []


def test_route_shim_failure_ignores_clean_task() -> None:
    """A task that finishes cleanly (no exception) must NOT trigger a crash."""
    crash = _FakeCrashEmitter()
    task = _StubTask(exception=None)
    _route_shim_failure(task, crash)
    assert crash.calls == []


# ---------------------------------------------------------------------------
# serve() shim-bind-failure routing (FIX-3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_serve_routes_shim_oserror_to_crash_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``start_shim`` raises ``OSError`` (e.g. EADDRINUSE on the loopback port),
    ``serve()`` catches it via its ``BaseException`` handler and calls
    ``crash.handle_crash`` — the bind failure is audited, not propagated raw.

    (This is the FIX-3 invariant: shim startup is INSIDE the try that routes to the
    crash emitter, not before it.)
    """
    crash_calls: list[BaseException] = []

    class _StubCrashEmitter:
        def handle_crash(self, exc: BaseException) -> None:
            crash_calls.append(exc)

    bind_error = OSError("EADDRINUSE: shim loopback bind failure")

    async def _raise_on_start() -> None:
        raise bind_error

    import alfred.egress.adapter_proxy_shim as _shim

    monkeypatch.setattr(server_mod, "configure_stderr_json_logging", lambda: None)
    monkeypatch.setattr(server_mod, "StdoutNotificationSink", lambda: object())
    monkeypatch.setattr(server_mod, "_build_server", lambda _s: object())
    monkeypatch.setattr(server_mod, "CrashEmitter", lambda **_kw: _StubCrashEmitter())
    monkeypatch.setattr(_shim, "start_shim", _raise_on_start)

    await server_mod.serve()
    assert crash_calls == [bind_error]
