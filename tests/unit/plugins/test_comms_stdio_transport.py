"""``CommsStdioTransport`` — line-delimited JSON-RPC pipe (PR-S4-11a Wave 1).

The transport is a DUMB duplex line-delimited JSON-RPC pipe to a comms plugin
subprocess. It carries no DLP, no secret substitution, no T3 tagging, no canary
scan — that work lives in ``process_inbound_message`` + ``ScannedOutboundBody``
upstream (ADR-0025). Its only security duty is a frame-size bound + loud failure
on a broken/malformed wire.

These unit cases drive the framing against in-memory ``StreamReader`` / a fake
process (no real subprocess — spawn-via-launcher is the Wave-2 integration test).
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from alfred.cli._launcher_spawn import PluginLaunchSpec
from alfred.plugins.comms_stdio_transport import (
    _MAX_COMMS_LINE_BYTES,
    CommsProtocolError,
    CommsStdioTransport,
)

pytestmark = pytest.mark.asyncio


def _spec() -> PluginLaunchSpec:
    return PluginLaunchSpec(
        plugin_id="alfred_comms_test",
        manifest_path=Path("/opt/alfred/manifest.toml"),
        module="alfred_comms_test.main",
        adapter_id="alfred_comms_test",
        import_roots=(Path("/opt/alfred/plugins"),),
        inherit_stdio=False,
        sandbox_kind="none",
    )


class _FakeStdin:
    """Records everything written; configurable broken-pipe on write/drain."""

    def __init__(self, *, broken: bool = False) -> None:
        self.buffer = bytearray()
        self.closed = False
        self._broken = broken

    def write(self, data: bytes) -> None:
        if self._broken:
            raise BrokenPipeError("stdin closed")
        self.buffer.extend(data)

    async def drain(self) -> None:
        if self._broken:
            raise BrokenPipeError("stdin closed")

    def close(self) -> None:
        self.closed = True


class _FakeProc:
    """Minimal stand-in for ``asyncio.subprocess.Process``."""

    def __init__(
        self,
        *,
        stdout: asyncio.StreamReader | None,
        stdin: _FakeStdin | None,
        returncode: int | None = None,
    ) -> None:
        self.stdout = stdout
        self.stdin = stdin
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self._wait_hangs = False

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        if self._wait_hangs:
            await asyncio.Event().wait()  # pragma: no cover - cancelled by wait_for
        return self.returncode if self.returncode is not None else 0


def _reader_with(lines: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(lines)
    reader.feed_eof()
    return reader


def _make_transport(proc: _FakeProc) -> CommsStdioTransport:
    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec())
    transport._proc = proc  # type: ignore[assignment]  # inject fake proc for hermetic test
    return transport


# ---------------------------------------------------------------------------
# send: one newline-terminated frame per call
# ---------------------------------------------------------------------------


async def test_send_writes_one_newline_terminated_json_frame() -> None:
    stdin = _FakeStdin()
    transport = _make_transport(_FakeProc(stdout=None, stdin=stdin))

    frame: Mapping[str, object] = {"jsonrpc": "2.0", "id": 1, "method": "lifecycle.start"}
    await transport.send(frame)

    written = stdin.buffer.decode()
    assert written.endswith("\n")
    assert written.count("\n") == 1
    assert json.loads(written) == frame


async def test_send_loud_on_broken_pipe() -> None:
    transport = _make_transport(_FakeProc(stdout=None, stdin=_FakeStdin(broken=True)))

    with pytest.raises(BrokenPipeError):
        await transport.send({"jsonrpc": "2.0", "method": "lifecycle.start"})


async def test_send_before_spawn_raises() -> None:
    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec())

    with pytest.raises(RuntimeError):
        await transport.send({"jsonrpc": "2.0", "method": "x"})


# ---------------------------------------------------------------------------
# read_frame: one frame per line
# ---------------------------------------------------------------------------


async def test_read_frame_parses_one_frame_per_line() -> None:
    a = json.dumps({"jsonrpc": "2.0", "method": "inbound.message", "params": {"n": 1}})
    b = json.dumps({"jsonrpc": "2.0", "method": "adapter.crashed", "params": {"n": 2}})
    proc = _FakeProc(stdout=_reader_with((a + "\n" + b + "\n").encode()), stdin=None)
    transport = _make_transport(proc)

    first = await transport.read_frame()
    second = await transport.read_frame()

    assert first == {"jsonrpc": "2.0", "method": "inbound.message", "params": {"n": 1}}
    assert second == {"jsonrpc": "2.0", "method": "adapter.crashed", "params": {"n": 2}}


async def test_read_frame_empty_read_is_clean_eof_none() -> None:
    proc = _FakeProc(stdout=_reader_with(b""), stdin=None)
    transport = _make_transport(proc)

    assert await transport.read_frame() is None


async def test_read_frame_before_spawn_raises() -> None:
    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec())

    with pytest.raises(RuntimeError):
        await transport.read_frame()


async def test_read_frame_reader_limit_overrun_raises_protocol_error() -> None:
    """A line past the StreamReader's own ``limit`` surfaces as CommsProtocolError.

    A real spawn pins the reader ``limit`` to ``max_line_bytes``; here we drive a
    reader with a tiny limit so ``readline()`` raises ``LimitOverrunError`` (a
    ``ValueError`` subclass), which the transport converts to its protocol error.
    """
    reader = asyncio.StreamReader(limit=16)
    reader.feed_data(b"x" * 64 + b"\n")
    reader.feed_eof()
    transport = _make_transport(_FakeProc(stdout=reader, stdin=None))

    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


async def test_read_frame_belt_and_braces_len_bound_raises() -> None:
    """A line under the reader limit but over ``max_line_bytes`` is still refused.

    Defence-in-depth: the explicit ``len(line) > max_line_bytes`` check catches a
    line the StreamReader's own limit let through (a line at exactly the reader
    limit). A small ``max_line_bytes`` with the default-limit reader exercises it.
    """
    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec(), max_line_bytes=32)
    # A 200-byte VALID JSON line slips past the default 64KB reader limit but
    # exceeds the 32-byte transport bound.
    line = ('{"k":"' + "a" * 200 + '"}').encode() + b"\n"
    transport._proc = _FakeProc(stdout=_reader_with(line), stdin=None)  # type: ignore[assignment]

    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


async def test_read_frame_json_garbage_raises_protocol_error() -> None:
    proc = _FakeProc(stdout=_reader_with(b"this is not json\n"), stdin=None)
    transport = _make_transport(proc)

    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


async def test_read_frame_non_dict_raises_protocol_error() -> None:
    proc = _FakeProc(stdout=_reader_with(b"[1, 2, 3]\n"), stdin=None)
    transport = _make_transport(proc)

    with pytest.raises(CommsProtocolError):
        await transport.read_frame()


# ---------------------------------------------------------------------------
# close: idempotent + escalating
# ---------------------------------------------------------------------------


async def test_close_closes_stdin_and_reaps() -> None:
    stdin = _FakeStdin()
    proc = _FakeProc(stdout=None, stdin=stdin, returncode=None)
    transport = _make_transport(proc)

    await transport.close()

    assert stdin.closed is True


async def test_close_is_idempotent() -> None:
    proc = _FakeProc(stdout=None, stdin=_FakeStdin(), returncode=0)
    transport = _make_transport(proc)

    await transport.close()
    # Second close is a no-op (process already reaped) — must not raise.
    await transport.close()


async def test_close_before_spawn_is_noop() -> None:
    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec())
    await transport.close()  # no proc — clean no-op


async def test_close_escalates_to_kill_on_wait_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = _FakeProc(stdout=None, stdin=_FakeStdin(), returncode=None)
    proc._wait_hangs = True
    transport = _make_transport(proc)

    # Force the bounded wait to time out immediately so the escalation arm runs
    # without a real 5s sleep.
    async def _instant_timeout(awaitable: Any, timeout: float) -> Any:
        if hasattr(awaitable, "close"):
            awaitable.close()
        raise TimeoutError

    monkeypatch.setattr("alfred.plugins.comms_stdio_transport.asyncio.wait_for", _instant_timeout)

    await transport.close()

    assert proc.killed is True


async def test_close_terminate_suffices_does_not_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    """SIGTERM-sufficed path: the cooperative close times out, terminate() works,
    the child exits on SIGTERM, so SIGKILL is NEVER sent."""
    proc = _FakeProc(stdout=None, stdin=_FakeStdin(), returncode=None)
    proc._wait_hangs = True
    transport = _make_transport(proc)

    calls = {"n": 0}

    async def _timeout_once_then_ok(awaitable: Any, timeout: float) -> Any:
        calls["n"] += 1
        if hasattr(awaitable, "close"):
            awaitable.close()
        if calls["n"] == 1:
            raise TimeoutError  # cooperative close timed out -> terminate()
        return 0  # after SIGTERM the child exited -> no kill()

    monkeypatch.setattr(
        "alfred.plugins.comms_stdio_transport.asyncio.wait_for", _timeout_once_then_ok
    )

    await transport.close()

    assert proc.terminated is True
    assert proc.killed is False


async def test_close_suppresses_process_lookup_error_during_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The child can exit between the wait timeout and the signal (concurrent
    SIGCHLD), so terminate()/kill() raise ProcessLookupError. close() must
    swallow it — it runs in the runner's finally during TaskGroup cancellation."""
    proc = _FakeProc(stdout=None, stdin=_FakeStdin(), returncode=None)

    def _gone() -> None:
        raise ProcessLookupError("no such process")

    proc.terminate = _gone  # type: ignore[method-assign]
    proc.kill = _gone  # type: ignore[method-assign]
    transport = _make_transport(proc)

    async def _instant_timeout(awaitable: Any, timeout: float) -> Any:
        if hasattr(awaitable, "close"):
            awaitable.close()
        raise TimeoutError

    monkeypatch.setattr("alfred.plugins.comms_stdio_transport.asyncio.wait_for", _instant_timeout)

    # Must complete without surfacing ProcessLookupError out of the finally path.
    await transport.close()


async def test_read_frame_after_eof_keeps_returning_none() -> None:
    """Post-EOF reads stay clean: ``None`` again, never a spurious raise."""
    proc = _FakeProc(stdout=_reader_with(b""), stdin=None)
    transport = _make_transport(proc)

    assert await transport.read_frame() is None
    assert await transport.read_frame() is None


# ---------------------------------------------------------------------------
# spawn: guards double-spawn (full launcher spawn is the Wave-2 integration test)
# ---------------------------------------------------------------------------


async def test_spawn_guards_against_double_spawn() -> None:
    transport = _make_transport(_FakeProc(stdout=None, stdin=_FakeStdin()))

    with pytest.raises(RuntimeError):
        await transport.spawn()


async def test_spawn_invokes_launcher_argv_with_scrubbed_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """spawn() builds the REAL launcher argv + a scrubbed env (no real subprocess).

    The launcher path is overridden via ``ALFRED_PLUGIN_LAUNCHER`` so no real
    ``alfred-plugin-launcher.sh`` runs; ``create_subprocess_exec`` is faked so the
    test stays hermetic. We assert the argv shape (``<launcher> <plugin_id>
    <python> -m <module>``), that the secret-bearing env is scrubbed, and that the
    stdout reader limit is pinned to ``max_line_bytes``.
    """
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", "/fake/launcher.sh")
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "leak-me")

    captured: dict[str, Any] = {}

    async def _fake_exec(*args: Any, **kwargs: Any) -> _FakeProc:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeProc(stdout=None, stdin=_FakeStdin())

    monkeypatch.setattr(
        "alfred.plugins.comms_stdio_transport.asyncio.create_subprocess_exec", _fake_exec
    )

    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec())
    await transport.spawn()

    argv = captured["args"]
    assert argv[0] == "/fake/launcher.sh"
    assert argv[1] == "alfred_comms_test"  # plugin_id
    assert argv[2] == sys.executable  # the interpreter the launcher execs
    assert argv[3] == "-m"
    assert argv[4] == "alfred_comms_test.main"  # module
    assert "DISCORD_BOT_TOKEN" not in captured["kwargs"]["env"]
    assert captured["kwargs"]["limit"] == _MAX_COMMS_LINE_BYTES


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: the assertion hardcodes a forward-slash suffix "
    "('bin/alfred-plugin-launcher.sh'), which a Windows-native path never "
    "matches; the launcher itself is a POSIX shell script irrelevant to a "
    "Windows runtime (#246 review)",
)
async def test_default_launcher_path_resolves_to_repo_bin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the env override, the launcher path points at the repo's bin/ script."""
    from alfred.plugins import comms_stdio_transport as mod

    monkeypatch.delenv("ALFRED_PLUGIN_LAUNCHER", raising=False)
    resolved = mod._comms_launcher_path()

    assert resolved.endswith("bin/alfred-plugin-launcher.sh")
    assert (mod._repo_root() / "bin").is_dir()


async def test_close_with_no_stdin_still_reaps() -> None:
    """A child whose stdin is already None is reaped without a stdin.close()."""
    proc = _FakeProc(stdout=None, stdin=None, returncode=None)
    transport = _make_transport(proc)

    await transport.close()  # must not raise on the stdin-is-None path
