"""PR-S4-11c-2b0: the host-side subprocess child-IO seam (no real subprocess).

Drives :mod:`alfred.security.quarantine_child_io` against a monkeypatched
``subprocess.Popen`` + a faked ``deliver_provider_key_via_fd3`` so the spawn
discipline is asserted hermetically on macOS / non-root CI:

* the spawn is SYNCHRONOUS (``subprocess.Popen``, not
  ``asyncio.create_subprocess_exec``) so the dup2-onto-fd-3 clobber window
  contains NO ``await`` — the event loop never polls its (temporarily clobbered)
  selector fd (the docker real-spawn fd-3 regression, #237);
* the argv execs the wheel-co-located child via
  ``python -m alfred.security.quarantine_child`` (ADR-0030);
* the exec interpreter honours ``ALFRED_QUARANTINE_CHILD_PYTHON`` (the bound-
  interpreter contract) and falls back to ``sys.executable``;
* ``write_frame`` ships the raw bytes verbatim onto the child stdin (then flushes);
* ``read_frame`` returns the full frame (4-byte header + body) — the contract the
  transport's ``_decode_result_payload`` strips — and is loud on a truncated / EOF
  reply (never a silent empty frame);
* ``read_frame`` is BOUNDED (``asyncio.wait_for`` over the executor read) so a
  wedged child cannot hang the turn forever;
* the spawn dups the pipe read-end onto LITERAL fd 3 + passes ``pass_fds=(3,)``
  and calls ``deliver_provider_key_via_fd3(write_fd=, key=)``;
* the child env is SCRUBBED (built from the allowlist, never ``dict(os.environ)``)
  — an operator's exported secret never crosses in — and carries NO ``/repo``
  PYTHONPATH roots (the child ships in the wheel now, ADR-0030);
* a ``ProviderKeyDeliveryError`` REFUSES the spawn loudly
  (``QuarantineChildSpawnError``) and terminates the child;
* ``aclose`` is idempotent (terminate + reap, second call a no-op).
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import types
from typing import Any

import pytest

import alfred.security.quarantine_child_io as child_io_mod
from alfred.audit.launcher_refusal import SandboxRefusalRow
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    _SubprocessChildIO,
    spawn_quarantine_child_io,
)
from alfred.security.quarantine_transport import _decode_result_payload
from alfred.supervisor.fd3_key_delivery import ProviderKeyDeliveryError


class _FakeStdin:
    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.flushed = 0
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.append(bytes(data))

    def flush(self) -> None:
        self.flushed += 1

    def close(self) -> None:
        self.closed = True


class _FakeStdout:
    """A raw-pipe stand-in: synchronous ``read(n)`` over a length-prefixed stream.

    Returns at most ``n`` bytes per call (raw-pipe semantics — the seam's
    ``_blocking_read_exactly`` loops over short reads), and returns ``b""`` (EOF)
    when drained mid-frame so the loud-on-truncated-EOF contract is exercised.
    """

    def __init__(self, frames: list[bytes]) -> None:
        self._buf = bytearray(b"".join(frames))

    def read(self, n: int) -> bytes:
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk


class _FakeStderr:
    """A raw-pipe stderr stand-in: synchronous ``read(n)`` over a byte buffer.

    Mirrors ``_FakeStdout`` (returns at most ``n`` bytes per call, ``b""`` at EOF)
    and adds ``close()`` so the aclose stderr-pipe-close (Task 3) is observable.
    """

    def __init__(self, data: bytes = b"") -> None:
        self._buf = bytearray(data)
        self.closed = False
        self.read_calls = 0

    def read(self, n: int) -> bytes:
        self.read_calls += 1
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def close(self) -> None:
        self.closed = True


class _FakePopen:
    def __init__(self, stdout_frames: list[bytes], stderr_bytes: bytes = b"") -> None:
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(stdout_frames)
        self.stderr = _FakeStderr(stderr_bytes)
        self.returncode: int | None = None
        self.terminate_calls = 0
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:  # pragma: no cover - not exercised on the happy paths
        self.returncode = -9

    def wait(self) -> int:
        self.wait_calls += 1
        self.returncode = 0
        return 0


def _framed(body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + body


def _boot_frames() -> list[bytes]:
    """The two frames a real child emits at boot (hello + ready), for a fake stdout (#443)."""
    return [HELLO_FRAME, READY_FRAME]


@pytest.fixture
def _spawn_capture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Capture the spawn argv/env/pass_fds + the fd-3 delivery call."""
    captured: dict[str, Any] = {"proc": None, "delivery": None, "dup2": []}

    # The spawn now reads the two-frame boot handshake INSIDE itself (#443): the
    # default stdout leads with [hello, ready] so the handshake completes and the
    # returned IO's first post-spawn read is the reply.
    fake_proc = _FakePopen(
        stdout_frames=[*_boot_frames(), _framed(b'{"jsonrpc":"2.0","result":{"ok":1}}')]
    )
    captured["proc"] = fake_proc

    def _fake_popen(args: Any, *_a: Any, **kwargs: Any) -> _FakePopen:
        captured["argv"] = args
        captured["env"] = kwargs.get("env")
        captured["pass_fds"] = kwargs.get("pass_fds")
        return fake_proc

    def _fake_deliver(*, write_fd: int, key: str) -> None:
        captured["delivery"] = {"write_fd": write_fd, "key": key}

    # Record dup2(read_fd, 3) so the test proves the read-end lands on LITERAL fd 3.
    def _fake_dup2(src: int, dst: int, *a: Any, **k: Any) -> int:
        captured["dup2"].append((src, dst))
        # Do not actually dup onto fd 3 in-process (would clobber the test runner);
        # the call record is what we assert.
        return dst

    monkeypatch.setattr(child_io_mod.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(child_io_mod, "deliver_provider_key_via_fd3", _fake_deliver)
    monkeypatch.setattr(child_io_mod.os, "dup2", _fake_dup2)
    # os.pipe is real, but close the fds the seam opens so the test leaks none —
    # the seam closes the read-end after spawn + the write-end via delivery; with
    # delivery faked, ensure the write-end is closed here via a wrapper.
    real_pipe = child_io_mod.os.pipe

    def _tracking_pipe() -> tuple[int, int]:
        r, w = real_pipe()
        captured.setdefault("pipes", []).append((r, w))
        return r, w

    monkeypatch.setattr(child_io_mod.os, "pipe", _tracking_pipe)
    return captured


async def test_spawn_argv_execs_wheel_child_module(_spawn_capture: dict[str, Any]) -> None:
    """The argv execs ``<launcher> <id> <python> -m alfred.security.quarantine_child``."""
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        argv = _spawn_capture["argv"]
        assert argv[-2:] == ["-m", "alfred.security.quarantine_child"]
        # The launcher + the quarantined-LLM plugin id lead the argv.
        assert "alfred-plugin-launcher.sh" in argv[0]
        assert argv[1] == "alfred.quarantined-llm"
        # The exec interpreter (argv[2]) defaults to this process's interpreter.
        assert argv[2] == sys.executable
    finally:
        await cio.aclose()


async def test_spawn_honours_child_python_override(
    _spawn_capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ALFRED_QUARANTINE_CHILD_PYTHON`` overrides the bwrap exec interpreter.

    The bound-interpreter contract (ADR-0030): dev/CI points the child at
    ``/usr/bin/python3`` (a real binary under the policy's ``/usr`` ro-bind) with
    ``alfred`` pip-installed there, because a uv-venv ``sys.executable`` is a
    symlink outside any bound path and would fail ``execvp`` under bwrap.
    """
    monkeypatch.setenv("ALFRED_QUARANTINE_CHILD_PYTHON", "/usr/bin/python3")
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        argv = _spawn_capture["argv"]
        assert argv[2] == "/usr/bin/python3"
        assert argv[-2:] == ["-m", "alfred.security.quarantine_child"]
    finally:
        await cio.aclose()


async def test_spawn_dups_read_end_onto_fd3_and_passes_it(_spawn_capture: dict[str, Any]) -> None:
    cio = await spawn_quarantine_child_io(provider_key="sk-quarantine-key")
    try:
        # The pipe read-end was dup'd onto LITERAL fd 3.
        dup_targets = [dst for (_src, dst) in _spawn_capture["dup2"]]
        assert 3 in dup_targets
        # fd 3 was passed through to the child.
        assert _spawn_capture["pass_fds"] == (3,)
        # The provider key was delivered over the pipe write-end.
        assert _spawn_capture["delivery"] is not None
        assert _spawn_capture["delivery"]["key"] == "sk-quarantine-key"
    finally:
        await cio.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows path-separator: manifest-path forward-slash endswith check breaks under "
    "Windows backslash paths",
)
async def test_spawn_env_is_scrubbed_and_carries_no_repo_roots(
    _spawn_capture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator's exported secret never crosses + no ``/repo`` PYTHONPATH roots.

    PR-S4-11c-2b0 (ADR-0030): the child ships in the wheel, so the prior
    ``/repo/plugins`` + ``/repo/src`` PYTHONPATH roots are gone — the only env
    addition is the manifest path the launcher reads to resolve the kind=full
    policy.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-operator-secret")
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "operator-token")
    cio = await spawn_quarantine_child_io(provider_key="sk-quarantine-key")
    try:
        env = _spawn_capture["env"]
        assert isinstance(env, dict)
        assert "ANTHROPIC_API_KEY" not in env
        assert "DISCORD_BOT_TOKEN" not in env
        # The fd-3 key never lands in the env either (it crosses over fd 3 only).
        assert "sk-quarantine-key" not in repr(env)
        # No /repo PYTHONPATH roots — the child resolves off site-packages now.
        pythonpath = env.get("PYTHONPATH", "")
        assert "/plugins" not in pythonpath
        assert "/repo" not in pythonpath
        # The manifest path IS present (the launcher needs it for the policy).
        assert env["ALFRED_PLUGIN_MANIFEST_PATH"].endswith("quarantine_child/manifest.toml")
    finally:
        await cio.aclose()


async def test_write_frame_ships_bytes_verbatim_and_flushes(
    _spawn_capture: dict[str, Any],
) -> None:
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        frame = _framed(b'{"method":"quarantine.ingest"}')
        cio.write_frame(frame)
        assert _spawn_capture["proc"].stdin.written == [frame]
        # The raw pipe is flushed so the child sees the frame without buffering lag.
        assert _spawn_capture["proc"].stdin.flushed == 1
    finally:
        await cio.aclose()


async def test_read_frame_returns_full_frame_for_transport_decode(
    _spawn_capture: dict[str, Any],
) -> None:
    """read_frame returns the WHOLE frame (4-byte header + body).

    Regression (#237): it previously returned body-only, but the ChildIO contract
    is that ``QuarantineStdioTransport._decode_result_payload`` strips the header —
    and the in-test ``_EchoingChildDouble`` returns header+body. Body-only here made
    the decoder chop the first 4 JSON bytes on the REAL wire (JSONDecodeError),
    invisible on mac because the integration test uses the (correct) double.
    """
    import struct

    from alfred.security.quarantine_transport import _decode_result_payload

    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        frame = await cio.read_frame()
        body = b'{"jsonrpc":"2.0","result":{"ok":1}}'
        assert frame == struct.pack(">I", len(body)) + body
        # The contract that the bug broke: the transport decodes it cleanly.
        assert _decode_result_payload(frame) == {"ok": 1}
    finally:
        await cio.aclose()


async def test_read_frame_loud_on_truncated_eof(_spawn_capture: dict[str, Any]) -> None:
    """A truncated reply (EOF mid-frame) raises — never a silent empty body."""
    # Replace the proc's stdout with a stream that EOFs after a partial header. The
    # boot frames lead so the in-spawn handshake completes; the truncated reply is what
    # the test's own post-spawn read_frame then hits (#443).
    _spawn_capture["proc"].stdout = _FakeStdout([*_boot_frames(), b"\x00\x00"])
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()
    finally:
        await cio.aclose()


async def test_read_frame_loud_on_truncated_body_eof(_spawn_capture: dict[str, Any]) -> None:
    """A full header but a body that EOFs short raises — exercises the body read."""
    # A 4-byte header claiming 8 bytes, but only 2 body bytes before EOF. Boot frames
    # lead so the in-spawn handshake completes before the test's own read (#443).
    _spawn_capture["proc"].stdout = _FakeStdout([*_boot_frames(), struct.pack(">I", 8) + b"ab"])
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()
    finally:
        await cio.aclose()


async def test_read_frame_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A child that never replies trips the wait_for deadline (loud, not a hang).

    Constructs ``_SubprocessChildIO`` DIRECTLY rather than via the spawn: the #443
    boot handshake reads a hello inside the spawn, which a never-replying stdout would
    hang — this is a ``read_frame``-method test, not a spawn test.
    """
    # An Event the test releases in finally so the executor thread (which the
    # cancelled wait_for orphans) exits promptly rather than lingering to the
    # interpreter teardown and warning about a slow executor join.
    release = threading.Event()

    class _HangingStdout:
        def read(self, n: int) -> bytes:
            # Block the executor thread past the (shortened) deadline; the
            # wait_for cancels the future so read_frame raises loudly.
            release.wait(timeout=30)
            return b""  # pragma: no cover - the wait_for fires first

    fake: Any = _FakePopen(stdout_frames=[])  # Any: the fake carries a non-_FakeStdout stdout
    fake.stdout = _HangingStdout()
    monkeypatch.setattr(child_io_mod, "_READ_FRAME_TIMEOUT_S", 0.05)
    cio = _SubprocessChildIO(fake)  # construct directly — do NOT go through the spawn handshake
    try:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()
    finally:
        release.set()
        await cio.aclose()


async def test_provider_key_delivery_failure_refuses_spawn(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """A fd-3 delivery failure REFUSES the spawn loudly + terminates the child."""

    def _boom(*, write_fd: int, key: str) -> None:
        raise ProviderKeyDeliveryError()

    monkeypatch.setattr(child_io_mod, "deliver_provider_key_via_fd3", _boom)

    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k")

    # The half-spawned child was terminated (no leaked subprocess).
    assert _spawn_capture["proc"].terminate_calls >= 1


async def test_aclose_is_idempotent(_spawn_capture: dict[str, Any]) -> None:
    cio = await spawn_quarantine_child_io(provider_key="k")
    await cio.aclose()
    # Second close is a no-op (already reaped) — no exception, no double-terminate.
    await cio.aclose()
    assert _spawn_capture["proc"].terminate_calls <= 1


async def test_spawn_oserror_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """An OS spawn failure (missing launcher / exec error) refuses loudly."""

    def _boom_popen(args: Any, *_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("launcher missing")

    monkeypatch.setattr(child_io_mod.subprocess, "Popen", _boom_popen)
    # Faked delivery so the test never reaches it (spawn fails first).
    monkeypatch.setattr(child_io_mod, "deliver_provider_key_via_fd3", lambda **_k: None)

    with pytest.raises(QuarantineChildSpawnError):
        await spawn_quarantine_child_io(provider_key="k")


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: fd-3 dance (os.dup/dup2 literal-fd passing) is Unix subprocess mechanics",
)
async def test_spawn_without_prior_fd3_closes_installed_fd(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """When the parent has no prior fd 3, the installed dup is closed in finally.

    Forces the ``saved_fd3 is None`` else-branch by faking ``os.dup`` to raise —
    so the seam cannot save a prior fd 3 and must instead close the fd it dup'd
    onto fd 3 itself.
    """

    def _no_dup(_fd: int) -> int:
        raise OSError("no prior fd 3")

    closed: list[int] = []
    real_close = child_io_mod.os.close

    def _tracking_close(fd: int) -> None:
        closed.append(fd)
        # Do not actually close fd 3 (the faked dup2 never installed it); close
        # only real fds the seam opened.
        if fd != child_io_mod._PROVIDER_KEY_FD:
            real_close(fd)

    monkeypatch.setattr(child_io_mod.os, "dup", _no_dup)
    monkeypatch.setattr(child_io_mod.os, "close", _tracking_close)

    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        # The else-branch attempted to close the literal fd 3 it installed.
        assert child_io_mod._PROVIDER_KEY_FD in closed
    finally:
        await cio.aclose()


async def test_terminate_skips_when_child_already_exited(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """``aclose`` on an already-exited child does not call ``terminate``."""
    proc = _spawn_capture["proc"]
    cio = await spawn_quarantine_child_io(provider_key="k")
    # Mark the child as already-exited so _terminate_and_reap skips terminate().
    proc.returncode = 0
    await cio.aclose()
    assert proc.terminate_calls == 0


async def test_terminate_skips_when_poll_reports_exit(
    _spawn_capture: dict[str, Any],
) -> None:
    """``aclose`` skips ``terminate`` when ``poll()`` reports exit despite a None
    cached ``returncode`` — covers the second clause of the reap guard.
    """
    proc = _spawn_capture["proc"]
    cio = await spawn_quarantine_child_io(provider_key="k")
    # returncode stays None (the cached value), but poll() reports the child has
    # already exited — the seam must NOT re-terminate an exited child.
    proc.poll = lambda: 0  # type: ignore[method-assign]
    await cio.aclose()
    assert proc.terminate_calls == 0


def test_subprocess_child_io_satisfies_childio_protocol() -> None:
    # ChildIO is a @runtime_checkable Protocol, so issubclass is authoritative —
    # no hasattr fallback (which would pass on a partial impl). The transport
    # drives _SubprocessChildIO purely through this contract. Adding ``abort`` to
    # the Protocol (#472 finding 2) makes this assertion enforce that the real IO
    # implements it too.
    from alfred.security.quarantine_transport import ChildIO

    assert issubclass(_SubprocessChildIO, ChildIO)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals (SIGKILL) not on win32")
def test_abort_sigkills_the_child() -> None:
    """``abort()`` SIGKILLs the child. Oracle = the kernel wait status (#472 finding 2).

    ``returncode == -SIGKILL`` comes from ``waitpid``; nothing in our code produces it,
    and no internal flag (``_closed`` etc.) is consulted — the oracle is fully independent
    of the implementation predicate.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _SubprocessChildIO(proc).abort()
        proc.wait(timeout=5)
        assert proc.returncode == -signal.SIGKILL
    finally:
        proc.kill()  # no-op if already dead; never leak a 300s sleeper on assert failure


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX socketpair fd semantics not on win32")
def test_abort_closes_the_control_parent_end() -> None:
    """``abort()`` closes the brokered control-parent socket — the True arm of its guard.

    Tests B and the transport tests all construct with ``control_parent=None``; this pins
    the ``is not None`` branch so the module's 100% line+branch gate covers it. Oracle = the
    kernel fd (``fileno() == -1``), independent of any internal flag.
    """
    parent, child = socket.socketpair()
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _SubprocessChildIO(proc, control_parent=parent).abort()
        assert parent.fileno() == -1, (
            "the control-parent end survived abort() — capability not revoked"
        )
    finally:
        proc.kill()
        proc.wait(timeout=5)
        child.close()
        with contextlib.suppress(OSError):
            parent.close()


# --- #251: stderr drain helpers ---------------------------------------------


def test_sanitize_child_stderr_plain_text_passes_through() -> None:
    out = child_io_mod._sanitize_child_stderr(b"sandbox_refused reason=x", cap=4096)
    assert out == "sandbox_refused reason=x"


def test_sanitize_child_stderr_collapses_newlines_and_tabs_to_single_line() -> None:
    out = child_io_mod._sanitize_child_stderr(b"line one\n\tline two\r\nline three", cap=4096)
    # Single line, no control chars, whitespace runs collapsed to one space.
    assert out == "line one line two line three"
    assert "\n" not in out and "\r" not in out and "\t" not in out


def test_sanitize_child_stderr_defangs_ansi_escapes() -> None:
    # ESC (0x1b) is a Cc control char -> replaced; the inert "[31m"/"[0m" remain.
    out = child_io_mod._sanitize_child_stderr(b"\x1b[31mRED\x1b[0m alert", cap=4096)
    assert "\x1b" not in out
    assert out == "[31mRED [0m alert"


def test_sanitize_child_stderr_strips_bidi_and_zero_width_format_chars() -> None:
    # "Trojan Source" defense: Cf format chars (bidi overrides / isolates,
    # zero-width, BOM) are control-char-free but display-spoof a terminal, so they
    # must be stripped just like Cc controls. None may survive into the log field.
    # Built from code points (RLO/LRI/PDI/ZWSP/BOM) so no raw glyph enters the
    # source -> ruff-safe (no ambiguous-unicode lint).
    hostile = [chr(cp) for cp in (0x202E, 0x2066, 0x2069, 0x200B, 0xFEFF)]
    raw = ("admin" + "".join(hostile) + "resu ok").encode("utf-8")
    out = child_io_mod._sanitize_child_stderr(raw, cap=4096)
    assert out is not None
    for ch in hostile:
        assert ch not in out
    # Non-vacuous: the legitimate text MUST survive (guards a regression that
    # over-strips) — hostile chars removed, real diagnostic content preserved.
    assert "admin" in out and "resu ok" in out


def test_sanitize_child_stderr_non_utf8_does_not_crash() -> None:
    out = child_io_mod._sanitize_child_stderr(b"bad\xffbyte", cap=4096)
    assert out is not None
    assert "bad" in out and "byte" in out


def test_sanitize_child_stderr_empty_returns_none() -> None:
    assert child_io_mod._sanitize_child_stderr(b"", cap=4096) is None


def test_sanitize_child_stderr_all_control_returns_none() -> None:
    # Non-empty raw, but every char is control/whitespace -> collapses to "" -> None.
    assert child_io_mod._sanitize_child_stderr(b"\n\r\n\t  ", cap=4096) is None


def test_sanitize_child_stderr_truncates_over_cap_with_marker() -> None:
    out = child_io_mod._sanitize_child_stderr(b"a" * 5000, cap=4096)
    assert out is not None
    assert out.endswith(child_io_mod._STDERR_TRUNCATION_MARKER)
    assert len(out) == 4096 + len(child_io_mod._STDERR_TRUNCATION_MARKER)


def test_sanitize_child_stderr_truncated_flag_forces_marker_when_under_cap() -> None:
    # The explicit byte-overflow flag forces the marker even when the sanitized
    # char count is under cap — load-bearing for multi-byte stderr whose byte-capped
    # read decodes to fewer than `cap` chars (char-length alone would drop the marker).
    out = child_io_mod._sanitize_child_stderr(b"short line", cap=4096, truncated=True)
    assert out == "short line" + child_io_mod._STDERR_TRUNCATION_MARKER


def test_sanitize_child_stderr_not_truncated_flag_no_marker() -> None:
    out = child_io_mod._sanitize_child_stderr(b"short line", cap=4096, truncated=False)
    assert out == "short line"


def test_read_stderr_bytes_reads_all_under_cap() -> None:
    proc = types.SimpleNamespace(stderr=_FakeStderr(b"boom reason"))
    assert child_io_mod._read_stderr_bytes(proc, 4096) == b"boom reason"  # type: ignore[arg-type]


def test_read_stderr_bytes_caps_at_limit() -> None:
    proc = types.SimpleNamespace(stderr=_FakeStderr(b"x" * 100))
    assert child_io_mod._read_stderr_bytes(proc, 10) == b"x" * 10  # type: ignore[arg-type]


def test_read_stderr_bytes_no_pipe_returns_empty() -> None:
    proc = types.SimpleNamespace(stderr=None)
    assert child_io_mod._read_stderr_bytes(proc, 4096) == b""  # type: ignore[arg-type]


async def test_read_frame_failure_logs_child_stderr_when_exited(
    _spawn_capture: dict[str, Any],
) -> None:
    """A torn read_frame on an EXITED child surfaces its stderr reason (harm 1)."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    # Boot frames lead so the in-spawn handshake completes; the truncated header is what
    # the test's own post-spawn read_frame hits -> _TruncatedFrameError (#443).
    proc.stdout = _FakeStdout([*_boot_frames(), b"\x00\x00"])
    proc.stderr = _FakeStderr(b"supervisor.plugin.sandbox_refused reason=environment_not_set")
    proc.returncode = 1  # child has EXITED -> poll() gate passes, drain proceeds

    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with (
            structlog.testing.capture_logs() as logs,
            pytest.raises(QuarantineChildSpawnError),
        ):
            await cio.read_frame()
        events = [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
        assert len(events) == 1
        assert "environment_not_set" in events[0]["child_stderr"]
        # Logged at ERROR (failure=True) so error-level alerting sees it alongside
        # the read_frame_failed error it explains.
        assert events[0]["log_level"] == "error"
    finally:
        await cio.aclose()


async def test_read_frame_failure_skips_stderr_when_child_still_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wedged (still-running) child is NOT drained at the failure point (no block).

    Constructs ``_SubprocessChildIO`` DIRECTLY (the #443 in-spawn hello read would hang
    on a never-replying stdout) — this exercises the ``read_frame`` failure arm.
    """
    import structlog.testing

    release = threading.Event()

    class _HangingStdout:
        def read(self, n: int) -> bytes:
            release.wait(timeout=30)
            return b""  # pragma: no cover - the wait_for fires first

    fake: Any = _FakePopen(stdout_frames=[])  # Any: the fake carries a non-_FakeStdout stdout
    fake.stdout = _HangingStdout()
    # If the drain were ever attempted on this running child it would read this;
    # the poll()-gate must skip it (returncode stays None -> poll() is None).
    fake.stderr = _FakeStderr(b"should-not-be-read-while-running")
    monkeypatch.setattr(child_io_mod, "_READ_FRAME_TIMEOUT_S", 0.05)

    cio = _SubprocessChildIO(fake)  # construct directly — do NOT go through the spawn handshake
    try:
        with (
            structlog.testing.capture_logs() as logs,
            pytest.raises(QuarantineChildSpawnError),
        ):
            await cio.read_frame()
        # No child_stderr event at the failure point — the child is still running.
        assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
        # And the poll()-gate genuinely skipped the read — the stderr pipe was never
        # touched (proves non-drain by mechanism, not merely by log-event absence).
        assert fake.stderr.read_calls == 0
    finally:
        release.set()
        await cio.aclose()


async def test_read_frame_failure_drain_error_does_not_preempt_spawn_error(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """A best-effort drain that itself raises must NOT mask the QuarantineChildSpawnError.

    Hard rule #7 (spec §6): the diagnostic drain is best-effort — if the stderr read
    raises (e.g. an OSError on the pipe), the caller's contracted
    ``QuarantineChildSpawnError`` still propagates, and the drain failure surfaces
    LOUDLY as ``stderr_drain_failed`` (never a silent swallow, never a substituted
    exception).
    """
    import structlog.testing

    proc = _spawn_capture["proc"]
    # Boot frames lead so the in-spawn handshake completes; the truncated header is what
    # the test's own post-spawn read_frame hits -> read_frame raises (#443).
    proc.stdout = _FakeStdout([*_boot_frames(), b"\x00\x00"])
    proc.returncode = 1  # child EXITED -> drain proceeds past the poll() gate

    def _boom(_process: Any, _cap: int) -> bytes:
        raise OSError("stderr pipe read failed")

    monkeypatch.setattr(child_io_mod, "_read_stderr_bytes", _boom)

    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with (
            structlog.testing.capture_logs() as logs,
            pytest.raises(QuarantineChildSpawnError),  # the PRIMARY error still wins
        ):
            await cio.read_frame()
        failed = [e for e in logs if e["event"] == "security.quarantine_child.stderr_drain_failed"]
        assert len(failed) == 1  # loud, not silent
        # The failure CLASS is surfaced as an explicit field (NOT exc_info, which the
        # bootstrap chain renders as nothing) so an operator sees the cause.
        assert failed[0]["error_class"] == "OSError"
        assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
    finally:
        await cio.aclose()


async def test_terminate_and_reap_logs_loudly_when_reap_raises() -> None:
    """A reap (``process.wait``) that raises is logged LOUDLY, not silently swallowed.

    #414 / hard rule #7: this trust-boundary teardown previously wrapped the reap
    in a bare ``contextlib.suppress(Exception)`` with no logging — a genuine silent
    swallow. The fix surfaces ``security.quarantine_child.reap_failed`` with the
    error class (mirroring ``read_frame_failed`` / ``stderr_drain_failed``) while
    keeping teardown non-raising (best-effort).
    """
    import structlog.testing

    class _ReapBoom:
        returncode = None

        def poll(self) -> int:
            return 0  # already exited -> skip terminate(); exercise the reap arm

        def wait(self) -> int:
            raise OSError("reap boom")

    with structlog.testing.capture_logs() as logs:
        await child_io_mod._terminate_and_reap(_ReapBoom())  # type: ignore[arg-type]  # must NOT raise

    failed = [e for e in logs if e["event"] == "security.quarantine_child.reap_failed"]
    assert len(failed) == 1  # loud, not silent
    assert failed[0]["error_class"] == "OSError"


# Comfortably past both reap grace windows, but finite so the executor thread retires.
_UNREAPABLE_WAIT_S = 5.0


class _IgnoresSigterm:
    """A child that ignores SIGTERM and only dies on SIGKILL.

    Models the exact adversary case: a compromised/wedged T3 child that declines the
    polite signal. ``wait()`` blocks until ``kill()`` has been called.
    """

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False
        self._dead = threading.Event()

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True  # signal delivered, deliberately ignored

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self._dead.set()

    def wait(self) -> int:
        self._dead.wait()  # blocks until kill() lands — an unbounded wait hangs here
        return -9


async def test_terminate_and_reap_escalates_to_sigkill_when_sigterm_is_ignored() -> None:
    """A child ignoring SIGTERM must be SIGKILLed, not waited on forever.

    The teardown was SIGTERM-only with an unbounded ``process.wait()``. A T3 child that
    declines SIGTERM wedged the fail-closed path indefinitely: dispatch blew past
    ``action_deadline`` AND ``record_broker_failure`` never ran, so the very failure that
    triggered the teardown produced NO ``egress.broker.refused`` row. Escalation is what
    bounds it.
    """
    proc = _IgnoresSigterm()
    started = time.monotonic()

    await child_io_mod._terminate_and_reap(proc)  # type: ignore[arg-type]

    elapsed = time.monotonic() - started
    assert proc.terminated is True  # polite signal first
    assert proc.killed is True  # ... then escalated, because it was ignored
    assert elapsed < child_io_mod._REAP_TOTAL_GRACE_S + 1.0, (
        f"reap took {elapsed:.2f}s — the escalation did not bound it"
    )


async def test_terminate_and_reap_escalation_is_logged_loudly() -> None:
    """The SIGTERM->SIGKILL escalation is a security-relevant event, never silent (HARD #7)."""
    import structlog.testing

    with structlog.testing.capture_logs() as logs:
        await child_io_mod._terminate_and_reap(_IgnoresSigterm())  # type: ignore[arg-type]

    escalated = [
        e for e in logs if e["event"] == "security.quarantine_child.reap_escalated_sigkill"
    ]
    assert len(escalated) == 1


async def test_terminate_and_reap_surfaces_a_child_that_survives_sigkill() -> None:
    """A child that outlives SIGKILL is an OS-level anomaly — loud, and still BOUNDED.

    Only an uninterruptible (D-state) process reaches here, because SIGKILL cannot be
    caught, blocked or ignored. There is nothing left to escalate to, so the contract is:
    return anyway (never hang the fail-closed path) and say so at ERROR, leaving the
    process to the OS rather than silently pretending it was reaped.
    """
    import structlog.testing

    class _SurvivesSigkill:
        """Neither signal lands within either grace window.

        ``wait()`` outlives both windows but is NOT infinite: ``run_in_executor`` parks a
        default-pool thread that cancelling ``wait_for`` cannot interrupt, and a truly
        never-returning ``wait()`` would hang the interpreter's executor join at teardown —
        the test would wedge the suite instead of the code under test. Sleeping past the
        bound proves the same branch and lets the thread retire.
        """

        returncode = None

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            pass

        def kill(self) -> None:
            pass

        def wait(self) -> int:
            threading.Event().wait(timeout=_UNREAPABLE_WAIT_S)  # never set; returns False
            return -9

    started = time.monotonic()
    with structlog.testing.capture_logs() as logs:
        await child_io_mod._terminate_and_reap(_SurvivesSigkill())  # type: ignore[arg-type]
    elapsed = time.monotonic() - started

    assert [e for e in logs if e["event"] == "security.quarantine_child.reap_unreaped"]
    # Still returns — an unkillable child must not wedge the caller's refusal path.
    assert elapsed < child_io_mod._REAP_TOTAL_GRACE_S + 1.0


async def test_terminate_and_reap_does_not_kill_a_child_that_honours_sigterm() -> None:
    """The common path must stay a graceful SIGTERM — escalation is the exception."""

    class _Polite:
        returncode = None
        killed = False

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            pass

        def kill(self) -> None:  # pragma: no cover - asserted never reached
            _Polite.killed = True

        def wait(self) -> int:
            return 0  # exits promptly on SIGTERM

    await child_io_mod._terminate_and_reap(_Polite())  # type: ignore[arg-type]
    assert _Polite.killed is False  # no gratuitous SIGKILL on a well-behaved child


async def test_terminate_and_reap_cancelled_reap_propagates() -> None:
    """A ``CancelledError`` from the reap PROPAGATES — never demoted to a warning.

    The best-effort guard is ``except Exception`` (not ``BaseException``), so
    cooperative cancellation is honoured. Mirrors
    ``test_log_child_stderr_propagates_cancelled_error`` for the reap arm (#414).
    """
    import structlog.testing

    class _ReapCancel:
        returncode = None

        def poll(self) -> int:
            return 0

        def wait(self) -> int:
            raise asyncio.CancelledError

    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(asyncio.CancelledError),
    ):
        await child_io_mod._terminate_and_reap(_ReapCancel())  # type: ignore[arg-type]

    assert not [e for e in logs if e["event"] == "security.quarantine_child.reap_failed"]


async def test_log_child_stderr_propagates_cancelled_error(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """A CancelledError inside the drain body PROPAGATES — never swallowed.

    The best-effort guard is deliberately ``except Exception`` (not ``BaseException``)
    so cooperative cancellation is honoured. This pins the invariant against a future
    edit that broadens the catch (which would silently break task cancellation).
    """

    def _cancel(*_a: Any, **_k: Any) -> str | None:
        raise asyncio.CancelledError

    proc = _spawn_capture["proc"]
    proc.stderr = _FakeStderr(b"some stderr")  # non-empty so the sanitize call is reached
    proc.returncode = 0  # exited -> drain proceeds past the poll() gate
    # Inject the cancellation on the loop thread (at the sanitize step, inside the try
    # body) so it exercises the `except Exception` guard directly.
    monkeypatch.setattr(child_io_mod, "_sanitize_child_stderr", _cancel)

    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with pytest.raises(asyncio.CancelledError):
            await cio._log_child_stderr()
    finally:
        # Restore a benign sanitizer so aclose's own drain doesn't re-raise Cancelled.
        monkeypatch.undo()
        await cio.aclose()


async def test_log_child_stderr_read_is_bounded(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """A stderr write-end held open past child exit trips the drain deadline (no hang).

    Defence-in-depth for the ``_STDERR_DRAIN_TIMEOUT_S`` bound: if the exited child's
    stderr never reaches EOF (a broken PID-namespace assumption), the bounded read
    times out and surfaces ``stderr_drain_failed`` rather than hanging aclose forever.
    """
    import structlog.testing

    release = threading.Event()

    def _hang(_process: Any, _cap: int) -> bytes:
        release.wait(timeout=30)
        return b""  # pragma: no cover - the wait_for deadline fires first

    proc = _spawn_capture["proc"]
    proc.returncode = 0  # exited -> drain proceeds, but the read never returns
    monkeypatch.setattr(child_io_mod, "_read_stderr_bytes", _hang)
    monkeypatch.setattr(child_io_mod, "_STDERR_DRAIN_TIMEOUT_S", 0.05)

    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with structlog.testing.capture_logs() as logs:
            await cio._log_child_stderr()  # must return promptly, not hang
        failed = [e for e in logs if e["event"] == "security.quarantine_child.stderr_drain_failed"]
        assert len(failed) == 1
        assert failed[0]["error_class"] == "TimeoutError"
        # The timeout orphaned the executor thread (still holding the pipe's lock), so
        # aclose must SKIP the stderr close that would otherwise re-block on it.
        assert cio._stderr_reader_orphaned is True
        await cio.aclose()
        assert proc.stderr.closed is False  # close skipped -> left to Popen GC
    finally:
        release.set()


# --- #251: aclose drain + stderr-pipe close ---------------------------------


async def test_aclose_drains_stderr_after_reap_for_wedged_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """aclose drains the stderr the read_frame arm skipped (the wedged/timeout case).

    Constructs ``_SubprocessChildIO`` DIRECTLY (the #443 in-spawn hello read would hang
    on a never-replying stdout) — this exercises the aclose-after-wedge drain arm.
    """
    import structlog.testing

    release = threading.Event()

    class _HangingStdout:
        def read(self, n: int) -> bytes:
            release.wait(timeout=30)
            return b""  # pragma: no cover - the wait_for fires first

    fake: Any = _FakePopen(stdout_frames=[])  # Any: the fake carries a non-_FakeStdout stdout
    fake.stdout = _HangingStdout()
    fake.stderr = _FakeStderr(b"child wedged: stderr buffer full")
    monkeypatch.setattr(child_io_mod, "_READ_FRAME_TIMEOUT_S", 0.05)

    cio = _SubprocessChildIO(fake)  # construct directly — do NOT go through the spawn handshake
    with structlog.testing.capture_logs() as logs:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()  # child still "running" -> arm skips the drain
        release.set()
        await cio.aclose()  # _terminate_and_reap flips poll() -> exited -> drain runs
    events = [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
    assert len(events) == 1
    assert "buffer full" in events[0]["child_stderr"]


async def test_child_stderr_logged_at_most_once(_spawn_capture: dict[str, Any]) -> None:
    """read_frame drained+logged -> aclose does NOT re-emit (idempotency flag)."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    # Boot frames lead so the in-spawn handshake completes; the truncated frame is what
    # the test's own post-spawn read_frame hits -> read_frame raises (#443).
    proc.stdout = _FakeStdout([*_boot_frames(), b"\x00\x00"])
    proc.stderr = _FakeStderr(b"boom reason")
    proc.returncode = 1  # exited

    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()
        await cio.aclose()
    events = [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
    assert len(events) == 1  # exactly one, from read_frame; aclose is a no-op


async def test_aclose_empty_stderr_emits_no_event(_spawn_capture: dict[str, Any]) -> None:
    """A clean exit with empty stderr emits no child_stderr noise."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.returncode = 0  # exited, and the fixture stderr defaults to b""
    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        await cio.aclose()
    assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]


async def test_aclose_all_control_stderr_emits_no_event(_spawn_capture: dict[str, Any]) -> None:
    """Non-empty but all-control stderr sanitizes to None -> no event."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.stderr = _FakeStderr(b"\n\r\n\t   ")
    proc.returncode = 0
    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        await cio.aclose()
    assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]


async def test_aclose_over_cap_stderr_is_truncated_with_marker(
    _spawn_capture: dict[str, Any],
) -> None:
    """An over-cap child stderr surfaces the truncation marker (not a silent clip).

    Integration-level proof that the drain reads one byte past the log cap so
    ``_sanitize_child_stderr``'s ``…[truncated]`` marker actually fires end-to-end
    (with read-cap == log-cap it never could — a long diagnostic was silently
    clipped, exactly when the "there's more" hint matters most).
    """
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.stderr = _FakeStderr(b"x" * (child_io_mod._STDERR_LOG_CAP_BYTES + 500))
    proc.returncode = 0
    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        await cio.aclose()
    events = [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
    assert len(events) == 1
    field = events[0]["child_stderr"]
    assert field.endswith(child_io_mod._STDERR_TRUNCATION_MARKER)
    assert len(field) == child_io_mod._STDERR_LOG_CAP_BYTES + len(
        child_io_mod._STDERR_TRUNCATION_MARKER
    )
    # aclose (clean teardown, not a read_frame failure) logs at WARNING severity.
    assert events[0]["log_level"] == "warning"


async def test_aclose_over_cap_multibyte_stderr_still_marks_truncation(
    _spawn_capture: dict[str, Any],
) -> None:
    """Multi-byte over-cap stderr STILL trips the marker (the byte-overflow flag path).

    A byte-capped read of multi-byte UTF-8 decodes to FEWER than ``cap`` chars, so a
    char-length check alone would silently drop the marker. The explicit
    ``truncated`` flag (raw hit its byte cap) forces it. "€" is 3 UTF-8 bytes, so
    (cap+900 bytes) is well over the byte cap but ~1/3 the char count.
    """
    import structlog.testing

    proc = _spawn_capture["proc"]
    euro = "€".encode()  # 3 bytes / 1 char
    proc.stderr = _FakeStderr(euro * (child_io_mod._STDERR_LOG_CAP_BYTES // 3 + 300))
    proc.returncode = 0
    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        await cio.aclose()
    events = [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]
    assert len(events) == 1
    field = events[0]["child_stderr"]
    # Fewer than cap chars decoded (multi-byte), yet the marker fired via the flag.
    assert field.endswith(child_io_mod._STDERR_TRUNCATION_MARKER)
    assert len(field) < child_io_mod._STDERR_LOG_CAP_BYTES


async def test_aclose_closes_stderr_pipe(_spawn_capture: dict[str, Any]) -> None:
    """aclose closes the stderr pipe (fd hygiene) — after draining it."""
    proc = _spawn_capture["proc"]
    proc.returncode = 0
    cio = await spawn_quarantine_child_io(provider_key="k")
    await cio.aclose()
    assert proc.stderr.closed is True


async def test_aclose_with_no_stderr_pipe_is_safe(_spawn_capture: dict[str, Any]) -> None:
    """A None stderr pipe (defensive) neither crashes nor emits an event."""
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.stderr = None
    proc.returncode = 0
    cio = await spawn_quarantine_child_io(provider_key="k")
    with structlog.testing.capture_logs() as logs:
        await cio.aclose()  # must not raise AttributeError on None.close()
    assert not [e for e in logs if e["event"] == "security.quarantine_child.child_stderr"]


# ---------------------------------------------------------------------------
# _lift_above_targets — the fd-dance helper (P1d, #340). Extracted to module
# scope with injectable dup/close so the >=2-iteration branch is unit-testable
# without a real dup2-onto-3/4 (which would clobber the pytest runner). The
# fakes return monotonic non-cycling fds, mirroring the kernel's lowest-free-fd
# behaviour — a cycling fake would fabricate a double-close that can't happen.
# ---------------------------------------------------------------------------


def test_lift_above_targets_two_iterations_closes_intermediate() -> None:
    """dup(3)->4 (the OTHER target), dup(4)->7 (free): the intermediate 4 is closed
    exactly once; the caller's original (3) is NOT closed here (the spawn cleanup loop
    closes it under moved=True)."""
    closed: list[int] = []
    dups = iter([4, 7])
    usable, moved = child_io_mod._lift_above_targets(
        3, (3, 4), dup=lambda _fd: next(dups), close=closed.append
    )
    assert (usable, moved) == (7, True)
    assert closed == [4]


def test_lift_above_targets_single_iteration_closes_nothing() -> None:
    """The live control_fd=False single-target path: one dup, no intermediate — the
    ``if moved:`` TRUE arm never fires (moved is False on the only iteration)."""
    closed: list[int] = []
    usable, moved = child_io_mod._lift_above_targets(
        3, (3,), dup=lambda _fd: 7, close=closed.append
    )
    assert (usable, moved) == (7, True)
    assert closed == []


def test_lift_above_targets_no_collision_is_a_noop() -> None:
    """A source already above the target range: no dup, no close, moved False."""
    calls: list[int] = []
    usable, moved = child_io_mod._lift_above_targets(
        5, (3, 4), dup=lambda fd: calls.append(fd) or 99, close=calls.append
    )
    assert (usable, moved) == (5, False)
    assert calls == []


# ---------------------------------------------------------------------------
# #443: the host reads the two-frame boot handshake INSIDE the spawn. Built on
# ``_spawn_capture`` (its ``_tracking_pipe`` keeps fd hygiene identical to every
# sibling spawn test — core-engineer-002), swapping the fake's stdout/stderr/
# returncode per case rather than re-monkeypatching Popen/delivery/dup2 standalone.
# ---------------------------------------------------------------------------


async def test_spawn_completes_two_frame_handshake_and_returns(
    _spawn_capture: dict[str, Any],
) -> None:
    """A child that emits hello+ready lets the spawn return a live IO (#443).

    The fixture default pre-loads [hello, ready, {ok:1}]; the boot frames are consumed by
    the handshake INSIDE the spawn, so the first post-spawn read is the reply (rev-007).
    """
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        frame = await cio.read_frame()
        assert _decode_result_payload(frame) == {"ok": 1}
    finally:
        await cio.aclose()


async def test_spawn_probe_module_reads_hello_only(_spawn_capture: dict[str, Any]) -> None:
    """The probe module handshakes on hello ALONE — a second read would deadlock (§6.1).

    ``_BROKERED_PROBE_MODULE`` is not in ``_MODULES_EMITTING_READY``, so a stdout carrying
    ONLY a hello (no ready) still lets the spawn RETURN — if the host waited for a ready it
    would hit EOF and raise.
    """
    _spawn_capture["proc"].stdout = _FakeStdout([HELLO_FRAME])  # hello only, no ready
    cio = await spawn_quarantine_child_io(
        provider_key="k", child_module=child_io_mod._BROKERED_PROBE_MODULE
    )
    # SEC-001 (load-bearing): the returned probe instance MUST have proven exec via the
    # hello read. This is the §6.1 invariant — a future conditional-hello mutation that
    # returned a probe with _child_wrote_stdout False would reopen #446 on the probe path
    # while branch coverage stayed green. Assert it directly, not just "no deadlock".
    assert cio._child_wrote_stdout is True
    await cio.aclose()  # returned without a second read → no deadlock


async def test_spawn_launcher_refusal_records_row_and_refuses_boot(
    _spawn_capture: dict[str, Any],
) -> None:
    """A zero-stdout refusal at the hello read records the launcher row + raises (§9 sbx-021)."""
    import structlog.testing

    refusal_row = (
        b'{"event":"supervisor.plugin.sandbox_refused","plugin_id":"alfred.quarantined-llm",'
        b'"policy_ref":"","host_os":"linux","reason":"sandbox_block_missing",'
        b'"environment":"development"}\n'
    )
    proc = _spawn_capture["proc"]
    proc.stdout = _FakeStdout([])  # zero stdout → EOF at the hello read
    proc.stderr = _FakeStderr(refusal_row)
    proc.returncode = 0  # a refused launcher exits pre-exec
    recorded: list[tuple[SandboxRefusalRow, ...]] = []

    class _Recorder:
        async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
            recorded.append(rows)

        async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
            pass  # not exercised on this arm; here only for Protocol conformance

    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(QuarantineChildSpawnError),
    ):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=_Recorder())
    assert len(recorded) == 1
    assert recorded[0][0].reason == "sandbox_block_missing"
    # torn down via aclose (reaped; an already-exited child skips terminate)
    assert proc.wait_calls >= 1
    # te-006: the boot-handshake failure surfaces the security event with child_module
    # (structlog events do NOT reach caplog — assert via capture_logs).
    boot_failed = [
        e for e in logs if e["event"] == "security.quarantine_child.boot_handshake_failed"
    ]
    assert len(boot_failed) == 1
    assert boot_failed[0]["child_module"] == child_io_mod._CHILD_MODULE


async def test_boot_handshake_tears_down_child_on_non_contract_exit() -> None:
    """A CancelledError mid-handshake (boot cancelled) still tears the child down (#443).

    The `_await_boot_handshake` teardown must fire on EVERY abnormal exit, not only the
    contracted `QuarantineChildSpawnError`: a `read_frame` that propagates a
    `CancelledError` (a daemon boot cancelled mid-handshake — a `BaseException`, NOT an
    `Exception`, so a narrower `except QuarantineChildSpawnError`/`except Exception` would
    miss it) or any other unexpected exception must not leak the bwrap child + control
    socket. This pins the `except BaseException` teardown: the child is reaped and the
    exception propagates, while the loud `boot_handshake_failed` log stays scoped to the
    contract exception (a cancellation is not a security event).
    """
    import structlog.testing

    fake = _FakePopen(stdout_frames=[])  # returncode None -> aclose terminates+reaps

    async def _cancelled_read() -> bytes:
        raise asyncio.CancelledError

    cio = _SubprocessChildIO(fake)
    cio.read_frame = _cancelled_read  # type: ignore[method-assign]

    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(asyncio.CancelledError),  # the BaseException propagates, never demoted
    ):
        await child_io_mod._await_boot_handshake(cio, child_module=child_io_mod._CHILD_MODULE)

    # Torn down: aclose ran (terminate+reap) so the child never leaks on the cancelled path.
    assert fake.terminate_calls >= 1
    assert fake.wait_calls >= 1
    assert cio._closed is True
    # The loud security log is scoped to the contract exception — a cancellation is silent.
    assert not [e for e in logs if e["event"] == "security.quarantine_child.boot_handshake_failed"]


async def test_spawn_hello_then_no_ready_refuses_without_recording(
    _spawn_capture: dict[str, Any],
) -> None:
    """hello but no ready (a `_build_provider` death) refuses boot but records NO launcher row.

    The child proved exec with the hello (``_child_wrote_stdout`` True), so the missing
    ready is child-authored — the gate must NOT attribute it to the launcher (§3.2 row 2).
    """
    import structlog.testing

    proc = _spawn_capture["proc"]
    proc.stdout = _FakeStdout([HELLO_FRAME])  # hello, then EOF at the ready read
    proc.stderr = _FakeStderr(b"provider build crashed\n")
    proc.returncode = 1
    recorded: list[tuple[SandboxRefusalRow, ...]] = []

    class _Recorder:
        async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
            recorded.append(rows)

        async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
            pass  # not exercised on this arm; here only for Protocol conformance

    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(QuarantineChildSpawnError),
    ):
        await spawn_quarantine_child_io(provider_key="k", refusal_recorder=_Recorder())
    assert recorded == []  # child-authored → NOT recorded as a launcher refusal
    # te-006: the boot-handshake failure still surfaces the security event.
    boot_failed = [
        e for e in logs if e["event"] == "security.quarantine_child.boot_handshake_failed"
    ]
    assert len(boot_failed) == 1
    assert boot_failed[0]["child_module"] == child_io_mod._CHILD_MODULE
