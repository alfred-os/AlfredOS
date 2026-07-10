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

import struct
import sys
import threading
import types
from typing import Any

import pytest

import alfred.security.quarantine_child_io as child_io_mod
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    _SubprocessChildIO,
    spawn_quarantine_child_io,
)
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

    def read(self, n: int) -> bytes:
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def close(self) -> None:
        self.closed = True


class _FakePopen:
    def __init__(self, stdout_frames: list[bytes]) -> None:
        self.stdin = _FakeStdin()
        self.stdout = _FakeStdout(stdout_frames)
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


@pytest.fixture
def _spawn_capture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Capture the spawn argv/env/pass_fds + the fd-3 delivery call."""
    captured: dict[str, Any] = {"proc": None, "delivery": None, "dup2": []}

    fake_proc = _FakePopen(stdout_frames=[_framed(b'{"jsonrpc":"2.0","result":{"ok":1}}')])
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
    # Replace the proc's stdout with a stream that EOFs after a partial header.
    _spawn_capture["proc"].stdout = _FakeStdout([b"\x00\x00"])
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()
    finally:
        await cio.aclose()


async def test_read_frame_loud_on_truncated_body_eof(_spawn_capture: dict[str, Any]) -> None:
    """A full header but a body that EOFs short raises — exercises the body read."""
    # A 4-byte header claiming 8 bytes, but only 2 body bytes before EOF.
    _spawn_capture["proc"].stdout = _FakeStdout([struct.pack(">I", 8) + b"ab"])
    cio = await spawn_quarantine_child_io(provider_key="k")
    try:
        with pytest.raises(QuarantineChildSpawnError):
            await cio.read_frame()
    finally:
        await cio.aclose()


async def test_read_frame_is_bounded(
    monkeypatch: pytest.MonkeyPatch, _spawn_capture: dict[str, Any]
) -> None:
    """A child that never replies trips the wait_for deadline (loud, not a hang)."""
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

    _spawn_capture["proc"].stdout = _HangingStdout()
    monkeypatch.setattr(child_io_mod, "_READ_FRAME_TIMEOUT_S", 0.05)
    cio = await spawn_quarantine_child_io(provider_key="k")
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
    # drives _SubprocessChildIO purely through this contract.
    from alfred.security.quarantine_transport import ChildIO

    assert issubclass(_SubprocessChildIO, ChildIO)


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


def test_read_stderr_bytes_reads_all_under_cap() -> None:
    proc = types.SimpleNamespace(stderr=_FakeStderr(b"boom reason"))
    assert child_io_mod._read_stderr_bytes(proc, 4096) == b"boom reason"  # type: ignore[arg-type]


def test_read_stderr_bytes_caps_at_limit() -> None:
    proc = types.SimpleNamespace(stderr=_FakeStderr(b"x" * 100))
    assert child_io_mod._read_stderr_bytes(proc, 10) == b"x" * 10  # type: ignore[arg-type]


def test_read_stderr_bytes_no_pipe_returns_empty() -> None:
    proc = types.SimpleNamespace(stderr=None)
    assert child_io_mod._read_stderr_bytes(proc, 4096) == b""  # type: ignore[arg-type]
