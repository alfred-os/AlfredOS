"""The read_frame drain records launcher refusals (#433).

A refused launcher (``bin/alfred-plugin-launcher.sh``) exits BEFORE ``exec``ing
the quarantined child, so the child never produces a frame -> ``read_frame``
hits EOF -> ``_log_child_stderr(failure=True)`` drains the stderr carrying the
``sandbox_refused`` JSON row (the interception point empirically confirmed in
Task 0). This module drives that drain against a fake ``Popen`` (the
``_FakePopen`` convention from ``test_quarantine_child_io.py``) + a fake
:class:`alfred.security.sandbox_refusal_audit.SandboxRefusalRecorder`, never a
real bwrap subprocess.
"""

from __future__ import annotations

import contextlib
import os

import pytest

import alfred.security.quarantine_child_io as child_io_mod
from alfred.audit.launcher_refusal import SandboxRefusalRow
from alfred.security.quarantine_child_io import (
    QuarantineChildSpawnError,
    _SubprocessChildIO,
    spawn_quarantine_child_io,
)
from alfred.supervisor.fd3_key_delivery import ProviderKeyDeliveryError

_REFUSAL_ROW = (
    b'{"event":"supervisor.plugin.sandbox_refused","plugin_id":"alfred.quarantined-llm",'
    b'"reason":"sandbox_block_missing","environment":"development","host_os":"linux"}\n'
)


class _CapturingRecorder:
    """A ``SandboxRefusalRecorder`` double that just remembers what it was given."""

    def __init__(self) -> None:
        self.rows: list[SandboxRefusalRow] = []
        self.delivery_failures: list[str] = []  # captured plugin_ids (#444)

    async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
        self.rows.extend(rows)

    async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
        self.delivery_failures.append(plugin_id)


def _exited_fake(stderr: bytes):
    # Reuse the existing _FakePopen convention (test_quarantine_child_io.py:106):
    # empty stdout_frames -> read_frame hits EOF; preset returncode so the drain's
    # ``poll() is not None`` gate fires; stderr carries the refusal JSON.
    from tests.unit.security.test_quarantine_child_io import _FakePopen

    fake = _FakePopen(stdout_frames=[], stderr_bytes=stderr)
    fake.returncode = 1  # launcher exited (refusal) — poll() returns non-None
    return fake


def _running_fake(stderr: bytes):
    # Like ``_exited_fake`` but the launcher is STILL RUNNING: ``returncode`` stays
    # None so ``poll()`` returns None. Models a NON-refusal delivery failure (partial
    # writev / EAGAIN / other OSError with a live child — #444's domain), NOT a fast
    # refusal (which exits pre-exec). Drives the CR-2 ``poll() is None`` teardown gate.
    from tests.unit.security.test_quarantine_child_io import _FakePopen

    return _FakePopen(stdout_frames=[], stderr_bytes=stderr)  # returncode defaults to None


async def test_refusal_recorded_on_read_frame_eof() -> None:
    recorder = _CapturingRecorder()
    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW), refusal_recorder=recorder)
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == "sandbox_block_missing"


async def test_default_none_records_nothing() -> None:
    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW))  # no recorder
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    # no crash, unchanged behavior


async def _drive_epipe_spawn(fake, recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    """Drive ``spawn_quarantine_child_io`` through the fd-3 EPIPE (fast-refusal) arm.

    Fakes ``Popen`` -> ``fake``, ``deliver_provider_key_via_fd3`` -> raise
    ``ProviderKeyDeliveryError`` (the fast refusal), ``os.dup2`` -> record-only; tracks the
    real ``os.pipe`` fds so the write-end the faked delivery never closes does not leak.
    Asserts the spawn refuses fail-closed (``QuarantineChildSpawnError``).
    """
    opened: list[int] = []
    real_pipe = child_io_mod.os.pipe

    def _tracking_pipe() -> tuple[int, int]:
        r, w = real_pipe()
        opened.extend((r, w))
        return r, w

    def _boom_deliver(*, write_fd: int, key: str) -> None:
        raise ProviderKeyDeliveryError()

    monkeypatch.setattr(child_io_mod.subprocess, "Popen", lambda *a, **k: fake)
    monkeypatch.setattr(child_io_mod, "deliver_provider_key_via_fd3", _boom_deliver)
    monkeypatch.setattr(child_io_mod.os, "dup2", lambda s, d, *a, **k: d)
    monkeypatch.setattr(child_io_mod.os, "pipe", _tracking_pipe)
    try:
        with pytest.raises(QuarantineChildSpawnError):
            await spawn_quarantine_child_io(provider_key="k", refusal_recorder=recorder)
    finally:
        for fd in opened:
            with contextlib.suppress(OSError):
                os.close(fd)


async def test_fast_launcher_refusal_epipe_records_attributed_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fast (EPIPE) launcher refusal now persists its attributed row (#443 §8.4 CLOSE).

    The launcher exits PRE-``exec``, closing its inherited fd-3 read end before the parent's
    synchronous ``writev`` -> ``ProviderKeyDeliveryError`` (EPIPE) before the child exists.
    The gated drain on that arm records the launcher-authored ``sandbox_refused`` row (zero
    stdout) instead of losing it, and boot still refuses fail-closed.
    """
    recorder = _CapturingRecorder()
    await _drive_epipe_spawn(_exited_fake(_REFUSAL_ROW), recorder, monkeypatch)
    assert len(recorder.rows) == 1
    assert recorder.rows[0].reason == "sandbox_block_missing"


async def test_fast_refusal_arm_child_that_wrote_stdout_is_not_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On the EPIPE arm, ANY stdout byte means a child exec'd -> its stderr is NOT attributed.

    Closes the same forgery bypass the handshake gate closes: a (pathological) exec'd child
    that wrote a partial header then triggered EPIPE cannot forge a ``sandbox_refused`` row —
    ``_child_wrote_stdout`` is set, so the gate discards the drained stderr.
    """
    recorder = _CapturingRecorder()
    fake = _exited_fake_stdout(b"\x00\x00", _REFUSAL_ROW)  # partial header -> child wrote stdout
    await _drive_epipe_spawn(fake, recorder, monkeypatch)
    assert recorder.rows == []


async def test_fast_refusal_arm_running_child_records_delivery_failure_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#444: a STILL-RUNNING child on the delivery-failure arm is a genuine delivery
    failure -> persist the reserved provider_key_delivery_failed row, THEN tear down.

    ``poll() is None`` means the child is up (partial writev / EAGAIN), NOT a fast
    (EPIPE, exited) launcher refusal. The row is host-authored (no read_frame drive,
    no ~25s stall), the child is still terminated + reaped, and boot still refuses
    fail-closed.
    """
    recorder = _CapturingRecorder()
    fake = _running_fake(_REFUSAL_ROW)  # returncode None -> poll() is None (still running)
    await _drive_epipe_spawn(fake, recorder, monkeypatch)  # raises QuarantineChildSpawnError
    assert recorder.rows == []  # NOT the launcher-authored stderr-parse path
    assert recorder.delivery_failures == ["alfred.quarantined-llm"]  # #444 host-authored row
    assert fake.terminate_calls >= 1  # the live child was torn down (terminate)...
    assert fake.wait_calls >= 1  # ...and reaped (wait)


async def test_delivery_failure_audit_error_does_not_mask_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recorder that raises on the #444 write must NOT mask the delivery refusal.

    The primary ``QuarantineChildSpawnError`` still propagates AND the guard logs
    ``provider_key_delivery_audit_failed`` loudly (CLAUDE.md hard rule #7).

    Test-guidance override (the brief's double-``pytest.raises`` version dead-ends:
    ``_drive_epipe_spawn`` already wraps its OWN ``spawn_quarantine_child_io`` call in
    ``pytest.raises(QuarantineChildSpawnError)`` -- it is the shared EPIPE-arm driver
    every test in this module reuses -- so a SECOND outer ``pytest.raises`` here would
    have nothing to catch (the inner one already did) and fails "DID NOT RAISE" even
    though the primary error correctly still propagated up to that inner assertion).
    The "still raises fail-closed" half is therefore asserted via the helper's own
    internal ``pytest.raises``, not a redundant outer wrapper.
    """
    import structlog.testing

    class _BoomDeliveryRecorder:
        async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:  # pragma: no cover
            raise AssertionError("record() is not the #444 path")

        async def record_provider_key_delivery_failure(self, *, plugin_id: str) -> None:
            raise RuntimeError("audit down")

    recorder = _BoomDeliveryRecorder()
    with structlog.testing.capture_logs() as logs:
        await _drive_epipe_spawn(_running_fake(_REFUSAL_ROW), recorder, monkeypatch)
    failed = [
        e
        for e in logs
        if e["event"] == "security.quarantine_child.provider_key_delivery_audit_failed"
    ]
    assert len(failed) == 1  # loud, not silent
    assert failed[0]["error_class"] == "RuntimeError"


async def test_running_child_delivery_failure_without_recorder_still_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No recorder threaded -> the #444 write is a no-op, but boot still refuses fail-closed
    and the live child is still torn down (covers the ``_refusal_recorder is None`` branch)."""
    fake = _running_fake(_REFUSAL_ROW)
    await _drive_epipe_spawn(fake, None, monkeypatch)  # raises QuarantineChildSpawnError
    assert fake.terminate_calls >= 1
    assert fake.wait_calls >= 1


async def test_record_failure_does_not_mask_refusal() -> None:
    """A recorder that raises must NOT mask the ``read_frame`` refusal error.

    Test-guidance override (the brief's ``caplog``-based version is a dead
    param — structlog events do not land in ``caplog.records`` in this repo,
    see ``test_quarantine_child_io.py:643-647``): use
    ``structlog.testing.capture_logs`` and assert BOTH that the primary
    ``QuarantineChildSpawnError`` still propagates AND that the guard logs
    ``refusal_record_failed`` loudly (CLAUDE.md hard rule #7 — no silent
    swallow of a security-audit failure).
    """
    import structlog.testing

    class _BoomRecorder:
        async def record(self, rows: tuple[SandboxRefusalRow, ...]) -> None:
            raise RuntimeError("audit down")

    io = _SubprocessChildIO(_exited_fake(_REFUSAL_ROW), refusal_recorder=_BoomRecorder())
    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(QuarantineChildSpawnError),  # the PRIMARY error still wins
    ):
        await io.read_frame()
    failed = [e for e in logs if e["event"] == "security.quarantine_child.refusal_record_failed"]
    assert len(failed) == 1  # loud, not silent
    assert failed[0]["error_class"] == "RuntimeError"


async def test_clean_teardown_records_nothing() -> None:
    # stderr with no sandbox_refused row (child ran) -> aclose drains -> no record.
    recorder = _CapturingRecorder()
    fake = _exited_fake(b"some benign child log line\n")
    io = _SubprocessChildIO(fake, refusal_recorder=recorder)
    await io.aclose()
    assert recorder.rows == []


# ---------------------------------------------------------------------------
# sec-001/arch-001 (#433 follow-up): gate recording to the LAUNCHER-authored
# signal. A genuine refusal is read_frame EOF with NO frame EVER read (the
# launcher exited pre-exec, above). A crashed/wedged EXEC'D child is
# CHILD-authored stderr — a malicious child could otherwise forge a
# schema-valid sandbox_refused line and get an attributed audit row +
# fail_closed hookpoint dispatch out of it. Both cases below carry the exact
# same forged _REFUSAL_ROW in stderr but must record NOTHING.
# ---------------------------------------------------------------------------


def _exited_fake_with_frame(frame_body: bytes, stderr: bytes):
    # A real frame is read successfully ONCE (simulating a live, exec'd
    # quarantine child that produced at least one reply), then the buffer is
    # drained -> the NEXT read_frame call hits EOF mid-header. returncode is
    # preset so the drain's ``poll() is not None`` gate passes once we get
    # there (mirrors ``_exited_fake``).
    from tests.unit.security.test_quarantine_child_io import _FakePopen, _framed

    fake = _FakePopen(stdout_frames=[_framed(frame_body)], stderr_bytes=stderr)
    fake.returncode = 1
    return fake


def _exited_fake_stdout(stdout: bytes, stderr: bytes):
    # A fake whose stdout carries exactly ``stdout`` raw bytes (a partial/torn
    # frame the child wrote) then EOF; returncode preset so the drain proceeds.
    from tests.unit.security.test_quarantine_child_io import _FakePopen

    fake = _FakePopen(stdout_frames=[stdout], stderr_bytes=stderr)
    fake.returncode = 1
    return fake


async def test_post_frame_read_failure_not_recorded() -> None:
    """A crash AFTER a frame was read is CHILD-authored -- never recorded."""
    recorder = _CapturingRecorder()
    fake = _exited_fake_with_frame(b'{"jsonrpc":"2.0","result":{"ok":1}}', _REFUSAL_ROW)
    io = _SubprocessChildIO(fake, refusal_recorder=recorder)
    await io.read_frame()  # first read succeeds -> sets _child_wrote_stdout = True
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()  # buffer now empty -> EOF mid-frame (a crash)
    assert recorder.rows == []


async def test_first_turn_full_header_then_body_eof_not_recorded() -> None:
    """CR-Critical: a child that writes a valid 4-byte header then fails the BODY
    read on frame ONE is CHILD-authored -- its forged stderr row must NOT record.

    ``_child_wrote_stdout`` is set the instant the header is read (before the body),
    so the drain gate ``refusal_candidate and not self._child_wrote_stdout`` is False
    even though no full frame was ever returned. This is the exact first-turn forgery
    bypass CodeRabbit flagged.
    """
    import struct

    recorder = _CapturingRecorder()
    header_only = struct.pack(">I", 80)  # claims an 80-byte body that never arrives
    io = _SubprocessChildIO(
        _exited_fake_stdout(header_only, _REFUSAL_ROW), refusal_recorder=recorder
    )
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    assert recorder.rows == []  # child wrote stdout -> forged row suppressed


async def test_first_turn_partial_header_then_eof_not_recorded() -> None:
    """A child that writes a PARTIAL header (1-3 bytes) then EOF also wrote to
    stdout -- child-authored, forged stderr row not recorded.

    Covers the ``_TruncatedFrameError.bytes_read > 0`` arm: the header read itself
    tears mid-way, but the non-zero partial proves the child produced stdout.
    """
    recorder = _CapturingRecorder()
    io = _SubprocessChildIO(
        _exited_fake_stdout(b"\x00\x00", _REFUSAL_ROW), refusal_recorder=recorder
    )
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    assert recorder.rows == []


async def test_read_frame_timeout_not_attributed_to_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A read_frame TIMEOUT is a child-side event, NEVER a launcher refusal (CR follow-up).

    A refused launcher exits pre-``exec`` and closes stdout immediately -> a ZERO-byte
    EOF (``_TruncatedFrameError``), never a wall-clock timeout. So a ``TimeoutError``
    must not set ``refusal_candidate``, even when the child has since exited (``poll()``
    non-None) leaving a forged ``sandbox_refused`` row on stderr -- otherwise a child
    that stalls a partial header to the deadline then exits could forge an attributed
    T0 row. Here stdout blocks past a shortened deadline; stderr carries the forged row.
    """
    import threading

    import alfred.security.quarantine_child_io as child_io_mod

    release = threading.Event()

    class _HangingStdout:
        def read(self, n: int) -> bytes:
            release.wait(timeout=30)
            return b""  # pragma: no cover - the wait_for deadline fires first

    class _StderrReader:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self, n: int) -> bytes:
            chunk, self._data = self._data[:n], self._data[n:]
            return chunk

    class _TimingOutProc:
        def __init__(self) -> None:
            self.stdout = _HangingStdout()
            self.stderr = _StderrReader(_REFUSAL_ROW)
            self.returncode = 1  # child exited -> poll() non-None -> the drain proceeds

        def poll(self) -> int:
            return self.returncode

        def wait(self) -> int:
            return self.returncode

    monkeypatch.setattr(child_io_mod, "_READ_FRAME_TIMEOUT_S", 0.05)
    recorder = _CapturingRecorder()
    io = _SubprocessChildIO(_TimingOutProc(), refusal_recorder=recorder)  # type: ignore[arg-type]
    try:
        with pytest.raises(QuarantineChildSpawnError):
            await io.read_frame()
        assert recorder.rows == []  # TimeoutError -> refusal_candidate False -> not recorded
    finally:
        release.set()


async def test_launcher_authored_eof_with_no_refusal_row_records_nothing() -> None:
    """The gate passes (failure=True, no prior frame) but stderr has NO refusal row.

    Branch-coverage fill for ``_record_launcher_refusals``'s ``if rows:``: the
    gate letting a genuine pre-exec EOF through does not itself guarantee the
    stderr parses to a row -- benign launcher stderr with nothing recognisable
    must still record nothing (distinct from the child-authored-suppression
    tests above, which never even reach ``_record_launcher_refusals``).
    """
    recorder = _CapturingRecorder()
    io = _SubprocessChildIO(
        _exited_fake(b"some benign launcher log line\n"), refusal_recorder=recorder
    )
    with pytest.raises(QuarantineChildSpawnError):
        await io.read_frame()
    assert recorder.rows == []


async def test_aclose_with_refusal_row_not_recorded() -> None:
    """aclose (failure=False) never records -- not the launcher-refusal signal.

    Even though stderr carries a schema-valid ``sandbox_refused`` row and no
    frame was ever read, a clean teardown is not itself the ``read_frame``
    EOF signal the gate keys on -- only the ``read_frame`` failure arm may
    attribute a row (see the drain's ``_log_child_stderr`` docstring).
    """
    recorder = _CapturingRecorder()
    fake = _exited_fake(_REFUSAL_ROW)
    io = _SubprocessChildIO(fake, refusal_recorder=recorder)
    await io.aclose()
    assert recorder.rows == []
