"""fd-3 provider-key delivery framing contract (spec §5.3).

arch-009 fix: provider keys are NEVER passed via env vars (they would
appear in ``/proc/<pid>/environ`` and any ``ps``-style introspection).
Instead the host writes a 4-byte big-endian length prefix plus the raw
key bytes on file-descriptor 3. The subprocess reads exactly the
prefixed length, leaving an empty buffer — anything trailing on fd-3
is a protocol violation.

These tests pin the framing contract independent of the StdioTransport
implementation, so a future refactor that changes the host code can't
silently change the wire format. The StdioTransport unit tests verify
the host emits this exact frame.
"""

from __future__ import annotations

import os
import struct

import pytest


def test_fd3_key_delivery_4byte_length_prefix() -> None:
    """Host writes 4-byte big-endian length + N key bytes on fd 3 (spec §5.3).

    Round-trip: write the framed key on the writer end of a pipe, read it
    back on the reader end via ``readexactly``-style sequential reads,
    assert the unpacked length matches and the body decodes to the same
    bytes that went in. After consuming the framed bytes the pipe is
    empty — confirmed by a non-blocking ``os.read(..., 1)`` returning
    ``b""`` (the parent must close the writer before the reader checks
    for trailing bytes, otherwise the read would block).
    """
    r_fd, w_fd = os.pipe()
    try:
        key = b"sk-test-provider-key-abc123"
        header = struct.pack(">I", len(key))
        os.write(w_fd, header + key)
        # Close the writer BEFORE the trailing read — otherwise read(1)
        # would block waiting for more data. The child subprocess relies
        # on this same close-on-host-finished semantic.
        os.close(w_fd)
        w_fd = -1  # mark closed for the finally clause

        raw_header = os.read(r_fd, 4)
        length = struct.unpack(">I", raw_header)[0]
        raw_key = os.read(r_fd, length)
        trailing = os.read(r_fd, 1)

        assert length == len(key)
        assert raw_key == key
        assert trailing == b""  # buffer-emptiness invariant (spec §5.3)
    finally:
        if w_fd >= 0:
            os.close(w_fd)
        os.close(r_fd)


def test_fd3_zero_length_key_is_a_valid_frame() -> None:
    """A zero-length frame round-trips cleanly.

    Edge case — exercising the empty-body branch of the framing protocol.
    A subprocess reading the length and then ``read(0)`` must not block
    or return garbage. The host emits exactly four bytes (the header).
    """
    r_fd, w_fd = os.pipe()
    try:
        header = struct.pack(">I", 0)
        os.write(w_fd, header)
        os.close(w_fd)
        w_fd = -1

        raw_header = os.read(r_fd, 4)
        length = struct.unpack(">I", raw_header)[0]
        raw_key = os.read(r_fd, length) if length else b""

        assert length == 0
        assert raw_key == b""
    finally:
        if w_fd >= 0:
            os.close(w_fd)
        os.close(r_fd)


# ---------------------------------------------------------------------------
# CR-PR-140 F7 — ``_write_all`` short-write / EINTR retry contract.
# ---------------------------------------------------------------------------
#
# ``os.write`` on a pipe is not guaranteed to deliver the full buffer:
# a signal-interrupted or buffer-bounded write returns a short count
# (or raises ``InterruptedError``). The provider-key delivery path is a
# trust-boundary secret — a silent truncation corrupts key delivery,
# the child reads a header claiming N bytes then hits EOF when the
# parent closes the write end in ``finally``. CR on PR #140 caught the
# bare ``os.write(...)`` call as a MUST-FIX. The helper loops until the
# full frame has been written, retrying on EINTR.


def test_write_all_delivers_full_buffer_on_one_shot_write() -> None:
    """Happy path: a write that succeeds in one syscall returns cleanly."""
    from alfred.plugins.stdio_transport import _write_all

    r_fd, w_fd = os.pipe()
    try:
        data = b"a" * 1024
        _write_all(w_fd, data)
        os.close(w_fd)
        w_fd = -1

        received = b""
        while chunk := os.read(r_fd, 4096):
            received += chunk
        assert received == data
    finally:
        if w_fd >= 0:
            os.close(w_fd)
        os.close(r_fd)


def test_write_all_retries_on_short_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A short-write returning n < len(data) loops until the buffer is drained.

    Synthesises a sequence of short ``os.write`` returns via monkeypatch
    on the module-level ``os.write`` symbol the helper imports. The loop
    must concatenate the returned counts so that the final byte
    position equals ``len(data)``.
    """
    import alfred.plugins.stdio_transport as transport_mod
    from alfred.plugins.stdio_transport import _write_all

    data = b"0123456789ABCDEF"
    write_returns: list[int] = [4, 4, 4, 4]  # four short writes of 4 bytes each
    captured: list[bytes] = []

    def fake_write(fd: int, buf: memoryview | bytes) -> int:
        # memoryview slices are what the loop passes — coerce to bytes
        # for forensic comparison.
        captured.append(bytes(buf))
        return write_returns.pop(0)

    monkeypatch.setattr(transport_mod.os, "write", fake_write)  # type: ignore[attr-defined]

    _write_all(fd=999, data=data)  # fd value is irrelevant — write is monkeypatched

    # CR-140 R2 fix: previous code indexed `write_returns[i]` which the
    # fake_write closure had already drained via pop(0); dead code that
    # would IndexError if the simpler assertion below ever flipped. The
    # contract under test is that `_write_all` keeps issuing writes until
    # the full payload is delivered — captured-call-count + per-call
    # length together pin that contract without resurrecting dead state.
    total_returned = sum(min(len(c), 4) for c in captured)
    assert total_returned == len(data)
    # Each call's view should start at the correct offset.
    assert captured[0].startswith(b"0123")
    assert captured[1].startswith(b"4567")
    assert captured[2].startswith(b"89AB")
    assert captured[3].startswith(b"CDEF")


def test_write_all_retries_on_eintr(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ``InterruptedError`` (EINTR) is retried, not propagated.

    A signal-interrupted ``os.write`` before any bytes were written
    is not a delivery failure — the helper retries. CR on PR #140
    specifically called out the EINTR handling as part of the F7 fix.
    """
    import alfred.plugins.stdio_transport as transport_mod
    from alfred.plugins.stdio_transport import _write_all

    data = b"provider-key-secret"
    call_count = {"n": 0}

    def fake_write(fd: int, buf: memoryview | bytes) -> int:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise InterruptedError("EINTR")
        return len(buf)  # second call delivers everything

    monkeypatch.setattr(transport_mod.os, "write", fake_write)  # type: ignore[attr-defined]

    _write_all(fd=999, data=data)
    assert call_count["n"] == 2  # exactly one retry past the EINTR


def test_write_all_handles_empty_data() -> None:
    """An empty buffer is a valid frame — the loop body never executes.

    Defends against a future caller passing an empty key or header
    accidentally — the helper must not spin or raise on an empty input.
    """
    from alfred.plugins.stdio_transport import _write_all

    r_fd, w_fd = os.pipe()
    try:
        _write_all(w_fd, b"")
        os.close(w_fd)
        w_fd = -1
        # No bytes should have been delivered.
        assert os.read(r_fd, 1) == b""
    finally:
        if w_fd >= 0:
            os.close(w_fd)
        os.close(r_fd)
