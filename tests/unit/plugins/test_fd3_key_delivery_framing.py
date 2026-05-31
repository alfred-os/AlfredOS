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
