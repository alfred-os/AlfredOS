"""The shared boot-handshake frames are well-formed length-prefixed frames (#443)."""

from __future__ import annotations

import json
import struct

import pytest

from alfred.security.quarantine_child import _handshake as hs
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME


def _decode(frame: bytes) -> dict[str, object]:
    length = struct.unpack(">I", frame[:4])[0]
    body = frame[4:]
    assert len(body) == length, "length prefix must equal the body length"
    return json.loads(body)


def test_hello_frame_is_wellformed_and_names_boot_hello() -> None:
    assert _decode(HELLO_FRAME) == {"jsonrpc": "2.0", "method": "boot.hello"}


def test_ready_frame_is_wellformed_and_names_boot_ready() -> None:
    assert _decode(READY_FRAME) == {"jsonrpc": "2.0", "method": "boot.ready"}


def test_hello_and_ready_are_distinct() -> None:
    assert HELLO_FRAME != READY_FRAME


def test_emit_hello_writes_hello_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """``emit_hello`` writes exactly HELLO_FRAME to the raw stdout buffer + flushes (rev-002)."""
    written: list[bytes] = []
    flushes = {"n": 0}

    class _Buf:
        def write(self, data: bytes) -> None:
            written.append(bytes(data))

        def flush(self) -> None:
            flushes["n"] += 1

    class _Stdout:
        buffer = _Buf()

    monkeypatch.setattr(hs.sys, "stdout", _Stdout())
    hs.emit_hello()
    assert written == [HELLO_FRAME]
    assert flushes["n"] == 1
