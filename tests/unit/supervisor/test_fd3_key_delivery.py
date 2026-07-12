"""Provider-key fd-3 delivery (PR-S4-6 Component F — sec-3 KEYSTONE).

The Supervisor delivers the quarantined provider key to a sandboxed plugin
over fd 3: a single ``os.writev`` of a 4-byte big-endian length prefix + the
key bytes (atomic on POSIX), then closes the write end, zeroes the mutable
key buffer, and ``gc.collect()``s.

sec-3 invariants pinned here:

* The framing is ``struct.pack(">I", len) + key_bytes`` in ONE writev call.
* On EAGAIN / partial write the Supervisor REFUSES to spawn (raises
  :class:`ProviderKeyDeliveryError`) rather than delivering a truncated key.
* The mutable key ``bytearray`` is zeroed BEFORE ``gc.collect()``.
"""

from __future__ import annotations

import errno
import os
import struct
import sys
from unittest.mock import patch

import pytest

from alfred.supervisor.fd3_key_delivery import (
    ProviderKeyDeliveryError,
    deliver_provider_key_via_fd3,
)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.writev",
)
def test_delivery_writes_length_prefix_then_bytes() -> None:
    read_fd, write_fd = os.pipe()
    key = "sk-test-12345"
    key_bytes = key.encode("utf-8")
    try:
        with patch("alfred.supervisor.fd3_key_delivery.gc.collect") as mock_collect:
            deliver_provider_key_via_fd3(write_fd=write_fd, key=key)
            mock_collect.assert_called_once()
        # write_fd is closed after delivery.
        with pytest.raises(OSError):
            os.write(write_fd, b"x")
        # Framing: 4-byte big-endian length, then the key bytes.
        length_prefix = os.read(read_fd, 4)
        assert struct.unpack(">I", length_prefix)[0] == len(key_bytes)
        assert os.read(read_fd, len(key_bytes)) == key_bytes
    finally:
        os.close(read_fd)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.writev",
)
def test_delivery_uses_single_writev() -> None:
    # sec-3: the prefix + key go in ONE atomic writev, not two writes.
    read_fd, write_fd = os.pipe()
    try:
        with patch("alfred.supervisor.fd3_key_delivery.os.writev", wraps=os.writev) as mock_writev:
            deliver_provider_key_via_fd3(write_fd=write_fd, key="sk-abc")
            mock_writev.assert_called_once()
            # The iov passed carries exactly [length_prefix, key_bytes].
            _, iov = mock_writev.call_args.args
            assert len(iov) == 2
            assert struct.unpack(">I", bytes(iov[0]))[0] == len(b"sk-abc")
    finally:
        os.close(read_fd)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.writev (masked as DID NOT RAISE by the finally-block "
    "cleanup after patch() raises AttributeError) (#246 review)",
)
def test_partial_write_refuses() -> None:
    read_fd, write_fd = os.pipe()
    total = struct.calcsize(">I") + len("sk-abc")
    try:
        with patch("alfred.supervisor.fd3_key_delivery.os.writev", return_value=total - 1):
            with pytest.raises(ProviderKeyDeliveryError) as exc_info:
                deliver_provider_key_via_fd3(write_fd=write_fd, key="sk-abc")
            assert exc_info.value.reason == "provider_key_delivery_failed"
    finally:
        os.close(read_fd)
        # write_fd must be closed even on the refusal path (no fd leak).
        with pytest.raises(OSError):
            os.close(write_fd)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.writev (masked as DID NOT RAISE by the finally-block "
    "cleanup after patch() raises AttributeError) (#246 review)",
)
def test_eagain_refuses() -> None:
    read_fd, write_fd = os.pipe()
    try:
        with patch(
            "alfred.supervisor.fd3_key_delivery.os.writev",
            side_effect=BlockingIOError(errno.EAGAIN, "EAGAIN"),
        ):
            with pytest.raises(ProviderKeyDeliveryError) as exc_info:
                deliver_provider_key_via_fd3(write_fd=write_fd, key="sk-abc")
            assert exc_info.value.reason == "provider_key_delivery_failed"
    finally:
        os.close(read_fd)
        with pytest.raises(OSError):
            os.close(write_fd)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.writev",
)
def test_key_buffer_zeroed_before_gc_collect() -> None:
    # sec-3: the mutable key bytearray is zeroed BEFORE gc.collect(). The
    # implementation routes both through patchable module attributes; assert
    # the call order via a shared parent Mock's mock_calls sequence.
    from unittest.mock import Mock

    read_fd, write_fd = os.pipe()
    parent = Mock()
    try:
        with (
            patch(
                "alfred.supervisor.fd3_key_delivery._zero_buffer",
                parent.zero,
            ),
            patch(
                "alfred.supervisor.fd3_key_delivery.gc.collect",
                parent.collect,
            ),
        ):
            deliver_provider_key_via_fd3(write_fd=write_fd, key="sk-zero-canary")
        # _zero_buffer must be called before gc.collect.
        names = [c[0] for c in parent.mock_calls]
        assert names == ["zero", "collect"], names
        # The key still arrived intact on the wire (zeroing is post-write).
        length = struct.unpack(">I", os.read(read_fd, 4))[0]
        assert os.read(read_fd, length) == b"sk-zero-canary"
    finally:
        os.close(read_fd)


def test_zero_buffer_actually_zeroes() -> None:
    from alfred.supervisor.fd3_key_delivery import _zero_buffer

    buf = bytearray(b"secret-bytes")
    _zero_buffer(buf)
    assert bytes(buf) == b"\x00" * len(b"secret-bytes")


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.writev",
)
def test_delivery_does_not_retain_key_in_module_state() -> None:
    import alfred.supervisor.fd3_key_delivery as mod

    read_fd, write_fd = os.pipe()
    key = "sk-residency-canary"
    try:
        deliver_provider_key_via_fd3(write_fd=write_fd, key=key)
        for name in dir(mod):
            if name.startswith("_"):
                continue
            value = getattr(mod, name)
            if isinstance(value, str):
                assert key not in value, f"key found in module attr {name!r}"
    finally:
        os.close(read_fd)
