"""Tests for the shared byte-splice helper (Task 2, G7-4, Spec C §4.1, epic #333).

Pins the exact ``_pipe`` behaviour so the extraction is provably neutral:
payload-blind incremental copy, half-close on EOF, mid-splice OSError propagates,
write_eof OSError suppressed.
"""

import asyncio

import pytest

from alfred.egress.byte_splice import splice


class _CaptureWriter:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.eof = False
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buf.extend(data)

    async def drain(self) -> None:
        pass

    def write_eof(self) -> None:
        self.eof = True

    def close(self) -> None:
        self.closed = True


class _NoHalfCloseWriter(_CaptureWriter):
    """A transport that cannot half-close — ``write_eof`` raises (covered by suppress)."""

    def write_eof(self) -> None:
        raise OSError("cannot half-close")


class _ResetMidSpliceWriter(_CaptureWriter):
    """A peer that resets mid-splice — ``drain`` raises so the OSError must propagate."""

    async def drain(self) -> None:
        raise OSError("connection reset by peer")


@pytest.mark.asyncio
async def test_splice_copies_then_half_closes() -> None:
    r = asyncio.StreamReader()
    r.feed_data(b"hello")
    r.feed_eof()
    w = _CaptureWriter()
    await splice(r, w)
    assert bytes(w.buf) == b"hello"
    assert w.eof is True


@pytest.mark.asyncio
async def test_splice_write_eof_oserror_suppressed() -> None:
    r = asyncio.StreamReader()
    r.feed_eof()
    w = _NoHalfCloseWriter()
    await splice(r, w)  # must not raise


@pytest.mark.asyncio
async def test_splice_mid_splice_oserror_propagates() -> None:
    r = asyncio.StreamReader()
    r.feed_data(b"hello")
    r.feed_eof()
    w = _ResetMidSpliceWriter()
    with pytest.raises(OSError):
        await splice(r, w)
