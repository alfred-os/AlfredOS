"""Gate-conditional seq/ack codec in the comms transports (Spec A G2 / ADR-0032) (#237).

Drives ``CommsStdioTransport`` over in-memory streams (no subprocess) to prove
(the ``CommsSocketTransport`` mirror is added in Task 4):

* default-OFF send is byte-for-byte the existing plain ADR-0025 frame;
* negotiated-ON send carries the ``A1`` out-of-band header;
* a negotiated reader strips the header and returns the inner JSON object;
* a negotiated reader still reads a PLAIN line from an un-upgraded peer (the
  magic-gated fallback — mixed-wire safety);
* the JSON-RPC ``id`` survives the header round-trip;
* the transport emits an ``a=0`` PLACEHOLDER ack (it stores no high-water).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from alfred.cli._launcher_spawn import PluginLaunchSpec
from alfred.plugins.comms_seq_codec import SEQ_MAGIC, decode_seq_frame, encode_seq_frame
from alfred.plugins.comms_stdio_transport import CommsStdioTransport

pytestmark = pytest.mark.asyncio

_FRAME: Mapping[str, object] = {
    "jsonrpc": "2.0",
    "id": 42,
    "method": "inbound.message",
    "params": {"body": "hi"},
}


# --- stdio transport fakes -----------------------------------------------------


class _FakeStdin:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeProc:
    def __init__(
        self,
        *,
        stdout: asyncio.StreamReader | None,
        stdin: _FakeStdin | None,
    ) -> None:
        self.stdout = stdout
        self.stdin = stdin
        self.returncode: int | None = None


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


def _reader_with(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def _make_stdio(
    *, stdout: asyncio.StreamReader | None = None, stdin: _FakeStdin | None = None
) -> CommsStdioTransport:
    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec())
    transport._proc = _FakeProc(stdout=stdout, stdin=stdin)  # type: ignore[assignment]
    return transport


# ---------------------------------------------------------------------------
# stdio transport
# ---------------------------------------------------------------------------


async def test_stdio_send_off_is_plain_adr0025_bytes() -> None:
    stdin = _FakeStdin()
    transport = _make_stdio(stdin=stdin)
    await transport.send(_FRAME)
    written = bytes(stdin.buffer)
    assert written == json.dumps(_FRAME).encode() + b"\n"
    assert not written.startswith(SEQ_MAGIC)


async def test_stdio_send_on_carries_header_and_round_trips() -> None:
    stdin = _FakeStdin()
    transport = _make_stdio(stdin=stdin)
    transport.enable_seq_ack()
    await transport.send(_FRAME)
    written = bytes(stdin.buffer)
    assert written.startswith(SEQ_MAGIC)
    frame = decode_seq_frame(written)
    assert frame.seq == 0  # first send on this leg
    assert frame.ack == 0  # PLACEHOLDER, not a high-water
    assert frame.payload == json.dumps(_FRAME).encode()


async def test_stdio_send_seq_increments_per_frame() -> None:
    stdin = _FakeStdin()
    transport = _make_stdio(stdin=stdin)
    transport.enable_seq_ack()
    await transport.send(_FRAME)
    await transport.send(_FRAME)
    lines = bytes(stdin.buffer).splitlines(keepends=True)
    assert decode_seq_frame(lines[0]).seq == 0
    assert decode_seq_frame(lines[1]).seq == 1


async def test_stdio_read_decodes_seq_header_to_inner_object() -> None:
    unit = encode_seq_frame(json.dumps(_FRAME).encode(), seq=3, ack=1)
    transport = _make_stdio(stdout=_reader_with(unit))
    transport.enable_seq_ack()
    assert await transport.read_frame() == _FRAME


async def test_stdio_read_fallback_decodes_plain_line_when_enabled() -> None:
    """A negotiated reader still reads a PLAIN line from an un-upgraded peer."""
    plain = json.dumps({"id": 1}).encode() + b"\n"
    transport = _make_stdio(stdout=_reader_with(plain))
    transport.enable_seq_ack()
    assert await transport.read_frame() == {"id": 1}


async def test_stdio_read_does_not_store_recv_ack() -> None:
    """The transport carries an a=0 placeholder — no received high-water is stored."""
    unit = encode_seq_frame(json.dumps(_FRAME).encode(), seq=9, ack=4)
    transport = _make_stdio(stdout=_reader_with(unit))
    transport.enable_seq_ack()
    await transport.read_frame()
    assert not hasattr(transport, "_recv_ack")  # no high-water attribute at all
    # A subsequent send still emits a=0 (not the received seq).
    stdin = _FakeStdin()
    transport._proc.stdin = stdin  # type: ignore[union-attr]
    await transport.send(_FRAME)
    assert decode_seq_frame(bytes(stdin.buffer)).ack == 0


async def test_stdio_id_preserved_across_seq_encode_decode() -> None:
    stdin = _FakeStdin()
    sender = _make_stdio(stdin=stdin)
    sender.enable_seq_ack()
    await sender.send(_FRAME)
    reader = _make_stdio(stdout=_reader_with(bytes(stdin.buffer)))
    reader.enable_seq_ack()
    got = await reader.read_frame()
    assert got is not None and got["id"] == 42


async def test_stdio_read_over_bound_seq_unit_raises() -> None:
    """A negotiated reader enforces the per-frame bound on the whole unit."""
    from alfred.plugins.comms_wire import CommsProtocolError

    unit = encode_seq_frame(b"x" * 64, seq=0, ack=0)
    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec(), max_line_bytes=16)
    transport._proc = _FakeProc(stdout=_reader_with(unit), stdin=None)  # type: ignore[assignment]
    transport.enable_seq_ack()
    with pytest.raises(CommsProtocolError):
        await transport.read_frame()
