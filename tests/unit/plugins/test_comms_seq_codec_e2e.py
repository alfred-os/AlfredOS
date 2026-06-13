"""End-to-end negotiated seq/ack round-trip across a socket pair (Spec A G2 / ADR-0032) (#237).

A smoke test that the whole G2 surface COMPOSES: two ``CommsSocketTransport``s
over an ``asyncio`` socket pair, the gate flipped ON on both ends (simulating a
successful handshake), three frames sent host->peer, read back in FIFO order with
their ``id``s intact; the received seqs fed into a ``SeqDedupWindow`` to prove the
cumulative ack + replay-idempotency on the real wire; and a mid-stream flip-OFF to
prove mixed-wire safety (the still-ON reader reads the now-plain line).

The FIFO/ordering + dedup PROPERTIES are proven in the pure-codec property tests
(``test_comms_seq_codec.py``); this is the N=3 composition smoke, not the property.
"""

from __future__ import annotations

import asyncio
import json
import socket as _socket

import pytest

from alfred.plugins.comms_seq_codec import SEQ_MAGIC, SeqDedupWindow, decode_seq_frame
from alfred.plugins.comms_socket_transport import CommsSocketTransport

pytestmark = pytest.mark.asyncio


async def _socket_pair() -> tuple[CommsSocketTransport, CommsSocketTransport]:
    s_a, s_b = _socket.socketpair()
    reader_a, writer_a = await asyncio.open_connection(sock=s_a)
    reader_b, writer_b = await asyncio.open_connection(sock=s_b)
    host = CommsSocketTransport(adapter_id="tui", reader=reader_a, writer=writer_a)
    peer = CommsSocketTransport(adapter_id="tui", reader=reader_b, writer=writer_b)
    return host, peer


async def test_three_frames_fifo_with_ids_intact_and_dedup_window() -> None:
    host, peer = await _socket_pair()
    try:
        host.enable_seq_ack()
        peer.enable_seq_ack()

        ids = [10, 20, 30]
        for i in ids:
            await host.send({"jsonrpc": "2.0", "id": i, "method": "inbound.message"})

        # The peer reads the three inner objects in FIFO order with ids intact.
        received = [await peer.read_frame() for _ in ids]
        assert [f["id"] for f in received if f is not None] == ids

        # Feed the wire-level seqs (0,1,2 — the per-direction send counter) into a
        # SeqDedupWindow and prove cumulative_ack() == 2 + replay idempotency.
        window = SeqDedupWindow(leg="inbound")
        for seq in range(3):
            assert window.accept(seq) is True
        assert window.cumulative_ack() == 2
        for seq in range(3):
            assert window.accept(seq) is False  # replay accepts nothing new
        assert window.cumulative_ack() == 2
    finally:
        await host.close()
        await peer.close()


async def test_mixed_wire_safety_after_one_end_flips_off() -> None:
    """A still-ON reader reads a now-PLAIN line after the other end flips OFF."""
    host, peer = await _socket_pair()
    try:
        host.enable_seq_ack()
        peer.enable_seq_ack()

        # First frame carries the A1 header (both ON).
        await host.send({"jsonrpc": "2.0", "id": 1, "method": "inbound.message"})
        got = await peer.read_frame()
        assert got is not None and got["id"] == 1

        # The host "downgrades" mid-stream (e.g. a re-negotiation): its next send
        # is a plain ADR-0025 line. The peer is still ON, but decode is
        # magic-gated, so it reads the plain line without error.
        host._seq_ack_enabled = False
        await host.send({"jsonrpc": "2.0", "id": 2, "method": "inbound.message"})
        got2 = await peer.read_frame()
        assert got2 is not None and got2["id"] == 2
    finally:
        await host.close()
        await peer.close()


async def test_seq_frame_payload_is_the_verbatim_adr0025_line() -> None:
    """The header wraps the body byte-for-byte; the inner JSON is untouched."""
    host, peer = await _socket_pair()
    try:
        host.enable_seq_ack()
        msg: dict[str, object] = {"jsonrpc": "2.0", "id": 7, "method": "inbound.message"}
        await host.send(msg)
        line = await peer._reader.readline()
        assert line.startswith(SEQ_MAGIC)
        frame = decode_seq_frame(line)
        # Byte-for-byte: the carrier never re-serialises the body. The transport
        # emits ``json.dumps(frame).encode()`` (default separators), so the decoded
        # payload must equal exactly that — a substring check would not prove it.
        assert frame.payload == json.dumps(msg).encode()
    finally:
        await host.close()
        await peer.close()
