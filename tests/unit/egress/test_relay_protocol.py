"""Framed-transport envelopes + length-prefixed frame helpers (Spec C §4.2 mode-b, #333).

The core↔gateway tool-egress relay speaks a length-prefixed JSON-frame protocol
over ``asyncio.start_server`` (NOT HTTP — the architect's round-2 ruling). These
tests pin the ONE wire contract both ends share:

* the three frozen, ``extra="forbid"`` envelopes round-trip via
  ``model_dump_json()`` / ``model_validate_json()`` losslessly — including a
  binary (non-UTF-8) ``EgressResponse.body`` (web responses are arbitrary bytes);
* ``read_frame`` / ``write_frame`` round-trip a 4-byte-length-prefixed payload,
  and an over-``max_len`` frame raises BEFORE reading the body (no unbounded read).
"""

from __future__ import annotations

import asyncio

import pytest

from alfred.egress.relay_protocol import (
    EgressRelayReply,
    EgressRequest,
    EgressResponse,
    FrameTooLargeError,
    _RawToolRequest,
    read_frame,
    write_frame,
)


def test_egress_request_round_trips() -> None:
    req = EgressRequest(
        method="GET",
        url="https://api.example.com/v1/thing",
        headers={"accept": "application/json"},
        body="redacted-body",
        egress_id="a" * 64,
    )
    assert EgressRequest.model_validate_json(req.model_dump_json()) == req


def test_egress_request_rejects_unknown_field() -> None:
    with pytest.raises(ValueError, match="extra"):
        EgressRequest.model_validate_json(
            '{"method":"GET","url":"https://h/","headers":{},"body":"",'
            '"egress_id":"x","sneaky":"1"}'
        )


def test_egress_response_round_trips_binary_body() -> None:
    # Web responses are arbitrary bytes (PDFs, images, mangled UTF-8). The wire
    # representation must be byte-exact so C2 can mint a ContentHandle from the
    # EXACT bytes — a naive utf-8 decode would corrupt/raise here.
    raw = b"\xff\xfe\x00\x01binary\x80body"
    resp = EgressResponse(status=200, headers={"content-type": "application/pdf"}, body=raw)
    restored = EgressResponse.model_validate_json(resp.model_dump_json())
    assert restored.body == raw
    assert restored == resp


def test_raw_tool_request_defaults() -> None:
    # The live GET-only web.fetch consumer sends no body and is not idempotent by
    # default — in-doubt refuses unless the manifest declares idempotency (H3).
    raw = _RawToolRequest(method="GET", url="https://h/", headers={})
    assert raw.body == ""
    assert raw.idempotent is False


def test_raw_tool_request_rejects_unknown_field() -> None:
    with pytest.raises(ValueError, match="extra"):
        _RawToolRequest(method="GET", url="https://h/", headers={}, nope=1)  # type: ignore[call-arg]


def test_relay_reply_forwarded_round_trips() -> None:
    reply = EgressRelayReply(response=EgressResponse(status=200, headers={}, body=b"ok"))
    restored = EgressRelayReply.model_validate_json(reply.model_dump_json())
    assert restored.deny_reason is None
    assert restored.response is not None
    assert restored.response.body == b"ok"


def test_relay_reply_denied_round_trips() -> None:
    reply = EgressRelayReply(deny_reason="destination_not_allowlisted")
    restored = EgressRelayReply.model_validate_json(reply.model_dump_json())
    assert restored.response is None
    assert restored.deny_reason == "destination_not_allowlisted"


def test_relay_reply_rejects_unknown_deny_reason() -> None:
    # The wire boundary fails LOUD on a drifted/typoed reason: deny_reason is the
    # closed EgressRelayDenyReason, so an unknown value can't deserialise (CR review).
    with pytest.raises(ValueError, match="deny_reason"):
        EgressRelayReply.model_validate_json('{"deny_reason": "bogus_reason"}')


def test_relay_reply_rejects_both_set() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        EgressRelayReply(
            response=EgressResponse(status=200, headers={}, body=b""),
            deny_reason="dlp_redacted",
        )


def test_relay_reply_rejects_neither_set() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        EgressRelayReply()


@pytest.mark.asyncio
async def test_frame_round_trips() -> None:
    payload = b'{"hello":"world"}'
    reader, writer = _stream_pair()
    await write_frame(writer, payload)
    assert await read_frame(reader, max_len=1024) == payload


@pytest.mark.asyncio
async def test_empty_frame_round_trips() -> None:
    reader, writer = _stream_pair()
    await write_frame(writer, b"")
    assert await read_frame(reader, max_len=16) == b""


@pytest.mark.asyncio
async def test_over_max_len_frame_raises_before_reading_body() -> None:
    # A declared length exceeding max_len must raise on the prefix alone — the
    # body bytes are NEVER read (no unbounded read / memory-exhaustion).
    reader = asyncio.StreamReader()
    reader.feed_data((5).to_bytes(4, "big"))  # declares 5 bytes; NO body fed
    with pytest.raises(FrameTooLargeError):
        await read_frame(reader, max_len=4)


@pytest.mark.asyncio
async def test_truncated_prefix_raises_incomplete_read() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"\x00\x00")  # only 2 of the 4 prefix bytes
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError):
        await read_frame(reader, max_len=64)


@pytest.mark.asyncio
async def test_truncated_body_raises_incomplete_read() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data((10).to_bytes(4, "big") + b"abc")  # declares 10, supplies 3
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError):
        await read_frame(reader, max_len=64)


def _stream_pair() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A StreamReader fed by a capture-writer that round-trips written bytes back."""
    reader = asyncio.StreamReader()

    class _LoopbackWriter:
        def write(self, data: bytes) -> None:
            reader.feed_data(data)

        async def drain(self) -> None:
            return None

    return reader, _LoopbackWriter()  # type: ignore[return-value]
