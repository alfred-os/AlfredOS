"""In-process wire test for the G6-7-7 real-spawn discord PROBE (Spec B, #309).

The probe (``src/alfred/gateway/discord_probe.py``) is a TEST-ONLY packaged
adapter the launch-target override (Task 1) redirects ``"discord"`` to so Task 4
can spawn it for real under bwrap. It speaks the gateway adapter stdio wire:
read the ``lifecycle.start`` request, ack ``ok=True`` (NO ``seq_ack`` — plain
ADR-0025), read the fd-3 credential, emit a CONTENT-FREE ``fd3-received`` ack,
emit EXACTLY ONE scripted ``inbound.message`` carrying the scripted sentinels, then block
on stdin until EOF.

This suite drives ``_run_probe`` with an in-memory ``StreamReader`` + a fake
``read_credential`` so the wire ORDER + the content-free invariant + the
``InboundMessageNotification`` shape are pinned WITHOUT touching real fd 3, real
stdin/stdout, or a real Discord login. The order is load-bearing: a notification
emitted before the handshake ack is DROPPED host-side
(``comms_runner.py`` ``pre_handshake_frame_ignored``).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Final

import pytest

from alfred.comms_mcp.protocol import InboundMessageNotification
from alfred.gateway.discord_probe import (
    _PROBE_CONTENT,
    _PROBE_INBOUND_ID,
    _PROBE_PLATFORM_USER_ID,
    _run_probe,
)

pytestmark = pytest.mark.asyncio

# The host runner sends the lifecycle.start request with this id (comms_runner
# ``_LIFECYCLE_START_ID``); the probe must echo it back on the result frame.
_LIFECYCLE_START_ID: Final[int] = 0

# Fake, non-secret fd-3 bytes the test injects in place of a real credential. The
# content-free invariant asserts these bytes never appear in any emitted frame.
_FAKE_CREDENTIAL: Final[bytes] = b"FAKE-NOT-A-REAL-TOKEN-0123456789"


def _lifecycle_start_frame() -> bytes:
    """Encode the host's ``lifecycle.start`` request as a line-delimited frame."""
    frame = {
        "jsonrpc": "2.0",
        "id": _LIFECYCLE_START_ID,
        "method": "lifecycle.start",
        "params": {"adapter_id": "discord"},
    }
    return (json.dumps(frame) + "\n").encode()


class _RecordingWriter:
    """Records every frame the probe emits, in order."""

    def __init__(self) -> None:
        self.frames: list[dict[str, Any]] = []

    def __call__(self, frame: dict[str, Any]) -> None:
        self.frames.append(frame)


async def _drive_probe(
    *,
    feed_eof: bool = True,
) -> tuple[asyncio.StreamReader, _RecordingWriter, asyncio.Task[None]]:
    """Run ``_run_probe`` against an in-memory reader/writer; return (reader, writer, task).

    Feeds the ``lifecycle.start`` frame, then (when ``feed_eof``) closes the
    reader so the post-emit block releases and the coroutine completes.
    The reader is returned so callers can feed additional data or EOF to the
    SAME reader the running task is blocked on.
    """
    reader = asyncio.StreamReader()
    reader.feed_data(_lifecycle_start_frame())
    if feed_eof:
        reader.feed_eof()
    writer = _RecordingWriter()
    task = asyncio.create_task(_run_probe(reader, writer, read_credential=lambda: _FAKE_CREDENTIAL))
    return reader, writer, task


def _inbound_frames(writer: _RecordingWriter) -> list[dict[str, Any]]:
    return [f for f in writer.frames if f.get("method") == "inbound.message"]


def _handshake_reply(writer: _RecordingWriter) -> dict[str, Any]:
    replies = [f for f in writer.frames if f.get("id") == _LIFECYCLE_START_ID and "result" in f]
    assert len(replies) == 1, f"expected exactly one lifecycle.start reply, got {replies}"
    return replies[0]


async def test_acks_lifecycle_start_before_any_inbound() -> None:
    _reader, writer, task = await _drive_probe()
    await asyncio.wait_for(task, timeout=2.0)

    reply = _handshake_reply(writer)
    assert reply["result"]["ok"] is True
    assert reply["result"]["plugin_version"], "plugin_version must be a non-empty string"
    # Plain ADR-0025: the probe must NOT echo seq_ack (echoing it flips the host
    # version-gate ON and every subsequent host->probe frame arrives A1-wrapped).
    assert "seq_ack" not in reply["result"]

    # The ack frame index precedes every inbound.message index (ORDER is
    # load-bearing: a pre-handshake notification is dropped host-side).
    reply_index = writer.frames.index(reply)
    for frame in _inbound_frames(writer):
        assert writer.frames.index(frame) > reply_index


async def test_emits_exactly_one_valid_inbound_with_scripted_sentinels() -> None:
    _reader, writer, task = await _drive_probe()
    await asyncio.wait_for(task, timeout=2.0)

    inbound = _inbound_frames(writer)
    assert len(inbound) == 1, f"expected exactly one inbound.message, got {len(inbound)}"
    params = inbound[0]["params"]

    # Validates against the real wire model (tz-aware received_at enforced there).
    notification = InboundMessageNotification.model_validate(params)

    assert notification.adapter_id == "discord"
    assert notification.inbound_id == _PROBE_INBOUND_ID
    assert notification.platform_user_id == _PROBE_PLATFORM_USER_ID
    assert notification.body == {"content": _PROBE_CONTENT, "language": "en"}
    assert notification.sub_payload_refs == ()
    assert notification.addressing_signal == "dm"
    assert notification.received_at.tzinfo is not None
    # plain stdio carries no out-of-band wire seq.
    assert notification.wire_seq is None
    assert "wire_seq" not in params


async def test_fd3_ack_is_content_free_and_after_handshake() -> None:
    _reader, writer, task = await _drive_probe()
    await asyncio.wait_for(task, timeout=2.0)

    fd3_frames = [
        f for f in writer.frames if f.get("method") == "alfred.discord_probe/fd3_received"
    ]
    assert len(fd3_frames) == 1, "expected exactly one fd3-received ack"
    fd3 = fd3_frames[0]
    assert fd3["params"] == {"adapter_id": "discord", "received": True}

    # The fd3 ack is emitted AFTER the handshake reply.
    reply_index = writer.frames.index(_handshake_reply(writer))
    assert writer.frames.index(fd3) > reply_index

    # The fake credential bytes must appear in NO emitted frame.
    cred_text = _FAKE_CREDENTIAL.decode()
    for frame in writer.frames:
        serialised = json.dumps(frame)
        assert cred_text not in serialised, f"credential leaked into a frame: {frame}"
        assert _FAKE_CREDENTIAL not in serialised.encode()


async def test_empty_fd3_raises_and_emits_no_ack_or_inbound() -> None:
    """Empty fd-3 (EOF with no bytes) must fail closed: raise RuntimeError,
    emit NEITHER the fd3_received ack NOR any inbound.message after the
    handshake reply.  Prevents the e2e fd-3-delivery proof from passing
    vacuously when no credential was actually delivered.
    """
    reader = asyncio.StreamReader()
    reader.feed_data(_lifecycle_start_frame())
    reader.feed_eof()
    writer = _RecordingWriter()

    with pytest.raises(RuntimeError, match="fd-3 credential empty"):
        await _run_probe(reader, writer, read_credential=lambda: b"")

    # Only the handshake reply may have been written; no fd3_received or inbound.
    assert _handshake_reply(writer)  # handshake ack is fine (happened before the check)
    post_handshake = writer.frames[writer.frames.index(_handshake_reply(writer)) + 1 :]
    fd3_frames = [
        f for f in post_handshake if f.get("method") == "alfred.discord_probe/fd3_received"
    ]
    assert fd3_frames == [], f"fd3_received ack emitted on empty credential: {fd3_frames}"
    assert _inbound_frames(writer) == [], "inbound.message emitted on empty credential"


async def test_blocks_until_stdin_eof_then_completes() -> None:
    # No EOF: the probe must still be blocked on stdin AFTER emitting everything.
    reader, writer, task = await _drive_probe(feed_eof=False)

    # Let the probe handshake + emit; it must then block (task pending).
    for _ in range(5):
        await asyncio.sleep(0)
    assert _inbound_frames(writer), "probe must emit the inbound before blocking"
    assert not task.done(), "probe must block reading stdin until EOF"

    # Feed EOF to the SAME reader the blocked task is reading — proves that THIS
    # probe instance releases when ITS OWN stdin closes (not a separate instance).
    reader.feed_eof()
    await asyncio.wait_for(task, timeout=2.0)
    assert task.done()
    assert task.exception() is None
