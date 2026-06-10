"""Keystroke-batch -> InboundMessageNotification(addressing_signal='dm').

The session collects keystrokes into a batch and emits ONE
``InboundMessageNotification`` per batch with the wire-realistic shape:

* ``adapter_id == "tui"`` — the exact ``adapter_kind`` member (the host's
  ``AdapterId`` validator is exact-match, not a prefix, so a per-instance id
  like ``tui-<uuid>`` would fail validation; the wire field carries the kind);
* ``body == {"content": <text>, ...}`` — a ``Mapping`` keyed by
  ``BODY_FIELD_BY_KIND["tui"] == "content"`` (NOT a bare string), so the host
  scanner can locate the operator's typed text;
* ``addressing_signal == "dm"`` — always, the 1:1 invariant.
"""

from __future__ import annotations

import pytest
from alfred_tui.session import TuiSession

from alfred.comms_mcp.protocol import BODY_FIELD_BY_KIND, InboundMessageNotification


@pytest.mark.asyncio
async def test_keystroke_batch_emits_inbound_notification() -> None:
    emitted: list[InboundMessageNotification] = []

    async def _spy(note: InboundMessageNotification) -> None:
        emitted.append(note)

    session = TuiSession(notify=_spy)
    await session.start(adapter_id="tui")
    await session.consume_user_input("hello alfred")
    await session.flush_keystroke_batch()

    assert len(emitted) == 1
    note = emitted[0]
    assert note.adapter_id == "tui"
    assert note.body[BODY_FIELD_BY_KIND["tui"]] == "hello alfred"
    assert note.addressing_signal == "dm"
    # platform_user_id for TUI is the OS-level operator identity captured at start.
    assert note.platform_user_id


@pytest.mark.asyncio
async def test_empty_batch_does_not_emit() -> None:
    emitted: list[InboundMessageNotification] = []

    async def _spy(note: InboundMessageNotification) -> None:
        emitted.append(note)

    session = TuiSession(notify=_spy)
    await session.start(adapter_id="tui")
    await session.flush_keystroke_batch()  # nothing buffered
    assert emitted == []


@pytest.mark.asyncio
async def test_health_snapshot_reflects_started_state() -> None:
    session = TuiSession()
    snap_before = session.health_snapshot()
    assert snap_before.ok is False
    await session.start(adapter_id="tui")
    snap_after = session.health_snapshot()
    assert snap_after.ok is True
    assert snap_after.queue_depth == 0
    assert snap_after.error_count == 0


@pytest.mark.asyncio
async def test_stop_flushes_pending_buffer_count() -> None:
    session = TuiSession()
    await session.start(adapter_id="tui")
    await session.consume_user_input("partial")
    flushed = await session.stop(reason="operator")
    assert flushed == 1
    assert session.health_snapshot().queue_depth == 0
