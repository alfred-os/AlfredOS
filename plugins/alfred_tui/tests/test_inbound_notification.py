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
async def test_failed_notify_preserves_buffer_and_counts_error() -> None:
    """A failed inbound emit must NOT drop the operator's buffered input.

    PR-S4-10 review #2: the batch was cleared (and ``last_inbound_at`` stamped)
    before awaiting ``_notify``, so a notify failure silently lost the keystroke
    batch and reported a false-successful inbound. The session must keep the
    buffer intact, count the error, leave ``last_inbound_at`` unchanged, and
    re-raise loudly (no silent drop) — so a retry can re-flush the same text.
    """

    class _BoomError(RuntimeError):
        pass

    async def _failing(_note: InboundMessageNotification) -> None:
        raise _BoomError("notify sink down")

    session = TuiSession(notify=_failing)
    await session.start(adapter_id="tui")
    await session.consume_user_input("dont lose me")

    with pytest.raises(_BoomError):
        await session.flush_keystroke_batch()

    snap = session.health_snapshot()
    assert snap.queue_depth == 1, "buffered input was dropped on a failed notify"
    assert snap.error_count == 1, "failed notify was not counted as an error"
    assert snap.last_inbound_at is None, "failed notify stamped a false inbound time"


@pytest.mark.asyncio
async def test_buffer_survives_failed_notify_and_reflushes_on_retry() -> None:
    """After a failed emit the SAME buffered text re-flushes once the sink recovers."""
    calls: list[InboundMessageNotification] = []
    fail_next = {"on": True}

    async def _flaky(note: InboundMessageNotification) -> None:
        if fail_next["on"]:
            fail_next["on"] = False
            raise RuntimeError("transient sink failure")
        calls.append(note)

    session = TuiSession(notify=_flaky)
    await session.start(adapter_id="tui")
    await session.consume_user_input("retry me")

    with pytest.raises(RuntimeError):
        await session.flush_keystroke_batch()
    # sink recovered — the preserved buffer re-flushes the identical text.
    await session.flush_keystroke_batch()

    assert len(calls) == 1
    assert calls[0].body[BODY_FIELD_BY_KIND["tui"]] == "retry me"
    assert session.health_snapshot().queue_depth == 0


@pytest.mark.asyncio
async def test_reflush_reuses_inbound_id_then_new_batch_gets_fresh_id() -> None:
    """A buffered re-flush MUST carry the SAME ``inbound_id`` as the failed emit.

    ``TuiSession`` is a buffering emitter: a failed notify keeps the buffer and a
    retry re-flushes the SAME operator input. Minting a fresh ``inbound_id`` per
    flush would make the host idempotency ledger see the retry as a NEW frame and
    dispatch the operator's message TWICE. The id is the per-batch dedup key, so a
    re-flush of the same batch reuses it; only a fresh batch (after a successful
    flush cleared the buffer) gets a new id.
    """
    seen: list[InboundMessageNotification] = []
    fail_next = {"on": True}

    async def _flaky_then_capture(note: InboundMessageNotification) -> None:
        if fail_next["on"]:
            fail_next["on"] = False
            seen.append(note)  # capture the id minted on the FAILED emit
            raise RuntimeError("transient sink failure")
        seen.append(note)

    session = TuiSession(notify=_flaky_then_capture)
    await session.start(adapter_id="tui")
    await session.consume_user_input("retry me")

    with pytest.raises(RuntimeError):
        await session.flush_keystroke_batch()
    await session.flush_keystroke_batch()  # sink recovered — re-flush

    assert len(seen) == 2
    failed_id, retry_id = seen[0].inbound_id, seen[1].inbound_id
    assert retry_id == failed_id, "re-flush of the same buffered batch changed inbound_id"

    # A genuinely new batch (after the successful flush cleared the buffer) must
    # mint a FRESH id, so distinct frames stay distinct to the host ledger.
    await session.consume_user_input("a new line")
    await session.flush_keystroke_batch()
    assert len(seen) == 3
    assert seen[2].inbound_id != failed_id, "a fresh batch reused a stale inbound_id"


@pytest.mark.asyncio
async def test_stop_flushes_pending_buffer_count() -> None:
    session = TuiSession()
    await session.start(adapter_id="tui")
    await session.consume_user_input("partial")
    flushed = await session.stop(reason="operator")
    assert flushed == 1
    assert session.health_snapshot().queue_depth == 0
