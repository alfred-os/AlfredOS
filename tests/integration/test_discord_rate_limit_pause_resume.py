"""J3 fault-injection: full 429 → pause → resume cycle (J3, #206).

Exercises the rate-limit honour path end-to-end across the real adapter outbound
pieces and the real host ``OutboundQueue``:

1. five outbound messages are submitted to the host ``OutboundQueue``;
2. the mock Discord backend returns 429 (with ``retry_after``) on the third send;
3. the real ``OutboundDispatcher`` maps it to ``_OutboundRetryable`` AND awaits
   the real ``RateLimitEmitter``, whose notification sink calls
   ``OutboundQueue.pause`` (comms-3: the pause lands before the next dispatch);
4. messages 4 and 5 stay queued during the retry-after window — the queue does
   not surface them while paused;
5. after the window the queue auto-resumes and messages 4 and 5 deliver.

The queue's ``pause`` is a real synchronous call from the sink; the test asserts
the consume blocks during the window and proceeds after auto-resume.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Mapping
from typing import Any

import pytest

from alfred.comms_mcp.outbound_queue import OutboundQueue
from alfred.comms_mcp.protocol import OutboundMessageRequest, _OutboundDelivered
from alfred.security.dlp import OutboundDlp
from plugins.alfred_discord.idempotency_store import IdempotencyStore
from plugins.alfred_discord.notifications import NOTIFY_RATE_LIMIT
from plugins.alfred_discord.outbound_dispatcher import OutboundDispatcher
from plugins.alfred_discord.outbound_handler import OutboundHandler
from plugins.alfred_discord.rate_limit_emitter import RateLimitEmitter
from tests.support.discord_mocks import DiscordMockFactory

pytestmark = pytest.mark.integration

_ADAPTER_ID = "discord"
_RETRY_AFTER = 1


class _Broker:
    def redact(self, text: str) -> str:
        return text


class _PausingSink:
    """Notification sink that calls ``OutboundQueue.pause`` on a rate-limit frame.

    Stands in for the host's ``RateLimitHandler`` — parses the adapter's
    ``adapter.rate_limit_signal`` frame and applies the real host pause.
    """

    def __init__(self, queue: OutboundQueue[OutboundMessageRequest]) -> None:
        self._queue = queue
        self.pauses: list[int] = []

    async def emit(self, frame: Mapping[str, object]) -> None:
        if frame.get("method") != NOTIFY_RATE_LIMIT:
            return  # pragma: no cover - only rate-limit frames reach this sink
        params = frame["params"]
        assert isinstance(params, Mapping)
        retry_after = int(params["retry_after_seconds"])
        self.pauses.append(retry_after)
        self._queue.pause(_ADAPTER_ID, float(retry_after))


def _request(factory_dlp: OutboundDlp, n: int) -> OutboundMessageRequest:
    return OutboundMessageRequest(
        idempotency_key=uuid.uuid4(),
        adapter_id=_ADAPTER_ID,
        target_platform_id="1001",
        body=factory_dlp.scan_for_outbound(f"reply {n}"),
        attachments_refs=(),
        addressing_mode="dm",
    )


@pytest.mark.asyncio
async def test_429_pauses_queue_then_auto_resumes(
    discord_mock_factory: DiscordMockFactory, tmp_path: Any
) -> None:
    dlp = OutboundDlp(broker=_Broker(), audit=lambda **_: None)
    audit_writer = object()
    queue: OutboundQueue[OutboundMessageRequest] = OutboundQueue(audit_writer=audit_writer)
    sink = _PausingSink(queue)

    # A resolver whose third send raises 429; all others deliver.
    call_count = {"n": 0}
    rate_limited_exc = discord_mock_factory.http_exception(status=429, retry_after=_RETRY_AFTER)

    class _Resolver:
        async def resolve(self, target_platform_id: str, addressing_mode: str) -> Any:
            call_count["n"] += 1
            if call_count["n"] == 3:
                # The third send hits a 429 — the sendable raises it.
                return discord_mock_factory.sendable(raises=rate_limited_exc)
            return discord_mock_factory.sendable(sent_id=100 + call_count["n"])

    handler = OutboundHandler(
        resolver=_Resolver(), store=IdempotencyStore(db_path=tmp_path / "idem.db")
    )
    emitter = RateLimitEmitter(adapter_id=_ADAPTER_ID, sink=sink)
    dispatcher = OutboundDispatcher(handler=handler, rate_limit_emitter=emitter)

    # Submit five messages.
    requests = [_request(dlp, n) for n in range(5)]
    for req in requests:
        await queue.submit(_ADAPTER_ID, req)

    # Dispatch the first three: #1, #2 deliver; #3 hits 429 → pause lands.
    results = []
    for _ in range(3):
        req = await queue.consume(_ADAPTER_ID)
        results.append(await dispatcher.dispatch(req))

    assert isinstance(results[0], _OutboundDelivered)
    assert isinstance(results[1], _OutboundDelivered)
    assert results[2].outcome == "retryable_failure"
    # The pause landed with the platform's retry-after.
    assert sink.pauses == [_RETRY_AFTER]

    # While paused, consuming #4 must block past a short probe window.
    consume_task = asyncio.create_task(queue.consume(_ADAPTER_ID))
    await asyncio.sleep(0.1)
    assert not consume_task.done(), "queue surfaced a message while paused"

    # After the retry-after window the queue auto-resumes; #4 and #5 deliver.
    fourth = await asyncio.wait_for(consume_task, timeout=_RETRY_AFTER + 2)
    fourth_result = await dispatcher.dispatch(fourth)
    fifth = await queue.consume(_ADAPTER_ID)
    fifth_result = await dispatcher.dispatch(fifth)
    assert isinstance(fourth_result, _OutboundDelivered)
    assert isinstance(fifth_result, _OutboundDelivered)
