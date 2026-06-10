"""comms-3: a 429 blocks further outbound until the signal is awaited (#206).

Closure comms-3 (MEDIUM, RateLimitSignal ordering guarantee): when a 429 fires
the Discord plugin MUST (a) await the rate-limit signal handler synchronously
BEFORE (b) any further outbound emit. No fire-and-forget. This test plants a 429,
runs the outbound dispatch loop, and asserts the rate-limit signal lands in the
sink BEFORE the next outbound send touches Discord — there is no window in which
an outbound slips out between the 429 and the pause.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from alfred.comms_mcp.protocol import OutboundMessageRequest
from alfred.security.dlp import OutboundDlp, ScannedOutboundBody
from plugins.alfred_discord.idempotency_store import IdempotencyStore
from plugins.alfred_discord.outbound_dispatcher import OutboundDispatcher
from plugins.alfred_discord.outbound_handler import OutboundHandler
from plugins.alfred_discord.rate_limit_emitter import RateLimitEmitter
from tests.support.discord_mocks import DiscordMockFactory, DiscordMockSendable

_ADAPTER = "discord"


class _StubBroker:
    def redact(self, text: str) -> str:
        return text


def _scanned(text: str) -> ScannedOutboundBody:
    dlp = OutboundDlp(broker=_StubBroker(), audit=lambda *, event, subject: None)
    return dlp.scan_for_outbound(text)


class _OrderRecordingSink:
    """Records, in one shared log, both signal frames and outbound sends."""

    def __init__(self) -> None:
        self.events: list[str] = []

    async def emit(self, frame: Mapping[str, object]) -> None:
        self.events.append(f"signal:{frame['method']}")


class _SwitchableResolver:
    """First resolve returns the 429-raising target, later ones the clean target."""

    def __init__(
        self, *, first: DiscordMockSendable, rest: DiscordMockSendable, log: list[str]
    ) -> None:
        self._first = first
        self._rest = rest
        self._log = log
        self._calls = 0

    async def resolve(self, target_platform_id: str, addressing_mode: str) -> DiscordMockSendable:
        self._calls += 1
        target = self._first if self._calls == 1 else self._rest
        # Wrap send so the dispatch order is observable in the shared log.
        original_send = target.send

        async def _logged_send(content: str) -> object:
            self._log.append("outbound:send")
            return await original_send(content)

        target.send = _logged_send  # type: ignore[method-assign]
        return target


def _request(text: str) -> OutboundMessageRequest:
    return OutboundMessageRequest(
        adapter_id=_ADAPTER,
        idempotency_key=uuid4(),
        target_platform_id="777",
        body=_scanned(text),
        attachments_refs=(),
        addressing_mode="dm",
    )


async def test_429_signal_awaited_before_next_outbound(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    sink = _OrderRecordingSink()
    rl_429 = discord_mock_factory.http_exception(status=429, retry_after=2.0)
    first = discord_mock_factory.sendable(raises=rl_429)
    rest = discord_mock_factory.sendable(sent_id=1)
    resolver = _SwitchableResolver(first=first, rest=rest, log=sink.events)
    store = IdempotencyStore(db_path=tmp_path / "idempotency.db")
    handler = OutboundHandler(resolver=resolver, store=store)
    emitter = RateLimitEmitter(adapter_id=_ADAPTER, sink=sink)
    dispatcher = OutboundDispatcher(handler=handler, rate_limit_emitter=emitter)

    # First send hits a 429; second is a fresh, clean message.
    await dispatcher.dispatch(_request("first"))
    await dispatcher.dispatch(_request("second"))

    # The 429 send happens, THEN the signal lands, THEN the next outbound send.
    # There is NO "outbound:send" event between the first send and the signal.
    first_send = sink.events.index("outbound:send")
    signal = sink.events.index("signal:adapter.rate_limit_signal")
    second_send = sink.events.index("outbound:send", first_send + 1)
    assert first_send < signal < second_send
