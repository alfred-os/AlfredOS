"""MERGE-BLOCKING: the four Discord addressing modes round-trip end-to-end (J1, #206).

Drives the REAL PR-S4-9 path for each of the four addressing modes
(``dm | mention | channel | thread``):

* **inbound** — a ``discord_mock_factory`` message → the real
  ``plugins.alfred_discord.inbound_emitter.normalise`` → an
  ``InboundMessageNotification`` whose ``addressing_signal`` matches the mode →
  the real host ``process_inbound_message`` (recorded ``IdentityResolver``) →
  ``orchestrator.ingest`` records the canonical user;
* **outbound** — an ``OutboundMessageRequest`` for the mode → the real
  ``plugins.alfred_discord.outbound_handler.OutboundHandler`` → a mock-sendable
  ``channel.send`` → an ``_OutboundDelivered`` result.

This is one of the two required-status-check gates (Component K). It uses the
shared ``discord_mock_factory`` (closure test-1 — no ad-hoc Discord mocks) and a
recorded resolver so the gate is deterministic and CI-runnable.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

import pytest

from alfred.comms_mcp.inbound import ResolvedInbound, process_inbound_message
from alfred.comms_mcp.inbound_scanner import InboundContentScanner
from alfred.comms_mcp.protocol import (
    OutboundMessageRequest,
    PersonaAddressingMode,
    _OutboundDelivered,
)
from alfred.comms_mcp.sub_payload_promotion import SubPayloadPromoter
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import ContentHandle
from plugins.alfred_discord.idempotency_store import IdempotencyStore
from plugins.alfred_discord.inbound_emitter import normalise
from plugins.alfred_discord.outbound_handler import OutboundHandler

if TYPE_CHECKING:
    from plugins.alfred_discord.inbound_emitter import _MessageLike
from tests.support.discord_mocks import DiscordMockFactory

pytestmark = pytest.mark.integration

_ADAPTER_ID = "discord"
_BOT_USER_ID = 999
_LISTEN_CHANNEL = 7777


# --- recorded host dependencies --------------------------------------------


class _RecordedResolver:
    """A recorded ``IdentityResolver``: maps any platform user to a fixed identity."""

    def __init__(self) -> None:
        self.resolved: list[str] = []

    async def resolve(self, *, adapter_id: str, platform_user_id: str) -> ResolvedInbound:
        self.resolved.append(platform_user_id)
        return ResolvedInbound(
            canonical_user_id="user:alice",
            persona="alfred",
            language="en-US",
            adapter_id=adapter_id,
            display_name="Alice",
        )


class _RecordingOrchestrator:
    def __init__(self) -> None:
        self.ingested: list[dict[str, Any]] = []

    async def quarantined_extract(
        self, body: object, *, canonical_user_id: str, source_tier: str
    ) -> Any:
        from alfred.security.quarantine import Extracted, T3DerivedData

        return Extracted(
            data=T3DerivedData({"content": "ok"}), extraction_mode="native_constrained"
        )

    async def ingest(self, **kwargs: Any) -> object:
        self.ingested.append(kwargs)
        return {"ok": True}

    async def dispatch(self, ingested: object) -> None:
        return None


class _Burst:
    async def acquire(self, **_kwargs: Any) -> Any:
        from alfred.orchestrator.burst_limiter import Acquired

        return Acquired(tokens_remaining=4, waited_seconds=0.0)


class _Audit:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        subject = kwargs.get("subject", {})
        self.rows.append({**subject, **kwargs})

    async def append(self, **kwargs: Any) -> None:
        return None


class _Broker:
    def get(self, name: str) -> str:
        return "integration-pepper-32-bytes-long-ok!"

    def redact(self, text: str) -> str:
        return text


# --- mock outbound send target ---------------------------------------------


class _RecordingResolverTarget:
    """A ``TargetResolver`` returning a sendable that records the rendered content."""

    def __init__(self, factory: DiscordMockFactory) -> None:
        self._factory = factory
        self.sent: list[tuple[str, str]] = []

    async def resolve(self, target_platform_id: str, addressing_mode: PersonaAddressingMode) -> Any:
        sendable = self._factory.sendable(sent_id=314)
        outer = self

        class _Recording:
            async def send(self, content: str) -> Any:
                outer.sent.append((addressing_mode, content))
                return await sendable.send(content)

        return _Recording()


def _inbound_message(factory: DiscordMockFactory, mode: PersonaAddressingMode) -> Any:
    author = factory.user(user_id=1001)
    if mode == "dm":
        return factory.message(author=author, channel=factory.dm_channel(), content="hi")
    if mode == "thread":
        return factory.message(
            author=author, channel=factory.thread_channel(), content="hi in thread"
        )
    if mode == "mention":
        bot = factory.user(user_id=_BOT_USER_ID)
        channel = factory.channel(channel_id=_LISTEN_CHANNEL)
        return factory.message(author=author, channel=channel, content="hey", mentions=[bot])
    # channel: a listened text channel, no mention.
    return factory.message(
        author=author,
        channel=factory.channel(channel_id=_LISTEN_CHANNEL),
        content="channel msg",
    )


@pytest.mark.parametrize("mode", ["dm", "mention", "channel", "thread"])
@pytest.mark.asyncio
async def test_addressing_mode_inbound_round_trip(
    discord_mock_factory: DiscordMockFactory, mode: PersonaAddressingMode
) -> None:
    message = _inbound_message(discord_mock_factory, mode)
    notification = normalise(
        cast("_MessageLike", message),
        adapter_id=_ADAPTER_ID,
        bot_user_id=_BOT_USER_ID,
        channel_listen_set=frozenset({_LISTEN_CHANNEL}),
    )
    assert notification is not None
    # Inbound assertion: the wire frame's addressing_signal matches the mode.
    assert notification.addressing_signal == mode

    resolver = _RecordedResolver()
    orchestrator = _RecordingOrchestrator()
    promoter = SubPayloadPromoter(
        adapter_kind="discord", scanner=InboundContentScanner(), content_store=_NoStore()
    )
    await process_inbound_message(
        notification,
        identity_resolver=resolver,
        orchestrator=orchestrator,
        burst_limiter=_Burst(),
        audit_writer=_Audit(),
        secret_broker=_Broker(),
        sub_payload_promoter=promoter,
    )
    # The host resolved the platform user and ingested the canonical identity.
    assert resolver.resolved == [str(message.author.id)]
    assert orchestrator.ingested[0]["canonical_user_id"] == "user:alice"
    assert orchestrator.ingested[0]["addressing_signal"] == mode


@pytest.mark.parametrize("mode", ["dm", "mention", "channel", "thread"])
@pytest.mark.asyncio
async def test_addressing_mode_outbound_round_trip(
    discord_mock_factory: DiscordMockFactory, mode: PersonaAddressingMode, tmp_path: Any
) -> None:
    dlp = OutboundDlp(broker=_Broker(), audit=lambda **_: None)
    target = _RecordingResolverTarget(discord_mock_factory)
    handler = OutboundHandler(
        resolver=target,
        store=IdempotencyStore(db_path=tmp_path / f"idem-{mode}.db"),
    )
    request = OutboundMessageRequest(
        idempotency_key=uuid.uuid4(),
        adapter_id=_ADAPTER_ID,
        target_platform_id="1001",
        body=dlp.scan_for_outbound("persona reply"),
        attachments_refs=(),
        addressing_mode=mode,
    )
    result = await handler.handle_outbound(request)

    # Outbound assertion: delivered, and the send was routed for this mode.
    assert isinstance(result, _OutboundDelivered)
    assert result.outcome == "delivered"
    assert target.sent[0][0] == mode
    # The mention mode prefixes the @user; others send the body verbatim.
    if mode == "mention":
        assert target.sent[0][1].startswith("<@1001> ")
    else:
        assert target.sent[0][1] == "persona reply"


class _NoStore:
    """Content store stub for the addressing path (plain messages, no sub-payloads)."""

    async def write(
        self, *, handle_id: str, body: bytes, source_url: str
    ) -> ContentHandle:  # pragma: no cover - no sub-payloads in these bodies
        return ContentHandle(
            id=handle_id, source_url=source_url, fetch_timestamp=datetime.now(tz=UTC)
        )
