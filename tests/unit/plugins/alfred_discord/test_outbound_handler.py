"""``outbound_handler.handle_outbound`` → ``OutboundMessageResult`` (Task F2, #206).

The handler is the adapter's send-path. It:

* dedupes by the host-minted ``idempotency_key`` against the on-disk store
  (restart-survivable — a redelivery never double-sends);
* routes to the right Discord target per ``addressing_mode``
  (``dm`` / ``mention`` / ``channel`` / ``thread``);
* maps discord.py's send failures onto the ADR-0024
  ``OutboundMessageResult`` discriminated union (``delivered`` /
  ``retryable_failure`` / ``terminal_failure``);
* scrubs any exception detail with the in-plugin DLP-lite (sec-2) before it can
  reach the ``_OutboundTerminal.detail_redacted`` wire field.

All Discord targets/exceptions come from ``discord_mock_factory`` (closure
test-1). The send-target is resolved through an injected ``TargetResolver`` seam
so the handler is unit-testable without a live gateway.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    OutboundMessageRequest,
    _OutboundDelivered,
    _OutboundRetryable,
    _OutboundTerminal,
)
from alfred.security.dlp import OutboundDlp, ScannedOutboundBody
from plugins.alfred_discord.idempotency_store import IdempotencyStore
from plugins.alfred_discord.outbound_handler import OutboundHandler
from tests.support.discord_mocks import DiscordMockFactory, DiscordMockSendable

_ADAPTER = "discord"


class _StubBroker:
    def redact(self, text: str) -> str:
        return text


def _scanned(text: str) -> ScannedOutboundBody:
    dlp = OutboundDlp(broker=_StubBroker(), audit=lambda *, event, subject: None)
    return dlp.scan_for_outbound(text)


class _Resolver:
    """A ``TargetResolver`` double: returns the seeded sendable for any target."""

    def __init__(self, target: DiscordMockSendable) -> None:
        self.target = target
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, target_platform_id: str, addressing_mode: str) -> DiscordMockSendable:
        self.calls.append((target_platform_id, addressing_mode))
        return self.target


def _request(
    *,
    addressing_mode: str = "dm",
    target_platform_id: str = "777",
    idempotency_key: UUID | None = None,
    body_text: str = "hello",
) -> OutboundMessageRequest:
    scanned = _scanned(body_text)
    return OutboundMessageRequest(
        adapter_id=_ADAPTER,
        idempotency_key=idempotency_key or uuid4(),
        target_platform_id=target_platform_id,
        body=scanned,
        attachments_refs=(),
        addressing_mode=addressing_mode,  # type: ignore[arg-type]
    )


def _handler(tmp_path: Path, target: DiscordMockSendable) -> tuple[OutboundHandler, _Resolver]:
    store = IdempotencyStore(db_path=tmp_path / "idempotency.db")
    resolver = _Resolver(target)
    return OutboundHandler(resolver=resolver, store=store), resolver


async def test_dm_happy_path_returns_delivered(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    target = discord_mock_factory.sendable(sent_id=42)
    handler, _ = _handler(tmp_path, target)
    result = await handler.handle_outbound(_request(addressing_mode="dm"))
    assert isinstance(result, _OutboundDelivered)
    assert result.outcome == "delivered"
    assert result.platform_message_id == "42"
    assert target.sent == ["hello"]


async def test_mention_prefixes_user_mention(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    target = discord_mock_factory.sendable()
    handler, _ = _handler(tmp_path, target)
    result = await handler.handle_outbound(
        _request(addressing_mode="mention", target_platform_id="555")
    )
    assert isinstance(result, _OutboundDelivered)
    assert target.sent == ["<@555> hello"]


async def test_channel_send_bare_body(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    target = discord_mock_factory.sendable()
    handler, _ = _handler(tmp_path, target)
    result = await handler.handle_outbound(_request(addressing_mode="channel"))
    assert isinstance(result, _OutboundDelivered)
    assert target.sent == ["hello"]


async def test_thread_send(tmp_path: Path, discord_mock_factory: DiscordMockFactory) -> None:
    target = discord_mock_factory.sendable()
    handler, resolver = _handler(tmp_path, target)
    result = await handler.handle_outbound(_request(addressing_mode="thread"))
    assert isinstance(result, _OutboundDelivered)
    assert resolver.calls[-1] == ("777", "thread")


async def test_rate_limit_429_returns_retryable_rounded_up(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    exc = discord_mock_factory.http_exception(status=429, retry_after=2.5)
    target = discord_mock_factory.sendable(raises=exc)
    handler, _ = _handler(tmp_path, target)
    result = await handler.handle_outbound(_request())
    assert isinstance(result, _OutboundRetryable)
    assert result.outcome == "retryable_failure"
    assert result.retry_after_seconds == 3  # 2.5 rounded UP
    assert result.error_class == "discord_rate_limited"


async def test_server_5xx_returns_retryable_default_backoff(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    exc = discord_mock_factory.http_exception(status=500)
    target = discord_mock_factory.sendable(raises=exc)
    handler, _ = _handler(tmp_path, target)
    result = await handler.handle_outbound(_request())
    assert isinstance(result, _OutboundRetryable)
    assert result.retry_after_seconds == 5
    assert result.error_class == "discord_server_error"


async def test_forbidden_returns_terminal(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    target = discord_mock_factory.sendable(raises=discord_mock_factory.forbidden())
    handler, _ = _handler(tmp_path, target)
    result = await handler.handle_outbound(_request())
    assert isinstance(result, _OutboundTerminal)
    assert result.outcome == "terminal_failure"
    assert result.error_class == "discord_forbidden"
    assert len(result.detail_redacted) <= 256


async def test_not_found_returns_terminal(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    target = discord_mock_factory.sendable(raises=discord_mock_factory.not_found())
    handler, _ = _handler(tmp_path, target)
    result = await handler.handle_outbound(_request())
    assert isinstance(result, _OutboundTerminal)
    assert result.error_class == "discord_not_found"


class _RaisingResolver:
    """A ``TargetResolver`` double that raises the seeded exception on resolve.

    Models the live ``_BotTargetResolver.resolve`` casting a non-numeric
    ``target_platform_id`` to ``int`` and raising ``ValueError`` (L1).
    """

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def resolve(self, target_platform_id: str, addressing_mode: str) -> DiscordMockSendable:
        raise self._exc


async def test_non_numeric_target_value_error_returns_terminal(tmp_path: Path) -> None:
    # L1: a non-numeric target id makes the live resolver's ``int(...)`` raise
    # ``ValueError`` — not in the discord.py exception set — which previously
    # escaped as an uncaught crash. It must map to a terminal failure instead.
    store = IdempotencyStore(db_path=tmp_path / "idempotency.db")
    handler = OutboundHandler(
        resolver=_RaisingResolver(ValueError("invalid literal for int()")),
        store=store,
    )
    result = await handler.handle_outbound(_request(target_platform_id="not-a-snowflake"))
    assert isinstance(result, _OutboundTerminal)
    assert result.outcome == "terminal_failure"
    assert result.error_class == "discord_terminal_failure"


async def test_terminal_detail_is_dlp_scrubbed(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    # sec-2: a planted API-key-shaped secret in the exception string must NEVER
    # reach the wire detail_redacted field.
    leak = "boom sk-ABCDEFGHIJKLMNOPQRSTUVWX leaked"
    target = discord_mock_factory.sendable(raises=discord_mock_factory.forbidden())
    # Override the exception's rendered message to carry the planted secret.
    target._raises.args = (leak,)  # type: ignore[union-attr]
    handler, _ = _handler(tmp_path, target)
    result = await handler.handle_outbound(_request())
    assert isinstance(result, _OutboundTerminal)
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in result.detail_redacted


async def test_idempotency_dedup_skips_second_send(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    target = discord_mock_factory.sendable(sent_id=99)
    handler, _ = _handler(tmp_path, target)
    key = uuid4()
    first = await handler.handle_outbound(_request(idempotency_key=key))
    second = await handler.handle_outbound(_request(idempotency_key=key))
    assert isinstance(first, _OutboundDelivered)
    assert isinstance(second, _OutboundDelivered)
    assert second.platform_message_id == "99"
    # Exactly one real send — the second was served from the dedup store.
    assert len(target.sent) == 1


async def test_idempotency_dedup_survives_restart(
    tmp_path: Path, discord_mock_factory: DiscordMockFactory
) -> None:
    key = uuid4()
    target = discord_mock_factory.sendable(sent_id=99)
    handler, _ = _handler(tmp_path, target)
    await handler.handle_outbound(_request(idempotency_key=key))

    # Simulate plugin restart: a fresh store at the same path + a fresh target
    # that would EXPLODE if hit (so a re-send would fail the test loudly).
    boom = discord_mock_factory.sendable(raises=AssertionError("must not re-send"))
    restarted_store = IdempotencyStore(db_path=tmp_path / "idempotency.db")
    restarted = OutboundHandler(resolver=_Resolver(boom), store=restarted_store)
    result = await restarted.handle_outbound(_request(idempotency_key=key))
    assert isinstance(result, _OutboundDelivered)
    assert result.platform_message_id == "99"
    assert boom.sent == []


def test_cross_shape_construction_is_refused() -> None:
    # Pydantic (extra="forbid") refuses a delivered result carrying a
    # retryable-only field — field coupling is forbidden by construction.
    with pytest.raises(ValidationError):
        _OutboundDelivered(  # type: ignore[call-arg]
            outcome="delivered", platform_message_id="1", retry_after_seconds=2
        )
