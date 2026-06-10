"""``lifecycle.start`` / ``lifecycle.stop`` / ``adapter.health`` handlers (Task C2).

The lifecycle handlers authenticate via ``SecretBroker.get("discord_bot_token")``
(never reading the token from env directly), open the Discord WSS through an
injected gateway seam (mocked here; the real ``discord.Client`` wiring lands in
Wave 3's ``discord_gateway.py``), and report the ADR-0024 protocol-model results.

The token is NEVER logged: a dedicated test asserts no structlog event carries
the secret bytes.
"""

from __future__ import annotations

import pytest

from alfred.comms_mcp.protocol import HealthReport, LifecycleStartResult, LifecycleStopResult
from plugins.alfred_discord.lifecycle import DiscordLifecycle, GatewayError


class _FakeGateway:
    """Injected stand-in for the Wave-3 discord.Client WSS wrapper."""

    def __init__(self, *, fail_connect: bool = False) -> None:
        self.connected_with: str | None = None
        self.closed = False
        self.flushed = 7
        self._fail_connect = fail_connect

    async def connect(self, token: str) -> None:
        if self._fail_connect:
            raise GatewayError("bad credentials")
        self.connected_with = token

    async def close(self) -> int:
        self.closed = True
        return self.flushed

    @property
    def queue_depth(self) -> int:
        return 3


class _FakeBroker:
    def __init__(self, token: str = "tok-secret-123") -> None:  # noqa: S107 -- fabricated test token, not a credential
        self._token = token
        self.get_calls: list[str] = []

    def get(self, name: str) -> str:
        self.get_calls.append(name)
        return self._token


@pytest.mark.asyncio
async def test_start_authenticates_via_broker_and_opens_gateway() -> None:
    gateway = _FakeGateway()
    broker = _FakeBroker(token="tok-abc")  # noqa: S106 -- fabricated test token, not a credential
    lifecycle = DiscordLifecycle(broker=broker, gateway=gateway)

    result = await lifecycle.start()

    assert broker.get_calls == ["discord_bot_token"]
    assert gateway.connected_with == "tok-abc"
    assert isinstance(result, LifecycleStartResult)
    assert result.ok is True
    assert result.plugin_version


@pytest.mark.asyncio
async def test_start_is_idempotent() -> None:
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(broker=_FakeBroker(), gateway=gateway)

    await lifecycle.start()
    gateway.connected_with = None  # detect a second connect
    result = await lifecycle.start()

    assert result.ok is True
    # Second start must NOT reopen the gateway.
    assert gateway.connected_with is None


@pytest.mark.asyncio
async def test_start_failure_returns_not_ok() -> None:
    gateway = _FakeGateway(fail_connect=True)
    lifecycle = DiscordLifecycle(broker=_FakeBroker(), gateway=gateway)

    result = await lifecycle.start()

    assert result.ok is False
    assert result.plugin_version


@pytest.mark.asyncio
async def test_stop_closes_gateway_and_reports_flushed() -> None:
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(broker=_FakeBroker(), gateway=gateway)
    await lifecycle.start()

    result = await lifecycle.stop()

    assert gateway.closed is True
    assert isinstance(result, LifecycleStopResult)
    assert result.ok is True
    assert result.flushed_messages == 7


@pytest.mark.asyncio
async def test_health_reports_running_and_queue_depth() -> None:
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(broker=_FakeBroker(), gateway=gateway)
    await lifecycle.start()

    report = lifecycle.health()

    assert isinstance(report, HealthReport)
    assert report.ok is True
    assert report.queue_depth == 3
    assert report.error_count == 0
    assert report.last_inbound_at is None


@pytest.mark.asyncio
async def test_health_not_ok_before_start() -> None:
    lifecycle = DiscordLifecycle(broker=_FakeBroker(), gateway=_FakeGateway())
    report = lifecycle.health()
    assert report.ok is False


@pytest.mark.asyncio
async def test_token_never_logged(capsys: pytest.CaptureFixture[str]) -> None:
    secret = "tok-super-secret-xyz"  # noqa: S105 -- fabricated leak marker, not a credential
    gateway = _FakeGateway(fail_connect=True)
    lifecycle = DiscordLifecycle(broker=_FakeBroker(token=secret), gateway=gateway)

    await lifecycle.start()

    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err
