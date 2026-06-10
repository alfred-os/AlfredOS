"""``lifecycle.start`` / ``lifecycle.stop`` / ``adapter.health`` handlers (Task C2).

The lifecycle handlers authenticate via ``SecretBroker.get("discord_bot_token")``
(never reading the token from env directly), open the Discord WSS through an
injected gateway seam (mocked here; the real ``discord.Client`` wiring lands in
Wave 3's ``discord_gateway.py``), and report the ADR-0024 protocol-model results.

The token is NEVER logged: a dedicated test asserts no structlog event carries
the secret bytes.
"""

from __future__ import annotations

import asyncio

import pytest
from structlog.testing import capture_logs

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


@pytest.mark.asyncio
async def test_token_absent_from_captured_log_records() -> None:
    """Security: the token must be absent from the structured LOG RECORDS too.

    ``test_token_never_logged`` checks rendered stdout/stderr; this asserts the
    SAME guarantee at the structlog event-dict layer (before any renderer), so a
    config change to the log renderer can never silently start leaking the secret.
    """
    secret = "tok-super-secret-xyz"  # noqa: S105 -- fabricated leak marker, not a credential
    gateway = _FakeGateway(fail_connect=True)
    lifecycle = DiscordLifecycle(broker=_FakeBroker(token=secret), gateway=gateway)

    with capture_logs() as logs:
        await lifecycle.start()

    assert logs, "start_failed should have logged at least one event"
    for event in logs:
        for value in event.values():
            assert secret not in str(value)


class _RaisingBroker:
    """A broker whose ``get`` raises a non-Gateway operational error."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def get(self, name: str) -> str:
        raise self._exc


class _OddGateway:
    """A gateway whose ``connect`` raises a non-``GatewayError`` (e.g. transport)."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def connect(self, token: str) -> None:
        raise self._exc

    async def close(self) -> int:
        return 0

    @property
    def queue_depth(self) -> int:
        return 0


@pytest.mark.asyncio
async def test_broker_failure_is_wire_safe_not_ok() -> None:
    # A missing broker secret (or any broker error) must NOT escape the RPC
    # boundary as a raised exception — the contract is ``ok=False``.
    secret_marker = "tok-leak-in-broker-error"  # noqa: S105 -- fabricated, not a credential
    lifecycle = DiscordLifecycle(
        broker=_RaisingBroker(RuntimeError(secret_marker)),
        gateway=_FakeGateway(),
    )

    with capture_logs() as logs:
        result = await lifecycle.start()

    assert result.ok is False
    # The broker error's message (which could embed the token) must not be logged.
    for event in logs:
        for value in event.values():
            assert secret_marker not in str(value)


@pytest.mark.asyncio
async def test_non_gateway_transport_error_is_wire_safe_not_ok() -> None:
    # A non-``GatewayError`` raised during connect (a transport/operational error)
    # must also map to ``ok=False`` rather than crashing across the wire.
    lifecycle = DiscordLifecycle(
        broker=_FakeBroker(),
        gateway=_OddGateway(OSError("transport down")),
    )

    result = await lifecycle.start()

    assert result.ok is False


@pytest.mark.asyncio
async def test_concurrent_start_does_not_open_gateway_twice() -> None:
    """Serialized transitions: two overlapping ``start`` calls connect ONCE."""

    class _CountingGateway(_FakeGateway):
        def __init__(self) -> None:
            super().__init__()
            self.connect_calls = 0

        async def connect(self, token: str) -> None:
            self.connect_calls += 1
            await asyncio.sleep(0)  # yield so a concurrent start can interleave
            await super().connect(token)

    gateway = _CountingGateway()
    lifecycle = DiscordLifecycle(broker=_FakeBroker(), gateway=gateway)

    results = await asyncio.gather(lifecycle.start(), lifecycle.start())

    assert all(r.ok for r in results)
    # The lock + post-lock idempotency check means exactly one connect happened.
    assert gateway.connect_calls == 1


@pytest.mark.asyncio
async def test_concurrent_start_and_stop_do_not_interleave() -> None:
    """A start and a stop racing must not leave an inconsistent running state."""
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(broker=_FakeBroker(), gateway=gateway)
    await lifecycle.start()

    # Race a fresh start against a stop; the lock serialises them so the final
    # state is coherent (no half-open gateway).
    start_result, stop_result = await asyncio.gather(lifecycle.start(), lifecycle.stop())

    assert start_result.ok is True
    assert stop_result.ok is True
