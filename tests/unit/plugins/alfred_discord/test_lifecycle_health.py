"""``lifecycle.start`` / ``lifecycle.stop`` / ``adapter.health`` handlers (Task C2).

The lifecycle handlers authenticate by reading ``discord_bot_token`` from LITERAL
fd 3 — the core injects the token at child spawn (Spec B G6-5, #288), the exact
peer of ``deliver_provider_key_via_fd3``'s framing. The adapter no longer
self-brokers the token; it opens the Discord WSS through an injected gateway seam
(mocked here; the real ``discord.Client`` wiring lands in Wave 3's
``discord_gateway.py``), and reports the ADR-0024 protocol-model results.

The token is NEVER logged: a dedicated test asserts no structlog event carries
the secret bytes (C3 — preserved against the fd-3 source).
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


class _FakeTokenSource:
    """Injected fd-3 token source double: returns a pre-staged token string."""

    def __init__(self, token: str = "tok-secret-123") -> None:  # noqa: S107 -- fabricated test token, not a credential
        self._token = token
        self.read_calls = 0

    def read(self) -> str:
        self.read_calls += 1
        return self._token


@pytest.mark.asyncio
async def test_start_reads_token_from_fd3_and_opens_gateway() -> None:
    gateway = _FakeGateway()
    source = _FakeTokenSource(token="tok-abc")  # noqa: S106 -- fabricated test token, not a credential
    lifecycle = DiscordLifecycle(token_source=source, gateway=gateway)

    result = await lifecycle.start()

    assert source.read_calls == 1
    assert gateway.connected_with == "tok-abc"
    assert isinstance(result, LifecycleStartResult)
    assert result.ok is True
    assert result.plugin_version


@pytest.mark.asyncio
async def test_start_is_idempotent() -> None:
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(), gateway=gateway)

    await lifecycle.start()
    gateway.connected_with = None  # detect a second connect
    result = await lifecycle.start()

    assert result.ok is True
    # Second start must NOT reopen the gateway.
    assert gateway.connected_with is None


@pytest.mark.asyncio
async def test_start_failure_returns_not_ok() -> None:
    gateway = _FakeGateway(fail_connect=True)
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(), gateway=gateway)

    result = await lifecycle.start()

    assert result.ok is False
    assert result.plugin_version


@pytest.mark.asyncio
async def test_stop_closes_gateway_and_reports_flushed() -> None:
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(), gateway=gateway)
    await lifecycle.start()

    result = await lifecycle.stop()

    assert gateway.closed is True
    assert isinstance(result, LifecycleStopResult)
    assert result.ok is True
    assert result.flushed_messages == 7


@pytest.mark.asyncio
async def test_health_reports_running_and_queue_depth() -> None:
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(), gateway=gateway)
    await lifecycle.start()

    report = lifecycle.health()

    assert isinstance(report, HealthReport)
    assert report.ok is True
    assert report.queue_depth == 3
    assert report.error_count == 0
    assert report.last_inbound_at is None


@pytest.mark.asyncio
async def test_health_not_ok_before_start() -> None:
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(), gateway=_FakeGateway())
    report = lifecycle.health()
    assert report.ok is False


@pytest.mark.asyncio
async def test_token_never_logged(capsys: pytest.CaptureFixture[str]) -> None:
    secret = "tok-super-secret-xyz"  # noqa: S105 -- fabricated leak marker, not a credential
    gateway = _FakeGateway(fail_connect=True)
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(token=secret), gateway=gateway)

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
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(token=secret), gateway=gateway)

    with capture_logs() as logs:
        await lifecycle.start()

    assert logs, "start_failed should have logged at least one event"
    for event in logs:
        for value in event.values():
            assert secret not in str(value)


class _RaisingTokenSource:
    """A token source whose ``read`` raises (a torn / mis-framed fd-3 read)."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def read(self) -> str:
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
async def test_fd3_read_failure_is_wire_safe_not_ok() -> None:
    # A torn / mis-framed fd-3 read (or any source error) must NOT escape the RPC
    # boundary as a raised exception — the contract is ``ok=False`` (M3).
    secret_marker = "tok-leak-in-source-error"  # noqa: S105 -- fabricated, not a credential
    lifecycle = DiscordLifecycle(
        token_source=_RaisingTokenSource(RuntimeError(secret_marker)),
        gateway=_FakeGateway(),
    )

    with capture_logs() as logs:
        result = await lifecycle.start()

    assert result.ok is False
    # The source error's message (which could embed partial token bytes) must not
    # be logged.
    for event in logs:
        for value in event.values():
            assert secret_marker not in str(value)


@pytest.mark.asyncio
async def test_non_gateway_transport_error_is_wire_safe_not_ok() -> None:
    # A non-``GatewayError`` raised during connect (a transport/operational error)
    # must also map to ``ok=False`` rather than crashing across the wire.
    lifecycle = DiscordLifecycle(
        token_source=_FakeTokenSource(),
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
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(), gateway=gateway)

    results = await asyncio.gather(lifecycle.start(), lifecycle.start())

    assert all(r.ok for r in results)
    # The lock + post-lock idempotency check means exactly one connect happened.
    assert gateway.connect_calls == 1


@pytest.mark.asyncio
async def test_concurrent_start_and_stop_do_not_interleave() -> None:
    """A start and a stop racing must not leave an inconsistent running state."""
    gateway = _FakeGateway()
    lifecycle = DiscordLifecycle(token_source=_FakeTokenSource(), gateway=gateway)
    await lifecycle.start()

    # Race a fresh start against a stop; the lock serialises them so the final
    # state is coherent (no half-open gateway).
    start_result, stop_result = await asyncio.gather(lifecycle.start(), lifecycle.stop())

    assert start_result.ok is True
    assert stop_result.ok is True
