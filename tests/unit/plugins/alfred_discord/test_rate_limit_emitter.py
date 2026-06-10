"""``rate_limit_emitter`` emits ``RateLimitSignal`` on a Discord 429 (Task G1, #206).

When Discord returns a 429, the adapter MUST signal the host so the host's
``OutboundQueue.pause`` suspends further emit. Per closure comms-3 the signal is
AWAITED before any further outbound emit (NOT fire-and-forget): the emit loop
blocks on the signal-handler completion so no outbound slips out between the 429
and the pause.

Behaviour pinned here:

1. A 429 with ``retry_after=3.5`` emits one ``adapter.rate_limit_signal``
   notification with ``retry_after_seconds=4`` (rounded UP).
2. ``platform_endpoint`` is derived from the exception's response URL.
3. Debounce: two 429s for the same endpoint within the retry-after window emit
   ONE signal.
4. After a successful outbound (``clear`` is called), the debounce state resets
   so the next 429 emits a fresh signal.
5. comms-3 ordering: the signal-handler ``emit`` is AWAITED — the emitter does
   not return until the sink has accepted the frame.
"""

from __future__ import annotations

from collections.abc import Mapping
from unittest.mock import Mock

from plugins.alfred_discord.rate_limit_emitter import _UNKNOWN_ENDPOINT, RateLimitEmitter
from tests.support.discord_mocks import DiscordMockFactory

_ADAPTER = "discord"


class _RecordingSink:
    """An awaitable notification sink that records every frame in order."""

    def __init__(self) -> None:
        self.frames: list[Mapping[str, object]] = []
        self.emit_started = 0
        self.emit_finished = 0

    async def emit(self, frame: Mapping[str, object]) -> None:
        self.emit_started += 1
        self.frames.append(frame)
        self.emit_finished += 1


def _emitter(sink: _RecordingSink) -> RateLimitEmitter:
    return RateLimitEmitter(adapter_id=_ADAPTER, sink=sink)


async def test_429_emits_one_signal_rounded_up(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink)
    exc = discord_mock_factory.http_exception(status=429, retry_after=3.5)
    await emitter.emit_for_rate_limit(exc)
    assert len(sink.frames) == 1
    frame = sink.frames[0]
    assert frame["method"] == "adapter.rate_limit_signal"
    params = frame["params"]
    assert isinstance(params, Mapping)
    assert params["retry_after_seconds"] == 4
    assert params["adapter_id"] == _ADAPTER


async def test_platform_endpoint_derived_from_response_url(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink)
    exc = discord_mock_factory.http_exception(status=429, retry_after=1.0)
    await emitter.emit_for_rate_limit(exc)
    params = sink.frames[0]["params"]
    assert isinstance(params, Mapping)
    # The endpoint must reference discord.com and be non-empty.
    assert "discord.com" in str(params["platform_endpoint"])


async def test_debounce_suppresses_second_signal_in_window(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink)
    exc = discord_mock_factory.http_exception(status=429, retry_after=5.0)
    await emitter.emit_for_rate_limit(exc)
    await emitter.emit_for_rate_limit(exc)
    # Same endpoint within the retry-after window: only one signal.
    assert len(sink.frames) == 1


async def test_clear_resets_debounce(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    sink = _RecordingSink()
    emitter = _emitter(sink)
    exc = discord_mock_factory.http_exception(status=429, retry_after=5.0)
    await emitter.emit_for_rate_limit(exc)
    emitter.clear()  # successful outbound clears the debounce state
    await emitter.emit_for_rate_limit(exc)
    assert len(sink.frames) == 2


async def test_emit_is_awaited_before_returning(
    discord_mock_factory: DiscordMockFactory,
) -> None:
    # comms-3: the emitter must AWAIT the sink — on return, the frame has been
    # fully accepted (started == finished == 1), proving no fire-and-forget task
    # was left pending.
    sink = _RecordingSink()
    emitter = _emitter(sink)
    exc = discord_mock_factory.http_exception(status=429, retry_after=2.0)
    await emitter.emit_for_rate_limit(exc)
    assert sink.emit_started == 1
    assert sink.emit_finished == 1


def _exc_with_url(url: object) -> Mock:
    """A minimal exception double carrying ``response.url`` for ``_endpoint``."""
    response = Mock()
    response.url = url
    exc = Mock()
    exc.response = response
    return exc


def test_endpoint_no_response_url_returns_unknown() -> None:
    exc = _exc_with_url(None)
    assert RateLimitEmitter._endpoint(exc) == _UNKNOWN_ENDPOINT  # type: ignore[arg-type]


def test_endpoint_discord_url_is_coarse_host_plus_segment() -> None:
    exc = _exc_with_url("https://discord.com/api/v10/channels/1/messages")
    label = RateLimitEmitter._endpoint(exc)  # type: ignore[arg-type]
    assert label.startswith("discord.com")
    assert "discord.com" in label


def test_endpoint_non_discord_url_never_leaks_full_url() -> None:
    # A malicious redirect / MITM / library bug could surface a non-discord URL
    # carrying a sensitive id. The fallback must NEVER place the full URL (or its
    # id-bearing path) in the audit label — it collapses to the stable unknown
    # placeholder instead.
    leaky = "https://evil.example.com/secret/918273645546372819/token-abc"
    label = RateLimitEmitter._endpoint(_exc_with_url(leaky))  # type: ignore[arg-type]
    assert label == _UNKNOWN_ENDPOINT
    assert "evil.example.com" not in label
    assert "918273645546372819" not in label
    assert "token-abc" not in label
