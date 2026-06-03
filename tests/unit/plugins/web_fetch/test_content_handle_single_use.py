"""Single-use ``ContentHandle`` semantics (spec §7.2, §7.3).

The Redis-backed ``ContentStore`` enforces: on first extract, the store
atomically removes the key before returning the body. A second extract
on the same ``handle_id`` raises ``ContentHandleExpired`` — the same
typed error as TTL expiry, so an attacker cannot distinguish "double-
extract attempt" from "TTL fired" by observing the error shape.

The integration test ``tests/integration/test_redis_compose_service.py``
pins ``GETDEL`` as the production primitive for the atomic extract (it is
truly atomic across clients; a GET+DEL pipeline is not). This unit test
exercises the same primitive against a testcontainers Redis instance —
no mocks, no in-memory stub.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from testcontainers.redis import RedisContainer

from alfred.plugins.web_fetch.content_store import (
    ContentHandle,
    ContentHandleExpired,
    ContentStore,
)


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:7-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest_asyncio.fixture
async def store(redis_url: str) -> AsyncIterator[ContentStore]:
    """Function-scoped store so each test runs against a fresh client.

    The Redis container is module-scoped (cold-start is expensive); the
    Python client is cheap, so building a per-test store keeps the
    pytest-asyncio event-loop teardown clean.
    """
    s = ContentStore(redis_url=redis_url)
    try:
        yield s
    finally:
        await s.close()


def test_content_handle_has_no_content_field() -> None:
    """Orchestrator-side invariant (spec §7.3): ContentHandle is OPAQUE.

    ``ContentHandle`` exposes ``id``, ``source_url``, and
    ``fetch_timestamp`` only. A ``.content`` (or ``.body``) field would
    let the orchestrator dereference T3 bytes directly, breaking the
    quarantined-LLM split. This test pins the absence.
    """
    handle = ContentHandle(
        id=str(uuid.uuid4()),
        source_url="https://example.com/",
        fetch_timestamp=datetime.now(tz=UTC),
    )
    assert not hasattr(handle, "content")
    assert not hasattr(handle, "body")


def test_content_handle_is_frozen() -> None:
    """``frozen=True`` so the orchestrator cannot mutate the handle in flight."""
    handle = ContentHandle(
        id=str(uuid.uuid4()),
        source_url="https://example.com/",
        fetch_timestamp=datetime.now(tz=UTC),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        handle.id = "new-id"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_store_and_extract_once(store: ContentStore) -> None:
    body = b"<html>hello</html>"
    handle = await store.write(
        handle_id=str(uuid.uuid4()), body=body, source_url="https://example.com/"
    )
    result = await store.extract(handle.id)
    assert result == body


@pytest.mark.asyncio
async def test_second_extract_raises_expired(store: ContentStore) -> None:
    """Single-use invariant (spec §7.2): the second extract MUST fail."""
    body = b"<html>single use</html>"
    handle = await store.write(
        handle_id=str(uuid.uuid4()), body=body, source_url="https://example.com/page"
    )
    await store.extract(handle.id)
    with pytest.raises(ContentHandleExpired):
        await store.extract(handle.id)


@pytest.mark.asyncio
async def test_extract_unknown_handle_raises_expired(store: ContentStore) -> None:
    """A handle id that was never written cannot be distinguished from
    one that was already extracted — both surface as ``ContentHandleExpired``.
    The audit row records ``result="content_expired"`` either way.
    """
    with pytest.raises(ContentHandleExpired):
        await store.extract("00000000-0000-0000-0000-000000000000")


@pytest.mark.asyncio
async def test_concurrent_extract_race_closed(store: ContentStore) -> None:
    """Two concurrent extracts on the same handle: exactly one wins.

    The atomic ``GETDEL`` primitive guarantees there is no window where
    both calls can read the body before either DELetes the key. A
    pipeline-based GET+DEL would NOT prevent this race.
    """
    body = b"<html>race</html>"
    handle = await store.write(
        handle_id=str(uuid.uuid4()), body=body, source_url="https://example.com/race"
    )

    results: list[bytes | ContentHandleExpired] = []

    async def try_extract() -> None:
        try:
            results.append(await store.extract(handle.id))
        except ContentHandleExpired as e:
            results.append(e)

    async with asyncio.TaskGroup() as tg:
        tg.create_task(try_extract())
        tg.create_task(try_extract())

    successes = [r for r in results if isinstance(r, bytes)]
    expireds = [r for r in results if isinstance(r, ContentHandleExpired)]
    assert len(successes) == 1
    assert len(expireds) == 1


@pytest.mark.asyncio
async def test_handle_ttl_formula(store: ContentStore, redis_url: str) -> None:
    """Default TTL = action_deadline(30) + retries(2)*per_retry(10) + slack(30) = 80s.

    The formula is set so the handle stays alive long enough for the
    full retry chain (quarantined LLM extract path) but expires shortly
    after to bound the leakage window.
    """
    body = b"data"
    handle = await store.write(
        handle_id=str(uuid.uuid4()),
        body=body,
        source_url="https://example.com/ttl",
        action_deadline_seconds=30,
        max_extraction_retries=2,
        per_retry_budget_seconds=10,
        slack_seconds=30,
    )
    probe = aioredis.from_url(redis_url)
    try:
        ttl = await probe.ttl(f"alfred:content:{handle.id}")
    finally:
        await probe.aclose()
    # 2s tolerance window for clock drift between write and probe.
    assert 70 <= ttl <= 82, f"unexpected ttl {ttl}; formula = 30 + 2*10 + 30 = 80"


@pytest.mark.asyncio
async def test_extract_removes_key(store: ContentStore, redis_url: str) -> None:
    """After successful extract, the Redis key MUST be gone (spec §7.2)."""
    body = b"ephemeral"
    handle = await store.write(
        handle_id=str(uuid.uuid4()), body=body, source_url="https://example.com/del"
    )
    await store.extract(handle.id)
    probe = aioredis.from_url(redis_url)
    try:
        exists = await probe.exists(f"alfred:content:{handle.id}")
    finally:
        await probe.aclose()
    assert exists == 0


@pytest.mark.asyncio
async def test_explicit_delete_idempotent(store: ContentStore) -> None:
    """``delete`` is a no-op on an unknown id (idempotent quarantine path)."""
    handle = await store.write(
        handle_id=str(uuid.uuid4()), body=b"x", source_url="https://example.com/idemp"
    )
    await store.delete(handle.id)
    # Second delete must not raise.
    await store.delete(handle.id)
    with pytest.raises(ContentHandleExpired):
        await store.extract(handle.id)


@pytest.mark.asyncio
async def test_write_returns_handle_with_source_url(store: ContentStore) -> None:
    """``write`` is the only path that mints a handle; source_url is
    recorded for audit attribution, not for orchestrator-side reads."""
    body = b"data"
    pre_minted = str(uuid.uuid4())
    handle = await store.write(
        handle_id=pre_minted, body=body, source_url="https://example.com/path?q=1"
    )
    assert handle.source_url == "https://example.com/path?q=1"
    # ``id`` must equal the caller-supplied handle_id (no internal re-mint).
    assert handle.id == pre_minted
    uuid.UUID(handle.id)  # raises if not a valid UUID
    # ``fetch_timestamp`` MUST be tz-aware per CR-138 finding #4.
    assert handle.fetch_timestamp.tzinfo is not None


@pytest.mark.asyncio
async def test_close_is_idempotent(store: ContentStore) -> None:
    """Closing twice must not raise — supervisor SIGKILL paths call
    ``close()`` defensively without checking state first."""
    await store.close()
    await store.close()


def test_redis_url_property_exposed(redis_url: str) -> None:
    """The InboundCanaryScanner (Task 5) reads ``store.redis_url`` so it
    can open its own peek-mode connection without touching the store's
    internal client. Coverage on the property pins the contract."""
    s = ContentStore(redis_url=redis_url)
    assert s.redis_url == redis_url


# ---------------------------------------------------------------------------
# CR-146 major: write-time TTL guard + URL redaction in debug log.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action_deadline", "max_retries", "per_retry", "slack"),
    [
        # All zero — ttl = 0
        (0, 0, 0, 0),
        # All negative — ttl < 0
        (-10, 0, 0, 0),
        # Slack negative wipes out the rest — ttl = -1
        (10, 2, 5, -21),
    ],
)
async def test_write_rejects_non_positive_ttl(
    store: ContentStore,
    action_deadline: int,
    max_retries: int,
    per_retry: int,
    slack: int,
) -> None:
    """CR-146 major: PRD §7.2 makes the TTL knobs operator-tunable, but
    a misconfig producing ``ttl <= 0`` would either crash Redis SET EX
    at the wire or create an immediately-expiring key. Both shapes
    corrupt the quarantine-extract path silently. Fail at write-time
    with a clear error so the operator sees the bad config at boot.
    """
    with pytest.raises(ValueError, match="TTL must be positive"):
        await store.write(
            handle_id=str(uuid.uuid4()),
            body=b"x",
            source_url="https://example.com/",
            action_deadline_seconds=action_deadline,
            max_extraction_retries=max_retries,
            per_retry_budget_seconds=per_retry,
            slack_seconds=slack,
        )


@pytest.mark.asyncio
async def test_write_log_strips_sensitive_url_components(
    store: ContentStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """CR-146 major: the ``web_fetch.content_store.written`` debug log
    records a sanitized URL (no query string, no userinfo). Full URL
    stays on the in-memory ``ContentHandle`` and the audit-row path.
    """
    import structlog

    raw_url = "https://alice:hunter2@example.com/path?token=BEARER_SECRET#frag"
    with structlog.testing.capture_logs() as captured:
        handle = await store.write(handle_id=str(uuid.uuid4()), body=b"x", source_url=raw_url)

    written_events = [e for e in captured if e.get("event") == "web_fetch.content_store.written"]
    assert len(written_events) == 1
    sanitized = written_events[0]["source_url"]
    # Secrets MUST NOT appear in the log breadcrumb.
    assert "BEARER_SECRET" not in sanitized
    assert "hunter2" not in sanitized
    assert "alice" not in sanitized
    # Only scheme + host + path survive.
    assert sanitized == "https://example.com/path"
    # Full URL preserved on the handle — the audit row path reads
    # ``handle.source_url`` so this must stay intact.
    assert handle.source_url == raw_url


def test_content_store_sanitize_url_for_log_fallbacks() -> None:
    """``_sanitize_url_for_log`` falls back to a sentinel rather than
    risk leaking the raw URL into the log on a malformed input."""
    from alfred.plugins.web_fetch.content_store import _sanitize_url_for_log

    # No scheme → fallback (we never log a host-only / path-only string
    # that could be confused with a sanitized full URL).
    assert _sanitize_url_for_log("/just/a/path") == "<sanitize_failed>"
    # No host (scheme:opaque) → fallback.
    assert _sanitize_url_for_log("mailto:x@y") == "<sanitize_failed>"
    # Non-string input — urlparse raises, the helper catches.
    assert _sanitize_url_for_log(None) == "<sanitize_failed>"  # type: ignore[arg-type]
    # Port preserved alongside host so operators can distinguish
    # 443 vs 8080 in the breadcrumb.
    assert (
        _sanitize_url_for_log("https://example.com:8443/path?x=1")
        == "https://example.com:8443/path"
    )
    # Non-numeric port — ``urlparse(...).port`` raises ValueError on
    # lazy access. Sanitizer catches and falls back rather than
    # leaking the raw URL via an uncaught exception.
    assert _sanitize_url_for_log("https://example.com:notanumber/p") == "<sanitize_failed>"


@pytest.mark.asyncio
async def test_write_uses_passed_handle_id_not_internal_mint(
    store: ContentStore,
) -> None:
    """Host pre-mints handle_id; ContentStore.write uses it verbatim, no
    internal uuid4() mint. Cap-binding (spec §3) depends on this contract."""
    h = "pre-minted-deterministic-id"
    handle = await store.write(handle_id=h, body=b"x", source_url="https://example.com/")
    assert handle.id == h
