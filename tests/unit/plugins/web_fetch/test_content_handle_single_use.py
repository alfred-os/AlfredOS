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
    handle = await store.write(body=body, source_url="https://example.com/")
    result = await store.extract(handle.id)
    assert result == body


@pytest.mark.asyncio
async def test_second_extract_raises_expired(store: ContentStore) -> None:
    """Single-use invariant (spec §7.2): the second extract MUST fail."""
    body = b"<html>single use</html>"
    handle = await store.write(body=body, source_url="https://example.com/page")
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
    handle = await store.write(body=body, source_url="https://example.com/race")

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
    handle = await store.write(body=body, source_url="https://example.com/del")
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
    handle = await store.write(body=b"x", source_url="https://example.com/idemp")
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
    handle = await store.write(body=body, source_url="https://example.com/path?q=1")
    assert handle.source_url == "https://example.com/path?q=1"
    # ``id`` should be a UUID4 string (verified by parsing).
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
