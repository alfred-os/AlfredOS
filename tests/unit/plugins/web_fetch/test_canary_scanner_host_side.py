"""``InboundCanaryScanner`` host-side tests (spec §7.6).

The scanner runs on the PLUGIN-HOST SIDE, reading from the Redis content
store by ``handle_id`` without consuming the handle on a clean scan
(read-only peek via ``GETEX KEEPTTL``). On a canary trip it
quarantines the handle (DELETE) BEFORE raising
``WebFetchCanaryTripped`` — so a compromised consumer downstream cannot
race to dereference the trip'd content.

Naming disambiguation (spec rvw-007):

* :class:`alfred.plugins.inbound_scanner.InboundContentScanner` — scans
  every stdio-transport inbound frame for DLP patterns; runs inline in
  ``StdioTransport.dispatch``.
* :class:`alfred.plugins.web_fetch.canary_scanner.InboundCanaryScanner`
  (this module) — system-tier hook subscriber on ``tool.web.fetch``
  ``kind=post``; reads the content store by handle id and scans for
  operator-registered canary tokens.

They are different classes with different responsibilities; never
import one in place of the other.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest
import pytest_asyncio
from testcontainers.redis import RedisContainer

from alfred.plugins.web_fetch.canary_scanner import (
    SCANNER_HOOKPOINT,
    SCANNER_KIND,
    SCANNER_TIER,
    CanaryScanError,
    CanaryToken,
    InboundCanaryScanner,
)
from alfred.plugins.web_fetch.content_store import (
    ContentHandleExpired,
    ContentStore,
)
from alfred.plugins.web_fetch.errors import WebFetchCanaryTripped


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:7-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest_asyncio.fixture
async def store(redis_url: str) -> AsyncIterator[ContentStore]:
    s = ContentStore(redis_url=redis_url)
    try:
        yield s
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_clean_content_does_not_trip(store: ContentStore) -> None:
    """A body with no canary tokens completes without raise."""
    handle = await store.write(
        body=b"<html>clean content</html>", source_url="https://example.com/"
    )
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[CanaryToken("CANARY-TOKEN-12345")],
    )
    await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_canary_token_in_body_trips(store: ContentStore) -> None:
    """A body containing a registered canary raises WebFetchCanaryTripped.

    The raised exception carries source_url + handle_id so the
    tool.web.fetch.canary_tripped audit row can attribute the trip
    without string-parsing the message.
    """
    body = b"<html>CANARY-TOKEN-12345 injected here</html>"
    handle = await store.write(body=body, source_url="https://evil.test/page")
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[CanaryToken("CANARY-TOKEN-12345")],
    )
    with pytest.raises(WebFetchCanaryTripped) as exc_info:
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    assert exc_info.value.handle_id == handle.id
    assert exc_info.value.source_url == "https://evil.test/page"


@pytest.mark.asyncio
async def test_scanner_does_not_consume_clean_handle(store: ContentStore) -> None:
    """Read-only peek invariant: a clean scan must NOT consume the handle.

    The orchestrator's extract path is the only consumer; the scanner is
    a system-tier observer. GETEX with KEEPTTL preserves both the value
    and the original TTL.
    """
    body = b"<html>safe</html>"
    handle = await store.write(body=body, source_url="https://example.com/safe")
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[CanaryToken("SENTINEL-9999")],
    )
    await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    # Handle must still be extractable.
    result = await store.extract(handle.id)
    assert result == body


@pytest.mark.asyncio
async def test_canary_trip_quarantines_handle(store: ContentStore) -> None:
    """After a canary trip the handle MUST be deleted before the raise.

    A compromised downstream consumer cannot race to extract the trip'd
    content because it is already gone from the store at the moment
    WebFetchCanaryTripped propagates.
    """
    body = b"content with CANARY-QUARANTINE-TEST token"
    handle = await store.write(body=body, source_url="https://attacker.test/")
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[CanaryToken("CANARY-QUARANTINE-TEST")],
    )
    with pytest.raises(WebFetchCanaryTripped):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    with pytest.raises(ContentHandleExpired):
        await store.extract(handle.id)


@pytest.mark.asyncio
async def test_missing_body_raises_canary_scan_error(store: ContentStore) -> None:
    """err-010: scanner on a consumed/missing handle raises CanaryScanError,
    NOT a silent return.

    Silently returning would let the orchestrator proceed believing the
    content was scanned — breaking the §7.6 'every web.fetch result is
    scanned' invariant. CanaryScanError surfaces the fault so the hook
    dispatcher can emit a tool.web.fetch result='fault' audit row and
    the orchestrator can quarantine/abort rather than proceeding with
    unscanned content.
    """
    handle = await store.write(body=b"<html>data</html>", source_url="https://example.com/missing")
    # Consume the handle out from under the scanner.
    await store.extract(handle.id)
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[CanaryToken("SENTINEL-XXXX")],
    )
    with pytest.raises(CanaryScanError) as exc_info:
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    assert exc_info.value.handle_id == handle.id
    assert exc_info.value.drift_kind == "missing_body"


@pytest.mark.asyncio
async def test_case_insensitive_match(store: ContentStore) -> None:
    """Canary detection is case-insensitive — an attacker lowercasing a
    well-known canary string must still trip."""
    body = b"<html>canary-token-12345 lowercased</html>"
    handle = await store.write(body=body, source_url="https://attacker.test/")
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[CanaryToken("CANARY-TOKEN-12345")],
    )
    with pytest.raises(WebFetchCanaryTripped):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_multiple_canary_tokens_first_match_trips(store: ContentStore) -> None:
    """Multiple registered tokens: a match on any one trips the scan."""
    body = b"<html>nothing here except SECRET-B</html>"
    handle = await store.write(body=body, source_url="https://attacker.test/")
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[
            CanaryToken("SECRET-A"),
            CanaryToken("SECRET-B"),
            CanaryToken("SECRET-C"),
        ],
    )
    with pytest.raises(WebFetchCanaryTripped):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_empty_canary_set_never_trips(store: ContentStore) -> None:
    """A scanner with no canary tokens never trips — but the hook
    dispatcher should refuse this configuration at bootstrap (covered
    in the bootstrap tests, not here). At the scanner-class level the
    empty set is allowed for unit-test fixtures.
    """
    body = b"<html>any content</html>"
    handle = await store.write(body=body, source_url="https://example.com/")
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[],
    )
    await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_non_utf8_body_does_not_crash_scanner(store: ContentStore) -> None:
    """T3 bodies are routinely binary (PDFs, images). Scanner must use
    ``errors='replace'`` (or equivalent) so invalid UTF-8 sequences do
    not crash the scan — that would let an attacker block the canary
    check by serving deliberately mangled bytes.
    """
    # Invalid UTF-8 lead byte: \xff is never valid in UTF-8.
    body = b"\xff\xfe\xff CANARY-BLOCKED " + b"\xff" * 10
    handle = await store.write(body=body, source_url="https://attacker.test/binary")
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[CanaryToken("CANARY-BLOCKED")],
    )
    with pytest.raises(WebFetchCanaryTripped):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


def test_scanner_registered_as_system_tier_subscriber() -> None:
    """Spec §7.6 / §7.5 invariant: the scanner declares system-tier on
    tool.web.fetch kind=post."""
    assert SCANNER_HOOKPOINT == "tool.web.fetch"
    assert SCANNER_TIER == "system"
    assert SCANNER_KIND == "post"


def test_canary_token_is_frozen() -> None:
    """CanaryToken is a frozen dataclass — operators register the
    vocabulary once at bootstrap; in-flight mutation is a footgun."""
    import dataclasses

    token = CanaryToken("VALUE")
    with pytest.raises(dataclasses.FrozenInstanceError):
        token.value = "MUTATED"  # type: ignore[misc]
