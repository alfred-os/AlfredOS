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

from collections.abc import AsyncIterator, Callable, Iterator
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
import structlog
from redis.exceptions import RedisError
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

if TYPE_CHECKING:
    import redis.asyncio as aioredis

# perf-102: scanners hold long-lived peek clients. ``ScannerFactory``
# wraps the construction + aclose() lifecycle so every test gets a
# scanner that the fixture finalizer closes deterministically — no
# per-test ``try/finally: await scanner.aclose()`` boilerplate.
ScannerFactory = Callable[..., InboundCanaryScanner]


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


@pytest_asyncio.fixture
async def scanner_factory(store: ContentStore) -> AsyncIterator[ScannerFactory]:
    """Yield a factory that returns scanners wired to ``store``'s Redis
    URL and auto-closes their peek clients on teardown.

    Tests pass ``known_canary_tokens`` (and optionally override
    ``content_store`` / ``redis_url`` / ``redis_client``) — every other
    knob defaults from the ``store`` fixture. The fixture's finalizer
    calls :meth:`InboundCanaryScanner.aclose` on each scanner the test
    minted, so leaked peek clients can't bleed across tests and the
    perf-102 long-lived-client contract is exercised on every test
    that uses the factory.
    """
    created: list[InboundCanaryScanner] = []

    def _factory(
        *,
        known_canary_tokens: list[CanaryToken],
        content_store: ContentStore | None = None,
        redis_url: str | None = None,
        redis_client: aioredis.Redis | None = None,
    ) -> InboundCanaryScanner:
        # If neither override was passed, default the peek URL to the
        # store's URL. The factory's caller can opt out by passing
        # ``redis_url=None, redis_client=<explicit>`` to exercise the
        # injection path.
        if redis_url is None and redis_client is None:
            redis_url = store.redis_url
        scanner = InboundCanaryScanner(
            content_store=content_store if content_store is not None else store,
            known_canary_tokens=known_canary_tokens,
            redis_url=redis_url,
            redis_client=redis_client,
        )
        created.append(scanner)
        return scanner

    try:
        yield _factory
    finally:
        for scanner in created:
            await scanner.aclose()


@pytest.mark.asyncio
async def test_clean_content_does_not_trip(
    store: ContentStore, scanner_factory: ScannerFactory
) -> None:
    """A body with no canary tokens completes without raise."""
    handle = await store.write(
        body=b"<html>clean content</html>", source_url="https://example.com/"
    )
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("CANARY-TOKEN-12345")])
    await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_canary_token_in_body_trips(
    store: ContentStore, scanner_factory: ScannerFactory
) -> None:
    """A body containing a registered canary raises WebFetchCanaryTripped.

    The raised exception carries source_url + handle_id so the
    tool.web.fetch.canary_tripped audit row can attribute the trip
    without string-parsing the message.
    """
    body = b"<html>CANARY-TOKEN-12345 injected here</html>"
    handle = await store.write(body=body, source_url="https://evil.test/page")
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("CANARY-TOKEN-12345")])
    with pytest.raises(WebFetchCanaryTripped) as exc_info:
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    assert exc_info.value.handle_id == handle.id
    assert exc_info.value.source_url == "https://evil.test/page"


@pytest.mark.asyncio
async def test_scanner_does_not_consume_clean_handle(
    store: ContentStore, scanner_factory: ScannerFactory
) -> None:
    """Read-only peek invariant: a clean scan must NOT consume the handle.

    The orchestrator's extract path is the only consumer; the scanner is
    a system-tier observer. GETEX with KEEPTTL preserves both the value
    and the original TTL.
    """
    body = b"<html>safe</html>"
    handle = await store.write(body=body, source_url="https://example.com/safe")
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("SENTINEL-9999")])
    await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    # Handle must still be extractable.
    result = await store.extract(handle.id)
    assert result == body


@pytest.mark.asyncio
async def test_canary_trip_quarantines_handle(
    store: ContentStore, scanner_factory: ScannerFactory
) -> None:
    """After a canary trip the handle MUST be deleted before the raise.

    A compromised downstream consumer cannot race to extract the trip'd
    content because it is already gone from the store at the moment
    WebFetchCanaryTripped propagates.
    """
    body = b"content with CANARY-QUARANTINE-TEST token"
    handle = await store.write(body=body, source_url="https://attacker.test/")
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("CANARY-QUARANTINE-TEST")])
    with pytest.raises(WebFetchCanaryTripped):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    with pytest.raises(ContentHandleExpired):
        await store.extract(handle.id)


@pytest.mark.asyncio
async def test_canary_trip_raises_even_when_redis_delete_fails(
    store: ContentStore,
    scanner_factory: ScannerFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """err-002: a RedisError on quarantine delete must NOT swallow the
    canary trip.

    Two failure modes line up here: (a) the handle stays alive in Redis
    until TTL — survivable; (b) the typed canary exception fails to
    propagate — the orchestrator's canary arm never fires; the
    load-bearing defence is invisible. (b) is strictly worse, so the
    contract is: even when the quarantine I/O throws, the typed canary
    exception STILL raises. This test pins the invariant — if a future
    refactor accidentally chains the raise to the delete's success, the
    test catches it.
    """
    body = b"content with CANARY-DELETE-FAIL token"
    handle = await store.write(body=body, source_url="https://attacker.test/del-fail")

    async def _raise_redis_error(handle_id: str) -> None:
        # ConnectionError is a RedisError subclass — most common
        # production shape for a transient quarantine I/O failure.
        msg = "simulated Redis connection reset mid-quarantine"
        raise RedisError(msg)

    monkeypatch.setattr(store, "delete", _raise_redis_error)
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("CANARY-DELETE-FAIL")])
    with pytest.raises(WebFetchCanaryTripped) as exc_info:
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    # source_url + handle_id still attributed despite the delete failure
    # — the orchestrator's catch-arm needs both to emit the
    # canary_tripped audit row.
    assert exc_info.value.handle_id == handle.id
    assert exc_info.value.source_url == handle.source_url


@pytest.mark.asyncio
async def test_canary_trip_emits_quarantine_failed_structlog(
    store: ContentStore,
    scanner_factory: ScannerFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """err-002: the quarantine-failure leg emits a LOUD structlog event
    naming the failed quarantine.

    ``capture_logs`` intercepts structlog output. The event name is the
    operator-visible signal until the dedicated quarantine_failed audit
    schema lands — so the test pins both the event name AND the
    forensic attributes (handle_id + source_url + exception_type) so a
    future refactor cannot silently weaken the signal to a generic
    ``error`` event.

    ``exception_type`` carries the Python type name only — never
    ``str(exc)`` or ``exc.args`` (spec §5.6: a misbehaving subprocess
    may have laundered T3 fragments into the Redis error message).
    """
    body = b"content with CANARY-DELETE-STRUCTLOG token"
    handle = await store.write(
        body=body,
        source_url="https://attacker.test/structlog",
    )

    async def _raise_redis_error(handle_id: str) -> None:
        msg = "simulated Redis connection reset"
        raise RedisError(msg)

    monkeypatch.setattr(store, "delete", _raise_redis_error)
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("CANARY-DELETE-STRUCTLOG")])
    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises(WebFetchCanaryTripped),
    ):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)

    quarantine_failed_events = [
        e for e in captured if e.get("event") == "web_fetch.canary.quarantine_failed"
    ]
    assert len(quarantine_failed_events) == 1, (
        f"expected exactly one web_fetch.canary.quarantine_failed event; captured: {captured!r}"
    )
    event = quarantine_failed_events[0]
    assert event["log_level"] == "error", "quarantine_failed must be LOUD (error level)"
    assert event["handle_id"] == handle.id
    assert event["source_url"] == handle.source_url
    assert event["exception_type"] == "RedisError"


@pytest.mark.asyncio
async def test_missing_body_raises_canary_scan_error(
    store: ContentStore, scanner_factory: ScannerFactory
) -> None:
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
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("SENTINEL-XXXX")])
    with pytest.raises(CanaryScanError) as exc_info:
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    assert exc_info.value.handle_id == handle.id
    assert exc_info.value.drift_kind == "missing_body"


@pytest.mark.asyncio
async def test_case_insensitive_match(store: ContentStore, scanner_factory: ScannerFactory) -> None:
    """Canary detection is case-insensitive — an attacker lowercasing a
    well-known canary string must still trip."""
    body = b"<html>canary-token-12345 lowercased</html>"
    handle = await store.write(body=body, source_url="https://attacker.test/")
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("CANARY-TOKEN-12345")])
    with pytest.raises(WebFetchCanaryTripped):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_multiple_canary_tokens_first_match_trips(
    store: ContentStore, scanner_factory: ScannerFactory
) -> None:
    """Multiple registered tokens: a match on any one trips the scan."""
    body = b"<html>nothing here except SECRET-B</html>"
    handle = await store.write(body=body, source_url="https://attacker.test/")
    scanner = scanner_factory(
        known_canary_tokens=[
            CanaryToken("SECRET-A"),
            CanaryToken("SECRET-B"),
            CanaryToken("SECRET-C"),
        ],
    )
    with pytest.raises(WebFetchCanaryTripped):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_empty_canary_set_never_trips(
    store: ContentStore, scanner_factory: ScannerFactory
) -> None:
    """A scanner with no canary tokens never trips — but the hook
    dispatcher should refuse this configuration at bootstrap (covered
    in the bootstrap tests, not here). At the scanner-class level the
    empty set is allowed for unit-test fixtures.
    """
    body = b"<html>any content</html>"
    handle = await store.write(body=body, source_url="https://example.com/")
    scanner = scanner_factory(known_canary_tokens=[])
    await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_non_utf8_body_does_not_crash_scanner(
    store: ContentStore, scanner_factory: ScannerFactory
) -> None:
    """T3 bodies are routinely binary (PDFs, images). Scanner must use
    ``errors='replace'`` (or equivalent) so invalid UTF-8 sequences do
    not crash the scan — that would let an attacker block the canary
    check by serving deliberately mangled bytes.
    """
    # Invalid UTF-8 lead byte: \xff is never valid in UTF-8.
    body = b"\xff\xfe\xff CANARY-BLOCKED " + b"\xff" * 10
    handle = await store.write(body=body, source_url="https://attacker.test/binary")
    scanner = scanner_factory(known_canary_tokens=[CanaryToken("CANARY-BLOCKED")])
    with pytest.raises(WebFetchCanaryTripped):
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)


@pytest.mark.asyncio
async def test_scanner_reuses_client_across_scans(
    store: ContentStore,
    scanner_factory: ScannerFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """perf-102: the URL-owned client mints exactly once across N scans.

    The pre-perf-102 shape called ``aioredis.from_url`` + ``aclose`` on
    every scan, which opens a TCP handshake per fetch. The contract is
    now: one mint, held for the process lifetime. We monkeypatch a
    counter onto ``aioredis.from_url`` and assert it fires exactly once
    across multiple scans — if a refactor accidentally re-introduces
    per-scan construction the counter goes >1 and the test fails.

    We use the scanner's own URL-owned client (not an external one) so
    the lazy-mint code path is exercised. The factory's finalizer
    closes the client; the test does not need to.
    """
    import redis.asyncio as aio_real

    # Prime the store's client BEFORE the monkeypatch — the
    # ContentStore lazy-mints its own client on first I/O via the same
    # ``aioredis.from_url`` symbol. If we patched first, the store's
    # first write inside the loop would count as a "from_url call" the
    # scanner did not make, contaminating the perf signal.
    primer_handle = await store.write(
        body=b"<html>primer</html>", source_url="https://example.com/primer"
    )
    # Discard the primer handle so it does not pollute later scans.
    await store.delete(primer_handle.id)

    real_from_url = aio_real.from_url
    call_count = 0

    # Wrapper signature mirrors aio_real.from_url's call shape (url +
    # arbitrary kwargs); mypy treats the package's function as
    # ``(url: str, **kwargs: Any) -> Redis`` so we mirror that contract
    # exactly rather than ``*args, **kwargs: object`` (which surfaces
    # as a type mismatch on the real signature).
    def _counting_from_url(url: str, **kwargs: object) -> aio_real.Redis:
        nonlocal call_count
        call_count += 1
        return real_from_url(url, **kwargs)

    monkeypatch.setattr(aio_real, "from_url", _counting_from_url)

    scanner = scanner_factory(known_canary_tokens=[CanaryToken("SENTINEL-PERF-102")])
    # Run 5 scans against the same scanner against 5 distinct handles.
    # If the client is per-scan, count == 5; if it's long-lived, count == 1.
    for i in range(5):
        handle = await store.write(
            body=f"<html>clean content {i}</html>".encode(),
            source_url=f"https://example.com/scan-{i}",
        )
        await scanner.scan(handle_id=handle.id, source_url=handle.source_url)
    assert call_count == 1, (
        "perf-102: InboundCanaryScanner must mint its peek client exactly once "
        f"across N scans; observed {call_count} calls to aioredis.from_url."
    )


def test_scanner_construction_raises_when_neither_url_nor_client(
    store: ContentStore,
) -> None:
    """perf-102 negative path: neither redis_url nor redis_client is
    non-functional; raise at construction so the misconfiguration is
    impossible to ship past bootstrap.

    A silent fallback to ``store.redis_url`` would re-introduce the
    perf-102 connection-churn shape behind a hidden default. The
    explicit raise forces wiring code to make an intentional choice
    between "scanner owns its client" (``redis_url=...``) and
    "host injects the client" (``redis_client=...``).
    """
    with pytest.raises(ValueError, match="redis_url or redis_client"):
        InboundCanaryScanner(
            content_store=store,
            known_canary_tokens=[CanaryToken("SOMETHING")],
        )


@pytest.mark.asyncio
async def test_scanner_with_externally_supplied_client_does_not_close_on_aclose(
    store: ContentStore,
    redis_url: str,
) -> None:
    """The ``redis_client`` injection path is the dependency-injection
    contract: the host owns the client's lifecycle.

    :meth:`aclose` must NOT close an externally-supplied client — the
    host that injected it will close it as part of its own shutdown.
    Closing it would leave the host with a half-closed pool and
    surface as connection-reset errors on the next host I/O.
    """
    import redis.asyncio as aioredis

    external_client = aioredis.from_url(redis_url, decode_responses=False)
    try:
        scanner = InboundCanaryScanner(
            content_store=store,
            known_canary_tokens=[CanaryToken("SOMETHING")],
            redis_client=external_client,
        )
        await scanner.aclose()
        # If the scanner closed the client, this round-trip would raise
        # — the assertion is the success of the PING.
        assert await external_client.ping() is True
    finally:
        await external_client.aclose()


@pytest.mark.asyncio
async def test_scanner_aclose_is_idempotent_and_safe_before_first_scan(
    store: ContentStore,
) -> None:
    """``aclose()`` is callable from supervisor SIGKILL paths without
    coordinating with first-scan timing.

    The peek client is minted lazily on first scan; calling aclose
    before any scan has run must not raise (the client was never
    constructed). Calling aclose twice must also not raise — the
    second call is a no-op.
    """
    scanner = InboundCanaryScanner(
        content_store=store,
        known_canary_tokens=[CanaryToken("X")],
        redis_url=store.redis_url,
    )
    # No scan has run yet — the peek client is None.
    await scanner.aclose()
    # Second close — no-op, must not raise.
    await scanner.aclose()


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
