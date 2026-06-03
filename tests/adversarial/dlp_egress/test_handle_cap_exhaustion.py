"""Executable counterpart to ``handle_cap_exhaustion.yaml`` (de-2026-004).

The YAML is corpus-density-validated by ``test_corpus_density.py`` but
that alone does not exercise the runtime contract. This module loads the
YAML payload, instantiates the real :class:`HandleCap` against a real
Redis container, and pins the cap-refusal contract: exactly 5 reserves
succeed, the 6th raises
:class:`alfred.plugins.web_fetch.errors.WebFetchRateLimited` with
``bucket='handle_cap'``, and the cap-refusal audit-row vocabulary
matches the YAML's ``expected_audit_row`` block.

CR-156-r1 / T11 widening: the final test
:func:`test_dispatcher_audit_path_emits_cap_refusal_row` drives the cap
through the real :func:`dispatch_web_fetch` and asserts the cap-refusal
audit row is actually emitted by the dispatcher (not just that the cap
itself raises). The two-layer split — cap-raises tests + dispatcher-emits
test — keeps the lower-level invariant and the higher-level wiring
separately diagnosable when one breaks.

Trust-boundary contract pinned here:

* The refusal is structural (Lua-atomic ZADD against cap) — the 6th
  reserve is rejected BEFORE any network round-trip. The YAML's
  ``attack_steps`` line "Verify refusal happens BEFORE the plugin call"
  is satisfied by exercising ``HandleCap.try_reserve`` directly: the
  rejection happens entirely inside Redis with no plugin involvement.
* The closed audit-row vocabulary
  (``rate_limit_bucket='handle_cap'`` +
  ``dlp_scan_result='handle_cap_exceeded'`` + ``result='rate_limited'``)
  is asserted against the YAML's declaration so a future schema drift
  on either side fails loud here.

If this test starts failing after a code change, you have either:

* Loosened the cap (the YAML still claims cap=5 binds at 6 fetches —
  update the payload AND the runbook), or
* Broken the closed audit vocabulary (the YAML still claims those exact
  field values — update the schema AND every consumer that reads
  ``WEB_FETCH_FIELDS['rate_limit_bucket']`` / ``['dlp_scan_result']``).

Both are merge-blocking deltas; neither is a "just update the test"
fix.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Final

import pytest
import pytest_asyncio
import yaml
from testcontainers.redis import RedisContainer

from alfred.plugins.web_fetch.errors import WebFetchRateLimited
from alfred.plugins.web_fetch.handle_cap import HandleCap, HandleCapConfig

_PAYLOAD_PATH: Final[Path] = Path(__file__).parent / "handle_cap_exhaustion.yaml"


@pytest.fixture(scope="module")
def yaml_payload() -> dict[str, object]:
    """Load the YAML payload once per module — single source of truth."""
    return yaml.safe_load(_PAYLOAD_PATH.read_text())


@pytest.fixture(scope="module")
def redis_url() -> Iterator[str]:
    """Module-scoped Redis container — one boot per adversarial run."""
    with RedisContainer("redis:7-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest_asyncio.fixture
async def cap(redis_url: str, yaml_payload: dict[str, object]) -> AsyncIterator[HandleCap]:
    """HandleCap configured exactly as the YAML payload declares.

    Per-test fixture so each test starts from a clean cap object (the
    Redis container is module-scoped — keyspaces are isolated by the
    unique ``user_id`` each test uses).
    """
    payload = yaml_payload["payload"]
    assert isinstance(payload, dict)
    cap_per_user = payload["cap_per_user"]
    assert isinstance(cap_per_user, int)
    hc = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=cap_per_user))
    try:
        yield hc
    finally:
        await hc.aclose()


def _unique_user_id() -> str:
    """Unique user id per test — module-scoped Redis keys MUST NOT collide.

    Uses the YAML's declared user_id prefix plus a monotonic nanosecond
    suffix so the YAML signature is visible in any failing-test debug
    output AND the keyspace is isolated.
    """
    return f"attacker-user-1-{time.monotonic_ns()}"


def _unique_handle_id() -> str:
    """Pre-minted UUID4 — matches the dispatcher's contract."""
    return str(uuid.uuid4())


@pytest.mark.asyncio
async def test_six_concurrent_reserves_refuse_the_sixth(
    cap: HandleCap, yaml_payload: dict[str, object]
) -> None:
    """``concurrent_requests=6`` against ``cap_per_user=5`` →
    exactly 5 succeed, the 6th raises
    ``WebFetchRateLimited(bucket='handle_cap')``.

    This is the executable counterpart to the YAML's `attack_steps`
    lines 1-3: 6 concurrent attempts, 5 succeed, 1 fails. The race
    is structural — Lua-atomic ZADD inside Redis is the gate, not the
    asyncio scheduling order. The YAML's burst size (6/6 endpoints) is
    sized so the cap binds before the per-user 30/min rate limit can
    intercept (that's a different bucket).
    """
    payload = yaml_payload["payload"]
    assert isinstance(payload, dict)
    cap_per_user = payload["cap_per_user"]
    concurrent = payload["concurrent_requests"]
    assert isinstance(cap_per_user, int)
    assert isinstance(concurrent, int)
    assert concurrent == cap_per_user + 1, (
        "YAML payload no longer describes a +1 burst over the cap; "
        "the cap-binding-not-rate-limit invariant has drifted"
    )

    user_id = _unique_user_id()
    results: list[bool | WebFetchRateLimited] = []

    async def attempt() -> None:
        try:
            await cap.try_reserve(
                user_id=user_id,
                handle_id=_unique_handle_id(),
                handle_ttl_seconds=80,
            )
            results.append(True)
        except WebFetchRateLimited as e:
            results.append(e)

    async with asyncio.TaskGroup() as tg:
        for _ in range(concurrent):
            tg.create_task(attempt())

    successes = [r for r in results if r is True]
    failures = [r for r in results if isinstance(r, WebFetchRateLimited)]

    # Exactly `cap_per_user` successes; the rest refused.
    assert len(successes) == cap_per_user, (
        f"expected exactly {cap_per_user} successes, got {len(successes)}: {results}"
    )
    assert len(failures) == concurrent - cap_per_user, (
        f"expected {concurrent - cap_per_user} cap refusals, got {len(failures)}: {results}"
    )
    # YAML asserts the closed-vocabulary bucket name on the refusal.
    for failure in failures:
        assert failure.bucket == "handle_cap", (
            f"refused with wrong bucket: {failure.bucket!r} "
            f"(YAML pins 'handle_cap' as the binding limit)"
        )


@pytest.mark.asyncio
async def test_redis_keyspace_bounded_to_cap(
    cap: HandleCap, yaml_payload: dict[str, object]
) -> None:
    """``attack_steps`` line 3: "Verify Redis content keyspace for the
    user is bounded to exactly 5 keys".

    After the 6-against-5 burst, the per-user ZSET MUST hold exactly
    ``cap_per_user`` members — the Lua-atomic ZADD inside the script
    is the gate; ZCARD after the burst is the structural proof.
    """
    payload = yaml_payload["payload"]
    assert isinstance(payload, dict)
    cap_per_user = payload["cap_per_user"]
    concurrent = payload["concurrent_requests"]
    assert isinstance(cap_per_user, int)
    assert isinstance(concurrent, int)

    user_id = _unique_user_id()

    async def attempt() -> None:
        with contextlib.suppress(WebFetchRateLimited):
            await cap.try_reserve(
                user_id=user_id,
                handle_id=_unique_handle_id(),
                handle_ttl_seconds=80,
            )

    async with asyncio.TaskGroup() as tg:
        for _ in range(concurrent):
            tg.create_task(attempt())

    client = await cap._get_client()
    card = await client.zcard(f"alfred:handles:user:{user_id}")
    assert card == cap_per_user, (
        f"per-user keyspace not bounded: ZCARD={card}, "
        f"YAML pins exactly {cap_per_user} keys after the burst"
    )


def test_yaml_expected_audit_row_matches_closed_vocabulary(
    yaml_payload: dict[str, object],
) -> None:
    """The YAML's ``expected_audit_row`` block declares the closed
    vocabulary that the dispatcher's cap-refusal arm emits. Pin the
    three field values against the canonical schema source so a
    schema drift on either side surfaces here (and not at a downstream
    audit-graph consumer).

    This test pulls no Redis fixture — it's a structural cross-check
    between the YAML payload's declaration and the static
    ``DlpScanResult`` Literal in ``audit_row_schemas.py``.
    """
    from alfred.audit.audit_row_schemas import DlpScanResult, RateLimitBucket

    payload = yaml_payload["payload"]
    assert isinstance(payload, dict)
    expected = payload["expected_audit_row"]
    assert isinstance(expected, dict)

    assert expected["event"] == "tool.web.fetch"
    assert expected["rate_limit_bucket"] == "handle_cap"
    assert expected["dlp_scan_result"] == "handle_cap_exceeded"
    assert expected["result"] == "rate_limited"

    # Structural pin: both closed-vocabulary values MUST appear in the
    # schema Literals. A schema migration that removes either tag
    # fails loud here BEFORE the dispatcher's cap-refusal audit row
    # raises a Pydantic validation error at runtime.
    from typing import get_args

    assert "handle_cap" in get_args(RateLimitBucket)
    assert "handle_cap_exceeded" in get_args(DlpScanResult)


@pytest.mark.asyncio
async def test_dispatcher_audit_path_emits_cap_refusal_row(
    redis_url: str, yaml_payload: dict[str, object]
) -> None:
    """CR-156-r1 (T11): drive the real :func:`dispatch_web_fetch` with a
    real :class:`HandleCap` and assert the cap-refusal audit row reaches
    the audit sink.

    The lower-level tests
    (:func:`test_six_concurrent_reserves_refuse_the_sixth`,
    :func:`test_redis_keyspace_bounded_to_cap`) pin the cap primitive,
    but they bypass the dispatcher — the audit-row emission, the closed
    vocabulary tagging, and the cap-refusal-before-network-roundtrip
    contract live in :mod:`alfred.plugins.web_fetch.fetch_dispatcher`. A
    silent regression in the dispatcher's cap-refusal arm (audit row
    skipped, wrong tag, network round-trip before refusal) would
    previously have escaped the YAML's contract; this test closes the
    gap.

    Drives 6 dispatches against ``cap_per_user=5``: 5 ContentHandles
    return, 1 raises ``WebFetchRateLimited(bucket='handle_cap')``, and
    the audit sink captures exactly one cap-refusal row.
    """
    from datetime import UTC, datetime
    from unittest.mock import AsyncMock, MagicMock

    from alfred.plugins.web_fetch.allowlist import AllowlistEntry
    from alfred.plugins.web_fetch.fetch_dispatcher import (
        FetchDispatchConfig,
        dispatch_web_fetch,
    )
    from alfred.security.quarantine import ContentHandle

    payload = yaml_payload["payload"]
    assert isinstance(payload, dict)
    cap_per_user = payload["cap_per_user"]
    concurrent = payload["concurrent_requests"]
    assert isinstance(cap_per_user, int)
    assert isinstance(concurrent, int)

    cap = HandleCap(redis_url=redis_url, config=HandleCapConfig(per_user=cap_per_user))
    try:
        user_id = _unique_user_id()
        correlation_id = "corr-cr156-r1-t11"
        url = "https://example.com/page"

        # Transport returns a ContentHandle whose id matches the
        # host-pre-minted handle_id (dispatcher's host-side equality
        # check). The test patches ``uuid.uuid4`` per-call so the cap
        # uses a fresh id each dispatch and the transport's returned
        # handle matches.
        transport = AsyncMock()

        async def _dispatch_returning_matching_handle(
            method: str,
            params: dict[str, object],
        ) -> ContentHandle:
            # The dispatcher passes the host-pre-minted UUID through as
            # ``params["content_handle_id"]``; the post-dispatch host-side
            # equality check (spec §3) refuses anything that drifts. Mirror
            # the plugin's contract: return a ContentHandle whose id is the
            # value the host pre-minted.
            assert method == "web.fetch"
            handle_id = params["content_handle_id"]
            assert isinstance(handle_id, str)
            return ContentHandle(
                id=handle_id,
                source_url=url,
                fetch_timestamp=datetime.now(tz=UTC),
            )

        transport.dispatch = AsyncMock(side_effect=_dispatch_returning_matching_handle)

        # OutboundDlp identity scan — keeps the URL unchanged through
        # the dispatcher's per-field scan loop.
        dlp = MagicMock()
        dlp.scan = MagicMock(side_effect=lambda s: s)

        # Rate-limiter does NOT refuse — the cap is the binding limit
        # under test (YAML burst is sized so per_user 30/min doesn't bind).
        rate_limiter = AsyncMock()
        rate_limiter.check_and_increment = AsyncMock(return_value=None)

        audit = AsyncMock()
        audit.append_schema = AsyncMock(return_value=None)

        config = FetchDispatchConfig(
            manifest_allowed_entries=(AllowlistEntry(domain="example.com"),),
            operator_allowed_entries=(AllowlistEntry(domain="example.com"),),
            session_allowed_entries=(AllowlistEntry(domain="example.com"),),
            manifest_commit_hash="cr156-r1-t11",
            redis_url=redis_url,
            skip_tls_verify=False,
        )

        successes = 0
        refusals: list[WebFetchRateLimited] = []
        for _ in range(concurrent):
            try:
                handle = await dispatch_web_fetch(
                    url=url,
                    headers={"User-Agent": "alfred"},
                    user_id=user_id,
                    correlation_id=correlation_id,
                    config=config,
                    rate_limiter=rate_limiter,
                    outbound_dlp=dlp,
                    audit=audit,
                    transport=transport,
                    handle_cap=cap,
                )
                assert isinstance(handle, ContentHandle)
                successes += 1
            except WebFetchRateLimited as e:
                refusals.append(e)

        assert successes == cap_per_user, (
            f"expected exactly {cap_per_user} successes, got {successes}"
        )
        assert len(refusals) == concurrent - cap_per_user, (
            f"expected {concurrent - cap_per_user} refusals, got {len(refusals)}"
        )
        for refusal in refusals:
            assert refusal.bucket == "handle_cap"
        assert transport.dispatch.await_count == cap_per_user, (
            "the refused dispatch must short-circuit before the plugin call"
        )

        # Audit sink: exactly one cap-refusal row, tagged with the
        # closed-vocabulary handle_cap discriminators. The success
        # dispatches each emit their own ``result="ok"`` row; the
        # refusal arm is the one we pin here.
        cap_refusal_calls = [
            call
            for call in audit.append_schema.await_args_list
            if call.kwargs.get("subject", {}).get("rate_limit_bucket") == "handle_cap"
        ]
        assert len(cap_refusal_calls) == 1, (
            f"expected exactly one cap-refusal audit row, got {len(cap_refusal_calls)}"
        )
        refusal_call = cap_refusal_calls[0]
        subject = refusal_call.kwargs["subject"]
        assert subject["rate_limit_bucket"] == "handle_cap"
        assert subject["dlp_scan_result"] == "handle_cap_exceeded"
        assert refusal_call.kwargs["result"] == "rate_limited"
        # The refusal happens BEFORE the plugin call — the
        # content_handle_id field is None because the pre-minted UUID
        # for the refused dispatch was never written to Redis.
        assert subject["content_handle_id"] is None
    finally:
        await cap.aclose()
