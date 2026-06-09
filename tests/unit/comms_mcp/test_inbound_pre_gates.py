"""Pre-resolution + cheap-validate gates (sec-003 / perf-003).

Two coarse gates run BEFORE the resolver:

* :func:`_inbound_message_cheap_validate` rejects empty / oversized payloads
  before any expensive work (perf-003);
* :class:`_PreResolutionLimiter` caps per-``(adapter_id, platform_user_id_hash)``
  request rate so an unbound-user flood cannot drive unbounded resolver lookups
  (sec-003). A cap emits ``COMMS_INBOUND_BUDGET_CAPPED_FIELDS(dropped=True)`` and
  refuses without calling the resolver.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from alfred.comms_mcp.inbound import (
    _inbound_message_cheap_validate,
    _PreResolutionLimiter,
    process_inbound_message,
)

from ._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)


def test_cheap_validate_rejects_empty_platform_user_id() -> None:
    assert not _inbound_message_cheap_validate(platform_user_id="", body={"x": 1})


def test_cheap_validate_rejects_oversized_platform_user_id() -> None:
    assert not _inbound_message_cheap_validate(platform_user_id="x" * 1000, body={"x": 1})


def test_cheap_validate_rejects_non_string_id() -> None:
    assert not _inbound_message_cheap_validate(platform_user_id=123, body={"x": 1})


def test_cheap_validate_rejects_non_mapping_body() -> None:
    assert not _inbound_message_cheap_validate(platform_user_id="discord:1", body="x")


def test_cheap_validate_accepts_valid() -> None:
    assert _inbound_message_cheap_validate(platform_user_id="discord:1", body={"x": 1})


def test_pre_resolution_limiter_caps_after_budget() -> None:
    clock = [0.0]
    limiter = _PreResolutionLimiter(limit_per_minute=2, monotonic=lambda: clock[0])
    assert limiter.check_and_record(adapter_id="a", platform_user_id_hash="h")
    assert limiter.check_and_record(adapter_id="a", platform_user_id_hash="h")
    assert not limiter.check_and_record(adapter_id="a", platform_user_id_hash="h")


def test_pre_resolution_limiter_ages_out() -> None:
    clock = [0.0]
    limiter = _PreResolutionLimiter(
        limit_per_minute=1, window_seconds=60.0, monotonic=lambda: clock[0]
    )
    assert limiter.check_and_record(adapter_id="a", platform_user_id_hash="h")
    assert not limiter.check_and_record(adapter_id="a", platform_user_id_hash="h")
    clock[0] += 61.0
    assert limiter.check_and_record(adapter_id="a", platform_user_id_hash="h")


def test_pre_resolution_limiter_independent_keys() -> None:
    limiter = _PreResolutionLimiter(limit_per_minute=1)
    assert limiter.check_and_record(adapter_id="a", platform_user_id_hash="h1")
    assert limiter.check_and_record(adapter_id="a", platform_user_id_hash="h2")


def test_pre_resolution_limiter_evicts_lru() -> None:
    limiter = _PreResolutionLimiter(limit_per_minute=99, max_tracked_keys=2)
    for i in range(5):
        limiter.check_and_record(adapter_id="a", platform_user_id_hash=f"h{i}")
    assert len(limiter._hits) <= 2


@pytest.mark.asyncio
async def test_process_refuses_on_pre_resolution_cap() -> None:
    audit = SpyAuditWriter()
    resolver = SpyIdentityResolver(returns=make_resolved())
    # A limiter pre-loaded to its cap for the only key this notification hits.
    limiter = _PreResolutionLimiter(limit_per_minute=0)
    await process_inbound_message(
        make_notification(),
        identity_resolver=resolver,
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
        pre_resolution_limiter=limiter,
    )
    assert resolver.resolve_calls == 0
    rows = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["dropped"] is True


@pytest.mark.asyncio
async def test_process_refuses_empty_platform_user_id_before_resolver() -> None:
    # Construct a notification then bypass cheap-validate via a forged body type.
    audit = SpyAuditWriter()
    resolver = SpyIdentityResolver(returns=make_resolved())

    class _BadBodyNotification:
        adapter_id = "alfred_comms_test"
        platform_user_id = ""  # empty -> cheap validate refuses
        body: ClassVar[dict[str, object]] = {"content": "x"}
        sub_payload_refs: ClassVar[tuple[str, ...]] = ()
        addressing_signal = "dm"

    await process_inbound_message(
        _BadBodyNotification(),  # type: ignore[arg-type]
        identity_resolver=resolver,
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
    )
    assert resolver.resolve_calls == 0
