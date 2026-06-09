"""Handler protocols + concrete classes (Tasks 33-34).

The four ``@runtime_checkable`` protocols (``InboundHandler``, ``BindingHandler``,
``RateLimitHandler``, ``CrashHandler``) each declare
``async def process(self, notification) -> None``. The concrete classes
(``InboundMessageHandler`` etc.) implement them:

* inbound  -> ``process_inbound_message``
* binding  -> emits ``COMMS_BINDING_REQUESTED_FIELDS``
* rate-limit-> comms-001: absorb signal + global-scope breaker trip
  + ``COMMS_RATE_LIMIT_SIGNAL_FIELDS`` audit row
* crash    -> ``COMMS_ADAPTER_CRASHED_FIELDS`` + ``comms.adapter.crashed``
"""

from __future__ import annotations

from typing import Any

import pytest

from alfred.comms_mcp.handlers import (
    AdapterCrashHandler,
    BindingHandler,
    BindingRequestHandler,
    CrashHandler,
    InboundHandler,
    InboundMessageHandler,
    PlatformRateLimitHandler,
    RateLimitHandler,
)
from alfred.comms_mcp.protocol import (
    BindingRequestNotification,
    CrashedNotification,
    RateLimitSignal,
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

# --- protocol shape ---------------------------------------------------------


def test_protocols_declare_process() -> None:
    for proto in (InboundHandler, BindingHandler, RateLimitHandler, CrashHandler):
        assert hasattr(proto, "process")


# --- InboundHandler ---------------------------------------------------------


def _make_inbound(orch: SpyOrchestrator) -> InboundMessageHandler:
    return InboundMessageHandler(
        identity_resolver=SpyIdentityResolver(returns=make_resolved()),
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=SpyAuditWriter(),
        secret_broker=SpySecretBroker(),
    )


@pytest.mark.asyncio
async def test_inbound_handler_delegates_to_process_inbound_message() -> None:
    orch = SpyOrchestrator()
    handler = _make_inbound(orch)
    assert isinstance(handler, InboundHandler)
    await handler.process(make_notification())
    assert orch.quarantined_extract_calls == 1
    assert orch.dispatch_calls == 1


# --- BindingHandler ---------------------------------------------------------


@pytest.mark.asyncio
async def test_binding_handler_emits_binding_request() -> None:
    audit = SpyAuditWriter()
    handler = BindingRequestHandler(audit_writer=audit, secret_broker=SpySecretBroker())
    assert isinstance(handler, BindingHandler)
    notification = BindingRequestNotification(
        adapter_id="alfred_comms_test",
        platform_user_id="discord:victim",
        verification_phrase="banana phone 7",
        platform_metadata={"username": "alice"},
    )
    await handler.process(notification)
    rows = audit.rows_with_schema("COMMS_BINDING_REQUESTED_FIELDS")
    assert len(rows) == 1
    assert "discord:victim" not in str(rows[0])
    assert "banana phone 7" not in str(rows[0])


# --- RateLimitHandler (comms-001) -------------------------------------------


class _SpyBreakerTripper:
    def __init__(self) -> None:
        self.trip_calls: list[dict[str, Any]] = []

    async def trip_comms_breaker(self, *, adapter_id: str, reason: str) -> None:
        self.trip_calls.append({"adapter_id": adapter_id, "reason": reason})


@pytest.mark.asyncio
async def test_rate_limit_handler_emits_audit_no_trip_on_short_retry() -> None:
    audit = SpyAuditWriter()
    tripper = _SpyBreakerTripper()
    handler = PlatformRateLimitHandler(breaker_tripper=tripper, audit_writer=audit)
    assert isinstance(handler, RateLimitHandler)
    signal = RateLimitSignal(
        adapter_id="alfred_comms_test",
        retry_after_seconds=5,
        platform_endpoint="gateway",
    )
    await handler.process(signal)
    rows = audit.rows_with_schema("COMMS_RATE_LIMIT_SIGNAL_FIELDS")
    assert len(rows) == 1
    assert rows[0]["retry_after_seconds"] == 5
    assert tripper.trip_calls == []


@pytest.mark.asyncio
async def test_rate_limit_handler_trips_breaker_on_long_retry() -> None:
    audit = SpyAuditWriter()
    tripper = _SpyBreakerTripper()
    handler = PlatformRateLimitHandler(breaker_tripper=tripper, audit_writer=audit)
    signal = RateLimitSignal(
        adapter_id="alfred_comms_test",
        retry_after_seconds=31,  # > 30s threshold (comms-001)
        platform_endpoint="gateway",
    )
    await handler.process(signal)
    assert len(tripper.trip_calls) == 1
    assert tripper.trip_calls[0]["adapter_id"] == "alfred_comms_test"
    assert tripper.trip_calls[0]["reason"] == "comms.rate_limit.exhausted"


# --- CrashHandler -----------------------------------------------------------


class _SpyHookInvoker:
    def __init__(self) -> None:
        self.fired: list[str] = []

    async def fire_adapter_crashed(self, *, adapter_id: str, error_class: str) -> None:
        self.fired.append(adapter_id)


@pytest.mark.asyncio
async def test_crash_handler_emits_audit_and_fires_hookpoint() -> None:
    audit = SpyAuditWriter()
    invoker = _SpyHookInvoker()
    handler = AdapterCrashHandler(audit_writer=audit, hook_invoker=invoker)
    assert isinstance(handler, CrashHandler)
    notification = CrashedNotification(
        adapter_id="alfred_comms_test",
        error_class="ConnectionResetError",
        detail="some redacted detail",
    )
    await handler.process(notification)
    rows = audit.rows_with_schema("COMMS_ADAPTER_CRASHED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["error_class"] == "ConnectionResetError"
    assert invoker.fired == ["alfred_comms_test"]
