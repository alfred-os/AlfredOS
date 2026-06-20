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

import inspect
from typing import Any

import pytest

from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler
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
    # CR #232: assert ``process`` is an async coroutine function, not merely
    # present -- so a regression to a sync callable / property fails the contract.
    for proto in (InboundHandler, BindingHandler, RateLimitHandler, CrashHandler):
        process = getattr(proto, "process", None)
        assert process is not None
        assert inspect.iscoroutinefunction(process)


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


@pytest.mark.asyncio
async def test_inbound_handler_pre_resolution_limiter_persists_across_messages() -> None:
    """sec-003: the pre-resolution DoS gate accumulates across messages.

    The headline bug (CR #232): when ``process_inbound_message`` built a fresh
    ``_PreResolutionLimiter`` on every call, the coarse per-``(adapter_id,
    platform_user_id_hash)`` budget never accumulated, so the gate was a no-op
    in production. Driving a flood for ONE platform user through the SAME
    ``InboundMessageHandler`` (the real production caller — NO hand-passed
    limiter) MUST eventually refuse: the resolver stops being consulted and a
    budget-capped audit row is emitted. The handler owns one persistent limiter.
    """
    resolver = SpyIdentityResolver(returns=make_resolved())
    orch = SpyOrchestrator()
    audit = SpyAuditWriter()
    handler = InboundMessageHandler(
        identity_resolver=resolver,
        orchestrator=orch,
        burst_limiter=SpyBurstLimiter(),
        audit_writer=audit,
        secret_broker=SpySecretBroker(),
    )

    # The default cap is 50/min; drive well past it for one platform user.
    flood = 60
    for _ in range(flood):
        await handler.process(make_notification(platform_user_id="discord:flooder"))

    # The gate fired: the resolver was NOT consulted for every message, and at
    # least one message was hard-dropped pre-resolution.
    assert resolver.resolve_calls < flood
    capped = audit.rows_with_schema("COMMS_INBOUND_BUDGET_CAPPED_FIELDS")
    assert capped, "pre-resolution gate never refused despite a flood"
    assert all(row["dropped"] is True for row in capped)


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


def _make_crash_handler(
    audit: SpyAuditWriter,
    invoker: _SpyHookInvoker,
    *,
    reconciler: CrashIncidentReconciler | None = None,
) -> AdapterCrashHandler:
    return AdapterCrashHandler(
        audit_writer=audit,
        hook_invoker=invoker,
        reconciler=reconciler if reconciler is not None else CrashIncidentReconciler(),
    )


@pytest.mark.asyncio
async def test_crash_handler_emits_audit_and_fires_hookpoint() -> None:
    audit = SpyAuditWriter()
    invoker = _SpyHookInvoker()
    handler = _make_crash_handler(audit, invoker)
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
    # Provenance (PRD §7.1): the crash is plugin-triggered, so the trigger tier
    # is T3 -- not T0. (The hookpoint's carrier_tier stays T0 per spec §10; that
    # is the surrounding host-daemon action's tier, a distinct concept.)
    assert rows[0]["trust_tier_of_trigger"] == "T3"
    assert invoker.fired == ["alfred_comms_test"]


@pytest.mark.asyncio
async def test_in_child_crash_folds_and_carries_incident_fields() -> None:
    audit = SpyAuditWriter()
    reconciler = CrashIncidentReconciler()
    handler = _make_crash_handler(audit, _SpyHookInvoker(), reconciler=reconciler)
    await handler.process(
        CrashedNotification(adapter_id="discord", error_class="ValueError", detail="boom")
    )
    row = audit.rows_with_schema("COMMS_ADAPTER_CRASHED_FIELDS")[0]
    assert row["event"] == "comms.adapter.crashed"
    assert row["crash_signal_source"] == "child"
    assert row["crash_incident_id"]
    assert row["duplicate"] is False
    assert "host_restart_seq" not in row  # in-child row carries no seq
    assert len(reconciler.incidents("discord")) == 1


@pytest.mark.asyncio
async def test_in_child_duplicate_crash_still_audited_and_flagged() -> None:
    # TE-1/TE-3: a SECOND in-child crash for the same incarnation is folded (one
    # incident) but STILL audited, flagged duplicate (hard rule #7 at the handler).
    audit = SpyAuditWriter()
    reconciler = CrashIncidentReconciler()
    handler = _make_crash_handler(audit, _SpyHookInvoker(), reconciler=reconciler)
    note = CrashedNotification(adapter_id="discord", error_class="ValueError", detail="boom")
    await handler.process(note)
    await handler.process(note)
    rows = audit.rows_with_schema("COMMS_ADAPTER_CRASHED_FIELDS")
    assert len(rows) == 2  # both loud, neither dropped
    assert rows[0]["duplicate"] is False
    assert rows[1]["duplicate"] is True
    assert rows[0]["crash_incident_id"] == rows[1]["crash_incident_id"]
    assert len(reconciler.incidents("discord")) == 1


@pytest.mark.asyncio
async def test_crash_handler_rescrubs_secret_shaped_detail() -> None:
    """M1 canary: the host re-scrubs the UNTRUSTED plugin's crash detail.

    The plugin is T3 — its claim to have redacted ``detail`` is untrustworthy
    and the CrashedNotification docstring says the host re-scrubs. A planted
    ``sk-…``-shaped token must NOT survive into the crashed audit row.
    """
    audit = SpyAuditWriter()
    handler = _make_crash_handler(audit, _SpyHookInvoker())
    # Synthetic API-key-shaped canary (24 alnum bytes); not a real secret.
    canary_token = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"  # noqa: S105
    notification = CrashedNotification(
        adapter_id="alfred_comms_test",
        error_class="RuntimeError",
        detail=f"boom leaked {canary_token} here",
    )
    await handler.process(notification)
    detail = audit.rows_with_schema("COMMS_ADAPTER_CRASHED_FIELDS")[0]["detail_redacted"]
    assert canary_token not in detail
    assert "[REDACTED:api-key-shape]" in detail
