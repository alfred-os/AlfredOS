"""Shared test doubles for ``process_inbound_message`` unit tests (PR-S4-8).

The inbound entrypoint funnels through three injected dependencies — the
identity resolver, the orchestrator (extract/ingest/dispatch), and the burst
limiter — plus the audit writer. These spies record call order and kwargs so
the load-bearing ordering invariant (resolution -> burst-gate ->
quarantined_extract -> ingest -> dispatch) is assertable.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from alfred.comms_mcp.inbound import ResolvedInbound
from alfred.orchestrator.burst_limiter import Acquired, Dropped
from alfred.security.quarantine import Extracted, ExtractionResult, T3DerivedData


def make_resolved(
    *,
    canonical_user_id: str = "u_resolved",
    persona: str = "alfred",
    language: str = "en-US",
    adapter_id: str = "alfred_comms_test",
    display_name: str = "Test User",
) -> ResolvedInbound:
    return ResolvedInbound(
        canonical_user_id=canonical_user_id,
        persona=persona,
        language=language,
        adapter_id=adapter_id,
        display_name=display_name,
    )


class SpyIdentityResolver:
    """Records ``resolve`` calls; returns a fixed result (or ``None``)."""

    def __init__(self, *, returns: ResolvedInbound | None) -> None:
        self._returns = returns
        self.resolve_calls = 0
        self.last_call_kwargs: dict[str, Any] = {}

    async def resolve(self, *, adapter_id: str, platform_user_id: str) -> ResolvedInbound | None:
        self.resolve_calls += 1
        self.last_call_kwargs = {
            "adapter_id": adapter_id,
            "platform_user_id": platform_user_id,
        }
        return self._returns


class SpyOrchestrator:
    """Records extract/ingest/dispatch call order + kwargs."""

    def __init__(
        self,
        *,
        call_order: list[str] | None = None,
        extract_result: ExtractionResult | None = None,
    ) -> None:
        self.call_order = call_order if call_order is not None else []
        self.quarantined_extract_calls = 0
        self.ingest_calls = 0
        self.dispatch_calls = 0
        self.last_extract_kwargs: dict[str, Any] = {}
        self.last_ingest_kwargs: dict[str, Any] = {}
        self._extract_result = extract_result or Extracted(
            data=T3DerivedData({"content": "hi"}),
            extraction_mode="native_constrained",
        )

    async def quarantined_extract(
        self, body: object, *, canonical_user_id: str, source_tier: str
    ) -> ExtractionResult:
        self.quarantined_extract_calls += 1
        self.call_order.append("extract")
        self.last_extract_kwargs = {
            "body": body,
            "canonical_user_id": canonical_user_id,
            "source_tier": source_tier,
        }
        return self._extract_result

    async def ingest(self, **kwargs: Any) -> object:
        self.ingest_calls += 1
        self.call_order.append("ingest")
        self.last_ingest_kwargs = kwargs
        return {"ingested": True}

    async def dispatch(self, ingested: object) -> None:
        self.dispatch_calls += 1
        self.call_order.append("dispatch")


class SpyBurstLimiter:
    """Records ``acquire`` order; returns ``Acquired`` (or ``Dropped``)."""

    def __init__(
        self,
        *,
        call_order: list[str] | None = None,
        result: Acquired | Dropped | None = None,
    ) -> None:
        self.call_order = call_order if call_order is not None else []
        self.acquire_calls = 0
        self.last_acquire_kwargs: dict[str, Any] = {}
        self._result: Acquired | Dropped = result or Acquired(
            tokens_remaining=4, waited_seconds=0.0
        )

    async def acquire(
        self,
        *,
        canonical_user_id: str,
        persona: str,
        adapter_id: str = "unknown",
        language: str = "en-US",
    ) -> Acquired | Dropped:
        self.acquire_calls += 1
        self.call_order.append("burst")
        self.last_acquire_kwargs = {
            "canonical_user_id": canonical_user_id,
            "persona": persona,
            "adapter_id": adapter_id,
            "language": language,
        }
        return self._result


class SpyAuditWriter:
    """Records audit-row emissions with symmetric key validation."""

    def __init__(self) -> None:
        self.schema_rows: list[dict[str, Any]] = []
        self.event_rows: list[dict[str, Any]] = []

    async def append_schema(
        self,
        *,
        fields: frozenset[str],
        schema_name: str,
        event: str,
        subject: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        missing = fields - subject.keys()
        extra = subject.keys() - fields
        if missing or extra:
            raise AssertionError(
                f"append_schema {schema_name}: missing={sorted(missing)} extra={sorted(extra)}"
            )
        # ``trace_id`` is a persisted, indexed column — captured here so leak
        # tests (sec-010) can prove the raw platform_user_id never lands on it.
        # ``trust_tier_of_trigger`` is captured so provenance tests can assert the
        # trigger tier (e.g. a plugin-triggered crash row must be T3, not T0).
        # ``result`` is captured so provenance tests can pin the closed-vocab
        # disposition (e.g. a replay row must be ``"dropped"``, never ``"success"``).
        self.schema_rows.append(
            {
                "schema_name": schema_name,
                "event": event,
                "trace_id": kwargs.get("trace_id"),
                "trust_tier_of_trigger": kwargs.get("trust_tier_of_trigger"),
                "result": kwargs.get("result"),
                **subject,
            }
        )

    async def append(self, *, event: str, subject: dict[str, Any], **kwargs: Any) -> None:
        self.event_rows.append({"event": event, **subject})

    def rows_with_schema(self, schema_name: str) -> list[dict[str, Any]]:
        return [r for r in self.schema_rows if r["schema_name"] == schema_name]

    def rows_with_event(self, event: str) -> list[dict[str, Any]]:
        return [r for r in self.event_rows if r["event"] == event]


class SpySecretBroker:
    """Returns a fixed pepper for ``audit.hash_pepper``."""

    def __init__(self, *, pepper: str = "test-pepper-32-bytes-long-enough!") -> None:
        self._pepper = pepper
        self.get_calls = 0

    def get(self, name: str) -> str:
        self.get_calls += 1
        if name != "audit.hash_pepper":
            raise KeyError(name)
        return self._pepper


def make_notification(
    *,
    adapter_id: str = "alfred_comms_test",
    inbound_id: str | None = None,
    platform_user_id: str = "discord:victim",
    body: dict[str, object] | None = None,
    addressing_signal: str = "dm",
    wire_seq: int | None = None,
) -> Any:
    from alfred.comms_mcp.protocol import InboundMessageNotification

    return InboundMessageNotification(
        adapter_id=adapter_id,
        # Spec A G0 wire field. Defaults to a fresh per-call id so existing callers
        # (the corpus, the inbound unit tests) stay green without edits; the
        # idempotency tests pin a fixed id to drive the replay path deterministically.
        inbound_id=inbound_id or uuid.uuid4().hex,
        platform_user_id=platform_user_id,
        body=body if body is not None else {"content": "hello"},
        sub_payload_refs=(),
        received_at=datetime.now(UTC),
        addressing_signal=addressing_signal,  # type: ignore[arg-type]
        # Spec A G4b-2a-pre: the carrier out-of-band wire seq. ``None`` (the default)
        # for stdio / un-sequenced callers, so existing tests stay byte-for-byte; the
        # durable-intake-ack tests pin a value to drive ``observe``.
        wire_seq=wire_seq,
    )
