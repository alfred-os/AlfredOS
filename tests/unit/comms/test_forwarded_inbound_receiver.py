"""The core-side gateway-forwarded inbound receive trust boundary (Spec B G6-7-4).

ADR-0039 / #309. The :class:`GatewayForwardedInboundReceiver` is the highest-value
trust seam in the system: untrusted T3 crossing from the network-facing gateway
into the connectivity-free core. The gateway forwards a hosted adapter child's
``inbound.message`` as a :class:`GatewayAdapterInboundEnvelope`
(``{adapter_id, body}``); the receiver re-parses the opaque body core-side
(``reparse_forwarded_inbound`` is the ONLY body parser — SEC-309-1: the receiver
NEVER ``json.loads`` the body itself), admits it against the per-``adapter_id``
collaborator registry (K4), rebinds the REAL leg ``wire_seq``, and dispatches it
through ``process_inbound_message`` on the DISPATCHED edge
(``commit_at_dispatch_edge=True``).

These tests drive the receiver with an INJECTED fake ``dispatch`` so the unit does
not run the real pipeline; the dispatched-edge pipeline behaviour itself is covered
by ``tests/unit/comms/test_inbound_dispatched_edge.py``.

Invariants pinned here:

* **A HAPPY** — a well-formed discord notification dispatches with the DISCORD
  collaborator set, ``commit_at_dispatch_edge=True``, the SAME long-lived
  ``pre_resolution_limiter`` across two receive() calls, and the notification's
  ``wire_seq`` REBOUND to the REAL leg seq (not the body's scrubbed ``None``, not a
  body-smuggled value).
* **B/C/D terminal drops** — unknown-adapter (K4) + envelope/body mismatch are
  signed ``refused`` rows; a malformed body is a signed ``dropped`` row carrying
  ONLY a closed-vocab reason (never ``str(exc)``/the raw body). Each is followed by
  a drain ``observe(wire_seq)`` (ARCH-309-3 — never wedge a live contiguous-seq
  leg's high-water), and NO dispatch.
* **E routing** — the registry is queried with the ENVELOPE ``adapter_id``, never
  the body (SEC-309-1).
* **F fail-loud** — ``PromoterRequiredError`` (a misconfig the dispatch raises) is
  NOT caught; it propagates.
* **G audit-write failure** — a drop whose signed audit row fails to write does NOT
  drain (we never ACK an unrecorded drop) and PROPAGATES wrapped in the typed
  :class:`ForwardedInboundAuditWriteError` marker (chaining the raw backend error as
  its ``__cause__``) so Task 4's disposition discriminates it from a replayable fault
  and escalates a restart.
* **H order** — the signed audit write happens BEFORE the drain ``observe`` on every
  drop, so G short-circuits cleanly.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from alfred.audit import audit_row_schemas
from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.errors import ForwardedInboundAuditWriteError, PromoterRequiredError
from alfred.comms_mcp.forwarded_inbound_receiver import (
    GatewayForwardedInboundReceiver,
    _ForwardedCollaborators,
)
from tests.unit.comms_mcp._inbound_spies import (
    SpyAuditWriter,
    SpyBurstLimiter,
    SpyIdentityResolver,
    SpyOrchestrator,
    SpySecretBroker,
    make_notification,
    make_resolved,
)

pytestmark = pytest.mark.asyncio

# The single audit-write-failure marker the receiver MUST let propagate (Task 4's
# disposition arm escalates it). The receiver is agnostic to the exact class — it
# just never wraps/swallows an audit-write exception — so any sentinel exception a
# failing audit writer raises proves the propagation + no-drain invariant.
_AUDIT_WRITE_FAILED = RuntimeError("signed audit write failed")


def _discord_body(*, smuggled_wire_seq: int | None = None, **overrides: Any) -> bytes:
    """A well-formed ``InboundMessageNotification`` body the gateway forwards.

    ``adapter_id`` defaults to ``"discord"`` so it matches the envelope routing key
    on the happy path. ``smuggled_wire_seq`` lets a test plant a body-derived seq
    that the receiver MUST scrub-then-rebind (never trust).
    """
    notification = make_notification(
        adapter_id=overrides.pop("adapter_id", "discord"),
        body={"content": "hello there"},
        wire_seq=smuggled_wire_seq,
        **overrides,
    )
    return notification.model_dump_json().encode("utf-8")


def _envelope(*, adapter_id: str, body: bytes | str) -> dict[str, Any]:
    """The wire ``params`` of a ``gateway.adapter.inbound`` notification."""
    return {"adapter_id": adapter_id, "body": body}


class _SpyAckTracker:
    """Records ``observe(seq)`` calls so drain order/occurrence is assertable."""

    def __init__(self) -> None:
        self.observed: list[int] = []

    def observe(self, seq: int) -> None:
        self.observed.append(seq)


class _SpyIdempotencyStore:
    """A never-committed store: the dispatched-edge happy path needs only a read."""

    async def commit_once(self, *, inbound_id: str, adapter_id: str) -> bool:
        return True

    async def has_committed(self, *, inbound_id: str, adapter_id: str) -> bool:
        return False


class _RecordingDispatch:
    """An injected fake ``dispatch`` recording its call kwargs (no real pipeline)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, notification: Any, **kwargs: Any) -> None:
        self.calls.append({"notification": notification, **kwargs})


class _RaisingAuditWriter:
    """An audit writer whose ``append_schema`` always raises (drop-path failure).

    Used by the order/failure cases: every drop disposition's signed row goes
    through ``append_schema``, so this proves a failed write happens BEFORE (and
    short-circuits) the drain ``observe``.
    """

    def __init__(self) -> None:
        self.append_schema_calls = 0

    async def append_schema(self, **kwargs: Any) -> None:
        self.append_schema_calls += 1
        raise _AUDIT_WRITE_FAILED


def _discord_collaborators(*, pre_resolution_limiter: Any) -> _ForwardedCollaborators:
    """A non-None-promoter DISCORD collaborator set (the K4-admitted adapter)."""
    return _ForwardedCollaborators(
        sub_payload_promoter=object(),  # non-None: discord requires a promoter
        resolver_bridge=SpyIdentityResolver(returns=make_resolved(adapter_id="discord")),
        orchestrator=SpyOrchestrator(),
        burst_limiter=SpyBurstLimiter(),
        secret_broker=SpySecretBroker(),
        pre_resolution_limiter=pre_resolution_limiter,
    )


@pytest.fixture(autouse=True)
def _reset_audit_hash() -> Any:
    """Isolate the module-level comms audit-hash broker between tests."""
    audit_hash.reset_for_test()
    yield
    audit_hash.reset_for_test()


def _build_receiver(
    *,
    dispatch: Any,
    audit_writer: Any,
    pre_resolution_limiter: Any,
    ack_tracker: _SpyAckTracker | None = None,
) -> GatewayForwardedInboundReceiver:
    registry = {"discord": _discord_collaborators(pre_resolution_limiter=pre_resolution_limiter)}
    receiver = GatewayForwardedInboundReceiver(
        registry=registry,
        idempotency_store=_SpyIdempotencyStore(),
        audit_writer=audit_writer,
        dispatch=dispatch,
    )
    if ack_tracker is not None:
        receiver.set_ack_tracker(ack_tracker)
    return receiver


# --------------------------------------------------------------------------- #
# A HAPPY
# --------------------------------------------------------------------------- #


async def test_happy_dispatches_discord_collaborators_at_dispatch_edge() -> None:
    dispatch = _RecordingDispatch()
    audit_writer = SpyAuditWriter()
    limiter = object()  # long-lived sentinel — same object must reach both calls
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=limiter,
        ack_tracker=ack,
    )

    await receiver.receive(params=_envelope(adapter_id="discord", body=_discord_body()), wire_seq=7)

    assert len(dispatch.calls) == 1
    call = dispatch.calls[0]
    # The DISCORD collaborator set is threaded through, with the dispatched edge on.
    assert call["commit_at_dispatch_edge"] is True
    assert call["identity_resolver"] is receiver._registry["discord"].resolver_bridge
    assert call["orchestrator"] is receiver._registry["discord"].orchestrator
    assert call["burst_limiter"] is receiver._registry["discord"].burst_limiter
    assert call["secret_broker"] is receiver._registry["discord"].secret_broker
    assert call["sub_payload_promoter"] is receiver._registry["discord"].sub_payload_promoter
    assert call["pre_resolution_limiter"] is limiter
    assert call["audit_writer"] is audit_writer
    assert call["ack_tracker"] is ack
    assert call["idempotency_store"] is receiver._idempotency_store
    # No drop happened — the receiver does NOT drain on the dispatched path (the
    # pipeline owns the dispatched-edge observe).
    assert ack.observed == []


async def test_happy_rebinds_real_leg_wire_seq_not_body_value() -> None:
    dispatch = _RecordingDispatch()
    limiter = object()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=SpyAuditWriter(),
        pre_resolution_limiter=limiter,
    )

    # Body smuggles wire_seq=999; the REAL leg seq is 3. The dispatched notification
    # MUST carry 3, never the scrubbed None and never the smuggled 999.
    await receiver.receive(
        params=_envelope(adapter_id="discord", body=_discord_body(smuggled_wire_seq=999)),
        wire_seq=3,
    )

    assert dispatch.calls[0]["notification"].wire_seq == 3


async def test_happy_same_long_lived_limiter_across_two_receives() -> None:
    dispatch = _RecordingDispatch()
    limiter = object()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=SpyAuditWriter(),
        pre_resolution_limiter=limiter,
    )

    await receiver.receive(params=_envelope(adapter_id="discord", body=_discord_body()), wire_seq=1)
    await receiver.receive(params=_envelope(adapter_id="discord", body=_discord_body()), wire_seq=2)

    assert len(dispatch.calls) == 2
    assert dispatch.calls[0]["pre_resolution_limiter"] is limiter
    assert dispatch.calls[1]["pre_resolution_limiter"] is limiter


async def test_happy_with_no_ack_tracker_still_dispatches() -> None:
    """A receiver whose per-connection ack tracker was never set still dispatches.

    The dispatched-edge observe is the pipeline's job; the receiver's None tracker
    is forwarded to the dispatch and is the receiver's drain no-op on drops.
    """
    dispatch = _RecordingDispatch()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=SpyAuditWriter(),
        pre_resolution_limiter=object(),
    )

    await receiver.receive(params=_envelope(adapter_id="discord", body=_discord_body()), wire_seq=5)

    assert len(dispatch.calls) == 1
    assert dispatch.calls[0]["ack_tracker"] is None


# --------------------------------------------------------------------------- #
# B UNKNOWN ADAPTER (K4)
# --------------------------------------------------------------------------- #


async def test_unknown_adapter_refuses_audits_and_drains() -> None:
    dispatch = _RecordingDispatch()
    audit_writer = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=object(),
        ack_tracker=ack,
    )

    # "alfred_comms_test" is a valid AdapterId KIND but NOT in the registry (which
    # holds only "discord") → K4 unknown-adapter. The body is never parsed (K4
    # short-circuits before reparse), so plain bytes suffice.
    await receiver.receive(
        params=_envelope(adapter_id="alfred_comms_test", body=b"unparsed"),
        wire_seq=11,
    )

    assert dispatch.calls == []
    rows = audit_writer.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["adapter_id"] == "alfred_comms_test"
    assert rows[0]["reason"] == "unknown_adapter"
    assert rows[0]["result"] == "refused"
    assert rows[0]["trust_tier_of_trigger"] == "T3"
    # Drained: a live contiguous-seq leg must not wedge on a refused frame.
    assert ack.observed == [11]


# --------------------------------------------------------------------------- #
# C ENVELOPE/BODY MISMATCH
# --------------------------------------------------------------------------- #


async def test_envelope_body_mismatch_refuses_audits_and_drains() -> None:
    dispatch = _RecordingDispatch()
    audit_writer = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=object(),
        ack_tracker=ack,
    )

    # Envelope routes to "discord" (registry hit) but the body claims "tui" — the
    # reparse equality check raises InboundEnvelopeBodyMismatchError.
    await receiver.receive(
        params=_envelope(adapter_id="discord", body=_discord_body(adapter_id="tui")),
        wire_seq=13,
    )

    assert dispatch.calls == []
    rows = audit_writer.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["adapter_id"] == "discord"
    assert rows[0]["reason"] == "envelope_body_mismatch"
    assert rows[0]["result"] == "refused"
    assert ack.observed == [13]


# --------------------------------------------------------------------------- #
# D MALFORMED BODY
# --------------------------------------------------------------------------- #


async def test_malformed_body_drops_audits_and_drains_without_raising() -> None:
    dispatch = _RecordingDispatch()
    audit_writer = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=object(),
        ack_tracker=ack,
    )

    # A body that is not a valid InboundMessageNotification (non-JSON garbage) →
    # InboundBodyMalformedError. The receiver drops + drains + returns (NO raise).
    await receiver.receive(
        params=_envelope(adapter_id="discord", body=b"not-json-at-all"),
        wire_seq=17,
    )

    assert dispatch.calls == []
    rows = audit_writer.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["adapter_id"] == "discord"
    assert rows[0]["reason"] == "body_malformed"
    assert rows[0]["result"] == "dropped"
    # The signed row carries ONLY adapter_id + reason + observed_at — no body, no
    # str(exc). Prove no row field holds the raw body fragment.
    for value in rows[0].values():
        assert "not-json-at-all" not in str(value)
    assert ack.observed == [17]


async def test_malformed_body_drains_only_when_wire_seq_present() -> None:
    """A None wire_seq (un-sequenced leg) is a drain no-op — no observe call."""
    dispatch = _RecordingDispatch()
    audit_writer = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=object(),
        ack_tracker=ack,
    )

    await receiver.receive(params=_envelope(adapter_id="discord", body=b"not-json"), wire_seq=None)

    assert audit_writer.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert ack.observed == []


# --------------------------------------------------------------------------- #
# E ROUTING USES ENVELOPE adapter_id (SEC-309-1)
# --------------------------------------------------------------------------- #


async def test_routing_uses_envelope_adapter_id_not_body() -> None:
    """The collaborator lookup keys on the ENVELOPE id, never the body's claim."""
    dispatch = _RecordingDispatch()
    limiter = object()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=SpyAuditWriter(),
        pre_resolution_limiter=limiter,
    )

    # Envelope says discord (registry hit + body matches → dispatch). If routing
    # ever consulted the body's adapter_id first, an attacker could pick the
    # collaborator set; the equality check in reparse defends, but routing MUST use
    # the envelope id. The dispatched collaborator set proves the envelope keyed it.
    await receiver.receive(
        params=_envelope(adapter_id="discord", body=_discord_body(adapter_id="discord")),
        wire_seq=1,
    )

    assert dispatch.calls[0]["identity_resolver"] is receiver._registry["discord"].resolver_bridge


async def test_routing_does_not_json_loads_body_for_unknown_adapter() -> None:
    """K4 refusal short-circuits BEFORE any body parse (SEC-309-1).

    An unknown ENVELOPE adapter is refused on the registry miss alone; the receiver
    must NOT have parsed the body to reach that decision. A body that would raise on
    parse still produces the clean K4 refusal, proving no body parse ran first.
    """
    dispatch = _RecordingDispatch()
    audit_writer = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=object(),
        ack_tracker=ack,
    )

    await receiver.receive(
        params=_envelope(adapter_id="alfred_comms_test", body=b"would-raise-if-parsed"),
        wire_seq=21,
    )

    rows = audit_writer.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert rows[0]["reason"] == "unknown_adapter"
    assert ack.observed == [21]


# --------------------------------------------------------------------------- #
# F PromoterRequiredError NOT caught
# --------------------------------------------------------------------------- #


async def test_promoter_required_error_propagates() -> None:
    async def _raising_dispatch(notification: Any, **kwargs: Any) -> None:
        raise PromoterRequiredError("misconfig: no promoter")

    receiver = _build_receiver(
        dispatch=_raising_dispatch,
        audit_writer=SpyAuditWriter(),
        pre_resolution_limiter=object(),
    )

    with pytest.raises(PromoterRequiredError):
        await receiver.receive(
            params=_envelope(adapter_id="discord", body=_discord_body()), wire_seq=1
        )


# --------------------------------------------------------------------------- #
# G AUDIT-WRITE FAILURE on a drop → no drain, propagates
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("envelope_adapter", "body"),
    [
        pytest.param("alfred_comms_test", b"unparsed", id="unknown_adapter"),
        pytest.param("discord", _discord_body(adapter_id="tui"), id="envelope_body_mismatch"),
        pytest.param("discord", b"not-json", id="body_malformed"),
    ],
)
async def test_audit_write_failure_on_drop_does_not_drain_and_propagates(
    envelope_adapter: str, body: bytes
) -> None:
    dispatch = _RecordingDispatch()
    audit_writer = _RaisingAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=object(),
        ack_tracker=ack,
    )

    with pytest.raises(ForwardedInboundAuditWriteError) as excinfo:
        await receiver.receive(
            params=_envelope(adapter_id=envelope_adapter, body=body), wire_seq=31
        )

    # The audit-write failure propagates wrapped in the typed marker (Task 4's
    # disposition escalates a restart), chaining the raw backend error as its cause ...
    assert excinfo.value.__cause__ is _AUDIT_WRITE_FAILED
    # ... and the drop was NOT drained: never ACK an unrecorded drop.
    assert ack.observed == []
    assert dispatch.calls == []


# --------------------------------------------------------------------------- #
# H ORDER: signed audit write BEFORE drain observe
# --------------------------------------------------------------------------- #


class _OrderRecordingAuditWriter:
    """Records ``append_schema`` into a shared order list (for the ordering assert)."""

    def __init__(self, order: list[str]) -> None:
        self._order = order

    async def append_schema(self, **kwargs: Any) -> None:
        self._order.append("audit")


class _OrderRecordingAckTracker:
    def __init__(self, order: list[str]) -> None:
        self._order = order
        self.observed: list[int] = []

    def observe(self, seq: int) -> None:
        self._order.append("observe")
        self.observed.append(seq)


async def test_signed_audit_write_precedes_drain_observe() -> None:
    order: list[str] = []
    dispatch = _RecordingDispatch()
    receiver = GatewayForwardedInboundReceiver(
        registry={"discord": _discord_collaborators(pre_resolution_limiter=object())},
        idempotency_store=_SpyIdempotencyStore(),
        audit_writer=_OrderRecordingAuditWriter(order),
        dispatch=dispatch,
    )
    receiver.set_ack_tracker(_OrderRecordingAckTracker(order))

    await receiver.receive(
        params=_envelope(adapter_id="alfred_comms_test", body=b"unparsed"),
        wire_seq=41,
    )

    assert order == ["audit", "observe"]


# --------------------------------------------------------------------------- #
# I receive_fault — off-vocab envelope adapter_id (SEC-G674-1)
#
# An off-vocab ``adapter_id`` makes ``model_validate`` raise a ValidationError. Before
# FIX 2 that escaped to the disposition's blanket catch-and-continue → no signed row,
# no drain → infinite replay. Now it is caught and turned into a signed receive_fault
# DROP under a content-free sentinel adapter_id, then DRAINED, then returns (no raise).
# --------------------------------------------------------------------------- #


async def test_off_vocab_envelope_adapter_id_drops_receive_fault_and_drains() -> None:
    dispatch = _RecordingDispatch()
    audit_writer = SpyAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=object(),
        ack_tracker=ack,
    )

    # (a) off-vocab envelope adapter_id → one signed receive_fault row + observe + return.
    await receiver.receive(
        params=_envelope(adapter_id="not-a-real-kind", body=b"would-leak-if-on-row"),
        wire_seq=51,
    )

    assert dispatch.calls == []
    rows = audit_writer.rows_with_schema("COMMS_FORWARDED_INBOUND_DROPPED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["reason"] == "receive_fault"
    assert rows[0]["result"] == "dropped"
    assert rows[0]["trust_tier_of_trigger"] == "T3"
    # Content-free sentinel adapter_id — never str(exc) / the raw params/body.
    assert rows[0]["adapter_id"] == "<unparseable_envelope>"
    for value in rows[0].values():
        assert "would-leak-if-on-row" not in str(value)
        assert "not-a-real-kind" not in str(value)
    # Drained so the leg's contiguous high-water advances (no infinite replay).
    assert ack.observed == [51]


async def test_receive_fault_audit_write_failure_propagates() -> None:
    """(b) A receive_fault whose OWN signed row fails to write still escalates loud.

    The receive_fault drop routes through ``_audit_drop`` → ``ForwardedInboundAuditWriteError``
    on a write failure; it must propagate (the disposition escalates a restart), never
    be re-swallowed by the admission catch, and never drain.
    """
    dispatch = _RecordingDispatch()
    audit_writer = _RaisingAuditWriter()
    ack = _SpyAckTracker()
    receiver = _build_receiver(
        dispatch=dispatch,
        audit_writer=audit_writer,
        pre_resolution_limiter=object(),
        ack_tracker=ack,
    )

    with pytest.raises(ForwardedInboundAuditWriteError) as excinfo:
        await receiver.receive(
            params=_envelope(adapter_id="not-a-real-kind", body=b"x"), wire_seq=52
        )

    assert excinfo.value.__cause__ is _AUDIT_WRITE_FAILED
    assert ack.observed == []
    assert dispatch.calls == []


async def test_audit_write_error_from_dispatch_pipeline_propagates() -> None:
    """(b-companion) ``ForwardedInboundAuditWriteError`` from the DISPATCH propagates.

    The dispatched-edge pipeline can raise the typed marker (a forwarded-path audit
    emit failing). It must NOT be caught by the admission ``except Exception`` — it is
    re-raised by the dedicated ``except ForwardedInboundAuditWriteError`` arm so the
    disposition escalates a restart.
    """

    async def _raising_dispatch(notification: Any, **kwargs: Any) -> None:
        raise ForwardedInboundAuditWriteError("forwarded-path emit failed")

    receiver = _build_receiver(
        dispatch=_raising_dispatch,
        audit_writer=SpyAuditWriter(),
        pre_resolution_limiter=object(),
    )

    with pytest.raises(ForwardedInboundAuditWriteError):
        await receiver.receive(
            params=_envelope(adapter_id="discord", body=_discord_body()), wire_seq=1
        )


async def test_dropped_fields_constant_is_content_free() -> None:
    """The drop field-set carries no body/inbound_id/exception surface (spec §3.3)."""
    fields = audit_row_schemas.COMMS_FORWARDED_INBOUND_DROPPED_FIELDS
    assert fields == frozenset({"adapter_id", "reason", "observed_at"})
    forbidden = {"body", "inbound_id", "inbound_id_hash", "detail", "detail_redacted"}
    assert not (fields & forbidden)
    # Sanity: a well-formed body really does round-trip to valid JSON (guards the
    # test helper itself, so a future helper regression surfaces here).
    assert json.loads(_discord_body())["adapter_id"] == "discord"
