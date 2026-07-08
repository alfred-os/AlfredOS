"""Unit tests for :mod:`alfred.comms_mcp.real_turn_adapter` — Task 1 (#338 PR2).

Covers construction + ``quarantined_extract`` delegation + the ``ingest``
prepare-only leg: TypedRefusal -> benign reply, Extracted -> gate-checked
T3->T2 downgrade -> ``_PreparedTurn``, and downgrade-deny -> loud content-free
audit row + ``_HaltNoReply`` (no reply leaked on a security deny).

``dispatch`` / the turn + outbound send are Task 2 scope — not exercised here.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from alfred.audit import audit_row_schemas
from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.real_turn_adapter import (
    RealTurnOrchestratorAdapter,
    _HaltNoReply,
    _InboundUser,
    _PreparedTurn,
    _RefusalReply,
)
from alfred.security.quarantine import Extracted, TypedRefusal
from alfred.security.tiers import T2
from tests.helpers.gates import make_quarantined_extract_chain_gate

if TYPE_CHECKING:
    from alfred.hooks.capability import CapabilityGate


def test_turn_refused_schema_is_content_free() -> None:
    fields = audit_row_schemas.COMMS_INBOUND_TURN_REFUSED_FIELDS
    # FOLD-R2: mirror the sibling content-free comms rows — key by the PEPPERED
    # inbound_id_hash, NO user-id hash (attribution rides actor_user_id raw, like
    # orchestrator.turn). `hash_canonical_user_id` does not exist.
    assert fields == frozenset(
        {"adapter_id", "inbound_id_hash", "refusal_stage", "error_class", "observed_at"}
    )
    # No raw-content field ever enters this schema (HARD #7 / sec-010).
    assert "text" not in fields and "body" not in fields


class _FakeAuditHashBroker:
    """Minimal broker satisfying ``audit_hash._BrokerLike`` for unit tests.

    FOLD-R12: ``_emit_refused`` hashes via ``audit_hash``, which raises
    ``MissingAuditHashPepperError`` fail-closed until ``set_broker`` runs (the
    daemon wires the real broker at ``inbound.py:707``). This fixture stands in
    for the real broker so unit tests exercise the same fail-closed hashing path.
    ``get`` is SYNC (``_BrokerLike.get(name) -> str``, ``audit_hash.py:49``) — not
    the async ``SecretBroker.get`` the docstring elsewhere refers to.
    """

    def get(self, name: str) -> str:
        # 32-byte HKDF PRK floor (audit_hash._hkdf's SHA-256 digest-size check) —
        # mirrors the fixture pepper convention in test_audit_hash_pepper_lookup.py.
        return "p" * 40


@pytest.fixture(autouse=True)
def _wire_audit_hash_pepper() -> object:
    # `-> object` (not `None`): mypy requires a generator function's return type
    # to be `Generator`/`Iterator` or a supertype — matches the sibling fixture
    # convention in test_audit_hash_pepper_lookup.py.
    audit_hash.set_broker_for_test(_FakeAuditHashBroker())
    yield
    audit_hash.reset_for_test()


class _RecordingAudit:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))

    async def append(self, **kwargs: object) -> None:  # pragma: no cover - unused here
        self.rows.append(dict(kwargs))


def _notification(inbound_id: str = "ib-1") -> SimpleNamespace:
    return SimpleNamespace(
        adapter_id="tui",
        inbound_id=inbound_id,
        platform_user_id="plat-9",
        addressing_signal=SimpleNamespace(),
    )


def _extracted(text: str = "hi alfred") -> Extracted:
    # reason: T3DerivedData is a NewType over dict[str, object]; matches the
    # _greeting_extracted precedent in test_daemon_runtime.py.
    return Extracted(
        data={"text": text, "intent": "greeting"},  # type: ignore[arg-type]
        extraction_mode="native_constrained",
    )


def _adapter(*, gate: CapabilityGate, audit: _RecordingAudit) -> RealTurnOrchestratorAdapter:
    return RealTurnOrchestratorAdapter(
        orchestrator=SimpleNamespace(),  # type: ignore[arg-type]  # reason: not called by ingest
        working_memory_pool=SimpleNamespace(),  # type: ignore[arg-type]  # reason: not called by ingest
        gate=gate,
        audit_writer=audit,  # type: ignore[arg-type]  # reason: _RecordingAudit duck-types AuditWriter.append_schema/append only
        outbound_dlp=SimpleNamespace(),  # type: ignore[arg-type]  # reason: not called by ingest
        extractor_bridge=SimpleNamespace(),  # type: ignore[arg-type]  # reason: not called by ingest
    )


@pytest.mark.asyncio
async def test_ingest_typed_refusal_returns_benign_reply() -> None:
    adapter = _adapter(
        gate=make_quarantined_extract_chain_gate(grant_downgrade_t3=True), audit=_RecordingAudit()
    )
    outcome = await adapter.ingest(
        notification=_notification(),
        extracted=TypedRefusal(reason="cannot_extract"),
        canonical_user_id="u-1",
        addressing_signal=SimpleNamespace(),
        language="en-US",
        display_name="Ada",
    )
    assert isinstance(outcome, _RefusalReply)
    assert outcome.reply  # a non-empty benign string
    assert outcome.target_platform_id == "plat-9"


@pytest.mark.asyncio
async def test_ingest_extracted_downgrades_and_prepares_t2() -> None:
    audit = _RecordingAudit()
    adapter = _adapter(
        gate=make_quarantined_extract_chain_gate(grant_downgrade_t3=True), audit=audit
    )
    outcome = await adapter.ingest(
        notification=_notification(),
        extracted=_extracted("hi alfred"),
        canonical_user_id="u-1",
        addressing_signal=SimpleNamespace(),
        language="en-US",
        display_name="Ada",
    )
    assert isinstance(outcome, _PreparedTurn)
    assert outcome.content.tier is T2
    assert outcome.content.content == "hi alfred"
    assert outcome.user == _InboundUser(slug="u-1", display_name="Ada", language="en-US")
    assert outcome.egress.adapter_id == "tui"
    assert outcome.egress.inbound_id == "ib-1"
    assert outcome.egress.session_id == "u-1"
    # HARD #5 provenance: the downgrade receipt fired (downgrade_explicit=True).
    downgrade_rows = [r for r in audit.rows if r.get("event") == "quarantine.t3_derived_downgrade"]
    assert len(downgrade_rows) == 1
    downgrade_subject = downgrade_rows[0]["subject"]
    assert isinstance(downgrade_subject, dict)
    assert downgrade_subject["downgrade_explicit"] is True


@pytest.mark.asyncio
async def test_ingest_downgrade_deny_writes_loud_audit_and_halts() -> None:
    audit = _RecordingAudit()
    # grant_downgrade_t3=False → the RealGate DENIES the t3.downgrade check (fail-closed).
    adapter = _adapter(
        gate=make_quarantined_extract_chain_gate(grant_downgrade_t3=False), audit=audit
    )
    outcome = await adapter.ingest(
        notification=_notification(),
        extracted=_extracted("hi alfred"),
        canonical_user_id="u-1",
        addressing_signal=SimpleNamespace(),
        language="en-US",
        display_name="Ada",
    )
    assert isinstance(outcome, _HaltNoReply)  # no reply leaked on a security deny
    refusal_rows = [
        r for r in audit.rows if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ]
    assert len(refusal_rows) == 1
    refusal_subject = refusal_rows[0]["subject"]
    assert isinstance(refusal_subject, dict)
    assert refusal_subject["refusal_stage"] == "downgrade_denied"
    assert "hi alfred" not in str(refusal_rows[0])  # no raw content leaks into the row
