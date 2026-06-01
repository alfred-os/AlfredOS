"""``downgrade_to_orchestrator`` full impl tests (PR-S3-4 Task 8).

This is the ONLY path that converts a :class:`T3DerivedData` value back
into a plain dict the orchestrator can inject into a privileged prompt.

The function MUST:

* Consult :meth:`CapabilityGate.check_content_clearance` BEFORE writing
  the audit row (gate-first ordering; refused calls produce no audit row
  in this family — the gate's own refusal accounting handles those).
* On clearance grant — emit a ``quarantine.t3_derived_downgrade`` audit
  row via :meth:`AuditWriter.append_schema` using
  :data:`T3_DERIVED_DOWNGRADE_FIELDS` (NOT :data:`T1_DOWNGRADE_FIELDS` —
  rvw-003: T1 → T2 and T3-derived → T2 are distinct trust transitions).
* Return the unwrapped dict — the T3DerivedData provenance tag is
  retired at this boundary. The audit row IS the provenance receipt.

The previous PR-S3-1 stub used ``audit_row=Any``; the full impl swaps
that for a ``gate`` + ``audit_writer`` pair, matching the trust-boundary
discipline of :func:`quarantined_to_structured`.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.errors import AlfredError
from alfred.security.quarantine import T3DerivedData, downgrade_to_orchestrator

# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_audit_writer() -> MagicMock:
    writer = MagicMock()
    writer.calls = []
    writer.last_event = None

    async def _capture(**kwargs: Any) -> None:
        writer.calls.append(kwargs)
        writer.last_event = kwargs.get("event")

    writer.append_schema = AsyncMock(side_effect=_capture)
    return writer


class _AllowGate:
    def check(self, *, plugin_id: str, hookpoint: str, requested_tier: str) -> bool:
        return True

    def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
        return True

    def check_content_clearance(self, *, plugin_id: str, hookpoint: str, content_tier: str) -> bool:
        return True


class _DenyGate:
    def check(self, *, plugin_id: str, hookpoint: str, requested_tier: str) -> bool:
        return False

    def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
        return False

    def check_content_clearance(self, *, plugin_id: str, hookpoint: str, content_tier: str) -> bool:
        return False


# ---------------------------------------------------------------------------
# Gate-first ordering.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refuses_without_clearance(fake_audit_writer: MagicMock) -> None:
    """A deny-gate refuses BEFORE the audit row writes. No audit row is
    emitted in this family; the gate has its own refusal accounting on
    the orthogonal :data:`SECURITY_CAPABILITY_GATE_DENIED_FIELDS` family.
    """
    data: T3DerivedData = T3DerivedData({"title": "secret"})
    with pytest.raises(AlfredError):
        await downgrade_to_orchestrator(data, gate=_DenyGate(), audit_writer=fake_audit_writer)
    fake_audit_writer.append_schema.assert_not_called()


@pytest.mark.asyncio
async def test_gate_consulted_with_t3_derived_tier(fake_audit_writer: MagicMock) -> None:
    """``check_content_clearance`` is called with ``content_tier="T3_derived"``
    and ``hookpoint="t3.downgrade_to_orchestrator"``. The closed-vocabulary
    tier label is what audit-graph consumers join on.
    """
    seen: dict[str, str] = {}

    class _RecordingGate:
        def check_content_clearance(
            self, *, plugin_id: str, hookpoint: str, content_tier: str
        ) -> bool:
            seen["plugin_id"] = plugin_id
            seen["hookpoint"] = hookpoint
            seen["content_tier"] = content_tier
            return True

        def check(
            self, *, plugin_id: str, hookpoint: str, requested_tier: str
        ) -> bool:  # pragma: no cover
            return True

        def check_plugin_load(
            self, *, plugin_id: str, manifest_tier: str
        ) -> bool:  # pragma: no cover
            return True

    data: T3DerivedData = T3DerivedData({"title": "hello"})
    await downgrade_to_orchestrator(data, gate=_RecordingGate(), audit_writer=fake_audit_writer)
    assert seen["content_tier"] == "T3_derived"
    assert seen["hookpoint"] == "t3.downgrade_to_orchestrator"


# ---------------------------------------------------------------------------
# Audit-row emission.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emits_quarantine_t3_derived_downgrade_event(
    fake_audit_writer: MagicMock,
) -> None:
    """The audit event is ``quarantine.t3_derived_downgrade`` — NOT
    ``identity.t1_downgrade``. rvw-003: distinct trust transitions must
    not share audit families.
    """
    data: T3DerivedData = T3DerivedData({"title": "hello"})
    await downgrade_to_orchestrator(data, gate=_AllowGate(), audit_writer=fake_audit_writer)
    assert fake_audit_writer.last_event == "quarantine.t3_derived_downgrade"


@pytest.mark.asyncio
async def test_audit_row_uses_t3_derived_downgrade_fields_constant(
    fake_audit_writer: MagicMock,
) -> None:
    """``fields=`` is the :data:`T3_DERIVED_DOWNGRADE_FIELDS` constant.

    The constant identity (not just shape) matters: append_schema's
    symmetric validation depends on the constant — a frozenset literal
    inlined at the call site would diverge from the canonical definition
    silently.
    """
    from alfred.audit import audit_row_schemas

    data: T3DerivedData = T3DerivedData({"title": "hello"})
    await downgrade_to_orchestrator(data, gate=_AllowGate(), audit_writer=fake_audit_writer)
    last = fake_audit_writer.calls[-1]
    assert last["fields"] is audit_row_schemas.T3_DERIVED_DOWNGRADE_FIELDS
    assert last["schema_name"] == "T3_DERIVED_DOWNGRADE_FIELDS"


@pytest.mark.asyncio
async def test_audit_row_subject_carries_required_t3_derived_fields(
    fake_audit_writer: MagicMock,
) -> None:
    """Every field declared in :data:`T3_DERIVED_DOWNGRADE_FIELDS` is in
    ``subject``. ``source_tier="T3_derived"``, ``target_tier="T2"``,
    ``downgrade_explicit=True``.
    """
    data: T3DerivedData = T3DerivedData({"title": "hello"})
    await downgrade_to_orchestrator(data, gate=_AllowGate(), audit_writer=fake_audit_writer)
    subject = fake_audit_writer.calls[-1]["subject"]
    assert subject["source_tier"] == "T3_derived"
    assert subject["target_tier"] == "T2"
    assert subject["downgrade_explicit"] is True
    assert subject["trust_tier_of_trigger"] == "T3"
    assert subject["trust_tier_of_response"] == "T2"
    # downgrade_reason is a short closed-vocabulary tag; never free text.
    assert isinstance(subject["downgrade_reason"], str)
    # extraction_id + quarantined_llm_invocation_id are forensic-attribution
    # strings (or None when not threaded through).
    assert "extraction_id" in subject
    assert "quarantined_llm_invocation_id" in subject
    assert "correlation_id" in subject


@pytest.mark.asyncio
async def test_audit_row_data_payload_is_not_leaked(
    fake_audit_writer: MagicMock,
) -> None:
    """The T3-derived payload values MUST NOT appear in the audit row.

    The audit row carries provenance attribution, not content. A
    payload value (``"secret"``) leaking into the audit row would
    bypass the DLP redactor and let downstream log consumers observe
    raw T3-derived data outside the privileged-orchestrator path.
    """
    data: T3DerivedData = T3DerivedData(
        {"title": "secret payload value 12345"},
    )
    await downgrade_to_orchestrator(data, gate=_AllowGate(), audit_writer=fake_audit_writer)
    last = fake_audit_writer.calls[-1]
    # The unique payload string MUST NOT appear anywhere in the kwargs.
    flat = repr(last)
    assert "secret payload value 12345" not in flat


# ---------------------------------------------------------------------------
# Return shape.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_unwrapped_dict_on_grant(
    fake_audit_writer: MagicMock,
) -> None:
    """The return value is a plain :class:`dict` carrying the same
    key-value pairs as the input. Provenance is retired; the audit row
    is the receipt.
    """
    data: T3DerivedData = T3DerivedData({"title": "hello", "n": 7})
    result = await downgrade_to_orchestrator(
        data, gate=_AllowGate(), audit_writer=fake_audit_writer
    )
    assert isinstance(result, dict)
    assert result == {"title": "hello", "n": 7}


@pytest.mark.asyncio
async def test_per_call_correlation_id(fake_audit_writer: MagicMock) -> None:
    """Two downgrades emit distinct correlation_ids — single-source-of-
    truth for the audit-graph join key.
    """
    data: T3DerivedData = T3DerivedData({"title": "a"})
    await downgrade_to_orchestrator(data, gate=_AllowGate(), audit_writer=fake_audit_writer)
    await downgrade_to_orchestrator(data, gate=_AllowGate(), audit_writer=fake_audit_writer)
    first = fake_audit_writer.calls[0]["subject"]["correlation_id"]
    second = fake_audit_writer.calls[1]["subject"]["correlation_id"]
    assert first != second
