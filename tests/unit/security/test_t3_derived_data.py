"""Tests for T3DerivedData NewType, ContentHandle, and quarantined_to_structured
boundary stub. Spec §3.4, §3.7, §7.3.

Full quarantined_to_structured implementation lands in PR-S3-4.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta, tzinfo

import pytest
from pydantic import BaseModel

from alfred.security.quarantine import (
    ContentHandle,
    Extracted,
    ExtractionResult,  # noqa: F401  --  import-chain assertion for PR-S3-3a (sec-002)
    T3DerivedData,
    TypedRefusal,
    downgrade_to_orchestrator,
    quarantined_to_structured,
)


def test_t3_derived_data_is_newtype_over_dict() -> None:
    """T3DerivedData is a NewType — at runtime it is a plain dict.

    Type checkers treat it as distinct; mypy will flag cast(dict, t3_data)
    per the CI rule in scripts/check_tag_t3.py. See spec §3.7.
    """
    data: T3DerivedData = T3DerivedData({"title": "Example"})
    assert isinstance(data, dict)
    assert data["title"] == "Example"


def test_t3_derived_data_survives_json_round_trip() -> None:
    """T3DerivedData (a dict NewType) survives JSON serialisation.

    The NewType is NOT erased by json.dumps/loads — it remains a dict.
    The type annotation is preserved by callers who assign the parsed
    result to a T3DerivedData binding. Spec §3.7 NewType survival test.
    """
    data: T3DerivedData = T3DerivedData({"title": "Hello", "url": "https://example.com"})
    serialised = json.dumps(data)
    restored: T3DerivedData = T3DerivedData(json.loads(serialised))
    assert restored == data


def test_content_handle_is_frozen() -> None:
    """ContentHandle is a frozen dataclass — no mutation after construction."""
    handle = ContentHandle(
        id="abc-123",
        source_url="https://example.com",
        fetch_timestamp=datetime.now(tz=UTC),
    )
    with pytest.raises((AttributeError, TypeError)):
        handle.id = "mutated"  # type: ignore[misc]


def test_content_handle_has_no_content_field() -> None:
    """ContentHandle has no `.content` field — the orchestrator cannot
    dereference it to bytes. Spec §7.3 invariant."""
    handle = ContentHandle(
        id="abc-123",
        source_url="https://example.com",
        fetch_timestamp=datetime.now(tz=UTC),
    )
    assert not hasattr(handle, "content")


def test_content_handle_id_is_string() -> None:
    handle = ContentHandle(
        id="550e8400-e29b-41d4-a716-446655440000",
        source_url="https://example.com",
        fetch_timestamp=datetime.now(tz=UTC),
    )
    assert isinstance(handle.id, str)


def test_content_handle_rejects_naive_fetch_timestamp() -> None:
    """CR-138 finding #4: ContentHandle rejects naive datetimes.

    A naive ``datetime`` (no tzinfo) silently encodes the producer's
    local clock, breaking forensic ordering across hosts. The
    ``__post_init__`` validator must raise ``ValueError`` rather than
    silently accept the value.
    """
    naive = datetime(2026, 5, 31, 12, 0, 0)  # noqa: DTZ001 — deliberately naive for the test
    assert naive.tzinfo is None
    with pytest.raises(ValueError, match="must be timezone-aware"):
        ContentHandle(
            id="naive-handle",
            source_url="https://example.com",
            fetch_timestamp=naive,
        )


def test_content_handle_rejects_tzinfo_returning_none_utcoffset() -> None:
    """CR-138 finding #4: a tzinfo whose ``utcoffset()`` returns ``None`` is rejected.

    A ``tzinfo`` subclass that returns ``None`` from ``utcoffset`` is
    "tzinfo-present but offset-unknown" per the datetime contract, which
    is functionally naive. ContentHandle rejects this case alongside
    bare ``tzinfo=None``.
    """

    class _OffsetUnknownTz(tzinfo):
        """Returns ``None`` from ``utcoffset`` — legal but functionally naive."""

        def utcoffset(self, dt: datetime | None) -> timedelta | None:
            return None

        def dst(self, dt: datetime | None) -> timedelta | None:
            return None

        def tzname(self, dt: datetime | None) -> str | None:
            return None

    ambiguous = datetime(2026, 5, 31, 12, 0, 0, tzinfo=_OffsetUnknownTz())
    assert ambiguous.tzinfo is not None
    assert ambiguous.utcoffset() is None
    with pytest.raises(ValueError, match="must be timezone-aware"):
        ContentHandle(
            id="offset-unknown-handle",
            source_url="https://example.com",
            fetch_timestamp=ambiguous,
        )


def test_quarantined_to_structured_stub_raises_not_implemented() -> None:
    """The stub raises NotImplementedError — full impl is PR-S3-4.

    CR-138 finding #5: ``gate`` is non-optional at the trust boundary.
    The stub is exercised here with a fixture gate that returns ``True``
    for all clearance requests. PR-S3-4 will replace this with the real
    capability-gate wiring.
    """
    handle = ContentHandle(
        id="x",
        source_url="https://example.com",
        fetch_timestamp=datetime.now(tz=UTC),
    )

    class _Schema(BaseModel):
        schema_version: int = 1
        title: str

    class _FixtureGate:
        """Minimal CapabilityGate fixture: structurally satisfies the Protocol.

        Returns ``False`` (always-deny) — CR-138 R3 fix per CLAUDE.md hard
        rule #4 (capability gate is not bypassable in tests). The
        ``quarantined_to_structured`` stub raises ``NotImplementedError``
        before consulting the gate, so the deny value is never observed;
        but using ``return False`` (rather than ``return True``) keeps a
        future copy-paste of this fixture from accidentally codifying an
        always-allow pattern. When PR-S3-4 wires the real impl, a proper
        fixture-grant pattern lands here.
        """

        def check(
            self,
            *,
            plugin_id: str,
            hookpoint: str,
            requested_tier: str,
        ) -> bool:
            return False

    with pytest.raises(NotImplementedError):
        asyncio.run(quarantined_to_structured(handle, _Schema, extractor=None, gate=_FixtureGate()))


def test_downgrade_to_orchestrator_stub_raises_not_implemented() -> None:
    """The stub raises NotImplementedError — full impl is PR-S3-4."""
    data: T3DerivedData = T3DerivedData({"title": "x"})
    with pytest.raises(NotImplementedError):
        asyncio.run(downgrade_to_orchestrator(data, audit_row=None))  # type: ignore[arg-type]


def test_extraction_result_type_stubs_importable() -> None:
    """sec-002 (applied via PR-S3-1): ExtractionResult, Extracted, TypedRefusal
    are importable from alfred.security.quarantine before PR-S3-4 merges.

    PR-S3-3a needs these types at import time. This test confirms the
    import chain is satisfied from the PR-S3-1 stubs.
    """
    ts = datetime.now(tz=UTC)
    handle = ContentHandle(id="test-id", source_url="https://x.com", fetch_timestamp=ts)
    data: T3DerivedData = T3DerivedData({"title": "x"})
    extracted = Extracted(data=data, handle=handle)
    assert extracted.data is data

    refusal = TypedRefusal(reason="policy_violation", handle=handle)
    assert refusal.reason == "policy_violation"

    # ExtractionResult is the union type — check both branches are subtypes
    assert isinstance(extracted, Extracted)
    assert isinstance(refusal, TypedRefusal)
