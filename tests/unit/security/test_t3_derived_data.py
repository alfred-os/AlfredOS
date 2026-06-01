"""Tests for T3DerivedData NewType, ContentHandle, and quarantined_to_structured
boundary stub. Spec §3.4, §3.7, §7.3.

Full quarantined_to_structured implementation lands in PR-S3-4.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta, tzinfo

import pytest

from alfred.security.quarantine import (
    ContentHandle,
    Extracted,
    ExtractionResult,  # noqa: F401  --  import-chain assertion for PR-S3-3a (sec-002)
    ExtractionSchema,
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


def test_quarantined_to_structured_refuses_on_denied_gate() -> None:
    """The full implementation (PR-S3-4 Task 7) refuses on a deny-gate.

    Replaces the prior "stub raises NotImplementedError" pin. The new
    contract is gate-first: a denied ``check_content_clearance(...,
    content_tier="T3")`` raises :class:`AlfredError` BEFORE the
    extractor runs (the extractor is :data:`None` here precisely to
    catch any path that tried to invoke it).

    CR-138 finding #5: ``gate`` is non-optional at the trust boundary.
    CR-S3-2 R3 lesson: work must not happen before the gate check.
    """
    from alfred.errors import AlfredError

    handle = ContentHandle(
        id="x",
        source_url="https://example.com",
        fetch_timestamp=datetime.now(tz=UTC),
    )

    class _Schema(ExtractionSchema):
        title: str = ""

    class _DenyGate:
        """Minimal CapabilityGate fixture — fail-closed."""

        def check(self, *, plugin_id: str, hookpoint: str, requested_tier: str) -> bool:
            return False

        def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
            return False

        def check_content_clearance(
            self, *, plugin_id: str, hookpoint: str, content_tier: str
        ) -> bool:
            return False

    with pytest.raises(AlfredError):
        # extractor=None is deliberate — a denied gate must NOT touch
        # the extractor, so any path that tries would raise
        # AttributeError on the None and the test would fail.
        asyncio.run(
            quarantined_to_structured(
                handle,
                _Schema,
                extractor=None,  # type: ignore[arg-type]
                gate=_DenyGate(),
            )
        )


def test_downgrade_to_orchestrator_refuses_on_denied_gate() -> None:
    """The full implementation (PR-S3-4 Task 8) refuses on a deny-gate.

    Replaces the prior "stub raises NotImplementedError" pin. The new
    contract is gate-first: a denied ``check_content_clearance(...,
    content_tier="T3_derived")`` raises :class:`AlfredError` BEFORE the
    audit row writes. The :data:`None` audit writer here would
    AttributeError on any path that skipped the gate.
    """
    from alfred.errors import AlfredError

    data: T3DerivedData = T3DerivedData({"title": "x"})

    class _DenyGate:
        def check(self, *, plugin_id: str, hookpoint: str, requested_tier: str) -> bool:
            return False

        def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
            return False

        def check_content_clearance(
            self, *, plugin_id: str, hookpoint: str, content_tier: str
        ) -> bool:
            return False

    with pytest.raises(AlfredError):
        asyncio.run(
            downgrade_to_orchestrator(
                data,
                gate=_DenyGate(),
                audit_writer=None,  # type: ignore[arg-type]
            )
        )


def test_extraction_result_types_importable_and_constructable() -> None:
    """sec-002 (applied via PR-S3-1, fully landed in PR-S3-4): ``ExtractionResult``,
    ``Extracted``, ``TypedRefusal`` are importable + constructable.

    PR-S3-3a's ``DispatchResult`` union references ``ExtractionResult``;
    this test confirms the import chain is satisfied. PR-S3-4 promoted
    the stubs to Pydantic models with ``kind`` discriminants — see
    ``tests/unit/quarantine/test_extraction_result_types.py`` for the
    full shape suite.

    The ``handle=`` field present in the PR-S3-1 stub was dropped in
    PR-S3-4: ``ContentHandle`` is the *input* to ``quarantine.extract``,
    not part of the extraction result; handle-id correlation rides on
    the audit row, not on the result payload.
    """
    # ContentHandle import is still load-bearing for spec §7.3 — the
    # handle exists on the quarantine-input side. Spot-check construction.
    ts = datetime.now(tz=UTC)
    handle = ContentHandle(id="test-id", source_url="https://x.com", fetch_timestamp=ts)
    assert handle.id == "test-id"

    # Full-shape Extracted: kind + data: T3DerivedData + extraction_mode Literal.
    data: T3DerivedData = T3DerivedData({"title": "x"})
    extracted = Extracted(data=data, extraction_mode="native_constrained")
    assert extracted.data == data
    assert extracted.kind == "extracted"

    # Full-shape TypedRefusal: kind + closed-Literal reason.
    refusal = TypedRefusal(reason="cannot_extract")
    assert refusal.reason == "cannot_extract"
    assert refusal.kind == "typed_refusal"

    # ExtractionResult union: both branches present.
    assert isinstance(extracted, Extracted)
    assert isinstance(refusal, TypedRefusal)
