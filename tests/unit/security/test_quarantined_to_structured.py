"""``quarantined_to_structured`` full impl tests (PR-S3-4 Task 7).

This is the ONLY T3→orchestrator structured-data crossing path. The
function must:

* Consult :meth:`CapabilityGate.check_content_clearance` BEFORE invoking
  the extractor (gate-first ordering — CR-S3-2 R3 lesson: work happens
  after gate check, never before).
* On clearance grant — return the :class:`ExtractionResult` the
  extractor produced (an :class:`Extracted` or :class:`TypedRefusal`).
* On clearance refusal — raise :class:`AlfredError` BEFORE the extractor
  is touched. Tests assert ``extractor.extract`` was not awaited.

The capability-gate dependency is explicit (no default) per CR-138 R3:
a trust-boundary function whose gate can be elided through a default
arg is a function with a bypass path codified in its signature.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar, Literal
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.errors import AlfredError
from alfred.security.quarantine import (
    ContentHandle,
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    TypedRefusal,
    quarantined_to_structured,
)

# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_handle() -> ContentHandle:
    return ContentHandle(
        id="qts-uuid-001",
        source_url="https://example.test/article",
        fetch_timestamp=datetime.now(UTC),
    )


class _Schema(ExtractionSchema):
    schema_version: ClassVar[Literal[1]] = 1
    title: str = ""


class _AllowGate:
    """Fixture gate that grants every clearance request.

    Structural Protocol implementation — no inheritance.
    """

    def check(self, *, plugin_id: str, hookpoint: str, requested_tier: str) -> bool:
        return True

    def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
        return True

    def check_content_clearance(self, *, plugin_id: str, hookpoint: str, content_tier: str) -> bool:
        return True


class _DenyGate:
    """Fixture gate that refuses every clearance request — fail-closed."""

    def check(self, *, plugin_id: str, hookpoint: str, requested_tier: str) -> bool:
        return False

    def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
        return False

    def check_content_clearance(self, *, plugin_id: str, hookpoint: str, content_tier: str) -> bool:
        return False


@pytest.fixture
def fake_extractor_extracted() -> MagicMock:
    extractor = MagicMock()
    extractor.extract = AsyncMock(
        return_value=Extracted(
            data=T3DerivedData({"title": "hello"}),
            extraction_mode="native_constrained",
        ),
    )
    return extractor


@pytest.fixture
def fake_extractor_refused() -> MagicMock:
    extractor = MagicMock()
    extractor.extract = AsyncMock(return_value=TypedRefusal(reason="cannot_extract"))
    return extractor


# ---------------------------------------------------------------------------
# Gate-first ordering — CR-S3-2 R3 lesson.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_clearance_consulted_before_extractor(
    fake_handle: ContentHandle, fake_extractor_extracted: MagicMock
) -> None:
    """A denied gate refuses BEFORE the extractor runs.

    This is the load-bearing ordering: any work that runs before the
    gate check is work the gate has not authorised. The test asserts the
    extractor was never awaited.
    """
    gate = _DenyGate()
    with pytest.raises(AlfredError):
        await quarantined_to_structured(
            fake_handle,
            _Schema,
            extractor=fake_extractor_extracted,
            gate=gate,
        )
    fake_extractor_extracted.extract.assert_not_awaited()


@pytest.mark.asyncio
async def test_gate_check_uses_t3_content_tier(
    fake_handle: ContentHandle, fake_extractor_extracted: MagicMock
) -> None:
    """``check_content_clearance`` is called with the closed-vocabulary
    ``plugin_id="alfred.quarantined-llm"``, ``content_tier="T3"``, and
    ``hookpoint="quarantine.dereference"``. The plugin_id is pinned to
    :attr:`QuarantinedExtractor._PLUGIN_ID` so the audit-graph join key
    matches the extractor's own audit rows — CR-156 round 1 finding #3
    explicitly called the boundary-doc / implementation drift here.
    Typos in any of these silently widen the clearance.
    """
    seen: dict[str, Any] = {}

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

    await quarantined_to_structured(
        fake_handle,
        _Schema,
        extractor=fake_extractor_extracted,
        gate=_RecordingGate(),
    )
    assert seen["plugin_id"] == "alfred.quarantined-llm"
    assert seen["content_tier"] == "T3"
    assert seen["hookpoint"] == "quarantine.dereference"


# ---------------------------------------------------------------------------
# Happy paths.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_extracted_on_grant(
    fake_handle: ContentHandle, fake_extractor_extracted: MagicMock
) -> None:
    """The function returns the extractor's :class:`Extracted` result
    unchanged.
    """
    result = await quarantined_to_structured(
        fake_handle,
        _Schema,
        extractor=fake_extractor_extracted,
        gate=_AllowGate(),
    )
    assert isinstance(result, Extracted)
    assert result.extraction_mode == "native_constrained"
    assert dict(result.data) == {"title": "hello"}


@pytest.mark.asyncio
async def test_returns_typed_refusal_on_grant(
    fake_handle: ContentHandle, fake_extractor_refused: MagicMock
) -> None:
    """A :class:`TypedRefusal` result flows through unchanged. The
    function does NOT translate a refusal into an exception — refusal
    is a legitimate orchestrator outcome.
    """
    result = await quarantined_to_structured(
        fake_handle,
        _Schema,
        extractor=fake_extractor_refused,
        gate=_AllowGate(),
    )
    assert isinstance(result, TypedRefusal)
    assert result.reason == "cannot_extract"


@pytest.mark.asyncio
async def test_extractor_called_with_handle_and_schema(
    fake_handle: ContentHandle, fake_extractor_extracted: MagicMock
) -> None:
    """The extractor is invoked with the ContentHandle and the schema
    class — no positional surprises.
    """
    await quarantined_to_structured(
        fake_handle,
        _Schema,
        extractor=fake_extractor_extracted,
        gate=_AllowGate(),
    )
    fake_extractor_extracted.extract.assert_awaited_once_with(fake_handle, _Schema)
