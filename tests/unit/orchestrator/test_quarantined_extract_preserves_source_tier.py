"""``Orchestrator.quarantined_extract`` preserves ``source_tier="T3"`` (sec-001).

The wrapper is the orchestrator-side funnel into the Slice-3 quarantined
extractor. It MUST pass ``source_tier="T3"`` through verbatim and return the
real :data:`alfred.security.quarantine.ExtractionResult` union — there is NO
``schema_version`` field on that result (it is ``Extracted | TypedRefusal``).

The extractor is an injected, additive constructor dependency
(``quarantined_extractor=``); Slice-3 callers that omit it keep constructing.
The wrapper itself raises a loud error if invoked with no extractor wired,
because a half-wired orchestrator silently dropping the trust-boundary funnel
would violate CLAUDE.md hard rule #7.
"""

from __future__ import annotations

from typing import Any

import pytest

from alfred.security.quarantine import Extracted, ExtractionResult, T3DerivedData

from ._orchestrator_builder import make_orchestrator


class _SpyQuarantinedExtractor:
    """Records the kwargs ``quarantined_extract`` funnels in."""

    def __init__(self) -> None:
        self.called_with: dict[str, Any] = {}
        self.call_count = 0

    async def extract(
        self,
        *,
        body: object,
        canonical_user_id: str,
        source_tier: str,
    ) -> ExtractionResult:
        self.call_count += 1
        self.called_with = {
            "body": body,
            "canonical_user_id": canonical_user_id,
            "source_tier": source_tier,
        }
        return Extracted(
            data=T3DerivedData({"content": "hi"}),
            extraction_mode="native_constrained",
        )


@pytest.mark.asyncio
async def test_calls_underlying_extractor_with_source_tier_t3() -> None:
    extractor = _SpyQuarantinedExtractor()
    orch = make_orchestrator(quarantined_extractor=extractor)

    result = await orch.quarantined_extract(
        {"content": "hi"},
        canonical_user_id="u_resolved",
        source_tier="T3",
    )

    assert extractor.call_count == 1
    assert extractor.called_with["source_tier"] == "T3"
    assert extractor.called_with["canonical_user_id"] == "u_resolved"
    assert extractor.called_with["body"] == {"content": "hi"}
    assert isinstance(result, Extracted)
    # T3DerivedData is a NewType over dict at runtime.
    assert isinstance(result.data, dict)


@pytest.mark.asyncio
async def test_raises_when_no_extractor_wired() -> None:
    orch = make_orchestrator(quarantined_extractor=None)
    # Match both the raw catalog key (uncompiled-catalog dev runs) and the
    # resolved English (CI compiles the catalog).
    with pytest.raises(RuntimeError, match="no_extractor_wired|not wired"):
        await orch.quarantined_extract(
            {"content": "hi"},
            canonical_user_id="u_resolved",
            source_tier="T3",
        )
