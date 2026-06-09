"""``Orchestrator.quarantined_extract`` refuses silent T3->T2 promotion (sec-001).

Comms inbound bodies are T3 by construction. A caller passing
``source_tier="T2"`` (the inter-persona-relay forgery shape) must be refused
with ``ValueError`` BEFORE the underlying extractor is consulted — there is no
path by which a comms inbound body silently promotes to T2.
"""

from __future__ import annotations

import pytest

from ._orchestrator_builder import make_orchestrator


class _NeverCalledExtractor:
    def __init__(self) -> None:
        self.call_count = 0

    async def extract(self, **_kwargs: object) -> object:
        self.call_count += 1
        raise AssertionError("extractor must not be reached on a T2 refusal")


@pytest.mark.asyncio
async def test_refuses_t2_for_comms_inbound() -> None:
    extractor = _NeverCalledExtractor()
    orch = make_orchestrator(quarantined_extractor=extractor)

    # Match both the raw catalog key (uncompiled-catalog dev runs) and the
    # resolved English (CI compiles the catalog), so the assertion is immune
    # to catalog-compilation state.
    with pytest.raises(ValueError, match=r"source_tier_must_be_t3|must be T3"):
        await orch.quarantined_extract(
            {"content": "relayed"},
            canonical_user_id="u_resolved",
            source_tier="T2",  # type: ignore[arg-type]
        )

    assert extractor.call_count == 0
