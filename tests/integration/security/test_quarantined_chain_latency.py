"""Cross-fork integration: quarantined extraction chain latency (spec §12.4, §7a.1).

ADVISORY — not merge-blocking in Slice 3. The latency budget is the
end-to-end chain cost from ``quarantined_to_structured`` entry to
:class:`Extracted` return, with mocked transport/extractor (so the
measurement captures orchestrator-side overhead only — no provider HTTP).

Two distinct budgets are tested:

* **Cold-start budget** (< 500 ms): one-shot chain invocation, captures
  module-import + gate-construction + extractor wire-up overhead. Spec
  §7a.1 calls out the cold-start budget specifically so an operator can
  diagnose first-extract latency.
* **End-to-end p95 budget** (< 2 s): 5 sequential invocations, p95
  latency. Mocked transport so the budget reflects host-side overhead
  rather than provider RTT. Real-provider latency belongs in Slice-4
  smoke tests.

Advisory means: the assertions raise if violated, but the test does NOT
block the Slice-3 merge gate. The numbers will tighten as the chain
matures. Set ``ALFRED_SKIP_LATENCY_TESTS=1`` in CI environments where
the host is too noisy to honour the budget.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import ClassVar, Literal
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.security.quarantine import (
    ContentHandle,
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    quarantined_to_structured,
)


class _LatencySchema(ExtractionSchema):
    """Minimal ExtractionSchema for latency exercises."""

    schema_version: ClassVar[Literal[1]] = 1
    title: str = ""


class _AllowAllGate:
    def check(self, *, plugin_id: str, hookpoint: str, requested_tier: str) -> bool:
        return True

    def check_plugin_load(self, *, plugin_id: str, manifest_tier: str) -> bool:
        return True

    def check_content_clearance(self, *, plugin_id: str, hookpoint: str, content_tier: str) -> bool:
        return True


def _make_handle() -> ContentHandle:
    return ContentHandle(
        id="latency-test-uuid",
        source_url="https://example.test/article",
        fetch_timestamp=datetime.now(UTC),
    )


def _make_fake_extractor() -> MagicMock:
    extractor = MagicMock()
    extractor.extract = AsyncMock(
        return_value=Extracted(
            data=T3DerivedData({"title": "Safe Title"}),
            extraction_mode="native_constrained",
        ),
    )
    return extractor


_LATENCY_SKIP = os.environ.get("ALFRED_SKIP_LATENCY_TESTS") == "1"
_COLD_START_BUDGET_S = 0.5
_P95_BUDGET_S = 2.0
_ITERATIONS = 5


@pytest.mark.skipif(_LATENCY_SKIP, reason="ALFRED_SKIP_LATENCY_TESTS=1")
@pytest.mark.asyncio
async def test_quarantined_chain_cold_start_under_budget() -> None:
    """Cold-start: one chain invocation MUST return inside the 500 ms budget.

    Mocked extractor + gate so the measured time is orchestrator-side
    overhead (gate check, audit-row construction, dispatch wiring) —
    not provider RTT.
    """
    extractor = _make_fake_extractor()
    gate = _AllowAllGate()

    start = time.monotonic()
    result = await quarantined_to_structured(
        _make_handle(), _LatencySchema, extractor=extractor, gate=gate
    )
    elapsed = time.monotonic() - start

    assert isinstance(result, Extracted)
    assert elapsed < _COLD_START_BUDGET_S, (
        f"Cold-start chain latency was {elapsed * 1000:.1f}ms; "
        f"budget is {_COLD_START_BUDGET_S * 1000:.0f}ms (advisory, spec §7a.1)."
    )


@pytest.mark.skipif(_LATENCY_SKIP, reason="ALFRED_SKIP_LATENCY_TESTS=1")
@pytest.mark.asyncio
async def test_quarantined_chain_p95_under_budget() -> None:
    """p95 latency across 5 sequential invocations MUST be under 2 s.

    Sequential rather than concurrent — the chain has no in-flight
    sharing that would change p95 under concurrency, and sequential
    measurement is the simpler signal for "the orchestrator overhead
    is bounded".
    """
    extractor = _make_fake_extractor()
    gate = _AllowAllGate()

    samples: list[float] = []
    for _ in range(_ITERATIONS):
        start = time.monotonic()
        await quarantined_to_structured(
            _make_handle(), _LatencySchema, extractor=extractor, gate=gate
        )
        samples.append(time.monotonic() - start)

    # p95 across 5 samples is samples[-1] after sort (95th percentile of
    # 5 = ceil(0.95 * 5) - 1 = 4 index, i.e. the max). The narrow sample
    # size keeps the test fast; a Slice-4 smoke-tier exercise can do
    # larger N with the real provider.
    samples.sort()
    p95 = samples[-1]
    assert p95 < _P95_BUDGET_S, (
        f"p95 chain latency over {_ITERATIONS} iterations was "
        f"{p95 * 1000:.1f}ms; budget is {_P95_BUDGET_S * 1000:.0f}ms "
        "(advisory, spec §12.4)."
    )
