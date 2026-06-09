"""The dispatch arm observes the comms histograms + failure counter (Task 62).

A successful comms-notification dispatch observes
``alfred_comms_inbound_dispatch_seconds``; a handler exception increments
``alfred_comms_handler_failures_total`` on the same path that emits
``COMMS_HANDLER_FAILED_FIELDS`` (err-007).
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from prometheus_client import REGISTRY

from ._session_builders import INBOUND_PARAMS, build_session


def _count(name: str) -> float:
    value = REGISTRY.get_sample_value(name)
    return value if value is not None else 0.0


@pytest.mark.asyncio
async def test_successful_dispatch_observes_inbound_histogram() -> None:
    session = build_session(inbound_handler=AsyncMock())
    before = _count("alfred_comms_inbound_dispatch_seconds_count")
    await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    after = _count("alfred_comms_inbound_dispatch_seconds_count")
    assert after == before + 1


@pytest.mark.asyncio
async def test_handler_failure_increments_failures_counter() -> None:
    failing = AsyncMock()
    failing.process.side_effect = RuntimeError("boom")
    session = build_session(inbound_handler=failing, supervisor=AsyncMock())
    before = _count("alfred_comms_handler_failures_total")
    with pytest.raises(RuntimeError):
        await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)
    after = _count("alfred_comms_handler_failures_total")
    assert after == before + 1
