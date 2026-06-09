"""Handler exception → loud audit row + counter increment + re-raise (Task 40).

err-007: comms-handler exceptions are loud, not silent. The dispatcher emits
``COMMS_HANDLER_FAILED_FIELDS`` and re-raises the ORIGINAL exception so it
propagates to the StdioTransport reader (which logs + continues).
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests.unit.comms_mcp._inbound_spies import SpyAuditWriter

from ._session_builders import INBOUND_PARAMS, build_session


@pytest.mark.asyncio
async def test_handler_exception_emits_audit_and_reraises() -> None:
    handler = AsyncMock()
    handler.process = AsyncMock(side_effect=RuntimeError("downstream broke"))
    audit = SpyAuditWriter()
    session = build_session(inbound_handler=handler, audit_writer=audit)

    with pytest.raises(RuntimeError, match="downstream broke"):
        await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)

    rows = audit.rows_with_schema("COMMS_HANDLER_FAILED_FIELDS")
    assert len(rows) == 1
    assert rows[0]["error_class"] == "RuntimeError"
    assert rows[0]["notification_method"] == "inbound.message"
    assert rows[0]["handler_class"] == "InboundHandler"
    assert "broke" in rows[0]["detail_redacted"]


@pytest.mark.asyncio
async def test_handler_exception_increments_error_counter() -> None:
    from datetime import timedelta

    from alfred.utils.sliding_window_counter import SlidingWindowCounter

    counter = SlidingWindowCounter()
    handler = AsyncMock()
    handler.process = AsyncMock(side_effect=RuntimeError("boom"))
    session = build_session(inbound_handler=handler, error_counter=counter, supervisor=AsyncMock())

    with pytest.raises(RuntimeError):
        await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)

    assert counter.count_in_window(timedelta(minutes=5)) == 1


@pytest.mark.asyncio
async def test_handler_exception_redacts_secret_in_detail() -> None:
    handler = AsyncMock()
    handler.process = AsyncMock(
        side_effect=RuntimeError("leaked sk-ABCDEFGHIJKLMNOPQRSTUVWX in error")
    )
    audit = SpyAuditWriter()
    session = build_session(inbound_handler=handler, audit_writer=audit)

    with pytest.raises(RuntimeError):
        await session._on_post_handshake_method(method="inbound.message", params=INBOUND_PARAMS)

    detail = audit.rows_with_schema("COMMS_HANDLER_FAILED_FIELDS")[0]["detail_redacted"]
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in detail
