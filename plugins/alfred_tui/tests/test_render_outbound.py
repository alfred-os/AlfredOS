"""outbound.message -> RichLog render -> _OutboundDelivered (or terminal refusal).

The host-side outbound queue is the load-bearing layer that refuses
mention/channel/thread to TUI (spec §8.1 routing-rule table). The plugin's
handler is the defensive second layer: a non-``dm`` mode that escapes the host
guard returns a typed ``terminal_failure`` rather than silently rendering.

``OutboundMessageRequest.body`` is ``ScannedOutboundBody`` — a DLP-minted
``tuple[str, OutboundDlpScanResult]`` — so the test mints it through the only
permitted constructor (``OutboundDlp.scan_for_outbound``), mirroring
``tests/unit/comms_mcp/test_protocol_schemas``. The rendered text is the redacted
string at ``body[0]``.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from alfred_tui.outbound import handle_outbound_message
from alfred_tui.session import TuiSession

from alfred.comms_mcp.protocol import OutboundMessageRequest
from alfred.security.dlp import OutboundDlp, ScannedOutboundBody


def _scanned(text: str) -> ScannedOutboundBody:
    class _StubBroker:
        def redact(self, value: str) -> str:
            return value

    def _audit(*, event: str, subject: object) -> None: ...

    return OutboundDlp(broker=_StubBroker(), audit=_audit).scan_for_outbound(text)


@pytest.mark.asyncio
async def test_outbound_message_returns_delivered_with_id() -> None:
    rendered: list[str] = []

    def _render(body: str) -> None:
        rendered.append(body)

    session = TuiSession(render_outbound=_render)
    await session.start(adapter_id="tui")
    req = OutboundMessageRequest(
        adapter_id="tui",
        idempotency_key=uuid4(),
        target_platform_id="local-operator",
        body=_scanned("hello back"),
        attachments_refs=(),
        addressing_mode="dm",
    )
    result = await handle_outbound_message(req, session=session)
    assert result.outcome == "delivered"
    assert result.platform_message_id
    # The redacted body text reached the render hook (visible RichLog line).
    assert rendered == ["hello back"]


@pytest.mark.asyncio
async def test_outbound_message_refuses_non_dm_mode() -> None:
    rendered: list[str] = []
    session = TuiSession(render_outbound=rendered.append)
    await session.start(adapter_id="tui")
    req = OutboundMessageRequest(
        adapter_id="tui",
        idempotency_key=uuid4(),
        target_platform_id="local-operator",
        body=_scanned("x"),
        attachments_refs=(),
        addressing_mode="mention",
    )
    result = await handle_outbound_message(req, session=session)
    assert result.outcome == "terminal_failure"
    assert result.error_class == "tui_addressing_mode_not_supported"
    # A refused outbound must NOT render — the operator never sees the rejected body.
    assert rendered == []
