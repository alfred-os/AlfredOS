"""Unit tests for the daemon comms runtime adapters (PR-S4-11b Wave 2, #237).

Covers the three host-side surfaces ``daemon_runtime`` adds:

* :class:`CommsInboundOrchestratorAdapter` — the ``_OrchestratorLike`` the
  inbound trust-boundary path calls. ``quarantined_extract`` delegates to the
  injected :class:`CommsExtractorBridge`; ``ingest`` records + forwards;
  ``dispatch`` emits a fixed-shape ack outbound via a LATE-BOUND sender seam.
  Before the sender is bound, ``ingest`` / ``dispatch`` raise a loud
  :class:`RuntimeError` (CLAUDE.md hard rule #7 — no silent failure).
* :class:`CommsAdapterCrashedHookInvoker` — fires the ``comms.adapter.crashed``
  hookpoint through the real ``invoke`` API, system-only-subscribable.
* :func:`_build_comms_inbound_extractor` — a REAL
  :class:`QuarantinedExtractor` over a recorded-fixture transport, wired with a
  real ``outbound_dlp`` (the only seam the fixture stubs is the LLM transport).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.comms_mcp.bootstrap import CommsBodyExtraction, CommsExtractorBridge
from alfred.comms_mcp.daemon_runtime import (
    CommsAdapterCrashedHookInvoker,
    CommsInboundOrchestratorAdapter,
    OutboundSenderLike,
    _build_comms_inbound_extractor,
)
from alfred.comms_mcp.hookpoints import ADAPTER_CRASHED_HOOKPOINT
from alfred.comms_mcp.inbound import _OrchestratorLike
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security.quarantine import Extracted, declare_hookpoints
from tests.helpers.gates import make_quarantined_extract_chain_gate

_ADAPTER_ID = "alfred_comms_test"


@pytest.fixture
def fresh_registry_allow_system() -> Iterator[HookRegistry]:
    """Install a scoped RealGate registry granting the system-tier DLP grant.

    A real :class:`QuarantinedExtractor` refuses to construct without an active
    post-stage DLP subscriber registration (PRD §7.1); that registration needs a
    system-tier grant on the ``security.quarantined.extract`` chain. Mirrors the
    ``tests/unit/security`` fixture — a scoped :class:`RealGate`, never an
    always-allow shim (CLAUDE.md hard rule #2).
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(extra_system_plugin_ids=(__name__,)),
        strict_declarations=False,
    )
    try:
        set_registry(registry)
        declare_hookpoints(registry)
        yield registry
    finally:
        set_registry(prior)


class _RecordingSender:
    """Records every outbound the adapter emits; satisfies ``OutboundSenderLike``."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def send_outbound(
        self, *, adapter_id: str, target_platform_id: str, body: Mapping[str, object]
    ) -> Mapping[str, object]:
        self.calls.append(
            {
                "adapter_id": adapter_id,
                "target_platform_id": target_platform_id,
                "body": body,
            }
        )
        return {"platform_message_id": "msg-1"}


def _greeting_extracted() -> Extracted:
    return Extracted(
        data={"text": "hi", "intent": "greeting"},  # type: ignore[arg-type]
        extraction_mode="native_constrained",
    )


def _extractor_bridge() -> tuple[CommsExtractorBridge, MagicMock]:
    """A CommsExtractorBridge over a stub extractor returning a known result."""
    extractor = MagicMock()
    extractor.extract = AsyncMock(return_value=_greeting_extracted())
    bridge = CommsExtractorBridge(extractor=extractor)
    return bridge, extractor


# ---------------------------------------------------------------------------
# CommsInboundOrchestratorAdapter
# ---------------------------------------------------------------------------


def test_adapter_satisfies_orchestrator_like_protocol() -> None:
    bridge, _ = _extractor_bridge()
    adapter = CommsInboundOrchestratorAdapter(extractor_bridge=bridge)
    assert isinstance(adapter, _OrchestratorLike)


async def test_quarantined_extract_delegates_to_bridge() -> None:
    bridge, extractor = _extractor_bridge()
    adapter = CommsInboundOrchestratorAdapter(extractor_bridge=bridge)

    result = await adapter.quarantined_extract(
        {"content": "hello"}, canonical_user_id="alice", source_tier="T3"
    )

    assert isinstance(result, Extracted)
    extractor.extract.assert_awaited_once()
    # The bridge funnels through ``extract(handle, CommsBodyExtraction)``.
    args, _ = extractor.extract.call_args
    assert args[1] is CommsBodyExtraction


async def test_ingest_before_bind_raises_runtime_error() -> None:
    bridge, _ = _extractor_bridge()
    adapter = CommsInboundOrchestratorAdapter(extractor_bridge=bridge)

    with pytest.raises(RuntimeError):
        await adapter.ingest(
            notification=MagicMock(),
            extracted=MagicMock(),
            canonical_user_id="alice",
            addressing_signal="dm",
            language="en-US",
        )


async def test_dispatch_before_bind_raises_runtime_error() -> None:
    bridge, _ = _extractor_bridge()
    adapter = CommsInboundOrchestratorAdapter(extractor_bridge=bridge)

    with pytest.raises(RuntimeError):
        await adapter.dispatch({"ingested": True})


async def test_dispatch_after_bind_sends_fixed_ack_outbound() -> None:
    bridge, _ = _extractor_bridge()
    adapter = CommsInboundOrchestratorAdapter(extractor_bridge=bridge)
    sender = _RecordingSender()
    adapter.bind_outbound_sender(sender)

    notification = MagicMock()
    notification.adapter_id = _ADAPTER_ID
    notification.platform_user_id = "discord:42"

    ingested = await adapter.ingest(
        notification=notification,
        extracted=_greeting_extracted(),
        canonical_user_id="alice",
        addressing_signal="dm",
        language="en-US",
    )
    await adapter.dispatch(ingested)

    assert len(sender.calls) == 1
    call = sender.calls[0]
    assert call["adapter_id"] == _ADAPTER_ID
    # Only the platform id crosses outward — never the canonical user id.
    assert call["target_platform_id"] == "discord:42"
    assert "alice" not in str(call)


async def test_dispatch_non_mapping_ingested_raises_runtime_error() -> None:
    bridge, _ = _extractor_bridge()
    adapter = CommsInboundOrchestratorAdapter(extractor_bridge=bridge)
    adapter.bind_outbound_sender(_RecordingSender())

    # A non-Mapping ``ingested`` is a contract violation — fail loudly, not silent.
    with pytest.raises(RuntimeError):
        await adapter.dispatch("not-a-mapping")


def test_recording_sender_satisfies_outbound_sender_like() -> None:
    assert isinstance(_RecordingSender(), OutboundSenderLike)


# ---------------------------------------------------------------------------
# CommsAdapterCrashedHookInvoker
# ---------------------------------------------------------------------------


async def test_crash_invoker_fires_hookpoint() -> None:
    captured: dict[str, Any] = {}

    async def _fake_invoke(name: str, ctx: Any, **kwargs: Any) -> Any:
        captured["name"] = name
        captured["kind"] = kwargs.get("kind")
        captured["subscribable_tiers"] = kwargs.get("subscribable_tiers")
        captured["input"] = ctx.input
        return ctx

    invoker = CommsAdapterCrashedHookInvoker(invoke=_fake_invoke)
    await invoker.fire_adapter_crashed(adapter_id=_ADAPTER_ID, error_class="BrokenPipeError")

    assert captured["name"] == ADAPTER_CRASHED_HOOKPOINT
    assert captured["kind"] == "post"
    assert captured["input"]["adapter_id"] == _ADAPTER_ID
    assert captured["input"]["error_class"] == "BrokenPipeError"


def test_crash_invoker_defaults_to_real_invoke() -> None:
    # Constructing with no injected invoke binds the real ``alfred.hooks.invoke``.
    from alfred.hooks.invoke import invoke as real_invoke

    invoker = CommsAdapterCrashedHookInvoker()
    assert invoker._invoke is real_invoke


# ---------------------------------------------------------------------------
# _build_comms_inbound_extractor — real extractor, recorded-fixture transport
# ---------------------------------------------------------------------------


async def test_build_extractor_extracts_comms_body_extraction(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    from alfred.comms_mcp.bootstrap import CommsExtractorBridge
    from alfred.security.dlp import OutboundDlp

    del fresh_registry_allow_system  # installs the scoped gate via fixture side effect
    broker = MagicMock()
    broker.redact = MagicMock(side_effect=lambda x: x)
    audit_sink = MagicMock()
    audit_sink.emit = AsyncMock()
    outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)

    audit_writer = MagicMock()
    audit_writer.append_schema = AsyncMock()

    extractor = _build_comms_inbound_extractor(audit_writer=audit_writer, outbound_dlp=outbound_dlp)
    bridge = CommsExtractorBridge(extractor=extractor)

    result = await bridge.extract(
        body={"content": "hello"}, canonical_user_id="alice", source_tier="T3"
    )
    assert isinstance(result, Extracted)
    assert result.data["text"] == "hello"


async def test_recorded_transport_close_is_noop() -> None:
    from alfred.comms_mcp.daemon_runtime import _RecordedExtractTransport

    transport = _RecordedExtractTransport()
    # The recorded transport has no subprocess behind it; close is an idempotent
    # no-op the QuarantinedExtractor's teardown path can call safely.
    assert await transport.close() is None
