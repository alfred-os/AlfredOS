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
* :func:`_build_comms_inbound_extractor` — PR-S4-11c-2b: a REAL
  :class:`QuarantinedExtractor` over the REAL
  :class:`alfred.security.quarantine_transport.QuarantineStdioTransport`, driven by
  a LIVE quarantined child spawned via ``spawn_quarantine_child_io``. The unit cut
  monkeypatches the spawn seam to an in-proc echoing child double (no bwrap), so
  the genuine ``extract(handle, schema)`` + ingest-then-extract wire + post-stage
  DLP scan path is exercised host-only.
``_resolve_provider_key`` (the host pre-spawn provider-key resolve + its #340
golive refuse-boot on an unset key) is covered by its own focused module,
``test_daemon_runtime_provider_key.py``.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Iterator, Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import alfred.comms_mcp.daemon_runtime as daemon_runtime_mod
from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.comms_mcp.bootstrap import CommsBodyExtraction, CommsExtractorBridge
from alfred.comms_mcp.daemon_runtime import (
    CommsAdapterCrashedHookInvoker,
    CommsInboundOrchestratorAdapter,
    OutboundSenderLike,
    _build_comms_inbound_extractor,
)
from alfred.comms_mcp.hookpoints import ADAPTER_CRASHED_HOOKPOINT
from alfred.comms_mcp.inbound import _OrchestratorLike
from alfred.comms_mcp.protocol import OutboundMessageRequest
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security import tiers as _tiers
from alfred.security.dlp import OutboundDlp, OutboundDlpScanResult
from alfred.security.quarantine import Extracted, declare_hookpoints
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import make_quarantined_extract_chain_gate

_ADAPTER_ID = "alfred_comms_test"


class _EchoingChildDouble:
    """In-proc length-prefixed child double echoing the ingested body.

    Mirrors the real quarantine child's single-use ingest/extract cache so the
    daemon's ``QuarantineStdioTransport`` drives it exactly as it would the live
    bwrap child — without a subprocess. The unit cut monkeypatches
    ``spawn_quarantine_child_io`` to return one of these.
    """

    def __init__(self, *, provider_key: str) -> None:
        self.provider_key = provider_key
        self._ingested: dict[str, str] = {}
        self._reply: bytes | None = None
        self.aclose_calls = 0

    def write_frame(self, frame: bytes) -> None:
        length = struct.unpack(">I", frame[:4])[0]
        obj = json.loads(frame[4 : 4 + length])
        method, params = obj["method"], obj["params"]
        if method == "quarantine.ingest":
            self._ingested[params["handle_id"]] = params["context"]
        elif method == "quarantine.extract":
            # Fail loud on an unknown handle (CR #255) — the real transport raises
            # rather than defaulting, so the double must too, else a broken
            # ingest→extract handle flow silently echoes "" and false-passes.
            if params["handle_id"] not in self._ingested:
                raise AssertionError(f"unknown handle_id: {params['handle_id']!r}")
            context = self._ingested.pop(params["handle_id"])
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "kind": "extracted",
                        "data": {"text": context, "intent": "greeting"},
                        "extraction_mode": "native_constrained",
                    },
                }
            ).encode("utf-8")
            self._reply = struct.pack(">I", len(body)) + body

    async def read_frame(self) -> bytes:
        assert self._reply is not None
        reply, self._reply = self._reply, None
        return reply

    async def aclose(self) -> None:
        self.aclose_calls += 1


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
        self.requests: list[OutboundMessageRequest] = []

    async def send_outbound(self, request: OutboundMessageRequest) -> Mapping[str, object]:
        self.requests.append(request)
        return {"platform_message_id": "msg-1"}


class _SpyingOutboundDlp:
    """Records every ``scan_for_outbound`` call; delegates to a real ``OutboundDlp``.

    Lets a test assert the ack text was routed through the DLP chokepoint (hard
    rule #4) while still minting a genuine :data:`ScannedOutboundBody` — the ONLY
    type the ``OutboundMessageRequest.body`` field accepts.
    """

    def __init__(self) -> None:
        broker = MagicMock()
        broker.redact = MagicMock(side_effect=lambda x: x)
        self._dlp = OutboundDlp(broker=broker, audit=lambda *, event, subject: None)
        self.scanned_raw_bodies: list[str] = []

    def scan_for_outbound(self, raw_body: str) -> Any:
        self.scanned_raw_bodies.append(raw_body)
        return self._dlp.scan_for_outbound(raw_body)


def _make_adapter(bridge: CommsExtractorBridge) -> CommsInboundOrchestratorAdapter:
    """Construct the adapter over a real (broker-stubbed) ``OutboundDlp``."""
    broker = MagicMock()
    broker.redact = MagicMock(side_effect=lambda x: x)
    dlp = OutboundDlp(broker=broker, audit=lambda *, event, subject: None)
    return CommsInboundOrchestratorAdapter(extractor_bridge=bridge, outbound_dlp=dlp)


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
    adapter = _make_adapter(bridge)
    assert isinstance(adapter, _OrchestratorLike)


async def test_quarantined_extract_delegates_to_bridge() -> None:
    bridge, extractor = _extractor_bridge()
    adapter = _make_adapter(bridge)

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
    adapter = _make_adapter(bridge)

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
    adapter = _make_adapter(bridge)

    with pytest.raises(RuntimeError):
        await adapter.dispatch({"ingested": True})


async def test_dispatch_after_bind_sends_fixed_ack_outbound() -> None:
    bridge, _ = _extractor_bridge()
    spy_dlp = _SpyingOutboundDlp()
    adapter = CommsInboundOrchestratorAdapter(extractor_bridge=bridge, outbound_dlp=spy_dlp)  # type: ignore[arg-type]
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

    # CLAUDE.md hard rule #4: the ack was routed through the outbound DLP chokepoint
    # — ``scan_for_outbound`` was called with the raw ack content text, never bypassed.
    assert spy_dlp.scanned_raw_bodies == ["ack"]

    assert len(sender.requests) == 1
    request = sender.requests[0]
    assert request.adapter_id == _ADAPTER_ID
    # Only the platform id crosses outward — never the canonical user id.
    assert request.target_platform_id == "discord:42"
    assert "alice" not in str(request)
    # The ack is a direct reply; the TUI handler only accepts ``"dm"``.
    assert request.addressing_mode == "dm"
    assert request.attachments_refs == ()

    # The body is the DLP-MINTED ``ScannedOutboundBody`` tuple — NOT a raw dict.
    # ``request.body[0]`` is the redacted ack text; ``[1]`` is the scan result.
    assert isinstance(request.body, tuple)
    redacted_text, scan_result = request.body
    assert redacted_text == "ack"
    assert isinstance(scan_result, OutboundDlpScanResult)

    # A REAL client would accept this frame: the wire params round-trip back
    # through ``OutboundMessageRequest.model_validate`` (the consumer's path).
    wire_params = request.model_dump(mode="json")
    revalidated = OutboundMessageRequest.model_validate(wire_params)
    assert revalidated.body[0] == "ack"


async def test_dispatch_ack_body_is_not_a_raw_dict() -> None:
    """Mutation guard: the ack body MUST be the DLP-minted tuple, not a raw dict.

    The pre-fix behaviour sent ``body={"content": "ack"}`` (a raw dict), which (a)
    bypassed the DLP chokepoint (hard rule #4) and (b) fails
    ``OutboundMessageRequest.model_validate`` on a real client. This asserts the
    emitted request carries a genuine ``ScannedOutboundBody`` — a dict body would
    have failed ``OutboundMessageRequest(...)`` construction at dispatch time.
    """
    bridge, _ = _extractor_bridge()
    adapter = _make_adapter(bridge)
    sender = _RecordingSender()
    adapter.bind_outbound_sender(sender)

    await adapter.dispatch({"adapter_id": _ADAPTER_ID, "target_platform_id": "discord:42"})

    request = sender.requests[0]
    assert not isinstance(request.body, Mapping)
    assert request.body[0] == "ack"


async def test_dispatch_non_mapping_ingested_raises_runtime_error() -> None:
    bridge, _ = _extractor_bridge()
    adapter = _make_adapter(bridge)
    adapter.bind_outbound_sender(_RecordingSender())

    # A non-Mapping ``ingested`` is a contract violation — fail loudly, not silent.
    with pytest.raises(RuntimeError):
        await adapter.dispatch("not-a-mapping")


@pytest.mark.parametrize("missing_key", ["adapter_id", "target_platform_id"])
async def test_dispatch_missing_ingested_key_raises_contextual_runtime_error(
    missing_key: str,
) -> None:
    """A malformed ingest mapping MISSING a required key raises a CONTEXTUAL error.

    FIX 4 (Spec A G5 review): a Mapping missing ``adapter_id`` / ``target_platform_id``
    previously raised a bare, contextless ``KeyError`` (loud but useless to an
    operator), asymmetric with the ``dispatch_bad_ingested`` ``t()``-string
    ``RuntimeError`` two lines up. Now both surface a localized operator message — and
    crucially it is NOT a bare ``KeyError`` (no silent/contextless drop, CLAUDE.md
    hard rule #7).
    """
    from alfred.i18n import t

    bridge, _ = _extractor_bridge()
    adapter = _make_adapter(bridge)
    adapter.bind_outbound_sender(_RecordingSender())

    ingested = {"adapter_id": _ADAPTER_ID, "target_platform_id": "discord:42"}
    del ingested[missing_key]

    with pytest.raises(RuntimeError) as excinfo:
        await adapter.dispatch(ingested)

    # Contextual ``t()`` string — explicitly NOT a bare ``KeyError``.
    assert not isinstance(excinfo.value, KeyError)
    assert str(excinfo.value) == t("comms.daemon_runtime.dispatch_missing_ingested_key")


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
# _build_comms_inbound_extractor — real extractor over a (faked-spawn) live transport
# ---------------------------------------------------------------------------


async def test_build_extractor_drives_real_transport_over_spawned_child(
    fresh_registry_allow_system: HookRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flipped builder drives the REAL transport over a (faked) spawned child.

    PR-S4-11c-2b go-live flip: ``_build_comms_inbound_extractor`` is async and
    builds a ``QuarantineStdioTransport`` over a LIVE quarantined child. Here the
    spawn seam is monkeypatched to an in-proc echoing double, so the inline-over-
    wire content path (ingest THEN extract, body echoed back) runs host-only. The
    ``CommsExtractorBridge`` carries a real ``T3BodyRecorder`` (the ``record_body``
    seam) so the body is tagged T3 + staged in the SAME single-use map the
    transport drains.
    """
    from alfred.security.dlp import OutboundDlp

    del fresh_registry_allow_system  # installs the scoped gate via fixture side effect
    broker = MagicMock()
    broker.redact = MagicMock(side_effect=lambda x: x)
    broker.has = MagicMock(return_value=True)
    broker.get = MagicMock(return_value="real-quarantine-provider-key")
    audit_sink = MagicMock()
    audit_sink.emit = AsyncMock()
    outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)

    audit_writer = MagicMock()
    audit_writer.append_schema = AsyncMock()

    spawned: list[_EchoingChildDouble] = []

    async def _fake_spawn(
        *, provider_key: str, refusal_recorder: object = None
    ) -> _EchoingChildDouble:
        child = _EchoingChildDouble(provider_key=provider_key)
        spawned.append(child)
        return child

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
    )

    staging = QuarantineStagingMap()
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        extractor, transport = await _build_comms_inbound_extractor(
            audit_writer=audit_writer,
            outbound_dlp=outbound_dlp,
            secret_broker=broker,
            staging=staging,
            environment="production",
        )
        # The builder returns the live transport too so the daemon can reap the
        # child on every exit path (CR #255); it owns the faked child-IO here.
        assert transport is not None
        # The configured provider key flowed into the spawn (delivered over fd 3
        # in production).
        assert len(spawned) == 1
        assert spawned[0].provider_key == "real-quarantine-provider-key"

        recorder = T3BodyRecorder(nonce=nonce, staging=staging)
        bridge = CommsExtractorBridge(extractor=extractor, record_body=recorder)

        result = await bridge.extract(
            body={"content": "hello"}, canonical_user_id="alice", source_tier="T3"
        )
        assert isinstance(result, Extracted)
        # The body crossed the wire to the (faked) child and was echoed back. The
        # mapping body is JSON-serialised deterministically by the recorder.
        echoed_text = result.data["text"]
        assert isinstance(echoed_text, str)
        assert json.loads(echoed_text) == {"content": "hello"}
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(prior_nonce)


async def test_build_extractor_reaps_child_when_construction_fails(
    fresh_registry_allow_system: HookRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-spawn construction failure REAPS the just-spawned child (CR #255).

    If ``QuarantinedExtractor`` construction raises AFTER the spawn, the builder
    closes the child (via ``transport.close()``) before re-raising — it hasn't
    returned the transport, so the daemon's exit-path teardown can't see it and the
    bwrap child would otherwise leak.
    """
    from alfred.security.dlp import OutboundDlp

    del fresh_registry_allow_system  # scoped gate installed via fixture side effect
    broker = MagicMock()
    broker.has = MagicMock(return_value=True)
    broker.get = MagicMock(return_value="real-quarantine-provider-key")
    audit_sink = MagicMock()
    audit_sink.emit = AsyncMock()
    outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)
    audit_writer = MagicMock()

    spawned: list[_EchoingChildDouble] = []

    async def _fake_spawn(
        *, provider_key: str, refusal_recorder: object = None
    ) -> _EchoingChildDouble:
        child = _EchoingChildDouble(provider_key=provider_key)
        spawned.append(child)
        return child

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
    )

    def _boom(**_kwargs: object) -> object:
        raise RuntimeError("extractor construction failed (test)")

    monkeypatch.setattr("alfred.comms_mcp.daemon_runtime.QuarantinedExtractor", _boom)

    staging = QuarantineStagingMap()
    with pytest.raises(RuntimeError, match="construction failed"):
        await _build_comms_inbound_extractor(
            audit_writer=audit_writer,
            outbound_dlp=outbound_dlp,
            secret_broker=broker,
            staging=staging,
            environment="production",
        )

    assert len(spawned) == 1
    # The child was reaped despite the construction failure (no leak).
    assert spawned[0].aclose_calls == 1


async def test_build_extractor_reaps_child_when_transport_construction_fails(
    fresh_registry_allow_system: HookRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If TRANSPORT construction raises (transport stays None), the builder reaps the
    child via ``child_io.aclose()`` before re-raising (CR #255).

    Covers the ``else`` arm of the post-spawn cleanup — the transport was never
    built, so there is no ``transport.close()`` to delegate the reap to.
    """
    from alfred.security.dlp import OutboundDlp

    del fresh_registry_allow_system  # scoped gate installed via fixture side effect
    broker = MagicMock()
    broker.has = MagicMock(return_value=True)
    broker.get = MagicMock(return_value="real-quarantine-provider-key")
    audit_sink = MagicMock()
    audit_sink.emit = AsyncMock()
    outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)

    spawned: list[_EchoingChildDouble] = []

    async def _fake_spawn(
        *, provider_key: str, refusal_recorder: object = None
    ) -> _EchoingChildDouble:
        child = _EchoingChildDouble(provider_key=provider_key)
        spawned.append(child)
        return child

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
    )

    def _boom(**_kwargs: object) -> object:
        raise RuntimeError("transport construction failed (test)")

    # Patched at the SOURCE module — the builder imports it lazily by that path.
    monkeypatch.setattr("alfred.security.quarantine_transport.QuarantineStdioTransport", _boom)

    with pytest.raises(RuntimeError, match="transport construction failed"):
        await _build_comms_inbound_extractor(
            audit_writer=MagicMock(),
            outbound_dlp=outbound_dlp,
            secret_broker=broker,
            staging=QuarantineStagingMap(),
            environment="production",
        )

    assert len(spawned) == 1
    # transport was never built, so the child itself was closed directly.
    assert spawned[0].aclose_calls == 1


async def test_extractor_injects_refusal_auditor(
    fresh_registry_allow_system: HookRegistry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The builder constructs a real ``SandboxRefusalAuditor`` and passes it to the
    spawn as ``refusal_recorder`` (#433) — this is what lets a real launcher refusal
    be persisted at first extraction instead of only reaching child stderr.

    Patched at the SOURCE module (``alfred.security.quarantine_child_io``), NOT on
    ``daemon_runtime`` — the builder's ``spawn_quarantine_child_io`` import is a
    lazy in-function import, so patching the re-export would silently no-op.
    """
    from alfred.security.dlp import OutboundDlp
    from alfred.security.sandbox_refusal_audit import SandboxRefusalAuditor

    del fresh_registry_allow_system  # scoped gate installed via fixture side effect
    broker = MagicMock()
    broker.has = MagicMock(return_value=True)
    broker.get = MagicMock(return_value="real-quarantine-provider-key")
    audit_sink = MagicMock()
    audit_sink.emit = AsyncMock()
    outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)
    audit_writer = MagicMock()

    seen: dict[str, object] = {}

    async def _fake_spawn(*, provider_key: str, refusal_recorder: object = None) -> Any:
        seen["refusal_recorder"] = refusal_recorder
        raise RuntimeError("stop after capturing kwargs")

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
    )
    # Deterministic across dev/CI host OSes: pin the resolved host context so the
    # assertion below on `refusal_recorder._host_os` doesn't vary by where the
    # suite runs (matches test_resolve_host_os_maps_to_launcher_vocab's pattern).
    monkeypatch.setattr(daemon_runtime_mod.platform, "system", lambda: "Linux")

    with pytest.raises(RuntimeError, match="stop after capturing kwargs"):
        await _build_comms_inbound_extractor(
            audit_writer=audit_writer,
            outbound_dlp=outbound_dlp,
            secret_broker=broker,
            staging=QuarantineStagingMap(),
            environment="production",
        )

    recorder = seen["refusal_recorder"]
    assert isinstance(recorder, SandboxRefusalAuditor)
    # #444 live-proof: the builder threads the RESOLVED host OS + the passed
    # `environment` into the auditor — not just constructs *a* SandboxRefusalAuditor.
    assert recorder._host_os == "linux"
    assert recorder._environment == "production"


@pytest.mark.parametrize(
    ("system", "expected"),
    [("Linux", "linux"), ("Darwin", "macos"), ("Windows", "windows"), ("Plan9", "unknown")],
)
def test_resolve_host_os_maps_to_launcher_vocab(
    monkeypatch: pytest.MonkeyPatch, system: str, expected: str
) -> None:
    monkeypatch.setattr(daemon_runtime_mod.platform, "system", lambda: system)
    assert daemon_runtime_mod._resolve_host_os() == expected
