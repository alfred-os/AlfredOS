"""Unit tests for the quarantine request/response transport + staging seam.

PR-S4-11c-2a (epic #237). The host-side wire that carries a T3 inbound body to
the (eventually launcher-spawned) quarantined LLM. Host-only: no subprocess, no
bwrap, no real LLM — the child is an in-test length-prefixed double.

What is under test (ADR-0029):

* :class:`QuarantineStdioTransport` sends ``quarantine.ingest{handle_id, context}``
  THEN ``quarantine.extract{handle_id, ...}`` in that order, over a length-prefixed
  JSON-RPC child-IO seam, and returns a :class:`ControlResult` (NOT a
  :class:`ContentHandle` — the regression guard for ``quarantine.py:1038``).
* The host single-use staging map + the ``record_body`` seam: tags the inbound body
  ``TaggedContent[T3]`` via the boot nonce, stages it under ``handle.id``, and the
  transport drains it single-use (replay refused).
* The missing-nonce / wrong-nonce fail-loud posture.
* :class:`CommsExtractorBridge` calls ``record_body`` exactly once BEFORE
  ``extractor.extract``.
"""

from __future__ import annotations

import json
import struct
from typing import TYPE_CHECKING, Any

import pytest

from alfred.plugins.transport import ControlResult
from alfred.security.quarantine import ContentHandle
from alfred.security.quarantine_transport import (
    QuarantineStagingMap,
    QuarantineStdioTransport,
    StagingHandleNotConfiguredError,
    StagingNonceUnconfiguredError,
    T3BodyRecorder,
    _decode_result_payload,
)
from alfred.security.tiers import T3, CapabilityGateNonce

if TYPE_CHECKING:
    from collections.abc import Sequence


# ---------------------------------------------------------------------------
# Test child double — a length-prefixed JSON-RPC peer that records the frames
# it receives in order and replies to ``quarantine.extract`` with a recorded
# ``extracted`` payload. Mirrors the child's ingest/extract single-use cache.
# ---------------------------------------------------------------------------


def _frame(obj: dict[str, Any]) -> bytes:
    body = json.dumps(obj).encode("utf-8")
    return struct.pack(">I", len(body)) + body


class _RecordingChildIO:
    """In-process child-IO double for :class:`QuarantineStdioTransport`.

    Records every request method/params in receive order; replies to
    ``quarantine.extract`` with a ``CommsBodyExtraction``-valid ``extracted``
    payload, echoing the most-recently-ingested ``context`` into ``data.text``
    so the integration-shaped assertion can prove the body reached the child.
    """

    def __init__(self) -> None:
        self.received: list[tuple[str, dict[str, Any]]] = []
        self._ingested: dict[str, str] = {}
        self._pending_reply: bytes | None = None
        self.closed = False

    def write_frame(self, frame: bytes) -> None:
        length = struct.unpack(">I", frame[:4])[0]
        obj = json.loads(frame[4 : 4 + length])
        method = obj["method"]
        params = obj["params"]
        self.received.append((method, params))
        if method == "quarantine.ingest":
            # Single-use cache, mirroring quarantine_plugin.handle_ingest.
            self._ingested[params["handle_id"]] = params["context"]
        elif method == "quarantine.extract":
            # Pop single-use, mirroring quarantine_plugin.handle_extract.
            context = self._ingested.pop(params["handle_id"], "")
            self._pending_reply = _frame(
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "kind": "extracted",
                        "data": {"text": context, "intent": "greeting"},
                        "extraction_mode": "native_constrained",
                    },
                }
            )

    async def read_frame(self) -> bytes:
        if self._pending_reply is None:  # pragma: no cover - defensive
            raise AssertionError("read_frame called with no pending reply")
        reply = self._pending_reply
        self._pending_reply = None
        return reply

    async def aclose(self) -> None:
        self.closed = True


class _ContentHandleReturningChildIO(_RecordingChildIO):
    """A child that replies with a frame the transport must NOT lift to a handle.

    The transport's contract is to return a :class:`ControlResult` regardless of
    payload — this double proves the transport never synthesises a
    :class:`ContentHandle` (the regression guard for ``quarantine.py:1038``,
    where a ``ContentHandle`` trips ``PluginProtocolViolation``).
    """


def _make_handle() -> ContentHandle:
    from datetime import UTC, datetime

    return ContentHandle(
        id="deadbeef",
        source_url="comms-mcp://inbound",
        fetch_timestamp=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# 1 + 2: transport ordering + ControlResult (not ContentHandle).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_sends_ingest_then_extract_in_order() -> None:
    """The transport drains the staged body, sends ingest THEN extract."""
    staging = QuarantineStagingMap()
    nonce = CapabilityGateNonce()
    staging.stage("deadbeef", _tag(nonce, "hello there"))
    child = _RecordingChildIO()
    transport = QuarantineStdioTransport(child_io=child, staging=staging)

    result = await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )

    methods = [m for m, _ in child.received]
    assert methods == ["quarantine.ingest", "quarantine.extract"]
    ingest_params = child.received[0][1]
    assert ingest_params["handle_id"] == "deadbeef"
    assert ingest_params["context"] == "hello there"
    assert isinstance(result, ControlResult)
    assert result.method == "quarantine.extract"
    assert result.payload["kind"] == "extracted"


@pytest.mark.asyncio
async def test_dispatch_returns_control_result_not_content_handle() -> None:
    """Regression guard: the transport returns ControlResult, never ContentHandle.

    ``QuarantinedExtractor._extract_body`` (quarantine.py:1038) raises
    ``PluginProtocolViolation`` if it gets a ``ContentHandle`` instead of a
    ``ControlResult``. The transport must therefore never lift content into a
    handle on this path.
    """
    staging = QuarantineStagingMap()
    nonce = CapabilityGateNonce()
    staging.stage("deadbeef", _tag(nonce, "body"))
    child = _ContentHandleReturningChildIO()
    transport = QuarantineStdioTransport(child_io=child, staging=staging)

    result = await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )

    # Exactly a ControlResult — NOT a ContentHandle. The QuarantinedExtractor's
    # ``isinstance(result_raw, ControlResult)`` guard (quarantine.py:1038) trips
    # ``PluginProtocolViolation`` on a ContentHandle, so the transport must return
    # the control shape on this path. ``type() is`` (not ``isinstance``) so the
    # check is meaningful even though the static return type is ControlResult.
    assert type(result) is ControlResult
    assert not isinstance(result, ContentHandle)  # type: ignore[unreachable]


@pytest.mark.asyncio
async def test_close_delegates_to_child_io() -> None:
    """``close`` closes the injected child-IO seam."""
    child = _RecordingChildIO()
    transport = QuarantineStdioTransport(child_io=child, staging=QuarantineStagingMap())
    await transport.close()
    assert child.closed is True


# ---------------------------------------------------------------------------
# 3 + 4: record_body T3 staging + missing/wrong nonce fail-loud.
# ---------------------------------------------------------------------------


def _tag(nonce: CapabilityGateNonce, text: str) -> Any:
    """Tag ``text`` T3 under a registered ``nonce`` (test helper)."""
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security import tiers as _tiers

    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        from alfred.security.tiers import tag_t3_with_nonce

        return tag_t3_with_nonce(text, source="test", caller_token=nonce)
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


def test_record_body_stages_t3_under_handle_id(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """``record_body`` tags the body T3 and stages it under ``handle.id``.

    The ``authorized_t3_nonce`` fixture registers the nonce as the live slot, so
    ``tag_t3_with_nonce`` accepts it as ``caller_token``.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    handle = _make_handle()

    recorder(handle=handle, body="attack")

    tagged = staging.drain("deadbeef")
    assert tagged.tier is T3
    assert tagged.content == "attack"


def test_record_body_missing_nonce_raises_loud(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A recorder built with a ``None`` nonce refuses to stage — no silent
    untagged write (mirrors StdioTransport's NonceNotConfigured pattern)."""
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=None, staging=staging)
    handle = _make_handle()

    with pytest.raises(StagingNonceUnconfiguredError):
        recorder(handle=handle, body="attack")
    # Nothing was staged — the refusal happened before any write.
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain("deadbeef")


def test_record_body_wrong_nonce_surfaces_value_error() -> None:
    """4b: a WRONG (unregistered) nonce surfaces ``tag_t3_with_nonce``'s ValueError.

    No fixture registers the recorder's nonce, so the live slot is whatever the
    process holds (not this object); ``tag_t3_with_nonce`` raises
    ``ValueError(security.tag_t3_unauthorized)``.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=CapabilityGateNonce(), staging=staging)
    handle = _make_handle()

    with pytest.raises(ValueError, match="tag_t3_unauthorized"):
        recorder(handle=handle, body="attack")


# ---------------------------------------------------------------------------
# 5: staging map single-use.
# ---------------------------------------------------------------------------


def test_staging_map_single_use(authorized_t3_nonce: CapabilityGateNonce) -> None:
    """A second drain of the same handle id fails — single-use (replay refused)."""
    staging = QuarantineStagingMap()
    staging.stage("h1", _tag(authorized_t3_nonce, "once"))

    first = staging.drain("h1")
    assert first.content == "once"
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain("h1")


def test_staging_drain_missing_handle_raises() -> None:
    """Draining an unstaged handle id is a loud refusal, not an empty value."""
    staging = QuarantineStagingMap()
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain("never-staged")


@pytest.mark.asyncio
async def test_dispatch_replay_after_consume_refused(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A second dispatch against a consumed handle id fails — the staging map
    drained it on the first call (laundering-window close)."""
    staging = QuarantineStagingMap()
    staging.stage("deadbeef", _tag(authorized_t3_nonce, "body"))
    child = _RecordingChildIO()
    transport = QuarantineStdioTransport(child_io=child, staging=staging)

    await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )
    with pytest.raises(StagingHandleNotConfiguredError):
        await transport.dispatch(
            "quarantine.extract",
            {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
        )


# ---------------------------------------------------------------------------
# 6: CommsExtractorBridge calls record_body exactly once BEFORE extract.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bridge_calls_record_body_once_before_extract() -> None:
    """``CommsExtractorBridge`` records the body exactly once, before extract."""
    from alfred.comms_mcp.bootstrap import CommsBodyExtraction, CommsExtractorBridge
    from alfred.security.quarantine import Extracted

    order: list[str] = []
    record_calls: list[Sequence[object]] = []
    sentinel = Extracted(
        data={"text": "x", "intent": "greeting"},  # type: ignore[arg-type]
        extraction_mode="native_constrained",
    )

    class _SpyRecorder:
        def __call__(self, *, handle: ContentHandle, body: object) -> None:
            order.append("record")
            record_calls.append((handle, body))

    class _SpyExtractor:
        async def extract(self, handle: ContentHandle, schema: type) -> Extracted:
            order.append("extract")
            assert schema is CommsBodyExtraction
            return sentinel

    bridge = CommsExtractorBridge(
        extractor=_SpyExtractor(),  # type: ignore[arg-type]
        record_body=_SpyRecorder(),
    )
    result = await bridge.extract(body="hello", canonical_user_id="u1", source_tier="T3")

    assert result is sentinel
    assert order == ["record", "extract"]
    assert len(record_calls) == 1


# ---------------------------------------------------------------------------
# Body coercion + fail-loud edges (full-coverage of the trust-boundary file).
# ---------------------------------------------------------------------------


def test_record_body_bytes_decoded_to_t3_text(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A ``bytes`` body is decoded (errors=replace) before T3 tagging."""
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    recorder(handle=_make_handle(), body=b"raw \xff bytes")
    tagged = staging.drain("deadbeef")
    assert tagged.tier is T3
    assert tagged.content == "raw � bytes"


def test_record_body_mapping_serialised_deterministically(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A structured (Mapping) body is JSON-serialised (sorted) before tagging."""
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    recorder(handle=_make_handle(), body={"b": 2, "a": 1})
    tagged = staging.drain("deadbeef")
    assert tagged.content == '{"a": 1, "b": 2}'


@pytest.mark.asyncio
async def test_dispatch_unsupported_method_fails_loud() -> None:
    """A non-``quarantine.extract`` dispatch method is a loud refusal."""
    from alfred.errors import AlfredError

    transport = QuarantineStdioTransport(
        child_io=_RecordingChildIO(), staging=QuarantineStagingMap()
    )
    with pytest.raises(AlfredError, match="unsupported wire method"):
        await transport.dispatch("quarantine.ingest", {"handle_id": "x"})


@pytest.mark.asyncio
async def test_dispatch_non_dict_result_yields_empty_payload(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """A non-dict ``result`` frame yields an empty payload dict.

    The transport does NOT classify it — it returns an empty payload so the
    QuarantinedExtractor's own kind/data guards trip the protocol violation.
    """
    staging = QuarantineStagingMap()
    staging.stage("deadbeef", _tag(authorized_t3_nonce, "body"))

    class _NonDictResultChild(_RecordingChildIO):
        def write_frame(self, frame: bytes) -> None:
            length = struct.unpack(">I", frame[:4])[0]
            obj = json.loads(frame[4 : 4 + length])
            if obj["method"] == "quarantine.extract":
                self._pending_reply = _frame({"jsonrpc": "2.0", "result": "not-a-dict"})

    transport = QuarantineStdioTransport(child_io=_NonDictResultChild(), staging=staging)
    result = await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )
    assert result.payload == {}


def test_decode_result_payload_truncated_frame_raises_loud() -> None:
    """A reply frame too short to carry the length header fails LOUD, never empty.

    A malicious/buggy child (adversary-facing once 2b spawns the real subprocess)
    could send a truncated frame. The decode must NOT silently mis-parse it into an
    empty payload (which would let the laundering attempt slip past as a benign
    no-op) — stripping the 4-byte header off a sub-4-byte frame yields an empty
    body that ``json.loads`` rejects, so the failure propagates into the
    extractor's ``transport_failed`` audit (CLAUDE.md hard rule #7).
    """
    with pytest.raises(json.JSONDecodeError):
        _decode_result_payload(b"\x00\x01")  # 2 bytes — shorter than the 4-byte header


# ---------------------------------------------------------------------------
# 9: discard_staged — C9 drain-on-error, no orphaned T3 body (G7-2.5 Task 3)
# ---------------------------------------------------------------------------


def test_t3_body_recorder_discard_staged(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """``discard_staged`` removes a staged T3 body; subsequent drain raises; idempotent.

    Verifies three properties required by C9 (G7-2.5 Task 3):
    1. After staging a body via the recorder, ``discard_staged`` removes it so
       a follow-up ``staging.drain`` raises ``StagingHandleNotConfiguredError``
       (the staged entry is gone, not a silent no-op).
    2. A second call to ``discard_staged`` is a no-op — it does NOT raise even
       though the handle has already been drained/discarded.  This makes the
       ``except BaseException`` block in ``egress_response_extract.handle``
       safe to call unconditionally without checking first.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    handle = _make_handle()

    recorder(handle=handle, body="attack payload")

    # Confirm the body is staged before the discard.
    assert handle.id in staging._staged

    # Discard the staged body.
    recorder.discard_staged(handle.id)

    # After discard the staging map must be empty — the body cannot orphan.
    assert handle.id not in staging._staged

    # A subsequent drain must raise (the entry was removed, not silently zeroed).
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain(handle.id)

    # A second discard is a no-op — must not raise even though handle is gone.
    recorder.discard_staged(handle.id)


def test_staging_map_discard_is_silent_non_raising_no_op(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """``QuarantineStagingMap.discard`` removes a present handle and is a no-op
    (never raises) on an absent one — and, unlike ``drain``, it is NON-logging."""
    staging = QuarantineStagingMap()
    staging.stage("h1", _tag(authorized_t3_nonce, "body"))

    # Present handle → removed.
    staging.discard("h1")
    assert "h1" not in staging._staged
    with pytest.raises(StagingHandleNotConfiguredError):
        staging.drain("h1")

    # Absent handle → silent no-op (no raise).
    staging.discard("never-staged")


def test_discard_staged_on_drained_handle_emits_no_warning(
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C9 happy-path: ``discard_staged`` on an already-drained handle emits NO
    ``security.quarantine_staging.handle_not_configured`` warning and does not raise.

    The OutboundDlp extractor drains the staged body on the success path; C9's
    unconditional ``except BaseException`` cleanup then calls ``discard_staged`` on
    the already-gone handle. Routing that through the loud ``drain`` (old behaviour)
    logged a warning + would have raised — false security noise on a benign cleanup.
    ``discard`` is silent.
    """
    import alfred.security.quarantine_transport as qt

    warnings: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        qt._log,
        "warning",
        lambda *a, **k: warnings.append((a, k)),  # type: ignore[arg-type]
    )

    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    handle = _make_handle()
    recorder(handle=handle, body="attack payload")

    # Simulate the success path: the extractor already drained the body.
    staging.drain(handle.id)
    assert warnings == [], "the happy-path drain itself must not warn"

    # C9 cleanup on the already-drained handle: silent + no raise.
    recorder.discard_staged(handle.id)
    assert warnings == [], (
        "discard_staged on an already-drained handle must NOT emit "
        "security.quarantine_staging.handle_not_configured (false security noise)"
    )
