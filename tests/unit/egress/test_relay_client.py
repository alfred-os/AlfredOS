"""Unit tests for the in-core mode-(b) relay client (Spec C G7-2c-1, epic #333).

RED-first: all nine required behaviours from the C1 brief are assertive test
functions exercised against a fake gateway (in-memory StreamReader/Writer pair).
The test suite verifies:

1. Fresh fire — DLP redaction runs, the request frame carries the redacted body,
   egress_id, method, and url; returns ``Fired``.
2. ReplayComplete short-circuit — no dial, no audit row.
3. InDoubt + non-idempotent — raises EgressInDoubtError, no dial, exactly one
   in-doubt audit row.
4. InDoubt + idempotent refire — dials with Idempotency-Key header in frame.
5. Different-hash duplicate (EgressIdIntegrityError) — propagates, no dial.
6. Relay unreachable (OSError on open_connection) — IOPlaneUnavailableError +
   io-down audit row.
7. Truncated reply (EOF mid-frame) — IOPlaneUnavailableError + io-down audit row.
8. Relay deny frame — EgressDeniedError + exactly one denied audit row.
9. Head-of-line safety — a slow fire under the semaphore does not block a second
   concurrent fire on a free slot (deterministic asyncio.Event gate).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from alfred.egress.egress_id import (
    EgressIdIntegrityError,
    TurnEgressContext,
)
from alfred.egress.errors import EgressDeniedError, EgressInDoubtError, IOPlaneUnavailableError
from alfred.egress.relay_client import Deduplicated, Fired, RelayEgressClient
from alfred.egress.relay_protocol import (
    EgressRelayDenyReason,
    EgressRelayReply,
    EgressResponse,
    _RawToolRequest,
)
from alfred.memory.egress_idempotency import (
    CommitIntentResult,
    IntentFresh,
    IntentInDoubt,
    IntentReplayComplete,
)

# ---------------------------------------------------------------------------
# Fake infrastructure helpers
# ---------------------------------------------------------------------------

_CTX = TurnEgressContext(adapter_id="ada-1", inbound_id="in-1", session_id="sess-1")
_RELAY_URL = "tcp://localhost:9999"
_CALL_INDEX = 0


def _make_raw_request(
    *,
    body: str = "raw body",
    idempotent: bool = False,
    url: str = "https://api.example.com/data",
) -> _RawToolRequest:
    return _RawToolRequest(
        method="POST",
        url=url,
        headers={"accept": "application/json"},
        body=body,
        idempotent=idempotent,
    )


def _make_resp(body: bytes = b"ok") -> EgressResponse:
    return EgressResponse(status=200, headers={}, body=body)


# ---------------------------------------------------------------------------
# Stub DLP — passes body through; proves scan_for_outbound ran by prefixing
# the redacted text with a sentinel so tests can assert core stage-1 ran.
# ---------------------------------------------------------------------------


class _StubDlp:
    """Minimal stand-in for OutboundDlp that applies a deterministic redaction.

    Replaces every occurrence of ``RAW:`` with ``REDACTED:`` so the test can
    assert the request frame carries the DLP-redacted body, not the original.
    Scan is synchronous (OutboundDlp.scan_for_outbound is sync).
    """

    def scan_for_outbound(self, raw_body: str) -> tuple[str, Any]:
        # ScannedOutboundBody is a NewType over (str, OutboundDlpScanResult);
        # returning a plain tuple satisfies callers that only consume [0].
        redacted = raw_body.replace("RAW:", "REDACTED:")
        scan_result = MagicMock()
        scan_result.dlp_redactions_count = 0
        scan_result.canary_tripped = False
        return (redacted, scan_result)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Fake idempotency store
# ---------------------------------------------------------------------------


@dataclass
class _StubLedger:
    """Scripted EgressIdempotencyStore returning a preset CommitIntentResult."""

    result: CommitIntentResult = field(default_factory=IntentFresh)

    async def commit_intent(self, **_kwargs: Any) -> CommitIntentResult:
        return self.result

    async def record_response(self, **_kwargs: Any) -> None:
        return None

    async def prune_expired(self, **_kwargs: Any) -> int:
        return 0


class _ErrorLedger:
    """Ledger that raises EgressIdIntegrityError unconditionally."""

    async def commit_intent(self, *, egress_id: str, **_kwargs: Any) -> CommitIntentResult:
        raise EgressIdIntegrityError(egress_id=egress_id)

    async def record_response(self, **_kwargs: Any) -> None:
        return None

    async def prune_expired(self, **_kwargs: Any) -> int:
        return 0


# ---------------------------------------------------------------------------
# Spy audit writer (captures append_schema calls)
# ---------------------------------------------------------------------------


@dataclass
class _SpyAudit:
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def append_schema(self, **kwargs: Any) -> None:
        self.calls.append(dict(kwargs))


# ---------------------------------------------------------------------------
# In-memory fake gateway helpers
# ---------------------------------------------------------------------------


def _stream_pair() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A StreamReader fed by a loopback StreamWriter (mirrors relay_protocol tests)."""
    reader = asyncio.StreamReader()

    class _LoopbackWriter:
        def __init__(self) -> None:
            self.written: bytearray = bytearray()
            self._closed = False

        def write(self, data: bytes) -> None:
            reader.feed_data(data)
            self.written.extend(data)

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            self._closed = True

        async def wait_closed(self) -> None:
            return None

    return reader, _LoopbackWriter()  # type: ignore[return-value]


async def _make_open_connection(
    reply: EgressRelayReply,
) -> Callable[[str, int], tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    """Return a fake open_connection that pre-feeds ``reply`` as the first frame."""

    async def _open(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader = asyncio.StreamReader()

        class _Writer:
            def __init__(self) -> None:
                self.written: bytearray = bytearray()

            def write(self, data: bytes) -> None:
                self.written.extend(data)

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                return None

        writer = _Writer()
        frame = reply.model_dump_json().encode("utf-8")
        reader.feed_data(len(frame).to_bytes(4, "big") + frame)
        reader.feed_eof()
        return reader, writer  # type: ignore[return-value]

    return _open


async def _make_eof_connection() -> Callable[
    [str, int], tuple[asyncio.StreamReader, asyncio.StreamWriter]
]:
    """Return a fake open_connection that returns a reader at EOF (truncated reply)."""

    async def _open(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader = asyncio.StreamReader()

        class _Writer:
            def write(self, data: bytes) -> None:
                pass

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                return None

        # Feed a frame header claiming 10 bytes but supply only 3 → truncated.
        reader.feed_data((10).to_bytes(4, "big") + b"abc")
        reader.feed_eof()
        return reader, _Writer()  # type: ignore[return-value]

    return _open


def _make_client(
    *,
    ledger: Any = None,
    open_connection: Any = None,
    audit: Any = None,
    concurrency: int = 4,
) -> RelayEgressClient:
    return RelayEgressClient(
        relay_url=_RELAY_URL,
        core_dlp=_StubDlp(),  # type: ignore[arg-type]
        ledger=ledger or _StubLedger(),
        audit_writer=audit or _SpyAudit(),
        concurrency=concurrency,
        open_connection=open_connection,
    )


# ---------------------------------------------------------------------------
# Test 1 — Fresh fire: DLP redaction propagates, frame is correct, returns Fired
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fresh_fire_sends_correct_frame_and_returns_fired() -> None:
    """C1-T1: fresh intent → fire; request frame carries DLP-redacted body."""
    resp = _make_resp(b"hello")
    open_conn = await _make_open_connection(EgressRelayReply(response=resp))
    audit = _SpyAudit()
    client = _make_client(open_connection=open_conn, audit=audit)

    raw = _make_raw_request(body="RAW: secret data")
    outcome = await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    assert isinstance(outcome, Fired)
    assert outcome.response == resp
    # No audit row on successful fire
    assert len(audit.calls) == 0


@pytest.mark.asyncio
async def test_fresh_fire_body_is_dlp_redacted() -> None:
    """C1-T1b: the frame's body equals the DLP-redacted text, not the raw input."""
    written_frames: list[bytes] = []

    async def _capture_open(
        host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader = asyncio.StreamReader()
        reply = EgressRelayReply(response=_make_resp(b"ok"))
        frame_bytes = reply.model_dump_json().encode("utf-8")
        reader.feed_data(len(frame_bytes).to_bytes(4, "big") + frame_bytes)
        reader.feed_eof()

        class _CapWriter:
            def write(self, data: bytes) -> None:
                written_frames.append(data)

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                return None

        return reader, _CapWriter()  # type: ignore[return-value]

    client = _make_client(open_connection=_capture_open)
    raw = _make_raw_request(body="RAW: some sensitive value")
    await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    # Decode the written frame: 4-byte prefix + JSON payload
    assert written_frames, "no bytes written to connection"
    combined = b"".join(written_frames)
    payload = combined[4:]  # strip length prefix
    parsed = json.loads(payload)
    assert parsed["body"] == "REDACTED: some sensitive value"
    assert parsed["method"] == "POST"
    assert parsed["url"] == "https://api.example.com/data"
    # egress_id must be a 64-char hex string
    assert len(parsed["egress_id"]) == 64


# ---------------------------------------------------------------------------
# Test 2 — ReplayComplete: no dial, no audit row, returns Deduplicated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_complete_returns_deduplicated_without_dialing() -> None:
    """C1-T2: a committed_with_response ledger entry → Deduplicated; no network call."""
    dialed = False

    async def _should_not_dial(host: str, port: int) -> Any:
        nonlocal dialed
        dialed = True
        raise AssertionError("open_connection must not be called on replay")

    audit = _SpyAudit()
    client = _make_client(
        ledger=_StubLedger(result=IntentReplayComplete(response="stored_t2", language="en-US")),
        open_connection=_should_not_dial,
        audit=audit,
    )
    raw = _make_raw_request()
    outcome = await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    assert isinstance(outcome, Deduplicated)
    assert outcome.stored_t2 == "stored_t2"
    assert outcome.language == "en-US"
    assert not dialed
    assert len(audit.calls) == 0, "no audit row on replay"


# ---------------------------------------------------------------------------
# Test 3 — InDoubt + non-idempotent: raises EgressInDoubtError, no dial
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_indoubt_non_idempotent_raises_and_audits() -> None:
    """C1-T3: in-doubt + idempotent=False → EgressInDoubtError; exactly one audit row."""
    dialed = False

    async def _should_not_dial(host: str, port: int) -> Any:
        nonlocal dialed
        dialed = True
        raise AssertionError("must not dial on non-idempotent in-doubt")

    audit = _SpyAudit()
    client = _make_client(
        ledger=_StubLedger(result=IntentInDoubt()),
        open_connection=_should_not_dial,
        audit=audit,
    )
    raw = _make_raw_request(idempotent=False)
    with pytest.raises(EgressInDoubtError):
        await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    assert not dialed
    assert len(audit.calls) == 1
    assert audit.calls[0]["result"] == "in_doubt"


# ---------------------------------------------------------------------------
# Test 4 — InDoubt + idempotent: refires with Idempotency-Key header
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_indoubt_idempotent_refires_with_idempotency_key_header() -> None:
    """C1-T4: in-doubt + idempotent=True → refires; frame headers carry Idempotency-Key."""
    written_frames: list[bytes] = []
    resp = _make_resp(b"refire ok")

    async def _capture_open(
        host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader = asyncio.StreamReader()
        reply = EgressRelayReply(response=resp)
        frame_bytes = reply.model_dump_json().encode("utf-8")
        reader.feed_data(len(frame_bytes).to_bytes(4, "big") + frame_bytes)
        reader.feed_eof()

        class _CapWriter:
            def write(self, data: bytes) -> None:
                written_frames.append(data)

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                return None

        return reader, _CapWriter()  # type: ignore[return-value]

    audit = _SpyAudit()
    client = _make_client(
        ledger=_StubLedger(result=IntentInDoubt()),
        open_connection=_capture_open,
        audit=audit,
    )
    raw = _make_raw_request(idempotent=True)
    outcome = await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    assert isinstance(outcome, Fired)
    assert outcome.response == resp
    # No audit row on successful idempotent refire
    assert len(audit.calls) == 0

    combined = b"".join(written_frames)
    payload = combined[4:]
    parsed = json.loads(payload)
    egress_id = parsed["egress_id"]
    assert "Idempotency-Key" in parsed["headers"]
    assert parsed["headers"]["Idempotency-Key"] == egress_id


# ---------------------------------------------------------------------------
# Test 5 — Different-hash duplicate: EgressIdIntegrityError propagates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_integrity_error_propagates_without_dialing() -> None:
    """C1-T5: ledger raises EgressIdIntegrityError → propagates; no dial."""
    dialed = False

    async def _should_not_dial(host: str, port: int) -> Any:
        nonlocal dialed
        dialed = True
        raise AssertionError("must not dial on integrity error")

    client = _make_client(
        ledger=_ErrorLedger(),
        open_connection=_should_not_dial,
    )
    raw = _make_raw_request()
    with pytest.raises(EgressIdIntegrityError):
        await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    assert not dialed


# ---------------------------------------------------------------------------
# Test 6 — Relay unreachable (OSError): IOPlaneUnavailableError + audit row
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unreachable_relay_raises_io_plane_unavailable_and_audits() -> None:
    """C1-T6: OSError on open_connection → IOPlaneUnavailableError + io-down audit row."""

    async def _refuse_connect(host: str, port: int) -> Any:
        raise OSError("connection refused")

    audit = _SpyAudit()
    client = _make_client(open_connection=_refuse_connect, audit=audit)
    raw = _make_raw_request()

    with pytest.raises(IOPlaneUnavailableError):
        await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    assert len(audit.calls) == 1
    assert audit.calls[0]["result"] == "io_plane_unavailable"


# ---------------------------------------------------------------------------
# Test 7 — Truncated reply: IOPlaneUnavailableError + io-down audit row
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_truncated_reply_raises_io_plane_unavailable_and_audits() -> None:
    """C1-T7: EOF mid-frame → IOPlaneUnavailableError + io-down audit row."""
    open_conn = await _make_eof_connection()
    audit = _SpyAudit()
    client = _make_client(open_connection=open_conn, audit=audit)
    raw = _make_raw_request()

    with pytest.raises(IOPlaneUnavailableError):
        await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    assert len(audit.calls) == 1
    assert audit.calls[0]["result"] == "io_plane_unavailable"


# ---------------------------------------------------------------------------
# Test 8 — Relay deny frame: EgressDeniedError + denied audit row
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_frame_raises_egress_denied_and_audits() -> None:
    """C1-T8: EgressRelayReply with deny_reason → EgressDeniedError + denied audit row."""
    deny_reason = EgressRelayDenyReason.DESTINATION_NOT_ALLOWLISTED
    open_conn = await _make_open_connection(EgressRelayReply(deny_reason=deny_reason))
    audit = _SpyAudit()
    client = _make_client(open_connection=open_conn, audit=audit)
    raw = _make_raw_request()

    with pytest.raises(EgressDeniedError) as exc_info:
        await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    err = exc_info.value
    assert err.deny_reason == str(deny_reason)
    assert len(audit.calls) == 1
    assert audit.calls[0]["result"] == "denied"


# ---------------------------------------------------------------------------
# Test 9 — HoL safety: second fire completes while first is parked
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_fire_does_not_head_of_line_block() -> None:
    """C1-T9: a semaphore-parked fire (concurrency≥2) does not block a second slot.

    Gate: the first coroutine parks at ``slow_gate`` (an asyncio.Event); the
    second fires independently through an immediately-resolved gateway and
    completes before the first is released. Deterministic — no sleep.
    """
    slow_gate = asyncio.Event()
    first_started = asyncio.Event()

    resp = _make_resp(b"second ok")

    call_count = 0

    async def _gated_open(
        host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First caller: signal it started, then park until released.
            first_started.set()
            await slow_gate.wait()
        reader = asyncio.StreamReader()
        reply = EgressRelayReply(response=resp)
        frame_bytes = reply.model_dump_json().encode("utf-8")
        reader.feed_data(len(frame_bytes).to_bytes(4, "big") + frame_bytes)
        reader.feed_eof()

        class _W:
            def write(self, data: bytes) -> None:
                pass

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                return None

        return reader, _W()  # type: ignore[return-value]

    # concurrency=2 so both slots are available simultaneously.
    client = _make_client(open_connection=_gated_open, concurrency=2)
    raw1 = _make_raw_request(url="https://api.example.com/slow")
    raw2 = _make_raw_request(url="https://api.example.com/fast")

    ctx1 = TurnEgressContext(adapter_id="ada-1", inbound_id="in-1", session_id="sess-1")
    ctx2 = TurnEgressContext(adapter_id="ada-2", inbound_id="in-2", session_id="sess-2")

    t1 = asyncio.create_task(client.fire(raw_request=raw1, ctx=ctx1, call_index=0))

    # Wait for the first fire to enter the gateway open_connection (gated).
    await asyncio.wait_for(first_started.wait(), timeout=5.0)

    # Second fire should complete immediately (its slot is free).
    outcome2 = await asyncio.wait_for(
        client.fire(raw_request=raw2, ctx=ctx2, call_index=0), timeout=5.0
    )
    assert isinstance(outcome2, Fired)
    assert not t1.done(), "first task must still be parked"

    # Release first.
    slow_gate.set()
    outcome1 = await asyncio.wait_for(t1, timeout=5.0)
    assert isinstance(outcome1, Fired)


# ---------------------------------------------------------------------------
# Test 10 — Malformed reply frame (ValidationError): IOPlaneUnavailableError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_reply_frame_raises_io_plane_unavailable_and_audits() -> None:
    """C1-T10: a well-framed but structurally invalid JSON reply → IOPlaneUnavailableError.

    Exercises the ``except Exception`` branch in ``_do_fire`` (the parse fault
    path for a gateway that returns valid JSON but fails ``EgressRelayReply``
    model validation — e.g. an unknown deny_reason or missing both fields).
    """

    async def _bad_frame_open(
        host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader = asyncio.StreamReader()
        # A well-framed payload that is valid JSON but fails the exactly-one
        # model_validator (both response and deny_reason are None).
        payload = b'{"response": null, "deny_reason": null}'
        reader.feed_data(len(payload).to_bytes(4, "big") + payload)
        reader.feed_eof()

        class _W:
            def write(self, data: bytes) -> None:
                pass

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                return None

        return reader, _W()  # type: ignore[return-value]

    audit = _SpyAudit()
    client = _make_client(open_connection=_bad_frame_open, audit=audit)
    raw = _make_raw_request()

    with pytest.raises(IOPlaneUnavailableError):
        await client.fire(raw_request=raw, ctx=_CTX, call_index=_CALL_INDEX)

    assert len(audit.calls) == 1
    assert audit.calls[0]["result"] == "io_plane_unavailable"
