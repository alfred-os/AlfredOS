"""Unit tests for the core-side forwarded-inbound re-parse (Spec B G6-7-1, #309).

The pure function that turns the gateway's opaque forwarded body back into the
UNCHANGED InboundMessageNotification and enforces the envelope==body adapter_id
equality (the F3 mitigation's data-layer half). No wiring, no leg/admission (that
is G6-7-4) — just the byte-stable, fail-loud re-parse.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from alfred.comms_mcp.errors import (
    InboundBodyMalformedError,
    InboundEnvelopeBodyMismatchError,
)
from alfred.comms_mcp.inbound_reparse import reparse_forwarded_inbound
from alfred.comms_mcp.protocol import (
    GatewayAdapterInboundEnvelope,
    InboundMessageNotification,
)


def _valid_body(adapter_id: str = "discord") -> bytes:
    """A wire-shaped InboundMessageNotification params blob, JSON bytes."""
    return json.dumps(
        {
            "adapter_id": adapter_id,
            "inbound_id": "platform-msg-7",
            "platform_user_id": "user-42",
            "body": {"content": "hello alfred"},
            "sub_payload_refs": [],
            "received_at": datetime(2026, 6, 21, 12, 0, tzinfo=UTC).isoformat(),
            "addressing_signal": "dm",
        }
    ).encode("utf-8")


def test_happy_body_reparses_to_exact_inbound_notification() -> None:
    body = _valid_body("discord")
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=body)

    result = reparse_forwarded_inbound(env)

    assert isinstance(result, InboundMessageNotification)
    assert result.adapter_id == "discord"
    assert result.inbound_id == "platform-msg-7"
    assert result.platform_user_id == "user-42"
    assert result.body == {"content": "hello alfred"}
    assert result.sub_payload_refs == ()
    assert result.addressing_signal == "dm"
    assert result.received_at == datetime(2026, 6, 21, 12, 0, tzinfo=UTC)
    # wire_seq is carrier-leg metadata, not body-derived -> None after re-parse.
    # Pins all 8 InboundMessageNotification fields.
    assert result.wire_seq is None


def test_body_smuggled_wire_seq_is_scrubbed() -> None:
    # wire_seq is HOST-AUTHORITATIVE leg-carrier metadata (ADR-0032), never
    # payload-derived. A malicious adapter child could smuggle a wire_seq inside
    # the untrusted T3 body (it is a declared field, so extra="forbid" does NOT
    # block it). The re-parse MUST scrub it: a forged wire_seq surviving onto the
    # notification could corrupt the BoundedSeqAckTracker high-water (G6-7-4).
    raw = json.loads(_valid_body("discord"))
    raw["wire_seq"] = 999
    body = json.dumps(raw).encode("utf-8")
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=body)

    result = reparse_forwarded_inbound(env)

    assert result.wire_seq is None


def test_envelope_equals_body_adapter_id_passes() -> None:
    body = _valid_body("tui")
    env = GatewayAdapterInboundEnvelope(adapter_id="tui", body=body)
    assert reparse_forwarded_inbound(env).adapter_id == "tui"


def test_envelope_body_adapter_id_mismatch_raises_loud() -> None:
    # Body says discord; envelope (spawn-binding) says tui -> forged-body refusal.
    body = _valid_body("discord")
    env = GatewayAdapterInboundEnvelope(adapter_id="tui", body=body)
    with pytest.raises(InboundEnvelopeBodyMismatchError):
        reparse_forwarded_inbound(env)


def test_non_json_body_raises_malformed() -> None:
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=b"\xff\xfenot json")
    with pytest.raises(InboundBodyMalformedError) as exc_info:
        reparse_forwarded_inbound(env)
    # ``from None`` no-leak contract: the ValidationError (which echoes the raw T3
    # body) must not survive on the raised error's ``__cause__``.
    assert exc_info.value.__cause__ is None


def test_json_but_invalid_notification_raises_malformed() -> None:
    # Valid JSON object, but missing required InboundMessageNotification fields.
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=b'{"adapter_id": "discord"}')
    with pytest.raises(InboundBodyMalformedError) as exc_info:
        reparse_forwarded_inbound(env)
    assert exc_info.value.__cause__ is None


def test_non_object_top_level_json_raises_malformed() -> None:
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=b'"just a string"')
    with pytest.raises(InboundBodyMalformedError):
        reparse_forwarded_inbound(env)


def test_reparse_is_deterministic_on_identical_bytes() -> None:
    # Byte-stability (SEC-309-2): byte-identical bodies -> equal model every time,
    # so G0 dedup on (adapter_id, inbound_id) can never be a silent no-op. Two
    # SEPARATELY-constructed envelopes carrying byte-identical bodies (not the same
    # instance twice) make the determinism assertion exact across distinct inputs.
    body_first = _valid_body("discord")
    body_second = _valid_body("discord")
    assert body_first == body_second
    assert body_first is not body_second
    first = reparse_forwarded_inbound(
        GatewayAdapterInboundEnvelope(adapter_id="discord", body=body_first)
    )
    second = reparse_forwarded_inbound(
        GatewayAdapterInboundEnvelope(adapter_id="discord", body=body_second)
    )
    assert first == second
    assert first.inbound_id == second.inbound_id == "platform-msg-7"


def _walk_exception_chain(exc: BaseException) -> list[BaseException]:
    """Every exception reachable from ``exc`` via ``__cause__`` / ``__context__``."""
    seen: list[BaseException] = []
    stack: list[BaseException | None] = [exc]
    while stack:
        current = stack.pop()
        if current is None or current in seen:
            continue
        seen.append(current)
        stack.append(current.__cause__)
        stack.append(current.__context__)
    return seen


def test_malformed_body_leaks_no_secret_through_exception_chain() -> None:
    # T3-leak canary (#1): a malformed body carrying a secret-shaped sentinel must
    # not surface that sentinel anywhere on the raised exception. ``from None``
    # alone is NOT enough — pydantic's ValidationError echoes ``input_value`` (the
    # raw T3 body), and it survives on ``__context__`` unless the raise happens
    # OUTSIDE the ``except`` block. Both ``__cause__`` and ``__context__`` must be
    # None, and the sentinel must appear in no message across the whole chain.
    sentinel = "sk-LEAKED-SECRET-CANARY-9f3a2b"
    # Valid JSON object so we reach the ValidationError path (missing fields),
    # with the sentinel smuggled into a value pydantic would echo as input_value.
    body = json.dumps({"adapter_id": "discord", "platform_user_id": sentinel}).encode("utf-8")
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=body)

    with pytest.raises(InboundBodyMalformedError) as exc_info:
        reparse_forwarded_inbound(env)
    err = exc_info.value

    assert err.__cause__ is None
    assert err.__context__ is None
    for link in _walk_exception_chain(err):
        assert sentinel not in str(link)
        assert sentinel not in repr(link)


def test_malformed_message_carries_leak_safe_structural_detail() -> None:
    # Structural detail (#2): the malformed message must be a debug aid — it carries
    # the safe adapter_id and structural info (error-type codes and/or loc paths)
    # derived ONLY from exc.errors() type+loc, never the raw input/ctx values.
    sentinel = "sk-LEAKED-SECRET-CANARY-7c1d"
    body = json.dumps({"adapter_id": "discord", "platform_user_id": sentinel}).encode("utf-8")
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=body)

    with pytest.raises(InboundBodyMalformedError) as exc_info:
        reparse_forwarded_inbound(env)
    message = str(exc_info.value)

    assert "discord" in message  # safe closed-vocab adapter_id for audit attribution
    assert "missing" in message  # an error-type code from a required-field omission
    assert "inbound_id" in message  # a loc field-path of one missing field
    assert sentinel not in message  # the smuggled body value never appears


def test_str_body_reparses_identically_to_bytes_body() -> None:
    # The envelope accepts str or bytes; both decode to the same notification.
    body_bytes = _valid_body("discord")
    body_str = body_bytes.decode("utf-8")
    from_bytes = reparse_forwarded_inbound(
        GatewayAdapterInboundEnvelope(adapter_id="discord", body=body_bytes)
    )
    from_str = reparse_forwarded_inbound(
        GatewayAdapterInboundEnvelope(adapter_id="discord", body=body_str)
    )
    assert from_bytes == from_str
