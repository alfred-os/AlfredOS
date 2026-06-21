"""Unit tests for the gateway.adapter.inbound envelope (Spec B G6-7-1, #309).

The envelope is the gateway->core wire contract for a forwarded hosted-adapter
inbound. It carries the gateway-supplied out-of-band ``adapter_id`` (the spawn
binding mints it in G6-7-3; this slice only MODELS it) plus the opaque T3 body
the gateway never parses. The model itself is body-opaque: it stores ``body`` as
an untouched ``bytes``/``str`` member and never introspects it.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    GATEWAY_ADAPTER_INBOUND,
    GatewayAdapterInboundEnvelope,
)


def test_method_constant_is_the_wire_name() -> None:
    assert GATEWAY_ADAPTER_INBOUND == "gateway.adapter.inbound"


def test_envelope_constructs_with_bytes_body() -> None:
    body = json.dumps({"adapter_id": "discord"}).encode("utf-8")
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=body)
    assert env.adapter_id == "discord"
    assert env.body == body


def test_envelope_accepts_str_body_unparsed() -> None:
    # The envelope is body-opaque: a str body is stored verbatim, never parsed.
    raw = '{"this is": "not parsed by the envelope"}'
    env = GatewayAdapterInboundEnvelope(adapter_id="tui", body=raw)
    assert env.body == raw


def test_envelope_is_frozen() -> None:
    env = GatewayAdapterInboundEnvelope(adapter_id="discord", body=b"{}")
    with pytest.raises(ValidationError):
        env.adapter_id = "tui"  # type: ignore[misc]


def test_envelope_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        GatewayAdapterInboundEnvelope(
            adapter_id="discord",
            body=b"{}",
            smuggled="nope",  # type: ignore[call-arg]
        )


def test_envelope_rejects_unknown_adapter_kind() -> None:
    # adapter_id is the closed-vocab AdapterId; an unknown kind is a loud reject.
    with pytest.raises(ValidationError):
        GatewayAdapterInboundEnvelope(adapter_id="telegram", body=b"{}")
