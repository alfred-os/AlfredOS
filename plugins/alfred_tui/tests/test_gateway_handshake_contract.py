"""Pin the gateway<->cohost ``lifecycle.start`` handshake contract (Spec A G5 / #237).

The ``alfred-gateway`` stands in for the daemon on its CLIENT leg: it SENDS
``lifecycle.start`` to a dialed-in, UNMODIFIED TUI and STRICTLY validates the
result (:func:`alfred.gateway.client_link.client_handshake`). These two sides
were built to a shared spec but never actually connected until G5 re-points
``alfred chat`` at the gateway. This module exercises the wire contract in
ISOLATION — it drives the gateway's EXACT request params through the real
:class:`alfred_tui.server.TuiServer` and re-validates the cohost's result with
the gateway's STRICT :class:`LifecycleStartResult` model.

Three load-bearing properties:

* (a) the cohost ACCEPTS the minimal ``{adapter_id, seq_ack}`` the gateway sends
  (no ``credentials_ref`` / ``policies_snapshot_hash`` — relying on ADR-0035);
* (b) the cohost's result PASSES the gateway's strict result validation
  (``ok`` truthy, ``plugin_version`` non-empty, ``extra="forbid"`` satisfied);
* (c) the cohost does NOT echo ``seq_ack`` — the real operator-local TUI has no
  seq codec on its ``read_frame`` path, so the gateway must leave the client leg
  PLAIN. A cohost echoing ``seq_ack`` without deframing is the G2
  echo-without-deframe corruption bug.
"""

from __future__ import annotations

import pytest
from alfred_tui.server import build_server

from alfred.comms_mcp.protocol import (
    LifecycleStartRequest,
    LifecycleStartResult,
)

# ``SEQ_VERSION`` is the single source of truth in the seq/ack codec module — the
# SAME import the gateway's ``client_link`` uses to build its advertisement. The
# protocol's ``SeqAckCapability.version`` is a ``Literal["1"]`` pinned to it.
from alfred.plugins.comms_seq_codec import SEQ_VERSION

# The EXACT params the gateway's ``client_handshake`` sends (mirrors
# ``alfred.gateway.client_link``: ``_CLIENT_ADAPTER_ID="tui"`` + the version-gated
# seq/ack advertisement). No credentials / policies hash — ADR-0035 made them
# optional so the minimal handshake omits them.
_GATEWAY_START_PARAMS: dict[str, object] = {
    "adapter_id": "tui",
    "seq_ack": {"version": SEQ_VERSION},
}


def test_gateway_start_params_validate_against_the_request_model() -> None:
    """(a) The gateway's minimal params satisfy ``LifecycleStartRequest`` (ADR-0035).

    Asserts the exact ``{adapter_id, seq_ack}`` the gateway sends — with NO
    ``credentials_ref`` / ``policies_snapshot_hash`` — is a valid request, so the
    cohost's ``model_validate(params)`` in ``_handle`` cannot reject it.
    """
    req = LifecycleStartRequest.model_validate(_GATEWAY_START_PARAMS)
    assert req.adapter_id == "tui"
    assert req.credentials_ref is None
    assert req.policies_snapshot_hash is None
    assert req.seq_ack is not None
    assert req.seq_ack.version == SEQ_VERSION


@pytest.mark.asyncio
async def test_cohost_accepts_the_gateways_lifecycle_start_request() -> None:
    """(a) Drive the gateway's EXACT params THROUGH the real cohost dispatch.

    Constructs a real :class:`TuiServer` (over a default :class:`TuiSession`) and
    dispatches ``lifecycle.start`` with the gateway's params: it must NOT raise and
    must return a result mapping (not a JSON-RPC error frame).
    """
    server = build_server()
    response = await server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "lifecycle.start",
            "params": _GATEWAY_START_PARAMS,
        }
    )
    assert response is not None
    assert "error" not in response, response
    assert isinstance(response["result"], dict)


@pytest.mark.asyncio
async def test_cohost_result_passes_the_gateways_strict_validation() -> None:
    """(b) The cohost's result satisfies the gateway's strict ``LifecycleStartResult``.

    The gateway's ``_negotiate_from_result`` rejects a not-ok / missing-version /
    stray-field result via ``LifecycleStartResult.model_validate`` (``extra="forbid"``).
    The cohost's actual returned result must pass that same gate, with ``ok`` True
    and a non-empty ``plugin_version``.
    """
    server = build_server()
    response = await server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "lifecycle.start",
            "params": _GATEWAY_START_PARAMS,
        }
    )
    assert response is not None
    result = response["result"]

    validated = LifecycleStartResult.model_validate(result)
    assert validated.ok is True
    assert validated.plugin_version
    assert len(validated.plugin_version) >= 1


@pytest.mark.asyncio
async def test_cohost_leaves_the_client_leg_plain_no_seq_ack_echo() -> None:
    """(c) The cohost does NOT echo ``seq_ack`` -> the gateway keeps the leg PLAIN.

    The real operator-local TUI has no seq codec on its ``read_frame`` path. If it
    echoed the gateway's ``seq_ack`` advertisement, the gateway's
    ``_negotiate_from_result`` would flip seq/ack ON (``client_seq_enabled=True``)
    and then wrap frames the cohost cannot deframe — the G2 echo-without-deframe
    corruption. So the result's ``seq_ack`` MUST be absent/None.
    """
    server = build_server()
    response = await server.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "lifecycle.start",
            "params": _GATEWAY_START_PARAMS,
        }
    )
    assert response is not None
    result = response["result"]

    # On the wire the field is either absent or explicitly null; both leave the
    # gateway's client leg plain.
    assert result.get("seq_ack") is None
    assert LifecycleStartResult.model_validate(result).seq_ack is None
