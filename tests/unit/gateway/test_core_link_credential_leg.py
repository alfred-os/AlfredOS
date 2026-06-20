"""Tests for the credential request/response correlation primitive (G6-3 Task 2.5).

The gateway<->core ADR-0031 leg had NO request/response today (it is a
fire-and-forget notification pump). G6-3 adds ONE correlation primitive on
:class:`alfred.gateway.core_link.GatewayCoreLink`:

* ``request_spawn_grant(request, *, timeout)`` — send the ``gateway.adapter.spawn_request``
  frame over the leg's method-bearing ``send`` channel, register a pending waiter
  keyed on ``request_id``, and await the matching ``core.adapter.spawn_grant``
  RESPONSE (the FIRST core->gateway response frame on this leg);
* ``_consume_frame`` / ``_route_unit`` route an inbound ``core.adapter.spawn_grant``
  to its pending waiter (instead of dropping/relaying it);
* a bounded await that fails closed LOUDLY when the link is nominally UP but the
  reply is dropped/unrouted (distinct from await-core link-DOWN — correction A-C2);
* a link-DOWN signal: a request issued with no live transport raises a typed loud
  error (the supervisor's AWAITING_CORE consumes it — Task 4).
"""

from __future__ import annotations

import asyncio
import collections
import json
from collections.abc import Mapping

import pytest

from alfred.comms_mcp.adapter_credential_protocol import (
    CORE_ADAPTER_SPAWN_GRANT,
    GATEWAY_ADAPTER_SPAWN_REQUEST,
    SpawnGrant,
    SpawnRequest,
)
from alfred.gateway.core_link import (
    CredentialLegDownError,
    CredentialReplyTimeoutError,
    GatewayCoreLink,
)
from alfred.plugins.comms_seq_codec import SeqFrame

pytestmark = pytest.mark.asyncio

_EPOCH = "0123456789abcdef0123456789abcdef"
_REQ_ID = "11111111111111111111111111111111"
_SENTINEL_CRED = "SENTINEL-CREDENTIAL-DO-NOT-LEAK-7f3a"


class _RecordingClientListener:
    def __init__(self) -> None:
        self.controls: list[object] = []

    async def send_control(self, notification: object) -> None:
        self.controls.append(notification)


class _FakeCoreTransport:
    def __init__(self) -> None:
        self.sent: list[dict[str, object]] = []
        self.units: collections.deque[SeqFrame] = collections.deque()
        self.sent_units: list[tuple[bytes, int, int]] = []
        self.closed = False
        self.seq_ack_enabled = False

    async def spawn(self) -> None:  # pragma: no cover - unused
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(dict(frame))

    async def read_frame(self) -> Mapping[str, object] | None:  # pragma: no cover - unused here
        return None

    async def read_payload_unit(self) -> SeqFrame | None:  # pragma: no cover - unused here
        return self.units.popleft() if self.units else None

    async def send_payload_unit(
        self, payload: bytes, *, seq: int, ack: int
    ) -> None:  # pragma: no cover
        self.sent_units.append((payload, seq, ack))

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:  # pragma: no cover - unused here
        self.seq_ack_enabled = True


def _link_with_transport() -> tuple[GatewayCoreLink, _FakeCoreTransport]:
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    transport = _FakeCoreTransport()
    link._current_core_transport = transport  # bind a live leg
    link._core_epoch = _EPOCH
    return link, transport


def _request() -> SpawnRequest:
    return SpawnRequest(request_id=_REQ_ID, adapter_id="discord", host_restart_seq=0, epoch=_EPOCH)


def _grant_frame() -> dict[str, object]:
    grant = SpawnGrant(
        request_id=_REQ_ID,
        adapter_id="discord",
        host_restart_seq=0,
        epoch=_EPOCH,
        credential_material=_SENTINEL_CRED,
    )
    return {"jsonrpc": "2.0", "method": CORE_ADAPTER_SPAWN_GRANT, "params": grant.model_dump()}


# --- Happy round-trip ---------------------------------------------------------


async def test_request_spawn_grant_sends_then_awaits_correlated_grant() -> None:
    link, transport = _link_with_transport()
    request = _request()

    async def _deliver_grant() -> None:
        # The core responds: route the grant frame through the leg's consumer.
        await asyncio.sleep(0)
        await link._consume_frame(_grant_frame())

    task = asyncio.ensure_future(link.request_spawn_grant(request, timeout=2.0))
    await _deliver_grant()
    grant = await task

    assert isinstance(grant, SpawnGrant)
    assert grant.credential_material == _SENTINEL_CRED
    # The request frame went out on the method-bearing send channel.
    assert transport.sent[0]["method"] == GATEWAY_ADAPTER_SPAWN_REQUEST
    sent_params = transport.sent[0]["params"]
    assert isinstance(sent_params, dict)
    assert sent_params["request_id"] == _REQ_ID


async def test_grant_routed_via_route_unit_on_seq_wire() -> None:
    # On the production relay-ON wire the grant arrives as a raw SeqFrame whose
    # payload _route_unit method-peeks. It must be routed to the waiter, NOT relayed.
    relayed: list[bytes] = []

    async def _relay(payload: bytes) -> None:
        relayed.append(payload)

    link = GatewayCoreLink(
        client_listener=_RecordingClientListener(),  # type: ignore[arg-type]
        payload_relay=_relay,
    )
    transport = _FakeCoreTransport()
    link._current_core_transport = transport
    link._core_epoch = _EPOCH

    task = asyncio.ensure_future(link.request_spawn_grant(_request(), timeout=2.0))
    await asyncio.sleep(0)
    payload = json.dumps(_grant_frame()).encode("utf-8")
    await link._route_unit(SeqFrame(payload=payload, seq=0, ack=0))
    grant = await task

    assert grant.credential_material == _SENTINEL_CRED
    assert relayed == []  # the grant was consumed, never leaked to the client relay


# --- Bounded-await fail-closed on a dropped reply (correction A-C2) -----------


async def test_request_times_out_loud_when_reply_dropped() -> None:
    link, _transport = _link_with_transport()
    with pytest.raises(CredentialReplyTimeoutError):
        await link.request_spawn_grant(_request(), timeout=0.01)
    # The pending waiter is cleaned up (no leak): a late grant resolves nothing.
    assert link._pending_grants == {}


# --- Link-DOWN: no live transport (Task 4 consumes this) ----------------------


async def test_request_with_no_transport_raises_leg_down() -> None:
    link = GatewayCoreLink(client_listener=_RecordingClientListener())  # type: ignore[arg-type]
    link._core_epoch = _EPOCH
    # No _current_core_transport bound.
    with pytest.raises(CredentialLegDownError):
        await link.request_spawn_grant(_request(), timeout=2.0)


# --- Unsolicited grant (no pending request) -> dropped, not crashed (adv e) ---


async def test_unsolicited_grant_is_dropped() -> None:
    link, _transport = _link_with_transport()
    # No outstanding request: a grant frame is dropped (loud), never crashes.
    await link._consume_frame(_grant_frame())
    assert link._pending_grants == {}


# --- A grant for a DIFFERENT request_id does not resolve our waiter -----------


async def test_grant_for_other_request_id_does_not_resolve() -> None:
    link, _transport = _link_with_transport()

    async def _deliver_wrong_then_right() -> None:
        await asyncio.sleep(0)
        wrong = SpawnGrant(
            request_id="99999999999999999999999999999999",
            adapter_id="discord",
            host_restart_seq=0,
            epoch=_EPOCH,
            credential_material="other",
        )
        await link._consume_frame(
            {"jsonrpc": "2.0", "method": CORE_ADAPTER_SPAWN_GRANT, "params": wrong.model_dump()}
        )
        # Our waiter is still pending; now deliver the right one.
        await link._consume_frame(_grant_frame())

    task = asyncio.ensure_future(link.request_spawn_grant(_request(), timeout=2.0))
    await _deliver_wrong_then_right()
    grant = await task
    assert grant.request_id == _REQ_ID
