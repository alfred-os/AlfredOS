"""Runner-side forwarded-inbound receiver threading (G6-7-4 Task 5, #309).

The daemon (HOST runner) over the GATEWAY leg injects the per-boot
``GatewayForwardedInboundReceiver`` into :class:`CommsPluginRunner`, which threads
it into the default :class:`SessionDispatchDisposition`. A ``gateway.adapter.inbound``
notification is then routed to the receiver (re-parse + dispatched-edge commit)
INSTEAD of the session's ``unknown_method`` refusal.

* a runner built WITH a receiver routes ``gateway.adapter.inbound`` to it, with the
  out-of-band ``wire_seq`` threaded through unchanged, and NOT into the session;
* a runner built WITHOUT one (the stdio / daemon-spawned legs) leaves the routing OFF
  — the frame falls through to the session (the unknown_method refusal) and the
  receiver is never reached.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.comms_mcp.protocol import GATEWAY_ADAPTER_INBOUND
from alfred.plugins.comms_runner import CommsPluginRunner

pytestmark = pytest.mark.asyncio

_ADAPTER_ID = "discord"


class _NoopTransport:
    async def spawn(self) -> None:  # pragma: no cover - unused
        return None

    async def send(self, frame: Mapping[str, object]) -> None:  # pragma: no cover
        return None

    async def read_frame(self) -> Mapping[str, object] | None:  # pragma: no cover
        return None

    async def close(self) -> None:  # pragma: no cover
        return None

    def enable_seq_ack(self) -> None:  # pragma: no cover
        return None


class _FakeReceiver:
    """Records every ``receive`` call; stands in for the real receiver."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.bound_tracker: object | None = None

    async def receive(self, *, params: object, wire_seq: int | None) -> None:
        self.calls.append({"params": params, "wire_seq": wire_seq})

    def set_ack_tracker(self, ack_tracker: object) -> None:
        self.bound_tracker = ack_tracker


def _runner(*, receiver: Any | None) -> CommsPluginRunner:
    session = MagicMock()
    session._on_post_handshake_method = AsyncMock()
    session._supervisor = MagicMock()
    session._supervisor.request_plugin_restart = AsyncMock()
    return CommsPluginRunner(
        session=session,
        transport=_NoopTransport(),  # type: ignore[arg-type]
        adapter_id=_ADAPTER_ID,
        forwarded_inbound_receiver=receiver,
    )


async def test_forwarded_inbound_routed_to_receiver_with_wire_seq() -> None:
    receiver = _FakeReceiver()
    runner = _runner(receiver=receiver)
    params = {"adapter_id": _ADAPTER_ID, "body": "{}"}

    await runner._route_notification(GATEWAY_ADAPTER_INBOUND, params, wire_seq=7)

    # The receiver saw the frame with the out-of-band wire_seq threaded through...
    assert receiver.calls == [{"params": params, "wire_seq": 7}]
    # ...and the session dispatch was NOT invoked (intercepted before the refusal).
    runner._session._on_post_handshake_method.assert_not_awaited()


async def test_no_receiver_wired_falls_through_to_session() -> None:
    runner = _runner(receiver=None)
    params = {"adapter_id": _ADAPTER_ID, "body": "{}"}

    await runner._route_notification(GATEWAY_ADAPTER_INBOUND, params, wire_seq=7)

    # With no receiver wired, the frame falls through to the session dispatch (which
    # routes it to the status observer's unknown_method refusal). The receiver path is
    # never taken — proved by the session dispatch being awaited with the wire_seq.
    runner._session._on_post_handshake_method.assert_awaited_once()
    _, kwargs = runner._session._on_post_handshake_method.call_args
    assert kwargs["wire_seq"] == 7
