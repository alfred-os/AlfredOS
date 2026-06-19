"""G6-2b-2a (#288): the live status leg — sink + GatewayCoreLink status seam."""

from __future__ import annotations

import structlog

from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.status_leg import GatewayCoreLinkStatusSink


def _make_core_link() -> GatewayCoreLink:
    return GatewayCoreLink(client_listener=GatewayClientListener())


def test_current_core_epoch_is_none_before_handshake() -> None:
    link = _make_core_link()
    assert link.current_core_epoch() is None


def test_current_core_epoch_reflects_captured_epoch() -> None:
    link = _make_core_link()
    link._core_epoch = "a" * 32  # set as the peer handshake would
    assert link.current_core_epoch() == "a" * 32


class _FakeTransport:
    """Records frames sent via send() (the method-bearing path) vs send_payload_unit()."""

    def __init__(self) -> None:
        self.sent_frames: list[dict[str, object]] = []
        self.sent_payload_units: list[bytes] = []

    async def send(self, frame: dict[str, object]) -> None:
        self.sent_frames.append(frame)

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        self.sent_payload_units.append(payload)


async def test_send_status_frame_uses_send_not_payload_unit() -> None:
    link = _make_core_link()
    transport = _FakeTransport()
    link._current_core_transport = transport  # bound as run() would after handshake
    await link.send_status_frame("gateway.adapter.up", {"adapter_id": "discord", "epoch": "a" * 32})
    assert transport.sent_frames == [
        {
            "jsonrpc": "2.0",
            "method": "gateway.adapter.up",
            "params": {"adapter_id": "discord", "epoch": "a" * 32},
        }
    ]
    # Payload-blindness: the status frame NEVER rides the opaque T3 relay channel.
    assert transport.sent_payload_units == []


async def test_send_status_frame_loud_drops_on_no_transport() -> None:
    link = _make_core_link()  # _current_core_transport is None (no UP leg)
    # No raise AND a LOUD warning (CLAUDE.md hard rule #7: loud, not silent) — a gapped
    # leg is an operational edge, loud-dropped like relay_to_core, never silently swallowed.
    with structlog.testing.capture_logs() as log_records:
        await link.send_status_frame(
            "gateway.adapter.down", {"adapter_id": "discord", "reason": "operator"}
        )
    drop = next(r for r in log_records if r.get("event") == "gateway.status.send_dropped")
    assert drop["log_level"] == "warning"
    assert drop["reason"] == "no_core_transport"


class _RaisingTransport:
    """A transport whose send() raises a recognised send-path fault (loud-drop family)."""

    async def send(self, frame: dict[str, object]) -> None:
        raise BrokenPipeError("core leg died mid-send")

    async def send_payload_unit(
        self, payload: bytes, *, seq: int, ack: int
    ) -> None:  # pragma: no cover - never called on the status path
        raise AssertionError("status frames never ride send_payload_unit")


async def test_send_status_frame_loud_drops_on_send_fault() -> None:
    link = _make_core_link()
    link._current_core_transport = _RaisingTransport()
    # A send-path fault on a live-but-dying leg is a LOUD drop, never raised
    # (mirrors relay_to_core) — the dropped frame re-derives from the next transition.
    with structlog.testing.capture_logs() as log_records:
        await link.send_status_frame(
            "gateway.adapter.crashed",
            {"adapter_id": "discord", "error_class": "X", "detail": ""},
        )
    drop = next(r for r in log_records if r.get("event") == "gateway.status.send_dropped")
    assert drop["log_level"] == "warning"
    assert "error" in drop  # the send-path fault is recorded, not silently swallowed


async def test_status_sink_emits_through_core_link_status_frame() -> None:
    link = _make_core_link()
    transport = _FakeTransport()
    link._current_core_transport = transport
    sink = GatewayCoreLinkStatusSink(core_link=link)
    await sink.emit(
        "gateway.adapter.crashed", {"adapter_id": "discord", "error_class": "X", "detail": ""}
    )
    assert transport.sent_frames == [
        {
            "jsonrpc": "2.0",
            "method": "gateway.adapter.crashed",
            "params": {"adapter_id": "discord", "error_class": "X", "detail": ""},
        }
    ]
    assert transport.sent_payload_units == []
