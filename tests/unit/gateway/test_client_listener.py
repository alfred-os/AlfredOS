"""``GatewayClientListener`` — client-facing socket + control-frame emit (G3-3a).

Drives the thin client-facing kernel:

* it binds the gateway's own ``comms-gateway.sock`` (reused ``CommsSocketListener``,
  ``adapter_id="gateway"``) and accepts ONE same-uid loopback client;
* :meth:`send_control` writes the id-less ``{"jsonrpc":"2.0","method":"link.*",
  "params":{}}`` frame to the accepted client;
* a ``send_control`` BEFORE ``accept`` is a loud programming error;
* a ``send_control`` to a CLOSED client is LOUD (re-raised), never silent (security M2);
* peer-auth + the structlog-only ``on_peer_rejected`` are wired (a mismatched-uid peer
  is refused — exercised via the reused listener's seam).
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from alfred.comms_mcp.protocol import (
    LINK_RECONNECTING,
    LINK_RESTORED,
    LinkReconnectingNotification,
    LinkRestoredNotification,
    LinkUnavailableNotification,
)
from alfred.gateway import control_notification
from alfred.gateway.client_listener import (
    _GATEWAY_ADAPTER_ID,
    _METHOD_BY_MODEL,
    GatewayClientListener,
    _structlog_only_peer_rejected,
)
from alfred.gateway.link_state import (
    GatewayLinkEvent,
    LinkStateMachine,
)


@pytest.fixture
def runtime_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the socket runtime dir at a SHORT tmp HOME so tests never touch ~/.run."""
    with tempfile.TemporaryDirectory(prefix="alfgw-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


@pytest.fixture
async def _connected(
    runtime_dir: Path,
) -> AsyncIterator[tuple[GatewayClientListener, asyncio.StreamReader, asyncio.StreamWriter]]:
    listener = GatewayClientListener()
    await listener.bind()
    accept_task = asyncio.create_task(listener.accept())
    reader, writer = await asyncio.open_unix_connection(path=str(listener.path))
    await accept_task
    try:
        yield listener, reader, writer
    finally:
        writer.close()
        await listener.aclose()


def test_listener_uses_gateway_adapter_id() -> None:
    assert _GATEWAY_ADAPTER_ID == "gateway"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_bind_creates_gateway_keyed_socket(runtime_dir: Path) -> None:
    listener = GatewayClientListener()
    await listener.bind()
    try:
        assert listener.path == runtime_dir / "comms-gateway.sock"
        assert listener.path.is_socket()
    finally:
        await listener.aclose()
    assert not listener.path.exists()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_send_control_writes_idless_reconnecting_frame(
    _connected: tuple[GatewayClientListener, asyncio.StreamReader, asyncio.StreamWriter],
) -> None:
    listener, reader, _writer = _connected
    await listener.send_control(LinkReconnectingNotification())
    line = await asyncio.wait_for(reader.readline(), timeout=2.0)
    assert json.loads(line) == {
        "jsonrpc": "2.0",
        "method": "link.reconnecting",
        "params": {},
    }


@pytest.mark.parametrize(
    ("model", "method"),
    [
        (LinkReconnectingNotification, "link.reconnecting"),
        (LinkRestoredNotification, "link.restored"),
        (LinkUnavailableNotification, "link.unavailable"),
    ],
)
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_send_control_routes_each_method(
    _connected: tuple[GatewayClientListener, asyncio.StreamReader, asyncio.StreamWriter],
    model: type[LinkReconnectingNotification],
    method: str,
) -> None:
    listener, reader, _writer = _connected
    await listener.send_control(model())
    line = await asyncio.wait_for(reader.readline(), timeout=2.0)
    assert json.loads(line)["method"] == method


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_send_control_before_accept_is_loud(runtime_dir: Path) -> None:
    listener = GatewayClientListener()
    await listener.bind()
    try:
        with pytest.raises(RuntimeError):
            await listener.send_control(LinkReconnectingNotification())
    finally:
        await listener.aclose()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_send_control_to_dead_client_is_loud(
    _connected: tuple[GatewayClientListener, asyncio.StreamReader, asyncio.StreamWriter],
) -> None:
    listener, _reader, writer = _connected
    # Close the client end; the next send must fail loud (re-raised), not silently.
    writer.close()
    await writer.wait_closed()
    # The first write may land in the socket buffer before the RST is seen; loop until
    # the broken pipe surfaces, asserting it is LOUD (re-raised) within a bound.
    with pytest.raises((BrokenPipeError, ConnectionResetError)):
        for _ in range(50):
            await listener.send_control(LinkReconnectingNotification())
            await asyncio.sleep(0.01)


async def test_structlog_only_peer_rejected_is_a_noop_callback() -> None:
    # The 3a reject seam is structlog-only (no audit sink — security M3): it must
    # return cleanly for any uid (including the unknowable ``None``).
    await _structlog_only_peer_rejected(12345)
    await _structlog_only_peer_rejected(None)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.getuid family",
)
async def test_injected_on_peer_rejected_routes_a_mismatch(
    runtime_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An injected ``on_peer_rejected`` (G3-3b wires the metric-incrementing reject
    # handler here) receives the mismatched peer_uid — NOT the structlog stub. Force a
    # uid mismatch by monkeypatching the listener's peer-uid resolver to a foreign uid.
    import os

    import alfred.plugins.comms_socket_transport as transport_mod

    foreign_uid = os.getuid() + 1
    monkeypatch.setattr(transport_mod, "_resolve_peer_uid", lambda _sock: foreign_uid)

    rejected: asyncio.Future[int | None] = asyncio.get_running_loop().create_future()

    async def _capture(peer_uid: int | None) -> None:
        if not rejected.done():
            rejected.set_result(peer_uid)

    listener = GatewayClientListener(on_peer_rejected=_capture)
    await listener.bind()
    accept_task = asyncio.create_task(listener.accept())
    try:
        reader, writer = await asyncio.open_unix_connection(path=str(listener.path))
        observed = await asyncio.wait_for(rejected, timeout=2.0)
        assert observed == foreign_uid
        writer.close()
        await writer.wait_closed()
        del reader
    finally:
        accept_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await accept_task
        await listener.aclose()


async def test_default_on_peer_rejected_is_the_structlog_stub() -> None:
    # The DEFAULT (no injection) still routes to ``_structlog_only_peer_rejected`` —
    # unchanged behaviour for the default caller.
    listener = GatewayClientListener()
    assert listener._listener._on_peer_rejected is _structlog_only_peer_rejected


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_transport_getter_is_none_before_accept_then_set(
    _connected: tuple[GatewayClientListener, asyncio.StreamReader, asyncio.StreamWriter],
) -> None:
    # Before accept, ``.transport`` is None; after accept the getter exposes the
    # accepted CommsSocketTransport (the relay handoff seam for G3-3b).
    unbound = GatewayClientListener()
    assert unbound.transport is None
    listener, _reader, _writer = _connected
    assert listener.transport is not None
    assert listener.transport is listener._transport


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_aclose_is_idempotent(runtime_dir: Path) -> None:
    listener = GatewayClientListener()
    await listener.bind()
    await listener.aclose()
    await listener.aclose()  # second close is a safe no-op


# ---------------------------------------------------------------------------
# Task 2b — machine -> wire round-trip (architect M1)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
async def test_machine_to_wire_emits_section9_sequence(
    _connected: tuple[GatewayClientListener, asyncio.StreamReader, asyncio.StreamWriter],
) -> None:
    """Drive a full gap sequence through the machine; assert the connected client
    observes exactly the §9-correct frame sequence (reconnecting then restored, one
    per gap) — the kernel delivers the invariant machine->wire, not just in the
    pure unit (de-risks the G3-3b wiring).
    """
    listener, reader, _writer = _connected
    machine = LinkStateMachine()
    # A planned drain + redial, then a crash gap that closes via a raw ready (H2:
    # the ready races ahead of redial_started — the gap still closes).
    sequence = [
        GatewayLinkEvent.CORE_GOING_DOWN,  # reconnecting
        GatewayLinkEvent.REDIAL_STARTED,  # nothing
        GatewayLinkEvent.CORE_READY,  # restored
        GatewayLinkEvent.CORE_CRASH_EOF,  # reconnecting
        GatewayLinkEvent.CORE_READY,  # restored
    ]
    expected_methods: list[str] = []
    for event in sequence:
        control = machine.feed(event)
        if control is not None:
            notification = control_notification(control)
            await listener.send_control(notification)
            expected_methods.append(_METHOD_BY_MODEL[type(notification)])
    observed: list[str] = []
    for _ in range(len(expected_methods)):
        line = await asyncio.wait_for(reader.readline(), timeout=2.0)
        observed.append(json.loads(line)["method"])
    assert observed == expected_methods
    # §9: reconnecting/restored alternate, one restored per gap.
    assert observed == [
        LINK_RECONNECTING,
        LINK_RESTORED,
        LINK_RECONNECTING,
        LINK_RESTORED,
    ]
