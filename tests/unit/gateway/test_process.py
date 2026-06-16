"""Non-root, in-process tests for :class:`GatewayProcess` (Spec A G3-3b-2b / ADR-0031).

``GatewayProcess`` is the runnable front door: it binds the client-facing socket
(fail-closed), accepts ONE client racing shutdown, runs the client-leg HOST handshake,
builds the merged :class:`GatewayCoreLink` + :class:`GatewayRelay`, supervises
``relay.run()``, and REAPS the listener (its accepted transport + the socket file) on
EVERY exit path — including a cancel/exception unwind.

These tests mirror the 2a ``test_relay_wire_contract`` harness shape: a REAL core HOST
listener keyed ``"tui"`` (the gateway's default dial target), a REAL loopback client
dialing the gateway's ``"gateway"`` client socket, and a REAL listener/core-link/relay
stack. No root, no bwrap, no daemon — just unix sockets under a tmp ``$HOME``.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
import structlog.testing

from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    LIFECYCLE_REASON_SHUTDOWN,
    LINK_RECONNECTING,
)
from alfred.gateway import client_listener as client_listener_mod
from alfred.gateway.client_link import GatewayHandshakeError
from alfred.gateway.metrics import PEER_AUTH_REJECTED
from alfred.gateway.process import GatewayProcess
from alfred.plugins.comms_seq_codec import SEQ_VERSION
from alfred.plugins.comms_socket_transport import (
    CommsSocketListener,
    CommsSocketTransport,
    default_comms_socket_path,
    dial_comms_socket,
)

_CORE_ADAPTER_ID = "tui"
_GATEWAY_ADAPTER_ID = "gateway"


@pytest.fixture
def runtime_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the socket runtime dir at a SHORT tmp HOME so tests never touch ~/.run."""
    with tempfile.TemporaryDirectory(prefix="alfgw-proc-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


def _gateway_socket_path() -> Path:
    """The gateway's client-facing socket path under the tmp HOME."""
    return default_comms_socket_path(_GATEWAY_ADAPTER_ID)


async def _client_handshake_host(client: CommsSocketTransport, *, ok: bool = True) -> None:
    """Play the TUI side of the gateway's client-leg HOST handshake.

    The gateway (HOST) sends ``lifecycle.start`` FIRST; the TUI (this side) reads it and
    answers the result. ``ok=False`` answers a not-ok result so the gateway's
    ``client_handshake`` fails closed (``GatewayHandshakeError``).
    """
    start = await asyncio.wait_for(client.read_frame(), timeout=2.0)
    assert start is not None
    assert start["method"] == "lifecycle.start"
    result: dict[str, object] = (
        {"ok": True, "plugin_version": "alfred-tui/0"}
        if ok
        else {"ok": False, "plugin_version": "alfred-tui/0"}
    )
    # The real TUI is a PLAIN ADR-0025 peer (seq_ack=None) — no seq/ack echo, so the
    # gateway's client leg stays plain. This is the production shape.
    await client.send({"jsonrpc": "2.0", "id": start.get("id"), "result": result})


async def _accept_core_host(listener: CommsSocketListener, *, epoch: str) -> CommsSocketTransport:
    """Accept the gateway's dial and run the core HOST side of the handshake.

    The core (HOST on the gateway's CORE leg) sends ``lifecycle.start`` with the epoch +
    seq/ack advertisement, enables seq/ack, and reads the gateway's seq-framed ack.
    """
    transport = await listener.accept()
    await transport.send(
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "lifecycle.start",
            "params": {
                "adapter_id": _CORE_ADAPTER_ID,
                "epoch": epoch,
                "seq_ack": {"version": SEQ_VERSION},
            },
        }
    )
    transport.enable_seq_ack()
    ack = await transport.read_frame()
    assert ack is not None
    assert ack["result"]["ok"] is True  # type: ignore[index]
    return transport


# ---------------------------------------------------------------------------
# Happy path — bind, accept, handshake, relay a real turn end-to-end.
# ---------------------------------------------------------------------------


async def test_run_binds_accepts_handshakes_and_relays(runtime_dir: Path) -> None:
    """``run()`` binds the client socket, accepts a loopback client, runs the client
    handshake, then relays a real turn byte-for-byte in BOTH directions through the core.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()

    # The core HOST: bound BEFORE the process so the gateway's default dial finds it.
    core_listener = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
    await core_listener.bind()
    core_host_task = asyncio.create_task(_accept_core_host(core_listener, epoch=epoch))

    process = GatewayProcess(shutdown_event=shutdown)
    run_task = asyncio.ensure_future(process.run())

    try:
        # The client dials the gateway's client socket; once bound by run() the dial
        # connects. Retry the dial until the listener has bound (the process binds inside
        # run(), so a too-early dial would FileNotFound).
        client = await _dial_gateway_with_retry()
        await _client_handshake_host(client)
        core_host = await asyncio.wait_for(core_host_task, timeout=3.0)
        try:
            # core -> client (seq-framed on the core leg, plain on the client leg).
            down = b'{"jsonrpc":"2.0","id":11,"method":"inbound.message","params":{}}'
            await core_host.send_payload_unit(down, seq=0, ack=0)
            got_down = await asyncio.wait_for(client.read_payload_unit(), timeout=2.0)
            assert got_down is not None
            assert got_down.payload == down

            # client -> core (plain client leg, opaque-forwarded to the seq core leg).
            up = b'{"jsonrpc":"2.0","id":22,"method":"chat.send","params":{}}'
            await client.send_payload_unit(up, seq=0, ack=0)
            got_up = await asyncio.wait_for(core_host.read_payload_unit(), timeout=2.0)
            assert got_up is not None
            assert got_up.payload == up

            # Clean stop FIRST (shutdown is a clean stop, never a gap — no control frame
            # is pushed to the client), THEN reap the loopback ends.
            shutdown.set()
            with structlog.testing.capture_logs():
                await asyncio.wait_for(run_task, timeout=3.0)
        finally:
            await core_host.close()
            await client.close()
    finally:
        if not run_task.done():
            run_task.cancel()
        await core_listener.aclose()

    # The listener reaped its socket file on the clean shutdown exit.
    assert not _gateway_socket_path().exists()


async def _dial_gateway_with_retry() -> CommsSocketTransport:
    """Dial the gateway client socket, retrying until ``run()`` has bound it."""
    for _ in range(200):
        try:
            return await dial_comms_socket(_GATEWAY_ADAPTER_ID)
        except (FileNotFoundError, ConnectionRefusedError):
            await asyncio.sleep(0.01)
    raise AssertionError("gateway client socket never became dialable")


# ---------------------------------------------------------------------------
# Shutdown before a client connects — clean return, no core dial, socket unlinked.
# ---------------------------------------------------------------------------


async def test_shutdown_before_client_connects_returns_clean(runtime_dir: Path) -> None:
    """A shutdown set BEFORE any client connects ends ``run()`` cleanly: no core dial,
    and the listener socket file is unlinked.
    """
    shutdown = asyncio.Event()
    dialed = False

    async def _core_dial() -> object:
        nonlocal dialed
        dialed = True
        raise AssertionError("core must never be dialed when shutdown wins the accept race")

    process = GatewayProcess(shutdown_event=shutdown, core_dial=_core_dial)
    run_task = asyncio.ensure_future(process.run())
    # Let run() reach its accept race, then fire shutdown.
    for _ in range(50):
        if _gateway_socket_path().exists():
            break
        await asyncio.sleep(0)
    shutdown.set()
    await asyncio.wait_for(run_task, timeout=3.0)

    assert dialed is False
    assert not _gateway_socket_path().exists()


# ---------------------------------------------------------------------------
# Shutdown mid-relay — prompt return, socket unlinked, no leak.
# ---------------------------------------------------------------------------


async def test_shutdown_mid_relay_returns_and_reaps(runtime_dir: Path) -> None:
    """A shutdown set DURING the relay ends ``run()`` promptly; the socket is unlinked."""
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    core_listener = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
    await core_listener.bind()
    core_host_task = asyncio.create_task(_accept_core_host(core_listener, epoch=epoch))

    process = GatewayProcess(shutdown_event=shutdown)
    run_task = asyncio.ensure_future(process.run())
    try:
        client = await _dial_gateway_with_retry()
        await _client_handshake_host(client)
        core_host = await asyncio.wait_for(core_host_task, timeout=3.0)
        try:
            # A turn flows, proving the relay is live mid-stream.
            body = b'{"jsonrpc":"2.0","id":1,"method":"inbound.message","params":{}}'
            await core_host.send_payload_unit(body, seq=0, ack=0)
            got = await asyncio.wait_for(client.read_payload_unit(), timeout=2.0)
            assert got is not None and got.payload == body

            shutdown.set()
            with structlog.testing.capture_logs():
                await asyncio.wait_for(run_task, timeout=3.0)
            assert run_task.done()
        finally:
            await core_host.close()
            await client.close()
    finally:
        if not run_task.done():
            run_task.cancel()
        await core_listener.aclose()

    assert not _gateway_socket_path().exists()


# ---------------------------------------------------------------------------
# Cancel mid-relay — the finally-reap STILL runs (security-M2 cancel unwind).
# ---------------------------------------------------------------------------


async def test_cancel_mid_relay_still_reaps_listener(runtime_dir: Path) -> None:
    """A CANCEL of ``run()`` mid-relay still runs the ``finally: listener.aclose()`` —
    the socket file is unlinked even on a cancel unwind (the security-M2 reap).
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    core_listener = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
    await core_listener.bind()
    core_host_task = asyncio.create_task(_accept_core_host(core_listener, epoch=epoch))

    process = GatewayProcess(shutdown_event=shutdown)
    run_task = asyncio.ensure_future(process.run())
    try:
        client = await _dial_gateway_with_retry()
        await _client_handshake_host(client)
        core_host = await asyncio.wait_for(core_host_task, timeout=3.0)
        try:
            body = b'{"jsonrpc":"2.0","id":1,"method":"inbound.message","params":{}}'
            await core_host.send_payload_unit(body, seq=0, ack=0)
            got = await asyncio.wait_for(client.read_payload_unit(), timeout=2.0)
            assert got is not None and got.payload == body

            # Cancel run() mid-relay; the finally must still unlink the socket.
            run_task.cancel()
            with (
                structlog.testing.capture_logs(),
                pytest.raises(asyncio.CancelledError),
            ):
                await asyncio.wait_for(run_task, timeout=3.0)
        finally:
            await core_host.close()
            await client.close()
    finally:
        if not run_task.done():
            run_task.cancel()
        await core_listener.aclose()

    assert not _gateway_socket_path().exists()


# ---------------------------------------------------------------------------
# Client-handshake failure — fail-closed raise, listener still reaped.
# ---------------------------------------------------------------------------


async def test_client_handshake_failure_raises_and_reaps(runtime_dir: Path) -> None:
    """A not-ok client handshake raises ``GatewayHandshakeError`` (fail-closed) and the
    listener is STILL reaped — the socket file is unlinked even on the raise.
    """
    shutdown = asyncio.Event()

    async def _core_dial() -> object:
        raise AssertionError("core must never be dialed when the client handshake fails")

    process = GatewayProcess(shutdown_event=shutdown, core_dial=_core_dial)
    run_task = asyncio.ensure_future(process.run())
    try:
        client = await _dial_gateway_with_retry()
        # Answer the handshake NOT-ok so client_handshake fails closed.
        await _client_handshake_host(client, ok=False)
        with (
            structlog.testing.capture_logs(),
            pytest.raises(GatewayHandshakeError),
        ):
            await asyncio.wait_for(run_task, timeout=3.0)
        await client.close()
    finally:
        if not run_task.done():
            run_task.cancel()

    assert not _gateway_socket_path().exists()


# ---------------------------------------------------------------------------
# Bind OSError — fail-closed refuse (loud raise), no half-wired relay.
# ---------------------------------------------------------------------------


async def test_bind_oserror_refuses_loud(runtime_dir: Path) -> None:
    """A listener bind failure (an ``OSError`` from ``bind()``) propagates loud: the
    process REFUSES rather than running a half-wired relay (fail-closed, hard rule #7).
    """
    shutdown = asyncio.Event()

    async def _boom_bind() -> None:
        raise OSError("bind refused")

    def _exploding_listener(
        *, on_peer_rejected: object = None
    ) -> client_listener_mod.GatewayClientListener:
        listener = client_listener_mod.GatewayClientListener(
            on_peer_rejected=on_peer_rejected  # type: ignore[arg-type]
        )
        listener.bind = _boom_bind  # type: ignore[method-assign]
        return listener

    import alfred.gateway.process as process_mod

    process = GatewayProcess(shutdown_event=shutdown)
    with (
        structlog.testing.capture_logs(),
        pytest.MonkeyPatch.context() as mp,
        pytest.raises(OSError, match="bind refused"),
    ):
        mp.setattr(process_mod, "GatewayClientListener", _exploding_listener)
        await process.run()


# ---------------------------------------------------------------------------
# accept() RAISES while shutdown is also set — the genuine accept error is
# re-raised (not swallowed, not the stale transport). FIX 5.
# ---------------------------------------------------------------------------


async def test_accept_error_with_shutdown_set_propagates(runtime_dir: Path) -> None:
    """An ``accept()`` that RAISES while ``shutdown_event`` is also set propagates the
    accept error — it is NOT swallowed into a clean stop and is NOT the stale transport.

    Guards :meth:`GatewayProcess._accept_racing_shutdown`'s same-tick both-done branch,
    where ``accept_task.result()`` re-raises a genuine accept error. This test FAILS if
    line ~162's ``accept_task.result()`` were dropped (the error would be swallowed and
    the stale ``listener.transport`` returned instead — a silent failure).

    A fake listener whose ``accept()`` raises ``OSError`` immediately is driven with the
    shutdown event ALREADY set, so both children of the race resolve on the same tick.
    """

    class _ExplodingAcceptListener:
        """A minimal stand-in: ``accept()`` raises; ``bind``/``aclose`` are no-ops."""

        def __init__(self) -> None:
            self.transport = object()  # the STALE transport the bug would return
            self.aclosed = False

        async def bind(self) -> None:
            return None

        async def accept(self) -> object:
            raise OSError("accept refused under shutdown")

        async def aclose(self) -> None:
            self.aclosed = True

    shutdown = asyncio.Event()
    shutdown.set()  # shutdown already won — forces the same-tick both-done path.
    process = GatewayProcess(shutdown_event=shutdown)
    listener = _ExplodingAcceptListener()

    with pytest.raises(OSError, match="accept refused under shutdown"):
        await process._accept_racing_shutdown(listener)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Mismatched-uid client — PEER_AUTH_REJECTED increments + the loud row fires.
# ---------------------------------------------------------------------------


async def test_mismatched_uid_client_increments_metric_and_logs(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mismatched-uid client (forced via ``_resolve_peer_uid``) increments
    ``PEER_AUTH_REJECTED`` and fires the loud reject row; the listener keeps waiting, so
    the test pairs the reject with a shutdown to end ``run()`` cleanly.
    """
    import alfred.plugins.comms_socket_transport as transport_mod

    # Force the ACCEPTED peer uid to a value that never matches os.getuid(). The client
    # connects RAW (asyncio.open_unix_connection — NOT dial_comms_socket, which would run
    # the dial-side peer-auth check and reject before the gateway's accept side sees it).
    foreign_uid = os.getuid() + 1
    monkeypatch.setattr(transport_mod, "_resolve_peer_uid", lambda _sock: foreign_uid)

    before = PEER_AUTH_REJECTED._value.get()
    shutdown = asyncio.Event()
    process = GatewayProcess(shutdown_event=shutdown)
    run_task = asyncio.ensure_future(process.run())
    try:
        # Wait for run() to bind the socket, then dial it raw; the gateway listener
        # rejects the mismatched-uid peer + closes it, firing the reject callback.
        for _ in range(200):
            if _gateway_socket_path().exists():
                break
            await asyncio.sleep(0.01)
        with structlog.testing.capture_logs() as captured:
            reader, writer = await asyncio.open_unix_connection(path=str(_gateway_socket_path()))
            # Give the reject callback time to fire (the listener closes the connection).
            for _ in range(50):
                await asyncio.sleep(0)
            writer.close()
            del reader
        rejected = [c for c in captured if c.get("event") == "gateway.process.peer_uid_rejected"]
        assert len(rejected) == 1
        assert PEER_AUTH_REJECTED._value.get() == before + 1
    finally:
        shutdown.set()
        with structlog.testing.capture_logs():
            try:
                await asyncio.wait_for(run_task, timeout=3.0)
            except (TimeoutError, asyncio.CancelledError):
                run_task.cancel()

    assert not _gateway_socket_path().exists()


# ---------------------------------------------------------------------------
# A consumed lifecycle frame still reaches the client control channel through run().
# ---------------------------------------------------------------------------


async def test_run_relays_control_frame_on_core_going_down(runtime_dir: Path) -> None:
    """A ``daemon.lifecycle.going_down`` on the core leg drives a ``reconnecting`` control
    frame down to the client through the supervised relay — proving the full stack wires.
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()
    core_listener = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
    await core_listener.bind()
    core_host_task = asyncio.create_task(_accept_core_host(core_listener, epoch=epoch))

    process = GatewayProcess(shutdown_event=shutdown)
    run_task = asyncio.ensure_future(process.run())
    try:
        client = await _dial_gateway_with_retry()
        await _client_handshake_host(client)
        core_host = await asyncio.wait_for(core_host_task, timeout=3.0)
        try:
            going_down = json.dumps(
                {
                    "method": DAEMON_LIFECYCLE_GOING_DOWN,
                    "params": {"reason": LIFECYCLE_REASON_SHUTDOWN},
                }
            ).encode()
            await core_host.send_payload_unit(going_down, seq=0, ack=0)
            # Close the core HOST so the gateway gaps; the §9 invariant emits reconnecting.
            await core_host.close()
            await core_listener.aclose()
            reconnecting = await asyncio.wait_for(client.read_frame(), timeout=3.0)
            assert reconnecting is not None
            assert reconnecting["method"] == LINK_RECONNECTING
        finally:
            await client.close()
    finally:
        shutdown.set()
        with structlog.testing.capture_logs():
            try:
                await asyncio.wait_for(run_task, timeout=3.0)
            except (TimeoutError, asyncio.CancelledError):
                run_task.cancel()

    assert not _gateway_socket_path().exists()
