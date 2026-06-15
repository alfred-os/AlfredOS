"""End-to-end opaque turn through a real :class:`GatewayProcess` (Spec A G3-3b-2b / #237).

This is the DEDICATED full-turn e2e for the runnable front door: a real
:class:`GatewayProcess` standing BETWEEN a real loopback conformant fake-core
(a seq/ack-enabled :class:`CommsSocketListener` HOST keyed ``"tui"`` — the gateway's
default dial target) and a real loopback PLAIN client (the production TUI wire). It
proves the TRANSPORT substance of graduation criterion #7: a real opaque turn relayed
byte-for-byte through the resumable front door, INCLUDING a core gap+reconnect
mid-session under which the client connection is HELD (single-accept-for-life) and the
§9 ``reconnecting -> restored`` control sequence reaches the client.

It deliberately does NOT duplicate ``test_process.py``'s Task-4 coverage (bind/accept/
handshake/shutdown/cancel-reap/peer-reject/control-frame): those pin the lifecycle; this
pins the deeper opaque-turn + held-client-across-reconnect substance.

The real-orchestrator reply (a persona answering the inbound) is 2c/#230 + G5 — this
asserts ONLY the transport relay, never an orchestrator-produced body.

Deterministic: every frame is driven explicitly (no wall-clock sleeps) — bounded
``asyncio.sleep(0)`` yields + ``wait_for`` safety nets, mirroring the merged
``test_relay_wire_contract.py`` / ``test_process.py`` shape.
"""

from __future__ import annotations

import asyncio
import json
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
    LINK_RESTORED,
)
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
    with tempfile.TemporaryDirectory(prefix="alfgw-e2e-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


def _gateway_socket_path() -> Path:
    """The gateway's client-facing socket path under the tmp HOME."""
    return default_comms_socket_path(_GATEWAY_ADAPTER_ID)


async def _dial_gateway_with_retry() -> CommsSocketTransport:
    """Dial the gateway client socket, retrying until ``run()`` has bound it."""
    for _ in range(200):
        try:
            return await dial_comms_socket(_GATEWAY_ADAPTER_ID)
        except (FileNotFoundError, ConnectionRefusedError):
            await asyncio.sleep(0.01)
    raise AssertionError("gateway client socket never became dialable")


async def _client_handshake_host(client: CommsSocketTransport) -> None:
    """Play the PLAIN TUI side of the gateway's client-leg HOST handshake.

    The gateway (HOST) sends ``lifecycle.start`` FIRST; the TUI (this side) reads it
    and answers an ok result with NO ``seq_ack`` echo — the production plain-client
    shape (the gateway's client leg stays plain; the core leg negotiates seq/ack).
    """
    start = await asyncio.wait_for(client.read_frame(), timeout=2.0)
    assert start is not None
    assert start["method"] == "lifecycle.start"
    await client.send(
        {
            "jsonrpc": "2.0",
            "id": start.get("id"),
            "result": {"ok": True, "plugin_version": "alfred-tui/0"},
        }
    )


async def _accept_core_host(listener: CommsSocketListener, *, epoch: str) -> CommsSocketTransport:
    """Accept the gateway's dial and run the core HOST side of the handshake.

    The core (HOST on the gateway's CORE leg) sends ``lifecycle.start`` with the epoch
    + seq/ack advertisement, enables seq/ack, and reads the gateway's seq-framed ack.
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


async def _assert_clean_shutdown(run_task: asyncio.Task[None], shutdown: asyncio.Event) -> None:
    """Assert ``run()`` stops CLEANLY on ``shutdown_event`` — WITHOUT a forced cancel.

    Sets ``shutdown`` and awaits ``run_task`` directly. The clean stop is the property
    under test, so a forced ``cancel()`` must NOT be used to satisfy teardown: a relay
    that never observes ``shutdown_event`` (a real bug) makes ``wait_for`` raise
    ``TimeoutError`` here — the test FAILS loudly instead of a cancel papering over it.
    Mutation-sound: making ``GatewayProcess.run``'s shutdown-observation a no-op makes
    this assertion fail (the ``run_task`` never returns within the timeout).

    The caller's ``finally`` keeps a last-resort ``cancel()`` for the case where THIS
    assertion already raised — that cancel reaps a now-known-broken task, it never
    substitutes for the clean stop the assertion proves.
    """
    shutdown.set()
    with structlog.testing.capture_logs():
        # No try/except-cancel: a TimeoutError here is a genuine FAILURE (run() ignored
        # shutdown_event), not something to mask. asyncio.wait_for raises CancelledError
        # only if the awaiting test itself is cancelled, which is also a real failure.
        await asyncio.wait_for(run_task, timeout=3.0)
    assert run_task.done()
    assert not run_task.cancelled()  # it RETURNED on shutdown — was not force-cancelled.


# ---------------------------------------------------------------------------
# A full opaque turn through the process — byte-for-byte, inner id preserved.
# ---------------------------------------------------------------------------


async def test_opaque_turn_both_directions_byte_for_byte_through_process(
    runtime_dir: Path,
) -> None:
    """A client opaque payload arrives at the fake-core byte-for-byte (inner ``id``
    preserved), and a core opaque response arrives at the client byte-for-byte.

    The client sends a non-lifecycle JSON-RPC request (``inbound.message``); the core
    answers with the matching JSON-RPC response (``result`` carrying the same ``id``).
    Both relayed bodies are asserted EXACT — the gateway is a payload-blind T1 carrier
    that re-frames per leg but never mutates the body.
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
            # client -> core: a non-lifecycle opaque request frame.
            up_body = (
                b'{"jsonrpc":"2.0","id":99,"method":"inbound.message","params":{"text":"hello"}}'
            )
            await client.send_payload_unit(up_body, ack=0)
            got_up = await asyncio.wait_for(core_host.read_payload_unit(), timeout=2.0)
            assert got_up is not None
            assert got_up.payload == up_body  # byte-for-byte at the core
            assert b'"id":99' in got_up.payload  # inner id survived the deframe/reframe

            # core -> client: the matching opaque response frame (same inner id).
            down_body = b'{"jsonrpc":"2.0","id":99,"result":{"ack":true}}'
            await core_host.send_payload_unit(down_body, ack=0)
            got_down = await asyncio.wait_for(client.read_payload_unit(), timeout=2.0)
            assert got_down is not None
            assert got_down.payload == down_body  # byte-for-byte at the client
            assert b'"id":99' in got_down.payload

            # Clean stop FIRST (shutdown is a quiet return, never a gap — no control
            # frame is pushed to the client), THEN reap the loopback ends. Reaping the
            # ends before the clean stop would EOF the core leg and race a gap-feed onto
            # a closing client transport. The assertion below is mutation-sound: it FAILS
            # (TimeoutError) if run() ignores shutdown_event — no forced cancel masks it.
            await _assert_clean_shutdown(run_task, shutdown)
        finally:
            await core_host.close()
            await client.close()
    finally:
        if not run_task.done():
            run_task.cancel()
        await core_listener.aclose()

    assert not _gateway_socket_path().exists()


# ---------------------------------------------------------------------------
# Core gap + reconnect mid-session: held client + §9 control sequence + post-gap turn.
# ---------------------------------------------------------------------------


async def test_core_gap_reconnect_holds_client_and_relays_after_restore(
    runtime_dir: Path,
) -> None:
    """A core EOF mid-session is bridged WITHOUT dropping the client.

    The fake-core sends a ``going_down`` then EOFs; the gateway reconnects to a FRESH
    fake-core HOST that re-binds the core socket (a NEW epoch -> a real ``restored``).
    The SAME client transport keeps working across the whole gap (single-accept-for-life):

    * the client wire sees EXACTLY the §9 sequence ``reconnecting`` then ``restored``;
    * a post-reconnect client->core turn STILL relays byte-for-byte — proving the held
      client survived the gap and the relay rebound the fresh core leg.
    """
    epoch1 = uuid4().hex
    shutdown = asyncio.Event()
    core_listener1 = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
    await core_listener1.bind()
    core_host_task = asyncio.create_task(_accept_core_host(core_listener1, epoch=epoch1))

    process = GatewayProcess(shutdown_event=shutdown)
    run_task = asyncio.ensure_future(process.run())
    try:
        client = await _dial_gateway_with_retry()
        await _client_handshake_host(client)
        core_host1 = await asyncio.wait_for(core_host_task, timeout=3.0)

        # A pre-gap turn relays fine over the first core leg.
        pre_body = b'{"jsonrpc":"2.0","id":1,"method":"inbound.message","params":{}}'
        await core_host1.send_payload_unit(pre_body, ack=0)
        got_pre = await asyncio.wait_for(client.read_payload_unit(), timeout=2.0)
        assert got_pre is not None and got_pre.payload == pre_body

        # The gap: a going_down then EOF on the first core leg.
        going_down = json.dumps(
            {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": LIFECYCLE_REASON_SHUTDOWN}}
        ).encode()
        await core_host1.send_payload_unit(going_down, ack=0)
        # Free the original socket inode (HOST transport + listener) BEFORE the fresh
        # listener rebinds the same adapter id — the merged #273 reconnect fix: close the
        # first core listener so the redial does not collide on the socket path.
        await core_host1.close()
        await core_listener1.aclose()

        # §9 step 1: ``reconnecting`` reaches the held client over the SAME connection.
        reconnecting = await asyncio.wait_for(client.read_frame(), timeout=3.0)
        assert reconnecting is not None
        assert reconnecting["method"] == LINK_RECONNECTING

        # The gateway is now redialing; bind the FRESH core HOST + accept the redial.
        epoch2 = uuid4().hex
        assert epoch2 != epoch1
        core_listener2 = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
        await core_listener2.bind()
        core_host2 = await asyncio.wait_for(
            _accept_core_host(core_listener2, epoch=epoch2), timeout=3.0
        )
        try:
            # §9 step 2: ``restored`` reaches the held client (a real new-epoch all-clear).
            restored = await asyncio.wait_for(client.read_frame(), timeout=3.0)
            assert restored is not None
            assert restored["method"] == LINK_RESTORED

            # The held client survived the gap: a fresh client->core turn still relays.
            post_body = b'{"jsonrpc":"2.0","id":2,"method":"inbound.message","params":{}}'
            await client.send_payload_unit(post_body, ack=0)
            got_post = await asyncio.wait_for(core_host2.read_payload_unit(), timeout=2.0)
            assert got_post is not None
            assert got_post.payload == post_body  # byte-for-byte over the fresh core leg

            # Clean stop FIRST (a quiet return over the live second core leg), THEN reap
            # the ends — so the shutdown does not race a gap-feed onto a closing client.
            # Mutation-sound: a relay ignoring shutdown_event makes this FAIL, not pass.
            await _assert_clean_shutdown(run_task, shutdown)
        finally:
            await core_host2.close()
            await core_listener2.aclose()
            await client.close()
    finally:
        if not run_task.done():
            run_task.cancel()

    assert not _gateway_socket_path().exists()
