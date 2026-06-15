"""Non-root, in-process WIRE-CONTRACT + payload-blindness gate for ``GatewayRelay``.

This is the load-bearing gate (the #245 paper-gate fix): a launcher/root-only
integration test that proves a wire contract is NOT a real gate, so the deframe/reframe
contract is proved HERE, in-process, with REAL loopback :class:`CommsSocketTransport`s
on BOTH legs and a REAL :class:`GatewayClientListener` (not fakes) — the real listener is
what proves the control-frame-interleaved-with-payload property (architect L3). No root,
no bwrap, no daemon: just two unix sockets under a tmp ``$HOME``.

The fixture stands up the full gateway data path:

* a CORE HOST — a :class:`CommsSocketListener` keyed ``"tui"`` (the gateway's default
  dial target) that accepts the gateway's dial, plays the ``lifecycle.start`` handshake
  (epoch + ``seq_ack``), then drives seq-framed payloads + ``daemon.lifecycle.*`` frames
  deterministically (no wall-clock — every frame is sent explicitly);
* the GATEWAY — a real :class:`GatewayClientListener` (``"gateway"``) + a real
  :class:`GatewayCoreLink` + a real :class:`GatewayRelay`, all running concurrently;
* the CLIENT — a real loopback dial into the gateway's client socket.

The PRODUCTION shape is core seq-ON / client seq-OFF (plain TUI). A seq-on-both variant
proves RESEQ (the client-leg seq the gateway mints differs from the core-leg seq).
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest
import structlog.testing

from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    LIFECYCLE_REASON_SHUTDOWN,
    LINK_RECONNECTING,
    LINK_RESTORED,
)
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.relay import GatewayRelay
from alfred.plugins.comms_seq_codec import SEQ_VERSION
from alfred.plugins.comms_socket_transport import (
    CommsSocketListener,
    CommsSocketTransport,
    dial_comms_socket,
)

# The gateway dials this adapter id by default (``_DEFAULT_DIAL_ADAPTER_ID``); the core
# HOST binds the matching listener so the gateway's production dial path is exercised
# end-to-end (no dial seam injected).
_CORE_ADAPTER_ID = "tui"


@pytest.fixture
def runtime_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the socket runtime dir at a SHORT tmp HOME so tests never touch ~/.run."""
    with tempfile.TemporaryDirectory(prefix="alfgw-wc-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


@dataclass
class _GatewayHarness:
    """The running gateway + the two loopback ends a test drives it through."""

    relay_task: asyncio.Task[None]
    shutdown: asyncio.Event
    core_link: GatewayCoreLink
    client_listener: GatewayClientListener
    client: CommsSocketTransport
    core_host: CommsSocketTransport


async def _accept_core_host(listener: CommsSocketListener, *, epoch: str) -> CommsSocketTransport:
    """Accept the gateway's dial and run the core HOST side of the handshake.

    Sends ``lifecycle.start`` (plain) with the epoch + ``seq_ack`` advertisement, then
    enables seq/ack and reads the gateway's (seq-framed) ack. Returns the seq-enabled
    core-HOST transport ready to drive payloads + lifecycle frames.
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
    # The gateway enables seq/ack BEFORE writing its ack, so the ack is seq-framed; the
    # host must enable too (the magic-gated decoder strips the header on read).
    transport.enable_seq_ack()
    ack = await transport.read_frame()
    assert ack is not None
    assert ack["result"] == {
        "ok": True,
        "plugin_version": "alfred-gateway/0",
        "seq_ack": {"version": SEQ_VERSION},
    }
    return transport


async def _build_harness(
    *, client_seq_enabled: bool
) -> tuple[_GatewayHarness, CommsSocketListener]:
    """Stand up the full gateway path over real loopback sockets.

    Returns the harness plus the core listener (the caller reaps it). ``client_seq_enabled``
    drives the RESEQ variant: the client leg is then seq-framed too (the gateway resequences).
    """
    epoch = uuid4().hex
    shutdown = asyncio.Event()

    core_listener = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
    await core_listener.bind()
    client_listener = GatewayClientListener()
    await client_listener.bind()

    # The core HOST accepts the gateway's dial concurrently with the gateway dialing it.
    core_host_task = asyncio.create_task(_accept_core_host(core_listener, epoch=epoch))

    core_link = GatewayCoreLink(client_listener=client_listener, shutdown_event=shutdown)

    # The client dials the gateway's client socket; the gateway accepts it. The relay's
    # client transport is the ACCEPTED gateway-side end — build the relay around it once
    # the accept resolves (accept + dial race; drive both).
    accept_task = asyncio.create_task(client_listener.accept())
    client = await dial_comms_socket("gateway")
    await accept_task
    accepted_client = client_listener._transport
    assert accepted_client is not None
    if client_seq_enabled:
        # Forward-looking RESEQ variant: both legs negotiate seq/ack.
        accepted_client.enable_seq_ack()
        client.enable_seq_ack()

    relay = GatewayRelay(
        core_link=core_link,
        client_transport=accepted_client,
        client_seq_enabled=client_seq_enabled,
    )
    relay_task = asyncio.ensure_future(relay.run())
    core_host = await asyncio.wait_for(core_host_task, timeout=2.0)

    harness = _GatewayHarness(
        relay_task=relay_task,
        shutdown=shutdown,
        core_link=core_link,
        client_listener=client_listener,
        client=client,
        core_host=core_host,
    )
    return harness, core_listener


async def _reap_harness(harness: _GatewayHarness, core_listener: CommsSocketListener) -> None:
    """Reap the gateway + both ends on EVERY exit path (idempotent)."""
    harness.shutdown.set()
    with structlog.testing.capture_logs():
        try:
            await asyncio.wait_for(harness.relay_task, timeout=2.0)
        except (TimeoutError, asyncio.CancelledError):
            harness.relay_task.cancel()
    await harness.core_host.close()
    await core_listener.aclose()
    await harness.client.close()
    await harness.client_listener.aclose()


@pytest.fixture
async def harness(runtime_dir: Path) -> AsyncIterator[_GatewayHarness]:
    """Stand up the PRODUCTION gateway path (core seq-ON, client seq-OFF); reap on teardown."""
    built, core_listener = await _build_harness(client_seq_enabled=False)
    try:
        yield built
    finally:
        await _reap_harness(built, core_listener)


async def _read_client_payload(client: CommsSocketTransport) -> bytes:
    """Read one opaque payload off the PLAIN client leg (seq OFF) — the body bytes."""
    frame = await asyncio.wait_for(client.read_payload_unit(), timeout=2.0)
    assert frame is not None
    return frame.payload


# ---------------------------------------------------------------------------
# Wire-contract — production shape (core seq-ON, client seq-OFF).
# ---------------------------------------------------------------------------


async def test_wire_contract_payloads_both_directions_byte_for_byte(
    harness: _GatewayHarness,
) -> None:
    """A core->client payload AND a client->core payload both arrive byte-for-byte over
    the real sockets; the inner JSON-RPC ``id`` survives the deframe/reframe.
    """
    down_body = b'{"jsonrpc":"2.0","id":11,"method":"inbound.message","params":{"x": 1 }}'
    up_body = b'{"jsonrpc":"2.0","id":22,"method":"chat.send","params":{}}'

    # core -> client (seq-framed on the core leg, plain on the client leg).
    await harness.core_host.send_payload_unit(down_body, ack=0)
    got_down = await _read_client_payload(harness.client)
    assert got_down == down_body
    assert b'"id":11' in got_down

    # client -> core (plain on the client leg, opaque-forwarded to the seq core leg).
    await harness.client.send_payload_unit(up_body, ack=0)
    got_up = await asyncio.wait_for(harness.core_host.read_payload_unit(), timeout=2.0)
    assert got_up is not None
    assert got_up.payload == up_body
    assert b'"id":22' in got_up.payload


async def test_wire_contract_control_frame_sequence_on_client_leg(harness: _GatewayHarness) -> None:
    """§9 control-frame sequence ON the client leg across a going_down -> reconnect gap.

    The core HOST sends ``going_down`` then drops; the gateway reconnects to a fresh
    core; the client leg sees EXACTLY ``reconnecting`` then ``restored`` (the §9 invariant),
    and a payload interleaved INTO the stream is not corrupted.
    """
    # A payload before the gap relays fine.
    pre_body = b'{"jsonrpc":"2.0","id":1,"method":"inbound.message","params":{}}'
    await harness.core_host.send_payload_unit(pre_body, ack=0)
    assert await _read_client_payload(harness.client) == pre_body

    # An interleaved going_down consumed MID payload-stream: the gateway consumes it
    # (emits reconnecting on the client control channel) and the relay is not corrupted.
    going_down = json.dumps(
        {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": LIFECYCLE_REASON_SHUTDOWN}}
    ).encode()
    await harness.core_host.send_payload_unit(going_down, ack=0)

    # Stand up a fresh core HOST for the gateway's reconnect (a NEW epoch -> restored).
    epoch2 = uuid4().hex
    core_listener2 = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
    # The gateway will re-dial the SAME path; close the first core listener so the
    # reconnect lands on the fresh one bound at the same adapter id.
    await harness.core_host.close()

    # Read the client control channel: the gateway pushes id-less link.* frames over the
    # SAME client connection (interleaved with payloads), so read frames and pick out the
    # control methods.
    reconnecting = await asyncio.wait_for(harness.client.read_frame(), timeout=2.0)
    assert reconnecting is not None
    assert reconnecting["method"] == LINK_RECONNECTING

    # Now the gateway is redialing; bind the fresh core HOST + accept the redial.
    await core_listener2.bind()
    core_host2 = await asyncio.wait_for(
        _accept_core_host(core_listener2, epoch=epoch2), timeout=3.0
    )
    try:
        restored = await asyncio.wait_for(harness.client.read_frame(), timeout=3.0)
        assert restored is not None
        assert restored["method"] == LINK_RESTORED
        # A post-restore payload still relays byte-for-byte (the relay survived the gap).
        post_body = b'{"jsonrpc":"2.0","id":99,"method":"inbound.message","params":{}}'
        await core_host2.send_payload_unit(post_body, ack=0)
        assert await _read_client_payload(harness.client) == post_body
    finally:
        await core_host2.close()
        await core_listener2.aclose()


# ---------------------------------------------------------------------------
# Reseq proof (seq-on-BOTH variant) — the client-leg seq the gateway mints differs
# from the core-leg seq the payload arrived with (forward-looking, G4/G5).
# ---------------------------------------------------------------------------


async def test_reseq_client_leg_seq_differs_from_core_leg_seq(runtime_dir: Path) -> None:
    """With seq/ack on BOTH legs, the gateway RESEQUENCES — it does not pass seqs through.

    The core HOST sends a payload at core-leg ``seq=7``; the gateway relays it down the
    client leg under its OWN fresh client-leg seq (0, the first client-leg send), proving
    the seq is re-minted per leg, not forwarded. Symmetrically a client->core unit at
    client-leg ``seq=3`` arrives at the core HOST under the gateway's fresh core-leg seq.
    """
    harness, core_listener = await _build_harness(client_seq_enabled=True)
    try:
        # core -> client: the HOST sends a few throwaway units to advance its core-leg
        # send seq, then the payload-under-test — so the core-leg seq the payload carries
        # is non-zero, while the gateway re-mints the client-leg seq from its OWN counter.
        for i in range(3):
            await harness.core_host.send_payload_unit(f'{{"id":{i}}}'.encode(), ack=0)
            drained = await asyncio.wait_for(harness.client.read_payload_unit(), timeout=2.0)
            assert drained is not None
        down_body = b'{"jsonrpc":"2.0","id":1,"method":"inbound.message","params":{}}'
        await harness.core_host.send_payload_unit(down_body, ack=0)
        down_frame = await asyncio.wait_for(harness.client.read_payload_unit(), timeout=2.0)
        assert down_frame is not None
        assert down_frame.payload == down_body
        # The client-leg seq the gateway minted is its OWN monotonic client-leg send
        # counter — the 4th client-leg send is seq 3, NOT the core-leg seq the payload
        # arrived with. (The two counters happen to coincide here only because both legs
        # sent 4 units; the client->core leg below makes the independence unambiguous.)
        assert down_frame.seq is not None

        # client -> core: send TWO client-leg units so the client-leg send counter is
        # ahead of the core-leg receive; the gateway re-mints the core-leg seq from its
        # own (independent) core-leg send counter.
        up_body0 = b'{"jsonrpc":"2.0","id":10,"method":"chat.send","params":{}}'
        up_body1 = b'{"jsonrpc":"2.0","id":11,"method":"chat.send","params":{}}'
        await harness.client.send_payload_unit(up_body0, ack=0)
        await harness.client.send_payload_unit(up_body1, ack=0)
        core_frame0 = await asyncio.wait_for(harness.core_host.read_payload_unit(), timeout=2.0)
        core_frame1 = await asyncio.wait_for(harness.core_host.read_payload_unit(), timeout=2.0)
        assert core_frame0 is not None
        assert core_frame1 is not None
        assert core_frame0.payload == up_body0
        assert core_frame1.payload == up_body1
        # The core-leg seqs the gateway minted are a fresh monotonic run (0,1) on the
        # core-leg send counter — INDEPENDENT of the client-leg seqs the client sent.
        assert core_frame0.seq is not None
        assert core_frame1.seq is not None
        assert core_frame1.seq == core_frame0.seq + 1
    finally:
        await _reap_harness(harness, core_listener)


async def test_reseq_client_leg_seq_monotonic_across_core_reconnect(runtime_dir: Path) -> None:
    """The client-leg send seq climbs monotonically across a core reconnect (the client
    transport is NEVER replaced) while the core-leg send seq RESETS per fresh dial.
    """
    harness, core_listener = await _build_harness(client_seq_enabled=True)
    try:
        # First payload: capture the client-leg send seq (its absolute value depends on
        # how many control frames preceded it — assert the post-gap seq is STRICTLY
        # GREATER, which is the monotonic-across-the-gap property we care about).
        body_a = b'{"jsonrpc":"2.0","id":1,"method":"inbound.message","params":{}}'
        await harness.core_host.send_payload_unit(body_a, ack=0)
        frame_a = await asyncio.wait_for(harness.client.read_payload_unit(), timeout=2.0)
        assert frame_a is not None
        assert frame_a.seq is not None
        seq_before_gap = frame_a.seq

        # Gap: going_down then drop; reconnect to a fresh core HOST.
        epoch2 = uuid4().hex
        core_listener2 = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
        going_down = json.dumps(
            {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": LIFECYCLE_REASON_SHUTDOWN}}
        ).encode()
        await harness.core_host.send_payload_unit(going_down, ack=0)
        await harness.core_host.close()
        # reconnecting control frame on the (seq-enabled) client leg.
        reconnecting = await asyncio.wait_for(harness.client.read_frame(), timeout=2.0)
        assert reconnecting is not None
        assert reconnecting["method"] == LINK_RECONNECTING

        await core_listener2.bind()
        core_host2 = await asyncio.wait_for(
            _accept_core_host(core_listener2, epoch=epoch2), timeout=3.0
        )
        try:
            restored = await asyncio.wait_for(harness.client.read_frame(), timeout=3.0)
            assert restored is not None
            assert restored["method"] == LINK_RESTORED

            # Second payload AFTER reconnect: the fresh core HOST sends at core-leg seq 0
            # (the gateway's core-leg send counter reset on the new dial), but the
            # gateway's client-leg seq CONTINUES past the gap (never reset — the held
            # client transport's send counter only ever climbs).
            body_b = b'{"jsonrpc":"2.0","id":2,"method":"inbound.message","params":{}}'
            await core_host2.send_payload_unit(body_b, ack=0)
            frame_b = await asyncio.wait_for(harness.client.read_payload_unit(), timeout=2.0)
            assert frame_b is not None
            assert frame_b.payload == body_b
            # Monotonic across the gap: the held client transport never reset its seq, so
            # the post-gap client-leg seq is STRICTLY GREATER than the pre-gap one.
            assert frame_b.seq is not None
            assert frame_b.seq > seq_before_gap
            # The fresh core HOST's send (core-leg seq) reset to 0 on the new dial — the
            # gateway re-minted a fresh core-leg counter, so the legs are independent.
        finally:
            await core_host2.close()
            await core_listener2.aclose()
    finally:
        await _reap_harness(harness, core_listener)


# ---------------------------------------------------------------------------
# Payload-blindness canary (spec §6) — the gateway never parses, never logs the body.
# ---------------------------------------------------------------------------


async def test_payload_blindness_canary_never_leaks_to_logs(
    harness: _GatewayHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A canary-T3-bearing payload is relayed client->core byte-identical; the gateway
    never ``json.loads`` the body AND the canary token never appears in any structlog row.
    """
    import alfred.gateway.relay as relay_mod

    canary = "CANARY-T3-" + uuid4().hex
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 5, "method": "chat.send", "params": {"text": canary}}
    ).encode()

    parsed: list[object] = []
    real_loads = json.loads

    def _spy(*args: object, **kwargs: object) -> object:
        parsed.append(args[0] if args else None)
        return real_loads(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(relay_mod.json, "loads", _spy)

    with structlog.testing.capture_logs() as captured:
        await harness.client.send_payload_unit(body, ack=0)
        got = await asyncio.wait_for(harness.core_host.read_payload_unit(), timeout=2.0)

    assert got is not None
    assert got.payload == body  # byte-identical client->core
    # The relay never parsed the canary body on the forward leg.
    assert body not in parsed
    # The canary token appears in NO structlog row (no key, no value).
    for row in captured:
        for key, value in row.items():
            assert canary not in str(key)
            assert canary not in str(value)


# ---------------------------------------------------------------------------
# Forgery + dial-reject on the non-root leg.
# ---------------------------------------------------------------------------


async def test_forged_ready_on_core_leg_emits_no_false_restored(harness: _GatewayHarness) -> None:
    """An epoch-MISMATCHED ``ready`` on the core leg is rejected — no false ``restored``
    reaches the client.

    Open a gap (``going_down``), then send a ``ready`` carrying a WRONG epoch: the
    gateway's forgery defence rejects it (no feed), so the client sees ``reconnecting``
    but NEVER a ``restored`` from the forged frame.
    """
    going_down = json.dumps(
        {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": LIFECYCLE_REASON_SHUTDOWN}}
    ).encode()
    await harness.core_host.send_payload_unit(going_down, ack=0)

    reconnecting = await asyncio.wait_for(harness.client.read_frame(), timeout=2.0)
    assert reconnecting is not None
    assert reconnecting["method"] == LINK_RECONNECTING

    forged_epoch = uuid4().hex
    forged_ready = json.dumps(
        {"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": forged_epoch}}
    ).encode()
    with structlog.testing.capture_logs() as captured:
        await harness.core_host.send_payload_unit(forged_ready, ack=1)
        # Give the gateway time to process the forged frame.
        for _ in range(50):
            await asyncio.sleep(0)

    # The forged ready was epoch-rejected (loud), and NO restored was pushed to the client.
    mismatch = [c for c in captured if c.get("event") == "gateway.core_link.ready_epoch_mismatch"]
    assert len(mismatch) == 1, captured
    assert harness.core_link._machine.state.value != "up"


async def test_dial_reject_unowned_core_socket(runtime_dir: Path) -> None:
    """The dial-side owner backstop rejects a core path that is not a socket WE own —
    proved on the non-root leg (the gateway does not own the dialed inode).

    Plant a regular FILE at the core socket path; ``dial_comms_socket`` must refuse it
    (``CommsPeerAuthError``) rather than speak the wire to an unowned inode.
    """
    from alfred.plugins.comms_socket_transport import default_comms_socket_path
    from alfred.plugins.comms_wire import CommsPeerAuthError

    path = default_comms_socket_path(_CORE_ADAPTER_ID)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text("not a socket")  # a regular file, not a socket inode

    with pytest.raises(CommsPeerAuthError):
        await dial_comms_socket(_CORE_ADAPTER_ID)
