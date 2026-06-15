"""Adversarial: the trust-boundary properties of the runnable :class:`GatewayProcess`.

**Threat model** (Spec A G3-3b-2b / ADR-0031/0032, #237 — the gateway front door).
The G3-3b-2 unit/wire-contract suites prove the relay's properties in isolation; the
``test_process.py`` Task-4 suite proves the process LIFECYCLE. This module is the
release-blocking adversarial entry for the assembled PROCESS: the same trust-boundary
defenses must survive the full ``GatewayProcess.run()`` wiring, end-to-end over real
loopback sockets, non-root and in-process (the #245 paper-gate lesson — a launcher/
root-only test is NOT a real gate).

Three process-level boundary properties:

* **(a) peer-reject** — a wrong-uid client (``SO_PEERCRED`` impostor) connecting to a
  RUNNING process is refused end-to-end: ``gateway_peer_auth_rejected_total`` increments,
  the loud ``gateway.process.peer_uid_rejected`` row fires, and the listener keeps waiting
  (a rejection is an EXPECTED adversarial event, never a self-inflicted DoS).
* **(b) epoch-forgery** — a ``daemon.lifecycle.ready`` on the core leg carrying a DIFFERENT
  (shape-valid 32-hex) epoch than the handshake epoch produces NO ``link.restored`` through
  the process: the merged ``_consume_ready`` forgery defense survives the process wiring.
  Mutation-sound: deleting the epoch guard MUST fail this test (verified by reversion).
* **(c) payload-blindness** — a canary-T3-bearing payload relayed client->core through the
  process arrives byte-identical AND the canary token NEVER appears in any gateway structlog
  row (key or value) or metric label (CLAUDE.md hard rule #5 — the carrier is payload-blind).

Deterministic: every frame is driven explicitly (no wall-clock sleeps) — bounded
``asyncio.sleep(0)`` yields + ``wait_for`` safety nets.
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
from prometheus_client import REGISTRY

from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    LIFECYCLE_REASON_SHUTDOWN,
    LINK_RECONNECTING,
    LINK_RESTORED,
)
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
    with tempfile.TemporaryDirectory(prefix="alfgw-adv-") as home:
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
    """Play the PLAIN TUI side of the gateway's client-leg HOST handshake."""
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
    """Accept the gateway's dial and run the core HOST side of the handshake."""
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


async def _reap_run_task(run_task: asyncio.Task[None], shutdown: asyncio.Event) -> None:
    """Last-resort teardown reap for tests whose load-bearing assertion is NOT the clean
    stop (e.g. the peer-reject test asserts the reject row + that the process stayed up,
    THEN tears down). Sets ``shutdown`` and reaps, falling back to a forced cancel only if
    the task does not return — acceptable here because the clean stop is not what's under
    test. Tests that DO assert a clean shutdown must use :func:`_assert_clean_shutdown`.
    """
    shutdown.set()
    with structlog.testing.capture_logs():
        try:
            await asyncio.wait_for(run_task, timeout=3.0)
        except (TimeoutError, asyncio.CancelledError):
            run_task.cancel()


async def _assert_clean_shutdown(run_task: asyncio.Task[None], shutdown: asyncio.Event) -> None:
    """Assert ``run()`` stops CLEANLY on ``shutdown_event`` — WITHOUT a forced cancel.

    The clean stop is the property under test, so a forced ``cancel()`` must NOT satisfy
    teardown: a relay that never observes ``shutdown_event`` (a real bug) makes
    ``wait_for`` raise ``TimeoutError`` here and the test FAILS, rather than a cancel
    masking it. Mutation-sound: a no-op shutdown-observation in ``GatewayProcess.run``
    makes this assertion fail. The caller's ``finally`` keeps a last-resort ``cancel()``
    only for the case where THIS assertion already raised (reaping a known-broken task).
    """
    shutdown.set()
    with structlog.testing.capture_logs():
        await asyncio.wait_for(run_task, timeout=3.0)
    assert run_task.done()
    assert not run_task.cancelled()  # it RETURNED on shutdown — was not force-cancelled.


def _assert_canary_in_no_metric(canary: str) -> None:
    """Assert ``canary`` appears in NO prometheus metric the gateway exposes — not in a
    metric NAME, a label KEY, a label VALUE, or a sample name (CLAUDE.md hard rule #5:
    a canary must leak to neither logs NOR metrics).

    The gateway metrics are label-free by design (:mod:`alfred.gateway.metrics`); this
    walks the *whole* default :class:`~prometheus_client.CollectorRegistry` so a future
    collector that started attaching a payload-derived label would trip this guard. We
    iterate ``REGISTRY.collect()`` rather than the metric objects so the assertion covers
    every sample's name + labels (and stays robust to new gateway collectors).
    """
    for metric in REGISTRY.collect():
        assert canary not in metric.name, metric.name
        for sample in metric.samples:
            assert canary not in sample.name, sample.name
            for label_key, label_value in sample.labels.items():
                assert canary not in label_key, sample
                assert canary not in label_value, sample


# ---------------------------------------------------------------------------
# (a) Process-level peer-reject — wrong-uid client refused end-to-end.
# ---------------------------------------------------------------------------


async def test_process_rejects_wrong_uid_client_metric_and_loud_row(
    runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrong-uid client connecting to a RUNNING ``GatewayProcess`` is refused: the
    ``gateway_peer_auth_rejected_total`` counter increments, the loud
    ``gateway.process.peer_uid_rejected`` row fires (with the foreign uid), and the
    listener keeps waiting (paired with a shutdown to end ``run()`` cleanly).
    """
    import alfred.plugins.comms_socket_transport as transport_mod

    # Force the ACCEPTED peer uid to a value that never matches os.getuid(). The client
    # connects RAW (open_unix_connection) — NOT dial_comms_socket, which would run the
    # dial-side peer-auth check and reject before the gateway's accept side ever sees it.
    foreign_uid = os.getuid() + 4242
    monkeypatch.setattr(transport_mod, "_resolve_peer_uid", lambda _sock: foreign_uid)

    before = PEER_AUTH_REJECTED._value.get()
    shutdown = asyncio.Event()
    process = GatewayProcess(shutdown_event=shutdown)
    run_task = asyncio.ensure_future(process.run())
    try:
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
        assert len(rejected) == 1, captured
        assert rejected[0].get("log_level") == "warning"
        assert rejected[0].get("peer_uid") == foreign_uid
        # The metric incremented end-to-end through the running process.
        assert PEER_AUTH_REJECTED._value.get() == before + 1
        # The listener kept waiting — the rejection did not tear the process down.
        assert not run_task.done()
    finally:
        await _reap_run_task(run_task, shutdown)

    assert not _gateway_socket_path().exists()


# ---------------------------------------------------------------------------
# (b) Process-level epoch-forgery — a forged ``ready`` paints NO false ``restored``.
# ---------------------------------------------------------------------------


async def test_process_forged_ready_epoch_paints_no_false_restored(runtime_dir: Path) -> None:
    """A forged ``daemon.lifecycle.ready`` (wrong 32-hex epoch) on the core leg of a
    RUNNING process produces NO ``link.restored`` to the client.

    The load-bearing forgery: open a gap (``going_down`` then EOF) so the client sees
    ``reconnecting``, then a SEPARATE core HOST re-binds and front-runs a forged ``ready``
    BEFORE the gateway completes a fresh handshake. The merged ``_consume_ready`` epoch
    guard rejects the forgery with NO feed — the client's last control is ``reconnecting``,
    NEVER a false ``restored``, and the loud ``gateway.core_link.ready_epoch_mismatch`` row
    fires. MUTATION-SOUND: deleting the epoch guard makes the gateway feed CORE_READY and
    emit a real ``restored`` here, failing this test.
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

        # Open the gap: going_down then EOF on the first core leg.
        going_down = json.dumps(
            {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": LIFECYCLE_REASON_SHUTDOWN}}
        ).encode()
        await core_host1.send_payload_unit(going_down, ack=0)
        await core_host1.close()
        await core_listener1.aclose()

        # §9 step 1: ``reconnecting`` reaches the client.
        reconnecting = await asyncio.wait_for(client.read_frame(), timeout=3.0)
        assert reconnecting is not None
        assert reconnecting["method"] == LINK_RECONNECTING

        # A fresh core HOST re-binds and completes the handshake with a NEW (genuine)
        # epoch, then injects a forged ``ready`` carrying a DIFFERENT 32-hex epoch — the
        # false-liveness attack a same-uid impostor past SO_PEERCRED would mount.
        epoch2 = uuid4().hex
        forged_epoch = uuid4().hex
        assert forged_epoch != epoch2
        core_listener2 = CommsSocketListener(adapter_id=_CORE_ADAPTER_ID)
        await core_listener2.bind()
        core_host2 = await asyncio.wait_for(
            _accept_core_host(core_listener2, epoch=epoch2), timeout=3.0
        )
        try:
            # The genuine reconnect already painted ``restored`` (new handshake epoch
            # captured) — drain it so the forged ready below is what we test.
            restored = await asyncio.wait_for(client.read_frame(), timeout=3.0)
            assert restored is not None
            assert restored["method"] == LINK_RESTORED

            forged_ready = json.dumps(
                {"method": DAEMON_LIFECYCLE_READY, "params": {"epoch": forged_epoch}}
            ).encode()
            with structlog.testing.capture_logs() as captured:
                await core_host2.send_payload_unit(forged_ready, ack=1)
                # Give the gateway time to process + reject the forged frame.
                for _ in range(50):
                    await asyncio.sleep(0)

            # The forgery was epoch-rejected (loud) — and produced NO further control
            # frame to the client (no second, false ``restored`` from a forged epoch).
            mismatch = [
                c for c in captured if c.get("event") == "gateway.core_link.ready_epoch_mismatch"
            ]
            assert len(mismatch) == 1, captured
            assert mismatch[0].get("log_level") == "warning"
            # No control frame followed the forged ready on the client wire (drain races
            # the post-forgery yields above; a forged ``restored`` would arrive here).
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(client.read_frame(), timeout=0.2)

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


# ---------------------------------------------------------------------------
# (c) Process-level payload-blindness — a canary never leaks to logs/metrics.
# ---------------------------------------------------------------------------


async def test_process_canary_payload_relays_blind_no_log_leak(runtime_dir: Path) -> None:
    """A canary-T3-bearing payload relayed client->core through the RUNNING process
    arrives byte-identical AND the canary token appears in NO gateway structlog row
    (key or value) NOR any prometheus metric (name, label key, label value, sample) —
    the front door is a payload-blind T1 carrier (hard rule #5: logs AND metrics).

    The metric assertion makes the label-free invariant load-bearing: the gateway
    collectors carry no labels by design, so a canary can never reach a metric label —
    this test would catch a regression that started deriving a label from payload bytes.
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

        canary = "CANARY-T3-" + uuid4().hex
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 7, "method": "inbound.message", "params": {"text": canary}}
        ).encode()
        try:
            with structlog.testing.capture_logs() as captured:
                await client.send_payload_unit(body, ack=0)
                got = await asyncio.wait_for(core_host.read_payload_unit(), timeout=2.0)
                # Drive a few yields so any relay log row is captured within the block.
                for _ in range(20):
                    await asyncio.sleep(0)

            assert got is not None
            assert got.payload == body  # byte-identical client->core through the process
            assert canary.encode() in got.payload  # the canary made it (relay, not drop)

            # The canary token appears in NO structlog row — no key, no value.
            for row in captured:
                for key, value in row.items():
                    assert canary not in str(key), row
                    assert canary not in str(value), row

            # And in NO prometheus metric — name, label key, label value, or sample
            # (hard rule #5 is logs AND metrics; the gateway metrics are label-free).
            _assert_canary_in_no_metric(canary)

            # Clean stop FIRST (a quiet return, never a gap), THEN reap the ends.
            # Mutation-sound: a relay ignoring shutdown_event makes this FAIL, not pass.
            await _assert_clean_shutdown(run_task, shutdown)
        finally:
            await core_host.close()
            await client.close()
    finally:
        if not run_task.done():
            run_task.cancel()
        await core_listener.aclose()

    assert not _gateway_socket_path().exists()
