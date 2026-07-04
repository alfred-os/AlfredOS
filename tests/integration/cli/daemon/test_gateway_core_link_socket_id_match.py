"""Spec B G6-0b (#293) — the NON-ROOT merge gate for the gateway<->core socket link.

The criterion-#7 proof of record (``test_chat_gateway_socket_turn``) carries a
``skipif(_LAUNCHER_REQUIRES_ROOT)`` for parity with the launcher-spawn legs, so on
the REQUIRED non-root ``Integration`` CI job (euid != 0 on Linux) it SKIPS — and the
``integration-privileged`` job that DOES run it is NOT in branch protection's
required-checks list. The G6-0b link property therefore gates NOTHING on merge: the
project's #245 / G2 paper-gate hazard.

This test closes that hole. It runs the SAME load-bearing link property the heavy proof
asserts (the gateway's core leg reaches and HOLDS ``GatewayLinkState.UP``), but builds
ONLY the carrier leg that binds the socket + answers the gateway's ``lifecycle.start``
handshake — NO daemon-graph build, NO Postgres, NO ``RealGate`` plugin-load, NO
quarantined-child spawn, and therefore NO launcher hop that would force a root skip. It
runs as euid != 0 on Linux AND on macOS, so it is COLLECTED + EXECUTED (not skipped) by
the required ``Integration`` job — see the ``skipif`` below, which fires ONLY on a
platform genuinely without ``AF_UNIX`` (Windows), never on a non-root POSIX runner.

The property under proof (the "no socket-id mismatch" invariant + the held handshake)
------------------------------------------------------------------------------------
* The daemon binds ``comms-{adapter_kind}.sock``, where ``adapter_kind`` is resolved
  from the ENABLED adapter id ``alfred_tui`` through the PRODUCTION manifest reader
  (:func:`_resolve_comms_adapter_wire_spec`). For ``alfred_tui`` that is ``"tui"`` →
  ``comms-tui.sock``. We resolve it through the real reader (NOT a hard-coded ``"tui"``)
  so a manifest drift of ``adapter_kind`` away from ``"tui"`` is CAUGHT here.
* The gateway's :class:`GatewayCoreLink` dials ``dial_adapter_id="tui"`` →
  ``comms-tui.sock`` via the REAL :func:`dial_comms_socket` (the production default
  dial). If the bound path and the dialed path DIVERGE, the gateway dials a path with no
  listener, its reconnect loop redials forever, and the link NEVER reaches UP — so the
  ``_wait_for(... is UP)`` times out and the test FAILS CLOSED. The mutation check in the
  PR description proves exactly this red.
* The carrier performs the SAME host-side ``lifecycle.start`` handshake the production
  :meth:`alfred.plugins.comms_runner.CommsPluginRunner._handshake` performs: it SENDS
  ``lifecycle.start`` first (with a real minted per-boot ``epoch`` + the ``AlfredSeqAck/1``
  advertisement), then READS the gateway's ack and validates ``result.ok`` exactly as the
  runner does, flipping ``enable_seq_ack`` on the negotiated leg. This catches the
  seq-framing-asymmetry bug class: the gateway must send its ack PLAIN and flip its own
  framing only AFTER. If it instead seq-framed the ack, the carrier — still reading with
  seq OFF — would ``json.loads`` ``"A1 s=0 ..."``, raise :class:`CommsProtocolError`, tear
  the leg, and the link would fall to REDIALING and never hold UP (the heavy proof's BUG 1).

This is the lowest layer that proves the G6-0b link property; the e2e turn + the real
bwrap spawn stay the property of the heavier (root / docker) proofs.
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
from collections.abc import AsyncIterator, Coroutine, Iterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

import pytest

from alfred.bootstrap.lifecycle_epoch import mint_boot_epoch, reset_boot_epoch_for_tests
from alfred.cli.daemon._comms_boot import _resolve_comms_adapter_wire_spec
from alfred.cli.gateway._commands import _DEFAULT_DIAL_ADAPTER_ID
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.link_state import GatewayLinkState
from alfred.plugins.comms_seq_codec import SEQ_VERSION
from alfred.plugins.comms_socket_transport import (
    CommsProtocolError,
    CommsSocketListener,
    CommsSocketTransport,
)

# AF_UNIX is the carrier; only a platform genuinely without it (Windows) cannot run this.
# This is the ONLY sanctioned skip — explicitly NOT a non-root skip (the paper-gate hazard
# this test exists to close), so the required non-root ``Integration`` job collects + runs it.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not hasattr(socket, "AF_UNIX"),
        reason="AF_UNIX unavailable (Windows); the gateway<->core carrier requires it",
    ),
]

# The transport read-crash family the carrier's hold-open read suppresses on teardown
# (the gateway closing the leg). Mirrors comms_runner._TRANSPORT_READ_EXCEPTIONS.
_TRANSPORT_READ_EXCEPTIONS: tuple[type[BaseException], ...] = (
    BrokenPipeError,
    ConnectionResetError,
    asyncio.IncompleteReadError,
    EOFError,
    CommsProtocolError,
)

# The ENABLED adapter id. The daemon resolves its wire ``adapter_kind`` from THIS id's
# manifest; the gateway dials its own default id. The match between the two is the
# property under test (see the module docstring).
_ENABLED_ADAPTER_ID = "alfred_tui"

# The JSON-RPC id the host stamps on ``lifecycle.start`` — mirrors
# ``comms_runner._LIFECYCLE_START_ID`` (kept local so this test owns the exact shape it
# sends; a drift in the runner constant is irrelevant to the gateway's id-echo contract).
_LIFECYCLE_START_ID = 0

# Generous so a wedged leg fails LOUD (TimeoutError) rather than hanging the suite.
_TIMEOUT_S = 10.0


class _RecordingSupervisor:
    """Captures the carrier's accept-and-pump coroutine so the TEST owns + reaps it.

    The faithful socket-carrier stand-in (below) does not need the real ``Supervisor``;
    it registers its accept-and-pump coroutine here exactly as the daemon carrier would,
    and the test drives + reaps it. Mirrors the heavy proof's double.
    """

    def __init__(self) -> None:
        self.registered: list[asyncio.Task[None]] = []

    def register_plugin_task(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task: asyncio.Task[None] = asyncio.ensure_future(coro)
        self.registered.append(task)
        return task


@pytest.fixture
def runtime_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the socket runtime dir at a SHORT tmp ``$HOME`` so the test never touches ~/.run.

    A short ``/tmp/...`` prefix is load-bearing: AF_UNIX socket paths have a ~108-byte
    limit, and the deep pytest ``tmp_path`` on macOS overflows it. Mirrors the unit
    socket suite's ``runtime_dir`` fixture (``tests/unit/plugins/test_comms_socket_transport.py``).
    """
    with tempfile.TemporaryDirectory(prefix="alfgw-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


@asynccontextmanager
async def _faithful_core_carrier(
    *,
    bound_adapter_kind: str,
    epoch: str,
    supervisor: _RecordingSupervisor,
) -> AsyncIterator[CommsSocketListener]:
    """Bind ``comms-{bound_adapter_kind}.sock`` + answer ONE gateway core-leg handshake.

    A faithful stand-in for the daemon's socket carrier
    (:func:`alfred.cli.daemon._comms_boot._listen_socket_comms_adapter`) at exactly the two
    seams this property needs — and NO more — so the test runs without the root-forcing
    daemon graph:

    * It binds the SAME ``default_comms_socket_path(bound_adapter_kind)`` the production
      carrier binds (via the REAL :class:`CommsSocketListener`), so the dialed-vs-bound
      path match is the genuine property (a divergence makes the gateway's dial find no
      listener → never UP → the test fails closed).
    * On accept it performs the HOST side of the ``lifecycle.start`` handshake
      byte-for-byte as :meth:`CommsPluginRunner._handshake` does: SEND ``lifecycle.start``
      (real ``epoch`` + ``AlfredSeqAck/1`` advertisement) FIRST, then READ the gateway's
      ack and validate ``result.ok``, flipping ``enable_seq_ack`` on the negotiated leg.
      Reading the ack with seq still OFF is what catches the seq-framing-asymmetry bug
      class (the ack MUST go out plain; a seq-framed ack would not ``json.loads``).

    The accept-and-pump runs as a registered (supervised-style) task so the test drives
    + reaps it; the listener is reaped on context exit on EVERY path.
    """
    listener = CommsSocketListener(adapter_id=bound_adapter_kind)
    await listener.bind()
    # The accepted-transport handle is captured here (not just in the task local) so the
    # teardown can close it explicitly BEFORE ``listener.aclose()`` — a still-open accepted
    # child connection would otherwise wedge ``asyncio.start_unix_server``'s ``wait_closed``.
    accepted: list[CommsSocketTransport] = []

    async def _accept_and_handshake() -> None:
        # HOST side of the lifecycle.start handshake — mirrors CommsPluginRunner._handshake
        # (the core is HOST on the core leg: it SENDS lifecycle.start FIRST, the gateway is
        # the PEER that reads it, validates the epoch, and acks).
        transport: CommsSocketTransport = await listener.accept()
        accepted.append(transport)
        await transport.send(
            {
                "jsonrpc": "2.0",
                "id": _LIFECYCLE_START_ID,
                "method": "lifecycle.start",
                "params": {
                    # The ENABLED adapter id (``alfred_tui``), exactly as production
                    # ``CommsPluginRunner._handshake`` sends ``self._adapter_id`` — NOT the
                    # bound ``adapter_kind`` (``tui``). The two are deliberately distinct: the
                    # socket is bound at the KIND, the handshake carries the ENABLED id. The
                    # gateway validates only the ``epoch`` + frame shape (it makes no wire-trust
                    # decision on ``adapter_id``), so this stays faithful without affecting the
                    # property under test.
                    "adapter_id": _ENABLED_ADAPTER_ID,
                    "epoch": epoch,
                    "seq_ack": {"version": SEQ_VERSION},
                },
            }
        )
        # Read the gateway's ack. It MUST arrive PLAIN even though seq/ack was negotiated
        # (the gateway flips its own framing only AFTER the ack is on the wire). If the
        # gateway seq-framed the ack instead, this read — with our seq still OFF — would
        # raise CommsProtocolError on the un-decodable JSON, the leg would tear, and the
        # gateway would fall to REDIALING (the seq-framing-asymmetry bug class).
        ack = await transport.read_frame()
        assert ack is not None, "gateway closed the core leg before sending its handshake ack"
        assert ack.get("id") == _LIFECYCLE_START_ID, ack
        result = ack.get("result")
        assert isinstance(result, dict) and result.get("ok"), ack
        seq_ack = result.get("seq_ack")
        if isinstance(seq_ack, dict) and seq_ack.get("version") == SEQ_VERSION:
            # Both peers speak the wire version — flip AFTER reading the plain ack, exactly
            # as CommsPluginRunner._handshake does, so subsequent frames are seq-framed
            # symmetrically. Then hold the leg open (read until the gateway tears it down
            # on shutdown) so the link STAYS UP rather than seeing an immediate EOF.
            transport.enable_seq_ack()
        # Hold the accepted leg open: a clean return here would close ``transport`` and the
        # gateway's pump would see EOF and fall to REDIALING — which would mask a held-UP
        # leg. Block on a further read; the gateway is payload-blind and sends nothing on
        # the core leg in this property, so this parks until the teardown closes the
        # transport (EOF -> ``None``) or cancels the task (suppressed below).
        with suppress(*_TRANSPORT_READ_EXCEPTIONS):
            await transport.read_frame()

    supervisor.register_plugin_task(_accept_and_handshake())
    try:
        yield listener
    finally:
        # Close the accepted transport FIRST: it unblocks the held read (EOF) so the carrier
        # task ends on its own, AND it is the prerequisite for ``listener.aclose()``'s
        # ``server.wait_closed()`` to return (a live accepted child connection wedges it).
        for transport in accepted:
            with suppress(Exception):
                await transport.close()
        for task in supervisor.registered:
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(task, timeout=_TIMEOUT_S)
        await asyncio.wait_for(listener.aclose(), timeout=_TIMEOUT_S)


async def _wait_for(predicate: Any, timeout: float) -> None:
    """Poll ``predicate`` (a 0-arg bool callable) until true or the deadline."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise TimeoutError("gateway core-leg link condition never became true")


async def _drive_core_link_to_up(*, dial_adapter_id: str, runtime_dir: Path) -> None:
    """Bind the carrier at ``alfred_tui``'s resolved kind, dial it, assert the leg HOLDS UP.

    The shared body for both the green path and the fail-closed mutation check. ``dial_
    adapter_id`` is what the gateway's :class:`GatewayCoreLink` dials; the carrier always
    binds the PRODUCTION-resolved ``adapter_kind`` for ``alfred_tui``. When the two agree
    (the green path) the leg holds UP; when they diverge (the mutation) the dial finds no
    listener and the link never reaches UP (TimeoutError).
    """
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Resolve the daemon-side bind kind through the PRODUCTION manifest reader (NOT a
    # hard-coded "tui") so an ``adapter_kind`` drift in plugins/alfred_tui/manifest.toml is
    # caught: the bound path would diverge from the gateway's dialed path and the leg would
    # never reach UP.
    wire = _resolve_comms_adapter_wire_spec(_ENABLED_ADAPTER_ID)
    bound_adapter_kind = wire.adapter_kind

    reset_boot_epoch_for_tests()
    epoch = mint_boot_epoch()

    supervisor = _RecordingSupervisor()
    gateway_shutdown = asyncio.Event()
    core_link_task: asyncio.Task[None] | None = None

    # Deterministic reconnect clock (M3): no wall-clock backoff/jitter so a redial loop
    # (the mutation path) churns fast and the green path settles fast.
    async def _instant_sleep(_delay: float) -> None:
        await asyncio.sleep(0)

    def _no_jitter(hi: float) -> float:
        return hi

    try:
        async with _faithful_core_carrier(
            bound_adapter_kind=bound_adapter_kind,
            epoch=epoch,
            supervisor=supervisor,
        ):
            # The gateway's REAL core link, dialing the REAL production socket path via the
            # REAL ``dial_comms_socket`` (the default dial). The client listener is only used
            # to push control frames (which this core-leg property never emits — the leg goes
            # idempotently UP from UP), so a real-but-unbound listener is sufficient + honest:
            # no client-facing socket is needed to prove the core-leg handshake.
            from alfred.gateway.client_listener import GatewayClientListener

            core_link = GatewayCoreLink(
                client_listener=GatewayClientListener(),
                dial_adapter_id=dial_adapter_id,
                sleep=_instant_sleep,
                jitter=_no_jitter,
                shutdown_event=gateway_shutdown,
            )
            core_link_task = asyncio.ensure_future(core_link.run())

            try:
                # The leg must reach UP and STAY UP. ``_core_epoch`` is set by the peer
                # handshake; the settle re-check distinguishes a HELD leg from a captured-
                # then-torn one (an ack the carrier rejected would tear the leg → REDIALING).
                # On the mismatch path the dial never finds a listener, so this times out —
                # the fail-closed proof.
                await _wait_for(lambda: core_link._core_epoch is not None, _TIMEOUT_S)
                await asyncio.sleep(0.2)
                assert core_link._machine.state is GatewayLinkState.UP, (
                    "gateway core leg did not HOLD UP after the handshake — either the "
                    f"dialed adapter id {dial_adapter_id!r} does not resolve to the bound "
                    f"socket comms-{bound_adapter_kind}.sock (socket-id mismatch), or the "
                    "carrier rejected the gateway's ack (seq-framing asymmetry). Link state: "
                    f"{core_link._machine.state}"
                )
                # The captured epoch is the carrier's minted boot epoch — the handshake
                # genuinely completed (not a luck-of-timing UP).
                assert core_link._core_epoch == epoch
            finally:
                # Reap the gateway INSIDE the carrier context (before the carrier listener
                # tears down): set the shutdown event so ``run`` ends via its clean
                # ``_Shutdown`` path (NOT a cancel-race against the reconnect loop — which on
                # an ``_instant_sleep`` clock would tight-spin and starve the carrier reap),
                # await that clean exit with a hard timeout, then cancel only as a backstop.
                await _reap_gateway(core_link_task, gateway_shutdown)
                core_link_task = None
    finally:
        reset_boot_epoch_for_tests()


async def _reap_gateway(task: asyncio.Task[None], shutdown: asyncio.Event) -> None:
    """Stop ``GatewayCoreLink.run`` cleanly: signal shutdown, await, cancel as a backstop.

    Setting the shutdown event lets ``run`` end through its ``_Shutdown`` arm — both from a
    blocking pump read AND from the top-of-loop check in the reconnect loop (the mismatch
    path, which would otherwise tight-spin on the ``_instant_sleep`` clock). We await that
    clean exit with a hard timeout so a teardown bug fails LOUD rather than hanging, then
    cancel + await as a backstop. Every arm is timeout-bounded so a wedged leg never hangs
    the suite (CLAUDE.md hard rule #7 — fail loud, never hang).
    """
    shutdown.set()
    # Any non-clean outcome (a TimeoutError from wait_for, or run() raising) falls through to
    # the cancel backstop below — both are subclasses of Exception. The second wait_for keeps
    # the cancel-await bounded so a teardown bug fails loud rather than hangs (hard rule #7).
    if await _completed_within(task, _TIMEOUT_S):
        return
    task.cancel()
    with suppress(asyncio.CancelledError, Exception):
        await asyncio.wait_for(task, timeout=_TIMEOUT_S)


async def _completed_within(task: asyncio.Task[None], timeout: float) -> bool:
    """``True`` iff ``task`` finished within ``timeout`` (any outcome); ``False`` on timeout.

    A non-clean ``run()`` exit (it raised) still counts as "completed" — the awaiting test
    body owns the assertion, not this reaper — so any exception is swallowed and reported as
    completion. A genuine timeout returns ``False`` so the caller escalates to a cancel.
    """
    try:
        await asyncio.wait_for(task, timeout=timeout)
    except TimeoutError:
        return False
    except Exception:
        return True
    return True


async def test_core_link_reaches_up_when_dial_id_matches_bound_socket(runtime_dir: Path) -> None:
    """The gateway core leg HOLDS ``UP`` when its dial id matches the daemon's bound socket.

    The G6-0b merge gate. The daemon binds ``comms-tui.sock`` (resolved from the enabled
    ``alfred_tui`` adapter's manifest ``adapter_kind="tui"``); the gateway's default dial id
    is ``"tui"`` → ``comms-tui.sock``. The leg dials, completes the host->peer
    ``lifecycle.start`` handshake (epoch captured, ack accepted), and HOLDS UP. This is the
    property the criterion-#7 proof asserts but cannot gate on the required non-root job.
    """
    # The gateway's default dial id IS the property's left-hand side — assert it is the
    # production constant (not a test literal) so this gate tracks the real dial target.
    assert _DEFAULT_DIAL_ADAPTER_ID == "tui"
    await _drive_core_link_to_up(
        dial_adapter_id=_DEFAULT_DIAL_ADAPTER_ID,
        runtime_dir=runtime_dir,
    )


async def test_core_link_never_reaches_up_on_socket_id_mismatch(runtime_dir: Path) -> None:
    """FAIL-CLOSED proof: a dial id that misses the bound socket NEVER reaches UP.

    The structural guarantee that the green test above is not a tautology: if the gateway
    dials an adapter id whose ``comms-<id>.sock`` is NOT the one the carrier bound, the dial
    finds no listener, the reconnect loop redials forever, and the link NEVER reaches UP. We
    assert that ``_drive_core_link_to_up`` (which waits for UP) raises ``TimeoutError`` here —
    so the green test genuinely depends on the socket-id MATCH, and a future mismatch
    regression turns the green test red rather than passing by luck.
    """
    with pytest.raises(TimeoutError):
        await _drive_core_link_to_up(
            dial_adapter_id="wrong-mismatched-kind",
            runtime_dir=runtime_dir,
        )
