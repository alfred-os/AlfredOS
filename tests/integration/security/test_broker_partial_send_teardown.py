"""#340 golive review A2: a SEND-phase partial fd hand-off must revoke the capability.

The golive spec required an integration test for "the broker fails on socket 2 of 3" and it
was never written. This is it, exercising the REAL layers the invariant lives in:

* a REAL local TCP listener standing in for the gateway L7 CONNECT proxy;
* the REAL :func:`alfred.egress.control_fd_broker.broker_connected_sockets` — real
  ``socket.create_connection`` dials, real ``sendmsg(SCM_RIGHTS)`` fd passing;
* a REAL ``AF_UNIX`` socketpair as the fd-4 control channel, so the fd that reaches "the
  child" is a genuine kernel-installed descriptor, not a recorded call;
* the REAL :class:`alfred.security.quarantine_child_io._SubprocessChildIO` over a real (inert)
  subprocess, so ``aclose`` really terminates + reaps and really closes the control parent;
* the REAL :class:`alfred.security.quarantine_transport.QuarantineStdioTransport` dispatch;
* the REAL :class:`alfred.egress.broker_audit.EgressBrokerAuditor` and the REAL declared
  ``egress.broker.*`` hookpoints.

The ONLY injected fault is at the ``_send_one`` boundary: socket 1 is passed by the genuine
implementation, socket 2 raises. That is the exact shape the invariant is about, and it cannot
be produced deterministically any other way (a real partial ``sendmsg`` failure is racy).

WHY IT MATTERS. Connect-defer makes the CONNECT half all-or-nothing but cannot make the SEND
half atomic. Before the fix, socket 1 stayed in the child's SCM_RIGHTS queue forever: the
refusal writes no extract frame, so the child's ``drain_leftovers()`` ``finally`` — its only
reclaim path — never runs, and the ``transport_failed`` path never calls ``aclose()``. A
T3-holding child was left holding a live, gateway-reachable capability behind an audit row
that said the broker REFUSED. Repeated failures accumulate up to ``N-1`` such sockets each.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
from typing import TYPE_CHECKING, Any, cast

import pytest

import alfred.egress.control_fd_broker as cfb
from alfred.egress.broker_audit import EgressBrokerAuditor
from alfred.egress.hookpoints import declare_hookpoints as declare_egress_hookpoints
from alfred.hooks import HookRegistry, get_registry, set_registry
from alfred.plugins.transport import ControlResult
from alfred.security.quarantine_child_io import _SubprocessChildIO
from alfred.security.quarantine_transport import (
    QuarantineStagingMap,
    QuarantineStdioTransport,
)
from alfred.security.tiers import CapabilityGateNonce, tag_t3_with_nonce
from tests.helpers.gates import make_quarantined_extract_chain_gate

if TYPE_CHECKING:
    from collections.abc import Iterator

    from alfred.audit.log import AuditWriter

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="POSIX-only: the fd-4 control channel is an AF_UNIX socketpair",
)

# The socket index (1-based) whose SCM_RIGHTS pass is made to fail — "socket 2 of 3".
_FAILING_SOCKET_ORDINAL = 2


class _CapturingAuditWriter:
    """A Postgres-free ``AuditWriter`` double capturing every ``append_schema`` call.

    Real audit persistence is proven by ``test_audit_persistence`` and
    ``test_quarantine_transport_real``; this proof is about the BROKER invariant, so it stays
    self-contained (no testcontainers) and keeps the rows as secondary evidence.
    """

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def append_schema(self, **kwargs: Any) -> None:
        self.rows.append(kwargs)

    def rows_for(self, event: str) -> list[dict[str, Any]]:
        return [row for row in self.rows if row.get("event") == event]


@pytest.fixture
def authorized_t3_nonce() -> Iterator[CapabilityGateNonce]:
    """Install a fresh nonce as the authorised T3 slot (the ``tests/unit/security`` pattern).

    ``tag_t3_with_nonce`` refuses a nonce that is not the live slot identity, so staging a body
    needs the real slot installed. Save/restore under the bootstrap lock leaks no global state.
    """
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security import tiers as _tiers

    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


@pytest.fixture
def egress_registry() -> Iterator[None]:
    """A scoped registry with the REAL ``egress.broker.*`` declarations.

    A production ``RealGate`` with a fixture grant, never an always-allow shim (CLAUDE.md hard
    rule #2). Declaring the real hookpoints means the auditor's ``fail_closed`` dispatch runs
    against its real declaration — the tier/fail_closed drift check included.
    """
    prior = get_registry()
    registry = HookRegistry(gate=make_quarantined_extract_chain_gate(), strict_declarations=False)
    try:
        set_registry(registry)
        declare_egress_hookpoints(registry)
        yield
    finally:
        set_registry(prior)


@pytest.fixture
def gateway_listener() -> Iterator[tuple[socket.socket, str]]:
    """A real loopback TCP listener standing in for the gateway CONNECT proxy.

    Accepts in a daemon thread so ``socket.create_connection`` really completes a handshake;
    the accepted peers are held open for the lifetime of the test so a passed fd stays live
    and observably connected.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    host, port = listener.getsockname()
    accepted: list[socket.socket] = []
    stop = threading.Event()

    def _accept_loop() -> None:
        while not stop.is_set():
            try:
                conn, _addr = listener.accept()
            except OSError:
                return
            accepted.append(conn)

    thread = threading.Thread(target=_accept_loop, daemon=True)
    thread.start()
    try:
        yield listener, f"http://{host}:{port}"
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)
        for conn in accepted:
            conn.close()


class _Cfg:
    """A minimal ``EgressProxyConfig``-shaped stub (structural, PEP 544)."""

    def __init__(self, url: str) -> None:
        self.egress_proxy_url = url


def _inert_child_process() -> subprocess.Popen[bytes]:
    """A real, reapable child process standing in for the bwrap-sandboxed quarantine child.

    ``aclose`` must really SIGTERM + reap something for the teardown assertion to mean
    anything; spawning bwrap is out of scope for this (non-docker) proof, and the invariant
    under test is about fd revocation, not sandbox policy.
    """
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _fail_on_nth_send(monkeypatch: pytest.MonkeyPatch, ordinal: int) -> dict[str, int]:
    """Pass sockets through the REAL ``_send_one`` until ``ordinal``, which raises.

    Delegating to the genuine implementation for the earlier sockets is what makes this a real
    partial hand-off: an actual descriptor is duplicated into the peer's SCM_RIGHTS queue by
    the kernel, which the test then receives and proves live.
    """
    counter = {"n": 0}
    real_send_one = cfb._send_one

    def _send_one(parent_end: socket.socket, sock: socket.socket) -> None:
        counter["n"] += 1
        if counter["n"] == ordinal:
            sock.close()  # the real _send_one owns this in its own finally
            raise cfb.ControlFdBrokerError("sendmsg_failed")
        real_send_one(parent_end, sock)

    monkeypatch.setattr(cfb, "_send_one", _send_one)
    return counter


@pytest.mark.asyncio
async def test_broker_send_failure_on_socket_2_of_3_revokes_the_child(
    egress_registry: None,
    gateway_listener: tuple[socket.socket, str],
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Socket 2 of 3 fails to send: 1 fd reached the child, so the child is torn down.

    Six assertions, in the order the invariant is argued:

    1. the partial hand-off really happened — exactly one live fd landed in the child's queue;
    2. the orchestrator got a graceful typed refusal, never a raw ``ControlFdBrokerError``;
    3. no ingest/extract frame reached the wire (connect-defer's broker-before-write order);
    4. the child was TORN DOWN — the capability is revoked, not merely refused;
    5. the control channel is really closed, so the granted fds cannot be topped up;
    6. the durable ``egress.broker.refused`` row landed with the real destination + reason,
       and NO ``connected`` row was forged for a batch that never completed.
    """
    del egress_registry
    _listener, proxy_url = gateway_listener
    counter = _fail_on_nth_send(monkeypatch, _FAILING_SOCKET_ORDINAL)

    parent_end, child_end = cfb.make_control_socketpair()
    process = _inert_child_process()
    child_io = _SubprocessChildIO(process, control_parent=parent_end, egress_config=_Cfg(proxy_url))

    # Wrap (not replace) the real write_frame so the broker-before-write ordering is
    # observable without substituting the behaviour under test.
    frames: list[bytes] = []
    real_write_frame = child_io.write_frame

    def _spy_write_frame(frame: bytes) -> None:
        frames.append(frame)
        real_write_frame(frame)

    monkeypatch.setattr(child_io, "write_frame", _spy_write_frame)

    audit_writer = _CapturingAuditWriter()
    staging = QuarantineStagingMap()
    staging.stage(
        "deadbeef",
        tag_t3_with_nonce("hello there", source="test", caller_token=authorized_t3_nonce),
    )
    transport = QuarantineStdioTransport(
        child_io=child_io,
        staging=staging,
        broker_auditor=EgressBrokerAuditor(cast("AuditWriter", audit_writer)),
    )

    try:
        result = await transport.dispatch(
            "quarantine.extract",
            {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
        )

        # (1) The partial hand-off is REAL: the send loop reached the failing ordinal, and the
        # sockets before it were genuinely SCM_RIGHTS-passed into the child end.
        assert counter["n"] == _FAILING_SOCKET_ORDINAL
        _msg, passed_fd = cfb.recv_passed_fd(child_end)
        passed = socket.socket(fileno=passed_fd)
        try:
            # A live, gateway-connected descriptor — the capability the child was granted.
            assert passed.getpeername()[1] == _listener.getsockname()[1]
        finally:
            passed.close()
        # …and exactly one: the batch stopped at the failing ordinal. The sweep terminates on
        # peer-close EOF rather than EAGAIN, which is itself evidence of the revoke — the
        # teardown already closed the control parent, so no further fd can ever arrive.
        assert cfb.recv_passed_fd_nonblocking(child_end) is None

        # (2) Graceful typed refusal — the orchestrator never sees the broker error.
        assert isinstance(result, ControlResult)
        assert result.payload == {"kind": "typed_refusal", "reason": "provider_unavailable"}

        # (3) Broker-before-write: no ingest/extract frame followed the failed batch.
        assert frames == []

        # (4) The capability is REVOKED: the child is torn down, not left holding live fds.
        assert process.poll() is not None

        # (5) The control channel is closed — no further fd can be handed over it.
        assert parent_end.fileno() == -1

        # (6) Durable forensics: one refusal row carrying the real destination + closed-vocab
        # reason, and NO success row forged for a batch that never completed.
        refused = audit_writer.rows_for("egress.broker.refused")
        assert len(refused) == 1
        assert refused[0]["subject"]["destination"] == proxy_url.removeprefix("http://")
        assert refused[0]["subject"]["reason"] == "sendmsg_failed"
        assert refused[0]["result"] == "refused"
        assert audit_writer.rows_for("egress.broker.connected") == []
    finally:
        await child_io.aclose()  # idempotent — the revoke already ran
        child_end.close()


@pytest.mark.asyncio
async def test_revoked_child_degrades_gracefully_on_the_next_extraction(
    egress_registry: None,
    gateway_listener: tuple[socket.socket, str],
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a revoke, later extractions REFUSE gracefully — they do not crash the daemon.

    The quarantine child is spawned exactly ONCE, at daemon boot
    (``_build_comms_inbound_extractor``); there is no respawn scheduler, so a revoke takes the
    quarantine path down until the daemon restarts. That is the accepted fail-closed trade —
    but it must degrade, not explode. With the control parent closed, ``_send_one`` fails
    immediately on the FIRST socket (``delivered == 0``), so every later dispatch returns the
    same ``provider_unavailable`` typed refusal plus its own durable refusal row, and does NOT
    re-teardown an already-dead child.
    """
    del egress_registry
    _listener, proxy_url = gateway_listener
    _fail_on_nth_send(monkeypatch, _FAILING_SOCKET_ORDINAL)

    parent_end, child_end = cfb.make_control_socketpair()
    process = _inert_child_process()
    child_io = _SubprocessChildIO(process, control_parent=parent_end, egress_config=_Cfg(proxy_url))
    audit_writer = _CapturingAuditWriter()
    staging = QuarantineStagingMap()
    transport = QuarantineStdioTransport(
        child_io=child_io,
        staging=staging,
        broker_auditor=EgressBrokerAuditor(cast("AuditWriter", audit_writer)),
    )

    try:
        for handle_id in ("first", "second"):
            staging.stage(
                handle_id,
                tag_t3_with_nonce("body", source="test", caller_token=authorized_t3_nonce),
            )
            result = await transport.dispatch(
                "quarantine.extract",
                {"handle_id": handle_id, "schema_json": "{}", "schema_version": 1},
            )
            assert result.payload == {
                "kind": "typed_refusal",
                "reason": "provider_unavailable",
            }

        # Both extractions produced a durable refusal row — the second is not silently
        # swallowed just because the child was already revoked.
        # One row per extraction — the second is not silently dropped just because the child
        # was already revoked.
        assert len(audit_writer.rows_for("egress.broker.refused")) == 2
    finally:
        await child_io.aclose()
        child_end.close()
