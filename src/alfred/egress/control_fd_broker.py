"""Core-side SCM_RIGHTS reachability-broker for the quarantine child (#340 PR2a, ADR-0050).

The empty-netns quarantine child cannot open its own socket. This is the ONE sanctioned in-core
site that opens a bare TCP socket toward the gateway L7 CONNECT proxy and passes the connected fd
to the child via SCM_RIGHTS over an inherited AF_UNIX control fd. It writes ZERO application bytes
over that socket — the child performs CONNECT+TLS+HTTP and terminates TLS itself (HARD #5). Distinct
from EgressClient (which does httpx I/O over its proxied client); the raw-socket-egress ratchet
(tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py) keeps this the
sole INET-connect + sendmsg(SCM_RIGHTS) site in src/alfred.

This module ships the primitives — the error type, the control socketpair constructor, the
fd-receive helper, and the proxy-URL resolver — plus the async ``broker_connected_sockets``
orchestration (connect-defer): it opens ALL ``count`` INET sockets first (CONNECT-handshaking each
through the gateway proxy off-loop) and only then ``sendmsg``s the connected fds over the control
fd, so a partial connect failure sends the child NOTHING. ``broker_connected_socket`` (singular) is
the ``count=1`` pre-gate entrypoint the docker C1/C2 probe drives directly; the per-extraction batch
wiring lands in PR2b (#340 golive Task 9) behind the sign-off.
"""

from __future__ import annotations

import array
import asyncio
import os
import socket
from urllib.parse import urlsplit

import structlog

from alfred.egress._config_protocols import EgressProxyConfig
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.errors import AlfredError

_log = structlog.get_logger(__name__)


class ControlFdBrokerError(AlfredError):
    """The core could not broker a connected socket to the quarantine child (loud refusal, HARD #7).

    Rooted at :class:`AlfredError` (not bare ``Exception``) with a closed-vocabulary ``reason`` so a
    caller can attribute an ``egress.broker.refused`` audit row uniformly (golive spec §21). The
    optional ``destination`` (``"host:port"``, NEVER the raw proxy URL — userinfo/basic-auth must
    never reach a diagnostic string, mirroring :func:`_resolve_proxy_addr`) is the forensic subject
    ADR-0040 residual (vii) needs in the signed core log; :func:`broker_connected_sockets` stamps it
    when a batch fails so ``dispatch`` can write the failure row's ``destination`` from
    ``exc.destination``. ``reason`` stays the audit-vocab key (the ``EGRESS_BROKER_REFUSED_REASONS``
    drift-guard binds to it, NOT to ``destination``).

    ``delivered`` is the count of descriptors that had ALREADY been ``sendmsg``'d into the child's
    SCM_RIGHTS queue when the batch failed. Connect-defer makes the CONNECT half all-or-nothing,
    but it cannot make the SEND half atomic: a failure on socket *k* leaves *k-1* live,
    gateway-reachable fds in a T3-holding child that no drain will ever reclaim (the drain only
    runs in the extract branch's ``finally``, and a failed batch writes no extract frame). A
    non-zero ``delivered`` is therefore the signal that the child holds an un-revoked capability
    and must be torn down — see :meth:`alfred.security.quarantine_transport.
    QuarantineStdioTransport._run_broker_preamble`. It is diagnostic/control state only: the
    closed ``EGRESS_BROKER_REFUSED_FIELDS`` audit schema has no slot for it.
    """

    def __init__(
        self,
        reason: str = "control_fd_broker_failed",
        *,
        destination: str | None = None,
        delivered: int = 0,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.destination = destination
        self.delivered = delivered


def make_control_socketpair() -> tuple[socket.socket, socket.socket]:
    """Return ``(parent_end, child_end)``; the child end is non-CLOEXEC so bwrap inherits it.

    (core-001). The parent end keeps the PEP 446 CLOEXEC default (non-inheritable) so the
    child never gets a copy of the privileged end — a compromised child cannot intercept or
    suppress EOF on the parent side.
    """
    parent_end, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    child_end.set_inheritable(True)
    return parent_end, child_end


# One C ``int`` is the SCM_RIGHTS fd payload width; the ancillary buffer is sized for exactly one.
_FD_ITEMSIZE = array.array("i").itemsize
_FD_CMSG_SPACE = socket.CMSG_SPACE(_FD_ITEMSIZE)


def _collect_scm_rights_fds(ancdata: list[tuple[int, int, bytes]]) -> array.array[int]:
    """Extract every SCM_RIGHTS descriptor the kernel installed from a ``recvmsg`` result.

    Shared by the blocking :func:`recv_passed_fd` and the non-blocking
    :func:`recv_passed_fd_nonblocking` so both apply IDENTICAL fd extraction and — via
    :func:`_close_all` on refusal — the identical leaked-fd-close hardening (fold-log L-2).
    """
    fds = array.array("i")
    for level, typ, cmsg in ancdata:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds.frombytes(cmsg[: len(cmsg) - (len(cmsg) % fds.itemsize)])
    return fds


def _close_all(fds: array.array[int]) -> None:
    """Close every descriptor the kernel installed before a malformed frame is refused.

    A malformed frame (truncated OR not-exactly-one) must not leak a fd into this process. Which
    of the two refusals a >1-fd frame triggers is kernel-specific (macOS/BSD sets MSG_CTRUNC on the
    over-full 1-fd buffer; Linux instead delivers the extra fd and trips the count check), so BOTH
    arcs close through here.
    """
    for fd in fds:
        os.close(fd)


def recv_passed_fd(control_end: socket.socket) -> tuple[bytes, int]:
    """Receive the framed data + EXACTLY ONE SCM_RIGHTS fd on ``control_end`` (loud on truncation).

    Used by the docker probe (child side) and the golive brokered-egress ``bind`` path. A truncated
    ancillary payload (``MSG_CTRUNC``) or a frame carrying zero or >1 fds is a loud
    :class:`ControlFdBrokerError` — the capability envelope is "exactly one connected gateway
    socket per frame".

    fd extraction runs BEFORE the truncation check (not after) so that any fd the kernel DID manage
    to install ahead of truncating the rest gets closed before we raise — otherwise a truncated
    ancillary payload would leak that fd into this process's table (fold-log L-2).
    """
    msg, ancdata, flags, _addr = control_end.recvmsg(4096, _FD_CMSG_SPACE)
    fds = _collect_scm_rights_fds(ancdata)
    if flags & socket.MSG_CTRUNC:
        _close_all(fds)
        raise ControlFdBrokerError("ancillary_truncated")
    if len(fds) != 1:
        _close_all(fds)
        raise ControlFdBrokerError("expected_exactly_one_fd")
    return msg, int(fds[0])


def recv_passed_fd_nonblocking(control_end: socket.socket) -> int | None:
    """Non-blocking (``MSG_DONTWAIT``) sibling of :func:`recv_passed_fd` for the drain sweep.

    Returns the ONE passed fd, or ``None`` on peer-close/EOF (empty frame, zero fds) — the normal
    terminator when a caller sweeps un-consumed pre-brokered sockets (#340 PR2b-golive §6/§8).
    Raises ``BlockingIOError`` (``EAGAIN``) when nothing is queued so the caller can stop the
    sweep, and the SAME loud :class:`ControlFdBrokerError` as the blocking path on a malformed
    frame (``MSG_CTRUNC`` / not-exactly-one-fd) — a truncated or mis-counted frame is a fault,
    never a benign end-of-sweep, and must surface (HARD #7). Reuses the shared leaked-fd-close
    hardening so a refused non-blocking recv never leaks a descriptor either.
    """
    msg, ancdata, flags, _addr = control_end.recvmsg(4096, _FD_CMSG_SPACE, socket.MSG_DONTWAIT)
    fds = _collect_scm_rights_fds(ancdata)
    if flags & socket.MSG_CTRUNC:
        _close_all(fds)
        raise ControlFdBrokerError("ancillary_truncated")
    if not msg and len(fds) == 0:
        return None  # peer closed / no more frames -> the sweep's benign terminator
    if len(fds) != 1:
        _close_all(fds)
        raise ControlFdBrokerError("expected_exactly_one_fd")
    return int(fds[0])


def _resolve_proxy_addr(proxy_config: EgressProxyConfig) -> tuple[str, int]:
    """``host, port`` from ``egress_proxy_url`` — fail-closed like ``EgressClient.from_settings``.

    The raw ``proxy_url`` is deliberately kept OUT of the ``IOPlaneUnavailableError`` detail: a
    forward-gated deployment (#358, core-to-proxy Proxy-Auth) can carry basic-auth credentials in
    that URL, and this error message can reach an operator's terminal/log. Mirrors the
    ``EgressClient`` precedent of never echoing the raw configured URL into a diagnostic string.
    """
    proxy_url = proxy_config.egress_proxy_url
    if not (proxy_url and proxy_url.strip()):
        raise IOPlaneUnavailableError(
            detail="ALFRED_EGRESS_PROXY_URL is unset or blank — cannot broker a gateway socket."
        )
    parts = urlsplit(proxy_url)
    if parts.hostname is None or parts.port is None:
        raise IOPlaneUnavailableError(
            detail="ALFRED_EGRESS_PROXY_URL has no host:port — cannot broker a gateway socket."
        )
    return parts.hostname, parts.port


# Bounded connect toward the gateway proxy: a set-but-unreachable proxy must fail loud, not wedge
# the executor thread (core-002). Distinct from the PR2b provider read-timeout hierarchy.
_CONNECT_TIMEOUT_S = 10.0


def _connect_one(host: str, port: int) -> socket.socket:
    """Blocking (executor-thread) CONNECT: open ONE gateway-connected socket (no send).

    Split out of the old ``_connect_and_send`` so :func:`broker_connected_sockets` can run the
    CONNECT phase for the WHOLE batch before it sends any fd (connect-defer, golive spec §6): a
    partial connect failure therefore sends NOTHING to the child. Returns the connected socket with
    blocking restored; the caller owns its lifecycle (close after send, or close as unsent). A
    failed connect (the common case — gateway down) is a loud ``gateway_unreachable`` refusal, never
    a hang (``socket.create_connection`` bounds the wait at ``_CONNECT_TIMEOUT_S``).
    """
    try:
        sock = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_S)
    except OSError as exc:
        _log.error("egress.control_fd_broker.gateway_unreachable", error_class=type(exc).__name__)
        raise ControlFdBrokerError("gateway_unreachable") from exc
    # create_connection(timeout=) leaves O_NONBLOCK set on the returned socket; that flag rides the
    # shared file description across the SCM_RIGHTS pass. Restore blocking so the child's recv
    # blocks. No try/except here: settimeout(None) on a freshly-connected socket cannot raise in
    # practice, and a defensive guard would be uncoverable dead code (breaks the 100% branch gate)
    # — create_connection above is the only step that needs (and has) a guard.
    sock.settimeout(None)
    return sock


def _send_one(parent_end: socket.socket, sock: socket.socket) -> None:
    """Blocking (executor-thread) SEND: SCM_RIGHTS-pass ``sock`` over ``parent_end``, drop the copy.

    The core writes ZERO application bytes to ``sock`` (HARD #5) — it only passes the descriptor.
    The ``\\x01`` frame is the >=1 data byte an ancillary-only ``sendmsg`` over ``SOCK_STREAM``
    requires so the kernel does not drop the fd. Split out of the old ``_connect_and_send`` SEND
    half; the CONNECT is now :func:`_connect_one`.
    """
    try:
        frame = b"\x01"
        sent = parent_end.sendmsg(
            [frame],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [sock.fileno()]))],
        )
        if sent != len(frame):
            raise ControlFdBrokerError("short_data_send")
    except ControlFdBrokerError:
        raise
    except OSError as exc:
        _log.error("egress.control_fd_broker.sendmsg_failed", error_class=type(exc).__name__)
        raise ControlFdBrokerError("sendmsg_failed") from exc
    finally:
        # SCM_RIGHTS DUPLICATED the descriptor (refcount 2) — drop the core's copy immediately or
        # the child's later close sends no FIN and the core leaks one fd per broker. Safe: already
        # duplicated into the socket buffer by the time sendmsg returned. Also covers a raise
        # before/at sendmsg.
        sock.close()


async def broker_connected_sockets(
    *, parent_end: socket.socket, proxy_config: EgressProxyConfig, count: int
) -> list[tuple[str, int]]:
    """Broker ``count`` connected gateway sockets to the child over ``parent_end`` (connect-defer).

    Each extraction-retry attempt consumes one fresh brokered gateway socket (a consumed passed fd
    cannot re-dial), so the host brokers ``count`` up-front (golive spec §6). CONNECT-DEFER: open
    ALL ``count`` sockets first (:func:`_connect_one`), then ``sendmsg`` them to the child
    (:func:`_send_one`) ONLY if every connect succeeded. A partial failure therefore sends NOTHING —
    the child's fd-4 buffer never sees a partial batch, so there is nothing to reclaim; the
    connected-but-unsent host sockets are closed by the ``finally``. ``sendmsg``/``recvmsg`` with
    ``SCM_RIGHTS`` are blocking with no asyncio ancillary helper, so each connect/send runs in the
    default executor (the ``_blocking_read_exactly`` precedent).

    **The CONNECT phase is CONCURRENT; the SEND phase is SERIAL.** Both halves are load-bearing and
    deliberately asymmetric (golive spec §6, ADR-0052 "Fork 2"):

    * CONNECT runs under ``asyncio.gather`` because a serial loop costs ``count x
      _CONNECT_TIMEOUT_S`` (3 x 10 = 30s) of up-front latency before the extract frame even
      dispatches — equal to the whole 30s ``action_deadline``, so a degraded gateway would
      guarantee a deadline kill instead of the graceful ``provider_unavailable`` refusal.
      ``return_exceptions=True`` is required, not incidental: it lets the collection loop below
      recover EVERY socket that did connect, so the ``finally`` closes them all. A bare ``gather``
      would propagate the first exception while sibling futures were still resolving, orphaning
      their sockets.
    * SEND stays a serial ``for`` because SCM_RIGHTS **queue order is load-bearing** — the child
      consumes one socket per retry attempt in enqueue order — and two concurrent ``sendmsg``
      calls on one control fd could interleave.

    Fail-closed: any failure raises :class:`ControlFdBrokerError` (or an
    :class:`IOPlaneUnavailableError` for an unset/malformed proxy) — never a hang (HARD #7). On a
    batch failure the raised error carries ``destination = "host:port"`` (NEVER the raw proxy URL)
    so ``dispatch`` can attribute the ``egress.broker.refused`` audit row, plus ``delivered`` — how
    many fds already reached the child — so the caller can revoke a partially-granted capability.
    Returns ``[(host, port)] * count`` on full success (one ``destination`` per brokered target).
    """
    host, port = _resolve_proxy_addr(proxy_config)  # userinfo already stripped; may raise IOPlane…
    loop = asyncio.get_running_loop()
    connected: list[socket.socket] = []
    delivered = 0
    try:
        # CONNECT phase — establish all ``count`` gateway-connected host sockets CONCURRENTLY.
        # A failure here (gateway down) means the SEND phase never runs → the child buffer never
        # sees a partial batch → no reclaim.
        outcomes = await asyncio.gather(
            *(loop.run_in_executor(None, _connect_one, host, port) for _ in range(count)),
            return_exceptions=True,
        )
        # Partition BEFORE re-raising: every socket that connected must land in ``connected`` so
        # the ``finally`` closes it, even on the error path. Keep only the FIRST failure — the
        # rest are the same gateway outage observed N times, and re-raising a later one would
        # mask the earliest evidence.
        first_failure: BaseException | None = None
        for outcome in outcomes:
            if isinstance(outcome, socket.socket):
                connected.append(outcome)
            elif first_failure is None:
                first_failure = outcome
        if first_failure is not None:
            raise first_failure
        # SEND phase — only reached if EVERY connect succeeded. SERIAL + ordered (see docstring).
        for sock in connected:
            await loop.run_in_executor(None, _send_one, parent_end, sock)
            delivered += 1  # this fd is now in the child's SCM_RIGHTS queue — a live capability
    except ControlFdBrokerError as exc:
        # Stamp the destination (never the raw URL) so the failure audit row can key on it (§21),
        # and how many fds the child already holds so the caller can revoke them (A2).
        exc.destination = f"{host}:{port}"
        exc.delivered = delivered
        raise
    finally:
        # Sole socket cleanup: a SENT socket's host copy is already dup'd into the child (closing it
        # here just drops the redundant core copy — idempotent second close), and a connected-but-
        # UNSENT socket (a mid-batch failure left it) is closed so it does not leak.
        for sock in connected:
            sock.close()
    return [(host, port)] * count


async def broker_connected_socket(
    *, parent_end: socket.socket, proxy_config: EgressProxyConfig
) -> tuple[str, int]:
    """Broker ONE connected gateway socket to the child (the singular pre-gate entrypoint).

    Delegates to :func:`broker_connected_sockets` with ``count=1`` so the docker probe + the
    de-2026-020 adversarial harness keep their single-socket contract while the golive
    per-extraction path uses the batch. Returns the resolved ``(host, port)`` destination.
    """
    destinations = await broker_connected_sockets(
        parent_end=parent_end, proxy_config=proxy_config, count=1
    )
    return destinations[0]


__all__ = [
    "ControlFdBrokerError",
    "broker_connected_socket",
    "broker_connected_sockets",
    "make_control_socketpair",
    "recv_passed_fd",
    "recv_passed_fd_nonblocking",
]
