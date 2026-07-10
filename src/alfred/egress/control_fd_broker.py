"""Core-side SCM_RIGHTS reachability-broker for the quarantine child (#340 PR2a, ADR-0050).

The empty-netns quarantine child cannot open its own socket. This is the ONE sanctioned in-core
site that opens a bare TCP socket toward the gateway L7 CONNECT proxy and passes the connected fd
to the child via SCM_RIGHTS over an inherited AF_UNIX control fd. It writes ZERO application bytes
over that socket — the child performs CONNECT+TLS+HTTP and terminates TLS itself (HARD #5). Distinct
from EgressClient (which does httpx I/O over its proxied client); the raw-socket-egress ratchet
(tests/adversarial/sandbox_escape/test_only_sanctioned_raw_socket_egress_site.py) keeps this the
sole INET-connect + sendmsg(SCM_RIGHTS) site in src/alfred.

This module ships only the primitives (this file, #340 PR2a task 1): the error type, the control
socketpair constructor, the fd-receive helper, and the proxy-URL resolver. The async
``broker_connected_socket`` orchestration (open the INET socket, CONNECT-handshake it through the
gateway proxy, and sendmsg the result over the control fd) is a separate task — see the PR2a plan.
"""

from __future__ import annotations

import array
import os
import socket
from urllib.parse import urlsplit

from alfred.egress._config_protocols import EgressProxyConfig
from alfred.egress.errors import IOPlaneUnavailableError
from alfred.errors import AlfredError


class ControlFdBrokerError(AlfredError):
    """The core could not broker a connected socket to the quarantine child (loud refusal, HARD #7).

    Rooted at :class:`AlfredError` (not bare ``Exception``) with a closed-vocabulary ``reason`` so a
    caller can attribute a ``SANDBOX_REFUSED`` audit row uniformly. PR2a has no live audited caller
    (only the docker probe drives the broker); the audit-row WRITE lands in PR2b.
    """

    def __init__(self, reason: str = "control_fd_broker_failed") -> None:
        super().__init__(reason)
        self.reason = reason


def make_control_socketpair() -> tuple[socket.socket, socket.socket]:
    """Return ``(parent_end, child_end)``; the child end is non-CLOEXEC so bwrap inherits it.

    (core-001). The parent end keeps the PEP 446 CLOEXEC default (non-inheritable) so the
    child never gets a copy of the privileged end — a compromised child cannot intercept or
    suppress EOF on the parent side.
    """
    parent_end, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    child_end.set_inheritable(True)
    return parent_end, child_end


def recv_passed_fd(control_end: socket.socket) -> tuple[bytes, int]:
    """Receive the framed data + EXACTLY ONE SCM_RIGHTS fd on ``control_end`` (loud on truncation).

    Used by the docker probe (child side). A truncated ancillary payload (``MSG_CTRUNC``) or a frame
    carrying zero or >1 fds is a loud :class:`ControlFdBrokerError` — the capability envelope is
    "exactly one connected gateway socket per frame".

    fd extraction runs BEFORE the truncation check (not after) so that any fd the kernel DID manage
    to install ahead of truncating the rest gets closed before we raise — otherwise a truncated
    ancillary payload would leak that fd into this process's table (fold-log L-2).
    """
    fds = array.array("i")
    msg, ancdata, flags, _addr = control_end.recvmsg(4096, socket.CMSG_SPACE(fds.itemsize))
    for level, typ, cmsg in ancdata:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds.frombytes(cmsg[: len(cmsg) - (len(cmsg) % fds.itemsize)])
    if flags & socket.MSG_CTRUNC:
        for fd in fds:
            os.close(fd)
        raise ControlFdBrokerError("ancillary_truncated")
    if len(fds) != 1:
        raise ControlFdBrokerError("expected_exactly_one_fd")
    return msg, int(fds[0])


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


__all__ = ["ControlFdBrokerError", "make_control_socketpair", "recv_passed_fd"]
