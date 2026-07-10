"""Diagnostic probe child for the #340 PR2a docker C1/C2 test — INERT in production.

Spawned only by ``tests/integration/test_quarantine_fd_broker_real_spawn.py`` (Task 7,
docker-only) with ``child_module=_BROKERED_PROBE_MODULE``
(:mod:`alfred.security.quarantine_child_io`). Ships in the wheel so it lands under the
bwrap policy's ``/usr`` ro-bind (ADR-0030) — no policy widening. It receives one
SCM_RIGHTS fd per control frame on fd 4, and writes its C1/C2/usability verdict to
STDOUT (fd 1) — NEVER back over fd 4 (fd 4 is strictly one-way, core->child; the core
never ``recv``s it, closing reverse-fd-injection by construction; sec-002). On loop
exit (control-channel EOF or a fault) it writes ONE diagnostic line to STDERR (fd 2),
which the host drains + sanitizes (#251) — never onto fd 1 (frame-only) or fd 4.

The reusable ``recvmsg`` mechanics live in (and are unit-covered by)
:mod:`alfred.egress.control_fd_broker`; this entry is a thin ``# pragma: no cover``
subprocess shim (the ``__main__.py`` subprocess-entry precedent) — only the genuinely
netns-only bodies (the fd-4 socket construction, the recv/probe/verdict loop, and the
C1 negative-control connect, all of which need the empty netns or a live subprocess to
exercise) carry the pragma. Module scope (imports, constants, ``def`` statements) is
covered by a plain import test (``tests/unit/quarantine/test_brokered_probe_import.py``)
— this file lives under ``src/alfred/security/*``, which the release-blocking 100%
coverage gate globs, and an unimported module reads as 0% under that gate.
"""

from __future__ import annotations

import errno
import json
import socket
import struct
import sys

from alfred.egress.control_fd_broker import ControlFdBrokerError, recv_passed_fd

_CONTROL_FD = 4
# A routable public IP — a fresh connect MUST fail ENETUNREACH in the empty netns.
_LITERAL_IP = ("1.1.1.1", 443)
# A fresh connect from a genuinely EMPTY netns has NO route at all, so the kernel fails
# it with ENETUNREACH (empirically errno 101 in the bwrap child; ADR-0050 §2). A
# reachable-but-filtered network gives ETIMEDOUT/ECONNREFUSED and a firewall EPERM —
# none of which prove an empty netns — so ``c1_enetunreach`` is True ONLY for exactly
# ENETUNREACH, never any OSError (else a broken --unshare-net could false-green when the
# literal IP merely happens to be unreachable for another reason). Pinning the exact
# errno (not a route-absence family) keeps the negative control coherent with ADR-0050
# §2 and matches what an empty netns actually produces.
_EMPTY_NETNS_ERRNO = errno.ENETUNREACH
# Bound the plaintext usability round-trip: a stub that never echoes must trip a loud
# socket timeout, not wedge the probe loop (and, through it, the docker test) forever.
_USABILITY_TIMEOUT_S = 10.0


def _write_verdict(verdict: dict[str, object]) -> None:  # pragma: no cover - subprocess I/O
    """Write ONE length-prefixed JSON verdict frame to stdout (fd 1).

    Peer to the core-side frame reader the docker test drives. Stdout stays
    frame-only: no stray writes happen between verdict frames, and the verdict is
    the only thing this process ever puts on fd 1.
    """
    body = json.dumps(verdict).encode("utf-8")
    sys.stdout.buffer.write(struct.pack(">I", len(body)) + body)
    sys.stdout.buffer.flush()


def _probe_once(  # pragma: no cover - needs the empty netns
    control_end: socket.socket,
) -> dict[str, object]:
    """Receive one brokered fd over ``control_end`` and return its C1/C2/usability verdict.

    The probe SOLELY owns the fd ``recv_passed_fd`` hands back (a fresh SCM_RIGHTS
    descriptor, not shared with any other owner in this process), so it is released
    via ``close()`` — NOT ``detach()`` — once the checks are done. ``detach()`` would
    leak one descriptor per loop iteration since nothing else in this process ever
    closes it.
    """
    _data, fd = recv_passed_fd(control_end)
    passed = socket.socket(fileno=fd, family=socket.AF_INET, type=socket.SOCK_STREAM)
    try:
        # A silent stub must NOT hang the probe on ``recv`` — bound every blocking op
        # on the brokered fd so a stuck usability round-trip surfaces as a loud
        # ``socket.timeout`` (an ``OSError`` main() catches + diagnoses), not a wedge.
        passed.settimeout(_USABILITY_TIMEOUT_S)
        peer = list(passed.getpeername())
        so_error = passed.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)  # C2 liveness
        passed.sendall(b"ping")  # minimal usability over the passed fd (plaintext; no TLS in PR2a)
        usable = passed.recv(16) != b""
    finally:
        passed.close()  # the probe owns this fd exclusively — close it, don't leak via detach()
    # C1 negative control: a FRESH socket to a routable IP must fail with a route-absence
    # errno (empty netns). ``c1_enetunreach`` is True ONLY for that errno family, NOT any
    # OSError — a non-route failure (ETIMEDOUT/ECONNREFUSED/EPERM) does not prove the netns
    # is empty. The raw errno rides along in ``c1_errno`` for diagnostics.
    try:
        socket.create_connection(_LITERAL_IP, timeout=3).close()
        c1 = {"c1_enetunreach": False, "c1_errno": 0}
    except OSError as exc:
        c1 = {"c1_enetunreach": exc.errno == _EMPTY_NETNS_ERRNO, "c1_errno": exc.errno or 0}
    return {**c1, "c2_live": so_error == 0, "peer": peer, "usable": usable}


def main() -> None:  # pragma: no cover - subprocess entry (docker-only)
    """Reconstruct the inherited control socket (fd 4) and loop verdicts to stdout.

    The fd-4 socket is built HERE, never at module import time — importing this
    module in test / mypy / ruff / IDE contexts must not touch fd 4 (mirrors the
    ``__main__.py`` sec-007 fd-3 contract).
    """
    control_end = socket.socket(fileno=_CONTROL_FD, family=socket.AF_UNIX, type=socket.SOCK_STREAM)
    while True:
        try:
            verdict = _probe_once(control_end)
            # INSIDE the try: a closed stdout makes ``_write_verdict`` raise
            # ``BrokenPipeError`` (an ``OSError``), which must yield the single
            # diagnostic line below — never a bare traceback.
            _write_verdict(verdict)
        except (OSError, ValueError, ControlFdBrokerError) as exc:
            # Control-channel EOF (``recv_passed_fd`` raises ``ControlFdBrokerError``
            # when the parent closes its end — an ``AlfredError``, NOT an ``OSError``),
            # a malformed SCM_RIGHTS frame, a usability timeout, or a broken stdout on
            # ``_write_verdict``: the test tore the child down, or a real fault occurred.
            # Emit ONE line to stderr — drained + sanitized host-side (#251) — so a
            # docker-leg failure is attributable instead of a silent exit / traceback.
            print(
                f"brokered-probe: probe loop stopped ({type(exc).__name__}: {exc})",
                file=sys.stderr,
                flush=True,
            )
            return


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    main()
