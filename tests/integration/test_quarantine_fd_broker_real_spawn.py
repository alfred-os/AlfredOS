"""DOCKER-ONLY: the SCM_RIGHTS fd-broker topology proven against a REAL bwrapped child.

#340 PR2a (ADR-0050) — the core-side reachability-broker
(:mod:`alfred.egress.control_fd_broker`) hands an already-connected TCP socket to the
empty-netns quarantine child over an inherited AF_UNIX control fd (fd 4), and the child
uses it WITHOUT reopening its network namespace. This is the proof the unit + macOS
legs cannot give: a real ``bwrap``-sandboxed child, spawned through
``bin/alfred-plugin-launcher.sh`` under the SHIPPED ``kind="full"`` policy
(``--unshare-net``), receives a brokered fd per control frame and reports its verdict
over stdout.

The child here is the wheel-co-located diagnostic probe
(:mod:`alfred.security.quarantine_child._brokered_probe`, ``child_module=
_BROKERED_PROBE_MODULE``), NOT the real extractor — this PR2a leg proves the
TOPOLOGY (fd crosses bwrap; child cannot self-connect; core leaks no fd; core writes
zero application bytes) with the mechanism DORMANT on the live path. The child-side
TLS/HTTP transport + the ``control_fd`` flip land in PR2b behind the human sign-off.

What each assertion proves (spec §9, the fold-log M2/M6 folds):

* **C1 (empty netns):** the child's FRESH ``create_connection`` to a routable public
  IP fails ``ENETUNREACH`` — the netns is genuinely empty, so the ONLY reachability
  the child has is the brokered fd.
* **C2 (a live socket crossed):** ``getpeername``/``SO_ERROR`` on the passed fd show a
  connected socket to the stub proxy — SCM_RIGHTS carried it across the bwrap boundary.
* **usability:** a minimal plaintext round-trip over the passed fd succeeds.
* **no core-side leak:** the CORE process fd count is stable across ≥2 sequential
  passes to the SAME still-alive child (the broker closes its duplicated copy after
  ``sendmsg``).
* **HARD #5 (M2):** the stub records the FIRST bytes it receives on each brokered
  connection; they must equal ``b"ping"`` (the child's own first write) — proof the
  core wrote ZERO application bytes to the socket before passing it.

WHY DOCKER-ONLY: ``kind="full"`` resolves to bwrap on Linux; the spawn needs ``bwrap``
+ a Linux kernel + root (the reference launcher unshares) + the ADR-0030 bound
interpreter (``ALFRED_QUARANTINE_CHILD_PYTHON`` set, ``alfred`` installed into it — the
wheel-co-located probe resolves off THAT interpreter's site-packages, which the
policy's ``/usr`` ro-bind covers). It SKIPS on macOS / non-root / unprovisioned boxes;
it RUNS + gates merge on the privileged-Linux CI legs (``integration-privileged``;
aarch64 twin ``integration-privileged-arm64``, #269). Reproduce locally via
``docker run --rm --privileged --platform linux/<arch> debian:bookworm`` — use
``linux/arm64`` on an Apple-Silicon host (amd64 emulation fails there with
``exec format error`` without qemu binfmt), ``linux/amd64`` on x86-64 (see
procedural_local_docker_for_ci_only_failures in project memory).
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import struct
import threading
from pathlib import Path

import pytest

from alfred.security import quarantine_child_io as qcio

pytestmark = pytest.mark.integration

# DOCKER-ONLY guard, mirroring ``test_quarantine_child_real_spawn.py``: bwrap + Linux +
# root + the ADR-0030 bound-interpreter provisioning. The probe child (a peer of the
# real quarantine child under the SAME ``kind="full"`` policy + manifest) execs
# ``ALFRED_QUARANTINE_CHILD_PYTHON`` under the policy's ``/usr`` ro-bind, so the same
# provisioning signal gates it.
_HAS_BWRAP = shutil.which("bwrap") is not None
_PROVISIONED = bool(os.environ.get("ALFRED_QUARANTINE_CHILD_PYTHON"))
_DOCKER_ONLY = pytest.mark.skipif(
    not _HAS_BWRAP or os.uname().sysname != "Linux" or os.geteuid() != 0 or not _PROVISIONED,
    reason=(
        "brokered-fd real-spawn: needs bwrap + Linux + root + the ADR-0030 "
        "bound-interpreter provisioning (ALFRED_QUARANTINE_CHILD_PYTHON set, alfred "
        "installed into that interpreter). RUNS + gates merge on the privileged-Linux "
        "CI legs (`integration-privileged` on amd64, `integration-privileged-arm64` on "
        "aarch64 — #269); skipped on macOS / non-root / unprovisioned local "
        "boxes — reproduce via `docker run --rm --privileged --platform "
        "linux/<arch>`: use `linux/arm64` on an Apple-Silicon host (amd64 emulation "
        "fails there with `exec format error` without qemu binfmt), `linux/amd64` on "
        "x86-64."
    ),
)

# The child's single usability write over the brokered fd; the stub echoes it and the
# HARD #5 assertion pins the stub's first-received bytes to it (nothing core-prepended).
_PING = b"ping"
# Bound each accepted stub connection's recv so a child that connects then stalls fails
# closed (the handler thread ends, its conn fd is closed) instead of wedging forever.
_STUB_RECV_TIMEOUT_S = 10.0


class _StubProxy:
    """A trivial loopback TCP server standing in for the gateway CONNECT proxy.

    The core ``broker_connected_socket``s a connection here and passes the fd to the
    child; the child sends ``b"ping"`` and expects an echo (the usability check). To
    prove HARD #5 (the core wrote ZERO application bytes), this stub RECORDS the first
    bytes it receives on each accepted connection — the test asserts they are exactly
    the child's ``b"ping"``, nothing the core prepended.
    """

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.host, self.port = self._sock.getsockname()
        self._lock = threading.Lock()
        self._first_bytes: list[bytes] = []
        self._conn_threads: list[threading.Thread] = []
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return  # listening socket closed on teardown
            handler = threading.Thread(target=self._echo, args=(conn,), daemon=True)
            with self._lock:
                self._conn_threads.append(handler)
            handler.start()

    def _echo(self, conn: socket.socket) -> None:
        with conn:
            # A child that connects then stalls must NOT wedge this handler — bound the
            # recv so it fails closed (thread ends, conn fd closed) rather than owning the
            # accepted socket forever.
            conn.settimeout(_STUB_RECV_TIMEOUT_S)
            try:
                # Coalesce a (API-legal, astronomically unlikely) fragmented first write
                # so the recorded first bytes are the full ``_PING``, never a short read.
                data = b""
                while len(data) < len(_PING):
                    chunk = conn.recv(64)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                return  # stalled / broken client: give up — the test fails loud elsewhere
            if len(data) < len(_PING):
                return  # EOF before a full ping — no recording (the HARD #5 assert goes RED)
            # Record BEFORE echoing so the recording is complete before the child's own
            # ``recv`` (which returns only after this ``sendall``) unblocks — a
            # happens-before that makes the assertion race-free.
            with self._lock:
                self._first_bytes.append(bytes(data))
            with contextlib.suppress(OSError):
                conn.sendall(data)

    def first_bytes(self) -> list[bytes]:
        with self._lock:
            return list(self._first_bytes)

    def settle(self) -> None:
        """Join every accepted connection's echo thread so its ``conn`` fd is closed.

        The stub shares the test process, so an in-flight ``conn`` would otherwise be
        transiently counted in ``/proc/self/fd`` and race the core-side fd-leak snapshot.
        Joining the (recv-bounded) echo threads makes their ``with conn:`` close happen
        BEFORE the snapshot, so the count reflects only fds the core actually owns. The
        join timeout exceeds the per-conn recv timeout so a stalled handler is still
        reaped rather than left as a dangling daemon.
        """
        with self._lock:
            threads = list(self._conn_threads)
        for handler in threads:
            handler.join(timeout=_STUB_RECV_TIMEOUT_S + 1)

    def close(self) -> None:
        self._sock.close()  # unblock _serve's accept
        self._t.join(timeout=5)  # let the accept loop exit
        self.settle()  # reap the recv-bounded handlers so no conn fd / thread leaks on teardown


class _Cfg:
    """A minimal :class:`~alfred.egress._config_protocols.EgressProxyConfig` stub."""

    def __init__(self, host: str, port: int) -> None:
        self.egress_proxy_url: str | None = f"http://{host}:{port}"


async def _read_verdict(io: qcio._SubprocessChildIO) -> dict[str, object]:
    """Await one verdict frame and return the decoded JSON (``read_frame`` = header+body)."""
    raw = await io.read_frame()
    length = struct.unpack(">I", raw[:4])[0]
    verdict: dict[str, object] = json.loads(raw[4 : 4 + length])
    return verdict


@_DOCKER_ONLY
@pytest.mark.asyncio
async def test_brokered_fd_crosses_bwrap_and_child_cannot_self_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A brokered socket crosses bwrap into an empty-netns child; the core leaks + writes nothing.

    Mirrors ``test_quarantine_child_real_spawn.py``'s launcher setup: the daemon is
    absent here, so the test itself sets ``ALFRED_ENVIRONMENT`` for the launcher to
    resolve the ``kind="full"`` bwrap policy (without it the launcher refuses with
    ``environment_not_set`` and the child exits before replying — a truncated
    ``read_frame``).
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    proxy = _StubProxy()
    io: qcio._SubprocessChildIO | None = None
    try:
        # Spawn INSIDE the try so a spawn failure still runs `proxy.close()` in `finally`
        # (the proxy's listener + threads would otherwise leak). Mirrors the sibling
        # `test_quarantine_child_real_spawn.py` cleanup discipline.
        io = await qcio.spawn_quarantine_child_io(
            provider_key="probe-key-placeholder",  # the probe never reads fd 3 — no LLM call
            control_fd=True,
            child_module=qcio._BROKERED_PROBE_MODULE,
            egress_config=_Cfg(proxy.host, proxy.port),
        )
        fd_counts: list[int] = []
        for _ in range(2):  # >=2 sequential passes to the SAME still-alive child
            await io.broker_sockets(1)  # golive Task 9: broker ONE socket per probe pass
            verdict = await _read_verdict(io)
            # C1: the child's fresh connect had NO route (empty netns). The probe sets
            # this True ONLY for ENETUNREACH — a non-route failure would NOT prove an
            # empty netns, so it must not satisfy the negative control (ADR-0050 §2).
            assert verdict["c1_enetunreach"] is True, (
                f"C1 negative control expected ENETUNREACH (empty netns); "
                f"got errno {verdict['c1_errno']}"
            )
            assert verdict["c2_live"] is True  # C2: getpeername/SO_ERROR — a live socket crossed
            assert verdict["peer"] == [proxy.host, proxy.port]  # JSON array -> list
            assert verdict["usable"] is True  # minimal plaintext I/O over the passed fd
            # CORE-process fd count — stable iff the broker closed its copy after sendmsg.
            # Settle the stub first so no in-flight conn fd races the snapshot.
            proxy.settle()
            fd_counts.append(sum(1 for _ in Path("/proc/self/fd").iterdir()))
        assert fd_counts[0] == fd_counts[1]  # fd-count stable across passes — no core-side leak

        # HARD #5 (M2): the core wrote ZERO application bytes to the brokered socket —
        # the first bytes the stub saw on each connection are the child's own ``_PING``.
        assert proxy.first_bytes() == [_PING, _PING], (
            "HARD #5: the core must write no application bytes to the brokered socket; "
            f"expected the child's {_PING!r} first on each connection, got {proxy.first_bytes()!r}"
        )
    finally:
        # Nest so `proxy.close()` runs even if `io.aclose()` raises, and skip `aclose`
        # if the spawn itself failed (`io is None`).
        try:
            if io is not None:
                await io.aclose()
        finally:
            proxy.close()
