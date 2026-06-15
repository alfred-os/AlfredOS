"""Adversarial: a different-uid peer must not be served the comms socket.

**Threat model** (Spec A §4/§6 — gateway↔core peer authentication, G3-1): a
cross-uid impostor that slipped past the 0600/0700 FS perms (a stale-socket
race that re-bound the path first, or a wider-perm misconfig) connects to the
ADR-0031 comms listener. The `SO_PEERCRED` accept-side check must refuse it
WITHOUT wedging a legitimate same-uid dial-in. The full gateway corpus entries
(canary-transit, crash-pre-ack replay, spoofed-`ready`/stale-epoch, wedged-core
flood) land with the gateway process in G3-3/G4; this entry is the accept-side
peer-auth slice.

The 0600/0700 FS perms already bar a cross-uid connect on every platform; this
proves the `SO_PEERCRED` defense-in-depth on top refuses the impostor without
ack-and-dropping it (CLAUDE.md hard rule #7).
"""

import asyncio
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from alfred.plugins import comms_socket_transport as cst
from alfred.plugins.comms_socket_transport import (
    CommsPeerAuthError,
    CommsSocketListener,
    _assert_dial_path_owned,
    _peer_uid_authorized,
    dial_comms_socket,
)


@pytest.fixture
def short_runtime_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Monkeypatch ``_runtime_dir`` to a SHORT tmp dir (not an env override).

    G3-1 introduces no ``ALFRED_COMMS_RUNTIME_DIR`` knob (that lands in G3-4) — the
    adversarial test relocates the socket by monkeypatching the module-level
    ``_runtime_dir`` directly. A SHORT prefix (``/tmp/...``, not the deep pytest
    ``tmp_path``) is load-bearing: AF_UNIX paths have a ~108-byte limit that the
    macOS ``tmp_path`` already overflows. Production paths (``~/.run/alfred/...``)
    are short, so this is a test concern only.
    """
    with tempfile.TemporaryDirectory(prefix="alfsock-") as runtime:
        path = Path(runtime)
        monkeypatch.setattr(cst, "_runtime_dir", lambda: path)
        yield path


def test_impostor_uid_refused_legitimate_still_authorized() -> None:
    assert _peer_uid_authorized(reported_uid=os.getuid() + 4242) is False
    assert _peer_uid_authorized(reported_uid=os.getuid()) is True


@pytest.mark.asyncio
async def test_listener_serves_same_uid_peer(short_runtime_dir: Path) -> None:
    # Real same-uid loopback: bind, dial, the accept resolves (peer uid == ours).
    del short_runtime_dir
    listener = CommsSocketListener(adapter_id="tui")
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        _reader, writer = await asyncio.open_unix_connection(str(listener.path))
        transport = await asyncio.wait_for(accept_task, timeout=2.0)
        assert transport is not None
        writer.close()
        await writer.wait_closed()
        await transport.close()
    finally:
        await listener.aclose()


@pytest.mark.asyncio
async def test_impostor_refused_then_legitimate_resolves(
    short_runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # First connection reports a FOREIGN uid (impostor) -> refused, future unresolved;
    # second connection reports OUR uid -> the accept resolves to the SECOND transport.
    del short_runtime_dir
    uids = iter([os.getuid() + 9999, os.getuid()])
    monkeypatch.setattr(cst, "_resolve_peer_uid", lambda _sock: next(uids))
    listener = CommsSocketListener(adapter_id="tui")
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        # Impostor: connects, is refused, the accept stays pending.
        _r1, w1 = await asyncio.open_unix_connection(str(listener.path))
        await asyncio.sleep(0.1)
        assert not accept_task.done()
        # Legitimate: connects, the accept resolves.
        _r2, w2 = await asyncio.open_unix_connection(str(listener.path))
        transport = await asyncio.wait_for(accept_task, timeout=2.0)
        assert transport is not None
        for w in (w1, w2):
            w.close()
        await transport.close()
    finally:
        await listener.aclose()


@pytest.mark.asyncio
async def test_impostor_fires_reject_callback_and_does_not_refuse_boot(
    short_runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec A G3-2 (#237) arch-263-001: a rejected impostor fires the audit callback.

    The daemon supplies an ``on_peer_rejected`` callback that writes the
    ``comms.socket.peer_uid_rejected`` audit row. The callback MUST fire with the
    impostor's uid, and the listener must NOT refuse the boot (a rejection is an
    EXPECTED adversarial event — refusing here would be a self-inflicted DoS an
    attacker could trigger by racing the socket). A legitimate same-uid peer still
    serves afterwards.
    """
    del short_runtime_dir
    uids = iter([os.getuid() + 9999, os.getuid()])
    monkeypatch.setattr(cst, "_resolve_peer_uid", lambda _sock: next(uids))

    rejected: list[int | None] = []
    # Deterministic callback-gated wait (CR #264): await an Event set by the reject
    # callback rather than a fixed ``asyncio.sleep`` that can flake under slow CI.
    rejected_fired = asyncio.Event()

    async def _on_rejected(peer_uid: int | None) -> None:
        rejected.append(peer_uid)
        rejected_fired.set()

    listener = CommsSocketListener(adapter_id="tui", on_peer_rejected=_on_rejected)
    await listener.bind()
    try:
        accept_task = asyncio.ensure_future(listener.accept())
        _r1, w1 = await asyncio.open_unix_connection(str(listener.path))
        await asyncio.wait_for(rejected_fired.wait(), timeout=2.0)
        # The reject callback fired with the impostor uid — the audit row's source.
        assert rejected == [os.getuid() + 9999]
        # Boot is NOT refused: the accept stays pending, ready for a legitimate peer.
        assert not accept_task.done()
        _r2, w2 = await asyncio.open_unix_connection(str(listener.path))
        transport = await asyncio.wait_for(accept_task, timeout=2.0)
        assert transport is not None
        # The legitimate accept did not re-fire the reject callback.
        assert rejected == [os.getuid() + 9999]
        for w in (w1, w2):
            w.close()
        await transport.close()
    finally:
        await listener.aclose()


# ---------------------------------------------------------------------------
# Dial-side peer-auth (Spec A G3-3b): the "both-direction SO_PEERCRED" the
# accept side already has, now closed out on the DIAL side. The gateway is the
# dial-side PEER and does NOT own the dialed inode, so it needs BOTH a pre-dial
# lstat owner-backstop (the only owner enforcement on a no-SO_PEERCRED host,
# where the post-connect check degrades open) AND a post-connect SO_PEERCRED
# refusal. Threat: an attacker plants a socket they own at the dial path (a
# stale-socket race / wider-perm misconfig) and lures the gateway into dialing it.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dial_refuses_post_connect_mismatched_uid(
    short_runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dialed peer whose ``SO_PEERCRED`` uid is not ours is refused, FD reaped.

    The post-connect Linux-enforcing arm: even past the FS perms + the pre-dial
    lstat, a connected peer reporting a foreign uid is refused with
    ``CommsPeerAuthError`` (a ``CommsProtocolError``) and the dialed writer is closed
    — the gateway never speaks the wire to a peer it could not authenticate.
    """
    del short_runtime_dir
    dialed_writers: list[asyncio.StreamWriter] = []
    real_open = asyncio.open_unix_connection

    async def _capturing_open(
        *a: object, **k: object
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await real_open(*a, **k)  # type: ignore[arg-type]
        dialed_writers.append(writer)
        return reader, writer

    listener = CommsSocketListener(adapter_id="tui")
    await listener.bind()
    accept_task = asyncio.ensure_future(listener.accept())
    try:
        monkeypatch.setattr(cst, "_resolve_peer_uid", lambda _sock: os.getuid() + 9999)
        monkeypatch.setattr(cst.asyncio, "open_unix_connection", _capturing_open)
        with pytest.raises(CommsPeerAuthError):
            await dial_comms_socket("tui")
        # The dialed writer was closed on the reject path — no FD leak.
        assert len(dialed_writers) == 1
        assert dialed_writers[0].is_closing()
    finally:
        accept_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await accept_task
        await listener.aclose()


@pytest.mark.asyncio
async def test_dial_refuses_planted_non_socket_before_connecting(
    short_runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-socket inode planted at the dial path is refused BEFORE connecting.

    On a no-``SO_PEERCRED`` host the post-connect check degrades open, so the pre-dial
    lstat is the ONLY owner enforcement. An attacker who plants a regular file (or any
    non-socket inode) at the dial path must trip ``CommsPeerAuthError`` without the
    gateway ever attempting ``open_unix_connection`` (no connect to an attacker inode).
    """
    runtime = short_runtime_dir
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    planted = cst.default_comms_socket_path("tui")
    planted.write_bytes(b"attacker-planted, not a socket")

    connect_attempted = False

    async def _forbidden_connect(*a: object, **k: object) -> tuple[object, object]:
        nonlocal connect_attempted
        connect_attempted = True
        raise AssertionError("open_unix_connection must not be reached")

    monkeypatch.setattr(cst.asyncio, "open_unix_connection", _forbidden_connect)
    with pytest.raises(CommsPeerAuthError):
        await dial_comms_socket("tui")
    assert connect_attempted is False


def test_dial_path_owned_backstop_refuses_foreign_owned_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pre-dial lstat backstop refuses a socket owned by a DIFFERENT uid.

    A non-root test cannot chown a socket to another uid, so ``Path.lstat`` is
    monkeypatched to report a socket inode owned by a foreign uid — the wider-perm /
    stale-socket-race the gateway's owner-backstop exists to refuse.
    """
    import stat

    class _ForeignStat:
        st_mode = stat.S_IFSOCK | 0o600
        st_uid = os.getuid() + 9999

    monkeypatch.setattr(Path, "lstat", lambda _self: _ForeignStat())
    with pytest.raises(CommsPeerAuthError):
        _assert_dial_path_owned(Path("/nonexistent/attacker.sock"))
