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
    CommsSocketListener,
    _peer_uid_authorized,
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
