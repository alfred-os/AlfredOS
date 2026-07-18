"""GAP-2 shared property test for the fd-3-clobber spawn window (Spec B G6-5, #288).

The GAP-2 ruling COPIED the ~15-line synchronous fd-3 dup2 spawn window from
:func:`alfred.security.quarantine_child_io.spawn_quarantine_child_io` into
:meth:`alfred.gateway.adapter_child_factory.GatewayAdapterChildFactory._spawn_in_fd3_window`
(keeping the most-adversary-facing merged module + its per-file 100% gate untouched)
rather than factoring a shared helper. The anti-drift guard is THIS shared property
test: it drives BOTH spawn sites through one parametrized harness and asserts the
window's load-bearing invariants on each, so a future edit that breaks one window (and
not the other) is caught.

The invariants pinned for both windows:

* **NO ``await`` inside the window** — a "loop-driven sentinel" task is scheduled before
  the spawn; if the window drove the event loop (e.g. an ``await`` crept in around the
  synchronous ``Popen``), the sentinel would have run by the time ``Popen`` is called.
  We assert it had NOT run at spawn time. (The selector fd is commonly fd 3, so driving
  the loop while fd 3 is clobbered is the ``[Errno 22]`` regression the window prevents.)
* **the child inherits fd 3** — ``pass_fds == (3,)`` AND fd 3 is open at the instant the
  child forks (the dup'd read-end).
* **the parent fd 3 is restored** — a sentinel installed on fd 3 BEFORE the spawn is the
  SAME open file after the window closes.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import Callable
from typing import Any

import pytest

import alfred.gateway.adapter_child_factory as factory_mod
import alfred.security.quarantine_child_io as quarantine_mod
from alfred.security.quarantine_child._handshake import HELLO_FRAME, READY_FRAME


class _Stdio:
    """A synchronous pipe-shaped double: write/flush/read/readline/close.

    ``read`` optionally drains a caller-seeded ``frames`` buffer (raw-pipe
    semantics: at most ``n`` bytes per call, ``b""`` at EOF) so a real child's
    boot-handshake frames (#443) can be served; with no frames it stays the
    original always-empty stand-in. ``close`` stays real regardless of which —
    the gateway leg's ``GatewayAdapterStdioTransport.close`` calls ``.close()``
    on both stdin and stdout (rev-001), so a frames-bearing stdout must keep it.
    """

    def __init__(self, frames: list[bytes] | None = None) -> None:
        self.closed = False
        self._buf = bytearray(b"".join(frames)) if frames else bytearray()

    def write(self, _data: bytes) -> None: ...

    def flush(self) -> None: ...

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            chunk = bytes(self._buf)
            self._buf.clear()
            return chunk
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def readline(self) -> bytes:
        return b""

    def close(self) -> None:
        self.closed = True


class _SyncFakePopen:
    """A SYNCHRONOUS ``subprocess.Popen`` double — it never drives the event loop.

    Records the live state at fork time (fd 3 open?, pass_fds) so the property harness
    can assert the inheritance invariant for either spawn site.
    """

    last: _SyncFakePopen | None = None

    def __init__(self, argv: list[str], **kwargs: Any) -> None:
        self.argv = argv
        self.pass_fds = kwargs.get("pass_fds")
        self.fd3_open_at_fork = _fd_open(3)
        self.stdin = _Stdio()
        # Seeded so a future host-side handshake read (#443, Task 5) finds frames;
        # today neither spawn window reads stdout, so this sits unread (no-op).
        self.stdout = _Stdio([HELLO_FRAME, READY_FRAME])
        self.stderr = _Stdio()
        self.returncode: int | None = None
        type(self).last = self

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0


def _fd_open(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return False
    return True


class _SpawnObservation:
    """The cross-window observation a property assertion keys on."""

    def __init__(self) -> None:
        self.pass_fds: tuple[int, ...] | None = None
        self.fd3_open_at_fork: bool = False
        self.parent_fd3_restored: bool = False
        self.sentinel_ran_at_spawn: bool = False


async def _drive_quarantine_window(monkeypatch: pytest.MonkeyPatch) -> _SpawnObservation:
    """Drive the quarantine spawn window + capture the shared observation."""
    sentinel = {"ran": False}

    async def _sentinel_task() -> None:
        sentinel["ran"] = True

    # Schedule the sentinel BEFORE the window. If the window drives the loop, this runs.
    task = asyncio.ensure_future(_sentinel_task())

    obs = _SpawnObservation()
    captured: dict[str, Any] = {}

    def _fake_popen(argv: list[str], **kwargs: Any) -> _SyncFakePopen:
        captured["sentinel_at_spawn"] = sentinel["ran"]
        return _SyncFakePopen(argv, **kwargs)

    monkeypatch.setattr(quarantine_mod.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(quarantine_mod, "deliver_provider_key_via_fd3", lambda **_k: None)

    sentinel_r, sentinel_w = os.pipe()
    saved = os.dup(3) if _fd_open(3) else None
    try:
        os.dup2(sentinel_r, 3)
        stat_before = os.fstat(3)
        child_io = await quarantine_mod.spawn_quarantine_child_io(provider_key="k")
        stat_after = os.fstat(3)
        obs.parent_fd3_restored = (stat_after.st_dev, stat_after.st_ino) == (
            stat_before.st_dev,
            stat_before.st_ino,
        )
        proc = _SyncFakePopen.last
        assert proc is not None
        obs.pass_fds = proc.pass_fds
        obs.fd3_open_at_fork = proc.fd3_open_at_fork
        obs.sentinel_ran_at_spawn = bool(captured.get("sentinel_at_spawn"))
        await child_io.aclose()
    finally:
        if saved is not None:
            os.dup2(saved, 3)
            os.close(saved)
        else:
            with contextlib.suppress(OSError):
                os.close(3)
        for fd in (sentinel_r, sentinel_w):
            with contextlib.suppress(OSError):
                os.close(fd)
        await task
    return obs


async def _drive_factory_window(monkeypatch: pytest.MonkeyPatch) -> _SpawnObservation:
    """Drive the gateway-factory spawn window + capture the shared observation."""
    sentinel = {"ran": False}

    async def _sentinel_task() -> None:
        sentinel["ran"] = True

    task = asyncio.ensure_future(_sentinel_task())

    obs = _SpawnObservation()
    captured: dict[str, Any] = {}

    def _fake_popen(argv: list[str], **kwargs: Any) -> _SyncFakePopen:
        captured["sentinel_at_spawn"] = sentinel["ran"]
        return _SyncFakePopen(argv, **kwargs)

    runner_calls: dict[str, int] = {"n": 0}

    class _Runner:
        def __init__(self, **_k: Any) -> None: ...

        async def start_and_handshake(self) -> None:
            runner_calls["n"] += 1

    def _runner_factory(**_k: Any) -> _Runner:
        return _Runner()

    factory = factory_mod.GatewayAdapterChildFactory(
        runner_factory=_runner_factory,
        popen_factory=_fake_popen,  # type: ignore[arg-type]
    )

    async def _deliver(write_fd: int) -> None:
        os.close(write_fd)

    sentinel_r, sentinel_w = os.pipe()
    saved = os.dup(3) if _fd_open(3) else None
    try:
        os.dup2(sentinel_r, 3)
        stat_before = os.fstat(3)
        child = await factory.spawn_and_handshake(
            adapter_id="discord", epoch="e1", deliver_credential=_deliver
        )
        stat_after = os.fstat(3)
        obs.parent_fd3_restored = (stat_after.st_dev, stat_after.st_ino) == (
            stat_before.st_dev,
            stat_before.st_ino,
        )
        proc = _SyncFakePopen.last
        assert proc is not None
        obs.pass_fds = proc.pass_fds
        obs.fd3_open_at_fork = proc.fd3_open_at_fork
        obs.sentinel_ran_at_spawn = bool(captured.get("sentinel_at_spawn"))
        await child.aclose()
    finally:
        if saved is not None:
            os.dup2(saved, 3)
            os.close(saved)
        else:
            with contextlib.suppress(OSError):
                os.close(3)
        for fd in (sentinel_r, sentinel_w):
            with contextlib.suppress(OSError):
                os.close(fd)
        await task
    return obs


# The two spawn sites the COPIED window must keep identical (GAP-2 anti-drift).
_SPAWN_SITES: dict[str, Callable[[pytest.MonkeyPatch], Any]] = {
    "quarantine": _drive_quarantine_window,
    "gateway_adapter_factory": _drive_factory_window,
}


@pytest.fixture
def _reset_last_popen() -> None:
    _SyncFakePopen.last = None


@pytest.mark.parametrize("site", list(_SPAWN_SITES))
async def test_spawn_window_holds_the_fd3_invariants(
    site: str, monkeypatch: pytest.MonkeyPatch, _reset_last_popen: None
) -> None:
    """BOTH spawn windows: no await in-window, child inherits fd 3, parent fd 3 restored."""
    obs = await _SPAWN_SITES[site](monkeypatch)
    # No await inside the window: the sentinel scheduled before the spawn had NOT run by
    # the time ``Popen`` forked (driving the loop mid-window is the [Errno 22] footgun).
    assert obs.sentinel_ran_at_spawn is False, f"{site}: window drove the event loop"
    # The child inherits the dup'd read-end on LITERAL fd 3.
    assert obs.pass_fds == (3,), f"{site}: child does not inherit fd 3"
    assert obs.fd3_open_at_fork is True, f"{site}: fd 3 not open at fork"
    # The parent's prior fd 3 is restored once the window closes.
    assert obs.parent_fd3_restored is True, f"{site}: parent fd 3 not restored"
