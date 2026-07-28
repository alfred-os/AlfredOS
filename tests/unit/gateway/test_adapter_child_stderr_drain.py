"""The gateway adapter child's stderr must be drained, or the child WEDGES (#520).

``GatewayAdapterChildFactory`` spawns its child with a synchronous
:class:`subprocess.Popen` — deliberately, because the fd-3-clobber window must not
run the event loop. That choice has a consequence the asyncio sibling does not
share: **nothing polls the pipe.** With ``stderr=PIPE`` and no reader, the 64KB
kernel buffer fills and the child blocks in ``write()`` forever — no crash, no
error, no exit. Measured on this repo before the fix, 20MB attempted:

    asyncio limit=10MB (comms)   -> 20000/20000 KB  ok
    raw Popen        (gateway)   ->    64/20000 KB  STALLED

So unlike the comms site — where the defect is unbounded parent memory and a
stall assertion would be vacuous — a stall assertion is exactly right here.

These cases drive the pump against the real ``Popen`` shape rather than the whole
factory: ``spawn_and_handshake`` needs a credential leg, a runner and a handshake,
none of which bear on whether the pipe is drained.
"""

from __future__ import annotations

import subprocess
import sys
import threading

import pytest

from alfred.security.child_stderr import ChildStderrPump

_CHUNK_BYTES = 1024
_CHUNKS = 4096  # 4MB — 64x the 64KB kernel pipe buffer

_CHILD_SOURCE = f"""
import sys

for n in range(1, {_CHUNKS} + 1):
    sys.stderr.write("x" * {_CHUNK_BYTES - 1} + "\\n")
    sys.stderr.flush()
    sys.stdout.write(str(n) + "\\n")
    sys.stdout.flush()
"""

_DEADLINE_S = 30.0


def _spawn_chatty_child() -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed argv, no shell, test-local source
        [sys.executable, "-c", _CHILD_SOURCE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _drive_stdout(process: subprocess.Popen[bytes]) -> int:
    """Read the child's progress counter to EOF on a thread; return the highest seen."""
    seen = {"n": 0}

    def _read() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            seen["n"] = int(line)

    thread = threading.Thread(target=_read, daemon=True)
    thread.start()
    thread.join(timeout=_DEADLINE_S)
    return seen["n"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: needs pipe-buffer semantics")
def test_undrained_popen_stderr_wedges_the_child() -> None:
    """Pins the MECHANISM the pump exists for — the bug is real, not theoretical.

    Without this, the fix below could pass against a child that never filled a pipe
    in the first place, and the drain would be untested in the only way that counts.
    """
    process = _spawn_chatty_child()
    try:
        highest = _drive_stdout(process)
    finally:
        process.kill()
        process.wait()

    assert highest < _CHUNKS, (
        f"expected the undrained child to stall, but it reached {highest}/{_CHUNKS} — "
        "the pipe buffer no longer bounds this platform, so the case below proves nothing"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: needs pipe-buffer semantics")
def test_pump_keeps_a_chatty_popen_child_running_to_completion() -> None:
    """THE non-vacuous case: with the drain attached the same child finishes."""
    process = _spawn_chatty_child()
    pump = ChildStderrPump(plugin_id="alfred.discord", event="gateway.adapter.child_stderr")
    assert process.stderr is not None
    pump.start_blocking(process.stderr)
    try:
        highest = _drive_stdout(process)
    finally:
        process.kill()
        process.wait()

    assert highest == _CHUNKS, (
        f"child stalled at {highest}/{_CHUNKS} (~{highest * _CHUNK_BYTES // 1024}KB of "
        "stderr) despite the drain — its stderr pipe is still filling"
    )
