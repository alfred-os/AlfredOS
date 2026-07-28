"""``CommsStdioTransport`` must drain its child's stderr for the child's LIFETIME (#520).

The transport spawns a LONG-LIVED comms adapter with ``stderr=PIPE`` and, until
#520, nothing ever read that pipe. The adapter logs to stderr for its whole life:
``plugins/alfred_discord/server.py`` calls ``configure_stderr_json_logging``, which
pins structlog to ``PrintLoggerFactory(file=sys.stderr)``
(``comms_mcp/plugin_logging.py``).

**The failure mode here is memory, not a hang** — and the distinction is what makes
these cases non-vacuous. ``asyncio.create_subprocess_exec`` installs a
``_UnixReadPipeTransport`` that *actively polls* the pipe into the ``StreamReader``
buffer whether or not anybody calls ``read()``, so the kernel pipe never fills and
the child never blocks. Measured, 20MB of child stderr attempted:

    asyncio limit=64KB   ->   214/20000 KB  STALLED
    asyncio limit=10MB   -> 20000/20000 KB  ok      <- this transport (10MB limit)
    raw Popen (gateway)  ->    64/20000 KB  STALLED <- the sibling site, hangs

The bytes do not vanish; they pile up in the parent:

    child wrote 20000KB to stderr; parent StreamReader buffer holds 20000KB

So the defect on THIS path is an unbounded memory leak in the daemon, growing 1:1
with everything the adapter ever logs and freed only when the adapter dies. A
"child must not stall" assertion would pass here with or without the drain — it is
decisive only for the raw-``Popen`` gateway site, which is covered separately.

The drain is NOT the exit-gated one-shot read used by the quarantine child
(``security/quarantine_child_io._log_child_stderr``, #251): that deliberately
returns early unless ``poll()`` shows the child has exited, which is right for a
short-lived extraction child and useless for an adapter that must keep running.

Real subprocesses (not a fake process object): kernel pipe buffering and asyncio
transport flow-control are precisely what is under test, and an in-memory
``StreamReader`` cannot exhibit either.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from alfred.cli._launcher_spawn import PluginLaunchSpec
from alfred.plugins.comms_stdio_transport import CommsStdioTransport

pytestmark = pytest.mark.asyncio

_STDERR_CHUNK_BYTES = 1024
_STDERR_CHUNKS = 4096  # 4MB — far past any pipe buffer, well inside the 10MB limit

# What "drained" means for this site: the parent is not still holding the child's
# whole output. Generous (the drain may legitimately hold a partial line or a small
# in-flight chunk) but orders of magnitude below the 4MB an undrained reader keeps.
_MAX_RETAINED_BYTES = 256 * 1024

_PROGRESS_DEADLINE_S = 30.0

_CHILD_SOURCE = f"""
import sys

for n in range(1, {_STDERR_CHUNKS} + 1):
    sys.stderr.write("x" * {_STDERR_CHUNK_BYTES - 1} + "\\n")
    sys.stderr.flush()
    sys.stdout.write(str(n) + "\\n")
    sys.stdout.flush()
"""


def _fake_launcher(tmp_path: Path) -> Path:
    """A stand-in launcher that ignores its argv and runs the chatty child.

    The real launcher execs ``<python> -m <module>`` and the transport passes it
    ``plugin_id python -m module``. Nothing here depends on that argv — these cases
    are about the stderr pipe, not the sandbox.
    """
    child = tmp_path / "chatty_child.py"
    child.write_text(_CHILD_SOURCE, encoding="utf-8")
    script = tmp_path / "fake-launcher.sh"
    script.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{child}"\n', encoding="utf-8")
    script.chmod(0o700)
    return script


def _spec() -> PluginLaunchSpec:
    return PluginLaunchSpec(
        plugin_id="alfred_comms_test",
        manifest_path=Path("/opt/alfred/manifest.toml"),
        module="alfred_comms_test.main",
        adapter_id="alfred_comms_test",
        import_roots=(Path("/opt/alfred/plugins"),),
        inherit_stdio=False,
        sandbox_kind="none",
    )


async def _read_all_stdout(transport: CommsStdioTransport) -> int:
    """Drive the child to EOF on stdout; return its highest progress counter."""
    proc = transport._proc
    assert proc is not None and proc.stdout is not None
    highest = 0
    while True:
        line = await proc.stdout.readline()
        if not line:
            return highest
        highest = int(line)


def _retained_stderr_bytes(transport: CommsStdioTransport) -> int:
    """Bytes of child stderr the parent is still holding in the reader buffer."""
    proc = transport._proc
    assert proc is not None
    if proc.stderr is None:  # the drain may detach the reader entirely
        return 0
    return len(proc.stderr._buffer)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: needs /bin/sh + pipe semantics")
async def test_child_stderr_is_not_accumulated_in_parent_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A chatty long-lived child must not grow the daemon's memory 1:1 with its logs.

    THE non-vacuous case for #520 on this path: with no drain the parent's
    ``StreamReader`` buffer ends up holding every byte the child ever wrote. It also
    fails if the drain is exit-gated like #251's, since the child is still alive
    while it floods.
    """
    monkeypatch.setenv("ALFRED_PLUGIN_LAUNCHER", str(_fake_launcher(tmp_path)))
    transport = CommsStdioTransport(adapter_id="alfred_comms_test", spec=_spec())
    await transport.spawn()
    try:
        highest = await asyncio.wait_for(_read_all_stdout(transport), timeout=_PROGRESS_DEADLINE_S)
        assert highest == _STDERR_CHUNKS, f"child stalled at {highest}/{_STDERR_CHUNKS}"

        # Let the drain catch up with the tail the child wrote just before exiting.
        await asyncio.sleep(0.5)
        retained = _retained_stderr_bytes(transport)
    finally:
        await transport.close()

    written = _STDERR_CHUNKS * _STDERR_CHUNK_BYTES
    assert retained <= _MAX_RETAINED_BYTES, (
        f"parent is holding {retained / 1024:.0f}KB of the {written / 1024:.0f}KB the "
        "child wrote to stderr — the pipe is being buffered, not drained"
    )
