"""Host-side launcher-spawned child-IO for the quarantined LLM (PR-S4-11c-2b, #237).

The SPAWN half of the :class:`alfred.security.quarantine_transport.ChildIO` seam
for a REAL bwrap-sandboxed quarantined-LLM child. This is PRECURSOR INFRA — it
ships ahead of any production caller (the daemon stays on the ADR-0027 fixture
extractor until the final 2b flip), mirroring 11c-1's ``build_orchestrator``. The
docker-only real-spawn proof drives it DIRECTLY.

* :class:`_SubprocessChildIO` frames the length-prefixed JSON-RPC wire over the
  launcher-spawned subprocess's stdio (peer to the child's
  ``alfred.security.quarantine_child.__main__`` loop). ``read_frame`` is BOUNDED
  (``asyncio.wait_for``) so a wedged child cannot hang the inbound turn.
* :func:`spawn_quarantine_child_io` execs ``bin/alfred-plugin-launcher.sh`` with
  ``sandbox.kind="full"`` (the launcher resolves the per-OS bwrap policy) and
  delivers the provider key over LITERAL fd 3 via
  :func:`alfred.supervisor.fd3_key_delivery.deliver_provider_key_via_fd3`.

**Wheel co-location + bound interpreter (PR-S4-11c-2b0, ADR-0030).** The child
ships IN the installed ``alfred`` wheel under ``alfred.security.quarantine_child``
and is spawned via ``python -m alfred.security.quarantine_child`` — so it lands at
``/usr/.../site-packages``, ALREADY covered by the bwrap policy's ``/usr`` ro-bind
(no policy widening). The exec target must be a REAL binary under a bound prefix:
production runs the daemon under the pip-installed ``/usr`` CPython
(``sys.executable`` resolves it; the ``/usr`` bind covers interpreter + packages);
dev/CI overrides via :data:`_CHILD_PYTHON_ENV` (``ALFRED_QUARANTINE_CHILD_PYTHON``)
to ``/usr/bin/python3`` and ``pip install -e .`` into it (a uv-venv
``sys.executable`` is a SYMLINK outside any bound path and won't exec under
bwrap). The scrubbed env no longer carries ``/repo`` PYTHONPATH roots — the child
resolves off the default site-packages path now that it ships in the wheel.

fd-3 delivery (ADR-0015 #218): bwrap inherits fd 3 by default — NO bwrap CLI
flag. The robust spawn pattern (verified in the fd3_key_delivery docstring + a
docker bwrap repro) is to dup the pipe READ-end onto LITERAL fd 3 in the PARENT
(``os.dup2(read_fd, 3)``, saving + restoring any prior parent fd 3) and pass
``pass_fds=(3,)`` — a ``preexec_fn`` that dups onto fd 3 does NOT work because
``subprocess`` runs ``close_fds`` AFTER ``preexec_fn`` and closes the dup'd fd 3
(not in ``pass_fds``) before exec. The child reads ``os.read(3)`` directly — NOT
an env-var-named fd — so this transport hard-codes fd 3 and does NOT reuse
:meth:`alfred.plugins.stdio_transport.StdioTransport._spawn` (which names the fd
via ``ALFRED_PROVIDER_KEY_FD``).

SYNCHRONOUS spawn — the fd-3-clobber window must contain ZERO ``await`` (#237,
docker real-spawn proof): ``os.dup2(read_fd, 3)`` clobbers fd 3 PROCESS-WIDE, and
the asyncio event loop's epoll/kqueue selector fd is commonly allocated at a low
number — often fd 3 itself. If we drove the loop while fd 3 was clobbered (e.g.
``await asyncio.create_subprocess_exec(...)``, which runs the loop to connect the
child pipes), the loop would poll its OWN dead selector → ``OSError: [Errno 22]
Invalid argument``. Nondeterministic: it passes by luck when fd 3 happens not to
be the selector fd, fails when it is. So the spawn uses a SYNCHRONOUS
``subprocess.Popen`` placed entirely inside the dup2→restore window — the child
still inherits the dup'd fd 3 at ``fork()`` via ``pass_fds=(3,)``, and fd 3 is
restored in the parent the instant ``Popen`` returns. The loop never runs while
fd 3 is clobbered. The child's raw ``Popen`` pipes are adapted to non-blocking
reads via :class:`_SubprocessChildIO` AFTER the window closes.

Fail-closed (CLAUDE.md hard rule #7): a ``ProviderKeyDeliveryError`` REFUSES the
spawn — the half-spawned child is terminated and a loud
:class:`QuarantineChildSpawnError` is raised, never a child running without its
key. The scrubbed allowlist env (never ``dict(os.environ)``) keeps an operator's
exported ``ANTHROPIC_API_KEY`` / ``DISCORD_BOT_TOKEN`` out of the adversary-facing
``kind="full"`` child; the provider key crosses ONLY over fd 3.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import IO

import structlog

from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.plugins._comms_child_env import _scrubbed_base
from alfred.supervisor.fd3_key_delivery import (
    ProviderKeyDeliveryError,
    deliver_provider_key_via_fd3,
)

_log = structlog.get_logger(__name__)

# The launcher plugin id (manifest ``[plugin] id``) + the ``python -m`` module the
# launcher execs. The module is the wheel-co-located child package (ADR-0030); the
# plugin id matches its ``manifest.toml`` ``[plugin] id`` so the launcher resolves
# the ``kind="full"`` sandbox policy.
_PLUGIN_ID = "alfred.quarantined-llm"
_CHILD_MODULE = "alfred.security.quarantine_child"

# Dev/CI override for the bwrap exec interpreter (ADR-0030 bound-interpreter
# contract). Production leaves it unset → ``sys.executable`` (the daemon runs
# under the pip-installed /usr CPython, covered by the policy's /usr ro-bind).
# Dev/CI points it at ``/usr/bin/python3`` (a real binary under /usr) with
# ``alfred`` pip-installed into that interpreter, because a uv-venv
# ``sys.executable`` is a SYMLINK outside any bound path and won't exec under
# bwrap.
_CHILD_PYTHON_ENV = "ALFRED_QUARANTINE_CHILD_PYTHON"

# The literal fd the provider key is delivered over (ADR-0015 #218). The child
# reads ``os.read(3)`` — this is a hard-coded convention, not an env-named fd.
_PROVIDER_KEY_FD = 3

# 4-byte big-endian length prefix — peer to the child loop's framing.
_LENGTH_HEADER_BYTES = 4

# Bounded ``read_frame`` deadline (seconds): a wedged child must fail loud rather
# than hang the inbound turn forever. Mirrors the #240 inbound-turn 15s bound.
_READ_FRAME_TIMEOUT_S = 15.0


class QuarantineChildSpawnError(AlfredError):
    """The quarantined-LLM child could not be spawned or seeded.

    A loud refusal on the dual-LLM spawn boundary (CLAUDE.md hard rule #7): a
    failed fd-3 key delivery, an OS spawn failure, or a truncated / wedged reply
    frame all surface here so the caller (``QuarantineStdioTransport`` /
    ``_refuse_boot``) refuses the turn rather than running a child without its
    key or silently mis-parsing a torn frame.
    """


def _repo_root() -> Path:
    """Resolve the in-tree repo root that ships ``bin/``.

    This module lives at ``src/alfred/security/`` so the repo root is four
    parents up. Mirrors :func:`alfred.cli._launcher_spawn.repo_root` (three
    parents from ``src/alfred/cli/``) shifted one level deeper. Used only for the
    default launcher path; the child code itself ships in the wheel now (ADR-0030)
    and needs no repo-relative import root.
    """
    return Path(__file__).resolve().parents[3]


def _launcher_path() -> str:
    return os.environ.get(
        "ALFRED_PLUGIN_LAUNCHER", str(_repo_root() / "bin" / "alfred-plugin-launcher.sh")
    )


def _child_python() -> str:
    """Resolve the bwrap exec interpreter (ADR-0030 bound-interpreter contract).

    Production: unset env → ``sys.executable`` (the daemon's /usr CPython, covered
    by the policy's /usr ro-bind). Dev/CI: ``ALFRED_QUARANTINE_CHILD_PYTHON`` →
    ``/usr/bin/python3`` (a real binary under a bound prefix, with ``alfred``
    pip-installed there). A uv-venv ``sys.executable`` is a symlink outside any
    bound path and would fail ``execvp`` under bwrap — hence the override.
    """
    return os.environ.get(_CHILD_PYTHON_ENV, sys.executable)


def _child_env() -> dict[str, str]:
    """Build the SCRUBBED child env (allowlist only — never ``dict(os.environ)``).

    The quarantined child is the most adversary-facing surface in the system; it
    gets the same scrubbed allowlist the daemon-hosted comms transport uses
    (:func:`alfred.plugins._comms_child_env._scrubbed_base`), plus the manifest
    path the launcher reads to resolve the ``kind="full"`` sandbox policy. NO
    secret-bearing key is on the allowlist — the provider key crosses ONLY over
    fd 3.

    PR-S4-11c-2b0 (ADR-0030): the ``/repo/plugins`` + ``/repo/src`` ``PYTHONPATH``
    roots the prior repo-root child needed are GONE — the child now ships in the
    wheel under ``alfred.security.quarantine_child`` and resolves off the bound
    interpreter's default site-packages path. Injecting ``/repo`` roots would also
    be pointless under bwrap (``/repo`` is not bound) and a needless surface.
    """
    env = _scrubbed_base()
    env["ALFRED_PLUGIN_MANIFEST_PATH"] = str(
        Path(__file__).resolve().parent / "quarantine_child" / "manifest.toml"
    )
    return env


class _TruncatedFrameError(Exception):
    """Internal: the child's stdout reached EOF mid-frame (a torn / crashed wire).

    Raised by :func:`_blocking_read_exactly` inside the executor thread and mapped
    by :meth:`_SubprocessChildIO.read_frame` to a loud
    :class:`QuarantineChildSpawnError`. Never surfaces a silent empty body
    (CLAUDE.md hard rule #7). Peer to ``asyncio.IncompleteReadError`` on the old
    StreamReader path.
    """


def _blocking_read_exactly(stream: IO[bytes], count: int) -> bytes:
    """Read exactly ``count`` bytes from a raw pipe, looping over short reads.

    Runs in an executor thread (off the event loop) so a slow / wedged child does
    NOT block the loop. A short read that reaches EOF before ``count`` bytes are in
    hand raises :class:`_TruncatedFrameError` — the loud-on-truncated-EOF contract
    the old ``StreamReader.readexactly`` provided.
    """
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            raise _TruncatedFrameError
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class _SubprocessChildIO:
    """Frames the length-prefixed JSON-RPC wire over a launcher-spawned child.

    Satisfies :class:`alfred.security.quarantine_transport.ChildIO`: ``write_frame``
    ships one already-framed request onto the child's stdin; ``read_frame`` reads
    one full length-prefixed reply frame (4-byte header + body) under a bounded
    deadline (the transport's ``_decode_result_payload`` strips the header);
    ``aclose`` terminates + reaps the child idempotently.

    Wraps a synchronous :class:`subprocess.Popen` (the spawn-window fix, #237) — NOT
    an ``asyncio.subprocess.Process``. ``write_frame`` writes to the raw
    ``Popen.stdin`` pipe and flushes; ``read_frame`` does the blocking pipe read in
    an executor thread so a wedged child never blocks the event loop, bounded by
    ``asyncio.wait_for``.
    """

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._closed = False

    def write_frame(self, frame: bytes) -> None:
        """Ship one already-framed length-prefixed request onto child stdin."""
        if self._process.stdin is None:  # pragma: no cover - defensive; stdin is PIPE
            raise QuarantineChildSpawnError(t("security.quarantine_child.stdin_unavailable"))
        self._process.stdin.write(frame)
        self._process.stdin.flush()

    async def read_frame(self) -> bytes:
        """Read one full length-prefixed reply frame (4-byte header + body), bounded.

        A truncated / EOF reply (the child crashed or the wire tore) and a
        deadline overrun (a wedged child) both raise
        :class:`QuarantineChildSpawnError` — never a silent empty body (CLAUDE.md
        hard rule #7). The bound is :data:`_READ_FRAME_TIMEOUT_S`.

        The blocking pipe reads run in the default executor so the event loop is
        never blocked on a slow child — the loop polls its OWN selector freely
        while the read awaits (the spawn-window discipline this module exists to
        protect applies AFTER the dup2 window has long closed).
        """
        if self._process.stdout is None:  # pragma: no cover - defensive; stdout is PIPE
            raise QuarantineChildSpawnError(t("security.quarantine_child.stdout_unavailable"))
        stdout = self._process.stdout
        loop = asyncio.get_running_loop()
        try:
            header = await asyncio.wait_for(
                loop.run_in_executor(None, _blocking_read_exactly, stdout, _LENGTH_HEADER_BYTES),
                timeout=_READ_FRAME_TIMEOUT_S,
            )
            length = struct.unpack(">I", header)[0]
            body = await asyncio.wait_for(
                loop.run_in_executor(None, _blocking_read_exactly, stdout, length),
                timeout=_READ_FRAME_TIMEOUT_S,
            )
            # Return the WHOLE frame (4-byte header + body). The ChildIO contract
            # is that QuarantineStdioTransport's `_decode_result_payload` strips the
            # header — the in-test `_EchoingChildDouble` returns header+body too, so
            # returning body-only here mis-aligned the real wire vs the double (the
            # decoder chopped the first 4 JSON bytes -> JSONDecodeError). #237.
            return header + body
        except (TimeoutError, _TruncatedFrameError) as exc:
            _log.error(
                "security.quarantine_child.read_frame_failed", error_class=type(exc).__name__
            )
            raise QuarantineChildSpawnError(
                t("security.quarantine_child.read_frame_failed")
            ) from exc

    async def aclose(self) -> None:
        """Terminate + reap the child (idempotent)."""
        if self._closed:
            return
        self._closed = True
        await _terminate_and_reap(self._process)


async def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    """SIGTERM the child and await its exit off-loop (best-effort, never raises)."""
    if process.returncode is None and process.poll() is None:
        with contextlib.suppress(ProcessLookupError, OSError):
            process.terminate()
    # ``Popen.wait`` blocks — reap in an executor so the loop is not blocked.
    loop = asyncio.get_running_loop()
    with contextlib.suppress(Exception):
        await loop.run_in_executor(None, process.wait)


async def spawn_quarantine_child_io(*, provider_key: str) -> _SubprocessChildIO:
    """Spawn the bwrap-sandboxed quarantined-LLM child + deliver its key over fd 3.

    The robust spawn pattern (ADR-0015 #218 + the fd3_key_delivery docstring):

    1. ``os.pipe()`` — the read-end becomes the child's fd 3, the write-end stays
       in the parent for the key delivery.
    2. ``os.dup2(read_fd, 3)`` in the PARENT (saving + restoring any prior parent
       fd 3) so the inherited fd lands on the LITERAL fd 3 the child reads, then
       ``pass_fds=(3,)`` so ``subprocess``'s ``close_fds`` keeps it open across
       exec. (A ``preexec_fn`` dup does NOT survive ``close_fds``.)
    3. SYNCHRONOUSLY ``subprocess.Popen`` ``bin/alfred-plugin-launcher.sh
       <plugin_id> <python> -m <module>`` — NOT ``await
       asyncio.create_subprocess_exec``. The dup2 of step 2 clobbers fd 3
       PROCESS-WIDE, and the event loop's selector fd is commonly fd 3; driving the
       loop (which an ``await`` here would) while fd 3 is clobbered polls the loop's
       OWN dead selector → ``OSError: [Errno 22]`` (the docker real-spawn
       regression). ``Popen`` ``fork``s synchronously WITHOUT touching the loop, the
       child inherits the dup'd fd 3 at fork, and fd 3 is restored in the parent the
       instant ``Popen`` returns — the loop never polls a clobbered selector. The
       launcher resolves the ``kind="full"`` bwrap policy and execs bwrap, which
       inherits fd 3 by default. ``<python>`` is the bound interpreter
       (:func:`_child_python`); ``<module>`` is the wheel-co-located
       :data:`_CHILD_MODULE` (ADR-0030).
    4. :func:`deliver_provider_key_via_fd3` writes ``[len|key]`` over the write-end
       in one atomic ``writev`` (it closes the write-end itself, on success AND
       refusal).

    A :class:`ProviderKeyDeliveryError` (partial write / EAGAIN / OSError) or an OS
    spawn failure REFUSES the spawn: the half-spawned child is terminated and a
    loud :class:`QuarantineChildSpawnError` is raised (CLAUDE.md hard rule #7).
    """
    read_fd, write_fd = os.pipe()
    os.set_inheritable(read_fd, True)  # noqa: FBT003 - os.set_inheritable bool is positional only

    # Save any prior parent fd 3 so a clobber is reversible, then dup the pipe
    # read-end onto LITERAL fd 3.
    saved_fd3: int | None = None
    with contextlib.suppress(OSError):
        saved_fd3 = os.dup(_PROVIDER_KEY_FD)
    process: subprocess.Popen[bytes] | None = None
    try:
        # --- fd-3-clobber window OPENS. NO ``await`` until it CLOSES below. ---
        os.dup2(read_fd, _PROVIDER_KEY_FD)
        argv = [
            _launcher_path(),
            _PLUGIN_ID,
            _child_python(),
            "-m",
            _CHILD_MODULE,
        ]
        try:
            # SYNCHRONOUS spawn (no ``await``): ``Popen`` forks the child without
            # running the event loop, so the loop never polls its (temporarily
            # clobbered) selector fd. The child inherits the dup'd fd 3 at fork via
            # ``pass_fds``; ``close_fds`` defaults to True and keeps every other
            # inherited fd out of the adversary-facing child.
            process = subprocess.Popen(  # noqa: S603 - argv is module-internal, not user input
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_child_env(),
                pass_fds=(_PROVIDER_KEY_FD,),
            )
        except OSError as exc:
            _log.error("security.quarantine_child.spawn_failed", error_class=type(exc).__name__)
            raise QuarantineChildSpawnError(t("security.quarantine_child.spawn_failed")) from exc
    finally:
        # --- fd-3-clobber window CLOSES (no ``await`` ran above). ---
        # Restore the parent's prior fd 3 (or close the dup we installed) and drop
        # the parent's copy of the read-end — the child has its own via pass_fds.
        if saved_fd3 is not None:
            os.dup2(saved_fd3, _PROVIDER_KEY_FD)
            os.close(saved_fd3)
        else:
            with contextlib.suppress(OSError):
                os.close(_PROVIDER_KEY_FD)
        with contextlib.suppress(OSError):
            os.close(read_fd)

    # Deliver the provider key over the pipe write-end (it closes write_fd itself).
    try:
        deliver_provider_key_via_fd3(write_fd=write_fd, key=provider_key)
    except ProviderKeyDeliveryError as exc:
        _log.error("security.quarantine_child.provider_key_delivery_failed", reason=exc.reason)
        await _terminate_and_reap(process)
        raise QuarantineChildSpawnError(
            t("security.quarantine_child.provider_key_delivery_failed")
        ) from exc

    return _SubprocessChildIO(process)


__all__ = [
    "QuarantineChildSpawnError",
    "spawn_quarantine_child_io",
]
