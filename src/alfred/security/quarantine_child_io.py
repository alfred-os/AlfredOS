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

**Opt-in control-fd plumbing (#340 PR2a, ADR-0050 dormancy invariant).**
:func:`spawn_quarantine_child_io` grows a ``control_fd: bool = False`` parameter:
when set, a SECOND fd — literal fd 4, peer to ``_PROVIDER_KEY_FD = 3`` — carries
one end of an ``AF_UNIX`` socketpair (:func:`alfred.egress.control_fd_broker.
make_control_socketpair`) into the child, so the empty-netns quarantine child can
later receive a pre-connected gateway socket over SCM_RIGHTS
(:func:`alfred.egress.control_fd_broker.broker_connected_socket`, called from the
parent side via :meth:`_SubprocessChildIO.broker_socket`). Both fd-3 and fd-4
dup2s share the SAME synchronous zero-``await`` window described above — a
second clobbered-selector hazard would exist for fd 4 exactly as for fd 3 if it
were installed outside that window. The default is ``False`` and the live/echo
spawn (the daemon's only caller today) never passes ``control_fd=True`` — this
is PRECURSOR INFRA, dormant until PR2b's go-live cutover (ADR-0050): the
default-off spawn is BEHAVIOURALLY unchanged (``pass_fds=(3,)`` only, no
socketpair construction, no second dup2). The one added syscall on the live
path — a ``os.set_inheritable(3, True)`` after the fd-3 ``dup2`` — is a
provable no-op: ``os.dup2`` already leaves its target inheritable, so the
child inherits exactly what it did before.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import IO

import structlog

from alfred.egress import control_fd_broker
from alfred.egress._config_protocols import EgressProxyConfig
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

# The literal fd the pre-connected gateway socket is brokered over (#340 PR2a,
# ADR-0050), peer to _PROVIDER_KEY_FD = 3. Only installed when the caller opts
# in via ``control_fd=True`` — the default-off live/echo spawn never touches it.
_CONTROL_FD = 4

# The wheel-co-located diagnostic probe entry the docker C1/C2 test (Task 4)
# drives directly. Inert in production — never referenced by any live caller.
_BROKERED_PROBE_MODULE = "alfred.security.quarantine_child._brokered_probe"

# child_module is a CLOSED SET, never a free string — a free module would be a
# spawn-arbitrary-module hole (the child inherits fd 3 [+ fd 4 when control_fd
# is set]). Only the real child or the docker probe may be spawned.
_ALLOWED_CHILD_MODULES: frozenset[str] = frozenset({_CHILD_MODULE, _BROKERED_PROBE_MODULE})

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
    by the policy's /usr ro-bind). Dev/CI: ``ALFRED_QUARANTINE_CHILD_PYTHON`` → a
    real interpreter binary that may live OUTSIDE the static /usr binds (the #248 CI
    gate uses a hermetic ``proto``-managed 3.14 under ``~/.proto`` with ``alfred``
    installed into it); the launcher binds that interpreter's install prefix into the
    sandbox via the opt-in ``ALFRED_SANDBOX_BIND_INTERP_PREFIX`` flag ``_child_env``
    sets (ADR-0030). A uv-venv ``sys.executable`` is a symlink outside any bound path
    and would fail ``execvp`` under bwrap — hence the override + prefix bind.
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
    # Opt in to the launcher's interpreter-prefix bind (CR #250, ADR-0030): the
    # quarantine child execs a bound interpreter (``_child_python``) that may live
    # OUTSIDE the policy's static /usr binds (a proto/uv python under ~/.proto), so
    # the launcher must ro-bind its install prefix into the sandbox. This flag
    # scopes that bind to THIS spawn — generic kind:full plugins (run under a /usr
    # interpreter the policy already binds) never set it, so the launcher never
    # widens their namespace.
    env["ALFRED_SANDBOX_BIND_INTERP_PREFIX"] = "1"
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

    ``broker_socket`` is a CONCRETE method here only — NOT part of the
    :class:`alfred.security.quarantine_transport.ChildIO` Protocol in PR2a (that
    widening is deferred to PR2b, when ``QuarantineStdioTransport.dispatch``
    actually calls it; widening now would break the existing ``ChildIO`` test
    doubles under pyright for no live benefit). ``control_parent`` is ``None``
    unless the spawn opted into ``control_fd=True`` (#340 PR2a, ADR-0050); when
    present, this instance OWNS it (CR-#255 single-teardown seam) — closed by
    ``aclose`` or by the spawn's own failure-handling arcs, never both.
    """

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        control_parent: socket.socket | None = None,
        egress_config: EgressProxyConfig | None = None,
    ) -> None:
        self._process = process
        self._closed = False
        self._control_parent = control_parent
        self._egress_config = egress_config

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

    async def broker_socket(self) -> None:
        """Broker one connected gateway socket to the child (#340 PR2a: docker probe only).

        Delegates to :func:`alfred.egress.control_fd_broker.broker_connected_socket`
        over the owned parent control-end. A fail-loud refusal (CLAUDE.md hard rule
        #7, not pragma'd out — this IS a security branch) when the instance was
        never given a control-end or a proxy config: the caller opted OUT of
        ``control_fd`` at spawn time, or (defensively) constructed this instance
        directly without one.
        """
        if self._control_parent is None or self._egress_config is None:
            raise QuarantineChildSpawnError(t("security.quarantine_child.broker_unconfigured"))
        await control_fd_broker.broker_connected_socket(
            parent_end=self._control_parent, proxy_config=self._egress_config
        )

    async def aclose(self) -> None:
        """Terminate + reap the child (idempotent); close the owned control-end, if any."""
        if self._closed:
            return
        self._closed = True
        await _terminate_and_reap(self._process)
        if self._control_parent is not None:
            with contextlib.suppress(OSError):
                self._control_parent.close()


async def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    """SIGTERM the child and await its exit off-loop (best-effort, never raises)."""
    if process.returncode is None and process.poll() is None:
        with contextlib.suppress(ProcessLookupError, OSError):
            process.terminate()
    # ``Popen.wait`` blocks — reap in an executor so the loop is not blocked.
    loop = asyncio.get_running_loop()
    with contextlib.suppress(Exception):
        await loop.run_in_executor(None, process.wait)


async def spawn_quarantine_child_io(
    *,
    provider_key: str,
    control_fd: bool = False,
    child_module: str = _CHILD_MODULE,
    egress_config: EgressProxyConfig | None = None,
) -> _SubprocessChildIO:
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

    **Opt-in control-fd (#340 PR2a, ADR-0050 dormancy invariant).** When
    ``control_fd=True`` (default ``False`` — the live/echo spawn never sets it), a
    second AF_UNIX socketpair (:func:`make_control_socketpair`) is built; the
    child-end is dup'd onto literal fd 4 in the SAME synchronous zero-``await``
    window as the fd-3 dance above (a second clobbered-selector hazard would exist
    for fd 4 exactly as for fd 3 otherwise); the parent-end is kept and handed to
    the returned :class:`_SubprocessChildIO` for a later
    :meth:`_SubprocessChildIO.broker_socket` call. ``control_fd=True`` REQUIRES an
    ``egress_config`` — a misconfigured opt-in refuses loudly rather than silently
    spawning without a broker.

    Both a pipe read-end and a socketpair child-end normally land on some fd well
    above the ``(3, 4)`` target range (the kernel picks the lowest FREE fd; the
    dormant spawn ambiently keeps 3 and 4 occupied). If a source ever DID land on
    a target — a source fd is lifted above the whole target range FIRST, before
    ANY prior occupant is saved or ANY dup2 runs — so neither the save-of-a-prior-
    occupant nor a dup2-onto-a-target can alias a source we still need to read
    from. Each source is then closed EXACTLY ONCE: the lifted alias always (it is
    the parent's now-redundant copy after ``pass_fds`` hands the target to the
    child), and the pre-lift original ADDITIONALLY only if it was actually moved
    (otherwise the original IS the alias — closing both would double-close).

    ``child_module`` is validated against the closed :data:`_ALLOWED_CHILD_MODULES`
    set before anything is opened: a free module string would let a caller spawn
    an arbitrary module with fd 3 [+ fd 4] inherited — a capability-widening hole.

    A :class:`ProviderKeyDeliveryError` (partial write / EAGAIN / OSError) or an OS
    spawn failure REFUSES the spawn: the half-spawned child is terminated, any
    owned control-parent socket is closed (no fd leak on the refusal path), and a
    loud :class:`QuarantineChildSpawnError` is raised (CLAUDE.md hard rule #7).
    """
    if child_module not in _ALLOWED_CHILD_MODULES:
        raise QuarantineChildSpawnError(t("security.quarantine_child.child_module_not_allowed"))
    if control_fd and egress_config is None:
        raise QuarantineChildSpawnError(t("security.quarantine_child.broker_unconfigured"))

    read_fd, write_fd = os.pipe()
    os.set_inheritable(read_fd, True)  # noqa: FBT003 - os.set_inheritable bool is positional only

    control_parent: socket.socket | None = None
    control_child_fd: int | None = None
    if control_fd:
        control_parent, control_child = control_fd_broker.make_control_socketpair()
        # Detach to a raw fd int for the dup2 dance below (core-001: the parent
        # never holds a live Python socket object pointed at the CHILD's end).
        control_child_fd = control_child.detach()

    literal_targets: tuple[int, ...] = (
        (_PROVIDER_KEY_FD, _CONTROL_FD) if control_fd else (_PROVIDER_KEY_FD,)
    )

    def _lift_above_targets(fd: int) -> tuple[int, bool]:
        """Return ``(usable_fd, moved)``. Dup ``fd`` above the target range if it collides.

        Looping (not a single dup) covers the pathological case where the FIRST
        dup also lands on the (other) target — practically never with real fds,
        but the loop keeps the invariant "the returned fd is never one of
        ``literal_targets``" true unconditionally rather than by construction.
        """
        moved = False
        while fd in literal_targets:
            fd = os.dup(fd)
            moved = True
        return fd, moved

    read_src, read_moved = _lift_above_targets(read_fd)
    control_src, control_moved = (
        _lift_above_targets(control_child_fd) if control_child_fd is not None else (None, False)
    )

    # Save any prior occupant of each target so a clobber is reversible. Sources
    # were lifted above the range above, so this loop can only ever capture a
    # PRIOR occupant — never alias a source we still need.
    saved: dict[int, int] = {}
    for fd in literal_targets:
        with contextlib.suppress(OSError):
            saved[fd] = os.dup(fd)

    process: subprocess.Popen[bytes] | None = None
    try:
        # --- fd-clobber window OPENS. NO ``await`` until it CLOSES below (#237; now
        # BOTH fd 3 and fd 4 are clobbered process-wide when control_fd is set — the
        # await-free discipline still protects the loop selector for both). ---
        os.dup2(read_src, _PROVIDER_KEY_FD)
        os.set_inheritable(_PROVIDER_KEY_FD, True)  # noqa: FBT003
        if control_src is not None:
            os.dup2(control_src, _CONTROL_FD)
            os.set_inheritable(_CONTROL_FD, True)  # noqa: FBT003
        argv = [_launcher_path(), _PLUGIN_ID, _child_python(), "-m", child_module]
        try:
            # SYNCHRONOUS spawn (no ``await``): ``Popen`` forks the child without
            # running the event loop, so the loop never polls its (temporarily
            # clobbered) selector fd. The child inherits the dup'd fd(s) at fork via
            # ``pass_fds``; ``close_fds`` defaults to True and keeps every other
            # inherited fd out of the adversary-facing child.
            process = subprocess.Popen(  # noqa: S603 - argv is module-internal, not user input
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_child_env(),
                pass_fds=literal_targets,
            )
        except OSError as exc:
            _log.error("security.quarantine_child.spawn_failed", error_class=type(exc).__name__)
            # A failed Popen skips ``deliver_provider_key_via_fd3`` (which is what
            # otherwise closes ``write_fd``), so BOTH parent-owned fds must be closed
            # here or repeated spawn failures leak one pipe write-end + one control
            # socket per attempt (the ``finally`` below only reclaims ``read_fd`` and
            # the fd-dance sources). ``read_fd`` falls to the ``finally``.
            with contextlib.suppress(OSError):
                os.close(write_fd)
            if control_parent is not None:
                with contextlib.suppress(OSError):
                    control_parent.close()
            raise QuarantineChildSpawnError(t("security.quarantine_child.spawn_failed")) from exc
    finally:
        # --- fd-clobber window CLOSES (no ``await`` ran above). ---
        # Restore each target's prior occupant (or clear the target we installed).
        for fd in literal_targets:
            if fd in saved:
                os.dup2(saved[fd], fd)
                os.close(saved[fd])
            else:
                with contextlib.suppress(OSError):
                    os.close(fd)
        # Close each source EXACTLY ONCE: the lifted alias always (the parent's
        # copy is redundant once ``pass_fds`` hands the target to the child), and
        # the pre-lift original ADDITIONALLY only if a lift actually happened
        # (otherwise the original IS the alias — closing both would double-close).
        for original, src, moved in (
            (read_fd, read_src, read_moved),
            (control_child_fd, control_src, control_moved),
        ):
            if src is None:
                continue
            with contextlib.suppress(OSError):
                os.close(src)
            # ``moved`` is only ever True when ``original`` was a real fd (the
            # control-side entry pairs ``None`` with ``moved=False`` always) — the
            # ``original is not None`` guard is for mypy's benefit, not a real
            # runtime possibility.
            if moved and original is not None:
                with contextlib.suppress(OSError):
                    os.close(original)

    # Deliver the provider key over the pipe write-end (it closes write_fd itself).
    try:
        deliver_provider_key_via_fd3(write_fd=write_fd, key=provider_key)
    except ProviderKeyDeliveryError as exc:
        _log.error("security.quarantine_child.provider_key_delivery_failed", reason=exc.reason)
        await _terminate_and_reap(process)
        if control_parent is not None:
            with contextlib.suppress(OSError):
                control_parent.close()
        raise QuarantineChildSpawnError(
            t("security.quarantine_child.provider_key_delivery_failed")
        ) from exc

    return _SubprocessChildIO(process, control_parent=control_parent, egress_config=egress_config)


__all__ = [
    "QuarantineChildSpawnError",
    "spawn_quarantine_child_io",
]
