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
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import IO, TYPE_CHECKING

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

if TYPE_CHECKING:
    from alfred.security.sandbox_refusal_audit import SandboxRefusalRecorder

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
# than hang the inbound turn forever. MUST be >= the child's wall-clock budget
# (``provider_dispatch._MAX_TOTAL_WALL_CLOCK_SECONDS``) so a real extraction is not torn
# host-side, and < the orchestrator action_deadline (P1e, #340 — see
# test_quarantine_timeout_hierarchy). Raised from the original #240 15s (which sat BELOW
# the child budget) to give a real extraction framing headroom.
_READ_FRAME_TIMEOUT_S = 25.0

# Bounded best-effort drain of the quarantined child's stderr (#251). The child is
# spawned with ``stderr=PIPE``; on a failed/torn ``read_frame`` or on ``aclose`` the
# host reads up to this many bytes — ONLY once the child has exited (so the drain
# can never block on a wedged child) — and surfaces a SANITIZED single-line
# ``child_stderr`` field through the structured logger. Never a raw inherit: the
# quarantined child is the most adversary-facing surface, so its stderr is
# de-fanged (control chars stripped -> no forged log lines / terminal escapes) and
# masked by the bootstrap structlog leaf-redactor before it reaches a renderer.
_STDERR_LOG_CAP_BYTES = 4096
_STDERR_TRUNCATION_MARKER = " …[truncated]"

# Independent bound on the stderr-drain read (#251). The drain only runs once the
# child has EXITED, so under the shipped kind="full" bwrap policy (PID-namespace
# reaping — no grandchild outlives the child holding the write-end) the pipe read
# returns promptly. This deadline is defence-in-depth: it does NOT rest that
# liveness on the sandbox policy staying unchanged — a read that fails to return
# (e.g. a future policy drops --unshare-pid and a reparented grandchild keeps the
# write-end open) trips the bound and is caught as a best-effort ``stderr_drain_failed``
# rather than hanging ``aclose`` forever. Short (the child is already dead).
_STDERR_DRAIN_TIMEOUT_S = 2.0

# Unicode categories stripped from child stderr before it becomes a log field.
# ``Cc`` (C0/C1 controls) defeats forged log lines + ANSI terminal escapes; ``Cf``
# (format chars — bidi overrides U+202E, directional isolates U+2066-2069,
# zero-width U+200B / BOM U+FEFF) defeats "Trojan Source" bidi display-spoofing, a
# control-char-free attack the child (the most adversary-facing surface) could
# otherwise smuggle into an operator's terminal rendering of the log line. Stripping
# all of ``Cf`` also drops benign joiners (ZWJ/ZWNJ/soft-hyphen) — safety over
# fidelity is the right call for a hardened diagnostic field (not operator copy).
_STRIPPED_UNICODE_CATEGORIES: frozenset[str] = frozenset({"Cc", "Cf"})


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

    ``bytes_read`` carries how many bytes were consumed before EOF. It is
    security-load-bearing (sec-001): ANY byte on stdout means the child exec'd and
    wrote — so a mid-frame EOF with ``bytes_read > 0`` is a CHILD-authored torn
    wire, NOT a pre-``exec`` launcher refusal (which produces zero stdout). The
    ``read_frame`` drain gate uses this to refuse to attribute a child's stderr to
    the T0 launcher (closes the first-turn header-then-fail forgery bypass).
    """

    def __init__(self, bytes_read: int = 0) -> None:
        super().__init__()
        self.bytes_read = bytes_read


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
            # Report how many bytes DID arrive before EOF (sec-001): a non-zero
            # partial read means the child wrote to stdout, so its stderr is
            # child-authored, not a launcher refusal.
            raise _TruncatedFrameError(bytes_read=count - remaining)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_stderr_bytes(process: subprocess.Popen[bytes], cap: int) -> bytes:
    """Read up to ``cap`` bytes of the child's stderr. Caller guarantees exited.

    A pure blocking reader for ``loop.run_in_executor`` (off-loop, same posture as
    ``_blocking_read_exactly``). The child has already exited (the async caller's
    ``poll()`` gate), so its stderr write-end is closed and the read cannot block.
    Returns ``b""`` when there is no stderr pipe (defensive) or nothing was
    buffered. ``cap`` is positional so the caller needs no ``functools.partial``.
    """
    stderr = process.stderr
    if stderr is None:
        return b""
    chunks: list[bytes] = []
    remaining = cap
    while remaining > 0:
        chunk = stderr.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _sanitize_child_stderr(raw: bytes, *, cap: int, truncated: bool = False) -> str | None:
    """De-fang child stderr into a single-line structured-log field (or ``None``).

    The quarantined child is the most adversary-facing surface: its stderr may
    carry attacker-influenced bytes (newlines that forge log lines, ANSI escapes
    that manipulate an operator's terminal, bidi overrides that display-spoof the
    line, other C0/C1 control or format chars). Every char in a stripped Unicode
    category (:data:`_STRIPPED_UNICODE_CATEGORIES` — ``Cc`` C0/C1 controls incl.
    ``\\n \\r \\t \\x1b`` / DEL, and ``Cf`` format chars incl. bidi overrides /
    zero-width) is replaced with a space; whitespace runs are collapsed and the
    result stripped, so the field is single-line-searchable and injection-proof
    under BOTH the JSON and console renderers. Returns ``None`` when nothing
    printable remains (no empty-field noise). Secret-shape masking is handled
    DOWNSTREAM by the bootstrap structlog leaf-redactor once this lands as a log
    field.

    The ``…[truncated]`` marker is appended when the sanitized text exceeds ``cap``
    chars OR when ``truncated`` is set — the caller passes ``truncated=True`` when
    the RAW read hit its byte cap (more stderr existed than was read). The explicit
    flag is load-bearing for multi-byte UTF-8: a byte-capped read can decode to
    FEWER than ``cap`` chars, so ``len(collapsed) > cap`` alone would silently drop
    the marker even though bytes were clipped. Marker beats a mid-collapse cap.
    """
    text = raw.decode("utf-8", errors="replace")
    despaced = "".join(
        " " if unicodedata.category(ch) in _STRIPPED_UNICODE_CATEGORIES else ch for ch in text
    )
    collapsed = " ".join(despaced.split())
    if not collapsed:
        return None
    if truncated or len(collapsed) > cap:
        return collapsed[:cap] + _STDERR_TRUNCATION_MARKER
    return collapsed


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
        refusal_recorder: SandboxRefusalRecorder | None = None,
    ) -> None:
        self._process = process
        self._closed = False
        self._stderr_drained = False
        # Set the instant ANY byte is read off the child's stdout (see
        # ``read_frame``). sec-001/arch-001 (#433 follow-up): this is the
        # launcher-authored/child-authored discriminator for ``_log_child_stderr``
        # -- a refused launcher exits pre-``exec`` and NEVER writes to stdout, so a
        # ``read_frame`` EOF with this flag still False is the genuine refusal
        # signal. The moment the child writes even a partial header the child is
        # live and exec'd (the most adversary-facing surface), so any ``read_frame``
        # failure from then on is a crash/wedge of THAT child and its stderr must
        # never be turned into an attributed audit row. Keying on the FIRST stdout
        # byte (not a full frame) closes the first-turn forgery bypass CR flagged:
        # a child that writes a valid header then fails the body read on frame one.
        self._child_wrote_stdout = False
        # Set iff a drain read TIMED OUT: the executor thread is still blocked in the
        # real ``stderr.read()`` (holding the BufferedReader lock), so ``aclose`` must
        # NOT close that pipe out from under it (the close would re-block). Only
        # reachable if the write-end is held open past child exit (a broken bwrap
        # PID-namespace assumption) — unreachable under the shipped kind="full" policy.
        self._stderr_reader_orphaned = False
        self._control_parent = control_parent
        self._egress_config = egress_config
        self._refusal_recorder = refusal_recorder

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
            # The child wrote a full header -> it exec'd and produced stdout, so from
            # here on its stderr is child-authored, never a launcher refusal (sec-001).
            self._child_wrote_stdout = True
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
            # A PARTIAL read (some stdout bytes arrived before EOF) also proves the
            # child wrote to stdout -> child-authored (sec-001). Set BEFORE the drain
            # below reads the flag, so a header-then-fail (or partial-header-then-EOF)
            # first frame can never be attributed to the T0 launcher.
            if isinstance(exc, _TruncatedFrameError) and exc.bytes_read > 0:
                self._child_wrote_stdout = True
            # Only a ZERO-byte EOF is a launcher-refusal candidate (CR follow-up). A
            # TimeoutError is inherently a CHILD-side event -- a refused launcher exits
            # pre-``exec`` and closes stdout immediately (EOF, never a wall-clock
            # timeout), and on a timeout the executor read is still in flight so no
            # ``bytes_read`` evidence exists; attributing it to the T0 launcher would let
            # a child that stalls a partial header to the deadline then exits forge a row.
            refusal_candidate = isinstance(exc, _TruncatedFrameError) and exc.bytes_read == 0
            _log.error(
                "security.quarantine_child.read_frame_failed", error_class=type(exc).__name__
            )
            # failure=True -> the child_stderr diagnostic logs at ERROR, alongside the
            # read_frame_failed error it explains (visible to error-level alerting).
            await self._log_child_stderr(failure=True, refusal_candidate=refusal_candidate)
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

    async def _log_child_stderr(
        self, *, failure: bool = False, refusal_candidate: bool = False
    ) -> None:
        """Drain (iff the child has exited) + structured-log its stderr, at most once.

        Exit-gated, idempotent, AND best-effort-never-raises (#251). Order matters:

        1. Already drained -> return (the pipe is consumed; nothing to re-read).
        2. Child NOT exited (``poll() is None``) -> return WITHOUT setting the flag.
           Draining a live child could block on a wedged process; the ``read_frame``
           arm hits this on the timeout/wedged path and ``aclose`` retries after
           ``_terminate_and_reap`` guarantees exit.
        3. Child exited -> SET the flag (before the read, so a read failure is not
           retried), read off-loop under a bounded deadline, and emit
           ``security.quarantine_child.child_stderr`` ONLY when there is printable
           content (no empty-field noise on the happy teardown).

        ``failure`` selects the ``child_stderr`` severity: the ``read_frame``
        failure arm passes ``failure=True`` -> logged at ``error`` so an operator
        alerting at error-level sees the diagnostic ALONGSIDE the
        ``read_frame_failed`` error it explains; ``aclose`` uses the default
        ``warning`` (a clean teardown that merely had leftover stderr is not itself
        an error).

        **Never raises** — a diagnostic-drain failure (an ``OSError`` reading the
        pipe, a ``TimeoutError`` on the bounded read, or a structlog-emit failure)
        must NOT preempt the caller's contracted :class:`QuarantineChildSpawnError`
        (CLAUDE.md hard rule #7; spec §6), nor skip ``aclose``'s fd cleanup. Every
        failure past the exit gate — INCLUDING the fallback log emit itself — is
        caught and surfaced LOUDLY as a ``stderr_drain_failed`` warning carrying an
        explicit ``error_class`` field (never a silent swallow). The primary error
        the caller is about to ``raise`` is left untouched.

        ``poll()`` is a non-blocking ``waitpid(WNOHANG)`` — it actively detects a
        just-exited child (so the common EOF-after-exit case surfaces at the
        ``read_frame`` arm without a prior ``wait``); after ``_terminate_and_reap``
        it short-circuits on the cached ``returncode``.
        """
        if self._stderr_drained:
            return
        try:
            if self._process.poll() is None:  # still running — do NOT set the flag
                return
            self._stderr_drained = True  # set before the read: a read failure won't retry
            loop = asyncio.get_running_loop()
            # Read ONE byte past the log cap: ``truncated`` (below) then detects a
            # byte-overflow EXPLICITLY, so the ``…[truncated]`` marker fires even for
            # multi-byte stderr that decodes to <= cap chars (a char-length check
            # alone would silently drop the marker). Bounded by
            # ``_STDERR_DRAIN_TIMEOUT_S`` so a write-end held open past child exit (a
            # broken PID-namespace assumption) trips the deadline instead of hanging
            # ``aclose`` forever — the timeout lands in the ``except`` below.
            raw = await asyncio.wait_for(
                loop.run_in_executor(
                    None, _read_stderr_bytes, self._process, _STDERR_LOG_CAP_BYTES + 1
                ),
                timeout=_STDERR_DRAIN_TIMEOUT_S,
            )
            if not raw:
                return
            # Record BEFORE the best-effort diagnostic log (CR-major-1: a structlog emit
            # failure below must not skip the audit persistence — the whole point of #433).
            # Gate to the LAUNCHER-authored signal (sec-001/arch-001): only a genuine
            # pre-exec refusal surfaces as a read_frame ZERO-byte EOF (``refusal_candidate``)
            # with the child having produced NO stdout across its life
            # (``not self._child_wrote_stdout``). A TimeoutError (``refusal_candidate`` is
            # False) or any stdout byte -- full/partial header, or the aclose teardown path
            # -- is CHILD-authored: its stderr must NOT become an attributed supervisor
            # audit row. Residual: a child that execs, writes zero stdout, then dies at a
            # clean EOF emitting a forged row is indistinguishable here and defers to the
            # boot-time probe (ADR-0051 option A, #443) -- far narrower than "any crash".
            if refusal_candidate and not self._child_wrote_stdout:
                await self._record_launcher_refusals(raw)
            truncated = len(raw) > _STDERR_LOG_CAP_BYTES
            sanitized = _sanitize_child_stderr(raw, cap=_STDERR_LOG_CAP_BYTES, truncated=truncated)
            if sanitized is not None:
                log = _log.error if failure else _log.warning
                log("security.quarantine_child.child_stderr", child_stderr=sanitized)
        except Exception as exc:
            # Best-effort diagnostic: NEVER preempt the caller's QuarantineChildSpawnError
            # (hard rule #7). Fail LOUD via an explicit ``error_class`` field — NOT
            # ``exc_info`` (the bootstrap structlog chain has no traceback renderer, so
            # ``exc_info`` emits nothing); mirrors the ``read_frame_failed`` handler.
            # The fallback log is itself ``suppress``-wrapped so a structlog-emit failure
            # cannot escape to preempt the primary error or skip ``aclose``'s fd cleanup.
            # CANARY FORWARD GATE: once a canary-raising log processor is wired into the
            # shared redactor (dlp.OutboundCanaryTripped; canary=None today), a canary
            # token in child stderr would raise HERE — this ``except`` MUST then
            # special-case + escalate it rather than demote it to stderr_drain_failed.
            if isinstance(exc, TimeoutError):
                # The read deadline fired but the executor thread is STILL reading the
                # real pipe (holding its lock) — flag it so ``aclose`` skips the
                # ``stderr.close()`` that would otherwise re-block on that lock.
                self._stderr_reader_orphaned = True
            with contextlib.suppress(Exception):
                _log.warning(
                    "security.quarantine_child.stderr_drain_failed",
                    error_class=type(exc).__name__,
                )

    async def _record_launcher_refusals(self, raw: bytes) -> None:
        """Parse launcher refusal rows from raw stderr + record them. Never raises.

        Called ONLY from the ``_log_child_stderr`` gate ``if refusal_candidate and
        not self._child_wrote_stdout`` (sec-001/arch-001, #433 follow-up).
        ``refusal_candidate`` is a ZERO-byte ``_TruncatedFrameError`` — a clean EOF
        at offset zero — which is how a refused launcher presents: it exits
        pre-``exec``, writing ZERO stdout bytes and closing the pipe at once. A
        ``TimeoutError`` is never a candidate (a refusal does not stall to the
        deadline, and a timed-out read carries no byte evidence). A crashed/wedged
        EXEC'd child (it wrote any stdout — a full or even partial header — or this
        is the ``aclose`` teardown path) is CHILD-authored — the caller does not
        reach this method on those paths, so a malicious child cannot forge a
        ``sandbox_refused`` line into an attributed audit row (closing both the
        first-turn header-then-fail and the timeout-attribution bypasses).

        Fully self-guarding (CLAUDE.md hard rule #7): an
        ``append_schema`` / ``invoke`` failure is logged LOUD with an explicit
        ``error_class`` and swallowed, so it neither preempts the
        ``read_frame_failed`` ``QuarantineChildSpawnError`` nor breaks
        ``_log_child_stderr``'s best-effort "never raises" contract.

        CANARY FORWARD GATE (mirrors the sibling ``except`` in
        ``_log_child_stderr`` at ~line 559-562): once a canary-raising log
        processor is wired into the shared redactor
        (``dlp.OutboundCanaryTripped``; canary=None today), a canary token
        surfacing via ``parse_launcher_refusal_rows`` or the recorder's
        ``append_schema``/``invoke`` call would raise HERE — the ``except``
        below MUST then special-case + escalate it rather than demote it to
        ``refusal_record_failed``.
        """
        if self._refusal_recorder is None:
            return
        try:
            from alfred.audit.launcher_refusal import parse_launcher_refusal_rows

            rows = parse_launcher_refusal_rows(raw)
            if rows:
                await self._refusal_recorder.record(rows)
        except Exception as exc:
            _log.error(
                "security.quarantine_child.refusal_record_failed",
                error_class=type(exc).__name__,
            )

    async def aclose(self) -> None:
        """Terminate+reap the child; drain+log its stderr; close pipe/control-end.

        Idempotent. Once ``_terminate_and_reap`` returns (best-effort SIGTERM +
        off-loop reap), ``_log_child_stderr`` drains the stderr the ``read_frame``
        arm skipped on a wedged/timeout child (#251) — its own ``poll()`` gate still
        guards the read, so a not-yet-exited child is simply skipped, never blocked
        on. The stderr pipe fd is then closed (it is the pipe this IO owns
        end-to-end and the only one never read/closed before — stdin/stdout are left
        to ``Popen`` GC to avoid racing an orphaned ``read_frame`` executor thread
        still reading stdout). The close is SKIPPED when a drain read timed out
        (``_stderr_reader_orphaned``): its executor thread is still holding the
        ``BufferedReader`` lock, so closing here would re-block — that pipe is left to
        ``Popen`` GC too (unreachable under the shipped kind="full" PID-namespace
        policy, which closes the write-end on child exit).
        """
        if self._closed:
            return
        self._closed = True
        await _terminate_and_reap(self._process)
        await self._log_child_stderr()
        stderr = self._process.stderr
        if stderr is not None and not self._stderr_reader_orphaned:
            with contextlib.suppress(OSError):
                stderr.close()
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
    try:
        await loop.run_in_executor(None, process.wait)
    except Exception as exc:
        # Best-effort teardown (never raises), but LOUD not silent (#414, hard
        # rule #7): a reap gone wrong surfaces its error class instead of
        # vanishing. ``except Exception`` (not ``BaseException``) so cooperative
        # cancellation still propagates; the emit is ``suppress``-wrapped so a
        # structlog-emit failure during teardown cannot escape either. Mirrors
        # the ``stderr_drain_failed`` / ``read_frame_failed`` idiom.
        with contextlib.suppress(Exception):
            _log.warning("security.quarantine_child.reap_failed", error_class=type(exc).__name__)


def _lift_above_targets(
    fd: int,
    literal_targets: tuple[int, ...],
    *,
    dup: Callable[[int], int] | None = None,
    close: Callable[[int], None] | None = None,
) -> tuple[int, bool]:
    """Return ``(usable_fd, moved)``. Dup ``fd`` above the target range if it collides.

    Looping (not a single dup) keeps the invariant "the returned fd is never one of
    ``literal_targets``" true unconditionally rather than by construction. Each
    intermediate dup THIS function created is closed before the next iteration (P1d,
    #340): only the caller's ORIGINAL survives to the spawn cleanup loop (closed there
    under ``moved``). Without this in-loop close a >=2-iteration lift (a source landing on
    the OTHER target) orphans the first intermediate fd.

    ``dup``/``close`` are injectable so the >=2-iteration branch is unit-testable without a
    real ``dup2``-onto-3/4 (which would clobber the pytest runner). They default to
    ``None`` — NOT ``os.dup``/``os.close`` directly — so the module-level ``os.dup`` is
    resolved at CALL time (a def-time default would capture the real syscall and bypass the
    spawn suite's ``monkeypatch.setattr(os, "dup", ...)``).
    """
    _dup = dup if dup is not None else os.dup
    _close = close if close is not None else os.close
    moved = False
    while fd in literal_targets:
        new_fd = _dup(fd)
        if moved:
            # ``fd`` is an intermediate WE created last iteration (not the caller's
            # original) — close it so it isn't orphaned. The spawn cleanup loop closes the
            # original under ``moved=True``; closing it here would double-close.
            _close(fd)
        fd = new_fd
        moved = True
    return fd, moved


async def spawn_quarantine_child_io(
    *,
    provider_key: str,
    control_fd: bool = False,
    child_module: str = _CHILD_MODULE,
    egress_config: EgressProxyConfig | None = None,
    refusal_recorder: SandboxRefusalRecorder | None = None,
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

    read_src, read_moved = _lift_above_targets(read_fd, literal_targets)
    control_src, control_moved = (
        _lift_above_targets(control_child_fd, literal_targets)
        if control_child_fd is not None
        else (None, False)
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

    return _SubprocessChildIO(
        process,
        control_parent=control_parent,
        egress_config=egress_config,
        refusal_recorder=refusal_recorder,
    )


__all__ = [
    "QuarantineChildSpawnError",
    "spawn_quarantine_child_io",
]
