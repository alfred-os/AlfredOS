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
later receive pre-connected gateway sockets over SCM_RIGHTS
(:func:`alfred.egress.control_fd_broker.broker_connected_sockets`, called from the
parent side via :meth:`_SubprocessChildIO.broker_sockets`). Both fd-3 and fd-4
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
# ADR-0050), peer to _PROVIDER_KEY_FD = 3. Installed only when the caller opts in
# via ``control_fd=True``. Since #340 PR2b-golive the LIVE daemon spawn DOES opt
# in — this fd is the real-LLM child's sole reachability. The ``control_fd=False``
# default now serves the dormant/unit spawns, not the live one.
_CONTROL_FD = 4

# The wheel-co-located diagnostic probe entry the docker C1/C2 test (Task 4)
# drives directly. Inert in production — never referenced by any live caller.
_BROKERED_PROBE_MODULE = "alfred.security.quarantine_child._brokered_probe"

# The system CA bundle the go-live quarantine child verifies TLS against (#340
# PR2b-golive, spike-verified Debian/Ubuntu base-image location). Delivered to the
# empty-netns child via ``SSL_CERT_FILE`` in the scrubbed env (the child has no
# config bind); its brokered-egress transport terminates TLS against this store
# (HARD #5 — TLS terminates INSIDE the quarantine child, never at a shared proxy).
_DEFAULT_SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt"

# child_module is a CLOSED SET, never a free string — a free module would be a
# spawn-arbitrary-module hole (the child inherits fd 3 [+ fd 4 when control_fd
# is set]). Only the real child or the docker probe may be spawned.
_ALLOWED_CHILD_MODULES: frozenset[str] = frozenset({_CHILD_MODULE, _BROKERED_PROBE_MODULE})

# Modules whose child emits a `ready` frame after the `hello` (the real quarantine
# child builds a provider + asyncio streams, then signals liveness). The diagnostic
# probe is DELIBERATELY excluded: it is parent-speaks-first on fd 4, so a second
# handshake read would deadlock (spec §6.1). The `hello` read is UNCONDITIONAL for
# every allowed module, so every returned instance has proven exec.
_MODULES_EMITTING_READY: frozenset[str] = frozenset({_CHILD_MODULE})

# Modules whose child READS the golive provider config out of its spawn env
# (``ALFRED_QUARANTINE_MODEL`` / ``ALFRED_QUARANTINE_MAX_TOKENS``). Only the real child does:
# ``_build_provider`` indexes both, and ``_run_mcp_server`` re-reads the budget per extract.
# The diagnostic probe reads neither, so requiring the config for a probe spawn would be a
# guard that refuses a correct call. Keeps the A6 symmetry guard precise rather than blanket.
_MODULES_REQUIRING_PROVIDER_CONFIG: frozenset[str] = frozenset({_CHILD_MODULE})

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

# Grace windows for the two-stage reap in ``_terminate_and_reap``. The child is a T3
# process whose exit is a REVOCATION, so the teardown must be bounded: the caller
# (``_revoke_child_capability`` -> ``_refuse_broker``) still has to write the
# ``egress.broker.refused`` row afterwards, inside the outer ``action_deadline``.
#
# Both windows are deliberately short. A healthy child exits on SIGTERM in microseconds;
# 1s is ~6 orders of magnitude of headroom, and anything slower is already a wedged child
# we would rather kill than wait for. Total worst case is therefore ~2s, which leaves the
# refusal path's remaining budget for the audit write it exists to produce.
_REAP_SIGTERM_GRACE_S = 1.0
_REAP_SIGKILL_GRACE_S = 1.0
_REAP_TOTAL_GRACE_S = _REAP_SIGTERM_GRACE_S + _REAP_SIGKILL_GRACE_S

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


def _child_env(
    *,
    model: str | None = None,
    max_tokens: int | None = None,
    ssl_cert_file: str | None = None,
) -> dict[str, str]:
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

    **#340 PR2b-golive provider config (ADR-0050 Decision 8).** The LIVE
    (``control_fd=True``) spawn threads the real-LLM child's non-secret, non-T3
    provider config in here — ``model`` -> ``ALFRED_QUARANTINE_MODEL``,
    ``max_tokens`` -> ``ALFRED_QUARANTINE_MAX_TOKENS``, ``ssl_cert_file`` ->
    ``SSL_CERT_FILE`` (the child has no config bind). These are set via EXPLICIT
    host-passed ``env[key] = value`` assignments — the AST scrub guard
    (``test_comms_child_env_ast_scrub``) forbids ``dict(os.environ)``, not explicit
    assignment of a caller value. Each key is set ONLY when its argument is
    provided, so a DORMANT/echo (``control_fd=False``) spawn — which passes none —
    yields the pre-golive env BYTE-FOR-BYTE (the ADR-0050 dormancy invariant;
    ``test_child_env_live_is_dormant_plus_exactly_the_three_keys``).
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
    # Golive provider config — added ONLY on the live path (each arg non-``None``),
    # so the dormant spawn's env is byte-identical to before (see docstring).
    if model is not None:
        env["ALFRED_QUARANTINE_MODEL"] = model
    if max_tokens is not None:
        env["ALFRED_QUARANTINE_MAX_TOKENS"] = str(max_tokens)
    if ssl_cert_file is not None:
        env["SSL_CERT_FILE"] = ssl_cert_file
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

    ``broker_sockets`` satisfies the widened
    :class:`alfred.security.quarantine_transport.ChildIO` Protocol (#340 golive
    Task 9, when ``QuarantineStdioTransport.dispatch`` brokers the batch before
    writing the extract frame). ``control_parent`` is ``None``
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

    async def broker_sockets(self, count: int) -> list[tuple[str, int]]:
        """Broker ``count`` connected gateway sockets to the child (connect-defer, §6).

        Delegates to :func:`alfred.egress.control_fd_broker.broker_connected_sockets`
        over the owned parent control-end: it connects all ``count`` first and sends
        them only if every connect succeeded, so a partial CONNECT failure sends the
        child NOTHING (nothing to reclaim) and raises :class:`ControlFdBrokerError` —
        caught one layer up by :meth:`QuarantineStdioTransport.dispatch`, which records
        the egress-failure row + converts to a typed refusal. That "sends NOTHING"
        guarantee covers the CONNECT phase ONLY: a SEND-phase failure leaves fds already
        queued in the child, which ``dispatch`` handles by REVOKING the child when
        ``ControlFdBrokerError.delivered > 0``. This method is auditor-FREE:
        the transport owns the ``EgressBrokerAuditor`` and writes the success/failure
        rows (cleaner than threading an auditor through the child-IO seam). Returns the
        ``(host, port)`` destinations so the transport can attribute one success row per
        brokered target.

        A fail-loud refusal (CLAUDE.md hard rule #7, not pragma'd out — this IS a
        security branch) when the instance was never given a control-end or a proxy
        config: the caller opted OUT of ``control_fd`` at spawn time, or (defensively)
        constructed this instance directly without one.
        """
        if self._control_parent is None or self._egress_config is None:
            raise QuarantineChildSpawnError(t("security.quarantine_child.broker_unconfigured"))
        return await control_fd_broker.broker_connected_sockets(
            parent_end=self._control_parent, proxy_config=self._egress_config, count=count
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
            # clean EOF emitting a forged row is indistinguishable HERE -- but the #443
            # two-frame boot handshake (``_await_boot_handshake``, read inside
            # ``spawn_quarantine_child_io``) now forces a real child to emit an unsolicited
            # ``hello`` at boot BEFORE it could forge such a row, so a genuine exec'd child
            # always sets ``_child_wrote_stdout`` first and this gate only ever fires on a
            # true pre-exec launcher EOF. The one surviving sliver is the §8.4 EPIPE race
            # (a child killed after exec but before its hello flush) -- far narrower still.
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

    async def _record_provider_key_delivery_failure(self) -> None:
        """Persist the reserved ``provider_key_delivery_failed`` row (#444). Never raises.

        Called from ``_record_fast_launcher_refusal``'s ``poll() is None`` branch — a
        genuine fd-3 delivery failure with the child STILL UP (partial writev / EAGAIN),
        NOT a fast launcher refusal (which has EXITED -> the sec-001 stderr-parse path).
        The row is HOST-authored: every field is a trusted host constant carrying NO
        T3-derived value, so the canary-forward gate guarding ``_record_launcher_refusals``
        does not apply here.

        Fully self-guarding (CLAUDE.md hard rule #7): an ``append_schema`` / ``invoke``
        failure is logged LOUD with an explicit ``error_class`` and swallowed, so it
        never preempts the delivery-failure ``QuarantineChildSpawnError`` the caller
        re-raises.
        """
        if self._refusal_recorder is None:
            return
        try:
            await self._refusal_recorder.record_provider_key_delivery_failure(plugin_id=_PLUGIN_ID)
        except Exception as exc:
            _log.error(
                "security.quarantine_child.provider_key_delivery_audit_failed",
                error_class=type(exc).__name__,
                plugin_id=_PLUGIN_ID,
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
        self._close_control_end()

    def _close_control_end(self) -> None:
        """Close the brokered control-parent socket, suppressing a benign ``OSError``.

        Shared by :meth:`aclose` and :meth:`abort` (DRY — the control end is closed on both
        the graceful and the last-resort teardown). ``OSError`` is suppressed because a
        double-close / already-closed fd is not a failure worth propagating out of teardown.
        """
        if self._control_parent is not None:
            with contextlib.suppress(OSError):
                self._control_parent.close()

    def abort(self) -> None:
        """SIGKILL the child + close the control end. SYNCHRONOUS: never awaits, never raises.

        The cancellation-safe half of :meth:`aclose` (#472 finding 2). ``aclose`` is the
        graceful teardown (SIGTERM -> SIGKILL -> reap -> stderr drain -> fd close) and EVERY
        stage awaits, so a cancel delivered mid-teardown aborts it partway. This revokes the
        capability with the one operation the kernel guarantees and that cannot be caught,
        blocked or ignored — usable from inside a ``CancelledError`` handler where every
        ``await`` would immediately re-raise.

        **What SIGKILL to ``self._process`` actually tears down.** ``self._process`` is the
        host-side bwrap **monitor** (the launcher ``exec``s bwrap, ``bin/alfred-plugin-
        launcher.sh``). Under the shipped kind="full" policy that bwrap runs with BOTH
        ``--unshare-pid`` AND ``--die-with-parent`` (``sandbox_policy.py``;
        ``config/sandbox/quarantined-llm.linux.bwrap.policy``). SIGKILLing the monitor
        triggers ``--die-with-parent`` on the sandboxed child, which is PID 1 of the
        ``--unshare-pid`` namespace — and killing PID 1 of a PID namespace tears down the
        whole namespace, python child included. Same pid :func:`_terminate_and_reap` signals.

        Never raises: ``Popen.kill()`` is wrapped in ``suppress(ProcessLookupError, OSError)``
        (an already-exited or already-reaped child is a no-op, not a failure) and the control
        close is likewise suppressed. A genuine same-user kill cannot ``EPERM``, so the
        suppressed set is effectively "already dead" — an accepted, documented residual rather
        than a hidden failure (there is no post-kill re-verification here, unlike
        :func:`_terminate_and_reap`'s reap check; the caller's `capability_abort_failed`
        guard covers a seam that is malformed rather than merely already-dead).

        Does NOT reap. ``aclose`` sets ``_closed`` BEFORE tearing down and every caller of
        this method is reached after ``aclose`` was entered, so a later ``aclose`` early-
        returns without reaping. Usually harmless: the SIGKILL releases the ``waitpid`` that
        :func:`_reap_within` left an executor thread parked on, and that thread reaps the
        child. A zombie survives only in the narrow case where no such thread was ever parked
        (the cancel landed before :func:`_reap_within` submitted its first ``waitpid``
        executor) — it holds no fds, no memory and no capability, only a process-table entry
        the OS reaps at daemon exit.

        Residual, accepted: a ``send()`` already queued in the kernel on an established socket
        can still complete — a microsecond window against "alive indefinitely".
        """
        with contextlib.suppress(ProcessLookupError, OSError):
            self._process.kill()
        self._close_control_end()


async def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    """SIGTERM, then SIGKILL, the child and await its exit off-loop (best-effort, never raises).

    BOUNDED, because this is the fail-closed teardown. It was SIGTERM-only with an
    unbounded ``process.wait()``: a T3 child that simply declines SIGTERM wedged the
    caller forever. Two things then broke at once — dispatch blew past the outer
    ``action_deadline``, AND ``record_broker_failure`` never ran, so the very failure that
    triggered the teardown produced NO ``egress.broker.refused`` row. A revocation path
    that can hang is not a revocation path.

    SIGKILL is the escalation the kernel guarantees: it cannot be caught, blocked or
    ignored, so the only way past the second grace window is an uninterruptible (D-state)
    child, which is logged loud and left to the OS.
    """
    loop = asyncio.get_running_loop()
    if process.returncode is None and process.poll() is None:
        with contextlib.suppress(ProcessLookupError, OSError):
            process.terminate()
    if await _reap_within(loop, process, _REAP_SIGTERM_GRACE_S):
        return
    # SIGTERM ignored. Escalate — loudly, because a quarantine child declining the polite
    # signal is security-relevant, not routine teardown noise.
    with contextlib.suppress(Exception):
        _log.warning(
            "security.quarantine_child.reap_escalated_sigkill",
            sigterm_grace_s=_REAP_SIGTERM_GRACE_S,
        )
    with contextlib.suppress(ProcessLookupError, OSError):
        process.kill()
    if await _reap_within(loop, process, _REAP_SIGKILL_GRACE_S):
        return
    with contextlib.suppress(Exception):
        _log.error(
            "security.quarantine_child.reap_unreaped",
            total_grace_s=_REAP_TOTAL_GRACE_S,
        )


async def _reap_within(
    loop: asyncio.AbstractEventLoop, process: subprocess.Popen[bytes], grace_s: float
) -> bool:
    """Await the child's exit for at most ``grace_s``. ``True`` == reaped.

    ``Popen.wait`` blocks, so it runs in an executor. Cancelling the ``wait_for`` does NOT
    unblock that thread — it stays parked on ``waitpid`` until the process actually dies,
    which is precisely what the SIGKILL escalation then guarantees. Concurrent ``wait()``
    calls across the two attempts are safe: CPython serialises them on ``_waitpid_lock``.
    """
    try:
        await asyncio.wait_for(loop.run_in_executor(None, process.wait), timeout=grace_s)
    except TimeoutError:
        return False
    except Exception as exc:
        # Best-effort teardown (never raises), but LOUD not silent (#414, hard
        # rule #7): a reap gone wrong surfaces its error class instead of
        # vanishing. ``except Exception`` (not ``BaseException``) so cooperative
        # cancellation still propagates; the emit is ``suppress``-wrapped so a
        # structlog-emit failure during teardown cannot escape either. Mirrors
        # the ``stderr_drain_failed`` / ``read_frame_failed`` idiom.
        with contextlib.suppress(Exception):
            _log.warning("security.quarantine_child.reap_failed", error_class=type(exc).__name__)
        return True  # errored, not hung — escalating a SIGKILL would not help
    return True


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


async def _await_boot_handshake(child_io: _SubprocessChildIO, *, child_module: str) -> None:
    """Read the child's boot frames INSIDE the spawn; refuse boot if any is missing (#443).

    Every allowed child emits an unsolicited ``hello`` frame before it builds its
    provider — proof it exec'd (provenance; the read sets ``_child_wrote_stdout``). The
    real quarantine child ADDITIONALLY emits a ``ready`` frame before its request loop —
    proof it initialized and is serving (liveness). The diagnostic probe emits ONLY a
    hello (``_MODULES_EMITTING_READY`` excludes it — a second read would deadlock, §6.1).
    The hello read is UNCONDITIONAL, so every returned instance has proven exec — the
    invariant the launcher-vs-child audit gate rests on.

    A missing frame surfaces as a ``read_frame`` failure -> ``QuarantineChildSpawnError``,
    which the boot caller maps to ``_refuse_boot`` (fail-closed, hard rule #7).
    ``read_frame``'s own failure arm records the launcher-authored ``sandbox_refused``
    row + dispatches the ``fail_closed`` T0 hookpoint iff the failure is a zero-byte EOF
    with no prior stdout byte (the sec-001 gate) — so a GENUINE launcher refusal now
    persists its row + fires the hookpoint HERE, at boot, instead of at first extraction
    (the dispatch PR1 made boot-declarable).

    Teardown is unconditional on EVERY abnormal exit (``except BaseException``): the
    contracted ``QuarantineChildSpawnError``, a ``CancelledError`` from a daemon boot
    cancelled mid-handshake, or any unexpected exception ``read_frame`` might propagate all
    tear the half-spawned child down (``aclose``: terminate+reap, close the control-parent)
    before the error re-raises — a narrower ``except QuarantineChildSpawnError`` would leak
    the bwrap child + control socket on a ``CancelledError`` (which is a ``BaseException``,
    not an ``Exception``). The loud ``boot_handshake_failed`` log stays scoped to the
    contract exception — a cancellation is not a security event. The stderr drain already
    ran inside ``read_frame`` on the contract path, so ``aclose``'s own drain is an
    idempotent no-op there; on a cancellation the drain simply runs once in ``aclose``.
    """
    try:
        await child_io.read_frame()  # hello: provenance — sets _child_wrote_stdout
        if child_module in _MODULES_EMITTING_READY:
            await child_io.read_frame()  # ready: liveness
    except BaseException as exc:
        if isinstance(exc, QuarantineChildSpawnError):
            _log.error("security.quarantine_child.boot_handshake_failed", child_module=child_module)
        await child_io.aclose()
        raise


async def _record_fast_launcher_refusal(child_io: _SubprocessChildIO) -> None:
    """Drain + record a GENUINE fast launcher refusal on the fd-3 EPIPE arm (#443 §8.4).

    A *fast* launcher refusal exits the launcher PRE-``exec`` — closing its inherited fd-3
    read end before the parent's SYNCHRONOUS ``writev`` — so ``deliver_provider_key_via_fd3``
    raises ``ProviderKeyDeliveryError`` (EPIPE) before this instance is normally constructed,
    and the launcher's ``sandbox_refused`` row sits unread in ``process.stderr``. Drive ONE
    ``read_frame`` so the SAME sec-001 gate the handshake uses records that row: a genuine
    refusal presents as a zero-byte stdout EOF (``refusal_candidate`` and
    ``not _child_wrote_stdout``), its stderr is launcher-authored, and the drain persists the
    attributed row + fires the ``fail_closed`` T0 hookpoint. When the launcher's stderr carries
    no parseable ``sandbox_refused`` row (a genuine non-refusal delivery failure — #444's
    domain), the parser yields nothing and this adds no row.

    **Only drain a launcher that has ALREADY EXITED** (CR-2). ``ProviderKeyDeliveryError``
    covers more than EPIPE: a partial ``writev`` / EAGAIN / other ``OSError`` (see
    ``fd3_key_delivery.py``) can fire while the child is STILL RUNNING — a non-refusal delivery
    failure (#444's domain), not a fast refusal. A genuine fast refusal has already exited by
    the time we reach this arm (EPIPE means the launcher closed its inherited fd-3 read end,
    which happens at process exit). So this gates on ``poll()``: a still-running process
    (``poll() is None``) is a GENUINE delivery failure (#444's domain) — it first persists the
    reserved ``provider_key_delivery_failed`` row (host-authored, NO ``read_frame`` drive), then
    is torn down (``aclose``). Driving ``read_frame`` on a live child would block up to
    ``_READ_FRAME_TIMEOUT_S`` (~25s) awaiting an EOF it will never send, needlessly stalling the
    fail-closed boot — hence the row is host-authored rather than stderr-parsed. Only an
    already-exited launcher — the genuine fast-refusal signal — reaches the
    ``read_frame``-gated drain below.

    This does NOT reopen the forgery bypass §8.3's handshake closes: the drain is GATED on
    zero-stdout exactly as the runtime path is, and a post-``exec`` child cannot reach this arm
    without out-racing the synchronous ``writev`` (``exec`` of bwrap→runuser→python takes
    milliseconds; the writev is microseconds after ``fork``), so EPIPE ⟹ a launcher that
    exited before ``exec``. The residual is therefore identical to §11.5's accepted pre-hello
    window (an exec'd child that writes zero stdout then forges), not a new hole. Best-effort:
    the caller re-raises the delivery-failure ``QuarantineChildSpawnError`` regardless — this
    only recovers the attributed row a fast refusal would otherwise lose.
    """
    if child_io._process.poll() is None:
        # A LIVE child is a genuine delivery failure (#444's domain), NOT a fast
        # refusal (which has EXITED). Persist the reserved provider_key_delivery_failed
        # row BEFORE teardown, then terminate+reap at once rather than driving read_frame
        # and blocking ~25s on an EOF a live child never sends. ``aclose`` runs in a
        # ``finally`` so the bwrap child is ALWAYS reaped + the control socket ALWAYS
        # closed, even if the (self-guarded) row-write escapes with a BaseException
        # (e.g. a CancelledError, which the writer's ``except Exception`` does not catch)
        # — leak-free fail-closed, mirroring the else arm's own ``finally`` below.
        try:
            await child_io._record_provider_key_delivery_failure()
        finally:
            await child_io.aclose()
        return
    try:
        await child_io.read_frame()  # zero-stdout EOF -> sec-001 gate records the launcher row
    except QuarantineChildSpawnError:
        pass  # expected: the launcher refused; the row (if any) was recorded by the drain
    finally:
        await child_io.aclose()


async def spawn_quarantine_child_io(
    *,
    provider_key: str,
    control_fd: bool = False,
    child_module: str = _CHILD_MODULE,
    egress_config: EgressProxyConfig | None = None,
    model: str | None = None,
    max_tokens: int | None = None,
    ssl_cert_file: str = _DEFAULT_SSL_CERT_FILE,
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
    ``control_fd=True`` — which the LIVE daemon spawn now sets as of #340
    PR2b-golive; the ``False`` default remains for the dormant/unit spawns — a
    second AF_UNIX socketpair (:func:`make_control_socketpair`) is built; the
    child-end is dup'd onto literal fd 4 in the SAME synchronous zero-``await``
    window as the fd-3 dance above (a second clobbered-selector hazard would exist
    for fd 4 exactly as for fd 3 otherwise); the parent-end is kept and handed to
    the returned :class:`_SubprocessChildIO` for a later
    :meth:`_SubprocessChildIO.broker_sockets` call. ``control_fd=True`` REQUIRES an
    ``egress_config`` — a misconfigured opt-in refuses loudly rather than silently
    spawning without a broker.

    **#340 PR2b-golive provider config (ADR-0050 Decision 8).** The LIVE
    (``control_fd=True``) spawn threads the real-LLM child's provider config into
    the scrubbed env — ``model`` / ``max_tokens`` (routing.yaml ``[quarantine]``)
    and ``ssl_cert_file`` (default :data:`_DEFAULT_SSL_CERT_FILE`, the system CA
    bundle). These reach :func:`_child_env` ONLY on the ``control_fd=True`` path, so
    the DORMANT/echo spawn's env stays byte-identical to the pre-golive env (the
    ADR-0050 dormancy invariant). They are non-secret + non-T3 (the provider KEY
    still crosses only over fd 3); a bare ``control_fd=False`` spawn ignores them.

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

    A launcher refusal (the launcher exits pre-``exec``, so the child produces no
    ``hello``) now refuses the spawn HERE via the boot handshake
    (:func:`_await_boot_handshake`) — the first ``read_frame`` hits a zero-byte EOF,
    records the launcher-authored ``sandbox_refused`` row, and raises
    :class:`QuarantineChildSpawnError` — rather than returning a corpse the caller only
    discovers dead at first extraction (#443).
    """
    if child_module not in _ALLOWED_CHILD_MODULES:
        raise QuarantineChildSpawnError(t("security.quarantine_child.child_module_not_allowed"))
    if control_fd and egress_config is None:
        raise QuarantineChildSpawnError(t("security.quarantine_child.broker_unconfigured"))
    if (
        control_fd
        and child_module in _MODULES_REQUIRING_PROVIDER_CONFIG
        and (model is None or max_tokens is None)
    ):
        # SYMMETRY with the egress guard above. ``_child_env`` sets each provider-config var
        # ONLY when its argument is non-``None`` (the ADR-0050 dormancy invariant), so a live
        # spawn missing either one produces a child that boots without it and fails LATE and
        # obscurely: ``_build_provider`` ``KeyError``s on ``ALFRED_QUARANTINE_MODEL`` at boot,
        # and a missing ``ALFRED_QUARANTINE_MAX_TOKENS`` ``KeyError``s inside the extract loop
        # — AFTER the two-frame handshake already reported the child healthy. Refusing here
        # makes every live misconfiguration one loud pre-spawn failure of the same shape, and
        # costs no spawn (hard rule #7).
        raise QuarantineChildSpawnError(t("security.quarantine_child.provider_config_missing"))

    # Build the scrubbed child env ONCE, up front (no ``await``, no fd op — safe
    # anywhere). The LIVE (``control_fd=True``) spawn threads the golive provider
    # config into it; the DORMANT/echo (``control_fd=False``) spawn passes NONE, so
    # ``_child_env`` yields the pre-golive env byte-for-byte (ADR-0050 dormancy).
    child_env = (
        _child_env(model=model, max_tokens=max_tokens, ssl_cert_file=ssl_cert_file)
        if control_fd
        else _child_env()
    )

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
                env=child_env,
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
        # §8.4 CLOSE: a fast launcher refusal EPIPEs the key writev before the child exists,
        # so its ``sandbox_refused`` row would otherwise be lost. Route this arm through the
        # SAME sec-001-gated drain the handshake uses so a genuine (zero-stdout) fast refusal
        # persists its attributed row + fires the T0 hookpoint. ``_record_fast_launcher_refusal``
        # owns the IO — its ``aclose`` terminates+reaps the process and closes the control-parent
        # (replacing the old ``_terminate_and_reap`` + ``control_parent.close`` here).
        await _record_fast_launcher_refusal(
            _SubprocessChildIO(
                process,
                control_parent=control_parent,
                egress_config=egress_config,
                refusal_recorder=refusal_recorder,
            )
        )
        raise QuarantineChildSpawnError(
            t("security.quarantine_child.provider_key_delivery_failed")
        ) from exc

    child_io = _SubprocessChildIO(
        process,
        control_parent=control_parent,
        egress_config=egress_config,
        refusal_recorder=refusal_recorder,
    )
    # Read the two-frame boot handshake INSIDE the spawn (#443): a launcher refusal now
    # refuses boot with an attributed audit row here, instead of surfacing as a corpse at
    # first extraction. The recorder was threaded into `child_io` above so the read_frame
    # failure arm can persist the row + fire the fail_closed T0 hookpoint at boot.
    await _await_boot_handshake(child_io, child_module=child_module)
    return child_io


__all__ = [
    "QuarantineChildSpawnError",
    "spawn_quarantine_child_io",
]
