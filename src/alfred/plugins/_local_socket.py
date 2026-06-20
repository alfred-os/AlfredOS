"""Shared 0600-unix-socket security primitives for AlfredOS local IPC.

Extracted from :mod:`alfred.plugins.comms_socket_transport` (ADR-0031) so the comms
wire AND the daemon control socket (G6-2b-2c / ADR-0038) reuse ONE audited
implementation of peer-uid auth, owner-only bind, and call-time runtime-dir
resolution — rather than two divergent copies (the drift the #299 architect review
flagged, and the "three independent ``~/.run/alfred`` derivations" the 2b-2c design
retires). The security contract is unchanged from ADR-0031: a 0600 socket under a
0700 runtime dir whose parent is the operator's owner-only home, plus ``SO_PEERCRED``
defense-in-depth that degrades OPEN to the FS-perms-of-record on a no-``SO_PEERCRED``
host (a macOS dev box).

**Log-prefix parameterisation (correction Task-1).** The degrade-open breadcrumbs +
the dial-path-unowned warning take a caller-supplied ``log_prefix`` so the comms wire
keeps emitting ``comms.socket.*`` (its existing log/alert queries are unchanged) and
the control plane emits ``daemon.control.*`` — the extraction never silently relabels
or orphans an existing breadcrumb.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
from pathlib import Path
from typing import Final, Protocol

import structlog

from alfred.i18n import t
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsPeerAuthError

log = structlog.get_logger(__name__)


class _BreadcrumbLogger(Protocol):
    """The narrow logger surface the primitives emit through.

    Each caller passes its OWN module logger (``cst.log`` / the control server's
    ``log``) so the breadcrumb is attributable to — and monkeypatchable in — the
    calling module, not this shared one. Defaults to this module's logger.
    """

    def debug(self, event: str, **kw: object) -> None: ...

    def warning(self, event: str, **kw: object) -> None: ...


# arch-H1: re-export the shared frame bound under a PUBLIC name so the daemon
# control modules depend on this module's public surface, not ``comms_wire``'s
# underscore-prefixed constant.
MAX_LOCAL_SOCKET_LINE_BYTES: Final[int] = _MAX_COMMS_LINE_BYTES

_RUNTIME_DIR_MODE: Final[int] = 0o700
_SOCKET_MODE: Final[int] = 0o600

# The kernel ``struct ucred`` returned by ``SO_PEERCRED`` is three UNSIGNED ints
# ``{ pid_t pid; uid_t uid; gid_t gid; }``; ``"3I"`` matches it (uid is unsigned).
_UCRED_STRUCT: Final[str] = "3I"
# Perf (devex carry-forward): hoist the fixed struct width to a module constant so
# ``resolve_peer_uid`` does not recompute ``struct.calcsize`` on every accept.
_UCRED_WIDTH: Final[int] = struct.calcsize(_UCRED_STRUCT)


def runtime_dir() -> Path:
    """Resolve ``~/.run/alfred`` at call time (honours a changed ``$HOME``)."""
    return Path.home() / ".run" / "alfred"


def resolve_peer_uid(
    sock: socket.socket | None, *, log_prefix: str, log_to: _BreadcrumbLogger | None = None
) -> int | None:
    """Return the connected peer's uid, or ``None`` when unknowable.

    Linux answers via ``SO_PEERCRED`` (kernel-attested ``(pid, uid, gid)``). A
    platform without it (macOS dev hosts) returns ``None`` — the 0600 socket under
    the 0700 runtime dir is the same-uid enforcement-of-record there; ``SO_PEERCRED``
    is defense-in-depth, not the only line. NEVER raises: ``getsockopt`` may return
    fewer bytes than requested (a short read makes ``struct.unpack`` raise
    ``struct.error``), and a closed/non-AF_UNIX socket raises ``OSError`` — both
    degrade to ``None`` (accept on FS perms) rather than crashing the accept callback
    and wedging the listener.

    ``log_prefix`` keys the degrade-open breadcrumbs (``comms.socket`` /
    ``daemon.control``) so the extraction does not relabel either caller's events;
    ``log_to`` lets each caller emit through its OWN module logger (so the breadcrumb
    is attributable to + monkeypatchable in the calling module).
    """
    emit = log if log_to is None else log_to
    if sock is None or not hasattr(socket, "SO_PEERCRED"):
        # Leave a breadcrumb on the no-SO_PEERCRED branch (a macOS dev host) so the
        # FS-perms-of-record degrade is distinguishable in a trace from a short-read /
        # getsockopt-fault degrade — the operator can tell the peer-uid check was
        # SKIPPED (platform), not ATTEMPTED-and-failed.
        emit.debug(
            f"{log_prefix}.peer_cred_unsupported",
            so_peercred_present=hasattr(socket, "SO_PEERCRED"),
            sock_present=sock is not None,
        )
        return None
    width = _UCRED_WIDTH
    try:
        # ``SO_PEERCRED`` is a Linux-only socket constant; the ``hasattr`` guard above
        # gates the access. pyright on a macOS dev host cannot see the Linux-platform
        # typeshed stub, so silence the attr-access there (mypy on this host resolves
        # it, hence ``unused-ignore`` keeps the Linux gate quiet).
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, width)  # type: ignore[attr-defined, unused-ignore]
        if len(creds) != width:
            return None
        # ``struct.unpack`` is typed ``tuple[Any, ...]``; the ``"3I"`` format
        # guarantees three ints, so coerce the uid to ``int`` for mypy --strict.
        _pid, uid, _gid = struct.unpack(_UCRED_STRUCT, creds)
    except (OSError, struct.error) as exc:
        # Degrade-open to the FS-perms-of-record (return None -> authorized). Benign
        # for the enumerated cases (short read, closed/non-AF_UNIX socket), but a
        # security check that fails open leaves a breadcrumb so an UNEXPECTED
        # getsockopt fault on a SO_PEERCRED-advertising host is distinguishable from
        # the normal degrade path.
        emit.debug(f"{log_prefix}.peer_cred_unavailable", error=repr(exc))
        return None
    return int(uid)


def peer_uid_authorized(*, reported_uid: int | None) -> bool:
    """True if the peer is the same uid as us, or unknowable (FS-perms-of-record).

    ``None`` (no ``SO_PEERCRED`` / short read) is authorized: the only peer that can
    ``connect`` a 0600 socket under a 0700 dir is the owner. A reported uid that
    mismatches ``os.getuid()`` is a genuine impostor (a same-uid race that re-bound or
    a wider-perm misconfig) and is refused.
    """
    return reported_uid is None or reported_uid == os.getuid()


def unlink_stale_socket(path: Path) -> None:
    """Remove a leftover socket/file at ``path``; a missing path is not an error.

    Only ever removes a path we own (a socket or regular file under the daemon's own
    0700 runtime dir). A FIFO / device / symlink at the path is anomalous — refuse
    rather than blindly unlink something we do not recognise as ours.
    """
    try:
        # ``lstat`` (not stat) so a symlink target is never followed.
        st = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(st.st_mode) or stat.S_ISREG(st.st_mode):
        path.unlink()
    else:
        raise RuntimeError(
            f"local socket path {path} is not a socket or regular file: "
            f"{stat.S_IFMT(st.st_mode):#o}"
        )


def bind_owner_only_unix_socket(path: Path, *, backlog: int = 16) -> socket.socket:
    """mkdir-0700 + unconditional dir-chmod + unlink-stale + bind + chmod-0600 + listen.

    Returns the bound, listening socket. Mirrors the ADR-0031 bind discipline verbatim
    (its security comments are load-bearing — carried here):

    * ``mkdir(mode=...)`` only applies at CREATION (and is umask-masked even then); a
      pre-existing ``~/.run/alfred`` from a looser-umask boot keeps its old perms,
      leaving the 0600 socket under a too-open dir. Tighten the dir to 0700
      UNCONDITIONALLY so the bind->chmod window's 0700 invariant holds every boot
      (CLAUDE.md hard rule #7, fail-closed). The dir is alfred-owned runtime state and
      its parent is the user's owner-only home, so this chmod cannot be redirected
      through an attacker-controlled symlink.
    * A freshly-bound unix socket is created under the process umask; pin it to 0600
      explicitly so it is owner-only the instant the daemon advertises it.

    ``backlog`` is >1 here (the control plane is multi-connection); the comms wire
    passes ``backlog=1`` to preserve its one-shot ``listen(1)`` semantics.
    """
    runtime_parent = path.parent
    runtime_parent.mkdir(mode=_RUNTIME_DIR_MODE, parents=True, exist_ok=True)
    runtime_parent.chmod(_RUNTIME_DIR_MODE)  # unconditional: tighten a pre-existing looser dir
    unlink_stale_socket(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
        path.chmod(_SOCKET_MODE)
        sock.listen(backlog)
    except BaseException:
        # A bind/chmod/listen failure leaves a partial inode at the path; unlink it so
        # no unprotected socket lingers (the leak this cleanup exists to prevent).
        sock.close()
        unlink_stale_socket(path)
        raise
    return sock


def assert_path_owned(
    path: Path, *, log_prefix: str, log_to: _BreadcrumbLogger | None = None
) -> None:
    """Pre-dial owner-backstop: the dial path must be a socket WE own, or raise.

    The dial side's degrade-open hazard: on a host without ``SO_PEERCRED`` (a macOS
    dev box) the POST-connect peer-uid check returns ``None`` -> authorized, so a
    client would otherwise dial whatever inode squats at the path. This pre-dial
    ``lstat`` is the only owner enforcement on those hosts: refuse anything that is not
    an :func:`stat.S_ISSOCK` inode owned by ``os.getuid()``.

    ``lstat`` (NOT ``stat``) so an attacker-planted symlink to a victim socket is
    never followed — we assert on the link inode itself. A ``FileNotFoundError`` (the
    socket is absent) is NOT caught here — it surfaces BARE so the caller can map a
    missing socket to its daemon-absent contract (sec-HIGH-4).
    """
    emit = log if log_to is None else log_to
    st = path.lstat()
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
        emit.warning(
            f"{log_prefix}.dial_path_unowned",
            path=str(path),
            st_mode=f"{stat.S_IFMT(st.st_mode):#o}",
            st_uid=st.st_uid,
            expected_uid=os.getuid(),
        )
        raise CommsPeerAuthError(t("comms.transport.dial_path_unowned", path=str(path)))


__all__ = [
    "MAX_LOCAL_SOCKET_LINE_BYTES",
    "assert_path_owned",
    "bind_owner_only_unix_socket",
    "peer_uid_authorized",
    "resolve_peer_uid",
    "runtime_dir",
    "unlink_stale_socket",
]
