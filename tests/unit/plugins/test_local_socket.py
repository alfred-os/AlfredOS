"""Shared local-socket security primitives (G6-2b-2c RPC / #288, ADR-0038).

These exercise the EXTRACTED primitives directly as a public API, so the
load-bearing security branches are proven against the shared module itself —
not only mediated through the comms listener (correction sec-MEDIUM-1 / test-H1):

* ``assert_path_owned`` refuses a symlink (``lstat`` not ``stat``) + a non-owned
  inode, and raises a bare ``FileNotFoundError`` on a missing path (the client maps
  that to "daemon not running" — sec-HIGH-4);
* both degrade-open breadcrumbs fire on the no-``SO_PEERCRED`` / short-read branch,
  under the CALLER-supplied log prefix (correction Task-1: comms keeps
  ``comms.socket.*``, control uses ``daemon.control.*``);
* ``bind_owner_only_unix_socket`` UNCONDITIONALLY tightens a pre-existing 0755 parent
  to 0700, and its ``except BaseException`` cleanup unlinks the partial inode on a
  post-open failure;
* ``unlink_stale_socket`` refuses a FIFO at our path.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from alfred.plugins._local_socket import (
    MAX_LOCAL_SOCKET_LINE_BYTES,
    assert_path_owned,
    bind_owner_only_unix_socket,
    peer_uid_authorized,
    resolve_peer_uid,
    runtime_dir,
    unlink_stale_socket,
)
from alfred.plugins.comms_wire import _MAX_COMMS_LINE_BYTES, CommsPeerAuthError


@pytest.fixture
def short_runtime(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A SHORT tmp ``$HOME`` so bind tests never overflow the AF_UNIX 108-byte limit.

    Mirrors ``test_comms_socket_transport.py``'s ``runtime_dir`` fixture (correction
    test-L2): the deep pytest ``tmp_path`` on macOS already overflows AF_UNIX.
    """
    with tempfile.TemporaryDirectory(prefix="alflocal-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


def test_max_local_socket_line_bytes_re_exports_the_shared_bound() -> None:
    # arch-H1: the daemon modules depend on the shared module's PUBLIC name, not
    # ``comms_wire``'s underscore-prefixed bound.
    assert MAX_LOCAL_SOCKET_LINE_BYTES == _MAX_COMMS_LINE_BYTES


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: HOME-based runtime_dir resolution diverges from Windows "
    "Path.home()/USERPROFILE (#246 review)",
)
def test_runtime_dir_resolves_home_at_call_time(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert runtime_dir() == tmp_path / ".run" / "alfred"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: os.getuid family")
def test_peer_uid_authorized_rules() -> None:
    assert peer_uid_authorized(reported_uid=None) is True  # unknowable -> FS-perms-of-record
    assert peer_uid_authorized(reported_uid=os.getuid()) is True
    assert peer_uid_authorized(reported_uid=os.getuid() + 1) is False


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_bind_creates_0600_socket_under_0700_dir(short_runtime: Path) -> None:
    path = short_runtime / "control.sock"
    sock = bind_owner_only_unix_socket(path)
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    finally:
        sock.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_bind_tightens_a_preexisting_0755_parent_to_0700(short_runtime: Path) -> None:
    # sec-MEDIUM-1 (c): a pre-existing looser dir is tightened EVERY bind, not only
    # on creation (mkdir(mode=) is umask-masked + creation-only).
    short_runtime.mkdir(parents=True)
    short_runtime.chmod(0o755)
    path = short_runtime / "control.sock"
    sock = bind_owner_only_unix_socket(path)
    try:
        assert stat.S_IMODE(short_runtime.stat().st_mode) == 0o700
    finally:
        sock.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_bind_unlinks_a_stale_socket(short_runtime: Path) -> None:
    path = short_runtime / "control.sock"
    bind_owner_only_unix_socket(path).close()  # leaves a stale inode
    sock = bind_owner_only_unix_socket(path)  # must unlink-then-rebind, not EADDRINUSE
    sock.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_bind_cleanup_unlinks_partial_inode_on_post_open_failure(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # sec-MEDIUM-1 (d): a chmod failure AFTER bind must hit the ``except BaseException``
    # cleanup and unlink the partial inode (no leaked unprotected socket).
    path = short_runtime / "control.sock"

    real_chmod = Path.chmod

    def _boom(self: Path, mode: int, *a: object, **k: object) -> None:
        # CR T5: fail ONLY on the socket-path chmod (the post-bind one). The unconditional
        # parent-dir chmod runs FIRST (before bind), so a GLOBAL patch would raise there —
        # the failure would precede ``sock.bind`` and never reach the ``except
        # BaseException`` cleanup this test claims to exercise. Delegate the parent-dir
        # chmod to the real implementation so the inode is actually created before we boom.
        if self == path:
            raise PermissionError("simulated post-bind chmod failure")
        real_chmod(self, mode, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "chmod", _boom)
    with pytest.raises(PermissionError):
        bind_owner_only_unix_socket(path)
    assert not path.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: os.getuid family")
def test_assert_path_owned_refuses_non_socket(short_runtime: Path) -> None:
    short_runtime.mkdir(parents=True)
    f = short_runtime / "notasock"
    f.write_text("x")
    with pytest.raises(CommsPeerAuthError):
        assert_path_owned(f, log_prefix="daemon.control")


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_assert_path_owned_refuses_symlink_via_lstat(short_runtime: Path) -> None:
    # sec-MEDIUM-1 (a): a symlink (even to a socket we own) is refused on the LINK
    # inode — ``lstat`` never follows it.
    short_runtime.mkdir(parents=True)
    real = short_runtime / "real.sock"
    sock = bind_owner_only_unix_socket(real)
    try:
        link = short_runtime / "link.sock"
        link.symlink_to(real)
        with pytest.raises(CommsPeerAuthError):
            assert_path_owned(link, log_prefix="daemon.control")
    finally:
        sock.close()


def test_assert_path_owned_raises_filenotfound_bare_on_missing(short_runtime: Path) -> None:
    # sec-HIGH-4: a missing socket raises a BARE ``FileNotFoundError`` (not wrapped),
    # so the client maps it to ``DaemonControlUnavailableError``.
    short_runtime.mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        assert_path_owned(short_runtime / "absent.sock", log_prefix="daemon.control")


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: socket.AF_UNIX (not exposed by CPython on Windows)",
)
def test_assert_path_owned_accepts_owned_socket(short_runtime: Path) -> None:
    path = short_runtime / "ours.sock"
    sock = bind_owner_only_unix_socket(path)
    try:
        assert_path_owned(path, log_prefix="daemon.control")  # no raise
    finally:
        sock.close()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only: os.mkfifo")
def test_unlink_stale_socket_refuses_a_fifo(short_runtime: Path) -> None:
    # sec-MEDIUM-1 (e): a FIFO at our runtime path is anomalous — refuse rather than
    # blindly unlink something we do not recognise as ours; the FIFO survives.
    short_runtime.mkdir(parents=True)
    fifo = short_runtime / "weird.sock"
    os.mkfifo(fifo)
    with pytest.raises(RuntimeError):
        unlink_stale_socket(fifo)
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)


def test_unlink_stale_socket_missing_is_noop(short_runtime: Path) -> None:
    short_runtime.mkdir(parents=True)
    unlink_stale_socket(short_runtime / "absent.sock")  # no raise


class _RecLog:
    """Captures breadcrumb events the primitives emit via the ``log_to`` seam."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def debug(self, event: str, **kw: object) -> None:
        self.events.append((event, kw))

    def warning(self, event: str, **kw: object) -> None:
        self.events.append((event, kw))


class _FakeSock:
    def __init__(self, *, returns: bytes) -> None:
        self._returns = returns

    def getsockopt(self, _level: int, _opt: int, _buflen: int) -> bytes:
        return self._returns


def test_resolve_peer_uid_none_socket_is_none_with_prefix() -> None:
    # sec-MEDIUM-1 (b): the no-SO_PEERCRED breadcrumb fires under the CALLER prefix,
    # through the caller's own logger (the ``log_to`` seam).
    rec = _RecLog()
    assert resolve_peer_uid(None, log_prefix="daemon.control", log_to=rec) is None
    assert any(event == "daemon.control.peer_cred_unsupported" for event, _ in rec.events)


def test_resolve_peer_uid_short_read_logs_unavailable_under_prefix() -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("SO_PEERCRED unavailable on this host")
    rec = _RecLog()
    # A struct that unpacks but is the wrong width -> len != width -> None (no
    # breadcrumb on this arm — it is a clean short read, not a getsockopt fault).
    short = struct.pack("2I", 1, 2)
    result = resolve_peer_uid(_FakeSock(returns=short), log_prefix="daemon.control", log_to=rec)  # type: ignore[arg-type]
    assert result is None


def test_resolve_peer_uid_returns_uid_on_full_creds() -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("SO_PEERCRED unavailable on this host")
    creds = struct.pack("3I", 4321, 1000, 1000)
    assert resolve_peer_uid(_FakeSock(returns=creds), log_prefix="daemon.control") == 1000  # type: ignore[arg-type]


def test_resolve_peer_uid_getsockopt_oserror_logs_unavailable() -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("SO_PEERCRED unavailable on this host")
    rec = _RecLog()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.close()
    assert resolve_peer_uid(sock, log_prefix="comms.socket", log_to=rec) is None
    assert any(event == "comms.socket.peer_cred_unavailable" for event, _ in rec.events)
