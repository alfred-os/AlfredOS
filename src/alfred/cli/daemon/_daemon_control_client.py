"""Daemon control-plane client: dial + one request + one response (#288, ADR-0038).

The connect-analog of :func:`alfred.plugins.comms_socket_transport.dial_comms_socket`,
but request/response (not a pump): dial -> pre-dial ``assert_path_owned`` backstop ->
post-connect ``SO_PEERCRED`` -> send one ``ControlRequest`` -> read one bounded
``ControlResponse`` -> close. Three loud failure modes the caller maps to operator UX:

* :class:`DaemonControlUnavailableError` — the daemon is not running (the socket is
  absent OR a stale inode has no listener). The operator-facing "not running" path.
* :class:`DaemonControlAuthError` — the dialed path is not a socket we own, or the
  post-connect peer uid mismatched (a stale-socket race / wider-perm misconfig).
* :class:`DaemonControlProtocolError` — the response was empty / over-bound / malformed.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import structlog

from alfred.cli.daemon._daemon_control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    ControlRequest,
    ControlResponse,
)
from alfred.cli.daemon._daemon_control_server import default_control_socket_path
from alfred.plugins._local_socket import (
    MAX_LOCAL_SOCKET_LINE_BYTES,
    assert_path_owned,
    peer_uid_authorized,
    resolve_peer_uid,
)
from alfred.plugins.comms_wire import CommsPeerAuthError

if TYPE_CHECKING:
    from pathlib import Path

log = structlog.get_logger(__name__)

_CONTROL_LOG_PREFIX = "daemon.control"


class DaemonControlError(Exception):
    """Base for every control-plane dial failure.

    Lets the render layer catch ONE family and degrade on all of them (the
    ``alfred daemon status`` render must never crash on a control-plane fault —
    CLAUDE.md hard rule #7). The three subclasses keep their distinct names +
    behaviour so a caller that wants to distinguish daemon-absent from auth /
    protocol still can.
    """


class DaemonControlUnavailableError(DaemonControlError):
    """The daemon control socket is absent / unconnectable (daemon not running)."""


class DaemonControlAuthError(DaemonControlError):
    """The dialed socket is not owned by us / the peer uid mismatched."""


class DaemonControlProtocolError(DaemonControlError):
    """The response was empty / over-bound / malformed."""


async def query_daemon_control(
    method: str,
    *,
    params: dict[str, object] | None = None,
    path: Path | None = None,
    request_id: str = "1",
) -> ControlResponse:
    """Dial the daemon control socket, send one request, return one response.

    ``assert_path_owned`` raises a BARE ``FileNotFoundError`` on a missing socket (the
    daemon-absent path) — mapped to :class:`DaemonControlUnavailableError`. A
    ``ConnectionRefusedError`` from the connect (a stale inode we own with no listener)
    maps to the SAME unavailable contract (sec-HIGH-4).
    """
    sock_path = path if path is not None else default_control_socket_path()
    try:
        assert_path_owned(sock_path, log_prefix=_CONTROL_LOG_PREFIX, log_to=log)
    except FileNotFoundError as exc:
        raise DaemonControlUnavailableError(str(sock_path)) from exc
    except CommsPeerAuthError as exc:
        raise DaemonControlAuthError(str(exc)) from exc
    try:
        reader, writer = await asyncio.open_unix_connection(
            path=str(sock_path), limit=MAX_LOCAL_SOCKET_LINE_BYTES
        )
    except OSError as exc:
        # ANY connect-time OSError is the daemon-absent contract, not a raw crash: the
        # inode vanished between ``assert_path_owned``'s lstat and the connect
        # (``FileNotFoundError``), a stale inode we own has no listener
        # (``ConnectionRefusedError``), or a TOCTOU swapped the inode for one we can't
        # connect to (``ConnectionResetError``, ``PermissionError``/EACCES,
        # ``ENOTSOCK``, ...). All map to Unavailable so a connect fault degrades the
        # render rather than escaping ``DaemonControlError`` raw (T2 / CR Major).
        raise DaemonControlUnavailableError(str(sock_path)) from exc
    try:
        peer_uid = resolve_peer_uid(
            writer.get_extra_info("socket"), log_prefix=_CONTROL_LOG_PREFIX, log_to=log
        )
        if not peer_uid_authorized(reported_uid=peer_uid):
            raise DaemonControlAuthError(f"peer_uid={peer_uid}")
        request = ControlRequest(
            version=CONTROL_PROTOCOL_VERSION, id=request_id, method=method, params=params or {}
        )
        writer.write(request.model_dump_json().encode() + b"\n")
        try:
            await writer.drain()
            return await _read_response(reader)
        except (ConnectionResetError, BrokenPipeError) as exc:
            # The server dropped the connection mid-exchange (a flood-cap close, a reject
            # race, a crash): on Linux a server close-with-unread-data delivers an RST so
            # drain/read raise ECONNRESET; on macOS the same close surfaces as a clean EOF
            # (handled in ``_read_response``). A mid-exchange drop means the request was
            # NOT served -> Unavailable (the daemon-absent contract), NOT Protocol (which
            # is for a malformed/over-bound RESPONSE the server did send).
            raise DaemonControlUnavailableError(str(sock_path)) from exc
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _read_response(reader: asyncio.StreamReader) -> ControlResponse:
    try:
        raw = await reader.readline()
    except (ValueError, asyncio.LimitOverrunError) as exc:
        # The StreamReader limit tripped on an over-bound response line.
        raise DaemonControlProtocolError("over-bound control response") from exc
    except (ConnectionResetError, BrokenPipeError) as exc:
        # The server dropped us mid-read (Linux RST on a server close-with-unread-data;
        # macOS would have surfaced a clean EOF -> the empty-response branch below). A
        # drop means the request was not served -> Unavailable, not Protocol.
        raise DaemonControlUnavailableError("control connection dropped") from exc
    if not raw:
        raise DaemonControlProtocolError("empty control response")
    if len(raw) > MAX_LOCAL_SOCKET_LINE_BYTES:
        raise DaemonControlProtocolError("over-bound control response")
    try:
        return ControlResponse.model_validate_json(raw)
    except ValueError as exc:
        raise DaemonControlProtocolError(
            f"malformed control response: {type(exc).__name__}"
        ) from exc


__all__ = [
    "DaemonControlAuthError",
    "DaemonControlError",
    "DaemonControlProtocolError",
    "DaemonControlUnavailableError",
    "query_daemon_control",
]
