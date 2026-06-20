"""DaemonControlServer — request/response over the 0600 control socket (#288, ADR-0038).

The control plane is multi-connection request/response (one request -> one response ->
close per connection), in contrast to the comms wire's one-shot bidirectional pump. The
load-bearing properties proven here:

* bind creates a 0600 socket under a 0700 dir;
* a well-formed ``status.query`` returns a parseable ``DaemonStatusResult``;
* an unknown method / malformed request returns an ``error`` response (echoed id where
  known), the server keeps serving (test-H3);
* an over-bound request line raises BEFORE writing — silent-close (test-H3);
* a peer-uid mismatch fires the ``on_peer_rejected`` audit callback + closes, server
  keeps serving;
* a FAILED reject-audit-write ESCALATES loud, NOT swallowed by the resilient-connection
  guard (sec-LOW-1 / hard rule #7);
* the multi-connection resilience: after a bad first connection (every bad-kind), a
  second connection still answers (test-H2);
* a per-connection slow-loris (connect + never write) is dropped after the timeout AND
  the server still answers a later well-formed dial (sec-HIGH-1);
* the concurrency cap closes a flood past the ceiling (sec-HIGH-2);
* ``aclose`` cancels the serve task + unlinks the socket file.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

import alfred.cli.daemon._daemon_control_server as server_mod
from alfred.cli.daemon._daemon_control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    STATUS_QUERY_METHOD,
    UNKNOWN_REQUEST_ID,
    ControlResponse,
    DaemonStatusResult,
)
from alfred.cli.daemon._daemon_control_server import DaemonControlServer
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler
from alfred.plugins._local_socket import MAX_LOCAL_SOCKET_LINE_BYTES

pytestmark = pytest.mark.asyncio

_EPOCH = "e" * 32
_NOW = datetime(2026, 6, 20, 9, 0, 0, tzinfo=UTC)


class _FakeAudit:
    async def append_schema(self, **_kwargs: object) -> None:
        return None


@pytest.fixture
def short_runtime(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A SHORT tmp ``$HOME`` (AF_UNIX 108-byte limit — correction test-L2)."""
    with tempfile.TemporaryDirectory(prefix="alfctl-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


def _build() -> tuple[AdapterStatusObserver, CrashIncidentReconciler]:
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(
        audit=_FakeAudit(),
        expected_epoch=lambda: _EPOCH,
        now=lambda: _NOW,
        reconciler=reconciler,
    )
    return observer, reconciler


async def _seed_crashed(observer: AdapterStatusObserver) -> None:
    await observer.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "RuntimeError",
            "detail": "x",
            "host_restart_seq": 0,
        },
    )


async def _make_server(
    short_runtime: Path,
    *,
    on_peer_rejected: object = None,
) -> tuple[DaemonControlServer, Path]:
    observer, reconciler = _build()
    await _seed_crashed(observer)
    path = short_runtime / "control.sock"
    srv = DaemonControlServer(
        observer=observer,
        reconciler=reconciler,
        path=path,
        on_peer_rejected=on_peer_rejected,  # type: ignore[arg-type]
    )
    await srv.start()
    return srv, path


async def _assert_connection_dropped(reader: asyncio.StreamReader) -> None:
    """The server dropped us: clean EOF on macOS, ECONNRESET on Linux — both mean dropped.

    When the server closes a unix socket that still has unread/unsent data (a peer-uid
    reject, an audit-escalation close, a flood-cap close), Linux delivers a TCP-RST-
    equivalent so the client's ``read`` raises ``ConnectionResetError [Errno 104]``;
    macOS surfaces the same close as a clean EOF (``b""``). Both outcomes mean "the server
    dropped the connection without a frame" — the property these tests pin.
    """
    # ``suppress`` only swallows the Linux RST; an AssertionError (a non-empty frame —
    # the server did NOT drop us) still propagates and fails the test.
    with contextlib.suppress(ConnectionResetError, BrokenPipeError):
        assert await reader.read(100) == b""


async def _roundtrip(path: Path, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_unix_connection(path=str(path))
    try:
        # The server may close mid-write on an over-bound line (it raises before
        # reading the whole frame), so a BrokenPipe on the client drain is expected for
        # the over-bound case — suppress it and still read the (EOF) response.
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            writer.write(payload)
            await writer.drain()
        return await reader.readline()
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _status_query_bytes(request_id: str = "1") -> bytes:
    return (
        json.dumps(
            {
                "version": CONTROL_PROTOCOL_VERSION,
                "id": request_id,
                "method": STATUS_QUERY_METHOD,
                "params": {},
            }
        ).encode()
        + b"\n"
    )


async def test_bind_creates_0600_socket_under_0700_dir(short_runtime: Path) -> None:
    srv, path = await _make_server(short_runtime)
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    finally:
        await srv.aclose()


async def test_status_query_returns_parseable_result(short_runtime: Path) -> None:
    srv, path = await _make_server(short_runtime)
    try:
        raw = await _roundtrip(path, _status_query_bytes("abc"))
        resp = ControlResponse.model_validate_json(raw)
        assert resp.id == "abc"  # echoed id
        assert resp.error is None
        assert resp.result is not None
        result = DaemonStatusResult.model_validate(resp.result)
        assert result.adapters["discord"].state in {"crashed", "unknown"}
        assert result.adapters["discord"].latest_crash is not None
    finally:
        await srv.aclose()


async def test_status_query_with_no_observer_returns_empty_adapters(short_runtime: Path) -> None:
    # CR T0: a zero-adapter daemon binds the SAME control plane with NO observer /
    # reconciler (no comms graph). ``status.query`` must answer an EMPTY adapter map (the
    # ``adapters_none`` render), NOT crash and NOT report "unavailable".
    path = short_runtime / "control.sock"
    srv = DaemonControlServer(observer=None, reconciler=None, path=path)
    await srv.start()
    try:
        raw = await _roundtrip(path, _status_query_bytes("z"))
        resp = ControlResponse.model_validate_json(raw)
        assert resp.id == "z"
        assert resp.error is None
        assert resp.result is not None
        result = DaemonStatusResult.model_validate(resp.result)
        assert result.adapters == {}
    finally:
        await srv.aclose()


async def test_unknown_method_returns_error_with_echoed_id(short_runtime: Path) -> None:
    srv, path = await _make_server(short_runtime)
    try:
        payload = (
            json.dumps(
                {"version": CONTROL_PROTOCOL_VERSION, "id": "42", "method": "no.such.method"}
            ).encode()
            + b"\n"
        )
        raw = await _roundtrip(path, payload)
        resp = ControlResponse.model_validate_json(raw)
        assert resp.id == "42"  # echoed even on error (test-H3)
        assert resp.result is None
        assert resp.error is not None and resp.error.startswith("unknown_method:")
    finally:
        await srv.aclose()


async def test_malformed_request_returns_error_with_unknown_id(short_runtime: Path) -> None:
    srv, path = await _make_server(short_runtime)
    try:
        raw = await _roundtrip(path, b"this is not json\n")
        resp = ControlResponse.model_validate_json(raw)
        assert resp.id == UNKNOWN_REQUEST_ID  # id unknowable on a parse failure
        assert resp.result is None
        assert resp.error is not None and resp.error.startswith("malformed_request:")
    finally:
        await srv.aclose()


async def test_over_bound_request_silent_closes_without_a_frame(short_runtime: Path) -> None:
    # test-H3: the server raises BEFORE writing -> the client sees EOF (empty read),
    # NOT an error frame. Pin the silent-close contract explicitly.
    srv, path = await _make_server(short_runtime)
    try:
        over = b"x" * (srv._max_line_bytes + 10) + b"\n"
        raw = await _roundtrip(path, over)
        assert raw == b""  # EOF, no response frame
        # ... and the server still answers a subsequent well-formed dial.
        good = await _roundtrip(path, _status_query_bytes())
        assert ControlResponse.model_validate_json(good).error is None
    finally:
        await srv.aclose()


async def test_peer_uid_mismatch_fires_reject_callback_and_keeps_serving(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rejected: list[int | None] = []

    async def _on_reject(peer_uid: int | None) -> None:
        rejected.append(peer_uid)

    # Force the server-side peer-uid resolution to report a FOREIGN uid.
    monkeypatch.setattr(server_mod, "resolve_peer_uid", lambda _sock, **_kw: os.getuid() + 4242)
    srv, path = await _make_server(short_runtime, on_peer_rejected=_on_reject)
    try:
        reader, writer = await asyncio.open_unix_connection(path=str(path))
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            writer.write(_status_query_bytes())
            await writer.drain()
        await _assert_connection_dropped(reader)  # refused: closed without a frame
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        await asyncio.sleep(0.05)
        assert rejected == [os.getuid() + 4242]
        # The server keeps serving: a same-uid dial (resolution restored) still answers.
        monkeypatch.setattr(server_mod, "resolve_peer_uid", lambda _sock, **_kw: os.getuid())
        good = await _roundtrip(path, _status_query_bytes())
        assert ControlResponse.model_validate_json(good).error is None
    finally:
        await srv.aclose()


async def test_failed_reject_audit_write_escalates_loud(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # sec-LOW-1 / hard rule #7: a FAILED audit-write of a security reject must NOT be
    # swallowed by the resilient-connection guard. The server records the escalation
    # via a loud ``log.error`` distinct from the resilient ``connection_failed`` warn.
    errors: list[str] = []

    class _RecLog:
        def warning(self, _event: str, **_kw: object) -> None: ...
        def error(self, event: str, **_kw: object) -> None:
            errors.append(event)

        def debug(self, _event: str, **_kw: object) -> None: ...
        def info(self, _event: str, **_kw: object) -> None: ...

    async def _boom_reject(_peer_uid: int | None) -> None:
        raise RuntimeError("audit backend down")

    monkeypatch.setattr(server_mod, "log", _RecLog())
    monkeypatch.setattr(server_mod, "resolve_peer_uid", lambda _sock, **_kw: os.getuid() + 99)
    srv, path = await _make_server(short_runtime, on_peer_rejected=_boom_reject)
    try:
        reader, writer = await asyncio.open_unix_connection(path=str(path))
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            writer.write(_status_query_bytes())
            await writer.drain()
        await _assert_connection_dropped(reader)  # closed without a frame on reject
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        await asyncio.sleep(0.05)
        # The escalation is loud + distinguishable from a normal resilient continue.
        assert any("reject_audit_failed" in e for e in errors), errors
    finally:
        await srv.aclose()


@pytest.mark.parametrize(
    "bad_payload",
    [
        b"not json\n",  # malformed
        b"x" * (MAX_LOCAL_SOCKET_LINE_BYTES + 1024),  # over-bound (no newline: trips the limit)
        json.dumps({"version": CONTROL_PROTOCOL_VERSION, "id": "1", "method": "nope"}).encode()
        + b"\n",  # unknown method
    ],
    ids=["malformed", "over_bound", "unknown_method"],
)
async def test_server_serves_second_connection_after_bad_first(
    short_runtime: Path, bad_payload: bytes
) -> None:
    # test-H2: THE multi-connection-resilience property — a bad first connection never
    # wedges the accept loop; a real second roundtrip succeeds.
    srv, path = await _make_server(short_runtime)
    try:
        await _roundtrip(path, bad_payload)
        good = await _roundtrip(path, _status_query_bytes("second"))
        resp = ControlResponse.model_validate_json(good)
        assert resp.id == "second"
        assert resp.error is None
        DaemonStatusResult.model_validate(resp.result)
    finally:
        await srv.aclose()


async def test_slow_loris_peer_is_dropped_after_timeout(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # sec-HIGH-1: a peer that connects + never writes must NOT hold a serve task
    # forever. Shrink the exchange timeout so the test is fast.
    monkeypatch.setattr(server_mod, "_CONTROL_EXCHANGE_TIMEOUT_S", 0.2)
    srv, path = await _make_server(short_runtime)
    try:
        reader, writer = await asyncio.open_unix_connection(path=str(path))
        try:
            # Never write. The server's exchange timeout closes us; the read returns EOF.
            raw = await asyncio.wait_for(reader.readline(), timeout=2.0)
            assert raw == b""  # dropped after the deadline
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        # The server still answers a subsequent well-formed dial.
        good = await _roundtrip(path, _status_query_bytes())
        assert ControlResponse.model_validate_json(good).error is None
    finally:
        await srv.aclose()


async def test_concurrency_cap_closes_flood_past_ceiling(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # sec-HIGH-2: past the live-serve ceiling, an extra connection is closed
    # immediately (not queued unboundedly). Shrink the cap + slow the handler so the
    # ceiling is observable.
    monkeypatch.setattr(server_mod, "_MAX_CONCURRENT_SERVE", 2)

    held = asyncio.Event()

    async def _slow_status(_req: object) -> dict[str, object]:
        await held.wait()
        return {"adapters": {}}

    srv, path = await _make_server(short_runtime)
    srv._handlers[STATUS_QUERY_METHOD] = _slow_status  # type: ignore[assignment]
    try:
        # Open two connections that occupy both slots (handler blocks on ``held``).
        conns: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        for _ in range(2):
            r, w = await asyncio.open_unix_connection(path=str(path))
            w.write(_status_query_bytes())
            await w.drain()
            conns.append((r, w))
        await asyncio.sleep(0.1)
        # The 3rd connection is past the ceiling -> closed immediately (EOF on macOS,
        # ECONNRESET on Linux — both mean refused, not queued).
        r3, w3 = await asyncio.open_unix_connection(path=str(path))
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            w3.write(_status_query_bytes())
            await w3.drain()
        await asyncio.wait_for(_assert_connection_dropped(r3), timeout=2.0)
        w3.close()
        held.set()  # release the two held handlers
        for _r, w in conns:
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
    finally:
        await srv.aclose()


async def test_aclose_unlinks_socket_file(short_runtime: Path) -> None:
    srv, path = await _make_server(short_runtime)
    assert path.exists()
    await srv.aclose()
    assert not path.exists()
    # Idempotent: a second aclose is a no-op (the ``_server is None`` arm).
    await srv.aclose()


# --------------------------------------------------------------------------- #
# Direct-drive unit cases (the branches a socket roundtrip can't reliably hit) #
# --------------------------------------------------------------------------- #


def test_default_control_socket_path_is_under_runtime_dir(short_runtime: Path) -> None:
    from alfred.cli.daemon._daemon_control_server import default_control_socket_path

    assert default_control_socket_path() == short_runtime / "control.sock"


class _StubReader:
    """Returns a single pre-set line, then EOF."""

    def __init__(self, line: bytes) -> None:
        self._line = line

    async def readline(self) -> bytes:
        line, self._line = self._line, b""
        return line


class _StubWriter:
    def __init__(self) -> None:
        self.written: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        return None

    def get_extra_info(self, _name: str) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def test_serve_one_empty_read_returns_without_a_frame(short_runtime: Path) -> None:
    # The clean-EOF arm: an empty read -> no response written.
    srv, _ = await _make_server(short_runtime)
    try:
        writer = _StubWriter()
        await srv._serve_one(_StubReader(b""), writer)  # type: ignore[arg-type]
        assert writer.written == []
    finally:
        await srv.aclose()


async def test_serve_one_belt_and_braces_length_check_raises(short_runtime: Path) -> None:
    # The belt-and-braces ``len(raw) > max`` branch: a line longer than the bound that a
    # stub reader hands through whole (the real readline would have raised first). Pin
    # the raise-before-write contract.
    srv, _ = await _make_server(short_runtime)
    try:
        oversized = b"x" * (srv._max_line_bytes + 1)
        writer = _StubWriter()
        with pytest.raises(Exception, match="frame bound"):
            await srv._serve_one(_StubReader(oversized), writer)  # type: ignore[arg-type]
        assert writer.written == []  # raised BEFORE writing
    finally:
        await srv.aclose()


async def test_route_handler_error_returns_error_token_not_message(short_runtime: Path) -> None:
    # A handler that raises -> an ``error`` response carrying ONLY the exc TYPE name,
    # never ``str(exc)`` (sec-MEDIUM-4). The server does not crash.
    srv, _ = await _make_server(short_runtime)

    async def _boom(_req: object) -> dict[str, object]:
        raise RuntimeError("super secret backend detail")

    srv._handlers[STATUS_QUERY_METHOD] = _boom  # type: ignore[assignment]
    try:
        resp = await srv._route(_status_query_bytes("z"))
        assert resp.id == "z"
        assert resp.result is None
        assert resp.error == "handler_error:RuntimeError"
        assert "secret" not in (resp.error or "")
    finally:
        await srv.aclose()


async def test_on_connect_resilient_arm_swallows_generic_fault(
    short_runtime: Path,
) -> None:
    # The resilient ``except Exception`` arm: a generic fault on one connection is
    # logged + closed WITHOUT wedging the server (the accept loop keeps serving).
    srv, _ = await _make_server(short_runtime)

    class _RaisingReader:
        async def readline(self) -> bytes:
            raise RuntimeError("transient read fault")

    try:
        writer = _StubWriter()
        # Does NOT raise out — the generic fault is swallowed by the resilient guard.
        await srv._on_connect(_RaisingReader(), writer)  # type: ignore[arg-type]
    finally:
        await srv.aclose()


async def test_reject_peer_without_callback_is_a_quiet_early_return(
    short_runtime: Path,
) -> None:
    # The ``on_peer_rejected is None`` early-return: a refused peer is still loud-logged
    # but, with no audit callback configured, there is nothing to escalate.
    srv, _ = await _make_server(short_runtime, on_peer_rejected=None)
    try:
        await srv._reject_peer(os.getuid() + 13)  # no raise, no callback
    finally:
        await srv.aclose()


async def test_on_connect_reraises_reject_audit_escalation(
    short_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # sec-LOW-1: drive ``_on_connect`` directly so the escalation re-raise is OBSERVED
    # (a socket roundtrip leaves the raise in a detached task). A failed reject-audit
    # must surface loud, not fold into the resilient ``connection_failed`` swallow.
    from alfred.cli.daemon._daemon_control_server import _RejectAuditEscalationError

    async def _boom_reject(_peer_uid: int | None) -> None:
        raise RuntimeError("audit down")

    monkeypatch.setattr(server_mod, "resolve_peer_uid", lambda _sock, **_kw: os.getuid() + 7)
    srv, _ = await _make_server(short_runtime, on_peer_rejected=_boom_reject)
    try:
        writer = _StubWriter()
        with pytest.raises(_RejectAuditEscalationError):
            await srv._on_connect(_StubReader(b""), writer)  # type: ignore[arg-type]
    finally:
        await srv.aclose()
