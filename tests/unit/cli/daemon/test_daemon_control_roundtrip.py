"""End-to-end control-plane roundtrip: real server + real client over a real socket (#288).

The genuine proof the channel works — a real :class:`DaemonControlServer` bound over a
tmp socket holding a fake observer + reconciler with one crashed adapter, queried by the
real :func:`query_daemon_control`, returns a parsed result carrying that adapter as
``crashed`` (correction 4 / test-M5). The failure-mode roundtrip (unknown method) goes
against the REAL server too.
"""

from __future__ import annotations

import contextlib
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from alfred.cli.daemon._daemon_control_client import query_daemon_control
from alfred.cli.daemon._daemon_control_protocol import (
    STATUS_QUERY_METHOD,
    DaemonStatusResult,
)
from alfred.cli.daemon._daemon_control_server import DaemonControlServer
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler

pytestmark = pytest.mark.asyncio

_EPOCH = "e" * 32
_NOW = datetime(2026, 6, 20, 11, 0, 0, tzinfo=UTC)


class _FakeAudit:
    async def append_schema(self, **_kwargs: object) -> None:
        return None


@pytest.fixture
def short_runtime(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="alfrt-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home) / ".run" / "alfred"


async def _server_with_crashed_adapter(path: Path) -> DaemonControlServer:
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(
        audit=_FakeAudit(),
        expected_epoch=lambda: _EPOCH,
        now=lambda: _NOW,
        reconciler=reconciler,
    )
    await observer.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "RuntimeError",
            "detail": "boom",
            "host_restart_seq": 0,
        },
    )
    srv = DaemonControlServer(observer=observer, reconciler=reconciler, path=path)
    await srv.start()
    return srv


async def test_roundtrip_status_query_returns_crashed_adapter(short_runtime: Path) -> None:
    path = short_runtime / "control.sock"
    srv = await _server_with_crashed_adapter(path)
    try:
        response = await query_daemon_control(STATUS_QUERY_METHOD, path=path)
        assert response.error is None
        assert response.result is not None
        result = DaemonStatusResult.model_validate(response.result)
        line = result.adapters["discord"]
        assert line.state == "crashed"
        assert line.crash_incident_count == 1
        assert line.latest_crash is not None
        # No secret/T3 ever crosses the wire.
        assert "boom" not in response.model_dump_json()
    finally:
        await srv.aclose()


async def test_roundtrip_unknown_method_returns_error(short_runtime: Path) -> None:
    # test-M5: a failure-mode roundtrip against the REAL server.
    path = short_runtime / "control.sock"
    srv = await _server_with_crashed_adapter(path)
    try:
        response = await query_daemon_control("no.such.method", path=path)
        assert response.result is None
        assert response.error is not None
        assert response.error.startswith("unknown_method")
    finally:
        await srv.aclose()


async def test_roundtrip_uses_default_path_when_unspecified(short_runtime: Path) -> None:
    # The default-path branch: a server bound at the default ~/.run/alfred/control.sock
    # (the fixture points $HOME there) answers a query with NO explicit ``path=``.
    from alfred.cli.daemon._daemon_control_server import default_control_socket_path

    srv = await _server_with_crashed_adapter(default_control_socket_path())
    try:
        response = await query_daemon_control(STATUS_QUERY_METHOD)
        assert response.error is None
    finally:
        await srv.aclose()
        with contextlib.suppress(FileNotFoundError):
            default_control_socket_path().unlink()
