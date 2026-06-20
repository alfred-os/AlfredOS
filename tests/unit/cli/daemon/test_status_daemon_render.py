"""``alfred daemon status`` renders the live control-plane query (#288, ADR-0038).

After the pidfile subset, ``status_daemon`` dials the control socket and renders the live
per-adapter status. These tests run a REAL ``DaemonControlServer`` in a BACKGROUND THREAD
(its own event loop, so it actually services the connection while the synchronous Typer
command's ``asyncio.run`` dials it — mirroring the real separate-process daemon/CLI split)
over the default path (the fixture points ``$HOME`` at a short tmp dir):

* a crashed adapter renders its line with the LOCALIZED state token (correction test-L5 —
  via ``t()``, never the raw ``"crashed"`` literal) + the latest-crash diagnostic line;
* NO daemon (no socket) -> the existing not-running message, exit 0;
* a ``crash_signal_source == "both"`` renders the SEC-02 informational origin.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._daemon_control_server import (
    DaemonControlServer,
    default_control_socket_path,
)
from alfred.cli.daemon._daemon_pidfile import write_pidfile
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.comms_mcp.crash_incident_reconciler import CrashIncidentReconciler
from alfred.i18n import t

_EPOCH = "e" * 32
_NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)


class _FakeAudit:
    async def append_schema(self, **_kwargs: object) -> None:
        return None


@pytest.fixture
def short_home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Short ``$HOME`` (control socket honours it) + a tempdir pidfile path.

    The control socket path honours ``$HOME`` at call time (``runtime_dir()``), but the
    pidfile default dir is resolved at IMPORT time (``Path.home()``), so it must be
    monkeypatched separately — otherwise the render tests would pollute the real
    ``~/.run/alfred/daemon.pid``.
    """
    with tempfile.TemporaryDirectory(prefix="alfstat-") as home:
        monkeypatch.setenv("HOME", home)
        pidfile = Path(home) / "daemon.pid"
        monkeypatch.setattr("alfred.cli.daemon._commands.default_pidfile_path", lambda: pidfile)
        yield Path(home)


def _write_live_pidfile() -> None:
    """Write a pidfile for THIS (live) process so ``status_daemon`` reaches the control dial.

    ``status_daemon`` renders the pidfile subset first and returns early on a missing /
    stale pidfile — so the render tests must present a live pidfile before the control
    dial is exercised. Uses the (monkeypatched) command-module path.
    """
    from alfred.cli.daemon import _commands

    write_pidfile(
        _commands.default_pidfile_path(),
        pid=os.getpid(),
        boot_id="test-boot",
        started_at=_NOW.isoformat(),
    )


def _build() -> tuple[AdapterStatusObserver, CrashIncidentReconciler]:
    reconciler = CrashIncidentReconciler()
    observer = AdapterStatusObserver(
        audit=_FakeAudit(),
        expected_epoch=lambda: _EPOCH,
        now=lambda: _NOW,
        reconciler=reconciler,
    )
    return observer, reconciler


async def _seed_crashed(
    observer: AdapterStatusObserver,
    reconciler: CrashIncidentReconciler,
    *,
    both: bool,
) -> None:
    await observer.observe(
        "gateway.adapter.crashed",
        {
            "adapter_id": "discord",
            "error_class": "RuntimeError",
            "detail": "boom",
            "host_restart_seq": 0,
        },
    )
    if both:
        # An in-child crash for the SAME incarnation upgrades the source to "both"
        # (SEC-02: a diagnostic-coverage hint, NOT authenticated corroboration).
        reconciler.observe_child_crash(adapter_id="discord")


async def _seed_breaker_open(observer: AdapterStatusObserver) -> None:
    """Record a ``breaker_open`` adapter status so the render renders that state token.

    Used by the Fix-2 (test-L5) parametrization: the ``crashed`` catalog value is
    literally ``"crashed"`` (token == raw), so it cannot prove ``t()`` ran; the
    ``breaker_open`` catalog value is ``"breaker open"`` (a SPACE), which a raw
    ``"breaker_open"`` interpolation would never produce — so asserting it proves the
    render localized the wire token through ``t()`` rather than echoing it raw.
    """
    await observer.observe(
        "gateway.adapter.breaker_open",
        {"adapter_id": "discord", "retry_after_seconds": 5},
    )


@contextmanager
def _running_control_server(
    *, crashed: bool, both: bool = False, breaker_open: bool = False
) -> Iterator[None]:
    """Run a real ``DaemonControlServer`` in a background thread with its own loop.

    The server must service the connection while the synchronous Typer command's
    ``asyncio.run`` dials it — so it lives in a separate loop on a daemon thread (the
    real daemon/CLI split is two processes; this is the in-test analog).
    """
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    srv_box: list[DaemonControlServer] = []

    def _run() -> None:
        asyncio.set_event_loop(loop)
        observer, reconciler = _build()
        if crashed:
            loop.run_until_complete(_seed_crashed(observer, reconciler, both=both))
        if breaker_open:
            loop.run_until_complete(_seed_breaker_open(observer))
        srv = DaemonControlServer(
            observer=observer, reconciler=reconciler, path=default_control_socket_path()
        )
        loop.run_until_complete(srv.start())
        srv_box.append(srv)
        ready.set()
        loop.run_forever()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    assert ready.wait(timeout=5.0), "control server failed to start"
    try:
        yield
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5.0)
        # Reap on the (now stopped) loop, then close it.
        loop.run_until_complete(srv_box[0].aclose())
        loop.close()


def test_render_shows_localized_state_and_latest_crash(short_home: Path) -> None:
    del short_home
    with _running_control_server(crashed=True):
        _write_live_pidfile()
        result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    # The state token is the LOCALIZED catalog value, not the raw "crashed" literal.
    assert t("daemon.status.state.crashed") in result.output
    assert "discord" in result.output
    # The latest-crash diagnostic line is present (the source is rendered).
    assert "gateway" in result.output


def test_render_localizes_state_token_with_a_space(short_home: Path) -> None:
    """Fix-2 (test-L5): the ``breaker_open`` token proves the state went through ``t()``.

    The ``crashed`` catalog value IS literally ``"crashed"`` (token == raw), so the
    existing test cannot distinguish a localized token from a raw interpolation. The
    ``breaker_open`` catalog value is ``"breaker open"`` (with a SPACE) — distinct from
    the raw wire token ``"breaker_open"`` — so asserting the spaced value is present AND
    the raw token absent proves the render localized through ``t()``.
    """
    del short_home
    with _running_control_server(crashed=False, breaker_open=True):
        _write_live_pidfile()
        result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    localized = t("daemon.status.state.breaker_open")
    assert localized == "breaker open", localized  # guards the premise (space != underscore)
    assert localized in result.output
    assert "breaker_open" not in result.output  # the raw wire token never reaches the eye


def test_render_both_source_is_informational(short_home: Path) -> None:
    del short_home
    with _running_control_server(crashed=True, both=True):
        _write_live_pidfile()
        result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert "both" in result.output  # SEC-02 informational origin


def test_render_no_daemon_is_not_running(short_home: Path) -> None:
    del short_home
    # No server running -> the existing not-running path, exit 0.
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert t("daemon.status.not_running") in result.output


def test_render_no_adapters_section_when_empty(short_home: Path) -> None:
    del short_home
    with _running_control_server(crashed=False):
        _write_live_pidfile()
        result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert t("daemon.status.adapters_none") in result.output


# ---------------------------------------------------------------------------
# Fix-1 (#288 MEDIUM): the render must DEGRADE on EVERY control-plane error
# (not only ``DaemonControlUnavailableError``) and a server-returned
# ``response.error`` must be DISTINGUISHABLE from a healthy zero-adapter daemon.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error_name", ["DaemonControlAuthError", "DaemonControlProtocolError"])
def test_render_degrades_on_non_unavailable_control_error(
    short_home: Path, monkeypatch: pytest.MonkeyPatch, error_name: str
) -> None:
    """An auth / protocol fault degrades to the "status unavailable" line, exit 0, no crash.

    These are subclasses of ``DaemonControlError`` (NOT ``DaemonControlUnavailableError``),
    so the OLD render — which caught only ``DaemonControlUnavailableError`` — would let them
    crash the synchronous Typer command. The render now catches the base + degrades.
    """
    del short_home
    from alfred.cli.daemon import _daemon_control_client

    exc_type = getattr(_daemon_control_client, error_name)

    async def _raise(*_args: object, **_kwargs: object) -> object:
        raise exc_type("boom")

    monkeypatch.setattr(_daemon_control_client, "query_daemon_control", _raise)
    _write_live_pidfile()
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert result.exception is None, result.exception
    assert t("daemon.status.adapters_unavailable") in result.output


def test_render_degrades_on_server_returned_error(
    short_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server-returned ``response.error`` renders the "status unavailable" line.

    DISTINGUISHABLE from a healthy zero-adapter daemon (which renders ``adapters_none``) —
    the OLD render silently returned, indistinguishable from healthy.
    """
    del short_home
    from alfred.cli.daemon import _daemon_control_client
    from alfred.cli.daemon._daemon_control_protocol import ControlResponse

    async def _error_response(*_args: object, **_kwargs: object) -> ControlResponse:
        return ControlResponse(id="1", result=None, error="handler_failed:status.query")

    monkeypatch.setattr(_daemon_control_client, "query_daemon_control", _error_response)
    _write_live_pidfile()
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert result.exception is None, result.exception
    assert t("daemon.status.adapters_unavailable") in result.output
    assert t("daemon.status.adapters_none") not in result.output


def test_render_degrades_on_malformed_result_validation_error(
    short_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``response.result`` that fails ``DaemonStatusResult`` validation degrades, not crash.

    CR T1: ``DaemonStatusResult.model_validate(response.result)`` raises pydantic
    ``ValidationError`` (a ``ValueError`` subclass) on a malformed result (a wire/version
    skew). UNCAUGHT it crashed the read-only ``alfred daemon status``; the render now
    degrades to the "unavailable" line — exit 0, no traceback.
    """
    del short_home
    from alfred.cli.daemon import _daemon_control_client
    from alfred.cli.daemon._daemon_control_protocol import ControlResponse

    async def _bad_result(*_args: object, **_kwargs: object) -> ControlResponse:
        # ``adapters`` must be a dict of AdapterStatusLine: a string passes the loose
        # ``ControlResponse.result: dict[str, object]`` shape but fails DaemonStatusResult.
        return ControlResponse(id="1", result={"adapters": "not-a-mapping"})

    monkeypatch.setattr(_daemon_control_client, "query_daemon_control", _bad_result)
    _write_live_pidfile()
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert result.exception is None, result.exception
    assert t("daemon.status.adapters_unavailable") in result.output
    assert t("daemon.status.adapters_none") not in result.output


def test_render_unavailable_stays_silent(short_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``DaemonControlUnavailableError`` keeps the existing silent return (no extra line).

    The pidfile subset already rendered; the control socket is simply not reachable, so the
    "status unavailable" breadcrumb would be noise on the already-said not-running posture.
    """
    del short_home
    from alfred.cli.daemon import _daemon_control_client

    async def _raise(*_args: object, **_kwargs: object) -> object:
        raise _daemon_control_client.DaemonControlUnavailableError("no socket")

    monkeypatch.setattr(_daemon_control_client, "query_daemon_control", _raise)
    _write_live_pidfile()
    result = CliRunner().invoke(daemon_app, ["status"])
    assert result.exit_code == 0, result.output
    assert t("daemon.status.adapters_unavailable") not in result.output
