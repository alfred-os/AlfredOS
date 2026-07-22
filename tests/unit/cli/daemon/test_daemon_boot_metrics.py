"""#470: the daemon boot serves /metrics over the curated core registry.

``_start_core_metrics_server`` is a module-scope, monkeypatchable seam in
``alfred.cli.daemon._commands`` that ``_start_async`` calls early — before the
``Supervisor`` is constructed, so the call sits outside the #472 cancellation-safe
teardown ``finally`` (which only tracks the Supervisor's lifecycle). This suite
proves the seam resolves ``ALFRED_CORE_METRICS_PORT`` (default 9465), passes the
CURATED core registry (:func:`alfred.observability.core_metrics.build_core_registry`)
— not the default global registry — to ``start_metrics_server``, and that EVERY one of
its failure modes is loud-and-continue rather than a boot-killing traceback.

This test drives the REAL seam body, so it overrides the package-wide
``_stub_core_metrics_server`` autouse fixture (``conftest.py``) with a no-op of the
same name — the standard pytest pattern for exempting one module from a conftest
autouse fixture. Only ``start_metrics_server`` (the actual socket-binding call) is
mocked, so no real port is ever bound.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import structlog.testing
from prometheus_client import CollectorRegistry
from typer.testing import CliRunner

import alfred.cli.daemon._commands as cmd
from alfred.cli.daemon import daemon_app
from alfred.observability.core_metrics import CORE_OWNED_COLLECTORS

from .conftest import FakeAuditWriter

_BOOT_ID = "boot-id-fixture"

# The deadline the wedged-bind tests actually assert on: how long the WHOLE
# ``asyncio.run(...)`` (boot + loop teardown) may take while a bind is parked.
# Generous against CI jitter yet far below the ceiling below, so the two can
# never be confused for each other.
_RETURN_DEADLINE_S = 2.0

# Safety net inside every wedge fake: each blocks on an ``Event`` that the test
# releases in a ``finally``, but it also self-releases after this ceiling so a
# regression can never park a suite thread forever. It must sit well ABOVE
# ``_RETURN_DEADLINE_S`` — a regression that re-couples the bind to loop
# teardown then shows up as a deadline breach (a clean assertion failure)
# rather than as a hung run.
_WEDGE_CEILING_S = 10.0


@pytest.fixture(autouse=True)
def _stub_core_metrics_server() -> None:
    """Override the conftest-wide stub: this suite exercises the real seam."""


def test_boot_serves_curated_registry_on_core_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # A DISTINCT value from the 9465 default (final-review required fix): if the seam
    # ignored the env var entirely and always resolved to the default, this test would
    # still have passed against 9465 — asserting a value equal to the default is a
    # vacuous oracle (the seam not doing its job wouldn't fail it).
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9999")
    # test-001: the previous oracle was `kwargs["registry"] is not None`, which the
    # reviewer passed by substituting the DEFAULT global registry — i.e. it could not
    # catch re-exposing stale `gateway_*` families, the one thing the curated registry
    # exists to prevent. Pin IDENTITY against a sentinel that only `build_core_registry`
    # can supply, so "some registry" is no longer good enough.
    sentinel = CollectorRegistry()
    with (
        patch.object(cmd, "build_core_registry", return_value=sentinel),
        patch.object(cmd, "start_metrics_server", return_value=True) as m,
    ):
        cmd._start_core_metrics_server(_BOOT_ID)
    (port,), kwargs = m.call_args
    assert port == 9999
    assert kwargs["registry"] is sentinel


def test_boot_registry_holds_exactly_the_curated_collectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry actually handed to the exposition holds the curated set — no more, no less.

    Complements the identity assertion above: identity proves the seam calls the right
    builder, this proves the object that builder returns carries the reviewed collector set
    (so a default-registry substitution, which would carry `gateway_*` too, fails here).
    """
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9999")
    with patch.object(cmd, "start_metrics_server", return_value=True) as m:
        cmd._start_core_metrics_server(_BOOT_ID)
    registry = m.call_args.kwargs["registry"]
    assert set(registry._collector_to_names) == set(CORE_OWNED_COLLECTORS)


def test_boot_resolves_default_port_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Absent ``ALFRED_CORE_METRICS_PORT``, the seam falls back to 9465."""
    monkeypatch.delenv("ALFRED_CORE_METRICS_PORT", raising=False)
    with patch.object(cmd, "start_metrics_server", return_value=True) as m:
        cmd._start_core_metrics_server(_BOOT_ID)
    (port,), _kwargs = m.call_args
    assert port == 9465


def test_seam_skips_exposition_on_a_malformed_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """err-001: a bad port value logs LOUD and skips the exposition — it never raises.

    ``resolve_metrics_port`` raises ``ValueError`` on a malformed value, and ``start_daemon``
    only catches ``_BootRefusedError`` — so an escaping ``ValueError`` crashes the entire
    daemon boot with a raw traceback over one bad ``.env`` line.
    """
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "notaport")
    with (
        patch.object(cmd, "start_metrics_server", return_value=True) as m,
        structlog.testing.capture_logs() as logs,
    ):
        cmd._start_core_metrics_server(_BOOT_ID)  # must NOT raise
    assert m.call_args is None, "a malformed port must never reach start_metrics_server"
    bad = [e for e in logs if e["event"] == "daemon.boot.metrics_bad_port"]
    assert len(bad) == 1, f"expected one loud bad-port warning, got {logs!r}"
    assert bad[0]["boot_id"] == _BOOT_ID
    assert bad[0]["env_var"] == "ALFRED_CORE_METRICS_PORT"


def test_seam_logs_a_boot_scoped_warning_on_bind_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """err-002: the seam consumes ``start_metrics_server``'s bool and tags the failure.

    ``start_metrics_server``'s own ``metrics.bind_failed`` cannot carry a ``boot_id`` (it is
    shared with the gateway and knows nothing about a boot), and previously the seam threw
    the return value away — leaving a bind failure as the one boot-path event an operator
    could not correlate to a boot.
    """
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9999")
    with (
        patch.object(cmd, "start_metrics_server", return_value=False),
        structlog.testing.capture_logs() as logs,
    ):
        cmd._start_core_metrics_server(_BOOT_ID)
    failures = [e for e in logs if e["event"] == "daemon.boot.metrics_bind_failed"]
    assert len(failures) == 1, f"expected one boot-scoped bind-failure warning, got {logs!r}"
    assert failures[0]["boot_id"] == _BOOT_ID
    assert failures[0]["port"] == 9999


def test_seam_emits_no_failure_warning_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """The err-002 warning is scoped to failure — a healthy bind stays quiet."""
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9999")
    with (
        patch.object(cmd, "start_metrics_server", return_value=True),
        structlog.testing.capture_logs() as logs,
    ):
        cmd._start_core_metrics_server(_BOOT_ID)
    assert not [e for e in logs if e["event"].startswith("daemon.boot.metrics_")]


def test_bounded_wrapper_gives_up_on_a_wedged_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    """perf-001: a wedged ``bind``/``getaddrinfo`` costs the boot a deadline, not forever.

    ``start_http_server`` has no timeout of its own; called inline on the boot's event-loop
    thread a stalled resolver would wedge the daemon indefinitely. The wrapper runs it on a
    thread nobody joins and bounds the wait, so the boot continues with a loud warning.

    The oracle is the WALL CLOCK across the whole ``asyncio.run(...)``, not just the warning.
    Asserting only "the timeout was logged" passes against an implementation that logs the
    warning on time and then wedges on loop TEARDOWN — which is exactly what
    ``asyncio.wait_for(asyncio.to_thread(...))`` does, because ``asyncio.run`` closes by
    calling ``loop.shutdown_default_executor()``, which JOINS the very thread the timeout
    walked away from. Timing out the *wait* is not the invariant; returning is.
    """
    monkeypatch.setattr(cmd, "_CORE_METRICS_START_TIMEOUT_S", 0.05)
    entered = threading.Event()
    release = threading.Event()

    def _wedged(_boot_id: str) -> None:
        entered.set()
        release.wait(_WEDGE_CEILING_S)

    monkeypatch.setattr(cmd, "_start_core_metrics_server", _wedged)
    try:
        started_at = time.monotonic()
        with structlog.testing.capture_logs() as logs:
            asyncio.run(cmd._start_core_metrics_server_bounded(_BOOT_ID))  # must return, not hang
        elapsed = time.monotonic() - started_at
    finally:
        # Unpark the fake unconditionally so a failing assertion cannot leave a live
        # thread behind for the rest of the session.
        release.set()
    assert entered.wait(_RETURN_DEADLINE_S), "the seam never ran off-loop"
    assert elapsed < _RETURN_DEADLINE_S, (
        f"asyncio.run took {elapsed:.2f}s with the bind wedged — the deadline only stops "
        "the WAIT; the bind must also be off any executor asyncio joins at teardown"
    )
    timeouts = [e for e in logs if e["event"] == "daemon.boot.metrics_start_timeout"]
    assert len(timeouts) == 1, f"expected one loud timeout warning, got {logs!r}"
    assert timeouts[0]["boot_id"] == _BOOT_ID


def test_a_late_unwedging_bind_never_raises_into_its_own_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The completion signal is fire-and-forget across an already-CLOSED loop.

    Walking away from the bind means the loop it would report back to is gone by the time it
    unwedges (if it ever does). ``call_soon_threadsafe`` on a closed loop raises
    ``RuntimeError``, and unhandled in a bare thread that surfaces as a spurious traceback on
    the operator's console minutes after a boot that already logged its timeout and moved on.
    """
    monkeypatch.setattr(cmd, "_CORE_METRICS_START_TIMEOUT_S", 0.05)
    release = threading.Event()
    thread_errors: list[object] = []
    monkeypatch.setattr(threading, "excepthook", thread_errors.append)

    def _wedged(_boot_id: str) -> None:
        release.wait(_WEDGE_CEILING_S)

    monkeypatch.setattr(cmd, "_start_core_metrics_server", _wedged)
    before = {t.ident for t in threading.enumerate()}
    try:
        asyncio.run(cmd._start_core_metrics_server_bounded(_BOOT_ID))
        # Identify the worker while it is still parked — after the release it may be gone.
        worker = next(
            t
            for t in threading.enumerate()
            if t.name == "alfred-core-metrics-bind" and t.ident not in before
        )
    finally:
        release.set()  # the loop is now closed: its completion signal has no home
    worker.join(_RETURN_DEADLINE_S)
    assert not worker.is_alive(), "the unparked bind thread never finished"
    assert not thread_errors, f"the late completion signal escaped its thread: {thread_errors!r}"


def test_bind_thread_converts_an_unexpected_seam_error_to_a_structured_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unexpected seam error becomes a loud, boot-correlated event, not a raw traceback.

    ``_start_core_metrics_server`` handles its OWN expected faults (bad port, bind failure) and
    returns; anything still escaping runs on a bare daemon thread, where an unhandled exception
    would print a raw, ``boot_id``-less traceback via ``threading.excepthook`` — breaking the
    seam's "every failure is a structured, loud-and-continue, boot-correlated event" contract.
    The bind wrapper converts it to that shape while STILL signalling completion, so the boot
    neither wedges on the deadline nor spews an uncorrelated traceback.
    """

    def _boom(_boot_id: str) -> None:
        raise RuntimeError("unexpected seam failure")

    monkeypatch.setattr(cmd, "_start_core_metrics_server", _boom)
    started_at = time.monotonic()
    with structlog.testing.capture_logs() as logs:
        asyncio.run(cmd._start_core_metrics_server_bounded(_BOOT_ID))  # must NOT raise
    elapsed = time.monotonic() - started_at

    # It completed via the finally-signal, not the deadline: fast return AND no timeout event.
    assert elapsed < _RETURN_DEADLINE_S
    assert not [e for e in logs if e["event"] == "daemon.boot.metrics_start_timeout"]
    unexpected = [e for e in logs if e["event"] == "daemon.boot.metrics_start_unexpected_error"]
    assert len(unexpected) == 1, f"expected one loud unexpected-error warning, got {logs!r}"
    assert unexpected[0]["boot_id"] == _BOOT_ID
    assert "unexpected seam failure" in unexpected[0]["error"]


def test_bounded_wrapper_forwards_the_boot_id_on_the_happy_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wrapper is a deadline, not a rewrite: the seam still runs with the boot's id."""
    seen: list[str] = []
    monkeypatch.setattr(cmd, "_start_core_metrics_server", seen.append)
    asyncio.run(cmd._start_core_metrics_server_bounded(_BOOT_ID))
    assert seen == [_BOOT_ID]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.O_NOFOLLOW / os.getuid pidfile locking",
)
def test_malformed_port_does_not_crash_the_daemon_boot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """err-001 at the BOOT level — the regression the seam-scoped tests cannot prove.

    The seam tests above call ``_start_core_metrics_server`` directly, so they would still
    pass if ``_start_async`` invoked it somewhere a raised ``ValueError`` escaped. This drives
    the real ``alfred daemon start`` path with a malformed ``ALFRED_CORE_METRICS_PORT`` and
    asserts the boot completes normally (exit 0, no traceback) with the exposition skipped —
    the pre-existing bad-port tests only covered ``_healthcheck.py``.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "notaport")
    with patch.object(cmd, "start_metrics_server", return_value=True) as m:
        result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert m.call_args is None, "a malformed port must never reach start_metrics_server"
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS"), "boot did not complete"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: os.O_NOFOLLOW / os.getuid pidfile locking",
)
def test_a_wedged_bind_never_delays_the_boot_or_its_teardown(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    """perf-001 at the BOOT level — the whole ``asyncio.run`` returns with the bind parked.

    The seam-scoped wedge test above proves the wrapper itself returns; this proves the
    property survives at the only altitude that matters to an operator: ``alfred daemon
    start``, whose ``asyncio.run(_start_async())`` also has to CLOSE its loop. Anything that
    leaves the parked bind on a pool asyncio joins during close (the default executor)
    converts a startup hang into an EXIT hang — strictly worse, since the boot then looks
    healthy right up until shutdown never completes.

    The boot must still complete normally: exit 0, a ``DAEMON_BOOT_FIELDS`` row, and the
    exposition simply absent (loud-and-continue).
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setattr(cmd, "_CORE_METRICS_START_TIMEOUT_S", 0.05)
    entered = threading.Event()
    release = threading.Event()

    def _wedged_bind(_port: int, registry: object | None = None) -> bool:
        entered.set()
        release.wait(_WEDGE_CEILING_S)
        return True

    monkeypatch.setattr(cmd, "start_metrics_server", _wedged_bind)
    try:
        started_at = time.monotonic()
        result = CliRunner().invoke(daemon_app, ["start"])
        elapsed = time.monotonic() - started_at
    finally:
        release.set()
    assert entered.wait(_RETURN_DEADLINE_S), "the bind never ran"
    assert elapsed < _RETURN_DEADLINE_S, (
        f"alfred daemon start took {elapsed:.2f}s with the metrics bind wedged"
    )
    assert result.exit_code == 0, result.output
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS"), "boot did not complete"
