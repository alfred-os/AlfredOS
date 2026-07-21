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
    """perf-001: a hung ``bind``/``getaddrinfo`` costs the boot a deadline, not forever.

    ``start_http_server`` has no timeout of its own; called inline on the boot's event-loop
    thread a stalled resolver would wedge the daemon indefinitely. The wrapper offloads it
    and bounds the wait, so the boot continues with a loud warning.
    """
    monkeypatch.setattr(cmd, "_CORE_METRICS_START_TIMEOUT_S", 0.05)
    started = asyncio.Event()

    def _wedged(_boot_id: str) -> None:
        started.set()
        # Longer than the deadline, short enough not to slow the suite meaningfully.
        import time

        time.sleep(1.0)

    monkeypatch.setattr(cmd, "_start_core_metrics_server", _wedged)
    with structlog.testing.capture_logs() as logs:
        asyncio.run(cmd._start_core_metrics_server_bounded(_BOOT_ID))  # must return, not hang
    assert started.is_set()
    timeouts = [e for e in logs if e["event"] == "daemon.boot.metrics_start_timeout"]
    assert len(timeouts) == 1, f"expected one loud timeout warning, got {logs!r}"
    assert timeouts[0]["boot_id"] == _BOOT_ID


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
