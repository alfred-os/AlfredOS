"""#470: the daemon boot serves /metrics over the curated core registry.

``_start_core_metrics_server`` is a module-scope, monkeypatchable seam in
``alfred.cli.daemon._commands`` that ``_start_async`` calls early — before the
``Supervisor`` is constructed, so the call sits outside the #472 cancellation-safe
teardown ``finally`` (which only tracks the Supervisor's lifecycle). This suite
proves the seam resolves ``ALFRED_CORE_METRICS_PORT`` (default 9465) and passes the
CURATED core registry (:func:`alfred.observability.core_metrics.build_core_registry`)
— not the default global registry — to ``start_metrics_server``.

This test drives the REAL seam body, so it overrides the package-wide
``_stub_core_metrics_server`` autouse fixture (``conftest.py``) with a no-op of the
same name — the standard pytest pattern for exempting one module from a conftest
autouse fixture. Only ``start_metrics_server`` (the actual socket-binding call) is
mocked, so no real port is ever bound.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

import alfred.cli.daemon._commands as cmd


@pytest.fixture(autouse=True)
def _stub_core_metrics_server() -> None:
    """Override the conftest-wide stub: this suite exercises the real seam."""


def test_boot_serves_curated_registry_on_core_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # A DISTINCT value from the 9465 default (final-review required fix): if the seam
    # ignored the env var entirely and always resolved to the default, this test would
    # still have passed against 9465 — asserting a value equal to the default is a
    # vacuous oracle (the seam not doing its job wouldn't fail it).
    monkeypatch.setenv("ALFRED_CORE_METRICS_PORT", "9999")
    with patch.object(cmd, "start_metrics_server", return_value=True) as m:
        cmd._start_core_metrics_server()  # the extracted monkeypatchable seam
    (port,), kwargs = m.call_args
    assert port == 9999
    assert kwargs["registry"] is not None  # curated, not the default registry


def test_boot_resolves_default_port_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Absent ``ALFRED_CORE_METRICS_PORT``, the seam falls back to 9465."""
    monkeypatch.delenv("ALFRED_CORE_METRICS_PORT", raising=False)
    with patch.object(cmd, "start_metrics_server", return_value=True) as m:
        cmd._start_core_metrics_server()
    (port,), _kwargs = m.call_args
    assert port == 9465
