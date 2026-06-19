"""G6-2b-2a (#288): the daemon boot graph builds + registers the AdapterStatusObserver.

The daemon constructs ONE :class:`AdapterStatusObserver` in
``_build_comms_boot_graph`` (with an ``expected_epoch`` callable bound to the live
per-boot epoch) and injects it into every per-adapter session via
``for_comms_adapter(status_observer=...)`` — so a gateway-reported
``gateway.adapter.*`` frame is validated / epoch-reconciled / audited / refused
core-side. Modelled on
``test_daemon_idempotency_store_wired.py``: spy the consumer kwarg through a live
``CliRunner().invoke(daemon_app, ["start"])`` boot.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.bootstrap.lifecycle_epoch import current_boot_epoch
from alfred.cli.daemon import daemon_app
from alfred.comms_mcp.adapter_status_observer import AdapterStatusObserver
from alfred.hooks.registry import HookRegistry
from alfred.plugins.session import AlfredPluginSession

from .conftest import FakeAuditWriter
from .test_daemon_comms_spawn import (
    _ENABLED_ADAPTER,
    _patch_comms_seams,
    quarantine_registry,
)

__all__ = ["quarantine_registry"]  # re-exported fixture; silence the unused-import lint


def test_enabled_adapter_wires_status_observer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """The enabled adapter boots with a real AdapterStatusObserver injected.

    The observer's ``expected_epoch`` callable returns the daemon's live per-boot
    epoch — the SAME value threaded into the runner's ``lifecycle.start`` handshake,
    so a genuine live ``up`` matches and a forged epoch is refused.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    captured: list[Any] = []
    original = AlfredPluginSession.for_comms_adapter.__func__  # type: ignore[attr-defined]

    async def _spy_for_comms_adapter(cls: Any, **kwargs: Any) -> Any:
        captured.append(kwargs.get("status_observer"))
        return await original(cls, **kwargs)

    monkeypatch.setattr(
        AlfredPluginSession,
        "for_comms_adapter",
        classmethod(_spy_for_comms_adapter),
    )
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # Exactly one session built, wired with a real core-side status observer.
    assert len(captured) == 1
    observer = captured[0]
    assert isinstance(observer, AdapterStatusObserver)
    # The observer's expected_epoch reads the daemon's live per-boot epoch.
    assert observer._expected_epoch() == current_boot_epoch()
