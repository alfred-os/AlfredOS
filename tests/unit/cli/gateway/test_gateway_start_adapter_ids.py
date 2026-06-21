"""G6-5 Task 7/10 (#288): ``alfred gateway start`` sources its hosted adapter set from settings.

The standalone gateway now spawns + supervises the comms adapters an operator opts in via
``Settings.comms_enabled_adapters`` (env ``ALFRED_COMMS_ENABLED_ADAPTERS``, holding
**plugin-package ids** — the ``plugins/<id>/`` dir name). The CLI maps each through the
G6-5 Task-10 reconciliation seam to its canonical ``adapter_kind`` and EXCLUDES the TUI
dial-in kind (the TUI dials the gateway; it is not a spawned adapter), then threads the
canonical subset into ``GatewayProcess(adapter_ids=...)``.

Settings is stubbed in the command module (so the test does not re-run the
manifest-existence validator), but the stub holds the REAL plugin-package ids
(``alfred_discord`` / ``alfred_tui``) — the seam reads their real in-repo manifests, so
the captured ``adapter_ids`` are the canonical wire ids the factory + credential allowlist
key on (``discord``), NOT a per-test fiction. ``GatewayProcess`` is replaced with a double
that captures the ``adapter_ids`` kwarg and returns immediately.
"""

from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

from alfred.cli.gateway import gateway_app


def _patch_process(monkeypatch: pytest.MonkeyPatch, captured: dict[str, object]) -> None:
    class _FakeProcess:
        def __init__(
            self, *, shutdown_event: asyncio.Event, adapter_ids: object, **_kw: object
        ) -> None:
            del shutdown_event
            captured["adapter_ids"] = adapter_ids

        async def run(self) -> None:
            captured["ran"] = True

    monkeypatch.setattr("alfred.gateway.process.GatewayProcess", _FakeProcess)


def _patch_settings(monkeypatch: pytest.MonkeyPatch, enabled: tuple[str, ...]) -> None:
    class _FakeSettings:
        comms_enabled_adapters = enabled

    monkeypatch.setattr("alfred.config.settings.Settings", _FakeSettings)


def test_start_threads_enabled_adapters_into_adapter_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """``("alfred_discord",)`` -> ``GatewayProcess(adapter_ids=["discord"])`` (canonical).

    The operator's plugin-package id resolves to the canonical ``adapter_kind`` the rest
    of the spawn chain keys on, so the gateway is booted with ``discord`` — NOT the dir id.
    """
    captured: dict[str, object] = {}
    _patch_settings(monkeypatch, ("alfred_discord",))
    _patch_process(monkeypatch, captured)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert captured.get("ran") is True
    assert captured.get("adapter_ids") == ["discord"]


def test_start_excludes_the_tui_dial_in_from_adapter_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ``alfred_tui``-only set yields an EMPTY spawned set — the TUI is the dial-in leg."""
    captured: dict[str, object] = {}
    _patch_settings(monkeypatch, ("alfred_tui",))
    _patch_process(monkeypatch, captured)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert captured.get("adapter_ids") == []


def test_start_empty_enabled_set_yields_empty_spawned_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """No enabled adapters -> empty spawned set (behaviour-preserving for G5)."""
    captured: dict[str, object] = {}
    _patch_settings(monkeypatch, ())
    _patch_process(monkeypatch, captured)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert captured.get("adapter_ids") == []


def test_start_keeps_a_mixed_set_minus_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mixed ``(alfred_tui, alfred_discord)`` set drops the dial-in, keeps the canonical id."""
    captured: dict[str, object] = {}
    _patch_settings(monkeypatch, ("alfred_tui", "alfred_discord"))
    _patch_process(monkeypatch, captured)

    result = CliRunner().invoke(gateway_app, ["start"])

    assert result.exit_code == 0, result.stdout
    assert captured.get("adapter_ids") == ["discord"]
