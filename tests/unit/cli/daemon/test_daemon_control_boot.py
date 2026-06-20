"""The daemon boot loop binds + reaps the control server (#288, ADR-0038).

Modelled on the comms-boot harness (``test_daemon_comms_spawn`` / the
``boot_success_env`` fixture): a live ``CliRunner().invoke(daemon_app, ["start"])`` with
one enabled comms adapter. The control server is started before ``wait_for_shutdown`` and
reaped in the drain ``finally``, so we override ``wait_for_shutdown`` to dial the REAL
control socket WHILE the daemon is up — proving the socket answers (a live roundtrip, not
a spy). After shutdown the socket file is gone (reaped on every exit path) and a dial
raises ``DaemonControlUnavailableError``.
"""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._daemon_control_client import (
    DaemonControlUnavailableError,
    query_daemon_control,
)
from alfred.cli.daemon._daemon_control_protocol import (
    STATUS_QUERY_METHOD,
    DaemonStatusResult,
)
from alfred.cli.daemon._daemon_control_server import default_control_socket_path
from alfred.hooks.registry import HookRegistry

from .conftest import FakeAuditWriter
from .test_daemon_comms_spawn import (
    _ENABLED_ADAPTER,
    _patch_comms_seams,
    quarantine_registry,
)

__all__ = ["quarantine_registry"]  # re-exported fixture; silence the unused-import lint


@pytest.fixture
def short_home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point ``$HOME`` at a SHORT tmp dir so the control socket path fits AF_UNIX."""
    with tempfile.TemporaryDirectory(prefix="alfctlboot-") as home:
        monkeypatch.setenv("HOME", home)
        yield Path(home)


def test_boot_binds_control_socket_and_reaps_on_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
    short_home: Path,
) -> None:
    del quarantine_registry
    del patch_quarantine_child_spawn
    del short_home
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    dialed: list[DaemonStatusResult] = []
    socket_present_during_run: list[bool] = []

    async def _dial_while_up(_supervisor: object) -> None:
        # The control server is started BEFORE wait_for_shutdown and reaped AFTER, so a
        # dial here hits the live socket. The fake harness has no live frames, so
        # ``adapters`` is legitimately empty — the proof is that the REAL socket answered.
        socket_present_during_run.append(default_control_socket_path().exists())
        response = await query_daemon_control(STATUS_QUERY_METHOD)
        assert response.error is None and response.result is not None
        dialed.append(DaemonStatusResult.model_validate(response.result))

    monkeypatch.setattr("alfred.cli.daemon._commands.wait_for_shutdown", _dial_while_up)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # The socket existed + answered a live query while the daemon was up.
    assert socket_present_during_run == [True]
    assert len(dialed) == 1
    assert dialed[0].adapters == {}  # no live frames in the fake harness

    # ... and the socket is reaped on shutdown (every exit path).
    assert not default_control_socket_path().exists()
    with pytest.raises(DaemonControlUnavailableError):
        asyncio.run(query_daemon_control(STATUS_QUERY_METHOD))


def test_zero_adapter_boot_binds_control_socket_with_empty_adapters(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    short_home: Path,
) -> None:
    # CR T0: a ZERO-adapter daemon (no comms graph) must STILL bind the control plane —
    # it is a DAEMON control plane, not adapter-specific. A live dial answers an EMPTY
    # adapter map (the ``adapters_none`` posture), proving the socket binds even with
    # ``comms_graph is None`` (no quarantine seams / spawn fixtures needed — there is no
    # adapter to spawn).
    del short_home
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[]")

    dialed: list[DaemonStatusResult] = []
    socket_present_during_run: list[bool] = []

    async def _dial_while_up(_supervisor: object) -> None:
        socket_present_during_run.append(default_control_socket_path().exists())
        response = await query_daemon_control(STATUS_QUERY_METHOD)
        assert response.error is None and response.result is not None
        dialed.append(DaemonStatusResult.model_validate(response.result))

    monkeypatch.setattr("alfred.cli.daemon._commands.wait_for_shutdown", _dial_while_up)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    assert socket_present_during_run == [True]
    assert len(dialed) == 1
    assert dialed[0].adapters == {}  # zero-adapter daemon -> empty map, not "unavailable"

    # ... and the socket is reaped on shutdown (every exit path).
    assert not default_control_socket_path().exists()


def test_control_socket_reaped_on_post_start_boot_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
    short_home: Path,
) -> None:
    # test-M6: a boot failure AFTER the control server starts (here: ``wait_for_shutdown``
    # raises) must STILL unlink the socket via the drain ``finally`` (the "EVERY exit path"
    # reap). Guards a regression that moves the ``control_server`` declaration back inside
    # the supervisor ``try`` (where the finally could NameError on it).
    del quarantine_registry
    del patch_quarantine_child_spawn
    del short_home
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    socket_present_before_failure: list[bool] = []

    async def _fail_after_start(_supervisor: object) -> None:
        socket_present_before_failure.append(default_control_socket_path().exists())
        raise RuntimeError("simulated post-start boot failure")

    monkeypatch.setattr("alfred.cli.daemon._commands.wait_for_shutdown", _fail_after_start)

    result = CliRunner().invoke(daemon_app, ["start"])
    # The boot failed (the injected fault propagates), but the socket existed at the
    # point of failure ...
    assert socket_present_before_failure == [True]
    assert result.exit_code != 0
    # ... and was STILL reaped by the drain finally.
    assert not default_control_socket_path().exists()
