"""PR-S4-11a substrate proof — the host comms transport + serve loop, end to end.

The keystone the whole comms-MCP runtime stands on: a real, launcher-spawned
comms plugin emits a plugin -> host notification, and the host's
:class:`CommsPluginRunner` (driving a :class:`CommsStdioTransport`) routes it
all the way into the session's handler fan-out. Before this PR no host-side
line-delimited transport existed and nothing read unsolicited plugin -> host
frames, so an ``adapter.binding_request`` (or ``inbound.message``) could never
reach a handler in production. This test exercises that path against the REAL
``bin/alfred-plugin-launcher.sh`` and the real ``alfred_comms_test`` reference
plugin as a subprocess — no fake transport, no in-process shortcut.

Why the binding trigger (not ``inbound.message``)
-------------------------------------------------
The reference plugin's ``inject_inbound`` trigger is production-gated on
``ALFRED_ENV`` and *raises* (crashing the subprocess) outside dev/test, so it
couples substrate failure to env-gate behaviour. ``inject_binding_request`` is
ungated and emits a clean ``adapter.binding_request`` notification — the
cleanest lever to prove "plugin notification -> runner -> handler" in isolation.

Why this runs locally (macOS)
-----------------------------
The reference manifest declares ``sandbox.kind = "none"``. Under
``ALFRED_ENVIRONMENT=test`` the launcher execs the plugin unsandboxed on
non-Linux dev hosts (UID-drop via ``runuser`` is Linux-only and is the
``test_plugin_launcher_stub`` skip), so the genuine launcher exec + stdio
hand-off path is exercised on this developer's mac as well as in CI.

Marked ``integration`` because it spawns a real subprocess through the real
launcher. It uses a recording fake audit writer (the substrate proof is about
the WIRE + routing, not audit persistence) so no Postgres container is needed,
mirroring ``tests/integration/test_comms_mcp_contract.py``.
"""

from __future__ import annotations

import asyncio
import getpass
import os
from contextlib import suppress
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.cli._launcher_spawn import PluginLaunchSpec
from alfred.comms_mcp.protocol import BindingRequestNotification
from alfred.plugins.comms_runner import CommsPluginRunner
from alfred.plugins.comms_stdio_transport import CommsStdioTransport
from alfred.plugins.session import AlfredPluginSession

pytestmark = pytest.mark.integration

_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
_PLUGIN_DIR: Path = _REPO_ROOT / "plugins" / "alfred_comms_test"
_MANIFEST_PATH: Path = _PLUGIN_DIR / "manifest.toml"

# The reference plugin's stable identifiers (see plugins/alfred_comms_test/main.py).
_PLUGIN_ID = "alfred.comms-test"  # [plugin] id in the manifest + sandbox-policy key
_ADAPTER_ID = "alfred_comms_test"  # [comms_mcp] adapter_kind the host tables are keyed on
_INJECT_BINDING_TRIGGER = "alfred_comms_test/inject_binding_request"

# Generous bound so a wedged subprocess fails loud instead of hanging the runner.
_TIMEOUT_S = 10.0

# The reference plugin's kind="none" launcher path UID-drops via ``runuser`` on
# Linux, which needs root (and a target user that exists). Pointing
# ``ALFRED_PLUGIN_UID`` at the current user makes ``runuser -u <self>`` succeed
# when the test runs as root (CI integration image / production deployments
# invoke the launcher as root); the skipif covers the non-root-Linux runner that
# cannot UID-drop at all. On macOS the launcher execs unsandboxed in dev/test, so
# this test runs locally without root. Mirrors tests/unit/plugins/
# test_plugin_launcher_stub.py's proven posture (required-checks.md: launcher-
# spawn legs are local/root-only, the in-process legs carry the CI gate).
_LAUNCHER_TEST_UID = getpass.getuser()
_LAUNCHER_REQUIRES_ROOT = os.uname().sysname == "Linux" and os.geteuid() != 0


class _RecordingHandler:
    """Captures the notifications routed to it, signalling arrival via an event."""

    def __init__(self) -> None:
        self.received: list[Any] = []
        self.arrived = asyncio.Event()

    async def process(self, notification: Any) -> None:
        self.received.append(notification)
        self.arrived.set()


class _RecordingSupervisor:
    """No-op supervisor that records restart/trip hand-offs (none expected here)."""

    def __init__(self) -> None:
        self.restart_calls: list[dict[str, str]] = []
        self.trip_calls: list[dict[str, str]] = []

    async def request_plugin_restart(self, *, adapter_id: str, reason: str) -> None:
        self.restart_calls.append({"adapter_id": adapter_id, "reason": reason})

    async def trip_breaker(self, *, component_id: str, reason: str) -> None:
        self.trip_calls.append({"component_id": component_id, "reason": reason})


def _fake_audit_writer() -> MagicMock:
    """Recording audit writer; ``last_events`` lets the test await handshake completion."""
    writer = MagicMock()
    writer.events = []

    async def _capture(**kwargs: Any) -> None:
        event = kwargs.get("event")
        if isinstance(event, str):
            writer.events.append(event)

    writer.append_schema = AsyncMock(side_effect=_capture)
    writer.append = AsyncMock(side_effect=_capture)
    return writer


def _fixture_gate() -> MagicMock:
    """Capability gate keyed on an explicit grant (CLAUDE.md rule 2 — never always-allow).

    Grants exactly the reference plugin's declared identity
    (``alfred.comms-test`` / ``user-plugin``) and refuses anything else, so a
    regression that handshakes the wrong plugin surfaces as a denied load rather
    than a silent pass. Mirrors the grant in
    ``tests/integration/test_comms_mcp_contract.py``.
    """
    gate = MagicMock()

    def _check_plugin_load(*, plugin_id: str, manifest_tier: str) -> bool:
        return plugin_id == _PLUGIN_ID and manifest_tier == "user-plugin"

    def _check_content_clearance(*, plugin_id: str, content_tier: str, **_: object) -> bool:
        return plugin_id == _PLUGIN_ID and content_tier in {"T1", "T2"}

    gate.check_plugin_load = MagicMock(side_effect=_check_plugin_load)
    gate.check_content_clearance = MagicMock(side_effect=_check_content_clearance)
    return gate


async def _wait_for(predicate: Any, timeout: float) -> None:
    """Poll ``predicate`` (a 0-arg bool callable) until true or the deadline."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise TimeoutError("substrate condition never became true")


@pytest.mark.skipif(
    _LAUNCHER_REQUIRES_ROOT,
    reason="kind=none launcher UID-drops via runuser (root-only on Linux); "
    "runs locally + on the root CI integration runner",
)
async def test_runner_routes_binding_notification_from_launched_reference_plugin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end: launcher-spawned plugin notification -> runner -> binding handler."""
    # The launcher reads ALFRED_ENVIRONMENT; ``test`` execs kind="none" unsandboxed
    # on non-Linux dev hosts. It rides the scrubbed comms-child-env allowlist.
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # On a root Linux runner the launcher UID-drops to this user; it must exist,
    # so target the current user (rides the allowlist into the launcher).
    monkeypatch.setenv("ALFRED_PLUGIN_UID", _LAUNCHER_TEST_UID)

    spec = PluginLaunchSpec(
        plugin_id=_PLUGIN_ID,
        manifest_path=_MANIFEST_PATH,
        module="alfred_comms_test.main",
        adapter_id=_ADAPTER_ID,
        import_roots=(_REPO_ROOT / "plugins", _REPO_ROOT / "src"),
        inherit_stdio=False,
        sandbox_kind="none",
    )
    transport = CommsStdioTransport(adapter_id=_ADAPTER_ID, spec=spec)

    audit = _fake_audit_writer()
    supervisor = _RecordingSupervisor()
    binding_handler = _RecordingHandler()
    session = await AlfredPluginSession.for_comms_adapter(
        adapter_id=_ADAPTER_ID,
        manifest_raw=_MANIFEST_PATH.read_text(encoding="utf-8"),
        audit_writer=audit,
        gate=_fixture_gate(),
        supervisor=supervisor,
        inbound_handler=_RecordingHandler(),
        binding_handler=binding_handler,
        rate_limit_handler=_RecordingHandler(),
        crash_handler=_RecordingHandler(),
        # The runner owns the wire transport; the session needs none (it would
        # only use it for quarantine-kill, which this substrate test never trips).
        transport=None,
    )
    runner = CommsPluginRunner(session=session, transport=transport, adapter_id=_ADAPTER_ID)

    run_task = asyncio.create_task(runner.run())
    try:
        # Handshake done once the session has emitted plugin.lifecycle.loaded — the
        # pump is now reading, so a trigger we send will produce a routed frame.
        await _wait_for(lambda: "plugin.lifecycle.loaded" in audit.events, _TIMEOUT_S)

        # Poke the plugin to emit an adapter.binding_request. ``send`` is the
        # host->plugin write path; the runner is the sole READER (no conflict).
        # Distinctive values (NOT the reference plugin's defaults, which are
        # "discord:newcomer" / "blue-otter-42") so the round-trip of the trigger
        # params is genuinely proven: if the substrate dropped the params, the
        # plugin would emit its defaults and the assertions below would fail.
        await transport.send(
            {
                "jsonrpc": "2.0",
                "method": _INJECT_BINDING_TRIGGER,
                "params": {
                    "platform_user_id": "discord:uat-substrate-7271",
                    "verification_phrase": "purple-otter-99",
                },
            }
        )

        await asyncio.wait_for(binding_handler.arrived.wait(), timeout=_TIMEOUT_S)
    finally:
        # Clean EOF: closing stdin makes the plugin's readline return empty, it
        # exits, its stdout EOFs, the pump returns, run() completes. close() is
        # idempotent with the runner's own finally-arm.
        await transport.close()
        with suppress(asyncio.CancelledError):
            await asyncio.wait_for(run_task, timeout=_TIMEOUT_S)

    assert len(binding_handler.received) == 1
    notification = binding_handler.received[0]
    assert isinstance(notification, BindingRequestNotification)
    assert notification.adapter_id == _ADAPTER_ID
    # Both distinctive values must survive the trigger -> plugin -> wire -> runner
    # -> session-validate round-trip (each differs from the plugin's default).
    assert notification.verification_phrase == "purple-otter-99"
    assert notification.platform_user_id == "discord:uat-substrate-7271"
    # No restart / breaker hand-off on the clean happy path.
    assert supervisor.restart_calls == []
    assert supervisor.trip_calls == []
