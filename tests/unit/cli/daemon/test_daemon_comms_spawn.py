"""PR-S4-11b Wave 4: the daemon spawns enabled comms plugins on the substrate.

The boot-wiring unit cut — NO real subprocess. ``CommsStdioTransport`` and
``CommsPluginRunner`` are monkeypatched at the ``_commands`` module seam to fakes
so these tests exercise the construction order + readiness-probe-then-register +
fail-closed-on-handshake-failure logic hermetically (the genuine launcher spawn +
wire is the substrate integration test's job).

Three invariants:

* ``comms_enabled_adapters=()`` (the default) builds NONE of the comms graph and
  registers NO pump — boot is byte-for-byte unchanged.
* one enabled adapter -> exactly one ``register_plugin_task(runner.pump())`` after
  ``start_and_handshake`` succeeds, the four handlers wired, the inbound
  orchestrator's outbound sender bound.
* a handshake/spawn failure for an enabled adapter -> ``_refuse_boot`` (exit 2),
  pump NOT registered (fail-closed; CLAUDE.md hard rule #7).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
from typer.testing import CliRunner

from alfred.cli.daemon import daemon_app
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security.quarantine import declare_hookpoints
from tests.helpers.gates import make_quarantined_extract_chain_gate

from .conftest import FakeAuditWriter, FakeSupervisor

_ENABLED_ADAPTER = "alfred_comms_test"


@pytest.fixture
def quarantine_registry() -> Iterator[HookRegistry]:
    """Install a scoped registry granting the system-tier DLP grant.

    The daemon boot path constructs a REAL :class:`QuarantinedExtractor` (Wave 2's
    ``_build_comms_inbound_extractor``), which refuses to construct without an
    active post-stage DLP subscriber registration on the
    ``security.quarantined.extract`` chain (PRD §7.1). This installs a scoped
    :class:`RealGate`-backed registry granting that system grant — never an
    always-allow shim (CLAUDE.md hard rule #2). Mirrors the daemon_runtime unit
    test's fixture; in production the daemon installs the real registry before the
    comms graph is built (real-source follow-up — see the PR notes).
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(),
        strict_declarations=False,
    )
    try:
        set_registry(registry)
        declare_hookpoints(registry)
        yield registry
    finally:
        set_registry(prior)


class _FakeCommsTransport:
    """Stands in for :class:`CommsStdioTransport` — never spawns a subprocess."""

    instances: ClassVar[list[_FakeCommsTransport]] = []

    def __init__(self, *, adapter_id: str, spec: Any) -> None:
        self.adapter_id = adapter_id
        self.spec = spec
        _FakeCommsTransport.instances.append(self)

    async def close(self) -> None:
        return None


class _FakeRunner:
    """Stands in for :class:`CommsPluginRunner`.

    ``start_and_handshake`` succeeds or raises per :attr:`fail_handshake`. ``pump``
    returns a real coroutine the supervisor double records. ``send_request`` is
    the outbound seam the bound :class:`OutboundSenderLike` wrapper calls.
    """

    instances: ClassVar[list[_FakeRunner]] = []
    fail_handshake: ClassVar[bool] = False

    def __init__(
        self,
        *,
        session: Any,
        transport: Any,
        adapter_id: str,
        shutdown_event: Any = None,
        max_in_flight_notifications: int = 32,
    ) -> None:
        self.session = session
        self.transport = transport
        self.adapter_id = adapter_id
        # PR-S4-11b DEFECT 1: the boot path now injects the supervisor's
        # graceful-drain signal; record it so a test can assert the wiring.
        self.shutdown_event = shutdown_event
        # PR-S4-11b deadlock fix: the boot path now also passes the in-flight
        # notification-dispatch cap (matched to the session's dispatch-semaphore
        # cap from Settings). Record it so a test can assert the wiring.
        self.max_in_flight_notifications = max_in_flight_notifications
        self.handshake_called = False
        self.outbound_calls: list[dict[str, Any]] = []
        _FakeRunner.instances.append(self)

    async def start_and_handshake(self) -> None:
        self.handshake_called = True
        if _FakeRunner.fail_handshake:
            from alfred.plugins.errors import PluginError

            raise PluginError("handshake refused (fake)")

    async def pump(self) -> None:
        return None

    async def send_request(self, method: str, params: Any) -> Any:
        self.outbound_calls.append({"method": method, "params": params})
        return {}


@pytest.fixture(autouse=True)
def _reset_fakes() -> None:
    _FakeCommsTransport.instances.clear()
    _FakeRunner.instances.clear()
    _FakeRunner.fail_handshake = False


def _patch_comms_seams(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("alfred.cli.daemon._commands.CommsStdioTransport", _FakeCommsTransport)
    monkeypatch.setattr("alfred.cli.daemon._commands.CommsPluginRunner", _FakeRunner)


def test_default_empty_adapters_boot_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
) -> None:
    """``comms_enabled_adapters=()`` registers no pump + builds no comms graph."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # No ALFRED_COMMS_ENABLED_ADAPTERS set -> default ().
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    sup = FakeSupervisor.last_instance
    assert sup is not None
    assert sup.registered_tasks == []
    # None of the comms classes were constructed.
    assert _FakeRunner.instances == []
    assert _FakeCommsTransport.instances == []


def test_enabled_adapter_spawns_and_registers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """One enabled adapter -> one pump registered, sender bound, handlers wired."""
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    # Spy on the inbound orchestrator's late-bind seam so we can assert the
    # outbound sender was wired (the round-trip ack path is live).
    bound_senders: list[Any] = []
    from alfred.comms_mcp.daemon_runtime import CommsInboundOrchestratorAdapter

    original_bind = CommsInboundOrchestratorAdapter.bind_outbound_sender

    def _spy_bind(self: Any, sender: Any) -> None:
        bound_senders.append(sender)
        original_bind(self, sender)

    monkeypatch.setattr(CommsInboundOrchestratorAdapter, "bind_outbound_sender", _spy_bind)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    sup = FakeSupervisor.last_instance
    assert sup is not None
    # Exactly one supervised pump registered.
    assert len(sup.registered_tasks) == 1
    # Exactly one runner + transport constructed for the one enabled adapter.
    assert len(_FakeRunner.instances) == 1
    assert len(_FakeCommsTransport.instances) == 1

    runner = _FakeRunner.instances[0]
    assert runner.handshake_called is True
    # The wire adapter_kind (from the manifest) keys the runner/transport.
    assert runner.adapter_id == _ENABLED_ADAPTER
    # PR-S4-11b DEFECT 1: the runner is wired with the supervisor's graceful-drain
    # signal (the SAME event object) so its pump exits promptly on stop.
    assert runner.shutdown_event is sup.shutdown_event
    # PR-S4-11b deadlock fix: the runner's in-flight dispatch-task cap is wired
    # from the SAME Settings field as the session's dispatch semaphore so the two
    # backpressure bounds match. The boot env here leaves the field at its default.
    from alfred.config.settings import Settings

    assert (
        runner.max_in_flight_notifications == Settings().comms_max_in_flight_notifications  # type: ignore[no-untyped-call]
    )
    # O1: the spawn is observable in `alfred daemon start` output (not only via an
    # audit-log SQL query). The adapter-spawned line lands in the boot output.
    from alfred.i18n import t

    assert t("daemon.comms.adapter_spawned", adapter_id=_ENABLED_ADAPTER) in result.output
    assert _FakeCommsTransport.instances[0].adapter_id == _ENABLED_ADAPTER

    # The inbound orchestrator's outbound sender was bound exactly once, and it
    # routes through the runner's send_request (the dispatch-ack seam is live).
    assert len(bound_senders) == 1
    sender = bound_senders[0]
    import asyncio

    asyncio.run(
        sender.send_outbound(
            adapter_id=_ENABLED_ADAPTER, target_platform_id="discord:7", body={"content": "ack"}
        )
    )
    assert runner.outbound_calls == [
        {
            "method": "outbound.message",
            "params": {
                "adapter_id": _ENABLED_ADAPTER,
                "target_platform_id": "discord:7",
                "body": {"content": "ack"},
            },
        }
    ]


def test_boot_refuses_on_adapter_handshake_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """A handshake failure for an enabled adapter -> refuse boot (exit 2), no pump."""
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)
    _FakeRunner.fail_handshake = True

    result = CliRunner().invoke(daemon_app, ["start"])
    # _refuse_boot exits 2 (the fail-closed refusal contract).
    assert result.exit_code == 2

    sup = FakeSupervisor.last_instance
    assert sup is not None
    # The pump was NEVER registered — fail-closed, not parked-with-dead-plugin.
    assert sup.registered_tasks == []
    # A loud daemon.boot.failed row was written.
    assert boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    # FIX 1 (PR-S4-11b review): the comms spawn loop now runs BEFORE the
    # completion signal, so an adapter spawn/handshake failure must NOT have
    # emitted a (lying) daemon.boot.completed row — only the failure row.
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []


def test_boot_refuses_on_multiple_enabled_adapters(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """FIX 4: >1 enabled comms adapter -> refuse boot (exit 2), no pump.

    This cut builds ONE shared inbound orchestrator whose outbound sender is
    bound per-adapter (last-writer-wins), so with two enabled adapters one
    adapter's inbound turn would dispatch its ack through the OTHER adapter's
    runner — a cross-route. Until per-adapter routing lands (PR-S4-11c), the
    daemon REFUSES boot fail-closed (audited ``comms_multi_adapter_unsupported``)
    rather than parking a mis-wired multi-adapter graph.
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}", "alfred_discord"]')
    _patch_comms_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2

    sup = FakeSupervisor.last_instance
    assert sup is not None
    # No pump registered + no runner constructed — the refusal happened before
    # any adapter spawned (fail-closed, never a parked cross-routed graph).
    assert sup.registered_tasks == []
    assert _FakeRunner.instances == []
    rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert "comms_multi_adapter_unsupported" in reasons


def test_boot_refuses_on_adapter_manifest_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """A manifest parse/resolution failure for an enabled adapter -> refuse boot.

    The earlier fail-closed arm (before the runner exists): a missing/malformed
    ``[comms_mcp]`` block surfaces as a typed error that REFUSES the boot rather
    than silently skipping the adapter (CLAUDE.md hard rule #7).
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    from alfred.plugins.errors import ManifestError

    def _boom(_adapter_id: str) -> Any:
        raise ManifestError("manifest broke (fake)")

    monkeypatch.setattr("alfred.cli.daemon._commands._resolve_comms_adapter_wire_spec", _boom)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2

    sup = FakeSupervisor.last_instance
    assert sup is not None
    assert sup.registered_tasks == []
    # No runner was constructed — the refusal happened before spawn.
    assert _FakeRunner.instances == []
    assert boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
