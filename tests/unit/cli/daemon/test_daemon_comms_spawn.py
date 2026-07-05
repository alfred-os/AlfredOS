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
from alfred.cli.daemon._comms_boot import _UnknownAdapterKindError
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
        boot_epoch: str | None = None,
        credential_resolver: Any = None,
        forwarded_inbound_receiver: Any = None,
    ) -> None:
        self.session = session
        self.transport = transport
        self.adapter_id = adapter_id
        # Spec B G6-7-4 (#309): the boot path threads the forwarded-inbound receiver on
        # the gateway leg ONLY; the STDIO (daemon-spawned) carrier gets None. Record it
        # so the spawn test can assert the stdio leg stays receiver-LESS.
        self.forwarded_inbound_receiver = forwarded_inbound_receiver
        # Spec A G3-2 (#237): the boot path now threads the per-boot epoch into the
        # runner so it rides the handshake (architect H-2). Record it for assertions.
        self.boot_epoch = boot_epoch
        # Spec B G6-3 (#288): the boot path wires the credential resolver on the SOCKET
        # (gateway) leg; record it so a test can assert the per-carrier wiring.
        self.credential_resolver = credential_resolver
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
    monkeypatch.setattr("alfred.cli.daemon._comms_boot.CommsStdioTransport", _FakeCommsTransport)
    monkeypatch.setattr("alfred.cli.daemon._comms_boot.CommsPluginRunner", _FakeRunner)


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
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """One enabled adapter -> one pump registered, sender bound, handlers wired."""
    del quarantine_registry  # installed via fixture side effect
    # PR-S4-11c-2b: the comms boot graph now spawns the bwrap quarantined child;
    # the in-proc fake child-IO keeps this construction-only test off a real
    # subprocess. Assert the spawn happened (the go-live flip is live).
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

    # PR-S4-11c-2b go-live flip: the comms boot graph spawned exactly one live
    # quarantined child (via the fake child-IO seam) — the daemon is no longer on
    # the ADR-0027 fixture extractor. The provider key flowed into the spawn.
    assert len(patch_quarantine_child_spawn) == 1
    assert patch_quarantine_child_spawn[0].provider_key
    # CR #255: the live quarantine child is REAPED on normal shutdown — the boot
    # graph's `aclose` ran in the daemon's `finally` (transport.close -> child_io
    # .aclose), so the bwrap child never leaks past the daemon.
    assert patch_quarantine_child_spawn[0].aclose_calls >= 1

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
    # Spec A G3-2 (#237): the daemon threads the minted per-boot epoch INTO the
    # runner (it rides the handshake, architect H-2). Pin the actual value so the
    # daemon->runner epoch wiring can't silently regress to None / a stale epoch.
    from alfred.bootstrap.lifecycle_epoch import current_boot_epoch

    minted_epoch = current_boot_epoch()
    assert minted_epoch is not None
    assert runner.boot_epoch == minted_epoch
    # PR-S4-11b DEFECT 1: the runner is wired with the supervisor's graceful-drain
    # signal (the SAME event object) so its pump exits promptly on stop.
    assert runner.shutdown_event is sup.shutdown_event
    # Spec B G6-3 (#288): the STDIO (daemon-spawned) carrier carries NO credential
    # round-trip — the resolver is wired ONLY on the socket (gateway) leg. So a
    # stdio-spawned adapter's runner gets credential_resolver=None.
    assert runner.credential_resolver is None
    # Spec B G6-7-4 (#309): the STDIO carrier carries NO forwarded inbound either —
    # the receiver is wired ONLY on the gateway leg. A stdio-spawned runner gets
    # forwarded_inbound_receiver=None (the default-disposition refusal path unchanged).
    assert runner.forwarded_inbound_receiver is None
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
    # routes through the runner's send_request (the dispatch-ack seam is live). The
    # seam now takes a fully-validated OutboundMessageRequest (G5 #237) whose body
    # is the DLP-minted ScannedOutboundBody — it serialises to the wire params the
    # real TUI / Discord plugin re-validates.
    assert len(bound_senders) == 1
    sender = bound_senders[0]
    import asyncio
    from uuid import uuid4

    from alfred.comms_mcp.protocol import OutboundMessageRequest
    from alfred.security.dlp import OutboundDlp

    class _PassthroughBroker:
        def redact(self, text: str) -> str:
            return text

    dlp = OutboundDlp(broker=_PassthroughBroker(), audit=lambda *, event, subject: None)
    scanned = dlp.scan_for_outbound("ack")
    idem = uuid4()
    request = OutboundMessageRequest(
        adapter_id=_ENABLED_ADAPTER,
        idempotency_key=idem,
        target_platform_id="discord:7",
        body=scanned,
        attachments_refs=(),
        addressing_mode="dm",
    )

    asyncio.run(sender.send_outbound(request))
    assert runner.outbound_calls == [
        {
            "method": "outbound.message",
            "params": {
                "adapter_id": _ENABLED_ADAPTER,
                "idempotency_key": str(idem),
                "target_platform_id": "discord:7",
                "body": ["ack", {"dlp_redactions_count": 0, "canary_tripped": False}],
                "attachments_refs": [],
                "addressing_mode": "dm",
            },
        }
    ]


def test_boot_refuses_on_adapter_handshake_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A handshake failure for an enabled adapter -> refuse boot (exit 2), no pump."""
    del quarantine_registry  # installed via fixture side effect
    del patch_quarantine_child_spawn  # in-proc fake child-IO; no real bwrap spawn
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


def test_boot_refuses_fail_closed_on_quarantine_child_spawn_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """A bwrap quarantine-child spawn failure at boot -> refuse boot (exit 2), no pump.

    PR-S4-11c-2b go-live flip: ``_build_comms_boot_graph`` spawns the bwrap
    quarantined child. On a non-Linux / unprovisioned host that spawn raises
    ``QuarantineChildSpawnError`` — the daemon must REFUSE the boot fail-closed
    (audited, exit 2) rather than degrade to a fixture (CLAUDE.md hard rule #7).
    This drives the failure by monkeypatching the spawn seam to raise.
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    from alfred.security.quarantine_child_io import QuarantineChildSpawnError

    async def _failing_spawn(*, provider_key: str) -> Any:
        del provider_key
        raise QuarantineChildSpawnError("no bwrap on this host (test)")

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _failing_spawn
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    # The fail-closed refusal contract: exit 2, never a degraded boot.
    assert result.exit_code == 2

    sup = FakeSupervisor.last_instance
    assert sup is not None
    # The pump was NEVER registered — the refusal happens during the comms-graph
    # build, BEFORE supervisor.start / the spawn loop.
    assert sup.registered_tasks == []
    # A loud daemon.boot.failed row with the EXACT fail-closed reason (not just
    # "some refusal") — catches a wrong-refusal-arm regression (CR #255).
    rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert "quarantine_child_spawn_failed" in reasons
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # The operator-facing fail-closed message names the bwrap/provisioning need.
    assert "bwrap" in result.output


def test_boot_refuses_audited_on_comms_graph_broker_config_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """A ``SecretBrokerConfigError`` from the comms-graph broker build -> refuse (exit 2).

    #368 defense-in-depth: ``_build_comms_boot_graph`` builds its OWN
    ``SecretBroker`` (via ``build_broker``) — a second construction distinct
    from the ``_build_boot_outbound_dlp`` guard that already refuses boot on a
    bad secrets file BEFORE this block runs. That earlier guard makes this arm
    unreachable TODAY (it builds the identical broker first), but relying on that
    positional ordering to protect a security-boundary refusal is fragile
    (CLAUDE.md hard rule #7) — guard this call-site too so the refusal is LOCAL,
    not positional. Drives the failure by monkeypatching ``_build_comms_boot_graph``
    itself (the call the new except arm wraps) to raise the concrete subtype a
    real bad-secrets-file would.
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    from alfred.security.secrets import SecretBrokerNotAFileError

    async def _raise_broker_config_error(*_a: Any, **_k: Any) -> Any:
        raise SecretBrokerNotAFileError(
            "secrets path is a directory", path=Path("/etc/alfred/secrets.toml")
        )

    monkeypatch.setattr(
        "alfred.cli.daemon._commands._build_comms_boot_graph", _raise_broker_config_error
    )

    result = CliRunner().invoke(daemon_app, ["start"])
    # The fail-closed refusal contract: exit 2, never a degraded boot.
    assert result.exit_code == 2
    # A loud daemon.boot.failed row under the SAME dedicated secrets_config_failed
    # reason the _build_boot_outbound_dlp guard uses for the identical
    # broker-config failure (#370 item 2 — a misconfigured secrets file is a
    # secrets problem, whichever build catches it).
    rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert "secrets_config_failed" in reasons
    # The pump was NEVER registered — the refusal happens during the comms-graph
    # build, BEFORE supervisor.start / the spawn loop: no boot-completed row.
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []
    # The operator sees the actionable secrets message, not the generic
    # boot-infra text that would misdirect them (devex dx-001).
    assert "secrets path is a directory" in result.output


def test_boot_reaps_quarantine_child_when_post_spawn_step_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A post-spawn boot failure still REAPS the live quarantine child (CR #255).

    The comms-graph build spawns the bwrap child; if a LATER boot step
    (``Supervisor()`` / ``write_pidfile`` / ``start()``) fails, the daemon's
    ``finally`` must still close the quarantine transport so the child never leaks.
    Inject the failure at ``write_pidfile`` (after the spawn + Supervisor()).
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("pidfile write failed (test)")

    monkeypatch.setattr("alfred.cli.daemon._commands.write_pidfile", _boom)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code != 0
    # The child WAS spawned (the graph built before the failure)...
    assert len(patch_quarantine_child_spawn) == 1
    # ...and REAPED in the finally despite the boot failing after the spawn.
    assert patch_quarantine_child_spawn[0].aclose_calls >= 1


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

    monkeypatch.setattr("alfred.cli.daemon._comms_boot._resolve_comms_adapter_wire_spec", _boom)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2

    sup = FakeSupervisor.last_instance
    assert sup is not None
    assert sup.registered_tasks == []
    # No runner was constructed — the refusal happened before spawn.
    assert _FakeRunner.instances == []
    assert boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")


def test_boot_refuses_on_unregistered_adapter_kind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """A typo'd/unregistered ``adapter_kind`` refuses the FULL boot at carrier selection (#374).

    Witnesses the carrier-path narrow arm end-to-end (the boot loop resolves the carrier
    kind FIRST, so this is the copy that actually fires for a real unknown kind). The
    refusal carries the DISTINCT ``comms_adapter_unknown_kind`` reason in the durable boot
    row — so ``alfred audit log`` forensics tell a typo'd kind apart from a generic spawn
    refusal (the exact kind reaches the operator via the stderr message + the boot-failed
    hookpoint; see ``test_build_wiring_refuses_on_unregistered_adapter_kind``).
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    def _boom(_adapter_id: str) -> Any:
        raise _UnknownAdapterKindError(_adapter_id, "bogus_typo")

    monkeypatch.setattr("alfred.cli.daemon._comms_boot._resolve_comms_adapter_wire_spec", _boom)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2, result.output

    sup = FakeSupervisor.last_instance
    assert sup is not None
    assert sup.registered_tasks == []
    # No runner was constructed — the refusal happened at carrier selection, before spawn.
    assert _FakeRunner.instances == []
    rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert rows
    # Distinct forensic reason in the durable row (#374) — not the generic spawn-failed.
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert reasons == {"comms_adapter_unknown_kind"}


# These two child-reaping tests run LAST in the file: the supervisor-stop case
# boots fully (registers a pump), and the refusal tests above read the shared
# ``FakeSupervisor.last_instance`` (not reset by the autouse instance-clear), so
# they must not run before those refusal tests or they'd pollute that state.
def test_boot_reaps_child_when_supervisor_stop_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A failing ``supervisor.stop()`` must NOT skip the child reap (CR #255).

    The finally isolates the steps: ``supervisor.stop()`` runs in its own ``try``
    whose ``finally`` reaps the quarantine child + deletes the pidfile, so a
    ``stop()`` error can't leave the bwrap child leaked.
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    async def _boom_stop(_self: Any) -> None:
        raise RuntimeError("supervisor stop failed (test)")

    monkeypatch.setattr(FakeSupervisor, "stop", _boom_stop)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code != 0
    assert len(patch_quarantine_child_spawn) == 1
    # The child was reaped in the finally even though supervisor.stop() raised.
    assert patch_quarantine_child_spawn[0].aclose_calls >= 1


def test_boot_reaps_child_when_graph_assembly_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """Comms-graph assembly that raises AFTER the spawn reaps the live child (CR #255).

    Once ``_build_comms_inbound_extractor`` returns the child is live; if a later
    constructor (``T3BodyRecorder`` etc.) raises, ``_build_comms_boot_graph`` closes
    the transport before re-raising — the graph never returns, so the daemon's
    exit-path teardown can't see it.
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_ENABLED_ADAPTER}"]')
    _patch_comms_seams(monkeypatch)

    def _boom_recorder(**_kwargs: Any) -> object:
        raise RuntimeError("recorder construction failed (test)")

    # Patched at the SOURCE module — the boot graph imports it lazily by that path.
    monkeypatch.setattr("alfred.security.quarantine_transport.T3BodyRecorder", _boom_recorder)

    result = CliRunner().invoke(daemon_app, ["start"])

    assert result.exit_code != 0
    assert len(patch_quarantine_child_spawn) == 1
    # The transport (owning the live child) was closed in the graph-assembly except.
    assert patch_quarantine_child_spawn[0].aclose_calls >= 1
