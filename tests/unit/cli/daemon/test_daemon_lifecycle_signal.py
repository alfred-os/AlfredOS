"""Core lifecycle signal emission at boot-healthy + drain (Spec A G1/G3-2) (#237).

The daemon writes ``daemon.lifecycle.ready`` / ``daemon.lifecycle.going_down``
AUDIT rows at the right lifecycle points and mints the per-boot epoch (G1). As of
G3-2 the core ALSO SENDS those lifecycle frames over the socket-listener carrier
via the ``LifecycleBroadcaster`` (the runner's id-less ``send_notification``
seam). The audit row stays authoritative; the wire frame is best-effort — a
zero-sender boot is a clean no-op and the audit rows still record. These tests
assert the audit rows AND the wire-send-via-seam contract (broadcast through
``send_notification``, never by constructing the gateway-consume frame models).
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path
from typing import Any, ClassVar

import pytest
from sqlalchemy.exc import SQLAlchemyError
from typer.testing import CliRunner

import alfred.cli.daemon._commands as _daemon_commands
from alfred.cli.daemon import daemon_app
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.security.quarantine import declare_hookpoints
from tests.helpers.gates import make_quarantined_extract_chain_gate

from .conftest import FakeAuditWriter, FakeSupervisor

_COMMS_TEST_ADAPTER = "alfred_comms_test"
_TUI_ADAPTER = "alfred_tui"


class _ImmediateAcceptListener:
    """Stands in for ``CommsSocketListener`` — ``accept()`` resolves at once.

    Returns a closeable transport so the boot's ``_accept_and_pump`` proceeds past
    the accept race into the runner build + handshake + broadcaster register — the
    path the wire-send-via-seam contract test drives.
    """

    instances: ClassVar[list[_ImmediateAcceptListener]] = []

    def __init__(self, *, adapter_id: str, on_peer_rejected: Any = None) -> None:
        self.adapter_id = adapter_id
        self.on_peer_rejected = on_peer_rejected
        self.aclose_calls = 0
        _ImmediateAcceptListener.instances.append(self)

    async def bind(self) -> None:
        return None

    async def accept(self) -> Any:
        class _T:
            async def close(self) -> None:
                return None

        return _T()

    async def aclose(self) -> None:
        self.aclose_calls += 1


class _SeamRunner:
    """Stands in for ``CommsPluginRunner`` (socket carrier) for the seam test.

    ``send_notification`` is the bound id-less sender the boot must register with the
    ``LifecycleBroadcaster``; the test asserts the registered callable IS this method.
    ``pump`` returns at once so ``_accept_and_pump`` completes cleanly.
    """

    instances: ClassVar[list[_SeamRunner]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.handshake_called = False
        _SeamRunner.instances.append(self)

    async def start_and_handshake(self) -> None:
        self.handshake_called = True

    async def pump(self) -> None:
        return None

    async def send_notification(self, method: str, params: Any) -> None:
        return None

    async def send_request(self, method: str, params: Any) -> Any:
        return {}


class _CapturingSupervisor(FakeSupervisor):
    """A ``FakeSupervisor`` that CAPTURES the supervised coroutine instead of closing it.

    The shared ``FakeSupervisor.register_plugin_task`` closes the coroutine immediately
    (boot-wiring tests assert COUNT, not execution). The seam test must actually RUN
    ``_accept_and_pump`` to reach the register call, so it captures the coroutine for
    the test to drive under a bounded ``wait_for``.
    """

    captured: ClassVar[list[Any]] = []

    def register_plugin_task(self, coro: Any) -> Any:
        _CapturingSupervisor.captured.append(coro)
        return coro


def fault_audit_writer_on_phase(writer: FakeAuditWriter, phase: str) -> None:
    """Make ``writer.append_schema`` raise ``SQLAlchemyError`` for ONE phase.

    Targets a single ``daemon.lifecycle.<phase>`` row (``ready`` or
    ``going_down``) by its ``subject["phase"]`` so the OTHER lifecycle row — and
    every non-lifecycle boot row — still records successfully. This isolates the
    "this exact audit write hits a DB failure" condition the boot path's
    fail-loud + nested-finally reap chain is built to survive (CR #255, ADR-0033
    Decision 3), without poisoning unrelated rows.

    A faulted write still appends its row BEFORE raising, so a test can assert the
    faulted phase was *attempted* while proving the boot then refuses (exit 3).
    """
    original = writer.append_schema

    async def _faulting(**kw: Any) -> None:
        await original(**kw)
        subject = kw.get("subject") or {}
        if subject.get("phase") == phase:
            raise SQLAlchemyError(f"audit write for {phase} row failed (fake)")

    writer.append_schema = _faulting  # type: ignore[method-assign]


@pytest.fixture
def quarantine_registry() -> Any:
    """Scoped RealGate-backed registry granting the system DLP grant (no shim).

    A comms-enabled boot constructs a REAL ``QuarantinedExtractor`` that refuses
    to build without an active post-stage DLP subscriber on the
    ``security.quarantined.extract`` chain. Mirrors the sibling comms boot tests
    (``test_daemon_comms_socket`` / ``test_daemon_boot_t3_nonce``).
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: daemon boot pidfile os.O_NOFOLLOW/os.getuid",
)
def test_ready_row_emitted_after_boot_completed(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    # The boot-completed row is present (sanity).
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS")

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    ready = [r for r in lifecycle if r["subject"]["phase"] == "ready"]
    assert len(ready) == 1
    subject = ready[0]["subject"]
    assert subject["epoch"]  # non-empty per-boot epoch
    assert subject["reason"] == ""  # ready carries no reason
    assert subject["boot_id"]
    # ``result`` is a top-level append_schema kwarg (recorded by FakeAuditWriter
    # as a sibling of ``subject``), NOT a member of ``subject``.
    assert ready[0]["result"] == "success"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: daemon boot pidfile os.O_NOFOLLOW/os.getuid",
)
def test_ready_epoch_matches_going_down_epoch(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    CliRunner().invoke(daemon_app, ["start"])
    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    epochs = {r["subject"]["epoch"] for r in lifecycle}
    assert len(epochs) == 1  # ready + going_down share the one per-boot epoch
    # …and that single shared value equals the one minted epoch (not merely
    # "all rows agree" — pin the value so a future regression that mints a
    # second epoch but reuses the same string still fails).
    (shared_epoch,) = epochs
    from alfred.bootstrap.lifecycle_epoch import current_boot_epoch

    minted = current_boot_epoch()
    assert minted is not None
    assert shared_epoch == minted


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: daemon boot pidfile os.O_NOFOLLOW/os.getuid",
)
def test_going_down_row_emitted_at_drain(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    going_down = [r for r in lifecycle if r["subject"]["phase"] == "going_down"]
    assert len(going_down) == 1
    subject = going_down[0]["subject"]
    assert subject["reason"] == "shutdown"  # default for an unsignalled drain
    assert subject["epoch"]
    assert going_down[0]["result"] == "success"


def test_going_down_not_emitted_when_boot_refuses(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    """A boot that refuses before ``ready`` never announces ``going_down``.

    The drain ``finally`` runs on a refusal too, but the daemon was never up,
    so emitting ``going_down`` would announce a departure that never happened.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    async def _boom_start(self: object) -> None:  # supervisor.start raises
        raise RuntimeError("start failed")

    from .conftest import FakeSupervisor

    monkeypatch.setattr(FakeSupervisor, "start", _boom_start)
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code != 0

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    assert not [r for r in lifecycle if r["subject"]["phase"] == "going_down"]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: daemon boot pidfile os.O_NOFOLLOW/os.getuid",
)
def test_default_empty_adapters_emits_audit_rows_without_wire(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    """No adapters enabled -> both lifecycle AUDIT rows present; no runner/wire."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    phases = sorted(r["subject"]["phase"] for r in lifecycle)
    assert phases == ["going_down", "ready"]
    # Every row carries the single per-boot epoch (the authoritative record is
    # the audit row even with no wire peer).
    assert all(r["subject"]["epoch"] for r in lifecycle)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: daemon boot pidfile os.O_NOFOLLOW/os.getuid",
)
def test_boot_path_registers_runner_send_notification_with_broadcaster(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """G3-2 contract: the boot feeds the runner's id-less seam to the broadcaster.

    G3-2 SENDS the lifecycle frames (G1 was audit-only). The send goes through the
    runner's ``send_notification`` seam — NOT by the boot path constructing the
    ``ReadyNotification`` / ``GoingDownNotification`` wire models itself (those are
    the G3-3 gateway-CONSUME shapes; the core sends a plain id-less JSON-RPC frame).

    Behavioural, not source-text: this drives the REAL socket-carrier accept path to
    completion (a peer connects, the runner handshakes, the boot registers it) and
    asserts the callable handed to ``LifecycleBroadcaster.register`` IS the runner's
    bound ``send_notification`` — never the frame-model constructors. A regression
    that registered a hand-rolled frame builder (or wired a wrong sender) fails here.
    """
    del quarantine_registry  # installed via fixture side effect
    del patch_quarantine_child_spawn  # in-proc fake child-IO; no real bwrap spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')

    registered: list[tuple[str, object]] = []
    original_register = _daemon_commands.LifecycleBroadcaster.register

    def _spy_register(self: object, adapter_id: str, sender: object) -> None:
        registered.append((adapter_id, sender))
        original_register(self, adapter_id, sender)  # type: ignore[arg-type]

    monkeypatch.setattr(_daemon_commands.LifecycleBroadcaster, "register", _spy_register)
    monkeypatch.setattr(
        "alfred.cli.daemon._comms_boot.CommsSocketListener", _ImmediateAcceptListener
    )
    monkeypatch.setattr("alfred.cli.daemon._comms_boot.CommsPluginRunner", _SeamRunner)
    monkeypatch.setattr("alfred.cli.daemon._commands.Supervisor", _CapturingSupervisor)

    _ImmediateAcceptListener.instances.clear()
    _SeamRunner.instances.clear()
    _CapturingSupervisor.captured.clear()

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # Boot captured exactly one supervised accept-task; drive it to completion so a
    # peer "connects", the runner handshakes, and the boot reaches the register call.
    assert len(_CapturingSupervisor.captured) == 1
    import asyncio

    asyncio.run(asyncio.wait_for(_CapturingSupervisor.captured[0], timeout=1.0))

    # Exactly one runner built; its send_notification is what the boot registered.
    assert len(_SeamRunner.instances) == 1
    runner = _SeamRunner.instances[0]
    assert runner.handshake_called is True
    assert len(registered) == 1
    adapter_id, sender = registered[0]
    assert adapter_id == "tui"  # the wire adapter_kind
    # The registered callable IS the runner's bound send_notification seam — NOT a
    # frame-model constructor and NOT some other sender (the structural invariant).
    assert sender == runner.send_notification


def test_boot_path_never_constructs_lifecycle_frame_models() -> None:
    """The core must not construct the gateway-CONSUME frame models.

    Complements the behavioural register test above: the core sends a PLAIN id-less
    JSON-RPC frame via ``send_notification`` and never builds ``ReadyNotification`` /
    ``GoingDownNotification`` (those are G3-3's gateway DECODE shapes). This is a
    cheap structural backstop; the wire-send-via-seam behaviour is pinned above.
    """
    src = Path(inspect.getfile(_daemon_commands)).read_text()
    assert "ReadyNotification(" not in src and "GoingDownNotification(" not in src, (
        "The core sends a plain id-less JSON-RPC frame; it must not construct the "
        "gateway-consume frame models (those are G3-3's decode shapes)."
    )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: daemon boot pidfile os.O_NOFOLLOW/os.getuid",
)
def test_going_down_emit_failure_still_runs_the_reap_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A faulting ``going_down`` audit write must NOT skip the teardown reap chain.

    ADR-0033 Decision 3 restructured the boot ``finally`` into a nested
    ``try: _emit_going_down() finally: <stop + child/socket/pidfile reap>`` for
    exactly one reason: if the ``going_down`` audit write hits a DB/OS failure
    (``SQLAlchemyError`` → exit 3), the supervisor stop + the bwrap-quarantine
    child reap + the pidfile delete MUST still run, THEN the exception
    propagates (the #255 leak class). A future refactor that moves the
    ``going_down`` emit OUTSIDE the nested try would reintroduce that leak — and
    pass every other lifecycle test. This is the guard.

    A comms adapter is enabled so a quarantine child exists in the harness; the
    fault is scoped to the ``going_down`` row alone (the ``ready`` row succeeds,
    so ``ready_emitted`` is True and ``going_down`` is reached).
    """
    del quarantine_registry  # installed via fixture side effect
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_COMMS_TEST_ADAPTER}"]')

    # The comms graph (and so the quarantine child) is built regardless of the
    # per-adapter spawn; bypass the real adapter spawn/handshake (which needs a
    # plugin-load grant this hermetic cut does not seed) so the test exercises the
    # graph reap, not the adapter loader. Mirrors test_daemon_boot_t3_nonce.
    from alfred.cli.daemon import _commands

    async def _spawn_noop(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(_commands, "_spawn_comms_adapter", _spawn_noop)

    fault_audit_writer_on_phase(boot_success_env, "going_down")

    result = CliRunner().invoke(daemon_app, ["start"])

    # (a) fail-loud: the faulting going_down audit write refuses the boot (exit 3).
    assert result.exit_code == 3, result.output

    # The going_down row WAS attempted (the fault raises AFTER the row records),
    # while ready succeeded — so the emit was reached, not short-circuited.
    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    phases = sorted(r["subject"]["phase"] for r in lifecycle)
    assert phases == ["going_down", "ready"]

    # (b) supervisor.stop() ran despite the going_down emit raising.
    from .conftest import FakeSupervisor

    sup = FakeSupervisor.last_instance
    assert sup is not None
    assert sup.stopped is True

    # (c) the pidfile was deleted by the reap chain (boot_success_env pins the
    # pidfile path under this test's tmp_path: ``tmp_path / "daemon.pid"``).
    assert not (tmp_path / "daemon.pid").exists()

    # (d) the live quarantine child was reaped (aclose ran) — the exact #255 leak.
    assert len(patch_quarantine_child_spawn) == 1
    assert patch_quarantine_child_spawn[0].aclose_calls >= 1


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: daemon boot pidfile os.O_NOFOLLOW/os.getuid",
)
def test_ready_emit_failure_skips_going_down(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    """A faulting ``ready`` audit write means ``going_down`` is never emitted.

    The boot sets ``ready_emitted = True`` strictly AFTER ``_emit_ready``
    returns, so a faulting ``ready`` row (exit 3) leaves the flag False and the
    drain ``finally`` skips ``going_down`` — announcing a departure for a boot
    that never announced readiness would be wrong (invariant 3). Proves the
    ``ready_emitted`` guard held under a ready-row fault.
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    fault_audit_writer_on_phase(boot_success_env, "ready")

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 3, result.output

    lifecycle = boot_success_env.rows_for("DAEMON_LIFECYCLE_FIELDS")
    phases = sorted(r["subject"]["phase"] for r in lifecycle)
    # ready was attempted (and faulted); going_down was NEVER emitted.
    assert phases == ["ready"]
