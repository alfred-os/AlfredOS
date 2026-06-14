"""ADR-0031: the daemon binds a unix-socket listener for the foreground-TUI adapter.

The boot-wiring unit cut for the SOCKET carrier — NO real socket, NO real
subprocess. ``CommsSocketListener`` and ``CommsPluginRunner`` are monkeypatched at
the ``_commands`` module seam to fakes so these tests exercise the bind-inline +
accept-as-supervised-task + reap-on-every-exit-path logic hermetically.

Invariants under proof:

* an enabled socket-backed (``tui``) adapter BINDS its listener at boot + schedules
  exactly one supervised accept-task — the handshake does NOT run inline (the peer
  arrives asynchronously), so boot completes without a connected ``alfred chat``;
* the listener is REAPED on every exit path (clean shutdown, a later boot failure) —
  the socket-file analog of the bwrap-child reap;
* a bind failure REFUSES the boot fail-closed (audited, exit 2), no accept-task;
* the socket-backed adapter still COUNTS as enabled — multi-adapter refusal fires.
"""

from __future__ import annotations

import asyncio
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

_TUI_ADAPTER = "alfred_tui"


@pytest.fixture
def quarantine_registry() -> Any:
    """Scoped RealGate-backed registry granting the system DLP grant (no shim)."""
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


class _FakeSocketListener:
    """Stands in for :class:`CommsSocketListener` — never binds a real socket."""

    instances: ClassVar[list[_FakeSocketListener]] = []
    fail_bind: ClassVar[bool] = False

    def __init__(self, *, adapter_id: str) -> None:
        self.adapter_id = adapter_id
        self.bind_called = False
        self.accept_called = False
        self.aclose_calls = 0
        _FakeSocketListener.instances.append(self)

    async def bind(self) -> None:
        self.bind_called = True
        if _FakeSocketListener.fail_bind:
            raise OSError("bind failed (fake)")

    async def accept(self) -> Any:
        # The supervised accept-task awaits this. The unit cut never drives the task
        # (the fake supervisor records-and-closes the coroutine), so accept is never
        # actually awaited — assert it is not reached at boot.
        self.accept_called = True
        raise AssertionError("accept() must NOT run inline at boot")  # pragma: no cover

    async def aclose(self) -> None:
        self.aclose_calls += 1


class _FakeRunner:
    """Stands in for :class:`CommsPluginRunner` (socket carrier)."""

    instances: ClassVar[list[_FakeRunner]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.handshake_called = False
        _FakeRunner.instances.append(self)

    async def run(self) -> None:  # pragma: no cover - the unit cut never drives it
        return None

    async def start_and_handshake(self) -> None:
        # Spec A G3-2 (#237): the socket boot path splits run() into
        # start_and_handshake() + register(send_notification) + pump() so the
        # carrier's id-less sender registers with the lifecycle broadcaster only
        # AFTER its handshake. Record the call so a test can assert it ran.
        self.handshake_called = True

    async def pump(self) -> None:  # pragma: no cover
        return None

    async def send_notification(
        self, method: str, params: Any
    ) -> None:  # pragma: no cover
        return None

    async def send_request(self, method: str, params: Any) -> Any:  # pragma: no cover
        return {}


@pytest.fixture(autouse=True)
def _reset_fakes() -> Iterator[None]:
    _FakeSocketListener.instances.clear()
    _FakeSocketListener.fail_bind = False
    _FakeRunner.instances.clear()
    # The shared FakeSupervisor's stop-fault flag is class-level and would leak across
    # tests AND across files (FakeSupervisor lives in the package conftest, patched into
    # _commands.Supervisor for sibling daemon tests). Reset it BOTH at setup (so this
    # file is isolated from a prior leak) AND at teardown (so the supervisor-stop-raises
    # test below does not latch it True for later daemon tests in other files).
    FakeSupervisor.fail_stop = False
    try:
        yield
    finally:
        FakeSupervisor.fail_stop = False


def _patch_socket_seams(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("alfred.cli.daemon._commands.CommsSocketListener", _FakeSocketListener)
    monkeypatch.setattr("alfred.cli.daemon._commands.CommsPluginRunner", _FakeRunner)


def test_tui_adapter_binds_listener_and_schedules_accept_task(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """An enabled ``tui`` adapter binds the socket + schedules ONE supervised task.

    The handshake does NOT run inline — the peer (``alfred chat``) connects later, so
    boot must complete without it. Exactly one supervised accept-task is registered.
    """
    del quarantine_registry
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    _patch_socket_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # The quarantine child still spawns (the comms graph is built regardless of
    # carrier) and is reaped on shutdown.
    assert len(patch_quarantine_child_spawn) == 1
    assert patch_quarantine_child_spawn[0].aclose_calls >= 1

    # Exactly one listener bound, exactly one supervised accept-task scheduled.
    assert len(_FakeSocketListener.instances) == 1
    listener = _FakeSocketListener.instances[0]
    assert listener.bind_called is True
    assert listener.adapter_id == "tui"  # wire adapter_kind, not the launcher id

    sup = FakeSupervisor.last_instance
    assert sup is not None
    assert len(sup.registered_tasks) == 1

    # The "listening" line (NOT "spawned") lands in boot output — the peer connects
    # later, so the daemon advertises a listener, not a live handshake.
    from alfred.i18n import t

    assert t("daemon.comms.adapter_listening", adapter_id=_TUI_ADAPTER) in result.output


def test_tui_adapter_listener_reaped_on_clean_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """The socket listener is reaped in the daemon's finally (no stale socket)."""
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    _patch_socket_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    assert len(_FakeSocketListener.instances) == 1
    assert _FakeSocketListener.instances[0].aclose_calls >= 1


def test_tui_adapter_listener_reaped_when_later_boot_step_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A failure AFTER the bind still reaps the listener (no leaked socket inode)."""
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    _patch_socket_seams(monkeypatch)

    # Fail the completion-row emit AFTER the bind + accept-task registration.
    def _boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("post-bind boot step failed (test)")

    monkeypatch.setattr("alfred.cli.daemon._commands.wait_for_shutdown", _async_boom(_boom))

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code != 0

    assert len(_FakeSocketListener.instances) == 1
    assert _FakeSocketListener.instances[0].aclose_calls >= 1


def test_tui_adapter_listener_reaped_even_when_supervisor_stop_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A failing ``supervisor.stop()`` still reaps the listener AND deletes the pidfile.

    The boot finally isolates the drain: ``try: supervisor.stop() finally: <reap
    listeners + delete pidfile>``. A ``stop()`` that raises must NOT skip the
    socket-listener reap or the pidfile delete (the exact leaks that inner finally
    exists to prevent). This drives that arm directly.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    _patch_socket_seams(monkeypatch)
    FakeSupervisor.fail_stop = True

    result = CliRunner().invoke(daemon_app, ["start"])
    # The raised stop() propagates out of the boot's finally — a non-zero exit.
    assert result.exit_code != 0

    # The listener was still reaped despite stop() raising (socket not leaked).
    assert len(_FakeSocketListener.instances) == 1
    assert _FakeSocketListener.instances[0].aclose_calls >= 1
    # And the pidfile was still deleted (the conftest patches it under tmp_path).
    assert not (tmp_path / "daemon.pid").exists()


def test_no_enabled_adapters_binds_no_socket_listener(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """Booting with zero enabled adapters constructs NO socket listener.

    Pins the default-empty invariant for the socket carrier specifically: the whole
    comms graph (incl. the socket bind) is guarded behind a non-empty
    ``comms_enabled_adapters``, so an empty set must leave the listener list empty.
    """
    del quarantine_registry
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", "[]")
    _patch_socket_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # No adapter enabled -> no socket listener constructed at all.
    assert _FakeSocketListener.instances == []


def test_tui_adapter_bind_failure_refuses_boot_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """A socket bind failure refuses the boot (exit 2), no accept-task scheduled."""
    del quarantine_registry
    del patch_quarantine_child_spawn
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    _patch_socket_seams(monkeypatch)
    _FakeSocketListener.fail_bind = True

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2

    sup = FakeSupervisor.last_instance
    assert sup is not None
    # Fail-closed: no accept-task registered.
    assert sup.registered_tasks == []
    # The bound-then-failed listener was reaped, and a loud failed row written.
    assert _FakeSocketListener.instances[0].aclose_calls >= 1
    failed_rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    assert failed_rows
    # ADR-0031: a bind fault carries its OWN reason, distinct from spawn/handshake.
    reasons = {
        r["subject"]["failure_reason"] for r in failed_rows if isinstance(r["subject"], dict)
    }
    assert "comms_adapter_bind_failed" in reasons
    assert "comms_adapter_spawn_failed" not in reasons
    # No lying completion row.
    assert boot_success_env.rows_for("DAEMON_BOOT_FIELDS") == []


def test_tui_counts_as_enabled_for_multi_adapter_refusal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
) -> None:
    """TUI-over-socket + a second adapter -> multi-adapter refusal still fires."""
    del quarantine_registry
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}", "alfred_discord"]')
    _patch_socket_seams(monkeypatch)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 2

    # The refusal fires BEFORE any listener binds (no spawn side effects).
    assert _FakeSocketListener.instances == []
    rows = boot_success_env.rows_for("DAEMON_BOOT_FAILED_FIELDS")
    reasons = {r["subject"]["failure_reason"] for r in rows if isinstance(r["subject"], dict)}
    assert "comms_multi_adapter_unsupported" in reasons


def _async_boom(fn: Any) -> Any:
    async def _f(*args: Any, **kwargs: Any) -> None:
        fn(*args, **kwargs)

    return _f


class _BlockingAcceptListener:
    """Listener whose ``accept()`` blocks until cancelled — stands in for an absent peer.

    The CR-fix regression cut needs a listener that genuinely PARKS on ``accept()`` (no
    peer ever connects) so the test can prove ``_accept_and_pump`` exits promptly the
    instant the supervisor's shutdown event fires — rather than blocking until the
    drain budget force-cancels the bare ``await listener.accept()``.
    """

    instances: ClassVar[list[_BlockingAcceptListener]] = []

    def __init__(self, *, adapter_id: str) -> None:
        self.adapter_id = adapter_id
        self.accept_started = asyncio.Event()
        self.aclose_calls = 0
        _BlockingAcceptListener.instances.append(self)

    async def bind(self) -> None:
        return None

    async def accept(self) -> Any:
        # Park forever (until the supervised task is cancelled): no peer connects.
        self.accept_started.set()
        await asyncio.Event().wait()
        raise AssertionError("accept() unblocked without a peer")  # pragma: no cover

    async def aclose(self) -> None:
        self.aclose_calls += 1


class _CapturingSupervisor(FakeSupervisor):
    """A ``FakeSupervisor`` that CAPTURES the supervised coroutine instead of closing it.

    The shared ``FakeSupervisor.register_plugin_task`` closes the coroutine immediately
    (the boot-wiring tests assert COUNT, not execution). This regression test must
    actually RUN ``_accept_and_pump`` to prove its shutdown-race behaviour, so it
    captures the coroutine for the test to drive under a bounded ``wait_for``.
    """

    captured: ClassVar[list[Any]] = []

    def register_plugin_task(self, coro: Any) -> Any:
        _CapturingSupervisor.captured.append(coro)
        return coro


def test_accept_and_pump_returns_promptly_on_shutdown_with_no_peer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """The accept task drains PROMPTLY when shutdown fires before any peer connects.

    CR Minor (PR-S4-258): ``_accept_and_pump`` raced ``listener.accept()`` against the
    supervisor's shutdown event. With NO peer connected (the common post-merge state —
    the client ships later), setting the shutdown event must let the supervised task
    return at once, so a clean ``alfred daemon stop`` does NOT pay the full graceful-
    drain timeout before the force-cancel. The task must also build NO runner and
    require NO peer in that case.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    _BlockingAcceptListener.instances.clear()
    _CapturingSupervisor.captured.clear()
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    monkeypatch.setattr("alfred.cli.daemon._commands.CommsSocketListener", _BlockingAcceptListener)
    monkeypatch.setattr("alfred.cli.daemon._commands.CommsPluginRunner", _FakeRunner)
    monkeypatch.setattr("alfred.cli.daemon._commands.Supervisor", _CapturingSupervisor)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # Boot captured exactly one supervised accept-task; drive it directly.
    assert len(_CapturingSupervisor.captured) == 1
    accept_coro = _CapturingSupervisor.captured[0]
    sup = FakeSupervisor.last_instance
    assert isinstance(sup, _CapturingSupervisor)
    listener = _BlockingAcceptListener.instances[0]

    async def _drive() -> None:
        task = asyncio.ensure_future(accept_coro)
        # Let the task reach the parked ``accept()`` before signalling shutdown, so the
        # race genuinely resolves on the shutdown arm (not a pre-set event short-cut).
        await asyncio.wait_for(listener.accept_started.wait(), timeout=1.0)
        sup.shutdown_event.set()
        # The task must return PROMPTLY — well under the supervisor's 10s drain budget.
        await asyncio.wait_for(task, timeout=1.0)

    asyncio.run(_drive())

    # Shutdown raced ahead of any peer: NO runner was built and the listener was never
    # asked for a real connection beyond the parked accept.
    assert _FakeRunner.instances == []
    # The listener is still reaped by the daemon's finally (idempotent aclose).
    assert listener.aclose_calls >= 1


class _ClosingTransport:
    """A fake accepted transport that records its single ``close()``."""

    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


class _SameTickAcceptListener:
    """Listener whose ``accept()`` resolves IMMEDIATELY, returning a closeable transport.

    The same-tick-race regression needs BOTH ``listener.accept()`` AND the shutdown
    wait to be ``done`` when the post-``asyncio.wait`` check runs. Driving the captured
    coroutine with the shutdown event PRE-SET means both futures are ready on the first
    ``asyncio.wait``, so ``done`` contains both — the exact race ADR-0031 must resolve
    by PREFERRING shutdown (close + discard the accepted transport, build no runner).
    """

    instances: ClassVar[list[_SameTickAcceptListener]] = []

    def __init__(self, *, adapter_id: str) -> None:
        self.adapter_id = adapter_id
        self.transport = _ClosingTransport()
        self.aclose_calls = 0
        _SameTickAcceptListener.instances.append(self)

    async def bind(self) -> None:
        return None

    async def accept(self) -> Any:
        return self.transport

    async def aclose(self) -> None:
        self.aclose_calls += 1


def test_accept_and_pump_prefers_shutdown_on_same_tick_race(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boot_success_env: FakeAuditWriter,
    quarantine_registry: HookRegistry,
    patch_quarantine_child_spawn: list[Any],
) -> None:
    """When accept AND shutdown both resolve on the SAME tick, shutdown WINS.

    CR Major (PR-S4-258): if ``listener.accept()`` and the supervisor shutdown wait
    BOTH complete before the post-``asyncio.wait`` check, the daemon must take the
    SHUTDOWN path — never build a runner / start a handshake after stop has begun
    (the ADR-0031 accept-vs-shutdown invariant). The transport accepted moments before
    shutdown must be CLOSED (discarded), not leaked. Drives the captured coroutine with
    the shutdown event pre-set so both futures are done on the first race resolution.
    """
    del quarantine_registry
    del patch_quarantine_child_spawn
    _SameTickAcceptListener.instances.clear()
    _CapturingSupervisor.captured.clear()
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_COMMS_ENABLED_ADAPTERS", f'["{_TUI_ADAPTER}"]')
    monkeypatch.setattr("alfred.cli.daemon._commands.CommsSocketListener", _SameTickAcceptListener)
    monkeypatch.setattr("alfred.cli.daemon._commands.CommsPluginRunner", _FakeRunner)
    monkeypatch.setattr("alfred.cli.daemon._commands.Supervisor", _CapturingSupervisor)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    assert len(_CapturingSupervisor.captured) == 1
    accept_coro = _CapturingSupervisor.captured[0]
    sup = FakeSupervisor.last_instance
    assert isinstance(sup, _CapturingSupervisor)
    listener = _SameTickAcceptListener.instances[0]

    async def _drive() -> None:
        # Pre-set shutdown so the very first ``asyncio.wait`` sees BOTH the immediate
        # accept AND the shutdown wait as done — the same-tick race.
        sup.shutdown_event.set()
        await asyncio.wait_for(asyncio.ensure_future(accept_coro), timeout=1.0)

    asyncio.run(_drive())

    # Shutdown won the same-tick race: NO runner built...
    assert _FakeRunner.instances == []
    # ...and the transport accepted moments before shutdown was CLOSED, not leaked.
    assert listener.transport.close_calls == 1
    # The listener is still reaped by the daemon's finally (idempotent aclose).
    assert listener.aclose_calls >= 1
