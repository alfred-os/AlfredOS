"""Unit tests for :class:`GatewayAdapterChildFactory` (Spec B G6-5 Task 4, #288).

The keystone trust-boundary unit: the gateway's real ``_AdapterChildFactoryLike``.
It (a) ``os.pipe()``s the fd-3 channel, (b) SYNCHRONOUSLY spawns the adapter child
through the launcher inside the COPIED dup2->Popen->restore "no-await-while-fd3-
clobbered" window (the :mod:`alfred.security.quarantine_child_io` discipline,
verbatim per GAP-2), (c) invokes the supervisor's ``deliver_credential(write_fd)``
hook AFTER the window closes / BEFORE the handshake, (d) wraps the live Popen in a
:class:`GatewayAdapterStdioTransport`, builds a :class:`CommsPluginRunner`, runs the
handshake, and (e) returns a child whose ``wait_until_exit`` awaits the Popen exit.

Every collaborator is FAKE (no real launcher / Popen / credential / runner) so the
whole surface runs in-process on the required non-root gate:

* a fake ``popen_factory`` records argv / env / ``pass_fds`` and proves the window
  contained NO ``await`` (it fails loudly if the event loop is driven mid-window);
* a fake ``deliver_credential`` records when it ran (after the window, before the
  handshake) and can raise the credential exceptions to prove UNWRAPPED propagation;
* a fake ``runner_factory`` yields a fake runner whose ``start_and_handshake`` /
  exit are scriptable.

The child-reaping lifecycle (H1) is asserted on every pre-handshake fault path +
the teardown method + ``wait_until_exit`` cancellation-safety.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, cast

import pytest

from alfred.comms_mcp.adapter_credential_resolver import AdapterCredentialError
from alfred.gateway.adapter_child_factory import (
    GatewayAdapterChildFactory,
    _GatewayAdapterChild,
)
from alfred.gateway.adapter_stdio_transport import GatewayAdapterStdioTransport
from alfred.gateway.adapter_supervisor import GatewayAdapterSpawnError
from alfred.gateway.core_link import CredentialLegDownError

# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------


class _FakeStdio:
    """A raw-pipe stand-in exposing the ``IO[bytes]`` surface the transport reads."""

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakePopen:
    """A ``subprocess.Popen`` double that NEVER drives the event loop.

    Construction is synchronous (it is the body of the fd-3-clobber window), so a
    test asserting "no await in the window" can drive the spawn and trust that any
    suspension would have surfaced. ``wait`` is the blocking reap the child awaits
    in an executor; it returns the scripted ``returncode``.
    """

    def __init__(self, *, returncode: int | None = None) -> None:
        self.stdin = _FakeStdio()
        self.stdout = _FakeStdio()
        self.stderr = _FakeStdio()
        self._returncode = returncode
        self.returncode: int | None = None
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0
        # An Event the test sets to release a blocking ``wait`` (the long-lived
        # child case). When None, ``wait`` returns immediately (the exit case).
        self.release: asyncio.Event | None = None

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:
        self.kill_calls += 1

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        self.returncode = 0 if self._returncode is None else self._returncode
        return self.returncode


class _Spawned:
    """Records one ``popen_factory`` call's argv / kwargs + the live fd-3 state."""

    def __init__(self) -> None:
        self.argv: list[str] | None = None
        self.env: dict[str, str] | None = None
        self.pass_fds: tuple[int, ...] | None = None
        self.fd3_during_spawn: int | None = None
        self.proc: _FakePopen | None = None


class _PopenFactory:
    """A synchronous ``subprocess.Popen`` replacement (never drives the loop).

    On call it captures argv/env/pass_fds AND records the os.stat identity of the
    LIVE fd 3 (the dup'd read-end is on fd 3 at this instant — the child inherits
    it). It NEVER awaits, so a window that wrapped an ``await`` around this call
    would be caught by the no-await sentinel.
    """

    def __init__(self, *, proc: _FakePopen | None = None, raises: Exception | None = None) -> None:
        self.record = _Spawned()
        self._proc = proc if proc is not None else _FakePopen()
        self._raises = raises

    def __call__(self, argv: list[str], **kwargs: Any) -> _FakePopen:
        self.record.argv = argv
        self.record.env = kwargs.get("env")
        self.record.pass_fds = kwargs.get("pass_fds")
        # Capture that fd 3 is open RIGHT NOW (mid-window) — the child inherits it.
        try:
            os.fstat(3)
            self.record.fd3_during_spawn = 3
        except OSError:
            self.record.fd3_during_spawn = None
        if self._raises is not None:
            raise self._raises
        self.record.proc = self._proc
        return self._proc


class _FakeRunner:
    """A :class:`CommsPluginRunner` double driving the handshake + pump + teardown seams.

    ``pump_blocks`` (Spec B G6-7-3 / #309): when set, :meth:`pump` parks on it so a test
    can cancel the awaiting ``wait_until_exit`` mid-pump (the supervised steady state). By
    default ``pump`` returns at once (a clean child stdout EOF) so the exit-code reap runs.
    """

    def __init__(
        self,
        *,
        transport: GatewayAdapterStdioTransport,
        handshake_raises: Exception | None = None,
        pump_blocks: asyncio.Event | None = None,
        pump_raises: Exception | None = None,
    ) -> None:
        self._transport = transport
        self._handshake_raises = handshake_raises
        self._pump_blocks = pump_blocks
        self._pump_raises = pump_raises
        self.handshake_calls = 0
        self.pump_calls = 0

    async def start_and_handshake(self) -> None:
        self.handshake_calls += 1
        if self._handshake_raises is not None:
            # The real runner closes the transport on a handshake failure; mirror it.
            await self._transport.close()
            raise self._handshake_raises

    async def pump(self) -> None:
        self.pump_calls += 1
        if self._pump_raises is not None:
            # A defensive "unexpected fault escaped the pump" — the pump's normal terminal
            # arms RETURN, so a raise here is a bug/unhandled transport fault (Spec B
            # G6-7-3 / #309). ``wait_until_exit`` must reap the live child, not let it leak.
            raise self._pump_raises
        if self._pump_blocks is not None:
            # Park until released (or cancelled) — the supervised steady state. The real
            # pump closes the transport on a cancel; mirror it so teardown is observable.
            try:
                await self._pump_blocks.wait()
            except asyncio.CancelledError:
                await self._transport.close()
                raise


class _RunnerFactory:
    """Captures the transport the factory builds + yields a scriptable fake runner."""

    def __init__(
        self,
        *,
        handshake_raises: Exception | None = None,
        pump_blocks: asyncio.Event | None = None,
        pump_raises: Exception | None = None,
    ) -> None:
        self._handshake_raises = handshake_raises
        self._pump_blocks = pump_blocks
        self._pump_raises = pump_raises
        self.transport: GatewayAdapterStdioTransport | None = None
        self.adapter_id: str | None = None
        self.runner: _FakeRunner | None = None

    def __call__(self, *, transport: GatewayAdapterStdioTransport, adapter_id: str) -> _FakeRunner:
        self.transport = transport
        self.adapter_id = adapter_id
        self.runner = _FakeRunner(
            transport=transport,
            handshake_raises=self._handshake_raises,
            pump_blocks=self._pump_blocks,
            pump_raises=self._pump_raises,
        )
        return self.runner


class _DeliverRecorder:
    """A ``deliver_credential`` hook fake recording sequencing + optionally raising."""

    def __init__(self, *, raises: Exception | None = None) -> None:
        self._raises = raises
        self.calls = 0
        self.write_fd: int | None = None
        # The handshake-call count AT the moment the hook ran (must be 0 — the hook
        # runs BEFORE the handshake).
        self.handshake_calls_at_delivery: int | None = None
        # The fd-3 state when the hook ran: the window must be CLOSED (parent fd 3
        # restored to its prior value / closed), so fd 3 is NOT our read-end here.
        self._runner_factory: _RunnerFactory | None = None

    def bind_runner_factory(self, factory: _RunnerFactory) -> None:
        self._runner_factory = factory

    async def __call__(self, write_fd: int) -> None:
        self.calls += 1
        self.write_fd = write_fd
        if self._runner_factory is not None and self._runner_factory.runner is not None:
            self.handshake_calls_at_delivery = self._runner_factory.runner.handshake_calls
        else:
            self.handshake_calls_at_delivery = 0
        # The hook owns closing write_fd in production (the credential client does);
        # close it here so the test leaks no descriptor.
        os.close(write_fd)
        if self._raises is not None:
            raise self._raises


def _build_factory(
    *,
    popen_factory: _PopenFactory,
    runner_factory: _RunnerFactory,
) -> GatewayAdapterChildFactory:
    return GatewayAdapterChildFactory(
        runner_factory=cast("Any", runner_factory),
        popen_factory=cast("Any", popen_factory),
    )


# --------------------------------------------------------------------------
# Happy path + sequencing
# --------------------------------------------------------------------------


async def test_spawn_sequence_window_then_deliver_then_handshake() -> None:
    """The hook runs with the write end AFTER the window closes / BEFORE handshake."""
    popen_factory = _PopenFactory()
    runner_factory = _RunnerFactory()
    deliver = _DeliverRecorder()
    deliver.bind_runner_factory(runner_factory)
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=deliver
    )

    # The hook ran exactly once, with a real write fd, BEFORE the handshake.
    assert deliver.calls == 1
    assert isinstance(deliver.write_fd, int)
    assert deliver.handshake_calls_at_delivery == 0
    # The handshake ran AFTER the hook (the runner saw one start_and_handshake).
    assert runner_factory.runner is not None
    assert runner_factory.runner.handshake_calls == 1
    # The transport wraps the live Popen with the right adapter id.
    assert runner_factory.adapter_id == "discord"
    assert isinstance(runner_factory.transport, GatewayAdapterStdioTransport)
    assert isinstance(child, _GatewayAdapterChild)
    await child.aclose()


async def test_spawn_window_dups_read_end_onto_fd3_and_passes_it() -> None:
    """The child inherits the pipe read-end on LITERAL fd 3 (``pass_fds=(3,)``)."""
    popen_factory = _PopenFactory()
    runner_factory = _RunnerFactory()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )

    assert popen_factory.record.pass_fds == (3,)
    # fd 3 was OPEN at the instant Popen forked (the dup'd read-end) — the child
    # inherits it.
    assert popen_factory.record.fd3_during_spawn == 3
    await child.aclose()


async def test_spawn_window_restores_parent_fd3_after_spawn() -> None:
    """The parent's fd 3 is RESTORED once the window closes (clobber is reversible)."""
    # Open a sentinel on fd 3 BEFORE the spawn so the window has a prior fd 3 to save.
    sentinel_r, sentinel_w = os.pipe()
    saved = None
    try:
        saved = os.dup(3) if _fd_open(3) else None
        os.dup2(sentinel_r, 3)
        stat_before = os.fstat(3)
        popen_factory = _PopenFactory()
        runner_factory = _RunnerFactory()
        factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

        child = await factory.spawn_and_handshake(
            adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
        )
        # The parent's fd 3 is the SAME sentinel after the window closed.
        stat_after = os.fstat(3)
        assert (stat_after.st_dev, stat_after.st_ino) == (stat_before.st_dev, stat_before.st_ino)
        await child.aclose()
    finally:
        if saved is not None:
            os.dup2(saved, 3)
            os.close(saved)
        else:
            with __import__("contextlib").suppress(OSError):
                os.close(3)
        for fd in (sentinel_r, sentinel_w):
            with __import__("contextlib").suppress(OSError):
                os.close(fd)


async def test_spawn_argv_targets_the_launcher_with_discord_plugin_and_module() -> None:
    """The argv is ``[launcher, plugin_id, python, "-m", module]`` for discord."""
    popen_factory = _PopenFactory()
    runner_factory = _RunnerFactory()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )

    argv = popen_factory.record.argv
    assert argv is not None
    assert argv[1] == "alfred.discord"
    assert argv[-3:] == [argv[2], "-m", "plugins.alfred_discord.server"]
    await child.aclose()


async def test_spawn_env_is_scrubbed_and_sets_environment_no_host_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The child env is the scrubbed allowlist + ALFRED_ENVIRONMENT, no host secrets."""
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "operator-token")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-operator-secret")
    popen_factory = _PopenFactory()
    runner_factory = _RunnerFactory()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )

    env = popen_factory.record.env
    assert env is not None
    assert env.get("ALFRED_ENVIRONMENT") == "test"
    assert "DISCORD_BOT_TOKEN" not in env
    assert "ANTHROPIC_API_KEY" not in env
    await child.aclose()


# --------------------------------------------------------------------------
# Credential-exception propagation (H1 / M3 — UNWRAPPED)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        CredentialLegDownError("leg down"),
        AdapterCredentialError(adapter_id="discord", reason="grant_mismatch"),
    ],
)
async def test_credential_exception_propagates_unwrapped(exc: Exception) -> None:
    """A credential exception from the hook propagates UNWRAPPED (NOT re-wrapped)."""
    proc = _FakePopen()
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory()
    deliver = _DeliverRecorder(raises=exc)
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    with pytest.raises(type(exc)) as caught:
        await factory.spawn_and_handshake(
            adapter_id="discord", epoch="e1", deliver_credential=deliver
        )
    assert caught.value is exc
    # NOT a GatewayAdapterSpawnError — the supervisor's AWAITING_CORE arm depends on
    # the distinct type surviving.
    assert not isinstance(caught.value, GatewayAdapterSpawnError)
    # H1(a): the half-spawned child is reaped before the raise (no fd-3 wedge).
    assert proc.terminate_calls == 1
    assert proc.wait_calls == 1
    # The handshake never ran.
    assert runner_factory.runner is None


# --------------------------------------------------------------------------
# Fail-closed spawn / handshake faults -> GatewayAdapterSpawnError + reap (H1a)
# --------------------------------------------------------------------------


async def test_launcher_popen_fault_raises_spawn_error_no_child_to_reap() -> None:
    """A Popen OSError -> GatewayAdapterSpawnError; no child was created (nothing to reap)."""
    popen_factory = _PopenFactory(raises=OSError("launcher exploded"))
    runner_factory = _RunnerFactory()
    deliver = _DeliverRecorder()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    with pytest.raises(GatewayAdapterSpawnError):
        await factory.spawn_and_handshake(
            adapter_id="discord", epoch="e1", deliver_credential=deliver
        )
    # The hook never ran (the spawn failed before it) and no runner was built.
    assert deliver.calls == 0
    assert runner_factory.runner is None


async def test_handshake_fault_raises_spawn_error_and_reaps_child() -> None:
    """A handshake failure -> GatewayAdapterSpawnError AND the child is terminate-and-reaped."""
    proc = _FakePopen()
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory(handshake_raises=RuntimeError("handshake torn"))
    deliver = _DeliverRecorder()
    deliver.bind_runner_factory(runner_factory)
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    with pytest.raises(GatewayAdapterSpawnError):
        await factory.spawn_and_handshake(
            adapter_id="discord", epoch="e1", deliver_credential=deliver
        )
    # The credential WAS delivered (the hook ran before the handshake)...
    assert deliver.calls == 1
    # ...but the handshake tore, so the child is reaped (no wedge) — H1(a).
    assert proc.terminate_calls == 1
    assert proc.wait_calls == 1


class _RaisingRunnerFactory:
    """A ``runner_factory`` that raises AFTER the child spawned + the credential delivered.

    Models the unwired default (and any runner-construction fault): the child is already
    a live sandbox holding its delivered credential, so a raise here MUST still
    terminate-and-reap it (no leaked credentialed child) — the CR #3 reap gap.
    """

    def __init__(self, *, raises: Exception) -> None:
        self._raises = raises
        self.calls = 0

    def __call__(self, *, transport: GatewayAdapterStdioTransport, adapter_id: str) -> _FakeRunner:
        self.calls += 1
        raise self._raises


async def test_runner_factory_fault_reaps_spawned_child() -> None:
    """A ``runner_factory`` raise AFTER spawn+deliver terminate-and-reaps the child (CR #3).

    The credential was delivered to the live sandbox child over fd 3 BEFORE the runner is
    built. If building the runner raises, the child keeps running with its delivered
    credential unless it is reaped — a credential-leak gap. The factory must reap the
    spawned child (and propagate the error) just like the handshake-fault path.
    """
    proc = _FakePopen()
    popen_factory = _PopenFactory(proc=proc)
    original = RuntimeError("runner construction blew up")
    runner_factory = _RaisingRunnerFactory(raises=original)
    deliver = _DeliverRecorder()
    factory = GatewayAdapterChildFactory(
        runner_factory=cast("Any", runner_factory),
        popen_factory=cast("Any", popen_factory),
    )

    # A generic runner-construction fault is wrapped fail-closed (same contract as a
    # handshake fault) but the original cause is preserved.
    with pytest.raises(GatewayAdapterSpawnError) as caught:
        await factory.spawn_and_handshake(
            adapter_id="discord", epoch="e1", deliver_credential=deliver
        )
    assert caught.value.__cause__ is original
    # The credential WAS delivered (the hook ran before the runner build)...
    assert deliver.calls == 1
    assert runner_factory.calls == 1
    # ...but the runner build raised, so the spawned child is terminate-and-reaped (no
    # leaked credentialed child) — the CR #3 fix.
    assert proc.terminate_calls == 1
    assert proc.wait_calls == 1


async def test_unwired_runner_factory_default_reaps_spawned_child() -> None:
    """The production ``_unwired_runner_factory`` default also reaps the spawned child.

    With a non-empty adapter set but no real runner wired, the default factory raises a
    ``GatewayAdapterSpawnError`` AFTER the spawn+deliver — the same leak shape. The child
    must be reaped before the loud raise.
    """
    from alfred.gateway.process import _unwired_runner_factory

    proc = _FakePopen()
    popen_factory = _PopenFactory(proc=proc)
    deliver = _DeliverRecorder()
    factory = GatewayAdapterChildFactory(
        runner_factory=_unwired_runner_factory,
        popen_factory=cast("Any", popen_factory),
    )

    with pytest.raises(GatewayAdapterSpawnError):
        await factory.spawn_and_handshake(
            adapter_id="discord", epoch="e1", deliver_credential=deliver
        )
    assert deliver.calls == 1
    # The unwired default raised after spawn+deliver — the live child is reaped.
    assert proc.terminate_calls == 1
    assert proc.wait_calls == 1


async def test_handshake_already_typed_spawn_error_is_not_double_wrapped() -> None:
    """A runner ``GatewayAdapterSpawnError`` propagates AS-IS (reaped, not re-wrapped)."""
    proc = _FakePopen()
    popen_factory = _PopenFactory(proc=proc)
    typed = GatewayAdapterSpawnError("runner refused fail-closed")
    runner_factory = _RunnerFactory(handshake_raises=typed)
    deliver = _DeliverRecorder()
    deliver.bind_runner_factory(runner_factory)
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    with pytest.raises(GatewayAdapterSpawnError) as caught:
        await factory.spawn_and_handshake(
            adapter_id="discord", epoch="e1", deliver_credential=deliver
        )
    # The SAME error object — not a fresh GatewayAdapterSpawnError wrapping it.
    assert caught.value is typed
    # Still reaped (H1a).
    assert proc.terminate_calls == 1
    assert proc.wait_calls == 1


async def test_spawn_without_prior_fd3_closes_the_installed_dup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the parent has no prior fd 3, the window closes the dup it installed (else-branch).

    Forces the ``saved_fd3 is None`` else-branch by faking ``os.dup`` to raise so the
    window cannot save a prior fd 3 and must instead close the fd it dup'd onto fd 3
    itself. ``os.close`` is faked so the synthetic fd-3 close does not disturb the real
    descriptor table (mirrors the quarantine seam's coverage test).
    """

    def _no_dup(_fd: int) -> int:
        raise OSError("no prior fd 3")

    closed: list[int] = []
    real_close = os.close

    def _tracking_close(fd: int) -> None:
        closed.append(fd)
        # Do not actually close fd 3 (the real dup2 DID install our read-end there, but
        # closing it now would race the running test's fd table — track only).
        if fd != 3:
            real_close(fd)

    monkeypatch.setattr("alfred.gateway.adapter_child_factory.os.dup", _no_dup)
    monkeypatch.setattr("alfred.gateway.adapter_child_factory.os.close", _tracking_close)

    popen_factory = _PopenFactory()
    runner_factory = _RunnerFactory()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)
    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )
    # The else-branch attempted to close the literal fd 3 it installed.
    assert 3 in closed
    await child.aclose()


async def test_unknown_adapter_id_raises_spawn_error() -> None:
    """An adapter_id outside the CLOSED static map -> GatewayAdapterSpawnError (no spawn)."""
    popen_factory = _PopenFactory()
    runner_factory = _RunnerFactory()
    deliver = _DeliverRecorder()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    with pytest.raises(GatewayAdapterSpawnError):
        await factory.spawn_and_handshake(
            adapter_id="telegram", epoch="e1", deliver_credential=deliver
        )
    # Nothing was spawned, no credential requested.
    assert popen_factory.record.argv is None
    assert deliver.calls == 0


# --------------------------------------------------------------------------
# _GatewayAdapterChild — wait_until_exit + teardown (H1 b/c)
# --------------------------------------------------------------------------


async def test_wait_until_exit_awaits_and_maps_exit() -> None:
    """``wait_until_exit`` awaits ``proc.wait`` off-loop + returns ``(error_class, detail)``."""
    proc = _FakePopen(returncode=1)
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )
    error_class, detail = await child.wait_until_exit()
    assert proc.wait_calls >= 1
    assert isinstance(error_class, str) and error_class
    assert isinstance(detail, str)
    await child.aclose()


async def test_teardown_reaps_popen_and_closes_transport() -> None:
    """The teardown method terminates+waits the Popen AND closes the transport pipes (H1b)."""
    proc = _FakePopen()
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )
    await child.aclose()
    assert proc.terminate_calls == 1
    assert proc.wait_calls == 1
    # The transport closed the pipes (clean EOF for the child).
    assert proc.stdin.closed is True
    assert proc.stdout.closed is True
    # Idempotent.
    await child.aclose()
    assert proc.terminate_calls == 1


async def test_wait_until_exit_drives_the_runner_pump_then_reaps() -> None:
    """Spec B G6-7-3 (#309): the supervised lifetime DRIVES the pump, then reaps the code.

    The production-unwired trap guard: ``wait_until_exit`` must run ``runner.pump()`` (which
    forwards the child's inbound) before reaping the exit code — else the runner is dropped
    and a hosted child's ``inbound.message`` reaches nothing.
    """
    proc = _FakePopen(returncode=0)
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )
    assert runner_factory.runner is not None
    assert runner_factory.runner.pump_calls == 0  # not driven yet (factory just handshook)
    await child.wait_until_exit()
    assert runner_factory.runner.pump_calls == 1  # the supervised lifetime drove the pump
    assert proc.wait_calls >= 1  # then reaped the exit code
    await child.aclose()


async def test_wait_until_exit_cancel_during_pump_unwinds() -> None:
    """A planned-stop cancel mid-pump unwinds cleanly (the pump closes the transport)."""
    proc = _FakePopen()
    pump_gate = asyncio.Event()
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory(pump_blocks=pump_gate)
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )
    task = asyncio.ensure_future(child.wait_until_exit())
    await asyncio.sleep(0)  # let the pump park
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The cancelled pump closed the transport (clean EOF for the child); teardown reaps.
    await child.aclose()
    assert proc.terminate_calls == 1


async def test_wait_until_exit_pump_fault_reaps_child_and_returns_crash_tuple() -> None:
    """A non-Cancelled pump fault reaps the child + returns a bounded crash tuple (CR-1).

    ``pump``'s normal terminal arms (EOF / crash / malformed / shutdown) RETURN — so a
    raised non-``CancelledError`` exception is the defensive "a bug or unhandled transport
    fault escaped" case. If it propagated out of ``wait_until_exit`` the live Popen would
    leak (no reap) — violating the H1 "no leaked sandbox child" discipline (CLAUDE.md hard
    rule #7). The fix: terminate-and-reap the child and return a bounded, payload-blind
    crash tuple so the supervisor's crash arm restarts/breakers it instead of an exception
    escaping ``supervise_one``. The detail carries NO exception text (hard rule #5).
    """
    proc = _FakePopen()
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory(pump_raises=RuntimeError("secret-bearing pump fault"))
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )
    error_class, detail = await child.wait_until_exit()
    # A bounded, closed-vocab crash tuple — NOT the exception text (payload-blind, #5).
    assert error_class == "AdapterChildExited"
    assert detail == "exit_code=pump_failed"
    assert "secret-bearing" not in detail
    # The live child was terminate-and-reaped (no leaked sandbox child) — H1 / hard rule #7.
    assert proc.terminate_calls == 1
    assert proc.wait_calls == 1
    await child.aclose()


async def test_wait_until_exit_pump_cancel_propagates_without_reaping() -> None:
    """A ``CancelledError`` from the pump propagates; ``wait_until_exit`` does NOT reap (CR-1).

    A planned-stop cancellation still propagates and is reaped via ``aclose`` on the
    supervisor's teardown path — ``wait_until_exit`` must NOT reap on cancel (``aclose``
    owns it), distinguishing the planned-stop cancel from an unexpected pump fault.
    """
    proc = _FakePopen()
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory(pump_raises=asyncio.CancelledError())
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )
    with pytest.raises(asyncio.CancelledError):
        await child.wait_until_exit()
    # ``wait_until_exit`` did NOT reap — ``aclose`` (the supervisor teardown) owns it.
    assert proc.terminate_calls == 0
    assert proc.wait_calls == 0
    # ``aclose`` reaps it on the teardown path.
    await child.aclose()
    assert proc.terminate_calls == 1


async def test_wait_until_exit_is_cancellation_safe() -> None:
    """Cancelling the ``wait_until_exit`` task does not leak; teardown still reaps (H1c)."""
    proc = _FakePopen()
    # Make ``wait`` block until released so we can cancel the awaiting task mid-flight.
    gate = asyncio.Event()

    def _blocking_wait(timeout: float | None = None) -> int:
        # Runs in an executor thread; block on a threading primitive surrogate by
        # spinning on the asyncio Event's internal flag via a short sleep loop.
        import time

        while not gate.is_set():
            time.sleep(0.005)
        proc.wait_calls += 1
        proc.returncode = 0
        return 0

    proc.wait = _blocking_wait  # type: ignore[method-assign]
    popen_factory = _PopenFactory(proc=proc)
    runner_factory = _RunnerFactory()
    factory = _build_factory(popen_factory=popen_factory, runner_factory=runner_factory)

    child = await factory.spawn_and_handshake(
        adapter_id="discord", epoch="e1", deliver_credential=_DeliverRecorder()
    )
    task = asyncio.ensure_future(child.wait_until_exit())
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The cancelled task did not crash the child; teardown still reaps cleanly.
    gate.set()
    await child.aclose()
    assert proc.terminate_calls == 1


def _fd_open(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return False
    return True
