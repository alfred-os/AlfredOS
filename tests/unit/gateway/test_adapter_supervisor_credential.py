"""Supervisor + real-shaped credential client integration (G6-3 Task 4 + 5b, #288).

Drives :class:`GatewayAdapterSupervisor` against a fake child factory that owns a real
fd-3 pipe + a fake credential client, asserting the G6-3 wiring:

* the at-spawn credential is delivered over the child's fd-3 write end (Task 5b);
* the epoch is sourced LIVE per spawn (H1) — a core bounce mints a new epoch and the
  NEXT spawn carries it;
* a ``CredentialLegDownError`` from the credential round-trip routes the adapter to
  AWAITING_CORE (Task 4 link-down arm), NOT a crash;
* a fail-closed ``AdapterCredentialError`` (grant refusal / mismatch / fd-3 fault)
  aborts the spawn loudly with NO ``up`` frame (the no-continue matrix);
* per-adapter isolation: each spawn gets its OWN fd-3 + credential, the client holds
  no shared credential field (adversarial a in-process analog).
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from alfred.comms_mcp.adapter_credential_resolver import AdapterCredentialError
from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    GatewayAdapterSupervisor,
    _DeliverCredential,
)
from alfred.gateway.core_link import CredentialLegDownError

pytestmark = pytest.mark.asyncio

_EPOCH = "0123456789abcdef0123456789abcdef"
_EPOCH2 = "fedcba9876543210fedcba9876543210"
_A = "discord"
_SENTINEL_CRED = "SENTINEL-CREDENTIAL-DO-NOT-LEAK-7f3a"


@dataclass
class _RecordingSink:
    frames: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    async def emit(self, method: str, params: dict[str, object]) -> None:
        self.frames.append((method, params))

    def methods(self) -> list[str]:
        return [m for m, _ in self.frames]


@dataclass
class _FakeChild:
    adapter_id: str
    exit_future: asyncio.Future[tuple[str, str]]

    async def wait_until_exit(self) -> tuple[str, str]:
        return await self.exit_future


class _PipeChildFactory:
    """A factory that owns a real fd-3 pipe per spawn + invokes the credential hook.

    Records the (read_fd, write_fd) of each spawn so a test can prove per-spawn fd
    isolation, and the epoch passed to each spawn (H1).
    """

    def __init__(self) -> None:
        self.spawn_epochs: list[str] = []
        self.write_fds: list[int] = []
        self.children: list[_FakeChild] = []

    async def spawn_and_handshake(
        self, *, adapter_id: str, epoch: str, deliver_credential: _DeliverCredential
    ) -> _FakeChild:
        self.spawn_epochs.append(epoch)
        read_fd, write_fd = os.pipe()
        self.write_fds.append(write_fd)
        try:
            await deliver_credential(write_fd)
        finally:
            os.close(read_fd)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[tuple[str, str]] = loop.create_future()
        child = _FakeChild(adapter_id=adapter_id, exit_future=fut)
        self.children.append(child)
        return child


class _RecordingCredentialClient:
    """Records each acquire_and_deliver call + the bytes it wrote to the fd-3 sink."""

    def __init__(self, *, raise_factory: Callable[[], BaseException] | None = None) -> None:
        self.calls: list[tuple[str, int, str]] = []
        self.delivered: list[str] = []
        self._raise_factory = raise_factory

    async def acquire_and_deliver(
        self, *, adapter_id: str, host_restart_seq: int, write_fd: int, epoch: str
    ) -> None:
        self.calls.append((adapter_id, host_restart_seq, epoch))
        if self._raise_factory is not None:
            os.close(write_fd)  # the real client closes write_fd on its refusal path
            raise self._raise_factory()
        # Deliver the sentinel over fd 3 (length-prefixed), closing write_fd like the lib.
        body = _SENTINEL_CRED.encode("utf-8")
        os.write(write_fd, len(body).to_bytes(4, "big") + body)
        os.close(write_fd)
        self.delivered.append(_SENTINEL_CRED)


async def _instant_sleep(_seconds: float) -> None:
    pass


class _FakeClock:
    def __init__(self) -> None:
        self._t = 0.0

    def monotonic(self) -> float:
        self._t += 1.0
        return self._t


def _make_supervisor(
    *,
    factory: _PipeChildFactory,
    client: _RecordingCredentialClient,
    sink: _RecordingSink,
    epoch_source: Callable[[], str | None],
    cred_available: Callable[[], bool] | None = None,
) -> GatewayAdapterSupervisor:
    available = cred_available if cred_available is not None else (lambda: True)

    class _Seam:
        async def is_available(self, *, adapter_id: str) -> bool:
            return available()

    return GatewayAdapterSupervisor(
        child_factory=factory,  # type: ignore[arg-type]
        cred_seam=_Seam(),
        credential_client=client,  # type: ignore[arg-type]
        emitter=AdapterStatusEmitter(sink=sink),
        epoch_source=epoch_source,
        sleep=_instant_sleep,  # type: ignore[arg-type]
        monotonic=_FakeClock().monotonic,
    )


# --- Task 5b: the credential reaches the child's fd-3 -------------------------


async def test_spawn_delivers_credential_over_fd3_with_live_epoch() -> None:
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient()
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, client=client, sink=sink, epoch_source=lambda: _EPOCH)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A)

    # The credential client was called with the live epoch + incarnation 0.
    assert client.calls == [(_A, 0, _EPOCH)]
    assert client.delivered == [_SENTINEL_CRED]
    # The up frame carries the SAME (spawn) epoch.
    up = [(m, p) for m, p in sink.frames if m == "gateway.adapter.up"]
    assert up[0][1]["epoch"] == _EPOCH

    await sup.request_stop(_A)
    await task


# --- H1: epoch sourced LIVE per spawn (core bounce -> new epoch) ---------------


async def test_epoch_sourced_live_per_spawn_after_core_bounce() -> None:
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient()
    sink = _RecordingSink()
    # The epoch flips after the first read (a core bounce mints a new epoch).
    epochs = iter([_EPOCH, _EPOCH2, _EPOCH2, _EPOCH2])
    sup = _make_supervisor(
        factory=factory, client=client, sink=sink, epoch_source=lambda: next(epochs)
    )

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A, incarnation=1)
    # Crash the first incarnation -> the restart spawns under the NEW epoch.
    factory.children[0].exit_future.set_result(("Boom", "crashed"))
    await sup.wait_until_up(_A, incarnation=2)

    # The second spawn_request carried the bounced epoch (NOT the stale construction one).
    assert factory.spawn_epochs[0] == _EPOCH
    assert factory.spawn_epochs[1] == _EPOCH2
    assert client.calls[1][2] == _EPOCH2

    await sup.request_stop(_A)
    await task


# --- Task 4: leg-down during the round-trip -> AWAITING_CORE (not a crash) -----


async def test_leg_down_during_roundtrip_routes_to_awaiting_core() -> None:
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient(raise_factory=lambda: CredentialLegDownError("down"))
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, client=client, sink=sink, epoch_source=lambda: _EPOCH)

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_awaiting_core(_A)

    # No false ``up`` — the leg-down routed to AWAITING_CORE, NOT a crash/up.
    assert "gateway.adapter.up" not in sink.methods()

    await sup.request_stop(_A)
    await task


# --- Task 5b: credential refusal -> fail-closed spawn abort, NO up frame -------


async def test_credential_refusal_aborts_spawn_loud_no_up() -> None:
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient(
        raise_factory=lambda: AdapterCredentialError(adapter_id=_A, reason="grant_mismatch")
    )
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, client=client, sink=sink, epoch_source=lambda: _EPOCH)

    # First-attempt credential refusal surfaces loud (fail-closed boot refusal).
    with pytest.raises(GatewayAdapterSpawnError):
        await sup.supervise_one(_A)
    # NEVER a false ``up`` for an adapter whose credential was refused.
    assert "gateway.adapter.up" not in sink.methods()
    # A ``crashed`` frame WAS emitted (the spawn-abort feeds the crash arm).
    assert "gateway.adapter.crashed" in sink.methods()


# --- Adversarial (a) in-process analog: per-spawn fd isolation ----------------


async def test_each_spawn_gets_its_own_fd3_no_shared_buffer() -> None:
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient()
    sink = _RecordingSink()
    epochs = iter([_EPOCH, _EPOCH, _EPOCH, _EPOCH])
    sup = _make_supervisor(
        factory=factory, client=client, sink=sink, epoch_source=lambda: next(epochs)
    )

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A, incarnation=1)
    factory.children[0].exit_future.set_result(("Boom", "crashed"))
    await sup.wait_until_up(_A, incarnation=2)

    # Each incarnation got its OWN fresh fd-3 pipe + credential delivery (two separate
    # acquire_and_deliver calls, two separate writes). The OS may RECYCLE the same fd
    # NUMBER after the first is closed — that is correct (no overlapping live
    # descriptors), so isolation is asserted on the delivery COUNT + the no-shared-cred
    # invariant, not on fd-number inequality.
    assert len(factory.write_fds) == 2
    assert len(client.delivered) == 2
    assert len(client.calls) == 2
    # The real GatewayAdapterCredentialClient's no-self-credential invariant is proven
    # in test_adapter_credential_client.py; here the recording double deliberately keeps
    # a delivery log, so this test asserts the per-spawn isolation via the call/delivery
    # counts above rather than introspecting the double.

    await sup.request_stop(_A)
    await task
