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
import structlog.testing

from alfred.comms_mcp.adapter_credential_resolver import AdapterCredentialError
from alfred.gateway.adapter_status_emitter import AdapterStatusEmitter
from alfred.gateway.adapter_supervisor import (
    GatewayAdapterCredentialError,
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
    isolation, and the epoch passed to each spawn (H1). ``spawn_raises``, when set,
    makes the spawn itself fail BEFORE the credential round-trip — a launcher/
    handshake fault, distinct from a credential-pipeline refusal (which the
    ``_RecordingCredentialClient`` raise path drives instead).
    """

    def __init__(self, *, spawn_raises: Callable[[], BaseException] | None = None) -> None:
        self.spawn_epochs: list[str] = []
        self.write_fds: list[int] = []
        self.children: list[_FakeChild] = []
        self._spawn_raises = spawn_raises

    async def spawn_and_handshake(
        self, *, adapter_id: str, epoch: str, deliver_credential: _DeliverCredential
    ) -> _FakeChild:
        if self._spawn_raises is not None:
            raise self._spawn_raises()
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


# --- Task 4: recovery within the awaiting-core ceiling -> spawn proceeds -------


async def test_awaiting_core_recovers_within_ceiling_then_spawns() -> None:
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient()
    sink = _RecordingSink()
    # The leg is down for the first two probes, then comes back (within the ceiling).
    states = iter([False, False, True, True, True, True])
    sup = _make_supervisor(
        factory=factory,
        client=client,
        sink=sink,
        epoch_source=lambda: _EPOCH,
        cred_available=lambda: next(states, True),
    )

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A)
    # The adapter recovered + spawned after the leg came back (no breaker trip).
    assert "gateway.adapter.breaker_open" not in sink.methods()

    await sup.request_stop(_A)
    await task


async def test_awaiting_core_ceiling_exceeded_trips_breaker_distinct_alert() -> None:
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient()
    sink = _RecordingSink()
    # The leg never comes back: the awaiting-core re-probe ceiling must trip the
    # breaker (the distinct terminal alert) rather than park silently forever.
    sup = _make_supervisor(
        factory=factory,
        client=client,
        sink=sink,
        epoch_source=lambda: _EPOCH,
        cred_available=lambda: False,
    )

    await asyncio.wait_for(sup.supervise_one(_A), timeout=2.0)
    # The distinct terminal alert fired (no quiet-dark); no false ``up``.
    assert "gateway.adapter.breaker_open" in sink.methods()
    assert "gateway.adapter.up" not in sink.methods()


# --- H1/Task 4: a None live epoch at spawn time -> AWAITING_CORE ---------------


async def test_none_epoch_at_spawn_routes_to_awaiting_core_then_recovers() -> None:
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient()
    sink = _RecordingSink()
    # The cheap probe says available, but the LIVE epoch is None for the first spawn (a
    # leg that lost its handshake between the probe and the spawn) ->
    # CredentialLegDownError -> AWAITING_CORE; then the epoch comes back -> the awaiting
    # wait recovers (returns False) -> ``continue`` -> the retry spawns + reaches up.
    epochs = iter([None, _EPOCH, _EPOCH, _EPOCH])
    sup = _make_supervisor(
        factory=factory,
        client=client,
        sink=sink,
        epoch_source=lambda: next(epochs),
        cred_available=lambda: True,
    )

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A)
    # The first attempt parked in AWAITING_CORE (None epoch), then recovered + spawned.
    assert factory.spawn_epochs == [_EPOCH]

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


# --- the spawn_aborted row carries the DISTINCT credential reason -------------


def _spawn_aborted_reasons(logs: list[dict[str, object]]) -> list[object]:
    return [e["reason"] for e in logs if e.get("event") == "gateway.adapter.spawn_aborted"]


@pytest.mark.parametrize("reason", ["grant_mismatch", "delivery_failed", "missing_secret"])
async def test_spawn_aborted_carries_distinct_credential_reason(reason: str) -> None:
    # The spawn-aborted audit row must preserve the AdapterCredentialError's distinct
    # closed-vocab reason (the G6-3 failure-path contract), NOT collapse every credential
    # failure to the generic ``credential_refused``.
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient(
        raise_factory=lambda: AdapterCredentialError(adapter_id=_A, reason=reason)
    )
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, client=client, sink=sink, epoch_source=lambda: _EPOCH)

    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(GatewayAdapterSpawnError),
    ):
        await sup.supervise_one(_A)

    assert _spawn_aborted_reasons(logs) == [reason]


# --- Persistent credential refusal crash-loops to the breaker (child is None) -


async def test_first_attempt_credential_refusal_is_boot_refusal() -> None:
    factory = _PipeChildFactory()
    # The credential is refused on the FIRST attempt: fail-closed boot refusal (re-raised
    # as GatewayAdapterSpawnError so a boot can refuse the adapter), NO up frame.
    client = _RecordingCredentialClient(
        raise_factory=lambda: AdapterCredentialError(adapter_id=_A, reason="missing_secret")
    )
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, client=client, sink=sink, epoch_source=lambda: _EPOCH)

    with pytest.raises(GatewayAdapterSpawnError):
        await sup.supervise_one(_A)
    assert "gateway.adapter.up" not in sink.methods()
    assert "gateway.adapter.crashed" in sink.methods()


# --- the credential marker: friendly-refusal exception for Task 3 -------------


async def test_first_attempt_credential_refusal_raises_marker() -> None:
    # Task 3 (start_gateway) catches ONLY this marker subclass to render a friendly,
    # actionable refusal for a missing/mismatched/undeliverable operator credential
    # (#469 [R1]) -- the credential-refusal wrap must produce it, not the bare base.
    factory = _PipeChildFactory()
    client = _RecordingCredentialClient(
        raise_factory=lambda: AdapterCredentialError(adapter_id=_A, reason="missing_secret")
    )
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, client=client, sink=sink, epoch_source=lambda: _EPOCH)

    with (
        structlog.testing.capture_logs() as logs,
        pytest.raises(GatewayAdapterCredentialError) as excinfo,
    ):
        await sup.supervise_one(_A)

    # The marker carries the closed-vocab credential reason.
    assert excinfo.value.reason == "missing_secret"
    # The distinct spawn-aborted audit row is still written (_audit_spawn_aborted
    # is untouched by the marker change).
    assert any(e.get("event") == "gateway.adapter.spawn_aborted" for e in logs)


async def test_first_attempt_non_credential_spawn_failure_stays_bare() -> None:
    # A launcher/handshake fault (NOT a credential refusal) is a genuine bug/outage
    # and must keep surfacing the BARE GatewayAdapterSpawnError -- the friendly wrap
    # is credential-only (hard rule #7: a non-credential failure stays loud).
    factory = _PipeChildFactory(
        spawn_raises=lambda: GatewayAdapterSpawnError("fake launcher fault, not credential")
    )
    client = _RecordingCredentialClient()
    sink = _RecordingSink()
    sup = _make_supervisor(factory=factory, client=client, sink=sink, epoch_source=lambda: _EPOCH)

    with pytest.raises(GatewayAdapterSpawnError) as excinfo:
        await sup.supervise_one(_A)

    # Exact type, not just isinstance -- must NOT be the credential marker subclass.
    assert type(excinfo.value) is GatewayAdapterSpawnError


class _CrashThenRefuseClient:
    """Succeeds the first delivery, then refuses every subsequent one (G6-3).

    Drives the NON-first-attempt credential-abort -> crash-arm -> breaker path: the
    first incarnation comes up + crashes (a process exit), then the restart's
    credential is refused on every retry until the breaker trips and
    ``_spawn_or_terminal`` returns None (the ``child is None`` terminal in
    ``supervise_one``).
    """

    def __init__(self) -> None:
        self.calls = 0

    async def acquire_and_deliver(
        self, *, adapter_id: str, host_restart_seq: int, write_fd: int, epoch: str
    ) -> None:
        self.calls += 1
        os.close(write_fd)
        if self.calls > 1:
            raise AdapterCredentialError(adapter_id=adapter_id, reason="missing_secret")
        # First call: deliver the sentinel so the first incarnation reaches up.
        # (write_fd already closed; the fake child does not read it.)


async def test_restart_credential_refusal_routes_through_breaker() -> None:
    factory = _PipeChildFactory()
    client = _CrashThenRefuseClient()
    sink = _RecordingSink()
    sup = _make_supervisor(
        factory=factory,
        client=client,  # type: ignore[arg-type]
        sink=sink,
        epoch_source=lambda: _EPOCH,
    )

    task = asyncio.ensure_future(sup.supervise_one(_A))
    await sup.wait_until_up(_A, incarnation=1)
    # Crash the first incarnation (a process exit) -> restart spawns, whose credential
    # is now refused on every retry -> crash-loop -> breaker -> _spawn_or_terminal None.
    factory.children[0].exit_future.set_result(("BrokenPipeError", "first crash"))
    await sup.wait_until_breaker_open(_A)
    await task  # returns cleanly via the ``child is None`` terminal break

    assert "gateway.adapter.breaker_open" in sink.methods()


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
