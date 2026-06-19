"""G6-2b-2a (#288): GatewayProcess wires the supervisor live with an empty adapter set.

The adapter supervisor is wired LIVE into the gateway process boot (its status emitter
bound to the live ``core_link.send_status_frame`` leg), but with an EMPTY configured
adapter set (gap b) — the plumbing is live, no child is spawned until G6-3. The
supervised supervisor task is cancelled/reaped on gateway-process shutdown (correction
#5) so a future NON-empty set cannot block the shutdown forever.
"""

from __future__ import annotations

import asyncio

from alfred.gateway.adapter_supervisor import (
    GatewayAdapterSpawnError,
    GatewayAdapterSupervisor,
)
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.core_link import GatewayCoreLink
from alfred.gateway.process import (
    GatewayProcess,
    _UnavailableCredSeam,
    _UnspawnedAdapterChildFactory,
)


def _make_core_link() -> GatewayCoreLink:
    return GatewayCoreLink(client_listener=GatewayClientListener())


def test_process_builds_status_sink_and_supervisor_for_core_link() -> None:
    """The process builds a GatewayAdapterSupervisor bound to a core link's status leg.

    2b-2a wires the plumbing and spawns nothing — the configured adapter set is empty.
    """
    process = GatewayProcess(shutdown_event=asyncio.Event())
    core_link = _make_core_link()
    supervisor = process._build_adapter_supervisor(core_link)
    assert isinstance(supervisor, GatewayAdapterSupervisor)
    assert process._adapter_ids == []  # 2b-2a wires the plumbing, spawns nothing


async def test_supervise_empty_set_is_a_clean_noop() -> None:
    """supervise_all([]) returns immediately — live-wired, spawns nothing (gap b)."""
    process = GatewayProcess(shutdown_event=asyncio.Event())
    core_link = _make_core_link()
    supervisor = process._build_adapter_supervisor(core_link)
    await asyncio.wait_for(supervisor.supervise_all(process._adapter_ids), timeout=1.0)


async def test_unspawned_child_factory_fails_closed() -> None:
    """The placeholder child factory raises GatewayAdapterSpawnError (fail-closed, gap b).

    With the empty adapter set it is never called; if a future non-empty set is passed
    before G6-3, the spawn fails LOUD rather than running a credential-less adapter.
    """
    factory = _UnspawnedAdapterChildFactory()
    with __import__("pytest").raises(GatewayAdapterSpawnError):
        await factory.spawn_and_handshake(adapter_id="discord", epoch="a" * 32)


async def test_unavailable_cred_seam_is_always_unavailable() -> None:
    """The placeholder cred seam reports unavailable (real cred is G6-3)."""
    seam = _UnavailableCredSeam()
    assert await seam.is_available(adapter_id="discord") is False


async def test_supervisor_task_is_cancelled_on_shutdown() -> None:
    """Correction #5: the supervised supervisor task is cancelled/reaped on shutdown.

    Drives ``_run_relay_and_supervisor`` with a NON-empty adapter set so the supervisor
    would otherwise park forever (the placeholder cred seam never makes the adapter
    available — it stays in AWAITING_CORE). A fake relay returns as soon as shutdown is
    signalled; the helper must then cancel the parked supervisor task and return, never
    hang. A hang fails the ``wait_for`` timeout LOUD (hard rule #7).
    """
    shutdown = asyncio.Event()
    process = GatewayProcess(shutdown_event=shutdown, adapter_ids=["discord"])
    core_link = _make_core_link()
    supervisor = process._build_adapter_supervisor(core_link)

    class _FakeRelay:
        async def run(self) -> None:
            # Stand in for the real relay: end as soon as shutdown is signalled.
            await shutdown.wait()

    async def _signal_shutdown_soon() -> None:
        await asyncio.sleep(0.05)
        shutdown.set()

    signal_task = asyncio.ensure_future(_signal_shutdown_soon())
    try:
        # If the supervisor task were NOT cancelled on the relay's clean return, this
        # would hang (the discord adapter parks in AWAITING_CORE forever) -> timeout.
        await asyncio.wait_for(
            process._run_relay_and_supervisor(_FakeRelay(), supervisor), timeout=2.0
        )
    finally:
        await signal_task


async def test_supervisor_spawn_failure_aborts_and_cancels_the_relay() -> None:
    """A fail-closed supervisor spawn error surfaces LOUD and cancels the running relay.

    The supervisor (not the relay) finishes first WITH a raise — the helper re-raises it
    (so a real G6-3 spawn failure is never swallowed) and the ``finally`` cancels the
    still-running relay so it never outlives the aborted process (covers the relay-cancel
    arm).
    """
    import pytest

    process = GatewayProcess(shutdown_event=asyncio.Event(), adapter_ids=["discord"])

    class _RaisingSupervisor:
        async def supervise_all(self, adapter_ids: list[str]) -> None:
            raise GatewayAdapterSpawnError("spawn refused (fail-closed)")

    relay_cancelled = asyncio.Event()

    class _ForeverRelay:
        async def run(self) -> None:
            try:
                await asyncio.Event().wait()  # runs until cancelled
            except asyncio.CancelledError:
                relay_cancelled.set()
                raise

    with pytest.raises(GatewayAdapterSpawnError):
        await asyncio.wait_for(
            process._run_relay_and_supervisor(_ForeverRelay(), _RaisingSupervisor()),  # type: ignore[arg-type]
            timeout=2.0,
        )
    assert relay_cancelled.is_set()
