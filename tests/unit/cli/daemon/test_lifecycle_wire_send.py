"""``LifecycleBroadcaster`` — core lifecycle wire-send fan-out (Spec A G3-2) (#237).

G3-2 SENDS ``daemon.lifecycle.ready`` / ``daemon.lifecycle.going_down`` as id-less
JSON-RPC notification frames over the socket-listener carrier, alongside the G1
audit rows. The broadcaster is the tiny boot-local registry that collects the
socket-carrier runner's id-less sender and fans a lifecycle frame to it.

The HEADLINE behaviour (architect H-1) is the ZERO-SENDER no-op: the socket peer
connects on-demand later, so the boot-time ``ready`` broadcast reaches no sender —
that is the normal-boot runtime path and it must be a clean DEBUG-level no-op, not a
warning and not a raise. A registered sender raising a transport error is logged
WARNING and does not abort the broadcast; ``asyncio.CancelledError`` propagates (the
``going_down`` broadcast runs in the shutdown ``finally`` — swallowing cancellation
would wedge the drain). The audit row, written at the callsite, stays authoritative;
the wire frame is best-effort (spec §6).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest
from typer.testing import CliRunner

import alfred.cli.daemon._boot_audit as _boot_audit
import alfred.cli.daemon._commands as _daemon_commands
from alfred.cli.daemon import daemon_app
from alfred.cli.daemon._commands import LifecycleBroadcaster
from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
)
from alfred.plugins.comms_wire import CommsProtocolError

from .conftest import FakeAuditWriter, FakeSupervisor

pytestmark = pytest.mark.asyncio

_EPOCH = "a" * 32


class _RecordingSender:
    """Records every id-less ``(method, params)`` the broadcaster sends to it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, object]]] = []

    async def __call__(self, method: str, params: Mapping[str, object]) -> None:
        self.calls.append((method, dict(params)))


async def test_broadcast_ready_with_no_senders_is_a_clean_debug_noop() -> None:
    """The HEADLINE no-op (architect H-1): zero senders -> clean DEBUG, no warning.

    The normal-boot runtime path: the socket peer connects on-demand, so the
    boot-``ready`` broadcast reaches zero senders. It must NOT raise, and it must log
    the no-peer fact at DEBUG (not WARNING) — this is the expected path, not a fault.
    Asserts the actual logging contract, not merely "no exception".

    Uses :func:`structlog.testing.capture_logs` (not ``caplog``): the project routes
    structlog through its own pipeline, so ``caplog`` would miss the event. Mirrors
    ``tests/unit/security/test_extract_dlp_subscriber.py``.
    """
    import structlog.testing

    broadcaster = LifecycleBroadcaster()
    with structlog.testing.capture_logs() as captured:
        # No senders registered. Must not raise.
        await broadcaster.broadcast_ready(_EPOCH)
        await broadcaster.broadcast_going_down("shutdown")

    no_peer = [c for c in captured if c.get("event") == "comms.lifecycle.no_peer"]
    # One per broadcast (ready + going_down), each at DEBUG, each carrying its phase.
    assert len(no_peer) == 2, captured
    assert all(c.get("log_level") == "debug" for c in no_peer), no_peer
    assert {c.get("phase") for c in no_peer} == {"ready", "going_down"}, no_peer
    # The zero-sender path is the expected normal boot — NEVER a warning.
    assert not [c for c in captured if c.get("log_level") == "warning"], captured


async def test_broadcast_ready_calls_each_sender_once_with_epoch() -> None:
    broadcaster = LifecycleBroadcaster()
    sender = _RecordingSender()
    broadcaster.register("tui", sender)

    await broadcaster.broadcast_ready(_EPOCH)

    assert sender.calls == [(DAEMON_LIFECYCLE_READY, {"epoch": _EPOCH})]


async def test_broadcast_going_down_calls_each_sender_once_with_reason() -> None:
    broadcaster = LifecycleBroadcaster()
    sender = _RecordingSender()
    broadcaster.register("tui", sender)

    await broadcaster.broadcast_going_down("shutdown")

    assert sender.calls == [(DAEMON_LIFECYCLE_GOING_DOWN, {"reason": "shutdown"})]


async def test_broadcast_continues_when_a_sender_raises_transport_error() -> None:
    """A registered sender raising a transport error is logged, not fatal.

    The audit row (committed at the callsite) is authoritative; the wire frame is
    best-effort. A broken sender must not abort the broadcast to the others.
    """
    broadcaster = LifecycleBroadcaster()
    good = _RecordingSender()

    async def _broken(_method: str, _params: Mapping[str, object]) -> None:
        raise BrokenPipeError("peer gone")

    broadcaster.register("broken", _broken)
    broadcaster.register("good", good)

    # Does not raise despite the broken sender.
    await broadcaster.broadcast_ready(_EPOCH)

    # The good sender was still called.
    assert good.calls == [(DAEMON_LIFECYCLE_READY, {"epoch": _EPOCH})]


@pytest.mark.parametrize(
    "exc",
    [BrokenPipeError, ConnectionResetError, OSError, CommsProtocolError],
)
async def test_broadcast_swallows_only_the_narrow_transport_family(
    exc: type[BaseException],
) -> None:
    broadcaster = LifecycleBroadcaster()

    async def _raise(_method: str, _params: Mapping[str, object]) -> None:
        raise exc("boom")

    broadcaster.register("x", _raise)
    # None of the narrow transport family aborts the broadcast.
    await broadcaster.broadcast_ready(_EPOCH)


async def test_broadcast_does_not_swallow_unexpected_exception() -> None:
    """A non-transport ``Exception`` is NOT swallowed (no bare-except, hard rule #7)."""
    broadcaster = LifecycleBroadcaster()

    async def _bug(_method: str, _params: Mapping[str, object]) -> None:
        raise ValueError("a real bug")

    broadcaster.register("x", _bug)
    with pytest.raises(ValueError, match="a real bug"):
        await broadcaster.broadcast_ready(_EPOCH)


async def test_broadcast_bounds_a_wedged_sender_with_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connected-but-wedged peer that stops draining must NOT hang the broadcast.

    CR #264 / sec-264-002: ``going_down`` runs in the shutdown ``finally``; a sender
    whose ``await`` never returns (a peer that connected but stopped reading) would
    wedge the daemon drain forever. The broadcaster bounds each send with
    ``_LIFECYCLE_BROADCAST_TIMEOUT_SECONDS`` and, on timeout, logs
    ``comms.lifecycle.wire_send_timeout`` (loud, never silent — hard rule #7) and
    moves on. Monkeypatch the timeout tiny so the wedged sender trips it fast.
    """
    import structlog.testing

    # #256 PR-1: the timeout constant + LifecycleBroadcaster moved to _boot_audit;
    # the broadcaster reads the constant from _boot_audit's globals, so patch it there.
    monkeypatch.setattr(_boot_audit, "_LIFECYCLE_BROADCAST_TIMEOUT_SECONDS", 0.05)

    async def _wedged(_method: str, _params: Mapping[str, object]) -> None:
        await asyncio.sleep(10)  # never returns within the (tiny) timeout

    broadcaster = LifecycleBroadcaster()
    broadcaster.register("wedged", _wedged)

    with structlog.testing.capture_logs() as captured:
        # Must RETURN (not hang) despite the wedged sender.
        await broadcaster.broadcast_going_down("shutdown")

    timeouts = [c for c in captured if c.get("event") == "comms.lifecycle.wire_send_timeout"]
    assert len(timeouts) == 1, captured
    assert timeouts[0].get("log_level") == "warning"
    assert timeouts[0].get("adapter_id") == "wedged"
    assert timeouts[0].get("phase") == "going_down"
    assert timeouts[0].get("timeout_s") == 0.05


async def test_broadcast_going_down_reraises_cancelled_error() -> None:
    """``broadcast_going_down`` propagates ``CancelledError`` (runs in shutdown finally).

    Swallowing cancellation in the ``going_down`` broadcast — which runs in the
    boot drain ``finally`` — would wedge the supervisor drain.
    """
    broadcaster = LifecycleBroadcaster()

    async def _cancelled(_method: str, _params: Mapping[str, object]) -> None:
        raise asyncio.CancelledError

    broadcaster.register("x", _cancelled)
    with pytest.raises(asyncio.CancelledError):
        await broadcaster.broadcast_going_down("shutdown")


def test_going_down_broadcast_happens_before_supervisor_stop(
    monkeypatch: pytest.MonkeyPatch,
    boot_success_env: FakeAuditWriter,
) -> None:
    """H1 ordering invariant (architect M-2): broadcast ``going_down`` BEFORE stop().

    ``supervisor.stop()`` sets the supervisor ``shutdown_event``, which the
    socket-carrier pump observes and closes the transport — so a ``going_down``
    broadcast AFTER ``stop()`` would race a closing transport and lose the frame.
    This drives the REAL boot path's drain ``finally`` and asserts the broadcast
    ran strictly before ``stop()``.
    """
    del boot_success_env  # used for its boot-harness side effects (fakes installed)
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")

    order: list[str] = []

    original_broadcast = LifecycleBroadcaster.broadcast_going_down

    async def _recording_broadcast(self: LifecycleBroadcaster, reason: str) -> None:
        order.append("going_down_broadcast")
        await original_broadcast(self, reason)

    original_stop = FakeSupervisor.stop

    async def _recording_stop(self: FakeSupervisor) -> None:
        order.append("supervisor_stop")
        await original_stop(self)

    monkeypatch.setattr(
        _daemon_commands.LifecycleBroadcaster,
        "broadcast_going_down",
        _recording_broadcast,
    )
    monkeypatch.setattr(FakeSupervisor, "stop", _recording_stop)

    result = CliRunner().invoke(daemon_app, ["start"])
    assert result.exit_code == 0, result.output

    # The going_down broadcast fired, and it fired BEFORE supervisor.stop().
    assert "going_down_broadcast" in order
    assert "supervisor_stop" in order
    assert order.index("going_down_broadcast") < order.index("supervisor_stop")
