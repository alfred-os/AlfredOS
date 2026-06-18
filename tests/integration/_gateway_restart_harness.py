"""Shared harness for the G5 gateway restart-survival smoke (Spec A G5 / #237).

The G5 graduation proof (closing #237 criterion #7) drives the REAL chat ->
gateway -> core stack across a core restart, with everything real EXCEPT the
core, which is a CONTROLLABLE fake. This module owns the pieces that proof
shares:

* a **real client-leg socket** — :class:`alfred.gateway.process.GatewayProcess`
  binds the REAL :class:`GatewayClientListener` (``comms-gateway.sock``) and the
  chat side dials in over the REAL :class:`CommsSocketTransport`. There is NO
  in-memory client pair: the held-across-restart single-accept-for-life wire is
  exactly what the proof exercises, so it must be a genuine AF_UNIX socket.

* a **controllable fake core** — :class:`_ScriptedCoreTransport` /
  :class:`_DialRecorder`, LIFTED verbatim from ``tests/unit/gateway/test_core_link.py``
  (NOT reinvented). ``_DialRecorder`` pops a fresh-epoch ``_ScriptedCoreTransport``
  per dial; each scripts ``lifecycle.start``(epoch) -> the post-handshake relay
  pump (ack-echo / lifecycle / EOF). The gateway is the PEER on the core leg, so
  the fake core SENDS ``lifecycle.start`` first and the gateway RECEIVES it.

* the **real cohost wire pump** — the chat side runs the REAL
  :func:`alfred_tui.cohost.run_cohosted` serve loop (it answers the gateway's
  client-leg HOST handshake via the REAL :class:`alfred_tui.server.TuiServer` and
  routes ``link.*`` control frames to a recording ``on_link_state``). The Textual
  ``App`` is replaced by a parking double (no terminal in-process); the banner
  render is asserted against a REAL :class:`AlfredTuiApp` in the R5b test.

DETERMINISM (flakiness is failure). The injected ``sleep`` returns INSTANTLY for
the sub-second reconnect backoff but PARKS forever on the 30 s buffer-evict
interval — an instant sleep there would busy-spin ``_buffer_evict_loop`` and
starve the event loop. ``jitter`` is the identity. The fake-core EOF is driven by
a PER-LEG distinct blocking :class:`asyncio.Event` (never the gateway shutdown
event). Tests settle on an OBSERVABLE via a bounded ``range(...)`` yield loop,
never a fixed timeout.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import shutil
import tempfile
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from alfred_tui.cohost import run_cohosted
from alfred_tui.session import TuiSession

from alfred.comms_mcp.protocol import (
    DAEMON_COMMS_ACK,
    DAEMON_LIFECYCLE_GOING_DOWN,
)
from alfred.gateway.core_link import _BUFFER_EVICT_INTERVAL_SECONDS
from alfred.gateway.process import GatewayProcess
from alfred.gateway.replay_buffer import ReplayBuffer
from alfred.plugins.comms_seq_codec import SEQ_VERSION, SeqFrame

# How many cooperative-yield ticks a bounded settle loop spins before giving up on
# its observable. Generous enough to absorb the multi-hop real-socket round-trip
# (chat -> kernel -> gateway -> fake core) yet bounded so a genuine wedge fails the
# test loudly instead of hanging (vs a fixed wall-clock timeout, which is the flake
# vector this loop replaces).
_SETTLE_TICKS = 200


# ---------------------------------------------------------------------------
# The controllable fake core — LIFTED verbatim from
# tests/unit/gateway/test_core_link.py (Task 6 section). The gateway is the PEER on
# the core leg: the fake core SENDS lifecycle.start first and the gateway RECEIVES
# it via read_frame, then the relay pump reads SeqFrames via read_payload_unit.
# ---------------------------------------------------------------------------


class _ScriptedCoreTransport:
    """A fake ``_CommsTransportLike`` whose reads follow a single queued script.

    Each script entry is one of:
      * a ``Mapping`` — a frame ``read_frame`` returns (the handshake ``start``),
      * a :class:`SeqFrame` — a raw unit ``read_payload_unit`` returns (the relay path),
      * ``None`` — a clean EOF (the read returns ``None``),
      * a :class:`BaseException` INSTANCE — a transport-crash the read raises,
      * an :class:`asyncio.Event` — the read AWAITS the event, then (once set) returns
        ``None`` (a genuinely-pending read used to drive the shutdown / go-down race).

    The SAME ``_script`` feeds both ``read_frame`` (the handshake) and
    ``read_payload_unit`` (the post-handshake relay pump). ``sent`` records writebacks
    (the handshake ack), ``sent_units`` records relay-back payloads, ``closed`` flips on
    ``close()``.
    """

    def __init__(self, script: list[object]) -> None:
        self._script: collections.deque[object] = collections.deque(script)
        self.sent: list[dict[str, object]] = []
        # Spec A G4b-2-pre (#237): records (payload, seq, ack) — caller-owned seq.
        self.sent_units: list[tuple[bytes, int, int]] = []
        self.seq_ack_enabled = False
        self.closed = False

    async def spawn(self) -> None:  # pragma: no cover - unused on the peer leg
        return None

    async def send(self, frame: Mapping[str, object]) -> None:
        self.sent.append(dict(frame))

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None:
        self.sent_units.append((payload, seq, ack))

    async def _next(self) -> object | None:
        """Pop the next script entry, awaiting an ``Event`` / raising a crash."""
        if not self._script:
            return None
        entry = self._script.popleft()
        if isinstance(entry, asyncio.Event):
            await entry.wait()
            return None
        if isinstance(entry, BaseException):
            raise entry
        return entry

    async def read_frame(self) -> Mapping[str, object] | None:
        entry = await self._next()
        if entry is None:
            return None
        assert isinstance(entry, Mapping)
        return entry

    async def read_payload_unit(self) -> SeqFrame | None:
        entry = await self._next()
        if entry is None:
            return None
        assert isinstance(entry, SeqFrame)
        return entry

    async def close(self) -> None:
        self.closed = True

    def enable_seq_ack(self) -> None:
        self.seq_ack_enabled = True


class _DialRecorder:
    """A controllable ``dial`` seam: a queue of outcomes consumed one per call.

    Each entry is either a callable returning a transport (a successful dial) or an
    exception INSTANCE to raise (a failed dial). ``calls`` tracks how many times the
    loop dialed so a test can assert exactly one dial per (re)connect.
    """

    def __init__(self, outcomes: list[object]) -> None:
        self._outcomes: collections.deque[object] = collections.deque(outcomes)
        self.calls = 0

    async def __call__(self) -> _ScriptedCoreTransport:
        self.calls += 1
        outcome = self._outcomes.popleft()
        if isinstance(outcome, BaseException):
            raise outcome
        assert callable(outcome)
        return outcome()  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Core-leg script builders — the fake daemon's per-leg frame sequence.
# ---------------------------------------------------------------------------


def fresh_epoch() -> str:
    """A fresh 32-hex boot epoch — a new core boot starts a new seq space."""
    return uuid4().hex


def start_frame(epoch: str) -> dict[str, object]:
    """A ``lifecycle.start`` handshake frame the fake core SENDS first.

    Negotiates ``AlfredSeqAck/1`` on the core leg (the production daemon does), so the
    gateway flips the core-leg transport's seq/ack framing on after the plain ack.
    """
    return {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "lifecycle.start",
        "params": {"adapter_id": "tui", "epoch": epoch, "seq_ack": {"version": SEQ_VERSION}},
    }


def going_down_unit() -> SeqFrame:
    """A ``daemon.lifecycle.going_down`` SeqFrame — a planned drain opens the gap."""
    body = json.dumps(
        {"method": DAEMON_LIFECYCLE_GOING_DOWN, "params": {"reason": "shutdown"}}
    ).encode()
    return SeqFrame(seq=0, ack=0, payload=body)


def ack_unit(cumulative_ack: int, *, seq: int) -> SeqFrame:
    """A ``daemon.comms.ack`` SeqFrame trimming the gateway's ReplayBuffer to ``cumulative_ack``."""
    body = json.dumps(
        {"method": DAEMON_COMMS_ACK, "params": {"cumulative_ack": cumulative_ack}}
    ).encode()
    return SeqFrame(seq=seq, ack=0, payload=body)


# ---------------------------------------------------------------------------
# The deterministic sleep seam (the crux of non-flakiness).
# ---------------------------------------------------------------------------


def make_parking_sleep() -> Callable[[float], Any]:
    """A ``sleep`` that is INSTANT for small delays but PARKS on the evict interval.

    The buffer-injected core link spawns ``_buffer_evict_loop`` doing
    ``await self._sleep(30.0)`` in a tight ``while True``. An instant sleep there
    busy-spins and STARVES every other task on the loop (Task 0's implementer hit
    this). So: park forever (on a never-set event) when the delay is the evict
    interval, and return immediately for the sub-second reconnect backoff — yielding
    once so a reconnect still makes progress. The reconnect backoff is therefore
    effectively instant (no real wall-clock wait), keeping the test fast AND
    deterministic.
    """
    never = asyncio.Event()

    async def _sleep(delay: float) -> None:
        if delay >= _BUFFER_EVICT_INTERVAL_SECONDS:
            await never.wait()
            return
        await asyncio.sleep(0)

    return _sleep


@contextlib.contextmanager
def short_home() -> Iterator[Path]:
    """A SHORT temp dir to stand in for ``$HOME`` — the AF_UNIX path-length backstop.

    The gateway binds ``<home>/.run/alfred/comms-gateway.sock``; AF_UNIX ``sun_path`` is
    capped at ~104 bytes, and pytest's ``tmp_path`` (a deep ``.../pytest-of-<user>/...``
    tree) blows past it. So mint a short ``mkdtemp`` dir under the system temp root and
    reap it on exit — keeping the bound socket path well under the limit.
    """
    home = Path(tempfile.mkdtemp(prefix="g5-"))
    try:
        yield home
    finally:
        shutil.rmtree(home, ignore_errors=True)


async def settle(predicate: Callable[[], bool]) -> bool:
    """Yield up to :data:`_SETTLE_TICKS` cooperative ticks until ``predicate`` holds.

    Returns whether the predicate became true within the bound — the caller asserts
    on it so a wedge fails LOUD rather than hanging. This is the bounded settle the
    task mandates in place of a fixed timeout.
    """
    for _ in range(_SETTLE_TICKS):
        if predicate():
            return True
        await asyncio.sleep(0)
    return predicate()


# ---------------------------------------------------------------------------
# The parking Textual-app double (no terminal in-process).
# ---------------------------------------------------------------------------


class _ParkingApp:
    """An ``_AppLike`` double whose ``run_async`` parks until ``exit()`` resolves it.

    The cohost co-hosts ``app.run_async()`` + the wire pump under one TaskGroup. The
    real :class:`AlfredTuiApp.run_async` needs a terminal, which an in-process test
    has none of, so this double stands in for the APP task: it parks until the cohost
    calls ``exit()`` (the wire-ended graceful arm) or its task is cancelled (the
    operator-quit arm). The wire pump under test is REAL; only the terminal-bound app
    half is doubled. ``set_link_state`` is unused here — the test injects its own
    recording ``on_link_state`` — but is present to satisfy the ``_AppLike`` shape.
    """

    def __init__(self) -> None:
        self._exit = asyncio.Event()
        self.link_states: list[str] = []

    async def run_async(self) -> None:
        await self._exit.wait()

    def exit(self) -> None:
        self._exit.set()

    def set_link_state(self, method: str) -> None:  # pragma: no cover - unused seam
        self.link_states.append(method)


# ---------------------------------------------------------------------------
# The in-process gateway+chat harness.
# ---------------------------------------------------------------------------


@dataclass
class _GatewayStack:
    """A live gateway+chat stack: the running tasks + the test's drive seams."""

    gateway_task: asyncio.Task[None]
    chat_task: asyncio.Task[int]
    shutdown: asyncio.Event
    link_states: list[str]
    session: TuiSession
    dial: _DialRecorder
    _gateway: GatewayProcess = field(repr=False)

    async def send_operator_input(self, text: str) -> None:
        """Push one operator turn over the REAL socket as an ``inbound.message`` frame.

        Drives the REAL ``TuiSession`` the cohost built with the socket inbound sink:
        ``consume_user_input`` + ``flush_keystroke_batch`` mint a real
        :class:`InboundMessageNotification` and write it to the gateway over the real
        client socket — the genuine chat -> gateway -> core path (no shortcut).
        """
        await self.session.consume_user_input(text)
        await self.session.flush_keystroke_batch()


async def _record_link_state_factory(sink: list[str]) -> Callable[[str], Any]:
    async def _on_link_state(method: str) -> None:
        sink.append(method)

    return _on_link_state


@contextlib.asynccontextmanager
async def gateway_stack(
    *,
    monkeypatch: Any,
    core_outcomes: list[object],
    replay_buffer_factory: Callable[[], ReplayBuffer] = ReplayBuffer,
) -> AsyncIterator[_GatewayStack]:
    """Stand up a REAL gateway + REAL chat-wire over a REAL socket; tear down on exit.

    ``$HOME`` is redirected to a SHORT temp dir (:func:`short_home`, the AF_UNIX
    path-length backstop) so the gateway's ``comms-gateway.sock`` binds under an
    isolated ``~/.run/alfred`` and the chat side dials the same path. The gateway runs
    the REAL :class:`GatewayProcess` with an injected fake-core ``core_dial`` (the
    :class:`_DialRecorder` over ``core_outcomes``) and the deterministic ``sleep`` /
    identity ``jitter`` seams. The chat side runs the REAL :func:`run_cohosted` wire pump
    (answering the gateway's client handshake via the REAL :class:`TuiServer`) with a
    parking app double and a recording ``on_link_state``.

    Yields a :class:`_GatewayStack` once both legs have handshaked and the relay is
    pumping. On exit the shutdown event is set and both tasks are awaited (then
    cancelled as a backstop) so no task / socket / transport leaks — the hard-rule-#7
    symmetric teardown.
    """
    with short_home() as home:
        monkeypatch.setattr(Path, "home", lambda: home)
        async with _running_gateway_stack(
            monkeypatch=monkeypatch,
            core_outcomes=core_outcomes,
            replay_buffer_factory=replay_buffer_factory,
        ) as stack:
            yield stack


@contextlib.asynccontextmanager
async def _running_gateway_stack(
    *,
    monkeypatch: Any,
    core_outcomes: list[object],
    replay_buffer_factory: Callable[[], ReplayBuffer],
) -> AsyncIterator[_GatewayStack]:
    """The gateway+chat spawn/teardown body, run inside the ``short_home`` redirect."""
    shutdown = asyncio.Event()
    dial = _DialRecorder(core_outcomes)
    gateway = GatewayProcess(
        shutdown_event=shutdown,
        dial_adapter_id="tui",
        core_dial=dial,
        replay_buffer_factory=replay_buffer_factory,
        sleep=make_parking_sleep(),
        jitter=lambda hi: hi,
    )
    gateway_task: asyncio.Task[None] = asyncio.ensure_future(gateway.run())

    link_states: list[str] = []
    on_link_state = await _record_link_state_factory(link_states)
    captured_session: dict[str, TuiSession] = {}

    def _build_parking_app(session: TuiSession) -> _ParkingApp:
        captured_session["s"] = session
        return _ParkingApp()

    async def _run_chat() -> int:
        return await run_cohosted(
            adapter_id="gateway",
            build_app_fn=_build_parking_app,
            on_link_state=on_link_state,
        )

    chat_task: asyncio.Task[int] = asyncio.ensure_future(_run_chat())

    # Settle until BOTH legs are up. The chat session is constructed by the cohost ONLY
    # after it dials in AND the gateway answers the client handshake; the gateway dials
    # the core ONLY after that client handshake. So ``captured_session`` (client leg up)
    # AND ``dial.calls >= 1`` (core leg dialed) together prove the relay is wired.
    ok = await settle(lambda: bool(captured_session) and dial.calls >= 1)
    if not ok:
        # Surface whichever leg failed to come up so the failure is diagnostic, not a
        # bare timeout. A chat-task crash (handshake refusal) is re-raised here.
        if chat_task.done() and chat_task.exception() is not None:
            raise AssertionError(f"chat leg failed to come up: {chat_task.exception()!r}")
        if gateway_task.done() and gateway_task.exception() is not None:
            raise AssertionError(f"gateway leg failed to come up: {gateway_task.exception()!r}")
        raise AssertionError("stack did not reach steady state within the settle bound")

    stack = _GatewayStack(
        gateway_task=gateway_task,
        chat_task=chat_task,
        shutdown=shutdown,
        link_states=link_states,
        session=captured_session["s"],
        dial=dial,
        _gateway=gateway,
    )
    try:
        yield stack
    finally:
        shutdown.set()
        # Await both legs, then cancel as a backstop so a wedged half cannot hang the
        # suite. Both should return promptly: the gateway on its shutdown-won relay
        # return, the chat on the cohost's symmetric wire-ended app.exit().
        await _drain_tasks(gateway_task, chat_task)


async def _drain_tasks(*tasks: asyncio.Task[Any]) -> None:
    """Await tasks with a bounded settle, cancelling any stragglers; re-raise real errors."""
    await settle(lambda: all(t.done() for t in tasks))
    for task in tasks:
        if not task.done():
            task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
            raise result
