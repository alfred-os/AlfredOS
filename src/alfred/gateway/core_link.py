"""``GatewayCoreLink`` — the gateway's core-facing half (Spec A G3-3b / ADR-0032).

The ``alfred-gateway`` DIALS the core's unix socket. On that core leg the gateway
is the PEER, not the host: the core (daemon) runs :class:`CommsPluginRunner` as
HOST and SENDS ``lifecycle.start`` FIRST. The gateway must RECEIVE that frame,
validate its per-boot ``epoch``, capture it (so a later G4 resume can bind its
retained high-water to a specific core boot), and RESPOND with the ack — the
mirror image of the host-side handshake in
:meth:`alfred.plugins.comms_runner.CommsPluginRunner._handshake`.

**This module ships the full core-link manager.** The peer-handshake + epoch
capture, the reconnect/backoff loop, the :meth:`run` supervised pump, and the
:class:`LinkStateMachine` wiring all land here (Spec A G3-3b-1); only the opaque
client<->core payload relay is deferred to G3-3b-2.

**T1 carrier, payload-blind (security).** The gateway relays opaque payloads
byte-for-byte; it NEVER ``json.loads`` or acts on a payload body. This handshake
touches only the control frames (``lifecycle.start`` + its ack) and makes NO
wire-trust decision beyond validating the frame SHAPE and the epoch FORMAT (the
32-hex rule, reused from :class:`ReadyNotification` so it lives in one place).

**Fail-loud (CLAUDE.md hard rule #7).** A clean EOF before the handshake, or a
malformed/absent epoch, raises :class:`GatewayCoreLinkError` — never a silent
no-op. A pre-handshake non-``lifecycle.start`` frame is warn-and-dropped, mirroring
the host runner's behaviour for a peer that front-runs the handshake.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from typing import Final, Protocol, runtime_checkable

import structlog
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    DAEMON_COMMS_ACK,
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    GoingDownNotification,
    ReadyNotification,
)
from alfred.errors import AlfredError
from alfred.gateway._control_frames import control_notification
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.link_state import (
    GatewayLinkEvent,
    GatewayLinkState,
    LinkControl,
    LinkStateMachine,
)
from alfred.gateway.metrics import (
    BUFFER_CAP_RATIO,
    BUFFER_DEPTH_BYTES,
    BUFFER_DEPTH_FRAMES,
    CIRCUIT_BREAKER_OPEN,
    CORE_LINK_UP,
    CORE_UNAVAILABLE_SECONDS,
    RECONNECT_ATTEMPTS,
)
from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError, ReplayFrame
from alfred.plugins.comms_seq_codec import SEQ_VERSION, SeqFrame
from alfred.plugins.comms_wire import CommsProtocolError

log = structlog.get_logger(__name__)

# The gateway's self-reported version, echoed in the peer ack's ``plugin_version``
# (spec §8.1). The core only checks ``ok`` + ``seq_ack``, but the ack honours the
# full :class:`LifecycleStartResult` shape so a stricter core never rejects it.
GATEWAY_PLUGIN_VERSION: Final[str] = "alfred-gateway/0"

# The core socket the gateway dials. The core's TUI-facing socket is keyed
# ``tui`` today; G3-4 relocates the gateway onto its own externally-owned path.
_DEFAULT_DIAL_ADAPTER_ID: Final[str] = "tui"

# Reconnect-loop backoff schedule (Task 5 on this branch consumes these). Defined
# now so the later reconnect/redial loop adds behaviour without re-touching the
# module head — INITIAL doubles by _BACKOFF_FACTOR up to MAX between dial attempts.
INITIAL_BACKOFF_SECONDS: Final[float] = 0.25
MAX_BACKOFF_SECONDS: Final[float] = 5.0
_BACKOFF_FACTOR: Final[float] = 2.0

# A non-zero floor on EVERY reconnect delay (anti-stampede; honours spec §4's "never
# a 0-delay first retry" in CODE, not just docs). Full jitter draws in ``[0, backoff]``,
# so an UNCLAMPED draw — or a pathological injected jitter returning 0 / negative — could
# collapse a wait to 0 and tight-spin / thundering-herd. 50ms is negligible to an operator
# yet guarantees a real gap between redials. The clamp also bounds the ABOVE side (a jitter
# returning > backoff is pinned back to backoff), so every delay lands in
# ``[_MIN_RECONNECT_DELAY_SECONDS, backoff]``.
_MIN_RECONNECT_DELAY_SECONDS: Final[float] = 0.05

# Spec A G4b-2a (#237): the cadence of the supervised TTL-eviction sweep. The
# ReplayBuffer's TTL (default 300s) is the real retention bound; this is just how
# often the gateway checks for frames that have crossed it. 30s keeps the post-TTL
# residency window small relative to the TTL without busy-sweeping the buffer.
_BUFFER_EVICT_INTERVAL_SECONDS: Final[float] = 30.0

# The JSON-RPC method the core sends first on the core leg. Anything else before
# the handshake is warn-and-dropped (mirrors the host runner's pre-handshake arm).
_LIFECYCLE_START_METHOD: Final[str] = "lifecycle.start"

# A core-leg read that ends one of these ways is a GAP, not a fatal error: the
# socket tore, the peer dropped, or a wire violation landed. The pump treats them
# uniformly with a clean EOF — open/keep the gap, then reconnect. Mirrors the host
# runner's ``_TRANSPORT_READ_EXCEPTIONS`` (kept local so this trust-boundary module
# owns the exact family it gaps on). ``CommsProtocolError`` subsumes ``CommsPeerAuthError``.
_TRANSPORT_CRASH_EXCEPTIONS: Final[tuple[type[BaseException], ...]] = (
    BrokenPipeError,
    ConnectionResetError,
    asyncio.IncompleteReadError,
    EOFError,
    CommsProtocolError,
)


class _Shutdown(Exception):  # noqa: N818 — internal control signal, not an error
    """Internal control-flow signal: the shutdown event fired during a pump read.

    Raised by :meth:`GatewayCoreLink._read_frame_or_shutdown` when the shutdown
    waiter wins the read race, so :meth:`GatewayCoreLink.run` returns through its
    ``finally`` (closing the transport) WITHOUT feeding ``CORE_CRASH_EOF`` — a
    shutdown is a clean stop, never a gap, so it must NOT emit ``reconnecting``.
    Mirrors :class:`alfred.plugins.comms_runner._ShutdownSignalled`.
    """


class GatewayCoreLinkError(AlfredError):
    """The core-leg peer handshake failed (fail-loud, CLAUDE.md hard rule #7).

    Raised on a clean EOF before ``lifecycle.start`` arrives, or on a
    ``lifecycle.start`` whose ``epoch`` is absent or malformed (not 32 lowercase
    hex). Mirrors the host runner's :class:`PluginError` handshake-failure arm —
    an unusable core handshake is never a silent no-op.
    """


# The errors a FAILED INITIAL dial/handshake can raise. A first-attempt failure is
# not fatal — it is just the first not-UP edge: open the gap, then reconnect (which
# retries with backoff). Wider than the pump's crash family because the *initial*
# connect can also hit a missing/refused socket (the daemon not up yet) or a
# malformed handshake (``GatewayCoreLinkError`` — defined just above). It MUST also
# cover the read-crash family the steady-state pump tolerates: a ``read_frame`` on
# the FIRST handshake can raise ``EOFError`` / ``asyncio.IncompleteReadError`` (its
# subclass) if the core tears the leg mid-handshake — that is a gap-and-reconnect,
# never an uncaught escape that leaks the half-open transport + crashes ``run``.
_INITIAL_DIAL_EXCEPTIONS: Final[tuple[type[BaseException], ...]] = (
    FileNotFoundError,
    ConnectionRefusedError,
    OSError,
    EOFError,
    asyncio.IncompleteReadError,
    CommsProtocolError,
    GatewayCoreLinkError,
)


@runtime_checkable
class _CommsTransportLike(Protocol):
    """Structural seam for the transport the core-link drives.

    Mirrors :class:`alfred.plugins.comms_runner._CommsTransportLike` (the shared
    runner seam) so a test can drive the handshake with an in-memory frame queue
    and the link never reaches for transport internals beyond these four
    awaitables + the sync seq/ack flip. Re-declared locally rather than imported
    so this trust-boundary module owns the exact shape it binds to.
    """

    async def spawn(self) -> None: ...

    async def send(self, frame: Mapping[str, object]) -> None: ...

    async def read_frame(self) -> Mapping[str, object] | None: ...

    async def read_payload_unit(self) -> SeqFrame | None: ...

    async def send_payload_unit(self, payload: bytes, *, seq: int, ack: int) -> None: ...

    async def close(self) -> None: ...

    def enable_seq_ack(self) -> None: ...


class GatewayCoreLink:
    """The gateway's core-facing link: peer-side handshake + epoch capture.

    Construct one per gateway process. This cut owns :meth:`_peer_handshake`; later
    tasks on this branch extend ``__init__`` (the client listener, the link-state
    machine, the dial callable, the sleep/jitter seams, the shutdown event) and add
    the reconnect loop + the client<->core relay.
    """

    def __init__(
        self,
        *,
        client_listener: GatewayClientListener,
        machine: LinkStateMachine | None = None,
        dial_adapter_id: str = _DEFAULT_DIAL_ADAPTER_ID,
        dial: Callable[[], Awaitable[_CommsTransportLike]] | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[float], float] | None = None,
        shutdown_event: asyncio.Event | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        payload_relay: Callable[[bytes], Awaitable[None]] | None = None,
        replay_buffer: ReplayBuffer | None = None,
    ) -> None:
        self._dial_adapter_id = dial_adapter_id
        self._client_listener = client_listener
        # The reconnect-loop seams (all injectable so a test drives a deterministic
        # fake clock). The dial default lazily imports ``dial_comms_socket`` INSIDE
        # the thunk so importing this module does not pull the socket transport (and
        # so there is no import cycle if the transport ever reaches back here).
        self._dial: Callable[[], Awaitable[_CommsTransportLike]] = (
            dial if dial is not None else self._default_dial
        )
        self._sleep = sleep
        # Full jitter (AWS "Exponential Backoff And Jitter"): each raw draw is uniform in
        # ``[0, backoff]``, NOT the bare backoff — independent processes that gap together
        # must not redial in lockstep. ``_reconnect`` then CLAMPS that draw to
        # ``[_MIN_RECONNECT_DELAY_SECONDS, backoff]`` so the realised delay is never 0 /
        # negative (spec §4: never a 0-delay first retry). The default RNG is unseeded
        # (jitter is not security-sensitive); a test injects ``lambda hi: hi`` to read
        # the bare (clamped) schedule, or a seeded ``random.Random`` for a fixed draw.
        # S311: backoff jitter spreads coincident redials; it is NOT a security
        # primitive (no token, nonce, or key derives from it), so the non-crypto PRNG
        # is correct and a CSPRNG would be needless overhead.
        rng = random.Random()  # noqa: S311
        self._jitter: Callable[[float], float] = (
            jitter if jitter is not None else (lambda hi: rng.uniform(0.0, hi))
        )
        # The merged link-state machine — the kernel that decides which control frame
        # (if any) a lifecycle transition emits. Starts UP; one per gateway process.
        self._machine = machine if machine is not None else LinkStateMachine()
        # The most recently captured core boot epoch (32-hex). ``None`` until the
        # first successful peer handshake; a later G4 resume binds its retained
        # high-water to this so a core BOUNCE (new epoch) is distinguishable from a
        # transient reconnect to the SAME boot.
        self._core_epoch: str | None = None
        # Count of frames dropped by the per-frame router because they are neither
        # lifecycle control frames the gateway CONSUMES nor (yet) the payload frames
        # it RELAYS (the relay is G3-3b-2). T1 carrier: counted, never acted on.
        # NB advances ONLY on the relay-OFF (3b-1 standalone) path; with the relay ON,
        # ``_route_unit`` forwards the payload via ``_payload_relay`` instead of counting.
        self._dropped_payload_frames: int = 0
        # The supervised-lifecycle seams (Task 6). The shutdown event ends ``run`` as
        # a CLEAN stop (no spurious ``reconnecting``); when ``None`` the pump read is a
        # bare ``read_frame`` await. ``monotonic`` is injected so the not-UP duration
        # ``CORE_UNAVAILABLE_SECONDS`` accrues is deterministic under test.
        self._shutdown_event = shutdown_event
        self._monotonic = monotonic
        # The monotonic timestamp the link last left UP (the gap-open edge). ``None``
        # while UP — set on an UP->not-UP edge, read + cleared on the not-UP->UP edge
        # to accrue the elapsed not-UP seconds onto ``CORE_UNAVAILABLE_SECONDS``.
        self._gap_started_at: float | None = None
        # The opaque client<->core payload relay sink (Spec A G3-3b-2 / ADR-0032). When
        # ``None`` the pump reads PARSED frames and drops payloads (the merged 3b-1
        # behaviour). When SET the pump reads RAW units and ROUTES them: a lifecycle
        # frame is CONSUMED, everything else is forwarded byte-for-byte to this sink (T1
        # carrier — the body is NEVER ``json.loads``'d beyond a method-peek).
        self._payload_relay = payload_relay
        # The core-leg RECEIVE tracker: the relay reads ``cumulative_ack()`` from it to
        # send the core its real contiguous ack. Bounded (unlike the merged G2 window)
        # so an always-up gateway cannot be memory-DoS'd by an every-other-seq stream.
        self._core_tracker = BoundedSeqAckTracker()
        # The CURRENT live core transport, bound at the SAME points ``run`` binds its
        # local ``transport`` (only AFTER a successful handshake). ``relay_to_core``
        # snapshots this into a local so a reconnect swap is atomic w.r.t. the send;
        # ``None`` outside an UP leg (the reconnect-race write window — architect M3).
        self._current_core_transport: _CommsTransportLike | None = None
        # Spec A G4b-2-pre (#237): the gateway OWNS the client->core send-seq (so a
        # G4b-2a buffered frame's wire seq equals its ReplayBuffer key even across a
        # loud-dropped send). Per-connection: reset to 0 each ``_peer_handshake``, like
        # the receive tracker — a fresh core leg is a fresh seq space (design §3.2).
        self._client_to_core_seq = 0
        # Spec A G4b-2a (#237): the optional un-acked-inbound retention buffer. The
        # client->core seqs the gateway mints get appended here so a core BOUNCE can
        # replay the un-acked remainder (spec §5). ``None`` (the default) leaves
        # buffering OFF — the merged G3 relay tests construct unchanged — so this
        # foundation cut wires only the injection; the append/trim lands in a later task.
        self._replay_buffer = replay_buffer
        # Spec A G4b-2b (#237): the reconnect-replay seams. ``_pending_replay`` holds the
        # un-acked frames captured before a reconnect reset, awaiting re-send on the fresh
        # leg. ``_replay_pending`` is a gate the relay's client->core pump awaits: SET = the
        # pump may run; CLEARED (by the reconnect capture) = the pump parks until the flush
        # re-sends the replay (so replayed frames take the lowest seqs, preceding fresh
        # input). It starts SET (no replay pending on a fresh link / first connect).
        self._pending_replay: tuple[ReplayFrame, ...] = ()
        self._replay_pending: asyncio.Event = asyncio.Event()
        self._replay_pending.set()

    @property
    def replay_pending_gate(self) -> asyncio.Event:
        """The gate the relay's client->core pump awaits — SET while no reconnect-replay
        is pending, CLEARED while a captured replay is waiting to be flushed (Spec A
        G4b-2b). On a link with no ReplayBuffer it is permanently SET (never cleared)."""
        return self._replay_pending

    @property
    def replay_buffer_tripped(self) -> bool:
        """``True`` iff the injected ReplayBuffer's back-pressure breaker has latched.

        The relay's client->core pump polls this to halt the client read (Spec A
        G4b-2a back-pressure / R4); ``False`` when no buffer is injected (buffering off).
        """
        return self._replay_buffer.breaker_tripped if self._replay_buffer is not None else False

    async def wait_for_shutdown(self) -> None:
        """Block until this link's shutdown event fires (or forever, until cancelled).

        The client read-halt parks here while the buffer breaker is latched (Spec A
        G4b-2a / R4): when a shutdown event is wired it returns on shutdown; when it is
        not (a unit-test link), it blocks until the relay TaskGroup cancels the parked
        pump. Either way the park is cancellation-safe.
        """
        if self._shutdown_event is not None:
            await self._shutdown_event.wait()
        else:
            await asyncio.Event().wait()  # no event wired: block until cancelled

    def _refresh_buffer_metrics(self) -> None:
        """Push the current ReplayBuffer depth/cap/breaker state onto the gauges.

        Called after every buffer mutation (append, trim, reset, evict) so the gauges
        track the live buffer. A no-op when no buffer is injected (buffering off).
        """
        if self._replay_buffer is None:
            return
        BUFFER_DEPTH_FRAMES.set(self._replay_buffer.depth_frames)
        BUFFER_DEPTH_BYTES.set(self._replay_buffer.depth_bytes)
        BUFFER_CAP_RATIO.set(self._replay_buffer.cap_ratio)
        CIRCUIT_BREAKER_OPEN.set(1 if self._replay_buffer.breaker_tripped else 0)

    async def _buffer_evict_loop(self) -> None:
        """Periodically evict TTL-expired un-acked frames; audit each as input-loss.

        A supervised background task spawned by :meth:`run` (reaped in its ``finally``).
        Runs only when a buffer is injected. Each sweep evicts frames older than the
        buffer's TTL — deliberate security-over-liveness loss (pre-DLP input cannot be
        pinned across an unbounded crash-loop, spec §6), so every dropped seq gets a LOUD
        audit row (CLAUDE.md hard rule #7). The monotonic clock keeps ``evict_expired``'s
        non-regression precondition; the injected ``_sleep`` makes the interval testable.
        """
        assert self._replay_buffer is not None  # spawned only when a buffer is present
        while True:
            await self._sleep(_BUFFER_EVICT_INTERVAL_SECONDS)
            try:
                evicted = self._replay_buffer.evict_expired(now=self._monotonic())
            except ReplayBufferError:
                # The TTL bound is a security property (spec §6) — a sweep that raises
                # (e.g. a regressed monotonic read) must be LOUD (hard rule #7), never a
                # silent end to enforcement. Log + retry next tick (a fresh monotonic read
                # re-establishes the floor); do NOT let the loop die unobserved.
                log.error("gateway.comms.buffer_evict_failed", exc_info=True)
                continue
            for seq in evicted:
                log.warning("gateway.comms.buffer_evicted", seq=seq, reason="ttl_expired")
            self._refresh_buffer_metrics()

    @staticmethod
    def _on_evict_task_done(task: asyncio.Task[None]) -> None:
        """Surface an unexpected evict-loop death loud (it should only end via cancel)."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error("gateway.comms.buffer_evict_loop_died", error=repr(exc))

    async def _default_dial(self) -> _CommsTransportLike:
        """Production dial: connect the core's comms socket on the keyed adapter id.

        The import is local (not module-top) so importing this trust-boundary module
        stays cheap and cannot close an import cycle with the socket transport, which
        in turn imports this package's siblings.
        """
        from alfred.plugins.comms_socket_transport import dial_comms_socket

        return await dial_comms_socket(self._dial_adapter_id)

    async def run(self) -> None:
        """Supervised core-link lifecycle: dial, handshake, pump, reconnect on a gap.

        The top-level entry point. Dials + handshakes the core leg, then PUMPS the
        core frames — consuming lifecycle control frames (driving the §9 invariant)
        and dropping payload frames — reconnecting with backoff on a gap (a planned
        ``going_down`` then EOF, or a crash EOF). Returns promptly + cleanly when the
        shutdown event fires, WITHOUT a spurious ``reconnecting`` (a shutdown is a
        clean stop, not a gap).

        **No FD leak (CLAUDE.md hard rule #7).** The live transport is ``close()``d on
        EVERY exit path — shutdown, a clean run completion, or a propagating cancel —
        via the pump's ``try/finally``. **Fail-loud:** a gap is announced (not
        swallowed); only the shutdown signal is a quiet return.

        **Shutdown while (re)connecting.** A :class:`_Shutdown` raised from
        :meth:`_reconnect` — whether via :meth:`_initial_connect`'s failure path or the
        pump-gap :meth:`_reconnect_closing` — is caught at this top level and routed to
        the SAME clean return as the pump's read-race shutdown: no spurious
        ``reconnecting``/``restored``, the live transport still closed in the ``finally``.
        """
        transport: _CommsTransportLike | None = None
        evict_task: asyncio.Task[None] | None = None
        try:
            transport = await self._initial_connect()
            self._current_core_transport = transport
            if self._replay_buffer is not None:
                # Spec A G4b-2a (#237): the supervised TTL-eviction sweep runs only when a
                # buffer is injected. Spawned AFTER the initial connect (so a shutdown
                # DURING the initial connect never leaves an orphaned timer) and reaped in
                # the ``finally`` on every exit path.
                evict_task = asyncio.create_task(self._buffer_evict_loop())
                # Surface an UNEXPECTED loop death loud: the loop should only ever end via
                # the reap cancel below. A non-cancelled exception escaping it (despite the
                # in-loop ReplayBufferError guard) would silently stop TTL enforcement —
                # the done-callback makes that loud (hard rule #7).
                evict_task.add_done_callback(self._on_evict_task_done)
            while True:
                if self._shutdown_event is not None and self._shutdown_event.is_set():
                    return
                try:
                    handled = await self._pump_once(transport)
                except _TRANSPORT_CRASH_EXCEPTIONS as exc:
                    # A torn wire / dropped peer / wire violation: a GAP, not fatal.
                    # Loud (CLAUDE.md hard rule #7), open/keep the gap, then reconnect.
                    log.warning("gateway.core_link.pump_crash", error=repr(exc))
                    await self._feed(GatewayLinkEvent.CORE_CRASH_EOF)
                    transport = await self._reconnect_closing(transport)
                    self._current_core_transport = transport
                    continue
                if not handled:
                    # A clean EOF: the gap is already announced if a ``going_down``
                    # preceded it (idempotent CRASH_EOF), else this opens it.
                    await self._feed(GatewayLinkEvent.CORE_CRASH_EOF)
                    transport = await self._reconnect_closing(transport)
                    self._current_core_transport = transport
                    continue
        except _Shutdown:
            # A shutdown signalled during a pump read OR while (re)connecting — a CLEAN
            # stop, never a gap: return without a spurious banner. The ``finally`` closes
            # the live transport (``None`` if the initial connect never completed).
            return
        finally:
            # Reap the supervised evict timer FIRST (cancel + await-suppress the
            # CancelledError — the daemon reap pattern) so no background sweep outlives
            # ``run`` (CLAUDE.md hard rule #7 — no leaked task). ``None`` when no buffer
            # was injected or the initial connect never completed.
            if evict_task is not None:
                evict_task.cancel()
                with suppress(asyncio.CancelledError):
                    await evict_task
            # Drop the relay's transport reference BEFORE closing so a concurrent
            # ``relay_to_core`` snapshots ``None`` (a loud drop) rather than a
            # mid-close transport (CLAUDE.md hard rule #7 — no silent send-into-a-corpse).
            self._current_core_transport = None
            if transport is not None:
                await transport.close()

    async def _pump_once(self, transport: _CommsTransportLike) -> bool:
        """Read + process ONE core-leg event; ``False`` on a clean EOF (the gap arm).

        Dispatches on the relay wiring (the ONLY divergence — the crash / gap /
        reconnect arms in :meth:`run` are shared):

        * **No relay (``_payload_relay is None``)** — the merged 3b-1 behaviour: read a
          PARSED frame via :meth:`_read_frame_or_shutdown` and route it through
          :meth:`_consume_frame` (consume lifecycle, drop payload). A torn read raises a
          crash exception (handled by ``run``); a clean EOF returns ``False``.
        * **Relay set** — read a RAW :class:`SeqFrame` via
          :meth:`_read_payload_unit_or_shutdown`, feed its ``seq`` (if any) to the
          receive tracker, then route it via :meth:`_route_unit` (consume lifecycle,
          relay everything else byte-for-byte). The shutdown / crash / EOF arms are
          identical to the parsed path.

        Returns ``True`` when an event was processed (continue pumping), ``False`` on a
        clean EOF (``run`` opens the gap + reconnects). A :class:`_Shutdown` from either
        read-race propagates to ``run``'s clean return.
        """
        if self._payload_relay is None:
            frame = await self._read_frame_or_shutdown(transport)
            if frame is None:
                return False
            await self._consume_frame(frame)
            return True
        unit = await self._read_payload_unit_or_shutdown(transport)
        if unit is None:
            return False
        if unit.seq is not None:
            self._core_tracker.observe(unit.seq)
        await self._route_unit(unit)
        return True

    async def _initial_connect(self) -> _CommsTransportLike:
        """Dial + handshake the core leg ONCE; on failure open the gap + reconnect.

        A clean initial connect feeds ``CORE_READY`` from UP (idempotent — emits no
        banner, so there is no spurious ``restored`` at startup). A failed initial
        dial/handshake closes any half-open transport, opens the gap via
        ``CORE_CRASH_EOF`` (the first not-UP edge), and reconnects with backoff — so a
        daemon that is not up yet does not crash ``run`` (CLAUDE.md hard rule #7).
        """
        transport: _CommsTransportLike | None = None
        try:
            transport = await self._dial()
            await self._peer_handshake(transport)
        except _INITIAL_DIAL_EXCEPTIONS as exc:
            log.warning("gateway.core_link.initial_connect_failed", error=repr(exc))
            if transport is not None:
                # A dial that connected but whose handshake raised leaves a half-open
                # transport — close it before reconnecting (no FD leak).
                await transport.close()
            await self._feed(GatewayLinkEvent.CORE_CRASH_EOF)
            return await self._reconnect()
        await self._feed(GatewayLinkEvent.CORE_READY)
        return transport

    async def _reconnect_closing(self, stale: _CommsTransportLike) -> _CommsTransportLike:
        """Close the gapped transport, then reconnect — never leak the stale FD.

        The pump's ``finally`` only closes the CURRENT live transport; when a gap
        rebinds ``transport`` to a fresh leg the OLD one must be closed here or it
        leaks for the life of the process.

        **Clear-before-close (architect M3).** ``_current_core_transport`` is dropped
        to ``None`` BEFORE ``stale.close()`` — mirroring :meth:`run`'s ``finally`` — so a
        concurrent :meth:`relay_to_core` snapshots ``None`` (the clean None-drop) rather
        than the closing transport. The widened send-fault family would loud-drop the
        resulting closed-FD ``RuntimeError`` anyway, but clearing first is cleaner: the
        race resolves via the None-check, not via an exception on a half-closed leg.
        """
        self._current_core_transport = None
        await stale.close()
        return await self._reconnect()

    async def _read_frame_or_shutdown(
        self, transport: _CommsTransportLike
    ) -> Mapping[str, object] | None:
        """Read the next PARSED core frame, aborting the read if shutdown is signalled.

        The merged 3b-1 (relay-OFF) pump read. A thin wrapper over the shared
        :meth:`_read_or_shutdown` race template (only the read coroutine differs from
        the raw-unit variant). Mirrors :meth:`CommsPluginRunner._read_frame_or_shutdown`.
        """
        return await self._read_or_shutdown(transport.read_frame())

    async def _read_payload_unit_or_shutdown(
        self, transport: _CommsTransportLike
    ) -> SeqFrame | None:
        """Read the next RAW :class:`SeqFrame` unit, aborting on shutdown.

        The relay-ON pump read: same shutdown-race / crash / EOF discipline as
        :meth:`_read_frame_or_shutdown`, only the inner read is ``read_payload_unit``
        (the opaque-unit seam) so the body is forwarded byte-for-byte.
        """
        return await self._read_or_shutdown(transport.read_payload_unit())

    async def _read_or_shutdown[R](self, read: Awaitable[R]) -> R:
        """Await ``read``, aborting it (via :class:`_Shutdown`) if shutdown is signalled.

        The shared race template for both pump reads (the parsed-frame read and the
        raw-unit read). With no shutdown event wired this is a bare ``await read``. With
        one wired, the read races ``shutdown_event.wait()`` (FIRST_COMPLETED): a read win
        flows its result / EOF / raise on exactly as a bare await would; a shutdown win
        CANCELS the in-flight read (so a blocking read does not leak), awaits its
        cancellation, and raises :class:`_Shutdown` so the pump returns WITHOUT feeding a
        gap. The ``read`` MUST be a fresh coroutine each call (it is wrapped in a task).
        """
        if self._shutdown_event is None:
            return await read

        read_task: asyncio.Task[R] = asyncio.ensure_future(read)
        shutdown_task: asyncio.Task[bool] = asyncio.ensure_future(self._shutdown_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {read_task, shutdown_task}, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            # A force-cancel tearing down ``run``: cancel both children so neither
            # leaks, then let the CancelledError propagate — the pump's ``finally``
            # still closes the transport (cancellation-safety, CLAUDE.md rule #7).
            read_task.cancel()
            shutdown_task.cancel()
            raise
        if read_task in done:
            # The read won — cancel the (still-pending) shutdown waiter and surface
            # the read's result/exception exactly as a bare await would.
            shutdown_task.cancel()
            return read_task.result()
        # Shutdown won: cancel the in-flight blocking read so it does not leak, await
        # its cancellation, then signal the pump to exit cleanly (no gap fed).
        read_task.cancel()
        with suppress(asyncio.CancelledError, *_TRANSPORT_CRASH_EXCEPTIONS):
            await read_task
        raise _Shutdown

    async def _sleep_or_shutdown(self, delay: float) -> None:
        """Sleep ``delay`` seconds, returning EARLY (via :class:`_Shutdown`) on shutdown.

        With no shutdown event wired this is a bare ``self._sleep(delay)`` await — so the
        deterministic reconnect-schedule tests (which record the slept delays) see the
        delay unchanged. With one wired, the sleep races ``shutdown_event.wait()``
        (FIRST_COMPLETED): a sleep win returns normally; a shutdown win CANCELS the
        in-flight sleep (so it does not leak), awaits its cancellation, and raises
        :class:`_Shutdown` so :meth:`_reconnect` ends promptly INSTEAD of waiting out the
        full backoff. Mirrors :meth:`_read_frame_or_shutdown`'s race template.
        """
        if self._shutdown_event is None:
            await self._sleep(delay)
            return

        sleep_task: asyncio.Task[None] = asyncio.ensure_future(self._sleep(delay))
        shutdown_task: asyncio.Task[bool] = asyncio.ensure_future(self._shutdown_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {sleep_task, shutdown_task}, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            # A force-cancel tearing down ``run``: cancel both children so neither leaks,
            # then let the CancelledError propagate (cancellation-safety, CLAUDE.md rule #7).
            sleep_task.cancel()
            shutdown_task.cancel()
            raise
        if sleep_task in done:
            # The sleep elapsed first — cancel the (still-pending) shutdown waiter and
            # surface any sleep exception exactly as a bare await would.
            shutdown_task.cancel()
            sleep_task.result()
            return
        # Shutdown won: cancel the in-flight sleep so it does not leak, await its
        # cancellation, then signal ``_reconnect`` to exit promptly.
        sleep_task.cancel()
        with suppress(asyncio.CancelledError):
            await sleep_task
        raise _Shutdown

    async def _reconnect(self) -> _CommsTransportLike:
        """Dial + handshake the core leg, retrying with exponential backoff + jitter.

        Loops until a dial AND its peer handshake both succeed, returning the live
        transport. Each attempt first checks the shutdown event (so a shutdown signalled
        BETWEEN attempts ends the loop promptly via :class:`_Shutdown`), then feeds
        ``REDIAL_STARTED`` to the link-state machine, increments
        :data:`RECONNECT_ATTEMPTS`, then sleeps the backoff delay (racing the shutdown
        event, via :meth:`_sleep_or_shutdown`) BEFORE dialing (spec §4).

        **Full jitter with a non-zero floor (spec §4: never a 0-delay first retry).**
        The backoff CEILING starts at ``INITIAL_BACKOFF_SECONDS`` and doubles by
        ``_BACKOFF_FACTOR`` up to ``MAX_BACKOFF_SECONDS`` on every failed attempt. The
        realised delay each attempt is the full-jitter draw ``self._jitter(backoff)``
        CLAMPED to ``[_MIN_RECONNECT_DELAY_SECONDS, backoff]`` — so the FIRST (and every)
        retry delay is in ``[_MIN_RECONNECT_DELAY_SECONDS, INITIAL_BACKOFF_SECONDS]`` on
        attempt 1, NEVER 0. The clamp also defends a pathological injected jitter: a draw
        of 0 / negative is floored to ``_MIN_RECONNECT_DELAY_SECONDS`` and a draw > backoff
        is pinned back to ``backoff``.

        A transient transport fault (``FileNotFoundError`` / ``ConnectionRefusedError``
        / ``OSError`` — a daemon-absent or stale-socket dial) and a wire/peer-auth
        failure (``CommsProtocolError``, which subsumes ``CommsPeerAuthError``) are
        caught, logged LOUD (CLAUDE.md hard rule #7), and retried.

        A dial that SUCCEEDS but whose handshake then RAISES leaves a half-open
        transport: it is ``close()``d before the loop retries so a repeatedly-failing
        handshake cannot leak an FD per attempt.

        **Honours shutdown while reconnecting (CLAUDE.md hard rule #7).** During a
        prolonged core outage an operator shutdown must NOT hang behind the dial-forever
        loop: the top-of-iteration check raises :class:`_Shutdown` if shutdown is already
        set, and :meth:`_sleep_or_shutdown` returns promptly (raising :class:`_Shutdown`)
        if shutdown fires DURING the backoff sleep instead of waiting out the backoff.
        :meth:`run` catches that :class:`_Shutdown` and returns cleanly (no spurious
        ``reconnecting``/``restored``).
        """
        backoff = INITIAL_BACKOFF_SECONDS
        while True:
            if self._shutdown_event is not None and self._shutdown_event.is_set():
                raise _Shutdown
            await self._feed(GatewayLinkEvent.REDIAL_STARTED)
            RECONNECT_ATTEMPTS.inc()
            delay = min(max(self._jitter(backoff), _MIN_RECONNECT_DELAY_SECONDS), backoff)
            await self._sleep_or_shutdown(delay)
            try:
                transport = await self._dial()
            except (FileNotFoundError, ConnectionRefusedError, OSError, CommsProtocolError) as exc:
                # OSError is a superclass of ConnectionRefusedError; the explicit names
                # document the expected dial faults. CommsProtocolError subsumes
                # CommsPeerAuthError (a wrong-uid peer answered the dial).
                log.warning("gateway.core_link.reconnect_failed", error=repr(exc))
                backoff = min(backoff * _BACKOFF_FACTOR, MAX_BACKOFF_SECONDS)
                continue
            try:
                await self._peer_handshake(transport)
            except (GatewayCoreLinkError, CommsProtocolError, OSError) as exc:
                # The dial connected but the handshake failed (malformed/absent epoch,
                # a torn wire, or the peer dropping mid-handshake). Close the half-open
                # transport (no FD leak) and retry — a freshly-dialed transport that
                # cannot complete the handshake is a retryable gap, not a fatal crash.
                log.warning("gateway.core_link.reconnect_failed", error=repr(exc))
                await transport.close()
                backoff = min(backoff * _BACKOFF_FACTOR, MAX_BACKOFF_SECONDS)
                continue
            await self._feed(GatewayLinkEvent.CORE_READY)
            return transport

    async def _peer_handshake(self, transport: _CommsTransportLike) -> None:
        """Receive the core's ``lifecycle.start``, validate + capture the epoch, ack.

        The gateway is the PEER: it READS frames until ``lifecycle.start`` arrives
        (warn-and-dropping anything that front-runs it), validates the per-boot
        ``epoch`` against the 32-hex :class:`ReadyNotification` rule, stores it, and
        writes back the ack — enabling out-of-band seq/ack iff the core advertised
        the matching wire version.

        Raises :class:`GatewayCoreLinkError` on a clean EOF before the handshake or
        on an absent/malformed epoch (fail-loud, CLAUDE.md hard rule #7).
        """
        frame = await self._read_until_start(transport)
        params = frame.get("params")
        epoch = params.get("epoch") if isinstance(params, Mapping) else None
        self._core_epoch = self._validate_epoch(epoch)

        result: dict[str, object] = {"ok": True, "plugin_version": GATEWAY_PLUGIN_VERSION}
        # The ack ITSELF must go out PLAIN, even when seq/ack is negotiated: the
        # core (HOST) reads the ack with its own framing still OFF (it flips
        # ``enable_seq_ack`` only AFTER validating our ack — the flip-after-read
        # pattern in ``CommsPluginRunner._handshake``). Seq-framing the ack would
        # make the core ``json.loads("A1 s=0 ...")`` and reject it as malformed,
        # tearing the leg into an endless redial loop. The result CONTENT still
        # advertises ``seq_ack`` so the core knows we support it; we flip our own
        # framing only AFTER the plain ack is on the wire, so subsequent frames
        # are seq-framed — both peers flip-after, symmetrically.
        negotiated = self._core_advertised_seq_ack(params)
        if negotiated:
            result["seq_ack"] = {"version": SEQ_VERSION}

        await transport.send({"jsonrpc": "2.0", "id": frame.get("id"), "result": result})
        if negotiated:
            transport.enable_seq_ack()
        # FRESH receive tracker per (re)connect (resume correctness). Each core
        # transport is a NEW seq space starting at 0 — a new boot, a new epoch. A
        # process-lifetime tracker carries the OLD boot's high-water (say 1000), so
        # the new boot's low seqs (0,1,2) look already-settled and ``cumulative_ack``
        # stays stuck at the stale high-water — the gateway would ack the new boot for
        # frames it never sent (the resume-correctness corruption G4 builds on). This
        # reset runs on EVERY handshake (incl. the initial — a harmless reset of an
        # already-empty tracker), so a reconnect always rebinds the ack to the fresh
        # boot's seq space.
        self._core_tracker = BoundedSeqAckTracker()
        # Spec A G4b-2-pre (#237): reset the OWNED client->core send-seq alongside the
        # receive tracker — a fresh core leg is a fresh per-connection seq space, so the
        # first relay_to_core on the new leg sends wire seq 0 (resume correctness).
        self._client_to_core_seq = 0
        # Spec A G4b-2a (#237 / R1): a fresh core leg is a fresh seq space, so any frames
        # still held under the OLD epoch cannot be replayed in 2a (reconnect-replay is
        # 2b) and must not survive into epoch B — epoch B's seq restarts at 0, which the
        # buffer's strict-increase guard would reject, and a fresh-leg ack would trim
        # frames the new core never committed. So enumerate + LOUDLY audit each dropped
        # seq (hard rule #7 — interim input-loss, not silent), then reset the buffer's
        # floor for the new epoch. 2b replaces this drop with drain-replay-then-reset.
        if self._replay_buffer is not None:
            # Reset the buffer floor on EVERY reconnect (not just when non-empty): a
            # fully-acked reconnect drains the buffer via trim_to_ack WITHOUT resetting
            # _last_seq (stale-frame rejection by design), so a depth>0 guard would skip
            # the reset, leave _last_seq stale-high, and crash the relay pump when epoch
            # B's append(0, …) trips the strict-increase guard (comms-1). Loud per-seq
            # input-loss only when frames were actually dropped (hard rule #7); the floor
            # reset is unconditional. reset_for_new_epoch on an empty buffer is a no-op
            # beyond the floor rebind. retained_seqs() is body-free — no pre-DLP copy.
            for seq in self._replay_buffer.retained_seqs():
                log.warning(
                    "gateway.comms.buffer_reset_input_loss",
                    seq=seq,
                    reason="reconnect_no_replay_2a",
                )
            self._replay_buffer.reset_for_new_epoch()
            # Spec A G4b-2a (#237): the reset emptied the buffer — zero the gauges.
            self._refresh_buffer_metrics()

    async def _read_until_start(self, transport: _CommsTransportLike) -> Mapping[str, object]:
        """Read frames until ``lifecycle.start``; warn-and-drop anything before it.

        A clean EOF (``read_frame`` -> ``None``) before the handshake is a fatal,
        loud failure: the core dropped without starting the link.
        """
        while True:
            frame = await transport.read_frame()
            if frame is None:
                log.error(
                    "gateway.core_link.handshake_eof",
                    dial_adapter_id=self._dial_adapter_id,
                )
                raise GatewayCoreLinkError(
                    "core link closed before lifecycle.start "
                    f"(adapter_id={self._dial_adapter_id!r})"
                )
            if frame.get("method") == _LIFECYCLE_START_METHOD:
                return frame
            # A frame before the handshake is not expected on a conformant core
            # wire; warn (not debug) so a core that front-runs the handshake is
            # visible to an operator. The frame is dropped — we keep reading.
            log.warning(
                "gateway.core_link.pre_handshake_frame_ignored",
                dial_adapter_id=self._dial_adapter_id,
            )

    def _validate_epoch(self, epoch: object) -> str:
        """Validate ``epoch`` against the 32-hex :class:`ReadyNotification` rule.

        Reuses the wire model so the 32-lowercase-hex contract lives in ONE place
        (DRY). An absent (``None``) or malformed epoch is a loud, fatal reject.
        """
        try:
            return ReadyNotification(epoch=epoch).epoch  # type: ignore[arg-type]
        except ValidationError as exc:
            log.error(
                "gateway.core_link.epoch_invalid",
                dial_adapter_id=self._dial_adapter_id,
            )
            raise GatewayCoreLinkError(
                f"core lifecycle.start epoch invalid (adapter_id={self._dial_adapter_id!r})"
            ) from exc

    @staticmethod
    def _core_advertised_seq_ack(params: object) -> bool:
        """True iff the core advertised the matching out-of-band seq/ack version."""
        seq_ack = params.get("seq_ack") if isinstance(params, Mapping) else None
        return isinstance(seq_ack, Mapping) and seq_ack.get("version") == SEQ_VERSION

    async def _route_unit(self, frame: SeqFrame) -> None:
        """Route ONE raw relay unit: CONSUME lifecycle, FORWARD everything else verbatim.

        The relay-ON router (Spec A G3-3b-2 / ADR-0032). The gateway is a T1 carrier:
        it peeks ONLY the ``method`` of the opaque payload (a single ``json.loads`` to
        read the routing key — never to act on the body) to decide whether the unit is
        one of the two ``daemon.lifecycle.*`` control frames it CONSUMES (through the
        merged forgery-defended :meth:`_consume_frame` — a forged ``ready`` is STILL
        epoch-rejected before any feed) or an opaque payload it FORWARDS byte-for-byte
        to :attr:`_payload_relay`.

        **Fail-toward-relay (security SEC-3 / CLAUDE.md hard rule #7).** A payload whose
        method-peek FAILS — non-JSON bytes, a non-object top-level value, a too-deep
        nesting — is NEVER dropped and NEVER consumed-as-lifecycle: it is forwarded to
        the relay sink verbatim. The carrier does not get to silently swallow a body it
        could not classify; the core (the real trust boundary) re-parses it.
        """
        assert self._payload_relay is not None  # routed only on the relay-ON path
        try:
            parsed = json.loads(frame.payload)
            method = parsed.get("method") if isinstance(parsed, Mapping) else None
        except (json.JSONDecodeError, ValueError, RecursionError):
            # Un-parseable / non-object / pathological body: forward it untouched.
            # T1 carrier never drops or interprets — the core re-parses (hard rule #7).
            await self._payload_relay(frame.payload)
            return
        if method == DAEMON_COMMS_ACK:
            # Spec A G4b-2a-pre (#237 — F4): the daemon's durable-intake ACK. CONSUME
            # it in its OWN arm, BEFORE the ``_consume_frame`` lifecycle path: it has
            # NO epoch and is NOT a forgery-defended LinkStateMachine event, so routing
            # it through ``_consume_frame`` would trip epoch validation on every ack.
            # Consume == no-op/log here (``trim_to_ack`` lands in G4b-2a); the point is
            # it must NEITHER fall into the relay ``else`` (leaking a host control frame
            # to the client) NOR feed the link-state machine. Payload-blind: a missing /
            # malformed ``cumulative_ack`` is still consumed, never relayed.
            #
            # Spec A G4b-2a (#237): the daemon emits this ONLY on its G0 durable-intake
            # commit, so the ack is epoch-validated by construction (current UP leg) —
            # the security precondition the ReplayBuffer.trim_to_ack docstring names.
            # Payload-blind robustness: a missing/malformed cumulative_ack is still
            # CONSUMED (never relayed, never crashes), it just does not trim.
            if self._replay_buffer is not None:
                params = parsed.get("params") if isinstance(parsed, Mapping) else None
                ack = params.get("cumulative_ack") if isinstance(params, Mapping) else None
                if isinstance(ack, int) and not isinstance(ack, bool) and ack >= 0:
                    self._replay_buffer.trim_to_ack(ack)
                    # Spec A G4b-2a (#237): the trim shrank the buffer — refresh the
                    # depth/cap gauges to the post-trim state.
                    self._refresh_buffer_metrics()
                else:
                    log.warning("gateway.core_link.daemon_comms_ack_malformed")
            log.debug("gateway.core_link.daemon_comms_ack_consumed")
            return
        if method in (DAEMON_LIFECYCLE_READY, DAEMON_LIFECYCLE_GOING_DOWN):
            # A lifecycle control frame: CONSUME it (the forgery-defended path). The
            # parsed dict is fed to ``_consume_frame``, which Pydantic-validates +
            # epoch-reconciles BEFORE any machine feed — so a forged ``ready`` on the
            # raw path is rejected exactly as on the parsed pump.
            await self._consume_frame(parsed)
            return
        # An opaque payload (incl. a no-``method`` response): forward the ORIGINAL bytes.
        await self._payload_relay(frame.payload)

    async def relay_to_core(self, payload: bytes) -> None:
        """Forward an opaque client payload to the core leg, carrying the real ack.

        The send-half of the relay (Spec A G3-3b-2 / ADR-0032). Snapshots the CURRENT
        core transport into a local FIRST (so a concurrent reconnect swap is atomic
        w.r.t. this send — architect M3), then writes the opaque ``payload`` with the
        receive tracker's :meth:`BoundedSeqAckTracker.cumulative_ack` as the ``ack``,
        FLOORED to ``0``: the tracker's ``-1`` ("no contiguous run acked yet") maps to
        the wire's ``a=0`` placeholder. Without the floor the FIRST client->core unit —
        sent before the core leg has yet delivered a single seq — would carry ``ack=-1``,
        which :func:`encode_seq_frame` rejects (non-negative counters), crashing the
        client->core pump on a seq-enabled core leg. The real loopback wire-contract test
        (``test_relay_wire_contract``) is what surfaces this; the in-process fakes do not
        encode, so they cannot.

        **Loud drop, NO buffering (CLAUDE.md hard rule #7; G4 owns buffering).** Any
        send-path fault — transport-died (:class:`BrokenPipeError` /
        :class:`ConnectionResetError`), encode-failed (:class:`ValueError` from
        :func:`encode_seq_frame` send-seq decimal-width exhaustion, or
        :class:`CommsProtocolError` from an over-bound reframe), or a write to a
        transport ``close()``d mid-reconnect-swap (:class:`RuntimeError` "unable to
        perform operation on closed transport") — is a LOUD drop: never raised, never
        buffered. A ``None`` current transport (the reconnect-race write window) is the
        same loud drop. The client side keeps running; the dropped unit is the core's to
        re-request once the leg is back (a G4 ReplayBuffer concern), not this carrier's
        to hold. Letting any of these escape would crash the relay TaskGroup on an
        OPERATIONAL edge (a dead/swapping leg is expected), or gap the WRONG leg.
        """
        local = self._current_core_transport
        if local is None:
            log.warning(
                "gateway.relay.core_send_dropped",
                reason="no_core_transport",
            )
            return
        ack = max(self._core_tracker.cumulative_ack(), 0)
        # Spec A G4b-2-pre (#237): mint the OWNED client->core seq AFTER the None-check
        # (a no-transport drop must NOT consume a seq) and pass it EXPLICITLY — the
        # counter advances per relay_to_core call regardless of whether the send then
        # loud-drops, so a G4b-2a buffer-append-per-call keys on the exact wire seq.
        seq = self._client_to_core_seq
        self._client_to_core_seq += 1
        if self._replay_buffer is not None:
            # append-before-send (design §3.3): the buffer is the durable no-loss
            # record; the send below is best-effort and may loud-drop. Keyed on the
            # exact wire seq (G4b-2-pre) so a buffered frame's seq == its wire seq even
            # across a loud-dropped send. The buffer's hard-ceiling raise is the
            # fail-closed backstop if G4b's read-halt is buggy.
            self._replay_buffer.append(seq, payload, now=self._monotonic())
        if self._replay_buffer is not None and self._replay_buffer.breaker_tripped:
            # Spec A G4b-2a (#237 / R3): a soft-cap breach latched the breaker. Feed
            # BREAKER_TRIPPED UNCONDITIONALLY — the link-state machine (not a gateway
            # flag) absorbs repeats (link_state.py: UNAVAILABLE is absorbing), emitting
            # LinkControl.UNAVAILABLE exactly ONCE. On that once-only escalation edge,
            # write the single loud audit row (CLAUDE.md hard rule #7 — back-pressure is
            # never silent). Task 6 then halts the client read. The structlog row is the
            # gateway's honest audit (it has no DB; the signed-log reconcile is a tracked
            # 2b/design-§6 follow-up).
            control = await self._feed(GatewayLinkEvent.BREAKER_TRIPPED)
            if control is LinkControl.UNAVAILABLE:
                log.warning(
                    "gateway.comms.breaker_tripped",
                    depth_frames=self._replay_buffer.depth_frames,
                    depth_bytes=self._replay_buffer.depth_bytes,
                )
        if self._replay_buffer is not None:
            # Spec A G4b-2a (#237): push the post-append (+ post-trip) buffer state onto
            # the observability gauges. After the breaker feed so a trip reflects on the
            # CIRCUIT_BREAKER_OPEN gauge in the same refresh.
            self._refresh_buffer_metrics()
        try:
            await local.send_payload_unit(payload, seq=seq, ack=ack)
        except (
            BrokenPipeError,
            ConnectionResetError,
            RuntimeError,
            ValueError,
            CommsProtocolError,
        ) as exc:
            log.warning("gateway.relay.core_send_dropped", error=repr(exc))

    async def _consume_frame(self, frame: Mapping[str, object]) -> None:
        """Route ONE post-handshake core-leg frame: consume lifecycle, drop payload.

        The gateway CONSUMES the two ``daemon.lifecycle.*`` control frames (it does
        NOT relay them) — driving the merged :class:`LinkStateMachine`. Every other
        method (a payload frame the G3-3b-2 relay will forward, or a JSON-RPC
        response) is dropped + counted here; this cut does NOT relay it.

        **Typed-event boundary (security M4).** A raw/forged frame is Pydantic-validated
        and (for ``ready``) epoch-reconciled BEFORE the typed :meth:`LinkStateMachine.feed`.
        A malformed control frame is loud-and-returned (NOT a state transition); a
        ``ready`` whose epoch != the captured handshake epoch is a false-liveness
        forgery — rejected with NO feed, NO control frame (a false ``restored`` is an
        attack surface). T1 carrier: a payload body is NEVER ``json.loads``'d or acted on.
        """
        method = frame.get("method")
        if method == DAEMON_LIFECYCLE_GOING_DOWN:
            await self._consume_going_down(frame)
        elif method == DAEMON_LIFECYCLE_READY:
            await self._consume_ready(frame)
        else:
            # A payload frame the relay (G3-3b-2) will forward, or a JSON-RPC response
            # (``None`` method). Drop + count for now — never fed, never acted on.
            # Reached only on the relay-OFF path; the relay-ON ``_route_unit`` forwards.
            self._dropped_payload_frames += 1
            log.debug(
                "gateway.core_link.payload_frame_dropped",
                dial_adapter_id=self._dial_adapter_id,
                method=method,
            )

    async def _consume_going_down(self, frame: Mapping[str, object]) -> None:
        """Validate + consume a ``daemon.lifecycle.going_down``; feed CORE_GOING_DOWN."""
        try:
            GoingDownNotification.model_validate(frame.get("params") or {})
        except ValidationError:
            # A malformed control frame is NOT a state transition — loud + return, no
            # feed (CLAUDE.md hard rule #7). No exc detail logged (it could echo a
            # malformed wire field); the method name is enough to triage.
            log.warning(
                "gateway.core_link.malformed_lifecycle_frame",
                dial_adapter_id=self._dial_adapter_id,
                method=DAEMON_LIFECYCLE_GOING_DOWN,
            )
            return
        await self._feed(GatewayLinkEvent.CORE_GOING_DOWN)

    async def _consume_ready(self, frame: Mapping[str, object]) -> None:
        """Validate + epoch-reconcile a ``daemon.lifecycle.ready``; feed CORE_READY.

        THE FORGERY DEFENSE: a ``ready`` whose ``epoch`` != the captured handshake
        epoch is a false-liveness injection (a same-uid peer past ``SO_PEERCRED``
        lying). REJECT it — no feed, no control frame — so a forged ``restored`` can
        never reach the client (CLAUDE.md hard rule #7: loud + return).
        """
        try:
            parsed = ReadyNotification.model_validate(frame.get("params") or {})
        except ValidationError:
            log.warning(
                "gateway.core_link.malformed_lifecycle_frame",
                dial_adapter_id=self._dial_adapter_id,
                method=DAEMON_LIFECYCLE_READY,
            )
            return
        if parsed.epoch != self._core_epoch:
            log.warning(
                "gateway.core_link.ready_epoch_mismatch",
                dial_adapter_id=self._dial_adapter_id,
            )
            return
        await self._feed(GatewayLinkEvent.CORE_READY)

    async def _feed(self, event: GatewayLinkEvent) -> LinkControl | None:
        """Feed a TYPED event; emit any control frame; refresh metrics; RETURN it.

        Returns the control the machine emitted for ``event`` (or ``None``).

        The control frame (if any) is mapped via :func:`control_notification` and
        pushed to the client through the listener. ``CORE_LINK_UP`` is set to ``1``
        iff the resulting machine state is UP, else ``0``.

        The UP-ness EDGE is observed here (the one place every transition flows
        through): on UP->not-UP stamp the gap-open clock; on not-UP->UP accrue the
        elapsed seconds onto ``CORE_UNAVAILABLE_SECONDS``. An idempotent transition
        (UP->UP, or a not-UP->not-UP within one gap) crosses no edge and touches
        neither — so a multi-attempt gap accrues its seconds exactly once.
        """
        was_up = self._machine.state is GatewayLinkState.UP
        control = self._machine.feed(event)
        if control is not None:
            await self._client_listener.send_control(control_notification(control))
        now_up = self._machine.state is GatewayLinkState.UP
        if was_up and not now_up:
            self._gap_started_at = self._monotonic()
        elif not was_up and now_up and self._gap_started_at is not None:
            CORE_UNAVAILABLE_SECONDS.inc(self._monotonic() - self._gap_started_at)
            self._gap_started_at = None
        CORE_LINK_UP.set(1 if now_up else 0)
        return control


__all__ = [
    "GATEWAY_PLUGIN_VERSION",
    "GatewayCoreLink",
    "GatewayCoreLinkError",
]
