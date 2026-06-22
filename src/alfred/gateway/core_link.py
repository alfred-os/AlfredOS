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

from alfred.comms_mcp.adapter_credential_protocol import (
    CORE_ADAPTER_SPAWN_GRANT,
    GATEWAY_ADAPTER_SPAWN_REQUEST,
    SpawnGrant,
    SpawnRequest,
)
from alfred.comms_mcp.protocol import (
    DAEMON_COMMS_ACK,
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    GATEWAY_ADAPTER_INBOUND,
    GatewayAdapterInboundEnvelope,
    GoingDownNotification,
    ReadyNotification,
)
from alfred.errors import AlfredError
from alfred.gateway._control_frames import control_notification
from alfred.gateway._seq_tracker import BoundedSeqAckTracker
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.gateway_leg import GatewayLeg
from alfred.gateway.ingress_audit import IngressRefusalReason, record_ingress_refusal
from alfred.gateway.ingress_gate import IngressDecision
from alfred.gateway.leg_router import LegRouter, RouteOutcome
from alfred.gateway.leg_scheduler import LegQueueFullError
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
from alfred.gateway.replay_buffer import ReplayBufferError, ReplayFrame
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


# Spec B G6-4 Task 7 (#288): map the gate's payload-blind admission decision onto the K6
# closed-vocab audit reason. ADMITTED is never mapped (the caller guards it). Declared once
# so the ingress-refusal reason set cannot drift between the gate and the audit sink.
_INGRESS_REFUSAL_REASON: Final[Mapping[IngressDecision, IngressRefusalReason]] = {
    IngressDecision.OVERSIZED: IngressRefusalReason.OVERSIZED,
    IngressDecision.THROTTLED_RATE: IngressRefusalReason.THROTTLED_RATE,
    IngressDecision.THROTTLED_INFLIGHT: IngressRefusalReason.THROTTLED_INFLIGHT,
}


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


class CredentialLegDownError(AlfredError):
    """A ``spawn_request`` was issued while the core leg was DOWN (G6-3, #288).

    The link-DOWN arm of the credential round-trip: there is no live transport to
    send the request on. DISTINCT from :class:`CredentialReplyTimeoutError` (the
    link was UP but the reply never came — correction A-C2). The supervisor's
    AWAITING_CORE state consumes this loud signal (Task 4) rather than spawning a
    credential-less adapter (fail-closed, CLAUDE.md hard rule #7).
    """


class CredentialReplyTimeoutError(AlfredError):
    """A ``spawn_request`` was sent but no ``spawn_grant`` came back in time (G6-3).

    The bounded-await fail-closed arm (correction A-C2): the leg is nominally UP
    but the reply was dropped / unrouted (the leg silently drops unknown inbound
    methods, so a spawn could otherwise hang). A typed LOUD abort, never a hang —
    the gateway refuses the spawn rather than block forever.
    """


class ForwardLegUnavailableError(AlfredError):
    """A forwarded inbound named an adapter whose leg is NOT registered (G6-7-3, ERR-309-1).

    FORK-B. :meth:`GatewayCoreLink.forward_adapter_inbound` routes the wrapped inbound
    through the :class:`LegRouter`, which RETURNS (does not raise)
    :data:`RouteOutcome.REFUSED_UNKNOWN_ADAPTER` when the spawn-binding ``adapter_id`` is
    not a registered leg. That outcome MUST surface as this typed error — never be
    discarded — so the disposition can LOUD-TERMINAL-DROP the frame (CLAUDE.md hard rule #7:
    a lost inbound is loud, never silent, never a false ``forward_accepted``).

    DISTINCT from :class:`LegQueueFullError` / :class:`ReplayBufferError`: those are a FULL
    but REGISTERED leg (back-pressure — retry after the scheduler drains). This error is an
    UNREGISTERED / gone leg — the frame can never be delivered to it, so the disposition
    drops it terminally (retrying a gone leg is futile). Reachable when the scheduler's
    isolation arm (``record_for_send`` raises ``ReplayBufferError`` -> ``deregister_leg``)
    tears the leg down WHILE a forward is parked on back-pressure: on resume the held frame
    re-forwards and the router now refuses the (deregistered) leg.
    """


# Bounded await for a ``spawn_grant`` reply on an UP leg (correction A-C2). Mirrors
# the host runner's ``_SEND_REQUEST_TIMEOUT_SECONDS`` discipline: a reply that does
# not arrive in this window is a loud fail-closed abort, not a hang.
_SPAWN_GRANT_TIMEOUT_SECONDS: Final[float] = 10.0


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
        tui_leg: GatewayLeg | None = None,
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
        # local ``transport`` (only AFTER a successful handshake). ``write_leg_unit``
        # snapshots this into a local so a reconnect swap is atomic w.r.t. the send;
        # ``None`` outside an UP leg (the reconnect-race write window — architect M3).
        self._current_core_transport: _CommsTransportLike | None = None
        # Spec B G6-4a (#288): the TUI dial-in is the FIRST GatewayLeg. When injected it
        # OWNS its ReplayBuffer + the per-leg client->core send-seq (per-connection: reset
        # to 0 each ``_peer_handshake`` via ``reset_for_new_epoch``, so a fresh core leg is
        # a fresh seq space — design §3.2) + the breaker latch + the global-cap accounting.
        # The leg-routed ``submit_tui_unit`` drives ``record_for_send`` (seq mint + buffer
        # append + cap reserve) then the SINGLE physical ``write_leg_unit`` writer — there
        # is exactly one serialization point. ``None`` leaves buffering OFF (the merged G3
        # relay tests construct without a leg).
        self._tui_leg = tui_leg
        # Spec B G6-4 Task 7 (#288): the leg scheduler/router (the SINGLE steady-state
        # drainer). ``submit_tui_unit`` admits + ENQUEUES onto the TUI leg's scheduler queue
        # through this router (the K4 forged-adapter refusal lives in the router); the
        # scheduler's drain pump then mints the seq + appends + escalates + writes. ``None``
        # leaves the leg-routed submit path unwired (the merged G3 relay tests that construct
        # without a leg never call ``submit_tui_unit``). Wired AFTER construction via
        # :meth:`set_leg_router`: the router is built over the scheduler, which is built over
        # THIS link (a construction cycle), so the link cannot take it at ctor time — L2
        # (#288) replaces the prior dead ctor param + private late-write with one coherent
        # setter, mirroring the relay's post-construction ``_payload_relay`` binding.
        self._leg_router: LegRouter | None = None
        # Spec A G4b-2b (#237): the reconnect-replay seams. ``_pending_replay`` holds the
        # un-acked frames captured before a reconnect reset, awaiting re-send on the fresh
        # leg. ``_replay_pending`` is a gate the relay's client->core pump awaits: SET = the
        # pump may run; CLEARED (by the reconnect capture) = the pump parks until the flush
        # re-sends the replay (so replayed frames take the lowest seqs, preceding fresh
        # input). It starts SET (no replay pending on a fresh link / first connect).
        self._pending_replay: tuple[ReplayFrame, ...] = ()
        self._replay_pending: asyncio.Event = asyncio.Event()
        self._replay_pending.set()
        # Spec B G6-3 (#288): the credential request/response correlation registry.
        # ``request_spawn_grant`` registers a Future keyed on the request's
        # ``request_id``; an inbound ``core.adapter.spawn_grant`` (routed through
        # ``_consume_frame`` / ``_route_unit``) resolves the matching waiter. This is
        # the FIRST request/response shape on the otherwise fire-and-forget leg — an
        # unsolicited / mismatched grant (no pending waiter) is a loud drop, never a
        # crash (adversarial e). The credential lives in the Future's result only for
        # the brief window the awaiter consumes it; it is never stashed on ``self``.
        self._pending_grants: dict[str, asyncio.Future[SpawnGrant]] = {}

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
        G4b-2a back-pressure / R4); ``False`` when no leg is injected (buffering off).
        G6-4a (#288): reads the TUI leg's breaker latch (the leg owns the buffer).
        """
        return self._tui_leg.breaker_tripped if self._tui_leg is not None else False

    def set_leg_router(self, leg_router: LegRouter) -> None:
        """Wire the leg scheduler/router AFTER construction (L2, Spec B G6-4 #288).

        The router is built over the scheduler, which is built over THIS link (drains onto
        ``write_leg_unit`` + reads ``replay_pending_gate``) — a construction cycle, so the link
        cannot accept the router at ctor time. The gateway process (the one place that knows the
        leg<->scheduler topology) calls this once after building both, exactly as the relay binds
        ``_payload_relay`` post-construction. ``submit_tui_unit`` requires it to be set.
        """
        self._leg_router = leg_router

    def current_core_epoch(self) -> str | None:
        """The most recently captured core boot epoch (32-hex), or ``None``.

        ``None`` until the first successful peer handshake captures it (Spec B
        §3 / G6-2b-2a). The status leg reads this LAZILY at emit time (not at
        construction) so an ``up`` frame stamps the epoch the live handshake
        captured — a forged/stale epoch is what the core-side observer refuses.
        """
        return self._core_epoch

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
        """Push the TUI leg's depth/cap/breaker state onto the UNLABELLED gauges (JC-1 A).

        Called after every buffer mutation (append, trim, reset, evict) so the gauges track
        the live leg buffer. A no-op when no leg is injected (buffering off). G6-4a (#288):
        reads ``self._tui_leg`` (the leg wraps the same ``ReplayBuffer``); the leg ALSO
        refreshes its OWN per-adapter ``{adapter}``-labelled gauges inside ``record_for_send``
        (harmless — JC-1 keeps the G5 unlabelled series the live dashboards key on). PR13: this
        unlabelled shim is single-TUI-leg ONLY — G6-4 must NOT call it per-non-TUI-leg drain
        (only the leg's own labelled refresh scales; keep it O(1)-per-frame, never O(N)-legs).
        """
        if self._tui_leg is None:
            return
        BUFFER_DEPTH_FRAMES.set(self._tui_leg.depth_frames)
        BUFFER_DEPTH_BYTES.set(self._tui_leg.depth_bytes)
        BUFFER_CAP_RATIO.set(self._tui_leg.cap_ratio)
        CIRCUIT_BREAKER_OPEN.set(1 if self._tui_leg.breaker_tripped else 0)

    async def _buffer_evict_loop(self) -> None:
        """Periodically evict TTL-expired un-acked frames; audit each as input-loss.

        A supervised background task spawned by :meth:`run` (reaped in its ``finally``).
        Runs only when a leg is injected. Each sweep evicts frames older than the buffer's
        TTL — deliberate security-over-liveness loss (pre-DLP input cannot be pinned across
        an unbounded crash-loop, spec §6), so every dropped seq gets a LOUD audit row
        (CLAUDE.md hard rule #7). G6-4a (#288): ``leg.evict_expired`` uses the leg's injected
        ``now`` (wired to the same monotonic seam in ``process.py``) and releases the freed
        bytes back to the global cap (K2); the injected ``_sleep`` makes the interval testable.
        """
        assert self._tui_leg is not None  # spawned only when a leg is present
        while True:
            await self._sleep(_BUFFER_EVICT_INTERVAL_SECONDS)
            try:
                evicted = self._tui_leg.evict_expired()
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
            await self._flush_pending_replay()
            if self._tui_leg is not None:
                # Spec A G4b-2a (#237): the supervised TTL-eviction sweep runs only when a
                # leg is injected. Spawned AFTER the initial connect (so a shutdown
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
                    await self._flush_pending_replay()
                    continue
                if not handled:
                    # A clean EOF: the gap is already announced if a ``going_down``
                    # preceded it (idempotent CRASH_EOF), else this opens it.
                    await self._feed(GatewayLinkEvent.CORE_CRASH_EOF)
                    transport = await self._reconnect_closing(transport)
                    self._current_core_transport = transport
                    await self._flush_pending_replay()
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
            # Zero the retained PRE-DLP bytes on EVERY run() exit (security): the buffer
            # holds mutable bytearray copies of un-acked operator input so they can be
            # scrubbed in place; discard() zeros + empties them. Without this, a shutdown /
            # disconnect with un-acked frames leaves pre-DLP input resident in the always-up
            # process until GC (CLAUDE.md hard rule #7 — no silent residual exposure). Runs
            # AFTER the evict-task reap above so the evict loop cannot mutate concurrently.
            # discard() preserves the seq floor (correct for a terminal exit, unlike the
            # per-connection reset_for_new_epoch); the IMMUTABLE bytes in ``_pending_replay``
            # cannot be zeroed in place, so they are left to GC (the existing security model).
            # G6-4a (#288): ``leg.discard()`` zeros + empties the buffer AND releases its
            # bytes to the global cap (K2); it does NOT reset the seq floor (PR9 — only
            # ``reset_for_new_epoch`` does, the per-connection path).
            if self._tui_leg is not None:
                self._tui_leg.discard()
            # Drop the relay's transport reference BEFORE closing so a concurrent
            # ``submit_tui_unit`` snapshots ``None`` (a loud drop) rather than a
            # mid-close transport (CLAUDE.md hard rule #7 — no silent send-into-a-corpse).
            self._current_core_transport = None
            if transport is not None:
                await transport.close()

    async def _flush_pending_replay(self) -> None:
        """Re-send the captured un-acked remainder on the freshly-bound leg (G4b-2b).

        Called from ``run`` after a (re)connect binds ``_current_core_transport`` and the
        link is UP, BEFORE the pump resumes. Each stashed payload is re-sent through the TUI
        leg's ``record_for_send`` (append-before-send, fresh per-connection seq 0,1,…) then the
        single ``write_leg_unit`` writer, so the core G0-dedups on the in-payload ``inbound_id``
        (ADR-0032 §6.2); then the replay-pending gate is SET so the held client->core pump
        resumes — replayed frames have taken the lowest seqs, so fresh input follows in FIFO
        order. Idempotent: clears the stash at entry so a re-entrant call cannot double-replay.

        **No silent loss (R1, hard rule #7).** If the leg vanished mid-flush
        (``_current_core_transport is None`` — a reconnect race), the un-sent remainder is
        RE-STASHED and a loud ``buffer_replay_deferred`` row is written; the gate stays
        CLEARED so the next bind's flush retries (the client pump stays parked — the leg is
        unusable). ``buffer_replayed`` is emitted ONLY for a frame actually handed to the leg.
        A broken-pipe mid-replay (transport non-None, ``write_leg_unit`` loud-drops) is
        SELF-HEALING — ``record_for_send`` appended the frame BEFORE the send, so it stays
        buffered and replays next reconnect; only the None case re-stashes.

        **Never-raise contract (H1, Spec B G6-4 #288 — CRITICAL).** ``record_for_send`` CAN
        raise ``ReplayBufferError`` on a hard-ceiling breach, and an uncaught raise here would
        escape into ``run``'s reconnect path and crash the always-up core-link task. The PR3
        single-leg invariant ("the captured remainder fits in the buffer it just fit in") DOES
        NOT hold across the FIFO merge: a deferred remainder from a prior None-transport flush
        (R1) PREPENDED to this epoch's capture (in :meth:`_peer_handshake`) can build a
        COMBINED set that exceeds the hard ceiling of the freshly-reset (empty) buffer. So the
        per-frame ``record_for_send`` is wrapped in ``try/except ReplayBufferError``: a breach
        is a LOUD drop of THAT frame (``gateway.comms.buffer_replay_ceiling_dropped`` —
        closed-vocab, payload-blind: ``adapter_id`` + seq only, never a body) and the flush
        CONTINUES self-healing the frames that DO fit. It NEVER re-raises into ``run`` (CLAUDE.md
        hard rule #7: loud, never silent, never a core crash). ``write_leg_unit`` stays the SOLE
        physical writer (PR5: the None-check stays STRICTLY AHEAD of ``record_for_send`` so a
        None-transport defer does NOT consume a leg seq); its own faults are an internal
        loud-drop that never raises.
        """
        frames = self._pending_replay
        self._pending_replay = ()
        leg = self._tui_leg
        try:
            for index, frame in enumerate(frames):
                if self._current_core_transport is None:
                    self._pending_replay = frames[index:]
                    log.warning(
                        "gateway.comms.buffer_replay_deferred",
                        deferred=len(self._pending_replay),
                        reason="transport_lost_mid_replay",
                    )
                    return
                # PR5: ``record_for_send`` runs STRICTLY past the None-check above — a
                # None-transport defer must NOT consume a leg seq. ``frames`` is non-empty
                # only when a capture happened, which only happens on a leg-wired link.
                assert leg is not None
                # H1 (Spec B G6-4, #288): ``record_for_send`` CAN raise ``ReplayBufferError``
                # on a hard-ceiling breach. The PR3 invariant ("the captured remainder fits in
                # the buffer it just fit in") DOES NOT hold across the FIFO merge: a deferred
                # remainder from a prior None-transport flush (R1) PREPENDED to this epoch's
                # capture builds a COMBINED set that can exceed the hard ceiling of the
                # freshly-reset (empty) buffer. An uncaught raise here would escape into
                # ``run``'s reconnect arm and crash the always-up core-link task. Guard the
                # per-frame record/write: a hard-ceiling breach is a LOUD drop of THAT frame
                # (closed-vocab, payload-blind — ``adapter_id`` + seq only, never a body), and
                # the flush stays self-healing — the frames that DO fit are still re-sent so
                # resume converges (the dropped frame is deliberate security-over-liveness
                # loss, the same posture as TTL eviction, spec §6). NEVER re-raises into
                # ``run`` (CLAUDE.md hard rule #7: loud, not silent, but never a core crash).
                try:
                    seq = leg.record_for_send(frame.payload)
                except ReplayBufferError as exc:
                    log.warning(
                        "gateway.comms.buffer_replay_ceiling_dropped",
                        adapter_id=leg.adapter_id,
                        seq=frame.seq,
                        reason="hard_ceiling",
                        error=repr(exc),
                    )
                    continue
                log.warning(
                    "gateway.comms.buffer_replayed", seq=frame.seq, reason="reconnect_resume"
                )
                await self.write_leg_unit(
                    leg.adapter_id, frame.payload, seq=seq, ack=self.core_cumulative_ack()
                )
        finally:
            # Release the held pump ONLY on a COMPLETE flush. A defer (R1) leaves
            # _pending_replay non-empty -> gate stays clear; a complete/empty flush -> gate
            # set; a stray relay_to_core raise still hits this -> gate set (S5 DoS fail-safe,
            # no client->core wedge).
            if not self._pending_replay:
                self._replay_pending.set()

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
        # Spec A G4b-2-pre (#237): the per-connection client->core send-seq is reset
        # alongside the receive tracker — a fresh core leg is a fresh per-connection seq
        # space, so the first leg send on the new leg carries wire seq 0 (resume
        # correctness). G6-4a (#288): the seq now lives in the leg; ``reset_for_new_epoch``
        # below rebinds it to 0.
        if self._tui_leg is not None:
            leg = self._tui_leg
            # Spec A G4b-2b (#237): CAPTURE the un-acked remainder BEFORE the floor-reset so
            # it can be replayed on the fresh leg (the bodies are independent copies that
            # survive the reset's zeroing) — replacing the G4b-2a loud-loss drop. Clear the
            # replay-pending gate so the relay's client->core pump HOLDS until the flush
            # re-sends these: replayed frames must take the lowest seqs (precede fresh input,
            # spec §4). ORDERING INVARIANT (R4): this clear runs inside _peer_handshake, which
            # COMPLETES before the caller feeds CORE_READY and before run() rebinds the
            # transport + flushes — so the pump can never observe an unparked gate between
            # CORE_READY and the flush. An empty buffer (first connect / fully-acked
            # reconnect) is a no-op: nothing to replay, gate stays set. The unconditional
            # reset_for_new_epoch (the comms-1 fix) stays.
            # FIFO-MERGE (PR4): PREPEND any deferred remainder from a prior None-transport
            # flush (R1) ahead of this epoch's capture, rather than overwriting it — else the
            # deferred frames (which are NOT in the buffer) are silently lost, breaking the R1
            # no-silent-loss guarantee. ``_pending_replay`` MUST be the LEFT operand: deferred
            # frames are older in the stream, so they replay first; the core dedups any
            # already-committed re-send on the in-payload inbound_id. G6-4a (#288): the leg's
            # ``unacked_frames()`` returns ``(seq, payload)`` pairs — wrap them in
            # ``ReplayFrame`` so ``_pending_replay`` stays ``tuple[ReplayFrame, ...]``.
            self._pending_replay = self._pending_replay + tuple(
                ReplayFrame(seq=s, payload=p) for (s, p) in leg.unacked_frames()
            )
            if self._pending_replay:
                self._replay_pending.clear()
            leg.reset_for_new_epoch()
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
            if self._tui_leg is not None:
                params = parsed.get("params") if isinstance(parsed, Mapping) else None
                ack = params.get("cumulative_ack") if isinstance(params, Mapping) else None
                if isinstance(ack, int) and not isinstance(ack, bool) and ack >= 0:
                    # G6-4a (#288): the leg's ``trim_to_ack`` removes durably-acked frames
                    # AND releases their bytes to the global cap (K2).
                    self._tui_leg.trim_to_ack(ack)
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
        if method == CORE_ADAPTER_SPAWN_GRANT:
            # Spec B G6-3 (#288): the credential RESPONSE on the seq-enabled wire. The
            # method-peek classifies it as a control frame to CONSUME (route to its
            # pending waiter), NEVER forwarded byte-for-byte to the client relay — a
            # leaked credential frame would be a CRITICAL trust-boundary break. An
            # unsolicited/forged grant is a loud drop inside ``_route_spawn_grant``.
            params = parsed.get("params") if isinstance(parsed, Mapping) else None
            self._route_spawn_grant(params)
            return
        # An opaque payload (incl. a no-``method`` response): forward the ORIGINAL bytes.
        await self._payload_relay(frame.payload)

    async def submit_tui_unit(self, payload: bytes) -> None:
        """Admit + ENQUEUE an opaque TUI client payload onto the leg scheduler (G6-4 Task 7).

        The relay's stable client->core entry point (relay.py:243). Under Spec B G6-4 Task 7
        (architect Option A) the steady-state drainer is the
        :class:`alfred.gateway.leg_scheduler.GatewayLegScheduler`: this method ADMITS the
        frame through the TUI leg's payload-blind ingress gate and ENQUEUES it on the leg's
        bounded scheduler queue (via the :class:`alfred.gateway.leg_router.LegRouter`). The
        seq mint + buffer append (append-before-send) + breaker escalation + the single
        physical :meth:`write_leg_unit` ALL happen at DRAIN time, serialized BEHIND any
        in-flight reconnect-replay by :attr:`replay_pending_gate` (the scheduler awaits it).

        **No inline None-check / mint (PR5 re-expressed).** The seq is minted at drain, not
        here; the sole transport None-guard now lives in :meth:`write_leg_unit` (the physical
        writer guards the physical transport). A frame enqueued during a gap is
        ``record_for_send``-d at drain even if the transport is then ``None`` — it is
        loud-dropped on the wire but STAYS buffered (append-before-send) and re-sequences
        from 0 after the next ``reset_for_new_epoch``, so no permanent leg seq is burned.

        **Ingress admission (Spec B G6-4 / K3/K6).** ``try_admit`` is payload-blind (size /
        rate / in-flight only — never the body). The TUI leg's gate is NON-BINDING (the
        interactive path is never throttled), so admission always succeeds here; a real
        adapter leg (G6-5) that trips is back-pressured + audited (closed-vocab reason) and
        NOT enqueued — never a silent drop (hard rule #7). A full per-leg queue raises
        :class:`LegQueueFullError` which the relay pump turns into read back-pressure.
        Payload-blind (#5): ``adapter_id`` is the only routing key.
        """
        assert self._tui_leg is not None  # submit path is only reached on a leg-wired link
        assert self._leg_router is not None  # the scheduler/router is wired alongside the leg
        admit = self._tui_leg.try_admit(frame_bytes=len(payload))
        if admit.decision is not IngressDecision.ADMITTED:
            self._record_ingress_refusal(self._tui_leg, admit.decision)
            return
        # The in-flight slot is released as the frame leaves the gateway (the drain's write).
        # For the NON-BINDING TUI gate this is bookkeeping only; for a real adapter leg it is
        # what keeps the in-flight cap honest. We release immediately after enqueue: the leg
        # owns the durable retention (the buffer), so the ingress slot's job (volumetric
        # admission) is done once the frame is queued for the single writer.
        self._tui_leg.release_admit(admit.token)  # type: ignore[arg-type]  # ADMITTED -> token set
        # H2 (Spec B G6-4, #288): a registered leg whose bounded send-queue is full raises
        # ``LegQueueFullError`` from ``scheduler.enqueue`` (via the router). That raise was
        # OUTSIDE the relay read pump's try/except, so it escaped this method →
        # ``_client_to_core_pump`` → and crashed the always-up gateway's relay TaskGroup —
        # the OPPOSITE of this method's promised "read back-pressure". Handle it HERE at the
        # submit boundary: a full queue is the leg already saturated (the single writer cannot
        # keep up), so the frame is DROPPED-LOUD as a closed-vocab back-pressure refusal
        # (``queue_full``) + the per-adapter back-pressure counter, matching the breaker /
        # read-halt back-pressure posture — NEVER a crash (CLAUDE.md hard rule #7: loud, not
        # silent, never a core-down). Payload-blind: ``adapter_id`` is the only routing key.
        try:
            self._leg_router.route(self._tui_leg.adapter_id, payload)
        except LegQueueFullError:
            self._record_queue_full_back_pressure(self._tui_leg)

    async def forward_adapter_inbound(self, adapter_id: str, body: bytes | str) -> None:
        """Forward a hosted adapter child's ``inbound.message`` to the core (Spec B G6-7-3).

        FORK-B. The gateway forward-runner's disposition calls this with the SPAWN-BINDING
        ``adapter_id`` (SEC-309-1 — NEVER read from the body) and the child's already-parsed
        ``inbound.message`` ``params`` serialized to an opaque JSON ``str`` ``body``. This
        method:

        1. wraps the opaque body in a :class:`GatewayAdapterInboundEnvelope` carrying the
           passed (binding) ``adapter_id`` — the envelope is the method-bearing
           (``gateway.adapter.inbound``) frame the core's ``_route_notification`` discriminates
           by METHOD (G6-7-4), never by an id heuristic;
        2. serializes the WHOLE envelope to ``payload: bytes`` via ``model_dump_json``. The
           body's BYTE CONTENT is stable through serialize -> ReplayBuffer -> core re-parse,
           so the embedded ``inbound_id`` is byte-stable across the leg's ReplayBuffer replay
           (SEC-309-2). NOTE: a ``str`` ``body`` re-validates core-side as ``bytes`` (the wire
           model's ``bytes | str`` union coerces a JSON string to ``bytes``) — the content is
           preserved verbatim, but the runtime TYPE flips ``str`` -> ``bytes``. The disposition
           hands a ``str`` body precisely so the envelope serializer never base64-round-trips a
           ``bytes`` body lossily;
        3. routes ``payload`` through the :class:`LegRouter` the link already holds (the same
           ``set_leg_router`` binding ``submit_tui_unit`` uses) — the per-adapter leg's seq/ack
           + ReplayBuffer give the forwarded inbound resume + replay byte-stability for free.

        **Errors SURFACE to the caller (FORK-B / FORK-C).** A :class:`LegQueueFullError`
        (per-leg byte budget) or a :class:`ReplayBufferError` (global cap, defensively caught
        — only ``LegQueueFullError`` is the live synchronous raise) propagates to the
        disposition, which engages reader back-pressure (clear the gate). They are NOT swallowed
        here — a genuine full leg is back-pressure, never a silent drop (CLAUDE.md hard rule #7).
        Those are a FULL but REGISTERED leg.

        DISTINCTLY: the :class:`LegRouter` RETURNS (does not raise)
        :data:`RouteOutcome.REFUSED_UNKNOWN_ADAPTER` when ``adapter_id`` names NO registered
        leg (ERR-309-1). Discarding that return would let the disposition falsely log
        ``forward_accepted`` on a LOST frame (hard rule #7 silent-loss). So we INSPECT the
        outcome and raise :class:`ForwardLegUnavailableError` — a typed signal the disposition
        catches as a LOUD TERMINAL drop (the leg is gone — retrying is futile). This is reachable
        when the scheduler's isolation arm deregisters the leg WHILE a forward is parked on
        back-pressure: on resume the held frame re-forwards and the router now refuses it.

        The route is the PRODUCER path (enqueue), NEVER ``GatewayLeg.record_for_send`` (that is
        drain-time, scheduler-only). Payload-blind: ``adapter_id`` is the only routing key; the
        body is never parsed here.
        """
        assert self._leg_router is not None  # the gateway always wires the router before forward
        # ``adapter_id`` is a plain ``str`` here (the spawn-binding id); the wire model's
        # closed-vocab ``AdapterId`` validates it at construction — a forged kind is a loud
        # ValidationError at this boundary (fail-loud, hard rule #7), never a silent route.
        envelope = GatewayAdapterInboundEnvelope(adapter_id=adapter_id, body=body)
        # ADR-0039 item 3 (Spec B G6-7-4, #309): the core discriminates a forwarded inbound
        # from a directly-connected adapter's ``inbound.message`` by METHOD NAME — so the
        # forward rides as a JSON-RPC NOTIFICATION (no ``id``: fire-and-forget, mirroring
        # ``inbound.message`` itself), NOT a bare envelope object the daemon pump would mistake
        # for a response frame and drop. The opaque body stays verbatim inside ``params.body``
        # (payload-blind, byte-stable for G0 — SEC-309-2).
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": GATEWAY_ADAPTER_INBOUND,
                "params": envelope.model_dump(mode="json"),
            }
        ).encode()
        outcome = self._leg_router.route(adapter_id, payload)
        if outcome is RouteOutcome.REFUSED_UNKNOWN_ADAPTER:
            # ERR-309-1: the router refused (the leg is unregistered/gone). The K4
            # ``record_unknown_adapter_refusal`` row already fired inside ``route`` (labelled
            # as a forged/unknown-adapter refusal). Surface it as a typed terminal-drop signal
            # so the disposition LOUD-DROPS rather than discarding the outcome and falsely
            # logging ``forward_accepted`` on a LOST frame (hard rule #7 silent-loss).
            raise ForwardLegUnavailableError(
                f"forward refused: adapter_id={adapter_id!r} has no registered leg"
            )

    def _record_ingress_refusal(self, leg: GatewayLeg, decision: IngressDecision) -> None:
        """Back-pressure + metric + LOUD audit on an ingress trip (K6, never silent).

        Maps the gate's :class:`IngressDecision` onto the closed-vocab
        :class:`IngressRefusalReason` and writes the field-allowlisted refusal row
        (``adapter_id`` + reason + scalar counters only — no body / hash / platform-id).
        OVERSIZED and THROTTLED_RATE collapse onto ``THROTTLED_RATE`` is WRONG — each has its
        own reason; ``ADMITTED`` never reaches here (the caller guards it).
        """
        reason = _INGRESS_REFUSAL_REASON[decision]
        record_ingress_refusal(
            leg.adapter_id,
            reason,
            depth_frames=leg.depth_frames,
            depth_bytes=leg.depth_bytes,
            inflight=leg.inflight_count,
            cap_ratio=leg.cap_ratio,
        )

    def _record_queue_full_back_pressure(self, leg: GatewayLeg) -> None:
        """Back-pressure + metric + LOUD audit on a full leg send-queue (H2, never a crash).

        The :class:`LegQueueFullError` boundary handler (Spec B G6-4 / #288). A full per-leg
        send-queue means the bounded pre-append working memory is saturated (the single core
        writer cannot keep up); the frame is dropped-loud through the SAME field-allowlisted K6
        sink as the ingress-gate refusals, carrying the closed-vocab :attr:`QUEUE_FULL` reason.
        Payload-blind by construction (the sink has nowhere to put a body). NEVER raises — a
        producer outrunning the writer must back-pressure, not crash the always-up gateway.
        """
        record_ingress_refusal(
            leg.adapter_id,
            IngressRefusalReason.QUEUE_FULL,
            depth_frames=leg.depth_frames,
            depth_bytes=leg.depth_bytes,
            inflight=leg.inflight_count,
            cap_ratio=leg.cap_ratio,
        )

    async def escalate_if_breaker_tripped(self, leg: GatewayLeg) -> None:
        """Feed BREAKER_TRIPPED iff ``leg``'s soft cap latched; once-only UNAVAILABLE (JC-2).

        The drain-time breaker seam (Spec B G6-4 Task 7 / architect ruling). The scheduler
        calls this AFTER a successful ``record_for_send`` (the append is what can breach the
        soft cap) and BEFORE the physical write. The breaker feed MOVED here from the retired
        inline ``submit_tui_unit`` path; the ``LinkStateMachine`` + ``_feed`` + the audit row
        stay owned by the link (the scheduler stays leg-agnostic — it passes the opaque
        :class:`GatewayLeg`). The absorbing machine emits ``LinkControl.UNAVAILABLE`` EXACTLY
        once, so the loud audit row fires once across every caller (scheduler-fresh AND any
        future replay). Payload-blind: ``adapter_id`` / scalar depths only.

        The reconnect flush (:meth:`_flush_pending_replay`) does NOT call this: the captured
        remainder re-appends into a freshly-``reset_for_new_epoch``-ed (un-tripped) buffer
        and cannot breach, and escalating during a recovery replay would fight the reconnect.
        """
        if not leg.breaker_tripped:
            return
        control = await self._feed(GatewayLinkEvent.BREAKER_TRIPPED)
        if control is LinkControl.UNAVAILABLE:
            log.warning(
                "gateway.comms.breaker_tripped",
                # CR (Spec B G6-4 #288): include the leg id so a MULTI-leg incident keeps the
                # routing key needed to triage WHICH adapter tripped (CLAUDE.md hard rule #7 —
                # a loud row must carry enough context to act). Payload-blind: ``adapter_id``
                # is the gateway-chosen leg key, never a body / platform-id.
                adapter_id=leg.adapter_id,
                depth_frames=leg.depth_frames,
                depth_bytes=leg.depth_bytes,
            )
            # G6-4 Task 7 (#288): the breaker just latched at DRAIN — flip the UNLABELLED
            # JC-1 ``gateway_circuit_breaker_open`` gauge (the once-only escalation edge is
            # the right place; the ``ops/`` page-severity alert + Grafana panel key on the
            # unlabelled series). Single-TUI-leg ONLY — PR13: never per-non-TUI-leg drain, so
            # refresh the unlabelled shim only when the escalating leg IS the TUI leg.
            if leg is self._tui_leg:
                self._refresh_buffer_metrics()

    def core_cumulative_ack(self) -> int:
        """The core-leg receive tracker's contiguous ack, FLOORED to ``0`` (G6-4 / K1).

        The leg-agnostic ack a :class:`alfred.gateway.gateway_leg.GatewayLeg` stamps on a
        drained frame (the scheduler reads it before :meth:`write_leg_unit`). The tracker's
        ``-1`` ("nothing acked yet") maps to the wire's ``a=0`` placeholder, exactly as
        :meth:`relay_to_core` floors it — without the floor :func:`encode_seq_frame` would
        reject the first client->core unit (non-negative counters).
        """
        return max(self._core_tracker.cumulative_ack(), 0)

    async def write_leg_unit(self, adapter_id: str, payload: bytes, *, seq: int, ack: int) -> None:
        """Physically send ONE pre-sequenced leg frame onto the single core writer (K1).

        The leg-agnostic write primitive the
        :class:`alfred.gateway.leg_scheduler.GatewayLegScheduler` drains every leg onto.
        UNLIKE :meth:`relay_to_core` (the G5 single-TUI-leg path,
        which mints the seq + appends to its own buffer inline), this takes ``seq`` + ``ack``
        EXPLICITLY: the per-leg seq mint + ``ReplayBuffer.append`` + global-cap reserve all
        live in :class:`GatewayLeg` (moved out of ``relay_to_core`` per K1), and the
        scheduler hands the already-sequenced unit here for the physical write only.

        **Snapshot atomicity preserved (architect M3).** ``_current_core_transport`` is
        snapshotted into a local FIRST so a concurrent reconnect swap is atomic w.r.t. this
        send; a ``None`` snapshot (the reconnect-race / gap window) is a loud drop. The
        single physical writer is preserved — the scheduler serialises all legs onto this
        one coroutine; it never reaches into the transport itself.

        **Loud drop, never raise (CLAUDE.md hard rule #7).** Any send-path fault — a torn
        transport, an encode failure, or a write to a closed-mid-swap transport — is a LOUD
        drop, never raised into the scheduler pump (a dead/swapping leg is an OPERATIONAL
        edge; the frame stays in the leg's buffer for replay). ``adapter_id`` is carried for
        the audit breadcrumb only — payload-blind, no body parse.

        **Unlabelled JC-1 gauges (G6-4 Task 7 / #288).** The scheduler-owned
        ``record_for_send`` ran (and APPENDED) before this writer; under Option A this single
        link-owned per-drain writer is the seam that refreshes the UNLABELLED
        ``gateway_buffer_depth_*`` / ``gateway_buffer_cap_ratio`` series the ``ops/`` Grafana
        panels + alerts key on (the inline G5 path used to refresh them per-append). Done
        UNCONDITIONALLY of the wire outcome (the append is durable even on a loud drop), but
        ONLY for the TUI leg — PR13: never per-non-TUI-leg drain. The breaker-open gauge is
        refreshed on its once-only trip edge in :meth:`escalate_if_breaker_tripped`.
        """
        if self._tui_leg is not None and adapter_id == self._tui_leg.adapter_id:
            self._refresh_buffer_metrics()
        local = self._current_core_transport
        if local is None:
            log.warning(
                "gateway.relay.core_send_dropped",
                reason="no_core_transport",
                adapter_id=adapter_id,
            )
            return
        try:
            await local.send_payload_unit(payload, seq=seq, ack=ack)
        except (
            BrokenPipeError,
            ConnectionResetError,
            RuntimeError,
            ValueError,
            CommsProtocolError,
        ) as exc:
            log.warning("gateway.relay.core_send_dropped", error=repr(exc), adapter_id=adapter_id)

    async def send_status_frame(self, method: str, params: Mapping[str, object]) -> None:
        """Send a ``gateway.adapter.*`` status frame over the SEPARATE status channel.

        Spec B §3 / G6-2b-2a (#288). The status seam is DISTINCT from the opaque
        T3 ``_payload_relay`` (payload-blindness, CLAUDE.md hard rule #5): a status
        frame is a method-bearing JSON-RPC notification sent via the transport's
        :meth:`send` (the same primitive the handshake ack uses), so it lands in the
        core HOST's :meth:`alfred.plugins.comms_runner.CommsPluginRunner._pump` as a
        routed notification — NEVER via :meth:`send_payload_unit` (the opaque relay
        carrier). The gateway does not parse any T3 body to build this frame;
        ``params`` is supervision metadata.

        **Loud drop, NO buffering (CLAUDE.md hard rule #7).** A ``None`` current
        transport (the reconnect-race / pre-UP window) or any send-path fault is a
        LOUD drop, never raised, never buffered — mirroring :meth:`relay_to_core`.
        A dropped status frame is re-derivable from the next live transition; the
        status leg is observability, not durable-intake.
        """
        local = self._current_core_transport
        if local is None:
            log.warning("gateway.status.send_dropped", reason="no_core_transport", method=method)
            return
        frame: dict[str, object] = {"jsonrpc": "2.0", "method": method, "params": dict(params)}
        try:
            await local.send(frame)
        except (BrokenPipeError, ConnectionResetError, RuntimeError, CommsProtocolError) as exc:
            log.warning("gateway.status.send_dropped", error=repr(exc), method=method)

    async def request_spawn_grant(
        self, request: SpawnRequest, *, timeout: float = _SPAWN_GRANT_TIMEOUT_SECONDS
    ) -> SpawnGrant:
        """Send ``gateway.adapter.spawn_request`` and await its correlated grant (G6-3).

        The credential round-trip's gateway half (Task 2.5). Snapshots the current
        core transport, registers a pending Future keyed on ``request.request_id``,
        sends the request on the method-bearing ``send`` channel (the SAME primitive
        the status frames + handshake ack use — NOT the opaque ``send_payload_unit``
        relay), then awaits the matching :class:`SpawnGrant` the pump routes back via
        :meth:`_consume_frame` / :meth:`_route_unit`.

        **Fail-closed, two distinct arms (corrections A-C1/A-C2).**
        * Link-DOWN (no live transport, or the send raises a transport fault):
          :class:`CredentialLegDownError` — the supervisor's AWAITING_CORE consumes it.
        * Link-UP but the reply is dropped/unrouted: a bounded ``wait_for`` raises
          :class:`CredentialReplyTimeoutError` — a loud abort, never a hang.

        The pending Future is ALWAYS cleaned up (popped) on every exit path so a late
        grant cannot resolve a Future no one awaits, and the credential never lingers
        in the registry.
        """
        transport = self._current_core_transport
        if transport is None:
            raise CredentialLegDownError(
                f"core leg down; cannot request spawn grant (request_id={request.request_id!r})"
            )
        loop = asyncio.get_running_loop()
        future: asyncio.Future[SpawnGrant] = loop.create_future()
        # Register the waiter BEFORE the send so a response that races back is
        # correlated (mirrors the host runner's send_request ordering).
        self._pending_grants[request.request_id] = future
        try:
            try:
                await transport.send(
                    {
                        "jsonrpc": "2.0",
                        "method": GATEWAY_ADAPTER_SPAWN_REQUEST,
                        "params": request.model_dump(),
                    }
                )
            except (BrokenPipeError, ConnectionResetError, RuntimeError, CommsProtocolError) as exc:
                # The leg tore mid-send: treat as link-DOWN (the supervisor awaits-core),
                # NOT a reply-timeout. Loud + typed (CLAUDE.md hard rule #7).
                raise CredentialLegDownError(
                    f"core leg send failed (request_id={request.request_id!r})"
                ) from exc
            try:
                return await asyncio.wait_for(future, timeout)
            except TimeoutError as exc:
                log.error(
                    "gateway.core_link.spawn_grant_timeout",
                    request_id=request.request_id,
                )
                raise CredentialReplyTimeoutError(
                    f"no spawn grant within {timeout}s (request_id={request.request_id!r})"
                ) from exc
        finally:
            # Drop the waiter on EVERY exit (resolved, timed out, or send-failed) so a
            # late grant resolves nothing and the credential never lingers (security).
            self._pending_grants.pop(request.request_id, None)

    def _route_spawn_grant(self, params: object) -> None:
        """Resolve a pending credential waiter from an inbound grant frame's params.

        Always CONSUMES a ``core.adapter.spawn_grant`` frame: the params are validated
        + routed to a waiter, OR loud-dropped (an unsolicited / mismatched / malformed
        grant). The two call sites already route this method ONLY for the
        ``core.adapter.spawn_grant`` method, so it never needs to signal "not mine" — it
        returns ``None``. A malformed grant or one with no matching pending waiter is a
        LOUD drop, never a crash (adversarial e): the carrier cannot be hung or unwound
        by a forged response frame.
        """
        raw = params if isinstance(params, Mapping) else {}
        try:
            grant = SpawnGrant.model_validate(raw)
        except ValidationError:
            # A malformed grant — no exc detail logged (it could echo the raw wire +
            # the credential field). Loud + drop; never feed a waiter (hard rule #7).
            log.warning("gateway.core_link.spawn_grant_malformed")
            return
        future = self._pending_grants.get(grant.request_id)
        if future is None or future.done():
            # No outstanding request (unsolicited grant) or already-resolved: drop loud
            # (adversarial e). NEVER log the grant object (its credential is repr-safe,
            # but log only the routing id) and NEVER crash the pump.
            log.warning("gateway.core_link.spawn_grant_unsolicited", request_id=grant.request_id)
            return
        future.set_result(grant)

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
        elif method == CORE_ADAPTER_SPAWN_GRANT:
            # Spec B G6-3 (#288): the FIRST core->gateway RESPONSE frame on this leg.
            # Route it to its pending credential waiter (the request/response
            # correlation primitive) — NEVER relayed to the client, NEVER fed to the
            # link-state machine. An unsolicited/forged grant is a loud drop inside.
            self._route_spawn_grant(frame.get("params"))
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
    "CredentialLegDownError",
    "CredentialReplyTimeoutError",
    "ForwardLegUnavailableError",
    "GatewayCoreLink",
    "GatewayCoreLinkError",
    # REV-2 (#288): the shared transport-seam Protocol is part of this module's
    # public surface — ``alfred.gateway.relay`` binds to it as the type of the
    # core/client transport. Re-export it so a cross-module consumer reaches a
    # declared name rather than a ``_``-prefixed internal (the leading underscore
    # marks it as not-instantiable, not module-private).
    "_CommsTransportLike",
]
