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
import random
from collections.abc import Awaitable, Callable, Mapping
from typing import Final, Protocol, runtime_checkable

import structlog
from pydantic import ValidationError

from alfred.comms_mcp.protocol import (
    DAEMON_LIFECYCLE_GOING_DOWN,
    DAEMON_LIFECYCLE_READY,
    GoingDownNotification,
    ReadyNotification,
)
from alfred.errors import AlfredError
from alfred.gateway._control_frames import control_notification
from alfred.gateway.client_listener import GatewayClientListener
from alfred.gateway.link_state import (
    GatewayLinkEvent,
    GatewayLinkState,
    LinkStateMachine,
)
from alfred.gateway.metrics import CORE_LINK_UP, RECONNECT_ATTEMPTS
from alfred.plugins.comms_seq_codec import SEQ_VERSION
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

# The JSON-RPC method the core sends first on the core leg. Anything else before
# the handshake is warn-and-dropped (mirrors the host runner's pre-handshake arm).
_LIFECYCLE_START_METHOD: Final[str] = "lifecycle.start"


class GatewayCoreLinkError(AlfredError):
    """The core-leg peer handshake failed (fail-loud, CLAUDE.md hard rule #7).

    Raised on a clean EOF before ``lifecycle.start`` arrives, or on a
    ``lifecycle.start`` whose ``epoch`` is absent or malformed (not 32 lowercase
    hex). Mirrors the host runner's :class:`PluginError` handshake-failure arm —
    an unusable core handshake is never a silent no-op.
    """


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
        # Full jitter (AWS "Exponential Backoff And Jitter"): each delay is a uniform
        # draw in ``[0, backoff]``, NOT the bare backoff — independent processes that
        # gap together must not redial in lockstep. The default RNG is unseeded
        # (jitter is not security-sensitive); a test injects ``lambda hi: hi`` to read
        # the bare schedule, or a seeded ``random.Random`` for a fixed draw.
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
        self._dropped_payload_frames: int = 0

    async def _default_dial(self) -> _CommsTransportLike:
        """Production dial: connect the core's comms socket on the keyed adapter id.

        The import is local (not module-top) so importing this trust-boundary module
        stays cheap and cannot close an import cycle with the socket transport, which
        in turn imports this package's siblings.
        """
        from alfred.plugins.comms_socket_transport import dial_comms_socket

        return await dial_comms_socket(self._dial_adapter_id)

    async def _reconnect(self) -> _CommsTransportLike:
        """Dial + handshake the core leg, retrying with exponential backoff + jitter.

        Loops until a dial AND its peer handshake both succeed, returning the live
        transport. Each attempt feeds ``REDIAL_STARTED`` to the link-state machine,
        increments :data:`RECONNECT_ATTEMPTS`, then sleeps a FULL-JITTER delay BEFORE
        dialing (spec §4). The backoff SCHEDULE floor starts at
        ``INITIAL_BACKOFF_SECONDS`` (the ceiling never starts at 0) and doubles by
        ``_BACKOFF_FACTOR`` up to ``MAX_BACKOFF_SECONDS`` on every failed attempt; the
        actual delay each attempt is a full-jitter draw in ``[0, backoff]`` (so an
        individual draw CAN land near 0 — the jitter, by design, can collapse a single
        wait — but the schedule ceiling itself never starts at 0).

        A transient transport fault (``FileNotFoundError`` / ``ConnectionRefusedError``
        / ``OSError`` — a daemon-absent or stale-socket dial) and a wire/peer-auth
        failure (``CommsProtocolError``, which subsumes ``CommsPeerAuthError``) are
        caught, logged LOUD (CLAUDE.md hard rule #7), and retried.

        A dial that SUCCEEDS but whose handshake then RAISES leaves a half-open
        transport: it is ``close()``d before the loop retries so a repeatedly-failing
        handshake cannot leak an FD per attempt.
        """
        backoff = INITIAL_BACKOFF_SECONDS
        while True:
            await self._feed(GatewayLinkEvent.REDIAL_STARTED)
            RECONNECT_ATTEMPTS.inc()
            await self._sleep(self._jitter(backoff))
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
        if self._core_advertised_seq_ack(params):
            result["seq_ack"] = {"version": SEQ_VERSION}
            transport.enable_seq_ack()

        await transport.send({"jsonrpc": "2.0", "id": frame.get("id"), "result": result})

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

    async def _feed(self, event: GatewayLinkEvent) -> None:
        """Feed a TYPED event to the machine; emit any control frame; refresh the gauge.

        The control frame (if any) is mapped via :func:`control_notification` and
        pushed to the client through the listener. ``CORE_LINK_UP`` is set to ``1``
        iff the resulting machine state is UP, else ``0``.
        """
        control = self._machine.feed(event)
        if control is not None:
            await self._client_listener.send_control(control_notification(control))
        # CORE_UNAVAILABLE_SECONDS is a Task-6 concern (it needs a clock to accrue the
        # not-UP duration); the gauge is the only metric the pure transition updates.
        CORE_LINK_UP.set(1 if self._machine.state is GatewayLinkState.UP else 0)


__all__ = [
    "GATEWAY_PLUGIN_VERSION",
    "GatewayCoreLink",
    "GatewayCoreLinkError",
]
