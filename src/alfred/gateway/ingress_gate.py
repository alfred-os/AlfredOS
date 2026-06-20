"""``PerAdapterIngressGate`` — payload-blind per-adapter admission control (Spec B G6-4).

The always-up ``alfred-gateway`` multiplexes N adapter legs (+ the TUI dial-in leg)
over a single gateway->core link. This gate is the per-leg *volumetric* admission
controller that back-pressures a chatty leg BEFORE its frames reach the shared
ReplayBuffer / scheduler queue, so one leg cannot exhaust the shared core link or the
bounded pre-DLP retention budget (``[fleet perf-001/002/003]``).

Three coarse tiers, evaluated in this order so a refusal never consumes a scarcer
resource than the one that refused it:

1. **size** — a frame larger than ``max_frame_bytes`` is :data:`IngressDecision.OVERSIZED`.
   Size is *not content* (payload-blindness, CLAUDE.md hard rule #5): the gate is handed
   ``len(payload)``, never the body. Bounding the frame size bounds the head-of-line
   delay a single frame can impose on the single physical writer (K3).
2. **sustained rate** — a token bucket refilled LAZILY at ``sustained_rate_per_s`` and
   clamped at ``burst`` (``min(burst, tokens + elapsed*rate)`` — K5: no refill timer, the
   ``min`` is the no-over-accrual guard). Exhaustion is
   :data:`IngressDecision.THROTTLED_RATE`.
3. **in-flight cap** — a concurrency counter ``<= max_inflight``. Exhaustion is
   :data:`IngressDecision.THROTTLED_INFLIGHT`. An admitted frame holds a slot until its
   :meth:`release`; a slot held past ``ttl_seconds`` is reclaimed by :meth:`evict_stalled`
   so a *stalled* leg (a frame that never completes) cannot permanently wedge the cap
   (``[fleet perf-003]``).

**Payload-blind + volumetric, never identity.** :meth:`try_admit` takes ONLY a byte
count — no body, no platform-user-id. Keying on a per-user id at the gateway would (a)
leak a stable per-user identity into the SETUID process and (b) miss a distributed-id
flood. The core's :class:`alfred.comms_mcp.inbound._PreResolutionLimiter` keeps the
per-id defence-in-depth; this gate is the additive volume bound (the comms-F2 overturn).

**Pure — no I/O, no logging, no async.** Mirrors the sibling pure machines
(:class:`alfred.gateway.replay_buffer.ReplayBuffer`,
:class:`alfred.gateway.link_state.LinkStateMachine`): time is the injected ``now`` seam
(the spec §7 fake-clock), and *loudness is the wiring's job* — the gate returns a typed
:class:`AdmitResult` the leg relay (Task 2) turns into the metric + audit row. A misuse
(``release`` of an unknown token, a non-positive construction param) is the one fail-loud
arm and raises :class:`ValueError` (CLAUDE.md hard rule #7 — never a silent no-op).
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final


class IngressDecision(enum.Enum):
    """The four mutually-exclusive outcomes of :meth:`PerAdapterIngressGate.try_admit`."""

    ADMITTED = "admitted"
    OVERSIZED = "oversized"
    THROTTLED_RATE = "throttled_rate"
    THROTTLED_INFLIGHT = "throttled_inflight"


@dataclass(frozen=True, slots=True)
class AdmitResult:
    """The typed result of an admission attempt.

    ``token`` is set ONLY when :attr:`decision` is :data:`IngressDecision.ADMITTED`: it is
    the opaque in-flight handle the caller passes to :meth:`PerAdapterIngressGate.release`
    when the frame completes. On any refusal ``token`` is ``None``.
    """

    decision: IngressDecision
    token: int | None = None


@dataclass(slots=True)
class _InflightSlot:
    """One occupied in-flight slot: its admit-time stamp (for the TTL sweep)."""

    admitted_at: float


# An opaque, process-unique in-flight token. A global counter keyed across gates would be
# wasteful; instead each gate owns its own counter so a token from gate A is genuinely
# unknown to gate B (the cross-gate ``release`` is a fail-loud misuse, not a silent free).
_TOKEN_SEED: Final[int] = 1


class PerAdapterIngressGate:
    """Per-adapter token-bucket + in-flight-cap + size admission control (payload-blind)."""

    def __init__(
        self,
        adapter_id: str,
        *,
        sustained_rate_per_s: float,
        burst: int,
        max_inflight: int,
        ttl_seconds: float,
        max_frame_bytes: int,
        now: Callable[[], float],
    ) -> None:
        if sustained_rate_per_s <= 0:
            raise ValueError(f"sustained_rate_per_s must be positive: {sustained_rate_per_s}")
        if burst <= 0:
            raise ValueError(f"burst must be positive: {burst}")
        if max_inflight <= 0:
            raise ValueError(f"max_inflight must be positive: {max_inflight}")
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be positive: {ttl_seconds}")
        if max_frame_bytes <= 0:
            raise ValueError(f"max_frame_bytes must be positive: {max_frame_bytes}")
        self._adapter_id: Final[str] = adapter_id
        self._rate: Final[float] = sustained_rate_per_s
        self._burst: Final[int] = burst
        self._max_inflight: Final[int] = max_inflight
        self._ttl_seconds: Final[float] = ttl_seconds
        self._max_frame_bytes: Final[int] = max_frame_bytes
        self._now = now
        # The bucket starts FULL (a fresh leg may burst immediately). Float-valued so a
        # sub-token refill accumulates across calls without rounding loss.
        self._tokens: float = float(burst)
        self._last_refill: float = now()
        self._inflight: dict[int, _InflightSlot] = {}
        # The next in-flight token this gate will mint. A plain monotonic int (not
        # ``itertools.count``) so :meth:`release` can classify an unknown token as
        # issued-but-evicted (``< _next_token``) vs forged without consuming the counter.
        self._next_token: int = _TOKEN_SEED

    @property
    def adapter_id(self) -> str:
        """The gateway-chosen adapter id this gate guards (the sole metric label value)."""
        return self._adapter_id

    @property
    def inflight_count(self) -> int:
        """Number of in-flight slots currently held (observability / metric source)."""
        return len(self._inflight)

    def try_admit(self, *, frame_bytes: int) -> AdmitResult:
        """Attempt to admit one frame of ``frame_bytes`` bytes; never blocks.

        Evaluated size -> rate -> in-flight so a refusal never consumes a scarcer
        resource than the tier that refused. On admit a token is minted, a slot is
        reserved, and the bucket is debited; the caller MUST :meth:`release` the token
        when the frame completes (or it is reclaimed by the TTL sweep).
        """
        if frame_bytes > self._max_frame_bytes:
            return AdmitResult(IngressDecision.OVERSIZED)
        self._refill()
        if self._tokens < 1.0:
            return AdmitResult(IngressDecision.THROTTLED_RATE)
        if len(self._inflight) >= self._max_inflight:
            return AdmitResult(IngressDecision.THROTTLED_INFLIGHT)
        self._tokens -= 1.0
        token = self._next_token
        self._next_token += 1
        self._inflight[token] = _InflightSlot(admitted_at=self._now())
        return AdmitResult(IngressDecision.ADMITTED, token=token)

    def release(self, token: int) -> None:
        """Release an in-flight slot held by ``token``.

        A token already reclaimed by :meth:`evict_stalled` (a late completion of a
        stalled frame) is a quiet no-op — the slot is already free, so releasing it must
        NOT double-free. A token this gate NEVER issued (a cross-gate / forged token) is a
        fail-loud misuse: it raises :class:`ValueError` (CLAUDE.md hard rule #7) rather
        than silently corrupting the cap accounting. The two are distinguished by the
        token's magnitude: a value this gate could have minted (``>= _TOKEN_SEED`` and
        ``<`` the next id) but is no longer in-flight is the evicted-then-released case;
        anything else is unknown.
        """
        if token in self._inflight:
            del self._inflight[token]
            return
        if _TOKEN_SEED <= token < self._next_token:
            # Issued by THIS gate but already reclaimed (TTL-evicted): idempotent no-op.
            return
        raise ValueError(f"release of unknown ingress token: {token}")

    def evict_stalled(self) -> tuple[int, ...]:
        """Reclaim + return the tokens of slots held longer than ``ttl_seconds``.

        A slot is stalled when ``now - admitted_at > ttl_seconds`` (exactly-at-TTL is
        retained, mirroring :meth:`ReplayBuffer.evict_expired`). The returned tokens let
        the wiring write a loud audit row per reclaimed slot (the wedge guard is
        observable, never silent). Called both on-admit-adjacent and by the periodic
        sweeper (Task 7) so an IDLE-but-wedged leg is still swept.
        """
        now = self._now()
        stalled = tuple(
            token
            for token, slot in self._inflight.items()
            if now - slot.admitted_at > self._ttl_seconds
        )
        for token in stalled:
            del self._inflight[token]
        return stalled

    def _refill(self) -> None:
        """Lazily refill the bucket: ``min(burst, tokens + elapsed*rate)`` (K5).

        No timer — the elapsed time since the last refill is read from the injected clock
        and converted to tokens on demand. The ``min`` clamp is the no-over-accrual guard:
        an arbitrarily long idle still tops the bucket out at ``burst``, never higher.
        """
        now = self._now()
        elapsed = now - self._last_refill
        self._last_refill = now
        if elapsed <= 0:
            return
        self._tokens = min(float(self._burst), self._tokens + elapsed * self._rate)


__all__ = ["AdmitResult", "IngressDecision", "PerAdapterIngressGate"]
