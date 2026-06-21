"""``ReplayBuffer`` — pure un-acked inbound retention for the resume gateway.

Spec A G4a / ADR-0032 (#237). The always-up ``alfred-gateway`` holds the client
connection across a core restart; this buffer is where the operator's un-acked
**inbound** (client->core) frames live between the moment the gateway forwards them
and the moment the (possibly freshly-restarted) core durably acks them. On
reconnect (G4b-2b) the gateway captures the un-acked frames via
:meth:`unacked_frames`, calls :meth:`reset_for_new_epoch`, and re-sends them on
the fresh leg with FRESH per-connection seqs (``0, 1, …``); the core dedups on the
durable in-payload ``inbound_id`` (G0 ``commit_once`` on ``(adapter_id, inbound_id)``),
NOT on ``(leg, seq)``, so replay never double-executes across a restart.

**Seq is gateway-owned and PER-CONNECTION (G4b-2-pre/G4b-2a/G4b-2b wired).** The
gateway mints the client->core seq; that seq space resets to 0 on each core
handshake. The reconnect path calls :meth:`reset_for_new_epoch` to rebind the
monotonic floor for the fresh connection before the flush re-sends held frames with
fresh seqs. :meth:`discard` — the distinct shutdown / retry-exhaustion path — does
the same purge but does NOT reset the floor, so a late stale-stream frame arriving
after a discard is rejected loud (Security F1).

**Pure — no I/O, no clock, no logging.** Mirrors the sibling pure machines
:class:`~alfred.gateway.link_state.LinkStateMachine` and
:class:`~alfred.gateway._seq_tracker.BoundedSeqAckTracker`. Time is injected as an
explicit, monotonic ``now`` argument (the spec §7 fake-clock seam). **Loudness is
the G4b wiring's job:** this class never audits/logs; it surfaces signals
(:meth:`evict_expired` return value, :attr:`breaker_tripped`, the hard-ceiling
raise) the reconnect/relay layer polls to write the spec §6 loud audit rows.

**Trust posture (spec §6).** A **T1 carrier** of opaque, *pre-DLP* operator input
(payload-blind — never decodes a frame; T3 tagging stays in the core). Pinning that
input in the always-up process across a crash-loop is an exposure, so the cap
(``max_frames`` + ``max_bytes``) and ``ttl_seconds`` retention bound are **security**
properties, and every byte that leaves on a removal path is overwritten before its
reference is dropped.

**Bounded retention is a two-part contract.** On a soft-cap breach :meth:`append`
KEEPS the frame (the no-silent-drop guarantee) and trips :attr:`breaker_tripped`;
G4b enforces the bound by ceasing to drain the client socket. Post-breach growth is
bounded only by G4b's read-halt latency — the residual window this pure layer does
not close. As a backstop against a buggy G4b, :meth:`append` raises at a hard
ceiling (``_HARD_CAP_MULTIPLIER`` x each soft cap) so the process cannot be driven
to OOM (fail-closed, loud — never silent).

**Zeroing is best-effort.** We overwrite our own mutable ``bytearray`` body in place
on every removal. Python gives no crypto-erase guarantee; ``MADV_DONTDUMP`` /
core-dump suppression are G4b process-level mitigations, out of scope here. The
immutable ``bytes`` a caller passes to :meth:`append`, and those
:meth:`unacked_frames` returns (a flapping reconnect can mint many live copies at
once), are caller/wire-owned and not ours to zero — G4b's process hardening bounds
that exposure.

**No-silent-failure (CLAUDE.md hard rule #7).** TTL eviction returns the evicted
seqs (G4b audits each as input-loss); a non-monotonic/negative ``seq``, a
non-monotonic ``now``, a non-positive cap, and a hard-ceiling breach all raise
:class:`ReplayBufferError`. :meth:`trim_to_ack` is the one removal that is NOT
input-loss (it removes durably-acked frames) and so returns nothing — G4b must only
ever pass an epoch-validated cumulative ack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from alfred.errors import AlfredError

_DEFAULT_MAX_FRAMES: Final[int] = 4096
_DEFAULT_MAX_BYTES: Final[int] = 8 * 1024 * 1024
_DEFAULT_TTL_SECONDS: Final[float] = 300.0

# The soft cap (``max_frames``/``max_bytes``) is the back-pressure SIGNAL: a breach
# trips the breaker but keeps the frame (no silent drop). The hard ceiling is this
# multiple of the soft cap and is a fail-closed BACKSTOP: reaching it means G4b
# ignored the back-pressure signal (a bug/wedge), so ``append`` refuses loud rather
# than let the always-up security process grow to OOM. 2x leaves generous head-room
# for the in-flight frames between a breach and G4b halting its read loop.
_HARD_CAP_MULTIPLIER: Final[int] = 2


class ReplayBufferError(AlfredError):
    """A programming-error / fail-closed misuse of the buffer.

    Fail-loud (CLAUDE.md hard rule #7): a non-monotonic or negative ``seq``, a
    non-monotonic ``now``, a non-positive cap, or a hard-ceiling breach is never a
    silent no-op.
    """


@dataclass(frozen=True, slots=True)
class ReplayFrame:
    """A replayable un-acked frame: its gateway-owned per-direction seq + opaque payload.

    On reconnect the gateway re-mints FRESH per-connection seqs (starting at 0) when
    it replays held frames onto the new leg — ``seq`` here is the seq the frame carried
    on the ORIGINAL leg (used internally by the buffer; the relay assigns the fresh
    replay seq at send time). Cross-restart exactly-once is guaranteed by the durable
    in-payload ``inbound_id`` (G0 ``commit_once`` on ``(adapter_id, inbound_id)``), NOT
    by ``(leg, seq)``; ``seq`` is the per-connection per-direction wire counter.
    """

    seq: int
    payload: bytes


@dataclass(slots=True)
class _Retained:
    """One retained un-acked inbound frame.

    Mutable by design (unlike the frozen public :class:`ReplayFrame`): ``body`` is a
    MUTABLE copy of the opaque payload so it can be zeroed in place on removal, and
    the retention list is sliced in place on trim/evict. ``enqueued_at`` is the
    caller-supplied monotonic stamp the TTL reads.
    """

    seq: int
    body: bytearray
    enqueued_at: float


def _zero(body: bytearray) -> None:
    """Best-effort in-place overwrite of a retained body before its ref is dropped."""
    body[:] = b"\x00" * len(body)


class ReplayBuffer:
    """Pure FIFO retention of un-acked inbound frames; cap + TTL + breaker + zeroing."""

    def __init__(
        self,
        *,
        max_frames: int = _DEFAULT_MAX_FRAMES,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
    ) -> None:
        if max_frames <= 0 or max_bytes <= 0 or ttl_seconds <= 0:
            raise ReplayBufferError(
                "ReplayBuffer caps must be positive: "
                f"max_frames={max_frames} max_bytes={max_bytes} ttl_seconds={ttl_seconds}"
            )
        self._max_frames: Final[int] = max_frames
        self._max_bytes: Final[int] = max_bytes
        self._ttl_seconds: Final[float] = ttl_seconds
        self._hard_max_frames: Final[int] = max_frames * _HARD_CAP_MULTIPLIER
        self._hard_max_bytes: Final[int] = max_bytes * _HARD_CAP_MULTIPLIER
        self._retained: list[_Retained] = []
        self._depth_bytes: int = 0
        self._last_seq: int = -1
        self._last_now: float = float("-inf")
        self._breaker_tripped: bool = False

    @property
    def max_bytes(self) -> int:
        """The byte SOFT cap (the back-pressure breaker threshold), as a public accessor.

        L1 (Spec B G6-4 #288): ``process.py`` sizes the per-leg :class:`GlobalReplayCap`
        ceiling strictly above the buffer hard ceiling (PR2 invariant). It must read this
        public accessor rather than the private ``_max_bytes`` so the ceiling invariant does
        not depend on a private attribute. The HARD ceiling is ``_HARD_CAP_MULTIPLIER`` x this.
        """
        return self._max_bytes

    @property
    def depth_frames(self) -> int:
        """Number of un-acked frames currently retained."""
        return len(self._retained)

    @property
    def depth_bytes(self) -> int:
        """Sum of retained payload lengths (the byte-cap measure)."""
        return self._depth_bytes

    @property
    def breaker_tripped(self) -> bool:
        """``True`` once a soft cap was breached; cleared only by :meth:`discard`."""
        return self._breaker_tripped

    @property
    def cap_ratio(self) -> float:
        """Fullness as a fraction of the SOFT cap — ``max`` of the frame- and byte-ratios.

        ``1.0`` means a soft cap is exactly hit; ``> 1.0`` is the post-breach overshoot
        the breaker has already latched on (G4b's read-halt then bounds the growth). The
        gateway exports this as ``gateway_buffer_cap_ratio`` so an operator sees how close
        the always-up buffer is to back-pressure.
        """
        return max(self.depth_frames / self._max_frames, self._depth_bytes / self._max_bytes)

    def append(self, seq: int, payload: bytes, *, now: float) -> None:
        """FIFO-append a fresh un-acked inbound frame.

        ``seq`` is the gateway's per-direction monotonic counter and must be ``>= 0``
        and strictly greater than the previously appended seq; ``now`` must be ``>=``
        the previously appended ``now`` (a monotonic clock — the TTL prefix invariant
        depends on it). A violation is a programming error, raised loud. The payload
        is copied into a mutable ``bytearray`` we own (so we can zero it on removal)
        and stamped with ``now``.

        Soft cap: appending NEVER drops (spec §5). If it pushes depth past
        ``max_frames``/``max_bytes`` the frame is kept and :attr:`breaker_tripped` is
        set so G4b back-pressures the client read. Hard ceiling: if the append would
        push depth past ``_HARD_CAP_MULTIPLIER`` x either cap it raises
        :class:`ReplayBufferError` BEFORE storing — a fail-closed backstop against a
        G4b that ignored back-pressure, so the always-up process cannot OOM.
        """
        if seq < 0:
            raise ReplayBufferError(f"seq must be non-negative: {seq}")
        if seq <= self._last_seq:
            raise ReplayBufferError(f"seq must strictly increase: got {seq} after {self._last_seq}")
        if now < self._last_now:
            raise ReplayBufferError(f"now must be monotonic: got {now} after {self._last_now}")
        if (
            len(self._retained) + 1 > self._hard_max_frames
            or self._depth_bytes + len(payload) > self._hard_max_bytes
        ):
            raise ReplayBufferError(
                "ReplayBuffer hard ceiling breached — G4b is not honouring "
                f"back-pressure (frames={len(self._retained)}, bytes={self._depth_bytes})"
            )
        self._retained.append(_Retained(seq=seq, body=bytearray(payload), enqueued_at=now))
        self._depth_bytes += len(payload)
        self._last_seq = seq
        self._last_now = now
        if len(self._retained) > self._max_frames or self._depth_bytes > self._max_bytes:
            self._breaker_tripped = True

    def trim_to_ack(self, cumulative_ack: int) -> None:
        """Remove + zero every retained frame with ``seq <= cumulative_ack``.

        ``cumulative_ack`` is the core's epoch-validated durable contiguous-intake
        high-water (spec §4). Because retention is FIFO-ascending in seq, the acked
        frames are a leading prefix. ``-1`` / below-first-seq is a no-op; at/above the
        last seq empties. Does NOT clear :attr:`breaker_tripped`.

        This is the ONE removal that is not input-loss (the frames are durably
        committed), so it returns nothing. Security precondition (G4b's obligation):
        ``cumulative_ack`` must come only from an epoch-validated ack — a spoofed ack
        would zero un-committed input, and the pure buffer cannot tell them apart.
        """
        removed = 0
        for entry in self._retained:
            if entry.seq > cumulative_ack:
                break
            self._depth_bytes -= len(entry.body)
            _zero(entry.body)
            removed += 1
        if removed:
            del self._retained[:removed]

    def evict_expired(self, *, now: float) -> tuple[int, ...]:
        """Remove + zero frames older than ``ttl_seconds``; return the evicted seqs.

        A frame is expired when ``now - enqueued_at > ttl_seconds`` (exactly-at-TTL
        retained). ``now`` must be monotonic — like :meth:`append`, a regressed ``now``
        raises :class:`ReplayBufferError` rather than silently under-evicting (a
        backwards clock would compute ages too small and retain expired pre-DLP input
        past its TTL, weakening the spec §6 bound — CLAUDE.md hard rule #7). The
        observed time advances the shared monotonic floor, so a later append/evict
        cannot present an earlier time. Because the floor is monotonic, the expired
        frames are a leading FIFO prefix. Evicting un-acked input is deliberate
        security-over-liveness loss (pre-DLP input cannot be pinned across an unbounded
        crash-loop), so it is OBSERVABLE — the returned seqs let G4b write the spec §6
        loud audit row per dropped frame. Does NOT clear :attr:`breaker_tripped`.
        """
        if now < self._last_now:
            raise ReplayBufferError(f"now must be monotonic: got {now} after {self._last_now}")
        self._last_now = now
        evicted: list[int] = []
        for entry in self._retained:
            if now - entry.enqueued_at <= self._ttl_seconds:
                break
            self._depth_bytes -= len(entry.body)
            _zero(entry.body)
            evicted.append(entry.seq)
        if evicted:
            del self._retained[: len(evicted)]
        return tuple(evicted)

    def unacked_frames(self) -> tuple[ReplayFrame, ...]:
        """Return the retained un-acked frames as :class:`ReplayFrame`, FIFO order.

        The G4b-2b reconnect path captures the un-acked inbound remainder by calling
        this BEFORE :meth:`reset_for_new_epoch` (spec §5 step 3). The relay then
        re-sends each frame on the fresh leg with FRESH per-connection seqs (``0, 1,
        …``); the core dedups on the in-payload ``inbound_id`` (G0 ``commit_once`` on
        ``(adapter_id, inbound_id)``), not on the wire ``(leg, seq)``. Read-only:
        frames stay retained until the NEW core acks them. G4b call contract:
        ``trim_to_ack(core_durable_high_water)`` FIRST, then this returns exactly the
        un-acked remainder. Each returned ``payload`` is a fresh immutable copy of a
        retained body.
        """
        return tuple(
            ReplayFrame(seq=entry.seq, payload=bytes(entry.body)) for entry in self._retained
        )

    def _purge(self) -> None:
        """Zero every retained body, empty the queue, reset depth + clear the breaker.

        The shared core of :meth:`discard` and :meth:`reset_for_new_epoch` (the two
        differ ONLY in whether they also rebind the monotonic seq/now floor). Does NOT
        touch the floor — a caller that needs the per-connection reset adds it.
        """
        for entry in self._retained:
            _zero(entry.body)
        self._retained.clear()
        self._depth_bytes = 0
        self._breaker_tripped = False

    def discard(self) -> None:
        """Remove + zero EVERYTHING and clear the breaker latch.

        Called by G4b on clean gateway shutdown and when the reconnect retry-window
        is exhausted (resume gave up — the max-retry-window cap the pure buffer cannot
        observe). Does NOT reset the monotonic seq/now floor: not resetting here means a
        late stale-stream frame after a discard is rejected loud rather than silently
        admitted (Security F1). The per-connection seq-space reset (``_last_seq = -1``)
        is the distinct :meth:`reset_for_new_epoch` path the reconnect handshake uses;
        on the same connection the floor still correctly rejects stale frames whose seq
        is at or below the pre-discard high-water.
        """
        self._purge()

    def reset_for_new_epoch(self) -> None:
        """Zero + empty + clear the breaker AND reset the monotonic seq/now floor.

        The per-connection-reset path the reconnect handshake uses (G4b-2-pre/G4b-2a):
        the client->core seq space is per-connection (it restarts at 0 each handshake),
        so unlike :meth:`discard` (the shutdown/retry-exhaustion path, which PRESERVES
        the floor — a stale post-discard frame is rejected loud) this rebinds the floor
        for the fresh connection. Zeroes every retained body first (the spec §6 pre-DLP
        bound).
        """
        self._purge()
        self._last_seq = -1
        self._last_now = float("-inf")


__all__ = ["ReplayBuffer", "ReplayBufferError", "ReplayFrame"]
