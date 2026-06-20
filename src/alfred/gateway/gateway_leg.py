"""``GatewayLeg`` — the per-adapter owning object (Spec B G6-4 / #288, keystone K1).

Before G6-4 the gateway had ONE leg (the TUI dial-in), and
:meth:`alfred.gateway.core_link.GatewayCoreLink.relay_to_core` owned the single
client->core seq, the single ReplayBuffer, and the breaker feed inline. The G6-4 spec —
"per-leg buffer keyed on adapter_id + a fair scheduler over one writer" — does not map
onto that 1:1 shape. K1 introduces this owning object: each leg owns

* its ``adapter_id`` (the gateway-chosen, bounded, spawn-known routing/label value);
* its OWN :class:`alfred.gateway.replay_buffer.ReplayBuffer` (the class is reused verbatim
  — retention / zeroing / caps unchanged — one instance per leg);
* its per-leg client->core seq counter (per-connection: reset on each epoch);
* the breaker latch + read-halt back-pressure gate (re-exposed from the buffer);
* its :class:`alfred.gateway.ingress_gate.PerAdapterIngressGate` (admission control);
* a bounded send queue (the scheduler's per-leg queue — held by the scheduler, Task 5).

**Seq mint + buffer append happen at DRAIN time (K1).** :meth:`record_for_send` is what
the scheduler calls as it drains ONE unit off this leg's queue onto the single physical
``core_link`` writer: it reserves the global cap, mints the next per-leg seq, appends to
the buffer, and returns the seq. Round-robin only chooses WHICH leg to drain; it never
reorders within a leg, so the per-leg wire seq stays strictly monotone.

**Global-cap reserve/release with NO budget leak (K2).** Every byte that enters the
buffer is :meth:`GlobalReplayCap.reserve`-d first (a refusal is a loud fail-closed
:class:`ReplayBufferError` → the leg back-pressures, never a silent drop); every
byte-reclaim path (:meth:`trim_to_ack`, :meth:`evict_expired`, :meth:`discard`,
:meth:`reset_for_new_epoch`) computes the ``depth_bytes`` delta across the unmodified
buffer op and releases exactly that much. The append path reserves, then appends in a
``try`` that releases the reservation if the buffer's hard-ceiling raise fires — so a
reserve-then-append-raises sequence cannot leak the reservation. The invariant
``global_cap.leg_bytes(adapter_id) == self.depth_bytes`` holds after every op.

**Payload-blind (CLAUDE.md hard rule #5).** The leg keys only on ``adapter_id`` + byte
counts; it never parses or logs a body. **Pure-ish:** it touches the per-adapter
prometheus gauges (refreshing ONLY this leg's series, perf-H3) but does no socket I/O —
the actual send is the scheduler's call to ``core_link.write_leg_unit``.
"""

from __future__ import annotations

from collections.abc import Callable

from alfred.gateway.adapter_metrics import (
    ADAPTER_BUFFER_DEPTH_BYTES,
    ADAPTER_BUFFER_DEPTH_FRAMES,
)
from alfred.gateway.global_replay_cap import GlobalReplayCap
from alfred.gateway.ingress_audit import touch_ingress_series
from alfred.gateway.ingress_gate import AdmitResult, PerAdapterIngressGate
from alfred.gateway.replay_buffer import ReplayBuffer, ReplayBufferError


class GatewayLeg:
    """One gateway leg: its buffer, ingress gate, per-leg seq, breaker, and cap accounting."""

    def __init__(
        self,
        *,
        adapter_id: str,
        buffer: ReplayBuffer,
        ingress_gate: PerAdapterIngressGate,
        global_cap: GlobalReplayCap,
        now: Callable[[], float],
    ) -> None:
        self._adapter_id = adapter_id
        self._buffer = buffer
        self._ingress_gate = ingress_gate
        self._global_cap = global_cap
        self._now = now
        # The per-leg client->core send seq. Per-connection: reset to 0 each epoch so the
        # first relayed frame on a fresh core leg carries wire seq 0 (resume correctness).
        self._send_seq = 0
        # Materialise the per-adapter series at construction (F8) so a scrape sees the leg
        # at 0 before its first frame — both the buffer-depth gauges and the throttle counter.
        self._refresh_buffer_metrics()
        touch_ingress_series(adapter_id)

    @property
    def adapter_id(self) -> str:
        """The gateway-chosen adapter id (routing key + sole metric label)."""
        return self._adapter_id

    @property
    def depth_frames(self) -> int:
        """Un-acked frames retained in this leg's buffer."""
        return self._buffer.depth_frames

    @property
    def depth_bytes(self) -> int:
        """Resident un-acked bytes in this leg's buffer (the cap-accounting measure)."""
        return self._buffer.depth_bytes

    @property
    def cap_ratio(self) -> float:
        """This leg's buffer fullness as a fraction of its soft cap (audit scalar)."""
        return self._buffer.cap_ratio

    @property
    def breaker_tripped(self) -> bool:
        """``True`` once this leg's buffer soft cap was breached (back-pressure signal)."""
        return self._buffer.breaker_tripped

    @property
    def inflight_count(self) -> int:
        """In-flight ingress slots held by this leg (audit scalar)."""
        return self._ingress_gate.inflight_count

    @property
    def last_seq(self) -> int:
        """The highest per-leg send seq minted so far (``-1`` before the first)."""
        return self._send_seq - 1

    def try_admit(self, *, frame_bytes: int) -> AdmitResult:
        """Delegate admission to this leg's ingress gate (payload-blind, size only)."""
        return self._ingress_gate.try_admit(frame_bytes=frame_bytes)

    def release_admit(self, token: int) -> None:
        """Release an in-flight ingress slot (the frame completed its core round-trip)."""
        self._ingress_gate.release(token)

    def evict_stalled_admits(self) -> tuple[int, ...]:
        """Reclaim ingress slots held past the TTL (the periodic-sweep / wedge guard)."""
        return self._ingress_gate.evict_stalled()

    def record_for_send(self, payload: bytes) -> int:
        """Reserve cap + mint the next per-leg seq + append to the buffer; return the seq.

        Called by the scheduler at DRAIN time (K1). Reserves the global cap for
        ``len(payload)`` BEFORE the append; a refusal is a loud fail-closed
        :class:`ReplayBufferError` (the leg back-pressures — never a silent drop). The
        append runs in a ``try`` that releases the reservation if the buffer's hard-ceiling
        raise fires, so a reserve-then-raise cannot leak the budget (K2). The seq is minted
        BEFORE the append (so a hard-ceiling raise still advances the seq exactly as the
        old ``relay_to_core`` did — the wire seq is the single source of truth a buffered
        frame keys on).
        """
        n = len(payload)
        if not self._global_cap.reserve(self._adapter_id, n):
            raise ReplayBufferError(
                f"global replay cap full; refusing append for leg {self._adapter_id!r} "
                f"({n} bytes over budget)"
            )
        seq = self._send_seq
        self._send_seq += 1
        try:
            self._buffer.append(seq, payload, now=self._now())
        except ReplayBufferError:
            # The hard-ceiling backstop fired AFTER we reserved — release the reservation
            # so the cap does not leak (K2 (a)), then re-raise the loud fail-closed signal.
            self._global_cap.release(self._adapter_id, n)
            raise
        self._refresh_buffer_metrics()
        return seq

    def trim_to_ack(self, cumulative_ack: int) -> None:
        """Remove durably-acked frames; release their bytes back to the global cap (K2)."""
        self._reclaim(lambda: self._buffer.trim_to_ack(cumulative_ack))

    def evict_expired(self) -> tuple[int, ...]:
        """Evict TTL-expired frames; release their bytes; return the evicted seqs (K2)."""
        evicted: tuple[int, ...] = ()

        def _op() -> None:
            nonlocal evicted
            evicted = self._buffer.evict_expired(now=self._now())

        self._reclaim(_op)
        return evicted

    def discard(self) -> None:
        """Zero + empty the buffer (shutdown / retry-exhaustion); release all bytes (K2)."""
        self._reclaim(self._buffer.discard)

    def reset_for_new_epoch(self) -> None:
        """Per-connection reset: zero + empty + rebind the seq floor; release bytes (K2)."""

        def _op() -> None:
            self._buffer.reset_for_new_epoch()
            self._send_seq = 0

        self._reclaim(_op)

    def unacked_frames(self) -> tuple[tuple[int, bytes], ...]:
        """The un-acked remainder as ``(seq, payload)`` pairs (the reconnect-capture seam)."""
        return tuple((f.seq, f.payload) for f in self._buffer.unacked_frames())

    def teardown(self) -> None:
        """Reap the leg: discard the buffer + drop the global-cap entry (perf-L1).

        Zeroes the pre-DLP bytes (security) and removes this leg's per-leg cap accounting
        entry so a churning fleet (G6-5) does not leak dict entries. Idempotent.
        """
        self._buffer.discard()
        self._global_cap.remove_leg(self._adapter_id)
        self._refresh_buffer_metrics()

    def _reclaim(self, op: Callable[[], None]) -> None:
        """Run a byte-removing buffer ``op`` and release the freed bytes to the cap (K2).

        Computes the ``depth_bytes`` delta across the unmodified buffer op (so the
        ReplayBuffer class stays untouched) and releases exactly that many bytes from the
        global cap, then refreshes this leg's depth gauges. The delta is always ``>= 0``
        (these ops only remove bytes), so the cap release is well-formed.
        """
        before = self._buffer.depth_bytes
        op()
        freed = before - self._buffer.depth_bytes
        if freed:
            self._global_cap.release(self._adapter_id, freed)
        self._refresh_buffer_metrics()

    def _refresh_buffer_metrics(self) -> None:
        """Push ONLY this leg's buffer depth onto its ``{adapter}`` gauges (perf-H3)."""
        ADAPTER_BUFFER_DEPTH_FRAMES.labels(adapter=self._adapter_id).set(self._buffer.depth_frames)
        ADAPTER_BUFFER_DEPTH_BYTES.labels(adapter=self._adapter_id).set(self._buffer.depth_bytes)


__all__ = ["GatewayLeg"]
