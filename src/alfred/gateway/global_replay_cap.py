"""``GlobalReplayCap`` — aggregate resident-byte budget across all leg ReplayBuffers.

Spec B G6-4 / #288 (keystone K2). Each gateway leg owns its OWN
:class:`alfred.gateway.replay_buffer.ReplayBuffer` (per-leg soft cap + hard ceiling +
TTL). This coordinator bounds the SUM of every leg's resident un-acked bytes so the
total pre-DLP T1 retained in the always-up SETUID process is bounded *regardless of N
legs* (``[fleet perf-002]``) — a thing no per-leg cap can guarantee on its own.

The seam (K2): the leg's ``append`` path calls :meth:`reserve` with ``len(payload)``
BEFORE the buffer admits the bytes; every byte-reclaim path (``trim_to_ack``,
``evict_expired``, ``discard``, ``reset_for_new_epoch``, and the hard-ceiling-raise
rollback) calls :meth:`release` with the byte delta. The :class:`ReplayBuffer` class is
NOT modified — the reserve/release wrapping lives at the leg level (the call sites
compute the ``depth_bytes`` delta). The leg does the reserve/release in a
context-manager / ``finally`` so an exception between reserve and append cannot leak the
reservation (the budget-leak the architect, performance, and security reviews all flagged).

**Pure accountant — no I/O, no clock, no logging.** Mirrors the sibling pure machines
(:class:`ReplayBuffer`, :class:`alfred.gateway.ingress_gate.PerAdapterIngressGate`).
*Loudness is the wiring's job*: :meth:`reserve` returns ``False`` (refuse → the leg
back-pressures + writes the loud audit row), it does not log. The one fail-loud arm is
*misuse* — a negative amount, an over-release that would drive a leg negative, or a
release of a leg that never reserved — which raises :class:`GlobalReplayCapError`
(CLAUDE.md hard rule #7: budget corruption is never a silent clamp).

**Invariant (the budget-leak guard).** After ANY sequence of reserve/release/remove,
:attr:`total_bytes` equals the sum of every live leg's reserved bytes, and stays in
``[0, max_total_bytes]``. A failed (raising) op is atomic — it mutates nothing — so the
invariant holds even across a misuse.
"""

from __future__ import annotations

from typing import Final

from alfred.errors import AlfredError


class GlobalReplayCapError(AlfredError):
    """A fail-closed misuse of the global cap (CLAUDE.md hard rule #7).

    Raised on a non-positive ``max_total_bytes`` at construction, a negative reserve /
    release amount, an over-release that would drive a leg's accounting negative, or a
    release of a leg that never reserved. A refusal to admit (over-budget reserve) is NOT
    an error — it returns ``False`` so the leg can back-pressure.
    """


class GlobalReplayCap:
    """Tracks per-leg reserved bytes against an aggregate ceiling; pure + atomic."""

    def __init__(self, *, max_total_bytes: int) -> None:
        if max_total_bytes <= 0:
            raise GlobalReplayCapError(f"max_total_bytes must be positive: {max_total_bytes}")
        self._max_total_bytes: Final[int] = max_total_bytes
        self._total_bytes: int = 0
        self._per_leg: dict[str, int] = {}

    @property
    def total_bytes(self) -> int:
        """Sum of all legs' currently-reserved bytes (the aggregate measure)."""
        return self._total_bytes

    @property
    def max_total_bytes(self) -> int:
        """The configured aggregate ceiling (observability / docs)."""
        return self._max_total_bytes

    def leg_bytes(self, adapter_id: str) -> int:
        """Bytes currently reserved by ``adapter_id`` (0 if it never reserved)."""
        return self._per_leg.get(adapter_id, 0)

    def reserve(self, adapter_id: str, n_bytes: int) -> bool:
        """Try to reserve ``n_bytes`` for ``adapter_id``; ``True`` admitted, ``False`` refused.

        A reserve that would push :attr:`total_bytes` over ``max_total_bytes`` is REFUSED
        (returns ``False``) and accrues NOTHING — the leg then applies back-pressure + a
        loud audit row (never a silent drop). A negative amount is a fail-loud misuse.
        ``n_bytes == 0`` is a trivially-admitted no-op.
        """
        if n_bytes < 0:
            raise GlobalReplayCapError(f"reserve amount must be non-negative: {n_bytes}")
        if self._total_bytes + n_bytes > self._max_total_bytes:
            return False
        self._total_bytes += n_bytes
        self._per_leg[adapter_id] = self._per_leg.get(adapter_id, 0) + n_bytes
        return True

    def release(self, adapter_id: str, n_bytes: int) -> None:
        """Release ``n_bytes`` previously reserved by ``adapter_id`` back to the pool.

        A negative amount, a release of a leg that never reserved, or an over-release that
        would drive the leg's accounting negative is a fail-loud budget-corruption misuse
        (:class:`GlobalReplayCapError`) — NEVER a silent clamp to zero, which would hide a
        missed-reserve bug and slowly leak the aggregate budget. ``n_bytes == 0`` on a
        known leg is a no-op.
        """
        if n_bytes < 0:
            raise GlobalReplayCapError(f"release amount must be non-negative: {n_bytes}")
        current = self._per_leg.get(adapter_id)
        if current is None:
            raise GlobalReplayCapError(f"release of an unknown leg: {adapter_id!r}")
        if n_bytes > current:
            raise GlobalReplayCapError(
                f"release exceeds reserved for leg {adapter_id!r}: {n_bytes} > {current}"
            )
        self._per_leg[adapter_id] = current - n_bytes
        self._total_bytes -= n_bytes

    def remove_leg(self, adapter_id: str) -> int:
        """Drop ``adapter_id``'s accounting entry, freeing its budget; return bytes freed.

        The leg-teardown path (perf-L1): when a leg is reaped its per-leg entry is removed
        (so a churning fleet does not leak dict entries in G6-5) and any still-reserved
        bytes return to the global pool. An unknown leg is a 0-returning no-op.
        """
        freed = self._per_leg.pop(adapter_id, 0)
        self._total_bytes -= freed
        return freed


__all__ = ["GlobalReplayCap", "GlobalReplayCapError"]
