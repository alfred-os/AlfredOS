"""Bump-on-mutate version counter for the identity layer.

:class:`IdentityVersionCounter` is the cross-thread synchronisation
primitive that lets the in-process identity LRU (T11) and the per-user
:class:`BudgetGuard` (PR B) detect that a mutation happened without
re-querying the database on every access. Mutators on
:class:`IdentityResolver` (``add``/``bind``/``unbind``/``remove``/``set``)
call :meth:`bump`; readers compare their cached version against
:meth:`current` and invalidate when it has advanced.

The counter is pure in-process. The cross-process invalidation path —
PG ``LISTEN/NOTIFY`` delivered by :class:`IdentityListener` (T12) — is
what calls :meth:`bump` on this counter from the listener task. That
task may run on a different loop-thread than the mutator that triggered
the original ``NOTIFY``, so :meth:`bump` and :meth:`current` are guarded
by a :class:`threading.Lock`.

The lock is the cheap kind — a counter increment under the GIL plus a
tiny critical section. It exists for correctness across threads, not for
contention shaping. ``__slots__`` is set to keep the per-counter
footprint to the lock and a single integer, since one counter is
allocated per ``BudgetGuard`` and per ``IdentityResolver`` instance.
"""

from __future__ import annotations

import threading


class IdentityVersionCounter:
    """Monotonic counter, thread-safe, starts at zero.

    The contract:

    * ``current()`` starts at ``0`` and only ever returns values produced
      by previous ``bump()`` calls (i.e. the count of bumps so far).
    * ``bump()`` advances ``current()`` by exactly one, atomically with
      respect to concurrent ``bump()`` / ``current()`` callers.
    * The counter never decreases and never wraps. ``int`` is unbounded
      in Python; we will run out of process memory long before we run
      out of versions.
    """

    __slots__ = ("_lock", "_value")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value = 0

    def bump(self) -> None:
        """Atomically increment the counter by one."""
        with self._lock:
            self._value += 1

    def current(self) -> int:
        """Return the current version. Zero until the first ``bump()``."""
        with self._lock:
            return self._value
