"""Shared host-side constants for the ``web.fetch`` plugin (issue #147 / CR-CLI).

Centralises the per-action quarantine-extract deadline so the re-homed
:mod:`alfred.plugins.web_fetch.fetch_dispatcher` — which wraps the
``extractor.handle`` call in ``asyncio.timeout(action_deadline_seconds)`` —
and the live ``ContentStore`` TTL formula share the literal without either
module importing the other.

``_DEFAULT_SIZE_LIMIT_BYTES`` was removed in G7-2.5 Task 8: the
``WebFetchDispatchParams`` model it served was deleted when the subprocess
wire-shape path was retired.
"""

from __future__ import annotations

from typing import Final

# G7-2.5 Task 6 (plan-review CORE-1): the per-action quarantine-extract deadline
# (spec §7a). Relocated here from ``content_store.py`` so the re-homed
# :mod:`alfred.plugins.web_fetch.fetch_dispatcher` — which now wraps the
# ``extractor.handle`` call in ``asyncio.timeout(action_deadline_seconds)`` —
# and the live ``ContentStore`` TTL formula share the literal without either
# module importing the other. ``content_store.py`` imports it from here.
_DEFAULT_ACTION_DEADLINE_SECONDS: Final[int] = 30

# #339 PR4a (blocker 1 / #347): the per-user concurrency-reservation self-heal TTL.
# G7-2.5 fused fetch+extract, so a reservation is held only for one dispatch —
# bounded by ``_DEFAULT_ACTION_DEADLINE_SECONDS`` (30s). The dispatcher releases the
# slot in a ``finally`` on every exit path; this TTL is a BACKSTOP so a leaked slot
# (a release() that no-ops on a Redis transient) self-frees via passive
# ``ZREMRANGEBYSCORE`` eviction. Comfortably above the action deadline so a
# slow-but-live fetch is never evicted mid-flight while still counting.
_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS: Final[int] = 120

# #339 PR4b-audit (#347 blocker 2 / FIX-1): the bound on the POST-timeout ledger
# read the dispatcher performs to classify an action-deadline overrun as
# in-doubt. That read is CORRELATED with the timeout (the same DB stress that
# blew the action deadline can also make the ledger slow) — bounding it stops a
# slow/hung ledger from extending the already-breached deadline or holding the
# handle_cap slot open any longer than necessary. Deliberately short (a single
# indexed point-read, not a fetch) and independent of
# ``_DEFAULT_ACTION_DEADLINE_SECONDS``.
_LEDGER_READ_TIMEOUT_SECONDS: Final[float] = 5.0


__all__ = [
    "_DEFAULT_ACTION_DEADLINE_SECONDS",
    "_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS",
    "_LEDGER_READ_TIMEOUT_SECONDS",
]
