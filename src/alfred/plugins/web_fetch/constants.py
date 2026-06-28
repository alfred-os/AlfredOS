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


__all__ = ["_DEFAULT_ACTION_DEADLINE_SECONDS"]
