"""Shared host-side constants for the ``web.fetch`` plugin (issue #147 / CR-CLI).

Centralises the default response body cap so the host-side
:class:`alfred.plugins.web_fetch.dispatch_params.WebFetchDispatchParams`
model and the host-side
:mod:`alfred.plugins.web_fetch.fetch_dispatcher` agree without
duplicating the literal. CodeRabbit CR-CLI flagged the dual definition
across those two modules — co-locating here removes the drift hazard.

The subprocess at ``plugins/alfred_web_fetch/web_fetch_plugin.py`` held
its own copy of this constant (plugin-process-isolation contract: the
subprocess was self-contained). That subprocess was deleted in G7-2.5
Task 7; this constant now exclusively serves the host-side dispatcher.
"""

from __future__ import annotations

from typing import Final

_DEFAULT_SIZE_LIMIT_BYTES: Final[int] = 5 * 1024 * 1024

# G7-2.5 Task 6 (plan-review CORE-1): the per-action quarantine-extract deadline
# (spec §7a). Relocated here from ``content_store.py`` so the re-homed
# :mod:`alfred.plugins.web_fetch.fetch_dispatcher` — which now wraps the
# ``extractor.handle`` call in ``asyncio.timeout(action_deadline_seconds)`` —
# and the live ``ContentStore`` TTL formula share the literal without either
# module importing the other. ``content_store.py`` imports it from here.
_DEFAULT_ACTION_DEADLINE_SECONDS: Final[int] = 30


__all__ = ["_DEFAULT_ACTION_DEADLINE_SECONDS", "_DEFAULT_SIZE_LIMIT_BYTES"]
