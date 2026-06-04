"""Shared host-side constants for the ``web.fetch`` plugin (issue #147 / CR-CLI).

Centralises the default response body cap so the host-side
:class:`alfred.plugins.web_fetch.dispatch_params.WebFetchDispatchParams`
model and the host-side
:mod:`alfred.plugins.web_fetch.fetch_dispatcher` agree without
duplicating the literal. CodeRabbit CR-CLI flagged the dual definition
across those two modules — co-locating here removes the drift hazard.

NOT shared with the plugin subprocess at
``plugins/alfred_web_fetch/web_fetch_plugin.py``: per the plugin-process-
isolation contract the subprocess holds its own constant as the
secondary defence (the subprocess must remain self-contained — if the
host wire format ever lies about the cap, the plugin's own constant is
the authority). The host-side and subprocess-side constants are
intentionally kept in sync by code review, not by import.
"""

from __future__ import annotations

from typing import Final

_DEFAULT_SIZE_LIMIT_BYTES: Final[int] = 5 * 1024 * 1024


__all__ = ["_DEFAULT_SIZE_LIMIT_BYTES"]
