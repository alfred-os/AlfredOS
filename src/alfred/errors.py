"""Root of the AlfredOS error hierarchy.

Subsystem-specific error classes inherit from :class:`AlfredError` so the CLI
top-level dispatch (and orchestrator ``except`` arms in PR B) can catch them
uniformly without swallowing unrelated exceptions.
"""

from __future__ import annotations


class AlfredError(Exception):
    """Base for AlfredOS errors."""
