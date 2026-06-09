"""Comms-MCP host-side foundations (PR-S4-8, #152).

Wave 1 shipped the wire-format module (:mod:`alfred.comms_mcp.protocol`) and the
host-owned classifier registry (:mod:`alfred.comms_mcp.classifier_registry`).
Wave 2 adds:

* :mod:`alfred.comms_mcp.inbound` — the ``process_inbound_message`` entrypoint;
* :mod:`alfred.comms_mcp.inbound_scanner` — :class:`InboundContentScanner`;
* :mod:`alfred.comms_mcp.handlers` — the four notification handler protocols +
  concrete classes;
* :mod:`alfred.comms_mcp.errors` — the :class:`CommsMcpError` hierarchy.

:mod:`alfred.comms_mcp.hookpoints` is intentionally NOT re-exported here: its
module-bottom ``declare_hookpoints()`` registers against the process-singleton
registry at import time, so it is imported explicitly by the host bootstrap (and
by the drift-detector sync test) rather than as a side-effect of importing the
package.

Path note: deliberately ``comms_mcp``, not ``comms`` — the legacy
``alfred.comms`` package is dormant through this PR (spec §8.8).
"""

from alfred.comms_mcp import (
    classifier_registry,
    errors,
    handlers,
    inbound,
    inbound_scanner,
    observability,
    protocol,
)

__all__ = [
    "classifier_registry",
    "errors",
    "handlers",
    "inbound",
    "inbound_scanner",
    "observability",
    "protocol",
]
