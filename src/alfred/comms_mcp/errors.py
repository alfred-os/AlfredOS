"""Comms-MCP error hierarchy (PR-S4-8, #152).

Rooted at :class:`CommsMcpError` (an :class:`alfred.errors.AlfredError`) so the
CLI / orchestrator top-level dispatch can catch comms-MCP failures uniformly
without swallowing unrelated exceptions.
"""

from __future__ import annotations

from alfred.errors import AlfredError


class CommsMcpError(AlfredError):
    """Base for every comms-MCP error."""


class UnknownAdapterKindError(CommsMcpError):
    """An adapter announced a kind the host build does not recognise.

    New kinds arrive only by adding to
    :data:`alfred.comms_mcp.protocol.adapter_kind` (PR-S4-9/10), never by an
    unvalidated wire string.
    """


class InboundBurstDroppedError(CommsMcpError):
    """An inbound message was hard-dropped after the burst bucket stayed empty.

    Raised at call sites that treat a :class:`alfred.orchestrator.burst_limiter.Dropped`
    as an error rather than a silent return (the inbound entrypoint itself
    returns early + audits; this exception is for callers that need the loud
    variant).
    """


class CommsHandlerFailedError(CommsMcpError):
    """A notification handler raised while processing a plugin notification.

    The dispatcher (Wave 3 ``_on_post_handshake_method`` extension) emits
    ``COMMS_HANDLER_FAILED_FIELDS`` and re-raises; this typed error is the
    closed-vocabulary carrier for that failure.
    """


__all__ = [
    "CommsHandlerFailedError",
    "CommsMcpError",
    "InboundBurstDroppedError",
    "UnknownAdapterKindError",
]
