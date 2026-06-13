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


class DaemonUnavailableError(CommsMcpError):
    """Dialing the daemon's comms socket failed — no daemon is reachable.

    Raised by the foreground TUI co-host (``alfred_tui.cohost.run_cohosted``) when the
    ``dial`` itself raises an ``OSError`` family member (``FileNotFoundError`` — the
    socket inode is absent; ``ConnectionRefusedError`` — a stale inode with no
    listener). Wrapping ONLY the dial (not the whole co-host) keeps this typed
    condition distinct from a stray post-dial ``OSError`` (a PTY ioctl / broken render
    pipe), which must surface LOUD rather than be mislabelled "daemon required". The
    CLI (``_chat_main``) maps THIS error — and only this error — to the
    ``comms.tui.daemon_required_to_chat`` t() string + exit 3.
    """


class PromoterRequiredError(CommsMcpError):
    """An adapter kind with a non-empty required-classifier set got no promoter.

    M2 fail-closed guard. ``REQUIRED_CLASSIFIERS_BY_KIND`` for the inbound's
    adapter kind is non-empty (e.g. ``"discord"`` requires
    ``discord_sub_payloads``), so the host MUST promote sub-payloads host-side
    before the quarantined extract. A ``None`` promoter on that path would
    silently skip promotion and fall back to trusting the wire-asserted
    ``sub_payload_refs`` — exactly the untrusted-input-trust the classifier
    set exists to prevent. ``process_inbound_message`` audits and raises this
    rather than processing the message, so the misconfiguration fails closed.
    """


__all__ = [
    "CommsHandlerFailedError",
    "CommsMcpError",
    "DaemonUnavailableError",
    "InboundBurstDroppedError",
    "PromoterRequiredError",
    "UnknownAdapterKindError",
]
