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
    """Dialing the comms socket failed — no peer is reachable on it.

    Raised by the foreground TUI co-host (``alfred_tui.cohost.run_cohosted``) when the
    ``dial`` itself raises an ``OSError`` family member (``FileNotFoundError`` — the
    socket inode is absent; ``ConnectionRefusedError`` — a stale inode with no
    listener). Spec A G5 (#237) re-points the chat client off the daemon's
    ``comms-tui.sock`` to the GATEWAY's ``comms-gateway.sock`` (no dual-mode), so the
    unreachable peer is now the gateway; the name is retained as the shared typed
    dial-failure condition. Wrapping ONLY the dial (not the whole co-host) keeps this
    typed condition distinct from a stray post-dial ``OSError`` (a PTY ioctl / broken
    render pipe), which must surface LOUD rather than be mislabelled "gateway required".
    The CLI (``_chat_main``) maps THIS error — and only this error — to the
    ``comms.tui.gateway_required_to_chat`` t() string + exit 3.
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


class InboundReparseError(CommsMcpError):
    """A gateway-forwarded inbound failed the core-side re-parse (G6-7-1, #309).

    Base for the two loud refusals
    :func:`alfred.comms_mcp.inbound_reparse.reparse_forwarded_inbound` raises. Both
    are FAIL-LOUD (hard rule #7) — never a silent drop. The disposition the core
    attaches to each (the §3.3 K4-style forge refusal vs the §3.3/ARCH-309-3
    ack-to-drain on a malformed body) is wired in the receive slice (G6-7-4); this
    typed hierarchy is the data-layer contract those dispositions discriminate on.
    Carries NO raw T3 body on the exception (spec §3.3 — no payload in error attrs).
    """


class ForwardedInboundAuditWriteError(CommsMcpError):
    """A signed-audit write FAILED on the gateway-forwarded receive path (G6-7-4, #309).

    The typed marker the forwarded-inbound receive seam raises when an
    ``append_schema`` for a terminal-drop / dispatched-edge audit row fails to write.
    It mirrors :class:`alfred.comms_mcp.adapter_status_observer.AdapterStatusAuditWriteError`:
    the failure is wrapped in this DISTINCT marker AT THE WRITE SITE (the receiver's
    ``_audit_drop`` and ``inbound.py``'s forwarded-path audit emits), so the
    disposition's ``_route_forwarded_inbound`` can recognise it past its blanket
    catch-and-continue and ESCALATE loud (``log.error`` + restart request) — a failed
    signed-audit write at this T3 trust seam is non-skippable (CLAUDE.md hard rules
    #5/#7). It MUST escalate (restart), NEVER replay: a raw ``SQLAlchemyError`` on the
    forwarded path also comes from non-audit sources (``has_committed`` / ``commit_once``
    / ``orchestrator.dispatch``) whose designed recovery is LEG REPLAY, so the
    audit-write fault MUST be type-discriminated from those. Carries NO raw T3 body
    (the cause is the bare backend error).
    """


class InboundEnvelopeBodyMismatchError(InboundReparseError):
    """The envelope ``adapter_id`` did not equal the body-derived ``adapter_id``.

    The F3 forgery mitigation's data-layer half (spec §3.3): the body stays the
    sole G0 authority, and an envelope whose routing id disagrees with the body it
    wraps is a forged-body/valid-leg mismatch — refused loud (the core maps this to
    a K4-style refusal + signed audit row in G6-7-4), never default-routed. Carries
    only the two closed-vocab adapter_id KINDS, never the body.
    """


class InboundBodyMalformedError(InboundReparseError):
    """The opaque forwarded body could not be re-parsed into an inbound.

    The core re-parses a body the gateway never validated; a decode failure
    (non-UTF-8 / non-JSON / not a top-level object) or an
    :class:`InboundMessageNotification` validation failure raises this. In G6-7-4
    the core maps it to a loud bounded-field audit drop that ACKs the leg frame to
    drain it (ARCH-309-3 — no infinite replay). Carries NO raw body (spec §3.3).
    """


__all__ = [
    "CommsHandlerFailedError",
    "CommsMcpError",
    "DaemonUnavailableError",
    "ForwardedInboundAuditWriteError",
    "InboundBodyMalformedError",
    "InboundBurstDroppedError",
    "InboundEnvelopeBodyMismatchError",
    "InboundReparseError",
    "PromoterRequiredError",
    "UnknownAdapterKindError",
]
