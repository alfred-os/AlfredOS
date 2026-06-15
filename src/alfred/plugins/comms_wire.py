"""Shared comms-wire constants — the per-frame DoS bound + protocol-error type.

Spec A G2 / ADR-0032 (#237). A LEAF module (depends only on
:mod:`alfred.errors`) so the comms transports AND the seq/ack codec
(:mod:`alfred.plugins.comms_seq_codec`) can all import the bound + the
loud-failure type from ONE place. Before G2 these lived in
``comms_stdio_transport``; the codec needs them and both transports import the
codec, so leaving them in the transport would close a bidirectional import
cycle (architect F6). They move here UNCHANGED; the transports re-export them so
no existing importer churns.
"""

from __future__ import annotations

from typing import Final

from alfred.errors import AlfredError

# Mirrors :data:`alfred.plugins.stdio_transport._MAX_INBOUND_FRAME_BYTES` (10MB):
# a plugin that emits a single line larger than this is misbehaving, and the host
# refuses the frame rather than let a "claim 4GB on one line" wedge the loop. The
# child's stdout ``StreamReader`` limit is set to this value at spawn so the read
# itself fails fast instead of buffering unboundedly.
_MAX_COMMS_LINE_BYTES: Final[int] = 10 * 1024 * 1024


class CommsProtocolError(AlfredError):
    """The comms wire produced a malformed or over-bound frame.

    Mirrors :class:`alfred.plugins.stdio_transport.PluginProtocolError`: a
    wire-level violation the transport raises BEFORE the frame can reach the
    session dispatcher. Covers an over-:data:`_MAX_COMMS_LINE_BYTES` line,
    non-JSON bytes, and a JSON value that is not a top-level object. The raw
    bytes are never carried on the exception (spec §5.6 — no T3 in error
    attributes).
    """


class CommsPeerAuthError(CommsProtocolError):
    """A dialed/accepted comms peer's uid did not match ours.

    Raised when the socket peer-auth refuses a connection: a different-uid peer
    beat a legitimate dial-in to a 0600 socket (a stale-socket race), or a
    wider-perm misconfig left the socket inode owned by another uid. A
    :class:`CommsProtocolError` subclass so the runner's existing malformed-wire
    arm routes it uniformly. Carries NO T3 — only the local uids involved
    (spec §5.6).
    """


__all__ = [
    "_MAX_COMMS_LINE_BYTES",
    "CommsPeerAuthError",
    "CommsProtocolError",
]
