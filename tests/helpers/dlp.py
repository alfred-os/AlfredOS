"""Shared identity OutboundDlp for tests (DRY — was copy-pasted across ~10 files).

``ProposalContext.outbound_dlp`` is a REQUIRED field (PR-S4-2 / #173); every
dispatch-loop / supervisor / state test that builds a ProposalContext needs a
scanner to satisfy it. The default is an IDENTITY scanner — broker + sink are
no-ops — so the test exercises the wiring without a redaction side effect
(``dlp_redactions_count`` stays 0). Tests that need a REDACTING scanner build
their own with a real api-key regex; this helper is only the no-op baseline.
"""

from __future__ import annotations

from collections.abc import Mapping

from alfred.security.dlp import OutboundDlp


def identity_outbound_dlp() -> OutboundDlp:
    """Return an :class:`OutboundDlp` whose broker + sink are no-ops.

    The broker returns text unchanged (clean scan, count 0); the audit sink
    discards. Satisfies the required ``ProposalContext.outbound_dlp`` field
    without altering the scanned payload.
    """

    class _IdentityBroker:
        def redact(self, text: str) -> str:
            return text

    def _sink(*, event: str, subject: Mapping[str, object]) -> None:
        return None

    return OutboundDlp(broker=_IdentityBroker(), audit=_sink)
