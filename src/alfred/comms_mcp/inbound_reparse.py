"""Pure core-side re-parse of a gateway-forwarded inbound (Spec B G6-7-1, #309).

The data-layer half of the gateway->core inbound bridge (ADR-0039 option 1). The
gateway forwards a hosted adapter child's ``inbound.message`` as an opaque body
wrapped in a :class:`~alfred.comms_mcp.protocol.GatewayAdapterInboundEnvelope`
WITHOUT parsing the body (hard rule #5). This module is where the CORE — the
trusted boundary — turns that opaque body back into the UNCHANGED
:class:`~alfred.comms_mcp.protocol.InboundMessageNotification` and enforces the
F3 mitigation's data-layer half: the body-derived ``adapter_id`` MUST equal the
envelope ``adapter_id`` (spec §3.3). The body stays the sole G0 authority; the
envelope id is the gateway's spawn-binding routing key (SEC-309-1), and equality
makes a forged-body/valid-leg frame a loud refusal rather than a silent dispatch.

PURE + DETERMINISTIC. No I/O, no clock, no async, no global state. The same body
bytes always re-parse to an EQUAL notification (SEC-309-2), so G0 dedup on the
composite ``(adapter_id, inbound_id)`` can never be a silent no-op.

FAIL-LOUD (hard rule #7). A body that does not decode/validate raises
:class:`~alfred.comms_mcp.errors.InboundBodyMalformedError`; an envelope==body
``adapter_id`` mismatch raises
:class:`~alfred.comms_mcp.errors.InboundEnvelopeBodyMismatchError`. Neither carries
the raw T3 body on the exception (spec §3.3). The DISPOSITION (the K4-style forge
refusal vs the ARCH-309-3 ack-to-drain on a malformed body) is the core receive
slice's job (G6-7-4); this function only raises the typed contract.

SCOPE FENCE. This is NOT leg/registered-adapter admission (K4 — deferred to
G6-7-4) and NOT dispatch. It is the model + the equality check only.
"""

from __future__ import annotations

from pydantic import ValidationError

from alfred.comms_mcp.errors import (
    InboundBodyMalformedError,
    InboundEnvelopeBodyMismatchError,
)
from alfred.comms_mcp.protocol import (
    GatewayAdapterInboundEnvelope,
    InboundMessageNotification,
)

__all__ = ["reparse_forwarded_inbound"]


def reparse_forwarded_inbound(
    envelope: GatewayAdapterInboundEnvelope,
) -> InboundMessageNotification:
    """Re-parse a forwarded inbound's opaque body into its notification.

    Returns the validated :class:`InboundMessageNotification` the body encodes.
    Raises :class:`InboundBodyMalformedError` if the body is not a valid
    notification, or :class:`InboundEnvelopeBodyMismatchError` if the body's
    ``adapter_id`` does not equal ``envelope.adapter_id``.
    """
    # The CORE is the trusted parser of the T3 body. ``model_validate_json``
    # mirrors the production parse path (session.py:809's ``model_validate`` of the
    # JSON-RPC ``params``), accepting the byte run the envelope carried verbatim
    # (it takes ``str | bytes``). A decode failure (non-UTF-8 / non-JSON), a
    # non-object top-level, and a missing/invalid field all surface as a
    # ``ValidationError``.
    try:
        notification = InboundMessageNotification.model_validate_json(envelope.body)
    except ValidationError:
        # No raw body on the exception (spec §3.3); ``from None`` severs the
        # ValidationError chain so a body fragment cannot leak via ``__cause__``.
        raise InboundBodyMalformedError(
            "forwarded inbound body failed InboundMessageNotification validation"
        ) from None

    if notification.adapter_id != envelope.adapter_id:
        # F3 (spec §3.3): the body is authoritative; an envelope routing id that
        # disagrees with the body it wraps is a forged-body/valid-leg mismatch.
        # Only the two closed-vocab KINDS appear in the message, never the body.
        raise InboundEnvelopeBodyMismatchError(
            f"envelope adapter_id {envelope.adapter_id!r} != "
            f"body adapter_id {notification.adapter_id!r}"
        )

    return notification
