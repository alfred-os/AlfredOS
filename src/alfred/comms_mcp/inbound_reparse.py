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


def _structural_summary(exc: ValidationError) -> str:
    """A LEAK-SAFE one-line summary of why an inbound body failed validation.

    Built from ONLY the closed structural shape of each pydantic error — the
    error-type code and a leak-safe ``loc`` rendering — plus the error count. The raw
    ``input`` / ``msg`` / ``ctx`` values are DROPPED here on purpose: they echo the
    untrusted T3 body (e.g. ``input_value=...``) and must never reach an exception
    string the core might log (spec §3.3 — no payload in error attrs). The result
    turns the opaque "validation failed" sentence into an actionable debug aid
    (non-UTF-8 vs non-JSON vs missing-field) without leaking the body.

    The ``loc`` of an ``extra_forbidden`` error ENDS in the unexpected key NAME, which
    is attacker-supplied T3 (G6-7-2 carry-item: UAT on #311 saw ``extra_forbidden@<key>``
    surface a body's top-level key name). That whole ``loc`` is redacted to
    ``<redacted-t3-key>``. Every OTHER pydantic error type carries a schema-known field path
    in ``loc`` (a field must be DECLARED to be validated), safe to surface as an
    actionable debug aid. ``InboundMessageNotification`` has no
    ``dict[str, ConstrainedType]`` field (``body`` accepts any object), so
    ``extra_forbidden`` is the sole attacker-key vector; a future constrained-dict
    field would need this redaction broadened.
    """
    errors = exc.errors(include_url=False)
    parts: list[str] = []
    for error in errors:
        error_type = error["type"]
        if error_type == "extra_forbidden":
            parts.append(f"{error_type}@<redacted-t3-key>")
        else:
            parts.append(f"{error_type}@{'.'.join(str(segment) for segment in error['loc'])}")
    return f"{len(errors)} error(s): {', '.join(parts)}"


def reparse_forwarded_inbound(
    envelope: GatewayAdapterInboundEnvelope,
) -> InboundMessageNotification:
    """Re-parse a forwarded inbound's opaque body into its notification.

    Returns the validated :class:`InboundMessageNotification` the body encodes.
    Raises :class:`InboundBodyMalformedError` if the body is not a valid
    notification, or :class:`InboundEnvelopeBodyMismatchError` if the body's
    ``adapter_id`` does not equal ``envelope.adapter_id``.

    The body-supplied ``wire_seq`` is SCRUBBED to ``None``: ``wire_seq`` is
    host-authoritative leg-carrier metadata (ADR-0032), not payload-derived, so a
    value smuggled into the untrusted T3 body is dropped here. G6-7-3/-4 rebinds the
    real leg-carrier seq out-of-band.

    The :class:`InboundBodyMalformedError` message carries a LEAK-SAFE structural
    summary (error-type codes + ``loc`` field-paths + the safe ``adapter_id`` KIND)
    but NEVER the raw T3 body (spec §3.3). An ``extra_forbidden`` error's ``loc`` ENDS
    in the attacker-supplied extra-key NAME (T3-derived), so its ``loc`` is redacted to
    ``<redacted-t3-key>``; every other error type keeps its schema-known ``loc`` field-path.
    The malformed error is also raised with
    ``__context__`` cleared: the ``ValidationError`` (which echoes the body via
    ``input_value``) is captured and discarded inside the ``except`` and the
    :class:`InboundBodyMalformedError` is raised OUTSIDE it, so no body fragment
    survives on the exception chain even for a consumer that walks ``__context__``.
    """
    # The CORE is the trusted parser of the T3 body. ``model_validate_json``
    # mirrors the production parse path (AlfredPluginSession's
    # ``_route_comms_notification`` ``model_validate`` of the JSON-RPC ``params``),
    # accepting the byte run the envelope carried verbatim (it takes ``str |
    # bytes``). A decode failure (non-UTF-8 / non-JSON), a non-object top-level, and
    # a missing/invalid field all surface as a ``ValidationError``.
    #
    # The ValidationError MUST NOT escape this function on any attribute: it echoes
    # the raw T3 body via ``input_value`` (spec §3.3). ``from None`` clears
    # ``__cause__`` but the in-flight exception still lands on ``__context__`` when
    # we raise INSIDE the ``except``. So we capture only the leak-safe structural
    # summary inside the handler and raise OUTSIDE it, where there is no active
    # exception to attach — ``__context__`` is ``None``.
    structural: str | None = None
    try:
        notification = InboundMessageNotification.model_validate_json(envelope.body)
    except ValidationError as exc:
        structural = _structural_summary(exc)
    else:
        if notification.adapter_id != envelope.adapter_id:
            # F3 (spec §3.3): the body is authoritative; an envelope routing id
            # that disagrees with the body it wraps is a forged-body/valid-leg
            # mismatch. Only the two closed-vocab KINDS appear, never the body.
            raise InboundEnvelopeBodyMismatchError(
                f"envelope adapter_id {envelope.adapter_id!r} != "
                f"body adapter_id {notification.adapter_id!r}"
            )
        # ``wire_seq`` is HOST-AUTHORITATIVE leg-carrier metadata (ADR-0032),
        # NEVER payload-derived. It is a declared field, so ``extra="forbid"``
        # does NOT block a value smuggled into the untrusted T3 body; mirror the
        # host-authoritative ``wire_seq`` set in AlfredPluginSession's
        # ``_route_comms_notification`` inbound parse by scrubbing any body-derived
        # value. G6-7-3/-4 rebinds the real leg-carrier seq out-of-band; the
        # re-parse never trusts a body-derived ``wire_seq`` (a forged value could
        # corrupt the BoundedSeqAckTracker contiguous high-water the ack/replay
        # semantics rest on). ``model_copy`` is frozen-safe: it constructs a new
        # instance with the same validated fields and ``wire_seq=None`` (a valid
        # value), bypassing the frozen setattr guard without re-running validation.
        return notification.model_copy(update={"wire_seq": None})

    # Reached ONLY on a ValidationError. Raise OUTSIDE the ``except`` so there is no
    # active exception for Python to attach to ``__context__`` — the discarded
    # ValidationError (which echoes the raw T3 body via ``input_value``) cannot leak
    # via the exception chain. The message carries only the leak-safe structural
    # summary and the closed-vocab ``adapter_id``.
    raise InboundBodyMalformedError(
        "forwarded inbound body failed InboundMessageNotification validation "
        f"(adapter_id={envelope.adapter_id!r}; {structural})"
    )
