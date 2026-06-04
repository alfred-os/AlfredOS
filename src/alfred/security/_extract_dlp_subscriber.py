"""System-tier DLP subscriber on the ``security.quarantined.extract``
post chain (issue #158).

Spec §6.5 line 476 mandates this scan: a typed-extraction schema with
a free-text ``str`` field is an exfiltration channel; running
:meth:`alfred.security.dlp.OutboundDlp.scan` on the validated
:meth:`pydantic.BaseModel.model_dump` catches pattern-matchable
secrets (canary tokens, API keys, credit cards) before the validated
payload returns to the privileged orchestrator.

**Known limitation (semantic-exfil residual risk).**
:class:`alfred.security.dlp.OutboundDlp` is regex-based. Arbitrary
semantic exfiltration — e.g. ``"the user lives at 123 Main St"``
embedded in a natural-language ``summary`` field — is NOT caught
here. Closing that channel requires an AI-based DLP layer that is out
of AlfredOS's current threat model; see issue #158 for the
discussion. The comment is load-bearing — a future reviewer reading
this subscriber MUST NOT conclude "this scan is sufficient
defence". It is necessary but not sufficient.

Architecture:

* The subscriber is constructed with an :class:`OutboundDlp` instance
  (constructor injection — no global state). Lifecycle is owned by
  the :class:`alfred.security.quarantine.QuarantinedExtractor` which
  registers the subscriber idempotently in its ``__init__``.
* :func:`register_extract_dlp_subscriber` is the canonical
  registration entry point. It consults the active registry's
  subscriber bucket for an existing entry keyed on
  :attr:`OutboundDlpExtractSubscriber._SCAN_ID`; on a hit it
  short-circuits so multiple extractor instances don't double-register
  the scan.
* The subscriber's ``__call__`` is registered against the
  ``security.quarantined.extract`` hookpoint, kind ``post``, tier
  ``system`` — spec §6.5 pins the canonical DLP scan as a system-tier
  defence. The hookpoint's :data:`SYSTEM_OPERATOR_TIERS`
  subscribable allow-list keeps the ``user-plugin`` tier OUT; a
  user-plugin scan would not satisfy the trust-boundary contract.

The exact serialisation shape — :func:`json.dumps` with
``default=str``, ``ensure_ascii=False`` — is the canonical wire format
for the dump and matches what an attacker controlling the LLM output
would have emitted. ``default=str`` tolerates :class:`datetime` /
:class:`uuid.UUID` / other non-JSON-native types that
:meth:`pydantic.BaseModel.model_dump` surfaces verbatim; without it a
schema with a timestamp field would raise :class:`TypeError` BEFORE
the scan ran and silently disarm the boundary.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Any, Final

import structlog

from alfred.hooks import HookContext, HookRefusal
from alfred.hooks.audit_sink import HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED
from alfred.hooks.errors import HookError
from alfred.hooks.registry import HookRegistry, get_registry
from alfred.i18n import t

if TYPE_CHECKING:
    from alfred.security.dlp import OutboundDlp

_log = structlog.get_logger(__name__)


class OutboundDlpExtractSubscriber:
    """``post``-kind subscriber on ``security.quarantined.extract``.

    Receives a :class:`HookContext` whose ``input`` is the
    :meth:`pydantic.BaseModel.model_dump` of the validated
    :class:`alfred.security.quarantine.ExtractionResult`. Runs
    :meth:`OutboundDlp.scan` on the serialised JSON of the dump and
    raises :class:`HookRefusal` on any redaction (delta between scan
    input and scan output).

    Stateless — the only instance state is the injected DLP seam. The
    subscriber's lifecycle is owned by the registering extractor.
    """

    _SCAN_ID: Final[str] = "security.quarantined.extract.post.dlp"
    """Closed-vocabulary subscriber id surfaced on the
    :class:`HookRefusal` ``hook_id`` field.

    The audit-graph join key — drift here breaks every downstream
    consumer that filters by ``hook_id``. Public-ish constant so
    :func:`register_extract_dlp_subscriber` can key its idempotency
    check off the same value.
    """

    def __init__(self, *, outbound_dlp: OutboundDlp) -> None:
        """Wire the subscriber to an :class:`OutboundDlp` instance.

        Args:
            outbound_dlp: The DLP scanner. Keyword-only so the
                construction site can't drift positional args. No
                default — the subscriber MUST NOT silently construct
                its own scanner (that would bypass the orchestrator's
                DLP singleton wiring).
        """
        self._dlp = outbound_dlp

    async def __call__(
        self,
        ctx: HookContext[Any],
    ) -> HookContext[Any]:
        """Scan ``ctx.input`` (the ``model_dump`` dict) for DLP triggers.

        Serialises the dict to JSON via :func:`json.dumps` with
        ``default=str`` (tolerate datetime / UUID / other non-JSON-native
        types) and ``ensure_ascii=False`` (preserve non-ASCII content
        verbatim so a multi-byte canary character is detected as the
        exact UTF-8 byte sequence the scan's regex expects).

        Disposition:

        * Scan output equals input — no trigger fired; return the
          carrier unchanged so the dispatch chain continues.
        * Scan output differs from input — a redaction happened; the
          payload contained a pattern-matchable secret. Raise
          :class:`HookRefusal` so the dispatch chain aborts and the
          validated payload never returns to the orchestrator.
        * Scan raises — propagate. The hookpoint's
          ``fail_closed=True`` policy turns the propagation into a
          chain-level refusal (CLAUDE.md hard rule #7). NEVER swallow.

        Pattern-matchable channels CLOSED here:
        canary tokens, generic API key shapes (``sk-…`` /
        ``pk_…`` / ``tok-…`` / ``key_…`` with 20+ alnum chars), credit
        card patterns, anything the broker's redaction-key registry
        knows about.

        Semantic channels NOT closed: arbitrary paraphrased PII in
        natural-language fields. See module docstring for the
        residual-risk discussion. Out of scope per current threat
        model.

        Args:
            ctx: The carrier the dispatcher hands the subscriber.
                ``ctx.input`` is the ``model_dump`` of the validated
                :class:`ExtractionResult`; ``ctx.correlation_id`` is
                the chain's id, surfaced on the
                :class:`HookRefusal` for audit attribution.

        Returns:
            ``ctx`` unchanged on a clean scan. The dispatcher
            interprets the return as "this subscriber did not mutate"
            and proceeds to the next subscriber.

        Raises:
            HookRefusal: A pattern-matchable secret tripped the scan.
                The exception carries the closed-vocabulary
                ``hook_id`` :attr:`_SCAN_ID`, the ``action_id``
                ``security.quarantined.extract``, the ``reason``
                ``canary_or_secret_in_extracted_payload``, and the
                chain's ``correlation_id``. The dispatcher's pre-arm
                handles ``post``-stage refusal disposition
                differently from ``pre`` (no §6.5 authorization check
                — post refusals propagate uncaught), so the refusal
                propagates to the :meth:`extract` caller as a hard
                fault.
            BaseException: Whatever :meth:`OutboundDlp.scan` raised.
                The subscriber does NOT swallow.
        """
        payload = json.dumps(ctx.input, default=str, ensure_ascii=False)
        scanned = self._dlp.scan(payload)
        if scanned != payload:
            # OutboundDlp.scan returns the redacted text. Any
            # difference between input and output is a positive DLP
            # signal — the scan detected a canary token / API key
            # shape / credit card / known secret. Refuse the extract.
            #
            # CLAUDE.md hard rule #1: the audit row (downstream of
            # this raise) MUST NOT carry the raw ``payload`` or
            # ``scanned`` text — both may contain T3-derived content,
            # and the refusal-row schema in
            # :data:`alfred.hooks.invoke._REFUSAL_AUDIT_FIELDS`
            # explicitly omits ``reason``-text fields for that
            # reason. We carry only the closed-vocabulary
            # ``reason`` constant here; the propagating exception's
            # ``str()`` renders an i18n message that does not
            # interpolate the payload (the ``hooks.refusal``
            # catalog string takes ``hook_id`` / ``action_id`` /
            # ``reason`` only — see ``locale/en/LC_MESSAGES/alfred.po``).
            raise HookRefusal(
                hook_id=self._SCAN_ID,
                action_id="security.quarantined.extract",
                reason="canary_or_secret_in_extracted_payload",
                correlation_id=ctx.correlation_id,
            )
        return ctx


class RegistrationOutcome(Enum):
    """Closed-vocabulary outcome of a successful
    :func:`register_extract_dlp_subscriber` call.

    Only the success arms are surfaced as a return value. Failures
    (gate-deny, missing hookpoint, etc.) raise :class:`HookError`
    rather than returning a falsy value — CLAUDE.md hard rule #7
    forbids silent failures on security paths, and a boolean return
    pinned the helper to a fail-soft posture that left a half-wired
    extractor running without DLP. CR-156 round 7 / CR-158 T1.

    * :attr:`REGISTERED` — a fresh subscriber landed on the post
      chain. The caller's expectation that "after this call the DLP
      scan is active" is satisfied.
    * :attr:`ALREADY_REGISTERED` — the same :class:`OutboundDlp`
      instance was already wired by an earlier call (typically a
      sibling :class:`QuarantinedExtractor` in the same process).
      First-writer-wins; the caller's expectation is still satisfied.

    A different-instance re-registration raises :class:`HookError`
    (see helper docstring) — that arm is structurally distinct from
    the two outcomes here and does not fit on this enum.
    """

    REGISTERED = "registered"
    ALREADY_REGISTERED = "already_registered"


def register_extract_dlp_subscriber(
    *,
    registry: HookRegistry | None = None,
    outbound_dlp: OutboundDlp,
) -> RegistrationOutcome:
    """Subscribe :class:`OutboundDlpExtractSubscriber` to the
    ``security.quarantined.extract`` post chain.

    Idempotent on same-instance re-registration —
    :attr:`OutboundDlpExtractSubscriber._SCAN_ID` is a stable id and
    the helper consults the existing bucket before registering.
    Without that dedup a process that constructs multiple
    :class:`QuarantinedExtractor` instances (per-conversation,
    per-user) would land N copies of the scan in the post bucket and
    run the DLP pipeline N times per extract.

    Tier is ``system`` — spec §6.5 pins the canonical DLP scan as a
    system-tier defence. The hookpoint's :data:`SYSTEM_OPERATOR_TIERS`
    allow-list permits the registration; a tier drift to
    ``user-plugin`` would be refused at register time by the
    publisher's declared allow-list. Pin the value here so a refactor
    that drifts is loud.

    **Fail-loud on gate-deny / unavailable (PRD §7.1 + CLAUDE.md
    hard rule #7).** The registry's capability gate decides whether
    a system-tier subscriber may register. On the deny path
    (bootstrap-incomplete registry, ungranted gate, missing
    hookpoint) this helper RAISES :class:`HookError` rather than
    returning a falsy value. A half-wired :class:`QuarantinedExtractor`
    — one whose post-stage DLP scan never landed — would be an active
    trust-boundary violation, and the prior fail-soft return value
    left exactly that posture as the default. Hard rule #7 forbids
    silent failures on security paths; this raise IS the loud signal.

    Observability is preserved BEFORE the raise: a structlog WARN
    AND an audit row (:data:`HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED`)
    emit first, so an operator (or :class:`AuditWriter`-side log
    consumer) sees the failure even if the caller swallows the
    exception. The pre-check uses the SAME gate-query
    :meth:`HookRegistry.register` runs internally — consulting it
    first lets us emit the closed-vocabulary deny audit row before
    the registry's own (more generic) refusal arm fires.

    Args:
        registry: Optional override — tests pass a fresh registry to
            assert against a non-singleton store. Defaults to
            :func:`get_registry`.
        outbound_dlp: The DLP scanner the subscriber wraps.
            Keyword-only; no default — the orchestrator's bootstrap
            constructs the singleton and threads it through to every
            extractor.

    Returns:
        A :class:`RegistrationOutcome` enum value: ``REGISTERED`` if a
        fresh subscriber landed, ``ALREADY_REGISTERED`` if a same-
        instance call had already wired one. Both arms satisfy the
        caller's "DLP scan is active after this call" expectation.

    Notes:
        The idempotency check looks for an existing subscriber bound to
        :attr:`OutboundDlpExtractSubscriber._SCAN_ID` whose wrapped
        :class:`OutboundDlp` instance IS (identity, not equality) the
        ``outbound_dlp`` passed in.

        * Same SCAN_ID + same :class:`OutboundDlp` instance — returns
          :attr:`RegistrationOutcome.ALREADY_REGISTERED`
          (first-writer-wins).
        * Same SCAN_ID + DIFFERENT :class:`OutboundDlp` instance —
          raises :class:`HookError`. A drift in the wrapped scanner
          would silently disarm the orchestrator's DLP singleton
          wiring (the second call would land a no-op while leaving the
          first instance's scan as the active defence — but the call
          site's intent was "use *my* DLP", not "fall through to the
          first one"). Failing loudly preserves the orchestrator's
          ability to detect a bootstrap-wiring mistake.

        If a caller legitimately needs to swap the wrapped scanner,
        the proper path is registry :meth:`HookRegistry.reset`
        (test-only) or a reload-by-module flow (Slice-3 arch-002),
        not a re-register against the same SCAN_ID.

    Raises:
        HookError: The gate denied the system-tier subscriber
            registration (bootstrap-incomplete posture; ungranted
            production gate; missing hookpoint declaration) OR an
            existing :class:`OutboundDlpExtractSubscriber` is bound
            to a DIFFERENT :class:`OutboundDlp` instance. The WARN +
            audit row land BEFORE the raise so observability survives
            even if the caller swallows the exception.
    """
    target = registry if registry is not None else get_registry()
    existing = target.subscribers_for("security.quarantined.extract", "post")
    for sub in existing:
        bound_self = getattr(sub.hook_fn, "__self__", None)
        if isinstance(bound_self, OutboundDlpExtractSubscriber):
            # Already registered — same SCAN_ID, same hookpoint, same
            # kind. Verify identity of the wrapped scanner: a drift
            # would silently leave the FIRST scanner as the active
            # defence while the caller's expectation is "register *my*
            # scanner". Identity (``is``) rather than equality —
            # :class:`OutboundDlp` does not implement value equality,
            # and two distinct singletons should never be conflated
            # even if their internal state happens to match.
            if bound_self._dlp is not outbound_dlp:
                raise HookError(
                    "OutboundDlpExtractSubscriber is already bound to a "
                    "different OutboundDlp instance on "
                    "security.quarantined.extract; use "
                    "HookRegistry.reset (test-only) or the Slice-3 "
                    "reload-by-module flow rather than re-registering "
                    "with a new scanner."
                )
            # Same SCAN_ID, same OutboundDlp — first-writer-wins.
            return RegistrationOutcome.ALREADY_REGISTERED

    # Gate-aware pre-check. The same query the registry runs
    # internally — by consulting it first we emit the closed-vocab
    # HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED audit row BEFORE the raise
    # so an operator sees the specific failure shape rather than only
    # the registry's generic refusal arm. ``plugin_id`` matches what
    # :meth:`HookRegistry.register` passes as default attribution
    # (``hook_fn.__module__``) so both check sites see the same key.
    plugin_id = OutboundDlpExtractSubscriber.__call__.__module__
    hookpoint = "security.quarantined.extract"
    requested_tier = "system"
    if not target.gate.check(
        plugin_id=plugin_id,
        hookpoint=hookpoint,
        requested_tier=requested_tier,
    ):
        # CLAUDE.md hard rule #7 — every security-boundary refusal is
        # auditable. Emit a structlog WARN + an audit row BEFORE
        # raising so observability survives even if the caller
        # swallows the exception.
        #
        # The structlog ``event=`` identifier is the closed-vocab
        # audit-row name (operator can grep the audit log AND the
        # structlog stream with the same key). The ``message`` field
        # carries the i18n-rendered operator-facing string (CLAUDE.md
        # hard rule #1). Structured fields stay outside the
        # translatable string so audit-graph queries can filter on
        # them without re-parsing localised text.
        message = t(
            "security.quarantine.dlp_subscriber_registration_denied",
            plugin_id=plugin_id,
            hookpoint=hookpoint,
            requested_tier=requested_tier,
        )
        _log.warning(
            HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED,
            plugin_id=plugin_id,
            hookpoint=hookpoint,
            requested_tier=requested_tier,
            message=message,
        )
        # The audit row is the durable forensic record. ``_emit_sync``
        # bridges the async sink Protocol for this sync call path —
        # same pattern :meth:`HookRegistry.register` uses for its own
        # HOOKS_TIER_REJECTED row. Cross-module access is deliberate:
        # this helper IS the canonical registration entry-point for
        # the system-tier DLP subscriber; centralising the audit-row
        # emission here keeps the bootstrap-deny shape attributable to
        # one grep-able call site.
        target._emit_sync(
            event=HOOKS_DLP_SUBSCRIBER_NOT_REGISTERED,
            correlation_id="register-time",
            fields={
                "plugin_id": plugin_id,
                "hookpoint": hookpoint,
                "requested_tier": requested_tier,
                "deny_reason": "capability_gate_check_returned_false",
            },
        )
        # CR-156 round-7 / CR-158 T1: PRD §7.1 + CLAUDE.md hard rule
        # #7 — the boundary contract is "DLP scan is active after a
        # successful return". A boolean fail-soft return left a
        # half-wired extractor (no DLP scan on the post chain) as a
        # legal state; that's an active trust-boundary violation. The
        # raise here is what makes the contract enforceable at the
        # call site — :class:`QuarantinedExtractor.__init__` can no
        # longer silently swallow the deny path. The message stays
        # closed-vocabulary (plugin_id / hookpoint / requested_tier)
        # so the raise is greppable next to the audit row.
        raise HookError(
            "DLP subscriber registration denied for the "
            "security.quarantined.extract post chain — "
            f"plugin_id={plugin_id!r}, hookpoint={hookpoint!r}, "
            f"requested_tier={requested_tier!r}. The capability gate "
            "refused the system-tier registration; the extractor "
            "cannot construct without an active post-stage DLP scan "
            "(PRD §7.1, CLAUDE.md hard rule #7)."
        )

    subscriber = OutboundDlpExtractSubscriber(outbound_dlp=outbound_dlp)
    target.register(
        hook_fn=subscriber.__call__,
        hookpoint="security.quarantined.extract",
        kind="post",
        tier="system",
    )
    return RegistrationOutcome.REGISTERED


__all__ = [
    "OutboundDlpExtractSubscriber",
    "RegistrationOutcome",
    "register_extract_dlp_subscriber",
]
