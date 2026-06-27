"""Outbound DLP: the chokepoint every outbound message string passes through.

Three pipeline stages run inside :meth:`OutboundDlp.scan`:

1. **Broker redaction** — :meth:`alfred.security.secrets.SecretBroker.redact`
   replaces any value AlfredOS knows it owns (env-backed and file-backed
   secrets both).
2. **Generic API-key regex** — catches values shaped like a third-party
   API key (``sk-…``, ``pk_…``, ``tok-…``, ``key_…`` followed by 20+
   alphanumeric chars). Defends against the case where a secret leaked
   into a log line from a code path that never registered the value with
   the broker (a third-party SDK that exposed the key via its own
   exception ``__repr__``, for instance).
3. **Canary scan** (Spec C G7-2b) — scans the (post-stage-1+2) outbound text
   for any operator-registered canary token via the shared
   :class:`alfred.security.canary_matcher.CanaryMatcher`. A hit fails **LOUD**:
   the trip audit row is written, then :class:`OutboundCanaryTripped` raises
   (never fail-open — a swallowed match would let the canary'd body egress). An
   internal matcher error PROPAGATES for the same reason. When no matcher is
   wired (``canary=None`` — today's core default until it wires a vocabulary)
   the stage is a transparent no-op.

Broker-optional: ``broker`` may be ``None``. The gateway second pass (ADR-0036:
the gateway holds no vault) constructs ``OutboundDlp(broker=None, …)`` to run
the secret-INDEPENDENT stages 2+3 only — one code path, no fork.

Audit-on-modification: when ``scan()`` modifies the text, exactly one
``dlp.outbound_redacted`` audit row is written. The audit sink is
dependency-injected as a synchronous callable so DLP can run inside
synchronous structlog processors without spawning a task per log line.
Failure to write the audit row PROPAGATES — CLAUDE.md hard rule #7.

DLP cannot be disabled per-call. The only legitimate bypass is a
pure-internal tool that declares "no DLP needed" in its manifest, and
the adversarial suite verifies that claim. The bridge into structlog
(``_redact_value`` in ``src/alfred/cli/main.py``) is wired to route
through this module so log emissions inherit stage-2 + stage-3 coverage
that the older ``broker.redact``-only path missed (sec-003).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final, NewType, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.security.canary_matcher import CanaryMatcher

# Generic API-key shape: prefix + separator + 20-or-more alnum bytes,
# anchored on word boundaries so an embedded form (e.g.
# ``prefix-sk-AAAA…``) doesn't sneak past. Lowercase-prefix-only by
# design — major-provider SDKs use lowercase ``sk-`` / ``pk_`` / etc.;
# allowing a capitalised prefix would generate false positives on
# human-typed text. The 20-byte minimum keeps the false-positive rate
# low while catching every real-world provider format we've audited.
_GENERIC_API_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:sk|pk|tok|key)[-_][A-Za-z0-9]{20,}\b"
)
_REDACTION_SENTINEL: Final[str] = "[REDACTED:api-key-shape]"


def redact_secret_shapes(text: str) -> str:
    """Stage-2-only secret-shape scrub for INTERNAL audit-string hygiene.

    Substitutes every generic API-key-shaped token (``sk-``/``pk_``/… + 20+
    alnum bytes) with :data:`_REDACTION_SENTINEL`. This is the same Stage-2
    regex :meth:`OutboundDlp._scan_stages` runs, exposed as a stateless helper
    for call sites that need a quick secret-shape scrub without constructing
    the full ``OutboundDlp`` (broker + audit sink) — e.g. the comms session
    dispatcher scrubbing an exception ``str`` before it lands in an audit row.

    .. warning::

        This is **Stage 2 in isolation** — it runs NEITHER the broker-backed
        Stage-1 redactor (which scrubs values AlfredOS *knows* it owns) NOR the
        Stage-3 canary detector. It is therefore ONLY safe for host-internal
        strings that never cross the outbound wire (audit-row detail fields,
        log lines). For ANY text that leaves AlfredOS for a user/platform, the
        full chokepoint :meth:`OutboundDlp.scan_for_outbound` is mandatory —
        using this helper there would silently bypass broker redaction and the
        canary stage. It is kept public (not ``_``-prefixed) because it is a
        genuine shared utility across the ``plugins`` and ``comms_mcp`` packages;
        the contract above — not name-mangling — is what bounds its use.
    """
    return _GENERIC_API_KEY_RE.sub(_REDACTION_SENTINEL, text)


class OutboundDlpScanResult(BaseModel):
    """Forensic metadata of a single :meth:`OutboundDlp.scan_for_outbound` run.

    Carries the post-scan signal an outbound caller needs to make a refusal
    decision without re-deriving it: how many redaction stages fired
    (``dlp_redactions_count``) and whether a canary token tripped
    (``canary_tripped``). The redacted *text* lives alongside this in the
    :data:`ScannedOutboundBody` tuple — the two are minted together so a
    comms ``OutboundMessageRequest`` cannot carry text that skipped the scan.

    ``canary_tripped`` is **always False** on a returned result: as of Spec C
    G7-2b the canary stage fails LOUD — a hit raises :class:`OutboundCanaryTripped`
    BEFORE this result is minted, so a "tripped" body never produces a
    :class:`OutboundDlpScanResult` at all. The field is retained (rather than
    removed) for wire-contract stability — the comms ``OutboundMessageRequest``
    shape does not move.
    """

    dlp_redactions_count: int = Field(ge=0)
    canary_tripped: bool
    model_config = ConfigDict(frozen=True, extra="forbid")


# The ONLY type the comms ``OutboundMessageRequest.body`` field accepts
# (PR-S4-8 round-2 closure #1 — sec-001 CRITICAL). A ``NewType`` over the
# ``(redacted_text, scan_result)`` tuple: the tuple is mintable only by
# :meth:`OutboundDlp.scan_for_outbound`, so every outbound construction site
# is statically forced through the DLP chokepoint. The AST guard
# ``tests/unit/comms/test_outbound_request_constructed_via_scan.py`` refuses
# any ``OutboundMessageRequest(...)`` whose ``body=`` is not a
# ``scan_for_outbound(...)`` return value within the same function scope.
ScannedOutboundBody = NewType("ScannedOutboundBody", tuple[str, OutboundDlpScanResult])


class _BrokerLike(Protocol):
    """Structural type for the broker's redaction surface.

    DLP depends on this Protocol rather than the concrete broker so
    tests can inject a stub without spinning up the file backend.
    """

    def redact(self, text: str) -> str:
        # Protocol body. Tests cover via injected stubs; the body itself
        # is unreachable so the pragma keeps the 100% coverage gate
        # honest (otherwise it'd subtract a Protocol stub from real
        # coverage).
        raise NotImplementedError  # pragma: no cover


class _AuditSink(Protocol):
    """Synchronous audit sink for DLP modification events.

    DLP runs inside structlog's synchronous processor chain so the audit
    write MUST NOT block on the event loop. The CLI bootstrap wires a
    sink that records the event into an in-memory queue drained on an
    async tick; tests inject a list-appending stub.

    Signature: ``(event_name, subject_dict) -> None``. Raises propagate
    per CLAUDE.md hard rule #7 ("no silent failures in security paths").
    """

    def __call__(self, *, event: str, subject: Mapping[str, object]) -> None:
        raise NotImplementedError  # pragma: no cover


class OutboundCanaryTripped(AlfredError):  # noqa: N818 -- SECURITY EVENT, name pinned by Spec C §4.2
    """A registered canary token was found in outbound text (Spec C G7-2b).

    A SECURITY EVENT — raised by :meth:`OutboundDlp._scan_canary` after the trip
    audit row is written, so the body is REFUSED rather than egressed (HARD rule
    #7: loud, never fail-open). Carries the matched ``token`` as an attribute (an
    operator sentinel, for the handler / gateway deny-reason mapping); the t()'d
    message is deliberately token-free so it cannot leak the sentinel into a
    wider error surface.
    """

    reason = "outbound_canary_tripped"

    def __init__(self, *, token: str) -> None:
        self.token = token
        super().__init__(t("egress.outbound_canary_tripped"))


class OutboundDlp:
    """Three-stage outbound scanner.

    Stateless — every call is a fresh pipeline run. Concurrency: the
    underlying broker.redact already serialises against its own
    invalidation, and the regex is immutable; no DLP-side lock needed.
    """

    def __init__(
        self,
        *,
        broker: _BrokerLike | None,
        audit: _AuditSink,
        canary: CanaryMatcher | None = None,
    ) -> None:
        # ``broker`` and ``canary`` are BOTH optional. Core-side wires all three
        # (broker + regex + canary). Gateway-side (ADR-0036, no vault) wires
        # broker=None — stages 2+3 only. ONE code path, no fork.
        self._broker = broker
        self._audit = audit
        self._canary = canary

    def scan(self, text: str) -> str:
        """Run all three stages on ``text``; emit an audit row on modification.

        Returns the redacted text. Modification stays silent to the
        recipient — length-delta is a documented Slice-3 mitigation
        concern (oracle attack). The audit row records the byte deltas
        for forensic correlation.
        """
        redacted, _stages = self._scan_stages(text)
        return redacted

    def scan_for_outbound(self, raw_body: str) -> ScannedOutboundBody:
        """Mint a :data:`ScannedOutboundBody` from a raw outbound message body.

        The ONLY constructor of :data:`ScannedOutboundBody` (PR-S4-8 round-2
        closure #1). A comms ``OutboundMessageRequest`` cannot be built
        without first routing its body through this method, so the
        DLP-mandatory invariant is structural, not a convention an emit site
        can forget. Runs the same three-stage pipeline as :meth:`scan` (so
        the audit-on-modification row still fires) and additionally surfaces
        the redaction count + canary signal in a frozen
        :class:`OutboundDlpScanResult` for the caller's refusal decision.
        """
        redacted, stages_triggered = self._scan_stages(raw_body)
        scan_result = OutboundDlpScanResult(
            dlp_redactions_count=len(stages_triggered),
            # Always False on a returned result: a canary hit raises
            # OutboundCanaryTripped inside _scan_stages BEFORE this point (G7-2b),
            # so a tripped body never reaches here. Retained for wire stability.
            canary_tripped=False,
        )
        return ScannedOutboundBody((redacted, scan_result))

    def _scan_stages(self, text: str) -> tuple[str, tuple[str, ...]]:
        """Run the three-stage pipeline; return ``(redacted, stages_triggered)``.

        Shared core for :meth:`scan` and :meth:`scan_for_outbound`. Emits the
        ``dlp.outbound_redacted`` audit row on modification; raises propagate
        per CLAUDE.md hard rule #7.
        """
        pre = text
        stages_triggered: list[str] = []

        # Stage 1 — broker redaction. Skipped when no broker is wired (the
        # gateway second pass holds no vault — ADR-0036); the SAME code path,
        # just without the stage-1 block (``broker`` never appears in
        # ``stages_triggered`` then).
        if self._broker is not None:
            after_broker = self._broker.redact(text)
            if after_broker != text:
                stages_triggered.append("broker")
            text = after_broker

        # Stage 2 — generic API-key regex.
        after_regex = _GENERIC_API_KEY_RE.sub(_REDACTION_SENTINEL, text)
        if after_regex != text:
            stages_triggered.append("api_key_shape")
        text = after_regex

        # Audit-on-modification (stages 1+2) BEFORE the stage-3 canary scan, so a
        # body that BOTH carried a redactable secret AND trips a canary records the
        # redaction (``dlp.outbound_redacted``) before the trip (``dlp.outbound_canary_tripped``)
        # rather than losing the redaction row to the canary raise (CR review). Synchronous;
        # raises propagate per CLAUDE.md hard rule #7. ``pre_bytes`` / ``post_bytes`` are
        # UTF-8 byte counts (not character counts) — forensic consumers reason in bytes.
        if text != pre:
            self._audit(
                event="dlp.outbound_redacted",
                subject={
                    "pre_bytes": len(pre.encode("utf-8")),
                    "post_bytes": len(text.encode("utf-8")),
                    "stages_triggered": tuple(stages_triggered),
                },
            )

        # Stage 3 — real canary scan on the ORIGINAL ``pre`` text (NOT the redacted
        # ``text``): a canary token that also matches a stage-1/2 redaction (e.g. an
        # api-key-shaped canary) would otherwise be erased before this scan and the
        # trip silently lost — a fail-LOUD violation (CR review, HARD rule #7). Fails
        # loud on a hit (raises before returning); a no-op when no matcher.
        self._scan_canary(pre)

        return text, tuple(stages_triggered)

    def _scan_canary(self, text: str) -> None:
        """Stage 3 — scan ``text`` for a registered canary token; fail LOUD on a hit.

        No-op when no matcher is wired. On a match: write the trip audit row,
        THEN raise :class:`OutboundCanaryTripped` (HARD rule #7 — loud, never
        fail-open). The matcher's ``first_match`` is NOT wrapped in a swallowing
        try/except: an internal matcher error PROPAGATES (a swallowed error would
        let a canary'd body egress unscanned). Returns ``None`` (no modification).
        """
        if self._canary is None:
            return
        matched = self._canary.first_match(text)
        if matched is not None:
            # The matched token is an operator-registered sentinel (not T3 body
            # content), so naming it gives the operator attribution without a
            # body oracle. The raised exception's message stays token-free.
            self._audit(event="dlp.outbound_canary_tripped", subject={"token": matched})
            raise OutboundCanaryTripped(token=matched)


@runtime_checkable
class OutboundDlpProtocol(Protocol):
    """Structural type for the outbound DLP scanner.

    Used by frozen dataclasses (:class:`alfred.state.dispatch_registry.ProposalContext`)
    and other surfaces that need to annotate a DLP-scanner dependency
    without binding to the concrete :class:`OutboundDlp` class. The concrete
    class satisfies this protocol by virtue of its ``scan`` signature.

    The protocol is intentionally narrow — the only stable surface is
    ``scan``. A consumer that needs broker-redaction or audit-sink access
    constructs :class:`OutboundDlp` directly; everything else uses this
    protocol. Mirrors the in-module ``_BrokerLike`` / ``_AuditSink``
    structural-typing precedent.

    ``runtime_checkable`` so the injection boundary can ``isinstance``-check
    a candidate scanner; the dispatch loop never sees the concrete class
    (the AST guard ``test_dispatch_loop_no_local_dlp_construct`` enforces
    that — the singleton arrives via ``ProposalContext.outbound_dlp``).
    """

    def scan(self, text: str) -> str:
        # Protocol body. Real coverage comes from injected implementations;
        # the stub is unreachable so the pragma keeps the 100% coverage gate
        # honest (same discipline as ``_BrokerLike`` / ``_AuditSink``).
        raise NotImplementedError  # pragma: no cover


__all__ = [
    "OutboundCanaryTripped",
    "OutboundDlp",
    "OutboundDlpProtocol",
    "OutboundDlpScanResult",
    "ScannedOutboundBody",
    "redact_secret_shapes",
]
