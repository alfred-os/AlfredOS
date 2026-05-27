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
3. **Canary stub** — Slice-2 is a literal no-op (``return text``). Slice-3
   expands this stage with the canary system; the stub is a regression
   guard against accidentally dropping the stage in the interim. The unit
   test ``test_canary_stub_is_identity_in_slice_2`` is intentionally
   tight: any change to the stub fails the test on purpose.

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
from collections.abc import Callable, Mapping
from typing import Final, Protocol

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


class OutboundDlp:
    """Three-stage outbound scanner.

    Stateless — every call is a fresh pipeline run. Concurrency: the
    underlying broker.redact already serialises against its own
    invalidation, and the regex is immutable; no DLP-side lock needed.
    """

    def __init__(self, *, broker: _BrokerLike, audit: _AuditSink) -> None:
        self._broker = broker
        self._audit = audit

    def scan(self, text: str) -> str:
        """Run all three stages on ``text``; emit an audit row on modification.

        Returns the redacted text. Modification stays silent to the
        recipient — length-delta is a documented Slice-3 mitigation
        concern (oracle attack). The audit row records the byte deltas
        for forensic correlation.
        """
        pre = text
        stages_triggered: list[str] = []

        # Stage 1 — broker redaction.
        after_broker = self._broker.redact(text)
        if after_broker != text:
            stages_triggered.append("broker")
        text = after_broker

        # Stage 2 — generic API-key regex.
        after_regex = _GENERIC_API_KEY_RE.sub(_REDACTION_SENTINEL, text)
        if after_regex != text:
            stages_triggered.append("api_key_shape")
        text = after_regex

        # Stage 3 — canary stub (Slice-3 expands this).
        text = self._canary_stub(text)

        if text != pre:
            # Audit-on-modification. Synchronous; raises propagate per
            # CLAUDE.md hard rule #7.
            self._audit(
                event="dlp.outbound_redacted",
                subject={
                    "pre_bytes": len(pre),
                    "post_bytes": len(text),
                    "stages_triggered": tuple(stages_triggered),
                },
            )

        return text

    @staticmethod
    def _canary_stub(text: str) -> str:
        """Slice-3 canary stage hook. Slice-2: literal no-op.

        REGRESSION GUARD: the unit test pins this as an identity
        function. Do not change without an accompanying spec update —
        the Slice-3 expansion replaces this with real canary handling.
        """
        return text


__all__ = ["OutboundDlp"]


# Re-export the helper Callable type so the structlog bridge in
# ``alfred.cli.main`` can carry the same audit-sink signature without
# duplicating the typing pattern.
_DlpAuditCallable = Callable[..., None]
