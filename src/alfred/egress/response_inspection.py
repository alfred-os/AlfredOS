"""Pre-extract response-policy inspection seam (Spec C G7-2.5 Task 4, #333).

This module is the D1 inspection step that runs BEFORE the §4.3
quarantine-extract boundary in C2
(:class:`~alfred.egress.egress_response_extract.EgressResponseExtractor`).
It enforces three policies on the raw T3 :class:`~alfred.egress.relay_protocol.EgressResponse`:

1. **Inbound-canary detection**: scans raw bytes for a planted canary token
   (operator sentinel reflected back in the response).  A hit →
   :class:`_CanaryHit`.  C2 must record a terminal
   ``TypedRefusal(reason="refused_by_safety")`` to the ledger BEFORE raising
   :class:`InboundCanaryTripped` (the C8 invariant: a row left
   ``committed_no_response`` would allow an ``idempotent=True`` replay to
   re-fire at a flagged-hostile destination).

2. **MIME-type enforcement**: the ``Content-Type`` header is parsed
   case-insensitively; charset/boundary/etc. parameters are stripped.  A
   missing, malformed, or duplicate Content-Type fails CLOSED →
   :class:`_SoftRefusal` with ``subject_token="mime_type_not_allowed"``.

3. **Size cap**: ``len(body) > max_bytes`` →
   :class:`_SoftRefusal` with ``subject_token="size_limit_exceeded"``.

Canary runs **FIRST** (order is load-bearing — an oversized body must not
defer canary detection).

Design invariants (plan-review SEC-1/SEC-2/SEC-3, task-4-brief.md)
--------------------------------------------------------------------
* :func:`inspect_response` is **PURE**: it NEVER raises, NEVER performs I/O.
  All side effects (ledger write, raise) are owned by the C2 caller.
* :class:`_CanaryHit` does NOT carry the matched token or Content-Type
  (payload-blind).
* :class:`_SoftRefusal` carries a distinct ``subject_token`` for the
  dispatcher audit pivot.
* :class:`InboundCanaryTripped` carries destination host + egress_id only
  (payload-blind — no body content, no Content-Type string).

Residual (tracked)
------------------
If ``record_response`` itself fails (DB down) on the canary path, the row
stays ``committed_no_response`` → a replay re-fires.  The terminal-refused
guarantee is only as strong as the ledger write.  This narrow window is a
known residual (task-4-brief.md §Design / last bullet).
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from alfred.egress.relay_protocol import EgressResponse
from alfred.errors import AlfredError
from alfred.i18n import t
from alfred.security.canary_matcher import CanaryMatcher

# ---------------------------------------------------------------------------
# Verdict union
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Proceed:
    """Response passed all inspection checks; extraction may proceed."""


@dataclass(frozen=True, slots=True)
class _SoftRefusal:
    """MIME-type or size policy refused the response.

    C2 builds ``TypedRefusal(reason="cannot_extract")``, records it to the
    ledger, and returns an
    ``EgressExtractOutcome(result=refusal, deduplicated=False)``.  The
    extractor is NOT called.

    ``subject_token`` is the per-attack-class audit subject (free-JSON field,
    no CHECK constraint — mirrors ``domain_not_allowed``/``internal_ip_refused``
    precedent): ``"mime_type_not_allowed"`` | ``"size_limit_exceeded"``.
    """

    reason: Literal["cannot_extract"] = "cannot_extract"
    subject_token: str = ""


@dataclass(frozen=True, slots=True)
class _CanaryHit:
    """An inbound canary token was detected in the raw response bytes.

    C2 must (1) record ``TypedRefusal(reason="refused_by_safety")`` to the
    ledger FIRST (terminal ``committed_with_response`` — closes C8 replay
    re-fire), then (2) raise :class:`InboundCanaryTripped`.
    """


# ---------------------------------------------------------------------------
# ResponsePolicy
# ---------------------------------------------------------------------------


class ResponsePolicy(BaseModel, frozen=True):
    """Operator-configured response-inspection policy for ``web.fetch`` (D1 seam).

    ``mime_allowlist``
        Set of bare MIME types (no parameters) that are allowed through.
        Normalised to lowercase at construction so an operator who configures
        ``"Text/HTML"`` still matches the lowercased parsed ``Content-Type``.
        ``Content-Type`` is parsed case-insensitively; charset/boundary/etc.
        parameters are stripped.  A missing or duplicate ``Content-Type``
        header fails closed (→ :class:`_SoftRefusal`).

    ``max_bytes``
        Body length ceiling.  ``len(EgressResponse.body) > max_bytes`` →
        :class:`_SoftRefusal`.  Set this above the gateway's 10 MiB ceiling
        when only web.fetch-specific policy (not a global cap) should bind.

    ``canary``
        Compiled :class:`~alfred.security.canary_matcher.CanaryMatcher`; ``None``
        means the canary step is skipped.  When set, the raw bytes are decoded
        byte-losslessly (latin-1) for matching only.
    """

    mime_allowlist: frozenset[str]
    max_bytes: int
    canary: CanaryMatcher | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_validator("mime_allowlist", mode="before")
    @classmethod
    def _lowercase_mime_allowlist(cls, value: object) -> object:
        """Lowercase every allowlisted MIME so casing in operator config never
        diverges from the lowercased parsed ``Content-Type`` (CR-2).
        """
        if isinstance(value, (frozenset, set, list, tuple)):
            return frozenset(str(item).lower() for item in value)
        return value


# ---------------------------------------------------------------------------
# InboundCanaryTripped
# ---------------------------------------------------------------------------


class InboundCanaryTripped(AlfredError):  # noqa: N818 -- SECURITY EVENT, name pinned by Spec C §4.2
    """An inbound canary token was found in the raw response body (G7-2.5 D1).

    A SECURITY EVENT raised by C2 AFTER it has recorded a terminal
    ``TypedRefusal(reason="refused_by_safety")`` to the ledger (C8 invariant:
    the row is ``committed_with_response`` before the raise, so a §5 replay
    returns ``Deduplicated`` and NEVER re-fires at the flagged-hostile
    destination).

    **Payload-blind**: carries destination host (from URL) + egress_id only —
    no matched token, no body content, no ``Content-Type`` string.
    """

    reason = "inbound_canary_tripped"

    def __init__(self, *, destination: str, egress_id: str) -> None:
        self.destination = destination
        self.egress_id = egress_id
        super().__init__(
            t("egress.inbound_canary_tripped", destination=destination, egress_id=egress_id)
        )


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _host_only(url: str) -> str:
    """Extract the bare hostname for audit attribution (payload-blind).

    Returns the parsed ``hostname`` ONLY — never a path, query, or the raw
    ``netloc`` (which can carry attacker ``user:pass@`` userinfo or a ``:port``).
    A URL with no parseable hostname collapses to ``"<invalid-url>"`` so a
    malformed URL cannot sneak userinfo/port/body content into an error message
    or audit row.
    """
    parsed = urllib.parse.urlsplit(url)
    return parsed.hostname or "<invalid-url>"


def _parse_content_type(headers: Mapping[str, str]) -> str | None:
    """Parse the bare MIME type from response headers; fail closed on ambiguity.

    Iterates headers case-insensitively for ``content-type``; strips all
    parameters (``; charset=utf-8``, ``; boundary=...``). Returns:

    * The bare lowercase MIME type (e.g. ``"text/html"``) on success.
    * ``None`` if the header is absent, appears more than once (two keys
      that differ only in casing both match), or the resulting bare type is
      empty.
    """
    ct_values = [v for k, v in headers.items() if k.lower() == "content-type"]
    if len(ct_values) != 1:
        # Missing or ambiguous (duplicate keys with different casing) → fail closed.
        return None
    raw = ct_values[0].strip()
    if not raw:
        return None
    # Split on the first ";" to strip parameters (charset=utf-8, boundary=…)
    bare = raw.split(";", 1)[0].strip().lower()
    return bare if bare else None


# ---------------------------------------------------------------------------
# inspect_response — the pure inspection callable
# ---------------------------------------------------------------------------


def inspect_response(
    response: EgressResponse,
    policy: ResponsePolicy,
) -> _Proceed | _SoftRefusal | _CanaryHit:
    """Inspect a raw T3 ``EgressResponse`` against the given ``ResponsePolicy``.

    **Order (load-bearing)**:

    1. Canary scan on raw bytes (byte-lossless latin-1 decode for the
       :class:`~alfred.security.canary_matcher.CanaryMatcher`).
    2. MIME-type check (fail closed on missing/garbage ``Content-Type``).
    3. Size cap check.
    4. → :class:`_Proceed`.

    **PURE**: NEVER raises, NEVER performs I/O, NEVER writes.  Returns one of
    the three verdict dataclasses.
    """
    # Step 1: Canary scan (raw bytes decoded to str for the string-based matcher).
    #
    # SECURITY (G7-2.5 C12): decode latin-1 (byte-LOSSLESS — every byte 0-255 maps
    # to one code point, never raises). A lossy ``errors="replace"`` decode collapses
    # each invalid byte sequence to a single U+FFFD, which can MERGE byte-adjacent
    # tokens and let a canary that sits next to invalid-UTF-8 bytes slip the matcher.
    # Canary tokens are ASCII, so latin-1 preserves them exactly for the match.
    if policy.canary is not None:
        decoded_for_canary = response.body.decode("latin-1")
        if policy.canary.first_match(decoded_for_canary) is not None:
            return _CanaryHit()

    # Step 2: MIME-type check — fail closed on missing/duplicate/garbage.
    mime = _parse_content_type(response.headers)
    if mime is None or mime not in policy.mime_allowlist:
        return _SoftRefusal(reason="cannot_extract", subject_token="mime_type_not_allowed")  # noqa: S106

    # Step 3: Size cap.
    if len(response.body) > policy.max_bytes:
        return _SoftRefusal(reason="cannot_extract", subject_token="size_limit_exceeded")  # noqa: S106

    return _Proceed()


__all__ = [
    "InboundCanaryTripped",
    "ResponsePolicy",
    "_CanaryHit",
    "_Proceed",
    "_SoftRefusal",
    "_host_only",
    "inspect_response",
]
