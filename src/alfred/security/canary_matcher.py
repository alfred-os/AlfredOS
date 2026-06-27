"""Shared pure canary-token matcher (Spec C §4.2, epic #333).

The ONE canary-token matching primitive across AlfredOS:

* the inbound :class:`alfred.plugins.web_fetch.canary_scanner.InboundCanaryScanner`
  (plugin-host side, reads the content store and scans the T3 body), and
* the outbound gateway DLP second pass (``OutboundDlp`` stage 3 + the gateway
  ``EgressRelay``) which scans the redacted egress body,

both compile + search through :class:`CanaryMatcher`, so the ``re.escape`` +
``IGNORECASE`` compile site exists exactly once (DRY).

The matcher is PURE — it takes a decoded ``str`` and returns the matched token
value or ``None``; it does NO I/O (no Redis, no content store) and holds no
mutable state after construction. It is the lean home of :class:`CanaryToken`
too, so the gateway can build a matcher from operator config WITHOUT importing
the web_fetch plugin's Redis-backed scanner module (``canary_scanner.py``
re-exports :class:`CanaryToken` for its existing importers).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CanaryToken:
    """A single canary token string to scan for.

    Frozen on purpose: operators register the vocabulary once at bootstrap;
    in-flight mutation would be a footgun (a compromised subscriber rotating the
    registry mid-process would invalidate the spec §7.6 guarantee for any scan
    already in flight).
    """

    value: str

    def __post_init__(self) -> None:
        # PRD §7.6 treats this registry as operator-supplied input, and
        # ``re.escape("")`` produces a pattern that matches every body at offset
        # 0 — one blank entry would trip the canary path on benign content.
        # Whitespace-only is the same hazard class (``re.escape(" ")`` matches
        # every body that contains a space). Reject at construction so the
        # misconfiguration is caught at bootstrap (loud) rather than at first
        # scan (silent + impossible to attribute back to the registry load).
        if not self.value.strip():
            msg = (
                "CanaryToken.value must not be blank — empty or whitespace-only "
                "tokens compile to patterns that match every body and would "
                "trip the canary path on all content (PRD §7.6)."
            )
            raise ValueError(msg)


class CanaryMatcher:
    """Compile a canary vocabulary once; report the first matching token.

    The token registry is an operator-controlled vocabulary, not user input, so
    ``IGNORECASE`` never widens past what the operator authorised (and an
    attacker who lowercases a well-known canary still trips). Patterns are
    ``re.escape``-d so a token containing regex metacharacters matches LITERALLY.
    """

    def __init__(self, *, tokens: Sequence[CanaryToken]) -> None:
        # ``(pattern, value)`` pairs so ``first_match`` can return the canonical
        # registered token VALUE (for the audit row) rather than the escaped
        # pattern or the body's (possibly re-cased) substring.
        self._patterns: tuple[tuple[re.Pattern[str], str], ...] = tuple(
            (re.compile(re.escape(token.value), re.IGNORECASE), token.value) for token in tokens
        )

    def first_match(self, text: str) -> str | None:
        """Return the first registered token whose pattern appears in ``text``.

        Iterates in registration order and returns that token's canonical value,
        or ``None`` when no token matches. Pure: no I/O, no mutation.
        """
        for pattern, value in self._patterns:
            if pattern.search(text):
                return value
        return None


__all__ = ["CanaryMatcher", "CanaryToken"]
