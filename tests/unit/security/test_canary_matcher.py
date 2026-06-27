"""Pure :class:`CanaryMatcher` token-matcher (Spec C §4.2, epic #333).

The matcher is the ONE shared canary-token matching primitive — the inbound
``InboundCanaryScanner`` (plugin-host side) and the outbound gateway DLP pass
both compile + search through it, so there is a single ``re.escape`` +
``IGNORECASE`` compile site (DRY). It is PURE: no Redis, no content store, no
I/O — it takes a decoded ``str`` and returns the matched token value or ``None``.
"""

from __future__ import annotations

import dataclasses

import pytest

from alfred.security.canary_matcher import CanaryMatcher, CanaryToken


def test_planted_token_returns_its_value() -> None:
    matcher = CanaryMatcher(tokens=[CanaryToken("CANARY-TOKEN-12345")])
    assert matcher.first_match("body with CANARY-TOKEN-12345 inside") == "CANARY-TOKEN-12345"


def test_clean_text_returns_none() -> None:
    matcher = CanaryMatcher(tokens=[CanaryToken("CANARY-TOKEN-12345")])
    assert matcher.first_match("nothing to see here") is None


def test_match_is_case_insensitive() -> None:
    # An attacker lowercasing a well-known canary must still trip; the matched
    # VALUE returned is the registered (canonical) token, not the body's casing.
    matcher = CanaryMatcher(tokens=[CanaryToken("CANARY-TOKEN-12345")])
    assert matcher.first_match("see canary-token-12345 here") == "CANARY-TOKEN-12345"


def test_first_registered_matching_token_wins() -> None:
    # Registration order wins: with MULTIPLE registered tokens present in the text,
    # first_match returns the EARLIEST-registered one (B before C), not the one that
    # appears first positionally (CR review). Mirrors InboundCanaryScanner's loop.
    matcher = CanaryMatcher(
        tokens=[CanaryToken("SECRET-A"), CanaryToken("SECRET-B"), CanaryToken("SECRET-C")]
    )
    # Text contains C earlier positionally and B later, but B is registered first.
    assert matcher.first_match("SECRET-C appears, then SECRET-B") == "SECRET-B"


def test_empty_token_set_never_matches() -> None:
    matcher = CanaryMatcher(tokens=[])
    assert matcher.first_match("any content at all") is None


def test_regex_metacharacters_in_token_are_escaped_literal() -> None:
    # A token with regex metachars matches literally (re.escape), so it does NOT
    # behave as a pattern (e.g. ``.`` is a literal dot, not "any char").
    matcher = CanaryMatcher(tokens=[CanaryToken("a.b+c")])
    assert matcher.first_match("contains a.b+c literally") == "a.b+c"
    assert matcher.first_match("contains aXbZZc") is None


def test_match_within_replacement_char_noise() -> None:
    # The scanner decodes binary bodies with errors='replace' before calling the
    # matcher; a token surrounded by U+FFFD replacement chars must still match.
    matcher = CanaryMatcher(tokens=[CanaryToken("CANARY-BLOCKED")])
    noisy = "�� CANARY-BLOCKED ��"
    assert matcher.first_match(noisy) == "CANARY-BLOCKED"


@pytest.mark.parametrize("blank", ["", " ", "\t", "\n", "\r\n\t "])
def test_canary_token_rejects_blank_value(blank: str) -> None:
    # CanaryToken's __post_init__ guard: a blank token compiles to a pattern that
    # matches every body — fail at construction (PRD §7.6), never at first scan.
    with pytest.raises(ValueError, match="must not be blank"):
        CanaryToken(blank)


def test_canary_token_is_frozen() -> None:
    token = CanaryToken("VALUE")
    with pytest.raises(dataclasses.FrozenInstanceError):
        token.value = "MUTATED"  # type: ignore[misc]
