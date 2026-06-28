"""Unit tests for the pre-extract response-inspection seam (Task 4, #333).

These tests exercise ``inspect_response`` and its verdict union.  Key
design properties asserted:

1. PURE — ``inspect_response`` NEVER raises and NEVER writes (side-effect-free).
2. Verdict order: canary FIRST, then MIME, then size.
3. Canary detected on raw bytes (invalid-UTF-8 surroundings do not hide it).
4. MIME parsed case-insensitively; charset/boundary params stripped.
5. Fail-closed on missing, duplicate, or garbage Content-Type.
6. ``_SoftRefusal`` carries distinct subject tokens for the audit pivot.
7. ``InboundCanaryTripped`` is payload-blind (no body/Content-Type in message).
"""

from __future__ import annotations

from typing import Any

import pytest

from alfred.egress.relay_protocol import EgressResponse
from alfred.egress.response_inspection import (
    InboundCanaryTripped,
    ResponsePolicy,
    _CanaryHit,
    _host_only,
    _Proceed,
    _SoftRefusal,
    inspect_response,
)
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALLOWED_MIMES: frozenset[str] = frozenset({"text/html", "text/plain", "application/json"})
_MAX_BYTES = 1024


def _make_policy(
    *,
    mime_allowlist: frozenset[str] = _ALLOWED_MIMES,
    max_bytes: int = _MAX_BYTES,
    canary: CanaryMatcher | None = None,
) -> ResponsePolicy:
    return ResponsePolicy(mime_allowlist=mime_allowlist, max_bytes=max_bytes, canary=canary)


def _make_response(
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: bytes = b"hello",
) -> EgressResponse:
    return EgressResponse(
        status=status,
        headers=headers if headers is not None else {"Content-Type": "text/html"},
        body=body,
    )


def _make_canary(token: str = "SECRET-CANARY-ABC123") -> CanaryMatcher:  # noqa: S107
    return CanaryMatcher(tokens=[CanaryToken(value=token)])


# ---------------------------------------------------------------------------
# Test 1 — allowed MIME type under cap → _Proceed
# ---------------------------------------------------------------------------


def test_allowed_mime_under_cap_proceeds() -> None:
    """A text/html response within the size cap passes all checks."""
    policy = _make_policy()
    response = _make_response(headers={"Content-Type": "text/html"}, body=b"<html></html>")
    result = inspect_response(response, policy)
    assert isinstance(result, _Proceed)


# ---------------------------------------------------------------------------
# Test 2 — disallowed MIME → _SoftRefusal("mime_type_not_allowed")
# ---------------------------------------------------------------------------


def test_disallowed_mime_refused() -> None:
    """A disallowed MIME type produces _SoftRefusal with mime_type_not_allowed."""
    policy = _make_policy()
    response = _make_response(headers={"Content-Type": "application/octet-stream"}, body=b"binary")
    result = inspect_response(response, policy)
    assert isinstance(result, _SoftRefusal)
    assert result.reason == "cannot_extract"
    assert result.subject_token == "mime_type_not_allowed"  # noqa: S105


# ---------------------------------------------------------------------------
# Test 3 — body over max_bytes → _SoftRefusal("size_limit_exceeded")
# ---------------------------------------------------------------------------


def test_body_over_max_bytes_refused() -> None:
    """A body exceeding max_bytes produces _SoftRefusal with size_limit_exceeded."""
    policy = _make_policy(max_bytes=10)
    response = _make_response(body=b"X" * 11)
    result = inspect_response(response, policy)
    assert isinstance(result, _SoftRefusal)
    assert result.reason == "cannot_extract"
    assert result.subject_token == "size_limit_exceeded"  # noqa: S105


# ---------------------------------------------------------------------------
# Test 4 — missing Content-Type → _SoftRefusal (fail closed)
# ---------------------------------------------------------------------------


def test_missing_content_type_refused() -> None:
    """A response with no Content-Type header fails closed → _SoftRefusal."""
    policy = _make_policy()
    response = _make_response(headers={}, body=b"hello")
    result = inspect_response(response, policy)
    assert isinstance(result, _SoftRefusal)
    assert result.subject_token == "mime_type_not_allowed"  # noqa: S105


# ---------------------------------------------------------------------------
# Test 5 — garbage/empty Content-Type → _SoftRefusal (fail closed)
# ---------------------------------------------------------------------------


def test_empty_content_type_refused() -> None:
    """An empty Content-Type value fails closed → _SoftRefusal."""
    policy = _make_policy()
    response = _make_response(headers={"Content-Type": ""}, body=b"hello")
    result = inspect_response(response, policy)
    assert isinstance(result, _SoftRefusal)
    assert result.subject_token == "mime_type_not_allowed"  # noqa: S105


def test_whitespace_only_content_type_refused() -> None:
    """A whitespace-only Content-Type value fails closed → _SoftRefusal."""
    policy = _make_policy()
    response = _make_response(headers={"Content-Type": "   "}, body=b"hello")
    result = inspect_response(response, policy)
    assert isinstance(result, _SoftRefusal)
    assert result.subject_token == "mime_type_not_allowed"  # noqa: S105


# ---------------------------------------------------------------------------
# Test 6 — charset stripped → _Proceed for text/html; charset=utf-8
# ---------------------------------------------------------------------------


def test_charset_parameter_stripped_proceeds() -> None:
    """A Content-Type with charset parameter passes after stripping the parameter."""
    policy = _make_policy()
    response = _make_response(
        headers={"Content-Type": "text/html; charset=utf-8"}, body=b"<p>hi</p>"
    )
    result = inspect_response(response, policy)
    assert isinstance(result, _Proceed)


def test_mixed_case_content_type_proceeds() -> None:
    """Content-Type is parsed case-insensitively; TEXT/HTML → text/html."""
    policy = _make_policy()
    response = _make_response(
        headers={"content-type": "TEXT/HTML; Charset=UTF-8"}, body=b"<p>hi</p>"
    )
    result = inspect_response(response, policy)
    assert isinstance(result, _Proceed)


# ---------------------------------------------------------------------------
# Test 7 — duplicate Content-Type (same-semantic, different-cased key) → fail closed
# ---------------------------------------------------------------------------


def test_duplicate_content_type_key_refused() -> None:
    """Two Content-Type entries (different casing → both seen by iteration) → _SoftRefusal."""
    # dict with two semantically-equivalent-but-differently-cased keys
    policy = _make_policy()
    response = _make_response(
        headers={"content-type": "text/html", "Content-Type": "application/json"},
        body=b"hello",
    )
    result = inspect_response(response, policy)
    assert isinstance(result, _SoftRefusal)
    assert result.subject_token == "mime_type_not_allowed"  # noqa: S105


# ---------------------------------------------------------------------------
# Test 8 — canary hit → _CanaryHit (even when MIME/size would pass)
# ---------------------------------------------------------------------------


def test_canary_hit_before_mime_and_size_checks() -> None:
    """Canary is checked FIRST — a hit overrides a passing MIME and size."""
    token = "MY-SECRET-CANARY-12345"  # noqa: S105
    canary = _make_canary(token)
    policy = _make_policy(canary=canary)
    # MIME and size would both pass; canary token in body
    body = f"<html>This contains the token: {token}</html>".encode()
    response = _make_response(headers={"Content-Type": "text/html"}, body=body)
    result = inspect_response(response, policy)
    assert isinstance(result, _CanaryHit)


def test_canary_case_insensitive_hit() -> None:
    """CanaryMatcher uses IGNORECASE; a lowercase variant of the canary still trips."""
    token = "CANARY-XYZ-9999"  # noqa: S105
    canary = _make_canary(token)
    policy = _make_policy(canary=canary)
    body = f"response contains: {token.lower()}".encode()
    response = _make_response(headers={"Content-Type": "text/html"}, body=body)
    result = inspect_response(response, policy)
    assert isinstance(result, _CanaryHit)


# ---------------------------------------------------------------------------
# Test 9 — canary on raw bytes (invalid UTF-8 surroundings do not hide it)
# ---------------------------------------------------------------------------


def test_canary_detected_through_invalid_utf8_surroundings() -> None:
    """Canary token survives errors="replace" decoding of invalid byte sequences.

    The body contains the canary embedded in invalid UTF-8 bytes.  The
    errors="replace" decode replaces the bad bytes with U+FFFD but preserves
    the ASCII canary token.
    """
    token = "CANARY-BYTES-TEST"  # noqa: S105
    canary = _make_canary(token)
    policy = _make_policy(canary=canary)
    # Surround the ASCII canary with invalid UTF-8 bytes.
    body = b"\xff\xfe" + token.encode("ascii") + b"\xc0\x80"
    response = _make_response(headers={"Content-Type": "text/html"}, body=body)
    result = inspect_response(response, policy)
    assert isinstance(result, _CanaryHit)


# ---------------------------------------------------------------------------
# Test 10 — canary=None → no canary check
# ---------------------------------------------------------------------------


def test_no_canary_matcher_proceeds_on_allowed_mime() -> None:
    """When canary=None the canary stage is skipped entirely."""
    policy = _make_policy(canary=None)
    response = _make_response(headers={"Content-Type": "text/html"}, body=b"content")
    result = inspect_response(response, policy)
    assert isinstance(result, _Proceed)


# ---------------------------------------------------------------------------
# Test 11 — exact max_bytes boundary
# ---------------------------------------------------------------------------


def test_body_exactly_at_max_bytes_proceeds() -> None:
    """A body whose length equals max_bytes is NOT refused."""
    policy = _make_policy(max_bytes=5)
    response = _make_response(headers={"Content-Type": "text/html"}, body=b"XXXXX")
    result = inspect_response(response, policy)
    assert isinstance(result, _Proceed)


def test_body_one_over_max_bytes_refused() -> None:
    """A body of length max_bytes + 1 is refused."""
    policy = _make_policy(max_bytes=5)
    response = _make_response(headers={"Content-Type": "text/html"}, body=b"XXXXXY")
    result = inspect_response(response, policy)
    assert isinstance(result, _SoftRefusal)
    assert result.subject_token == "size_limit_exceeded"  # noqa: S105


# ---------------------------------------------------------------------------
# Test 12 — PURITY: inspect_response NEVER raises, regardless of input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "response_kwargs,policy_kwargs",
    [
        # Garbage headers value
        ({"headers": {"content-type": ";;;;"}, "body": b"hi"}, {}),
        # Binary body with no valid UTF-8
        ({"headers": {"Content-Type": "text/html"}, "body": bytes(range(256))}, {}),
        # Empty body
        ({"headers": {"Content-Type": "text/html"}, "body": b""}, {}),
        # Canary token in all-invalid-bytes body
        (
            {"headers": {"Content-Type": "text/html"}, "body": bytes(range(128, 256))},
            {"canary": _make_canary("TEST")},
        ),
        # Both MIME and canary present
        (
            {"headers": {"Content-Type": "text/html"}, "body": b"TEST"},
            {"canary": _make_canary("TEST")},
        ),
    ],
)
def test_inspect_response_never_raises(
    response_kwargs: dict[str, Any],
    policy_kwargs: dict[str, Any],
) -> None:
    """inspect_response must NEVER raise, even on adversarial inputs."""
    policy = _make_policy(**policy_kwargs)
    response = _make_response(**response_kwargs)
    # Must not raise; return value is _Proceed | _SoftRefusal | _CanaryHit
    result = inspect_response(response, policy)
    assert isinstance(result, (_Proceed, _SoftRefusal, _CanaryHit))


# ---------------------------------------------------------------------------
# Test 13 — InboundCanaryTripped is payload-blind
# ---------------------------------------------------------------------------


def test_inbound_canary_tripped_is_payload_blind() -> None:
    """InboundCanaryTripped carries destination+egress_id only; no body/Content-Type."""
    exc = InboundCanaryTripped(destination="example.com", egress_id="eid-abc123")
    msg = str(exc)
    # message must contain the destination and egress_id
    assert "example.com" in msg
    assert "eid-abc123" in msg
    # attributes accessible for the dispatcher
    assert exc.destination == "example.com"
    assert exc.egress_id == "eid-abc123"
    assert exc.reason == "inbound_canary_tripped"


def test_inbound_canary_tripped_has_no_body_content() -> None:
    """InboundCanaryTripped message must not contain the raw body or Content-Type."""
    body_content = "SENSITIVE_BODY_CONTENT_123"
    content_type = "application/evil"
    exc = InboundCanaryTripped(destination="target.com", egress_id="eid-xyz")
    msg = str(exc)
    assert body_content not in msg
    assert content_type not in msg


# ---------------------------------------------------------------------------
# Test 14 — _host_only is host-ONLY: userinfo + port + path never leak (CR-3)
# ---------------------------------------------------------------------------


def test_host_only_strips_userinfo_and_port() -> None:
    """A URL with ``user:pass@host:port`` collapses to the bare host — the
    ``netloc`` (which carries attacker userinfo + port) is NEVER returned."""
    host = _host_only("https://alice:hunter2@evil.example.com:8443/path?q=SECRET")
    assert host == "evil.example.com"
    # The userinfo / port / path / query must NOT survive into the audit subject.
    assert "alice" not in host
    assert "hunter2" not in host
    assert "8443" not in host
    assert "SECRET" not in host


def test_host_only_no_scheme_userinfo_still_stripped() -> None:
    """Even a scheme-less ``//user@host:port`` form returns host only."""
    assert _host_only("//bob:pw@internal.example:9000/x") == "internal.example"


def test_host_only_unparseable_collapses_to_sentinel() -> None:
    """A URL with no parseable hostname collapses to the payload-blind sentinel —
    it never falls back to a userinfo-bearing ``netloc``."""
    assert _host_only("not a url at all") == "<invalid-url>"


# ---------------------------------------------------------------------------
# Test 15 — canary scan is byte-LOSSLESS (latin-1), not lossy errors="replace"
# ---------------------------------------------------------------------------


def test_canary_with_nonascii_byte_detected_under_lossless_decode() -> None:
    """A canary whose latin-1 bytes a lossy UTF-8 decode would mangle is STILL hit.

    The canary contains a non-ASCII char (``Ö`` → latin-1 byte ``0xD6``, a UTF-8
    lead byte). Embedded as raw latin-1 bytes, a lossy ``errors="replace"`` UTF-8
    decode collapses the lead byte to ``U+FFFD`` (``"T\\ufffdKEN"``) and MISSES the
    match. The byte-lossless latin-1 decode (G7-2.5 C12) preserves it, so the
    canary trips.
    """
    token = "CANARY-TÖKEN-001"  # noqa: S105 — test sentinel, not a credential
    canary = _make_canary(token)
    policy = _make_policy(canary=canary)
    body = ("prefix " + token + " suffix").encode("latin-1")
    response = _make_response(headers={"Content-Type": "text/html"}, body=body)
    result = inspect_response(response, policy)
    assert isinstance(result, _CanaryHit)

    # Document the bug the fix closes: the OLD lossy decode WOULD have missed it.
    assert canary.first_match(body.decode("utf-8", errors="replace")) is None


# ---------------------------------------------------------------------------
# Test 16 — canary precedence: a canary in an oversized + disallowed-MIME body
#           still wins (canary checked FIRST) (CR-7)
# ---------------------------------------------------------------------------


def test_canary_precedence_over_oversized_and_disallowed_mime() -> None:
    """Canary is checked BEFORE MIME and size — a body that is ALSO oversized AND
    of a disallowed MIME still returns ``_CanaryHit`` (the security-event ordering)."""
    token = "PRECEDENCE-CANARY-9"  # noqa: S105 — test sentinel, not a credential
    canary = _make_canary(token)
    # max_bytes tiny + MIME off the allowlist: both would refuse, but canary wins.
    policy = _make_policy(mime_allowlist=frozenset({"text/html"}), max_bytes=4, canary=canary)
    body = (token + " " + "X" * 200).encode()
    response = _make_response(headers={"Content-Type": "application/octet-stream"}, body=body)
    result = inspect_response(response, policy)
    assert isinstance(result, _CanaryHit)


# ---------------------------------------------------------------------------
# Test 17 — mime_allowlist is lowercased at ResponsePolicy construction (CR-2)
# ---------------------------------------------------------------------------


def test_mime_allowlist_lowercased_at_construction() -> None:
    """An operator-configured ``"Text/HTML"`` matches a ``text/html`` response —
    the allowlist is normalised to lowercase at construction so casing in config
    never diverges from the lowercased parsed Content-Type."""
    policy = ResponsePolicy(
        mime_allowlist=frozenset({"Text/HTML", "Application/JSON"}),
        max_bytes=1024,
        canary=None,
    )
    # The stored allowlist is lowercased.
    assert policy.mime_allowlist == frozenset({"text/html", "application/json"})
    # A lowercase response Content-Type now matches the mixed-case config entry.
    response = _make_response(headers={"Content-Type": "text/html"}, body=b"<p>hi</p>")
    assert isinstance(inspect_response(response, policy), _Proceed)


def test_mime_allowlist_non_collection_passes_through_to_pydantic() -> None:
    """A non-collection ``mime_allowlist`` is left untouched by the lowercasing
    normaliser so Pydantic raises a clean ValidationError (rather than the
    validator masking the bad input)."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        ResponsePolicy(mime_allowlist=123, max_bytes=1024, canary=None)  # type: ignore[arg-type]
