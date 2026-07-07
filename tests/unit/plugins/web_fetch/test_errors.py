"""Tests for the ``WebFetchError`` hierarchy (spec §7.10).

The hierarchy splits operational errors (``WebFetchError`` family) from
the security-event class (``WebFetchCanaryTripped``). The distinction is
load-bearing: the orchestrator catches ``WebFetchError`` and returns a
user-visible message; it treats ``WebFetchCanaryTripped`` as a security
incident requiring quarantine + audit + alert. Tests pin the
``not issubclass(...)`` invariant so a future refactor cannot collapse
the two hierarchies without tripping the test.
"""

from __future__ import annotations

import pytest

from alfred.errors import AlfredError
from alfred.plugins.web_fetch.errors import (
    WebFetchActionTimeout,
    WebFetchCanaryTripped,
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchRateLimited,
)


def test_web_fetch_error_is_alfred_error() -> None:
    """``WebFetchError`` roots the operational tree under ``AlfredError``."""
    assert issubclass(WebFetchError, AlfredError)


def test_domain_not_allowed_is_web_fetch_error() -> None:
    assert issubclass(WebFetchDomainNotAllowed, WebFetchError)


def test_rate_limited_is_web_fetch_error() -> None:
    assert issubclass(WebFetchRateLimited, WebFetchError)


def test_action_timeout_is_web_fetch_error() -> None:
    """Positive pin (FOLD-LAYER FIX-4) -- contrast the negative
    ``test_canary_tripped_is_NOT_web_fetch_error`` pin below.
    ``WebFetchActionTimeout`` deliberately DOES subclass ``WebFetchError``:
    the recoverable-return semantics fit (an action-deadline timeout is an
    operational condition the orchestrator can surface and recover from),
    unlike the canary trip's halting security-event semantics. Because it
    IS a ``WebFetchError``, the ``dispatch_tool`` ``except`` arm ordering
    is load-bearing (see the class docstring in errors.py) -- this pin
    just fixes the taxonomy choice so a future refactor cannot silently
    move it out of the tree without tripping a test.
    """
    assert issubclass(WebFetchActionTimeout, WebFetchError)


def test_canary_tripped_is_NOT_web_fetch_error() -> None:  # noqa: N802 -- emphasis intentional; the NOT is load-bearing
    """SECURITY INVARIANT (spec §7.10): the canary trip is a security event,
    not an operational fetch error. Collapsing it into the operational tree
    would let a ``except WebFetchError`` arm swallow a canary trip.
    """
    assert not issubclass(WebFetchCanaryTripped, WebFetchError)
    assert issubclass(WebFetchCanaryTripped, AlfredError)


def test_domain_not_allowed_carries_domain_attr() -> None:
    err = WebFetchDomainNotAllowed("attacker.example.com")
    assert err.domain == "attacker.example.com"
    assert "attacker.example.com" in str(err)


def test_rate_limited_carries_bucket_attr() -> None:
    err = WebFetchRateLimited("per_domain")
    assert err.bucket == "per_domain"
    assert "per_domain" in str(err)


def test_canary_tripped_carries_source_url_and_handle_id() -> None:
    err = WebFetchCanaryTripped(source_url="https://attacker.test/page", handle_id="abc-123")
    assert err.source_url == "https://attacker.test/page"
    assert err.handle_id == "abc-123"


def test_web_fetch_action_timeout_carries_forensic_fields() -> None:
    exc = WebFetchActionTimeout(
        egress_id="d" * 64,
        destination_host="example.com",
        in_doubt=True,
        ledger_state="committed_no_response",
    )
    assert isinstance(exc, WebFetchError)  # taxonomy: catchable as WebFetchError
    assert exc.egress_id == "d" * 64
    assert exc.destination_host == "example.com"
    assert exc.in_doubt is True
    assert exc.ledger_state == "committed_no_response"
    # Message is a fixed operator string — it must NOT interpolate the forensic
    # data (host/egress_id) into the message body (audit hygiene).
    assert "example.com" not in str(exc)
    assert "d" * 64 not in str(exc)


@pytest.mark.parametrize(
    "exc",
    [
        WebFetchDomainNotAllowed("d.example"),
        WebFetchRateLimited("per_user"),
        WebFetchCanaryTripped(source_url="https://x.example", handle_id="id"),
        WebFetchActionTimeout(
            egress_id="e" * 64,
            destination_host="d.example",
            in_doubt=False,
            ledger_state=None,
        ),
    ],
)
def test_every_exception_is_raise_able(exc: Exception) -> None:
    """Each error is a real ``Exception``: ``raise`` must round-trip through
    ``pytest.raises`` without surprises (no abstract / metaclass mishaps).
    """
    with pytest.raises(type(exc)):
        raise exc


def test_dead_response_policy_error_classes_removed() -> None:
    """G7-2.5 re-home (#333): the response-policy error classes the deleted
    plugin subprocess raised are GONE.

    ``WebFetchMimeTypeNotAllowed`` / ``WebFetchSizeLimitExceeded`` /
    ``WebFetchRedirectRefused`` had NO live raiser after the re-home — the MIME
    and size refusals are now ``TypedRefusal(cannot_extract)`` from the C2 D1
    seam (``response_inspection``), and redirects are refused gateway-side
    (``EgressRelayDenyReason.UPSTREAM_REDIRECT_REFUSED``). Removing the dead
    classes also drops their attacker-``{mime_type}``-interpolating t() messages.
    This pins the removal so a future re-add fails loud.
    """
    import alfred.plugins.web_fetch as pkg
    from alfred.plugins.web_fetch import errors as errors_mod

    for name in (
        "WebFetchMimeTypeNotAllowed",
        "WebFetchSizeLimitExceeded",
        "WebFetchRedirectRefused",
    ):
        assert not hasattr(errors_mod, name), f"{name} should be removed from errors.py"
        assert name not in errors_mod.__all__, f"{name} should be off errors.__all__"
        assert name not in pkg.__all__, f"{name} should be off the package __all__"
