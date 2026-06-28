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


@pytest.mark.parametrize(
    "exc",
    [
        WebFetchDomainNotAllowed("d.example"),
        WebFetchRateLimited("per_user"),
        WebFetchCanaryTripped(source_url="https://x.example", handle_id="id"),
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
