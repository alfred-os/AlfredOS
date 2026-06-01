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
    WebFetchMimeTypeNotAllowed,
    WebFetchRateLimited,
    WebFetchSizeLimitExceeded,
    WebFetchTlsError,
)


def test_web_fetch_error_is_alfred_error() -> None:
    """``WebFetchError`` roots the operational tree under ``AlfredError``."""
    assert issubclass(WebFetchError, AlfredError)


def test_domain_not_allowed_is_web_fetch_error() -> None:
    assert issubclass(WebFetchDomainNotAllowed, WebFetchError)


def test_tls_error_is_web_fetch_error() -> None:
    assert issubclass(WebFetchTlsError, WebFetchError)


def test_rate_limited_is_web_fetch_error() -> None:
    assert issubclass(WebFetchRateLimited, WebFetchError)


def test_mime_type_not_allowed_is_web_fetch_error() -> None:
    assert issubclass(WebFetchMimeTypeNotAllowed, WebFetchError)


def test_size_limit_exceeded_is_web_fetch_error() -> None:
    assert issubclass(WebFetchSizeLimitExceeded, WebFetchError)


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


def test_tls_error_carries_url_and_detail() -> None:
    err = WebFetchTlsError(url="https://bad.example/", detail="cert verify failed")
    assert err.url == "https://bad.example/"
    assert err.detail == "cert verify failed"
    # The string surface must include the URL so operators can correlate
    # with the originating request without parsing the structlog row.
    assert "https://bad.example/" in str(err)


def test_rate_limited_carries_bucket_attr() -> None:
    err = WebFetchRateLimited("per_domain")
    assert err.bucket == "per_domain"
    assert "per_domain" in str(err)


def test_mime_type_not_allowed_carries_mime_attr() -> None:
    err = WebFetchMimeTypeNotAllowed("application/octet-stream")
    assert err.mime_type == "application/octet-stream"
    assert "application/octet-stream" in str(err)


def test_size_limit_exceeded_carries_size_attrs() -> None:
    err = WebFetchSizeLimitExceeded(size_bytes=10_485_760, limit_bytes=5_242_880)
    assert err.size_bytes == 10_485_760
    assert err.limit_bytes == 5_242_880


def test_canary_tripped_carries_source_url_and_handle_id() -> None:
    err = WebFetchCanaryTripped(source_url="https://attacker.test/page", handle_id="abc-123")
    assert err.source_url == "https://attacker.test/page"
    assert err.handle_id == "abc-123"


@pytest.mark.parametrize(
    "exc",
    [
        WebFetchDomainNotAllowed("d.example"),
        WebFetchTlsError(url="https://x.example", detail="boom"),
        WebFetchRateLimited("per_user"),
        WebFetchMimeTypeNotAllowed("text/x-evil"),
        WebFetchSizeLimitExceeded(size_bytes=1, limit_bytes=0),
        WebFetchCanaryTripped(source_url="https://x.example", handle_id="id"),
    ],
)
def test_every_exception_is_raise_able(exc: Exception) -> None:
    """Each error is a real ``Exception``: ``raise`` must round-trip through
    ``pytest.raises`` without surprises (no abstract / metaclass mishaps).
    """
    with pytest.raises(type(exc)):
        raise exc
