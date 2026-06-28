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
    WebFetchRedirectRefused,
    WebFetchSizeLimitExceeded,
)


def test_web_fetch_error_is_alfred_error() -> None:
    """``WebFetchError`` roots the operational tree under ``AlfredError``."""
    assert issubclass(WebFetchError, AlfredError)


def test_domain_not_allowed_is_web_fetch_error() -> None:
    assert issubclass(WebFetchDomainNotAllowed, WebFetchError)


def test_rate_limited_is_web_fetch_error() -> None:
    assert issubclass(WebFetchRateLimited, WebFetchError)


def test_mime_type_not_allowed_is_web_fetch_error() -> None:
    assert issubclass(WebFetchMimeTypeNotAllowed, WebFetchError)


def test_size_limit_exceeded_is_web_fetch_error() -> None:
    assert issubclass(WebFetchSizeLimitExceeded, WebFetchError)


def test_redirect_refused_is_web_fetch_error() -> None:
    """SSRF guard (spec §7.4): a refused 3xx is an operational error so the
    orchestrator's ``except WebFetchError`` arm surfaces it cleanly. Not a
    security event (no canary trip) — the upstream merely tried to widen
    via a redirect; refusal is the normal protocol response."""
    assert issubclass(WebFetchRedirectRefused, WebFetchError)


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


def test_mime_type_not_allowed_carries_mime_attr() -> None:
    err = WebFetchMimeTypeNotAllowed("application/octet-stream")
    assert err.mime_type == "application/octet-stream"
    assert "application/octet-stream" in str(err)


def test_size_limit_exceeded_carries_size_attrs() -> None:
    err = WebFetchSizeLimitExceeded(size_bytes=10_485_760, limit_bytes=5_242_880)
    assert err.size_bytes == 10_485_760
    assert err.limit_bytes == 5_242_880


def test_redirect_refused_carries_status_and_target_attrs() -> None:
    """Both fields are recorded verbatim on ``self.*`` so the audit
    row sees exactly where the redirect tried to point — silently
    dropping the target would weaken the SSRF audit trail.

    CR-146 major: the caller-visible ``str(err)`` deliberately does
    NOT interpolate ``redirect_target`` — the Location header is
    attacker-controlled and may carry signed query params or internal
    hostnames. Status code is safe to surface (numeric, low-entropy);
    redirect_target stays on the audit row only.
    """
    err = WebFetchRedirectRefused(status_code=302, redirect_target="http://10.0.0.1/internal")
    # Typed attrs preserved for the audit row.
    assert err.status_code == 302
    assert err.redirect_target == "http://10.0.0.1/internal"
    # Status code is operator-safe (low-entropy enum-like) and stays
    # in the user-facing message.
    assert "302" in str(err)
    # CR-146 major: target MUST NOT leak into the caller-visible string.
    assert "10.0.0.1" not in str(err)
    assert "/internal" not in str(err)


def test_canary_tripped_carries_source_url_and_handle_id() -> None:
    err = WebFetchCanaryTripped(source_url="https://attacker.test/page", handle_id="abc-123")
    assert err.source_url == "https://attacker.test/page"
    assert err.handle_id == "abc-123"


@pytest.mark.parametrize(
    "exc",
    [
        WebFetchDomainNotAllowed("d.example"),
        WebFetchRateLimited("per_user"),
        WebFetchMimeTypeNotAllowed("text/x-evil"),
        WebFetchSizeLimitExceeded(size_bytes=1, limit_bytes=0),
        WebFetchRedirectRefused(status_code=301, redirect_target="http://a.example/"),
        WebFetchCanaryTripped(source_url="https://x.example", handle_id="id"),
    ],
)
def test_every_exception_is_raise_able(exc: Exception) -> None:
    """Each error is a real ``Exception``: ``raise`` must round-trip through
    ``pytest.raises`` without surprises (no abstract / metaclass mishaps).
    """
    with pytest.raises(type(exc)):
        raise exc


def test_redirect_refused_is_re_exported_from_package() -> None:
    """``WebFetchRedirectRefused`` is part of the ``alfred.plugins.web_fetch``
    public surface (review finding ar-003).

    Every other ``WebFetch*`` operational error is re-exported from the
    package ``__init__``; the SSRF-guard redirect refusal sibling must be
    too. An asymmetric public surface forces downstream consumers
    (orchestrator ``except`` arms, integration tests, plugin authors)
    to know the deep leaf-module path for one error and the package path
    for the rest — a footgun that surfaces as ``ImportError`` only after
    the redirect-refusal path is exercised.

    The check pins both ``__all__`` membership (the documented contract)
    and ``getattr`` resolution (the runtime surface), and asserts the
    re-export is the SAME object as the leaf-module class so a future
    refactor cannot accidentally rebind it.
    """
    import alfred.plugins.web_fetch as pkg
    from alfred.plugins.web_fetch.errors import (
        WebFetchRedirectRefused as LeafRedirectRefused,
    )

    assert "WebFetchRedirectRefused" in pkg.__all__, (
        "alfred.plugins.web_fetch.__all__ missing 'WebFetchRedirectRefused' — "
        "public-surface asymmetry vs sibling WebFetch* errors (review ar-003)."
    )
    assert pkg.WebFetchRedirectRefused is LeafRedirectRefused, (
        "alfred.plugins.web_fetch.WebFetchRedirectRefused is not the same "
        "object as the leaf-module class — re-export accidentally rebound."
    )
