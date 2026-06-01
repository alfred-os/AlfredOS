"""``WebFetchError`` hierarchy and the ``WebFetchCanaryTripped`` security
event (spec §7.10).

The hierarchy splits along two intentionally non-overlapping trees:

* :class:`WebFetchError` and its subclasses — *operational* errors. The
  fetch failed for a policy or network reason. The orchestrator catches
  these and surfaces a user-visible message.
* :class:`WebFetchCanaryTripped` — a *security event* under
  :class:`alfred.errors.AlfredError`. Collapsing the two trees would let
  an ``except WebFetchError`` arm silently swallow a canary trip, which
  is a release-blocker shape. The ``not issubclass`` invariant is pinned
  in :mod:`tests.unit.plugins.web_fetch.test_errors`.

Each operational error carries the structured attribute(s) the
``WEB_FETCH_FIELDS`` audit row records (``domain``, ``url``, ``bucket``,
``mime_type``, ``size_bytes``, ``limit_bytes``). The audit writer reads
typed exception attributes — never string-parses messages — so a future
i18n change to the message template cannot drift the audit row.

i18n: every operator-facing string routes through :func:`alfred.i18n.t`
per CLAUDE.md i18n rule #1. The catalog entries live under the ``web.*``
prefix; missing keys fall back to the key string itself so a partial
catalog still ships diagnosable text.
"""

from __future__ import annotations

from alfred.errors import AlfredError
from alfred.i18n import t


class WebFetchError(AlfredError):
    """Base class for operational web.fetch errors.

    Catch this to surface a recoverable user-facing message. Do NOT catch
    :class:`WebFetchCanaryTripped` through this arm — the canary-trip
    event is deliberately outside the operational tree (spec §7.10).
    """


class WebFetchDomainNotAllowed(WebFetchError):  # noqa: N818 -- name pinned by spec §7.10
    """The URL domain is not in the effective three-way allowlist.

    Effective = manifest ∩ operator config ∩ per-session (spec §7.4).
    The ``domain`` attribute is what the allowlist intersection refused;
    audit rows record it under ``WEB_FETCH_FIELDS["domain"]``.
    """

    def __init__(self, domain: str) -> None:
        super().__init__(t("web.fetch.error.domain_not_allowed", domain=domain))
        self.domain = domain


class WebFetchTlsError(WebFetchError):
    """TLS verification failed (spec §7.11).

    Production has no operator override — ``ALFRED_ENV=development`` is
    the only escape hatch and is gated by :class:`TlsPolicy` at
    construction time. The ``url`` and ``detail`` attributes are surfaced
    so operators can correlate with the originating request without
    parsing the structlog row.
    """

    def __init__(self, url: str, detail: str) -> None:
        super().__init__(t("web.fetch.error.tls_failure", url=url, detail=detail))
        self.url = url
        self.detail = detail


class WebFetchRateLimited(WebFetchError):  # noqa: N818 -- name pinned by spec §7.10
    """A rate-limit bucket refused the request (spec §7.7).

    ``bucket`` is one of ``"per_domain"`` / ``"per_user"`` /
    ``"daily_budget"`` — pinned by the Lua atomic check in
    :mod:`alfred.plugins.web_fetch.rate_limit`. Audit rows record it under
    ``WEB_FETCH_FIELDS["rate_limit_bucket"]``.
    """

    def __init__(self, bucket: str) -> None:
        super().__init__(t("web.fetch.error.rate_limited", bucket=bucket))
        self.bucket = bucket


class WebFetchMimeTypeNotAllowed(WebFetchError):  # noqa: N818 -- name pinned by spec §7.10
    """The response MIME type is not in the allowed set.

    Resolves spec §16 open question — the plugin host narrows the allowed
    MIME types at response time and refuses anything outside the manifest
    declaration. ``mime_type`` is the refused value.
    """

    def __init__(self, mime_type: str) -> None:
        super().__init__(t("web.fetch.error.mime_type_not_allowed", mime_type=mime_type))
        self.mime_type = mime_type


class WebFetchSizeLimitExceeded(WebFetchError):  # noqa: N818 -- name pinned by spec §7.10
    """The response body exceeded the configured size limit (default 5 MB).

    Both the actual byte count and the limit are carried so the audit row
    can record both — the limit changes via operator config, and a row
    that records only the actual size cannot be correlated with the
    policy in effect at request time.
    """

    def __init__(self, size_bytes: int, limit_bytes: int) -> None:
        super().__init__(
            t("web.fetch.error.size_limit_exceeded", size=size_bytes, limit=limit_bytes)
        )
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes


# NB: NOT a ``WebFetchError`` subclass. Spec §7.10 makes this distinction
# load-bearing — the orchestrator's operational-error arm must not catch
# canary trips.
class WebFetchCanaryTripped(AlfredError):  # noqa: N818 -- SECURITY EVENT, name pinned by spec §7.10
    """SECURITY EVENT: an operator-registered canary token was detected
    in fetched T3 content (spec §7.6).

    The plugin host quarantines the content handle (DELETE on the Redis
    key) BEFORE raising this exception, so the orchestrator can never
    dereference the trip'd content even if it tries.

    ``source_url`` and ``handle_id`` are recorded in the
    ``tool.web.fetch.canary_tripped`` audit row. The orchestrator treats
    this as a security incident: emit the audit row, quarantine the
    handle (already done by the scanner), alert the operator, and refuse
    the conversation turn.
    """

    def __init__(self, source_url: str, handle_id: str) -> None:
        super().__init__(t("security.canary_tripped", url=source_url, handle_id=handle_id))
        self.source_url = source_url
        self.handle_id = handle_id


__all__ = [
    "WebFetchCanaryTripped",
    "WebFetchDomainNotAllowed",
    "WebFetchError",
    "WebFetchMimeTypeNotAllowed",
    "WebFetchRateLimited",
    "WebFetchSizeLimitExceeded",
    "WebFetchTlsError",
]
