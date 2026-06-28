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

from alfred.audit.audit_row_schemas import RateLimitBucket

# Disputed-#1 (review pass): the canonical RateLimitBucket Literal lives
# in audit_row_schemas.py (Task 2). errors.py imports it so the bucket
# discriminator stays a single source of truth; SIEM/audit consumers
# never need to import errors.py for the closed vocabulary.
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


class WebFetchRedirectRefused(WebFetchError):  # noqa: N818 -- name pinned by spec §7.4
    """The upstream returned an HTTP 3xx redirect (spec §7.4 SSRF guard).

    The plugin subprocess refuses to follow redirects: an allowlisted
    endpoint could otherwise hand off to an internal-IP / non-allowlisted
    target via ``Location:``, silently widening the surface past the
    operator's three-way allowlist cap. The host can re-dispatch the
    redirect target through the full allowlist + rate-limit + audit
    machinery if it actually wants to follow.

    ``status_code`` carries the 3xx status (301 / 302 / 303 / 307 / 308)
    so audit rows can distinguish permanent-vs-temporary redirects;
    ``redirect_target`` is the upstream ``Location`` value, recorded
    verbatim so reviewers see exactly where the bypass attempt pointed.

    CR-146 major: the caller-visible message intentionally does NOT
    interpolate ``redirect_target`` — the Location header is attacker-
    controlled and may carry signed query params, internal hostnames,
    or metadata IPs. Leaking that string back to the requester (the
    typed ``WebFetchError`` surfaces to the caller per PRD §7.10) would
    hand SSRF forensics to the attacker. The full ``redirect_target``
    stays on ``self.redirect_target`` for the audit row (where the
    operator audience belongs).
    """

    def __init__(self, status_code: int, redirect_target: str) -> None:
        super().__init__(
            t(
                "web.fetch.error.redirect_refused",
                status_code=status_code,
            )
        )
        self.status_code = status_code
        self.redirect_target = redirect_target


class WebFetchTlsError(WebFetchError):
    """TLS verification failed (spec §7.11).

    TLS enforcement now originates at the gateway relay (G7-2b); this
    exception records a TLS-level failure surfaced by the relay in its
    deny/response envelope. The ``url`` and ``detail`` attributes are
    surfaced so operators can correlate with the originating request
    without parsing the structlog row.
    """

    def __init__(self, url: str, detail: str) -> None:
        super().__init__(t("web.fetch.error.tls_failure", url=url, detail=detail))
        self.url = url
        self.detail = detail


class WebFetchRateLimited(WebFetchError):  # noqa: N818 -- name pinned by spec §7.10
    """A rate-limit bucket refused the request (spec §7.7, §7.10).

    ``bucket`` is one of :data:`RateLimitBucket`. Audit rows record it under
    ``WEB_FETCH_FIELDS["rate_limit_bucket"]``. The ``handle_cap`` bucket
    uses a dedicated i18n catalog entry (``web.fetch.error.rate_limited.handle_cap``)
    that points operators at ``web_fetch.max_concurrent_handles_per_user``;
    the other three use the generic ``web.fetch.error.rate_limited`` template.
    """

    def __init__(self, bucket: RateLimitBucket) -> None:
        if bucket == "handle_cap":
            super().__init__(t("web.fetch.error.rate_limited.handle_cap"))
        else:
            super().__init__(t("web.fetch.error.rate_limited", bucket=bucket))
        self.bucket: RateLimitBucket = bucket


class WebFetchHandleIdMismatch(WebFetchError):  # noqa: N818 -- spec §3 host equality check
    """The plugin returned a ContentHandle whose id differs from the
    host-side pre-minted reservation (spec §3).

    Defence-in-depth: a buggy or compromised plugin could write the body
    under a different Redis key, decorrelating the cap counter from real
    Redis memory pressure. The dispatcher raises this typed exception,
    releases the cap slot, and emits a ``dlp_scan_result="handle_id_mismatch"``
    audit row before re-raising.

    The caller-visible message intentionally does NOT interpolate
    ``expected`` / ``got`` — leaking pre-mint metadata back to the caller
    tells an attacker the host-pre-mint shape. Forensic detail stays on
    ``self.expected`` / ``self.got`` for the audit row (operator audience).
    """

    def __init__(self, expected: str, got: str) -> None:
        super().__init__(t("web.fetch.error.handle_id_mismatch"))
        self.expected = expected
        self.got = got


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


class WebFetchInternalIPRefused(WebFetchError):  # noqa: N818 -- name pinned by sec-pr-s3-5-003
    """The URL's hostname resolved to an internal address (sec-pr-s3-5-003).

    DNS-rebinding / cloud-metadata SSRF / RFC1918 internal-IP attacks
    that the URL-name allowlist alone cannot block: an upstream resolver
    that hands back ``10.0.0.1`` / ``169.254.169.254`` / ``127.0.0.1`` for
    an allowlisted hostname would otherwise let the fetcher reach an
    internal endpoint. Since G7-2b this guard lives in the gateway egress
    relay (``EgressRelayDenyReason.RESOLVED_IP_NOT_GLOBAL``); the
    connectivity-free core (Spec C) no longer resolves DNS. This exception
    is raised when the relay returns that deny reason.

    ``url`` is the URL the caller asked for; ``resolved_ip`` is the
    offending IP address the resolver returned (empty string when the
    refusal happens before resolution — e.g. ``no_hostname`` / DNS
    failure); ``reason`` is the closed-vocabulary refusal class so
    audit rows can pivot on the attack shape.

    CR-146 major: the caller-visible message intentionally does NOT
    interpolate ``url`` or ``resolved_ip`` — leaking the resolved IP
    back to the requester tells an SSRF attacker exactly which
    internal address the resolver returned, weaponising the refusal
    into a metadata-IP / RFC1918 oracle. The audit row still records
    both fields off ``self.url`` / ``self.resolved_ip`` (operator
    audience).
    """

    def __init__(self, url: str, resolved_ip: str, reason: str) -> None:
        super().__init__(t("web.fetch.error.internal_ip_refused"))
        self.url = url
        self.resolved_ip = resolved_ip
        self.reason = reason


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
    "WebFetchHandleIdMismatch",
    "WebFetchInternalIPRefused",
    "WebFetchMimeTypeNotAllowed",
    "WebFetchRateLimited",
    "WebFetchRedirectRefused",
    "WebFetchSizeLimitExceeded",
    "WebFetchTlsError",
]
