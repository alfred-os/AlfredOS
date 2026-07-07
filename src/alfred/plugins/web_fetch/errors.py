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
``WEB_FETCH_FIELDS`` audit row records (``domain``, ``url``, ``rate_limit_bucket``).
The audit writer reads typed exception attributes — never string-parses
messages — so a future i18n change to the message template cannot drift
the audit row.

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


class WebFetchActionTimeout(WebFetchError):  # noqa: N818 -- forensic event, name pinned by #347 blocker-2
    """The fused fetch+extract overran its per-action deadline (spec §7, #347 blocker 2).

    Carries the forensic fields the orchestrator-wiring chokepoint records on the
    enriched ``tool.dispatch`` timeout row. The side effect may have fired before
    the deadline (``in_doubt``); the message body carries NO forensic data (audit
    hygiene) — the structured attributes do.

    DELIBERATELY a ``WebFetchError`` subclass (FOLD-LAYER FIX-4) — unlike
    ``WebFetchCanaryTripped`` below, an action-deadline timeout is a
    recoverable operational condition, not a halting security event. BECAUSE
    it subclasses ``WebFetchError``, ``dispatch_tool``'s ``except`` arm
    ordering is load-bearing: its handler MUST precede the generic
    ``except WebFetchError`` arm, or a future reorder silently swallows these
    forensic fields into the generic tool-error row instead of the enriched
    timeout row.
    """

    def __init__(
        self,
        *,
        egress_id: str,
        destination_host: str,
        in_doubt: bool,
        ledger_state: str | None,
    ) -> None:
        super().__init__(t("web.fetch.error.action_timeout"))
        self.egress_id = egress_id
        self.destination_host = destination_host
        self.in_doubt = in_doubt
        self.ledger_state = ledger_state


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
    "WebFetchActionTimeout",
    "WebFetchCanaryTripped",
    "WebFetchDomainNotAllowed",
    "WebFetchError",
    "WebFetchHandleIdMismatch",
    "WebFetchRateLimited",
]
