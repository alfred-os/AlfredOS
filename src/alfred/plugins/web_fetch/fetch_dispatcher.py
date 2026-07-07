"""Orchestrator-side ``web.fetch`` dispatcher (spec §7.1-§7.12, Spec C G7-2.5).

The orchestrator never calls ``web.fetch`` directly — it calls
:func:`dispatch_web_fetch`. This module runs on the HOST SIDE (the orchestrator
process), not inside any plugin subprocess.

G7-2.5 re-home (#333; ADR-0041): the dispatcher no longer drives a plugin
subprocess over ``transport.dispatch``, and it no longer returns an opaque T3
``ContentHandle`` for deferred extraction. The connectivity-free core (HARD rule
#9 / Spec C) cannot open an external socket, so the fetch is performed by the
gateway egress relay. The dispatcher keeps the CORE-SIDE gatekeeping and hands
the request to
:class:`alfred.egress.egress_response_extract.EgressResponseExtractor`, which
fires the request through the gateway relay and returns a **T2**
:class:`~alfred.egress.egress_response_extract.EgressExtractOutcome`
(``Extracted | TypedRefusal``) via the sanctioned ``quarantined_to_structured``
seam — the orchestrator never sees raw T3 bytes.

``web.fetch`` is therefore now a **fused fetch+extract unit** returning T2, not a
fetch-then-defer-extraction contract (ADR-0041 records the three coupled
decisions: the T3-handle→T2 contract, the ``HandleCap`` removal, and the
de-2026-004 re-target). #339 PR4a (ADR-0047 / amended ADR-0041) RE-ATTACHES
``HandleCap`` — not as the old ContentHandle-count guard, but as a pure
per-user concurrency bound: reserve one slot before the network fire, release
it in a ``finally`` on every exit path (see Step 3b below), superseding the
G7-2.5 removal. Kept core-side: outbound DLP (URL refuse-on-secret +
header redaction), the three-way path-prefix allowlist + broadening cap, the
per-domain rate limiter, and the success/refusal audit rows. Removed core-side
(now the gateway's structural job): the SSRF host-IP guard, redirect refusal,
TLS origination, and the subprocess fetch path. The 5 MiB response cap + MIME
allowlist + inbound-canary scan move to the C2 pre-extract seam
(:class:`~alfred.egress.response_inspection.ResponsePolicy`). Production assembly
(reusing the daemon's one quarantine graph) lives in
:func:`alfred.plugins.web_fetch.assembly.build_web_fetch_egress_extractor`.

Residual (ADR-0041 / §7, tracked #339): no live ``dispatch_web_fetch`` caller
exists until #339 wires the tool-calling loop (after G7-3). The ``language``
source (HARD rule #3) landed in PR3; the per-user fairness bound lands here in
PR4a (the reserve-before-network gate + release-in-``finally`` below). PR4b
(#347 blocker 4, this change) wires broker secret-injection for authenticated
fetch: a raw secret in a header value refuses (Step 1b) and an allowlisted
``{{secret:<name>}}`` placeholder is resolved via
:meth:`alfred.security.secrets.SecretBroker.substitute` (Step 1c), both BEFORE
the Step 3b ``handle_cap`` reserve (ADR-0048).

Core-side responsibilities (in order):

  1. :class:`alfred.security.dlp.OutboundDlp` — scan the URL (refuse-on-secret:
     a redacted URL the gateway cannot fetch is never sent, and a raw
     secret-bearing URL is never forwarded) and redact-and-send the header
     values (spec §7.9b).
  1b. Header raw-secret defence (#339 PR4b-broker, ADR-0048): a header value
      the DLP scan redacted (a raw secret was present) refuses loud rather
      than sending the redacted form — mirrors the URL arm above.
  1c. Broker ``{{secret:<name>}}`` substitution (#339 PR4b-broker, ADR-0048):
      resolves an allowlisted, provisioned placeholder into the real secret
      value for the wire request; an off-allowlist / unprovisioned / malformed
      reference refuses loud. Runs AFTER DLP (ADR-0017: the placeholder frame
      is DLP-clean text, not a raw secret) and BEFORE the Step 3b handle_cap
      reserve — the empty default
      :data:`~alfred.plugins.web_fetch.auth_allowlist.WEB_FETCH_AUTH_SECRET_ALLOWLIST`
      means every placeholder refuses today; placing substitution any later
      would leak a per-user concurrency slot on every such refusal.
  2. :class:`alfred.plugins.web_fetch.allowlist.AllowlistIntersection`
     three-way check + ``web.allowlist.manifest_broadening_capped`` audit row
     (spec §7.4).
  3. :class:`alfred.plugins.web_fetch.rate_limit.RateLimiter`
     Lua-atomic ``check_and_increment`` (spec §7.7).
  4. Build a :class:`~alfred.egress.relay_protocol._RawToolRequest` (REAL url on
     the wire, substituted+redacted headers) and fire it through the extractor
     under the per-action deadline (``asyncio.timeout(action_deadline_seconds)``).

Audit invariant (rvw-001 / Cluster 4): every emit site goes through
``await audit.append_schema(fields=..., schema_name=..., subject=...)`` with the
subject dict carrying EXACTLY the keys named in the schema constant.

Canary trips (SEC-2 / HARD rule #7): the extractor's C2 layer holds no
``AuditWriter`` — it records the TERMINAL ledger refusal and raises
:class:`~alfred.egress.response_inspection.InboundCanaryTripped`. The dispatcher
catches it, writes the ONE loud ``result="quarantined"`` audit row, then
re-raises.
"""

from __future__ import annotations

import asyncio
import math
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, NoReturn
from urllib.parse import urlparse

import structlog

from alfred.audit.audit_row_schemas import (
    WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS,
    WEB_FETCH_FIELDS,
    DlpScanResult,
)
from alfred.egress.egress_id import compute_egress_id
from alfred.egress.relay_protocol import _RawToolRequest
from alfred.egress.response_inspection import InboundCanaryTripped
from alfred.i18n import t
from alfred.plugins.web_fetch.allowlist import AllowlistEntry, AllowlistIntersection
from alfred.plugins.web_fetch.auth_allowlist import (
    WEB_FETCH_AUTH_SECRET_ALLOWLIST,
    _SecretSubstituter,
)
from alfred.plugins.web_fetch.constants import (
    _DEFAULT_ACTION_DEADLINE_SECONDS,
    _DEFAULT_HANDLE_RESERVATION_TTL_SECONDS,
    _LEDGER_READ_TIMEOUT_SECONDS,
)
from alfred.plugins.web_fetch.errors import (
    WebFetchActionTimeout,
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchRateLimited,
)
from alfred.plugins.web_fetch.rate_limit import RateLimiter
from alfred.security.quarantine import Extracted
from alfred.security.secrets import SecretSubstitutionNotAllowed, UnknownSecretError

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.egress.egress_id import TurnEgressContext
    from alfred.egress.egress_response_extract import (
        EgressExtractOutcome,
        EgressResponseExtractor,
    )
    from alfred.plugins.web_fetch.handle_cap import HandleCap
    from alfred.security.dlp import OutboundDlp
    from alfred.security.quarantine import ExtractionSchema

_log = structlog.get_logger(__name__)

# Slice-3 depth=1 invariant (spec §7.9): every fetch is depth=1. A depth>1 fetch
# would let a quarantined-LLM extract chain re-fetch the T3 content via the
# orchestrator — the depth=1 lock is the structural defence pinned by
# ``test_recursion_depth_one.py``.
_FETCH_DEPTH: Final[int] = 1

# H11 / perf-100: sentinel passed to the ``allowlist`` field's
# ``default_factory`` so the dataclass machinery can run before
# ``__post_init__`` overwrites it with the real intersection.
# ``AllowlistIntersection([], [], [])`` is the canonical empty form — its
# ``check()`` refuses every URL, so a config that somehow skipped
# ``__post_init__`` fails closed at the first allowlist check.
_SENTINEL_ALLOWLIST: Final[AllowlistIntersection] = AllowlistIntersection(
    manifest=[], operator=[], session=[]
)


def _safe_hostname(url: str) -> str:
    """The bare lowercase host authority for audit + rate-limit attribution.

    Returns ``urlparse(url).hostname`` (host ONLY — never userinfo, port, path, or
    query) so neither the audit ``domain`` nor the PRD §7.7 per-domain rate-limit
    BUCKET can be fragmented or poisoned by a ``user:pass@host:port`` variant (a
    ``netloc`` carries all of those, so a ``user@host`` form would both leak userinfo
    into the audit row AND evade the per-host limit). ``ValueError``-safe: a URL
    ``urlparse`` rejects (e.g. an out-of-range port) collapses to ``""`` rather than
    crashing the gatekeeping path.
    """
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


@dataclass(frozen=True, slots=True)
class FetchDispatchConfig:
    """Immutable per-session configuration for the fetch dispatcher.

    Constructed once at session-start time. The three allowlist tuples feed into
    :class:`AllowlistIntersection`; the ``manifest_commit_hash`` provides forensic
    correlation for the plugin version active at fetch time (spec §7.12).

    G7-2.5 (plan-review CORE-4): the ``redis_url`` (fed the deleted subprocess
    content-store) and ``skip_tls_verify`` (fed the deleted parent-side
    ``TlsPolicy`` check — TLS is the gateway's job now) fields are GONE. The
    gateway re-runs DLP, enforces the SSRF chain and originates the real TLS, so
    none of that machinery lives on the per-session config any more.

    H11 / perf-100: ``allowlist`` is pre-built once in ``__post_init__`` and
    reused across every fetch in the session, turning the per-fetch hot path
    into a single ``allowlist.check(url)`` call.

    H12 / perf-101: ``_broadening_cap_emitted`` is a mutable cell on the
    otherwise-frozen config tracking whether the cap event has been emitted in
    this session. The cell is a single-element ``list`` rather than a bool so
    frozen+slots stays intact (``list.append`` mutates in-place — the canonical
    ``frozen-with-internal-cache`` idiom). The worst case under concurrent
    dispatch is a few duplicate rows (forensic-redundant, not a security
    regression) so no lock is needed at this layer.
    """

    manifest_allowed_entries: tuple[AllowlistEntry, ...]
    operator_allowed_entries: tuple[AllowlistEntry, ...]
    session_allowed_entries: tuple[AllowlistEntry, ...]
    manifest_commit_hash: str
    plugin_id: str = "alfred.web-fetch"
    # H11 / H12: late-bound cached state. Both fields are ``init=False`` so they
    # don't appear in the generated ``__init__`` signature.
    allowlist: AllowlistIntersection = field(
        init=False,
        default_factory=lambda: _SENTINEL_ALLOWLIST,
    )
    _broadening_cap_emitted: list[bool] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        # H11: build the AllowlistIntersection once. ``object.__setattr__`` is the
        # canonical Python idiom for frozen-dataclass post-init field population.
        allowlist = AllowlistIntersection(
            manifest=list(self.manifest_allowed_entries),
            operator=list(self.operator_allowed_entries),
            session=list(self.session_allowed_entries),
        )
        object.__setattr__(self, "allowlist", allowlist)


async def _classify_action_timeout(
    *,
    extractor: EgressResponseExtractor,
    egress_id: str,
    destination_host: str,
    correlation_id: str,
) -> WebFetchActionTimeout:
    """Build the :class:`WebFetchActionTimeout` for a post-deadline overrun (#347
    blocker 2).

    Reads the egress-idempotency ledger state under a bounded guard so a
    correlated DB fault can never mask the in-doubt row (FIX-1, HARD rule #7). On
    a read failure OR a read that overruns its own bounded ``asyncio.timeout``
    (both ``Exception`` subclasses), returns ``in_doubt=True`` with the distinct
    ``ledger_state="read_unavailable"`` sentinel — NOT ``None`` (``None`` means
    "no row -> never fired -> in_doubt=False", the opposite safe direction).

    This never raises: the caller raises the returned exception (with ``from
    None`` to suppress the noisy cancellation-internals chain). See the module
    docstring's ``WebFetchActionTimeout`` Raises entry for the accepted external-
    ``CancelledError`` residual (this guard catches ``Exception``, not
    ``BaseException``).
    """
    try:
        # Bounded: this path already breached its deadline; don't let a slow/hung
        # ledger extend it or hold the handle_cap slot.
        async with asyncio.timeout(_LEDGER_READ_TIMEOUT_SECONDS):
            state = await extractor.ledger_state(egress_id=egress_id)
    except Exception as read_exc:
        _log.error(
            "web_fetch.timeout.ledger_read_failed",
            egress_id=egress_id,
            error_type=type(read_exc).__name__,
            correlation_id=correlation_id,
        )
        return WebFetchActionTimeout(
            egress_id=egress_id,
            destination_host=destination_host,
            in_doubt=True,
            ledger_state="read_unavailable",
        )
    return WebFetchActionTimeout(
        egress_id=egress_id,
        destination_host=destination_host,
        in_doubt=state == "committed_no_response",
        ledger_state=state,
    )


async def dispatch_web_fetch(
    *,
    url: str,
    headers: dict[str, str],
    user_id: str,
    correlation_id: str,
    egress_ctx: TurnEgressContext,
    call_index: int,
    schema: type[ExtractionSchema],
    config: FetchDispatchConfig,
    rate_limiter: RateLimiter,
    handle_cap: HandleCap,
    outbound_dlp: OutboundDlp,
    broker: _SecretSubstituter,
    auth_secret_allowlist: frozenset[str] = WEB_FETCH_AUTH_SECRET_ALLOWLIST,
    audit: AuditWriter,
    extractor: EgressResponseExtractor,
    action_deadline_seconds: float = _DEFAULT_ACTION_DEADLINE_SECONDS,
) -> EgressExtractOutcome:
    """Full orchestrator-side ``web.fetch`` dispatch (spec §7.1-§7.12, G7-2.5).

    Returns a **T2** :class:`~alfred.egress.egress_response_extract.EgressExtractOutcome`
    on success OR on a soft pre-extract refusal (MIME/size — the outcome's
    ``result`` is a :class:`~alfred.security.quarantine.TypedRefusal`). Raises:

    * :class:`WebFetchError` — a secret in the URL (refuse-on-secret) or a
      DLP-scan failure.
    * :class:`WebFetchDomainNotAllowed` — URL outside the three-way allowlist.
    * :class:`WebFetchRateLimited` — rate-limit refusal (carries the bucket);
      includes the pre-network ``"handle_cap"`` bucket (#339 PR4a, Step 3b) —
      the per-user concurrency reservation refused BEFORE the extractor fires,
      audited as ``dlp_scan_result="handle_cap_exceeded"``.
    * :class:`~alfred.egress.response_inspection.InboundCanaryTripped` — an
      inbound canary was reflected in the response (after a loud audit row).
    * :class:`~alfred.plugins.web_fetch.errors.WebFetchActionTimeout` — the
      fused fetch+extract overran ``action_deadline_seconds``. Packages
      ``egress_id`` / ``in_doubt`` / ``ledger_state`` for the enriched,
      non-skippable ``tool.dispatch`` timeout row (#347 blocker 2). If the
      post-timeout ledger read itself raises OR overruns its own bounded
      ``asyncio.timeout`` (both are ``Exception`` subclasses — correlated DB
      stress), the typed exception still surfaces — with ``in_doubt=True`` and
      ``ledger_state="read_unavailable"`` — rather than being lost (HARD
      rule #7: bookkeeping must never mask an in-doubt timeout).

      RESIDUAL (accepted, matching the ADR-0041/ADR-0047 residual pattern): the
      read guard catches ``Exception``, not ``BaseException``. A genuine
      EXTERNAL ``asyncio.CancelledError`` (turn-abort / supervisor cancellation,
      distinct from this scope's own action-deadline) landing during the bounded
      ledger read propagates uncaught and no ``tool.dispatch`` row is written for
      that call. This is deliberate structured-concurrency behaviour — a cancel
      during teardown must propagate, never be swallowed to write bookkeeping
      (mirrors the ``except Exception`` handle_cap-release guard below, #339 PR4a
      FIX-8). The at-most-once/in-doubt property is preserved (the ledger row is
      untouched); only the audit row is skipped on this narrow external-cancel
      window.
    """
    # Step 1: OutboundDlp on both fields (spec §7.9b). The DLP surface is a
    # single ``scan(text: str) -> str``; run it once per field.
    #
    # M7 / err-003: a DLP-scan exception (broker outage, regex panic) is a
    # security-path failure — emit an audit row BEFORE the re-raise so the
    # operator log carries the failure even if the caller swallows it (HARD
    # rule #7).
    try:
        clean_url = outbound_dlp.scan(url)
        # M3 / arch-006: scan each header value individually so header-shaped
        # secrets (Bearer tokens, ``Authorization`` values) are redacted on the
        # wire. We send the REAL ``url`` (the gateway must resolve it) but the
        # REDACTED header values.
        clean_headers: dict[str, str] = {name: outbound_dlp.scan(v) for name, v in headers.items()}
    except Exception:
        # CR-146: PRD §7.9b's fail-closed contract means a DLP outage MUST NOT
        # let an unscanned URL flow into audit storage — the raw URL may carry
        # secrets in its query string or userinfo. Substitute a redacted
        # sentinel; host attribution survives via ``_safe_hostname`` (host only —
        # no userinfo, no port, no query).
        domain_for_audit = _safe_hostname(url)
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": "<REDACTED_DLP_FAILURE>",
                "domain": domain_for_audit,
                "status_code": None,
                "content_handle_id": None,
                "fetch_depth": _FETCH_DEPTH,
                "rate_limit_bucket": None,
                "manifest_commit_hash": config.manifest_commit_hash,
                "trust_tier_of_result": "T3",
                "dlp_scan_result": "dlp_scan_error",
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="dlp_scan_error",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        raise

    # M3 / CR-5: ``domain`` is the bare HOST (never ``netloc``) so it is uniform
    # across the audit ``domain`` AND the PRD §7.7 per-domain rate-limit bucket —
    # a ``user:pass@host:port`` variant cannot leak userinfo into the audit row or
    # fragment (evade) the per-host rate limit.
    domain = _safe_hostname(clean_url)

    async def _refuse(*, dlp_scan_result: DlpScanResult, message_key: str) -> NoReturn:
        """FIX-10 (DRY): the URL / header / substitution pre-network refusals
        below share this exact ``WEB_FETCH_FIELDS`` subject shape — nothing to
        report yet (no status, no handle, no rate-limit bucket). Closes over
        ``clean_url`` / ``domain`` (bound just above) and the enclosing scope's
        ``user_id`` / ``correlation_id`` / ``config`` / ``audit``.

        ``from None`` (FIX-8): the PRIMARY containment is structural, not
        traceback-suppression — the raised ``WebFetchError``'s own message is a
        FIXED, closed-vocabulary catalog string; ``.ref`` (the possibly
        attacker-influenced secret name) never appears in its ``__str__`` /
        ``__repr__`` / ``.args``, and it never echoes ``dlp_scan_result`` or any
        other caller input. ``from None`` additionally sets
        ``__suppress_context__ = True``, which governs DEFAULT traceback
        rendering (e.g. ``traceback.format_exception``) so a downstream render
        does not print the chained ``UnknownSecretError.__str__`` (a
        ``KeyError`` subclass whose message embeds the requested name — see
        ``SecretBroker.get``) — but it does NOT clear ``__context__`` itself;
        that reference remains reachable to code that inspects it directly.
        """
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": clean_url,
                "domain": domain,
                "status_code": None,
                "content_handle_id": None,
                "fetch_depth": _FETCH_DEPTH,
                "rate_limit_bucket": None,
                "manifest_commit_hash": config.manifest_commit_hash,
                "trust_tier_of_result": "T3",
                "dlp_scan_result": dlp_scan_result,
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="refused",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        raise WebFetchError(t(message_key)) from None

    # C1 / C12: the DLP redacted the URL → a secret lives in the URL itself.
    # Refuse loud rather than EITHER forwarding the raw secret-bearing URL OR
    # sending a redacted URL the gateway cannot resolve.
    if clean_url != url:
        await _refuse(
            dlp_scan_result="url_secret_refused",
            message_key="web.fetch.error.url_secret_refused",
        )

    # Step 1b (#339 PR4b-broker, ADR-0048): a RAW secret in a header value (DLP
    # redacted it) is refused, not redact-and-sent — HARD rule #6. A
    # {{secret:*}} placeholder is benign text to DLP (no redaction), so it does
    # NOT trip this arm; it is resolved in Step 1c below. Placed immediately
    # after the URL refusal above and BEFORE Step 2's allowlist check / Step
    # 3b's handle_cap reserve (FIX-1 / plan-review CRITICAL) — see Step 1c's
    # docstring note for why the ordering matters.
    if any(clean_headers[name] != value for name, value in headers.items()):
        await _refuse(
            dlp_scan_result="header_secret_refused",
            message_key="web.fetch.error.header_secret_refused",
        )

    # Step 1c (#339 PR4b-broker, ADR-0048): resolve {{secret:<name>}}
    # placeholders in header values via the broker, AFTER DLP (ADR-0017: the
    # placeholder frame is already DLP-clean text, not a raw secret) and
    # BEFORE the relay frame — and, critically, BEFORE the Step 3b handle_cap
    # reserve (FIX-1 / plan-review CRITICAL): with the empty-by-default
    # ``WEB_FETCH_AUTH_SECRET_ALLOWLIST`` every placeholder refuses here, so
    # running substitution any later (e.g. just before ``_RawToolRequest``)
    # would reserve-then-refuse on every such call — leaking a per-user
    # concurrency slot per refusal, a planner-inducible self-DoS. Off-allowlist
    # / malformed / unprovisioned references refuse loud (HARD rule #6/#7).
    #
    # FIX-9 totality: a broker BACKEND fault (anything other than
    # ``SecretSubstitutionNotAllowed`` / ``UnknownSecretError``) propagates
    # uncaught from ``substitute()`` here and is caught by ``dispatch_tool``'s
    # outer ``except Exception -> unexpected_error/fault`` arm one layer up
    # (loud audit there — the PR4a FIX-9 / handle_cap-reserve precedent). A
    # second arm here would double-audit the same fault.
    try:
        auth_headers = {
            name: broker.substitute(value, allowed_secrets=auth_secret_allowlist)
            for name, value in clean_headers.items()
        }
    except (SecretSubstitutionNotAllowed, UnknownSecretError) as exc:
        # err-001: log the exception TYPE NAME ONLY (never ``exc.ref``, ``str(exc)``,
        # or any secret) so an operator can forensically distinguish an
        # off-allowlist/malformed probe (SecretSubstitutionNotAllowed) from an
        # unprovisioned-but-allowlisted secret (UnknownSecretError) without either
        # leaking the referenced name into the log stream.
        _log.warning(
            "web_fetch.secret_substitution_refused",
            error_type=type(exc).__name__,
            correlation_id=correlation_id,
        )
        await _refuse(
            dlp_scan_result="secret_substitution_refused",
            message_key="web.fetch.error.secret_substitution_refused",
        )

    # Step 2: Three-way allowlist intersection (spec §7.4).
    #
    # H11 / perf-100: the intersection is pre-built once on the per-session
    # ``FetchDispatchConfig``; the per-fetch hot path is a single ``check()``.
    allowlist = config.allowlist

    # H12 / perf-101: the broadening-cap audit row is a manifest-load-time event
    # (not per-fetch). The ``_broadening_cap_emitted`` cell is the once-then-skip
    # latch: empty means "not yet emitted", non-empty means "already emitted".
    if not config._broadening_cap_emitted:
        for cap_event in allowlist.broadening_cap_events():
            await audit.append_schema(
                fields=WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS,
                schema_name="WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS",
                event="web.allowlist.manifest_broadening_capped",
                actor_user_id=user_id,
                subject={
                    "plugin_id": config.plugin_id,
                    "manifest_domains": sorted(cap_event.manifest_domains),
                    "operator_allowed_domains": sorted(cap_event.operator_allowed_domains),
                    # CR-146: ``capped_domains`` carries (domain, path_prefix)
                    # tuples — collapsing to bare domains loses the path-prefix
                    # granularity PRD §7.4 / §13 demand for the audit trail.
                    "capped_domains": [
                        {"domain": e.domain, "path_prefix": e.path_prefix}
                        for e in cap_event.capped_domains
                    ],
                    "correlation_id": correlation_id,
                },
                trust_tier_of_trigger="T0",
                result="capped",
                cost_estimate_usd=0.0,
                trace_id=correlation_id,
            )
        # Latch after the loop regardless of whether there were events to emit —
        # the config is frozen, so the manifest will not grow capped entries
        # mid-session; this guards against a future non-idempotent refactor.
        config._broadening_cap_emitted.append(True)

    try:
        allowlist.check(clean_url)
    except WebFetchDomainNotAllowed:
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": clean_url,
                "domain": domain,
                "status_code": None,
                "content_handle_id": None,
                "fetch_depth": _FETCH_DEPTH,
                "rate_limit_bucket": None,
                "manifest_commit_hash": config.manifest_commit_hash,
                "trust_tier_of_result": "T3",
                "dlp_scan_result": "domain_not_allowed",
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="domain_not_allowed",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        raise

    # Step 3: Lua-atomic rate-limit check (spec §7.7).
    try:
        await rate_limiter.check_and_increment(domain=domain, user_id=user_id)
    except WebFetchRateLimited as e:
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": clean_url,
                "domain": domain,
                "status_code": None,
                "content_handle_id": None,
                "fetch_depth": _FETCH_DEPTH,
                # Record the specific bucket that refused ("per_domain" /
                # "per_user" / "daily_budget") so operators can target the
                # tightened limit without re-correlating.
                "rate_limit_bucket": e.bucket,
                "manifest_commit_hash": config.manifest_commit_hash,
                "trust_tier_of_result": "T3",
                "dlp_scan_result": "rate_limited",
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="rate_limited",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        raise

    # Step 3b: reserve one per-user concurrency slot BEFORE the network fire
    # (#339 PR4a blocker 1 / #347; spec §7.10). G7-2.5 removed the ContentHandle
    # cap when web.fetch fused fetch+extract; #339 reinstates it as a pure per-user
    # concurrency bound — the T3 body now stages in-memory transiently (not a Redis
    # ContentHandle), so ``handle_id`` is a synthetic ZSET member and the old
    # host-side handle_id-equality check is gone. The slot is released in the
    # ``finally`` below on EVERY Step-4/5 exit path.
    #
    # FIX-9: only ``WebFetchRateLimited`` (cap exceeded) is audited-and-reraised
    # here, mirroring the Step-3 rate-limiter above. A reserve transport fault
    # (RedisError / ValueError / RuntimeError) propagates uncaught and is audited
    # LOUD one layer up by the ``dispatch_tool`` chokepoint's
    # ``except Exception -> unexpected_error/fault`` arm (HARD rule #7 satisfied by
    # the outer totality — a second dispatcher arm would double-audit).
    handle_id = str(uuid.uuid4())
    # CR-cloud (PR4a review) + perf-reviewer: a hardcoded 120s reservation TTL
    # could passively evict a live slot if an operator raises
    # ``action_deadline_seconds`` above it — the fetch would still be in flight
    # (bounded by the action deadline) after the reservation self-heals away.
    # TTL must outlive the per-fetch action deadline (the max single-fetch
    # duration) so a slow-but-live fetch's slot is never passively evicted
    # mid-flight; the 120s constant is the floor/self-heal backstop for the
    # common (30s-deadline) case.
    reservation_ttl_seconds = max(
        _DEFAULT_HANDLE_RESERVATION_TTL_SECONDS,
        math.ceil(action_deadline_seconds) * 2,
    )
    try:
        await handle_cap.try_reserve(
            user_id=user_id,
            handle_id=handle_id,
            handle_ttl_seconds=reservation_ttl_seconds,
        )
    except WebFetchRateLimited as e:
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": clean_url,
                "domain": domain,
                "status_code": None,
                "content_handle_id": None,
                "fetch_depth": _FETCH_DEPTH,
                "rate_limit_bucket": e.bucket,  # "handle_cap"
                "manifest_commit_hash": config.manifest_commit_hash,
                "trust_tier_of_result": "T3",
                "dlp_scan_result": "handle_cap_exceeded",
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="rate_limited",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        raise

    # Step 4: build the relay request (REAL url + REDACTED headers) and fire it
    # through the gateway egress relay under the per-action deadline (C13).
    #
    # #339 PR4a (FIX-8): Step 4 + Step 5 are wrapped in a try/finally so the
    # per-user slot reserved above is released on EVERY exit path — success,
    # soft refusal, InboundCanaryTripped re-raise, WebFetchActionTimeout (PR4b-audit
    # FIX-1, converted from the raw action-deadline TimeoutError), or a generic
    # transport error. See the ``finally`` block below for the release itself.
    try:
        raw_request = _RawToolRequest(
            method="GET", url=url, headers=auth_headers, body="", idempotent=True
        )
        try:
            async with asyncio.timeout(action_deadline_seconds):
                outcome = await extractor.handle(
                    raw_request=raw_request,
                    ctx=egress_ctx,
                    call_index=call_index,
                    schema=schema,
                    # C11b residual: the turn-user's language is not reachable from
                    # this call site yet — the per-user turn context lands with the
                    # LLM tool-calling subsystem.
                    language=None,  # TODO: #339
                )
        except InboundCanaryTripped:
            # HARD rule #7 (plan-review SEC-2): the canary trip raises out of C2,
            # which holds no AuditWriter — the dispatcher writes the loud,
            # non-skippable audit row here BEFORE re-raising. C2 already recorded the
            # terminal ledger refusal (Task 4).
            await audit.append_schema(
                fields=WEB_FETCH_FIELDS,
                schema_name="WEB_FETCH_FIELDS",
                event="tool.web.fetch",
                actor_user_id=user_id,
                subject={
                    "url": clean_url,
                    "domain": domain,
                    "status_code": None,
                    "content_handle_id": None,
                    "fetch_depth": _FETCH_DEPTH,
                    "rate_limit_bucket": None,
                    "manifest_commit_hash": config.manifest_commit_hash,
                    # T3: a canary reflection means hostile T3 content came back; no
                    # T2 was produced for the orchestrator.
                    "trust_tier_of_result": "T3",
                    "dlp_scan_result": "inbound_canary_tripped",
                    "canary_tripped": True,
                    "triggering_user_id": user_id,
                    "correlation_id": correlation_id,
                },
                trust_tier_of_trigger="T0",
                result="quarantined",
                cost_estimate_usd=0.0,
                trace_id=correlation_id,
            )
            raise
        except TimeoutError:
            # #347 blocker 2: the fused fetch+extract overran the action deadline.
            # asyncio.timeout has already converted CancelledError->TimeoutError and
            # cleared its cancel scope, so the bounded ledger read below runs
            # un-cancelled. The outer ``finally`` still releases the handle_cap slot
            # after this raise. ``from None``: the deadline TimeoutError carries no
            # forensic payload (the typed exception's fields do) — suppress the noisy
            # cancellation-internals chain.
            egress_id = compute_egress_id(egress_ctx, call_index=call_index)
            timeout_exc = await _classify_action_timeout(
                extractor=extractor,
                egress_id=egress_id,
                destination_host=domain,
                correlation_id=correlation_id,
            )
            raise timeout_exc from None

        # Step 5: success / soft-refusal audit row (C3) with the real status (C7).
        #
        # ``trust_tier_of_result="T2"`` — the orchestrator now receives an extracted
        # T2 outcome (was T3 in the handle-returning era). The status is the upstream
        # HTTP code; validate it is a plausible code (100-599) else None (a
        # deduplicated replay carries status=None, and a malformed code would corrupt
        # the audit graph).
        if outcome.status is not None and 100 <= outcome.status <= 599:
            status_code: int | None = outcome.status
        else:
            status_code = None

        base_subject: dict[str, object | None] = {
            "url": clean_url,
            "domain": domain,
            "status_code": status_code,
            "content_handle_id": None,
            "fetch_depth": _FETCH_DEPTH,
            "rate_limit_bucket": None,
            "manifest_commit_hash": config.manifest_commit_hash,
            "trust_tier_of_result": "T2",
            "canary_tripped": False,
            "triggering_user_id": user_id,
            "correlation_id": correlation_id,
        }
        if isinstance(outcome.result, Extracted):
            await audit.append_schema(
                fields=WEB_FETCH_FIELDS,
                schema_name="WEB_FETCH_FIELDS",
                event="tool.web.fetch",
                actor_user_id=user_id,
                subject={**base_subject, "dlp_scan_result": "clean"},
                trust_tier_of_trigger="T0",
                # #328: the web.fetch success row uses the canonical ``success``
                # disposition (matching the 24+ other success sites — operator_session,
                # daemon boot, dispatch_loop, supervisor, …), NOT the legacy ``ok``
                # split that made every web.fetch success invisible to a
                # ``result = 'success'`` audit-graph/metrics query. Both are in
                # ``ck_audit_log_result``; dropping the now-unused ``ok`` from the
                # domain is a deferred follow-up migration (only after the #320 guard
                # confirms no remaining ``ok`` writer).
                result="success",
                cost_estimate_usd=0.0,
                trace_id=correlation_id,
            )
        else:
            # A soft TypedRefusal from the pre-extract MIME/size seam (the
            # payload-blind ``policy_refusal_token`` — NEVER the raw Content-Type),
            # or a quarantined-LLM extract refusal. Either way ``result="refused"``.
            #
            # M2 / CR-cloud-6: when the pre-extract seam did NOT fire
            # (``policy_refusal_token is None``) the refusal came from the quarantined
            # LLM itself — surface its closed-vocab ``TypedRefusal.reason``
            # (``cannot_extract`` / ``refused_by_safety``) so the SECURITY signal of a
            # ``refused_by_safety`` extraction is not dropped from the audit pivot.
            # ``reason`` is closed-vocab + payload-blind (no T3 fragment). In this
            # ``else`` branch ``outcome.result`` is narrowed to ``TypedRefusal`` (the
            # ``Extracted`` arm returned above), so ``.reason`` is always present.
            dlp_scan_result: str | None = outcome.policy_refusal_token
            if dlp_scan_result is None:
                dlp_scan_result = outcome.result.reason
            await audit.append_schema(
                fields=WEB_FETCH_FIELDS,
                schema_name="WEB_FETCH_FIELDS",
                event="tool.web.fetch",
                actor_user_id=user_id,
                subject={**base_subject, "dlp_scan_result": dlp_scan_result},
                trust_tier_of_trigger="T0",
                result="refused",
                cost_estimate_usd=0.0,
                trace_id=correlation_id,
            )

        return outcome
    finally:
        # Release the per-user slot on EVERY exit path (#339 PR4a): success, soft
        # refusal, InboundCanaryTripped re-raise, WebFetchActionTimeout, transport
        # error.
        # FIX-8: wrap in try/except Exception (NOT BaseException, so CancelledError
        # still propagates) so a non-RedisError from release() can never MASK the
        # in-flight security exception. release() already swallows RedisError
        # (structlog-only); this guards the rarer non-RedisError path.
        try:
            await handle_cap.release(
                user_id=user_id, handle_id=handle_id, correlation_id=correlation_id
            )
        except Exception as exc:  # never let a release fault mask the in-flight security exception
            _log.error(
                "web_fetch.handle_cap.release_unexpected",
                user_id=user_id,
                handle_id=handle_id,
                error_type=type(exc).__name__,
                correlation_id=correlation_id,
            )


__all__ = ["FetchDispatchConfig", "dispatch_web_fetch"]
