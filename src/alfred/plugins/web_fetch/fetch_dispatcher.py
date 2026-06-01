"""Orchestrator-side ``web.fetch`` dispatcher (spec §7.1-§7.12).

The orchestrator never calls ``web.fetch`` directly — it calls
:func:`dispatch_web_fetch`. This module runs on the HOST SIDE (the
orchestrator process), not inside the plugin subprocess.

Responsibilities:

  1. :class:`alfred.security.dlp.OutboundDlp` scan on
     ``(url, headers)`` BEFORE crossing the wire (spec §7.9b).
  2. :class:`alfred.plugins.web_fetch.allowlist.AllowlistIntersection`
     three-way check (spec §7.4).
  3. Emit ``web.allowlist.manifest_broadening_capped`` audit row if
     the manifest tried to widen past the operator config (spec §7.4).
  4. :class:`alfred.plugins.web_fetch.rate_limit.RateLimiter`
     Lua-atomic ``check_and_increment`` (spec §7.7).
  5. :meth:`alfred.plugins.stdio_transport.StdioTransport.dispatch` →
     :class:`~alfred.security.quarantine.ContentHandle`.
  6. ``tool.web.fetch`` hookpoint pre + post / error / cancel invocation
     (spec §7.5). [hookpoint dispatch wiring lands with PR-S3-3a's
     subscriber registration — this module only emits the audit rows.]

Audit invariant (rvw-001 / Cluster 4): every emit site goes through
``await audit.append_schema(fields=..., schema_name=..., subject=...)``
with the subject dict carrying EXACTLY the keys named in the schema
constant. The older
``audit_sink.emit(event=..., fields=..., ...)`` pattern that the
plan draft mentioned did not match the real
:meth:`alfred.audit.log.AuditWriter.append_schema` signature — wrong
arg names, missing required kwargs, missing await — and would have
raised ``TypeError`` at the first emit site. Using ``append_schema``
also gets us the symmetric subject-key validation for free.

err-012 fix: when the plugin subprocess returns a structured JSON-RPC
error envelope, the host transport surfaces it as a
:class:`~alfred.plugins.transport.ControlResult` whose ``payload``
carries the ``error.data`` block. We branch by ``isinstance`` on the
:class:`~alfred.security.quarantine.ContentHandle` success path and
map the error-type tag onto the right typed exception. The earlier
draft raised :class:`WebFetchTlsError` for every non-handle result,
which lost MIME / size / generic failure modes — the
``_ERROR_TYPE_MAP`` table makes the mapping explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final
from urllib.parse import urlparse

import structlog

from alfred.audit.audit_row_schemas import (
    WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS,
    WEB_FETCH_FIELDS,
)
from alfred.i18n import t
from alfred.plugins.transport import ControlResult
from alfred.plugins.web_fetch.allowlist import AllowlistEntry, AllowlistIntersection
from alfred.plugins.web_fetch.errors import (
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchInternalIPRefused,
    WebFetchMimeTypeNotAllowed,
    WebFetchRateLimited,
    WebFetchRedirectRefused,
    WebFetchSizeLimitExceeded,
    WebFetchTlsError,
)
from alfred.plugins.web_fetch.host_ip_guard import check_url_host_ips
from alfred.plugins.web_fetch.rate_limit import RateLimiter
from alfred.plugins.web_fetch.tls_policy import TlsPolicy
from alfred.security.quarantine import ContentHandle

if TYPE_CHECKING:
    from alfred.audit.log import AuditWriter
    from alfred.plugins.transport import PluginTransport
    from alfred.security.dlp import OutboundDlp

log = structlog.get_logger(__name__)

# Slice-3 depth=1 invariant (spec §7.9): every fetch is depth=1. A
# depth>1 fetch would let a quarantined-LLM extract chain re-fetch the
# T3 content via the orchestrator — the depth=1 lock is the structural
# defence pinned by ``test_recursion_depth_one.py``.
_FETCH_DEPTH: Final[int] = 1

# Matches the plugin-side _DEFAULT_SIZE_LIMIT_BYTES so the host and
# subprocess agree on the cap when the plugin's structured error envelope
# omits the limit (defensive default; the plugin always sets it).
_DEFAULT_SIZE_LIMIT_BYTES: Final[int] = 5 * 1024 * 1024

# err-012 fix: explicit map from the plugin-side error.data["type"]
# string to the host-side typed exception. The old draft used
# ``# type: ignore[name-defined]`` for ``WebFetchError`` — the missing
# import was the actual bug. Importing WebFetchError at module top makes
# the ignore unnecessary AND lets the mapping table type-check cleanly.
_ERROR_TYPE_MAP: Final[dict[str, type[WebFetchError]]] = {
    "WebFetchTlsError": WebFetchTlsError,
    "WebFetchMimeTypeNotAllowed": WebFetchMimeTypeNotAllowed,
    "WebFetchSizeLimitExceeded": WebFetchSizeLimitExceeded,
    "WebFetchRedirectRefused": WebFetchRedirectRefused,
    "WebFetchInternalIPRefused": WebFetchInternalIPRefused,
    "TlsConfigError": WebFetchTlsError,
}

# H11 / perf-100: sentinel passed to the ``allowlist`` field's
# ``default_factory`` so the dataclass machinery can run before
# ``__post_init__`` overwrites it with the real intersection.
# ``AllowlistIntersection([], [], [])`` is the canonical empty form —
# its ``check()`` refuses every URL, so a config that somehow skipped
# ``__post_init__`` fails closed at the first allowlist check.
_SENTINEL_ALLOWLIST: Final[AllowlistIntersection] = AllowlistIntersection(
    manifest=[], operator=[], session=[]
)


@dataclass(frozen=True, slots=True)
class FetchDispatchConfig:
    """Immutable per-session configuration for the fetch dispatcher.

    Constructed once at session-start time. The three allowlist tuples
    feed into :class:`AllowlistIntersection`; the
    ``manifest_commit_hash`` provides forensic correlation for the
    plugin version active at fetch time (spec §7.12).

    ``redis_url`` (C2 / arch-002): the plugin subprocess's ``_handle_fetch``
    reads ``params["redis_url"]`` to open its content-store connection. The
    parent owns the connection-string source (operator config) and threads
    it through every dispatch; making it part of the per-session immutable
    config keeps the wire-format contract pinned at config-construction
    time rather than re-resolving per fetch.

    ``skip_tls_verify`` (H1 / H10 / arch-003 / sec-pr-s3-5-001): the dev
    escape hatch documented in :mod:`alfred.plugins.web_fetch.tls_policy`.
    Held on the config so the parent-side :class:`TlsPolicy` check fires
    at construction time (defence-in-depth: a misconfigured production
    operator who flips this bit trips ``TlsConfigError`` immediately —
    before the value is forwarded to the subprocess where the
    subprocess-side check is enforcement-of-last-resort).

    H11 / perf-100: ``allowlist`` is pre-built once in ``__post_init__``
    and reused across every fetch in the session. The pre-fix code
    re-constructed :class:`AllowlistIntersection` (O(manifest * operator
    * session) work) on every dispatch, which is wasted CPU + GC churn
    when the inputs are immutable. Holding the built intersection on
    the per-session config preserves the spec invariant (immutable
    config) and turns the per-fetch hot path into a single
    ``allowlist.check(url)`` call.

    H12 / perf-101: ``_broadening_cap_emitted`` is a mutable cell on
    the otherwise-frozen config tracking whether the cap event has
    been emitted in this session. ``broadening_cap_events()`` is a
    manifest-load-time event (not per-fetch); emitting it on every
    dispatch flooded the audit DB with redundant rows. The cell is a
    single-element ``list`` rather than a bool so frozen+slots stays
    intact (Python's frozen-dataclass guard refuses ``__setattr__``,
    but ``list.append`` mutates in-place — the canonical
    ``frozen-with-internal-cache`` idiom). Concurrency: the dispatcher
    runs in asyncio; the read-then-append is single-shot per cell
    creation, and the worst case under concurrent dispatch is a few
    duplicate rows (forensic-redundant, not a security regression) so
    no lock is needed at this layer.
    """

    manifest_allowed_entries: tuple[AllowlistEntry, ...]
    operator_allowed_entries: tuple[AllowlistEntry, ...]
    session_allowed_entries: tuple[AllowlistEntry, ...]
    manifest_commit_hash: str
    redis_url: str
    plugin_id: str = "alfred.web-fetch"
    skip_tls_verify: bool = False
    # H11 / H12: late-bound cached state. Both fields are ``init=False``
    # so they don't appear in the generated ``__init__`` signature
    # (callers still construct ``FetchDispatchConfig(manifest=..., ...)``).
    # ``default_factory`` is the dataclass-idiomatic way to populate them
    # at instance-construction time:
    #   * ``allowlist`` is built in ``__post_init__`` because its inputs
    #     come from the other fields; we seed it with a sentinel and
    #     overwrite via ``object.__setattr__``.
    #   * ``_broadening_cap_emitted`` starts empty — the dispatcher
    #     appends a single token on first emission so subsequent
    #     dispatches see a non-empty list and skip the loop.
    allowlist: AllowlistIntersection = field(
        init=False,
        default_factory=lambda: _SENTINEL_ALLOWLIST,
    )
    _broadening_cap_emitted: list[bool] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        # H11: build the AllowlistIntersection once. ``object.__setattr__``
        # is the canonical Python idiom for frozen-dataclass post-init
        # field population (the dataclass's __setattr__ is the source of
        # the immutability; bypassing it at construction time is the
        # pattern :pep:`557` documents).
        allowlist = AllowlistIntersection(
            manifest=list(self.manifest_allowed_entries),
            operator=list(self.operator_allowed_entries),
            session=list(self.session_allowed_entries),
        )
        object.__setattr__(self, "allowlist", allowlist)


async def dispatch_web_fetch(
    *,
    url: str,
    headers: dict[str, str],
    user_id: str,
    correlation_id: str,
    config: FetchDispatchConfig,
    rate_limiter: RateLimiter,
    outbound_dlp: OutboundDlp,
    audit: AuditWriter,
    transport: PluginTransport,
) -> ContentHandle:
    """Full orchestrator-side ``web.fetch`` dispatch (spec §7.1-§7.12).

    Returns a :class:`ContentHandle` on success. Raises
    :class:`WebFetchError` subclasses on operational failure — domain
    not allowed, rate-limit refusal, TLS verification failure, MIME
    rejection, size cap, or generic plugin error.

    The :class:`~alfred.plugins.web_fetch.errors.WebFetchCanaryTripped`
    security event is deliberately NOT a ``WebFetchError`` subclass —
    canary trips surface via the host-side
    :class:`alfred.plugins.web_fetch.canary_scanner.InboundCanaryScanner`
    on the post-hookpoint, not through this function's exception arm.

    T3-tagging contract (C1 / arch-001 / PRD §7.1): the returned
    :class:`ContentHandle` is opaque — it carries no ``.content`` field.
    The actual T3 tagging of the fetched bytes happens **inside the
    transport** at :meth:`alfred.plugins.stdio_transport.StdioTransport._read_response`
    (the canonical anchor: the transport calls ``tag_t3_with_nonce`` on
    the decoded bytes and persists the wrapped :class:`~alfred.security.tiers.TaggedContent[T3]`
    into the content store keyed by ``ContentHandle.id``). The dispatcher
    pins this contract by returning ONLY a :class:`ContentHandle` on the
    success path — by the time control reaches that ``return``, the
    transport has already minted the handle AND written the T3-tagged
    wrapper to the store. Per the task's option (b), the dereference
    site (the quarantined-LLM plugin's ``get(handle_id)``) is the
    unambiguous "first host-side read" of the content; the wrapper at
    that point carries the nonce + provenance the dual-LLM split relies
    on (PRD §7.1 invariant).
    """
    # Parent-side TLS policy check (H1 / H10 / arch-003 / sec-pr-s3-5-001 /
    # ar-002): construct :class:`TlsPolicy` BEFORE any subprocess dispatch
    # so a non-development environment with ``skip_tls_verify=True`` fails
    # loud in the parent — never reaching ``transport.dispatch``. The
    # subprocess-side check is defence-in-depth; the parent-side check is
    # the authoritative gate. Raises :class:`TlsConfigError` (which is an
    # :class:`AlfredError`, not a :class:`WebFetchError` — the policy
    # rejection is a config refusal, not an operational fetch error, so
    # callers see a distinct exception class).
    TlsPolicy(skip_tls_verify=config.skip_tls_verify)

    # Step 1: OutboundDlp on both fields (spec §7.9b). The plan called
    # this ``scan_fields`` but the actual OutboundDlp surface is a single
    # ``scan(text: str) -> str``; we run it once per field.
    #
    # M7 / err-003: a DLP-scan exception (broker outage, regex panic) is
    # a security-path failure — emit an audit row BEFORE the re-raise so
    # the operator log carries the failure even if the caller swallows
    # it (CLAUDE.md hard rule #7). The closed-vocabulary
    # ``dlp_scan_error`` result tag is distinct from
    # ``scanned_dirty`` / ``clean`` so audit consumers can branch on
    # transport-layer DLP failures vs in-band DLP modification.
    try:
        clean_url = outbound_dlp.scan(url)
        # M3 / arch-006: scan each header value individually rather than
        # one ``str(headers)`` blob. The old code redacted the blob and
        # then THREW IT AWAY — the original ``headers`` dict crossed the
        # wire verbatim, so header-shaped secrets (Bearer tokens,
        # ``Authorization`` values) leaked. Per-field scanning lets us
        # construct ``clean_headers`` and dispatch with redacted values.
        # OutboundDlp's surface is ``scan(text: str) -> str`` (no
        # per-field API in Slice-3); iteration over the dict is the
        # idiomatic fix.
        clean_headers: dict[str, str] = {name: outbound_dlp.scan(v) for name, v in headers.items()}
    except Exception:
        domain_for_audit = urlparse(url).netloc
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": url,
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
    domain = urlparse(clean_url).netloc

    # Step 2: Three-way allowlist intersection (spec §7.4).
    #
    # H11 / perf-100: the intersection is pre-built once on the per-
    # session ``FetchDispatchConfig`` (see ``__post_init__``). The
    # per-fetch hot path is now a single ``check()`` call, avoiding the
    # O(manifest * operator * session) reconstruction per dispatch.
    allowlist = config.allowlist

    # H12 / perf-101: the broadening-cap audit row is a manifest-load-
    # time event (not per-fetch). The pre-fix code emitted it on every
    # dispatch, flooding the audit DB. The ``_broadening_cap_emitted``
    # cell on the config is the once-then-skip latch: an empty list
    # means "not yet emitted", a non-empty list means "already emitted
    # in this session" so we skip.
    #
    # We keep the audit-row content tied to the correlation_id of the
    # FETCH that exposed the cap (forensic locality) rather than the
    # session-start correlation id — operators tracing a fetch failure
    # back to a manifest cap event need both ids on the same row.
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
                    "capped_domains": [e.domain for e in cap_event.capped_domains],
                    "correlation_id": correlation_id,
                },
                trust_tier_of_trigger="T0",
                result="capped",
                cost_estimate_usd=0.0,
                trace_id=correlation_id,
            )
        # Mark emitted regardless of whether there were any events to
        # emit — the loop is the manifest-load-time read; if the
        # manifest had no capped entries today it will not magically
        # grow them mid-session (the config is frozen). Latching after
        # the loop guards against the rare case where a future refactor
        # makes ``broadening_cap_events()`` non-idempotent.
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

    # Step 2b: Host-IP allowlist guard (sec-pr-s3-5-003 / H3 SSRF defence).
    #
    # The three-way URL allowlist above matched on the URL netloc (the
    # *name* the caller asked for) — it does NOT check the resolved IP.
    # An attacker who controls DNS for an allowlisted domain can return
    # an RFC1918 / cloud-metadata / loopback address (DNS rebinding) so
    # the fetcher hits an internal endpoint anyway. The IP guard pre-
    # resolves the hostname and refuses if ANY resolved IP is internal.
    #
    # Emit a typed audit row BEFORE re-raising so the forensic trail
    # carries the refusal class (CLAUDE.md hard rule #7). The
    # ``internal_ip_refused`` ``dlp_scan_result`` tag is closed-vocabulary
    # so audit consumers can pivot by attack class against the
    # rfc1918 / link_local / loopback / multicast / reserved /
    # dns_failure / no_hostname reasons the host_ip_guard exception
    # carries on its ``.reason`` attribute.
    try:
        check_url_host_ips(clean_url, TlsPolicy(skip_tls_verify=config.skip_tls_verify))
    except WebFetchInternalIPRefused:
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
                "dlp_scan_result": "internal_ip_refused",
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="internal_ip_refused",
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
                # Record the specific bucket that refused ("per_domain"
                # / "per_user" / "daily_budget") so operators can target
                # the tightened limit without re-correlating.
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

    # Step 4: Dispatch to the plugin subprocess via the transport.
    #
    # ``redis_url`` (C2 / arch-002): the plugin's ``_handle_fetch`` reads
    # ``params["redis_url"]`` to open its content-store connection. Without
    # this key the subprocess would ``KeyError`` on first real dispatch.
    # The parent owns the connection-string source so the subprocess
    # cannot synthesise its own — pin the URL at the wire-format boundary.
    #
    # ``skip_tls_verify`` (H1 / H10 / arch-003): forwarded so the
    # subprocess-side :class:`TlsPolicy` check fires too (defence-in-depth
    # — the parent-side check above is the authoritative gate, but the
    # subprocess MUST also refuse to silently honour a flipped bit).
    #
    # M7 / err-004: a transport-layer crash (subprocess death, broken
    # pipe, framing error) is a forensic-attribution failure if we
    # silently re-raise — emit an audit row BEFORE propagating so the
    # operator log carries the failure (CLAUDE.md hard rule #7). The
    # ``transport_error`` result tag is closed-vocabulary, distinct from
    # ``dispatch_shape_error`` (in-band protocol violation) and the
    # ``dlp_scan_result`` family (which Slice-3 documents as locked
    # schema — see devex-002 note below).
    try:
        result = await transport.dispatch(
            "web.fetch",
            {
                "url": clean_url,
                "headers": clean_headers,
                "correlation_id": correlation_id,
                "redis_url": config.redis_url,
                "skip_tls_verify": config.skip_tls_verify,
            },
        )
    except Exception:
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
                "dlp_scan_result": "transport_error",
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="transport_error",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        raise

    if isinstance(result, ContentHandle):
        handle = result
    elif isinstance(result, ControlResult):
        # err-012 fix: the plugin returned a structured JSON-RPC error
        # envelope; the transport's control-plane shape surfaces it as
        # ControlResult.payload. Map the ``data.type`` tag (or top-level
        # ``type``) to the right typed exception via _ERROR_TYPE_MAP.
        # Raising WebFetchTlsError for every non-handle path was wrong
        # — MIME refusals and size-limit refusals are distinct user-
        # facing failures and the audit row's dlp_scan_result tag MUST
        # reflect the actual refusal reason.
        error_data: dict[str, object] = dict(result.payload)
        error_type_obj = error_data.get("type", "WebFetchError")
        error_type = error_type_obj if isinstance(error_type_obj, str) else "WebFetchError"
        dlp_scan_obj = error_data.get("dlp_scan_result", "fetch_error")
        dlp_result = dlp_scan_obj if isinstance(dlp_scan_obj, str) else "fetch_error"
        status_code_obj = error_data.get("status_code")
        status_code: int | None = status_code_obj if isinstance(status_code_obj, int) else None

        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject={
                "url": clean_url,
                "domain": domain,
                "status_code": status_code,
                "content_handle_id": None,
                "fetch_depth": _FETCH_DEPTH,
                "rate_limit_bucket": None,
                "manifest_commit_hash": config.manifest_commit_hash,
                "trust_tier_of_result": "T3",
                "dlp_scan_result": dlp_result,
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result=dlp_result,
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )

        # Resolve to the specific exception subclass. Each branch maps
        # the structured ``error.data`` carrier shape to the typed
        # exception's positional contract — keeping the typing tight at
        # the boundary avoids ``Any``-leakage downstream.
        exc_class = _ERROR_TYPE_MAP.get(error_type, WebFetchError)
        message_obj = error_data.get("message", str(error_data))
        message_str = message_obj if isinstance(message_obj, str) else str(error_data)
        if exc_class is WebFetchTlsError:
            raise WebFetchTlsError(url=clean_url, detail=message_str)
        if exc_class is WebFetchMimeTypeNotAllowed:
            mime_obj = error_data.get("mime_type", "unknown")
            mime_str = mime_obj if isinstance(mime_obj, str) else "unknown"
            raise WebFetchMimeTypeNotAllowed(mime_str)
        if exc_class is WebFetchSizeLimitExceeded:
            size_obj = error_data.get("size_bytes", 0)
            limit_obj = error_data.get("limit_bytes", _DEFAULT_SIZE_LIMIT_BYTES)
            size_bytes = size_obj if isinstance(size_obj, int) else 0
            limit_bytes = limit_obj if isinstance(limit_obj, int) else _DEFAULT_SIZE_LIMIT_BYTES
            raise WebFetchSizeLimitExceeded(size_bytes=size_bytes, limit_bytes=limit_bytes)
        if exc_class is WebFetchRedirectRefused:
            status_obj = error_data.get("status_code", 0)
            target_obj = error_data.get("redirect_target", "")
            status_int = status_obj if isinstance(status_obj, int) else 0
            target_str = target_obj if isinstance(target_obj, str) else ""
            raise WebFetchRedirectRefused(status_code=status_int, redirect_target=target_str)
        if exc_class is WebFetchInternalIPRefused:
            # sec-pr-s3-5-003: the subprocess-side IP guard caught a
            # DNS-rebinding race (the parent-side guard resolved to a
            # safe IP; the subprocess's own resolution returned an
            # internal one). The typed exception preserves the closed
            # reason vocabulary so the audit row + structlog stream see
            # the same attack class string the parent-side guard would
            # have emitted.
            resolved_obj = error_data.get("resolved_ip", "")
            reason_obj = error_data.get("reason", "reserved")
            resolved_str = resolved_obj if isinstance(resolved_obj, str) else ""
            reason_str = reason_obj if isinstance(reason_obj, str) else "reserved"
            raise WebFetchInternalIPRefused(
                url=clean_url,
                resolved_ip=resolved_str,
                reason=reason_str,
            )
        # C4 / i18n-002: the plugin-side ``message`` string is data, NOT
        # a localisable surface — wrap the WebFetchError carrier in t()
        # so the operator-visible error text is catalogued. The
        # plugin-supplied detail flows through as a placeholder so
        # forensic attribution is preserved without bypassing the i18n
        # contract (CLAUDE.md i18n hard rule #1).
        raise WebFetchError(t("web.fetch.error.plugin_returned_message", message=message_str))
    else:
        # An ExtractionResult coming back from a ``web.fetch`` dispatch
        # is a protocol violation — extraction is only legitimate for
        # quarantine.extract. We surface as WebFetchError so callers
        # see a typed failure (audit row + exception) rather than a
        # silent type confusion downstream.
        shape_name = type(result).__name__
        # H7 / err-001: emit a ``dispatch_shape_error`` audit row BEFORE
        # the raise. A trust-boundary anomaly (transport contract
        # violation) must surface in the audit graph; structlog alone
        # leaves no row in the audit DB for forensic correlation.
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
                "trust_tier_of_result": "T0",
                "dlp_scan_result": "dispatch_shape_error",
                "canary_tripped": False,
                "triggering_user_id": user_id,
                "correlation_id": correlation_id,
            },
            trust_tier_of_trigger="T0",
            result="dispatch_shape_error",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
        # devex-005: normalise structlog event names under
        # ``web_fetch.*`` so log consumers can filter by the subsystem
        # prefix without per-module exceptions.
        log.error(
            "web_fetch.dispatch_shape_error",
            shape=shape_name,
            correlation_id=correlation_id,
        )
        # C3 / i18n-001: wrap the operator-facing exception string via
        # t() so the error text is catalogued. The shape name (a Python
        # type name) is data, surfaced through the ``shape`` placeholder.
        raise WebFetchError(t("web.fetch.error.unexpected_dispatch_shape", shape=shape_name))

    # Step 5: success audit row.
    #
    # H6 / ar-001 / devex-001: ``rate_limit_bucket`` is None on success.
    # The schema declares this field as the bucket tag that REFUSED the
    # fetch ("per_domain" / "per_user" / "daily_budget" / None). The
    # success path did not get refused; previously this row mis-recorded
    # the domain string under ``rate_limit_bucket``, which broke
    # audit-graph filters that pivot on the bucket vocabulary. The
    # ``domain`` field on this row already carries the netloc — see the
    # ``"domain": domain`` line below.
    #
    # M7 / err-005: a success-path audit-write failure must not silently
    # drop the row — emit a LOUD structlog warning carrying the
    # would-be subject so an operator can correlate after the fact, then
    # re-raise. The caller of dispatch_web_fetch loses the handle (the
    # returned ContentHandle is the success token), but the forensic
    # signal survives in the structlog stream.
    #
    # devex-002 (DEFERRED): the ``dlp_scan_result`` field is overloaded —
    # it carries genuine DLP outcomes ("clean", "scanned_dirty",
    # "dlp_scan_error") AND fetch-outcome tags ("domain_not_allowed",
    # "rate_limited", "transport_error", "dispatch_shape_error"). The
    # clean fix is a separate ``fetch_outcome`` field. WEB_FETCH_FIELDS
    # is locked (schema migration would land in a follow-up PR); we
    # document the gap here. Audit-row tests pin the current values so
    # the migration is a clean delta. See task devex-002.
    success_subject: dict[str, object | None] = {
        "url": clean_url,
        "domain": domain,
        # HTTP status is not surfaced through ContentHandle (T3
        # provenance is the field on the handle). The success row
        # carries 200 by convention; if the plugin starts returning
        # non-2xx success responses the schema needs a transport-
        # surfaced status field.
        "status_code": 200,
        "content_handle_id": handle.id,
        "fetch_depth": _FETCH_DEPTH,
        "rate_limit_bucket": None,
        "manifest_commit_hash": config.manifest_commit_hash,
        "trust_tier_of_result": "T3",
        "dlp_scan_result": "clean",
        "canary_tripped": False,
        "triggering_user_id": user_id,
        "correlation_id": correlation_id,
    }
    try:
        await audit.append_schema(
            fields=WEB_FETCH_FIELDS,
            schema_name="WEB_FETCH_FIELDS",
            event="tool.web.fetch",
            actor_user_id=user_id,
            subject=success_subject,
            trust_tier_of_trigger="T0",
            result="ok",
            cost_estimate_usd=0.0,
            trace_id=correlation_id,
        )
    except Exception:
        # LOUD structlog signal so an operator scanning the log finds
        # the would-be row. ``subject`` is serialised in full because the
        # row never reached the audit DB; this is the only forensic trail
        # of the successful fetch.
        log.warning(
            "web_fetch.success_audit_write_failed",
            correlation_id=correlation_id,
            subject=success_subject,
        )
        raise

    return handle


__all__ = ["FetchDispatchConfig", "dispatch_web_fetch"]
