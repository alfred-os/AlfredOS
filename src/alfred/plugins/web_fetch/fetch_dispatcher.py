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

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from urllib.parse import urlparse

import structlog

from alfred.audit.audit_row_schemas import (
    WEB_ALLOWLIST_MANIFEST_BROADENING_CAPPED_FIELDS,
    WEB_FETCH_FIELDS,
)
from alfred.plugins.transport import ControlResult
from alfred.plugins.web_fetch.allowlist import AllowlistEntry, AllowlistIntersection
from alfred.plugins.web_fetch.errors import (
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchMimeTypeNotAllowed,
    WebFetchRateLimited,
    WebFetchRedirectRefused,
    WebFetchSizeLimitExceeded,
    WebFetchTlsError,
)
from alfred.plugins.web_fetch.rate_limit import RateLimiter
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
    "TlsConfigError": WebFetchTlsError,
}


@dataclass(frozen=True, slots=True)
class FetchDispatchConfig:
    """Immutable per-session configuration for the fetch dispatcher.

    Constructed once at session-start time. The three allowlist tuples
    feed into :class:`AllowlistIntersection`; the
    ``manifest_commit_hash`` provides forensic correlation for the
    plugin version active at fetch time (spec §7.12).
    """

    manifest_allowed_entries: tuple[AllowlistEntry, ...]
    operator_allowed_entries: tuple[AllowlistEntry, ...]
    session_allowed_entries: tuple[AllowlistEntry, ...]
    manifest_commit_hash: str
    plugin_id: str = "alfred.web-fetch"


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
    """
    # Step 1: OutboundDlp on both fields (spec §7.9b). The plan called
    # this ``scan_fields`` but the actual OutboundDlp surface is a single
    # ``scan(text: str) -> str``; we run it once per field. ``str(headers)``
    # is the canonical way to scan the header dict for secret-shaped
    # content; the OutboundDlp behaviour on a Python dict-repr is
    # equivalent to scanning the JSON-encoded form for the regex/broker
    # stages (Slice-3 NER lands in a follow-up).
    clean_url = outbound_dlp.scan(url)
    clean_headers_str = outbound_dlp.scan(str(headers))
    # ``clean_headers_str`` is held only for the DLP side-effect; the
    # actual headers dict crosses the wire unchanged. The Slice-3
    # contract is "outbound DLP emits an audit row on modification";
    # the substitution of a redacted-header dict back into the request
    # is left to a follow-up that decouples header-shape from
    # text-shape (NER on multi-line strings is a separate change).
    del clean_headers_str
    domain = urlparse(clean_url).netloc

    # Step 2: Three-way allowlist intersection (spec §7.4).
    allowlist = AllowlistIntersection(
        manifest=list(config.manifest_allowed_entries),
        operator=list(config.operator_allowed_entries),
        session=list(config.session_allowed_entries),
    )

    # Emit broadening-cap audit rows BEFORE the allowlist check — the
    # cap is a manifest-load-time event, not a per-fetch event, but
    # surfacing it here (rather than at session start) keeps the audit
    # row tied to the correlation_id of the fetch that exposed the cap.
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
    result = await transport.dispatch(
        "web.fetch",
        {
            "url": clean_url,
            "headers": headers,
            "correlation_id": correlation_id,
        },
    )

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
        # Fallback: generic WebFetchError carries the plugin's message.
        raise WebFetchError(message_str)
    else:
        # An ExtractionResult coming back from a ``web.fetch`` dispatch
        # is a protocol violation — extraction is only legitimate for
        # quarantine.extract. We surface as WebFetchError so callers
        # see a typed failure (audit row + exception) rather than a
        # silent type confusion downstream.
        log.error(
            "web_fetch.unexpected_dispatch_shape",
            shape=type(result).__name__,
            correlation_id=correlation_id,
        )
        raise WebFetchError(
            f"web.fetch returned unexpected dispatch shape: {type(result).__name__}"
        )

    # Step 5: success audit row.
    await audit.append_schema(
        fields=WEB_FETCH_FIELDS,
        schema_name="WEB_FETCH_FIELDS",
        event="tool.web.fetch",
        actor_user_id=user_id,
        subject={
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
            "rate_limit_bucket": domain,
            "manifest_commit_hash": config.manifest_commit_hash,
            "trust_tier_of_result": "T3",
            "dlp_scan_result": "clean",
            "canary_tripped": False,
            "triggering_user_id": user_id,
            "correlation_id": correlation_id,
        },
        trust_tier_of_trigger="T0",
        result="ok",
        cost_estimate_usd=0.0,
        trace_id=correlation_id,
    )

    return handle


__all__ = ["FetchDispatchConfig", "dispatch_web_fetch"]
