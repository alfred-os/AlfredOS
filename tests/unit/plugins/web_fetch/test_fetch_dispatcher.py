"""Unit tests for the orchestrator-side ``dispatch_web_fetch``.

Trust-boundary code requires 100% line + branch coverage (CLAUDE.md
hard rule). Every branch in
:func:`alfred.plugins.web_fetch.fetch_dispatcher.dispatch_web_fetch` is
exercised here against ``AsyncMock`` fakes for the four collaborators
(transport, dlp, audit, rate_limiter). The branches covered are:

  * Success → ContentHandle returned, success audit row emitted.
  * Broadening cap → manifest-broadening_capped row + success.
  * Domain not allowed → typed audit row + ``WebFetchDomainNotAllowed``
    re-raise.
  * Rate-limited → typed audit row + ``WebFetchRateLimited`` re-raise
    carrying the bucket name.
  * ControlResult error envelope, one branch per ``_ERROR_TYPE_MAP``
    entry plus the fallback generic ``WebFetchError``.
  * Unexpected dispatch shape → ``WebFetchError`` with the shape name.

The fixtures use :class:`unittest.mock.AsyncMock` rather than custom
fakes — the dispatcher's collaborator contract is small enough that the
inspect-time signature check ``AsyncMock`` provides is sufficient.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.plugins.transport import ControlResult
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
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
from alfred.plugins.web_fetch.fetch_dispatcher import (
    FetchDispatchConfig,
    dispatch_web_fetch,
)
from alfred.plugins.web_fetch.tls_policy import TlsConfigError
from alfred.security.quarantine import ContentHandle


def _build_config(
    *,
    manifest: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
    operator: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
    session: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
    skip_tls_verify: bool = False,
    redis_url: str = "redis://localhost:6379/0",
) -> FetchDispatchConfig:
    """Build a :class:`FetchDispatchConfig` with the common shape.

    The defaults set up a single example.com triple-intersection so a
    test that does not care about allowlist drift can call dispatch and
    reach the rate-limiter / transport branches.

    ``redis_url`` (C2) is required at the config level — tests pin a
    deterministic placeholder so the JSON-RPC payload assertion in
    ``test_redis_url_threaded_through_to_dispatch`` stays bit-stable.

    ``skip_tls_verify`` (H1 / H10) defaults to ``False`` so tests
    exercise the production-safe shape; the parent-side
    :class:`TlsPolicy` check passes silently for that value. Tests that
    pin the parent-side refusal pass ``skip_tls_verify=True`` and rely on
    a non-development ``ALFRED_ENV`` to surface the
    :class:`TlsConfigError`.
    """
    return FetchDispatchConfig(
        manifest_allowed_entries=manifest,
        operator_allowed_entries=operator,
        session_allowed_entries=session,
        manifest_commit_hash="abc123",
        redis_url=redis_url,
        skip_tls_verify=skip_tls_verify,
    )


def _build_dlp() -> Any:
    """Build an :class:`OutboundDlp`-shaped fake.

    Only ``scan(text)`` is exercised by the dispatcher; the identity
    return-value is sufficient for every audit-row branch except the
    DLP-modification path (which is a separate primitive owned by
    :mod:`alfred.security.dlp` and tested there).
    """
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda s: s)
    return dlp


def _build_audit() -> AsyncMock:
    """Build an :class:`AuditWriter`-shaped async fake."""
    audit = AsyncMock()
    audit.append_schema = AsyncMock(return_value=None)
    return audit


def _build_rate_limiter(*, refused: str | None = None) -> AsyncMock:
    """Build a :class:`RateLimiter`-shaped fake.

    ``refused`` is the bucket name to raise with; ``None`` lets the
    check pass and the dispatch continues to the transport.
    """
    rate_limiter = AsyncMock()
    if refused is None:
        rate_limiter.check_and_increment = AsyncMock(return_value=None)
    else:
        rate_limiter.check_and_increment = AsyncMock(side_effect=WebFetchRateLimited(refused))
    return rate_limiter


def _build_transport_returning_handle() -> AsyncMock:
    """Build a transport whose dispatch returns a :class:`ContentHandle`."""
    transport = AsyncMock()
    handle = ContentHandle(
        id="handle-uuid",
        source_url="https://example.com/page",
        fetch_timestamp=datetime.now(tz=UTC),
    )
    transport.dispatch = AsyncMock(return_value=handle)
    return transport


def _build_transport_returning_control(payload: dict[str, object]) -> AsyncMock:
    """Build a transport whose dispatch returns a :class:`ControlResult`."""
    transport = AsyncMock()
    transport.dispatch = AsyncMock(return_value=ControlResult(method="web.fetch", payload=payload))
    return transport


@pytest.mark.asyncio
async def test_success_returns_handle_and_emits_ok_audit_row() -> None:
    """The success path returns the ContentHandle from transport.dispatch
    and writes a ``result="ok"`` row keyed on its handle id.

    H6 / ar-001: the success row sets ``rate_limit_bucket=None`` —
    the field's domain is the bucket tag that REFUSED the fetch, not
    the netloc that succeeded. ``domain`` carries the netloc instead.
    """
    audit = _build_audit()
    handle = await dispatch_web_fetch(
        url="https://example.com/page",
        headers={"User-Agent": "alfred"},
        user_id="user-1",
        correlation_id="corr-1",
        config=_build_config(),
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=_build_transport_returning_handle(),
    )

    assert isinstance(handle, ContentHandle)
    assert handle.id == "handle-uuid"
    # Only the success row should have been emitted (no broadening cap
    # because manifest ⊆ operator). The symmetric ``append_schema`` check
    # validates every WEB_FETCH_FIELDS key is present.
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["event"] == "tool.web.fetch"
    assert call.kwargs["result"] == "ok"
    subject = call.kwargs["subject"]
    assert subject["content_handle_id"] == "handle-uuid"
    assert subject["dlp_scan_result"] == "clean"
    assert subject["status_code"] == 200
    # H6: success path leaves rate_limit_bucket=None — the bucket is the
    # refusal tag, not the success domain.
    assert subject["rate_limit_bucket"] is None
    assert subject["domain"] == "example.com"


@pytest.mark.asyncio
async def test_broadening_cap_emits_capped_row_then_succeeds() -> None:
    """Manifest declares a domain the operator does not permit → the
    cap event surfaces as a ``web.allowlist.manifest_broadening_capped``
    row before the dispatch."""
    audit = _build_audit()
    manifest = (
        AllowlistEntry(domain="example.com"),
        AllowlistEntry(domain="evil.com"),  # capped — not in operator set
    )
    operator = (AllowlistEntry(domain="example.com"),)
    session = (AllowlistEntry(domain="example.com"),)

    await dispatch_web_fetch(
        url="https://example.com/page",
        headers={},
        user_id="user-1",
        correlation_id="corr-2",
        config=_build_config(manifest=manifest, operator=operator, session=session),
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=_build_transport_returning_handle(),
    )

    # Two rows: broadening_capped + ok.
    assert audit.append_schema.await_count == 2
    first_call = audit.append_schema.await_args_list[0]
    assert first_call.kwargs["event"] == "web.allowlist.manifest_broadening_capped"
    assert first_call.kwargs["result"] == "capped"
    # CR-146 major: capped_domains now carries (domain, path_prefix)
    # dicts rather than bare-domain strings — the bare-domain shape
    # collapsed two manifest entries on the same domain with different
    # prefixes (e.g. ``example.com/admin/`` vs ``example.com/private/``)
    # into indistinguishable audit rows, losing forensic detail PRD
    # §7.4 / §13 demand.
    capped = first_call.kwargs["subject"]["capped_domains"]
    assert any(entry["domain"] == "evil.com" for entry in capped)
    # AllowlistEntry default path_prefix is "/" — the manifest entry
    # ``AllowlistEntry(domain="evil.com")`` records its full
    # (domain, path_prefix) shape in the audit row.
    assert any(entry["domain"] == "evil.com" and entry["path_prefix"] == "/" for entry in capped)


@pytest.mark.asyncio
async def test_capped_domains_preserve_path_prefix_in_audit_row() -> None:
    """CR-146 major: two manifest entries on the SAME domain capped
    to different path prefixes must not collapse to a single bare
    domain in the audit row. The dict-form ``(domain, path_prefix)``
    keeps the forensic detail PRD §7.4 / §13 demand.
    """
    audit = _build_audit()
    manifest = (
        AllowlistEntry(domain="example.com"),
        # Two evil.com entries on different prefixes — without the
        # dict-form they would become a single ``"evil.com"`` string
        # in the audit row, hiding which prefix the manifest tried to
        # add.
        AllowlistEntry(domain="evil.com", path_prefix="/admin"),
        AllowlistEntry(domain="evil.com", path_prefix="/private"),
    )
    operator = (AllowlistEntry(domain="example.com"),)
    session = (AllowlistEntry(domain="example.com"),)

    await dispatch_web_fetch(
        url="https://example.com/page",
        headers={},
        user_id="user-1",
        correlation_id="corr-cr146-cap-prefix",
        config=_build_config(manifest=manifest, operator=operator, session=session),
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=_build_transport_returning_handle(),
    )

    first_call = audit.append_schema.await_args_list[0]
    capped = first_call.kwargs["subject"]["capped_domains"]
    # Both capped entries on evil.com appear DISTINCTLY in the audit
    # row (the bare-domain shape would have produced one collapsed
    # entry).
    assert {(e["domain"], e["path_prefix"]) for e in capped} >= {
        ("evil.com", "/admin/"),
        ("evil.com", "/private/"),
    }


@pytest.mark.asyncio
async def test_domain_not_allowed_audits_then_raises() -> None:
    """A URL outside the effective allowlist emits a
    ``result="domain_not_allowed"`` row before re-raising."""
    audit = _build_audit()
    with pytest.raises(WebFetchDomainNotAllowed):
        await dispatch_web_fetch(
            url="https://evil.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-3",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=_build_transport_returning_handle(),
        )
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "domain_not_allowed"
    assert call.kwargs["subject"]["dlp_scan_result"] == "domain_not_allowed"


@pytest.mark.asyncio
async def test_rate_limited_audits_with_bucket_then_raises() -> None:
    """A rate-limit refusal records the bucket name and re-raises."""
    audit = _build_audit()
    with pytest.raises(WebFetchRateLimited) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-4",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(refused="per_domain"),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=_build_transport_returning_handle(),
        )
    assert excinfo.value.bucket == "per_domain"
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "rate_limited"
    assert call.kwargs["subject"]["rate_limit_bucket"] == "per_domain"


@pytest.mark.asyncio
async def test_control_result_tls_error_maps_to_tls_exception() -> None:
    """A ControlResult with ``type=WebFetchTlsError`` raises
    :class:`WebFetchTlsError`."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchTlsError",
            "message": "cert expired",
            "dlp_scan_result": "tls_verification_failed",
        }
    )
    with pytest.raises(WebFetchTlsError) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-5",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.detail == "cert expired"
    assert audit.append_schema.await_count == 1
    assert audit.append_schema.await_args.kwargs["result"] == "tls_verification_failed"


@pytest.mark.asyncio
async def test_control_result_tls_config_error_also_maps_to_tls_exception() -> None:
    """``TlsConfigError`` (plugin couldn't construct policy) maps to
    :class:`WebFetchTlsError` so callers see one TLS failure class."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "TlsConfigError",
            "message": "skip_tls_verify=True requires ALFRED_ENV=development",
        }
    )
    with pytest.raises(WebFetchTlsError):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-5b",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )


@pytest.mark.asyncio
async def test_control_result_mime_error_maps_to_mime_exception() -> None:
    """A ControlResult with MIME refusal raises
    :class:`WebFetchMimeTypeNotAllowed` carrying the refused mime."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchMimeTypeNotAllowed",
            "message": "MIME type 'image/png' not allowed",
            "mime_type": "image/png",
        }
    )
    with pytest.raises(WebFetchMimeTypeNotAllowed) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-6",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.mime_type == "image/png"


@pytest.mark.asyncio
async def test_control_result_size_error_maps_to_size_exception() -> None:
    """A ControlResult with size refusal raises
    :class:`WebFetchSizeLimitExceeded` carrying both byte counts."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchSizeLimitExceeded",
            "message": "Response body exceeded limit 1024 bytes",
            "size_bytes": 2048,
            "limit_bytes": 1024,
        }
    )
    with pytest.raises(WebFetchSizeLimitExceeded) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-7",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.size_bytes == 2048
    assert excinfo.value.limit_bytes == 1024


@pytest.mark.asyncio
async def test_control_result_redirect_refused_maps_to_redirect_exception() -> None:
    """A ControlResult with redirect refusal raises
    :class:`WebFetchRedirectRefused` carrying the status code and target.

    SSRF guard (spec §7.4, CR-145): the plugin refuses 3xx upstream because
    a follow-the-redirect path would let an allowlisted endpoint hand off
    to an internal-IP / non-allowlisted target. This test pins the
    error-type-map plumbing so the typed exception (and its audit row)
    reaches the orchestrator instead of a generic WebFetchError.
    """
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchRedirectRefused",
            "message": "Redirect refused: 302 -> 'http://10.0.0.1/internal'",
            "status_code": 302,
            "redirect_target": "http://10.0.0.1/internal",
            "dlp_scan_result": "redirect_refused",
        }
    )
    with pytest.raises(WebFetchRedirectRefused) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/redir",
            headers={},
            user_id="user-1",
            correlation_id="corr-redir",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.status_code == 302
    assert excinfo.value.redirect_target == "http://10.0.0.1/internal"


@pytest.mark.asyncio
async def test_control_result_redirect_refused_with_non_int_status_defaults() -> None:
    """Defence-in-depth: a malformed plugin payload with a non-int
    ``status_code`` defaults to 0 rather than raising TypeError. The
    plugin always emits an int today but the dispatcher is the host-side
    type-narrowing layer."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchRedirectRefused",
            "message": "Redirect refused",
            "status_code": "302",  # str, not int — defensive coercion
            "redirect_target": "http://attacker.example/",
        }
    )
    with pytest.raises(WebFetchRedirectRefused) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/redir",
            headers={},
            user_id="user-1",
            correlation_id="corr-redir-defensive",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.status_code == 0
    assert excinfo.value.redirect_target == "http://attacker.example/"


@pytest.mark.asyncio
async def test_control_result_redirect_refused_with_non_str_target_defaults() -> None:
    """Defence-in-depth: a malformed plugin payload with a non-str
    ``redirect_target`` defaults to empty string rather than propagating
    a non-str into the typed exception attribute."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchRedirectRefused",
            "message": "Redirect refused",
            "status_code": 301,
            "redirect_target": 12345,  # int, not str — defensive coercion
        }
    )
    with pytest.raises(WebFetchRedirectRefused) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/redir",
            headers={},
            user_id="user-1",
            correlation_id="corr-redir-target-defensive",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.status_code == 301
    assert excinfo.value.redirect_target == ""


@pytest.mark.asyncio
async def test_control_result_unknown_type_falls_back_to_generic_error() -> None:
    """A ControlResult with an unknown ``type`` falls back to
    :class:`WebFetchError`."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchError",
            "message": "DNS resolution failed",
        }
    )
    with pytest.raises(WebFetchError) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-8",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    # The generic fallback carries the plugin-side message string.
    assert "DNS resolution failed" in str(excinfo.value)


@pytest.mark.asyncio
async def test_control_result_with_non_string_type_falls_back_to_default() -> None:
    """Defence-in-depth: a malformed ``type`` (non-string) defaults to
    ``WebFetchError`` rather than tripping a TypeError."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": 42,  # non-string — defensive default to WebFetchError
            "message": "weird payload",
        }
    )
    with pytest.raises(WebFetchError):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-9",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )


@pytest.mark.asyncio
async def test_control_result_with_non_string_dlp_result_uses_default() -> None:
    """A ControlResult whose ``dlp_scan_result`` is not a string defaults
    to ``fetch_error`` — the audit row stays well-typed."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchError",
            "message": "stuff",
            "dlp_scan_result": ["not", "a", "string"],
        }
    )
    with pytest.raises(WebFetchError):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-10",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert audit.append_schema.await_args.kwargs["result"] == "fetch_error"


@pytest.mark.asyncio
async def test_control_result_with_int_status_code_is_recorded() -> None:
    """A ControlResult with ``status_code`` (int) records that integer
    onto the audit row."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchError",
            "message": "upstream 500",
            "status_code": 500,
        }
    )
    with pytest.raises(WebFetchError):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-11",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert audit.append_schema.await_args.kwargs["subject"]["status_code"] == 500


@pytest.mark.asyncio
async def test_control_result_with_non_int_status_code_records_none() -> None:
    """A malformed ``status_code`` (non-int) is recorded as ``None``
    rather than passed through unchanged."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchError",
            "message": "weird",
            "status_code": "five hundred",
        }
    )
    with pytest.raises(WebFetchError):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-12",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert audit.append_schema.await_args.kwargs["subject"]["status_code"] is None


@pytest.mark.asyncio
async def test_control_result_size_error_with_missing_byte_counts_uses_defaults() -> None:
    """Size-limit envelope without ``size_bytes`` / ``limit_bytes`` keys
    falls back to ``0`` / module default."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchSizeLimitExceeded",
            "message": "exceeded",
        }
    )
    with pytest.raises(WebFetchSizeLimitExceeded) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-13",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.size_bytes == 0
    assert excinfo.value.limit_bytes == 5 * 1024 * 1024


@pytest.mark.asyncio
async def test_control_result_size_error_with_non_int_bytes_uses_defaults() -> None:
    """Defence-in-depth: non-int ``size_bytes`` / ``limit_bytes`` fall
    back to defaults rather than passing through to the exception."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchSizeLimitExceeded",
            "size_bytes": "lots",
            "limit_bytes": "more",
        }
    )
    with pytest.raises(WebFetchSizeLimitExceeded) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-14",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.size_bytes == 0
    assert excinfo.value.limit_bytes == 5 * 1024 * 1024


@pytest.mark.asyncio
async def test_control_result_mime_error_with_non_string_mime_uses_default() -> None:
    """Malformed mime field defaults to ``"unknown"``."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchMimeTypeNotAllowed",
            "mime_type": 12345,
        }
    )
    with pytest.raises(WebFetchMimeTypeNotAllowed) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-15",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.mime_type == "unknown"


@pytest.mark.asyncio
async def test_control_result_with_non_string_message_falls_back_to_repr() -> None:
    """A non-string ``message`` falls back to ``str(error_data)`` so the
    generic WebFetchError carries something diagnostic."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchError",
            "message": {"weird": "object"},
        }
    )
    with pytest.raises(WebFetchError) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-16",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    # str(error_data) carries the full dict repr.
    assert "weird" in str(excinfo.value)


@pytest.mark.asyncio
async def test_unexpected_dispatch_shape_raises_generic_error() -> None:
    """A transport that returns a shape outside the
    ``DispatchResult`` union (used here as an
    :class:`ExtractionResult`-shaped surrogate) surfaces as a generic
    ``WebFetchError`` with the type name in the message.

    H7 / err-001: the dispatch-shape-error path now emits a
    ``result="dispatch_shape_error"`` audit row BEFORE raising — the
    structlog event alone left no row in the audit DB for forensic
    correlation, which broke the audit-graph invariant for a
    trust-boundary anomaly.

    C3 / i18n-001: the WebFetchError message routes through t(); the
    shape name is the i18n placeholder.
    """
    audit = _build_audit()

    class _UnknownResult:
        """Placeholder for an unexpected dispatch shape."""

    transport = AsyncMock()
    transport.dispatch = AsyncMock(return_value=_UnknownResult())

    with pytest.raises(WebFetchError) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-17",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert "_UnknownResult" in str(excinfo.value)
    # H7: audit row emitted with dispatch_shape_error result.
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "dispatch_shape_error"
    assert call.kwargs["subject"]["dlp_scan_result"] == "dispatch_shape_error"
    # trust_tier_of_result is T0 not T3 — there is no T3 content to
    # quarantine because the transport never delivered a handle.
    assert call.kwargs["subject"]["trust_tier_of_result"] == "T0"


# ---------------------------------------------------------------------------
# Commit 1 — C1 / C2 / H1+H10: T3 tagging contract, redis_url threading,
# parent-side TlsPolicy.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_url_threaded_through_to_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C2 / arch-002: the JSON-RPC payload MUST carry ``redis_url``.

    Without this key, the plugin subprocess's ``_handle_fetch`` would
    ``KeyError`` on its first fetch. The parent-owned URL is the only
    legitimate source; threading it through every dispatch keeps the
    wire-format contract pinned in one place.
    """
    monkeypatch.setenv("ALFRED_ENV", "development")
    audit = _build_audit()
    transport = _build_transport_returning_handle()
    redis_url = "redis://operator-redis:6379/3"

    await dispatch_web_fetch(
        url="https://example.com/page",
        headers={"User-Agent": "alfred"},
        user_id="user-1",
        correlation_id="corr-c2",
        config=_build_config(redis_url=redis_url),
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=transport,
    )

    # The transport's dispatch was called with the JSON-RPC params dict
    # as the second positional argument.
    args, _kwargs = transport.dispatch.await_args
    params = args[1]
    assert params["redis_url"] == redis_url, (
        f"FetchDispatchConfig.redis_url must thread into transport.dispatch params; got {params!r}"
    )


@pytest.mark.asyncio
async def test_skip_tls_verify_threaded_through_to_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H1 / H10: ``skip_tls_verify`` flows from config to the subprocess.

    Defence-in-depth: the parent-side :class:`TlsPolicy` check is the
    authoritative gate; the subprocess-side check is the second line of
    defence. The bit MUST be threaded explicitly through the wire so the
    subprocess cannot drift into accepting bad TLS independently of the
    parent's decision.
    """
    # ALFRED_ENV=development is required so the parent-side TlsPolicy
    # check accepts skip_tls_verify=True at all (fail-closed default).
    monkeypatch.setenv("ALFRED_ENV", "development")
    audit = _build_audit()
    transport = _build_transport_returning_handle()

    await dispatch_web_fetch(
        url="https://example.com/page",
        headers={},
        user_id="user-1",
        correlation_id="corr-h1-thread",
        config=_build_config(skip_tls_verify=True),
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=transport,
    )

    args, _kwargs = transport.dispatch.await_args
    params = args[1]
    assert params["skip_tls_verify"] is True


@pytest.mark.asyncio
async def test_parent_tls_policy_refuses_skip_in_non_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H1 / H10 / arch-003 / sec-pr-s3-5-001 / ar-002.

    The parent-side :class:`TlsPolicy` check fires BEFORE
    ``transport.dispatch`` is called. In a non-development environment
    a config with ``skip_tls_verify=True`` must raise
    :class:`TlsConfigError` and never touch the subprocess — otherwise a
    compromised orchestrator caller could rely solely on subprocess-side
    enforcement and a buggy plugin would silently accept the bypass.
    """
    monkeypatch.setenv("ALFRED_ENV", "production")
    audit = _build_audit()
    transport = _build_transport_returning_handle()

    with pytest.raises(TlsConfigError):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-h1",
            config=_build_config(skip_tls_verify=True),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    # Parent-side check fires BEFORE the transport is touched.
    assert transport.dispatch.await_count == 0
    # The refusal happens before audit emission too — the TlsConfigError
    # is the structural signal; refusal accounting at this layer would
    # double-count with the supervisor-side ``supervisor.config_insecure``
    # row that observes the same condition at startup.
    assert audit.append_schema.await_count == 0


@pytest.mark.asyncio
async def test_t3_tagging_contract_documented_on_success_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C1 / arch-001: success path returns the opaque :class:`ContentHandle`.

    The contract this test pins is structural, not behavioural — the
    dispatcher relies on
    :meth:`alfred.plugins.stdio_transport.StdioTransport._read_response`
    having tagged the bytes T3 and persisted the wrapper into the
    content store BEFORE returning the handle (see the docstring
    "T3-tagging contract" block). This test fails loud if a future
    refactor changes the success-path return type to something other
    than :class:`ContentHandle` (e.g. directly returning bytes), because
    that would break the dereference-site contract — the
    quarantined-LLM plugin's ``get(handle_id)`` MUST be the unambiguous
    "first host-side read" of the content.
    """
    monkeypatch.setenv("ALFRED_ENV", "development")
    audit = _build_audit()
    transport = _build_transport_returning_handle()

    result = await dispatch_web_fetch(
        url="https://example.com/page",
        headers={},
        user_id="user-1",
        correlation_id="corr-c1",
        config=_build_config(),
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=transport,
    )
    # The structural pin: success returns ContentHandle (opaque), not
    # bytes / TaggedContent / dict / etc. ContentHandle carries no
    # ``.content`` field — see :mod:`alfred.security.quarantine`.
    assert isinstance(result, ContentHandle)
    assert not hasattr(result, "content")


# ---------------------------------------------------------------------------
# Commit 2 — H6 / H7 / C3 / C4 / M7 / devex-002 / devex-005: audit-row
# fidelity + error-arm coverage + i18n catalogue.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dlp_scan_exception_emits_audit_row_then_raises() -> None:
    """M7 / err-003: a DLP-scan exception emits a
    ``result="dlp_scan_error"`` audit row BEFORE re-raising.

    Without the row, a broker outage / regex panic on the security
    path leaves no forensic trail — CLAUDE.md hard rule #7 (no silent
    failures in security paths).
    """
    audit = _build_audit()

    class _DlpExplodedError(RuntimeError):
        pass

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=_DlpExplodedError("broker offline"))

    with pytest.raises(_DlpExplodedError):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-m7-dlp",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=dlp,
            audit=audit,
            transport=_build_transport_returning_handle(),
        )
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "dlp_scan_error"
    assert call.kwargs["subject"]["dlp_scan_result"] == "dlp_scan_error"
    # CR-146 major: PRD §7.9b's fail-closed contract means the raw URL
    # MUST NOT land in the audit row when the DLP scan failed — the
    # unscanned URL may carry query-string secrets that the DLP would
    # otherwise have redacted. Substitute a sentinel so a broker outage
    # cannot become a secret-exfiltration path INTO audit storage.
    assert call.kwargs["subject"]["url"] == "<REDACTED_DLP_FAILURE>"
    # Host attribution survives via ``parsed.hostname`` (no userinfo,
    # no port, no query) so operators can still pivot to the
    # originating endpoint.
    assert call.kwargs["subject"]["domain"] == "example.com"


@pytest.mark.asyncio
async def test_dlp_scan_exception_redacts_userinfo_and_query_in_audit() -> None:
    """CR-146 major: a DLP outage MUST NOT let the raw URL flow into
    audit storage. The userinfo (``user:password@``) and query string
    (``?token=...``) are the attack-class fields — both must be absent
    from the audit row's ``subject.url`` field. The ``domain`` field
    is sourced from ``parsed.hostname`` so userinfo is stripped from
    the host-attribution path too.
    """
    audit = _build_audit()

    class _DlpExplodedError(RuntimeError):
        pass

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=_DlpExplodedError("broker offline"))

    raw_url = "https://alice:hunter2@example.com/api?token=BEARER_SECRET"
    with pytest.raises(_DlpExplodedError):
        await dispatch_web_fetch(
            url=raw_url,
            headers={},
            user_id="user-1",
            correlation_id="corr-cr146-dlp-redact",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=dlp,
            audit=audit,
            transport=_build_transport_returning_handle(),
        )

    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "dlp_scan_error"
    subject = call.kwargs["subject"]
    # ``url`` field carries the redacted sentinel.
    assert subject["url"] == "<REDACTED_DLP_FAILURE>"
    # Defence-in-depth: explicit anti-leak assertions on the audit row
    # body. Even if a future refactor changes the sentinel string, the
    # secret components stay out.
    audit_row_repr = repr(subject)
    assert "BEARER_SECRET" not in audit_row_repr
    assert "hunter2" not in audit_row_repr
    assert "alice" not in audit_row_repr
    # Host attribution survives via ``parsed.hostname`` — no userinfo.
    assert subject["domain"] == "example.com"


@pytest.mark.asyncio
async def test_transport_exception_emits_audit_row_then_raises() -> None:
    """M7 / err-004: a transport-layer exception emits a
    ``result="transport_error"`` audit row BEFORE re-raising.

    Subprocess death / broken pipe / framing error is a transport-
    layer crash, not an in-band protocol violation; the closed-
    vocabulary ``transport_error`` tag is distinct from
    ``dispatch_shape_error``.
    """
    audit = _build_audit()

    class _TransportCrashedError(RuntimeError):
        pass

    transport = AsyncMock()
    transport.dispatch = AsyncMock(side_effect=_TransportCrashedError("broken pipe"))

    with pytest.raises(_TransportCrashedError):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-m7-transport",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "transport_error"
    assert call.kwargs["subject"]["dlp_scan_result"] == "transport_error"


@pytest.mark.asyncio
async def test_success_audit_write_failure_logs_loud_then_raises() -> None:
    """M7 / err-005: a success-path audit-write failure must surface
    loudly (structlog warning carrying the would-be subject) before
    re-raising.

    The dispatcher cannot synthesise a recoverable handle return when
    the audit row never reached the DB — the structlog event is the
    only forensic trail for the successful fetch.
    """
    audit = _build_audit()
    # The success path issues ONE append_schema call; make it raise.
    audit.append_schema = AsyncMock(side_effect=RuntimeError("audit DB down"))

    with pytest.raises(RuntimeError, match="audit DB down"):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-m7-success-write",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=_build_transport_returning_handle(),
        )
    # The append_schema was attempted once for the ok row.
    assert audit.append_schema.await_count == 1


@pytest.mark.asyncio
async def test_headers_scanned_per_value_for_secret_leakage() -> None:
    """M3 / arch-006: headers are scanned per-value and the redacted
    values cross the wire — the original ``headers`` dict does NOT.

    The pre-fix dispatcher scanned ``str(headers)`` (a side-effect for
    the audit row) and then passed the raw dict to ``transport.dispatch``.
    Header secrets leaked verbatim. This test pins the per-field redaction
    path.
    """
    audit = _build_audit()
    transport = _build_transport_returning_handle()

    # DLP that redacts anything starting with "Bearer ".
    def _redact(s: str) -> str:
        return "[REDACTED]" if s.startswith("Bearer ") else s

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=_redact)

    await dispatch_web_fetch(
        url="https://example.com/page",
        headers={"Authorization": "Bearer sk-abc123", "User-Agent": "alfred"},
        user_id="user-1",
        correlation_id="corr-m3",
        config=_build_config(),
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=dlp,
        audit=audit,
        transport=transport,
    )

    args, _kwargs = transport.dispatch.await_args
    sent_headers = args[1]["headers"]
    # The redacted value flows through; the secret was never on the wire.
    assert sent_headers["Authorization"] == "[REDACTED]"
    # Non-secret header passes through unchanged.
    assert sent_headers["User-Agent"] == "alfred"


@pytest.mark.asyncio
async def test_plugin_returned_message_routes_through_i18n() -> None:
    """C4 / i18n-002: the generic WebFetchError fallback wraps the
    plugin's message in the i18n catalogue. The plugin-supplied detail
    is the placeholder, NOT the carrier string.
    """
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchError",
            "message": "DNS resolution failed",
        }
    )
    with pytest.raises(WebFetchError) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-c4",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    msg = str(excinfo.value)
    # The catalogued carrier text appears; the plugin detail is embedded.
    assert "DNS resolution failed" in msg
    assert "plugin returned an error" in msg


# ---------------------------------------------------------------------------
# Commit 3 — H11 / H12: per-session AllowlistIntersection + once-only
# broadening cap.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_per_session_allowlist_is_built_once_and_reused() -> None:
    """H11 / perf-100: ``FetchDispatchConfig.allowlist`` is built ONCE in
    ``__post_init__`` and reused across every fetch in the session.

    The pre-fix dispatcher reconstructed
    :class:`AllowlistIntersection` on every dispatch (O(manifest *
    operator * session) work). This test pins the identity of the
    cached object across multiple dispatches — a future regression
    that re-builds per fetch fails the ``is`` check.
    """
    audit = _build_audit()
    config = _build_config()
    cached_allowlist = config.allowlist
    transport_1 = _build_transport_returning_handle()
    transport_2 = _build_transport_returning_handle()

    await dispatch_web_fetch(
        url="https://example.com/page-1",
        headers={},
        user_id="user-1",
        correlation_id="corr-h11-1",
        config=config,
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=transport_1,
    )
    await dispatch_web_fetch(
        url="https://example.com/page-2",
        headers={},
        user_id="user-1",
        correlation_id="corr-h11-2",
        config=config,
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=transport_2,
    )
    # The allowlist object the config exposes is bit-for-bit identical
    # across dispatches — proving the per-fetch reconstruction is gone.
    assert config.allowlist is cached_allowlist


@pytest.mark.asyncio
async def test_broadening_cap_event_emitted_at_most_once_per_session() -> None:
    """H12 / perf-101: the broadening-cap audit row is a manifest-load-
    time event; it MUST NOT re-emit on every fetch.

    Two dispatches against the same config must produce exactly ONE
    broadening_capped row (not two). Subsequent dispatches see the
    ``_broadening_cap_emitted`` latch and skip the emit loop.
    """
    audit = _build_audit()
    manifest = (
        AllowlistEntry(domain="example.com"),
        AllowlistEntry(domain="evil.com"),  # capped — absent from operator
    )
    operator = (AllowlistEntry(domain="example.com"),)
    session = (AllowlistEntry(domain="example.com"),)
    config = _build_config(manifest=manifest, operator=operator, session=session)

    await dispatch_web_fetch(
        url="https://example.com/page-1",
        headers={},
        user_id="user-1",
        correlation_id="corr-h12-1",
        config=config,
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=_build_transport_returning_handle(),
    )
    await dispatch_web_fetch(
        url="https://example.com/page-2",
        headers={},
        user_id="user-1",
        correlation_id="corr-h12-2",
        config=config,
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=_build_transport_returning_handle(),
    )

    # 1 broadening-cap row + 2 success rows = 3 total. Without the latch
    # we'd see 2 broadening-cap rows + 2 success rows = 4.
    broadening_calls = [
        c
        for c in audit.append_schema.await_args_list
        if c.kwargs.get("event") == "web.allowlist.manifest_broadening_capped"
    ]
    assert len(broadening_calls) == 1, (
        f"Expected exactly ONE broadening_capped row across two dispatches; "
        f"got {len(broadening_calls)}. Cap-event emission is supposed to be "
        f"manifest-load-time, not per-fetch (H12 / perf-101)."
    )


@pytest.mark.asyncio
async def test_broadening_cap_latches_even_when_manifest_had_no_capped_entries() -> None:
    """Defence-in-depth: the ``_broadening_cap_emitted`` cell is latched
    after the loop even when there were no events to emit.

    A future refactor of ``broadening_cap_events()`` that made it non-
    idempotent would otherwise re-trigger the cap-check loop on every
    dispatch. The latch is the structural defence.
    """
    audit = _build_audit()
    config = _build_config()  # default: no capped entries (manifest ⊆ operator)
    assert config._broadening_cap_emitted == []  # initial state

    await dispatch_web_fetch(
        url="https://example.com/page",
        headers={},
        user_id="user-1",
        correlation_id="corr-h12-latch",
        config=config,
        rate_limiter=_build_rate_limiter(),
        outbound_dlp=_build_dlp(),
        audit=audit,
        transport=_build_transport_returning_handle(),
    )
    # Latched after the first dispatch even though the loop emitted
    # zero broadening-cap rows.
    assert config._broadening_cap_emitted == [True]


@pytest.mark.asyncio
async def test_unexpected_dispatch_shape_message_routes_through_i18n() -> None:
    """C3 / i18n-001: the unexpected-dispatch-shape WebFetchError text
    routes through the catalogue. ``{shape}`` carries the Python type
    name; the carrier text is catalogued.
    """
    audit = _build_audit()

    class _BogusResult:
        pass

    transport = AsyncMock()
    transport.dispatch = AsyncMock(return_value=_BogusResult())

    with pytest.raises(WebFetchError) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-c3",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    msg = str(excinfo.value)
    assert "_BogusResult" in msg
    # Catalogued operator-facing text is present (pinned against pybabel
    # fuzzy-copy drift).
    assert "unexpected dispatch shape" in msg


# ---------------------------------------------------------------------------
# sec-pr-s3-5-003 / H3 — host-IP allowlist guard against DNS-rebinding /
# cloud-metadata SSRF. The dispatcher refuses URLs whose hostname resolves
# to RFC1918 / loopback / link-local / multicast / reserved addresses
# BEFORE the transport dispatch even though the URL passed the three-way
# allowlist. The audit row uses the closed-vocabulary
# ``internal_ip_refused`` tag so audit consumers can pivot on the attack.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_internal_ip_refused_emits_audit_row_then_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A URL whose hostname resolves to an internal IP is refused.

    The DNS-rebinding case: ``example.com`` is in the three-way
    allowlist (matches on netloc), but the resolver returns
    ``10.0.0.1``. The IP guard refuses BEFORE the transport call,
    emits a typed audit row with ``result="internal_ip_refused"``
    so the forensic trail carries the attack class, and re-raises
    :class:`WebFetchInternalIPRefused`.
    """
    import socket

    def _fake(host: str, port: int | None, *args: Any, **kwargs: Any) -> Any:
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake)
    audit = _build_audit()
    transport = _build_transport_returning_handle()

    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-ssrf",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.resolved_ip == "10.0.0.1"
    assert excinfo.value.reason == "rfc1918"
    # Parent-side guard refused BEFORE the transport was touched.
    assert transport.dispatch.await_count == 0
    # One audit row: the internal-IP refusal.
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "internal_ip_refused"
    assert call.kwargs["subject"]["dlp_scan_result"] == "internal_ip_refused"


@pytest.mark.asyncio
async def test_internal_ip_refused_for_aws_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """169.254.169.254 (AWS / Azure metadata) is refused with reason=link_local."""
    import socket

    def _fake(host: str, port: int | None, *args: Any, **kwargs: Any) -> Any:
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake)
    audit = _build_audit()

    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-ssrf-aws",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=_build_transport_returning_handle(),
        )
    assert excinfo.value.reason == "link_local"


@pytest.mark.asyncio
async def test_control_result_internal_ip_refused_maps_to_typed_exception() -> None:
    """A ControlResult with ``type=WebFetchInternalIPRefused`` raises
    :class:`WebFetchInternalIPRefused` preserving the refusal class.

    The subprocess-side IP guard is defence-in-depth — when its
    resolution catches an internal IP that the parent's resolution
    missed (DNS rebinding race), the structured error envelope must
    surface as the right typed exception on the orchestrator side so
    the audit row carries the closed ``internal_ip_refused`` tag and
    the host-side error-mapping arm preserves the attack-class
    ``reason`` for forensic pivoting.
    """
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchInternalIPRefused",
            "message": "https://example.com/ resolved to internal address 10.0.0.1",
            "resolved_ip": "10.0.0.1",
            "reason": "rfc1918",
            "dlp_scan_result": "internal_ip_refused",
        }
    )
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-ssrf-cr",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.resolved_ip == "10.0.0.1"
    assert excinfo.value.reason == "rfc1918"
    # The audit row records the internal-IP refusal class.
    assert audit.append_schema.await_count == 1
    assert audit.append_schema.await_args.kwargs["result"] == "internal_ip_refused"


@pytest.mark.asyncio
async def test_control_result_internal_ip_refused_with_missing_fields_defaults() -> None:
    """Defence-in-depth: a malformed plugin payload (missing
    ``resolved_ip`` / ``reason``) defaults to empty / ``reserved``
    rather than tripping a TypeError."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchInternalIPRefused",
            "message": "refused",
        }
    )
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-ssrf-cr-defensive",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.resolved_ip == ""
    assert excinfo.value.reason == "reserved"


@pytest.mark.asyncio
async def test_control_result_internal_ip_refused_with_non_string_fields_defaults() -> None:
    """Non-string ``resolved_ip`` / ``reason`` default rather than passing
    through. Keeps the typed exception attributes well-typed at the
    boundary."""
    audit = _build_audit()
    transport = _build_transport_returning_control(
        {
            "type": "WebFetchInternalIPRefused",
            "message": "refused",
            "resolved_ip": 12345,  # not a string
            "reason": ["not", "a", "string"],
        }
    )
    with pytest.raises(WebFetchInternalIPRefused) as excinfo:
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={},
            user_id="user-1",
            correlation_id="corr-ssrf-cr-types",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
        )
    assert excinfo.value.resolved_ip == ""
    assert excinfo.value.reason == "reserved"
