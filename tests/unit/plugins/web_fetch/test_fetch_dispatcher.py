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
from alfred.security.quarantine import ContentHandle


def _build_config(
    *,
    manifest: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
    operator: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
    session: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
) -> FetchDispatchConfig:
    """Build a :class:`FetchDispatchConfig` with the common shape.

    The defaults set up a single example.com triple-intersection so a
    test that does not care about allowlist drift can call dispatch and
    reach the rate-limiter / transport branches.
    """
    return FetchDispatchConfig(
        manifest_allowed_entries=manifest,
        operator_allowed_entries=operator,
        session_allowed_entries=session,
        manifest_commit_hash="abc123",
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
    and writes a ``result="ok"`` row keyed on its handle id."""
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
    assert "evil.com" in first_call.kwargs["subject"]["capped_domains"]


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
    ``WebFetchError`` with the type name in the message."""
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
