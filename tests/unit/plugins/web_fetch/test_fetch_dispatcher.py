"""Unit tests for the re-homed orchestrator-side ``dispatch_web_fetch``.

G7-2.5 Task 6 (#333): the dispatcher no longer drives a plugin subprocess via
``transport.dispatch`` — it runs core-side gatekeeping (URL/header DLP, the
three-way allowlist, the rate-limiter) and then fires through the gateway
egress relay via :class:`~alfred.egress.egress_response_extract.EgressResponseExtractor`,
which returns a T2 :class:`~alfred.egress.egress_response_extract.EgressExtractOutcome`
(``Extracted | TypedRefusal`` — the orchestrator never sees raw T3 bytes).

Trust-boundary code requires 100% line + branch coverage (CLAUDE.md hard
rule). Every branch in
:func:`alfred.plugins.web_fetch.fetch_dispatcher.dispatch_web_fetch` is
exercised here against ``AsyncMock`` fakes for the collaborators (extractor,
dlp, audit, rate_limiter). The branches covered are:

  * Happy ``Extracted`` outcome → returned + ``result="ok"`` / T2 success row.
  * Soft ``TypedRefusal`` outcome (MIME/size) → returned + ``result="refused"``
    row carrying the payload-blind ``policy_refusal_token``.
  * URL-secret → ``result="refused"`` / ``url_secret_refused`` row + the
    extractor is NEVER called (no redacted URL crosses the wire).
  * Inbound-canary trip → exactly ONE ``result="quarantined"`` row written
    BEFORE the ``InboundCanaryTripped`` re-raise.
  * Domain not allowed / rate-limited → typed audit row + re-raise.
  * DLP-scan exception → ``dlp_scan_error`` row + ``<REDACTED_DLP_FAILURE>``
    + re-raise.
  * Action-deadline expiry → ``TimeoutError`` surfaced.
  * Broadening-cap → ``manifest_broadening_capped`` row, at most once / session.
  * Status-code clamp (plausible HTTP code 100-599 else None).
  * Real URL on the wire + per-value header redaction.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from alfred.egress.egress_id import TurnEgressContext
from alfred.egress.egress_response_extract import (
    EgressExtractOutcome,
    EgressResponseExtractor,
)
from alfred.egress.response_inspection import InboundCanaryTripped
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.constants import _DEFAULT_ACTION_DEADLINE_SECONDS
from alfred.plugins.web_fetch.errors import (
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchRateLimited,
)
from alfred.plugins.web_fetch.fetch_dispatcher import (
    FetchDispatchConfig,
    dispatch_web_fetch,
)
from alfred.security.quarantine import (
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    TypedRefusal,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

_CTX = TurnEgressContext(adapter_id="ada-1", inbound_id="in-1", session_id="sess-1")


class _TestSchema(ExtractionSchema):
    """Minimal extraction schema the dispatcher threads to the extractor."""

    payload: str


def _build_config(
    *,
    manifest: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
    operator: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
    session: tuple[AllowlistEntry, ...] = (AllowlistEntry(domain="example.com"),),
) -> FetchDispatchConfig:
    """Build a :class:`FetchDispatchConfig` with the common single-domain shape.

    The dead ``redis_url`` / ``skip_tls_verify`` fields are gone (the subprocess
    and the parent-side TlsPolicy they fed are gateway-side now) — fixtures pass
    only the allowlist triple + ``manifest_commit_hash``.
    """
    return FetchDispatchConfig(
        manifest_allowed_entries=manifest,
        operator_allowed_entries=operator,
        session_allowed_entries=session,
        manifest_commit_hash="abc123",
    )


def _build_dlp() -> Any:
    """An :class:`OutboundDlp`-shaped fake whose ``scan`` is the identity."""
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda s: s)
    return dlp


def _build_audit() -> AsyncMock:
    """An :class:`AuditWriter`-shaped async fake."""
    audit = AsyncMock()
    audit.append_schema = AsyncMock(return_value=None)
    return audit


def _build_rate_limiter(*, refused: str | None = None) -> AsyncMock:
    """A :class:`RateLimiter`-shaped fake; ``refused`` raises that bucket."""
    rate_limiter = AsyncMock()
    if refused is None:
        rate_limiter.check_and_increment = AsyncMock(return_value=None)
    else:
        rate_limiter.check_and_increment = AsyncMock(side_effect=WebFetchRateLimited(refused))
    return rate_limiter


def _make_extracted_outcome(*, status: int | None = 200) -> EgressExtractOutcome:
    """A T2 ``Extracted`` outcome (the happy success shape)."""
    return EgressExtractOutcome(
        result=Extracted(
            data=T3DerivedData({"payload": "structured"}),
            extraction_mode="native_constrained",
        ),
        deduplicated=False,
        language=None,
        status=status,
    )


def _make_soft_refusal_outcome(
    *, dlp_tag: str = "mime_type_not_allowed", status: int | None = 415
) -> EgressExtractOutcome:
    """A T2 soft ``TypedRefusal`` outcome from the pre-extract MIME/size seam."""
    return EgressExtractOutcome(
        result=TypedRefusal(reason="cannot_extract"),
        deduplicated=False,
        language=None,
        status=status,
        policy_refusal_token=dlp_tag,
    )


def _build_extractor(
    *,
    outcome: EgressExtractOutcome | None = None,
    raises: BaseException | None = None,
) -> AsyncMock:
    """A fake :class:`EgressResponseExtractor` whose ``handle`` is scripted."""
    ext = AsyncMock(spec=EgressResponseExtractor)
    if raises is not None:
        ext.handle = AsyncMock(side_effect=raises)
    else:
        ext.handle = AsyncMock(return_value=outcome)
    return ext


async def _dispatch(**overrides: Any) -> EgressExtractOutcome:
    """Call ``dispatch_web_fetch`` with sensible defaults, overridable per-test."""
    kwargs: dict[str, Any] = {
        "url": "https://example.com/page",
        "headers": {"User-Agent": "alfred"},
        "user_id": "user-1",
        "correlation_id": "corr-1",
        "egress_ctx": _CTX,
        "call_index": 0,
        "schema": _TestSchema,
        "config": _build_config(),
        "rate_limiter": _build_rate_limiter(),
        "outbound_dlp": _build_dlp(),
        "audit": _build_audit(),
        "extractor": _build_extractor(outcome=_make_extracted_outcome()),
    }
    kwargs.update(overrides)
    return await dispatch_web_fetch(**kwargs)


# ---------------------------------------------------------------------------
# Happy path — Extracted → success row (status + T2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_extracted_returns_outcome_and_success_row() -> None:
    """A fresh ``Extracted`` outcome is returned and a ``result="ok"`` row is
    written with the upstream status and ``trust_tier_of_result="T2"``."""
    audit = _build_audit()
    outcome = _make_extracted_outcome(status=200)
    extractor = _build_extractor(outcome=outcome)

    returned = await _dispatch(audit=audit, extractor=extractor)

    assert returned is outcome
    assert isinstance(returned.result, Extracted)
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["event"] == "tool.web.fetch"
    assert call.kwargs["result"] == "ok"
    subject = call.kwargs["subject"]
    assert subject["dlp_scan_result"] == "clean"
    assert subject["trust_tier_of_result"] == "T2"
    assert subject["status_code"] == 200
    assert subject["domain"] == "example.com"
    assert subject["content_handle_id"] is None
    assert subject["canary_tripped"] is False
    assert subject["rate_limit_bucket"] is None
    assert subject["triggering_user_id"] == "user-1"


@pytest.mark.asyncio
async def test_extractor_called_with_threaded_ctx_call_index_schema() -> None:
    """The egress context, call_index and schema are threaded verbatim to the
    extractor; ``language`` is ``None`` (C11b residual — TODO #339)."""
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    await _dispatch(extractor=extractor, call_index=7)

    handle_kwargs = extractor.handle.await_args.kwargs
    assert handle_kwargs["ctx"] is _CTX
    assert handle_kwargs["call_index"] == 7
    assert handle_kwargs["schema"] is _TestSchema
    assert handle_kwargs["language"] is None


@pytest.mark.asyncio
async def test_real_url_sent_on_wire_with_redacted_headers() -> None:
    """The REAL url crosses the wire (the gateway must fetch it); header VALUES
    are DLP-redacted per-value before the relay sees them."""
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    def _redact(s: str) -> str:
        return "[REDACTED]" if s.startswith("Bearer ") else s

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=_redact)

    await _dispatch(
        extractor=extractor,
        outbound_dlp=dlp,
        url="https://example.com/page",
        headers={"Authorization": "Bearer sk-abc123", "User-Agent": "alfred"},
    )

    raw_request = extractor.handle.await_args.kwargs["raw_request"]
    assert raw_request.url == "https://example.com/page"
    assert raw_request.method == "GET"
    assert raw_request.idempotent is True
    assert raw_request.headers["Authorization"] == "[REDACTED]"
    assert raw_request.headers["User-Agent"] == "alfred"


@pytest.mark.asyncio
async def test_success_row_status_code_clamped_to_none_when_implausible() -> None:
    """An absent/implausible upstream status is recorded as ``None`` (a
    deduplicated replay carries ``status=None``)."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome(status=None))

    await _dispatch(audit=audit, extractor=extractor)

    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "ok"
    assert call.kwargs["subject"]["status_code"] is None


@pytest.mark.asyncio
async def test_success_row_status_code_clamped_for_out_of_range() -> None:
    """An out-of-range status (e.g. 999) is clamped to ``None`` rather than
    corrupting the audit graph."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome(status=999))

    await _dispatch(audit=audit, extractor=extractor)

    assert audit.append_schema.await_args.kwargs["subject"]["status_code"] is None


# ---------------------------------------------------------------------------
# Soft TypedRefusal outcome (MIME/size) → result="refused"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_soft_typed_refusal_outcome_audits_refused() -> None:
    """A soft ``TypedRefusal`` outcome is RETURNED (not raised) and audited with
    ``result="refused"`` + the payload-blind ``policy_refusal_token`` — never
    the raw Content-Type."""
    audit = _build_audit()
    outcome = _make_soft_refusal_outcome(dlp_tag="mime_type_not_allowed", status=415)
    extractor = _build_extractor(outcome=outcome)

    returned = await _dispatch(audit=audit, extractor=extractor)

    assert returned is outcome
    assert isinstance(returned.result, TypedRefusal)
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "refused"
    subject = call.kwargs["subject"]
    assert subject["dlp_scan_result"] == "mime_type_not_allowed"
    assert subject["trust_tier_of_result"] == "T2"
    assert subject["status_code"] == 415


@pytest.mark.asyncio
async def test_soft_size_refusal_token_carried() -> None:
    """The size-cap seam token rides through verbatim."""
    audit = _build_audit()
    extractor = _build_extractor(
        outcome=_make_soft_refusal_outcome(dlp_tag="size_limit_exceeded", status=200)
    )

    await _dispatch(audit=audit, extractor=extractor)

    assert audit.append_schema.await_args.kwargs["subject"]["dlp_scan_result"] == (
        "size_limit_exceeded"
    )


# ---------------------------------------------------------------------------
# URL-secret refusal — extractor never called
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_url_secret_refused_audits_and_skips_extractor() -> None:
    """A secret in the URL (``scan(url) != url``) refuses BEFORE the wire — the
    extractor is never called and a ``url_secret_refused`` row is written."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    dlp = MagicMock()
    # The URL scan redacts (returns a different string) -> a secret is present.
    dlp.scan = MagicMock(
        side_effect=lambda s: "https://example.com/<REDACTED>" if s.startswith("http") else s
    )

    with pytest.raises(WebFetchError):
        await _dispatch(audit=audit, extractor=extractor, outbound_dlp=dlp)

    extractor.handle.assert_not_awaited()
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "refused"
    assert call.kwargs["subject"]["dlp_scan_result"] == "url_secret_refused"


@pytest.mark.asyncio
async def test_url_secret_refused_message_routes_through_i18n() -> None:
    """The url-secret ``WebFetchError`` surface is catalogued (i18n hard rule)."""
    dlp = MagicMock()
    dlp.scan = MagicMock(
        side_effect=lambda s: "https://example.com/<REDACTED>" if s.startswith("http") else s
    )

    with pytest.raises(WebFetchError) as excinfo:
        await _dispatch(outbound_dlp=dlp)

    # The catalogued operator-facing text is present (pinned against drift).
    assert "secret" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Inbound-canary trip — exactly ONE quarantined row BEFORE the re-raise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_canary_trip_audits_quarantined_once_before_reraise() -> None:
    """A canary trip (the extractor raises ``InboundCanaryTripped``) writes
    EXACTLY ONE loud ``result="quarantined"`` row BEFORE the re-raise."""
    audit = _build_audit()
    tripped = InboundCanaryTripped(destination="example.com", egress_id="deadbeef")
    extractor = _build_extractor(raises=tripped)

    with pytest.raises(InboundCanaryTripped):
        await _dispatch(audit=audit, extractor=extractor)

    # The row was awaited (and thus written) before the raise propagated.
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "quarantined"
    subject = call.kwargs["subject"]
    assert subject["dlp_scan_result"] == "inbound_canary_tripped"
    assert subject["canary_tripped"] is True
    assert subject["status_code"] is None
    assert subject["trust_tier_of_result"] == "T3"


# ---------------------------------------------------------------------------
# Domain not allowed / rate limited — typed audit row + re-raise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_domain_not_allowed_audits_then_raises() -> None:
    """A URL outside the effective allowlist emits ``domain_not_allowed`` and
    re-raises; the extractor is never called."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    with pytest.raises(WebFetchDomainNotAllowed):
        await _dispatch(audit=audit, extractor=extractor, url="https://evil.com/page")

    extractor.handle.assert_not_awaited()
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "domain_not_allowed"
    assert call.kwargs["subject"]["dlp_scan_result"] == "domain_not_allowed"


@pytest.mark.asyncio
async def test_rate_limited_audits_with_bucket_then_raises() -> None:
    """A rate-limit refusal records the bucket and re-raises."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    with pytest.raises(WebFetchRateLimited) as excinfo:
        await _dispatch(
            audit=audit,
            extractor=extractor,
            rate_limiter=_build_rate_limiter(refused="per_domain"),
        )

    extractor.handle.assert_not_awaited()
    assert excinfo.value.bucket == "per_domain"
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "rate_limited"
    assert call.kwargs["subject"]["rate_limit_bucket"] == "per_domain"


# ---------------------------------------------------------------------------
# DLP-scan exception — dlp_scan_error + redacted URL + re-raise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dlp_scan_exception_audits_then_raises() -> None:
    """A DLP-scan exception emits a ``dlp_scan_error`` row carrying the redacted
    URL sentinel BEFORE re-raising (CLAUDE.md hard rule #7)."""
    audit = _build_audit()

    class _DlpExplodedError(RuntimeError):
        pass

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=_DlpExplodedError("broker offline"))

    with pytest.raises(_DlpExplodedError):
        await _dispatch(audit=audit, outbound_dlp=dlp)

    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "dlp_scan_error"
    assert call.kwargs["subject"]["dlp_scan_result"] == "dlp_scan_error"
    assert call.kwargs["subject"]["url"] == "<REDACTED_DLP_FAILURE>"
    assert call.kwargs["subject"]["domain"] == "example.com"


@pytest.mark.asyncio
async def test_dlp_scan_exception_redacts_userinfo_and_query_in_audit() -> None:
    """A DLP outage must not leak a raw URL (userinfo / query secrets) into the
    audit row — the sentinel + hostname-only attribution survive."""
    audit = _build_audit()

    class _DlpExplodedError(RuntimeError):
        pass

    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=_DlpExplodedError("broker offline"))

    with pytest.raises(_DlpExplodedError):
        await _dispatch(
            audit=audit,
            outbound_dlp=dlp,
            url="https://alice:hunter2@example.com/api?token=BEARER_SECRET",
        )

    subject = audit.append_schema.await_args.kwargs["subject"]
    assert subject["url"] == "<REDACTED_DLP_FAILURE>"
    audit_row_repr = repr(subject)
    assert "BEARER_SECRET" not in audit_row_repr
    assert "hunter2" not in audit_row_repr
    assert "alice" not in audit_row_repr
    assert subject["domain"] == "example.com"


# ---------------------------------------------------------------------------
# Action-deadline expiry — TimeoutError surfaced
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_action_deadline_expiry_surfaces_timeout() -> None:
    """An extractor that overruns the action-deadline surfaces ``TimeoutError``
    (the orchestrator's supervisor.action_timeout family audits it)."""

    async def _slow_handle(**_kwargs: Any) -> EgressExtractOutcome:
        await asyncio.sleep(10)
        raise AssertionError("unreachable")  # pragma: no cover

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _slow_handle

    with pytest.raises(TimeoutError):
        await _dispatch(extractor=extractor, action_deadline_seconds=0.01)


@pytest.mark.asyncio
async def test_default_action_deadline_constant_is_used() -> None:
    """The default action-deadline comes from ``constants._DEFAULT_ACTION_DEADLINE_SECONDS``."""
    # A no-op fast extractor completes well within the default deadline.
    outcome = await _dispatch()
    assert isinstance(outcome.result, Extracted)
    # Sanity: the relocated constant is a positive number.
    assert _DEFAULT_ACTION_DEADLINE_SECONDS > 0


# ---------------------------------------------------------------------------
# Broadening cap — capped row, at most once per session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadening_cap_emits_capped_row_then_succeeds() -> None:
    """A manifest that widens past the operator set emits a
    ``manifest_broadening_capped`` row before the success row."""
    audit = _build_audit()
    manifest = (
        AllowlistEntry(domain="example.com"),
        AllowlistEntry(domain="evil.com"),  # capped — not in operator set
    )
    operator = (AllowlistEntry(domain="example.com"),)
    session = (AllowlistEntry(domain="example.com"),)

    await _dispatch(
        audit=audit,
        config=_build_config(manifest=manifest, operator=operator, session=session),
    )

    assert audit.append_schema.await_count == 2
    first_call = audit.append_schema.await_args_list[0]
    assert first_call.kwargs["event"] == "web.allowlist.manifest_broadening_capped"
    assert first_call.kwargs["result"] == "capped"
    capped = first_call.kwargs["subject"]["capped_domains"]
    assert any(entry["domain"] == "evil.com" for entry in capped)


@pytest.mark.asyncio
async def test_broadening_cap_emitted_at_most_once_per_session() -> None:
    """Two dispatches against the same config produce exactly ONE capped row."""
    audit = _build_audit()
    manifest = (
        AllowlistEntry(domain="example.com"),
        AllowlistEntry(domain="evil.com"),
    )
    operator = (AllowlistEntry(domain="example.com"),)
    session = (AllowlistEntry(domain="example.com"),)
    config = _build_config(manifest=manifest, operator=operator, session=session)

    await _dispatch(audit=audit, config=config)
    await _dispatch(audit=audit, config=config)

    broadening_calls = [
        c
        for c in audit.append_schema.await_args_list
        if c.kwargs.get("event") == "web.allowlist.manifest_broadening_capped"
    ]
    assert len(broadening_calls) == 1


@pytest.mark.asyncio
async def test_broadening_cap_latches_even_with_no_capped_entries() -> None:
    """The latch flips after the first dispatch even when no cap event fired."""
    config = _build_config()  # default: manifest ⊆ operator, no cap
    assert config._broadening_cap_emitted == []

    await _dispatch(config=config)

    assert config._broadening_cap_emitted == [True]


@pytest.mark.asyncio
async def test_per_session_allowlist_is_built_once_and_reused() -> None:
    """``FetchDispatchConfig.allowlist`` is built once and reused across fetches."""
    config = _build_config()
    cached = config.allowlist

    await _dispatch(config=config, url="https://example.com/page-1")
    await _dispatch(config=config, url="https://example.com/page-2")

    assert config.allowlist is cached


# ---------------------------------------------------------------------------
# FetchDispatchConfig field cleanup
# ---------------------------------------------------------------------------


def test_config_drops_dead_redis_url_and_skip_tls_verify_fields() -> None:
    """The dead ``redis_url`` / ``skip_tls_verify`` fields are gone — the model
    constructs from the allowlist triple + ``manifest_commit_hash`` alone."""
    config = _build_config()
    field_names = set(type(config).model_fields) if hasattr(type(config), "model_fields") else set()
    # dataclass — inspect via __dataclass_fields__.
    field_names = set(getattr(config, "__dataclass_fields__", {}))
    assert "redis_url" not in field_names
    assert "skip_tls_verify" not in field_names
