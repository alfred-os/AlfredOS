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

  * Happy ``Extracted`` outcome → returned + ``result="success"`` / T2 success row.
  * Soft ``TypedRefusal`` outcome (MIME/size) → returned + ``result="refused"``
    row carrying the payload-blind ``policy_refusal_token``.
  * URL-secret → ``result="refused"`` / ``url_secret_refused`` row + the
    extractor is NEVER called (no redacted URL crosses the wire).
  * Inbound-canary trip → exactly ONE ``result="quarantined"`` row written
    BEFORE the ``InboundCanaryTripped`` re-raise.
  * Domain not allowed / rate-limited → typed audit row + re-raise.
  * DLP-scan exception → ``dlp_scan_error`` row + ``<REDACTED_DLP_FAILURE>``
    + re-raise.
  * Action-deadline expiry → enriched ``WebFetchActionTimeout`` surfaced (not a
    bare ``TimeoutError``), carrying ``egress_id`` / ``in_doubt`` /
    ``ledger_state`` (#347 blocker 2). A correlated ledger-read failure still
    surfaces the exception, forcing ``in_doubt=True`` /
    ``ledger_state="read_unavailable"`` (PR4b-audit FIX-1).
  * Broadening-cap → ``manifest_broadening_capped`` row, at most once / session.
  * Status-code clamp (plausible HTTP code 100-599 else None).
  * Real URL on the wire + per-value header redaction.
  * Header raw-secret refusal (Step 1b, #339 PR4b-broker) → ``result="refused"``
    / ``header_secret_refused`` row + no reserve, no extractor call.
  * Broker ``{{secret:*}}`` substitution (Step 1c, #339 PR4b-broker): an
    off-allowlist / unprovisioned reference refuses (``secret_substitution_refused``,
    no reserve, no extractor call, no secret-name leak via ``__context__`` —
    FIX-8's ``from None``); an allowlisted + provisioned reference is
    substituted into the wire headers AFTER DLP and never appears in an audit
    subject.
"""

from __future__ import annotations

import asyncio
import traceback
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import structlog

from alfred.egress.egress_id import TurnEgressContext, compute_egress_id
from alfred.egress.egress_response_extract import (
    EgressExtractOutcome,
    EgressResponseExtractor,
)
from alfred.egress.response_inspection import InboundCanaryTripped
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.constants import (
    _DEFAULT_ACTION_DEADLINE_SECONDS,
    _DEFAULT_HANDLE_RESERVATION_TTL_SECONDS,
)
from alfred.plugins.web_fetch.errors import (
    WebFetchActionTimeout,
    WebFetchDomainNotAllowed,
    WebFetchError,
    WebFetchRateLimited,
)
from alfred.plugins.web_fetch.fetch_dispatcher import (
    FetchDispatchConfig,
    _safe_hostname,
    dispatch_web_fetch,
)
from alfred.security.quarantine import (
    Extracted,
    ExtractionSchema,
    T3DerivedData,
    TypedRefusal,
)
from alfred.security.secrets import SecretBroker

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


class _SpyHandleCap:
    """Fake :class:`~alfred.plugins.web_fetch.handle_cap.HandleCap` (#339 PR4a).

    Permissive by default (``raise_on_reserve=False``) so every existing
    dispatcher test — none of which cares about the per-user concurrency
    bound — keeps passing once ``handle_cap`` becomes a required kwarg.
    Records reserved/released handle ids in call order so the new tests can
    assert reserve-precedes-network and release-on-every-exit-path. Also
    captures every ``handle_ttl_seconds`` the dispatcher passed in
    (CR-cloud PR4a review: the TTL is now derived from
    ``action_deadline_seconds`` rather than a bare constant) — additive, so
    existing callers that never inspect ``ttls_seen`` are unaffected.
    """

    def __init__(self, *, raise_on_reserve: bool = False) -> None:
        self.reserved: list[str] = []
        self.released: list[str] = []
        self.ttls_seen: list[int] = []
        self._raise = raise_on_reserve

    async def try_reserve(self, *, user_id: str, handle_id: str, handle_ttl_seconds: int) -> None:
        self.ttls_seen.append(handle_ttl_seconds)
        if self._raise:
            raise WebFetchRateLimited("handle_cap")
        self.reserved.append(handle_id)

    async def release(
        self, *, user_id: str, handle_id: str, correlation_id: str | None = None
    ) -> None:
        self.released.append(handle_id)


async def _dispatch(**overrides: Any) -> EgressExtractOutcome:
    """Call ``dispatch_web_fetch`` with sensible defaults, overridable per-test.

    FIX-2 (PR4b-broker plan-review fold): the default ``broker`` is a REAL
    :class:`SecretBroker` (env-only, zero secrets provisioned) — NOT a
    passthrough fake. Enforcement (the confused-deputy allowlist check +
    ``UnknownSecretError`` on an unprovisioned name) lives INSIDE
    ``SecretBroker.substitute`` itself; a passthrough fake never raises, so
    ``test_off_allowlist_placeholder_refused_audits_and_skips_extractor``
    could not pass against one. A real broker with no placeholder in the
    header value is a no-op passthrough anyway (the ``{{secret:*}}`` regex
    simply doesn't match), so every pre-existing test above — none of which
    references a placeholder — is unaffected.
    """
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
        "handle_cap": _SpyHandleCap(),
        "broker": SecretBroker(env={}),
        "auth_secret_allowlist": frozenset(),
    }
    kwargs.update(overrides)
    return await dispatch_web_fetch(**kwargs)


# ---------------------------------------------------------------------------
# Happy path — Extracted → success row (status + T2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_extracted_returns_outcome_and_success_row() -> None:
    """A fresh ``Extracted`` outcome is returned and a ``result="success"`` row is
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
    assert call.kwargs["result"] == "success"
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
async def test_real_url_sent_on_wire_with_clean_headers() -> None:
    """The REAL url crosses the wire (the gateway must fetch it); CLEAN header
    values (no DLP redaction, no ``{{secret:*}}`` placeholder) pass through to
    the relay unchanged. A redacted (secret-bearing) header now REFUSES — see
    ``test_header_raw_secret_refused_audits_and_skips_extractor`` — so the old
    mixed clean+secret case this test used to cover is gone; this test pins
    the surviving multi-header no-redaction / no-substitution else-path
    (FIX-11 coverage)."""
    extractor = _build_extractor(outcome=_make_extracted_outcome())
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda s: s)  # nothing redacted

    await _dispatch(
        extractor=extractor,
        outbound_dlp=dlp,
        url="https://example.com/page",
        headers={"User-Agent": "alfred", "Accept": "text/html"},
    )

    raw_request = extractor.handle.await_args.kwargs["raw_request"]
    assert raw_request.url == "https://example.com/page"
    assert raw_request.method == "GET"
    assert raw_request.idempotent is True
    assert raw_request.headers["User-Agent"] == "alfred"
    assert raw_request.headers["Accept"] == "text/html"


@pytest.mark.asyncio
async def test_success_row_status_code_clamped_to_none_when_implausible() -> None:
    """An absent/implausible upstream status is recorded as ``None`` (a
    deduplicated replay carries ``status=None``)."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome(status=None))

    await _dispatch(audit=audit, extractor=extractor)

    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "success"
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
# Action-deadline expiry — enriched WebFetchActionTimeout surfaced (#347
# blocker 2 / PR4b-audit FIX-1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_action_deadline_expiry_surfaces_timeout() -> None:
    """An extractor that overruns the action-deadline surfaces the enriched
    ``WebFetchActionTimeout`` — NOT a bare ``TimeoutError`` — so the forensic
    egress_id/in_doubt/ledger_state fields are never lost (#347 blocker 2)."""

    async def _slow_handle(**_kwargs: Any) -> EgressExtractOutcome:
        await asyncio.sleep(10)
        raise AssertionError("unreachable")  # pragma: no cover

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _slow_handle
    extractor.ledger_state = AsyncMock(return_value=None)

    with pytest.raises(WebFetchActionTimeout):
        await _dispatch(extractor=extractor, action_deadline_seconds=0.01)


@pytest.mark.asyncio
async def test_action_deadline_timeout_in_doubt_true_when_committed_no_response() -> None:
    """FIX-1 happy path: a hung extractor whose ledger row is
    ``committed_no_response`` surfaces ``WebFetchActionTimeout(in_doubt=True)``
    with the egress_id/destination_host/ledger_state the forensic
    ``tool.dispatch`` row needs (#347 blocker 2). The hang is a real
    never-set ``asyncio.Event().wait()`` (not ``asyncio.sleep``) so the
    extractor is verifiably still in-flight when the action deadline fires —
    it can only unblock via the outer ``asyncio.timeout`` cancellation."""
    never_set = asyncio.Event()

    async def _hang(**_kwargs: Any) -> EgressExtractOutcome:
        await never_set.wait()
        raise AssertionError("unreachable")  # pragma: no cover

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _hang
    extractor.ledger_state = AsyncMock(return_value="committed_no_response")
    spy = _SpyHandleCap()

    with pytest.raises(WebFetchActionTimeout) as excinfo:
        await _dispatch(extractor=extractor, handle_cap=spy, action_deadline_seconds=0.05)

    exc = excinfo.value
    assert exc.in_doubt is True
    assert exc.ledger_state == "committed_no_response"
    assert exc.destination_host == "example.com"
    assert exc.egress_id == compute_egress_id(_CTX, call_index=0)
    extractor.ledger_state.assert_awaited_once_with(egress_id=exc.egress_id)
    # The finally still releases the handle_cap slot after the raise.
    assert spy.released == spy.reserved
    assert len(spy.released) == 1


@pytest.mark.asyncio
async def test_action_deadline_timeout_in_doubt_false_when_state_none() -> None:
    """A ledger row that never committed (``state is None`` — the side effect
    never fired) is the SAFE case: ``in_doubt`` is False, distinct from the
    ``committed_no_response`` in-doubt case above."""
    never_set = asyncio.Event()

    async def _hang(**_kwargs: Any) -> EgressExtractOutcome:
        await never_set.wait()
        raise AssertionError("unreachable")  # pragma: no cover

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _hang
    extractor.ledger_state = AsyncMock(return_value=None)

    with pytest.raises(WebFetchActionTimeout) as excinfo:
        await _dispatch(extractor=extractor, action_deadline_seconds=0.05)

    assert excinfo.value.in_doubt is False
    assert excinfo.value.ledger_state is None


@pytest.mark.asyncio
async def test_action_deadline_timeout_in_doubt_false_when_committed_with_response() -> None:
    """FIX J (test-engineer + CodeRabbit review, #339 PR4b-audit): a hung
    extractor whose ledger row is ``committed_with_response`` is the OTHER
    safe case — the side effect fired AND a response was already recorded
    before the deadline, so ``in_doubt`` must be False. Distinct from the
    ``committed_no_response`` in-doubt=True case above AND from the
    ``state is None`` sibling (never fired). Locks the
    ``in_doubt=state == "committed_no_response"`` classification branch in
    ``fetch_dispatcher.py`` — a mutation to the constant ``in_doubt=True``
    would make this test fail."""
    never_set = asyncio.Event()

    async def _hang(**_kwargs: Any) -> EgressExtractOutcome:
        await never_set.wait()
        raise AssertionError("unreachable")  # pragma: no cover

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _hang
    extractor.ledger_state = AsyncMock(return_value="committed_with_response")

    with pytest.raises(WebFetchActionTimeout) as excinfo:
        await _dispatch(extractor=extractor, action_deadline_seconds=0.05)

    assert excinfo.value.in_doubt is False
    assert excinfo.value.ledger_state == "committed_with_response"


@pytest.mark.asyncio
async def test_action_deadline_timeout_ledger_read_failure_forces_in_doubt() -> None:
    """FIX-1: the post-timeout ledger read is CORRELATED with the timeout (the
    same DB stress can blow both). A read failure must NEVER swallow the
    forensic timeout (HARD rule #7) — it forces the safe-direction
    ``in_doubt=True`` / ``ledger_state="read_unavailable"`` sentinel and logs
    loud."""
    never_set = asyncio.Event()

    async def _hang(**_kwargs: Any) -> EgressExtractOutcome:
        await never_set.wait()
        raise AssertionError("unreachable")  # pragma: no cover

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _hang
    extractor.ledger_state = AsyncMock(side_effect=RuntimeError("ledger db down"))

    with (
        structlog.testing.capture_logs() as caps,
        pytest.raises(WebFetchActionTimeout) as excinfo,
    ):
        await _dispatch(extractor=extractor, action_deadline_seconds=0.05)

    exc = excinfo.value
    assert exc.in_doubt is True
    assert exc.ledger_state == "read_unavailable"

    read_fail_logs = [c for c in caps if c.get("event") == "web_fetch.timeout.ledger_read_failed"]
    assert len(read_fail_logs) == 1
    assert read_fail_logs[0]["error_type"] == "RuntimeError"
    assert read_fail_logs[0]["correlation_id"] == "corr-1"


@pytest.mark.asyncio
async def test_action_deadline_timeout_ledger_read_genuinely_hangs_bounds_via_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FIX-1 coverage gap (PR4b-audit review): the sibling test above only
    proves the guard against a ``ledger_state()`` that RAISES. This test
    empirically proves the *bound itself* — ``asyncio.timeout(
    _LEDGER_READ_TIMEOUT_SECONDS)`` in the ``except TimeoutError`` arm — fires
    when ``ledger_state()`` genuinely HANGS rather than raising. Both
    ``extractor.handle`` and ``extractor.ledger_state`` are real ``async
    def``s awaiting a never-set ``asyncio.Event()``; the only way either
    unblocks is cancellation from an enclosing ``asyncio.timeout`` scope. The
    module constant is monkeypatched (at the ``fetch_dispatcher`` binding the
    function looks up by name at call time — the module does
    ``from ... import _LEDGER_READ_TIMEOUT_SECONDS``, so patching
    ``fetch_dispatcher._LEDGER_READ_TIMEOUT_SECONDS`` takes effect) to a tiny
    bound so the inner read-timeout fires fast and deterministically,
    converting to a real ``TimeoutError`` -> the same safe
    ``in_doubt=True`` / ``ledger_state="read_unavailable"`` outcome as the
    raise-case sibling."""
    monkeypatch.setattr(
        "alfred.plugins.web_fetch.fetch_dispatcher._LEDGER_READ_TIMEOUT_SECONDS", 0.05
    )

    handle_never_set = asyncio.Event()
    ledger_never_set = asyncio.Event()
    ledger_state_calls: list[str] = []

    async def _hang(**_kwargs: Any) -> EgressExtractOutcome:
        await handle_never_set.wait()
        raise AssertionError("unreachable")  # pragma: no cover

    async def _hanging_ledger_state(*, egress_id: str) -> str | None:
        ledger_state_calls.append(egress_id)
        await ledger_never_set.wait()
        raise AssertionError("unreachable")  # pragma: no cover

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _hang
    extractor.ledger_state = _hanging_ledger_state
    spy = _SpyHandleCap()

    with (
        structlog.testing.capture_logs() as caps,
        pytest.raises(WebFetchActionTimeout) as excinfo,
    ):
        await _dispatch(extractor=extractor, handle_cap=spy, action_deadline_seconds=0.05)

    exc = excinfo.value
    assert exc.in_doubt is True
    assert exc.ledger_state == "read_unavailable"
    assert len(ledger_state_calls) == 1
    assert ledger_state_calls[0] == exc.egress_id

    read_fail_logs = [c for c in caps if c.get("event") == "web_fetch.timeout.ledger_read_failed"]
    assert len(read_fail_logs) == 1
    assert read_fail_logs[0]["error_type"] == "TimeoutError"
    assert read_fail_logs[0]["correlation_id"] == "corr-1"

    # The finally still releases the handle_cap slot after the raise, exactly
    # as it does on the raise-case sibling above.
    assert spy.released == spy.reserved
    assert len(spy.released) == 1


@pytest.mark.asyncio
async def test_default_action_deadline_constant_is_used() -> None:
    """The default action-deadline IS ``constants._DEFAULT_ACTION_DEADLINE_SECONDS``.

    CR-10: pin the dispatcher's actual default value (not just "positive") so a
    future signature edit that hard-codes a different default fails loud.
    """
    import inspect

    # A no-op fast extractor completes well within the default deadline.
    outcome = await _dispatch()
    assert isinstance(outcome.result, Extracted)
    # The signature default equals the relocated constant, exactly.
    default = inspect.signature(dispatch_web_fetch).parameters["action_deadline_seconds"].default
    assert default == _DEFAULT_ACTION_DEADLINE_SECONDS
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
    # FetchDispatchConfig is a dataclass — inspect via __dataclass_fields__ (CR-12:
    # the earlier ``model_fields`` probe was dead — it was immediately overwritten).
    field_names = set(getattr(config, "__dataclass_fields__", {}))
    assert "redis_url" not in field_names
    assert "skip_tls_verify" not in field_names


# ---------------------------------------------------------------------------
# M3 / CR-5 — hostname-uniform audit + rate-limit domain (no userinfo/port leak)
# ---------------------------------------------------------------------------


def test_safe_hostname_strips_userinfo_port_and_is_valueerror_safe() -> None:
    """``_safe_hostname`` returns the bare host (no userinfo / port / path) and
    collapses an unparseable URL to ``""`` rather than raising."""
    assert _safe_hostname("https://alice:pw@example.com:8443/p?q=secret") == "example.com"
    assert _safe_hostname("https://example.com/page") == "example.com"
    # ValueError-safe: a malformed IPv6 URL makes urlsplit raise — collapse to "".
    assert _safe_hostname("http://[::1") == ""


@pytest.mark.asyncio
async def test_userinfo_url_audit_domain_is_host_only_on_domain_not_allowed() -> None:
    """A ``user:pass@host:port`` URL that fails the allowlist records a host-only
    ``domain`` in the ``domain_not_allowed`` row — userinfo + port never leak."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    with pytest.raises(WebFetchDomainNotAllowed):
        await _dispatch(
            audit=audit,
            extractor=extractor,
            url="https://alice:hunter2@example.com:8443/page",
        )

    extractor.handle.assert_not_awaited()
    subject = audit.append_schema.await_args.kwargs["subject"]
    # The audit + rate-limit ``domain`` field is host-only — userinfo + port never
    # leak into it. (The separate ``url`` field carries the DLP-scanned URL by
    # design; this test pins the host-only attribution field, not the whole row.)
    assert subject["domain"] == "example.com"
    assert "alice" not in subject["domain"]
    assert "hunter2" not in subject["domain"]
    assert "8443" not in subject["domain"]


@pytest.mark.asyncio
async def test_rate_limit_bucket_is_host_only() -> None:
    """The PRD §7.7 per-domain rate-limit bucket is keyed on the bare host, so a
    ``user@host`` variant cannot fragment (evade) the per-host limit."""
    rate_limiter = _build_rate_limiter()

    await _dispatch(
        rate_limiter=rate_limiter,
        url="https://example.com/page",
    )

    rate_limiter.check_and_increment.assert_awaited_once()
    assert rate_limiter.check_and_increment.await_args.kwargs["domain"] == "example.com"


# ---------------------------------------------------------------------------
# M2 / CR-cloud-6 — preserve the quarantined-LLM refusal reason in the audit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extractor_typed_refusal_reason_surfaced_in_audit() -> None:
    """A quarantined-LLM ``TypedRefusal(refused_by_safety)`` (no pre-extract policy
    token) surfaces its closed-vocab ``reason`` as ``dlp_scan_result`` — the
    SECURITY signal is not dropped from the audit pivot."""
    audit = _build_audit()
    # policy_refusal_token is None (the D1 seam did not fire) — the refusal is the
    # quarantined LLM's own decision, carried on outcome.result.reason.
    outcome = EgressExtractOutcome(
        result=TypedRefusal(reason="refused_by_safety"),
        deduplicated=False,
        language=None,
        status=200,
        policy_refusal_token=None,
    )
    extractor = _build_extractor(outcome=outcome)

    await _dispatch(audit=audit, extractor=extractor)

    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "refused"
    assert call.kwargs["subject"]["dlp_scan_result"] == "refused_by_safety"


# ---------------------------------------------------------------------------
# #339 PR4a — per-user HandleCap reserve/release re-threaded into dispatch
# (Step 3b reserve-before-network gate + try/finally release-on-every-exit)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reserve_before_network_and_release_on_success() -> None:
    """The per-user slot is reserved BEFORE the extractor fires — proven by the
    extractor's own assertion at fire time, not just by call ordering on the
    spy — and released on the plain success exit path."""
    spy = _SpyHandleCap()

    async def _handle(**_kwargs: Any) -> EgressExtractOutcome:
        assert len(spy.reserved) == 1
        return _make_extracted_outcome()

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _handle

    await _dispatch(extractor=extractor, handle_cap=spy)

    assert len(spy.reserved) == 1
    assert spy.released == spy.reserved


@pytest.mark.asyncio
async def test_reservation_ttl_derived_from_action_deadline() -> None:
    """CR-cloud (PR4a review) + perf-reviewer: the reservation TTL must
    outlive the per-fetch action deadline so a slow-but-live fetch's slot is
    never passively evicted mid-flight. Asserts both the derived branch (an
    operator-raised deadline of 200s doubles to 400s, exceeding the 120s
    floor) and the floor branch (the default 30s deadline still floors at
    the 120s backstop, matching the ``~120s`` runbook language)."""
    spy = _SpyHandleCap()
    await _dispatch(
        extractor=_build_extractor(outcome=_make_extracted_outcome()),
        handle_cap=spy,
        action_deadline_seconds=200,
    )
    assert spy.ttls_seen == [400]

    spy_default = _SpyHandleCap()
    await _dispatch(
        extractor=_build_extractor(outcome=_make_extracted_outcome()),
        handle_cap=spy_default,
    )
    assert spy_default.ttls_seen == [_DEFAULT_HANDLE_RESERVATION_TTL_SECONDS]
    assert spy_default.ttls_seen == [120]


@pytest.mark.asyncio
async def test_release_on_soft_refusal() -> None:
    """A soft ``TypedRefusal`` outcome (MIME/size) still releases the reserved
    slot — the ``finally`` covers the Step-5 soft-refusal branch, not only the
    ``Extracted`` success branch."""
    spy = _SpyHandleCap()
    extractor = _build_extractor(outcome=_make_soft_refusal_outcome())

    await _dispatch(extractor=extractor, handle_cap=spy)

    assert len(spy.released) == 1
    assert spy.released == spy.reserved


@pytest.mark.asyncio
async def test_release_on_canary_trip() -> None:
    """An ``InboundCanaryTripped`` re-raise still releases the reserved slot —
    the ``finally`` wraps the ``except InboundCanaryTripped`` re-raise too."""
    spy = _SpyHandleCap()
    tripped = InboundCanaryTripped(destination="example.com", egress_id="deadbeef")
    extractor = _build_extractor(raises=tripped)

    with pytest.raises(InboundCanaryTripped):
        await _dispatch(extractor=extractor, handle_cap=spy)

    assert len(spy.released) == 1
    assert spy.released == spy.reserved


@pytest.mark.asyncio
async def test_release_on_timeout() -> None:
    """An action-deadline expiry (``WebFetchActionTimeout``) still releases the
    reserved slot."""
    spy = _SpyHandleCap()

    async def _slow_handle(**_kwargs: Any) -> EgressExtractOutcome:
        await asyncio.sleep(10)
        raise AssertionError("unreachable")  # pragma: no cover

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _slow_handle
    extractor.ledger_state = AsyncMock(return_value=None)

    with pytest.raises(WebFetchActionTimeout):
        await _dispatch(extractor=extractor, handle_cap=spy, action_deadline_seconds=0.01)

    assert len(spy.released) == 1
    assert spy.released == spy.reserved


@pytest.mark.asyncio
async def test_release_on_generic_transport_error() -> None:
    """FIX-7a: a generic transport-shaped error propagating out of the
    extractor (not one of the two typed arms) still releases the reserved
    slot — the ``finally`` is unconditional, not per-exception-type."""
    spy = _SpyHandleCap()
    extractor = _build_extractor(raises=WebFetchError("boom"))

    with pytest.raises(WebFetchError):
        await _dispatch(extractor=extractor, handle_cap=spy)

    assert len(spy.released) == 1
    assert spy.released == spy.reserved


@pytest.mark.asyncio
async def test_handle_cap_exceeded_refuses_pre_network_with_audit() -> None:
    """A cap-exceeded reserve refuses BEFORE the network fire: the extractor is
    never awaited, and exactly one ``handle_cap_exceeded`` / ``handle_cap``
    audit row is written matching the ``WEB_FETCH_FIELDS`` Step-3 shape."""
    audit = _build_audit()
    spy = _SpyHandleCap(raise_on_reserve=True)
    fired: list[bool] = []

    async def _handle(**_kwargs: Any) -> EgressExtractOutcome:
        fired.append(True)
        raise AssertionError("extractor must not be awaited on cap-exceeded")

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _handle

    with pytest.raises(WebFetchRateLimited):
        await _dispatch(audit=audit, extractor=extractor, handle_cap=spy)

    assert fired == []
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "rate_limited"
    subject = call.kwargs["subject"]
    assert subject["dlp_scan_result"] == "handle_cap_exceeded"
    assert subject["rate_limit_bucket"] == "handle_cap"


@pytest.mark.asyncio
async def test_early_refusal_does_not_reserve() -> None:
    """FIX-7b: a refusal EARLIER than Step 3b (domain not allowed) never
    reserves — and therefore never needs a release — a per-user slot."""
    spy = _SpyHandleCap()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    with pytest.raises(WebFetchDomainNotAllowed):
        await _dispatch(extractor=extractor, handle_cap=spy, url="https://evil.com/page")

    extractor.handle.assert_not_awaited()
    assert spy.reserved == []
    assert spy.released == []


@pytest.mark.asyncio
async def test_release_fault_does_not_mask_exception() -> None:
    """FIX-8: a ``release()`` fault (a non-``RedisError`` bug — the real
    ``HandleCap.release`` already swallows ``RedisError`` itself) must never
    mask the in-flight security exception. The propagating exception is still
    ``InboundCanaryTripped``, not the release fault."""

    class _FaultyReleaseHandleCap:
        async def try_reserve(
            self, *, user_id: str, handle_id: str, handle_ttl_seconds: int
        ) -> None:
            return None

        async def release(
            self, *, user_id: str, handle_id: str, correlation_id: str | None = None
        ) -> None:
            raise RuntimeError("release exploded")

    tripped = InboundCanaryTripped(destination="example.com", egress_id="deadbeef")
    extractor = _build_extractor(raises=tripped)

    with structlog.testing.capture_logs() as caps, pytest.raises(InboundCanaryTripped):
        await _dispatch(extractor=extractor, handle_cap=_FaultyReleaseHandleCap())

    # Assert that the loud log fired with the required fields (Finding 1).
    release_logs = [c for c in caps if c.get("event") == "web_fetch.handle_cap.release_unexpected"]
    assert len(release_logs) == 1
    release_log = release_logs[0]
    assert "error_type" in release_log
    assert release_log["error_type"] == "RuntimeError"
    assert "correlation_id" in release_log
    assert release_log["correlation_id"] == "corr-1"


@pytest.mark.asyncio
async def test_reserve_transport_fault_propagates_no_release_no_audit() -> None:
    """FIX-9 totality (CR #4 + error-reviewer + security-engineer): a reserve
    TRANSPORT fault — a non-``WebFetchRateLimited`` exception out of
    ``handle_cap.try_reserve`` (e.g. a Redis connection blip), as distinct from
    the cap-exceeded ``WebFetchRateLimited`` arm covered by
    ``test_handle_cap_exceeded_refuses_pre_network_with_audit`` — PROPAGATES
    uncaught rather than being swallowed or mis-typed.

    The reserve call (Step 3b) sits BEFORE the Step-4/5 ``try/finally`` that
    guards the release — nothing was held yet when the fault fires, so:

    * ``release()`` is NEVER called (there is no reservation to release);
    * NO local ``tool.web.fetch`` audit row is written here — only the
      ``except WebFetchRateLimited`` arm audits at this layer; a transport
      fault is audited ONE LAYER UP by ``dispatch_tool``'s catch-all
      (``except Exception -> unexpected_error/fault``), so a second audit arm
      here would double-audit the same fault (module docstring FIX-9 note).
    """
    audit = _build_audit()

    class _FaultyReserveHandleCap:
        """A ``handle_cap``-shaped fake whose ``try_reserve`` raises a
        transport-shaped, NON-``WebFetchRateLimited`` exception — e.g. what a
        real Redis connection reset would surface, distinct from the
        deliberate cap-exceeded refusal ``_SpyHandleCap(raise_on_reserve=True)``
        models."""

        def __init__(self) -> None:
            self.released: list[str] = []

        async def try_reserve(
            self, *, user_id: str, handle_id: str, handle_ttl_seconds: int
        ) -> None:
            raise RuntimeError("redis connection reset")

        async def release(
            self, *, user_id: str, handle_id: str, correlation_id: str | None = None
        ) -> None:
            self.released.append(handle_id)  # must NEVER be called

    faulty = _FaultyReserveHandleCap()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    with pytest.raises(RuntimeError, match="redis connection reset"):
        await _dispatch(audit=audit, extractor=extractor, handle_cap=faulty)

    extractor.handle.assert_not_awaited()
    assert faulty.released == []
    assert audit.append_schema.await_count == 0


@pytest.mark.asyncio
async def test_cancelled_error_propagates_and_releases_slot() -> None:
    """Low / optional (error-reviewer): an ``asyncio.CancelledError`` raised
    inside the extractor's ``handle()`` propagates OUT of ``dispatch_web_fetch``
    uncaught, AND the reserved per-user slot is still released — the outer
    ``finally`` (Step 4/5) runs unconditionally, while the narrower
    ``except Exception`` guarding the release call does NOT catch it
    (``CancelledError`` is a ``BaseException`` subclass, not an ``Exception``
    subclass — see the module's FIX-8 docstring note). Modelled on
    ``test_release_on_timeout``, substituting a direct raise for the sleep +
    action-deadline race so no real cancellation/timeout wiring is needed —
    mirrors the precedent in
    ``tests/unit/egress/test_egress_response_extract.py::test_cancelled_error_leaves_no_orphaned_body``.
    """
    spy = _SpyHandleCap()

    async def _cancelled_handle(**_kwargs: Any) -> EgressExtractOutcome:
        raise asyncio.CancelledError()

    extractor = AsyncMock(spec=EgressResponseExtractor)
    extractor.handle = _cancelled_handle

    with pytest.raises(asyncio.CancelledError):
        await _dispatch(extractor=extractor, handle_cap=spy)

    assert len(spy.released) == 1
    assert spy.released == spy.reserved


# ---------------------------------------------------------------------------
# #339 PR4b-broker Task 3 — header raw-secret defence (Step 1b) + broker
# substitution (Step 1c). FIX-1 (plan-review CRITICAL): BOTH steps sit
# immediately after the URL url_secret_refused block and BEFORE Step 2 (the
# allowlist check) / Step 3b (the handle_cap reserve) — refusing an
# off-allowlist placeholder must never reserve, and then leak, a per-user
# concurrency slot.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_header_raw_secret_refused_audits_and_skips_extractor() -> None:
    """A RAW secret in a header (DLP redacts it) is refused pre-network — not
    redact-and-sent — with a header_secret_refused row; the extractor never
    fires."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda s: "[REDACTED]" if s.startswith("Bearer ") else s)

    with pytest.raises(WebFetchError):
        await _dispatch(
            audit=audit,
            outbound_dlp=dlp,
            extractor=extractor,
            headers={"Authorization": "Bearer sk-raw"},
        )

    extractor.handle.assert_not_awaited()
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "refused"
    assert call.kwargs["subject"]["dlp_scan_result"] == "header_secret_refused"


@pytest.mark.asyncio
async def test_header_raw_secret_refused_message_routes_through_i18n() -> None:
    """The header-secret ``WebFetchError`` surface is catalogued (i18n hard
    rule) — mirrors the existing URL-secret i18n pin."""
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda s: "[REDACTED]" if s.startswith("Bearer ") else s)

    with pytest.raises(WebFetchError) as excinfo:
        await _dispatch(outbound_dlp=dlp, headers={"Authorization": "Bearer sk-raw"})

    assert "secret" in str(excinfo.value).lower()


@pytest.mark.asyncio
async def test_off_allowlist_placeholder_refused_audits_and_skips_extractor() -> None:
    """An off-allowlist {{secret:*}} reference is refused (empty allowlist) with
    a secret_substitution_refused row; the extractor never fires."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    with pytest.raises(WebFetchError):
        await _dispatch(
            audit=audit,
            extractor=extractor,
            headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
            auth_secret_allowlist=frozenset(),  # explicit empty (the #339 default)
        )

    extractor.handle.assert_not_awaited()
    assert audit.append_schema.await_count == 1
    call = audit.append_schema.await_args
    assert call.kwargs["result"] == "refused"
    assert call.kwargs["subject"]["dlp_scan_result"] == "secret_substitution_refused"


@pytest.mark.asyncio
async def test_off_allowlist_placeholder_refused_message_routes_through_i18n() -> None:
    """The substitution-refusal ``WebFetchError`` surface is catalogued (i18n
    hard rule). PR #403 review: the msgstr no longer says "allowlist" (that
    word collided with the unrelated ``alfred web allowlist add`` domain
    command and named an operator lever that does not exist this release) —
    pin the reworded "not permitted" + audit-log-breadcrumb text instead."""
    with pytest.raises(WebFetchError) as excinfo:
        await _dispatch(
            headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
            auth_secret_allowlist=frozenset(),
        )

    message = str(excinfo.value).lower()
    assert "permitted" in message
    assert "audit log" in message


@pytest.mark.asyncio
async def test_off_allowlist_placeholder_refused_logs_forensic_discriminator() -> None:
    """err-001 (PR #403 review): Step 1c's ``except (SecretSubstitutionNotAllowed,
    UnknownSecretError)`` arm logs the exception TYPE NAME ONLY — never
    ``exc.ref``, ``str(exc)``, or any secret — BEFORE calling ``_refuse``. This
    is the forensic signal that lets an operator distinguish an off-allowlist /
    malformed probe (``SecretSubstitutionNotAllowed``, this test) from an
    unprovisioned secret (``UnknownSecretError``, the sibling test below)
    without leaking the referenced name into the log stream."""
    with (
        structlog.testing.capture_logs() as caps,
        pytest.raises(WebFetchError),
    ):
        await _dispatch(
            headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
            auth_secret_allowlist=frozenset(),
        )

    refusal_logs = [c for c in caps if c.get("event") == "web_fetch.secret_substitution_refused"]
    assert len(refusal_logs) == 1
    log = refusal_logs[0]
    assert log["error_type"] == "SecretSubstitutionNotAllowed"
    assert log["correlation_id"] == "corr-1"
    assert "deepseek_api_key" not in repr(log)


@pytest.mark.asyncio
async def test_off_allowlist_placeholder_refused_logs_unknown_secret_discriminator() -> None:
    """Sibling discriminator case: an ALLOWLISTED-but-UNPROVISIONED secret name
    makes ``SecretBroker.get`` raise ``UnknownSecretError`` (not
    ``SecretSubstitutionNotAllowed``) — the forensic log's ``error_type``
    distinguishes the two arms, matching ``_classify_action_timeout``'s
    established ``error_type=type(exc).__name__`` discriminator pattern."""
    broker = SecretBroker(env={})  # deepseek_api_key allowlisted but unset

    with (
        structlog.testing.capture_logs() as caps,
        pytest.raises(WebFetchError),
    ):
        await _dispatch(
            broker=broker,
            headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
            auth_secret_allowlist=frozenset({"deepseek_api_key"}),
        )

    refusal_logs = [c for c in caps if c.get("event") == "web_fetch.secret_substitution_refused"]
    assert len(refusal_logs) == 1
    assert refusal_logs[0]["error_type"] == "UnknownSecretError"
    assert "deepseek_api_key" not in repr(refusal_logs[0])


@pytest.mark.asyncio
async def test_broker_backend_fault_propagates_uncaught_not_converted_to_refusal() -> None:
    """test-002 / FIX-9 totality (PR #403 review): a broker BACKEND fault — a
    plain ``RuntimeError`` that is NEITHER ``SecretSubstitutionNotAllowed`` NOR
    ``UnknownSecretError`` — propagates OUT of ``dispatch_web_fetch`` uncaught.
    The Step-1c ``except`` arm is narrowly typed to the two refusal exceptions;
    it must NOT swallow (and mis-convert to ``secret_substitution_refused``) an
    unrelated backend fault (e.g. a future remote secret store's transport
    error). The fault is audited ONE LAYER UP by ``dispatch_tool``'s outer
    ``except Exception`` arm, not by a second arm here (module docstring's
    FIX-9 note, mirroring the PR4a handle_cap-reserve precedent) — so NO local
    ``tool.web.fetch`` audit row is written."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    class _FaultyBroker:
        def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str:
            raise RuntimeError("secret store connection reset")

    with pytest.raises(RuntimeError, match="secret store connection reset"):
        await _dispatch(
            audit=audit,
            extractor=extractor,
            broker=_FaultyBroker(),
            headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
            auth_secret_allowlist=frozenset({"deepseek_api_key"}),
        )

    extractor.handle.assert_not_awaited()
    assert audit.append_schema.await_count == 0


@pytest.mark.asyncio
async def test_allowlisted_placeholder_substituted_into_wire_headers() -> None:
    """A placeholder whose name is allowlisted + provisioned is substituted
    into the relay request AFTER DLP; the real value never appears in an
    audit subject."""
    audit = _build_audit()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    class _FakeBroker:
        def substitute(self, text: str, *, allowed_secrets: frozenset[str]) -> str:
            return text.replace("{{secret:deepseek_api_key}}", "sk-REAL")

    await _dispatch(
        audit=audit,
        extractor=extractor,
        broker=_FakeBroker(),
        headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
        auth_secret_allowlist=frozenset({"deepseek_api_key"}),
    )

    raw_request = extractor.handle.await_args.kwargs["raw_request"]
    assert raw_request.headers["Authorization"] == "Bearer sk-REAL"
    # The real value is never in any audit subject (headers are not an audit field).
    for call in audit.append_schema.await_args_list:
        assert "sk-REAL" not in repr(call.kwargs["subject"])


@pytest.mark.asyncio
async def test_allowlisted_placeholder_with_real_broker_substitutes_provisioned_secret() -> None:
    """FIX-2 positive-path coverage against the REAL ``SecretBroker`` (not just
    the brief's ``_FakeBroker``): a fixture secret provisioned on the broker
    and allowlisted for this call is substituted in verbatim, proving
    ``SecretBroker.substitute`` itself — not merely the Protocol shape — is
    wired correctly end to end."""
    extractor = _build_extractor(outcome=_make_extracted_outcome())
    broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": "sk-fixture-real-value"})

    await _dispatch(
        extractor=extractor,
        broker=broker,
        headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
        auth_secret_allowlist=frozenset({"deepseek_api_key"}),
    )

    raw_request = extractor.handle.await_args.kwargs["raw_request"]
    assert raw_request.headers["Authorization"] == "Bearer sk-fixture-real-value"


@pytest.mark.asyncio
async def test_header_placeholder_refusal_reserves_no_slot() -> None:
    """FIX-1 (plan-review CRITICAL): a Step-1c substitution refusal happens
    BEFORE Step 3b's handle_cap reserve — refusing every off-allowlist
    placeholder (the empty default allowlist means EVERY placeholder refuses)
    must never reserve, and thus never need to release, a per-user
    concurrency slot. A reserve-then-refuse ordering would be a
    planner-inducible self-DoS (an attacker-controlled placeholder burns a
    slot on every refused call)."""
    spy = _SpyHandleCap()
    extractor = _build_extractor(outcome=_make_extracted_outcome())

    with pytest.raises(WebFetchError):
        await _dispatch(
            extractor=extractor,
            handle_cap=spy,
            headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
            auth_secret_allowlist=frozenset(),
        )

    extractor.handle.assert_not_awaited()
    assert spy.reserved == []
    assert spy.released == []


@pytest.mark.asyncio
async def test_header_raw_secret_refusal_reserves_no_slot() -> None:
    """Symmetric with the Step-1c test above: a Step-1b raw-secret refusal is
    also earlier than the Step 3b reserve, so it never reserves a slot
    either."""
    spy = _SpyHandleCap()
    extractor = _build_extractor(outcome=_make_extracted_outcome())
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda s: "[REDACTED]" if s.startswith("Bearer ") else s)

    with pytest.raises(WebFetchError):
        await _dispatch(
            extractor=extractor,
            handle_cap=spy,
            outbound_dlp=dlp,
            headers={"Authorization": "Bearer sk-raw"},
        )

    extractor.handle.assert_not_awaited()
    assert spy.reserved == []
    assert spy.released == []


@pytest.mark.asyncio
async def test_off_allowlist_placeholder_refusal_does_not_leak_secret_name_via_context() -> None:
    """FIX-8: ``_refuse`` raises ``WebFetchError(...) from None``, so
    ``__cause__`` is ``None`` and ``__suppress_context__`` is ``True`` — a
    downstream traceback render (structlog / ``traceback.format_exception``,
    which both honour ``__suppress_context__``) never echoes the
    (attacker-influenced) secret name carried in ``UnknownSecretError``'s
    ``str()`` (it is a ``KeyError`` subclass whose message embeds the name —
    see ``SecretBroker.get``). Uses an ALLOWLISTED-but-UNPROVISIONED secret
    name so the broker's real ``get()`` raises ``UnknownSecretError``
    (the ``SecretSubstitutionNotAllowed`` arm never echoes the ref in its own
    ``str()``, so it doesn't exercise this leak path)."""
    broker = SecretBroker(env={})  # no secrets provisioned

    with pytest.raises(WebFetchError) as excinfo:
        await _dispatch(
            broker=broker,
            headers={"Authorization": "Bearer {{secret:deepseek_api_key}}"},
            auth_secret_allowlist=frozenset({"deepseek_api_key"}),
        )

    exc = excinfo.value
    assert exc.__cause__ is None
    assert exc.__suppress_context__ is True
    rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert "deepseek_api_key" not in rendered


@pytest.mark.asyncio
async def test_no_placeholder_header_substitutes_to_itself() -> None:
    """FIX-11 coverage: coverage.py does not instrument dict-comprehension
    conditionals — pin the else-path where ``broker.substitute`` is called on
    a header value with no ``{{secret:*}}`` placeholder and returns it
    byte-for-byte unchanged (proven against a REAL ``SecretBroker``, not a
    passthrough fake, so the no-op behaviour is the broker's actual
    ``re.sub`` no-match path, not a test double's shortcut)."""
    extractor = _build_extractor(outcome=_make_extracted_outcome())
    broker = SecretBroker(env={})

    await _dispatch(
        extractor=extractor,
        broker=broker,
        headers={"X-Custom": "no-placeholder-here"},
        auth_secret_allowlist=frozenset(),
    )

    raw_request = extractor.handle.await_args.kwargs["raw_request"]
    assert raw_request.headers["X-Custom"] == "no-placeholder-here"
