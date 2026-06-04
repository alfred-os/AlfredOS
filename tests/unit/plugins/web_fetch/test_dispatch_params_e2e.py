"""End-to-end parametrised coverage of dispatch_web_fetch's host-side
validation arm (issue #147 §5.3).

Drives ``dispatch_web_fetch`` with the production dispatcher path; only
the dispatcher's CONSTRUCTION of ``WebFetchDispatchParams`` is patched
to simulate each missing-required-field / wrong-type case. The
production validation + cap-release + audit-row + structlog emit chain
fires for real.

The ``tests/adversarial/`` corpus categories don't include a
``security_misconfig`` shape — this isn't an adversarial scenario, it
is defensive engineering against host-side defects (the C2/arch-002
shape from PR-S3-5). See spec §5.3 for the rationale.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from structlog.testing import capture_logs

from alfred.plugins.web_fetch.dispatch_params import WebFetchDispatchParams
from alfred.plugins.web_fetch.errors import WebFetchError
from alfred.plugins.web_fetch.fetch_dispatcher import dispatch_web_fetch

# Reuse the existing factory machinery so this file pins the production
# dispatcher path, not a parallel test-only construction. test_fetch_dispatcher
# is a module under tests/unit/plugins/web_fetch/ (the conftest.py + __init__.py
# make it importable as a sibling).
from tests.unit.plugins.web_fetch.test_fetch_dispatcher import (
    _build_audit,
    _build_config,
    _build_dlp,
    _build_handle_cap,
    _build_rate_limiter,
    _build_transport_returning_handle,
    _pin_pre_minted_handle_id,
)

_MISSING_FIELDS: tuple[str, ...] = (
    "url",
    "headers",
    "redis_url",
    "correlation_id",
    "content_handle_id",
)


def _make_patched_init_missing(missing_field: str) -> Any:
    """Build a patched ``__init__`` that drops ``missing_field`` before
    delegating, so the real Pydantic validation raises ``ValidationError``
    on the missing-field case.
    """
    original_init = WebFetchDispatchParams.__init__

    def patched_init(self: WebFetchDispatchParams, **kwargs: Any) -> None:
        kwargs.pop(missing_field, None)
        original_init(self, **kwargs)

    return patched_init


def _make_patched_init_wrong_type(field: str, wrong_value: object) -> Any:
    """Build a patched ``__init__`` that overwrites ``field`` with
    ``wrong_value`` before delegating, exercising the strict=True arm
    of the production model on each wrong-type case.
    """
    original_init = WebFetchDispatchParams.__init__

    def patched_init(self: WebFetchDispatchParams, **kwargs: Any) -> None:
        kwargs[field] = wrong_value
        original_init(self, **kwargs)

    return patched_init


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_field", _MISSING_FIELDS)
async def test_each_missing_required_field_fails_clean(missing_field: str) -> None:
    """Each missing required field raises ``WebFetchError``;
    ``transport.dispatch`` never called; cap released; audit row carries
    ``dispatch_param_invalid``.

    L-1 (TEST-1): the structlog signal
    ``web_fetch.dispatch.param_validation_failed`` fires exactly once per
    failure, carries ``exception_type="ValidationError"`` for forensic
    correlation, and does NOT echo the missing field name in any value
    — that's the load-bearing redaction (Pydantic error messages embed
    field names AND ``input_value=...`` blobs that may carry secrets).

    L-2 (TEST-3): the audit row's ``subject["content_handle_id"]`` is
    the pre-minted UUID (NOT None), distinguishing the validation-error
    row from the cap-refusal row (which uses None per #157 disputed-2 —
    no body was ever written under that id).
    """
    audit = _build_audit()
    transport = _build_transport_returning_handle()
    handle_cap = _build_handle_cap()

    with (
        _pin_pre_minted_handle_id("pinned-handle-uuid"),
        patch.object(
            WebFetchDispatchParams,
            "__init__",
            _make_patched_init_missing(missing_field),
        ),
        capture_logs() as logs,
        pytest.raises(WebFetchError),
    ):
        # correlation_id is leak-safe: it embeds an index, not the
        # missing field name itself. The L-1 redaction assertion below
        # checks that NO structlog value carries ``missing_field`` —
        # using ``missing_field`` in the cid would be a self-fulfilling
        # false positive (the field name is data the operator typed,
        # not data the production code surfaced).
        correlation_id = f"cid-e2e-missing-idx-{_MISSING_FIELDS.index(missing_field)}"
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={"Accept": "text/html"},
            user_id="user-e2e",
            correlation_id=correlation_id,
            config=_build_config(),
            rate_limiter=_build_rate_limiter(refused=None),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
            handle_cap=handle_cap,
        )

    transport.dispatch.assert_not_called()
    handle_cap.release.assert_awaited_once()
    rows = [c.kwargs for c in audit.append_schema.await_args_list]
    inv = [r for r in rows if r["result"] == "dispatch_param_invalid"]
    assert len(inv) == 1, (
        f"expected exactly one dispatch_param_invalid row for missing "
        f"{missing_field!r}; got {rows!r}"
    )
    assert inv[0]["subject"]["dlp_scan_result"] == "dispatch_param_invalid"

    # L-2 / TEST-3: pre-minted UUID pinned on the audit row. None would
    # collide with the cap-refusal row's content_handle_id=None
    # precedent, breaking audit-graph correlators that distinguish the
    # two fault classes via this field.
    assert inv[0]["subject"]["content_handle_id"] == "pinned-handle-uuid", (
        f"L-2: expected pre-minted UUID on dispatch_param_invalid row; "
        f"got {inv[0]['subject']['content_handle_id']!r}"
    )

    # L-1 / TEST-1: exactly one structlog event with
    # exception_type="ValidationError" and no leak of the missing field
    # name through any value (the test name embeds it; structlog values
    # must not).
    validation_events = [
        e for e in logs if e.get("event") == "web_fetch.dispatch.param_validation_failed"
    ]
    assert len(validation_events) == 1, (
        f"L-1: expected exactly one param_validation_failed structlog event "
        f"for missing {missing_field!r}; got {validation_events!r}"
    )
    event = validation_events[0]
    assert event["exception_type"] == "ValidationError", (
        f"L-1: exception_type tag is the forensic-correlation channel; "
        f"got {event['exception_type']!r}"
    )
    # The missing field name must NOT appear in any value: that is the
    # redaction the from-None + type-name-only contract defends.
    for key, value in event.items():
        # The structlog event-name key is "event"; skip it (it carries
        # the static "param_validation_failed" tag, not a leak).
        if key == "event":
            continue
        assert missing_field not in str(value), (
            f"L-1: missing field name {missing_field!r} leaked through "
            f"structlog value {key}={value!r}"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("url", 42),
        ("headers", "Accept: text/html"),
        ("redis_url", 99),
        ("correlation_id", 99),
        ("content_handle_id", 99),
        ("size_limit_bytes", 0),
        ("size_limit_bytes", -1),
        ("size_limit_bytes", 1.5),
        ("skip_tls_verify", 1),
    ],
)
async def test_each_wrong_type_field_fails_clean(field: str, wrong_value: object) -> None:
    """Each wrong-type variant (per spec §5.3) raises ``WebFetchError``
    via the model's ``strict=True`` / ``Field(gt=0)`` arms;
    ``transport.dispatch`` never called; cap released; audit row carries
    ``dispatch_param_invalid``."""
    audit = _build_audit()
    transport = _build_transport_returning_handle()
    handle_cap = _build_handle_cap()

    with (
        patch.object(
            WebFetchDispatchParams,
            "__init__",
            _make_patched_init_wrong_type(field, wrong_value),
        ),
        pytest.raises(WebFetchError),
    ):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={"Accept": "text/html"},
            user_id="user-e2e",
            correlation_id=f"cid-e2e-wrong-{field}",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(refused=None),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
            handle_cap=handle_cap,
        )

    transport.dispatch.assert_not_called()
    handle_cap.release.assert_awaited_once()
    rows = [c.kwargs for c in audit.append_schema.await_args_list]
    inv = [r for r in rows if r["result"] == "dispatch_param_invalid"]
    assert len(inv) == 1, (
        f"expected exactly one dispatch_param_invalid row for wrong-type "
        f"{field!r}={wrong_value!r}; got {rows!r}"
    )


@pytest.mark.asyncio
async def test_dispatcher_passes_exact_kwarg_set_to_model() -> None:
    """SEC-147-2 / M-2: pins the dispatcher↔model kwarg-set contract
    end-to-end.

    Drives the real dispatcher through the production
    ``WebFetchDispatchParams`` construction with NO behaviour patching —
    the spy only OBSERVES the kwargs the dispatcher passes and forwards
    them to the real ``__init__``. The test fails on any field-set drift
    (dispatcher adds/removes a kwarg without updating the model) which
    is the exact shape ``extra="forbid"`` defends at runtime but which
    a unit-level model test cannot witness end-to-end.

    The expected set covers every required field on the model plus the
    optional ``skip_tls_verify`` (the dispatcher always passes it
    explicitly from the per-session config). ``size_limit_bytes`` is
    NOT yet plumbed through the dispatcher — when it is, this test
    fails loud and the expected set grows in the same PR.
    """
    audit = _build_audit()
    transport = _build_transport_returning_handle()
    handle_cap = _build_handle_cap()
    captured_kwargs: dict[str, object] | None = None
    real_init = WebFetchDispatchParams.__init__

    def spy_init(self: WebFetchDispatchParams, **kwargs: Any) -> None:
        nonlocal captured_kwargs
        captured_kwargs = dict(kwargs)
        real_init(self, **kwargs)

    with (
        _pin_pre_minted_handle_id(),
        patch.object(WebFetchDispatchParams, "__init__", spy_init),
    ):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={"Accept": "text/html"},
            user_id="user-e2e",
            correlation_id="cid-e2e-contract",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(refused=None),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
            handle_cap=handle_cap,
        )

    assert captured_kwargs is not None, (
        "SEC-147-2: dispatcher never constructed WebFetchDispatchParams"
    )
    expected = {
        "url",
        "headers",
        "redis_url",
        "correlation_id",
        "content_handle_id",
        "skip_tls_verify",
    }
    actual = set(captured_kwargs.keys())
    assert actual == expected, (
        f"SEC-147-2: dispatcher↔model contract drift: got {actual}, "
        f"expected {expected}. If this PR adds/removes a kwarg, the "
        f"expected set must change in lockstep with the dispatcher."
    )


@pytest.mark.asyncio
async def test_dispatcher_param_validation_error_chain_suppressed() -> None:
    """SEC-147-1: ``raise WebFetchError(...) from None`` suppresses the
    ``__cause__`` chain so the Pydantic ``ValidationError`` (whose
    message embeds ``input_value=...`` for failed fields) cannot leak
    through ``logger.exception()`` upstream.

    Pins ``__cause__ is None`` (the load-bearing redaction) and
    ``__context__`` is the original ``ValidationError`` (Python's
    automatic re-attachment — that's the local runtime trace; only
    ``__cause__`` is suppressed by ``from None``). The structlog
    ``exception_type`` signal is the forensic-correlation channel;
    ``correlation_id`` ties it back to the audit row.
    """
    audit = _build_audit()
    transport = _build_transport_returning_handle()
    handle_cap = _build_handle_cap()

    # Patch construction to drop a required field so the real Pydantic
    # validation raises ValidationError on the production code path.
    with (
        _pin_pre_minted_handle_id(),
        patch.object(
            WebFetchDispatchParams,
            "__init__",
            _make_patched_init_missing("url"),
        ),
        pytest.raises(WebFetchError) as exc_info,
    ):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={"Accept": "text/html"},
            user_id="user-e2e",
            correlation_id="cid-e2e-cause-chain",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(refused=None),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
            handle_cap=handle_cap,
        )

    assert exc_info.value.__cause__ is None, (
        "SEC-147-1: cause chain must be suppressed to prevent Pydantic "
        "input_value leak via __cause__"
    )
    # Python automatically attaches __context__ on a raise inside an
    # except-arm; only __cause__ is suppressed by `from None`. Pinning
    # __context__ here documents that the redaction is targeted (not a
    # blanket sanitisation) so a future refactor cannot regress to a
    # generic `raise` that loses the LOCAL stack trace too.
    assert isinstance(exc_info.value.__context__, ValidationError), (
        f"SEC-147-1: __context__ should be the original ValidationError "
        f"(local trace); got {type(exc_info.value.__context__)!r}"
    )


@pytest.mark.asyncio
async def test_extra_field_in_kwargs_fails_clean() -> None:
    """An extra kwarg surfaces via ``extra="forbid"`` — the future
    dispatcher-adds-a-key-without-updating-the-model shape (spec §2.1)."""
    audit = _build_audit()
    transport = _build_transport_returning_handle()
    handle_cap = _build_handle_cap()

    original_init = WebFetchDispatchParams.__init__

    def patched_init(self: WebFetchDispatchParams, **kwargs: Any) -> None:
        kwargs["unexpected_key"] = "x"
        original_init(self, **kwargs)

    with (
        patch.object(WebFetchDispatchParams, "__init__", patched_init),
        pytest.raises(WebFetchError),
    ):
        await dispatch_web_fetch(
            url="https://example.com/page",
            headers={"Accept": "text/html"},
            user_id="user-e2e",
            correlation_id="cid-e2e-extra",
            config=_build_config(),
            rate_limiter=_build_rate_limiter(refused=None),
            outbound_dlp=_build_dlp(),
            audit=audit,
            transport=transport,
            handle_cap=handle_cap,
        )

    transport.dispatch.assert_not_called()
    handle_cap.release.assert_awaited_once()
    rows = [c.kwargs for c in audit.append_schema.await_args_list]
    assert any(r["result"] == "dispatch_param_invalid" for r in rows), (
        f"expected dispatch_param_invalid audit row; got {rows!r}"
    )
