"""Tests for the WebFetchRateLimited bucket widening + WebFetchHandleIdMismatch."""

from __future__ import annotations

from alfred.plugins.web_fetch.errors import (
    WebFetchError,
    WebFetchHandleIdMismatch,
    WebFetchRateLimited,
)


def test_handle_cap_bucket_accepted() -> None:
    """bucket='handle_cap' is a legal value alongside the three existing buckets."""
    exc = WebFetchRateLimited("handle_cap")
    assert exc.bucket == "handle_cap"
    assert isinstance(exc, WebFetchError)


def test_handle_cap_bucket_message_dispatches_to_dedicated_key() -> None:
    """The msgstr for bucket='handle_cap' points at the dedicated catalog key
    so operators are routed to the right config knob (not the generic
    web_fetch.rate_limits one)."""
    exc = WebFetchRateLimited("handle_cap")
    msg = str(exc)
    # The dedicated msgstr mentions max_concurrent_handles_per_user.
    assert "max_concurrent_handles_per_user" in msg or "concurrent" in msg.lower()


def test_existing_buckets_still_use_generic_template() -> None:
    """Existing three buckets continue to use the generic web.fetch.error.rate_limited
    msgstr — no regression from the dispatch added for handle_cap.

    Also verifies the negative half: the dedicated handle-cap remediation
    pointer (``max_concurrent_handles_per_user``) MUST NOT leak into the
    generic template — that key belongs to the cap-only catalog entry, and
    a regression that routed every bucket through it would mis-direct
    operators of the existing three buckets at the wrong knob.
    """
    for bucket in ("per_domain", "per_user", "daily_budget"):
        exc = WebFetchRateLimited(bucket)
        assert exc.bucket == bucket
        assert "max_concurrent_handles_per_user" not in str(exc)


def test_handle_id_mismatch_is_webfetch_error_subclass() -> None:
    """WebFetchHandleIdMismatch is a WebFetchError (operational error,
    not a security event) — the orchestrator's operational arm surfaces it."""
    exc = WebFetchHandleIdMismatch(expected="aaa", got="bbb")
    assert isinstance(exc, WebFetchError)
    assert exc.expected == "aaa"
    assert exc.got == "bbb"


def test_handle_id_mismatch_message_does_not_leak_ids() -> None:
    """The caller-visible message does NOT interpolate the offending ids
    (forensic detail rides on .expected / .got for the audit row)."""
    exc = WebFetchHandleIdMismatch(expected="aaaa-bbbb-cccc", got="xxxx-yyyy-zzzz")
    msg = str(exc)
    assert "aaaa-bbbb-cccc" not in msg
    assert "xxxx-yyyy-zzzz" not in msg
