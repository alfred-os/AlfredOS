"""Shared fire-spy test doubles + payload filter for the cap-2026
tool-argument-injection corpus.

``RelayNeverFiresExtractor`` and ``RateLimiterNeverConsulted`` RAISE if reached,
so a defense regression fails at the exact call site. ``SpyHandleCap`` is a
permissive-but-UNREACHED fake (the refusal fires before the handle-cap reserve),
present only to satisfy ``build_web_fetch_tool``'s signature. CLAUDE.md hard rule
#2 (never a permissive capability-gate shim) is enforced by the REAL
``make_tool_dispatch_gate()`` ``RealGate`` in each test — NOT by these doubles,
which are a rate-limiter / relay / handle-cap concern, not the gate. Used by
``test_cap_2026_006_tool_arg_injection.py`` and the ``cap-2026-007``..``011``
breadth modules.
"""

from __future__ import annotations

import pytest

from alfred.egress.egress_response_extract import EgressExtractOutcome
from tests.adversarial.payload_schema import AdversarialPayload


class RelayNeverFiresExtractor:
    """Fire-spy proving the egress relay NEVER fires for a refused call."""

    async def handle(self, **_kwargs: object) -> EgressExtractOutcome:
        raise AssertionError(
            "EgressResponseExtractor.handle() was called for a refused tool "
            "call — the refusal must fire BEFORE the relay/extractor ever runs"
        )


class RateLimiterNeverConsulted:
    """Fire-spy proving the rate limiter is never consulted for a refused call."""

    async def check_and_increment(self, *, domain: str, user_id: str) -> None:
        raise AssertionError(
            "RateLimiter.check_and_increment() was called for a refused tool "
            "call — the refusal must fire BEFORE the rate limiter runs"
        )


class SpyHandleCap:
    """Permissive-but-UNREACHED fake ``HandleCap`` — construction-only plumbing
    required by ``build_web_fetch_tool``'s signature; the refusal precedes the
    handle-cap reserve so this is never invoked (NOT a defense under test, and
    NOT the capability gate — see the module docstring)."""

    async def try_reserve(self, *, user_id: str, handle_id: str, handle_ttl_seconds: int) -> None:
        return None

    async def release(
        self, *, user_id: str, handle_id: str, correlation_id: str | None = None
    ) -> None:
        return None


def payload_by_id(
    corpus_payloads: tuple[AdversarialPayload, ...], payload_id: str
) -> AdversarialPayload:
    """Filter the session-scoped corpus to one payload, failing loudly on a
    missing/duplicate id (the corpus drift-guard shared by the cap-2026-006..011
    tests)."""
    matches = [p for p in corpus_payloads if p.id == payload_id]
    if len(matches) != 1:
        raise pytest.UsageError(
            f"adversarial corpus must have exactly one payload id={payload_id!r}; "
            f"found {len(matches)} under tests/adversarial/capability_bypass/"
        )
    return matches[0]
