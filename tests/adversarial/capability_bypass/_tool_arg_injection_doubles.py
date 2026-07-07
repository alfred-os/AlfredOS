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
from alfred.orchestrator.builtin_tools import build_web_fetch_tool
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.security.secrets import SecretBroker
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.dlp import identity_outbound_dlp


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


def build_refusing_web_fetch_registry(
    writer: object, *, safe_domain: str = "safe.example.com"
) -> ToolRegistry:
    """Build a real ToolRegistry with the T3 web.fetch tool whose three-way
    allowlist permits ONLY ``safe_domain`` (all tiers), wired with the
    raise-if-reached fire-spies + an unreached SpyHandleCap. Any off-allowlist
    URL is refused pre-egress; the fire-spies prove the relay/rate-limiter never
    run. Shared by the cap-2026-006..011 tool-arg-injection modules."""
    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=safe_domain),),
        operator_allowed_entries=(AllowlistEntry(domain=safe_domain),),
        session_allowed_entries=(AllowlistEntry(domain=safe_domain),),
        manifest_commit_hash="test-commit",
    )
    web_fetch_spec = build_web_fetch_tool(
        extractor=RelayNeverFiresExtractor(),  # type: ignore[arg-type]
        config=config,
        rate_limiter=RateLimiterNeverConsulted(),  # type: ignore[arg-type]
        handle_cap=SpyHandleCap(),  # type: ignore[arg-type]
        outbound_dlp=identity_outbound_dlp(),
        broker=SecretBroker(env={}),
        audit=writer,  # type: ignore[arg-type]
    )
    return ToolRegistry([web_fetch_spec])


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
