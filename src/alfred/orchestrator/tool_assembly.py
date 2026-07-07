"""``build_tool_registry`` — the orchestrator's tool-registry composition root
(#339 PR2 Task 7, spec §8).

Wires the two builtin tools (:mod:`alfred.orchestrator.builtin_tools`) into a
single :class:`~alfred.orchestrator.tool_registry.ToolRegistry`:

* ``web.fetch`` — an :class:`~alfred.orchestrator.tool_registry.ExternalToolSpec`
  built by :func:`~alfred.orchestrator.builtin_tools.build_web_fetch_tool` over
  the :class:`~alfred.egress.egress_response_extract.EgressResponseExtractor`
  assembled by
  :func:`~alfred.plugins.web_fetch.assembly.build_web_fetch_egress_extractor`.
* ``clock.now`` — the first-party ≤T2
  :class:`~alfred.orchestrator.tool_registry.InternalToolSpec` built by
  :func:`~alfred.orchestrator.builtin_tools.build_clock_tool`.

REUSE, not re-spawn (§4.3 "one production extractor"; CORE-4 shared-child HoL)
-------------------------------------------------------------------------------
``gate`` / ``extractor`` / ``recorder`` are the daemon's ALREADY-BUILT
quarantine-graph components (the live ``QuarantinedExtractor``, the
``CapabilityGate``, the ``T3BodyRecorder`` minted over the boot
``CapabilityGateNonce``) — passed straight through to
``build_web_fetch_egress_extractor``. This function never constructs a second
quarantined child; it is pure composition over an already-live graph.

Test callers only in PR2
-------------------------
This assembly has **no production caller** in PR2 — it is not wired into
``build_orchestrator`` / the Act phase (that lands in PR3, once a real
turn-user and the dispatch loop exist). An integration test
(``tests/integration/orchestrator/test_tool_assembly.py``) drives the full
stack over a loopback relay to prove the wiring is correct ahead of PR3's
live caller — the same "test is the proof, not a live caller" precedent
``build_web_fetch_egress_extractor`` itself establishes (ADR-0041 / §5.3).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from alfred.orchestrator.builtin_tools import build_clock_tool, build_web_fetch_tool
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.plugins.web_fetch.assembly import build_web_fetch_egress_extractor

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from alfred.audit.log import AuditWriter
    from alfred.config.settings import Settings
    from alfred.hooks.capability import CapabilityGate
    from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
    from alfred.plugins.web_fetch.handle_cap import HandleCap
    from alfred.plugins.web_fetch.rate_limit import RateLimiter
    from alfred.security.dlp import OutboundDlp
    from alfred.security.quarantine import QuarantinedExtractor
    from alfred.security.quarantine_transport import T3BodyRecorder
    from alfred.security.secrets import SecretBroker


def _utc_now() -> datetime:
    """Default ``now`` callable for ``build_tool_registry`` — real UTC wall clock."""
    return datetime.now(UTC)


def build_tool_registry(
    *,
    settings: Settings,
    gate: CapabilityGate,
    extractor: QuarantinedExtractor,
    recorder: T3BodyRecorder,
    outbound_dlp: OutboundDlp,
    broker: SecretBroker,
    audit_writer: AuditWriter,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    rate_limiter: RateLimiter,
    handle_cap: HandleCap,
    config: FetchDispatchConfig,
    now: Callable[[], datetime] = _utc_now,
) -> ToolRegistry:
    """Assemble the production :class:`ToolRegistry` (``web.fetch`` + ``clock.now``).

    Args:
        settings: Carries ``egress_relay_url`` — threaded straight into
            :func:`build_web_fetch_egress_extractor` (REQUIRED to be set;
            that factory fails closed otherwise).
        gate: The boot ``CapabilityGate`` — reused for BOTH the egress
            extractor's gate-first T3→T2 dereference check AND (at dispatch
            time, via ``dispatch_tool``) the ``tool.dispatch`` /
            ``t3.downgrade_to_orchestrator`` checks. ONE gate object, never a
            per-tool copy.
        extractor: The boot ``QuarantinedExtractor`` over the LIVE quarantined
            child. Reused, not re-spawned.
        recorder: The boot ``T3BodyRecorder`` (nonce + staging map shared with
            the extractor's transport).
        outbound_dlp: The boot ``OutboundDlp`` — the relay client's core-side
            redaction pass AND ``build_web_fetch_tool``'s dispatch-time DLP
            scanner.
        broker: The daemon's ``SecretBroker`` service (#339 PR4b-broker),
            injected by plain DI — resolves an allowlisted
            ``{{secret:<name>}}`` header placeholder into the real secret
            value at ``dispatch_web_fetch``'s Step 1c, gated by the
            empty-default ``WEB_FETCH_AUTH_SECRET_ALLOWLIST`` (see
            ADR-0048).
        audit_writer: The durable audit sink for both the relay client's
            refusal rows and ``dispatch_web_fetch``'s per-fetch audit rows.
        session_scope: The async session scope the egress extractor's
            Postgres idempotency ledger commits intents / records T2 through.
        rate_limiter: The per-domain/per-user/daily ``web.fetch`` rate
            limiter (spec §7.7).
        handle_cap: The per-user concurrent-fetch cap (spec §7.10).
        config: The per-session ``FetchDispatchConfig`` (three-way allowlist
            + manifest commit hash).
        now: The clock callable ``clock.now`` reports from. Defaults to the
            real UTC wall clock (:func:`_utc_now`); tests inject a fixed
            callable for determinism.

    Returns:
        A :class:`ToolRegistry` advertising exactly two tools: ``web.fetch``
        (T3, quarantine-extracted) and ``clock.now`` (T2, first-party).
    """
    web_fetch_extractor = build_web_fetch_egress_extractor(
        settings=settings,
        gate=gate,
        extractor=extractor,
        recorder=recorder,
        outbound_dlp=outbound_dlp,
        audit_writer=audit_writer,
        session_scope=session_scope,
    )
    web_fetch_spec = build_web_fetch_tool(
        extractor=web_fetch_extractor,
        config=config,
        rate_limiter=rate_limiter,
        handle_cap=handle_cap,
        outbound_dlp=outbound_dlp,
        broker=broker,
        audit=audit_writer,
    )
    clock_spec = build_clock_tool(now=now)
    return ToolRegistry([web_fetch_spec, clock_spec])


__all__ = ["build_tool_registry"]
