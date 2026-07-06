"""Production assembly of the ``web.fetch`` egress extractor (Spec C G7-2.5 PR2, #333).

The orchestrator's tool-calling loop (epic #339, after G7-3) drives a re-homed
``web.fetch`` through
:class:`~alfred.egress.egress_response_extract.EgressResponseExtractor` — the
sanctioned §4.3 T3→T2 boundary that fires the fetch through the gateway relay
and returns a **T2** outcome via ``quarantined_to_structured``. This module is
the composition root for that extractor.

:func:`build_web_fetch_egress_extractor` is a **factory**, not boot-time
construction. ``dispatch_web_fetch`` has zero production callers until #339, so
building the extractor at daemon boot would be dangling, never-exercised
construction (the "paper-gate" the plan-review flagged). Instead #339's
tool-loop calls this factory at the point it first needs a live ``web.fetch``;
an integration test exercises the assembled extractor over a loopback relay to
prove the wiring (ADR-0041 / §5.3 — the test is the proof, not a live caller).

REUSE, not re-spawn (§4.3 "one production extractor"; CORE-4 shared-child HoL)
-----------------------------------------------------------------------------
The factory takes the daemon's **already-built** quarantine graph — the live
:class:`~alfred.security.quarantine.QuarantinedExtractor`, the
:class:`~alfred.hooks.capability.CapabilityGate`, and the
:class:`~alfred.security.quarantine_transport.T3BodyRecorder` minted over the
boot ``CapabilityGateNonce`` — and threads them straight into the
``EgressResponseExtractor``. It NEVER spawns a second quarantined child: a
second child would both double the sandbox cost and reintroduce the CORE-4
shared-child head-of-line bound the one-extractor rule exists to avoid.

What the factory adds on top of the reused graph: the
:class:`~alfred.egress.relay_client.RelayEgressClient` (C1), its Postgres
idempotency ledger, and the web.fetch :class:`~alfred.egress.response_inspection.ResponsePolicy`
(MIME allowlist + the 5 MiB response cap + the optional inbound-canary matcher).

Fail-closed: ``settings.egress_relay_url`` MUST be set (PR2 wires it via
compose). An unset relay URL is a misconfiguration — the factory refuses rather
than build an extractor that would crash on first fire (HARD rule #9 — the core
has no direct-egress fallback for tool egress).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from alfred.egress.egress_response_extract import EgressResponseExtractor
from alfred.egress.relay_client import RelayEgressClient
from alfred.egress.response_inspection import ResponsePolicy
from alfred.memory.egress_idempotency import PostgresEgressIdempotencyStore
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from alfred.audit.log import AuditWriter
    from alfred.config.settings import Settings
    from alfred.hooks.capability import CapabilityGate
    from alfred.security.dlp import OutboundDlp
    from alfred.security.quarantine import QuarantinedExtractor
    from alfred.security.quarantine_transport import T3BodyRecorder

# Spec C5 (G7-2.5): web.fetch's OWN response-size ceiling, deliberately TIGHTER
# than the gateway relay's 10 MiB structural cap. Each fetched MiB now costs a
# quarantined-LLM extraction pass, so web.fetch narrows the cap as a
# cost/quality policy (the gateway cap stays the generic-relay backstop). PR1's
# re-home removed the old subprocess ``_DEFAULT_SIZE_LIMIT_BYTES``; this is its
# canonical re-establishment as a named ``ResponsePolicy.max_bytes`` value.
_WEB_FETCH_RESPONSE_MAX_BYTES: Final[int] = 5 * 1024 * 1024

# web.fetch's MIME allowlist (Spec C §3 D1). ``Content-Type`` is attacker-
# controlled T3 — this is an advisory cost/quality narrowing, NEVER an injection
# control (the dual-LLM split + schema validation are the real containment). A
# missing/duplicate/garbage Content-Type fails CLOSED (a soft refusal) in
# ``inspect_response``.
_WEB_FETCH_MIME_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "text/html",
        "text/plain",
        "application/json",
        "application/xml",
        "text/markdown",
    }
)

# A sane in-flight bound for the relay client's global semaphore. The per-user
# fairness bound + the per-(user, persona) quarantine burst-limiter belong in
# #339 with the real turn-user (§7 residual); until then this caps concurrent
# mode-(b) fires so a burst cannot head-of-line the comms relay.
_DEFAULT_RELAY_CONCURRENCY: Final[int] = 8


def _resolve_web_fetch_canary(settings: Settings) -> CanaryMatcher:
    """Build the web.fetch INBOUND-reflection canary matcher from settings.

    The core-side counterpart to the gateway's ``resolve_canary_tokens`` (#339
    blocker 5 / #347). ALWAYS returns a NON-``None`` matcher: an empty token list
    yields a no-op matcher (``first_match`` always ``None``) so the
    ``ResponsePolicy`` canary seam is uniformly ARMED — populated when the operator
    sets ``ALFRED_WEB_FETCH_CANARY_TOKENS``, a no-op otherwise. Never ``None`` —
    that was the pre-#339 unwired state the ``de-2026-012`` merge-blocker enforces
    against.
    """
    return CanaryMatcher(tokens=[CanaryToken(token) for token in settings.web_fetch_canary_tokens])


def build_web_fetch_egress_extractor(
    *,
    settings: Settings,
    gate: CapabilityGate,
    extractor: QuarantinedExtractor,
    recorder: T3BodyRecorder,
    outbound_dlp: OutboundDlp,
    audit_writer: AuditWriter,
    session_scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    concurrency: int = _DEFAULT_RELAY_CONCURRENCY,
    canary: CanaryMatcher | None = None,
) -> EgressResponseExtractor:
    """Assemble the production ``web.fetch`` :class:`EgressResponseExtractor`.

    The ``gate`` / ``extractor`` / ``recorder`` are the daemon's existing
    quarantine-graph components (built once at boot; see
    ``cli/daemon/_commands.py``) — passed in, NEVER re-spawned (§4.3 one
    extractor; CORE-4 shared-child HoL). The daemon supplies
    ``session_scope=build_boot_session_scope(settings)`` so the ledger rides the
    SAME shared DSN-cached engine as the rest of the boot graph.

    Args:
        settings: Carries ``egress_relay_url`` (the gateway mode-(b) relay
            address PR2 wires via compose). REQUIRED to be set.
        gate: The boot ``CapabilityGate`` — the gate-first clearance check the
            ``quarantined_to_structured`` seam consults.
        extractor: The boot ``QuarantinedExtractor`` over the LIVE quarantined
            child. Reused, not re-spawned.
        recorder: The boot ``T3BodyRecorder`` (nonce + staging map shared with
            the extractor's transport).
        outbound_dlp: The boot ``OutboundDlp`` (broker set) — the relay client's
            core-side stage-1+2+3 redaction pass.
        audit_writer: The durable audit sink for the relay client's refusal
            rows (HARD rule #7).
        session_scope: The async session scope the Postgres idempotency ledger
            commits intents / records T2 through.
        concurrency: The relay client's in-flight semaphore bound.
        canary: Optional inbound-canary matcher for the pre-extract seam. When
            ``None`` (default), derived from ``settings.web_fetch_canary_tokens``
            — always a non-``None`` matcher (empty tokens yield a no-op matcher).
            An explicit matcher overrides the settings-derived one (#339 PR4a).

    Returns:
        A wired ``EgressResponseExtractor`` ready for ``dispatch_web_fetch``.
        Build this ONCE at composition and cache it: the relay client's in-flight
        concurrency semaphore is per-INSTANCE, so calling the factory per fetch
        would give each fire its own semaphore and defeat the global cap (#339).

    Raises:
        ValueError: ``settings.egress_relay_url`` is unset (fail-closed: the
            connectivity-free core has no direct tool-egress fallback — HARD
            rule #9). Mirrors ``RelayEgressClient``'s own URL contract.

    (#339 PR4a wiring, blocker 5 / #347): The inbound-reflection canary seam is
    now ALWAYS ARMED. An explicit ``canary`` (e.g. for testing) is honoured;
    otherwise the matcher is derived from ``ALFRED_WEB_FETCH_CANARY_TOKENS``
    (settings.web_fetch_canary_tokens). A non-``None`` matcher is GUARANTEED
    even with zero tokens (a no-op matcher). Closes the ``de-2026-012``
    merge-blocker: ``policy.canary`` is never ``None`` for a factory-built
    extractor.
    """
    relay_url = settings.egress_relay_url
    if relay_url is None:
        # Fail-closed: an unset relay URL means tool egress is not configured.
        # The core cannot open an external socket (HARD rule #9), so there is no
        # fallback — refuse to build an extractor that would crash on first fire.
        raise ValueError(
            "settings.egress_relay_url is unset — the web.fetch egress extractor "
            "cannot be assembled without the gateway relay address (set "
            "ALFRED_EGRESS_RELAY_URL; PR2 wires it via compose)."
        )

    ledger = PostgresEgressIdempotencyStore(session_scope=session_scope)
    relay_client = RelayEgressClient(
        relay_url=relay_url,
        core_dlp=outbound_dlp,
        ledger=ledger,
        audit_writer=audit_writer,
        concurrency=concurrency,
    )
    # #339 PR4a (blocker 5, #347): the inbound-reflection canary seam is now
    # ALWAYS armed. An explicit ``canary`` (e.g. a test) is honoured; otherwise
    # derive the matcher from the core-side token source
    # (``ALFRED_WEB_FETCH_CANARY_TOKENS``) — non-``None`` even with zero tokens (a
    # no-op matcher). Closes the ``de-2026-012`` strict-xfail merge-blocker:
    # ``policy.canary`` is never ``None`` for a factory-built extractor.
    resolved_canary = canary if canary is not None else _resolve_web_fetch_canary(settings)
    response_policy = ResponsePolicy(
        mime_allowlist=_WEB_FETCH_MIME_ALLOWLIST,
        max_bytes=_WEB_FETCH_RESPONSE_MAX_BYTES,
        canary=resolved_canary,
    )
    return EgressResponseExtractor(
        relay_client=relay_client,
        gate=gate,
        extractor=extractor,
        recorder=recorder,
        response_policy=response_policy,
    )


__all__ = ["build_web_fetch_egress_extractor"]
