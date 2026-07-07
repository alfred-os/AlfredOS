"""Adversarial wiring-smoke for the ``cap-2026-006`` corpus payload.

The threat (epic §11, arch-002/test-003/sec-006, moved into #339 PR2): a
recorded planner emits a ``web.fetch`` tool call whose ``url`` argument
targets an attacker-chosen host OUTSIDE the three-way allowlist, betting
``dispatch_tool`` forwards the request to the gateway egress relay
unchecked. Tool-argument injection is the classic "the model is not the
security boundary" shape (OWASP LLM01): even if a persona was coerced via
indirect prompt injection into requesting the off-list URL, the TOOL LAYER —
not the model — must refuse it (CLAUDE.md hard rule #5: the privileged
orchestrator never sees raw T3 content, and #339's ``dispatch_tool``
chokepoint is exactly the tool-layer perimeter).

The defense under test is the REAL
:class:`alfred.plugins.web_fetch.allowlist.AllowlistIntersection` three-way
check inside :func:`alfred.plugins.web_fetch.fetch_dispatcher.dispatch_web_fetch`
(spec §7.4, step 2): the effective allowlist built for this test covers ONLY
``safe.example.com`` across all three tiers (manifest/operator/session), so
``attacker.example.net`` is refused at every tier. ``dispatch_web_fetch``
raises :class:`~alfred.plugins.web_fetch.errors.WebFetchDomainNotAllowed`
BEFORE the per-domain rate limiter (step 3) or the egress extractor's relay
fire (step 4) ever run. ``dispatch_tool``'s own
``except WebFetchDomainNotAllowed:`` arm catches it, writes the
``domain_not_allowed``/``refused`` ``tool.dispatch`` audit row, and returns
the benign, closed-vocabulary ``orchestrator.tool.domain_not_allowed`` string
to the planner — the attacker-chosen URL is never fetched and never echoed
back.

The test drives the REAL production
:class:`~alfred.orchestrator.tool_registry.ToolRegistry` built over
:func:`~alfred.orchestrator.builtin_tools.build_web_fetch_tool`, a REAL
:class:`~alfred.plugins.web_fetch.fetch_dispatcher.FetchDispatchConfig` /
``AllowlistIntersection``, and the composed :func:`tests.helpers.gates.make_tool_dispatch_gate`
``RealGate`` fixture — NEVER a permissive shim (CLAUDE.md hard rule #2). The
allowlist refusal fires PRE-egress (spec §7.4 step 2 precedes step 4's relay
fire), so a fire-spy extractor/rate-limiter that raise on any call is enough
to prove the fetch never reaches the gateway relay — no Postgres/Redis
testcontainers needed for this assertion. Mirrors scenario (d) of the fuller
integration proof in
``tests/integration/orchestrator/test_tool_assembly.py::test_build_tool_registry_end_to_end``,
but as a fast, dependency-free adversarial runner.
"""

from __future__ import annotations

from typing import Final

import pytest

from alfred.audit.audit_row_schemas import TOOL_DISPATCH_FIELDS
from alfred.egress.egress_id import TurnEgressContext
from alfred.i18n import t
from alfred.orchestrator.builtin_tools import build_web_fetch_tool
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.providers.base import ToolCall
from alfred.security.secrets import SecretBroker
from tests.adversarial.capability_bypass._tool_arg_injection_doubles import (
    RateLimiterNeverConsulted,
    RelayNeverFiresExtractor,
    SpyHandleCap,
)
from tests.adversarial.payload_schema import AdversarialPayload
from tests.helpers.dlp import identity_outbound_dlp
from tests.helpers.egress_doubles import _CapturingAuditWriter
from tests.helpers.gates import make_tool_dispatch_gate

_PAYLOAD_ID: Final[str] = "cap-2026-006"

# The attacker-chosen URL the payload pins, and the ONE domain the effective
# allowlist permits (identical entry across manifest/operator/session —
# the attacker host is outside it at every tier, so no broadening-cap event
# fires; the refusal below is a genuine containment verdict).
_ATTACKER_URL: Final[str] = "https://attacker.example.net/exfil"
_SAFE_DOMAIN: Final[str] = "safe.example.com"

_CTX: Final[TurnEgressContext] = TurnEgressContext(
    adapter_id="cap-2026-006", inbound_id="planner-turn", session_id="corpus-session"
)


@pytest.fixture
def tool_arg_injection_payload(
    corpus_payloads: tuple[AdversarialPayload, ...],
) -> AdversarialPayload:
    """Filter the session-scoped corpus to this wiring-smoke payload.

    Fails loudly if the payload is missing/duplicated so a future rename or
    delete surfaces here (the drift-guard pattern shared across the corpus;
    mirrors ``cap-2026-005``'s ``sink_containment_payload`` fixture).
    """
    matches = [p for p in corpus_payloads if p.id == _PAYLOAD_ID]
    if not matches:
        msg = (
            f"adversarial corpus is missing payload id={_PAYLOAD_ID!r}; expected at "
            "tests/adversarial/capability_bypass/"
            "cap-2026-006-tool-arg-injection-offlist-url-refused.yaml"
        )
        raise pytest.UsageError(msg)
    if len(matches) != 1:
        msg = (
            f"adversarial corpus has {len(matches)} entries for id={_PAYLOAD_ID!r}; "
            "expected exactly one. Corpus IDs must be unique — fix the duplicate."
        )
        raise pytest.UsageError(msg)
    return matches[0]


async def test_tool_arg_injection_offlist_url_refused(
    tool_arg_injection_payload: AdversarialPayload,
) -> None:
    """A planner-emitted ``web.fetch`` call targeting an off-allowlist
    attacker URL is REFUSED by the REAL three-way allowlist — never
    dispatched, never fetched, never relayed."""
    payload_fields = tool_arg_injection_payload.payload
    assert isinstance(payload_fields, dict)
    tool_call_fields = payload_fields["tool_call"]
    assert isinstance(tool_call_fields, dict)
    assert tool_call_fields["name"] == "web.fetch"
    arguments = tool_call_fields["arguments"]
    assert isinstance(arguments, dict)
    assert arguments["url"] == _ATTACKER_URL
    assert tool_arg_injection_payload.expected_outcome == "refused"

    # Real per-session config: the effective allowlist covers ONLY
    # `safe.example.com` across all three tiers — `attacker.example.net` is
    # outside it at every tier, so the intersection refuses.
    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        operator_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        session_allowed_entries=(AllowlistEntry(domain=_SAFE_DOMAIN),),
        manifest_commit_hash="test-commit",
    )
    writer = _CapturingAuditWriter()
    # This test exercises the three-way domain allowlist, not authenticated
    # fetch — a real, empty-env SecretBroker with the default empty
    # WEB_FETCH_AUTH_SECRET_ALLOWLIST keeps auth entirely out of scope here
    # (#339 PR4b-broker Task 6, FIX-5).
    web_fetch_spec = build_web_fetch_tool(
        extractor=RelayNeverFiresExtractor(),  # type: ignore[arg-type]
        config=config,
        rate_limiter=RateLimiterNeverConsulted(),  # type: ignore[arg-type]
        handle_cap=SpyHandleCap(),  # type: ignore[arg-type]
        outbound_dlp=identity_outbound_dlp(),
        broker=SecretBroker(env={}),
        audit=writer,  # type: ignore[arg-type]
    )
    registry = ToolRegistry([web_fetch_spec])

    call = ToolCall(id=_PAYLOAD_ID, name="web.fetch", arguments=dict(arguments))
    out = await dispatch_tool(
        call,
        0,
        ctx=_CTX,
        registry=registry,
        gate=make_tool_dispatch_gate(),
        dlp=identity_outbound_dlp(),
        audit=writer,  # type: ignore[arg-type]
        user_id="attacker-controlled-planner-turn",
        correlation_id="corr-cap-2026-006",
        language="en",
    )

    # The planner receives ONLY the benign, closed-vocabulary refusal string —
    # never the raw attacker URL echoed back, never any fetched content.
    assert out == t("orchestrator.tool.domain_not_allowed", tool="web.fetch")

    # Exactly one `tool.dispatch` audit row records the refusal (the sibling
    # `tool.web.fetch` row `dispatch_web_fetch` itself writes carries a
    # different `schema_name` — filtering keeps this assertion robust to
    # audit-row ordering rather than indexing `rows[-1]`).
    dispatch_rows = [row for row in writer.rows if row.get("schema_name") == "TOOL_DISPATCH_FIELDS"]
    assert len(dispatch_rows) == 1
    dispatch_row = dispatch_rows[0]
    assert dispatch_row["subject"]["dispatch_outcome"] == "domain_not_allowed"
    assert dispatch_row["result"] == "refused"
    assert set(dispatch_row["subject"].keys()) == set(TOOL_DISPATCH_FIELDS)
