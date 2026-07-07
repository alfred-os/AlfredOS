"""Integration: ``build_tool_registry`` — the orchestrator's tool-registry
composition root, driven end-to-end through ``dispatch_tool`` (#339 PR2 Task 7).

Mirrors ``tests/integration/egress/test_web_fetch_assembly.py``'s pattern (real
Postgres ledger via testcontainers, a real loopback ``EgressRelay`` with a faked
upstream, the recorded-LLM-response ``AsyncMock`` extractor double) but drives the
FULL stack ``build_tool_registry`` wires — ``dispatch_tool`` → ``ToolRegistry`` →
``ExternalToolSpec``/``InternalToolSpec`` → ``dispatch_web_fetch`` /
``EgressResponseExtractor`` — rather than exercising the egress extractor alone.

This is the first integration point where the REAL fetch+extract quarantine
chain (``EgressResponseExtractor.handle`` → ``quarantined_to_structured``) runs
UNDER ``dispatch_tool``. ``dispatch_tool``'s own two gate surfaces
(``tool.dispatch`` + ``t3.downgrade_to_orchestrator``, covered by
``tests.helpers.gates.make_tool_dispatch_gate()``) are therefore not the only
grant the shared gate needs — the ONE ``CapabilityGate`` object threaded through
``build_tool_registry`` (reused for both the extractor's gate-first T3→T2
dereference check AND ``dispatch_tool``'s own checks, never a per-tool copy) also
needs the ``quarantine.dereference`` content-T3 grant
(``QuarantinedExtractor._PLUGIN_ID = "alfred.quarantined-llm"``) that
``quarantined_to_structured`` consults before calling the extractor.
``_assembly_gate()`` (``tests/integration/orchestrator/conftest.py`` — #339 PR3
FIX-12 DRY extraction, shared with ``test_act_loop_real_chain.py``) composes
``make_tool_dispatch_gate()``'s two grants with that third grant on a single
real ``RealGate``, never a permissive shim (CLAUDE.md hard rule #2), mirroring
the established composed-gate precedent in
``tests/integration/cli/daemon/test_chat_gateway_socket_turn.py``
(``_boot_gate_with_tui_load_grant``).

``build_tool_registry`` has **test callers only** in PR2 — this integration test
IS the proof of the wiring, not a stand-in for a live caller (PR3 wires the Act
phase; ``test_act_loop_real_chain.py`` is that proof).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.egress.egress_id import TurnEgressContext, compute_egress_id
from alfred.memory.db import session_scope
from alfred.memory.models import AuditEntry, EgressIdempotency
from alfred.orchestrator.builtin_tools import build_web_fetch_tool
from alfred.orchestrator.tool_assembly import build_tool_registry
from alfred.orchestrator.tool_dispatch import dispatch_tool
from alfred.orchestrator.tool_registry import ToolRegistry
from alfred.plugins.web_fetch.allowlist import AllowlistEntry
from alfred.plugins.web_fetch.assembly import build_web_fetch_egress_extractor
from alfred.plugins.web_fetch.fetch_dispatcher import FetchDispatchConfig
from alfred.plugins.web_fetch.handle_cap import HandleCap
from alfred.plugins.web_fetch.rate_limit import RateLimiter
from alfred.providers.base import ToolCall
from alfred.security.dlp import redact_secret_shapes
from alfred.security.quarantine import Extracted, T3DerivedData
from alfred.security.quarantine_transport import QuarantineStagingMap, T3BodyRecorder
from alfred.security.secrets import SecretBroker
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.dlp import identity_outbound_dlp
from tests.helpers.egress_doubles import (
    _FakeClient,
)
from tests.integration.orchestrator.conftest import _assembly_gate, _settings, boot_loopback_relay

pytestmark = pytest.mark.integration

_FAKE_HOST = "safe-upstream.example"
_FAKE_PORT = 443
_FAKE_URL = f"https://{_FAKE_HOST}/api/tool"
_FAKE_ALLOWLIST: frozenset[tuple[str, int]] = frozenset({(_FAKE_HOST, _FAKE_PORT)})
_FORBIDDEN_HOST = "attacker.example.net"
_FORBIDDEN_URL = f"https://{_FORBIDDEN_HOST}/steal"
_FIXED_NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)

# FIX-13/FIX-14 (#339 PR4b-broker Task 6): a benign fixture auth token for the
# authenticated-fetch positive-path test below. Provably NOT shaped like a
# real secret — see the `redact_secret_shapes` pin inside the test — so a
# substituted header carrying it clears the gateway's stage-2 regex re-scan
# instead of being denied `DLP_REDACTED` (spec §7 positive-path residual).
_BENIGN_AUTH_TOKEN: Final[str] = "benign-fixture-token-value"  # noqa: S105 -- fixture value, not a real credential


@pytest.mark.asyncio
async def test_build_tool_registry_end_to_end(
    migrated_url: str,
    redis_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``build_tool_registry`` assembles a working registry over the daemon's
    one quarantine graph; ``dispatch_tool`` drives both tools end-to-end.

    (a) ``reg.definitions()`` advertises both ``web.fetch`` and ``clock.now``.
    (b) An allowlisted ``web.fetch`` call flows all the way to a T2 string (the
        echo-extracted + downgraded + DLP-scanned ``{text, intent}`` JSON).
    (c) The internal ``clock.now`` call returns the injected fixed timestamp.
    (d) An off-allowlist URL refuses with the ``domain_not_allowed`` recoverable
        string + a ``refused`` ``tool.dispatch`` audit row, and the relay is
        NEVER fired for it (the allowlist check runs before the relay fire).
    """
    # --- The daemon's ONE quarantine graph (reused, never re-spawned). --------
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = _assembly_gate()
    extracted = Extracted(
        data=T3DerivedData({"text": "hello from the echo child", "intent": "informational"}),
        extraction_mode="native_constrained",
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=extracted)

    rate_limiter = RateLimiter(redis_url=redis_url)
    handle_cap = HandleCap(redis_url=redis_url)

    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    audit_writer = AuditWriter(session_factory=lambda: session_scope(factory))

    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        operator_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        session_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        manifest_commit_hash="test-commit",
    )

    try:
        async with boot_loopback_relay(allowlist=_FAKE_ALLOWLIST) as (
            _relay,
            port,
            fire_counter,
            _canned,
        ):
            registry = build_tool_registry(
                settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
                gate=gate,
                extractor=mock_extractor,
                recorder=recorder,
                outbound_dlp=identity_outbound_dlp(),
                # This test exercises the registry-assembly wiring, not
                # authenticated fetch — a real, empty-env SecretBroker with
                # the default empty WEB_FETCH_AUTH_SECRET_ALLOWLIST keeps
                # auth entirely out of scope here (#339 PR4b-broker Task 6,
                # FIX-5).
                broker=SecretBroker(env={}),
                audit_writer=audit_writer,
                session_scope=lambda: session_scope(factory),
                rate_limiter=rate_limiter,
                handle_cap=handle_cap,
                config=config,
                now=lambda: _FIXED_NOW,
            )

            # (a) The registry advertises exactly the two builtin tools.
            advertised = {d.name for d in registry.definitions()}
            assert advertised == {"web.fetch", "clock.now"}

            # (b) An allowlisted web.fetch call flows end-to-end to a T2 string.
            ctx_b = TurnEgressContext(adapter_id="ada-b", inbound_id="in-b", session_id="sess-b")
            out_b = await dispatch_tool(
                ToolCall(id="call-b", name="web.fetch", arguments={"url": _FAKE_URL}),
                0,
                ctx=ctx_b,
                registry=registry,
                gate=gate,
                dlp=identity_outbound_dlp(),
                audit=audit_writer,
                user_id="user-1",
                correlation_id="corr-b",
                language="en",
            )
            assert json.loads(out_b) == {
                "text": "hello from the echo child",
                "intent": "informational",
            }
            mock_extractor.extract.assert_awaited_once()
            assert fire_counter.value == 1

            # (c) The internal clock.now call returns the injected fixed timestamp.
            ctx_c = TurnEgressContext(adapter_id="ada-c", inbound_id="in-c", session_id="sess-c")
            out_c = await dispatch_tool(
                ToolCall(id="call-c", name="clock.now", arguments={}),
                0,
                ctx=ctx_c,
                registry=registry,
                gate=gate,
                dlp=identity_outbound_dlp(),
                audit=audit_writer,
                user_id="user-1",
                correlation_id="corr-c",
                language="en",
            )
            assert out_c == _FIXED_NOW.isoformat()

            # (d) An off-allowlist URL refuses recoverably; the relay never fires
            #     for it — the allowlist check runs BEFORE the relay fire (Step 2
            #     precedes Step 4 in dispatch_web_fetch).
            ctx_d = TurnEgressContext(adapter_id="ada-d", inbound_id="in-d", session_id="sess-d")
            out_d = await dispatch_tool(
                ToolCall(id="call-d", name="web.fetch", arguments={"url": _FORBIDDEN_URL}),
                0,
                ctx=ctx_d,
                registry=registry,
                gate=gate,
                dlp=identity_outbound_dlp(),
                audit=audit_writer,
                user_id="user-1",
                correlation_id="corr-d",
                language="en",
            )
            assert "not allowed" in out_d
            # The relay fire count is STILL 1 — the forbidden-domain call never
            # reached the relay.
            assert fire_counter.value == 1

            async with engine.connect() as conn:
                rows = (
                    await conn.execute(
                        sa.select(AuditEntry.result, AuditEntry.subject).where(
                            AuditEntry.trace_id == "corr-d",
                            AuditEntry.event == "tool.dispatch",
                        )
                    )
                ).fetchall()
            assert len(rows) == 1
            assert rows[0].result == "refused"
            assert rows[0].subject["dispatch_outcome"] == "domain_not_allowed"
    finally:
        # CR trivial: guard each close INDEPENDENTLY — a failure in
        # ``rate_limiter.close()`` must not skip ``handle_cap.aclose()`` /
        # ``engine.dispose()`` (nested try/finally mirrors the
        # shutdown/serve_task + engine.dispose() nesting in
        # ``test_web_fetch_assembly.py``).
        try:
            await rate_limiter.close()
        finally:
            try:
                await handle_cap.aclose()
            finally:
                await engine.dispose()


# ---------------------------------------------------------------------------
# FIX-13/FIX-14 (#339 PR4b-broker Task 6) — header-capturing loopback relay
#
# ``boot_loopback_relay`` (conftest.py) defaults to
# ``make_fake_external_world()``'s plain ``_FakeClient`` factory — sufficient
# for every OTHER test in this directory, none of which needs to observe what
# the gateway's upstream client actually received. The authenticated-fetch
# positive-path test below is the one caller that does: it must prove a
# broker-substituted secret survives past the GATEWAY's second-pass DLP
# re-scan (spec §7 residual), not merely past the dispatcher (already
# unit-covered in
# ``test_fetch_dispatcher.py::test_allowlisted_placeholder_substituted_into_wire_headers``).
# ``boot_loopback_relay`` accepts an optional ``wrap_client`` decorator seam
# (#339 PR4b-broker Task-6 review, FIX-B) precisely for this: pass
# ``wrap_client=`` a callable that decorates each freshly-opened
# ``_FakeClient`` instead of hand-rolling a second copy of the
# bind/serve/shutdown dance. ``_HeaderCapturingClient`` below is that
# decorator — a thin wrapper over ``_FakeClient`` (never a reimplementation
# of its body/response/fire-count behaviour) — passed as
# ``boot_loopback_relay(..., wrap_client=...)``.
# ---------------------------------------------------------------------------


class _HeaderCapturingClient:
    """Decorates a ``_FakeClient`` to additionally record the last forwarded
    request's headers into a shared, mutable ``capture`` dict-holder.

    The relay opens a FRESH client per request (``egress_relay.py``'s
    ``_open_client()`` seam) — mirrors the ``_FireCounter`` shared-holder
    pattern in ``tests.helpers.egress_doubles`` rather than a plain instance
    attribute, since a per-instance attribute would not be visible outside
    the (short-lived) client itself.
    """

    def __init__(self, inner: _FakeClient, capture: dict[str, dict[str, str]]) -> None:
        self._inner = inner
        self._capture = capture

    def build_request(
        self, method: str, url: str, *, headers: dict[str, str], content: Any
    ) -> httpx.Request:
        self._capture["headers"] = dict(headers)
        return self._inner.build_request(method, url, headers=headers, content=content)

    async def send(
        self, request: httpx.Request, *, follow_redirects: bool, stream: bool = False
    ) -> Any:
        return await self._inner.send(request, follow_redirects=follow_redirects, stream=stream)

    async def aclose(self) -> None:
        await self._inner.aclose()


@pytest.mark.asyncio
async def test_build_tool_registry_authenticated_fetch_positive_path(
    migrated_url: str,
    redis_url: str,
    authorized_t3_nonce: CapabilityGateNonce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FIX-13/FIX-14 (#339 PR4b-broker Task 6, ADR-0048 §7): a fixture-bound
    ``{{secret:deepseek_api_key}}`` header placeholder is substituted by
    ``SecretBroker.substitute`` and the real value survives past the
    GATEWAY's loopback relay (second-pass DLP re-scan included) to the
    upstream client — proving the end-to-end positive path documented in
    ADR-0048 §7, not just the dispatcher-level substitution the unit tests
    (``test_fetch_dispatcher.py``) already cover in isolation. The stored T2
    ledger row and every audit row for this call carry no secret.

    ``build_tool_registry`` always calls ``build_web_fetch_tool`` with the
    PRODUCTION empty ``WEB_FETCH_AUTH_SECRET_ALLOWLIST`` default (no
    ``auth_secret_allowlist=`` override at that call site — see
    ``tool_assembly.py``) — by design, #339 ships live authenticated fetch
    OFF. This test therefore calls ``build_web_fetch_tool`` directly with a
    FIXTURE allowlist, the same lower-level pattern
    ``test_tool_dispatch_timeout_audit_postgres.py`` uses, rather than going
    through ``build_tool_registry``.
    """
    staging = QuarantineStagingMap()
    recorder = T3BodyRecorder(nonce=authorized_t3_nonce, staging=staging)
    gate = _assembly_gate()
    extracted = Extracted(
        data=T3DerivedData({"text": "hello from the echo child", "intent": "informational"}),
        extraction_mode="native_constrained",
    )
    mock_extractor = AsyncMock()
    mock_extractor.extract = AsyncMock(return_value=extracted)

    rate_limiter = RateLimiter(redis_url=redis_url)
    handle_cap = HandleCap(redis_url=redis_url)

    engine = create_async_engine(migrated_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    audit_writer = AuditWriter(session_factory=lambda: session_scope(factory))

    config = FetchDispatchConfig(
        manifest_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        operator_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        session_allowed_entries=(AllowlistEntry(domain=_FAKE_HOST),),
        manifest_commit_hash="test-commit",
    )

    # The fixture broker provisions ONLY deepseek_api_key, with a value that
    # is provably benign (FIX-14 below) — never a real credential, and never
    # allowlisted in production (the closed WEB_FETCH_AUTH_SECRET_ALLOWLIST
    # ships empty — see auth_allowlist.py).
    broker = SecretBroker(env={"ALFRED_DEEPSEEK_API_KEY": _BENIGN_AUTH_TOKEN})
    fixture_allowlist = frozenset({"deepseek_api_key"})

    correlation_id = "corr-auth-positive"
    ctx = TurnEgressContext(adapter_id="ada-auth", inbound_id="in-auth", session_id="sess-auth")
    egress_id = compute_egress_id(ctx, call_index=0)

    capture: dict[str, dict[str, str]] = {}

    def _wrap_capturing(client: _FakeClient) -> _HeaderCapturingClient:
        return _HeaderCapturingClient(client, capture)

    try:
        async with boot_loopback_relay(allowlist=_FAKE_ALLOWLIST, wrap_client=_wrap_capturing) as (
            _relay,
            port,
            fire_counter,
            _canned,
        ):
            web_fetch_extractor = build_web_fetch_egress_extractor(
                settings=_settings(monkeypatch, relay_url=f"tcp://127.0.0.1:{port}"),
                gate=gate,
                extractor=mock_extractor,
                recorder=recorder,
                outbound_dlp=identity_outbound_dlp(),
                audit_writer=audit_writer,
                session_scope=lambda: session_scope(factory),
            )
            spec = build_web_fetch_tool(
                extractor=web_fetch_extractor,
                config=config,
                rate_limiter=rate_limiter,
                handle_cap=handle_cap,
                outbound_dlp=identity_outbound_dlp(),
                broker=broker,
                auth_secret_allowlist=fixture_allowlist,
                audit=audit_writer,
            )
            registry = ToolRegistry([spec])

            out = await dispatch_tool(
                ToolCall(
                    id="call-auth",
                    name="web.fetch",
                    arguments={
                        "url": _FAKE_URL,
                        "headers": {"Authorization": "Bearer {{secret:deepseek_api_key}}"},
                    },
                ),
                0,
                ctx=ctx,
                registry=registry,
                gate=gate,
                dlp=identity_outbound_dlp(),
                audit=audit_writer,
                user_id="user-auth",
                correlation_id=correlation_id,
                language="en",
            )

            # The fetch succeeded end-to-end (not refused) — the planner got
            # the extracted {text, intent} JSON, same shape as the
            # unauthenticated positive path in
            # test_build_tool_registry_end_to_end above.
            assert json.loads(out) == {
                "text": "hello from the echo child",
                "intent": "informational",
            }
            assert fire_counter.value == 1
            mock_extractor.extract.assert_awaited_once()

            # --- §7 positive-path proof: the SUBSTITUTED header reached the
            #     loopback upstream, past BOTH the core dispatcher AND the
            #     gateway's second-pass DLP re-scan. --------------------------
            substituted_header_value = f"Bearer {_BENIGN_AUTH_TOKEN}"
            assert "headers" in capture
            assert capture["headers"]["Authorization"] == substituted_header_value

            # FIX-14: pin that the benign fixture token does NOT match the
            # gateway's stage-2 generic-API-key-shape regex — the exact
            # `redact_secret_shapes` regex `OutboundDlp` runs identically at
            # the gateway (`broker=None`, spec §7). Had this pin failed, the
            # substituted header above would have been denied (DLP_REDACTED)
            # rather than forwarded, and `fire_counter.value == 1` above
            # would never have been reached.
            assert redact_secret_shapes(substituted_header_value) == substituted_header_value

        # --- FIX-13 scan-mechanics sanity check (strengthened, Task-6 review) --
        # The GENUINE end-to-end secret-handling proof is the header-capture
        # assertion above (`capture["headers"]["Authorization"]` — §7
        # positive path). `AuditEntry.subject` and `EgressIdempotency.response`
        # are a closed, header-free field set by construction (see the module
        # note above `_HeaderCapturingClient`), so the two `not in` absence
        # assertions below CANNOT observe a substitution regression — they
        # would pass even if `SecretBroker.substitute` leaked the real header
        # value elsewhere. What they CAN catch is a schema change that starts
        # smuggling header content into the audit subject or the ledger
        # response. This block proves the two absence checks are at least
        # capable of firing for that failure mode: it re-applies the IDENTICAL
        # `json.dumps(...)` / bare `in` scan expressions used below, over
        # synthetic data shaped like the real inputs but with the token
        # planted, and asserts each scan finds it.
        _planted_subject_rows: list[dict[str, str]] = [{"planted_for_control": _BENIGN_AUTH_TOKEN}]
        assert _BENIGN_AUTH_TOKEN in json.dumps(_planted_subject_rows)
        _planted_ledger_response = f"prefix-{_BENIGN_AUTH_TOKEN}-suffix"
        assert _BENIGN_AUTH_TOKEN in _planted_ledger_response

        async with engine.connect() as conn:
            audit_rows = (
                await conn.execute(
                    sa.select(AuditEntry.subject).where(AuditEntry.trace_id == correlation_id)
                )
            ).fetchall()
            ledger_response = (
                await conn.execute(
                    sa.select(EgressIdempotency.response).where(
                        EgressIdempotency.egress_id == egress_id
                    )
                )
            ).scalar_one()
        # Sanity: the query above found rows worth scanning — an empty result
        # would make the absence assertions below vacuous.
        assert audit_rows
        assert _BENIGN_AUTH_TOKEN not in json.dumps([dict(row.subject) for row in audit_rows])
        assert ledger_response is not None
        assert _BENIGN_AUTH_TOKEN not in ledger_response
    finally:
        # CR trivial: guard each close INDEPENDENTLY — see the sibling
        # test's identical rationale above.
        try:
            await rate_limiter.close()
        finally:
            try:
                await handle_cap.aclose()
            finally:
                await engine.dispose()
