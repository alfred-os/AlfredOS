"""#338 PR2 Task 5 — RELEASE-BLOCKING boundary proof for ``RealTurnOrchestratorAdapter``.

Drives the REAL daemon comms boot graph (:func:`_build_comms_boot_graph`, Task 3's
construction path) over a REAL Postgres testcontainer + the REAL echo quarantine
child, calling :func:`process_inbound_message` DIRECTLY (mirroring the A2-closer
pattern in ``tests/integration/comms/test_forwarded_poison_ceiling_postgres.py`` —
proving the boundary COMPOSITION, not the wire) so every test in this module
exercises the genuine ``ingest -> dispatch`` translator over a real
``RealGate`` / real ``AuditWriter`` / real ``WorkingMemoryPool`` / real
``BurstLimiter``, with only the router (``FixedAnswerRouter``/subclasses,
CLAUDE.md's egress-proxy exemption for tests) and the quarantined-child transport
substituted (no bwrap on this host — mirrors every sibling integration test in this
tree).

Why a DIFFERENT quarantine-child double than ``_EchoingChildDouble``
----------------------------------------------------------------------
Every other integration proof in this repo uses an ``_EchoingChildDouble`` that
echoes the WHOLE staged T3 context verbatim into the extracted ``text`` field —
correct for those tests (their bodies carry only recognized keys), but WRONG for
the HARD#5 provenance proof below: FOLD-7's whole-request-scan false-fail warning
is exactly this — "the echo child makes extracted T2 text == the raw T3 body
byte-for-byte". A verbatim echo would leak a marker planted in ANY raw body key
straight into ``text``, making the "the schema drops framing keys" property
untestable. ``_ExtractionAwareChildDouble`` below instead performs the SAME
schema-shaped extraction (``CommsBodyExtraction{text, intent}``) a real
quarantined LLM does: it round-trips the staged JSON context and projects ONLY
the recognized ``text`` field, dropping any other body key — so a marker
stuffed into a framing key genuinely never survives extraction, and the
provenance test proves something real instead of a fixture tautology.

Layer boundary (CLAUDE.md "pick the lowest layer that proves the property")
------------------------------------------------------------------------------
Unit tests (``test_real_turn_adapter_ingest.py`` / ``test_real_turn_adapter_dispatch.py``,
Tasks 1-2) already pin every individual branch of the translator with fakes; they
supply the 100% branch-coverage floor. This module supplies what unit tests
structurally cannot: real-gate-checked-downgrade ordering against a real audit
log, real Postgres-backed idempotency/attempt-store composition under a crash
injection, and a genuine concurrent-asyncio-task race against the real
``WorkingMemoryPool`` (the FOLD-R1 Critical's non-vacuous proof).
"""

from __future__ import annotations

import asyncio
import itertools
import json
import struct
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker

from alfred.audit.log import AuditWriter
from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.cli.daemon._commands import (
    _build_boot_outbound_dlp,
    _build_comms_boot_graph,
    _CommsBootGraph,
    build_boot_session_scope,
)
from alfred.comms_mcp.inbound import _FORWARDED_DISPATCH_ATTEMPT_CEILING, process_inbound_message
from alfred.comms_mcp.protocol import InboundMessageNotification
from alfred.comms_mcp.real_turn_adapter import _PERSONA
from alfred.config.settings import Settings
from alfred.hooks.boot import install_boot_hook_registry
from alfred.hooks.registry import get_registry, set_registry
from alfred.i18n import t
from alfred.identity.models import Authorization, Platform, PlatformIdentity, User
from alfred.memory.forwarded_dispatch_attempts import PostgresForwardedDispatchAttemptStore
from alfred.memory.hooks_audit_sink import EpisodicAuditSink
from alfred.memory.inbound_idempotency import PostgresInboundIdempotencyStore
from alfred.memory.models import Base
from alfred.orchestrator.core import _ALFRED_PERSONA_ID
from alfred.providers.base import CompletionRequest, CompletionResponse
from alfred.providers.router import ProviderRouter
from alfred.security import tiers as _tiers
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import _make_in_memory_backend, _make_no_op_audit_sink
from tests.helpers.routers import FixedAnswerRouter

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Fixed identity constants (discriminating values so a dropped field surfaces
# as the wrong canonical id / an empty transcript rather than passing by luck).
# ---------------------------------------------------------------------------
_ADAPTER_ID = "alfred_comms_test"  # empty required-classifier set -> no promoter needed
_OPERATOR_SLUG = "the-operator"
_ALICE_SLUG = "alice"
_ALICE_PLATFORM_ID = "discord:alice-9931"
_ALICE_LANGUAGE = "en-GB"
_BOB_SLUG = "bob"
_BOB_PLATFORM_ID = "discord:bob-4471"
_BOB_LANGUAGE = "en-US"

_AUDIT_HASH_PEPPER = "integration-test-pepper-0123456789abcdef-padding"
_TIMEOUT_S = 15.0

# A high-entropy, plainly-synthetic marker for the HARD#5 provenance proof.
_MARKER = "HARD5-PROVENANCE-MARKER-do-not-reach-planner-9f3ac1e0"


# ---------------------------------------------------------------------------
# Quarantine-child double — schema-shaped extraction (see module docstring).
# ---------------------------------------------------------------------------


class _ExtractionAwareChildDouble:
    """In-proc quarantine-child double that performs REAL schema-shaped extraction.

    On ``quarantine.ingest`` it stashes the staged JSON context; on
    ``quarantine.extract`` it PARSES that JSON and projects ONLY the
    ``CommsBodyExtraction``-recognized ``text`` key into the extracted result —
    any other raw body key (e.g. an attacker-injected framing field) is dropped,
    never copied into ``text``/``intent``. A body carrying ``__force_refusal__``
    makes it return a ``typed_refusal`` instead (the error-leg tests' escape
    hatch) — mirrors what a real quarantined LLM does when it cannot make sense
    of malformed/adversarial input.
    """

    def __init__(self, *, provider_key: str) -> None:
        self.provider_key = provider_key
        self._ingested: dict[str, str] = {}
        self._reply: bytes | None = None

    def write_frame(self, frame: bytes) -> None:
        length = struct.unpack(">I", frame[:4])[0]
        obj = json.loads(frame[4 : 4 + length])
        method, params = obj["method"], obj["params"]
        if method == "quarantine.ingest":
            self._ingested[params["handle_id"]] = params["context"]
        elif method == "quarantine.extract":
            try:
                context = self._ingested.pop(params["handle_id"])
            except KeyError as exc:  # pragma: no cover - defensive; a mismatch fails the test
                raise AssertionError(
                    f"unexpected quarantine handle_id {params['handle_id']!r}"
                ) from exc
            parsed = json.loads(context)
            if isinstance(parsed, dict) and parsed.get("__force_refusal__"):
                result: dict[str, object] = {"kind": "typed_refusal", "reason": "cannot_extract"}
            else:
                extracted_text = parsed.get("text", "") if isinstance(parsed, dict) else str(parsed)
                result = {
                    "kind": "extracted",
                    "data": {"text": extracted_text, "intent": "test_intent"},
                    "extraction_mode": "native_constrained",
                }
            body = json.dumps({"jsonrpc": "2.0", "result": result}).encode("utf-8")
            self._reply = struct.pack(">I", len(body)) + body

    async def read_frame(self) -> bytes:
        assert self._reply is not None
        reply, self._reply = self._reply, None
        return reply

    async def aclose(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Outbound sender doubles.
# ---------------------------------------------------------------------------


class _RecordingSender:
    def __init__(self) -> None:
        self.sent: list[Any] = []

    async def send_outbound(self, request: Any) -> dict[str, object]:
        self.sent.append(request)
        return {}


class _FlakyOnceSender:
    """Fails the FIRST ``send_outbound`` call, then delegates to ``inner``.

    The crash-injection seam for the FOLD-R6 bounded-residual resume test — a
    transport blip on the outbound leg, not a T3/security fault.
    """

    def __init__(self, inner: _RecordingSender) -> None:
        self._inner = inner
        self._failed_once = False
        self.call_count = 0

    async def send_outbound(self, request: Any) -> dict[str, object]:
        self.call_count += 1
        if not self._failed_once:
            self._failed_once = True
            raise ConnectionError("simulated crash-injection: outbound send failed")
        return await self._inner.send_outbound(request)


class _RaisingSender:
    """Always raises — the FOLD-5 ``send_failed`` integration leg."""

    async def send_outbound(self, request: Any) -> dict[str, object]:
        raise ConnectionError("simulated wire failure")


# ---------------------------------------------------------------------------
# Ordinal-tracking doubles (HARD#5 FOLD-R4a ordering proof).
# ---------------------------------------------------------------------------


class _CapturingRouter(FixedAnswerRouter):
    """``FixedAnswerRouter`` that also stamps each ``complete`` with a shared ordinal."""

    def __init__(self, *, counter: itertools.count[int], order: list[tuple[int, str]]) -> None:
        super().__init__(answer="scripted-answer")
        self._counter = counter
        self._order = order

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self._order.append((next(self._counter), "planner.complete"))
        return await super().complete(request)


class _OrderTrackingAuditWriter:
    """Delegates to a REAL ``AuditWriter`` while stamping every write with a shared ordinal.

    Lets the HARD#5 test prove the downgrade receipt was written strictly BEFORE
    the first planner call — a structural ordering fact, not a clock-resolution
    guess (real Postgres ``created_at`` timestamps are not fine-grained enough to
    trust for this).
    """

    def __init__(
        self, inner: AuditWriter, *, counter: itertools.count[int], order: list[tuple[int, str]]
    ) -> None:
        self._inner = inner
        self._counter = counter
        self._order = order

    async def append_schema(self, **kwargs: Any) -> None:
        self._order.append((next(self._counter), str(kwargs.get("event", ""))))
        await self._inner.append_schema(**kwargs)

    async def append(self, **kwargs: Any) -> None:
        self._order.append((next(self._counter), str(kwargs.get("event", ""))))
        await self._inner.append(**kwargs)


# ---------------------------------------------------------------------------
# Gate / seeding / boot-audit-writer helpers (mirrors the Task 3 + sibling
# daemon-boot integration tests' pattern).
# ---------------------------------------------------------------------------


def _boot_gate(*, grant_downgrade: bool) -> RealGate:
    """A REAL RealGate (CLAUDE.md hard rule #2 — never a permissive shim).

    Always grants the system-tier ``security.quarantined.extract`` chain (the
    QuarantinedExtractor's post-stage DLP subscriber needs it to register);
    ``grant_downgrade`` toggles the ``t3.downgrade_to_orchestrator`` grant this
    adapter's ``ingest`` checks on every turn — ``False`` exercises the
    downgrade-deny refusal leg.
    """
    grants = {
        GrantRow(
            plugin_id="alfred.security._extract_dlp_subscriber",
            subscriber_tier="system",
            hookpoint="security.quarantined.extract",
            content_tier=None,
            proposal_branch="test-fixture",
        ),
    }
    if grant_downgrade:
        grants.add(
            GrantRow(
                plugin_id="t3.downgrade_to_orchestrator",
                subscriber_tier="system",
                hookpoint="t3.downgrade_to_orchestrator",
                content_tier="T3",
                proposal_branch="test-fixture",
            )
        )
    frozen = frozenset(grants)
    return RealGate(
        policy=GatePolicy(grants=frozen),
        backend=_make_in_memory_backend(grants=frozen),
        audit_sink=_make_no_op_audit_sink(),
    )


def _seed_users(sync_url: str) -> None:
    """Seed the operator (required by ``Orchestrator.__init__``) + two bound users.

    Alice/Bob are DISTINCT canonical users bound under DISTINCT Discord platform
    ids so the concurrent-turn tests can drive genuinely independent identities.
    """
    sync_engine = create_engine(sync_url, future=True)
    try:
        sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)
        with sync_factory.begin() as session:
            session.add(
                User(
                    slug=_OPERATOR_SLUG,
                    display_name=_OPERATOR_SLUG,
                    authorization=Authorization.OPERATOR.value,
                    daily_budget_usd=5.0,
                    language="en-US",
                )
            )
            alice = User(
                slug=_ALICE_SLUG,
                display_name="Alice",
                authorization=Authorization.STANDARD.value,
                daily_budget_usd=5.0,
                language=_ALICE_LANGUAGE,
            )
            session.add(alice)
            session.flush()
            session.add(
                PlatformIdentity(
                    user_id=alice.id,
                    platform=Platform.DISCORD.value,
                    platform_id=_ALICE_PLATFORM_ID,
                )
            )
            bob = User(
                slug=_BOB_SLUG,
                display_name="Bob",
                authorization=Authorization.STANDARD.value,
                daily_budget_usd=5.0,
                language=_BOB_LANGUAGE,
            )
            session.add(bob)
            session.flush()
            session.add(
                PlatformIdentity(
                    user_id=bob.id, platform=Platform.DISCORD.value, platform_id=_BOB_PLATFORM_ID
                )
            )
    finally:
        sync_engine.dispose()


@asynccontextmanager
async def _boot_audit_writer(postgres_url: str) -> AsyncIterator[AuditWriter]:
    """Create the schema, seed users, and yield a real Postgres ``AuditWriter``."""
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
        _seed_users(sync_url)

        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        yield AuditWriter(session_factory=session_scope)
    finally:
        await engine.dispose()


def _fetch_audit_rows(sync_url: str, *, event: str) -> list[dict[str, Any]]:
    engine = create_engine(sync_url, future=True)
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text(
                    "SELECT subject, trace_id, actor_user_id, trust_tier_of_trigger, result, "
                    "cost_actual_usd FROM audit_log WHERE event = :event ORDER BY created_at"
                ),
                {"event": event},
            )
            return [dict(row._mapping) for row in result]
    finally:
        engine.dispose()


def _all_message_text(request: CompletionRequest) -> str:
    """Concatenate every message's content (system prompt + history) for a scan."""
    return "\n".join(m.content for m in request.messages)


# ---------------------------------------------------------------------------
# The real stack.
# ---------------------------------------------------------------------------


@dataclass
class _RealStack:
    graph: _CommsBootGraph
    settings: Settings
    sync_url: str
    audit: _OrderTrackingAuditWriter
    order: list[tuple[int, str]]
    sender: _RecordingSender
    captured_router: FixedAnswerRouter

    async def send_inbound(
        self,
        *,
        body: Mapping[str, object],
        platform_user_id: str = _ALICE_PLATFORM_ID,
        inbound_id: str | None = None,
        commit_at_dispatch_edge: bool = False,
        idempotency_store: PostgresInboundIdempotencyStore | None = None,
        attempt_store: PostgresForwardedDispatchAttemptStore | None = None,
    ) -> None:
        # Identity is resolved host-side from platform_user_id — there is no
        # canonical_user_id input to this seam (CR-cloud, #338 PR2 review: the
        # prior `canonical_user_id: str = _ALICE_SLUG` param was immediately
        # `del`'d and could silently mislead a future caller passing a
        # mismatched value with no error).
        notification = InboundMessageNotification(
            adapter_id=_ADAPTER_ID,
            inbound_id=inbound_id or uuid.uuid4().hex,
            platform_user_id=platform_user_id,
            body=body,
            sub_payload_refs=(),
            received_at=datetime.now(UTC),
            addressing_signal="dm",
        )
        await process_inbound_message(
            notification,
            identity_resolver=self.graph.resolver_bridge,  # type: ignore[arg-type]
            orchestrator=self.graph.inbound_orchestrator,
            burst_limiter=self.graph.burst_limiter,  # type: ignore[arg-type]
            audit_writer=self.audit,  # type: ignore[arg-type]
            secret_broker=self.graph.secret_broker,  # type: ignore[arg-type]
            commit_at_dispatch_edge=commit_at_dispatch_edge,
            idempotency_store=idempotency_store,
            attempt_store=attempt_store,
        )

    def audit_rows(self, *, event: str) -> list[dict[str, Any]]:
        return _fetch_audit_rows(self.sync_url, event=event)

    def downgrade_preceded_first_planner_request(self) -> bool:
        downgrade_ordinals = sorted(
            o for o, e in self.order if e == "quarantine.t3_derived_downgrade"
        )
        planner_ordinals = sorted(o for o, e in self.order if e == "planner.complete")
        assert downgrade_ordinals, "downgrade receipt never recorded — ordering assertion vacuous"
        assert planner_ordinals, "planner never called — ordering assertion vacuous"
        return downgrade_ordinals[0] < planner_ordinals[0]


@asynccontextmanager
async def _boot_stack(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    grant_downgrade: bool = True,
    router: FixedAnswerRouter | None = None,
) -> AsyncIterator[_RealStack]:
    """Assemble the REAL comms boot graph over a REAL Postgres testcontainer.

    Mirrors ``test_comms_boot_graph_real_turn.py`` (Task 3) + the sibling
    daemon-boot integration tests' env/gate/nonce/registry choreography, but
    calls ``process_inbound_message`` DIRECTLY rather than driving a launcher-
    spawned plugin or a socket carrier — this module's property is the
    BOUNDARY TRANSLATOR's composition with real infra, not the wire (that is
    the sibling tests' job).
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_ENV", "test")
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "not-a-real-secret-integration-placeholder")
    monkeypatch.setenv("ALFRED_AUDIT.HASH_PEPPER", _AUDIT_HASH_PEPPER)

    settings = Settings()  # type: ignore[no-untyped-call]  # env-driven; mirrors daemon boot
    sync_url = postgres_url.replace("+asyncpg", "+psycopg2")

    prior_registry = get_registry()
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE
    gate = _boot_gate(grant_downgrade=grant_downgrade)
    graph: _CommsBootGraph | None = None

    try:
        async with _boot_audit_writer(postgres_url) as raw_audit:
            install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=raw_audit))
            outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=raw_audit)
            with _NONCE_LOCK:
                nonce = CapabilityGateNonce()
                _tiers._set_authorized_t3_nonce(nonce)

            async def _fake_spawn(*, provider_key: str) -> _ExtractionAwareChildDouble:
                return _ExtractionAwareChildDouble(provider_key=provider_key)

            monkeypatch.setattr(
                "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
            )

            order: list[tuple[int, str]] = []
            counter = itertools.count()
            tracked_audit = _OrderTrackingAuditWriter(raw_audit, counter=counter, order=order)
            captured_router = (
                router if router is not None else _CapturingRouter(counter=counter, order=order)
            )

            graph = await _build_comms_boot_graph(
                settings=settings,
                audit=cast(AuditWriter, tracked_audit),
                outbound_dlp=outbound_dlp,
                t3_nonce=nonce,
                policies_ref=None,
                real_gate=gate,
                router_override=cast(ProviderRouter, captured_router),
            )
            sender = _RecordingSender()
            graph.inbound_orchestrator.bind_outbound_sender(sender)

            yield _RealStack(
                graph=graph,
                settings=settings,
                sync_url=sync_url,
                audit=tracked_audit,
                order=order,
                sender=sender,
                captured_router=captured_router,
            )
    finally:
        if graph is not None:
            await graph.aclose()
        set_registry(prior_registry)
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(prior_nonce)


# ---------------------------------------------------------------------------
# Step 1: HARD#5 provenance test (FOLD-7 / FOLD-R4a — release-blocking).
# ---------------------------------------------------------------------------


async def test_privileged_prompt_arrives_only_through_the_gate_checked_downgrade(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A marker in a schema-dropped framing field never reaches the planner.

    NOT a body-scan (FOLD-7): the echo-style child would make extracted
    ``text`` == the raw T3 body byte-for-byte, so scanning the whole request
    for the marker's ABSENCE would false-fail against any double that just
    echoes the whole context. Instead this asserts (a) the gate-checked
    downgrade receipt fired, (b) the planner was genuinely called (a
    non-vacuous guard — the PR4c/FIX-11 lesson), (c) the receipt precedes the
    first planner request (structural ordering, not a body scan), and (d) the
    marker — planted in ``__injected_frame__``, a key
    ``CommsBodyExtraction`` does not surface — never appears in ANY captured
    planner request.
    """
    async with _boot_stack(postgres_url, monkeypatch) as stack:
        await stack.send_inbound(body={"text": "hi", "__injected_frame__": _MARKER})

        # (a) the downgrade receipt fired with downgrade_explicit=True.
        downgrade = stack.audit_rows(event="quarantine.t3_derived_downgrade")
        assert len(downgrade) == 1
        assert downgrade[0]["subject"]["downgrade_explicit"] is True

        # FOLD-R4 non-vacuous guard: the planner MUST have been called.
        assert stack.captured_router.requests, "planner never called — provenance assertion vacuous"

        # FOLD-R4a ordering: the downgrade receipt precedes the first planner call.
        assert stack.downgrade_preceded_first_planner_request()

        # (d) the marker never reached the planner — dropped by the extraction schema.
        for req in stack.captured_router.requests:
            assert _MARKER not in _all_message_text(req)


# ---------------------------------------------------------------------------
# Step 2: cost-model shape (FOLD-R17).
# ---------------------------------------------------------------------------


async def test_orchestrator_turn_row_carries_turn_total_and_terminal_cost_shape(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``subject.turn_cost_usd`` is the turn total; ``cost_actual_usd`` is the terminal field.

    FOLD-R17: with the empty-registry single completion the two are numerically
    EQUAL this slice — that is expected, not a bug. This pins the SHAPE (both
    fields present, correctly named) as the schema/semantics contract, not a
    numeric discriminator.
    """
    async with _boot_stack(postgres_url, monkeypatch) as stack:
        await stack.send_inbound(body={"text": "hello there"})

        rows = stack.audit_rows(event="orchestrator.turn")
        assert len(rows) == 1, rows
        row = rows[0]
        subject = row["subject"]
        assert "turn_cost_usd" in subject
        assert isinstance(subject["turn_cost_usd"], int | float)
        assert row["cost_actual_usd"] is not None
        # Single-completion turn: numerically equal by construction this slice
        # (FOLD-R17) — asserted as an equality PIN, not an inequality.
        assert subject["turn_cost_usd"] == pytest.approx(row["cost_actual_usd"])


# ---------------------------------------------------------------------------
# Step 3: bounded-residual resume (FOLD-R6).
# ---------------------------------------------------------------------------


async def test_forwarded_crash_injection_replays_exactly_twice_with_bounded_residual(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FORWARDED path: one outbound-send failure replays the turn EXACTLY twice.

    FOLD-R6 (DECISION CLOSED): the residual is bounded by the POISON CEILING
    (5, ``inbound.py:201``) IN GENERAL — not "at most twice" — a single
    injected failure happens to produce exactly two runs, but the general
    bound this same ledger enforces is the ceiling. The in-process working-
    memory deque is NOT rolled back on the failed first attempt — asserted
    directly (the un-rolled-back double-append this fold accepts as a bounded,
    self-healing residual, not silently swept under the rug).
    """
    async with _boot_stack(postgres_url, monkeypatch) as stack:
        flaky_sender = _FlakyOnceSender(stack.sender)
        stack.graph.inbound_orchestrator.bind_outbound_sender(flaky_sender)

        idempotency_store = stack.graph.idempotency_store
        attempt_store = PostgresForwardedDispatchAttemptStore(
            session_scope=build_boot_session_scope(stack.settings)
        )
        inbound_id = f"resume-{uuid.uuid4().hex}"

        # First delivery: dispatch runs the real turn, then the send fails —
        # process_inbound_message's forwarded-edge try/except audits
        # dispatch_failed and RE-RAISES; the frame is NOT committed.
        with pytest.raises(ConnectionError):
            await stack.send_inbound(
                body={"text": "resume me"},
                inbound_id=inbound_id,
                commit_at_dispatch_edge=True,
                idempotency_store=idempotency_store,
                attempt_store=attempt_store,
            )
        assert (
            await idempotency_store.has_committed(adapter_id=_ADAPTER_ID, inbound_id=inbound_id)
            is False
        )
        # The general bound this ledger enforces is the poison ceiling (5) —
        # ONE failure has consumed exactly one unit of that budget so far.
        assert await attempt_store.attempt_count(adapter_id=_ADAPTER_ID, inbound_id=inbound_id) == 1
        assert _FORWARDED_DISPATCH_ATTEMPT_CEILING == 5

        # The un-rolled-back residual: the FIRST (failed) turn's user+assistant
        # append already landed in the shared in-process deque — nothing
        # unwinds it when the send fails downstream of the pool release.
        pool = stack.graph.inbound_orchestrator._pool  # type: ignore[attr-defined]
        key = (_PERSONA, _ALICE_SLUG)
        wm = await pool.acquire(key)
        turns_after_failure = await wm.turns()
        await pool.release(key, wm)
        assert len(turns_after_failure) == 2  # user + assistant, NOT rolled back
        assert turns_after_failure[0].role == "user"
        assert turns_after_failure[1].role == "assistant"

        # Second delivery (the gateway's replay of the SAME frame): the flaky
        # sender's ONE failure is already spent, so this send succeeds. The
        # turn re-runs (a fresh completion) rather than short-circuiting,
        # because the FIRST attempt never committed.
        await stack.send_inbound(
            body={"text": "resume me"},
            inbound_id=inbound_id,
            commit_at_dispatch_edge=True,
            idempotency_store=idempotency_store,
            attempt_store=attempt_store,
        )
        assert (
            await idempotency_store.has_committed(adapter_id=_ADAPTER_ID, inbound_id=inbound_id)
            is True
        )
        # The turn ran EXACTLY twice for one injected failure — never a single
        # deterministic retry ceiling, never a silent third run.
        assert len(stack.captured_router.requests) == 2
        assert flaky_sender.call_count == 2

        # The residual is DOUBLE-APPEND, never cross-user: only alice's key was
        # ever touched (never crosses a user partition).
        assert set(stack.graph.inbound_orchestrator._pool._entries.keys()) == {key}  # type: ignore[attr-defined]
        wm = await pool.acquire(key)
        turns_after_replay = await wm.turns()
        await pool.release(key, wm)
        assert len(turns_after_replay) == 4  # 2 user + 2 assistant — duplicated, not lost


async def test_direct_path_crash_injection_is_at_most_once(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DIRECT path (``commit_at_dispatch_edge=False``): a send failure is at-most-once.

    No forwarded-edge replay envelope exists on this path — a failure
    propagates straight out of ``process_inbound_message`` and the frame is
    simply lost (the user must resend), matching FOLD-R22's confirmed posture.
    """
    async with _boot_stack(postgres_url, monkeypatch) as stack:
        stack.graph.inbound_orchestrator.bind_outbound_sender(_RaisingSender())

        with pytest.raises(ConnectionError):
            await stack.send_inbound(body={"text": "direct crash"})

        # Exactly one turn ran (the direct path never retries).
        assert len(stack.captured_router.requests) == 1
        send_failed_rows = [
            r
            for r in stack.audit_rows(event="comms.inbound.real_turn.refused")
            if r["subject"].get("refusal_stage") == "send_failed"
        ]
        assert len(send_failed_rows) == 1


# ---------------------------------------------------------------------------
# Step 5: concurrent same-user turn serialization (FOLD-R1, the Critical).
# ---------------------------------------------------------------------------


class _BlockOnMarkerRouter(FixedAnswerRouter):
    """Blocks the completion whose request contains ``block_marker`` until released.

    Lets a test deterministically force a specific turn to sit mid-flight
    (past its own user-append, inside its provider call) while a SECOND
    concurrent turn for the SAME key races ahead — the exact window the
    FOLD-R1 per-key mutex must close.
    """

    def __init__(self, *, block_marker: str) -> None:
        super().__init__(answer="scripted-answer")
        self._block_marker = block_marker
        self.blocked_call_started = asyncio.Event()
        self._release = asyncio.Event()

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.requests.append(request)
        if self._block_marker in _all_message_text(request):
            self.blocked_call_started.set()
            await self._release.wait()
        return CompletionResponse(
            content=self.answer,
            tokens_in=1,
            tokens_out=1,
            cost_usd=0.0,
            model="fixed-answer-test-double",
            stop_reason="end_turn",
            tool_calls=(),
        )

    def release(self) -> None:
        self._release.set()


async def test_concurrent_same_user_turns_are_serialized_by_the_per_key_mutex(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two concurrent same-user frames never interleave the shared WorkingMemory deque.

    FOLD-R1 (Critical, MEM-1): without the adapter's per-``(persona, slug)``
    mutex, turn B's user-append can land BETWEEN turn A's user-append and its
    (still in-flight) assistant-append, producing a torn transcript
    [userA, userB, assistantB, assistantA]. This test forces exactly that race
    window (turn A's provider call blocks until released) and asserts the
    transcript stays strictly serial: [userA, assistantA, userB, assistantB].

    This test MUST FAIL against a build without ``_turn_locks`` — verified by
    temporarily neutering ``_turn_lock_for`` locally (see the Task 5 report for
    the confirmed-fail transcript) and restoring it before this commit.
    """
    router = _BlockOnMarkerRouter(block_marker="BLOCK-A")
    async with _boot_stack(postgres_url, monkeypatch, router=router) as stack:
        task_a = asyncio.ensure_future(stack.send_inbound(body={"text": "BLOCK-A first message"}))
        await asyncio.wait_for(router.blocked_call_started.wait(), _TIMEOUT_S)

        task_b = asyncio.ensure_future(stack.send_inbound(body={"text": "second message"}))
        # Deterministic (not a sleep(0)-tick race): WITH the mutex, B structurally
        # CANNOT reach the router until A releases the lock — which only happens
        # when THIS test calls router.release() below — so B's request count
        # staying at 1 is guaranteed, not a timing guess. A generous real-time
        # window (B needs a quarantine-extract round trip + two Postgres writes
        # to reach the router) makes the absent-mutex direction non-flaky too:
        # if the mutex is missing, B reliably clears all of that well within 1s.
        await asyncio.sleep(1.0)
        assert len(router.requests) == 1, (
            "task B's request already reached the planner — it raced ahead of "
            "the per-key mutex instead of blocking on A's held lock"
        )
        assert not task_b.done()

        router.release()
        await asyncio.wait_for(asyncio.gather(task_a, task_b), _TIMEOUT_S)

        pool = stack.graph.inbound_orchestrator._pool  # type: ignore[attr-defined]
        key = (_PERSONA, _ALICE_SLUG)
        wm = await pool.acquire(key)
        turns = await wm.turns()
        await pool.release(key, wm)

        assert len(turns) == 4
        assert turns[0].role == "user" and "BLOCK-A" in turns[0].content
        assert turns[1].role == "assistant"  # NOT userB — no torn interleave
        assert turns[2].role == "user" and "second message" in turns[2].content
        assert turns[3].role == "assistant"


async def test_concurrent_cross_user_turns_are_not_serialized(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-key mutex is per-``(persona, slug)`` — a DIFFERENT user is never blocked."""
    router = _BlockOnMarkerRouter(block_marker="BLOCK-ALICE")
    async with _boot_stack(postgres_url, monkeypatch, router=router) as stack:
        task_alice = asyncio.ensure_future(
            stack.send_inbound(
                body={"text": "BLOCK-ALICE message"},
                platform_user_id=_ALICE_PLATFORM_ID,
            )
        )
        await asyncio.wait_for(router.blocked_call_started.wait(), _TIMEOUT_S)

        # Bob's turn (a DIFFERENT key) must complete WHILE Alice's turn is still
        # blocked mid-flight — proving the mutex never serialises cross-user work.
        await asyncio.wait_for(
            stack.send_inbound(body={"text": "hi from bob"}, platform_user_id=_BOB_PLATFORM_ID),
            _TIMEOUT_S,
        )
        assert len(stack.sender.sent) == 1  # bob's reply already sent

        router.release()
        await asyncio.wait_for(task_alice, _TIMEOUT_S)
        assert len(stack.sender.sent) == 2


# ---------------------------------------------------------------------------
# Step 6: persona-key rehydrate coherence (FOLD-R20).
# ---------------------------------------------------------------------------


async def test_persona_key_matches_the_shared_persona_id_and_rehydrates_prior_turns(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adapter's pool-key persona equals the orchestrator's shared persona id.

    FOLD-R20: a guard against a future persona-id rename silently desyncing
    the adapter's pool-acquire key from the persona the orchestrator writes
    episodic under (and the pool rehydrates by, ``working_pool.py:116``) — a
    COLD rehydrate (a fresh ``WorkingMemoryPool`` over the same episodic
    backing) must return the prior turn's history.
    """
    assert _PERSONA == _ALFRED_PERSONA_ID

    async with _boot_stack(postgres_url, monkeypatch) as stack:
        await stack.send_inbound(body={"text": "remember this"})

        from alfred.memory.episodic import EpisodicMemory
        from alfred.memory.working_pool import WorkingMemoryPool

        def _episodic_factory(session: AsyncSession) -> EpisodicMemory:
            return EpisodicMemory(session=session)

        cold_pool = WorkingMemoryPool(
            episodic_factory=_episodic_factory,
            pool_session_scope=build_boot_session_scope(stack.settings),
        )
        key = (_PERSONA, _ALICE_SLUG)
        wm = await cold_pool.acquire(key)
        turns = await wm.turns()
        await cold_pool.release(key, wm)

        assert len(turns) == 2  # the prior turn's user + assistant messages
        assert turns[0].role == "user" and "remember this" in turns[0].content
        assert turns[1].role == "assistant"


# ---------------------------------------------------------------------------
# Step 4: error/refusal-leg integration (FOLD-5) — the legs uniquely provable
# with real infra; every branch is ALSO unit-pinned (Tasks 1-2).
# ---------------------------------------------------------------------------


async def test_typed_refusal_sends_benign_reply_in_users_language(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _boot_stack(postgres_url, monkeypatch) as stack:
        await stack.send_inbound(body={"text": "hi", "__force_refusal__": True})

        assert len(stack.sender.sent) == 1
        # ``ingest`` called set_language(resolved.language) before rendering —
        # alice is en-GB (distinct from the en-US default), so t() under the
        # SAME (still-active) language context must match the sent reply.
        expected = t("comms.inbound.real_turn.extraction_refused")
        assert stack.sender.sent[0].body[0] == expected
        # No adapter-owned refusal row for a TypedRefusal — it is a benign,
        # expected extraction outcome, not a security/budget/turn fault.
        assert stack.audit_rows(event="comms.inbound.real_turn.refused") == []


async def test_downgrade_deny_writes_loud_row_and_sends_nothing(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _boot_stack(postgres_url, monkeypatch, grant_downgrade=False) as stack:
        await stack.send_inbound(body={"text": "hi"})

        assert stack.sender.sent == []  # no reply leaked on a security deny
        rows = stack.audit_rows(event="comms.inbound.real_turn.refused")
        assert len(rows) == 1
        subject = rows[0]["subject"]
        assert subject["refusal_stage"] == "downgrade_denied"
        assert isinstance(subject["inbound_id_hash"], str) and subject["inbound_id_hash"]
        assert rows[0]["actor_user_id"] == _ALICE_SLUG


async def test_send_failure_writes_send_failed_row_and_reraises(
    postgres_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _boot_stack(postgres_url, monkeypatch) as stack:
        stack.graph.inbound_orchestrator.bind_outbound_sender(_RaisingSender())

        with pytest.raises(ConnectionError):
            await stack.send_inbound(body={"text": "hi"})

        rows = stack.audit_rows(event="comms.inbound.real_turn.refused")
        stages = [r["subject"]["refusal_stage"] for r in rows]
        assert stages == ["send_failed"]
