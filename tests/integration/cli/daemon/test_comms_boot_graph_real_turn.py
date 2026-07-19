"""#338 PR2 Task 3: the daemon comms boot graph assembles the REAL turn adapter.

Proof that ``_build_comms_boot_graph`` — given the new REQUIRED ``real_gate``
param and the ``router_override`` test seam (so the REAL, egress-proxied
``build_router`` is never reached) — assembles a
:class:`RealTurnOrchestratorAdapter` (the #338 PR2 cutover) rather than the
deterministic-echo ``CommsInboundOrchestratorAdapter``, and exposes the RAW
``IdentityResolver`` (carrying the promoted ``version_counter`` — arch-001) on
the graph, not just the sync bridge.

INTEGRATION tier, not unit (deviation from the task-3 brief's initially-assumed
unit-tier path — see the Task 3 report): ``build_orchestrator`` assembles a
REAL ``Orchestrator``, whose constructor (``core.py:308``) SYNCHRONOUSLY calls
``identity_resolver.get_operator()`` to cache the household operator identity
for the orchestrator's lifetime — a real, pre-existing ``Orchestrator.__init__``
contract, not something this task introduces. That requires a reachable
Postgres with exactly one seeded operator user, so this suite cannot be made
hermetic while it builds a genuine ``Orchestrator`` over the graph's real
resolver (FOLD-1 — reusing that exact resolver instance, not a bare one, is
the point of the assertion below). Mirrors the FIVE existing direct callers of
``_build_comms_boot_graph`` in this directory, all of which are integration-tier
for the identical reason.

Construction-only: no turn is driven here (that is
``tests/unit/comms_mcp/test_real_turn_adapter_*.py`` + the integration
provenance suite's job). ``router_override`` means the real, network-touching
``build_router`` is never reached; the quarantined child spawn is faked
(mirrors every sibling test in this directory).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.cli.daemon._commands import _build_boot_outbound_dlp
from alfred.cli.daemon._comms_boot import _build_comms_boot_graph, _CommsBootGraph
from alfred.comms_mcp.real_turn_adapter import RealTurnOrchestratorAdapter
from alfred.config.settings import Settings
from alfred.hooks.boot import install_boot_hook_registry
from alfred.hooks.registry import get_registry, set_registry
from alfred.identity.models import Authorization, User
from alfred.memory.hooks_audit_sink import EpisodicAuditSink
from alfred.memory.models import Base
from alfred.security import tiers as _tiers
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy, GrantRow
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import _make_in_memory_backend, _make_no_op_audit_sink
from tests.helpers.routers import FixedAnswerRouter

pytestmark = pytest.mark.integration

_OPERATOR_SLUG = "the-operator"


def _boot_gate_for_this_graph() -> RealGate:
    """A REAL RealGate seeded for the two chains graph construction touches.

    CLAUDE.md hard rule #2 — a real :class:`RealGate` over scoped fixture grants,
    NEVER a permissive shim. Two grants: the system-tier
    ``security.quarantined.extract`` grant so the ``QuarantinedExtractor``'s
    post-stage DLP subscriber registers, and the ``t3.downgrade_to_orchestrator``
    content-tier T3 grant the ``RealTurnOrchestratorAdapter`` would need on a
    REAL turn (unexercised here — construction-only — but the fixture should be
    turn-capable, not accidentally deny-scoped).
    """
    grants = frozenset(
        {
            GrantRow(
                plugin_id="alfred.security._extract_dlp_subscriber",
                subscriber_tier="system",
                hookpoint="security.quarantined.extract",
                content_tier=None,
                proposal_branch="test-fixture",
            ),
            GrantRow(
                plugin_id="t3.downgrade_to_orchestrator",
                subscriber_tier="system",
                hookpoint="t3.downgrade_to_orchestrator",
                content_tier="T3",
                proposal_branch="test-fixture",
            ),
        }
    )
    return RealGate(
        policy=GatePolicy(grants=grants),
        backend=_make_in_memory_backend(grants=grants),
        audit_sink=_make_no_op_audit_sink(),
    )


def _seed_operator(sync_url: str) -> None:
    """Seed the single operator user ``Orchestrator.__init__`` requires.

    ``build_orchestrator`` (with the graph's real ``resolver`` injected)
    constructs a genuine ``Orchestrator``, whose constructor synchronously calls
    ``identity_resolver.get_operator()`` — this raises ``IdentityResolutionError``
    against an empty ``users`` table, so the graph build needs exactly one
    operator row present before the call.
    """
    sync_engine = create_engine(sync_url, future=True)
    try:
        sync_factory_kwargs: dict[str, Any] = {"expire_on_commit": False, "future": True}
        from sqlalchemy.orm import sessionmaker

        sync_factory = sessionmaker(sync_engine, **sync_factory_kwargs)
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
    finally:
        sync_engine.dispose()


@asynccontextmanager
async def _boot_audit_writer(postgres_url: str) -> AsyncIterator[AuditWriter]:
    """Create the schema, seed the operator, and yield a real Postgres AuditWriter."""
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
        _seed_operator(sync_url)

        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        yield AuditWriter(session_factory=session_scope)
    finally:
        await engine.dispose()


class _EchoingChildDouble:
    """Minimal in-proc quarantined-child double — never actually driven here.

    Construction-only: this suite never calls ``quarantine.ingest`` /
    ``quarantine.extract``, so the double need not implement the real echo
    protocol (mirrors the sibling proofs' ``_EchoingChildDouble``, trimmed to
    just the seam ``QuarantineStdioTransport``/``spawn_quarantine_child_io``
    need).
    """

    def __init__(self, *, provider_key: str) -> None:
        self.provider_key = provider_key

    def write_frame(self, frame: bytes) -> None:  # pragma: no cover - unused (construction-only)
        return None

    async def read_frame(self) -> bytes:  # pragma: no cover - unused (construction-only)
        raise AssertionError("construction-only proof drives no quarantine turn")

    async def aclose(self) -> None:
        return None


@pytest.fixture
def _boot_env(monkeypatch: pytest.MonkeyPatch, postgres_url: str) -> None:
    """Set the env the production Settings + broker read.

    ``router_override`` (below) means the REAL, egress-proxied ``build_router``
    is never reached, so no ``ALFRED_EGRESS_PROXY_URL`` is needed here (unlike
    ``test_chat_gateway_socket_turn.py``, which drives a real turn).
    """
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    monkeypatch.setenv("ALFRED_ENV", "test")
    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "not-a-real-secret-integration-placeholder")
    # #340 golive Task 7: the comms boot now REFUSES on an unset quarantine provider
    # key (host pre-spawn §20.2 primary defense — the placeholder path is gone). The
    # 2b echo child still reads + scrubs + discards it, so a placeholder value clears
    # the refuse and lets _build_comms_boot_graph assemble the graph under test.
    monkeypatch.setenv(
        "ALFRED_QUARANTINE_PROVIDER_API_KEY", "not-a-real-secret-quarantine-placeholder"
    )


@pytest.mark.usefixtures("_boot_env")
async def test_graph_exposes_raw_resolver_and_real_turn_adapter(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings()  # type: ignore[no-untyped-call]  # env-driven; mirrors daemon boot

    prior_registry = get_registry()
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE
    gate = _boot_gate_for_this_graph()
    graph: _CommsBootGraph | None = None

    try:
        async with _boot_audit_writer(postgres_url) as audit:
            install_boot_hook_registry(gate, sink=EpisodicAuditSink(audit=audit))

            outbound_dlp = _build_boot_outbound_dlp(settings=settings, audit=audit)
            with _NONCE_LOCK:
                nonce = CapabilityGateNonce()
                _tiers._set_authorized_t3_nonce(nonce)

            async def _fake_spawn(
                *, provider_key: str, refusal_recorder: object = None, **_golive: object
            ) -> _EchoingChildDouble:
                return _EchoingChildDouble(provider_key=provider_key)

            monkeypatch.setattr(
                "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
            )

            graph = await _build_comms_boot_graph(
                settings=settings,
                audit=audit,
                outbound_dlp=outbound_dlp,
                t3_nonce=nonce,
                policies_ref=None,
                real_gate=gate,
                router_override=FixedAnswerRouter(),  # type: ignore[arg-type]  # offline test seam
            )

            assert isinstance(graph.inbound_orchestrator, RealTurnOrchestratorAdapter)
            # arch-001: the RAW resolver (with the promoted version_counter), not
            # just the sync bridge — build_orchestrator reuses THIS instance so the
            # process-global install_identity_factories is not re-fired.
            assert graph.resolver is not None
            assert hasattr(graph.resolver, "version_counter")
    finally:
        if graph is not None:
            await graph.aclose()
        set_registry(prior_registry)
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(prior_nonce)
