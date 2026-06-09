"""Shared harness for the comms-MCP integration tests (Component L, #152).

Assembles the real comms host from the Wave-2/3 surfaces + the bootstrap seam
bridges, against a real Postgres testcontainer:

* a real :class:`AuditWriter` wired through an async ``session_scope`` so its rows
  commit on their own transaction (CLAUDE.md hard rule #7);
* a real sync :class:`IdentityResolver` (seeded with a synthetic Discord-bound
  user), wrapped by the :class:`SyncIdentityResolverBridge`;
* a real :class:`QuarantinedExtractor` driven by a deterministic fixture
  transport (the recorded-LLM-response pattern CLAUDE.md sanctions outside smoke
  tests), wrapped by the :class:`CommsExtractorBridge`;
* a real :class:`BurstLimiter`;
* a recording outbound buffer that captures every host -> plugin frame so the
  #152 identity invariant (the canonical id never crosses outward) can be
  asserted on real bytes.

The reference plugin's ``build_inbound_notification`` supplies the inbound frame
shape; the harness drives :func:`process_inbound_message` host-side directly (the
plugin + the host's ``StdioTransport`` speak different framings — see
``test_comms_mcp_contract.py`` — so the host-side path is exercised against the
inbound notification model rather than through the transport state machine).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker

from alfred.audit.log import AuditWriter
from alfred.comms_mcp.bootstrap import (
    CommsBodyExtraction,
    CommsExtractorBridge,
    SyncIdentityResolverBridge,
)
from alfred.comms_mcp.protocol import InboundMessageNotification
from alfred.hooks import HookRegistry, get_registry, set_registry
from alfred.identity import (
    Authorization,
    IdentityResolver,
    IdentityVersionCounter,
    NullRateLimiter,
    Platform,
)
from alfred.identity.models import PlatformIdentity, User
from alfred.memory.models import Base
from alfred.orchestrator.burst_limiter import BurstLimiter
from alfred.security.quarantine import QuarantinedExtractor, declare_hookpoints
from plugins.alfred_comms_test import main as reference_plugin
from tests.helpers.gates import make_quarantined_extract_chain_gate

ADAPTER_ID = "alfred_comms_test"
PLATFORM_USER_ID = "discord:victim"
CANONICAL_SLUG = "alice"
USER_LANGUAGE = "en-GB"


# ---------------------------------------------------------------------------
# Recording outbound buffer — captures host -> plugin frames (assertion 4)
# ---------------------------------------------------------------------------


class RecordingOutbound:
    """Captures every host -> plugin frame as raw bytes for leak assertions."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []

    def write_frame(self, frame: Mapping[str, object]) -> None:
        self.frames.append((json.dumps(dict(frame)) + "\n").encode())


# ---------------------------------------------------------------------------
# Spy resolver bridge — counts resolve calls + records kwargs (assertions 1,2,3)
# ---------------------------------------------------------------------------


@dataclass
class SpyResolverBridge:
    """Wraps the real :class:`SyncIdentityResolverBridge`, recording each call."""

    inner: SyncIdentityResolverBridge
    resolve_calls: int = 0
    last_call_kwargs: dict[str, str] = field(default_factory=dict)
    last_return: Any = None

    async def resolve(self, *, adapter_id: str, platform_user_id: str) -> Any:
        self.resolve_calls += 1
        self.last_call_kwargs = {
            "adapter_id": adapter_id,
            "platform_user_id": platform_user_id,
        }
        self.last_return = await self.inner.resolve(
            adapter_id=adapter_id, platform_user_id=platform_user_id
        )
        return self.last_return


# ---------------------------------------------------------------------------
# Stub orchestrator — real quarantined_extract bridge, recording ingest/dispatch
# ---------------------------------------------------------------------------


class HarnessOrchestrator:
    """Routes ``quarantined_extract`` to the real bridge; records ingest/dispatch.

    ``ingest`` builds an outbound frame and writes it to the recording buffer so
    the round-trip produces a captured host -> plugin frame (assertion 4). The
    canonical user id is deliberately NOT placed on the outbound frame — only the
    platform-facing ``target_platform_id`` crosses outward.
    """

    def __init__(
        self, *, extractor_bridge: CommsExtractorBridge, outbound: RecordingOutbound
    ) -> None:
        self._extractor_bridge = extractor_bridge
        self._outbound = outbound
        self.dispatch_calls = 0
        self.last_extract_kwargs: dict[str, Any] = {}

    async def quarantined_extract(
        self,
        body: bytes | str | Mapping[str, object],
        *,
        canonical_user_id: str,
        source_tier: Any,
    ) -> Any:
        self.last_extract_kwargs = {
            "body": body,
            "canonical_user_id": canonical_user_id,
            "source_tier": source_tier,
        }
        return await self._extractor_bridge.extract(
            body=body, canonical_user_id=canonical_user_id, source_tier=source_tier
        )

    async def ingest(self, **kwargs: Any) -> object:
        # Emit a synthetic outbound reply. Only the platform id crosses outward —
        # never the canonical user id (spec §8.2 identity invariant).
        self._outbound.write_frame(
            {
                "jsonrpc": "2.0",
                "method": "outbound.message",
                "params": {
                    "adapter_id": ADAPTER_ID,
                    "target_platform_id": PLATFORM_USER_ID,
                    "body": "ack",
                },
            }
        )
        return {"ingested": True}

    async def dispatch(self, ingested: object) -> None:
        self.dispatch_calls += 1


# ---------------------------------------------------------------------------
# Real fixture-transport quarantined extractor
# ---------------------------------------------------------------------------


def _build_fixture_extractor(audit_writer: AuditWriter) -> QuarantinedExtractor:
    """Construct a REAL ``QuarantinedExtractor`` with a deterministic transport.

    The transport returns a ``CommsBodyExtraction``-valid ``extracted`` payload —
    the recorded-LLM-response pattern. The DLP stub is an identity scan (the
    inbound bodies carry no secrets in these fixtures). The real extractor lifts
    the payload into :class:`Extracted`, exercising the genuine
    ``extract(handle, schema)`` surface the bridge funnels through.
    """
    transport = MagicMock()
    transport.dispatch = AsyncMock(
        return_value=_control_result_extracted(),
    )
    dlp = MagicMock()
    dlp.scan = MagicMock(side_effect=lambda x: x)
    return QuarantinedExtractor(
        transport=transport,
        audit_writer=audit_writer,
        outbound_dlp=dlp,
    )


def _control_result_extracted() -> Any:
    from alfred.plugins.transport import ControlResult

    return ControlResult(
        method="quarantine.extract",
        payload={
            "kind": "extracted",
            "data": {"text": "hello", "intent": "greeting"},
            "extraction_mode": "native_constrained",
        },
    )


# ---------------------------------------------------------------------------
# Assembled host
# ---------------------------------------------------------------------------


@dataclass
class CommsHost:
    """The assembled comms host the integration tests drive."""

    audit_writer: AuditWriter
    resolver_bridge: SpyResolverBridge
    orchestrator: HarnessOrchestrator
    burst_limiter: BurstLimiter
    secret_broker: Any
    outbound: RecordingOutbound
    async_sessionmaker: async_sessionmaker[AsyncSession]


def make_inbound_notification(
    *,
    body: dict[str, Any] | None = None,
    platform_metadata: dict[str, Any] | None = None,
    platform_user_id: str = PLATFORM_USER_ID,
) -> InboundMessageNotification:
    """Build an ``InboundMessageNotification`` via the reference plugin's frame."""
    inject_payload: dict[str, Any] = {
        "platform_user_id": platform_user_id,
        "content": (body or {}).get("content", "attack"),
    }
    if platform_metadata is not None:
        inject_payload["platform_metadata"] = platform_metadata
    frame = reference_plugin.build_inbound_notification(inject_payload)
    params = dict(frame["params"])
    if body is not None:
        params["body"] = body
    # platform_metadata is not part of the host-side InboundMessageNotification
    # schema (extra="forbid"); the forged value is carried on the wire frame for
    # the leak/forgery assertions, then dropped before model construction.
    params.pop("platform_metadata", None)
    return InboundMessageNotification.model_validate(params)


def _seed_user(sync_url: str) -> None:
    sync_engine = create_engine(sync_url, future=True)
    try:
        sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)
        with sync_factory.begin() as session:
            user = User(
                slug=CANONICAL_SLUG,
                display_name=CANONICAL_SLUG,
                authorization=Authorization.STANDARD.value,
                daily_budget_usd=5.0,
                language=USER_LANGUAGE,
            )
            session.add(user)
            session.flush()
            session.add(
                PlatformIdentity(
                    user_id=user.id,
                    platform=Platform.DISCORD.value,
                    platform_id=PLATFORM_USER_ID,
                )
            )
    finally:
        sync_engine.dispose()


@asynccontextmanager
async def build_comms_host(postgres_url: str) -> AsyncIterator[CommsHost]:
    """Assemble the comms host against a real Postgres container URL."""
    # Install a scoped RealGate registry seeded with exactly the system-tier
    # grant the post-stage DLP subscriber needs (CLAUDE.md hard rule #2 — a
    # production gate with a fixture grant, never an always-allow shim). The
    # real QuarantinedExtractor refuses to construct without it.
    prior_registry = get_registry()
    scoped_registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(), strict_declarations=False
    )
    set_registry(scoped_registry)
    declare_hookpoints(scoped_registry)

    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
        _seed_user(sync_url)

        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        audit_writer = AuditWriter(session_factory=session_scope)

        sync_engine = create_engine(sync_url, future=True)
        sync_factory = sessionmaker(sync_engine, expire_on_commit=False, future=True)
        real_resolver = IdentityResolver(
            session_factory=sync_factory,
            version_counter=IdentityVersionCounter(),
            rate_limiter=NullRateLimiter(),
        )
        resolver_bridge = SpyResolverBridge(
            inner=SyncIdentityResolverBridge(resolver=real_resolver)
        )

        outbound = RecordingOutbound()
        extractor = _build_fixture_extractor(audit_writer)
        extractor_bridge = CommsExtractorBridge(extractor=extractor)
        orchestrator = HarnessOrchestrator(extractor_bridge=extractor_bridge, outbound=outbound)

        burst_limiter = BurstLimiter(audit_writer=audit_writer)

        secret_broker = MagicMock()
        secret_broker.get = MagicMock(return_value="integration-test-pepper")

        try:
            yield CommsHost(
                audit_writer=audit_writer,
                resolver_bridge=resolver_bridge,
                orchestrator=orchestrator,
                burst_limiter=burst_limiter,
                secret_broker=secret_broker,
                outbound=outbound,
                async_sessionmaker=sm,
            )
        finally:
            sync_engine.dispose()
    finally:
        await engine.dispose()
        set_registry(prior_registry)


def schema_for_tests() -> type[CommsBodyExtraction]:
    """Expose the extraction schema for direct assertions if needed."""
    return CommsBodyExtraction
