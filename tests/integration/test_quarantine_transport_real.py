"""Load-bearing integration: real extractor + real quarantine transport (#237).

PR-S4-11c-2a (ADR-0029). Drives the WHOLE host-side quarantine content path end
to end against a real Postgres-backed :class:`AuditWriter` and a real scoped
:class:`RealGate` registry — only the launcher-spawned subprocess is replaced by
an in-test length-prefixed child DOUBLE (no subprocess, no bwrap, no real LLM,
per 2a scope):

* real :class:`alfred.security.quarantine_transport.T3BodyRecorder` tags the
  inbound body ``TaggedContent[T3]`` and stages it under the minted handle id;
* real :class:`alfred.comms_mcp.bootstrap.CommsExtractorBridge` mints the handle,
  records the body, delegates to ``extractor.extract``;
* real :class:`alfred.security.quarantine.QuarantinedExtractor` drives the real
  :class:`alfred.security.quarantine_transport.QuarantineStdioTransport`;
* the transport drains the staged body, ships ``quarantine.ingest`` then
  ``quarantine.extract`` over the child double, which echoes the ingested context
  back so the assertion proves the body crossed the wire (not a fixed replay);
* the post-stage DLP subscriber (``security.quarantined.extract``,
  quarantine.py:774) runs on a real registry; and
* the ``quarantine.extract`` audit row lands in Postgres with
  ``result="extracted"``.
"""

from __future__ import annotations

import json
import struct
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.comms_mcp.bootstrap import CommsExtractorBridge
from alfred.hooks.registry import HookRegistry, get_registry, set_registry
from alfred.memory.models import AuditEntry, Base
from alfred.security import tiers as _tiers
from alfred.security.dlp import OutboundDlp
from alfred.security.quarantine import Extracted, QuarantinedExtractor, declare_hookpoints
from alfred.security.quarantine_transport import (
    QuarantineStagingMap,
    QuarantineStdioTransport,
    T3BodyRecorder,
)
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import make_quarantined_extract_chain_gate

pytestmark = pytest.mark.integration


class _EchoingChildDouble:
    """Length-prefixed JSON-RPC child double echoing the ingested body.

    Mirrors the quarantine child's single-use ingest/extract cache
    (``alfred.security.quarantine_child.__main__`` ``handle_ingest`` /
    ``handle_extract``): caches the ingested ``context`` and pops it single-use on
    extract, replying with a ``CommsBodyExtraction``-valid ``extracted`` payload
    whose ``data.text`` is the echoed body. No subprocess — this is the in-test
    stand-in for the PR-S4-11c-2b launcher-spawned child.
    """

    def __init__(self) -> None:
        self.received: list[str] = []
        self._ingested: dict[str, str] = {}
        self._reply: bytes | None = None

    def write_frame(self, frame: bytes) -> None:
        length = struct.unpack(">I", frame[:4])[0]
        obj = json.loads(frame[4 : 4 + length])
        method, params = obj["method"], obj["params"]
        self.received.append(method)
        if method == "quarantine.ingest":
            self._ingested[params["handle_id"]] = params["context"]
        elif method == "quarantine.extract":
            context = self._ingested.pop(params["handle_id"], "")
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "result": {
                        "kind": "extracted",
                        "data": {"text": context, "intent": "greeting"},
                        "extraction_mode": "native_constrained",
                    },
                }
            ).encode("utf-8")
            self._reply = struct.pack(">I", len(body)) + body

    async def read_frame(self) -> bytes:
        assert self._reply is not None
        reply, self._reply = self._reply, None
        return reply

    async def aclose(self) -> None:
        return None


@asynccontextmanager
async def _audit_writer(postgres_url: str) -> AsyncIterator[tuple[AuditWriter, Any]]:
    engine = create_async_engine(postgres_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sm = async_sessionmaker(bind=engine, expire_on_commit=False)

        @asynccontextmanager
        async def session_scope() -> AsyncIterator[AsyncSession]:
            async with sm() as session, session.begin():
                yield session

        yield AuditWriter(session_factory=session_scope), sm
    finally:
        await engine.dispose()


async def _rows_with_event(sm: Any, event: str) -> list[AuditEntry]:
    async with sm() as session:
        result = await session.execute(select(AuditEntry).where(AuditEntry.event == event))
        return list(result.scalars().all())


@pytest.mark.asyncio
async def test_real_extractor_over_real_transport_records_body_and_audits(
    postgres_url: str,
) -> None:
    """The full host quarantine path: body -> stage -> ingest -> extract -> audit.

    Asserts the body crossed the wire (the child echoed it), the extractor lifted
    a real :class:`Extracted`, the post-stage DLP subscriber ran (it runs on the
    real registry as part of ``extract``), and the ``quarantine.extract`` audit
    row landed with ``result="extracted"``.
    """
    # Scoped RealGate registry granting exactly the system-tier DLP grant the
    # post-stage subscriber needs — a production gate with a fixture grant, never
    # an always-allow shim (CLAUDE.md hard rule #2). The real QuarantinedExtractor
    # refuses to construct without the active registration.
    prior_registry = get_registry()
    scoped_registry = HookRegistry(
        gate=make_quarantined_extract_chain_gate(), strict_declarations=False
    )
    set_registry(scoped_registry)
    declare_hookpoints(scoped_registry)

    # Register a known authorised T3 nonce as the live slot for the recorder's
    # tag(T3) call; restore on the way out so no global state leaks.
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)

    try:
        async with _audit_writer(postgres_url) as (audit, sm):
            # Real OutboundDlp (the post-stage scanner) over a passthrough broker.
            from unittest.mock import AsyncMock, MagicMock

            broker = MagicMock()
            broker.redact = MagicMock(side_effect=lambda x: x)
            audit_sink = MagicMock()
            audit_sink.emit = AsyncMock()
            outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)

            # Construct the machinery DIRECTLY (PR-S4-11c-2a ships the transport;
            # the daemon's _build_comms_inbound_extractor still wires the ADR-0027
            # fixture extractor — the real-transport production flip is 2b). This
            # test proves the real extractor drives the real QuarantineStdioTransport
            # over the injected child-IO seam + single-use staging map.
            staging = QuarantineStagingMap()
            child = _EchoingChildDouble()
            transport = QuarantineStdioTransport(child_io=child, staging=staging)
            extractor = QuarantinedExtractor(
                transport=transport,
                audit_writer=audit,
                outbound_dlp=outbound_dlp,
            )
            recorder = T3BodyRecorder(nonce=nonce, staging=staging)
            bridge = CommsExtractorBridge(extractor=extractor, record_body=recorder)

            result = await bridge.extract(
                body="hello from the wire",
                canonical_user_id="alice",
                source_tier="T3",
            )

            # The body crossed the wire: ingest THEN extract, body echoed back.
            assert child.received == ["quarantine.ingest", "quarantine.extract"]
            assert isinstance(result, Extracted)
            assert result.data["text"] == "hello from the wire"

            # The post-stage DLP subscriber ran (no HookRefusal) and the audit row
            # landed with the body's classification.
            rows = await _rows_with_event(sm, "quarantine.extract")
            assert len(rows) == 1
            assert rows[0].result == "extracted"
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(prior_nonce)
        set_registry(prior_registry)
