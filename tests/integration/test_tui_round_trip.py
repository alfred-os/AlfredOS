"""MERGE-BLOCKING: TUI MCP plugin + daemon round-trip end-to-end (#206).

This is the PR-S4-10 Component-D integration gate. It exercises the real
``plugins/alfred_tui`` adapter against the real host dispatcher across two
load-bearing legs, neither of which is mocked at the seam under test:

* **inbound -> process_inbound_message** — a keystroke-batch flushed through the
  REAL :class:`alfred_tui.session.TuiSession` (the plugin's own inbound emitter,
  exactly as ``test_discord_addressing_modes`` drives the real Discord
  ``normalise``) mints a real :class:`InboundMessageNotification`, which is fed
  to the REAL host :func:`alfred.comms_mcp.inbound.process_inbound_message`
  (PR-S4-8) backed by a testcontainer Postgres ``AuditWriter``. The host-side
  :class:`IdentityResolver` seam is consulted EXACTLY ONCE (positive count
  assertion) with PLATFORM identifiers, and the resolver-derived canonical id
  never appears on any captured plugin->host wire frame (spec §8.2).

* **outbound -> RichLog** — the orchestrator's reply is painted back through the
  REAL :func:`alfred_tui.outbound.handle_outbound_message` into the REAL
  ``AlfredTuiApp`` RichLog (driven under Textual's ``run_test`` pilot, the same
  seam ``test_render_wiring`` pins), and a non-``dm`` mode is refused with the
  defensive ``tui_addressing_mode_not_supported`` terminal failure.

Why this shape rather than the plan's ``alfred_session_factory`` pseudocode:
the TUI server exposes NO wire method to inject a keystroke (its inbound is
driven by the Textual app feeding ``consume_user_input``). The merge-blocking
host invariants (resolver-consulted-once, canonical-id-never-on-the-wire) are
therefore driven through the real plugin inbound emitter in-process against the
real host dispatcher — the identical strategy ``test_discord_addressing_modes``
uses.

Carrier-flip note (PR-S4-237-2, ADR-0031 Shape A): the original third leg
spawned ``alfred_tui.server`` via the launcher and round-tripped over the
child's stdio. That leg was RETIRED with the stdio carrier: ``alfred chat`` no
longer launcher-spawns the TUI — it runs in-process and DIALS the daemon's 0600
unix socket (``alfred_tui.cohost.run_cohosted``). The real-PTY + real-daemon +
real-socket e2e turn (painting the stubbed ``ack``) is a dedicated PTY smoke
(deferred to PR-4), not a launcher-stdio subprocess. The two in-process legs
below carry the merge-blocking host-invariant + RichLog-round-trip coverage.

Requires docker (testcontainer Postgres); skips cleanly without it.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from alfred_tui.outbound import handle_outbound_message
from alfred_tui.render import build_app
from alfred_tui.session import TuiSession
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from alfred.audit.log import AuditWriter
from alfred.comms_mcp.inbound import ResolvedInbound, process_inbound_message
from alfred.comms_mcp.protocol import (
    InboundMessageNotification,
    OutboundMessageRequest,
    _OutboundDelivered,
    _OutboundTerminal,
)
from alfred.memory.models import AuditEntry, Base
from alfred.security.dlp import OutboundDlp

pytestmark = pytest.mark.integration

# HKDF (audit_hash) requires a >=32-byte PRK; the test pepper must clear that
# floor exactly as the production audit.hash_pepper does.
_TEST_PEPPER = "integration-test-pepper-0123456789abcdef-padding"


# ---------------------------------------------------------------------------
# Recorded host dependencies (mirrors test_discord_addressing_modes)
# ---------------------------------------------------------------------------


class _RecordedResolver:
    """A recorded ``IdentityResolver``: counts calls + records PLATFORM kwargs.

    ``canonical_user_id`` is DERIVED from the wire's ``platform_user_id`` at
    resolve time (not a contrived constant), so the "canonical id never on the
    wire" assertion tests a REAL substitution: a value computed FROM a wire
    field must still not appear on any captured wire frame (review F8). It is
    populated to ``None`` until the first ``resolve`` so a test that asserts on
    it after the host call reads the substituted value.
    """

    def __init__(self) -> None:
        self.resolve_calls = 0
        self.last_kwargs: dict[str, str] = {}
        self.canonical_user_id: str | None = None

    async def resolve(self, *, adapter_id: str, platform_user_id: str) -> ResolvedInbound:
        self.resolve_calls += 1
        self.last_kwargs = {"adapter_id": adapter_id, "platform_user_id": platform_user_id}
        # The host maps the PLATFORM id to an internal canonical id. Derive it
        # from a stable HASH of the platform id so the downstream non-leak
        # assertion tests a genuine platform->canonical substitution (a value
        # computed FROM the wire) WITHOUT embedding the raw platform substring —
        # the canonical form must be opaque, mirroring a real resolver that
        # never round-trips the raw handle into a canonical id or an audit row.
        import hashlib

        digest = hashlib.sha256(platform_user_id.encode()).hexdigest()[:16]
        self.canonical_user_id = f"user:{digest}"
        return ResolvedInbound(
            canonical_user_id=self.canonical_user_id,
            persona="alfred",
            language="en-US",
            adapter_id=adapter_id,
            display_name="Test User",
        )


class _RecordingOrchestrator:
    """Records the canonical id + the wire-facing notification ingest carried."""

    def __init__(self) -> None:
        self.ingested: list[dict[str, Any]] = []

    async def quarantined_extract(
        self, body: object, *, canonical_user_id: str, source_tier: str
    ) -> Any:
        from alfred.security.quarantine import Extracted, T3DerivedData

        return Extracted(data=T3DerivedData({"text": "ok"}), extraction_mode="native_constrained")

    async def ingest(self, **kwargs: Any) -> object:
        self.ingested.append(kwargs)
        return {"ok": True}

    async def dispatch(self, ingested: object) -> None:
        return None


class _Burst:
    async def acquire(self, **_kwargs: Any) -> Any:
        from alfred.orchestrator.burst_limiter import Acquired

        return Acquired(tokens_remaining=4, waited_seconds=0.0)


class _Broker:
    def get(self, name: str) -> str:
        return _TEST_PEPPER

    def redact(self, text: str) -> str:
        return text


# ---------------------------------------------------------------------------
# Postgres-backed audit writer (real AuditWriter, real rows)
# ---------------------------------------------------------------------------


async def _build_audit_writer(postgres_url: str) -> tuple[AuditWriter, async_sessionmaker[Any]]:
    engine = create_async_engine(postgres_url, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sm = async_sessionmaker(bind=engine, expire_on_commit=False)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def session_scope() -> Any:
        async with sm() as session, session.begin():
            yield session

    return AuditWriter(session_factory=session_scope), sm


# ---------------------------------------------------------------------------
# 1. inbound -> host: resolver consulted once, canonical id never on the wire
# ---------------------------------------------------------------------------


async def test_tui_inbound_reaches_process_inbound_message(postgres_url: str) -> None:
    """A keystroke-batch reaches the host dispatcher; resolver consulted once."""
    captured: list[InboundMessageNotification] = []

    async def _sink(note: InboundMessageNotification) -> None:
        captured.append(note)

    session = TuiSession(notify=_sink)
    await session.start(adapter_id="tui-test-instance")
    await session.consume_user_input("hello alfred")
    await session.flush_keystroke_batch()
    assert len(captured) == 1
    notification = captured[0]
    # The real plugin emits a "tui"-kind, dm-addressed notification.
    assert notification.adapter_id == "tui"
    assert notification.addressing_signal == "dm"

    audit_writer, _sm = await _build_audit_writer(postgres_url)
    resolver = _RecordedResolver()
    orchestrator = _RecordingOrchestrator()

    await process_inbound_message(
        notification,
        identity_resolver=resolver,
        orchestrator=orchestrator,
        burst_limiter=_Burst(),
        audit_writer=audit_writer,
        secret_broker=_Broker(),
    )

    # The host consulted the IdentityResolver EXACTLY ONCE, with PLATFORM ids.
    assert resolver.resolve_calls == 1
    assert resolver.last_kwargs["adapter_id"] == "tui"
    assert resolver.last_kwargs["platform_user_id"] == notification.platform_user_id

    # The canonical id is threaded host-side into ingest, never onto the wire.
    assert orchestrator.ingested, "production must have called ingest"
    canonical = resolver.canonical_user_id
    assert canonical is not None
    assert orchestrator.ingested[0]["canonical_user_id"] == canonical
    # The canonical id is a genuine SUBSTITUTION of the on-wire platform id
    # (review F8): it is the resolver's deterministic mapping of the EXACT
    # platform_user_id that crossed the wire — recomputing the mapping from the
    # frame's own platform id reproduces it. So the non-leak assertion below has
    # teeth: it is testing that a value derived from a real wire field does not
    # itself appear on the wire, not a constant that was never on it.
    import hashlib

    expected = f"user:{hashlib.sha256(notification.platform_user_id.encode()).hexdigest()[:16]}"
    assert canonical == expected
    notification_dump = json.dumps(notification.model_dump(mode="json"))
    assert canonical not in notification_dump
    assert notification.platform_user_id in notification_dump  # the platform id IS on the wire


async def test_tui_inbound_records_peppered_audit_row(postgres_url: str) -> None:
    """The inbound promotion lands a T3 row with a peppered platform_user_id hash."""
    captured: list[InboundMessageNotification] = []

    async def _sink(note: InboundMessageNotification) -> None:
        captured.append(note)

    session = TuiSession(notify=_sink)
    await session.consume_user_input("audit me")
    await session.flush_keystroke_batch()
    notification = captured[0]

    audit_writer, sm = await _build_audit_writer(postgres_url)
    await process_inbound_message(
        notification,
        identity_resolver=_RecordedResolver(),
        orchestrator=_RecordingOrchestrator(),
        burst_limiter=_Burst(),
        audit_writer=audit_writer,
        secret_broker=_Broker(),
    )

    async with sm() as db:
        rows = list(
            (
                await db.execute(
                    select(AuditEntry).where(AuditEntry.event == "comms.inbound.t3_promoted")
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    subject = rows[0].subject
    # The raw operator handle never lands on the row — only its keyed hash.
    assert notification.platform_user_id not in str(subject)
    assert subject["adapter_id"] == "tui"


# ---------------------------------------------------------------------------
# 2. outbound -> RichLog: dm renders, non-dm is refused defensively
# ---------------------------------------------------------------------------


async def test_tui_outbound_renders_to_plugin_richlog() -> None:
    """A dm outbound paints into the real AlfredTuiApp RichLog and acks delivered."""
    from textual.widgets import RichLog

    session = TuiSession()
    app = build_app(session)
    dlp = OutboundDlp(broker=_Broker(), audit=lambda **_: None)
    request = _outbound_request(dlp, mode="dm", text="PONG")

    async with app.run_test() as pilot:
        result = await handle_outbound_message(request, session=session)
        await pilot.pause()
        log = app.query_one("#conversation_log", RichLog)
        rendered = "\n".join(str(line) for line in log.lines)

    assert isinstance(result, _OutboundDelivered)
    assert result.outcome == "delivered"
    assert "PONG" in rendered


async def test_tui_outbound_refuses_non_dm_addressing_mode() -> None:
    """A non-dm mode escaping the host guard is refused with a terminal failure."""
    session = TuiSession()
    dlp = OutboundDlp(broker=_Broker(), audit=lambda **_: None)
    request = _outbound_request(dlp, mode="mention", text="should not render")

    result = await handle_outbound_message(request, session=session)

    assert isinstance(result, _OutboundTerminal)
    assert result.outcome == "terminal_failure"
    assert result.error_class == "tui_addressing_mode_not_supported"


# ---------------------------------------------------------------------------
# shared fixtures
# ---------------------------------------------------------------------------


def _outbound_request(dlp: OutboundDlp, *, mode: str, text: str) -> OutboundMessageRequest:
    import uuid

    return OutboundMessageRequest(
        adapter_id="tui",
        idempotency_key=uuid.uuid4(),
        target_platform_id="operator",
        body=dlp.scan_for_outbound(text),
        attachments_refs=(),
        addressing_mode=mode,  # type: ignore[arg-type]
    )
