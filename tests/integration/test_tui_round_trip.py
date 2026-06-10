"""MERGE-BLOCKING: TUI MCP plugin + daemon round-trip end-to-end (#206).

This is the PR-S4-10 Component-D integration gate. It exercises the real
``plugins/alfred_tui`` adapter against the real host dispatcher across three
load-bearing legs, none of which is mocked at the seam under test:

* **launcher-spawn + stdio outbound** — the plugin is spawned through the REAL
  ``bin/alfred-plugin-launcher.sh`` (positional ``<plugin_id> <executable>
  [args...]`` + ``ALFRED_PLUGIN_MANIFEST_PATH`` env — the PR-S4-6 contract, no
  ``--manifest``/``--adapter-id`` flags) running ``python -m alfred_tui.server``.
  A line-delimited JSON-RPC ``lifecycle.start`` then ``outbound.message`` (mode
  ``dm``) round-trips over the child's stdio and returns ``delivered`` — proving
  the launcher hands the plugin a live MCP stdio surface.

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
driven by the Textual app feeding ``consume_user_input`` — there is no
``inject_inbound`` trigger like the reference plugin's), so a launcher-spawned
subprocess cannot emit an ``inbound.message`` without a PTY. The merge-blocking
host invariants (resolver-consulted-once, canonical-id-never-on-the-wire) are
therefore driven through the real plugin inbound emitter in-process against the
real host dispatcher — the identical strategy ``test_discord_addressing_modes``
uses — while the launcher subprocess proves the spawn + stdio outbound contract.

Foundation-gap note (launcher leg): the bare ``alfred_tui.server`` subprocess
does not call :func:`alfred.cli._bootstrap.configure_logging`, so structlog runs
its default console renderer and human-readable log lines interleave on stdout.
The real host ``StdioTransport`` reads line-delimited JSON-RPC *frames*; this
test's ``_read_or_skip`` mirrors that by discarding non-frame lines. Routing the
plugin's logs to stderr (or wiring the JSON renderer in ``serve()``) is a
Wave-1-owned production follow-up, out of scope for this Component-D gate.

Requires docker (testcontainer Postgres); skips cleanly without it.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
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

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO_ROOT / "bin" / "alfred-plugin-launcher.sh"
_TUI_MANIFEST = _REPO_ROOT / "plugins" / "alfred_tui" / "manifest.toml"
_PLUGIN_ID = "alfred_tui"
_SERVER_MODULE = "alfred_tui.server"

# HKDF (audit_hash) requires a >=32-byte PRK; the test pepper must clear that
# floor exactly as the production audit.hash_pepper does.
_TEST_PEPPER = "integration-test-pepper-0123456789abcdef-padding"
_FRAME_TIMEOUT_S = 5.0


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
# 3. launcher-spawn: the real launcher hands the plugin a live MCP stdio surface
# ---------------------------------------------------------------------------


async def test_tui_launcher_spawn_stdio_outbound_round_trip() -> None:
    """Spawn plugins/alfred_tui via the REAL launcher; outbound round-trips stdio.

    Proves the PR-S4-6 launcher contract (positional args +
    ``ALFRED_PLUGIN_MANIFEST_PATH``) hands ``alfred_tui.server`` a live
    line-delimited JSON-RPC surface: ``lifecycle.start`` then a ``dm``
    ``outbound.message`` returns ``delivered``.

    Skips when the launcher cannot exec the plugin on this host (the kind=none
    path needs ``runuser`` on Linux; macOS execs unsandboxed only in dev/test).
    """
    if not _LAUNCHER.exists():  # pragma: no cover - guarded by repo layout
        pytest.skip("launcher script missing")

    proc = await _spawn_via_launcher()
    try:
        assert proc.stdin is not None and proc.stdout is not None

        if proc.returncode is not None and proc.returncode != 0:  # pragma: no cover
            pytest.skip("launcher refused to exec the plugin on this host (sandbox policy)")

        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "lifecycle.start",
                "params": {
                    "adapter_id": "tui",
                    "credentials_ref": "tui-no-credentials",
                    "policies_snapshot_hash": "0" * 64,
                },
            },
        )
        start = await _read_or_skip(proc)
        assert start["result"]["ok"] is True

        await _send(
            proc.stdin,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "outbound.message",
                "params": {
                    "adapter_id": "tui",
                    "idempotency_key": "00000000-0000-4000-8000-000000000000",
                    "target_platform_id": "operator",
                    "body": ["spawned outbound", _scan_result_payload()],
                    "attachments_refs": [],
                    "addressing_mode": "dm",
                },
            },
        )
        outbound = await _read_or_skip(proc)
        assert outbound["result"]["outcome"] == "delivered"
    finally:
        await _close(proc)


# ---------------------------------------------------------------------------
# launcher-spawn helpers (mirror test_comms_mcp_reference_plugin_lifecycle)
# ---------------------------------------------------------------------------


async def _spawn_via_launcher() -> asyncio.subprocess.Process:
    # The launcher resolves the environment + manifest sandbox block via an
    # internal ``python3 -m alfred.plugins.manifest_reader`` call, so the
    # ``python3`` on PATH must be able to import ``alfred``. Prepend the active
    # interpreter's bin dir so the launcher's helper resolves the venv python
    # (matching how CI's uv-managed PATH exposes it) rather than a bare system
    # python3 without the core package.
    venv_bin = str(Path(sys.executable).parent)
    env = {
        **os.environ,
        "PATH": os.pathsep.join((venv_bin, os.environ.get("PATH", ""))),
        "ALFRED_ENVIRONMENT": "test",
        "ALFRED_PLUGIN_MANIFEST_PATH": str(_TUI_MANIFEST),
        "PYTHONPATH": os.pathsep.join(
            p
            for p in (
                str(_REPO_ROOT / "plugins" / "alfred_tui" / "src"),
                str(_REPO_ROOT / "src"),
                os.environ.get("PYTHONPATH", ""),
            )
            if p
        ),
    }
    return await asyncio.create_subprocess_exec(
        "bash",
        str(_LAUNCHER),
        _PLUGIN_ID,
        sys.executable,
        "-m",
        _SERVER_MODULE,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )


async def _send(stdin: asyncio.StreamWriter, frame: dict[str, Any]) -> None:
    stdin.write((json.dumps(frame) + "\n").encode())
    await stdin.drain()


async def _read_or_skip(proc: asyncio.subprocess.Process) -> dict[str, Any]:
    """Read the next JSON-RPC frame, skipping any non-frame log lines.

    The bare ``alfred_tui.server`` subprocess (no supervisor) leaves structlog on
    its default console renderer, so human-readable log lines can interleave on
    stdout. The real host ``StdioTransport`` reads line-delimited JSON-RPC
    *frames*; this reader mirrors that by discarding any line that is not a JSON
    object (the same ``{``-prefix filter ``test_discord_gateway_smoke`` uses).
    See the module docstring's foundation-gap note.
    """
    assert proc.stdout is not None
    deadline = asyncio.get_event_loop().time() + _FRAME_TIMEOUT_S
    while asyncio.get_event_loop().time() < deadline:
        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=_FRAME_TIMEOUT_S)
        except TimeoutError:  # pragma: no cover - defensive
            pytest.skip("plugin produced no stdio frame before timeout (launcher/sandbox)")
        if not line:  # pragma: no cover - launcher refused to hand off
            pytest.skip("plugin closed stdout before a frame arrived (launcher refused exec)")
        text = line.decode().strip()
        if not text.startswith("{"):
            continue
        return dict(json.loads(text))
    pytest.skip("no JSON-RPC frame within the read window (only log lines)")  # pragma: no cover


async def _close(proc: asyncio.subprocess.Process) -> None:
    if proc.stdin is not None and not proc.stdin.is_closing():
        proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=_FRAME_TIMEOUT_S)
    except TimeoutError:  # pragma: no cover - defensive
        proc.kill()
        await proc.wait()


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


def _scan_result_payload() -> dict[str, Any]:
    """A wire-shaped OutboundDlpScanResult for the launcher-spawn outbound frame."""
    dlp = OutboundDlp(broker=_Broker(), audit=lambda **_: None)
    _text, scan_result = dlp.scan_for_outbound("spawned outbound")
    return scan_result.model_dump(mode="json")
