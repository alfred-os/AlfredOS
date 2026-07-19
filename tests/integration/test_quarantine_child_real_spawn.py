"""DOCKER-ONLY: the REAL bwrap-sandboxed quarantined child over the host transport.

PR-S4-11c-2b0 (#237, ADR-0030) — the dual-LLM trust boundary proven against a
REAL spawned child. This is the proof the unit + macOS legs cannot give: a real
``alfred.security.quarantine_child`` subprocess, spawned through
``bin/alfred-plugin-launcher.sh`` (``sandbox.kind="full"`` → bwrap), reachable
because the child now ships in the wheel under the policy's ``/usr`` ro-bind, with
its provider key delivered over fd 3, drives a full ingest → extract round trip:

    T3BodyRecorder (tag T3 + stage) -> QuarantineStdioTransport
      -> quarantine.ingest{handle_id, body} -> bwrapped child caches it
      -> quarantine.extract{handle_id, schema} -> child pops + echoes
      -> ControlResult -> QuarantinedExtractor lift -> post-stage DLP scan
      -> quarantine.extract audit row (result="extracted")

DIRECT-SPAWN SHAPE (NOT the daemon flip). This precursor PR (2b0) does NOT flip
the production daemon — it keeps the ADR-0027 fixture extractor (the final 2b
flip is a separate PR). So this test constructs the machinery DIRECTLY, exactly
like the 2a ``test_quarantine_transport_real.py`` BUT with
``child_io = await spawn_quarantine_child_io(...)`` in place of the in-test
``_EchoingChildDouble``. The ONLY thing that changes versus 2a is the child-IO
seam: a real bwrapped subprocess instead of an in-proc double. No daemon, no boot
graph, no production-flip dependency.

The child runs the DETERMINISTIC echo loop (PR-S4-11c-2b — no real LLM; 2c swaps
in the model): it caches the ``quarantine.ingest`` body and replies to
``quarantine.extract`` by echoing it. The ``result="extracted"`` audit row only
lands AFTER the host lifts that reply into an ``Extracted`` result + runs the
post-stage DLP scan — so a child that never spawned / never replied would time
out at ``read_frame`` (QuarantineChildSpawnError) and no row would land.

WHY DOCKER-ONLY: ``sandbox.kind="full"`` resolves to bwrap on Linux; the spawn
needs ``bwrap`` present, a Linux kernel, AND root (the reference launcher path +
the bwrap unshares). It SKIPS on macOS / non-root CI. Run it in
``docker run --rm --privileged debian:bookworm`` (verified: bubblewrap 0.8.0
installs there) — see procedural_local_docker_for_ci_only_failures in project
memory. The docker harness MUST set ``ALFRED_QUARANTINE_CHILD_PYTHON=/usr/bin/
python3`` and ``pip install`` ``alfred`` into THAT interpreter (the bound-
interpreter contract, ADR-0030): the wheel-co-located child resolves off
``/usr/bin/python3``'s site-packages, which the policy's ``/usr`` ro-bind covers.
A uv-venv ``sys.executable`` is a symlink outside any bound path and fails
``execvp`` under bwrap — hence the override.
"""

from __future__ import annotations

import os
import shutil
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
from alfred.security.quarantine_child_io import spawn_quarantine_child_io
from alfred.security.quarantine_transport import (
    QuarantineStagingMap,
    QuarantineStdioTransport,
    T3BodyRecorder,
)
from alfred.security.tiers import CapabilityGateNonce
from tests.helpers.gates import make_quarantined_extract_chain_gate

pytestmark = pytest.mark.integration

_INBOUND_BODY = "hello from the real bwrap quarantine child"

# DOCKER-ONLY guard: bwrap + Linux + root. Run in
# ``docker run --rm --privileged debian:bookworm`` (bubblewrap 0.8.0) with
# ``ALFRED_QUARANTINE_CHILD_PYTHON=/usr/bin/python3`` + ``alfred`` pip-installed
# into that interpreter (ADR-0030 bound-interpreter contract).
_HAS_BWRAP = shutil.which("bwrap") is not None
# Provisioning signal (ADR-0030): a real bwrap spawn needs the child importable
# under bwrap (alfred installed into the bound interpreter's site-packages) AND a
# bound real interpreter whose install prefix the launcher binds read-only into
# the sandbox — both supplied when the harness sets ``ALFRED_QUARANTINE_CHILD_PYTHON``.
# The standard CI integration leg runs under the uv venv (interpreter symlinked
# OUTSIDE any bound prefix), so this SKIPS there rather than failing.
# #248 wired this into the privileged-Linux CI leg (`integration-privileged` in
# ci.yml): a hermetic proto-managed `~/.proto/tools/python/3.14.*` (NOT a system /
# deadsnakes /usr python) with `alfred` installed via `uv pip install --python`,
# and `ALFRED_QUARANTINE_CHILD_PYTHON` threaded into the root pytest run — the
# launcher binds that `~/.proto` prefix into the sandbox (ADR-0030), so this test
# now RUNS (not skips) in CI and gates merge.
_PROVISIONED = bool(os.environ.get("ALFRED_QUARANTINE_CHILD_PYTHON"))
_DOCKER_ONLY = pytest.mark.skipif(
    not _HAS_BWRAP or os.uname().sysname != "Linux" or os.geteuid() != 0 or not _PROVISIONED,
    reason=(
        "real bwrap quarantine-child spawn: needs bwrap + Linux + root + the "
        "ADR-0030 bound-interpreter provisioning (ALFRED_QUARANTINE_CHILD_PYTHON set, "
        "alfred installed into that interpreter). RUNS + gates merge on BOTH "
        "privileged-Linux CI legs (`integration-privileged` on amd64 and "
        "`integration-privileged-arm64` on aarch64 — #269); skipped on macOS / "
        "non-root / unprovisioned local boxes. Reproduce in `docker run --rm "
        "--privileged --platform linux/<arch>` with a bound py3.14 — use "
        "`linux/arm64` on an Apple-Silicon host (amd64 emulation fails there with "
        "`exec format error` without qemu binfmt), `linux/amd64` on an x86-64 host."
    ),
)


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


@pytest.mark.skip(
    reason=(
        "#340 golive: deterministic-echo removed; the real-extract integration proof is "
        "rebuilt in Task 14 with a canned-Anthropic TLS stub + control_fd + spawn env. "
        "This test spawns __main__ WITHOUT control_fd/model/max_tokens env and asserts "
        "the child ECHOES the inbound body (result.data['text'] == _INBOUND_BODY), which "
        "the cutover makes impossible: main() now unconditionally reconstructs fd 4 and "
        "_build_provider requires ALFRED_QUARANTINE_MODEL/ALFRED_QUARANTINE_MAX_TOKENS. "
        "Task 14 re-greens this under the #245 assert-RAN gate."
    )
)
@_DOCKER_ONLY
@pytest.mark.asyncio
async def test_real_bwrap_quarantine_child_round_trip_over_real_transport(
    postgres_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A REAL bwrapped child echoes the inbound body + a quarantine.extract row lands.

    Identical to the 2a real-transport proof EXCEPT the child-IO seam is a REAL
    bwrap-sandboxed subprocess (``spawn_quarantine_child_io``) rather than the
    in-proc ``_EchoingChildDouble``. Asserts: the body crossed the wire (the live
    child echoed it back), the extractor lifted a real :class:`Extracted`, the
    post-stage DLP subscriber ran, and the ``quarantine.extract`` audit row landed
    with ``result="extracted"``. No daemon, no production flip — the machinery is
    constructed directly.
    """
    # The launcher resolves the kind="full" bwrap policy from ALFRED_ENVIRONMENT
    # (manifest_reader --read-environment). In production the daemon sets it; with
    # no daemon here the test must, mirroring the conftest launcher fixture + the
    # smoke daemon-spawn tests (ALFRED_ENVIRONMENT=test). spawn_quarantine_child_io
    # forwards it into the SCRUBBED child env via the allowlisted _scrubbed_base();
    # without it the launcher refuses with environment_not_set and the child exits
    # before replying, surfacing as a truncated read_frame. "test" still bwraps the
    # kind="full" linux child (the env only gates the kind="none" / non-Linux paths).
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    # Scoped RealGate registry granting exactly the system-tier DLP grant the
    # post-stage subscriber needs — a production gate with a fixture grant, never
    # an always-allow shim (CLAUDE.md hard rule #2).
    prior_registry = get_registry()
    with _NONCE_LOCK:
        prior_nonce = _tiers._AUTHORIZED_T3_NONCE

    child_io = None
    try:
        # Global registry + nonce mutations live INSIDE the try so an exception here
        # (e.g. declare_hookpoints raising) still restores them in `finally` rather
        # than leaking scoped global state into the next test.
        scoped_registry = HookRegistry(
            gate=make_quarantined_extract_chain_gate(), strict_declarations=False
        )
        set_registry(scoped_registry)
        declare_hookpoints(scoped_registry)
        with _NONCE_LOCK:
            nonce = CapabilityGateNonce()
            _tiers._set_authorized_t3_nonce(nonce)

        async with _audit_writer(postgres_url) as (audit, sm):
            from unittest.mock import AsyncMock, MagicMock

            broker = MagicMock()
            broker.redact = MagicMock(side_effect=lambda x: x)
            audit_sink = MagicMock()
            audit_sink.emit = AsyncMock()
            outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)

            staging = QuarantineStagingMap()
            # THE difference from 2a: a REAL bwrap-sandboxed child over fd 3. The
            # provider key is a placeholder — the 2b deterministic-echo child reads
            # + scrubs it but makes NO LLM call, so no broker / real key is needed.
            child_io = await spawn_quarantine_child_io(
                provider_key="quarantine-key-2b0-placeholder"
            )
            transport = QuarantineStdioTransport(child_io=child_io, staging=staging)
            extractor = QuarantinedExtractor(
                transport=transport,
                audit_writer=audit,
                outbound_dlp=outbound_dlp,
            )
            recorder = T3BodyRecorder(nonce=nonce, staging=staging)
            bridge = CommsExtractorBridge(extractor=extractor, record_body=recorder)

            result = await bridge.extract(
                body=_INBOUND_BODY,
                canonical_user_id="alice",
                source_tier="T3",
            )

            # The body crossed the wire to the REAL child + was echoed back.
            assert isinstance(result, Extracted)
            assert result.data["text"] == _INBOUND_BODY

            rows = await _rows_with_event(sm, "quarantine.extract")
            assert len(rows) == 1
            assert rows[0].result == "extracted"
    finally:
        if child_io is not None:
            await child_io.aclose()
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(prior_nonce)
        set_registry(prior_registry)
