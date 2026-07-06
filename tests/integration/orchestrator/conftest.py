"""Shared fixtures + helpers for ``tests/integration/orchestrator/`` (#339 PR3 FIX-12).

Extracted from ``test_tool_assembly.py`` (#339 PR2 Task 7) so
``test_act_loop_real_chain.py`` (#339 PR3 Task 5) can reuse the SAME
migrated-Postgres / Redis / authorized-nonce / composed-gate / loopback-relay
harness without re-deriving it — a second hand-rolled copy risks drifting
from the ``dispatch_tool`` three-grant composition (CLAUDE.md hard rule #2:
never a permissive shim for a security-gated assertion).

The three fixtures below (``migrated_url``, ``redis_url``,
``authorized_t3_nonce``) and the autouse ``_shutdown_default_executor`` are
pytest fixtures — directory-scoped ``conftest.py`` fixtures are auto-
discovered by every test module in this directory, no import needed. The
two plain helpers (``_settings``, ``_assembly_gate``) and the
``boot_loopback_relay`` async context manager are NOT fixtures — pytest has
no auto-discovery for plain callables, so callers import them explicitly::

    from tests.integration.orchestrator.conftest import (
        _assembly_gate,
        _settings,
        boot_loopback_relay,
    )
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from testcontainers.redis import RedisContainer

from alfred.config.settings import Settings
from alfred.gateway.egress_relay import EgressRelay
from alfred.gateway.egress_relay_audit import record_egress_relay
from alfred.hooks.capability import CapabilityGate
from alfred.security.canary_matcher import CanaryMatcher
from alfred.security.capability_gate._bootstrap_grants import FIRST_PARTY_SYSTEM_GRANTS
from alfred.security.capability_gate._gate import RealGate
from alfred.security.capability_gate.policy import GatePolicy
from alfred.security.dlp import OutboundDlp
from tests.helpers.egress_doubles import (
    _await_relay_ready,
    _CannedResponse,
    _FireCounter,
    make_fake_external_world,
)
from tests.helpers.gates import (
    _make_in_memory_backend,
    _make_no_op_audit_sink,
    make_tool_dispatch_gate,
)


@pytest.fixture(autouse=True)
async def _shutdown_default_executor() -> Any:
    # The C2 pre-extract seam runs ``inspect_response`` via ``asyncio.to_thread``;
    # reap the default executor so no worker thread outlives the test loop.
    yield
    await asyncio.get_running_loop().shutdown_default_executor()


@pytest.fixture
def migrated_url(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    from alembic import command, config

    monkeypatch.setenv("ALFRED_DATABASE_URL", postgres_url)
    cfg = config.Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")
    return postgres_url


@pytest.fixture
def redis_url() -> Iterator[str]:
    with RedisContainer("redis:8-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"


@pytest.fixture
def authorized_t3_nonce() -> Any:
    """Install a fresh CapabilityGateNonce as the authorised slot."""
    from alfred.bootstrap.nonce_factory import _NONCE_LOCK
    from alfred.security import tiers as _tiers
    from alfred.security.tiers import CapabilityGateNonce

    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


def _settings(monkeypatch: pytest.MonkeyPatch, *, relay_url: str) -> Settings:
    monkeypatch.setenv("ALFRED_DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setenv("ALFRED_ENVIRONMENT", "test")
    return Settings(egress_relay_url=relay_url)


def _assembly_gate() -> CapabilityGate:
    """Compose ``make_tool_dispatch_gate()``'s two grants with the THIRD grant
    the real fetch+extract quarantine chain needs on the SAME shared gate — see
    the module docstring. Built from the exact grant set
    ``make_tool_dispatch_gate()`` returns (no re-derivation / drift risk) plus
    one additional ``GrantRow``, mirroring the composed-gate precedent in
    ``tests/integration/cli/daemon/test_chat_gateway_socket_turn.py``.

    The third grant (``quarantine.dereference``) is DERIVED from
    ``FIRST_PARTY_SYSTEM_GRANTS`` rather than hand-rolled — that constant now
    seeds the exact same row at boot (see
    ``src/alfred/security/capability_gate/_bootstrap_grants.py``), so
    sourcing it here means the test fixture and production seed can never
    drift apart on ``plugin_id`` / ``subscriber_tier`` / ``hookpoint`` /
    ``content_tier`` (the fields the gate actually matches on —
    ``proposal_branch`` is an audit-trail field only, so borrowing
    production's value here is harmless).
    """
    base = make_tool_dispatch_gate()
    assert isinstance(base, RealGate)
    dereference_grant = next(
        (g for g in FIRST_PARTY_SYSTEM_GRANTS if g.hookpoint == "quarantine.dereference"),
        None,
    )
    assert dereference_grant is not None, (
        "quarantine.dereference grant missing from FIRST_PARTY_SYSTEM_GRANTS"
    )
    grants = set(base._policy.grants)
    grants.add(dereference_grant)
    frozen_grants = frozenset(grants)
    return RealGate(
        policy=GatePolicy(grants=frozen_grants),
        backend=_make_in_memory_backend(grants=frozen_grants),
        audit_sink=_make_no_op_audit_sink(),
    )


@asynccontextmanager
async def boot_loopback_relay(
    *,
    allowlist: frozenset[tuple[str, int]],
) -> AsyncIterator[tuple[EgressRelay, int, _FireCounter, _CannedResponse]]:
    """Boot a real loopback ``EgressRelay`` with a faked upstream client.

    Yields ``(relay, port, fire_counter, canned)``:

    * ``relay`` — the live ``EgressRelay`` instance (rarely needed directly;
      callers mostly care that it's up and serving on ``port``).
    * ``port`` — the bound loopback port; construct ``Settings(egress_relay_url=
      f"tcp://127.0.0.1:{port}")`` (via :func:`_settings`) to point a
      ``build_tool_registry`` assembly at it.
    * ``fire_counter`` — increments once per upstream round-trip; assert on it
      to prove the relay did (or did not) fire.
    * ``canned`` — the mutable canned-response holder. Set ``canned.body``
      BEFORE the first dispatch to control what the faked upstream serves
      (e.g. Task 5's FIX-11 containment-regression marker).

    On exit (including on an exception propagating through the ``async
    with`` block) the relay is signalled to shut down and its serve task is
    awaited with a 5s timeout — mirrors the inline try/finally dance
    ``test_tool_assembly.py`` used before this extraction.
    """
    open_client_factory, fire_counter, canned = make_fake_external_world()

    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port: int = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()

    gateway_dlp = OutboundDlp(
        broker=None, audit=lambda **_kw: None, canary=CanaryMatcher(tokens=[])
    )
    relay = EgressRelay(
        tool_allowlist=allowlist,
        dlp=gateway_dlp,
        audit=record_egress_relay,
        bind_host="127.0.0.1",
        port=port,
        resolve=lambda _h: "1.1.1.1",
        open_client=open_client_factory,
        response_byte_cap=4096,
        upstream_deadline_s=10.0,
    )
    shutdown = asyncio.Event()
    serve_task: asyncio.Task[Any] = asyncio.ensure_future(relay.serve(shutdown))
    try:
        await _await_relay_ready(port, serve_task)
    except BaseException:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
        raise

    try:
        yield relay, port, fire_counter, canned
    finally:
        shutdown.set()
        await asyncio.wait_for(serve_task, timeout=5)
