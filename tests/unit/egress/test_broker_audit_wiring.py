"""Golive Task 10: wire the dormant ``EgressBrokerAuditor`` live.

Three regressions this file guards against (rev.2 fold carry-forwards #1 and #3;
carry-forward #2 is Task 9's transport-level wiring, already covered by
``tests/unit/security/test_quarantine_transport.py``):

1. **Undeclared hookpoint.** The pre-gate auditor's ``invoke()`` call targets
   ``egress.broker.connected`` / ``egress.broker.refused`` — neither event was
   declared in the strict hook registry before this task. A strict-mode
   ``invoke()`` on an undeclared event RAISES ``HookError`` (see
   ``alfred.hooks.invoke._enforce_subscribable_tiers``), so the auditor's first
   LIVE dispatch would fail-loud break without the declaration landing first.
2. **Auditor not threaded.** ``_build_comms_inbound_extractor`` must construct a
   real ``EgressBrokerAuditor`` and pass it to ``QuarantineStdioTransport`` as
   ``broker_auditor=`` — the transport (Task 9's design), NOT
   ``spawn_quarantine_child_io`` / ``_SubprocessChildIO``, is where the auditor
   lives; Task 9 already wired ``dispatch``'s success/failure call sites against
   an injected ``broker_auditor`` (defaulting to ``None``).
3. **Destination is a credential surface.** ``record_broker_success`` must
   receive ``host:port`` — never the proxy URL (no ``@`` userinfo, no ``//``
   scheme).
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from alfred.bootstrap.nonce_factory import _NONCE_LOCK
from alfred.egress.hookpoints import declare_hookpoints
from alfred.hooks.context import HookContext
from alfred.hooks.invoke import invoke
from alfred.hooks.registry import SYSTEM_ONLY_TIERS, HookRegistry, get_registry, set_registry
from alfred.security import tiers as _tiers
from alfred.security.tiers import CapabilityGateNonce, tag_t3_with_nonce
from tests.helpers.gates import make_permissive_fixture_gate

# ``declare_hookpoints`` is imported above at FILE TOP LEVEL (not deferred
# inside a test body) so pytest's collection phase — which imports every test
# module BEFORE any fixture ever swaps the registry singleton — fires this
# module's bottom-of-module ``declare_hookpoints()`` call while
# ``get_registry()`` is still the pristine default singleton. Mirrors
# ``tests/unit/comms_mcp/test_daemon_runtime.py``'s top-level
# ``from alfred.security.quarantine import ... declare_hookpoints``. A
# deferred (inside-test-body) import would make this module's FIRST-EVER
# import land under whichever test's scoped registry fixture happens to run
# first in the full suite — and since Python caches modules, every later
# import (including ``tests/unit/hooks/test_known_hookpoints_sync.py``'s
# ``importlib.import_module`` sweep) would silently no-op, leaving the sync
# test unable to see these hookpoints registered against ITS OWN active
# registry. Confirmed by reproduction: this exact failure occurred before
# this import was hoisted to file scope.

# ---------------------------------------------------------------------------
# Fixtures — mirrors tests/unit/hooks/conftest.py's strict_registry /
# tests/unit/egress/test_egress_response_extract.py's authorized_t3_nonce.
# Each test module keeps its own copy (fixtures are directory-scoped in this
# repo; see the six pre-existing duplicates of fresh_registry_allow_system).
# ---------------------------------------------------------------------------


@pytest.fixture
def strict_registry_allow_system() -> Iterator[HookRegistry]:
    """A strict-declarations registry (the production posture under #119).

    No subscribers register in these tests — the gate choice is irrelevant to
    the declared-hookpoint assertion, but ``allow_system=True`` mirrors the
    convention every other strict-registry test in this repo uses.
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=make_permissive_fixture_gate(allow_system=True),
        strict_declarations=True,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


@pytest.fixture
def authorized_t3_nonce() -> Iterator[CapabilityGateNonce]:
    """Install a fresh ``CapabilityGateNonce`` as the authorised T3-tagging slot."""
    with _NONCE_LOCK:
        previous = _tiers._AUTHORIZED_T3_NONCE
        nonce = CapabilityGateNonce()
        _tiers._set_authorized_t3_nonce(nonce)
    try:
        yield nonce
    finally:
        with _NONCE_LOCK:
            _tiers._set_authorized_t3_nonce(previous)


# ---------------------------------------------------------------------------
# 1. Hookpoints declared — strict-mode invoke() must not raise.
# ---------------------------------------------------------------------------


async def test_broker_hookpoints_are_declared(
    strict_registry_allow_system: HookRegistry,
) -> None:
    """``egress.broker.connected`` / ``egress.broker.refused`` are declared.

    Regression for carry-forward #1: before this task neither event was
    registered anywhere, so this same call would raise
    ``alfred.hooks.errors.HookError`` (dispatch-time "undeclared hookpoint in
    strict mode").
    """
    declare_hookpoints(strict_registry_allow_system)

    for event in ("egress.broker.connected", "egress.broker.refused"):
        ctx: HookContext[dict[str, object]] = HookContext(
            action_id=event,
            hookpoint=event,
            input={},
            correlation_id="test-correlation",
            kind="post",
        )
        # Must not raise — this is the EXACT (kind, subscribable_tiers,
        # fail_closed) shape EgressBrokerAuditor._write dispatches with.
        result = await invoke(
            event,
            ctx,
            kind="post",
            subscribable_tiers=SYSTEM_ONLY_TIERS,
            fail_closed=True,
        )
        assert result is not None


# ---------------------------------------------------------------------------
# 2. The auditor is threaded onto the TRANSPORT, not spawn_quarantine_child_io.
# ---------------------------------------------------------------------------


class _EgressCfg:
    """Minimal ``EgressProxyConfig``-shaped stub (structural, PEP 544).

    Mirrors ``tests/unit/comms_mcp/test_daemon_runtime.py``'s local double — a
    real value is required because ``_build_comms_inbound_extractor`` validates
    ``egress_config.egress_proxy_url`` PRE-spawn (``_resolve_egress_config``);
    a bare ``MagicMock()`` would fail that validation before reaching the
    transport-construction line this test targets.
    """

    def __init__(self, egress_proxy_url: str | None = "http://alfred-gateway:8889") -> None:
        self.egress_proxy_url = egress_proxy_url


class _AcloseOnlyChildIO:
    """Minimal ``ChildIO`` double — only ``aclose`` is exercised.

    The transport constructor is monkeypatched to raise immediately below, so
    ``_build_comms_inbound_extractor``'s except-arm reaps the child via
    ``child_io.aclose()`` without ever touching ``broker_sockets`` /
    ``write_frame`` / ``read_frame``.
    """

    def __init__(self) -> None:
        self.aclose_calls = 0

    async def aclose(self) -> None:
        self.aclose_calls += 1

    def abort(self) -> None:  # pragma: no cover - not exercised (never reaches revoke)
        return None


async def test_auditor_is_threaded_into_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_build_comms_inbound_extractor`` constructs an ``EgressBrokerAuditor``
    and passes it as ``broker_auditor=`` into ``QuarantineStdioTransport`` —
    NOT into ``spawn_quarantine_child_io`` (the brief's stale Step-3 path; Task
    9 never put the auditor on ``_SubprocessChildIO``).

    The transport constructor is patched at its SOURCE module
    (``alfred.security.quarantine_transport.QuarantineStdioTransport``) to
    capture its kwargs and raise — mirroring
    ``test_build_extractor_reaps_child_when_transport_construction_fails`` in
    ``tests/unit/comms_mcp/test_daemon_runtime.py``.
    """
    from alfred.comms_mcp.daemon_runtime import _build_comms_inbound_extractor
    from alfred.egress.broker_audit import EgressBrokerAuditor
    from alfred.security.dlp import OutboundDlp
    from alfred.security.quarantine_transport import QuarantineStagingMap

    broker = MagicMock()
    broker.has = MagicMock(return_value=True)
    broker.get = MagicMock(return_value="real-quarantine-provider-key")
    audit_sink = MagicMock()
    outbound_dlp = OutboundDlp(broker=broker, audit=audit_sink)
    audit_writer = MagicMock()

    spawned: list[_AcloseOnlyChildIO] = []

    async def _fake_spawn(
        *, provider_key: str, refusal_recorder: object = None, **_golive: object
    ) -> _AcloseOnlyChildIO:
        child = _AcloseOnlyChildIO()
        spawned.append(child)
        return child

    monkeypatch.setattr(
        "alfred.security.quarantine_child_io.spawn_quarantine_child_io", _fake_spawn
    )

    seen: dict[str, Any] = {}

    def _capturing_transport_ctor(
        *, child_io: object, staging: object, broker_auditor: object = None
    ) -> object:
        seen["broker_auditor"] = broker_auditor
        raise RuntimeError("stop after capturing kwargs")

    # Patched at the SOURCE module — the builder imports it lazily by that
    # path (mirrors the existing transport-construction-failure test).
    monkeypatch.setattr(
        "alfred.security.quarantine_transport.QuarantineStdioTransport",
        _capturing_transport_ctor,
    )

    with pytest.raises(RuntimeError, match="stop after capturing kwargs"):
        await _build_comms_inbound_extractor(
            audit_writer=audit_writer,
            outbound_dlp=outbound_dlp,
            secret_broker=broker,
            staging=QuarantineStagingMap(),
            environment="production",
            egress_config=_EgressCfg(),
        )

    auditor = seen["broker_auditor"]
    assert isinstance(auditor, EgressBrokerAuditor)
    # The auditor is bound to the SAME audit_writer the builder received —
    # not a fresh/default one.
    assert auditor._audit is audit_writer
    # The child was reaped despite the construction failure (no fd leak).
    assert len(spawned) == 1
    assert spawned[0].aclose_calls == 1


# ---------------------------------------------------------------------------
# 3. Destination is host:port — never the proxy URL (no userinfo, no scheme).
# ---------------------------------------------------------------------------


class _RecordingBrokerAuditor:
    """Fake ``EgressBrokerAuditor`` recording every ``record_broker_success`` call."""

    def __init__(self) -> None:
        self.successes: list[str] = []

    async def record_broker_success(
        self, *, destination: str, extraction_id: str, socket_ordinal: int
    ) -> None:
        self.successes.append(destination)

    async def record_broker_failure(
        self, *, destination: str, reason: str, extraction_id: str
    ) -> None:
        raise AssertionError("not exercised by this test")


class _FakeBrokeringChildIO:
    """``ChildIO`` double whose ``broker_sockets`` returns a fixed destination list."""

    def __init__(self, destinations: list[tuple[str, int]], reply: bytes) -> None:
        self._destinations = destinations
        self._reply = reply

    async def broker_sockets(self, count: int) -> list[tuple[str, int]]:
        return list(self._destinations)

    def write_frame(self, frame: bytes) -> None:
        return None

    async def read_frame(self) -> bytes:
        return self._reply

    async def aclose(self) -> None:  # pragma: no cover - not exercised here
        return None

    def abort(self) -> None:  # pragma: no cover - not exercised (never reaches revoke)
        return None


def _extracted_reply_frame() -> bytes:
    import json

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "result": {
                "kind": "extracted",
                "data": {"text": "hello", "intent": "greeting"},
                "extraction_mode": "native_constrained",
            },
        }
    ).encode("utf-8")
    return struct.pack(">I", len(body)) + body


async def test_success_row_destination_is_host_port_not_url(
    authorized_t3_nonce: CapabilityGateNonce,
) -> None:
    """``record_broker_success`` receives ``"gw:8889"`` — no ``@``, no ``//``.

    Drives ``QuarantineStdioTransport.dispatch`` (Task 9's real call site) with
    a fake ``broker_sockets`` returning ``[("gw", 8889)]`` and a recording
    auditor double, per the golive brief's carry-forward #3 regression test.
    """
    from typing import cast

    from alfred.egress.broker_audit import EgressBrokerAuditor
    from alfred.security.quarantine_transport import QuarantineStagingMap, QuarantineStdioTransport

    staging = QuarantineStagingMap()
    staging.stage(
        "deadbeef",
        tag_t3_with_nonce("hello there", source="test", caller_token=authorized_t3_nonce),
    )
    auditor = _RecordingBrokerAuditor()
    child = _FakeBrokeringChildIO(destinations=[("gw", 8889)], reply=_extracted_reply_frame())
    # QuarantineStdioTransport.__init__ types broker_auditor as the concrete
    # EgressBrokerAuditor class (not a Protocol) — the fake only needs to satisfy
    # dispatch's structural use (record_broker_success/record_broker_failure; the runtime
    # code never does an isinstance check). Mirrors
    # tests/unit/security/test_quarantine_transport.py's `_staged_transport(auditor: Any)`
    # escape for the identical fake-vs-concrete-class mismatch. Since #340 review A5 the
    # argument is REQUIRED (no None default), so every caller must supply one.
    transport = QuarantineStdioTransport(
        child_io=child, staging=staging, broker_auditor=cast(EgressBrokerAuditor, auditor)
    )

    await transport.dispatch(
        "quarantine.extract",
        {"handle_id": "deadbeef", "schema_json": "{}", "schema_version": 1},
    )

    assert auditor.successes == ["gw:8889"]
    for destination in auditor.successes:
        assert "@" not in destination
        assert "//" not in destination
