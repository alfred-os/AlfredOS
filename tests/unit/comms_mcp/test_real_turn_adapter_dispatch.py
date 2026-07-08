"""Unit tests for :mod:`alfred.comms_mcp.real_turn_adapter` — Task 2 (#338 PR2).

Covers the ``dispatch`` leg: the pool-bracketed real turn (FOLD-3) + the
DLP-scanned send, the benign-reply / halt-no-reply short-circuits, the
BudgetError halt-no-raise leg, the turn-error audit-then-reraise leg, the
per-``(persona, slug)`` turn mutex (FOLD-R1, Critical), and the pre-bind
``RuntimeError`` (FOLD-R5). ``ingest`` / the downgrade leg are Task 1 scope —
not re-exercised here.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from alfred.budget.guard import BudgetError
from alfred.comms_mcp import audit_hash
from alfred.comms_mcp.real_turn_adapter import (
    RealTurnOrchestratorAdapter,
    _HaltNoReply,
    _InboundUser,
    _PreparedTurn,
    _RefusalReply,
)
from alfred.security.tiers import T2, tag
from tests.helpers.dlp import identity_outbound_dlp
from tests.helpers.gates import make_quarantined_extract_chain_gate


class _FakeAuditHashBroker:
    """Minimal broker satisfying ``audit_hash._BrokerLike`` for unit tests.

    FOLD-R12: the ``budget_denied`` / ``turn_error`` / ``send_failed`` legs all
    reach ``_emit_refused``, which hashes via ``audit_hash`` and raises
    ``MissingAuditHashPepperError`` fail-closed until ``set_broker`` runs (the
    daemon wires the real broker at ``inbound.py:707``). Mirrors the fixture in
    ``test_real_turn_adapter_ingest.py``.
    """

    def get(self, name: str) -> str:
        return "p" * 40


@pytest.fixture(autouse=True)
def _wire_audit_hash_pepper() -> object:
    audit_hash.set_broker_for_test(_FakeAuditHashBroker())
    yield
    audit_hash.reset_for_test()


class _RecordingSender:
    def __init__(self) -> None:
        self.sent: list[object] = []

    async def send_outbound(self, request):
        self.sent.append(request)
        return {}


class _RecordingAudit:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def append_schema(self, **kwargs: object) -> None:
        self.rows.append(dict(kwargs))


class _Pool:
    def __init__(self) -> None:
        self.acquired: list[object] = []
        self.released: list[object] = []

    async def acquire(self, key):
        self.acquired.append(key)
        return SimpleNamespace(key=key)

    async def release(self, key, wm) -> None:
        self.released.append(key)


class _Orchestrator:
    def __init__(self, *, answer: str | None = None, exc: Exception | None = None) -> None:
        self._answer = answer
        self._exc = exc
        self.calls: list[dict[str, object]] = []

    async def handle_user_message(self, *, user, content, working_memory, egress_context=None):
        self.calls.append({"user": user, "content": content, "egress": egress_context})
        if self._exc is not None:
            raise self._exc
        assert self._answer is not None
        return self._answer


def _prepared() -> _PreparedTurn:
    return _PreparedTurn(
        content=tag(T2, "hi alfred", source="comms.inbound"),
        user=_InboundUser(slug="u-1", display_name="Ada", language="en-US"),
        egress=SimpleNamespace(adapter_id="tui", inbound_id="ib-1", session_id="u-1"),  # type: ignore[arg-type]
        adapter_id="tui",
        target_platform_id="plat-9",
    )


def _adapter(*, orchestrator, audit=None, sender=None, pool=None):
    a = RealTurnOrchestratorAdapter(
        orchestrator=orchestrator,
        working_memory_pool=pool or _Pool(),
        gate=make_quarantined_extract_chain_gate(grant_downgrade_t3=True),
        audit_writer=audit or _RecordingAudit(),
        # FOLD-R9: a real broker-backed OutboundDlp — ``OutboundMessageRequest.body``
        # is a ``ScannedOutboundBody`` NewType a bare stand-in can't mint.
        outbound_dlp=identity_outbound_dlp(),
        extractor_bridge=SimpleNamespace(),
    )
    a.bind_outbound_sender(sender or _RecordingSender())
    return a


async def test_dispatch_prepared_runs_turn_and_sends_scanned_answer() -> None:
    orch = _Orchestrator(answer="Good evening, operator.")
    sender = _RecordingSender()
    pool = _Pool()
    adapter = _adapter(orchestrator=orch, sender=sender, pool=pool)
    await adapter.dispatch(_prepared())
    assert len(orch.calls) == 1
    assert orch.calls[0]["egress"] is not None  # the REAL egress context threaded (constraint 4)
    assert len(sender.sent) == 1
    assert sender.sent[0].body[0] == "Good evening, operator."  # DLP-scanned body
    assert pool.acquired == [("alfred", "u-1")]
    assert pool.released == [("alfred", "u-1")]


async def test_dispatch_refusal_sends_benign_reply() -> None:
    sender = _RecordingSender()
    adapter = _adapter(orchestrator=_Orchestrator(answer="unused"), sender=sender)
    await adapter.dispatch(
        _RefusalReply(reply="benign", adapter_id="tui", target_platform_id="plat-9")
    )
    assert len(sender.sent) == 1
    assert sender.sent[0].body[0] == "benign"


async def test_dispatch_halt_sends_nothing() -> None:
    sender = _RecordingSender()
    adapter = _adapter(orchestrator=_Orchestrator(answer="unused"), sender=sender)
    await adapter.dispatch(_HaltNoReply(stage="downgrade_denied"))
    assert sender.sent == []


async def test_dispatch_budget_error_audits_and_halts_no_reply_no_raise() -> None:
    audit = _RecordingAudit()
    sender = _RecordingSender()
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=BudgetError("over")), audit=audit, sender=sender, pool=pool
    )
    await adapter.dispatch(_prepared())  # must NOT raise
    assert sender.sent == []  # no reply leaked
    stages = [
        r["subject"]["refusal_stage"]
        for r in audit.rows
        if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ]
    assert stages == ["budget_denied"]
    assert pool.released == [("alfred", "u-1")]  # released in finally


async def test_dispatch_turn_error_audits_and_reraises() -> None:
    audit = _RecordingAudit()
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=RuntimeError("provider down")), audit=audit, pool=pool
    )
    with pytest.raises(RuntimeError):
        await adapter.dispatch(_prepared())
    stages = [
        r["subject"]["refusal_stage"]
        for r in audit.rows
        if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ]
    assert stages == ["turn_error"]
    assert pool.released == [("alfred", "u-1")]  # released in finally even on error


async def test_dispatch_send_failure_audits_send_failed_and_reraises() -> None:
    """FOLD-R11: a scan/send failure with turn context writes a loud ``send_failed``
    row (not silently dropped) then re-raises."""
    audit = _RecordingAudit()

    class _RaisingSender:
        async def send_outbound(self, request):
            raise ConnectionError("wire down")

    adapter = _adapter(
        orchestrator=_Orchestrator(answer="hi"), audit=audit, sender=_RaisingSender()
    )
    with pytest.raises(ConnectionError):
        await adapter.dispatch(_prepared())
    stages = [
        r["subject"]["refusal_stage"]
        for r in audit.rows
        if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ]
    assert stages == ["send_failed"]


async def test_dispatch_holds_turn_mutex_across_the_turn() -> None:
    """FOLD-R1 (Critical): the per-(persona, slug) lock is HELD for the WHOLE
    acquire -> handle_user_message -> release span, not released early — this is
    what stops two same-user frames from racing the shared WorkingMemory buffer.
    The harder concurrent-interleaving proof is Task 5's; this unit test pins that
    the mutex itself is engaged around the orchestrator call.
    """
    observed_locked: list[bool] = []
    adapter: RealTurnOrchestratorAdapter

    class _ObservingOrchestrator:
        async def handle_user_message(self, *, user, content, working_memory, egress_context=None):
            observed_locked.append(adapter._turn_locks[("alfred", "u-1")].locked())
            return "answer"

    adapter = _adapter(orchestrator=_ObservingOrchestrator())
    await adapter.dispatch(_prepared())

    assert observed_locked == [True]  # locked WHILE the turn ran
    assert adapter._turn_locks[("alfred", "u-1")].locked() is False  # released after


async def test_dispatch_before_bind_raises_runtime_error() -> None:
    """FOLD-R5: covers ``_require_sender``'s ``sender is None`` branch."""
    adapter = RealTurnOrchestratorAdapter(
        orchestrator=_Orchestrator(answer="unused"),
        working_memory_pool=_Pool(),
        gate=make_quarantined_extract_chain_gate(grant_downgrade_t3=True),
        audit_writer=_RecordingAudit(),
        outbound_dlp=identity_outbound_dlp(),
        extractor_bridge=SimpleNamespace(),
    )
    with pytest.raises(RuntimeError):
        await adapter.dispatch(_prepared())


async def test_dispatch_bad_ingested_raises_runtime_error() -> None:
    """Defensive branch: the ingest union is closed, but ``dispatch`` guards it."""
    adapter = _adapter(orchestrator=_Orchestrator(answer="unused"))
    with pytest.raises(RuntimeError):
        await adapter.dispatch(object())
