"""Shared test doubles for ``RealTurnOrchestratorAdapter.dispatch`` tests.

These doubles were originally private to ``test_real_turn_adapter_dispatch.py``
and are re-used by the adversarial corpus's executable counterpart
(``tests/adversarial/comms_identity_boundary/test_cib_corpus_executable.py``,
cib-2026-009) so that entry drives the SAME real ``dispatch()`` boundary
rather than reimplementing an independent double set that could silently
drift from the unit tests' own wiring. Extracted here — matching the
``_inbound_spies.py`` convention in this same directory — so neither test
module reaches into the other's ``test_*.py`` file, and the cross-file
dependency is documented rather than implicit.

``_RecordingAudit`` is not one of the names the corpus test imports directly,
but it is ``_adapter()``'s default ``audit_writer`` (``audit or
_RecordingAudit()``) — it has to live here too, or ``_adapter`` couldn't be
extracted without either a reverse import back into a ``test_*.py`` module or
changing its default-argument behaviour for every existing call site in
``test_real_turn_adapter_dispatch.py``.
"""

from __future__ import annotations

from types import SimpleNamespace

from alfred.comms_mcp.real_turn_adapter import (
    RealTurnOrchestratorAdapter,
    _InboundUser,
    _PreparedTurn,
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


class _RecordingSender:
    def __init__(self) -> None:
        self.sent: list[object] = []
        self.turn_states_sent: list[object] = []

    async def send_outbound(self, request):
        self.sent.append(request)
        return {}

    async def send_turn_state(self, notification):
        self.turn_states_sent.append(notification)


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


def _adapter(*, orchestrator, audit=None, sender=None, pool=None, outbound_dlp=None):
    a = RealTurnOrchestratorAdapter(
        orchestrator=orchestrator,
        working_memory_pool=pool or _Pool(),
        gate=make_quarantined_extract_chain_gate(grant_downgrade_t3=True),
        audit_writer=audit or _RecordingAudit(),
        # FOLD-R9: a real broker-backed OutboundDlp — ``OutboundMessageRequest.body``
        # is a ``ScannedOutboundBody`` NewType a bare stand-in can't mint. The
        # ``outbound_dlp`` override exists for the #594 R1 Fix C2 scan-leg tests,
        # which need a scanner that genuinely trips or genuinely faults.
        outbound_dlp=outbound_dlp or identity_outbound_dlp(),
        extractor_bridge=SimpleNamespace(),
    )
    a.bind_outbound_sender(sender or _RecordingSender())
    return a


def _unbound_adapter(*, orchestrator):
    """Sibling to ``_adapter()`` for the pre-``bind_outbound_sender`` shape.

    Deliberately skips the ``bind_outbound_sender`` call ``_adapter()`` always
    makes — for the FOLD-R5 sender-unbound tests
    (``test_dispatch_before_bind_raises_runtime_error``,
    ``test_halt_no_reply_with_no_bound_sender_halts_loudly_without_raising``,
    ``test_refusal_reply_with_no_bound_sender_still_raises``), which need
    ``self._sender is None`` at dispatch time. Extracted (arc-001, PR #594
    Task S1) once a third call site inlined the same 7-line construction.
    """
    return RealTurnOrchestratorAdapter(
        orchestrator=orchestrator,
        working_memory_pool=_Pool(),
        gate=make_quarantined_extract_chain_gate(grant_downgrade_t3=True),
        audit_writer=_RecordingAudit(),
        outbound_dlp=identity_outbound_dlp(),
        extractor_bridge=SimpleNamespace(),
    )
