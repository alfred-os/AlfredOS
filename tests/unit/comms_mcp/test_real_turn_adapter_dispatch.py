"""Unit tests for :mod:`alfred.comms_mcp.real_turn_adapter` — Task 2 (#338 PR2).

Covers the ``dispatch`` leg: the pool-bracketed real turn (FOLD-3) + the
DLP-scanned send, the benign-reply / halt-no-reply short-circuits, the
BudgetError halt-no-raise leg, the OutboundCanaryTripped halt-no-raise leg
(#410 PR3 — final-review I4 fix), the turn-error audit-then-reraise leg, the
per-``(persona, slug)`` turn mutex (FOLD-R1, Critical), and the pre-bind
``RuntimeError`` (FOLD-R5). ``ingest`` / the downgrade leg are Task 1 scope —
not re-exercised here.
"""

from __future__ import annotations

import asyncio
import contextlib
from types import SimpleNamespace
from typing import get_args

import pytest
import structlog.testing

from alfred.budget.guard import BudgetError
from alfred.comms_mcp import audit_hash
from alfred.comms_mcp import real_turn_adapter as real_turn_adapter_mod
from alfred.comms_mcp.protocol import TurnFailedNotification
from alfred.comms_mcp.real_turn_adapter import (
    RealTurnOrchestratorAdapter,
    _client_turn_failure_stage,
    _HaltNoReply,
    _InboundUser,
    _PreparedTurn,
    _RefusalReply,
    _RefusalStage,
)
from alfred.security.canary_matcher import CanaryMatcher, CanaryToken
from alfred.security.dlp import OutboundCanaryTripped, OutboundDlp
from alfred.security.tiers import T2, tag
from tests.helpers.dlp import identity_outbound_dlp
from tests.helpers.gates import make_quarantined_extract_chain_gate
from tests.unit.comms_mcp._real_turn_adapter_doubles import (
    _adapter,
    _FakeAuditHashBroker,
    _Orchestrator,
    _Pool,
    _prepared,
    _RecordingAudit,
    _RecordingSender,
)


@pytest.fixture(autouse=True)
def _wire_audit_hash_pepper() -> object:
    audit_hash.set_broker_for_test(_FakeAuditHashBroker())
    yield
    audit_hash.reset_for_test()


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
    await adapter.dispatch(_HaltNoReply(stage="downgrade_denied", adapter_id="tui"))
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


async def test_dispatch_canary_tripped_audits_and_halts_no_reply_no_raise() -> None:
    """#410 PR3 (I4 fix): an ``OutboundCanaryTripped`` out of ``dispatch_tool`` is
    DETERMINISTIC (same content trips the same canary every replay) — like
    ``BudgetError`` above, it must halt (no reply, no re-raise) rather than fall
    into the generic ``turn_error`` leg, which would re-raise into the forwarded
    path's bounded-replay handling and burn the poison ceiling reproducing an
    identical trip. Inert today (``clock.now`` can't embed a canary token); this
    pins the classification ahead of `web.fetch` (#583) making it load-bearing.
    """
    audit = _RecordingAudit()
    sender = _RecordingSender()
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=OutboundCanaryTripped(token="canary-token-1")),  # noqa: S106
        audit=audit,
        sender=sender,
        pool=pool,
    )
    await adapter.dispatch(_prepared())  # must NOT raise
    assert sender.sent == []  # no reply leaked
    stages = [
        r["subject"]["refusal_stage"]
        for r in audit.rows
        if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ]
    assert stages == ["dlp_canary_tripped"]
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

        async def send_turn_state(self, notification):
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


async def test_dispatch_refusal_send_failure_reraises_without_audit() -> None:
    """A send failure on the ``_RefusalReply`` leg has NO turn context to audit.

    Covers the ``notification is None`` / ``canonical_user_id is None`` arm of
    ``_send``'s except block (the ``ingest``-leg refusal reply carries no
    notification/canonical_user_id — only the forwarded/direct dispatch-error
    handlers in ``process_inbound_message`` see this failure). The adapter
    re-raises WITHOUT writing a ``send_failed`` row (there is no turn to
    attribute it to) — distinct from ``test_dispatch_send_failure_audits_...``
    above, which drives the ``_PreparedTurn`` leg where turn context exists.
    """
    audit = _RecordingAudit()

    class _RaisingSender:
        async def send_outbound(self, request):
            raise ConnectionError("wire down")

        async def send_turn_state(self, notification):
            raise ConnectionError("wire down")

    adapter = _adapter(
        orchestrator=_Orchestrator(answer="unused"), audit=audit, sender=_RaisingSender()
    )
    with pytest.raises(ConnectionError):
        await adapter.dispatch(
            _RefusalReply(reply="benign", adapter_id="tui", target_platform_id="plat-9")
        )
    refusal_rows = [
        r for r in audit.rows if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ]
    assert refusal_rows == []  # no turn context -> no adapter-owned audit row


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


async def test_turn_lock_for_reuses_existing_lock_for_same_key() -> None:
    """``_turn_lock_for``'s get-or-create: a SECOND call for the same key REUSES
    the lock (the ``lock is not None`` branch), never minting a second one that
    would let two same-key turns bypass each other."""
    adapter = _adapter(orchestrator=_Orchestrator(answer="first"))
    await adapter.dispatch(_prepared())  # first call -> creates the lock (dict was empty)

    key = ("alfred", "u-1")
    created_lock = adapter._turn_locks[key]
    assert len(adapter._turn_locks) == 1

    await adapter.dispatch(_prepared())  # second call, SAME key -> must reuse it

    assert len(adapter._turn_locks) == 1  # no second entry minted
    assert adapter._turn_locks[key] is created_lock  # the SAME lock object


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


# ---------------------------------------------------------------------------
# #593: client-visible turn-failure notify wiring (Task 12)
# ---------------------------------------------------------------------------


class _RaisingSendOutboundSender:
    """``send_outbound`` always fails; ``send_turn_state`` RECORDS (never raises).

    Used to prove the ``send_failed`` leg never even attempts a notify call —
    a sender that raised on ``send_turn_state`` too (like ``_RaisingSender``
    above) couldn't distinguish "notify not called" from "notify called and
    its exception was swallowed".
    """

    def __init__(self) -> None:
        self.turn_states_sent: list[object] = []

    async def send_outbound(self, request: object) -> dict[str, object]:
        raise ConnectionError("wire down")

    async def send_turn_state(self, notification: object) -> None:
        self.turn_states_sent.append(notification)


class _WireFaultOnNotifySender:
    """``send_outbound`` succeeds (records); ``send_turn_state`` raises a given
    fault every time. Parameterises the class-of-fault so the "logged, halt
    still returns", "does not replace the turn-error reraise" and (#594 R1)
    "an UNEXPECTED, non-wire exception is contained just the same" tests can
    each drive their own exception class through one double."""

    def __init__(self, fault: Exception) -> None:
        self.sent: list[object] = []
        self._fault = fault

    async def send_outbound(self, request: object) -> dict[str, object]:
        self.sent.append(request)
        return {}

    async def send_turn_state(self, notification: object) -> None:
        raise self._fault


class _CancelledOnNotifySender:
    """``send_outbound`` records; ``send_turn_state`` raises ``CancelledError``.

    Distinct from ``_WireFaultOnNotifySender``: ``CancelledError`` derives from
    ``BaseException``, so ``_notify_turn_failed``'s containment (a bare
    ``except Exception`` since #594 R1) structurally cannot catch it — it must
    fall through both ``except`` clauses and propagate, rather than being
    logged-and-swallowed the way every ``Exception`` is.
    """

    def __init__(self) -> None:
        self.sent: list[object] = []

    async def send_outbound(self, request: object) -> dict[str, object]:
        self.sent.append(request)
        return {}

    async def send_turn_state(self, notification: object) -> None:
        raise asyncio.CancelledError


class _HangingNotifySender:
    """``send_turn_state`` never completes — proves the notify bound fires."""

    def __init__(self) -> None:
        self.sent: list[object] = []

    async def send_outbound(self, request: object) -> dict[str, object]:
        self.sent.append(request)
        return {}

    async def send_turn_state(self, notification: object) -> None:
        await asyncio.sleep(10)  # far longer than any test-scoped timeout


async def test_dispatch_halt_notifies_client_turn_failed() -> None:
    sender = _RecordingSender()
    adapter = _adapter(orchestrator=_Orchestrator(answer="unused"), sender=sender)
    await adapter.dispatch(_HaltNoReply(stage="downgrade_denied", adapter_id="tui"))
    assert sender.sent == []  # still no TEXT reply
    assert sender.turn_states_sent == [TurnFailedNotification(stage="refused")]


async def test_dispatch_budget_error_notifies_budget_exhausted() -> None:
    sender = _RecordingSender()
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=BudgetError("over")), sender=sender, pool=pool
    )
    await adapter.dispatch(_prepared())  # must NOT raise
    assert sender.turn_states_sent == [TurnFailedNotification(stage="budget_exhausted")]


async def test_dispatch_canary_tripped_notifies_refused_not_the_control_name() -> None:
    """#593 anti-oracle proof: an ``OutboundCanaryTripped`` must never leak the
    control name onto the wire. The client only ever sees the coarse ``refused``
    stage — the literal string ``"canary"`` must appear NOWHERE in the sent frame.
    """
    sender = _RecordingSender()
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=OutboundCanaryTripped(token="canary-token-1")),  # noqa: S106
        sender=sender,
        pool=pool,
    )
    await adapter.dispatch(_prepared())  # must NOT raise
    assert len(sender.turn_states_sent) == 1
    notification = sender.turn_states_sent[0]
    assert notification.stage == "refused"
    assert "canary" not in notification.model_dump_json().lower()  # anti-oracle


async def test_dispatch_turn_error_notifies_then_still_reraises() -> None:
    sender = _RecordingSender()
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=RuntimeError("provider down")), sender=sender, pool=pool
    )
    with pytest.raises(RuntimeError):
        await adapter.dispatch(_prepared())
    assert sender.turn_states_sent == [TurnFailedNotification(stage="internal_error")]


async def test_dispatch_send_failure_does_not_notify() -> None:
    """#593: the ``send_failed`` leg deliberately does NOT notify (see the
    comment in ``_send``'s except block) — the send that just failed used the
    SAME wire, so a notify down it is near-certain to fail too, and this leg
    re-raises, so a late-succeeding retry could deliver the real answer AFTER a
    false turn-failed signal."""
    sender = _RaisingSendOutboundSender()
    adapter = _adapter(orchestrator=_Orchestrator(answer="hi"), sender=sender)
    with pytest.raises(ConnectionError):
        await adapter.dispatch(_prepared())
    assert sender.turn_states_sent == []


async def test_notify_wire_failure_is_logged_and_does_not_break_the_halt() -> None:
    """A ``send_turn_state`` wire fault on the ``budget_denied`` halt leg is
    LOGGED and swallowed — ``dispatch`` still returns cleanly (no reply leaked,
    no exception propagates)."""
    sender = _WireFaultOnNotifySender(BrokenPipeError("client hung up"))
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=BudgetError("over")), sender=sender, pool=pool
    )
    with structlog.testing.capture_logs() as captured:
        await adapter.dispatch(_prepared())  # must NOT raise
    assert sender.sent == []
    assert any(
        entry.get("event") == "comms.inbound.real_turn.turn_failed_notify_failed"
        and entry.get("log_level") == "warning"
        and entry.get("error_class") == "BrokenPipeError"
        for entry in captured
    ), captured


async def test_notify_wire_failure_does_not_replace_the_turn_error_reraise() -> None:
    """A wire fault out of the notify call on the ``turn_error`` leg must NOT
    replace the ORIGINAL turn exception: it is caught+logged INSIDE
    ``_notify_turn_failed`` (never escapes it), so the ``raise`` in ``dispatch``
    still re-raises the real fault, not a transport exception."""
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=RuntimeError("provider down")),
        sender=_WireFaultOnNotifySender(OSError("client socket gone")),
        pool=pool,
    )
    with pytest.raises(RuntimeError, match="provider down"):
        await adapter.dispatch(_prepared())


async def test_unexpected_notify_exception_does_not_replace_the_turn_error() -> None:
    """#594 R1 (err-001 Half B): an exception the notify path never anticipated
    must be contained exactly like a wire fault, not substituted for the turn's
    OWN exception.

    ``_notify_turn_failed`` documents "NEVER raises", and ``dispatch``'s
    ``turn_error`` leg relies on that IN PROSE when it notifies and then
    re-raises ``outcome.reraise``. Before this fix the containment was a fixed
    four-member wire-fault tuple, so anything outside it — a ``ValidationError``
    from building the notification, a bug in a sender implementation, the
    ``ValueError`` stood in for here — escaped and REPLACED the real turn
    fault. That hands the forwarded path's bounded-replay machinery a transport
    exception instead of the fault it is supposed to act on; on a
    ``_HaltNoReply`` leg it would convert an already-audited deterministic halt
    into a re-raise, burning the poison ceiling on duplicate PAID completions.
    """
    sender = _WireFaultOnNotifySender(ValueError("a sender bug nobody anticipated"))
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=RuntimeError("provider down")),
        sender=sender,
        pool=_Pool(),
    )
    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises(RuntimeError, match="provider down"),
    ):
        await adapter.dispatch(_prepared())
    assert any(
        entry.get("event") == "comms.inbound.real_turn.turn_failed_notify_failed"
        and entry.get("log_level") == "warning"
        and entry.get("error_class") == "ValueError"
        for entry in captured
    ), captured


async def test_notify_turn_failed_lets_cancelled_error_propagate() -> None:
    """``CancelledError`` must propagate out of ``_notify_turn_failed`` uncaught
    (#594 Fix-4). The containment there is deliberately over ``Exception`` and
    never ``BaseException`` — precisely so a caller-level task cancellation
    (e.g. the daemon shutting down mid-turn) that lands while ``send_turn_state``
    is in-flight actually cancels the notify, rather than being silently caught
    and logged like an ordinary fault. This test is what keeps #594 R1's
    widening (from a narrow wire-fault tuple to bare ``except Exception``) from
    quietly becoming ``except BaseException``.

    Called directly (mirroring
    ``test_notify_turn_failed_skips_non_notifiable_stage_directly`` below)
    with a NOTIFIABLE stage (``budget_denied`` -> client stage
    ``budget_exhausted``) so execution actually reaches the
    ``await asyncio.wait_for(sender.send_turn_state(...))`` call rather than
    short-circuiting on the ``client_stage is None`` guard.
    """
    sender = _CancelledOnNotifySender()
    adapter = _adapter(orchestrator=_Orchestrator(answer="unused"), sender=sender)
    with pytest.raises(asyncio.CancelledError):
        await adapter._notify_turn_failed(sender, adapter_id="tui", stage="budget_denied")


async def test_notify_timeout_is_bounded_and_does_not_hang_the_halt(monkeypatch) -> None:
    """A wedged-but-connected client (``send_turn_state`` never returns) must
    not hold the halt leg hostage — ``asyncio.wait_for``'s bound fires and the
    halt still returns promptly."""
    monkeypatch.setattr(real_turn_adapter_mod, "_NOTIFY_TIMEOUT_SECONDS", 0.01)
    sender = _HangingNotifySender()
    adapter = _adapter(orchestrator=_Orchestrator(answer="unused"), sender=sender)
    with structlog.testing.capture_logs() as captured:
        await adapter.dispatch(_HaltNoReply(stage="downgrade_denied", adapter_id="tui"))
    assert any(
        entry.get("event") == "comms.inbound.real_turn.turn_failed_notify_timeout"
        for entry in captured
    ), captured


class _EventGatedHangingNotifySender:
    """``send_outbound`` records; ``send_turn_state`` signals ``notify_started``
    then hangs until cancelled.

    Lets a test wait DETERMINISTICALLY (no sleep-loop polling) for ``dispatch``
    to have reached — and be blocked inside — the notify call, so it can then
    assert on state that must already be true by that point (perf-001, PR #594).
    """

    def __init__(self) -> None:
        self.sent: list[object] = []
        self.notify_started = asyncio.Event()

    async def send_outbound(self, request: object) -> dict[str, object]:
        self.sent.append(request)
        return {}

    async def send_turn_state(self, notification: object) -> None:
        self.notify_started.set()
        await asyncio.sleep(10)  # far longer than any test-scoped timeout


async def test_dispatch_releases_lock_before_notify_wire_wait_on_budget_denied() -> None:
    """perf-001 (PR #594): the ``budget_denied`` halt leg's up-to-2s notify wire
    wait must NOT hold the per-(persona, slug) turn mutex. Drives a hanging
    ``send_turn_state`` and proves the lock is already free — and
    ``_pool.release`` has already run — WHILE ``dispatch`` is still blocked
    inside the (never-completing) notify call.
    """
    sender = _EventGatedHangingNotifySender()
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=BudgetError("over")), sender=sender, pool=pool
    )
    task = asyncio.create_task(adapter.dispatch(_prepared()))
    try:
        await asyncio.wait_for(sender.notify_started.wait(), timeout=1.0)
        # `dispatch` is now parked inside the hanging notify call — prove the
        # lock already released and the working-memory buffer already returned,
        # i.e. WITHOUT waiting for (let alone the full 2.0s of) the notify.
        assert pool.released == [("alfred", "u-1")]
        assert adapter._turn_locks[("alfred", "u-1")].locked() is False
        assert not task.done()  # confirms we really caught it mid-notify
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_dispatch_releases_lock_before_notify_wire_wait_on_turn_error() -> None:
    """Same proof as above for the trickier ``turn_error`` leg, which notifies
    THEN re-raises: the lock must release (and the re-raise must not yet have
    happened) while ``dispatch`` is still parked inside the notify call —
    confirming the reraise, like the notify, now runs only after the mutex
    (and the ``finally: await self._pool.release(...)`` it wraps) has cleared.
    """
    sender = _EventGatedHangingNotifySender()
    pool = _Pool()
    adapter = _adapter(
        orchestrator=_Orchestrator(exc=RuntimeError("provider down")), sender=sender, pool=pool
    )
    task = asyncio.create_task(adapter.dispatch(_prepared()))
    try:
        await asyncio.wait_for(sender.notify_started.wait(), timeout=1.0)
        assert pool.released == [("alfred", "u-1")]
        assert adapter._turn_locks[("alfred", "u-1")].locked() is False
        assert not task.done()  # the RuntimeError has not been re-raised yet
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


class _OrderProvingOrchestrator:
    """Turn 1's ``handle_user_message`` call parks mid-processing (holding the
    per-key turn lock) until explicitly released; turn 2's call proceeds
    immediately once it gets to run. Distinguishes the two turns by
    ``content.content`` — ``_PreparedTurn.content`` is a ``TaggedContent[T2]``,
    not a bare string.
    """

    def __init__(self) -> None:
        self.turn_1_started = asyncio.Event()
        self.release_turn_1 = asyncio.Event()

    async def handle_user_message(self, *, user, content, working_memory, egress_context=None):
        if content.content == "turn 1":
            self.turn_1_started.set()
            await self.release_turn_1.wait()
            raise BudgetError("turn 1 over budget")
        return "turn 2 answer"


class _OrderRecordingSender:
    """Records BOTH ``send_outbound`` and ``send_turn_state`` calls into ONE
    ordered log, so cross-call-type ordering (an earlier turn's ``turn.failed``
    notify vs a later turn's reply send) can be asserted directly rather than
    inferred from two separate lists.
    """

    def __init__(self) -> None:
        self.events: list[tuple[str, object]] = []

    async def send_outbound(self, request: object) -> dict[str, object]:
        self.events.append(("send", request))
        return {}

    async def send_turn_state(self, notification: object) -> None:
        self.events.append(("notify", notification))


def _prepared_with_content(text: str) -> _PreparedTurn:
    """Same shape as ``_prepared()`` but with distinguishable content, for a
    test that needs to tell two SAME-key turns apart via a shared
    orchestrator double."""
    return _PreparedTurn(
        content=tag(T2, text, source="comms.inbound"),
        user=_InboundUser(slug="u-1", display_name="Ada", language="en-US"),
        egress=SimpleNamespace(adapter_id="tui", inbound_id="ib-1", session_id="u-1"),  # type: ignore[arg-type]
        adapter_id="tui",
        target_platform_id="plat-9",
    )


async def test_dispatch_notifies_same_key_turns_in_submission_order_even_when_concurrent() -> None:
    """Cross-module proof for a client-side assumption (#594 follow-up finding).

    ``AlfredTuiApp._resolve_pending_turn`` (``plugins/alfred_tui/src/alfred_tui/
    textual/app.py``) treats a stale/late completion signal for a
    watchdog-abandoned turn as arriving strictly BEFORE a later, genuinely
    still-pending turn's own signal — with NO wire-level correlation of any
    kind available to actually distinguish them. That assumption rests
    entirely on THIS module: the per-``(persona, slug)`` turn lock (FOLD-R1)
    serializes two same-key turns' PROCESSING, and — since PR #594's
    lock-boundary move — the notify/send call for each turn only starts AFTER
    that turn's own ``async with lock:`` block has exited, with no ``await``
    in between. See the matching contract comment on ``dispatch`` /
    ``_TurnFailed`` / ``_TurnSucceeded`` above: do not add an ``await``
    between lock release and notify/send initiation, and do not loosen the
    per-key lock to allow same-key concurrency, without revisiting this test
    and the TUI's debt-counter design.

    This test dispatches turn 1 (fails -> ``send_turn_state``) and turn 2
    (succeeds -> ``send_outbound``) for the SAME key, with turn 1 deliberately
    parked mid-processing (via an event-gated orchestrator double) so it is
    still holding the lock when turn 2's ``dispatch()`` call is issued and
    genuinely blocks on lock acquisition — proving turn 2 cannot jump the
    queue, not merely that it happens not to in an untimed race. Both a
    ``send_turn_state`` and a ``send_outbound`` call are used (rather than two
    of the same kind) so the assertion covers ordering ACROSS the two sender
    methods, matching the real notify-then-reply shape a stale-turn-then-
    live-turn sequence produces in production.
    """
    sender = _OrderRecordingSender()
    orchestrator = _OrderProvingOrchestrator()
    pool = _Pool()
    adapter = _adapter(orchestrator=orchestrator, sender=sender, pool=pool)

    task_1 = asyncio.create_task(adapter.dispatch(_prepared_with_content("turn 1")))
    await asyncio.wait_for(orchestrator.turn_1_started.wait(), timeout=1.0)

    # Turn 1 is now parked mid-processing, holding the per-key lock. Issue
    # turn 2's dispatch call WHILE turn 1 is still in flight.
    task_2 = asyncio.create_task(adapter.dispatch(_prepared_with_content("turn 2")))
    await asyncio.sleep(0)  # let turn 2's dispatch run up to the lock and block on it
    assert not task_2.done(), "turn 2 must genuinely block on the lock, not race ahead"
    assert sender.events == [], "neither turn may have signaled the sender yet"

    orchestrator.release_turn_1.set()
    await asyncio.gather(task_1, task_2)

    assert [kind for kind, _ in sender.events] == ["notify", "send"], (
        "turn 1's completion signal must reach the sender strictly before "
        "turn 2's, even though turn 2's dispatch was already in flight and "
        "waiting on the lock"
    )
    notify = sender.events[0][1]
    assert notify.stage == "budget_exhausted"
    sent = sender.events[1][1]
    assert sent.body[0] == "turn 2 answer"  # DLP-scanned body, index 0 is the text


async def test_notify_skipped_for_non_client_adapter_kind() -> None:
    """``adapter_id="discord"`` is not in ``TURN_STATE_CLIENT_KINDS`` — the
    debug-log-and-skip arm fires and NOTHING is sent to it."""
    sender = _RecordingSender()
    adapter = _adapter(orchestrator=_Orchestrator(answer="unused"), sender=sender)
    await adapter.dispatch(_HaltNoReply(stage="downgrade_denied", adapter_id="discord"))
    assert sender.turn_states_sent == []


async def test_notify_turn_failed_skips_non_notifiable_stage_directly() -> None:
    """Defensive completeness: ``_notify_turn_failed`` handles EVERY
    ``_RefusalStage`` value generically, including ``send_failed`` (whose
    mapped client stage is ``None``) even though no production call site ever
    passes it that stage (the ``send_failed`` leg deliberately never calls this
    helper — see ``_send``'s except block). A direct call proves the
    ``client_stage is None`` short-circuit is safe/inert on its own rather than
    leaving it gated by the file's 100% coverage requirement but unexercised.
    """
    sender = _RecordingSender()
    adapter = _adapter(orchestrator=_Orchestrator(answer="unused"), sender=sender)
    await adapter._notify_turn_failed(sender, adapter_id="tui", stage="send_failed")
    assert sender.turn_states_sent == []


def test_client_turn_failure_stage_is_total_over_refusal_stage() -> None:
    """Every member of the real ``_RefusalStage`` maps without hitting
    ``assert_never`` — the exhaustiveness guarantee ``_client_turn_failure_stage``
    exists to provide (a future refusal stage added without a client decision
    must be a type-check failure here, never a silent drop)."""
    assert {stage: _client_turn_failure_stage(stage) for stage in get_args(_RefusalStage)} == {
        "downgrade_denied": "refused",
        "dlp_canary_tripped": "refused",
        "budget_denied": "budget_exhausted",
        "downgrade_malformed": "internal_error",
        "dlp_scan_failed": "internal_error",
        "turn_error": "internal_error",
        "send_failed": None,
    }


# ---------------------------------------------------------------------------
# #594 R1 Fix C2: `_send`'s DLP-scan leg is classified separately from the wire.
#
# `scan_for_outbound` runs strictly BEFORE any wire write, so the wire is still
# healthy there — a client notify is deliverable and honest, unlike on the
# send leg. And an `OutboundCanaryTripped` in the FINAL answer is the same
# DETERMINISTIC event the `dispatch_tool` arm already halts on (#410 PR3's I4
# fix wave); before this split it fell into the blanket handler, was audited
# under the TRANSPORT `send_failed` stage, and re-raised — burning the
# forwarded-replay ceiling re-tripping the identical canary on identical
# content. Inert today (`canary=None` is the core default).
# ---------------------------------------------------------------------------


class _RaisingScanDlp:
    """``scan_for_outbound`` raises a NON-canary infrastructure fault.

    Stands in for a broker/vault blip inside DLP stage 1 — the one clean case
    the root-cause investigation found where the wire is healthy and, before
    Fix C2, nothing was ever sent to the client.
    """

    def __init__(self, fault: Exception) -> None:
        self._fault = fault

    def scan_for_outbound(self, raw_body: str) -> object:
        raise self._fault


def _canary_tripping_dlp(token: str) -> OutboundDlp:
    """A REAL ``OutboundDlp`` whose stage-3 matcher trips on ``token``.

    Deliberately the real class with a real :class:`CanaryMatcher` rather than
    a double that just raises: the point of the test is the classification of
    the exception ``OutboundDlp`` itself raises out of ``_scan_stages``, so a
    hand-raised stand-in could pass while the production wiring diverged.
    """

    class _IdentityBroker:
        def redact(self, text: str) -> str:
            return text

    def _sink(*, event: str, subject: object) -> None:
        return None

    return OutboundDlp(
        broker=_IdentityBroker(),
        audit=_sink,  # type: ignore[arg-type]
        canary=CanaryMatcher(tokens=[CanaryToken(value=token)]),
    )


async def test_canary_trip_on_the_final_answer_audits_dlp_canary_tripped_and_halts() -> None:
    """A canary in the persona's ANSWER is a security event, not a transport fault.

    It must land in the forensic log under ``dlp_canary_tripped`` (matching the
    ``dispatch_tool`` arm), notify the client with the COARSE ``refused`` stage,
    send no body, and — critically — NOT re-raise, so the forwarded path commits
    the frame instead of replaying an identical trip up to the poison ceiling.
    """
    audit = _RecordingAudit()
    sender = _RecordingSender()
    adapter = _adapter(
        orchestrator=_Orchestrator(answer="here is your answer: canary-token-1"),
        audit=audit,
        sender=sender,
        outbound_dlp=_canary_tripping_dlp("canary-token-1"),
    )

    await adapter.dispatch(_prepared())  # must NOT raise — deterministic halt

    assert sender.sent == []  # the canary'd body never egressed
    stages = [
        r["subject"]["refusal_stage"]
        for r in audit.rows
        if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ]
    assert stages == ["dlp_canary_tripped"], (
        "a canary trip in the final answer must NOT be audited as a transport "
        "`send_failed` — that misattributes a successful indirect prompt "
        "injection and takes the replay path"
    )
    assert len(sender.turn_states_sent) == 1
    notification = sender.turn_states_sent[0]
    assert notification.stage == "refused"
    assert "canary" not in notification.model_dump_json().lower()  # anti-oracle


async def test_dlp_scan_failure_notifies_the_client_but_a_wire_send_failure_does_not() -> None:
    """The two legs of ``_send`` differ in exactly one thing: is the wire alive?

    Both halves in one test so the CONTRAST is what is pinned, not two
    independent facts that could drift apart. The scan leg (wire healthy,
    nothing written yet) audits ``dlp_scan_failed``, notifies, and re-raises for
    the forwarded replay; the send leg (wire just failed) keeps its deliberate
    ``send_failed`` + NO-notify posture.
    """
    scan_audit = _RecordingAudit()
    scan_sender = _RecordingSender()
    scan_adapter = _adapter(
        orchestrator=_Orchestrator(answer="hi"),
        audit=scan_audit,
        sender=scan_sender,
        outbound_dlp=_RaisingScanDlp(RuntimeError("vault unreachable")),
    )
    with pytest.raises(RuntimeError, match="vault unreachable"):
        await scan_adapter.dispatch(_prepared())
    assert scan_sender.sent == []
    assert [
        r["subject"]["refusal_stage"]
        for r in scan_audit.rows
        if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ] == ["dlp_scan_failed"]
    assert scan_sender.turn_states_sent == [TurnFailedNotification(stage="internal_error")], (
        "the scan runs before any wire write, so the client CAN and MUST be told"
    )

    send_audit = _RecordingAudit()
    send_sender = _RaisingSendOutboundSender()
    send_adapter = _adapter(
        orchestrator=_Orchestrator(answer="hi"), audit=send_audit, sender=send_sender
    )
    with pytest.raises(ConnectionError):
        await send_adapter.dispatch(_prepared())
    assert [
        r["subject"]["refusal_stage"]
        for r in send_audit.rows
        if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ] == ["send_failed"]
    assert send_sender.turn_states_sent == [], (
        "the send leg's no-notify design is unchanged (C1): the same wire just "
        "failed, and a later successful replay could deliver the real answer "
        "after a false turn-failed signal"
    )


async def test_dlp_scan_failure_on_the_refusal_reply_leg_notifies_without_an_audit_row() -> None:
    """``ingest``'s ``_RefusalReply`` leg carries no turn context to attribute to.

    Same no-turn-context arm as ``test_dispatch_refusal_send_failure_reraises_
    without_audit`` covers for the send leg: no adapter-owned refusal row (the
    inbound path audits it on the forwarded edge), but the client notify still
    fires — it only needs the ``adapter_id``, which this leg does have.
    """
    audit = _RecordingAudit()
    sender = _RecordingSender()
    adapter = _adapter(
        orchestrator=_Orchestrator(answer="unused"),
        audit=audit,
        sender=sender,
        outbound_dlp=_RaisingScanDlp(RuntimeError("vault unreachable")),
    )
    with pytest.raises(RuntimeError, match="vault unreachable"):
        await adapter.dispatch(
            _RefusalReply(reply="benign", adapter_id="tui", target_platform_id="plat-9")
        )
    assert [
        r for r in audit.rows if r.get("schema_name") == "COMMS_INBOUND_TURN_REFUSED_FIELDS"
    ] == []
    assert sender.turn_states_sent == [TurnFailedNotification(stage="internal_error")]
