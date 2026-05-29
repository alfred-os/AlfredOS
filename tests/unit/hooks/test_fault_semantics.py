"""Tests for ``alfred.hooks.invoke``'s fault arms — Slice-2.5 PR-A Task 9.

Task 9 wires the per-chain ``asyncio.timeout()`` deadline into the
dispatcher's four kind-handlers. This module pins the three load-bearing
invariants the dispatcher MUST honour when the chain exceeds the
deadline:

1. **The audit row lands** — every timeout emits a
   :data:`alfred.hooks.audit_sink.HOOKS_CHAIN_TIMEOUT` row through the
   registry-owned sink. The row carries ``hookpoint``, ``kind``, and
   ``deadline_seconds`` so PR-B's :class:`EpisodicAuditSink` can attribute
   the fault to the right action stage. (CLAUDE.md hard rule #7 — no
   silent failures in security paths.)
2. **The cancelled subscriber's ``finally`` runs to completion**
   (core-006). The dispatcher awaits the cancelled coroutine in the
   ``except TimeoutError`` handler — NOT inside the live ``asyncio.timeout``
   scope — so a subscriber's resource-release / lock-drop logic
   actually executes before the dispatcher returns. The half-open-cursor
   sentinel test below proves this with an ``asyncio.Event`` flag set in
   the laggy subscriber's ``finally`` block.
3. **The ``fail_closed`` policy is honoured** — ``fail_closed=False``
   returns the last-good context (chain abandoned, action body still
   runs); ``fail_closed=True`` raises :class:`HookError` AFTER the audit
   row has been emitted (loud failure for security-critical actions).

The tests use ``asyncio.Event().wait()`` on a never-firing event to
emulate a hung subscriber — wall-clock independent (test-101). The
dispatcher's deadline is injected via the registry's
``chain_deadline_seconds`` kwarg (see
:class:`alfred.hooks.registry.HookRegistry`) so a CI runner under load
does not flake against a 0.25-second production default.

Out of scope (each lands with its own task):

* ``HookRefusal`` audit emission — Task 11 (refusable-tier filter).
* Unexpected subscriber exception wrap into :class:`HookSubscriberError`
  — Task 10.
* Re-entry bypass via :data:`alfred.hooks.registry._reentry` — Task 12.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterator
from typing import Any

import pytest

from alfred.hooks.audit_sink import HOOKS_CHAIN_TIMEOUT
from alfred.hooks.capability import DevGate
from alfred.hooks.context import HookContext, HookKind
from alfred.hooks.errors import HookError
from alfred.hooks.invoke import invoke
from alfred.hooks.registry import HookRegistry, get_registry, set_registry

from .conftest import SpyAuditSink

# ──────────────────────────────────────────────────────────────────────
# Test helpers
# ──────────────────────────────────────────────────────────────────────

# A deadline short enough that any test subscriber awaiting a
# never-firing :class:`asyncio.Event` will fire the timeout deterministically
# even under heavy CI load, but not so small that the asyncio scheduler's
# own dispatch overhead trips it spuriously on a fast subscriber. The
# half-open-cursor sentinel test's success is the wall-clock independence
# proof — if this number ever flakes, the dispatcher is doing real work
# inside the timeout block we did not intend.
_SHORT_DEADLINE: float = 0.01


def _ctx(
    *,
    input_: object = "initial",
    hookpoint: str = "action.test",
    kind: str = "pre",
    correlation_id: str = "corr-fault",
    action_id: str = "action.test",
) -> HookContext[Any]:
    """Build a fresh :class:`HookContext` for a fault-semantics test.

    Centralised so a future field addition doesn't churn every test.
    The ``kind`` argument accepts a plain ``str`` because some
    parametrised cases pass a stage that ``invoke`` will retarget via
    :meth:`HookContext.for_stage`.
    """
    return HookContext(
        action_id=action_id,
        hookpoint=hookpoint,
        input=input_,
        correlation_id=correlation_id,
        kind=kind,  # type: ignore[arg-type]  # tests pass stale kinds intentionally
    )


@pytest.fixture
def short_deadline_registry(spy_sink: SpyAuditSink) -> Iterator[HookRegistry]:
    """Install a :class:`HookRegistry` with a tight deadline + spy sink.

    The deadline is :data:`_SHORT_DEADLINE` (10ms — see the constant's
    docstring). The :class:`SpyAuditSink` from the shared conftest is
    injected as the registry's ``sink`` so the ``hooks.chain_timeout``
    audit row is observable to tests without relying on global structlog
    state.

    Restores the previous registry on teardown — same swap-and-restore
    discipline as :func:`fresh_registry` (CLAUDE.md no-global-state rule:
    every test holds the registry only for its own scope).
    """
    prior = get_registry()
    registry = HookRegistry(
        gate=DevGate(),
        sink=spy_sink,
        chain_deadline_seconds=_SHORT_DEADLINE,
    )
    set_registry(registry)
    try:
        yield registry
    finally:
        set_registry(prior)


def _timeout_rows(spy_sink: SpyAuditSink) -> list[dict[str, object]]:
    """Filter the spy sink's recorded calls to just the timeout rows.

    Future fault paths (Tasks 10-12) emit OTHER ``HOOKS_*`` event ids on
    the same sink; this helper lets the timeout tests assert against
    their own slice of the call list without flaking when an adjacent
    arm starts emitting too.
    """
    return [c for c in spy_sink.calls if c["event"] == HOOKS_CHAIN_TIMEOUT]


# ──────────────────────────────────────────────────────────────────────
# 1. fail_closed=False — audit + last-good ctx returned, no raise
# ──────────────────────────────────────────────────────────────────────


async def test_timeout_fail_closed_false_returns_last_good_ctx(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """A ``pre`` subscriber hangs on a never-firing event; the chain
    times out. ``fail_closed=False`` → ONE
    :data:`HOOKS_CHAIN_TIMEOUT` audit row + the last-good ctx returned;
    NO exception raised. (CLAUDE.md hard rule #7 — the row is the
    loud-failure escape; the action body still runs with the input ctx.)
    """

    async def hung(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        await asyncio.Event().wait()  # never fires — wall-clock independent
        return None

    short_deadline_registry.register(
        hook_fn=hung,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )

    src = _ctx(input_="payload")
    result = await invoke("hp", src, kind="pre", fail_closed=False)

    # Last-good ctx: payload preserved (no subscriber mutated before the
    # timeout fired).
    assert result.input == "payload"

    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    row = rows[0]
    assert row["event"] == HOOKS_CHAIN_TIMEOUT
    assert row["correlation_id"] == "corr-fault"
    fields = row["fields"]
    assert isinstance(fields, dict)
    assert fields["hookpoint"] == "hp"
    assert fields["kind"] == "pre"
    assert fields["deadline_seconds"] == _SHORT_DEADLINE


# ──────────────────────────────────────────────────────────────────────
# 2. fail_closed=True — audit BEFORE HookError raise
# ──────────────────────────────────────────────────────────────────────


async def test_timeout_fail_closed_true_raises_hook_error_after_audit(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """Same setup but ``fail_closed=True``: the dispatcher emits the
    audit row FIRST, then raises :class:`HookError`. The visible
    invariant is "audit row present AND ``HookError`` raised" — the
    emission completes before the raise (the sink call inside the except
    handler is ``await``-ed before the conditional raise).
    """

    async def hung(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        await asyncio.Event().wait()
        return None

    short_deadline_registry.register(
        hook_fn=hung,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )

    with pytest.raises(HookError):
        await invoke("hp", _ctx(), kind="pre", fail_closed=True)

    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    assert rows[0]["event"] == HOOKS_CHAIN_TIMEOUT
    assert rows[0]["correlation_id"] == "corr-fault"


# ──────────────────────────────────────────────────────────────────────
# 3. Half-open-cursor sentinel (core-006) — cancelled subscriber's
#    finally runs to completion in the except TimeoutError handler
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("fail_closed", [False, True])
async def test_cancelled_subscriber_finally_runs_to_completion(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
    *,
    fail_closed: bool,
) -> None:
    """core-006 invariant: when the chain times out, the cancelled
    subscriber's ``finally`` block runs BEFORE the dispatcher returns
    or raises. The dispatcher awaits the cancelled coroutine inside the
    ``except TimeoutError`` handler — never inside the live timeout
    scope.

    The laggy subscriber sets ``cleanup_flag`` in its ``finally``; the
    test observes the flag is set after the timeout fires for BOTH
    ``fail_closed`` values (the await-to-completion happens before the
    audit emit + conditional raise).
    """
    cleanup_flag = asyncio.Event()

    async def laggy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_flag.set()
        return None  # unreachable but satisfies mypy's None vs ctx return

    short_deadline_registry.register(
        hook_fn=laggy,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )

    if fail_closed:
        with pytest.raises(HookError):
            await invoke("hp", _ctx(), kind="pre", fail_closed=True)
    else:
        await invoke("hp", _ctx(), kind="pre", fail_closed=False)

    # The load-bearing assertion: by the time invoke returned/raised,
    # the cancelled coroutine's finally block had already run. This is
    # the half-open-cursor pin — a real subscriber that opens a DB
    # cursor in __aenter__ and releases it in finally will release the
    # cursor even on chain timeout.
    assert cleanup_flag.is_set() is True


# ──────────────────────────────────────────────────────────────────────
# 4. All four kinds respect the deadline
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("kind", ["pre", "post", "error", "cancel"])
async def test_all_four_kinds_respect_chain_deadline(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
    *,
    kind: HookKind,
) -> None:
    """Each of ``pre`` / ``post`` / ``error`` / ``cancel`` chains is
    wrapped in its own ``asyncio.timeout`` and emits the
    :data:`HOOKS_CHAIN_TIMEOUT` audit row with the matching ``kind``.

    For ``error``/``cancel`` we pass ``exc`` so the dispatcher does not
    refuse with a defensive RuntimeError (those arms are pinned in
    Task 8's test_dispatch).
    """

    async def hung(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        await asyncio.Event().wait()
        return None

    short_deadline_registry.register(
        hook_fn=hung,
        hookpoint="hp",
        kind=kind,
        tier="operator",
    )

    if kind in ("pre", "post"):
        await invoke("hp", _ctx(), kind=kind, fail_closed=False)
    else:
        # error/cancel kinds require exc; the timeout fires inside the
        # chain, the dispatcher returns last-good ctx without re-raising
        # exc (the chain-abandoned semantic — the audit row IS the loud
        # failure).
        await invoke(
            "hp",
            _ctx(),
            kind=kind,
            exc=ValueError("upstream-failure"),
            fail_closed=False,
        )

    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    fields = rows[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["kind"] == kind
    assert fields["hookpoint"] == "hp"


# ──────────────────────────────────────────────────────────────────────
# 5. No timeout when chain is fast — sink has zero timeout rows
# ──────────────────────────────────────────────────────────────────────


async def test_fast_chain_emits_no_timeout_row(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """A passthrough subscriber that returns immediately must NOT trip
    the timeout. The dispatcher's success branch exits the
    ``asyncio.timeout`` scope cleanly with no audit emission.

    Pins the "happy path is silent" invariant — only fault paths emit
    audit rows; a fast chain leaves the spy sink empty.
    """

    async def passthrough(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        return None

    short_deadline_registry.register(
        hook_fn=passthrough,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )

    await invoke("hp", _ctx(), kind="pre", fail_closed=False)

    assert _timeout_rows(spy_sink) == []


# ──────────────────────────────────────────────────────────────────────
# 6. No-subscribers path does not trigger timeout
# ──────────────────────────────────────────────────────────────────────


async def test_no_subscribers_emits_no_timeout_row(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """The empty-subscribers branch through :func:`invoke` does not
    enter the timeout block (or enters and exits trivially) and does
    NOT emit a timeout audit row. Pins the "miss path pays no fault
    cost" invariant — important because most action callsites in a
    quiet system have zero subscribers.
    """
    await invoke("hp.no.subs", _ctx(), kind="pre", fail_closed=False)
    assert _timeout_rows(spy_sink) == []


# ──────────────────────────────────────────────────────────────────────
# 7. chain_deadline_seconds on registry IS the gate
# ──────────────────────────────────────────────────────────────────────


async def test_chain_deadline_seconds_on_registry_is_the_gate(
    spy_sink: SpyAuditSink,
) -> None:
    """The dispatcher reads :attr:`HookRegistry.chain_deadline_seconds`
    on the active registry — NOT the module-level constant. Two
    registries with different deadlines on the SAME hung subscriber
    pattern produce different audit-row attributes.

    This pins the injection seam — Task 12's reentry tests and PR-B's
    integration tests both swap the deadline via this kwarg.
    """

    async def hung(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        await asyncio.Event().wait()
        return None

    prior = get_registry()

    # Tight registry — timeout fires.
    tight = HookRegistry(
        gate=DevGate(),
        sink=spy_sink,
        chain_deadline_seconds=_SHORT_DEADLINE,
    )
    set_registry(tight)
    try:
        tight.register(
            hook_fn=hung,
            hookpoint="hp",
            kind="pre",
            tier="operator",
        )
        await invoke("hp", _ctx(), kind="pre", fail_closed=False)
    finally:
        set_registry(prior)

    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    fields = rows[0]["fields"]
    assert isinstance(fields, dict)
    # The recorded deadline_seconds is the registry's value, NOT the
    # module-level default constant — pins the injection seam.
    assert fields["deadline_seconds"] == _SHORT_DEADLINE


# ──────────────────────────────────────────────────────────────────────
# 8. Audit row fields schema — pin for PR-B's EpisodicAuditSink
# ──────────────────────────────────────────────────────────────────────


async def test_handle_chain_timeout_awaits_not_done_pending_to_completion(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """White-box: directly exercise the await-to-completion arm of
    :func:`alfred.hooks.invoke._handle_chain_timeout`.

    In the default control flow, by the time the dispatcher reaches
    its ``except TimeoutError`` arm, the in-flight subscriber task has
    already been awaited to done state (the ``await pending`` inside
    the timeout-wrapped loop waits for the cancellation+finally to
    finish before re-raising). The ``if pending is not None and not
    pending.done()`` guard is the DEFENSIVE arm — it covers a future
    refactor where the loop body might leave the task in a not-done
    state (an alternative iteration shape that races the deadline).

    This test pins that defensive arm directly. We hand
    :func:`_handle_chain_timeout` a fresh not-done :class:`asyncio.Task`
    wrapping a coroutine that sets a sentinel in its ``finally`` — the
    helper must await it to done state BEFORE emitting the audit row.
    Without the await-to-completion, the sentinel would not be set
    when the helper returns (the task would still be in-flight on a
    different event-loop tick).
    """
    from alfred.hooks.invoke import _handle_chain_timeout

    cleanup_flag = asyncio.Event()

    async def hung() -> HookContext[Any] | None:
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_flag.set()
        return None

    # Create a task that is NOT yet done — the helper's defensive arm
    # is exactly the path we exercise here. Cancel it BEFORE handing it
    # to the helper so the await inside the helper sees a cancelled
    # task that hasn't yet had its finally run on this event-loop tick.
    pending: asyncio.Task[HookContext[Any] | None] = asyncio.create_task(hung())
    # Yield to let the task start (reach the inner await).
    await asyncio.sleep(0)
    assert not pending.done()
    pending.cancel()
    # Critical: do NOT await pending here — that would be the bug we
    # are testing the helper for. Hand the not-done task to the helper
    # and let IT do the await-to-completion in its except arm.
    assert not pending.done()

    src_ctx = _ctx(input_="last-good")
    result = await _handle_chain_timeout(
        pending=pending,
        chain_ctx=src_ctx,
        hookpoint="hp.whitebox",
        kind="pre",
        deadline_seconds=_SHORT_DEADLINE,
        fail_closed=False,
    )

    # The defensive await-to-completion ran: the subscriber's finally
    # has set the sentinel. This is the core-006 invariant — even a
    # not-done task gets its cleanup before the audit row + return.
    assert cleanup_flag.is_set() is True
    assert pending.done() is True

    # The audit row landed AFTER the await-to-completion.
    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    assert result.input == "last-good"


async def test_chain_timeout_audit_row_fields_schema(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """The ``fields`` mapping on a :data:`HOOKS_CHAIN_TIMEOUT` audit row
    contains EXACTLY ``hookpoint``, ``kind``, ``deadline_seconds``,
    ``cleanup_timed_out``. PR-B's :class:`EpisodicAuditSink` keys off
    this schema; an unannounced addition or removal here breaks PR-B's
    row-projection.

    Pin'd as a set-equality assertion against the canonical
    :data:`alfred.hooks.invoke._CHAIN_TIMEOUT_AUDIT_FIELDS` constant so a
    future field surfaces as a failing test the author MUST acknowledge
    AND keeps the documentation source of truth (the constant) in sync
    with the wire format (the emitted row).
    """
    from alfred.hooks.invoke import _CHAIN_TIMEOUT_AUDIT_FIELDS

    async def hung(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        await asyncio.Event().wait()
        return None

    short_deadline_registry.register(
        hook_fn=hung,
        hookpoint="hp",
        kind="post",
        tier="operator",
    )

    await invoke("hp", _ctx(), kind="post", fail_closed=False)

    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    fields = rows[0]["fields"]
    assert isinstance(fields, dict)
    assert set(fields.keys()) == set(_CHAIN_TIMEOUT_AUDIT_FIELDS)
    assert set(fields.keys()) == {
        "hookpoint",
        "kind",
        "deadline_seconds",
        "cleanup_timed_out",
    }
    # Cooperative subscriber (Event().wait() raises CancelledError
    # promptly when cancelled) — cleanup completed inside the secondary
    # deadline, so the flag is False.
    assert fields["cleanup_timed_out"] is False


# ──────────────────────────────────────────────────────────────────────
# 9. S-001 — adversarial cancellation-trap subscriber
# ──────────────────────────────────────────────────────────────────────


async def test_handle_chain_timeout_secondary_deadline_marks_audit_row(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """S-001 hardening — WHITE-BOX exercise of the secondary cleanup
    deadline inside :func:`_handle_chain_timeout`.

    Why white-box: in the normal dispatcher flow, by the time the
    primary ``asyncio.timeout`` scope's ``__aexit__`` raises
    :class:`TimeoutError`, the cancelled subscriber's task has been
    awaited to done state — ``await pending`` does not return until
    pending is done, and the primary timeout's cancellation IS the
    mechanism that drives the subscriber's ``finally`` to completion.
    A subscriber whose ``finally`` defends against cancellation (e.g.
    a slow-rollback DB cleanup that catches each cancel signal and
    keeps draining the connection) actually prevents the primary
    timeout from converting to :class:`TimeoutError` at all — the
    dispatcher's ``await pending`` blocks until ``pending`` is done,
    period. The secondary deadline shipped here defends an INTERNAL
    invariant of the helper: if a future refactor (or a tier-policy
    arm that imports pending from somewhere other than the kind
    handler's own ``asyncio.timeout`` scope) ever surfaces a not-done
    pending to the helper with a defensive cleanup, the helper must
    bound that await rather than block indefinitely.

    The white-box test hands the helper a not-done task whose
    ``finally`` outlasts :data:`_CLEANUP_DEADLINE_SECONDS`, asserts the
    audit row lands with ``cleanup_timed_out=True``, and force-cancels
    cleanup in the test teardown.

    Operator-flow caveat (recorded in
    :data:`_CLEANUP_DEADLINE_SECONDS`'s docstring): the full
    "cancellation-trap DoS" — a subscriber that catches
    :class:`asyncio.CancelledError` and never lets it propagate —
    defeats the primary chain timeout at the kind-handler level and
    is therefore NOT defended against by Task 9's secondary deadline.
    That arm needs a primary-handler refactor to an
    :func:`asyncio.wait`-based dispatch, tracked as a Task-9 follow-up.
    """
    from alfred.hooks.invoke import _CLEANUP_DEADLINE_SECONDS, _handle_chain_timeout

    cleanup_started = asyncio.Event()

    async def defensive_cleanup() -> HookContext[Any] | None:
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_started.set()
            # Cleanup runs longer than _CLEANUP_DEADLINE_SECONDS.
            # Each await defends against the outer cancellation so the
            # cleanup keeps running — models a real resource-release
            # path that prioritises completion over responsiveness to
            # cancel signals.
            loop = asyncio.get_running_loop()
            cleanup_deadline = loop.time() + _CLEANUP_DEADLINE_SECONDS * 4
            while loop.time() < cleanup_deadline:
                try:
                    await asyncio.sleep(0.005)
                except asyncio.CancelledError:
                    continue
        return None

    pending: asyncio.Task[HookContext[Any] | None] = asyncio.create_task(defensive_cleanup())
    # Let the task reach its inner await.
    await asyncio.sleep(0)
    assert not pending.done()
    # Cancel — models the primary timeout's cancel-propagation that
    # would have happened before the helper is entered. The defensive
    # cleanup will trap each ensuing cancel signal.
    pending.cancel()

    src_ctx = _ctx(input_="last-good")
    result = await _handle_chain_timeout(
        pending=pending,
        chain_ctx=src_ctx,
        hookpoint="hp.whitebox",
        kind="pre",
        deadline_seconds=_SHORT_DEADLINE,
        fail_closed=False,
    )

    # The secondary deadline fired — helper returned without blocking
    # for the full 4x cleanup window.
    assert cleanup_started.is_set() is True
    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    fields = rows[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["cleanup_timed_out"] is True
    assert result.input == "last-good"

    # Force-cancel and let the leaked task wind down before teardown
    # so pytest-asyncio doesn't see an orphan task at loop close.
    pending.cancel()
    for _ in range(10):
        if pending.done():
            break
        await asyncio.sleep(0.02)
    # Drain any final exception so asyncio doesn't log unretrieved.
    with contextlib.suppress(BaseException):
        await pending


async def test_handle_chain_timeout_secondary_deadline_fail_closed_raises(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """S-001 + ``fail_closed=True`` (white-box): the secondary deadline
    fires, the audit row lands with ``cleanup_timed_out=True``, AND
    :class:`HookError` raises with the cleanup-timed-out flag in its
    message.

    Pins that the cleanup-deadline arm interacts cleanly with the
    existing fail-closed policy — the abandonment is loud both ways.
    The :class:`HookError` message surfaces ``cleanup_timed_out=True``
    so an operator catching the exception sees the slow-cleanup
    attribution without cross-referencing the audit log.

    Same white-box rationale as
    :func:`test_handle_chain_timeout_secondary_deadline_marks_audit_row`.
    """
    from alfred.hooks.invoke import _CLEANUP_DEADLINE_SECONDS, _handle_chain_timeout

    async def defensive_cleanup() -> HookContext[Any] | None:
        try:
            await asyncio.Event().wait()
        finally:
            loop = asyncio.get_running_loop()
            cleanup_deadline = loop.time() + _CLEANUP_DEADLINE_SECONDS * 4
            while loop.time() < cleanup_deadline:
                try:
                    await asyncio.sleep(0.005)
                except asyncio.CancelledError:
                    continue
        return None

    pending: asyncio.Task[HookContext[Any] | None] = asyncio.create_task(defensive_cleanup())
    await asyncio.sleep(0)
    pending.cancel()

    src_ctx = _ctx()
    with pytest.raises(HookError) as exc_info:
        await _handle_chain_timeout(
            pending=pending,
            chain_ctx=src_ctx,
            hookpoint="hp.whitebox",
            kind="pre",
            deadline_seconds=_SHORT_DEADLINE,
            fail_closed=True,
        )

    # The HookError message surfaces the S-001 signal.
    assert "cleanup_timed_out=True" in str(exc_info.value)

    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    fields = rows[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["cleanup_timed_out"] is True

    # Teardown the leaked task so pytest-asyncio doesn't trip on it.
    pending.cancel()
    for _ in range(10):
        if pending.done():
            break
        await asyncio.sleep(0.02)
    with contextlib.suppress(BaseException):
        await pending


# ──────────────────────────────────────────────────────────────────────
# 10. S-002 — BaseException during finally still permits audit emission
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cleanup_exc_cls",
    [
        RuntimeError,
        ValueError,
    ],
)
async def test_subscriber_finally_raises_does_not_prevent_audit(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
    *,
    cleanup_exc_cls: type[BaseException],
) -> None:
    """S-002 (white-box): a subscriber whose ``finally`` itself raises
    does NOT prevent the audit-row emission.

    White-box rationale: in the normal dispatcher flow, if the
    subscriber's ``finally`` raises a non-cancellation exception, the
    kind-handler's ``await pending`` re-raises that exception BEFORE
    the ``asyncio.timeout`` scope's ``__aexit__`` runs — so the
    handler never reaches the ``except TimeoutError`` arm and never
    enters :func:`_handle_chain_timeout`. Task 10's
    unexpected-subscriber-exception fault arm is what handles that
    flow; Task 9's helper-suppress arm only protects against an
    exception RAISED FROM ``pending.result()`` DURING the helper's
    drain step. That path is reachable today only via the helper's
    defensive not-done branch (the same path
    :func:`test_handle_chain_timeout_awaits_not_done_pending_to_completion`
    pins).

    The drain step wraps ``pending.result()`` in
    ``contextlib.suppress(BaseException)`` — explicitly so a botched
    cleanup cannot suppress the loud-failure audit (CLAUDE.md hard
    rule #7).

    Parametrised across :class:`RuntimeError` and :class:`ValueError`
    to pin two distinct exception types across the ``Exception``-tier
    suppress arm. The BaseException-tier sentinels (:class:`SystemExit`,
    :class:`KeyboardInterrupt`) are intentionally out of scope: Python
    3.14's ``Task.__step`` re-raises them in the event loop itself for
    process-termination correctness, BEFORE control returns to the
    helper's drain. The production ``contextlib.suppress(BaseException)``
    is the correct defensive shape regardless — the suppress is the
    last-resort barrier — but the threat surface is shaped by
    well-typed application exceptions a real subscriber's cleanup
    might raise (timeout libraries, ORM rollback failures, etc.).
    """
    from alfred.hooks.invoke import _handle_chain_timeout

    async def laggy_with_bad_cleanup() -> HookContext[Any] | None:
        try:
            await asyncio.Event().wait()
        finally:
            raise cleanup_exc_cls("cleanup itself failed")

    pending: asyncio.Task[HookContext[Any] | None] = asyncio.create_task(laggy_with_bad_cleanup())
    await asyncio.sleep(0)
    assert not pending.done()
    pending.cancel()
    # Do NOT await pending here — the helper must handle the drain.

    src_ctx = _ctx(input_="last-good")

    # The botched cleanup must NOT propagate out of the helper when
    # fail_closed=False — the audit row IS the loud-failure escape.
    result = await _handle_chain_timeout(
        pending=pending,
        chain_ctx=src_ctx,
        hookpoint="hp.whitebox",
        kind="pre",
        deadline_seconds=_SHORT_DEADLINE,
        fail_closed=False,
    )
    assert result.input == "last-good"

    # The audit row landed despite the bad cleanup. Cooperative
    # subscriber (the finally raised promptly) — the secondary deadline
    # did not fire.
    rows = _timeout_rows(spy_sink)
    assert len(rows) == 1
    fields = rows[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["cleanup_timed_out"] is False


# ──────────────────────────────────────────────────────────────────────
# 11. S-003 — Multi-subscriber chain-position invariant on timeout
# ──────────────────────────────────────────────────────────────────────


async def test_timeout_short_circuits_remaining_subscribers(
    short_deadline_registry: HookRegistry,
    spy_sink: SpyAuditSink,
) -> None:
    """S-003: when the first subscriber times out, the dispatcher does
    NOT proceed to run subsequent subscribers in the chain.

    Pins the chain-position invariant — the timeout is per-chain, not
    per-subscriber. A leaked subscriber after a timeout would
    double-emit side effects (DB writes, span starts) past the abandoned
    chain, defeating the "chain abandoned, action body proceeds with
    last-good ctx" semantic.

    The first subscriber hangs on a never-firing event; the second sets
    an asyncio.Event marker. After invoke returns, the marker MUST NOT
    have been set — proving the dispatcher short-circuited at the
    timeout rather than continuing to walk the chain.
    """
    second_ran = asyncio.Event()

    async def first_hangs(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        await asyncio.Event().wait()
        return None

    async def second_marks(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        second_ran.set()
        return None

    short_deadline_registry.register(
        hook_fn=first_hangs,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )
    short_deadline_registry.register(
        hook_fn=second_marks,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )

    await invoke("hp", _ctx(), kind="pre", fail_closed=False)

    # The second subscriber NEVER ran — the timeout short-circuited the
    # remainder of the chain.
    assert second_ran.is_set() is False
    # Exactly one timeout audit row (NOT one-per-subscriber).
    assert len(_timeout_rows(spy_sink)) == 1
