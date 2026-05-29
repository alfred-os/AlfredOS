"""Hook subsystem dispatch primitive — Slice-2.5 PR-A Tasks 8 + 9 + 10.

The :func:`invoke` primitive is the public entry point every action
callsite uses to drive a hook chain. It is intentionally tiny:

1. Apply :meth:`HookContext.for_stage` to retarget the carrier to the
   ``(hookpoint, kind)`` :func:`invoke` was called with. The dispatcher
   is AUTHORITATIVE for the stage — a stale caller-side ctx is silently
   rewritten so subscribers always see the correct stage.
2. Route to one of four private handlers based on ``kind``: ``_run_pre``
   / ``_run_post`` / ``_run_error`` / ``_run_cancel``. Each handler is a
   structurally distinct function so the 100% branch-coverage gate
   (Task 14) can pin each kind independently.
3. Each handler wraps its subscriber walk in ONE
   ``asyncio.timeout(deadline_seconds)`` (Task 9 / perf §5). On
   :class:`TimeoutError` the dispatcher emits a
   :data:`alfred.hooks.audit_sink.HOOKS_CHAIN_TIMEOUT` audit row through
   the registry-owned sink and either returns the last-good ctx
   (``fail_closed=False``) or raises :class:`HookError`
   (``fail_closed=True``). The cancelled-subscriber await-to-completion
   (core-006) happens INSIDE the ``except TimeoutError`` handler, never
   inside the live timeout scope.
4. Each chain-walking handler catches NON-:class:`HookRefusal`,
   NON-:class:`asyncio.CancelledError`, NON-:class:`TimeoutError`
   exceptions from a subscriber (Task 10 / spec §6.6) and:

   * wraps the fault as
     :class:`alfred.hooks.errors.HookSubscriberError` via
     :meth:`HookSubscriberError.from_subscriber`, chaining ``__cause__``
     back to the original exception so the traceback walks both;
   * emits a
     :data:`alfred.hooks.audit_sink.HOOKS_SUBSCRIBER_ERROR` row through
     the registry-owned sink. Fields are NAME + TYPE only — NEVER
     ``str(exc)`` or ``exc.args``, because the subscriber may have
     inadvertently wrapped T3 user content in its exception (CLAUDE.md
     hard rule #1 — never log secrets);
   * applies ``fail_closed``: ``True`` raises the wrapped error so the
     action body sees a hard fault; ``False`` treats the subscriber as
     pass-through and continues the chain with the LAST-GOOD ctx (the
     ctx as it was BEFORE the erroring subscriber's call). The error
     is still audited — recorded, not hidden (CLAUDE.md hard rule #7).

   ``_run_cancel`` is special: cleanup is best-effort, so the swallow
   stays but the audit row makes the swallow no longer silent. Cancel
   never wraps and never honours ``fail_closed`` — the original
   cancellation always propagates.

5. Return the handler's :class:`HookContext` (for ``pre`` / ``post`` /
   error-suppressed / timeout-recovered / fail-closed-false subscriber-
   error-recovered) or re-raise (for the ``error``-all-none path, the
   ``cancel`` propagate-cancellation path when the chain completed
   within the deadline, and the fail-closed-true subscriber-error
   wrap).

Faults still pending land in later tasks:

* Refusal-authorisation by tier + audit row          → Task 11.
* Re-entry bypass via :data:`alfred.hooks.registry._reentry` → Task 12.

The five-parameter :func:`invoke` signature is verbatim from spec §0 —
``subscribable_tiers`` / ``refusable_tiers`` / ``fail_closed`` /
``exc`` all flow through even where dispatch ignores them, so later
tasks layer fault logic without changing the call shape.

Design — how ``exc`` reaches error/cancel subscribers:

  Subscribers are uniformly typed
  ``Callable[[HookContext[T]], Awaitable[HookContext[T] | None]]`` —
  they never grow a positional ``exc`` argument. To make ``exc``
  available without forking the subscriber signature, the dispatcher
  injects it onto ``ctx.metadata`` under the key
  :data:`ERROR_EXC_METADATA_KEY` before iterating the chain. The
  :class:`HookContext` is frozen so ``with_metadata`` produces a fresh
  carrier; no original ctx is mutated. Subscribers that need the
  upstream exception read ``ctx.metadata["error_exc"]`` directly.

Design — why each kind owns its own timeout-wrapped walk (Option 3):

  ``pre`` and ``post`` share a linear walk-and-fold shape; ``error`` is
  "first non-None wins, else re-raise exc"; ``cancel`` is "swallow
  subscriber exceptions, always re-raise exc". Unifying the four
  through one callback-parameterised iterator would obscure each
  handler's disposition logic. Instead each handler inlines its own
  ``async with asyncio.timeout(...)`` block plus its kind-specific
  loop body; a single :func:`_handle_chain_timeout` helper
  centralises the shared three-step fault sequence (await the
  cancelled subscriber to completion, emit the audit row, apply
  ``fail_closed``). The four handlers therefore each have a structurally
  distinct ``def`` and a structurally distinct ``try/except
  TimeoutError`` arm — the eight-way coverage pin Task 14 will exercise.

Design — core-006 cancelled-coroutine await-to-completion:

  When the ``asyncio.timeout`` scope expires, the in-flight subscriber
  task is cancelled by the scheduler. By the time the ``except
  TimeoutError`` arm starts running, the scope has already exited and
  the cancellation has been delivered to the subscriber — but the
  subscriber's ``finally`` block (database commit-or-rollback, lock
  release, span close) has NOT necessarily completed. The dispatcher
  must ``await`` the cancelled task once more inside the ``except``
  handler so the subscriber's cleanup runs to completion before any
  audit row is emitted or any caller observes the chain's outcome.
  This is the half-open-cursor pin tested by
  ``test_cancelled_subscriber_finally_runs_to_completion``. The
  ``except BaseException`` on the await is cleanup-only — whatever the
  cancelled subscriber raises during its own ``finally`` (typically
  :class:`asyncio.CancelledError`, defensively any
  :class:`BaseException`) must not prevent the audit row from landing.

Design — cancel subscriber exceptions are NOT re-raised:

  The ``_run_cancel`` handler catches every :class:`BaseException`
  (except the cancel sentinel itself) from a subscriber and continues
  with the next subscriber. This is the "cancel cleanup is
  best-effort" semantic — a botched cleanup must not block the rest
  from running, and absolutely must not suppress the original
  cancellation. Task 10 will layer audit-row emission onto the catch
  arm so the swallow is no longer silent (CLAUDE.md hard rule #7 —
  Task-10's audit row IS the loud-failure escape). For Task 9 the
  swallow ships without audit attribution; the test suite verifies
  the propagate-cancellation contract directly.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Coroutine
from typing import Any, Final, cast

from alfred.hooks.audit_sink import HOOKS_CHAIN_TIMEOUT, HOOKS_SUBSCRIBER_ERROR
from alfred.hooks.context import HookContext, HookKind
from alfred.hooks.errors import HookError, HookRefusal, HookSubscriberError
from alfred.hooks.registry import Subscriber, get_registry

# ──────────────────────────────────────────────────────────────────────
# Module constants
# ──────────────────────────────────────────────────────────────────────

ERROR_EXC_METADATA_KEY: Final[str] = "error_exc"
"""Key under which the dispatcher stashes the upstream exception on
``ctx.metadata`` before invoking an ``error`` or ``cancel`` chain.

Public because subscribers read it directly. PR-B's documented
subscriber-author guide references the constant by import (not by
string literal) so a future rename surfaces at every read site.
"""


# Default subscribable / refusable tier sets — verbatim spec §0.
_DEFAULT_TIERS: Final[frozenset[str]] = frozenset({"system", "operator", "user-plugin"})


_CLEANUP_DEADLINE_SECONDS: Final[float] = 0.05
"""Secondary deadline bounding the cancelled-subscriber await-to-completion
step inside :func:`_handle_chain_timeout` (S-001 hardening).

The chain-timeout fault sequence's first step awaits the in-flight
subscriber task ONE MORE TIME after the primary ``asyncio.timeout``
scope has fired and cancellation has propagated to the subscriber, so
the subscriber's ``finally`` block (DB commit-or-rollback, lock
release, span close) runs to completion before the audit row lands.
WITHOUT a second bound on that await, a subscriber whose ``finally``
takes longer than the rest of the chain budget — a slow DB rollback
under load, a network close that hangs on a half-open socket — would
inflate the dispatcher's tail latency and push the audit row past the
operator's alert window.

50 ms is the chosen value:

* Long enough for any legitimate cooperative cleanup — a DB connection
  rollback, an in-process file close, a span flush — to finish, even on
  a loaded CI runner.
* Short enough that a slow cleanup stalls the audit emission by no
  more than 50 ms, well inside the operator's tolerance for a chain
  that has ALREADY exceeded its primary deadline.

When this secondary deadline expires, the helper sets
``cleanup_timed_out=True`` on the audit row, force-cancels the task one
more time (best-effort signal), and proceeds to emit the audit row and
apply the fail-closed policy. The task is then left running until
garbage collection; that's an accepted leak because the audit row
records the leak attribution and the dispatch chain itself is
unblocked. The leak is a tradeoff against the alternative (blocking
the dispatcher indefinitely), which is strictly worse.

Threat-model caveat: the secondary deadline defends against
slow-but-cooperative cleanup. It does NOT defend against a subscriber
that TRAPS :class:`asyncio.CancelledError` and never lets it propagate
out of its coroutine — in that adversarial case the PRIMARY chain
timeout itself is defeated (``await pending`` in the kind handler
never returns because the subscriber's task is never done). The full
trap DoS needs a primary-handler refactor to an :func:`asyncio.wait`
-based dispatch; that lands as a follow-up to Task 9. The S-001
hardening shipped here covers the slow-cleanup arm of the threat
surface; the full trap DoS arm is tracked separately.
"""


_SUBSCRIBER_ERROR_AUDIT_FIELDS: Final[frozenset[str]] = frozenset(
    {"hookpoint", "kind", "subscriber_name", "exception_type"}
)
"""Canonical key set for the ``fields`` mapping on every
:data:`HOOKS_SUBSCRIBER_ERROR` audit row.

PR-B's :class:`alfred.audit.log.AuditWriter`-backed sink keys off this
schema for row projection; an unannounced addition / removal here breaks
the projector. The set is asserted by
``tests/unit/hooks/test_fault_semantics.py::test_subscriber_error_audit_row_fields_schema``
so a drift surfaces as a failing test the author MUST acknowledge.

Schema:

* ``hookpoint`` — dotted hookpoint identifier (str)
* ``kind`` — lifecycle stage (one of ``"pre"`` / ``"post"`` / ``"error"``
  / ``"cancel"``)
* ``subscriber_name`` — ``hook_fn.__qualname__`` of the offending
  subscriber (str). Lets the operator grep the registry for the plugin
  / module that crashed.
* ``exception_type`` — ``exc.__class__.__name__`` of the original
  unexpected exception (str). NAME ONLY — never ``str(exc)`` or
  ``exc.args``, because the subscriber may have inadvertently wrapped
  T3 user content in its exception (CLAUDE.md hard rule #1 — never
  log secrets). The wrapped :class:`HookSubscriberError`'s
  ``__cause__`` chain is where an operator with audit-log access can
  inspect the upstream traceback.
"""


_CHAIN_TIMEOUT_AUDIT_FIELDS: Final[frozenset[str]] = frozenset(
    {"hookpoint", "kind", "deadline_seconds", "cleanup_timed_out"}
)
"""Canonical key set for the ``fields`` mapping on every
:data:`HOOKS_CHAIN_TIMEOUT` audit row.

PR-B's :class:`alfred.audit.log.AuditWriter`-backed sink keys off this
schema for row projection; an unannounced addition / removal here breaks
the projector. The set is asserted by
``tests/unit/hooks/test_fault_semantics.py::test_chain_timeout_audit_row_fields_schema``
so a drift surfaces as a failing test the author MUST acknowledge.

Schema:

* ``hookpoint`` — dotted hookpoint identifier (str)
* ``kind`` — lifecycle stage (one of ``"pre"`` / ``"post"`` / ``"error"``
  / ``"cancel"``)
* ``deadline_seconds`` — the primary chain deadline that fired (float)
* ``cleanup_timed_out`` — ``True`` when the SECONDARY (cleanup) deadline
  also expired, indicating an adversarial subscriber trapped
  :class:`asyncio.CancelledError` and the dispatcher abandoned the
  task. ``False`` for a cooperative subscriber whose ``finally`` ran
  inside the cleanup budget. (S-001 hardening.)
"""


def _spawn_subscriber[T](
    sub: Subscriber,
    chain_ctx: HookContext[T],
) -> asyncio.Task[HookContext[T] | None]:
    """Wrap ``sub.hook_fn(chain_ctx)`` in a fresh :class:`asyncio.Task`.

    Centralises the one place in this module where the structural
    return-type widening between :data:`alfred.hooks.registry.HookFn`
    (``Callable[..., Awaitable[HookContext[Any] | None]]``) and
    :func:`asyncio.create_task`'s parameter shape
    (``Coroutine[Any, Any, _T]``) is bridged. The
    :meth:`HookRegistry.register` validator rejects any non-coroutine
    function at registration time via
    :func:`inspect.iscoroutinefunction` — so at dispatch time
    ``sub.hook_fn(...)`` is GUARANTEED to be a real coroutine, and
    the :func:`typing.cast` here is a static-checker hint rather than
    a runtime conversion.

    Living in one helper means a future widening of :data:`HookFn`
    (e.g. PR-B's value-returning-action carrier) updates the type
    contract in ONE call site instead of four.
    """
    coro = cast(
        Coroutine[Any, Any, HookContext[T] | None],
        sub.hook_fn(chain_ctx),
    )
    return asyncio.create_task(coro)


# ──────────────────────────────────────────────────────────────────────
# Public entry point — invoke[T]
# ──────────────────────────────────────────────────────────────────────


async def invoke[T](
    name: str,
    ctx: HookContext[T],
    *,
    kind: HookKind,
    subscribable_tiers: frozenset[str] = _DEFAULT_TIERS,
    refusable_tiers: frozenset[str] = _DEFAULT_TIERS,
    fail_closed: bool = False,
    exc: BaseException | None = None,
) -> HookContext[T]:
    """Dispatch a hook chain for ``(name, kind)``.

    Authoritative entry point — applies :meth:`HookContext.for_stage`
    first so a subscriber always sees the stage :func:`invoke` was
    called with, even if the caller-passed ``ctx`` claims a different
    stage. Then routes to one of four private handlers by ``kind``.

    Tasks 8 + 9 ship the happy-path dispatch and the chain-timeout
    fault arm:

    * ``pre`` — walk the chain, allow each subscriber to mutate
      ``ctx.input`` via :meth:`HookContext.with_input`. A
      :class:`HookRefusal` raised by any subscriber propagates
      immediately; downstream subscribers do not run; the caller never
      sees a rewritten ctx (the action body never runs). A chain
      timeout emits :data:`HOOKS_CHAIN_TIMEOUT` and either returns
      last-good ctx or raises :class:`HookError`.
    * ``post`` — walk the chain, fold every subscriber's returned ctx
      into the next subscriber's input. The final ctx is the
      end-of-chain fold. Same timeout treatment as ``pre``.
    * ``error`` — walk the chain with ``exc`` exposed under
      ``ctx.metadata[ERROR_EXC_METADATA_KEY]``. The FIRST subscriber
      that returns a :class:`HookContext` wins
      (swallow-and-substitute); subsequent subscribers do not run. If
      every subscriber returns ``None``, the original ``exc``
      re-raises. A chain timeout SUPPRESSES the would-be re-raise —
      the audit row is the loud-failure escape, and last-good ctx is
      returned (or :class:`HookError` raised on ``fail_closed``).
    * ``cancel`` — walk the chain so each subscriber can run cleanup;
      return values are IGNORED; the original ``exc`` (whatever
      :class:`BaseException` the caller passed; conventionally
      :class:`asyncio.CancelledError`) re-raises after the chain
      finishes. A chain timeout SUPPRESSES the propagate-cancellation
      semantic for the timeout arm specifically — the audit row makes
      the abandonment loud, and last-good ctx is returned (or
      :class:`HookError` raised on ``fail_closed``).

    Args:
        name: The dotted hookpoint identifier (e.g.
            ``"action.memory.episodic.record"``). Positional so a
            typo is caught as a type mismatch by mypy.
        ctx: The :class:`HookContext` the action callsite built.
            :meth:`HookContext.for_stage` rewrites its ``hookpoint``
            and ``kind`` before any subscriber sees it.
        kind: The lifecycle stage one of the four
            :data:`alfred.hooks.context.HookKind` literals.
        subscribable_tiers: Tier set whose subscribers are permitted
            to RUN at this dispatch. Threaded through to the four
            handlers for Task-11's tier-filter; this slice ignores
            the value (every registered subscriber runs).
        refusable_tiers: Tier set whose subscribers are permitted
            to refuse via :class:`HookRefusal`. Threaded through for
            Task-11's authorisation; this slice ignores the value
            (every :class:`HookRefusal` propagates).
        fail_closed: Whether to fail closed on a chain timeout / Task
            10's unexpected subscriber error. On a chain timeout:
            ``True`` raises :class:`HookError` AFTER the audit row;
            ``False`` returns last-good ctx with the audit row as the
            loud-failure escape.
        exc: The upstream exception for ``error`` / ``cancel`` kinds.
            Typed :class:`BaseException` because
            :class:`asyncio.CancelledError` is a ``BaseException``
            in Python 3.8+, NOT an :class:`Exception`. Ignored for
            ``pre`` / ``post`` (the caller can still pass it; the
            dispatcher does not propagate it onto ``ctx.metadata``
            for those kinds).

    Returns:
        For ``pre`` — the final mutated ctx (or the input ctx if no
        subscriber mutated, or last-good on timeout).
        For ``post`` — the final folded ctx (or last-good on timeout).
        For ``error`` — the substitute ctx returned by the first
        non-``None`` subscriber, OR the last-good ctx if the chain
        timed out before any subscriber suppressed. If all subscribers
        returned ``None`` AND the chain did not time out,
        :func:`invoke` re-raises ``exc`` instead of returning.
        For ``cancel`` — last-good ctx if the chain timed out;
        otherwise never returns (``exc`` always re-raises).

    Raises:
        HookError: ``fail_closed=True`` and the chain exceeded the
            registry's ``chain_deadline_seconds``. The audit row is
            emitted FIRST so the fault attribution lands even when
            the caller does not catch the exception.
        HookRefusal: A ``pre`` subscriber refused the action. The
            error carries the refuser's ``hook_id`` / ``action_id`` /
            ``reason`` / ``correlation_id`` for the audit row Task 11
            will emit; this slice simply propagates.
        BaseException: The ``exc`` passed in, re-raised for the
            ``error``-all-none path and the ``cancel`` path WHEN the
            chain completed inside its deadline. Identity is preserved
            so the upstream traceback is intact. On timeout the
            re-raise is suppressed in favour of the audit row +
            last-good ctx return.
    """
    # Retarget the carrier — invoke is authoritative for the stage.
    # Even with zero subscribers, the returned ctx reflects the
    # (hookpoint, kind) the caller specified, NOT what the input ctx
    # claimed. This is what makes a stale caller-side ctx safe.
    ctx = ctx.for_stage(hookpoint=name, kind=kind)

    if kind == "pre":
        return await _run_pre(
            name,
            ctx,
            subscribable_tiers=subscribable_tiers,
            refusable_tiers=refusable_tiers,
            fail_closed=fail_closed,
        )
    if kind == "post":
        return await _run_post(
            name,
            ctx,
            subscribable_tiers=subscribable_tiers,
            fail_closed=fail_closed,
        )
    if kind == "error":
        return await _run_error(
            name,
            ctx,
            exc=exc,
            subscribable_tiers=subscribable_tiers,
            fail_closed=fail_closed,
        )
    # kind == "cancel" — the HookKind literal type pins exhaustiveness;
    # mypy / pyright reject any other value at the call site.
    return await _run_cancel(
        name,
        ctx,
        exc=exc,
        subscribable_tiers=subscribable_tiers,
        fail_closed=fail_closed,
    )


# ──────────────────────────────────────────────────────────────────────
# Shared timeout-handling helper
# ──────────────────────────────────────────────────────────────────────


async def _handle_chain_timeout[T](
    *,
    pending: asyncio.Task[HookContext[T] | None] | None,
    chain_ctx: HookContext[T],
    hookpoint: str,
    kind: HookKind,
    deadline_seconds: float,
    fail_closed: bool,
) -> HookContext[T]:
    """Centralised three-step timeout fault sequence.

    Called by each kind-handler's ``except TimeoutError`` arm. The
    sequence — order matters and is load-bearing:

    1. **Await the cancelled subscriber to completion** (core-006),
       BOUNDED by a SECONDARY deadline (S-001 hardening).
       The ``asyncio.timeout`` scope has already exited by the time
       this helper runs, so the in-flight subscriber task has been
       cancelled — but its ``finally`` block may not yet have run.
       Awaiting the task here gives the subscriber's cleanup
       (database commit-or-rollback, lock release, span close) a
       chance to finish before the dispatcher returns or raises. The
       wait is bounded by :data:`_CLEANUP_DEADLINE_SECONDS` so a slow
       cleanup cannot stall the audit emission past the operator's
       tolerance window. When the secondary deadline expires we set
       ``cleanup_timed_out=True`` on the audit row, force-cancel the
       task one more time as a best-effort signal, and abandon it
       (the task is left running until GC; the audit row records the
       leak). The ``contextlib.suppress(BaseException)`` around the
       drain is cleanup-only — :class:`asyncio.CancelledError` is the
       conventional value raised by ``pending.result()`` on a
       cancelled task, but defensively we absorb any
       :class:`BaseException` so a subscriber's botched ``finally``
       cannot prevent the audit row from landing.
    2. **Emit the audit row** through the registry-owned sink. CLAUDE.md
       hard rule #7 — the row IS the loud-failure escape; the chain
       was abandoned, the operator must see attribution. The
       ``cleanup_timed_out`` field surfaces the adversarial-trap signal
       so the operator can distinguish a cooperative-but-slow chain
       from a hostile subscriber.
    3. **Apply the ``fail_closed`` policy.** ``True`` raises
       :class:`HookError`; ``False`` returns the last-good ctx (the
       chain's snapshot before the timeout fired). The audit row is
       emitted BEFORE the conditional raise so even an uncaught
       :class:`HookError` leaves an audit trail.

    Args:
        pending: The :class:`asyncio.Task` wrapping the subscriber
            call that was in-flight when the timeout fired. ``None``
            when the timeout fires between iterations (subscriber just
            returned, next ``create_task`` not yet reached) — that
            window is small but legal; we skip the await-to-completion
            and proceed straight to the audit emission.
        chain_ctx: The last-good ctx — the chain's snapshot at the
            most recent fold point before the timeout fired. Returned
            to the caller in the ``fail_closed=False`` arm.
        hookpoint: The dotted hookpoint identifier — surfaces on the
            audit row as the ``hookpoint`` field so PR-B's
            :class:`EpisodicAuditSink` can attribute the timeout to
            the right action.
        kind: The lifecycle stage that timed out — surfaces on the
            audit row as the ``kind`` field so the operator can see
            which arm of the action's lifecycle was abandoned.
        deadline_seconds: The deadline value that was applied —
            surfaces on the audit row so a future tuning is traceable.
        fail_closed: The policy bit. ``True`` raises
            :class:`HookError` after the audit; ``False`` returns
            ``chain_ctx``.

    Returns:
        ``chain_ctx`` (the last-good carrier) when ``fail_closed`` is
        ``False``. Never returns when ``fail_closed`` is ``True``.

    Raises:
        HookError: When ``fail_closed`` is ``True``. Message includes
            hookpoint, kind, deadline, ``cleanup_timed_out``, and
            correlation id so the operator can trace the audit row to
            the raise site AND tell the cooperative-but-slow case apart
            from the adversarial-trap case. NOT translated via
            :func:`alfred.i18n.t` — no ``hooks.chain_timeout`` catalog
            key exists this slice and inline English with audit
            attribution preserves the loud-failure discipline (CLAUDE.md
            hard rule #7).
    """
    # Step 1 (core-006 + S-001): await the cancelled subscriber to
    # completion, bounded by the secondary cleanup deadline so a
    # subscriber whose ``finally`` outlasts :data:`_CLEANUP_DEADLINE_SECONDS`
    # cannot stall the audit emission.
    #
    # Implementation uses :func:`asyncio.wait` with an explicit
    # ``timeout=`` rather than wrapping ``await pending`` in an
    # ``asyncio.timeout()`` context. The wait-based bound is robust
    # against a slow cleanup because :func:`asyncio.wait` runs its own
    # timer and reports completion-or-timeout WITHOUT cancelling the
    # awaited task — that lets the cleanup-suppression semantic stay
    # explicit (we observe done-state, we drain via
    # ``pending.result()``) without the
    # ``contextlib.suppress(BaseException)`` swallowing the secondary
    # timeout's :class:`asyncio.CancelledError` and silently disarming
    # the bound.
    #
    # After the wait we drain any exception ``pending`` accumulated
    # via ``pending.result()`` so an unretrieved-exception warning
    # does not surface on a botched-finally subscriber.
    # ``contextlib.suppress`` is cleanup-only — :class:`asyncio.CancelledError`
    # is the conventional value but defensively we absorb any
    # :class:`BaseException` so the audit emission below still runs.
    #
    # Threat-model caveat: a subscriber that truly TRAPS
    # :class:`asyncio.CancelledError` and never lets it propagate
    # defeats the PRIMARY chain timeout entirely (``await pending``
    # in the kind handler never returns because pending is never
    # done). The secondary deadline here is a real defense for
    # slow-but-cooperative cleanup; it does NOT defend against the
    # full cancellation-trap DoS — that needs a primary-handler
    # refactor to an asyncio.wait-based dispatch and is tracked
    # separately (see Task 9 follow-up notes).
    cleanup_timed_out = False
    if pending is not None and not pending.done():
        done, _still_pending = await asyncio.wait(
            {pending},
            timeout=_CLEANUP_DEADLINE_SECONDS,
        )
        if pending in done:
            # Cooperative subscriber: finally ran inside the cleanup budget.
            # Retrieve the result/exception so asyncio does not log it
            # as unretrieved.
            with contextlib.suppress(BaseException):
                pending.result()
        else:
            # Slow cleanup outlasted the secondary deadline. Record
            # the leak on the audit row, force-cancel as a best-effort
            # signal, and abandon the task (left running until GC —
            # the audit row records attribution).
            cleanup_timed_out = True
            pending.cancel()

    # Step 2: emit audit row through the registry-owned sink. The
    # ``cleanup_timed_out`` field is the S-001 signal that distinguishes
    # a cooperative-but-slow chain from a hostile subscriber. Schema
    # canonicalised by :data:`_CHAIN_TIMEOUT_AUDIT_FIELDS`.
    await get_registry().sink.emit(
        event=HOOKS_CHAIN_TIMEOUT,
        correlation_id=chain_ctx.correlation_id,
        fields={
            "hookpoint": hookpoint,
            "kind": kind,
            "deadline_seconds": deadline_seconds,
            "cleanup_timed_out": cleanup_timed_out,
        },
    )

    # Step 3: apply fail_closed policy.
    if fail_closed:
        raise HookError(
            f"hooks.chain_timeout: chain for hookpoint={hookpoint!r} "
            f"kind={kind!r} exceeded deadline={deadline_seconds}s "
            f"(cleanup_timed_out={cleanup_timed_out}); "
            f"see audit log (correlation_id={chain_ctx.correlation_id!r})."
        )
    return chain_ctx


# ──────────────────────────────────────────────────────────────────────
# Shared subscriber-error helper — Task 10
# ──────────────────────────────────────────────────────────────────────


async def _emit_subscriber_error_audit(
    *,
    sub: Subscriber,
    exc: BaseException,
    hookpoint: str,
    kind: HookKind,
    correlation_id: str,
) -> None:
    """Emit one :data:`HOOKS_SUBSCRIBER_ERROR` audit row through the
    registry-owned sink.

    Centralises the audit-row field shape so the schema is built in ONE
    place — every kind handler (and the cancel arm) shares it. Drift is
    impossible because there is only one call site that builds the
    ``fields`` mapping; the canonical key set is
    :data:`_SUBSCRIBER_ERROR_AUDIT_FIELDS`.

    Hard-rule discipline (CLAUDE.md #1 — never log secrets): the audit
    row carries the subscriber's ``__qualname__`` and the original
    exception's class NAME only. NEVER ``str(exc)``, ``exc.args``, or
    any string derived from the exception's message — those may carry
    T3 user content the subscriber inadvertently wrapped in its
    exception. The chained :class:`HookSubscriberError`'s
    ``__cause__`` chain is where an operator with audit-log access can
    inspect the upstream traceback; the audit row itself stays
    name-and-type only.

    Args:
        sub: The :class:`Subscriber` whose ``hook_fn`` raised. Its
            ``__qualname__`` surfaces as the ``subscriber_name`` field.
        exc: The original unexpected exception. Only its class NAME is
            read; the instance is otherwise untouched here (the wrap
            site sets ``__cause__`` separately).
        hookpoint: The dotted hookpoint identifier — surfaces as the
            ``hookpoint`` field so PR-B's projector can attribute the
            fault to the right action.
        kind: The lifecycle stage — surfaces as the ``kind`` field so
            the operator can see which arm of the action's lifecycle
            faulted.
        correlation_id: Cross-system trace correlation id, passed
            through to the sink so the row joins on
            ``correlation_id``-keyed traces.
    """
    await get_registry().sink.emit(
        event=HOOKS_SUBSCRIBER_ERROR,
        correlation_id=correlation_id,
        fields={
            "hookpoint": hookpoint,
            "kind": kind,
            "subscriber_name": sub.hook_fn.__qualname__,
            "exception_type": exc.__class__.__name__,
        },
    )


def _wrap_subscriber_error(
    *,
    sub: Subscriber,
    correlation_id: str,
) -> HookSubscriberError:
    """Build the :class:`HookSubscriberError` wrap for an unexpected
    subscriber exception.

    Centralises the :meth:`HookSubscriberError.from_subscriber` call
    shape so a future widening of the wrap surface (e.g. an additional
    kwarg, an alternative constructor) lands in one place rather than
    at three handler sites. Cause chaining is the caller's job: every
    call site is ``raise _wrap_subscriber_error(...) from exc``, which
    sets ``__cause__`` (and ``__suppress_context__``) via Python's
    ``raise ... from`` machinery.

    Args:
        sub: The :class:`Subscriber` whose call raised.
        correlation_id: The chain's correlation id; surfaces in the
            wrap's rendered message via
            :meth:`HookSubscriberError.from_subscriber`.

    Returns:
        The :class:`HookSubscriberError` wrap. The caller is expected
        to ``raise ... from exc`` to attach ``__cause__``.
    """
    return HookSubscriberError.from_subscriber(
        name=sub.hook_fn.__qualname__,
        correlation_id=correlation_id,
    )


# ──────────────────────────────────────────────────────────────────────
# Per-kind private handlers
# ──────────────────────────────────────────────────────────────────────


async def _run_pre[T](
    name: str,
    ctx: HookContext[T],
    *,
    subscribable_tiers: frozenset[str],
    refusable_tiers: frozenset[str],
    fail_closed: bool,
) -> HookContext[T]:
    """Dispatch the ``pre`` chain.

    Linear walk-and-fold under one ``asyncio.timeout``. A
    subscriber-raised :class:`HookRefusal` propagates immediately —
    subsequent subscribers do not run, and the caller's caught
    exception means no mutated ctx is observable to the action body.
    Task 11 will layer ``refusable_tiers`` enforcement onto the raise
    arm; this slice lets every refusal propagate.

    On timeout: emits :data:`HOOKS_CHAIN_TIMEOUT` and either returns
    the last-good ctx (``fail_closed=False``) or raises
    :class:`HookError` (``fail_closed=True``). The cancelled
    subscriber's ``finally`` runs to completion via
    :func:`_handle_chain_timeout` before the disposition.

    Args:
        name: The hookpoint identifier the caller passed to
            :func:`invoke`.
        ctx: The retargeted carrier.
        subscribable_tiers: Threaded through for Task 11. Ignored.
        refusable_tiers: Threaded through for Task 11. Ignored.
        fail_closed: Task 9's timeout policy bit. Consumed in the
            ``except TimeoutError`` arm.

    Returns:
        The chain ctx folded across every ``pre`` subscriber, OR the
        last-good ctx if the chain timed out and ``fail_closed`` is
        ``False``.
    """
    del subscribable_tiers, refusable_tiers
    subscribers = get_registry().subscribers_for(name, "pre")
    deadline_seconds = get_registry().chain_deadline_seconds

    chain_ctx = ctx
    last_good_ctx = ctx
    pending: asyncio.Task[HookContext[T] | None] | None = None
    try:
        async with asyncio.timeout(deadline_seconds):
            for sub in subscribers:
                pending = _spawn_subscriber(sub, chain_ctx)
                try:
                    result = await pending
                except Exception as exc:
                    # Task 10 §6.6: caught + wrapped + audited + fail_closed
                    # applied. The catch is :class:`Exception` (NOT
                    # :class:`BaseException`) so :class:`asyncio.CancelledError`
                    # and :class:`SystemExit` / :class:`KeyboardInterrupt`
                    # propagate. :class:`HookRefusal` is a subclass of
                    # :class:`Exception` BUT is short-circuited by the
                    # explicit ``isinstance`` re-raise below; Task 11 will
                    # layer ``refusable_tiers`` enforcement onto that
                    # re-raise.
                    pending = None
                    if isinstance(exc, HookRefusal):
                        # Task 11 owns refusal-by-tier; this slice lets
                        # every refusal propagate uncaught by the wrap arm.
                        raise
                    # Wrap, audit, apply fail_closed.
                    await _emit_subscriber_error_audit(
                        sub=sub,
                        exc=exc,
                        hookpoint=name,
                        kind="pre",
                        correlation_id=chain_ctx.correlation_id,
                    )
                    if fail_closed:
                        raise _wrap_subscriber_error(
                            sub=sub,
                            correlation_id=chain_ctx.correlation_id,
                        ) from exc
                    # fail_closed=False: subscriber is pass-through.
                    # Rewind chain_ctx to the last-good snapshot so the
                    # NEXT subscriber sees the ctx as it was BEFORE this
                    # subscriber's call. Mutations the subscriber would
                    # have produced are discarded.
                    chain_ctx = last_good_ctx
                    continue
                pending = None
                if result is not None:
                    chain_ctx = result
                    last_good_ctx = result
        return chain_ctx
    except TimeoutError:
        return await _handle_chain_timeout(
            pending=pending,
            chain_ctx=chain_ctx,
            hookpoint=name,
            kind="pre",
            deadline_seconds=deadline_seconds,
            fail_closed=fail_closed,
        )


async def _run_post[T](
    name: str,
    ctx: HookContext[T],
    *,
    subscribable_tiers: frozenset[str],
    fail_closed: bool,
) -> HookContext[T]:
    """Dispatch the ``post`` chain.

    Linear walk-and-fold under one ``asyncio.timeout``. ``post`` has
    no short-circuit semantic — every subscriber runs (until Task 10
    introduces the unexpected-exception fault policy). The final ctx
    is the end-of-chain fold.

    On timeout: same disposition as ``_run_pre`` — audit row + either
    last-good or :class:`HookError`.

    Args:
        name: The hookpoint identifier the caller passed.
        ctx: The retargeted carrier.
        subscribable_tiers: Threaded through for Task 11. Ignored.
        fail_closed: Task 9's timeout policy bit.

    Returns:
        The chain ctx folded across every ``post`` subscriber, OR the
        last-good ctx if the chain timed out and ``fail_closed`` is
        ``False``.
    """
    del subscribable_tiers
    subscribers = get_registry().subscribers_for(name, "post")
    deadline_seconds = get_registry().chain_deadline_seconds

    chain_ctx = ctx
    last_good_ctx = ctx
    pending: asyncio.Task[HookContext[T] | None] | None = None
    try:
        async with asyncio.timeout(deadline_seconds):
            for sub in subscribers:
                pending = _spawn_subscriber(sub, chain_ctx)
                try:
                    result = await pending
                except Exception as exc:
                    # Task 10 §6.6: caught + wrapped + audited + fail_closed
                    # applied. Same shape as :func:`_run_pre`; post has no
                    # refusal contract (Task 11 only authorises ``pre``
                    # refusals) so the isinstance guard is unnecessary
                    # here, BUT we still re-raise :class:`HookRefusal` for
                    # safety so a subscriber that incorrectly raises one
                    # from a post-handler propagates rather than getting
                    # audited as a generic subscriber error.
                    pending = None
                    if isinstance(exc, HookRefusal):
                        raise
                    await _emit_subscriber_error_audit(
                        sub=sub,
                        exc=exc,
                        hookpoint=name,
                        kind="post",
                        correlation_id=chain_ctx.correlation_id,
                    )
                    if fail_closed:
                        raise _wrap_subscriber_error(
                            sub=sub,
                            correlation_id=chain_ctx.correlation_id,
                        ) from exc
                    chain_ctx = last_good_ctx
                    continue
                pending = None
                if result is not None:
                    chain_ctx = result
                    last_good_ctx = result
        return chain_ctx
    except TimeoutError:
        return await _handle_chain_timeout(
            pending=pending,
            chain_ctx=chain_ctx,
            hookpoint=name,
            kind="post",
            deadline_seconds=deadline_seconds,
            fail_closed=fail_closed,
        )


async def _run_error[T](
    name: str,
    ctx: HookContext[T],
    *,
    exc: BaseException | None,
    subscribable_tiers: frozenset[str],
    fail_closed: bool,
) -> HookContext[T]:
    """Dispatch the ``error`` chain.

    The first subscriber that returns a :class:`HookContext` wins
    (swallow-and-substitute) — subsequent subscribers do not run. If
    every subscriber returns ``None``, the original ``exc`` re-raises
    so the upstream failure is not silently swallowed (CLAUDE.md hard
    rule #7). The no-subscribers case also re-raises ``exc`` — same
    rationale.

    On chain timeout: the would-be re-raise is SUPPRESSED — the
    audit row IS the loud-failure escape, and last-good ctx is
    returned (or :class:`HookError` raised on ``fail_closed``). This
    is the timeout-arm-overrides-error-re-raise rule: when the chain
    didn't get to decide whether to suppress, the dispatcher takes the
    safer "record + return" path rather than re-raising an exception
    the chain might have meant to suppress.

    Task 11 will layer tier policy: only ``system``-tier subscribers'
    suppression is honoured; ``user-plugin``-tier returns are denied
    with a :data:`alfred.hooks.audit_sink.HOOKS_UNAUTHORIZED_REFUSAL`
    audit row. This slice grants suppression unconditionally.

    Args:
        name: The hookpoint identifier the caller passed.
        ctx: The retargeted carrier. Augmented with
            ``ctx.metadata[ERROR_EXC_METADATA_KEY] = exc`` for the
            duration of the chain so subscribers can introspect the
            upstream exception.
        exc: The upstream exception that triggered the ``error``
            stage. Re-raised at the end of the handler if no
            subscriber suppressed AND the chain did not time out.
        subscribable_tiers: Threaded through for Task 11. Ignored.
        fail_closed: Task 9's timeout policy bit.

    Returns:
        The substitute ctx returned by the first non-``None``
        subscriber, OR the last-good ctx on timeout when
        ``fail_closed`` is ``False``.

    Raises:
        HookError: ``fail_closed`` and the chain timed out.
        BaseException: The ``exc`` parameter, re-raised on the
            no-suppression-completed path. Identity preserved (the
            same instance) so the upstream traceback stays intact.
    """
    del subscribable_tiers

    subscribers = get_registry().subscribers_for(name, "error")
    deadline_seconds = get_registry().chain_deadline_seconds

    # Stash exc on metadata so subscribers can introspect it without
    # widening the canonical async-fn signature. The merge builds a
    # fresh dict so the caller's ctx.metadata is untouched.
    chain_ctx = ctx.with_metadata(**{ERROR_EXC_METADATA_KEY: exc})

    pending: asyncio.Task[HookContext[T] | None] | None = None
    suppressed: HookContext[T] | None = None
    last_good_ctx = chain_ctx
    try:
        async with asyncio.timeout(deadline_seconds):
            for sub in subscribers:
                pending = _spawn_subscriber(sub, chain_ctx)
                try:
                    result = await pending
                except Exception as raised_exc:
                    # Task 10 §6.6: caught + wrapped + audited + fail_closed
                    # applied. A subscriber that RAISES does NOT count as
                    # "returned a substitute" — the suppressed-vs-re-raise
                    # short-circuit on the error arm checks ``result is
                    # not None``, not "the catch arm fired". So when
                    # fail_closed=False and the subscriber raises, the
                    # chain continues and the upstream ``exc`` may still
                    # re-raise at the end if no later subscriber returns
                    # a substitute. That's the "no silent failure"
                    # guarantee for the error stage (CLAUDE.md hard
                    # rule #7).
                    pending = None
                    if isinstance(raised_exc, HookRefusal):
                        raise
                    await _emit_subscriber_error_audit(
                        sub=sub,
                        exc=raised_exc,
                        hookpoint=name,
                        kind="error",
                        correlation_id=chain_ctx.correlation_id,
                    )
                    if fail_closed:
                        raise _wrap_subscriber_error(
                            sub=sub,
                            correlation_id=chain_ctx.correlation_id,
                        ) from raised_exc
                    # fail_closed=False: continue chain with last-good ctx.
                    chain_ctx = last_good_ctx
                    continue
                pending = None
                if result is not None:
                    # First non-None wins — short-circuit the rest of the
                    # chain. Capture the substitute and break out of the
                    # timeout-wrapped loop so the post-loop disposition
                    # logic can return it cleanly.
                    suppressed = result
                    last_good_ctx = result
                    break
    except TimeoutError:
        return await _handle_chain_timeout(
            pending=pending,
            chain_ctx=chain_ctx,
            hookpoint=name,
            kind="error",
            deadline_seconds=deadline_seconds,
            fail_closed=fail_closed,
        )

    if suppressed is not None:
        return suppressed

    # No subscriber suppressed AND the chain did not time out — re-raise
    # the upstream exception. This is the load-bearing "no silent
    # failures" guarantee for the error stage; mypy narrowing for the
    # ``exc is None`` branch is via the explicit raise path below.
    if exc is None:
        # Defensive: a missing ``exc`` on an ``error`` invoke is a
        # caller bug. Raising RuntimeError instead of failing silently
        # keeps the loud-failure discipline (hard rule #7).
        raise RuntimeError(
            "invoke(kind='error', ...) called without an exc argument; "
            "the error stage requires the upstream exception."
        )
    raise exc


async def _run_cancel[T](
    name: str,
    ctx: HookContext[T],
    *,
    exc: BaseException | None,
    subscribable_tiers: frozenset[str],
    fail_closed: bool,
) -> HookContext[T]:
    """Dispatch the ``cancel`` chain.

    Walks every subscriber so each can run cleanup. Subscriber return
    values are IGNORED — ``cancel`` is cleanup-only, no
    mutation/substitution semantic. The original ``exc`` (conventionally
    :class:`asyncio.CancelledError`, which is a :class:`BaseException`
    in Python 3.8+) ALWAYS re-raises after the chain finishes —
    EXCEPT on chain timeout, where the audit row replaces the re-raise
    (the audit is the loud-failure escape and the chain didn't get to
    finish cleanup anyway).

    A subscriber that itself raises is swallowed-and-skipped so
    best-effort cleanup continues — Task 10 will layer an audit row
    onto the catch arm so the swallow is no longer silent. The catch
    deliberately covers :class:`BaseException` (not just
    :class:`Exception`) so a nested :class:`asyncio.CancelledError`
    raised by a subscriber cannot suppress the outer cancellation
    either; the outer ``exc`` we re-raise at the end is what the
    caller sees.

    Args:
        name: The hookpoint identifier the caller passed.
        ctx: The retargeted carrier. Augmented with
            ``ctx.metadata[ERROR_EXC_METADATA_KEY] = exc`` so cleanup
            subscribers can introspect the cancellation cause.
        exc: The cancellation sentinel. Conventionally a
            :class:`asyncio.CancelledError`. Re-raised at the end
            UNLESS the chain timed out.
        subscribable_tiers: Threaded through for Task 11. Ignored.
        fail_closed: Task 9's timeout policy bit.

    Returns:
        Last-good ctx on chain timeout when ``fail_closed`` is
        ``False``. Otherwise never returns — every path ends in a
        raise (either the re-raised ``exc`` or :class:`HookError`).

    Raises:
        HookError: ``fail_closed`` and the chain timed out.
        BaseException: The ``exc`` parameter, re-raised when the chain
            completed inside its deadline. Identity preserved.
    """
    del subscribable_tiers

    subscribers = get_registry().subscribers_for(name, "cancel")
    deadline_seconds = get_registry().chain_deadline_seconds
    chain_ctx = ctx.with_metadata(**{ERROR_EXC_METADATA_KEY: exc})

    pending: asyncio.Task[HookContext[T] | None] | None = None
    try:
        async with asyncio.timeout(deadline_seconds):
            for sub in subscribers:
                pending = _spawn_subscriber(sub, chain_ctx)
                try:
                    await pending
                except asyncio.CancelledError:
                    # Re-raise so the surrounding ``asyncio.timeout``
                    # scope can convert it into ``TimeoutError`` —
                    # ``asyncio.timeout`` signals deadline expiry by
                    # cancelling the current task and EXPECTS the
                    # cancellation to reach the scope boundary. If we
                    # swallowed it here (the broad ``BaseException``
                    # arm below) the timeout would silently disarm and
                    # the audit row would never land (CLAUDE.md hard
                    # rule #7).
                    raise
                except BaseException as cleanup_exc:
                    # cancel cleanup is best-effort; Task 10 emits an
                    # audit row so the swallow is not silent (CLAUDE.md
                    # hard rule #7). Re-raising a subscriber-raised
                    # exception here would let a cleanup bug suppress
                    # the original cancellation, which is the user-visible
                    # regression we are explicitly preventing.
                    # ``BaseException`` is the correct width —
                    # :class:`asyncio.CancelledError` is short-circuited
                    # above; :class:`SystemExit` / :class:`KeyboardInterrupt`
                    # would propagate the process-termination signal if
                    # not absorbed, but cancel cleanup must not abort
                    # itself on a botched subscriber so we absorb here.
                    # ``fail_closed`` is NOT honoured on the cancel arm —
                    # the cancellation always propagates at the end of
                    # the chain.
                    # Task 10 §6.6 (cancel arm): emit the audit row so
                    # the swallow is not silent (CLAUDE.md hard rule #7).
                    # No wrap, no fail_closed — cancel always propagates
                    # the original cancellation via the post-loop raise.
                    await _emit_subscriber_error_audit(
                        sub=sub,
                        exc=cleanup_exc,
                        hookpoint=name,
                        kind="cancel",
                        correlation_id=chain_ctx.correlation_id,
                    )
                pending = None
    except TimeoutError:
        return await _handle_chain_timeout(
            pending=pending,
            chain_ctx=chain_ctx,
            hookpoint=name,
            kind="cancel",
            deadline_seconds=deadline_seconds,
            fail_closed=fail_closed,
        )

    # Defensive — cancel without an exc is a caller bug; refuse loudly.
    if exc is None:
        raise RuntimeError(
            "invoke(kind='cancel', ...) called without an exc argument; "
            "the cancel stage requires the cancellation sentinel."
        )
    raise exc
