"""Hook subsystem dispatch primitive — Slice-2.5 PR-A Task 8.

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
3. Return the handler's :class:`HookContext` (for ``pre`` / ``post`` /
   error-suppressed) or re-raise (for the error-no-suppression /
   cancel-always-propagates branches).

This module ships the HAPPY PATH only. Faults land in later tasks:

* Per-chain ``asyncio.timeout`` wrap                 → Task 9.
* Unexpected-subscriber-exception fault policy + row → Task 10.
* Refusal-authorisation by tier + audit row          → Task 11.
* Re-entry bypass via :data:`alfred.hooks.registry._reentry` → Task 12.

The five-parameter :func:`invoke` signature is verbatim from spec §0 —
``subscribable_tiers`` / ``refusable_tiers`` / ``fail_closed`` /
``exc`` all flow through even where Task-8 dispatch ignores them, so
later tasks layer fault logic without changing the call shape.

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

Design — why ``_run_chain`` only serves ``pre`` and ``post``:

  ``pre`` and ``post`` share a linear-walk shape: walk the snapshot,
  call each subscriber, fold a ``HookContext`` return into the chain
  ctx, leave the chain ctx unchanged on a ``None`` return. The shared
  helper folds that into one body. ``error`` (first non-``None`` wins,
  re-raise if all ``None``) and ``cancel`` (return values ignored,
  ``exc`` always re-raises, subscriber exceptions cannot suppress) are
  different enough that inlining them is clearer than parameterising
  them through a callback. Each of the four handlers therefore has its
  own ``def`` and a structurally distinct body — the four-way coverage
  pin Task 14 will exercise.

Design — cancel subscriber exceptions are NOT re-raised:

  The ``_run_cancel`` handler catches every :class:`BaseException`
  (except the cancel sentinel itself) from a subscriber and continues
  with the next subscriber. This is the "cancel cleanup is
  best-effort" semantic — a botched cleanup must not block the rest
  from running, and absolutely must not suppress the original
  cancellation. Task 10 will layer audit-row emission onto the catch
  arm so the swallow is no longer silent (CLAUDE.md hard rule #7 —
  Task-10's audit row IS the loud-failure escape). For Task 8 the
  swallow ships without audit attribution; the test suite verifies
  the propagate-cancellation contract directly.
"""

from __future__ import annotations

from typing import Final

from alfred.hooks.context import HookContext, HookKind
from alfred.hooks.registry import (
    HOOK_CHAIN_DEADLINE_SECONDS,
    Subscriber,
    get_registry,
)

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

    Task 8 ships the happy-path dispatch:

    * ``pre`` — walk the chain, allow each subscriber to mutate
      ``ctx.input`` via :meth:`HookContext.with_input`. A
      :class:`HookRefusal` raised by any subscriber propagates
      immediately; downstream subscribers do not run; the caller never
      sees a rewritten ctx (the action body never runs).
    * ``post`` — walk the chain, fold every subscriber's returned ctx
      into the next subscriber's input. The final ctx is the
      end-of-chain fold.
    * ``error`` — walk the chain with ``exc`` exposed under
      ``ctx.metadata[ERROR_EXC_METADATA_KEY]``. The FIRST subscriber
      that returns a :class:`HookContext` wins
      (swallow-and-substitute); subsequent subscribers do not run. If
      every subscriber returns ``None``, the original ``exc``
      re-raises.
    * ``cancel`` — walk the chain so each subscriber can run cleanup;
      return values are IGNORED; the original ``exc`` (whatever
      :class:`BaseException` the caller passed; conventionally
      :class:`asyncio.CancelledError`) re-raises after the chain
      finishes. A subscriber exception is swallowed (best-effort
      cleanup) and the next subscriber still runs.

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
        fail_closed: Whether to fail closed on a timeout / unexpected
            subscriber error. Consumed by Tasks 9 + 10; this slice
            ignores the value.
        exc: The upstream exception for ``error`` / ``cancel`` kinds.
            Typed :class:`BaseException` because
            :class:`asyncio.CancelledError` is a ``BaseException``
            in Python 3.8+, NOT an :class:`Exception`. Ignored for
            ``pre`` / ``post`` (the caller can still pass it; the
            dispatcher does not propagate it onto ``ctx.metadata``
            for those kinds).

    Returns:
        For ``pre`` — the final mutated ctx (or the input ctx if no
        subscriber mutated).
        For ``post`` — the final folded ctx.
        For ``error`` — the substitute ctx returned by the first
        non-``None`` subscriber. If all subscribers returned ``None``,
        :func:`invoke` re-raises ``exc`` instead of returning.
        For ``cancel`` — never returns; ``exc`` always re-raises.

    Raises:
        HookRefusal: A ``pre`` subscriber refused the action. The
            error carries the refuser's ``hook_id`` / ``action_id`` /
            ``reason`` / ``correlation_id`` for the audit row Task 11
            will emit; this slice simply propagates.
        BaseException: The ``exc`` passed in, re-raised for the
            ``error``-all-none path and the ``cancel`` path. Identity
            is preserved so the upstream traceback is intact.
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
# Shared linear-walk core (used by _run_pre + _run_post)
# ──────────────────────────────────────────────────────────────────────


async def _run_chain[T](
    subscribers: tuple[Subscriber, ...],
    ctx: HookContext[T],
    *,
    deadline_seconds: float,
) -> HookContext[T]:
    """Walk a linear chain folding each subscriber's result.

    The shared core for ``pre`` and ``post`` — both share the
    "walk-and-fold" shape:

    * Subscriber returns a :class:`HookContext` → that becomes the new
      chain ctx; the next subscriber sees the rewritten payload.
    * Subscriber returns ``None`` → the current chain ctx flows
      forward unchanged.

    A :class:`HookRefusal` raised by any subscriber propagates
    out — the caller sees the raise. This is the only short-circuit
    semantic this helper honours; the rest of the per-kind disposition
    lives in :func:`_run_pre` / :func:`_run_post` / :func:`_run_error`
    / :func:`_run_cancel`.

    Args:
        subscribers: Ordered tuple from
            :meth:`HookRegistry.subscribers_for`. Iterated synchronously
            before the first ``await`` so a concurrent register-after-
            snapshot is safe.
        ctx: The carrier to fold subscribers' results into.
        deadline_seconds: Per-CHAIN deadline. Accepted now and IGNORED
            this slice; Task 9 wraps the body in
            ``asyncio.timeout(deadline_seconds)``. Keeping the parameter
            on the signature now means Task 9 lands as a single-line
            wrap-the-body edit, not a signature change every handler
            has to re-thread.

    Returns:
        The chain ctx after every subscriber has run.
    """
    # deadline_seconds is wired through for Task 9 but unused this slice.
    # Avoid an unused-arg lint via a side-effect-free reference.
    del deadline_seconds

    for sub in subscribers:
        result = await sub.hook_fn(ctx)
        if result is not None:
            ctx = result
    return ctx


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

    Linear walk via :func:`_run_chain`. A subscriber-raised
    :class:`HookRefusal` propagates immediately — subsequent
    subscribers do not run, and the caller's caught exception means
    no mutated ctx is observable to the action body. Task 11 will
    layer ``refusable_tiers`` enforcement onto the raise arm; this
    slice lets every refusal propagate.

    Args:
        name: The hookpoint identifier the caller passed to
            :func:`invoke`.
        ctx: The retargeted carrier.
        subscribable_tiers: Threaded through for Task 11. Ignored.
        refusable_tiers: Threaded through for Task 11. Ignored.
        fail_closed: Threaded through for Task 9. Ignored.

    Returns:
        The chain ctx folded across every ``pre`` subscriber.
    """
    del subscribable_tiers, refusable_tiers, fail_closed
    subscribers = get_registry().subscribers_for(name, "pre")
    return await _run_chain(
        subscribers,
        ctx,
        deadline_seconds=HOOK_CHAIN_DEADLINE_SECONDS,
    )


async def _run_post[T](
    name: str,
    ctx: HookContext[T],
    *,
    subscribable_tiers: frozenset[str],
    fail_closed: bool,
) -> HookContext[T]:
    """Dispatch the ``post`` chain.

    Linear walk via :func:`_run_chain`. ``post`` has no short-circuit
    semantic — every subscriber runs (until Task 10 introduces the
    unexpected-exception fault policy). The final ctx is the
    end-of-chain fold.

    Args:
        name: The hookpoint identifier the caller passed.
        ctx: The retargeted carrier.
        subscribable_tiers: Threaded through for Task 11. Ignored.
        fail_closed: Threaded through for Task 9. Ignored.

    Returns:
        The chain ctx folded across every ``post`` subscriber.
    """
    del subscribable_tiers, fail_closed
    subscribers = get_registry().subscribers_for(name, "post")
    return await _run_chain(
        subscribers,
        ctx,
        deadline_seconds=HOOK_CHAIN_DEADLINE_SECONDS,
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
            subscriber suppressed.
        subscribable_tiers: Threaded through for Task 11. Ignored.
        fail_closed: Threaded through for Task 9. Ignored.

    Returns:
        The substitute ctx returned by the first non-``None``
        subscriber.

    Raises:
        BaseException: The ``exc`` parameter, re-raised. Identity
            preserved (the same instance) so the upstream traceback
            stays intact.
    """
    del subscribable_tiers, fail_closed

    subscribers = get_registry().subscribers_for(name, "error")

    # Stash exc on metadata so subscribers can introspect it without
    # widening the canonical async-fn signature. The merge builds a
    # fresh dict so the caller's ctx.metadata is untouched.
    chain_ctx = ctx.with_metadata(**{ERROR_EXC_METADATA_KEY: exc})

    for sub in subscribers:
        result = await sub.hook_fn(chain_ctx)
        if result is not None:
            # First non-None wins — short-circuit the rest of the chain.
            return result

    # No subscriber suppressed — re-raise the upstream exception. This
    # is the load-bearing "no silent failures" guarantee for the error
    # stage; mypy narrowing for the ``exc is None`` branch is via the
    # explicit raise path below. ``exc`` is optionally None on the
    # signature for symmetry with the other kinds, but a caller that
    # passes kind="error" without an exc is a programming error.
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
    in Python 3.8+) ALWAYS re-raises after the chain finishes.

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
            :class:`asyncio.CancelledError`. Re-raised at the end.
        subscribable_tiers: Threaded through for Task 11. Ignored.
        fail_closed: Threaded through for Task 9. Ignored.

    Returns:
        Never returns — the declared return type satisfies the
        :func:`invoke` signature, but every path ends in a raise.

    Raises:
        BaseException: The ``exc`` parameter, re-raised. Identity
            preserved.
    """
    del subscribable_tiers, fail_closed

    subscribers = get_registry().subscribers_for(name, "cancel")
    chain_ctx = ctx.with_metadata(**{ERROR_EXC_METADATA_KEY: exc})

    for sub in subscribers:
        try:  # noqa: SIM105 -- explicit try/except keeps the inline comment block visible to future readers; `contextlib.suppress(BaseException)` would hide the security-review-load-bearing rationale.
            await sub.hook_fn(chain_ctx)
        except BaseException:  # noqa: S110 -- cancel cleanup is best-effort; Task 10 adds audit-row emission to this arm so the swallow is not silent. Re-raising would let a cleanup bug suppress the original cancellation, which is the user-visible regression we are explicitly preventing.
            # Best-effort cleanup — swallow so subsequent subscribers
            # can still run. CLAUDE.md hard rule #7's loud-failure
            # discipline is satisfied by Task 10's audit row on the
            # same arm; this slice ships the propagate-cancellation
            # contract pinned by the test suite. Re-raising here would
            # let a cleanup bug suppress the original cancellation —
            # the user-visible regression we are explicitly preventing.
            pass

    # Defensive — cancel without an exc is a caller bug; refuse loudly.
    if exc is None:
        raise RuntimeError(
            "invoke(kind='cancel', ...) called without an exc argument; "
            "the cancel stage requires the cancellation sentinel."
        )
    raise exc
