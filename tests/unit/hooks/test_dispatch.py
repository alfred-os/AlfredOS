"""Tests for ``alfred.hooks.invoke`` — Slice-2.5 PR-A Task 8.

The :func:`alfred.hooks.invoke.invoke` primitive is the dispatcher's
public entry point. It applies :meth:`HookContext.for_stage` to retarget
the carrier to the (hookpoint, kind) pair the caller passed, then routes
to one of four private handlers (``_run_pre`` / ``_run_post`` /
``_run_error`` / ``_run_cancel``). Each handler walks the
:meth:`HookRegistry.subscribers_for` snapshot and folds subscriber
results into a final :class:`HookContext` (or re-raises, per kind).

Invariants pinned here (Task 8 happy-path dispatch — fault wiring lands
in Tasks 9-12):

* :func:`invoke` is AUTHORITATIVE for ``(hookpoint, kind)`` — a stale
  caller-side ctx is silently retargeted via ``for_stage``.
* ``pre`` mutations flow through the chain; a later ``HookRefusal``
  short-circuits and the caller never observes the earlier mutations
  (the action body never runs).
* ``post`` mutations chain through every subscriber and the final ctx
  is the fold.
* ``error`` subscribers may either return a substitute ctx
  (swallow-and-substitute, first non-``None`` wins) or ``None``
  (re-raise the original ``exc``).
* ``cancel`` subscribers run cleanup only — their return values are
  ignored, ``CancelledError`` ALWAYS propagates, and a cancel subscriber
  raising an unrelated exception cannot suppress the cancellation.
* The no-subscribers path returns a ctx whose payload is identical to
  the input (``for_stage`` produces a fresh frozen instance with the
  same ``input``, ``correlation_id``, etc.).
* :meth:`HookRegistry.subscribers_for` returns the :data:`_EMPTY`
  module singleton on a miss — the dispatcher's miss branch pays no
  allocation.

Out of scope for Task 8 (each lands with its own failing test):

* Per-chain ``asyncio.timeout`` wrap (Task 9).
* Unexpected-subscriber-exception fault policy + audit row (Task 10).
* Refusal-authorisation by tier (Task 11).
* Re-entry bypass via :data:`alfred.hooks.registry._reentry` (Task 12).
* Audit-row emission for any fault path.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from alfred.hooks.context import HookContext, HookKind
from alfred.hooks.errors import HookError, HookRefusal
from alfred.hooks.invoke import invoke
from alfred.hooks.registry import _EMPTY, HookRegistry, _reentry

# ──────────────────────────────────────────────────────────────────────
# Test helpers
# ──────────────────────────────────────────────────────────────────────


def _ctx(
    *,
    input_: object = "initial",
    hookpoint: str = "action.test",
    kind: str = "pre",
    correlation_id: str = "corr-1",
    action_id: str = "action.test",
) -> HookContext[Any]:
    """Build a fresh :class:`HookContext` for a test.

    Centralised so a future field addition doesn't churn every test.
    The ``kind`` argument accepts a plain ``str`` because some tests
    deliberately pass a STALE kind to prove :func:`invoke` retargets via
    :meth:`HookContext.for_stage`; mypy-strict at the test layer would
    reject the broader type without a cast site here.
    """
    return HookContext(
        action_id=action_id,
        hookpoint=hookpoint,
        input=input_,
        correlation_id=correlation_id,
        kind=kind,  # type: ignore[arg-type]  # tests pass stale kinds intentionally
    )


# ──────────────────────────────────────────────────────────────────────
# 1. invoke applies for_stage — subscriber sees the CORRECTED stage
# ──────────────────────────────────────────────────────────────────────


async def test_invoke_applies_for_stage_to_retarget_stale_caller_ctx(
    fresh_registry: HookRegistry,
) -> None:
    """``invoke`` rewrites ``ctx.hookpoint`` + ``ctx.kind`` so a
    subscriber sees the stage ``invoke`` was called with, not the stage
    the caller's stale ctx claims.

    The caller passes ``kind="pre"`` on the ctx but invokes the
    ``"post"`` chain — the subscriber must see ``ctx.kind == "post"``
    and ``ctx.hookpoint == "stage.b"``.
    """
    seen: dict[str, object] = {}

    async def subscriber(ctx: HookContext[Any]) -> HookContext[Any] | None:
        seen["kind"] = ctx.kind
        seen["hookpoint"] = ctx.hookpoint
        return None

    fresh_registry.register(
        hook_fn=subscriber,
        hookpoint="stage.b",
        kind="post",
        tier="operator",
    )

    stale = _ctx(hookpoint="stage.a", kind="pre")
    await invoke("stage.b", stale, kind="post")

    assert seen == {"kind": "post", "hookpoint": "stage.b"}


# ──────────────────────────────────────────────────────────────────────
# 2. pre mutation flows through chain to invoke's return
# ──────────────────────────────────────────────────────────────────────


async def test_pre_mutation_flows_to_invokes_return(
    fresh_registry: HookRegistry,
) -> None:
    """Two ``pre`` subscribers: A mutates input → "mutated"; B is a
    passthrough returning ``None``. ``invoke`` returns a ctx whose
    ``input == "mutated"``.
    """

    async def mutator(ctx: HookContext[Any]) -> HookContext[Any]:
        return ctx.with_input("mutated")

    async def passthrough(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        return None

    fresh_registry.register(
        hook_fn=mutator,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )
    fresh_registry.register(
        hook_fn=passthrough,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )

    result = await invoke("hp", _ctx(), kind="pre")
    assert result.input == "mutated"


# ──────────────────────────────────────────────────────────────────────
# 3. pre mutation discarded on later refusal
# ──────────────────────────────────────────────────────────────────────


async def test_pre_refusal_discards_earlier_mutation(
    fresh_registry: HookRegistry,
) -> None:
    """A ``pre`` chain of [mutator, refuser]: the refuser raises
    :class:`HookRefusal`; the caller's caught exception means no
    mutated ctx is observable (the action never sees the mutation).

    This pins the spec's "discard the chain's mutation on refusal"
    semantic — the only escape path for the caller is the raised
    exception, and the exception carries no rewritten ctx.
    """

    async def mutator(ctx: HookContext[Any]) -> HookContext[Any]:
        return ctx.with_input("would-be-mutated")

    async def refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="refuser",
            action_id="action.test",
            reason="policy",
            correlation_id="corr-1",
        )

    fresh_registry.register(
        hook_fn=mutator,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )
    fresh_registry.register(
        hook_fn=refuser,
        hookpoint="hp",
        kind="pre",
        tier="operator",
    )

    with pytest.raises(HookRefusal) as exc_info:
        await invoke("hp", _ctx(), kind="pre")

    # The exception object carries the refuser's attribution — there is
    # no rewritten ctx to inspect. The action body never runs.
    assert exc_info.value.hook_id == "refuser"
    assert exc_info.value.reason == "policy"


# ──────────────────────────────────────────────────────────────────────
# 4. post mutations chain through every subscriber
# ──────────────────────────────────────────────────────────────────────


async def test_post_mutations_chain_through_every_subscriber(
    fresh_registry: HookRegistry,
) -> None:
    """Two ``post`` subscribers, each mutating input. The final ctx
    reflects BOTH mutations in registration order (same tier → seq
    order; see :meth:`HookRegistry.subscribers_for`).
    """

    async def append_a(ctx: HookContext[Any]) -> HookContext[Any]:
        assert isinstance(ctx.input, str)
        return ctx.with_input(ctx.input + ":A")

    async def append_b(ctx: HookContext[Any]) -> HookContext[Any]:
        assert isinstance(ctx.input, str)
        return ctx.with_input(ctx.input + ":B")

    fresh_registry.register(
        hook_fn=append_a,
        hookpoint="hp",
        kind="post",
        tier="operator",
    )
    fresh_registry.register(
        hook_fn=append_b,
        hookpoint="hp",
        kind="post",
        tier="operator",
    )

    result = await invoke("hp", _ctx(input_="x"), kind="post")
    assert result.input == "x:A:B"


# ──────────────────────────────────────────────────────────────────────
# 5. error: swallow-and-substitute when subscriber returns a ctx
# ──────────────────────────────────────────────────────────────────────


async def test_error_swallow_and_substitute(
    fresh_registry: HookRegistry,
) -> None:
    """An ``error`` subscriber returning a :class:`HookContext` causes
    :func:`invoke` to return that ctx (swallow-and-substitute). No
    exception re-raises.
    """

    async def suppressor(ctx: HookContext[Any]) -> HookContext[Any]:
        # The substitute ctx is observable by the caller as the
        # invoke return value.
        return ctx.with_input("substituted")

    fresh_registry.register(
        hook_fn=suppressor,
        hookpoint="hp",
        kind="error",
        tier="operator",
    )

    result = await invoke(
        "hp",
        _ctx(),
        kind="error",
        exc=ValueError("boom"),
    )
    assert result.input == "substituted"


# ──────────────────────────────────────────────────────────────────────
# 6. error: re-raise when subscriber returns None
# ──────────────────────────────────────────────────────────────────────


async def test_error_subscriber_returning_none_re_raises_original_exc(
    fresh_registry: HookRegistry,
) -> None:
    """An ``error`` subscriber that returns ``None`` triggers
    re-raise of the original ``exc``; traceback is preserved (the same
    exception INSTANCE is the raised value).
    """
    original = ValueError("original-boom")

    async def observer(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        return None

    fresh_registry.register(
        hook_fn=observer,
        hookpoint="hp",
        kind="error",
        tier="operator",
    )

    with pytest.raises(ValueError) as exc_info:
        await invoke("hp", _ctx(), kind="error", exc=original)
    assert exc_info.value is original


async def test_error_no_subscribers_re_raises_exc(
    fresh_registry: HookRegistry,
) -> None:
    """``error`` invoke with zero subscribers re-raises the original
    ``exc`` — the no-subscriber path must NOT silently swallow the
    upstream failure.
    """
    original = RuntimeError("upstream-boom")

    with pytest.raises(RuntimeError) as exc_info:
        await invoke("hp", _ctx(), kind="error", exc=original)
    assert exc_info.value is original


# ──────────────────────────────────────────────────────────────────────
# 7. cancel: cleanup-only, CancelledError always propagates
# ──────────────────────────────────────────────────────────────────────


async def test_cancel_subscriber_cleanup_propagates_cancellederror(
    fresh_registry: HookRegistry,
) -> None:
    """A normal ``cancel`` subscriber runs cleanup and ``CancelledError``
    propagates. Subscriber return value is IGNORED.
    """
    cleanup_ran: list[bool] = []

    async def cleanup(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        cleanup_ran.append(True)
        # Even if we returned a substitute ctx, cancel ignores it.
        return _ctx.with_input("ignored-substitute")

    fresh_registry.register(
        hook_fn=cleanup,
        hookpoint="hp",
        kind="cancel",
        tier="operator",
    )

    cancelled = _CancelledMarker()
    with pytest.raises(_CancelledMarker) as exc_info:
        await invoke("hp", _ctx(), kind="cancel", exc=cancelled)

    assert cleanup_ran == [True]
    assert exc_info.value is cancelled


# ──────────────────────────────────────────────────────────────────────
# 8. cancel: subscriber raising ValueError cannot suppress cancel
# ──────────────────────────────────────────────────────────────────────


async def test_cancel_subscriber_raising_cannot_suppress(
    fresh_registry: HookRegistry,
) -> None:
    """A ``cancel`` subscriber that itself raises ``ValueError`` does
    NOT suppress the cancellation — the original ``exc`` re-raises.
    Subsequent cancel subscribers still run (cleanup is best-effort).
    """
    second_ran: list[bool] = []

    async def raiser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise ValueError("cleanup-failed")

    async def second(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        second_ran.append(True)
        return None

    fresh_registry.register(
        hook_fn=raiser,
        hookpoint="hp",
        kind="cancel",
        tier="operator",
    )
    fresh_registry.register(
        hook_fn=second,
        hookpoint="hp",
        kind="cancel",
        tier="operator",
    )

    cancelled = _CancelledMarker()
    with pytest.raises(_CancelledMarker) as exc_info:
        await invoke("hp", _ctx(), kind="cancel", exc=cancelled)
    assert exc_info.value is cancelled
    # The second subscriber still ran — the first's exception did not
    # short-circuit cleanup. This is the "cancel is best-effort" pin.
    assert second_ran == [True]


# ──────────────────────────────────────────────────────────────────────
# 9. No-subscribers path returns ctx with same payload
# ──────────────────────────────────────────────────────────────────────


async def test_no_subscribers_returns_ctx_with_same_payload(
    fresh_registry: HookRegistry,
) -> None:
    """Invoking a hookpoint with zero subscribers returns a ctx whose
    payload-equivalent fields match the input. ``for_stage`` runs
    UNCONDITIONALLY so the returned instance may not be identical to
    the input, but its ``input`` / ``correlation_id`` / ``action_id``
    must be preserved.
    """
    src = _ctx(input_="payload", correlation_id="corr-X")
    result = await invoke("hp.no.subs", src, kind="pre")

    assert result.input == "payload"
    assert result.correlation_id == "corr-X"
    assert result.action_id == src.action_id
    # for_stage retargets — even with zero subscribers, kind/hookpoint
    # are rewritten to what invoke was called with.
    assert result.kind == "pre"
    assert result.hookpoint == "hp.no.subs"


# ──────────────────────────────────────────────────────────────────────
# 10. _EMPTY identity pin — no allocation on miss
# ──────────────────────────────────────────────────────────────────────


def test_subscribers_for_returns_empty_singleton_on_miss(
    fresh_registry: HookRegistry,
) -> None:
    """The no-allocation invariant: ``subscribers_for`` returns the
    shared :data:`_EMPTY` tuple identity on a miss. The dispatcher's
    happy path through :func:`invoke` lands on this branch for every
    zero-subscriber hookpoint.

    This is the registry-side pin that backs the
    ``test_no_subscribers_returns_ctx_with_same_payload`` invariant —
    if a future regression allocates a fresh empty tuple per miss, the
    identity check fails here.
    """
    found = fresh_registry.subscribers_for("hp.never.registered", "pre")
    assert found is _EMPTY


# ──────────────────────────────────────────────────────────────────────
# 11. Branch-coverage pins for each private handler
# ──────────────────────────────────────────────────────────────────────


async def test_pre_handler_with_zero_subscribers(
    fresh_registry: HookRegistry,
) -> None:
    """Exercises ``_run_pre``'s empty-subscribers branch — distinct
    from the multi-subscriber branch covered by test #2.
    """
    result = await invoke("hp", _ctx(input_="x"), kind="pre")
    assert result.input == "x"


async def test_post_handler_with_zero_subscribers(
    fresh_registry: HookRegistry,
) -> None:
    """Exercises ``_run_post``'s empty-subscribers branch — distinct
    from the multi-subscriber branch covered by test #4.
    """
    result = await invoke("hp", _ctx(input_="x"), kind="post")
    assert result.input == "x"


async def test_post_subscriber_returning_none_passes_through(
    fresh_registry: HookRegistry,
) -> None:
    """A ``post`` subscriber returning ``None`` leaves the ctx
    untouched for the next subscriber — pins the ``None``-result branch
    of ``_run_post``.
    """

    async def noop(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        return None

    async def append_tag(ctx: HookContext[Any]) -> HookContext[Any]:
        assert isinstance(ctx.input, str)
        return ctx.with_input(ctx.input + ":tagged")

    fresh_registry.register(
        hook_fn=noop,
        hookpoint="hp",
        kind="post",
        tier="operator",
    )
    fresh_registry.register(
        hook_fn=append_tag,
        hookpoint="hp",
        kind="post",
        tier="operator",
    )

    result = await invoke("hp", _ctx(input_="x"), kind="post")
    assert result.input == "x:tagged"


async def test_error_first_substitute_wins(
    fresh_registry: HookRegistry,
) -> None:
    """Two ``error`` subscribers: the first returns a substitute; the
    second is never called. Pins the "first non-``None`` wins"
    short-circuit branch of ``_run_error``.
    """
    second_ran: list[bool] = []

    async def first(ctx: HookContext[Any]) -> HookContext[Any]:
        return ctx.with_input("first-sub")

    async def second(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        second_ran.append(True)
        return None

    fresh_registry.register(
        hook_fn=first,
        hookpoint="hp",
        kind="error",
        tier="operator",
    )
    fresh_registry.register(
        hook_fn=second,
        hookpoint="hp",
        kind="error",
        tier="operator",
    )

    result = await invoke("hp", _ctx(), kind="error", exc=ValueError("x"))
    assert result.input == "first-sub"
    assert second_ran == []


async def test_cancel_handler_with_zero_subscribers(
    fresh_registry: HookRegistry,
) -> None:
    """``_run_cancel`` with no subscribers still re-raises the original
    ``exc``. Exercises the empty-iteration branch of the cancel handler.
    """
    cancelled = _CancelledMarker()
    with pytest.raises(_CancelledMarker) as exc_info:
        await invoke("hp", _ctx(), kind="cancel", exc=cancelled)
    assert exc_info.value is cancelled


# ──────────────────────────────────────────────────────────────────────
# 12. Defensive RuntimeError pins — error/cancel without exc
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("fresh_registry")
async def test_error_kind_without_exc_raises_runtime_error() -> None:
    """Calling :func:`invoke` with ``kind="error"`` and ``exc=None`` is
    a caller bug — the early precondition check at the top of
    :func:`invoke` refuses loudly with a :class:`RuntimeError` so the
    upstream failure cannot be silently swallowed (CLAUDE.md hard
    rule #7). The per-handler check in :func:`_run_error` remains as a
    defense-in-depth canary; today the early raise reaches first.
    """
    with pytest.raises(RuntimeError, match="error stage requires"):
        await invoke("hp.defensive.error", _ctx(), kind="error", exc=None)


@pytest.mark.usefixtures("fresh_registry")
async def test_cancel_kind_without_exc_raises_runtime_error() -> None:
    """Calling :func:`invoke` with ``kind="cancel"`` and ``exc=None`` is
    a caller bug — the early precondition check at the top of
    :func:`invoke` refuses loudly with a :class:`RuntimeError`. There
    is no meaningful cancellation to re-raise without a sentinel, so
    silently returning would violate the "cancel always propagates"
    contract. The per-handler check in :func:`_run_cancel` remains as a
    defense-in-depth canary.
    """
    with pytest.raises(RuntimeError, match="cancel stage requires"):
        await invoke("hp.defensive.cancel", _ctx(), kind="cancel", exc=None)


@pytest.mark.usefixtures("fresh_registry")
async def test_reentrant_invoke_error_kind_without_exc_raises_runtime_error() -> None:
    """The early ``exc``-precondition guard ALSO catches the
    re-entrant bypass path.

    Without the early raise at the top of :func:`invoke`, a re-entry
    detection would route directly to :func:`_invoke_internal` BEFORE
    the per-handler defensive RuntimeError checks fire — silently
    bypassing the chain on a missing-``exc`` caller bug. Seeding the
    ``_reentry`` stack with the target hookpoint simulates the
    re-entrant condition without spinning up a subscriber that
    self-invokes; the early guard at the public surface is what
    catches the misuse.
    """
    token = _reentry.set(("hp.reentrant.error",))
    try:
        with pytest.raises(RuntimeError, match="error stage requires"):
            await invoke("hp.reentrant.error", _ctx(), kind="error", exc=None)
    finally:
        _reentry.reset(token)


@pytest.mark.usefixtures("fresh_registry")
async def test_reentrant_invoke_cancel_kind_without_exc_raises_runtime_error() -> None:
    """Symmetric re-entrant-path guard for ``kind="cancel"``.

    Same shape as the error-arm reentrant test: the early
    precondition at :func:`invoke`'s public surface guarantees an
    omitted ``exc`` raises :class:`RuntimeError` on the bypass route,
    not just on the first-call route. The per-handler check in
    :func:`_run_cancel` is the defense-in-depth backstop.
    """
    token = _reentry.set(("hp.reentrant.cancel",))
    try:
        with pytest.raises(RuntimeError, match="cancel stage requires"):
            await invoke("hp.reentrant.cancel", _ctx(), kind="cancel", exc=None)
    finally:
        _reentry.reset(token)


@pytest.mark.usefixtures("fresh_registry")
async def test_dispatch_unknown_kind_raises_hook_error() -> None:
    """A runtime-constructed ``kind`` value outside the :data:`HookKind`
    literal set raises :class:`HookError`.

    The :data:`HookKind` Literal alias provides STATIC exhaustiveness
    via mypy / pyright at the call site, but a runtime caller that
    bypasses the type system (``cast(Any, "invalid")``) or builds the
    string from un-sanitised input would otherwise silently route to
    the ``cancel`` handler under the pre-fix branch ordering — a
    silent misroute is exactly the hazard CLAUDE.md hard rule #7
    forbids. The explicit ``raise HookError(...)`` keeps the
    misuse loud.
    """
    bad_kind = cast(HookKind, "invalid-kind")
    with pytest.raises(HookError, match="Unsupported hook kind"):
        await invoke("hp.unknown.kind", _ctx(), kind=bad_kind)


# ──────────────────────────────────────────────────────────────────────
# 13. Defense-in-depth canaries — per-handler exc=None raises
# ──────────────────────────────────────────────────────────────────────
#
# The early precondition guard at the top of :func:`invoke` catches
# ``exc is None`` on every public-surface call (first-call, re-entrant,
# and via :func:`invoking`) BEFORE reaching the per-kind handlers, so
# the handlers' own ``if exc is None: raise RuntimeError(...)`` arms
# are NORMALLY unreachable. They remain in source as defense-in-depth
# canaries: a future refactor that moves the early guard out of
# :func:`invoke` (a refactor we explicitly do not want) would surface
# as the handlers' arms going from "unreached" to "reached" — a
# coverage delta a reviewer is forced to notice.
#
# The tests below exercise the canaries directly by importing the
# private handlers and calling them with ``exc=None``, with the
# explicit caveat that PRODUCTION CODE NEVER ROUTES HERE.


@pytest.mark.usefixtures("fresh_registry")
async def test_run_error_handler_directly_raises_without_exc() -> None:
    """Defense-in-depth canary: :func:`_run_error` keeps its own
    ``exc is None`` raise as anti-refactor scaffolding.

    Calling the private handler directly bypasses the public early
    guard at :func:`invoke`'s entry. Without subscribers AND with
    ``exc=None``, the handler reaches the defensive
    ``raise RuntimeError(...)`` arm at the end of its body. This
    arm SHOULD NOT be reachable from production code (the public
    surface raises first); the canary stays so a refactor that
    weakens the public guard is caught by a coverage delta.
    """
    from alfred.hooks.invoke import _run_error

    with pytest.raises(RuntimeError, match="error stage requires"):
        await _run_error(
            "hp.canary.error",
            _ctx(),
            exc=None,
            subscribable_tiers=frozenset({"system", "operator", "user-plugin"}),
            fail_closed=False,
        )


@pytest.mark.usefixtures("fresh_registry")
async def test_run_cancel_handler_directly_raises_without_exc() -> None:
    """Defense-in-depth canary: :func:`_run_cancel` keeps its own
    ``exc is None`` raise as anti-refactor scaffolding.

    Symmetric to the error-arm canary above — the per-handler
    defensive arm is unreachable via :func:`invoke` but pinned here
    so the language-level coverage signal stays honest if a future
    refactor moves the public early guard.
    """
    from alfred.hooks.invoke import _run_cancel

    with pytest.raises(RuntimeError, match="cancel stage requires"):
        await _run_cancel(
            "hp.canary.cancel",
            _ctx(),
            exc=None,
            subscribable_tiers=frozenset({"system", "operator", "user-plugin"}),
            fail_closed=False,
        )


# ──────────────────────────────────────────────────────────────────────
# Test-scope sentinel exception
# ──────────────────────────────────────────────────────────────────────


class _CancelledMarker(BaseException):
    """A test-scope ``BaseException`` standing in for
    :class:`asyncio.CancelledError`.

    Using a marker class instead of the real ``CancelledError`` lets us
    assert identity preservation without poking the running task's
    cancellation state — pytest-asyncio handles a real CancelledError
    specially during teardown. The dispatcher's ``cancel`` handler
    treats the ``exc`` payload as an opaque ``BaseException`` re-raise
    target, so the marker class exercises the same code path.

    Underscore-prefixed name keeps pytest from collecting it as a test
    class (the ``Test`` prefix would trigger automatic collection).
    """
