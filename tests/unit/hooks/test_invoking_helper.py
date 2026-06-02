"""Tests for :func:`alfred.hooks.invoke.invoking` — Slice-2.5 PR-A Task 13.

The :func:`invoking` async context manager is the ergonomic surface over
the raw four-kind :func:`invoke` primitive. An action that wants the
canonical ``pre → body → post / error / cancel`` lifecycle uses
:func:`invoking` instead of hand-rolling four :func:`invoke` calls. The
helper:

* mints ONE ``correlation_id`` shared across every stage so the audit
  trail joins on a single id;
* threads each chain's output frozen :class:`HookContext` into the
  flow's mutable ``_ctx`` holder so ``flow.input`` reflects the latest
  stage's mutation (the ctx instances themselves stay frozen — the
  Flow is the mutable holder);
* fires ``post`` on body success, ``error`` on body :class:`Exception`,
  and ``cancel`` on :class:`asyncio.CancelledError` mid-body — with the
  CANCEL chain firing BEFORE the error chain and the ERROR chain
  never running on a cancellation. This is the load-bearing
  test-102 cancel-before-error invariant (spec §4) — a regression here
  would let an action's error handler observe a cancellation as if it
  were a non-cancellation failure, which would corrupt audit
  attribution and could leak T3 user content into the wrong audit
  arm (CLAUDE.md hard rule #7 + trust-tier discipline).

Each test below has ONE responsibility — refactor risk on the helper
surfaces as a single failing test rather than a cluster of vague
errors.

Out of scope (PR-B owns these):

* The five canonical hookpoint names ``before_validate`` /
  ``before_db_write`` / ``after_flush`` / ``write_failed`` /
  ``cancelled`` — :func:`invoking` is name-agnostic; PR-B's
  ``EpisodicMemory.record`` picks the names.
* Integration with the real :class:`alfred.audit.log.AuditWriter`
  sink — PR-B's :class:`EpisodicAuditSink` is the durable path.
* The ``gate=`` kwarg's effect on subscriber tier checks — Slice-3's
  grant gate (:class:`alfred.security.capability_gate._gate.RealGate`)
  consumes that surface; the fixture-parity gate (post-PR-S3-7) is
  exercised through the standard registry-injection fixtures in
  :mod:`tests.unit.hooks.conftest`.
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Any

import pytest

from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookRefusal
from alfred.hooks.invoke import Flow, invoking
from alfred.hooks.registry import HookRegistry

# ──────────────────────────────────────────────────────────────────────
# Test helpers
# ──────────────────────────────────────────────────────────────────────


class _CancelledMarker(BaseException):
    """A test-scope :class:`BaseException` standing in for
    :class:`asyncio.CancelledError`.

    Mirrors the marker used in ``test_dispatch.py`` — pytest-asyncio
    handles a real :class:`asyncio.CancelledError` specially during
    teardown, so a marker class exercises the same dispatcher code
    paths without poking the running task's cancellation state. NOT a
    substitute for the real cancel-arm coverage in the cancel-mid-body
    test below, which raises a real :class:`asyncio.CancelledError`
    inside the body to exercise the helper's ``except CancelledError``
    arm. This marker stands in for the ``exc=`` payload only.
    """


# ──────────────────────────────────────────────────────────────────────
# 1. Shared correlation_id across stages
# ──────────────────────────────────────────────────────────────────────


async def test_invoking_mints_one_correlation_id_shared_across_stages(
    fresh_registry: HookRegistry,
) -> None:
    """:func:`invoking` mints ONE ``correlation_id`` at entry and threads
    it through every chain stage.

    Spy ``pre`` subscribers on two different stage names both observe
    the SAME ``correlation_id`` on their handed-in ctx. The audit-trail
    join key is this id; a per-stage mint would defeat the join.
    """
    seen: list[str] = []

    async def spy_a(ctx: HookContext[Any]) -> HookContext[Any] | None:
        seen.append(ctx.correlation_id)
        return None

    async def spy_b(ctx: HookContext[Any]) -> HookContext[Any] | None:
        seen.append(ctx.correlation_id)
        return None

    fresh_registry.register(hook_fn=spy_a, hookpoint="a", kind="pre", tier="operator")
    fresh_registry.register(hook_fn=spy_b, hookpoint="b", kind="pre", tier="operator")

    async with invoking("action.test", "payload") as flow:
        await flow.pre("a")
        await flow.pre("b")

    assert len(seen) == 2
    assert seen[0] == seen[1]
    # And it is a non-empty string (uuid4 hex-form).
    assert seen[0]


# ──────────────────────────────────────────────────────────────────────
# 2. flow.pre() returns the SAME flow object
# ──────────────────────────────────────────────────────────────────────


async def test_flow_pre_returns_same_flow_object(
    fresh_registry: HookRegistry,
) -> None:
    """``await flow.pre(stage)`` returns the same :class:`Flow` instance.

    Pinned by the spec — the helper is a builder shape so callers may
    chain or read ``flow.input`` immediately after; both must observe
    the threaded result via the SAME flow holder.
    """

    async def passthrough(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        return None

    fresh_registry.register(hook_fn=passthrough, hookpoint="stage", kind="pre", tier="operator")

    async with invoking("action.test", "payload") as flow:
        returned = await flow.pre("stage")
        assert returned is flow


# ──────────────────────────────────────────────────────────────────────
# 3. flow.pre() threading: mutation flows to flow.input (frozen ctx)
# ──────────────────────────────────────────────────────────────────────


async def test_flow_pre_threading_mutation_visible_via_flow_input(
    fresh_registry: HookRegistry,
) -> None:
    """A ``pre`` subscriber that returns ``ctx.with_input(...)`` mutates
    the next-stage view via the flow's internal ``_ctx`` holder.

    After ``await flow.pre("before_db_write")``, ``flow.input`` reflects
    the mutated payload. The :class:`HookContext` instances themselves
    stay frozen — the helper rebinds the holder, never mutates the
    carrier.
    """

    async def redactor(ctx: HookContext[Any]) -> HookContext[Any]:
        return ctx.with_input("REDACTED")

    fresh_registry.register(
        hook_fn=redactor, hookpoint="before_db_write", kind="pre", tier="operator"
    )

    async with invoking("action.test", "sensitive") as flow:
        assert flow.input == "sensitive"
        await flow.pre("before_db_write")
        assert flow.input == "REDACTED"


# ──────────────────────────────────────────────────────────────────────
# 4. Sequential pre() calls accumulate mutations
# ──────────────────────────────────────────────────────────────────────


async def test_flow_pre_sequential_calls_accumulate_mutations(
    fresh_registry: HookRegistry,
) -> None:
    """Two ``pre`` stages: A mutates "raw" → "A-touched"; B sees
    "A-touched" and mutates → "A-touched|B-touched".

    Each stage's subscribers see the threaded output of the previous
    stage — the flow is the mutable holder of the latest frozen ctx.
    """

    async def stage_a(ctx: HookContext[Any]) -> HookContext[Any]:
        assert isinstance(ctx.input, str)
        return ctx.with_input(ctx.input + "|A-touched")

    async def stage_b(ctx: HookContext[Any]) -> HookContext[Any]:
        assert isinstance(ctx.input, str)
        return ctx.with_input(ctx.input + "|B-touched")

    fresh_registry.register(hook_fn=stage_a, hookpoint="stage_a", kind="pre", tier="operator")
    fresh_registry.register(hook_fn=stage_b, hookpoint="stage_b", kind="pre", tier="operator")

    async with invoking("action.test", "raw") as flow:
        await flow.pre("stage_a")
        await flow.pre("stage_b")
        assert flow.input == "raw|A-touched|B-touched"


# ──────────────────────────────────────────────────────────────────────
# 5. flow.body() fires post chain on success
# ──────────────────────────────────────────────────────────────────────


async def test_body_fires_post_on_success(
    fresh_registry: HookRegistry,
) -> None:
    """A successful body exit fires the ``post`` chain on the named
    hookpoint. Error / cancel chains do NOT run.
    """
    post_ran: list[bool] = []
    error_ran: list[bool] = []
    cancel_ran: list[bool] = []

    async def post_spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        post_ran.append(True)
        return None

    async def error_spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        error_ran.append(True)
        return None

    async def cancel_spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        cancel_ran.append(True)
        return None

    fresh_registry.register(hook_fn=post_spy, hookpoint="after_flush", kind="post", tier="operator")
    fresh_registry.register(
        hook_fn=error_spy, hookpoint="write_failed", kind="error", tier="operator"
    )
    fresh_registry.register(
        hook_fn=cancel_spy, hookpoint="cancelled", kind="cancel", tier="operator"
    )

    # The nested ``async with`` is structurally required — the inner
    # ``flow.body(...)`` depends on ``flow`` from the outer
    # ``invoking(...)``. SIM117 cannot combine the two.
    async with invoking("action.test", "payload") as flow:  # noqa: SIM117
        async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
            pass  # success path

    assert post_ran == [True]
    assert error_ran == []
    assert cancel_ran == []


# ──────────────────────────────────────────────────────────────────────
# 6. flow.body() fires error chain on Exception + re-raises
# ──────────────────────────────────────────────────────────────────────


async def test_body_fires_error_on_exception_and_reraises(
    fresh_registry: HookRegistry,
) -> None:
    """An :class:`Exception` raised inside ``flow.body()`` fires the
    ``error`` chain and re-raises the original exception (no
    suppression). Post / cancel chains do NOT run.
    """
    post_ran: list[bool] = []
    error_ran: list[BaseException] = []
    cancel_ran: list[bool] = []

    async def post_spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        post_ran.append(True)
        return None

    async def error_spy(ctx: HookContext[Any]) -> HookContext[Any] | None:
        # The dispatcher stashes the upstream exc under
        # ctx.metadata[ERROR_EXC_METADATA_KEY]; we read via metadata
        # to verify the spy got the right exc.
        upstream = ctx.metadata.get("error_exc")
        assert isinstance(upstream, BaseException)
        error_ran.append(upstream)
        return None

    async def cancel_spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        cancel_ran.append(True)
        return None

    fresh_registry.register(hook_fn=post_spy, hookpoint="after_flush", kind="post", tier="operator")
    fresh_registry.register(
        hook_fn=error_spy, hookpoint="write_failed", kind="error", tier="operator"
    )
    fresh_registry.register(
        hook_fn=cancel_spy, hookpoint="cancelled", kind="cancel", tier="operator"
    )

    boom = ValueError("body-failed")
    with pytest.raises(ValueError) as exc_info:
        async with invoking("action.test", "payload") as flow:
            async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
                raise boom

    assert exc_info.value is boom
    assert post_ran == []
    assert len(error_ran) == 1 and error_ran[0] is boom
    assert cancel_ran == []


# ──────────────────────────────────────────────────────────────────────
# 7. test-102: cancel-before-error on CancelledError mid-body
# ──────────────────────────────────────────────────────────────────────


async def test_body_cancel_before_error_on_cancellederror_mid_body(
    fresh_registry: HookRegistry,
) -> None:
    """**test-102 — the load-bearing cancel-before-error invariant.**

    A :class:`asyncio.CancelledError` raised inside ``flow.body()``:

    * fires the ``cancel`` chain;
    * does NOT fire the ``error`` chain;
    * re-raises the :class:`asyncio.CancelledError` so the surrounding
      task's cancellation propagates.

    A regression here would let an error subscriber observe a
    cancellation as if it were a non-cancellation failure — corrupting
    audit attribution and potentially leaking T3 user content into the
    wrong audit arm (CLAUDE.md hard rule #7 + trust-tier discipline).
    """
    post_ran: list[bool] = []
    error_ran: list[bool] = []
    cancel_ran: list[BaseException] = []

    async def post_spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        post_ran.append(True)
        return None

    async def error_spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        error_ran.append(True)
        return None

    async def cancel_spy(ctx: HookContext[Any]) -> HookContext[Any] | None:
        upstream = ctx.metadata.get("error_exc")
        assert isinstance(upstream, BaseException)
        cancel_ran.append(upstream)
        return None

    fresh_registry.register(hook_fn=post_spy, hookpoint="after_flush", kind="post", tier="operator")
    fresh_registry.register(
        hook_fn=error_spy, hookpoint="write_failed", kind="error", tier="operator"
    )
    fresh_registry.register(
        hook_fn=cancel_spy, hookpoint="cancelled", kind="cancel", tier="operator"
    )

    with pytest.raises(asyncio.CancelledError):
        async with invoking("action.test", "payload") as flow:
            async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
                raise asyncio.CancelledError()

    # test-102 pin: cancel fired, error did NOT, post did NOT.
    assert len(cancel_ran) == 1
    assert isinstance(cancel_ran[0], asyncio.CancelledError)
    assert error_ran == []
    assert post_ran == []


# ──────────────────────────────────────────────────────────────────────
# 8. Only ONE chain fires per body exit
# ──────────────────────────────────────────────────────────────────────


async def test_body_fires_exactly_one_chain_per_exit(
    fresh_registry: HookRegistry,
) -> None:
    """Three separate ``invoking`` blocks — one success, one error,
    one cancel. Each exits via exactly ONE chain; the other two do not
    fire for that block. Spies accumulate across the three blocks.
    """
    post_calls: list[str] = []
    error_calls: list[str] = []
    cancel_calls: list[str] = []

    async def post_spy(ctx: HookContext[Any]) -> HookContext[Any] | None:
        assert isinstance(ctx.input, str)
        post_calls.append(ctx.input)
        return None

    async def error_spy(ctx: HookContext[Any]) -> HookContext[Any] | None:
        assert isinstance(ctx.input, str)
        error_calls.append(ctx.input)
        return None

    async def cancel_spy(ctx: HookContext[Any]) -> HookContext[Any] | None:
        assert isinstance(ctx.input, str)
        cancel_calls.append(ctx.input)
        return None

    fresh_registry.register(hook_fn=post_spy, hookpoint="after_flush", kind="post", tier="operator")
    fresh_registry.register(
        hook_fn=error_spy, hookpoint="write_failed", kind="error", tier="operator"
    )
    fresh_registry.register(
        hook_fn=cancel_spy, hookpoint="cancelled", kind="cancel", tier="operator"
    )

    # Success block. Nested ``async with`` is structurally required —
    # ``flow.body(...)`` depends on ``flow`` from the outer ``invoking()``.
    async with invoking("action.test", "ok") as flow:  # noqa: SIM117
        async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
            pass

    # Error block.
    with pytest.raises(ValueError):
        async with invoking("action.test", "errored") as flow:
            async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
                raise ValueError("boom")

    # Cancel block.
    with pytest.raises(asyncio.CancelledError):
        async with invoking("action.test", "cancelled-input") as flow:
            async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
                raise asyncio.CancelledError()

    assert post_calls == ["ok"]
    assert error_calls == ["errored"]
    assert cancel_calls == ["cancelled-input"]


# ──────────────────────────────────────────────────────────────────────
# 9. Empty body (no statement) — post chain still fires
# ──────────────────────────────────────────────────────────────────────


async def test_body_empty_block_fires_post(
    fresh_registry: HookRegistry,
) -> None:
    """``async with flow.body(...): pass`` is a successful exit; the
    ``post`` chain fires for the empty body too. Pins that the helper
    does not require a body-emitted value to fire post.
    """
    post_ran: list[bool] = []

    async def post_spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        post_ran.append(True)
        return None

    fresh_registry.register(hook_fn=post_spy, hookpoint="after_flush", kind="post", tier="operator")

    # Nested ``async with`` is structurally required — see test 5.
    async with invoking("action.test", "payload") as flow:  # noqa: SIM117
        async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
            pass

    assert post_ran == [True]


# ──────────────────────────────────────────────────────────────────────
# 10. HookRefusal from a pre-stage propagates; body never runs
# ──────────────────────────────────────────────────────────────────────


async def test_flow_pre_refusal_propagates_body_never_runs(
    fresh_registry: HookRegistry,
) -> None:
    """A :class:`HookRefusal` raised by a ``pre`` subscriber propagates
    from ``flow.pre()`` uncaught — the body never runs. Authorization
    is checked against the default ``refusable_tiers``, which includes
    ``operator``.
    """
    body_ran: list[bool] = []

    async def refuser(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise HookRefusal(
            hook_id="refuser",
            action_id="action.test",
            reason="policy",
            correlation_id="corr-1",
        )

    fresh_registry.register(
        hook_fn=refuser, hookpoint="before_db_write", kind="pre", tier="operator"
    )

    with pytest.raises(HookRefusal):
        async with invoking("action.test", "payload") as flow:
            await flow.pre("before_db_write")
            # If we get here, the refusal did not propagate — fail loud.
            async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
                body_ran.append(True)

    assert body_ran == []


# ──────────────────────────────────────────────────────────────────────
# 11. flow.body() requires cancel kwarg
# ──────────────────────────────────────────────────────────────────────


async def test_body_requires_cancel_kwarg(
    fresh_registry: HookRegistry,
) -> None:
    """``flow.body(post=..., error=...)`` without ``cancel`` raises
    :class:`TypeError`.

    All three names are required because the cancel-before-error
    invariant (test-102) needs an explicit cancel hookpoint — defaulting
    or auto-deriving would hide the contract.
    """
    async with invoking("action.test", "payload") as flow:
        with pytest.raises(TypeError):
            # type: ignore[call-arg]  # the missing arg IS the test
            async with flow.body(post="after_flush", error="write_failed"):  # type: ignore[call-arg]
                pass


async def test_body_requires_post_kwarg(
    fresh_registry: HookRegistry,
) -> None:
    """``flow.body(error=..., cancel=...)`` without ``post`` raises
    :class:`TypeError`. Same load-bearing-name argument as cancel.
    """
    async with invoking("action.test", "payload") as flow:
        with pytest.raises(TypeError):
            async with flow.body(error="write_failed", cancel="cancelled"):  # type: ignore[call-arg]
                pass


async def test_body_requires_error_kwarg(
    fresh_registry: HookRegistry,
) -> None:
    """``flow.body(post=..., cancel=...)`` without ``error`` raises
    :class:`TypeError`. Same load-bearing-name argument as the others.
    """
    async with invoking("action.test", "payload") as flow:
        with pytest.raises(TypeError):
            async with flow.body(post="after_flush", cancel="cancelled"):  # type: ignore[call-arg]
                pass


# ──────────────────────────────────────────────────────────────────────
# 12. gate=None default works (no explicit gate)
# ──────────────────────────────────────────────────────────────────────


async def test_invoking_gate_none_default(
    fresh_registry: HookRegistry,
) -> None:
    """:func:`invoking` works without an explicit ``gate=`` kwarg —
    subscribers register against the active registry (whose gate the
    fixture installed) and the helper itself does not re-check the
    gate. PR-A scope; Slice-3 will layer per-call gate overrides.
    """
    ran: list[bool] = []

    async def spy(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        ran.append(True)
        return None

    fresh_registry.register(hook_fn=spy, hookpoint="stage", kind="pre", tier="operator")

    async with invoking("action.test", "payload") as flow:
        await flow.pre("stage")

    assert ran == [True]


# ──────────────────────────────────────────────────────────────────────
# 13. Multiple invoking() blocks mint distinct correlation_ids
# ──────────────────────────────────────────────────────────────────────


async def test_distinct_correlation_ids_across_invoking_blocks(
    fresh_registry: HookRegistry,
) -> None:
    """Two sequential ``invoking()`` blocks mint distinct
    ``correlation_id``s — the helper does not cache a single id at
    module scope.
    """
    ids: list[str] = []

    async def spy(ctx: HookContext[Any]) -> HookContext[Any] | None:
        ids.append(ctx.correlation_id)
        return None

    fresh_registry.register(hook_fn=spy, hookpoint="stage", kind="pre", tier="operator")

    async with invoking("action.test", "payload-1") as flow:
        await flow.pre("stage")

    async with invoking("action.test", "payload-2") as flow:
        await flow.pre("stage")

    assert len(ids) == 2
    assert ids[0] != ids[1]


# ──────────────────────────────────────────────────────────────────────
# 14. Flow.input reads through to the threaded ctx; HookContext stays frozen
# ──────────────────────────────────────────────────────────────────────


async def test_hookcontext_remains_frozen_through_flow_rebinding(
    fresh_registry: HookRegistry,
) -> None:
    """The flow rebinds its internal ``_ctx`` holder to each chain's
    output. The :class:`HookContext` instances themselves stay frozen
    — the carrier returned by a subscriber's ``with_input`` is a NEW
    frozen instance; the flow rebinding is the only mutation.

    Pins the "ctx frozen, flow mutable" split — the spec's load-bearing
    immutability invariant.
    """
    seen_ctxs: list[HookContext[Any]] = []

    async def stage_a(ctx: HookContext[Any]) -> HookContext[Any]:
        seen_ctxs.append(ctx)
        return ctx.with_input("A")

    async def stage_b(ctx: HookContext[Any]) -> HookContext[Any]:
        seen_ctxs.append(ctx)
        return ctx.with_input("B")

    fresh_registry.register(hook_fn=stage_a, hookpoint="a", kind="pre", tier="operator")
    fresh_registry.register(hook_fn=stage_b, hookpoint="b", kind="pre", tier="operator")

    async with invoking("action.test", "raw") as flow:
        await flow.pre("a")
        await flow.pre("b")

    # Stage A's input handed in == "raw"; stage B's == "A" (the threaded
    # output of A). Both seen ctxs are distinct frozen instances.
    assert seen_ctxs[0].input == "raw"
    assert seen_ctxs[1].input == "A"
    assert seen_ctxs[0] is not seen_ctxs[1]

    # Attempting to mutate either frozen ctx raises. Match the canonical
    # pattern in ``test_context.py::test_hookcontext_is_frozen`` — the
    # dataclass is ``frozen=True``, so the precise exception type is
    # :class:`dataclasses.FrozenInstanceError`; pinning the loose
    # ``(AttributeError, Exception)`` mask would hide a regression that
    # downgraded the frozenness to a plain ``__setattr__`` block.
    with pytest.raises(dataclasses.FrozenInstanceError):
        seen_ctxs[0].input = "mutated"  # type: ignore[misc]


# ──────────────────────────────────────────────────────────────────────
# 15. Flow[T] is the documented type — exported alongside invoking
# ──────────────────────────────────────────────────────────────────────


async def test_flow_is_importable_from_invoke_module() -> None:
    """:class:`Flow` is importable from :mod:`alfred.hooks.invoke` as
    the documented type that ``invoking()`` yields. Task 14 promotes
    it to the package's ``__all__``; this test pins the source location.
    """
    # Already imported at the top of this module — the import alone
    # would have failed if the symbol did not exist. Assert the class
    # is generic-aware (PEP 695 ``Flow[T]`` is a runtime ``type``).
    assert isinstance(Flow, type)


# ──────────────────────────────────────────────────────────────────────
# 16. Cancel-chain timeout — body raises CancelledError, cancel chain
#     itself exceeds deadline, helper still re-raises CancelledError
# ──────────────────────────────────────────────────────────────────────


async def test_body_reraises_cancellederror_when_cancel_chain_times_out(
    fresh_registry: HookRegistry,
) -> None:
    """When the body raises :class:`asyncio.CancelledError` and the
    cancel chain itself times out (``fail_closed=False`` default —
    :func:`invoke` returns last-good ctx instead of re-raising), the
    flow's body still re-raises the original
    :class:`asyncio.CancelledError`.

    Covers the bare ``raise`` immediately after
    ``await invoke(cancel, ...)`` in :meth:`Flow.body` — the documented
    defensive arm that the dispatcher's chain-timeout recovery would
    otherwise let escape silently. CLAUDE.md hard rule #7 — the
    original cancellation must propagate so the surrounding task's
    cancel state is honoured.
    """
    # Drive the chain past the registry's deadline by registering a
    # subscriber that awaits an event that never gets set. The dispatcher's
    # `asyncio.timeout` scope fires, the subscriber is cancelled, the
    # cleanup helper drains, the audit row lands, and `_run_cancel`
    # returns last-good ctx (fail_closed=False is the default).
    fresh_registry.chain_deadline_seconds = 0.01
    never_set = asyncio.Event()

    async def slow_cancel(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        await never_set.wait()
        return None  # unreachable

    fresh_registry.register(
        hook_fn=slow_cancel, hookpoint="cancelled", kind="cancel", tier="operator"
    )

    with pytest.raises(asyncio.CancelledError):
        async with invoking("action.test", "payload") as flow:
            async with flow.body(post="after_flush", error="write_failed", cancel="cancelled"):
                raise asyncio.CancelledError()


# ──────────────────────────────────────────────────────────────────────
# 17. error-arm swallow-and-substitute — body exception swallowed when
#     an error subscriber returns a substitute ctx (Task-8 cascade)
# ──────────────────────────────────────────────────────────────────────


async def test_body_error_substitute_swallows_body_exception_and_threads_substitute_ctx(
    fresh_registry: HookRegistry,
) -> None:
    """An ``error`` subscriber that returns a substitute ctx swallows
    the body's exception and the substitute's input propagates to
    ``flow.input``.

    Pins the Task-8 first-non-``None``-wins cascade through
    :meth:`Flow.body`'s ``except Exception:`` arm — the dispatcher
    returns the substitute ctx (no re-raise), the body rebinds
    ``_ctx`` to it (``invoke.py`` line ~1704), and the surrounding
    ``invoking()`` block exits cleanly. The companion
    ``test_body_fires_error_on_exception_and_reraises`` covers the
    all-``None`` re-raise path; this is the suppression-path twin.

    A regression here — e.g. a stray ``raise exc`` after the rebind
    or a sentinel that fails to thread — would either leak the body's
    exception past the substitution semantic (breaking error
    recovery) or strand ``flow.input`` on the pre-error view
    (corrupting downstream readers of the rebound ctx).
    """
    substitute_marker = "substitute-applied"

    async def substitute(ctx: HookContext[Any]) -> HookContext[Any] | None:
        # Task-8 swallow-and-substitute: returning a non-``None`` ctx
        # wins the cascade and the dispatcher returns it instead of
        # re-raising the upstream exc.
        return ctx.with_input(substitute_marker)

    fresh_registry.register(
        hook_fn=substitute,
        hookpoint="write_failed_substitute",
        kind="error",
        tier="operator",
    )

    async with invoking("action.test", "payload") as flow:  # noqa: SIM117
        async with flow.body(
            post="after_flush_unused",
            error="write_failed_substitute",
            cancel="cancelled_unused",
        ):
            raise ValueError("body fail")  # error subscriber substitutes

    # The body's ValueError was swallowed; substitute's input flows out
    # via flow.input. The frozen ctx was rebound on the Flow holder.
    assert flow.input == substitute_marker


# ──────────────────────────────────────────────────────────────────────
# 18. CancelledError during Flow.pre() propagates uncaught — the
#     cancel-before-error invariant is scoped to Flow.body() ONLY
# ──────────────────────────────────────────────────────────────────────


async def test_cancellederror_during_flow_pre_propagates_uncaught(
    fresh_registry: HookRegistry,
) -> None:
    """A :class:`asyncio.CancelledError` raised by a pre-stage
    subscriber propagates UNCAUGHT through :meth:`Flow.pre`.

    The cancel-before-error invariant (test-102) is scoped to
    :meth:`Flow.body` only. A cancellation mid-pre does NOT fire any
    cancel chain — there's no ``cancel=`` binding at the pre-stage
    layer, by design. The cancellation propagates verbatim so the
    surrounding task's cancel state is honoured, as documented at
    :meth:`Flow.body`'s docstring (the body invariant boundary).

    A regression here — e.g. a defensive ``except CancelledError``
    around ``flow.pre()`` that silently swallowed or recovered the
    cancellation — would let a pre-stage cancellation be observed as
    "no-op" by the surrounding action, corrupting task cancel state
    (CLAUDE.md hard rule #7 + cooperative-cancellation discipline).
    """
    cancel_chain_spy: list[bool] = []

    async def cancels_during_pre(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        raise asyncio.CancelledError("subscriber cancelled mid-pre")

    async def cancel_chain(_ctx: HookContext[Any]) -> HookContext[Any] | None:
        cancel_chain_spy.append(True)
        return None

    fresh_registry.register(
        hook_fn=cancels_during_pre,
        hookpoint="before_validate_cancels",
        kind="pre",
        tier="operator",
    )
    fresh_registry.register(
        hook_fn=cancel_chain,
        hookpoint="cancelled_chain_should_not_fire",
        kind="cancel",
        tier="operator",
    )

    with pytest.raises(asyncio.CancelledError):
        async with invoking("action.test", "payload") as flow:
            await flow.pre("before_validate_cancels")
            pytest.fail("flow.pre() should have raised CancelledError")  # unreachable

    # Cancel chain at the body level did NOT fire — the pre-stage cancel
    # propagated without invoking any cancel-chain disposition logic.
    assert cancel_chain_spy == []
