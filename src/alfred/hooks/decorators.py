"""Hook subsystem decorator surface — Slice-2.5 PR-A Task 7.

The :func:`hook` decorator is the public registration seam every plugin
or runtime module uses to wire an async subscriber against
``(hookpoint, kind, tier)`` at module import time. It is a deliberately
thin shim around :meth:`HookRegistry.register`:

1. Validate the decorated function is a coroutine function via
   :func:`inspect.iscoroutinefunction`. A sync function raises
   :class:`HookError` at DECORATION time — before any registry mutation
   — with the catalog-rendered ``hooks.subscriber_must_be_async``
   message routed through :func:`subscriber_must_be_async_message`.
2. Delegate to :func:`get_registry`.register(...) on success. The
   registry consults the capability gate; a refusal raises
   :class:`HookError` LOUDLY and the decorator does not catch.
3. Return the decorated function UNCHANGED — same object identity. No
   wrapping, no proxy, no ``functools.wraps``. Tests that call the
   subscriber directly (skipping the dispatcher) lean on the
   identity-preserving contract; the dispatcher only ever calls
   ``subscriber.hook_fn`` so it does not care either way.

Subscriber contract (the type signature the dispatcher expects, even
though the decorator itself does not narrow it):

* Returns ``HookContext[T] | None``.
* ``None`` means "no change / proceed with default disposition" for
  every kind. For ``error`` kind specifically, ``None`` = re-raise the
  underlying exception (the dispatcher's swallow-vs-re-raise decision
  in Tasks 9-12 keys off the ``None`` return).
* A returned :class:`HookContext` is a rewritten carrier — only ``pre``
  hooks may use this to mutate the action's input mid-chain.

Design notes:

* The decorator factory binds ``name`` / ``kind`` / ``tier`` at
  ``hook(...)`` call time but resolves :func:`get_registry` at
  DECORATION time — i.e. when the inner ``_wrap`` runs. This means a
  plugin module imported AFTER a :func:`set_registry` swap registers
  against the post-swap registry, which is the contract the test
  fixture's swap-and-restore relies on.
* The decorator does not introspect or store the kwargs on the function
  as attributes. Operators inspecting "what's this subscriber wired
  to?" go through :meth:`HookRegistry.subscribers_for`, not through
  ``fn.__hook_*__`` attributes. Keeping the function unchanged means a
  dual-decorated function (two ``@hook(...)`` stacked) registers
  cleanly twice, with no metadata collision.
* CLAUDE.md hard rule #7 (no silent failures) drives the
  "fail-loud BEFORE mutating state" ordering: the sync-check happens
  first, then the gate consult inside ``register``, then the insert. A
  rejected registration is invisible to lookup.
* CLAUDE.md i18n rule #1 (every operator-facing string through
  ``t()``) is honoured by routing the rejection message through
  :func:`subscriber_must_be_async_message`, which renders against the
  ``hooks.subscriber_must_be_async`` catalog entry.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Literal

from alfred.hooks.context import HookKind
from alfred.hooks.errors import HookError, subscriber_must_be_async_message
from alfred.hooks.registry import HookFn, get_registry


def hook(
    name: str,
    *,
    kind: HookKind,
    tier: Literal["system", "operator", "user-plugin"],
) -> Callable[[HookFn], HookFn]:
    """Register the decorated async function as a hook subscriber.

    Decorator factory — verbatim spec §0 signature. The active
    :class:`HookRegistry` is the one :func:`get_registry` returns at
    decoration time, which means the test fixture's swap-and-restore
    works transparently.

    Args:
        name: The dotted hookpoint identifier
            (e.g. ``"action.memory.episodic.record"``). Positional so a
            typo at the call site is caught by mypy as a type mismatch
            on the first argument, not a missing kwarg.
        kind: The lifecycle stage. Keyword-only; one of the four
            :data:`alfred.hooks.context.HookKind` literals
            (``"pre"`` / ``"post"`` / ``"error"`` / ``"cancel"``).
        tier: The trust tier the subscriber requests. Keyword-only; one
            of ``"system"`` / ``"operator"`` / ``"user-plugin"``. The
            capability gate (default :class:`alfred.hooks.capability.DevGate`)
            denies anything else; an unknown literal is also caught at
            mypy-strict time as a :class:`typing.Literal` mismatch.

    Returns:
        A decorator that takes an async :data:`HookFn` and returns the
        SAME function unchanged (identity-preserving). The returned
        callable is therefore directly awaitable in tests that bypass
        the dispatcher.

    Raises (inside the inner ``_wrap`` — i.e. at DECORATION time):
        HookError: If the decorated function is not a coroutine function
            (rendered via :func:`subscriber_must_be_async_message`), or
            if the capability gate refuses the requested ``tier`` (the
            registry raises and the decorator propagates).

    Example:
        .. code-block:: python

            @hook("action.memory.episodic.record", kind="pre", tier="operator")
            async def redact_pii(
                ctx: HookContext[EpisodicRecordInput],
            ) -> HookContext[EpisodicRecordInput] | None:
                if needs_redaction(ctx.input):
                    return ctx.with_input(redact(ctx.input))
                return None  # proceed with default disposition
    """

    def _wrap(fn: HookFn) -> HookFn:
        # Hard rule #7: fail LOUDLY and BEFORE any state mutation.
        # The iscoroutinefunction check has to happen before the
        # registry insert so a rejected registration is invisible to
        # the dispatcher. Routing through
        # :func:`subscriber_must_be_async_message` keeps the catalog
        # key referenced in exactly one place (i18n rule #1).
        if not inspect.iscoroutinefunction(fn):
            raise HookError(subscriber_must_be_async_message(name=fn.__qualname__))

        # Resolve the active registry at DECORATION time, not at
        # decorator-factory time, so the test fixture's
        # :func:`set_registry` swap-and-restore is honoured.
        get_registry().register(
            hook_fn=fn,
            hookpoint=name,
            kind=kind,
            tier=tier,
        )

        # Return identity — no wrapping. The dispatcher only ever calls
        # ``subscriber.hook_fn``; tests that want to call the function
        # directly rely on the unchanged-callable contract.
        return fn

    return _wrap
