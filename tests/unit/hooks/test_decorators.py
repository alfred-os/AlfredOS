"""Tests for ``alfred.hooks.decorators.hook`` — Slice-2.5 PR-A Task 7.

The ``@hook`` decorator is the public registration surface a plugin or
runtime module imports to wire an async subscriber against ``(hookpoint,
kind, tier)`` at module import time. It is a thin shim around
:meth:`HookRegistry.register`: validate-async then delegate, returning
the decorated function UNCHANGED.

Invariants pinned here (mirroring the Task 7 brief):

* **Registers against ``get_registry()``** — the decorator wires the
  module-level singleton, not a hidden default. The
  :func:`fresh_registry` fixture's swap-and-restore means each test sees
  its own isolated registry.
* **Returns the function unchanged** — no wrapping, no proxy. The
  identity assertion ``decorated_fn is fn`` is the contract; tests that
  want to invoke the function directly (without going through the
  dispatcher) lean on this.
* **Sync rejection at decoration time** — the i18n-rendered
  ``hooks.subscriber_must_be_async`` message goes through the
  :func:`subscriber_must_be_async_message` helper from
  :mod:`alfred.hooks.errors`. The registry is NOT mutated by a failed
  decoration — fail-loud BEFORE state change (CLAUDE.md hard rule #7).
* **Gate refusal propagates** — when the underlying ``register`` raises
  (e.g. a system-tier subscriber against a default :class:`DevGate`),
  the decorator does not catch. The raise surfaces at decoration time.
* **``origin_module`` recorded** — ``Subscriber.origin_module`` equals
  the decorated function's ``__module__``. The decorator does not need
  to do anything special here — :meth:`HookRegistry.register` reads
  ``hook_fn.__module__`` itself — but the test pins the round-trip so a
  future regression that strips ``__module__`` (e.g. via
  ``functools.wraps`` on a wrapped callable) is caught at the decorator
  surface, not just inside ``register``.

Out of scope for Task 7 (covered by Task 6's ``test_registry.py``):

* The kind/tier round-trip through ``Subscriber`` fields.
* The ``_EMPTY`` identity on miss.
* The seq monotonicity / tier-then-seq ordering.

The decorator's signature is verbatim from spec §0; mypy-strict catches
bad ``kind`` / ``tier`` literals at the call site. We do not write a
runtime test for an invalid ``Literal`` value at the decorator entry
because Python's type system is the enforcement layer there — a runtime
``kind="bad"`` would propagate into :meth:`HookRegistry.register` and
surface (via ``_TIER_RANK`` ``KeyError`` only on a bad ``tier``); both
shapes are already covered by Task 6's tests and the static type
contract is the load-bearing pin.
"""

from __future__ import annotations

from typing import Any

import pytest

from alfred.hooks.context import HookContext
from alfred.hooks.decorators import hook
from alfred.hooks.errors import HookError, subscriber_must_be_async_message
from alfred.hooks.registry import _EMPTY, HookRegistry, get_registry

# ──────────────────────────────────────────────────────────────────────
# Module-scope helpers — the decorator captures ``__module__`` and
# ``__qualname__`` from the decorated function; defining them at module
# scope keeps the captured attributes deterministic across tests.
# ──────────────────────────────────────────────────────────────────────


async def _async_helper(_ctx: HookContext[Any]) -> None:
    """Module-scope async subscriber used by the identity tests.

    Lives at module scope so ``__module__`` is
    ``"tests.unit.hooks.test_decorators"`` and ``__qualname__`` is
    ``"_async_helper"`` — both checked by the round-trip tests below.
    """


def _sync_helper(_ctx: HookContext[Any]) -> None:
    """Synchronous helper — the sync-rejection target. The decorator
    must refuse to register this at decoration time; it never reaches
    the dispatcher.
    """


# ──────────────────────────────────────────────────────────────────────
# 1. Happy path: @hook on an async function registers a subscriber
# ──────────────────────────────────────────────────────────────────────


def test_hook_on_async_function_registers_subscriber(
    fresh_registry: HookRegistry,
) -> None:
    """``@hook("hp", kind="pre", tier="operator")`` on an async function
    appends one subscriber to the active registry under (hp, "pre").

    The fixture's :func:`set_registry` swap makes ``get_registry()``
    inside the decorator resolve to ``fresh_registry``, so the new
    subscriber lands here and is discoverable via the registry's own
    lookup. The hook_fn identity assertion is what pins "no wrapping" at
    the registry-store level — even if the decorator returned a wrapper,
    a different identity here would fail.
    """

    @hook("action.decorated", kind="pre", tier="operator")
    async def my_subscriber(_ctx: HookContext[Any]) -> None:
        return None

    found = fresh_registry.subscribers_for("action.decorated", "pre")
    assert len(found) == 1
    assert found[0].hook_fn is my_subscriber
    assert found[0].hookpoint == "action.decorated"
    assert found[0].kind == "pre"
    assert found[0].tier == "operator"


# ──────────────────────────────────────────────────────────────────────
# 2. Returns the decorated function unchanged (identity, not equality)
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("fresh_registry")
def test_hook_returns_the_function_unchanged() -> None:
    """The decorator returns ``fn`` UNCHANGED — same object identity.

    Pinning identity (not equality) means the decorator MUST NOT wrap
    via ``functools.wraps`` or any proxy. Tests that want to call the
    subscriber directly (skipping the dispatcher) lean on this — and a
    regression to a wrapper would silently change the dispatch
    semantics (e.g. ``functools.wraps`` would lose ``__wrapped__`` /
    ``__module__`` shadowing).
    """

    async def my_fn(_ctx: HookContext[Any]) -> None:
        return None

    decorated = hook("action.identity", kind="pre", tier="operator")(my_fn)
    assert decorated is my_fn


# ──────────────────────────────────────────────────────────────────────
# 3. Sync function: HookError at DECORATION time
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("fresh_registry")
def test_hook_on_sync_function_raises_hook_error_at_decoration_time() -> None:
    """A sync function decorated with ``@hook`` raises
    :class:`HookError` immediately — at decoration time, BEFORE the
    decorator returns.

    CLAUDE.md hard rule #7: no silent failures. Sync subscribers cannot
    be awaited; the failure has to surface at the registration site so
    the traceback blames the right source line. Deferring to first
    invocation would blame the dispatcher and bury the real bug.
    """
    with pytest.raises(HookError):
        hook("action.sync", kind="pre", tier="operator")(_sync_helper)  # type: ignore[arg-type]  # reason: deliberately passing sync fn to provoke the decoration-time rejection


@pytest.mark.usefixtures("fresh_registry")
def test_hook_sync_rejection_message_uses_subscriber_must_be_async_helper() -> None:
    """The rejection message equals
    :func:`subscriber_must_be_async_message(name=fn.__qualname__)`.

    The decorator MUST route through the same helper as the registry's
    ``register`` so the catalog key is referenced in exactly one place
    and the operator-facing string respects the active locale (i18n
    rule #1).
    """
    expected = subscriber_must_be_async_message(name=_sync_helper.__qualname__)
    with pytest.raises(HookError) as exc_info:
        hook("action.sync.msg", kind="pre", tier="operator")(_sync_helper)  # type: ignore[arg-type]  # reason: deliberately passing sync fn to provoke the decoration-time rejection
    assert str(exc_info.value) == expected


# ──────────────────────────────────────────────────────────────────────
# 4. Registry is NOT mutated on sync rejection — fail-loud BEFORE state
# ──────────────────────────────────────────────────────────────────────


def test_hook_sync_rejection_does_not_mutate_registry(
    fresh_registry: HookRegistry,
) -> None:
    """A failed decoration leaves the registry empty on the requested
    (hookpoint, kind) pair — the ``_EMPTY`` singleton is returned.

    Pins "fail-loud BEFORE mutating state": the ``iscoroutinefunction``
    check happens before any registry call, so a rejected registration
    cannot leave a half-registered subscriber. Without this guarantee,
    a sync function would appear in the chain at dispatch time and
    surface as a runtime ``TypeError`` deep inside the dispatcher.
    """
    with pytest.raises(HookError):
        hook("action.fail.no.trace", kind="pre", tier="operator")(_sync_helper)  # type: ignore[arg-type]  # reason: deliberately passing sync fn to provoke the decoration-time rejection
    assert fresh_registry.subscribers_for("action.fail.no.trace", "pre") is _EMPTY


# ──────────────────────────────────────────────────────────────────────
# 5. Without args / kwargs: bare `@hook` is a TypeError
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("fresh_registry")
def test_hook_without_arguments_is_a_type_error() -> None:
    """``@hook`` (no parentheses, no args) does NOT work — ``name`` is
    required positional and ``kind`` / ``tier`` are required kwargs.

    The decorator factory form ``hook(name, *, kind=..., tier=...)`` is
    the only supported shape. Calling ``hook(fn_directly)`` would pass
    ``fn`` as ``name`` and then fail with a ``TypeError`` for missing
    ``kind`` / ``tier`` kwargs — which is what we pin here so a future
    "bare ``@hook``" convenience overload regression is caught.
    """

    async def my_fn(_ctx: HookContext[Any]) -> None: ...

    with pytest.raises(TypeError):
        hook(my_fn)  # type: ignore[arg-type,call-arg]  # reason: deliberately calling decorator with non-str positional and no kwargs to assert the TypeError contract


# ──────────────────────────────────────────────────────────────────────
# 6. Gate refusal at registration propagates out of the decorator
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("fresh_registry")
def test_hook_propagates_gate_refusal_at_decoration_time() -> None:
    """The default :class:`DevGate` denies the ``system`` tier; a
    ``@hook(..., tier="system")`` against the default fixture raises
    :class:`HookError` at decoration time.

    The decorator does NOT catch — the underlying
    :meth:`HookRegistry.register` raises and the decorator lets the
    exception propagate. Pinning this means a future "swallow refusals
    and warn" regression in the decorator is caught here, not silently
    in production.
    """
    with pytest.raises(HookError):

        @hook("action.privileged", kind="pre", tier="system")
        async def my_subscriber(_ctx: HookContext[Any]) -> None:
            return None


def test_hook_gate_refusal_does_not_mutate_registry(
    fresh_registry: HookRegistry,
) -> None:
    """A gate-refused decoration leaves the registry empty on the
    requested (hookpoint, kind) pair. The :meth:`HookRegistry.register`
    method raises BEFORE inserting into the bucket; the decorator
    cannot re-introduce a half-registration of its own.
    """
    with pytest.raises(HookError):

        @hook("action.privileged.no.trace", kind="pre", tier="system")
        async def my_subscriber(_ctx: HookContext[Any]) -> None:
            return None

    assert fresh_registry.subscribers_for("action.privileged.no.trace", "pre") is _EMPTY


# ──────────────────────────────────────────────────────────────────────
# 7. origin_module recorded from the decorated function's __module__
# ──────────────────────────────────────────────────────────────────────


def test_hook_records_origin_module_from_decorated_function(
    fresh_registry: HookRegistry,
) -> None:
    """The registered :class:`Subscriber` carries
    ``origin_module == fn.__module__`` — the module the decorated
    function was defined in.

    Slice-3's reload-by-module flow keys off this attribution; the
    audit row's "blame source" pointer surfaces it. A future regression
    that wraps the function and shadows ``__module__`` would be caught
    here at the decorator surface, not buried inside ``register``.

    Uses the module-scope :func:`_async_helper` so ``__module__`` is
    deterministically ``"tests.unit.hooks.test_decorators"``.
    """
    hook("action.origin", kind="pre", tier="operator")(_async_helper)
    found = fresh_registry.subscribers_for("action.origin", "pre")
    assert len(found) == 1
    assert found[0].origin_module == _async_helper.__module__
    assert found[0].origin_module == "tests.unit.hooks.test_decorators"


# ──────────────────────────────────────────────────────────────────────
# 8. Wires against get_registry() — swap registry, decorator follows
# ──────────────────────────────────────────────────────────────────────


def test_hook_registers_against_get_registry_singleton(
    fresh_registry: HookRegistry,
) -> None:
    """The decorator calls ``get_registry()`` at decoration time; the
    fixture's swap-and-restore means ``fresh_registry`` is the resolved
    singleton.

    Pinning this is the contract for ``@hook`` at module import time —
    a plugin that imports the decorator and applies it lands in
    whatever registry ``get_registry()`` resolves at that moment. A
    regression that bound the decorator to a hidden default at
    decorator-factory time (rather than at decoration time) would
    break here because ``fresh_registry`` would not see the new
    subscriber.
    """
    assert fresh_registry is get_registry()

    @hook("action.singleton", kind="pre", tier="operator")
    async def my_sub(_ctx: HookContext[Any]) -> None:
        return None

    # The just-registered subscriber lives in fresh_registry, NOT in
    # any hidden default — the fixture's installed registry is the one
    # the decorator wired against.
    assert len(fresh_registry.subscribers_for("action.singleton", "pre")) == 1


# ──────────────────────────────────────────────────────────────────────
# 9. Decorated function remains directly callable as a coroutine
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.usefixtures("fresh_registry")
async def test_decorated_function_remains_directly_callable_as_coroutine() -> None:
    """Because ``@hook`` returns ``fn`` unchanged, the decorated function
    is still a coroutine function — directly awaitable in tests that
    skip the dispatcher and call the subscriber's body in isolation.

    Pins the "no wrapping" contract from the runtime side: a wrapper
    that returned a callable-but-not-coroutine would fail this test
    even if it passed the identity check above on a sufficiently
    forgiving wrapper implementation. The coroutine call here is the
    independent witness.
    """
    call_log: list[str] = []

    @hook("action.directly.callable", kind="pre", tier="operator")
    async def my_sub(_ctx: HookContext[Any]) -> None:
        call_log.append("ran")

    ctx: HookContext[None] = HookContext(
        action_id="action.directly.callable",
        hookpoint="action.directly.callable",
        input=None,
        correlation_id="corr-direct",
        kind="pre",
    )
    result = await my_sub(ctx)
    assert result is None
    assert call_log == ["ran"]
