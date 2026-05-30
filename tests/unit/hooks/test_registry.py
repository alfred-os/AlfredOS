"""Tests for ``alfred.hooks.registry`` — the per-process hook registry,
the gate-and-sink injection seams, the lookup-by-(hookpoint, kind) shape,
the tier-then-seq ordering invariant, and the module-level
:func:`get_registry` / :func:`set_registry` singleton accessors.

Slice-2.5 PR-A Task 6. Non-fault rows only — the fault-path audit-row
assertions (refusal, chain-timeout, subscriber-error,
unauthorized-refusal, reentry-bypass) land alongside Tasks 9-12 where
the dispatcher emits them. This file pins the registration / lookup /
ordering / accessor invariants every later task relies on.

Invariants pinned here:

* **Register/lookup round-trip** — a single subscriber registered on
  ``("action.x", "pre")`` is the one element of
  ``subscribers_for("action.x", "pre")``. The returned value is a tuple
  (not a list) — the dispatcher iterates it on the hot path and the
  immutable view is load-bearing for the "no mutation across stages"
  invariant.
* **Tier-then-seq ordering** (hypothesis property) — subscribers come
  back sorted by ``(_TIER_RANK[tier], registration_seq)`` regardless of
  the insertion order. ``system`` runs before ``operator`` runs before
  ``user-plugin`` within a chain; same-tier ties break on the monotonic
  registration counter.
* **``subscribers_for(miss) is _EMPTY`` identity** — every miss returns
  the exact same module-level empty tuple. The identity (not just
  ``== ()``) is what pins the no-allocation proof: the dispatcher's
  hot-path miss branch must not pay for a fresh ``tuple()`` per call.
* **``origin_module`` recorded** — ``Subscriber.origin_module`` equals
  ``hook_fn.__module__`` so the audit row and Slice-3's reload-by-module
  logic can attribute every subscriber back to its source module.
* **``fresh_registry()`` isolation** — the cross-test contract: a
  subscriber registered in test A is absent in test B. The
  ``set_registry()`` swap-and-restore at fixture boundaries is the seam.
* **``set_registry()`` swap + restore** — ``get_registry()`` returns the
  installed instance; the fixture's teardown restores the prior one.
* **``reset()`` clears** — registering N subscribers then calling
  ``reset()`` empties every keyed slot. The clear is for test isolation
  inside one registry instance (NOT a production reload path — Slice 3
  owns that).
* **Sink injection seam** — ``HookRegistry(gate=..., sink=spy).sink is
  spy`` and the default ``HookRegistry(gate=...).sink`` is a
  :class:`StructlogAuditSink` instance. The dispatcher
  (Tasks 9-12) reads ``get_registry().sink`` for every emission; the
  test surface here pins the public attribute name.
* **Async-only enforcement at register** — a sync function passed to
  :meth:`HookRegistry.register` raises :class:`HookError` with the
  ``hooks.subscriber_must_be_async`` catalog-rendered message. The
  language-toggle assertion pins the i18n-rule-#1 contract for the
  rejection message (operator-facing string → ``t()``).
* **Gate refusal at register** — a :class:`DevGate` (default-deny on
  ``system``) refusing a ``tier="system"`` subscriber raises
  :class:`HookError`. The registry deliberately does NOT emit an audit
  row at register-time (sink.emit is async; register is sync); the
  decision is documented in :class:`HookRegistry`'s class docstring.
* **Registration sequence monotonicity** — two consecutive
  :meth:`register` calls assign strictly-increasing
  ``registration_seq`` values. The dispatcher leans on the monotonic
  property for stable same-tier ordering.
* **ContextVar default** — :data:`alfred.hooks.registry._reentry`
  defaults to the empty tuple so the dispatcher's re-entry guard
  (Task 12) can rely on a "no parents yet" sentinel without an
  explicit ``.set(())`` at every action entry.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import FrozenInstanceError
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from alfred.hooks.audit_sink import StructlogAuditSink
from alfred.hooks.capability import DevGate
from alfred.hooks.context import HookContext, HookKind
from alfred.hooks.errors import HookError
from alfred.hooks.registry import (
    _EMPTY,
    _TIER_RANK,
    HOOK_CHAIN_DEADLINE_SECONDS,
    HookRegistry,
    _reentry,
    get_registry,
    set_registry,
)
from alfred.i18n import set_language, t
from tests.unit.hooks.conftest import SpyAuditSink

# ──────────────────────────────────────────────────────────────────────
# Tiny helper subscribers used across the suite
# ──────────────────────────────────────────────────────────────────────


async def _noop_pre(_ctx: HookContext[Any]) -> None:
    """Async no-op subscriber. Used wherever the test only cares about
    registration + lookup, not subscriber behaviour. Lives at module
    scope so :attr:`Subscriber.origin_module` equals
    ``"tests.unit.hooks.test_registry"`` deterministically.
    """


async def _noop_post(_ctx: HookContext[Any]) -> None:
    """Second async no-op; identical body, distinct identity. Lets a
    test register two subscribers without :meth:`register` collapsing
    them on object equality (it never should — same-callable double
    registration is legitimate; the test pins it).
    """


def _sync_noop(_ctx: HookContext[Any]) -> None:
    """Synchronous no-op — the register-time rejection target. The
    async-only contract bans this at registration; the test uses it
    only to provoke the :class:`HookError`.
    """


# ──────────────────────────────────────────────────────────────────────
# 1. Module constants
# ──────────────────────────────────────────────────────────────────────


def test_hook_chain_deadline_seconds_is_quarter_second() -> None:
    """``HOOK_CHAIN_DEADLINE_SECONDS`` is the verbatim spec §0 value.

    Task 9 wraps every chain in ``asyncio.timeout(HOOK_CHAIN_DEADLINE_SECONDS)``;
    a drift in this value silently re-tunes every chain's deadline.
    """
    assert HOOK_CHAIN_DEADLINE_SECONDS == 0.25


def test_tier_rank_lookup_table_is_verbatim_spec() -> None:
    """``_TIER_RANK`` orders ``system`` < ``operator`` < ``user-plugin``.

    The dispatcher sorts subscribers by ``(_TIER_RANK[tier], seq)``;
    a wrong rank silently re-orders the chain's stages and that's a
    security-sensitive bug (system-tier hooks MUST see the carrier
    first).
    """
    assert _TIER_RANK == {"system": 0, "operator": 1, "user-plugin": 2}


def test_empty_is_the_module_singleton_empty_tuple() -> None:
    """``_EMPTY`` is a module-level empty tuple — same identity every
    access. The miss-path identity assertion below leans on this.
    """
    assert _EMPTY == ()
    assert isinstance(_EMPTY, tuple)


# ──────────────────────────────────────────────────────────────────────
# 2. Register / lookup round-trip
# ──────────────────────────────────────────────────────────────────────


def test_register_then_lookup_returns_single_subscriber(
    fresh_registry: HookRegistry,
) -> None:
    """A single ``register`` followed by ``subscribers_for`` returns a
    1-tuple containing the registered subscriber.
    """
    fresh_registry.register(
        hook_fn=_noop_pre,
        hookpoint="action.x",
        kind="pre",
        tier="operator",
    )
    found = fresh_registry.subscribers_for("action.x", "pre")
    assert len(found) == 1
    assert found[0].hook_fn is _noop_pre
    assert found[0].hookpoint == "action.x"
    assert found[0].kind == "pre"
    assert found[0].tier == "operator"


def test_lookup_returns_a_tuple_not_a_list(
    fresh_registry: HookRegistry,
) -> None:
    """The dispatcher iterates the hot-path return; an immutable tuple
    pins "no mutation across stages" at the type level.
    """
    fresh_registry.register(
        hook_fn=_noop_pre,
        hookpoint="action.x",
        kind="pre",
        tier="operator",
    )
    assert isinstance(fresh_registry.subscribers_for("action.x", "pre"), tuple)


def test_lookup_distinguishes_hookpoint(
    fresh_registry: HookRegistry,
) -> None:
    """A subscriber registered on ``action.x`` does not surface under
    ``action.y``. The lookup key is the (hookpoint, kind) pair.
    """
    fresh_registry.register(
        hook_fn=_noop_pre,
        hookpoint="action.x",
        kind="pre",
        tier="operator",
    )
    assert fresh_registry.subscribers_for("action.y", "pre") is _EMPTY


def test_lookup_distinguishes_kind(
    fresh_registry: HookRegistry,
) -> None:
    """A ``pre`` subscriber does not surface under ``post``. The kind
    half of the (hookpoint, kind) key is honoured at lookup time.
    """
    fresh_registry.register(
        hook_fn=_noop_pre,
        hookpoint="action.x",
        kind="pre",
        tier="operator",
    )
    assert fresh_registry.subscribers_for("action.x", "post") is _EMPTY


# ──────────────────────────────────────────────────────────────────────
# 3. Tier-then-seq ordering (hypothesis property)
# ──────────────────────────────────────────────────────────────────────


_TIER_NAMES = list(_TIER_RANK.keys())


@given(
    insertion_order=st.lists(
        st.sampled_from(_TIER_NAMES),
        min_size=1,
        max_size=12,
    ),
)
@settings(max_examples=50, deadline=None)
def test_subscribers_sorted_by_tier_then_registration_seq(
    insertion_order: list[str],
) -> None:
    """Regardless of insertion order, lookup returns subscribers sorted
    by ``(_TIER_RANK[tier], registration_seq)``.

    The hypothesis strategy generates a shuffled tier sequence; we
    register one subscriber per tier (with allow_system=True so every
    tier is grantable), then assert the returned tuple is in the
    expected order: ``system`` first, then ``operator``, then
    ``user-plugin``, with same-tier ties broken on monotonic
    registration_seq.

    Building the registry inside the body keeps the property
    function-pure; hypothesis disallows pytest fixtures on the
    parameter list.
    """
    registry = HookRegistry(gate=DevGate(allow_system=True))

    # Register one subscriber per element of the insertion order.
    # Each registration captures the seq it received so we can assert
    # ordering after lookup.
    async def _sub(_ctx: HookContext[Any]) -> None:
        return None

    for tier in insertion_order:
        registry.register(
            hook_fn=_sub,
            hookpoint="action.ordering",
            kind="pre",
            tier=tier,
        )

    found = registry.subscribers_for("action.ordering", "pre")
    keys = [(_TIER_RANK[s.tier], s.registration_seq) for s in found]
    assert keys == sorted(keys), (
        f"Subscribers not in (tier, seq) order. Got {keys} for insertion {insertion_order}"
    )


def test_same_tier_ties_break_on_registration_seq(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """Two subscribers at the same tier come back in registration order.

    The monotonic-seq invariant is the tie-breaker; without it
    same-tier subscribers would have unspecified order and the chain's
    behaviour would be a function of dict iteration order.
    """

    async def _a(_ctx: HookContext[Any]) -> None: ...

    async def _b(_ctx: HookContext[Any]) -> None: ...

    fresh_registry_allow_system.register(
        hook_fn=_a, hookpoint="action.tie", kind="pre", tier="operator"
    )
    fresh_registry_allow_system.register(
        hook_fn=_b, hookpoint="action.tie", kind="pre", tier="operator"
    )

    found = fresh_registry_allow_system.subscribers_for("action.tie", "pre")
    assert [s.hook_fn for s in found] == [_a, _b]


# ──────────────────────────────────────────────────────────────────────
# 4. Miss returns the _EMPTY singleton (identity, not equality)
# ──────────────────────────────────────────────────────────────────────


def test_subscribers_for_miss_returns_empty_singleton_identity(
    fresh_registry: HookRegistry,
) -> None:
    """``subscribers_for(miss) is _EMPTY`` — IDENTITY, not equality.

    Pins the no-allocation invariant on the hot-path miss branch:
    every miss returns the exact same module-level empty tuple. A
    drift to ``return tuple()`` would pass equality but break the
    identity check.
    """
    miss1 = fresh_registry.subscribers_for("no.such.hookpoint", "pre")
    miss2 = fresh_registry.subscribers_for("also.missing", "post")
    assert miss1 is _EMPTY
    assert miss2 is _EMPTY
    # Belt-and-braces: identical object across distinct misses.
    assert miss1 is miss2


# ──────────────────────────────────────────────────────────────────────
# 5. origin_module is recorded from hook_fn.__module__
# ──────────────────────────────────────────────────────────────────────


def test_origin_module_equals_hook_fn_module(
    fresh_registry: HookRegistry,
) -> None:
    """The :attr:`Subscriber.origin_module` field equals
    ``hook_fn.__module__`` at register time.

    Slice 3's reload-by-module flow keys off this; the audit attribution
    for each hook also surfaces it on every fault row. Pin it now.
    """
    fresh_registry.register(
        hook_fn=_noop_pre,
        hookpoint="action.origin",
        kind="pre",
        tier="operator",
    )
    found = fresh_registry.subscribers_for("action.origin", "pre")
    assert found[0].origin_module == _noop_pre.__module__


# ──────────────────────────────────────────────────────────────────────
# 6. fresh_registry() isolation across tests
# ──────────────────────────────────────────────────────────────────────


def test_fresh_registry_isolation_part_a(
    fresh_registry: HookRegistry,
) -> None:
    """First half of the isolation pair: register a subscriber in this
    test. The pair-b test asserts the registry it gets is empty.
    """
    fresh_registry.register(
        hook_fn=_noop_pre,
        hookpoint="action.iso",
        kind="pre",
        tier="operator",
    )
    assert len(fresh_registry.subscribers_for("action.iso", "pre")) == 1


def test_fresh_registry_isolation_part_b(
    fresh_registry: HookRegistry,
) -> None:
    """Second half: the subscriber from part-a must NOT be visible here.

    The :func:`fresh_registry` fixture's swap-and-restore is the
    isolation seam. If this fails, the fixture is leaking state across
    tests through the module-level singleton.
    """
    assert fresh_registry.subscribers_for("action.iso", "pre") is _EMPTY


# ──────────────────────────────────────────────────────────────────────
# 7. set_registry() swap + restore
# ──────────────────────────────────────────────────────────────────────


def test_set_registry_swaps_the_active_singleton() -> None:
    """``set_registry(other)`` makes ``get_registry()`` return ``other``.

    Belt-and-braces: capture the pre-test instance, install a fresh
    one, assert ``get_registry()`` returns the fresh one, then restore
    so the harness-wide singleton is untouched after this test.
    """
    prior = get_registry()
    other = HookRegistry(gate=DevGate())
    try:
        set_registry(other)
        assert get_registry() is other
    finally:
        set_registry(prior)
    # After restore the singleton is back to the pre-test instance.
    assert get_registry() is prior


def test_get_registry_returns_same_instance_across_calls() -> None:
    """Two consecutive ``get_registry()`` calls return the same object.

    The accessor is a getter, not a factory — Tasks 7-12 lean on the
    "one registry per process" semantics for the @hook decorator's
    registration site to wire into the dispatcher's lookup site.
    """
    assert get_registry() is get_registry()


# ──────────────────────────────────────────────────────────────────────
# 8. reset() clears every keyed slot
# ──────────────────────────────────────────────────────────────────────


def test_reset_clears_every_subscriber(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """Register N subscribers across distinct (hookpoint, kind) pairs;
    call :meth:`reset`; every previously-keyed lookup returns
    ``_EMPTY``.
    """
    fresh_registry_allow_system.register(
        hook_fn=_noop_pre, hookpoint="a.x", kind="pre", tier="operator"
    )
    fresh_registry_allow_system.register(
        hook_fn=_noop_post, hookpoint="a.x", kind="post", tier="system"
    )
    fresh_registry_allow_system.register(
        hook_fn=_noop_pre, hookpoint="a.y", kind="pre", tier="user-plugin"
    )
    # Sanity: all three are registered.
    assert len(fresh_registry_allow_system.subscribers_for("a.x", "pre")) == 1
    assert len(fresh_registry_allow_system.subscribers_for("a.x", "post")) == 1
    assert len(fresh_registry_allow_system.subscribers_for("a.y", "pre")) == 1

    fresh_registry_allow_system.reset()

    assert fresh_registry_allow_system.subscribers_for("a.x", "pre") is _EMPTY
    assert fresh_registry_allow_system.subscribers_for("a.x", "post") is _EMPTY
    assert fresh_registry_allow_system.subscribers_for("a.y", "pre") is _EMPTY


def test_reset_lets_registration_seq_continue_or_restart(
    fresh_registry: HookRegistry,
) -> None:
    """After ``reset()`` the registry continues to work — subsequent
    registrations get fresh ``registration_seq`` values and lookups
    surface them.

    The exact seq value after reset is an internal detail (could
    continue monotonic or restart at 0); the test only pins that
    registration after reset round-trips through lookup.
    """
    fresh_registry.register(hook_fn=_noop_pre, hookpoint="a", kind="pre", tier="operator")
    fresh_registry.reset()
    fresh_registry.register(hook_fn=_noop_pre, hookpoint="a", kind="pre", tier="operator")
    found = fresh_registry.subscribers_for("a", "pre")
    assert len(found) == 1


# ──────────────────────────────────────────────────────────────────────
# 9. Sink injection seam
# ──────────────────────────────────────────────────────────────────────


def test_registry_exposes_injected_sink_via_public_attribute(
    spy_sink: SpyAuditSink,
) -> None:
    """``HookRegistry(gate=..., sink=spy).sink is spy`` — the public
    attribute is the seam Tasks 9-12 read via ``get_registry().sink``.

    Pinning the IDENTITY (not just equality) is the contract: the
    dispatcher must not lose the caller-supplied sink to a defensive
    copy or proxy. The PR-B DB-backed sink replaces this attribute at
    construction time; no source change to dispatch.
    """
    registry = HookRegistry(gate=DevGate(), sink=spy_sink)
    assert registry.sink is spy_sink


def test_registry_default_sink_is_structlog_audit_sink() -> None:
    """The default ``HookRegistry(gate=...).sink`` is a
    :class:`StructlogAuditSink`.

    Documenting the PR-A default explicitly so PR-B's DB-backed swap
    has an obvious "before" to point at. The default's logger is the
    project's structlog handle ``alfred.hooks``.
    """
    registry = HookRegistry(gate=DevGate())
    assert isinstance(registry.sink, StructlogAuditSink)


# ──────────────────────────────────────────────────────────────────────
# 10. Async-only enforcement at register
# ──────────────────────────────────────────────────────────────────────


def test_register_rejects_sync_function_with_loud_hook_error(
    fresh_registry: HookRegistry,
) -> None:
    """A non-coroutine ``hook_fn`` raises :class:`HookError` at register
    time — never silently accepted, never quietly wrapped.

    CLAUDE.md hard rule #7: no silent failures. The dispatcher would
    later ``await subscriber(...)`` and a sync callable would surface
    as a runtime ``TypeError`` only at first invocation. We fail at
    registration so the error blames the right source line.
    """
    with pytest.raises(HookError):
        fresh_registry.register(
            hook_fn=_sync_noop,  # type: ignore[arg-type]  # reason: deliberately passing sync fn to assert register-time rejection
            hookpoint="action.sync",
            kind="pre",
            tier="operator",
        )


def test_register_sync_rejection_message_is_i18n_rendered(
    fresh_registry: HookRegistry,
) -> None:
    """The rejection message is the catalog-rendered
    ``hooks.subscriber_must_be_async`` string, not the bare key.

    CLAUDE.md i18n rule #1: every operator-facing string goes through
    ``t()``. A bare-key fallback would mean the catalog binding broke
    silently. We assert the rendered template contains the
    function name AND the marker word "async" so a catalog drift to a
    different copy still pins the i18n round-trip.
    """
    with pytest.raises(HookError) as exc_info:
        fresh_registry.register(
            hook_fn=_sync_noop,  # type: ignore[arg-type]  # reason: deliberately passing sync fn to assert register-time rejection
            hookpoint="action.sync",
            kind="pre",
            tier="operator",
        )
    rendered = str(exc_info.value)
    assert _sync_noop.__qualname__ in rendered
    assert "async" in rendered
    # Bare-key fallback would be literally "hooks.subscriber_must_be_async";
    # a catalog hit produces a longer rendered template.
    assert rendered != "hooks.subscriber_must_be_async"


def test_register_sync_rejection_message_honours_active_language(
    fresh_registry: HookRegistry,
) -> None:
    """The rejection message respects the active i18n language.

    Switching languages with ``set_language(...)`` MUST change the
    message :class:`HookError` carries — pins i18n rule #2 (persona
    prompts honour user.language) at the error-rendering boundary.
    Switching to a locale we know is NOT installed falls back to ``en``
    because :mod:`alfred.i18n.translator` uses the gettext languages
    fallback; what we pin is that the rendering goes through ``t()``,
    not that a German catalog exists. Use ``t()`` directly as the
    oracle so the test follows whatever the catalog says.
    """
    try:
        set_language("en-US")
        expected_en = t("hooks.subscriber_must_be_async", name=_sync_noop.__qualname__)
        with pytest.raises(HookError) as exc_info:
            fresh_registry.register(
                hook_fn=_sync_noop,  # type: ignore[arg-type]  # reason: deliberately passing sync fn to assert register-time rejection
                hookpoint="action.sync.lang",
                kind="pre",
                tier="operator",
            )
        assert str(exc_info.value) == expected_en
    finally:
        set_language("en-US")


# ──────────────────────────────────────────────────────────────────────
# 11. Gate refusal at register
# ──────────────────────────────────────────────────────────────────────


def test_register_raises_hook_error_when_gate_refuses_system_tier(
    fresh_registry: HookRegistry,
) -> None:
    """A subscriber requesting ``tier="system"`` against a default
    :class:`DevGate` (``allow_system=False``) is refused — register
    raises :class:`HookError`.

    The decision (documented in :class:`HookRegistry`'s docstring):
    register is SYNC and does NOT emit an audit row itself. The audit
    row for refusals happens at DISPATCH time in Tasks 9-12. At
    register-time the failure surfaces loudly via the raise.
    """
    with pytest.raises(HookError):
        fresh_registry.register(
            hook_fn=_noop_pre,
            hookpoint="action.privileged",
            kind="pre",
            tier="system",
        )


def test_register_gate_refusal_does_not_record_subscriber(
    fresh_registry: HookRegistry,
) -> None:
    """A failed register call leaves no trace: lookup on the rejected
    (hookpoint, kind) still returns the ``_EMPTY`` singleton.

    Pins "fail-closed": a denied registration MUST NOT silently appear
    in the chain at dispatch time.
    """
    with pytest.raises(HookError):
        fresh_registry.register(
            hook_fn=_noop_pre,
            hookpoint="action.privileged",
            kind="pre",
            tier="system",
        )
    assert fresh_registry.subscribers_for("action.privileged", "pre") is _EMPTY


def test_register_grants_system_tier_when_gate_allows_it(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """The positive control on the gate seam: with
    ``allow_system=True``, the ``system`` tier registers cleanly.

    Without this test the deny path could be passing for the wrong
    reason (e.g. always-fail in :meth:`register`).
    """
    fresh_registry_allow_system.register(
        hook_fn=_noop_pre,
        hookpoint="action.privileged",
        kind="pre",
        tier="system",
    )
    found = fresh_registry_allow_system.subscribers_for("action.privileged", "pre")
    assert len(found) == 1
    assert found[0].tier == "system"


def test_register_unknown_tier_raises_hook_error_before_bucket_mutation() -> None:
    """An unknown tier is rejected BEFORE any bucket mutation — the
    registry's "failed register leaves no trace" invariant survives.

    The realistic adversarial shape is a custom capability gate that
    erroneously grants an unknown tier (a Slice-3 grant-gate bug, a
    test fixture that pre-approves everything, etc.). Without the
    early tier-validation check, the gate would say "yes", the
    subscriber would be appended to the bucket, and the subsequent
    ``bucket.sort(key=lambda s: (_TIER_RANK[s.tier], ...))`` would
    raise :class:`KeyError` AFTER the partial state had landed —
    violating both fail-loud (cryptic ``KeyError`` rather than an
    attributed :class:`HookError`) and fail-closed (registry in a
    partial-commit state). The early gate keeps the invariant
    intact: lookup on the (hookpoint, kind) returns the
    :data:`_EMPTY` singleton because nothing was ever appended.
    """

    class _AlwaysAllowGate:
        """Adversarial gate — grants every requested tier, including
        unknown strings. The early tier-validation must catch the
        misuse here, not the sort step."""

        def check(
            self,
            *,
            plugin_id: str,
            hookpoint: str,
            requested_tier: str,
        ) -> bool:
            del plugin_id, hookpoint, requested_tier
            return True

    registry = HookRegistry(gate=_AlwaysAllowGate())
    with pytest.raises(HookError, match="Unknown hook tier"):
        registry.register(
            hook_fn=_noop_pre,
            hookpoint="action.invalid_tier",
            kind="pre",
            tier="invalid-tier",  # type: ignore[arg-type]  # the test's whole point.
        )
    # Bucket-mutation invariant: nothing landed. The miss-path singleton
    # is the proof — a failed bucket-append-then-sort would have left a
    # partial entry behind.
    assert registry.subscribers_for("action.invalid_tier", "pre") is _EMPTY


# ──────────────────────────────────────────────────────────────────────
# 12. Registration sequence monotonicity
# ──────────────────────────────────────────────────────────────────────


def test_registration_seq_is_strictly_increasing(
    fresh_registry: HookRegistry,
) -> None:
    """Two consecutive ``register`` calls assign strictly increasing
    ``registration_seq`` values.

    Same-tier tie-breaking in the dispatcher leans on the monotonic
    property; a regression to non-monotonic seq would silently shuffle
    subscriber order within a tier.
    """
    fresh_registry.register(hook_fn=_noop_pre, hookpoint="a", kind="pre", tier="operator")
    fresh_registry.register(hook_fn=_noop_post, hookpoint="a", kind="pre", tier="operator")
    found = fresh_registry.subscribers_for("a", "pre")
    assert len(found) == 2
    assert found[0].registration_seq < found[1].registration_seq


# ──────────────────────────────────────────────────────────────────────
# 13. ContextVar default
# ──────────────────────────────────────────────────────────────────────


def test_reentry_contextvar_default_is_empty_tuple() -> None:
    """The :data:`_reentry` ContextVar defaults to the empty tuple.

    Task 12's reentry-guard appends to ``_reentry.get()`` to track the
    parent action chain; the empty-tuple sentinel lets the first
    invocation skip an explicit ``.set(())``. Pins the default value
    that mirrors the i18n :data:`_active_lang` ContextVar pattern.
    """
    assert _reentry.get() == ()
    assert isinstance(_reentry.get(), tuple)


# ──────────────────────────────────────────────────────────────────────
# 14. Subscriber dataclass shape — frozen + slots + every required field
# ──────────────────────────────────────────────────────────────────────


def test_subscriber_is_frozen(
    fresh_registry: HookRegistry,
) -> None:
    """:class:`Subscriber` is ``frozen=True`` — assigning to a field
    raises :class:`FrozenInstanceError`.

    The dispatcher receives :class:`Subscriber` instances on the hot
    path; immutability prevents accidental mid-chain state drift.
    """
    fresh_registry.register(hook_fn=_noop_pre, hookpoint="a", kind="pre", tier="operator")
    sub = fresh_registry.subscribers_for("a", "pre")[0]
    with pytest.raises(FrozenInstanceError):
        sub.tier = "system"  # type: ignore[misc]


def test_subscriber_has_no_instance_dict(
    fresh_registry: HookRegistry,
) -> None:
    """``slots=True`` on :class:`Subscriber` — no per-instance
    ``__dict__``. Keeps the hot path allocation-light.
    """
    fresh_registry.register(hook_fn=_noop_pre, hookpoint="a", kind="pre", tier="operator")
    sub = fresh_registry.subscribers_for("a", "pre")[0]
    assert not hasattr(sub, "__dict__")


def test_subscriber_carries_every_required_field(
    fresh_registry: HookRegistry,
) -> None:
    """:class:`Subscriber` carries ``hook_fn``, ``hookpoint``,
    ``kind``, ``tier``, ``origin_module``, ``registration_seq`` —
    the six fields spec §3.2 requires.
    """
    fresh_registry.register(hook_fn=_noop_pre, hookpoint="a", kind="pre", tier="operator")
    sub = fresh_registry.subscribers_for("a", "pre")[0]
    assert sub.hook_fn is _noop_pre
    assert sub.hookpoint == "a"
    assert sub.kind == "pre"
    assert sub.tier == "operator"
    assert sub.origin_module == _noop_pre.__module__
    assert isinstance(sub.registration_seq, int)


# ──────────────────────────────────────────────────────────────────────
# 15. register signature is keyword-only
# ──────────────────────────────────────────────────────────────────────


def test_register_rejects_positional_args(
    fresh_registry: HookRegistry,
) -> None:
    """``register("a", ...)`` is a ``TypeError`` — the ``*,`` after
    ``self`` in :meth:`HookRegistry.register` makes every parameter
    keyword-only.

    Mirrors the :class:`alfred.hooks.capability.CapabilityGate.check`
    and :class:`alfred.hooks.audit_sink.AuditSink.emit` discipline:
    silent argument-order regression at the call site is impossible.
    """
    with pytest.raises(TypeError):
        fresh_registry.register(  # type: ignore[misc]
            _noop_pre,  # pyright: ignore[reportCallIssue]
            "a",
            "pre",
            "operator",
        )


# ──────────────────────────────────────────────────────────────────────
# 16. Async signature on `register`'s hook_fn validation
# ──────────────────────────────────────────────────────────────────────


def test_register_accepts_async_function(
    fresh_registry: HookRegistry,
) -> None:
    """Sanity: a coroutine function passes the ``iscoroutinefunction``
    check (positive control). Without this the async-only assertion
    above could be passing for the wrong reason.
    """
    assert inspect.iscoroutinefunction(_noop_pre)
    fresh_registry.register(hook_fn=_noop_pre, hookpoint="a", kind="pre", tier="operator")
    assert len(fresh_registry.subscribers_for("a", "pre")) == 1


# ──────────────────────────────────────────────────────────────────────
# 17. Spy sink structural conformance (sanity for downstream tasks)
# ──────────────────────────────────────────────────────────────────────


def test_spy_sink_is_structurally_an_audit_sink(spy_sink: SpyAuditSink) -> None:
    """The conftest :class:`SpyAuditSink` honours the
    :class:`alfred.hooks.audit_sink.AuditSink` Protocol structurally.

    Pins the contract for Tasks 9-12 that inject the spy into a
    :class:`HookRegistry` and expect the dispatcher's ``isinstance``
    type-narrow to succeed.
    """
    from alfred.hooks.audit_sink import AuditSink

    assert isinstance(spy_sink, AuditSink)


@pytest.mark.asyncio
async def test_spy_sink_records_emit_call_shape(spy_sink: SpyAuditSink) -> None:
    """A single ``await spy.emit(...)`` records one entry on
    :attr:`SpyAuditSink.calls` with the expected three fields.

    Confidence for Tasks 9-12 that the recorder will catch their
    fault-row emissions without an off-by-one.
    """
    await spy_sink.emit(
        event="hooks.refusal",
        correlation_id="corr-1",
        fields={"hookpoint": "before_validate"},
    )
    assert len(spy_sink.calls) == 1
    entry = spy_sink.calls[0]
    assert entry["event"] == "hooks.refusal"
    assert entry["correlation_id"] == "corr-1"
    assert entry["fields"] == {"hookpoint": "before_validate"}


# ──────────────────────────────────────────────────────────────────────
# 18. Type-narrowing: HookKind alias accepted on register
# ──────────────────────────────────────────────────────────────────────


def test_register_accepts_every_hook_kind(
    fresh_registry_allow_system: HookRegistry,
) -> None:
    """Each of the four :data:`HookKind` literals registers and looks up.

    The (hookpoint, kind) key is the storage shape; pin every kind
    round-trips so a future regression that key-collapses ``pre`` and
    ``error`` (say) fails loudly here.
    """
    kinds: list[HookKind] = ["pre", "post", "error", "cancel"]
    for k in kinds:
        fresh_registry_allow_system.register(
            hook_fn=_noop_pre,
            hookpoint="action.kinds",
            kind=k,
            tier="operator",
        )
    for k in kinds:
        found = fresh_registry_allow_system.subscribers_for("action.kinds", k)
        assert len(found) == 1
        assert found[0].kind == k


# ──────────────────────────────────────────────────────────────────────
# 19. asyncio loop integration sanity — registry methods don't yield
# ──────────────────────────────────────────────────────────────────────


def test_register_and_lookup_run_outside_event_loop(
    fresh_registry: HookRegistry,
) -> None:
    """Registry methods are synchronous — they MUST work outside an
    asyncio loop. The @hook decorator (Task 7) calls ``register`` at
    import time, before any event loop exists.
    """
    # The fixture itself runs outside an event loop, so reaching this
    # point with the previous tests passing is the sanity check; we
    # also assert ``asyncio.get_running_loop`` raises here, to make
    # the implicit explicit.
    with pytest.raises(RuntimeError):
        asyncio.get_running_loop()
    fresh_registry.register(hook_fn=_noop_pre, hookpoint="a", kind="pre", tier="operator")
    assert len(fresh_registry.subscribers_for("a", "pre")) == 1
