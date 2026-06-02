"""Tests for ``register_hookpoint`` declaration API + tier-allowlist
enforcement (#119, commits 1-2).

Pins the spec §6.2 contract: a publisher MUST declare a hookpoint via
:meth:`HookRegistry.register_hookpoint` before any subscriber may
register against it; once declared, only subscribers whose ``tier`` is
in the declared ``subscribable_tiers`` may register. The declaration
carries the per-hookpoint ``subscribable_tiers`` / ``refusable_tiers``
/ ``fail_closed`` metadata that the registration-enforcement and the
dispatch-time defense-in-depth (commit 3) consult.

Five invariants in this file:

1. **Undeclared hookpoint refuses subscriber registration.** Forces
   the publisher-declares-first module-init ordering.
2. **Idempotent declaration on equal args.** Re-importing a publisher
   module re-runs the declaration; identical metadata is a no-op.
3. **Conflicting declaration raises.** Two declarations of the same
   name with different metadata is a publisher-version-drift or
   copy-paste-typo shape; loud refusal is the correct disposition.
4. **Subscriber tier in allow-list succeeds** (positive control).
5. **Subscriber tier outside the allow-list refuses** with a loud
   :data:`HOOKS_TIER_REJECTED` audit row. The failed register leaves
   no trace.

The dispatch-time re-check lands in commit 3
(``test_dispatch_publisher_drift.py``).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from typing import Any

import pytest
import structlog.testing

from alfred.hooks.audit_sink import HOOKS_TIER_REJECTED
from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookError
from alfred.hooks.registry import HookpointMeta, HookRegistry
from tests.helpers.gates import make_deny_all_gate
from tests.unit.hooks.conftest import SpyAuditSink

# ──────────────────────────────────────────────────────────────────────
# 0. Production-singleton default — the #119 invariant pin
# ──────────────────────────────────────────────────────────────────────


def test_default_strict_declarations_is_true_in_production_singleton() -> None:
    """The :class:`HookRegistry` constructor defaults ``strict_declarations``
    to ``True`` — the production posture under #119.

    A future PR that flips this default would silently downgrade the
    register-time tier-allowlist gate: every subscriber against an
    undeclared hookpoint would register cleanly and run at dispatch
    with no allow-list enforcement. The downgrade would be undetectable
    in the test corpus because most fixtures explicitly request
    ``strict_declarations=False`` to stay backward-compatible with the
    pre-#119 tests.

    This test is the explicit invariant pin: the DEFAULT is strict.
    The fixture composition is the deliberate opt-out. See the SEC-Med-1
    finding in the #119 review report.

    Behaviour-based assertion: a registry constructed without the
    keyword raises :class:`HookError` on register against an undeclared
    hookpoint. No public introspection API exists for
    ``strict_declarations``; the behavioural pin is the contract.
    """

    async def _noop_local(_ctx: HookContext[Any]) -> None:
        """Async no-op."""

    # Slice-3 spec §15.1: assert the strict-declaration deny path
    # against :class:`RealGate` (:func:`make_deny_all_gate`) so a
    # regression in RealGate's deny semantics cannot be hidden by
    # the test-only shim. The strict-declaration check fires BEFORE
    # the gate consult in :meth:`HookRegistry.register`, so the
    # gate's deny posture is defense-in-depth here.
    reg = HookRegistry(gate=make_deny_all_gate())
    with pytest.raises(HookError, match="not declared"):
        reg.register(
            hook_fn=_noop_local,
            hookpoint="undeclared.in.production.posture",
            kind="pre",
            tier="operator",
        )


async def _noop(_ctx: HookContext[Any]) -> None:
    """Async no-op subscriber used wherever the body is immaterial."""


# ──────────────────────────────────────────────────────────────────────
# 1. Undeclared hookpoint refuses registration
# ──────────────────────────────────────────────────────────────────────


def test_undeclared_hookpoint_refuses_registration(
    strict_registry: HookRegistry,
) -> None:
    """Registering against an undeclared hookpoint raises :class:`HookError`.

    Publishers MUST call :meth:`HookRegistry.register_hookpoint` for a
    hookpoint before any subscriber may register against it. This forces
    a module-init ordering invariant — the publisher imports first and
    declares its metadata; subscriber modules import second and find
    the declaration already in place.

    Without this gate, a subscriber could register against a misspelled
    hookpoint (typo on the publisher's name) and never run — the typo
    would silently disable the security stage. The undeclared-hookpoint
    refusal turns the typo into a loud :class:`HookError` at decorator
    time.

    A failed register MUST leave no trace — the
    ``subscribers_for(name, kind)`` lookup returns the empty singleton
    after the raise, mirroring the gate-refusal invariant.

    Uses the :func:`strict_registry` fixture which sets
    ``strict_declarations=True`` — the production posture. The
    :func:`fresh_registry` fixture defaults to permissive
    (``strict_declarations=False``) to keep PR-A's pre-#119 tests
    backward-compatible; only this file's tests assert the strict
    contract.
    """
    with pytest.raises(HookError, match="not declared"):
        strict_registry.register(
            hook_fn=_noop,
            hookpoint="not.declared.yet",
            kind="pre",
            tier="operator",
        )
    assert strict_registry.subscribers_for("not.declared.yet", "pre") == ()


# ──────────────────────────────────────────────────────────────────────
# 2. Idempotent declaration with same args
# ──────────────────────────────────────────────────────────────────────


def test_idempotent_declaration_with_same_args(
    strict_registry: HookRegistry,
) -> None:
    """Two ``register_hookpoint`` calls with identical args succeed both
    times — declaration is idempotent on equality of the carried metadata.

    The realistic shape is a publisher module that gets re-imported
    (pytest test isolation, Slice-3's reload-by-module flow). The
    re-import re-runs the module-init declaration; a strict "first-call
    wins, subsequent calls raise" contract would force every publisher
    to wrap the call in a "have I declared this yet?" check, which is
    boilerplate that obscures the invariant.

    Idempotency makes the safe path the easy path — and the strict path
    for genuine conflicts (next test) preserves loud-failure on real
    drift.
    """
    strict_registry.register_hookpoint(
        name="memory.episodic.record.before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    # Second call with the SAME args — must not raise.
    strict_registry.register_hookpoint(
        name="memory.episodic.record.before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    # The declared metadata is what the first call set.
    meta = strict_registry.hookpoint_meta("memory.episodic.record.before_db_write")
    assert meta == HookpointMeta(
        name="memory.episodic.record.before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )


# ──────────────────────────────────────────────────────────────────────
# 3. Conflicting declaration raises
# ──────────────────────────────────────────────────────────────────────


def test_conflicting_declaration_raises(
    strict_registry: HookRegistry,
) -> None:
    """A second ``register_hookpoint`` with DIFFERENT args raises
    :class:`HookError`.

    Two real-world shapes this defends against:

    * **Publisher version drift** — two versions of the same publisher
      module land in one process (a vendored library + a stale local
      copy), each declaring the same hookpoint with different
      ``subscribable_tiers``. Silent acceptance would mean the
      last-import-wins decides which allow-list is enforced, which is a
      surprise vector at install / reload time.
    * **Publisher typo on a metadata field** — copy-paste error
      flipping ``fail_closed`` on a security-tier hookpoint to
      ``False``. Loud refusal forces the author to reconcile the two
      sites before either runs.

    The error message attributes both the hookpoint name and the
    metadata mismatch so the operator can grep the source for the two
    declaration sites.
    """
    strict_registry.register_hookpoint(
        name="memory.episodic.record.before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    # Different ``subscribable_tiers`` — must raise.
    with pytest.raises(HookError, match="already declared with different metadata"):
        strict_registry.register_hookpoint(
            name="memory.episodic.record.before_db_write",
            subscribable_tiers=frozenset({"operator"}),
            refusable_tiers=frozenset({"system"}),
            fail_closed=True,
        )


def test_conflicting_declaration_differs_on_fail_closed(
    strict_registry: HookRegistry,
) -> None:
    """Drift on ``fail_closed`` alone is sufficient to raise.

    Catches the highest-blast typo shape — flipping a security-tier
    hookpoint's ``fail_closed`` to ``False`` silently would defeat
    CLAUDE.md hard rule #7 across every subscriber the dispatcher
    invokes.
    """
    strict_registry.register_hookpoint(
        name="memory.episodic.record.before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    with pytest.raises(HookError, match="already declared with different metadata"):
        strict_registry.register_hookpoint(
            name="memory.episodic.record.before_db_write",
            subscribable_tiers=frozenset({"system", "operator"}),
            refusable_tiers=frozenset({"system"}),
            fail_closed=False,
        )


def test_conflicting_declaration_differs_on_refusable_tiers(
    strict_registry: HookRegistry,
) -> None:
    """Drift on ``refusable_tiers`` alone is sufficient to raise.

    The full triplet of metadata fields must agree across all
    declarations of one hookpoint.
    """
    strict_registry.register_hookpoint(
        name="memory.episodic.record.before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    with pytest.raises(HookError, match="already declared with different metadata"):
        strict_registry.register_hookpoint(
            name="memory.episodic.record.before_db_write",
            subscribable_tiers=frozenset({"system", "operator"}),
            refusable_tiers=frozenset({"system", "operator"}),
            fail_closed=True,
        )


# ──────────────────────────────────────────────────────────────────────
# 4. HookpointMeta dataclass shape
# ──────────────────────────────────────────────────────────────────────


def test_hookpoint_meta_is_frozen() -> None:
    """:class:`HookpointMeta` is ``frozen=True`` — assigning to a field
    raises :class:`FrozenInstanceError`.

    The metadata is the per-hookpoint contract that registration and
    dispatch both consult; immutability prevents a subscriber or a test
    fixture from rewriting it after publishers have declared.
    """
    meta = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset({"operator"}),
        refusable_tiers=frozenset({"operator"}),
        fail_closed=False,
    )
    with pytest.raises(FrozenInstanceError):
        meta.fail_closed = True  # type: ignore[misc]


def test_hookpoint_meta_carries_required_fields() -> None:
    """:class:`HookpointMeta` carries ``name``, ``subscribable_tiers``,
    ``refusable_tiers``, ``fail_closed`` — the four fields the
    declaration contract requires.
    """
    meta = HookpointMeta(
        name="memory.episodic.record.before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    assert meta.name == "memory.episodic.record.before_db_write"
    assert meta.subscribable_tiers == frozenset({"system", "operator"})
    assert meta.refusable_tiers == frozenset({"system"})
    assert meta.fail_closed is True


def test_hookpoint_meta_equality_keys_off_all_fields() -> None:
    """Two :class:`HookpointMeta` instances are equal iff every field
    matches.

    Equality is what makes idempotent re-declaration safe — the
    registry compares the new meta to the stored one via ``==``, and a
    drift on any field produces ``!=`` and raises.
    """
    a = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    b = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    c = HookpointMeta(
        name="x",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=False,  # drift
    )
    assert a == b
    assert a != c


# ──────────────────────────────────────────────────────────────────────
# 5. hookpoint_meta() lookup
# ──────────────────────────────────────────────────────────────────────


def test_hookpoint_meta_returns_none_for_undeclared(
    strict_registry: HookRegistry,
) -> None:
    """:meth:`HookRegistry.hookpoint_meta` returns ``None`` for an
    undeclared name.

    The dispatcher uses this to detect drift between the publisher's
    invoke-time allow-list and the registry's declared one
    (defense-in-depth at dispatch time, commit 3). A ``None`` return
    signals "no declaration at all" — the publisher bypassed the
    ``register_hookpoint`` contract entirely.
    """
    assert strict_registry.hookpoint_meta("not.declared") is None


def test_hookpoint_meta_returns_stored_metadata_after_declare(
    strict_registry: HookRegistry,
) -> None:
    """After ``register_hookpoint`` succeeds, ``hookpoint_meta`` returns
    the stored :class:`HookpointMeta`.
    """
    strict_registry.register_hookpoint(
        name="before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    meta = strict_registry.hookpoint_meta("before_db_write")
    assert meta is not None
    assert meta.name == "before_db_write"
    assert meta.subscribable_tiers == frozenset({"system", "operator"})
    assert meta.refusable_tiers == frozenset({"system"})
    assert meta.fail_closed is True


# ──────────────────────────────────────────────────────────────────────
# 6. register_hookpoint signature shape
# ──────────────────────────────────────────────────────────────────────


def test_register_hookpoint_rejects_positional_args(
    strict_registry: HookRegistry,
) -> None:
    """``register_hookpoint("name", frozenset(...), ...)`` is a
    ``TypeError`` — every parameter (including ``name``) is keyword-only.

    Mirrors :meth:`HookRegistry.register`'s and the
    :class:`HookRegistry` constructor's ``*,`` discipline so a silent
    argument-order regression at the call site is impossible. The
    Group J change in the #119 review tightened ``name`` from
    positional to keyword-only for surface symmetry — every register-
    surface API in this module shares the same all-keyword posture
    now.
    """
    with pytest.raises(TypeError):
        strict_registry.register_hookpoint(  # type: ignore[misc]
            "name",  # pyright: ignore[reportCallIssue]
            frozenset({"operator"}),  # pyright: ignore[reportCallIssue]
            frozenset({"operator"}),
            False,  # noqa: FBT003 — the whole point of the test is to assert positional rejection
        )


# ──────────────────────────────────────────────────────────────────────
# 7. Tier-allowlist enforcement at registration (#119 commit 2)
# ──────────────────────────────────────────────────────────────────────


def test_subscriber_tier_in_allowlist_succeeds(
    strict_registry: HookRegistry,
) -> None:
    """A subscriber whose ``tier`` is in the hookpoint's
    ``subscribable_tiers`` registers cleanly.

    Positive control on the new register-time gate — without it the
    deny test below could be passing for the wrong reason (e.g.
    always-fail in :meth:`register`).
    """
    strict_registry.register_hookpoint(
        name="before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    # ``operator`` IS in the allow-list. The fixture-parity gate (via
    # :func:`make_permissive_fixture_gate`) also grants ``operator``;
    # both gates pass.
    strict_registry.register(
        hook_fn=_noop,
        hookpoint="before_db_write",
        kind="pre",
        tier="operator",
    )
    found = strict_registry.subscribers_for("before_db_write", "pre")
    assert len(found) == 1
    assert found[0].tier == "operator"


def test_subscriber_tier_not_in_allowlist_refuses(
    spy_sink: SpyAuditSink,
) -> None:
    """A subscriber whose ``tier`` is NOT in ``subscribable_tiers`` is
    refused at register-time.

    Three invariants pinned:

    1. :class:`HookError` raised at the register call site.
    2. A loud :data:`HOOKS_TIER_REJECTED` audit row emitted through
       the registry's sink (CLAUDE.md hard rule #7 — no silent
       failures, every refusal is auditable).
    3. The failed register leaves no trace — ``subscribers_for``
       returns empty.

    The shape exercised here is the spec line 696-697 adversarial:
    ``user-plugin`` tier rejected on
    ``subscribable_tiers={"system","operator"}``.

    Slice-3 spec §15.1: asserts against :class:`RealGate`
    (:func:`make_deny_all_gate`). The tier-allowlist check fires
    BEFORE the gate consult, so the gate's deny posture is
    defense-in-depth here.
    """
    registry = HookRegistry(
        gate=make_deny_all_gate(),
        sink=spy_sink,
        strict_declarations=True,
    )
    registry.register_hookpoint(
        name="before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )

    with pytest.raises(HookError, match="not allowed on hookpoint"):
        registry.register(
            hook_fn=_noop,
            hookpoint="before_db_write",
            kind="pre",
            tier="user-plugin",
        )
    assert registry.subscribers_for("before_db_write", "pre") == ()

    # Audit row emitted. The audit row is the loud-failure escape
    # (CLAUDE.md hard rule #7). :meth:`register` is sync and the
    # registry uses ``asyncio.run`` to drive the async sink in a
    # sub-loop, so the row lands BEFORE register returns — no extra
    # draining required.
    matching = [c for c in spy_sink.calls if c["event"] == HOOKS_TIER_REJECTED]
    assert len(matching) == 1, (
        f"expected exactly one HOOKS_TIER_REJECTED audit row; got "
        f"{[c['event'] for c in spy_sink.calls]}"
    )
    fields = matching[0]["fields"]
    assert isinstance(fields, dict)
    assert fields["hookpoint"] == "before_db_write"
    assert fields["kind"] == "pre"
    assert fields["subscriber_tier"] == "user-plugin"
    assert fields["subscriber_name"] == _noop.__qualname__
    # The allow-list surfaces on the row so the operator can grep
    # "what tier set was in force when this rejection fired?".
    assert set(fields["subscribable_tiers"]) == {"system", "operator"}  # type: ignore[arg-type]


def test_failed_tier_registration_leaves_no_trace(
    strict_registry: HookRegistry,
) -> None:
    """The bucket-mutation invariant — a refused-by-tier registration
    leaves the registry empty.

    Mirrors :func:`test_register_gate_refusal_does_not_record_subscriber`
    for the new register-time tier-allowlist enforcement. A drift here
    would let a refused subscriber sneak into a later dispatch.
    """
    strict_registry.register_hookpoint(
        name="before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )
    with pytest.raises(HookError):
        strict_registry.register(
            hook_fn=_noop,
            hookpoint="before_db_write",
            kind="pre",
            tier="user-plugin",
        )
    assert strict_registry.subscribers_for("before_db_write", "pre") == ()


def test_tier_rejection_audit_row_is_emitted_synchronously(
    spy_sink: SpyAuditSink,
) -> None:
    """The :data:`HOOKS_TIER_REJECTED` row is observable IMMEDIATELY
    after :meth:`register` returns (raises).

    The async-sink-from-sync-register design (mirrors the gate-refusal
    Option-A choice in :class:`HookRegistry`'s docstring) uses
    :func:`asyncio.run` in a sub-loop so the audit row lands BEFORE
    the raise propagates. Without this synchronous landing, an
    operator monitoring the audit log could miss a refusal whose
    register-time exception was caught silently by the caller.

    Pinned here so a future refactor to a fire-and-forget background
    task would surface as this test failing.

    Slice-3 spec §15.1: asserts the tier-allowlist deny path against
    :class:`RealGate` (:func:`make_deny_all_gate`); the gate's deny
    posture is defense-in-depth here (the tier-allowlist check fires
    first).
    """
    registry = HookRegistry(
        gate=make_deny_all_gate(),
        sink=spy_sink,
        strict_declarations=True,
    )
    registry.register_hookpoint(
        name="before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )

    with pytest.raises(HookError):
        registry.register(
            hook_fn=_noop,
            hookpoint="before_db_write",
            kind="pre",
            tier="user-plugin",
        )

    # The spy MUST have the row IMMEDIATELY after the raise propagates.
    # No ``asyncio.run`` / ``asyncio.sleep`` draining here — that's the
    # whole point.
    assert any(c["event"] == HOOKS_TIER_REJECTED for c in spy_sink.calls)


def test_tier_rejection_inside_running_loop_emits_synchronously(
    spy_sink: SpyAuditSink,
) -> None:
    """The :data:`HOOKS_TIER_REJECTED` audit row lands synchronously
    even when :meth:`register` is called from inside a running event loop.

    The decorator (`@hook`) is typically called at module import time
    before any loop runs, so the simple ``asyncio.run`` path covers the
    common case. But a test or a plugin that calls ``register`` from
    inside an ``async def`` MUST NOT hit a "cannot nest event loops"
    runtime error. The implementation handles both arms by checking
    :func:`asyncio.get_running_loop` and dispatching the emit via a
    dedicated thread when a loop is already running.

    Pinned here as a regression guard — a future refactor that drops
    the running-loop arm would surface as this test raising
    :class:`RuntimeError`.

    Slice-3 spec §15.1: asserts the tier-allowlist deny path against
    :class:`RealGate` (:func:`make_deny_all_gate`); the gate's deny
    posture is defense-in-depth here (the tier-allowlist check fires
    first).
    """

    async def _provoke() -> None:
        registry = HookRegistry(
            gate=make_deny_all_gate(),
            sink=spy_sink,
            strict_declarations=True,
        )
        registry.register_hookpoint(
            name="before_db_write",
            subscribable_tiers=frozenset({"system", "operator"}),
            refusable_tiers=frozenset({"system"}),
            fail_closed=True,
        )
        with pytest.raises(HookError):
            registry.register(
                hook_fn=_noop,
                hookpoint="before_db_write",
                kind="pre",
                tier="user-plugin",
            )

    asyncio.run(_provoke())
    assert any(c["event"] == HOOKS_TIER_REJECTED for c in spy_sink.calls)


# ──────────────────────────────────────────────────────────────────────
# CR cycle-1 MAJ-3 — register_hookpoint normalisation + tier validation
# ──────────────────────────────────────────────────────────────────────


def test_register_hookpoint_normalizes_mutable_set_to_frozenset(
    strict_registry: HookRegistry,
) -> None:
    """A caller passing ``set(...)`` (mutable) for the tier sets has
    the stored metadata normalised to :class:`frozenset` so the caller
    cannot later mutate the allow-list.

    CR cycle-1 MAJ-3 — the prior shape trusted the runtime type:
    ``HookpointMeta.subscribable_tiers`` was annotated ``frozenset[str]``
    but Python does not enforce annotations at runtime, so a ``set``
    landed inside :class:`HookpointMeta` and a later ``my_set.add(...)``
    silently rewrote the stored allow-list. Normalising at declaration
    time locks the immutability invariant in code.

    Behavioural pin: mutating the ORIGINAL set after register does NOT
    affect the stored metadata.
    """
    original_subscribable: set[str] = {"system", "operator"}
    original_refusable: set[str] = {"system"}

    strict_registry.register_hookpoint(
        name="before_db_write",
        subscribable_tiers=original_subscribable,
        refusable_tiers=original_refusable,
        fail_closed=True,
    )

    stored = strict_registry.hookpoint_meta("before_db_write")
    assert stored is not None
    assert isinstance(stored.subscribable_tiers, frozenset)
    assert isinstance(stored.refusable_tiers, frozenset)

    # Mutate the originals AFTER register — the stored metadata must
    # not change.
    original_subscribable.add("user-plugin")
    original_refusable.add("operator")

    re_read = strict_registry.hookpoint_meta("before_db_write")
    assert re_read is not None
    assert re_read.subscribable_tiers == frozenset({"system", "operator"})
    assert re_read.refusable_tiers == frozenset({"system"})


def test_register_hookpoint_rejects_unknown_tier_in_subscribable_tiers(
    strict_registry: HookRegistry,
) -> None:
    """A misspelled tier name in ``subscribable_tiers`` raises
    :class:`HookError` at declaration time, not at the first subscriber
    register.

    CR cycle-1 MAJ-3 — the high-blast typo shape: a publisher with
    ``subscribable_tiers={"operatior"}`` (typo) silently disables the
    register-time allow-list gate because the typo never matches any
    subscriber's requested tier — every register refuses without an
    obvious cause. Declaration-time validation surfaces the typo at
    module init.
    """
    with pytest.raises(HookError, match=r"unknown tier|hooks\.unknown_tier_in_declaration"):
        strict_registry.register_hookpoint(
            name="typo.hookpoint",
            subscribable_tiers=frozenset({"operatior"}),  # typo
            refusable_tiers=frozenset({"system"}),
            fail_closed=True,
        )


def test_register_hookpoint_rejects_unknown_tier_in_refusable_tiers(
    strict_registry: HookRegistry,
) -> None:
    """A misspelled tier name in ``refusable_tiers`` also raises at
    declaration time.

    Symmetric to the ``subscribable_tiers`` arm — both fields are
    validated against ``_TIER_RANK`` so a typo on either side surfaces
    at module init.
    """
    with pytest.raises(HookError, match=r"unknown tier|hooks\.unknown_tier_in_declaration"):
        strict_registry.register_hookpoint(
            name="typo.hookpoint",
            subscribable_tiers=frozenset({"system", "operator"}),
            refusable_tiers=frozenset({"unknown"}),  # not in _TIER_RANK
            fail_closed=True,
        )


def test_register_hookpoint_rejects_multiple_unknown_tiers(
    strict_registry: HookRegistry,
) -> None:
    """Multiple unknown tiers across both fields are reported in one
    raise — the operator sees every typo at once, not one per register
    attempt.
    """
    with pytest.raises(HookError, match=r"unknown tier|hooks\.unknown_tier_in_declaration"):
        strict_registry.register_hookpoint(
            name="typo.hookpoint",
            subscribable_tiers=frozenset({"operatior", "system"}),
            refusable_tiers=frozenset({"unknown", "system"}),
            fail_closed=True,
        )


def test_register_hookpoint_accepts_all_three_valid_tiers(
    strict_registry: HookRegistry,
) -> None:
    """Positive control — the full known-tier vocabulary
    (``"system"``, ``"operator"``, ``"user-plugin"``) is accepted.

    Pins that the validation logic does not over-reject. A future
    change that tightens the gate must surface here.
    """
    strict_registry.register_hookpoint(
        name="open.hookpoint",
        subscribable_tiers=frozenset({"system", "operator", "user-plugin"}),
        refusable_tiers=frozenset({"system", "operator", "user-plugin"}),
        fail_closed=False,
    )
    stored = strict_registry.hookpoint_meta("open.hookpoint")
    assert stored is not None
    assert stored.subscribable_tiers == frozenset({"system", "operator", "user-plugin"})
    assert stored.refusable_tiers == frozenset({"system", "operator", "user-plugin"})


# ──────────────────────────────────────────────────────────────────────
# CR cycle-2 MAJ-2 — bounded no-running-loop _emit_sync arm
# ──────────────────────────────────────────────────────────────────────


class _StallingAuditSink:
    """Structural :class:`alfred.hooks.audit_sink.AuditSink` whose
    :meth:`emit` sleeps long enough to trip the
    :data:`_EMIT_SYNC_THREAD_JOIN_SECONDS` bound.

    Pins the CR cycle-2 MAJ-2 contract: a sink that stalls at module-
    import time (no running loop yet — the common path for the
    ``@hook`` decorator) does NOT hang :meth:`HookRegistry.register`.
    The :func:`asyncio.wait_for` wrap on the no-running-loop arm of
    :meth:`HookRegistry._emit_sync` raises :class:`TimeoutError`
    inside the sub-loop and the structlog fallback fires with
    ``reason="sink_emit_timeout_import_time"``.

    Sleep is intentionally long enough (1.0 s) to land WELL outside
    the 500 ms bound regardless of CI machine jitter. The fallback
    path is what we're pinning, not the bound itself — Group B's
    perf-gate calibration owns the bound.
    """

    async def emit(
        self,
        *,
        event: str,
        correlation_id: str,
        fields: Mapping[str, object],
    ) -> None:
        """Sleep for 1.0 s — well outside the 500 ms bound."""
        await asyncio.sleep(1.0)


def test_emit_sync_no_running_loop_arm_bounds_stalling_sink() -> None:
    """A stalling sink at module-import time (no running loop) does
    NOT hang :meth:`HookRegistry.register` — the no-running-loop arm
    of :meth:`HookRegistry._emit_sync` wraps the sub-loop emit in a
    :func:`asyncio.wait_for` with the same 500 ms bound the running-
    loop arm uses, AND falls back to structlog with
    ``reason="sink_emit_timeout_import_time"`` so the audit row is
    NEVER lost (CLAUDE.md hard rule #7).

    Three invariants pinned:

    1. The :class:`HookError` raise propagates as expected — the
       audit-row outcome (sink succeeds, sink times out, sink raises)
       does not change the tier-refusal raise. The register-time
       refusal is the user-visible contract; the audit row is the
       loud-failure escape.
    2. The structlog ``alfred.hooks.audit_fallback`` channel records
       the rejection event with the import-time ``reason`` so an
       operator can distinguish a startup-time sink stall from a
       running-loop stall.
    3. :meth:`register` returns inside a small wall-clock budget — if
       the timeout regressed to "unbounded" the test would wedge the
       sink's 1.0 s sleep through to :meth:`register`'s caller, which
       this assertion catches as a wall-clock budget overrun.

    Regression guard against the prior shape:
    ``asyncio.run(self.sink.emit(...))`` on the no-running-loop arm
    had no bound at all — a DB-backed sink that stalled on connect
    at module-import time would hang the entire process startup.
    """
    sink = _StallingAuditSink()
    # Slice-3 spec §15.1: deny-path security tests assert against
    # :class:`RealGate` (:func:`make_deny_all_gate`). The tier-
    # allowlist check fires before the gate consult, so the gate's
    # deny posture is defense-in-depth here — the load-bearing
    # assertion is the bounded sink stall, not the gate's outcome.
    registry = HookRegistry(
        gate=make_deny_all_gate(),
        sink=sink,
        strict_declarations=True,
    )
    registry.register_hookpoint(
        name="before_db_write",
        subscribable_tiers=frozenset({"system", "operator"}),
        refusable_tiers=frozenset({"system"}),
        fail_closed=True,
    )

    # Capture structlog output across the register call so the
    # fallback row is observable. ``capture_logs()`` intercepts the
    # ``alfred.hooks.audit_fallback`` logger output regardless of the
    # global structlog config — required because the project's default
    # config does not route through stdlib logging.
    before = time.monotonic()
    with (
        structlog.testing.capture_logs() as captured,
        pytest.raises(HookError, match="not allowed on hookpoint"),
    ):
        registry.register(
            hook_fn=_noop,
            hookpoint="before_db_write",
            kind="pre",
            tier="user-plugin",
        )
    elapsed_seconds = time.monotonic() - before
    # The sink sleeps 1.0 s; the bound is 0.5 s. Allow 0.95 s wall-
    # clock budget so the test stays robust on slow CI machines while
    # still pinning that the unbounded shape (which would yield ~1.0 s)
    # is rejected.
    assert elapsed_seconds < 0.95, (
        f"register() took {elapsed_seconds:.3f}s — exceeded the no-running-loop "
        f"arm's bounded budget; the asyncio.wait_for bound may have regressed."
    )

    # Fallback row landed on the dedicated fallback channel with the
    # import-time reason — distinct from the running-loop arm's
    # ``"sink_emit_timeout"`` so operators can correlate the two
    # paths separately.
    fallback_rows = [
        c
        for c in captured
        if c.get("event") == HOOKS_TIER_REJECTED
        and c.get("reason") == "sink_emit_timeout_import_time"
    ]
    assert len(fallback_rows) == 1, (
        f"expected exactly one fallback row with "
        f"reason='sink_emit_timeout_import_time'; got {captured!r}"
    )
    row = fallback_rows[0]
    # The full attribution survives the fallback — same fields the
    # primary sink would have received.
    assert row["hookpoint"] == "before_db_write"
    assert row["kind"] == "pre"
    assert row["subscriber_tier"] == "user-plugin"
    assert row["log_level"] == "error"

    # The failed register leaves no trace — same invariant as the
    # primary-sink path.
    assert registry.subscribers_for("before_db_write", "pre") == ()
