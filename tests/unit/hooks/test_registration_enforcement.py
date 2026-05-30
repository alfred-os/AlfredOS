"""Tests for ``register_hookpoint`` declaration API (#119, commit 1).

Pins the spec §6.2 first half: a publisher MUST declare a hookpoint
via :meth:`HookRegistry.register_hookpoint` before any subscriber may
register against it. Declaration carries the per-hookpoint
``subscribable_tiers`` / ``refusable_tiers`` / ``fail_closed``
metadata that the registration-enforcement and the dispatch-time
defense-in-depth (commits 2-3) consult.

Three invariants in this file:

1. **Undeclared hookpoint refuses subscriber registration.** Forces
   the publisher-declares-first module-init ordering.
2. **Idempotent declaration on equal args.** Re-importing a publisher
   module re-runs the declaration; identical metadata is a no-op.
3. **Conflicting declaration raises.** Two declarations of the same
   name with different metadata is a publisher-version-drift or
   copy-paste-typo shape; loud refusal is the correct disposition.

The tier-allowlist enforcement that uses the stored metadata lands in
commit 2 (``test_subscriber_tier_not_in_allowlist_refuses``); the
dispatch-time re-check lands in commit 3
(``test_dispatch_publisher_drift.py``).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from alfred.hooks.context import HookContext
from alfred.hooks.errors import HookError
from alfred.hooks.registry import HookpointMeta, HookRegistry

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

    reg = HookRegistry(gate=DevGate())
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
