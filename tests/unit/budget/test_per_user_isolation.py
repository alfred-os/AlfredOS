"""Hypothesis property tests pinning per-user ``BudgetGuard`` isolation.

PR-B Phase 1 Task 4 (plan §1 lines 121-126). The example-based tests in
``test_guard.py`` pin two-user shapes; these property tests fuzz across many
users and interleaved charges to catch isolation-leak bugs the named cases
would miss — for example a hash-collision-driven cross-user write, or a NaN
guard regression that only manifests after a specific charge sequence.

Three properties:

1. **Sum-of-charges per user** — interleave charges across an arbitrary user
   set, then assert ``spent_today(u)`` equals the sum of charges keyed on
   ``u``.
2. **NaN/inf on user A never alters user B** — for every (a, b) pair, a NaN
   or inf cost on ``a`` raises ``ValueError`` and leaves ``b``'s row exactly
   as it was (spent + ``_day``).
3. **Evict-then-recharge is independent** — after ``evict(u)``, a fresh
   charge on ``u`` reads back as the new running total; other users'
   ``spent_today`` is unchanged.
"""

from __future__ import annotations

import math
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from alfred.budget.guard import BudgetGuard
from alfred.identity.version_counter import IdentityVersionCounter


class _StubUser:
    """Minimal duck-typed stand-in for the ``alfred.identity.models.User`` ORM."""

    __slots__ = ("daily_budget_usd", "slug")

    def __init__(self, *, slug: str, daily_budget_usd: float) -> None:
        self.slug = slug
        self.daily_budget_usd = daily_budget_usd


def _user_loader() -> Callable[[str], _StubUser | None]:
    """Build a loader that mints a fresh ``_StubUser`` per call.

    Every user_id Hypothesis emits is "known" — the property surface under
    test is the per-user store, not the resolver-rejection path.
    ``daily_budget_usd`` is large enough that no individual charge in the
    strategy below trips the per-user cap.
    """

    def _load(user_id: str) -> _StubUser | None:
        return _StubUser(slug=user_id, daily_budget_usd=1.0)

    return _load


# Slug-shaped strings only. Real ``user_id`` values come from the resolver's
# slug column, which is ``[a-z0-9-]+``. Constraining to lowercase letters
# keeps the strategy in-domain and avoids burning shrinker time on Unicode
# escape paths that the resolver rejects upstream.
_USER_ID = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10)

# Per-call cap is 0.10 below; cost strategy stays well under that so the
# property is "isolation under valid charges", not "cap-breach handling"
# (which the example-based tests in test_guard.py already cover).
_COST = st.floats(min_value=0.001, max_value=0.01, allow_nan=False, allow_infinity=False)


@given(charges=st.lists(st.tuples(_USER_ID, _COST), max_size=30))
@settings(max_examples=50, deadline=None)
def test_per_user_spend_isolation(charges: list[tuple[str, float]]) -> None:
    """Interleaving charges across users sums correctly per user.

    Property: for every user ``u`` that appears in the charge trace,
    ``spent_today(u)`` equals the sum of every cost paired with ``u`` in the
    trace. No cross-talk between users — a charge on Alice never bleeds into
    Bob's running total.
    """
    guard = BudgetGuard(
        user_loader=_user_loader(),
        per_call_max_usd=0.10,
        version_counter=IdentityVersionCounter(),
    )
    expected: dict[str, float] = {}
    for user_id, cost in charges:
        guard.check_and_charge(user_id, cost)
        expected[user_id] = expected.get(user_id, 0.0) + cost
    for user_id, total in expected.items():
        # Float-sum drift is real after dozens of additions; approx() tolerates
        # it while still catching any genuine cross-user contamination.
        assert guard.spent_today(user_id) == pytest.approx(total)


@given(
    user_a=_USER_ID,
    user_b=_USER_ID,
    seed_cost=_COST,
    bad_cost=st.sampled_from([float("nan"), float("inf"), float("-inf")]),
)
@settings(max_examples=50, deadline=None)
def test_nan_inf_one_user_never_alters_another(
    user_a: str, user_b: str, seed_cost: float, bad_cost: float
) -> None:
    """A rejected NaN/inf charge on user A leaves user B's row pristine.

    Property: validation runs BEFORE the per-user store is touched, so a
    bad cost on ``user_a`` raises ``ValueError`` without mutating
    ``user_b``'s spent total. Holds even when ``user_a == user_b`` (the
    rejection is total — no partial write).
    """
    guard = BudgetGuard(
        user_loader=_user_loader(),
        per_call_max_usd=0.10,
        version_counter=IdentityVersionCounter(),
    )
    guard.check_and_charge(user_b, seed_cost)
    bob_spent_before = guard.spent_today(user_b)
    with pytest.raises(ValueError):
        guard.check_and_charge(user_a, bad_cost)
    # Bob's row is byte-identical post-rejection. NaN comparisons would
    # blow up here if ``_spent`` was somehow corrupted — math.isclose
    # surfaces that as a fail rather than a propagated NaN.
    bob_spent_after = guard.spent_today(user_b)
    assert math.isfinite(bob_spent_after)
    assert bob_spent_after == pytest.approx(bob_spent_before)


@given(
    target=_USER_ID,
    others=st.lists(st.tuples(_USER_ID, _COST), max_size=10),
    pre_evict=_COST,
    post_evict=_COST,
)
@settings(max_examples=50, deadline=None)
def test_evict_resets_then_independent(
    target: str,
    others: list[tuple[str, float]],
    pre_evict: float,
    post_evict: float,
) -> None:
    """``evict(u)`` drops ``u``'s row; re-charging starts from zero.

    Property: after ``evict(target)``, a fresh charge of ``post_evict``
    reads back exactly ``post_evict`` (the pre-evict spend is gone). Other
    users' ``spent_today`` is unchanged across the evict.
    """
    guard = BudgetGuard(
        user_loader=_user_loader(),
        per_call_max_usd=0.10,
        version_counter=IdentityVersionCounter(),
    )
    # Seed the target plus an arbitrary set of bystanders; snapshot their
    # spent totals so we can prove ``evict`` only touched the target.
    guard.check_and_charge(target, pre_evict)
    others_expected: dict[str, float] = {}
    for user_id, cost in others:
        if user_id == target:
            # Skip — keep ``target``'s spend uniquely defined by pre_evict so
            # the post-evict reset assertion stays sharp.
            continue
        guard.check_and_charge(user_id, cost)
        others_expected[user_id] = others_expected.get(user_id, 0.0) + cost
    guard.evict(target)
    guard.check_and_charge(target, post_evict)
    # Target's row reflects only the post-evict charge.
    assert guard.spent_today(target) == pytest.approx(post_evict)
    # Every bystander's row is exactly what it was before the evict.
    for user_id, total in others_expected.items():
        assert guard.spent_today(user_id) == pytest.approx(total)
