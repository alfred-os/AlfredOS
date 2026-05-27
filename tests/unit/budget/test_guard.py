"""Tests for the per-user budget guard.

PR-B Phase 1 reshape (spec §2 lines 174-184): the guard is now an in-process
``dict[user_id, _UserBudget]`` keyed on the canonical resolver slug; the
slice-1 global-cap shape tests (``TestBudgetGuard`` / ``TestWouldExceed`` /
``TestNonNegativeInvariants`` / ``TestEstimateFor``) were deleted in the
same commit. The retained error-shape tests (``TestUnknownBudgetUserError``
+ ``TestBudgetExceededError``) pin contract that survives the refactor; the
per-user contract lives in the lower half of the file.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from unittest.mock import MagicMock

import pytest

from alfred.budget.guard import (
    BudgetError,
    BudgetExceededError,
    BudgetGuard,
    PerCallCapExceededError,
    UnknownBudgetUserError,
)
from alfred.identity.version_counter import IdentityVersionCounter
from alfred.providers.base import CompletionRequest, Message


class TestUnknownBudgetUserError:
    """``UnknownBudgetUserError`` is defense-in-depth for the per-user guard.

    PR-B routes budget calls through a resolver that maps ``user_id`` to a
    per-user guard. The resolver is supposed to reject unknown user_ids before
    they reach the guard layer, but if a caller bypasses the resolver (a
    programming error) the guard layer raises this so the failure surfaces
    loudly with an actionable remediation hint instead of silently charging
    nothing.
    """

    def test_unknown_budget_user_error_inherits_budget_error(self) -> None:
        assert issubclass(UnknownBudgetUserError, BudgetError)

    def test_unknown_budget_user_error_message_includes_user_id(self) -> None:
        err = UnknownBudgetUserError(user_id="alice")
        # The user_id is what an operator needs to know to remediate, and the
        # message points at the exact CLI command they have to run.
        assert "alice" in str(err)
        assert "alfred user add" in str(err)


class TestBudgetExceededError:
    """``BudgetExceededError`` is the per-user daily-cap hit.

    Carries typed ``spent_usd`` + ``cap_usd`` attributes so downstream
    consumers (the discord ``budget_blocked`` i18n template in PR D2, audit
    rows, future TUI surfaces) can render structured kwargs rather than
    parsing ``str(exc)``.
    """

    def test_budget_exceeded_error_inherits_budget_error(self) -> None:
        assert issubclass(BudgetExceededError, BudgetError)

    def test_budget_exceeded_error_carries_typed_kwargs(self) -> None:
        err = BudgetExceededError(spent_usd=0.95, cap_usd=1.00)
        # Attributes survive the raise/catch round-trip — pinning this keeps
        # downstream consumers safe from accidentally regressing to str(exc).
        assert err.spent_usd == 0.95
        assert err.cap_usd == 1.00

    def test_budget_exceeded_error_attributes_after_raise(self) -> None:
        try:
            raise BudgetExceededError(spent_usd=2.50, cap_usd=2.00)
        except BudgetExceededError as caught:
            assert caught.spent_usd == 2.50
            assert caught.cap_usd == 2.00


# ---------------------------------------------------------------------------
# Per-user isolation contract (PR-B Phase 1 Task 2)
# ---------------------------------------------------------------------------
#
# Slice-1's BudgetGuard tracked a single global ``_spent``; PR B (T3) refactors
# it into a per-user store keyed on the canonical ``user_id`` returned by the
# identity resolver. These tests pin the isolation contract a multi-user
# household depends on: charging Alice's row must never move Bob's row, NaN
# fuzzing on Alice's path must never corrupt Bob's running total, and an
# operator's day-rollover must remain Alice-local.
#
# The new signature shape is (per spec §2 lines 174-184):
#
#     BudgetGuard(*, user_loader=Callable[[str], User | None],
#                    per_call_max_usd: float,
#                    version_counter: IdentityVersionCounter)
#     guard.check_and_charge(user_id, cost_usd)
#     guard.would_exceed(user_id, cost_usd) -> bool
#     guard.estimate_for(user_id, request) -> float
#     guard.spent_today(user_id) -> float
#     guard.evict(user_id) -> None
#
# Every test in this section uses that shape, so until T3 lands the implementation
# these tests will fail at construction or method-dispatch time. That is the
# point — they are the failing-first half of TDD.


class _StubUser:
    """Minimal duck-typed stand-in for the ``alfred.identity.models.User`` ORM.

    The guard only reads ``daily_budget_usd`` on first-load and after a
    version-counter bump (spec §2 line 175). A plain attribute carrier here
    keeps the test surface independent of SQLAlchemy session machinery.
    """

    __slots__ = ("daily_budget_usd", "slug")

    def __init__(self, *, slug: str, daily_budget_usd: float) -> None:
        self.slug = slug
        self.daily_budget_usd = daily_budget_usd


def _loader_from_dict(users: dict[str, _StubUser]) -> Callable[[str], _StubUser | None]:
    """Build a dict-backed user_loader. Returns ``None`` for unknown user_ids."""

    def _load(user_id: str) -> _StubUser | None:
        return users.get(user_id)

    return _load


class TestPerUserIsolation:
    """Charging one user does not move another user's spend / day-state.

    Spec §2 line 174: ``_user_budgets`` is the per-user store; each entry's
    ``_spent`` and ``_day`` are independent. Violating this would let a
    chatty user starve a quiet one (or vice versa), and would defeat the
    operator's per-user daily caps entirely.
    """

    def _make_guard(
        self,
        *,
        users: dict[str, _StubUser],
        per_call_max_usd: float = 0.10,
    ) -> BudgetGuard:
        return BudgetGuard(
            user_loader=_loader_from_dict(users),
            per_call_max_usd=per_call_max_usd,
            version_counter=IdentityVersionCounter(),
        )

    def test_charging_alice_does_not_move_bob_spent_today(self) -> None:
        users = {
            "alice": _StubUser(slug="alice", daily_budget_usd=1.0),
            "bob": _StubUser(slug="bob", daily_budget_usd=1.0),
        }
        guard = self._make_guard(users=users)
        guard.check_and_charge("alice", 0.05)
        guard.check_and_charge("alice", 0.03)
        # Bob hasn't been charged at all — his row must still read zero.
        assert guard.spent_today("bob") == 0.0
        # And Alice's row reflects exactly her two charges.
        assert guard.spent_today("alice") == pytest.approx(0.08)

    def test_per_call_cap_is_global_across_users(self) -> None:
        # Per-call cap is the orchestrator's blast-radius gate (spec §2 line
        # 178: "Per-call cap stays global"). A user-specific cap would let
        # a malicious /alfred user add command pre-disable the cap for that
        # user. The cap is process-wide, set once at construction.
        users = {
            "alice": _StubUser(slug="alice", daily_budget_usd=10.0),
            "bob": _StubUser(slug="bob", daily_budget_usd=10.0),
        }
        guard = self._make_guard(users=users, per_call_max_usd=0.10)
        # 0.20 > 0.10 cap — both users must be rejected identically.
        with pytest.raises(PerCallCapExceededError):
            guard.check_and_charge("alice", 0.20)
        with pytest.raises(PerCallCapExceededError):
            guard.check_and_charge("bob", 0.20)
        # No charge stuck on either user.
        assert guard.spent_today("alice") == 0.0
        assert guard.spent_today("bob") == 0.0

    def test_day_rollover_is_per_user_alice_rolls_without_disturbing_bob(self) -> None:
        users = {
            "alice": _StubUser(slug="alice", daily_budget_usd=1.0),
            "bob": _StubUser(slug="bob", daily_budget_usd=1.0),
        }
        guard = self._make_guard(users=users)
        guard.check_and_charge("alice", 0.05)
        guard.check_and_charge("bob", 0.07)
        # Simulate Alice's row crossing midnight without Bob's row doing so.
        # The per-user store is ``_user_budgets: dict[str, _UserBudget]``;
        # we tickle only Alice's entry.
        alice_entry = guard._user_budgets["alice"]
        alice_entry.day = dt.datetime.now(dt.UTC).date() - dt.timedelta(days=1)
        # Alice's next charge sees a new day and resets HER row only.
        guard.check_and_charge("alice", 0.02)
        assert guard.spent_today("alice") == pytest.approx(0.02)
        # Bob never crossed midnight in this scenario — his spend stays.
        assert guard.spent_today("bob") == pytest.approx(0.07)


class TestUnknownBudgetUserRaisesAtEverySurface:
    """The four user-facing methods raise ``UnknownBudgetUserError`` for unknowns.

    Spec §2 line 175: a typo'd user_id must surface loudly at every surface,
    not silently no-op a charge against a phantom guard or return a bogus
    zero from ``spent_today``. The resolver is the first line of defense;
    the guard is the defense-in-depth that catches resolver-bypass bugs.
    """

    def _empty_guard(self) -> BudgetGuard:
        # No users in the loader's dict — every user_id is "unknown".
        return BudgetGuard(
            user_loader=_loader_from_dict({}),
            per_call_max_usd=0.10,
            version_counter=IdentityVersionCounter(),
        )

    def test_check_and_charge_raises_on_unknown_user(self) -> None:
        guard = self._empty_guard()
        with pytest.raises(UnknownBudgetUserError) as excinfo:
            guard.check_and_charge("ghost", 0.01)
        assert excinfo.value.user_id == "ghost"

    def test_would_exceed_raises_on_unknown_user(self) -> None:
        guard = self._empty_guard()
        with pytest.raises(UnknownBudgetUserError) as excinfo:
            guard.would_exceed("ghost", 0.01)
        assert excinfo.value.user_id == "ghost"

    def test_estimate_for_raises_on_unknown_user(self) -> None:
        guard = self._empty_guard()
        request = CompletionRequest(messages=[Message(role="user", content="hi")])
        with pytest.raises(UnknownBudgetUserError) as excinfo:
            guard.estimate_for("ghost", request)
        assert excinfo.value.user_id == "ghost"

    def test_spent_today_raises_on_unknown_user(self) -> None:
        guard = self._empty_guard()
        with pytest.raises(UnknownBudgetUserError) as excinfo:
            guard.spent_today("ghost")
        assert excinfo.value.user_id == "ghost"


class TestEvict:
    """``evict`` is the soft-delete escape hatch.

    Called by ``IdentityResolver.remove`` when an operator removes a user
    (spec §2 line 179). Removes the user's entry so a re-add starts clean.
    Must be a no-op for unknown user_ids — operators commonly remove a user
    that was never charged within this process's lifetime.
    """

    def test_evict_removes_existing_entry(self) -> None:
        users = {"alice": _StubUser(slug="alice", daily_budget_usd=1.0)}
        guard = BudgetGuard(
            user_loader=_loader_from_dict(users),
            per_call_max_usd=0.10,
            version_counter=IdentityVersionCounter(),
        )
        guard.check_and_charge("alice", 0.05)
        assert "alice" in guard._user_budgets
        guard.evict("alice")
        assert "alice" not in guard._user_budgets

    def test_evict_unknown_user_is_no_op(self) -> None:
        # Operators commonly call remove() for a user that hasn't been
        # touched yet this process — the guard must not raise on it. Use the
        # empty-loader form so even the user_loader has no opinion.
        guard = BudgetGuard(
            user_loader=_loader_from_dict({}),
            per_call_max_usd=0.10,
            version_counter=IdentityVersionCounter(),
        )
        # Should not raise — no return value to assert on, just absence of
        # exception. Repeated evicts are equally fine.
        guard.evict("ghost")
        guard.evict("ghost")

    def test_re_introducing_a_user_after_evict_starts_fresh(self) -> None:
        # The soft-delete contract: an evicted user's running spend is
        # genuinely gone. The operator chose to remove them; their charges
        # do not survive into a re-introduction.
        users = {"alice": _StubUser(slug="alice", daily_budget_usd=1.0)}
        guard = BudgetGuard(
            user_loader=_loader_from_dict(users),
            per_call_max_usd=0.10,
            version_counter=IdentityVersionCounter(),
        )
        guard.check_and_charge("alice", 0.05)
        guard.evict("alice")
        # Re-introduce — the loader still resolves to a User row (the
        # operator re-added the same slug).
        guard.check_and_charge("alice", 0.02)
        assert guard.spent_today("alice") == pytest.approx(0.02)


class TestPerUserValidationBeforeMutation:
    """NaN/inf rejection must not leak entries into ``_user_budgets``.

    Spec §2 line 176 is explicit: "validation raises BEFORE ``_user_budgets``
    is mutated". A typo'd user_id paired with a NaN cost (the kind of bug
    surface that fuzzers reach for) must not silently materialise a budget
    row for a user the resolver hasn't introduced. The hypothesis property
    test in PR-B T4 exercises this aggressively; these unit tests pin the
    surface contract.
    """

    def _two_user_guard(self) -> tuple[BudgetGuard, dict[str, _StubUser]]:
        users = {
            "alice": _StubUser(slug="alice", daily_budget_usd=1.0),
            "bob": _StubUser(slug="bob", daily_budget_usd=1.0),
        }
        guard = BudgetGuard(
            user_loader=_loader_from_dict(users),
            per_call_max_usd=0.10,
            version_counter=IdentityVersionCounter(),
        )
        return guard, users

    def test_nan_cost_raises_value_error_without_mutating_other_users(self) -> None:
        guard, _ = self._two_user_guard()
        guard.check_and_charge("bob", 0.04)  # establish bob's row
        bob_spent_before = guard.spent_today("bob")
        with pytest.raises(ValueError, match="finite"):
            guard.check_and_charge("alice", float("nan"))
        # Bob's row must be byte-identical post-rejection.
        assert guard.spent_today("bob") == bob_spent_before
        # And Alice's row must still register zero spend (the NaN call
        # rejected before it mutated her _spent).
        assert guard.spent_today("alice") == 0.0

    def test_inf_cost_raises_value_error_without_mutating_other_users(self) -> None:
        guard, _ = self._two_user_guard()
        guard.check_and_charge("bob", 0.04)
        bob_spent_before = guard.spent_today("bob")
        with pytest.raises(ValueError, match="finite"):
            guard.check_and_charge("alice", float("inf"))
        assert guard.spent_today("bob") == bob_spent_before
        assert guard.spent_today("alice") == 0.0

    def test_validation_raises_before_user_budgets_is_mutated(self) -> None:
        # Spec §2 line 176 — the load-bearing invariant. A NaN cost for an
        # otherwise-untouched-this-process user must NOT leave an entry
        # behind in _user_budgets. If validation ran AFTER _load_or_get_user
        # the dict would carry a phantom row keyed on the user even though
        # no charge stuck.
        guard, _ = self._two_user_guard()
        assert "alice" not in guard._user_budgets
        with pytest.raises(ValueError, match="finite"):
            guard.check_and_charge("alice", float("nan"))
        # The critical assertion: _user_budgets is still pristine.
        assert "alice" not in guard._user_budgets

    def test_negative_cost_raises_value_error_without_mutating_other_users(self) -> None:
        # Negative-cost rejection has the same mutation-ordering invariant
        # as NaN — both are input-sanitisation that runs before the load
        # path. Pin it here because negative cost is the more likely
        # provider-bug shape than NaN in real traffic.
        guard, _ = self._two_user_guard()
        guard.check_and_charge("bob", 0.04)
        bob_spent_before = guard.spent_today("bob")
        with pytest.raises(ValueError, match="non-negative"):
            guard.check_and_charge("alice", -0.01)
        assert guard.spent_today("bob") == bob_spent_before
        assert "alice" not in guard._user_budgets


class TestBudgetExceededErrorOnDailyCap:
    """The per-user daily cap raises ``BudgetExceededError`` with typed kwargs.

    Spec §2 lines 180-184: when a per-user daily cap is breached, the
    raised exception must carry ``spent_usd`` (the running total before the
    rejected charge) and ``cap_usd`` (that user's ``daily_budget_usd``) as
    typed attributes. PR D2's discord ``budget_blocked`` i18n template
    consumes these as structured kwargs — string-parsing ``str(exc)`` is the
    failure mode this test class exists to prevent.
    """

    def test_daily_cap_breach_raises_budget_exceeded_error_with_attributes(self) -> None:
        users = {"alice": _StubUser(slug="alice", daily_budget_usd=0.10)}
        guard = BudgetGuard(
            user_loader=_loader_from_dict(users),
            per_call_max_usd=0.10,
            version_counter=IdentityVersionCounter(),
        )
        guard.check_and_charge("alice", 0.08)  # 0.08 spent
        with pytest.raises(BudgetExceededError) as excinfo:
            # 0.08 + 0.05 = 0.13 > 0.10 daily cap
            guard.check_and_charge("alice", 0.05)
        # The typed attributes are what downstream consumers actually use —
        # pin both so a regression to a string-formatted exception fails loudly.
        assert excinfo.value.spent_usd == pytest.approx(0.08)
        assert excinfo.value.cap_usd == pytest.approx(0.10)

    def test_daily_cap_breach_does_not_mutate_other_users(self) -> None:
        # Defense-in-depth: a daily-cap breach on Alice must not change
        # Bob's running total. Distinct from the NaN/inf case because the
        # rejection point is mid-method (after validation, after load) —
        # the invariant has to hold at every raise-point, not just the
        # input-sanitisation prologue.
        users = {
            "alice": _StubUser(slug="alice", daily_budget_usd=0.10),
            "bob": _StubUser(slug="bob", daily_budget_usd=1.0),
        }
        guard = BudgetGuard(
            user_loader=_loader_from_dict(users),
            per_call_max_usd=0.10,
            version_counter=IdentityVersionCounter(),
        )
        guard.check_and_charge("alice", 0.08)
        guard.check_and_charge("bob", 0.04)
        bob_spent_before = guard.spent_today("bob")
        with pytest.raises(BudgetExceededError):
            guard.check_and_charge("alice", 0.05)
        assert guard.spent_today("bob") == bob_spent_before
        # And Alice's row still reads exactly her pre-breach total — the
        # rejected charge does not accumulate.
        assert guard.spent_today("alice") == pytest.approx(0.08)

    def test_estimate_for_unused_request_arg_does_not_error(self) -> None:
        # Slice-1's ``estimate_for`` returned the per-call cap regardless of
        # request shape; PR B keeps that contract per-user. Confirms the
        # per-user signature still accepts a MagicMock request unchanged,
        # so the slice-2 token-aware refactor (in a later PR) can swap the
        # body without touching the call shape.
        users = {"alice": _StubUser(slug="alice", daily_budget_usd=1.0)}
        guard = BudgetGuard(
            user_loader=_loader_from_dict(users),
            per_call_max_usd=0.07,
            version_counter=IdentityVersionCounter(),
        )
        assert guard.estimate_for("alice", MagicMock()) == pytest.approx(0.07)
