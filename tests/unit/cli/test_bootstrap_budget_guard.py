"""Unit: ``build_budget_guard`` constructs a settings-derived ``BudgetGuard``.

PR-S4-11c-1 extracts the orchestrator's per-user budget gate out of the
smoke test's inline wiring into a reusable production builder. The two
load-bearing assertions:

* the returned object is a real :class:`BudgetGuard` wired to the resolver's
  ``show`` loader and the resolver's shared version counter, and
* the per-call cap comes from ``Settings.per_call_max_usd`` — NOT a hardcoded
  literal. The smoke test's ``0.10`` happens to equal the settings default,
  so a builder that hardcoded ``0.10`` would pass a naive equality check;
  this test pins a NON-default cap on the settings stub and asserts the guard
  charges against it, which only succeeds if the builder reads from settings.

``BudgetGuard`` exposes no public per-call-cap accessor — the cap is only
observable through behaviour. We assert it via ``check_and_charge``: a cost
just over the pinned cap must raise :class:`PerCallCapExceededError`, and a
cost just under it must pass. This pins the wiring through the public surface
rather than reaching into the private ``_per_call_max_usd`` attribute.
"""

from __future__ import annotations

from typing import Any

import pytest

from alfred.budget.guard import BudgetGuard, PerCallCapExceededError
from alfred.cli._bootstrap import build_budget_guard
from alfred.identity import IdentityVersionCounter


class _FakeUser:
    """Duck-typed user the loader returns — only ``daily_budget_usd`` is read."""

    daily_budget_usd = 1000.0


class _FakeResolver:
    """Minimal resolver stub exposing the surface ``build_budget_guard`` reads.

    The builder only needs ``show(slug=...)`` (the per-user loader) and the
    promoted ``version_counter`` attribute the CLI pins at construction.
    """

    def __init__(self) -> None:
        self.version_counter = IdentityVersionCounter()
        self._users: dict[str, object] = {}

    def show(self, *, slug: str) -> object | None:
        return self._users.get(slug)

    def add_user(self, slug: str, user: object) -> None:
        self._users[slug] = user


def _settings_with_cap(cap: float) -> Any:
    """A duck-typed settings carrying only ``per_call_max_usd``.

    The builder reads exactly one field; a full ``Settings`` would need a DB
    URL + API key env. Keeping the stub minimal documents the dependency.
    """

    class _S:
        per_call_max_usd = cap

    return _S()


def test_build_budget_guard_returns_budget_guard() -> None:
    resolver = _FakeResolver()
    guard = build_budget_guard(resolver, _settings_with_cap(0.10))
    assert isinstance(guard, BudgetGuard)


def test_build_budget_guard_charges_against_settings_cap() -> None:
    """A NON-default cap proves the builder reads settings, not a literal.

    0.42 is deliberately != the settings default (0.10) and != the smoke
    literal (0.10): a hardcoded-0.10 builder would refuse the 0.30 charge
    below (0.30 > 0.10) and so fail this test.
    """
    resolver = _FakeResolver()
    resolver.add_user("operator", _FakeUser())
    guard = build_budget_guard(resolver, _settings_with_cap(0.42))

    # Just under the pinned 0.42 cap: must pass.
    guard.check_and_charge("operator", 0.30)

    # Just over the pinned cap: must raise the per-call refusal.
    with pytest.raises(PerCallCapExceededError):
        guard.check_and_charge("operator", 0.50)


def test_build_budget_guard_loader_resolves_user() -> None:
    """The wired loader routes a fixture slug through ``resolver.show``."""
    resolver = _FakeResolver()
    resolver.add_user("operator", _FakeUser())
    guard = build_budget_guard(resolver, _settings_with_cap(0.10))
    # ``spent_today`` exercises the loader for a known slug; a fresh guard
    # reports zero spend, proving the loader resolved the user without raising
    # ``UnknownBudgetUserError``.
    assert guard.spent_today("operator") == 0.0
