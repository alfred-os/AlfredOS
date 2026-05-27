"""Per-user budget guard.

Slice-2 PR-B reshapes :class:`BudgetGuard` from a single-user global counter
into a per-user store keyed on the canonical ``user_id`` returned by the
identity resolver. The orchestrator's pre-flight ``would_exceed`` /
``estimate_for`` and post-flight ``check_and_charge`` paths gain a ``user_id``
argument; an in-process ``dict[user_id, _UserBudget]`` holds each user's
running spend, day-rollover state, and cached ``daily_budget_usd`` cap.

Key invariants (spec §2 lines 174-184):

* **Per-user isolation.** Charging Alice never moves Bob's row. Day-rollover
  is per-entry.
* **Validate-then-mutate.** Every per-user surface validates ``cost_usd``
  (NaN/inf/negative) BEFORE touching ``_user_budgets``. A typo'd user_id
  paired with a NaN cost MUST NOT leak a phantom entry.
* **Never evict spend.** ``_spent`` + ``day`` for known users are in-process
  source of truth. Only the explicit ``evict(user_id)`` escape hatch (called
  by ``IdentityResolver.remove`` on soft-delete) drops a row.
* **Version-counter subscribe.** The injected
  :class:`IdentityVersionCounter` is the cross-process invalidation primitive
  — every time the resolver mutates a User row anywhere, it bumps the
  counter, and the next ``_load_or_get_user`` call refreshes its cached cap.

The slice-1 ``BudgetGuard(daily_usd=, per_call_max_usd=)`` constructor is
replaced by ``BudgetGuard(*, user_loader, per_call_max_usd, version_counter)``
— call sites are updated in the same commit.
"""

from __future__ import annotations

import datetime as dt
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from alfred.identity.version_counter import IdentityVersionCounter
    from alfred.providers.base import CompletionRequest


class BudgetError(RuntimeError):
    """Base for budget-related errors."""


class PerCallCapExceededError(BudgetError):
    """A single call would exceed the per-call cost cap."""


class UnknownBudgetUserError(BudgetError):
    """A budget operation referenced a ``user_id`` the resolver doesn't know.

    Defense-in-depth: PR-B's per-user resolver is supposed to reject unknown
    user_ids before they reach the guard layer. If a caller bypasses the
    resolver (a programming error), this surfaces loudly with the exact CLI
    command an operator runs to remediate, instead of silently no-op'ing a
    charge against a phantom guard.
    """

    def __init__(self, *, user_id: str) -> None:
        # Keep the user_id on the exception so downstream consumers (audit
        # rows, structured logs) can render it as a typed field rather than
        # parsing it out of the message string.
        self.user_id = user_id
        super().__init__(
            f"budget unknown for user_id={user_id!r}; operator must add via 'alfred user add'"
        )


class BudgetExceededError(BudgetError):
    """Per-user daily budget cap was hit.

    Carries typed ``spent_usd`` + ``cap_usd`` attributes so the discord
    ``budget_blocked`` i18n template (PR D2) and audit rows can render
    structured kwargs rather than parsing ``str(exc)``.
    """

    def __init__(self, *, spent_usd: float, cap_usd: float) -> None:
        self.spent_usd = spent_usd
        self.cap_usd = cap_usd
        super().__init__(f"per-user daily budget ${cap_usd:.2f} exceeded (spent ${spent_usd:.4f})")


# ---------------------------------------------------------------------------
# Per-user budget entry
# ---------------------------------------------------------------------------


@dataclass
class _UserBudget:
    """In-process per-user spend tracker.

    Mutable on purpose: ``check_and_charge`` increments ``spent`` and may
    advance ``day``; ``_load_or_get_user`` refreshes ``daily_usd`` +
    ``daily_usd_version`` when the version counter advances. Keeping these
    fields together as a single dataclass keeps the dict-of-records pattern
    explicit (vs four parallel dicts) and lets the per-user invariants live
    co-located with their state.
    """

    daily_usd: float
    daily_usd_version: int
    per_call_max_usd: float
    day: dt.date
    spent: float


# Type alias for the user_loader injection seam. Returns a duck-typed User
# (anything with ``daily_budget_usd: float``); the orchestrator constructs
# one bound to the IdentityResolver, tests pass dict-backed stubs. Kept as
# ``object`` rather than the SQLAlchemy ORM to avoid an import cycle at
# module load time and to keep the unit-test stubs minimal — only one
# attribute is read, ``daily_budget_usd``.
if TYPE_CHECKING:
    UserLoader = Callable[[str], object | None]


class BudgetGuard:
    """Per-user cost gate keyed on the canonical ``user_id``.

    Constructor signature:

    .. code-block:: python

        BudgetGuard(
            user_loader=lambda user_id: resolver.show(slug=user_id),
            per_call_max_usd=settings.per_call_max_usd,
            version_counter=identity_version_counter,
        )

    Every per-user method (``check_and_charge``, ``would_exceed``,
    ``estimate_for``, ``spent_today``) takes ``user_id`` as its first
    argument and raises :class:`UnknownBudgetUserError` if the loader
    returns ``None`` for that id.
    """

    def __init__(
        self,
        *,
        user_loader: Callable[[str], object | None],
        per_call_max_usd: float,
        version_counter: IdentityVersionCounter,
    ) -> None:
        # Per-call cap stays global (spec §2 line 178): a user-specific cap
        # would let a malicious ``alfred user add --per-call-max-usd inf``
        # pre-disable the cap for that user. The cap is process-wide, set
        # once at construction.
        #
        # Finite + non-negative: NaN/inf would corrupt spend math, and a
        # negative cap inverts the meaning of the gate.
        if not math.isfinite(per_call_max_usd):
            raise ValueError(
                f"BudgetGuard per_call_max_usd must be finite (got {per_call_max_usd})"
            )
        if per_call_max_usd < 0:
            raise ValueError(
                f"BudgetGuard per_call_max_usd must be non-negative (got {per_call_max_usd})"
            )
        self._user_loader = user_loader
        self._per_call_max_usd = per_call_max_usd
        self._version_counter = version_counter
        # The per-user store: keyed on canonical user_id (the resolver's
        # ``user.slug``). Never evict an entry implicitly — only via the
        # explicit ``evict()`` escape hatch — so a chatty user's running
        # spend never resets just because the dict happened to be touched.
        self._user_budgets: dict[str, _UserBudget] = {}

    # ------------------------------------------------------------------ #
    # Public per-user surface
    # ------------------------------------------------------------------ #

    def check_and_charge(self, user_id: str, cost_usd: float) -> None:
        """Charge ``cost_usd`` to ``user_id``'s row after validation.

        Raises:
            ValueError: ``cost_usd`` is NaN, inf, or negative.
            PerCallCapExceededError: ``cost_usd`` exceeds the global
                per-call cap.
            UnknownBudgetUserError: ``user_id`` isn't known to the loader.
            BudgetExceededError: the charge would breach the user's
                per-day cap. Carries typed ``spent_usd`` + ``cap_usd``.
        """
        # Validate BEFORE loading / mutating. Spec §2 line 176: a typo'd
        # user_id paired with a NaN cost MUST NOT leak a phantom entry into
        # ``_user_budgets``. The order here is load-bearing.
        self._validate_cost(cost_usd)
        # Resolve user_id BEFORE the per-call cap check so an unknown user
        # paired with an over-cap cost still surfaces as UnknownBudgetUserError
        # (the precise, actionable failure mode) rather than the more generic
        # PerCallCapExceededError that an operator might misread as a tuning
        # problem. The cost-validation gate above still runs first so a NaN
        # cost on an unknown user remains a ValueError, never an
        # UnknownBudgetUserError-shaped phantom-entry leak.
        entry = self._load_or_get_user(user_id)
        if cost_usd > self._per_call_max_usd:
            raise PerCallCapExceededError(
                f"call cost ${cost_usd:.4f} exceeds per-call cap ${self._per_call_max_usd:.2f}"
            )
        self._roll_day_if_needed(entry)
        if entry.spent + cost_usd > entry.daily_usd:
            # Raise without mutation: the charge does not stick. Carries the
            # pre-rejection spent total so downstream consumers (the discord
            # ``budget_blocked`` template, audit rows) can render typed
            # kwargs rather than parsing the message.
            raise BudgetExceededError(spent_usd=entry.spent, cap_usd=entry.daily_usd)
        entry.spent += cost_usd

    def would_exceed(self, user_id: str, cost_usd: float) -> bool:
        """Return ``True`` iff charging ``user_id`` ``cost_usd`` would breach either cap.

        Called by the orchestrator BEFORE the provider call so an
        over-budget request is refused without spending money on it.

        Raises:
            ValueError: ``cost_usd`` is NaN, inf, or negative.
            UnknownBudgetUserError: ``user_id`` isn't known to the loader.
        """
        self._validate_cost(cost_usd)
        # Resolve user_id BEFORE the per-call cap check so an unknown user
        # paired with an over-cap cost surfaces as UnknownBudgetUserError
        # rather than a silent ``True``. Pre-flight callers (the orchestrator)
        # then audit the precise failure mode instead of guessing why the
        # turn was refused.
        entry = self._load_or_get_user(user_id)
        if cost_usd > self._per_call_max_usd:
            return True
        self._roll_day_if_needed(entry)
        return entry.spent + cost_usd > entry.daily_usd

    def estimate_for(self, user_id: str, _request: CompletionRequest) -> float:
        """Estimate the USD cost of a provider call for ``user_id`` before sending it.

        Slice-2 PR-B returns the conservative flat-rate estimate (the
        per-call cap itself) carried over from slice-1 so ``would_exceed``
        reduces to "is there cap-worth of budget left?". A later PR
        replaces this with a token-aware estimate that reads the request's
        message tokens and the routed provider's published rates.

        Raises:
            UnknownBudgetUserError: ``user_id`` isn't known to the loader.
        """
        # Loading here serves two purposes: (1) confirms the user_id is
        # known so estimate_for can't be used to bypass the resolver's
        # rejection of unknown ids, (2) primes the cache so the subsequent
        # would_exceed/check_and_charge round-trip is one DB hit, not two.
        self._load_or_get_user(user_id)
        return self._per_call_max_usd

    def spent_today(self, user_id: str) -> float:
        """Return ``user_id``'s running spend for the current UTC day.

        Raises:
            UnknownBudgetUserError: ``user_id`` isn't known to the loader.
        """
        entry = self._load_or_get_user(user_id)
        self._roll_day_if_needed(entry)
        return entry.spent

    def evict(self, user_id: str) -> None:
        """Drop ``user_id``'s entry from the in-process store.

        Called by :meth:`IdentityResolver.remove` when an operator
        soft-deletes a user (spec §2 line 179). A re-added user starts with
        a fresh ``_spent`` of zero — the previous spend doesn't survive the
        operator-initiated removal.

        No-op for unknown user_ids: operators commonly remove a user that
        was never charged within this process's lifetime, and repeated
        evicts are equally fine.
        """
        self._user_budgets.pop(user_id, None)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    @staticmethod
    def _validate_cost(cost_usd: float) -> None:
        """Reject NaN/inf/negative costs.

        A negative ``cost_usd`` would subtract from the running total and
        silently refund past spend, opening a daily-cap bypass. NaN/inf
        would poison ``_spent`` once added; cap comparisons would silently
        stop working. Refuse at the boundary so providers / tests surface
        the bug loudly rather than corrupting the running total.

        Static so callers don't need an instance reference and so it's
        impossible to accidentally mutate state from the validation path.
        """
        if not math.isfinite(cost_usd):
            raise ValueError(f"cost_usd must be finite, got {cost_usd}")
        if cost_usd < 0:
            raise ValueError(f"cost_usd must be non-negative, got {cost_usd}")

    def _load_or_get_user(self, user_id: str) -> _UserBudget:
        """Return ``user_id``'s ``_UserBudget``, loading or refreshing as needed.

        Cache logic:

        * No entry exists yet → call the loader, validate the cap, create
          a fresh entry stamped with the current version counter.
        * Entry exists but version counter has advanced → reload the cap
          from the loader (the operator may have run ``alfred user set
          --daily-budget``).
        * Entry exists and version counter is unchanged → return as-is.

        Raises :class:`UnknownBudgetUserError` if the loader returns
        ``None``. Raises :class:`ValueError` if the loader returns a User
        whose ``daily_budget_usd`` is NaN/inf/non-positive — the DB CHECK
        on ``users.daily_budget_usd > 0`` is the primary defense, this is
        the in-process defense-in-depth.
        """
        entry = self._user_budgets.get(user_id)
        current_version = self._version_counter.current()
        if entry is not None and entry.daily_usd_version >= current_version:
            return entry

        user = self._user_loader(user_id)
        if user is None:
            raise UnknownBudgetUserError(user_id=user_id)
        # Read the cap off the duck-typed user. ``getattr`` over a direct
        # attribute access keeps the type signature ``object | None`` (no
        # SQLAlchemy import cycle) at the cost of a slightly looser load
        # path; the validation below is what makes the loose typing safe.
        daily_usd = getattr(user, "daily_budget_usd", None)
        if not isinstance(daily_usd, int | float):
            raise ValueError(
                f"user_loader for {user_id!r} returned a row without a numeric "
                f"daily_budget_usd (got {daily_usd!r})"
            )
        daily_usd_f = float(daily_usd)
        if not math.isfinite(daily_usd_f):
            raise ValueError(
                f"user_loader for {user_id!r} returned non-finite daily_budget_usd={daily_usd_f}"
            )
        if daily_usd_f <= 0:
            raise ValueError(
                f"user_loader for {user_id!r} returned non-positive daily_budget_usd={daily_usd_f}"
            )

        if entry is None:
            entry = _UserBudget(
                daily_usd=daily_usd_f,
                daily_usd_version=current_version,
                per_call_max_usd=self._per_call_max_usd,
                day=dt.datetime.now(dt.UTC).date(),
                spent=0.0,
            )
            self._user_budgets[user_id] = entry
        else:
            # Counter advanced: refresh the cached cap but DO NOT reset
            # ``spent`` or ``day`` — the operator's authoritative running
            # totals must survive a cap change.
            entry.daily_usd = daily_usd_f
            entry.daily_usd_version = current_version
        return entry

    @staticmethod
    def _roll_day_if_needed(entry: _UserBudget) -> None:
        """Reset ``entry.spent`` to zero when the UTC day advances.

        Per-entry rather than per-guard: each user's day-rollover is
        independent so Alice's running spend doesn't reset because Bob
        happened to charge first thing in the morning.
        """
        today = dt.datetime.now(dt.UTC).date()
        if today != entry.day:
            entry.day = today
            entry.spent = 0.0
