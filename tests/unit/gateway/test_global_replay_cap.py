"""Unit tests for the pure ``GlobalReplayCap`` coordinator (Spec B G6-4 / #288, K2).

The cap bounds the SUM of every leg's ReplayBuffer resident bytes so the total
pre-DLP T1 in the always-up SETUID process is bounded regardless of N legs
(``[fleet perf-002]``). It is a pure accountant: ``reserve`` before a leg appends,
``release`` on every byte-reclaim path. The triple-flagged budget-leak guard (K2) is
proven here by the ``total == Σ per-leg`` invariant under any op sequence.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from alfred.gateway.global_replay_cap import GlobalReplayCap, GlobalReplayCapError


def test_non_positive_cap_raises() -> None:
    with pytest.raises(GlobalReplayCapError, match="positive"):
        GlobalReplayCap(max_total_bytes=0)
    with pytest.raises(GlobalReplayCapError, match="positive"):
        GlobalReplayCap(max_total_bytes=-1)


def test_fresh_cap_is_empty() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    assert cap.total_bytes == 0
    assert cap.leg_bytes("tui") == 0
    assert cap.max_total_bytes == 100


def test_reserve_within_budget_succeeds_and_accrues() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    assert cap.reserve("tui", 40) is True
    assert cap.total_bytes == 40
    assert cap.leg_bytes("tui") == 40


def test_reserve_to_exact_cap_succeeds() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    assert cap.reserve("a", 60) is True
    assert cap.reserve("b", 40) is True  # exactly fills
    assert cap.total_bytes == 100


def test_reserve_that_would_exceed_cap_refuses_and_does_not_accrue() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    assert cap.reserve("a", 60) is True
    assert cap.reserve("b", 41) is False  # 60+41=101 > 100
    assert cap.total_bytes == 60  # the refused reserve accrued NOTHING
    assert cap.leg_bytes("b") == 0


def test_off_by_one_boundary() -> None:
    # F7: exact-boundary off-by-one. cap=10: reserve 10 ok, then +1 refused; but
    # 9 then 1 fills exactly.
    cap = GlobalReplayCap(max_total_bytes=10)
    assert cap.reserve("a", 10) is True
    assert cap.reserve("a", 1) is False
    cap2 = GlobalReplayCap(max_total_bytes=10)
    assert cap2.reserve("a", 9) is True
    assert cap2.reserve("a", 1) is True
    assert cap2.reserve("a", 1) is False


def test_n_legs_under_per_leg_but_over_global_refuses_the_over_budget_leg() -> None:
    # The headline perf-002 scenario: N legs each modest, summing over the global cap.
    cap = GlobalReplayCap(max_total_bytes=100)
    assert cap.reserve("a", 40) is True
    assert cap.reserve("b", 40) is True
    # c is small per-leg but the sum (40+40+40=120) blows the global cap.
    assert cap.reserve("c", 40) is False
    assert cap.leg_bytes("c") == 0
    # Releasing frees global budget for c.
    cap.release("a", 40)
    assert cap.reserve("c", 40) is True


def test_release_frees_budget() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    cap.reserve("a", 100)
    assert cap.reserve("b", 1) is False
    cap.release("a", 50)
    assert cap.total_bytes == 50
    assert cap.reserve("b", 50) is True


def test_release_zero_is_noop() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    cap.reserve("a", 40)
    cap.release("a", 0)
    assert cap.total_bytes == 40


def test_reserve_zero_is_noop_success() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    assert cap.reserve("a", 0) is True
    assert cap.total_bytes == 0


def test_release_more_than_reserved_is_loud() -> None:
    # A release that would drive a leg's accounting negative is a budget-corruption
    # misuse — fail loud (CLAUDE.md hard rule #7), never silently clamp to 0.
    cap = GlobalReplayCap(max_total_bytes=100)
    cap.reserve("a", 40)
    with pytest.raises(GlobalReplayCapError, match="release"):
        cap.release("a", 41)


def test_release_unknown_leg_is_loud() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    with pytest.raises(GlobalReplayCapError, match="release"):
        cap.release("never-reserved", 1)


def test_reserve_negative_is_loud() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    with pytest.raises(GlobalReplayCapError, match="non-negative"):
        cap.reserve("a", -1)


def test_release_negative_is_loud() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    cap.reserve("a", 10)
    with pytest.raises(GlobalReplayCapError, match="non-negative"):
        cap.release("a", -1)


def test_remove_leg_frees_its_budget_and_entry() -> None:
    # perf-L1: leg teardown removes the per-leg accounting entry (a real leak when
    # legs churn in G6-5) and frees its reserved budget back to the global pool.
    cap = GlobalReplayCap(max_total_bytes=100)
    cap.reserve("a", 60)
    freed = cap.remove_leg("a")
    assert freed == 60
    assert cap.total_bytes == 0
    assert cap.leg_bytes("a") == 0
    # The entry is gone — a subsequent reserve re-creates it cleanly.
    assert cap.reserve("b", 100) is True


def test_remove_unknown_leg_is_noop() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    assert cap.remove_leg("nope") == 0


def test_per_leg_isolation() -> None:
    cap = GlobalReplayCap(max_total_bytes=100)
    cap.reserve("a", 30)
    cap.reserve("b", 20)
    assert cap.leg_bytes("a") == 30
    assert cap.leg_bytes("b") == 20
    cap.release("a", 30)
    assert cap.leg_bytes("a") == 0
    assert cap.leg_bytes("b") == 20  # b untouched


# --------------------------------------------------------------------------- #
# K2 invariant: total == Σ per-leg after ANY op sequence                       #
# --------------------------------------------------------------------------- #


@st.composite
def _op_sequences(draw: st.DrawFn) -> list[tuple[str, str, int]]:
    legs = ["a", "b", "c"]
    return draw(
        st.lists(
            st.tuples(
                st.sampled_from(["reserve", "release", "remove"]),
                st.sampled_from(legs),
                st.integers(min_value=0, max_value=50),
            ),
            max_size=40,
        )
    )


@given(_op_sequences())
def test_total_equals_sum_of_legs_invariant(ops: list[tuple[str, str, int]]) -> None:
    cap = GlobalReplayCap(max_total_bytes=200)
    for kind, leg, n in ops:
        try:
            if kind == "reserve":
                cap.reserve(leg, n)
            elif kind == "release":
                cap.release(leg, n)
            else:
                cap.remove_leg(leg)
        except GlobalReplayCapError:
            # A loud refusal (over-release / unknown leg) leaves accounting intact —
            # the invariant must STILL hold (the failed op was atomic).
            pass
        assert cap.total_bytes == sum(cap.leg_bytes(leg) for leg in ("a", "b", "c"))
        assert cap.total_bytes >= 0
        assert cap.total_bytes <= 200
