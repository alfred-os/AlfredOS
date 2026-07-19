"""P1e (#340): the quarantine timeout hierarchy must stay monotone so a real extraction
is not torn host-side. NOTE the constants alone do NOT bound the retry loop — golive's
per-call ``asyncio.wait_for(remaining_budget)`` makes the budget the true ceiling; this
guard only pins the ORDERING against silent re-inversion. See the PR2b design spec
``docs/superpowers/specs/2026-07-11-issue-340-pr2b-golive-cutover-design.md`` §4 P1e / §19-A3.
"""

from alfred.plugins.web_fetch.constants import _DEFAULT_ACTION_DEADLINE_SECONDS
from alfred.security.quarantine import EXTRACTION_MAX_RETRIES
from alfred.security.quarantine_child.brokered_egress import _CHILD_SDK_READ_TIMEOUT
from alfred.security.quarantine_child.provider_dispatch import (
    _BACKOFF_BASE_SECONDS,
    _MAX_TOTAL_WALL_CLOCK_SECONDS,
)
from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S


def _sdk_read_seconds() -> float:
    """The child's socket-level SDK read ceiling (``httpx.Timeout.read``), narrowed non-None.

    ``httpx.Timeout(read=8.0)`` always sets ``.read``; the assert narrows ``float | None``
    for mypy AND fails loud if a future retune drops the read component to ``None``.
    """
    read = _CHILD_SDK_READ_TIMEOUT.read
    assert read is not None
    return read


def test_timeout_hierarchy_is_monotone() -> None:
    # The action deadline is the operator-tunable OUTER bound the web_fetch dispatcher
    # enforces via asyncio.timeout(action_deadline_seconds); derive it from that constant
    # (not a hardcoded 30) so a default change — or a re-inversion of the two lower module
    # constants — trips this guard. (An operator override BELOW the code constants is a
    # config-misconfiguration a unit guard can't catch; this pins the code-level ordering.)
    action_deadline = float(_DEFAULT_ACTION_DEADLINE_SECONDS)
    # Strict monotone: action_deadline > host read-frame > child wall-clock budget. The 4th
    # term (child SDK read <= budget) is pinned by test_child_side_timeout_chain_is_strict.
    assert action_deadline > _READ_FRAME_TIMEOUT_S > _MAX_TOTAL_WALL_CLOCK_SECONDS


def test_child_side_timeout_chain_is_strict() -> None:
    """§17 (#340 golive Task 15): the FULL child-side nesting is strictly monotone.

    ``SDK_read(8) < child_budget(20) < host_read(25) < action_deadline(30)`` — the §4-P1e
    pattern extended with the 4th (SDK read) term golive lands. The SDK read is drawn from
    the REAL ``_CHILD_SDK_READ_TIMEOUT.read`` so a future httpx-timeout retune that inverted
    the nesting (e.g. an 8s read pushed above the 20s budget) trips this guard.

    Task-16 boundary: the gateway per-listener handshake term (22s) belongs to the 5-term
    ordering-invariant test Task 16 adds (``action_deadline > gateway_handshake >
    child_budget > ...``) — NOT here. This test is child-side only.
    """
    action_deadline = float(_DEFAULT_ACTION_DEADLINE_SECONDS)
    assert (
        _sdk_read_seconds()
        < _MAX_TOTAL_WALL_CLOCK_SECONDS
        < _READ_FRAME_TIMEOUT_S
        < action_deadline
    )


def test_action_deadline_dominates_the_two_phase_read_frame_bound() -> None:
    """§17: the ``2 x _READ_FRAME_TIMEOUT_S`` per-frame bound is dominated by action_deadline.

    ``_SubprocessChildIO.read_frame`` bounds the header read and the body read SEPARATELY,
    each at ``_READ_FRAME_TIMEOUT_S`` — a theoretical ``2 x 25 = 50s`` per-frame ceiling
    (golive spec §17). A wedged child is capped BELOW that only by the
    ``asyncio.timeout(action_deadline_seconds)`` outer wrap on the extraction path. For that
    wrap to be the EFFECTIVE ceiling it must fire first: ``action_deadline < 2 x
    _READ_FRAME_TIMEOUT_S``. If a constant drift pushed action_deadline to/above 50, a wedged
    child could hang the full 50s per frame — this guard pins that the outer wrap dominates.
    """
    action_deadline = float(_DEFAULT_ACTION_DEADLINE_SECONDS)
    assert action_deadline < 2 * _READ_FRAME_TIMEOUT_S


def test_worst_case_attempts_fit_the_child_budget() -> None:
    """§17: the SDK-read x attempt-count worst case is bounded by the 20s child budget.

    rev.1 left ``3 x SDK_read(8) + backoff`` unreconciled (3 x 8 + 1.5 = 25.5 > 20). golive's
    per-call ``asyncio.wait_for(remaining_budget)`` (provider_dispatch, Task 5) makes the 20s
    budget a HARD ceiling BY CONSTRUCTION — a late attempt gets the truncated remaining
    budget, never a fresh 8s — so the constants are deliberately NOT changed. This test pins
    the two structural facts that keep that true, PLUS documents WHY the wrap is load-bearing:

    * a SINGLE attempt's SDK read fits the budget with headroom, and
    * the total inter-attempt backoff is a small fraction of the budget;
    * the NAIVE "N fresh 8s attempts + backoff" sum OVERRUNS the budget — precisely why each
      ``provider.complete()`` is wrapped in ``wait_for(remaining_budget)``. If a refactor
      dropped that wrap, this documented overrun would silently become a real ~25s hang.
    """
    sdk_read = _sdk_read_seconds()
    total_backoff = sum(_BACKOFF_BASE_SECONDS * (2**k) for k in range(EXTRACTION_MAX_RETRIES))
    # (a) one attempt's read fits inside the budget with room for the others.
    assert sdk_read < _MAX_TOTAL_WALL_CLOCK_SECONDS
    # (b) total backoff across all retries is a small fraction of the budget.
    assert total_backoff < _MAX_TOTAL_WALL_CLOCK_SECONDS
    # (c) the naive worst case OVERRUNS — so the wait_for(remaining_budget) wrap is what
    # actually holds the ceiling (the last attempt is truncated, not given a fresh read).
    naive_worst_case = (EXTRACTION_MAX_RETRIES + 1) * sdk_read + total_backoff
    assert naive_worst_case > _MAX_TOTAL_WALL_CLOCK_SECONDS
