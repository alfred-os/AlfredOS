"""P1e (#340): the quarantine timeout hierarchy must stay monotone so a real extraction
is not torn host-side.

NOTE the constants alone do NOT bound the retry loop, and neither does
``asyncio.wait_for``: the SDK read runs in a shielded worker thread
(``anyio.to_thread.run_sync``, ``abandon_on_cancel=False``), so ``wait_for`` cancels and
then awaits it. The true ceiling is the ABSOLUTE per-attempt socket deadline
``dispatch_extraction`` installs via ``source.bind(budget_seconds=remaining)`` — see
``brokered_egress`` and its behavioural tests. This module pins the ARITHMETIC that
mechanism has to satisfy, and the ORDERING, against silent re-inversion. See the PR2b
design spec ``docs/superpowers/specs/2026-07-11-issue-340-pr2b-golive-cutover-design.md``
§4 P1e / §19-A3 / §17.
"""

from alfred.egress.broker_audit import _AUDIT_AWAIT_TIMEOUT_S
from alfred.plugins.web_fetch.constants import _DEFAULT_ACTION_DEADLINE_SECONDS
from alfred.security.quarantine import BROKER_SOCKET_COUNT, EXTRACTION_MAX_RETRIES
from alfred.security.quarantine_child.brokered_egress import _CHILD_SDK_READ_TIMEOUT
from alfred.security.quarantine_child.provider_dispatch import (
    _BACKOFF_BASE_SECONDS,
    _MAX_TOTAL_WALL_CLOCK_SECONDS,
)
from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S
from alfred.security.quarantine_transport import _BROKER_PREAMBLE_TIMEOUT_S


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


def test_broker_preamble_term_nests_inside_the_action_deadline() -> None:
    """§17 (#340 review A7): the per-extraction broker preamble is INSIDE the hierarchy.

    The preamble (``broker_sockets`` + its ``egress.broker.connected`` rows) was the one
    per-extraction term bounded by nothing. Unbounded it sits entirely OUTSIDE this hierarchy:
    under gateway degradation the outer ``action_deadline`` fires mid-preamble and the
    extraction dies as an anonymous deadline kill, so the graceful ``provider_unavailable``
    refusal and the ``egress.broker.refused`` forensic row are never produced.

    The preamble is SEQUENTIAL with the host ``read_frame`` bound, not nested inside it, so
    the invariant is a SUM, not an ordering: both must fit within the outer deadline. Drawn
    from LIVE constants so a drift in any term trips this guard.
    """
    action_deadline = float(_DEFAULT_ACTION_DEADLINE_SECONDS)
    # Success path: the full preamble, then a full-length reply read.
    host_side_worst_case = _BROKER_PREAMBLE_TIMEOUT_S + _READ_FRAME_TIMEOUT_S
    assert host_side_worst_case < action_deadline
    # The preamble must also stay the INNERMOST host-side term — it bounds a step that runs
    # before the child is even asked to work, so it must never rival the child's own budget.
    assert _BROKER_PREAMBLE_TIMEOUT_S < _MAX_TOTAL_WALL_CLOCK_SECONDS


def test_broker_preamble_bound_dominates_its_own_audit_write_budget() -> None:
    """§17: the preamble bound is the EFFECTIVE ceiling for a hung broker audit write.

    ``EgressBrokerAuditor`` bounds each ``append_schema`` at its own
    ``_AUDIT_AWAIT_TIMEOUT_S``, and the preamble awaits ``BROKER_SOCKET_COUNT`` of them. Left
    to compose, ``N x 5s`` would blow any sane preamble budget, so the preamble bound is
    deliberately TIGHTER than a single audit-write bound and preempts it. Documented here
    because it is an inversion of the usual inner-<-outer nesting: a hung audit write now
    surfaces as ``broker_preamble_deadline_exceeded`` rather than the auditor's own
    ``egress.broker.audit_write_timeout``. Both are loud, typed, and fail closed (HARD #7) —
    but a future retune that raised the preamble bound above ``N x _AUDIT_AWAIT_TIMEOUT_S``
    would silently restore the unbounded hot-path stall this guard exists to prevent.
    """
    assert _BROKER_PREAMBLE_TIMEOUT_S < _AUDIT_AWAIT_TIMEOUT_S * BROKER_SOCKET_COUNT


def test_worst_case_attempts_overrun_without_the_shared_socket_deadline() -> None:
    """§17: what the child budget costs if the per-attempt socket deadline ever regresses.

    This test previously asserted that ``asyncio.wait_for(remaining_budget)`` makes the 20s
    budget "a HARD ceiling BY CONSTRUCTION". **That premise was false.** The SDK's blocking
    ``recv`` runs in ``anyio.to_thread.run_sync`` with ``abandon_on_cancel=False``, so
    ``wait_for`` cancels the task and then *awaits* the shielded worker thread until it
    returns on its own — it cannot truncate a provider read at all.

    What holds the ceiling is at the socket layer: ``dispatch_extraction`` passes the
    REMAINING budget to ``source.bind()``, which anchors it as an ABSOLUTE deadline that every
    syscall of that attempt is clamped against (``brokered_egress._BlockingFdStream``). Note
    ``sock.settimeout`` ALONE is not enough either — it is a per-syscall IDLE timeout that
    resets on every byte received, so a slow-drip response is unbounded under it. The
    behavioural proofs live in ``test_brokered_egress_transport.py``
    (``test_read_deadline_is_cumulative_not_per_syscall_idle``) and
    ``test_quarantined_extractor_dispatch.py``
    (``test_each_bind_receives_the_shrinking_remaining_budget``).

    This test pins the ARITHMETIC those mechanisms exist to satisfy, including the concrete
    consequence of losing them.
    """
    sdk_read = _sdk_read_seconds()
    total_backoff = sum(_BACKOFF_BASE_SECONDS * (2**k) for k in range(EXTRACTION_MAX_RETRIES))
    # (a) one attempt's read fits inside the budget with room for the others.
    assert sdk_read < _MAX_TOTAL_WALL_CLOCK_SECONDS
    # (b) total backoff across all retries is a small fraction of the budget.
    assert total_backoff < _MAX_TOTAL_WALL_CLOCK_SECONDS
    # (c) the naive "N fresh 8s attempts + backoff" sum OVERRUNS the child budget, which is
    # why the last attempt must be handed the TRUNCATED remainder rather than a fresh read.
    naive_worst_case = (EXTRACTION_MAX_RETRIES + 1) * sdk_read + total_backoff
    assert naive_worst_case > _MAX_TOTAL_WALL_CLOCK_SECONDS
    # (d) THE CONSEQUENCE, and why this is not merely an efficiency question: that same naive
    # sum also exceeds the HOST's read-frame bound. If the shared deadline regressed, the host
    # would tear the child down BEFORE it could emit the in-budget refusal it was busy
    # producing — the graceful typed refusal is not merely late, it is lost, and the failure
    # surfaces as an anonymous host-side timeout instead (HARD #7).
    assert naive_worst_case > _READ_FRAME_TIMEOUT_S


def test_child_budget_leaves_headroom_for_the_reply_frame() -> None:
    """§17: the child's ceiling must clear the host's read-frame bound by a real margin.

    A child that finishes AT the host's deadline still has to serialise and write its reply
    frame. The gap between the two is the budget for that write (and for scheduler jitter on
    a loaded box), so the two constants must not merely be ordered — they must be apart.
    """
    headroom = _READ_FRAME_TIMEOUT_S - _MAX_TOTAL_WALL_CLOCK_SECONDS
    assert headroom >= 2.0, (
        f"only {headroom}s between the child budget and the host read-frame bound — a child "
        "that uses its full budget may not get its refusal onto the wire"
    )
