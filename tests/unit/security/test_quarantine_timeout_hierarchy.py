"""P1e (#340): the quarantine timeout hierarchy must stay monotone so a real extraction
is not torn host-side. NOTE the constants alone do NOT bound the retry loop — golive's
per-call ``asyncio.wait_for(remaining_budget)`` makes the budget the true ceiling; this
guard only pins the ORDERING against silent re-inversion. See the PR2b design spec
``docs/superpowers/specs/2026-07-11-issue-340-pr2b-golive-cutover-design.md`` §4 P1e / §19-A3.
"""

from alfred.plugins.web_fetch.constants import _DEFAULT_ACTION_DEADLINE_SECONDS
from alfred.security.quarantine_child.provider_dispatch import _MAX_TOTAL_WALL_CLOCK_SECONDS
from alfred.security.quarantine_child_io import _READ_FRAME_TIMEOUT_S


def test_timeout_hierarchy_is_monotone() -> None:
    # The action deadline is the operator-tunable OUTER bound the web_fetch dispatcher
    # enforces via asyncio.timeout(action_deadline_seconds); derive it from that constant
    # (not a hardcoded 30) so a default change — or a re-inversion of the two lower module
    # constants — trips this guard. (An operator override BELOW the code constants is a
    # config-misconfiguration a unit guard can't catch; this pins the code-level ordering.)
    action_deadline = float(_DEFAULT_ACTION_DEADLINE_SECONDS)
    # Strict monotone: action_deadline > host read-frame > child wall-clock budget. The 4th
    # term (child SDK read <= budget) is injected by PR2b-golive via from_settings.
    assert action_deadline > _READ_FRAME_TIMEOUT_S > _MAX_TOTAL_WALL_CLOCK_SECONDS
