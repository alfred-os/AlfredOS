"""TUI end-to-end smoke test — AWAITING Component D launcher-spawn rewrite.

History
-------

Through Slice 2/3 this file drove the in-process :class:`AlfredTuiApp`
(Textual) via ``app.run_test()`` + ``Pilot`` against a real Postgres
testcontainer and the real Orchestrator / WorkingMemoryPool / BudgetGuard
/ IdentityResolver. That worked because the TUI lived in-process at
``alfred.comms.tui``.

PR-S4-10 (the TUI flag-day) deleted ``src/alfred/comms/``: the TUI is now
the out-of-process MCP plugin at ``plugins/alfred_tui/``, launched through
``bin/alfred-plugin-launcher.sh`` and spoken to over the stdio MCP
transport. The in-process ``app.run_test()`` driver no longer has an
``AlfredTuiApp`` to import, so the Slice-2 harness cannot survive the
deletion unchanged.

The replacement is a launcher-spawn end-to-end smoke: spawn the plugin via
the launcher, complete the MCP plugin handshake, drive one operator turn
over a stdio MCP round-trip against the real orchestrator-backed stack, and
assert the same persistence invariants (episode pair, audit row shape,
budget movement, slice-1 rehydrate cadence) the in-process harness pinned.

That rewrite is scheduled for **Component D** of PR-S4-10 (Windows
redirect + smoke graduation + integration gates) — it needs the launcher
contract and the plugin-handshake fixtures that Component D introduces, and
landing a half-built spawn harness inside the irreversible deletion commit
(Component C) would risk flake on the slice's most safety-critical step.

Until Component D lands, this module is a skip-guarded stub: it imports
nothing from the deleted ``alfred.comms`` package and reports SKIPPED
(never PASSED) so the smoke layer's skip-vs-pass discipline holds and the
gap stays visible in the test report.

TODO(Component D): replace this stub with the launcher-spawn + MCP-handshake
+ stdio-round-trip e2e described above. Re-pin the four Slice-2 invariants:
  1. mock-provider round trip → episode pair + audit row (seven-branch
     shape, T1 trigger tier, language tag) + per-user budget movement;
  2. real-provider round trip gated on ``ALFRED_SMOKE_PROVIDER_KEY``;
  3. slice-1 rehydrate cadence across two consecutive plugin sessions
     sharing one testcontainer Postgres.
The Slice-2 assertions are preserved in git history at the commit prior to
PR-S4-10's deletion of ``src/alfred/comms/`` for the rewrite to port.
"""

from __future__ import annotations

import pytest

# Component D will replace this whole module with the launcher-spawn e2e.
# A module-level skip keeps the smoke layer honest (SKIPPED, never PASSED)
# without importing the deleted in-process TUI app.
pytestmark = pytest.mark.skip(
    reason=(
        "TUI e2e smoke awaits the Component D launcher-spawn rewrite — the "
        "in-process alfred.comms.tui driver was deleted in PR-S4-10 and the "
        "out-of-process plugins/alfred_tui/ MCP harness lands in Component D. "
        "See this module's docstring TODO(Component D)."
    )
)


@pytest.mark.smoke
def test_tui_e2e_pending_component_d_launcher_spawn() -> None:
    """Placeholder for the Component D launcher-spawn TUI e2e.

    Skipped at module level. Present so the smoke report names the gap
    explicitly rather than silently dropping TUI e2e coverage between the
    Component C deletion and the Component D rewrite.
    """
    pytest.fail("unreachable — module-level skip applies")  # pragma: no cover
