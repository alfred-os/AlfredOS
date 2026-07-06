"""#339 PR3: the 3 tool-dispatch first-party grants are live on the boot gate,
each verified on its correct axis (subscriber vs content clearance).

These are pure :class:`GatePolicy` tests (no ``RealGate``, no backend) — they
pin that :data:`FIRST_PARTY_SYSTEM_GRANTS` itself carries the coordinates the
production ``dispatch_tool`` / ``quarantined_to_structured`` /
``downgrade_to_orchestrator`` call sites query with. The drift-guard against
the runtime constants (``TOOL_DISPATCH_PLUGIN_ID`` / ``TOOL_DISPATCH_HOOKPOINT``)
lives in ``test_bootstrap_grants.py``; the direct two-branch exercise of
``_first_party_grant_live`` (the daemon boot assertion) lives in
``tests/unit/cli/daemon/test_daemon_quarantine_boot_infra.py``.
"""

from __future__ import annotations

from alfred.security.capability_gate._bootstrap_grants import FIRST_PARTY_SYSTEM_GRANTS
from alfred.security.capability_gate.policy import GatePolicy


def _policy() -> GatePolicy:
    return GatePolicy(grants=frozenset(FIRST_PARTY_SYSTEM_GRANTS))


def test_tool_dispatch_grant_is_live_on_subscriber_axis() -> None:
    assert _policy().check(
        plugin_id="alfred.orchestrator.tool_dispatch",
        hookpoint="tool.dispatch",
        requested_tier="system",
    )


def test_quarantine_dereference_grant_is_live_on_content_axis() -> None:
    assert _policy().check_content_clearance(
        plugin_id="alfred.quarantined-llm",
        hookpoint="quarantine.dereference",
        content_tier="T3",
    )


def test_downgrade_grant_is_live_on_content_axis() -> None:
    assert _policy().check_content_clearance(
        plugin_id="t3.downgrade_to_orchestrator",
        hookpoint="t3.downgrade_to_orchestrator",
        content_tier="T3",
    )
