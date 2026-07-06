"""First-party system bootstrap-grant constant (PR-S4-11b0 / #339 PR3).

The :data:`FIRST_PARTY_SYSTEM_GRANTS` tuple is the SINGLE source of
truth for the in-tree defences that AlfredOS seeds at boot rather than
routing through the reviewer-gate proposal flow (ADR-0026). Four rows
today: the system-tier ``security.quarantined.extract`` post-chain DLP
subscriber (spec §6.5 / issue #158), plus the three #339 PR3
tool-dispatch grants the live agentic tool-dispatch T3 path needs
(``tool.dispatch``, ``quarantine.dereference``,
``t3.downgrade_to_orchestrator``).

These tests pin:

* the EXACT field values of all four seeded rows (drift here would seed
  the wrong grant, or fail to authorise the DLP subscriber the
  :class:`alfred.security.quarantine.QuarantinedExtractor` constructor
  needs, or fail to clear a real turn's tool-dispatch/quarantine
  boundary);
* the sentinel ``proposal_branch`` that distinguishes a first-party
  seed from an operator-/reviewer-issued grant in the audit graph;
* that the constant is an immutable :class:`tuple` of frozen
  :class:`GrantRow` — a mutable default would let a test (or a runtime
  bug) rewrite the seed set under the gate;
* (#339 PR3 drift-guard) that each of the three new rows' coordinates
  match the LITERAL constants the runtime ``dispatch_tool`` /
  ``quarantined_to_structured`` / ``downgrade_to_orchestrator`` call
  sites query the gate with.
"""

from __future__ import annotations

from alfred.security.capability_gate._bootstrap_grants import (
    FIRST_PARTY_SYSTEM_GRANTS,
)
from alfred.security.capability_gate.policy import GrantRow


def test_first_party_system_grants_is_immutable_tuple_of_grant_rows() -> None:
    assert isinstance(FIRST_PARTY_SYSTEM_GRANTS, tuple)
    assert all(isinstance(g, GrantRow) for g in FIRST_PARTY_SYSTEM_GRANTS)


def test_first_party_system_grants_holds_exactly_the_four_seeded_rows() -> None:
    """#339 PR3: the exact-equality drift pin, grown from one row to four.

    A change to ANY field on ANY row — a typo'd hookpoint, a swapped
    content_tier, a wrong plugin_id — fails this test rather than
    silently seeding the wrong grant (CLAUDE.md hard rule #7)."""
    expected = (
        GrantRow(
            plugin_id="alfred.security._extract_dlp_subscriber",
            subscriber_tier="system",
            hookpoint="security.quarantined.extract",
            content_tier=None,
            proposal_branch="bootstrap:first-party-system",
        ),
        GrantRow(
            plugin_id="alfred.orchestrator.tool_dispatch",
            subscriber_tier="system",
            hookpoint="tool.dispatch",
            content_tier=None,
            proposal_branch="bootstrap:first-party-system",
        ),
        GrantRow(
            plugin_id="alfred.quarantined-llm",
            subscriber_tier="system",
            hookpoint="quarantine.dereference",
            content_tier="T3",
            proposal_branch="bootstrap:first-party-system",
        ),
        GrantRow(
            plugin_id="t3.downgrade_to_orchestrator",
            subscriber_tier="system",
            hookpoint="t3.downgrade_to_orchestrator",
            content_tier="T3",
            proposal_branch="bootstrap:first-party-system",
        ),
    )
    assert expected == FIRST_PARTY_SYSTEM_GRANTS


def test_seeded_plugin_id_matches_dlp_subscriber_module() -> None:
    """The seeded plugin_id MUST equal the attribution the production
    helper passes (``OutboundDlpExtractSubscriber.__call__.__module__``).

    A drift between the seed's ``plugin_id`` and the value
    :func:`register_extract_dlp_subscriber` queries the gate with would
    leave the DLP subscriber denied at register time despite a seeded
    grant — the silent half-wired-extractor shape CLAUDE.md hard rule #7
    forbids. Asserting the linkage here pins the two sites together.

    #339 PR3: the constant now holds four rows, so the DLP-subscriber row
    is located by ``plugin_id`` rather than unpacked positionally — a
    single-element-unpack ``(row,) = FIRST_PARTY_SYSTEM_GRANTS`` would
    raise ``ValueError`` at four rows.
    """
    from alfred.security._extract_dlp_subscriber import OutboundDlpExtractSubscriber

    dlp_row = next(
        (
            g
            for g in FIRST_PARTY_SYSTEM_GRANTS
            if g.plugin_id == "alfred.security._extract_dlp_subscriber"
        ),
        None,
    )
    assert dlp_row is not None, "DLP subscriber row missing from FIRST_PARTY_SYSTEM_GRANTS"
    assert dlp_row.plugin_id == OutboundDlpExtractSubscriber.__call__.__module__
    assert dlp_row.hookpoint == "security.quarantined.extract"
    assert dlp_row.subscriber_tier == "system"


def test_seeded_tool_dispatch_grants_match_runtime_query_coordinates() -> None:
    """#339 PR3 drift-guard (FIX-8): the three new rows' coordinates match
    the LITERAL constants/values the runtime call sites query the gate
    with — ``dispatch_tool`` (``alfred.orchestrator.tool_dispatch.py``),
    ``quarantined_to_structured`` and ``downgrade_to_orchestrator`` (both
    in ``alfred.security.quarantine``).

    Mirrors :func:`test_seeded_plugin_id_matches_dlp_subscriber_module`'s
    pattern for the DLP row: a drift here would leave a live turn's tool
    dispatch or quarantine-downgrade denied at a gate boundary despite a
    seeded grant — the silent half-wired-dispatch shape CLAUDE.md hard
    rule #7 forbids.
    """
    from alfred.orchestrator.tool_hookpoints import (
        TOOL_DISPATCH_HOOKPOINT,
        TOOL_DISPATCH_PLUGIN_ID,
    )

    by_hookpoint = {g.hookpoint: g for g in FIRST_PARTY_SYSTEM_GRANTS}

    # dispatch_tool: gate.check(plugin_id=TOOL_DISPATCH_PLUGIN_ID,
    #   hookpoint=TOOL_DISPATCH_HOOKPOINT, requested_tier="system").
    tool_dispatch = by_hookpoint[TOOL_DISPATCH_HOOKPOINT]
    assert tool_dispatch.plugin_id == TOOL_DISPATCH_PLUGIN_ID
    assert tool_dispatch.subscriber_tier == "system"
    assert tool_dispatch.content_tier is None

    # quarantined_to_structured: gate.check_content_clearance(
    #   plugin_id="alfred.quarantined-llm",
    #   hookpoint="quarantine.dereference", content_tier="T3").
    dereference = by_hookpoint["quarantine.dereference"]
    assert dereference.plugin_id == "alfred.quarantined-llm"
    assert dereference.content_tier == "T3"

    # downgrade_to_orchestrator: gate.check_content_clearance(
    #   plugin_id="t3.downgrade_to_orchestrator",
    #   hookpoint="t3.downgrade_to_orchestrator", content_tier="T3").
    downgrade = by_hookpoint["t3.downgrade_to_orchestrator"]
    assert downgrade.plugin_id == "t3.downgrade_to_orchestrator"
    assert downgrade.content_tier == "T3"


def test_sentinel_proposal_branch_distinguishes_first_party_seed() -> None:
    for row in FIRST_PARTY_SYSTEM_GRANTS:
        assert row.proposal_branch == "bootstrap:first-party-system"
