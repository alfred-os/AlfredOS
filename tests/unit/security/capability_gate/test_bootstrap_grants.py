"""First-party system bootstrap-grant constant (PR-S4-11b0).

The :data:`FIRST_PARTY_SYSTEM_GRANTS` tuple is the SINGLE source of
truth for the in-tree defences that AlfredOS seeds at boot rather than
routing through the reviewer-gate proposal flow (ADR-0026). Today that
is exactly one row: the system-tier ``security.quarantined.extract``
post-chain DLP subscriber (spec §6.5 / issue #158).

These tests pin:

* the EXACT field values of the one seeded row (drift here would seed
  the wrong grant, or fail to authorise the DLP subscriber the
  :class:`alfred.security.quarantine.QuarantinedExtractor` constructor
  needs);
* the sentinel ``proposal_branch`` that distinguishes a first-party
  seed from an operator-/reviewer-issued grant in the audit graph;
* that the constant is an immutable :class:`tuple` of frozen
  :class:`GrantRow` — a mutable default would let a test (or a runtime
  bug) rewrite the seed set under the gate.
"""

from __future__ import annotations

from alfred.security.capability_gate._bootstrap_grants import (
    FIRST_PARTY_SYSTEM_GRANTS,
)
from alfred.security.capability_gate.policy import GrantRow


def test_first_party_system_grants_is_immutable_tuple_of_grant_rows() -> None:
    assert isinstance(FIRST_PARTY_SYSTEM_GRANTS, tuple)
    assert all(isinstance(g, GrantRow) for g in FIRST_PARTY_SYSTEM_GRANTS)


def test_first_party_system_grants_holds_exactly_the_dlp_subscriber_row() -> None:
    expected = (
        GrantRow(
            plugin_id="alfred.security._extract_dlp_subscriber",
            subscriber_tier="system",
            hookpoint="security.quarantined.extract",
            content_tier=None,
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
    """
    from alfred.security._extract_dlp_subscriber import OutboundDlpExtractSubscriber

    (row,) = FIRST_PARTY_SYSTEM_GRANTS
    assert row.plugin_id == OutboundDlpExtractSubscriber.__call__.__module__
    assert row.hookpoint == "security.quarantined.extract"
    assert row.subscriber_tier == "system"


def test_sentinel_proposal_branch_distinguishes_first_party_seed() -> None:
    for row in FIRST_PARTY_SYSTEM_GRANTS:
        assert row.proposal_branch == "bootstrap:first-party-system"
