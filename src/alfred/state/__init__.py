"""``alfred.state`` — typed payload models for the state.git reviewer-gate flow.

ADR-0018 establishes :class:`StateGitProposalPayload` as the typed contract
between operator-facing proposal producers (the CLI, the proposal-flow
async path) and the canonical writer
(:class:`alfred.cli._state_git.StateGitProposalClient`). Models live here
— outside both ``alfred.cli`` and ``alfred.security`` — because both
subsystems consume them: anchoring the package under either would
introduce a reverse-direction import.
"""

from __future__ import annotations

from alfred.state.proposal_payloads import (
    ConfigSetProposal,
    PluginGrantProposal,
    PluginRevokeProposal,
    StateGitProposalPayload,
    WebAllowlistProposal,
)

__all__ = [
    "ConfigSetProposal",
    "PluginGrantProposal",
    "PluginRevokeProposal",
    "StateGitProposalPayload",
    "WebAllowlistProposal",
]
