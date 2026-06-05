"""BreakerResetProposal payload + writer path convention — Task 2 of #171.

Pins the Pydantic shape (ADR-0021 §Decision / spec §2.3) and the writer
path convention (`policies/breaker-resets/<proposal_id>.json`) at the
boundary so a future regression cannot silently land a malformed
proposal in state.git.

The path convention is load-bearing for the dispatcher: the dispatch
loop's HEAD-diff walker keys the discriminator off the path prefix
(``policies/breaker-resets/...`` → ``proposal_type="breaker-reset"``).
A drift between this writer and the dispatcher's path-derivation logic
would silently misroute or skip side-effecting proposals.
"""

from __future__ import annotations

import json
from typing import get_args

import pytest
from pydantic import ValidationError

from alfred.cli._state_git import _on_disk_files_for
from alfred.state.proposal_payloads import (
    BreakerResetProposal,
    PluginGrantProposal,
    StateGitProposalPayload,
)

# ---------------------------------------------------------------------------
# Pydantic shape
# ---------------------------------------------------------------------------


def test_breaker_reset_proposal_classvar_discriminator() -> None:
    """The discriminator is a ClassVar literal — never a model field.

    Mirrors the StateGitProposalPayload contract: the writer reads
    ``type(payload).proposal_type`` rather than an instance attribute
    so an operator (or a malformed test fixture) cannot smuggle a
    mismatched value past the dispatcher.
    """
    assert BreakerResetProposal.proposal_type == "breaker-reset"


def test_breaker_reset_proposal_inherits_from_state_git_proposal_payload() -> None:
    """Subclassing keeps the frozen + extra=forbid + strict invariants."""
    assert issubclass(BreakerResetProposal, StateGitProposalPayload)


def test_breaker_reset_proposal_canonical_construction() -> None:
    """The canonical shape constructs cleanly."""
    payload = BreakerResetProposal(
        component_id="alfred.web-fetch",
        operator_user_id="operator-1",
    )
    assert payload.component_id == "alfred.web-fetch"
    assert payload.operator_user_id == "operator-1"
    assert payload.reason == "operator_initiated"


def test_breaker_reset_proposal_reason_literal_default() -> None:
    """``reason`` is a closed Literal — only ``operator_initiated`` today."""
    annotations = BreakerResetProposal.model_fields["reason"].annotation
    assert get_args(annotations) == ("operator_initiated",)


def test_breaker_reset_proposal_refuses_unknown_reason() -> None:
    """A future reason lands by widening the Literal, not by smuggling."""
    with pytest.raises(ValidationError):
        BreakerResetProposal(
            component_id="alfred.web-fetch",
            operator_user_id="operator-1",
            reason="malicious_value",  # type: ignore[arg-type]
        )


def test_breaker_reset_proposal_refuses_extra_fields() -> None:
    """``extra='forbid'`` inherited from the base; no smuggled fields."""
    with pytest.raises(ValidationError):
        BreakerResetProposal(
            component_id="alfred.web-fetch",
            operator_user_id="operator-1",
            unknown_field="surprise",  # type: ignore[call-arg]
        )


def test_breaker_reset_proposal_is_frozen() -> None:
    """Frozen so forensic log lines do not drift from the on-disk payload."""
    payload = BreakerResetProposal(
        component_id="alfred.web-fetch",
        operator_user_id="operator-1",
    )
    with pytest.raises(ValidationError):
        payload.component_id = "alfred.other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Writer path convention — `_on_disk_files_for` extension
# ---------------------------------------------------------------------------


def test_on_disk_files_for_breaker_reset_emits_policies_breaker_resets_path() -> None:
    """The explicit branch in _on_disk_files_for must land the spec path.

    Spec §2.3 + ADR-0021 §Decision: the path convention is
    ``policies/breaker-resets/<proposal_id>.json``. The dispatch loop
    relies on this prefix to discriminate side-effecting proposals
    from declarative-projection blobs.
    """
    payload = BreakerResetProposal(
        component_id="alfred.web-fetch",
        operator_user_id="operator-1",
    )
    files = _on_disk_files_for(payload, proposal_id="abc123def4567890")
    assert list(files.keys()) == ["policies/breaker-resets/abc123def4567890.json"]


def test_on_disk_files_for_breaker_reset_blob_is_payload_round_trip() -> None:
    """The on-disk blob must round-trip back through the Pydantic model.

    This pins the dispatcher's parse path: the loop reads the JSON
    blob and reconstructs a typed BreakerResetProposal. Drift between
    the writer dump and the dispatcher parse would surface here.
    """
    payload = BreakerResetProposal(
        component_id="alfred.web-fetch",
        operator_user_id="operator-1",
    )
    files = _on_disk_files_for(payload, proposal_id="abc123def4567890")
    blob_json = files["policies/breaker-resets/abc123def4567890.json"]
    parsed = json.loads(blob_json)
    rehydrated = BreakerResetProposal.model_validate(parsed)
    assert rehydrated == payload


def test_on_disk_files_for_plugin_grant_unchanged_by_breaker_reset_branch() -> None:
    """Pin the PluginGrantProposal path so the new branch is additive."""
    payload = PluginGrantProposal(
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
    )
    files = _on_disk_files_for(payload, proposal_id="abc123def4567890")
    assert list(files.keys()) == ["policies/grants/alfred.web-fetch/abc123def4567890.json"]
