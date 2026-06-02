"""CR-149 round-10 (3339361798) — field-shape refusal at the canonical writer boundary.

ADR-0018 anchors the proposal payloads as the writer boundary. Before
this regression the models accepted unconstrained strings for
``plugin_id``, ``hookpoint``, ``domain``, and the ``quarantined-provider``
config value, so a non-CLI producer (a future async writer, a state.git
replay tool, a malformed test fixture) could land malformed values in
state.git that the CLI's parse-time validators would have refused.

These tests pin the closed shapes at the model layer so every producer
gets the same refusal semantics before the proposal hits disk.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alfred.state.proposal_payloads import (
    ConfigSetProposal,
    PluginGrantProposal,
    PluginRevokeProposal,
    WebAllowlistProposal,
)

# ---------------------------------------------------------------------------
# PluginGrantProposal / PluginRevokeProposal — plugin_id closed shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "plugin_id",
    [
        # path traversal — must never reach the on-disk path
        "../../../etc/passwd",
        # path separator inside the id
        "alfred/web-fetch",
        # uppercase — registry normalises to lowercase, refuse at boundary
        "Alfred.web-fetch",
        # trailing separator
        "alfred-",
        # leading dot
        ".alfred",
        # consecutive dots
        "alfred..web",
        # empty
        "",
    ],
)
def test_plugin_grant_proposal_refuses_malformed_plugin_id(plugin_id: str) -> None:
    """Pydantic ValidationError fires at the model boundary, not later."""
    with pytest.raises(ValidationError):
        PluginGrantProposal(
            plugin_id=plugin_id,
            subscriber_tier="operator",
            hookpoint="tool.web.fetch",
            content_tier=None,
        )


def test_plugin_grant_proposal_accepts_canonical_plugin_id() -> None:
    """The first-party plugin id shape passes the validator."""
    payload = PluginGrantProposal(
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint="tool.web.fetch",
        content_tier=None,
    )
    assert payload.plugin_id == "alfred.web-fetch"


def test_plugin_revoke_proposal_refuses_malformed_plugin_id() -> None:
    """Mirror of the grant-side refusal — both families share semantics."""
    with pytest.raises(ValidationError):
        PluginRevokeProposal(plugin_id="../../etc/passwd")


# ---------------------------------------------------------------------------
# PluginGrantProposal — hookpoint closed shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hookpoint",
    [
        # path traversal
        "../tool.web.fetch",
        # path separator
        "tool/web/fetch",
        # whitespace
        "tool web fetch",
        # trailing separator
        "tool.web-",
        # leading dot
        ".tool",
        # consecutive dots
        "tool..fetch",
        # empty
        "",
    ],
)
def test_plugin_grant_proposal_refuses_malformed_hookpoint(hookpoint: str) -> None:
    with pytest.raises(ValidationError):
        PluginGrantProposal(
            plugin_id="alfred.web-fetch",
            subscriber_tier="operator",
            hookpoint=hookpoint,
            content_tier=None,
        )


def test_plugin_grant_proposal_accepts_wildcard_hookpoint() -> None:
    """The ``*`` wildcard anchors a plugin-load grant (every hookpoint)."""
    payload = PluginGrantProposal(
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint="*",
        content_tier=None,
    )
    assert payload.hookpoint == "*"


@pytest.mark.parametrize(
    "hookpoint",
    [
        "tool.web.fetch",  # canonical lowercase
        "t3.downgrade_to_orchestrator",  # snake_case + leading-digit segment
        "tag.T3",  # tier-tagged hookpoint used by the round-trip suite
        "quarantine.dereference",
    ],
)
def test_plugin_grant_proposal_accepts_real_hookpoint_shapes(hookpoint: str) -> None:
    """Every production-shape hookpoint round-trips through the validator."""
    payload = PluginGrantProposal(
        plugin_id="alfred.web-fetch",
        subscriber_tier="operator",
        hookpoint=hookpoint,
        content_tier=None,
    )
    assert payload.hookpoint == hookpoint


# ---------------------------------------------------------------------------
# WebAllowlistProposal — domain closed shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    [
        # URL paste (scheme + path)
        "https://example.com/v1",
        # path-traversal
        "../etc/passwd",
        # path separator embedded
        "example.com/v1",
        # consecutive dots (empty label)
        "example..com",
        # leading hyphen label
        "-foo.com",
        # trailing hyphen label
        "foo-.com",
        # missing TLD
        "example",
        # uppercase
        "Example.com",
        # empty
        "",
    ],
)
def test_web_allowlist_proposal_refuses_malformed_domain(domain: str) -> None:
    with pytest.raises(ValidationError):
        WebAllowlistProposal(
            action="add",
            domain=domain,
        )


def test_web_allowlist_proposal_accepts_canonical_domain() -> None:
    payload = WebAllowlistProposal(action="add", domain="example.com")
    assert payload.domain == "example.com"
    # CR-149 round-6 default — add path defaults to "/" via model_validator.
    assert payload.path_prefix == "/"


# ---------------------------------------------------------------------------
# ConfigSetProposal — quarantined-provider closed set
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "openai",  # not in the declared set today
        "Anthropic",  # case-sensitive — closed set holds lowercase only
        "",
    ],
)
def test_config_set_proposal_refuses_unknown_quarantined_provider(value: str) -> None:
    with pytest.raises(ValidationError):
        ConfigSetProposal(
            config_key="quarantined-provider",
            value=value,
        )


@pytest.mark.parametrize("value", ["anthropic", "deepseek"])
def test_config_set_proposal_accepts_declared_quarantined_provider(value: str) -> None:
    payload = ConfigSetProposal(
        config_key="quarantined-provider",
        value=value,
    )
    assert payload.value == value
