"""sec-pr-s3-6-01 — closed-set validators for operator-supplied CLI strings.

Pins the parser-time rejection contract for the four validator helpers
in :mod:`alfred.cli._validators`. Each validator's happy-path acceptance
plus every failure-shape it claims to refuse is exercised here so the
module ships at 100% line + branch coverage (trust-boundary rule from
CLAUDE.md).

The tests intentionally hit the validator functions directly rather than
through the wired CLI commands — those wired surfaces have their own
end-to-end tests in :mod:`tests.unit.cli.test_plugin_cli` /
:mod:`test_web_cli` / :mod:`test_config_cli`. Splitting the coverage this
way keeps the validator suite sub-millisecond and lets us pin each
refusal message's load-bearing structure (the ``BadParameter`` carries
both the localised body AND the ``param_hint``, so a future regression
that drops one would surface only here).
"""

from __future__ import annotations

from collections.abc import Iterable
from unittest.mock import patch

import pytest
import typer

from alfred.cli._validators import (
    SubscriberTier,
    validate_domain,
    validate_hookpoint,
    validate_plugin_id,
    validate_quarantined_provider,
    validate_subscriber_tier,
)

# ---------------------------------------------------------------------------
# validate_plugin_id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "valid",
    [
        "alfred.web-fetch",
        "alfred_comms_test",
        "alfred.memory.episodic",
        "ab",
        "a1.b2",
        "alfred-deepseek",
    ],
)
def test_validate_plugin_id_accepts_canonical_shapes(valid: str) -> None:
    """The regex ``^[a-z][a-z0-9._-]+$`` admits every first-party plugin id."""
    assert validate_plugin_id(valid) == valid


@pytest.mark.parametrize(
    "bad",
    [
        # path traversal — the load-bearing security refusal
        "../../../etc/passwd",
        "../alfred",
        # uppercase / mixed-case
        "Alfred",
        "alfred.WebFetch",
        # whitespace
        "alfred fetch",
        " alfred",
        "alfred ",
        # starts with non-letter
        "1alfred",
        ".alfred",
        "_alfred",
        # too short
        "a",
        # empty
        "",
        # disallowed punctuation
        "alfred/web",
        "alfred:web",
        "alfred@web",
    ],
)
def test_validate_plugin_id_refuses_out_of_set_shapes(bad: str) -> None:
    """Every non-conforming shape raises ``BadParameter`` at parse time."""
    with pytest.raises(typer.BadParameter):
        validate_plugin_id(bad)


def test_validate_plugin_id_bad_parameter_carries_param_hint() -> None:
    """The Typer pretty-printer attaches ``param_hint`` to the rendered message.

    Without the hint the operator's terminal would show ``Error: Invalid …``
    without anchoring it to ``plugin_id`` specifically. Pinning the field
    keeps the operator UX explicit.
    """
    with pytest.raises(typer.BadParameter) as excinfo:
        validate_plugin_id("BAD")
    assert excinfo.value.param_hint == "'plugin_id'"


# ---------------------------------------------------------------------------
# validate_subscriber_tier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("system", SubscriberTier.SYSTEM),
        ("operator", SubscriberTier.OPERATOR),
        ("user-plugin", SubscriberTier.USER_PLUGIN),
    ],
)
def test_validate_subscriber_tier_accepts_known_values(
    value: str, expected: SubscriberTier
) -> None:
    """Each of the three subscriber-capability tiers round-trips."""
    assert validate_subscriber_tier(value) is expected


@pytest.mark.parametrize(
    "bad",
    [
        # Content trust tier strings (T0-T3) belong on the orthogonal axis.
        # Conflating them is exactly the typo the closed-set rejection catches.
        "T0",
        "T1",
        "T2",
        "T3",
        # Out of either set.
        "T4",
        "SYSTEM",
        "user_plugin",  # underscore mismatch — _TIER_RANK has the hyphen form
        "operator ",
        "",
    ],
)
def test_validate_subscriber_tier_refuses_out_of_set(bad: str) -> None:
    """Any string outside the closed set raises ``BadParameter``."""
    with pytest.raises(typer.BadParameter):
        validate_subscriber_tier(bad)


def test_validate_subscriber_tier_bad_parameter_lists_valid_tiers() -> None:
    """The error message enumerates the valid tier set so the operator
    sees the immediate recovery path without consulting docs."""
    with pytest.raises(typer.BadParameter) as excinfo:
        validate_subscriber_tier("T4")
    body = excinfo.value.message
    # All three valid tier names appear so the operator knows the closed set.
    assert "system" in body
    assert "operator" in body
    assert "user-plugin" in body


# ---------------------------------------------------------------------------
# validate_hookpoint
# ---------------------------------------------------------------------------


def _stub_known_hookpoints(names: Iterable[str]) -> object:
    """Build a patch target that returns ``names`` from the seam."""
    return patch(
        "alfred.cli._validators._known_hookpoints_provider",
        lambda: tuple(names),
    )


def test_validate_hookpoint_accepts_registered_name() -> None:
    """A name in the registry returns unchanged."""
    with _stub_known_hookpoints({"plugin.grant.requested", "memory.episodic.before_db_write"}):
        assert validate_hookpoint("plugin.grant.requested") == "plugin.grant.requested"


def test_validate_hookpoint_refuses_unknown_with_close_match_hint() -> None:
    """An unknown name surfaces the difflib-nearest match list."""
    with (
        _stub_known_hookpoints(
            {
                "plugin.grant.requested",
                "plugin.grant.approved",
                "plugin.grant.denied",
                "plugin.grant.revoked",
            }
        ),
        pytest.raises(typer.BadParameter) as excinfo,
    ):
        validate_hookpoint("plugin.grant.requestd")  # missing 'e'
    body = excinfo.value.message
    # The closest match is surfaced so the operator sees the typo fix.
    assert "plugin.grant.requested" in body


def test_validate_hookpoint_refuses_unknown_with_no_close_match_hint() -> None:
    """An entirely-foreign string still raises but says so explicitly.

    The body's ``(no close matches)`` literal anchors the rendering when
    ``difflib.get_close_matches`` returns ``[]`` so the operator does not
    see a confusing empty suggestion list.
    """
    with (
        _stub_known_hookpoints({"plugin.grant.requested"}),
        pytest.raises(typer.BadParameter) as excinfo,
    ):
        validate_hookpoint("xxxxxxxxxxxxxxxx")
    assert "no close matches" in excinfo.value.message


def test_validate_hookpoint_refuses_when_registry_empty() -> None:
    """A degraded fixture with no publishers loaded raises a distinct hint.

    The empty-registry branch lives behind a separate localised key so the
    operator-facing error tells them the registry is empty rather than
    blaming their input.
    """
    with _stub_known_hookpoints(()), pytest.raises(typer.BadParameter) as excinfo:
        validate_hookpoint("plugin.grant.requested")
    assert "empty" in excinfo.value.message.lower()


def test_validate_hookpoint_bad_parameter_carries_param_hint() -> None:
    """``param_hint`` anchors the Typer error to the hookpoint argument."""
    with _stub_known_hookpoints({"x.y.z"}), pytest.raises(typer.BadParameter) as excinfo:
        validate_hookpoint("not-registered")
    assert excinfo.value.param_hint == "'hookpoint'"


def test_validate_hookpoint_default_provider_queries_live_registry() -> None:
    """The default seam reads from ``alfred.hooks.registry.get_registry``.

    This pins the contract that the unpatched validator hits the running
    registry singleton — a future refactor that swaps the seam to a
    stub would silently break production validation without this guard.
    """
    # Re-importing the publisher module is idempotent on equal metadata
    # (HookRegistry.register_hookpoint contract) so the registry is
    # guaranteed to carry the four plugin.grant.* names by the time this
    # test runs.
    import alfred.security.capability_gate.proposals  # noqa: F401
    from alfred.cli._validators import _default_known_hookpoints_provider
    from alfred.hooks.registry import get_registry

    provider = _default_known_hookpoints_provider()
    expected = set(get_registry()._hookpoints)
    assert set(provider) == expected


# ---------------------------------------------------------------------------
# validate_domain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "valid",
    [
        "example.com",
        "api.example.com",
        "static.cdn.example.co",
        "a-b.example.org",
        "x1.y2.example.net",
    ],
)
def test_validate_domain_accepts_bare_lowercase_domain(valid: str) -> None:
    """Bare lowercase domains pass."""
    assert validate_domain(valid) == valid


@pytest.mark.parametrize(
    "bad",
    [
        # operator pasted a URL — distinct localised refusal
        "http://example.com",
        "https://example.com/v1/",
        "ftp://example.com",
    ],
)
def test_validate_domain_refuses_url_with_scheme(bad: str) -> None:
    """A non-empty scheme raises the dedicated localised refusal."""
    with pytest.raises(typer.BadParameter) as excinfo:
        validate_domain(bad)
    # The localised body singles out the scheme refusal so the operator
    # gets a "drop the scheme" hint, not a generic regex failure.
    assert "scheme" in excinfo.value.message.lower()


@pytest.mark.parametrize(
    "bad",
    [
        "../../../etc/passwd",
        "..example.com",
        "example.com/v1",
        "example.com/../etc",
        "example.com\\windows",
    ],
)
def test_validate_domain_refuses_path_traversal(bad: str) -> None:
    """Any ``..`` substring or path separator is refused outright."""
    with pytest.raises(typer.BadParameter):
        validate_domain(bad)


@pytest.mark.parametrize(
    "bad",
    [
        # not a bare domain shape (no TLD, single-label, mixed case)
        "localhost",
        "example",
        "Example.com",
        "example.c",  # TLD too short
        "example.123",  # numeric TLD
        "example.com.",  # trailing dot — regex anchors the TLD at end
        "exa mple.com",  # whitespace
    ],
)
def test_validate_domain_refuses_off_shape(bad: str) -> None:
    """Anything outside the bare-domain regex is refused."""
    with pytest.raises(typer.BadParameter):
        validate_domain(bad)


def test_validate_domain_refuses_empty_string() -> None:
    """Empty input is refused with the generic invalid-domain message."""
    with pytest.raises(typer.BadParameter):
        validate_domain("")


def test_validate_domain_bad_parameter_carries_param_hint() -> None:
    """Each rejection branch anchors ``param_hint='domain'``."""
    with pytest.raises(typer.BadParameter) as excinfo:
        validate_domain("not a domain")
    assert excinfo.value.param_hint == "'domain'"


# ---------------------------------------------------------------------------
# validate_quarantined_provider
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("valid", ["anthropic", "deepseek"])
def test_validate_quarantined_provider_accepts_declared_ids(valid: str) -> None:
    """Both declared provider ids pass."""
    assert validate_quarantined_provider(valid) == valid


@pytest.mark.parametrize(
    "bad",
    [
        # typo on a real provider id
        "anthropc",
        "deepseek ",
        "DeepSeek",
        # path traversal
        "../etc/passwd",
        # an unknown provider id — closed set must refuse silently-novel inputs
        "openai",
        "",
    ],
)
def test_validate_quarantined_provider_refuses_out_of_set(bad: str) -> None:
    """Anything outside the closed set raises ``BadParameter``."""
    with pytest.raises(typer.BadParameter):
        validate_quarantined_provider(bad)


def test_validate_quarantined_provider_lists_valid_providers() -> None:
    """The error message enumerates the closed set so the recovery is obvious."""
    with pytest.raises(typer.BadParameter) as excinfo:
        validate_quarantined_provider("openai")
    body = excinfo.value.message
    assert "anthropic" in body
    assert "deepseek" in body


def test_validate_quarantined_provider_param_hint() -> None:
    """``param_hint`` anchors the error to the value position."""
    with pytest.raises(typer.BadParameter) as excinfo:
        validate_quarantined_provider("openai")
    assert excinfo.value.param_hint == "'value'"
