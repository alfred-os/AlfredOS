"""PluginManifest validation — PR-S3-3a Task 3 (spec §4.3, ADR-0017 Decision 7).

Two-axis naming rule (spec §4.3):

* ``subscriber_tier`` is a subscriber capability declaration; the closed
  vocabulary is ``{system, operator, user-plugin}``. The orchestrator's
  capability gate consults this value to decide which grants the plugin
  may request.
* The content trust tier (T0/T1/T2/T3) is a property of the *content*
  flowing through ``TaggedContent`` and audit rows — never a property of
  the plugin itself.

Conflating the two axes is the classic shape of a tier-laundering bug, so
the manifest parser refuses any T0-T3 string in ``subscriber_tier`` at
handshake (arch-007 fix).

``alfred.manifest_version`` is pinned to ``1`` (ADR-0017 Decision 7). The
``Literal[1]`` annotation gives mypy the same view; the runtime check
raises :class:`ManifestVersionError` before any capability-gate work.

The ``[plugin] platform`` field is reserved for Slice-4 comms-MCP and is
optional in v1. Including or omitting it is valid; non-string values are
not.
"""

from __future__ import annotations

import pytest

from alfred.plugins.errors import ManifestError, ManifestTierError, ManifestVersionError
from alfred.plugins.manifest import parse_manifest

# ---------------------------------------------------------------------------
# Canonical valid manifest — every test starts from this and perturbs one
# field. Keeping the baseline in one place stops "tested-the-wrong-field"
# regressions.
# ---------------------------------------------------------------------------

VALID_MANIFEST_TOML = """\
[alfred]
manifest_version = 1

[plugin]
id = "alfred.test-plugin"
subscriber_tier = "system"
sandbox_profile = "user-plugin"
"""


# ---------------------------------------------------------------------------
# Happy path.
# ---------------------------------------------------------------------------


def test_valid_manifest_parses() -> None:
    manifest = parse_manifest(VALID_MANIFEST_TOML)
    assert manifest.plugin_id == "alfred.test-plugin"
    assert manifest.manifest_version == 1
    assert manifest.subscriber_tier == "system"
    assert manifest.sandbox_profile == "user-plugin"


def test_pluginmanifest_is_frozen() -> None:
    # Frozen so the orchestrator cannot mutate the manifest between
    # capability-gate check and audit-log emission.
    import pydantic

    manifest = parse_manifest(VALID_MANIFEST_TOML)
    with pytest.raises(pydantic.ValidationError):
        manifest.subscriber_tier = "operator"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Manifest version pin (ADR-0017 Decision 7).
# ---------------------------------------------------------------------------


def test_version_mismatch_raises() -> None:
    bad = VALID_MANIFEST_TOML.replace("manifest_version = 1", "manifest_version = 2")
    with pytest.raises(ManifestVersionError) as exc_info:
        parse_manifest(bad)
    assert exc_info.value.got == 2


def test_unknown_manifest_version_same_as_mismatch() -> None:
    bad = VALID_MANIFEST_TOML.replace("manifest_version = 1", "manifest_version = 99")
    with pytest.raises(ManifestVersionError):
        parse_manifest(bad)


def test_missing_manifest_version_raises() -> None:
    bad = VALID_MANIFEST_TOML.replace("manifest_version = 1\n", "")
    with pytest.raises(ManifestVersionError):
        parse_manifest(bad)


def test_string_manifest_version_raises() -> None:
    # A string value (e.g. "1.0") is not the integer 1 — refuse.
    bad = VALID_MANIFEST_TOML.replace("manifest_version = 1", 'manifest_version = "1"')
    with pytest.raises(ManifestVersionError):
        parse_manifest(bad)


def test_version_error_is_catchable_as_manifest_error() -> None:
    bad = VALID_MANIFEST_TOML.replace("manifest_version = 1", "manifest_version = 2")
    with pytest.raises(ManifestError):
        parse_manifest(bad)


# ---------------------------------------------------------------------------
# subscriber_tier closed vocabulary — T3 as subscriber_tier is refused.
# arch-007 fix: distinct from version mismatch.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("forbidden_tier", ["T0", "T1", "T2", "T3"])
def test_content_trust_tier_as_subscriber_tier_refused(forbidden_tier: str) -> None:
    bad = VALID_MANIFEST_TOML.replace(
        'subscriber_tier = "system"', f'subscriber_tier = "{forbidden_tier}"'
    )
    with pytest.raises(ManifestTierError) as exc_info:
        parse_manifest(bad)
    assert exc_info.value.tier == forbidden_tier


def test_unknown_subscriber_tier_refused() -> None:
    bad = VALID_MANIFEST_TOML.replace('subscriber_tier = "system"', 'subscriber_tier = "root"')
    with pytest.raises(ManifestError):
        parse_manifest(bad)


@pytest.mark.parametrize("valid_tier", ["system", "operator", "user-plugin"])
def test_all_valid_subscriber_tiers_accepted(valid_tier: str) -> None:
    src = VALID_MANIFEST_TOML.replace(
        'subscriber_tier = "system"', f'subscriber_tier = "{valid_tier}"'
    )
    manifest = parse_manifest(src)
    assert manifest.subscriber_tier == valid_tier


# ---------------------------------------------------------------------------
# [plugin] platform — reserved for Slice 4.
# ---------------------------------------------------------------------------


def test_platform_field_is_optional_in_v1() -> None:
    manifest = parse_manifest(VALID_MANIFEST_TOML)
    assert manifest.platform is None


def test_platform_field_accepted_when_provided() -> None:
    src = VALID_MANIFEST_TOML + '\nplatform = "discord"\n'
    manifest = parse_manifest(src)
    assert manifest.platform == "discord"


# ---------------------------------------------------------------------------
# Plugin id presence — empty / missing is a structural error.
# ---------------------------------------------------------------------------


def test_missing_plugin_id_raises() -> None:
    bad = VALID_MANIFEST_TOML.replace('id = "alfred.test-plugin"\n', "")
    with pytest.raises(ManifestError):
        parse_manifest(bad)


# ---------------------------------------------------------------------------
# Structural errors — bad TOML, missing [plugin] table, wrong types.
# ---------------------------------------------------------------------------


def test_malformed_toml_raises_manifest_error() -> None:
    with pytest.raises(ManifestError):
        parse_manifest("[plugin\nid = ")


def test_missing_plugin_table_raises_manifest_error() -> None:
    # Only the [alfred] section, no [plugin] table at all.
    with pytest.raises(ManifestError):
        parse_manifest("[alfred]\nmanifest_version = 1\n")


def test_subscriber_tier_not_string_raises_manifest_error() -> None:
    bad = VALID_MANIFEST_TOML.replace('subscriber_tier = "system"', "subscriber_tier = 5")
    with pytest.raises(ManifestError):
        parse_manifest(bad)


def test_sandbox_profile_not_string_raises_manifest_error() -> None:
    bad = VALID_MANIFEST_TOML.replace('sandbox_profile = "user-plugin"', "sandbox_profile = 42")
    with pytest.raises(ManifestError):
        parse_manifest(bad)


def test_platform_not_string_raises_manifest_error() -> None:
    src = VALID_MANIFEST_TOML + "platform = 7\n"
    with pytest.raises(ManifestError):
        parse_manifest(src)


# ---------------------------------------------------------------------------
# Direct PluginManifest construction (bypassing parse_manifest) still
# triggers the subscriber_tier field validator — defence in depth.
# ---------------------------------------------------------------------------


def test_direct_construction_t3_subscriber_tier_refused() -> None:
    # Pydantic v2 propagates non-ValidationError exceptions raised in
    # field_validators as-is — so the defence-in-depth path surfaces the
    # same ManifestTierError as parse_manifest.
    from alfred.plugins.manifest import PluginManifest

    with pytest.raises(ManifestTierError):
        PluginManifest(
            manifest_version=1,
            plugin_id="alfred.x",
            subscriber_tier="T3",
            sandbox_profile="user-plugin",
        )


def test_direct_construction_unknown_subscriber_tier_refused() -> None:
    from alfred.plugins.manifest import PluginManifest

    with pytest.raises(ManifestError):
        PluginManifest(
            manifest_version=1,
            plugin_id="alfred.x",
            subscriber_tier="root",
            sandbox_profile="user-plugin",
        )
