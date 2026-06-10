"""``comms_adapter_load_grants`` builder unit coverage (PR-S4-11b / ADR-0027).

The builder derives ONE plugin-LOAD grant per operator-enabled first-party
comms adapter so the adapter's manifest-tier handshake
(:meth:`alfred.security.capability_gate.policy.GatePolicy.check_plugin_load`)
clears at boot — exactly parallel to ADR-0026's static
:data:`FIRST_PARTY_SYSTEM_GRANTS` DLP seed, but config-sourced because the
enabled set is operator-chosen (reviewer-gated deployment config).

Config-is-authorization for FIRST-PARTY adapters: the
``comms_enabled_adapters`` Settings validator already PROVES every entry
names a real in-repo ``plugins/<id>/manifest.toml`` (path-charset checked,
file-exists checked), so the only thing this builder adds is a real grant
ROW the gate then evaluates normally. The gate is NEVER special-cased to
"trust first-party by name" — the seed lands a row, the same hot-path
``check`` evaluates it (mirrors ADR-0026's anti-pattern guard).

Driver-free unit tier: the builder is a PURE ``Settings -> tuple[GrantRow]``
transform reading source-controlled manifests off disk; no Postgres, no
gate.
"""

from __future__ import annotations

import pytest

from alfred.config.settings import Settings, SettingsError
from alfred.plugins.errors import CommsAdapterSystemTierError, ManifestError
from alfred.security.capability_gate._comms_adapter_grants import (
    _COMMS_ADAPTER_PROPOSAL_BRANCH,
    comms_adapter_load_grants,
)

# The reference adapter the substrate + smoke tests enable. Its dir name
# (``alfred_comms_test``) is the Settings/``comms_enabled_adapters`` entry;
# its manifest ``[plugin] id`` (``alfred.comms-test``) is the gate plugin_id
# the load grant MUST carry — the two are deliberately distinct (dir uses
# underscores, plugin id uses a dot). This test pins that the grant carries
# the MANIFEST id, not the dir id.
_ENABLED_ADAPTER = "alfred_comms_test"
_MANIFEST_PLUGIN_ID = "alfred.comms-test"
_MANIFEST_SUBSCRIBER_TIER = "user-plugin"


def _settings_with_adapters(*adapter_ids: str) -> Settings:
    """Construct ``Settings`` with the given comms adapters enabled.

    A non-placeholder ``deepseek_api_key`` + an explicit ``environment`` are
    required for construction; the rest default. The
    ``comms_enabled_adapters`` validator runs here, so a bad adapter id
    raises ``SettingsError`` before the builder is reached.
    """
    return Settings(
        environment="test",
        deepseek_api_key="not-a-real-secret-unit-test-placeholder",
        comms_enabled_adapters=adapter_ids,
    )


def test_builder_empty_for_default_empty_config() -> None:
    """Default-empty ``comms_enabled_adapters`` yields NO grants.

    A default daemon boot seeds only the static first-party grants — the
    comms-adapter seed is purely additive and contributes nothing unless an
    operator opted an adapter in.
    """
    settings = _settings_with_adapters()
    assert comms_adapter_load_grants(settings) == ()


def test_builder_one_load_grant_for_enabled_adapter() -> None:
    """One enabled adapter -> exactly one wildcard plugin-load grant.

    The grant's ``plugin_id`` is the manifest ``[plugin] id`` (the launcher
    plugin id the handshake's ``check_plugin_load`` queries), the
    ``subscriber_tier`` is the manifest's declared tier, ``hookpoint`` is
    the ``"*"`` wildcard a plugin-load grant uses, and ``content_tier`` is
    ``None`` (subscriber-axis grant, not a content clearance).
    """
    settings = _settings_with_adapters(_ENABLED_ADAPTER)

    grants = comms_adapter_load_grants(settings)

    assert len(grants) == 1
    grant = grants[0]
    assert grant.plugin_id == _MANIFEST_PLUGIN_ID
    assert grant.subscriber_tier == _MANIFEST_SUBSCRIBER_TIER
    assert grant.hookpoint == "*"
    assert grant.content_tier is None


def test_builder_uses_distinct_bootstrap_sentinel_branch() -> None:
    """The grant carries the comms-adapter bootstrap sentinel branch.

    Distinct from ADR-0026's ``bootstrap:first-party-system`` so an
    audit-graph query can tell a config-sourced comms-adapter load grant
    apart from the static DLP-subscriber grant AND from an operator/reviewer
    proposal grant.
    """
    settings = _settings_with_adapters(_ENABLED_ADAPTER)

    (grant,) = comms_adapter_load_grants(settings)

    assert grant.proposal_branch == _COMMS_ADAPTER_PROPOSAL_BRANCH
    assert _COMMS_ADAPTER_PROPOSAL_BRANCH == "bootstrap:first-party-comms-adapter"
    assert _COMMS_ADAPTER_PROPOSAL_BRANCH != "bootstrap:first-party-system"


def test_builder_preserves_enabled_order_for_multiple_adapters() -> None:
    """Two enabled adapters -> one grant each, in enumeration order.

    Enabling the same reference adapter twice would be rejected by the
    Settings validator? No — the validator allows repeats; but the daemon
    enables a SET of distinct ids. We pin that each enabled id maps to its
    own grant by enumerating the reference adapter alongside the discord
    adapter, both first-party in-repo.
    """
    settings = _settings_with_adapters(_ENABLED_ADAPTER, "alfred_discord")

    grants = comms_adapter_load_grants(settings)

    assert [g.plugin_id for g in grants] == [_MANIFEST_PLUGIN_ID, "alfred.discord"]


def test_builder_fails_closed_on_unparseable_manifest(tmp_path, monkeypatch) -> None:
    """A broken manifest for an enabled adapter raises, never seeds-nothing.

    The Settings validator guarantees the manifest FILE exists, but not that
    it parses. A corrupt manifest at the builder must surface loudly (refuse
    boot) rather than silently dropping the grant for an adapter the operator
    believes is enabled (CLAUDE.md hard rule #7).
    """
    from alfred.plugins.errors import ManifestError

    bad_root = tmp_path / "repo"
    (bad_root / "plugins" / _ENABLED_ADAPTER).mkdir(parents=True)
    (bad_root / "plugins" / _ENABLED_ADAPTER / "manifest.toml").write_text(
        "this is = = not valid toml ["
    )
    monkeypatch.setattr(
        "alfred.security.capability_gate._comms_adapter_grants._REPO_ROOT", bad_root
    )

    # Build a Settings whose validator we bypass for the manifest-exists check
    # by pointing the BUILDER's repo root at the broken tree. The validator
    # ran against the real repo at construction, so use a real enabled id.
    settings = _settings_with_adapters(_ENABLED_ADAPTER)

    with pytest.raises(ManifestError):
        comms_adapter_load_grants(settings)


def test_builder_fails_closed_on_missing_manifest_file(tmp_path, monkeypatch) -> None:
    """A missing manifest file at the builder's repo root raises loudly.

    Belt-and-braces: even though the Settings validator proved the file
    existed at construction, a builder pointed at a tree without it must NOT
    silently skip the grant.
    """
    empty_root = tmp_path / "empty_repo"
    (empty_root / "plugins").mkdir(parents=True)
    monkeypatch.setattr(
        "alfred.security.capability_gate._comms_adapter_grants._REPO_ROOT", empty_root
    )

    settings = _settings_with_adapters(_ENABLED_ADAPTER)

    with pytest.raises((FileNotFoundError, SettingsError, OSError)):
        comms_adapter_load_grants(settings)


def _write_manifest_with_tier(repo_root, adapter_id: str, *, tier: str) -> None:
    """Write a minimal-but-valid comms manifest declaring ``subscriber_tier``.

    Mirrors ``plugins/<id>/manifest.toml`` shape closely enough that
    ``parse_manifest`` accepts everything EXCEPT the tier under test, so the
    tier-ceiling refusal is the sole reason a build fails.
    """
    adapter_dir = repo_root / "plugins" / adapter_id
    adapter_dir.mkdir(parents=True, exist_ok=True)
    (adapter_dir / "manifest.toml").write_text(
        "\n".join(
            (
                "alfred.manifest_version = 1",
                "[plugin]",
                f'id = "alfred.comms-{adapter_id}"',
                f'subscriber_tier = "{tier}"',
                'sandbox_profile = "user-plugin"',
                "[sandbox]",
                'kind = "none"',
                "[comms_mcp]",
                f'adapter_kind = "{adapter_id}"',
                "classifiers_optional = []",
                f'module = "{adapter_id}.main"',
                "",
            )
        ),
        encoding="utf-8",
    )


def test_builder_refuses_system_tier_comms_adapter(tmp_path, monkeypatch) -> None:
    """A comms manifest declaring ``subscriber_tier="system"`` REFUSES the build.

    FIX 1 (PR-S4-11b review BLOCKER): config-is-authorization (ADR-0027
    Decision 6) was reasoned around ``operator`` / ``user-plugin`` adapters.
    A comms manifest declaring ``system`` would otherwise auto-receive a
    ``system``-tier wildcard load grant from config alone — a privilege jump
    (self-escalation to the OS trust tier) that rides the boot seed. A comms
    adapter is ``operator`` or ``user-plugin`` BY CONSTRUCTION; ``system`` is
    not a comms-adapter posture, so the builder fails closed with a dedicated
    ``CommsAdapterSystemTierError`` (a ``ManifestError`` subclass, so the boot
    catch maps it to the audited ``boot_infra_install_failed`` refusal).
    """
    repo_root = tmp_path / "repo"
    _write_manifest_with_tier(repo_root, _ENABLED_ADAPTER, tier="system")
    monkeypatch.setattr(
        "alfred.security.capability_gate._comms_adapter_grants._REPO_ROOT", repo_root
    )
    settings = _settings_with_adapters(_ENABLED_ADAPTER)

    with pytest.raises(CommsAdapterSystemTierError) as excinfo:
        comms_adapter_load_grants(settings)

    # Dedicated leaf, but caught by the manifest-family boot ``except``.
    assert isinstance(excinfo.value, ManifestError)
    assert excinfo.value.adapter_id == _ENABLED_ADAPTER


@pytest.mark.parametrize("tier", ["operator", "user-plugin"])
def test_builder_allows_operator_and_user_plugin_tiers(tmp_path, monkeypatch, tier: str) -> None:
    """``operator`` + ``user-plugin`` comms adapters are seeded normally.

    The tier ceiling REFUSES only ``system``; the two legitimate comms-adapter
    postures still produce exactly one wildcard load grant carrying the
    manifest tier.
    """
    repo_root = tmp_path / "repo"
    _write_manifest_with_tier(repo_root, _ENABLED_ADAPTER, tier=tier)
    monkeypatch.setattr(
        "alfred.security.capability_gate._comms_adapter_grants._REPO_ROOT", repo_root
    )
    settings = _settings_with_adapters(_ENABLED_ADAPTER)

    (grant,) = comms_adapter_load_grants(settings)

    assert grant.subscriber_tier == tier
    assert grant.hookpoint == "*"
