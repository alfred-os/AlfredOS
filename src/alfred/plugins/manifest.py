"""Plugin manifest parser (spec §4.3, ADR-0017 Decision 7).

Slice-3 manifests use TOML. ``alfred.manifest_version`` is pinned to ``1``;
any other value (including string ``"1"``) raises
:class:`alfred.plugins.errors.ManifestVersionError` before any
capability-gate work.

Two-axis naming rule (spec §4.3):

* ``subscriber_tier`` is a *subscriber capability* declaration — closed
  vocabulary ``{system, operator, user-plugin}``.
* The content trust tier (T0-T3) is a property of the *content* flowing
  through ``TaggedContent`` and audit rows, never of the plugin itself.

Conflating the two is the classic shape of a tier-laundering bug, so any
``T0``/``T1``/``T2``/``T3`` string in ``subscriber_tier`` is refused with
:class:`ManifestTierError` (arch-007 — distinct from version mismatch).

The ``[plugin] platform`` field is reserved for the Slice-4 comms-MCP
adapter rewrite; it is optional in v1. Including it lets Slice 4 land
without bumping ``alfred.manifest_version`` to 2.

The parser deliberately performs the version + tier checks *before*
constructing :class:`PluginManifest` so the dedicated exception classes
surface to callers without being wrapped in Pydantic's
``ValidationError``. The Pydantic model still re-validates the
``subscriber_tier`` value (defence in depth: anyone constructing
``PluginManifest`` directly without going through ``parse_manifest``
still gets refused).
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from alfred.i18n import t
from alfred.plugins.errors import (
    ManifestError,
    ManifestSandboxMissingError,
    ManifestTierError,
    ManifestVersionError,
)

_VALID_SUBSCRIBER_TIERS: Final[frozenset[str]] = frozenset({"system", "operator", "user-plugin"})
_CONTENT_TRUST_TIERS: Final[frozenset[str]] = frozenset({"T0", "T1", "T2", "T3"})

# Per-key malformed-type catalog keys for the optional ``[comms_mcp]`` string keys
# (``module`` / ``adapter_kind``). Dict-dereferenced in :func:`_parse_comms_mcp_str_key`
# so the operator-facing message names the offending key; the ``adapter_kind`` entry is
# reserved in ``_spec_b_reserve`` (the literal is invisible to pybabel here).
_COMMS_MCP_KEY_TYPE_ERRORS: Final[Mapping[str, str]] = {
    "module": "plugin.manifest_comms_mcp_module_type",
    "adapter_kind": "plugin.manifest_comms_mcp_adapter_kind_type",
}

# Spec §7.1 (PR-S4-6): the OS-level isolation primitive a plugin declares.
# Orthogonal to ``subscriber_tier`` (capability-gate posture) and the
# legacy free-form ``sandbox_profile`` label — see manifest.py module
# docstring + plan §2 "Sandbox kind versus subscriber tier".
_SANDBOX_KIND: Final[frozenset[str]] = frozenset({"full", "none", "stub"})

# The per-OS keys ``[sandbox.policy_refs]`` may carry. A fourth OS (e.g.
# ``freebsd``) must extend this set, ``SandboxBlock.policy_refs`` Literal,
# the manifest_reader validation, AND the launcher ``case`` branch in one
# atomic PR (cross-PR contract — plan §5).
_VALID_OS_KEYS: Final[frozenset[str]] = frozenset({"linux", "macos", "windows"})


class SandboxBlock(BaseModel):
    """The manifest's ``[sandbox]`` table (spec §7.1, PR-S4-6).

    Frozen + ``extra="forbid"`` so an unknown key in the table is a
    construction-time error rather than a silent miss — a typo in a future
    field name must not degrade to "no sandbox" silently.

    ``kind`` selects the OS-level isolation primitive. ``policy_refs`` is
    the per-OS map of relative paths the launcher resolves; it is required
    when ``kind == "full"`` (a full sandbox with no policy to apply is a
    contradiction) and tolerated-but-validated otherwise.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["full", "none", "stub"]
    policy_refs: Mapping[Literal["linux", "macos", "windows"], str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_policy_refs_when_full(self) -> SandboxBlock:
        if self.kind == "full" and not self.policy_refs:
            raise ValueError(t("plugin.manifest_sandbox_policy_refs_required", kind=self.kind))
        return self


class PluginManifest(BaseModel):
    """Validated plugin manifest (spec §4.3).

    Frozen so the orchestrator and supervisor cannot mutate the manifest
    between capability-gate check and audit-row emission — a mutated
    manifest would silently drift from what the gate approved.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_version: Literal[1]
    plugin_id: str
    subscriber_tier: str
    sandbox_profile: str
    sandbox: SandboxBlock
    platform: str | None = None  # reserved for Slice-4 comms-MCP
    # PR-S4-11b (#237): the ``python -m`` target the daemon spawns a comms plugin
    # at. Sourced from ``[comms_mcp] module`` and additive/optional — a manifest
    # with no ``[comms_mcp]`` block (or no ``module`` key) parses with this
    # ``None``, so every pre-11b manifest stays back-compat.
    comms_mcp_module: str | None = None
    # G6-5 Task 10 (#288): the canonical wire ``adapter_id`` a comms adapter
    # announces (``[comms_mcp] adapter_kind``, e.g. ``discord``). DISTINCT from the
    # plugin-package id (the ``plugins/<id>/`` dir name) and the launcher
    # ``[plugin] id`` (spec §8.3 id-triplet). Additive/optional — a manifest with no
    # ``[comms_mcp]`` block (or no ``adapter_kind`` key) parses with this ``None``,
    # so every non-comms manifest stays back-compat. The gateway-hosting resolve
    # seam (:func:`alfred.cli.gateway._commands._resolve_adapter_kind`) reads it so
    # ``comms_enabled_adapters`` (plugin-package ids) reconcile to the canonical
    # ``adapter_id`` the factory / credential allowlist / legs key on.
    comms_mcp_adapter_kind: str | None = None

    @field_validator("subscriber_tier")
    @classmethod
    def _validate_subscriber_tier(cls, value: str) -> str:
        """Defence in depth: reject content trust tiers + unknown labels.

        :func:`parse_manifest` performs this check first so a public
        :class:`ManifestTierError` surfaces directly to callers, but
        direct ``PluginManifest(...)`` construction would otherwise skip
        the check. This validator runs in that case too.
        """
        if value in _CONTENT_TRUST_TIERS:
            raise ManifestTierError(value)
        if value not in _VALID_SUBSCRIBER_TIERS:
            raise ManifestError(
                t(
                    "plugin.manifest_unknown_subscriber_tier",
                    tier=repr(value),
                    valid_tiers=", ".join(sorted(_VALID_SUBSCRIBER_TIERS)),
                )
            )
        return value


def parse_manifest(raw: str) -> PluginManifest:
    """Parse a TOML manifest string into a validated :class:`PluginManifest`.

    Raises
    ------
    ManifestVersionError
        ``alfred.manifest_version`` is missing or not the integer ``1``.
    ManifestTierError
        ``[plugin] subscriber_tier`` is a content trust tier (T0-T3).
    ManifestError
        Any other manifest-level problem (missing required field,
        unknown subscriber_tier value, malformed TOML, etc.).
    """
    try:
        data: dict[str, Any] = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(t("plugin.manifest_invalid_toml", detail=str(exc))) from exc

    alfred_section = data.get("alfred", {})
    version = alfred_section.get("manifest_version")
    # ADR-0017 Decision 7: the integer 1 is the sole accepted value. A
    # string "1" or any other type is refused — no semver tolerance.
    if version != 1 or not isinstance(version, int) or isinstance(version, bool):
        # ``-1`` is a sentinel for "the source value was not even an int" so
        # callers always see a real integer on the exception attribute.
        got = version if isinstance(version, int) and not isinstance(version, bool) else -1
        raise ManifestVersionError(got=got)

    plugin_section = data.get("plugin")
    if not isinstance(plugin_section, dict):
        raise ManifestError(t("plugin.manifest_missing_plugin_section"))

    plugin_id = plugin_section.get("id")
    if not isinstance(plugin_id, str) or not plugin_id:
        raise ManifestError(t("plugin.manifest_invalid_plugin_id"))

    subscriber_tier_raw = plugin_section.get("subscriber_tier")
    if not isinstance(subscriber_tier_raw, str):
        raise ManifestError(t("plugin.manifest_invalid_subscriber_tier_type"))

    # Tier check happens HERE so ManifestTierError surfaces to the caller
    # un-wrapped. The Pydantic field_validator below catches the direct-
    # construction path; this check catches the parse_manifest path.
    if subscriber_tier_raw in _CONTENT_TRUST_TIERS:
        raise ManifestTierError(subscriber_tier_raw)
    if subscriber_tier_raw not in _VALID_SUBSCRIBER_TIERS:
        raise ManifestError(
            t(
                "plugin.manifest_unknown_subscriber_tier",
                tier=repr(subscriber_tier_raw),
                valid_tiers=", ".join(sorted(_VALID_SUBSCRIBER_TIERS)),
            )
        )

    sandbox_profile = plugin_section.get("sandbox_profile", "user-plugin")
    if not isinstance(sandbox_profile, str):
        raise ManifestError(t("plugin.manifest_invalid_sandbox_profile_type"))

    platform_raw = plugin_section.get("platform")
    if platform_raw is not None and not isinstance(platform_raw, str):
        raise ManifestError(t("plugin.manifest_invalid_platform_type"))

    sandbox_block = _parse_sandbox_block(data, plugin_id=plugin_id)
    comms_section = _parse_comms_mcp_section(data)
    comms_mcp_module = _parse_comms_mcp_str_key(comms_section, key="module")
    comms_mcp_adapter_kind = _parse_comms_mcp_str_key(comms_section, key="adapter_kind")

    return PluginManifest(
        manifest_version=1,
        plugin_id=plugin_id,
        subscriber_tier=subscriber_tier_raw,
        sandbox_profile=sandbox_profile,
        sandbox=sandbox_block,
        platform=platform_raw,
        comms_mcp_module=comms_mcp_module,
        comms_mcp_adapter_kind=comms_mcp_adapter_kind,
    )


def _parse_comms_mcp_section(data: dict[str, Any]) -> dict[str, Any] | None:
    """Read + shape-validate the optional ``[comms_mcp]`` block (PR-S4-11b, #237).

    Returns the block dict, or ``None`` when it is ABSENT — every pre-11b manifest
    stays back-compat.

    FIX 5 (PR-S4-11b review): a PRESENT-but-non-table ``comms_mcp`` (e.g.
    ``comms_mcp = "oops"``) is a MALFORMED manifest, not "no block". It is rejected
    with :class:`ManifestError` rather than silently treated as absent — the
    silent-absence shape masked a broken manifest the operator believes declares a
    comms adapter (CLAUDE.md hard rule #7).
    """
    if "comms_mcp" not in data:
        return None
    comms_section = data["comms_mcp"]
    if not isinstance(comms_section, dict):
        raise ManifestError(t("plugin.manifest_comms_mcp_not_table"))
    return comms_section


def _parse_comms_mcp_str_key(comms_section: dict[str, Any] | None, *, key: str) -> str | None:
    """Read one optional string key out of the ``[comms_mcp]`` block (PR-S4-11b / G6-5).

    Returns ``None`` when the block is absent or carries no ``key`` — a manifest with
    no ``[comms_mcp] <key>`` stays back-compat. A PRESENT-but-non-string value is a
    MALFORMED manifest (typed :class:`ManifestError`, not a raw Pydantic
    ``ValidationError``); the closed-vocab error key is per-field so the operator-facing
    message names the offending key. Shared by ``module`` (PR-S4-11b) and ``adapter_kind``
    (G6-5 Task 10) so both reads apply the SAME absent/malformed discipline.
    """
    if comms_section is None:
        return None
    value = comms_section.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ManifestError(t(_COMMS_MCP_KEY_TYPE_ERRORS[key]))
    return value


def _parse_sandbox_block(data: dict[str, Any], *, plugin_id: str) -> SandboxBlock:
    """Read + validate the manifest's ``[sandbox]`` table (spec §7.1).

    Fails closed: a missing or non-table ``sandbox`` key raises
    :class:`ManifestSandboxMissingError` so the supervisor can attribute
    ``reason="sandbox_block_missing"`` from the exception type. The ``kind``
    and ``policy_refs`` checks run *before* constructing :class:`SandboxBlock`
    so :class:`ManifestError` surfaces un-wrapped (mirroring the
    version/tier pattern above); the Pydantic ``model_validator`` is the
    defence-in-depth backstop for direct construction.
    """
    sandbox_section = data.get("sandbox")
    if not isinstance(sandbox_section, dict):
        raise ManifestSandboxMissingError(plugin_id=plugin_id)

    raw_kind = sandbox_section.get("kind")
    if raw_kind not in _SANDBOX_KIND:
        raise ManifestError(
            t(
                "plugin.manifest_sandbox_kind_invalid",
                got=repr(raw_kind),
                valid=", ".join(sorted(_SANDBOX_KIND)),
            )
        )

    policy_refs_raw = sandbox_section.get("policy_refs", {})
    if not isinstance(policy_refs_raw, dict):
        raise ManifestError(t("plugin.manifest_sandbox_policy_refs_type"))
    for os_key, os_value in policy_refs_raw.items():
        if os_key not in _VALID_OS_KEYS:
            raise ManifestError(
                t(
                    "plugin.manifest_sandbox_policy_refs_unknown_os",
                    got=repr(os_key),
                    valid=", ".join(sorted(_VALID_OS_KEYS)),
                )
            )
        # A non-string value (e.g. ``linux = 7``) must surface as the typed
        # ManifestError here, BEFORE SandboxBlock construction — otherwise
        # Pydantic raises a raw ValidationError that leaks past the launcher's
        # bare-key contract (CR #229 R2 finding-2/-9).
        if not isinstance(os_value, str):
            raise ManifestError(t("plugin.manifest_sandbox_policy_refs_value_type", os_key=os_key))

    # ``kind: full`` requires a non-empty policy_refs map. Checked HERE so a
    # public ``ManifestError`` surfaces to ``parse_manifest`` callers
    # un-wrapped; the ``SandboxBlock`` model_validator is the defence-in-depth
    # backstop for direct construction (which raises Pydantic ValidationError).
    if raw_kind == "full" and not policy_refs_raw:
        raise ManifestError(t("plugin.manifest_sandbox_policy_refs_required", kind=raw_kind))

    return SandboxBlock(kind=raw_kind, policy_refs=policy_refs_raw)


__all__ = [
    "PluginManifest",
    "SandboxBlock",
    "parse_manifest",
]
