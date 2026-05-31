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
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from alfred.plugins.errors import ManifestError, ManifestTierError, ManifestVersionError

_VALID_SUBSCRIBER_TIERS: Final[frozenset[str]] = frozenset({"system", "operator", "user-plugin"})
_CONTENT_TRUST_TIERS: Final[frozenset[str]] = frozenset({"T0", "T1", "T2", "T3"})


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
    platform: str | None = None  # reserved for Slice-4 comms-MCP

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
                f"unknown subscriber_tier {value!r}; valid: {sorted(_VALID_SUBSCRIBER_TIERS)}"
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
        raise ManifestError(f"manifest is not valid TOML: {exc}") from exc

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
        raise ManifestError("manifest is missing the required [plugin] table")

    plugin_id = plugin_section.get("id")
    if not isinstance(plugin_id, str) or not plugin_id:
        raise ManifestError("manifest [plugin] id is missing or not a string")

    subscriber_tier_raw = plugin_section.get("subscriber_tier")
    if not isinstance(subscriber_tier_raw, str):
        raise ManifestError("manifest [plugin] subscriber_tier is missing or not a string")

    # Tier check happens HERE so ManifestTierError surfaces to the caller
    # un-wrapped. The Pydantic field_validator below catches the direct-
    # construction path; this check catches the parse_manifest path.
    if subscriber_tier_raw in _CONTENT_TRUST_TIERS:
        raise ManifestTierError(subscriber_tier_raw)
    if subscriber_tier_raw not in _VALID_SUBSCRIBER_TIERS:
        raise ManifestError(
            f"unknown subscriber_tier {subscriber_tier_raw!r}; valid: "
            f"{sorted(_VALID_SUBSCRIBER_TIERS)}"
        )

    sandbox_profile = plugin_section.get("sandbox_profile", "user-plugin")
    if not isinstance(sandbox_profile, str):
        raise ManifestError("manifest [plugin] sandbox_profile is not a string")

    platform_raw = plugin_section.get("platform")
    if platform_raw is not None and not isinstance(platform_raw, str):
        raise ManifestError("manifest [plugin] platform is not a string")

    return PluginManifest(
        manifest_version=1,
        plugin_id=plugin_id,
        subscriber_tier=subscriber_tier_raw,
        sandbox_profile=sandbox_profile,
        platform=platform_raw,
    )


__all__ = [
    "PluginManifest",
    "parse_manifest",
]
