"""End-to-end adapter-id namespace consistency for the gateway-hosted chain (G6-5 Task 10, #288).

Three id namespaces coexist (spec §8.3 id-triplet):

* the **plugin-package id** — the ``plugins/<id>/`` directory name (``alfred_discord``),
  which :attr:`alfred.config.settings.Settings.comms_enabled_adapters` validates against
  (the validator probes ``plugins/<id>/manifest.toml``);
* the **manifest ``[plugin] id``** — the launcher target / sandbox-policy key
  (``alfred.discord``);
* the **canonical ``adapter_id`` / ``[comms_mcp] adapter_kind``** — the wire id the legs,
  the status observer, the credential resolver allowlist
  (:data:`alfred.comms_mcp.adapter_credential_resolver._ADAPTER_SECRET_ALLOWLIST`), and the
  child factory launch map
  (:data:`alfred.gateway.adapter_child_factory._ADAPTER_LAUNCH_TARGETS`) all key on
  (``discord``).

The Task-7 flag: ``_resolve_hosted_adapter_ids`` previously passed the plugin-package id
straight through to ``GatewayProcess(adapter_ids=...)``, so an operator who set the (only
valid) ``ALFRED_COMMS_ENABLED_ADAPTERS=alfred_discord`` got a gateway that spawned
``adapter_id="alfred_discord"`` — which the factory + resolver, keyed on ``discord``, both
refuse. This module pins the SINGLE mapping seam: ``_resolve_hosted_adapter_ids`` resolves
each enabled plugin-package id to its manifest ``adapter_kind`` (the canonical id), and the
resulting id is the SAME string the factory + the credential allowlist key on.
"""

from __future__ import annotations

from alfred.cli.gateway._commands import _resolve_hosted_adapter_ids
from alfred.comms_mcp.adapter_credential_resolver import _ADAPTER_SECRET_ALLOWLIST
from alfred.gateway.adapter_child_factory import _ADAPTER_LAUNCH_TARGETS


def _settings_stub(*enabled: str) -> object:
    class _FakeSettings:
        comms_enabled_adapters = enabled

    return _FakeSettings


def test_discord_plugin_package_id_maps_to_canonical_adapter_id(monkeypatch) -> None:
    """``alfred_discord`` (plugin-package id) -> ``discord`` (canonical adapter_id).

    The operator's only valid ``comms_enabled_adapters`` entry for Discord is the
    plugin-package dir id (the validator proves ``plugins/alfred_discord/manifest.toml``);
    the resolve seam must translate it to the canonical ``adapter_kind`` the rest of the
    spawn chain keys on.
    """
    monkeypatch.setattr("alfred.config.settings.Settings", _settings_stub("alfred_discord"))
    assert _resolve_hosted_adapter_ids() == ["discord"]


def test_canonical_id_hits_factory_and_credential_allowlist(monkeypatch) -> None:
    """The resolved canonical id is the SAME key the factory + credential allowlist use.

    This is the end-to-end invariant the Task-7 flag broke: the string the gateway is
    booted with (settings value -> resolve seam -> ``adapter_ids`` -> spawned ``adapter_id``)
    MUST be a launch-target key AND a credential-allowlist key, else the spawn refuses at
    the factory or the credential resolver.
    """
    monkeypatch.setattr("alfred.config.settings.Settings", _settings_stub("alfred_discord"))
    (adapter_id,) = _resolve_hosted_adapter_ids()
    assert adapter_id in _ADAPTER_LAUNCH_TARGETS
    assert adapter_id in _ADAPTER_SECRET_ALLOWLIST


def test_reference_adapter_kind_passes_through(monkeypatch) -> None:
    """The reference adapter's dir id == its ``adapter_kind`` (``alfred_comms_test``).

    The reference plugin's plugin-package id and its ``[comms_mcp] adapter_kind`` are the
    same string, so the seam is a no-op for it — the reference boots byte-for-byte as
    before the seam existed.
    """
    monkeypatch.setattr("alfred.config.settings.Settings", _settings_stub("alfred_comms_test"))
    assert _resolve_hosted_adapter_ids() == ["alfred_comms_test"]


def test_tui_excluded_by_plugin_package_id(monkeypatch) -> None:
    """The TUI dial-in is excluded after resolving its plugin-package id to its kind.

    An operator can only list a real plugin-package id (the ``comms_enabled_adapters``
    validator probes ``plugins/<id>/manifest.toml``), so the TUI is listed as
    ``alfred_tui``; the seam resolves it to ``adapter_kind="tui"`` and excludes it — the
    TUI dials the gateway, it is never a spawned adapter.
    """
    monkeypatch.setattr("alfred.config.settings.Settings", _settings_stub("alfred_tui"))
    assert _resolve_hosted_adapter_ids() == []


def test_mixed_set_keeps_discord_drops_tui(monkeypatch) -> None:
    """A mixed set resolves discord -> canonical and drops the TUI dial-in."""
    monkeypatch.setattr(
        "alfred.config.settings.Settings",
        _settings_stub("alfred_tui", "alfred_discord"),
    )
    assert _resolve_hosted_adapter_ids() == ["discord"]
