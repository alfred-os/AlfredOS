"""The Discord adapter manifest declares the comms-MCP adapter block (Task C1).

The on-disk ``plugins/alfred_discord/manifest.toml`` must:

* parse through the real :func:`alfred.plugins.manifest.parse_manifest`;
* declare ``[sandbox] kind = "full"`` (sec-1 HIGH round-2 closure — Discord
  ingests adversary-controlled bytes from arbitrary users, so the first-party
  relay carve-out to ``kind = "none"`` is dropped);
* ship per-OS ``[sandbox.policy_refs]`` (the merged ``SandboxBlock`` schema
  refuses ``kind = "full"`` with an empty ``policy_refs`` map — the flat
  ``policy_ref = "discord-adapter.toml"`` the orchestrator decision names is
  NOT expressible on the merged schema, deferred to #230; here we ship the
  per-OS map mirroring the quarantined-LLM interim posture);
* declare ``[comms_mcp] adapter_kind = "discord"`` matching the host-side
  :data:`alfred.comms_mcp.protocol.adapter_kind` member;
* declare ``[secrets]`` for ``discord_bot_token`` and ``audit.hash_pepper``;
* carry NO ``[[hooks]]`` entries (the adapter only emits notifications).

``subscriber_tier`` stays ``"user-plugin"`` (the capability-gate vocabulary the
parser validates) — a literal ``"T2"`` is a *content trust tier* the parser
refuses by design, orthogonal to the capability axis. The inbound BODIES this
adapter relays become T3 host-side at ``process_inbound_message``.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from alfred.comms_mcp.protocol import adapter_kind
from alfred.plugins.manifest import parse_manifest

_MANIFEST_PATH = Path(__file__).parents[4] / "plugins" / "alfred_discord" / "manifest.toml"


def test_manifest_parses_via_real_parser() -> None:
    manifest = parse_manifest(_MANIFEST_PATH.read_text())
    assert manifest.plugin_id == "alfred.discord"
    assert manifest.subscriber_tier == "user-plugin"


def test_manifest_sandbox_kind_is_full() -> None:
    manifest = parse_manifest(_MANIFEST_PATH.read_text())
    assert manifest.sandbox.kind == "full"


def test_manifest_full_sandbox_ships_per_os_policy_refs() -> None:
    manifest = parse_manifest(_MANIFEST_PATH.read_text())
    # kind=full with an empty policy_refs map is refused by the schema; assert
    # all three OS keys resolve to the discord-adapter policy bundle (the bytes
    # ship in a later wave, mirroring the quarantined-LLM interim posture).
    assert set(manifest.sandbox.policy_refs) == {"linux", "macos", "windows"}
    for ref in manifest.sandbox.policy_refs.values():
        assert "discord-adapter" in ref


def test_manifest_declares_comms_mcp_adapter_kind() -> None:
    raw = tomllib.loads(_MANIFEST_PATH.read_text())
    comms_block = raw["comms_mcp"]
    assert comms_block["adapter_kind"] == "discord"
    assert comms_block["adapter_kind"] in adapter_kind
    assert comms_block["classifiers_optional"] == []


def test_manifest_declares_required_secrets() -> None:
    raw = tomllib.loads(_MANIFEST_PATH.read_text())
    secrets_block = raw["secrets"]
    assert "discord_bot_token" in secrets_block
    assert "audit.hash_pepper" in secrets_block


def test_manifest_has_no_hook_subscriptions() -> None:
    raw = tomllib.loads(_MANIFEST_PATH.read_text())
    # The adapter only EMITS notifications; it subscribes to no hookpoints.
    # A ``[[hooks]]`` block would make RealGate.check_plugin_load reject it.
    assert "hooks" not in raw
