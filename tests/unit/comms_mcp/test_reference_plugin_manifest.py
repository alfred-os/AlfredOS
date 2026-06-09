"""The reference plugin manifest declares the comms-MCP adapter block (Task 49).

The on-disk ``plugins/alfred_comms_test/manifest.toml`` must:

* parse through the real :func:`alfred.plugins.manifest.parse_manifest`;
* declare ``[sandbox] kind = "none"`` (PR-S4-6 relay-adapter invariant);
* declare ``[comms_mcp] adapter_kind = "alfred_comms_test"`` matching the
  host-side :data:`alfred.comms_mcp.protocol.adapter_kind` member.

The ``subscriber_tier`` stays ``"user-plugin"`` (the capability-gate vocabulary
the parser validates) — a literal ``"T2"`` is a *content trust tier* the parser
refuses by design, orthogonal to the capability axis.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from alfred.comms_mcp.protocol import adapter_kind
from alfred.plugins.manifest import parse_manifest

_MANIFEST_PATH = Path(__file__).parents[3] / "plugins" / "alfred_comms_test" / "manifest.toml"


def test_manifest_parses_via_real_parser() -> None:
    manifest = parse_manifest(_MANIFEST_PATH.read_text())
    assert manifest.sandbox.kind == "none"
    assert manifest.subscriber_tier == "user-plugin"


def test_manifest_declares_comms_mcp_adapter_kind() -> None:
    raw = tomllib.loads(_MANIFEST_PATH.read_text())
    comms_block = raw["comms_mcp"]
    assert comms_block["adapter_kind"] == "alfred_comms_test"
    # The declared kind is a real host-side adapter_kind member.
    assert comms_block["adapter_kind"] in adapter_kind
    assert comms_block["classifiers_optional"] == []
