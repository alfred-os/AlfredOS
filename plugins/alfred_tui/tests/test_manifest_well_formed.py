"""Manifest declares adapter_kind=tui, sandbox.kind=none, subscriber_tier=operator.

The TUI is an operator-local terminal adapter, NOT an adversary-facing relay
like Discord: ``sandbox.kind = none`` (we *are* the operator's foreground PTY)
and ``subscriber_tier = operator``. ``manifest_version`` is the integer Slice-4
baseline. These are read straight off the raw TOML so a typo in the manifest
surfaces as a loud test failure independent of the host's schema loader.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_MANIFEST = Path(__file__).resolve().parent.parent / "manifest.toml"


def test_manifest_declares_required_fields() -> None:
    data = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))
    assert data["alfred"]["manifest_version"] == 1
    assert data["plugin"]["subscriber_tier"] == "operator"
    assert data["plugin"]["platform"] == "tui"
    assert data["comms_mcp"]["adapter_kind"] == "tui"
    assert data["sandbox"]["kind"] == "none"


def test_manifest_classifiers_optional_is_empty() -> None:
    # §8.5: the TUI opts into NO additional classifiers — the host runs its
    # (empty, marker-justified) required set and nothing more.
    data = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))
    assert data["comms_mcp"]["classifiers_optional"] == []
