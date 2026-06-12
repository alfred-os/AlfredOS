"""Quarantined-LLM manifest sandbox-block migration proof (PR-S4-6 B.3 + L.5).

Two guarantees:

* The on-disk ``alfred/security/quarantine_child/manifest.toml`` parses through
  the canonical parser and carries a ``kind: full`` sandbox block with the
  three per-OS ``policy_refs`` entries (B.3 — proof the migration sticks).
* A snapshot of the parsed ``sandbox`` block catches silent drift over time
  (L.5 — a regression in the migration would change this shape).

The actual policy bytes at the three referenced paths ship in PR-S4-7; this
test only asserts the manifest declaration, not the policy files.
"""

from __future__ import annotations

from pathlib import Path

from alfred.plugins.manifest import parse_manifest


def _manifest_path() -> Path:
    import alfred

    return Path(alfred.__file__).parent / "security" / "quarantine_child" / "manifest.toml"


def _parsed_sandbox() -> object:
    raw = _manifest_path().read_text(encoding="utf-8")
    return parse_manifest(raw).sandbox


def test_quarantined_llm_manifest_declares_kind_full() -> None:
    sandbox = _parsed_sandbox()
    assert sandbox.kind == "full"


def test_quarantined_llm_manifest_policy_refs_per_os() -> None:
    sandbox = _parsed_sandbox()
    assert sandbox.policy_refs["linux"].endswith(".bwrap.policy")
    assert sandbox.policy_refs["macos"].endswith(".macos.sb")
    assert sandbox.policy_refs["windows"].endswith(".windows.stub.policy")


def test_quarantined_llm_manifest_sandbox_snapshot() -> None:
    """Snapshot the sandbox block shape so B.3's migration cannot silently
    drift. Any change to the kind or policy_refs map fails this assertion."""
    sandbox = _parsed_sandbox()
    assert sandbox.kind == "full"
    assert dict(sandbox.policy_refs) == {
        "linux": "config/sandbox/quarantined-llm.linux.bwrap.policy",
        "macos": "config/sandbox/quarantined-llm.macos.sb",
        "windows": "config/sandbox/quarantined-llm.windows.stub.policy",
    }
