"""Manifest ``[sandbox]`` block parsing (PR-S4-6 Component B, spec §7.1).

The Slice-3 manifest parser learns a new required ``[sandbox]`` table.
``parse_manifest`` refuses a manifest that lacks it (fail-closed: a plugin
with no declared isolation posture must never load) and validates the
``kind`` against the closed ``{full, none, stub}`` vocabulary plus the
per-OS ``policy_refs`` map shape.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from alfred.plugins.errors import ManifestError, ManifestSandboxMissingError
from alfred.plugins.manifest import SandboxBlock, parse_manifest

_BASE = """
[alfred]
manifest_version = 1

[plugin]
id = "alfred.example"
subscriber_tier = "user-plugin"
sandbox_profile = "user-plugin"
"""


def test_sandbox_block_missing_refuses() -> None:
    with pytest.raises(ManifestSandboxMissingError) as exc_info:
        parse_manifest(_BASE)
    # The error carries the plugin_id so the supervisor can attribute the
    # sandbox_refused audit row without re-parsing the exception message.
    assert exc_info.value.plugin_id == "alfred.example"


def test_sandbox_kind_full_with_policy_refs_parses() -> None:
    raw = (
        _BASE
        + """
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = "config/sandbox/foo.linux.bwrap.policy"
macos = "config/sandbox/foo.macos.sb"
windows = "config/sandbox/foo.windows.stub.policy"
"""
    )
    m = parse_manifest(raw)
    assert m.sandbox.kind == "full"
    assert m.sandbox.policy_refs["linux"].endswith(".bwrap.policy")
    assert m.sandbox.policy_refs["macos"].endswith(".macos.sb")
    assert m.sandbox.policy_refs["windows"].endswith(".windows.stub.policy")


def test_sandbox_kind_full_without_policy_refs_refuses() -> None:
    raw = (
        _BASE
        + """
[sandbox]
kind = "full"
"""
    )
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_sandbox_kind_none_no_policy_refs_ok() -> None:
    raw = (
        _BASE
        + """
[sandbox]
kind = "none"
"""
    )
    m = parse_manifest(raw)
    assert m.sandbox.kind == "none"
    assert m.sandbox.policy_refs == {}


def test_sandbox_kind_stub_no_policy_refs_ok() -> None:
    raw = (
        _BASE
        + """
[sandbox]
kind = "stub"
"""
    )
    m = parse_manifest(raw)
    assert m.sandbox.kind == "stub"
    assert m.sandbox.policy_refs == {}


def test_sandbox_kind_invalid_refuses() -> None:
    raw = (
        _BASE
        + """
[sandbox]
kind = "containerd"
"""
    )
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_sandbox_kind_missing_refuses() -> None:
    raw = (
        _BASE
        + """
[sandbox]
policy_refs = {}
"""
    )
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_sandbox_policy_refs_unknown_os_key_refuses() -> None:
    raw = (
        _BASE
        + """
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = "x"
plan9 = "y"
"""
    )
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_sandbox_policy_refs_non_string_value_refuses() -> None:
    # CR #229 R2 finding-9/-2: a non-string policy_refs value (here ``linux =
    # 7``) must raise the TYPED ManifestError, NOT leak a raw pydantic
    # ValidationError from SandboxBlock construction. Locks the parse contract.
    raw = (
        _BASE
        + """
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = 7
"""
    )
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_sandbox_policy_refs_non_table_refuses() -> None:
    raw = (
        _BASE
        + """
[sandbox]
kind = "none"
policy_refs = "not-a-table"
"""
    )
    with pytest.raises(ManifestError):
        parse_manifest(raw)


def test_sandbox_kind_none_with_policy_refs_tolerated() -> None:
    # Forward-compat: kind:none MAY carry a policy_refs table; the parser
    # tolerates it as long as the OS keys are valid (defence in depth — a
    # malformed entry is still refused).
    raw = (
        _BASE
        + """
[sandbox]
kind = "none"

[sandbox.policy_refs]
linux = "config/sandbox/foo.linux.bwrap.policy"
"""
    )
    m = parse_manifest(raw)
    assert m.sandbox.kind == "none"
    assert m.sandbox.policy_refs["linux"].endswith(".bwrap.policy")


def test_sandboxblock_direct_full_without_policy_refs_refuses() -> None:
    # Defence in depth: constructing SandboxBlock directly (bypassing
    # parse_manifest's pre-check) still refuses kind:full with no policy_refs
    # via the model_validator. Pydantic wraps the ValueError in a
    # ValidationError (a ValueError subclass).
    with pytest.raises(ValueError):
        SandboxBlock(kind="full")


def test_sandbox_block_non_table_refuses() -> None:
    raw = (
        _BASE
        + """
sandbox = "not-a-table"
"""
    )
    with pytest.raises(ManifestSandboxMissingError):
        parse_manifest(raw)


def test_sandbox_policy_refs_injection_charset_refuses() -> None:
    # #437: a policy_ref carrying JSON-injection chars (a double-quote + comma
    # forging an `event` field) must raise the TYPED ManifestError before
    # SandboxBlock construction. Single-quoted TOML literal carries the quotes
    # verbatim. The launcher interpolates POLICY_REF raw into audit-JSON printf
    # rows; PLUGIN_ID is charset-validated for exactly this reason.
    raw = (
        _BASE
        + """
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = 'config/x","event":"forged'
"""
    )
    # match= pins the SPECIFIC charset branch, not just any ManifestError — a
    # different refusal (bad kind, missing block) would pass a bare raises().
    with pytest.raises(ManifestError, match=r"policy_refs\[linux\].*path-safe set"):
        parse_manifest(raw)


# Chars guaranteed outside [A-Za-z0-9._/-] AND safe inside a single-quoted TOML
# literal (no single-quote, no newline/control). Every generated value has >=1.
_INJECTION_ALPHABET = '",;:{}[]<>= \t()|&$#@!*?~`^%+'


@given(st.text(alphabet=_INJECTION_ALPHABET, min_size=1))
def test_sandbox_policy_refs_charset_property_refuses(bad: str) -> None:
    # Any value composed of out-of-set chars is refused. Single-quoted TOML
    # literal carries them verbatim (the alphabet excludes ' and newlines).
    raw = (
        _BASE
        + f"""
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = '{bad}'
"""
    )
    with pytest.raises(ManifestError, match=r"policy_refs\[linux\].*path-safe set"):
        parse_manifest(raw)


def test_sandbox_policy_refs_valid_path_still_parses() -> None:
    # A legitimate path-safe policy_ref must still parse (guards against an
    # over-strict allowlist). Mirrors the shape of every shipped policy_ref.
    raw = (
        _BASE
        + """
[sandbox]
kind = "full"

[sandbox.policy_refs]
linux = "config/sandbox/example.linux.bwrap.policy"
"""
    )
    manifest = parse_manifest(raw)
    assert manifest.sandbox.policy_refs["linux"] == "config/sandbox/example.linux.bwrap.policy"
