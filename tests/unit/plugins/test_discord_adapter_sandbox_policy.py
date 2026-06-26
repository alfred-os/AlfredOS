"""Discord-adapter sandbox-policy bytes (P2, #206 / sec-1 PR #205 round-2).

The Discord manifest declares ``[sandbox] kind = "full"`` and references three
per-OS policy files. Wave 1 shipped the manifest reference; these policy bytes
ship here. The Discord adapter ingests adversary-controlled bytes from arbitrary
Discord users, so it runs under the SAME bwrap fs/namespace containment as the
quarantined LLM — with deliberate differences: it needs outbound TLS to the
Discord gateway, so it ro-binds ``/etc/ssl/certs`` (the quarantined LLM does
not) and, UNLIKE the quarantined LLM (whose echo child now ``--unshare-net``s
under Spec C G7-1, #333), the Discord adapter does NOT yet ``unshare net`` — its
Discord-only egress allowlist is deferred to #230 / G7-4.

These tests pin:

* every referenced policy file exists at its manifest path;
* the Linux bwrap policy parses via ``read_policy_toml`` and translates via
  ``policy_to_bwrap_flags`` to the expected fs/namespace containment;
* ``/etc/ssl/certs`` is ro-bound (TLS to the Discord gateway);
* ``net`` is NOT in the unshare set — egress is NOT yet kernel-enforced (#230);
* the macOS profile + Windows stub mirror the quarantined-LLM shape.
"""

from __future__ import annotations

from pathlib import Path

from alfred.plugins.manifest import parse_manifest
from alfred.plugins.sandbox_policy import policy_to_bwrap_flags, read_policy_toml


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _linux_policy_text() -> str:
    return (_repo_root() / "config" / "sandbox" / "discord-adapter.linux.bwrap.policy").read_text(
        encoding="utf-8"
    )


def test_manifest_policy_refs_resolve_to_existing_files() -> None:
    manifest = (_repo_root() / "plugins" / "alfred_discord" / "manifest.toml").read_text(
        encoding="utf-8"
    )
    sandbox = parse_manifest(manifest).sandbox
    assert sandbox.kind == "full"
    for ref in sandbox.policy_refs.values():
        assert (_repo_root() / ref).is_file(), ref


def test_linux_policy_parses_and_isolates_filesystem() -> None:
    policy = read_policy_toml(_linux_policy_text())
    flags = policy_to_bwrap_flags(policy)
    joined = " ".join(flags)
    # System trees bound read-only so CPython + discord.py can link.
    assert "--ro-bind /usr /usr" in joined
    # Ephemeral writable scratch (tmpfs), synthesised /dev, parent-reaped.
    assert "--tmpfs" in joined
    assert "--dev" in joined
    assert "--die-with-parent" in joined


def test_linux_policy_binds_tls_certs_unlike_quarantined_llm() -> None:
    # The Discord plugin opens a WSS connection to the gateway and needs the
    # system CA bundle to verify the TLS chain — the quarantined LLM does not.
    policy = read_policy_toml(_linux_policy_text())
    cert_binds = [src for src, _dst in policy.ro_binds if "ssl/certs" in src]
    assert cert_binds, "discord adapter must ro-bind /etc/ssl/certs for TLS"


def test_linux_policy_unshares_namespaces_but_not_net() -> None:
    policy = read_policy_toml(_linux_policy_text())
    assert "pid" in policy.unshare
    assert "uts" in policy.unshare
    assert "cgroup" in policy.unshare
    assert "ipc" in policy.unshare
    # SECURITY-CRITICAL (#230): egress is NOT yet kernel-enforced. The plugin
    # needs outbound network for the Discord WSS connection, and the policy
    # schema cannot yet express a Discord-only egress allowlist. NO unshare net.
    assert "net" not in policy.unshare


def test_linux_policy_keep_fd_3_for_broker_channel() -> None:
    policy = read_policy_toml(_linux_policy_text())
    assert 3 in policy.keep_fds


def test_egress_deferral_to_230_documented_in_policy() -> None:
    # The accepted egress gap must be explicit in the policy bytes so an auditor
    # sees the #230 tracking issue, not a silent omission.
    text = _linux_policy_text()
    assert "#230" in text
    assert "unshare-net" in text or "unshare net" in text


def test_macos_profile_is_deny_default() -> None:
    text = (_repo_root() / "config" / "sandbox" / "discord-adapter.macos.sb").read_text(
        encoding="utf-8"
    )
    assert "(version 1)" in text
    assert "(deny default)" in text


def test_windows_stub_is_unenforced() -> None:
    text = (_repo_root() / "config" / "sandbox" / "discord-adapter.windows.stub.policy").read_text(
        encoding="utf-8"
    )
    assert "enforced = false" in text
    assert "#230" in text
