"""Discord-adapter sandbox-policy bytes (P2, #206 / sec-1 PR #205 round-2).

The Discord manifest declares ``[sandbox] kind = "full"`` and references three
per-OS policy files. Wave 1 shipped the manifest reference; these policy bytes
ship here. The Discord adapter ingests adversary-controlled bytes from arbitrary
Discord users, so it runs under the SAME bwrap fs/namespace containment as the
quarantined LLM — with deliberate differences: it needs outbound TLS to the
Discord gateway, so it ro-binds ``/etc/ssl/certs`` (the quarantined LLM does
not).

G7-4 (#230): ``net`` IS now in the unshare set — the sandbox runs in an empty
netns; the ONLY egress path is the bind-mounted gateway L7 CONNECT proxy socket
at ``/home/alfred/.egress/discord/egress.sock`` (rw-bound, ADR-0043).

These tests pin:

* every referenced policy file exists at its manifest path;
* the Linux bwrap policy parses via ``read_policy_toml`` and translates via
  ``policy_to_bwrap_flags`` to the expected fs/namespace containment;
* ``/etc/ssl/certs`` is ro-bound (TLS to the Discord gateway);
* ``net`` IS in the unshare set — egress is kernel-enforced (G7-4 / ADR-0043);
* the egress socket dir ``/home/alfred/.egress/discord`` is rw-bound (FIX-5:
  ``connect(2)`` on a UNIX-domain socket requires write permission on the path);
* the macOS profile + Windows stub mirror the quarantined-LLM shape.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from alfred.egress.adapter_egress_addr import DISCORD_EGRESS_SOCKET_PATH
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


def test_linux_policy_unshares_net_for_egress_containment() -> None:
    policy = read_policy_toml(_linux_policy_text())
    assert "pid" in policy.unshare
    assert "uts" in policy.unshare
    assert "cgroup" in policy.unshare
    assert "ipc" in policy.unshare
    # G7-4 / ADR-0043: net IS unshared — empty netns; egress ONLY via the
    # bind-mounted gateway L7 CONNECT proxy socket.
    assert "net" in policy.unshare


def test_linux_policy_keep_fd_3_for_broker_channel() -> None:
    policy = read_policy_toml(_linux_policy_text())
    assert 3 in policy.keep_fds


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: DISCORD_EGRESS_SOCKET_PATH.parent is a hardcoded Linux "
    "path; WindowsPath str() renders it with backslashes, mismatching the "
    "bwrap policy's forward-slash literal (#246 review)",
)
def test_linux_policy_rw_binds_egress_socket_dir() -> None:
    # FIX-5 / G7-4: the egress socket dir must be rw-bound (--bind), NOT
    # ro-bound (--ro-bind). connect(2) on a UNIX-domain socket path requires
    # write permission; a read-only bind fails with EACCES.
    policy = read_policy_toml(_linux_policy_text())
    # Pin the EXACT directory path derived from the canonical constant so this
    # assertion tracks any future path change automatically (no hardcoded guess).
    egress_socket_dir = str(DISCORD_EGRESS_SOCKET_PATH.parent)
    egress_rw = [src for src, _dst in policy.rw_binds if src == egress_socket_dir]
    assert egress_rw, f"discord policy must rw-bind {egress_socket_dir!r} exactly (FIX-5)"


def test_enforced_egress_posture_documented_in_policy() -> None:
    # G7-4: the enforced egress posture (--unshare-net + ADR-0043) must be
    # explicit in the policy bytes so an auditor sees the enforcement contract.
    text = _linux_policy_text()
    assert "ADR-0043" in text
    assert "--unshare-net" in text or '"net"' in text


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
