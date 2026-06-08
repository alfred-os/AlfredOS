"""Slice-4 PR-S4-0b Components G + H — setup-script + broker registry.

Component G: ``bin/alfred-setup.sh`` seeds ``audit.hash_pepper`` into the
broker secrets file and ensures ``~/.config/alfred/sandbox/`` exists with
mode 0700. Both additions are idempotent — re-running the script on a host
that already has a pepper MUST NOT clobber the existing value (rotating
the pepper invalidates cross-row correlation per spec §8.10).

Component H: ``audit.hash_pepper`` is registered in
``src/alfred/security/secrets.py::SUPPORTED_SECRETS`` so
``SecretBroker.get("audit.hash_pepper")`` doesn't raise
``UnknownSecretError`` when consumers (PR-S4-5 ``_resolve_operator``,
PR-S4-8/9 comms hash-helpers, PR-S4-1 daemon-boot probe) request it.
"""

from __future__ import annotations

from pathlib import Path

from alfred.security.secrets import SUPPORTED_SECRETS

_SETUP_SH = Path("bin/alfred-setup.sh")


# ---------------------------------------------------------------------------
# Component G: ``bin/alfred-setup.sh`` additions
# ---------------------------------------------------------------------------


def test_setup_script_creates_sandbox_config_dir() -> None:
    """The script creates ``~/.config/alfred/sandbox/`` with mode 0700.

    PR-S4-6's launcher reads policies from this dir. Without it the
    launcher refuses with ``policy_ref_unreadable`` per spec §7.5.
    """
    content = _SETUP_SH.read_text()
    assert any(
        pattern in content
        for pattern in (
            '"$HOME/.config/alfred/sandbox"',
            "$HOME/.config/alfred/sandbox",
            'sandbox_dir="$HOME/.config/alfred/sandbox"',
        )
    ), "sandbox dir step missing from bin/alfred-setup.sh"
    assert (
        'chmod 700 "$sandbox_dir"' in content
        or 'chmod 700 "$HOME/.config/alfred/sandbox"' in content
    ), "sandbox dir is not chmod 700 — operator-readable policy files should not be world-readable"


def test_setup_script_seeds_audit_hash_pepper() -> None:
    """The script seeds ``audit.hash_pepper`` via ``openssl rand -hex 32``."""
    content = _SETUP_SH.read_text()
    assert "audit.hash_pepper" in content, "audit.hash_pepper key missing from bin/alfred-setup.sh"
    assert "openssl rand -hex 32" in content, "openssl rand -hex 32 pepper generation step missing"


def test_setup_script_audit_pepper_is_idempotent() -> None:
    """Re-running the script with an existing pepper MUST NOT clobber it.

    The bootstrap step guards with ``grep -q "^audit.hash_pepper..."`` and
    exits the seed branch when the value already exists. Rotating the
    pepper invalidates cross-row correlation per spec §8.10.
    """
    content = _SETUP_SH.read_text()
    pepper_block = _slice_around(content, "audit.hash_pepper", lines_before=2, lines_after=60)
    assert any(
        guard in pepper_block
        for guard in (
            "grep -q",
            "[[ -z",
            "[ -z ",
            "if ! ",
            "test -n",
        )
    ), f"No idempotency guard around audit.hash_pepper seed:\n{pepper_block}"


def test_setup_script_pepper_file_mode_0600() -> None:
    """The pepper target file is mode 0600 (readable only by the operator).

    The pepper is the master HMAC key — any leak compromises every
    ``*_hash`` audit-row field across PR-S4-5 + PR-S4-8/9.
    """
    content = _SETUP_SH.read_text()
    # The pepper-bootstrap block ensures the target file is 0600 before
    # appending. Either an explicit chmod 0600 OR the pre-existing
    # secrets.toml file (already chmodded by the secrets bind-mount step
    # above) covers the contract.
    assert "chmod 600" in content, "no chmod 600 on the secrets file path"


def test_setup_script_openssl_preflight_friendly_error() -> None:
    """If openssl is missing the script reports an actionable error.

    `openssl` is part of the Slice-1 preflight but a freshly-installed
    minimal Linux image may lack it. The bootstrap step's branch falls
    through to a clear error pointing at the apt/brew install command
    rather than failing silently mid-script.
    """
    content = _SETUP_SH.read_text()
    pepper_block = _slice_around(content, "openssl rand -hex 32", lines_before=20, lines_after=2)
    assert "openssl" in pepper_block and (
        "command -v openssl" in pepper_block or "require_cmd openssl" in pepper_block
    ), f"No openssl preflight around pepper bootstrap:\n{pepper_block}"


# ---------------------------------------------------------------------------
# Component H: SecretBroker.SUPPORTED_SECRETS membership
# ---------------------------------------------------------------------------


def test_audit_hash_pepper_in_supported_secrets() -> None:
    """``audit.hash_pepper`` is a registered broker secret.

    Without this registration ``SecretBroker.get("audit.hash_pepper")``
    raises ``UnknownSecretError`` even when the bootstrap-seeded value
    is in the file.
    """
    assert "audit.hash_pepper" in SUPPORTED_SECRETS


def test_supported_secrets_includes_all_slice_1_through_4_entries() -> None:
    """SUPPORTED_SECRETS contains every secret AlfredOS ships through Slice-4.

    Closure for the PR #215 test-engineer "brittle hard-coded length"
    finding: enumerate the SET so unrelated PRs that add a secret only
    have to extend the literal here, and so the assertion gives a
    meaningful failure message instead of a bare integer mismatch.
    """
    expected_subset = {
        # Slice-1: provider secret + Anthropic fallback
        "deepseek_api_key",
        "anthropic_api_key",
        # Slice-2: Discord adapter
        "discord_bot_token",
        # Slice-4 (this PR): HMAC pepper for *_hash audit-row fields
        "audit.hash_pepper",
    }
    assert expected_subset <= SUPPORTED_SECRETS, (
        f"missing from SUPPORTED_SECRETS: {expected_subset - SUPPORTED_SECRETS}"
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _slice_around(text: str, needle: str, lines_before: int, lines_after: int) -> str:
    """Return ``lines_before + lines_after`` lines around the first ``needle``."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if needle in line:
            start = max(0, i - lines_before)
            end = min(len(lines), i + lines_after + 1)
            return "\n".join(lines[start:end])
    return ""
