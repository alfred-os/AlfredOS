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

import re
from pathlib import Path

from alfred.security.secrets import SUPPORTED_SECRETS
from tests._setup_script_helpers import slice_shell_step

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

    Rotating the pepper invalidates cross-row correlation per spec §8.10, so
    ``_pepper_bootstrap``'s reconcile logic (#591) MUST no-op — not
    regenerate, not rewrite either side — when ``.env`` and ``secrets.toml``
    already agree. The governing check is the equality branch
    ``if [[ "$env_pepper" == "$file_pepper" ]]``, which leads straight to the
    ``"already configured"`` no-op message.

    Sliced with ``slice_shell_step`` (cuts at the next ``step "..."``
    marker) rather than a fixed-line-count window: a magic ``lines_after=N``
    is fragile against the block growing (as it did when #591 added three
    new helper functions between the marker and this guard) and, worse, a
    generic guard-pattern list (``"grep -q"``, ``"[[ -z"``, ...) can pass by
    coincidence against an unrelated helper's grep sitting inside the window
    rather than the real dispatch path this test exists to pin. Matching the
    literal equality-check text instead means the test can only pass if the
    real governing branch is actually present, and fails if it is ever
    removed, renamed, or reworked into a different comparison shape.

    Anchored on the ``step`` MARKER (via ``slice_shell_step``), not on the
    first textual occurrence of ``audit.hash_pepper``: the old anchor keyed
    on the first line mentioning the string anywhere in the script, so any
    earlier PROSE mention — a comment in an unrelated step — silently
    relocated the slice onto text that was never the bootstrap, and the
    guard assertion then failed (or, worse, passed against the wrong block).
    #340 PR2b-golive tripped exactly that when the .env credential gate
    gained a comment contrasting itself with the pepper. The marker is
    unambiguous and moves only when the step itself does; ``slice_shell_step``
    also fails loudly (``ValueError``) if the marker is ever renamed or
    removed, rather than silently slicing an empty block.
    """
    pepper_block = slice_shell_step(_SETUP_SH, "Bootstrapping audit.hash_pepper secret")
    assert '"$env_pepper" == "$file_pepper"' in pepper_block, (
        "No idempotency guard (env/file equality check) around audit.hash_pepper "
        f"seed:\n{pepper_block}"
    )
    assert "already configured" in pepper_block, (
        f"equality guard present but no-op message missing/renamed:\n{pepper_block}"
    )


def test_setup_script_seeds_the_pepper_into_dotenv_too() -> None:
    """#591: the bootstrap writes ALFRED_AUDIT_HASH_PEPPER into .env, not just secrets.toml.

    docker-compose.yaml forwards ALFRED_AUDIT_HASH_PEPPER from .env into
    alfred-core as ALFRED_AUDIT.HASH_PEPPER (#591 part 1, already landed). If
    the setup script never populates the .env side, the container boots with
    an unset pepper and every *_hash audit write raises
    MissingAuditHashPepperError on the operator's first message.
    """
    block = slice_shell_step(_SETUP_SH, "Bootstrapping audit.hash_pepper secret")
    # Not a bare substring check: "ALFRED_AUDIT_HASH_PEPPER" also appears in
    # comments, the `pepper_env_key="ALFRED_AUDIT_HASH_PEPPER"` assignment, and
    # failure-message text, all of which survive even if BOTH real
    # `_pepper_write_env` call sites were deleted. A same-shape suggested fix
    # (checking `pepper_env_key=...` or the bare string "_pepper_write_env")
    # would ALSO pass vacuously, because the function's own definition line
    # (`_pepper_write_env() {`) still contains that literal string regardless
    # of whether it is ever called. Anchor on the actual CALL syntax instead —
    # the function name followed by a quoted `$variable` argument, which only
    # a real invocation (not the definition, not a comment, not the env-key
    # assignment) can produce.
    assert re.search(r'_pepper_write_env\s+"\$\w+"', block), (
        "no `_pepper_write_env` INVOCATION found in the pepper bootstrap step "
        "(only its definition and/or the pepper_env_key variable would remain "
        "after deleting the real call sites) — .env would never receive the "
        "pepper docker-compose forwards to alfred-core"
    )


def test_setup_script_refuses_on_pepper_drift() -> None:
    """#591: a pepper that DIFFERS between .env and secrets.toml must refuse, not pick one.

    audit.hash_pepper is not in _PREFER_FILE, so alfred-core always uses the
    .env value while host-side ``alfred`` commands use the file. Silently
    picking one over the other would invalidate every *_hash audit row
    written under whichever value lost (spec §8.10) — the reconcile logic
    must return non-zero and tell the operator to reconcile by hand instead.
    """
    block = slice_shell_step(_SETUP_SH, "Bootstrapping audit.hash_pepper secret")
    assert "DIFFERS" in block, (
        "no drift-refusal error message in the pepper bootstrap step — "
        "a differing .env/secrets.toml pepper pair must be surfaced to the "
        "operator, not picked silently"
    )
    # Anchored, not two independent membership checks: the step now contains
    # SEVERAL other `return 1`s (#594 R2's _pepper_refuse_unusable_shapes adds
    # three more), so `"return 1" in block` alone would stay green even if the
    # DIFFERS branch itself lost its return and silently fell through. This
    # requires the actual `return 1` to appear within a few lines of the
    # DIFFERS error message — i.e. inside the same branch, not merely
    # somewhere in the ~90-line step.
    assert re.search(r'"[^"]*DIFFERS[^"]*"[^\n]*\n(?:[^\n]*\n){0,3}?\s*return 1\b', block), (
        "the DIFFERS error message is not immediately followed by 'return 1' "
        "— the drift-refusal branch may have lost its non-zero return, which "
        "would let the script proceed as if the peppers agreed"
    )


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
