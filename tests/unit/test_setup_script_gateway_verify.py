"""#309 flag-day — setup-script gateway-adapter verify path.

Both ``bin/alfred-setup.sh`` and ``bin/alfred-setup.ps1`` must route the
Discord verification through the gateway-hosted adapter path rather than the
removed standalone ``alfred-discord`` service.

The three assertions capture the three observable post-migration properties:

1. The *old* call site is gone (``alfred-discord verify`` invocation).
2. The *new* verification call is present (``gateway adapters --wait-ready``).
3. The token variable name now matches the gateway-hosted path
   (``ALFRED_DISCORD_BOT_TOKEN`` in ``.env`` instead of
   ``discord_bot_token`` in ``secrets.toml``).
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
SH = ROOT / "bin" / "alfred-setup.sh"
PS1 = ROOT / "bin" / "alfred-setup.ps1"


def test_sh_uses_gateway_adapters_verify() -> None:
    """``bin/alfred-setup.sh`` calls ``gateway adapters --wait-ready``.

    The standalone ``alfred-discord verify`` call was removed in the #309
    flag-day (Tasks 3-4).  The new path is the gateway-hosted adapter probe
    and reads the token from ``ALFRED_DISCORD_BOT_TOKEN`` in ``.env``
    (``_PREFER_FILE`` in the secret broker, so ``secrets.toml`` would shadow
    the env var — the script warns about this explicitly).
    """
    text = SH.read_text()
    assert "alfred-discord verify" not in text
    assert "gateway adapters --wait-ready" in text
    assert "ALFRED_DISCORD_BOT_TOKEN" in text


def test_ps1_uses_gateway_adapters_verify() -> None:
    """``bin/alfred-setup.ps1`` mirrors the gateway-adapter verify path.

    The ``.ps1`` had no Discord logic before #309; this is a parity addition
    so the warning surfaces on Windows (WSL2) as well.
    """
    text = PS1.read_text()
    assert "alfred-discord verify" not in text
    assert "gateway adapters --wait-ready" in text
    assert "ALFRED_DISCORD_BOT_TOKEN" in text


def test_ps1_advisory_uses_non_empty_env_token_semantics() -> None:
    """#469 Blocker 2 CodeRabbit finding 3: the ``.ps1`` advisory guard must agree with
    ``seed_hosted_adapters`` (``bin/alfred-setup.sh``, which ``.ps1`` delegates to via
    WSL) on what counts as "a Discord token is configured".

    ``seed_hosted_adapters`` only ever reads ``.env`` (via ``read_env_var``) and only
    treats a PRESENT-AND-NON-EMPTY value as proof of opt-in — it never consults the
    shell environment. Before this fix the ``.ps1`` guard disagreed on both axes: (a) it
    matched a bare ``ALFRED_DISCORD_BOT_TOKEN=`` key line (empty value) as if it were
    non-empty, and (b) it treated a parent-shell ``$env:ALFRED_DISCORD_BOT_TOKEN`` as
    proof of opt-in even though the seeder never sees the shell environment — so the two
    could disagree (a token exported only in the parent PowerShell shell would suppress
    the advisory here while ``seed_hosted_adapters`` still left Discord un-hosted).

    There is no pwsh CI leg to execute this script (Windows support is WSL2-forwarding
    only, ADR-0015), so this is a static-text regression guard for the specific
    disagreement pattern rather than a real-execution test.
    """
    text = PS1.read_text()
    assert "$env:ALFRED_DISCORD_BOT_TOKEN" not in text, (
        "a shell-exported token must not be treated as opt-in proof — "
        "seed_hosted_adapters (which this script delegates to via WSL) never reads "
        "the shell environment, only .env"
    )
    assert r"ALFRED_DISCORD_BOT_TOKEN\s*=\s*\S" in text, (
        "the .env token match must require a NON-EMPTY value after '=', mirroring "
        'seed_hosted_adapters\' `[[ -n "$token" ]]` guard — a bare '
        "'ALFRED_DISCORD_BOT_TOKEN=' key line must not read as opt-in proof"
    )
