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
